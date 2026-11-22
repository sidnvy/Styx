//! Isolated regression test for abrupt Host exit (crash / power loss / kernel
//! panic without TransportDrainV1) followed by a fresh Host incarnation.
use super::*;
use crate::{
    android::{RunStatus, run as run_android_host},
    enrollment::{
        client::{self, CredentialStore},
        http::EnrollmentHttp,
        service::EnrollmentService,
        shared::SharedEnrollment,
    },
    gateway::{auth::GatewayBearerPolicy, http::GatewayHttp, paired::PairedGatewayBackend},
    host::{android::AndroidPlatform, protocol::wire},
    store::{
        PrivateRoot,
        enrollment::{EnrollmentJournal, JournalBudget, OwnedEnrollmentJournal},
    },
    tls::{GatewayServerTls, generate_gateway_ca, issue_server_leaf, paired_gateway_namespace},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rmcp::{
    ClientServiceExt,
    model::*,
    service::ClientLifecycleMode,
    transport::{
        StreamableHttpClientTransport, streamable_http_client::StreamableHttpClientTransportConfig,
    },
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use styx_contracts::{
    error::ErrorCategory,
    identity::{DeviceId, Sha256Digest},
};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

#[derive(Default)]
struct MemoryCreds(Mutex<Option<Zeroizing<String>>>);
impl CredentialStore for MemoryCreds {
    fn load(&self) -> Result<Option<Zeroizing<String>>, client::ClientError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .as_ref()
            .map(|v| Zeroizing::new(v.to_string())))
    }
    fn save(&self, json: &str) -> Result<(), client::ClientError> {
        *self.0.lock().unwrap() = Some(Zeroizing::new(json.into()));
        Ok(())
    }
}

struct FakeAndroid {
    incarnation: &'static str,
    actions: AtomicUsize,
    delay_next_action: AtomicBool,
    observations: Mutex<BTreeMap<String, String>>,
}
impl FakeAndroid {
    fn new(incarnation: &'static str) -> Self {
        Self {
            incarnation,
            actions: AtomicUsize::new(0),
            delay_next_action: AtomicBool::new(false),
            observations: Mutex::new(BTreeMap::new()),
        }
    }
}
impl AndroidPlatform for FakeAndroid {
    fn execute(&self, name: &str, arguments: Value) -> Result<Value, ErrorCategory> {
        match name {
            "status" => Ok(json!({"accessibility":true,"device_locked":false})),
            "clear" => {
                self.observations.lock().unwrap().clear();
                Ok(json!({"ok":true}))
            }
            "release_caller" => {
                if let Some(caller) = arguments["__caller_id"].as_str() {
                    self.observations.lock().unwrap().remove(caller);
                }
                Ok(json!({"ok":true}))
            }
            "android_observe" => {
                let caller = arguments["__caller_id"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .ok_or(ErrorCategory::InvalidRequest)?;
                let id = format!("obs-{}-{caller}", self.incarnation);
                self.observations
                    .lock()
                    .unwrap()
                    .insert(caller.to_owned(), id.clone());
                Ok(json!({
                    "ok": true,
                    "observation_id": id,
                    "nodes": [{"node_id":"node-1","text":"Synthetic target"}]
                }))
            }
            "android_act" => {
                let caller = arguments["__caller_id"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .ok_or(ErrorCategory::InvalidRequest)?;
                let obs = arguments["observation_id"].as_str();
                let current = self.observations.lock().unwrap().get(caller).cloned();
                if current.as_deref() != obs {
                    return Ok(json!({
                        "ok": false,
                        "error": {
                            "code": "stale_observation",
                            "message": "Observation does not belong to current Host incarnation",
                            "uncertain": false
                        }
                    }));
                }
                self.actions.fetch_add(1, Ordering::SeqCst);
                if self.delay_next_action.swap(false, Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(500));
                }
                Ok(json!({"ok": true, "incarnation": self.incarnation}))
            }
            _ => Err(ErrorCategory::InvalidRequest),
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn token() -> String {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).unwrap();
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(unix)]
fn private_dir(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[cfg(not(unix))]
fn private_dir(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
}

fn fresh_store(path: &Path) -> OwnedEnrollmentJournal {
    private_dir(path);
    let root = PrivateRoot::open(path).unwrap();
    let mut writer = root.try_configuration_writer().unwrap();
    {
        let mut journal =
            EnrollmentJournal::open(&root, &mut writer, JournalBudget::default()).unwrap();
        journal.record_time_floor(now_ms()).unwrap();
    }
    OwnedEnrollmentJournal::open_existing(root, writer, JournalBudget::default()).unwrap()
}

fn call_tool(name: &'static str, args: Value) -> CallToolRequestParams {
    CallToolRequestParams::new(name).with_arguments(args.as_object().unwrap().clone())
}

async fn wait_device_gen(
    relay: &RelayHandle,
    device: &DeviceId,
    exclude: Option<&HostGeneration>,
) -> HostGeneration {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(found) = relay.devices().await.unwrap().into_iter().find(|d| {
                d.device_id == *device
                    && d.android_online
                    && d.host_generation
                        .as_ref()
                        .is_some_and(|g| Some(g) != exclude)
            }) {
                return found.host_generation.unwrap();
            }
            tokio::time::sleep(Duration::from_millis(15)).await;
        }
    })
    .await
    .expect("Android Host generation must appear online")
}

async fn wait_device_offline(relay: &RelayHandle, device: &DeviceId) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if relay
                .devices()
                .await
                .unwrap()
                .into_iter()
                .all(|d| d.device_id != *device || d.host_generation.is_none())
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(15)).await;
        }
    })
    .await
    .expect("Aborted Host must leave live registry")
}

#[tokio::test]
async fn abrupt_host_crash_allows_authorized_owner_rebind_without_replay_or_cross_generation_reuse()
{
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("abrupt-rebind");
    private_dir(&root);
    let mobile_dir = root.join("mobile");
    private_dir(&mobile_dir);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let origin = format!("https://{address}");
    let hosts = vec![address.to_string()];
    let now = now_ms() / 1000;
    let ca = generate_gateway_ca(now, now - 60, now + 86400).unwrap();
    let leaf = issue_server_leaf(
        &ca.certificate_pem,
        &ca.private_key,
        &ca.anchor_pin,
        &origin,
        now,
    )
    .unwrap();
    let tls = Arc::new(
        GatewayServerTls::from_pem(
            &leaf.certificate_chain_pem,
            &leaf.private_key,
            leaf.leaf_pin,
        )
        .unwrap(),
    );
    let ca_pem = String::from_utf8(ca.certificate_pem.to_vec()).unwrap();
    let ca_der = rustls_pemfile::certs(&mut std::io::Cursor::new(&ca_pem))
        .next()
        .unwrap()
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca_der).unwrap();
    let client_tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let raw = reqwest::Client::builder()
        .tls_backend_preconfigured(client_tls)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    let admin = token();
    let mcp_token = token();
    let service = EnrollmentService::recover_existing(
        fresh_store(&root.join("journal")),
        admin.as_bytes(),
        Sha256Digest::of_bytes(mcp_token.as_bytes()),
        hosts.clone(),
    )
    .unwrap();
    let shared = SharedEnrollment::new(service);
    let relay = RelayHandle::new(
        shared.clone(),
        paired_gateway_namespace(&ca.anchor_pin),
        uuid::Uuid::new_v4().to_string().try_into().unwrap(),
    );
    let backend = Arc::new(PairedGatewayBackend::new(relay.clone()));
    let policy =
        Arc::new(GatewayBearerPolicy::new(mcp_token.as_bytes(), hosts.clone(), vec![]).unwrap());
    let gateway_http = GatewayHttp::new(policy.clone(), backend);
    let app = EnrollmentHttp::new_paired(tls, shared, relay.clone(), gateway_http, hosts.clone())
        .unwrap();
    let gateway_stop = CancellationToken::new();
    let server = tokio::spawn(app.run(listener, gateway_stop.clone()));

    let inv = raw
        .post(format!("{origin}/styx/enroll/invitations"))
        .bearer_auth(&admin)
        .json(&json!({"short_code":{"origin":origin,"ca_pem":ca_pem}}))
        .send()
        .await
        .unwrap();
    assert_eq!(inv.status(), reqwest::StatusCode::OK);
    let inv: Value = inv.json().await.unwrap();
    let cred_store = MemoryCreds::default();
    let creds = tokio::time::timeout(
        Duration::from_secs(30),
        client::pair(
            &cred_store,
            &origin,
            inv["pairing_code"].as_str().unwrap(),
            "Abrupt Crash Pixel",
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let device = creds.device_id.clone();

    // --- Incarnation 1 ---
    let platform1 = Arc::new(FakeAndroid::new("gen1"));
    let stop1 = CancellationToken::new();
    let reporter: Arc<dyn Fn(RunStatus) + Send + Sync> = Arc::new(|_| {});
    let host1 = tokio::spawn({
        let mobile_dir = mobile_dir.clone();
        let platform1 = platform1.clone();
        let stop1 = stop1.clone();
        let reporter = reporter.clone();
        async move { run_android_host(creds, &mobile_dir, platform1, stop1, reporter).await }
    });
    let gen1 = wait_device_gen(&relay, &device, None).await;

    // Direct owner handles to verify binding invariants + unauthorized fence.
    let mut owner_headers = http::HeaderMap::new();
    owner_headers.insert(http::header::HOST, hosts[0].parse().unwrap());
    owner_headers.insert(
        http::header::AUTHORIZATION,
        format!("Bearer {mcp_token}").parse().unwrap(),
    );
    let principal = policy.authorize(&owner_headers).unwrap();
    let direct_owner = principal.new_mcp_session_owner().unwrap();
    let fenced_owner = principal.new_mcp_session_owner().unwrap();
    let old_direct = relay.bind_android(&direct_owner, &device).await.unwrap();
    assert_eq!(old_direct.host_generation(), &gen1);
    relay.fence_owner(&fenced_owner).unwrap();

    // Real MCP client session (same Mcp-Session-Id across the crash).
    let mut cfg = StreamableHttpClientTransportConfig::with_uri(format!("{origin}/mcp"))
        .auth_header(mcp_token)
        .reinit_on_expired_session(false)
        .max_concurrent_requests(2);
    cfg.allow_stateless = false;
    let mcp = ClientConfig::new(
        ClientCapabilities::default(),
        Implementation::new("abrupt-rebind-test", "1"),
    )
    .with_protocol_version(ProtocolVersion::V_2025_11_25)
    .serve_with_lifecycle(
        StreamableHttpClientTransport::with_client(raw.clone(), cfg),
        ClientLifecycleMode::Initialize,
    )
    .await
    .unwrap();

    let obs1 = mcp
        .call_tool(call_tool(
            "android_observe",
            json!({"environment_id":device,"screenshot":false}),
        ))
        .await
        .unwrap();
    assert_ne!(obs1.is_error, Some(true));
    let obs1_id = obs1.structured_content.unwrap()["observation_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(obs1_id.contains("gen1"));

    // Start an in-flight action on Incarnation 1, then abruptly kill Host 1 (no drain!).
    platform1.delay_next_action.store(true, Ordering::SeqCst);
    let peer = mcp.peer().clone();
    let dev_clone = device.clone();
    let obs1_clone = obs1_id.clone();
    let in_flight = tokio::spawn(async move {
        peer.call_tool(call_tool(
            "android_act",
            json!({
                "environment_id": dev_clone,
                "observation_id": obs1_clone,
                "action": {"type":"click","node_id":"node-1"}
            }),
        ))
        .await
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        while platform1.actions.load(Ordering::SeqCst) != 1 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();

    // Simulate sudden process kill / kernel panic / power loss: abort host1 without stop1.cancel()!
    host1.abort();
    let _ = host1.await;
    let lost = tokio::time::timeout(Duration::from_secs(5), in_flight)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(lost.is_error, Some(true));
    let lost_text = lost.content[0].as_text().unwrap().text.as_str();
    assert!(
        lost_text.contains("outcome_unknown") || lost_text.contains("RESULT_UNKNOWN"),
        "abruptly lost in-flight action must report unknown: {lost_text}"
    );
    wait_device_offline(&relay, &device).await;

    // --- Incarnation 2 (fresh Host process reloading persisted credentials, new host_generation) ---
    let creds2 = client::load_ready(&cred_store).unwrap();
    let platform2 = Arc::new(FakeAndroid::new("gen2"));
    let stop2 = CancellationToken::new();
    let host2 = tokio::spawn({
        let mobile_dir = mobile_dir.clone();
        let platform2 = platform2.clone();
        let stop2 = stop2.clone();
        let reporter = reporter.clone();
        async move { run_android_host(creds2, &mobile_dir, platform2, stop2, reporter).await }
    });
    let gen2 = wait_device_gen(&relay, &device, Some(&gen1)).await;
    assert_ne!(gen2, gen1);

    // 1. Old direct binding must truthfully remain NOT physically_settled, permanently closed,
    //    and unusable for calls.
    assert!(!old_direct.physically_settled());
    assert!(old_direct.closed());
    let old_frame = || wire::Call::Android {
        owner: old_direct.owner_ref(),
        grant_revision: old_direct.grant_revision(),
        command: wire::AndroidCommand {
            name: "android_observe".into(),
            arguments: serde_json::Map::new(),
        },
    };
    assert!(matches!(
        relay.call(&old_direct, old_frame()).await,
        Err(RelayError::Unauthorized)
    ));

    // 2. Authorized direct owner can open a fresh binding on gen2 with a new owner_epoch,
    //    and old OwnerRef frames remain rejected on the replacement.
    let new_direct = relay
        .bind_android(&direct_owner, &device)
        .await
        .expect("legitimate owner must rebind after abrupt Host crash");
    assert_eq!(new_direct.host_generation(), &gen2);
    assert!(new_direct.owner_ref() != old_direct.owner_ref());
    assert!(matches!(
        relay.call(&new_direct, old_frame()).await,
        Err(RelayError::Unauthorized)
    ));

    // 3. Unauthorized / fenced owner MUST NOT acquire authority through recovery.
    assert!(matches!(
        relay.bind_android(&fenced_owner, &device).await,
        Err(RelayError::Unauthorized)
    ));

    // 4. Same MCP session MUST NOT reuse gen1's observation_id on gen2,
    //    and gen1's interrupted action was NEVER replayed on gen2.
    assert_eq!(platform2.actions.load(Ordering::SeqCst), 0);
    let stale_act = mcp
        .call_tool(call_tool(
            "android_act",
            json!({
                "environment_id": device,
                "observation_id": obs1_id,
                "action": {"type":"click","node_id":"node-1"}
            }),
        ))
        .await
        .unwrap();
    assert_eq!(stale_act.is_error, Some(true));
    assert_eq!(platform2.actions.load(Ordering::SeqCst), 0);

    // 5. Same MCP session CAN observe and act freshly on gen2!
    let obs2 = mcp
        .call_tool(call_tool(
            "android_observe",
            json!({"environment_id":device,"screenshot":false}),
        ))
        .await
        .unwrap();
    assert_ne!(
        obs2.is_error,
        Some(true),
        "expected fresh observe on gen2 to succeed: {obs2:?}"
    );
    let obs2_id = obs2.structured_content.unwrap()["observation_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(obs2_id.contains("gen2"));

    let act2 = mcp
        .call_tool(call_tool(
            "android_act",
            json!({
                "environment_id": device,
                "observation_id": obs2_id,
                "action": {"type":"click","node_id":"node-1"}
            }),
        ))
        .await
        .unwrap();
    assert_ne!(
        act2.is_error,
        Some(true),
        "expected fresh act on gen2 to succeed: {act2:?}"
    );
    assert_eq!(platform2.actions.load(Ordering::SeqCst), 1);

    let _ = mcp.cancel().await;
    stop2.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), host2).await;
    gateway_stop.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), server).await;
}
