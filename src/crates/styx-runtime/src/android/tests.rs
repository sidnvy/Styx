//! Real loopback enrollment, TLS, MCP and WSS with synthetic Android callbacks.
//! This exercises the shared transport and Core lifecycle, not Android OS APIs.
use super::*;
use crate::{
    enrollment::{
        client::{self, CredentialStore},
        http::EnrollmentHttp,
        service::EnrollmentService,
        shared::SharedEnrollment,
    },
    gateway::{
        auth::GatewayBearerPolicy,
        http::GatewayHttp,
        paired::{PairedGatewayBackend, RelayHandle},
    },
    store::{
        PrivateRoot,
        enrollment::{EnrollmentJournal, JournalBudget, OwnedEnrollmentJournal},
    },
    tls::{GatewayServerTls, generate_gateway_ca, issue_server_leaf},
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
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{
        Condvar, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use styx_contracts::identity::Sha256Digest;
use tokio::net::TcpListener;
use zeroize::Zeroizing;

#[derive(Default)]
struct MemoryStore(Mutex<Option<Zeroizing<String>>>);
impl CredentialStore for MemoryStore {
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
    actions: AtomicUsize,
    observations: AtomicUsize,
    accessibility: AtomicBool,
    delay_next_action: AtomicBool,
    block_next_action: AtomicBool,
    action_blocked: AtomicBool,
    released: Mutex<bool>,
    release: Condvar,
    clears: AtomicUsize,
}
impl FakeAndroid {
    fn new() -> Self {
        Self {
            actions: AtomicUsize::new(0),
            observations: AtomicUsize::new(0),
            accessibility: AtomicBool::new(true),
            delay_next_action: AtomicBool::new(false),
            block_next_action: AtomicBool::new(false),
            action_blocked: AtomicBool::new(false),
            released: Mutex::new(false),
            release: Condvar::new(),
            clears: AtomicUsize::new(0),
        }
    }
}
impl AndroidPlatform for FakeAndroid {
    fn execute(&self, name: &str, arguments: Value) -> Result<Value, ErrorCategory> {
        match name {
            "status" => Ok(
                json!({"accessibility":self.accessibility.load(Ordering::SeqCst),"device_locked":false}),
            ),
            "clear" => {
                self.clears.fetch_add(1, Ordering::SeqCst);
                *self.released.lock().unwrap() = true;
                self.release.notify_all();
                Ok(json!({"ok":true}))
            }
            "release_caller" => Ok(json!({"ok":true})),
            "android_list_displays" => Ok(
                json!({"ok":true,"displays":[{"display_id":0,"width":1080,"height":2340},{"display_id":7,"width":1080,"height":1920}]}),
            ),
            "android_observe" => {
                assert!(
                    arguments["__caller_id"]
                        .as_str()
                        .is_some_and(|id| !id.is_empty())
                );
                let n = self.observations.fetch_add(1, Ordering::SeqCst) + 1;
                let mut result = json!({"ok":true,"observation_id":format!("observation-{n}"),"display_id":arguments.get("display_id").and_then(Value::as_u64).unwrap_or(0),"nodes":[{"node_id":"node-1","text":"Synthetic test target"}]});
                if arguments["screenshot"] == true {
                    result["screenshot"] = json!({
                        "mime_type":"image/png",
                        "data":"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jE6sAAAAASUVORK5CYII=",
                        "width":1,"height":1
                    });
                }
                Ok(result)
            }
            "android_act" => {
                assert!(
                    arguments["__caller_id"]
                        .as_str()
                        .is_some_and(|id| !id.is_empty())
                );
                self.actions.fetch_add(1, Ordering::SeqCst);
                if self.delay_next_action.swap(false, Ordering::SeqCst) {
                    // Deliberate callback lag lets the test drop the original reply.
                    std::thread::sleep(Duration::from_millis(500));
                }
                if self.block_next_action.swap(false, Ordering::SeqCst) {
                    let mut released = self.released.lock().unwrap();
                    *released = false;
                    self.action_blocked.store(true, Ordering::SeqCst);
                    let (_released, timeout) = self
                        .release
                        .wait_timeout_while(released, Duration::from_secs(5), |released| !*released)
                        .unwrap();
                    self.action_blocked.store(false, Ordering::SeqCst);
                    assert!(
                        !timeout.timed_out(),
                        "capability disable must clear an active action before waiting for its admission gate"
                    );
                    return Ok(
                        json!({"ok":false,"error":{"code":"capability_disabled","message":"Synthetic action was stopped by clear","uncertain":false}}),
                    );
                }
                Ok(json!({"ok":true}))
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
fn private_dir(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
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
fn call(name: &str, arguments: Value) -> CallToolRequestParams {
    serde_json::from_value(json!({"name":name,"arguments":arguments})).unwrap()
}
fn data(result: CallToolResult) -> Value {
    assert_ne!(
        result.is_error,
        Some(true),
        "tool refused: {:?}",
        result.content
    );
    result.structured_content.expect("structured tool result")
}
async fn wait_android(relay: &RelayHandle, device: &DeviceId) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if relay
                .devices()
                .await
                .unwrap()
                .iter()
                .any(|d| &d.device_id == device && d.android_online)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("Android-only WSS registration");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn independent_android_pairing_wss_images_reconnect_disable_and_revoke() {
    let parent = std::env::var_os("STYX_TEST_PAIRED_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let root = parent.join(format!("android-{}", uuid::Uuid::new_v4()));
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
    let gateway_http = GatewayHttp::new(
        Arc::new(GatewayBearerPolicy::new(mcp_token.as_bytes(), hosts.clone(), vec![]).unwrap()),
        backend,
    );
    let app = EnrollmentHttp::new_paired(tls, shared, relay.clone(), gateway_http, hosts).unwrap();
    let gateway_stop = CancellationToken::new();
    let server = tokio::spawn(app.run(listener, gateway_stop.clone()));

    let invitation = raw
        .post(format!("{origin}/styx/enroll/invitations"))
        .bearer_auth(&admin)
        .json(&json!({"short_code":{"origin":origin,"ca_pem":ca_pem}}))
        .send()
        .await
        .unwrap();
    assert_eq!(invitation.status(), reqwest::StatusCode::OK);
    let invitation: Value = invitation.json().await.unwrap();
    let store = MemoryStore::default();
    let credentials = tokio::time::timeout(
        Duration::from_secs(30),
        client::pair(
            &store,
            &origin,
            invitation["pairing_code"].as_str().unwrap(),
            "Synthetic Pixel Android",
        ),
    )
    .await
    .expect("real short-code pairing deadline")
    .unwrap();
    let device = credentials.device_id.clone();
    assert_eq!(client::load_ready(&store).unwrap().device_id, device);
    let platform = Arc::new(FakeAndroid::new());
    let host_stop = CancellationToken::new();
    let (status_tx, mut status_rx) = tokio::sync::mpsc::unbounded_channel();
    let reporter: Reporter = Arc::new(move |status| {
        let _ = status_tx.send(status);
    });
    let platform_run = platform.clone();
    let run_stop = host_stop.clone();
    let files_dir = mobile_dir.clone();
    let run_reporter = reporter.clone();
    let host = tokio::spawn(async move {
        run(
            credentials,
            &files_dir,
            platform_run,
            run_stop,
            run_reporter,
        )
        .await
    });
    wait_android(&relay, &device).await;
    let original = relay
        .inner
        .state
        .lock()
        .unwrap()
        .entries
        .get(&device)
        .cloned()
        .unwrap();
    assert!(original.android_feature);
    assert!(!original.exec_feature && !original.browser_feature && !original.computer_feature);
    assert!(
        original.lease.lock().await.is_none(),
        "Android must not borrow a business Exec lease"
    );
    assert!(
        original.bootstrap_lease.lock().await.is_some(),
        "authenticated bootstrap control lease is retained"
    );

    // A legacy peer does not negotiate Android. Refuse the new patch before
    // looking up any control lease or writing a frame its old DTO cannot parse.
    // The original Entry retains all Core leases and the actual control link.
    let legacy = Arc::new(crate::gateway::paired::Entry {
        host_settings: true,
        device: original.device.clone(),
        transport_generation: original.transport_generation.clone(),
        host_connection: original.host_connection.clone(),
        host_generation: original.host_generation.clone(),
        grant_revision: original.grant_revision,
        profile: original.profile.clone(),
        tx: original.tx.clone(),
        stop: original.stop.clone(),
        live: AtomicBool::new(true),
        admission: Mutex::new(false),
        drain: Mutex::new(None),
        drain_enabled: original.drain_enabled,
        lease: tokio::sync::Mutex::new(None),
        bootstrap_lane: original.bootstrap_lane,
        bootstrap_lease: tokio::sync::Mutex::new(None),
        exec_feature: original.exec_feature,
        browser_feature: original.browser_feature,
        computer_feature: original.computer_feature,
        android_feature: false,
        browser_lease: tokio::sync::Mutex::new(None),
        computer_lease: tokio::sync::Mutex::new(None),
    });
    relay
        .inner
        .state
        .lock()
        .unwrap()
        .entries
        .insert(device.clone(), legacy);
    for android in [false, true] {
        let result = relay
            .host_capabilities(
                &device,
                Some(crate::host::settings::CapabilityPatch {
                    android: Some(android),
                    ..Default::default()
                }),
            )
            .await;
        assert!(matches!(
            result,
            Err(crate::gateway::paired::RelayError::Unsupported)
        ));
    }
    relay
        .inner
        .state
        .lock()
        .unwrap()
        .entries
        .insert(device.clone(), original.clone());
    assert!(original.live.load(Ordering::Acquire));
    assert!(!original.stop.is_cancelled());
    relay
        .host_capabilities(&device, None)
        .await
        .expect("original control link remains usable after a legacy Android patch refusal");
    relay
        .host_capabilities(
            &device,
            Some(crate::host::settings::CapabilityPatch {
                exec: Some(false),
                ..Default::default()
            }),
        )
        .await
        .expect("desktop-only patch still reaches the unchanged control link");

    let mut config = StreamableHttpClientTransportConfig::with_uri(format!("{origin}/mcp"))
        .auth_header(mcp_token)
        .reinit_on_expired_session(false)
        .max_concurrent_requests(2);
    config.allow_stateless = false;
    let mcp = ClientConfig::new(
        ClientCapabilities::default(),
        Implementation::new("android-native-loopback-test", "1"),
    )
    .with_protocol_version(ProtocolVersion::V_2025_11_25)
    .serve_with_lifecycle(
        StreamableHttpClientTransport::with_client(raw.clone(), config),
        ClientLifecycleMode::Initialize,
    )
    .await
    .unwrap();
    let listed = data(
        mcp.call_tool(call("list_execution_environments", json!({})))
            .await
            .unwrap(),
    );
    assert_eq!(listed["environments"][0]["environment_id"], device.as_str());
    assert_eq!(listed["environments"][0]["platform"], "android");
    assert_eq!(listed["environments"][0]["connection"], "connected");
    let status = data(
        mcp.call_tool(call(
            "get_execution_environment_status",
            json!({"environment_id":device}),
        ))
        .await
        .unwrap(),
    );
    assert_eq!(status["exec"]["configured"], false);
    assert_eq!(status["android"]["readiness"], "ready");
    let displays = data(
        mcp.call_tool(call(
            "android_list_displays",
            json!({"environment_id":device}),
        ))
        .await
        .unwrap(),
    );
    assert_eq!(displays["displays"][1]["display_id"], 7);
    let secondary = data(
        mcp.call_tool(call(
            "android_observe",
            json!({"environment_id":device,"display_id":7}),
        ))
        .await
        .unwrap(),
    );
    assert_eq!(secondary["display_id"], 7);

    let observed = mcp
        .call_tool(call(
            "android_observe",
            json!({"environment_id":device,"screenshot":true}),
        ))
        .await
        .unwrap();
    assert_ne!(observed.is_error, Some(true));
    let serialized = serde_json::to_value(&observed).unwrap();
    assert!(
        serialized["content"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["type"] == "image")
    );
    assert!(
        serialized["structuredContent"]["screenshot"]
            .get("data")
            .is_none()
    );
    let first_observation = observed.structured_content.unwrap()["observation_id"].clone();

    // Drop the WSS reply after the one platform action started. Reconnection
    // keeps the same Core/caller and must never invoke that action a second time.
    platform.delay_next_action.store(true, Ordering::SeqCst);
    let peer = mcp.peer().clone();
    let request = call(
        "android_act",
        json!({"environment_id":device,"observation_id":first_observation,"action":{"type":"click","node_id":"node-1"}}),
    );
    let in_flight = tokio::spawn(async move { peer.call_tool(request).await });
    tokio::time::timeout(Duration::from_secs(5), async {
        while platform.actions.load(Ordering::SeqCst) != 1 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    original.stop.cancel();
    let lost = tokio::time::timeout(Duration::from_secs(5), in_flight)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(lost.is_error, Some(true));
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let next = relay
                .inner
                .state
                .lock()
                .unwrap()
                .entries
                .get(&device)
                .cloned();
            if let Some(next) = next
                && next.transport_generation != original.transport_generation
                && next.live.load(Ordering::Acquire)
            {
                assert_eq!(next.host_generation, original.host_generation);
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("same Host reconnects");
    wait_android(&relay, &device).await;
    assert_eq!(platform.actions.load(Ordering::SeqCst), 1);
    let fresh = data(
        mcp.call_tool(call("android_observe", json!({"environment_id":device})))
            .await
            .unwrap(),
    );
    data(mcp.call_tool(call("android_act", json!({"environment_id":device,"observation_id":fresh["observation_id"],"action":{"type":"click","node_id":"node-1"}}))).await.unwrap());
    assert_eq!(platform.actions.load(Ordering::SeqCst), 2);

    // A normal Host stop settles the original binding before a new Core starts.
    // Keep this exact authenticated MCP client and persisted device identity.
    let old_generation = fresh["operation_id"]["host_generation"].clone();
    let old_observation = fresh["observation_id"].clone();
    host_stop.cancel();
    tokio::time::timeout(Duration::from_secs(30), host)
        .await
        .expect("original Android Host stops through its transport drain")
        .unwrap()
        .unwrap();
    let stopped = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(status) = status_rx.recv().await {
            if status.state == "stopped" {
                return status;
            }
        }
        panic!("Android Host did not report its stopped state");
    })
    .await
    .unwrap();
    assert_eq!(
        stopped.transport_drain,
        Some(TransportDrainOutcome::Complete)
    );

    let credentials = client::load_ready(&store).unwrap();
    assert_eq!(credentials.device_id, device);
    let platform_run = platform.clone();
    let files_dir = mobile_dir.clone();
    let run_reporter = reporter.clone();
    let host_stop = CancellationToken::new();
    let run_stop = host_stop.clone();
    let host = tokio::spawn(async move {
        run(
            credentials,
            &files_dir,
            platform_run,
            run_stop,
            run_reporter,
        )
        .await
    });
    wait_android(&relay, &device).await;
    let resumed = mcp
        .call_tool(call("android_observe", json!({"environment_id":device})))
        .await
        .unwrap();
    assert_ne!(
        resumed.is_error,
        Some(true),
        "the same MCP caller must bind to the gracefully restarted Host"
    );
    let fresh = data(resumed);
    assert_eq!(fresh["environment_id"], device.as_str());
    assert_ne!(fresh["operation_id"]["host_generation"], old_generation);
    assert_ne!(fresh["observation_id"], old_observation);
    assert_eq!(platform.actions.load(Ordering::SeqCst), 2);

    platform.accessibility.store(false, Ordering::SeqCst);
    let status = data(
        mcp.call_tool(call(
            "get_execution_environment_status",
            json!({"environment_id":device}),
        ))
        .await
        .unwrap(),
    );
    assert_eq!(status["android"]["readiness"], "permission_required");
    let refused = mcp
        .call_tool(call("android_observe", json!({"environment_id":device})))
        .await
        .unwrap();
    assert_eq!(refused.is_error, Some(true));
    platform.accessibility.store(true, Ordering::SeqCst);

    // An active callback holds the settings admission read gate. Disabling
    // Android must reach platform.clear before awaiting the write gate.
    let clears = platform.clears.load(Ordering::SeqCst);
    platform.block_next_action.store(true, Ordering::SeqCst);
    let peer = mcp.peer().clone();
    let request = call(
        "android_act",
        json!({"environment_id":device,"observation_id":fresh["observation_id"],"action":{"type":"click","node_id":"node-1"}}),
    );
    let blocked_action = tokio::spawn(async move { peer.call_tool(request).await });
    tokio::time::timeout(Duration::from_secs(5), async {
        while !platform.action_blocked.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("synthetic action entered its blocked callback");
    data(
        tokio::time::timeout(
            Duration::from_secs(3),
            mcp.call_tool(call(
                "set_execution_environment_capabilities",
                json!({"environment_id":device,"android":false}),
            )),
        )
        .await
        .expect("capability disable clears the active callback before waiting")
        .unwrap(),
    );
    let blocked_result = blocked_action.await.unwrap().unwrap();
    assert_eq!(blocked_result.is_error, Some(true));
    assert!(platform.clears.load(Ordering::SeqCst) > clears);
    assert_eq!(platform.actions.load(Ordering::SeqCst), 3);
    let refused = mcp.call_tool(call("android_act", json!({"environment_id":device,"observation_id":fresh["observation_id"],"action":{"type":"click","node_id":"node-1"}}))).await.unwrap();
    assert_eq!(refused.is_error, Some(true));
    assert_eq!(platform.actions.load(Ordering::SeqCst), 3);
    data(
        mcp.call_tool(call(
            "set_execution_environment_capabilities",
            json!({"environment_id":device,"android":true}),
        ))
        .await
        .unwrap(),
    );
    data(
        mcp.call_tool(call("android_observe", json!({"environment_id":device})))
            .await
            .unwrap(),
    );

    let revoked = raw
        .post(format!("{origin}/styx/enroll/revoke"))
        .bearer_auth(&admin)
        .json(&json!({"device_id":device}))
        .send()
        .await
        .unwrap();
    assert_eq!(revoked.status(), reqwest::StatusCode::OK);
    let refused = mcp.call_tool(call("android_act", json!({"environment_id":device,"observation_id":fresh["observation_id"],"action":{"type":"click","node_id":"node-1"}}))).await.unwrap();
    assert_eq!(refused.is_error, Some(true));
    assert_eq!(platform.actions.load(Ordering::SeqCst), 3);
    tokio::time::timeout(Duration::from_secs(20), async {
        while let Some(status) = status_rx.recv().await {
            if status.state == "revoked" {
                return;
            }
        }
        panic!("Host did not report revocation");
    })
    .await
    .expect("real revocation closes authenticated Android Host");
    assert!(matches!(
        host.await.unwrap(),
        Err(ErrorCategory::Unauthorized)
    ));
    mcp.cancel().await.unwrap();
    gateway_stop.cancel();
    let stopped = tokio::time::timeout(Duration::from_secs(15), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(stopped.connections_joined);
    assert!(stopped.blocking_jobs_joined);
    assert!(!stopped.worker_failure_observed);
    std::fs::remove_dir_all(&root).unwrap();
}
