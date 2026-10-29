//! Synthetic identities, actual durable enrollment/TLS/MCP/WSS and owned Codex.
//! Kernel/file observations, rather than tool acknowledgments, are the oracle.
use super::*;
use crate::{
    gateway::{
        auth::GatewayBearerPolicy,
        http::{GatewayHttp, HttpBudget},
        paired::{RelayHandle, backend::PairedGatewayBackend},
    },
    host::{
        bootstrap::OwnedExecHost,
        link::{HostWssLink, LinkAuthentication, LinkEndpoint, SecretBearer},
        protocol::PairedTrustedProfile,
    },
    providers::codex::OwnedExecutorConfig,
};
use rmcp::{
    ClientServiceExt,
    model::*,
    service::ClientLifecycleMode,
    transport::{
        StreamableHttpClientTransport, streamable_http_client::StreamableHttpClientTransportConfig,
    },
};
use std::collections::BTreeMap;
use styx_contracts::{
    capability::*,
    error::Recovery,
    identity::{ConnectionGeneration, GatewayId, HostGeneration},
};
use styx_core::policy::AdmissionFacts;
use tokio::sync::Semaphore;

async fn pair(
    client: &Client,
    node: &Mutex<NodeClient>,
    admin: &str,
    device: &DeviceId,
    cwd: &Path,
    browser: bool,
) -> Unwrapped {
    pair_with_metadata(
        client,
        node,
        admin,
        device,
        cwd,
        browser,
        ("Owned paired Exec", "linux"),
    )
    .await
}
async fn pair_with_metadata(
    client: &Client,
    node: &Mutex<NodeClient>,
    admin: &str,
    device: &DeviceId,
    cwd: &Path,
    browser: bool,
    metadata: (&str, &str),
) -> Unwrapped {
    let invitation = client
        .request(Method::POST, "/styx/enroll/invitations", Some(admin), b"{}")
        .await;
    assert_eq!(invitation.status, 200);
    let invitation: InvitationReply = invitation.decode();
    let mut node = node.lock().await;
    let payload = JoinPayload {
        invitation: invitation.invitation.expose().to_owned(),
        device_id: device.clone(),
        label: metadata.0.into(),
        platform: metadata.1.into(),
        cwd: cwd.to_str().unwrap().into(),
        shell: "/bin/sh".into(),
        computer_requested: false,
        browser_requested: Some(browser),
        public_key_pem: node.hello.public_a.clone(),
    };
    let signature = node.sign_join("a", &payload).await;
    let joined = client
        .request(
            Method::POST,
            "/styx/enroll/join",
            None,
            &encoded(&SignedJoin {
                payload: &payload,
                signature: &signature,
            }),
        )
        .await;
    assert_eq!(joined.status, 202);
    let observed_leaf = joined.leaf;
    let joined: Joined = joined.decode();
    assert_eq!(joined.fingerprint, node.hello.fingerprint_a);
    let comparison = node
        .comparison(
            &format!("https://{}", client.host),
            observed_leaf,
            &joined.request_id,
            joined.fingerprint,
        )
        .await;
    assert_eq!(comparison, joined.comparison_code);
    let approved = client.request(Method::POST, "/styx/enroll/approve", Some(admin), &encoded(&json!({"request_id":joined.request_id,"fingerprint":joined.fingerprint,"enable_computer":false,"enable_browser":browser}))).await;
    assert_eq!(approved.status, 200);
    let claim = ClaimRequest {
        request_id: &joined.request_id,
        claim_secret: joined.claim_secret.expose(),
    };
    let claimed = client
        .request(Method::POST, "/styx/enroll/claim", None, &encoded(&claim))
        .await;
    assert_eq!(claimed.status, 200);
    let claimed: Claimed = claimed.decode();
    let credential = node
        .unwrap("a", &claimed.encrypted_credential, &joined.request_id)
        .await
        .unwrap();
    let confirmed = client
        .request(
            Method::POST,
            "/styx/enroll/confirm",
            None,
            &encoded(&ConfirmRequest {
                request_id: &joined.request_id,
                claim_secret: joined.claim_secret.expose(),
                confirmation: &credential.confirmation,
            }),
        )
        .await;
    assert_eq!(confirmed.status, 200);
    credential
}
fn facts(device: DeviceId) -> AdmissionFacts {
    AdmissionFacts {
        device_id: device,
        grant_revision: 7,
        local_policy_allowed: true,
        descriptor: CapabilityDescriptor {
            contract_version: 1,
            capability_id: CapabilityId::ExecRun,
            scope: Scope::Host,
            provider_id: ProviderId::try_from("codex").unwrap(),
            configured: true,
            remote_grant: true,
            availability: Availability::Available,
            authorization: Authorization::Granted,
            target_session: None,
            reason: None,
            observed_at: 1,
            observation_generation: 1,
            recovery: Recovery::None,
        },
        session_state: None,
        current_observation: None,
    }
}
fn call(name: &str, arguments: Value) -> CallToolRequestParams {
    serde_json::from_value(
        json!({"name":name,"arguments":arguments,"_meta":{"owner":"untrusted-owner-claim"}}),
    )
    .unwrap()
}
fn data(result: CallToolResult) -> Value {
    assert_ne!(
        result.is_error,
        Some(true),
        "typed tool failure: {:?}",
        result.content
    );
    result.structured_content.expect("typed output")
}
async fn file_within(path: &Path, expected: &str) {
    let until = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if std::fs::read_to_string(path).is_ok_and(|text| text == expected) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < until,
            "independent file oracle deadline"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn read_process_birth(path: &Path) -> std::io::Result<u64> {
    let text = std::fs::read_to_string(path)?;
    text.rsplit_once(')')
        .and_then(|(_, rest)| rest.split_whitespace().nth(19))
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "kernel stat starttime missing or invalid",
            )
        })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires owned paired root, fixed Codex/Node22 and TLS fixtures; actual enrollment to MCP/WSS/native Exec journey"]
async fn actual_paired_tls_mcp_codex_nonce_owner_and_revocation_journey() {
    paired_journey(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires sockets and STYX_TEST_PAIRED_ROOT/TLS_FIXTURES/CODEX_BIN plus Node22; >1000 actual Gateway/Host owner cycles"]
async fn paired_session_capacity_turnover_requires_sockets() {
    paired_journey(true).await;
}

async fn paired_journey(capacity: bool) {
    let parent =
        PathBuf::from(std::env::var("STYX_TEST_PAIRED_ROOT").expect("owned root required"));
    std::fs::create_dir_all(&parent).unwrap();
    let root = parent.join(uuid::Uuid::new_v4().to_string());
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let fixture = PathBuf::from(std::env::var("STYX_TEST_TLS_FIXTURES").unwrap());
    let cert = std::fs::read(fixture.join("cert-a.pem")).unwrap();
    let ca = std::fs::read(fixture.join("ca-a.pem")).unwrap();
    let leaf_der = rustls_pemfile::certs(&mut std::io::Cursor::new(&cert))
        .next()
        .unwrap()
        .unwrap();
    let ca_der = rustls_pemfile::certs(&mut std::io::Cursor::new(&ca))
        .next()
        .unwrap()
        .unwrap();
    let leaf = GatewayLeafPin::from_certificate_der(&leaf_der);
    let key = PrivateKeyPem::from_protected_reader_bytes(
        std::fs::read(fixture.join("key-a.pem")).unwrap(),
    )
    .unwrap();
    let tls = Arc::new(GatewayServerTls::from_pem(&cert, &key, leaf.clone()).unwrap());
    drop(key);
    let client_tls = Arc::new(
        GatewayClientTls::from_pinned_ca_pem(
            &ca,
            TrustAnchorPin::from_certificate_der(&ca_der),
            Some(leaf),
        )
        .unwrap(),
    );
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca_der).unwrap();
    let tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let raw = reqwest::Client::builder()
        .tls_backend_preconfigured(tls_config)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let host_header = format!("localhost:{}", address.port());
    let admin = random_token();
    let mcp = random_token();
    let service = EnrollmentService::recover_existing(
        fresh_store(&root.join("store")),
        admin.as_bytes(),
        Sha256Digest::of_bytes(mcp.as_bytes()),
        vec![host_header.clone()],
        Limits::default(),
    )
    .unwrap();
    let gateway_id = GatewayId::try_from("owned-paired-gateway").unwrap();
    let gateway_epoch =
        GatewayEpoch::try_from(format!("owned-gateway-{}", uuid::Uuid::new_v4())).unwrap();
    let partition = Arc::new(Semaphore::new(styx_contracts::HOST_QUEUED_BYTES));
    let policy = Arc::new(
        GatewayBearerPolicy::new(mcp.as_bytes(), vec![host_header.clone()], vec![]).unwrap(),
    );
    // Constructor is composed with the same service, TLS leaf and listener.
    let shared = crate::enrollment::shared::SharedEnrollment::new(service);
    let relay = RelayHandle::new(
        shared.clone(),
        gateway_id.clone(),
        gateway_epoch,
        partition
            .clone()
            .try_acquire_many_owned(16 * 1024 * 1024)
            .unwrap(),
    )
    .unwrap();
    let backend = Arc::new(PairedGatewayBackend::new(relay.clone(), None));
    let http_budget = HttpBudget::from_reserved_partition(
        Arc::new(Semaphore::new(crate::gateway::http::GATEWAY_HTTP_BYTES))
            .try_acquire_many_owned(crate::gateway::http::GATEWAY_HTTP_BYTES as u32)
            .unwrap(),
    )
    .unwrap();
    let mcp_http = GatewayHttp::new(policy, backend.clone(), http_budget);
    let app = EnrollmentHttp::new_paired(
        tls,
        shared,
        relay,
        mcp_http.clone(),
        vec![host_header.clone()],
    )
    .unwrap();
    let stop = CancellationToken::new();
    let app_run = app.clone();
    let run_stop = stop.clone();
    let server = tokio::spawn(async move { app_run.run(listener, run_stop).await });
    let client = Client {
        tls: client_tls.clone(),
        address,
        host: host_header.clone(),
    };
    let node = Mutex::new(NodeClient::start().await);
    let device = DeviceId::try_from("styx-1123456789abcdef01234567").unwrap();
    let credential = pair(&client, &node, &admin, &device, &root, capacity).await;
    let generation =
        HostGeneration::try_from(format!("owned-host-{}", uuid::Uuid::new_v4())).unwrap();
    let codex = PathBuf::from(std::env::var("STYX_TEST_CODEX_BIN").unwrap());
    let host = Arc::new(
        OwnedExecHost::spawn(
            OwnedExecutorConfig {
                binary: codex,
                cwd: root.clone(),
                environment: BTreeMap::from([
                    ("PATH".into(), "/usr/bin:/bin".into()),
                    ("HOME".into(), root.display().to_string()),
                    (
                        "CODEX_HOME".into(),
                        root.join("codex-home").display().to_string(),
                    ),
                ]),
                rpc_timeout: Duration::from_secs(3),
                retained_process_limit: 16,
            },
            generation.clone(),
            facts(device.clone()),
            4,
        )
        .await
        .unwrap(),
    );
    if capacity {
        let mut browser_facts = facts(device.clone());
        browser_facts.descriptor.capability_id = CapabilityId::BrowserHeadless;
        browser_facts.descriptor.scope = Scope::Browser;
        host.authority()
            .configure_browser(browser_facts, host.reserve_browser_io().unwrap())
            .unwrap();
    }
    let endpoint_text = format!("wss://{host_header}/styx/host/v3/{}/exec", device.as_str());
    // Negative upgrades share the actual listener and use independent random
    // connection generations; a later positive path rules out blanket failure.
    for (url, token, expected_status) in [
        (
            format!("wss://{host_header}/styx/host/v3/styx-2123456789abcdef01234567/exec"),
            credential.credential.expose().to_owned(),
            403,
        ),
        (
            format!("wss://{host_header}/styx/hosts/{}/exec", device.as_str()),
            credential.credential.expose().to_owned(),
            404,
        ),
        (endpoint_text.clone(), random_token().to_string(), 403),
    ] {
        let rejected_endpoint = LinkEndpoint::parse(&url).unwrap();
        let rejected_bearer = SecretBearer::from_protected_reader(token).unwrap();
        let attempt = HostWssLink::connect(
            &rejected_endpoint,
            &client_tls,
            TcpStream::connect(address).await.unwrap(),
            LinkAuthentication::Bearer(&rejected_bearer),
            ConnectionGeneration::try_from(format!("rejected-wire-{}", uuid::Uuid::new_v4()))
                .unwrap(),
            host.link_budget(),
        )
        .await;
        assert!(
            matches!(
                attempt,
                Err(crate::host::link::LinkError::UpgradeStatus(status)) if status == expected_status
            ),
            "wrong device, legacy endpoint and wrong credential must each reject the actual upgrade"
        );
    }
    let endpoint = LinkEndpoint::parse(&endpoint_text).unwrap();
    let bearer =
        SecretBearer::from_protected_reader(credential.credential.expose().to_owned()).unwrap();
    let host_task = host.clone();
    let proto_device = device.clone();
    let proto_tls = client_tls.clone();
    let host_root = root.clone();
    let protocol_job = tokio::spawn(async move {
        let protocol = host_task
            .paired_protocol(PairedTrustedProfile {
                endpoint: endpoint_text,
                gateway_namespace: gateway_id,
                device_id: proto_device,
                host_generation: generation,
            })
            .unwrap();
        let protocol = if capacity {
            protocol
                .with_browser_profiles(Arc::new(CapacityBrowser { root: host_root }))
                .unwrap()
        } else {
            protocol
        };
        let tcp = TcpStream::connect(address).await.unwrap();
        let mut link = HostWssLink::connect(
            &endpoint,
            &proto_tls,
            tcp,
            LinkAuthentication::Bearer(&bearer),
            ConnectionGeneration::try_from(format!("host-wire-{}", uuid::Uuid::new_v4())).unwrap(),
            host_task.link_budget(),
        )
        .await
        .unwrap();
        let result = protocol.run_connection(&mut link).await;
        let shutdown = link.shutdown(Duration::from_secs(5)).await;
        (result, shutdown)
    });
    let root_work = root.clone();
    let policy_host = host.clone();
    let mut worker = tokio::spawn(async move {
        let uri = format!("https://{host_header}/mcp");
        let connect = || {
            let config = StreamableHttpClientTransportConfig::with_uri(uri.clone())
                .auth_header(mcp.to_string())
                .reinit_on_expired_session(false)
                .max_sse_event_size(1024 * 1024)
                .max_concurrent_requests(1);
            let transport = StreamableHttpClientTransport::with_client(raw.clone(), config);
            ClientConfig::new(
                ClientCapabilities::default(),
                Implementation::new("owned-paired-oracle", "1"),
            )
            .with_protocol_version(serde_json::from_value(json!("2025-11-25")).unwrap())
            .serve_with_lifecycle(transport, ClientLifecycleMode::Initialize)
        };
        if capacity {
            capacity_cycles(&raw, &uri, mcp.as_ref(), &device, &mcp_http, &root_work).await;
        }
        let owner_a = connect().await.unwrap();
        let owner_b = connect().await.unwrap();
        let public: Value = serde_json::from_str(include_str!(
            "../../../../docs/rust-core-rewrite/PUBLIC-MCP-V1.json"
        ))
        .unwrap();
        assert_eq!(
            serde_json::to_value(owner_a.list_tools(None).await.unwrap().tools).unwrap(),
            public["tools"]
        );
        let until = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let status = owner_a
                .call_tool(call(
                    "get_execution_environment_status",
                    json!({"environment_id":device.as_str()}),
                ))
                .await
                .unwrap();
            if status.is_error != Some(true)
                && status
                    .structured_content
                    .as_ref()
                    .and_then(|v| v["exec"]["connection"].as_str())
                    == Some("connected")
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < until,
                "paired Host ready deadline"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let no_default = owner_a
            .call_tool(call("exec_command", json!({"cmd":"printf forbidden"})))
            .await
            .unwrap();
        assert_eq!(no_default.is_error, Some(true));
        let nonce = uuid::Uuid::new_v4().to_string();
        let cmd = format!(
            "printf '%s\\n' '{nonce}' >> once.txt; printf ready; IFS= read -r value; printf '%s' \"$value\" > input.txt; printf done"
        );
        let started = data(owner_a.call_tool(call("exec_command", json!({"cmd":cmd,"login":false,"environment_id":device.as_str(),"yield_time_ms":100}))).await.unwrap());
        let sid = started["session_id"]
            .as_u64()
            .expect("live process presentation handle");
        file_within(&root_work.join("once.txt"), &format!("{nonce}\n")).await;
        let denied = owner_b
            .call_tool(call(
                "write_stdin",
                json!({"session_id":sid,"chars":"intruder\n","yield_time_ms":100}),
            ))
            .await
            .unwrap();
        assert_eq!(denied.is_error, Some(true));
        assert!(
            !root_work.join("input.txt").exists(),
            "cross-owner input cannot reach process"
        );
        let sent = owner_a
            .call_tool(call(
                "write_stdin",
                json!({"session_id":sid,"chars":"authorized-input\n","yield_time_ms":100}),
            ))
            .await
            .unwrap();
        assert_ne!(sent.is_error, Some(true));
        file_within(&root_work.join("input.txt"), "authorized-input").await;
        assert_eq!(
            std::fs::read_to_string(root_work.join("once.txt")).unwrap(),
            format!("{nonce}\n")
        );
        // Host policy, independently of an unchanged authenticated Gateway
        // connection, must produce a known pre-dispatch denial and no effect.
        let mut denied_facts = facts(device.clone());
        denied_facts.local_policy_allowed = false;
        policy_host.authority().replace_trusted_facts(denied_facts);
        let policy_denied = owner_a.call_tool(call("exec_command", json!({"cmd":"printf forbidden > policy-denied.txt","login":false,"environment_id":device.as_str()}))).await.unwrap();
        assert_eq!(policy_denied.is_error, Some(true));
        let denied_text = policy_denied
            .content
            .first()
            .and_then(|block| block.as_text())
            .expect("typed denial text");
        let denied: Value = serde_json::from_str(&denied_text.text).unwrap();
        assert_eq!(denied["category"], "PERMISSION_DENIED");
        assert_eq!(denied["execution_certainty"], "not_dispatched");
        assert_eq!(denied["cursor_may_be_consumed"], false);
        assert!(!root_work.join("policy-denied.txt").exists());
        policy_host
            .authority()
            .replace_trusted_facts(facts(device.clone()));
        // A live resource belonging to B must survive A's session cleanup.
        let waiting = data(owner_b.call_tool(call("exec_command", json!({"cmd":"printf waiting; IFS= read -r value; printf '%s' \"$value\" > survivor.txt","login":false,"environment_id":device.as_str(),"yield_time_ms":100}))).await.unwrap());
        let survivor = waiting["session_id"].as_u64().unwrap();
        let cleanup_resource = data(owner_a.call_tool(call("exec_command", json!({"cmd":"printf '%s' \"$$\" > cleanup.pid; printf cleanup-ready; IFS= read -r never; printf forbidden > cleanup-escaped.txt","login":false,"environment_id":device.as_str(),"yield_time_ms":100}))).await.unwrap());
        assert!(cleanup_resource["session_id"].as_u64().is_some());
        let pid_path = root_work.join("cleanup.pid");
        let until = tokio::time::Instant::now() + Duration::from_secs(5);
        while !pid_path.exists() {
            assert!(tokio::time::Instant::now() < until);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let pid: u32 = std::fs::read_to_string(&pid_path).unwrap().parse().unwrap();
        assert!(pid > 1);
        let process_path = PathBuf::from(format!("/proc/{pid}/stat"));
        let process_birth = read_process_birth(&process_path)
            .expect("original owned shell has a valid kernel stat");
        owner_a.cancel().await.unwrap();
        let until = tokio::time::Instant::now() + Duration::from_secs(8);
        loop {
            let still_same = match read_process_birth(&process_path) {
                Ok(birth) => birth == process_birth,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                Err(error) => panic!("kernel exit observation is unknown: {error}"),
            };
            if !still_same && backend.observed_physical_cleanups() >= 1 {
                break;
            }
            assert!(
                tokio::time::Instant::now() < until,
                "original shell must exit and Host must attest physical drain/release after owner close"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            !root_work.join("cleanup-escaped.txt").exists(),
            "cleanup cannot replay stdin"
        );
        let continued = owner_b
            .call_tool(call(
                "write_stdin",
                json!({"session_id":survivor,"chars":"still-owned\n","yield_time_ms":100}),
            ))
            .await
            .unwrap();
        assert_ne!(continued.is_error, Some(true));
        file_within(&root_work.join("survivor.txt"), "still-owned").await;
        let revoked = client
            .request(
                Method::POST,
                "/styx/enroll/revoke",
                Some(&admin),
                &encoded(&json!({"device_id":device.as_str()})),
            )
            .await;
        assert_eq!(revoked.status, 200);
        let after = owner_b.call_tool(call("exec_command", json!({"cmd":"printf forbidden > revoked.txt","login":false,"environment_id":device.as_str()}))).await.unwrap();
        assert_eq!(after.is_error, Some(true));
        assert!(!root_work.join("revoked.txt").exists());
        owner_b.cancel().await.unwrap();
        json!({"native_nonce":nonce,"start_effect_count":1,"wrong_device_legacy_route_wrong_credential_upgrades":"all rejected","cross_owner_input":"rejected_without_effect","host_policy_denial":"PERMISSION_DENIED/not_dispatched with no file effect","authorized_stdin":"observed_by_independent_file_read","closed_owner_shell":"original pid/starttime absent", "closed_owner_pid":pid,"closed_owner_starttime":process_birth,"host_physical_cleanup_complete":backend.observed_physical_cleanups()>=1, "other_owner_after_delete":"survived","revoked_device":"new_exec_rejected_without_effect","scope":"synthetic owned Linux loopback, not native package/account acceptance"})
    });
    let result = tokio::time::timeout(
        Duration::from_secs(if capacity { 900 } else { 90 }),
        &mut worker,
    )
    .await;
    if result.is_err() {
        worker.abort();
        let _ = worker.await;
    }
    stop.cancel();
    let transport = tokio::time::timeout(Duration::from_secs(20), server).await;
    let protocol = tokio::time::timeout(Duration::from_secs(10), protocol_job).await;
    let cleanup = host.shutdown_owned(Duration::from_secs(10)).await;
    node.lock().await.stop().await;
    let report = result.unwrap().unwrap();
    let transport = transport.unwrap().unwrap().unwrap();
    assert_joined(&transport);
    let _protocol_result = protocol
        .expect("owned Host protocol task joined before deadline")
        .expect("owned Host protocol task did not panic");
    let cleanup = cleanup.unwrap();
    assert!(cleanup.supervised_jobs_joined);
    assert!(
        cleanup
            .native
            .as_ref()
            .expect("fixture configured Exec")
            .executor_exited
            && cleanup
                .native
                .as_ref()
                .expect("fixture configured Exec")
                .reader_task_reaped
            && cleanup
                .native
                .as_ref()
                .expect("fixture configured Exec")
                .stderr_task_reaped,
        "native executor and IO tasks actually reaped"
    );
    std::fs::write(
        root.join("paired-observation.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
}

async fn capacity_cycles(
    raw: &reqwest::Client,
    uri: &str,
    token: &str,
    device: &DeviceId,
    http: &Arc<GatewayHttp<PairedGatewayBackend>>,
    root: &Path,
) {
    async fn post(
        raw: &reqwest::Client,
        uri: &str,
        token: &str,
        sid: Option<&str>,
        body: Value,
    ) -> reqwest::Response {
        let mut r = raw
            .post(uri)
            .bearer_auth(token)
            .header("accept", "application/json, text/event-stream");
        if let Some(sid) = sid {
            r = r
                .header("mcp-session-id", sid)
                .header("mcp-protocol-version", "2025-11-25");
        }
        r.json(&body).send().await.unwrap()
    }
    async fn tool(
        raw: &reqwest::Client,
        uri: &str,
        token: &str,
        sid: &str,
        name: &str,
        args: Value,
    ) -> Value {
        let r=post(raw,uri,token,Some(sid),json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":name,"arguments":args}})).await;
        assert_eq!(r.status(), reqwest::StatusCode::OK);
        let text = r.text().await.unwrap();
        let reply: Value = if text.starts_with('{') {
            serde_json::from_str(&text).unwrap()
        } else {
            text.lines()
                .filter_map(|line| line.strip_prefix("data:"))
                .find_map(|line| serde_json::from_str::<Value>(line.trim()).ok())
                .unwrap()
        };
        assert!(reply.get("error").is_none(), "{reply}");
        assert_ne!(reply["result"]["isError"], true, "{reply}");
        reply["result"]["structuredContent"].clone()
    }
    let mut first = None;
    for abandon in [false, true] {
        for n in 0..1050 {
            if abandon {
                http.age_idle_sessions_for_test(Duration::from_secs(61));
            }
            let r=post(raw,uri,token,None,json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"paired-capacity-oracle","version":"1"}}})).await;
            assert_eq!(
                r.status(),
                reqwest::StatusCode::OK,
                "cycle {n}, abandon={abandon}"
            );
            let sid = r.headers()["mcp-session-id"].to_str().unwrap().to_owned();
            r.bytes().await.unwrap();
            let r = post(
                raw,
                uri,
                token,
                Some(&sid),
                json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            )
            .await;
            assert_eq!(r.status(), reqwest::StatusCode::ACCEPTED);
            r.bytes().await.unwrap();
            if n == 0 && !abandon {
                let until = tokio::time::Instant::now() + Duration::from_secs(10);
                loop {
                    let status = tool(
                        raw,
                        uri,
                        token,
                        &sid,
                        "get_execution_environment_status",
                        json!({"environment_id":device.as_str()}),
                    )
                    .await;
                    if status["exec"]["connection"] == "connected" {
                        break;
                    }
                    assert!(
                        tokio::time::Instant::now() < until,
                        "Host connection not ready"
                    );
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
            let mut result=tool(raw,uri,token,&sid,"exec_command",json!({"cmd":"printf 'cycle\\n' >> turnover.txt","login":false,"environment_id":device.as_str(),"yield_time_ms":100})).await;
            for _ in 0..50 {
                let Some(process) = result["session_id"].as_u64() else {
                    break;
                };
                result = tool(
                    raw,
                    uri,
                    token,
                    &sid,
                    "write_stdin",
                    json!({"session_id":process,"chars":"","yield_time_ms":100}),
                )
                .await;
            }
            assert_eq!(
                result["exit_code"], 0,
                "must independently settle the original exec before abandoning"
            );
            if first.is_none() {
                first = Some(sid.clone());
            }
            if !abandon {
                let r = raw
                    .delete(uri)
                    .bearer_auth(token)
                    .header("mcp-session-id", &sid)
                    .header("mcp-protocol-version", "2025-11-25")
                    .send()
                    .await
                    .unwrap();
                assert_eq!(r.status(), reqwest::StatusCode::ACCEPTED);
                r.bytes().await.unwrap();
            }
            assert!(http.retained_sessions() <= 64);
        }
    }
    assert_eq!(
        std::fs::read_to_string(root.join("turnover.txt"))
            .unwrap()
            .lines()
            .count(),
        2100,
        "independent native effects"
    );
    http.age_idle_sessions_for_test(Duration::from_secs(601));
    http.expire_idle_for_test().await;
    // Actual native work has no background GET: only backend ownership can
    // protect this session after advancing the test's idle clock.
    let r=post(raw,uri,token,None,json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"live-native-oracle","version":"1"}}})).await;
    assert_eq!(r.status(), reqwest::StatusCode::OK);
    let live = r.headers()["mcp-session-id"].to_str().unwrap().to_owned();
    r.bytes().await.unwrap();
    post(
        raw,
        uri,
        token,
        Some(&live),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    )
    .await
    .bytes()
    .await
    .unwrap();
    let started=tool(raw,uri,token,&live,"exec_command",json!({"cmd":"printf '%s' \"$$\" > protected.pid; IFS= read -r value; printf '%s' \"$value\" > protected.txt","login":false,"environment_id":device.as_str(),"yield_time_ms":100})).await;
    let process = started["session_id"].as_u64().unwrap();
    let until = tokio::time::Instant::now() + Duration::from_secs(5);
    while !root.join("protected.pid").exists() {
        assert!(tokio::time::Instant::now() < until);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let pid = std::fs::read_to_string(root.join("protected.pid")).unwrap();
    assert!(Path::new(&format!("/proc/{pid}/stat")).exists());
    http.age_idle_sessions_for_test(Duration::from_secs(601));
    http.expire_idle_for_test().await;
    assert!(
        Path::new(&format!("/proc/{pid}/stat")).exists(),
        "expiry must preserve the original running exec"
    );
    let before = live_allocations();
    tool(
        raw,
        uri,
        token,
        &live,
        "browser_tabs",
        json!({"action":"new","environment_id":device.as_str()}),
    )
    .await;
    let browser_bytes = live_allocations().saturating_sub(before);
    let mut result = tool(
        raw,
        uri,
        token,
        &live,
        "write_stdin",
        json!({"session_id":process,"chars":"still-owned\n","yield_time_ms":100}),
    )
    .await;
    for _ in 0..50 {
        let Some(process) = result["session_id"].as_u64() else {
            break;
        };
        result = tool(
            raw,
            uri,
            token,
            &live,
            "write_stdin",
            json!({"session_id":process,"chars":"","yield_time_ms":100}),
        )
        .await;
    }
    assert_eq!(result["exit_code"], 0);
    file_within(&root.join("protected.txt"), "still-owned").await;
    http.age_idle_sessions_for_test(Duration::from_secs(601));
    http.expire_idle_for_test().await;
    tool(
        raw,
        uri,
        token,
        &live,
        "browser_tabs",
        json!({"action":"list","environment_id":device.as_str()}),
    )
    .await;
    tool(
        raw,
        uri,
        token,
        &live,
        "browser_close",
        json!({"environment_id":device.as_str()}),
    )
    .await;
    http.age_idle_sessions_for_test(Duration::from_secs(601));
    http.expire_idle_for_test().await;
    assert_eq!(
        raw.get(uri)
            .bearer_auth(token)
            .header("mcp-session-id", &live)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::NOT_FOUND
    );
    println!(
        "SESSION_MEMORY open_native_tab_parent_process_increment={browser_bytes} (Gateway+Host Rust in one fixture; native browser processes excluded)"
    );
    let r = raw
        .get(uri)
        .bearer_auth(token)
        .header("mcp-session-id", first.unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::NOT_FOUND);
    println!(
        "paired production Gateway/Host: 1050 DELETE + 1050 abandoned native-exec owners; status={}",
        http.status()
    );
}

#[allow(unsafe_code)] // glibc read-only, pointer-free allocator statistics; test fixture only.
fn live_allocations() -> usize {
    let info = unsafe { libc::mallinfo2() };
    info.uordblks + info.hblkhd
}
struct CapacityBrowser {
    root: PathBuf,
}
impl crate::host::protocol::browser::BrowserBootstrap for CapacityBrowser {
    fn prepare_profile(
        &self,
        owner: &styx_core::operations::OwnerLease,
    ) -> Result<crate::providers::browser::OwnedBrowserConfig, styx_contracts::error::ErrorCategory>
    {
        let directory = self.root.join(format!(
            "browser-{}",
            Sha256Digest::of_bytes(owner.owner_id().as_str().as_bytes()).to_hex()
        ));
        let profile = directory.join("profile");
        let output = directory.join("output");
        let workspace = directory.join("workspace");
        for path in [&directory, &profile, &output, &workspace] {
            std::fs::create_dir_all(path)
                .map_err(|_| styx_contracts::error::ErrorCategory::IntegrityFailure)?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                .map_err(|_| styx_contracts::error::ErrorCategory::IntegrityFailure)?;
        }
        Ok(crate::providers::browser::OwnedBrowserConfig {
            node_binary: std::env::var_os("STYX_TEST_BROWSER_NODE")
                .expect("owned Node22 input")
                .into(),
            worker_entry: std::env::var_os("STYX_TEST_BROWSER_WORKER")
                .expect("owned worker input")
                .into(),
            browser_binary: std::env::var_os("STYX_TEST_BROWSER_EXECUTABLE")
                .expect("owned browser input")
                .into(),
            workspace_dir: workspace,
            profile_dir: profile,
            output_dir: output,
            rpc_timeout: Duration::from_secs(8),
        })
    }
    fn validate_before_spawn(&self) -> Result<(), styx_contracts::error::ErrorCategory> {
        Ok(())
    }
    fn validate_control(&self) -> Result<(), styx_contracts::error::ErrorCategory> {
        Ok(())
    }
}

/// Real pairing persistence, admin authorization and MCP discovery; no native
/// operation is executed by this inventory/revocation scenario.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires sockets, STYX_TEST_PAIRED_ROOT, STYX_TEST_TLS_FIXTURES and STYX_TEST_NODE22; two real paired identities"]
async fn named_computers_revoke_requires_sockets() {
    let parent =
        PathBuf::from(std::env::var("STYX_TEST_PAIRED_ROOT").expect("owned root required"));
    std::fs::create_dir_all(&parent).unwrap();
    let root = parent.join(uuid::Uuid::new_v4().to_string());
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let fixture = PathBuf::from(std::env::var("STYX_TEST_TLS_FIXTURES").unwrap());
    let cert = std::fs::read(fixture.join("cert-a.pem")).unwrap();
    let ca = std::fs::read(fixture.join("ca-a.pem")).unwrap();
    let leaf_der = rustls_pemfile::certs(&mut std::io::Cursor::new(&cert))
        .next()
        .unwrap()
        .unwrap();
    let ca_der = rustls_pemfile::certs(&mut std::io::Cursor::new(&ca))
        .next()
        .unwrap()
        .unwrap();
    let leaf = GatewayLeafPin::from_certificate_der(&leaf_der);
    let key = PrivateKeyPem::from_protected_reader_bytes(
        std::fs::read(fixture.join("key-a.pem")).unwrap(),
    )
    .unwrap();
    let tls = Arc::new(GatewayServerTls::from_pem(&cert, &key, leaf.clone()).unwrap());
    drop(key);
    let client_tls = Arc::new(
        GatewayClientTls::from_pinned_ca_pem(
            &ca,
            TrustAnchorPin::from_certificate_der(&ca_der),
            Some(leaf),
        )
        .unwrap(),
    );
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca_der).unwrap();
    let tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let raw = reqwest::Client::builder()
        .tls_backend_preconfigured(tls_config)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let host_header = format!("localhost:{}", address.port());
    let admin = random_token();
    let mcp = random_token();
    let service = EnrollmentService::recover_existing(
        fresh_store(&root.join("store")),
        admin.as_bytes(),
        Sha256Digest::of_bytes(mcp.as_bytes()),
        vec![host_header.clone()],
        Limits::default(),
    )
    .unwrap();
    let gateway_id = GatewayId::try_from("owned-paired-gateway").unwrap();
    let gateway_epoch =
        GatewayEpoch::try_from(format!("owned-gateway-{}", uuid::Uuid::new_v4())).unwrap();
    let partition = Arc::new(Semaphore::new(styx_contracts::HOST_QUEUED_BYTES));
    let policy = Arc::new(
        GatewayBearerPolicy::new(mcp.as_bytes(), vec![host_header.clone()], vec![]).unwrap(),
    );
    // Constructor is composed with the same service, TLS leaf and listener.
    let shared = crate::enrollment::shared::SharedEnrollment::new(service);
    let relay = RelayHandle::new(
        shared.clone(),
        gateway_id.clone(),
        gateway_epoch,
        partition
            .clone()
            .try_acquire_many_owned(16 * 1024 * 1024)
            .unwrap(),
    )
    .unwrap();
    let backend = Arc::new(PairedGatewayBackend::new(relay.clone(), None));
    let http_budget = HttpBudget::from_reserved_partition(
        Arc::new(Semaphore::new(crate::gateway::http::GATEWAY_HTTP_BYTES))
            .try_acquire_many_owned(crate::gateway::http::GATEWAY_HTTP_BYTES as u32)
            .unwrap(),
    )
    .unwrap();
    let mcp_http = GatewayHttp::new(policy, backend.clone(), http_budget);
    let app = EnrollmentHttp::new_paired(
        tls,
        shared,
        relay,
        mcp_http.clone(),
        vec![host_header.clone()],
    )
    .unwrap();
    let stop = CancellationToken::new();
    let app_run = app.clone();
    let run_stop = stop.clone();
    let server = tokio::spawn(async move { app_run.run(listener, run_stop).await });
    let client = Client {
        tls: client_tls.clone(),
        address,
        host: host_header.clone(),
    };

    let node_a = Mutex::new(NodeClient::start().await);
    let node_b = Mutex::new(NodeClient::start().await);
    let first = DeviceId::try_from("styx-1123456789abcdef01234567").unwrap();
    let second = DeviceId::try_from("styx-2123456789abcdef01234567").unwrap();
    let _first_credential = pair_with_metadata(
        &client,
        &node_a,
        &admin,
        &first,
        &root,
        false,
        ("Desk Linux", "linux"),
    )
    .await;
    let _second_credential = pair_with_metadata(
        &client,
        &node_b,
        &admin,
        &second,
        &root,
        false,
        ("Travel Mac", "darwin"),
    )
    .await;
    let uri = format!("https://{host_header}/mcp");
    let transport = StreamableHttpClientTransport::with_client(
        raw,
        StreamableHttpClientTransportConfig::with_uri(uri)
            .auth_header(mcp.to_string())
            .reinit_on_expired_session(false),
    );
    let running = ClientConfig::new(
        ClientCapabilities::default(),
        Implementation::new("named-computers-test", "1"),
    )
    .serve_with_lifecycle(transport, ClientLifecycleMode::Initialize)
    .await
    .unwrap();
    let list = data(
        running
            .call_tool(call("list_execution_environments", json!({})))
            .await
            .unwrap(),
    );
    let environments = list["environments"].as_array().unwrap();
    assert_eq!(environments.len(), 2);
    for (id, label, platform) in [
        (&first, "Desk Linux", "linux"),
        (&second, "Travel Mac", "macos"),
    ] {
        let env = environments
            .iter()
            .find(|e| e["environment_id"] == id.as_str())
            .unwrap();
        assert_eq!(env["label"], label);
        assert_eq!(env["platform"], platform);
        let status = data(
            running
                .call_tool(call(
                    "get_execution_environment_status",
                    json!({"environment_id":id.as_str()}),
                ))
                .await
                .unwrap(),
        );
        assert_eq!(status["label"], label);
        assert_eq!(status["platform"], platform);
    }
    let body = encoded(&json!({"device_id":first.as_str()}));
    // Model credentials and unauthenticated callers cannot administer pairings.
    for bearer in [None, Some(mcp.as_ref())] {
        assert_ne!(
            client
                .request(Method::POST, "/styx/enroll/revoke", bearer, &body)
                .await
                .status,
            200
        );
    }
    assert_eq!(
        data(
            running
                .call_tool(call("list_execution_environments", json!({})))
                .await
                .unwrap()
        )["environments"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let origin = url::Url::parse(&format!("https://{host_header}/")).unwrap();
    let inventory = crate::management::native_join_http::exchange_local_computers(
        &origin,
        &client_tls,
        None,
        admin.as_bytes(),
    )
    .await
    .unwrap();
    assert_eq!(inventory.status, 200);
    let rows: Value = serde_json::from_slice(&inventory.body).unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 2);
    let revoked = crate::management::native_join_http::exchange_local_computers(
        &origin,
        &client_tls,
        Some(&body),
        admin.as_bytes(),
    )
    .await
    .unwrap();
    assert_eq!(revoked.status, 200);
    let list = data(
        running
            .call_tool(call("list_execution_environments", json!({})))
            .await
            .unwrap(),
    );
    assert_eq!(list["environments"].as_array().unwrap().len(), 1);
    assert_eq!(list["environments"][0]["environment_id"], second.as_str());
    assert_eq!(list["environments"][0]["label"], "Travel Mac");
    let removed = running
        .call_tool(call(
            "get_execution_environment_status",
            json!({"environment_id":first.as_str()}),
        ))
        .await
        .unwrap();
    assert_eq!(removed.is_error, Some(true));
    let inventory = client
        .request(Method::GET, "/styx/enroll/devices", Some(&admin), &[])
        .await;
    let rows: Value = inventory.decode();
    assert_eq!(
        rows.as_array()
            .unwrap()
            .iter()
            .find(|r| r["device_id"] == first.as_str())
            .unwrap()["status"],
        "revoked"
    );
    running.cancel().await.unwrap();
    node_a.lock().await.stop().await;
    node_b.lock().await.stop().await;
    stop.cancel();
    assert_joined(
        &tokio::time::timeout(Duration::from_secs(20), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
    );
}
