//! Synthetic identities, actual durable enrollment/TLS/MCP/WSS and owned Codex.
//! Kernel/file observations, rather than tool acknowledgments, are the oracle.
use super::*;
use crate::{
    gateway::{
        auth::GatewayBearerPolicy,
        http::GatewayHttp,
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

/// Same frozen Exec contract through different real MCP transports. This is
/// strict-TLS/paired-Host/native-executor evidence, not ChatGPT acceptance.
async fn tunnel_continuation(
    raw: &reqwest::Client,
    uri: &str,
    forwarding: &str,
    device: &DeviceId,
    root: &Path,
) -> Value {
    let connect = || {
        let mut config = StreamableHttpClientTransportConfig::with_uri(uri.to_owned())
            .auth_header(forwarding.to_owned())
            .reinit_on_expired_session(false)
            .max_concurrent_requests(1);
        config.allow_stateless = false;
        ClientConfig::new(
            ClientCapabilities::default(),
            Implementation::new("owned-paired-tunnel-oracle", "1"),
        )
        .with_protocol_version(ProtocolVersion::V_2025_11_25)
        .serve_with_lifecycle(
            StreamableHttpClientTransport::with_client(raw.clone(), config),
            ClientLifecycleMode::Initialize,
        )
    };
    let meta = json!({"openai/organization":"owned-paired-org", "openai/subject":"owned-paired-subject", "openai/session":"owned-paired-conversation"});
    let request = |name: &str, arguments: Value, meta: Value| {
        serde_json::from_value::<CallToolRequestParams>(
            json!({"name":name,"arguments":arguments,"_meta":meta}),
        )
        .unwrap()
    };
    let first = connect().await.unwrap();
    let nonce = uuid::Uuid::new_v4().to_string();
    let command = format!(
        "printf '%s' \"$$\" > tunnel.pid; printf '%s\\n' '{nonce}' >> tunnel-once.txt; printf tunnel-ready; IFS= read -r value; printf '%s' \"$value\" > tunnel-input.txt; printf tunnel-done"
    );
    let started = data(first.call_tool(request("exec_command", json!({"cmd":command,"login":false,"environment_id":device.as_str(),"yield_time_ms":100}), meta.clone())).await.unwrap());
    let sid = started["session_id"].as_u64().expect("live native process");
    file_within(&root.join("tunnel-once.txt"), &format!("{nonce}\n")).await;
    let pid: u32 = std::fs::read_to_string(root.join("tunnel.pid"))
        .unwrap()
        .parse()
        .unwrap();
    assert!(pid > 1);
    let process = PathBuf::from(format!("/proc/{pid}/stat"));
    let birth = read_process_birth(&process).unwrap();
    let second = connect().await.unwrap();
    // A new ChatGPT conversation can discover the same Host task. The
    // authenticated deployment grants access; chat identity is not task ownership.
    let mut next_meta = meta.clone();
    next_meta["openai/session"] = json!("next-chat");
    let listed = data(
        second
            .call_tool(request(
                "list_execution_tasks",
                json!({"environment_id":device}),
                next_meta.clone(),
            ))
            .await
            .unwrap(),
    );
    assert!(
        listed["tasks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["session_id"] == sid)
    );
    first.cancel().await.unwrap();
    assert_eq!(
        read_process_birth(&process).unwrap(),
        birth,
        "deleting first transport must leave the original shell alive"
    );
    let mut output = data(
        second
            .call_tool(request(
                "write_stdin",
                json!({"session_id":sid,"chars":"authorized-tunnel-input\n","yield_time_ms":100}),
                next_meta.clone(),
            ))
            .await
            .unwrap(),
    );
    file_within(&root.join("tunnel-input.txt"), "authorized-tunnel-input").await;
    let until = tokio::time::Instant::now() + Duration::from_secs(5);
    while output["exit_code"].is_null() {
        assert!(
            tokio::time::Instant::now() < until,
            "native exit receipt deadline"
        );
        output = data(
            second
                .call_tool(request(
                    "write_stdin",
                    json!({"session_id":sid,"chars":"","yield_time_ms":100}),
                    next_meta.clone(),
                ))
                .await
                .unwrap(),
        );
    }
    assert_eq!(output["exit_code"], 0);
    let until = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let still_original = match read_process_birth(&process) {
            Ok(actual) => actual == birth,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => panic!("kernel exit observation unknown: {error}"),
        };
        if !still_original {
            break;
        }
        assert!(
            tokio::time::Instant::now() < until,
            "native shell exit deadline"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        std::fs::read_to_string(root.join("tunnel-once.txt")).unwrap(),
        format!("{nonce}\n")
    );
    second.cancel().await.unwrap();
    json!({"native_nonce":nonce,"start_effect_count":1,"host_wss_reconnect":"original task rediscovered without restart","native_pid":pid,"native_starttime":birth,"first_transport_deleted":"original native process survived","different_chat":"same Host task discovered and continued","second_transport_stdin":"independent exact file readback","exit_code":0,"original_shell":"exited","scope":"owned strict-TLS paired Linux/Codex reference, not installed/account acceptance"})
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
    paired_journey(false, 1, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires sockets and STYX_TEST_PAIRED_ROOT/TLS_FIXTURES/CODEX_BIN plus Node22; >1000 actual Gateway/Host owner cycles"]
async fn paired_session_capacity_turnover_requires_sockets() {
    paired_journey(true, 1, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires sockets and STYX_TEST_PAIRED_ROOT/TLS_FIXTURES/CODEX_BIN/NODE22; five real paired Hosts with independent native effects"]
async fn five_connected_computers_exec_requires_sockets() {
    paired_journey(false, 5, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires real TLS/MCP/WSS, pinned Codex/Node/Browser inputs; retained contexts and explicit handoff"]
async fn browser_sessions_survive_chat_close_and_transfer_requires_sockets() {
    paired_journey(false, 1, true).await;
}

async fn paired_journey(capacity: bool, computers: usize, browser_handoff: bool) {
    let browser_enabled = capacity || browser_handoff;
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
    let forwarding = random_token();
    let service = EnrollmentService::recover_existing(
        fresh_store(&root.join("store")),
        admin.as_bytes(),
        Sha256Digest::of_bytes(mcp.as_bytes()),
        vec![host_header.clone()],
    )
    .unwrap();
    let gateway_id = GatewayId::try_from("owned-paired-gateway").unwrap();
    let gateway_epoch =
        GatewayEpoch::try_from(format!("owned-gateway-{}", uuid::Uuid::new_v4())).unwrap();

    let policy = Arc::new(
        GatewayBearerPolicy::new(mcp.as_bytes(), vec![host_header.clone()], vec![])
            .unwrap()
            .with_tunnel_ingress(forwarding.as_bytes())
            .unwrap(),
    );
    // Constructor is composed with the same service, TLS leaf and listener.
    let shared = crate::enrollment::shared::SharedEnrollment::new(service);
    let relay = RelayHandle::new(shared.clone(), gateway_id.clone(), gateway_epoch);
    let backend = Arc::new(PairedGatewayBackend::new(relay.clone()));
    let mcp_http = GatewayHttp::new(policy, backend.clone());
    let app = EnrollmentHttp::new_paired(
        tls,
        shared,
        relay.clone(),
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
    if computers > 1 {
        let work = many_connected_computers(
            &client,
            &admin,
            &mcp,
            &raw,
            &client_tls,
            &gateway_id,
            &relay,
            &root,
            computers,
        );
        let result = tokio::time::timeout(Duration::from_secs(120), work).await;
        stop.cancel();
        let transport = tokio::time::timeout(Duration::from_secs(20), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        node.lock().await.stop().await;
        assert_joined(&transport);
        result.expect("five-computer independent-effect deadline");
        return;
    }
    let device = DeviceId::try_from("styx-1123456789abcdef01234567").unwrap();
    let credential = pair(&client, &node, &admin, &device, &root, browser_enabled).await;
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
            },
            generation.clone(),
            facts(device.clone()),
        )
        .await
        .unwrap(),
    );
    if browser_enabled {
        let mut browser_facts = facts(device.clone());
        browser_facts.descriptor.capability_id = CapabilityId::BrowserHeadless;
        browser_facts.descriptor.scope = Scope::Browser;
        host.authority().configure_browser(browser_facts).unwrap();
    }
    let settings = if browser_handoff {
        let settings = crate::host::settings::HostSettings::open(
            &root,
            crate::host::settings::Capabilities {
                exec: true,
                browser: true,
                computer: false,
            },
        )
        .unwrap();
        settings
            .attach(Arc::new(FixtureCapabilityRuntime {
                host: host.clone(),
                work: root.clone(),
                device: device.clone(),
            }))
            .unwrap();
        Some(settings)
    } else {
        None
    };
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
    let (reconnect_tx, mut reconnect_rx) =
        tokio::sync::mpsc::channel::<tokio::sync::oneshot::Sender<()>>(1);
    let (revoked_sent, revoked_received) = tokio::sync::oneshot::channel();
    let protocol_job = tokio::spawn(async move {
        let make_protocol = || {
            let protocol = host_task
                .paired_protocol(PairedTrustedProfile {
                    endpoint: endpoint_text.clone(),
                    gateway_namespace: gateway_id.clone(),
                    device_id: proto_device.clone(),
                    host_generation: generation.clone(),
                })
                .unwrap();
            let protocol = if browser_enabled {
                protocol
                    .with_browser_profiles(Arc::new(CapacityBrowser {
                        root: host_root.clone(),
                    }))
                    .unwrap()
            } else {
                protocol
            };
            if let Some(settings) = &settings {
                protocol.with_settings(settings.clone())
            } else {
                protocol
            }
        };
        let mut protocol = make_protocol();
        let mut reconnected = None;
        loop {
            let tcp = TcpStream::connect(address).await.unwrap();
            let mut link = HostWssLink::connect(
                &endpoint,
                &proto_tls,
                tcp,
                LinkAuthentication::Bearer(&bearer),
                ConnectionGeneration::try_from(format!("host-wire-{}", uuid::Uuid::new_v4()))
                    .unwrap(),
            )
            .await
            .unwrap();
            if let Some(ready) = reconnected.take() {
                let ready: tokio::sync::oneshot::Sender<()> = ready;
                let _ = ready.send(());
            }
            let result = tokio::select! {
                result = protocol.run_connection(&mut link) => Some(result),
                Some(request) = reconnect_rx.recv() => { reconnected = Some(request); None },
            };
            let shutdown = link.shutdown(Duration::from_secs(5)).await;
            if let Some(result) = result {
                let cleanup = if matches!(
                    &result,
                    Err(crate::host::protocol::ProtocolError::PairingRevoked)
                ) {
                    // The Host supervisor uses the same normal shutdown entry
                    // after an explicit permanent revocation, never after EOF.
                    let facts = host_task
                        .shutdown_owned(Duration::from_secs(10))
                        .await
                        .unwrap();
                    let _ = revoked_sent.send(());
                    Some(facts)
                } else {
                    None
                };
                break (result, shutdown, cleanup);
            }
            drop(protocol);
            protocol = make_protocol();
        }
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
        if browser_handoff {
            browser_session_journey(&raw, &uri, mcp.as_ref(), &device, &reconnect_tx, &root_work)
                .await;
        }
        let tunnel = if !capacity {
            tunnel_continuation(&raw, &uri, &forwarding, &device, &root_work).await
        } else {
            json!("covered by paired native journey")
        };
        let nonce = uuid::Uuid::new_v4().to_string();
        let cmd = format!(
            "printf '%s\\n' '{nonce}' >> once.txt; printf ready; IFS= read -r value; printf '%s' \"$value\" > input.txt; printf done"
        );
        let started = data(
            owner_a
                .call_tool(call(
                    "exec_command",
                    json!({"cmd":cmd,"login":false,"yield_time_ms":100}),
                ))
                .await
                .unwrap(),
        );
        let sid = started["session_id"]
            .as_u64()
            .expect("live process presentation handle");
        file_within(&root_work.join("once.txt"), &format!("{nonce}\n")).await;
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        reconnect_tx.send(ready_tx).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), ready_rx)
            .await
            .unwrap()
            .unwrap();
        // Read-only discovery waits for the new authenticated socket. Neither
        // reconnection nor polling is permission to resend the original start.
        let until = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let listed = owner_b
                .call_tool(call(
                    "list_execution_tasks",
                    json!({"environment_id":device}),
                ))
                .await
                .unwrap();
            if listed.is_error != Some(true) {
                assert!(
                    data(listed)["tasks"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|t| t["session_id"] == sid)
                );
                break;
            }
            assert!(
                tokio::time::Instant::now() < until,
                "Host task rediscovery after actual WSS replacement"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let listed = data(
            owner_b
                .call_tool(call(
                    "list_execution_tasks",
                    json!({"environment_id":device}),
                ))
                .await
                .unwrap(),
        );
        assert!(
            listed["tasks"]
                .as_array()
                .unwrap()
                .iter()
                .any(|t| t["session_id"] == sid)
        );
        let sent = owner_b
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
        // Host tasks from both conversations survive A's session cleanup.
        let waiting = data(owner_b.call_tool(call("exec_command", json!({"cmd":"printf waiting; IFS= read -r value; printf '%s' \"$value\" > survivor.txt","login":false,"environment_id":device.as_str(),"yield_time_ms":100}))).await.unwrap());
        let survivor = waiting["session_id"].as_u64().unwrap();
        let cleanup_resource = data(owner_a.call_tool(call("exec_command", json!({"cmd":"printf '%s' \"$$\" > cleanup.pid; printf cleanup-ready; IFS= read -r never; printf forbidden > cleanup-escaped.txt","login":false,"environment_id":device.as_str(),"yield_time_ms":100}))).await.unwrap());
        let stopped_id = cleanup_resource["session_id"].as_u64().unwrap();
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
        while backend.observed_physical_cleanups() < 1 {
            assert!(
                tokio::time::Instant::now() < until,
                "chat access cleanup deadline"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            read_process_birth(&process_path).unwrap(),
            process_birth,
            "closing chat must preserve Host task"
        );
        let listed = data(
            owner_b
                .call_tool(call(
                    "list_execution_tasks",
                    json!({"environment_id":device}),
                ))
                .await
                .unwrap(),
        );
        assert!(
            listed["tasks"]
                .as_array()
                .unwrap()
                .iter()
                .any(|t| t["session_id"] == stopped_id)
        );
        data(
            owner_b
                .call_tool(call(
                    "stop_execution_task",
                    json!({"environment_id":device,"session_id":stopped_id}),
                ))
                .await
                .unwrap(),
        );
        let until = tokio::time::Instant::now() + Duration::from_secs(8);
        while read_process_birth(&process_path).ok() == Some(process_birth) {
            assert!(
                tokio::time::Instant::now() < until,
                "explicit stop must end original process"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let final_result = data(
            owner_b
                .call_tool(call(
                    "write_stdin",
                    json!({"environment_id":device,"session_id":stopped_id,"chars":""}),
                ))
                .await
                .unwrap(),
        );
        assert!(final_result["exit_code"].is_number());
        let retained = data(
            owner_b
                .call_tool(call(
                    "write_stdin",
                    json!({"environment_id":device,"session_id":stopped_id,"chars":""}),
                ))
                .await
                .unwrap(),
        );
        assert_eq!(
            final_result, retained,
            "terminal result remains available after provider release"
        );
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
        let waiting = data(owner_b.call_tool(call("exec_command",json!({"cmd":"printf '%s' $$ > revoke-task.pid; IFS= read -r value; printf forbidden > revoke-task-escaped.txt","login":false,"environment_id":device,"yield_time_ms":100}))).await.unwrap());
        assert!(waiting["session_id"].is_number());
        let pid_file = root_work.join("revoke-task.pid");
        let until = tokio::time::Instant::now() + Duration::from_secs(5);
        while !pid_file.exists() {
            assert!(tokio::time::Instant::now() < until);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let revoke_pid: u32 = std::fs::read_to_string(pid_file).unwrap().parse().unwrap();
        let revoke_stat = PathBuf::from(format!("/proc/{revoke_pid}/stat"));
        let revoke_birth = read_process_birth(&revoke_stat).unwrap();
        let revoked = client
            .request(
                Method::POST,
                "/styx/enroll/revoke",
                Some(&admin),
                &encoded(&json!({"device_id":device.as_str()})),
            )
            .await;
        assert_eq!(revoked.status, 200);
        assert_eq!(
            serde_json::from_slice::<Value>(&revoked.body).unwrap()["remote_tasks"],
            "unconfirmed"
        );
        tokio::time::timeout(Duration::from_secs(20), revoked_received)
            .await
            .expect("explicit revoke notification and Host cleanup")
            .unwrap();
        assert_ne!(
            read_process_birth(&revoke_stat).ok(),
            Some(revoke_birth),
            "revocation ends the original task"
        );
        assert!(!root_work.join("revoke-task-escaped.txt").exists());
        let after = owner_b.call_tool(call("exec_command", json!({"cmd":"printf forbidden > revoked.txt","login":false,"environment_id":device.as_str()}))).await.unwrap();
        assert_eq!(after.is_error, Some(true));
        assert!(!root_work.join("revoked.txt").exists());
        owner_b.cancel().await.unwrap();
        json!({"native_nonce":nonce,"start_effect_count":1,"tunnel_continuation":tunnel,"wrong_device_legacy_route_wrong_credential_upgrades":"all rejected","cross_conversation_task_access":"listed_and_continued","host_policy_denial":"PERMISSION_DENIED/not_dispatched with no file effect","authorized_stdin":"observed_by_independent_file_read","closed_owner_shell":"survived_chat_close_then_explicit_stop_confirmed", "closed_owner_pid":pid,"closed_owner_starttime":process_birth,"host_physical_cleanup_complete":backend.observed_physical_cleanups()>=1, "other_owner_after_delete":"survived","revoked_device":"new_exec_rejected_and_original_task_stopped_by_Host","scope":"synthetic owned Linux loopback, not native package/account acceptance"})
    });
    let result = tokio::time::timeout(
        Duration::from_secs(if capacity {
            900
        } else if browser_handoff {
            180
        } else {
            90
        }),
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
    node.lock().await.stop().await;
    let transport = transport.unwrap().unwrap().unwrap();
    assert_joined(&transport);
    let (protocol_result, _, cleanup) = protocol
        .expect("owned Host protocol task joined before deadline")
        .expect("owned Host protocol task did not panic");

    let cleanup = match cleanup {
        Some(facts) => facts,
        None => host.shutdown_owned(Duration::from_secs(10)).await.unwrap(),
    };
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
    let report = result.unwrap().unwrap();
    assert!(matches!(
        protocol_result,
        Err(crate::host::protocol::ProtocolError::PairingRevoked)
    ));
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
    async fn new_session(raw: &reqwest::Client, uri: &str, token: &str) -> String {
        let r=post(raw,uri,token,None,json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"retained-host-oracle","version":"1"}}})).await;
        assert_eq!(r.status(), reqwest::StatusCode::OK);
        let sid = r.headers()["mcp-session-id"].to_str().unwrap().to_owned();
        r.bytes().await.unwrap();
        post(
            raw,
            uri,
            token,
            Some(&sid),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        )
        .await
        .bytes()
        .await
        .unwrap();
        sid
    }
    let mut first = None;
    for abandon in [false, true] {
        for n in 0..1050 {
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
            assert!(http.retained_sessions() <= 2100);
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

    http.collect_closed_sessions_for_test().await;
    // Idle HTTP sessions and Host-owned work survive without a background GET.
    // A fresh caller below must discover/continue the original resources.
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

    http.collect_closed_sessions_for_test().await;
    assert!(
        Path::new(&format!("/proc/{pid}/stat")).exists(),
        "expiry must preserve the original running exec"
    );
    let live = new_session(raw, uri, token).await;
    let before = live_allocations();
    let opened = tool(
        raw,
        uri,
        token,
        &live,
        "browser_tabs",
        json!({"action":"new","environment_id":device.as_str()}),
    )
    .await;
    let browser_id = opened["browser_session_id"].as_str().unwrap().to_owned();
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

    http.collect_closed_sessions_for_test().await;
    let live = new_session(raw, uri, token).await;
    tool(
        raw,
        uri,
        token,
        &live,
        "take_over_browser_session",
        json!({"environment_id":device,"browser_session_id":browser_id}),
    )
    .await;
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

    http.collect_closed_sessions_for_test().await;
    assert_eq!(
        raw.get(uri)
            .bearer_auth(token)
            .header("mcp-session-id", &live)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::OK
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
    // Fixture directories preserve evidence; there is no retained owner registry.
    fn release_profile(&self, _: &styx_core::operations::OwnerLease) {}

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

struct FixtureCapabilityRuntime {
    host: Arc<OwnedExecHost>,
    work: PathBuf,
    device: DeviceId,
}
impl crate::host::settings::CapabilityRuntime for FixtureCapabilityRuntime {
    fn apply(
        &self,
        _before: crate::host::settings::Capabilities,
        after: crate::host::settings::Capabilities,
    ) -> futures_util::future::BoxFuture<'_, Result<(), styx_contracts::error::ErrorCategory>> {
        Box::pin(async move {
            self.host
                .authority()
                .stop_disabled_capabilities(after)
                .await?;
            if after.exec && !self.host.coordinator().exec_configured() {
                self.host
                    .enable_executor(
                        OwnedExecutorConfig {
                            binary: PathBuf::from(std::env::var("STYX_TEST_CODEX_BIN").unwrap()),
                            cwd: self.work.clone(),
                            environment: BTreeMap::from([
                                ("PATH".into(), "/usr/bin:/bin".into()),
                                ("HOME".into(), self.work.display().to_string()),
                                (
                                    "CODEX_HOME".into(),
                                    self.work.join("codex-home").display().to_string(),
                                ),
                            ]),
                            rpc_timeout: Duration::from_secs(3),
                        },
                        facts(self.device.clone()),
                    )
                    .await
                    .map_err(|_| styx_contracts::error::ErrorCategory::CapabilityUnsupported)?;
            }
            Ok(())
        })
    }
}

// Real enrollment, production TLS/WSS, independent native Codex processes and
// MCP calls. These roots are disposable and never touch an installed profile.
#[allow(clippy::too_many_arguments)]
async fn many_connected_computers(
    client: &Client,
    admin: &str,
    model: &str,
    raw: &reqwest::Client,
    tls: &Arc<GatewayClientTls>,
    gateway: &GatewayId,
    relay: &RelayHandle,
    root: &Path,
    computers: usize,
) {
    let mut hosts = Vec::new();
    let mut settings_controllers = Vec::new();
    let mut jobs = Vec::new();
    let mut devices = Vec::new();
    let mut nonces = Vec::new();
    for n in 0..computers {
        let work = root.join(format!("computer-{n}"));
        std::fs::create_dir(&work).unwrap();
        std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o700)).unwrap();
        let device = DeviceId::try_from(format!("styx-{n:024x}")).unwrap();
        // Each real computer has its own key/fingerprint, as Core requires.
        let node = Mutex::new(NodeClient::start().await);
        let credential = pair(client, &node, admin, &device, &work, false).await;
        node.lock().await.stop().await;
        let generation =
            HostGeneration::try_from(format!("computer-{n}-{}", uuid::Uuid::new_v4())).unwrap();
        let host = Arc::new(if n + 1 == computers {
            OwnedExecHost::reserve(generation.clone(), facts(device.clone()))
                .unwrap()
                .without_executor()
                .unwrap()
        } else {
            OwnedExecHost::spawn(
                OwnedExecutorConfig {
                    binary: PathBuf::from(std::env::var("STYX_TEST_CODEX_BIN").unwrap()),
                    cwd: work.clone(),
                    environment: BTreeMap::from([
                        ("PATH".into(), "/usr/bin:/bin".into()),
                        ("HOME".into(), work.display().to_string()),
                        (
                            "CODEX_HOME".into(),
                            work.join("codex-home").display().to_string(),
                        ),
                    ]),
                    rpc_timeout: Duration::from_secs(3),
                },
                generation.clone(),
                facts(device.clone()),
            )
            .await
            .unwrap()
        });
        let settings = crate::host::settings::HostSettings::open(
            &work,
            crate::host::settings::Capabilities {
                exec: n + 1 != computers,
                browser: false,
                computer: false,
            },
        )
        .unwrap();
        settings
            .attach(Arc::new(FixtureCapabilityRuntime {
                host: host.clone(),
                work: work.clone(),
                device: device.clone(),
            }))
            .unwrap();
        settings_controllers.push(settings.clone());
        let endpoint = format!(
            "wss://{}/styx/host/v3/{}/exec",
            client.host,
            device.as_str()
        );
        let trusted = PairedTrustedProfile {
            endpoint: endpoint.clone(),
            gateway_namespace: gateway.clone(),
            device_id: device.clone(),
            host_generation: generation,
        };
        let endpoint = LinkEndpoint::parse(&endpoint).unwrap();
        let bearer =
            SecretBearer::from_protected_reader(credential.credential.expose().to_owned()).unwrap();
        let mut link = HostWssLink::connect(
            &endpoint,
            tls,
            TcpStream::connect(client.address).await.unwrap(),
            LinkAuthentication::Bearer(&bearer),
            ConnectionGeneration::try_from(format!("computer-wire-{n}")).unwrap(),
        )
        .await
        .unwrap();
        let stop = CancellationToken::new();
        let run_stop = stop.clone();
        let run_host = host.clone();
        let job = tokio::spawn(async move {
            let protocol = run_host
                .paired_protocol(trusted)
                .unwrap()
                .with_settings(settings);
            let result = protocol
                .run_connection_with_stop(&mut link, &run_stop)
                .await;
            let shutdown = link.shutdown(Duration::from_secs(5)).await;
            (result, shutdown)
        });
        jobs.push((stop, job));
        hosts.push(host);
        devices.push(device);
        nonces.push(uuid::Uuid::new_v4().to_string());
    }
    let until = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if relay
            .devices()
            .await
            .unwrap()
            .iter()
            .filter(|d| d.online)
            .count()
            == computers
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < until,
            "all five physical Host links must be ready together"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(relay.connection_count(), computers);
    let config =
        StreamableHttpClientTransportConfig::with_uri(format!("https://{}/mcp", client.host))
            .auth_header(model.to_owned())
            .reinit_on_expired_session(false)
            .max_concurrent_requests(1);
    let owner = ClientConfig::new(
        ClientCapabilities::default(),
        Implementation::new("many-computers-oracle", "1"),
    )
    .with_protocol_version(serde_json::from_value(json!("2025-11-25")).unwrap())
    .serve_with_lifecycle(
        StreamableHttpClientTransport::with_client(raw.clone(), config),
        ClientLifecycleMode::Initialize,
    )
    .await
    .unwrap();
    // A Host that starts with every capability disabled remains connected and
    // manageable. Enabling Exec starts its first executor within the same Host.
    let initially_disabled = computers - 1;
    assert!(!hosts[initially_disabled].coordinator().exec_configured());
    let status = data(
        owner
            .call_tool(call(
                "get_execution_environment_status",
                json!({"environment_id":devices[initially_disabled].as_str()}),
            ))
            .await
            .unwrap(),
    );
    assert_eq!(status["exec"]["configured"], false);
    assert_eq!(status["exec"]["connection"], "connected");
    data(
        owner
            .call_tool(call(
                "set_execution_environment_capabilities",
                json!({"environment_id":devices[initially_disabled].as_str(),"exec":true}),
            ))
            .await
            .unwrap(),
    );
    assert!(hosts[initially_disabled].coordinator().exec_configured());
    // One MCP conversation targets every Host. Missing targets must remain
    // ambiguous even when one device was used most recently.
    for (name, arguments) in [
        (
            "exec_command",
            json!({"cmd":"printf forbidden > ambiguous-effect.txt","login":false}),
        ),
        ("browser_tabs", json!({"action":"list"})),
        ("list_windows", json!({})),
    ] {
        let result = owner.call_tool(call(name, arguments)).await.unwrap();
        assert_eq!(result.is_error, Some(true));
        let wire = serde_json::to_value(result).unwrap();
        let error: Value =
            serde_json::from_str(wire["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(error["error"], "environment_required", "{name}");
        assert_eq!(error["uncertain"], false);
    }
    for (n, device) in devices.iter().enumerate() {
        let effect = root.join(format!("computer-{n}/independent-effect.txt"));
        assert!(!effect.exists());
        // One dispatch per computer; a missing effect never causes replay.
        let command = format!("printf '%s' '{}' > independent-effect.txt", nonces[n]);
        data(owner.call_tool(call("exec_command", json!({"cmd":command,"login":false,"environment_id":device.as_str(),"yield_time_ms":100}))).await.unwrap());
        file_within(&effect, &nonces[n]).await;
        assert_eq!(relay.connection_count(), computers);
    }
    // The status probe allocates no owner and observes physical computers once,
    // independently of how many Exec/Browser/Computer lanes each advertises.
    let status = raw
        .get(format!("https://{}/mcp", client.host))
        .bearer_auth(model)
        .header("mcp-session-id", "styx-status-observation")
        .send()
        .await
        .unwrap();
    assert_eq!(status.status(), reqwest::StatusCode::NOT_FOUND);
    assert_eq!(
        status.headers()["x-styx-computers-connected"],
        computers.to_string()
    );
    // A running task is stopped by a remote capability change. A second Host's
    // task stays alive and accepts its original stdin; control remains usable
    // with all capabilities disabled, then a local change re-enables Exec.
    let first = data(owner.call_tool(call("exec_command", json!({"cmd":"printf '%s' $$ > settings-task.pid; IFS= read -r value; printf forbidden > settings-old-effect.txt","login":false,"environment_id":devices[0].as_str(),"yield_time_ms":100}))).await.unwrap());
    assert!(first["session_id"].as_u64().is_some());
    let other = data(owner.call_tool(call("exec_command", json!({"cmd":"IFS= read -r value; printf '%s' \"$value\" > unaffected-effect.txt","login":false,"environment_id":devices[1].as_str(),"yield_time_ms":100}))).await.unwrap());
    let disabled = data(owner.call_tool(call("set_execution_environment_capabilities", json!({"environment_id":devices[0].as_str(),"exec":false,"browser":false,"computer":false}))).await.unwrap());
    assert_eq!(disabled["capabilities"]["applied"], true);
    assert!(hosts[0].coordinator().exec_configured());
    let status = data(
        owner
            .call_tool(call(
                "get_execution_environment_status",
                json!({"environment_id":devices[0].as_str()}),
            ))
            .await
            .unwrap(),
    );
    assert_eq!(status["exec"]["configured"], false);
    assert_eq!(relay.connection_count(), computers);
    let refused = owner.call_tool(call("exec_command", json!({"cmd":"printf forbidden > disabled-effect.txt","login":false,"environment_id":devices[0].as_str()}))).await.unwrap();
    assert_eq!(refused.is_error, Some(true));
    data(owner.call_tool(call("write_stdin", json!({"environment_id":devices[1],"session_id":other["session_id"],"chars":"still-running\n","yield_time_ms":100}))).await.unwrap());
    file_within(
        &root.join("computer-1/unaffected-effect.txt"),
        "still-running",
    )
    .await;
    let enabled = settings_controllers[0]
        .update(crate::host::settings::CapabilityPatch {
            exec: Some(true),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(enabled.applied);
    let status = data(
        owner
            .call_tool(call(
                "get_execution_environment_status",
                json!({"environment_id":devices[0].as_str()}),
            ))
            .await
            .unwrap(),
    );
    assert_eq!(status["exec"]["configured"], true);
    data(owner.call_tool(call("exec_command", json!({"cmd":"printf fresh > reenabled-effect.txt","login":false,"environment_id":devices[0].as_str(),"yield_time_ms":100}))).await.unwrap());
    file_within(&root.join("computer-0/reenabled-effect.txt"), "fresh").await;
    assert!(!root.join("computer-0/disabled-effect.txt").exists());
    assert!(!root.join("computer-0/settings-old-effect.txt").exists());
    let reopened = crate::host::settings::HostSettings::open(
        &root.join("computer-0"),
        crate::host::settings::Capabilities {
            exec: false,
            browser: true,
            computer: true,
        },
    )
    .unwrap();
    assert_eq!(reopened.current(), enabled.configured);
    // Keep the other Hosts online while the explicit target disconnects.
    // Neither an explicit offline target nor an omitted target may fall back.
    let (stop, job) = jobs.remove(0);
    stop.cancel();
    let (result, shutdown) = tokio::time::timeout(Duration::from_secs(20), job)
        .await
        .unwrap()
        .unwrap();
    result.unwrap();
    shutdown.unwrap();
    let until = tokio::time::Instant::now() + Duration::from_secs(5);
    while relay
        .devices()
        .await
        .unwrap()
        .iter()
        .any(|d| d.device_id == devices[0] && d.online)
    {
        assert!(
            tokio::time::Instant::now() < until,
            "selected Host must go offline"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    for (target, expected) in [
        (Some(devices[0].as_str()), "offline"),
        (None, "environment_required"),
    ] {
        let mut arguments = json!({"cmd":"printf forbidden > fallback-effect.txt","login":false});
        if let Some(target) = target {
            arguments["environment_id"] = json!(target);
        }
        let result = owner
            .call_tool(call("exec_command", arguments))
            .await
            .unwrap();
        assert_eq!(result.is_error, Some(true));
        let wire = serde_json::to_value(result).unwrap();
        let error: Value =
            serde_json::from_str(wire["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(error["error"], expected);
        assert_eq!(error["uncertain"], false);
    }
    for (n, nonce) in nonces.iter().enumerate() {
        let work = root.join(format!("computer-{n}"));
        assert!(!work.join("fallback-effect.txt").exists());
        assert!(!work.join("ambiguous-effect.txt").exists());
        assert_eq!(
            std::fs::read_to_string(work.join("independent-effect.txt")).unwrap(),
            *nonce
        );
    }
    owner.cancel().await.unwrap();
    for (stop, job) in jobs {
        stop.cancel();
        let (result, shutdown) = tokio::time::timeout(Duration::from_secs(20), job)
            .await
            .unwrap()
            .unwrap();
        result.unwrap();
        shutdown.unwrap();
    }
    for settings in settings_controllers {
        settings.close().await;
    }
    for host in hosts {
        let cleanup = host.shutdown_owned(Duration::from_secs(10)).await.unwrap();
        assert!(
            cleanup.supervised_jobs_joined
                && cleanup.native.as_ref().is_some_and(|n| n.executor_exited
                    && n.reader_task_reaped
                    && n.stderr_task_reaped)
        );
    }
    let until = tokio::time::Instant::now() + Duration::from_secs(5);
    while relay.connection_count() != 0 {
        assert!(
            tokio::time::Instant::now() < until,
            "all disconnected computers release their slots"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    std::fs::write(root.join("many-computers-observation.json"), serde_json::to_vec_pretty(&json!({
        "connected_computers":computers,"devices":devices,"independent_effect_nonces":nonces,
        "capability_settings":"remote disable stops owned Exec; other Host session survives; same local controller re-enables; persisted settings reopen",
        "mcp_conversations":1,"ambiguous_target":"not dispatched for Exec, Browser and Computer Use","offline_target":"not dispatched; no effect on any other Host",
        "effects":"computer-N/independent-effect.txt; exact unique nonce bytes read independently",
        "slots_after_disconnect":0,"scope":"owned loopback TLS/WSS and real native Exec; not installed-platform acceptance"
    })).unwrap()).unwrap();
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
    )
    .unwrap();
    let gateway_id = GatewayId::try_from("owned-paired-gateway").unwrap();
    let gateway_epoch =
        GatewayEpoch::try_from(format!("owned-gateway-{}", uuid::Uuid::new_v4())).unwrap();

    let policy = Arc::new(
        GatewayBearerPolicy::new(mcp.as_bytes(), vec![host_header.clone()], vec![]).unwrap(),
    );
    // Constructor is composed with the same service, TLS leaf and listener.
    let shared = crate::enrollment::shared::SharedEnrollment::new(service);
    let relay = RelayHandle::new(shared.clone(), gateway_id.clone(), gateway_epoch);
    let backend = Arc::new(PairedGatewayBackend::new(relay.clone()));
    let mcp_http = GatewayHttp::new(policy, backend.clone());
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
    // A single paired Host is selected even while offline; readiness must not
    // change device identity or create a request for another target.
    let offline = running
        .call_tool(call("exec_command", json!({"cmd":"printf forbidden"})))
        .await
        .unwrap();
    assert_eq!(offline.is_error, Some(true));
    let wire = serde_json::to_value(offline).unwrap();
    let error: Value = serde_json::from_str(wire["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(error["error"], "offline");
    assert_eq!(error["uncertain"], false);
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
    let revoked = crate::management::native_join_http::exchange_local_computers(
        &origin,
        &client_tls,
        Some(&encoded(&json!({"device_id":second.as_str()}))),
        admin.as_bytes(),
    )
    .await
    .unwrap();
    assert_eq!(revoked.status, 200);
    for (name, args) in [
        ("exec_command", json!({"cmd":"printf forbidden"})),
        ("browser_tabs", json!({"action":"list"})),
        ("list_windows", json!({})),
    ] {
        let result = running.call_tool(call(name, args)).await.unwrap();
        assert_eq!(result.is_error, Some(true));
        let wire = serde_json::to_value(result).unwrap();
        let error: Value =
            serde_json::from_str(wire["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(error["error"], "environment_unavailable", "{name}");
        assert_eq!(error["uncertain"], false);
    }
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
async fn browser_session_journey(
    raw: &reqwest::Client,
    uri: &str,
    token: &str,
    device: &DeviceId,
    reconnect: &tokio::sync::mpsc::Sender<tokio::sync::oneshot::Sender<()>>,
    root: &Path,
) {
    use http_body_util::{BodyExt, Full, Limited};
    use hyper::{Request, Response, body::Incoming, service::service_fn};
    use hyper_util::rt::TokioIo;
    fn snapshot_text(result: &CallToolResult) -> String {
        assert_ne!(result.is_error, Some(true));
        result
            .content
            .iter()
            .filter_map(|c| c.as_text().map(|t| t.text.as_str()))
            .collect::<Vec<_>>()
            .join("\n")
    }
    fn snapshot_ref(text: &str, label: &str) -> String {
        let refs: Vec<_> = text
            .lines()
            .filter(|line| line.contains(label))
            .filter_map(|line| line.split_once("[ref="))
            .filter_map(|(_, rest)| rest.split_once(']'))
            .map(|(reference, _)| reference)
            .collect();
        assert_eq!(refs.len(), 1, "one observed fixture control required");
        assert!(refs[0].starts_with("styx-"));
        refs[0].to_owned()
    }
    let effects = Arc::new(Mutex::new(Vec::<String>::new()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let stop = tokio_util::sync::CancellationToken::new();
    let server_stop = stop.clone();
    let observed = effects.clone();
    let server = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let stream =
                tokio::select! {_=server_stop.cancelled()=>break,r=listener.accept()=>r.unwrap().0};
            let observed = observed.clone();
            connections.spawn(async move {
                let service=service_fn(move |request:Request<Incoming>|{let observed=observed.clone();async move {
                    let body=if request.uri().path()=="/effect" {
                        let body=Limited::new(request.into_body(),4096).collect().await.unwrap().to_bytes();let value=String::from_utf8(body.to_vec()).unwrap();observed.lock().await.push(value.clone());value
                    }else{r#"<!doctype html><title>Browser transfer fixture</title><label>Retained value<input id="retained" aria-label="Retained value"></label><button onclick="fetch('/effect',{method:'POST',body:document.querySelector('#retained').value}).then(r=>r.text()).then(value=>document.querySelector('#saved').textContent='Saved: '+value)">Commit retained value</button><output id="saved"></output>"#.to_owned()};
                    Ok::<_,std::convert::Infallible>(Response::builder().header("connection","close").header("content-type","text/html").body(Full::new(Bytes::from(body))).unwrap())
                }});
                let _=hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream),service).await;
            });
        }
        while connections.join_next().await.is_some() {}
    });
    let connect = || {
        let config = StreamableHttpClientTransportConfig::with_uri(uri.to_owned())
            .auth_header(token.to_owned())
            .reinit_on_expired_session(false)
            .max_concurrent_requests(2);
        ClientConfig::new(
            ClientCapabilities::default(),
            Implementation::new("browser-transfer-oracle", "1"),
        )
        .with_protocol_version(ProtocolVersion::V_2025_11_25)
        .serve_with_lifecycle(
            StreamableHttpClientTransport::with_client(raw.clone(), config),
            ClientLifecycleMode::Initialize,
        )
    };
    let a = connect().await.unwrap();
    let b = connect().await.unwrap();
    let url = format!("http://{address}/");
    let nonce = uuid::Uuid::new_v4().to_string();
    let opened = data(
        a.call_tool(call(
            "browser_navigate",
            json!({"environment_id":device,"url":url}),
        ))
        .await
        .unwrap(),
    );
    let id = opened["browser_session_id"].as_str().unwrap().to_owned();
    let initial = a
        .call_tool(call("browser_snapshot", json!({"environment_id":device})))
        .await
        .unwrap();
    let input = snapshot_ref(&snapshot_text(&initial), "textbox \"Retained value\"");
    data(
        a.call_tool(call(
            "browser_type",
            json!({"environment_id":device,"target":input,"text":nonce}),
        ))
        .await
        .unwrap(),
    );
    let original_snapshot = a
        .call_tool(call("browser_snapshot", json!({"environment_id":device})))
        .await
        .unwrap();
    let before_transfer = snapshot_text(&original_snapshot);
    assert!(
        before_transfer.contains(&nonce),
        "typed value must be independently observed"
    );
    std::fs::write(root.join("browser-before-transfer.txt"), &before_transfer).unwrap();
    let old_ref = snapshot_ref(&before_transfer, "button \"Commit retained value\"");
    let other = data(
        b.call_tool(call(
            "browser_navigate",
            json!({"environment_id":device,"url":url}),
        ))
        .await
        .unwrap(),
    );
    let other_id = other["browser_session_id"].as_str().unwrap().to_owned();
    assert_ne!(id, other_id);
    let isolated=b.call_tool(call("browser_evaluate",json!({"environment_id":device,"function":"() => document.querySelector('#retained').value === ''"}))).await.unwrap();
    assert_ne!(isolated.is_error, Some(true));
    assert!(
        serde_json::to_string(&isolated.content)
            .unwrap()
            .contains("true")
    );
    data(
        b.call_tool(call(
            "take_over_browser_session",
            json!({"environment_id":device,"browser_session_id":id}),
        ))
        .await
        .unwrap(),
    );
    let stale = b
        .call_tool(call(
            "browser_click",
            json!({"environment_id":device,"target":old_ref}),
        ))
        .await
        .unwrap();
    assert_eq!(
        stale.is_error,
        Some(true),
        "old snapshot must be refreshed after transfer"
    );
    let denied=a.call_tool(call("browser_evaluate",json!({"environment_id":device,"function":"async () => {await fetch('/effect',{method:'POST',body:'forbidden'}); return true}"}))).await.unwrap();
    assert_eq!(denied.is_error, Some(true));
    assert!(effects.lock().await.is_empty());
    a.cancel().await.unwrap();
    let (ready, receive) = tokio::sync::oneshot::channel();
    reconnect.send(ready).await.unwrap();
    receive.await.unwrap();
    let until = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let result = b
            .call_tool(call(
                "list_browser_sessions",
                json!({"environment_id":device}),
            ))
            .await
            .unwrap();
        if result.is_error != Some(true) {
            assert!(
                data(result)["sessions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|s| s["browser_session_id"] == id)
            );
            break;
        }
        assert!(tokio::time::Instant::now() < until);
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    b.cancel().await.unwrap();
    let c = connect().await.unwrap();
    let listed = data(
        c.call_tool(call(
            "list_browser_sessions",
            json!({"environment_id":device}),
        ))
        .await
        .unwrap(),
    );
    assert_eq!(listed["sessions"].as_array().unwrap().len(), 2);
    data(
        c.call_tool(call(
            "take_over_browser_session",
            json!({"environment_id":device,"browser_session_id":id}),
        ))
        .await
        .unwrap(),
    );
    let retained = c
        .call_tool(call("browser_snapshot", json!({"environment_id":device})))
        .await
        .unwrap();
    let retained_text = snapshot_text(&retained);
    assert!(
        retained_text.contains(&nonce),
        "typed state must survive transfer and reconnect"
    );
    let button = snapshot_ref(&retained_text, "button \"Commit retained value\"");
    data(
        c.call_tool(call(
            "browser_click",
            json!({"environment_id":device,"target":button}),
        ))
        .await
        .unwrap(),
    );
    let saved = format!("Saved: {nonce}");
    data(
        c.call_tool(call(
            "browser_wait_for",
            json!({"environment_id":device,"text":saved}),
        ))
        .await
        .unwrap(),
    );
    let after_commit = snapshot_text(
        &c.call_tool(call("browser_snapshot", json!({"environment_id":device})))
            .await
            .unwrap(),
    );
    assert!(
        after_commit.contains(&saved),
        "server-confirmed result must be independently observed"
    );
    std::fs::write(root.join("browser-after-commit.txt"), &after_commit).unwrap();
    assert_eq!(*effects.lock().await, vec![nonce.clone()]);
    let d = connect().await.unwrap();
    let original_action=c.call_tool(call("browser_evaluate",json!({"environment_id":device,"function":"async () => {await fetch('/effect',{method:'POST',body:'busy-original'}); await new Promise(r=>setTimeout(r,1000)); return true}"})));
    let concurrent_transfer = async {
        tokio::time::timeout(Duration::from_secs(5), async {
            while effects.lock().await.len() < 2 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let reply = d
            .call_tool(call(
                "take_over_browser_session",
                json!({"environment_id":device,"browser_session_id":id}),
            ))
            .await
            .unwrap();
        assert_eq!(reply.is_error, Some(true));
        assert!(
            serde_json::to_string(&reply)
                .unwrap()
                .contains("capacity_busy")
        );
    };
    let (action_result, ()) = tokio::join!(original_action, concurrent_transfer);
    assert_ne!(action_result.unwrap().is_error, Some(true));
    assert_eq!(
        *effects.lock().await,
        vec![nonce.clone(), "busy-original".to_owned()]
    );
    d.cancel().await.unwrap();
    let disabled = data(
        c.call_tool(call(
            "set_execution_environment_capabilities",
            json!({"environment_id":device,"browser":false}),
        ))
        .await
        .unwrap(),
    );
    assert_eq!(disabled["capabilities"]["configured"]["browser"], false);
    assert_eq!(
        c.call_tool(call("browser_snapshot", json!({"environment_id":device})))
            .await
            .unwrap()
            .is_error,
        Some(true)
    );
    data(
        c.call_tool(call(
            "set_execution_environment_capabilities",
            json!({"environment_id":device,"browser":true}),
        ))
        .await
        .unwrap(),
    );
    assert!(
        data(
            c.call_tool(call(
                "list_browser_sessions",
                json!({"environment_id":device})
            ))
            .await
            .unwrap()
        )["sessions"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let fresh = data(
        c.call_tool(call(
            "browser_navigate",
            json!({"environment_id":device,"url":url}),
        ))
        .await
        .unwrap(),
    );
    assert_ne!(fresh["browser_session_id"], id);
    data(
        c.call_tool(call("browser_close", json!({"environment_id":device})))
            .await
            .unwrap(),
    );
    assert!(
        data(
            c.call_tool(call(
                "list_browser_sessions",
                json!({"environment_id":device})
            ))
            .await
            .unwrap()
        )["sessions"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    c.cancel().await.unwrap();
    stop.cancel();
    server.await.unwrap();
    std::fs::write(root.join("browser-handoff.json"),serde_json::to_vec_pretty(&json!({"status":"PASS","retained_session":id,"independent_session":other_id,"independent_http_effects":*effects.lock().await,"public_form_tools":["browser_snapshot","browser_type","browser_click","browser_wait_for"],"typed_value_independently_observed":true,"submitted_value_independently_observed":true,"chat_close_retained":true,"protocol_rebuilt":true,"previous_operator_denied":true,"old_snapshot_denied":true,"concurrent_transfer_busy":true,"capability_disabled_stopped_sessions":true,"explicit_close_removed_session":true})).unwrap()).unwrap();
}
