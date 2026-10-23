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
        label: "Owned paired Exec".into(),
        platform: "linux".into(),
        cwd: cwd.to_str().unwrap().into(),
        shell: "/bin/sh".into(),
        computer_requested: false,
        browser_requested: Some(false),
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
    let approved = client.request(Method::POST, "/styx/enroll/approve", Some(admin), &encoded(&json!({"request_id":joined.request_id,"fingerprint":joined.fingerprint,"enable_computer":false,"enable_browser":false}))).await;
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
        partition
            .clone()
            .try_acquire_many_owned(32 * 1024 * 1024)
            .unwrap(),
    )
    .unwrap();
    let mcp_http = GatewayHttp::new(policy, backend.clone(), http_budget);
    let app = EnrollmentHttp::new_paired(tls, shared, relay, mcp_http, vec![host_header.clone()])
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
    let credential = pair(&client, &node, &admin, &device, &root).await;
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
    let endpoint_text = format!("wss://{host_header}/styx/host/v3/{}/exec", device.as_str());
    // Negative upgrades share the actual listener and use independent random
    // connection generations; a later positive path rules out blanket failure.
    for (url, token) in [
        (
            format!("wss://{host_header}/styx/host/v3/styx-2123456789abcdef01234567/exec"),
            credential.credential.expose().to_owned(),
        ),
        (
            format!("wss://{host_header}/styx/hosts/{}/exec", device.as_str()),
            credential.credential.expose().to_owned(),
        ),
        (endpoint_text.clone(), random_token().to_string()),
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
                Err(crate::host::link::LinkError::HandshakeRejected)
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
    let protocol_job = tokio::spawn(async move {
        let protocol = host_task
            .paired_protocol(PairedTrustedProfile {
                endpoint: endpoint_text,
                gateway_namespace: gateway_id,
                device_id: proto_device,
                host_generation: generation,
            })
            .unwrap();
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
    let result = tokio::time::timeout(Duration::from_secs(90), &mut worker).await;
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
        cleanup.native.executor_exited
            && cleanup.native.reader_task_reaped
            && cleanup.native.stderr_task_reaped,
        "native executor and IO tasks actually reaped"
    );
    std::fs::write(
        root.join("paired-observation.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
}
