use super::*;
use crate::{
    host::link::{HostLinkBudget, LINK_BYTES, LinkAuthentication, SecretBearer},
    providers::codex::{CodexStdio, OwnedExecutorConfig},
    tls::{GatewayClientTls, GatewayLeafPin, GatewayServerTls, PrivateKeyPem, TrustAnchorPin},
};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use styx_contracts::{capability::*, error::Recovery};
use styx_core::{operations::OperationLedger, policy::AdmissionFacts};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Semaphore,
};
use tokio_tungstenite::{WebSocketStream, accept_async, tungstenite::Message};
type GatewayWs = WebSocketStream<tokio_rustls::server::TlsStream<TcpStream>>;
fn facts() -> AdmissionFacts {
    AdmissionFacts {
        device_id: DeviceId::try_from("owned-protocol-device").unwrap(),
        grant_revision: 1,
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
fn owner() -> Value {
    json!({"owner_id":"fixture:owner-a","owner_epoch":"owner-epoch-a"})
}
fn envelope(generation: &str, mut call: Value) -> Message {
    let method = call
        .as_object_mut()
        .unwrap()
        .remove("method")
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    let mut externally_tagged = serde_json::Map::new();
    externally_tagged.insert(method, call);
    let call = Value::Object(externally_tagged);
    Message::Text(json!({"request_id":uuid::Uuid::new_v4().to_string(),"connection_generation":if generation.is_empty(){Value::Null}else{json!(generation)},"call":call}).to_string().into())
}
async fn call(ws: &mut GatewayWs, generation: &str, request: Value) -> Value {
    ws.send(envelope(generation, request)).await.unwrap();
    let response = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let response: Value = serde_json::from_str(response.to_text().unwrap()).unwrap();
    assert_eq!(response["connection_generation"], generation);
    response["reply"].clone()
}
fn spec(root: &Path, file: &str, nonce: &str) -> Value {
    json!({"argv":["/bin/sh","-c",format!("printf '%s\\n' '{nonce}' >> '{file}'; printf '%s' '{nonce}'")],"cwd_file_uri":url::Url::from_directory_path(root).unwrap().to_string(),"environment":{"PATH":"/usr/bin:/bin"},"tty":false})
}
#[derive(Clone, Copy)]
enum Journey {
    Normal,
    LostStart,
    LostRead,
    Reconcile,
    BadVersion,
    BadInitialGeneration,
    StaleGeneration,
}
struct Fixture {
    listener: Arc<TcpListener>,
    server: Arc<GatewayServerTls>,
    tls: GatewayClientTls,
    endpoint: LinkEndpoint,
    bearer: SecretBearer,
    budget: Arc<HostLinkBudget>,
    root: PathBuf,
    nonce: String,
}
async fn journey(
    protocol: &HostProtocol<'_>,
    fixture: &Fixture,
    mode: Journey,
    target: Option<Value>,
    index: u32,
) -> Option<Value> {
    // Host-only random generation; Gateway task receives neither this value nor a clone.
    let generation = format!("protocol-connection-{index}-{}", uuid::Uuid::new_v4());
    let listener = fixture.listener.clone();
    let server = fixture.server.clone();
    let root = fixture.root.clone();
    let nonce = fixture.nonce.clone();
    let gateway = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = server.accept(tcp, Duration::from_secs(2)).await.unwrap();
        let mut ws = accept_async(tls).await.unwrap();
        // Host must not send an unsolicited hello, including on reconnection.
        assert!(
            tokio::time::timeout(Duration::from_millis(30), ws.next())
                .await
                .is_err()
        );
        let version = if matches!(mode, Journey::BadVersion) {
            1
        } else {
            2
        };
        ws.send(envelope(if matches!(mode,Journey::BadInitialGeneration){"untrusted-initial-guess"}else{""},json!({"method":"negotiate","version":version,"challenge":"fixture-side-effect-free-challenge","gateway_namespace":"gateway-fixture-a","gateway_epoch":"gateway-epoch-a"}))).await.unwrap();
        if matches!(mode, Journey::BadVersion | Journey::BadInitialGeneration) {
            let result = tokio::time::timeout(Duration::from_secs(2), ws.next())
                .await
                .unwrap();
            assert!(!matches!(result, Some(Ok(Message::Text(_)))));
            return None;
        }
        let negotiated = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let negotiated: Value = serde_json::from_str(negotiated.to_text().unwrap()).unwrap();
        let server_generation = negotiated["reply"]["connection_generation"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(negotiated["connection_generation"], server_generation);
        if matches!(mode, Journey::StaleGeneration) {
            ws.send(envelope("stale-prior-connection",json!({"method":"prepare_start","owner":owner(),"grant_revision":1,"timeout_ms":10000,"spec":spec(&root,"must-not-execute.txt",&nonce)}))).await.unwrap();
            let result = tokio::time::timeout(Duration::from_secs(2), ws.next())
                .await
                .unwrap();
            assert!(!matches!(result, Some(Ok(Message::Text(_)))));
            return None;
        }
        assert_eq!(
            negotiated["reply"]["challenge"],
            "fixture-side-effect-free-challenge"
        );
        assert_eq!(
            negotiated["reply"]["host_generation"],
            "protocol-host-generation"
        );
        assert_eq!(negotiated["reply"]["device_id"], "owned-protocol-device");
        assert_eq!(negotiated["reply"]["read_resume"], false);
        assert_eq!(
            negotiated["reply"]["owner_issuance"],
            "bootstrap_preverified_only"
        );
        let target = if let Some(target) = target {
            target
        } else {
            let file = if matches!(mode, Journey::LostStart) {
                "lost-start.txt"
            } else {
                "normal.txt"
            };
            let bad=call(&mut ws,&server_generation,json!({"method":"prepare_start","owner":{"owner_id":"spoofed-owner","owner_epoch":"owner-epoch-a"},"grant_revision":1,"timeout_ms":10000,"spec":spec(&root,file,&nonce)})).await;
            assert_eq!(bad["category"], "UNAUTHORIZED");
            assert!(!root.join(file).exists());
            let prepared=call(&mut ws,&server_generation,json!({"method":"prepare_start","owner":owner(),"grant_revision":1,"timeout_ms":10000,"spec":spec(&root,file,&nonce)})).await;
            assert_eq!(prepared["status"], "prepared");
            assert!(!root.join(file).exists(), "prepare cannot execute");
            let snapshot = &prepared["snapshot"];
            let target = json!({"operation_id":snapshot["operation_id"],"payload_digest":snapshot["payload_digest"]});
            std::fs::write(root.join(format!("{file}.operation.json")), serde_json::to_vec_pretty(&json!({"target":target,"nonce":nonce,"connection_generation":server_generation,"stage":"prepared_before_any_dispatch"})).unwrap()).unwrap();
            target
        };
        if matches!(mode, Journey::LostStart) {
            ws.send(envelope(
                &server_generation,
                json!({"method":"dispatch_start","owner":owner(),"target":target}),
            ))
            .await
            .unwrap();
            ws.close(None).await.unwrap();
            return Some(target);
        }
        if matches!(mode, Journey::LostRead) {
            ws.send(envelope(&server_generation,json!({"method":"read","owner":owner(),"target":target,"grant_revision":1,"timeout_ms":10000,"max_bytes":16384,"wait_ms":100}))).await.unwrap();
            ws.close(None).await.unwrap();
            return Some(target);
        }
        let mut tampered = target.clone();
        tampered["payload_digest"] = json!("a".repeat(64));
        let denied = call(
            &mut ws,
            &server_generation,
            json!({"method":"dispatch_start","owner":owner(),"target":tampered}),
        )
        .await;
        assert_eq!(denied["status"], "error");
        let started = call(
            &mut ws,
            &server_generation,
            json!({"method":"dispatch_start","owner":owner(),"target":target}),
        )
        .await;
        assert_eq!(started["status"], "start");
        if matches!(mode, Journey::Reconcile) {
            assert_eq!(started["dispatch"], "existing_no_replay");
        }
        let duplicate = call(
            &mut ws,
            &server_generation,
            json!({"method":"dispatch_start","owner":owner(),"target":target}),
        )
        .await;
        assert_eq!(duplicate["dispatch"], "existing_no_replay");
        for method in ["write", "terminate"] {
            assert_eq!(
                call(&mut ws, &server_generation, json!({"method":method})).await["status"],
                "unsupported"
            );
        }
        let mut output = String::new();
        let mut drained = false;
        for _ in 0..50 {
            let read=call(&mut ws,&server_generation,json!({"method":"read","owner":owner(),"target":target,"grant_revision":1,"timeout_ms":10000,"max_bytes":16384,"wait_ms":100})).await;
            assert_eq!(read["status"], "read");
            assert_eq!(read["read_resume"], false);
            for chunk in read["chunks"].as_array().unwrap() {
                output.push_str(chunk["text"].as_str().unwrap());
            }
            if read["output_drain"] == "drained" {
                assert_eq!(read["liveness"], "exited");
                assert_eq!(read["exit_code"], 0);
                drained = true;
                break;
            }
        }
        assert!(drained);
        if matches!(mode, Journey::Normal) {
            assert_eq!(output, nonce);
        } // Reconcile does not pretend to restore the dropped read response.
        ws.close(None).await.unwrap();
        Some(target)
    });
    let tcp = TcpStream::connect(fixture.listener.local_addr().unwrap())
        .await
        .unwrap();
    let mut link = HostWssLink::connect(
        &fixture.endpoint,
        &fixture.tls,
        tcp,
        LinkAuthentication::Bearer(&fixture.bearer),
        ConnectionGeneration::try_from(generation).unwrap(),
        fixture.budget.clone(),
    )
    .await
    .unwrap();
    let result = protocol.run_connection(&mut link).await;
    if matches!(
        mode,
        Journey::BadVersion | Journey::BadInitialGeneration | Journey::StaleGeneration
    ) {
        assert_eq!(result, Err(ProtocolError::NegotiationRejected));
    } else if matches!(mode, Journey::LostStart | Journey::LostRead) {
        assert_eq!(result, Err(ProtocolError::ResponseLost));
    } else {
        result.unwrap();
    }
    link.shutdown(Duration::from_secs(2)).await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), gateway)
        .await
        .unwrap()
        .unwrap()
}
#[test]
fn raw_spec_and_response_writer_have_explicit_bounds() {
    let raw = r#"{"request_id":"r","connection_generation":"g","call":{"prepare_start":{"owner":{"owner_id":"o","owner_epoch":"e"},"grant_revision":1,"timeout_ms":100,"spec":{"nested":[1,2,3]}}}}"#.to_owned();
    let parsed: Request<'_> = serde_json::from_str(&raw).unwrap();
    match parsed.call {
        Call::PrepareStart { spec, .. } => assert_eq!(spec.get(), r#"{"nested":[1,2,3]}"#),
        _ => panic!(),
    }
    let mut writer = BoundedJson(Vec::new());
    assert!(writer.write_all(&vec![0; RESPONSE_LIMIT + 1]).is_err());
    assert!(writer.0.is_empty());
}
#[tokio::test]
#[ignore = "requires isolated STYX_TEST_CODEX/STYX_TEST_EXEC_ROOT/STYX_TEST_TLS_FIXTURES"]
async fn actual_tls_wss_codex_start_read_duplicate_and_lost_response_batch() {
    let root = PathBuf::from(std::env::var("STYX_TEST_EXEC_ROOT").unwrap())
        .join(uuid::Uuid::new_v4().to_string());
    std::fs::create_dir_all(root.join("codex-home")).unwrap();
    let global = Arc::new(Semaphore::new(styx_contracts::HOST_QUEUED_BYTES));
    // The actual adapter now owns a partition from this same Host source.
    // Protocol heap remains a conservative composition reservation.
    let rpc_partition = global
        .clone()
        .try_acquire_many_owned(16 * 1024 * 1024)
        .unwrap();
    let protocol_partition = global
        .clone()
        .try_acquire_many_owned(8 * 1024 * 1024)
        .unwrap();
    let adapter = CodexStdio::spawn_owned_with_reserved_budget(
        OwnedExecutorConfig {
            binary: std::env::var("STYX_TEST_CODEX").unwrap().into(),
            cwd: root.clone(),
            environment: BTreeMap::from([
                ("PATH".into(), "/usr/bin:/bin".into()),
                ("HOME".into(), root.display().to_string()),
                (
                    "CODEX_HOME".into(),
                    root.join("codex-home").display().to_string(),
                ),
            ]),
            rpc_timeout: Duration::from_secs(2),
            retained_process_limit: 8,
        },
        rpc_partition,
    )
    .await
    .unwrap();
    let (host, authority) = HostCoordinator::new_owned(
        adapter,
        OperationLedger::new(HostGeneration::try_from("protocol-host-generation").unwrap()),
        facts(),
        2,
    )
    .unwrap();
    let pkidir = PathBuf::from(std::env::var("STYX_TEST_TLS_FIXTURES").unwrap());
    let ca = std::fs::read(pkidir.join("ca-a.pem")).unwrap();
    let cert = std::fs::read(pkidir.join("cert-a.pem")).unwrap();
    let key = PrivateKeyPem::from_protected_reader_bytes(
        std::fs::read(pkidir.join("key-a.pem")).unwrap(),
    )
    .unwrap();
    let ca_der = rustls_pemfile::certs(&mut std::io::Cursor::new(&ca))
        .next()
        .unwrap()
        .unwrap();
    let leaf_der = rustls_pemfile::certs(&mut std::io::Cursor::new(&cert))
        .next()
        .unwrap()
        .unwrap();
    let leaf = GatewayLeafPin::from_certificate_der(&leaf_der);
    let server = Arc::new(GatewayServerTls::from_pem(&cert, &key, leaf.clone()).unwrap());
    drop(key);
    let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
    let endpoint = format!(
        "wss://localhost:{}/host-protocol",
        listener.local_addr().unwrap().port()
    );
    let mut protocol = HostProtocol::new(
        TrustedProfile {
            endpoint: endpoint.clone(),
            gateway_namespace: GatewayId::try_from("gateway-fixture-a").unwrap(),
            gateway_epoch: GatewayEpoch::try_from("gateway-epoch-a").unwrap(),
            device_id: facts().device_id,
            host_generation: HostGeneration::try_from("protocol-host-generation").unwrap(),
        },
        host,
        &authority,
    )
    .unwrap();
    protocol
        .register_bootstrap_verified_owner(
            OwnerId::try_from("fixture:owner-a").unwrap(),
            OwnerEpoch::try_from("owner-epoch-a").unwrap(),
        )
        .unwrap();
    protocol
        .register_bootstrap_verified_owner(
            OwnerId::try_from("fixture:owner-a").unwrap(),
            OwnerEpoch::try_from("owner-epoch-a").unwrap(),
        )
        .unwrap();
    let fixture = Fixture {
        listener,
        server,
        tls: GatewayClientTls::from_pinned_ca_pem(
            &ca,
            TrustAnchorPin::from_certificate_der(&ca_der),
            Some(leaf),
        )
        .unwrap(),
        endpoint: LinkEndpoint::parse(&endpoint).unwrap(),
        bearer: SecretBearer::from_protected_reader("fixture-host-bearer".into()).unwrap(),
        budget: HostLinkBudget::from_reserved_partition(
            global
                .clone()
                .try_acquire_many_owned(LINK_BYTES as u32)
                .unwrap(),
        )
        .unwrap(),
        root: root.clone(),
        nonce: uuid::Uuid::new_v4().to_string(),
    };
    journey(&protocol, &fixture, Journey::BadVersion, None, 1).await;
    assert!(!root.join("normal.txt").exists());
    journey(&protocol, &fixture, Journey::BadInitialGeneration, None, 2).await;
    journey(&protocol, &fixture, Journey::StaleGeneration, None, 3).await;
    assert!(!root.join("must-not-execute.txt").exists());
    journey(&protocol, &fixture, Journey::Normal, None, 4).await;
    let lost = journey(&protocol, &fixture, Journey::LostStart, None, 5)
        .await
        .unwrap();
    for _ in 0..100 {
        if root.join("lost-start.txt").exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        std::fs::read_to_string(root.join("lost-start.txt")).unwrap(),
        format!("{}\n", fixture.nonce)
    );
    journey(
        &protocol,
        &fixture,
        Journey::LostRead,
        Some(lost.clone()),
        6,
    )
    .await;
    journey(&protocol, &fixture, Journey::Reconcile, Some(lost), 7).await;
    for name in ["normal.txt", "lost-start.txt"] {
        assert_eq!(
            std::fs::read_to_string(root.join(name)).unwrap(),
            format!("{}\n", fixture.nonce)
        );
    }
    let cleanup = authority
        .shutdown_owned(Duration::from_secs(5))
        .await
        .unwrap();
    assert!(cleanup.supervised_jobs_joined);
    assert!(cleanup.native.executor_exited);
    assert!(cleanup.native.reader_task_reaped);
    assert!(cleanup.native.stderr_task_reaped);
    std::fs::write(root.join("native-cleanup.json"), serde_json::to_vec_pretty(&json!({"supervised_jobs_joined":cleanup.supervised_jobs_joined,"executor_exited":cleanup.native.executor_exited,"reader_task_reaped":cleanup.native.reader_task_reaped,"stderr_task_reaped":cleanup.native.stderr_task_reaped,"native_receipt":format!("{:?}",cleanup.native)})).unwrap()).unwrap();
    drop(fixture);
    drop(protocol_partition);
    drop(protocol);
    drop(authority);
    assert_eq!(
        global.available_permits(),
        styx_contracts::HOST_QUEUED_BYTES
    );
    println!(
        "actual TLS/WSS→HostCoordinator→same owned Codex batch PASS: no unsolicited hello/version1 rejected; bootstrap-only owner; normal nonce+exit0/drain; duplicate/digest/owner negative controls; actual start/read response disconnects retained no-replay, fresh connections same Host/executor; lost read output not claimed restored; independent two nonce files append exactly once; owned cleanup reaped+joined; all Host bytes returned; fixture preverified owners are not real-account issuance"
    );
}

/// New targeted-action journey only. Owners are explicitly preverified by this
/// isolated bootstrap; this is not real-account issuance or legacy compatibility.
#[tokio::test]
#[ignore = "requires isolated STYX_TEST_CODEX/STYX_TEST_EXEC_ROOT/STYX_TEST_TLS_FIXTURES; new canonical WSS action journey only"]
async fn actual_canonical_tls_wss_host_action_journey() {
    use crate::host::bootstrap::OwnedExecHost;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let root = PathBuf::from(std::env::var("STYX_TEST_EXEC_ROOT").unwrap())
        .join(uuid::Uuid::new_v4().to_string());
    std::fs::create_dir_all(root.join("codex-home")).unwrap();
    let host = Arc::new(
        OwnedExecHost::spawn(
            OwnedExecutorConfig {
                binary: std::env::var("STYX_TEST_CODEX").unwrap().into(),
                cwd: root.clone(),
                environment: BTreeMap::from([
                    ("PATH".into(), "/usr/bin:/bin".into()),
                    ("HOME".into(), root.display().to_string()),
                    (
                        "CODEX_HOME".into(),
                        root.join("codex-home").display().to_string(),
                    ),
                ]),
                rpc_timeout: Duration::from_secs(2),
                retained_process_limit: 4,
            },
            HostGeneration::try_from("protocol-action-host-generation").unwrap(),
            facts(),
            2,
        )
        .await
        .unwrap(),
    );
    let expected_unreserved =
        styx_contracts::HOST_QUEUED_BYTES - 16 * 1024 * 1024 - 8 * 1024 * 1024 - LINK_BYTES;
    assert_eq!(host.unreserved_queued_bytes(), expected_unreserved);
    let worker_host = host.clone();
    let worker_root = root.clone();
    // The test retains bootstrap authority outside the worker, so an assertion
    // failure still reaches explicit owned executor cleanup.
    let worker = tokio::spawn(async move {
        let host = worker_host;
        let root = worker_root;
        let pkidir = PathBuf::from(std::env::var("STYX_TEST_TLS_FIXTURES").unwrap());
        let ca = std::fs::read(pkidir.join("ca-a.pem")).unwrap();
        let cert = std::fs::read(pkidir.join("cert-a.pem")).unwrap();
        let key = PrivateKeyPem::from_protected_reader_bytes(
            std::fs::read(pkidir.join("key-a.pem")).unwrap(),
        )
        .unwrap();
        let ca_der = rustls_pemfile::certs(&mut std::io::Cursor::new(&ca))
            .next()
            .unwrap()
            .unwrap();
        let leaf_der = rustls_pemfile::certs(&mut std::io::Cursor::new(&cert))
            .next()
            .unwrap()
            .unwrap();
        let leaf = GatewayLeafPin::from_certificate_der(&leaf_der);
        let server = Arc::new(GatewayServerTls::from_pem(&cert, &key, leaf.clone()).unwrap());
        drop(key);
        let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
        let endpoint = format!(
            "wss://localhost:{}/host-actions",
            listener.local_addr().unwrap().port()
        );
        let mut protocol = host
            .protocol(TrustedProfile {
                endpoint: endpoint.clone(),
                gateway_namespace: GatewayId::try_from("gateway-fixture-a").unwrap(),
                gateway_epoch: GatewayEpoch::try_from("gateway-epoch-a").unwrap(),
                device_id: facts().device_id,
                host_generation: HostGeneration::try_from("protocol-action-host-generation")
                    .unwrap(),
            })
            .unwrap();
        protocol
            .register_bootstrap_verified_owner(
                OwnerId::try_from("fixture:owner-a").unwrap(),
                OwnerEpoch::try_from("owner-epoch-a").unwrap(),
            )
            .unwrap();
        let fixture = Fixture {
            listener,
            server,
            tls: GatewayClientTls::from_pinned_ca_pem(
                &ca,
                TrustAnchorPin::from_certificate_der(&ca_der),
                Some(leaf),
            )
            .unwrap(),
            endpoint: LinkEndpoint::parse(&endpoint).unwrap(),
            bearer: SecretBearer::from_protected_reader("isolated-action-fixture-bearer".into())
                .unwrap(),
            budget: host.link_budget(),
            root: root.clone(),
            nonce: uuid::Uuid::new_v4().to_string(),
        };
        let listener = fixture.listener.clone();
        let server = fixture.server.clone();
        let root = fixture.root.clone();
        let nonce = fixture.nonce.clone();
        let gateway = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let tls = server.accept(tcp, Duration::from_secs(2)).await.unwrap();
            let mut ws = accept_async(tls).await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(30), ws.next())
                    .await
                    .is_err()
            );
            // The Gateway receives neither the Host's local generation nor a
            // clone; only the actual negotiation response can supply it.
            ws.send(envelope("",json!({"method":"negotiate","version":2,"challenge":"action-wire-fixture-challenge","gateway_namespace":"gateway-fixture-a","gateway_epoch":"gateway-epoch-a"}))).await.unwrap();
            let negotiated = tokio::time::timeout(Duration::from_secs(3), ws.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            let negotiated: Value = serde_json::from_str(negotiated.to_text().unwrap()).unwrap();
            let generation = negotiated["reply"]["connection_generation"]
                .as_str()
                .unwrap()
                .to_owned();
            assert_eq!(negotiated["connection_generation"], generation);
            assert_eq!(
                negotiated["reply"]["challenge"],
                "action-wire-fixture-challenge"
            );
            assert_eq!(
                negotiated["reply"]["host_generation"],
                "protocol-action-host-generation"
            );
            assert_eq!(
                negotiated["reply"]["owner_issuance"],
                "bootstrap_preverified_only"
            );
            assert_eq!(negotiated["reply"]["write"], true);
            assert_eq!(negotiated["reply"]["terminate"], true);
            let mut process = spec(&root, "unused", "unused");
            process["argv"] = json!([
                "/bin/sh",
                "-c",
                "read -r line; printf '%s\\n' \"$line\" >> wss-action-effect; printf WSS_ACTION_ACK; read -r hold"
            ]);
            let prepared=call(&mut ws,&generation,json!({"method":"prepare_start","owner":owner(),"grant_revision":1,"timeout_ms":10000,"spec":process})).await;
            assert_eq!(prepared["status"], "prepared");
            let resource = json!({"operation_id":prepared["snapshot"]["operation_id"],"payload_digest":prepared["snapshot"]["payload_digest"]});
            let started = call(
                &mut ws,
                &generation,
                json!({"method":"dispatch_start","owner":owner(),"target":resource}),
            )
            .await;
            assert_eq!(started["dispatch"], "started");
            assert!(!root.join("wss-action-effect").exists());
            let input =
                json!({"kind":"write_stdin","input_base64":STANDARD.encode(format!("{nonce}\n"))});
            let unknown = json!({"owner_id":"unregistered-owner","owner_epoch":"owner-epoch-a"});
            let denied=call(&mut ws,&generation,json!({"method":"prepare_action","owner":unknown,"target":resource,"grant_revision":1,"timeout_ms":10000,"action":input})).await;
            assert_eq!(denied["category"], "UNAUTHORIZED");
            let mut bad_target = resource.clone();
            bad_target["payload_digest"] = json!("a".repeat(64));
            let denied=call(&mut ws,&generation,json!({"method":"prepare_action","owner":owner(),"target":bad_target,"grant_revision":1,"timeout_ms":10000,"action":input})).await;
            assert_eq!(denied["category"], "INTEGRITY_FAILURE");
            let mut bad_target = resource.clone();
            bad_target["operation_id"]["sequence"] = json!(999999);
            let denied=call(&mut ws,&generation,json!({"method":"prepare_action","owner":owner(),"target":bad_target,"grant_revision":1,"timeout_ms":10000,"action":input})).await;
            assert_eq!(denied["category"], "STALE_OPERATION");
            // Prepare only reserves: a wrong grant revision is denied at the
            // first dispatch, where fresh trusted facts are actually available.
            let stale_grant=call(&mut ws,&generation,json!({"method":"prepare_action","owner":owner(),"target":resource,"grant_revision":2,"timeout_ms":10000,"action":input})).await;
            assert_eq!(stale_grant["status"], "prepared");
            let stale_grant_ref = json!({"operation_id":stale_grant["snapshot"]["operation_id"],"payload_digest":stale_grant["snapshot"]["payload_digest"]});
            let denied = call(
                &mut ws,
                &generation,
                json!({"method":"dispatch_action","owner":owner(),"action":stale_grant_ref}),
            )
            .await;
            assert_eq!(denied["category"], "STATE_CONFLICT");
            assert!(!root.join("wss-action-effect").exists());
            let prepared=call(&mut ws,&generation,json!({"method":"prepare_action","owner":owner(),"target":resource,"grant_revision":1,"timeout_ms":10000,"action":input})).await;
            assert_eq!(prepared["status"], "prepared");
            assert!(!root.join("wss-action-effect").exists());
            assert_eq!(prepared["snapshot"]["target"], resource);
            assert_eq!(prepared["snapshot"]["liveness"], "not_applicable");
            let action = json!({"operation_id":prepared["snapshot"]["operation_id"],"payload_digest":prepared["snapshot"]["payload_digest"]});
            assert_ne!(action["operation_id"], resource["operation_id"]);
            let denied = call(
                &mut ws,
                &generation,
                json!({"method":"dispatch_action","owner":unknown,"action":action}),
            )
            .await;
            assert_eq!(denied["category"], "UNAUTHORIZED");
            let mut altered = action.clone();
            altered["payload_digest"] = json!("b".repeat(64));
            let denied = call(
                &mut ws,
                &generation,
                json!({"method":"dispatch_action","owner":owner(),"action":altered}),
            )
            .await;
            assert_eq!(denied["category"], "INTEGRITY_FAILURE");
            assert!(!root.join("wss-action-effect").exists());
            let wrote = call(
                &mut ws,
                &generation,
                json!({"method":"dispatch_action","owner":owner(),"action":action}),
            )
            .await;
            assert_eq!(wrote["status"], "action");
            assert_eq!(wrote["dispatch"], "acknowledged");
            assert_eq!(wrote["snapshot"]["state"], "succeeded");
            assert_eq!(wrote["snapshot"]["liveness"], "not_applicable");
            assert_eq!(wrote["acknowledgment"]["kind"], "write_accepted");
            let duplicate = call(
                &mut ws,
                &generation,
                json!({"method":"dispatch_action","owner":owner(),"action":action}),
            )
            .await;
            assert_eq!(duplicate["dispatch"], "existing_no_replay");
            assert_eq!(duplicate["snapshot"], wrote["snapshot"]);
            assert_eq!(duplicate["write_id"], wrote["write_id"]);
            assert_eq!(duplicate["acknowledgment"], wrote["acknowledgment"]);
            let inspected = call(
                &mut ws,
                &generation,
                json!({"method":"inspect_action","owner":owner(),"action":action}),
            )
            .await;
            assert_eq!(inspected["snapshot"], wrote["snapshot"]);
            assert_eq!(inspected["dispatch"], "existing_no_replay");
            let mut output = String::new();
            for _ in 0..30 {
                let page=call(&mut ws,&generation,json!({"method":"read","owner":owner(),"target":resource,"grant_revision":1,"timeout_ms":10000,"max_bytes":16384,"wait_ms":100})).await;
                assert_eq!(page["status"], "read");
                assert_eq!(page["liveness"], "running");
                for chunk in page["chunks"].as_array().unwrap() {
                    output.push_str(chunk["text"].as_str().unwrap());
                }
                if output == "WSS_ACTION_ACK" {
                    break;
                }
            }
            assert_eq!(output, "WSS_ACTION_ACK");
            assert_eq!(
                std::fs::read_to_string(root.join("wss-action-effect")).unwrap(),
                format!("{nonce}\n")
            );
            let before = call(
                &mut ws,
                &generation,
                json!({"method":"inspect_start","owner":owner(),"target":resource}),
            )
            .await;
            assert_eq!(before["snapshot"]["liveness"], "running");
            let prepared=call(&mut ws,&generation,json!({"method":"prepare_action","owner":owner(),"target":resource,"grant_revision":1,"timeout_ms":10000,"action":{"kind":"terminate"}})).await;
            assert_eq!(prepared["status"], "prepared");
            let terminate = json!({"operation_id":prepared["snapshot"]["operation_id"],"payload_digest":prepared["snapshot"]["payload_digest"]});
            let terminated = call(
                &mut ws,
                &generation,
                json!({"method":"dispatch_action","owner":owner(),"action":terminate}),
            )
            .await;
            assert_eq!(terminated["dispatch"], "acknowledged");
            assert_eq!(terminated["snapshot"]["liveness"], "not_applicable");
            assert_eq!(terminated["acknowledgment"]["kind"], "terminate_requested");
            let after = call(
                &mut ws,
                &generation,
                json!({"method":"inspect_start","owner":owner(),"target":resource}),
            )
            .await;
            assert_eq!(
                after["snapshot"], before["snapshot"],
                "request ACK cannot rewrite original process lifecycle"
            );
            let mut exit = None;
            for _ in 0..50 {
                let page=call(&mut ws,&generation,json!({"method":"read","owner":owner(),"target":resource,"grant_revision":1,"timeout_ms":10000,"max_bytes":16384,"wait_ms":100})).await;
                assert_eq!(page["status"], "read");
                if page["output_drain"] == "drained" {
                    assert_eq!(page["liveness"], "exited");
                    exit = page["exit_code"].as_i64();
                    break;
                }
            }
            assert!(exit.is_some());
            assert_eq!(
                std::fs::read_to_string(root.join("wss-action-effect")).unwrap(),
                format!("{nonce}\n")
            );
            ws.close(None).await.unwrap();
            json!({"root":root,"nonce":nonce,"effectCount":1,"writeAction":action,"writeId":wrote["write_id"],"terminateAction":terminate,
                "nativeExitAfterRead":exit,"generationObservedOnlyFromNegotiation":true,"bootstrapPreverifiedOnly":true,
                "canonicalOwnedExecHostUsed":true,"sameSharedRootBudget":true,"prepareZeroEffect":true,"duplicateNoReplay":true,
                "unknownOwnerChangedDigestTargetGrantDenied":true,"terminateAckDidNotRewriteParent":true})
        });
        let tcp = TcpStream::connect(fixture.listener.local_addr().unwrap())
            .await
            .unwrap();
        // Random connection generation exists only on the Host side until the
        // protocol returns it as part of authenticated negotiation.
        let mut link = HostWssLink::connect(
            &fixture.endpoint,
            &fixture.tls,
            tcp,
            LinkAuthentication::Bearer(&fixture.bearer),
            ConnectionGeneration::try_from(format!("host-action-link-{}", uuid::Uuid::new_v4()))
                .unwrap(),
            fixture.budget.clone(),
        )
        .await
        .unwrap();
        let result = protocol.run_connection(&mut link).await;
        let stopped = link.shutdown(Duration::from_secs(2)).await;
        let gateway = tokio::time::timeout(Duration::from_secs(3), gateway).await;
        result.unwrap();
        stopped.unwrap();
        let observation = gateway.unwrap().unwrap();
        assert_eq!(host.unreserved_queued_bytes(), expected_unreserved);
        println!("WSS_ACTION_OBSERVATION {}", observation);
    });
    let outcome = worker.await;
    let cleanup = host.shutdown_owned(Duration::from_secs(5)).await.unwrap();
    println!("WSS_ACTION_CLEANUP {:?}", cleanup);
    assert!(
        cleanup.supervised_jobs_joined
            && cleanup.native.executor_exited
            && cleanup.native.reader_task_reaped
            && cleanup.native.stderr_task_reaped
    );
    assert_eq!(host.unreserved_queued_bytes(), expected_unreserved);
    outcome.unwrap();
}
