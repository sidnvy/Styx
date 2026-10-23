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
