//! Actual TLS/WSS protocol faults with an explicitly disabled executor. These
//! cases prove transport admission/outcome behavior, never native task effects.
use super::*;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug)]
enum Fault {
    OldPeer,
    Complete,
    WrongDrainId,
    WrongHostGeneration,
    LostResult,
    UnnegotiatedResult,
}
async fn receive(ws: &mut GatewayWs) -> Value {
    let frame = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("bounded original socket response")
        .expect("original socket open")
        .expect("valid original frame");
    serde_json::from_str(frame.to_text().expect("text frame")).unwrap()
}
async fn send_call(ws: &mut GatewayWs, generation: &str, call: Call) {
    let request = Request {
        request_id: uuid::Uuid::new_v4().to_string().try_into().unwrap(),
        connection_generation: Some(generation.to_owned().try_into().unwrap()),
        call,
    };
    ws.send(Message::Text(
        serde_json::to_string(&request).unwrap().into(),
    ))
    .await
    .unwrap();
}
async fn fault_case(mode: Fault) {
    let host = crate::host::bootstrap::OwnedExecHost::reserve(
        "protocol-host-generation".try_into().unwrap(),
        facts(),
        2,
    )
    .unwrap()
    .without_executor()
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
    let server = GatewayServerTls::from_pem(&cert, &key, leaf.clone()).unwrap();
    drop(key);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!(
        "wss://localhost:{}/host-protocol",
        listener.local_addr().unwrap().port()
    );
    let protocol = host
        .paired_protocol(PairedTrustedProfile {
            endpoint: endpoint.clone(),
            gateway_namespace: "gateway-fixture-a".try_into().unwrap(),
            device_id: facts().device_id,
            host_generation: "protocol-host-generation".try_into().unwrap(),
        })
        .unwrap();
    let stop = CancellationToken::new();
    let request_stop = stop.clone();
    let gateway = async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = server.accept(tcp, Duration::from_secs(2)).await.unwrap();
        let mut ws = accept_async(tls).await.unwrap();
        ws.send(envelope(
            "",
            json!({"method":"negotiate","version":3,
            "challenge":"drain-fault-owned-challenge","gateway_namespace":"gateway-fixture-a",
            "gateway_epoch":"gateway-epoch-a"}),
        ))
        .await
        .unwrap();
        let negotiated = receive(&mut ws).await;
        let generation = negotiated["connection_generation"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(
            negotiated["reply"]["features"]
                .as_array()
                .unwrap()
                .contains(&json!(TRANSPORT_DRAIN_V1))
        );
        if matches!(mode, Fault::UnnegotiatedResult) {
            send_call(
                &mut ws,
                &generation,
                Call::TransportDrainResult {
                    drain_id: "unsolicited-drain".try_into().unwrap(),
                    host_generation: "protocol-host-generation".try_into().unwrap(),
                    complete: true,
                },
            )
            .await;
            let frame = tokio::time::timeout(Duration::from_secs(3), ws.next())
                .await
                .unwrap();
            assert!(
                !matches!(frame, Some(Ok(Message::Text(_)))),
                "unsolicited result cannot complete drain"
            );
            return;
        }
        if !matches!(mode, Fault::OldPeer) {
            send_call(&mut ws, &generation, Call::EnableTransportDrain).await;
            assert_eq!(
                receive(&mut ws).await["reply"]["status"],
                "transport_drain_enabled"
            );
        }
        request_stop.cancel();
        if matches!(mode, Fault::OldPeer) {
            let frame = tokio::time::timeout(Duration::from_secs(3), ws.next())
                .await
                .unwrap();
            assert!(
                !matches!(frame, Some(Ok(Message::Text(_)))),
                "old peer must not receive unnegotiated HostControl"
            );
            return;
        }
        let frame = receive(&mut ws).await;
        let HostControl::TransportDrainV1 {
            drain_id,
            connection_generation,
            host_generation,
            timeout_ms,
        } = serde_json::from_value(frame).unwrap();
        assert_eq!(connection_generation.as_str(), generation);
        assert_eq!(host_generation.as_str(), "protocol-host-generation");
        assert!((1..=TRANSPORT_DRAIN_TIMEOUT_MS).contains(&timeout_ms));
        if matches!(mode, Fault::LostResult) {
            return;
        }
        let expected = drain_id.clone();
        send_call(
            &mut ws,
            &generation,
            Call::TransportDrainResult {
                drain_id: if matches!(mode, Fault::WrongDrainId) {
                    "different-drain-id".try_into().unwrap()
                } else {
                    drain_id
                },
                host_generation: if matches!(mode, Fault::WrongHostGeneration) {
                    "new-host-generation".try_into().unwrap()
                } else {
                    host_generation
                },
                complete: true,
            },
        )
        .await;
        if matches!(mode, Fault::Complete) {
            let reply = receive(&mut ws).await;
            assert_eq!(reply["reply"]["status"], "transport_drain_result_accepted");
            assert_eq!(reply["reply"]["drain_id"], expected.as_str());
        } else {
            let frame = tokio::time::timeout(Duration::from_secs(3), ws.next())
                .await
                .unwrap();
            assert!(
                !matches!(frame, Some(Ok(Message::Text(_)))),
                "stale ID/incarnation result must be rejected"
            );
        }
    };
    let host_side = async {
        let tcp = TcpStream::connect(format!(
            "127.0.0.1:{}",
            url::Url::parse(&endpoint).unwrap().port().unwrap()
        ))
        .await
        .unwrap();
        let tls = GatewayClientTls::from_pinned_ca_pem(
            &ca,
            TrustAnchorPin::from_certificate_der(&ca_der),
            Some(leaf),
        )
        .unwrap();
        let mut link = HostWssLink::connect(
            &LinkEndpoint::parse(&endpoint).unwrap(),
            &tls,
            tcp,
            LinkAuthentication::Bearer(
                &SecretBearer::from_protected_reader("owned-drain-fixture-bearer".into()).unwrap(),
            ),
            format!("drain-link-{}", uuid::Uuid::new_v4())
                .try_into()
                .unwrap(),
            host.link_budget(),
        )
        .await
        .unwrap();
        let result = protocol.run_connection_with_stop(&mut link, &stop).await;
        // This always awaits original I/O tasks, including an abrupt peer loss;
        // a close handshake error is not promoted into a remote cleanup fact.
        let _close_result = link.shutdown(Duration::from_secs(2)).await;
        result
    };
    let ((), result) = tokio::time::timeout(Duration::from_secs(15), async {
        tokio::join!(gateway, host_side)
    })
    .await
    .unwrap();
    match mode {
        Fault::Complete => assert_eq!(result, Ok(Some(TransportDrainOutcome::Complete))),
        Fault::OldPeer => assert_eq!(result, Ok(Some(TransportDrainOutcome::Unsupported))),
        _ => assert!(result.is_err() || result == Ok(Some(TransportDrainOutcome::Unknown))),
    }
    let cleanup = host.shutdown_owned(Duration::from_secs(2)).await.unwrap();
    assert!(cleanup.supervised_jobs_joined);
    assert!(
        cleanup.native.is_none(),
        "fixture intentionally has no native executor"
    );
}
#[tokio::test]
#[ignore = "requires isolated STYX_TEST_TLS_FIXTURES; protocol fault evidence, not native acceptance"]
async fn actual_tls_wss_drain_negotiation_stale_result_and_loss() {
    for mode in [
        Fault::OldPeer,
        Fault::Complete,
        Fault::WrongDrainId,
        Fault::WrongHostGeneration,
        Fault::LostResult,
        Fault::UnnegotiatedResult,
    ] {
        fault_case(mode).await;
        println!("actual TLS/WSS Host drain contract {mode:?}: PASS; executor disabled");
    }
}
