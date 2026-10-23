use super::*;
use crate::tls::{GatewayLeafPin, GatewayServerTls, PrivateKeyPem, TrustAnchorPin};
use tokio_tungstenite::{
    accept_hdr_async,
    tungstenite::handshake::server::{Request, Response},
};

#[test]
fn endpoint_credentials_and_partition_are_fail_closed() {
    for url in [
        "ws://localhost/",
        "wss://user:secret@localhost/",
        "wss://localhost/?bearer=secret",
        "wss://localhost/#secret",
    ] {
        assert!(LinkEndpoint::parse(url).is_err());
    }
    assert!(SecretBearer::from_protected_reader("x\r\ny".into()).is_err());
    let bearer = SecretBearer::from_protected_reader("test-only-secret".into()).unwrap();
    assert_eq!(format!("{bearer:?}"), "SecretBearer([REDACTED])");
    let sem = Arc::new(Semaphore::new(1));
    assert!(HostLinkBudget::from_reserved_partition(sem.try_acquire_owned().unwrap()).is_err());
}

// Tungstenite Callback fixes its rejection type to an unboxed HTTP response.
#[allow(clippy::result_large_err)]
#[tokio::test]
#[ignore = "requires STYX_TEST_TLS_FIXTURES isolated test PKI"]
async fn strict_tls_wss_data_heartbeat_limits_close_cleanup_batch() {
    let fixture = std::path::PathBuf::from(std::env::var("STYX_TEST_TLS_FIXTURES").unwrap());
    let ca = std::fs::read(fixture.join("ca-a.pem")).unwrap();
    let cert = std::fs::read(fixture.join("cert-a.pem")).unwrap();
    let key = PrivateKeyPem::from_protected_reader_bytes(
        std::fs::read(fixture.join("key-a.pem")).unwrap(),
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
    let tls = GatewayClientTls::from_pinned_ca_pem(
        &ca,
        TrustAnchorPin::from_certificate_der(&ca_der),
        Some(leaf),
    )
    .unwrap();
    drop(key);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let endpoint =
        LinkEndpoint::parse(&format!("wss://localhost:{}/host-link", address.port())).unwrap();
    let bearer = SecretBearer::from_protected_reader("isolated-test-token".into()).unwrap();
    let nonce = uuid::Uuid::new_v4().to_string();
    let expected_nonce = nonce.clone();
    let (heartbeat_tx, heartbeat_rx) = oneshot::channel();
    let serving = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let stream = server.accept(tcp, Duration::from_secs(2)).await.unwrap();
        let mut ws = accept_hdr_async(stream, |request: &Request, response: Response| {
            assert_eq!(request.uri().path(), "/host-link");
            assert_eq!(
                request.headers().get("authorization").unwrap(),
                "Bearer isolated-test-token"
            );
            assert!(!request.headers().contains_key("origin"));
            assert!(!request.headers().contains_key("sec-websocket-protocol"));
            Ok(response)
        })
        .await
        .unwrap();
        assert_eq!(
            ws.next().await.unwrap().unwrap().into_text().unwrap(),
            expected_nonce
        );
        ws.send(Message::Text("native-handler-still-waiting".into()))
            .await
            .unwrap();
        ws.send(Message::Ping(b"live-heartbeat".to_vec().into()))
            .await
            .unwrap();
        let pong = tokio::time::timeout(Duration::from_millis(500), ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(pong, Message::Pong(b"live-heartbeat".to_vec().into()));
        heartbeat_tx.send(()).unwrap();
        // This oversized remote text is independently emitted, never passed
        // through the client's outbound check. Client must end the generation.
        ws.send(Message::Text("x".repeat(MAX_MESSAGE + 1).into()))
            .await
            .unwrap();
        let closed = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .unwrap();
        assert!(!matches!(closed, Some(Ok(Message::Text(_)))));
        // Independent fresh generations: explicit close and inbound delivery
        // saturation are separate from the oversized frame case above.
        for saturation in [false, true] {
            let (tcp, _) = listener.accept().await.unwrap();
            let stream = server.accept(tcp, Duration::from_secs(2)).await.unwrap();
            let mut ws = accept_hdr_async(stream, |request: &Request, response: Response| {
                assert_eq!(
                    request.headers().get("authorization").unwrap(),
                    "Bearer isolated-test-token"
                );
                assert!(!request.headers().contains_key("origin"));
                Ok(response)
            })
            .await
            .unwrap();
            if saturation {
                for value in ["queued-one", "queued-two", "must-close"] {
                    ws.send(Message::Text(value.into())).await.unwrap();
                }
            } else {
                ws.send(Message::Close(None)).await.unwrap();
            }
            let closed = tokio::time::timeout(Duration::from_secs(2), ws.next())
                .await
                .unwrap();
            assert!(!matches!(closed, Some(Ok(Message::Text(_)))));
        }
    });
    let host_sem = Arc::new(Semaphore::new(styx_contracts::HOST_QUEUED_BYTES));
    let budget = HostLinkBudget::from_reserved_partition(
        host_sem
            .clone()
            .try_acquire_many_owned(LINK_BYTES as u32)
            .unwrap(),
    )
    .unwrap();
    let generation = ConnectionGeneration::try_from("owned-wss-generation-1").unwrap();
    let mut link = HostWssLink::connect(
        &endpoint,
        &tls,
        TcpStream::connect(address).await.unwrap(),
        LinkAuthentication::Bearer(&bearer),
        generation.clone(),
        budget.clone(),
    )
    .await
    .unwrap();
    assert_eq!(
        host_sem.available_permits(),
        styx_contracts::HOST_QUEUED_BYTES - LINK_BYTES
    );
    assert_eq!(
        link.send_text("x".repeat(MAX_MESSAGE + 1), Duration::from_secs(1))
            .await,
        Err(SendFailure::NotSent(LinkError::TooLarge))
    );
    let spare_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let spare_tcp = TcpStream::connect(spare_listener.local_addr().unwrap())
        .await
        .unwrap();
    assert!(matches!(
        HostWssLink::connect(
            &endpoint,
            &tls,
            spare_tcp,
            LinkAuthentication::Bearer(&bearer),
            ConnectionGeneration::try_from("must-not-connect").unwrap(),
            budget.clone()
        )
        .await,
        Err(LinkError::Capacity)
    ));
    drop(spare_listener);
    let sender = link.sender();
    assert_eq!(sender.generation(), &generation);
    let stale_sender = sender.clone();
    let sending =
        tokio::spawn(async move { sender.send_text(nonce, Duration::from_secs(1)).await });
    let incoming = link.recv().await.unwrap();
    sending.await.unwrap().unwrap();
    assert_eq!(incoming.generation, generation);
    assert_eq!(incoming.as_str(), "native-handler-still-waiting");
    // Simulate a native RPC handler that keeps its delivered frame and does not
    // call recv again: heartbeat still completes through the independent reader.
    tokio::time::timeout(Duration::from_secs(1), heartbeat_rx)
        .await
        .unwrap()
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        tokio::time::timeout(Duration::from_secs(2), link.recv())
            .await
            .unwrap()
            .is_none()
    );
    link.shutdown(Duration::from_secs(2)).await.unwrap();
    assert_eq!(
        stale_sender
            .send_text("must-not-revive-generation".into(), Duration::from_secs(1))
            .await,
        Err(SendFailure::NotSent(LinkError::Closed))
    );
    drop(budget);
    // Delivered text itself retains the same Host partition until dropped.
    assert_eq!(
        host_sem.available_permits(),
        styx_contracts::HOST_QUEUED_BYTES - LINK_BYTES
    );
    drop(incoming);
    assert_eq!(
        host_sem.available_permits(),
        styx_contracts::HOST_QUEUED_BYTES
    );
    for (index, saturation) in [false, true].into_iter().enumerate() {
        let budget = HostLinkBudget::from_reserved_partition(
            host_sem
                .clone()
                .try_acquire_many_owned(LINK_BYTES as u32)
                .unwrap(),
        )
        .unwrap();
        let mut link = HostWssLink::connect(
            &endpoint,
            &tls,
            TcpStream::connect(address).await.unwrap(),
            LinkAuthentication::Bearer(&bearer),
            ConnectionGeneration::try_from(format!("owned-fresh-generation-{}", index + 2))
                .unwrap(),
            budget.clone(),
        )
        .await
        .unwrap();
        if saturation {
            // Deliberately do not consume while all three texts arrive.
            tokio::time::sleep(Duration::from_millis(100)).await;
            let first = link.recv().await.unwrap();
            let second = link.recv().await.unwrap();
            assert_eq!(first.as_str(), "queued-one");
            assert_eq!(second.as_str(), "queued-two");
            assert!(link.recv().await.is_none());
            drop((first, second));
        } else {
            assert!(
                tokio::time::timeout(Duration::from_secs(2), link.recv())
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        link.shutdown(Duration::from_secs(2)).await.unwrap();
        drop(budget);
        assert_eq!(
            host_sem.available_permits(),
            styx_contracts::HOST_QUEUED_BYTES
        );
    }
    tokio::time::timeout(Duration::from_secs(2), serving)
        .await
        .unwrap()
        .unwrap();
    println!(
        "strict AWS-LC TLS+actual WSS batch PASS: independent nonce readback, bearer header only/no Origin, no v2 inference, heartbeat while handler holds frame, outbound+remote inbound 2MiB bounds, oversize/explicit-close/full-inbound generations ended, second link refused by partition, tasks+server joined, shared Host budget returned only after delivered frame drop"
    );
}
