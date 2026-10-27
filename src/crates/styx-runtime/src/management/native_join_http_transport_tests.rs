//! Real TCP + strict TLS response-boundary regressions. Fresh synthetic keys,
//! no enrollment store, identity, product action, redirect or business retry.
use super::*;
use crate::tls::{GatewayServerTls, generate_gateway_ca, issue_server_leaf};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
};

const BUDGET: Duration = Duration::from_secs(5);
const COMPLETE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}";

struct Fixture {
    client: GatewayClientTls,
    refused: GatewayClientTls,
    server: Arc<GatewayServerTls>,
}
impl Fixture {
    fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let ca = generate_gateway_ca(now, now - 60, now + 86400).unwrap();
        let leaf = issue_server_leaf(
            &ca.certificate_pem,
            &ca.private_key,
            &ca.anchor_pin,
            "https://127.0.0.1:4444/",
            now,
        )
        .unwrap();
        let client = GatewayClientTls::from_pinned_ca_pem(
            &ca.certificate_pem,
            ca.anchor_pin.clone(),
            Some(leaf.leaf_pin.clone()),
        )
        .unwrap();
        let refused = GatewayClientTls::from_pinned_ca_pem(
            &ca.certificate_pem,
            ca.anchor_pin,
            Some(GatewayLeafPin::parse_hex(&"0".repeat(64)).unwrap()),
        )
        .unwrap();
        let server = Arc::new(
            GatewayServerTls::from_pem(
                &leaf.certificate_chain_pem,
                &leaf.private_key,
                leaf.leaf_pin,
            )
            .unwrap(),
        );
        Self {
            client,
            refused,
            server,
        }
    }
}
#[derive(Clone, Copy)]
enum Tail {
    ResetOnClientClose,
    ResetAfterWrite,
    Hold,
}

// One actual accepted connection, one whole request, one response. The returned
// task is always joined by its caller, including when the client result fails.
async fn serve(
    f: &Fixture,
    response: Vec<u8>,
    tail: Tail,
) -> (
    url::Url,
    oneshot::Sender<()>,
    tokio::task::JoinHandle<usize>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = url::Url::parse(&format!("https://{}/", listener.local_addr().unwrap())).unwrap();
    let server = f.server.clone();
    let (release, released) = oneshot::channel();
    let task = tokio::spawn(async move {
        let (tcp, _) = tokio::time::timeout(BUDGET, listener.accept())
            .await
            .unwrap()
            .unwrap();
        let mut tls = server.accept(tcp, BUDGET).await.unwrap();
        let mut request = Vec::new();
        let mut chunk = [0; 1024];
        let header_end = loop {
            let n = tls.read(&mut chunk).await.unwrap();
            assert!(n > 0 && request.len() + n <= 16384);
            request.extend_from_slice(&chunk[..n]);
            if let Some(i) = request.windows(4).position(|b| b == b"\r\n\r\n") {
                break i + 4;
            }
        };
        // The fixed test request is always exactly two body bytes; observing it
        // proves a transport error is after dispatch, without printing its data.
        while request.len() < header_end + 2 {
            let n = tls.read(&mut chunk).await.unwrap();
            assert!(n > 0);
            request.extend_from_slice(&chunk[..n]);
        }
        assert_eq!(request.len(), header_end + 2);
        tls.write_all(&response).await.unwrap();
        tls.flush().await.unwrap();
        match tail {
            Tail::ResetOnClientClose => {
                // Legacy Hyper waits for the TLS shutdown after a complete
                // bounded response; this peer refuses that tail with a real RST.
                let _ = tokio::time::timeout(BUDGET, tls.read(&mut chunk))
                    .await
                    .unwrap();
            }
            Tail::ResetAfterWrite => (),
            Tail::Hold => {
                let _ = tokio::time::timeout(BUDGET, released).await.unwrap();
            }
        }
        #[allow(deprecated)] // Test-only real OS RST, no custom socket FFI.
        tls.get_ref().0.set_linger(Some(Duration::ZERO)).unwrap();
        drop(tls);
        request.len()
    });
    (origin, release, task)
}
async fn join_peer(task: tokio::task::JoinHandle<usize>) {
    assert!(
        tokio::time::timeout(Duration::from_secs(8), task)
            .await
            .unwrap()
            .unwrap()
            > 2
    );
}

#[tokio::test]
async fn complete_tls_response_is_final_before_connection_tail_but_incomplete_is_unknown() {
    let f = Fixture::new();

    let keepalive = String::from_utf8(COMPLETE.to_vec())
        .unwrap()
        .replace("Connection: close", "Connection: keep-alive")
        .into_bytes();
    // Baseline: an actually collected body is followed by a real TCP reset.
    // Keeping the original sender open makes the connection read that tail,
    // rather than racing a successful local shutdown before the peer resets.
    let (origin, release, task) = serve(&f, keepalive.clone(), Tail::Hold).await;
    let tcp = TcpStream::connect(("127.0.0.1", origin.port().unwrap()))
        .await
        .unwrap();
    let tls = f.client.connect("127.0.0.1", tcp, BUDGET).await.unwrap();
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake::<_, Full<Bytes>>(TokioIo::new(tls))
            .await
            .unwrap();
    let request = Request::builder()
        .method(hyper::Method::POST)
        .uri("/styx/enroll/confirm")
        .header(header::HOST, origin.authority())
        .body(Full::new(Bytes::from_static(b"{}")))
        .unwrap();
    let response = async {
        let response = sender.send_request(request).await.unwrap();
        assert_eq!(response.status(), 200);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let _ = release.send(());
        body
    };
    let (body, tail) = tokio::time::timeout(BUDGET, async { tokio::join!(response, connection) })
        .await
        .unwrap();
    drop(sender);
    join_peer(task).await;
    assert_eq!(body.as_ref(), b"{}");
    let tail = tail.expect_err("the negative control must actually reset the TLS connection tail");
    let observation = HttpFailureObservation::capture(
        unknown(JoinHttpErrorKind::Http),
        HttpFailureStage::Connection,
        &tail,
        true,
        true,
    );
    assert_eq!(observation.io_kind, Some("connection_reset"));

    // Drive the exact private ownership helper used by product exchange with
    // that same real-TLS condition. Body success closes local IO immediately;
    // the later real peer RST cannot replace it. No invented IO error is used.
    let (origin, release, task) = serve(&f, keepalive, Tail::Hold).await;
    let tcp = TcpStream::connect(("127.0.0.1", origin.port().unwrap()))
        .await
        .unwrap();
    let tls = f.client.connect("127.0.0.1", tcp, BUDGET).await.unwrap();
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake::<_, Full<Bytes>>(TokioIo::new(tls))
            .await
            .unwrap();
    let request = Request::builder()
        .method(hyper::Method::POST)
        .uri("/styx/enroll/confirm")
        .header(header::HOST, origin.authority())
        .body(Full::new(Bytes::from_static(b"{}")))
        .unwrap();
    let response = async {
        let response = sender
            .send_request(request)
            .await
            .map_err(|_| unknown(JoinHttpErrorKind::Http))?;
        assert_eq!(response.status(), 200);
        let body = Limited::new(response.into_body(), RESPONSE_BYTES)
            .collect()
            .await
            .map_err(|_| unknown(JoinHttpErrorKind::Http))?
            .to_bytes();
        let _ = release.send(());
        Ok(body)
    };
    let body = tokio::time::timeout(BUDGET, finish_response_owned(response, connection)).await;
    drop(sender);
    join_peer(task).await;
    assert_eq!(body.unwrap().unwrap().as_ref(), b"{}");

    let (origin, release, task) = serve(&f, COMPLETE.to_vec(), Tail::ResetOnClientClose).await;
    let response = exchange(
        &origin,
        &f.client,
        "/styx/enroll/confirm",
        b"{}",
        None,
        BUDGET,
    )
    .await;
    drop(release);
    join_peer(task).await;
    let response = response.unwrap();
    assert_eq!(response.status, 200);
    assert!(response.body.as_slice() == b"{}");

    // A complete response must not wait for an unrelated remote close. A result
    // received within this bound releases only this peer's test-only tail.
    let (origin, release, task) = serve(&f, COMPLETE.to_vec(), Tail::Hold).await;
    let response = tokio::time::timeout(
        Duration::from_secs(2),
        exchange(
            &origin,
            &f.client,
            "/styx/enroll/confirm",
            b"{}",
            None,
            BUDGET,
        ),
    )
    .await;
    let _ = release.send(());
    join_peer(task).await;
    assert_eq!(response.unwrap().unwrap().status, 200);

    // Truncation, malformed response, length excess and redirect remain unknown
    // after one actually observed request. No response body grants enrollment.
    let cases = [
        (b"HTTP/1.1 200 OK\r\nContent-Length: 32\r\nConnection: close\r\n\r\n{}".to_vec(), JoinHttpErrorKind::Http, Tail::ResetAfterWrite),
        (b"HTTP/1.1 200 OK\r\nInvalid Header: value\r\n\r\n{}".to_vec(), JoinHttpErrorKind::Http, Tail::ResetAfterWrite),
        ([format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", RESPONSE_BYTES + 1).into_bytes(),vec![b'x';RESPONSE_BYTES + 1]].concat(), JoinHttpErrorKind::ResponseTooLarge, Tail::Hold),
        (b"HTTP/1.1 302 Found\r\nContent-Length: 0\r\nLocation: https://wrong.invalid/\r\nConnection: close\r\n\r\n".to_vec(), JoinHttpErrorKind::RedirectRefused, Tail::Hold),
    ];
    for (wire, kind, tail) in cases {
        let (origin, release, task) = serve(&f, wire, tail).await;
        let result = exchange(
            &origin,
            &f.client,
            "/styx/enroll/confirm",
            b"{}",
            None,
            BUDGET,
        )
        .await;
        drop(release);
        join_peer(task).await;
        let error = result.err().unwrap();
        assert_eq!(error.kind, kind);
        assert_eq!(error.certainty, JoinHttpCertainty::ResultUnknown);
    }

    let (origin, release, task) = serve(&f, Vec::new(), Tail::Hold).await;
    let result = exchange(
        &origin,
        &f.client,
        "/styx/enroll/confirm",
        b"{}",
        None,
        Duration::from_secs(1),
    )
    .await;
    let _ = release.send(());
    join_peer(task).await;
    let error = result.err().unwrap();
    assert_eq!(error.kind, JoinHttpErrorKind::Deadline);
    assert_eq!(error.certainty, JoinHttpCertainty::ResultUnknown);

    // Certificate validation precedes any request dispatch, even when the CA
    // is trusted but the exact expected peer leaf pin is deliberately wrong.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = url::Url::parse(&format!("https://{}/", listener.local_addr().unwrap())).unwrap();
    let server = f.server.clone();
    let peer = tokio::spawn(async move {
        let (tcp, _) = tokio::time::timeout(BUDGET, listener.accept())
            .await
            .unwrap()
            .unwrap();
        match server.accept(tcp, BUDGET).await {
            Ok(mut tls) => {
                let mut byte = [0];
                match tokio::time::timeout(BUDGET, tls.read(&mut byte))
                    .await
                    .unwrap()
                {
                    Ok(n) => n,
                    Err(_) => 0,
                }
            }
            Err(_) => 0,
        }
    });
    let result = exchange(
        &origin,
        &f.refused,
        "/styx/enroll/confirm",
        b"{}",
        None,
        BUDGET,
    )
    .await;
    let application_bytes = tokio::time::timeout(BUDGET, peer).await.unwrap().unwrap();
    let error = result.err().unwrap();
    assert_eq!(error.kind, JoinHttpErrorKind::Tls(TlsError::PinMismatch));
    assert_eq!(error.certainty, JoinHttpCertainty::NotDispatched);
    assert_eq!(application_bytes, 0);
}
