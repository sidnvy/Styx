use super::*;
use crate::tls::{GatewayServerTls, generate_gateway_ca, issue_server_leaf};
use std::sync::Mutex;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

#[derive(Default)]
struct MemoryStore(Mutex<Option<Zeroizing<String>>>);
impl CredentialStore for MemoryStore {
    fn load(&self) -> Result<Option<Zeroizing<String>>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .as_ref()
            .map(|v| Zeroizing::new(v.to_string())))
    }
    fn save(&self, json: &str) -> Result<()> {
        *self.0.lock().unwrap() = Some(Zeroizing::new(json.into()));
        Ok(())
    }
}
async fn fixture(
    phase: Phase,
) -> (
    MemoryStore,
    TcpListener,
    GatewayServerTls,
    DeviceId,
    Sha256Digest,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("https://{}", listener.local_addr().unwrap());
    let now = now_ms().unwrap();
    let ca = generate_gateway_ca(now / 1000, now / 1000 - 60, now / 1000 + 86400).unwrap();
    let leaf = issue_server_leaf(
        &ca.certificate_pem,
        &ca.private_key,
        &ca.anchor_pin,
        &origin,
        now / 1000,
    )
    .unwrap();
    let device_id: DeviceId = "styx-0123456789abcdef01234567".try_into().unwrap();
    let fingerprint = Sha256Digest::of_bytes(b"synthetic-identity");
    let request_id = "0123456789abcdef0123456789abcdef";
    let comparison = styx_contracts::legacy::PairingComparison {
        gateway_origin: origin.clone(),
        certificate_sha256: leaf.leaf_pin.as_hex().try_into().unwrap(),
        request_id: request_id.into(),
        device_fingerprint: fingerprint,
    }
    .comparison_code()
    .unwrap();
    let pending = serde_json::json!({
        "status":"pending", "request_id":request_id, "comparison_code":comparison,
        "expires_at":now + 60_000, "fingerprint":fingerprint,
        "claim_secret":"synthetic-claim-secret-with-more-than-32-characters",
        "ingress":{"origin":origin,"certificate_sha256":leaf.leaf_pin.as_hex()}
    });
    let record = Record {
        schema: 1,
        identity: protocol::JoinIdentity {
            schema: 2,
            gateway_origin: origin,
            device_id: device_id.clone(),
            fingerprint,
            public_key_pem: String::new(),
            label: "Synthetic Android".into(),
            platform: "android".into(),
            cwd: String::new(),
            shell: String::new(),
            computer_requested: false,
            browser_requested: false,
        },
        ca_pem: String::from_utf8(ca.certificate_pem.to_vec()).unwrap(),
        anchor_sha256: ca.anchor_pin.as_hex().try_into().unwrap(),
        private_key_pem: "synthetic-key-not-used-for-get-self".into(),
        phase,
        pending: Some(Pending {
            body: pending.to_string(),
            leaf_sha256: leaf.leaf_pin.as_hex(),
        }),
        credential: Some("synthetic-device-credential-with-more-than-32-characters".into()),
    };
    let store = MemoryStore::default();
    record.persist(&store).unwrap();
    let server = GatewayServerTls::from_pem(
        &leaf.certificate_chain_pem,
        &leaf.private_key,
        leaf.leaf_pin,
    )
    .unwrap();
    (store, listener, server, device_id, fingerprint)
}

#[tokio::test]
async fn confirmation_response_loss_is_resolved_by_authenticated_self_without_replaying_confirmation()
 {
    let (store, listener, tls, device_id, fingerprint) = fixture(Phase::ConfirmDispatched).await;
    let device = device_id.clone();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut stream = tls.accept(tcp, Duration::from_secs(5)).await.unwrap();
        let mut request = Vec::new();
        let mut chunk = [0; 2048];
        while !request.windows(4).any(|v| v == b"\r\n\r\n") {
            let n = stream.read(&mut chunk).await.unwrap();
            assert_ne!(n, 0);
            request.extend_from_slice(&chunk[..n]);
        }
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with(&format!(
            "GET /styx/enroll/self/{}/capabilities HTTP/1.1\r\n",
            device.as_str()
        )));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: bearer ")
        );
        let body = serde_json::json!({
            "status":"approved", "device_id":device, "fingerprint":fingerprint,
            "generation":"synthetic-generation", "capabilities":{"exec":true,"computer":false,"browser":false}
        }).to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let ready = tokio::time::timeout(Duration::from_secs(5), resume(&store))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ready.device_id, device_id);
    assert_eq!(load_ready(&store).unwrap().device_id, device_id);
    assert!(read(&store).unwrap().pending.is_none());
    server.await.unwrap();
}

#[tokio::test]
async fn lost_join_response_is_retained_without_another_network_request() {
    let (store, listener, _tls, _, _) = fixture(Phase::JoinDispatched).await;
    let result = tokio::time::timeout(Duration::from_secs(1), resume(&store))
        .await
        .unwrap();
    let error = match result {
        Ok(_) => panic!("unknown join must not become ready"),
        Err(error) => error,
    };
    assert_eq!(error.code, "pairing_join_result_unknown");
    assert!(error.uncertain);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), listener.accept())
            .await
            .is_err()
    );
}
