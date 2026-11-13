//! In-memory endpoint renewal for an explicitly opted-in native Gateway.
//! Original protected CA, origin and SANs stay fixed. No file or journal writes.
use super::*;
use std::{
    net::IpAddr,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

const RENEW_BEFORE_SECONDS: i64 = 6 * 60 * 60;
struct Current {
    tls: GatewayServerTls,
    not_before: i64,
    not_after: i64,
}
pub(super) struct EndpointRenewal {
    ca: Vec<u8>,
    key: PrivateKeyPem,
    pin: TrustAnchorPin,
    origin: String,
    addresses: Vec<IpAddr>,
    current: Mutex<Current>,
}
fn rejected<T>(_: T) -> TlsError {
    TlsError::ConfigurationRejected
}
fn clock() -> Result<i64, TlsError> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(rejected)?
            .as_secs(),
    )
    .map_err(rejected)
}
fn issue(
    ca: &[u8],
    key: &PrivateKeyPem,
    pin: &TrustAnchorPin,
    origin: &str,
    addresses: &[IpAddr],
    now: i64,
) -> Result<Current, TlsError> {
    let leaf = issue_server_leaf_with_lan_addresses(
        ca,
        key,
        pin,
        origin,
        addresses,
        u64::try_from(now).map_err(rejected)?,
    )
    .map_err(rejected)?;
    let certificates = certificate_chain(&leaf.certificate_chain_pem)?;
    Ok(Current {
        tls: GatewayServerTls::from_pem(
            &leaf.certificate_chain_pem,
            &leaf.private_key,
            GatewayLeafPin::from_certificate_der(&certificates[0]),
        )?,
        not_before: leaf.not_before_unix,
        not_after: leaf.not_after_unix,
    })
}
impl EndpointRenewal {
    fn refresh_at(&self, now: i64) -> Result<(), TlsError> {
        let mut current = self.current.lock().map_err(rejected)?;
        let margin =
            RENEW_BEFORE_SECONDS.min(current.not_after.saturating_sub(current.not_before) / 4);
        if now < current.not_before || now >= current.not_after.saturating_sub(margin) {
            // Failed renewal never publishes a partial result or serves an expired
            // cache entry. Issuer validates current CA validity/key/pin every time.
            *current = issue(
                &self.ca,
                &self.key,
                &self.pin,
                &self.origin,
                &self.addresses,
                now,
            )?;
        }
        Ok(())
    }
    fn snapshot_at(&self, now: i64) -> Result<(TlsAcceptor, GatewayLeafPin), TlsError> {
        let current = self.current.lock().map_err(rejected)?;
        if now < current.not_before || now >= current.not_after {
            return Err(TlsError::ConfigurationRejected);
        }
        Ok((current.tls.acceptor.clone(), current.tls.leaf_pin.clone()))
    }
    pub(super) fn current(&self) -> Result<(TlsAcceptor, GatewayLeafPin), TlsError> {
        self.snapshot_at(clock()?)
    }
}
impl GatewayServerTls {
    /// Called only in the original Gateway's owned blocking validation job.
    pub fn renew_endpoint(&self) -> Result<(), TlsError> {
        self.renewal
            .as_ref()
            .map_or(Ok(()), |r| r.refresh_at(clock()?))
    }

    pub fn renewing(
        ca: Vec<u8>,
        key: PrivateKeyPem,
        pin: TrustAnchorPin,
        origin: String,
        addresses: Vec<IpAddr>,
    ) -> Result<Self, TlsError> {
        let current = issue(&ca, &key, &pin, &origin, &addresses, clock()?)?;
        Ok(Self {
            acceptor: current.tls.acceptor.clone(),
            leaf_pin: current.tls.leaf_pin.clone(),
            renewal: Some(Arc::new(EndpointRenewal {
                ca,
                key,
                pin,
                origin,
                addresses,
                current: Mutex::new(current),
            })),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn renewal_after_expired_leaf_preserves_anchor_and_refuses_expired_ca() {
        let now = clock().unwrap();
        let ca = generate_gateway_ca(now as u64, (now - 60) as u64, (now + 10 * 86400) as u64)
            .ok()
            .unwrap();
        let der = certificate_chain(&ca.certificate_pem).unwrap().remove(0);
        let server = GatewayServerTls::renewing(
            ca.certificate_pem.clone(),
            ca.private_key,
            ca.anchor_pin.clone(),
            "https://127.0.0.1:22022".into(),
            vec!["10.0.38.8".parse().unwrap()],
        )
        .unwrap();
        let renewal = server.renewal.as_ref().unwrap();
        let (_, first) = renewal.snapshot_at(now).unwrap();
        assert_eq!(renewal.snapshot_at(now + 60).unwrap().1, first);
        assert!(renewal.snapshot_at(now + 25 * 3600).is_err());
        renewal.refresh_at(now + 25 * 3600).unwrap();
        let (_, second) = renewal.snapshot_at(now + 25 * 3600).unwrap();
        assert_ne!(first, second);
        let held = renewal.current.lock().unwrap();
        assert!(held.not_after > now + 25 * 3600);
        assert_eq!(TrustAnchorPin::from_certificate_der(&der), renewal.pin);
        drop(held);
        assert!(renewal.refresh_at(now + 11 * 86400).is_err());
        // An invalid future clock does not replace the last complete cache.
        assert_eq!(renewal.snapshot_at(now + 25 * 3600).unwrap().1, second);
    }
    #[tokio::test]
    async fn renewing_handshake_uses_the_original_ca_and_exact_connection_leaf() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let now = clock().unwrap() as u64;
        let ca = generate_gateway_ca(now, now - 60, now + 365 * 86400)
            .ok()
            .unwrap();
        let original_ca = ca.certificate_pem.clone();
        let original_pin = ca.anchor_pin.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = GatewayServerTls::renewing(
            ca.certificate_pem,
            ca.private_key,
            ca.anchor_pin,
            format!("https://{address}"),
            vec![],
        )
        .unwrap();
        let initial_pin = server.certificate_pin().clone();
        let serving = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let (mut stream, pin) = server
                .accept_with_leaf(tcp, Duration::from_secs(5))
                .await
                .unwrap();
            let mut nonce = [0; 5];
            stream.read_exact(&mut nonce).await.unwrap();
            assert_eq!(&nonce, b"proof");
            stream.write_all(b"ACK").await.unwrap();
            pin
        });
        let client =
            GatewayClientTls::from_pinned_ca_pem(&original_ca, original_pin, None).unwrap();
        let tcp = TcpStream::connect(address).await.unwrap();
        let mut stream = client
            .connect("127.0.0.1", tcp, Duration::from_secs(5))
            .await
            .unwrap();
        let actual_pin = GatewayLeafPin::from_certificate_der(
            &stream.get_ref().1.peer_certificates().unwrap()[0],
        );
        stream.write_all(b"proof").await.unwrap();
        let mut ack = [0; 3];
        stream.read_exact(&mut ack).await.unwrap();
        assert_eq!(&ack, b"ACK");
        assert_eq!(serving.await.unwrap(), actual_pin);
        assert_eq!(initial_pin, actual_pin);
    }
}
