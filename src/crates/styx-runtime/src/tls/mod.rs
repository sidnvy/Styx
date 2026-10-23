//! Shared TLS transport material, without file access, identity generation,
//! pairing/owner authorization, or a global crypto-provider mutation.
//!
//! A successful TLS handshake is not application authorization. This initial
//! server mode does not authenticate client certificates. An existing mTLS
//! profile must not silently select it; that policy requires an explicit adapter.
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
};
use std::{io::Cursor, sync::Arc, time::Duration};
use styx_contracts::identity::Sha256Digest;
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use zeroize::{Zeroize, Zeroizing};

const MAX_CERTIFICATE_PEM_BYTES: usize = 128 * 1024;
const MAX_PRIVATE_PEM_BYTES: usize = 64 * 1024;
const MAX_CERTIFICATES: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TlsError {
    #[error("invalid TLS material or encoding")]
    InvalidMaterial,
    #[error("TLS material exceeds its bounded size")]
    MaterialTooLarge,
    #[error("unexpected TLS PEM item or certificate count")]
    UnexpectedPemItems,
    #[error("TLS certificate fingerprint does not match its configured pin")]
    PinMismatch,
    #[error("TLS provider, certificate or private key configuration rejected")]
    ConfigurationRejected,
    #[error("invalid TLS server hostname or IP literal")]
    InvalidServerName,
    #[error("TLS handshake rejected")]
    HandshakeRejected,
    #[error("TLS handshake deadline expired")]
    HandshakeTimeout,
    #[error("TLS server certificate is absent")]
    MissingPeerCertificate,
    #[error("invalid TLS handshake deadline")]
    InvalidDeadline,
}

macro_rules! certificate_pin {
    ($name:ident) => {
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct $name(Sha256Digest);
        impl $name {
            /// SHA256 of the original X509 certificate DER, never PEM or SPKI.
            pub fn from_certificate_der(der: &[u8]) -> Self {
                Self(Sha256Digest::of_bytes(der))
            }
            pub fn parse_hex(value: &str) -> Result<Self, TlsError> {
                Sha256Digest::try_from(value.to_owned())
                    .map(Self)
                    .map_err(|_| TlsError::InvalidMaterial)
            }
            pub fn as_hex(&self) -> String {
                self.0.to_hex()
            }
        }
    };
}
certificate_pin!(TrustAnchorPin);
certificate_pin!(GatewayLeafPin);

/// Owned bytes supplied by the existing protected reader. This constructor does
/// not establish that a file was protected; the caller owns that boundary.
/// The original input is moved and zeroized on drop rather than copied/logged.
pub struct PrivateKeyPem(Zeroizing<Vec<u8>>);
impl PrivateKeyPem {
    pub fn from_protected_reader_bytes(bytes: Vec<u8>) -> Result<Self, TlsError> {
        let bytes = Zeroizing::new(bytes);
        if bytes.is_empty() {
            return Err(TlsError::InvalidMaterial);
        }
        if bytes.len() > MAX_PRIVATE_PEM_BYTES {
            return Err(TlsError::MaterialTooLarge);
        }
        Ok(Self(bytes))
    }
}
impl std::fmt::Debug for PrivateKeyPem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PrivateKeyPem([REDACTED])")
    }
}

fn certificate_chain(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    if pem.len() > MAX_CERTIFICATE_PEM_BYTES {
        return Err(TlsError::MaterialTooLarge);
    }
    let mut certificates = vec![];
    for item in rustls_pemfile::read_all(&mut Cursor::new(pem)) {
        match item.map_err(|_| TlsError::InvalidMaterial)? {
            rustls_pemfile::Item::X509Certificate(cert) => {
                if certificates.len() >= MAX_CERTIFICATES {
                    return Err(TlsError::UnexpectedPemItems);
                }
                certificates.push(cert)
            }
            rustls_pemfile::Item::Pkcs1Key(mut key) => {
                key.zeroize();
                return Err(TlsError::UnexpectedPemItems);
            }
            rustls_pemfile::Item::Pkcs8Key(mut key) => {
                key.zeroize();
                return Err(TlsError::UnexpectedPemItems);
            }
            rustls_pemfile::Item::Sec1Key(mut key) => {
                key.zeroize();
                return Err(TlsError::UnexpectedPemItems);
            }
            _ => return Err(TlsError::UnexpectedPemItems),
        }
    }
    if certificates.is_empty() {
        return Err(TlsError::InvalidMaterial);
    }
    Ok(certificates)
}
fn private_key(pem: &PrivateKeyPem) -> Result<PrivateKeyDer<'static>, TlsError> {
    let mut keys = Zeroizing::new(Vec::<PrivateKeyDer<'static>>::new());
    for item in rustls_pemfile::read_all(&mut Cursor::new(&*pem.0)) {
        let key = match item.map_err(|_| TlsError::InvalidMaterial)? {
            rustls_pemfile::Item::Pkcs1Key(key) => PrivateKeyDer::Pkcs1(key),
            rustls_pemfile::Item::Pkcs8Key(key) => PrivateKeyDer::Pkcs8(key),
            rustls_pemfile::Item::Sec1Key(key) => PrivateKeyDer::Sec1(key),
            _ => return Err(TlsError::UnexpectedPemItems),
        };
        keys.push(key);
        if keys.len() > 1 {
            return Err(TlsError::UnexpectedPemItems);
        }
    }
    keys.pop().ok_or(TlsError::InvalidMaterial)
}
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}
fn deadline(timeout: Duration) -> Result<tokio::time::Instant, TlsError> {
    if timeout.is_zero() || timeout > Duration::from_secs(30) {
        return Err(TlsError::InvalidDeadline);
    }
    Ok(tokio::time::Instant::now() + timeout)
}

/// Strict configured trust anchor and optional *separately configured* leaf pin.
/// Legacy CA-file+hostname profiles remain CA-file+hostname profiles: a missing
/// leaf pin is not inferred from the CA pin, and configured leaf pins are kept.
pub struct GatewayClientTls {
    connector: TlsConnector,
    leaf_pin: Option<GatewayLeafPin>,
    anchor_pins: Vec<TrustAnchorPin>,
}
impl std::fmt::Debug for GatewayClientTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayClientTls")
            .field("anchor_pins", &self.anchor_pins)
            .field("leaf_pin", &self.leaf_pin)
            .finish()
    }
}
impl GatewayClientTls {
    pub fn from_pinned_ca_pem(
        ca_pem: &[u8],
        expected_anchor: TrustAnchorPin,
        configured_leaf: Option<GatewayLeafPin>,
    ) -> Result<Self, TlsError> {
        Self::from_pinned_ca_bundle(ca_pem, &[expected_anchor], configured_leaf)
    }
    /// Existing CA bundles may be preserved as an exact bounded trust set. All
    /// decoded certificates must have a configured pin; matching only the first
    /// certificate never authorizes additional roots. Order is not authority.
    pub fn from_pinned_ca_bundle(
        ca_pem: &[u8],
        expected_anchors: &[TrustAnchorPin],
        configured_leaf: Option<GatewayLeafPin>,
    ) -> Result<Self, TlsError> {
        let certificates = certificate_chain(ca_pem)?;
        if certificates.len() != expected_anchors.len() {
            return Err(TlsError::UnexpectedPemItems);
        }
        let mut unmatched = expected_anchors.to_vec();
        for certificate in &certificates {
            let actual = TrustAnchorPin::from_certificate_der(certificate);
            let index = unmatched
                .iter()
                .position(|pin| pin == &actual)
                .ok_or(TlsError::PinMismatch)?;
            unmatched.remove(index);
        }
        let mut roots = RootCertStore::empty();
        for certificate in certificates {
            roots
                .add(certificate)
                .map_err(|_| TlsError::InvalidMaterial)?;
        }
        let mut config = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|_| TlsError::ConfigurationRejected)?
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            connector: TlsConnector::from(Arc::new(config)),
            leaf_pin: configured_leaf,
            anchor_pins: expected_anchors.to_vec(),
        })
    }
    /// Returns a stream only after normal chain+hostname validation and any
    /// configured leaf pin. No application bytes may precede this return.
    /// `server_name` is a DNS name or unbracketed IP literal, not a URL.
    pub async fn connect(
        &self,
        server_name: &str,
        tcp: TcpStream,
        timeout: Duration,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>, TlsError> {
        let until = deadline(timeout)?;
        if server_name.len() > 253 {
            return Err(TlsError::InvalidServerName);
        }
        let name = ServerName::try_from(server_name.to_owned())
            .map_err(|_| TlsError::InvalidServerName)?;
        let stream = tokio::time::timeout_at(until, self.connector.connect(name, tcp))
            .await
            .map_err(|_| TlsError::HandshakeTimeout)?
            .map_err(|_| TlsError::HandshakeRejected)?;
        if let Some(expected) = &self.leaf_pin {
            let peer = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|chain| chain.first())
                .ok_or(TlsError::MissingPeerCertificate)?;
            if &GatewayLeafPin::from_certificate_der(peer) != expected {
                return Err(TlsError::PinMismatch);
            }
        }
        Ok(stream)
    }
}

/// One-way server TLS only. Pairing, bearer/owner checks and client certificate
/// authentication are separate decisions, never implied by accept().
pub struct GatewayServerTls {
    acceptor: TlsAcceptor,
    leaf_pin: GatewayLeafPin,
}
impl std::fmt::Debug for GatewayServerTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayServerTls")
            .field("leaf_pin", &self.leaf_pin)
            .finish()
    }
}
impl GatewayServerTls {
    pub fn from_pem(
        certificates_pem: &[u8],
        private_pem: &PrivateKeyPem,
        expected_leaf: GatewayLeafPin,
    ) -> Result<Self, TlsError> {
        let certificates = certificate_chain(certificates_pem)?;
        if GatewayLeafPin::from_certificate_der(&certificates[0]) != expected_leaf {
            return Err(TlsError::PinMismatch);
        }
        let builder = ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|_| TlsError::ConfigurationRejected)?
            .with_no_client_auth();
        let key = private_key(private_pem)?;
        // AWS-LC Rustls KeyProvider wraps the consumed private DER in Zeroizing
        // and validates certificate/key consistency; raw PEM remains caller-owned.
        let mut config = builder
            .with_single_cert(certificates, key)
            .map_err(|_| TlsError::ConfigurationRejected)?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            acceptor: TlsAcceptor::from(Arc::new(config)),
            leaf_pin: expected_leaf,
        })
    }
    pub fn certificate_pin(&self) -> &GatewayLeafPin {
        &self.leaf_pin
    }
    pub async fn accept(
        &self,
        tcp: TcpStream,
        timeout: Duration,
    ) -> Result<tokio_rustls::server::TlsStream<TcpStream>, TlsError> {
        let until = deadline(timeout)?;
        tokio::time::timeout_at(until, self.acceptor.accept(tcp))
            .await
            .map_err(|_| TlsError::HandshakeTimeout)?
            .map_err(|_| TlsError::HandshakeRejected)
    }
}
#[cfg(test)]
mod tests;
