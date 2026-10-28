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
use styx_contracts::identity::{GatewayId, Sha256Digest};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use zeroize::{Zeroize, Zeroizing};

const MAX_CERTIFICATE_PEM_BYTES: usize = 128 * 1024;
const MAX_PRIVATE_PEM_BYTES: usize = 64 * 1024;
const MAX_CERTIFICATES: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
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
    #[error("TLS certificate rejected: {0}")]
    CertificateRejected(CertificateFailure),
    #[error("TLS handshake transport error: {0:?}")]
    HandshakeIo(std::io::ErrorKind),
    #[error("TLS handshake rejected")]
    HandshakeRejected,
    #[error("TLS handshake deadline expired")]
    HandshakeTimeout,
    #[error("TLS server certificate is absent")]
    MissingPeerCertificate,
    #[error("invalid TLS handshake deadline")]
    InvalidDeadline,
}

/// Sanitized classification of the existing Rustls verifier's rejection.
/// No certificate names, peer-controlled strings or private material are retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateFailure {
    BadEncoding,
    Expired,
    NotYetValid,
    NameMismatch,
    UnknownIssuer,
    Revoked,
    UnhandledCriticalExtension,
    BadSignature,
    UnsupportedSignatureAlgorithm,
    InvalidPurpose,
    RevocationStatus,
    InvalidOcspResponse,
    ApplicationVerification,
    InvalidCaAsLeaf,
    InvalidLeafAsCa,
    Other,
}
impl CertificateFailure {
    pub fn code(self) -> &'static str {
        match self {
            Self::BadEncoding => "tls_certificate_bad_encoding",
            Self::Expired => "tls_certificate_expired",
            Self::NotYetValid => "tls_certificate_not_yet_valid",
            Self::NameMismatch => "tls_certificate_name_mismatch",
            Self::UnknownIssuer => "tls_certificate_unknown_issuer",
            Self::Revoked => "tls_certificate_revoked",
            Self::UnhandledCriticalExtension => "tls_certificate_unhandled_critical_extension",
            Self::BadSignature => "tls_certificate_bad_signature",
            Self::UnsupportedSignatureAlgorithm => {
                "tls_certificate_unsupported_signature_algorithm"
            }
            Self::InvalidPurpose => "tls_certificate_invalid_purpose",
            Self::RevocationStatus => "tls_certificate_revocation_status",
            Self::InvalidOcspResponse => "tls_certificate_invalid_ocsp_response",
            Self::ApplicationVerification => "tls_certificate_application_verification",
            Self::InvalidCaAsLeaf => "tls_certificate_ca_used_as_leaf",
            Self::InvalidLeafAsCa => "tls_certificate_leaf_used_as_ca",
            Self::Other => "tls_certificate_other",
        }
    }
    #[allow(deprecated)] // Rustls still exposes legacy variants alongside contextual ones.
    fn from_rustls(error: &rustls::CertificateError) -> Self {
        use rustls::CertificateError as C;
        match error {
            C::BadEncoding => Self::BadEncoding,
            C::Expired | C::ExpiredContext { .. } => Self::Expired,
            C::NotValidYet | C::NotValidYetContext { .. } => Self::NotYetValid,
            C::NotValidForName | C::NotValidForNameContext { .. } => Self::NameMismatch,
            C::UnknownIssuer => Self::UnknownIssuer,
            C::Revoked => Self::Revoked,
            C::UnhandledCriticalExtension => Self::UnhandledCriticalExtension,
            C::BadSignature => Self::BadSignature,
            C::UnsupportedSignatureAlgorithm
            | C::UnsupportedSignatureAlgorithmContext { .. }
            | C::UnsupportedSignatureAlgorithmForPublicKeyContext { .. } => {
                Self::UnsupportedSignatureAlgorithm
            }
            C::InvalidPurpose | C::InvalidPurposeContext { .. } => Self::InvalidPurpose,
            C::UnknownRevocationStatus
            | C::ExpiredRevocationList
            | C::ExpiredRevocationListContext { .. } => Self::RevocationStatus,
            C::InvalidOcspResponse => Self::InvalidOcspResponse,
            C::ApplicationVerificationFailure => Self::ApplicationVerification,
            C::Other(other) => match other.0.downcast_ref::<webpki::Error>() {
                Some(webpki::Error::CaUsedAsEndEntity) => Self::InvalidCaAsLeaf,
                Some(webpki::Error::EndEntityUsedAsCa) => Self::InvalidLeafAsCa,
                _ => Self::Other,
            },
            _ => Self::Other,
        }
    }
}
impl std::fmt::Display for CertificateFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

// Tokio-Rustls wraps process_new_packets' original Rustls error directly in
// io::Error. Inspect that typed payload; do not parse Display/Debug or alter
// validation. An unrecognized underlying certificate cause stays Other.
fn classify_handshake(error: std::io::Error) -> TlsError {
    match error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    {
        Some(rustls::Error::InvalidCertificate(cause)) => {
            TlsError::CertificateRejected(CertificateFailure::from_rustls(cause))
        }
        Some(_) => TlsError::HandshakeRejected,
        None => TlsError::HandshakeIo(error.kind()),
    }
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

/// Paired routing identity is bound to the configured Gateway CA certificate
/// DER, never an endpoint address, PEM spelling, SPKI or rotating leaf. Callers
/// supply the anchor pin from their already-validated local TLS configuration.
pub(crate) fn paired_gateway_namespace(anchor: &TrustAnchorPin) -> GatewayId {
    format!("paired.{}", anchor.as_hex())
        .try_into()
        .expect("fixed prefix and SHA256 hex form a valid Gateway ID")
}

/// Owned bytes supplied by the existing protected reader. This constructor does
/// not establish that a file was protected; the caller owns that boundary.
/// The original input is moved and zeroized on drop rather than copied/logged.
pub struct PrivateKeyPem(Zeroizing<Vec<u8>>);
impl PrivateKeyPem {
    /// Borrow only for the protected reader / same-transaction private writer.
    /// Never serialize, log, or use this as proof of writer or source authority.
    pub(crate) fn as_protected_bytes(&self) -> &[u8] {
        &self.0
    }
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
    /// Exact configured trust set; never derived from an observed peer leaf.
    #[cfg(test)]
    pub(crate) fn configured_anchors(&self) -> &[TrustAnchorPin] {
        &self.anchor_pins
    }
    /// Separate optional endpoint pin. Migration must not silently replace it.
    #[cfg(test)]
    pub(crate) fn configured_leaf(&self) -> Option<&GatewayLeafPin> {
        self.leaf_pin.as_ref()
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
            .map_err(classify_handshake)?;
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
            .map_err(classify_handshake)
    }
}
#[cfg(test)]
mod tests;

mod issuer;
#[cfg(test)]
pub(crate) use issuer::issue_server_leaf;
pub(crate) use issuer::{generate_gateway_ca, issue_server_leaf_with_lan_addresses};
