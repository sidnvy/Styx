//! Fresh trust-anchor generation and preserved-anchor endpoint issuance.
//! No filesystem, network, clock reads, logging or admission authority.
//! The trusted caller owns bootstrap or original protected observations,
//! transaction/writer custody, and one-time durable publication.
#[cfg(test)]
use super::GatewayLeafPin;
use super::{PrivateKeyPem, TrustAnchorPin, certificate_chain, private_key};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, PKCS_RSA_SHA256, PublicKeyData,
    RsaKeySize, SanType, SerialNumber,
};
use std::net::IpAddr;
use time::OffsetDateTime;
use url::{Host, Url};
use x509_parser::{extensions::ParsedExtension, public_key::PublicKey};
use zeroize::Zeroizing;

const MAX_ORIGIN: usize = 512;
const MAX_LEAF_SECONDS: i64 = 24 * 60 * 60;
const MIN_REMAINING_SECONDS: i64 = 60;
const CLOCK_SKEW_SECONDS: i64 = 60;
const MAX_ISSUED_CHAIN: usize = 128 * 1024;

/// Static, secret-free errors only. Do not attach upstream parser/key text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IssuerError {
    InvalidMaterial,
    AnchorMismatch,
    UnsupportedIssuer,
    InvalidIssuerSignature,
    IssuerNotCurrentlyValid,
    IssuerKeyMismatch,
    InvalidOrigin,
    InvalidClock,
    EntropyUnavailable,
    IssuanceFailed,
}
#[cfg(test)]
impl IssuerError {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::InvalidMaterial => "tls_issuer_invalid_material",
            Self::AnchorMismatch => "tls_issuer_anchor_mismatch",
            Self::UnsupportedIssuer => "tls_issuer_unsupported",
            Self::InvalidIssuerSignature => "tls_issuer_signature_invalid",
            Self::IssuerNotCurrentlyValid => "tls_issuer_not_currently_valid",
            Self::IssuerKeyMismatch => "tls_issuer_key_mismatch",
            Self::InvalidOrigin => "tls_issuer_origin_invalid",
            Self::InvalidClock => "tls_issuer_clock_invalid",
            Self::EntropyUnavailable => "tls_issuer_entropy_unavailable",
            Self::IssuanceFailed => "tls_leaf_issuance_failed",
        }
    }
}

/// Generated DATA, not a C07 proof, selected endpoint or publication capability.
/// No Clone, Debug or Serde: the private key must never enter a generic report.
/// The caller retains the original CA certificate/key observations separately.
pub(crate) struct IssuedGatewayEndpoint {
    pub(crate) certificate_chain_pem: Vec<u8>,
    pub(crate) private_key: PrivateKeyPem,
    #[cfg(test)]
    pub(crate) anchor_pin: TrustAnchorPin,
    #[cfg(test)]
    pub(crate) leaf_pin: GatewayLeafPin,
    #[cfg(test)]
    pub(crate) origin: String,
    pub(crate) not_before_unix: i64,
    pub(crate) not_after_unix: i64,
}

/// Fresh DATA for a single explicit bootstrap, not durable publication or
/// enrollment authority. The private PEM is owned/zeroized by `PrivateKeyPem`.
/// No Clone, Debug or Serde; persistence remains the caller's same-writer job.
pub(crate) struct IssuedGatewayCa {
    pub(crate) certificate_pem: Vec<u8>,
    pub(crate) private_key: PrivateKeyPem,
    pub(crate) anchor_pin: TrustAnchorPin,
    pub(crate) not_before_unix: i64,
    pub(crate) not_after_unix: i64,
}

/// Generate one fresh RSA-3072 trust anchor, compatible with `issue_server_leaf`.
///
/// The trusted caller explicitly supplies the entire validity window and clock;
/// no expiry default, wall-clock read, persistence, implicit retry or CA rotation
/// happens here. Invalid UTC/window input is refused before RSA/entropy work.
/// This synchronous crypto operation belongs on the caller's owned blocking job.
pub(crate) fn generate_gateway_ca(
    trusted_now_unix: u64,
    not_before_unix: u64,
    not_after_unix: u64,
) -> Result<IssuedGatewayCa, IssuerError> {
    let now = i64::try_from(trusted_now_unix).map_err(|_| IssuerError::InvalidClock)?;
    let start = i64::try_from(not_before_unix).map_err(|_| IssuerError::InvalidClock)?;
    let end = i64::try_from(not_after_unix).map_err(|_| IssuerError::InvalidClock)?;
    OffsetDateTime::from_unix_timestamp(now).map_err(|_| IssuerError::InvalidClock)?;
    let not_before =
        OffsetDateTime::from_unix_timestamp(start).map_err(|_| IssuerError::InvalidClock)?;
    let not_after =
        OffsetDateTime::from_unix_timestamp(end).map_err(|_| IssuerError::InvalidClock)?;
    if start > now
        || end
            .checked_sub(now)
            .is_none_or(|remaining| remaining < MIN_REMAINING_SECONDS)
    {
        return Err(IssuerError::IssuerNotCurrentlyValid);
    }
    let key = Zeroizing::new(
        KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_3072)
            .map_err(|_| IssuerError::IssuanceFailed)?,
    );
    let mut serial = [0u8; 16];
    getrandom::fill(&mut serial).map_err(|_| IssuerError::EntropyUnavailable)?;
    serial[0] &= 0x7f;
    if serial.iter().all(|byte| *byte == 0) {
        return Err(IssuerError::EntropyUnavailable);
    }
    let mut params =
        CertificateParams::new(Vec::<String>::new()).map_err(|_| IssuerError::IssuanceFailed)?;
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "Styx Gateway trust anchor");
    // This anchor may issue endpoint leaves, not subordinate CAs. No SAN/EKU:
    // it is never an endpoint, and strict clients must still reject CA-as-leaf.
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.use_authority_key_identifier_extension = true;
    params.serial_number = Some(SerialNumber::from_slice(&serial));
    params.not_before = not_before;
    params.not_after = not_after;
    let ca = params
        .self_signed(&*key)
        .map_err(|_| IssuerError::IssuanceFailed)?;
    let (rest, parsed) = x509_parser::parse_x509_certificate(ca.der().as_ref())
        .map_err(|_| IssuerError::IssuanceFailed)?;
    if !rest.is_empty()
        || parsed.subject() != parsed.issuer()
        || parsed.public_key().raw != key.subject_public_key_info().as_slice()
    {
        return Err(IssuerError::IssuanceFailed);
    }
    parsed
        .verify_signature(None)
        .map_err(|_| IssuerError::IssuanceFailed)?;
    let certificate_pem = ca.pem().into_bytes();
    if certificate_pem.len() > MAX_ISSUED_CHAIN {
        return Err(IssuerError::IssuanceFailed);
    }
    let private_key = PrivateKeyPem::from_protected_reader_bytes(key.serialize_pem().into_bytes())
        .map_err(|_| IssuerError::IssuanceFailed)?;
    Ok(IssuedGatewayCa {
        certificate_pem,
        private_key,
        anchor_pin: TrustAnchorPin::from_certificate_der(ca.der().as_ref()),
        not_before_unix: start,
        not_after_unix: end,
    })
}

fn endpoint(origin: &str) -> Result<(String, SanType), IssuerError> {
    if origin.is_empty() || origin.len() > MAX_ORIGIN {
        return Err(IssuerError::InvalidOrigin);
    }
    let parsed = Url::parse(origin).map_err(|_| IssuerError::InvalidOrigin)?;
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
    {
        return Err(IssuerError::InvalidOrigin);
    }
    let canonical = parsed.origin().ascii_serialization();
    // Refuse URL normalization from silently selecting a different origin.
    if origin != canonical && origin != format!("{canonical}/") {
        return Err(IssuerError::InvalidOrigin);
    }
    let san = match parsed.host().ok_or(IssuerError::InvalidOrigin)? {
        Host::Ipv4(ip) => SanType::IpAddress(IpAddr::V4(ip)),
        Host::Ipv6(ip) => SanType::IpAddress(IpAddr::V6(ip)),
        Host::Domain(name) => {
            if name.is_empty() || name.len() > 253 || name.contains('*') || name.ends_with('.') {
                return Err(IssuerError::InvalidOrigin);
            }
            SanType::DnsName(name.try_into().map_err(|_| IssuerError::InvalidOrigin)?)
        }
    };
    Ok((canonical, san))
}

/// Pure first issuance, NEVER an implicit recovery/retry operation.
///
/// Only the observed original self-signed RSA CA family is supported here.
/// Unknown constraints/extensions are refused, not silently copied or ignored.
/// `trusted_now_unix` is supplied by the trusted coordinator's monotonic floor /
/// wall-clock policy; this function cannot authenticate a caller-supplied time.
pub(crate) fn issue_server_leaf(
    ca_pem: &[u8],
    ca_key: &PrivateKeyPem,
    expected_anchor: &TrustAnchorPin,
    original_origin: &str,
    trusted_now_unix: u64,
) -> Result<IssuedGatewayEndpoint, IssuerError> {
    issue_server_leaf_with_lan(
        ca_pem,
        ca_key,
        expected_anchor,
        original_origin,
        None,
        trusted_now_unix,
    )
}

pub(crate) fn issue_server_leaf_with_lan(
    ca_pem: &[u8],
    ca_key: &PrivateKeyPem,
    expected_anchor: &TrustAnchorPin,
    original_origin: &str,
    lan_address: Option<IpAddr>,
    trusted_now_unix: u64,
) -> Result<IssuedGatewayEndpoint, IssuerError> {
    if let Some(address) = lan_address {
        crate::gateway::auth::lan_address(true, Some(&address.to_string()))
            .map_err(|_| IssuerError::InvalidOrigin)?;
    }
    let certificates = certificate_chain(ca_pem).map_err(|_| IssuerError::InvalidMaterial)?;
    if certificates.len() != 1 {
        return Err(IssuerError::InvalidMaterial);
    }
    let original_der = &certificates[0];
    let anchor_pin = TrustAnchorPin::from_certificate_der(original_der.as_ref());
    if &anchor_pin != expected_anchor {
        return Err(IssuerError::AnchorMismatch);
    }
    let (remainder, ca) = x509_parser::parse_x509_certificate(original_der.as_ref())
        .map_err(|_| IssuerError::InvalidMaterial)?;
    if !remainder.is_empty() {
        return Err(IssuerError::InvalidMaterial);
    }
    ca.extensions_map()
        .map_err(|_| IssuerError::InvalidMaterial)?;
    // This small supported legacy family has no name/policy/EKU constraints.
    // Adding such a family requires explicit semantics, not a parser fallback.
    for extension in ca.extensions() {
        match extension.parsed_extension() {
            ParsedExtension::BasicConstraints(_)
            | ParsedExtension::KeyUsage(_)
            | ParsedExtension::SubjectAlternativeName(_) => {}
            ParsedExtension::SubjectKeyIdentifier(_)
            | ParsedExtension::AuthorityKeyIdentifier(_)
                if !extension.critical => {}
            _ => return Err(IssuerError::UnsupportedIssuer),
        }
    }
    if !ca
        .basic_constraints()
        .map_err(|_| IssuerError::InvalidMaterial)?
        .is_some_and(|extension| extension.value.ca)
    {
        return Err(IssuerError::UnsupportedIssuer);
    }
    if ca
        .key_usage()
        .map_err(|_| IssuerError::InvalidMaterial)?
        .is_some_and(|extension| !extension.value.key_cert_sign())
    {
        return Err(IssuerError::UnsupportedIssuer);
    }
    match ca
        .public_key()
        .parsed()
        .map_err(|_| IssuerError::InvalidMaterial)?
    {
        PublicKey::RSA(key) if (2048..=8192).contains(&key.key_size()) => {}
        _ => return Err(IssuerError::UnsupportedIssuer),
    }
    if ca.subject() != ca.issuer() || ca.signature_algorithm != ca.tbs_certificate.signature {
        return Err(IssuerError::UnsupportedIssuer);
    }
    ca.verify_signature(None)
        .map_err(|_| IssuerError::InvalidIssuerSignature)?;
    let now = i64::try_from(trusted_now_unix).map_err(|_| IssuerError::InvalidClock)?;
    let ca_start = ca.validity().not_before.timestamp();
    let ca_end = ca.validity().not_after.timestamp();
    if ca_start > now || ca_end <= now {
        return Err(IssuerError::IssuerNotCurrentlyValid);
    }
    let not_before = now.saturating_sub(CLOCK_SKEW_SECONDS).max(ca_start);
    let not_after = now
        .checked_add(MAX_LEAF_SECONDS)
        .ok_or(IssuerError::InvalidClock)?
        .min(ca_end);
    if not_after
        .checked_sub(now)
        .is_none_or(|remaining| remaining < MIN_REMAINING_SECONDS)
    {
        return Err(IssuerError::IssuerNotCurrentlyValid);
    }
    let (_origin, san) = endpoint(original_origin)?;
    let not_before_date =
        OffsetDateTime::from_unix_timestamp(not_before).map_err(|_| IssuerError::InvalidClock)?;
    let not_after_date =
        OffsetDateTime::from_unix_timestamp(not_after).map_err(|_| IssuerError::InvalidClock)?;

    // Reuse the existing strict one-private-key PEM decoder. Zeroizing owns its
    // transient DER; rcgen's zeroize feature wipes its serialized DER copy too.
    // Backend-internal allocation zeroization is the crypto library's boundary.
    let der_key = Zeroizing::new(private_key(ca_key).map_err(|_| IssuerError::InvalidMaterial)?);
    let signing_key = Zeroizing::new(
        KeyPair::from_der_and_sign_algo(&der_key, &PKCS_RSA_SHA256)
            .map_err(|_| IssuerError::UnsupportedIssuer)?,
    );
    if signing_key.subject_public_key_info().as_slice() != ca.public_key().raw {
        return Err(IssuerError::IssuerKeyMismatch);
    }
    let signer = Issuer::from_ca_cert_der(original_der, &*signing_key)
        .map_err(|_| IssuerError::UnsupportedIssuer)?;
    let leaf_key = Zeroizing::new(
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|_| IssuerError::IssuanceFailed)?,
    );
    let mut serial = [0u8; 16];
    getrandom::fill(&mut serial).map_err(|_| IssuerError::EntropyUnavailable)?;
    serial[0] &= 0x7f;
    if serial.iter().all(|byte| *byte == 0) {
        return Err(IssuerError::EntropyUnavailable);
    }
    let mut params =
        CertificateParams::new(Vec::<String>::new()).map_err(|_| IssuerError::IssuanceFailed)?;
    // Nonempty fixed subject avoids an empty-DN/noncritical-SAN combination.
    // SAN remains authoritative; never copy the CA distinguished name.
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "Styx Gateway endpoint");
    params.subject_alt_names = vec![san];
    if let Some(address) = lan_address {
        for ip in ["127.0.0.1".parse().expect("fixed loopback"), address] {
            let san = SanType::IpAddress(ip);
            if !params.subject_alt_names.contains(&san) {
                params.subject_alt_names.push(san);
            }
        }
    }
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.use_authority_key_identifier_extension = true;
    params.serial_number = Some(SerialNumber::from_slice(&serial));
    params.not_before = not_before_date;
    params.not_after = not_after_date;
    let leaf = params
        .signed_by(&*leaf_key, &signer)
        .map_err(|_| IssuerError::IssuanceFailed)?;
    // Verify the generated signature with the preserved issuer public key.
    // This is not a substitute for the eventual standard Rustls name/chain handshake.
    let (rest, generated) = x509_parser::parse_x509_certificate(leaf.der().as_ref())
        .map_err(|_| IssuerError::IssuanceFailed)?;
    if !rest.is_empty() {
        return Err(IssuerError::IssuanceFailed);
    }
    generated
        .verify_signature(Some(ca.public_key()))
        .map_err(|_| IssuerError::IssuanceFailed)?;
    #[cfg(test)]
    let leaf_pin = GatewayLeafPin::from_certificate_der(leaf.der().as_ref());
    let mut certificate_chain_pem = leaf.pem().into_bytes();
    if certificate_chain_pem
        .len()
        .checked_add(ca_pem.len())
        .is_none_or(|length| length > MAX_ISSUED_CHAIN)
    {
        return Err(IssuerError::IssuanceFailed);
    }
    certificate_chain_pem.extend_from_slice(ca_pem); // ORIGINAL CA PEM bytes, not re-encoded.
    let private_key =
        PrivateKeyPem::from_protected_reader_bytes(leaf_key.serialize_pem().into_bytes())
            .map_err(|_| IssuerError::IssuanceFailed)?;
    Ok(IssuedGatewayEndpoint {
        certificate_chain_pem,
        private_key,
        #[cfg(test)]
        anchor_pin,
        #[cfg(test)]
        leaf_pin,
        #[cfg(test)]
        origin: _origin,
        not_before_unix: not_before,
        not_after_unix: not_after,
    })
}

#[cfg(test)]
#[path = "issuer_tests.rs"]
mod tests;
