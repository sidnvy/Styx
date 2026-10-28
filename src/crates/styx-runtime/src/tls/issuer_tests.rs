//! Self-contained synthetic issuer crypto + actual loopback standard TLS.
//! No original profile/key, service, installed Gateway or C07 completion claim.
use super::*;
use crate::tls::{CertificateFailure, GatewayClientTls, GatewayServerTls, TlsError};
// BasicConstraints/RsaKeySize are inherited from the issuer imports.
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const BUDGET: Duration = Duration::from_secs(3);
const NONCE: &[u8] = b"owned-issuer-loopback-no-business-authority";

#[test]
fn gateway_lan_certificate_has_loopback_and_private_ip_sans() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let ca = generate_gateway_ca(now, now - 60, now + 2 * 86400).unwrap();
    let issued = issue_server_leaf_with_lan(
        &ca.certificate_pem,
        &ca.private_key,
        &ca.anchor_pin,
        "https://127.0.0.1:8795",
        Some("100.64.1.2".parse().unwrap()),
        now,
    )
    .unwrap();
    let chain = certificate_chain(&issued.certificate_chain_pem).unwrap();
    let (_, leaf) = x509_parser::parse_x509_certificate(&chain[0]).unwrap();
    let sans = leaf.subject_alternative_name().unwrap().unwrap();
    let ips: Vec<_> = sans
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            x509_parser::extensions::GeneralName::IPAddress(ip) => Some(*ip),
            _ => None,
        })
        .collect();
    assert_eq!(ips, vec![&[127, 0, 0, 1][..], &[100, 64, 1, 2][..]]);
    assert_eq!(chain[1], certificate_chain(&ca.certificate_pem).unwrap()[0]);
    let local = issue_server_leaf(
        &ca.certificate_pem,
        &ca.private_key,
        &ca.anchor_pin,
        "https://127.0.0.1:8795",
        now,
    )
    .unwrap();
    let local_chain = certificate_chain(&local.certificate_chain_pem).unwrap();
    let (_, local_leaf) = x509_parser::parse_x509_certificate(&local_chain[0]).unwrap();
    assert_eq!(
        local_leaf
            .subject_alternative_name()
            .unwrap()
            .unwrap()
            .value
            .general_names
            .len(),
        1
    );
    assert!(
        issue_server_leaf_with_lan(
            &ca.certificate_pem,
            &ca.private_key,
            &ca.anchor_pin,
            "https://127.0.0.1:8795",
            Some("8.8.8.8".parse().unwrap()),
            now
        )
        .is_err()
    );
}

fn ca_parameters(now: i64) -> CertificateParams {
    let mut params = CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    // The actual original Core CA has no KU extension; absence must stay usable.
    params.key_usages.clear();
    params.not_before = OffsetDateTime::from_unix_timestamp(now - 120).unwrap();
    params.not_after = OffsetDateTime::from_unix_timestamp(now + 2 * 86400).unwrap();
    params
}

/// A single bounded connection, always joins the owned server task before
/// returning either a client refusal or an acknowledged application exchange.
async fn loopback(
    server: Arc<GatewayServerTls>,
    client: &GatewayClientTls,
    name: &str,
) -> (Result<(), TlsError>, usize) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let serving = tokio::spawn(async move {
        let (tcp, _) = tokio::time::timeout(BUDGET, listener.accept())
            .await
            .unwrap()
            .unwrap();
        let Ok(mut stream) = server.accept(tcp, BUDGET).await else {
            return 0;
        };
        let mut request = [0u8; NONCE.len()];
        match tokio::time::timeout(BUDGET, stream.read_exact(&mut request)).await {
            Ok(Ok(_)) => {
                assert_eq!(&request, NONCE);
                stream.write_all(b"ACK").await.unwrap();
                stream.shutdown().await.unwrap();
                request.len()
            }
            _ => 0,
        }
    });
    let outcome = match client
        .connect(name, TcpStream::connect(address).await.unwrap(), BUDGET)
        .await
    {
        Err(error) => Err(error),
        Ok(mut stream) => {
            let result = tokio::time::timeout(BUDGET, async {
                stream.write_all(NONCE).await?;
                let mut response = [0u8; 3];
                stream.read_exact(&mut response).await?;
                if &response != b"ACK" {
                    return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
                }
                stream.shutdown().await
            })
            .await;
            match result {
                Ok(result) => result.map_err(|error| TlsError::HandshakeIo(error.kind())),
                Err(_) => Err(TlsError::HandshakeTimeout),
            }
        }
    };
    let observed = tokio::time::timeout(Duration::from_secs(8), serving)
        .await
        .unwrap()
        .unwrap();
    (outcome, observed)
}

#[tokio::test]
async fn original_rsa_ca_independent_leaf_and_strict_loopback_aggregate() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let now_i64 = i64::try_from(now).unwrap();
    // RSA work has a real blocking-task join; no environment fixture dependency.
    let (ca_pem, ca_key, wrong_key, constrained_pem) = tokio::task::spawn_blocking(move || {
        let signer =
            Zeroizing::new(KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).unwrap());
        let wrong =
            Zeroizing::new(KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).unwrap());
        let params = ca_parameters(now_i64);
        let ca = params.self_signed(&*signer).unwrap();
        let mut constrained = ca_parameters(now_i64);
        constrained
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ClientAuth);
        let restricted = constrained.self_signed(&*signer).unwrap();
        (
            ca.pem().into_bytes(),
            PrivateKeyPem::from_protected_reader_bytes(signer.serialize_pem().into_bytes())
                .unwrap(),
            PrivateKeyPem::from_protected_reader_bytes(wrong.serialize_pem().into_bytes()).unwrap(),
            restricted.pem().into_bytes(),
        )
    })
    .await
    .unwrap();
    let ca_before = ca_pem.clone();
    let key_before = Zeroizing::new(ca_key.as_protected_bytes().to_vec()); // generated TEST key only
    let ca_der = certificate_chain(&ca_pem).unwrap().remove(0);
    let anchor = TrustAnchorPin::from_certificate_der(ca_der.as_ref());
    let old_leaf = GatewayLeafPin::from_certificate_der(ca_der.as_ref());
    let issued = issue_server_leaf(&ca_pem, &ca_key, &anchor, "https://127.0.0.1/", now).unwrap();
    assert_eq!(issued.anchor_pin, anchor);
    assert_ne!(issued.leaf_pin.as_hex(), anchor.as_hex());
    assert_eq!(issued.origin, "https://127.0.0.1");
    assert!(issued.not_before_unix <= now_i64 && issued.not_after_unix > now_i64);
    assert!(issued.not_after_unix <= now_i64 + 86400);
    let chain = certificate_chain(&issued.certificate_chain_pem).unwrap();
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[1], ca_der);
    let (_, leaf) = x509_parser::parse_x509_certificate(chain[0].as_ref()).unwrap();
    assert!(!leaf.basic_constraints().unwrap().unwrap().value.ca);
    assert!(
        leaf.extended_key_usage()
            .unwrap()
            .unwrap()
            .value
            .server_auth
    );

    let server = Arc::new(
        GatewayServerTls::from_pem(
            &issued.certificate_chain_pem,
            &issued.private_key,
            issued.leaf_pin.clone(),
        )
        .unwrap(),
    );
    let strict = GatewayClientTls::from_pinned_ca_pem(&ca_pem, anchor.clone(), None).unwrap();
    assert_eq!(strict.configured_anchors(), std::slice::from_ref(&anchor));
    assert!(strict.configured_leaf().is_none());
    let (accepted, bytes) = loopback(server.clone(), &strict, "127.0.0.1").await;
    assert!(accepted.is_ok());
    assert_eq!(bytes, NONCE.len());
    let pinned = GatewayClientTls::from_pinned_ca_pem(
        &ca_pem,
        anchor.clone(),
        Some(issued.leaf_pin.clone()),
    )
    .unwrap();
    assert_eq!(pinned.configured_leaf(), Some(&issued.leaf_pin));
    let (accepted, bytes) = loopback(server.clone(), &pinned, "127.0.0.1").await;
    assert!(accepted.is_ok());
    assert_eq!(bytes, NONCE.len());
    // A preserved CA anchor is not an implicit replacement for an old exact leaf pin.
    let old_pin_client =
        GatewayClientTls::from_pinned_ca_pem(&ca_pem, anchor.clone(), Some(old_leaf.clone()))
            .unwrap();
    let (refused, bytes) = loopback(server.clone(), &old_pin_client, "127.0.0.1").await;
    assert!(matches!(refused, Err(TlsError::PinMismatch)));
    assert_eq!(bytes, 0);
    let (refused, bytes) = loopback(server, &strict, "wrong.invalid").await;
    assert!(matches!(
        refused,
        Err(TlsError::CertificateRejected(
            CertificateFailure::NameMismatch
        ))
    ));
    assert_eq!(bytes, 0);
    let old_server = Arc::new(GatewayServerTls::from_pem(&ca_pem, &ca_key, old_leaf).unwrap());
    let (refused, bytes) = loopback(old_server, &strict, "127.0.0.1").await;
    assert!(matches!(
        refused,
        Err(TlsError::CertificateRejected(
            CertificateFailure::InvalidCaAsLeaf
        ))
    ));
    assert_eq!(bytes, 0);

    let wrong_anchor = TrustAnchorPin::from_certificate_der(chain[0].as_ref());
    assert!(matches!(
        issue_server_leaf(&ca_pem, &ca_key, &wrong_anchor, "https://127.0.0.1/", now),
        Err(IssuerError::AnchorMismatch)
    ));
    assert!(matches!(
        issue_server_leaf(&ca_pem, &wrong_key, &anchor, "https://127.0.0.1/", now),
        Err(IssuerError::IssuerKeyMismatch)
    ));
    assert!(matches!(
        issue_server_leaf(
            &ca_pem,
            &ca_key,
            &anchor,
            "https://127.0.0.1/",
            now + 3 * 86400
        ),
        Err(IssuerError::IssuerNotCurrentlyValid)
    ));
    assert!(matches!(
        issue_server_leaf(&ca_pem, &ca_key, &anchor, "https://127.0.0.1/", u64::MAX),
        Err(IssuerError::InvalidClock)
    ));
    for origin in [
        "http://127.0.0.1/",
        "https://user@127.0.0.1/",
        "https://127.0.0.1/private",
        "https://*.invalid/",
    ] {
        assert!(matches!(
            issue_server_leaf(&ca_pem, &ca_key, &anchor, origin, now),
            Err(IssuerError::InvalidOrigin)
        ));
    }
    let constrained_der = certificate_chain(&constrained_pem).unwrap().remove(0);
    let constrained_anchor = TrustAnchorPin::from_certificate_der(constrained_der.as_ref());
    assert!(matches!(
        issue_server_leaf(
            &constrained_pem,
            &ca_key,
            &constrained_anchor,
            "https://127.0.0.1/",
            now
        ),
        Err(IssuerError::UnsupportedIssuer)
    ));
    assert_eq!(ca_pem, ca_before);
    assert!(ca_key.as_protected_bytes() == key_before.as_slice());
    assert_eq!(
        IssuerError::IssuerKeyMismatch.code(),
        "tls_issuer_key_mismatch"
    );
    println!(
        "synthetic RSA issuer + standard loopback TLS aggregate: original CA/key bytes preserved; independent leaf accepted twice; CA-as-leaf/old exact-leaf pin/wrong name refused before nonce; all5 owned TLS tasks and RSA blocking task joined; not installed Gateway/C07 acceptance"
    );
}

/// One generated trust anchor feeds the real existing leaf issuer and strict
/// Rustls transport. This is TLS crypto/loopback evidence, not bootstrap/store.
#[tokio::test]
async fn fresh_rsa_ca_explicit_window_and_strict_leaf_aggregate() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // Invalid input must not get as far as any expensive RSA generation.
    for (clock, start, end) in [
        (u64::MAX, now, now + 86400),
        (now, u64::MAX, now + 86400),
        (now, now, u64::MAX),
        (253_402_300_800, now, now + 86400), // outside supported UTC year range
    ] {
        assert!(matches!(
            generate_gateway_ca(clock, start, end),
            Err(IssuerError::InvalidClock)
        ));
    }
    for (start, end) in [(now + 1, now + 86400), (now, now), (now, now + 59)] {
        assert!(matches!(
            generate_gateway_ca(now, start, end),
            Err(IssuerError::IssuerNotCurrentlyValid)
        ));
    }
    let start = now - 60;
    let end = now + 2 * 86400;
    let (ca, issued) = tokio::task::spawn_blocking(move || {
        let ca = generate_gateway_ca(now, start, end).unwrap();
        let issued = issue_server_leaf(
            &ca.certificate_pem,
            &ca.private_key,
            &ca.anchor_pin,
            "https://127.0.0.1/",
            now,
        )
        .unwrap();
        (ca, issued)
    })
    .await
    .unwrap();
    assert_eq!(ca.not_before_unix, i64::try_from(start).unwrap());
    assert_eq!(ca.not_after_unix, i64::try_from(end).unwrap());
    let certs = certificate_chain(&ca.certificate_pem).unwrap();
    assert_eq!(certs.len(), 1);
    let (rest, parsed) = x509_parser::parse_x509_certificate(certs[0].as_ref()).unwrap();
    assert!(rest.is_empty());
    assert_eq!(parsed.subject(), parsed.issuer());
    parsed.verify_signature(None).unwrap();
    let constraints = parsed.basic_constraints().unwrap().unwrap();
    assert!(constraints.critical && constraints.value.ca);
    assert_eq!(constraints.value.path_len_constraint, Some(0));
    let usage = parsed.key_usage().unwrap().unwrap();
    assert!(usage.critical && usage.value.key_cert_sign() && usage.value.crl_sign());
    assert!(!usage.value.digital_signature());
    assert!(parsed.extended_key_usage().unwrap().is_none());
    assert!(parsed.subject_alternative_name().unwrap().is_none());
    assert!(
        matches!(parsed.public_key().parsed().unwrap(), PublicKey::RSA(key) if key.key_size() == 3072)
    );
    let mut subject_id = None;
    let mut authority_id = None;
    for extension in parsed.extensions() {
        match extension.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(id) => subject_id = Some(id.0),
            ParsedExtension::AuthorityKeyIdentifier(id) => {
                authority_id = id.key_identifier.as_ref().map(|id| id.0);
            }
            _ => {}
        }
    }
    assert!(subject_id.is_some() && subject_id == authority_id);
    let der = Zeroizing::new(private_key(&ca.private_key).unwrap());
    let restored = Zeroizing::new(KeyPair::from_der_and_sign_algo(&der, &PKCS_RSA_SHA256).unwrap());
    // Compare only public material; private PEM/DER never enters assertion output.
    assert!(restored.subject_public_key_info().as_slice() == parsed.public_key().raw);
    assert_eq!(
        ca.anchor_pin,
        TrustAnchorPin::from_certificate_der(&certs[0])
    );
    let chain = certificate_chain(&issued.certificate_chain_pem).unwrap();
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[1], certs[0]);
    let (_, leaf) = x509_parser::parse_x509_certificate(chain[0].as_ref()).unwrap();
    assert!(!leaf.basic_constraints().unwrap().unwrap().value.ca);
    assert!(
        leaf.extended_key_usage()
            .unwrap()
            .unwrap()
            .value
            .server_auth
    );
    assert_eq!(issued.anchor_pin, ca.anchor_pin);
    assert_ne!(issued.leaf_pin.as_hex(), ca.anchor_pin.as_hex());
    let client =
        GatewayClientTls::from_pinned_ca_pem(&ca.certificate_pem, ca.anchor_pin.clone(), None)
            .unwrap();
    let server = Arc::new(
        GatewayServerTls::from_pem(
            &issued.certificate_chain_pem,
            &issued.private_key,
            issued.leaf_pin.clone(),
        )
        .unwrap(),
    );
    let (accepted, bytes) = loopback(server.clone(), &client, "127.0.0.1").await;
    assert!(accepted.is_ok());
    assert_eq!(bytes, NONCE.len());
    let (refused, bytes) = loopback(server, &client, "wrong.invalid").await;
    assert!(matches!(
        refused,
        Err(TlsError::CertificateRejected(
            CertificateFailure::NameMismatch
        ))
    ));
    assert_eq!(bytes, 0);
}
