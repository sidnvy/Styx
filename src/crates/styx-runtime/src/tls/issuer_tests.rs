//! Self-contained synthetic issuer crypto + actual loopback standard TLS.
//! No original profile/key, service, installed Gateway or C07 completion claim.
use super::*;
use crate::tls::{CertificateFailure, GatewayClientTls, GatewayServerTls, TlsError};
use rcgen::{BasicConstraints, RsaKeySize};
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
