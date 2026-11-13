use super::*;

#[test]
fn setup_http_verifier_keeps_chain_hostname_and_exact_leaf_checks() {
    use rustls::client::danger::ServerCertVerifier;
    let now = 1900000000;
    let ca = generate_gateway_ca(now, now - 60, now + 86400 * 365)
        .ok()
        .unwrap();
    let first = issue_server_leaf(
        &ca.certificate_pem,
        &ca.private_key,
        &ca.anchor_pin,
        "https://127.0.0.1:22022",
        now,
    )
    .ok()
    .unwrap();
    let other = issue_server_leaf(
        &ca.certificate_pem,
        &ca.private_key,
        &ca.anchor_pin,
        "https://127.0.0.1:22022",
        now,
    )
    .ok()
    .unwrap();
    let mut roots = RootCertStore::empty();
    roots
        .add(certificate_chain(&ca.certificate_pem).unwrap().remove(0))
        .unwrap();
    let chain =
        rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider())
            .build()
            .unwrap();
    let verifier = PinnedHttpPeer {
        chain,
        leaf: first.leaf_pin,
    };
    let leaf = certificate_chain(&first.certificate_chain_pem)
        .unwrap()
        .remove(0);
    let other = certificate_chain(&other.certificate_chain_pem)
        .unwrap()
        .remove(0);
    let name = ServerName::try_from("127.0.0.1").unwrap();
    let clock = rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_secs(now));
    assert!(
        verifier
            .verify_server_cert(&leaf, &[], &name, &[], clock)
            .is_ok()
    );
    assert!(
        verifier
            .verify_server_cert(&other, &[], &name, &[], clock)
            .is_err()
    );
    assert!(
        verifier
            .verify_server_cert(
                &leaf,
                &[],
                &ServerName::try_from("wrong.invalid").unwrap(),
                &[],
                clock
            )
            .is_err()
    );
}

#[test]
fn private_raw_key_debug_is_redacted_and_pin_domains_are_explicit() {
    let key =
        PrivateKeyPem::from_protected_reader_bytes(b"fixture-private-secret-never-print".to_vec())
            .unwrap();
    assert_eq!(format!("{key:?}"), "PrivateKeyPem([REDACTED])");
    assert!(
        PrivateKeyPem::from_protected_reader_bytes(vec![0; MAX_PRIVATE_PEM_BYTES + 1]).is_err()
    );
    assert!(TrustAnchorPin::parse_hex(&"F".repeat(64)).is_err());
    let anchor = TrustAnchorPin::parse_hex(&"a".repeat(64)).unwrap();
    let leaf = GatewayLeafPin::parse_hex(&"b".repeat(64)).unwrap();
    assert_ne!(anchor.as_hex(), leaf.as_hex());
    assert!(certificate_chain(b"no certificate here").is_err());
}

#[test]
fn typed_certificate_classification_never_parses_error_text() {
    use rustls::CertificateError as C;
    for (cause, expected) in [
        (C::Expired, CertificateFailure::Expired),
        (C::NotValidYet, CertificateFailure::NotYetValid),
        (C::NotValidForName, CertificateFailure::NameMismatch),
        (C::UnknownIssuer, CertificateFailure::UnknownIssuer),
        (
            C::Other(rustls::OtherError(Arc::new(
                webpki::Error::CaUsedAsEndEntity,
            ))),
            CertificateFailure::InvalidCaAsLeaf,
        ),
        (
            C::Other(rustls::OtherError(Arc::new(
                webpki::Error::EndEntityUsedAsCa,
            ))),
            CertificateFailure::InvalidLeafAsCa,
        ),
    ] {
        let wrapped = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            rustls::Error::InvalidCertificate(cause),
        );
        assert_eq!(
            classify_handshake(wrapped),
            TlsError::CertificateRejected(expected)
        );
    }
    let text = std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "invalid peer certificate: CaUsedAsEndEntity",
    );
    assert_eq!(
        classify_handshake(text),
        TlsError::HandshakeIo(std::io::ErrorKind::InvalidData)
    );
    let unknown = rustls::CertificateError::Other(rustls::OtherError(Arc::new(
        std::io::Error::other("CaUsedAsEndEntity"),
    )));
    assert_eq!(
        CertificateFailure::from_rustls(&unknown),
        CertificateFailure::Other
    );
    let protocol = std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        rustls::Error::General("private peer context".into()),
    );
    let classified = classify_handshake(protocol);
    assert_eq!(classified, TlsError::HandshakeRejected);
    assert!(!format!("{classified:?}").contains("private peer context"));
}
