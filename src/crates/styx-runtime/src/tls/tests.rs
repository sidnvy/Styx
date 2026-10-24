use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

/// Test-only fresh fixtures live below the owned evidence directory. Keys are
/// not serialized into receipts/logs. The product TLS API never generates keys.
#[tokio::test]
#[ignore = "requires STYX_TEST_TLS_FIXTURES with owned test-only cert-a/key-a/cert-b PEM files"]
async fn aws_lc_owned_loopback_tls_full_scenario_batch() {
    let root = std::path::PathBuf::from(std::env::var("STYX_TEST_TLS_FIXTURES").unwrap());
    let a = std::fs::read(root.join("cert-a.pem")).unwrap();
    let b = std::fs::read(root.join("cert-b.pem")).unwrap();
    let ca_a = std::fs::read(root.join("ca-a.pem")).unwrap();
    let ca_b = std::fs::read(root.join("ca-b.pem")).unwrap();
    let key =
        PrivateKeyPem::from_protected_reader_bytes(std::fs::read(root.join("key-a.pem")).unwrap())
            .unwrap();
    assert_eq!(format!("{key:?}"), "PrivateKeyPem([REDACTED])");
    let a_der = certificate_chain(&a).unwrap().remove(0);
    let b_der = certificate_chain(&b).unwrap().remove(0);
    let anchor_a = TrustAnchorPin::from_certificate_der(&certificate_chain(&ca_a).unwrap()[0]);
    let anchor_b = TrustAnchorPin::from_certificate_der(&certificate_chain(&ca_b).unwrap()[0]);
    let leaf_a = GatewayLeafPin::from_certificate_der(&a_der);
    let leaf_b = GatewayLeafPin::from_certificate_der(&b_der);
    assert_ne!(
        anchor_a.as_hex(),
        leaf_a.as_hex(),
        "CA and leaf are deliberately different certificates"
    );
    assert!(matches!(
        GatewayClientTls::from_pinned_ca_pem(&ca_a, anchor_b.clone(), None),
        Err(TlsError::PinMismatch)
    ));
    let mut extra = ca_a.clone();
    extra.extend_from_slice(&ca_b);
    assert!(matches!(
        GatewayClientTls::from_pinned_ca_pem(&extra, anchor_a.clone(), None),
        Err(TlsError::UnexpectedPemItems)
    ));
    GatewayClientTls::from_pinned_ca_bundle(&extra, &[anchor_b.clone(), anchor_a.clone()], None)
        .unwrap();
    assert!(matches!(
        GatewayServerTls::from_pem(&a, &key, leaf_b.clone()),
        Err(TlsError::PinMismatch)
    ));
    let wrong_key =
        PrivateKeyPem::from_protected_reader_bytes(std::fs::read(root.join("key-b.pem")).unwrap())
            .unwrap();
    assert!(matches!(
        GatewayServerTls::from_pem(&a, &wrong_key, leaf_a.clone()),
        Err(TlsError::ConfigurationRejected)
    ));
    let server = Arc::new(GatewayServerTls::from_pem(&a, &key, leaf_a.clone()).unwrap());
    drop(key);
    drop(wrong_key); // Rustls owns its parsed key; raw PEM is wiped now.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let nonce = uuid::Uuid::new_v4().to_string().into_bytes();
    let observed_nonce = nonce.clone();
    let serving = tokio::spawn(async move {
        let mut workers = tokio::task::JoinSet::new();
        for _ in 0..5 {
            let (tcp, _) = listener.accept().await.unwrap();
            let server = server.clone();
            let expected = observed_nonce.clone();
            workers.spawn(async move {
                match server.accept(tcp, Duration::from_secs(2)).await {
                    Ok(mut tls) => {
                        let mut request = vec![0; expected.len()];
                        if tls.read_exact(&mut request).await.is_err() {
                            return "no_application_bytes";
                        }
                        assert_eq!(request, expected);
                        tls.write_all(b"ACK").await.unwrap();
                        tls.shutdown().await.unwrap();
                        "application_echoed"
                    }
                    Err(TlsError::HandshakeRejected) => "transport_rejected",
                    Err(error) => panic!("unexpected server TLS outcome: {error:?}"),
                }
            });
        }
        let mut observations = vec![];
        while let Some(result) = workers.join_next().await {
            observations.push(result.unwrap());
        }
        observations
    });
    let strict_legacy =
        GatewayClientTls::from_pinned_ca_pem(&ca_a, anchor_a.clone(), None).unwrap();
    let pinned_leaf =
        GatewayClientTls::from_pinned_ca_pem(&ca_a, anchor_a.clone(), Some(leaf_a.clone()))
            .unwrap();
    for client in [&strict_legacy, &pinned_leaf] {
        let tcp = TcpStream::connect(address).await.unwrap();
        let mut tls = client
            .connect("localhost", tcp, Duration::from_secs(2))
            .await
            .unwrap();
        tls.write_all(&nonce).await.unwrap();
        let mut answer = [0; 3];
        tls.read_exact(&mut answer).await.unwrap();
        assert_eq!(&answer, b"ACK");
        tls.shutdown().await.unwrap();
    }
    let wrong_leaf =
        GatewayClientTls::from_pinned_ca_pem(&ca_a, anchor_a.clone(), Some(leaf_b)).unwrap();
    assert!(matches!(
        wrong_leaf
            .connect(
                "localhost",
                TcpStream::connect(address).await.unwrap(),
                Duration::from_secs(2)
            )
            .await,
        Err(TlsError::PinMismatch)
    ));
    assert!(matches!(
        strict_legacy
            .connect(
                "wrong.invalid",
                TcpStream::connect(address).await.unwrap(),
                Duration::from_secs(2)
            )
            .await,
        Err(TlsError::CertificateRejected(
            CertificateFailure::NameMismatch
        ))
    ));
    let untrusted = GatewayClientTls::from_pinned_ca_pem(&ca_b, anchor_b, Some(leaf_a)).unwrap();
    assert!(matches!(
        untrusted
            .connect(
                "localhost",
                TcpStream::connect(address).await.unwrap(),
                Duration::from_secs(2)
            )
            .await,
        Err(TlsError::CertificateRejected(
            CertificateFailure::UnknownIssuer
        ))
    ));
    let outcomes = tokio::time::timeout(Duration::from_secs(3), serving)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        outcomes
            .iter()
            .filter(|x| **x == "application_echoed")
            .count(),
        2
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|x| **x == "transport_rejected")
            .count(),
        2
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|x| **x == "no_application_bytes")
            .count(),
        1
    );
    println!(
        "explicit AWS-LC Rustls local TLS batch PASS: CA+hostname legacy preserved; configured leaf pin enforced before app bytes; wrong anchor/leaf/name/untrusted CA and mismatched key rejected; independent server nonce echoes exactly2; listener and all5 workers joined; raw key Debug redacted"
    );
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

/// New focused transport classifications, not a repeat of the full TLS journey.
/// These are owned loopback fixtures, not the original installed Gateway.
#[tokio::test]
#[ignore = "requires STYX_TEST_TLS_FIXTURES with the owned original TLS fixtures"]
async fn strict_verifier_certificate_classification_batch() {
    let root = std::path::PathBuf::from(std::env::var("STYX_TEST_TLS_FIXTURES").unwrap());
    let leaf = std::fs::read(root.join("cert-a.pem")).unwrap();
    let ca = std::fs::read(root.join("ca-a.pem")).unwrap();
    let foreign_ca = std::fs::read(root.join("ca-b.pem")).unwrap();
    let leaf_key =
        PrivateKeyPem::from_protected_reader_bytes(std::fs::read(root.join("key-a.pem")).unwrap())
            .unwrap();
    let ca_key = PrivateKeyPem::from_protected_reader_bytes(
        std::fs::read(root.join("ca-key-a.pem")).unwrap(),
    )
    .unwrap();
    let valid = Arc::new(
        GatewayServerTls::from_pem(
            &leaf,
            &leaf_key,
            GatewayLeafPin::from_certificate_der(&certificate_chain(&leaf).unwrap()[0]),
        )
        .unwrap(),
    );
    let invalid_ca_leaf = Arc::new(
        GatewayServerTls::from_pem(
            &ca,
            &ca_key,
            GatewayLeafPin::from_certificate_der(&certificate_chain(&ca).unwrap()[0]),
        )
        .unwrap(),
    );
    let trusted = GatewayClientTls::from_pinned_ca_pem(
        &ca,
        TrustAnchorPin::from_certificate_der(&certificate_chain(&ca).unwrap()[0]),
        None,
    )
    .unwrap();
    let foreign = GatewayClientTls::from_pinned_ca_pem(
        &foreign_ca,
        TrustAnchorPin::from_certificate_der(&certificate_chain(&foreign_ca).unwrap()[0]),
        None,
    )
    .unwrap();
    for (server, client, name, expected) in [
        (valid.clone(), &trusted, "localhost", None),
        (
            valid.clone(),
            &trusted,
            "wrong.invalid",
            Some(CertificateFailure::NameMismatch),
        ),
        (
            valid,
            &foreign,
            "localhost",
            Some(CertificateFailure::UnknownIssuer),
        ),
        (
            invalid_ca_leaf,
            &trusted,
            "localhost",
            Some(CertificateFailure::InvalidCaAsLeaf),
        ),
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let serving = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let result = server.accept(tcp, Duration::from_secs(2)).await;
            if let Ok(mut tls) = result {
                let _ = tls.shutdown().await;
            }
        });
        let result = client
            .connect(
                name,
                TcpStream::connect(address).await.unwrap(),
                Duration::from_secs(2),
            )
            .await;
        match expected {
            None => {
                let mut tls = result.expect("ordinary CA-signed server chain must remain valid");
                let _ = tls.shutdown().await;
            }
            Some(cause) => assert_eq!(result.err(), Some(TlsError::CertificateRejected(cause))),
        }
        serving.await.unwrap();
    }
    println!(
        "focused actual strict TLS classification PASS: valid chain; wrong name; unknown issuer; CA-as-leaf; all4 owned listener/tasks joined; no verifier bypass or application request"
    );
}
