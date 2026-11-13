use super::*;

#[test]
fn claim_confirmation_uses_original_ascii_token_and_exact_request_domain() {
    let token =
        ClaimCapability::from_legacy_token_bytes(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
    let request = EnrollmentRequestId::parse(&"1".repeat(32)).unwrap();
    // Independently computed with the existing fixed Node22 createHmac code.
    assert_eq!(
        token.confirm(&request).to_hex(),
        "9bdbfb0cc8f71dfc0866ade46b2a3e15859b85d6fbe15051331677d8f24a95ef"
    );
    token.verify(&request, &token.confirm(&request)).unwrap();
    assert!(
        token
            .verify(
                &EnrollmentRequestId::parse(&"2".repeat(32)).unwrap(),
                &token.confirm(&request)
            )
            .is_err()
    );
    assert!(ClaimConfirmation::from_hex(&"F".repeat(64)).is_err());
    assert!(
        ClaimCapability::from_legacy_token_bytes(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n").is_err()
    );
    assert!(EnrollmentRequestId::parse("not-a-request").is_err());
    assert_eq!(format!("{token:?}"), "ClaimCapability([REDACTED])");
}

#[test]
fn pem_domains_are_strict_and_private_debug_does_not_expose_bytes() {
    assert!(
        DevicePrivateKey::from_pkcs8_pem(
            b"-----BEGIN RSA PRIVATE KEY-----\nYQ==\n-----END RSA PRIVATE KEY-----"
        )
        .is_err()
    );
    assert!(DevicePublicKey::from_spki_pem(b"-----BEGIN PUBLIC KEY-----\nYQ==\n-----END PUBLIC KEY-----\n-----BEGIN PRIVATE KEY-----").is_err());
    // RFC8410 PKCS8 Ed25519 seed: a test-only key, never persisted.
    let mut der = hex::decode("302e020100300506032b657004220420").unwrap();
    der.extend_from_slice(&[7; 32]);
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        STANDARD.encode(der)
    );
    let publisher = PublisherSigningKey::from_pkcs8_pem(pem.as_bytes()).unwrap();
    assert_eq!(format!("{publisher:?}"), "PublisherSigningKey([REDACTED])");
    assert!(DevicePrivateKey::from_pkcs8_pem(pem.as_bytes()).is_err());
    let public = publisher.verifying_key();
    let pin = public.fingerprint().unwrap();
    let raw = b"{\"schema\":1}\n";
    let sig = publisher.sign_manifest(RawReleaseManifest::from_original_bytes(raw));
    public
        .verify_manifest(&pin, RawReleaseManifest::from_original_bytes(raw), &sig)
        .unwrap();
    assert!(
        public
            .verify_manifest(
                &pin,
                RawReleaseManifest::from_original_bytes(b"{\"schema\":1}"),
                &sig
            )
            .is_err()
    );
    assert_eq!(
        public.verify_manifest(
            &PublisherFingerprint::parse(&"0".repeat(64)).unwrap(),
            RawReleaseManifest::from_original_bytes(raw),
            &sig
        ),
        Err(CryptoError::PublisherPinMismatch)
    );
}
