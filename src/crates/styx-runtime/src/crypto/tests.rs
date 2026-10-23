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

/// A single complete legacy algorithm/encoding batch using the actual fixed
/// Node22 crypto implementation and the real JS canonical-envelope functions.
/// Test-only private keys travel over anonymous process pipes, never files/logs.
#[test]
#[ignore = "requires STYX_TEST_NODE22 explicitly pointing at the fixed Node22 binary"]
fn legacy_node22_bidirectional_crypto_batch() {
    use serde_json::{Value, json};
    use std::{
        io::{BufRead, BufReader, Write},
        process::{Command, Stdio},
    };
    let node = std::env::var("STYX_TEST_NODE22").expect("set fixed Node22 path");
    let protocol = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../shared/enrollment-protocol.mjs");
    let mut child = Command::new(node)
        .args([
            "--input-type=module",
            "-e",
            include_str!("node22-interop.mjs"),
        ])
        .env("STYX_TEST_PROTOCOL", protocol)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    let mut line = zeroize::Zeroizing::new(String::new());
    reader.read_line(&mut line).unwrap();
    let fixture: Value = serde_json::from_str(&line).expect("Node fixture JSON");
    assert!(fixture["node"].as_str().unwrap().starts_with("v22."));
    let private =
        DevicePrivateKey::from_pkcs8_pem(fixture["privatePem"].as_str().unwrap().as_bytes())
            .unwrap();
    assert_eq!(format!("{private:?}"), "DevicePrivateKey([REDACTED])");
    let public =
        DevicePublicKey::from_spki_pem(fixture["publicPem"].as_str().unwrap().as_bytes()).unwrap();
    let crlf = fixture["publicPem"].as_str().unwrap().replace('\n', "\r\n");
    assert_eq!(
        DevicePublicKey::from_spki_pem(crlf.as_bytes())
            .unwrap()
            .fingerprint(),
        public.fingerprint()
    );
    assert_eq!(public.fingerprint(), private.public_key().fingerprint());
    assert_eq!(
        public.fingerprint().as_hex(),
        fixture["fingerprint"].as_str().unwrap()
    );
    assert!(matches!(
        DevicePublicKey::from_spki_pem(fixture["weakPublicPem"].as_str().unwrap().as_bytes()),
        Err(CryptoError::UnsupportedDeviceKey)
    ));
    let mut returned = vec![];
    for vector in fixture["vectors"].as_array().unwrap() {
        let payload = vector["payload"].as_str().unwrap().as_bytes();
        public
            .verify(
                DeviceProofBytes::from_canonical_bytes(payload),
                &hex::decode(vector["signature"].as_str().unwrap()).unwrap(),
            )
            .unwrap();
        assert!(
            public
                .verify(
                    DeviceProofBytes::from_canonical_bytes(b"tampered"),
                    &hex::decode(vector["signature"].as_str().unwrap()).unwrap()
                )
                .is_err()
        );
        returned.push(hex::encode(
            private
                .sign(DeviceProofBytes::from_canonical_bytes(payload))
                .unwrap(),
        ));
    }
    let payload = fixture["vectors"][0]["payload"]
        .as_str()
        .unwrap()
        .as_bytes();
    assert!(
        public
            .verify(
                DeviceProofBytes::from_canonical_bytes(payload),
                &hex::decode(fixture["wrongSalt"].as_str().unwrap()).unwrap()
            )
            .is_err()
    );
    let plaintext = private
        .unwrap_credential(&hex::decode(fixture["encrypted"].as_str().unwrap()).unwrap())
        .unwrap();
    assert_eq!(&*plaintext, b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let mut corrupt = hex::decode(fixture["encrypted"].as_str().unwrap()).unwrap();
    corrupt[0] ^= 1;
    assert!(private.unwrap_credential(&corrupt).is_err());
    let request = EnrollmentRequestId::parse(fixture["requestId"].as_str().unwrap()).unwrap();
    let token = ClaimCapability::from_legacy_token_bytes(&plaintext).unwrap();
    assert_eq!(
        token.confirm(&request).to_hex(),
        fixture["confirmation"].as_str().unwrap()
    );
    token
        .verify(
            &request,
            &ClaimConfirmation::from_hex(fixture["confirmation"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
    let publisher = PublisherSigningKey::from_pkcs8_pem(
        fixture["publisherPrivatePem"].as_str().unwrap().as_bytes(),
    )
    .unwrap();
    let verifier = PublisherVerifyingKey::from_spki_pem(
        fixture["publisherPublicPem"].as_str().unwrap().as_bytes(),
    )
    .unwrap();
    let pin = verifier.fingerprint().unwrap();
    assert_eq!(
        pin.as_hex(),
        fixture["publisherFingerprint"].as_str().unwrap()
    );
    let manifest = fixture["manifest"].as_str().unwrap().as_bytes();
    verifier
        .verify_manifest(
            &pin,
            RawReleaseManifest::from_original_bytes(manifest),
            &hex::decode(fixture["publisherSignature"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
    assert!(
        verifier
            .verify_manifest(
                &pin,
                RawReleaseManifest::from_original_bytes(&manifest[..manifest.len() - 1]),
                &hex::decode(fixture["publisherSignature"].as_str().unwrap()).unwrap()
            )
            .is_err()
    );
    assert!(
        PublisherVerifyingKey::from_spki_pem(fixture["publicPem"].as_str().unwrap().as_bytes())
            .is_err()
    );
    let response = json!({"signatures":returned,"encrypted":hex::encode(public.wrap_credential(&plaintext).unwrap()),"confirmation":token.confirm(&request).to_hex(),"publisherSignature":hex::encode(publisher.sign_manifest(RawReleaseManifest::from_original_bytes(manifest)))});
    writeln!(child.stdin.take().unwrap(), "{response}").unwrap();
    let mut result = String::new();
    reader.read_line(&mut result).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&result).unwrap()["status"],
        "PASS"
    );
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "Node verification process failed");
    println!(
        "Node22 legacy 3072-bit RSA/SPKI/PSS32/OAEP-SHA256/HMAC and raw-manifest Ed25519 bidirectional batch PASS; no private files written"
    );
}
