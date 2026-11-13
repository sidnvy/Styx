//! Pure generated-key compatibility, not enrollment, identity persistence,
//! OS permissions or a model/API request. One real RSA generation and join.
use super::*;

#[tokio::test]
async fn generated_rsa3072_sign_oaep_reopen_and_wrong_proof_aggregate() {
    let generated = tokio::task::spawn_blocking(DevicePrivateKey::generate_rsa3072)
        .await
        .unwrap()
        .unwrap();
    let public = generated.public_key();
    assert_eq!(public.credential_ciphertext_size(), 384);
    assert_eq!(public.fingerprint().as_hex().len(), 64);
    let payload = DeviceProofBytes::from_canonical_bytes(b"owned-canonical-test-preimage");
    let signature = generated.private_key().sign(payload).unwrap();
    assert_eq!(signature.len(), 384);
    assert!(public.verify(payload, &signature).is_ok());
    assert!(matches!(
        public.verify(
            DeviceProofBytes::from_canonical_bytes(b"different-owned-test-preimage"),
            &signature
        ),
        Err(CryptoError::InvalidProof)
    ));
    let mut changed = signature.clone();
    changed[0] ^= 1;
    assert!(matches!(
        public.verify(payload, &changed),
        Err(CryptoError::InvalidProof)
    ));
    assert!(matches!(
        public.verify(payload, &signature[..383]),
        Err(CryptoError::InvalidProof)
    ));

    let credential =
        Zeroizing::new(b"owned-generated-key-credential-no-enrollment-authority".to_vec());
    let sealed = public.wrap_credential(&credential).unwrap();
    assert_eq!(sealed.len(), 384);
    let unwrapped = generated.private_key().unwrap_credential(&sealed).unwrap();
    // No assertion formatting of plaintext, PEM, DER or other secret material.
    assert!(unwrapped.as_slice() == credential.as_slice());
    let mut wrong = sealed.clone();
    wrong[0] ^= 1;
    assert!(matches!(
        generated.private_key().unwrap_credential(&wrong),
        Err(CryptoError::InvalidProof)
    ));
    assert!(matches!(
        generated.private_key().unwrap_credential(&sealed[..383]),
        Err(CryptoError::InvalidProof)
    ));

    let reopened = DevicePrivateKey::from_pkcs8_pem(generated.protected_pkcs8_pem()).unwrap();
    assert!(reopened.public_key().spki_der() == public.spki_der());
    assert!(reopened.public_key().fingerprint() == public.fingerprint());
    assert!(reopened.public_key().verify(payload, &signature).is_ok());
    let reopened_signature = reopened.sign(payload).unwrap();
    assert!(public.verify(payload, &reopened_signature).is_ok());
    let reopened_plaintext = reopened.unwrap_credential(&sealed).unwrap();
    assert!(reopened_plaintext.as_slice() == credential.as_slice());
    assert!(matches!(
        DevicePrivateKey::from_pkcs8_pem(
            b"-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----\n"
        ),
        Err(CryptoError::InvalidKeyEncoding)
    ));
}
