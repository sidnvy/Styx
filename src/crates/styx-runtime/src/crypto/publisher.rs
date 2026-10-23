use super::{CryptoError, decode_pem};
use ed25519_dalek::{
    Signature, Signer as _, SigningKey, VerifyingKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePublicKey},
};
use sha2::{Digest, Sha256};

/// Exact manifest.json bytes, including whitespace/newline. No added domain tag:
/// legacy build-host-release.mjs signs raw bytes; installer.mjs verifies them.
#[derive(Clone, Copy)]
pub struct RawReleaseManifest<'a>(&'a [u8]);
impl<'a> RawReleaseManifest<'a> {
    pub fn from_original_bytes(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublisherFingerprint(String);
impl PublisherFingerprint {
    pub fn parse(value: &str) -> Result<Self, CryptoError> {
        if value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            Ok(Self(value.to_owned()))
        } else {
            Err(CryptoError::InvalidKeyEncoding)
        }
    }
    pub fn as_hex(&self) -> &str {
        &self.0
    }
}
pub struct PublisherSigningKey(SigningKey);
impl std::fmt::Debug for PublisherSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PublisherSigningKey([REDACTED])")
    }
}
impl PublisherSigningKey {
    pub fn from_pkcs8_pem(pem: &[u8]) -> Result<Self, CryptoError> {
        let der = decode_pem(pem, "PRIVATE KEY", 4096)?;
        Ok(Self(
            SigningKey::from_pkcs8_der(&der).map_err(|_| CryptoError::InvalidKeyEncoding)?,
        ))
    }
    pub fn verifying_key(&self) -> PublisherVerifyingKey {
        PublisherVerifyingKey(self.0.verifying_key())
    }
    pub fn sign_manifest(&self, raw: RawReleaseManifest<'_>) -> [u8; 64] {
        self.0.sign(raw.0).to_bytes()
    }
}
pub struct PublisherVerifyingKey(VerifyingKey);
impl std::fmt::Debug for PublisherVerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PublisherVerifyingKey")
    }
}
impl PublisherVerifyingKey {
    pub fn from_spki_pem(pem: &[u8]) -> Result<Self, CryptoError> {
        let der = decode_pem(pem, "PUBLIC KEY", 2400)?;
        Ok(Self(
            VerifyingKey::from_public_key_der(&der).map_err(|_| CryptoError::InvalidKeyEncoding)?,
        ))
    }
    pub fn fingerprint(&self) -> Result<PublisherFingerprint, CryptoError> {
        let der = self
            .0
            .to_public_key_der()
            .map_err(|_| CryptoError::InvalidKeyEncoding)?;
        Ok(PublisherFingerprint(hex::encode(Sha256::digest(
            der.as_ref(),
        ))))
    }
    pub fn verify_manifest(
        &self,
        expected: &PublisherFingerprint,
        raw: RawReleaseManifest<'_>,
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        if &self.fingerprint()? != expected {
            return Err(CryptoError::PublisherPinMismatch);
        }
        self.0
            .verify_strict(
                raw.0,
                &Signature::from_slice(signature).map_err(|_| CryptoError::InvalidProof)?,
            )
            .map_err(|_| CryptoError::InvalidProof)
    }
}
