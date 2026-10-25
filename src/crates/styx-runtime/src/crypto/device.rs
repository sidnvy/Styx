use super::{CryptoError, decode_pem};
use aws_lc_rs::{
    encoding::{AsDer, Pkcs8V1Der, PublicKeyX509Der},
    rand::SystemRandom,
    rsa::{
        KeySize, OAEP_SHA256_MGF1SHA256, OaepPrivateDecryptingKey, OaepPublicEncryptingKey,
        PrivateDecryptingKey, PublicEncryptingKey,
    },
    signature::{self, RsaKeyPair},
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Already-canonical bytes from enrollment-protocol.joinPayload/capabilityPayload.
/// This layer never serializes, reorders JSON, or invents a signing prefix.
#[derive(Clone, Copy)]
pub struct DeviceProofBytes<'a>(&'a [u8]);
impl<'a> DeviceProofBytes<'a> {
    pub fn from_canonical_bytes(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceFingerprint(String);
impl DeviceFingerprint {
    pub fn as_hex(&self) -> &str {
        &self.0
    }
}

pub struct DevicePrivateKey {
    signer: RsaKeyPair,
    decryptor: OaepPrivateDecryptingKey,
    public: DevicePublicKey,
}
impl std::fmt::Debug for DevicePrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DevicePrivateKey([REDACTED])")
    }
}
/// Fresh cryptographic DATA, never a device ID, enrolled identity or writer
/// capability. No Debug/Clone/Serde; caller owns any protected persistence.
pub struct GeneratedDeviceIdentity {
    private_key: DevicePrivateKey,
    _pkcs8_pem: Zeroizing<Vec<u8>>,
    public_key_pem: String,
}
impl GeneratedDeviceIdentity {
    pub fn private_key(&self) -> &DevicePrivateKey {
        &self.private_key
    }
    pub fn public_key(&self) -> &DevicePublicKey {
        self.private_key.public_key()
    }
    pub fn public_key_pem(&self) -> &str {
        &self.public_key_pem
    }
    /// Borrow only for the caller's protected same-writer persistence. Never
    /// serialize/log this PEM or treat possession as enrollment authority.
    #[cfg(any(
        test,
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")
    ))]
    pub(crate) fn protected_pkcs8_pem(&self) -> &[u8] {
        &self._pkcs8_pem
    }
}

impl DevicePrivateKey {
    /// One fresh RSA-3072 key, imported through the existing compatibility
    /// decoder. This synchronous crypto work belongs on an owned blocking job.
    /// No filesystem, clock, policy, device ID, network or automatic retry.
    pub fn generate_rsa3072() -> Result<GeneratedDeviceIdentity, CryptoError> {
        let generated = PrivateDecryptingKey::generate(KeySize::Rsa3072)
            .map_err(|_| CryptoError::OperationFailed)?;
        // AWS-LC's owned DER buffer zeroizes on drop. rcgen supplies the mature
        // PKCS8 PEM codec; no custom PEM framing or second RSA generation.
        let encoded = AsDer::<Pkcs8V1Der<'static>>::as_der(&generated)
            .map_err(|_| CryptoError::OperationFailed)?;
        let pkcs8 = rustls::pki_types::PrivatePkcs8KeyDer::from(encoded.as_ref());
        let serializer = Zeroizing::new(
            rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &rcgen::PKCS_RSA_SHA256)
                .map_err(|_| CryptoError::OperationFailed)?,
        );
        let pkcs8_pem = Zeroizing::new(serializer.serialize_pem().into_bytes());
        let private_key = Self::from_pkcs8_pem(&pkcs8_pem)?;
        let original_public = DevicePublicKey::from_backend(generated.public_key())?;
        if private_key.public_key().spki_der() != original_public.spki_der() {
            return Err(CryptoError::OperationFailed);
        }
        Ok(GeneratedDeviceIdentity {
            private_key,
            _pkcs8_pem: pkcs8_pem,
            public_key_pem: serializer.public_key_pem(),
        })
    }
    pub fn from_pkcs8_pem(pem: &[u8]) -> Result<Self, CryptoError> {
        let der = decode_pem(pem, "PRIVATE KEY", 16 * 1024)?;
        let private =
            PrivateDecryptingKey::from_pkcs8(&der).map_err(|_| CryptoError::InvalidKeyEncoding)?;
        validate_bits(private.key_size_bits())?;
        let public = DevicePublicKey::from_backend(private.public_key())?;
        let signer = RsaKeyPair::from_pkcs8(&der).map_err(|_| CryptoError::InvalidKeyEncoding)?;
        let decryptor =
            OaepPrivateDecryptingKey::new(private).map_err(|_| CryptoError::OperationFailed)?;
        Ok(Self {
            signer,
            decryptor,
            public,
        })
    }
    pub fn public_key(&self) -> &DevicePublicKey {
        &self.public
    }
    pub fn sign(&self, payload: DeviceProofBytes<'_>) -> Result<Vec<u8>, CryptoError> {
        let mut signature = vec![0; self.signer.public_modulus_len()];
        self.signer
            .sign(
                &signature::RSA_PSS_SHA256,
                &SystemRandom::new(),
                payload.0,
                &mut signature,
            )
            .map_err(|_| CryptoError::OperationFailed)?;
        Ok(signature)
    }
    /// Decrypted secret is zeroized on drop. It is not logged or persisted here.
    pub fn unwrap_credential(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let mut plaintext = Zeroizing::new(vec![0; self.decryptor.min_output_size()]);
        let length = self
            .decryptor
            .decrypt(&OAEP_SHA256_MGF1SHA256, ciphertext, &mut plaintext, None)
            .map_err(|_| CryptoError::InvalidProof)?
            .len();
        plaintext.truncate(length);
        Ok(plaintext)
    }
}

pub struct DevicePublicKey {
    spki: Vec<u8>,
    encryptor: OaepPublicEncryptingKey,
    fingerprint: DeviceFingerprint,
}
impl std::fmt::Debug for DevicePublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DevicePublicKey")
            .field("fingerprint", &self.fingerprint)
            .finish()
    }
}
impl DevicePublicKey {
    pub fn from_spki_pem(pem: &[u8]) -> Result<Self, CryptoError> {
        let der = decode_pem(pem, "PUBLIC KEY", 2400)?;
        Self::from_backend(
            PublicEncryptingKey::from_der(&der).map_err(|_| CryptoError::InvalidKeyEncoding)?,
        )
    }
    fn from_backend(public: PublicEncryptingKey) -> Result<Self, CryptoError> {
        validate_bits(public.key_size_bits())?;
        let spki = AsDer::<PublicKeyX509Der<'static>>::as_der(&public)
            .map_err(|_| CryptoError::InvalidKeyEncoding)?
            .as_ref()
            .to_vec();
        let fingerprint = DeviceFingerprint(hex::encode(Sha256::digest(&spki)));
        let encryptor =
            OaepPublicEncryptingKey::new(public).map_err(|_| CryptoError::OperationFailed)?;
        Ok(Self {
            spki,
            encryptor,
            fingerprint,
        })
    }
    pub fn fingerprint(&self) -> &DeviceFingerprint {
        &self.fingerprint
    }
    pub fn spki_der(&self) -> &[u8] {
        &self.spki
    }
    pub fn verify(
        &self,
        payload: DeviceProofBytes<'_>,
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        signature::UnparsedPublicKey::new(&signature::RSA_PSS_2048_8192_SHA256, &self.spki)
            .verify(payload.0, signature)
            .map_err(|_| CryptoError::InvalidProof)
    }
    /// RSA modulus ciphertext width, not proof that a stored ciphertext decrypts
    /// to a particular credential. Initial wrapping remains a separate fact.
    pub fn credential_ciphertext_size(&self) -> usize {
        self.encryptor.ciphertext_size()
    }
    pub fn wrap_credential(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut ciphertext = vec![0; self.encryptor.ciphertext_size()];
        let length = self
            .encryptor
            .encrypt(&OAEP_SHA256_MGF1SHA256, plaintext, &mut ciphertext, None)
            .map_err(|_| CryptoError::OperationFailed)?
            .len();
        ciphertext.truncate(length);
        Ok(ciphertext)
    }
}
fn validate_bits(bits: usize) -> Result<(), CryptoError> {
    if (3072..=4096).contains(&bits) {
        Ok(())
    } else {
        Err(CryptoError::UnsupportedDeviceKey)
    }
}

#[cfg(test)]
#[path = "device_generation_tests.rs"]
mod generation_tests;
