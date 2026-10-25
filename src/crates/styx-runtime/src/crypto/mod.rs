//! Legacy cryptographic compatibility, without filesystem or enrollment authority.
//!
//! Device RSA, claim HMAC and release-publisher Ed25519 are distinct domains.
//! Callers retain responsibility for authenticated canonical preimages, protected
//! file access, key pins and transaction state. Fresh cryptographic generation does not enroll a device or grant filesystem authority.
mod claim;
mod device;
mod publisher;

pub use claim::{ClaimCapability, ClaimConfirmation, EnrollmentRequestId};
pub use device::{
    DeviceFingerprint, DevicePrivateKey, DeviceProofBytes, DevicePublicKey, GeneratedDeviceIdentity,
};
pub use publisher::{
    PublisherFingerprint, PublisherSigningKey, PublisherVerifyingKey, RawReleaseManifest,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("invalid legacy key encoding")]
    InvalidKeyEncoding,
    #[error("unsupported device identity key (RSA 3072..4096 required)")]
    UnsupportedDeviceKey,
    #[error("cryptographic operation failed")]
    OperationFailed,
    #[error("invalid cryptographic proof")]
    InvalidProof,
    #[error("invalid claim capability or confirmation")]
    InvalidClaim,
    #[error("invalid enrollment request id")]
    InvalidRequestId,
    #[error("publisher fingerprint mismatch")]
    PublisherPinMismatch,
}

// Strict PKCS8/SPKI PEM labels; no encrypted/PKCS1/private-key autodetection.
// Rust owns and wipes the temporary base64/DER buffers. Native backend-owned
// key allocations follow AWS-LC's destruction rules, not a Rust zeroize claim.
fn decode_pem(pem: &[u8], label: &str, maximum: usize) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if pem.len() > maximum {
        return Err(CryptoError::InvalidKeyEncoding);
    }
    let text = std::str::from_utf8(pem)
        .map_err(|_| CryptoError::InvalidKeyEncoding)?
        .trim();
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let inner = text
        .strip_prefix(&begin)
        .and_then(|s| s.strip_suffix(&end))
        .ok_or(CryptoError::InvalidKeyEncoding)?;
    // Only PEM whitespace is removed; STANDARD rejects punctuation/trailing PEM.
    let compact = Zeroizing::new(
        inner
            .bytes()
            .filter(|b| !b.is_ascii_whitespace())
            .collect::<Vec<_>>(),
    );
    Ok(Zeroizing::new(
        STANDARD
            .decode(&*compact)
            .map_err(|_| CryptoError::InvalidKeyEncoding)?,
    ))
}

#[cfg(test)]
mod tests;
