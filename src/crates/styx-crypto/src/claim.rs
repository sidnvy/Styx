use super::CryptoError;
use aws_lc_rs::hmac;
use zeroize::Zeroizing;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrollmentRequestId(String);
impl EnrollmentRequestId {
    pub fn parse(value: &str) -> Result<Self, CryptoError> {
        if value.len() == 32
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            Ok(Self(value.to_owned()))
        } else {
            Err(CryptoError::InvalidRequestId)
        }
    }
}
pub struct ClaimCapability(Zeroizing<Vec<u8>>);
impl std::fmt::Debug for ClaimCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClaimCapability([REDACTED])")
    }
}
impl ClaimCapability {
    /// Token bytes are ASCII base64url text, NOT decoded base64url bytes.
    /// File newline trimming remains the protected-file reader's responsibility.
    pub fn from_legacy_token_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < 32
            || !bytes
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-')
        {
            return Err(CryptoError::InvalidClaim);
        }
        Ok(Self(Zeroizing::new(bytes.to_vec())))
    }
    fn message(request: &EnrollmentRequestId) -> String {
        format!("styx-enrollment-confirm:{}", request.0)
    }
    pub fn confirm(&self, request: &EnrollmentRequestId) -> ClaimConfirmation {
        let key = hmac::Key::new(hmac::HMAC_SHA256, &self.0);
        ClaimConfirmation(
            hmac::sign(&key, Self::message(request).as_bytes())
                .as_ref()
                .to_vec(),
        )
    }
    pub fn verify(
        &self,
        request: &EnrollmentRequestId,
        proof: &ClaimConfirmation,
    ) -> Result<(), CryptoError> {
        let key = hmac::Key::new(hmac::HMAC_SHA256, &self.0);
        hmac::verify(&key, Self::message(request).as_bytes(), &proof.0)
            .map_err(|_| CryptoError::InvalidProof)
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct ClaimConfirmation(Vec<u8>);
impl std::fmt::Debug for ClaimConfirmation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClaimConfirmation([REDACTED])")
    }
}
impl ClaimConfirmation {
    pub fn from_hex(value: &str) -> Result<Self, CryptoError> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(CryptoError::InvalidClaim);
        }
        Ok(Self(
            hex::decode(value).map_err(|_| CryptoError::InvalidClaim)?,
        ))
    }
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }
}
