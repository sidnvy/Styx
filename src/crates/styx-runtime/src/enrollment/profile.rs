//! Typed public profile and exact legacy proof validation. No private identity,
//! invitation/claim secret or device bearer is persisted in StoredProfile.
use crate::crypto::{DeviceProofBytes, DevicePublicKey};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use regex::RegexSet;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use styx_contracts::{
    identity::{DeviceId, Sha256Digest},
    legacy::{CapabilityPayload, JoinPayload},
};

const MAX_BODY: usize = 16 * 1024;
const MAX_PEM: usize = 2400;
const MAX_SIGNATURE: usize = 2048;
const DEVICE: usize = 0;
const INVITATION: usize = 1;
const LABEL: usize = 2;
const WINDOWS_ABSOLUTE: usize = 3;
const POSIX_SHELL: usize = 4;
const WINDOWS_SHELL: usize = 5;
fn patterns() -> Result<&'static RegexSet> {
    static PATTERNS: OnceLock<std::result::Result<RegexSet, regex::Error>> = OnceLock::new();
    PATTERNS
        .get_or_init(|| {
            RegexSet::new([
                r"\Astyx-[a-f0-9]{24}\z",
                r"\A[A-Za-z0-9_-]{32,}\z",
                r"\A[\p{L}\p{N} ._()\-]{1,72}\z",
                r"\A(?:[A-Za-z]:[\\/]|[\\/])",
                r"/(?i-u:sh|bash|zsh)/*\z",
                r"[\\/](?i-u:powershell\.exe|pwsh\.exe|pwsh)[\\/]*\z",
            ])
        })
        .as_ref()
        .map_err(|_| ProfileError::Internal)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(super) enum ProfileError {
    #[error("public profile or signing input exceeds its bound")]
    Size,
    #[error("invalid stored profile schema")]
    Schema,
    #[error("invalid legacy device identity")]
    DeviceId,
    #[error("invalid invitation encoding")]
    Invitation,
    #[error("invalid friendly device label")]
    Label,
    #[error("unsupported device platform")]
    Platform,
    #[error("invalid platform absolute working directory")]
    Cwd,
    #[error("invalid platform absolute shell or unsupported shell name")]
    Shell,
    #[error("invalid or unsupported original device public key")]
    PublicKey,
    #[error("stored fingerprint does not match the device SPKI")]
    Fingerprint,
    #[error("invalid canonical base64url device signature")]
    Signature,
    #[error("device identity proof rejected")]
    Proof,
    #[error("capability proof does not identify this stored device")]
    CapabilityIdentity,
    #[error("capability proof supplied a different SPKI")]
    CapabilityKey,
    #[error("invalid capability signing scope")]
    CapabilityScope,
    #[error("profile validator unavailable")]
    Internal,
}
type Result<T> = std::result::Result<T, ProfileError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredProfile {
    pub schema: u8,
    pub device_id: DeviceId,
    pub fingerprint: Sha256Digest,
    pub label: String,
    pub platform: String,
    pub cwd: String,
    pub shell: String,
    pub public_key_pem: String,
}
/// Constructed only after full field/SPKI validation, and, for a new join, the
/// actual signature. Stored-profile restoration does not claim to re-run the
/// old invitation-bearing join proof or prove protected-file provenance.
pub(super) struct VerifiedProfile {
    raw: Vec<u8>,
    profile: StoredProfile,
    public_key: DevicePublicKey,
}
impl std::fmt::Debug for VerifiedProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedProfile")
            .field("device_id", &self.profile.device_id)
            .field("fingerprint", &self.profile.fingerprint)
            .field("profile_bytes", &self.raw.len())
            .finish()
    }
}
fn fields(
    device: &DeviceId,
    label: &str,
    platform: &str,
    cwd: &str,
    shell: &str,
    pem: &str,
) -> Result<()> {
    let re = patterns()?;
    if !re.matches(device.as_str()).matched(DEVICE) {
        return Err(ProfileError::DeviceId);
    }
    if !re.matches(label).matched(LABEL) {
        return Err(ProfileError::Label);
    }
    if !matches!(platform, "linux" | "darwin" | "win32") {
        return Err(ProfileError::Platform);
    }
    // Node path.posix/win32 semantics are independent of the Gateway's own OS.
    // JS string.length counts UTF-16 code units for these two path bounds.
    let absolute = |path: &str| {
        if platform == "win32" {
            re.matches(path).matched(WINDOWS_ABSOLUTE)
        } else {
            path.starts_with('/')
        }
    };
    if cwd.contains('\0') || cwd.encode_utf16().count() > 512 || !absolute(cwd) {
        return Err(ProfileError::Cwd);
    }
    let shell_pattern = if platform == "win32" {
        WINDOWS_SHELL
    } else {
        POSIX_SHELL
    };
    if shell.contains('\0')
        || shell.encode_utf16().count() > 512
        || !absolute(shell)
        || !re.matches(shell).matched(shell_pattern)
    {
        return Err(ProfileError::Shell);
    }
    if pem.len() > MAX_PEM {
        return Err(ProfileError::PublicKey);
    }
    Ok(())
}
fn fingerprint(key: &DevicePublicKey) -> Result<Sha256Digest> {
    Sha256Digest::try_from(key.fingerprint().as_hex().to_owned())
        .map_err(|_| ProfileError::Fingerprint)
}
fn signature(raw: &str) -> Result<Vec<u8>> {
    if raw.is_empty() || raw.len() > MAX_SIGNATURE {
        return Err(ProfileError::Signature);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|_| ProfileError::Signature)?;
    if URL_SAFE_NO_PAD.encode(&decoded) != raw {
        return Err(ProfileError::Signature);
    }
    Ok(decoded)
}

pub(super) fn verify_join(
    payload: &JoinPayload,
    signature_base64url: &str,
) -> Result<VerifiedProfile> {
    // Bound the structured input before the canonical codec allocates bytes.
    let total = [
        &payload.invitation,
        &payload.label,
        &payload.platform,
        &payload.cwd,
        &payload.shell,
        &payload.public_key_pem,
    ]
    .into_iter()
    .try_fold(0usize, |n, s| n.checked_add(s.len()))
    .ok_or(ProfileError::Size)?;
    if total > MAX_BODY {
        return Err(ProfileError::Size);
    }
    fields(
        &payload.device_id,
        &payload.label,
        &payload.platform,
        &payload.cwd,
        &payload.shell,
        &payload.public_key_pem,
    )?;
    if !patterns()?.matches(&payload.invitation).matched(INVITATION) {
        return Err(ProfileError::Invitation);
    }
    let public_key = DevicePublicKey::from_spki_pem(payload.public_key_pem.as_bytes())
        .map_err(|_| ProfileError::PublicKey)?;
    let signature = signature(signature_base64url)?;
    let canonical = payload.signing_bytes().map_err(|_| ProfileError::Schema)?;
    if canonical.len() > MAX_BODY {
        return Err(ProfileError::Size);
    }
    public_key
        .verify(
            DeviceProofBytes::from_canonical_bytes(&canonical),
            &signature,
        )
        .map_err(|_| ProfileError::Proof)?;
    let profile = StoredProfile {
        schema: 1,
        device_id: payload.device_id.clone(),
        fingerprint: fingerprint(&public_key)?,
        label: payload.label.clone(),
        platform: payload.platform.clone(),
        cwd: payload.cwd.clone(),
        shell: payload.shell.clone(),
        public_key_pem: payload.public_key_pem.clone(),
    };
    let raw = serde_json::to_vec(&profile).map_err(|_| ProfileError::Schema)?;
    if raw.len() > MAX_BODY {
        return Err(ProfileError::Size);
    }
    Ok(VerifiedProfile {
        raw,
        profile,
        public_key,
    })
}
impl VerifiedProfile {
    /// Caller first proves role, exact stored content hash and private-reader
    /// provenance. Preserve these ORIGINAL profile bytes, never normalize them.
    pub fn from_stored(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_BODY {
            return Err(ProfileError::Size);
        }
        let profile: StoredProfile =
            serde_json::from_slice(bytes).map_err(|_| ProfileError::Schema)?;
        if profile.schema != 1 {
            return Err(ProfileError::Schema);
        }
        fields(
            &profile.device_id,
            &profile.label,
            &profile.platform,
            &profile.cwd,
            &profile.shell,
            &profile.public_key_pem,
        )?;
        let public_key = DevicePublicKey::from_spki_pem(profile.public_key_pem.as_bytes())
            .map_err(|_| ProfileError::PublicKey)?;
        if fingerprint(&public_key)? != profile.fingerprint {
            return Err(ProfileError::Fingerprint);
        }
        Ok(Self {
            raw: bytes.to_vec(),
            profile,
            public_key,
        })
    }
    pub fn raw_profile_bytes(&self) -> &[u8] {
        &self.raw
    }
    pub fn fingerprint(&self) -> Sha256Digest {
        self.profile.fingerprint
    }
    pub fn public_key(&self) -> &DevicePublicKey {
        &self.public_key
    }
    pub fn profile(&self) -> &StoredProfile {
        &self.profile
    }
    /// Signature/identity proof only; current bearer, capability generation CAS,
    /// live lane fence and transaction authority remain in runtime/Core.
    pub fn verify_capability(
        &self,
        payload: &CapabilityPayload,
        supplied_public_pem: &str,
        signature_base64url: &str,
    ) -> Result<()> {
        if payload.device_id != self.profile.device_id
            || payload.fingerprint != self.profile.fingerprint
        {
            return Err(ProfileError::CapabilityIdentity);
        }
        if payload.generation.is_empty() || payload.generation.encode_utf16().count() > 128 {
            return Err(ProfileError::CapabilityScope);
        }
        if supplied_public_pem.len() > MAX_PEM {
            return Err(ProfileError::PublicKey);
        }
        let supplied = DevicePublicKey::from_spki_pem(supplied_public_pem.as_bytes())
            .map_err(|_| ProfileError::PublicKey)?;
        if supplied.spki_der() != self.public_key.spki_der() {
            return Err(ProfileError::CapabilityKey);
        }
        let bytes = payload
            .signing_bytes()
            .map_err(|_| ProfileError::CapabilityScope)?;
        let signature = signature(signature_base64url)?;
        self.public_key
            .verify(DeviceProofBytes::from_canonical_bytes(&bytes), &signature)
            .map_err(|_| ProfileError::Proof)
    }
}

#[cfg(test)]
#[path = "profile_tests.rs"]
mod tests;
