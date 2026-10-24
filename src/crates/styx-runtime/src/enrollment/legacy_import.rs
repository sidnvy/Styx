//! Bounded original legacy enrollment/catalog observations for a trusted C07
//! adapter. NOT an atomic archive, stopped Gateway, imported ledger or new grant.
//! Existing maintenance excludes cooperative configuration writers only; the
//! old Gateway must separately settle and these bindings must be revalidated
//! immediately before any future migration publication.
use super::profile::{StoredProfile, VerifiedProfile};
use crate::store::{
    ConfigurationMaintenance, FileObservation, PayloadInventory, PayloadLimits, PrivateRoot,
    RawFile, RootIdentity,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path, PathBuf},
    sync::Arc,
};
use styx_contracts::identity::{DeviceId, Sha256Digest, TransactionId};

const MAX_DB: usize = 4 * 1024 * 1024;
const MAX_CATALOG: usize = 1024 * 1024;
const MAX_TOKEN: usize = 4096;
const MAX_DEVICES: usize = 1024;
const MAX_PENDING: usize = 64;
const MAX_INVITATIONS: usize = 64;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
type Result<T> = std::result::Result<T, LegacyImportError>;
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum LegacyImportError {
    #[error("legacy_enrollment_input_invalid")]
    Invalid,
    #[error("legacy_enrollment_source_changed")]
    Changed,
    #[error("legacy_enrollment_input_unavailable")]
    Unavailable,
    #[error("legacy_enrollment_capacity")]
    Capacity,
    #[error("legacy_enrollment_layout_unsupported")]
    Unsupported,
    #[error("legacy_enrollment_preparation_blocked")]
    Unsettled,
    #[error("legacy_enrollment_maintenance_unproven")]
    Maintenance,
}
#[derive(Deserialize)]
struct Deployment {
    schema: u32,
    mode: String,
    gateway: Gateway,
}
#[derive(Deserialize)]
struct Gateway {
    url: String,
}
#[derive(Deserialize)]
struct DeploymentState {
    schema: u32,
    mode: String,
    #[serde(rename = "configSha256")]
    config_sha256: Sha256Digest,
    #[serde(default)]
    uncertain: bool,
    #[serde(rename = "activeStep")]
    active_step: Option<Box<serde_json::value::RawValue>>,
}
#[derive(Deserialize)]
struct Runtime {
    schema: u32,
    url: String,
    #[serde(rename = "enrollmentDir")]
    enrollment: PathBuf,
    #[serde(rename = "catalogFile")]
    catalog: PathBuf,
}
#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Database {
    version: u32,
    invitations: Vec<HistoricalInvitation>,
    pending: Vec<HistoricalPending>,
    devices: Vec<DeviceRecord>,
    #[serde(default, deserialize_with = "non_null_option")]
    default_environment_id: Option<String>,
}
#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Catalog {
    version: u32,
    targets: Vec<HistoricalTarget>,
    #[serde(default, deserialize_with = "non_null_option")]
    default_environment_id: Option<String>,
}
/// No unknown metadata is discarded. Unsupported historical variants refuse or
/// block preparation, while exact source bytes remain available for original-ID
/// recovery. Optional legacy fields permit absence, never null-as-absence.
#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct HistoricalInvitation {
    pub id: String,
    pub hash: Sha256Digest,
    pub exp: u64,
    pub used: bool,
    #[serde(default, deserialize_with = "non_null_option")]
    pub ingress: Option<HistoricalIngress>,
    #[serde(default, deserialize_with = "non_null_option")]
    pub window_id: Option<String>,
    #[serde(default, deserialize_with = "non_null_option")]
    pub invalidated_at: Option<u64>,
}
#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct HistoricalIngress {
    pub origin: String,
    // Historical encoding only. No original served leaf is available here,
    // so this MUST NOT be promoted to a verified current certificate pin.
    #[serde(rename = "certificate_sha256")]
    _historical_certificate_sha256: Sha256Digest,
    pub generation: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HistoricalPendingStatus {
    Pending,
    Approved,
    Claimed,
    Revoked,
}
#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct HistoricalPending {
    pub request_id: String,
    pub device_id: DeviceId,
    pub label: String,
    pub platform: String,
    pub cwd: String,
    pub shell: String,
    pub computer_requested: bool,
    #[serde(default, deserialize_with = "non_null_option")]
    pub browser_requested: Option<bool>,
    pub public_key_pem: String,
    pub fingerprint: Sha256Digest,
    #[serde(default, deserialize_with = "non_null_option")]
    pub claim_hash: Option<Sha256Digest>,
    #[serde(default, deserialize_with = "non_null_option")]
    pub ingress: Option<HistoricalIngress>,
    pub exp: u64,
    pub status: HistoricalPendingStatus,
    #[serde(default, deserialize_with = "non_null_option")]
    pub approved_at: Option<u64>,
    #[serde(default, deserialize_with = "non_null_option")]
    pub claim_expires_at: Option<u64>,
    #[serde(default, deserialize_with = "non_null_option")]
    pub sealed_token: Option<String>,
    #[serde(default, deserialize_with = "non_null_option")]
    pub claimed_at: Option<u64>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HistoricalDeviceStatus {
    Approved,
    Revoked,
}
#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DeviceRecord {
    id: DeviceId,
    label: String,
    fingerprint: Sha256Digest,
    target: HistoricalTarget,
    status: HistoricalDeviceStatus,
    approved_at: u64,
    #[serde(default, deserialize_with = "non_null_option")]
    revoked_at: Option<u64>,
}
#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct HistoricalTarget {
    pub id: String,
    pub kind: String,
    pub platform: String,
    pub generation: String,
    pub allowed: bool,
    pub cwd: String,
    pub shell: String,
    pub shells: Vec<String>,
    pub exec: HistoricalExec,
    #[serde(default, deserialize_with = "non_null_option")]
    pub computer: Option<HistoricalComputer>,
    #[serde(default, deserialize_with = "non_null_option")]
    pub browser: Option<HistoricalBrowser>,
    #[serde(default, deserialize_with = "non_null_option")]
    pub env: Option<BTreeMap<String, String>>,
}
#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct HistoricalExec {
    pub transport: String,
    #[serde(default, deserialize_with = "non_null_option")]
    pub token_file: Option<PathBuf>,
    #[serde(default, deserialize_with = "non_null_option")]
    pub client_certificate_sha256: Option<Sha256Digest>,
    #[serde(default, deserialize_with = "non_null_option")]
    pub url: Option<String>,
    #[serde(default, deserialize_with = "non_null_option")]
    pub binary: Option<String>,
}
#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct HistoricalComputer {
    pub enabled: bool,
    #[serde(default, deserialize_with = "non_null_option")]
    pub transport: Option<String>,
    #[serde(default, deserialize_with = "non_null_option")]
    pub max_connections: Option<u8>,
    #[serde(default, deserialize_with = "non_null_option")]
    pub binary: Option<String>,
    #[serde(default, deserialize_with = "non_null_option")]
    pub socket: Option<String>,
    #[serde(default, deserialize_with = "non_null_option")]
    pub url: Option<String>,
    #[serde(default, deserialize_with = "non_null_option")]
    pub token_file: Option<String>,
}
#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct HistoricalBrowser {
    pub enabled: bool,
    #[serde(default, deserialize_with = "non_null_option")]
    pub transport: Option<String>,
}
fn non_null_option<'de, D, T>(d: D) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(d).map(Some)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreparationBlocker {
    UnclosedInvitation,
    PendingJoin,
    UnsettledClaim,
    StaticCatalogTargets,
    HistoricalIdentityConflict,
    UnreferencedToken,
    UnsupportedEnvironment,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HistoricalCapabilities {
    pub exec: bool,
    pub computer: bool,
    pub browser: bool,
}
/// Source facts, never Core authenticated Device/SelfProof/JoinFacts. In
/// particular sealed width is not proof of decryption/token equivalence.
pub(crate) struct HistoricalDevice {
    pub id: DeviceId,
    pub status: HistoricalDeviceStatus,
    pub fingerprint: Sha256Digest,
    pub generation: String,
    pub capabilities: HistoricalCapabilities,
    profile: VerifiedProfile,
    pub pending_index: usize,
    pub token_material: Option<usize>,
}
impl HistoricalDevice {
    pub(crate) fn raw_profile_bytes(&self) -> &[u8] {
        self.profile.raw_profile_bytes()
    }
    pub(crate) fn public_key_spki_der(&self) -> &[u8] {
        self.profile.public_key().spki_der()
    }
    pub(crate) fn effective_capabilities(&self) -> HistoricalCapabilities {
        if self.status == HistoricalDeviceStatus::Revoked {
            HistoricalCapabilities {
                exec: false,
                computer: false,
                browser: false,
            }
        } else {
            self.capabilities
        }
    }
}
struct Frozen {
    raw: RawFile,
    max_bytes: usize,
}
/// No Debug/Serialize/Deserialize. All original files, roots, maintenance and
/// token inventory stay retained. Snapshot equality is detection, NOT an atomic
/// old-writer barrier. Construction is crate-private trusted C07 composition.
pub(crate) struct LegacyImportSnapshot<'a> {
    maintenance: &'a ConfigurationMaintenance,
    root: Arc<PrivateRoot>,
    path: PathBuf,
    identity: RootIdentity,
    original: Vec<Frozen>,
    tokens: PayloadInventory,
    token_root: PrivateRoot,
    pub(crate) devices: Vec<HistoricalDevice>,
    pub(crate) pending: Vec<HistoricalPending>,
    pub(crate) invitations: Vec<HistoricalInvitation>,
    pub(crate) static_targets: Vec<HistoricalTarget>,
    default_environment_id: Option<String>,
    blockers: BTreeSet<PreparationBlocker>,
    credential_materials: Vec<HistoricalCredential>,
    transaction: TransactionId,
}
/// Non-sensitive preparation report only; no credentials, PEM, claim hashes,
/// raw bodies or promise of original-writer quiescence/Core import.
#[derive(Serialize)]
pub struct LegacyImportSummary {
    pub schema: u16,
    pub stage: &'static str,
    pub source_bindings_sha256: Sha256Digest,
    pub devices: usize,
    pub approved: usize,
    pub revoked: usize,
    pub pending_records: usize,
    pub invitations: usize,
    pub credential_files: usize,
    pub static_targets: usize,
    pub default_environment_id: Option<String>,
    pub blockers: Vec<PreparationBlocker>,
    pub native_imported: bool,
    pub original_gateway_settlement_attested: bool,
}
/// Token raw bytes are preserved in `original`, never Debug/Serde/public logs.
pub(crate) struct HistoricalCredential {
    pub device: Option<DeviceId>,
    pub relative_path: PathBuf,
    pub raw_sha256: Sha256Digest,
    pub credential_sha256: Sha256Digest,
    raw_index: usize,
}
impl<'m> LegacyImportSnapshot<'m> {
    pub(crate) fn summary(&self) -> Result<LegacyImportSummary> {
        self.revalidate()?;
        self.validate_bindings()?;
        let mut bindings: Vec<_> = self.raw_bindings().collect();
        bindings.sort_by(|a, b| a.0.cmp(b.0));
        let mut digest = Sha256::new();
        digest.update(b"styx-legacy-enrollment-observation-v1\0");
        digest.update(serde_json::to_vec(&self.identity).map_err(|_| LegacyImportError::Invalid)?);
        for (path, _, sha, stamp) in bindings {
            let path = path.as_os_str().as_encoded_bytes();
            digest.update((path.len() as u64).to_be_bytes());
            digest.update(path);
            digest.update(sha.as_bytes());
            digest.update(serde_json::to_vec(stamp).map_err(|_| LegacyImportError::Invalid)?);
        }
        Ok(LegacyImportSummary {
            schema: 1,
            stage: "historical_snapshot_preparation_only",
            source_bindings_sha256: Sha256Digest::from_bytes(digest.finalize().into()),
            devices: self.devices.len(),
            approved: self
                .devices
                .iter()
                .filter(|d| d.status == HistoricalDeviceStatus::Approved)
                .count(),
            revoked: self
                .devices
                .iter()
                .filter(|d| d.status == HistoricalDeviceStatus::Revoked)
                .count(),
            pending_records: self.pending.len(),
            invitations: self.invitations.len(),
            credential_files: self.credential_materials().len(),
            static_targets: self.static_targets.len(),
            default_environment_id: self.default_environment_id().map(str::to_owned),
            blockers: self.blockers().iter().copied().collect(),
            native_imported: false,
            original_gateway_settlement_attested: false,
        })
    }
    pub(crate) fn validate_preparation(&self) -> Result<()> {
        self.revalidate()?;
        self.validate_bindings()?;
        if !self.blockers().is_empty() {
            return Err(LegacyImportError::Unsettled);
        }
        Ok(())
    }
    pub(crate) fn default_environment_id(&self) -> Option<&str> {
        self.default_environment_id.as_deref()
    }
    pub(crate) fn blockers(&self) -> &BTreeSet<PreparationBlocker> {
        &self.blockers
    }
    pub(crate) fn credential_materials(&self) -> &[HistoricalCredential] {
        &self.credential_materials
    }
    pub(crate) fn credential_bytes(&self, index: usize) -> Result<&[u8]> {
        let material = self
            .credential_materials
            .get(index)
            .ok_or(LegacyImportError::Invalid)?;
        let frozen = self
            .original
            .get(material.raw_index)
            .ok_or(LegacyImportError::Invalid)?;
        credential(frozen.raw.bytes())
    }
    pub(crate) fn raw_bindings(
        &self,
    ) -> impl Iterator<Item = (&Path, &[u8], Sha256Digest, &FileObservation)> {
        self.original.iter().map(|f| {
            (
                f.raw.relative_path(),
                f.raw.bytes(),
                Sha256Digest::of_bytes(f.raw.bytes()),
                f.raw.observation(),
            )
        })
    }
    pub(crate) fn transaction_id(&self) -> &TransactionId {
        &self.transaction
    }
    pub(crate) fn revalidate(&self) -> Result<()> {
        if self
            .maintenance
            .validate_active()
            .map_err(|_| LegacyImportError::Maintenance)?
            != self.identity
            || self.root.identity() != self.identity
            || PrivateRoot::open(&self.path)
                .map_err(|_| LegacyImportError::Changed)?
                .identity()
                != self.identity
        {
            return Err(LegacyImportError::Changed);
        }
        for f in &self.original {
            let now = self
                .root
                .read_raw(f.raw.relative_path(), f.max_bytes)
                .map_err(|_| LegacyImportError::Changed)?;
            if now.bytes() != f.raw.bytes() || now.observation() != f.raw.observation() {
                return Err(LegacyImportError::Changed);
            }
        }
        let current = PrivateRoot::open(self.path.join("gateway/enrollment/tokens"))
            .map_err(|_| LegacyImportError::Changed)?;
        if current.identity() != self.token_root.identity() {
            return Err(LegacyImportError::Changed);
        }
        self.tokens
            .revalidate()
            .map_err(|_| LegacyImportError::Changed)?;
        if self
            .maintenance
            .validate_active()
            .map_err(|_| LegacyImportError::Maintenance)?
            != self.identity
        {
            return Err(LegacyImportError::Changed);
        }
        Ok(())
    }
}
// Reconcile retained typed facts against the exact ORIGINAL bytes before a
// preparation decision. This is source consistency, never a new Core grant.
impl LegacyImportSnapshot<'_> {
    fn validate_bindings(&self) -> Result<()> {
        if self.transaction_id() != self.maintenance.transaction_id() {
            return Err(LegacyImportError::Maintenance);
        }
        let original = |path: &str| {
            self.original
                .iter()
                .find(|f| f.raw.relative_path() == Path::new(path))
                .map(|f| f.raw.bytes())
                .ok_or(LegacyImportError::Invalid)
        };
        let db: Database = parse(original("gateway/enrollment/state.json")?)?;
        let catalog: Catalog = parse(original("gateway/targets.json")?)?;
        if self.pending != db.pending
            || self.invitations != db.invitations
            || self.static_targets != catalog.targets
            || self.devices.len() != db.devices.len()
            || self.default_environment_id()
                != db
                    .default_environment_id
                    .as_deref()
                    .or(catalog.default_environment_id.as_deref())
        {
            return Err(LegacyImportError::Invalid);
        }
        let mut blockers = BTreeSet::new();
        if !catalog.targets.is_empty() {
            blockers.insert(PreparationBlocker::StaticCatalogTargets);
        }
        if db.invitations.iter().any(|v| !v.used) {
            blockers.insert(PreparationBlocker::UnclosedInvitation);
        }
        for p in &db.pending {
            match p.status {
                HistoricalPendingStatus::Pending => {
                    blockers.insert(PreparationBlocker::PendingJoin);
                }
                HistoricalPendingStatus::Approved => {
                    blockers.insert(PreparationBlocker::UnsettledClaim);
                }
                HistoricalPendingStatus::Claimed | HistoricalPendingStatus::Revoked => {}
            }
        }
        for (index, material) in self.credential_materials().iter().enumerate() {
            let frozen = self
                .original
                .get(material.raw_index)
                .ok_or(LegacyImportError::Invalid)?;
            let relative = material
                .relative_path
                .strip_prefix("gateway/enrollment/tokens")
                .map_err(|_| LegacyImportError::Invalid)?;
            if relative.components().count() != 1
                || frozen.raw.relative_path() != material.relative_path
                || Sha256Digest::of_bytes(frozen.raw.bytes()) != material.raw_sha256
                || Sha256Digest::of_bytes(self.credential_bytes(index)?)
                    != material.credential_sha256
            {
                return Err(LegacyImportError::Invalid);
            }
            let member = self
                .tokens
                .members()
                .iter()
                .find(|m| m.path == relative)
                .ok_or(LegacyImportError::Invalid)?;
            if member.sha256 != material.raw_sha256
                || member.bytes != frozen.raw.bytes().len() as u64
                || member.executable
            {
                return Err(LegacyImportError::Invalid);
            }
            let expected = relative
                .to_str()
                .and_then(|s| s.strip_suffix(".token"))
                .and_then(|s| DeviceId::try_from(s.to_owned()).ok())
                .filter(|id| db.devices.iter().any(|d| d.id == *id));
            if material.device != expected {
                return Err(LegacyImportError::Invalid);
            }
            if material.device.is_none() {
                blockers.insert(PreparationBlocker::UnreferencedToken);
            }
        }
        if self.credential_materials().len() != self.tokens.members().len() {
            return Err(LegacyImportError::Invalid);
        }
        let mut fingerprints = BTreeSet::new();
        for (device, record) in self.devices.iter().zip(&db.devices) {
            let pending = self
                .pending
                .get(device.pending_index)
                .ok_or(LegacyImportError::Invalid)?;
            let expected_profile = StoredProfile {
                schema: 1,
                device_id: pending.device_id.clone(),
                fingerprint: pending.fingerprint,
                label: pending.label.clone(),
                platform: pending.platform.clone(),
                cwd: pending.cwd.clone(),
                shell: pending.shell.clone(),
                public_key_pem: pending.public_key_pem.clone(),
            };
            let profile_bytes =
                serde_json::to_vec(&expected_profile).map_err(|_| LegacyImportError::Invalid)?;
            let capabilities = HistoricalCapabilities {
                exec: record.target.allowed,
                computer: record.target.computer.as_ref().is_some_and(|v| v.enabled),
                browser: record.target.browser.as_ref().is_some_and(|v| v.enabled),
            };
            let expected_effective = if record.status == HistoricalDeviceStatus::Revoked {
                HistoricalCapabilities {
                    exec: false,
                    computer: false,
                    browser: false,
                }
            } else {
                capabilities
            };
            let expected_token = Path::new("gateway/enrollment/tokens")
                .join(format!("{}.token", record.id.as_str()));
            let matches: Vec<_> = self
                .credential_materials()
                .iter()
                .enumerate()
                .filter(|(_, m)| {
                    m.device.as_ref() == Some(&record.id) && m.relative_path == expected_token
                })
                .map(|(i, _)| i)
                .collect();
            if device.id != record.id
                || device.status != record.status
                || device.fingerprint != record.fingerprint
                || device.generation != record.target.generation
                || pending.device_id != record.id
                || pending.fingerprint != record.fingerprint
                || device.raw_profile_bytes() != profile_bytes
                || Sha256Digest::of_bytes(device.public_key_spki_der()) != record.fingerprint
                || device.capabilities != capabilities
                || device.effective_capabilities() != expected_effective
                || matches.len() > 1
                || device.token_material != matches.first().copied()
                || (record.status == HistoricalDeviceStatus::Approved
                    && device.token_material.is_none())
            {
                return Err(LegacyImportError::Invalid);
            }
            if !fingerprints.insert(*record.fingerprint.as_bytes()) {
                blockers.insert(PreparationBlocker::HistoricalIdentityConflict);
            }
            if record.target.env.as_ref().is_some_and(|v| !v.is_empty()) {
                blockers.insert(PreparationBlocker::UnsupportedEnvironment);
            }
        }
        if &blockers != self.blockers() {
            return Err(LegacyImportError::Invalid);
        }
        Ok(())
    }
}
fn read(
    root: &PrivateRoot,
    path: impl AsRef<Path>,
    max_bytes: usize,
    original: &mut Vec<Frozen>,
) -> Result<usize> {
    let raw = root.read_raw(path, max_bytes).map_err(|e| match e {
        crate::store::StoreError::TooLarge => LegacyImportError::Capacity,
        _ => LegacyImportError::Unavailable,
    })?;
    original.push(Frozen { raw, max_bytes });
    Ok(original.len() - 1)
}
fn credential(raw: &[u8]) -> Result<&[u8]> {
    let text = std::str::from_utf8(raw)
        .map_err(|_| LegacyImportError::Invalid)?
        .trim();
    if !(32..=1024).contains(&text.len())
        || !text
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
    {
        return Err(LegacyImportError::Invalid);
    }
    Ok(text.as_bytes())
}
fn parse<T: serde::de::DeserializeOwned>(raw: &[u8]) -> Result<T> {
    serde_json::from_slice(raw).map_err(|_| LegacyImportError::Invalid)
}

pub(crate) fn capture<'a>(
    state_dir: &Path,
    root: Arc<PrivateRoot>,
    maintenance: &'a ConfigurationMaintenance,
) -> Result<LegacyImportSnapshot<'a>> {
    if !cfg!(all(target_os = "linux", target_env = "gnu")) {
        return Err(LegacyImportError::Unsupported);
    }
    if !state_dir.is_absolute()
        || state_dir.as_os_str().len() > 4096
        || state_dir
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(LegacyImportError::Unsupported);
    }
    let identity = maintenance
        .validate_active()
        .map_err(|_| LegacyImportError::Maintenance)?;
    if root.identity() != identity
        || PrivateRoot::open(state_dir)
            .map_err(|_| LegacyImportError::Unavailable)?
            .identity()
            != identity
    {
        return Err(LegacyImportError::Maintenance);
    }
    let mut original = Vec::new();
    let deployment_i = read(&root, "deployment.json", MAX_CATALOG, &mut original)?;
    let deployment: Deployment = parse(original[deployment_i].raw.bytes())?;
    let state_i = read(&root, "state.json", MAX_CATALOG, &mut original)?;
    let state: DeploymentState = parse(original[state_i].raw.bytes())?;
    if deployment.schema != 1
        || deployment.mode != "create-local"
        || state.schema != 1
        || state.mode != deployment.mode
        || state.uncertain
        || state.active_step.is_some()
        || state.config_sha256 != Sha256Digest::of_bytes(original[deployment_i].raw.bytes())
    {
        return Err(LegacyImportError::Unsupported);
    }
    let origin =
        url::Url::parse(&deployment.gateway.url).map_err(|_| LegacyImportError::Invalid)?;
    if origin.scheme() != "https"
        || origin.host_str().is_none()
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.query().is_some()
        || origin.fragment().is_some()
        || origin.path() != "/"
    {
        return Err(LegacyImportError::Unsupported);
    }
    let runtime_i = read(&root, "gateway/runtime.json", MAX_CATALOG, &mut original)?;
    let runtime: Runtime = parse(original[runtime_i].raw.bytes())?;
    // Fixed deployment gatewayPaths schema. Arbitrary CLI/env-selected catalog,
    // enrollment database and credential paths are deliberately unsupported.
    if runtime.schema != 1
        || runtime.url != deployment.gateway.url
        || runtime.enrollment != state_dir.join("gateway/enrollment")
        || runtime.catalog != state_dir.join("gateway/targets.json")
    {
        return Err(LegacyImportError::Unsupported);
    }
    let catalog_i = read(&root, "gateway/targets.json", MAX_CATALOG, &mut original)?;
    let catalog: Catalog = parse(original[catalog_i].raw.bytes())?;
    let database_i = read(
        &root,
        "gateway/enrollment/state.json",
        MAX_DB,
        &mut original,
    )?;
    let database: Database = parse(original[database_i].raw.bytes())?;
    if catalog.version != 1 || database.version != 1 {
        return Err(LegacyImportError::Unsupported);
    }
    if catalog.targets.len() > 64
        || database.devices.len() > MAX_DEVICES
        || database.pending.len() > MAX_PENDING
        || database.invitations.len() > MAX_INVITATIONS
    {
        return Err(LegacyImportError::Capacity);
    }
    let mut blockers = BTreeSet::new();
    let mut catalog_ids = BTreeSet::new();
    for target in &catalog.targets {
        validate_target(target)?;
        if !catalog_ids.insert(target.id.clone()) {
            return Err(LegacyImportError::Invalid);
        }
    }
    if !catalog.targets.is_empty() {
        blockers.insert(PreparationBlocker::StaticCatalogTargets);
    }
    if catalog
        .default_environment_id
        .as_ref()
        .is_some_and(|id| !catalog_ids.contains(id))
    {
        return Err(LegacyImportError::Invalid);
    }
    let mut invitation_ids = BTreeSet::new();
    let mut invitation_hashes = BTreeSet::new();
    for invitation in &database.invitations {
        if !hex(&invitation.id, 20)
            || !safe_time(invitation.exp)
            || invitation.invalidated_at.is_some_and(|t| !safe_time(t))
            || !invitation_ids.insert(&invitation.id)
            || !invitation_hashes.insert(*invitation.hash.as_bytes())
            || invitation
                .window_id
                .as_ref()
                .is_some_and(|v| v.is_empty() || v.len() > 128 || v.chars().any(char::is_control))
        {
            return Err(LegacyImportError::Invalid);
        }
        if let Some(ingress) = &invitation.ingress {
            validate_ingress(ingress)?;
        }
        if !invitation.used {
            blockers.insert(PreparationBlocker::UnclosedInvitation);
        }
    }
    let mut pending_by_device = BTreeMap::new();
    let mut request_ids = BTreeSet::new();
    let mut verified_profiles = Vec::new();
    for (index, pending) in database.pending.iter().enumerate() {
        if !request_ids.insert(&pending.request_id)
            || !hex(&pending.request_id, 32)
            || !safe_time(pending.exp)
            || pending_by_device
                .insert(pending.device_id.clone(), index)
                .is_some()
        {
            return Err(LegacyImportError::Invalid);
        }
        let stored = StoredProfile {
            schema: 1,
            device_id: pending.device_id.clone(),
            fingerprint: pending.fingerprint,
            label: pending.label.clone(),
            platform: pending.platform.clone(),
            cwd: pending.cwd.clone(),
            shell: pending.shell.clone(),
            public_key_pem: pending.public_key_pem.clone(),
        };
        let bytes = serde_json::to_vec(&stored).map_err(|_| LegacyImportError::Invalid)?;
        let verified =
            VerifiedProfile::from_stored(&bytes).map_err(|_| LegacyImportError::Invalid)?;
        if let Some(ingress) = &pending.ingress {
            validate_ingress(ingress)?;
        }
        for time in [
            pending.approved_at,
            pending.claim_expires_at,
            pending.claimed_at,
        ]
        .into_iter()
        .flatten()
        {
            if !safe_time(time) {
                return Err(LegacyImportError::Invalid);
            }
        }
        match pending.status {
            HistoricalPendingStatus::Pending => {
                if pending.claim_hash.is_none()
                    || pending.sealed_token.is_some()
                    || pending.claimed_at.is_some()
                    || pending.approved_at.is_some()
                    || pending.claim_expires_at.is_some()
                {
                    return Err(LegacyImportError::Invalid);
                }
                blockers.insert(PreparationBlocker::PendingJoin);
            }
            HistoricalPendingStatus::Approved => {
                if pending.claim_hash.is_none()
                    || pending.claimed_at.is_some()
                    || pending.approved_at.is_none()
                    || pending.claim_expires_at.is_none()
                {
                    return Err(LegacyImportError::Invalid);
                }
                let sealed = pending
                    .sealed_token
                    .as_ref()
                    .ok_or(LegacyImportError::Invalid)?;
                if sealed.len() > 1024 {
                    return Err(LegacyImportError::Capacity);
                }
                let decoded = URL_SAFE_NO_PAD
                    .decode(sealed)
                    .map_err(|_| LegacyImportError::Invalid)?;
                if decoded.len() != verified.public_key().credential_ciphertext_size()
                    || URL_SAFE_NO_PAD.encode(&decoded) != *sealed
                {
                    return Err(LegacyImportError::Invalid);
                }
                // Ciphertext width alone never proves token equivalence.
                blockers.insert(PreparationBlocker::UnsettledClaim);
            }
            HistoricalPendingStatus::Claimed => {
                if pending.claim_hash.is_none()
                    || pending.sealed_token.is_some()
                    || pending.approved_at.is_none()
                    || pending.claimed_at.is_none()
                    || pending.claim_expires_at.is_none()
                {
                    return Err(LegacyImportError::Invalid);
                }
            }
            HistoricalPendingStatus::Revoked => {
                if pending.claim_hash.is_some() || pending.sealed_token.is_some() {
                    return Err(LegacyImportError::Invalid);
                }
            }
        }
        verified_profiles.push(Some(verified));
    }
    let token_root = PrivateRoot::open(state_dir.join("gateway/enrollment/tokens"))
        .map_err(|_| LegacyImportError::Unavailable)?;
    let tokens = token_root
        .payload_inventory(PayloadLimits {
            max_files: MAX_DEVICES,
            max_directories: 1,
            max_depth: 1,
            max_file_bytes: MAX_TOKEN as u64,
            max_total_bytes: (MAX_DEVICES * MAX_TOKEN) as u64,
        })
        .map_err(|_| LegacyImportError::Capacity)?;
    let mut material_by_device = BTreeMap::new();
    let mut credential_materials = Vec::new();
    let known_ids: BTreeSet<_> = database.devices.iter().map(|d| d.id.as_str()).collect();
    for member in tokens.members() {
        let name = member.path.to_str().ok_or(LegacyImportError::Invalid)?;
        if member.path.components().count() != 1 || member.executable {
            return Err(LegacyImportError::Unsupported);
        }
        let device = name
            .strip_suffix(".token")
            .and_then(|v| DeviceId::try_from(v.to_owned()).ok());
        let device = device.filter(|v| known_ids.contains(v.as_str()));
        if device.is_none() {
            blockers.insert(PreparationBlocker::UnreferencedToken);
        }
        let relative = Path::new("gateway/enrollment/tokens").join(&member.path);
        let raw_index = read(&root, &relative, MAX_TOKEN, &mut original)?;
        let raw = original[raw_index].raw.bytes();
        let value = credential(raw)?;
        if Sha256Digest::of_bytes(raw) != member.sha256 {
            return Err(LegacyImportError::Changed);
        }
        let index = credential_materials.len();
        if let Some(id) = &device
            && material_by_device.insert(id.clone(), index).is_some()
        {
            return Err(LegacyImportError::Invalid);
        }
        credential_materials.push(HistoricalCredential {
            device,
            relative_path: relative,
            raw_sha256: Sha256Digest::of_bytes(raw),
            credential_sha256: Sha256Digest::of_bytes(value),
            raw_index,
        });
    }
    let mut devices = Vec::new();
    let mut device_ids = BTreeSet::new();
    let mut fingerprints = BTreeSet::new();
    for record in database.devices {
        let p_index = *pending_by_device
            .get(&record.id)
            .ok_or(LegacyImportError::Unsupported)?;
        let pending = &database.pending[p_index];
        validate_target(&record.target)?;
        let token_path = runtime
            .enrollment
            .join("tokens")
            .join(format!("{}.token", record.id.as_str()));
        if !device_ids.insert(record.id.clone())
            || catalog_ids.contains(record.id.as_str())
            || record.target.id != record.id.as_str()
            || record.label != pending.label
            || record.fingerprint != pending.fingerprint
            || record.target.platform != pending.platform
            || record.target.cwd != pending.cwd
            || record.target.shell != pending.shell
            || record.target.shells != [pending.shell.clone()]
            || record.target.kind != "host"
            || record.target.exec.transport != "outbound"
            || record.target.exec.token_file.as_ref() != Some(&token_path)
            || record.target.exec.client_certificate_sha256.is_some()
            || !safe_time(record.approved_at)
        {
            return Err(LegacyImportError::Invalid);
        }
        let computer = record
            .target
            .computer
            .as_ref()
            .ok_or(LegacyImportError::Unsupported)?
            .enabled;
        let browser = record.target.browser.as_ref().is_some_and(|v| v.enabled);
        // Initial approval is a requested subset. Later signed old self-CAS may
        // legitimately add either capability; the DB retains no CAS signature,
        // so preserve the current historical grant without fabricating a proof.
        if record.target.generation.starts_with("paired-")
            && ((computer && !pending.computer_requested)
                || (browser && !pending.browser_requested.unwrap_or(false)))
        {
            return Err(LegacyImportError::Invalid);
        }
        if record.target.env.as_ref().is_some_and(|v| !v.is_empty()) {
            blockers.insert(PreparationBlocker::UnsupportedEnvironment);
        }
        if !fingerprints.insert(*record.fingerprint.as_bytes()) {
            blockers.insert(PreparationBlocker::HistoricalIdentityConflict);
        }
        let token_material = material_by_device.get(&record.id).copied();
        match record.status {
            HistoricalDeviceStatus::Approved => {
                if !record.target.allowed
                    || record.revoked_at.is_some()
                    || !matches!(
                        pending.status,
                        HistoricalPendingStatus::Approved | HistoricalPendingStatus::Claimed
                    )
                    || token_material.is_none()
                {
                    return Err(LegacyImportError::Invalid);
                }
            }
            HistoricalDeviceStatus::Revoked => {
                if !record.revoked_at.is_some_and(safe_time)
                    || pending.status != HistoricalPendingStatus::Revoked
                {
                    return Err(LegacyImportError::Invalid);
                }
                // A left-behind token after old revoke's unlink failure remains
                // preserved, but status always wins: no effective grant.
            }
        }
        let profile = verified_profiles[p_index]
            .take()
            .ok_or(LegacyImportError::Invalid)?;
        devices.push(HistoricalDevice {
            id: record.id,
            status: record.status,
            fingerprint: record.fingerprint,
            generation: record.target.generation,
            capabilities: HistoricalCapabilities {
                exec: record.target.allowed,
                computer,
                browser,
            },
            profile,
            pending_index: p_index,
            token_material,
        });
    }
    for pending in &database.pending {
        if !device_ids.contains(&pending.device_id)
            && pending.status != HistoricalPendingStatus::Pending
        {
            return Err(LegacyImportError::Invalid);
        }
    }
    if database.default_environment_id.as_ref().is_some_and(|id| {
        !devices
            .iter()
            .any(|d| d.id.as_str() == id && d.status == HistoricalDeviceStatus::Approved)
    }) {
        return Err(LegacyImportError::Invalid);
    }
    let snapshot = LegacyImportSnapshot {
        maintenance,
        root,
        path: state_dir.to_path_buf(),
        identity,
        original,
        tokens,
        token_root,
        devices,
        pending: database.pending,
        invitations: database.invitations,
        static_targets: catalog.targets,
        default_environment_id: database
            .default_environment_id
            .or(catalog.default_environment_id),
        blockers,
        credential_materials,
        transaction: maintenance.transaction_id().clone(),
    };
    snapshot.revalidate()?;
    Ok(snapshot)
}
fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn safe_time(t: u64) -> bool {
    t > 0 && t <= MAX_SAFE_INTEGER
}
fn validate_ingress(v: &HistoricalIngress) -> Result<()> {
    let origin = url::Url::parse(&v.origin).map_err(|_| LegacyImportError::Invalid)?;
    if origin.scheme() != "https"
        || origin.origin().ascii_serialization() != v.origin
        || v.generation.is_empty()
        || v.generation.len() > 128
        || v.generation.chars().any(char::is_control)
    {
        return Err(LegacyImportError::Invalid);
    }
    Ok(())
}
fn validate_target(t: &HistoricalTarget) -> Result<()> {
    if t.id.is_empty()
        || t.id.len() > 128
        || !t
            .id
            .bytes()
            .all(|v| v.is_ascii_alphanumeric() || b"._-".contains(&v))
        || !matches!(t.kind.as_str(), "host" | "environment")
        || !matches!(t.platform.as_str(), "linux" | "darwin" | "win32")
        || t.generation.is_empty()
        || t.generation.len() > 128
        || t.generation.chars().any(char::is_control)
        || t.cwd.len() > 2048
        || t.shell.len() > 2048
        || !absolute(&t.platform, &t.cwd)
        || !absolute(&t.platform, &t.shell)
        || t.shells.is_empty()
        || t.shells.len() > 16
        || !t.shells.contains(&t.shell)
        || t.shells
            .iter()
            .any(|v| v.len() > 2048 || !absolute(&t.platform, v))
    {
        return Err(LegacyImportError::Invalid);
    }
    match t.exec.transport.as_str() {
        "outbound" => {
            if t.kind != "host"
                || (t.exec.token_file.is_some() == t.exec.client_certificate_sha256.is_some())
                || t.exec.token_file.as_ref().is_some_and(|v| !v.is_absolute())
                || t.exec.url.is_some()
                || t.exec.binary.is_some()
            {
                return Err(LegacyImportError::Invalid);
            }
        }
        "websocket" => {
            let url = t.exec.url.as_ref().ok_or(LegacyImportError::Invalid)?;
            let url = url::Url::parse(url).map_err(|_| LegacyImportError::Invalid)?;
            if !matches!(url.scheme(), "ws" | "wss") {
                return Err(LegacyImportError::Invalid);
            }
        }
        "stdio" => {
            if !t
                .exec
                .binary
                .as_ref()
                .is_some_and(|v| absolute(&t.platform, v))
            {
                return Err(LegacyImportError::Invalid);
            }
        }
        _ => return Err(LegacyImportError::Unsupported),
    }
    if let Some(env) = &t.env
        && (env.len() > 64 || env.iter().any(|(k, v)| k.len() > 256 || v.len() > 4096))
    {
        return Err(LegacyImportError::Capacity);
    }
    if t.computer.as_ref().is_some_and(|c| c.socket.is_some()) {
        return Err(LegacyImportError::Unsupported);
    }
    if let Some(c) = &t.computer
        && c.enabled
    {
        match c.transport.as_deref() {
            Some("outbound") => {
                if t.kind != "host"
                    || t.exec.transport != "outbound"
                    || c.max_connections.is_some_and(|v| !(1..=8).contains(&v))
                {
                    return Err(LegacyImportError::Invalid);
                }
            }
            Some("stdio") => {
                if !c.binary.as_ref().is_some_and(|v| absolute(&t.platform, v)) {
                    return Err(LegacyImportError::Invalid);
                }
            }
            Some("mcp-http") => {
                if c.url.as_ref().is_none_or(|v| {
                    v.len() > 2048 || !(v.starts_with("https://") || v.starts_with("http://"))
                }) || c
                    .token_file
                    .as_ref()
                    .is_none_or(|v| !Path::new(v).is_absolute())
                {
                    return Err(LegacyImportError::Invalid);
                }
            }
            _ => return Err(LegacyImportError::Invalid),
        }
    }
    if let Some(b) = &t.browser
        && b.enabled
        && (t.kind != "host"
            || t.exec.transport != "outbound"
            || b.transport.as_deref() != Some("outbound"))
    {
        return Err(LegacyImportError::Invalid);
    }
    Ok(())
}
fn absolute(platform: &str, path: &str) -> bool {
    if path.contains('\0') {
        return false;
    }
    if platform == "win32" {
        let b = path.as_bytes();
        path.starts_with(['\\', '/'])
            || (b.len() >= 3
                && b[0].is_ascii_alphabetic()
                && b[1] == b':'
                && matches!(b[2], b'/' | b'\\'))
    } else {
        path.starts_with('/')
    }
}
#[cfg(test)]
#[path = "legacy_import_tests.rs"]
mod tests;
