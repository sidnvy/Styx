//! Versioned native configuration data, never OS/identity/writer authority.
//! Marker/state schemas intentionally differ from legacy onboarding schema1.
use crate::{
    identity::{Sha256Digest, TransactionId},
    management::ReaderContract,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const NATIVE_MARKER_SCHEMA: u16 = 1;
pub const NATIVE_STATE_SCHEMA: u16 = 2;
pub const NATIVE_MARKER_BYTES: usize = 4096;
pub const NATIVE_STATE_BYTES: usize = 1024 * 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeRuntimeFormat {
    NativeRustV1,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeRootKind {
    StyxConfigurationRoot,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeStateKind {
    StyxDesiredState,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "platform", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeRootIdentity {
    Linux {
        device: u64,
        inode: u64,
        uid: u32,
    },
    /// Observed local Windows object identity. DATA only; this does not enable
    /// configuration writes, journal recovery or execute a selected image.
    Windows {
        volume_serial: u64,
        file_id: u64,
        owner_sid: String,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRootMarker {
    pub schema: u16,
    pub kind: NativeRootKind,
    pub runtime_format: NativeRuntimeFormat,
    pub root_identity: NativeRootIdentity,
    /// Opaque 32-byte OS-random scope, encoded with the existing fixed-size hex
    /// scalar. This is not a hash/pin, device identity, secret, or trust root.
    pub scope_generation: Sha256Digest,
    pub reader_floor: ReaderContract,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeDeploymentMode {
    CreateLocal,
    JoinExisting,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeManager {
    ForegroundCli,
    AppManaged,
    PersistentService,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeRunDesired {
    Running,
    Stopped,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeAutostartDesired {
    Enabled,
    Disabled,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeComponentDesired {
    pub manager: NativeManager,
    pub run: NativeRunDesired,
    pub autostart: NativeAutostartDesired,
}
fn required_option<'de, D, T>(decoder: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(decoder)
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeDesired {
    #[serde(deserialize_with = "required_option")]
    pub gateway: Option<NativeComponentDesired>,
    #[serde(deserialize_with = "required_option")]
    pub host: Option<NativeComponentDesired>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeStateTransaction {
    pub transaction_id: TransactionId,
    pub sequence: u64,
}
/// Durable original-identity bindings, never a runtime/commit authority by DTO.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeMigrationBinding {
    pub transaction_id: TransactionId,
    pub original_state_sha256: Sha256Digest,
    pub retired_receipt_sha256: Sha256Digest,
    pub enrollment_baseline_sha256: Sha256Digest,
    pub enrollment_committed_sha256: Sha256Digest,
    pub candidate_manifest_sha256: Sha256Digest,
    pub publisher_spki_sha256: Sha256Digest,
    pub preservation_sha256: Sha256Digest,
    pub scope_bindings_sha256: Sha256Digest,
    pub original_token_relative_path: String,
}
/// No Debug/automatic logging: unknown extension values can contain secrets.
/// Formal readers MUST first reject decoded duplicate keys at every depth.
#[derive(Clone, Serialize)]
pub struct NativeState {
    pub schema: u16,
    pub kind: NativeStateKind,
    pub runtime_format: NativeRuntimeFormat,
    pub reader_contract: ReaderContract,
    pub scope_generation: Sha256Digest,
    pub deployment_raw_sha256: Sha256Digest,
    pub mode: NativeDeploymentMode,
    pub revision: u64,
    pub last_transaction: Option<NativeStateTransaction>,
    pub desired: NativeDesired,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub migration: Option<NativeMigrationBinding>,
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Box<serde_json::value::RawValue>>,
}
impl NativeState {
    /// Compare opaque extension bytes, never interpret/roundtrip their numbers.
    pub fn extensions_preserved_in(&self, target: &Self) -> bool {
        self.extensions.len() == target.extensions.len()
            && self.extensions.iter().all(|(name, value)| {
                target
                    .extensions
                    .get(name)
                    .is_some_and(|other| value.get().as_bytes() == other.get().as_bytes())
            })
    }
}

/// Explicit private configuration plan. This includes opaque target material;
/// clients must store it privately, not treat it as a redacted status/log DTO.
/// Parsing never supplies writer, root, maintenance or migration authority.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeConfigurationPlan {
    pub schema: u16,
    pub scope_generation: Sha256Digest,
    pub root_identity: NativeRootIdentity,
    pub intent: crate::management::DesiredStateCommit,
    pub target: Box<serde_json::value::RawValue>,
}

/// Versioned DATA only: the original cutover journal and retained maintenance
/// custody select it. Private endpoint key hashes remain in the private journal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeGatewayEndpointBinding {
    pub schema: u16,
    pub transaction_id: TransactionId,
    pub root_identity: NativeRootIdentity,
    pub candidate_manifest_sha256: Sha256Digest,
    pub origin: String,
    pub anchor_sha256: Sha256Digest,
    pub leaf_sha256: Sha256Digest,
    pub chain_sha256: Sha256Digest,
    pub not_before_unix: i64,
    pub not_after_unix: i64,
}

/// Canonical configuration DATA selecting a retained publisher-verified runtime.
/// Paths and kernel identity are locators/bindings, never execution, migration
/// commit, installation or publisher approval authority by themselves.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRuntimeSelection {
    pub schema: u16,
    pub payload_path: String,
    pub payload_root: NativeRootIdentity,
    pub manifest_sha256: Sha256Digest,
    pub publisher_file: String,
    pub publisher_spki_sha256: Sha256Digest,
}
