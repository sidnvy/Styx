//! Fresh native Host local binding DATA. Gateway remains the grant authority.
//! No legacy succeeded-step evidence, private PEM or device bearer lives here.
use crate::{
    identity::{DeviceId, Sha256Digest},
    native_management::{NativeRootIdentity, NativeRuntimeSelection},
};
use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeHostJoinSeed {
    pub schema: u16,
    pub root_identity: NativeRootIdentity,
    pub scope_generation: Sha256Digest,
    pub deployment_raw_sha256: Sha256Digest,
    pub runtime: NativeRuntimeSelection,
    pub gateway_origin: String,
    pub anchor_sha256: Sha256Digest,
    pub device_id: DeviceId,
    pub fingerprint: Sha256Digest,
    pub public_key_pem: String,
    pub label: String,
    pub platform: String,
    pub cwd: String,
    pub shell: String,
    pub computer_requested: bool,
    pub browser_requested: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeHostReady {
    pub schema: u16,
    pub seed_sha256: Sha256Digest,
    pub request_id: String,
    pub credential_sha256: Sha256Digest,
    pub device_id: DeviceId,
    pub fingerprint: Sha256Digest,
    pub generation: String,
    pub computer_approved: bool,
    pub browser_approved: bool,
}
