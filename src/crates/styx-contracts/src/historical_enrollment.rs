//! Private versioned historical enrollment journal data, never a remote proof.
//! This does not alter Device, native mutation or public MCP schemas. Runtime
//! verifies original roots/material crypto and original migration coordination.
use crate::{
    enrollment::{Device, Grant, MaterialRef, OpaqueProfileRef},
    identity::*,
};
use serde::{Deserialize, Serialize};

pub const HISTORICAL_BASELINE_BYTES: usize = 1024 * 1024;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "platform", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceRoot {
    Linux { device: u64, inode: u64, uid: u32 },
    Macos { device: u64, inode: u64, uid: u32 },
}
/// A revoked historical identity may legitimately have no credential file. It
/// is not a Device with an invented credential; it never permits any action.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalRevoked {
    pub id: DeviceId,
    pub fingerprint: Sha256Digest,
    pub grant: Grant,
    pub generation: String,
    pub profile: OpaqueProfileRef,
}
/// Original raw token material and normalized authentication material have
/// different hashes when original bytes include a newline. Neither hash is a
/// secret/bearer capability. A binding cannot authorize a revoked identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalTokenBinding {
    pub device: DeviceId,
    pub original_relative_path: String,
    pub raw_material: MaterialRef,
    pub normalized_material: MaterialRef,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalEnrollmentBaseline {
    pub schema: u8,
    pub migration: TransactionId,
    pub gateway_epoch: GatewayEpoch,
    pub sequence: u64,
    pub expected_revision: u64,
    pub prepared_at: u64,
    pub source_bindings_sha256: Sha256Digest,
    pub source_root: SourceRoot,
    pub enrollment_root: SourceRoot,
    pub devices: Vec<Device>,
    pub revoked: Vec<HistoricalRevoked>,
    pub default_device: Option<DeviceId>,
    pub token_bindings: Vec<HistoricalTokenBinding>,
    pub required_materials: Vec<MaterialRef>,
}
#[derive(Debug, thiserror::Error)]
#[error("invalid or unsupported historical enrollment baseline")]
pub struct HistoricalDecodeError;
fn bounds(body: &HistoricalEnrollmentBaseline) -> Result<(), HistoricalDecodeError> {
    if body.schema != 1
        || body.sequence != 1
        || body.expected_revision != 0
        || body
            .devices
            .len()
            .checked_add(body.revoked.len())
            .is_none_or(|n| n > 4096)
        || body.token_bindings.len() > 4096
        || body.required_materials.len() > 4096
        || body.token_bindings.iter().any(|b| {
            b.original_relative_path.len() > 512
                || b.original_relative_path.is_empty()
                || b.original_relative_path.starts_with('/')
                || b.original_relative_path
                    .split('/')
                    .any(|p| p.is_empty() || p == "." || p == "..")
                || b.original_relative_path
                    .bytes()
                    .any(|b| matches!(b, 0 | b'\\' | b':'))
        })
    {
        return Err(HistoricalDecodeError);
    }
    Ok(())
}
pub fn encode(body: &HistoricalEnrollmentBaseline) -> Result<Vec<u8>, HistoricalDecodeError> {
    bounds(body)?;
    let bytes = serde_json::to_vec(body).map_err(|_| HistoricalDecodeError)?;
    if bytes.len() > HISTORICAL_BASELINE_BYTES {
        return Err(HistoricalDecodeError);
    }
    Ok(bytes)
}
pub fn decode(bytes: &[u8]) -> Result<HistoricalEnrollmentBaseline, HistoricalDecodeError> {
    if bytes.is_empty() || bytes.len() > HISTORICAL_BASELINE_BYTES {
        return Err(HistoricalDecodeError);
    }
    let body = serde_json::from_slice(bytes).map_err(|_| HistoricalDecodeError)?;
    bounds(&body)?;
    Ok(body)
}
