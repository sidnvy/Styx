//! Private versioned historical enrollment journal data, never a remote proof.
//! This does not alter Device, native mutation or public MCP schemas. Runtime
//! verifies original roots/material crypto and original migration coordination.
use crate::{
    enrollment::{Device, Grant, MaterialRef, OpaqueProfileRef},
    identity::*,
    native_management::NativeRootIdentity,
};
use serde::{Deserialize, Serialize};

pub const HISTORICAL_BASELINE_BYTES: usize = 1024 * 1024;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "platform", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceRoot {
    Linux {
        device: u64,
        inode: u64,
        uid: u32,
    },
    Macos {
        device: u64,
        inode: u64,
        uid: u32,
    },
    Windows {
        volume_serial: u64,
        file_id: u64,
        owner_sid: String,
    },
}
impl From<NativeRootIdentity> for SourceRoot {
    fn from(root: NativeRootIdentity) -> Self {
        match root {
            NativeRootIdentity::Linux { device, inode, uid } => Self::Linux { device, inode, uid },
            NativeRootIdentity::Macos { device, inode, uid } => Self::Macos { device, inode, uid },
            NativeRootIdentity::Windows {
                volume_serial,
                file_id,
                owner_sid,
            } => Self::Windows {
                volume_serial,
                file_id,
                owner_sid,
            },
        }
    }
}
impl From<SourceRoot> for NativeRootIdentity {
    fn from(root: SourceRoot) -> Self {
        match root {
            SourceRoot::Linux { device, inode, uid } => Self::Linux { device, inode, uid },
            SourceRoot::Macos { device, inode, uid } => Self::Macos { device, inode, uid },
            SourceRoot::Windows {
                volume_serial,
                file_id,
                owner_sid,
            } => Self::Windows {
                volume_serial,
                file_id,
                owner_sid,
            },
        }
    }
}
impl SourceRoot {
    fn same_owner(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Linux { uid, .. }, Self::Linux { uid: other, .. })
            | (Self::Macos { uid, .. }, Self::Macos { uid: other, .. }) => uid == other,
            (
                Self::Windows { owner_sid, .. },
                Self::Windows {
                    owner_sid: other, ..
                },
            ) => owner_sid == other,
            _ => false,
        }
    }
    fn valid_native(&self) -> bool {
        match self {
            Self::Linux { inode, .. } | Self::Macos { inode, .. } => *inode != 0,
            Self::Windows {
                file_id, owner_sid, ..
            } => {
                *file_id != 0
                    && owner_sid.len() <= 184
                    && owner_sid.starts_with("S-1-")
                    && owner_sid[4..]
                        .split('-')
                        .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
            }
        }
    }
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
    /// Identity of the original enrollment source, never a target path.
    pub enrollment_root: SourceRoot,
    /// Schema 1 omitted this field and stored history at enrollment_root.
    /// Schema 2 writes history under the SAME original state-root writer.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "explicit_journal_root"
    )]
    pub journal_root: Option<SourceRoot>,
    pub devices: Vec<Device>,
    pub revoked: Vec<HistoricalRevoked>,
    pub default_device: Option<DeviceId>,
    pub token_bindings: Vec<HistoricalTokenBinding>,
    pub required_materials: Vec<MaterialRef>,
}
#[derive(Debug, thiserror::Error)]
#[error("invalid or unsupported historical enrollment baseline")]
pub struct HistoricalDecodeError;
fn explicit_journal_root<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<SourceRoot>, D::Error> {
    // Absence is the old schema; an explicit null was never an old field.
    SourceRoot::deserialize(deserializer).map(Some)
}
impl HistoricalEnrollmentBaseline {
    /// Resolve only the explicitly versioned target. A malformed/new version
    /// must not silently fall back to an old source directory or mint a writer.
    pub fn journal_root(&self) -> Result<&SourceRoot, HistoricalDecodeError> {
        // Windows identity was never admitted by historical v1/v2. A newly
        // understood enum variant must not silently widen those old readers.
        if self.schema != 3
            && [&self.source_root, &self.enrollment_root]
                .into_iter()
                .chain(self.journal_root.iter())
                .any(|root| matches!(root, SourceRoot::Windows { .. }))
        {
            return Err(HistoricalDecodeError);
        }
        match (self.schema, self.journal_root.as_ref()) {
            (3, Some(root))
                if root == &self.source_root
                    && root.valid_native()
                    && self.enrollment_root.valid_native()
                    && root.same_owner(&self.enrollment_root) =>
            {
                Ok(root)
            }
            (1, None) => Ok(&self.enrollment_root),
            (2, Some(root)) if root == &self.source_root => Ok(root),
            _ => Err(HistoricalDecodeError),
        }
    }
}
fn bounds(body: &HistoricalEnrollmentBaseline) -> Result<(), HistoricalDecodeError> {
    if body.journal_root().is_err()
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

#[cfg(test)]
mod native_history_tests {
    use super::*;
    #[test]
    fn legacy_v2_linux_bytes_are_not_rewritten_by_native_schema_support() {
        let original = br#"{"schema":2,"migration":"old-migration","gateway_epoch":"old-gateway","sequence":1,"expected_revision":0,"prepared_at":10,"source_bindings_sha256":"0000000000000000000000000000000000000000000000000000000000000000","source_root":{"platform":"linux","device":1,"inode":2,"uid":1000},"enrollment_root":{"platform":"linux","device":1,"inode":3,"uid":1000},"journal_root":{"platform":"linux","device":1,"inode":2,"uid":1000},"devices":[],"revoked":[],"default_device":null,"token_bindings":[],"required_materials":[]}"#;
        let decoded = decode(original).unwrap();
        assert_eq!(decoded.schema, 2);
        assert_eq!(encode(&decoded).unwrap(), original);
    }
    fn body(root: SourceRoot) -> HistoricalEnrollmentBaseline {
        HistoricalEnrollmentBaseline {
            schema: 3,
            migration: "native-history-3".try_into().unwrap(),
            gateway_epoch: "native-history-epoch".try_into().unwrap(),
            sequence: 1,
            expected_revision: 0,
            prepared_at: 1,
            source_bindings_sha256: Sha256Digest::of_bytes(b"original"),
            source_root: root.clone(),
            enrollment_root: root.clone(),
            journal_root: Some(root),
            devices: vec![],
            revoked: vec![],
            default_device: None,
            token_bindings: vec![],
            required_materials: vec![],
        }
    }
    #[test]
    fn native_history_roundtrip_preserves_exact_platform_identity_and_old_versions_refuse_windows()
    {
        let root = NativeRootIdentity::Windows {
            volume_serial: 1,
            file_id: 2,
            owner_sid: "S-1-5-21-123".into(),
        };
        let good = body(root.clone().into());
        let decoded = decode(&encode(&good).unwrap()).unwrap();
        assert_eq!(NativeRootIdentity::from(decoded.source_root), root);
        for version in [1, 2] {
            let mut value = good.clone();
            value.schema = version;
            if version == 1 {
                value.journal_root = None;
            }
            assert!(encode(&value).is_err());
            assert!(decode(&serde_json::to_vec(&value).unwrap()).is_err());
        }
    }
    #[test]
    fn native_history_rejects_foreign_owner_platform_and_target_root() {
        let root = SourceRoot::Macos {
            device: 1,
            inode: 2,
            uid: 501,
        };
        let good = body(root);
        for bad in [
            SourceRoot::Linux {
                device: 1,
                inode: 2,
                uid: 501,
            },
            SourceRoot::Macos {
                device: 1,
                inode: 2,
                uid: 502,
            },
        ] {
            let mut value = good.clone();
            value.enrollment_root = bad;
            assert!(encode(&value).is_err());
        }
        let mut value = good;
        value.journal_root = Some(SourceRoot::Macos {
            device: 1,
            inode: 3,
            uid: 501,
        });
        assert!(encode(&value).is_err());
    }
}
