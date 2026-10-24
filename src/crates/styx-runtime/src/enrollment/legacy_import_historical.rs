//! Material projection of protected original history, not new approval or
//! pairing. The old raw registry and credential files are never rewritten.
use super::*;
use styx_contracts::{
    enrollment::{CredentialRef, Device, Grant, MaterialKind, MaterialRef, OpaqueProfileRef},
    historical_enrollment::{
        HistoricalEnrollmentBaseline, HistoricalRevoked, HistoricalTokenBinding, SourceRoot,
    },
    identity::GatewayEpoch,
};
use zeroize::Zeroizing;

pub(crate) struct HistoricalMaterialBundle {
    pub body: HistoricalEnrollmentBaseline,
    pub materials: Vec<(MaterialRef, Zeroizing<Vec<u8>>)>,
}
fn root_id(root: RootIdentity) -> SourceRoot {
    let RootIdentity::Linux { device, inode, uid } = root;
    SourceRoot::Linux { device, inode, uid }
}
fn key(reference: &MaterialRef) -> (&'static str, String) {
    (
        match reference.kind {
            MaterialKind::Profile => "profile",
            MaterialKind::Token => "token",
            MaterialKind::Sealed => "sealed",
        },
        reference.digest.to_hex(),
    )
}
impl LegacyImportSnapshot<'_> {
    pub(crate) fn original_enrollment_identity(&self) -> RootIdentity {
        self.enrollment_root.identity()
    }
    pub(crate) fn historical_bundle(
        &self,
        epoch: GatewayEpoch,
        prepared_at: u64,
    ) -> Result<HistoricalMaterialBundle> {
        self.validate_preparation()?;
        if prepared_at == 0 || prepared_at > MAX_SAFE_INTEGER {
            return Err(LegacyImportError::Invalid);
        }
        let summary = self.summary()?;
        let mut materials = BTreeMap::new();
        let mut add = |kind, raw: &[u8]| {
            let reference = MaterialRef {
                kind,
                digest: Sha256Digest::of_bytes(raw),
            };
            materials
                .entry(key(&reference))
                .or_insert_with(|| (reference.clone(), Zeroizing::new(raw.to_vec())));
            reference
        };
        let mut devices = Vec::new();
        let mut revoked = Vec::new();
        let mut token_bindings = Vec::new();
        for device in &self.devices {
            let profile = add(MaterialKind::Profile, device.raw_profile_bytes());
            let grant = Grant {
                computer: device.capabilities.computer,
                browser: device.capabilities.browser,
            };
            if device.status == HistoricalDeviceStatus::Revoked {
                revoked.push(HistoricalRevoked {
                    id: device.id.clone(),
                    fingerprint: device.fingerprint,
                    grant,
                    generation: device.generation.clone(),
                    profile: OpaqueProfileRef(profile.digest),
                });
            } else {
                if !device.capabilities.exec {
                    return Err(LegacyImportError::Unsupported);
                }
                let index = device.token_material.ok_or(LegacyImportError::Invalid)?;
                let token = add(MaterialKind::Token, self.credential_bytes(index)?);
                devices.push(Device {
                    id: device.id.clone(),
                    fingerprint: device.fingerprint,
                    grant,
                    generation: device.generation.clone(),
                    credential: CredentialRef(token.digest),
                    credential_hash: token.digest,
                    profile: OpaqueProfileRef(profile.digest),
                    revoked: false,
                });
            }
            if let Some(index) = device.token_material {
                let original = self
                    .credential_materials()
                    .get(index)
                    .ok_or(LegacyImportError::Invalid)?;
                let raw = self
                    .original
                    .get(original.raw_index)
                    .ok_or(LegacyImportError::Invalid)?;
                let raw_material = add(MaterialKind::Token, raw.raw.bytes());
                let normalized_material = add(MaterialKind::Token, self.credential_bytes(index)?);
                token_bindings.push(HistoricalTokenBinding {
                    device: device.id.clone(),
                    original_relative_path: original
                        .relative_path
                        .to_str()
                        .ok_or(LegacyImportError::Invalid)?
                        .to_owned(),
                    raw_material,
                    normalized_material,
                });
            }
        }
        let materials: Vec<_> = materials.into_values().collect();
        let body = HistoricalEnrollmentBaseline {
            schema: 1,
            migration: self.transaction_id().clone(),
            gateway_epoch: epoch,
            sequence: 1,
            expected_revision: 0,
            prepared_at,
            source_bindings_sha256: summary.source_bindings_sha256,
            source_root: root_id(self.identity.clone()),
            enrollment_root: root_id(self.original_enrollment_identity()),
            devices,
            revoked,
            default_device: self
                .default_environment_id()
                .map(|s| DeviceId::try_from(s.to_owned()))
                .transpose()
                .map_err(|_| LegacyImportError::Invalid)?,
            token_bindings,
            required_materials: materials
                .iter()
                .map(|(reference, _)| reference.clone())
                .collect(),
        };
        // Validate pure links before I/O. Do not attest a durable receipt or
        // construct another ledger merely to validate a candidate projection.
        styx_core::enrollment::validate_historical_baseline(
            &body,
            styx_core::enrollment::Limits::default(),
        )
        .map_err(|_| LegacyImportError::Invalid)?;
        self.revalidate()?;
        Ok(HistoricalMaterialBundle { body, materials })
    }
}
