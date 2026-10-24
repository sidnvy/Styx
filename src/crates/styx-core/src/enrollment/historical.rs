//! Trusted historical baseline replay, never a synthetic Join/Approve or grant.
//! Runtime must prove original writer/maintenance, durable commit and material
//! contents before attesting these bytes. Core validates only the pure links.
use super::*;
use std::collections::BTreeSet;
pub use styx_contracts::historical_enrollment::HistoricalRevoked;
use styx_contracts::historical_enrollment::{self as contract, HistoricalEnrollmentBaseline};

pub struct HistoricalBaselineRecovery {
    brand: Arc<()>,
    body: HistoricalEnrollmentBaseline,
    bytes: Arc<[u8]>,
    digest: Sha256Digest,
    receipt: Sha256Digest,
}
redacted!(HistoricalBaselineRecovery);

impl EnrollmentControl {
    /// Only the trusted boot adapter can assert verified durable provenance.
    /// Original bytes are retained; no legacy signature or CAS is fabricated.
    pub fn attest_historical_baseline(
        &self,
        bytes: &[u8],
        digest: Sha256Digest,
        receipt: Sha256Digest,
    ) -> Result<HistoricalBaselineRecovery> {
        if bytes.len() > contract::HISTORICAL_BASELINE_BYTES {
            return Err(EnrollmentError::Capacity);
        }
        if Sha256Digest::of_bytes(bytes) != digest {
            return Err(EnrollmentError::DurableMismatch);
        }
        let body = contract::decode(bytes).map_err(|_| EnrollmentError::Invalid)?;
        Ok(HistoricalBaselineRecovery {
            brand: self.brand.clone(),
            body,
            bytes: bytes.into(),
            digest,
            receipt,
        })
    }
}
fn material_key(reference: &MaterialRef) -> (&'static str, String) {
    (
        match reference.kind {
            MaterialKind::Profile => "profile",
            MaterialKind::Token => "token",
            MaterialKind::Sealed => "sealed",
        },
        reference.digest.to_hex(),
    )
}
/// Pure bounded DTO validation for preparation, not a durable receipt, recovered
/// ledger, original-runtime settlement or permission to publish imported facts.
pub fn validate_historical_baseline(
    baseline: &HistoricalEnrollmentBaseline,
    limits: Limits,
) -> Result<()> {
    baseline
        .journal_root()
        .map_err(|_| EnrollmentError::DurableMismatch)?;
    if baseline.sequence != 1 || baseline.expected_revision != 0 || baseline.prepared_at == 0 {
        return Err(EnrollmentError::DurableMismatch);
    }
    if limits.devices == 0
        || limits.devices > 4096
        || limits.retired == 0
        || limits.retired > 8192
        || baseline.token_bindings.len() > 4096
        || baseline.required_materials.len() > 4096
    {
        return Err(EnrollmentError::Capacity);
    }
    let count = baseline
        .devices
        .len()
        .checked_add(baseline.revoked.len())
        .ok_or(EnrollmentError::Capacity)?;
    // Reserve one retirement slot for EVERY approved key before publication.
    if count > limits.devices || count > limits.retired {
        return Err(EnrollmentError::Capacity);
    }
    let mut ids = BTreeSet::new();
    let mut fingerprints = BTreeSet::new();
    let mut required = BTreeSet::new();
    for device in &baseline.devices {
        if device.revoked
            || device.credential.0 != device.credential_hash
            || !generation(&device.generation)
            || device.generation.chars().any(char::is_control)
            || !ids.insert(device.id.clone())
            || !fingerprints.insert(*device.fingerprint.as_bytes())
        {
            return Err(EnrollmentError::Invalid);
        }
        required.insert(("profile", device.profile.0.to_hex()));
    }
    for device in &baseline.revoked {
        if !generation(&device.generation)
            || device.generation.chars().any(char::is_control)
            || !ids.insert(device.id.clone())
            || !fingerprints.insert(*device.fingerprint.as_bytes())
        {
            return Err(EnrollmentError::Invalid);
        }
        required.insert(("profile", device.profile.0.to_hex()));
    }
    let mut token_ids = BTreeSet::new();
    for token in &baseline.token_bindings {
        if !ids.contains(&token.device)
            || token.original_relative_path
                != format!("gateway/enrollment/tokens/{}.token", token.device.as_str())
            || !token_ids.insert(token.device.clone())
            || token.raw_material.kind != MaterialKind::Token
            || token.normalized_material.kind != MaterialKind::Token
        {
            return Err(EnrollmentError::Invalid);
        }
        if let Some(device) = baseline.devices.iter().find(|d| d.id == token.device)
            && token.normalized_material.digest != device.credential_hash
        {
            return Err(EnrollmentError::Invalid);
        }
        required.insert(material_key(&token.raw_material));
        required.insert(material_key(&token.normalized_material));
    }
    if baseline
        .devices
        .iter()
        .any(|device| !token_ids.contains(&device.id))
        || baseline
            .default_device
            .as_ref()
            .is_some_and(|id| !baseline.devices.iter().any(|d| &d.id == id))
        || baseline.required_materials.len() != required.len()
        || baseline
            .required_materials
            .iter()
            .map(material_key)
            .collect::<Vec<_>>()
            != required.into_iter().collect::<Vec<_>>()
    {
        return Err(EnrollmentError::Invalid);
    }
    // This uses the SAME closed codec bounds as replay, without creating an
    // attestation or substituting reserialized bytes for original durable data.
    contract::encode(baseline).map_err(|_| EnrollmentError::Invalid)?;
    Ok(())
}
impl EnrollmentLedger {
    pub(super) fn registered_identity_conflict(
        &self,
        id: &DeviceId,
        fingerprint: Sha256Digest,
    ) -> bool {
        self.devices
            .values()
            .any(|d| &d.id == id || d.fingerprint == fingerprint)
            || self
                .historical_revoked
                .values()
                .any(|d| &d.id == id || d.fingerprint == fingerprint)
    }
    pub(super) fn retained_device_count(&self) -> usize {
        // Both maps are bounded before every insertion; their sum cannot wrap.
        self.devices.len() + self.historical_revoked.len()
    }
    pub fn historical_revoked_for_admin(
        &self,
        admin: &EnrollmentAdminAuthority,
    ) -> Result<Vec<HistoricalRevoked>> {
        self.available()?;
        self.brand(&admin.brand)?;
        Ok(self.historical_revoked.values().cloned().collect())
    }
    pub fn historical_revoked_for_recovery(
        &self,
        control: &EnrollmentControl,
    ) -> Result<Vec<HistoricalRevoked>> {
        self.brand(&control.brand)?;
        Ok(self.historical_revoked.values().cloned().collect())
    }
    pub fn default_device_for_admin(
        &self,
        admin: &EnrollmentAdminAuthority,
    ) -> Result<Option<DeviceId>> {
        self.available()?;
        self.brand(&admin.brand)?;
        Ok(self.default_device.clone())
    }
    /// Import only into a truly pristine closed ledger. No merge, current TTL
    /// replay, inferred transport closure or public admission occurs here.
    pub fn recover_historical_baseline(
        &mut self,
        record: HistoricalBaselineRecovery,
    ) -> Result<()> {
        self.brand(&record.brand)?;
        if !self.recovering
            || self.revision != 0
            || self.sequence != 0
            || self.time_floor != 0
            || self.observed_time.get() != 0
            || self.recovered_head.is_some()
            || self.staged.is_some()
            || self.historical_baseline.is_some()
            || !self.invitations.is_empty()
            || !self.pending.is_empty()
            || !self.devices.is_empty()
            || !self.historical_revoked.is_empty()
            || !self.retired.is_empty()
            || !self.lanes.is_empty()
            || self.default_device.is_some()
        {
            return Err(EnrollmentError::Conflict);
        }
        let baseline = &record.body;
        if Sha256Digest::of_bytes(&record.bytes) != record.digest {
            return Err(EnrollmentError::DurableMismatch);
        }
        validate_historical_baseline(baseline, self.limits)?;
        // All fallible work precedes mutation. The historical facts keep their
        // original generation/grant; absent token on revoked is NOT synthesized.
        self.devices = baseline
            .devices
            .iter()
            .cloned()
            .map(|d| (d.id.clone(), d))
            .collect();
        self.historical_revoked = baseline
            .revoked
            .iter()
            .cloned()
            .map(|d| (d.id.clone(), d))
            .collect();
        self.retired = baseline.revoked.iter().map(|d| d.fingerprint).collect();
        for device in &baseline.devices {
            for lane in [Lane::Exec, Lane::Computer, Lane::Browser] {
                self.lanes
                    .insert((device.id.clone(), lane), LaneState::RecoveredUnknown);
            }
        }
        self.default_device = baseline.default_device.clone();
        self.revision = 1;
        self.sequence = 1;
        self.time_floor = baseline.prepared_at;
        self.recovered_head = Some(record.receipt);
        self.historical_baseline = Some(record);
        Ok(())
    }
}
#[cfg(test)]
#[path = "historical_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "historical_root_tests.rs"]
mod root_tests;
