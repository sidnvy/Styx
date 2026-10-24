//! Recovery of an existing durable enrollment-domain historical baseline.
//! This is deliberately not a C07 migration publication/commit authority.
use super::*;
use crate::crypto::ClaimCapability;
use crate::store::enrollment::HistoricalObservation;

const INTENT: &str = "historical-baseline.intent";
const PREPARED: &str = "historical-baseline.prepared";
const COMMITTED: &str = "historical-baseline.committed";

pub(super) fn is_record_name(name: &str) -> bool {
    matches!(name, INTENT | PREPARED | COMMITTED)
}

pub(super) fn observe_committed(
    journal: &EnrollmentJournal<'_>,
) -> Result<Option<HistoricalObservation>> {
    let Some(observation) = journal.observe_historical()? else {
        return Ok(None);
    };
    if observation.prepared.is_none() || observation.committed.is_none() {
        return Err(RecoveryBlocked::UnresolvedInventory);
    }
    if observation.digest != Sha256Digest::of_bytes(&observation.original_bytes)
        || styx_contracts::historical_enrollment::decode(&observation.original_bytes)
            .map_err(invalid)?
            != observation.body
    {
        return Err(RecoveryBlocked::InvalidRecord);
    }
    Ok(Some(observation))
}

pub(super) fn verify_record(
    observation: Option<&HistoricalObservation>,
    name: &str,
    bytes: &[u8],
) -> Result<()> {
    let observation = observation.ok_or(RecoveryBlocked::InvalidRecord)?;
    let expected = match name {
        INTENT => observation.original_bytes.clone(),
        PREPARED => serde_json::to_vec(
            observation
                .prepared
                .as_ref()
                .ok_or(RecoveryBlocked::InvalidRecord)?,
        )
        .map_err(invalid)?,
        COMMITTED => serde_json::to_vec(
            observation
                .committed
                .as_ref()
                .ok_or(RecoveryBlocked::InvalidRecord)?,
        )
        .map_err(invalid)?,
        _ => return Err(RecoveryBlocked::UnknownEntry),
    };
    if expected != bytes {
        return Err(RecoveryBlocked::InventoryChanged);
    }
    Ok(())
}

pub(super) fn recover(
    journal: &mut EnrollmentJournal<'_>,
    observation: HistoricalObservation,
    ledger: &mut EnrollmentLedger,
    control: &EnrollmentControl,
) -> Result<Sha256Digest> {
    // Resync only the already existing original baseline chain/materials. The
    // store checks its enrollment_root against its original retained PrivateRoot;
    // source_root is the distinct legacy configuration root, not this namespace.
    let after = journal
        .resync_historical()?
        .ok_or(RecoveryBlocked::InventoryChanged)?;
    if after.original_bytes != observation.original_bytes
        || after.digest != observation.digest
        || after.body != observation.body
    {
        return Err(RecoveryBlocked::InventoryChanged);
    }
    for name in [PREPARED, COMMITTED] {
        let bytes = match name {
            PREPARED => serde_json::to_vec(
                after
                    .prepared
                    .as_ref()
                    .ok_or(RecoveryBlocked::InvalidRecord)?,
            ),
            _ => serde_json::to_vec(
                after
                    .committed
                    .as_ref()
                    .ok_or(RecoveryBlocked::InvalidRecord)?,
            ),
        }
        .map_err(invalid)?;
        verify_record(Some(&observation), name, &bytes)?;
    }
    for binding in &observation.body.token_bindings {
        let raw = journal.read_material(&binding.raw_material)?;
        let normalized = journal.read_material(&binding.normalized_material)?;
        // Exactly the legacy protected-file normalization. Authentication uses
        // the normalized material, never the original newline-bearing bytes.
        let text = std::str::from_utf8(&raw).map_err(invalid)?.trim();
        if text.as_bytes() != normalized {
            return Err(RecoveryBlocked::InvalidRecord);
        }
        ClaimCapability::from_legacy_token_bytes(&normalized).map_err(invalid)?;
    }
    let receipt = observation
        .committed
        .as_ref()
        .ok_or(RecoveryBlocked::InvalidRecord)?
        .digest()?;
    let record = control.attest_historical_baseline(
        &observation.original_bytes,
        observation.digest,
        receipt,
    )?;
    ledger.recover_historical_baseline(record)?;
    Ok(receipt)
}

#[cfg(test)]
#[path = "recovery_historical_tests.rs"]
mod tests;
