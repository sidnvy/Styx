//! Historical enrollment preflight under the original configuration fence.
//! This does not stop the old Gateway, publish a native ledger or grant access.
use super::legacy_service::TransitionError;
pub use crate::enrollment::legacy_import::{LegacyImportSummary, PreparationBlocker};
use crate::{
    enrollment::legacy_import::{self, LegacyImportSnapshot},
    store::{ConfigurationMaintenance, PrivateRoot},
};
use std::{path::Path, sync::Arc};

/// Retains original raw files, token inventory and the active maintenance
/// borrow. There is no DTO conversion to Core authority or ordinary startup.
pub struct LegacyEnrollmentSnapshot<'m> {
    original: LegacyImportSnapshot<'m>,
}
fn classify(error: legacy_import::LegacyImportError) -> TransitionError {
    use legacy_import::LegacyImportError as E;
    match error {
        E::Invalid | E::Maintenance => TransitionError::Conflict,
        E::Changed => TransitionError::Unknown,
        E::Unavailable => TransitionError::Unavailable,
        E::Capacity | E::Unsettled => TransitionError::Busy,
        E::Unsupported => TransitionError::Unsupported,
    }
}
impl<'m> LegacyEnrollmentSnapshot<'m> {
    pub fn capture(
        state_dir: &Path,
        original: Arc<PrivateRoot>,
        maintenance: &'m ConfigurationMaintenance,
    ) -> Result<Self, TransitionError> {
        legacy_import::capture(state_dir, original, maintenance)
            .map(|original| Self { original })
            .map_err(classify)
    }
    /// Non-sensitive diagnostics explicitly retain original-Gateway settlement
    /// and native-import flags as false. A clean report is not admission.
    pub fn summary(&self) -> Result<LegacyImportSummary, TransitionError> {
        self.original.summary().map_err(classify)
    }
    pub fn revalidate(&self) -> Result<(), TransitionError> {
        self.original.revalidate().map_err(classify)
    }
    /// Historical inputs may be prepared only after every explicit blocker is
    /// resolved. Success still does not attest physical old-writer settlement.
    pub fn validate_preparation(&self) -> Result<(), TransitionError> {
        self.original.validate_preparation().map_err(classify)
    }
}

impl LegacyEnrollmentSnapshot<'_> {
    /// Claims one existing writer's fixed history store; caller retains that
    /// original owner even on failure. This does not acquire a second writer or
    /// prove original Gateway settlement. All ordinary access stays fenced.
    pub fn claim_history_store(
        &self,
        owner: &crate::store::OwnedConfigurationRoot,
        maintenance: &ConfigurationMaintenance,
    ) -> Result<crate::store::enrollment::OwnedEnrollmentJournal, TransitionError> {
        self.original.revalidate().map_err(classify)?;
        if owner.identity().map_err(|_| TransitionError::Unknown)?
            != self.original.original_enrollment_identity()
            || maintenance.transaction_id() != self.original.transaction_id()
            || !maintenance.matches(owner)
        {
            return Err(TransitionError::Conflict);
        }
        crate::store::enrollment::OwnedEnrollmentJournal::open_for_historical(
            owner.clone(),
            maintenance,
            crate::store::enrollment::JournalBudget::default(),
        )
        .map_err(|_| TransitionError::Unknown)
    }
    /// Persist original historical data in the native journal while C07 remains
    /// pending. A domain commit is NOT migration commit or network admission.
    /// Original caller-owned writer/maintenance and source remain retained on
    /// failure; there is no automatic retry, grant, token restore or activation.
    pub fn persist_candidate_history(
        &self,
        journal: &mut crate::store::enrollment::OwnedEnrollmentJournal,
        maintenance: &ConfigurationMaintenance,
        epoch: styx_contracts::identity::GatewayEpoch,
        trusted_now: u64,
    ) -> Result<crate::store::enrollment::HistoricalCommittedReceipt, TransitionError> {
        if maintenance.transaction_id() != self.original.transaction_id() {
            return Err(TransitionError::Conflict);
        }
        let bundle: crate::enrollment::legacy_import::HistoricalMaterialBundle = self
            .original
            .historical_bundle(epoch, trusted_now)
            .map_err(classify)?;
        let bytes = styx_contracts::historical_enrollment::encode(&bundle.body)
            .map_err(|_| TransitionError::Conflict)?;
        let result = journal
            .with_historical_journal(maintenance, |j| {
                if j.root_identity()? != self.original.original_enrollment_identity() {
                    return Err(crate::store::enrollment::JournalError::Conflict);
                }
                j.preflight_historical_bundle(&bytes, &bundle.materials)?;
                if j.read_time_floor()?.is_some_and(|time| time > trusted_now) {
                    return Err(crate::store::enrollment::JournalError::Conflict);
                }
                j.record_time_floor(trusted_now)?;
                for (expected, raw) in &bundle.materials {
                    if j.put_material(expected.kind, raw)? != *expected {
                        return Err(crate::store::enrollment::JournalError::Unknown);
                    }
                }
                let prepared = j.prepare_historical(&bytes)?;
                j.commit_historical(&prepared)
            })
            .map_err(|_| TransitionError::Unknown);
        // No cross-owner mutex is held during original-source observations.
        self.original
            .revalidate()
            .map_err(|_| TransitionError::Unknown)?;
        result
    }
}
