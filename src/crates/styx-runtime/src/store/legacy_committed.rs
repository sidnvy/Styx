//! Same-owner final cutover proof. Neither serialized receipts nor a closed
//! listener can manufacture this value. Fresh-process recovery is a distinct
//! committed-chain reader; this port owns only the original live transition.
use super::*;
use crate::store::{configuration::ConfigurationState, management::OwnedManagementJournal};

/// Retains the same writer and exact preparation through service promotion.
/// Deliberately no Clone/Deserialize; callers share the one proof with Arc.
#[must_use]
pub(crate) struct CommittedNativeCutover {
    owner: OwnedConfigurationRoot,
    journal: Arc<Mutex<OwnedManagementJournal>>,
    prepared: Arc<PreparedCutover>,
    root: RootIdentity,
    canonical_pin: FileObservation,
    committed: JournalReceipt,
}
impl CommittedNativeCutover {
    pub(crate) fn transaction_id(&self) -> &TransactionId {
        &self.prepared.intent().transaction_id
    }
    pub(crate) fn matches_prepared(&self, prepared: &PreparedNativeCutover) -> bool {
        Arc::ptr_eq(&self.prepared, &prepared.prepared)
    }
    pub(in crate::store) fn matches_fenced_root(
        &self,
        root: &RootIdentity,
        transaction: Option<&TransactionId>,
    ) -> bool {
        &self.root == root && transaction == Some(self.transaction_id())
    }
    fn validate_locked(
        &self,
        journal: &OwnedManagementJournal,
        state: &ConfigurationState,
    ) -> JournalResult<()> {
        if state.root.identity() != self.root {
            return Err(JournalError::Conflict);
        }
        let raw = state
            .root
            .read_raw(
                "state.json",
                styx_contracts::native_management::NATIVE_STATE_BYTES,
            )
            .map_err(|_| JournalError::Unknown)?;
        if raw.observation() != &self.canonical_pin || raw.bytes() != self.prepared.target() {
            return Err(JournalError::Unknown);
        }
        journal.validate_committed_cutover_locked(state, &self.prepared, &self.committed)
    }
    pub(crate) fn validate_owner(&self, owner: &OwnedConfigurationRoot) -> JournalResult<()> {
        if !self.owner.same_authority(owner) {
            return Err(JournalError::Conflict);
        }
        let journal = self.journal.lock().map_err(|_| JournalError::Unknown)?;
        owner.with_state(|state| {
            state.ordinary_admission()?;
            self.validate_locked(&journal, state)
        })
    }
}
impl LegacyWriterFence {
    pub(crate) fn record_cutover_paired_validation(
        &self,
        applied: &AppliedNativeCutover,
        raw: &[u8],
    ) -> JournalResult<Sha256Digest> {
        self.validate().map_err(|_| JournalError::Unknown)?;
        let identity = self.owner.identity()?;
        {
            let slot = self.retirement.lock().map_err(|_| JournalError::Unknown)?;
            if applied.root != identity
                || matching(&slot, &applied.prepared)?.canonical_pin.as_ref()
                    != Some(&applied.canonical_pin)
            {
                return Err(JournalError::Conflict);
            }
        }
        let result = self
            .original_journal()?
            .lock()
            .map_err(|_| JournalError::Unknown)?
            .record_cutover_paired_validation(&self.maintenance, &applied.prepared, raw);
        if result.is_err() {
            self.mark_cutover_unknown();
        }
        self.validate().map_err(|_| JournalError::Unknown)?;
        result
    }
    /// Called only after actual paired cleanup and durable Verified/Committed.
    /// The exact same writer remains alive; no namespace or ledger is replaced.
    pub(crate) fn finish_original_cutover(
        &self,
        applied: &AppliedNativeCutover,
        committed: JournalReceipt,
    ) -> JournalResult<CommittedNativeCutover> {
        self.validate().map_err(|_| JournalError::Unknown)?;
        let identity = self.owner.identity()?;
        {
            let slot = self.retirement.lock().map_err(|_| JournalError::Unknown)?;
            if matching(&slot, &applied.prepared)?.canonical_pin.as_ref()
                != Some(&applied.canonical_pin)
                || applied.root != identity
            {
                return Err(JournalError::Conflict);
            }
        }
        let proof = CommittedNativeCutover {
            owner: self.owner.clone(),
            journal: self.original_journal()?,
            prepared: applied.prepared.clone(),
            root: applied.root.clone(),
            canonical_pin: applied.canonical_pin.clone(),
            committed,
        };
        let journal = proof.journal.lock().map_err(|_| JournalError::Unknown)?;
        self.owner.with_maintenance(&self.maintenance, |state| {
            proof.validate_locked(&journal, state)?;
            state.finish_legacy_cutover(&proof)
        })?;
        drop(journal);
        proof.validate_owner(&self.owner)?;
        Ok(proof)
    }
}
