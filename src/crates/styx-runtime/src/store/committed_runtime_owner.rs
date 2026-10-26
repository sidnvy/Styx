//! Fresh-process reopening of the original committed configuration. The
//! read-only Host snapshot never owns this port or the Gateway writer.
use super::*;
use crate::store::{OwnedConfigurationRoot, management::OwnedManagementJournal};
use std::sync::Arc;

#[must_use]
pub(crate) struct RecoveredCommittedRuntime {
    owner: OwnedConfigurationRoot,
    snapshot: Arc<CommittedRuntimeSnapshot>,
    _journal: Option<OwnedManagementJournal>,
}
impl RecoveredCommittedRuntime {
    pub(crate) fn reopen(
        owner: OwnedConfigurationRoot,
        snapshot: Arc<CommittedRuntimeSnapshot>,
    ) -> JournalResult<Self> {
        if owner.identity()? != snapshot.root_identity() {
            return Err(JournalError::Conflict);
        }
        let journal =
            OwnedManagementJournal::open_existing(owner.clone(), JournalBudget::default())?;
        let mut proof = Self::reopen_with_journal(&owner, snapshot, &journal)?;
        proof._journal = Some(journal);
        Ok(proof)
    }
    pub(in crate::store) fn reopen_with_journal(
        owner: &OwnedConfigurationRoot,
        snapshot: Arc<CommittedRuntimeSnapshot>,
        journal: &OwnedManagementJournal,
    ) -> JournalResult<Self> {
        if owner.identity()? != snapshot.root_identity()
            || !journal.configuration_root().same_authority(owner)
        {
            return Err(JournalError::Conflict);
        }
        let proof = Self {
            owner: owner.clone(),
            snapshot,
            _journal: None,
        };
        proof.owner.with_state(|state| {
            state.require_recovery_inspection()?;
            proof.snapshot.revalidate()?;
            let canonical = state
                .root
                .read_raw("state.json", MAX)
                .map_err(|_| JournalError::Unknown)?;
            if canonical.bytes() != proof.snapshot.canonical() {
                return Err(JournalError::Conflict);
            }
            journal.with_directory_locked(state, |directory| {
                let scan = files::scan(directory, JournalBudget::default())?;
                let source =
                    cutover::original(&scan, &proof.snapshot.original.intent.transaction_id)?;
                if source.intent != proof.snapshot.original.intent
                    || source.phases != proof.snapshot.original.phases
                    || source.last_stage != DurableStage::Committed
                {
                    return Err(JournalError::Conflict);
                }
                cutover::check_committed_successor_root(&state.root, &source, &scan)?;
                for file in &scan.files {
                    files::sync_file(directory, &file.name)?;
                    if files::read(directory, &file.name, MAX)?.as_deref() != Some(file.bytes()) {
                        return Err(JournalError::Unknown);
                    }
                }
                directory.sync_all().map_err(|_| JournalError::Unknown)?;
                proof.snapshot.revalidate()
            })?;
            state.finish_recovered_cutover(&proof)
        })?;
        proof.validate_owner(&proof.owner)?;
        Ok(proof)
    }
    pub(in crate::store) fn matches_root(&self, root: &RootIdentity) -> bool {
        &self.snapshot.root_identity() == root
    }
    pub(crate) fn validate_owner(&self, owner: &OwnedConfigurationRoot) -> JournalResult<()> {
        if !self.owner.same_authority(owner) {
            return Err(JournalError::Conflict);
        }
        owner.with_state(|state| {
            if !self.matches_root(&state.root.identity()) {
                return Err(JournalError::Unknown);
            }
            state.ordinary_admission()?;
            // A changed original material poisons this same owner; do not
            // leave published admission open after returning an error.
            self.snapshot
                .revalidate()
                .map_err(|_| JournalError::Unknown)
        })
    }
    pub(crate) fn state(&self) -> &NativeState {
        self.snapshot.state()
    }
}
