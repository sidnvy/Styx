//! Writer-owned reopening of a completed native migration and its later C07 tip.
//! A read-only snapshot cannot release admission. The caller retains its original
//! configuration owner even if this operation fails.
use super::*;
use crate::store::{OwnedConfigurationRoot, management::OwnedManagementJournal};

#[must_use]
pub(crate) struct RecoveredNativeCommittedRuntime {
    owner: OwnedConfigurationRoot,
    snapshot: Arc<NativeCommittedRuntimeSnapshot>,
    _journal: Option<OwnedManagementJournal>,
}
impl RecoveredNativeCommittedRuntime {
    pub(crate) fn reopen(
        owner: &OwnedConfigurationRoot,
        snapshot: Arc<NativeCommittedRuntimeSnapshot>,
    ) -> JournalResult<Self> {
        if owner.identity()? != snapshot.root_identity() {
            return Err(JournalError::Conflict);
        }
        let journal =
            OwnedManagementJournal::open_existing(owner.clone(), JournalBudget::default())?;
        let mut proof = Self::reopen_with_journal(owner, snapshot, &journal)?;
        proof._journal = Some(journal);
        Ok(proof)
    }
    /// Reuse the management coordinator's already claimed namespace. Acquiring
    /// a second journal under the same writer would violate single ownership.
    pub(in crate::store) fn reopen_with_journal(
        owner: &OwnedConfigurationRoot,
        snapshot: Arc<NativeCommittedRuntimeSnapshot>,
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
        owner.with_state(|state| {
            state.require_recovery_inspection()?;
            proof.snapshot.revalidate()?;
            journal.with_directory_locked(state, |directory| {
                let scan = files::scan(directory, JournalBudget::default())?;
                let source = cutover::original_for::<NativeRootIdentity>(
                    &scan,
                    &proof.snapshot.original.intent.transaction_id,
                )?;
                if source.raw_intent != proof.snapshot.original.raw_intent
                    || source.phases != proof.snapshot.original.phases
                    || source.last_stage != DurableStage::Committed
                {
                    return Err(JournalError::Conflict);
                }
                let marker = super::super::native_state::decode_marker(&source.marker)
                    .map_err(|_| JournalError::Conflict)?;
                let raw = state
                    .root
                    .read_raw("state.json", MAX)
                    .map_err(|_| JournalError::Unknown)?;
                let canonical = super::super::native_state::decode_state(raw.bytes(), &marker)
                    .map_err(|_| JournalError::Conflict)?;
                management::validate_readonly_native_tip(&scan, &canonical, &marker)?;
                for file in &scan.files {
                    files::sync_file(directory, &file.name)?;
                    if files::read(directory, &file.name, MAX)?.as_deref() != Some(file.bytes()) {
                        return Err(JournalError::Unknown);
                    }
                }
                sync_directory(directory)?;
                Ok(())
            })?;
            state
                .root
                .inner
                .with_configuration_writer_directory(&state.writer, |directory| {
                    Ok((|| {
                        for name in [".styx-native-root-v1.json", "deployment.json", "state.json"] {
                            files::sync_file(directory, name)?;
                        }
                        sync_directory(directory)
                    })())
                })
                .map_err(|_| JournalError::Unknown)??;
            proof.snapshot.revalidate()?;
            state.finish_recovered_native_cutover(&proof)
        })?;
        proof.validate_owner(owner)?;
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
            // A changed retained material/namespace/App scope after reopening
            // must poison the SAME owner, not return an error while leaving its
            // published admission open. with_state publishes Unknown monotonically.
            self.snapshot
                .revalidate()
                .map_err(|_| JournalError::Unknown)
        })
    }
    pub(crate) fn state(&self) -> &NativeState {
        self.snapshot.state()
    }
}
fn sync_directory(directory: &std::fs::File) -> JournalResult<()> {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        directory.sync_all().map_err(|_| JournalError::Unknown)
    }
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    {
        files::sync_directory(directory)
    }
}
