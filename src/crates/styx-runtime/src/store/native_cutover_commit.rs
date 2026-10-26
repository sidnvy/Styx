//! Final native migration settlement from the original completed probes.
//! Platform guards retain OS ownership; this shared stage never performs or replays work.
use super::*;

use crate::migration::{
    mac_exec_validation::MacCandidateExecProbe, mac_pair_validation::MacPairReadinessProbe,
};
use styx_core::management::transaction::JournalReceipt;

/// Same live original effects and writer; no Clone/Serde/public constructor.
/// This capability does not come from reopening a committed JSON receipt.
#[must_use]
pub(crate) struct NativeCommittedCutover<'guard, 'effects, 'materials> {
    guard: &'guard NativeCanonicalCutover<'effects, 'materials>,
    committed: JournalReceipt,
    local_sha256: Sha256Digest,
    pair_sha256: Sha256Digest,
}

impl<'effects, 'materials> NativeCanonicalCutover<'effects, 'materials> {
    fn validation_bytes(
        &self,
        local: &mut MacCandidateExecProbe<'_, '_, '_, '_>,
        pair: &mut MacPairReadinessProbe<'_, '_, '_, '_>,
    ) -> JournalResult<(Vec<u8>, Vec<u8>)> {
        // Signed loader compatibility, supplied by the root's R72 release
        // contract change; supporting StateV2 alone does not read report v2.
        if !self
            .candidate
            .manifest()
            .minimum_reader
            .supports_host_admission_v2()
        {
            return Err(JournalError::Conflict);
        }
        self.validate_applied()?;
        let local = local
            .validated_report_for(self)
            .map_err(|_| JournalError::Unknown)?;
        let pair = pair
            .validated_report_for(self)
            .map_err(|_| JournalError::Unknown)?;
        self.validate_applied()?;
        Ok((local, pair))
    }

    /// No probe execution here. Both actual attempts have already completed and
    /// joined. Resuming this method only reads/re-syncs the original chain and
    /// appends missing durable stages; it never replays a nonce or connection.
    pub(crate) fn commit_validated<'guard>(
        &'guard self,
        journal: &mut OwnedManagementJournal,
        local: &mut MacCandidateExecProbe<'_, '_, '_, '_>,
        pair: &mut MacPairReadinessProbe<'_, '_, '_, '_>,
    ) -> JournalResult<NativeCommittedCutover<'guard, 'effects, 'materials>> {
        if !journal.cutover_prepared_matches(&self.prepared) {
            return Err(JournalError::Conflict);
        }
        let (local_raw, pair_raw) = self.validation_bytes(local, pair)?;
        let mut original =
            journal.resync_native_cutover(self.maintenance, self.transaction_id())?;
        if original.intent != *self.prepared.intent()
            || !matches!(
                original.last_stage,
                DurableStage::Applied | DurableStage::Verified | DurableStage::Committed
            )
        {
            return Err(JournalError::Conflict);
        }
        // Existing bytes must be EXACTLY this original completed probe's bytes.
        // Absent attachments may only be appended at Applied, by the same writer.
        match original.validation_report() {
            Some(raw) if raw == local_raw => {}
            None if original.last_stage == DurableStage::Applied => {
                journal.record_cutover_validation(self.maintenance, &self.prepared, &local_raw)?;
            }
            _ => return Err(JournalError::Conflict),
        }
        match original.paired_validation_report() {
            Some(raw) if raw == pair_raw => {}
            None if original.last_stage == DurableStage::Applied => {
                journal.record_cutover_paired_validation(
                    self.maintenance,
                    &self.prepared,
                    &pair_raw,
                )?;
            }
            _ => return Err(JournalError::Conflict),
        }
        original = journal.resync_native_cutover(self.maintenance, self.transaction_id())?;
        if original.validation_report() != Some(local_raw.as_slice())
            || original.paired_validation_report() != Some(pair_raw.as_slice())
        {
            return Err(JournalError::Unknown);
        }
        if original.last_stage == DurableStage::Applied {
            self.require_same_validation(local, pair, &local_raw, &pair_raw)?;
            journal.append_cutover_phase(
                self.maintenance,
                &self.prepared,
                DurableStage::Verified,
            )?;
            original = journal.resync_native_cutover(self.maintenance, self.transaction_id())?;
        }
        if original.last_stage == DurableStage::Verified {
            self.require_same_validation(local, pair, &local_raw, &pair_raw)?;
            journal.append_cutover_phase(
                self.maintenance,
                &self.prepared,
                DurableStage::Committed,
            )?;
            original = journal.resync_native_cutover(self.maintenance, self.transaction_id())?;
        }
        if original.last_stage != DurableStage::Committed {
            return Err(JournalError::Unknown);
        }
        self.require_same_validation(local, pair, &local_raw, &pair_raw)?;
        let proof = NativeCommittedCutover {
            guard: self,
            committed: original.phases.last().ok_or(JournalError::Unknown)?.clone(),
            local_sha256: Sha256Digest::of_bytes(&local_raw),
            pair_sha256: Sha256Digest::of_bytes(&pair_raw),
        };
        // Do not nest an API that reacquires the same mutex in this closure.
        self.owner.with_maintenance(self.maintenance, |state| {
            proof.validate_locked(journal, state)
        })?;
        Ok(proof)
    }
    fn require_same_validation(
        &self,
        local: &mut MacCandidateExecProbe<'_, '_, '_, '_>,
        pair: &mut MacPairReadinessProbe<'_, '_, '_, '_>,
        local_raw: &[u8],
        pair_raw: &[u8],
    ) -> JournalResult<()> {
        let current = self.validation_bytes(local, pair)?;
        if current.0 != local_raw || current.1 != pair_raw {
            return Err(JournalError::Unknown);
        }
        Ok(())
    }
}
impl NativeCommittedCutover<'_, '_, '_> {
    pub(in crate::store) fn matches_fenced_owner(
        &self,
        owner: &OwnedConfigurationRoot,
        root: &RootIdentity,
        transaction: Option<&TransactionId>,
    ) -> bool {
        self.guard.owner.same_authority(owner)
            && self.guard.maintenance.matches(owner)
            && self.guard.prepared.matches_owner(owner)
            && committed_root_identity(self.guard.config_root()).is_ok_and(|actual| &actual == root)
            && transaction == Some(self.guard.transaction_id())
    }
    fn validate_locked(
        &self,
        journal: &OwnedManagementJournal,
        state: &crate::store::configuration::ConfigurationState,
    ) -> JournalResult<()> {
        state.require_native_maintenance(self.guard.transaction_id())?;
        if !journal.cutover_prepared_matches(&self.guard.prepared) {
            return Err(JournalError::Conflict);
        }
        let raw = state
            .root
            .read_raw("state.json", NATIVE_STATE_BYTES)
            .map_err(|_| JournalError::Unknown)?;
        if Some(raw.observation()) != self.guard.canonical_pin.as_ref()
            || raw.bytes() != self.guard.prepared.target()
        {
            return Err(JournalError::Unknown);
        }
        journal.validate_committed_cutover_locked(state, &self.guard.prepared, &self.committed)?;
        let inventory = journal.observe_locked(state)?;
        if inventory.has_unresolved_legacy_handoffs()
            || inventory.high_water != self.guard.prepared.intent().sequence
            || inventory.committed_cutover_anchor
                != Some((
                    self.guard.prepared.intent().sequence,
                    self.guard.target_sha256(),
                ))
            || inventory.transactions.iter().any(|transaction| {
                transaction.prepared.is_none()
                    || transaction
                        .phase_receipts
                        .last()
                        .is_none_or(|phase| phase.stage != DurableStage::Committed)
            })
        {
            return Err(JournalError::Conflict);
        }
        Ok(())
    }
    /// Consume this capability only under its original retained owner/fence.
    /// On any failure all original objects remain with the outer owner; this does
    /// not reconstruct fresh probes, drop/reopen a writer, or clear Unknown.
    pub(crate) fn release_admission(
        self,
        journal: &OwnedManagementJournal,
        local: &mut MacCandidateExecProbe<'_, '_, '_, '_>,
        pair: &mut MacPairReadinessProbe<'_, '_, '_, '_>,
        app_scope: Option<&crate::app::HostScope>,
    ) -> JournalResult<()> {
        let (local_raw, pair_raw) = self.guard.validation_bytes(local, pair)?;
        if Sha256Digest::of_bytes(&local_raw) != self.local_sha256
            || Sha256Digest::of_bytes(&pair_raw) != self.pair_sha256
        {
            return Err(JournalError::Conflict);
        }
        self.guard
            .owner
            .with_maintenance(self.guard.maintenance, |state| {
                if let Some(scope) = app_scope {
                    scope.validate().map_err(|_| JournalError::Unknown)?;
                }
                self.validate_locked(journal, state)?;
                state.finish_native_cutover(&self, &self.guard.owner)
            })
    }
}
