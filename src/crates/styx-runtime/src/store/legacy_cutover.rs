//! First legacy-to-native canonical replacement under the ORIGINAL writer.
//! Only the migration coordinator calls these ports after physical scope/probe
//! checks. A prepared receipt is never final commit or ordinary admission.
use super::*;
use crate::store::{
    management::cutover::PreparedCutover,
    native_root::NATIVE_MARKER_FILE,
    native_state,
    secure_journal::{JournalError, JournalResult, files},
};
use nix::fcntl::{RenameFlags, renameat2};
use std::path::Path;
use styx_contracts::{
    identity::{Sha256Digest, TransactionId},
    management::{DurableStage, JournalReceipt},
};

pub(super) struct CutoverSlot {
    prepared: Option<Arc<PreparedCutover>>,
    canonical_pin: Option<FileObservation>,
    indeterminate: bool,
}
#[must_use]
pub(crate) struct PreparedNativeCutover {
    prepared: Arc<PreparedCutover>,
}
#[must_use]
pub(crate) struct AppliedNativeCutover {
    prepared: Arc<PreparedCutover>,
    root: RootIdentity,
    canonical_pin: FileObservation,
}
impl PreparedNativeCutover {
    pub(crate) fn transaction_id(&self) -> &TransactionId {
        &self.prepared.intent().transaction_id
    }
    pub(crate) fn target_sha256(&self) -> Sha256Digest {
        self.prepared.intent().target_state_sha256
    }
    pub(crate) fn prepared_sha256(&self) -> Sha256Digest {
        self.prepared.journal().record_sha256
    }
    pub(crate) fn endpoint_binding(&self) -> Option<&[u8]> {
        self.prepared.endpoint_binding()
    }
    pub(crate) fn endpoint_chain(&self) -> Option<&[u8]> {
        self.prepared.endpoint_chain()
    }
    pub(crate) fn endpoint_key(&self) -> Option<&[u8]> {
        self.prepared.endpoint_key()
    }
    pub(crate) fn history_baseline_sha256(&self) -> Sha256Digest {
        self.prepared.history_baseline_sha256()
    }
    pub(crate) fn history_committed_sha256(&self) -> Sha256Digest {
        self.prepared.history_committed_sha256()
    }
}
impl AppliedNativeCutover {
    pub(crate) fn transaction_id(&self) -> &TransactionId {
        &self.prepared.intent().transaction_id
    }
    pub(crate) fn target_sha256(&self) -> Sha256Digest {
        self.prepared.intent().target_state_sha256
    }
    pub(crate) fn candidate_sha256(&self) -> Sha256Digest {
        self.prepared.intent().candidate_manifest_sha256
    }
}
fn matching<'a>(
    slot: &'a retirement::RetirementSlot,
    prepared: &Arc<PreparedCutover>,
) -> JournalResult<&'a CutoverSlot> {
    let slot = slot.cutover.as_ref().ok_or(JournalError::Conflict)?;
    if slot.indeterminate
        || !slot
            .prepared
            .as_ref()
            .is_some_and(|same| Arc::ptr_eq(same, prepared))
    {
        return Err(JournalError::Unknown);
    }
    Ok(slot)
}
/// The ONLY new exception to the original frozen state locator: same opaque
/// prepared transaction + actual successful replacement's retained inode pin.
/// A DTO, target hash alone, or missing old path is not enough.
pub(super) fn validate_canonical_replacement(
    retirement: &retirement::RetirementSlot,
    root: &PrivateRoot,
    old: &FrozenFile,
) -> JournalResult<bool> {
    let Some(slot) = &retirement.cutover else {
        return Ok(false);
    };
    if slot.indeterminate {
        return Err(JournalError::Unknown);
    }
    if old.binding.root != LegacyMaterialRoot::Configuration
        || old.binding.relative_path != Path::new("state.json")
    {
        return Ok(false);
    }
    let Some(pin) = &slot.canonical_pin else {
        return Ok(false);
    };
    let prepared = slot.prepared.as_ref().ok_or(JournalError::Unknown)?;
    if prepared.before() != old.bytes.as_slice()
        || prepared.intent().before_state_sha256.to_hex() != old.sha256
    {
        return Err(JournalError::Unknown);
    }
    let canonical = root
        .read_raw(
            "state.json",
            styx_contracts::native_management::NATIVE_STATE_BYTES,
        )
        .map_err(|_| JournalError::Unknown)?;
    let marker = root
        .read_raw(
            NATIVE_MARKER_FILE,
            styx_contracts::native_management::NATIVE_MARKER_BYTES,
        )
        .map_err(|_| JournalError::Unknown)?;
    if canonical.observation() != pin
        || canonical.bytes() != prepared.target()
        || marker.bytes() != prepared.marker()
    {
        return Err(JournalError::Unknown);
    }
    let marker = native_state::decode_marker(marker.bytes()).map_err(|_| JournalError::Unknown)?;
    native_state::decode_state(canonical.bytes(), &marker).map_err(|_| JournalError::Unknown)?;
    Ok(true)
}
impl LegacyWriterFence {
    /// Borrow the exact retained preparation, never reconstruct it from a DTO.
    pub(crate) fn validate_prepared_cutover(
        &self,
        prepared: &PreparedNativeCutover,
    ) -> JournalResult<()> {
        self.validate().map_err(|_| JournalError::Unknown)?;
        {
            let slot = self.retirement.lock().map_err(|_| JournalError::Unknown)?;
            matching(&slot, &prepared.prepared)?;
        }
        let original = self
            .original_journal()?
            .lock()
            .map_err(|_| JournalError::Unknown)?
            .resync_original_cutover(&self.maintenance, prepared.transaction_id())?;
        if &original.intent != prepared.prepared.intent()
            || original.phases.first() != Some(prepared.prepared.journal())
        {
            return Err(JournalError::Unknown);
        }
        self.validate().map_err(|_| JournalError::Unknown)
    }
    pub(crate) fn cutover_sequence(&self) -> JournalResult<u64> {
        self.validate().map_err(|_| JournalError::Conflict)?;
        self.original_journal()?
            .lock()
            .map_err(|_| JournalError::Unknown)?
            .observe()?
            .handoffs
            .into_iter()
            .find(|handoff| &handoff.transaction_id == self.maintenance.transaction_id())
            .filter(|handoff| {
                handoff.stage == crate::store::management::CredentialRetirementStage::Retired
            })
            .map(|handoff| handoff.sequence)
            .ok_or(JournalError::Conflict)
    }
    pub(crate) fn prepare_native_cutover(
        &self,
        inputs: crate::store::management::cutover::CutoverInputs,
    ) -> JournalResult<PreparedNativeCutover> {
        self.validate().map_err(|_| JournalError::Conflict)?;
        let handle = self.original_journal()?;
        {
            let mut slot = self.retirement.lock().map_err(|_| JournalError::Unknown)?;
            if slot.cutover.is_some() {
                return Err(JournalError::Conflict);
            }
            slot.cutover = Some(CutoverSlot {
                prepared: None,
                canonical_pin: None,
                indeterminate: false,
            });
        }
        let result = handle
            .lock()
            .map_err(|_| JournalError::Unknown)?
            .prepare_cutover(&self.maintenance, inputs);
        match result {
            Ok(prepared) => {
                let prepared = Arc::new(prepared);
                if !prepared.matches_owner(&self.owner) {
                    self.mark_cutover_unknown();
                    return Err(JournalError::Unknown);
                }
                self.retirement
                    .lock()
                    .map_err(|_| JournalError::Unknown)?
                    .cutover
                    .as_mut()
                    .ok_or(JournalError::Unknown)?
                    .prepared = Some(prepared.clone());
                self.validate().map_err(|_| JournalError::Unknown)?;
                Ok(PreparedNativeCutover { prepared })
            }
            Err(error) => {
                self.mark_cutover_unknown();
                Err(error)
            }
        }
    }
    fn mark_cutover_unknown(&self) {
        if let Ok(mut slot) = self.retirement.lock()
            && let Some(cutover) = &mut slot.cutover
        {
            cutover.indeterminate = true;
        }
    }
    pub(crate) fn apply_native_cutover(
        &self,
        original: &PreparedNativeCutover,
    ) -> JournalResult<AppliedNativeCutover> {
        self.validate().map_err(|_| JournalError::Conflict)?;
        let handle = self.original_journal()?;
        let journal = handle.lock().map_err(|_| JournalError::Unknown)?;
        let result = self.owner.with_maintenance(&self.maintenance, |state| {
            {
                let slot = self.retirement.lock().map_err(|_| JournalError::Unknown)?;
                if matching(&slot, &original.prepared)?.canonical_pin.is_some()
                    || !original.prepared.matches_owner(&self.owner)
                {
                    return Err(JournalError::Conflict);
                }
            }
            let prepared = &original.prepared;
            let pin = state
                .root
                .read_raw(
                    "state.json",
                    styx_contracts::native_management::NATIVE_STATE_BYTES,
                )
                .map_err(|_| JournalError::Unknown)?;
            if pin.bytes() != prepared.before() {
                return Err(JournalError::Conflict);
            }
            state
                .root
                .ensure_absent(NATIVE_MARKER_FILE)
                .map_err(|_| JournalError::Conflict)?;
            let marker = native_state::decode_marker(prepared.marker())
                .map_err(|_| JournalError::InvalidInput)?;
            let target = native_state::decode_state(prepared.target(), &marker)
                .map_err(|_| JournalError::InvalidInput)?;
            if target.raw_sha256() != prepared.intent().target_state_sha256 {
                return Err(JournalError::Conflict);
            }
            state.preflight_growth(
                prepared
                    .target()
                    .len()
                    .checked_add(prepared.marker().len())
                    .ok_or(JournalError::BudgetExceeded)?,
            )?;
            journal.with_directory_locked(state, |directory| {
                let temporary = format!(
                    "txn-{}.state-temporary",
                    prepared.intent().transaction_id.as_str()
                );
                files::immutable(
                    directory,
                    &temporary,
                    prepared.target(),
                    journal.budget(),
                    &|_| {},
                )?;
                state
                    .root
                    .inner
                    .with_configuration_writer_directory(&state.writer, |root_dir| {
                        Ok((|| {
                            state
                                .root
                                .inner
                                .create_fixed(
                                    &state.writer,
                                    NATIVE_MARKER_FILE,
                                    prepared.marker(),
                                    &|_| {},
                                )
                                .map_err(|_| JournalError::Unknown)?;
                            let now = state
                                .root
                                .read_raw(
                                    "state.json",
                                    styx_contracts::native_management::NATIVE_STATE_BYTES,
                                )
                                .map_err(|_| JournalError::Unknown)?;
                            if now.observation() != pin.observation()
                                || now.bytes() != prepared.before()
                            {
                                return Err(JournalError::Unknown);
                            }
                            // Cooperative conditional replace, exactly like native
                            // configuration assignment; no hostile same-UID CAS claim.
                            renameat2(
                                directory,
                                temporary.as_str(),
                                root_dir,
                                "state.json",
                                RenameFlags::empty(),
                            )
                            .map_err(|_| JournalError::Unknown)?;
                            root_dir.sync_all().map_err(|_| JournalError::Unknown)?;
                            directory.sync_all().map_err(|_| JournalError::Unknown)?;
                            Ok(())
                        })())
                    })
                    .map_err(|_| JournalError::Unknown)??;
                Ok(())
            })?;
            let current = state
                .root
                .read_raw(
                    "state.json",
                    styx_contracts::native_management::NATIVE_STATE_BYTES,
                )
                .map_err(|_| JournalError::Unknown)?;
            if current.bytes() != prepared.target() {
                return Err(JournalError::Unknown);
            }
            let pin = current.observation().clone();
            self.retirement
                .lock()
                .map_err(|_| JournalError::Unknown)?
                .cutover
                .as_mut()
                .ok_or(JournalError::Unknown)?
                .canonical_pin = Some(pin.clone());
            Ok(AppliedNativeCutover {
                prepared: prepared.clone(),
                root: state.root.identity(),
                canonical_pin: pin,
            })
        });
        if result.is_err() {
            self.mark_cutover_unknown();
        }
        result
    }
    pub(crate) fn record_cutover_validation(
        &self,
        applied: &AppliedNativeCutover,
        report: &[u8],
    ) -> JournalResult<Sha256Digest> {
        self.validate().map_err(|_| JournalError::Unknown)?;
        let handle = self.original_journal()?;
        let result = handle
            .lock()
            .map_err(|_| JournalError::Unknown)?
            .record_cutover_validation(&self.maintenance, &applied.prepared, report);
        if result.is_err() {
            self.mark_cutover_unknown();
        }
        self.validate().map_err(|_| JournalError::Unknown)?;
        result
    }
    pub(crate) fn record_cutover_phase(
        &self,
        applied: &AppliedNativeCutover,
        stage: DurableStage,
    ) -> JournalResult<JournalReceipt> {
        self.validate().map_err(|_| JournalError::Unknown)?;
        if applied.root != self.owner.identity()? {
            return Err(JournalError::Conflict);
        }
        {
            let slot = self.retirement.lock().map_err(|_| JournalError::Unknown)?;
            if matching(&slot, &applied.prepared)?.canonical_pin.as_ref()
                != Some(&applied.canonical_pin)
            {
                return Err(JournalError::Unknown);
            }
        }
        let handle = self.original_journal()?;
        let result = (|| {
            let mut journal = handle.lock().map_err(|_| JournalError::Unknown)?;
            let receipt =
                journal.append_cutover_phase(&self.maintenance, &applied.prepared, stage)?;
            let original =
                journal.resync_original_cutover(&self.maintenance, applied.transaction_id())?;
            if original.phases.last() != Some(&receipt) {
                return Err(JournalError::Unknown);
            }
            Ok(receipt)
        })();
        if result.is_err() {
            self.mark_cutover_unknown();
        }
        self.validate().map_err(|_| JournalError::Unknown)?;
        result
    }
}

/// Read-only pending boot diagnostics; never a resume/commit/clear capability.
#[derive(Serialize)]
pub struct PendingNativeCutoverReport {
    pub transaction_id: TransactionId,
    pub stage: DurableStage,
    pub target_sha256: Sha256Digest,
    pub last_receipt_sha256: Sha256Digest,
    pub validation_sha256: Option<Sha256Digest>,
    pub ordinary_admission_open: bool,
}
pub(crate) fn inspect_pending_native_cutover(
    owner: OwnedConfigurationRoot,
) -> JournalResult<PendingNativeCutoverReport> {
    let journal = crate::store::management::OwnedManagementJournal::open_existing(
        owner.clone(),
        crate::store::enrollment::JournalBudget::default(),
    )?;
    owner.with_state(|state| {
        state.require_recovery_inspection()?;
        journal.with_directory_locked(state, |directory| {
            let scan = files::scan(directory, journal.budget())?;
            let parsed = crate::store::management::cutover::scan_cutovers(&scan)?;
            let record = parsed.records.first().ok_or(JournalError::Conflict)?;
            let inventory = journal.observe_locked(state)?;
            if parsed.records.len() != 1 || !inventory.orphans.is_empty() {
                return Err(JournalError::Conflict);
            }
            crate::store::management::cutover::check_canonical(state, record, true)?;
            for file in &scan.files {
                files::sync_file(directory, &file.name)?;
                if files::read(directory, &file.name, journal.budget().max_file_bytes)?.as_deref()
                    != Some(file.bytes())
                {
                    return Err(JournalError::Unknown);
                }
            }
            directory.sync_all().map_err(|_| JournalError::Unknown)?;
            crate::store::management::cutover::check_canonical(state, record, true)?;
            state.require_recovery_inspection()?;
            Ok(PendingNativeCutoverReport {
                transaction_id: record.intent.transaction_id.clone(),
                stage: record.last_stage,
                target_sha256: record.intent.target_state_sha256,
                last_receipt_sha256: record
                    .phases
                    .last()
                    .ok_or(JournalError::Conflict)?
                    .record_sha256,
                validation_sha256: record.validation_sha256,
                ordinary_admission_open: false,
            })
        })
    })
}
