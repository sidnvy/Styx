//! Native configuration transactions under one opaque root/writer binding.
//! This changes desired configuration only; no OS service action, legacy owner
//! cutover, pairing or execution lease is implied. Unknown native effects are
//! never retried here. Recovery concerns the SAME pure configuration assignment.
use super::management::{
    ManagementTransactionObservation, OriginalManagementTransaction, OwnedManagementJournal,
};
use super::native_root::NativeRootBinding;
use super::native_state::{self, ValidatedNativeState};
use super::secure_journal::{JournalBudget, JournalError, JournalResult};
use super::{ConfigurationMaintenance, OwnedConfigurationRoot, RootIdentity};
use styx_contracts::identity::{Sha256Digest, TransactionId};
use styx_core::management::{state::validate_transition, transaction::*};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NativeTransactionError {
    #[error("native_transaction_invalid_input")]
    InvalidInput,
    #[error("native_transaction_conflict")]
    Conflict,
    #[error("native_transaction_unknown_inspect")]
    UnknownInspect,
    #[error("native_transaction_unsupported")]
    Unsupported,
}
impl From<JournalError> for NativeTransactionError {
    fn from(error: JournalError) -> Self {
        match error {
            JournalError::InvalidInput => Self::InvalidInput,
            JournalError::Conflict => Self::Conflict,
            JournalError::Unsupported => Self::Unsupported,
            _ => Self::UnknownInspect,
        }
    }
}
#[must_use = "the original native binding still owns the configuration writer"]
pub struct NativeTransactionOpenFailure {
    error: NativeTransactionError,
    binding: Box<NativeRootBinding>,
}
impl NativeTransactionOpenFailure {
    pub fn error(&self) -> NativeTransactionError {
        self.error
    }
    pub fn binding(&self) -> &NativeRootBinding {
        &self.binding
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeCommitResult {
    pub transaction_id: TransactionId,
    pub canonical_raw_sha256: Sha256Digest,
    pub committed: JournalReceipt,
    /// Explicit original configuration reconciliation, not native action replay.
    pub recovered: bool,
}
/// Only this coordinator can mint proof, after actual formal read + complete
/// original journal replay under the same owner lock. No DTO is a release port.
pub(super) struct NativeCommitProof {
    root: RootIdentity,
    transaction: TransactionId,
}
impl NativeCommitProof {
    pub(super) fn matches(&self, root: &RootIdentity, transaction: Option<&TransactionId>) -> bool {
        &self.root == root && transaction == Some(&self.transaction)
    }
}
pub struct NativeTransactions {
    binding: NativeRootBinding,
    journal: OwnedManagementJournal,
    retained_maintenance: Option<ConfigurationMaintenance>,
    retained_runtime_update: Option<runtime_update::RuntimeUpdateCustody>,
}
impl NativeTransactions {
    #[cfg(all(test, target_os = "linux", target_env = "gnu"))]
    pub(in crate::store) fn journal_for_test(&mut self) -> &mut OwnedManagementJournal {
        &mut self.journal
    }
    pub fn open(binding: NativeRootBinding) -> Result<Self, NativeTransactionOpenFailure> {
        match OwnedManagementJournal::open_existing(
            binding.configuration_root(),
            JournalBudget::default(),
        ) {
            Ok(journal) => Ok(Self {
                binding,
                journal,
                retained_maintenance: None,
                retained_runtime_update: None,
            }),
            Err(error) => Err(NativeTransactionOpenFailure {
                error: error.into(),
                binding: Box::new(binding),
            }),
        }
    }
    /// Reopen only a fully committed migration and complete later native tip.
    /// This reuses this coordinator's original journal and writer; it never
    /// decodes the old legacy before-image as a native configuration or advances
    /// an incomplete migration. Manager/scope policy belongs to the caller.
    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "macos",
        target_os = "windows"
    ))]
    pub(crate) fn reconcile_committed_migration(
        &mut self,
        snapshot: std::sync::Arc<super::committed_runtime_native::NativeCommittedRuntimeSnapshot>,
    ) -> Result<(), NativeTransactionError> {
        if self.marker().reader_floor
            != styx_contracts::management::ReaderContract::NativeMigratedStateV2
            || self.retained_maintenance.is_some()
        {
            return Err(NativeTransactionError::Conflict);
        }
        self.readstate()?;
        let owner = self.configuration_root();
        let _recovered =
            super::committed_runtime_native::RecoveredNativeCommittedRuntime::reopen_with_journal(
                &owner,
                snapshot,
                &self.journal,
            )?;
        Ok(())
    }
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    pub(crate) fn reconcile_committed_legacy_migration(
        &mut self,
        snapshot: std::sync::Arc<super::committed_runtime::CommittedRuntimeSnapshot>,
    ) -> Result<(), NativeTransactionError> {
        if self.marker().reader_floor
            != styx_contracts::management::ReaderContract::NativeMigratedStateV1
            || self.retained_maintenance.is_some()
        {
            return Err(NativeTransactionError::Conflict);
        }
        self.readstate()?;
        let owner = self.configuration_root();
        let _recovered = super::committed_runtime::RecoveredCommittedRuntime::reopen_with_journal(
            &owner,
            snapshot,
            &self.journal,
        )?;
        Ok(())
    }
    /// Transfer the already claimed journal into its one service coordinator.
    /// No writer or namespace is acquired here; the caller serialized admission.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    pub(crate) fn from_service_journal(
        owner: OwnedConfigurationRoot,
        journal: OwnedManagementJournal,
    ) -> Result<Self, NativeTransactionError> {
        if !journal.configuration_root().same_authority(&owner) {
            return Err(NativeTransactionError::Conflict);
        }
        let binding = super::native_root::bind_owned_native(owner)
            .map_err(|_| NativeTransactionError::UnknownInspect)?;
        Ok(Self {
            binding,
            journal,
            retained_maintenance: None,
            retained_runtime_update: None,
        })
    }
    /// The caller holds the original SharedEnrollment mutex and local control gate.
    /// Only autostart changes; Core/device lanes and all run states are preserved.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    pub(crate) fn set_service_autostart(
        &mut self,
        owner: &OwnedConfigurationRoot,
        component: crate::management::native::NativeComponent,
        enabled: bool,
        expected_revision: u64,
        transaction: TransactionId,
    ) -> Result<(NativeCommitResult, u64), NativeTransactionError> {
        use styx_contracts::native_management::NativeAutostartDesired;
        self.assign_service_desired(owner, component, expected_revision, transaction, |role| {
            role.autostart = if enabled {
                NativeAutostartDesired::Enabled
            } else {
                NativeAutostartDesired::Disabled
            };
        })
    }
    /// Desired Stop is committed before notification; it is never an actual-exit receipt.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    pub(crate) fn set_service_stopped(
        &mut self,
        owner: &OwnedConfigurationRoot,
        component: crate::management::native::NativeComponent,
        expected_revision: u64,
        transaction: TransactionId,
    ) -> Result<(NativeCommitResult, u64), NativeTransactionError> {
        self.assign_service_desired(owner, component, expected_revision, transaction, |role| {
            role.run = styx_contracts::native_management::NativeRunDesired::Stopped;
        })
    }
    /// Only a Host can be requested Running through the live Gateway writer.
    /// This changes intent only; the caller's original OS definition starts it.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    pub(crate) fn set_service_host_running(
        &mut self,
        owner: &OwnedConfigurationRoot,
        expected_revision: u64,
        transaction: TransactionId,
    ) -> Result<(NativeCommitResult, u64), NativeTransactionError> {
        self.assign_service_desired(
            owner,
            crate::management::native::NativeComponent::Host,
            expected_revision,
            transaction,
            |role| {
                role.run = styx_contracts::native_management::NativeRunDesired::Running;
            },
        )
    }
    /// Read this transaction's formally hash-bound target, not today's canonical
    /// revision and not the independent journal sequence number.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    pub(crate) fn service_transaction_target_revision(
        &self,
        transaction: &TransactionId,
    ) -> Result<u64, NativeTransactionError> {
        let original = self.journal.read_original(transaction)?;
        validate_original(&original, self.marker())?;
        let target = native_state::decode_state(&original.target, self.marker())
            .map_err(|_| NativeTransactionError::UnknownInspect)?;
        Ok(target.state().revision)
    }
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    fn assign_service_desired(
        &mut self,
        owner: &OwnedConfigurationRoot,
        component: crate::management::native::NativeComponent,
        expected_revision: u64,
        transaction: TransactionId,
        assign: impl FnOnce(&mut styx_contracts::native_management::NativeComponentDesired),
    ) -> Result<(NativeCommitResult, u64), NativeTransactionError> {
        use styx_contracts::native_management::{
            NATIVE_STATE_BYTES, NativeManager, NativeStateTransaction,
        };
        if !self.configuration_root().same_authority(owner) || self.retained_maintenance.is_some() {
            return Err(NativeTransactionError::Conflict);
        }
        let before = self.readstate()?;
        if before.state().revision != expected_revision {
            return Err(NativeTransactionError::Conflict);
        }
        let mut target = before.state().clone();
        let role = match component {
            crate::management::native::NativeComponent::Host => target.desired.host.as_mut(),
            crate::management::native::NativeComponent::Gateway => target.desired.gateway.as_mut(),
        }
        .ok_or(NativeTransactionError::InvalidInput)?;
        if role.manager != NativeManager::PersistentService {
            return Err(NativeTransactionError::Conflict);
        }
        assign(role);
        target.revision = target
            .revision
            .checked_add(1)
            .ok_or(NativeTransactionError::InvalidInput)?;
        let inventory = self.journal.observe()?;
        let sequence = inventory
            .high_water
            .max(
                before
                    .state()
                    .last_transaction
                    .as_ref()
                    .map_or(0, |t| t.sequence),
            )
            .checked_add(1)
            .ok_or(NativeTransactionError::InvalidInput)?;
        target.last_transaction = Some(NativeStateTransaction {
            transaction_id: transaction.clone(),
            sequence,
        });
        let bytes =
            serde_json::to_vec(&target).map_err(|_| NativeTransactionError::InvalidInput)?;
        if bytes.len() > NATIVE_STATE_BYTES {
            return Err(NativeTransactionError::InvalidInput);
        }
        // Reject conflicts, reused IDs and incomplete predecessors before fencing.
        let (before, intent) = self.plan(&bytes)?;
        let maintenance = owner.begin_maintenance(transaction)?;
        let result = self.apply_prepared(&maintenance, &before, &bytes, &intent, &|_, _| {});
        match result {
            Ok(commit) => Ok((commit, target.revision)),
            Err(error) => {
                self.retained_maintenance = Some(maintenance);
                Err(error)
            }
        }
    }
    pub fn marker(&self) -> &styx_contracts::native_management::NativeRootMarker {
        self.binding.marker()
    }
    pub fn configuration_root(&self) -> OwnedConfigurationRoot {
        self.binding.configuration_root()
    }
    pub fn readstate(&self) -> Result<ValidatedNativeState, NativeTransactionError> {
        self.binding
            .validated_readstate()
            .map_err(|_| NativeTransactionError::UnknownInspect)
    }
    /// Observation is neither a new durability receipt nor permission to replay.
    pub fn query(
        &self,
        id: &TransactionId,
    ) -> Result<Option<ManagementTransactionObservation>, NativeTransactionError> {
        Ok(self
            .journal
            .observe()?
            .transactions
            .into_iter()
            .find(|tx| &tx.intent.transaction_id == id))
    }
    /// Read the original, hash-bound role ownership before any recovery. This
    /// exposes desired DATA only and cannot authorize or replay a transaction.
    pub(crate) fn original_desired(
        &self,
        id: &TransactionId,
    ) -> Result<
        (
            styx_contracts::native_management::NativeDesired,
            styx_contracts::native_management::NativeDesired,
        ),
        NativeTransactionError,
    > {
        let original = self.journal.read_original(id)?;
        validate_original(&original, self.binding.marker())?;
        let before = native_state::decode_state(&original.before, self.binding.marker())
            .map_err(|_| NativeTransactionError::UnknownInspect)?;
        let target = native_state::decode_state(&original.target, self.binding.marker())
            .map_err(|_| NativeTransactionError::UnknownInspect)?;
        Ok((
            before.state().desired.clone(),
            target.state().desired.clone(),
        ))
    }
    /// Standalone startup only. If enrollment authority is instantiated, callers
    /// must obtain its complete maintenance gate and use apply_with_maintenance.
    pub fn apply_target(
        &mut self,
        target: &[u8],
    ) -> Result<NativeCommitResult, NativeTransactionError> {
        self.apply_observing(target, &|_, _| {})
    }
    fn apply_observing(
        &mut self,
        target: &[u8],
        observer: &dyn Fn(&str, &str),
    ) -> Result<NativeCommitResult, NativeTransactionError> {
        let (before, intent) = self.plan(target)?;
        let maintenance = self
            .configuration_root()
            .begin_standalone_native(intent.transaction_id.clone(), false)?;
        let result = self.apply_prepared(&maintenance, &before, target, &intent, observer);
        if result.is_err() {
            self.retained_maintenance = Some(maintenance);
        }
        result
    }
    pub fn apply_with_maintenance(
        &mut self,
        maintenance: &ConfigurationMaintenance,
        target: &[u8],
    ) -> Result<NativeCommitResult, NativeTransactionError> {
        let (before, intent) = self.plan(target)?;
        self.apply_prepared(maintenance, &before, target, &intent, &|_, _| {})
    }
    /// Typed preview under this opaque binding, not permission to apply later.
    pub fn validate_target(
        &self,
        target: &[u8],
    ) -> Result<DesiredStateCommit, NativeTransactionError> {
        self.plan(target).map(|(_, intent)| intent)
    }
    /// Save an explicitly requested private review artifact without modifying
    /// canonical state or journal. Name is fixed by a validated transaction ID.
    /// Existing files are never replaced; no network/filepath authority is minted.
    pub fn save_plan(
        &self,
        id: &TransactionId,
        bytes: &[u8],
    ) -> Result<String, NativeTransactionError> {
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "windows",
            target_os = "macos"
        ))]
        {
            if bytes.is_empty()
                || bytes.len() > styx_contracts::native_management::NATIVE_STATE_BYTES
            {
                return Err(NativeTransactionError::InvalidInput);
            }
            let name = format!("plan-{}.json", id.as_str());
            self.binding.with_binding(|state, _| {
                state.ordinary_admission()?;
                match state.root.ensure_absent(&name) {
                    Ok(()) => (),
                    Err(super::StoreError::Changed) => return Err(JournalError::Conflict),
                    Err(_) => return Err(JournalError::Unknown),
                }
                state
                    .root
                    .inner
                    .create_fixed(&state.writer, &name, bytes, &|_| {})
                    .map_err(|_| JournalError::Unknown)
            })?;
            Ok(name)
        }
        #[cfg(not(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "windows",
            target_os = "macos"
        )))]
        {
            let _ = (id, bytes);
            Err(NativeTransactionError::Unsupported)
        }
    }
    fn plan(
        &self,
        target_raw: &[u8],
    ) -> Result<(Vec<u8>, DesiredStateCommit), NativeTransactionError> {
        let before = self.readstate()?;
        self.validate_complete_chain(&before)?;
        let target = native_state::decode_state(target_raw, self.binding.marker())
            .map_err(|_| NativeTransactionError::InvalidInput)?;
        let tx = target
            .state()
            .last_transaction
            .as_ref()
            .ok_or(NativeTransactionError::InvalidInput)?;
        let intent = DesiredStateCommit {
            transaction_id: tx.transaction_id.clone(),
            sequence: tx.sequence,
            deployment_raw_sha256: before.state().deployment_raw_sha256,
            before_state_sha256: before.raw_sha256(),
            target_state_sha256: target.raw_sha256(),
            reader: before.state().reader_contract,
        };
        validate_transition(
            before.state(),
            target.state(),
            self.binding.marker(),
            &intent,
        )
        .map_err(|_| NativeTransactionError::InvalidInput)?;
        let inventory = self.journal.observe()?;
        if !inventory.orphans.is_empty()
            || intent.sequence <= inventory.high_water
            || inventory.transactions.iter().any(|tx| {
                tx.intent.transaction_id == intent.transaction_id
                    || !tx
                        .phase_receipts
                        .last()
                        .is_some_and(|r| r.stage == DurableStage::Committed)
            })
        {
            return Err(NativeTransactionError::Conflict);
        }
        Ok((before.raw_bytes().to_vec(), intent))
    }
    fn apply_prepared(
        &mut self,
        maintenance: &ConfigurationMaintenance,
        before: &[u8],
        target: &[u8],
        intent: &DesiredStateCommit,
        observer: &dyn Fn(&str, &str),
    ) -> Result<NativeCommitResult, NativeTransactionError> {
        if maintenance.transaction_id() != &intent.transaction_id {
            return Err(NativeTransactionError::Conflict);
        }
        let raw_intent =
            serde_json::to_vec(intent).map_err(|_| NativeTransactionError::InvalidInput)?;
        let prepared = self
            .journal
            .prepare(maintenance, &raw_intent, before, target)?;
        observer("prepared", "persisted");
        let mut transaction = ManagementTransaction::plan(intent.clone())
            .map_err(|_| NativeTransactionError::InvalidInput)?;
        transaction
            .prepare(PreparedFacts {
                intent: intent.clone(),
                deployment_raw_sha256: intent.deployment_raw_sha256,
                canonical_state_sha256: intent.before_state_sha256,
                reader: intent.reader,
                journal: prepared.journal,
            })
            .map_err(|_| NativeTransactionError::UnknownInspect)?;
        self.replace_canonical(maintenance, before, target, intent, observer)?;
        self.complete(maintenance, transaction, false, observer)
    }
    fn replace_canonical(
        &self,
        maintenance: &ConfigurationMaintenance,
        before: &[u8],
        target: &[u8],
        intent: &DesiredStateCommit,
        observer: &dyn Fn(&str, &str),
    ) -> Result<(), NativeTransactionError> {
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "windows",
            target_os = "macos"
        ))]
        {
            self.validate_update_publication(before, target, intent)?;
            use super::secure_journal::files;
            #[cfg(all(target_os = "linux", target_env = "gnu"))]
            use nix::fcntl::{RenameFlags, renameat2};
            self.binding.with_binding(|state, marker| {
                self.configuration_root()
                    .same_authority(&self.journal.configuration_root())
                    .then_some(())
                    .ok_or(JournalError::Conflict)?;
                if !maintenance.matches(&self.configuration_root()) {
                    return Err(JournalError::Conflict);
                }
                state.require_native_maintenance(maintenance.transaction_id())?;
                let current = self.binding.read_locked(state)?;
                let parsed_target = native_state::decode_state(target, marker)
                    .map_err(|_| JournalError::InvalidInput)?;
                styx_core::management::state::validate_committed_transition(
                    current.state(),
                    parsed_target.state(),
                    marker,
                    intent,
                )
                .map_err(|_| JournalError::Conflict)?;
                if current.raw_bytes() != before
                    || current.raw_sha256() != intent.before_state_sha256
                    || parsed_target.raw_sha256() != intent.target_state_sha256
                {
                    return Err(JournalError::Conflict);
                }
                let pin = state
                    .root
                    .read_raw(
                        "state.json",
                        styx_contracts::native_management::NATIVE_STATE_BYTES,
                    )
                    .map_err(|_| JournalError::Unknown)?;
                state.preflight_growth(target.len())?;
                self.journal.with_directory_locked(state, |directory| {
                    let temporary =
                        format!("txn-{}.state-temporary", intent.transaction_id.as_str());
                    files::immutable(
                        directory,
                        &temporary,
                        target,
                        self.journal.budget(),
                        &|phase| observer("canonical_temporary", phase),
                    )?;
                    // Cooperating writer conditional replacement. This is NOT an
                    // atomic compare-and-swap against hostile same-UID writers.
                    let now = state
                        .root
                        .read_raw(
                            "state.json",
                            styx_contracts::native_management::NATIVE_STATE_BYTES,
                        )
                        .map_err(|_| JournalError::Unknown)?;
                    if now.observation() != pin.observation() || now.bytes() != before {
                        return Err(JournalError::Unknown);
                    }
                    state
                        .root
                        .inner
                        .with_configuration_writer_directory(&state.writer, |_root_dir| {
                            let result = (|| {
                                #[cfg(all(target_os = "linux", target_env = "gnu"))]
                                {
                                    renameat2(
                                        directory,
                                        temporary.as_str(),
                                        _root_dir,
                                        "state.json",
                                        RenameFlags::empty(),
                                    )
                                    .map_err(|_| JournalError::Unknown)?;
                                    observer("canonical", "rename");
                                    _root_dir.sync_all().map_err(|_| JournalError::Unknown)?;
                                    directory.sync_all().map_err(|_| JournalError::Unknown)?;
                                }
                                #[cfg(target_os = "macos")]
                                {
                                    nix::fcntl::renameat(
                                        directory,
                                        temporary.as_str(),
                                        _root_dir,
                                        "state.json",
                                    )
                                    .map_err(|_| JournalError::Unknown)?;
                                    observer("canonical", "rename");
                                    files::sync_file(_root_dir, "state.json")?;
                                    files::sync_directory(_root_dir)?;
                                    files::sync_directory(directory)?;
                                }
                                #[cfg(target_os = "windows")]
                                {
                                    // Original writer, expected canonical observation and
                                    // protected namespace remain held throughout publication.
                                    state
                                        .root
                                        .inner
                                        .replace_native_state_from_journal(
                                            &state.writer,
                                            (directory, &temporary),
                                            &pin,
                                            target,
                                            &|phase| observer("canonical", phase),
                                        )
                                        .map_err(|_| JournalError::Unknown)?;
                                }
                                observer("canonical", "directory_sync");
                                Ok(())
                            })();
                            Ok(result)
                        })
                        .map_err(|_| JournalError::Unknown)??;
                    Ok(())
                })?;
                if self.binding.read_locked(state)?.raw_bytes() != target {
                    return Err(JournalError::Unknown);
                }
                Ok(())
            })?;
            Ok(())
        }
        #[cfg(not(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "windows",
            target_os = "macos"
        )))]
        {
            let _ = (maintenance, before, target, intent, observer);
            Err(NativeTransactionError::Unsupported)
        }
    }
    fn complete(
        &mut self,
        maintenance: &ConfigurationMaintenance,
        mut transaction: ManagementTransaction,
        recovered: bool,
        observer: &dyn Fn(&str, &str),
    ) -> Result<NativeCommitResult, NativeTransactionError> {
        let intent = transaction.snapshot().intent;
        self.revalidate_runtime_custody()?;
        for stage in [
            DurableStage::Applied,
            DurableStage::Verified,
            DurableStage::Committed,
        ] {
            let last = transaction.snapshot().last_durable_stage;
            if stage_rank(stage) <= stage_rank(last) {
                continue;
            }
            self.revalidate_runtime_custody()?;
            self.binding.with_binding(|state, _| {
                if self.binding.resync_locked(state)?.raw_sha256() != intent.target_state_sha256 {
                    return Err(JournalError::Conflict);
                }
                Ok(())
            })?;
            let receipt = self.journal.append_phase(
                maintenance,
                &intent,
                stage,
                transaction
                    .snapshot()
                    .journal_head
                    .ok_or(NativeTransactionError::UnknownInspect)?,
                recovered,
            )?;
            advance(&mut transaction, &intent, receipt)?;
            observer(stage_label(stage), "persisted");
        }
        // Verify actual complete original chain and canonical file again in the
        // SAME short owner closure that mints proof and clears the fence.
        let committed = self.binding.with_binding(|state, marker| {
            state.require_native_maintenance(maintenance.transaction_id())?;
            self.journal
                .assert_complete_locked(state, &intent.transaction_id)?;
            let canonical = self.binding.resync_locked(state)?;
            let original = self
                .journal
                .read_original_locked(state, &intent.transaction_id)?;
            validate_original(&original, marker)?;
            let replay = replay(&original)?;
            if original.intent != intent
                || canonical.raw_sha256() != intent.target_state_sha256
                || replay.snapshot().last_durable_stage != DurableStage::Committed
            {
                return Err(JournalError::Unknown);
            }
            let proof = NativeCommitProof {
                root: state.root.identity(),
                transaction: intent.transaction_id.clone(),
            };
            state.finish_native(&proof)?;
            original.phases.last().cloned().ok_or(JournalError::Unknown)
        })?;
        observer("committed", "reply");
        Ok(NativeCommitResult {
            transaction_id: intent.transaction_id,
            canonical_raw_sha256: intent.target_state_sha256,
            committed,
            recovered,
        })
    }
    /// Explicit recovery of ORIGINAL pure configuration intent. An incomplete
    /// journal, unknown orphan, changed canonical bytes, or Applied->before
    /// contradiction remains fenced for inspection; no fresh transaction is made.
    pub fn recover_original(
        &mut self,
        id: &TransactionId,
    ) -> Result<NativeCommitResult, NativeTransactionError> {
        let inventory = self.journal.observe()?;
        if !inventory.orphans.is_empty()
            || inventory
                .transactions
                .last()
                .is_none_or(|tx| &tx.intent.transaction_id != id)
        {
            return Err(NativeTransactionError::UnknownInspect);
        }
        let original = self.journal.read_original(id)?;
        validate_original(&original, self.binding.marker())?;
        let transaction = replay(&original)?;
        if transaction.snapshot().last_durable_stage != DurableStage::Committed {
            self.validate_update_publication(&original.before, &original.target, &original.intent)?;
        }
        let canonical = self.readstate()?;
        if self.marker().reader_floor
            == styx_contracts::management::ReaderContract::NativeManagementStateV1
        {
            if transaction.snapshot().last_durable_stage == DurableStage::Committed {
                self.validate_complete_chain(&canonical)?;
            } else {
                self.validate_update_recovery_chain(id, &canonical)?;
            }
        }
        if transaction
            .recovery_decision(
                &original.intent,
                canonical.state().deployment_raw_sha256,
                canonical.raw_sha256(),
            )
            .map_err(|_| NativeTransactionError::UnknownInspect)?
            == RecoveryDecision::UnknownInspect
        {
            return Err(NativeTransactionError::UnknownInspect);
        }
        // The original coordinator may have completed finish_native before its
        // caller lost the reply. Confirm that already-admitted complete tip;
        // do not try to acquire a recovery fence that no longer exists. This
        // never releases a fence or adopts another transaction/owner.
        if self.marker().reader_floor
            == styx_contracts::management::ReaderContract::NativeManagementStateV1
            && transaction.snapshot().last_durable_stage == DurableStage::Committed
            && self.retained_maintenance.is_none()
            && self.configuration_root().ensure_admission().is_ok()
        {
            self.revalidate_runtime_custody()?;
            if canonical.raw_sha256() != original.intent.target_state_sha256 {
                return Err(NativeTransactionError::UnknownInspect);
            }
            self.validate_complete_chain(&canonical)?;
            let committed = original
                .phases
                .last()
                .filter(|receipt| receipt.stage == DurableStage::Committed)
                .cloned()
                .ok_or(NativeTransactionError::UnknownInspect)?;
            return Ok(NativeCommitResult {
                transaction_id: id.clone(),
                canonical_raw_sha256: canonical.raw_sha256(),
                committed,
                recovered: true,
            });
        }
        let maintenance = match self.retained_maintenance.take() {
            Some(maintenance) if maintenance.transaction_id() == id => maintenance,
            Some(other) => {
                self.retained_maintenance = Some(other);
                return Err(NativeTransactionError::Conflict);
            }
            None => self
                .configuration_root()
                .begin_standalone_native(id.clone(), true)?,
        };
        let result = (|| {
            let synced = self.journal.resync_original(&maintenance, id)?;
            validate_original(&synced, self.binding.marker())?;
            let transaction = replay(&synced)?;
            let canonical = self
                .binding
                .with_binding(|state, _| self.binding.resync_locked(state))?;
            let decision = transaction
                .recovery_decision(
                    &synced.intent,
                    canonical.state().deployment_raw_sha256,
                    canonical.raw_sha256(),
                )
                .map_err(|_| NativeTransactionError::UnknownInspect)?;
            match decision {
                RecoveryDecision::ResumePrepared => self.replace_canonical(
                    &maintenance,
                    &synced.before,
                    &synced.target,
                    &synced.intent,
                    &|_, _| {},
                )?,
                RecoveryDecision::VerifyTarget
                | RecoveryDecision::CommitVerified
                | RecoveryDecision::AlreadyCommitted => (),
                _ => return Err(NativeTransactionError::UnknownInspect),
            }
            self.complete(&maintenance, transaction, true, &|_, _| {})
        })();
        if result.is_err() {
            self.retained_maintenance = Some(maintenance);
        }
        result
    }
}
fn stage_rank(stage: DurableStage) -> u8 {
    match stage {
        DurableStage::Planned => 0,
        DurableStage::Prepared => 1,
        DurableStage::Applied => 2,
        DurableStage::Verified => 3,
        DurableStage::Committed => 4,
    }
}
fn stage_label(stage: DurableStage) -> &'static str {
    match stage {
        DurableStage::Planned => "planned",
        DurableStage::Prepared => "prepared",
        DurableStage::Applied => "applied",
        DurableStage::Verified => "verified",
        DurableStage::Committed => "committed",
    }
}
fn validate_original(
    original: &OriginalManagementTransaction,
    marker: &styx_contracts::native_management::NativeRootMarker,
) -> JournalResult<()> {
    let before =
        native_state::decode_state(&original.before, marker).map_err(|_| JournalError::Unknown)?;
    let target =
        native_state::decode_state(&original.target, marker).map_err(|_| JournalError::Unknown)?;
    if before.raw_sha256() != original.intent.before_state_sha256
        || target.raw_sha256() != original.intent.target_state_sha256
    {
        return Err(JournalError::Unknown);
    }
    styx_core::management::state::validate_committed_transition(
        before.state(),
        target.state(),
        marker,
        &original.intent,
    )
    .map_err(|_| JournalError::Unknown)
}
fn replay(original: &OriginalManagementTransaction) -> JournalResult<ManagementTransaction> {
    let intent = &original.intent;
    let mut transaction =
        ManagementTransaction::plan(intent.clone()).map_err(|_| JournalError::Unknown)?;
    let first = original.phases.first().ok_or(JournalError::Unknown)?;
    transaction
        .prepare(PreparedFacts {
            intent: intent.clone(),
            deployment_raw_sha256: intent.deployment_raw_sha256,
            canonical_state_sha256: intent.before_state_sha256,
            reader: intent.reader,
            journal: first.clone(),
        })
        .map_err(|_| JournalError::Unknown)?;
    for receipt in original.phases.iter().skip(1) {
        advance(&mut transaction, intent, receipt.clone()).map_err(|_| JournalError::Unknown)?;
    }
    Ok(transaction)
}
fn advance(
    transaction: &mut ManagementTransaction,
    intent: &DesiredStateCommit,
    journal: JournalReceipt,
) -> Result<(), NativeTransactionError> {
    match journal.stage {
        DurableStage::Applied => transaction.applied(AppliedFacts {
            intent: intent.clone(),
            deployment_raw_sha256: intent.deployment_raw_sha256,
            canonical_state_sha256: intent.target_state_sha256,
            journal,
        }),
        DurableStage::Verified => transaction.verified(VerificationFacts {
            intent: intent.clone(),
            deployment_raw_sha256: intent.deployment_raw_sha256,
            canonical_state_sha256: intent.target_state_sha256,
            reader: intent.reader,
            journal,
        }),
        DurableStage::Committed => transaction.committed(CommitFacts {
            intent: intent.clone(),
            deployment_raw_sha256: intent.deployment_raw_sha256,
            canonical_state_sha256: intent.target_state_sha256,
            journal,
        }),
        _ => return Err(NativeTransactionError::UnknownInspect),
    }
    .map_err(|_| NativeTransactionError::UnknownInspect)
}

#[cfg(test)]
#[path = "native_transaction_tests.rs"]
mod tests;

#[cfg(all(test, any(target_os = "windows", target_os = "macos")))]
#[path = "native_transaction_platform_tests.rs"]
mod native_tests;

#[cfg(target_os = "macos")]
#[path = "native_transaction_macos.rs"]
mod macos_recovery;
#[cfg(target_os = "macos")]
pub(crate) use macos_recovery::{
    MacMigrationRecovery, MacMigrationRecoveryFailure, MacMigrationRecoveryStart,
    begin_mac_host_migration, begin_mac_legacy_recovery,
};

#[cfg(target_os = "windows")]
#[path = "native_transaction_windows.rs"]
mod windows_migration;
#[cfg(target_os = "windows")]
pub(crate) use windows_migration::{
    WindowsHostMigrationReview, WindowsMigrationPreparationFailure, WindowsMigrationRecovery,
    begin_windows_host_migration, begin_windows_legacy_recovery, review_windows_host_migration,
};

#[path = "native_runtime_update.rs"]
mod runtime_update;
