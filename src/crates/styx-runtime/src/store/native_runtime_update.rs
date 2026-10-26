//! Closed stopped-fresh runtime assignment through the original C07 coordinator.
//! No DTO, selected pathname, or desired Stopped value proves process settlement.
use super::*;
use crate::release::VerifiedNativeRelease;
use crate::store::ExecutionLeaseGuard;
use styx_contracts::{
    management::ReaderContract,
    native_management::{
        NATIVE_RUNTIME_SELECTED_STATE_SCHEMA, NATIVE_RUNTIME_SELECTION_KEY,
        NATIVE_RUNTIME_UPDATE_KEY, NativeRuntimeSelection, NativeRuntimeUpdate, NativeState,
        NativeStateTransaction,
    },
};

pub(super) struct RuntimeUpdateCustody {
    previous: VerifiedNativeRelease,
    candidate: VerifiedNativeRelease,
    before: NativeRuntimeSelection,
    target: NativeRuntimeSelection,
    transaction: TransactionId,
    execution: Option<ExecutionLeaseGuard>,
}
impl RuntimeUpdateCustody {
    fn validate(&self) -> Result<(), NativeTransactionError> {
        self.previous
            .revalidate()
            .map_err(|_| NativeTransactionError::UnknownInspect)?;
        self.candidate
            .revalidate()
            .map_err(|_| NativeTransactionError::UnknownInspect)?;
        self.execution
            .as_ref()
            .ok_or(NativeTransactionError::Conflict)?
            .validate()
            .map_err(|_| NativeTransactionError::UnknownInspect)
    }
}
fn selection(state: &NativeState) -> Result<NativeRuntimeSelection, NativeTransactionError> {
    state
        .runtime_selection()
        .map_err(|_| NativeTransactionError::InvalidInput)?
        .ok_or(NativeTransactionError::InvalidInput)
}
fn runtime_transition(
    before: &[u8],
    target: &[u8],
    marker: &styx_contracts::native_management::NativeRootMarker,
    intent: &DesiredStateCommit,
) -> Result<bool, NativeTransactionError> {
    let before = native_state::decode_state(before, marker)
        .map_err(|_| NativeTransactionError::UnknownInspect)?;
    let target = native_state::decode_state(target, marker)
        .map_err(|_| NativeTransactionError::UnknownInspect)?;
    Ok(styx_core::management::state::validate_runtime_transition(
        before.state(),
        target.state(),
        marker,
        intent,
    )
    .is_ok())
}
impl NativeTransactions {
    /// Internally generate the sole permitted selection-changing target. Both
    /// original C08 descriptions and execution exclusion remain held on failure.
    pub(crate) fn update_runtime(
        &mut self,
        previous: VerifiedNativeRelease,
        candidate: VerifiedNativeRelease,
        id: TransactionId,
        sequence: u64,
    ) -> Result<NativeCommitResult, NativeTransactionError> {
        self.update_runtime_observing(previous, candidate, id, sequence, &|_, _| {})
    }
    // Original production path; tests supply only a persisted-step observer.
    // No environment flag, alternate writer or synthetic commit port exists.
    fn update_runtime_observing(
        &mut self,
        previous: VerifiedNativeRelease,
        candidate: VerifiedNativeRelease,
        id: TransactionId,
        sequence: u64,
        observer: &dyn Fn(&str, &str),
    ) -> Result<NativeCommitResult, NativeTransactionError> {
        self.retain_update(previous, candidate, id.clone())?;
        let result = (|| {
            let before = self.readstate()?;
            self.validate_complete_chain(&before)?;
            let held = self
                .retained_runtime_update
                .as_ref()
                .ok_or(NativeTransactionError::Conflict)?;
            if selection(before.state())? != held.before {
                return Err(NativeTransactionError::Conflict);
            }
            let mut target = before.state().clone();
            target.schema = NATIVE_RUNTIME_SELECTED_STATE_SCHEMA;
            target.reader_contract = ReaderContract::NativeRuntimeSelectedStateV1;
            target.revision = target
                .revision
                .checked_add(1)
                .ok_or(NativeTransactionError::InvalidInput)?;
            let transaction = NativeStateTransaction {
                transaction_id: id.clone(),
                sequence,
            };
            let bootstrap_runtime = before
                .state()
                .runtime_update()
                .map_err(|_| NativeTransactionError::InvalidInput)?
                .map(|update| update.bootstrap_runtime)
                .unwrap_or_else(|| held.before.clone());
            let update = NativeRuntimeUpdate {
                schema: 1,
                bootstrap_runtime,
                previous_runtime: held.before.clone(),
                transaction: transaction.clone(),
            };
            target.last_transaction = Some(transaction);
            target.extensions.insert(
                NATIVE_RUNTIME_SELECTION_KEY.into(),
                serde_json::value::to_raw_value(&held.target)
                    .map_err(|_| NativeTransactionError::InvalidInput)?,
            );
            target.extensions.insert(
                NATIVE_RUNTIME_UPDATE_KEY.into(),
                serde_json::value::to_raw_value(&update)
                    .map_err(|_| NativeTransactionError::InvalidInput)?,
            );
            let bytes =
                serde_json::to_vec(&target).map_err(|_| NativeTransactionError::InvalidInput)?;
            let intent = DesiredStateCommit {
                transaction_id: id.clone(),
                sequence,
                deployment_raw_sha256: before.state().deployment_raw_sha256,
                before_state_sha256: before.raw_sha256(),
                target_state_sha256: Sha256Digest::of_bytes(&bytes),
                reader: target.reader_contract,
            };
            styx_core::management::state::validate_runtime_transition(
                before.state(),
                &target,
                self.marker(),
                &intent,
            )
            .map_err(|_| NativeTransactionError::InvalidInput)?;
            let inventory = self.journal.observe()?;
            if sequence <= inventory.high_water
                || inventory
                    .transactions
                    .iter()
                    .any(|tx| tx.intent.transaction_id == id)
            {
                return Err(NativeTransactionError::Conflict);
            }
            self.validate_update_publication(before.raw_bytes(), &bytes, &intent)?;
            let maintenance = self
                .configuration_root()
                .begin_standalone_native(id, false)?;
            let result =
                self.apply_prepared(&maintenance, before.raw_bytes(), &bytes, &intent, observer);
            if result.is_err() {
                self.retained_maintenance = Some(maintenance);
            }
            result
        })();
        if result.is_ok() {
            self.retained_runtime_update = None;
        }
        result
    }
    /// Return only the original hash-bound before/target selections of a genuine
    /// update. This observation grants neither release trust nor replay authority.
    pub(crate) fn runtime_update_selections(
        &self,
        id: &TransactionId,
    ) -> Result<Option<(NativeRuntimeSelection, NativeRuntimeSelection)>, NativeTransactionError>
    {
        let original = self.journal.read_original(id)?;
        validate_original(&original, self.marker())?;
        if !runtime_transition(
            &original.before,
            &original.target,
            self.marker(),
            &original.intent,
        )? {
            return Ok(None);
        }
        let before = native_state::decode_state(&original.before, self.marker())
            .map_err(|_| NativeTransactionError::UnknownInspect)?;
        let target = native_state::decode_state(&original.target, self.marker())
            .map_err(|_| NativeTransactionError::UnknownInspect)?;
        Ok(Some((
            selection(before.state())?,
            selection(target.state())?,
        )))
    }
    /// Explicit recovery of the same original update, never a replacement target.
    pub(crate) fn recover_runtime_update(
        &mut self,
        previous: VerifiedNativeRelease,
        candidate: VerifiedNativeRelease,
        id: &TransactionId,
    ) -> Result<NativeCommitResult, NativeTransactionError> {
        self.retain_update(previous, candidate, id.clone())?;
        let result = (|| {
            let expected = self
                .runtime_update_selections(id)?
                .ok_or(NativeTransactionError::InvalidInput)?;
            let held = self
                .retained_runtime_update
                .as_ref()
                .ok_or(NativeTransactionError::Conflict)?;
            if expected != (held.before.clone(), held.target.clone()) {
                return Err(NativeTransactionError::Conflict);
            }
            self.recover_original(id)
        })();
        if result.is_ok() {
            self.retained_runtime_update = None;
        }
        result
    }
    fn retain_update(
        &mut self,
        previous: VerifiedNativeRelease,
        candidate: VerifiedNativeRelease,
        id: TransactionId,
    ) -> Result<(), NativeTransactionError> {
        if self.retained_runtime_update.is_some() {
            return Err(NativeTransactionError::Conflict);
        }
        let before = previous
            .runtime_selection()
            .map_err(|_| NativeTransactionError::InvalidInput)?;
        let target = candidate
            .runtime_selection()
            .map_err(|_| NativeTransactionError::InvalidInput)?;
        let trusted = before.publisher_spki_sha256 == target.publisher_spki_sha256
            && previous.manifest().target == candidate.manifest().target
            && candidate
                .supports_state_reader(ReaderContract::NativeRuntimeSelectedStateV1)
                .map_err(|_| NativeTransactionError::InvalidInput)?
            && candidate
                .supports_state_reader(ReaderContract::NativeManagementStateV1)
                .map_err(|_| NativeTransactionError::InvalidInput)?;
        self.retained_runtime_update = Some(RuntimeUpdateCustody {
            previous,
            candidate,
            before,
            target,
            transaction: id,
            execution: None,
        });
        if !trusted {
            return Err(NativeTransactionError::InvalidInput);
        }
        // The actual execution root is the fresh configuration root. Acquiring
        // its separate OS lock prevents a foreground Host/Gateway race while the
        // original configuration writer prevents a new desired Running commit.
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "windows",
            target_os = "macos"
        ))]
        let execution = self.binding.with_binding(|state, _| {
            state
                .root
                .try_execution_lease()
                .map_err(|_| JournalError::Conflict)
        })?;
        #[cfg(not(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "windows",
            target_os = "macos"
        )))]
        return Err(NativeTransactionError::Unsupported);
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "windows",
            target_os = "macos"
        ))]
        {
            self.retained_runtime_update
                .as_mut()
                .ok_or(NativeTransactionError::Conflict)?
                .execution = Some(execution);
            self.revalidate_runtime_custody()
        }
    }
    pub(super) fn revalidate_runtime_custody(&self) -> Result<(), NativeTransactionError> {
        if let Some(held) = &self.retained_runtime_update {
            held.validate()?;
        }
        Ok(())
    }
    pub(super) fn validate_update_publication(
        &self,
        before: &[u8],
        target: &[u8],
        intent: &DesiredStateCommit,
    ) -> Result<(), NativeTransactionError> {
        if !runtime_transition(before, target, self.marker(), intent)? {
            return Ok(());
        }
        let held = self
            .retained_runtime_update
            .as_ref()
            .ok_or(NativeTransactionError::UnknownInspect)?;
        let before = native_state::decode_state(before, self.marker())
            .map_err(|_| NativeTransactionError::UnknownInspect)?;
        let target = native_state::decode_state(target, self.marker())
            .map_err(|_| NativeTransactionError::UnknownInspect)?;
        if intent.transaction_id != held.transaction
            || selection(before.state())? != held.before
            || selection(target.state())? != held.target
        {
            return Err(NativeTransactionError::Conflict);
        }
        held.validate()
    }
    pub(super) fn validate_update_recovery_chain(
        &self,
        id: &TransactionId,
        canonical: &ValidatedNativeState,
    ) -> Result<(), NativeTransactionError> {
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "windows",
            target_os = "macos"
        ))]
        {
            self.binding.with_binding(|state, marker| {
                if self.binding.read_locked(state)?.raw_bytes() != canonical.raw_bytes() {
                    return Err(JournalError::Conflict);
                }
                self.journal.with_directory_locked(state, |dir| {
                    let scan =
                        super::super::secure_journal::files::scan(dir, self.journal.budget())?;
                    super::super::management::validate_fresh_native_recovery_tip(
                        &scan, canonical, marker, id,
                    )
                })
            })?;
            Ok(())
        }
        #[cfg(not(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "windows",
            target_os = "macos"
        )))]
        {
            let _ = (id, canonical);
            Err(NativeTransactionError::Unsupported)
        }
    }
    pub(super) fn validate_complete_chain(
        &self,
        canonical: &ValidatedNativeState,
    ) -> Result<(), NativeTransactionError> {
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "windows",
            target_os = "macos"
        ))]
        {
            self.binding.with_binding(|state, marker| {
                if self.binding.read_locked(state)?.raw_bytes() != canonical.raw_bytes() {
                    return Err(JournalError::Conflict);
                }
                self.journal.with_directory_locked(state, |dir| {
                    let scan =
                        super::super::secure_journal::files::scan(dir, self.journal.budget())?;
                    super::super::management::validate_readonly_native_tip(&scan, canonical, marker)
                })
            })?;
            Ok(())
        }
        #[cfg(not(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "windows",
            target_os = "macos"
        )))]
        {
            let _ = canonical;
            Err(NativeTransactionError::Unsupported)
        }
    }
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[path = "native_runtime_update_tests.rs"]
mod tests;
