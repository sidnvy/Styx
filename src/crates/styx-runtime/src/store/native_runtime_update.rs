//! Closed stopped-fresh runtime assignment through the original C07 coordinator.
//! No DTO, selected pathname, or desired Stopped value proves process settlement.
use super::*;
use crate::release::VerifiedNativeRelease;
use crate::store::ExecutionLeaseGuard;
use styx_contracts::{
    management::ReaderContract,
    native_management::{
        NATIVE_APP_RUNTIME_SELECTED_STATE_SCHEMA, NATIVE_RUNTIME_SELECTED_STATE_SCHEMA,
        NATIVE_RUNTIME_SELECTION_KEY, NATIVE_RUNTIME_UPDATE_KEY,
        NATIVE_SERVICE_RUNTIME_SELECTED_STATE_SCHEMA, NativeRuntimeSelection, NativeRuntimeUpdate,
        NativeState, NativeStateTransaction,
    },
};

/// Exact original transaction, same already-claimed journal and writer.
/// Cannot be decoded from a request or recreated by a second namespace claim.
#[cfg(target_os = "macos")]
pub(crate) struct OriginalServiceRuntimeRepair {
    owner: OwnedConfigurationRoot,
    journal: std::sync::Arc<OwnedManagementJournal>,
    original: OriginalManagementTransaction,
    marker: styx_contracts::native_management::NativeRootMarker,
    before: NativeState,
    target: NativeState,
    binding: styx_contracts::native_management::NativeServiceRepairBinding,
    initially_committed: bool,
}
#[cfg(target_os = "macos")]
impl OriginalServiceRuntimeRepair {
    pub(crate) fn before(&self) -> &NativeState {
        &self.before
    }
    pub(crate) fn target(&self) -> &NativeState {
        &self.target
    }
    pub(crate) fn binding(&self) -> &styx_contracts::native_management::NativeServiceRepairBinding {
        &self.binding
    }
    pub(crate) fn transaction_id(&self) -> &TransactionId {
        &self.original.intent.transaction_id
    }
    pub(crate) fn before_bytes(&self) -> &[u8] {
        &self.original.before
    }
    pub(crate) fn target_bytes(&self) -> &[u8] {
        &self.original.target
    }
    pub(crate) fn initially_committed(&self) -> bool {
        self.initially_committed
    }
    /// Blocking only; never call while already inside a configuration callback.
    pub(crate) fn validate_owner(
        &self,
        owner: &OwnedConfigurationRoot,
    ) -> Result<(), NativeTransactionError> {
        if !self.owner.same_authority(owner) {
            return Err(NativeTransactionError::Conflict);
        }
        let current = self.journal.read_original(self.transaction_id())?;
        validate_original(&current, &self.marker)?;
        if current.raw_intent != self.original.raw_intent
            || current.before != self.original.before
            || current.target != self.original.target
            || !current.phases.starts_with(&self.original.phases)
        {
            return Err(NativeTransactionError::UnknownInspect);
        }
        let last_stage = current
            .phases
            .last()
            .ok_or(NativeTransactionError::UnknownInspect)?
            .stage;
        let committed = last_stage == DurableStage::Committed;
        self.owner.with_state(|state| {
            let raw_marker = state
                .root
                .read_raw(".styx-native-root-v1.json", 4096)
                .map_err(|_| JournalError::Unknown)?;
            let marker = native_state::decode_marker(raw_marker.bytes())
                .map_err(|_| JournalError::Unknown)?;
            if marker != self.marker {
                return Err(JournalError::Conflict);
            }
            let raw = state
                .root
                .read_raw("state.json", 1024 * 1024)
                .map_err(|_| JournalError::Unknown)?;
            // Only Prepared may still name A. Applied and later already prove
            // B was published; accepting A then would hide a canonical rollback.
            if (raw.bytes() != self.before_bytes() && raw.bytes() != self.target_bytes())
                || (last_stage != DurableStage::Prepared && raw.bytes() != self.target_bytes())
            {
                return Err(JournalError::Conflict);
            }
            let canonical = native_state::decode_state(raw.bytes(), &marker)
                .map_err(|_| JournalError::Unknown)?;
            self.journal.with_directory_locked(state, |dir| {
                let scan = super::super::secure_journal::files::scan(dir, self.journal.budget())?;
                if committed {
                    super::super::management::validate_readonly_native_tip(
                        &scan, &canonical, &marker,
                    )
                } else {
                    super::super::management::validate_fresh_native_recovery_tip(
                        &scan,
                        &canonical,
                        &marker,
                        self.transaction_id(),
                    )
                }
            })
        })?;
        Ok(())
    }
}
pub(super) struct RuntimeUpdateCustody {
    previous: VerifiedNativeRelease,
    candidate: VerifiedNativeRelease,
    before: NativeRuntimeSelection,
    target: NativeRuntimeSelection,
    transaction: TransactionId,
    execution: Option<ExecutionLeaseGuard>,
    app_scope: Option<std::sync::Arc<crate::app::HostScope>>,
    #[cfg(target_os = "macos")]
    service_scope: Option<std::sync::Arc<crate::platform::macos_service::RegisteredInactiveProof>>,
}
impl RuntimeUpdateCustody {
    fn service_owned(&self) -> bool {
        #[cfg(target_os = "macos")]
        {
            self.service_scope.is_some()
        }
        #[cfg(not(target_os = "macos"))]
        {
            false
        }
    }
    fn validate(&self, owner: &OwnedConfigurationRoot) -> Result<(), NativeTransactionError> {
        #[cfg(not(target_os = "macos"))]
        let _ = owner;
        #[cfg(target_os = "macos")]
        if let Some(proof) = &self.service_scope {
            proof
                .validate_owner(owner)
                .map_err(|_| NativeTransactionError::UnknownInspect)?;
        }
        if let Some(scope) = &self.app_scope {
            scope
                .validate()
                .map_err(|_| NativeTransactionError::UnknownInspect)?;
        }
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
    .is_ok()
        || styx_core::management::state::validate_app_runtime_transition(
            before.state(),
            target.state(),
            marker,
            intent,
        )
        .is_ok()
        || styx_core::management::state::validate_service_runtime_repair_transition(
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
        self.update_runtime_scoped_observing(previous, candidate, id, sequence, None, observer)
    }
    pub(crate) fn update_runtime_for_app(
        &mut self,
        previous: VerifiedNativeRelease,
        candidate: VerifiedNativeRelease,
        id: TransactionId,
        sequence: u64,
        scope: std::sync::Arc<crate::app::HostScope>,
    ) -> Result<NativeCommitResult, NativeTransactionError> {
        self.update_runtime_scoped_observing(
            previous,
            candidate,
            id,
            sequence,
            Some(scope),
            &|_, _| {},
        )
    }
    fn update_runtime_scoped_observing(
        &mut self,
        previous: VerifiedNativeRelease,
        candidate: VerifiedNativeRelease,
        id: TransactionId,
        sequence: u64,
        scope: Option<std::sync::Arc<crate::app::HostScope>>,
        observer: &dyn Fn(&str, &str),
    ) -> Result<NativeCommitResult, NativeTransactionError> {
        self.retain_update(previous, candidate, id.clone(), scope)?;
        self.apply_retained_runtime_update(id, sequence, observer)
    }
    fn apply_retained_runtime_update(
        &mut self,
        id: TransactionId,
        sequence: u64,
        observer: &dyn Fn(&str, &str),
    ) -> Result<NativeCommitResult, NativeTransactionError> {
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
            if !held
                .previous
                .supports_state_reader(before.state().reader_contract)
                .map_err(|_| NativeTransactionError::InvalidInput)?
            {
                return Err(NativeTransactionError::InvalidInput);
            }
            let mut target = before.state().clone();
            let app_owned = held.app_scope.is_some();
            let service_owned = held.service_owned();
            #[cfg(target_os = "macos")]
            if let Some(proof) = &held.service_scope {
                if before.raw_bytes() != proof.initial_state().bytes() {
                    return Err(NativeTransactionError::Conflict);
                }
                let gateway = target
                    .desired
                    .gateway
                    .as_mut()
                    .ok_or(NativeTransactionError::Conflict)?;
                gateway.run = styx_contracts::native_management::NativeRunDesired::Running;
                gateway.autostart =
                    styx_contracts::native_management::NativeAutostartDesired::Enabled;
            }
            target.schema = if service_owned {
                NATIVE_SERVICE_RUNTIME_SELECTED_STATE_SCHEMA
            } else if app_owned {
                NATIVE_APP_RUNTIME_SELECTED_STATE_SCHEMA
            } else {
                NATIVE_RUNTIME_SELECTED_STATE_SCHEMA
            };
            target.reader_contract = if service_owned {
                ReaderContract::NativeServiceRuntimeSelectedStateV1
            } else if app_owned {
                ReaderContract::NativeAppRuntimeSelectedStateV1
            } else {
                ReaderContract::NativeRuntimeSelectedStateV1
            };
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
                service_repair: {
                    #[cfg(target_os = "macos")]
                    {
                        held.service_scope
                            .as_ref()
                            .map(|proof| proof.repair_binding())
                            .transpose()
                            .map_err(|_| NativeTransactionError::UnknownInspect)?
                    }
                    #[cfg(not(target_os = "macos"))]
                    {
                        None
                    }
                },
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
            if service_owned {
                styx_core::management::state::validate_service_runtime_repair_transition(
                    before.state(),
                    &target,
                    self.marker(),
                    &intent,
                )
            } else if app_owned {
                styx_core::management::state::validate_app_runtime_transition(
                    before.state(),
                    &target,
                    self.marker(),
                    &intent,
                )
            } else {
                styx_core::management::state::validate_runtime_transition(
                    before.state(),
                    &target,
                    self.marker(),
                    &intent,
                )
            }
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
        // A service repair keeps both signed releases, original proof and the
        // transferred execution lease through post-commit OS observation and
        // generation of the exact administrator request. Dropping its original
        // owner after success releases custody; failure retains that owner.
        if result.is_ok()
            && self
                .retained_runtime_update
                .as_ref()
                .is_some_and(|held| !held.service_owned())
        {
            self.retained_runtime_update = None;
        }
        result
    }
    #[cfg(target_os = "macos")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn update_runtime_for_failed_service(
        &mut self,
        previous: VerifiedNativeRelease,
        candidate: VerifiedNativeRelease,
        id: TransactionId,
        sequence: u64,
        proof: std::sync::Arc<crate::platform::macos_service::RegisteredInactiveProof>,
        execution: &mut Option<ExecutionLeaseGuard>,
    ) -> Result<NativeCommitResult, NativeTransactionError> {
        if self.retained_runtime_update.is_some() {
            return Err(NativeTransactionError::Conflict);
        }
        proof
            .validate_owner(&self.configuration_root())
            .map_err(|_| NativeTransactionError::UnknownInspect)?;
        let guard = execution.as_ref().ok_or(NativeTransactionError::Conflict)?;
        if guard.identity().root != self.configuration_root().identity()? {
            return Err(NativeTransactionError::Conflict);
        }
        guard
            .validate()
            .map_err(|_| NativeTransactionError::UnknownInspect)?;
        let before = previous
            .runtime_selection()
            .map_err(|_| NativeTransactionError::InvalidInput)?;
        let target = candidate
            .runtime_selection()
            .map_err(|_| NativeTransactionError::InvalidInput)?;
        let trusted = before
            == *proof
                .original_definition()
                .runtime_selection()
                .map_err(|_| NativeTransactionError::Conflict)?
            && before.publisher_spki_sha256 == target.publisher_spki_sha256
            && previous.manifest().target == candidate.manifest().target
            && candidate
                .supports_state_reader(ReaderContract::NativeServiceRuntimeSelectedStateV1)
                .map_err(|_| NativeTransactionError::InvalidInput)?;
        self.retained_runtime_update = Some(RuntimeUpdateCustody {
            previous,
            candidate,
            before,
            target,
            transaction: id.clone(),
            execution: execution.take(),
            app_scope: None,
            service_scope: Some(proof),
        });
        if !trusted {
            return Err(NativeTransactionError::InvalidInput);
        }
        self.revalidate_runtime_custody()?;
        self.apply_retained_runtime_update(id, sequence, &|_, _| {})
    }
    #[cfg(target_os = "macos")]
    pub(crate) fn failed_service_repair_request(
        &self,
        id: &TransactionId,
        revision: u64,
        canonical: &Sha256Digest,
    ) -> Result<serde_json::Value, NativeTransactionError> {
        let held = self
            .retained_runtime_update
            .as_ref()
            .ok_or(NativeTransactionError::Conflict)?;
        if &held.transaction != id {
            return Err(NativeTransactionError::Conflict);
        }
        held.validate(&self.configuration_root())?;
        held.service_scope
            .as_ref()
            .ok_or(NativeTransactionError::Conflict)?
            .repair_request(&held.candidate, id, revision, canonical)
            .map_err(|_| NativeTransactionError::UnknownInspect)
    }
    #[cfg(target_os = "macos")]
    pub(crate) fn original_service_runtime_repair(
        &self,
        id: &TransactionId,
    ) -> Result<OriginalServiceRuntimeRepair, NativeTransactionError> {
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
        validate_original(&original, self.marker())?;
        let before = native_state::decode_state(&original.before, self.marker())
            .map_err(|_| NativeTransactionError::UnknownInspect)?;
        let target = native_state::decode_state(&original.target, self.marker())
            .map_err(|_| NativeTransactionError::UnknownInspect)?;
        styx_core::management::state::validate_service_runtime_repair_transition(
            before.state(),
            target.state(),
            self.marker(),
            &original.intent,
        )
        .map_err(|_| NativeTransactionError::Conflict)?;
        let binding = target
            .state()
            .runtime_update()
            .map_err(|_| NativeTransactionError::UnknownInspect)?
            .and_then(|v| v.service_repair)
            .ok_or(NativeTransactionError::Conflict)?;
        let initially_committed = original
            .phases
            .last()
            .is_some_and(|r| r.stage == DurableStage::Committed);
        let frame = OriginalServiceRuntimeRepair {
            owner: self.configuration_root(),
            journal: self.journal.clone(),
            before: before.state().clone(),
            target: target.state().clone(),
            marker: self.marker().clone(),
            binding,
            original,
            initially_committed,
        };
        frame.validate_owner(&self.configuration_root())?;
        Ok(frame)
    }
    #[cfg(target_os = "macos")]
    pub(crate) fn recover_runtime_for_failed_service(
        &mut self,
        previous: VerifiedNativeRelease,
        candidate: VerifiedNativeRelease,
        original: std::sync::Arc<OriginalServiceRuntimeRepair>,
        proof: std::sync::Arc<crate::platform::macos_service::RegisteredInactiveProof>,
        execution: &mut Option<ExecutionLeaseGuard>,
    ) -> Result<NativeCommitResult, NativeTransactionError> {
        if self.retained_runtime_update.is_some() {
            return Err(NativeTransactionError::Conflict);
        }
        original.validate_owner(&self.configuration_root())?;
        proof
            .validate_owner(&self.configuration_root())
            .map_err(|_| NativeTransactionError::UnknownInspect)?;
        let guard = execution.as_ref().ok_or(NativeTransactionError::Conflict)?;
        if guard.identity().root != self.configuration_root().identity()? {
            return Err(NativeTransactionError::Conflict);
        }
        guard
            .validate()
            .map_err(|_| NativeTransactionError::UnknownInspect)?;
        let before = previous
            .runtime_selection()
            .map_err(|_| NativeTransactionError::InvalidInput)?;
        let target = candidate
            .runtime_selection()
            .map_err(|_| NativeTransactionError::InvalidInput)?;
        if before != selection(original.before())?
            || target != selection(original.target())?
            || proof
                .repair_binding()
                .map_err(|_| NativeTransactionError::UnknownInspect)?
                != *original.binding()
            || before.publisher_spki_sha256 != target.publisher_spki_sha256
            || previous.manifest().target != candidate.manifest().target
            || !previous
                .supports_state_reader(original.before().reader_contract)
                .map_err(|_| NativeTransactionError::InvalidInput)?
            || !candidate
                .supports_state_reader(original.target().reader_contract)
                .map_err(|_| NativeTransactionError::InvalidInput)?
        {
            return Err(NativeTransactionError::Conflict);
        }
        let id = original.transaction_id().clone();
        self.retained_runtime_update = Some(RuntimeUpdateCustody {
            previous,
            candidate,
            before,
            target,
            transaction: id.clone(),
            execution: execution.take(),
            app_scope: None,
            service_scope: Some(proof),
        });
        let result = self.recover_original(&id);
        if result.is_ok() {
            original.validate_owner(&self.configuration_root())?;
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
        self.retain_update(previous, candidate, id.clone(), None)?;
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
    pub(crate) fn recover_runtime_update_for_app(
        &mut self,
        previous: VerifiedNativeRelease,
        candidate: VerifiedNativeRelease,
        id: &TransactionId,
        scope: std::sync::Arc<crate::app::HostScope>,
    ) -> Result<NativeCommitResult, NativeTransactionError> {
        self.retain_update(previous, candidate, id.clone(), Some(scope.clone()))?;
        self.recover_retained_runtime_update_for_app(&scope, id)
    }
    pub(crate) fn recover_retained_runtime_update_for_app(
        &mut self,
        scope: &std::sync::Arc<crate::app::HostScope>,
        id: &TransactionId,
    ) -> Result<NativeCommitResult, NativeTransactionError> {
        self.validate_runtime_app_scope(scope)?;
        let expected = self
            .runtime_update_selections(id)?
            .ok_or(NativeTransactionError::InvalidInput)?;
        let held = self
            .retained_runtime_update
            .as_ref()
            .ok_or(NativeTransactionError::Conflict)?;
        if &held.transaction != id
            || held
                .app_scope
                .as_ref()
                .is_none_or(|s| !std::sync::Arc::ptr_eq(s, scope))
            || expected != (held.before.clone(), held.target.clone())
        {
            return Err(NativeTransactionError::Conflict);
        }
        let original = self.journal.read_original(id)?;
        let before = native_state::decode_state(&original.before, self.marker())
            .map_err(|_| NativeTransactionError::UnknownInspect)?;
        let target = native_state::decode_state(&original.target, self.marker())
            .map_err(|_| NativeTransactionError::UnknownInspect)?;
        if !held
            .previous
            .supports_state_reader(before.state().reader_contract)
            .map_err(|_| NativeTransactionError::UnknownInspect)?
            || !held
                .candidate
                .supports_state_reader(target.state().reader_contract)
                .map_err(|_| NativeTransactionError::UnknownInspect)?
        {
            return Err(NativeTransactionError::Conflict);
        }
        held.validate(&self.configuration_root())?;
        let result = self.recover_original(id);
        if result.is_ok() {
            self.retained_runtime_update = None;
        }
        result
    }
    pub(crate) fn pending_app_transaction(
        &self,
    ) -> Result<Option<TransactionId>, NativeTransactionError> {
        let inventory = self.journal.observe()?;
        if !inventory.orphans.is_empty() {
            return Err(NativeTransactionError::UnknownInspect);
        }
        let Some(last) = inventory.transactions.last() else {
            return Ok(None);
        };
        if last
            .phase_receipts
            .last()
            .is_some_and(|p| p.stage == DurableStage::Committed)
        {
            return Ok(None);
        }
        Ok(Some(last.intent.transaction_id.clone()))
    }
    pub(crate) fn has_runtime_update_custody(&self) -> bool {
        self.retained_runtime_update.is_some()
    }
    pub(crate) fn runtime_update_high_water(&self) -> Result<u64, NativeTransactionError> {
        Ok(self.journal.observe()?.high_water)
    }
    fn validate_runtime_app_scope(
        &self,
        scope: &std::sync::Arc<crate::app::HostScope>,
    ) -> Result<(), NativeTransactionError> {
        scope
            .validate()
            .map_err(|_| NativeTransactionError::UnknownInspect)?;
        let root = crate::store::PrivateRoot::open(scope.state_dir())
            .map_err(|_| NativeTransactionError::UnknownInspect)?;
        if root.identity() != self.configuration_root().identity()? {
            return Err(NativeTransactionError::Conflict);
        }
        Ok(())
    }
    fn retain_update(
        &mut self,
        previous: VerifiedNativeRelease,
        candidate: VerifiedNativeRelease,
        id: TransactionId,
        scope: Option<std::sync::Arc<crate::app::HostScope>>,
    ) -> Result<(), NativeTransactionError> {
        if let Some(scope) = &scope {
            self.validate_runtime_app_scope(scope)?;
        }
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
                .supports_state_reader(if scope.is_some() {
                    ReaderContract::NativeAppRuntimeSelectedStateV1
                } else {
                    ReaderContract::NativeRuntimeSelectedStateV1
                })
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
            app_scope: scope,
            #[cfg(target_os = "macos")]
            service_scope: None,
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
        self.revalidate_app_service_custody()?;
        if let Some(held) = &self.retained_runtime_update {
            held.validate(&self.configuration_root())?;
        }
        Ok(())
    }
    pub(super) fn validate_update_publication(
        &self,
        before: &[u8],
        target: &[u8],
        intent: &DesiredStateCommit,
    ) -> Result<(), NativeTransactionError> {
        self.validate_app_service_publication(before, target, intent)?;
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
        #[cfg(target_os = "macos")]
        if let Some(proof) = &held.service_scope {
            let recorded = target
                .state()
                .runtime_update()
                .map_err(|_| NativeTransactionError::UnknownInspect)?
                .and_then(|v| v.service_repair)
                .ok_or(NativeTransactionError::Conflict)?;
            if recorded
                != proof
                    .repair_binding()
                    .map_err(|_| NativeTransactionError::UnknownInspect)?
            {
                return Err(NativeTransactionError::Conflict);
            }
        }
        let service_transition =
            styx_core::management::state::validate_service_runtime_repair_transition(
                before.state(),
                target.state(),
                self.marker(),
                intent,
            )
            .is_ok();
        let app_transition = styx_core::management::state::validate_app_runtime_transition(
            before.state(),
            target.state(),
            self.marker(),
            intent,
        )
        .is_ok();
        if service_transition != held.service_owned()
            || app_transition != held.app_scope.is_some()
            || intent.transaction_id != held.transaction
            || selection(before.state())? != held.before
            || selection(target.state())? != held.target
        {
            return Err(NativeTransactionError::Conflict);
        }
        held.validate(&self.configuration_root())
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

#[cfg(all(test, target_os = "macos"))]
#[path = "native_service_repair_tests.rs"]
mod service_repair_tests;
