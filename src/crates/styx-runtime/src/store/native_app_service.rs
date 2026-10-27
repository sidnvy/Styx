//! Original App-scope manager transfer through the existing C07 coordinator.
//! The reader grammar is not a publication capability: this typed custody holds
//! the original scope, selected signed release and actual execution exclusion.
use super::*;
use crate::{app::HostScope, release::VerifiedNativeRelease, store::ExecutionLeaseGuard};
use std::{path::Path, sync::Arc};
use styx_contracts::{
    management::ReaderContract,
    native_management::{
        NATIVE_APP_SERVICE_TRANSFERRED_STATE_SCHEMA, NativeManager, NativeStateTransaction,
    },
};

pub(super) struct AppServiceTransferCustody {
    scope: Arc<HostScope>,
    release: VerifiedNativeRelease,
    execution: ExecutionLeaseGuard,
    transaction: TransactionId,
    before_sha256: Sha256Digest,
    target_sha256: Sha256Digest,
}
impl AppServiceTransferCustody {
    fn validate(&self, owner: &OwnedConfigurationRoot) -> Result<(), NativeTransactionError> {
        self.scope
            .validate()
            .map_err(|_| NativeTransactionError::UnknownInspect)?;
        let root = crate::store::PrivateRoot::open(self.scope.state_dir())
            .map_err(|_| NativeTransactionError::UnknownInspect)?;
        if root.identity() != owner.identity()? {
            return Err(NativeTransactionError::Conflict);
        }
        self.release
            .revalidate()
            .map_err(|_| NativeTransactionError::UnknownInspect)?;
        self.execution
            .validate()
            .map_err(|_| NativeTransactionError::UnknownInspect)
    }
}
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
impl NativeTransactions {
    /// No target bytes or manager DTO is accepted. The sole target is generated
    /// under the original writer after the original role has actually settled.
    pub(crate) fn transfer_app_to_service(
        &mut self,
        scope: Arc<HostScope>,
        release: VerifiedNativeRelease,
        id: TransactionId,
        sequence: u64,
    ) -> Result<NativeCommitResult, NativeTransactionError> {
        if self.retained_app_service_transfer.is_some() || self.has_runtime_update_custody() {
            return Err(NativeTransactionError::Conflict);
        }
        scope
            .validate()
            .map_err(|_| NativeTransactionError::UnknownInspect)?;
        let root = crate::store::PrivateRoot::open(scope.state_dir())
            .map_err(|_| NativeTransactionError::UnknownInspect)?;
        if root.identity() != self.configuration_root().identity()? {
            return Err(NativeTransactionError::Conflict);
        }
        let before = self.readstate()?;
        self.validate_complete_chain(&before)?;
        let selected = before
            .state()
            .runtime_selection()
            .map_err(|_| NativeTransactionError::InvalidInput)?
            .ok_or(NativeTransactionError::InvalidInput)?;
        let stable = scope
            .state_dir()
            .parent()
            .ok_or(NativeTransactionError::Conflict)?
            .join("runtime-versions");
        let payload = Path::new(&selected.payload_path);
        if !payload.starts_with(&stable)
            || payload == stable
            || payload
                .components()
                .any(|part| part.as_os_str().to_string_lossy().ends_with(".app"))
        {
            return Err(NativeTransactionError::InvalidInput);
        }
        release
            .revalidate_matches_selection(&selected)
            .map_err(|_| NativeTransactionError::UnknownInspect)?;
        if !release
            .supports_state_reader(before.state().reader_contract)
            .map_err(|_| NativeTransactionError::InvalidInput)?
            || !release
                .supports_state_reader(ReaderContract::NativeAppServiceTransferredStateV1)
                .map_err(|_| NativeTransactionError::InvalidInput)?
        {
            return Err(NativeTransactionError::InvalidInput);
        }
        let mut target = before.state().clone();
        target.schema = NATIVE_APP_SERVICE_TRANSFERRED_STATE_SCHEMA;
        target.reader_contract = ReaderContract::NativeAppServiceTransferredStateV1;
        target.revision = target
            .revision
            .checked_add(1)
            .ok_or(NativeTransactionError::InvalidInput)?;
        for desired in target
            .desired
            .host
            .iter_mut()
            .chain(target.desired.gateway.iter_mut())
        {
            desired.manager = NativeManager::PersistentService;
        }
        target.last_transaction = Some(NativeStateTransaction {
            transaction_id: id.clone(),
            sequence,
        });
        let raw = serde_json::to_vec(&target).map_err(|_| NativeTransactionError::InvalidInput)?;
        let intent = DesiredStateCommit {
            transaction_id: id.clone(),
            sequence,
            deployment_raw_sha256: before.state().deployment_raw_sha256,
            before_state_sha256: before.raw_sha256(),
            target_state_sha256: Sha256Digest::of_bytes(&raw),
            reader: target.reader_contract,
        };
        styx_core::management::state::validate_app_service_transfer_transition(
            before.state(),
            &target,
            self.marker(),
            &intent,
        )
        .map_err(|_| NativeTransactionError::InvalidInput)?;
        let inventory = self.journal.observe()?;
        if !inventory.orphans.is_empty()
            || sequence <= inventory.high_water
            || inventory.transactions.iter().any(|tx| {
                tx.intent.transaction_id == id
                    || !tx
                        .phase_receipts
                        .last()
                        .is_some_and(|p| p.stage == DurableStage::Committed)
            })
        {
            return Err(NativeTransactionError::Conflict);
        }
        let execution = root
            .try_execution_lease()
            .map_err(|_| NativeTransactionError::Conflict)?;
        self.retained_app_service_transfer = Some(AppServiceTransferCustody {
            scope,
            release,
            execution,
            transaction: id.clone(),
            before_sha256: intent.before_state_sha256,
            target_sha256: intent.target_state_sha256,
        });
        // From this point any error retains all original custody. In particular
        // a lost commit acknowledgement never permits publication or OS replay.
        self.validate_app_service_publication(before.raw_bytes(), &raw, &intent)?;
        let maintenance = self
            .configuration_root()
            .begin_standalone_native(id, false)?;
        let result =
            self.apply_prepared(&maintenance, before.raw_bytes(), &raw, &intent, &|_, _| {});
        match result {
            Ok(receipt) => {
                let current = self.readstate()?;
                self.validate_complete_chain(&current)?;
                self.revalidate_app_service_custody()?;
                if current.raw_bytes() != raw
                    || current.raw_sha256() != receipt.canonical_raw_sha256
                {
                    return Err(NativeTransactionError::UnknownInspect);
                }
                self.retained_app_service_transfer = None;
                Ok(receipt)
            }
            Err(error) => {
                self.retained_maintenance = Some(maintenance);
                Err(error)
            }
        }
    }
    pub(super) fn revalidate_app_service_custody(&self) -> Result<(), NativeTransactionError> {
        if let Some(held) = &self.retained_app_service_transfer {
            held.validate(&self.configuration_root())?;
        }
        Ok(())
    }
    pub(crate) fn has_app_service_custody(&self) -> bool {
        self.retained_app_service_transfer.is_some()
    }
    /// Called by the common canonical-publication and original-recovery gate.
    /// Pure grammar alone can never recreate a manager-transfer capability.
    pub(super) fn validate_app_service_publication(
        &self,
        before: &[u8],
        target: &[u8],
        intent: &DesiredStateCommit,
    ) -> Result<(), NativeTransactionError> {
        let parsed_before = native_state::decode_state(before, self.marker())
            .map_err(|_| NativeTransactionError::UnknownInspect)?;
        let parsed_target = native_state::decode_state(target, self.marker())
            .map_err(|_| NativeTransactionError::UnknownInspect)?;
        if styx_core::management::state::validate_app_service_transfer_transition(
            parsed_before.state(),
            parsed_target.state(),
            self.marker(),
            intent,
        )
        .is_err()
        {
            return Ok(());
        }
        let held = self
            .retained_app_service_transfer
            .as_ref()
            .ok_or(NativeTransactionError::UnknownInspect)?;
        if held.transaction != intent.transaction_id
            || held.before_sha256 != Sha256Digest::of_bytes(before)
            || held.target_sha256 != Sha256Digest::of_bytes(target)
            || held.before_sha256 != intent.before_state_sha256
            || held.target_sha256 != intent.target_state_sha256
        {
            return Err(NativeTransactionError::Conflict);
        }
        held.validate(&self.configuration_root())
    }
}
