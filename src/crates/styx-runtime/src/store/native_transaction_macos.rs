//! Move the existing management writer/journal into validated migration recovery.
//! The CLI cannot impersonate App custody; incomplete/unknown probes never replay.
use super::*;
use crate::store::{
    committed_runtime_native::{NativeCommittedRuntimeSnapshot, NativeValidatedMigrationSnapshot},
    management::cutover::{self, OriginalCutover},
    platform::{MacMigrationOwnerTask, start_resume_validated_host_migration},
    secure_journal::files,
};
use std::{path::PathBuf, sync::Arc};
use styx_contracts::native_management::{
    NativeAutostartDesired, NativeManager, NativeRootIdentity,
};
use tokio::{runtime::Handle, sync::SemaphorePermit};

pub(crate) enum MacMigrationRecoveryStart {
    Complete(NativeTransactions, NativeCommitResult),
    Running(MacMigrationRecovery),
}
#[must_use = "retain the original transaction owner or the started recovery task"]
pub(crate) struct MacMigrationRecoveryFailure {
    error: NativeTransactionError,
    process_teardown_required: bool,
    _ownership: FailedOwner,
}
enum FailedOwner {
    Transactions { _owner: Box<NativeTransactions> },
    Running { _owner: Box<MacMigrationRecovery> },
}
impl MacMigrationRecoveryFailure {
    pub(crate) fn error(&self) -> NativeTransactionError {
        self.error
    }
    pub(crate) fn process_teardown_required(&self) -> bool {
        self.process_teardown_required
    }
    fn transactions(error: NativeTransactionError, owner: NativeTransactions) -> Box<Self> {
        Box::new(Self {
            error,
            process_teardown_required: false,
            _ownership: FailedOwner::Transactions {
                _owner: Box::new(owner),
            },
        })
    }
}
#[must_use = "the actual worker and original binding must remain owned until joined"]
pub(crate) struct MacMigrationRecovery {
    binding: NativeRootBinding,
    task: MacMigrationOwnerTask,
    transaction: TransactionId,
}
impl NativeTransactions {
    fn original_mac_migration(
        &self,
        id: &TransactionId,
    ) -> Result<OriginalCutover<NativeRootIdentity>, NativeTransactionError> {
        let owner = self.configuration_root();
        Ok(owner.with_state(|state| {
            self.journal.with_directory_locked(state, |directory| {
                let scan = files::scan(directory, self.journal.budget())?;
                let original = cutover::original_for::<NativeRootIdentity>(&scan, id)?;
                if original.intent.schema != 4 {
                    return Err(JournalError::Conflict);
                }
                if original.last_stage != DurableStage::Committed {
                    cutover::check_canonical(state, &original, true)?;
                }
                // Committed reopening validates the complete later native tip
                // through the existing committed reader below.
                Ok(original)
            })
        })?)
    }
    /// Consumes this coordinator, never opens another writer/namespace. All
    /// preflight failures return its original ownership. After start, the actual
    /// non-abortable worker holds the bounded management permit through Unknown.
    pub(crate) fn begin_mac_migration_recovery(
        mut self,
        state_dir: PathBuf,
        id: TransactionId,
        app_scope: Option<Arc<crate::app::HostScope>>,
        runtime: Handle,
        permit: SemaphorePermit<'static>,
    ) -> Result<MacMigrationRecoveryStart, Box<MacMigrationRecoveryFailure>> {
        let preflight = (|| -> Result<_, NativeTransactionError> {
            if self.retained_maintenance.is_some() {
                return Err(NativeTransactionError::Conflict);
            }
            let state = self.readstate()?;
            let binding = state
                .state()
                .migration_v2()
                .map_err(|_| NativeTransactionError::Conflict)?
                .ok_or(NativeTransactionError::Conflict)?;
            if binding.transaction_id != id {
                return Err(NativeTransactionError::Conflict);
            }
            let host = state
                .state()
                .desired
                .host
                .ok_or(NativeTransactionError::Unsupported)?;
            if state.state().desired.gateway.is_some()
                || host.autostart != NativeAutostartDesired::Disabled
            {
                return Err(NativeTransactionError::Unsupported);
            }
            match (host.manager, &app_scope) {
                (NativeManager::AppManaged, Some(scope)) if scope.state_dir() == state_dir => {
                    scope
                        .validate()
                        .map_err(|_| NativeTransactionError::UnknownInspect)?;
                }
                (NativeManager::ForegroundCli, None) => (),
                _ => return Err(NativeTransactionError::Conflict),
            }
            self.original_mac_migration(&id)
        })();
        let original = match preflight {
            Ok(original) => original,
            Err(error) => return Err(MacMigrationRecoveryFailure::transactions(error, self)),
        };
        if original.last_stage == DurableStage::Committed {
            let done = (|| -> Result<_, NativeTransactionError> {
                let snapshot = Arc::new(NativeCommittedRuntimeSnapshot::open(&state_dir)?);
                self.reconcile_committed_migration(snapshot)?;
                if let Some(scope) = &app_scope {
                    scope
                        .validate()
                        .map_err(|_| NativeTransactionError::UnknownInspect)?;
                }
                Ok(NativeCommitResult {
                    transaction_id: id.clone(),
                    canonical_raw_sha256: self.readstate()?.raw_sha256(),
                    committed: original
                        .phases
                        .last()
                        .cloned()
                        .ok_or(NativeTransactionError::Conflict)?,
                    recovered: true,
                })
            })();
            return match done {
                Ok(result) => Ok(MacMigrationRecoveryStart::Complete(self, result)),
                Err(error) => Err(MacMigrationRecoveryFailure::transactions(error, self)),
            };
        }
        let pending = (|| -> Result<_, NativeTransactionError> {
            let snapshot = NativeValidatedMigrationSnapshot::open(&state_dir, original.last_stage)?;
            if snapshot.root_identity() != self.configuration_root().identity()?
                || snapshot.original().raw_intent != original.raw_intent
                || snapshot.original().phases != original.phases
            {
                return Err(NativeTransactionError::Conflict);
            }
            let candidate = snapshot.candidate().clone();
            snapshot.revalidate()?;
            // This is the existing transaction's recovery fence, not a new id.
            let maintenance = self
                .configuration_root()
                .begin_standalone_native(id.clone(), true)?;
            Ok((candidate, Arc::new(maintenance)))
        })();
        let (candidate, maintenance) = match pending {
            Ok(value) => value,
            Err(error) => return Err(MacMigrationRecoveryFailure::transactions(error, self)),
        };
        let Self {
            binding,
            journal,
            retained_maintenance: _,
        } = self;
        let task = start_resume_validated_host_migration(
            runtime,
            state_dir,
            binding.configuration_root(),
            maintenance,
            journal,
            candidate,
            app_scope,
            Arc::new(permit),
        );
        Ok(MacMigrationRecoveryStart::Running(MacMigrationRecovery {
            binding,
            task,
            transaction: id,
        }))
    }
}
impl MacMigrationRecovery {
    /// Cancellation only drops a waiter. The started worker keeps original OS
    /// custody and the bounded permit; successful ownership returns after join.
    pub(crate) async fn finish(
        mut self,
    ) -> Result<
        (
            NativeTransactions,
            NativeCommitResult,
            Arc<SemaphorePermit<'static>>,
        ),
        Box<MacMigrationRecoveryFailure>,
    > {
        let result = self.task.observe().await;
        if !matches!(&result, Ok(o) if o.stage == "resumed_committed_admission_released") {
            return Err(Box::new(MacMigrationRecoveryFailure {
                error: NativeTransactionError::UnknownInspect,
                process_teardown_required: result.is_ok(),
                _ownership: FailedOwner::Running {
                    _owner: Box::new(self),
                },
            }));
        }
        let scope = match self.task.join_committed().await {
            Ok(scope) => scope,
            Err(_) => {
                return Err(Box::new(MacMigrationRecoveryFailure {
                    error: NativeTransactionError::UnknownInspect,
                    process_teardown_required: false,
                    _ownership: FailedOwner::Running {
                        _owner: Box::new(self),
                    },
                }));
            }
        };
        let retained_permit = scope.recovery_permit.clone();
        let transactions = NativeTransactions {
            binding: self.binding,
            journal: scope.journal,
            retained_maintenance: None,
        };
        let committed = (|| -> Result<_, NativeTransactionError> {
            if !transactions
                .configuration_root()
                .same_authority(&scope.owner)
            {
                return Err(NativeTransactionError::Conflict);
            }
            if let Some(app) = &scope.app_scope {
                app.validate()
                    .map_err(|_| NativeTransactionError::UnknownInspect)?;
            }
            transactions.configuration_root().ensure_admission()?;
            let original = transactions.original_mac_migration(&self.transaction)?;
            if original.last_stage != DurableStage::Committed {
                return Err(NativeTransactionError::UnknownInspect);
            }
            Ok(NativeCommitResult {
                transaction_id: self.transaction,
                canonical_raw_sha256: transactions.readstate()?.raw_sha256(),
                committed: original
                    .phases
                    .last()
                    .cloned()
                    .ok_or(NativeTransactionError::UnknownInspect)?,
                recovered: true,
            })
        })();
        match committed {
            Ok(result) => match retained_permit {
                Some(permit) => Ok((transactions, result, permit)),
                None => Err(MacMigrationRecoveryFailure::transactions(
                    NativeTransactionError::UnknownInspect,
                    transactions,
                )),
            },
            Err(error) => Err(MacMigrationRecoveryFailure::transactions(
                error,
                transactions,
            )),
        }
    }
}
