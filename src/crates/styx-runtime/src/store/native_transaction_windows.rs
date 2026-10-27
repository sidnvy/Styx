//! Windows review entry under the original configuration writer. Preparing the
//! private management namespace is the only possible durable initialization;
//! review does not exclude Startup, retire credentials, or change canonical state.
use super::*;
use crate::{
    app::HostScope,
    release::VerifiedNativeRelease,
    store::{PrivateRoot, configuration::ConfigurationOpenFailure},
};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use styx_contracts::native_management::{
    NativeAutostartDesired, NativeComponentDesired, NativeDesired, NativeManager,
    NativeRootIdentity, NativeRunDesired,
};

pub(crate) struct WindowsHostMigrationReview {
    pub(crate) transaction_id: TransactionId,
    pub(crate) raw: Vec<u8>,
    pub(crate) plan_sha256: Sha256Digest,
}
/// Failed preflight retains any original writer/fence already acquired. Neither
/// error inspection nor a public report manufactures a settled native owner.
#[must_use = "retain the original owner or non-aborted migration job"]
pub(crate) struct WindowsMigrationPreparationFailure {
    error: NativeTransactionError,
    diagnostic: Option<serde_json::Value>,
    teardown: bool,
    waiting: bool,
    _app_scope: Option<Arc<HostScope>>,
    _ownership: FailedPreparation,
}
enum FailedPreparation {
    Unstarted,
    Configuration(OwnedConfigurationRoot),
    Opening(Box<ConfigurationOpenFailure>),
    Preparing(Box<WindowsMigrationPreparation>),
    Legacy(Box<LegacyRecoveryOwner>),
    Running {
        _recovery: Box<WindowsMigrationRecovery>,
        _observation: Option<NativeMigrationObservation>,
    },
    Rejected {
        _scope: Box<NativeMigrationRejectedScope>,
        _recovery: Box<WindowsMigrationRecovery>,
    },
    Committed(Box<NativeMigrationCommittedScope>),
    Transactions {
        _transactions: Box<NativeTransactions>,
        _permit: Arc<SemaphorePermit<'static>>,
        _app_scope: Option<Arc<HostScope>>,
    },
}
impl WindowsMigrationPreparationFailure {
    pub(crate) fn diagnostic(&self) -> Option<serde_json::Value> {
        self.diagnostic.clone()
    }
    pub(crate) fn process_teardown_required(&self) -> bool {
        self.teardown
    }
    pub(crate) fn waiting_for_later_boot(&self) -> bool {
        self.waiting
    }
    pub(crate) fn error(&self) -> NativeTransactionError {
        self.error
    }
}
struct WindowsMigrationPreparation {
    owner: OwnedConfigurationRoot,
    maintenance: Option<ConfigurationMaintenance>,
    journal: Option<OwnedManagementJournal>,
    candidate: Arc<VerifiedNativeRelease>,
    app_scope: Option<Arc<HostScope>>,
    desired: NativeDesired,
}
fn failed(
    error: NativeTransactionError,
    ownership: FailedPreparation,
) -> Box<WindowsMigrationPreparationFailure> {
    Box::new(WindowsMigrationPreparationFailure {
        error,
        diagnostic: None,
        teardown: false,
        waiting: false,
        _app_scope: None,
        _ownership: ownership,
    })
}
fn prepare_initial(
    state_dir: &Path,
    id: TransactionId,
    candidate: Arc<VerifiedNativeRelease>,
    run: NativeRunDesired,
    app_scope: Option<Arc<HostScope>>,
) -> Result<WindowsMigrationPreparation, Box<WindowsMigrationPreparationFailure>> {
    let retained_scope = app_scope.clone();
    let preparation_failed = |error, ownership| {
        let mut failure = failed(error, ownership);
        failure._app_scope = retained_scope.clone();
        failure
    };
    let root = PrivateRoot::open(state_dir).map_err(|_| {
        preparation_failed(
            NativeTransactionError::UnknownInspect,
            FailedPreparation::Unstarted,
        )
    })?;
    let writer = root.try_existing_configuration_writer().map_err(|_| {
        preparation_failed(
            NativeTransactionError::Conflict,
            FailedPreparation::Unstarted,
        )
    })?;
    let owner = OwnedConfigurationRoot::open_existing_retaining(root, writer).map_err(|error| {
        preparation_failed(error.error.into(), FailedPreparation::Opening(error))
    })?;
    let desired = NativeDesired {
        gateway: None,
        host: Some(NativeComponentDesired {
            manager: if app_scope.is_some() {
                NativeManager::AppManaged
            } else {
                NativeManager::ForegroundCli
            },
            run,
            autostart: NativeAutostartDesired::Disabled,
        }),
    };
    let mut prepared = WindowsMigrationPreparation {
        owner,
        maintenance: None,
        journal: None,
        candidate,
        app_scope,
        desired,
    };
    let checked = (|| -> Result<(), NativeTransactionError> {
        prepared.owner.ensure_admission()?;
        prepared.owner.with_state(|state| {
            state
                .root
                .ensure_absent(crate::store::native_root::NATIVE_MARKER_FILE)
                .map_err(|_| JournalError::Conflict)
        })?;
        prepared
            .candidate
            .revalidate()
            .map_err(|_| NativeTransactionError::UnknownInspect)?;
        if let Some(scope) = &prepared.app_scope {
            if scope.state_dir() != state_dir {
                return Err(NativeTransactionError::Conflict);
            }
            scope
                .validate()
                .map_err(|_| NativeTransactionError::UnknownInspect)?;
        }
        prepared.maintenance = Some(prepared.owner.begin_standalone_native(id, false)?);
        let maintenance = prepared
            .maintenance
            .as_ref()
            .ok_or(NativeTransactionError::Conflict)?;
        prepared.journal = Some(OwnedManagementJournal::open_for_native_retirement(
            prepared.owner.clone(),
            maintenance,
            JournalBudget::default(),
        )?);
        Ok(())
    })();
    match checked {
        Ok(()) => Ok(prepared),
        Err(error) => Err(preparation_failed(
            error,
            FailedPreparation::Preparing(Box::new(prepared)),
        )),
    }
}
/// Execute on a blocking thread: all COM observations are created, used and
/// dropped inside this call. The returned bytes are review data, not authority.
pub(crate) fn review_windows_host_migration(
    state_dir: PathBuf,
    id: TransactionId,
    candidate: Arc<VerifiedNativeRelease>,
    run: NativeRunDesired,
    app_scope: Option<Arc<HostScope>>,
) -> Result<WindowsHostMigrationReview, Box<WindowsMigrationPreparationFailure>> {
    let prepared = prepare_initial(&state_dir, id.clone(), candidate, run, app_scope)?;
    let result = (|| -> Result<_, NativeTransactionError> {
        let review = crate::store::platform::review_windows_restart_host_migration(
            &state_dir,
            &prepared.owner,
            prepared
                .maintenance
                .as_ref()
                .ok_or(NativeTransactionError::Conflict)?,
            prepared
                .journal
                .as_ref()
                .ok_or(NativeTransactionError::Conflict)?,
            &prepared.candidate,
            &prepared.desired,
            prepared.app_scope.as_deref(),
        )?;
        Ok(WindowsHostMigrationReview {
            transaction_id: id,
            raw: review.raw,
            plan_sha256: review.sha256,
        })
    })();
    match result {
        Ok(review) => Ok(review),
        Err(error) => Err(failed(
            error,
            FailedPreparation::Preparing(Box::new(prepared)),
        )),
    }
}

use crate::store::{
    management::cutover,
    native_migration_job::{
        NativeMigrationCommittedScope, NativeMigrationObservation, NativeMigrationOwnerTask,
        NativeMigrationRejectedScope,
    },
    platform::{start_resume_windows_restart_host_migration, start_windows_restart_host_migration},
    secure_journal::files,
};
use tokio::{runtime::Handle, sync::SemaphorePermit};

struct LegacyRecoveryOwner {
    _app_scope: Option<Arc<HostScope>>,
    owner: OwnedConfigurationRoot,
    journal: OwnedManagementJournal,
    // Original by-value fence; never reconstructed by unwrapping an Arc.
    maintenance: Option<ConfigurationMaintenance>,
}
#[must_use = "retain the original owner task until actual settlement"]
pub(crate) struct WindowsMigrationRecovery {
    task: Option<NativeMigrationOwnerTask>,
    binding: Option<NativeRootBinding>,
    ready: Option<(
        NativeTransactions,
        NativeCommitResult,
        Arc<SemaphorePermit<'static>>,
    )>,
    _app_scope: Option<Arc<HostScope>>,
    transaction: TransactionId,
    recovered: bool,
}
fn detailed_failure(
    error: NativeTransactionError,
    ownership: FailedPreparation,
    id: &TransactionId,
    stage: &'static str,
    outcome: &'static str,
    teardown: bool,
) -> Box<WindowsMigrationPreparationFailure> {
    let waiting = outcome == "pending";
    let mut failure = failed(error, ownership);
    failure.teardown = teardown;
    failure.waiting = waiting;
    failure.diagnostic = Some(serde_json::json!({
        "transaction_id": id,
        "stage": stage,
        "outcome": outcome,
        "next_action": if waiting {
            "restart_windows_then_explicitly_recover_original_transaction"
        } else if outcome == "not_started" {
            "review_preconditions_before_explicit_migration"
        } else {
            "inspect_original_transaction_then_recover_or_manual_review"
        },
        "operations_replayed": false,
        "cleanup_confirmed": false,
    }));
    failure
}

/// Move the SAME already-open writer, by-value fence and journal into the
/// original retained COM worker. No OS flow or approval is duplicated here.
#[expect(
    clippy::too_many_arguments,
    reason = "closed original-owner migration entry includes explicit approval"
)]
pub(crate) fn begin_windows_host_migration(
    state_dir: PathBuf,
    id: TransactionId,
    candidate: Arc<VerifiedNativeRelease>,
    run: NativeRunDesired,
    app_scope: Option<Arc<HostScope>>,
    runtime: Handle,
    permit: SemaphorePermit<'static>,
    approved_sha: Sha256Digest,
) -> Result<WindowsMigrationRecovery, Box<WindowsMigrationPreparationFailure>> {
    let mut prepared = prepare_initial(&state_dir, id.clone(), candidate, run, app_scope)?;
    // Validate both Options before taking either original resource. An error
    // retains the complete preparation instead of dropping a partially moved one.
    if prepared.maintenance.is_none() || prepared.journal.is_none() {
        return Err(detailed_failure(
            NativeTransactionError::Conflict,
            FailedPreparation::Preparing(Box::new(prepared)),
            &id,
            "initial_migration_preflight",
            "not_started",
            false,
        ));
    }
    let maintenance = prepared.maintenance.take().expect("checked original fence");
    let journal = prepared.journal.take().expect("checked original journal");
    let task = start_windows_restart_host_migration(
        runtime,
        state_dir,
        prepared.owner,
        maintenance,
        journal,
        prepared.candidate,
        prepared.desired,
        prepared.app_scope,
        Arc::new(permit),
        approved_sha,
    );
    Ok(WindowsMigrationRecovery {
        task: Some(task),
        binding: None,
        ready: None,
        _app_scope: None,
        transaction: id,
        recovered: false,
    })
}

/// Existing pre-canonical transaction only. A marker, token attempt or native
/// cutover never falls back to this legacy entry or obtains a replacement id.
pub(crate) fn begin_windows_legacy_recovery(
    state_dir: PathBuf,
    id: TransactionId,
    app_scope: Option<Arc<HostScope>>,
    runtime: Handle,
    permit: SemaphorePermit<'static>,
) -> Result<WindowsMigrationRecovery, Box<WindowsMigrationPreparationFailure>> {
    let legacy_failed = |error, ownership| {
        let mut failure = failed(error, ownership);
        failure._app_scope = app_scope.clone();
        failure
    };
    let root = PrivateRoot::open(&state_dir).map_err(|_| {
        legacy_failed(
            NativeTransactionError::UnknownInspect,
            FailedPreparation::Unstarted,
        )
    })?;
    let writer = root.try_existing_configuration_writer().map_err(|_| {
        legacy_failed(
            NativeTransactionError::Conflict,
            FailedPreparation::Unstarted,
        )
    })?;
    let owner = OwnedConfigurationRoot::open_existing_retaining(root, writer)
        .map_err(|error| legacy_failed(error.error.into(), FailedPreparation::Opening(error)))?;
    let journal =
        match OwnedManagementJournal::open_existing(owner.clone(), JournalBudget::default()) {
            Ok(journal) => journal,
            Err(error) => {
                return Err(legacy_failed(
                    error.into(),
                    FailedPreparation::Configuration(owner),
                ));
            }
        };
    let mut original = LegacyRecoveryOwner {
        _app_scope: app_scope.clone(),
        owner,
        journal,
        maintenance: None,
    };
    let checked = (|| -> Result<_, NativeTransactionError> {
        original.maintenance = Some(original.owner.begin_standalone_native(id.clone(), true)?);
        let maintenance = original
            .maintenance
            .as_ref()
            .ok_or(NativeTransactionError::Conflict)?;
        original.owner.with_maintenance(maintenance, |state| {
            state
                .root
                .ensure_absent(crate::store::native_root::NATIVE_MARKER_FILE)
                .map_err(|_| JournalError::Conflict)
        })?;
        let plan = original.journal.resync_native_migration_plan(maintenance)?;
        let recovery = plan
            .owner_recovery_inputs()?
            .ok_or(NativeTransactionError::Conflict)?;
        if !plan.complete()
            || plan.retirement.transaction_id != id
            || recovery.validated_intent()?.schema != 3
            || plan.desired.gateway.is_some()
            || !plan.desired.host.as_ref().is_some_and(|host| {
                host.autostart == NativeAutostartDesired::Disabled
                    && host.manager != NativeManager::PersistentService
            })
        {
            return Err(NativeTransactionError::Conflict);
        }
        match (
            plan.desired.host.as_ref().map(|host| host.manager),
            &app_scope,
        ) {
            (Some(NativeManager::ForegroundCli), None) => (),
            (Some(NativeManager::AppManaged), Some(scope)) if scope.state_dir() == state_dir => {
                scope
                    .validate()
                    .map_err(|_| NativeTransactionError::UnknownInspect)?;
            }
            _ => return Err(NativeTransactionError::Conflict),
        }
        let inventory = original.journal.observe()?;
        if !inventory.handoffs.is_empty()
            || inventory.committed_cutover_anchor.is_some()
            || !inventory.orphans.is_empty()
        {
            return Err(NativeTransactionError::Conflict);
        }
        let candidate = Arc::new(
            crate::release::verify_selected(&plan.selection)
                .map_err(|_| NativeTransactionError::UnknownInspect)?,
        );
        if candidate.report().target != "x86_64-pc-windows-msvc"
            || candidate.report().manifest_sha256 != plan.retirement.candidate_manifest_sha256
            || candidate.report().publisher_spki_sha256
                != plan.retirement.publisher_spki_sha256.to_hex()
        {
            return Err(NativeTransactionError::Conflict);
        }
        Ok(candidate)
    })();
    let candidate = match checked {
        Ok(candidate) => candidate,
        Err(error) => {
            return Err(detailed_failure(
                error,
                FailedPreparation::Legacy(Box::new(original)),
                &id,
                "legacy_recovery_preflight",
                "blocked",
                false,
            ));
        }
    };
    let maintenance = original.maintenance.take().expect("checked original fence");
    let task = start_resume_windows_restart_host_migration(
        runtime,
        state_dir,
        original.owner,
        maintenance,
        original.journal,
        candidate,
        app_scope,
        Arc::new(permit),
    );
    Ok(WindowsMigrationRecovery {
        task: Some(task),
        binding: None,
        ready: None,
        _app_scope: None,
        transaction: id,
        recovered: true,
    })
}

impl WindowsMigrationRecovery {
    /// Only an actual worker join transfers the committed original writer back.
    /// Unknown or a real boot checkpoint retains this task rather than retrying.
    pub(crate) async fn finish(
        mut self,
    ) -> Result<
        (
            NativeTransactions,
            NativeCommitResult,
            Arc<SemaphorePermit<'static>>,
        ),
        Box<WindowsMigrationPreparationFailure>,
    > {
        if let Some((transactions, result, permit)) = self.ready.take() {
            if self
                ._app_scope
                .as_ref()
                .is_some_and(|scope| scope.validate().is_err())
            {
                return Err(detailed_failure(
                    NativeTransactionError::UnknownInspect,
                    FailedPreparation::Transactions {
                        _transactions: Box::new(transactions),
                        _permit: permit,
                        _app_scope: self._app_scope.take(),
                    },
                    &self.transaction,
                    "committed_recovery_scope_changed",
                    "unknown",
                    false,
                ));
            }
            return Ok((transactions, result, permit));
        }
        let observed = match self.task.as_mut() {
            Some(task) => task.observe().await,
            None => {
                let id = self.transaction.clone();
                return Err(detailed_failure(
                    NativeTransactionError::Conflict,
                    FailedPreparation::Running {
                        _recovery: Box::new(self),
                        _observation: None,
                    },
                    &id,
                    "migration_task_missing",
                    "unknown",
                    false,
                ));
            }
        };
        let mut observed = match observed {
            Ok(observed) => observed,
            Err(_) => {
                let id = self.transaction.clone();
                return Err(detailed_failure(
                    NativeTransactionError::UnknownInspect,
                    FailedPreparation::Running {
                        _recovery: Box::new(self),
                        _observation: None,
                    },
                    &id,
                    "owner_observation_lost",
                    "unknown",
                    false,
                ));
            }
        };
        if observed.transaction_id == self.transaction
            && let Some(scope) = observed.rejected_scope.take()
        {
            let stage = observed.stage;
            let joined = self
                .task
                .as_mut()
                .expect("original task")
                .join_rejected()
                .await
                .is_ok();
            let id = self.transaction.clone();
            return Err(detailed_failure(
                if joined {
                    NativeTransactionError::Conflict
                } else {
                    NativeTransactionError::UnknownInspect
                },
                FailedPreparation::Rejected {
                    _scope: scope,
                    _recovery: Box::new(self),
                },
                &id,
                stage,
                if joined { "not_started" } else { "unknown" },
                false,
            ));
        }
        let expected_stage = if self.binding.is_some() {
            "resumed_committed_admission_released"
        } else {
            "committed_admission_released"
        };
        if observed.transaction_id != self.transaction || observed.stage != expected_stage {
            let waiting = observed.transaction_id == self.transaction
                && observed.stage == "waiting_for_later_boot";
            let stage = observed.stage;
            let id = self.transaction.clone();
            return Err(detailed_failure(
                if waiting {
                    NativeTransactionError::Conflict
                } else {
                    NativeTransactionError::UnknownInspect
                },
                FailedPreparation::Running {
                    _recovery: Box::new(self),
                    _observation: Some(observed),
                },
                &id,
                stage,
                if waiting { "pending" } else { "unknown" },
                true,
            ));
        }
        let scope = match self
            .task
            .as_mut()
            .expect("original task")
            .join_committed()
            .await
        {
            Ok(scope) => scope,
            Err(_) => {
                let id = self.transaction.clone();
                return Err(detailed_failure(
                    NativeTransactionError::UnknownInspect,
                    FailedPreparation::Running {
                        _recovery: Box::new(self),
                        _observation: Some(observed),
                    },
                    &id,
                    "committed_worker_join_failed",
                    "unknown",
                    false,
                ));
            }
        };
        let Some(permit) = scope.recovery_permit.clone() else {
            return Err(detailed_failure(
                NativeTransactionError::UnknownInspect,
                FailedPreparation::Committed(scope),
                &self.transaction,
                "committed_permit_missing",
                "unknown",
                false,
            ));
        };
        let binding = match self.binding.take() {
            Some(binding) => binding,
            None => match crate::store::native_root::bind_owned_native(scope.owner.clone()) {
                Ok(binding) => binding,
                Err(_) => {
                    return Err(detailed_failure(
                        NativeTransactionError::UnknownInspect,
                        FailedPreparation::Committed(scope),
                        &self.transaction,
                        "committed_native_binding_failed",
                        "unknown",
                        false,
                    ));
                }
            },
        };
        let app_scope = scope.app_scope.clone();
        let owner = scope.owner.clone();
        let transactions = NativeTransactions {
            binding,
            journal: Arc::new(scope.journal),
            retained_maintenance: None,
            retained_runtime_update: None,
            retained_app_service_transfer: None,
        };
        let checked = (|| -> Result<_, NativeTransactionError> {
            if !transactions.configuration_root().same_authority(&owner) {
                return Err(NativeTransactionError::Conflict);
            }
            if let Some(app) = &app_scope {
                app.validate()
                    .map_err(|_| NativeTransactionError::UnknownInspect)?;
            }
            owner.ensure_admission()?;
            let state = transactions.readstate()?;
            let (target, receipt) = owner.with_state(|state| {
                transactions
                    .journal
                    .with_directory_locked(state, |directory| {
                        let scan = files::scan(directory, transactions.journal.budget())?;
                        let original =
                            cutover::original_for::<NativeRootIdentity>(&scan, &self.transaction)?;
                        if original.intent.schema != 4
                            || original.last_stage != DurableStage::Committed
                        {
                            return Err(JournalError::Conflict);
                        }
                        Ok((
                            original.intent.target_state_sha256,
                            original
                                .phases
                                .last()
                                .cloned()
                                .ok_or(JournalError::Conflict)?,
                        ))
                    })
            })?;
            if target != state.raw_sha256() {
                return Err(NativeTransactionError::UnknownInspect);
            }
            Ok(NativeCommitResult {
                transaction_id: self.transaction.clone(),
                canonical_raw_sha256: state.raw_sha256(),
                committed: receipt,
                recovered: self.recovered,
            })
        })();
        match checked {
            Ok(result) => Ok((transactions, result, permit)),
            Err(error) => Err(detailed_failure(
                error,
                FailedPreparation::Transactions {
                    _transactions: Box::new(transactions),
                    _permit: permit,
                    _app_scope: app_scope,
                },
                &self.transaction,
                "committed_original_readback_failed",
                "unknown",
                false,
            )),
        }
    }
}

impl NativeTransactions {
    /// Native canonical recovery never returns to the legacy checkpoint route.
    /// Already Committed is full read-only reconciliation; Applied/Verified must
    /// have both durable successful reports and reacquire original OS custody.
    pub(crate) fn begin_windows_migration_recovery(
        mut self,
        state_dir: PathBuf,
        id: TransactionId,
        app_scope: Option<Arc<HostScope>>,
        runtime: Handle,
        permit: SemaphorePermit<'static>,
    ) -> Result<WindowsMigrationRecovery, Box<WindowsMigrationPreparationFailure>> {
        use crate::store::committed_runtime_native::{
            NativeCommittedRuntimeSnapshot, NativeValidatedMigrationSnapshot,
        };
        let permit = Arc::new(permit);
        let preflight = (|| -> Result<_, NativeTransactionError> {
            if self.retained_maintenance.is_some()
                || self.retained_runtime_update.is_some()
                || self.retained_app_service_transfer.is_some()
            {
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
                .as_ref()
                .ok_or(NativeTransactionError::Conflict)?;
            if state.state().desired.gateway.is_some()
                || host.autostart != NativeAutostartDesired::Disabled
            {
                return Err(NativeTransactionError::Unsupported);
            }
            match (host.manager, &app_scope) {
                (NativeManager::ForegroundCli, None) => (),
                (NativeManager::AppManaged, Some(scope)) if scope.state_dir() == state_dir => scope
                    .validate()
                    .map_err(|_| NativeTransactionError::UnknownInspect)?,
                _ => return Err(NativeTransactionError::Conflict),
            }
            Ok(self.configuration_root().with_state(|state| {
                self.journal.with_directory_locked(state, |directory| {
                    let scan = files::scan(directory, self.journal.budget())?;
                    let original = cutover::original_for::<NativeRootIdentity>(&scan, &id)?;
                    if original.intent.schema != 4 {
                        return Err(JournalError::Conflict);
                    }
                    if original.last_stage != DurableStage::Committed {
                        cutover::check_canonical(state, &original, true)?;
                    }
                    Ok(original)
                })
            })?)
        })();
        let original = match preflight {
            Ok(original) => original,
            Err(error) => {
                return Err(detailed_failure(
                    error,
                    FailedPreparation::Transactions {
                        _transactions: Box::new(self),
                        _permit: permit,
                        _app_scope: app_scope,
                    },
                    &id,
                    "native_recovery_preflight",
                    "blocked",
                    false,
                ));
            }
        };
        if original.last_stage == DurableStage::Committed {
            let checked = (|| -> Result<_, NativeTransactionError> {
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
            return match checked {
                Ok(result) => Ok(WindowsMigrationRecovery {
                    task: None,
                    binding: None,
                    ready: Some((self, result, permit)),
                    _app_scope: app_scope,
                    transaction: id,
                    recovered: true,
                }),
                Err(error) => Err(detailed_failure(
                    error,
                    FailedPreparation::Transactions {
                        _transactions: Box::new(self),
                        _permit: permit,
                        _app_scope: app_scope,
                    },
                    &id,
                    "committed_recovery_failed",
                    "unknown",
                    false,
                )),
            };
        }
        let checked = (|| -> Result<_, NativeTransactionError> {
            let snapshot = NativeValidatedMigrationSnapshot::open(&state_dir, original.last_stage)?;
            if snapshot.root_identity() != self.configuration_root().identity()?
                || snapshot.original().raw_intent != original.raw_intent
                || snapshot.original().phases != original.phases
            {
                return Err(NativeTransactionError::Conflict);
            }
            snapshot.revalidate()?;
            let candidate = snapshot.candidate().clone();
            let maintenance = self
                .configuration_root()
                .begin_standalone_native(id.clone(), true)?;
            Ok((candidate, maintenance))
        })();
        let (candidate, maintenance) = match checked {
            Ok(value) => value,
            Err(error) => {
                return Err(detailed_failure(
                    error,
                    FailedPreparation::Transactions {
                        _transactions: Box::new(self),
                        _permit: permit,
                        _app_scope: app_scope,
                    },
                    &id,
                    "validated_native_recovery_blocked",
                    "unknown",
                    false,
                ));
            }
        };
        let Self {
            binding,
            journal,
            retained_maintenance,
            // The preflight above refuses runtime-update custody before moving
            // this coordinator into the unrelated migration worker.
            retained_runtime_update,
            retained_app_service_transfer,
        } = self;
        // Migration requires exclusive original journal custody. Preserve the
        // coordinator if an opaque frame still retains the same writer.
        let journal = match Arc::try_unwrap(journal) {
            Ok(journal) => journal,
            Err(journal) => {
                return Err(detailed_failure(
                    NativeTransactionError::Conflict,
                    FailedPreparation::Transactions {
                        _transactions: Box::new(Self {
                            binding,
                            journal,
                            retained_maintenance,
                            retained_runtime_update,
                            retained_app_service_transfer,
                        }),
                        _permit: permit,
                        _app_scope: app_scope,
                    },
                    &id,
                    "validated_native_journal_shared",
                    "unknown",
                    false,
                ));
            }
        };
        let task = crate::store::platform::start_resume_validated_windows_host_migration(
            runtime,
            state_dir,
            binding.configuration_root(),
            maintenance,
            journal,
            candidate,
            app_scope.clone(),
            permit,
        );
        Ok(WindowsMigrationRecovery {
            task: Some(task),
            binding: Some(binding),
            ready: None,
            _app_scope: app_scope,
            transaction: id,
            recovered: true,
        })
    }
}
