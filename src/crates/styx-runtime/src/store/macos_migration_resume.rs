//! Resume a validated original Mac migration without dispatching any operation.
//! Historical successful reports stay historical; no old JoinHandle is invented.
use super::*;
use crate::store::{
    committed_runtime_native::NativeValidatedMigrationSnapshot,
    management::cutover::PreparedCutover,
};
use styx_core::management::transaction::JournalReceipt;

/// Only constructed after actual original custody and both durable successful
/// reports are verified, and the original journal reaches Committed.
pub(in crate::store) struct MacResumedCutover<'a> {
    owner: &'a OwnedConfigurationRoot,
    maintenance: &'a ConfigurationMaintenance,
    prepared: &'a PreparedCutover<NativeRootIdentity>,
    committed: JournalReceipt,
}
impl MacResumedCutover<'_> {
    pub(in crate::store) fn matches_fenced_owner(
        &self,
        owner: &OwnedConfigurationRoot,
        root: &RootIdentity,
        transaction: Option<&TransactionId>,
    ) -> bool {
        self.owner.same_authority(owner)
            && self.maintenance.matches(owner)
            && self.prepared.matches_owner(owner)
            && native_id(root.clone()).is_ok_and(|id| id == self.prepared.intent().config_root)
            && transaction == Some(self.maintenance.transaction_id())
            && self.committed.stage == DurableStage::Committed
    }
}

/// Caller must own the ORIGINAL recovery writer/journal and its same-tx fence.
/// No source is reacquired to escape a retained or poisoned owner. Missing
/// reports remain Unknown; only Applied/Verified with both reports can enter.
pub(in crate::store) fn start_resume_validated_host_migration(
    runtime: Handle,
    state_dir: PathBuf,
    owner: OwnedConfigurationRoot,
    maintenance: Arc<ConfigurationMaintenance>,
    journal: OwnedManagementJournal,
    candidate: Arc<VerifiedNativeRelease>,
    app_scope: Option<Arc<crate::app::HostScope>>,
    permit: Arc<tokio::sync::SemaphorePermit<'static>>,
) -> MacMigrationOwnerTask {
    let (sender, observation) = oneshot::channel();
    let executor = runtime.clone();
    let job = runtime.spawn_blocking(move || {
        let _permit = permit.clone();
        executor.block_on(run_resume(
            state_dir,
            owner,
            maintenance,
            journal,
            candidate,
            app_scope,
            permit,
            sender,
        ));
    });
    MacMigrationOwnerTask::from_job(observation, job)
}
async fn run_resume(
    state_dir: PathBuf,
    owner: OwnedConfigurationRoot,
    maintenance: Arc<ConfigurationMaintenance>,
    mut journal: OwnedManagementJournal,
    candidate: Arc<VerifiedNativeRelease>,
    app_scope: Option<Arc<crate::app::HostScope>>,
    permit: Arc<tokio::sync::SemaphorePermit<'static>>,
    sender: oneshot::Sender<MacMigrationObservation>,
) {
    let transaction = maintenance.transaction_id().clone();
    let mut sender = Some(sender);
    macro_rules! keep {
        ($result:expr, $stage:literal $(, $held:expr)* $(,)?) => {
            match $result {
                Ok(value) => value,
                Err(_) => retain_scope((&owner, &maintenance, &journal, &candidate, &app_scope, &permit, $($held,)*), &mut sender,
                    MacMigrationObservation { transaction_id: transaction.clone(), stage: $stage, local_exec_report: None, pair_admission_report: None, rejected_scope: None, committed_scope: None }).await,
            }
        };
    }
    keep!(
        (|| {
            if !maintenance.matches(&owner) || !journal.configuration_root().same_authority(&owner)
            {
                return Err(JournalError::Conflict);
            }
            candidate.revalidate().map_err(|_| JournalError::Unknown)?;
            Ok(())
        })(),
        "unknown_resume_owner"
    );
    let starting = keep!(
        journal.resync_native_cutover(&maintenance, &transaction),
        "unknown_resume_starting_stage"
    );
    let snapshot = keep!(
        NativeValidatedMigrationSnapshot::open(&state_dir, starting.last_stage),
        "unknown_resume_materials",
        &starting
    );
    let prepared = keep!(
        journal.reopen_validated_native_cutover(&maintenance, candidate.clone()),
        "unknown_resume_original_chain",
        &snapshot
    );
    keep!(
        (|| {
            if snapshot.root_identity() != owner.identity()?
                || snapshot.original().intent != *prepared.intent()
                || snapshot
                    .candidate()
                    .runtime_selection()
                    .map_err(|_| JournalError::Unknown)?
                    != candidate
                        .runtime_selection()
                        .map_err(|_| JournalError::Unknown)?
            {
                return Err(JournalError::Conflict);
            }
            let plan = journal.resync_native_migration_plan(&maintenance)?;
            plan.validate_cutover(snapshot.original())?;
            let host = plan.desired.host.as_ref().ok_or(JournalError::Conflict)?;
            if plan.desired.gateway.is_some() || host.autostart != NativeAutostartDesired::Disabled
            {
                return Err(JournalError::Unsupported);
            }
            match (host.manager, &app_scope) {
                (NativeManager::AppManaged, Some(scope)) if scope.state_dir() == state_dir => {
                    scope.validate().map_err(|_| JournalError::Unknown)?;
                }
                (NativeManager::ForegroundCli, None) => {}
                _ => return Err(JournalError::Conflict),
            }
            Ok(())
        })(),
        "unknown_resume_scope",
        &snapshot,
        &prepared
    );
    let root = keep!(
        PrivateRoot::open(&state_dir),
        "unknown_resume_root",
        &snapshot,
        &prepared
    );
    let host = keep!(
        PrivateRoot::open(snapshot.host_base_dir()),
        "unknown_resume_host",
        &snapshot,
        &prepared,
        &root
    );
    keep!(
        (|| {
            if root.identity() != snapshot.root_identity()
                || host.identity() != snapshot.host_root_identity()
            {
                return Err(JournalError::Conflict);
            }
            Ok(())
        })(),
        "unknown_resume_root_binding",
        &snapshot,
        &prepared,
        &root,
        &host
    );
    let lease = keep!(
        host.try_execution_lease(),
        "unknown_resume_execution_lease",
        &snapshot,
        &prepared,
        &root,
        &host
    );
    let (effects, held) = keep!(
        MacBootRecoveryEffects::reopen_guards_held_for_cutover(
            owner.clone(),
            maintenance.clone(),
            &root.inner,
            &host.inner,
            &journal,
            &prepared
        ),
        "unknown_resume_guard_custody",
        &snapshot,
        &prepared,
        &root,
        &host,
        &lease
    );
    let (retirement, record) = keep!(
        journal.reopen_retired_for_cutover(&maintenance, &prepared),
        "unknown_resume_retired_record",
        &snapshot,
        &prepared,
        &root,
        &host,
        &lease,
        &effects,
        &held
    );
    let token = keep!(
        MacTokenRetirement::reopen_recorded_retired(
            &host.inner,
            owner.clone(),
            maintenance.clone(),
            &retirement,
            &record
        ),
        "unknown_resume_token_custody",
        &snapshot,
        &prepared,
        &root,
        &host,
        &lease,
        &effects,
        &held,
        &retirement,
        &record
    );
    let canonical = keep!(
        root.read_raw("state.json", NATIVE_STATE_BYTES),
        "unknown_resume_canonical_pin",
        &snapshot,
        &prepared,
        &host,
        &lease,
        &effects,
        &held,
        &retirement,
        &record,
        &token
    );
    let local_raw = keep!(
        snapshot
            .original()
            .validation_report()
            .ok_or(JournalError::Conflict),
        "unknown_resume_local_report",
        &snapshot,
        &prepared,
        &host,
        &lease,
        &effects,
        &held,
        &token
    )
    .to_vec();
    let pair_raw = keep!(
        snapshot
            .original()
            .paired_validation_report()
            .ok_or(JournalError::Conflict),
        "unknown_resume_pair_report",
        &snapshot,
        &prepared,
        &host,
        &lease,
        &effects,
        &held,
        &token
    )
    .to_vec();
    keep!(
        snapshot.revalidate(),
        "unknown_resume_initial_revalidation",
        &snapshot,
        &prepared,
        &host,
        &lease,
        &effects,
        &held,
        &token
    );
    let validate_materials = || -> JournalResult<()> {
        snapshot.revalidate_materials()?;
        lease.validate().map_err(|_| JournalError::Unknown)?;
        effects.validate_retained(&held)?;
        if token.validate_retired()? != *record.post_stamp() {
            return Err(JournalError::Unknown);
        }
        if let Some(scope) = &app_scope {
            scope.validate().map_err(|_| JournalError::Unknown)?;
        }
        let now = root
            .read_raw("state.json", NATIVE_STATE_BYTES)
            .map_err(|_| JournalError::Unknown)?;
        if now.observation() != canonical.observation() || now.bytes() != prepared.target() {
            return Err(JournalError::Unknown);
        }
        Ok(())
    };
    for next in [DurableStage::Verified, DurableStage::Committed] {
        keep!(
            validate_materials(),
            "unknown_resume_materials_before_phase",
            &snapshot,
            &prepared,
            &host,
            &lease,
            &effects,
            &held,
            &token
        );
        let original = keep!(
            journal.resync_native_cutover(&maintenance, &transaction),
            "unknown_resume_phase_read",
            &snapshot,
            &prepared,
            &host,
            &lease,
            &effects,
            &held,
            &token
        );
        keep!(
            if original.raw_intent == snapshot.original().raw_intent
                && original.validation_report() == Some(local_raw.as_slice())
                && original.paired_validation_report() == Some(pair_raw.as_slice())
            {
                Ok(())
            } else {
                Err(JournalError::Unknown)
            },
            "unknown_resume_report_changed",
            &snapshot,
            &prepared,
            &host,
            &lease,
            &effects,
            &held,
            &token
        );
        if matches!(
            (original.last_stage, next),
            (DurableStage::Applied, DurableStage::Verified)
                | (DurableStage::Verified, DurableStage::Committed)
        ) {
            keep!(
                journal.append_cutover_phase(&maintenance, &prepared, next),
                "unknown_resume_phase_append",
                &snapshot,
                &prepared,
                &host,
                &lease,
                &effects,
                &held,
                &token
            );
        }
    }
    keep!(
        validate_materials(),
        "unknown_resume_final_materials",
        &snapshot,
        &prepared,
        &host,
        &lease,
        &effects,
        &held,
        &token
    );
    let original = keep!(
        journal.resync_native_cutover(&maintenance, &transaction),
        "unknown_resume_final_chain",
        &snapshot,
        &prepared,
        &host,
        &lease,
        &effects,
        &held,
        &token
    );
    let committed = keep!(
        original
            .phases
            .last()
            .filter(|p| p.stage == DurableStage::Committed)
            .cloned()
            .ok_or(JournalError::Unknown),
        "unknown_resume_not_committed",
        &snapshot,
        &prepared,
        &host,
        &lease,
        &effects,
        &held,
        &token
    );
    let proof = MacResumedCutover {
        owner: &owner,
        maintenance: &maintenance,
        prepared: &prepared,
        committed,
    };
    keep!(
        owner.with_maintenance(&maintenance, |state| {
            // These checks do not reacquire the configuration mutex.
            lease.validate().map_err(|_| JournalError::Unknown)?;
            if let Some(scope) = &app_scope {
                scope.validate().map_err(|_| JournalError::Unknown)?;
            }
            snapshot.revalidate_materials()?;
            effects.validate_retained(&held)?;
            if token.validate_retired_locked()? != *record.post_stamp() {
                return Err(JournalError::Unknown);
            }
            let raw = state
                .root
                .read_raw("state.json", NATIVE_STATE_BYTES)
                .map_err(|_| JournalError::Unknown)?;
            if raw.observation() != canonical.observation() || raw.bytes() != prepared.target() {
                return Err(JournalError::Unknown);
            }
            journal.validate_committed_cutover_locked(state, &prepared, &proof.committed)?;
            let inv = journal.observe_locked(state)?;
            if inv.has_unresolved_legacy_handoffs()
                || inv.high_water != prepared.intent().sequence
                || inv.committed_cutover_anchor
                    != Some((
                        prepared.intent().sequence,
                        prepared.intent().target_state_sha256,
                    ))
            {
                return Err(JournalError::Conflict);
            }
            state.finish_mac_resumed_cutover(&proof, &owner)
        }),
        "unknown_resume_admission",
        &snapshot,
        &prepared,
        &host,
        &lease,
        &effects,
        &held,
        &token
    );
    drop(lease);
    if let Some(sender) = sender.take() {
        let _ = sender.send(MacMigrationObservation {
            transaction_id: transaction,
            stage: "resumed_committed_admission_released",
            local_exec_report: Some(local_raw),
            pair_admission_report: Some(pair_raw),
            rejected_scope: None,
            committed_scope: Some(Box::new(MacMigrationCommittedScope {
                recovery_permit: Some(permit),
                owner: owner.clone(),
                journal,
                candidate: candidate.clone(),
                app_scope,
            })),
        });
    }
}
