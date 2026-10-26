//! Continue the original rename-before-cutover transaction, never an old probe.
//! Only an absent schema4 chain permits the first canonical/probe sequence.
use super::*;
use crate::foreground::profile::read_recovered_pair_materials;
use crate::store::MacRetiredMaterialSource;
use tokio::sync::SemaphorePermit;

pub(in crate::store) fn start_resume_pre_cutover_host_migration(
    runtime: Handle,
    state_dir: PathBuf,
    owner: OwnedConfigurationRoot,
    maintenance: Arc<ConfigurationMaintenance>,
    journal: OwnedManagementJournal,
    candidate: Arc<VerifiedNativeRelease>,
    app_scope: Option<Arc<crate::app::HostScope>>,
    permit: Arc<SemaphorePermit<'static>>,
) -> MacMigrationOwnerTask {
    let (sender, observation) = oneshot::channel();
    let executor = runtime.clone();
    let job = runtime.spawn_blocking(move || {
        executor.block_on(run(
            executor.clone(),
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
    MacMigrationOwnerTask {
        observation,
        observed: false,
        rejected_observed: false,
        committed_scope: None,
        worker_joined: false,
        worker_failed: false,
        _job: job,
    }
}
async fn run(
    runtime: Handle,
    state_dir: PathBuf,
    owner: OwnedConfigurationRoot,
    maintenance: Arc<ConfigurationMaintenance>,
    mut journal: OwnedManagementJournal,
    candidate: Arc<VerifiedNativeRelease>,
    app_scope: Option<Arc<crate::app::HostScope>>,
    permit: Arc<SemaphorePermit<'static>>,
    sender: oneshot::Sender<MacMigrationObservation>,
) {
    let transaction = maintenance.transaction_id().clone();
    let mut sender = Some(sender);
    macro_rules! keep {
        ($result:expr, $stage:literal $(, $held:expr)* $(,)?) => {
            match $result {
                Ok(value) => value,
                Err(_) => retain_scope(
                    (&owner, &maintenance, &journal, &candidate, &app_scope, &permit, $($held,)*),
                    &mut sender,
                    MacMigrationObservation {
                        transaction_id: transaction.clone(), stage: $stage,
                        local_exec_report: None, pair_admission_report: None,
                        rejected_scope: None, committed_scope: None,
                    },
                ).await,
            }
        };
    }
    let saved = keep!(
        journal.resync_native_migration_plan(&maintenance),
        "unknown_original_plan"
    );
    keep!(
        (|| -> JournalResult<()> {
            if !maintenance.matches(&owner)
                || !journal.configuration_root().same_authority(&owner)
                || !saved.complete()
                || saved.retirement.transaction_id != transaction
                || saved.desired.gateway.is_some()
                || !saved.desired.host.as_ref().is_some_and(|host| {
                    host.autostart == NativeAutostartDesired::Disabled
                        && host.manager != NativeManager::PersistentService
                })
            {
                return Err(JournalError::Conflict);
            }
            match (saved.desired.host.as_ref().map(|h| h.manager), &app_scope) {
                (Some(NativeManager::ForegroundCli), None) => {}
                (Some(NativeManager::AppManaged), Some(scope))
                    if scope.state_dir() == state_dir =>
                {
                    scope.validate().map_err(|_| JournalError::Unknown)?;
                }
                _ => return Err(JournalError::Conflict),
            }
            candidate.revalidate().map_err(|_| JournalError::Unknown)?;
            let target = match std::env::consts::ARCH {
                "x86_64" => "x86_64-apple-darwin",
                "aarch64" => "aarch64-apple-darwin",
                _ => return Err(JournalError::Unsupported),
            };
            if candidate.report().target != target
                || candidate
                    .runtime_selection()
                    .map_err(|_| JournalError::Unknown)?
                    != saved.selection
                || candidate.report().manifest_sha256 != saved.retirement.candidate_manifest_sha256
                || candidate.report().publisher_spki_sha256
                    != saved.retirement.publisher_spki_sha256.to_hex()
                || candidate.manifest().scope != NativeReleaseScope::RuntimeCandidate
                || !candidate
                    .manifest()
                    .minimum_reader
                    .supports_host_admission_v2()
                || !candidate
                    .manifest()
                    .minimum_reader
                    .supports_state_reader(ReaderContract::NativeMigratedStateV2)
            {
                return Err(JournalError::Conflict);
            }
            candidate
                .pin_worker(NativeExternalWorker::CodexExec)
                .map_err(|_| JournalError::Unknown)?;
            if !journal.observe()?.orphans.is_empty() {
                return Err(JournalError::Conflict);
            }
            owner.with_maintenance(&maintenance, |state| {
                state
                    .root
                    .ensure_absent(crate::store::native_root::NATIVE_MARKER_FILE)
                    .map_err(|_| JournalError::Conflict)?;
                journal.with_directory_locked(state, |directory| {
                    let scan = files::scan(directory, journal.budget())?;
                    let cutovers = crate::store::management::cutover::scan_cutovers(&scan)?;
                    if !cutovers.records.is_empty() || !cutovers.native_records.is_empty() {
                        return Err(JournalError::Conflict);
                    }
                    Ok(())
                })
            })
        })(),
        "unknown_pre_cutover_scope"
    );
    let root = keep!(PrivateRoot::open(&state_dir), "unknown_original_root");
    let host = keep!(
        (|| -> JournalResult<PrivateRoot> {
            let deployment = root
                .read_raw("deployment.json", NATIVE_STATE_BYTES)
                .map_err(|_| JournalError::Unknown)?;
            if Sha256Digest::of_bytes(deployment.bytes()) != saved.pair.deployment_raw_sha256 {
                return Err(JournalError::Conflict);
            }
            let value: serde_json::Value =
                serde_json::from_slice(deployment.bytes()).map_err(|_| JournalError::Conflict)?;
            if value.get("schema").and_then(|v| v.as_u64()) != Some(1)
                || value.get("mode").and_then(|v| v.as_str()) != Some("join-existing")
            {
                return Err(JournalError::Conflict);
            }
            let path = PathBuf::from(
                value
                    .pointer("/host/baseDir")
                    .and_then(|v| v.as_str())
                    .ok_or(JournalError::Conflict)?,
            );
            let host = PrivateRoot::open(&path).map_err(|_| JournalError::Unknown)?;
            if native_id(host.identity())? != saved.pair.host_root
                || native_id(root.identity())? != saved.pair.config_root
            {
                return Err(JournalError::Conflict);
            }
            Ok(host)
        })(),
        "unknown_original_host",
        &root
    );
    let (effects, held) = keep!(
        MacBootRecoveryEffects::reopen_guards_held(
            owner.clone(),
            maintenance.clone(),
            &root.inner,
            &host.inner,
            &journal
        ),
        "unknown_original_guards",
        &root,
        &host
    );
    keep!(
        if saved.matches_recovery(held.prepared().intent()) {
            Ok(())
        } else {
            Err(JournalError::Conflict)
        },
        "unknown_original_guard_plan",
        &effects,
        &held
    );
    let (prepared, recorded) = keep!(
        journal.reopen_native_retirement(&maintenance, &transaction),
        "unknown_original_retirement",
        &effects,
        &held
    );
    keep!(
        if prepared.intent() == &saved.retirement
            && prepared.raw_intent_sha256() == Sha256Digest::of_bytes(saved.retirement_raw())
        {
            Ok(())
        } else {
            Err(JournalError::Conflict)
        },
        "unknown_original_retirement_plan",
        &effects,
        &held
    );
    let mut token = keep!(
        match &recorded {
            Some(record) => MacTokenRetirement::reopen_recorded_retired(
                &host.inner,
                owner.clone(),
                maintenance.clone(),
                &prepared,
                record
            ),
            None => MacTokenRetirement::reopen_unrecorded_retired(
                &host.inner,
                owner.clone(),
                maintenance.clone(),
                &journal,
                &prepared,
                &effects,
                &held
            ),
        },
        "unknown_observed_token_rename",
        &effects,
        &held
    );
    let retired = match recorded {
        Some(record) => record,
        None => keep!(
            token.record_observed_retirement(&mut journal, &prepared, &effects, &held),
            "unknown_original_retired_receipt",
            &effects,
            &held,
            &token
        ),
    };
    let source = keep!(
        MacRetiredMaterialSource::open(&state_dir, &journal, &saved, &token, &effects, &held),
        "unknown_recovered_material_source",
        &effects,
        &held,
        &token
    );
    let materials = keep!(
        read_recovered_pair_materials(&state_dir, &maintenance, &source),
        "unknown_recovered_materials",
        &effects,
        &held,
        &token,
        &source
    );
    let plan = keep!(
        MacCutoverPlan::capture(&materials, saved.pair.preservation_sha256),
        "unknown_recovered_cutover_plan",
        &effects,
        &held,
        &token,
        &source,
        &materials
    );
    let scopes = keep!(
        scope_bindings(&owner, &maintenance, &journal, &held),
        "unknown_recovered_scope_bindings",
        &effects,
        &held,
        &token,
        &materials
    );
    let owners = keep!(
        crate::store::native_legacy_owners::capture_native_legacy_owners(&root, &state_dir),
        "unknown_recovered_owner_bindings",
        &effects,
        &held,
        &token,
        &materials
    );
    let preservation = keep!(
        saved.preservation.as_ref().ok_or(JournalError::Conflict),
        "unknown_original_preservation",
        &effects,
        &held,
        &token,
        &materials
    );
    let before = keep!(
        saved.before.as_deref().ok_or(JournalError::Conflict),
        "unknown_original_before",
        &effects,
        &held,
        &token,
        &materials
    );
    let inputs = keep!(
        render_target(
            &candidate,
            &saved.retirement,
            &saved.marker,
            retired.record_sha256(),
            &saved.pair,
            preservation.clone(),
            scopes,
            owners,
            before,
            saved.desired.clone()
        ),
        "unknown_recovered_target",
        &effects,
        &held,
        &token,
        &materials
    );
    keep!(
        if inputs.marker == saved.marker_raw()
            && matches!(&inputs.history, NativeCutoverHistoryInputs::PreservedHostPair { bindings }
            if bindings == saved.pair_raw())
        {
            Ok(())
        } else {
            Err(JournalError::Conflict)
        },
        "unknown_recovered_target_bindings",
        &effects,
        &held,
        &token,
        &materials
    );
    let mut applied = keep!(
        plan.prepare(
            owner.clone(),
            &maintenance,
            &mut journal,
            &effects,
            &held,
            &token,
            &host,
            &state_dir,
            inputs,
            candidate.clone()
        ),
        "unknown_original_cutover_prepare",
        &effects,
        &held,
        &token,
        &materials
    );
    keep!(
        applied.apply(&mut journal),
        "unknown_original_cutover_apply",
        &effects,
        &held,
        &token,
        &materials,
        &applied
    );
    finish_applied_migration(
        runtime,
        owner.clone(),
        maintenance.clone(),
        journal,
        candidate.clone(),
        app_scope,
        applied,
        sender,
        Some(permit),
    )
    .await;
}
