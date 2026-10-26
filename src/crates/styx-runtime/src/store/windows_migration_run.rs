//! One original Windows COM worker through reviewed Startup exclusion and,
//! after a genuinely later boot, the actual token/canonical/validation tail.
//! No original writer is reopened and no checkpoint/probe is inferred from DTOs.
use super::*;
use crate::{
    foreground::profile::{OriginalNativePairMaterials, read_original_pair_materials},
    store::{
        management::{
            handoff::{self, RetirementKind},
            migration_plan::MigrationPlanInputs,
        },
        native_migration_inputs::{Preservation, migration_marker, render_target, scope_bindings},
        native_migration_job::{
            NativeMigrationObservation, NativeMigrationOwnerTask, NativeMigrationRejectedScope,
            finish_applied_migration, retain_scope,
        },
        platform::{WindowsCutoverCustody, WindowsCutoverPlan},
    },
};
use styx_contracts::{native_management::*, native_release::NativeExternalWorker};
use styx_core::management::transaction::DurableStage;
use tokio::{runtime::Handle, sync::oneshot};

/// Public review DATA only. Explicit management approval must echo this exact
/// hash; neither this function nor the execution runner approves itself.
pub(in crate::store) struct WindowsRestartMigrationReview {
    pub(in crate::store) raw: Vec<u8>,
    pub(in crate::store) sha256: Sha256Digest,
}

/// A closed review of the WHOLE logical migration. The older schema2 approval
/// still exclusively describes original-owner exclusion and is not rewritten.
/// Generated marker entropy / guard nonces are deliberately NOT review inputs.
#[derive(serde::Serialize)]
#[serde(deny_unknown_fields)]
struct MigrationReviewEnvelope<'a> {
    schema: u16,
    action: &'static str,
    transaction_id: &'a TransactionId,
    config_root: &'a NativeRootIdentity,
    host_root: &'a NativeRootIdentity,
    deployment_raw_sha256: Sha256Digest,
    before_state_sha256: Sha256Digest,
    original_token: &'a NativeRetirementFileStamp,
    preservation_sha256: Sha256Digest,
    selected_materials_sha256: Sha256Digest,
    host_pair_sha256: Sha256Digest,
    candidate_manifest_sha256: Sha256Digest,
    publisher_spki_sha256: Sha256Digest,
    runtime_selection_sha256: Sha256Digest,
    desired: NativeDesired,
    original_maintenance_plan_sha256: Sha256Digest,
}
fn migration_review(
    intent: &NativeRetirementIntent,
    durable: &MigrationPlanInputs,
    original_maintenance_plan_sha256: Sha256Digest,
) -> JournalResult<WindowsRestartMigrationReview> {
    if durable.retirement != serde_json::to_vec(intent).map_err(failed)? {
        return Err(JournalError::Conflict);
    }
    let desired = serde_json::from_slice(&durable.desired).map_err(failed)?;
    let envelope = MigrationReviewEnvelope {
        schema: 1,
        action: "migrate_windows_preserved_host_pair_after_restart",
        transaction_id: &intent.transaction_id,
        config_root: &intent.config_root,
        host_root: &intent.host_root,
        deployment_raw_sha256: intent.deployment_raw_sha256,
        before_state_sha256: intent.before_state_sha256,
        original_token: &intent.original_token,
        preservation_sha256: Sha256Digest::of_bytes(&durable.preservation),
        selected_materials_sha256: Sha256Digest::of_bytes(&durable.selected),
        host_pair_sha256: Sha256Digest::of_bytes(&durable.host_pair),
        candidate_manifest_sha256: intent.candidate_manifest_sha256,
        publisher_spki_sha256: intent.publisher_spki_sha256,
        runtime_selection_sha256: Sha256Digest::of_bytes(&durable.runtime_selection),
        desired,
        original_maintenance_plan_sha256,
    };
    let raw = serde_json::to_vec(&envelope).map_err(failed)?;
    let sha256 = Sha256Digest::of_bytes(&raw);
    Ok(WindowsRestartMigrationReview { raw, sha256 })
}
fn require_review_approval(
    review: &WindowsRestartMigrationReview,
    approved: Sha256Digest,
) -> JournalResult<()> {
    if review.sha256 != approved || Sha256Digest::of_bytes(&review.raw) != approved {
        return Err(JournalError::Conflict);
    }
    Ok(())
}

struct InitialInputs<'m> {
    root: PrivateRoot,
    host: PrivateRoot,
    materials: OriginalNativePairMaterials<'m>,
    observation: WindowsLegacyObservation,
    checkpoint: WindowsMigrationCheckpointPlan,
    intent: NativeRetirementIntent,
    durable: MigrationPlanInputs,
}
/// Call on the original blocking worker. This captures genuine Shell/COM/kernel
/// observations and drops them on this same thread; it creates NO journal file.
pub(in crate::store) fn review_windows_restart_host_migration(
    state_dir: &Path,
    owner: &OwnedConfigurationRoot,
    maintenance: &ConfigurationMaintenance,
    journal: &OwnedManagementJournal,
    candidate: &VerifiedNativeRelease,
    desired: &NativeDesired,
    app_scope: Option<&crate::app::HostScope>,
) -> JournalResult<WindowsRestartMigrationReview> {
    let inputs = capture_initial(
        state_dir,
        owner,
        maintenance,
        journal,
        candidate,
        desired,
        app_scope,
    )?;
    migration_review(
        &inputs.intent,
        &inputs.durable,
        inputs.checkpoint.plan_sha256(),
    )
}
fn capture_initial<'m>(
    state_dir: &Path,
    owner: &OwnedConfigurationRoot,
    maintenance: &'m ConfigurationMaintenance,
    journal: &OwnedManagementJournal,
    candidate: &VerifiedNativeRelease,
    desired: &NativeDesired,
    app_scope: Option<&crate::app::HostScope>,
) -> JournalResult<InitialInputs<'m>> {
    validate_requested_manager(desired, state_dir, app_scope)?;
    if !maintenance.matches(owner) || !journal.configuration_root().same_authority(owner) {
        return Err(JournalError::Conflict);
    }
    let root = PrivateRoot::open(state_dir).map_err(failed)?;
    owner.with_maintenance(maintenance, |state| {
        if state.root.identity() != root.identity() {
            return Err(JournalError::Conflict);
        }
        Ok(())
    })?;
    let host = original_host(&root)?;
    let descriptor_raw = host.read_raw("service.json", 32768).map_err(failed)?;
    let descriptor: WindowsServiceDescriptor =
        serde_json::from_slice(descriptor_raw.bytes()).map_err(failed)?;
    let observation =
        WindowsLegacyObservation::capture_foreground_only(&descriptor.task_name).map_err(failed)?;
    let materials = read_original_pair_materials(state_dir, maintenance).map_err(failed)?;
    if !materials.executor_configured() {
        return Err(JournalError::Unsupported);
    }
    let before = root.read_raw("state.json", 1024 * 1024).map_err(failed)?;
    handoff::reject_migration_v2_collision(before.bytes())?;
    let preservation = Preservation::capture(&materials)?;
    let preservation_raw = serde_json::to_vec(&preservation.rows).map_err(failed)?;
    let selected = serde_json::to_vec(materials.preservation_entries()).map_err(failed)?;
    let pair = materials
        .pair_binding(Sha256Digest::of_bytes(&preservation_raw))
        .map_err(failed)?;
    let publisher = materials.publisher_sha256().map_err(failed)?;
    validate_candidate(candidate, publisher)?;
    if pair.config_root != root_native(root.identity())?
        || pair.host_root != root_native(host.identity())?
    {
        return Err(JournalError::Conflict);
    }
    let inventory = journal.observe()?;
    if !inventory.orphans.is_empty()
        || inventory.has_legacy_handoffs()
        || !inventory.owner_recoveries.is_empty()
        || !inventory.migration_plans.is_empty()
        || inventory.transactions.iter().any(|t| {
            t.phase_receipts
                .last()
                .is_none_or(|p| p.stage != DurableStage::Committed)
        })
    {
        return Err(JournalError::Conflict);
    }
    let sequence = inventory
        .high_water
        .checked_add(1)
        .ok_or(JournalError::BudgetExceeded)?;
    let token_raw = host.read_raw("device/host.token", 4096).map_err(failed)?;
    // READ-only here: opening the retirement WRITE/DELETE handle would exclude
    // the original profile's ordinary token reads during checkpoint capture.
    let pin = ffi::open(
        &host.inner.path.join("device/host.token"),
        false,
        false,
        false,
    )
    .map_err(failed)?;
    if read_pin(&pin, token_raw.bytes())? != *token_raw.observation() {
        return Err(JournalError::Conflict);
    }
    let original_token = native_stamp(&pin, token_raw.bytes())?;
    drop(pin);
    let intent = NativeRetirementIntent {
        schema: 3,
        kind: RetirementKind::LegacyCredentialRetirement,
        transaction_id: maintenance.transaction_id().clone(),
        sequence,
        config_root: pair.config_root.clone(),
        host_root: pair.host_root.clone(),
        deployment_raw_sha256: pair.deployment_raw_sha256,
        before_state_sha256: Sha256Digest::of_bytes(before.bytes()),
        preservation_sha256: Sha256Digest::of_bytes(&selected),
        service_descriptor_sha256: Sha256Digest::of_bytes(descriptor_raw.bytes()),
        candidate_manifest_sha256: candidate.report().manifest_sha256,
        publisher_spki_sha256: publisher,
        original_token,
    };
    let checkpoint = WindowsMigrationCheckpointPlan::capture(
        owner,
        maintenance,
        &host,
        &observation,
        candidate,
        &intent,
        &materials,
    )?;
    let recovery = checkpoint.owner_recovery_inputs()?;
    let marker = migration_marker(&intent)?;
    let durable = MigrationPlanInputs {
        retirement: serde_json::to_vec(&intent).map_err(failed)?,
        host_pair: serde_json::to_vec(&pair).map_err(failed)?,
        desired: serde_json::to_vec(desired).map_err(failed)?,
        marker: serde_json::to_vec(&marker).map_err(failed)?,
        runtime_selection: serde_json::to_vec(&candidate.runtime_selection().map_err(failed)?)
            .map_err(failed)?,
        owner_recovery: Some(serde_json::to_vec(&recovery).map_err(failed)?),
        before: before.bytes().to_vec(),
        preservation: preservation_raw,
        selected,
    };
    preservation.validate_original()?;
    materials.revalidate().map_err(failed)?;
    Ok(InitialInputs {
        root,
        host,
        materials,
        observation,
        checkpoint,
        intent,
        durable,
    })
}
fn original_host(root: &PrivateRoot) -> JournalResult<PrivateRoot> {
    let raw = root
        .read_raw("deployment.json", 1024 * 1024)
        .map_err(failed)?;
    let config: serde_json::Value = serde_json::from_slice(raw.bytes()).map_err(failed)?;
    if config.get("schema").and_then(|v| v.as_u64()) != Some(1)
        || config.get("mode").and_then(|v| v.as_str()) != Some("join-existing")
    {
        return Err(JournalError::Unsupported);
    }
    let path = Path::new(
        config
            .pointer("/host/baseDir")
            .and_then(|v| v.as_str())
            .ok_or(JournalError::Conflict)?,
    );
    if !path.is_absolute() {
        return Err(JournalError::Conflict);
    }
    PrivateRoot::open(path).map_err(failed)
}
fn validate_candidate(
    candidate: &VerifiedNativeRelease,
    publisher: Sha256Digest,
) -> JournalResult<()> {
    candidate_matches(candidate, candidate.report().manifest_sha256, publisher)?;
    if !candidate
        .manifest()
        .minimum_reader
        .supports_host_admission_v2()
        || !candidate
            .manifest()
            .worker_closures
            .iter()
            .any(|w| w.kind == NativeExternalWorker::CodexExec)
    {
        return Err(JournalError::Unsupported);
    }
    Ok(())
}
fn observation(transaction: &TransactionId, stage: &'static str) -> NativeMigrationObservation {
    NativeMigrationObservation {
        transaction_id: transaction.clone(),
        stage,
        local_exec_report: None,
        pair_admission_report: None,
        rejected_scope: None,
        committed_scope: None,
    }
}
/// Inputs and approval are already admitted by the existing management caller.
/// COM is created INSIDE this actual non-abortable worker, never moved into it.
pub(in crate::store) fn start_windows_restart_host_migration(
    runtime: Handle,
    state_dir: PathBuf,
    owner: OwnedConfigurationRoot,
    maintenance: ConfigurationMaintenance,
    journal: OwnedManagementJournal,
    candidate: Arc<VerifiedNativeRelease>,
    desired: NativeDesired,
    app_scope: Option<Arc<crate::app::HostScope>>,
    permit: Arc<tokio::sync::SemaphorePermit<'static>>,
    approved_plan_sha256: Sha256Digest,
) -> NativeMigrationOwnerTask {
    let (sender, receiver) = oneshot::channel();
    let executor = runtime.clone();
    let job = runtime.spawn_blocking(move || {
        executor.block_on(async move {
            let maintenance = Arc::new(maintenance);
            let transaction = maintenance.transaction_id().clone();
            let mut sender = Some(sender);
            let inputs = match capture_initial(
                &state_dir,
                &owner,
                &maintenance,
                &journal,
                &candidate,
                &desired,
                app_scope.as_deref(),
            ) {
                Ok(inputs) => inputs,
                Err(_) => {
                    let mut result =
                        observation(&transaction, "windows_migration_preflight_rejected");
                    result.rejected_scope = Some(Box::new(NativeMigrationRejectedScope {
                        permit,
                        app_scope,
                        owner,
                        maintenance: maintenance.clone(),
                        journal,
                        candidate,
                    }));
                    if let Some(sender) = sender.take() {
                        let _ = sender.send(result);
                    }
                    return;
                }
            };
            let approved = migration_review(
                &inputs.intent,
                &inputs.durable,
                inputs.checkpoint.plan_sha256(),
            )
            .and_then(|review| require_review_approval(&review, approved_plan_sha256));
            if approved.is_err() {
                drop(inputs);
                let mut result = observation(&transaction, "windows_migration_review_mismatch");
                result.rejected_scope = Some(Box::new(NativeMigrationRejectedScope {
                    permit,
                    app_scope,
                    owner,
                    maintenance: maintenance.clone(),
                    journal,
                    candidate,
                }));
                if let Some(sender) = sender.take() {
                    let _ = sender.send(result);
                }
                return;
            }
            let original_maintenance_sha256 = inputs.checkpoint.plan_sha256();
            let InitialInputs {
                root,
                host,
                materials,
                observation: os,
                checkpoint,
                intent,
                durable,
            } = inputs;
            let mut journal = journal;
            if journal
                .persist_native_migration_plan(&maintenance, &durable)
                .is_err()
            {
                retain_scope(
                    (
                        &owner,
                        &maintenance,
                        &journal,
                        &candidate,
                        &app_scope,
                        &permit,
                        &root,
                        &host,
                        &materials,
                        &os,
                        &checkpoint,
                        &durable,
                    ),
                    &mut sender,
                    observation(&transaction, "unknown_windows_pre_effect_plan"),
                )
                .await;
            }
            let job = WindowsMigrationCheckpointJob::new(
                checkpoint,
                &mut journal,
                &owner,
                &maintenance,
                &os,
                &candidate,
                &intent,
                &host,
                &materials,
                app_scope.as_deref(),
            );
            let mut checkpoint_job = match job {
                Ok(job) => job,
                Err(_) => {
                    retain_scope(
                        (
                            &owner,
                            &maintenance,
                            &candidate,
                            &app_scope,
                            &permit,
                            &root,
                            &host,
                            &materials,
                            &os,
                            &durable,
                        ),
                        &mut sender,
                        observation(&transaction, "unknown_windows_checkpoint_binding"),
                    )
                    .await
                }
            };
            if checkpoint_job
                .prepare_and_exclude(original_maintenance_sha256)
                .is_err()
            {
                retain_scope(
                    (
                        &checkpoint_job,
                        &owner,
                        &maintenance,
                        &candidate,
                        &app_scope,
                        &permit,
                        &root,
                        &host,
                        &materials,
                        &os,
                        &durable,
                    ),
                    &mut sender,
                    observation(&transaction, "unknown_windows_checkpoint_exclusion"),
                )
                .await;
            }
            // The checkpoint's exclusion was actually recorded on THIS boot.
            // A user reboot that preceded it cannot be retrofitted into proof.
            retain_scope(
                (
                    &checkpoint_job,
                    &owner,
                    &maintenance,
                    &candidate,
                    &app_scope,
                    &permit,
                    &root,
                    &host,
                    &materials,
                    &os,
                    &durable,
                ),
                &mut sender,
                observation(&transaction, "waiting_for_later_boot"),
            )
            .await;
        });
    });
    NativeMigrationOwnerTask::from_job(receiver, job)
}

pub(in crate::store) fn start_resume_windows_restart_host_migration(
    runtime: Handle,
    state_dir: PathBuf,
    owner: OwnedConfigurationRoot,
    maintenance: ConfigurationMaintenance,
    journal: OwnedManagementJournal,
    candidate: Arc<VerifiedNativeRelease>,
    app_scope: Option<Arc<crate::app::HostScope>>,
    permit: Arc<tokio::sync::SemaphorePermit<'static>>,
) -> NativeMigrationOwnerTask {
    let (sender, receiver) = oneshot::channel();
    let executor = runtime.clone();
    let job = runtime.spawn_blocking(move || {
        executor.block_on(run_resume(
            executor.clone(),
            state_dir,
            owner,
            maintenance,
            journal,
            candidate,
            app_scope,
            permit,
            sender,
        ))
    });
    NativeMigrationOwnerTask::from_job(receiver, job)
}
async fn run_resume(
    runtime: Handle,
    state_dir: PathBuf,
    owner: OwnedConfigurationRoot,
    maintenance: ConfigurationMaintenance,
    mut journal: OwnedManagementJournal,
    candidate: Arc<VerifiedNativeRelease>,
    app_scope: Option<Arc<crate::app::HostScope>>,
    permit: Arc<tokio::sync::SemaphorePermit<'static>>,
    sender: oneshot::Sender<NativeMigrationObservation>,
) {
    let transaction = maintenance.transaction_id().clone();
    let mut sender = Some(sender);
    macro_rules! keep {($result:expr,$stage:literal $(,$held:expr)* $(,)?)=>{
        match $result {Ok(value)=>value,Err(_)=>retain_scope((&owner,&journal,&candidate,&app_scope,&permit,$($held,)*),&mut sender,observation(&transaction,$stage)).await}
    };}
    let root = keep!(
        PrivateRoot::open(&state_dir),
        "unknown_windows_resume_root",
        &maintenance
    );
    keep!(
        owner.with_maintenance(&maintenance, |state| {
            if state.root.identity() != root.identity() {
                return Err(JournalError::Conflict);
            }
            Ok(())
        }),
        "unknown_windows_resume_owner",
        &maintenance,
        &root
    );
    let saved = keep!(
        journal.resync_native_migration_plan(&maintenance),
        "unknown_windows_original_plan",
        &maintenance,
        &root
    );
    keep!(
        validate_requested_manager(&saved.desired, &state_dir, app_scope.as_deref()),
        "unknown_windows_resume_manager",
        &maintenance,
        &root,
        &saved
    );
    let inventory = keep!(
        journal.observe(),
        "unknown_windows_resume_inventory",
        &maintenance,
        &root,
        &saved
    );
    // This route is ONLY before the first token attempt. An existing cutover or
    // credential stage requires its original dedicated reconciliation consumer,
    // never another validation attempt or a fallback to the fresh constructor.
    keep!(
        if inventory.committed_cutover_anchor.is_none()
            && inventory.handoffs.is_empty()
            && inventory.orphans.is_empty()
        {
            Ok(())
        } else {
            Err(JournalError::Conflict)
        },
        "windows_existing_attempt_requires_recovery",
        &maintenance,
        &root,
        &saved
    );
    let host = keep!(
        original_host(&root),
        "unknown_windows_resume_host",
        &maintenance,
        &root,
        &saved
    );
    let service = keep!(
        host.read_raw("service.json", 32768),
        "unknown_windows_resume_descriptor",
        &maintenance,
        &root,
        &saved,
        &host
    );
    let descriptor: WindowsServiceDescriptor = keep!(
        serde_json::from_slice(service.bytes()),
        "unknown_windows_resume_descriptor_format",
        &maintenance,
        &root,
        &saved,
        &host
    );
    let os = keep!(
        WindowsLegacyObservation::capture_foreground_only(&descriptor.task_name),
        "unknown_windows_resume_native_observation",
        &maintenance,
        &root,
        &saved,
        &host
    );
    keep!(
        validate_candidate(&candidate, saved.retirement.publisher_spki_sha256),
        "unknown_windows_resume_candidate",
        &maintenance,
        &root,
        &saved,
        &host,
        &os
    );
    let resumed = resume_recorded_windows_checkpoint(
        &mut journal,
        owner.clone(),
        maintenance,
        &os,
        &candidate,
        &host,
        &saved.retirement,
        app_scope.clone(),
    );
    let guarded = match resumed {
        Ok(WindowsMigrationCheckpointResume::GuardsHeld(guarded)) => guarded,
        Ok(WindowsMigrationCheckpointResume::WaitingForLaterBoot(waiting)) => {
            retain_scope(
                (
                    &owner, &journal, &candidate, &app_scope, &permit, &root, &host, &os, &saved,
                    waiting,
                ),
                &mut sender,
                observation(&transaction, "waiting_for_later_boot"),
            )
            .await
        }
        Err(failure) => {
            retain_scope(
                (
                    &owner, &journal, &candidate, &app_scope, &permit, &root, &host, &os, &saved,
                    failure,
                ),
                &mut sender,
                observation(&transaction, "unknown_windows_restart_reconciliation"),
            )
            .await
        }
    };
    let effects = &guarded.effects;
    let held = &guarded.held;
    let maintenance = effects.maintenance();
    keep!(
        effects.validate_cutover_custody(&owner, held, &os),
        "unknown_windows_actual_guards",
        &guarded,
        &root,
        &host,
        &os,
        &saved
    );
    let materials = keep!(
        read_original_pair_materials(&state_dir, maintenance),
        "unknown_windows_original_materials",
        &guarded,
        &root,
        &host,
        &os,
        &saved
    );
    let preservation = keep!(
        Preservation::capture(&materials),
        "unknown_windows_preservation",
        &guarded,
        &root,
        &host,
        &os,
        &saved,
        &materials
    );
    let preservation_raw = keep!(
        serde_json::to_vec(&preservation.rows),
        "unknown_windows_preservation_encoding",
        &guarded,
        &materials,
        &preservation
    );
    let selected = keep!(
        serde_json::to_vec(materials.preservation_entries()),
        "unknown_windows_selected_encoding",
        &guarded,
        &materials,
        &preservation
    );
    let before = keep!(
        root.read_raw("state.json", 1024 * 1024),
        "unknown_windows_before",
        &guarded,
        &materials,
        &preservation
    );
    let pair = keep!(
        materials.pair_binding(Sha256Digest::of_bytes(&preservation_raw)),
        "unknown_windows_pair_binding",
        &guarded,
        &materials,
        &preservation
    );
    keep!(
        (|| -> JournalResult<()> {
            if saved.preservation.as_deref() == Some(preservation_raw.as_slice())
                && saved.selected.as_deref() == Some(selected.as_slice())
                && saved.before.as_deref() == Some(before.bytes())
                && saved.pair == pair
                && saved.selection == candidate.runtime_selection().map_err(failed)?
            {
                Ok(())
            } else {
                Err(JournalError::Conflict)
            }
        })(),
        "unknown_windows_saved_materials_changed",
        &guarded,
        &materials,
        &preservation
    );
    let plan = keep!(
        WindowsCutoverPlan::capture(&materials, Sha256Digest::of_bytes(&preservation_raw)),
        "unknown_windows_cutover_capture",
        &guarded,
        &materials,
        &preservation
    );
    let scopes = keep!(
        scope_bindings(&owner, maintenance, &journal, held),
        "unknown_windows_scope_bindings",
        &guarded,
        &materials,
        &preservation,
        &plan
    );
    let owners = keep!(
        crate::store::native_legacy_owners::capture_native_legacy_owners(&root, &state_dir),
        "unknown_windows_owner_bindings",
        &guarded,
        &materials,
        &preservation,
        &plan
    );
    let raw_token = keep!(
        host.read_raw("device/host.token", 4096),
        "unknown_windows_token_source",
        &guarded,
        &materials,
        &preservation,
        &plan
    );
    keep!(
        materials.revalidate(),
        "unknown_windows_materials_before_token",
        &guarded,
        &materials,
        &preservation,
        &plan
    );
    keep!(
        preservation.validate_original(),
        "unknown_windows_preservation_before_token",
        &guarded,
        &materials,
        &preservation,
        &plan
    );
    let mut token = keep!(
        host.inner
            .prepare_token_retirement(&transaction, &raw_token),
        "unknown_windows_token_pin",
        &guarded,
        &materials,
        &preservation,
        &plan
    );
    keep!(
        if token.original_stamp() == &saved.retirement.original_token {
            Ok(())
        } else {
            Err(JournalError::Conflict)
        },
        "unknown_windows_original_token_changed",
        &guarded,
        &materials,
        &preservation,
        &plan,
        &token
    );
    let sizing = keep!(
        render_target(
            &candidate,
            &saved.retirement,
            &saved.marker,
            Sha256Digest::from_bytes([0; 32]),
            &pair,
            preservation_raw.clone(),
            scopes.clone(),
            owners.clone(),
            before.bytes(),
            saved.desired.clone()
        ),
        "unknown_windows_future_target_size",
        &guarded,
        &materials,
        &preservation,
        &plan,
        &token
    );
    keep!(
        journal.preflight_host_cutover_capacity(maintenance, &sizing),
        "unknown_windows_future_cutover_budget",
        &guarded,
        &materials,
        &preservation,
        &plan,
        &token
    );
    let expected_len = sizing.target.len();
    drop(sizing);
    let retirement = keep!(
        journal.prepare_native_credential_retirement(maintenance, &saved.retirement),
        "unknown_windows_retirement_prepared",
        &guarded,
        &materials,
        &preservation,
        &plan,
        &token
    );
    let retired = keep!(
        token.retire_and_record(&mut journal, &owner, maintenance, &retirement, &candidate),
        "unknown_windows_token_retirement",
        &guarded,
        &materials,
        &preservation,
        &plan,
        &token,
        &retirement
    );
    let inputs = keep!(
        render_target(
            &candidate,
            &saved.retirement,
            &saved.marker,
            retired.record_sha256(),
            &pair,
            preservation_raw,
            scopes,
            owners,
            before.bytes(),
            saved.desired.clone()
        ),
        "unknown_windows_target_render",
        &guarded,
        &materials,
        &preservation,
        &plan,
        &token,
        &retirement,
        &retired
    );
    keep!(
        if inputs.target.len() == expected_len {
            Ok(())
        } else {
            Err(JournalError::Unknown)
        },
        "unknown_windows_target_size_changed",
        &guarded,
        &materials,
        &preservation,
        &plan,
        &token,
        &retirement,
        &retired
    );
    let custody = WindowsCutoverCustody::new(owner.clone(), effects, held, &os, &token, &host);
    let mut applied = keep!(
        plan.prepare(custody, &mut journal, &state_dir, inputs, candidate.clone()),
        "unknown_windows_cutover_prepared",
        &guarded,
        &materials,
        &preservation,
        &plan,
        &token,
        &retirement,
        &retired
    );
    keep!(
        applied.apply(&mut journal),
        "unknown_windows_canonical_or_applied",
        &guarded,
        &materials,
        &preservation,
        &plan,
        &token,
        &retirement,
        &retired,
        &applied
    );
    finish_applied_migration(
        runtime,
        owner.clone(),
        maintenance,
        journal,
        candidate.clone(),
        app_scope,
        applied,
        sender,
        Some(permit),
    )
    .await;
    // guarded/materials/token/original COM remain in THIS frame while the shared
    // tail borrows them. A dropped observer does not terminate this actual job.
}

#[cfg(test)]
mod review_tests {
    use super::*;
    // Codec/admission binding only: these are explicit synthetic DATA, not an
    // original process, a Windows filesystem proof, or an execution acceptance.
    fn fixture() -> (NativeRetirementIntent, MigrationPlanInputs, Sha256Digest) {
        let root = NativeRootIdentity::Windows {
            volume_serial: 1,
            file_id: 2,
            owner_sid: "S-1-5-21-1".into(),
        };
        let stamp = NativeRetirementFileStamp::Windows {
            volume_serial: 1,
            file_id: 3,
            owner_sid: "S-1-5-21-1".into(),
            nlink: 1,
            byte_len: 40,
            modified_seconds: 1,
            modified_nanoseconds: 0,
            changed_seconds: 1,
            changed_nanoseconds: 0,
            sha256: Sha256Digest::of_bytes(b"synthetic original token hash input"),
        };
        let intent = NativeRetirementIntent {
            schema: 3,
            kind: RetirementKind::LegacyCredentialRetirement,
            transaction_id: TransactionId::try_from("10000000-0000-4000-8000-000000000001")
                .unwrap(),
            sequence: 1,
            config_root: root.clone(),
            host_root: root,
            deployment_raw_sha256: Sha256Digest::of_bytes(b"deployment"),
            before_state_sha256: Sha256Digest::of_bytes(b"before"),
            preservation_sha256: Sha256Digest::of_bytes(b"selected"),
            service_descriptor_sha256: Sha256Digest::of_bytes(b"descriptor"),
            candidate_manifest_sha256: Sha256Digest::of_bytes(b"candidate"),
            publisher_spki_sha256: Sha256Digest::of_bytes(b"publisher"),
            original_token: stamp,
        };
        let desired = NativeDesired {
            gateway: None,
            host: Some(NativeComponentDesired {
                manager: NativeManager::ForegroundCli,
                run: NativeRunDesired::Running,
                autostart: NativeAutostartDesired::Disabled,
            }),
        };
        let durable = MigrationPlanInputs {
            retirement: serde_json::to_vec(&intent).unwrap(),
            host_pair: b"pair".to_vec(),
            desired: serde_json::to_vec(&desired).unwrap(),
            marker: b"fresh entropy not approved bytes".to_vec(),
            runtime_selection: b"selection".to_vec(),
            owner_recovery: None,
            before: b"before".to_vec(),
            preservation: b"preservation".to_vec(),
            selected: b"selected".to_vec(),
        };
        (
            intent,
            durable,
            Sha256Digest::of_bytes(b"unchanged original checkpoint plan"),
        )
    }
    #[test]
    fn whole_migration_review_rejects_substituted_desired_candidate_root_and_source() {
        let (intent, mut durable, maintenance_hash) = fixture();
        let original = migration_review(&intent, &durable, maintenance_hash).unwrap();
        let approved = original.sha256;
        require_review_approval(&original, approved).unwrap();
        let data: serde_json::Value = serde_json::from_slice(&original.raw).unwrap();
        assert_eq!(data["desired"]["host"]["run"], "running");
        // The original schema2 checkpoint hash stays identical across ALL these
        // substitutions. It alone could not have rejected this real bug.
        let mut desired: NativeDesired = serde_json::from_slice(&durable.desired).unwrap();
        desired.host.as_mut().unwrap().run = NativeRunDesired::Stopped;
        durable.desired = serde_json::to_vec(&desired).unwrap();
        assert!(
            require_review_approval(
                &migration_review(&intent, &durable, maintenance_hash).unwrap(),
                approved
            )
            .is_err()
        );
        let (mut intent, mut durable, maintenance_hash) = fixture();
        intent.candidate_manifest_sha256 = Sha256Digest::of_bytes(b"different signed candidate");
        durable.retirement = serde_json::to_vec(&intent).unwrap();
        assert!(
            require_review_approval(
                &migration_review(&intent, &durable, maintenance_hash).unwrap(),
                approved
            )
            .is_err()
        );
        let (mut intent, mut durable, maintenance_hash) = fixture();
        let NativeRootIdentity::Windows { file_id, .. } = &mut intent.config_root else {
            panic!("fixture")
        };
        *file_id += 1;
        durable.retirement = serde_json::to_vec(&intent).unwrap();
        assert!(
            require_review_approval(
                &migration_review(&intent, &durable, maintenance_hash).unwrap(),
                approved
            )
            .is_err()
        );
        let (intent, mut durable, maintenance_hash) = fixture();
        durable.runtime_selection = b"different payload root".to_vec();
        assert!(
            require_review_approval(
                &migration_review(&intent, &durable, maintenance_hash).unwrap(),
                approved
            )
            .is_err()
        );
        let (intent, durable, maintenance_hash) = fixture();
        assert!(
            require_review_approval(
                &migration_review(
                    &intent,
                    &durable,
                    Sha256Digest::of_bytes(b"changed startup source")
                )
                .unwrap(),
                approved
            )
            .is_err()
        );
        let (mut intent, mut durable, maintenance_hash) = fixture();
        intent.transaction_id =
            TransactionId::try_from("10000000-0000-4000-8000-000000000002").unwrap();
        durable.retirement = serde_json::to_vec(&intent).unwrap();
        assert!(
            require_review_approval(
                &migration_review(&intent, &durable, maintenance_hash).unwrap(),
                approved
            )
            .is_err()
        );
        let (mut intent, mut durable, maintenance_hash) = fixture();
        let NativeRetirementFileStamp::Windows { file_id, .. } = &mut intent.original_token else {
            panic!("fixture")
        };
        *file_id += 1;
        durable.retirement = serde_json::to_vec(&intent).unwrap();
        assert!(
            require_review_approval(
                &migration_review(&intent, &durable, maintenance_hash).unwrap(),
                approved
            )
            .is_err()
        );
        let (intent, durable, maintenance_hash) = fixture();
        // New entropy generated during the second capture is not a changed
        // logical plan. Approval must remain usable for the exact same inputs.
        let mut later = durable;
        later.marker = b"new entropy".to_vec();
        later.owner_recovery = Some(b"new guard nonce".to_vec());
        require_review_approval(
            &migration_review(&intent, &later, maintenance_hash).unwrap(),
            approved,
        )
        .unwrap();
    }
}
