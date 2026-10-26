//! One original-owner Darwin migration through actual validation and commit.
//! Source plan is durable before effects; interrupted recovery consumer is still internal work.
use super::*;
pub(in crate::store) use crate::store::native_migration_job::{
    NativeMigrationCommittedScope as MacMigrationCommittedScope,
    NativeMigrationObservation as MacMigrationObservation,
    NativeMigrationOwnerTask as MacMigrationOwnerTask,
    NativeMigrationRejectedScope as MacMigrationRejectedScope,
};
use crate::store::native_migration_job::{finish_applied_migration, retain_scope};
use crate::{
    foreground::profile::read_original_pair_materials,
    release::VerifiedNativeRelease,
    store::{
        configuration::{ConfigurationMaintenance, OwnedConfigurationRoot},
        management::{
            OwnedManagementJournal,
            handoff::{self, NativeRetirementIntent, RetirementKind},
            migration_plan::MigrationPlanInputs,
        },
        native_migration_inputs::{Preservation, migration_marker, render_target, scope_bindings},
        secure_journal::{JournalError, JournalResult, files},
    },
};
use styx_contracts::{
    identity::{Sha256Digest, TransactionId},
    management::ReaderContract,
    native_management::*,
    native_release::{NativeExternalWorker, NativeReleaseScope},
};
use styx_core::management::transaction::DurableStage;
use tokio::{runtime::Handle, sync::oneshot};

/// Moves only already-acquired ORIGINAL capabilities into one owned task.
/// No writer/journal is acquired by path here; no caller command/token is read.
/// `desired` is an explicit local plan; unsupported service/autostart is refused.
/// Supports previous-boot foreground ownership recovery and preserves the
/// explicit manager. Normal completion uses real validation before commit;
/// Unknown retains the original transaction without replay. This is not a
/// declaration of complete platform acceptance.
pub(in crate::store) fn start_previous_boot_host_migration(
    runtime: Handle,
    state_dir: PathBuf,
    owner: OwnedConfigurationRoot,
    maintenance: Arc<ConfigurationMaintenance>,
    journal: OwnedManagementJournal,
    candidate: Arc<VerifiedNativeRelease>,
    desired: NativeDesired,
    app_scope: Option<Arc<crate::app::HostScope>>,
    permit: Arc<tokio::sync::SemaphorePermit<'static>>,
) -> MacMigrationOwnerTask {
    let (sender, observation) = oneshot::channel();
    let executor = runtime.clone();
    // A started Tokio blocking job cannot be aborted by dropping its observer.
    // Construct all borrowed profile/guard values INSIDE this same job. No
    // borrowed guard is sent to another 'static task and no mem::forget is used.
    let job = runtime.spawn_blocking(move || {
        let _permit = permit.clone();
        executor.block_on(run_original_scope(
            executor.clone(),
            state_dir,
            owner,
            maintenance,
            journal,
            candidate,
            desired,
            app_scope,
            sender,
            permit,
        ));
    });
    MacMigrationOwnerTask::from_job(observation, job)
}
async fn run_original_scope(
    runtime: Handle,
    state_dir: PathBuf,
    owner: OwnedConfigurationRoot,
    maintenance: Arc<ConfigurationMaintenance>,
    mut journal: OwnedManagementJournal,
    candidate: Arc<VerifiedNativeRelease>,
    desired: NativeDesired,
    app_scope: Option<Arc<crate::app::HostScope>>,
    sender: oneshot::Sender<MacMigrationObservation>,
    permit: Arc<tokio::sync::SemaphorePermit<'static>>,
) {
    let transaction = maintenance.transaction_id().clone();
    let mut sender = Some(sender);
    // Every failed stage keeps all values which can already own effects. A
    // returned error from bootstrap is never treated as a nonexistent child.
    macro_rules! keep {
        ($result:expr, $stage:literal $(, $held:expr)* $(,)?) => {
            match $result {
                Ok(value) => value,
                Err(_) => retain_scope((&owner, &maintenance, &journal, &candidate, &app_scope, &permit, $($held,)*), &mut sender,
                    MacMigrationObservation { transaction_id: transaction.clone(), stage: $stage, local_exec_report: None, pair_admission_report: None, rejected_scope: None, committed_scope: None }).await,
            }
        };
    }
    macro_rules! pre {
        ($result:expr, $stage:literal $(, $held:expr)* $(,)?) => {
            match $result {
                Ok(value) => value,
                Err(_) => {
                    // No C/retirement/canonical/probe operation has been called.
                    // Transfer actual original capabilities back, do not park.
                    let rejected = MacMigrationRejectedScope {
                        permit: permit.clone(),
                        app_scope: app_scope.clone(),
                        owner: owner.clone(),
                        maintenance: maintenance.clone(),
                        journal,
                        candidate: candidate.clone(),
                    };
                    if let Some(sender) = sender.take() {
                        let _ = sender.send(MacMigrationObservation {
                            transaction_id: transaction.clone(),
                            stage: $stage,
                            local_exec_report: None,
                            pair_admission_report: None,
                            rejected_scope: Some(Box::new(rejected)),
                            committed_scope: None,
                        });
                    }
                    return;
                }
            }
        };
    }
    pre!(
        (|| {
            if !maintenance.matches(&owner)
                || !journal.configuration_root().same_authority(&owner)
                || desired.gateway.is_some()
                || !desired.host.as_ref().is_some_and(|h| {
                    h.autostart == NativeAutostartDesired::Disabled
                        && h.manager != NativeManager::PersistentService
                })
            {
                return Err(JournalError::Conflict);
            }
            match (desired.host.as_ref().map(|host| host.manager), &app_scope) {
                (Some(NativeManager::AppManaged), Some(scope))
                    if scope.state_dir() == state_dir =>
                {
                    scope.validate().map_err(|_| JournalError::Unknown)?;
                }
                (Some(NativeManager::ForegroundCli), None) => {}
                _ => return Err(JournalError::Conflict),
            }
            candidate.revalidate().map_err(|_| JournalError::Unknown)?;
            let expected_target = match std::env::consts::ARCH {
                "x86_64" => "x86_64-apple-darwin",
                "aarch64" => "aarch64-apple-darwin",
                _ => return Err(JournalError::Unsupported),
            };
            let selection = candidate
                .runtime_selection()
                .map_err(|_| JournalError::Unknown)?;
            if candidate.report().target != expected_target
                || !matches!(selection.payload_root, NativeRootIdentity::Macos { .. })
                || selection.manifest_sha256 != candidate.report().manifest_sha256
                || selection.publisher_spki_sha256.to_hex()
                    != candidate.report().publisher_spki_sha256
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
                return Err(JournalError::Unsupported);
            }
            candidate
                .pin_worker(NativeExternalWorker::CodexExec)
                .map_err(|_| JournalError::Unsupported)?;
            Ok(())
        })(),
        "unknown_preflight"
    );
    let root = pre!(PrivateRoot::open(&state_dir), "unknown_state_root");
    pre!(
        (|| {
            if root.identity() != owner.identity()? {
                return Err(JournalError::Conflict);
            }
            root.ensure_absent(crate::store::native_root::NATIVE_MARKER_FILE)
                .map_err(|_| JournalError::Conflict)
        })(),
        "unknown_original_binding",
        &root
    );
    let deployment = pre!(
        root.read_raw("deployment.json", NATIVE_STATE_BYTES),
        "unknown_deployment",
        &root
    );
    let data: serde_json::Value = pre!(
        serde_json::from_slice(deployment.bytes()),
        "unknown_deployment_format",
        &root,
        &deployment
    );
    let host_path = pre!(
        (|| {
            if data.get("schema").and_then(|v| v.as_u64()) != Some(1)
                || data.get("mode").and_then(|v| v.as_str()) != Some("join-existing")
            {
                return Err(JournalError::Unsupported);
            }
            let path = PathBuf::from(
                data.pointer("/host/baseDir")
                    .and_then(|v| v.as_str())
                    .ok_or(JournalError::InvalidInput)?,
            );
            if !path.is_absolute() {
                return Err(JournalError::InvalidInput);
            }
            Ok(path)
        })(),
        "unknown_host_topology",
        &root,
        &deployment
    );
    let host = pre!(
        PrivateRoot::open(&host_path),
        "unknown_host_root",
        &root,
        &deployment
    );
    let materials = pre!(
        read_original_pair_materials(&state_dir, &maintenance),
        "unknown_original_crypto",
        &root,
        &host,
        &deployment
    );
    let before = pre!(
        root.read_raw("state.json", NATIVE_STATE_BYTES),
        "unknown_original_state",
        &root,
        &host,
        &materials
    );
    pre!(
        handoff::reject_migration_v2_collision(before.bytes()),
        "unknown_reserved_key",
        &root,
        &host,
        &materials,
        &before
    );
    let preservation = pre!(
        Preservation::capture(&materials),
        "unknown_preservation",
        &root,
        &host,
        &materials,
        &before
    );
    let preservation_raw = pre!(
        serde_json::to_vec(&preservation.rows),
        "unknown_preservation_encoding",
        &root,
        &host,
        &materials,
        &preservation,
        &before
    );
    let selected = pre!(
        serde_json::to_vec(materials.preservation_entries()),
        "unknown_selected_encoding",
        &root,
        &host,
        &materials,
        &preservation,
        &before
    );
    let pair = pre!(
        materials.pair_binding(Sha256Digest::of_bytes(&preservation_raw)),
        "unknown_original_pair",
        &root,
        &host,
        &materials,
        &preservation,
        &before
    );
    let publisher = pre!(
        materials.publisher_sha256(),
        "unknown_original_publisher",
        &root,
        &host,
        &materials,
        &preservation,
        &before
    );
    pre!(
        (|| {
            if !materials.executor_configured()
                || publisher.to_hex() != candidate.report().publisher_spki_sha256
                || pair.config_root != native_id(root.identity())?
                || pair.host_root != native_id(host.identity())?
            {
                return Err(JournalError::Conflict);
            }
            preservation.validate_original()?;
            Ok(())
        })(),
        "unknown_candidate_or_original_pair",
        &root,
        &host,
        &materials,
        &preservation,
        &before
    );
    let inventory = pre!(
        journal.observe(),
        "unknown_original_journal",
        &root,
        &host,
        &materials,
        &preservation,
        &before
    );
    pre!(
        (|| {
            if !inventory.orphans.is_empty()
                || inventory.has_legacy_handoffs()
                || !inventory.owner_recoveries.is_empty()
                || inventory.transactions.iter().any(|t| {
                    t.phase_receipts
                        .last()
                        .is_none_or(|p| p.stage != DurableStage::Committed)
                })
            {
                return Err(JournalError::Conflict);
            }
            Ok(())
        })(),
        "unknown_incomplete_journal",
        &root,
        &host,
        &materials,
        &preservation,
        &before
    );
    let sequence = pre!(
        inventory
            .high_water
            .checked_add(1)
            .ok_or(JournalError::BudgetExceeded),
        "unknown_sequence",
        &root,
        &host,
        &materials,
        &preservation,
        &before
    );
    let plan = pre!(
        MacCutoverPlan::capture(&materials, Sha256Digest::of_bytes(&preservation_raw)),
        "unknown_original_plan_capture",
        &root,
        &host,
        &materials,
        &preservation,
        &before
    );
    let raw_token = pre!(
        host.read_raw("device/host.token", 4096),
        "unknown_original_token",
        &root,
        &host,
        &materials,
        &preservation,
        &before
    );
    let mut token = pre!(
        MacTokenRetirement::prepare(&host.inner, owner.clone(), maintenance.clone(), &raw_token),
        "unknown_token_pin",
        &root,
        &host,
        &materials,
        &preservation,
        &before
    );
    let descriptor = pre!(
        host.read_raw("service.json", 32768),
        "unknown_original_descriptor",
        &root,
        &host,
        &materials,
        &preservation,
        &before,
        &token
    );
    let intent = NativeRetirementIntent {
        schema: 3,
        kind: RetirementKind::LegacyCredentialRetirement,
        transaction_id: transaction.clone(),
        sequence,
        config_root: pair.config_root.clone(),
        host_root: pair.host_root.clone(),
        deployment_raw_sha256: pair.deployment_raw_sha256,
        before_state_sha256: Sha256Digest::of_bytes(before.bytes()),
        preservation_sha256: Sha256Digest::of_bytes(&selected),
        service_descriptor_sha256: Sha256Digest::of_bytes(descriptor.bytes()),
        candidate_manifest_sha256: candidate.report().manifest_sha256,
        publisher_spki_sha256: publisher,
        original_token: token.pre_stamp(),
    };
    let input = pre!(
        MacPreviousBootInput::capture(&root.inner, &host.inner),
        "unknown_original_boot_or_restart",
        &root,
        &host,
        &materials,
        &preservation,
        &before,
        &token
    );
    let recovery_inputs = pre!(
        input.plan(&intent),
        "unknown_original_recovery_plan",
        &root,
        &host,
        &materials,
        &preservation,
        &before,
        &token
    );
    let recovery_intent = pre!(
        recovery_inputs.validated_intent(),
        "unknown_recovery_plan_encoding",
        &root,
        &host,
        &materials,
        &preservation,
        &before,
        &token
    );
    let marker = pre!(
        migration_marker(&intent),
        "unknown_marker_generation",
        &root,
        &host,
        &materials,
        &preservation,
        &before,
        &token
    );
    let durable_inputs = pre!(
        (|| -> JournalResult<MigrationPlanInputs> {
            Ok(MigrationPlanInputs {
                retirement: serde_json::to_vec(&intent).map_err(|_| JournalError::InvalidInput)?,
                host_pair: serde_json::to_vec(&pair).map_err(|_| JournalError::InvalidInput)?,
                desired: serde_json::to_vec(&desired).map_err(|_| JournalError::InvalidInput)?,
                marker: serde_json::to_vec(&marker).map_err(|_| JournalError::InvalidInput)?,
                runtime_selection: serde_json::to_vec(
                    &candidate
                        .runtime_selection()
                        .map_err(|_| JournalError::Unknown)?,
                )
                .map_err(|_| JournalError::InvalidInput)?,
                owner_recovery: Some(
                    serde_json::to_vec(&recovery_inputs).map_err(|_| JournalError::InvalidInput)?,
                ),
                before: before.bytes().to_vec(),
                preservation: preservation_raw.clone(),
                selected: selected.clone(),
            })
        })(),
        "unknown_pre_effect_plan_encoding",
        &root,
        &host,
        &materials,
        &preservation,
        &before,
        &token
    );
    // Recheck the same original App instance immediately before the first
    // durable write; pure preflight failure still returns all original custody.
    pre!(
        app_scope.as_ref().map_or(Ok(()), |scope| {
            scope.validate().map_err(|_| JournalError::Unknown)
        }),
        "unknown_app_scope_before_effects"
    );
    let saved_plan = keep!(
        journal.persist_native_migration_plan(&maintenance, &durable_inputs),
        "unknown_pre_effect_plan_publication",
        &root,
        &host,
        &materials,
        &preservation,
        &before,
        &token,
        &recovery_inputs
    );
    let recovery = keep!(
        journal.prepare_legacy_owner_recovery(
            &maintenance,
            &recovery_intent,
            recovery_inputs.originals,
            recovery_inputs.guards
        ),
        "unknown_c_prepared",
        &root,
        &host,
        &materials,
        &preservation,
        &before,
        &token
    );
    let mut effects = keep!(
        MacBootRecoveryEffects::from_prepared(
            owner.clone(),
            maintenance.clone(),
            &root.inner,
            &host.inner,
            &recovery
        ),
        "unknown_c_effect_binding",
        &root,
        &host,
        &materials,
        &preservation,
        &before,
        &token,
        &recovery
    );
    let held = keep!(
        effects.archive_and_hold(&mut journal, &recovery),
        "unknown_c_archive_or_guards",
        &root,
        &host,
        &materials,
        &preservation,
        &before,
        &token,
        &recovery,
        &effects
    );
    keep!(
        effects.validate_retained(&held),
        "unknown_c_retained",
        &root,
        &host,
        &materials,
        &preservation,
        &before,
        &token,
        &effects,
        &held
    );
    let scopes = keep!(
        scope_bindings(&owner, &maintenance, &journal, &held),
        "unknown_scope_bindings",
        &root,
        &host,
        &materials,
        &preservation,
        &before,
        &token,
        &effects,
        &held
    );
    let owners = keep!(
        crate::store::native_legacy_owners::capture_native_legacy_owners(&root, &state_dir),
        "unknown_owner_bindings",
        &root,
        &host,
        &materials,
        &preservation,
        &before,
        &token,
        &effects,
        &held
    );
    let retirement = keep!(
        journal.prepare_native_credential_retirement(&maintenance, &intent),
        "unknown_retirement_prepared",
        &root,
        &host,
        &materials,
        &preservation,
        &before,
        &token,
        &effects,
        &held
    );
    // Capture the plan while the original token still exists; fill only the
    // actual retired receipt into target after the one OS retirement below.
    keep!(
        materials.revalidate(),
        "unknown_materials_before_retire",
        &root,
        &host,
        &materials,
        &preservation,
        &before,
        &token,
        &effects,
        &held,
        &retirement
    );
    keep!(
        preservation.validate_original(),
        "unknown_preservation_before_retire",
        &root,
        &host,
        &materials,
        &preservation,
        &before,
        &token,
        &effects,
        &held,
        &retirement
    );
    // Size-only rendering: the future receipt digest has fixed-width encoding.
    // These bytes are never written or used as a migration/canonical proof.
    let sizing = keep!(
        render_target(
            &candidate,
            &intent,
            &saved_plan.marker,
            Sha256Digest::from_bytes([0; 32]),
            &pair,
            preservation_raw.clone(),
            scopes.clone(),
            owners.clone(),
            before.bytes(),
            desired.clone()
        ),
        "unknown_target_size_preflight",
        &materials,
        &preservation,
        &before,
        &token,
        &effects,
        &held,
        &retirement
    );
    keep!(
        journal.preflight_host_cutover_capacity(&maintenance, &sizing),
        "unknown_future_cutover_capacity",
        &materials,
        &preservation,
        &before,
        &token,
        &effects,
        &held,
        &retirement
    );
    let expected_target_bytes = sizing.target.len();
    drop(sizing);
    let retired = keep!(
        token.retire_and_record(&mut journal, &retirement),
        "unknown_token_retirement",
        &root,
        &host,
        &materials,
        &preservation,
        &before,
        &token,
        &effects,
        &held,
        &retirement
    );
    // Pair was captured before retirement, and is checked against actual token
    // post and immutable materials. No synthetic token or baseline is created.
    let cutover_inputs = keep!(
        render_target(
            &candidate,
            &intent,
            &saved_plan.marker,
            retired.record_sha256(),
            &pair,
            preservation_raw,
            scopes,
            owners,
            before.bytes(),
            desired
        ),
        "unknown_target_render",
        &root,
        &host,
        &materials,
        &preservation,
        &before,
        &token,
        &effects,
        &held,
        &retired
    );
    keep!(
        if cutover_inputs.target.len() == expected_target_bytes {
            Ok(())
        } else {
            Err(JournalError::Unknown)
        },
        "unknown_target_size_changed_after_retirement",
        &materials,
        &preservation,
        &before,
        &token,
        &effects,
        &held,
        &retired
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
            cutover_inputs,
            candidate.clone()
        ),
        "unknown_cutover_prepared",
        &root,
        &host,
        &materials,
        &preservation,
        &before,
        &token,
        &effects,
        &held,
        &retired
    );
    keep!(
        applied.apply(&mut journal),
        "unknown_canonical_or_applied",
        &root,
        &host,
        &materials,
        &preservation,
        &before,
        &token,
        &effects,
        &held,
        &retired,
        &applied
    );
    finish_applied_migration(
        runtime,
        owner.clone(),
        &maintenance,
        journal,
        candidate.clone(),
        app_scope,
        applied,
        sender,
        Some(permit),
    )
    .await;
}

fn native_id(identity: RootIdentity) -> JournalResult<NativeRootIdentity> {
    match identity {
        RootIdentity::Macos { device, inode, uid } => {
            Ok(NativeRootIdentity::Macos { device, inode, uid })
        }
        _ => Err(JournalError::Unsupported),
    }
}

#[path = "macos_migration_resume.rs"]
mod resume;
pub(in crate::store) use resume::{MacResumedCutover, start_resume_validated_host_migration};

#[path = "macos_migration_pre_cutover.rs"]
mod pre_cutover;
pub(in crate::store) use pre_cutover::start_resume_pre_cutover_host_migration;
