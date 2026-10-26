//! One original-owner Darwin migration through actual validation and commit.
//! Source plan is durable before effects; interrupted recovery consumer is still internal work.
use super::*;
use crate::{
    foreground::profile::{
        OriginalNativePairMaterials, load_applied_mac_maintenance_profile,
        read_original_pair_materials,
    },
    migration::{
        mac_exec_validation::MacCandidateExecProbe, mac_pair_validation::MacPairReadinessProbe,
    },
    release::VerifiedNativeRelease,
    store::{
        configuration::{ConfigurationMaintenance, OwnedConfigurationRoot},
        management::{
            OwnedManagementJournal,
            cutover::{NativeCutoverHistoryInputs, NativeCutoverInputs},
            handoff::{
                self, LegacyGuardsHeld, NativeRetirementIntent, OwnerRecoveryStage, RetirementKind,
            },
            migration_plan::MigrationPlanInputs,
        },
        native_state,
        secure_journal::{JournalError, JournalResult, files},
    },
};
use serde::Serialize;
use serde_json::value::RawValue;
use std::collections::BTreeMap;
use styx_contracts::{
    identity::{Sha256Digest, TransactionId},
    management::ReaderContract,
    native_management::*,
    native_release::{NativeExternalWorker, NativeReleaseScope},
};
use styx_core::management::transaction::DurableStage;
use tokio::{runtime::Handle, sync::oneshot, task::JoinHandle};

/// One-shot observation data, optionally transferring original owned resources.
/// A dropped observer does not abort the original blocking job or release scope.
pub(in crate::store) struct MacMigrationObservation {
    pub(in crate::store) transaction_id: TransactionId,
    pub(in crate::store) stage: &'static str,
    pub(in crate::store) local_exec_report: Option<Vec<u8>>,
    pub(in crate::store) pair_admission_report: Option<Vec<u8>>,
    pub(in crate::store) rejected_scope: Option<Box<MacMigrationRejectedScope>>,
    committed_scope: Option<Box<MacMigrationCommittedScope>>,
}
/// Retained original capabilities after a strictly ZERO-effect rejection.
/// No Clone/Serde and no fence-clear method; caller gets its original scope back.
pub(in crate::store) struct MacMigrationRejectedScope {
    pub(in crate::store) app_scope: Option<Arc<crate::app::HostScope>>,
    pub(in crate::store) owner: OwnedConfigurationRoot,
    pub(in crate::store) maintenance: Arc<ConfigurationMaintenance>,
    pub(in crate::store) journal: OwnedManagementJournal,
    pub(in crate::store) candidate: Arc<VerifiedNativeRelease>,
}
/// Final commit returned the SAME configuration writer and domain journal.
/// Only the actual joined owner task returns this scope to an ordinary caller.
pub(in crate::store) struct MacMigrationCommittedScope {
    pub(in crate::store) recovery_permit: Option<Arc<tokio::sync::SemaphorePermit<'static>>>,
    pub(in crate::store) app_scope: Option<Arc<crate::app::HostScope>>,
    pub(in crate::store) owner: OwnedConfigurationRoot,
    pub(in crate::store) journal: OwnedManagementJournal,
    pub(in crate::store) candidate: Arc<VerifiedNativeRelease>,
}
#[must_use = "retain the original non-aborted job and its observation"]
pub(in crate::store) struct MacMigrationOwnerTask {
    observation: oneshot::Receiver<MacMigrationObservation>,
    observed: bool,
    rejected_observed: bool,
    committed_scope: Option<Box<MacMigrationCommittedScope>>,
    worker_joined: bool,
    worker_failed: bool,
    _job: JoinHandle<()>,
}
impl MacMigrationOwnerTask {
    /// Cancelling this WAIT leaves the original receiver and job in self.
    pub(in crate::store) async fn observe(&mut self) -> JournalResult<MacMigrationObservation> {
        if self.observed {
            return Err(JournalError::Conflict);
        }
        let mut result = (&mut self.observation)
            .await
            .map_err(|_| JournalError::Unknown);
        self.observed = true;
        if let Ok(observation) = &mut result {
            self.rejected_observed = observation.rejected_scope.is_some();
            self.committed_scope = observation.committed_scope.take();
        }
        result
    }
    /// Return the original scope only AFTER the actual worker join. Cancelling
    /// this wait retains both its handle and the scope in this task object.
    pub(in crate::store) async fn join_committed(
        &mut self,
    ) -> JournalResult<Box<MacMigrationCommittedScope>> {
        if self.committed_scope.is_none() {
            return Err(JournalError::Conflict);
        }
        self.join_worker().await?;
        self.committed_scope.take().ok_or(JournalError::Conflict)
    }
    async fn join_worker(&mut self) -> JournalResult<()> {
        if self.worker_failed {
            return Err(JournalError::Unknown);
        }
        if !self.worker_joined {
            if (&mut self._job).await.is_err() {
                self.worker_failed = true;
                return Err(JournalError::Unknown);
            }
            self.worker_joined = true;
        }
        Ok(())
    }
    /// A zero-effect rejection actually returns from the worker. This is its
    /// real join; Unknown cannot use this port to discard scope.
    pub(in crate::store) async fn join_rejected(&mut self) -> JournalResult<()> {
        if !self.rejected_observed {
            return Err(JournalError::Conflict);
        }
        self.join_worker().await
    }
}
/// Moves only already-acquired ORIGINAL capabilities into one owned task.
/// No writer/journal is acquired by path here; no caller command/token is read.
/// `desired` is an explicit local plan; unsupported service/autostart is refused.
/// INTERNAL UNFINISHED COMPOSITION ONLY: do not expose to CLI/App or execute on
/// a real profile until interrupted recovery consumers are implemented. The normal path commits using real probes and transfers its
/// same writer; failure retains the original scope without replay.
pub(in crate::store) fn start_previous_boot_host_migration(
    runtime: Handle,
    state_dir: PathBuf,
    owner: OwnedConfigurationRoot,
    maintenance: Arc<ConfigurationMaintenance>,
    journal: OwnedManagementJournal,
    candidate: Arc<VerifiedNativeRelease>,
    desired: NativeDesired,
    app_scope: Option<Arc<crate::app::HostScope>>,
) -> MacMigrationOwnerTask {
    let (sender, observation) = oneshot::channel();
    let executor = runtime.clone();
    // A started Tokio blocking job cannot be aborted by dropping its observer.
    // Construct all borrowed profile/guard values INSIDE this same job. No
    // borrowed guard is sent to another 'static task and no mem::forget is used.
    let job = runtime.spawn_blocking(move || {
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
async fn retain_scope<T>(
    held: T,
    sender: &mut Option<oneshot::Sender<MacMigrationObservation>>,
    observation: MacMigrationObservation,
) -> ! {
    if let Some(sender) = sender.take() {
        let _ = sender.send(observation);
    }
    // An Unknown effect retains every ORIGINAL value in this frame until an
    // explicit recovery consumer can reconcile it. The successful path returns.
    // There is intentionally no caller boolean that drops/clears this fence.
    loop {
        std::future::pending::<()>().await;
        std::hint::black_box(&held);
    }
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
) {
    let transaction = maintenance.transaction_id().clone();
    let mut sender = Some(sender);
    // Every failed stage keeps all values which can already own effects. A
    // returned error from bootstrap is never treated as a nonexistent child.
    macro_rules! keep {
        ($result:expr, $stage:literal $(, $held:expr)* $(,)?) => {
            match $result {
                Ok(value) => value,
                Err(_) => retain_scope((&owner, &maintenance, &journal, &candidate, &app_scope, $($held,)*), &mut sender,
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
        maintenance.clone(),
        journal,
        candidate.clone(),
        app_scope,
        applied,
        sender,
        None,
    )
    .await;
}

/// Finish one already-applied original migration using actual joined probes.
/// The caller must await this inside the same non-abortable owner job: `applied`
/// borrows its original materials/C/held/token, keeping that caller frame alive.
/// No probe retry or historical-report substitution is performed here.
async fn finish_applied_migration(
    runtime: Handle,
    owner: OwnedConfigurationRoot,
    maintenance: Arc<ConfigurationMaintenance>,
    mut journal: OwnedManagementJournal,
    candidate: Arc<VerifiedNativeRelease>,
    app_scope: Option<Arc<crate::app::HostScope>>,
    applied: MacCanonicalCutover<'_, '_>,
    mut sender: Option<oneshot::Sender<MacMigrationObservation>>,
    recovery_permit: Option<Arc<tokio::sync::SemaphorePermit<'static>>>,
) {
    let transaction = maintenance.transaction_id().clone();
    macro_rules! keep {
        ($result:expr, $stage:literal $(, $held:expr)* $(,)?) => {
            match $result {
                Ok(value) => value,
                Err(_) => retain_scope(
                    (&owner, &maintenance, &journal, &candidate, &app_scope,
                        &recovery_permit, &applied, $($held,)*),
                    &mut sender,
                    MacMigrationObservation {
                        transaction_id: transaction.clone(),
                        stage: $stage,
                        local_exec_report: None,
                        pair_admission_report: None,
                        rejected_scope: None,
                        committed_scope: None,
                    },
                ).await,
            }
        };
    }
    let profile = keep!(
        load_applied_mac_maintenance_profile(&applied),
        "unknown_maintenance_profile",
        &applied
    );
    let mut probe = keep!(
        MacCandidateExecProbe::prepare(&profile),
        "unknown_probe_prepare",
        &applied,
        &profile
    );
    let report_raw = keep!(
        probe.run_joined(&runtime).and_then(|report| {
            serde_json::to_vec(report)
                .map_err(|_| crate::migration::mac_exec_validation::MacExecValidationError::Unknown)
        }),
        "unknown_exec_cleanup_or_report",
        &applied,
        &profile,
        &probe
    );
    keep!(
        probe.revalidate_success(),
        "unknown_after_local_probe",
        &applied,
        &profile,
        &probe
    );
    keep!(
        applied.validate_applied(),
        "unknown_after_local_applied",
        &applied,
        &profile,
        &probe
    );
    let mut pair_probe = keep!(
        MacPairReadinessProbe::prepare(&profile),
        "unknown_pair_probe_prepare",
        &profile,
        &probe,
        &applied,
    );
    let pair_report_raw = keep!(
        pair_probe.run_joined(&runtime).and_then(|report| {
            serde_json::to_vec(report)
                .map_err(|_| crate::migration::mac_pair_validation::MacPairValidationError::Unknown)
        }),
        "unknown_original_pair_readiness_or_cleanup",
        &profile,
        &probe,
        &pair_probe,
        &applied,
    );
    keep!(
        pair_probe.revalidate_success(),
        "unknown_pair_revalidation",
        &profile,
        &probe,
        &pair_probe,
        &applied,
    );
    keep!(
        probe.revalidate_success(),
        "unknown_local_effect_after_pair_validation",
        &profile,
        &probe,
        &pair_probe,
        &applied,
    );
    keep!(
        app_scope.as_ref().map_or(Ok(()), |scope| {
            scope.validate().map_err(|_| JournalError::Unknown)
        }),
        "unknown_app_scope_before_commit",
        &profile,
        &probe,
        &pair_probe,
        &applied,
    );
    let committed = keep!(
        applied.commit_validated(&mut journal, &mut probe, &mut pair_probe),
        "unknown_final_validation_or_commit",
        &profile,
        &probe,
        &pair_probe,
        &applied,
    );
    keep!(
        committed.release_admission(&journal, &mut probe, &mut pair_probe, app_scope.as_deref()),
        "unknown_committed_admission_release",
        &profile,
        &probe,
        &pair_probe,
        &applied,
    );
    // Both workers are already settled. Drop the local execution lease BEFORE
    // transferring the same owner; it must not obstruct ordinary runtime start.
    drop(pair_probe);
    drop(probe);
    if let Some(sender) = sender.take() {
        let _ = sender.send(MacMigrationObservation {
            transaction_id: transaction,
            stage: "committed_admission_released",
            local_exec_report: Some(report_raw),
            pair_admission_report: Some(pair_report_raw),
            rejected_scope: None,
            committed_scope: Some(Box::new(MacMigrationCommittedScope {
                recovery_permit,
                app_scope,
                owner: owner.clone(),
                journal,
                candidate: candidate.clone(),
            })),
        });
    }
}
fn native_id(identity: RootIdentity) -> JournalResult<NativeRootIdentity> {
    match identity {
        RootIdentity::Macos { device, inode, uid } => {
            Ok(NativeRootIdentity::Macos { device, inode, uid })
        }
        _ => Err(JournalError::Unsupported),
    }
}
#[derive(Serialize)]
struct PreservationRow {
    path: PathBuf,
    sha256: Sha256Digest,
    bytes: u64,
    observation: FileObservation,
}
struct PreservationPin {
    root: PrivateRoot,
    name: PathBuf,
    observation: FileObservation,
    digest: Sha256Digest,
    max: usize,
}
struct Preservation {
    rows: Vec<PreservationRow>,
    pins: Vec<PreservationPin>,
}
impl Preservation {
    fn capture(materials: &OriginalNativePairMaterials<'_>) -> JournalResult<Self> {
        materials.revalidate().map_err(|_| JournalError::Unknown)?;
        let entries = materials.preservation_entries();
        if entries.is_empty() || entries.len() > 128 {
            return Err(JournalError::BudgetExceeded);
        }
        let mut rows = BTreeMap::new();
        let mut pins = Vec::new();
        for entry in entries {
            let root = PrivateRoot::open(entry.path.parent().ok_or(JournalError::InvalidInput)?)
                .map_err(|_| JournalError::Unknown)?;
            let name = PathBuf::from(entry.path.file_name().ok_or(JournalError::InvalidInput)?);
            let max = usize::try_from(entry.bytes)
                .map_err(|_| JournalError::BudgetExceeded)?
                .checked_add(1)
                .ok_or(JournalError::BudgetExceeded)?;
            if max > NATIVE_STATE_BYTES + 1 {
                return Err(JournalError::BudgetExceeded);
            }
            let raw = root
                .read_raw(&name, max)
                .map_err(|_| JournalError::Unknown)?;
            if Sha256Digest::of_bytes(raw.bytes()) != entry.sha256
                || raw.bytes().len() as u64 != entry.bytes
            {
                return Err(JournalError::Unknown);
            }
            if let Some(old) = rows.get(&entry.path) {
                let old: &PreservationRow = old;
                if old.sha256 != entry.sha256 || old.observation != *raw.observation() {
                    return Err(JournalError::Unknown);
                }
            } else {
                rows.insert(
                    entry.path.clone(),
                    PreservationRow {
                        path: entry.path.clone(),
                        sha256: entry.sha256,
                        bytes: entry.bytes,
                        observation: raw.observation().clone(),
                    },
                );
            }
            pins.push(PreservationPin {
                root,
                name,
                observation: raw.observation().clone(),
                digest: entry.sha256,
                max,
            });
        }
        let value = Self {
            rows: rows.into_values().collect(),
            pins,
        };
        value.validate_original()?;
        materials.revalidate().map_err(|_| JournalError::Unknown)?;
        Ok(value)
    }
    fn validate_original(&self) -> JournalResult<()> {
        for pin in &self.pins {
            let raw = pin
                .root
                .read_raw(&pin.name, pin.max)
                .map_err(|_| JournalError::Unknown)?;
            if raw.observation() != &pin.observation
                || Sha256Digest::of_bytes(raw.bytes()) != pin.digest
            {
                return Err(JournalError::Unknown);
            }
        }
        Ok(())
    }
}
fn scope_bindings(
    owner: &OwnedConfigurationRoot,
    maintenance: &ConfigurationMaintenance,
    journal: &OwnedManagementJournal,
    held: &LegacyGuardsHeld,
) -> JournalResult<Vec<u8>> {
    owner.with_maintenance(maintenance, |state| journal.with_directory_locked(state, |directory| {
        let scan = files::scan(directory, journal.budget())?;
        let records = handoff::scan_owner_recoveries(&scan)?;
        if records.records.len() != 1 { return Err(JournalError::Conflict); }
        let original = &records.records[0];
        if original.stage() != Some(OwnerRecoveryStage::GuardsHeld) || original.intent != *held.prepared().intent() { return Err(JournalError::Conflict); }
        serde_json::to_vec(&serde_json::json!({"schema":1,"kind":"mac_original_previous_boot_guards_held","transaction_id":original.intent.transaction_id,"config_root":original.intent.config_root,"original_recovery_intent_sha256":Sha256Digest::of_bytes(&original.raw_intent),"guard_posts":original.guards_held_posts().ok_or(JournalError::Conflict)?,"historical_outcome":"unknown_not_replayed"})).map_err(|_| JournalError::InvalidInput)
    }))
}
fn raw<T: Serialize>(value: &T) -> JournalResult<Box<RawValue>> {
    RawValue::from_string(serde_json::to_string(value).map_err(|_| JournalError::InvalidInput)?)
        .map_err(|_| JournalError::InvalidInput)
}
fn migration_marker(retirement: &NativeRetirementIntent) -> JournalResult<NativeRootMarker> {
    let mut entropy = [0u8; 32];
    getrandom::fill(&mut entropy).map_err(|_| JournalError::Unknown)?;
    Ok(NativeRootMarker {
        schema: NATIVE_MARKER_SCHEMA,
        kind: NativeRootKind::StyxConfigurationRoot,
        runtime_format: NativeRuntimeFormat::NativeRustV1,
        root_identity: retirement.config_root.clone(),
        scope_generation: Sha256Digest::from_bytes(entropy),
        reader_floor: ReaderContract::NativeMigratedStateV2,
    })
}
fn render_target(
    candidate: &VerifiedNativeRelease,
    retirement: &NativeRetirementIntent,
    marker: &NativeRootMarker,
    retired_sha256: Sha256Digest,
    pair: &NativePreservedHostPair,
    preservation: Vec<u8>,
    scopes: Vec<u8>,
    owners: Box<RawValue>,
    before: &[u8],
    desired: NativeDesired,
) -> JournalResult<NativeCutoverInputs> {
    if marker.root_identity != retirement.config_root
        || marker.reader_floor != ReaderContract::NativeMigratedStateV2
    {
        return Err(JournalError::Conflict);
    }
    let pair_raw = serde_json::to_vec(pair).map_err(|_| JournalError::InvalidInput)?;
    let binding = NativeMigrationBindingV2 {
        schema: 2,
        transaction_id: retirement.transaction_id.clone(),
        root_identity: retirement.config_root.clone(),
        original_state_sha256: retirement.before_state_sha256,
        retired_receipt_sha256: retired_sha256,
        candidate_manifest_sha256: retirement.candidate_manifest_sha256,
        publisher_spki_sha256: retirement.publisher_spki_sha256,
        preservation_sha256: Sha256Digest::of_bytes(&preservation),
        scope_bindings_sha256: Sha256Digest::of_bytes(&scopes),
        original_token_relative_path: retirement
            .token_destination()
            .to_str()
            .ok_or(JournalError::Unsupported)?
            .to_owned(),
        host_pair_sha256: Sha256Digest::of_bytes(&pair_raw),
        endpoint_mode: NativeMigrationEndpointMode::PreservedRemote,
        history: NativeMigrationHistory::PreservedHostPair {
            source_bindings_sha256: Sha256Digest::of_bytes(&pair_raw),
        },
    };
    let original = RawValue::from_string(
        std::str::from_utf8(before)
            .map_err(|_| JournalError::InvalidInput)?
            .to_owned(),
    )
    .map_err(|_| JournalError::InvalidInput)?;
    let extensions = BTreeMap::from([
        ("original_legacy_state".into(), original),
        (NATIVE_MIGRATION_V2_KEY.into(), raw(&binding)?),
        (
            "runtime_selection_v1".into(),
            raw(&candidate
                .runtime_selection()
                .map_err(|_| JournalError::Unknown)?)?,
        ),
        ("legacy_owner_bindings_v2".into(), owners),
    ]);
    let target = NativeState {
        schema: NATIVE_STATE_SCHEMA,
        kind: NativeStateKind::StyxDesiredState,
        runtime_format: NativeRuntimeFormat::NativeRustV1,
        reader_contract: marker.reader_floor,
        scope_generation: marker.scope_generation,
        deployment_raw_sha256: retirement.deployment_raw_sha256,
        mode: NativeDeploymentMode::JoinExisting,
        revision: 1,
        last_transaction: Some(NativeStateTransaction {
            transaction_id: retirement.transaction_id.clone(),
            sequence: retirement.sequence,
        }),
        desired,
        migration: None,
        extensions,
    };
    styx_core::management::state::validate_state(&target, &marker)
        .map_err(|_| JournalError::InvalidInput)?;
    Ok(NativeCutoverInputs {
        history: NativeCutoverHistoryInputs::PreservedHostPair { bindings: pair_raw },
        endpoint_mode: NativeMigrationEndpointMode::PreservedRemote,
        preservation,
        scope_bindings: scopes,
        marker: serde_json::to_vec(&marker).map_err(|_| JournalError::InvalidInput)?,
        before: before.to_vec(),
        target: serde_json::to_vec(&target).map_err(|_| JournalError::InvalidInput)?,
        endpoint: None,
    })
}

#[path = "macos_migration_resume.rs"]
mod resume;
pub(in crate::store) use resume::{MacResumedCutover, start_resume_validated_host_migration};

#[path = "macos_migration_pre_cutover.rs"]
mod pre_cutover;
pub(in crate::store) use pre_cutover::start_resume_pre_cutover_host_migration;
