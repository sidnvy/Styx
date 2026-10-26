//! Actual initial checkpoint producer. This is a child of the original Windows
//! maintenance-plan module so it uses that exact review codec and observations.
//! All methods run inside ONE retained blocking MTA job. No JSON can construct
//! original App evidence, a settled scope or a successful migration capability.
use super::*;
use crate::{
    foreground::profile::OriginalNativePairMaterials,
    store::{
        management::handoff::{OwnerRecoveryPlan, ProofStamp},
        platform::{
            WindowsOriginalApp, WindowsRestartCheckpoint,
            restart::{StartupLinkRead, read_original_startup_link},
        },
    },
};

/// Read-only original sources and the exact future C bytes. The review hash is
/// accepted only by the caller's existing management authority, not as a bearer
/// token. Random guard bytes are generated ONCE and saved in original Prepared.
pub(in crate::store) struct WindowsMigrationCheckpointPlan {
    legacy: WindowsLegacyMaintenancePlan,
    original_app: WindowsOriginalApp,
    startup: Option<StartupLinkRead>,
    review: Vec<u8>,
    review_sha256: Sha256Digest,
    intent: LegacyOwnerRecoveryIntent,
    originals: Vec<RecoveryOriginal>,
    guards: Vec<RecoveryGuard>,
    // Set before the first journal write. Caller must retain the original job
    // and capabilities on an error after this point; dropping a waiter is not
    // cancellation or evidence that preparation/rename did not happen.
    attempted: bool,
}
impl WindowsMigrationCheckpointPlan {
    pub(in crate::store) fn capture(
        owner: &OwnedConfigurationRoot,
        maintenance: &ConfigurationMaintenance,
        host: &PrivateRoot,
        observation: &WindowsLegacyObservation,
        candidate: &VerifiedNativeRelease,
        successor: &NativeRetirementIntent,
        materials: &OriginalNativePairMaterials<'_>,
    ) -> JournalResult<Self> {
        candidate_matches(
            candidate,
            successor.candidate_manifest_sha256,
            successor.publisher_spki_sha256,
        )?;
        materials.revalidate().map_err(failed)?;
        let pair = materials
            .pair_binding(successor.preservation_sha256)
            .map_err(failed)?;
        if pair.transaction_id != successor.transaction_id
            || pair.config_root != successor.config_root
            || pair.host_root != successor.host_root
            || pair.deployment_raw_sha256 != successor.deployment_raw_sha256
            || pair.credential_sha256 != successor.original_token.content_sha256()
            || materials.before_sha256().map_err(failed)? != successor.before_state_sha256
            || materials.publisher_sha256().map_err(failed)? != successor.publisher_spki_sha256
        {
            return Err(JournalError::Conflict);
        }
        let legacy = WindowsLegacyMaintenancePlan::capture(
            owner,
            maintenance,
            host,
            observation,
            successor,
        )?;
        let startup = read_original_startup_link()?;
        let original_app =
            WindowsOriginalApp::capture(&startup, &legacy.evidence.root.path, materials)?;
        let checkpoint = original_app.checkpoint().clone();
        let mut body: PlanBody = serde_json::from_slice(legacy.review_bytes()).map_err(failed)?;
        body.schema = 2;
        body.action = "retire_legacy_foreground_owner_after_windows_restart".into();
        body.startup_checkpoint_sha256 = Some(Sha256Digest::of_bytes(
            &serde_json::to_vec(&checkpoint).map_err(failed)?,
        ));
        let review = serde_json::to_vec(&body).map_err(failed)?;
        let review_sha256 = Sha256Digest::of_bytes(&review);
        let mut originals = Vec::new();
        for (index, name) in [
            (1, RecoveryOriginalName::Lock),
            (2, RecoveryOriginalName::Observer),
        ] {
            let raw = &legacy.evidence.originals[index];
            let file = ffi::open(
                &legacy.evidence.root.path.join(name.source_name()),
                false,
                false,
                false,
            )
            .map_err(failed)?;
            if read_pin(&file, raw.bytes())? != *raw.observation() {
                return Err(JournalError::Conflict);
            }
            originals.push(RecoveryOriginal {
                name,
                raw: raw.bytes().to_vec(),
                stamp: native_stamp(&file, raw.bytes())?,
            });
        }
        let guard_raw = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        )
        .into_bytes();
        let guards: Vec<_> = [
            RecoveryGuardName::Advance,
            RecoveryGuardName::Background,
            RecoveryGuardName::Capabilities,
            RecoveryGuardName::Foreground,
        ]
        .into_iter()
        .map(|name| RecoveryGuard {
            name,
            raw: guard_raw.clone(),
        })
        .collect();
        let intent = LegacyOwnerRecoveryIntent {
            schema: 3,
            kind: RecoveryKind::LegacyOwnerRecovery,
            transaction_id: successor.transaction_id.clone(),
            sequence: successor.sequence,
            config_root: successor.config_root.clone(),
            deployment_raw_sha256: successor.deployment_raw_sha256,
            before_state_sha256: successor.before_state_sha256,
            candidate_manifest_sha256: successor.candidate_manifest_sha256,
            publisher_spki_sha256: successor.publisher_spki_sha256,
            previous_boot: None,
            current_boot: RecoveryBoot {
                id: body.current_boot.id,
                started_at_ms: body.current_boot.started_at,
            },
            basis: Some(RecoveryBasis::ExplicitLegacyMaintenance {
                plan_sha256: review_sha256,
                device_id: body.device_id,
                identity_json_sha256: body.identity_sha256,
                configuration_hash: body.configuration_hash,
                observer_pid: body.previous_owner_pid,
            }),
            restart: RecoveryRestartBinding::WindowsStartupExclusion,
            successor_retirement_intent_sha256: Sha256Digest::of_bytes(
                &serde_json::to_vec(successor).map_err(failed)?,
            ),
            originals: originals
                .iter()
                .map(|o| RecoveryOriginalBinding {
                    name: o.name,
                    stamp: o.stamp.clone(),
                })
                .collect(),
            guards: guards
                .iter()
                .map(|g| RecoveryGuardBinding {
                    name: g.name,
                    sha256: Sha256Digest::of_bytes(&g.raw),
                    byte_len: g.raw.len() as u64,
                })
                .collect(),
            startup_checkpoint: Some(checkpoint),
        };
        let this = Self {
            legacy,
            original_app,
            startup: Some(startup),
            review,
            review_sha256,
            intent,
            originals,
            guards,
            attempted: false,
        };
        this.revalidate(
            owner,
            maintenance,
            observation,
            candidate,
            successor,
            materials,
        )?;
        Ok(this)
    }
    /// Exact data for the SAME pre-effect migration header. Caller must persist
    /// that complete header before entering prepare_and_exclude. No nonce or
    /// attachment is regenerated during resync or after an interrupted append.
    pub(in crate::store) fn owner_recovery_inputs(&self) -> JournalResult<OwnerRecoveryPlan> {
        if self.attempted {
            return Err(JournalError::Conflict);
        }
        let startup = self.startup.as_ref().ok_or(JournalError::Conflict)?;
        let input = OwnerRecoveryPlan {
            intent: serde_json::value::to_raw_value(&self.intent).map_err(failed)?,
            originals: self.copy_originals(),
            guards: self.copy_guards(),
            authorization_plan: Some(self.review.clone()),
            startup_raw: Some(startup.bytes.clone()),
        };
        if input.validated_intent()? != self.intent {
            return Err(JournalError::Conflict);
        }
        Ok(input)
    }
    fn copy_originals(&self) -> Vec<RecoveryOriginal> {
        self.originals
            .iter()
            .map(|o| RecoveryOriginal {
                name: o.name,
                raw: o.raw.clone(),
                stamp: o.stamp.clone(),
            })
            .collect()
    }
    fn copy_guards(&self) -> Vec<RecoveryGuard> {
        self.guards
            .iter()
            .map(|g| RecoveryGuard {
                name: g.name,
                raw: g.raw.clone(),
            })
            .collect()
    }
    fn validate_saved_plan(
        &self,
        journal: &OwnedManagementJournal,
        maintenance: &ConfigurationMaintenance,
    ) -> JournalResult<()> {
        let saved = journal.resync_native_migration_plan(maintenance)?;
        let expected = self.owner_recovery_inputs()?;
        let actual = saved
            .owner_recovery_inputs()?
            .ok_or(JournalError::Conflict)?;
        if !saved.matches_recovery(&self.intent)
            || Sha256Digest::of_bytes(saved.retirement_raw())
                != self.intent.successor_retirement_intent_sha256
            || serde_json::to_vec(&actual).map_err(failed)?
                != serde_json::to_vec(&expected).map_err(failed)?
        {
            return Err(JournalError::Conflict);
        }
        Ok(())
    }
    pub(in crate::store) fn review_bytes(&self) -> &[u8] {
        &self.review
    }
    pub(in crate::store) fn plan_sha256(&self) -> Sha256Digest {
        self.review_sha256
    }
    pub(in crate::store) fn transaction_id(&self) -> &TransactionId {
        &self.intent.transaction_id
    }
    pub(in crate::store) fn attempt_started(&self) -> bool {
        self.attempted
    }
    fn revalidate(
        &self,
        owner: &OwnedConfigurationRoot,
        maintenance: &ConfigurationMaintenance,
        observation: &WindowsLegacyObservation,
        candidate: &VerifiedNativeRelease,
        successor: &NativeRetirementIntent,
        materials: &OriginalNativePairMaterials<'_>,
    ) -> JournalResult<()> {
        if maintenance.transaction_id() != &self.intent.transaction_id
            || Sha256Digest::of_bytes(&self.review) != self.review_sha256
            || Sha256Digest::of_bytes(&serde_json::to_vec(successor).map_err(failed)?)
                != self.intent.successor_retirement_intent_sha256
            || self.intent.startup_checkpoint.as_ref() != Some(self.original_app.checkpoint())
        {
            return Err(JournalError::Conflict);
        }
        owner.with_maintenance(maintenance, |state| {
            if root_native(state.root.identity())? != self.intent.config_root {
                return Err(JournalError::Conflict);
            }
            let before = state
                .root
                .read_raw("state.json", 1024 * 1024)
                .map_err(failed)?;
            if Sha256Digest::of_bytes(before.bytes()) != self.intent.before_state_sha256 {
                return Err(JournalError::Conflict);
            }
            Ok(())
        })?;
        self.legacy.revalidate(observation)?;
        candidate_matches(
            candidate,
            self.intent.candidate_manifest_sha256,
            self.intent.publisher_spki_sha256,
        )?;
        self.original_app.revalidate(materials)?;
        observation.checkpoint().map_err(failed)?;
        Ok(())
    }
}

/// Borrows the actual original writer/fence/COM scope. The outer management
/// worker must own these values and its original semaphore permit until this
/// operation settles. This object cannot be sent to a different COM thread.
/// WaitingLaterBoot is NOT scope settlement, NotDispatched or migration success.
pub(in crate::store) struct WindowsMigrationCheckpointJob<'a, 'm> {
    plan: WindowsMigrationCheckpointPlan,
    journal: &'a mut OwnedManagementJournal,
    owner: &'a OwnedConfigurationRoot,
    maintenance: &'m ConfigurationMaintenance,
    observation: &'a WindowsLegacyObservation,
    candidate: &'a VerifiedNativeRelease,
    successor: &'a NativeRetirementIntent,
    host: &'a PrivateRoot,
    materials: &'a OriginalNativePairMaterials<'m>,
    app_scope: Option<&'a crate::app::HostScope>,
    prepared: Option<PreparedLegacyOwnerRecovery>,
    checkpoint: Option<WindowsRestartCheckpoint>,
}
impl<'a, 'm> WindowsMigrationCheckpointJob<'a, 'm> {
    pub(in crate::store) fn new(
        plan: WindowsMigrationCheckpointPlan,
        journal: &'a mut OwnedManagementJournal,
        owner: &'a OwnedConfigurationRoot,
        maintenance: &'m ConfigurationMaintenance,
        observation: &'a WindowsLegacyObservation,
        candidate: &'a VerifiedNativeRelease,
        successor: &'a NativeRetirementIntent,
        host: &'a PrivateRoot,
        materials: &'a OriginalNativePairMaterials<'m>,
        app_scope: Option<&'a crate::app::HostScope>,
    ) -> JournalResult<Self> {
        if plan.attempted || !journal.configuration_root().same_authority(owner) {
            return Err(JournalError::Conflict);
        }
        plan.revalidate(
            owner,
            maintenance,
            observation,
            candidate,
            successor,
            materials,
        )?;
        let saved = journal.resync_native_migration_plan(maintenance)?;
        validate_requested_manager(&saved.desired, &plan.legacy.evidence.root.path, app_scope)?;
        Ok(Self {
            plan,
            journal,
            owner,
            maintenance,
            observation,
            candidate,
            successor,
            host,
            materials,
            app_scope,
            prepared: None,
            checkpoint: None,
        })
    }
    /// One management-authorized attempt. On any error after attempt_started,
    /// keep THIS job and all its borrowed scope alive; recover the original tx.
    /// Never call again to manufacture another guard nonce/transaction.
    pub(in crate::store) fn prepare_and_exclude(
        &mut self,
        approved_plan_sha256: Sha256Digest,
    ) -> JournalResult<()> {
        if self.plan.attempted || approved_plan_sha256 != self.plan.review_sha256 {
            return Err(JournalError::Conflict);
        }
        self.plan.revalidate(
            self.owner,
            self.maintenance,
            self.observation,
            self.candidate,
            self.successor,
            self.materials,
        )?;
        self.plan
            .validate_saved_plan(self.journal, self.maintenance)?;
        let saved = self
            .journal
            .resync_native_migration_plan(self.maintenance)?;
        validate_requested_manager(
            &saved.desired,
            &self.plan.legacy.evidence.root.path,
            self.app_scope,
        )?;
        self.plan.attempted = true;
        // The callee consumes its vectors, including on failure. Keep the exact
        // original nonce/raw here as well as in the durable pre-effect header.
        let originals = self.plan.copy_originals();
        let guards = self.plan.copy_guards();
        let startup = self.plan.startup.as_ref().ok_or(JournalError::Conflict)?;
        let prepared = self.journal.prepare_windows_restart_checkpoint(
            self.maintenance,
            &self.plan.intent,
            originals,
            guards,
            &self.plan.review,
            &startup.bytes,
        )?;
        self.prepared = Some(prepared);
        // Original read-only no-write/no-delete HANDLE must be released before
        // opening the rename HANDLE. The durable original raw/stamp is already
        // in this SAME journal. Reopen validates exact object+bytes across gap.
        drop(self.plan.startup.take());
        let prepared = self.prepared.as_ref().ok_or(JournalError::Unknown)?;
        self.checkpoint = Some(WindowsRestartCheckpoint::open(
            self.journal,
            prepared,
            self.owner,
            self.maintenance,
            self.observation,
            self.candidate,
            self.host,
            self.successor,
        )?);
        self.plan.original_app.revalidate(self.materials)?;
        let next = self
            .checkpoint
            .as_mut()
            .ok_or(JournalError::Unknown)?
            .exclude_and_record(
                self.journal,
                prepared,
                self.maintenance,
                self.observation,
                self.candidate,
            )?;
        self.prepared = Some(next);
        if self.prepared.as_ref().and_then(|p| p.stage())
            != Some(OwnerRecoveryStage::RestartExcluded)
        {
            return Err(JournalError::Unknown);
        }
        if let Some(scope) = self.app_scope {
            scope.validate().map_err(failed)?;
        }
        // This is the exact durable checkpoint. No reboot is performed; no
        // pre-existing user reboot can satisfy this newly recorded boot fence.
        Ok(())
    }
    pub(in crate::store) fn waiting_for_later_boot(&self) -> bool {
        self.checkpoint.is_some()
            && self.prepared.as_ref().and_then(|p| p.stage())
                == Some(OwnerRecoveryStage::RestartExcluded)
    }
    pub(in crate::store) fn attempt_started(&self) -> bool {
        self.plan.attempt_started()
    }
    pub(in crate::store) fn prepared(&self) -> Option<&PreparedLegacyOwnerRecovery> {
        self.prepared.as_ref()
    }
}

/// Actual retained scope at the mandatory reboot boundary. This does not say the
/// original App/Core are stopped; only a later boot under the recorded exclusion
/// can establish that fact. No automatic restart or process-name kill is issued.
pub(in crate::store) struct WindowsMigrationWaitingForBoot {
    pub(in crate::store) app_scope: Option<Arc<crate::app::HostScope>>,
    pub(in crate::store) owner: OwnedConfigurationRoot,
    pub(in crate::store) maintenance: ConfigurationMaintenance,
    checkpoint: WindowsRestartCheckpoint,
    prepared: PreparedLegacyOwnerRecovery,
}
/// Actual C effects and original durable GuardsHeld, kept together for the
/// shared token/canonical/probe tail. Neither can be minted from a report.
pub(in crate::store) struct WindowsMigrationRecoveredGuards {
    pub(in crate::store) app_scope: Option<Arc<crate::app::HostScope>>,
    pub(in crate::store) owner: OwnedConfigurationRoot,
    pub(in crate::store) effects: WindowsBootRecoveryEffects,
    pub(in crate::store) held: LegacyGuardsHeld,
}
pub(in crate::store) enum WindowsMigrationCheckpointResume {
    WaitingForLaterBoot(WindowsMigrationWaitingForBoot),
    GuardsHeld(WindowsMigrationRecoveredGuards),
}
/// An error retains whichever ORIGINAL capability currently owns the fence and
/// physical HANDLEs. Caller also retains its original journal/COM job/permit.
pub(in crate::store) enum WindowsCheckpointRetainedScope {
    BeforeTransfer {
        owner: OwnedConfigurationRoot,
        maintenance: ConfigurationMaintenance,
        checkpoint: Option<WindowsRestartCheckpoint>,
    },
    OpenFailure(Box<WindowsRecoveryOpenFailure>),
    Effects(WindowsBootRecoveryEffects),
}
pub(in crate::store) struct WindowsCheckpointResumeFailure {
    pub(in crate::store) app_scope: Option<Arc<crate::app::HostScope>>,
    pub(in crate::store) error: JournalError,
    pub(in crate::store) retained: WindowsCheckpointRetainedScope,
}

/// Continue ONLY the original recorded checkpoint, on the same blocking COM
/// worker as observation. Does not open a second writer/journal, issue a new
/// transaction, synthesize a prior reboot, or replay any validation probe.
/// Prepared without a recorded exclusion is deliberately not accepted here.
pub(in crate::store) fn resume_recorded_windows_checkpoint(
    journal: &mut OwnedManagementJournal,
    owner: OwnedConfigurationRoot,
    maintenance: ConfigurationMaintenance,
    observation: &WindowsLegacyObservation,
    candidate: &VerifiedNativeRelease,
    host: &PrivateRoot,
    successor: &NativeRetirementIntent,
    app_scope: Option<Arc<crate::app::HostScope>>,
) -> std::result::Result<WindowsMigrationCheckpointResume, Box<WindowsCheckpointResumeFailure>> {
    let mut checkpoint = None;
    // Until transfer, every failure returns the original owner/fence and any
    // already opened Startup custody. This closure itself performs no rename.
    let prepared_result = (|| -> JournalResult<PreparedLegacyOwnerRecovery> {
        candidate_matches(
            candidate,
            successor.candidate_manifest_sha256,
            successor.publisher_spki_sha256,
        )?;
        let saved = journal.resync_native_migration_plan(&maintenance)?;
        if saved.retirement_raw() != serde_json::to_vec(successor).map_err(failed)? {
            return Err(JournalError::Conflict);
        }
        let state_dir =
            owner.with_maintenance(&maintenance, |state| Ok(state.root.inner.path.clone()))?;
        validate_requested_manager(&saved.desired, &state_dir, app_scope.as_deref())?;
        let saved_c = saved
            .owner_recovery_inputs()?
            .ok_or(JournalError::Conflict)?;
        let intent = saved_c.validated_intent()?;
        if intent.schema != 3 || !saved.matches_recovery(&intent) || !maintenance.matches(&owner) {
            return Err(JournalError::Conflict);
        }
        let prepared =
            journal.resync_legacy_owner_recovery(&maintenance, &successor.transaction_id)?;
        if !prepared.matches_owner(&owner)
            || prepared.intent() != &intent
            || !matches!(
                prepared.stage(),
                Some(
                    OwnerRecoveryStage::RestartExcluded
                        | OwnerRecoveryStage::BootObserved
                        | OwnerRecoveryStage::Archived
                        | OwnerRecoveryStage::GuardsHeld
                )
            )
            || prepared.authorization_plan() != saved_c.authorization_plan.as_deref()
            || prepared.startup_raw() != saved_c.startup_raw.as_deref()
        {
            return Err(JournalError::Conflict);
        }
        checkpoint = Some(WindowsRestartCheckpoint::open(
            journal,
            &prepared,
            &owner,
            &maintenance,
            observation,
            candidate,
            host,
            successor,
        )?);
        Ok(prepared)
    })();
    let prepared = match prepared_result {
        Ok(p) => p,
        Err(error) => {
            return Err(Box::new(WindowsCheckpointResumeFailure {
                app_scope,
                error,
                retained: WindowsCheckpointRetainedScope::BeforeTransfer {
                    owner,
                    maintenance,
                    checkpoint,
                },
            }));
        }
    };
    let checkpoint = match checkpoint {
        Some(c) => c,
        None => {
            return Err(Box::new(WindowsCheckpointResumeFailure {
                app_scope,
                error: JournalError::Unknown,
                retained: WindowsCheckpointRetainedScope::BeforeTransfer {
                    owner,
                    maintenance,
                    checkpoint: None,
                },
            }));
        }
    };
    let boot = match observation.checkpoint() {
        Ok(boot) => boot,
        Err(_) => {
            return Err(Box::new(WindowsCheckpointResumeFailure {
                app_scope,
                error: JournalError::Unknown,
                retained: WindowsCheckpointRetainedScope::BeforeTransfer {
                    owner,
                    maintenance,
                    checkpoint: Some(checkpoint),
                },
            }));
        }
    };
    if prepared.stage() == Some(OwnerRecoveryStage::RestartExcluded)
        && prepared.intent().current_boot.id
            == format!("wmi-lastboot-unix-micros:{}", boot.unix_micros)
        && prepared.intent().current_boot.started_at_ms == boot.unix_micros / 1000
    {
        return Ok(WindowsMigrationCheckpointResume::WaitingForLaterBoot(
            WindowsMigrationWaitingForBoot {
                app_scope,
                owner,
                maintenance,
                checkpoint,
                prepared,
            },
        ));
    }
    let prepared = match checkpoint.observe_boot_and_record(
        journal,
        &prepared,
        &maintenance,
        observation,
        candidate,
    ) {
        Ok(p) => p,
        Err(error) => {
            return Err(Box::new(WindowsCheckpointResumeFailure {
                app_scope,
                error,
                retained: WindowsCheckpointRetainedScope::BeforeTransfer {
                    owner,
                    maintenance,
                    checkpoint: Some(checkpoint),
                },
            }));
        }
    };
    let mut effects = match checkpoint.into_recovery(
        journal,
        &prepared,
        owner.clone(),
        maintenance,
        observation,
        candidate,
        host,
        successor,
    ) {
        Ok(effects) => effects,
        Err(failure) => {
            return Err(Box::new(WindowsCheckpointResumeFailure {
                app_scope,
                error: JournalError::Unknown,
                retained: WindowsCheckpointRetainedScope::OpenFailure(failure),
            }));
        }
    };
    let held = match effects.resume_prepared(journal, prepared, observation, candidate) {
        Ok(held) => held,
        Err(error) => {
            return Err(Box::new(WindowsCheckpointResumeFailure {
                app_scope,
                error,
                retained: WindowsCheckpointRetainedScope::Effects(effects),
            }));
        }
    };
    if let Err(error) = effects.validate_cutover_custody(&owner, &held, observation) {
        return Err(Box::new(WindowsCheckpointResumeFailure {
            app_scope,
            error,
            retained: WindowsCheckpointRetainedScope::Effects(effects),
        }));
    }
    if let Some(scope) = &app_scope {
        if scope.validate().is_err() {
            return Err(Box::new(WindowsCheckpointResumeFailure {
                app_scope,
                error: JournalError::Unknown,
                retained: WindowsCheckpointRetainedScope::Effects(effects),
            }));
        }
    }
    Ok(WindowsMigrationCheckpointResume::GuardsHeld(
        WindowsMigrationRecoveredGuards {
            app_scope,
            owner,
            effects,
            held,
        },
    ))
}

fn validate_requested_manager(
    desired: &styx_contracts::native_management::NativeDesired,
    state_dir: &Path,
    app_scope: Option<&crate::app::HostScope>,
) -> JournalResult<()> {
    use styx_contracts::native_management::{NativeAutostartDesired, NativeManager};
    if desired.gateway.is_some()
        || !desired.host.as_ref().is_some_and(|h| {
            h.autostart == NativeAutostartDesired::Disabled
                && h.manager != NativeManager::PersistentService
        })
    {
        return Err(JournalError::Conflict);
    }
    match (desired.host.as_ref().map(|h| h.manager), app_scope) {
        (Some(NativeManager::ForegroundCli), None) => Ok(()),
        (Some(NativeManager::AppManaged), Some(scope)) if scope.state_dir() == state_dir => {
            scope.validate().map_err(failed)
        }
        _ => Err(JournalError::Conflict),
    }
}

#[path = "windows_migration_run.rs"]
mod run;
pub(in crate::store) use run::{
    WindowsRestartMigrationReview, review_windows_restart_host_migration,
    start_resume_windows_restart_host_migration, start_windows_restart_host_migration,
};
