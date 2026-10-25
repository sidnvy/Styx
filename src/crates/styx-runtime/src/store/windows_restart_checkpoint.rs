//! Thin consumer of the original durable C checkpoint. No writer, plan,
//! authorization or reboot controller is created here. The caller retains the
//! original journal, maintenance fence and MTA observation worker on errors.
use super::*;
use crate::store::platform::restart::{StartupLinkCustody, StartupLocation, StartupOriginal};

pub(in crate::store) struct WindowsRestartCheckpoint {
    startup: StartupLinkCustody,
    service_root: Root,
    service: RawFile,
}
impl WindowsRestartCheckpoint {
    /// Consume an already authorized and durable checkpoint. Its producer must
    /// have verified the old signed package and original App/Core relationship;
    /// this adapter does not manufacture either fact from the JSON attachment.
    /// An incomplete journal must finish/resync Prepared before this call.
    pub(in crate::store) fn open(
        journal: &OwnedManagementJournal,
        prepared: &PreparedLegacyOwnerRecovery,
        owner: &OwnedConfigurationRoot,
        maintenance: &ConfigurationMaintenance,
        observation: &WindowsLegacyObservation,
        candidate: &VerifiedNativeRelease,
        host: &PrivateRoot,
        successor: &NativeRetirementIntent,
    ) -> JournalResult<Self> {
        journal.validate_legacy_owner_prepared(maintenance, prepared)?;
        if !journal.owner_recovery_prepared_matches(prepared)
            || !prepared.matches_owner(owner)
            || prepared.intent().schema != 3
            || prepared.stage().is_none()
            || maintenance.transaction_id() != &prepared.intent().transaction_id
            || Sha256Digest::of_bytes(&serde_json::to_vec(successor).map_err(failed)?)
                != prepared.intent().successor_retirement_intent_sha256
        {
            return Err(JournalError::Conflict);
        }
        let checkpoint = prepared
            .startup_checkpoint()
            .ok_or(JournalError::Conflict)?;
        let raw = prepared.startup_raw().ok_or(JournalError::Conflict)?;
        candidate_matches(
            candidate,
            prepared.intent().candidate_manifest_sha256,
            prepared.intent().publisher_spki_sha256,
        )?;
        let service = service_binding(host, successor, observation)?;
        let now = observation.checkpoint().map_err(failed)?;
        let checkpoint_boot = admitted_boot(&prepared.intent().current_boot, now)?;
        let archive = owner.with_maintenance(maintenance, |state| {
            if root_native(state.root.identity())? != prepared.intent().config_root {
                return Err(JournalError::Conflict);
            }
            let deployment = state
                .root
                .read_raw("deployment.json", 1024 * 1024)
                .map_err(failed)?;
            if Sha256Digest::of_bytes(deployment.bytes()) != prepared.intent().deployment_raw_sha256
            {
                return Err(JournalError::Conflict);
            }
            let dir = state
                .root
                .inner
                .create_journal_directory("foreground-recovery", false)
                .map_err(failed)?;
            let parent = Root::from_directory_handle(&dir).map_err(failed)?;
            let dir = parent
                .create_journal_directory(prepared.intent().transaction_id.as_str(), false)
                .map_err(failed)?;
            let archive = Root::from_directory_handle(&dir).map_err(failed)?;
            parent.sync_directory().map_err(failed)?;
            state.root.inner.sync_directory().map_err(failed)?;
            // Before BootObserved, C has no authority to archive the old guard.
            // Later phases are checked by the original C object before effects.
            if matches!(
                prepared.stage(),
                Some(OwnerRecoveryStage::Prepared | OwnerRecoveryStage::RestartExcluded)
            ) {
                for entry in std::fs::read_dir(&archive.path).map_err(failed)? {
                    if entry.map_err(failed)?.file_name()
                        != OsStr::new("windows-startup-original.lnk")
                    {
                        return Err(JournalError::Conflict);
                    }
                }
            }
            Ok(archive)
        })?;
        let startup = StartupLinkCustody::reopen(
            owner.clone(),
            maintenance,
            StartupOriginal {
                transaction: prepared.intent().transaction_id.clone(),
                config_root: prepared.intent().config_root.clone(),
                startup_directory: PathBuf::from(&checkpoint.startup_directory),
                original: checkpoint.original_link.clone(),
                bytes: raw.to_vec(),
                target: checkpoint.target.clone(),
                arguments: checkpoint.arguments.clone(),
                working_directory: checkpoint.working_directory.clone(),
                checkpoint_boot,
            },
            archive,
            observation,
        )?;
        let this = Self {
            startup,
            service_root: host.inner.clone(),
            service,
        };
        this.validate(journal, prepared, maintenance, observation, candidate)?;
        Ok(this)
    }
    fn validate(
        &self,
        journal: &OwnedManagementJournal,
        prepared: &PreparedLegacyOwnerRecovery,
        maintenance: &ConfigurationMaintenance,
        observation: &WindowsLegacyObservation,
        candidate: &VerifiedNativeRelease,
    ) -> JournalResult<()> {
        journal.validate_legacy_owner_prepared(maintenance, prepared)?;
        if !journal.owner_recovery_prepared_matches(prepared)
            || prepared.intent().schema != 3
            || !self.startup.matches_prepared(prepared)
        {
            return Err(JournalError::Conflict);
        }
        candidate_matches(
            candidate,
            prepared.intent().candidate_manifest_sha256,
            prepared.intent().publisher_spki_sha256,
        )?;
        let service = self
            .service_root
            .read_raw(Path::new("service.json"), 32768)
            .map_err(failed)?;
        if service.observation() != self.service.observation()
            || service.bytes() != self.service.bytes()
        {
            return Err(JournalError::Conflict);
        }
        observation.checkpoint().map_err(failed)?;
        match prepared.stage() {
            Some(OwnerRecoveryStage::Prepared) => {
                if prepared.startup_post().is_some() || prepared.boot_observation().is_some() {
                    return Err(JournalError::Conflict);
                }
            }
            Some(
                OwnerRecoveryStage::RestartExcluded
                | OwnerRecoveryStage::BootObserved
                | OwnerRecoveryStage::Archived
                | OwnerRecoveryStage::GuardsHeld,
            ) => {
                if self.startup.location() != StartupLocation::Archived
                    || prepared.startup_post()
                        != Some(&self.startup.validate_excluded(maintenance, observation)?)
                {
                    return Err(JournalError::Conflict);
                }
            }
            None => return Err(JournalError::Conflict),
        }
        if let Some(boot) = prepared.boot_observation() {
            let now = self
                .startup
                .observe_later_boot_while_excluded(maintenance, observation)?;
            admitted_boot(boot, now)?;
        }
        Ok(())
    }
    /// Exactly one no-replace rename, or observation of the original rename
    /// already completed before a lost record. A failed record retains self;
    /// caller resyncs the SAME journal before calling again.
    pub(in crate::store) fn exclude_and_record(
        &mut self,
        journal: &mut OwnedManagementJournal,
        prepared: &PreparedLegacyOwnerRecovery,
        maintenance: &ConfigurationMaintenance,
        observation: &WindowsLegacyObservation,
        candidate: &VerifiedNativeRelease,
    ) -> JournalResult<PreparedLegacyOwnerRecovery> {
        self.validate(journal, prepared, maintenance, observation, candidate)?;
        if prepared.stage() != Some(OwnerRecoveryStage::Prepared) {
            return journal
                .resync_legacy_owner_recovery(maintenance, &prepared.intent().transaction_id);
        }
        let post = self.startup.exclude(maintenance, observation)?;
        // Exclusion validates original handles and flushes both directories.
        // No source delete / name-based relaunch / inferred cleanup acknowledgement.
        journal.record_legacy_restart_excluded(maintenance, prepared, post)
    }
    /// Read-only native boot observation followed by the original phase append.
    /// This never initiates reboot or calls any installer. Business Unknown stays.
    pub(in crate::store) fn observe_boot_and_record(
        &self,
        journal: &mut OwnedManagementJournal,
        prepared: &PreparedLegacyOwnerRecovery,
        maintenance: &ConfigurationMaintenance,
        observation: &WindowsLegacyObservation,
        candidate: &VerifiedNativeRelease,
    ) -> JournalResult<PreparedLegacyOwnerRecovery> {
        self.validate(journal, prepared, maintenance, observation, candidate)?;
        if prepared.stage() == Some(OwnerRecoveryStage::Prepared) {
            return Err(JournalError::Conflict);
        }
        let now = self
            .startup
            .observe_later_boot_while_excluded(maintenance, observation)?;
        if prepared.stage() != Some(OwnerRecoveryStage::RestartExcluded) {
            return journal
                .resync_legacy_owner_recovery(maintenance, &prepared.intent().transaction_id);
        }
        let checkpoint = prepared
            .startup_checkpoint()
            .ok_or(JournalError::Conflict)?;
        // Reused PIDs from the new boot are allowed; the original exact births
        // must not remain. Birth ordering is never used to infer App ownership.
        for process in [&checkpoint.app, &checkpoint.core] {
            if let Some(ProcessIdentity::Windows {
                creation_time_100ns,
                ..
            }) = ffi::process_optional(process.pid).map_err(failed)?
            {
                if creation_time_100ns == process.birth_filetime {
                    return Err(JournalError::Conflict);
                }
            }
        }
        journal.record_legacy_boot_observed(
            maintenance,
            prepared,
            RecoveryBoot {
                id: format!("wmi-lastboot-unix-micros:{}", now.unix_micros),
                started_at_ms: now.unix_micros / 1000,
            },
        )
    }
    /// Transfer the SAME original writer/fence AND Startup handle into the C
    /// effect. On failure all are returned in WindowsRecoveryOpenFailure.
    /// Caller then uses existing resume_prepared (BootObserved→archive→guards),
    /// retaining that actual effect object through retirement/cutover settlement.
    pub(in crate::store) fn into_recovery(
        self,
        journal: &OwnedManagementJournal,
        prepared: &PreparedLegacyOwnerRecovery,
        owner: OwnedConfigurationRoot,
        maintenance: ConfigurationMaintenance,
        observation: &WindowsLegacyObservation,
        candidate: &VerifiedNativeRelease,
        host: &PrivateRoot,
        successor: &NativeRetirementIntent,
    ) -> std::result::Result<WindowsBootRecoveryEffects, Box<WindowsRecoveryOpenFailure>> {
        if let Err(error) = self.validate(journal, prepared, &maintenance, observation, candidate) {
            return Err(Box::new(WindowsRecoveryOpenFailure {
                error,
                owner,
                maintenance,
                startup: Some(self.startup),
            }));
        }
        WindowsBootRecoveryEffects::from_authorized_prepared_inner(
            journal,
            prepared,
            owner,
            maintenance,
            observation,
            candidate,
            host,
            successor,
            Some(self.startup),
        )
    }
}
