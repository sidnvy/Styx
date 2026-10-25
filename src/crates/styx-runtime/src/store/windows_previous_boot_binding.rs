//! Opaque same-journal consumer. No DTO can independently enter OS effects.
use super::*;
use crate::{
    release::VerifiedNativeRelease,
    store::management::{
        OwnedManagementJournal,
        handoff::{
            LegacyGuardsHeld, LegacyOwnerRecoveryIntent, NativeRetirementFileStamp,
            NativeRetirementIntent, OwnerRecoveryStage, PreparedLegacyOwnerRecovery, RecoveryBasis,
            RecoveryBoot, RecoveryGuard, RecoveryGuardBinding, RecoveryGuardName,
            RecoveryGuardPost, RecoveryKind, RecoveryOriginal, RecoveryOriginalBinding,
            RecoveryOriginalName, RecoveryOriginalPost, RecoveryRestartBinding,
        },
    },
};
use styx_contracts::native_management::NativeRootIdentity;

fn root_native(root: RootIdentity) -> JournalResult<NativeRootIdentity> {
    match root {
        RootIdentity::Windows {
            volume_serial,
            file_id,
            owner_sid,
        } => Ok(NativeRootIdentity::Windows {
            volume_serial,
            file_id,
            owner_sid,
        }),
        _ => Err(JournalError::Conflict),
    }
}
fn original_raw(
    original: &crate::store::management::handoff::RecoveryOriginal,
    root: &NativeRootIdentity,
) -> JournalResult<RawFile> {
    let NativeRetirementFileStamp::Windows {
        volume_serial,
        file_id,
        owner_sid,
        nlink,
        byte_len,
        modified_seconds,
        modified_nanoseconds,
        changed_seconds,
        changed_nanoseconds,
        sha256,
    } = &original.stamp
    else {
        return Err(JournalError::Conflict);
    };
    let NativeRootIdentity::Windows {
        owner_sid: expected_sid,
        ..
    } = root
    else {
        return Err(JournalError::Conflict);
    };
    if owner_sid != expected_sid
        || *nlink != 1
        || *byte_len != original.raw.len() as u64
        || *byte_len > 4096
        || Sha256Digest::of_bytes(&original.raw) != *sha256
    {
        return Err(JournalError::Conflict);
    }
    Ok(RawFile {
        relative_path: PathBuf::from(original.name.source_name()),
        bytes: original.raw.clone(),
        sha256: sha256.to_hex(),
        observation: FileObservation {
            device: *volume_serial,
            inode: *file_id,
            byte_len: *byte_len,
            modified_seconds: *modified_seconds,
            modified_nanoseconds: *modified_nanoseconds,
            changed_seconds: *changed_seconds,
            changed_nanoseconds: *changed_nanoseconds,
        },
    })
}
fn native_stamp(file: &File, raw: &[u8]) -> JournalResult<NativeRetirementFileStamp> {
    let before = private_facts(file, false).map_err(failed)?;
    let sid = ffi::private(file).map_err(failed)?;
    let actual = read_pin(file, raw)?;
    if before.observation != actual || before.links != 1 {
        return Err(JournalError::Conflict);
    }
    Ok(NativeRetirementFileStamp::Windows {
        volume_serial: actual.device,
        file_id: actual.inode,
        owner_sid: sid,
        nlink: u64::from(before.links),
        byte_len: actual.byte_len,
        modified_seconds: actual.modified_seconds,
        modified_nanoseconds: actual.modified_nanoseconds,
        changed_seconds: actual.changed_seconds,
        changed_nanoseconds: actual.changed_nanoseconds,
        sha256: Sha256Digest::of_bytes(raw),
    })
}
/// Preserve the original admission epoch in the journal. A later real OS boot
/// may resume the SAME effects, but cannot rewrite their history or old facts.
fn admitted_boot(original: &RecoveryBoot, now: BootStamp) -> JournalResult<BootStamp> {
    let suffix = original
        .id
        .strip_prefix("wmi-lastboot-unix-micros:")
        .ok_or(JournalError::Conflict)?;
    let micros: u64 = suffix.parse().map_err(failed)?;
    if micros == 0 || suffix != micros.to_string() || original.started_at_ms != micros / 1000 {
        return Err(JournalError::Conflict);
    }
    let admitted = BootStamp {
        unix_micros: micros,
    };
    if now != admitted && !now.definitely_after_old_ms(original.started_at_ms) {
        return Err(JournalError::Conflict);
    }
    Ok(admitted)
}
fn candidate_matches(
    candidate: &VerifiedNativeRelease,
    manifest: Sha256Digest,
    publisher: Sha256Digest,
) -> JournalResult<()> {
    candidate.revalidate().map_err(failed)?;
    let report = candidate.report();
    if report.scope != "runtime_candidate"
        || report.target != "x86_64-pc-windows-msvc"
        || report.manifest_sha256 != manifest
        || Sha256Digest::try_from(report.publisher_spki_sha256.clone()).map_err(failed)?
            != publisher
    {
        return Err(JournalError::Conflict);
    }
    Ok(())
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsServiceDescriptor {
    task_name: String,
    install_root: PathBuf,
    host_config_file: PathBuf,
    publisher_key_file: PathBuf,
    node_binary: PathBuf,
}
fn service_binding(
    host: &PrivateRoot,
    successor: &NativeRetirementIntent,
    observation: &WindowsLegacyObservation,
) -> JournalResult<RawFile> {
    if root_native(host.identity())? != successor.host_root {
        return Err(JournalError::Conflict);
    }
    let raw = host.read_raw("service.json", 32768).map_err(failed)?;
    if Sha256Digest::of_bytes(raw.bytes()) != successor.service_descriptor_sha256 {
        return Err(JournalError::Conflict);
    }
    let descriptor: WindowsServiceDescriptor =
        serde_json::from_slice(raw.bytes()).map_err(failed)?;
    if descriptor.task_name != observation.task_name()
        || [
            &descriptor.install_root,
            &descriptor.host_config_file,
            &descriptor.publisher_key_file,
            &descriptor.node_binary,
        ]
        .iter()
        .any(|p| !p.is_absolute())
    {
        return Err(JournalError::Conflict);
    }
    observation.checkpoint().map_err(failed)?;
    Ok(raw)
}
/// Constructor failures preserve the SAME writer and active maintenance fence.
/// This is local error custody, never a deserializable management authority.
pub(in crate::store) struct WindowsRecoveryOpenFailure {
    pub(in crate::store) error: JournalError,
    pub(in crate::store) owner: OwnedConfigurationRoot,
    pub(in crate::store) maintenance: ConfigurationMaintenance,
    pub(in crate::store) startup: Option<StartupLinkCustody>,
}
impl WindowsBootRecoveryEffects {
    /// Borrow the original active fence for the next SAME-journal retirement.
    /// Caller retains this effect owner through retirement and cutover settlement.
    pub(in crate::store) fn maintenance(&self) -> &ConfigurationMaintenance {
        &self.maintenance
    }
    pub(in crate::store) fn validate_guards(
        &self,
        observation: &WindowsLegacyObservation,
    ) -> JournalResult<()> {
        if !self.completed {
            return Err(JournalError::Conflict);
        }
        self.validate_context(observation)?;
        self.observe_complete(observation)
    }
    /// First durable same-journal pre-stage. The caller supplies the original
    /// protected Host selected by the trusted migration profile. This descriptor
    /// selects only the fixed task observation, never an executable or new path.
    /// Original installation admission must already be foreground-only; a task
    /// absence observation is not a claim about arbitrary external services.
    pub(in crate::store) fn prepare_previous_boot(
        journal: &mut OwnedManagementJournal,
        owner: &OwnedConfigurationRoot,
        maintenance: &ConfigurationMaintenance,
        host: &PrivateRoot,
        observation: &WindowsLegacyObservation,
        candidate: &VerifiedNativeRelease,
        successor: &NativeRetirementIntent,
    ) -> JournalResult<PreparedLegacyOwnerRecovery> {
        candidate_matches(
            candidate,
            successor.candidate_manifest_sha256,
            successor.publisher_spki_sha256,
        )?;
        let service = service_binding(host, successor, observation)?;
        if successor.schema != 3 || maintenance.transaction_id() != &successor.transaction_id {
            return Err(JournalError::Conflict);
        }
        let evidence = owner.with_maintenance(maintenance, |state| {
            if root_native(state.root.identity())? != successor.config_root {
                return Err(JournalError::Conflict);
            }
            let before = state
                .root
                .read_raw("state.json", 1024 * 1024)
                .map_err(failed)?;
            if Sha256Digest::of_bytes(before.bytes()) != successor.before_state_sha256 {
                return Err(JournalError::Conflict);
            }
            state.root.inner.previous_boot_evidence(observation)
        })?;
        if Sha256Digest::of_bytes(evidence.originals[0].bytes()) != successor.deployment_raw_sha256
        {
            return Err(JournalError::Conflict);
        }
        let old = validate_owner_receipt(
            &evidence.originals[0],
            &evidence.originals[1],
            &evidence.originals[2],
            evidence.current_boot,
        )?;
        let mut originals = Vec::new();
        for name in [
            RecoveryOriginalName::Lock,
            RecoveryOriginalName::Owner,
            RecoveryOriginalName::Observer,
        ] {
            let Some(raw) = evidence
                .originals
                .iter()
                .find(|r| r.relative_path() == Path::new(name.source_name()))
            else {
                continue;
            };
            let pin = ffi::open(
                &evidence.root.path.join(name.source_name()),
                false,
                false,
                false,
            )
            .map_err(failed)?;
            if read_pin(&pin, raw.bytes())? != *raw.observation() {
                return Err(JournalError::Conflict);
            }
            originals.push(RecoveryOriginal {
                name,
                raw: raw.bytes().to_vec(),
                stamp: native_stamp(&pin, raw.bytes())?,
            });
        }
        // Opaque random bytes match the existing guards' exclusive-file contract;
        // neither a PID nor a deserializable token grants migration authority.
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
            schema: 1,
            startup_checkpoint: None,
            kind: RecoveryKind::LegacyOwnerRecovery,
            transaction_id: successor.transaction_id.clone(),
            sequence: successor.sequence,
            config_root: successor.config_root.clone(),
            deployment_raw_sha256: successor.deployment_raw_sha256,
            before_state_sha256: successor.before_state_sha256,
            candidate_manifest_sha256: successor.candidate_manifest_sha256,
            publisher_spki_sha256: successor.publisher_spki_sha256,
            previous_boot: Some(RecoveryBoot {
                id: old.boot.id,
                started_at_ms: old.boot.started_at,
            }),
            basis: None,
            current_boot: RecoveryBoot {
                id: format!(
                    "wmi-lastboot-unix-micros:{}",
                    evidence.current_boot.unix_micros
                ),
                started_at_ms: evidence.current_boot.unix_micros / 1000,
            },
            restart: RecoveryRestartBinding::ForegroundOnlyNoInstalledManager,
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
        };
        evidence.revalidate(observation)?;
        let current_service = service_binding(host, successor, observation)?;
        if current_service.observation() != service.observation()
            || current_service.bytes() != service.bytes()
        {
            return Err(JournalError::Conflict);
        }
        candidate_matches(
            candidate,
            intent.candidate_manifest_sha256,
            intent.publisher_spki_sha256,
        )?;
        journal.prepare_legacy_owner_recovery(maintenance, &intent, originals, guards)
    }
    /// Reconstruct only from the original immutable attachments under the SAME
    /// retained journal writer. Live source files may already have moved.
    pub(in crate::store) fn from_prepared(
        journal: &OwnedManagementJournal,
        prepared: &PreparedLegacyOwnerRecovery,
        owner: OwnedConfigurationRoot,
        maintenance: ConfigurationMaintenance,
        observation: &WindowsLegacyObservation,
        candidate: &VerifiedNativeRelease,
        host: &PrivateRoot,
        successor: &NativeRetirementIntent,
    ) -> std::result::Result<Self, Box<WindowsRecoveryOpenFailure>> {
        let result = (|| -> JournalResult<(WindowsPreviousBootEvidence, Vec<u8>, RawFile)> {
            journal.validate_legacy_owner_prepared(&maintenance, prepared)?;
            if !journal.owner_recovery_prepared_matches(prepared)
                || !prepared.matches_owner(&owner)
                || maintenance.transaction_id() != &prepared.intent().transaction_id
            {
                return Err(JournalError::Conflict);
            }
            let intent = prepared.intent();
            candidate_matches(
                candidate,
                intent.candidate_manifest_sha256,
                intent.publisher_spki_sha256,
            )?;
            if Sha256Digest::of_bytes(&serde_json::to_vec(successor).map_err(failed)?)
                != intent.successor_retirement_intent_sha256
            {
                return Err(JournalError::Conflict);
            }
            let service = service_binding(host, successor, observation)?;
            let (root, deployment) = owner.with_maintenance(&maintenance, |state| {
                if root_native(state.root.identity())? != intent.config_root {
                    return Err(JournalError::Conflict);
                }
                let deployment = state
                    .root
                    .read_raw("deployment.json", 1024 * 1024)
                    .map_err(failed)?;
                if Sha256Digest::of_bytes(deployment.bytes()) != intent.deployment_raw_sha256 {
                    return Err(JournalError::Conflict);
                }
                Ok((state.root.inner.clone(), deployment))
            })?;
            let now = observation.checkpoint().map_err(failed)?;
            let original_admission_boot = admitted_boot(&intent.current_boot, now)?;
            let original_owner = prepared
                .originals()
                .iter()
                .find(|o| o.name == RecoveryOriginalName::Owner)
                .ok_or(JournalError::Conflict)?;
            let original_lock = prepared
                .originals()
                .iter()
                .find(|o| o.name == RecoveryOriginalName::Lock)
                .ok_or(JournalError::Conflict)?;
            let owner_raw = original_raw(original_owner, &intent.config_root)?;
            let lock_raw = original_raw(original_lock, &intent.config_root)?;
            let receipt = validate_owner_receipt(
                &deployment,
                &owner_raw,
                &lock_raw,
                original_admission_boot,
            )?;
            let previous = intent
                .previous_boot
                .as_ref()
                .ok_or(JournalError::Conflict)?;
            if intent.schema != 1
                || intent.basis.is_some()
                || previous.id != receipt.boot.id
                || previous.started_at_ms != receipt.boot.started_at
            {
                return Err(JournalError::Conflict);
            }
            let mut originals = vec![deployment, owner_raw, lock_raw];
            if let Some(original) = prepared
                .originals()
                .iter()
                .find(|o| o.name == RecoveryOriginalName::Observer)
            {
                let raw = original_raw(original, &intent.config_root)?;
                before_boot(&raw, original_admission_boot)?;
                let v: serde_json::Value = serde_json::from_slice(raw.bytes()).map_err(failed)?;
                if v.get("pid").and_then(|v| v.as_u64()) != Some(u64::from(receipt.pid))
                    || v.get("configurationHash").and_then(|v| v.as_str())
                        != Some(receipt.configuration_hash.as_str())
                    || v.get("lock")
                        .and_then(|v| v.get("sha256"))
                        .and_then(|v| v.as_str())
                        != Some(receipt.lock.sha256.as_str())
                {
                    return Err(JournalError::Conflict);
                }
                originals.push(raw);
            }
            let guard = prepared
                .guard_bytes()
                .first()
                .ok_or(JournalError::Conflict)?;
            if prepared.guard_bytes().len() != 4
                || prepared.guard_bytes().iter().any(|g| g.raw != guard.raw)
            {
                return Err(JournalError::Conflict);
            }
            // The producer chooses one random original ownership record for all four
            // fixed guards. No caller-selected guard path/bytes enter this consumer.
            let evidence = WindowsPreviousBootEvidence {
                root,
                originals,
                current_boot: now,
            };
            if guard.raw.is_empty() || guard.raw.len() > 4096 {
                return Err(JournalError::Conflict);
            }
            Ok((evidence, guard.raw.clone(), service))
        })();
        match result {
            Ok((evidence, guard_bytes, service)) => Ok(Self {
                evidence,
                owner,
                maintenance,
                transaction: prepared.intent().transaction_id.clone(),
                guard_bytes,
                archive: None,
                service: Some((host.inner.clone(), service)),
                legacy_identity: None,
                startup: None,
                original_pins: Vec::new(),
                created: Vec::new(),
                attempted: false,
                archived: false,
                guards_attempted: false,
                marker_retired: false,
                completed: false,
            }),
            Err(error) => Err(Box::new(WindowsRecoveryOpenFailure {
                error,
                owner,
                maintenance,
                startup: None,
            })),
        }
    }
    fn match_prepared(
        &self,
        journal: &OwnedManagementJournal,
        prepared: &PreparedLegacyOwnerRecovery,
    ) -> JournalResult<()> {
        journal.validate_legacy_owner_prepared(&self.maintenance, prepared)?;
        if !journal.owner_recovery_prepared_matches(prepared)
            || !prepared.matches_owner(&self.owner)
            || prepared.intent().transaction_id != self.transaction
            || prepared
                .guard_bytes()
                .iter()
                .any(|g| g.raw != self.guard_bytes)
            || prepared.originals().len() != self.evidence.originals.len() - 1
        {
            return Err(JournalError::Conflict);
        }
        for original in prepared.originals() {
            let expected = original_raw(original, &prepared.intent().config_root)?;
            let saved = self
                .evidence
                .originals
                .iter()
                .find(|r| r.relative_path() == expected.relative_path())
                .ok_or(JournalError::Conflict)?;
            if saved.observation() != expected.observation() || saved.bytes() != expected.bytes() {
                return Err(JournalError::Conflict);
            }
        }
        Ok(())
    }
    fn archive_posts(
        &self,
        prepared: &PreparedLegacyOwnerRecovery,
    ) -> JournalResult<Vec<RecoveryOriginalPost>> {
        prepared
            .originals()
            .iter()
            .map(|original| {
                let pin = self
                    .original_pins
                    .iter()
                    .find(|pin| {
                        self.evidence.originals[pin.index].relative_path()
                            == Path::new(original.name.source_name())
                    })
                    .ok_or(JournalError::Unknown)?;
                Ok(RecoveryOriginalPost {
                    name: original.name,
                    stamp: native_stamp(
                        pin.handle.as_ref().ok_or(JournalError::Unknown)?,
                        &original.raw,
                    )?,
                })
            })
            .collect()
    }
    fn guard_posts(
        &self,
        prepared: &PreparedLegacyOwnerRecovery,
    ) -> JournalResult<Vec<RecoveryGuardPost>> {
        prepared
            .guard_bytes()
            .iter()
            .map(|original| {
                let pin = self
                    .created
                    .iter()
                    .find(|pin| pin.name == original.name.source_name())
                    .ok_or(JournalError::Unknown)?;
                Ok(RecoveryGuardPost {
                    name: original.name,
                    stamp: native_stamp(
                        pin.handle.as_ref().ok_or(JournalError::Unknown)?,
                        &original.raw,
                    )?,
                })
            })
            .collect()
    }
    /// First attempt. Original phase and OS object remain owned by caller on
    /// Unknown. A failed append is resolved using journal resync, never replay.
    pub(in crate::store) fn apply_prepared(
        &mut self,
        journal: &mut OwnedManagementJournal,
        prepared: PreparedLegacyOwnerRecovery,
        observation: &WindowsLegacyObservation,
        candidate: &VerifiedNativeRelease,
    ) -> JournalResult<LegacyGuardsHeld> {
        candidate_matches(
            candidate,
            prepared.intent().candidate_manifest_sha256,
            prepared.intent().publisher_spki_sha256,
        )?;
        self.match_prepared(journal, &prepared)?;
        if prepared.intent().schema == 3 || prepared.stage() != Some(OwnerRecoveryStage::Prepared) {
            return Err(JournalError::Conflict);
        }
        self.execute_archive(observation)?;
        let archived = journal.record_legacy_owner_archived(
            &self.maintenance,
            &prepared,
            self.archive_posts(&prepared)?,
        )?;
        self.finish_guards(observation)?;
        let result = journal.record_legacy_guards_held(
            &self.maintenance,
            &archived,
            self.guard_posts(archived.prepared())?,
        )?;
        self.observe_complete(observation)?;
        Ok(result)
    }
    /// Explicit recovered Prepared/Archived/GuardsHeld from the same journal.
    /// Completed items are re-pinned; only proven pending items execute. A fully
    /// recorded GuardsHeld may only be reobserved, never recreate missing files.
    pub(in crate::store) fn resume_prepared(
        &mut self,
        journal: &mut OwnedManagementJournal,
        prepared: PreparedLegacyOwnerRecovery,
        observation: &WindowsLegacyObservation,
        candidate: &VerifiedNativeRelease,
    ) -> JournalResult<LegacyGuardsHeld> {
        candidate_matches(
            candidate,
            prepared.intent().candidate_manifest_sha256,
            prepared.intent().publisher_spki_sha256,
        )?;
        self.match_prepared(journal, &prepared)?;
        let stage = prepared.stage().ok_or(JournalError::Conflict)?;
        let ready_stage = if prepared.intent().schema == 3 {
            let startup = self.startup.as_ref().ok_or(JournalError::Conflict)?;
            if !startup.matches_prepared(&prepared)
                || prepared.startup_post()
                    != Some(&startup.validate_excluded(&self.maintenance, observation)?)
                || !matches!(
                    stage,
                    OwnerRecoveryStage::BootObserved
                        | OwnerRecoveryStage::Archived
                        | OwnerRecoveryStage::GuardsHeld
                )
            {
                return Err(JournalError::Conflict);
            }
            startup.observe_later_boot_while_excluded(&self.maintenance, observation)?;
            OwnerRecoveryStage::BootObserved
        } else {
            if self.startup.is_some()
                || !matches!(
                    stage,
                    OwnerRecoveryStage::Prepared
                        | OwnerRecoveryStage::Archived
                        | OwnerRecoveryStage::GuardsHeld
                )
            {
                return Err(JournalError::Conflict);
            }
            OwnerRecoveryStage::Prepared
        };
        if stage == OwnerRecoveryStage::GuardsHeld {
            // Require the completed marker and archive BEFORE any ensure/create.
            let archive = self
                .evidence
                .root
                .journal_directory("foreground-recovery")
                .map_err(failed)?;
            let archive = Root::from_directory_handle(&archive).map_err(failed)?;
            let tx = archive
                .journal_directory(self.transaction.as_str())
                .map_err(failed)?;
            let tx = Root::from_directory_handle(&tx).map_err(failed)?;
            if maybe_raw(&tx, "foreground-recovery.lock.retired")?.is_none() {
                return Err(JournalError::Unknown);
            }
            self.archive = Some(tx);
        }
        self.resume_archive(observation)?;
        if stage == OwnerRecoveryStage::GuardsHeld {
            self.observe_complete(observation)?;
            return prepared.into_guards_held();
        }
        let archived = if stage == ready_stage {
            journal.record_legacy_owner_archived(
                &self.maintenance,
                &prepared,
                self.archive_posts(&prepared)?,
            )?
        } else {
            prepared.into_archived()?
        };
        if !self.completed {
            self.resume_guards(observation)?;
        }
        let result = journal.record_legacy_guards_held(
            &self.maintenance,
            &archived,
            self.guard_posts(archived.prepared())?,
        )?;
        self.observe_complete(observation)?;
        Ok(result)
    }
}

#[cfg(test)]
#[path = "windows_previous_boot_recovery_tests.rs"]
mod tests;

#[path = "windows_legacy_maintenance.rs"]
mod legacy;
pub(in crate::store) use legacy::{WindowsLegacyMaintenancePlan, WindowsRestartCheckpoint};
