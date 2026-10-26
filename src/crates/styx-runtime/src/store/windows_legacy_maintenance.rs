//! Explicit maintenance for pre-owner-receipt installations. The review body is
//! the existing planLegacyForegroundRecovery body, not a new grant or ledger.
//! Observer PID absence is only one negative fact, never tree settlement.
use super::*;
use serde::{Deserialize, Serialize};
use styx_contracts::identity::DeviceId;

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PlanBoot {
    platform: String,
    id: String,
    started_at: u64,
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PlanFile {
    name: String,
    ino: String,
    dev: String,
    sha256: Sha256Digest,
    modified_at: u64,
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PlanBody {
    schema: u16,
    action: String,
    state_dir: String,
    device_id: DeviceId,
    identity_sha256: Sha256Digest,
    configuration_hash: Sha256Digest,
    current_boot: PlanBoot,
    previous_owner_pid: u32,
    files: Vec<PlanFile>,
    previous_work_outcome: String,
    identity_mutation: String,
    requires_explicit_authorization: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    startup_checkpoint_sha256: Option<Sha256Digest>,
}
fn millis(raw: &RawFile) -> JournalResult<u64> {
    let stamp = raw.observation();
    filetime_projection::unix_millis_js(stamp.modified_seconds, stamp.modified_nanoseconds)
        .ok_or(JournalError::Conflict)
}

fn plan_file(raw: &RawFile) -> JournalResult<PlanFile> {
    Ok(PlanFile {
        name: raw
            .relative_path()
            .to_str()
            .ok_or(JournalError::Conflict)?
            .to_owned(),
        ino: raw.observation().inode.to_string(),
        dev: raw.observation().device.to_string(),
        sha256: Sha256Digest::of_bytes(raw.bytes()),
        modified_at: millis(raw)?,
    })
}
fn observer(raw: &RawFile, lock: &RawFile, configuration_hash: Sha256Digest) -> JournalResult<u32> {
    let value: serde_json::Value = serde_json::from_slice(raw.bytes()).map_err(failed)?;
    let pid = value
        .get("pid")
        .and_then(|v| v.as_u64())
        .and_then(|v| u32::try_from(v).ok())
        .filter(|p| *p != 0)
        .ok_or(JournalError::Conflict)?;
    if value.get("configurationHash").and_then(|v| v.as_str())
        != Some(configuration_hash.to_hex().as_str())
        || value
            .get("lock")
            .and_then(|v| v.get("sha256"))
            .and_then(|v| v.as_str())
            != Some(Sha256Digest::of_bytes(lock.bytes()).to_hex().as_str())
    {
        return Err(JournalError::Conflict);
    }
    // Original NTFS ino in this old observer can be a rounded JS Number. It is
    // deliberately NOT converted back to an identity: retained OS stamps bind
    // both exact files, while the observer only binds its original lock hash.
    Ok(pid)
}
fn require_observer_absent(pid: u32) -> JournalResult<()> {
    match ffi::process_optional(pid).map_err(failed)? {
        None => Ok(()),
        Some(_) => Err(JournalError::Conflict),
    }
}
fn identity(host: &PrivateRoot) -> JournalResult<(RawFile, DeviceId)> {
    let raw = host
        .read_raw("device/identity.json", 32768)
        .map_err(failed)?;
    let value: serde_json::Value = serde_json::from_slice(raw.bytes()).map_err(failed)?;
    let id = value
        .get("device_id")
        .and_then(|v| v.as_str())
        .ok_or(JournalError::Conflict)?;
    let id = DeviceId::try_from(id).map_err(failed)?;
    Ok((raw, id))
}
/// Read-only retained plan. No Clone/Deserialize; serialized review bytes alone
/// neither admit a manager nor prove the original App's actual maintenance exit.
pub(in crate::store) struct WindowsLegacyMaintenancePlan {
    evidence: WindowsPreviousBootEvidence,
    host: Root,
    identity: RawFile,
    service: RawFile,
    body: PlanBody,
    raw: Vec<u8>,
    digest: Sha256Digest,
}
impl WindowsLegacyMaintenancePlan {
    pub(in crate::store) fn review_bytes(&self) -> &[u8] {
        &self.raw
    }
    /// Same old planSha256 meaning: compact ordered body bytes, without adding
    /// the derived planSha256 property to its own hash input.
    pub(in crate::store) fn plan_sha256(&self) -> Sha256Digest {
        self.digest
    }
    pub(in crate::store) fn capture(
        owner: &OwnedConfigurationRoot,
        maintenance: &ConfigurationMaintenance,
        host: &PrivateRoot,
        observation: &WindowsLegacyObservation,
        successor: &NativeRetirementIntent,
    ) -> JournalResult<Self> {
        let service = service_binding(host, successor, observation)?;
        let boot = observation.checkpoint().map_err(failed)?;
        let (root, deployment, lock, observer_raw) =
            owner.with_maintenance(maintenance, |state| {
                if root_native(state.root.identity())? != successor.config_root
                    || maintenance.transaction_id() != &successor.transaction_id
                {
                    return Err(JournalError::Conflict);
                }
                state
                    .root
                    .ensure_absent("foreground-owner.json")
                    .map_err(failed)?;
                state
                    .root
                    .ensure_absent("foreground-recovery.lock")
                    .map_err(failed)?;
                let deployment = state
                    .root
                    .read_raw("deployment.json", 1024 * 1024)
                    .map_err(failed)?;
                let before = state
                    .root
                    .read_raw("state.json", 1024 * 1024)
                    .map_err(failed)?;
                if Sha256Digest::of_bytes(deployment.bytes()) != successor.deployment_raw_sha256
                    || Sha256Digest::of_bytes(before.bytes()) != successor.before_state_sha256
                {
                    return Err(JournalError::Conflict);
                }
                Ok((
                    state.root.inner.clone(),
                    deployment,
                    state
                        .root
                        .read_raw("foreground.lock", 4096)
                        .map_err(failed)?,
                    state
                        .root
                        .read_raw("foreground-observer.json", 4096)
                        .map_err(failed)?,
                ))
            })?;
        // Match the protected deployment's actual Host root by native identity,
        // not lexical case conversion or a caller-supplied replacement locator.
        let config: serde_json::Value =
            serde_json::from_slice(deployment.bytes()).map_err(failed)?;
        let host_path = config
            .get("host")
            .and_then(|v| v.get("baseDir"))
            .and_then(|v| v.as_str())
            .ok_or(JournalError::Conflict)?;
        if PrivateRoot::open(host_path).map_err(failed)?.identity() != host.identity() {
            return Err(JournalError::Conflict);
        }
        let configuration_hash =
            styx_contracts::legacy_deployment::deployment_connection_hash(deployment.bytes())
                .map_err(failed)?;
        let pid = observer(&observer_raw, &lock, configuration_hash)?;
        before_boot(&lock, boot)?;
        before_boot(&observer_raw, boot)?;
        require_observer_absent(pid)?;
        let (identity, device_id) = identity(host)?;
        let body = PlanBody {
            schema: 1,
            action: "retire_legacy_foreground_owner".into(),
            state_dir: root.path.to_str().ok_or(JournalError::Conflict)?.into(),
            device_id,
            identity_sha256: Sha256Digest::of_bytes(identity.bytes()),
            configuration_hash,
            current_boot: PlanBoot {
                platform: "win32".into(),
                id: format!("wmi-lastboot-unix-micros:{}", boot.unix_micros),
                started_at: boot.unix_micros / 1000,
            },
            previous_owner_pid: pid,
            files: vec![plan_file(&lock)?, plan_file(&observer_raw)?],
            previous_work_outcome: "unknown_not_replayed".into(),
            identity_mutation: "none".into(),
            requires_explicit_authorization: true,
            startup_checkpoint_sha256: None,
        };
        let raw = serde_json::to_vec(&body).map_err(failed)?;
        let digest = Sha256Digest::of_bytes(&raw);
        let plan = Self {
            evidence: WindowsPreviousBootEvidence {
                root,
                originals: vec![deployment, lock, observer_raw],
                current_boot: boot,
            },
            host: host.inner.clone(),
            identity,
            service,
            body,
            raw,
            digest,
        };
        plan.revalidate(observation)?;
        Ok(plan)
    }
    pub(in crate::store) fn revalidate_review(
        &self,
        approved_sha256: Sha256Digest,
        observation: &WindowsLegacyObservation,
    ) -> JournalResult<()> {
        if approved_sha256 != self.digest {
            return Err(JournalError::Conflict);
        }
        self.revalidate(observation)
    }
    pub(in crate::store) fn revalidate(
        &self,
        observation: &WindowsLegacyObservation,
    ) -> JournalResult<()> {
        self.evidence.revalidate(observation)?;
        self.evidence
            .root
            .ensure_absent(Path::new("foreground-owner.json"))
            .map_err(failed)?;
        self.evidence
            .root
            .ensure_absent(Path::new("foreground-recovery.lock"))
            .map_err(failed)?;
        for saved in [&self.identity, &self.service] {
            let now = self
                .host
                .read_raw(saved.relative_path(), saved.bytes().len())
                .map_err(failed)?;
            if now.observation() != saved.observation() || now.bytes() != saved.bytes() {
                return Err(JournalError::Conflict);
            }
        }
        let descriptor: WindowsServiceDescriptor =
            serde_json::from_slice(self.service.bytes()).map_err(failed)?;
        if descriptor.task_name != observation.task_name()
            || Sha256Digest::of_bytes(&self.raw) != self.digest
            || serde_json::to_vec(&self.body).map_err(failed)? != self.raw
        {
            return Err(JournalError::Conflict);
        }
        require_observer_absent(self.body.previous_owner_pid)?;
        observation.checkpoint().map_err(failed)?;
        Ok(())
    }
}

impl WindowsLegacyMaintenancePlan {
    /// Private durability port, called ONLY by the original management authority
    /// after it accepted this exact review hash and completed the separate legacy
    /// App maintenance-exit prerequisite. The hash is not an authentication token.
    pub(in crate::store) fn prepare_reviewed(
        &self,
        approved_plan_sha256: Sha256Digest,
        journal: &mut OwnedManagementJournal,
        owner: &OwnedConfigurationRoot,
        maintenance: &ConfigurationMaintenance,
        observation: &WindowsLegacyObservation,
        candidate: &VerifiedNativeRelease,
        successor: &NativeRetirementIntent,
    ) -> JournalResult<PreparedLegacyOwnerRecovery> {
        if approved_plan_sha256 != self.digest
            || successor.schema != 3
            || root_native(self.evidence.root.identity())? != successor.config_root
            || root_native(self.host.identity())? != successor.host_root
            || maintenance.transaction_id() != &successor.transaction_id
            || Sha256Digest::of_bytes(self.evidence.originals[0].bytes())
                != successor.deployment_raw_sha256
            || Sha256Digest::of_bytes(self.service.bytes()) != successor.service_descriptor_sha256
        {
            return Err(JournalError::Conflict);
        }
        owner.with_maintenance(maintenance, |state| {
            if state.root.identity() != self.evidence.root.identity() {
                return Err(JournalError::Conflict);
            }
            let before = state
                .root
                .read_raw("state.json", 1024 * 1024)
                .map_err(failed)?;
            if Sha256Digest::of_bytes(before.bytes()) != successor.before_state_sha256 {
                return Err(JournalError::Conflict);
            }
            Ok(())
        })?;
        self.revalidate_review(approved_plan_sha256, observation)?;
        candidate_matches(
            candidate,
            successor.candidate_manifest_sha256,
            successor.publisher_spki_sha256,
        )?;
        let mut originals = Vec::new();
        for (index, name) in [
            (1, RecoveryOriginalName::Lock),
            (2, RecoveryOriginalName::Observer),
        ] {
            let raw = &self.evidence.originals[index];
            let pin = ffi::open(
                &self.evidence.root.path.join(name.source_name()),
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
            schema: 2,
            startup_checkpoint: None,
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
                id: self.body.current_boot.id.clone(),
                started_at_ms: self.body.current_boot.started_at,
            },
            basis: Some(RecoveryBasis::ExplicitLegacyMaintenance {
                plan_sha256: self.digest,
                device_id: self.body.device_id.clone(),
                identity_json_sha256: self.body.identity_sha256,
                configuration_hash: self.body.configuration_hash,
                observer_pid: self.body.previous_owner_pid,
            }),
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
        self.revalidate(observation)?;
        journal.prepare_authorized_legacy_owner_recovery(
            maintenance,
            &intent,
            originals,
            guards,
            &self.raw,
        )
    }
}

impl WindowsBootRecoveryEffects {
    /// Restore only a durably reviewed schema2 stage. No new review or owner
    /// receipt is synthesized. The native management consumer retains its
    /// independent original-App maintenance-exit requirement on every entry.
    pub(in crate::store) fn from_authorized_prepared(
        journal: &OwnedManagementJournal,
        prepared: &PreparedLegacyOwnerRecovery,
        owner: OwnedConfigurationRoot,
        maintenance: ConfigurationMaintenance,
        observation: &WindowsLegacyObservation,
        candidate: &VerifiedNativeRelease,
        host: &PrivateRoot,
        successor: &NativeRetirementIntent,
    ) -> std::result::Result<Self, Box<WindowsRecoveryOpenFailure>> {
        Self::from_authorized_prepared_inner(
            journal,
            prepared,
            owner,
            maintenance,
            observation,
            candidate,
            host,
            successor,
            None,
        )
    }
    fn from_authorized_prepared_inner(
        journal: &OwnedManagementJournal,
        prepared: &PreparedLegacyOwnerRecovery,
        owner: OwnedConfigurationRoot,
        maintenance: ConfigurationMaintenance,
        observation: &WindowsLegacyObservation,
        candidate: &VerifiedNativeRelease,
        host: &PrivateRoot,
        successor: &NativeRetirementIntent,
        startup: Option<StartupLinkCustody>,
    ) -> std::result::Result<Self, Box<WindowsRecoveryOpenFailure>> {
        let checked =
            (|| -> JournalResult<(WindowsPreviousBootEvidence, Vec<u8>, RawFile, RawFile, u32)> {
                journal.validate_legacy_owner_prepared(&maintenance, prepared)?;
                if !journal.owner_recovery_prepared_matches(prepared)
                    || !prepared.matches_owner(&owner)
                    || maintenance.transaction_id() != &prepared.intent().transaction_id
                {
                    return Err(JournalError::Conflict);
                }
                let intent = prepared.intent();
                let Some(RecoveryBasis::ExplicitLegacyMaintenance {
                    plan_sha256,
                    device_id,
                    identity_json_sha256,
                    configuration_hash,
                    observer_pid,
                }) = &intent.basis
                else {
                    return Err(JournalError::Conflict);
                };
                let restart = if let Some(startup) = &startup {
                    if intent.schema != 3
                        || !startup.matches_prepared(prepared)
                        || !matches!(
                            prepared.stage(),
                            Some(
                                OwnerRecoveryStage::BootObserved
                                    | OwnerRecoveryStage::Archived
                                    | OwnerRecoveryStage::GuardsHeld
                            )
                        )
                        || prepared.startup_post()
                            != Some(&startup.validate_excluded(&maintenance, observation)?)
                    {
                        return Err(JournalError::Conflict);
                    }
                    let now =
                        startup.observe_later_boot_while_excluded(&maintenance, observation)?;
                    let recorded = prepared.boot_observation().ok_or(JournalError::Conflict)?;
                    admitted_boot(recorded, now)?;
                    true
                } else {
                    false
                };
                if intent.schema != if restart { 3 } else { 2 }
                    || intent.previous_boot.is_some()
                    || Sha256Digest::of_bytes(&serde_json::to_vec(successor).map_err(failed)?)
                        != intent.successor_retirement_intent_sha256
                {
                    return Err(JournalError::Conflict);
                }
                candidate_matches(
                    candidate,
                    intent.candidate_manifest_sha256,
                    intent.publisher_spki_sha256,
                )?;
                let service = service_binding(host, successor, observation)?;
                let plan = prepared
                    .authorization_plan()
                    .ok_or(JournalError::Conflict)?;
                if Sha256Digest::of_bytes(plan) != *plan_sha256 {
                    return Err(JournalError::Conflict);
                }
                let body: PlanBody = serde_json::from_slice(plan).map_err(failed)?;
                if serde_json::to_vec(&body).map_err(failed)? != plan
                    || body.schema != if restart { 2 } else { 1 }
                    || body.action
                        != if restart {
                            "retire_legacy_foreground_owner_after_windows_restart"
                        } else {
                            "retire_legacy_foreground_owner"
                        }
                    || body.startup_checkpoint_sha256
                        != if restart {
                            Some(Sha256Digest::of_bytes(
                                &serde_json::to_vec(
                                    prepared
                                        .startup_checkpoint()
                                        .ok_or(JournalError::Conflict)?,
                                )
                                .map_err(failed)?,
                            ))
                        } else {
                            None
                        }
                    || body.device_id != *device_id
                    || body.identity_sha256 != *identity_json_sha256
                    || body.configuration_hash != *configuration_hash
                    || body.previous_owner_pid != *observer_pid
                    || body.previous_work_outcome != "unknown_not_replayed"
                    || body.identity_mutation != "none"
                    || !body.requires_explicit_authorization
                    || body.current_boot.platform != "win32"
                    || body.current_boot.id != intent.current_boot.id
                    || body.current_boot.started_at != intent.current_boot.started_at_ms
                {
                    return Err(JournalError::Conflict);
                }
                let now = observation.checkpoint().map_err(failed)?;
                let original_admission = admitted_boot(&intent.current_boot, now)?;
                let (root, deployment) = owner.with_maintenance(&maintenance, |state| {
                    if root_native(state.root.identity())? != intent.config_root {
                        return Err(JournalError::Conflict);
                    }
                    state
                        .root
                        .ensure_absent("foreground-owner.json")
                        .map_err(failed)?;
                    let deployment = state
                        .root
                        .read_raw("deployment.json", 1024 * 1024)
                        .map_err(failed)?;
                    if Sha256Digest::of_bytes(deployment.bytes()) != intent.deployment_raw_sha256 {
                        return Err(JournalError::Conflict);
                    }
                    Ok((state.root.inner.clone(), deployment))
                })?;
                if root.path.to_str() != Some(body.state_dir.as_str())
                    || styx_contracts::legacy_deployment::deployment_connection_hash(
                        deployment.bytes(),
                    )
                    .map_err(failed)?
                        != *configuration_hash
                {
                    return Err(JournalError::Conflict);
                }
                let config: serde_json::Value =
                    serde_json::from_slice(deployment.bytes()).map_err(failed)?;
                let host_path = config
                    .get("host")
                    .and_then(|v| v.get("baseDir"))
                    .and_then(|v| v.as_str())
                    .ok_or(JournalError::Conflict)?;
                if PrivateRoot::open(host_path).map_err(failed)?.identity() != host.identity() {
                    return Err(JournalError::Conflict);
                }
                let (identity, actual_device_id) = identity(host)?;
                if actual_device_id != *device_id
                    || Sha256Digest::of_bytes(identity.bytes()) != *identity_json_sha256
                {
                    return Err(JournalError::Conflict);
                }
                let mut saved = Vec::new();
                for name in [RecoveryOriginalName::Lock, RecoveryOriginalName::Observer] {
                    let original = prepared
                        .originals()
                        .iter()
                        .find(|o| o.name == name)
                        .ok_or(JournalError::Conflict)?;
                    let raw = original_raw(original, &intent.config_root)?;
                    before_boot(&raw, original_admission)?;
                    saved.push(raw);
                }
                if prepared.originals().len() != 2
                    || body.files
                        != saved
                            .iter()
                            .map(plan_file)
                            .collect::<JournalResult<Vec<_>>>()?
                    || observer(&saved[1], &saved[0], *configuration_hash)? != *observer_pid
                {
                    return Err(JournalError::Conflict);
                }
                require_observer_absent(*observer_pid)?;
                let guards = prepared.guard_bytes();
                let guard = guards.first().ok_or(JournalError::Conflict)?;
                if guards.len() != 4
                    || guard.raw.is_empty()
                    || guard.raw.len() > 4096
                    || guards.iter().any(|g| g.raw != guard.raw)
                {
                    return Err(JournalError::Conflict);
                }
                let mut originals = vec![deployment];
                originals.extend(saved);
                Ok((
                    WindowsPreviousBootEvidence {
                        root,
                        originals,
                        current_boot: now,
                    },
                    guard.raw.clone(),
                    service,
                    identity,
                    *observer_pid,
                ))
            })();
        match checked {
            Ok((evidence, guard_bytes, service, identity, pid)) => Ok(Self {
                evidence,
                owner,
                maintenance,
                transaction: prepared.intent().transaction_id.clone(),
                guard_bytes,
                archive: None,
                service: Some((host.inner.clone(), service)),
                legacy_identity: Some((host.inner.clone(), identity, pid)),
                startup,
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
                startup,
            })),
        }
    }
}

#[cfg(test)]
#[path = "windows_legacy_maintenance_tests.rs"]
mod tests;

#[path = "windows_restart_checkpoint.rs"]
mod restart_checkpoint;
pub(in crate::store) use restart_checkpoint::WindowsRestartCheckpoint;

#[path = "windows_migration_owner.rs"]
mod migration_owner;
pub(in crate::store) use migration_owner::{
    WindowsCheckpointResumeFailure, WindowsCheckpointRetainedScope, WindowsMigrationCheckpointJob,
    WindowsMigrationCheckpointPlan, WindowsMigrationCheckpointResume,
    WindowsMigrationRecoveredGuards, WindowsMigrationWaitingForBoot, WindowsRestartMigrationReview,
    resume_recorded_windows_checkpoint, review_windows_restart_host_migration,
    start_resume_windows_restart_host_migration, start_windows_restart_host_migration,
};
