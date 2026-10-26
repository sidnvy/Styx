//! Previous Windows boot epoch evidence, not writer exclusion or full admission.
//! No old process handles are reconstructed. Raw receipts remain unchanged and
//! old work stays Unknown. Caller separately owns the cooperative writer fence
//! and excludes newly restarted instances before using this in a cutover.
use super::*;
use crate::platform::windows_legacy_observation::{BootStamp, WindowsLegacyObservation};
use crate::store::secure_journal::{JournalError, JournalResult};
use serde::Deserialize;
use styx_contracts::identity::Sha256Digest;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
#[path = "windows_previous_boot_effect.rs"]
mod effects;
#[path = "windows_filetime_projection.rs"]
mod filetime_projection;
pub(in crate::store) use effects::{
    WindowsBootRecoveryEffects, WindowsCheckpointResumeFailure, WindowsCheckpointRetainedScope,
    WindowsLegacyMaintenancePlan, WindowsMigrationCheckpointJob, WindowsMigrationCheckpointPlan,
    WindowsMigrationCheckpointResume, WindowsMigrationRecoveredGuards,
    WindowsMigrationWaitingForBoot, WindowsRecoveryOpenFailure, WindowsRestartCheckpoint,
    WindowsRestartMigrationReview, WindowsResumedCutover, resume_recorded_windows_checkpoint,
    review_windows_restart_host_migration, start_resume_validated_windows_host_migration,
    start_resume_windows_restart_host_migration, start_windows_restart_host_migration,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviousBoot {
    platform: String,
    id: String,
    #[serde(rename = "startedAt")]
    started_at: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LockIdentity {
    ino: String,
    dev: String,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerReceipt {
    schema: u16,
    kind: String,
    pid: u32,
    #[serde(rename = "configurationHash")]
    configuration_hash: String,
    boot: PreviousBoot,
    #[serde(rename = "createdAt")]
    created_at: u64,
    lock: LockIdentity,
}
fn failed<T>(_: T) -> JournalError {
    JournalError::Conflict
}
fn before_boot(raw: &RawFile, boot: BootStamp) -> JournalResult<()> {
    let o = raw.observation();
    let nanos = filetime_projection::unix_nanoseconds(o.modified_seconds, o.modified_nanoseconds)
        .ok_or(JournalError::Conflict)?;
    let boot_nanos = u128::from(boot.unix_micros)
        .checked_mul(1000)
        .ok_or(JournalError::Conflict)?;
    if nanos >= boot_nanos {
        return Err(JournalError::Conflict);
    }
    Ok(())
}
fn validate_owner_receipt(
    deployment: &RawFile,
    owner: &RawFile,
    lock: &RawFile,
    now: BootStamp,
) -> JournalResult<OwnerReceipt> {
    let value: OwnerReceipt = serde_json::from_slice(owner.bytes()).map_err(failed)?;
    let connection_hash =
        styx_contracts::legacy_deployment::deployment_connection_hash(deployment.bytes())
            .map_err(failed)?;
    let old_time = OffsetDateTime::parse(&value.boot.id, &Rfc3339).map_err(failed)?;
    let old_ms = u64::try_from(old_time.unix_timestamp_nanos() / 1_000_000).map_err(failed)?;
    if value.schema != 1
        || value.kind != "native_app"
        || value.pid == 0
        || value.boot.platform != "win32"
        || old_ms != value.boot.started_at
        || !now.definitely_after_old_ms(old_ms)
        || value.created_at < old_ms
        || u128::from(value.created_at) * 1000 >= u128::from(now.unix_micros)
        || value.configuration_hash != connection_hash.to_hex()
        || value.lock.sha256 != Sha256Digest::of_bytes(lock.bytes()).to_hex()
        || value.lock.ino.parse::<u64>().map_err(failed)? != lock.observation().inode
        || value.lock.dev.parse::<u64>().map_err(failed)? != lock.observation().device
    {
        return Err(JournalError::Conflict);
    }
    before_boot(&owner, now)?;
    before_boot(&lock, now)?;
    Ok(value)
}
/// Retains the exact original root and protected raw receipts, not a bool DTO.
/// This never authorizes token retirement by itself.
pub(in crate::store) struct WindowsPreviousBootEvidence {
    root: Root,
    originals: Vec<RawFile>,
    current_boot: BootStamp,
}
impl Root {
    pub(in crate::store) fn previous_boot_evidence(
        &self,
        observation: &WindowsLegacyObservation,
    ) -> JournalResult<WindowsPreviousBootEvidence> {
        let now = observation.checkpoint().map_err(failed)?;
        self.validate_root().map_err(failed)?;
        self.ensure_absent(Path::new("foreground-recovery.lock"))
            .map_err(failed)?;
        let deployment = self
            .read_raw(Path::new("deployment.json"), 1024 * 1024)
            .map_err(failed)?;
        let owner = self
            .read_raw(Path::new("foreground-owner.json"), 4096)
            .map_err(failed)?;
        let lock = self
            .read_raw(Path::new("foreground.lock"), 4096)
            .map_err(failed)?;
        let value = validate_owner_receipt(&deployment, &owner, &lock, now)?;
        let mut originals = vec![deployment, owner, lock];
        match self.read_raw(Path::new("foreground-observer.json"), 4096) {
            Ok(observer) => {
                let v: serde_json::Value =
                    serde_json::from_slice(observer.bytes()).map_err(failed)?;
                if v.get("pid").and_then(|v| v.as_u64()) != Some(u64::from(value.pid))
                    || v.get("configurationHash").and_then(|v| v.as_str())
                        != Some(value.configuration_hash.as_str())
                    || v.get("lock")
                        .and_then(|v| v.get("sha256"))
                        .and_then(|v| v.as_str())
                        != Some(value.lock.sha256.as_str())
                {
                    return Err(JournalError::Conflict);
                }
                before_boot(&observer, now)?;
                originals.push(observer);
            }
            Err(StoreError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                self.ensure_absent(Path::new("foreground-observer.json"))
                    .map_err(failed)?;
            }
            Err(_) => return Err(JournalError::Conflict),
        }
        let evidence = WindowsPreviousBootEvidence {
            root: self.clone(),
            originals,
            current_boot: now,
        };
        evidence.revalidate(observation)?;
        Ok(evidence)
    }
}
impl WindowsPreviousBootEvidence {
    pub(in crate::store) fn revalidate(
        &self,
        observation: &WindowsLegacyObservation,
    ) -> JournalResult<()> {
        self.root.validate_root().map_err(failed)?;
        if observation.checkpoint().map_err(failed)? != self.current_boot {
            return Err(JournalError::Conflict);
        }
        self.root
            .ensure_absent(Path::new("foreground-recovery.lock"))
            .map_err(failed)?;
        for original in &self.originals {
            let now = self
                .root
                .read_raw(original.relative_path(), original.bytes().len())
                .map_err(failed)?;
            if now.observation() != original.observation() || now.bytes() != original.bytes() {
                return Err(JournalError::Conflict);
            }
        }
        if !self
            .originals
            .iter()
            .any(|r| r.relative_path() == Path::new("foreground-observer.json"))
        {
            self.root
                .ensure_absent(Path::new("foreground-observer.json"))
                .map_err(failed)?;
        }
        if observation.checkpoint().map_err(failed)? != self.current_boot {
            return Err(JournalError::Conflict);
        }
        self.root.validate_root().map_err(failed)
    }
}
