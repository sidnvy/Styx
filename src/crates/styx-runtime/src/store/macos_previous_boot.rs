//! Fixed legacy foreground-recovery producer. No UI, new service, JS execution,
//! process-name scan or inferred historical business success. The old owner is
//! accepted only by the original previous-boot/time/config combination plus
//! current original PID absence and continuously held restart exclusions.
use super::legacy_effect::{digest_file, stamp};
use super::*;
use crate::store::{
    ConfigurationMaintenance, OwnedConfigurationRoot,
    management::OwnedManagementJournal,
    management::handoff::*,
    secure_journal::{JournalError, JournalResult},
};
use serde::Deserialize;
use styx_contracts::{identity::Sha256Digest, native_management::NativeRootIdentity};

fn bad<T>(r: Result<T>) -> JournalResult<T> {
    r.map_err(|_| JournalError::Unknown)
}
fn native(file: &File) -> JournalResult<NativeRetirementFileStamp> {
    Ok(NativeRetirementFileStamp::Macos {
        stamp: stamp(file)?,
    })
}
fn millis(boot: (u64, u32)) -> JournalResult<u64> {
    boot.0
        .checked_mul(1000)
        .and_then(|s| s.checked_add(u64::from(boot.1) / 1000))
        .ok_or(JournalError::Unknown)
}
fn boot_record(boot: (u64, u32)) -> JournalResult<RecoveryBoot> {
    Ok(RecoveryBoot {
        id: format!("sec = {}, usec = {}", boot.0, boot.1),
        started_at_ms: millis(boot)?,
    })
}
fn parse_boot(id: &str) -> JournalResult<(u64, u32)> {
    let text = id.strip_prefix("sec = ").ok_or(JournalError::Conflict)?;
    let (a, b) = text.split_once(", usec = ").ok_or(JournalError::Conflict)?;
    let result = (
        a.parse::<u64>().map_err(|_| JournalError::Conflict)?,
        b.parse::<u32>().map_err(|_| JournalError::Conflict)?,
    );
    if result.0 == 0 || result.1 >= 1_000_000 || boot_record(result)?.id != id {
        return Err(JournalError::Conflict);
    }
    Ok(result)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OldBoot {
    platform: String,
    id: String,
    #[serde(rename = "startedAt")]
    started_at: f64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OldLock {
    ino: String,
    dev: String,
    sha256: Sha256Digest,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OldOwner {
    schema: u16,
    kind: String,
    pid: u32,
    #[serde(rename = "configurationHash")]
    configuration_hash: Sha256Digest,
    boot: OldBoot,
    #[serde(rename = "createdAt")]
    created_at: f64,
    lock: OldLock,
}
#[derive(Deserialize)]
struct OldObserver {
    pid: u32,
    #[serde(rename = "configurationHash")]
    configuration_hash: Sha256Digest,
    lock: ObserverLock,
}
#[derive(Deserialize)]
struct ObserverLock {
    sha256: Sha256Digest,
}
fn original_owner(originals: &[RecoveryOriginal]) -> JournalResult<OldOwner> {
    let raw = originals
        .iter()
        .find(|o| o.name == RecoveryOriginalName::Owner)
        .ok_or(JournalError::Conflict)?;
    serde_json::from_slice(&raw.raw).map_err(|_| JournalError::Conflict)
}
fn old_stamp(original: &RecoveryOriginal) -> JournalResult<&RetirementFileStamp> {
    match &original.stamp {
        NativeRetirementFileStamp::Macos { stamp } => Ok(stamp),
        _ => Err(JournalError::Conflict),
    }
}
fn validate_originals(
    originals: &[RecoveryOriginal],
    deployment: &[u8],
    prepared_current: &RecoveryBoot,
) -> JournalResult<u32> {
    let owner = original_owner(originals)?;
    let previous = parse_boot(&owner.boot.id)?;
    let current = parse_boot(&prepared_current.id)?;
    let previous_ms = previous.0 as f64 * 1000.0 + f64::from(previous.1) / 1000.0;
    let current_ms = current.0 as f64 * 1000.0 + f64::from(current.1) / 1000.0;
    let lock = originals
        .iter()
        .find(|o| o.name == RecoveryOriginalName::Lock)
        .ok_or(JournalError::Conflict)?;
    let lock_stamp = old_stamp(lock)?;
    if owner.schema != 1
        || owner.kind != "native_app"
        || owner.pid == 0
        || owner.boot.platform != "darwin"
        || previous >= current
        || !owner.boot.started_at.is_finite()
        || owner.boot.started_at != previous_ms
        || prepared_current.started_at_ms != millis(current)?
        || !owner.created_at.is_finite()
        || owner.created_at < previous_ms
        || owner.created_at >= current_ms
        || owner.configuration_hash
            != styx_contracts::legacy_deployment::deployment_connection_hash(deployment)
                .map_err(|_| JournalError::Conflict)?
        || owner.lock.ino != lock_stamp.inode.to_string()
        || owner.lock.dev != lock_stamp.device.to_string()
        || owner.lock.sha256 != lock.stamp.content_sha256()
        || originals.iter().any(|o| {
            old_stamp(o).is_err()
                || old_stamp(o).is_ok_and(|s| {
                    s.modified_seconds < 0
                        || s.modified_seconds as f64 * 1000.0
                            + s.modified_nanoseconds as f64 / 1_000_000.0
                            >= current_ms
                })
        })
    {
        return Err(JournalError::Conflict);
    }
    if let Some(observer) = originals
        .iter()
        .find(|o| o.name == RecoveryOriginalName::Observer)
    {
        let value: OldObserver =
            serde_json::from_slice(&observer.raw).map_err(|_| JournalError::Conflict)?;
        if value.pid != owner.pid
            || value.configuration_hash != owner.configuration_hash
            || value.lock.sha256 != owner.lock.sha256
        {
            return Err(JournalError::Conflict);
        }
    }
    Ok(owner.pid)
}
fn read_pin(root: &Root, name: &str, raw: &[u8]) -> JournalResult<File> {
    let file = bad(open_at(
        &root.directory,
        OsStr::new(name),
        OFlag::O_RDONLY | OFlag::O_NONBLOCK,
        Mode::empty(),
    ))?;
    if digest_file(&file, raw.len())?.as_slice() != raw {
        return Err(JournalError::Conflict);
    }
    stamp(&file)?;
    Ok(file)
}
fn maybe_raw(root: &Root, name: &str) -> JournalResult<Option<RawFile>> {
    match root.read_raw(Path::new(name), 4096) {
        Ok(raw) => Ok(Some(raw)),
        Err(StoreError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            bad(root.ensure_absent(Path::new(name)))?;
            Ok(None)
        }
        Err(_) => Err(JournalError::Unknown),
    }
}
/// Read-only input producer. Prepared facts do not come from remote paths/JSON.
/// The retained source roots and deployment are checked throughout OS effects.
pub(in crate::store) struct MacPreviousBootInput {
    root: Root,
    host: Root,
    deployment: Vec<u8>,
    originals: Vec<RecoveryOriginal>,
    current: RecoveryBoot,
    restart: super::legacy_restart::MacLegacyRestartSources,
}
impl MacPreviousBootInput {
    pub(in crate::store) fn capture(root: &Root, host: &Root) -> JournalResult<Self> {
        let current = boot_record(bad(ffi::legacy_boot_time())?)?;
        let deployment = bad(root.read_raw(Path::new("deployment.json"), 1024 * 1024))?;
        validate_topology(root, host, deployment.bytes())?;
        bad(root.ensure_absent(Path::new("foreground-recovery.lock")))?;
        let mut originals = Vec::new();
        for name in [
            RecoveryOriginalName::Lock,
            RecoveryOriginalName::Owner,
            RecoveryOriginalName::Observer,
        ] {
            let Some(raw) = maybe_raw(root, name.source_name())? else {
                if name == RecoveryOriginalName::Observer {
                    continue;
                }
                return Err(JournalError::Conflict);
            };
            let file = read_pin(root, name.source_name(), raw.bytes())?;
            if observation(&bad(journal_private_file(&file))?) != *raw.observation() {
                return Err(JournalError::Conflict);
            }
            originals.push(RecoveryOriginal {
                name,
                raw: raw.bytes().to_vec(),
                stamp: native(&file)?,
            });
        }
        let restart = super::legacy_restart::MacLegacyRestartSources::capture(root, host)?;
        let pid = validate_originals(&originals, deployment.bytes(), &current)?;
        if bad(ffi::process_identity_optional(pid))?.is_some()
            || boot_record(bad(ffi::legacy_boot_time())?)?.id != current.id
        {
            return Err(JournalError::Conflict);
        }
        Ok(Self {
            root: root.clone(),
            host: host.clone(),
            deployment: deployment.bytes().to_vec(),
            originals,
            current,
            restart,
        })
    }
    /// The exact successor is decided before preparation; no second transaction.
    pub(in crate::store) fn plan(
        self,
        successor: &NativeRetirementIntent,
    ) -> JournalResult<OwnerRecoveryPlan> {
        self.restart.revalidate()?;
        if self.restart.service_sha256() != Some(successor.service_descriptor_sha256) {
            return Err(JournalError::Unsupported);
        }
        if successor.deployment_raw_sha256 != Sha256Digest::of_bytes(&self.deployment)
            || successor.config_root != root_id(self.root.identity())?
            || successor.host_root != root_id(self.host.identity())?
        {
            return Err(JournalError::Conflict);
        }
        let before = bad(self.root.read_raw(Path::new("state.json"), 1024 * 1024))?;
        reject_migration_v2_collision(before.bytes())?;
        if successor.before_state_sha256 != Sha256Digest::of_bytes(before.bytes()) {
            return Err(JournalError::Conflict);
        }
        let original_owner = original_owner(&self.originals)?;
        let previous = boot_record(parse_boot(&original_owner.boot.id)?)?;
        let mut guards = Vec::new();
        for name in [
            RecoveryGuardName::Advance,
            RecoveryGuardName::Background,
            RecoveryGuardName::Capabilities,
            RecoveryGuardName::Foreground,
        ] {
            let mut entropy = [0u8; 32];
            getrandom::fill(&mut entropy).map_err(|_| JournalError::Unknown)?;
            let raw=serde_json::to_vec(&serde_json::json!({"schema":1,"kind":"native_migration_guard","transaction_id":successor.transaction_id,"scope":name,"nonce":Sha256Digest::of_bytes(&entropy)})).map_err(|_|JournalError::InvalidInput)?;
            guards.push(RecoveryGuard { name, raw });
        }
        let intent = LegacyOwnerRecoveryIntent {
            schema: 1,
            kind: RecoveryKind::LegacyOwnerRecovery,
            startup_checkpoint: None,
            transaction_id: successor.transaction_id.clone(),
            sequence: successor.sequence,
            config_root: successor.config_root.clone(),
            deployment_raw_sha256: successor.deployment_raw_sha256,
            before_state_sha256: successor.before_state_sha256,
            candidate_manifest_sha256: successor.candidate_manifest_sha256,
            publisher_spki_sha256: successor.publisher_spki_sha256,
            previous_boot: Some(previous),
            current_boot: self.current,
            basis: None,
            restart: RecoveryRestartBinding::ForegroundOnlyNoInstalledManager,
            successor_retirement_intent_sha256: Sha256Digest::of_bytes(
                &serde_json::to_vec(successor).map_err(|_| JournalError::InvalidInput)?,
            ),
            originals: self
                .originals
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
        let plan = OwnerRecoveryPlan {
            intent: serde_json::value::RawValue::from_string(
                serde_json::to_string(&intent).map_err(|_| JournalError::InvalidInput)?,
            )
            .map_err(|_| JournalError::InvalidInput)?,
            originals: self.originals,
            guards,
        };
        plan.validated_intent()?;
        Ok(plan)
    }
}
fn root_id(id: RootIdentity) -> JournalResult<NativeRootIdentity> {
    match id {
        RootIdentity::Macos { device, inode, uid } => {
            Ok(NativeRootIdentity::Macos { device, inode, uid })
        }
        _ => Err(JournalError::Conflict),
    }
}
fn validate_topology(root: &Root, host: &Root, expected: &[u8]) -> JournalResult<()> {
    bad(root.validate_root())?;
    bad(host.validate_root())?;
    let raw = bad(root.read_raw(Path::new("deployment.json"), 1024 * 1024))?;
    if raw.bytes() != expected {
        return Err(JournalError::Conflict);
    }
    let d: serde_json::Value =
        serde_json::from_slice(expected).map_err(|_| JournalError::Conflict)?;
    // Connection binding uses the shared original-JS-compatible contract above.
    if d.get("schema").and_then(|v| v.as_u64()) != Some(1)
        || d.get("mode").and_then(|v| v.as_str()) != Some("join-existing")
        || d.pointer("/host/baseDir").and_then(|v| v.as_str()) != host.path.to_str()
    {
        return Err(JournalError::Unsupported);
    }
    Ok(())
}
struct HeldGuard {
    name: RecoveryGuardName,
    file: File,
    stamp: NativeRetirementFileStamp,
}
/// OWNED current effects. A failed call retains this object; Drop never deletes
/// locks, kills an old App/daemon or turns an attempted operation into success.
pub(in crate::store) struct MacBootRecoveryEffects {
    owner: OwnedConfigurationRoot,
    maintenance: Arc<ConfigurationMaintenance>,
    root: Root,
    host: Root,
    deployment: Vec<u8>,
    prepared_boot: RecoveryBoot,
    original_pid: u32,
    archive: Option<Root>,
    original_pins: Vec<File>,
    guards: Vec<HeldGuard>,
    marker: Option<File>,
    marker_done: bool,
    restart: super::legacy_restart::MacLegacyRestartSources,
}
impl MacBootRecoveryEffects {
    pub(in crate::store) fn maintenance(&self) -> &ConfigurationMaintenance {
        &self.maintenance
    }
    pub(in crate::store) fn matches_owner(&self, owner: &OwnedConfigurationRoot) -> bool {
        self.owner.same_authority(owner)
    }
    pub(in crate::store) fn from_prepared(
        owner: OwnedConfigurationRoot,
        maintenance: Arc<ConfigurationMaintenance>,
        root: &Root,
        host: &Root,
        prepared: &PreparedLegacyOwnerRecovery,
    ) -> JournalResult<Self> {
        if !prepared.matches_owner(&owner)
            || !maintenance.matches(&owner)
            || maintenance.transaction_id() != &prepared.intent().transaction_id
            || prepared.intent().config_root != root_id(root.identity())?
        {
            return Err(JournalError::Conflict);
        }
        let deployment = bad(root.read_raw(Path::new("deployment.json"), 1024 * 1024))?;
        if Sha256Digest::of_bytes(deployment.bytes()) != prepared.intent().deployment_raw_sha256 {
            return Err(JournalError::Conflict);
        }
        let original_pid = validate_originals(
            prepared.originals(),
            deployment.bytes(),
            &prepared.intent().current_boot,
        )?;
        let restart = super::legacy_restart::MacLegacyRestartSources::capture(root, host)?;
        let value = Self {
            owner,
            maintenance,
            root: root.clone(),
            host: host.clone(),
            deployment: deployment.bytes().to_vec(),
            prepared_boot: prepared.intent().current_boot.clone(),
            original_pid,
            archive: None,
            original_pins: Vec::new(),
            guards: Vec::new(),
            marker: None,
            marker_done: false,
            restart,
        };
        value.environment()?;
        Ok(value)
    }
    /// Reopen the original GuardsHeld chain before canonical cutover. Both
    /// journal observations require the original before-state and transaction.
    /// This only restores physical custody; it performs no recovery effects.
    pub(in crate::store) fn reopen_guards_held(
        owner: OwnedConfigurationRoot,
        maintenance: Arc<ConfigurationMaintenance>,
        root: &Root,
        host: &Root,
        journal: &OwnedManagementJournal,
    ) -> JournalResult<(Self, LegacyGuardsHeld)> {
        if !maintenance.matches(&owner) || !journal.configuration_root().same_authority(&owner) {
            return Err(JournalError::Conflict);
        }
        let prepared =
            journal.resync_legacy_owner_recovery(&maintenance, maintenance.transaction_id())?;
        if !journal.owner_recovery_prepared_matches(&prepared) {
            return Err(JournalError::Conflict);
        }
        let (value, held) =
            Self::reopen_guards_held_custody(owner, maintenance.clone(), root, host, prepared)?;
        let rechecked = journal
            .resync_legacy_owner_recovery(&maintenance, maintenance.transaction_id())?
            .into_guards_held()?;
        value.validate_retained(&rechecked)?;
        Ok((value, held))
    }
    /// Reopen only the ORIGINAL completed C chain and its actual private files.
    /// No rename, guard creation, phase append or scope-settlement inference.
    /// A canonical successor exception is checked only by the original journal
    /// using the SAME opaque cutover, never a supplied state/receipt DTO.
    pub(in crate::store) fn reopen_guards_held_for_cutover(
        owner: OwnedConfigurationRoot,
        maintenance: Arc<ConfigurationMaintenance>,
        root: &Root,
        host: &Root,
        journal: &OwnedManagementJournal,
        cutover: &crate::store::management::cutover::PreparedCutover<NativeRootIdentity>,
    ) -> JournalResult<(Self, LegacyGuardsHeld)> {
        if !maintenance.matches(&owner) || !journal.configuration_root().same_authority(&owner) {
            return Err(JournalError::Conflict);
        }
        let prepared = journal.resync_legacy_owner_recovery_for_cutover(&maintenance, cutover)?;
        if !journal.owner_recovery_prepared_matches(&prepared) {
            return Err(JournalError::Conflict);
        }
        let (value, held) =
            Self::reopen_guards_held_custody(owner, maintenance.clone(), root, host, prepared)?;
        // Recheck the SAME original journal binding after all physical reads;
        // no receipt is reconstructed from newly observed filesystem facts.
        let rechecked = journal
            .resync_legacy_owner_recovery_for_cutover(&maintenance, cutover)?
            .into_guards_held()?;
        value.validate_retained(&rechecked)?;
        Ok((value, held))
    }
    /// Restore actual file custody only from an opaque original journal chain.
    /// The caller must recheck its corresponding journal observation afterward.
    fn reopen_guards_held_custody(
        owner: OwnedConfigurationRoot,
        maintenance: Arc<ConfigurationMaintenance>,
        root: &Root,
        host: &Root,
        prepared: PreparedLegacyOwnerRecovery,
    ) -> JournalResult<(Self, LegacyGuardsHeld)> {
        let held = prepared.into_guards_held()?;
        let prepared = held.prepared();
        let mut value =
            Self::from_prepared(owner.clone(), maintenance.clone(), root, host, prepared)?;
        owner.with_maintenance(&maintenance, |_| {
            value.environment()?;
            // Read-only fixed roots: unlike archive(), neither missing parent
            // nor missing transaction directory is ever created here.
            let archive = bad(Root::open(
                &root
                    .path
                    .join("foreground-recovery")
                    .join(prepared.intent().transaction_id.as_str()),
            ))?;
            let expected: std::collections::BTreeSet<_> = prepared
                .originals()
                .iter()
                .flat_map(|o| {
                    [
                        format!("{}.before", o.name.source_name()),
                        format!("{}.retired", o.name.source_name()),
                    ]
                })
                .chain(std::iter::once("foreground-recovery.lock.retired".into()))
                .collect();
            for entry in std::fs::read_dir(&archive.path).map_err(|_| JournalError::Unknown)? {
                let name = entry
                    .map_err(|_| JournalError::Unknown)?
                    .file_name()
                    .into_string()
                    .map_err(|_| JournalError::Conflict)?;
                if !expected.contains(&name) {
                    return Err(JournalError::Conflict);
                }
            }
            bad(archive.validate_root())?;
            // Old Owner/Observer and the temporary recovery marker must remain
            // absent. foreground.lock is instead the recorded NEW held guard.
            for name in [
                "foreground-owner.json",
                "foreground-observer.json",
                "foreground-recovery.lock",
            ] {
                if maybe_raw(root, name)?.is_some() {
                    return Err(JournalError::Unknown);
                }
            }
            let posts = prepared
                .archived_original_posts()
                .ok_or(JournalError::Conflict)?;
            if posts.len() != prepared.originals().len() {
                return Err(JournalError::Conflict);
            }
            for (post, original) in posts.iter().zip(prepared.originals()) {
                if post.name != original.name || !original.stamp.same_file_after_rename(&post.stamp)
                {
                    return Err(JournalError::Conflict);
                }
                let before = read_pin(
                    &archive,
                    &format!("{}.before", original.name.source_name()),
                    &original.raw,
                )?;
                let retired = read_pin(
                    &archive,
                    &format!("{}.retired", original.name.source_name()),
                    &original.raw,
                )?;
                if native(&retired)? != post.stamp {
                    return Err(JournalError::Unknown);
                }
                // Keep actual FDs, including exact-byte .before companions;
                // those companions have no historical identity stamp in C.
                value.original_pins.push(before);
                value.original_pins.push(retired);
            }
            let posts = prepared.guards_held_posts().ok_or(JournalError::Conflict)?;
            if posts.len() != prepared.guard_bytes().len() {
                return Err(JournalError::Conflict);
            }
            for (post, binding) in posts.iter().zip(prepared.guard_bytes()) {
                if post.name != binding.name {
                    return Err(JournalError::Conflict);
                }
                let file = read_pin(root, binding.name.source_name(), &binding.raw)?;
                if native(&file)? != post.stamp {
                    return Err(JournalError::Unknown);
                }
                value.guards.push(HeldGuard {
                    name: binding.name,
                    file,
                    stamp: post.stamp.clone(),
                });
            }
            let marker_raw = &prepared
                .guard_bytes()
                .first()
                .ok_or(JournalError::Conflict)?
                .raw;
            value.marker = Some(read_pin(
                &archive,
                "foreground-recovery.lock.retired",
                marker_raw,
            )?);
            value.marker_done = true;
            value.archive = Some(archive);
            value.validate_retained(&held)?;
            for name in [
                "foreground-owner.json",
                "foreground-observer.json",
                "foreground-recovery.lock",
            ] {
                if maybe_raw(root, name)?.is_some() {
                    return Err(JournalError::Unknown);
                }
            }
            Ok(())
        })?;
        Ok((value, held))
    }
    fn environment(&self) -> JournalResult<()> {
        self.restart.revalidate()?;
        validate_topology(&self.root, &self.host, &self.deployment)?;
        let actual = bad(ffi::legacy_boot_time())?;
        let prepared = parse_boot(&self.prepared_boot.id)?;
        // A later real reboot is allowed; original Prepared boot is historical.
        // Backward/overlapping timestamps or unknown process facts refuse.
        if actual < prepared || bad(ffi::process_identity_optional(self.original_pid))?.is_some() {
            return Err(JournalError::Conflict);
        }
        Ok(())
    }
    fn archive(&mut self, tx: &styx_contracts::identity::TransactionId) -> JournalResult<Root> {
        if let Some(root) = &self.archive {
            bad(root.validate_root())?;
            return Ok(root.clone());
        }
        let parent = match Root::open(&self.root.path.join("foreground-recovery")) {
            Ok(root) => root,
            Err(StoreError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => self
                .root
                .create_fresh_child(OsStr::new("foreground-recovery"))
                .map_err(|_| JournalError::Unknown)?,
            Err(_) => return Err(JournalError::Unknown),
        };
        let archive = match Root::open(&parent.path.join(tx.as_str())) {
            Ok(root) => root,
            Err(StoreError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => parent
                .create_fresh_child(OsStr::new(tx.as_str()))
                .map_err(|_| JournalError::Unknown)?,
            Err(_) => return Err(JournalError::Unknown),
        };
        self.archive = Some(archive.clone());
        Ok(archive)
    }
    fn guard(
        &mut self,
        journal: &OwnedManagementJournal,
        prepared: &PreparedLegacyOwnerRecovery,
        name: RecoveryGuardName,
    ) -> JournalResult<()> {
        journal.validate_legacy_owner_prepared(&self.maintenance, prepared)?;
        let raw = &prepared
            .guard_bytes()
            .iter()
            .find(|g| g.name == name)
            .ok_or(JournalError::Conflict)?
            .raw;
        self.environment()?;
        let owner = self.owner.clone();
        let maintenance = self.maintenance.clone();
        owner.with_maintenance(&maintenance, |state| {
            match maybe_raw(&self.root, name.source_name())? {
                None => {
                    bad(self
                        .root
                        .create_fixed(&state.writer, name.source_name(), raw, &|_| {}))?
                }
                Some(old) => {
                    if old.bytes() != raw {
                        return Err(JournalError::Conflict);
                    }
                }
            }
            let file = read_pin(&self.root, name.source_name(), raw)?;
            let stamp = native(&file)?;
            self.guards.push(HeldGuard { name, file, stamp });
            Ok(())
        })
    }
    pub(in crate::store) fn execute_archive(
        &mut self,
        journal: &OwnedManagementJournal,
        prepared: &PreparedLegacyOwnerRecovery,
    ) -> JournalResult<Vec<RecoveryOriginalPost>> {
        journal.validate_legacy_owner_prepared(&self.maintenance, prepared)?;
        if prepared.stage() != Some(OwnerRecoveryStage::Prepared) {
            return Err(JournalError::Conflict);
        }
        self.environment()?;
        let archive = self.archive(&prepared.intent().transaction_id)?;
        let raw = &prepared
            .guard_bytes()
            .first()
            .ok_or(JournalError::Conflict)?
            .raw;
        let owner = self.owner.clone();
        let maintenance = self.maintenance.clone();
        owner.with_maintenance(&maintenance, |state| {
            // Fixed archive membership; unknown files prevent any further move.
            let expected: std::collections::BTreeSet<_> = prepared
                .originals()
                .iter()
                .flat_map(|o| {
                    [
                        format!("{}.before", o.name.source_name()),
                        format!("{}.retired", o.name.source_name()),
                    ]
                })
                .chain(std::iter::once("foreground-recovery.lock.retired".into()))
                .collect();
            for entry in std::fs::read_dir(&archive.path).map_err(|_| JournalError::Unknown)? {
                let name = entry
                    .map_err(|_| JournalError::Unknown)?
                    .file_name()
                    .into_string()
                    .map_err(|_| JournalError::Conflict)?;
                if !expected.contains(&name) {
                    return Err(JournalError::Conflict);
                }
            }
            bad(archive.validate_root())?;
            if let Some(old) = maybe_raw(&self.root, "foreground-recovery.lock")? {
                if old.bytes() != raw {
                    return Err(JournalError::Conflict);
                }
            } else {
                bad(self.root.create_fixed(
                    &state.writer,
                    "foreground-recovery.lock",
                    raw,
                    &|_| {},
                ))?;
            }
            self.marker = Some(read_pin(&self.root, "foreground-recovery.lock", raw)?);
            Ok(())
        })?;
        for name in [
            RecoveryGuardName::Advance,
            RecoveryGuardName::Background,
            RecoveryGuardName::Capabilities,
        ] {
            self.guard(journal, prepared, name)?;
        }
        let mut posts = Vec::new();
        for original in prepared.originals() {
            let before_name = format!("{}.before", original.name.source_name());
            let retired_name = format!("{}.retired", original.name.source_name());
            let owner = self.owner.clone();
            owner.with_maintenance(&maintenance, |_| {
                self.environment()?;
                // Save original bytes without creating a second ledger.
                match maybe_raw(&archive, &before_name)? {
                    Some(raw) => {
                        if raw.bytes() != original.raw {
                            return Err(JournalError::Conflict);
                        }
                    }
                    None => {
                        let file = bad(open_at(
                            &archive.directory,
                            OsStr::new(&before_name),
                            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL,
                            Mode::from_bits_truncate(0o600),
                        ))?;
                        let mut file = file;
                        file.write_all(&original.raw)
                            .map_err(|_| JournalError::Unknown)?;
                        bad(sync_private_file(&file))?;
                        bad(archive.sync_directory())?;
                    }
                }
                let source = maybe_raw(&self.root, original.name.source_name())?;
                let destination = maybe_raw(&archive, &retired_name)?;
                let file = match (source, destination) {
                    (Some(source), None) => {
                        if source.bytes() != original.raw {
                            return Err(JournalError::Conflict);
                        }
                        let pin = read_pin(&self.root, original.name.source_name(), &original.raw)?;
                        if native(&pin)? != original.stamp {
                            return Err(JournalError::Conflict);
                        }
                        bad(rename_exclusive(
                            &self.root.directory,
                            original.name.source_name(),
                            &archive.directory,
                            &retired_name,
                        ))?;
                        bad(sync_private_file(&pin))?;
                        bad(self.root.sync_directory())?;
                        bad(archive.sync_directory())?;
                        pin
                    }
                    (None, Some(destination)) => {
                        if destination.bytes() != original.raw {
                            return Err(JournalError::Conflict);
                        }
                        read_pin(&archive, &retired_name, &original.raw)?
                    }
                    _ => return Err(JournalError::Unknown),
                };
                let post = native(&file)?;
                if !original.stamp.same_file_after_rename(&post) {
                    return Err(JournalError::Unknown);
                }
                let named = read_pin(&archive, &retired_name, &original.raw)?;
                if native(&named)? != post {
                    return Err(JournalError::Unknown);
                }
                self.original_pins.push(file);
                posts.push(RecoveryOriginalPost {
                    name: original.name,
                    stamp: post,
                });
                self.environment()?;
                Ok(())
            })?;
        }
        Ok(posts)
    }
    pub(in crate::store) fn finish_guards(
        &mut self,
        journal: &OwnedManagementJournal,
        archived: &ArchivedLegacyOwnerRecovery,
    ) -> JournalResult<Vec<RecoveryGuardPost>> {
        let prepared = archived.prepared();
        journal.validate_legacy_owner_prepared(&self.maintenance, prepared)?;
        self.environment()?;
        if prepared.stage() != Some(OwnerRecoveryStage::Archived) {
            return Err(JournalError::Conflict);
        }
        for name in [
            RecoveryGuardName::Advance,
            RecoveryGuardName::Background,
            RecoveryGuardName::Capabilities,
            RecoveryGuardName::Foreground,
        ] {
            if !self.guards.iter().any(|g| g.name == name) {
                self.guard(journal, prepared, name)?;
            }
        }
        let archive = self.archive(&prepared.intent().transaction_id)?;
        let raw = &prepared
            .guard_bytes()
            .first()
            .ok_or(JournalError::Conflict)?
            .raw;
        let owner = self.owner.clone();
        let maintenance = self.maintenance.clone();
        owner.with_maintenance(&maintenance, |_| {
            match (
                maybe_raw(&self.root, "foreground-recovery.lock")?,
                maybe_raw(&archive, "foreground-recovery.lock.retired")?,
            ) {
                (Some(source), None) => {
                    if source.bytes() != raw {
                        return Err(JournalError::Conflict);
                    }
                    let marker = read_pin(&self.root, "foreground-recovery.lock", raw)?;
                    bad(rename_exclusive(
                        &self.root.directory,
                        "foreground-recovery.lock",
                        &archive.directory,
                        "foreground-recovery.lock.retired",
                    ))?;
                    bad(sync_private_file(&marker))?;
                    self.marker = Some(marker);
                    bad(self.root.sync_directory())?;
                    bad(archive.sync_directory())?;
                }
                (None, Some(retired)) => {
                    if retired.bytes() != raw {
                        return Err(JournalError::Conflict);
                    }
                    self.marker =
                        Some(read_pin(&archive, "foreground-recovery.lock.retired", raw)?);
                }
                _ => return Err(JournalError::Unknown),
            }
            self.marker_done = true;
            self.environment()?;
            Ok(())
        })?;
        self.validate_guards(prepared)
    }
    fn validate_guards(
        &self,
        prepared: &PreparedLegacyOwnerRecovery,
    ) -> JournalResult<Vec<RecoveryGuardPost>> {
        if !self.marker_done {
            return Err(JournalError::Unknown);
        }
        self.environment()?;
        let mut posts = Vec::new();
        for binding in prepared.guard_bytes() {
            let held = self
                .guards
                .iter()
                .find(|g| g.name == binding.name)
                .ok_or(JournalError::Unknown)?;
            if native(&held.file)? != held.stamp {
                return Err(JournalError::Unknown);
            }
            let named = read_pin(&self.root, binding.name.source_name(), &binding.raw)?;
            if native(&named)? != held.stamp {
                return Err(JournalError::Unknown);
            }
            posts.push(RecoveryGuardPost {
                name: binding.name,
                stamp: held.stamp.clone(),
            });
        }
        Ok(posts)
    }
    /// A borrowed original OS effect object, not serialized receipt authority.
    /// Every final guard and archived original is compared to the ORIGINAL
    /// journal post stamp, then to a held/named descriptor on this invocation.
    pub(in crate::store) fn validate_retained(&self, held: &LegacyGuardsHeld) -> JournalResult<()> {
        let prepared = held.prepared();
        if !prepared.matches_owner(&self.owner)
            || prepared.intent().config_root != root_id(self.root.identity())?
            || prepared.intent().transaction_id != *self.maintenance.transaction_id()
        {
            return Err(JournalError::Conflict);
        }
        self.environment()?;
        let current = self.validate_guards(prepared)?;
        let original = prepared.guards_held_posts().ok_or(JournalError::Conflict)?;
        if current != original {
            return Err(JournalError::Unknown);
        }
        let archive = self.archive.as_ref().ok_or(JournalError::Unknown)?;
        bad(archive.validate_root())?;
        let archived = prepared
            .archived_original_posts()
            .ok_or(JournalError::Conflict)?;
        if archived.len() != prepared.originals().len() {
            return Err(JournalError::Conflict);
        }
        for (post, original) in archived.iter().zip(prepared.originals()) {
            if post.name != original.name {
                return Err(JournalError::Conflict);
            }
            let file = read_pin(
                archive,
                &format!("{}.retired", original.name.source_name()),
                &original.raw,
            )?;
            if native(&file)? != post.stamp {
                return Err(JournalError::Unknown);
            }
        }
        let marker = self.marker.as_ref().ok_or(JournalError::Unknown)?;
        let raw = &prepared
            .guard_bytes()
            .first()
            .ok_or(JournalError::Conflict)?
            .raw;
        let named = read_pin(archive, "foreground-recovery.lock.retired", raw)?;
        if native(marker)? != native(&named)? || digest_file(marker, raw.len())?.as_slice() != raw {
            return Err(JournalError::Unknown);
        }
        self.environment()
    }
    /// Explicit composition keeps BOTH original OS owner and same-journal phase
    /// alive; ordinary admission and token retirement have not been performed.
    pub(in crate::store) fn archive_and_hold(
        &mut self,
        journal: &mut OwnedManagementJournal,
        prepared: &PreparedLegacyOwnerRecovery,
    ) -> JournalResult<LegacyGuardsHeld> {
        let archived = match prepared.stage() {
            Some(OwnerRecoveryStage::Prepared) => {
                let facts = self.execute_archive(journal, prepared)?;
                journal.record_legacy_owner_archived(&self.maintenance, prepared, facts)?
            }
            Some(OwnerRecoveryStage::Archived) => journal
                .resync_legacy_owner_recovery(&self.maintenance, &prepared.intent().transaction_id)?
                .into_archived()?,
            _ => return Err(JournalError::Conflict),
        };
        let facts = self.finish_guards(journal, &archived)?;
        journal.record_legacy_guards_held(&self.maintenance, &archived, facts)
    }
}
