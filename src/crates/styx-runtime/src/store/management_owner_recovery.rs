//! Same ManagementV1 transaction pre-stage for fixed legacy foreground recovery.
//! Stored observations attest bytes/durability, not an OS effect or idle runtime.
use super::*;

const MAX_RECOVERY_RAW: usize = 4096;
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::store) enum RecoveryOriginalName {
    Lock,
    Owner,
    Observer,
}
impl RecoveryOriginalName {
    pub(in crate::store) fn source_name(self) -> &'static str {
        match self {
            Self::Lock => "foreground.lock",
            Self::Owner => "foreground-owner.json",
            Self::Observer => "foreground-observer.json",
        }
    }
    fn suffix(self) -> &'static str {
        match self {
            Self::Lock => "original-lock",
            Self::Owner => "original-owner",
            Self::Observer => "original-observer",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::store) enum RecoveryGuardName {
    Foreground,
    Advance,
    Background,
    Capabilities,
}
impl RecoveryGuardName {
    pub(in crate::store) fn source_name(self) -> &'static str {
        match self {
            Self::Foreground => "foreground.lock",
            Self::Advance => "advance.lock",
            Self::Background => "background.lock",
            Self::Capabilities => "capabilities.lock",
        }
    }
    fn suffix(self) -> &'static str {
        match self {
            Self::Foreground => "guard-foreground",
            Self::Advance => "guard-advance",
            Self::Background => "guard-background",
            Self::Capabilities => "guard-capabilities",
        }
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::store) struct RecoveryOriginalBinding {
    pub name: RecoveryOriginalName,
    pub stamp: NativeRetirementFileStamp,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::store) struct RecoveryGuardBinding {
    pub name: RecoveryGuardName,
    pub sha256: Sha256Digest,
    pub byte_len: u64,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::store) struct RecoveryBoot {
    pub id: String,
    pub started_at_ms: u64,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::store) enum RecoveryKind {
    LegacyOwnerRecovery,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::store) enum RecoveryRestartBinding {
    ForegroundOnlyNoInstalledManager,
    WindowsStartupExclusion,
}
/// Data bound by the original C intent. Actual Windows APIs remain the producer.
/// The existing config_root binds SID/volume; fixed names and archive path are
/// derived by the OS adapter, never supplied by wire or by these fields.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::store) struct WindowsRestartProcess {
    pub pid: u32,
    pub birth_filetime: u64,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::store) struct WindowsStartupCheckpoint {
    pub original_link: NativeRetirementFileStamp,
    pub startup_directory: String,
    pub target: String,
    pub arguments: String,
    pub working_directory: String,
    pub desired_enabled: bool,
    pub app: WindowsRestartProcess,
    pub core: WindowsRestartProcess,
    pub original_package_sha256: Sha256Digest,
    pub original_app_sha256: Sha256Digest,
    pub original_publisher_spki_sha256: Sha256Digest,
}
/// DTO only. The actual platform producer must establish boot and closed restart
/// sources and keep its original guards, never infer them from this serialization.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(in crate::store) enum RecoveryBasis {
    ExplicitLegacyMaintenance {
        plan_sha256: Sha256Digest,
        device_id: styx_contracts::identity::DeviceId,
        identity_json_sha256: Sha256Digest,
        configuration_hash: Sha256Digest,
        observer_pid: u32,
    },
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::store) struct LegacyOwnerRecoveryIntent {
    pub schema: u16,
    pub kind: RecoveryKind,
    pub transaction_id: TransactionId,
    pub sequence: u64,
    pub config_root: styx_contracts::native_management::NativeRootIdentity,
    pub deployment_raw_sha256: Sha256Digest,
    pub before_state_sha256: Sha256Digest,
    pub candidate_manifest_sha256: Sha256Digest,
    pub publisher_spki_sha256: Sha256Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_boot: Option<RecoveryBoot>,
    pub current_boot: RecoveryBoot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basis: Option<RecoveryBasis>,
    pub restart: RecoveryRestartBinding,
    pub successor_retirement_intent_sha256: Sha256Digest,
    pub originals: Vec<RecoveryOriginalBinding>,
    pub guards: Vec<RecoveryGuardBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub startup_checkpoint: Option<WindowsStartupCheckpoint>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::store) struct RecoveryOriginal {
    pub name: RecoveryOriginalName,
    pub raw: Vec<u8>,
    pub stamp: NativeRetirementFileStamp,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::store) struct RecoveryGuard {
    pub name: RecoveryGuardName,
    pub raw: Vec<u8>,
}
/// Original producer DATA captured before its first durable preparation.
/// Keeping every nonce here permits exact partial preparation repair, never
/// regenerating a missing guard after restart. This is not a Prepared capability.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::store) struct OwnerRecoveryPlan {
    pub intent: Box<serde_json::value::RawValue>,
    pub originals: Vec<RecoveryOriginal>,
    pub guards: Vec<RecoveryGuard>,
}
impl OwnerRecoveryPlan {
    /// Exact entries of the original schema1 preparation, for bounded resync
    /// after a partial write. No later phase or OS effect is represented here.
    pub(in crate::store) fn preparation_entries(&self) -> JournalResult<Vec<(String, Vec<u8>)>> {
        let intent = self.validated_intent()?;
        let phase = RecoveryPhase {
            schema: 1,
            kind: RecoveryKind::LegacyOwnerRecovery,
            transaction_id: intent.transaction_id.clone(),
            sequence: intent.sequence,
            raw_intent_sha256: Sha256Digest::of_bytes(self.intent.get().as_bytes()),
            stage: OwnerRecoveryStage::Prepared,
            previous: None,
            originals: Vec::new(),
            guards: Vec::new(),
            startup_post: None,
            boot_observation: None,
        };
        let mut entries = vec![
            (
                member(&intent.transaction_id, "intent"),
                self.intent.get().as_bytes().to_vec(),
            ),
            (
                member(&intent.transaction_id, "prepared"),
                serde_json::to_vec(&phase).map_err(|_| JournalError::InvalidInput)?,
            ),
        ];
        entries.extend(self.originals.iter().map(|o| {
            (
                member(&intent.transaction_id, o.name.suffix()),
                o.raw.clone(),
            )
        }));
        entries.extend(self.guards.iter().map(|g| {
            (
                member(&intent.transaction_id, g.name.suffix()),
                g.raw.clone(),
            )
        }));
        Ok(entries)
    }
    pub(in crate::store) fn validated_intent(&self) -> JournalResult<LegacyOwnerRecoveryIntent> {
        let intent: LegacyOwnerRecoveryIntent =
            serde_json::from_str(self.intent.get()).map_err(|_| JournalError::InvalidInput)?;
        valid_intent(&intent)?;
        // The existing C writer emits canonical intent bytes; require its exact
        // original encoding up front rather than normalizing recorded history.
        if intent.schema != 1
            || serde_json::to_vec(&intent).map_err(|_| JournalError::InvalidInput)?
                != self.intent.get().as_bytes()
            || self.originals.len() != intent.originals.len()
            || self.guards.len() != intent.guards.len()
        {
            return Err(JournalError::Conflict);
        }
        for (raw, binding) in self.originals.iter().zip(&intent.originals) {
            if raw.name != binding.name
                || raw.stamp != binding.stamp
                || raw.raw.is_empty()
                || raw.raw.len() > MAX_RECOVERY_RAW
                || Sha256Digest::of_bytes(&raw.raw) != binding.stamp.content_sha256()
            {
                return Err(JournalError::Conflict);
            }
        }
        for (raw, binding) in self.guards.iter().zip(&intent.guards) {
            if raw.name != binding.name
                || raw.raw.len() as u64 != binding.byte_len
                || Sha256Digest::of_bytes(&raw.raw) != binding.sha256
            {
                return Err(JournalError::Conflict);
            }
        }
        Ok(intent)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::store) enum OwnerRecoveryStage {
    Prepared,
    RestartExcluded,
    BootObserved,
    Archived,
    GuardsHeld,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::store) struct RecoveryOriginalPost {
    pub name: RecoveryOriginalName,
    pub stamp: NativeRetirementFileStamp,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::store) struct RecoveryGuardPost {
    pub name: RecoveryGuardName,
    pub stamp: NativeRetirementFileStamp,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryPhase {
    schema: u16,
    kind: RecoveryKind,
    transaction_id: TransactionId,
    sequence: u64,
    raw_intent_sha256: Sha256Digest,
    stage: OwnerRecoveryStage,
    previous: Option<Sha256Digest>,
    originals: Vec<RecoveryOriginalPost>,
    guards: Vec<RecoveryGuardPost>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    startup_post: Option<NativeRetirementFileStamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    boot_observation: Option<RecoveryBoot>,
}
pub(in crate::store) struct OriginalOwnerRecovery {
    pub intent: LegacyOwnerRecoveryIntent,
    pub raw_intent: Vec<u8>,
    pub originals: Vec<RecoveryOriginal>,
    pub guards: Vec<RecoveryGuard>,
    pub authorization_plan: Option<Vec<u8>>,
    pub startup_raw: Option<Vec<u8>>,
    phases: Vec<(Vec<u8>, RecoveryPhase)>,
}
impl OriginalOwnerRecovery {
    pub(in crate::store) fn stage(&self) -> Option<OwnerRecoveryStage> {
        self.phases.last().map(|(_, p)| p.stage)
    }
    pub(in crate::store) fn guards_held_posts(&self) -> Option<&[RecoveryGuardPost]> {
        self.phases
            .last()
            .filter(|(_, phase)| phase.stage == OwnerRecoveryStage::GuardsHeld)
            .map(|(_, phase)| phase.guards.as_slice())
    }
    fn last_digest(&self) -> Option<Sha256Digest> {
        self.phases
            .last()
            .map(|(raw, _)| Sha256Digest::of_bytes(raw))
    }
}
pub(in crate::store) struct OwnerRecoveryInventory {
    pub used: BTreeSet<String>,
    pub records: Vec<OriginalOwnerRecovery>,
}
/// These values can only be minted by original-byte parser under the owned
/// writer. They retain it; cancellation/Drop neither clears it nor undoes work.
pub(in crate::store) struct PreparedLegacyOwnerRecovery {
    owner: OwnedConfigurationRoot,
    namespace: (u64, u64),
    original: OriginalOwnerRecovery,
}
pub(in crate::store) struct ArchivedLegacyOwnerRecovery {
    prepared: PreparedLegacyOwnerRecovery,
}
pub(in crate::store) struct LegacyGuardsHeld {
    archived: ArchivedLegacyOwnerRecovery,
}
impl PreparedLegacyOwnerRecovery {
    pub(in crate::store) fn startup_checkpoint(&self) -> Option<&WindowsStartupCheckpoint> {
        self.original.intent.startup_checkpoint.as_ref()
    }
    pub(in crate::store) fn startup_raw(&self) -> Option<&[u8]> {
        self.original.startup_raw.as_deref()
    }
    pub(in crate::store) fn startup_post(&self) -> Option<&NativeRetirementFileStamp> {
        self.original
            .phases
            .last()
            .and_then(|(_, p)| p.startup_post.as_ref())
    }
    pub(in crate::store) fn boot_observation(&self) -> Option<&RecoveryBoot> {
        self.original
            .phases
            .last()
            .and_then(|(_, p)| p.boot_observation.as_ref())
    }
    pub(in crate::store) fn intent(&self) -> &LegacyOwnerRecoveryIntent {
        &self.original.intent
    }
    pub(in crate::store) fn stage(&self) -> Option<OwnerRecoveryStage> {
        self.original.stage()
    }
    pub(in crate::store) fn into_archived(self) -> JournalResult<ArchivedLegacyOwnerRecovery> {
        if self.stage() != Some(OwnerRecoveryStage::Archived) {
            return Err(JournalError::Conflict);
        }
        Ok(ArchivedLegacyOwnerRecovery { prepared: self })
    }
    pub(in crate::store) fn into_guards_held(self) -> JournalResult<LegacyGuardsHeld> {
        if self.stage() != Some(OwnerRecoveryStage::GuardsHeld) {
            return Err(JournalError::Conflict);
        }
        Ok(LegacyGuardsHeld {
            archived: ArchivedLegacyOwnerRecovery { prepared: self },
        })
    }
    pub(in crate::store) fn matches_owner(&self, owner: &OwnedConfigurationRoot) -> bool {
        self.owner.same_authority(owner)
    }
    pub(in crate::store) fn originals(&self) -> &[RecoveryOriginal] {
        &self.original.originals
    }
    pub(in crate::store) fn guard_bytes(&self) -> &[RecoveryGuard] {
        &self.original.guards
    }
    pub(in crate::store) fn authorization_plan(&self) -> Option<&[u8]> {
        self.original.authorization_plan.as_deref()
    }
    pub(in crate::store) fn guards_held_posts(&self) -> Option<&[RecoveryGuardPost]> {
        self.original.guards_held_posts()
    }
    pub(in crate::store) fn archived_original_posts(&self) -> Option<&[RecoveryOriginalPost]> {
        self.original
            .phases
            .iter()
            .find(|(_, p)| p.stage == OwnerRecoveryStage::Archived)
            .map(|(_, p)| p.originals.as_slice())
    }
}
impl ArchivedLegacyOwnerRecovery {
    pub(in crate::store) fn prepared(&self) -> &PreparedLegacyOwnerRecovery {
        &self.prepared
    }
}
impl LegacyGuardsHeld {
    pub(in crate::store) fn prepared(&self) -> &PreparedLegacyOwnerRecovery {
        &self.archived.prepared
    }
}
fn member(id: &TransactionId, suffix: &str) -> String {
    format!("txn-{}.owner-recovery-{suffix}", id.as_str())
}
fn bytes<'a>(scan: &'a JournalObservation, name: &str) -> JournalResult<Option<&'a [u8]>> {
    let mut matching = scan.files.iter().filter(|f| f.name == name);
    let one = matching.next();
    if matching.next().is_some() {
        return Err(JournalError::Conflict);
    }
    Ok(one.map(|f| f.bytes()))
}
fn windows_boot_micros(boot: &RecoveryBoot) -> Option<u64> {
    let raw = boot.id.strip_prefix("wmi-lastboot-unix-micros:")?;
    let n: u64 = raw.parse().ok()?;
    (n > 0 && raw == n.to_string() && boot.started_at_ms == n / 1000).then_some(n)
}
fn startup_valid(i: &LegacyOwnerRecoveryIntent) -> bool {
    let Some(c) = &i.startup_checkpoint else {
        return matches!(i.schema, 1 | 2)
            && i.restart == RecoveryRestartBinding::ForegroundOnlyNoInstalledManager;
    };
    if i.schema != 3
        || i.restart != RecoveryRestartBinding::WindowsStartupExclusion
        || !matches!(
            i.config_root,
            styx_contracts::native_management::NativeRootIdentity::Windows { .. }
        )
        || !matches!(c.original_link, NativeRetirementFileStamp::Windows { .. })
        || !c.original_link.valid_for(&i.config_root)
        || windows_boot_micros(&i.current_boot).is_none()
        || c.app.pid == 0
        || c.core.pid == 0
        || c.app.pid == c.core.pid
        || c.app.birth_filetime == 0
        || c.core.birth_filetime < c.app.birth_filetime
    {
        return false;
    }
    let Some(boot_filetime) = windows_boot_micros(&i.current_boot)
        .and_then(|n| n.checked_add(11_644_473_600_000_000))
        .and_then(|n| n.checked_mul(10))
    else {
        return false;
    };
    if c.app.birth_filetime < boot_filetime
        || c.original_publisher_spki_sha256 != i.publisher_spki_sha256
        || !matches!((&c.original_link, &i.config_root),
            (NativeRetirementFileStamp::Windows {volume_serial: a, ..},
             styx_contracts::native_management::NativeRootIdentity::Windows {volume_serial: b, ..}) if a == b)
    {
        return false;
    }
    [
        &c.startup_directory,
        &c.target,
        &c.arguments,
        &c.working_directory,
    ]
    .iter()
    .all(|s| !s.is_empty() && s.len() <= 32768 && !s.contains('\0'))
}
fn recovery_stages(schema: u16) -> Vec<(OwnerRecoveryStage, &'static str)> {
    let mut stages = vec![(OwnerRecoveryStage::Prepared, "prepared")];
    if schema == 3 {
        stages.extend([
            (OwnerRecoveryStage::RestartExcluded, "restart-excluded"),
            (OwnerRecoveryStage::BootObserved, "boot-observed"),
        ]);
    }
    stages.extend([
        (OwnerRecoveryStage::Archived, "archived"),
        (OwnerRecoveryStage::GuardsHeld, "guards-held"),
    ]);
    stages
}
fn valid_intent(i: &LegacyOwnerRecoveryIntent) -> JournalResult<()> {
    let names: BTreeSet<_> = i.originals.iter().map(|f| f.name).collect();
    let guards: BTreeSet<_> = i.guards.iter().map(|g| g.name).collect();
    let shape = match (&i.basis, &i.previous_boot, i.schema) {
        (None, Some(previous), 1) => {
            !previous.id.is_empty()
                && previous.id.len() <= 256
                && previous.id != i.current_boot.id
                && previous.started_at_ms < i.current_boot.started_at_ms
                && names.contains(&RecoveryOriginalName::Owner)
                && names.contains(&RecoveryOriginalName::Lock)
                && names.len() <= 3
        }
        (Some(RecoveryBasis::ExplicitLegacyMaintenance { observer_pid, .. }), None, 2 | 3) => {
            *observer_pid > 0
                && names
                    == BTreeSet::from([RecoveryOriginalName::Lock, RecoveryOriginalName::Observer])
        }
        _ => false,
    };
    if !shape
        || !startup_valid(i)
        || i.kind != RecoveryKind::LegacyOwnerRecovery
        || i.sequence == 0
        || !i.config_root.valid_pair(&i.config_root)
        || i.current_boot.id.is_empty()
        || i.current_boot.id.len() > 256
        || i.current_boot.started_at_ms == 0
        || names.len() != i.originals.len()
        || guards.len() != 4
        || i.guards.len() != 4
        || i.originals
            .iter()
            .any(|f| !f.stamp.valid_for(&i.config_root))
        || i.guards.iter().any(|g| !(16..=4096).contains(&g.byte_len))
    {
        return Err(JournalError::InvalidInput);
    }
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationBoot {
    platform: String,
    id: String,
    #[serde(rename = "startedAt")]
    started_at: f64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationFile {
    name: String,
    ino: String,
    dev: String,
    sha256: Sha256Digest,
    #[serde(rename = "modifiedAt")]
    modified_at: f64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationPlan {
    schema: u16,
    action: String,
    #[serde(rename = "stateDir")]
    state_dir: String,
    #[serde(rename = "deviceId")]
    device_id: styx_contracts::identity::DeviceId,
    #[serde(rename = "identitySha256")]
    identity_sha256: Sha256Digest,
    #[serde(rename = "configurationHash")]
    configuration_hash: Sha256Digest,
    #[serde(rename = "currentBoot")]
    current_boot: AuthorizationBoot,
    #[serde(rename = "previousOwnerPid")]
    previous_owner_pid: u32,
    files: Vec<AuthorizationFile>,
    #[serde(rename = "previousWorkOutcome")]
    previous_work_outcome: String,
    #[serde(rename = "identityMutation")]
    identity_mutation: String,
    #[serde(rename = "requiresExplicitAuthorization")]
    requires_explicit_authorization: bool,
    #[serde(rename = "planSha256", default)]
    _legacy_plan_sha256: Option<Sha256Digest>,
    #[serde(rename = "startupCheckpointSha256", default)]
    startup_checkpoint_sha256: Option<Sha256Digest>,
}
fn file_tuple(s: &NativeRetirementFileStamp) -> JournalResult<(u64, u64, i64, i64)> {
    Ok(match s {
        NativeRetirementFileStamp::Linux { stamp } | NativeRetirementFileStamp::Macos { stamp } => {
            (
                stamp.device,
                stamp.inode,
                stamp.modified_seconds,
                stamp.modified_nanoseconds,
            )
        }
        NativeRetirementFileStamp::Windows {
            volume_serial,
            file_id,
            modified_seconds,
            modified_nanoseconds,
            ..
        } => {
            // FILE_BASIC_INFO is retained in its original FILETIME epoch in
            // FileObservation/journal stamps. Only the comparison with legacy
            // Node fs.Stats.mtimeMs projects it to the Unix epoch.
            // https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime
            if *modified_seconds < 0 || !(0..1_000_000_000).contains(modified_nanoseconds) {
                return Err(JournalError::Conflict);
            }
            (
                *volume_serial,
                *file_id,
                modified_seconds
                    .checked_sub(11_644_473_600)
                    .ok_or(JournalError::Conflict)?,
                *modified_nanoseconds,
            )
        }
    })
}
fn validate_authorization_plan(
    i: &LegacyOwnerRecoveryIntent,
    raw: Option<&[u8]>,
) -> JournalResult<()> {
    let Some(RecoveryBasis::ExplicitLegacyMaintenance {
        plan_sha256,
        device_id,
        identity_json_sha256,
        configuration_hash,
        observer_pid,
    }) = &i.basis
    else {
        return if raw.is_none() {
            Ok(())
        } else {
            Err(JournalError::Conflict)
        };
    };
    let raw = raw.ok_or(JournalError::Conflict)?;
    if raw.len() > MAX_INTENT || Sha256Digest::of_bytes(raw) != *plan_sha256 {
        return Err(JournalError::Conflict);
    }
    let p: AuthorizationPlan = serde_json::from_slice(raw).map_err(|_| JournalError::Conflict)?;
    let platform = match i.config_root {
        styx_contracts::native_management::NativeRootIdentity::Linux { .. } => "linux",
        styx_contracts::native_management::NativeRootIdentity::Macos { .. } => "darwin",
        styx_contracts::native_management::NativeRootIdentity::Windows { .. } => "win32",
    };
    let path = std::path::Path::new(&p.state_dir);
    let plan_scope_valid = if let Some(c) = &i.startup_checkpoint {
        let canonical = serde_json::to_vec(c).map_err(|_| JournalError::Conflict)?;
        p.schema == 2
            && p.action == "retire_legacy_foreground_owner_after_windows_restart"
            && p.startup_checkpoint_sha256 == Some(Sha256Digest::of_bytes(&canonical))
    } else {
        p.schema == 1
            && p.action == "retire_legacy_foreground_owner"
            && p.startup_checkpoint_sha256.is_none()
    };
    if !plan_scope_valid
        || !path.is_absolute()
        || path.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
        || p.device_id != *device_id
        || p.identity_sha256 != *identity_json_sha256
        || p.configuration_hash != *configuration_hash
        || p.previous_owner_pid != *observer_pid
        || p.current_boot.platform != platform
        || p.current_boot.id != i.current_boot.id
        || !p.current_boot.started_at.is_finite()
        || p.current_boot.started_at < 0.0
        || p.current_boot.started_at.floor() as u64 != i.current_boot.started_at_ms
        || p.previous_work_outcome != "unknown_not_replayed"
        || p.identity_mutation != "none"
        || !p.requires_explicit_authorization
        || p.files.len() != i.originals.len()
    {
        return Err(JournalError::Conflict);
    }
    for (f, b) in p.files.iter().zip(&i.originals) {
        let (dev, ino, sec, nano) = file_tuple(&b.stamp)?;
        if f.name != b.name.source_name()
            || f.dev != dev.to_string()
            || f.ino != ino.to_string()
            || f.sha256 != b.stamp.content_sha256()
            || !f.modified_at.is_finite()
            || f.modified_at != (sec as f64 * 1000.0 + nano as f64 / 1_000_000.0).floor()
            || f.modified_at >= p.current_boot.started_at
        {
            return Err(JournalError::Conflict);
        }
    }
    Ok(())
}
fn validate_current_authorization(
    state: &ConfigurationState,
    i: &LegacyOwnerRecoveryIntent,
    raw: Option<&[u8]>,
) -> JournalResult<()> {
    validate_authorization_plan(i, raw)?;
    let Some(raw) = raw else { return Ok(()) };
    let plan: AuthorizationPlan =
        serde_json::from_slice(raw).map_err(|_| JournalError::Conflict)?;
    let opened =
        crate::store::PrivateRoot::open(&plan.state_dir).map_err(|_| JournalError::Unknown)?;
    if opened.identity() != state.root.identity() {
        return Err(JournalError::Conflict);
    }
    let deployment = state
        .root
        .read_raw("deployment.json", 1024 * 1024)
        .map_err(|_| JournalError::Unknown)?;
    let d: serde_json::Value =
        serde_json::from_slice(deployment.bytes()).map_err(|_| JournalError::Conflict)?;
    if styx_contracts::legacy_deployment::deployment_connection_hash(deployment.bytes())
        .map_err(|_| JournalError::Conflict)?
        != plan.configuration_hash
    {
        return Err(JournalError::Conflict);
    }
    let host = d
        .pointer("/host/baseDir")
        .and_then(|v| v.as_str())
        .ok_or(JournalError::Conflict)?;
    let root = crate::store::PrivateRoot::open(host).map_err(|_| JournalError::Unknown)?;
    let identity = root
        .read_raw("device/identity.json", 1024 * 1024)
        .map_err(|_| JournalError::Unknown)?;
    if Sha256Digest::of_bytes(identity.bytes()) != plan.identity_sha256 {
        return Err(JournalError::Conflict);
    }
    let identity: serde_json::Value =
        serde_json::from_slice(identity.bytes()).map_err(|_| JournalError::Conflict)?;
    if identity.get("device_id").and_then(|v| v.as_str()) != Some(plan.device_id.as_str()) {
        return Err(JournalError::Conflict);
    }
    Ok(())
}
fn validate_startup_phase(
    original: &OriginalOwnerRecovery,
    p: &RecoveryPhase,
) -> JournalResult<()> {
    let Some(c) = &original.intent.startup_checkpoint else {
        return if p.startup_post.is_none() && p.boot_observation.is_none() {
            Ok(())
        } else {
            Err(JournalError::Conflict)
        };
    };
    if p.stage == OwnerRecoveryStage::Prepared {
        return if p.startup_post.is_none() && p.boot_observation.is_none() {
            Ok(())
        } else {
            Err(JournalError::Conflict)
        };
    }
    let post = p.startup_post.as_ref().ok_or(JournalError::Conflict)?;
    if !c.original_link.same_file_after_rename(post) {
        return Err(JournalError::Conflict);
    }
    if p.stage == OwnerRecoveryStage::RestartExcluded {
        return if p.boot_observation.is_none() {
            Ok(())
        } else {
            Err(JournalError::Conflict)
        };
    }
    let previous = original.phases.last().ok_or(JournalError::Conflict)?;
    if previous.1.startup_post.as_ref() != Some(post) {
        return Err(JournalError::Conflict);
    }
    let after = p.boot_observation.as_ref().ok_or(JournalError::Conflict)?;
    let old = windows_boot_micros(&original.intent.current_boot).ok_or(JournalError::Conflict)?;
    let new = windows_boot_micros(after).ok_or(JournalError::Conflict)?;
    // Same conservative whole-second boundary as the actual BootStamp adapter.
    if new / 1_000_000 <= old / 1_000_000 {
        return Err(JournalError::Conflict);
    }
    if p.stage != OwnerRecoveryStage::BootObserved
        && previous.1.boot_observation.as_ref() != Some(after)
    {
        return Err(JournalError::Conflict);
    }
    Ok(())
}
pub(in crate::store) fn scan_owner_recoveries(
    scan: &JournalObservation,
) -> JournalResult<OwnerRecoveryInventory> {
    let mut result = OwnerRecoveryInventory {
        used: BTreeSet::new(),
        records: Vec::new(),
    };
    for f in scan
        .files
        .iter()
        .filter(|f| f.name.ends_with(".owner-recovery-intent"))
    {
        let intent: LegacyOwnerRecoveryIntent =
            serde_json::from_slice(f.bytes()).map_err(|_| JournalError::Conflict)?;
        valid_intent(&intent)?;
        if f.name != member(&intent.transaction_id, "intent") || f.bytes().len() > MAX_INTENT {
            return Err(JournalError::Conflict);
        }
        result.used.insert(f.name.clone());
        let mut original = OriginalOwnerRecovery {
            intent,
            raw_intent: f.bytes().to_vec(),
            originals: Vec::new(),
            guards: Vec::new(),
            authorization_plan: None,
            startup_raw: None,
            phases: Vec::new(),
        };
        for b in &original.intent.originals {
            let name = member(&original.intent.transaction_id, b.name.suffix());
            let raw = bytes(scan, &name)?.ok_or(JournalError::Conflict)?;
            if raw.len() > MAX_RECOVERY_RAW
                || Sha256Digest::of_bytes(raw) != b.stamp.content_sha256()
            {
                return Err(JournalError::Conflict);
            }
            original.originals.push(RecoveryOriginal {
                name: b.name,
                raw: raw.to_vec(),
                stamp: b.stamp.clone(),
            });
            result.used.insert(name);
        }
        for b in &original.intent.guards {
            let name = member(&original.intent.transaction_id, b.name.suffix());
            let raw = bytes(scan, &name)?.ok_or(JournalError::Conflict)?;
            if raw.len() as u64 != b.byte_len || Sha256Digest::of_bytes(raw) != b.sha256 {
                return Err(JournalError::Conflict);
            }
            original.guards.push(RecoveryGuard {
                name: b.name,
                raw: raw.to_vec(),
            });
            result.used.insert(name);
        }
        let plan_name = member(&original.intent.transaction_id, "authorization-plan");
        original.authorization_plan = bytes(scan, &plan_name)?.map(|b| b.to_vec());
        validate_authorization_plan(&original.intent, original.authorization_plan.as_deref())?;
        if original.authorization_plan.is_some() {
            result.used.insert(plan_name);
        }
        let startup_name = member(&original.intent.transaction_id, "startup-original");
        original.startup_raw = bytes(scan, &startup_name)?.map(|b| b.to_vec());
        match (&original.intent.startup_checkpoint, &original.startup_raw) {
            (None, None) => {}
            (Some(c), Some(raw))
                if !raw.is_empty()
                    && raw.len() <= MAX_RECOVERY_RAW
                    && matches!(&c.original_link, NativeRetirementFileStamp::Windows {byte_len, ..} if *byte_len == raw.len() as u64)
                    && Sha256Digest::of_bytes(raw) == c.original_link.content_sha256() =>
            {
                result.used.insert(startup_name);
            }
            _ => return Err(JournalError::Conflict),
        }
        // Reserved Windows-only phase files on an old schema are explicit
        // conflicts, not invisible optional evidence or a second scanner.
        if original.intent.schema != 3 {
            for suffix in ["restart-excluded", "boot-observed"] {
                if bytes(scan, &member(&original.intent.transaction_id, suffix))?.is_some() {
                    return Err(JournalError::Conflict);
                }
            }
        }
        let mut missing = false;
        for (stage, suffix) in recovery_stages(original.intent.schema) {
            let name = member(&original.intent.transaction_id, suffix);
            let Some(raw) = bytes(scan, &name)? else {
                missing = true;
                continue;
            };
            if missing {
                return Err(JournalError::Conflict);
            }
            let p: RecoveryPhase =
                serde_json::from_slice(raw).map_err(|_| JournalError::Conflict)?;
            if raw.len() > MAX_INTENT
                || p.schema != original.intent.schema
                || p.kind != RecoveryKind::LegacyOwnerRecovery
                || p.transaction_id != original.intent.transaction_id
                || p.sequence != original.intent.sequence
                || p.raw_intent_sha256 != Sha256Digest::of_bytes(&original.raw_intent)
                || p.stage != stage
                || p.previous != original.last_digest()
            {
                return Err(JournalError::Conflict);
            }
            validate_startup_phase(&original, &p)?;
            if matches!(
                stage,
                OwnerRecoveryStage::Prepared
                    | OwnerRecoveryStage::RestartExcluded
                    | OwnerRecoveryStage::BootObserved
            ) {
                if !p.originals.is_empty() || !p.guards.is_empty() {
                    return Err(JournalError::Conflict);
                }
            } else {
                if p.originals.len() != original.intent.originals.len()
                    || p.originals
                        .iter()
                        .zip(&original.intent.originals)
                        .any(|(post, b)| {
                            post.name != b.name || !b.stamp.same_file_after_rename(&post.stamp)
                        })
                {
                    return Err(JournalError::Conflict);
                }
                if stage == OwnerRecoveryStage::Archived {
                    if !p.guards.is_empty() {
                        return Err(JournalError::Conflict);
                    }
                } else if p.guards.len() != 4
                    || p.guards
                        .iter()
                        .zip(&original.intent.guards)
                        .any(|(post, b)| {
                            post.name != b.name
                                || !post.stamp.valid_for(&original.intent.config_root)
                                || post.stamp.content_sha256() != b.sha256
                        })
                {
                    return Err(JournalError::Conflict);
                }
            }
            original.phases.push((raw.to_vec(), p));
            result.used.insert(name);
        }
        result.records.push(original);
    }
    if result.records.len() > 1 {
        return Err(JournalError::Conflict);
    }
    Ok(result)
}
fn original(scan: &JournalObservation, id: &TransactionId) -> JournalResult<OriginalOwnerRecovery> {
    let mut records = scan_owner_recoveries(scan)?.records;
    if records.len() != 1 || records[0].intent.transaction_id != *id {
        return Err(JournalError::Conflict);
    }
    Ok(records.remove(0))
}
fn canonical(state: &ConfigurationState, intent: &LegacyOwnerRecoveryIntent) -> JournalResult<()> {
    if native_writer::actual_root(state.root.identity())? != intent.config_root {
        return Err(JournalError::Conflict);
    }
    for (name, hash) in [
        ("deployment.json", intent.deployment_raw_sha256),
        ("state.json", intent.before_state_sha256),
    ] {
        let raw = state
            .root
            .read_raw(name, 1024 * 1024)
            .map_err(|_| JournalError::Unknown)?;
        if Sha256Digest::of_bytes(raw.bytes()) != hash {
            return Err(JournalError::Conflict);
        }
        if name == "state.json" {
            native_writer::reject_migration_v2_collision(raw.bytes())?;
        }
    }
    Ok(())
}
/// Inspect only an unfinished schema3 preparation. No effect was authorized:
/// Prepared must be absent and every existing member must match the exact same
/// original request. The projected baseline is for admission/budget inspection,
/// never an alternate parser or a modified on-disk journal.
fn incomplete_startup_preparation(
    scan: &JournalObservation,
    intent: &LegacyOwnerRecoveryIntent,
    entries: &[(String, Vec<u8>)],
) -> JournalResult<Option<JournalObservation>> {
    if intent.schema != 3 || bytes(scan, &member(&intent.transaction_id, "prepared"))?.is_some() {
        return Ok(None);
    }
    let prefix = format!("txn-{}.owner-recovery-", intent.transaction_id.as_str());
    let members: Vec<_> = scan
        .files
        .iter()
        .filter(|f| f.name.starts_with(&prefix))
        .collect();
    if members.is_empty() {
        return Ok(None);
    }
    // Intent is published first. A missing intent with later attachments is not
    // a supported interrupted write and must not be reconstructed by guessing.
    if bytes(scan, &member(&intent.transaction_id, "intent"))?.is_none() {
        return Err(JournalError::Conflict);
    }
    for file in members {
        if entries
            .iter()
            .filter(|(name, _)| name == &file.name)
            .count()
            != 1
            || entries
                .iter()
                .find(|(name, _)| name == &file.name)
                .is_none_or(|(_, raw)| raw.as_slice() != file.bytes())
        {
            return Err(JournalError::Conflict);
        }
    }
    let files: Vec<_> = scan
        .files
        .iter()
        .filter(|f| !f.name.starts_with(&prefix))
        .map(|f| crate::store::secure_journal::ObservedJournalFile {
            name: f.name.clone(),
            bytes: f.bytes().to_vec(),
        })
        .collect();
    Ok(Some(JournalObservation {
        total_bytes: files.iter().map(|f| f.bytes().len()).sum(),
        files,
    }))
}

impl OwnedManagementJournal {
    pub(in crate::store) fn owner_recovery_prepared_matches(
        &self,
        prepared: &PreparedLegacyOwnerRecovery,
    ) -> bool {
        prepared.matches_owner(&self.owner) && prepared.namespace == self.namespace
    }
    pub(in crate::store) fn validate_legacy_owner_prepared(
        &self,
        maintenance: &ConfigurationMaintenance,
        prepared: &PreparedLegacyOwnerRecovery,
    ) -> JournalResult<()> {
        if !self.owner_recovery_prepared_matches(prepared)
            || maintenance.transaction_id() != &prepared.intent().transaction_id
        {
            return Err(JournalError::Conflict);
        }
        self.owner.with_maintenance(maintenance, |state| {
            canonical(state, prepared.intent())?;
            self.with_directory_locked(state, |dir| {
                let scan = files::scan(dir, self.budget)?;
                let inventory = super::super::platform::inventory(&scan)?;
                if !inventory.orphans.is_empty() {
                    return Err(JournalError::Conflict);
                }
                let original = original(&scan, &prepared.intent().transaction_id)?;
                if original.raw_intent != prepared.original.raw_intent
                    || original.last_digest() != prepared.original.last_digest()
                {
                    return Err(JournalError::Conflict);
                }
                Ok(())
            })
        })
    }
    pub(in crate::store) fn prepare_legacy_owner_recovery(
        &mut self,
        maintenance: &ConfigurationMaintenance,
        intent: &LegacyOwnerRecoveryIntent,
        originals: Vec<RecoveryOriginal>,
        guards: Vec<RecoveryGuard>,
    ) -> JournalResult<PreparedLegacyOwnerRecovery> {
        if intent.schema != 1 {
            return Err(JournalError::Conflict);
        }
        self.prepare_owner_recovery(maintenance, intent, originals, guards, None, None)
    }
    pub(in crate::store) fn prepare_authorized_legacy_owner_recovery(
        &mut self,
        maintenance: &ConfigurationMaintenance,
        intent: &LegacyOwnerRecoveryIntent,
        originals: Vec<RecoveryOriginal>,
        guards: Vec<RecoveryGuard>,
        authorization_plan: &[u8],
    ) -> JournalResult<PreparedLegacyOwnerRecovery> {
        if intent.schema != 2 {
            return Err(JournalError::Conflict);
        }
        self.prepare_owner_recovery(
            maintenance,
            intent,
            originals,
            guards,
            Some(authorization_plan),
            None,
        )
    }
    /// Private same-journal preparation; caller's explicit reviewed-plan authority
    /// is separate. ALL attachments and Prepared must be durable before any effect.
    pub(in crate::store) fn prepare_windows_restart_checkpoint(
        &mut self,
        maintenance: &ConfigurationMaintenance,
        intent: &LegacyOwnerRecoveryIntent,
        originals: Vec<RecoveryOriginal>,
        guards: Vec<RecoveryGuard>,
        authorization_plan: &[u8],
        startup_raw: &[u8],
    ) -> JournalResult<PreparedLegacyOwnerRecovery> {
        if intent.schema != 3 {
            return Err(JournalError::Conflict);
        }
        self.prepare_owner_recovery(
            maintenance,
            intent,
            originals,
            guards,
            Some(authorization_plan),
            Some(startup_raw),
        )
    }
    fn prepare_owner_recovery(
        &mut self,
        maintenance: &ConfigurationMaintenance,
        intent: &LegacyOwnerRecoveryIntent,
        originals: Vec<RecoveryOriginal>,
        guards: Vec<RecoveryGuard>,
        authorization_plan: Option<&[u8]>,
        startup_raw: Option<&[u8]>,
    ) -> JournalResult<PreparedLegacyOwnerRecovery> {
        valid_intent(intent)?;
        if maintenance.transaction_id() != &intent.transaction_id
            || originals.len() != intent.originals.len()
            || guards.len() != 4
        {
            return Err(JournalError::Conflict);
        }
        let raw = serde_json::to_vec(intent).map_err(|_| JournalError::InvalidInput)?;
        let phase = RecoveryPhase {
            schema: intent.schema,
            kind: RecoveryKind::LegacyOwnerRecovery,
            transaction_id: intent.transaction_id.clone(),
            sequence: intent.sequence,
            raw_intent_sha256: Sha256Digest::of_bytes(&raw),
            stage: OwnerRecoveryStage::Prepared,
            previous: None,
            originals: Vec::new(),
            guards: Vec::new(),
            startup_post: None,
            boot_observation: None,
        };
        let mut entries = vec![
            (member(&intent.transaction_id, "intent"), raw),
            (
                member(&intent.transaction_id, "prepared"),
                serde_json::to_vec(&phase).map_err(|_| JournalError::InvalidInput)?,
            ),
        ];
        for (o, b) in originals.iter().zip(&intent.originals) {
            if o.name != b.name || o.stamp != b.stamp {
                return Err(JournalError::Conflict);
            }
            entries.push((
                member(&intent.transaction_id, o.name.suffix()),
                o.raw.clone(),
            ));
        }
        for (g, b) in guards.iter().zip(&intent.guards) {
            if g.name != b.name {
                return Err(JournalError::Conflict);
            }
            entries.push((
                member(&intent.transaction_id, g.name.suffix()),
                g.raw.clone(),
            ));
        }
        validate_authorization_plan(intent, authorization_plan)?;
        if let Some(raw) = authorization_plan {
            entries.push((
                member(&intent.transaction_id, "authorization-plan"),
                raw.to_vec(),
            ));
        }
        if let Some(raw) = startup_raw {
            entries.push((
                member(&intent.transaction_id, "startup-original"),
                raw.to_vec(),
            ));
        }
        if intent.schema == 3 {
            // New schema only: publish Prepared last. An incomplete preparation
            // cannot authorize the OS rename. Old record ordering/bytes unchanged.
            let position = entries
                .iter()
                .position(|(name, _)| *name == member(&intent.transaction_id, "prepared"))
                .ok_or(JournalError::Conflict)?;
            let prepared_entry = entries.remove(position);
            entries.push(prepared_entry);
        }
        // Validate the exact candidate bytes with the SAME scanner before write.
        let synthetic = JournalObservation {
            total_bytes: entries.iter().map(|(_, b)| b.len()).sum(),
            files: entries
                .iter()
                .map(|(n, b)| crate::store::secure_journal::ObservedJournalFile {
                    name: n.clone(),
                    bytes: b.clone(),
                })
                .collect(),
        };
        original(&synthetic, &intent.transaction_id)?;
        self.owner.with_maintenance(maintenance, |state| {
            canonical(state, intent)?;
            validate_current_authorization(state, intent, authorization_plan)?;
            self.with_directory_locked(state, |dir| {
                let scan = files::scan(dir, self.budget)?;
                let baseline = incomplete_startup_preparation(&scan, intent, &entries)?;
                let baseline_scan = baseline.as_ref().unwrap_or(&scan);
                let plan_baseline = super::super::migration_plan::recovery_baseline(
                    baseline_scan,
                    intent,
                    &entries,
                )?;
                let inventory = super::super::platform::inventory(
                    plan_baseline.as_ref().unwrap_or(baseline_scan),
                )?;
                if !inventory.orphans.is_empty()
                    || inventory.has_legacy_handoffs()
                    || intent.sequence <= inventory.high_water
                    || inventory.transactions.iter().any(|t| {
                        t.intent.transaction_id == intent.transaction_id
                            || t.phase_receipts
                                .last()
                                .is_none_or(|p| p.stage != DurableStage::Committed)
                    })
                    || inventory
                        .transactions
                        .last()
                        .is_some_and(|t| t.intent.target_state_sha256 != intent.before_state_sha256)
                {
                    return Err(JournalError::Conflict);
                }
                let mut reserved = entries.clone();
                for (_, suffix) in recovery_stages(intent.schema).into_iter().skip(1) {
                    reserved.push((member(&intent.transaction_id, suffix), vec![0; MAX_INTENT]));
                }
                preflight(state, &scan, &reserved, self.budget)?;
                // immutable resyncs exact existing members and creates only
                // missing ones. Prepared remains last for this schema.
                for (name, raw) in &entries {
                    files::immutable(dir, name, raw, self.budget, &|_| {})?;
                }
                let parsed = original(&files::scan(dir, self.budget)?, &intent.transaction_id)?;
                Ok(PreparedLegacyOwnerRecovery {
                    owner: self.owner.clone(),
                    namespace: self.namespace,
                    original: parsed,
                })
            })
        })
    }
    fn append_owner_recovery(
        &mut self,
        maintenance: &ConfigurationMaintenance,
        prepared: &PreparedLegacyOwnerRecovery,
        stage: OwnerRecoveryStage,
        originals: Vec<RecoveryOriginalPost>,
        guards: Vec<RecoveryGuardPost>,
        startup_post: Option<NativeRetirementFileStamp>,
        boot_observation: Option<RecoveryBoot>,
    ) -> JournalResult<PreparedLegacyOwnerRecovery> {
        if !prepared.matches_owner(&self.owner)
            || prepared.namespace != self.namespace
            || maintenance.transaction_id() != &prepared.intent().transaction_id
        {
            return Err(JournalError::Conflict);
        }
        self.owner.with_maintenance(maintenance, |state| {
            canonical(state, prepared.intent())?;
            self.with_directory_locked(state, |dir| {
                let scan = files::scan(dir, self.budget)?;
                let inventory = super::super::platform::inventory(&scan)?;
                if !inventory.orphans.is_empty() {
                    return Err(JournalError::Conflict);
                }
                let old = original(&scan, &prepared.intent().transaction_id)?;
                let expected = match stage {
                    OwnerRecoveryStage::Prepared if old.intent.schema == 3 => None,
                    OwnerRecoveryStage::RestartExcluded if old.intent.schema == 3 => {
                        Some(OwnerRecoveryStage::Prepared)
                    }
                    OwnerRecoveryStage::BootObserved if old.intent.schema == 3 => {
                        Some(OwnerRecoveryStage::RestartExcluded)
                    }
                    OwnerRecoveryStage::Archived if old.intent.schema == 3 => {
                        Some(OwnerRecoveryStage::BootObserved)
                    }
                    OwnerRecoveryStage::Archived => Some(OwnerRecoveryStage::Prepared),
                    OwnerRecoveryStage::GuardsHeld => Some(OwnerRecoveryStage::Archived),
                    _ => return Err(JournalError::Conflict),
                };
                if old.raw_intent != prepared.original.raw_intent
                    || old.stage() != expected
                    || old.last_digest() != prepared.original.last_digest()
                {
                    return Err(JournalError::Conflict);
                }
                let phase = RecoveryPhase {
                    schema: old.intent.schema,
                    kind: RecoveryKind::LegacyOwnerRecovery,
                    transaction_id: old.intent.transaction_id.clone(),
                    sequence: old.intent.sequence,
                    raw_intent_sha256: Sha256Digest::of_bytes(&old.raw_intent),
                    stage,
                    previous: old.last_digest(),
                    originals,
                    guards,
                    startup_post,
                    boot_observation,
                };
                let suffix = match stage {
                    OwnerRecoveryStage::Prepared => "prepared",
                    OwnerRecoveryStage::RestartExcluded => "restart-excluded",
                    OwnerRecoveryStage::BootObserved => "boot-observed",
                    OwnerRecoveryStage::Archived => "archived",
                    OwnerRecoveryStage::GuardsHeld => "guards-held",
                };
                let name = member(&old.intent.transaction_id, suffix);
                let raw = serde_json::to_vec(&phase).map_err(|_| JournalError::InvalidInput)?;
                let mut check = files::scan(dir, self.budget)?;
                check.total_bytes += raw.len();
                check
                    .files
                    .push(crate::store::secure_journal::ObservedJournalFile {
                        name: name.clone(),
                        bytes: raw.clone(),
                    });
                original(&check, &old.intent.transaction_id)?;
                preflight(state, &scan, &[(name.clone(), raw.clone())], self.budget)?;
                files::immutable(dir, &name, &raw, self.budget, &|_| {})?;
                let result = original(&files::scan(dir, self.budget)?, &old.intent.transaction_id)?;
                Ok(PreparedLegacyOwnerRecovery {
                    owner: self.owner.clone(),
                    namespace: self.namespace,
                    original: result,
                })
            })
        })
    }
    /// Resume ONLY a complete immutable checkpoint whose final Prepared file
    /// was not published. The original scanner must already validate every raw
    /// attachment; no Windows effect was authorized before this append succeeds.
    pub(in crate::store) fn record_windows_restart_prepared(
        &mut self,
        maintenance: &ConfigurationMaintenance,
        prepared: &PreparedLegacyOwnerRecovery,
    ) -> JournalResult<PreparedLegacyOwnerRecovery> {
        self.append_owner_recovery(
            maintenance,
            prepared,
            OwnerRecoveryStage::Prepared,
            Vec::new(),
            Vec::new(),
            None,
            None,
        )
    }
    /// Actual retained OS effect producer supplies the post; this record attests
    /// the durable bytes/chain only, never derives OS completion from a DTO.
    pub(in crate::store) fn record_legacy_restart_excluded(
        &mut self,
        maintenance: &ConfigurationMaintenance,
        prepared: &PreparedLegacyOwnerRecovery,
        post: NativeRetirementFileStamp,
    ) -> JournalResult<PreparedLegacyOwnerRecovery> {
        self.append_owner_recovery(
            maintenance,
            prepared,
            OwnerRecoveryStage::RestartExcluded,
            Vec::new(),
            Vec::new(),
            Some(post),
            None,
        )
    }
    pub(in crate::store) fn record_legacy_boot_observed(
        &mut self,
        maintenance: &ConfigurationMaintenance,
        prepared: &PreparedLegacyOwnerRecovery,
        actual_boot: RecoveryBoot,
    ) -> JournalResult<PreparedLegacyOwnerRecovery> {
        self.append_owner_recovery(
            maintenance,
            prepared,
            OwnerRecoveryStage::BootObserved,
            Vec::new(),
            Vec::new(),
            prepared.startup_post().cloned(),
            Some(actual_boot),
        )
    }
    pub(in crate::store) fn record_legacy_owner_archived(
        &mut self,
        maintenance: &ConfigurationMaintenance,
        prepared: &PreparedLegacyOwnerRecovery,
        originals: Vec<RecoveryOriginalPost>,
    ) -> JournalResult<ArchivedLegacyOwnerRecovery> {
        Ok(ArchivedLegacyOwnerRecovery {
            prepared: self.append_owner_recovery(
                maintenance,
                prepared,
                OwnerRecoveryStage::Archived,
                originals,
                Vec::new(),
                prepared.startup_post().cloned(),
                prepared.boot_observation().cloned(),
            )?,
        })
    }
    pub(in crate::store) fn record_legacy_guards_held(
        &mut self,
        maintenance: &ConfigurationMaintenance,
        archived: &ArchivedLegacyOwnerRecovery,
        guards: Vec<RecoveryGuardPost>,
    ) -> JournalResult<LegacyGuardsHeld> {
        let originals = archived
            .prepared
            .original
            .phases
            .last()
            .ok_or(JournalError::Conflict)?
            .1
            .originals
            .clone();
        Ok(LegacyGuardsHeld {
            archived: ArchivedLegacyOwnerRecovery {
                prepared: self.append_owner_recovery(
                    maintenance,
                    &archived.prepared,
                    OwnerRecoveryStage::GuardsHeld,
                    originals,
                    guards,
                    archived.prepared.startup_post().cloned(),
                    archived.prepared.boot_observation().cloned(),
                )?,
            },
        })
    }
    /// Original chain synchronization only. It returns its observed last stage;
    /// the platform may continue only OS items proven Pending under original pins.
    pub(in crate::store) fn resync_legacy_owner_recovery(
        &self,
        maintenance: &ConfigurationMaintenance,
        id: &TransactionId,
    ) -> JournalResult<PreparedLegacyOwnerRecovery> {
        if maintenance.transaction_id() != id {
            return Err(JournalError::Conflict);
        }
        self.owner.with_maintenance(maintenance, |state| {
            self.with_directory_locked(state, |dir| {
                let scan = files::scan(dir, self.budget)?;
                let inventory = super::super::platform::inventory(&scan)?;
                if !inventory.orphans.is_empty() {
                    return Err(JournalError::Conflict);
                }
                let before = original(&scan, id)?;
                canonical(state, &before.intent)?;
                let used = scan_owner_recoveries(&scan)?.used;
                for name in &used {
                    files::sync_file(dir, name)?;
                    let expected = bytes(&scan, name)?.ok_or(JournalError::Unknown)?;
                    if files::read(dir, name, MAX_INTENT)?.as_deref() != Some(expected) {
                        return Err(JournalError::Unknown);
                    }
                }
                super::super::platform::sync_directory(dir)?;
                let after = original(&files::scan(dir, self.budget)?, id)?;
                if after.raw_intent != before.raw_intent
                    || after.last_digest() != before.last_digest()
                {
                    return Err(JournalError::Unknown);
                }
                Ok(PreparedLegacyOwnerRecovery {
                    owner: self.owner.clone(),
                    namespace: self.namespace,
                    original: after,
                })
            })
        })
    }
}

#[cfg(test)]
#[path = "management_owner_recovery_tests.rs"]
mod tests;
