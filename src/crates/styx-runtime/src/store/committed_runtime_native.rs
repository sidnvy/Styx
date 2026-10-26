//! Formal V2 ordinary-process observation after original same-journal COMMIT.
//! No writer, maintenance release, remote grant or old owner proof is minted by
//! opening this snapshot. It verifies actual canonical and original materials.
use super::{
    FileObservation, PrivateRoot, RootIdentity,
    management::{self, cutover, handoff},
    secure_journal::{JournalBudget, JournalError, JournalResult, files},
};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use styx_contracts::{identity::Sha256Digest, management::ReaderContract, native_management::*};
use styx_core::management::transaction::DurableStage;
use zeroize::Zeroizing;
const NAMESPACE: &str = ".styx-management-journal-v1";
const MAX: usize = 1024 * 1024;
const HOST_ABSENT: &[&str] = &[
    "install/.health-update-lock",
    "install/.health-operation-lock",
    "install/.health-recovery-guard",
];
const STATE_ABSENT: &[&str] = &[
    "foreground-recovery.lock",
    "gateway-runtime-recovery.lock",
    "host-payload-migration-recovery.lock",
    "host-update-recovery.lock",
    "account-acceptance.lock",
    "onboarding-plugin.lock",
    "tunnel/owner.lock",
    "host-payload-migration.json",
];
struct MaterialPin {
    root: Arc<PrivateRoot>,
    path: PathBuf,
    observation: FileObservation,
    digest: Sha256Digest,
    max: usize,
}
impl MaterialPin {
    fn revalidate(&self) -> JournalResult<()> {
        let raw = self
            .root
            .read_raw(&self.path, self.max)
            .map_err(|_| JournalError::Unknown)?;
        if raw.observation() != &self.observation
            || Sha256Digest::of_bytes(raw.bytes()) != self.digest
        {
            return Err(JournalError::Unknown);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum RequiredStage {
    Committed,
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    Validated(DurableStage),
}
impl RequiredStage {
    fn stage(self) -> DurableStage {
        match self {
            Self::Committed => DurableStage::Committed,
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            Self::Validated(stage) => stage,
        }
    }
}

/// Read-only incomplete-migration observation. No writer, grant, credential
/// accessor, ordinary profile conversion or constructor from report JSON.
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(in crate::store) struct NativeValidatedMigrationSnapshot {
    inner: NativeCommittedRuntimeSnapshot,
}
#[cfg(any(target_os = "macos", target_os = "windows"))]
impl NativeValidatedMigrationSnapshot {
    pub(in crate::store) fn open(path: &Path, stage: DurableStage) -> JournalResult<Self> {
        if !matches!(stage, DurableStage::Applied | DurableStage::Verified) {
            return Err(JournalError::Conflict);
        }
        Ok(Self {
            inner: NativeCommittedRuntimeSnapshot::open_inner(
                path,
                RequiredStage::Validated(stage),
            )?,
        })
    }
    /// Full original inventory AND stage: advancing a phase invalidates it.
    pub(in crate::store) fn revalidate(&self) -> JournalResult<()> {
        self.inner.revalidate()
    }
    /// After the original writer advances its phase, recheck only physical
    /// materials. Caller MUST separately validate the new journal/phase chain.
    /// This is never ordinary admission or proof of the new phase.
    pub(in crate::store) fn revalidate_materials(&self) -> JournalResult<()> {
        self.inner.revalidate_pending_materials()
    }
    pub(in crate::store) fn original(&self) -> &cutover::OriginalCutover<NativeRootIdentity> {
        &self.inner.original
    }
    pub(in crate::store) fn candidate(&self) -> &Arc<crate::release::VerifiedNativeRelease> {
        &self.inner.candidate
    }
    pub(in crate::store) fn root_identity(&self) -> RootIdentity {
        self.inner.root.identity()
    }
    pub(in crate::store) fn host_root_identity(&self) -> RootIdentity {
        self.inner.host.identity()
    }
    pub(in crate::store) fn host_base_dir(&self) -> &Path {
        &self.inner.host_base_dir
    }
}

/// No Debug/Serde; exact inventory and original credential facts are private.
pub(crate) struct NativeCommittedRuntimeSnapshot {
    required_stage: RequiredStage,
    root: Arc<PrivateRoot>,
    state_dir: PathBuf,
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    host_base_dir: PathBuf,
    host: Arc<PrivateRoot>,
    namespace: PrivateRoot,
    pins: Vec<MaterialPin>,
    inventory: Vec<(String, Sha256Digest)>,
    original: cutover::OriginalCutover<NativeRootIdentity>,
    retirement: handoff::NativeOriginalRetirement,
    state: NativeState,
    selection: NativeRuntimeSelection,
    candidate: Arc<crate::release::VerifiedNativeRelease>,
    guard_materials: Vec<(String, Vec<u8>)>,
    // The original App instance remains alive for every provider using this
    // snapshot. A marker or manager string cannot construct this scope.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    service_tip: Option<super::native_live_tip::ServiceTip>,
    app_scope: Option<Arc<crate::app::HostScope>>,
}
fn actual_root(id: RootIdentity) -> JournalResult<NativeRootIdentity> {
    match id {
        RootIdentity::Linux { device, inode, uid } => {
            Ok(NativeRootIdentity::Linux { device, inode, uid })
        }
        #[cfg(target_os = "macos")]
        RootIdentity::Macos { device, inode, uid } => {
            Ok(NativeRootIdentity::Macos { device, inode, uid })
        }
        #[cfg(target_os = "windows")]
        RootIdentity::Windows {
            volume_serial,
            file_id,
            owner_sid,
        } => Ok(NativeRootIdentity::Windows {
            volume_serial,
            file_id,
            owner_sid,
        }),
    }
}
fn pin(
    root: &Arc<PrivateRoot>,
    name: impl AsRef<Path>,
    max: usize,
    pins: &mut Vec<MaterialPin>,
) -> JournalResult<Vec<u8>> {
    let raw = root
        .read_raw(name.as_ref(), max)
        .map_err(|_| JournalError::Unknown)?;
    pins.push(MaterialPin {
        root: root.clone(),
        path: name.as_ref().to_path_buf(),
        observation: raw.observation().clone(),
        digest: Sha256Digest::of_bytes(raw.bytes()),
        max,
    });
    Ok(raw.bytes().to_vec())
}
fn absolute(path: &Path) -> bool {
    path.is_absolute()
        && path.components().all(|c| {
            !matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
}
fn hash_matches(raw: &[u8], expected: Sha256Digest) -> JournalResult<()> {
    if Sha256Digest::of_bytes(raw) == expected {
        Ok(())
    } else {
        Err(JournalError::Conflict)
    }
}
fn stamp_matches(
    stamp: &handoff::NativeRetirementFileStamp,
    root: &NativeRootIdentity,
    observation: &FileObservation,
    bytes: &[u8],
) -> bool {
    let (
        device,
        inode,
        len,
        modified_seconds,
        modified_nanoseconds,
        changed_seconds,
        changed_nanoseconds,
    ) = match stamp {
        handoff::NativeRetirementFileStamp::Linux { stamp }
        | handoff::NativeRetirementFileStamp::Macos { stamp } => (
            stamp.device,
            stamp.inode,
            stamp.byte_len,
            stamp.modified_seconds,
            stamp.modified_nanoseconds,
            stamp.changed_seconds,
            stamp.changed_nanoseconds,
        ),
        handoff::NativeRetirementFileStamp::Windows {
            volume_serial,
            file_id,
            byte_len,
            modified_seconds,
            modified_nanoseconds,
            changed_seconds,
            changed_nanoseconds,
            ..
        } => (
            *volume_serial,
            *file_id,
            *byte_len,
            *modified_seconds,
            *modified_nanoseconds,
            *changed_seconds,
            *changed_nanoseconds,
        ),
    };
    use handoff::ProofStamp;
    stamp.valid_for(root)
        && observation.device == device
        && observation.inode == inode
        && observation.byte_len == len
        && observation.modified_seconds == modified_seconds
        && observation.modified_nanoseconds == modified_nanoseconds
        && observation.changed_seconds == changed_seconds
        && observation.changed_nanoseconds == changed_nanoseconds
        && Sha256Digest::of_bytes(bytes) == stamp.content_sha256()
}
/// Signed-reader feature gate AFTER the original journal/report decoder. A
/// readable StateV2 alone does not declare support for newer journal evidence.
/// This observation grants no admission and never replaces full report checks.
pub(in crate::store) fn validate_selected_reader_features(
    reader: styx_contracts::native_release::NativeReleaseReader,
    has_migration_plan: bool,
    paired_report: &[u8],
) -> JournalResult<()> {
    #[derive(serde::Deserialize)]
    struct Header {
        schema: u16,
    }
    let header: Header =
        serde_json::from_slice(paired_report).map_err(|_| JournalError::Conflict)?;
    let admission_v2 = header.schema == 2;
    if !reader.supports_state_reader(ReaderContract::NativeMigratedStateV2)
        || ((has_migration_plan || admission_v2) && !reader.supports_host_admission_v2())
    {
        return Err(JournalError::Unsupported);
    }
    Ok(())
}

impl NativeCommittedRuntimeSnapshot {
    pub(crate) fn open_for_app(
        path: &Path,
        scope: Arc<crate::app::HostScope>,
    ) -> JournalResult<Self> {
        let snapshot = Self::open_app(path, scope)?;
        if !snapshot
            .state
            .desired
            .host
            .as_ref()
            .is_some_and(|host| host.run == NativeRunDesired::Running)
        {
            return Err(JournalError::Conflict);
        }
        Ok(snapshot)
    }
    /// Gateway may remain available while the same App's Host is paused.
    /// This never relaxes the Host runtime reader's Running requirement.
    pub(crate) fn open_for_app_gateway(
        path: &Path,
        scope: Arc<crate::app::HostScope>,
    ) -> JournalResult<Self> {
        let snapshot = Self::open_app(path, scope)?;
        if !snapshot
            .state
            .desired
            .gateway
            .as_ref()
            .is_some_and(|gateway| gateway.run == NativeRunDesired::Running)
        {
            return Err(JournalError::Conflict);
        }
        Ok(snapshot)
    }
    fn open_app(path: &Path, scope: Arc<crate::app::HostScope>) -> JournalResult<Self> {
        if scope.state_dir() != path {
            return Err(JournalError::Conflict);
        }
        scope.validate().map_err(|_| JournalError::Unknown)?;
        let mut snapshot = Self::open(path)?;
        if snapshot.state.desired.host.is_none()
            || snapshot
                .state
                .desired
                .host
                .iter()
                .chain(snapshot.state.desired.gateway.iter())
                .any(|role| {
                    role.manager != NativeManager::AppManaged
                        || role.autostart != NativeAutostartDesired::Disabled
                })
        {
            return Err(JournalError::Conflict);
        }
        snapshot.app_scope = Some(scope);
        snapshot.revalidate()?;
        Ok(snapshot)
    }
    pub(crate) fn open(path: &Path) -> JournalResult<Self> {
        Self::open_inner(path, RequiredStage::Committed)
    }
    fn open_inner(path: &Path, required_stage: RequiredStage) -> JournalResult<Self> {
        if !absolute(path) {
            return Err(JournalError::InvalidInput);
        }
        let root = Arc::new(PrivateRoot::open(path).map_err(|_| JournalError::Unknown)?);
        let namespace =
            PrivateRoot::open(path.join(NAMESPACE)).map_err(|_| JournalError::Unknown)?;
        let scan = namespace
            .inner
            .with_readonly_directory(|d| Ok(files::scan(d, JournalBudget::default())))
            .map_err(|_| JournalError::Unknown)??;
        let inventory = management::readonly_inventory(&scan)?;
        if !inventory.orphans.is_empty()
            || inventory.transactions.iter().any(|t| {
                t.phase_receipts
                    .last()
                    .is_none_or(|p| p.stage != DurableStage::Committed)
            })
        {
            return Err(JournalError::Conflict);
        }
        let parsed = cutover::scan_cutovers(&scan)?;
        if !parsed.records.is_empty() || parsed.native_records.len() != 1 {
            return Err(JournalError::Conflict);
        }
        let original = cutover::original_for::<NativeRootIdentity>(
            &scan,
            &parsed.native_records[0].intent.transaction_id,
        )?;
        if original.intent.schema != 4
            || original.last_stage != required_stage.stage()
            || original.validation_report().is_none()
            || original.paired_validation_report().is_none()
        {
            return Err(JournalError::Conflict);
        }
        let marker = super::native_state::decode_marker(&original.marker)
            .map_err(|_| JournalError::Conflict)?;
        let canonical_raw = root
            .read_raw("state.json", MAX)
            .map_err(|_| JournalError::Unknown)?;
        let canonical = super::native_state::decode_state(canonical_raw.bytes(), &marker)
            .map_err(|_| JournalError::Conflict)?;
        match required_stage {
            RequiredStage::Committed => {
                management::validate_readonly_native_tip(&scan, &canonical, &marker)?
            }
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            RequiredStage::Validated(_) => {
                validate_pending_chain(&scan, &original)?;
                cutover::check_canonical_root(&root, &original, true)?;
                if canonical_raw.bytes() != original.target {
                    return Err(JournalError::Conflict);
                }
            }
        }
        let state = canonical.state().clone();
        let binding = state
            .migration_v2()
            .map_err(|_| JournalError::Conflict)?
            .ok_or(JournalError::Conflict)?;
        if marker.root_identity != actual_root(root.identity())?
            || state.reader_contract != ReaderContract::NativeMigratedStateV2
            || state.desired.host.is_none()
        {
            return Err(JournalError::Conflict);
        }
        let selection: NativeRuntimeSelection = serde_json::from_str(
            state
                .extensions
                .get("runtime_selection_v1")
                .ok_or(JournalError::Conflict)?
                .get(),
        )
        .map_err(|_| JournalError::Conflict)?;
        if selection.manifest_sha256 != binding.candidate_manifest_sha256
            || selection.publisher_spki_sha256 != binding.publisher_spki_sha256
        {
            return Err(JournalError::Conflict);
        }
        let candidate = Arc::new(
            crate::release::verify_selected(&selection).map_err(|_| JournalError::Unknown)?,
        );
        validate_selected_reader_features(
            candidate.manifest().minimum_reader,
            !inventory.migration_plans.is_empty(),
            original
                .paired_validation_report()
                .ok_or(JournalError::Conflict)?,
        )?;
        let mut pins = Vec::new();
        for file in &scan.files {
            pin(&root, format!("{NAMESPACE}/{}", file.name), MAX, &mut pins)?;
        }
        let deployment = pin(&root, "deployment.json", MAX, &mut pins)?;
        hash_matches(&deployment, original.intent.deployment_raw_sha256)?;
        if pin(&root, "state.json", MAX, &mut pins)? != canonical_raw.bytes()
            || pin(&root, ".styx-native-root-v1.json", 4096, &mut pins)? != original.marker
        {
            return Err(JournalError::Conflict);
        }
        let d: serde_json::Value =
            serde_json::from_slice(&deployment).map_err(|_| JournalError::Conflict)?;
        let base = PathBuf::from(
            d.pointer("/host/baseDir")
                .and_then(|v| v.as_str())
                .ok_or(JournalError::Conflict)?,
        );
        if !absolute(&base) {
            return Err(JournalError::Conflict);
        }
        let host = Arc::new(PrivateRoot::open(&base).map_err(|_| JournalError::Unknown)?);
        if actual_root(host.identity())? != original.intent.host_root {
            return Err(JournalError::Conflict);
        }
        let publisher = d
            .pointer("/host/publisherSha256")
            .and_then(|v| v.as_str())
            .ok_or(JournalError::Conflict)?;
        if publisher != selection.publisher_spki_sha256.to_hex() {
            return Err(JournalError::Conflict);
        }
        let mut retired = handoff::scan_handoffs(&scan)?.native_records;
        if retired.len() != 1 {
            return Err(JournalError::Conflict);
        }
        let retirement = retired.remove(0).original();
        hash_matches(
            &pin(&host, "service.json", 32768, &mut pins)?,
            retirement.intent.service_descriptor_sha256,
        )?;
        let mut guard_materials = Vec::new();
        let recoveries = handoff::scan_owner_recoveries(&scan)?;
        if recoveries.records.len() > 1 {
            return Err(JournalError::Conflict);
        }
        if let Some(recovery) = recoveries.records.first() {
            if recovery.stage() != Some(handoff::OwnerRecoveryStage::GuardsHeld) {
                return Err(JournalError::Conflict);
            }
            if recovery.intent.transaction_id != original.intent.transaction_id
                || recovery.intent.sequence != original.intent.sequence
            {
                return Err(JournalError::Conflict);
            }
            let posts = recovery.guards_held_posts().ok_or(JournalError::Conflict)?;
            for guard in &recovery.guards {
                let name = guard.name.source_name();
                let raw = root
                    .read_raw(name, 4096)
                    .map_err(|_| JournalError::Unknown)?;
                let post = posts
                    .iter()
                    .find(|p| p.name == guard.name)
                    .ok_or(JournalError::Conflict)?;
                if raw.bytes() != guard.raw
                    || !stamp_matches(
                        &post.stamp,
                        &actual_root(root.identity())?,
                        raw.observation(),
                        raw.bytes(),
                    )
                {
                    return Err(JournalError::Conflict);
                }
                let actual = pin(&root, name, 4096, &mut pins)?;
                if actual != raw.bytes() {
                    return Err(JournalError::Conflict);
                }
                guard_materials.push((name.into(), actual));
            }
        }
        let owner_bindings = state
            .extensions
            .get("legacy_owner_bindings_v2")
            .ok_or(JournalError::Conflict)?;
        super::native_legacy_owners::validate_native_legacy_owners(
            owner_bindings,
            &root,
            &host,
            path,
            retirement.intent.service_descriptor_sha256,
        )?;
        for name in STATE_ABSENT {
            root.ensure_absent(name)
                .map_err(|_| JournalError::Conflict)?;
        }
        for name in HOST_ABSENT {
            host.ensure_absent(name)
                .map_err(|_| JournalError::Conflict)?;
        }
        root.ensure_absent("foreground-recovery.lock")
            .map_err(|_| JournalError::Conflict)?;
        match &binding.history {
            NativeMigrationHistory::PreservedHostPair {
                source_bindings_sha256,
            } => {
                if *source_bindings_sha256 != binding.host_pair_sha256 {
                    return Err(JournalError::Conflict);
                }
            }
            NativeMigrationHistory::ImportedLocalGateway {
                baseline_sha256,
                committed_sha256,
            } => {
                let baseline_raw = pin(
                    &root,
                    ".styx-enrollment-journal-v1/historical-baseline.intent",
                    MAX,
                    &mut pins,
                )?;
                hash_matches(&baseline_raw, *baseline_sha256)?;
                let baseline = styx_contracts::historical_enrollment::decode(&baseline_raw)
                    .map_err(|_| JournalError::Conflict)?;
                if !matches!(baseline.schema, 2 | 3)
                    || baseline.migration != original.intent.transaction_id
                    || baseline
                        .journal_root()
                        .map_err(|_| JournalError::Conflict)?
                        != &actual_root(root.identity())?.into()
                {
                    return Err(JournalError::Conflict);
                }
                hash_matches(
                    &pin(
                        &root,
                        ".styx-enrollment-journal-v1/historical-baseline.committed",
                        MAX,
                        &mut pins,
                    )?,
                    *committed_sha256,
                )?;
            }
        }
        let raw = original
            .host_pair
            .as_deref()
            .ok_or(JournalError::Conflict)?;
        hash_matches(raw, binding.host_pair_sha256)?;
        let pair: NativePreservedHostPair =
            serde_json::from_slice(raw).map_err(|_| JournalError::Conflict)?;
        hash_matches(
            &pin(&host, "device/identity.json", MAX, &mut pins)?,
            pair.identity_json_sha256,
        )?;
        // The owned buffer is erased after hashing, never logged.
        let private = Zeroizing::new(pin(&host, "device/identity.pem", 16384, &mut pins)?);
        hash_matches(&private, pair.identity_private_pem_sha256)?;
        let profile = pin(&host, "device/host.json", MAX, &mut pins)?;
        hash_matches(&profile, pair.host_profile_sha256)?;
        let h: serde_json::Value =
            serde_json::from_slice(&profile).map_err(|_| JournalError::Conflict)?;
        if h.get("host_id").and_then(|v| v.as_str()) != Some(pair.device_id.as_str())
            || h.get("token_file").and_then(|v| v.as_str())
                != base.join("device/host.token").to_str()
        {
            return Err(JournalError::Conflict);
        }
        let ca = PathBuf::from(
            h.get("gateway_ca_file")
                .and_then(|v| v.as_str())
                .ok_or(JournalError::Conflict)?,
        );
        if !absolute(&ca) {
            return Err(JournalError::Conflict);
        }
        let ca_root = Arc::new(
            PrivateRoot::open(ca.parent().ok_or(JournalError::Conflict)?)
                .map_err(|_| JournalError::Unknown)?,
        );
        hash_matches(
            &pin(
                &ca_root,
                ca.file_name().ok_or(JournalError::Conflict)?,
                128 * 1024,
                &mut pins,
            )?,
            pair.gateway_ca_pem_sha256,
        )?;
        let identity: serde_json::Value = serde_json::from_slice(
            host.read_raw("device/identity.json", MAX)
                .map_err(|_| JournalError::Unknown)?
                .bytes(),
        )
        .map_err(|_| JournalError::Conflict)?;
        if identity.get("device_id").and_then(|v| v.as_str()) != Some(pair.device_id.as_str())
            || identity.get("fingerprint").and_then(|v| v.as_str())
                != Some(pair.fingerprint.to_hex().as_str())
        {
            return Err(JournalError::Conflict);
        }

        let token_name = retirement.intent.token_destination();
        let token = Zeroizing::new(pin(&host, &token_name, 4096, &mut pins)?);
        let post = retirement
            .post_stamp
            .as_ref()
            .ok_or(JournalError::Conflict)?;
        let token_observation = host
            .read_raw(&token_name, 4096)
            .map_err(|_| JournalError::Unknown)?;
        if !stamp_matches(
            post,
            &actual_root(host.identity())?,
            token_observation.observation(),
            &token,
        ) {
            return Err(JournalError::Conflict);
        }
        hash_matches(&token, pair.credential_sha256)?;
        host.ensure_absent("device/host.token")
            .map_err(|_| JournalError::Conflict)?;
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        if matches!(required_stage, RequiredStage::Validated(_)) {
            // Reopen the FULL original immutable preservation set, including
            // publisher and legacy active selector. Only the two effects this
            // transaction explicitly performed may differ at their old paths.
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Row {
                path: PathBuf,
                sha256: Sha256Digest,
                bytes: u64,
                observation: serde_json::Value,
            }
            let canonical_path = path.join("state.json");
            let token_path = base.join("device/host.token");
            let mut allowed = std::collections::BTreeSet::from([
                canonical_path.clone(),
                path.join("deployment.json"),
                token_path.clone(),
                base.join("publisher.pem"),
                base.join("device/identity.json"),
                base.join("device/identity.pem"),
                base.join("device/host.json"),
                base.join("install/active.json"),
                ca.clone(),
            ]);
            if let Some(original_ca) = d.pointer("/gateway/caFile").and_then(|v| v.as_str()) {
                allowed.insert(PathBuf::from(original_ca));
            }
            let rows: Vec<Row> = serde_json::from_slice(&original.preservation)
                .map_err(|_| JournalError::Conflict)?;
            let active_path = base.join("install/active.json");
            let active_row = rows
                .iter()
                .find(|row| row.path == active_path)
                .ok_or(JournalError::Conflict)?;
            let active_raw = pin(&host, "install/active.json", MAX, &mut pins)?;
            if Sha256Digest::of_bytes(&active_raw) != active_row.sha256
                || active_raw.len() as u64 != active_row.bytes
                || serde_json::to_value(&pins.last().ok_or(JournalError::Conflict)?.observation)
                    .map_err(|_| JournalError::Conflict)?
                    != active_row.observation
            {
                return Err(JournalError::Unknown);
            }
            allowed.extend(
                crate::foreground::profile::original_release_metadata_paths(&base, &active_raw)
                    .map_err(|_| JournalError::Conflict)?,
            );
            if rows.len() != allowed.len() {
                return Err(JournalError::Conflict);
            }
            let mut seen = std::collections::BTreeSet::new();
            for row in rows {
                if !absolute(&row.path)
                    || !allowed.contains(&row.path)
                    || !seen.insert(row.path.clone())
                    || row.bytes == 0
                    || row.bytes > MAX as u64
                {
                    return Err(JournalError::Conflict);
                }
                if row.path == canonical_path {
                    if row.sha256 != original.intent.before_state_sha256
                        || row.bytes != original.before.len() as u64
                    {
                        return Err(JournalError::Conflict);
                    }
                    continue;
                }
                if row.path == token_path {
                    if row.sha256 != pair.credential_sha256 || row.bytes != token.len() as u64 {
                        return Err(JournalError::Conflict);
                    }
                    continue;
                }
                let material_root = Arc::new(
                    PrivateRoot::open(row.path.parent().ok_or(JournalError::Conflict)?)
                        .map_err(|_| JournalError::Unknown)?,
                );
                let name = row.path.file_name().ok_or(JournalError::Conflict)?;
                let current = material_root
                    .read_raw(name, MAX)
                    .map_err(|_| JournalError::Unknown)?;
                if current.bytes().len() as u64 != row.bytes
                    || Sha256Digest::of_bytes(current.bytes()) != row.sha256
                    || serde_json::to_value(current.observation())
                        .map_err(|_| JournalError::Conflict)?
                        != row.observation
                {
                    return Err(JournalError::Unknown);
                }
                let observed = Zeroizing::new(pin(&material_root, name, MAX, &mut pins)?);
                if observed.as_slice() != current.bytes()
                    || pins
                        .last()
                        .is_none_or(|p| &p.observation != current.observation())
                {
                    return Err(JournalError::Unknown);
                }
            }
            if seen != allowed {
                return Err(JournalError::Conflict);
            }
            pin_original_nonce(&host, &original, &pair, &mut pins)?;
        }
        let snapshot = Self {
            required_stage,
            root,
            state_dir: path.to_owned(),
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            host_base_dir: base,
            host,
            namespace,
            pins,
            inventory: scan
                .files
                .iter()
                .map(|f| (f.name.clone(), Sha256Digest::of_bytes(f.bytes())))
                .collect(),
            original,
            retirement,
            state,
            selection,
            candidate,
            guard_materials,
            app_scope: None,
            #[cfg(all(target_os = "linux", target_env = "gnu"))]
            service_tip: None,
        };
        snapshot.revalidate()?;
        Ok(snapshot)
    }
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    pub(crate) fn open_for_service(
        scope: Arc<crate::platform::linux::native_service::ServiceScope>,
    ) -> JournalResult<Self> {
        let mut snapshot = Self::open(scope.state_dir())?;
        snapshot.service_tip = Some(super::native_live_tip::ServiceTip::open(scope)?);
        snapshot.revalidate()?;
        Ok(snapshot)
    }
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    pub(crate) fn service_tip_status(&self) -> Result<(), super::native_live_tip::LiveTipError> {
        self.service_tip
            .as_ref()
            .map_or(Ok(()), |tip| tip.revalidate())
    }
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    pub(crate) fn service_canonical_matches(
        &self,
        root: &PrivateRoot,
        raw: &super::RawFile,
    ) -> Result<Option<bool>, super::native_live_tip::LiveTipError> {
        if root.identity() != self.root.identity() {
            return Err(super::native_live_tip::LiveTipError::Changed);
        }
        self.service_tip
            .as_ref()
            .map(|tip| {
                tip.revalidate_proof()
                    .and_then(|proof| proof.matches_observed_state(raw))
            })
            .transpose()
    }

    pub(crate) fn revalidate(&self) -> JournalResult<()> {
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        let successor = self
            .service_tip
            .as_ref()
            .map(|tip| tip.revalidate_proof())
            .transpose()
            .map_err(super::native_live_tip::LiveTipError::journal)?;
        if let Some(scope) = &self.app_scope {
            if scope.state_dir() != self.state_dir {
                return Err(JournalError::Conflict);
            }
            scope.validate().map_err(|_| JournalError::Unknown)?;
        }
        self.candidate
            .revalidate()
            .map_err(|_| JournalError::Unknown)?;
        super::native_legacy_owners::validate_native_legacy_owners(
            self.state
                .extensions
                .get("legacy_owner_bindings_v2")
                .ok_or(JournalError::Conflict)?,
            &self.root,
            &self.host,
            &self.state_dir,
            self.retirement.intent.service_descriptor_sha256,
        )?;
        let current =
            PrivateRoot::open(self.state_dir.join(NAMESPACE)).map_err(|_| JournalError::Unknown)?;
        if current.identity() != self.namespace.identity() {
            return Err(JournalError::Unknown);
        }
        let scan = self
            .namespace
            .inner
            .with_readonly_directory(|d| Ok(files::scan(d, JournalBudget::default())))
            .map_err(|_| JournalError::Unknown)??;
        let expected_scan = scan.files.len() == self.inventory.len()
            && scan
                .files
                .iter()
                .zip(&self.inventory)
                .all(|(f, (name, sha))| {
                    f.name == *name && Sha256Digest::of_bytes(f.bytes()) == *sha
                });
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        let expected_scan = successor
            .as_ref()
            .map_or(expected_scan, |proof| proof.matches_scan(&scan));
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        if let Some(proof) = &successor {
            proof.check_scan(&scan)?;
        }
        if !expected_scan {
            return Err(JournalError::Unknown);
        }
        let parsed = cutover::original_for::<NativeRootIdentity>(
            &scan,
            &self.original.intent.transaction_id,
        )?;
        if parsed.raw_intent != self.original.raw_intent
            || parsed.phases != self.original.phases
            || parsed.last_stage != self.required_stage.stage()
        {
            return Err(JournalError::Unknown);
        }
        for pin in &self.pins {
            #[cfg(all(target_os = "linux", target_env = "gnu"))]
            if let Some(proof) = &successor
                && pin.root.identity() == self.root.identity()
                && pin.path == Path::new("state.json")
            {
                let raw = proof.read_state(&pin.root, pin.max)?;
                proof.check_state(&raw)?;
                continue; // Exact current proof replaces the old canonical expectation.
            }
            pin.revalidate()?;
        }
        self.root
            .ensure_absent("foreground-recovery.lock")
            .map_err(|_| JournalError::Unknown)?;
        self.host
            .ensure_absent("device/host.token")
            .map_err(|_| JournalError::Unknown)?;
        let marker = super::native_state::decode_marker(&self.original.marker)
            .map_err(|_| JournalError::Conflict)?;
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        let raw = if let Some(proof) = &successor {
            proof.read_state(&self.root, MAX)?
        } else {
            self.root
                .read_raw("state.json", MAX)
                .map_err(|_| JournalError::Unknown)?
        };
        #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
        let raw = self
            .root
            .read_raw("state.json", MAX)
            .map_err(|_| JournalError::Unknown)?;
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        if let Some(proof) = &successor {
            proof.check_state(&raw)?;
        }
        let canonical = super::native_state::decode_state(raw.bytes(), &marker)
            .map_err(|_| JournalError::Conflict)?;
        match self.required_stage {
            RequiredStage::Committed => {
                management::validate_readonly_native_tip(&scan, &canonical, &marker)?
            }
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            RequiredStage::Validated(_) => {
                validate_pending_chain(&scan, &parsed)?;
                cutover::check_canonical_root(&self.root, &parsed, true)?;
                if raw.bytes() != self.original.target {
                    return Err(JournalError::Unknown);
                }
            }
        }
        for name in STATE_ABSENT {
            self.root
                .ensure_absent(name)
                .map_err(|_| JournalError::Unknown)?;
        }
        for name in HOST_ABSENT {
            self.host
                .ensure_absent(name)
                .map_err(|_| JournalError::Unknown)?;
        }
        let after = self
            .namespace
            .inner
            .with_readonly_directory(|d| Ok(files::scan(d, JournalBudget::default())))
            .map_err(|_| JournalError::Unknown)??;
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        if let Some(proof) = &successor {
            proof.check_scan(&after)?;
        }
        if after.files.len() != scan.files.len()
            || after
                .files
                .iter()
                .zip(&scan.files)
                .any(|(a, b)| a.name != b.name || a.bytes() != b.bytes())
        {
            return Err(JournalError::Unknown);
        }
        // Bracket the full inventory and canonical read with original material
        // checks. Equal bytes at a replacement inode are still a changed input.
        for pin in &self.pins {
            #[cfg(all(target_os = "linux", target_env = "gnu"))]
            if let Some(proof) = &successor
                && pin.root.identity() == self.root.identity()
                && pin.path == Path::new("state.json")
            {
                let raw = proof.read_state(&pin.root, pin.max)?;
                proof.check_state(&raw)?;
                continue; // Exact current proof replaces the old canonical expectation.
            }
            pin.revalidate()?;
        }
        if PrivateRoot::open(self.state_dir.join(NAMESPACE))
            .map_err(|_| JournalError::Unknown)?
            .identity()
            != self.namespace.identity()
        {
            return Err(JournalError::Unknown);
        }
        Ok(())
    }
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    fn revalidate_pending_materials(&self) -> JournalResult<()> {
        if !matches!(self.required_stage, RequiredStage::Validated(_)) {
            return Err(JournalError::Conflict);
        }
        self.candidate
            .revalidate()
            .map_err(|_| JournalError::Unknown)?;
        if PrivateRoot::open(&self.state_dir)
            .map_err(|_| JournalError::Unknown)?
            .identity()
            != self.root.identity()
            || PrivateRoot::open(&self.host_base_dir)
                .map_err(|_| JournalError::Unknown)?
                .identity()
                != self.host.identity()
            || PrivateRoot::open(self.state_dir.join(NAMESPACE))
                .map_err(|_| JournalError::Unknown)?
                .identity()
                != self.namespace.identity()
        {
            return Err(JournalError::Unknown);
        }
        super::native_legacy_owners::validate_native_legacy_owners(
            self.state
                .extensions
                .get("legacy_owner_bindings_v2")
                .ok_or(JournalError::Conflict)?,
            &self.root,
            &self.host,
            &self.state_dir,
            self.retirement.intent.service_descriptor_sha256,
        )?;
        for material in &self.pins {
            if !(Arc::ptr_eq(&material.root, &self.root) && material.path.starts_with(NAMESPACE)) {
                material.revalidate()?;
            }
        }
        let raw = self
            .root
            .read_raw("state.json", MAX)
            .map_err(|_| JournalError::Unknown)?;
        let marker = self
            .root
            .read_raw(".styx-native-root-v1.json", 4096)
            .map_err(|_| JournalError::Unknown)?;
        if raw.bytes() != self.original.target || marker.bytes() != self.original.marker {
            return Err(JournalError::Unknown);
        }
        for name in STATE_ABSENT {
            self.root
                .ensure_absent(name)
                .map_err(|_| JournalError::Unknown)?;
        }
        for name in HOST_ABSENT {
            self.host
                .ensure_absent(name)
                .map_err(|_| JournalError::Unknown)?;
        }
        self.host
            .ensure_absent("device/host.token")
            .map_err(|_| JournalError::Unknown)?;
        self.candidate
            .revalidate()
            .map_err(|_| JournalError::Unknown)
    }
    pub(crate) fn state(&self) -> &NativeState {
        &self.state
    }
    pub(crate) fn selection(&self) -> &NativeRuntimeSelection {
        &self.selection
    }
    pub(crate) fn before(&self) -> &[u8] {
        &self.original.before
    }
    pub(crate) fn endpoint_binding(&self) -> Option<&[u8]> {
        self.original.endpoint_binding()
    }
    pub(crate) fn endpoint_chain(&self) -> Option<&[u8]> {
        self.original.endpoint_chain()
    }
    pub(crate) fn endpoint_key(&self) -> Option<&[u8]> {
        self.original.endpoint_key()
    }
    pub(crate) fn root_identity(&self) -> RootIdentity {
        self.root.identity()
    }
    pub(crate) fn read_retired_token(
        &self,
        host: &PrivateRoot,
    ) -> JournalResult<Zeroizing<Vec<u8>>> {
        self.revalidate()?;
        if host.identity() != self.host.identity() {
            return Err(JournalError::Conflict);
        }
        let raw = host
            .read_raw(self.retirement.intent.token_destination(), 4096)
            .map_err(|_| JournalError::Unknown)?;
        let post = self
            .retirement
            .post_stamp
            .as_ref()
            .ok_or(JournalError::Conflict)?;
        if !stamp_matches(
            post,
            &actual_root(host.identity())?,
            raw.observation(),
            raw.bytes(),
        ) {
            return Err(JournalError::Unknown);
        }
        self.revalidate()?;
        Ok(Zeroizing::new(raw.bytes().to_vec()))
    }
    pub(crate) fn validate_legacy_owners(
        &self,
        state: &PrivateRoot,
        host: &PrivateRoot,
    ) -> JournalResult<()> {
        if state.identity() != self.root.identity() || host.identity() != self.host.identity() {
            return Err(JournalError::Conflict);
        }
        self.revalidate()?;
        for (name, expected) in &self.guard_materials {
            if state
                .read_raw(name, 4096)
                .map_err(|_| JournalError::Unknown)?
                .bytes()
                != expected
            {
                return Err(JournalError::Unknown);
            }
        }
        for name in HOST_ABSENT {
            host.ensure_absent(name)
                .map_err(|_| JournalError::Unknown)?;
        }
        Ok(())
    }
}

/// The already strict original cutover parser verified BOTH successful reports.
/// This adds complete pre-effect plan + exact tip constraints, not new authority.
#[cfg(any(target_os = "macos", target_os = "windows"))]
fn validate_pending_chain(
    scan: &super::secure_journal::JournalObservation,
    original: &cutover::OriginalCutover<NativeRootIdentity>,
) -> JournalResult<()> {
    if !matches!(
        original.last_stage,
        DurableStage::Applied | DurableStage::Verified
    ) || original.validation_report().is_none()
        || original.paired_validation_report().is_none()
    {
        return Err(JournalError::Conflict);
    }
    let inventory = management::readonly_inventory(scan)?;
    if !inventory.orphans.is_empty()
        || inventory.high_water != original.intent.sequence
        || inventory.transactions.iter().any(|tx| {
            tx.intent.sequence >= original.intent.sequence
                || tx.prepared.is_none()
                || tx
                    .phase_receipts
                    .last()
                    .is_none_or(|p| p.stage != DurableStage::Committed)
        })
    {
        return Err(JournalError::Conflict);
    }
    let plans = management::migration_plan::scan_plans(scan)?;
    if plans.records.len() != 1 {
        return Err(JournalError::Conflict);
    }
    plans.records[0].validate_cutover(original)
}

/// Pin the CURRENT protected nonce after matching the original durable effect
/// hash/length/path. This is not a recovered historical inode or JoinHandle.
#[cfg(any(target_os = "macos", target_os = "windows"))]
fn pin_original_nonce(
    host: &Arc<PrivateRoot>,
    original: &cutover::OriginalCutover<NativeRootIdentity>,
    pair: &NativePreservedHostPair,
    pins: &mut Vec<MaterialPin>,
) -> JournalResult<()> {
    #[derive(serde::Deserialize)]
    struct Effect {
        transaction_id: styx_contracts::identity::TransactionId,
        candidate_manifest_sha256: Sha256Digest,
        device_id: styx_contracts::identity::DeviceId,
        nonce_relative_path: PathBuf,
        nonce_sha256: Sha256Digest,
        nonce_bytes: usize,
    }
    // The full report was validated by original_for; this is its additional
    // physical effect projection, never an alternative relaxed report parser.
    let effect: Effect =
        serde_json::from_slice(original.validation_report().ok_or(JournalError::Conflict)?)
            .map_err(|_| JournalError::Conflict)?;
    let fixed = PathBuf::from(format!(
        ".styx-migration-probe-{}",
        original.intent.transaction_id.as_str()
    ));
    if effect.transaction_id != original.intent.transaction_id
        || effect.candidate_manifest_sha256 != original.intent.candidate_manifest_sha256
        || effect.device_id != pair.device_id
        || effect.nonce_relative_path != fixed
        || effect.nonce_bytes == 0
        || effect.nonce_bytes > 256
    {
        return Err(JournalError::Conflict);
    }
    let raw = pin(host, &fixed, 256, pins)?;
    if raw.len() != effect.nonce_bytes {
        return Err(JournalError::Conflict);
    }
    hash_matches(&raw, effect.nonce_sha256)
}

#[path = "committed_runtime_native_owner.rs"]
mod owner;
pub(crate) use owner::RecoveredNativeCommittedRuntime;
