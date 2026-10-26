//! Existing-only native Host profile observation. No writer, recovery, fsync,
//! remote grant, migration proof, or signed-release authority is minted here.
#![cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "windows",
    target_os = "macos"
))]
use super::{
    FileObservation, PrivateRoot, RootIdentity, management, native_state,
    secure_journal::{JournalBudget, JournalError, JournalObservation, JournalResult, files},
};
#[cfg(any(all(target_os = "linux", target_env = "gnu"), target_os = "macos"))]
use std::os::unix::fs::MetadataExt;
use std::{
    collections::BTreeSet,
    fs::File,
    io::Cursor,
    path::{Path, PathBuf},
    sync::Arc,
};
use styx_contracts::{
    identity::Sha256Digest,
    native_host::{NativeHostJoinSeed, NativeHostReady},
    native_management::{
        NativeAutostartDesired, NativeDeploymentMode, NativeManager, NativeRootIdentity,
        NativeRunDesired, NativeRuntimeSelection,
    },
};
use zeroize::Zeroizing;

const NAMESPACE: &str = ".styx-management-journal-v1";
const MAX: usize = 1024 * 1024;
const SEED: &str = "host-join-seed-v1.json";
const READY: &str = "host-ready-v1.json";
const OWNERS: &[&str] = &[
    "foreground.lock",
    "foreground-recovery.lock",
    "background.lock",
    "advance.lock",
    "capabilities.lock",
    "service.json",
    "install/.health-update-lock",
    "install/.health-operation-lock",
    "install/.health-recovery-guard",
];
const INPUTS: &[(&str, usize)] = &[
    (".styx-native-root-v1.json", 4096),
    ("deployment.json", MAX),
    ("state.json", MAX),
    (SEED, MAX),
    ("host-ca.pem", 128 * 1024),
    ("host-identity.pem", 16 * 1024),
    ("host-join-dispatched-v1.json", MAX),
    ("host-join-reply-v1.json", MAX),
    ("host-credential.token", 4096),
    ("host-confirm-dispatched-v1.json", MAX),
    (READY, MAX),
];
struct Pin {
    path: String,
    limit: usize,
    observation: FileObservation,
    digest: Sha256Digest,
}
/// Private material has no Debug/Clone/Serialize. Retains the original root and
/// namespace handles; revalidation never selects a replacement generation.
pub(crate) struct NativeHostSnapshot {
    root: PrivateRoot,
    state_dir: PathBuf,
    namespace: File,
    namespace_identity: (u64, u64),
    journal: JournalObservation,
    pins: Vec<Pin>,
    seed: NativeHostJoinSeed,
    current_selection: NativeRuntimeSelection,
    ready: NativeHostReady,
    ca: Vec<u8>,
    identity: Zeroizing<Vec<u8>>,
    credential: Zeroizing<Vec<u8>>,
    app_scope: Option<Arc<crate::app::HostScope>>,
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    service_tip: Option<super::native_live_tip::ServiceTip>,
}
impl NativeHostSnapshot {
    pub(crate) fn open(path: &Path) -> JournalResult<Self> {
        Self::open_source(
            path,
            None,
            #[cfg(all(target_os = "linux", target_env = "gnu"))]
            None,
        )
    }
    pub(crate) fn open_for_app(
        path: &Path,
        scope: Arc<crate::app::HostScope>,
    ) -> JournalResult<Self> {
        Self::open_source(
            path,
            Some(scope),
            #[cfg(all(target_os = "linux", target_env = "gnu"))]
            None,
        )
    }
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    pub(crate) fn open_for_service(
        scope: Arc<crate::platform::linux::native_service::ServiceScope>,
    ) -> JournalResult<Self> {
        let path = scope.state_dir().to_owned();
        if scope.role() != crate::platform::linux::native_service::ServiceRole::Host {
            return Err(JournalError::Conflict);
        }
        Self::open_source(&path, None, Some(scope))
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

    fn open_source(
        path: &Path,
        app_scope: Option<Arc<crate::app::HostScope>>,
        #[cfg(all(target_os = "linux", target_env = "gnu"))] service_scope: Option<
            Arc<crate::platform::linux::native_service::ServiceScope>,
        >,
    ) -> JournalResult<Self> {
        validate_app_scope(app_scope.as_deref(), path)?;
        let manager = if app_scope.is_some() {
            NativeManager::AppManaged
        } else {
            NativeManager::ForegroundCli
        };
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        let manager = if let Some(scope) = &service_scope {
            if scope.state_dir() != path || app_scope.is_some() {
                return Err(JournalError::Conflict);
            }
            scope.validate().map_err(|_| JournalError::Conflict)?;
            NativeManager::PersistentService
        } else {
            manager
        };
        if !path.is_absolute() {
            return Err(JournalError::InvalidInput);
        }
        let root = PrivateRoot::open(path).map_err(|_| JournalError::Unknown)?;
        ownership(&root)?;
        let namespace = root
            .inner
            .with_readonly_directory(|dir| Ok(files::directory(dir, NAMESPACE)))
            .map_err(|_| JournalError::Unknown)??;
        let namespace_identity = directory_identity(&namespace)?;
        let journal = files::scan(&namespace, JournalBudget::default())?;
        let mut pins = Vec::new();
        let mut identities = BTreeSet::new();
        let mut marker_raw = Vec::new();
        let mut deployment_raw = Vec::new();
        let mut state_raw = Vec::new();
        let mut seed_raw = Vec::new();
        let mut ready_raw = Vec::new();
        let mut ca = Vec::new();
        let mut identity = Zeroizing::new(Vec::new());
        let mut credential = Zeroizing::new(Vec::new());
        for &(name, limit) in INPUTS {
            let raw = pin(&root, name, limit, &mut pins, &mut identities)?;
            match name {
                ".styx-native-root-v1.json" => marker_raw = raw,
                "deployment.json" => deployment_raw = raw,
                "state.json" => state_raw = raw,
                SEED => seed_raw = raw,
                READY => ready_raw = raw,
                "host-ca.pem" => ca = raw,
                "host-identity.pem" => identity = Zeroizing::new(raw),
                "host-credential.token" => credential = Zeroizing::new(raw),
                _ => (), // Protocol-phase business validation belongs to the join client.
            }
        }
        for file in &journal.files {
            let name = format!("{NAMESPACE}/{}", file.name);
            let raw = pin(
                &root,
                &name,
                JournalBudget::default().max_file_bytes,
                &mut pins,
                &mut identities,
            )?;
            if raw != file.bytes() {
                return Err(JournalError::Unknown);
            }
        }
        let marker =
            native_state::decode_marker(&marker_raw).map_err(|_| JournalError::Conflict)?;
        if !matches_root(&root.identity(), &marker.root_identity) {
            return Err(JournalError::Conflict);
        }
        let canonical =
            native_state::decode_state(&state_raw, &marker).map_err(|_| JournalError::Conflict)?;
        let state = canonical.state();
        if state.mode != NativeDeploymentMode::JoinExisting
            || state.has_migration_binding()
            || state.desired.gateway.is_some()
            || !state.desired.host.as_ref().is_some_and(|d| {
                d.run == NativeRunDesired::Running
                    && d.manager == manager
                    && (manager == NativeManager::PersistentService
                        || d.autostart == NativeAutostartDesired::Disabled)
            })
            || state.deployment_raw_sha256 != Sha256Digest::of_bytes(&deployment_raw)
        {
            return Err(JournalError::Conflict);
        }
        let expected_seed: Sha256Digest = serde_json::from_str(
            state
                .extensions
                .get("fresh_host_seed_v1")
                .ok_or(JournalError::Conflict)?
                .get(),
        )
        .map_err(|_| JournalError::Conflict)?;
        let seed: NativeHostJoinSeed =
            serde_json::from_slice(&seed_raw).map_err(|_| JournalError::Conflict)?;
        let ready: NativeHostReady =
            serde_json::from_slice(&ready_raw).map_err(|_| JournalError::Conflict)?;
        if expected_seed != Sha256Digest::of_bytes(&seed_raw)
            || seed.schema != 1
            || ready.schema != 1
            || seed.platform != native_platform()
            || seed.root_identity != marker.root_identity
            || seed.scope_generation != marker.scope_generation
            || seed.deployment_raw_sha256 != state.deployment_raw_sha256
            || ready.seed_sha256 != expected_seed
            || ready.device_id != seed.device_id
            || ready.fingerprint != seed.fingerprint
            || ready.credential_sha256 != Sha256Digest::of_bytes(&credential)
            || !(32..=4096).contains(&credential.len())
            || !credential
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || matches!(*b, b'_' | b'-'))
            || ready.request_id.is_empty()
            || ready.generation.is_empty()
        {
            return Err(JournalError::Conflict);
        }
        let certificates = rustls_pemfile::certs(&mut Cursor::new(&ca))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| JournalError::Conflict)?;
        if certificates.len() != 1 || Sha256Digest::of_bytes(&certificates[0]) != seed.anchor_sha256
        {
            return Err(JournalError::Conflict);
        }
        management::validate_readonly_native_tip(&journal, &canonical, &marker)?;
        let current_selection = validated_runtime_selection(&root, &canonical, &marker)?;
        let bootstrap = state
            .runtime_update()
            .map_err(|_| JournalError::Conflict)?
            .map_or_else(
                || current_selection.clone(),
                |update| update.bootstrap_runtime,
            );
        if bootstrap != seed.runtime {
            return Err(JournalError::Conflict);
        }
        let candidate = crate::release::verify_selected(&current_selection)
            .map_err(|_| JournalError::Conflict)?;
        if !candidate
            .supports_state_reader(state.reader_contract)
            .map_err(|_| JournalError::Conflict)?
        {
            return Err(JournalError::Conflict);
        }
        let snapshot = Self {
            root,
            state_dir: path.to_owned(),
            namespace,
            namespace_identity,
            journal,
            pins,
            seed,
            current_selection,
            ready,
            ca,
            identity,
            credential,
            app_scope,
            #[cfg(all(target_os = "linux", target_env = "gnu"))]
            service_tip: service_scope
                .map(super::native_live_tip::ServiceTip::open)
                .transpose()?,
        };
        snapshot.revalidate()?;
        Ok(snapshot)
    }
    pub(crate) fn revalidate(&self) -> JournalResult<()> {
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        let successor = self
            .service_tip
            .as_ref()
            .map(|tip| tip.revalidate_proof())
            .transpose()
            .map_err(super::native_live_tip::LiveTipError::journal)?;
        validate_app_scope(self.app_scope.as_deref(), &self.state_dir)?;
        ownership(&self.root)?;
        self.root
            .inner
            .with_readonly_directory(|directory| {
                let result = (|| {
                    let current = files::directory(directory, NAMESPACE)?;
                    if directory_identity(&current)? != self.namespace_identity
                        || directory_identity(&self.namespace)? != self.namespace_identity
                    {
                        return Err(JournalError::Unknown);
                    }
                    self.check_pins(
                        #[cfg(all(target_os = "linux", target_env = "gnu"))]
                        successor.as_ref(),
                    )?;
                    let scan = files::scan(&self.namespace, JournalBudget::default())?;
                    #[cfg(all(target_os = "linux", target_env = "gnu"))]
                    if let Some(proof) = &successor {
                        proof.check_scan(&scan)?;
                    }
                    let matches = same_scan(&scan, &self.journal);
                    #[cfg(all(target_os = "linux", target_env = "gnu"))]
                    let matches = successor
                        .as_ref()
                        .map_or(matches, |proof| proof.matches_scan(&scan));
                    if !matches {
                        return Err(JournalError::Unknown);
                    }
                    self.check_pins(
                        #[cfg(all(target_os = "linux", target_env = "gnu"))]
                        successor.as_ref(),
                    )?;
                    let final_directory = files::directory(directory, NAMESPACE)?;
                    if directory_identity(&final_directory)? != self.namespace_identity {
                        return Err(JournalError::Unknown);
                    }
                    ownership(&self.root)?;
                    validate_app_scope(self.app_scope.as_deref(), &self.state_dir)
                })();
                Ok(result)
            })
            .map_err(|_| JournalError::Unknown)?
    }
    fn check_pins(
        &self,
        #[cfg(all(target_os = "linux", target_env = "gnu"))] successor: Option<
            &super::native_live_tip::ServiceTipProof,
        >,
    ) -> JournalResult<()> {
        for pin in &self.pins {
            #[cfg(all(target_os = "linux", target_env = "gnu"))]
            let raw = if pin.path == "state.json"
                && let Some(proof) = successor
            {
                proof.read_state(&self.root, pin.limit)?
            } else {
                self.root
                    .read_raw(&pin.path, pin.limit)
                    .map_err(|_| JournalError::Unknown)?
            };
            #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
            let raw = self
                .root
                .read_raw(&pin.path, pin.limit)
                .map_err(|_| JournalError::Unknown)?;
            let matches = raw.observation() == &pin.observation
                && Sha256Digest::of_bytes(raw.bytes()) == pin.digest;
            #[cfg(all(target_os = "linux", target_env = "gnu"))]
            let matches = if pin.path == "state.json" {
                successor.map_or(matches, |proof| proof.matches_state(&raw))
            } else {
                matches
            };
            if !matches {
                #[cfg(all(target_os = "linux", target_env = "gnu"))]
                if pin.path == "state.json"
                    && let Some(proof) = successor
                {
                    proof.check_state(&raw)?;
                }
                return Err(JournalError::Unknown);
            }
        }
        Ok(())
    }
    pub(crate) fn root_identity(&self) -> RootIdentity {
        self.root.identity()
    }
    pub(crate) fn seed(&self) -> &NativeHostJoinSeed {
        &self.seed
    }
    /// Selected only after the complete original C07 chain and bootstrap binding
    /// were verified. The caller still retains/revalidates the signed C08 object.
    pub(crate) fn current_selection(&self) -> &NativeRuntimeSelection {
        &self.current_selection
    }
    pub(crate) fn ready(&self) -> &NativeHostReady {
        &self.ready
    }
    pub(crate) fn ca_pem(&self) -> &[u8] {
        &self.ca
    }
    pub(crate) fn private_identity_pem(&self) -> &[u8] {
        &self.identity
    }
    pub(crate) fn credential(&self) -> &[u8] {
        &self.credential
    }
    pub(crate) fn state_dir(&self) -> &Path {
        &self.state_dir
    }
}
fn validate_app_scope(scope: Option<&crate::app::HostScope>, path: &Path) -> JournalResult<()> {
    if let Some(scope) = scope {
        if path != scope.state_dir() {
            return Err(JournalError::Conflict);
        }
        scope.validate().map_err(|_| JournalError::Unknown)?;
    }
    Ok(())
}

fn ownership(root: &PrivateRoot) -> JournalResult<()> {
    for name in OWNERS {
        root.ensure_absent(name)
            .map_err(|_| JournalError::Unknown)?;
    }
    Ok(())
}
fn native_platform() -> &'static str {
    if cfg!(target_os = "windows") {
        "win32"
    } else if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "linux"
    }
}
fn directory_identity(directory: &File) -> JournalResult<(u64, u64)> {
    #[cfg(target_os = "windows")]
    {
        super::windows_file_identity(directory).map_err(|_| JournalError::Unknown)
    }
    #[cfg(any(all(target_os = "linux", target_env = "gnu"), target_os = "macos"))]
    {
        let metadata = directory.metadata().map_err(|_| JournalError::Unknown)?;
        Ok((metadata.dev(), metadata.ino()))
    }
}
fn matches_root(actual: &RootIdentity, marker: &NativeRootIdentity) -> bool {
    match (actual, marker) {
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        (
            RootIdentity::Linux { device, inode, uid },
            NativeRootIdentity::Linux {
                device: expected_device,
                inode: expected_inode,
                uid: expected_uid,
            },
        ) => device == expected_device && inode == expected_inode && uid == expected_uid,
        #[cfg(target_os = "macos")]
        (
            RootIdentity::Macos { device, inode, uid },
            NativeRootIdentity::Macos {
                device: expected_device,
                inode: expected_inode,
                uid: expected_uid,
            },
        ) => device == expected_device && inode == expected_inode && uid == expected_uid,
        #[cfg(target_os = "windows")]
        (
            RootIdentity::Windows {
                volume_serial,
                file_id,
                owner_sid,
            },
            NativeRootIdentity::Windows {
                volume_serial: expected_volume,
                file_id: expected_file,
                owner_sid: expected_sid,
            },
        ) => {
            volume_serial == expected_volume
                && file_id == expected_file
                && owner_sid == expected_sid
        }
        _ => false,
    }
}

fn pin(
    root: &PrivateRoot,
    path: &str,
    limit: usize,
    pins: &mut Vec<Pin>,
    identities: &mut BTreeSet<(u64, u64)>,
) -> JournalResult<Vec<u8>> {
    let raw = root
        .read_raw(path, limit)
        .map_err(|_| JournalError::Unknown)?;
    if raw.bytes().is_empty()
        || !identities.insert((raw.observation().device, raw.observation().inode))
    {
        return Err(JournalError::Unknown);
    }
    pins.push(Pin {
        path: path.to_owned(),
        limit,
        observation: raw.observation().clone(),
        digest: Sha256Digest::of_bytes(raw.bytes()),
    });
    Ok(raw.bytes().to_vec())
}
fn same_scan(a: &JournalObservation, b: &JournalObservation) -> bool {
    a.total_bytes == b.total_bytes
        && a.files.len() == b.files.len()
        && a.files
            .iter()
            .zip(&b.files)
            .all(|(a, b)| a.name == b.name && a.bytes() == b.bytes())
}

/// Existing-only complete C07 observation on the caller's retained root. No
/// writer or namespace is created, and returned DATA is not execution authority.
/// Both canonical/marker pins and the original namespace are checked around the
/// parser, so an unproven pointer never becomes the current runtime selection.
pub(crate) fn validated_runtime_selection(
    root: &PrivateRoot,
    canonical: &native_state::ValidatedNativeState,
    marker: &styx_contracts::native_management::NativeRootMarker,
) -> JournalResult<NativeRuntimeSelection> {
    if !matches_root(&root.identity(), &marker.root_identity) {
        return Err(JournalError::Conflict);
    }
    let marker_raw = root
        .read_raw(".styx-native-root-v1.json", 4096)
        .map_err(|_| JournalError::Unknown)?;
    let actual_marker =
        native_state::decode_marker(marker_raw.bytes()).map_err(|_| JournalError::Conflict)?;
    let state_raw = root
        .read_raw("state.json", MAX)
        .map_err(|_| JournalError::Unknown)?;
    if actual_marker != *marker || state_raw.bytes() != canonical.raw_bytes() {
        return Err(JournalError::Unknown);
    }
    root.inner
        .with_readonly_directory(|directory| {
            let result = (|| {
                let namespace = files::directory(directory, NAMESPACE)?;
                let identity = directory_identity(&namespace)?;
                let scan = files::scan(&namespace, JournalBudget::default())?;
                let mut journal_pins = Vec::with_capacity(scan.files.len());
                for file in &scan.files {
                    let raw = root
                        .read_raw(
                            format!("{NAMESPACE}/{}", file.name),
                            JournalBudget::default().max_file_bytes,
                        )
                        .map_err(|_| JournalError::Unknown)?;
                    if raw.bytes() != file.bytes() {
                        return Err(JournalError::Unknown);
                    }
                    journal_pins.push(raw);
                }
                management::validate_readonly_native_tip(&scan, canonical, marker)?;
                let state = canonical.state();
                let current = state
                    .runtime_selection()
                    .map_err(|_| JournalError::Conflict)?
                    .ok_or(JournalError::Conflict)?;
                if let Some(update) = state.runtime_update().map_err(|_| JournalError::Conflict)?
                    && (current.publisher_spki_sha256
                        != update.bootstrap_runtime.publisher_spki_sha256
                        || (state.desired.host.iter().chain(state.desired.gateway.iter()).any(|d| d.manager == NativeManager::AppManaged)
                            != (state.reader_contract == styx_contracts::management::ReaderContract::NativeAppRuntimeSelectedStateV1)))
                {
                    return Err(JournalError::Conflict);
                }
                let after = files::scan(&namespace, JournalBudget::default())?;
                let current_namespace = files::directory(directory, NAMESPACE)?;
                if !same_scan(&scan, &after)
                    || directory_identity(&namespace)? != identity
                    || directory_identity(&current_namespace)? != identity
                {
                    return Err(JournalError::Unknown);
                }
                for before in &journal_pins {
                    let after = root
                        .read_raw(
                            before.relative_path(),
                            JournalBudget::default().max_file_bytes,
                        )
                        .map_err(|_| JournalError::Unknown)?;
                    if after.bytes() != before.bytes()
                        || after.observation() != before.observation()
                    {
                        return Err(JournalError::Unknown);
                    }
                }
                for (name, before) in [
                    ("state.json", &state_raw),
                    (".styx-native-root-v1.json", &marker_raw),
                ] {
                    let after = root
                        .read_raw(name, MAX)
                        .map_err(|_| JournalError::Unknown)?;
                    if after.bytes() != before.bytes()
                        || after.observation() != before.observation()
                    {
                        return Err(JournalError::Unknown);
                    }
                }
                Ok(current)
            })();
            Ok(result)
        })
        .map_err(|_| JournalError::Unknown)?
}
