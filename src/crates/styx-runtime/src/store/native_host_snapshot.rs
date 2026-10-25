//! Existing-only native Host profile observation. No writer, recovery, fsync,
//! remote grant, migration proof, or signed-release authority is minted here.
#![cfg(any(all(target_os = "linux", target_env = "gnu"), target_os = "windows"))]
use super::{
    FileObservation, PrivateRoot, RootIdentity, management, native_state,
    secure_journal::{JournalBudget, JournalError, JournalObservation, JournalResult, files},
};
#[cfg(all(target_os = "linux", target_env = "gnu"))]
use std::os::unix::fs::MetadataExt;
use std::{
    collections::BTreeSet,
    fs::File,
    io::Cursor,
    path::{Path, PathBuf},
};
use styx_contracts::{
    identity::Sha256Digest,
    native_host::{NativeHostJoinSeed, NativeHostReady},
    native_management::{
        NativeAutostartDesired, NativeDeploymentMode, NativeManager, NativeRootIdentity,
        NativeRunDesired,
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
    ready: NativeHostReady,
    ca: Vec<u8>,
    identity: Zeroizing<Vec<u8>>,
    credential: Zeroizing<Vec<u8>>,
}
impl NativeHostSnapshot {
    pub(crate) fn open(path: &Path) -> JournalResult<Self> {
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
            || state.migration.is_some()
            || state.desired.gateway.is_some()
            || !state.desired.host.as_ref().is_some_and(|d| {
                d.run == NativeRunDesired::Running
                    && d.manager == NativeManager::ForegroundCli
                    && d.autostart == NativeAutostartDesired::Disabled
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
        let snapshot = Self {
            root,
            state_dir: path.to_owned(),
            namespace,
            namespace_identity,
            journal,
            pins,
            seed,
            ready,
            ca,
            identity,
            credential,
        };
        snapshot.revalidate()?;
        Ok(snapshot)
    }
    pub(crate) fn revalidate(&self) -> JournalResult<()> {
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
                    self.check_pins()?;
                    let scan = files::scan(&self.namespace, JournalBudget::default())?;
                    if !same_scan(&scan, &self.journal) {
                        return Err(JournalError::Unknown);
                    }
                    self.check_pins()?;
                    let final_directory = files::directory(directory, NAMESPACE)?;
                    if directory_identity(&final_directory)? != self.namespace_identity {
                        return Err(JournalError::Unknown);
                    }
                    ownership(&self.root)?;
                    Ok(())
                })();
                Ok(result)
            })
            .map_err(|_| JournalError::Unknown)?
    }
    fn check_pins(&self) -> JournalResult<()> {
        for pin in &self.pins {
            let raw = self
                .root
                .read_raw(&pin.path, pin.limit)
                .map_err(|_| JournalError::Unknown)?;
            if raw.observation() != &pin.observation
                || Sha256Digest::of_bytes(raw.bytes()) != pin.digest
            {
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
    } else {
        "linux"
    }
}
fn directory_identity(directory: &File) -> JournalResult<(u64, u64)> {
    #[cfg(target_os = "windows")]
    {
        super::windows_file_identity(directory).map_err(|_| JournalError::Unknown)
    }
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
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
