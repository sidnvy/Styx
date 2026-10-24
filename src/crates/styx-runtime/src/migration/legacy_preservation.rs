//! Original-input preservation observations under the caller's retained migration
//! proof. No authority, copying, login validation or filesystem mutation occurs.
use super::{CredentialRetirementObservation, TransitionError};
use crate::{
    enrollment::legacy_import::LegacyImportSummary,
    foreground::profile::LoadedMaintenanceProfile,
    store::{FileObservation, PayloadInventory, PayloadLimits, PrivateRoot, RootIdentity},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io,
    path::{Component, Path, PathBuf},
    sync::Arc,
};
use styx_contracts::identity::Sha256Digest;

const FILE_BYTES: usize = 1024 * 1024;
const RECORD_BYTES: usize = 1024 * 1024;
const MAX_INPUTS: usize = 256;

#[derive(Serialize)]
pub struct PreservationReport {
    pub schema: u16,
    pub immutable_files: usize,
    pub canonical_files: usize,
    pub browser_trees: usize,
    pub source_token_files: usize,
    pub linux_uid: u32,
    pub linux_gid: u32,
    pub login_state: &'static str,
    pub os_permission_scope: &'static str,
}
#[derive(Clone, PartialEq, Eq, Serialize)]
struct Security {
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
}
#[derive(Serialize)]
struct Entry {
    path: PathBuf,
    root_identity: RootIdentity,
    observation: FileObservation,
    sha256: Sha256Digest,
    security: Security,
    canonical: bool,
    #[serde(skip)]
    root: Arc<PrivateRoot>,
    #[serde(skip)]
    relative: PathBuf,
}
#[derive(Serialize)]
struct TreeMember {
    path: PathBuf,
    bytes: u64,
    sha256: Sha256Digest,
    executable: bool,
    observation: FileObservation,
    security: Security,
}
#[derive(Serialize)]
struct Tree {
    path: PathBuf,
    root_identity: RootIdentity,
    members: Vec<TreeMember>,
    browser: bool,
    #[serde(skip)]
    inventory: PayloadInventory,
}
struct AbsentTree {
    parent: Arc<PrivateRoot>,
    relative: PathBuf,
    path: PathBuf,
}
/// Private journal payload only. No Debug/Serialize implementation exposes the
/// retained observations through ordinary diagnostics or network responses.
pub struct OriginalPreservation {
    entries: Vec<Entry>,
    trees: Vec<Tree>,
    absent: Vec<AbsentTree>,
    source_bindings: Sha256Digest,
    retirement_receipt: Sha256Digest,
    original_host: Arc<PrivateRoot>,
    transaction: styx_contracts::identity::TransactionId,
    uid: u32,
    gid: u32,
}
#[derive(Deserialize)]
struct Runtime {
    schema: u32,
    #[serde(rename = "tlsCertificateFile")]
    certificate: PathBuf,
    #[serde(rename = "tlsPrivateKeyFile")]
    key: PathBuf,
    #[serde(rename = "modelTokenFile")]
    model: PathBuf,
    #[serde(rename = "adminTokenFile")]
    admin: PathBuf,
    #[serde(rename = "enrollmentDir")]
    enrollment: PathBuf,
    #[serde(rename = "catalogFile")]
    catalog: PathBuf,
}
#[derive(Deserialize)]
struct Host {
    browser: Option<Browser>,
}
#[derive(Deserialize)]
struct Browser {
    profile_root: Option<PathBuf>,
}
fn valid_path(path: &Path) -> bool {
    path.is_absolute()
        && path.as_os_str().len() <= 4096
        && !path
            .components()
            .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
}
#[cfg(target_os = "linux")]
fn security(path: &Path, observation: &FileObservation) -> Result<Security, TransitionError> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::symlink_metadata(path).map_err(|_| TransitionError::Unknown)?;
    if !m.is_file()
        || m.dev() != observation.device
        || m.ino() != observation.inode
        || m.len() != observation.byte_len
        || m.mtime() != observation.modified_seconds
        || m.mtime_nsec() != observation.modified_nanoseconds
        || m.ctime() != observation.changed_seconds
        || m.ctime_nsec() != observation.changed_nanoseconds
        || m.uid() != nix::unistd::geteuid().as_raw()
        || m.nlink() != 1
        || m.mode() & 0o077 != 0
    {
        return Err(TransitionError::Unknown);
    }
    Ok(Security {
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode(),
        links: m.nlink(),
    })
}
#[cfg(not(target_os = "linux"))]
fn security(_: &Path, _: &FileObservation) -> Result<Security, TransitionError> {
    Err(TransitionError::Unsupported)
}
fn observe(path: &Path, canonical: bool) -> Result<Entry, TransitionError> {
    if !valid_path(path) {
        return Err(TransitionError::Unsupported);
    }
    let parent = path.parent().ok_or(TransitionError::Conflict)?;
    let relative = PathBuf::from(path.file_name().ok_or(TransitionError::Conflict)?);
    let root = Arc::new(PrivateRoot::open(parent).map_err(|_| TransitionError::Unavailable)?);
    let first = root
        .read_raw(&relative, FILE_BYTES)
        .map_err(|_| TransitionError::Unavailable)?;
    let first_security = security(path, first.observation())?;
    let second = root
        .read_raw(&relative, FILE_BYTES)
        .map_err(|_| TransitionError::Unknown)?;
    if first.bytes() != second.bytes()
        || first.observation() != second.observation()
        || security(path, second.observation())? != first_security
    {
        return Err(TransitionError::Unknown);
    }
    Ok(Entry {
        path: path.to_owned(),
        root_identity: root.identity(),
        observation: first.observation().clone(),
        sha256: Sha256Digest::of_bytes(first.bytes()),
        security: first_security,
        canonical,
        root,
        relative,
    })
}
fn add(
    entries: &mut BTreeMap<PathBuf, Entry>,
    path: &Path,
    canonical: &Path,
) -> Result<(), TransitionError> {
    if entries.contains_key(path) {
        return Ok(());
    }
    if entries.len() >= MAX_INPUTS {
        return Err(TransitionError::Busy);
    }
    entries.insert(path.to_owned(), observe(path, path == canonical)?);
    Ok(())
}
fn tree(path: &Path, browser: bool) -> Result<Tree, TransitionError> {
    if !valid_path(path) {
        return Err(TransitionError::Unsupported);
    }
    let root = PrivateRoot::open(path).map_err(|_| TransitionError::Unsupported)?;
    let limits = if browser {
        PayloadLimits::default()
    } else {
        PayloadLimits {
            max_files: 1024,
            max_directories: 1,
            max_depth: 1,
            max_file_bytes: 4096,
            max_total_bytes: 4 * 1024 * 1024,
        }
    };
    let inventory = root
        .payload_inventory(limits)
        .map_err(|_| TransitionError::Unsupported)?;
    if inventory.members().iter().any(|m| {
        if browser {
            m.path.file_name().is_some_and(|n| {
                matches!(
                    n.to_str(),
                    Some("SingletonLock" | "SingletonSocket" | "SingletonCookie" | "lockfile")
                )
            })
        } else {
            m.path.components().count() != 1 || m.path.extension().is_none_or(|e| e != "token")
        }
    }) {
        return Err(TransitionError::Conflict);
    }
    let mut members = Vec::with_capacity(inventory.members().len());
    for member in inventory.members() {
        use std::os::unix::fs::MetadataExt;
        let absolute = path.join(&member.path);
        let metadata =
            std::fs::symlink_metadata(&absolute).map_err(|_| TransitionError::Unknown)?;
        let observation = FileObservation {
            device: metadata.dev(),
            inode: metadata.ino(),
            byte_len: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        };
        if observation.byte_len != member.bytes {
            return Err(TransitionError::Unknown);
        }
        let security = security(&absolute, &observation)?;
        members.push(TreeMember {
            path: member.path.clone(),
            bytes: member.bytes,
            sha256: member.sha256,
            executable: member.executable,
            observation,
            security,
        });
    }
    // The descriptor-backed snapshot brackets pathname-only metadata projection.
    inventory
        .revalidate()
        .map_err(|_| TransitionError::Unknown)?;
    Ok(Tree {
        path: path.to_owned(),
        root_identity: root.identity(),
        members,
        browser,
        inventory,
    })
}

pub(crate) fn capture(
    state_dir: &Path,
    profile: &LoadedMaintenanceProfile,
    source_summary: &LegacyImportSummary,
    retired: &CredentialRetirementObservation,
) -> Result<OriginalPreservation, TransitionError> {
    if !cfg!(all(target_os = "linux", target_env = "gnu")) {
        return Err(TransitionError::Unsupported);
    }
    if !valid_path(state_dir)
        || !retired.original_inode_preserved
        || !retired.original_bytes_preserved
        || !retired.original_locator_absent
    {
        return Err(TransitionError::Conflict);
    }
    profile.revalidate().map_err(|_| TransitionError::Unknown)?;
    let host = profile.host_base_dir();
    let canonical = state_dir.join("state.json");
    let mut entries = BTreeMap::new();
    for input in profile.preservation_entries() {
        add(&mut entries, &input.path, &canonical)?;
        let actual = entries.get(&input.path).ok_or(TransitionError::Unknown)?;
        if actual.sha256 != input.sha256 || actual.observation.byte_len != input.bytes {
            return Err(TransitionError::Unknown);
        }
    }
    let state = Arc::new(PrivateRoot::open(state_dir).map_err(|_| TransitionError::Unavailable)?);
    for name in [
        "deployment.json",
        "state.json",
        "gateway/runtime.json",
        "gateway/owner.json",
        "gateway/targets.json",
        "gateway/enrollment/state.json",
    ] {
        add(&mut entries, &state_dir.join(name), &canonical)?;
    }
    let runtime: Runtime = serde_json::from_slice(
        state
            .read_raw("gateway/runtime.json", FILE_BYTES)
            .map_err(|_| TransitionError::Unavailable)?
            .bytes(),
    )
    .map_err(|_| TransitionError::Conflict)?;
    let gateway = state_dir.join("gateway");
    if runtime.schema != 1
        || runtime.certificate != gateway.join("certificate.pem")
        || runtime.key != gateway.join("private-key.pem")
        || runtime.model != gateway.join("model.token")
        || runtime.admin != gateway.join("admin.token")
        || runtime.enrollment != gateway.join("enrollment")
        || runtime.catalog != gateway.join("targets.json")
    {
        return Err(TransitionError::Unsupported);
    }
    for path in [
        &runtime.certificate,
        &runtime.key,
        &runtime.model,
        &runtime.admin,
    ] {
        add(&mut entries, path, &canonical)?;
    }
    let relative = PathBuf::from(format!(
        "device/.styx-retired-host-token-{}",
        retired.transaction_id.as_str()
    ));
    if retired.retired_relative_path != relative {
        return Err(TransitionError::Conflict);
    }
    let host_root = Arc::new(PrivateRoot::open(host).map_err(|_| TransitionError::Unavailable)?);
    host_root
        .ensure_absent("device/host.token")
        .map_err(|_| TransitionError::Conflict)?;
    add(&mut entries, &host.join(relative), &canonical)?;
    let host_json: Host = serde_json::from_slice(
        host_root
            .read_raw("device/host.json", FILE_BYTES)
            .map_err(|_| TransitionError::Unavailable)?
            .bytes(),
    )
    .map_err(|_| TransitionError::Conflict)?;
    let token_tree = tree(&runtime.enrollment.join("tokens"), false)?;
    if token_tree.members.len() != source_summary.credential_files {
        return Err(TransitionError::Unknown);
    }
    let mut trees = vec![token_tree];
    let mut absent = Vec::new();
    let mut browser_paths = vec![host.join("browser")];
    if let Some(path) = host_json.browser.and_then(|b| b.profile_root)
        && !browser_paths.contains(&path)
    {
        browser_paths.push(path);
    }
    for path in browser_paths {
        if !valid_path(&path) {
            return Err(TransitionError::Unsupported);
        }
        let parent_path = path.parent().ok_or(TransitionError::Unsupported)?;
        let parent =
            Arc::new(PrivateRoot::open(parent_path).map_err(|_| TransitionError::Unsupported)?);
        let relative = PathBuf::from(path.file_name().ok_or(TransitionError::Unsupported)?);
        if parent.ensure_absent(&relative).is_ok() {
            absent.push(AbsentTree {
                parent,
                relative,
                path,
            });
        } else {
            trees.push(tree(&path, true)?);
        }
    }
    let result = OriginalPreservation {
        entries: entries.into_values().collect(),
        trees,
        absent,
        source_bindings: source_summary.source_bindings_sha256,
        retirement_receipt: retired.retired_receipt_sha256,
        original_host: host_root,
        transaction: retired.transaction_id.clone(),
        uid: nix::unistd::geteuid().as_raw(),
        gid: nix::unistd::getegid().as_raw(),
    };
    result.revalidate()?;
    profile.revalidate().map_err(|_| TransitionError::Unknown)?;
    Ok(result)
}
impl OriginalPreservation {
    pub fn report(&self) -> PreservationReport {
        PreservationReport {
            schema: 1,
            immutable_files: self.entries.iter().filter(|e| !e.canonical).count(),
            canonical_files: self.entries.iter().filter(|e| e.canonical).count(),
            browser_trees: self.trees.iter().filter(|t| t.browser).count(),
            source_token_files: self
                .trees
                .iter()
                .filter(|t| !t.browser)
                .map(|t| t.members.len())
                .sum(),
            linux_uid: self.uid,
            linux_gid: self.gid,
            login_state: "preserved_input_not_login_validation",
            os_permission_scope: "linux_uid_gid_private_files_only_not_macos_tcc_or_windows_acl",
        }
    }
    pub(crate) fn revalidate(&self) -> Result<(), TransitionError> {
        self.validate_entries(false)
    }
    /// Only an exact prepared cutover effect may invoke this internal variant.
    /// It exempts the captured canonical state file and no other source input.
    pub(crate) fn revalidate_except_canonical(&self) -> Result<(), TransitionError> {
        self.validate_entries(true)
    }
    fn validate_entries(&self, except_canonical: bool) -> Result<(), TransitionError> {
        for entry in &self.entries {
            if except_canonical && entry.canonical {
                continue;
            }
            if entry.root.identity() != entry.root_identity {
                return Err(TransitionError::Unknown);
            }
            let raw = entry
                .root
                .read_raw(&entry.relative, FILE_BYTES)
                .map_err(|_| TransitionError::Unknown)?;
            if raw.observation() != &entry.observation
                || Sha256Digest::of_bytes(raw.bytes()) != entry.sha256
                || security(&entry.path, raw.observation())? != entry.security
            {
                return Err(TransitionError::Unknown);
            }
        }
        self.original_host
            .ensure_absent("device/host.token")
            .map_err(|_| TransitionError::Unknown)?;
        for tree in &self.trees {
            tree.inventory
                .revalidate()
                .map_err(|_| TransitionError::Unknown)?;
            for member in &tree.members {
                if security(&tree.path.join(&member.path), &member.observation)? != member.security
                {
                    return Err(TransitionError::Unknown);
                }
            }
            tree.inventory
                .revalidate()
                .map_err(|_| TransitionError::Unknown)?;
        }
        for absent in &self.absent {
            absent
                .parent
                .ensure_absent(&absent.relative)
                .map_err(|_| TransitionError::Unknown)?;
        }
        Ok(())
    }
    pub(crate) fn private_bytes(&self) -> Result<Vec<u8>, TransitionError> {
        self.revalidate()?;
        #[derive(Serialize)]
        struct Record<'a> {
            schema: u16,
            transaction: &'a styx_contracts::identity::TransactionId,
            source_bindings_sha256: Sha256Digest,
            retired_receipt_sha256: Sha256Digest,
            entries: &'a [Entry],
            trees: &'a [Tree],
            absent_browser_paths: Vec<&'a Path>,
            report: PreservationReport,
        }
        struct Bounded(Vec<u8>);
        impl io::Write for Bounded {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if bytes.len() > RECORD_BYTES.saturating_sub(self.0.len()) {
                    return Err(io::Error::other("preservation_record_limit"));
                }
                self.0.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut writer = Bounded(Vec::new());
        serde_json::to_writer(
            &mut writer,
            &Record {
                schema: 1,
                transaction: &self.transaction,
                source_bindings_sha256: self.source_bindings,
                retired_receipt_sha256: self.retirement_receipt,
                entries: &self.entries,
                trees: &self.trees,
                absent_browser_paths: self.absent.iter().map(|a| a.path.as_path()).collect(),
                report: self.report(),
            },
        )
        .map_err(|_| TransitionError::Busy)?;
        Ok(writer.0)
    }
}
