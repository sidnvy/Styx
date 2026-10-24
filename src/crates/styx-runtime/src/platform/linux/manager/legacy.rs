//! Exact installed legacy scope capture and once-only graceful settlement.
//! No StopUnit, activation, retirement or management handoff authority.
//! Same-UID malicious manager/filesystem writers remain outside the cooperative
//! boundary. Every capture retains the original maintenance/fence on failure.
use super::*;
use crate::store::legacy_handoff::{LegacyServiceDescriptor, LegacyWriterFence};
use futures_util::FutureExt as _;
use nix::{
    fcntl::{OFlag, open as open_fd, openat},
    sys::stat::Mode,
    unistd::{Uid, User},
};
use rustix::process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::{Read, Seek, SeekFrom},
    os::fd::{AsFd, OwnedFd},
};
use std::{panic::AssertUnwindSafe, sync::Mutex};
use tokio::sync::{OwnedSemaphorePermit, watch};

const MANIFEST_CAP: usize = 1024 * 1024;
const UNIT_CAP: usize = 32 * 1024;
const IMAGE_CAP: u64 = 1024 * 1024 * 1024;
type LegacyResult<T> = std::result::Result<T, LegacyError>;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LegacyError {
    Invalid,
    Busy,
    Conflict,
    Unavailable,
    Unsupported,
    Unknown,
}
fn conflict<T>(_: T) -> LegacyError {
    LegacyError::Conflict
}
fn unavailable<T>(_: T) -> LegacyError {
    LegacyError::Unavailable
}
fn unknown<T>(_: T) -> LegacyError {
    LegacyError::Unknown
}

// No Deserialize/Clone/Debug on authority-bearing objects. DTOs below grant none.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ServiceLayout {
    unit_name: String,
    install_root: PathBuf,
    host_config_file: PathBuf,
    trust_public_key_file: PathBuf,
    node_binary: PathBuf,
    #[serde(default = "three")]
    restart_sec: u8,
}
fn three() -> u8 {
    3
}
#[derive(Deserialize)]
struct SignedManifest {
    schema: u32,
    version: String,
    platform: String,
    arch: String,
    files: Vec<Member>,
}
#[derive(Deserialize)]
struct Member {
    path: String,
    sha256: Sha256Digest,
    size: u64,
    executable: bool,
}
struct Frozen {
    relative: PathBuf,
    hash: Sha256Digest,
    length: usize,
}

#[path = "legacy_gateway.rs"]
mod gateway;

pub(crate) struct VerifiedLegacyServiceInputs {
    protected_descriptor: Arc<LegacyServiceDescriptor>,
    profile: Arc<Profile>,
    base: PrivateRoot,
    descriptor: ServiceLayout,
    frozen: Vec<Frozen>,
    node_sha: Sha256Digest,
    unit_file: PathBuf,
    unit_bytes: Vec<u8>,
    unit_fd: File,
    unit_stat: Stat,
}
impl VerifiedLegacyServiceInputs {
    /// Existing profile loader verifies original publisher pin, active raw
    /// manifest signature and the complete retained release inventory. We only
    /// accept the exact schema-1 manifest hash it already authenticated.
    async fn load(state_dir: &Path) -> LegacyResult<Self> {
        let profile = open(state_dir).await.map_err(unavailable)?;
        legacy_blocking(move || Self::derive(profile)).await
    }
    fn derive(profile: Arc<Profile>) -> LegacyResult<Self> {
        profile._loaded.revalidate().map_err(conflict)?;
        let base_path = profile._loaded.host_base_dir();
        let base = PrivateRoot::open(base_path).map_err(unavailable)?;
        let raw = base
            .read_raw("service.json", UNIT_CAP)
            .map_err(unavailable)?;
        let protected_descriptor =
            Arc::new(LegacyServiceDescriptor::capture(&base).map_err(conflict)?);
        if protected_descriptor.host_root_identity() != base.identity()
            || protected_descriptor.raw_sha256() != Sha256Digest::of_bytes(raw.bytes())
            || protected_descriptor.raw_bytes() != raw.bytes()
        {
            return Err(LegacyError::Conflict);
        }
        let descriptor: ServiceLayout = serde_json::from_slice(raw.bytes()).map_err(conflict)?;
        if !unit_name(&descriptor.unit_name)
            || !(1..=30).contains(&descriptor.restart_sec)
            || descriptor.install_root != base_path.join("install")
            || descriptor.host_config_file != base_path.join("device/host.json")
            || descriptor.trust_public_key_file != base_path.join("publisher.pem")
            || descriptor.node_binary != base_path.join("install/node")
        {
            return Err(LegacyError::Unsupported);
        }
        for p in [
            &descriptor.install_root,
            &descriptor.host_config_file,
            &descriptor.trust_public_key_file,
            &descriptor.node_binary,
        ] {
            safe_unit_path(p)?;
        }
        let version = &profile._loaded.diagnostics().version;
        if version.is_empty()
            || version.len() > 128
            || !version
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b".-_".contains(&c))
        {
            return Err(LegacyError::Conflict);
        }
        let manifest_rel = PathBuf::from(format!("install/releases/{version}/manifest.json"));
        let manifest_raw = base
            .read_raw(&manifest_rel, MANIFEST_CAP)
            .map_err(unavailable)?;
        if Sha256Digest::of_bytes(manifest_raw.bytes())
            != profile._loaded.diagnostics().manifest_sha256
        {
            return Err(LegacyError::Conflict);
        }
        let manifest: SignedManifest =
            serde_json::from_slice(manifest_raw.bytes()).map_err(conflict)?;
        if manifest.schema != 1
            || manifest.version != *version
            || manifest.platform != "linux"
            || manifest.arch
                != if cfg!(target_arch = "x86_64") {
                    "x64"
                } else if cfg!(target_arch = "aarch64") {
                    "arm64"
                } else {
                    return Err(LegacyError::Unsupported);
                }
            || manifest.files.len() > 4096
        {
            return Err(LegacyError::Unsupported);
        }
        let mut names = BTreeSet::new();
        if manifest.files.iter().any(|m| !names.insert(&m.path)) {
            return Err(LegacyError::Conflict);
        }
        let mut frozen = vec![
            freeze("service.json", raw.bytes()),
            freeze(manifest_rel, manifest_raw.bytes()),
        ];
        let mut node_sha = None;
        for (signed, stable, executable) in [
            ("bin/node", "install/node", true),
            ("host/launch.mjs", "install/launch.mjs", false),
            ("host/installer.mjs", "install/installer.mjs", false),
            (
                "host/private-storage.mjs",
                "install/private-storage.mjs",
                false,
            ),
        ] {
            let member = manifest
                .files
                .iter()
                .find(|m| m.path == signed)
                .ok_or(LegacyError::Unsupported)?;
            if member.size == 0 || member.size > IMAGE_CAP || member.executable != executable {
                return Err(LegacyError::Conflict);
            }
            let bytes = base
                .read_raw(stable, member.size as usize)
                .map_err(unavailable)?;
            if bytes.bytes().len() as u64 != member.size
                || Sha256Digest::of_bytes(bytes.bytes()) != member.sha256
            {
                return Err(LegacyError::Conflict);
            }
            frozen.push(freeze(stable, bytes.bytes()));
            if executable {
                node_sha = Some(member.sha256);
            }
        }
        let user = User::from_uid(Uid::current())
            .map_err(unavailable)?
            .ok_or(LegacyError::Unavailable)?;
        let unit_file = user
            .dir
            .join(".config/systemd/user")
            .join(&descriptor.unit_name);
        let mut unit_fd = open_checked(&unit_file, false)?;
        let unit_stat = stat(&unit_fd)?;
        let unit_bytes = read_file(&mut unit_fd, UNIT_CAP as u64)?;
        let expected = generated_unit(&descriptor, "exec");
        if unit_bytes != expected.as_bytes()
            && unit_bytes != generated_unit(&descriptor, "simple").as_bytes()
        {
            return Err(LegacyError::Conflict);
        }
        let value = Self {
            protected_descriptor,
            profile,
            base,
            descriptor,
            frozen,
            node_sha: node_sha.ok_or(LegacyError::Unsupported)?,
            unit_file,
            unit_bytes,
            unit_fd,
            unit_stat,
        };
        value.revalidate()?;
        Ok(value)
    }
    pub(crate) fn service_descriptor(&self) -> Arc<LegacyServiceDescriptor> {
        self.protected_descriptor.clone()
    }
    pub(crate) fn host_root_identity(&self) -> RootIdentity {
        self.base.identity()
    }
    pub(crate) fn open_host_root(&self) -> LegacyResult<PrivateRoot> {
        self.revalidate()?;
        let root = PrivateRoot::open(self.profile._loaded.host_base_dir()).map_err(unavailable)?;
        if root.identity() != self.base.identity() {
            return Err(LegacyError::Conflict);
        }
        Ok(root)
    }
    pub(crate) fn publisher_sha256(&self) -> &str {
        &self.profile._loaded.diagnostics().publisher_sha256
    }
    fn revalidate(&self) -> LegacyResult<()> {
        self.profile._loaded.revalidate().map_err(conflict)?;
        let descriptor = LegacyServiceDescriptor::capture(&self.base).map_err(conflict)?;
        if descriptor.host_root_identity() != self.protected_descriptor.host_root_identity()
            || descriptor.raw_bytes() != self.protected_descriptor.raw_bytes()
            || descriptor.raw_sha256() != self.protected_descriptor.raw_sha256()
        {
            return Err(LegacyError::Conflict);
        }
        for f in &self.frozen {
            let raw = self
                .base
                .read_raw(&f.relative, f.length)
                .map_err(conflict)?;
            if raw.bytes().len() != f.length || Sha256Digest::of_bytes(raw.bytes()) != f.hash {
                return Err(LegacyError::Conflict);
            }
        }
        if stat(&self.unit_fd)? != self.unit_stat {
            return Err(LegacyError::Conflict);
        }
        let mut now = open_checked(&self.unit_file, false)?;
        if stat(&now)? != self.unit_stat || read_file(&mut now, UNIT_CAP as u64)? != self.unit_bytes
        {
            return Err(LegacyError::Conflict);
        }
        Ok(())
    }
}
fn freeze(relative: impl Into<PathBuf>, bytes: &[u8]) -> Frozen {
    Frozen {
        relative: relative.into(),
        hash: Sha256Digest::of_bytes(bytes),
        length: bytes.len(),
    }
}
fn unit_name(s: &str) -> bool {
    let Some(s) = s
        .strip_prefix("styx-")
        .and_then(|v| v.strip_suffix(".service"))
    else {
        return false;
    };
    let s = s.strip_prefix("vnext-").unwrap_or(s);
    !s.is_empty()
        && s.len() <= 49
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}
fn safe_unit_path(p: &Path) -> LegacyResult<()> {
    let s = p.to_str().ok_or(LegacyError::Invalid)?;
    if !p.is_absolute()
        || s.len() > 4096
        || !s
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"/._+@-".contains(&c))
        || p.components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
    {
        return Err(LegacyError::Unsupported);
    }
    Ok(())
}
fn generated_unit(d: &ServiceLayout, kind: &str) -> String {
    // Exact original linuxUserUnit bytes, including final newline. No INI parser.
    format!(
        "# Managed by Styx VNext Linux user installer. ID: styx-linux-user-v1\n[Unit]\nDescription=Styx VNext isolated Host connector ({})\nDocumentation=https://github.com/sidnvy/Styx\nStartLimitIntervalSec=45\nStartLimitBurst=6\n\n[Service]\nType={}\nExecStart={} {}/launch.mjs {} {} {}\nWorkingDirectory={}\nRestart=on-failure\nRestartSec={}\nTimeoutStopSec=12\nKillMode=control-group\nUMask=0077\nNoNewPrivileges=true\nStandardOutput=journal\nStandardError=journal\n\n[Install]\nWantedBy=default.target\n",
        d.unit_name,
        kind,
        d.node_binary.display(),
        d.install_root.display(),
        d.install_root.display(),
        d.host_config_file.display(),
        d.trust_public_key_file.display(),
        d.install_root.display(),
        d.restart_sec
    )
}

#[derive(PartialEq, Eq)]
struct Stat {
    dev: u64,
    ino: u64,
    uid: u32,
    mode: u32,
    nlink: u64,
    len: u64,
    mt: i64,
    mn: i64,
    ct: i64,
    cn: i64,
}
fn stat(f: &File) -> LegacyResult<Stat> {
    let m = f.metadata().map_err(unknown)?;
    Ok(Stat {
        dev: m.dev(),
        ino: m.ino(),
        uid: m.uid(),
        mode: m.mode(),
        nlink: m.nlink(),
        len: m.len(),
        mt: m.mtime(),
        mn: m.mtime_nsec(),
        ct: m.ctime(),
        cn: m.ctime_nsec(),
    })
}
/// Safe nix descriptor walk: root or current-UID owned immutable parent path;
/// final private regular file, or cgroup directory. Never follows a symlink.
fn open_checked(path: &Path, directory: bool) -> LegacyResult<File> {
    if !path.is_absolute() || path.as_os_str().len() > 4096 {
        return Err(LegacyError::Invalid);
    }
    let mut fd: OwnedFd = open_fd(
        "/",
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(unavailable)?;
    let parts: Vec<_> = path
        .components()
        .filter_map(|p| match p {
            Component::RootDir => None,
            Component::Normal(n) => Some(Ok(n)),
            _ => Some(Err(LegacyError::Invalid)),
        })
        .collect::<LegacyResult<_>>()?;
    if parts.is_empty() {
        return Err(LegacyError::Invalid);
    }
    for (i, part) in parts.iter().enumerate() {
        let last = i + 1 == parts.len();
        let flags = OFlag::O_RDONLY
            | OFlag::O_CLOEXEC
            | OFlag::O_NOFOLLOW
            | OFlag::O_NONBLOCK
            | if !last || directory {
                OFlag::O_DIRECTORY
            } else {
                OFlag::empty()
            };
        fd = openat(fd.as_fd(), Path::new(part), flags, Mode::empty()).map_err(unavailable)?;
        let m = nix::sys::stat::fstat(&fd).map_err(unavailable)?;
        if (m.st_uid != 0 && m.st_uid != Uid::current().as_raw()) || m.st_mode & 0o022 != 0 {
            return Err(LegacyError::Conflict);
        }
        if last
            && !directory
            && (m.st_uid != Uid::current().as_raw()
                || m.st_nlink != 1
                || m.st_mode & 0o077 != 0
                || m.st_mode & libc::S_IFMT != libc::S_IFREG)
        {
            return Err(LegacyError::Conflict);
        }
    }
    Ok(File::from(fd))
}
fn read_file(f: &mut File, cap: u64) -> LegacyResult<Vec<u8>> {
    let before = stat(f)?;
    if before.len > cap {
        return Err(LegacyError::Conflict);
    }
    f.seek(SeekFrom::Start(0)).map_err(unknown)?;
    let mut out = Vec::new();
    (&mut *f)
        .take(cap + 1)
        .read_to_end(&mut out)
        .map_err(unknown)?;
    if out.len() as u64 > cap || stat(f)? != before {
        return Err(LegacyError::Conflict);
    }
    Ok(out)
}
fn image_sha(f: &mut File) -> LegacyResult<Sha256Digest> {
    let before = stat(f)?;
    if before.len == 0 || before.len > IMAGE_CAP {
        return Err(LegacyError::Conflict);
    }
    f.seek(SeekFrom::Start(0)).map_err(unknown)?;
    let mut hash = Sha256::new();
    let mut remaining = IMAGE_CAP + 1;
    let mut buf = [0u8; 65536];
    loop {
        let n = f.read(&mut buf).map_err(unknown)?;
        if n == 0 {
            break;
        }
        if n as u64 > remaining {
            return Err(LegacyError::Conflict);
        }
        remaining -= n as u64;
        hash.update(&buf[..n]);
    }
    if stat(f)? != before {
        return Err(LegacyError::Conflict);
    }
    // Scalar parse uses the existing strict 32-byte hash type, not secret data.
    Ok(Sha256Digest::from_bytes(hash.finalize().into()))
}

// Closed, locally verified inputs only: neither a remote UnitSpec nor Host
// argv/descriptor reuse can manufacture Gateway control authority. Both kinds
// retain the original Host fence, but authenticate their own installed launch.
enum ScopeInputs {
    Host(Arc<VerifiedLegacyServiceInputs>),
    Gateway {
        host: Arc<VerifiedLegacyServiceInputs>,
        gateway: Arc<gateway::VerifiedGatewayInputs>,
    },
}
pub(crate) struct VerifiedGatewayCaptureInputs(Arc<ScopeInputs>);
impl ScopeInputs {
    fn host(&self) -> &Arc<VerifiedLegacyServiceInputs> {
        match self {
            Self::Host(host) | Self::Gateway { host, .. } => host,
        }
    }
    fn unit_name(&self) -> &str {
        match self {
            Self::Host(host) => &host.descriptor.unit_name,
            Self::Gateway { gateway, .. } => &gateway.unit_name,
        }
    }
    fn unit_file(&self) -> &Path {
        match self {
            Self::Host(host) => &host.unit_file,
            Self::Gateway { gateway, .. } => &gateway.unit_file,
        }
    }
    fn unit_bytes(&self) -> &[u8] {
        match self {
            Self::Host(host) => &host.unit_bytes,
            Self::Gateway { gateway, .. } => &gateway.unit_bytes,
        }
    }
    fn argv(&self) -> Vec<String> {
        match self {
            Self::Host(host) => {
                let d = &host.descriptor;
                vec![
                    d.node_binary.to_string_lossy().into_owned(),
                    d.install_root
                        .join("launch.mjs")
                        .to_string_lossy()
                        .into_owned(),
                    d.install_root.to_string_lossy().into_owned(),
                    d.host_config_file.to_string_lossy().into_owned(),
                    d.trust_public_key_file.to_string_lossy().into_owned(),
                ]
            }
            Self::Gateway { gateway, .. } => gateway.expected_argv.clone(),
        }
    }
    fn node_sha(&self) -> Sha256Digest {
        match self {
            Self::Host(host) => host.node_sha,
            Self::Gateway { gateway, .. } => gateway.node_sha,
        }
    }
    fn cwd(&self) -> LegacyResult<&str> {
        match self {
            Self::Host(host) => host
                .descriptor
                .install_root
                .to_str()
                .ok_or(LegacyError::Invalid),
            Self::Gateway { .. } => Ok(""),
        }
    }
    fn stop_usec(&self) -> u64 {
        match self {
            Self::Host(_) => 12_000_000,
            Self::Gateway { .. } => 15_000_000,
        }
    }
    fn restart_usec(&self) -> u64 {
        match self {
            Self::Host(host) => u64::from(host.descriptor.restart_sec) * 1_000_000,
            Self::Gateway { .. } => 3_000_000,
        }
    }
    fn revalidate(&self) -> LegacyResult<()> {
        match self {
            Self::Host(host) => host.revalidate(),
            // Host's original credential has already been retired. Its same
            // writer/fence is checked separately, never via an ordinary loader.
            Self::Gateway { gateway, .. } => gateway.revalidate(),
        }
    }
    fn revalidate_after_settlement(&self) -> LegacyResult<()> {
        match self {
            // Preserve the original Host settlement contract: the original
            // fence/descriptor is rechecked, not a second whole-profile load.
            Self::Host(_) => Ok(()),
            Self::Gateway { gateway, .. } => gateway.revalidate(),
        }
    }
    fn verify_fence(&self, fence: &LegacyWriterFence) -> LegacyResult<()> {
        let host = self.host();
        fence
            .verify_service_descriptor(&host.protected_descriptor)
            .map_err(conflict)?;
        if fence.configuration_root().identity().map_err(conflict)? != host.profile.root.identity()
        {
            return Err(LegacyError::Conflict);
        }
        Ok(())
    }
}

/// Never Clone/Deserialize. Scope is retained through original-ID settlement;
/// even a confirmed physical stop is NOT a writer/activation handoff proof.
pub(crate) struct LegacyManagedScope {
    inputs: Arc<ScopeInputs>,
    fence: Arc<LegacyWriterFence>,
    gateway_registered: Mutex<bool>,
    connection: zbus::Connection,
    manager_owner: String,
    manager_birth: ProcessIdentity,
    unit_object: zbus::zvariant::OwnedObjectPath,
    invocation: String,
    main: ProcessIdentity,
    main_image: File,
    main_image_stat: Stat,
    cgroup_path: String,
    cgroup: File,
    cgroup_stat: Stat,
    events: File,
    settlement: Mutex<Option<SettlementTask>>,
}
#[must_use]
pub(crate) struct LegacyCaptureFailure {
    pub(crate) cause: LegacyError,
    retained: Arc<LegacyWriterFence>,
}
impl LegacyCaptureFailure {
    pub(crate) fn fence(&self) -> &LegacyWriterFence {
        &self.retained
    }
}
struct Captured {
    connection: zbus::Connection,
    manager_owner: String,
    manager_birth: ProcessIdentity,
    unit_object: zbus::zvariant::OwnedObjectPath,
    invocation: String,
    main: ProcessIdentity,
    main_image: File,
    main_image_stat: Stat,
    cgroup_path: String,
    cgroup: File,
    cgroup_stat: Stat,
    events: File,
}
/// The short fence write/fsync section shares the same bounded preparation pool.
pub(crate) fn preparation_permit() -> LegacyResult<OwnedSemaphorePermit> {
    READERS
        .clone()
        .try_acquire_owned()
        .map_err(|_| LegacyError::Busy)
}

pub(crate) async fn load_inputs(
    state_dir: &Path,
) -> LegacyResult<Arc<VerifiedLegacyServiceInputs>> {
    Ok(Arc::new(
        VerifiedLegacyServiceInputs::load(state_dir).await?,
    ))
}
/// A verified C08 runtime candidate must match the ORIGINAL publisher before
/// any legacy scope control. Caller retains candidate through scope/proof use;
/// this read-only check does not authorize activation or substitute a new key.
pub(crate) async fn verify_candidate(
    inputs: Arc<VerifiedLegacyServiceInputs>,
    candidate: Arc<crate::release::VerifiedNativeRelease>,
) -> LegacyResult<()> {
    let report = candidate.report();
    if !cfg!(all(
        target_arch = "x86_64",
        target_os = "linux",
        target_env = "gnu"
    )) {
        return Err(LegacyError::Unsupported);
    }
    if report.scope != "runtime_candidate"
        || report.target != "x86_64-unknown-linux-gnu"
        || report.publisher_spki_sha256 != inputs.publisher_sha256()
    {
        return Err(LegacyError::Conflict);
    }
    legacy_blocking(move || {
        candidate.revalidate().map_err(|error| match error {
            crate::release::ReleaseError::Unknown => LegacyError::Unknown,
            crate::release::ReleaseError::Unavailable => LegacyError::Unavailable,
            crate::release::ReleaseError::Busy => LegacyError::Busy,
            crate::release::ReleaseError::Unsupported => LegacyError::Unsupported,
            crate::release::ReleaseError::Invalid
            | crate::release::ReleaseError::Untrusted
            | crate::release::ReleaseError::Integrity
            | crate::release::ReleaseError::Changed
            | crate::release::ReleaseError::Capacity => LegacyError::Conflict,
        })?;
        inputs.revalidate()
    })
    .await
}
async fn capture_checked(
    inputs: Arc<ScopeInputs>,
    fence: Arc<LegacyWriterFence>,
) -> LegacyResult<Arc<LegacyManagedScope>> {
    let check = fence.clone();
    let original = inputs.clone();
    legacy_blocking(move || original.verify_fence(&check)).await?;
    let c = capture_exact(&inputs, Instant::now() + Duration::from_secs(20)).await?;
    let check = fence.clone();
    let original = inputs.clone();
    legacy_blocking(move || {
        original.verify_fence(&check)?;
        original.revalidate()
    })
    .await?;
    Ok(Arc::new(LegacyManagedScope {
        inputs,
        fence,
        gateway_registered: Mutex::new(false),
        connection: c.connection,
        manager_owner: c.manager_owner,
        manager_birth: c.manager_birth,
        unit_object: c.unit_object,
        invocation: c.invocation,
        main: c.main,
        main_image: c.main_image,
        main_image_stat: c.main_image_stat,
        cgroup_path: c.cgroup_path,
        cgroup: c.cgroup,
        cgroup_stat: c.cgroup_stat,
        events: c.events,
        settlement: Mutex::new(None),
    }))
}
// Official systemd Service.ExecStart: a(sasbttttuii). No parsing formatted
// systemctl ExecStart strings, shell splitting, request argv or env authority.
type ExecStart = (String, Vec<String>, bool, u64, u64, u64, u64, u32, i32, i32);
async fn capture_exact(i: &Arc<ScopeInputs>, end: Instant) -> LegacyResult<Captured> {
    timeout_at(end, capture_exact_inner(i))
        .await
        .map_err(unknown)?
}
// Authorization and settlement samples must be fresh DBus reads. The pinned
// generic Proxy builder otherwise defaults to lazy property caching, which can
// make a second read an old snapshot rather than the required second sample.
async fn live_proxy<'a>(
    connection: &zbus::Connection,
    destination: &'a str,
    path: &'a str,
    interface: &'a str,
) -> zbus::Result<zbus::Proxy<'a>> {
    zbus::proxy::Builder::new(connection)
        .destination(destination)?
        .path(path)?
        .interface(interface)?
        .cache_properties(zbus::proxy::CacheProperties::No)
        .build()
        .await
}

async fn capture_exact_inner(i: &Arc<ScopeInputs>) -> LegacyResult<Captured> {
    let p = &i.host().profile;
    let stream = tokio::net::UnixStream::connect(p.runtime.join("bus"))
        .await
        .map_err(unavailable)?;
    if stream.peer_cred().map_err(unavailable)?.uid() != p.identity.uid {
        return Err(LegacyError::Conflict);
    }
    let connection = zbus::connection::Builder::unix_stream(stream)
        .max_queued(4)
        .method_timeout(Duration::from_secs(2))
        .build()
        .await
        .map_err(unavailable)?;
    let bus = zbus::fdo::DBusProxy::new(&connection)
        .await
        .map_err(unavailable)?;
    let owner = bus
        .get_name_owner("org.freedesktop.systemd1".try_into().map_err(conflict)?)
        .await
        .map_err(unavailable)?;
    if bus
        .get_connection_unix_user(owner.as_ref().into())
        .await
        .map_err(unknown)?
        != p.identity.uid
    {
        return Err(LegacyError::Conflict);
    }
    let manager_pid = bus
        .get_connection_unix_process_id(owner.as_ref().into())
        .await
        .map_err(unknown)?;
    let manager_birth = ProcessIdentity::observe(manager_pid).map_err(unknown)?;
    if std::fs::metadata(format!("/proc/{manager_pid}"))
        .map_err(unknown)?
        .uid()
        != p.identity.uid
    {
        return Err(LegacyError::Conflict);
    }
    let manager = zbus::Proxy::new(
        &connection,
        owner.as_str(),
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
    )
    .await
    .map_err(unavailable)?;
    let unit_object: zbus::zvariant::OwnedObjectPath = manager
        .call("GetUnit", &(i.unit_name(),))
        .await
        .map_err(unavailable)?;
    let _: () = manager
        .call("RefUnit", &(i.unit_name(),))
        .await
        .map_err(unknown)?;
    // Reference is connection-scoped. No signal/StopUnit has occurred.
    let unit = live_proxy(
        &connection,
        owner.as_str(),
        unit_object.as_str(),
        "org.freedesktop.systemd1.Unit",
    )
    .await
    .map_err(unavailable)?;
    let service = live_proxy(
        &connection,
        owner.as_str(),
        unit_object.as_str(),
        "org.freedesktop.systemd1.Service",
    )
    .await
    .map_err(unavailable)?;
    for (key, wanted) in [
        ("Id", i.unit_name()),
        ("LoadState", "loaded"),
        ("ActiveState", "active"),
        ("SubState", "running"),
        (
            "FragmentPath",
            i.unit_file().to_str().ok_or(LegacyError::Invalid)?,
        ),
        ("SourcePath", ""),
        ("Following", ""),
    ] {
        if property_string(&unit, key).await? != wanted {
            return Err(LegacyError::Conflict);
        }
    }
    let names: Vec<String> = unit.get_property("Names").await.map_err(unknown)?;
    let dropins: Vec<String> = unit.get_property("DropInPaths").await.map_err(unknown)?;
    let reload: bool = unit
        .get_property("NeedDaemonReload")
        .await
        .map_err(unknown)?;
    let transient: bool = unit.get_property("Transient").await.map_err(unknown)?;
    if names != [i.unit_name().to_owned()] || !dropins.is_empty() || reload || transient {
        return Err(LegacyError::Conflict);
    }
    let invocation_bytes: Vec<u8> = unit.get_property("InvocationID").await.map_err(unknown)?;
    if invocation_bytes.len() != 16 || invocation_bytes.iter().all(|v| *v == 0) {
        return Err(LegacyError::Conflict);
    }
    let invocation = invocation_bytes
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect::<String>();
    let raw_type = if i.unit_bytes().windows(13).any(|s| s == b"\nType=simple\n") {
        "simple"
    } else {
        "exec"
    };
    for (key, wanted) in [
        ("Type", raw_type),
        ("Restart", "on-failure"),
        ("KillMode", "control-group"),
        ("WorkingDirectory", i.cwd()?),
    ] {
        if property_string(&service, key).await? != wanted {
            return Err(LegacyError::Conflict);
        }
    }
    let timeout: u64 = service
        .get_property("TimeoutStopUSec")
        .await
        .map_err(unknown)?;
    let restart: u64 = service.get_property("RestartUSec").await.map_err(unknown)?;
    let mask: u32 = service.get_property("UMask").await.map_err(unknown)?;
    let nnp: bool = service
        .get_property("NoNewPrivileges")
        .await
        .map_err(unknown)?;
    let send_kill: bool = service.get_property("SendSIGKILL").await.map_err(unknown)?;
    if timeout != i.stop_usec() || restart != i.restart_usec() || mask != 0o77 || !nnp || !send_kill
    {
        return Err(LegacyError::Conflict);
    }
    let execs: Vec<ExecStart> = service.get_property("ExecStart").await.map_err(unknown)?;
    let expected = i.argv();
    if execs.len() != 1 || execs[0].0 != expected[0] || execs[0].1 != expected || execs[0].2 {
        return Err(LegacyError::Conflict);
    }
    let pid: u32 = service.get_property("MainPID").await.map_err(unknown)?;
    let exec_pid: u32 = service.get_property("ExecMainPID").await.map_err(unknown)?;
    if pid < 2 || exec_pid != pid {
        return Err(LegacyError::Conflict);
    }
    let uid = p.identity.uid;
    let sha = i.node_sha();
    let argv = expected.clone();
    let (main, main_image, main_image_stat) = legacy_blocking(move || {
        let main = ProcessIdentity::observe(pid).map_err(unknown)?;
        if std::fs::metadata(format!("/proc/{pid}"))
            .map_err(unknown)?
            .uid()
            != uid
        {
            return Err(LegacyError::Conflict);
        }
        // Intended kernel exe alias; expected bytes came from the signed member.
        let mut image = File::open(format!("/proc/{pid}/exe")).map_err(unknown)?;
        let stamp = stat(&image)?;
        if stamp.uid != uid || stamp.mode & 0o022 != 0 || image_sha(&mut image)? != sha {
            return Err(LegacyError::Conflict);
        }
        let mut cmd_file = File::open(format!("/proc/{pid}/cmdline")).map_err(unknown)?;
        let cmd = read_file(&mut cmd_file, 16 * 1024)?;
        if cmd
            .split(|c| *c == 0)
            .filter(|v| !v.is_empty())
            .collect::<Vec<_>>()
            != argv.iter().map(|s| s.as_bytes()).collect::<Vec<_>>()
            || !main.still_current().map_err(unknown)?
        {
            return Err(LegacyError::Conflict);
        }
        Ok((main, image, stamp))
    })
    .await?;
    let cgroup_path = property_string(&service, "ControlGroup").await?;
    let path = super::cgroup_path(p, i.unit_name(), &cgroup_path).map_err(conflict)?;
    let cgroup = open_checked(&path, true)?;
    if nix::sys::statfs::fstatfs(&cgroup)
        .map_err(unavailable)?
        .filesystem_type()
        != nix::sys::statfs::CGROUP2_SUPER_MAGIC
    {
        return Err(LegacyError::Unsupported);
    }
    let cgroup_stat = stat(&cgroup)?;
    let events = File::from(
        openat(
            cgroup.as_fd(),
            "cgroup.events",
            OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )
        .map_err(unknown)?,
    );
    require_process_cgroup(pid, &cgroup_path, &cgroup_stat)?;
    // End-to-end double sample: no MainPID/Invocation/cgroup/owner adoption.
    let now_pid: u32 = service.get_property("MainPID").await.map_err(unknown)?;
    let now_inv: Vec<u8> = unit.get_property("InvocationID").await.map_err(unknown)?;
    if now_pid != pid
        || now_inv != invocation_bytes
        || property_string(&service, "ControlGroup").await? != cgroup_path
        || !main.still_current().map_err(unknown)?
        || !manager_birth.still_current().map_err(unknown)?
        || bus
            .get_name_owner("org.freedesktop.systemd1".try_into().map_err(conflict)?)
            .await
            .map_err(unknown)?
            .as_str()
            != owner.as_str()
        || stat(&main_image)? != main_image_stat
    {
        return Err(LegacyError::Conflict);
    }
    let check = i.clone();
    legacy_blocking(move || check.revalidate()).await?;
    drop(service);
    drop(unit);
    drop(manager);
    drop(bus);
    Ok(Captured {
        connection,
        manager_owner: owner.to_string(),
        manager_birth,
        unit_object,
        invocation,
        main,
        main_image,
        main_image_stat,
        cgroup_path,
        cgroup,
        cgroup_stat,
        events,
    })
}
async fn property_string(proxy: &zbus::Proxy<'_>, name: &str) -> LegacyResult<String> {
    let value: String = proxy.get_property(name).await.map_err(unknown)?;
    if value.len() > 4096 || value.chars().any(char::is_control) {
        return Err(LegacyError::Conflict);
    }
    Ok(value)
}
fn require_process_cgroup(pid: u32, expected: &str, held: &Stat) -> LegacyResult<()> {
    let path = format!("/proc/{pid}/cgroup");
    let mut file = File::open(path).map_err(unknown)?;
    let bytes = read_file(&mut file, 4096)?;
    if bytes.len() > 4096 {
        return Err(LegacyError::Conflict);
    }
    let text = std::str::from_utf8(&bytes).map_err(conflict)?;
    if text.lines().collect::<Vec<_>>() != [format!("0::{expected}")] {
        return Err(LegacyError::Conflict);
    }
    let current = open_checked(
        &Path::new("/sys/fs/cgroup").join(expected.trim_start_matches('/')),
        true,
    )?;
    let now = stat(&current)?;
    if now.dev != held.dev || now.ino != held.ino {
        return Err(LegacyError::Conflict);
    }
    Ok(())
}

// The existing READERS/spawn_blocking wrapper owns admission to actual finish.
// An outer timeout does not cancel that work or return its permit early.
async fn legacy_blocking<T: Send + 'static>(
    f: impl FnOnce() -> LegacyResult<T> + Send + 'static,
) -> LegacyResult<T> {
    match blocking(move || Ok(f())).await {
        Ok(value) => value,
        Err(error) => Err(match error {
            ManagerError::Busy => LegacyError::Busy,
            ManagerError::Invalid => LegacyError::Invalid,
            ManagerError::Conflict => LegacyError::Conflict,
            ManagerError::Unavailable => LegacyError::Unavailable,
            ManagerError::Unknown => LegacyError::Unknown,
        }),
    }
}

/// Capture has no side effect on the service. A synchronously registered owner
/// retains its fence even if every waiter is dropped before the DBus read ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CaptureState {
    Pending,
    Ready,
    Failed(LegacyError),
}
struct CaptureCompletion {
    result: Option<LegacyResult<Arc<LegacyManagedScope>>>,
    worker: Option<tokio::task::JoinHandle<()>>,
    retained: Option<Arc<CaptureJob>>,
    capacity: Option<OwnedSemaphorePermit>,
}
struct CaptureJob {
    fence: Arc<LegacyWriterFence>,
    completion: Mutex<CaptureCompletion>,
}
pub(crate) struct LegacyCaptureTicket {
    job: Arc<CaptureJob>,
    state: watch::Receiver<CaptureState>,
}
pub(crate) fn capture(
    inputs: Arc<VerifiedLegacyServiceInputs>,
    fence: LegacyWriterFence,
) -> std::result::Result<LegacyCaptureTicket, LegacyCaptureFailure> {
    capture_owned(Arc::new(ScopeInputs::Host(inputs)), Arc::new(fence))
}
fn capture_owned(
    inputs: Arc<ScopeInputs>,
    fence: Arc<LegacyWriterFence>,
) -> std::result::Result<LegacyCaptureTicket, LegacyCaptureFailure> {
    let capacity = ACTIONS
        .clone()
        .try_acquire_owned()
        .map_err(|_| LegacyCaptureFailure {
            cause: LegacyError::Busy,
            retained: fence.clone(),
        })?;
    let (tx, state) = watch::channel(CaptureState::Pending);
    let job = Arc::new(CaptureJob {
        fence: fence.clone(),
        completion: Mutex::new(CaptureCompletion {
            result: None,
            worker: None,
            retained: None,
            capacity: Some(capacity),
        }),
    });
    let mut completion = job.completion.lock().map_err(|_| LegacyCaptureFailure {
        cause: LegacyError::Unknown,
        retained: fence.clone(),
    })?;
    // Intentional bounded retention, broken only by explicit consume+actual join.
    completion.retained = Some(job.clone());
    let owned = job.clone();
    completion.worker = Some(tokio::spawn(async move {
        let result = AssertUnwindSafe(capture_checked(inputs, fence))
            .catch_unwind()
            .await
            .unwrap_or(Err(LegacyError::Unknown));
        let state = match &result {
            Ok(_) => CaptureState::Ready,
            Err(e) => CaptureState::Failed(*e),
        };
        if let Ok(mut completion) = owned.completion.lock() {
            completion.result = Some(result);
            tx.send_replace(state);
        }
        // If this mutex were poisoned, the retained owner remains inaccessible
        // and fenced, rather than inferring that the read/capture succeeded.
    }));
    drop(completion);
    Ok(LegacyCaptureTicket { job, state })
}
impl LegacyCaptureTicket {
    pub(crate) fn query(&self) -> CaptureState {
        *self.state.borrow()
    }
    pub(crate) async fn changed(&mut self) -> CaptureState {
        let _ = self.state.changed().await;
        self.query()
    }
    /// Busy is a read/consume race, never permission to dispatch another job.
    /// now_or_never performs the actual join synchronously only after finished;
    /// cancelling a consume future cannot lose the original JoinHandle.
    pub(crate) fn try_complete(
        &self,
    ) -> std::result::Result<Arc<LegacyManagedScope>, LegacyCaptureFailure> {
        let failure = |cause| LegacyCaptureFailure {
            cause,
            retained: self.job.fence.clone(),
        };
        let mut c = self
            .job
            .completion
            .lock()
            .map_err(|_| failure(LegacyError::Unknown))?;
        let handle = c
            .worker
            .as_ref()
            .ok_or_else(|| failure(LegacyError::Conflict))?;
        if !handle.is_finished() {
            return Err(failure(LegacyError::Busy));
        }
        let handle = c
            .worker
            .take()
            .ok_or_else(|| failure(LegacyError::Unknown))?;
        if !matches!(handle.now_or_never(), Some(Ok(()))) {
            return Err(failure(LegacyError::Unknown));
        }
        let result = c
            .result
            .take()
            .ok_or_else(|| failure(LegacyError::Unknown))?;
        c.retained.take();
        c.capacity.take();
        result.map_err(failure)
    }
}
impl std::fmt::Debug for LegacyCaptureFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LegacyCaptureFailure")
            .field("cause", &self.cause)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SettlementPhase {
    Registered,
    Stopping,
    Unknown,
    Confirmed,
    Consumed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct LegacySettlementObservation {
    pub phase: SettlementPhase,
    pub term_attempted: bool,
    pub signal_accepted: bool,
    pub original_main_exited: bool,
    pub original_cgroup_empty: bool,
    pub manager_reported_success: bool,
    pub worker_joined: bool,
    pub checkpoint: &'static str,
    pub elapsed_millis: u64,
    pub failure: Option<LegacyError>,
}
impl LegacySettlementObservation {
    fn registered() -> Self {
        Self {
            phase: SettlementPhase::Registered,
            term_attempted: false,
            signal_accepted: false,
            original_main_exited: false,
            original_cgroup_empty: false,
            manager_reported_success: false,
            worker_joined: false,
            checkpoint: "registered",
            elapsed_millis: 0,
            failure: None,
        }
    }
}
fn publish_checkpoint(
    fact: &mut LegacySettlementObservation,
    checkpoint: &'static str,
    started: Instant,
    tx: &watch::Sender<LegacySettlementObservation>,
) {
    fact.checkpoint = checkpoint;
    fact.elapsed_millis = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    tx.send_replace(*fact);
}
struct SettlementTask {
    worker: Option<tokio::task::JoinHandle<()>>,
    state: watch::Receiver<LegacySettlementObservation>,
    retained: Option<Arc<LegacyManagedScope>>,
    capacity: Option<OwnedSemaphorePermit>,
}
/// Physical facts and the SAME still-held writer/fence. No handoff/activation
/// authority, no Clone/Serde, no constructor outside this original joined job.
pub(crate) struct LegacySettlementProof {
    scope: Arc<LegacyManagedScope>,
    observation: LegacySettlementObservation,
    _capacity: OwnedSemaphorePermit,
}
impl LegacySettlementProof {
    /// Independently authenticate Gateway launch inputs under this SAME original
    /// Host retirement authority. This does not reload an ordinary Host profile.
    pub(crate) async fn load_gateway_inputs(
        &self,
        candidate: Arc<crate::release::VerifiedNativeRelease>,
    ) -> LegacyResult<VerifiedGatewayCaptureInputs> {
        let ScopeInputs::Host(host) = self.scope.inputs.as_ref() else {
            return Err(LegacyError::Conflict);
        };
        // A denial needs no repeated inventory scan. Registration still checks
        // the same slot atomically after verification, including racing callers.
        if *self.scope.gateway_registered.lock().map_err(unknown)? {
            return Err(LegacyError::Conflict);
        }
        self.verify_original_still_settled().await?;
        self.credential_retirement_observation()?;
        let host = host.clone();
        let inputs = legacy_blocking(move || {
            let gateway = gateway::VerifiedGatewayInputs::derive(&host)?;
            if candidate.report().publisher_spki_sha256 != gateway.publisher_sha256 {
                return Err(LegacyError::Conflict);
            }
            candidate.revalidate().map_err(conflict)?;
            gateway.revalidate()?;
            Ok(Arc::new(ScopeInputs::Gateway {
                host,
                gateway: Arc::new(gateway),
            }))
        })
        .await?;
        self.verify_original_still_settled().await?;
        self.credential_retirement_observation()?;
        Ok(VerifiedGatewayCaptureInputs(inputs))
    }
    /// The original Host owns one Gateway capture slot. A Busy capacity refusal
    /// before registration is retryable; any registered job (including Unknown)
    /// permanently occupies this slot. A second waiter cannot issue another TERM.
    pub(crate) fn capture_gateway(
        &self,
        inputs: VerifiedGatewayCaptureInputs,
    ) -> std::result::Result<LegacyCaptureTicket, LegacyCaptureFailure> {
        let inputs = inputs.0;
        let fail = |cause| LegacyCaptureFailure {
            cause,
            retained: self.scope.fence.clone(),
        };
        let ScopeInputs::Gateway { host, .. } = inputs.as_ref() else {
            return Err(fail(LegacyError::Conflict));
        };
        if !matches!(self.scope.inputs.as_ref(), ScopeInputs::Host(original) if Arc::ptr_eq(original, host))
        {
            return Err(fail(LegacyError::Conflict));
        }
        let mut registered = self
            .scope
            .gateway_registered
            .lock()
            .map_err(|_| fail(LegacyError::Unknown))?;
        if *registered {
            return Err(fail(LegacyError::Conflict));
        }
        let result = capture_owned(inputs, self.scope.fence.clone());
        if !matches!(&result, Err(error) if error.cause == LegacyError::Busy) {
            *registered = true;
        }
        result
    }
    /// Recheck the original pinned invocation while its reference is retained.
    /// A different invocation, owner or leftover process is never adopted.
    pub(crate) async fn verify_original_still_settled(&self) -> LegacyResult<()> {
        if matches!(self.scope.inputs.as_ref(), ScopeInputs::Gateway { .. }) {
            let inputs = self.scope.inputs.clone();
            let fence = self.scope.fence.clone();
            legacy_blocking(move || {
                inputs.verify_fence(&fence)?;
                inputs.revalidate()
            })
            .await?;
        }
        let facts = tokio::time::timeout(Duration::from_secs(8), observe_original(&self.scope))
            .await
            .map_err(unknown)??;
        if !facts.original_main_exited
            || !facts.original_cgroup_empty
            || !facts.manager_reported_success
        {
            return Err(LegacyError::Conflict);
        }
        Ok(())
    }
    pub(crate) fn retire_credential_locator(
        &self,
        target: &crate::release::VerifiedNativeRelease,
    ) -> LegacyResult<()> {
        self.scope
            .fence
            .retire_credential_locator(target)
            .map_err(|error| match error {
                crate::store::legacy_handoff::LegacyFenceError::Unknown => LegacyError::Unknown,
                _ => LegacyError::Conflict,
            })?;
        Ok(())
    }
    pub(crate) fn credential_retirement_observation(
        &self,
    ) -> LegacyResult<crate::store::legacy_handoff::CredentialRetirementObservation> {
        self.scope
            .fence
            .credential_retirement_observation()
            .map_err(|_| LegacyError::Unknown)
    }
    pub(crate) fn invalidate_credential_retirement(&self) {
        self.scope.fence.invalidate_credential_retirement();
    }
    pub(crate) fn observation(&self) -> LegacySettlementObservation {
        self.observation
    }
    pub(crate) fn fence(&self) -> &LegacyWriterFence {
        &self.scope.fence
    }
    pub(crate) fn service_descriptor(&self) -> &LegacyServiceDescriptor {
        &self.scope.inputs.host().protected_descriptor
    }
}
impl LegacyManagedScope {
    pub(crate) fn is_gateway_of(&self, original: &LegacySettlementProof) -> bool {
        matches!((self.inputs.as_ref(), original.scope.inputs.as_ref()),
            (ScopeInputs::Gateway { host, .. }, ScopeInputs::Host(expected)) if Arc::ptr_eq(host, expected))
            && Arc::ptr_eq(&self.fence, &original.scope.fence)
            && self.inputs.unit_name() != original.scope.inputs.unit_name()
            && self.invocation != original.scope.invocation
            && (self.cgroup_stat.dev, self.cgroup_stat.ino)
                != (
                    original.scope.cgroup_stat.dev,
                    original.scope.cgroup_stat.ino,
                )
    }
    pub(crate) fn begin_settlement(
        self: &Arc<Self>,
        budget: Duration,
        cancel: CancellationToken,
    ) -> LegacyResult<()> {
        if budget < Duration::from_millis(1) || budget > Duration::from_secs(30) {
            return Err(LegacyError::Invalid);
        }
        let mut job = self.settlement.lock().map_err(unknown)?;
        if job.is_some() {
            return Err(LegacyError::Conflict);
        }
        let capacity = ACTIONS
            .clone()
            .try_acquire_owned()
            .map_err(|_| LegacyError::Busy)?;
        let (tx, state) = watch::channel(LegacySettlementObservation::registered());
        let owned = self.clone();
        let guard = self.clone();
        let started = Instant::now();
        let worker = tokio::spawn(async move {
            let result = AssertUnwindSafe(run_settlement(owned, budget, cancel, tx.clone()))
                .catch_unwind()
                .await;
            if !matches!(result, Ok(Ok(()))) {
                let mut current = *tx.borrow();
                current.phase = SettlementPhase::Unknown;
                current.failure = Some(match result {
                    Ok(Err(error)) => error,
                    _ => LegacyError::Unknown,
                });
                current.elapsed_millis =
                    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                tx.send_replace(current);
            }
            // guard also survives panic handling. The record's explicit retained
            // Arc keeps this exact fence after completion, including Unknown.
            drop(guard);
        });
        *job = Some(SettlementTask {
            worker: Some(worker),
            state,
            retained: Some(self.clone()),
            capacity: Some(capacity),
        });
        Ok(())
    }
    pub(crate) fn query_settlement(&self) -> LegacyResult<Option<LegacySettlementObservation>> {
        let task = self.settlement.lock().map_err(unknown)?;
        Ok(task.as_ref().map(|t| {
            let mut value = *t.state.borrow();
            if t.retained.is_none() && t.capacity.is_none() {
                value.phase = SettlementPhase::Consumed;
                value.worker_joined = true;
            }
            value
        }))
    }
    /// Only a confirmed completed worker may be joined/consumed. All failure
    /// paths leave the intentional retained Arc and original writer in place.
    pub(crate) fn consume_settlement(&self) -> LegacyResult<LegacySettlementProof> {
        let mut task = self.settlement.lock().map_err(unknown)?;
        let task = task.as_mut().ok_or(LegacyError::Invalid)?;
        let mut observation = *task.state.borrow();
        if observation.phase != SettlementPhase::Confirmed {
            return Err(LegacyError::Unknown);
        }
        let worker = task.worker.as_ref().ok_or(LegacyError::Conflict)?;
        if !worker.is_finished() {
            return Err(LegacyError::Busy);
        }
        if !matches!(
            task.worker
                .take()
                .ok_or(LegacyError::Unknown)?
                .now_or_never(),
            Some(Ok(()))
        ) {
            return Err(LegacyError::Unknown);
        }
        let scope = task.retained.take().ok_or(LegacyError::Unknown)?;
        let capacity = task.capacity.take().ok_or(LegacyError::Unknown)?;
        observation.worker_joined = true;
        observation.phase = SettlementPhase::Consumed;
        Ok(LegacySettlementProof {
            scope,
            observation,
            _capacity: capacity,
        })
    }
}

async fn run_settlement(
    scope: Arc<LegacyManagedScope>,
    budget: Duration,
    cancel: CancellationToken,
    tx: watch::Sender<LegacySettlementObservation>,
) -> LegacyResult<()> {
    let started = Instant::now();
    let deadline = started + budget;
    let mut fact = LegacySettlementObservation::registered();
    if cancel.is_cancelled() {
        return Err(LegacyError::Unknown);
    }
    // Revalidate complete signed bootstrap and same descriptor/fence before any
    // control. No asynchronous request provides a replacement executable path.
    publish_checkpoint(&mut fact, "validating_inputs", started, &tx);
    let check = scope.clone();
    legacy_blocking(move || {
        check.inputs.verify_fence(&check.fence)?;
        check.inputs.revalidate()?;
        if check.main.still_current().map_err(unknown)? {
            check_live_image(&check)?;
        }
        // An original main that naturally exited is not replaced or signalled;
        // only its original manager result and held cgroup can settle it.
        Ok(())
    })
    .await?;
    publish_checkpoint(&mut fact, "observing_original", started, &tx);
    let before = observe_original(&scope).await?;
    if cancel.is_cancelled() || Instant::now() >= deadline {
        return Err(LegacyError::Unknown);
    }
    if before.confirmed() {
        fact.original_main_exited = true;
        fact.original_cgroup_empty = true;
        fact.manager_reported_success = true;
        fact.phase = SettlementPhase::Confirmed;
        tx.send_replace(fact);
        return Ok(());
    }
    if before.original_main_exited || cancel.is_cancelled() || Instant::now() >= deadline {
        return Err(LegacyError::Unknown);
    }
    publish_checkpoint(&mut fact, "opening_pidfd", started, &tx);
    let pid = match &scope.main {
        ProcessIdentity::Linux { pid, .. } => *pid,
    };
    let pid = Pid::from_raw(i32::try_from(pid).map_err(conflict)?).ok_or(LegacyError::Invalid)?;
    let pidfd = pidfd_open(pid, PidfdFlags::empty()).map_err(unavailable)?;
    // PID-fd acquired between two original birth checks. No signal by raw PID.
    if !scope.main.still_current().map_err(unknown)? {
        return Err(LegacyError::Conflict);
    }
    let before = observe_original(&scope).await?;
    if before.original_main_exited || cancel.is_cancelled() || Instant::now() >= deadline {
        return Err(LegacyError::Unknown);
    }
    publish_checkpoint(&mut fact, "signalling_original", started, &tx);
    fact.term_attempted = true;
    fact.signal_accepted = pidfd_send_signal(&pidfd, Signal::TERM).is_ok();
    fact.phase = if fact.signal_accepted {
        SettlementPhase::Stopping
    } else {
        SettlementPhase::Unknown
    };
    tx.send_replace(fact);
    if !fact.signal_accepted {
        return Err(LegacyError::Unknown);
    }
    // Exactly one signal. Unknown is sticky: no automatic reconciliation or
    // replay; the original record/fence/capacity remains retained for original-ID
    // management recovery. Stopping is only the bounded live observation phase.
    publish_checkpoint(&mut fact, "waiting_original_exit", started, &tx);
    loop {
        if Instant::now() >= deadline || cancel.is_cancelled() {
            return Err(LegacyError::Unknown);
        }
        let observed = observe_original(&scope).await?;
        fact.original_main_exited = observed.original_main_exited;
        fact.original_cgroup_empty = observed.original_cgroup_empty;
        fact.manager_reported_success = observed.manager_reported_success;
        if Instant::now() >= deadline || cancel.is_cancelled() {
            fact.phase = SettlementPhase::Unknown;
            tx.send_replace(fact);
            return Err(LegacyError::Unknown);
        }
        if observed.confirmed() {
            publish_checkpoint(&mut fact, "verifying_settled_inputs", started, &tx);
            let check = scope.clone();
            legacy_blocking(move || {
                check.inputs.verify_fence(&check.fence)?;
                check.inputs.revalidate_after_settlement()
            })
            .await?;
            if Instant::now() >= deadline || cancel.is_cancelled() {
                fact.phase = SettlementPhase::Unknown;
                tx.send_replace(fact);
                return Err(LegacyError::Unknown);
            }
            fact.phase = SettlementPhase::Confirmed;
            publish_checkpoint(&mut fact, "confirmed", started, &tx);
            return Ok(());
        }
        tx.send_replace(fact);
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}
struct OriginalObservation {
    original_main_exited: bool,
    original_cgroup_empty: bool,
    manager_reported_success: bool,
}
impl OriginalObservation {
    fn confirmed(&self) -> bool {
        self.original_main_exited && self.original_cgroup_empty && self.manager_reported_success
    }
}
async fn observe_original(scope: &Arc<LegacyManagedScope>) -> LegacyResult<OriginalObservation> {
    let bus = zbus::fdo::DBusProxy::new(&scope.connection)
        .await
        .map_err(unknown)?;
    if bus
        .get_name_owner("org.freedesktop.systemd1".try_into().map_err(conflict)?)
        .await
        .map_err(unknown)?
        .as_str()
        != scope.manager_owner
        || !scope.manager_birth.still_current().map_err(unknown)?
    {
        return Err(LegacyError::Conflict);
    }
    let unit = live_proxy(
        &scope.connection,
        scope.manager_owner.as_str(),
        scope.unit_object.as_str(),
        "org.freedesktop.systemd1.Unit",
    )
    .await
    .map_err(unknown)?;
    let service = live_proxy(
        &scope.connection,
        scope.manager_owner.as_str(),
        scope.unit_object.as_str(),
        "org.freedesktop.systemd1.Service",
    )
    .await
    .map_err(unknown)?;
    let invocation: Vec<u8> = unit.get_property("InvocationID").await.map_err(unknown)?;
    let current_cgroup = property_string(&service, "ControlGroup").await?;
    if invocation.len() != 16
        || invocation
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
            != scope.invocation
        || (!current_cgroup.is_empty() && current_cgroup != scope.cgroup_path)
    {
        return Err(LegacyError::Conflict);
    }
    let dropins: Vec<String> = unit.get_property("DropInPaths").await.map_err(unknown)?;
    let reload: bool = unit
        .get_property("NeedDaemonReload")
        .await
        .map_err(unknown)?;
    if !dropins.is_empty()
        || reload
        || property_string(&unit, "FragmentPath").await?
            != scope
                .inputs
                .unit_file()
                .to_str()
                .ok_or(LegacyError::Invalid)?
    {
        return Err(LegacyError::Conflict);
    }
    let pid: u32 = service.get_property("MainPID").await.map_err(unknown)?;
    let original_pid = match &scope.main {
        ProcessIdentity::Linux { pid, .. } => *pid,
    };
    let exec_pid: u32 = service.get_property("ExecMainPID").await.map_err(unknown)?;
    if (pid != 0 && pid != original_pid) || exec_pid != original_pid {
        return Err(LegacyError::Conflict);
    }
    let active = property_string(&unit, "ActiveState").await?;
    if current_cgroup.is_empty() && (pid != 0 || active != "inactive") {
        return Err(LegacyError::Conflict);
    }
    let result = property_string(&service, "Result").await?;
    let code: i32 = service
        .get_property("ExecMainCode")
        .await
        .map_err(unknown)?;
    let status: i32 = service
        .get_property("ExecMainStatus")
        .await
        .map_err(unknown)?;
    let source = scope.clone();
    let (original_main_exited, original_cgroup_empty) = legacy_blocking(move || {
        source.inputs.verify_fence(&source.fence)?;
        let exited = !source.main.still_current().map_err(unknown)?;
        if !exited {
            require_process_cgroup(original_pid, &source.cgroup_path, &source.cgroup_stat)?;
            check_live_image(&source)?;
        }
        let held = stat(&source.cgroup)?;
        let empty = if held.nlink == 0 {
            // Original held directory was removed. A replacement pathname never
            // becomes the old scope, even if a new unit uses the same name.
            true
        } else {
            let current = open_checked(
                &Path::new("/sys/fs/cgroup").join(source.cgroup_path.trim_start_matches('/')),
                true,
            )?;
            let current = stat(&current)?;
            if current.dev != source.cgroup_stat.dev || current.ino != source.cgroup_stat.ino {
                return Err(LegacyError::Conflict);
            }
            cgroup_empty(&source.events)?
        };
        Ok((exited, empty))
    })
    .await?;
    Ok(OriginalObservation {
        original_main_exited,
        original_cgroup_empty,
        manager_reported_success: pid == 0
            && active == "inactive"
            && result == "success"
            && code == 1
            && status == 0,
    })
}
fn check_live_image(scope: &LegacyManagedScope) -> LegacyResult<()> {
    let pid = match &scope.main {
        ProcessIdentity::Linux { pid, .. } => *pid,
    };
    let current = File::open(format!("/proc/{pid}/exe")).map_err(unknown)?;
    if stat(&current)? != scope.main_image_stat || stat(&scope.main_image)? != scope.main_image_stat
    {
        return Err(LegacyError::Conflict);
    }
    let expected = scope.inputs.argv();
    let mut file = File::open(format!("/proc/{pid}/cmdline")).map_err(unknown)?;
    let raw = read_file(&mut file, 16 * 1024)?;
    if raw
        .split(|v| *v == 0)
        .filter(|v| !v.is_empty())
        .collect::<Vec<_>>()
        != expected.iter().map(|v| v.as_bytes()).collect::<Vec<_>>()
        || !scope.main.still_current().map_err(unknown)?
    {
        return Err(LegacyError::Conflict);
    }
    Ok(())
}
fn cgroup_empty(events: &File) -> LegacyResult<bool> {
    use std::os::unix::fs::FileExt as _;
    let mut bytes = [0u8; 4096];
    let n = events.read_at(&mut bytes, 0).map_err(unknown)?;
    if n == bytes.len() {
        return Err(LegacyError::Unknown);
    }
    parse_cgroup_empty(&bytes[..n])
}
fn parse_cgroup_empty(bytes: &[u8]) -> LegacyResult<bool> {
    let text = std::str::from_utf8(bytes).map_err(unknown)?;
    let mut populated = None;
    for line in text.lines() {
        let (key, value) = line.split_once(' ').ok_or(LegacyError::Unknown)?;
        if key == "populated" {
            if populated.is_some() {
                return Err(LegacyError::Unknown);
            }
            populated = Some(match value {
                "0" => false,
                "1" => true,
                _ => return Err(LegacyError::Unknown),
            });
        }
    }
    populated.map(|v| !v).ok_or(LegacyError::Unknown)
}
#[cfg(test)]
#[path = "legacy_tests.rs"]
mod tests;
