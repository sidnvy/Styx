//! Existing-UID system launchd adapter. Registration material is DATA only:
//! this module never writes /Library, invokes sudo, creates an account or changes
//! canonical state. The consumer owns the original C07/operation serialization.
//! launchctl output is a bounded OS observation, not a job or cleanup receipt.
use crate::{
    release::{self, VerifiedNativeRelease},
    store::{self, PrivateRoot, ProcessIdentity, RootIdentity, native_state},
};
use core_foundation::url::CFURL;
use nix::{
    fcntl::{OFlag, open, openat},
    sys::stat::Mode,
    unistd::{Uid, User},
};
use security_framework::os::macos::code_signing::{
    Flags, GuestAttributes, SecCode, SecRequirement, SecStaticCode,
};
use serde::Serialize;
use std::{
    fs::File,
    os::{
        fd::AsFd,
        unix::fs::{FileExt, MetadataExt},
    },
    path::{Component, Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};
use styx_contracts::{
    identity::Sha256Digest,
    native_management::{
        NativeComponentDesired, NativeManager, NativeRunDesired, NativeRuntimeSelection,
    },
};
use tokio::{
    io::AsyncReadExt,
    process::Command,
    sync::{Semaphore, oneshot},
};

const LIMIT: usize = 64 * 1024;
const LAUNCHCTL: &str = "/bin/launchctl";
const PLIST_PARENT: &str = "/Library/LaunchDaemons";
// Darwin sockaddr_un is shorter than Linux's. Keep the endpoint in the same
// original private state root, with unchanged peer and protocol authentication.
pub(crate) const CONTROL_SOCKET_NAME: &str = ".styx.sock";
static TOOLS: Semaphore = Semaphore::const_new(2);
// Separate from TOOLS: a utility may retain its tool permit while waiting for a
// checked read, so sharing that semaphore would permit a self-deadlock.
static READERS: Semaphore = Semaphore::const_new(2);
/// Bounded synchronous observation only. A dropped async waiter never aborts
/// the original blocking job: its captured Arc(s) and permit survive until the
/// closure actually completes. Callers cannot return borrowed material.
pub(crate) async fn blocking_read<T: Send + 'static>(
    read: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    let permit = READERS.try_acquire().map_err(|_| ServiceError::Busy)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        read()
    })
    .await
    .map_err(unknown)?
}
async fn process_is_current(birth: ProcessIdentity) -> Result<bool> {
    blocking_read(move || birth.still_current().map_err(unknown)).await
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ServiceRole {
    Host,
    Gateway,
}
impl ServiceRole {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Gateway => "gateway",
        }
    }
    pub(crate) fn desired(
        self,
        s: &styx_contracts::native_management::NativeState,
    ) -> Option<NativeComponentDesired> {
        match self {
            Self::Host => s.desired.host,
            Self::Gateway => s.desired.gateway,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ServiceError {
    #[error("invalid native system service input")]
    Invalid,
    #[error("native system service identity changed")]
    Conflict,
    #[error("native system service unavailable or registration not authorized")]
    Unavailable,
    #[error("native system service operation capacity reached")]
    Busy,
    #[error("native system service operation or observation unknown")]
    Unknown,
}
type Result<T> = std::result::Result<T, ServiceError>;
fn changed<T>(_: T) -> ServiceError {
    ServiceError::Conflict
}
fn unknown<T>(_: T) -> ServiceError {
    ServiceError::Unknown
}
fn unavailable<T>(_: T) -> ServiceError {
    ServiceError::Unavailable
}
fn path_text(path: &Path) -> Result<&str> {
    let v = path.to_str().ok_or(ServiceError::Invalid)?;
    if !path.is_absolute()
        || v.len() > 4096
        || v.bytes().any(|b| b < 32 || b == 127)
        || v.contains("//")
        || v.contains("/./")
        || v.ends_with("/.")
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(ServiceError::Invalid);
    }
    Ok(v)
}
fn validate_control_path(state_dir: &Path) -> Result<()> {
    nix::sys::socket::UnixAddr::new(&state_dir.join(CONTROL_SOCKET_NAME))
        .map(|_| ())
        .map_err(|_| ServiceError::Invalid)
}
fn xml(v: &str) -> String {
    v.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Stamp {
    dev: u64,
    ino: u64,
    uid: u32,
    mode: u32,
    links: u64,
    len: u64,
    seconds: i64,
    nanos: i64,
}
fn stamp(file: &File, directory: bool, uid: u32) -> Result<Stamp> {
    let m = file.metadata().map_err(unknown)?;
    if (if directory {
        !m.is_dir()
    } else {
        !m.is_file() || m.nlink() != 1
    }) || m.uid() != uid
        || m.mode() & 0o022 != 0
    {
        return Err(ServiceError::Conflict);
    }
    store::macos_service_require_empty_acl(file).map_err(changed)?;
    Ok(Stamp {
        dev: m.dev(),
        ino: m.ino(),
        uid: m.uid(),
        mode: m.mode(),
        links: m.nlink(),
        len: m.len(),
        seconds: m.ctime(),
        nanos: m.ctime_nsec(),
    })
}
fn read_exact(file: &File, max: usize) -> Result<Vec<u8>> {
    let before = stamp(file, false, 0)?;
    if before.len > max as u64 {
        return Err(ServiceError::Conflict);
    }
    let mut raw = vec![0; before.len as usize];
    file.read_exact_at(&mut raw, 0).map_err(unknown)?;
    if stamp(file, false, 0)? != before {
        return Err(ServiceError::Conflict);
    }
    Ok(raw)
}
struct DirectoryPin {
    file: File,
    path: PathBuf,
    original: (u64, u64),
}
impl DirectoryPin {
    fn open(path: &Path) -> Result<Self> {
        path_text(path)?;
        let mut fd = open(
            "/",
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(unavailable)?;
        stamp(&File::from(fd.try_clone().map_err(unknown)?), true, 0)?;
        for part in path.components().filter_map(|c| {
            if let Component::Normal(p) = c {
                Some(p)
            } else {
                None
            }
        }) {
            fd = openat(
                fd.as_fd(),
                Path::new(part),
                OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(unavailable)?;
            stamp(&File::from(fd.try_clone().map_err(unknown)?), true, 0)?;
        }
        let file = File::from(fd);
        let st = stamp(&file, true, 0)?;
        Ok(Self {
            file,
            path: path.into(),
            original: (st.dev, st.ino),
        })
    }
    fn validate(&self) -> Result<()> {
        let original = stamp(&self.file, true, 0)?;
        let current = Self::open(&self.path)?;
        if (original.dev, original.ino) != self.original || current.original != self.original {
            return Err(ServiceError::Conflict);
        }
        Ok(())
    }
}
struct DefinitionPin {
    file: File,
    stamp: Stamp,
    raw: Vec<u8>,
}
impl DefinitionPin {
    fn open(parent: &DirectoryPin, name: &str) -> Result<Option<Self>> {
        parent.validate()?;
        let fd = match openat(
            parent.file.as_fd(),
            name,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(nix::errno::Errno::ENOENT) => return Ok(None),
            Err(e) => return Err(unavailable(e)),
        };
        let file = File::from(fd);
        let st = stamp(&file, false, 0)?;
        let raw = read_exact(&file, LIMIT)?;
        if stamp(&file, false, 0)? != st {
            return Err(ServiceError::Conflict);
        }
        parent.validate()?;
        Ok(Some(Self {
            file,
            stamp: st,
            raw,
        }))
    }
    fn validate(&self, parent: &DirectoryPin, name: &str) -> Result<()> {
        let now = Self::open(parent, name)?.ok_or(ServiceError::Conflict)?;
        if stamp(&self.file, false, 0)? != self.stamp
            || read_exact(&self.file, LIMIT)? != self.raw
            || now.stamp != self.stamp
            || now.raw != self.raw
        {
            return Err(ServiceError::Conflict);
        }
        Ok(())
    }
}
/// Original protected root and signed selection are retained for the entire
/// instance. Not Clone/Deserialize; installation cannot mint service authority.
pub(crate) struct Definition {
    root: PrivateRoot,
    root_identity: RootIdentity,
    path: PathBuf,
    role: ServiceRole,
    selection: NativeRuntimeSelection,
    candidate: Arc<VerifiedNativeRelease>,
    cdhash: Vec<u8>,
    uid: u32,
    username: String,
    home: PathBuf,
    executable: PathBuf,
    label: String,
    parent: DirectoryPin,
    filename: String,
    expected: Vec<u8>,
    pin: Option<DefinitionPin>,
    tool: File,
    tool_stamp: Stamp,
    stop: std::sync::Mutex<Option<RunningRecord>>,
    install_preparation: bool,
}
/// Borrowed fixed installation DATA for an explicitly authorized one-shot
/// administrator installer. It grants neither write access nor C07 authority.
pub(crate) struct InstallationMaterial<'a> {
    pub(crate) path: PathBuf,
    pub(crate) bytes: &'a [u8],
    pub(crate) uid: u32,
    pub(crate) label: &'a str,
    pub(crate) requires_initial_disabled: bool,
}
/// Original registered job observed inactive after a known failed generation.
/// This is not a live ServiceScope, administrator grant, or cleanup receipt.
/// Consumers retain it with the original C07 writer/operation/execution leases.
/// It cannot be reconstructed from a report or a caller-provided pathname.
pub(crate) struct RegisteredInactiveProof {
    definition: Arc<Definition>,
    observation: ServiceObservation,
    initial_state: store::RawFile,
    fenced: std::sync::atomic::AtomicBool,
}
impl RegisteredInactiveProof {
    pub(crate) fn original_definition(&self) -> &Arc<Definition> {
        &self.definition
    }
    pub(crate) fn observation(&self) -> &ServiceObservation {
        &self.observation
    }
    /// Original canonical bytes AND file identity, for the consumer's exact
    /// expected-revision/transaction comparison before any C07 publication.
    pub(crate) fn initial_state(&self) -> &store::RawFile {
        &self.initial_state
    }
    /// Fixed installer DATA only. Caller holds the original C07 writer,
    /// operation and execution exclusions and asynchronously revalidates the
    /// failed registration before/after this bounded blocking observation.
    pub(crate) fn repair_request(
        &self,
        candidate: &VerifiedNativeRelease,
        id: &styx_contracts::identity::TransactionId,
        revision: u64,
        canonical: &Sha256Digest,
    ) -> Result<serde_json::Value> {
        use std::sync::atomic::Ordering;
        if self.fenced.load(Ordering::Acquire) {
            return Err(ServiceError::Unknown);
        }
        let old = &self.definition;
        old.validate_identity()?;
        let pin = old.pin.as_ref().ok_or(ServiceError::Conflict)?;
        let marker_raw = old
            .root
            .read_raw(".styx-native-root-v1.json", 4096)
            .map_err(changed)?;
        let marker = native_state::decode_marker(marker_raw.bytes()).map_err(changed)?;
        let raw = old
            .root
            .read_raw("state.json", 1024 * 1024)
            .map_err(changed)?;
        let state = native_state::decode_state(raw.bytes(), &marker).map_err(changed)?;
        let current = crate::store::native_host_snapshot::validated_runtime_selection(
            &old.root, &state, &marker,
        )
        .map_err(changed)?;
        let selected = candidate.runtime_selection().map_err(changed)?;
        let value = state.state();
        let update = value
            .runtime_update()
            .map_err(changed)?
            .ok_or(ServiceError::Conflict)?;
        if old.role != ServiceRole::Gateway
            || value.mode != styx_contracts::native_management::NativeDeploymentMode::CreateLocal
            || value.desired.host.is_some()
            || value.has_migration_binding()
            || value.desired.gateway
                != Some(NativeComponentDesired {
                    manager: NativeManager::PersistentService,
                    run: NativeRunDesired::Running,
                    autostart: styx_contracts::native_management::NativeAutostartDesired::Enabled,
                })
            || value.reader_contract
                != styx_contracts::management::ReaderContract::NativeServiceRuntimeSelectedStateV1
            || value.schema != 5
            || value.revision != revision
            || value
                .last_transaction
                .as_ref()
                .is_none_or(|tx| &tx.transaction_id != id || *tx != update.transaction)
            || update.previous_runtime != old.selection
            || selected != current
            || selected == old.selection
            || selected.publisher_spki_sha256 != old.selection.publisher_spki_sha256
            || candidate.report().target != old.candidate.report().target
            || Sha256Digest::of_bytes(raw.bytes()) != *canonical
            || !candidate
                .supports_state_reader(value.reader_contract)
                .map_err(changed)?
        {
            return Err(ServiceError::Conflict);
        }
        let executable = Path::new(&selected.payload_path).join(candidate.report().entrypoint);
        path_text(&executable)?;
        if executable
            .components()
            .any(|part| part.as_os_str().to_string_lossy().ends_with(".app"))
        {
            return Err(ServiceError::Invalid);
        }
        let bytes = definition_bytes(
            &old.label,
            &old.username,
            &old.home,
            &executable,
            &old.path,
            ServiceRole::Gateway,
        )?;
        let member = candidate
            .manifest()
            .files
            .iter()
            .find(|member| member.path == candidate.manifest().entrypoint && member.executable)
            .ok_or(ServiceError::Conflict)?;
        let RootIdentity::Macos { device, inode, uid } = old.root_identity else {
            return Err(ServiceError::Conflict);
        };
        let request = serde_json::json!({"schema":1,"kind":"launchd_failed_registration_repair",
            "uid":old.uid,"username":old.username,"role":"gateway",
            "state_dir":old.path,"state_root":{"device":device,"inode":inode,"uid":uid},
            "canonical_sha256":canonical,"transaction_id":id,"revision":revision,
            "definition_path":Path::new(PLIST_PARENT).join(&old.filename),
            "definition_plist":std::str::from_utf8(&bytes).map_err(unknown)?,
            "definition_sha256":Sha256Digest::of_bytes(&bytes),"label":old.label,
            "executable_path":executable,"executable_sha256":member.sha256,"runtime_selection":selected,
            "old_definition_sha256":Sha256Digest::of_bytes(&pin.raw),
            "old_definition_identity":{"device":pin.stamp.dev,"inode":pin.stamp.ino,
                "uid":pin.stamp.uid,"mode":pin.stamp.mode & 0o7777,"links":pin.stamp.links},
            "old_runtime_selection":old.selection,"original_registration":self.observation});
        // No executable Definition(B) is minted while installed Definition(A)
        // still exists. Recheck both original authorities after reading DATA.
        candidate.revalidate().map_err(changed)?;
        old.validate_identity()?;
        let after = old
            .root
            .read_raw("state.json", 1024 * 1024)
            .map_err(changed)?;
        if after.observation() != raw.observation()
            || after.bytes() != raw.bytes()
            || self.fenced.load(Ordering::Acquire)
        {
            return Err(ServiceError::Unknown);
        }
        Ok(request)
    }
    /// Synchronous full original-material check: call only on an owned bounded
    /// blocking job. This does not refresh launchd state. The async consumer
    /// must also revalidate before/after C07 under its original exclusion leases.
    pub(crate) fn validate_owner(&self, owner: &store::OwnedConfigurationRoot) -> Result<()> {
        use std::sync::atomic::Ordering;
        let result: Result<()> = (|| {
            if self.fenced.load(Ordering::Acquire)
                || owner.identity().map_err(unknown)? != self.definition.root_identity
            {
                return Err(ServiceError::Unknown);
            }
            self.definition.validate_identity()?;
            Ok(())
        })();
        if result.is_err() {
            self.fenced.store(true, Ordering::Release);
            return Err(ServiceError::Unknown);
        }
        Ok(())
    }
    /// Original registration only: a legitimate same-writer C07 selection
    /// successor does not rebind this proof to a replacement plist or image.
    /// Two stable observations are bounded evidence, never an atomic OS lock.
    pub(crate) async fn revalidate(self: &Arc<Self>) -> Result<()> {
        use std::sync::atomic::Ordering;
        if self.fenced.load(Ordering::Acquire) {
            return Err(ServiceError::Unknown);
        }
        let result: Result<()> = async {
            let first = self.definition.inspect_registered_identity().await?;
            if !same_failed_inactive(&self.observation, &first) {
                return Err(ServiceError::Unknown);
            }
            let second = self.definition.inspect_registered_identity().await?;
            if !same_failed_inactive(&first, &second) {
                return Err(ServiceError::Unknown);
            }
            Ok(())
        }
        .await;
        if result.is_err() {
            // Keep the original Arc/pins; a later quiet observation cannot
            // restore a proof that already observed a restart or replacement.
            self.fenced.store(true, Ordering::Release);
            return Err(ServiceError::Unknown);
        }
        Ok(())
    }
}
fn failed_inactive(observed: &ServiceObservation) -> bool {
    observed.pid.is_none()
        && observed.runs > 0
        && observed.state == "not running"
        && (observed.signaled_exit || observed.last_exit_code.is_some_and(|code| code != 0))
}
fn same_failed_inactive(original: &ServiceObservation, current: &ServiceObservation) -> bool {
    failed_inactive(original) && failed_inactive(current) && original == current
}

impl Definition {
    pub(crate) fn prepare(path: &Path, role: ServiceRole) -> Result<Self> {
        Self::prepare_owned(path, role, false)
    }
    /// Derive future fixed installation DATA only; never a runtime scope.
    pub(crate) fn prepare_install(path: &Path) -> Result<Self> {
        Self::prepare_owned(path, ServiceRole::Gateway, true)
    }
    fn prepare_owned(path: &Path, role: ServiceRole, install_preparation: bool) -> Result<Self> {
        path_text(path)?;
        // Reject an unusable native endpoint before preparing C07 or an
        // administrator package, rather than failing after system registration.
        validate_control_path(path)?;
        let root = PrivateRoot::open(path).map_err(unavailable)?;
        let RootIdentity::Macos { device, inode, uid } = root.identity() else {
            return Err(ServiceError::Invalid);
        };
        if uid == 0 || uid != Uid::current().as_raw() {
            return Err(ServiceError::Conflict);
        }
        let marker = root
            .read_raw(".styx-native-root-v1.json", 4096)
            .map_err(changed)?;
        let marker = native_state::decode_marker(marker.bytes()).map_err(changed)?;
        let raw = root.read_raw("state.json", 1024 * 1024).map_err(changed)?;
        let state = native_state::decode_state(raw.bytes(), &marker).map_err(changed)?;
        let deployment = root
            .read_raw("deployment.json", 1024 * 1024)
            .map_err(changed)?;
        if Sha256Digest::of_bytes(deployment.bytes()) != state.state().deployment_raw_sha256 {
            return Err(ServiceError::Conflict);
        }
        let desired = role.desired(state.state()).ok_or(ServiceError::Invalid)?;
        if state.state().has_migration_binding()
            || if install_preparation {
                role != ServiceRole::Gateway
                    || state.state().mode
                        != styx_contracts::native_management::NativeDeploymentMode::CreateLocal
                    || state.state().desired.host.is_some()
                    || desired.manager != NativeManager::ForegroundCli
                    || desired.run != NativeRunDesired::Stopped
                    || desired.autostart
                        != styx_contracts::native_management::NativeAutostartDesired::Disabled
            } else {
                desired.manager != NativeManager::PersistentService
            }
        {
            return Err(ServiceError::Conflict);
        }
        let selection =
            crate::store::native_host_snapshot::validated_runtime_selection(&root, &state, &marker)
                .map_err(changed)?;
        let candidate = Arc::new(release::verify_selected(&selection).map_err(changed)?);
        let report = candidate.report();
        if report.target != format!("{}-apple-darwin", std::env::consts::ARCH) {
            return Err(ServiceError::Conflict);
        }
        let executable = Path::new(&selection.payload_path).join(report.entrypoint);
        path_text(&executable)?;
        // Never register a payload that this App installer is about to rename.
        if executable
            .components()
            .any(|p| p.as_os_str().to_string_lossy().ends_with(".app"))
        {
            return Err(ServiceError::Invalid);
        }
        let cdhash = candidate.macos_executable_cdhash().map_err(changed)?;
        let user = User::from_uid(Uid::from_raw(uid))
            .map_err(unavailable)?
            .ok_or(ServiceError::Unavailable)?;
        if user.name.is_empty()
            || !user
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(ServiceError::Invalid);
        }
        path_text(&user.dir)?;
        let hash = Sha256Digest::of_bytes(
            format!("styx-native-system-service-v1:{device}:{inode}:{uid}").as_bytes(),
        )
        .to_hex();
        let label = format!("app.styx.native.{uid}.{}.{}", &hash[..32], role.name());
        let filename = format!("{label}.plist");
        let expected = definition_bytes(&label, &user.name, &user.dir, &executable, path, role)?;
        let parent = DirectoryPin::open(Path::new(PLIST_PARENT))?;
        let pin = DefinitionPin::open(&parent, &filename)?;
        if (install_preparation && pin.is_some()) || pin.as_ref().is_some_and(|p| p.raw != expected)
        {
            return Err(ServiceError::Conflict);
        }
        let fd = open(
            LAUNCHCTL,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(unavailable)?;
        let tool = File::from(fd);
        let tool_stamp = stamp(&tool, false, 0)?;
        let url = CFURL::from_path(LAUNCHCTL, false).ok_or(ServiceError::Unavailable)?;
        let code = SecStaticCode::from_path(&url, Flags::NONE).map_err(unavailable)?;
        let apple: SecRequirement = "anchor apple".parse().map_err(unavailable)?;
        code.check_validity(Flags::STRICT_VALIDATE | Flags::NO_NETWORK_ACCESS, &apple)
            .map_err(unavailable)?;
        let result = Self {
            root,
            root_identity: RootIdentity::Macos { device, inode, uid },
            path: path.into(),
            role,
            selection,
            candidate,
            cdhash,
            uid,
            username: user.name,
            home: user.dir,
            executable,
            label,
            parent,
            filename,
            expected,
            pin,
            tool,
            tool_stamp,
            stop: std::sync::Mutex::new(None),
            install_preparation,
        };
        result.validate()?;
        Ok(result)
    }
    pub(crate) fn installation_material(&self) -> Result<InstallationMaterial<'_>> {
        self.validate()?;
        Ok(InstallationMaterial {
            path: Path::new(PLIST_PARENT).join(&self.filename),
            bytes: &self.expected,
            uid: self.uid,
            label: &self.label,
            requires_initial_disabled: true,
        })
    }
    /// Call only after an independent authorized installer completed. This
    /// adopts exactly our bytes/root-owned file, never repairs a partial file.
    pub(crate) fn bind_installed(&mut self) -> Result<()> {
        if self.install_preparation {
            return Err(ServiceError::Invalid);
        }
        if self.pin.is_some() {
            return self.validate();
        }
        self.validate_identity()?;
        let p =
            DefinitionPin::open(&self.parent, &self.filename)?.ok_or(ServiceError::Unavailable)?;
        if p.raw != self.expected {
            return Err(ServiceError::Conflict);
        }
        self.pin = Some(p);
        self.validate()
    }
    pub(crate) fn validate_identity(&self) -> Result<()> {
        let current = PrivateRoot::open(&self.path).map_err(changed)?;
        if current.identity() != self.root_identity || self.root.identity() != self.root_identity {
            return Err(ServiceError::Conflict);
        }
        self.root.revalidate_runtime_directory().map_err(changed)?;
        self.candidate.revalidate().map_err(changed)?;
        let user = User::from_uid(Uid::from_raw(self.uid))
            .map_err(unavailable)?
            .ok_or(ServiceError::Unavailable)?;
        if user.name != self.username
            || user.dir != self.home
            || stamp(&self.tool, false, 0)? != self.tool_stamp
        {
            return Err(ServiceError::Conflict);
        }
        let fd = open(
            LAUNCHCTL,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(unavailable)?;
        if stamp(&File::from(fd), false, 0)? != self.tool_stamp {
            return Err(ServiceError::Conflict);
        }
        self.parent.validate()?;
        if let Some(pin) = &self.pin {
            pin.validate(&self.parent, &self.filename)?;
        }
        Ok(())
    }
    pub(crate) fn validate(&self) -> Result<()> {
        self.validate_identity()?;
        let marker = self
            .root
            .read_raw(".styx-native-root-v1.json", 4096)
            .map_err(changed)?;
        let marker = native_state::decode_marker(marker.bytes()).map_err(changed)?;
        let raw = self
            .root
            .read_raw("state.json", 1024 * 1024)
            .map_err(changed)?;
        let state = native_state::decode_state(raw.bytes(), &marker).map_err(changed)?;
        let deployment = self
            .root
            .read_raw("deployment.json", 1024 * 1024)
            .map_err(changed)?;
        if Sha256Digest::of_bytes(deployment.bytes()) != state.state().deployment_raw_sha256 {
            return Err(ServiceError::Conflict);
        }
        let desired = self
            .role
            .desired(state.state())
            .ok_or(ServiceError::Conflict)?;
        let selected = crate::store::native_host_snapshot::validated_runtime_selection(
            &self.root, &state, &marker,
        )
        .map_err(changed)?;
        let manager_matches = if self.install_preparation {
            self.role == ServiceRole::Gateway
                && state.state().mode
                    == styx_contracts::native_management::NativeDeploymentMode::CreateLocal
                && state.state().desired.host.is_none()
                && !state.state().has_migration_binding()
                && desired.manager == NativeManager::ForegroundCli
                && desired.run == NativeRunDesired::Stopped
                && desired.autostart
                    == styx_contracts::native_management::NativeAutostartDesired::Disabled
        } else {
            desired.manager == NativeManager::PersistentService
        };
        if !manager_matches || selected != self.selection {
            return Err(ServiceError::Conflict);
        }
        Ok(())
    }
    /// Read-only canonical observation. This does not reconcile a journal or
    /// grant installation/manager authority.
    pub(crate) fn state(&self) -> Result<styx_contracts::native_management::NativeState> {
        self.state_observation().map(|(state, _)| state)
    }
    /// Complete readonly C07 validation plus the original canonical bytes' hash.
    pub(crate) fn state_observation(
        &self,
    ) -> Result<(styx_contracts::native_management::NativeState, Sha256Digest)> {
        self.validate()?;
        let marker = self
            .root
            .read_raw(".styx-native-root-v1.json", 4096)
            .map_err(changed)?;
        let marker = native_state::decode_marker(marker.bytes()).map_err(changed)?;
        let raw = self
            .root
            .read_raw("state.json", 1024 * 1024)
            .map_err(changed)?;
        let state = native_state::decode_state(raw.bytes(), &marker).map_err(changed)?;
        let selected = crate::store::native_host_snapshot::validated_runtime_selection(
            &self.root, &state, &marker,
        )
        .map_err(changed)?;
        if selected != self.selection
            || self.role.desired(state.state()).is_none_or(|d| {
                d.manager
                    != if self.install_preparation {
                        NativeManager::ForegroundCli
                    } else {
                        NativeManager::PersistentService
                    }
            })
        {
            return Err(ServiceError::Conflict);
        }
        self.validate()?;
        Ok((state.state().clone(), Sha256Digest::of_bytes(raw.bytes())))
    }
    /// Same original root/candidate/definition after our explicitly committed
    /// configuration transition. No installed object is adopted here.
    pub(crate) fn reopen_after_preparation(&self) -> Result<Self> {
        self.validate_identity()?;
        let next = Self::prepare(&self.path, self.role)?;
        if next.root_identity != self.root_identity
            || next.selection != self.selection
            || next.expected != self.expected
            || next.pin.is_some()
        {
            return Err(ServiceError::Conflict);
        }
        Ok(next)
    }
    pub(crate) fn require_pending_registration(&self) -> Result<()> {
        self.validate()?;
        if self.pin.is_some() {
            return Err(ServiceError::Conflict);
        }
        Ok(())
    }
    /// Profile-bound DATA for an independently authorized administrator package.
    /// It neither registers a job nor supplies any configuration-writer authority.
    pub(crate) fn first_start_request(
        &self,
        id: &styx_contracts::identity::TransactionId,
        revision: u64,
        canonical: &Sha256Digest,
    ) -> Result<serde_json::Value> {
        self.require_pending_registration()?;
        let (state, hash) = self.state_observation()?;
        let gateway = state.desired.gateway.ok_or(ServiceError::Conflict)?;
        if self.install_preparation
            || self.role != ServiceRole::Gateway
            || state.mode != styx_contracts::native_management::NativeDeploymentMode::CreateLocal
            || state.desired.host.is_some()
            || state.has_migration_binding()
            || gateway.manager != NativeManager::PersistentService
            || gateway.run != NativeRunDesired::Running
            || gateway.autostart
                != styx_contracts::native_management::NativeAutostartDesired::Enabled
            || state.revision != revision
            || &hash != canonical
            || state
                .last_transaction
                .as_ref()
                .is_none_or(|tx| &tx.transaction_id != id)
        {
            return Err(ServiceError::Conflict);
        }
        let RootIdentity::Macos { device, inode, uid } = self.root_identity else {
            return Err(ServiceError::Conflict);
        };
        let manifest = self.candidate.manifest();
        let executable = manifest
            .files
            .iter()
            .find(|entry| entry.path == manifest.entrypoint && entry.executable)
            .ok_or(ServiceError::Conflict)?;
        let material = self.installation_material()?;
        let request = serde_json::json!({"schema":1,"kind":"launchd_first_start",
            "uid":self.uid,"username":self.username,"role":"gateway",
            "state_dir":self.path,"state_root":{"device":device,"inode":inode,"uid":uid},
            "canonical_sha256":canonical,"transaction_id":id,"revision":revision,
            "definition_path":material.path,"definition_plist":std::str::from_utf8(material.bytes).map_err(unknown)?,
            "definition_sha256":Sha256Digest::of_bytes(material.bytes),"label":self.label,
            "executable_path":self.executable,"executable_sha256":executable.sha256,
            "runtime_selection":self.selection});
        self.validate()?;
        Ok(request)
    }
    pub(crate) fn runtime_selection(&self) -> Result<&NativeRuntimeSelection> {
        self.validate()?;
        Ok(&self.selection)
    }
    pub(crate) fn state_dir(&self) -> &Path {
        &self.path
    }
    pub(crate) fn role(&self) -> ServiceRole {
        self.role
    }
    fn target(&self) -> String {
        format!("system/{}", self.label)
    }
    pub(crate) async fn inspect(self: &Arc<Self>) -> Result<ServiceObservation> {
        self.inspect_registered(true).await
    }
    async fn inspect_registered_identity(self: &Arc<Self>) -> Result<ServiceObservation> {
        self.inspect_registered(false).await
    }
    async fn inspect_registered(self: &Arc<Self>, full_state: bool) -> Result<ServiceObservation> {
        let checked = self.clone();
        blocking_read(move || {
            if full_state {
                checked.validate()
            } else {
                checked.validate_identity()
            }
        })
        .await?;
        if self.pin.is_none() {
            return Err(ServiceError::Unavailable);
        }
        let output = tool(self.clone(), vec!["print".into(), self.target()], false).await?;
        let observed = parse_print(&output, &self.label)?;
        if observed.path != Path::new(PLIST_PARENT).join(&self.filename)
            || observed.program != self.executable
            || observed.username != self.username
            || observed.arguments != self.arguments()
        {
            return Err(ServiceError::Conflict);
        }
        let checked = self.clone();
        blocking_read(move || {
            if full_state {
                checked.validate()
            } else {
                checked.validate_identity()
            }
        })
        .await?;
        Ok(observed)
    }
    /// Capture only an already-installed, exact original Gateway definition.
    /// Any error leaves the caller responsible for retaining this Definition
    /// and its C07 owner; failure never authorizes a fresh install or retry.
    pub(crate) async fn capture_registered_inactive(
        self: &Arc<Self>,
    ) -> Result<Arc<RegisteredInactiveProof>> {
        let checked = self.clone();
        let initial_state = blocking_read(move || {
            let (state, hash) = checked.state_observation()?;
            if checked.install_preparation
                || checked.pin.is_none()
                || checked.role != ServiceRole::Gateway
                || state.mode
                    != styx_contracts::native_management::NativeDeploymentMode::CreateLocal
                || state.desired.host.is_some()
                || state.has_migration_binding()
                || state
                    .desired
                    .gateway
                    .as_ref()
                    .is_none_or(|role| role.manager != NativeManager::PersistentService)
            {
                return Err(ServiceError::Conflict);
            }
            let raw = checked
                .root
                .read_raw("state.json", 1024 * 1024)
                .map_err(changed)?;
            if Sha256Digest::of_bytes(raw.bytes()) != hash {
                return Err(ServiceError::Unknown);
            }
            Ok(raw)
        })
        .await?;
        let first = self
            .inspect_registered_identity()
            .await
            .map_err(|_| ServiceError::Unknown)?;
        let second = self
            .inspect_registered_identity()
            .await
            .map_err(|_| ServiceError::Unknown)?;
        if !same_failed_inactive(&first, &second) {
            return Err(ServiceError::Unknown);
        }
        let checked = self.clone();
        let initial_state = blocking_read(move || {
            checked.validate()?;
            let current = checked
                .root
                .read_raw("state.json", 1024 * 1024)
                .map_err(changed)?;
            if current.observation() != initial_state.observation()
                || current.bytes() != initial_state.bytes()
            {
                return Err(ServiceError::Unknown);
            }
            Ok(initial_state)
        })
        .await
        .map_err(|_| ServiceError::Unknown)?;
        Ok(Arc::new(RegisteredInactiveProof {
            definition: self.clone(),
            observation: first,
            initial_state,
            fenced: std::sync::atomic::AtomicBool::new(false),
        }))
    }
    fn arguments(&self) -> Vec<String> {
        vec![
            self.executable.to_string_lossy().into_owned(),
            "__service-run".into(),
            "--state-dir".into(),
            self.path.to_string_lossy().into_owned(),
            "--role".into(),
            self.role.name().into(),
        ]
    }
    pub(crate) async fn prepare_stop(self: &Arc<Self>) -> Result<RunningInstance> {
        let peer = ServicePeer::observe_definition(self.clone()).await?;
        let mut slot = self.stop.lock().map_err(unknown)?;
        if slot.is_some() {
            return Err(ServiceError::Busy);
        }
        *slot = Some(RunningRecord {
            birth: peer.birth.clone(),
            runs: peer.runs,
        });
        Ok(RunningInstance { peer })
    }
    /// An explicit authorized installer may bootstrap our already-pinned
    /// root-owned definition. No escalation or implicit registration occurs.
    pub(crate) async fn bootstrap(self: &Arc<Self>) -> Result<ServiceObservation> {
        let checked = self.clone();
        blocking_read(move || checked.validate()).await?;
        if self.pin.is_none() {
            return Err(ServiceError::Unavailable);
        }
        tool(
            self.clone(),
            vec![
                "bootstrap".into(),
                "system".into(),
                Path::new(PLIST_PARENT)
                    .join(&self.filename)
                    .to_string_lossy()
                    .into_owned(),
            ],
            true,
        )
        .await?;
        self.inspect().await
    }
    /// Read the SAME captured stop attempt; never dispatch another signal.
    pub(crate) async fn observe_original_stop(self: &Arc<Self>) -> Result<StopObservation> {
        let (birth, runs) = {
            let slot = self.stop.lock().map_err(unknown)?;
            let original = slot.as_ref().ok_or(ServiceError::Invalid)?;
            (original.birth.clone(), original.runs)
        };
        let now = self.inspect().await?;
        if now.runs != runs || now.pid.is_some() || process_is_current(birth.clone()).await? {
            return Err(ServiceError::Unknown);
        }
        Ok(StopObservation {
            original: birth,
            original_birth_absent: true,
            manager_last_exit_code: now.last_exit_code,
            manager_runs: runs,
            product_jobs_joined: false,
        })
    }
    /// Wait for the SAME prepare_stop capture after the original Core's private
    /// Stop RPC. This never signals, replays a request, or adopts a new instance.
    pub(crate) async fn wait_original_stop(self: &Arc<Self>) -> Result<StopObservation> {
        let (birth, runs) = {
            let slot = self.stop.lock().map_err(unknown)?;
            let original = slot.as_ref().ok_or(ServiceError::Invalid)?;
            (original.birth.clone(), original.runs)
        };
        let ProcessIdentity::Macos {
            pid: original_pid, ..
        } = &birth
        else {
            return Err(ServiceError::Conflict);
        };
        let original_pid = *original_pid;
        let end = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let now = self.inspect().await?;
            if now.runs != runs || now.pid.is_some_and(|pid| pid != original_pid) {
                return Err(ServiceError::Unknown);
            }
            if now.pid.is_none() && !process_is_current(birth.clone()).await? {
                // Only the exact signed __service-run clean exit can attest its
                // internal Core/transport joins. Absence alone never does so.
                if now.last_exit_code != Some(0) || now.signaled_exit {
                    return Err(ServiceError::Unknown);
                }
                return Ok(StopObservation {
                    original: birth,
                    original_birth_absent: true,
                    manager_last_exit_code: now.last_exit_code,
                    manager_runs: runs,
                    product_jobs_joined: false,
                });
            }
            if tokio::time::Instant::now() >= end {
                return Err(ServiceError::Unknown);
            }
            tokio::time::sleep(Duration::from_millis(80)).await;
        }
    }
    pub(crate) async fn start(self: &Arc<Self>) -> Result<ServiceObservation> {
        let before = self.inspect().await?;
        if before.pid.is_some() {
            return Err(ServiceError::Conflict);
        }
        tool(self.clone(), vec!["kickstart".into(), self.target()], true).await?;
        self.inspect().await // observational only; no automatic Start retry
    }
    pub(crate) async fn set_enabled(self: &Arc<Self>, enabled: bool) -> Result<()> {
        self.inspect().await?;
        tool(
            self.clone(),
            vec![
                if enabled { "enable" } else { "disable" }.into(),
                self.target(),
            ],
            true,
        )
        .await?;
        let checked = self.clone();
        blocking_read(move || checked.validate()).await?;
        if self.enabled().await? != enabled {
            return Err(ServiceError::Unknown);
        }
        Ok(())
    }
    pub(crate) async fn enabled(self: &Arc<Self>) -> Result<bool> {
        self.inspect().await?;
        let raw = tool(
            self.clone(),
            vec!["print-disabled".into(), "system".into()],
            false,
        )
        .await?;
        let enabled = parse_disabled(&raw, &self.label)?;
        self.inspect().await?;
        Ok(enabled)
    }

    /// Consumer must already have committed desiredStopped and hold its ONE
    /// original operation lease. Never use this to mean autostart Disabled.
    pub(crate) async fn stop(
        self: &Arc<Self>,
        instance: RunningInstance,
    ) -> Result<StopObservation> {
        if !Arc::ptr_eq(self, &instance.peer.definition) {
            return Err(ServiceError::Conflict);
        }
        let checked = instance.peer.clone();
        blocking_read(move || checked.validate()).await?;
        // launchctl has no PID/birth CAS. Original operation serialization and
        // before/after job+kernel validation cover normal lifecycle races, not a
        // hostile administrator replacing the system registration mid-call.
        tool(
            self.clone(),
            vec!["kill".into(), "SIGTERM".into(), self.target()],
            true,
        )
        .await?;
        let end = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let now = self.inspect().await?;
            if now.runs != instance.peer.runs {
                return Err(ServiceError::Unknown);
            }
            if !process_is_current(instance.peer.birth.clone()).await? && now.pid.is_none() {
                return Ok(StopObservation {
                    original: instance.peer.birth.clone(),
                    original_birth_absent: true,
                    manager_last_exit_code: now.last_exit_code,
                    manager_runs: now.runs,
                    product_jobs_joined: false,
                });
            }
            if tokio::time::Instant::now() >= end {
                return Err(ServiceError::Unknown);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}
fn definition_bytes(
    label: &str,
    user: &str,
    home: &Path,
    exe: &Path,
    root: &Path,
    role: ServiceRole,
) -> Result<Vec<u8>> {
    let values = [
        path_text(exe)?,
        "__service-run",
        "--state-dir",
        path_text(root)?,
        "--role",
        role.name(),
    ];
    let args = values
        .iter()
        .map(|x| format!("<string>{}</string>", xml(x)))
        .collect::<String>();
    let text = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>Label</key><string>{}</string><key>ProgramArguments</key><array>{args}</array><key>UserName</key><string>{}</string><key>WorkingDirectory</key><string>{}</string><key>EnvironmentVariables</key><dict><key>HOME</key><string>{}</string><key>PATH</key><string>/usr/bin:/bin</string></dict><key>RunAtLoad</key><true/><key>KeepAlive</key><false/><key>ProcessType</key><string>Background</string></dict></plist>\n",
        xml(label),
        xml(user),
        xml(path_text(home)?),
        xml(path_text(home)?)
    );
    if text.len() > LIMIT {
        return Err(ServiceError::Invalid);
    }
    Ok(text.into_bytes())
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct ServiceObservation {
    pub(crate) path: PathBuf,
    pub(crate) program: PathBuf,
    pub(crate) username: String,
    pub(crate) arguments: Vec<String>,
    pub(crate) pid: Option<u32>,
    pub(crate) runs: u64,
    pub(crate) last_exit_code: Option<i32>,
    pub(crate) signaled_exit: bool,
    pub(crate) state: String,
}
fn parse_disabled(raw: &[u8], label: &str) -> Result<bool> {
    if raw.len() > LIMIT {
        return Err(ServiceError::Unknown);
    }
    let text = std::str::from_utf8(raw).map_err(unknown)?;
    let mut lines = text.lines().map(str::trim).filter(|s| !s.is_empty());
    if lines.next() != Some("disabled services = {") {
        return Err(ServiceError::Unknown);
    }
    let mut found = None;
    let mut closed = false;
    for line in lines {
        if closed {
            return Err(ServiceError::Unknown);
        }
        if line == "}" {
            closed = true;
            continue;
        }
        let (name, flag) = line.split_once(" => ").ok_or(ServiceError::Unknown)?;
        if !name.starts_with('"') || !name.ends_with('"') || name.len() < 3 {
            return Err(ServiceError::Unknown);
        }
        let value = match flag.trim_end_matches(',') {
            "true" => false,
            "false" => true,
            _ => return Err(ServiceError::Unknown),
        };
        if &name[1..name.len() - 1] == label {
            if found.replace(value).is_some() {
                return Err(ServiceError::Conflict);
            }
        }
    }
    if !closed {
        return Err(ServiceError::Unknown);
    }
    Ok(found.unwrap_or(true))
}
/// Strict bounded launchctl print subset. Unknown formatting/duplicate authority
/// fields fails closed. It is intentionally not a general launchd parser.
fn parse_print(raw: &[u8], label: &str) -> Result<ServiceObservation> {
    if raw.len() > LIMIT {
        return Err(ServiceError::Unknown);
    }
    let text = std::str::from_utf8(raw).map_err(unknown)?;
    let mut lines = text.lines();
    let head = lines.next().ok_or(ServiceError::Unknown)?;
    if !head.trim().starts_with(&format!("system/{label} = {{")) {
        return Err(ServiceError::Conflict);
    }
    let mut depth = 1u32;
    let mut fields = std::collections::BTreeMap::new();
    let mut args = None;
    let mut collecting = false;
    let mut values = Vec::new();
    for line in lines {
        let value = line.trim();
        if collecting {
            if value == "}" {
                collecting = false;
                depth -= 1;
                args = Some(std::mem::take(&mut values));
                continue;
            }
            if value.contains(['{', '}']) || value.len() > 4096 || values.len() >= 8 {
                return Err(ServiceError::Unknown);
            }
            values.push(value.to_owned());
            continue;
        }
        if value == "}" {
            depth = depth.checked_sub(1).ok_or(ServiceError::Unknown)?;
            continue;
        }
        if depth == 1 && value == "arguments = {" {
            if args.is_some() {
                return Err(ServiceError::Conflict);
            }
            collecting = true;
            depth += 1;
            continue;
        }
        if depth == 1 {
            if let Some((key, value)) = value.split_once(" = ") {
                if [
                    "path",
                    "program",
                    "username",
                    "pid",
                    "runs",
                    "last exit code",
                    "last terminating signal",
                    "state",
                ]
                .contains(&key)
                    && fields.insert(key.to_owned(), value.to_owned()).is_some()
                {
                    return Err(ServiceError::Conflict);
                }
            }
        }
        if value.ends_with('{') {
            depth += 1;
            if depth > 16 {
                return Err(ServiceError::Unknown);
            }
        }
    }
    if depth != 0 || collecting {
        return Err(ServiceError::Unknown);
    }
    let get = |key: &str| fields.get(key).cloned().ok_or(ServiceError::Unknown);
    let pid = fields
        .get("pid")
        .map(|v| v.parse::<u32>().map_err(unknown))
        .transpose()?;
    if pid == Some(0) {
        return Err(ServiceError::Unknown);
    }
    Ok(ServiceObservation {
        path: PathBuf::from(get("path")?),
        program: PathBuf::from(get("program")?),
        username: get("username")?,
        arguments: args.ok_or(ServiceError::Unknown)?,
        pid,
        runs: get("runs")?.parse().map_err(unknown)?,
        last_exit_code: fields
            .get("last exit code")
            .map(|v| v.parse().map_err(unknown))
            .transpose()?,
        // Unknown/nonzero signal notation never becomes a clean-exit proof.
        signaled_exit: fields
            .get("last terminating signal")
            .is_some_and(|value| value != "0"),
        state: get("state")?,
    })
}
/// Additional observation only: process absence is NOT original waitpid or
/// product/remote-owner settlement. Consumer must combine its original joins.
#[derive(Serialize)]
pub(crate) struct StopObservation {
    pub(crate) original: ProcessIdentity,
    pub(crate) original_birth_absent: bool,
    pub(crate) manager_last_exit_code: Option<i32>,
    pub(crate) manager_runs: u64,
    pub(crate) product_jobs_joined: bool,
}
struct RunningRecord {
    birth: ProcessIdentity,
    runs: u64,
}
pub(crate) struct RunningInstance {
    peer: Arc<ServicePeer>,
}
pub(crate) struct ServicePeer {
    definition: Arc<Definition>,
    birth: ProcessIdentity,
    runs: u64,
}
impl ServicePeer {
    pub(crate) async fn observe(path: &Path, role: ServiceRole) -> Result<Arc<Self>> {
        let path = path.to_owned();
        let definition = blocking_read(move || Definition::prepare(&path, role)).await?;
        Self::observe_definition(Arc::new(definition)).await
    }
    async fn observe_definition(definition: Arc<Definition>) -> Result<Arc<Self>> {
        let before = definition.inspect().await?;
        let pid = before.pid.ok_or(ServiceError::Unavailable)?;
        let runs = before.runs;
        let peer = blocking_read(move || {
            let birth = ProcessIdentity::observe(pid).map_err(unavailable)?;
            let ProcessIdentity::Macos { uid, .. } = &birth else {
                return Err(ServiceError::Conflict);
            };
            if *uid != definition.uid {
                return Err(ServiceError::Conflict);
            }
            let peer = Arc::new(Self {
                definition,
                birth,
                runs,
            });
            peer.validate()?;
            Ok(peer)
        })
        .await?;
        let after = peer.definition.inspect().await?;
        if before != after {
            return Err(ServiceError::Conflict);
        }
        Ok(peer)
    }
    pub(crate) fn pid(&self) -> u32 {
        match self.birth {
            ProcessIdentity::Macos { pid, .. } => pid,
            _ => unreachable!("Mac service holds only Darwin identity"),
        }
    }
    pub(crate) fn uid(&self) -> u32 {
        self.definition.uid
    }
    pub(crate) fn state_dir(&self) -> &Path {
        self.definition.state_dir()
    }
    pub(crate) fn role(&self) -> ServiceRole {
        self.definition.role()
    }
    pub(crate) fn validate_identity(&self) -> Result<()> {
        self.definition.validate_identity()?;
        if !self.birth.still_current().map_err(unknown)? {
            return Err(ServiceError::Conflict);
        }
        let mut attrs = GuestAttributes::new();
        attrs.set_pid(self.pid() as i32);
        let guest =
            SecCode::copy_guest_with_attribues(None, &attrs, Flags::NONE).map_err(changed)?;
        let req: SecRequirement = format!("cdhash H\"{}\"", hex::encode(&self.definition.cdhash))
            .parse()
            .map_err(changed)?;
        guest
            .check_validity(Flags::STRICT_VALIDATE | Flags::NO_NETWORK_ACCESS, &req)
            .map_err(changed)?;
        if guest.path(Flags::NONE).map_err(changed)?.to_path().as_ref()
            != Some(&self.definition.executable)
            || !self.birth.still_current().map_err(unknown)?
        {
            return Err(ServiceError::Conflict);
        }
        Ok(())
    }
    pub(crate) fn validate(&self) -> Result<()> {
        // Membership was authenticated twice by launchd at construction. Retain
        // that original birth and immutable root-owned definition, not a fresh
        // by-name lookup that could adopt a restarted job. This synchronous
        // port never blocks an async caller on another Tokio task.
        self.definition.validate()?;
        self.validate_identity()
    }
}
/// Mint only for the actual system-manager process, never a DTO/argv claim.
pub(crate) struct ServiceScope {
    peer: Arc<ServicePeer>,
}
impl ServiceScope {
    pub(crate) async fn authenticate(path: &Path, role: ServiceRole) -> Result<Arc<Self>> {
        let path = path.to_owned();
        let definition = blocking_read(move || {
            let definition = Arc::new(Definition::prepare(&path, role)?);
            let current = role
                .desired(&{
                    let marker = definition
                        .root
                        .read_raw(".styx-native-root-v1.json", 4096)
                        .map_err(changed)?;
                    let marker = native_state::decode_marker(marker.bytes()).map_err(changed)?;
                    let raw = definition
                        .root
                        .read_raw("state.json", 1024 * 1024)
                        .map_err(changed)?;
                    native_state::decode_state(raw.bytes(), &marker)
                        .map_err(changed)?
                        .state()
                        .clone()
                })
                .ok_or(ServiceError::Invalid)?;
            if current.run != NativeRunDesired::Running {
                return Err(ServiceError::Conflict);
            }
            Ok(definition)
        })
        .await?;
        let peer = ServicePeer::observe_definition(definition).await?;
        if peer.pid() != std::process::id() {
            return Err(ServiceError::Conflict);
        }
        Ok(Arc::new(Self { peer }))
    }
    pub(crate) fn state_dir(&self) -> &Path {
        self.peer.state_dir()
    }
    pub(crate) fn role(&self) -> ServiceRole {
        self.peer.role()
    }
    /// Synchronous full protected observation: caller must use its bounded
    /// blocking worker. This method is deliberately not an async cache.
    pub(crate) fn validate_identity(&self) -> Result<()> {
        self.peer.validate_identity()
    }
    /// Synchronous full protected observation; use only on a blocking worker.
    pub(crate) fn validate(&self) -> Result<()> {
        self.peer.validate()
    }
}
async fn drain<R: tokio::io::AsyncRead + Unpin>(mut reader: R, max: usize) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    let mut buf = [0u8; 4096];
    let mut overflow = false;
    loop {
        let n = reader.read(&mut buf).await.map_err(unknown)?;
        if n == 0 {
            break;
        }
        if data.len() + n > max {
            overflow = true;
        } else if !overflow {
            data.extend_from_slice(&buf[..n]);
        }
    }
    if overflow {
        Err(ServiceError::Unknown)
    } else {
        Ok(data)
    }
}
/// ONE owned fixed utility. Waiter loss never cancels/replays a dispatched OS
/// operation. The job retains definition pins, capacity and original child until
/// wait and both IO joins. Deadline kills only its own launchctl utility, never
/// substitutes for the managed Host/Gateway's physical cleanup.
async fn tool(
    definition: Arc<Definition>,
    arguments: Vec<String>,
    mutation: bool,
) -> Result<Vec<u8>> {
    if definition.install_preparation {
        return Err(ServiceError::Invalid);
    }
    let permit = TOOLS.try_acquire().map_err(|_| ServiceError::Busy)?;
    let (send, receive) = oneshot::channel();
    tokio::spawn(async move {
        let _permit = permit;
        let result = async {
            let checked = definition.clone();
            blocking_read(move || checked.validate_identity()).await?;
            let mut child = Command::new(LAUNCHCTL)
                .args(arguments)
                .env_clear()
                .env("HOME", &definition.home)
                .env("PATH", "/usr/bin:/bin")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(false)
                .spawn()
                .map_err(unavailable)?;
            let streams = (child.stdout.take(), child.stderr.take());
            let (Some(stdout), Some(stderr)) = streams else {
                let _ = child.start_kill();
                while child.wait().await.is_err() {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                return Err(ServiceError::Unknown);
            };
            let a = tokio::spawn(drain(stdout, LIMIT));
            let b = tokio::spawn(drain(stderr, 8192));
            let waited = tokio::time::timeout(Duration::from_secs(10), child.wait()).await;
            let (status, expired) = match waited {
                Ok(Ok(s)) => (Some(s), false),
                _ => {
                    let _ = child.start_kill();
                    while child.wait().await.is_err() {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    (None, true)
                }
            };
            let (out, err) = tokio::join!(a, b);
            let out = out.map_err(unknown)??;
            err.map_err(unknown)??;
            let checked = definition.clone();
            blocking_read(move || checked.validate_identity()).await?;
            if expired || status.is_none_or(|s| !s.success()) {
                return Err(if mutation {
                    ServiceError::Unknown
                } else {
                    ServiceError::Unavailable
                });
            }
            Ok(out)
        }
        .await;
        let _ = send.send(result);
    });
    receive.await.map_err(unknown)?
}
#[cfg(test)]
#[path = "macos_service_tests.rs"]
mod tests;

#[cfg(test)]
mod stop_observation_tests {
    use super::*;
    #[test]
    fn clean_exit_code_does_not_hide_signal_termination() {
        let raw = b"system/label = {\n path = /Library/LaunchDaemons/label.plist\n program = /private/bin/styx\n username = sid\n arguments = {\n /private/bin/styx\n }\n runs = 2\n state = not running\n last exit code = 0\n last terminating signal = Killed: 9\n}\n";
        let observed = parse_print(raw, "label").unwrap();
        assert_eq!(observed.last_exit_code, Some(0));
        assert!(observed.signaled_exit);
        let clean = String::from_utf8(raw.to_vec())
            .unwrap()
            .replace(" last terminating signal = Killed: 9\n", "");
        assert!(
            !parse_print(clean.as_bytes(), "label")
                .unwrap()
                .signaled_exit
        );
    }
}

#[cfg(test)]
mod registered_inactive_tests {
    use super::*;
    #[test]
    fn failed_generation_requires_stable_registered_inactive_evidence() {
        let original = ServiceObservation {
            path: PathBuf::from("/Library/LaunchDaemons/owned.plist"),
            program: PathBuf::from("/private/owned/bin/styx"),
            username: "owned".into(),
            arguments: vec!["__service-run".into()],
            pid: None,
            runs: 1,
            last_exit_code: Some(4),
            signaled_exit: false,
            state: "not running".into(),
        };
        assert!(same_failed_inactive(&original, &original));
        let mut changed = original.clone();
        changed.pid = Some(123);
        assert!(!same_failed_inactive(&original, &changed));
        changed = original.clone();
        changed.runs += 1;
        assert!(!same_failed_inactive(&original, &changed));
        changed = original.clone();
        changed.program = PathBuf::from("/other/bin/styx");
        assert!(!same_failed_inactive(&original, &changed));
        changed = original.clone();
        changed.state = "waiting".into();
        assert!(!same_failed_inactive(&original, &changed));
        changed = original.clone();
        changed.last_exit_code = None;
        assert!(!failed_inactive(&changed));
        changed.last_exit_code = Some(0);
        assert!(!failed_inactive(&changed));
        changed.signaled_exit = true;
        assert!(failed_inactive(&changed)); // failed history, never clean exit
        changed.runs = 0;
        assert!(!failed_inactive(&changed));
    }
}
