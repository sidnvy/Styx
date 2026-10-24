//! Current-UID, explicit transient Host actions. Observations are not desired
//! configuration, a migration grant, autostart, or Host/tool readiness.
//! StopUnit has no InvocationID CAS: exact reobservation and fresh non-reused
//! names protect normal lifecycle races, not a compromised same-UID manager.
use crate::{
    foreground::profile,
    store::{PrivateRoot, ProcessIdentity, RootIdentity},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::File,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
    process::Stdio,
    sync::{Arc, LazyLock},
    time::Duration,
};
use styx_contracts::identity::Sha256Digest;
use tokio::{
    io::AsyncReadExt,
    process::Command,
    sync::{Semaphore, oneshot},
    time::{Instant, timeout_at},
};
use tokio_util::sync::CancellationToken;

const OUTPUT_LIMIT: usize = 64 * 1024;
static ACTIONS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(2)));
static READERS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(2)));
type Result<T> = std::result::Result<T, ManagerError>;
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ManagerError {
    #[error("invalid transient Host reference")]
    Invalid,
    #[error("transient Host reference conflicts with current facts")]
    Conflict,
    #[error("user manager or protected profile unavailable")]
    Unavailable,
    #[error("transient Host action capacity reached")]
    Busy,
    #[error("transient Host action or cleanup outcome unknown")]
    Unknown,
}
impl ManagerError {
    pub fn exit_code(self) -> u8 {
        match self {
            Self::Invalid | Self::Conflict => 2,
            Self::Unavailable | Self::Busy => 3,
            Self::Unknown => 4,
        }
    }
    pub fn code(self) -> &'static str {
        match self {
            Self::Invalid => "host_manager_invalid",
            Self::Conflict => "host_manager_conflict",
            Self::Unavailable => "host_manager_unavailable",
            Self::Busy => "host_manager_busy",
            Self::Unknown => "host_manager_unknown",
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileRoot {
    pub device: u64,
    pub inode: u64,
    pub uid: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelBirth {
    pub boot_id: String,
    pub pid: u32,
    pub start_ticks: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
    pub device: u64,
    pub inode: u64,
}
/// Caller receipt only. Deserialization grants no control authority: every action
/// must reobserve this exact profile, invocation, native image and birth.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitRefDto {
    pub schema: u16,
    pub profile_root: ProfileRoot,
    pub unit: String,
    pub invocation_id: String,
    pub main: KernelBirth,
    pub cgroup: String,
    pub cgroup_identity: FileIdentity,
    pub image: FileIdentity,
}
pub struct UnitRef {
    observed: UnitRefDto,
}
impl UnitRef {
    pub fn observation(&self) -> &UnitRefDto {
        &self.observed
    }
    pub fn into_observation(self) -> UnitRefDto {
        self.observed
    }
}
// Successful start hands ownership to systemd. Dropping this observation MUST
// NOT stop the service; a lost response is reconciled with list_scoped/query.
#[derive(Clone, Debug, Serialize)]
pub struct UnitObservation {
    pub reference: UnitRefDto,
    pub active_state: String,
    pub sub_state: String,
    pub service_result: String,
    pub exec_main_code: u32,
    pub exec_main_status: i32,
    pub original_process_exited: bool,
    pub cgroup_empty: Option<bool>,
    pub cgroup_removed: bool,
    pub stop_complete: bool,
    pub readiness: &'static str,
}
#[derive(Debug, Serialize)]
pub struct ScopedUnit {
    pub unit: String,
    pub invocation_id: String,
    pub active_state: String,
    pub reference: Option<UnitRefDto>,
}
struct Profile {
    root: PrivateRoot,
    identity: ProfileRoot,
    path: PathBuf,
    scope: String,
    image: File,
    image_identity: FileIdentity,
    runtime: PathBuf,
    _loaded: profile::LoadedLegacyProfile,
}
fn birth(value: ProcessIdentity) -> KernelBirth {
    let ProcessIdentity::Linux {
        boot_id,
        pid,
        start_ticks,
    } = value;
    KernelBirth {
        boot_id,
        pid,
        start_ticks,
    }
}
fn identity(file: &File) -> Result<FileIdentity> {
    let m = file.metadata().map_err(|_| ManagerError::Unknown)?;
    Ok(FileIdentity {
        device: m.dev(),
        inode: m.ino(),
    })
}
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    let permit = READERS
        .clone()
        .try_acquire_owned()
        .map_err(|_| ManagerError::Busy)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        f()
    })
    .await
    .map_err(|_| ManagerError::Unknown)?
}
async fn open(path: &Path) -> Result<Arc<Profile>> {
    let path = path.to_path_buf();
    let profile = blocking(move || {
        if !path.is_absolute()
            || path.to_str().is_none()
            || path.as_os_str().len() > 4096
            || path
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        {
            return Err(ManagerError::Invalid);
        }
        let loaded = profile::load_legacy(&path).map_err(|_| ManagerError::Unavailable)?;
        loaded.revalidate().map_err(|_| ManagerError::Conflict)?;
        let root = PrivateRoot::open(&path).map_err(|_| ManagerError::Unavailable)?;
        let RootIdentity::Linux { device, inode, uid } = root.identity();
        if uid != nix::unistd::Uid::current().as_raw() {
            return Err(ManagerError::Conflict);
        }
        let scope = Sha256Digest::of_bytes(
            format!("styx-transient-host-v1:{device}:{inode}:{uid}").as_bytes(),
        )
        .to_hex();
        use std::os::unix::fs::FileTypeExt;
        let runtime = PathBuf::from(format!("/run/user/{uid}"));
        let directory =
            std::fs::symlink_metadata(&runtime).map_err(|_| ManagerError::Unavailable)?;
        let bus = std::fs::symlink_metadata(runtime.join("bus"))
            .map_err(|_| ManagerError::Unavailable)?;
        if !directory.is_dir()
            || directory.file_type().is_symlink()
            || directory.uid() != uid
            || directory.mode() & 0o077 != 0
            || !bus.file_type().is_socket()
            || bus.uid() != uid
        {
            return Err(ManagerError::Unavailable);
        }
        let image = File::open("/proc/self/exe").map_err(|_| ManagerError::Unavailable)?;
        let image_identity = identity(&image)?;
        Ok(Arc::new(Profile {
            root,
            identity: ProfileRoot { device, inode, uid },
            path,
            scope,
            image,
            image_identity,
            runtime: PathBuf::from(format!("/run/user/{uid}")),
            _loaded: loaded,
        }))
    })
    .await?;
    let stream = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::UnixStream::connect(profile.runtime.join("bus")),
    )
    .await
    .map_err(|_| ManagerError::Unavailable)?
    .map_err(|_| ManagerError::Unavailable)?;
    if stream
        .peer_cred()
        .map_err(|_| ManagerError::Unavailable)?
        .uid()
        != profile.identity.uid
    {
        return Err(ManagerError::Conflict);
    }
    drop(stream);
    Ok(profile)
}
fn check_scope(profile: &Profile, unit: &str) -> Result<()> {
    let prefix = format!("styx-host-{}-", profile.scope);
    let nonce = unit
        .strip_prefix(&prefix)
        .and_then(|v| v.strip_suffix(".service"))
        .ok_or(ManagerError::Invalid)?;
    if nonce.len() != 32
        || !nonce
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(ManagerError::Invalid);
    }
    Ok(())
}
fn invocation(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        && value.bytes().any(|b| b != b'0')
}
fn environment(command: &mut Command, runtime: &Path) {
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .env("XDG_RUNTIME_DIR", runtime)
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}/bus", runtime.display()),
        )
        .current_dir("/");
}
struct Tool {
    success: bool,
    stdout: Vec<u8>,
}
/// Each utility is owned until actual wait, including timeout/cancel. A timeout
/// terminates only this exact utility child, never the Host or its cgroup.
async fn tool(
    binary: &'static str,
    args: Vec<OsString>,
    runtime: PathBuf,
    end: Instant,
) -> Result<Tool> {
    tool_owned(binary, args, runtime, end, None).await
}
async fn tool_owned(
    binary: &'static str,
    args: Vec<OsString>,
    runtime: PathBuf,
    end: Instant,
    waited: Option<oneshot::Sender<()>>,
) -> Result<Tool> {
    if Instant::now() >= end {
        return Err(ManagerError::Unknown);
    }
    let permit = ACTIONS
        .clone()
        .try_acquire_owned()
        .map_err(|_| ManagerError::Busy)?;
    let (send, receive) = oneshot::channel();
    tokio::spawn(async move {
        let mut unreaped = None;
        let result = async {
            let mut command = Command::new(binary);
            environment(&mut command, &runtime);
            let mut child = command
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|_| ManagerError::Unavailable)?;
            let mut stdout = child.stdout.take().ok_or(ManagerError::Unknown)?;
            let mut stderr = child.stderr.take().ok_or(ManagerError::Unknown)?;
            let mut out = vec![0u8; OUTPUT_LIMIT + 1];
            let mut err = vec![0u8; 8193];
            let result = timeout_at(end, async {
                let (a, b, status) = tokio::join!(
                    read_bounded(&mut stdout, &mut out),
                    read_bounded(&mut stderr, &mut err),
                    child.wait()
                );
                let a = a?;
                b?;
                let status = status.map_err(|_| ManagerError::Unknown)?;
                out.truncate(a);
                Ok(Tool {
                    success: status.success(),
                    stdout: out,
                })
            })
            .await
            .unwrap_or(Err(ManagerError::Unknown));
            drop(stdout);
            drop(stderr);
            if result.is_err() && !terminate_utility(&mut child).await {
                unreaped = Some(child);
            }
            result
        }
        .await;
        if let Some(mut child) = unreaped {
            // Return Unknown within the cleanup budget, while the original
            // owned child and capacity remain retained until actual wait.
            tokio::spawn(async move {
                let _permit = permit;
                while child.wait().await.is_err() {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                if let Some(waited) = waited {
                    let _ = waited.send(());
                }
            });
        } else {
            drop(permit);
            if let Some(waited) = waited {
                let _ = waited.send(());
            }
        }
        let _ = send.send(result);
    });
    receive.await.map_err(|_| ManagerError::Unknown)?
}
async fn terminate_utility(child: &mut tokio::process::Child) -> bool {
    if let Some(pid) = child.id() {
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid as i32),
            nix::sys::signal::Signal::SIGTERM,
        );
    }
    if matches!(
        tokio::time::timeout(Duration::from_millis(250), child.wait()).await,
        Ok(Ok(_))
    ) {
        return true;
    }
    // Tokio retains ownership of the child. This escalation cannot target a
    // manager-owned Host, an arbitrary caller PID, or a service cgroup.
    let _ = child.start_kill();
    matches!(
        tokio::time::timeout(Duration::from_secs(2), child.wait()).await,
        Ok(Ok(_))
    )
}
// Uses only Tokio reads into preallocated bounded buffers; no unbounded output().
async fn read_bounded<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    buffer: &mut [u8],
) -> Result<usize> {
    let mut used = 0;
    loop {
        if used == buffer.len() {
            return Err(ManagerError::Unknown);
        }
        let n = reader
            .read(&mut buffer[used..])
            .await
            .map_err(|_| ManagerError::Unknown)?;
        if n == 0 {
            return Ok(used);
        }
        used += n;
    }
}
#[derive(Clone)]
struct Properties {
    values: BTreeMap<String, String>,
}
impl Properties {
    fn get(&self, key: &str) -> Result<&str> {
        self.values
            .get(key)
            .map(String::as_str)
            .ok_or(ManagerError::Unknown)
    }
    fn u32(&self, key: &str) -> Result<u32> {
        self.get(key)?.parse().map_err(|_| ManagerError::Unknown)
    }
    fn expected(&self, profile: &Profile, unit: &str) -> Result<()> {
        check_scope(profile, unit)?;
        for (k, v) in [
            ("Type", "exec"),
            ("Transient", "yes"),
            ("Restart", "no"),
            ("KillMode", "mixed"),
            ("SendSIGKILL", "no"),
            ("TimeoutStopUSec", "infinity"),
        ] {
            if self.get(k)? != v {
                return Err(ManagerError::Conflict);
            }
        }
        if self.get("Description")? != format!("Styx transient Host {unit}")
            || !invocation(self.get("InvocationID")?)
        {
            return Err(ManagerError::Conflict);
        }
        Ok(())
    }
}
async fn properties(profile: &Profile, unit: &str, end: Instant) -> Result<Properties> {
    check_scope(profile, unit)?;
    let out=tool("/usr/bin/systemctl",vec!["--user".into(),"--no-pager".into(),"show".into(),
        "--property=LoadState,ActiveState,SubState,InvocationID,ControlGroup,MainPID,ExecMainPID,ExecMainCode,ExecMainStatus,Result,Type,Transient,Restart,KillMode,SendSIGKILL,TimeoutStopUSec,Description".into(),unit.into()],profile.runtime.clone(),end).await?;
    let text = std::str::from_utf8(&out.stdout).map_err(|_| ManagerError::Unknown)?;
    let mut values = BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line.split_once('=').ok_or(ManagerError::Unknown)?;
        if value.len() > 4096 || values.insert(key.into(), value.into()).is_some() {
            return Err(ManagerError::Unknown);
        }
    }
    let p = Properties { values };
    if !out.success && p.get("LoadState")? != "not-found" {
        return Err(ManagerError::Unknown);
    }
    Ok(p)
}
fn cgroup_path(profile: &Profile, unit: &str, value: &str) -> Result<PathBuf> {
    if value.len() > 4096
        || !value.starts_with(&format!(
            "/user.slice/user-{}.slice/user@{}.service/",
            profile.identity.uid, profile.identity.uid
        ))
        || !value.ends_with(&format!("/{unit}"))
        || value.contains("//")
        || value.chars().any(char::is_control)
        || Path::new(value)
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(ManagerError::Conflict);
    }
    Ok(Path::new("/sys/fs/cgroup").join(value.trim_start_matches('/')))
}
fn check_main(profile: &Profile, pid: u32) -> Result<KernelBirth> {
    use std::io::Read;
    let before = ProcessIdentity::observe(pid).map_err(|_| ManagerError::Unknown)?;
    let image = File::open(format!("/proc/{pid}/exe")).map_err(|_| ManagerError::Unknown)?;
    if identity(&image)? != profile.image_identity
        || identity(&profile.image)? != profile.image_identity
    {
        return Err(ManagerError::Conflict);
    }
    let mut bytes = Vec::new();
    File::open(format!("/proc/{pid}/cmdline"))
        .map_err(|_| ManagerError::Unknown)?
        .take(16385)
        .read_to_end(&mut bytes)
        .map_err(|_| ManagerError::Unknown)?;
    if bytes.len() > 16384 {
        return Err(ManagerError::Unknown);
    }
    let args: Vec<_> = bytes.split(|b| *b == 0).filter(|s| !s.is_empty()).collect();
    let first = args
        .first()
        .and_then(|a| std::str::from_utf8(a).ok())
        .ok_or(ManagerError::Conflict)?;
    let launcher = first
        .strip_prefix("/proc/")
        .and_then(|s| s.strip_suffix("/exe"))
        .ok_or(ManagerError::Conflict)?;
    if launcher.is_empty()
        || !launcher.bytes().all(|b| b.is_ascii_digit())
        || args.len() != 5
        || args[1] != b"host"
        || args[2] != b"run"
        || args[3] != b"--state-dir"
        || args[4] != profile.path.as_os_str().as_encoded_bytes()
        || ProcessIdentity::observe(pid).map_err(|_| ManagerError::Unknown)? != before
    {
        return Err(ManagerError::Conflict);
    }
    Ok(birth(before))
}
async fn reference(profile: Arc<Profile>, unit: String, p: Properties) -> Result<UnitRefDto> {
    blocking(move || {
        p.expected(&profile, &unit)?;
        if p.get("ActiveState")? != "active" || p.get("SubState")? != "running" {
            return Err(ManagerError::Unavailable);
        }
        let main = check_main(&profile, p.u32("MainPID")?)?;
        let cgroup = p.get("ControlGroup")?.to_owned();
        let path = cgroup_path(&profile, &unit, &cgroup)?;
        let m = std::fs::symlink_metadata(&path).map_err(|_| ManagerError::Unknown)?;
        if !m.is_dir() || m.file_type().is_symlink() {
            return Err(ManagerError::Unknown);
        }
        Ok(UnitRefDto {
            schema: 1,
            profile_root: profile.identity.clone(),
            unit,
            invocation_id: p.get("InvocationID")?.into(),
            main,
            cgroup,
            cgroup_identity: FileIdentity {
                device: m.dev(),
                inode: m.ino(),
            },
            image: profile.image_identity.clone(),
        })
    })
    .await
}
async fn inspect(profile: Arc<Profile>, r: &UnitRefDto, end: Instant) -> Result<UnitObservation> {
    if r.schema != 1
        || r.profile_root != profile.identity
        || r.image != profile.image_identity
        || !invocation(&r.invocation_id)
        || r.main.pid == 0
        || r.main.boot_id.len() > 64
    {
        return Err(ManagerError::Conflict);
    }
    let p = properties(&profile, &r.unit, end).await?;
    p.expected(&profile, &r.unit)?;
    if p.get("InvocationID")? != r.invocation_id
        || (!p.get("ControlGroup")?.is_empty() && p.get("ControlGroup")? != r.cgroup)
        || p.u32("ExecMainPID")? != r.main.pid
    {
        return Err(ManagerError::Conflict);
    }
    let r = r.clone();
    blocking(move || {
        let current = PrivateRoot::open(&profile.path).map_err(|_| ManagerError::Unknown)?;
        if current.identity() != profile.root.identity() {
            return Err(ManagerError::Conflict);
        }
        let original = ProcessIdentity::Linux {
            boot_id: r.main.boot_id.clone(),
            pid: r.main.pid,
            start_ticks: r.main.start_ticks,
        };
        let alive = original
            .still_current()
            .map_err(|_| ManagerError::Unknown)?;
        let main_pid = p.u32("MainPID")?;
        if main_pid != 0 && (main_pid != r.main.pid || !alive) {
            return Err(ManagerError::Conflict);
        }
        if alive && check_main(&profile, r.main.pid)? != r.main {
            return Err(ManagerError::Conflict);
        }
        let path = cgroup_path(&profile, &r.unit, &r.cgroup)?;
        let (empty, removed) = match std::fs::symlink_metadata(&path) {
            Ok(m) => {
                if !m.is_dir()
                    || m.file_type().is_symlink()
                    || m.dev() != r.cgroup_identity.device
                    || m.ino() != r.cgroup_identity.inode
                {
                    return Err(ManagerError::Conflict);
                }
                use std::io::Read;
                let mut text = String::new();
                File::open(path.join("cgroup.events"))
                    .map_err(|_| ManagerError::Unknown)?
                    .take(4097)
                    .read_to_string(&mut text)
                    .map_err(|_| ManagerError::Unknown)?;
                if text.len() > 4096 {
                    return Err(ManagerError::Unknown);
                }
                let empty = match text.lines().find_map(|l| l.strip_prefix("populated ")) {
                    Some("0") => true,
                    Some("1") => false,
                    _ => return Err(ManagerError::Unknown),
                };
                (Some(empty), false)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (None, true),
            Err(_) => return Err(ManagerError::Unknown),
        };
        let inactive = matches!(p.get("ActiveState")?, "inactive" | "failed");
        let code = p.u32("ExecMainCode")?;
        let status = p
            .get("ExecMainStatus")?
            .parse()
            .map_err(|_| ManagerError::Unknown)?;
        let clean = p.get("Result")? == "success" && code == 1 && status == 0;
        Ok(UnitObservation {
            reference: r,
            active_state: p.get("ActiveState")?.into(),
            sub_state: p.get("SubState")?.into(),
            service_result: p.get("Result")?.into(),
            exec_main_code: code,
            exec_main_status: status,
            original_process_exited: !alive,
            cgroup_empty: empty,
            cgroup_removed: removed,
            stop_complete: inactive && !alive && (empty == Some(true) || removed) && clean,
            readiness: "process_started_host_readiness_not_observed",
        })
    })
    .await
}
/// Successful return is manager handoff, not enrollment or connection readiness.
pub async fn start(state_dir: &Path, cancel: CancellationToken) -> Result<UnitRef> {
    let path = state_dir.to_path_buf();
    let cancel = cancel.child_token();
    let guard = cancel.clone().drop_guard();
    let (send, receive) = oneshot::channel();
    tokio::spawn(async move {
        let result = start_owned(&path, &cancel).await;
        let _ = send.send(result);
    });
    let result = receive.await.map_err(|_| ManagerError::Unknown)?;
    guard.disarm();
    result
}
async fn start_owned(path: &Path, cancel: &CancellationToken) -> Result<UnitRef> {
    let profile = open(path).await?;
    let nonce = uuid::Uuid::new_v4().simple().to_string();
    let unit = format!("styx-host-{}-{nonce}.service", profile.scope);
    let end = Instant::now() + Duration::from_secs(15);
    if properties(&profile, &unit, end).await?.get("LoadState")? != "not-found" {
        return Err(ManagerError::Conflict);
    }
    if cancel.is_cancelled() {
        return Err(ManagerError::Unknown);
    }
    let mut args: Vec<OsString> = [
        "--user",
        "--quiet",
        "--no-ask-password",
        "--service-type=exec",
        "--expand-environment=no",
    ]
    .into_iter()
    .map(Into::into)
    .collect();
    args.extend(
        [
            format!("--unit={unit}"),
            format!("--description=Styx transient Host {unit}"),
            "--property=Restart=no".into(),
            "--property=KillMode=mixed".into(),
            "--property=SendSIGKILL=no".into(),
            "--property=TimeoutStopSec=infinity".into(),
            "--property=RemainAfterExit=yes".into(),
            "--property=Delegate=no".into(),
            "--property=UMask=0077".into(),
        ]
        .into_iter()
        .map(Into::into),
    );
    args.extend(
        [
            "--",
            "/usr/bin/env",
            "-i",
            "PATH=/usr/bin:/bin",
            "LANG=C.UTF-8",
        ]
        .into_iter()
        .map(Into::into),
    );
    args.push(format!("XDG_RUNTIME_DIR={}", profile.runtime.display()).into());
    args.push(
        format!(
            "DBUS_SESSION_BUS_ADDRESS=unix:path={}/bus",
            profile.runtime.display()
        )
        .into(),
    );
    args.extend([
        OsString::from(format!("/proc/{}/exe", std::process::id())),
        "host".into(),
        "run".into(),
        "--state-dir".into(),
        profile.path.as_os_str().to_owned(),
    ]);
    let (waited, reaped) = oneshot::channel();
    let launched = tool_owned(
        "/usr/bin/systemd-run",
        args,
        profile.runtime.clone(),
        end,
        Some(waited),
    )
    .await;
    let result = async {
        if !launched?.success {
            return Err(ManagerError::Unknown);
        }
        loop {
            let p = properties(&profile, &unit, end).await?;
            if let Ok(r) = reference(profile.clone(), unit.clone(), p).await {
                let observed = inspect(profile.clone(), &r, end).await?;
                if observed.original_process_exited {
                    return Err(ManagerError::Unknown);
                }
                if cancel.is_cancelled() {
                    return Err(ManagerError::Unknown);
                }
                return Ok(UnitRef { observed: r });
            }
            if Instant::now() >= end {
                return Err(ManagerError::Unknown);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    .await;
    if result.is_err() {
        // Missing unit is conclusive only after the original utility can no
        // longer submit a late StartTransientUnit. Keep startup cleanup owned
        // until actual wait (or channel close before any child was created).
        let _ = reaped.await;
        cleanup_attempt(profile, &unit).await;
    }
    result
}
// Failure/cancel reconciles the same selected nonce. It never starts a new unit.
async fn cleanup_attempt(profile: Arc<Profile>, unit: &str) {
    let mut original_cgroup: Option<String> = None;
    let mut original_pid = 0;
    loop {
        let end = Instant::now() + Duration::from_secs(5);
        if let Ok(p) = properties(&profile, unit, end).await {
            if p.get("LoadState") == Ok("not-found") {
                // The StartTransientUnit utility has actually exited, so it
                // cannot subsequently submit a late start for this nonce.
                if original_cgroup.is_none() {
                    return;
                }
            } else if p.expected(&profile, unit).is_ok() {
                if let Ok(cg) = p.get("ControlGroup")
                    && !cg.is_empty()
                {
                    original_cgroup = Some(cg.into());
                }
                if let Ok(pid) = p.u32("ExecMainPID")
                    && pid != 0
                {
                    original_pid = pid;
                }
                if let Ok(pin) = UnitPin::open(&profile, unit, end).await {
                    let expected = p.get("InvocationID").unwrap_or("").to_owned();
                    if let Ok(current) = properties(&profile, unit, end).await {
                        if current.get("InvocationID") == Ok(expected.as_str()) {
                            let _ = tool(
                                "/usr/bin/systemctl",
                                vec![
                                    "--user".into(),
                                    "--no-ask-password".into(),
                                    "--no-block".into(),
                                    "stop".into(),
                                    unit.into(),
                                ],
                                profile.runtime.clone(),
                                end,
                            )
                            .await;
                            let _ = pin.close().await;
                        } else {
                            let _ = pin.close().await;
                        }
                    } else {
                        let _ = pin.close().await;
                    }
                }
            }
        }
        let observed = properties(&profile, unit, Instant::now() + Duration::from_secs(2)).await;
        let inactive = observed.as_ref().is_ok_and(|p| {
            p.get("LoadState") == Ok("not-found")
                || matches!(p.get("ActiveState"), Ok("inactive" | "failed"))
                    && p.u32("MainPID") == Ok(0)
        });
        if inactive {
            let profile = profile.clone();
            let cg = original_cgroup.clone();
            let unit = unit.to_owned();
            let gone = blocking(move || {
                use std::io::Read;
                if original_pid != 0 {
                    match std::fs::metadata(format!("/proc/{original_pid}")) {
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        _ => return Ok(false),
                    }
                }
                let Some(cg) = cg else { return Ok(true) };
                let path = cgroup_path(&profile, &unit, &cg)?;
                let mut text = String::new();
                match File::open(path.join("cgroup.events")) {
                    Ok(f) => {
                        f.take(4097)
                            .read_to_string(&mut text)
                            .map_err(|_| ManagerError::Unknown)?;
                        Ok(text.len() <= 4096 && text.lines().any(|l| l == "populated 0"))
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
                    Err(_) => Err(ManagerError::Unknown),
                }
            })
            .await;
            if gone == Ok(true) {
                return;
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

pub async fn query(state_dir: &Path, r: &UnitRefDto) -> Result<UnitObservation> {
    inspect(
        open(state_dir).await?,
        r,
        Instant::now() + Duration::from_secs(5),
    )
    .await
}
pub async fn stop(
    state_dir: &Path,
    r: &UnitRefDto,
    expected_invocation: &str,
) -> Result<UnitObservation> {
    let path = state_dir.to_path_buf();
    let r = r.clone();
    let expected = expected_invocation.to_owned();
    let (send, receive) = oneshot::channel();
    tokio::spawn(async move {
        let result = stop_owned(&path, &r, &expected).await;
        let _ = send.send(result);
    });
    receive.await.map_err(|_| ManagerError::Unknown)?
}
async fn stop_owned(
    state_dir: &Path,
    r: &UnitRefDto,
    expected_invocation: &str,
) -> Result<UnitObservation> {
    if expected_invocation != r.invocation_id || !invocation(expected_invocation) {
        return Err(ManagerError::Conflict);
    }
    let profile = open(state_dir).await?;
    let end = Instant::now() + Duration::from_secs(10);
    let before = inspect(profile.clone(), r, end).await?;
    if before.stop_complete {
        return Ok(before);
    }
    // Official RefUnit pins the transient object across StopUnit/GC, solely
    // until native result facts are captured. It is not persistent registration.
    let pin = UnitPin::open(&profile, &r.unit, end).await?;
    let result = async {
        inspect(profile.clone(), r, end).await?;
        let output = tool(
            "/usr/bin/systemctl",
            vec![
                "--user".into(),
                "--no-ask-password".into(),
                "--no-block".into(),
                "stop".into(),
                r.unit.clone().into(),
            ],
            profile.runtime.clone(),
            end,
        )
        .await?;
        if !output.success {
            return Err(ManagerError::Unknown);
        }
        loop {
            let now = inspect(profile.clone(), r, end).await?;
            if now.stop_complete {
                return Ok(now);
            }
            if Instant::now() >= end {
                return Err(ManagerError::Unknown);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    .await;
    let closed = pin.close().await;
    if closed.is_err() {
        return Err(ManagerError::Unknown);
    }
    result
}
/// Recovery of a lost start reply is observation only, never implicit adoption.
pub async fn list_scoped(state_dir: &Path) -> Result<Vec<ScopedUnit>> {
    let profile = open(state_dir).await?;
    let end = Instant::now() + Duration::from_secs(10);
    let output = tool(
        "/usr/bin/systemctl",
        vec![
            "--user".into(),
            "--no-pager".into(),
            "--no-legend".into(),
            "--plain".into(),
            "list-units".into(),
            "--all".into(),
            format!("styx-host-{}-*.service", profile.scope).into(),
        ],
        profile.runtime.clone(),
        end,
    )
    .await?;
    if !output.success {
        return Err(ManagerError::Unavailable);
    }
    let text = std::str::from_utf8(&output.stdout).map_err(|_| ManagerError::Unknown)?;
    let names: Vec<_> = text
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .collect();
    if names.len() > 16 {
        return Err(ManagerError::Busy);
    }
    let mut observations = Vec::new();
    for unit in names {
        check_scope(&profile, unit)?;
        let p = properties(&profile, unit, end).await?;
        p.expected(&profile, unit)?;
        let reference = reference(profile.clone(), unit.into(), p.clone())
            .await
            .ok();
        observations.push(ScopedUnit {
            unit: unit.into(),
            invocation_id: p.get("InvocationID")?.into(),
            active_state: p.get("ActiveState")?.into(),
            reference,
        });
    }
    Ok(observations)
}

#[zbus::proxy(
    interface = "org.freedesktop.systemd1.Manager",
    default_path = "/org/freedesktop/systemd1"
)]
trait SystemdManager {
    fn ref_unit(&self, name: &str) -> zbus::Result<()>;
    fn unref_unit(&self, name: &str) -> zbus::Result<()>;
}
struct UnitPin {
    connection: zbus::Connection,
    owner: String,
    unit: String,
}
impl UnitPin {
    async fn open(profile: &Profile, unit: &str, end: Instant) -> Result<Self> {
        check_scope(profile, unit)?;
        let stream = timeout_at(
            end,
            tokio::net::UnixStream::connect(profile.runtime.join("bus")),
        )
        .await
        .map_err(|_| ManagerError::Unknown)?
        .map_err(|_| ManagerError::Unavailable)?;
        if stream
            .peer_cred()
            .map_err(|_| ManagerError::Unavailable)?
            .uid()
            != profile.identity.uid
        {
            return Err(ManagerError::Conflict);
        }
        let connection = timeout_at(
            end,
            zbus::connection::Builder::unix_stream(stream)
                .max_queued(4)
                .method_timeout(Duration::from_secs(2))
                .build(),
        )
        .await
        .map_err(|_| ManagerError::Unknown)?
        .map_err(|_| ManagerError::Unavailable)?;
        let result = async {
            let bus = zbus::fdo::DBusProxy::new(&connection)
                .await
                .map_err(|_| ManagerError::Unavailable)?;
            let owner = bus
                .get_name_owner(
                    "org.freedesktop.systemd1"
                        .try_into()
                        .map_err(|_| ManagerError::Invalid)?,
                )
                .await
                .map_err(|_| ManagerError::Unavailable)?;
            if bus
                .get_connection_unix_user(owner.as_ref().into())
                .await
                .map_err(|_| ManagerError::Unknown)?
                != profile.identity.uid
            {
                return Err(ManagerError::Conflict);
            }
            let manager = SystemdManagerProxy::builder(&connection)
                .destination(owner.as_str())
                .map_err(|_| ManagerError::Invalid)?
                .build()
                .await
                .map_err(|_| ManagerError::Unavailable)?;
            manager
                .ref_unit(unit)
                .await
                .map_err(|_| ManagerError::Unknown)?;
            Ok::<_, ManagerError>(owner.to_string())
        }
        .await;
        match result {
            Ok(owner) => Ok(Self {
                connection,
                owner,
                unit: unit.into(),
            }),
            Err(error) => {
                let _ = connection.close().await;
                Err(error)
            }
        }
    }
    async fn close(self) -> Result<()> {
        let until = Instant::now() + Duration::from_secs(2);
        let result = async {
            let manager = SystemdManagerProxy::builder(&self.connection)
                .destination(self.owner.as_str())
                .map_err(|_| ManagerError::Invalid)?
                .build()
                .await
                .map_err(|_| ManagerError::Unknown)?;
            manager
                .unref_unit(&self.unit)
                .await
                .map_err(|_| ManagerError::Unknown)
        }
        .await;
        let closed = timeout_at(until, self.connection.close()).await;
        if !matches!(closed, Ok(Ok(()))) {
            return Err(ManagerError::Unknown);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stopped_owned_utility_is_reaped_without_touching_sibling() {
        let mut stopped = Command::new("/usr/bin/sleep")
            .arg("30")
            .kill_on_drop(true)
            .spawn()
            .expect("owned stopped utility");
        let mut sibling = Command::new("/usr/bin/sleep")
            .arg("30")
            .kill_on_drop(true)
            .spawn()
            .expect("owned independent sibling");
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(stopped.id().expect("utility PID") as i32),
            nix::sys::signal::Signal::SIGSTOP,
        )
        .expect("stop exact owned child");
        let stop_deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let status = std::fs::read_to_string(format!(
                "/proc/{}/status",
                stopped.id().expect("owned utility PID")
            ))
            .expect("owned utility status");
            if status.lines().any(|line| {
                line.starts_with("State:") && line.split_whitespace().nth(1) == Some("T")
            }) {
                break;
            }
            assert!(
                Instant::now() < stop_deadline,
                "actual Stopped not observed"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let before = Instant::now();
        assert!(terminate_utility(&mut stopped).await);
        assert!(before.elapsed() < Duration::from_secs(3));
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(
            stopped
                .try_wait()
                .expect("actual wait")
                .expect("actual exit")
                .signal(),
            Some(nix::libc::SIGKILL)
        );
        assert!(sibling.try_wait().expect("independent sibling").is_none());
        sibling.kill().await.expect("reap exact test sibling");
    }
}
