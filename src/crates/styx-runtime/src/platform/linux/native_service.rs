//! Fixed native user units. Environment variables and a matching unit name are
//! not runtime authority: admission authenticates the actual original process.
use super::*;
use nix::{
    fcntl::{OFlag, open as open_fd, openat},
    sys::stat::{Mode, mkdirat},
    unistd::{Uid, UnlinkatFlags, User, unlinkat},
};
use std::{
    io::Write,
    os::fd::{AsFd, OwnedFd},
};
use styx_contracts::native_management::{
    NativeManager, NativeRunDesired, NativeRuntimeSelection, NativeState,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
        state: &NativeState,
    ) -> Option<styx_contracts::native_management::NativeComponentDesired> {
        match self {
            Self::Host => state.desired.host,
            Self::Gateway => state.desired.gateway,
        }
    }
}
pub(crate) type ServiceError = ManagerError;
pub(crate) const CONTROL_SOCKET_NAME: &str = ".styx-service-control-v1.sock";
type ServiceResult<T> = std::result::Result<T, ServiceError>;
fn invalid<T>(_: T) -> ServiceError {
    ServiceError::Invalid
}
fn changed<T>(_: T) -> ServiceError {
    ServiceError::Conflict
}
fn unknown<T>(_: T) -> ServiceError {
    ServiceError::Unknown
}
fn unavailable<T>(_: T) -> ServiceError {
    ServiceError::Unavailable
}
fn safe_path(path: &Path) -> ServiceResult<&str> {
    let s = path.to_str().ok_or(ServiceError::Invalid)?;
    if !path.is_absolute()
        || s.len() > 4096
        || s.contains("//")
        || !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(ServiceError::Invalid);
    }
    Ok(s)
}
fn checked_directory(path: &Path, create: bool) -> ServiceResult<File> {
    safe_path(path)?;
    let mut fd: OwnedFd = open_fd(
        "/",
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(unavailable)?;
    for part in path.components().filter_map(|c| {
        if let Component::Normal(v) = c {
            Some(v)
        } else {
            None
        }
    }) {
        let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
        let next = match openat(fd.as_fd(), Path::new(part), flags, Mode::empty()) {
            Ok(v) => v,
            Err(nix::errno::Errno::ENOENT) if create => {
                mkdirat(fd.as_fd(), Path::new(part), Mode::S_IRWXU).map_err(unavailable)?;
                File::from(fd.try_clone().map_err(unknown)?)
                    .sync_all()
                    .map_err(unknown)?;
                openat(fd.as_fd(), Path::new(part), flags, Mode::empty()).map_err(unavailable)?
            }
            Err(e) => return Err(unavailable(e)),
        };
        let m = nix::sys::stat::fstat(&next).map_err(unknown)?;
        if (m.st_uid != 0 && m.st_uid != Uid::current().as_raw()) || m.st_mode & 0o022 != 0 {
            return Err(ServiceError::Conflict);
        }
        fd = next;
    }
    Ok(File::from(fd))
}
fn bytes(file: &File, limit: usize) -> ServiceResult<Vec<u8>> {
    use std::os::unix::fs::FileExt as _;
    let before = file.metadata().map_err(unknown)?;
    if before.len() > limit as u64 {
        return Err(ServiceError::Conflict);
    }
    let mut result = vec![0; before.len() as usize];
    file.read_exact_at(&mut result, 0).map_err(unknown)?;
    let after = file.metadata().map_err(unknown)?;
    if (
        before.dev(),
        before.ino(),
        before.ctime(),
        before.ctime_nsec(),
        before.len(),
    ) != (
        after.dev(),
        after.ino(),
        after.ctime(),
        after.ctime_nsec(),
        after.len(),
    ) {
        return Err(ServiceError::Conflict);
    }
    Ok(result)
}
struct UnitPin {
    file: File,
    metadata: (u64, u64, i64, i64),
    raw: Vec<u8>,
}
impl UnitPin {
    fn capture(parent: &File, name: &str) -> ServiceResult<Option<Self>> {
        let fd = match openat(
            parent.as_fd(),
            name,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
            Mode::empty(),
        ) {
            Ok(v) => v,
            Err(nix::errno::Errno::ENOENT) => return Ok(None),
            Err(e) => return Err(unavailable(e)),
        };
        let file = File::from(fd);
        let m = file.metadata().map_err(unknown)?;
        if !m.is_file()
            || m.uid() != Uid::current().as_raw()
            || m.mode() & 0o077 != 0
            || m.nlink() != 1
        {
            return Err(ServiceError::Conflict);
        }
        let raw = bytes(&file, 32 * 1024)?;
        Ok(Some(Self {
            file,
            metadata: (m.dev(), m.ino(), m.ctime(), m.ctime_nsec()),
            raw,
        }))
    }
    fn validate(&self, parent: &File, name: &str, expected: &[u8]) -> ServiceResult<()> {
        let now = Self::capture(parent, name)?.ok_or(ServiceError::Conflict)?;
        let held = self.file.metadata().map_err(unknown)?;
        if self.metadata != now.metadata
            || (held.dev(), held.ino(), held.ctime(), held.ctime_nsec()) != self.metadata
            || self.raw != expected
            || now.raw != expected
            || bytes(&self.file, 32 * 1024)? != expected
        {
            return Err(ServiceError::Conflict);
        }
        Ok(())
    }
}
/// The original signed executable and protected scope are retained throughout
/// each OS operation. A report/serialized unit name cannot reconstruct this.
pub(crate) struct Definition {
    root: PrivateRoot,
    root_identity: RootIdentity,
    path: PathBuf,
    role: ServiceRole,
    selection: NativeRuntimeSelection,
    candidate: Arc<crate::release::VerifiedNativeRelease>,
    image: File,
    image_identity: FileIdentity,
    executable: PathBuf,
    parent_path: PathBuf,
    parent: File,
    parent_identity: FileIdentity,
    unit: String,
    expected: Vec<u8>,
    pin: Option<UnitPin>,
    runtime: PathBuf,
    operation_running: Option<RunningBinding>,
}
impl Definition {
    /// Installation alone may create missing fixed user-unit directories. No
    /// existing mode/ACL or unknown unit is repaired or overwritten.
    pub(crate) fn prepare(
        path: &Path,
        role: ServiceRole,
        create_directories: bool,
    ) -> ServiceResult<Self> {
        safe_path(path)?;
        let root = PrivateRoot::open(path).map_err(unavailable)?;
        let root_identity = root.identity();
        let RootIdentity::Linux { device, inode, uid } = root_identity;
        if uid != Uid::current().as_raw() || uid == 0 {
            return Err(ServiceError::Conflict);
        }
        let canonical = read_state(&root)?;
        // Check the actual platform address contract before any C07/OS effect.
        // No truncated path, alias, or fallback endpoint may select another root.
        if canonical.desired.gateway.is_some() {
            nix::sys::socket::UnixAddr::new(&path.join(CONTROL_SOCKET_NAME)).map_err(invalid)?;
        }
        role.desired(&canonical).ok_or(ServiceError::Invalid)?;
        let selection = selection(&canonical)?;
        let candidate = Arc::new(crate::release::verify_selected(&selection).map_err(changed)?);
        if candidate.report().target != "x86_64-unknown-linux-gnu" {
            return Err(ServiceError::Invalid);
        }
        let executable = Path::new(&selection.payload_path).join(candidate.report().entrypoint);
        safe_path(&executable)?;
        let image = File::open(&executable).map_err(unavailable)?;
        let image_identity = identity(&image)?;
        candidate.revalidate().map_err(changed)?;
        let home = User::from_uid(Uid::current())
            .map_err(unavailable)?
            .ok_or(ServiceError::Unavailable)?
            .dir;
        let parent_path = home.join(".config/systemd/user");
        let parent = checked_directory(&parent_path, create_directories)?;
        let parent_identity = identity(&parent)?;
        let digest = Sha256Digest::of_bytes(
            format!("styx-native-service-v1:{device}:{inode}:{uid}").as_bytes(),
        )
        .to_hex();
        let unit = format!("styx-native-{}-{}.service", &digest[..32], role.name());
        let expected = unit_definition(&executable, path, role)?.into_bytes();
        let pin = UnitPin::capture(&parent, &unit)?;
        if pin.as_ref().is_some_and(|p| p.raw != expected) {
            return Err(ServiceError::Conflict);
        }
        let runtime = PathBuf::from(format!("/run/user/{uid}"));
        let directory = checked_directory(&runtime, false)?;
        if directory.metadata().map_err(unknown)?.uid() != uid {
            return Err(ServiceError::Conflict);
        }
        let result = Self {
            root,
            root_identity: RootIdentity::Linux { device, inode, uid },
            path: path.into(),
            role,
            selection,
            candidate,
            image,
            image_identity,
            executable,
            parent_path,
            parent,
            parent_identity,
            unit,
            expected,
            pin,
            runtime,
            operation_running: None,
        };
        result.validate()?;
        Ok(result)
    }
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        if self.root.identity() != self.root_identity
            || PrivateRoot::open(&self.path)
                .map_err(unavailable)?
                .identity()
                != self.root_identity
            || identity(&self.parent)? != self.parent_identity
            || identity(&checked_directory(&self.parent_path, false)?)? != self.parent_identity
            || identity(&self.image)? != self.image_identity
            || identity(&File::open(&self.executable).map_err(unavailable)?)? != self.image_identity
            || selection(&read_state(&self.root)?)? != self.selection
        {
            return Err(ServiceError::Conflict);
        }
        self.candidate.revalidate().map_err(changed)?;
        if let Some(pin) = &self.pin {
            pin.validate(&self.parent, &self.unit, &self.expected)?;
        } else if UnitPin::capture(&self.parent, &self.unit)?.is_some() {
            return Err(ServiceError::Conflict);
        }
        Ok(())
    }
    pub(crate) fn state(&self) -> ServiceResult<NativeState> {
        read_state(&self.root)
    }
    async fn ctl(&self, verb: &'static str, no_block: bool) -> ServiceResult<()> {
        self.validate()?;
        let mut args: Vec<OsString> = ["--user", "--no-ask-password"]
            .into_iter()
            .map(Into::into)
            .collect();
        if no_block {
            args.push("--no-block".into());
        }
        args.push(verb.into());
        if verb != "daemon-reload" {
            args.push(self.unit.clone().into());
        }
        let output = tool(
            "/usr/bin/systemctl",
            args,
            self.runtime.clone(),
            Instant::now() + Duration::from_secs(15),
        )
        .await?;
        if !output.success {
            return Err(ServiceError::Unknown);
        }
        Ok(())
    }
    pub(crate) async fn inspect(&self) -> ServiceResult<ServiceObservation> {
        self.validate()?;
        let output = tool("/usr/bin/systemctl", vec!["--user".into(),"--no-pager".into(),"show".into(),
            "--property=Id,LoadState,ActiveState,SubState,InvocationID,ControlGroup,MainPID,ExecMainPID,ExecMainCode,ExecMainStatus,Result,FragmentPath,SourcePath,DropInPaths,NeedDaemonReload,Transient,UnitFileState,Restart,KillMode,SendSIGKILL,TimeoutStopUSec".into(),self.unit.clone().into()],self.runtime.clone(),Instant::now()+Duration::from_secs(10)).await?;
        let text = std::str::from_utf8(&output.stdout).map_err(unknown)?;
        let mut fields = BTreeMap::new();
        for line in text.lines() {
            let (name, value) = line.split_once('=').ok_or(ServiceError::Unknown)?;
            if value.len() > 4096 || fields.insert(name.to_owned(), value.to_owned()).is_some() {
                return Err(ServiceError::Unknown);
            }
        }
        let get = |key: &str| {
            fields
                .get(key)
                .map(String::as_str)
                .ok_or(ServiceError::Unknown)
        };
        let load = get("LoadState")?;
        if self.pin.is_none() {
            if load != "not-found" {
                return Err(ServiceError::Conflict);
            }
            return Ok(ServiceObservation::absent(self.unit.clone(), self.role));
        }
        if !output.success
            || get("Id")? != self.unit
            || load != "loaded"
            || !get("SourcePath")?.is_empty()
            || get("FragmentPath")?
                != self
                    .parent_path
                    .join(&self.unit)
                    .to_str()
                    .ok_or(ServiceError::Invalid)?
            || !get("DropInPaths")?.is_empty()
            || get("NeedDaemonReload")? != "no"
            || get("Transient")? != "no"
            || get("Restart")? != "no"
            || get("KillMode")? != "mixed"
            || get("SendSIGKILL")? != "no"
            || get("TimeoutStopUSec")? != "infinity"
        {
            return Err(ServiceError::Conflict);
        }
        let active = get("ActiveState")?.to_owned();
        let substate = get("SubState")?.to_owned();
        if !["active", "inactive", "activating", "deactivating", "failed"]
            .contains(&active.as_str())
        {
            return Err(ServiceError::Unknown);
        }
        let invocation = get("InvocationID")?.to_owned();
        if !invocation.is_empty()
            && (invocation.len() != 32 || !invocation.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(ServiceError::Conflict);
        }
        let enabled = match get("UnitFileState")? {
            "enabled" => Some(true),
            "disabled" => Some(false),
            _ => return Err(ServiceError::Conflict),
        };
        let pid = get("MainPID")?.parse().map_err(unknown)?;
        let exec_pid = get("ExecMainPID")?.parse().map_err(unknown)?;
        let result = get("Result")?;
        let manager_success =
            result == "success" && get("ExecMainCode")? == "1" && get("ExecMainStatus")? == "0";
        let cgroup = get("ControlGroup")?.to_owned();
        if !cgroup.is_empty() {
            self.cgroup_path(&cgroup)?;
        }
        self.validate()?;
        Ok(ServiceObservation {
            schema: 1,
            unit: self.unit.clone(),
            role: self.role,
            installed: true,
            enabled,
            active,
            substate,
            invocation_id: invocation,
            main_pid: pid,
            exec_main_pid: exec_pid,
            cgroup,
            manager_success,
            lifetime_scope: "user_login",
            survives_logout: None,
            runtime_health: "not_observed",
        })
    }
    fn cgroup_path(&self, value: &str) -> ServiceResult<PathBuf> {
        let uid = Uid::current().as_raw();
        if !value.starts_with(&format!("/user.slice/user-{uid}.slice/user@{uid}.service/"))
            || !value.ends_with(&format!("/{}", self.unit))
            || value.contains("//")
            || Path::new(value)
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        {
            return Err(ServiceError::Conflict);
        }
        Ok(Path::new("/sys/fs/cgroup").join(value.trim_start_matches('/')))
    }
    pub(crate) async fn install(&mut self) -> ServiceResult<ServiceObservation> {
        if self.pin.is_some() {
            return Err(ServiceError::Conflict);
        }
        let before = self.inspect().await?;
        if before.installed {
            return Err(ServiceError::Conflict);
        }
        let fd = openat(
            self.parent.as_fd(),
            self.unit.as_str(),
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::S_IRUSR | Mode::S_IWUSR,
        )
        .map_err(unknown)?;
        let mut file = File::from(fd);
        file.write_all(&self.expected).map_err(unknown)?;
        file.sync_all().map_err(unknown)?;
        self.parent.sync_all().map_err(unknown)?;
        self.pin = Some(UnitPin::capture(&self.parent, &self.unit)?.ok_or(ServiceError::Unknown)?);
        self.validate()?;
        self.ctl("daemon-reload", false).await?;
        let after = self.inspect().await?;
        if after.active != "inactive" || after.enabled != Some(false) {
            return Err(ServiceError::Unknown);
        }
        Ok(after)
    }
    pub(crate) async fn set_enabled(&self, enabled: bool) -> ServiceResult<ServiceObservation> {
        let before = self.inspect().await?;
        if !before.installed {
            return Err(ServiceError::Conflict);
        }
        self.ctl(if enabled { "enable" } else { "disable" }, false)
            .await?;
        let after = self.inspect().await?;
        if after.enabled != Some(enabled)
            || before.main_pid != after.main_pid
            || before.invocation_id != after.invocation_id
            || before.active != after.active
        {
            return Err(ServiceError::Unknown);
        }
        Ok(after)
    }
    pub(crate) async fn start(&self) -> ServiceResult<ServiceObservation> {
        let before = self.inspect().await?;
        if !before.installed || before.active != "inactive" || before.main_pid != 0 {
            return Err(ServiceError::Conflict);
        }
        self.ctl("start", true).await?;
        let until = Instant::now() + Duration::from_secs(20);
        loop {
            let status = self.inspect().await?;
            if status.active == "active" && status.substate == "running" && status.main_pid != 0 {
                self.bind_running(&status)?;
                return Ok(status);
            }
            if status.active == "failed" || Instant::now() >= until {
                return Err(ServiceError::Unknown);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    /// Capture BEFORE committing Stopped or asking the original Core to drain.
    /// The actual original birth/CG handles remain here on every later failure.
    pub(crate) async fn prepare_stop(&mut self) -> ServiceResult<()> {
        if self.operation_running.is_some() {
            return Err(ServiceError::Conflict);
        }
        let before = self.inspect().await?;
        if before.active != "active" || before.main_pid == 0 {
            return Err(ServiceError::Conflict);
        }
        self.operation_running = Some(self.bind_running(&before)?);
        Ok(())
    }
    pub(crate) async fn stop(&self, request_os_stop: bool) -> ServiceResult<ServiceObservation> {
        let bound = self
            .operation_running
            .as_ref()
            .ok_or(ServiceError::Conflict)?;
        let ProcessIdentity::Linux {
            pid: original_pid, ..
        } = bound.birth;
        if request_os_stop {
            let current = self.inspect().await?;
            if current.invocation_id != bound.invocation {
                return Err(ServiceError::Conflict);
            }
            if current.main_pid != 0 {
                if current.main_pid != original_pid
                    || !bound.birth.still_current().map_err(unknown)?
                {
                    return Err(ServiceError::Conflict);
                }
                // Exactly one manager request for the captured invocation. No
                // process is signalled by a raw caller-supplied PID.
                self.ctl("stop", true).await?;
            }
        }
        let until = Instant::now() + Duration::from_secs(45);
        loop {
            let status = self.inspect().await?;
            if !status.invocation_id.is_empty() && status.invocation_id != bound.invocation {
                return Err(ServiceError::Conflict);
            }
            let held = bound.cgroup.metadata().map_err(unknown)?;
            if (FileIdentity {
                device: held.dev(),
                inode: held.ino(),
            }) != bound.cgroup_identity
            {
                return Err(ServiceError::Conflict);
            }
            let empty = held.nlink() == 0 || group_empty(&bound.events)?;
            if status.active == "inactive"
                && status.main_pid == 0
                && status.exec_main_pid == original_pid
                && status.manager_success
                && !bound.birth.still_current().map_err(unknown)?
                && empty
            {
                return Ok(status);
            }
            if Instant::now() >= until {
                return Err(ServiceError::Unknown);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    pub(crate) async fn uninstall(&mut self) -> ServiceResult<ServiceObservation> {
        let before = self.inspect().await?;
        if !before.installed
            || before.enabled != Some(false)
            || before.active != "inactive"
            || before.main_pid != 0
        {
            return Err(ServiceError::Conflict);
        }
        self.validate()?;
        unlinkat(
            self.parent.as_fd(),
            self.unit.as_str(),
            UnlinkatFlags::NoRemoveDir,
        )
        .map_err(unknown)?;
        self.parent.sync_all().map_err(unknown)?;
        self.pin = None;
        self.ctl("daemon-reload", false).await?;
        self.inspect().await
    }
    fn bind_running(&self, status: &ServiceObservation) -> ServiceResult<RunningBinding> {
        let birth = ProcessIdentity::observe(status.main_pid).map_err(unknown)?;
        if status.main_pid == 0
            || status.invocation_id.len() != 32
            || status.invocation_id.bytes().all(|b| b == b'0')
            || identity(&File::open(format!("/proc/{}/exe", status.main_pid)).map_err(unknown)?)?
                != self.image_identity
        {
            return Err(ServiceError::Conflict);
        }
        let raw = std::fs::read(format!("/proc/{}/cmdline", status.main_pid)).map_err(unknown)?;
        let expected = [
            self.executable.as_os_str().as_encoded_bytes(),
            b"__service-run",
            b"--state-dir",
            self.path.as_os_str().as_encoded_bytes(),
            b"--role",
            self.role.name().as_bytes(),
        ];
        if raw
            .split(|v| *v == 0)
            .filter(|v| !v.is_empty())
            .collect::<Vec<_>>()
            != expected
        {
            return Err(ServiceError::Conflict);
        }
        let cg = self.cgroup_path(&status.cgroup)?;
        let cgroup = checked_directory(&cg, false)?;
        let cgroup_identity = identity(&cgroup)?;
        let events = File::from(
            openat(
                cgroup.as_fd(),
                "cgroup.events",
                OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(unknown)?,
        );
        require_membership(status.main_pid, &status.cgroup)?;
        if !birth.still_current().map_err(unknown)? {
            return Err(ServiceError::Conflict);
        }
        Ok(RunningBinding {
            birth,
            cgroup,
            cgroup_identity,
            events,
            cgroup_path: status.cgroup.clone(),
            invocation: status.invocation_id.clone(),
        })
    }
}
fn read_state(root: &PrivateRoot) -> ServiceResult<NativeState> {
    let marker = root
        .read_raw(".styx-native-root-v1.json", 4096)
        .map_err(unavailable)?;
    let marker = crate::store::native_state::decode_marker(marker.bytes()).map_err(changed)?;
    let RootIdentity::Linux { device, inode, uid } = root.identity();
    if marker.root_identity
        != (styx_contracts::native_management::NativeRootIdentity::Linux { device, inode, uid })
    {
        return Err(ServiceError::Conflict);
    }
    let raw = root
        .read_raw("state.json", 1024 * 1024)
        .map_err(unavailable)?;
    crate::store::native_state::decode_state(raw.bytes(), &marker)
        .map(|v| v.state().clone())
        .map_err(changed)
}
fn selection(state: &NativeState) -> ServiceResult<NativeRuntimeSelection> {
    serde_json::from_str(
        state
            .extensions
            .get("runtime_selection_v1")
            .ok_or(ServiceError::Invalid)?
            .get(),
    )
    .map_err(invalid)
}
fn require_membership(pid: u32, expected: &str) -> ServiceResult<()> {
    let raw = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).map_err(unknown)?;
    if raw.len() > 4096 || raw.lines().collect::<Vec<_>>() != [format!("0::{expected}")] {
        return Err(ServiceError::Conflict);
    }
    let m = std::fs::metadata(format!("/proc/{pid}")).map_err(unknown)?;
    if m.uid() != Uid::current().as_raw() {
        return Err(ServiceError::Conflict);
    }
    Ok(())
}
fn group_empty(events: &File) -> ServiceResult<bool> {
    use std::os::unix::fs::FileExt as _;
    let mut buf = [0; 4096];
    let n = events.read_at(&mut buf, 0).map_err(unknown)?;
    if n == buf.len() {
        return Err(ServiceError::Unknown);
    }
    let text = std::str::from_utf8(&buf[..n]).map_err(unknown)?;
    let values = text
        .lines()
        .filter_map(|line| line.strip_prefix("populated "))
        .collect::<Vec<_>>();
    match values.as_slice() {
        ["0"] => Ok(true),
        ["1"] => Ok(false),
        _ => Err(ServiceError::Unknown),
    }
}
fn unit_definition(executable: &Path, path: &Path, role: ServiceRole) -> ServiceResult<String> {
    let binary = safe_path(executable)?;
    let path = safe_path(path)?;
    Ok(format!(
        "# Styx native Rust user service v1\n[Unit]\nDescription=Styx native {}\n\n[Service]\nType=exec\nExecStart={binary} __service-run --state-dir {path} --role {}\nWorkingDirectory=/\nRestart=no\nKillMode=mixed\nSendSIGKILL=no\nTimeoutStopSec=infinity\nUMask=0077\nEnvironment=PATH=/usr/bin:/bin LANG=C.UTF-8\n\n[Install]\nWantedBy=default.target\n",
        role.name(),
        role.name()
    ))
}
#[derive(Serialize)]
pub(crate) struct ServiceObservation {
    pub(crate) schema: u16,
    pub(crate) unit: String,
    pub(crate) role: ServiceRole,
    pub(crate) installed: bool,
    pub(crate) enabled: Option<bool>,
    pub(crate) active: String,
    pub(crate) substate: String,
    pub(crate) invocation_id: String,
    pub(crate) main_pid: u32,
    pub(crate) exec_main_pid: u32,
    pub(crate) cgroup: String,
    pub(crate) manager_success: bool,
    pub(crate) lifetime_scope: &'static str,
    pub(crate) survives_logout: Option<bool>,
    pub(crate) runtime_health: &'static str,
}
impl ServiceObservation {
    fn absent(unit: String, role: ServiceRole) -> Self {
        Self {
            schema: 1,
            unit,
            role,
            installed: false,
            enabled: None,
            active: "not_installed".into(),
            substate: "not_installed".into(),
            invocation_id: String::new(),
            main_pid: 0,
            exec_main_pid: 0,
            cgroup: String::new(),
            manager_success: false,
            lifetime_scope: "user_login",
            survives_logout: None,
            runtime_health: "not_observed",
        }
    }
}
struct RunningBinding {
    birth: ProcessIdentity,
    cgroup: File,
    cgroup_identity: FileIdentity,
    events: File,
    cgroup_path: String,
    invocation: String,
}
/// Client-side binding to the actual installed service process. SO_PEERCRED
/// must still match this retained peer after connecting the fixed control path.
pub(crate) struct ServicePeer {
    definition: Definition,
    running: RunningBinding,
}
impl ServicePeer {
    pub(crate) async fn observe(path: &Path, role: ServiceRole) -> ServiceResult<Arc<Self>> {
        let definition = Definition::prepare(path, role, false)?;
        let desired = role
            .desired(&definition.state()?)
            .ok_or(ServiceError::Invalid)?;
        if desired.manager != NativeManager::PersistentService
            || desired.run != NativeRunDesired::Running
        {
            return Err(ServiceError::Conflict);
        }
        let before = definition.inspect().await?;
        if before.main_pid == 0 || before.active != "active" && before.active != "activating" {
            return Err(ServiceError::Conflict);
        }
        let running = definition.bind_running(&before)?;
        let after = definition.inspect().await?;
        if after.main_pid != before.main_pid || after.invocation_id != before.invocation_id {
            return Err(ServiceError::Conflict);
        }
        let peer = Arc::new(Self {
            definition,
            running,
        });
        peer.validate()?;
        Ok(peer)
    }
    pub(crate) fn pid(&self) -> u32 {
        let ProcessIdentity::Linux { pid, .. } = &self.running.birth;
        *pid
    }
    pub(crate) fn uid(&self) -> u32 {
        let RootIdentity::Linux { uid, .. } = &self.definition.root_identity;
        *uid
    }
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        self.definition.validate()?;
        let desired = self
            .definition
            .role
            .desired(&self.definition.state()?)
            .ok_or(ServiceError::Invalid)?;
        if desired.manager != NativeManager::PersistentService
            || !self.running.birth.still_current().map_err(unknown)?
            || identity(&self.running.cgroup)? != self.running.cgroup_identity
            || identity(&checked_directory(
                &self.definition.cgroup_path(&self.running.cgroup_path)?,
                false,
            )?)? != self.running.cgroup_identity
            || identity(&File::open(format!("/proc/{}/exe", self.pid())).map_err(unknown)?)?
                != self.definition.image_identity
            || self.running.invocation.len() != 32
        {
            return Err(ServiceError::Conflict);
        }
        require_membership(self.pid(), &self.running.cgroup_path)
    }
}
/// Non-serializable current-process authority. No environment variable, request
/// path or serialized report can construct a service scope.
pub(crate) struct ServiceScope {
    peer: Arc<ServicePeer>,
}
impl ServiceScope {
    pub(crate) async fn authenticate(path: &Path, role: ServiceRole) -> ServiceResult<Arc<Self>> {
        let peer = ServicePeer::observe(path, role).await?;
        if peer.pid() != std::process::id() {
            return Err(ServiceError::Conflict);
        }
        let scope = Arc::new(Self { peer });
        scope.validate()?;
        Ok(scope)
    }
    pub(crate) fn state_dir(&self) -> &Path {
        &self.peer.definition.path
    }
    pub(crate) fn role(&self) -> ServiceRole {
        self.peer.definition.role
    }
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        // This already-minted scope remains the original process while an
        // explicit Stopped target drains it. New scopes still require Running.
        self.peer.validate()
    }
}
