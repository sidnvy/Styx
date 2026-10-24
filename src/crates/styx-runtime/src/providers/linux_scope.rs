//! Linux headless process-tree ownership, not a desktop/session grant or sandbox.
//! One random transient user service owns either the fixed Browser worker or
//! fixed Cua MCP driver launch. Native descendants must remain in that cgroup;
//! normal-lifecycle containment is not a hostile same-UID sandbox.
//! No direct-launch fallback, external-scope adoption or PID-name killing.
//! Defaults bound aggregate cgroup charged memory to 2GiB, swap to zero and
//! tasks (including threads) to256; not Host RSS/CPU performance guarantees.
//! Missing delegated controllers fail closed; no user-manager reconfiguration.
//! StopUnit has no InvocationID CAS: guard the original unique manager/unit and
//! document that a compromised same-UID account is outside this trust boundary.
use crate::store::ProcessIdentity;
use std::{
    ffi::OsString,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path, PathBuf},
    process::{ExitStatus, Stdio},
    sync::{Arc, LazyLock},
    time::Duration,
};
use tokio::{
    io::AsyncReadExt,
    net::UnixStream,
    process::{Child, Command},
    sync::{Semaphore, oneshot},
    time::{Instant, timeout_at},
};
use tokio_util::sync::CancellationToken;

type Result<T> = std::result::Result<T, ScopeError>;
const STDOUT_BYTES: usize = 64 * 1024;
const STDERR_BYTES: usize = 8 * 1024;
static TOOL_SLOT: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(1)));

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ScopeError {
    #[error("scope_busy")]
    Busy,
    #[error("scope_invalid_request")]
    InvalidRequest,
    #[error("scope_permission_denied")]
    PermissionDenied,
    #[error("scope_unsupported")]
    Unsupported,
    #[error("scope_outcome_unknown")]
    Unknown,
    #[error("scope_cleanup_unconfirmed")]
    CleanupUnconfirmed,
}
/// Fixed trusted launch forms only. Paths/display names are not OS authority:
/// callers retain verified image/config pins and an authenticated session lease.
pub(crate) struct ScopeCommand {
    executable: PathBuf,
    workspace: PathBuf,
    home: PathBuf,
    launch: Launch,
}
enum Launch {
    Browser {
        worker: PathBuf,
        config: PathBuf,
    },
    Cua {
        wayland_display: String,
        hyprland_instance: String,
    },
}
impl ScopeCommand {
    pub(crate) fn browser(
        node: PathBuf,
        worker: PathBuf,
        config: PathBuf,
        workspace: PathBuf,
        home: PathBuf,
    ) -> Result<Self> {
        let value = Self {
            executable: node,
            workspace,
            home,
            launch: Launch::Browser { worker, config },
        };
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn cua(
        driver: PathBuf,
        workspace: PathBuf,
        home: PathBuf,
        wayland_display: String,
        hyprland_instance: String,
    ) -> Result<Self> {
        // These bounded names come from the trusted association lease, not a
        // request/environment lookup. Shape checks do not authenticate a seat.
        if !wayland_display.strip_prefix("wayland-").is_some_and(|v| {
            !v.is_empty() && v.len() <= 16 && v.bytes().all(|b| b.is_ascii_digit())
        }) || hyprland_instance.is_empty()
            || hyprland_instance.len() > 256
            || !hyprland_instance
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        {
            return Err(ScopeError::InvalidRequest);
        }
        let value = Self {
            executable: driver,
            workspace,
            home,
            launch: Launch::Cua {
                wayland_display,
                hyprland_instance,
            },
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<()> {
        let mut paths = vec![&self.executable, &self.workspace, &self.home];
        if let Launch::Browser { worker, config } = &self.launch {
            paths.extend([worker, config]);
        }
        for path in paths {
            if !path.is_absolute()
                || path.as_os_str().len() > 4096
                || path.to_str().is_none_or(|text| text.contains('\0'))
                || path
                    .components()
                    .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
            {
                return Err(ScopeError::InvalidRequest);
            }
        }
        Ok(())
    }
}
pub(crate) struct ScopeCleanup {
    pub wrapper_exited: bool,
    pub confirmed: bool,
    pub exit_success: Option<bool>,
}
struct Manager {
    owner: String,
    process: ProcessIdentity,
    bus_peer: ProcessIdentity,
    bus_inode: u64,
    bus_device: u64,
}
struct Cgroup {
    path: PathBuf,
    directory: File,
    events: File,
    kill: Option<File>,
    device: u64,
    inode: u64,
}
struct Stamp {
    manager: Manager,
    invocation: String,
    cgroup: Cgroup,
}
pub(crate) struct LinuxOwnedScope {
    unit: String,
    uid: u32,
    runtime: PathBuf,
    private_tmp: PathBuf,
    executable: PathBuf,
    stamp: Option<Stamp>,
    wrapper_exit: Option<ExitStatus>,
}
impl std::fmt::Debug for LinuxOwnedScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinuxOwnedScope")
            .field("unit", &self.unit)
            .field("attested", &self.stamp.is_some())
            .finish()
    }
}
impl LinuxOwnedScope {
    /// The provider retains verified executable/worker/config fd pins and stores this
    /// scope BEFORE spawning/awaiting. Failed first attestation stays owned and
    /// Unknown; no tool or MCP initialize is permitted before it succeeds.
    pub(crate) fn command(input: ScopeCommand) -> Result<(Command, Self)> {
        input.validate()?;
        let uid = nix::unistd::Uid::current().as_raw();
        let runtime = PathBuf::from(format!("/run/user/{uid}"));
        let prefix = match &input.launch {
            Launch::Browser { .. } => "styx-browser",
            Launch::Cua { .. } => "styx-cua",
        };
        let unit_stem = format!("{prefix}-{}", uuid::Uuid::new_v4().simple());
        let unit = format!("{unit_stem}.service");
        let private_tmp = runtime.join(&unit_stem);
        // Never ask systemd to chmod/adopt a pre-existing directory. The name
        // is fresh per scope; same-UID hostile replacement remains outside the
        // normal-lifecycle trust boundary, as for unit query/StopUnit itself.
        match std::fs::symlink_metadata(&private_tmp) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => return Err(ScopeError::InvalidRequest),
            Err(_) => return Err(ScopeError::Unsupported),
        }
        let mut command = Command::new("/usr/bin/systemd-run");
        fixed_environment(&mut command, &runtime);
        command
            .args([
                "--user",
                "--quiet",
                "--wait",
                "--pipe",
                "--collect",
                "--service-type=exec",
            ])
            .arg(format!("--unit={unit}"))
            // The user manager creates this short private runtime directory
            // below XDG_RUNTIME_DIR and removes it when this exact unit stops.
            .arg(format!("--property=RuntimeDirectory={unit_stem}"))
            .args([
                "--property=RuntimeDirectoryMode=0700",
                "--property=RuntimeDirectoryPreserve=no",
            ])
            .args([
                "--property=Restart=no",
                "--property=KillMode=control-group",
                "--property=Delegate=no",
                "--property=TimeoutStopSec=1s",
                "--property=SendSIGKILL=yes",
                "--property=MemoryMax=2147483648",
                "--property=MemorySwapMax=0",
                "--property=TasksMax=256",
                "--property=LimitCORE=0",
            ])
            .arg(format!(
                "--property=WorkingDirectory={}",
                input.workspace.display()
            ))
            // Clearing the wrapper environment does not clear the user manager's
            // environment. env -i is the target's exact environment boundary.
            .args([
                "--",
                "/usr/bin/env",
                "-i",
                "PATH=/usr/bin:/bin",
                "LANG=C.UTF-8",
            ])
            .arg(format!("HOME={}", input.home.display()))
            .arg(format!("TMPDIR={}", private_tmp.display()))
            .arg(format!("XDG_RUNTIME_DIR={}", runtime.display()))
            .arg(format!(
                "DBUS_SESSION_BUS_ADDRESS=unix:path={}/bus",
                runtime.display()
            ));
        match &input.launch {
            Launch::Browser { worker, config } => {
                command
                    .arg("PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1")
                    .arg(&input.executable)
                    .arg(worker)
                    .arg("--config")
                    .arg(config);
            }
            Launch::Cua {
                wayland_display,
                hyprland_instance,
            } => {
                // This fixed form is selected only by trusted, explicitly
                // enabled Desktop bootstrap. Opt-in selects the native backend;
                // it is not evidence of a capture/input permission grant.
                command
                    .arg("CUA_DRIVER_RS_ENABLE_WAYLAND=1")
                    .arg(format!("WAYLAND_DISPLAY={wayland_display}"))
                    .arg(format!("HYPRLAND_INSTANCE_SIGNATURE={hyprland_instance}"))
                    .arg(&input.executable)
                    .arg("mcp");
            }
        }
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        Ok((
            command,
            Self {
                unit,
                uid,
                runtime,
                private_tmp,
                executable: input.executable,
                stamp: None,
                wrapper_exit: None,
            },
        ))
    }
    pub(crate) async fn attest_started(&mut self, end: Instant) -> Result<()> {
        if let Some(stamp) = &self.stamp {
            self.check_manager(end).await?;
            stamp.cgroup.attest_resource_limits()?;
            return self.attest_private_tmp();
        }
        let manager = self.manager(end).await?;
        loop {
            let properties = self.properties(end).await?;
            // The wrapper may not yet have sent StartTransientUnit when spawn
            // returns. Only observe the same owned unit until the original
            // deadline; never resend its start or infer cleanup from absence.
            if properties.load == "not-found" {
                if Instant::now() >= end {
                    return Err(ScopeError::Unknown);
                }
                tokio::time::sleep_until(end.min(Instant::now() + Duration::from_millis(10))).await;
                continue;
            }
            // A loaded but failed/dead service is not an uncreated unit.
            if properties.load != "loaded"
                || !matches!(properties.active.as_str(), "activating" | "active")
            {
                return Err(ScopeError::Unknown);
            }
            if properties.kill_mode != "control-group"
                || properties.delegate != "no"
                || properties.restart != "no"
                || !invocation(&properties.invocation)
            {
                return Err(ScopeError::Unsupported);
            }
            if properties.main_pid != 0 {
                let process = ProcessIdentity::observe(properties.main_pid)
                    .map_err(|_| ScopeError::Unknown)?;
                let proc = PathBuf::from(format!("/proc/{}", properties.main_pid));
                let executable =
                    std::fs::metadata(&self.executable).map_err(|_| ScopeError::Unknown)?;
                if let Ok(image) = std::fs::metadata(proc.join("exe"))
                    && image.dev() == executable.dev()
                    && image.ino() == executable.ino()
                {
                    if std::fs::metadata(&proc)
                        .map_err(|_| ScopeError::Unknown)?
                        .uid()
                        != self.uid
                    {
                        return Err(ScopeError::PermissionDenied);
                    }
                    let cgroup = self.open_cgroup(&properties.control_group)?;
                    let membership = std::fs::read_to_string(proc.join("cgroup"))
                        .map_err(|_| ScopeError::Unknown)?;
                    if !membership
                        .lines()
                        .any(|line| line == format!("0::{}", properties.control_group))
                        || !process.still_current().map_err(|_| ScopeError::Unknown)?
                    {
                        return Err(ScopeError::Unknown);
                    }
                    let after = self.manager(end).await?;
                    if !manager.same(&after) {
                        return Err(ScopeError::Unknown);
                    }
                    self.stamp = Some(Stamp {
                        manager,
                        invocation: properties.invocation,
                        cgroup,
                    });
                    // Preserve exact cleanup authority even when controllers
                    // are unavailable/misconfigured. No MCP tool is permitted
                    // until the original kernel cgroup proves all limits.
                    self.stamp
                        .as_ref()
                        .ok_or(ScopeError::Unknown)?
                        .cgroup
                        .attest_resource_limits()?;
                    self.attest_private_tmp()?;
                    return Ok(());
                }
            }
            if Instant::now() >= end {
                return Err(ScopeError::Unknown);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    /// Actual wrapper wait and original cgroup emptiness are both necessary.
    /// ACK/job acceptance alone never releases the physical executor lane.
    pub(crate) async fn stop_and_confirm(
        &mut self,
        child: &mut Child,
        budget: Duration,
    ) -> Result<ScopeCleanup> {
        let end = Instant::now() + budget.min(Duration::from_secs(30));
        if let Some(status) = child
            .try_wait()
            .map_err(|_| ScopeError::CleanupUnconfirmed)?
        {
            self.wrapper_exit = Some(status);
        }
        let wrapper_exited = self.wrapper_exit.is_some();
        let Some(stamp) = self.stamp.as_ref() else {
            return Ok(ScopeCleanup {
                wrapper_exited,
                confirmed: false,
                exit_success: self.wrapper_exit.map(|status| status.success()),
            });
        };
        self.check_manager(end).await?;
        let properties = self.properties(end).await?;
        if properties.load != "not-found" {
            if properties.invocation != stamp.invocation
                || (!properties.control_group.is_empty()
                    && properties.control_group != stamp.cgroup.control_group()?)
                || (properties.control_group.is_empty()
                    && (!inactive(&properties.active) || properties.main_pid != 0))
                || properties.kill_mode != "control-group"
                || properties.delegate != "no"
                || properties.restart != "no"
            {
                return Err(ScopeError::CleanupUnconfirmed);
            }
            if !inactive(&properties.active) {
                // Address the pinned unique owner, not a replacement manager.
                // systemd itself offers no expected-invocation CAS.
                let args = vec![
                    "--user".into(),
                    "call".into(),
                    stamp.manager.owner.clone().into(),
                    "/org/freedesktop/systemd1".into(),
                    "org.freedesktop.systemd1.Manager".into(),
                    "StopUnit".into(),
                    "ss".into(),
                    self.unit.clone().into(),
                    "replace".into(),
                ];
                let stopped = tool("/usr/bin/busctl", args, &self.runtime, end).await;
                if !matches!(stopped, Ok(output) if output.status.success()) {
                    // A captured cgroup.kill file can only address the original
                    // kernel cgroup. Never reopen a path or kill a guessed PID.
                    if !stamp.cgroup.kill_original()? {
                        return Err(ScopeError::CleanupUnconfirmed);
                    }
                }
            }
        }
        loop {
            let properties = self.properties(end).await?;
            let stamp = self.stamp.as_ref().ok_or(ScopeError::CleanupUnconfirmed)?;
            let gone = properties.load == "not-found";
            if !gone && properties.invocation != stamp.invocation {
                return Err(ScopeError::CleanupUnconfirmed);
            }
            let quiescent = gone || (inactive(&properties.active) && properties.main_pid == 0);
            if quiescent && stamp.cgroup.empty()? {
                self.check_manager(end).await?;
                if let Ok(Ok(status)) = timeout_at(end, child.wait()).await {
                    self.wrapper_exit = Some(status);
                }
                let wrapper_exited = self.wrapper_exit.is_some();
                return Ok(ScopeCleanup {
                    wrapper_exited,
                    confirmed: wrapper_exited,
                    exit_success: self.wrapper_exit.map(|status| status.success()),
                });
            }
            if Instant::now() >= end {
                if let Some(status) = child
                    .try_wait()
                    .map_err(|_| ScopeError::CleanupUnconfirmed)?
                {
                    self.wrapper_exit = Some(status);
                }
                return Ok(ScopeCleanup {
                    wrapper_exited: self.wrapper_exit.is_some(),
                    confirmed: false,
                    exit_success: self.wrapper_exit.map(|status| status.success()),
                });
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    fn attest_private_tmp(&self) -> Result<()> {
        // This path is generated only from actual UID and the same random
        // unit stem, never from a request or a long workspace/output path.
        let before =
            std::fs::symlink_metadata(&self.private_tmp).map_err(|_| ScopeError::Unsupported)?;
        if !before.is_dir()
            || before.uid() != self.uid
            || before.mode() & 0o777 != 0o700
            || std::fs::canonicalize(&self.private_tmp).map_err(|_| ScopeError::Unsupported)?
                != self.private_tmp
        {
            return Err(ScopeError::Unsupported);
        }
        let directory = open_directory(&self.private_tmp)?;
        let opened = directory.metadata().map_err(|_| ScopeError::Unknown)?;
        if opened.dev() != before.dev()
            || opened.ino() != before.ino()
            || opened.uid() != self.uid
            || opened.mode() & 0o777 != 0o700
        {
            return Err(ScopeError::Unknown);
        }
        Ok(())
    }
    async fn check_manager(&self, end: Instant) -> Result<()> {
        let stamp = self.stamp.as_ref().ok_or(ScopeError::CleanupUnconfirmed)?;
        if stamp.manager.same(&self.manager(end).await?) {
            Ok(())
        } else {
            Err(ScopeError::CleanupUnconfirmed)
        }
    }
    async fn manager(&self, end: Instant) -> Result<Manager> {
        let dir = std::fs::symlink_metadata(&self.runtime).map_err(|_| ScopeError::Unsupported)?;
        if !dir.is_dir() || dir.uid() != self.uid || dir.mode() & 0o077 != 0 {
            return Err(ScopeError::Unsupported);
        }
        let bus_path = self.runtime.join("bus");
        let before = std::fs::symlink_metadata(&bus_path).map_err(|_| ScopeError::Unsupported)?;
        use std::os::unix::fs::FileTypeExt;
        if !before.file_type().is_socket() || before.uid() != self.uid {
            return Err(ScopeError::Unsupported);
        }
        let stream = timeout_at(end, UnixStream::connect(&bus_path))
            .await
            .map_err(|_| ScopeError::Unknown)?
            .map_err(|_| ScopeError::Unsupported)?;
        let credential = stream.peer_cred().map_err(|_| ScopeError::Unsupported)?;
        if credential.uid() != self.uid {
            return Err(ScopeError::Unsupported);
        }
        let bus_pid = credential
            .pid()
            .and_then(|pid| u32::try_from(pid).ok())
            .ok_or(ScopeError::Unsupported)?;
        let bus_peer = ProcessIdentity::observe(bus_pid).map_err(|_| ScopeError::Unsupported)?;
        drop(stream);
        let after = std::fs::symlink_metadata(&bus_path).map_err(|_| ScopeError::Unknown)?;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(ScopeError::Unknown);
        }
        let owner = self
            .bus("GetNameOwner", "s", "org.freedesktop.systemd1", end)
            .await?;
        let owner: String =
            serde_json::from_str(owner.strip_prefix("s ").ok_or(ScopeError::Unsupported)?)
                .map_err(|_| ScopeError::Unsupported)?;
        if owner.len() > 128
            || !owner.starts_with(':')
            || !owner[1..].bytes().all(|b| b.is_ascii_digit() || b == b'.')
        {
            return Err(ScopeError::Unsupported);
        }
        let uid = self.bus("GetConnectionUnixUser", "s", &owner, end).await?;
        if number(&uid)? != self.uid {
            return Err(ScopeError::Unsupported);
        }
        let pid = number(
            &self
                .bus("GetConnectionUnixProcessID", "s", &owner, end)
                .await?,
        )?;
        let process = ProcessIdentity::observe(pid).map_err(|_| ScopeError::Unsupported)?;
        if std::fs::metadata(format!("/proc/{pid}"))
            .map_err(|_| ScopeError::Unsupported)?
            .uid()
            != self.uid
        {
            return Err(ScopeError::Unsupported);
        }
        Ok(Manager {
            owner,
            process,
            bus_peer,
            bus_inode: before.ino(),
            bus_device: before.dev(),
        })
    }
    async fn bus(
        &self,
        method: &str,
        signature: &str,
        value: &str,
        end: Instant,
    ) -> Result<String> {
        let args = [
            "--user",
            "call",
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            method,
            signature,
            value,
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        let output = tool("/usr/bin/busctl", args, &self.runtime, end).await?;
        if !output.status.success() {
            return Err(ScopeError::Unsupported);
        }
        String::from_utf8(output.stdout)
            .map(|s| s.trim().to_owned())
            .map_err(|_| ScopeError::Unsupported)
    }
    async fn properties(&self, end: Instant) -> Result<Properties> {
        let args = vec![
            "--user".into(),
            "show".into(),
            "--no-pager".into(),
            "--property=LoadState,ActiveState,InvocationID,ControlGroup,MainPID,KillMode,Delegate,Restart"
                .into(),
            self.unit.clone().into(),
        ];
        let output = tool("/usr/bin/systemctl", args, &self.runtime, end).await?;
        // LoadState=not-found is explicit machine evidence even if show exits
        // nonzero. No stderr phrase or exit code is interpreted as absence.
        let properties = parse_properties(&output.stdout)?;
        if !output.status.success() && properties.load != "not-found" {
            return Err(ScopeError::Unknown);
        }
        Ok(properties)
    }
    fn open_cgroup(&self, control_group: &str) -> Result<Cgroup> {
        let path = checked_cgroup(control_group, self.uid, &self.unit)?;
        let root = open_directory(Path::new("/sys/fs/cgroup"))?;
        if nix::sys::statfs::fstatfs(&root)
            .map_err(|_| ScopeError::Unsupported)?
            .filesystem_type()
            != nix::sys::statfs::CGROUP2_SUPER_MAGIC
            || root.metadata().map_err(|_| ScopeError::Unsupported)?.uid() != 0
        {
            return Err(ScopeError::Unsupported);
        }
        let mut current = PathBuf::from("/sys/fs/cgroup");
        for component in Path::new(control_group).components() {
            if let Component::Normal(part) = component {
                current.push(part);
                let _pin = open_directory(&current)?;
            }
        }
        let directory = open_directory(&path)?;
        if nix::sys::statfs::fstatfs(&directory)
            .map_err(|_| ScopeError::Unsupported)?
            .filesystem_type()
            != nix::sys::statfs::CGROUP2_SUPER_MAGIC
        {
            return Err(ScopeError::Unsupported);
        }
        let meta = directory.metadata().map_err(|_| ScopeError::Unknown)?;
        let anchored = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
        let events = open_nofollow(&anchored.join("cgroup.events"), false)?;
        let kill = open_nofollow(&anchored.join("cgroup.kill"), true).ok();
        Ok(Cgroup {
            path,
            directory,
            events,
            kill,
            device: meta.dev(),
            inode: meta.ino(),
        })
    }
}
impl Manager {
    fn same(&self, other: &Self) -> bool {
        self.owner == other.owner
            && self.process == other.process
            && self.bus_peer == other.bus_peer
            && self.bus_inode == other.bus_inode
            && self.bus_device == other.bus_device
    }
}
impl Cgroup {
    fn attest_resource_limits(&self) -> Result<()> {
        if nix::sys::statfs::fstatfs(&self.directory)
            .map_err(|_| ScopeError::Unsupported)?
            .filesystem_type()
            != nix::sys::statfs::CGROUP2_SUPER_MAGIC
            || self
                .directory
                .metadata()
                .map_err(|_| ScopeError::Unknown)?
                .nlink()
                == 0
        {
            return Err(ScopeError::Unsupported);
        }
        // Resolve each fixed kernel file through the captured original cgroup
        // directory, never an arbitrary/new cgroup path. Kernel files are tiny;
        // absent delegation or any differing limit refuses native dispatch.
        let anchored = PathBuf::from(format!("/proc/self/fd/{}", self.directory.as_raw_fd()));
        for (name, expected) in [
            ("memory.max", "2147483648\n"),
            ("memory.swap.max", "0\n"),
            ("pids.max", "256\n"),
        ] {
            let file = open_nofollow(&anchored.join(name), false)?;
            let mut bytes = Vec::with_capacity(65);
            file.take(65)
                .read_to_end(&mut bytes)
                .map_err(|_| ScopeError::Unknown)?;
            if bytes.as_slice() != expected.as_bytes() {
                return Err(ScopeError::Unsupported);
            }
        }
        Ok(())
    }
    fn control_group(&self) -> Result<String> {
        self.path
            .strip_prefix("/sys/fs/cgroup")
            .map(|p| format!("/{}", p.display()))
            .map_err(|_| ScopeError::CleanupUnconfirmed)
    }
    fn empty(&self) -> Result<bool> {
        let metadata = self
            .directory
            .metadata()
            .map_err(|_| ScopeError::CleanupUnconfirmed)?;
        if metadata.dev() != self.device
            || metadata.ino() != self.inode
            || nix::sys::statfs::fstatfs(&self.directory)
                .map_err(|_| ScopeError::CleanupUnconfirmed)?
                .filesystem_type()
                != nix::sys::statfs::CGROUP2_SUPER_MAGIC
        {
            return Err(ScopeError::CleanupUnconfirmed);
        }
        if metadata.nlink() == 0 {
            return Ok(true);
        }
        match std::fs::symlink_metadata(&self.path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(ScopeError::CleanupUnconfirmed);
            }
            Ok(current) if current.dev() == self.device && current.ino() == self.inode => {}
            _ => return Err(ScopeError::CleanupUnconfirmed),
        }
        let mut file = &self.events;
        file.seek(SeekFrom::Start(0))
            .map_err(|_| ScopeError::CleanupUnconfirmed)?;
        let mut text = String::new();
        file.take(4097)
            .read_to_string(&mut text)
            .map_err(|_| ScopeError::CleanupUnconfirmed)?;
        if text.len() > 4096 {
            return Err(ScopeError::CleanupUnconfirmed);
        }
        match text
            .lines()
            .find_map(|line| line.strip_prefix("populated "))
        {
            Some("0") => Ok(true),
            Some("1") => Ok(false),
            _ => Err(ScopeError::CleanupUnconfirmed),
        }
    }
    fn kill_original(&self) -> Result<bool> {
        let Some(file) = &self.kill else {
            return Ok(false);
        };
        if nix::sys::statfs::fstatfs(file)
            .map_err(|_| ScopeError::CleanupUnconfirmed)?
            .filesystem_type()
            != nix::sys::statfs::CGROUP2_SUPER_MAGIC
        {
            return Err(ScopeError::CleanupUnconfirmed);
        }
        use std::io::Write;
        let mut file = file;
        file.write_all(b"1\n")
            .map_err(|_| ScopeError::CleanupUnconfirmed)?;
        Ok(true)
    }
}
fn inactive(state: &str) -> bool {
    matches!(state, "inactive" | "failed")
}
fn invocation(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && value != "00000000000000000000000000000000"
}
fn number(value: &str) -> Result<u32> {
    value
        .strip_prefix("u ")
        .ok_or(ScopeError::Unsupported)?
        .parse()
        .map_err(|_| ScopeError::Unsupported)
}
fn checked_cgroup(value: &str, uid: u32, unit: &str) -> Result<PathBuf> {
    let prefix = format!("/user.slice/user-{uid}.slice/user@{uid}.service/");
    if value.len() > 4096
        || !value.starts_with(&prefix)
        || !value.ends_with(&format!("/{unit}"))
        || value.contains("//")
        || value.chars().any(char::is_control)
        || Path::new(value)
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(ScopeError::Unsupported);
    }
    Ok(Path::new("/sys/fs/cgroup").join(value.trim_start_matches('/')))
}
fn open_directory(path: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY)
        .open(path)
        .map_err(|_| ScopeError::Unsupported)
}
fn open_nofollow(path: &Path, write: bool) -> Result<File> {
    OpenOptions::new()
        .read(!write)
        .write(write)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| ScopeError::Unsupported)
}
struct Properties {
    load: String,
    active: String,
    invocation: String,
    control_group: String,
    main_pid: u32,
    kill_mode: String,
    delegate: String,
    restart: String,
}
fn parse_properties(bytes: &[u8]) -> Result<Properties> {
    let text = std::str::from_utf8(bytes).map_err(|_| ScopeError::Unknown)?;
    let mut fields = std::collections::BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line.split_once('=').ok_or(ScopeError::Unknown)?;
        if fields.insert(key, value).is_some() {
            return Err(ScopeError::Unknown);
        }
    }
    let get = |key| fields.get(key).copied().ok_or(ScopeError::Unknown);
    Ok(Properties {
        load: get("LoadState")?.into(),
        active: get("ActiveState")?.into(),
        invocation: get("InvocationID")?.into(),
        control_group: get("ControlGroup")?.into(),
        main_pid: get("MainPID")?.parse().map_err(|_| ScopeError::Unknown)?,
        kill_mode: get("KillMode")?.into(),
        delegate: get("Delegate")?.into(),
        restart: get("Restart")?.into(),
    })
}
fn fixed_environment(command: &mut Command, runtime: &Path) {
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
struct ToolOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
}
/// Mature CLI protocols run in one bounded, owned subprocess at a time. A
/// cancelled waiter cannot drop a still-running control child or its slot.
async fn tool(
    binary: &'static str,
    args: Vec<OsString>,
    runtime: &Path,
    end: Instant,
) -> Result<ToolOutput> {
    if Instant::now() >= end {
        return Err(ScopeError::CleanupUnconfirmed);
    }
    let permit = TOOL_SLOT
        .clone()
        .try_acquire_owned()
        .map_err(|_| ScopeError::Busy)?;
    let mut command = Command::new(binary);
    fixed_environment(&mut command, runtime);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().map_err(|_| ScopeError::Unsupported)?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let stop = CancellationToken::new();
    let guard = stop.clone().drop_guard();
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let _permit = permit;
        let mut stdout = stdout;
        let mut stderr = stderr;
        let mut out = vec![0u8; STDOUT_BYTES + 1];
        let mut err = vec![0u8; STDERR_BYTES + 1];
        let until = end.min(Instant::now() + Duration::from_secs(2));
        let result = tokio::select! {
            _=stop.cancelled()=>Err(ScopeError::CleanupUnconfirmed),
            result=timeout_at(until,async {
                let (a,b,status)=tokio::join!(read_optional(&mut stdout,&mut out),read_optional(&mut stderr,&mut err),child.wait());
                let used=a?;b?;let status=status.map_err(|_|ScopeError::Unknown)?;out.truncate(used);Ok(ToolOutput {status,stdout:out})
            })=>result.unwrap_or(Err(ScopeError::CleanupUnconfirmed)),
        };
        drop(stdout);
        drop(stderr);
        if result.is_err() {
            let _ = child.start_kill();
            if !matches!(
                timeout_at(Instant::now() + Duration::from_millis(500), child.wait()).await,
                Ok(Ok(_))
            ) {
                let _ = tx.send(Err(ScopeError::CleanupUnconfirmed));
                // Retain the exact owned child and single command slot after
                // returning Unknown, until actual kernel wait succeeds.
                while child.wait().await.is_err() {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                return;
            }
        }
        let _ = tx.send(result);
    });
    let result = rx.await.map_err(|_| ScopeError::CleanupUnconfirmed)?;
    guard.disarm();
    result
}
async fn read_optional<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut Option<R>,
    bytes: &mut [u8],
) -> Result<usize> {
    match reader {
        Some(reader) => read_bounded(reader, bytes).await,
        None => Err(ScopeError::Unknown),
    }
}
async fn read_bounded(
    reader: &mut (impl tokio::io::AsyncRead + Unpin),
    bytes: &mut [u8],
) -> Result<usize> {
    let mut used = 0;
    loop {
        let n = reader
            .read(&mut bytes[used..])
            .await
            .map_err(|_| ScopeError::Unknown)?;
        if n == 0 {
            return Ok(used);
        }
        used += n;
        if used == bytes.len() {
            return Err(ScopeError::Unknown);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_machine_identity_fields_reject_ambiguous_targets() {
        let unit = "styx-browser-0123456789abcdef0123456789abcdef.service";
        assert!(
            checked_cgroup(
                &format!("/user.slice/user-1000.slice/user@1000.service/app.slice/{unit}"),
                1000,
                unit
            )
            .is_ok()
        );
        for value in [
            format!("/user.slice/user-1001.slice/user@1001.service/app.slice/{unit}"),
            format!("/user.slice/user-1000.slice/user@1000.service/../{unit}"),
            format!("/tmp/{unit}"),
        ] {
            assert!(checked_cgroup(&value, 1000, unit).is_err());
        }
        assert!(!invocation("00000000000000000000000000000000"));
        assert!(invocation("0123456789abcdef0123456789abcdef"));
        assert!(parse_properties(b"LoadState=loaded\nLoadState=not-found\n").is_err());
    }
}
