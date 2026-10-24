//! Linux discovery runs in a bounded, caller-owned process, never in Core's
//! address space. Its result remains unverified desktop candidates.
use crate::platform::linux::{self, Association, DiscoveryError, LinuxDiscoverySnapshot};
use std::{
    fs::File,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::PathBuf,
    process::Stdio,
    sync::{Arc, LazyLock},
    time::Duration,
};
use tokio::{
    io::AsyncReadExt,
    process::{Child, Command},
    sync::{Semaphore, oneshot},
    time::{Instant, timeout_at},
};
use tokio_util::sync::CancellationToken;

const MAX_OUTPUT: usize = 64 * 1024;
const WORK_TIME: Duration = Duration::from_millis(1500);
const CLEANUP_TIME: Duration = Duration::from_millis(500);
static SLOT: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(1)));

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProbeError {
    #[error("session_probe_busy")]
    Busy,
    #[error("session_probe_spawn_failed")]
    Spawn,
    #[error("session_probe_deadline")]
    Deadline,
    #[error("session_probe_output_too_large")]
    OutputTooLarge,
    #[error("session_probe_invalid_facts")]
    InvalidFacts,
    #[error("session_probe_worker_failed")]
    WorkerFailed,
    #[error("session_probe_cleanup_unconfirmed")]
    CleanupUnconfirmed,
    #[error("session_probe_cancelled")]
    Cancelled,
    #[error("session_probe_limit_failed")]
    Limits,
    #[error("session_probe_discovery_rejected")]
    Discovery(DiscoveryError),
}
impl ProbeError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Busy => "session_probe_busy",
            Self::Spawn => "session_probe_spawn_failed",
            Self::Deadline => "session_probe_deadline",
            Self::OutputTooLarge => "session_probe_output_too_large",
            Self::InvalidFacts => "session_probe_invalid_facts",
            Self::WorkerFailed => "session_probe_worker_failed",
            Self::CleanupUnconfirmed => "session_probe_cleanup_unconfirmed",
            Self::Cancelled => "session_probe_cancelled",
            Self::Limits => "session_probe_limit_failed",
            Self::Discovery(error) => match error {
                DiscoveryError::Deadline => "discovery_deadline",
                DiscoveryError::Unavailable => "system_bus_unavailable",
                DiscoveryError::UntrustedPeer => "untrusted_system_bus_peer",
                DiscoveryError::OwnerChanged => "login_owner_changed",
                DiscoveryError::SessionChanged => "session_changed_during_snapshot",
                DiscoveryError::InvalidFacts => "invalid_login_facts",
                DiscoveryError::Capacity => "discovery_capacity",
                DiscoveryError::CloseUnconfirmed => "system_bus_close_unconfirmed",
            },
        }
    }
}
/// Internal stdout refusal: an exact typed cause, never peer error text.
/// Only exit code 2 plus this complete schema is interpreted as discovery refusal.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerRefusal {
    schema: u16,
    error: DiscoveryError,
}
impl WorkerRefusal {
    pub fn from_error(error: DiscoveryError) -> Self {
        Self { schema: 1, error }
    }
}
/// Only the hidden worker calls this, before creating any Tokio runtime.
/// AS is virtual address space, DATA is Linux allocator/mmap data; neither is
/// described as a per-message cap or a measurement of RSS.
pub fn prepare_worker_limits() -> Result<(), ProbeError> {
    use nix::sys::resource::{Resource, getrlimit, setrlimit};
    let parent: u32 = std::env::var("STYX_INTERNAL_PROBE_PARENT_PID")
        .map_err(|_| ProbeError::Limits)?
        .parse()
        .map_err(|_| ProbeError::Limits)?;
    let birth: u64 = std::env::var("STYX_INTERNAL_PROBE_PARENT_BIRTH")
        .map_err(|_| ProbeError::Limits)?
        .parse()
        .map_err(|_| ProbeError::Limits)?;
    check_parent(parent, birth)?;
    nix::sys::prctl::set_pdeathsig(nix::sys::signal::Signal::SIGKILL)
        .map_err(|_| ProbeError::Limits)?;
    check_parent(parent, birth)?;
    for (resource, soft, hard) in [
        (Resource::RLIMIT_AS, 512 * 1024 * 1024, 512 * 1024 * 1024),
        (Resource::RLIMIT_DATA, 96 * 1024 * 1024, 96 * 1024 * 1024),
        (Resource::RLIMIT_CPU, 2, 3),
        (Resource::RLIMIT_NOFILE, 32, 32),
        (Resource::RLIMIT_CORE, 0, 0),
    ] {
        let (old_soft, old_hard) = getrlimit(resource).map_err(|_| ProbeError::Limits)?;
        let hard = old_hard.min(hard);
        setrlimit(resource, old_soft.min(soft).min(hard), hard).map_err(|_| ProbeError::Limits)?;
    }
    Ok(())
}
fn check_parent(pid: u32, birth: u64) -> Result<(), ProbeError> {
    if u32::try_from(nix::unistd::getppid().as_raw()).ok() != Some(pid) {
        return Err(ProbeError::Limits);
    }
    match crate::store::ProcessIdentity::observe(pid).map_err(|_| ProbeError::Limits)? {
        crate::store::ProcessIdentity::Linux {
            pid: actual,
            start_ticks,
            ..
        } if actual == pid && start_ticks == birth => Ok(()),
        _ => Err(ProbeError::Limits),
    }
}
/// Worker-only operation. It never calls the parent runner recursively.
pub async fn worker_snapshot() -> Result<LinuxDiscoverySnapshot, ProbeError> {
    linux::discover_candidates(nix::unistd::Uid::current().as_raw())
        .await
        .map_err(ProbeError::Discovery)
}
struct PinnedWorker {
    _image: File,
    launch: PathBuf,
    args: Vec<std::ffi::OsString>,
    #[cfg(test)]
    environment: std::collections::BTreeMap<String, String>,
    #[cfg(test)]
    observed_exit: Option<Arc<std::sync::Mutex<Option<std::process::ExitStatus>>>>,
}
impl PinnedWorker {
    fn current() -> Result<Self, ProbeError> {
        let image = File::open("/proc/self/exe").map_err(|_| ProbeError::Spawn)?;
        if !image.metadata().map_err(|_| ProbeError::Spawn)?.is_file() {
            return Err(ProbeError::Spawn);
        }
        let launch = PathBuf::from(format!(
            "/proc/{}/fd/{}",
            std::process::id(),
            image.as_raw_fd()
        ));
        Ok(Self {
            _image: image,
            launch,
            args: vec!["__linux-desktop-probe".into()],
            #[cfg(test)]
            environment: Default::default(),
            #[cfg(test)]
            observed_exit: None,
        })
    }
}
/// The public caller supplies no executable, UID, socket or environment.
/// Dropping its future cancels only the waiter; an owned job keeps the process,
/// image pin and single slot until wait() actually confirms reaping.
pub async fn probe_current_user() -> Result<LinuxDiscoverySnapshot, ProbeError> {
    run(
        PinnedWorker::current()?,
        nix::unistd::Uid::current().as_raw(),
    )
    .await
}
async fn run(image: PinnedWorker, uid: u32) -> Result<LinuxDiscoverySnapshot, ProbeError> {
    run_with(image, move |output, _end| async move {
        decode_snapshot(output, uid)
    })
    .await
}
/// Raw output can only be minted after this exact owned child was waited.
/// Private completion keeps the original image pin and shared slot until any
/// bounded native revalidation is joined; it is not a network decoder port.
struct WorkerOutput {
    bytes: Vec<u8>,
    status: std::process::ExitStatus,
}
async fn run_with<T, F, Fut>(image: PinnedWorker, complete: F) -> Result<T, ProbeError>
where
    T: Send + 'static,
    F: FnOnce(WorkerOutput, Instant) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<T, ProbeError>> + Send + 'static,
{
    let permit = SLOT
        .clone()
        .try_acquire_owned()
        .map_err(|_| ProbeError::Busy)?;
    let stop = CancellationToken::new();
    let guard = stop.clone().drop_guard();
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let _permit = permit;
        let _image_pin = &image;
        let mut reply = Some(tx);
        if stop.is_cancelled() {
            respond(&mut reply, Err(ProbeError::Cancelled));
            return;
        }
        let image_before = match image._image.metadata() {
            Ok(metadata) => metadata,
            Err(_) => {
                respond(&mut reply, Err(ProbeError::Spawn));
                return;
            }
        };
        let parent = match crate::store::ProcessIdentity::current() {
            Ok(parent) => parent,
            Err(_) => {
                respond(&mut reply, Err(ProbeError::Spawn));
                return;
            }
        };
        let crate::store::ProcessIdentity::Linux {
            pid: parent_pid,
            start_ticks: parent_birth,
            ..
        } = parent;
        let started = Instant::now();
        let mut command = Command::new(&image.launch);
        command
            .args(&image.args)
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .stdout(Stdio::piped())
            .kill_on_drop(true);
        #[cfg(test)]
        command.envs(&image.environment);
        command
            .env("STYX_INTERNAL_PROBE_PARENT_PID", parent_pid.to_string())
            .env("STYX_INTERNAL_PROBE_PARENT_BIRTH", parent_birth.to_string());
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(_) => {
                respond(&mut reply, Err(ProbeError::Spawn));
                return;
            }
        };
        let Some(mut stdout) = child.stdout.take() else {
            cleanup(&mut child, started + WORK_TIME + CLEANUP_TIME, &mut reply).await;
            respond(&mut reply, Err(ProbeError::WorkerFailed));
            return;
        };
        let result = tokio::select! {
            _ = stop.cancelled() => Err(ProbeError::Cancelled),
            result = timeout_at(started + WORK_TIME, collect_output(&mut child, &mut stdout)) =>
                result.unwrap_or(Err(ProbeError::Deadline)),
        };
        drop(stdout);
        if result.is_err() {
            cleanup(&mut child, Instant::now() + CLEANUP_TIME, &mut reply).await;
        }
        #[cfg(test)]
        if let Some(observer) = &image.observed_exit
            && let Ok(Some(status)) = child.try_wait()
            && let Ok(mut observed) = observer.lock()
        {
            *observed = Some(status);
        }
        let result = match result {
            Ok(output) => complete(output, started + WORK_TIME + CLEANUP_TIME).await,
            Err(error) => Err(error),
        };
        let result = if image._image.metadata().is_ok_and(|after| {
            (
                after.dev(),
                after.ino(),
                after.size(),
                after.mtime(),
                after.mtime_nsec(),
                after.ctime(),
                after.ctime_nsec(),
            ) == (
                image_before.dev(),
                image_before.ino(),
                image_before.size(),
                image_before.mtime(),
                image_before.mtime_nsec(),
                image_before.ctime(),
                image_before.ctime_nsec(),
            )
        }) {
            result
        } else {
            Err(ProbeError::InvalidFacts)
        };
        respond(&mut reply, result);
        // image remains in this task until actual child wait/cleanup finishes.
        drop(image);
    });
    let result = rx.await.unwrap_or(Err(ProbeError::CleanupUnconfirmed));
    guard.disarm();
    result
}
fn respond<T>(
    reply: &mut Option<oneshot::Sender<Result<T, ProbeError>>>,
    result: Result<T, ProbeError>,
) {
    if let Some(tx) = reply.take() {
        let _ = tx.send(result);
    }
}
async fn cleanup<T>(
    child: &mut Child,
    end: Instant,
    reply: &mut Option<oneshot::Sender<Result<T, ProbeError>>>,
) {
    let _ = child.start_kill();
    if matches!(timeout_at(end, child.wait()).await, Ok(Ok(_))) {
        return;
    }
    respond(reply, Err(ProbeError::CleanupUnconfirmed));
    // No release on the cleanup deadline: keep ownership and capacity fenced
    // until the kernel confirms this exact owned Child was reaped.
    loop {
        let _ = child.start_kill();
        if child.wait().await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
async fn collect_output(
    child: &mut Child,
    stdout: &mut tokio::process::ChildStdout,
) -> Result<WorkerOutput, ProbeError> {
    let mut bytes = vec![0u8; MAX_OUTPUT + 1];
    let mut used = 0;
    loop {
        let n = stdout
            .read(&mut bytes[used..])
            .await
            .map_err(|_| ProbeError::WorkerFailed)?;
        if n == 0 {
            break;
        }
        used += n;
        if used > MAX_OUTPUT {
            return Err(ProbeError::OutputTooLarge);
        }
    }
    let status = child
        .wait()
        .await
        .map_err(|_| ProbeError::CleanupUnconfirmed)?;
    bytes.truncate(used);
    Ok(WorkerOutput { bytes, status })
}
fn decode_snapshot(output: WorkerOutput, uid: u32) -> Result<LinuxDiscoverySnapshot, ProbeError> {
    let WorkerOutput { bytes, status } = output;
    if !status.success() {
        if status.code() == Some(2)
            && let Ok(refusal) = serde_json::from_slice::<WorkerRefusal>(&bytes)
            && refusal.schema == 1
        {
            return Err(ProbeError::Discovery(refusal.error));
        }
        return Err(ProbeError::WorkerFailed);
    }
    let snapshot = serde_json::from_slice(&bytes).map_err(|_| ProbeError::InvalidFacts)?;
    validate(snapshot, uid)
}
fn field(s: &str) -> bool {
    s.len() <= 256 && !s.chars().any(char::is_control)
}
fn candidate_shape(c: &linux::LinuxCandidate, uid: u32) -> bool {
    c.uid == uid
        && !c.session_id.is_empty()
        && field(&c.session_id)
        && c.leader_pid != 0
        && c.leader_birth != 0
        && matches!(c.backend.as_str(), "wayland" | "x11")
        && field(&c.state)
        && !c.state.is_empty()
        && c.seat.as_ref().is_none_or(|s| !s.is_empty() && field(s))
        && c.agent_association == Association::Unknown
        && c.compositor_association == Association::Unknown
}
fn validate(
    snapshot: LinuxDiscoverySnapshot,
    uid: u32,
) -> Result<LinuxDiscoverySnapshot, ProbeError> {
    if snapshot.schema != 1
        || !snapshot.connection_closed
        || snapshot.candidates.len() > 32
        || !field(&snapshot.login_unique_owner)
        || zbus::names::UniqueName::try_from(snapshot.login_unique_owner.as_str()).is_err()
    {
        return Err(ProbeError::InvalidFacts);
    }
    let mut ids = std::collections::BTreeSet::new();
    for c in &snapshot.candidates {
        if !candidate_shape(c, uid) || !ids.insert(c.session_id.clone()) {
            return Err(ProbeError::InvalidFacts);
        }
    }
    Ok(snapshot)
}
#[cfg(test)]
mod tests;

pub mod watch;

/// Same-image read-only selected Desktop association worker.
pub mod association;
