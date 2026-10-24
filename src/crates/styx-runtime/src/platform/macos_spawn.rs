//! Darwin native-image launch. START_SUSPENDED is a verification barrier, not readiness.
//! Only the direct parent reaps this child; cancellation requests termination but never
//! substitutes an acknowledgement for waitpid. Business descendants belong to Host cleanup.
use crate::store::{PinnedExecutable, ProcessIdentity};
use nix::{
    spawn::{PosixSpawnAttr, PosixSpawnFileActions, PosixSpawnFlags, posix_spawn},
    sys::{
        signal::{Signal, kill},
        wait::{WaitPidFlag, WaitStatus, waitpid},
    },
    unistd::Pid,
};
use security_framework::os::macos::code_signing::{
    Flags, GuestAttributes, SecCode, SecRequirement,
};
use std::{
    collections::BTreeMap,
    ffi::{CString, OsString},
    io,
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::{ffi::OsStrExt, process::ExitStatusExt},
    },
    path::PathBuf,
    process::ExitStatus,
    str::FromStr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    process::{ChildStderr, ChildStdin, ChildStdout},
    sync::Mutex as AsyncMutex,
    task::JoinHandle,
};

pub struct SpawnFailure {
    pub code: &'static str,
    child: Option<SuspendedChild>,
}
impl SpawnFailure {
    pub fn into_owned_child(self) -> Option<SuspendedChild> {
        self.child
    }
}
impl std::fmt::Debug for SpawnFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpawnFailure")
            .field("code", &self.code)
            .field("retains_child", &self.child.is_some())
            .finish()
    }
}
fn refused(code: &'static str) -> SpawnFailure {
    SpawnFailure { code, child: None }
}
struct Facts {
    birth: Option<ProcessIdentity>,
    exit: Option<ExitStatus>,
    wait_unknown: bool,
}
struct Shared {
    pid: Pid,
    facts: Mutex<Facts>,
    terminate: AtomicBool,
    joined: AtomicBool,
    // Retain the trusted source even if the public waiter is dropped.
    _image: Arc<PinnedExecutable>,
}
#[derive(Clone, Debug)]
pub struct ChildReceipt {
    pub pid: u32,
    pub birth: Option<ProcessIdentity>,
    pub actual_wait: bool,
    pub supervisor_joined: bool,
    pub exit_success: Option<bool>,
}
pub struct RunningChild {
    shared: Arc<Shared>,
    supervisor: AsyncMutex<Option<JoinHandle<()>>>,
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
}
pub struct SuspendedChild {
    child: Option<RunningChild>,
    path: PathBuf,
    cdhash: Vec<u8>,
}

#[allow(unsafe_code)]
mod darwin_file_actions {
    use nix::spawn::PosixSpawnFileActions;
    use std::ffi::CStr;

    // nix 0.31.3 spawn.rs:229 declares this wrapper repr(transparent), with
    // its sole libc::posix_spawn_file_actions_t field. Darwin's official
    // addchdir_np operates on that initialized object; no OS layout is copied.
    unsafe extern "C" {
        fn posix_spawn_file_actions_addchdir_np(
            actions: *mut nix::libc::posix_spawn_file_actions_t,
            path: *const nix::libc::c_char,
        ) -> nix::libc::c_int;
    }
    pub(super) fn chdir(actions: &mut PosixSpawnFileActions, path: &CStr) -> Result<(), i32> {
        // SAFETY: initialized transparent pinned-version nix wrapper and live CStr.
        let result = unsafe {
            posix_spawn_file_actions_addchdir_np(
                (actions as *mut PosixSpawnFileActions).cast(),
                path.as_ptr(),
            )
        };
        if result == 0 { Ok(()) } else { Err(result) }
    }
}
fn cstring(value: &std::ffi::OsStr) -> Result<CString, SpawnFailure> {
    CString::new(value.as_bytes()).map_err(|_| refused("invalid_spawn_argument"))
}
fn io_error() -> io::Error {
    io::Error::other("darwin_child_wait_unconfirmed")
}

/// Must run on the existing bounded blocking worker with a Tokio runtime entered.
/// args excludes argv[0]. Environment is complete: nothing is inherited.
pub fn spawn_suspended(
    image: Arc<PinnedExecutable>,
    args: Vec<OsString>,
    cwd: PathBuf,
    env: BTreeMap<OsString, OsString>,
) -> Result<SuspendedChild, SpawnFailure> {
    // The only production caller supplies fixed executor arguments. Bound this
    // OS boundary before CString/environment allocation nevertheless.
    if args.len() > 64 || env.len() > 64 || cwd.as_os_str().as_bytes().len() > 4096 {
        return Err(refused("invalid_spawn_input"));
    }
    let mut supplied_bytes = 0usize;
    for bytes in args.iter().map(|value| value.as_bytes()).chain(
        env.iter()
            .flat_map(|(key, value)| [key.as_bytes(), value.as_bytes()]),
    ) {
        if bytes.len() > 8192 {
            return Err(refused("invalid_spawn_input"));
        }
        supplied_bytes = supplied_bytes
            .checked_add(bytes.len())
            .ok_or_else(|| refused("invalid_spawn_input"))?;
        if supplied_bytes > 65536 {
            return Err(refused("invalid_spawn_input"));
        }
    }
    let runtime =
        tokio::runtime::Handle::try_current().map_err(|_| refused("runtime_unavailable"))?;
    image.revalidate().map_err(|_| refused("image_changed"))?;
    let path = image
        .source_path_for_suspended_spawn()
        .map_err(|_| refused("image_unavailable"))?;
    let cdhash = image
        .expected_cdhash()
        .map_err(|_| refused("image_signature_invalid"))?;
    if !matches!(cdhash.len(), 20 | 32) || !cwd.is_absolute() {
        return Err(refused("invalid_spawn_input"));
    }
    let executable = cstring(path.as_os_str())?;
    let directory = cstring(cwd.as_os_str())?;
    let mut argv = vec![executable.clone()];
    for arg in args {
        argv.push(cstring(&arg)?);
    }
    let mut environment = Vec::with_capacity(env.len());
    for (key, value) in env {
        if key.is_empty() || key.as_bytes().contains(&b'=') {
            return Err(refused("invalid_spawn_environment"));
        }
        let mut pair = key;
        pair.push("=");
        pair.push(value);
        environment.push(cstring(&pair)?);
    }
    // Standard-library pipe owns descriptor creation/inheritance semantics. This
    // does not claim a globally atomic pipe2 guarantee on Darwin.
    let (input_read, input_write) = io::pipe().map_err(|_| refused("pipe_unavailable"))?;
    let (input_read, input_write) = (OwnedFd::from(input_read), OwnedFd::from(input_write));
    let (output_read, output_write) = io::pipe().map_err(|_| refused("pipe_unavailable"))?;
    let (output_read, output_write) = (OwnedFd::from(output_read), OwnedFd::from(output_write));
    let (error_read, error_write) = io::pipe().map_err(|_| refused("pipe_unavailable"))?;
    let (error_read, error_write) = (OwnedFd::from(error_read), OwnedFd::from(error_write));
    let mut actions = PosixSpawnFileActions::init().map_err(|_| refused("spawn_unavailable"))?;
    for (fd, target) in [(&input_read, 0), (&output_write, 1), (&error_write, 2)] {
        actions
            .add_dup2(fd.as_raw_fd(), target)
            .map_err(|_| refused("spawn_unavailable"))?;
    }
    darwin_file_actions::chdir(&mut actions, directory.as_c_str())
        .map_err(|_| refused("spawn_directory_unavailable"))?;
    let mut attributes = PosixSpawnAttr::init().map_err(|_| refused("spawn_unavailable"))?;
    attributes
        .set_flags(PosixSpawnFlags::from_bits_retain(
            nix::libc::POSIX_SPAWN_START_SUSPENDED | nix::libc::POSIX_SPAWN_CLOEXEC_DEFAULT,
        ))
        .map_err(|_| refused("spawn_unavailable"))?;
    // Convert the parent's ends before creating any OS child: conversion failure is pre-I/O.
    let stdin = ChildStdin::from_std(std::process::ChildStdin::from(input_write))
        .map_err(|_| refused("stdio_unavailable"))?;
    let stdout = ChildStdout::from_std(std::process::ChildStdout::from(output_read))
        .map_err(|_| refused("stdio_unavailable"))?;
    let stderr = ChildStderr::from_std(std::process::ChildStderr::from(error_read))
        .map_err(|_| refused("stdio_unavailable"))?;
    image.revalidate().map_err(|_| refused("image_changed"))?;
    let pid = posix_spawn(
        executable.as_c_str(),
        &actions,
        &attributes,
        &argv,
        &environment,
    )
    .map_err(|_| refused("spawn_refused"))?;
    drop((input_read, output_write, error_write));
    let birth = ProcessIdentity::observe(pid.as_raw() as u32).ok();
    let shared = Arc::new(Shared {
        pid,
        facts: Mutex::new(Facts {
            birth,
            exit: None,
            wait_unknown: false,
        }),
        terminate: AtomicBool::new(false),
        joined: AtomicBool::new(false),
        _image: image,
    });
    let owned = shared.clone();
    let supervisor = runtime.spawn(async move {
        loop {
            {
                let mut facts = owned.facts.lock().unwrap_or_else(|e| e.into_inner());
                if owned.terminate.load(Ordering::Acquire) {
                    let _ = kill(owned.pid, Signal::SIGKILL);
                }
                match waitpid(owned.pid, Some(WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::Exited(_, code)) => {
                        facts.exit = Some(ExitStatus::from_raw(code << 8));
                        break;
                    }
                    Ok(WaitStatus::Signaled(_, signal, dumped)) => {
                        facts.exit = Some(ExitStatus::from_raw(
                            signal as i32 | if dumped { 0x80 } else { 0 },
                        ));
                        break;
                    }
                    Ok(_) => {}
                    Err(nix::errno::Errno::EINTR) => {}
                    Err(_) => {
                        facts.wait_unknown = true;
                        break;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });
    let child = RunningChild {
        shared,
        supervisor: AsyncMutex::new(Some(supervisor)),
        stdin: Some(stdin),
        stdout: Some(stdout),
        stderr: Some(stderr),
    };
    let suspended = SuspendedChild {
        child: Some(child),
        path,
        cdhash,
    };
    if suspended.receipt().birth.is_none() {
        return Err(SpawnFailure {
            code: "child_identity_unknown",
            child: Some(suspended),
        });
    }
    Ok(suspended)
}
impl SuspendedChild {
    pub fn receipt(&self) -> ChildReceipt {
        self.child
            .as_ref()
            .expect("owned suspended child")
            .receipt()
    }
    pub fn verify_and_resume(mut self) -> Result<RunningChild, SpawnFailure> {
        let verification = (|| {
            let child = self.child.as_ref().ok_or(())?;
            let facts = child.shared.facts.lock().map_err(|_| ())?;
            let birth = facts.birth.as_ref().ok_or(())?;
            if facts.exit.is_some()
                || facts.wait_unknown
                || child.shared.terminate.load(Ordering::Acquire)
                || ProcessIdentity::observe(child.id()).as_ref().ok() != Some(birth)
            {
                return Err(());
            }
            child.shared._image.revalidate().map_err(|_| ())?;
            let mut attributes = GuestAttributes::new();
            attributes.set_pid(child.shared.pid.as_raw());
            let guest = SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE)
                .map_err(|_| ())?;
            let hex: String = self
                .cdhash
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            let requirement =
                SecRequirement::from_str(&format!("cdhash H\"{hex}\"")).map_err(|_| ())?;
            guest
                .check_validity(
                    Flags::STRICT_VALIDATE | Flags::NO_NETWORK_ACCESS,
                    &requirement,
                )
                .map_err(|_| ())?;
            if guest.path(Flags::NONE).map_err(|_| ())?.to_path().as_ref() != Some(&self.path) {
                return Err(());
            }
            child.shared._image.revalidate().map_err(|_| ())?;
            if ProcessIdentity::observe(child.id()).as_ref().ok() != Some(birth) {
                return Err(());
            }
            kill(child.shared.pid, Signal::SIGCONT).map_err(|_| ())
        })();
        if verification.is_err() {
            if let Some(child) = &self.child {
                let _ = child.start_kill();
            }
            return Err(SpawnFailure {
                code: "suspended_image_verification_failed",
                child: Some(self),
            });
        }
        Ok(self.child.take().expect("verified owned child"))
    }
    pub async fn terminate_and_wait(&mut self) -> io::Result<ExitStatus> {
        let child = self.child.as_mut().ok_or_else(io_error)?;
        let _ = child.start_kill();
        child.wait().await
    }
}
impl RunningChild {
    pub fn id(&self) -> u32 {
        self.shared.pid.as_raw() as u32
    }
    pub fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.stdin.take()
    }
    pub fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.stdout.take()
    }
    pub fn take_stderr(&mut self) -> Option<ChildStderr> {
        self.stderr.take()
    }
    pub fn receipt(&self) -> ChildReceipt {
        let facts = self.shared.facts.lock().unwrap_or_else(|e| e.into_inner());
        ChildReceipt {
            pid: self.id(),
            birth: facts.birth.clone(),
            actual_wait: facts.exit.is_some(),
            supervisor_joined: self.shared.joined.load(Ordering::Acquire),
            exit_success: facts.exit.map(|exit| exit.success()),
        }
    }
    pub fn start_kill(&self) -> io::Result<()> {
        self.shared.terminate.store(true, Ordering::Release);
        let facts = self.shared.facts.lock().map_err(|_| io_error())?;
        if facts.exit.is_some() {
            return Ok(());
        }
        if facts.wait_unknown {
            return Err(io_error());
        }
        // The sole reaper holds this same lock. An unreaped direct child PID cannot ABA.
        kill(self.shared.pid, Signal::SIGKILL)
            .map_err(|error| io::Error::from_raw_os_error(error as i32))
    }
    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        let facts = self.shared.facts.lock().map_err(|_| io_error())?;
        if facts.wait_unknown {
            Err(io_error())
        } else {
            Ok(facts.exit)
        }
    }
    pub async fn wait(&mut self) -> io::Result<ExitStatus> {
        // Borrow the retained JoinHandle across await; cancelling this waiter does not detach it.
        let mut task = self.supervisor.lock().await;
        if let Some(handle) = task.as_mut() {
            let result = handle.await;
            task.take();
            self.shared.joined.store(true, Ordering::Release);
            if result.is_err() {
                self.shared
                    .facts
                    .lock()
                    .map_err(|_| io_error())?
                    .wait_unknown = true;
                return Err(io_error());
            }
        }
        drop(task);
        self.try_wait()?.ok_or_else(io_error)
    }
}
impl Drop for RunningChild {
    fn drop(&mut self) {
        self.shared.terminate.store(true, Ordering::Release);
    }
}
#[cfg(test)]
#[path = "macos_spawn_tests.rs"]
mod tests;
