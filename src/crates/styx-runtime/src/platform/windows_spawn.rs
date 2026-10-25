//! Windows native-image boundary. The process is born in a non-breakaway Job
//! and remains suspended until its pinned PE and exact kernel birth are verified.
//! Root wait and Job ActiveProcesses==0 are separate facts; neither Drop nor
//! TerminateJobObject acknowledgement is a cleanup receipt.
use crate::store::{PinnedExecutable, ProcessIdentity};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, Read},
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        fs::MetadataExt,
        io::{AsRawHandle, OwnedHandle},
        process::ExitStatusExt,
    },
    path::PathBuf,
    process::ExitStatus,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    process::{ChildStderr, ChildStdin, ChildStdout},
    sync::{Mutex as AsyncMutex, watch},
    task::JoinHandle,
};

pub(crate) struct SpawnFailure {
    pub(crate) code: &'static str,
    child: Option<Box<RunningChild>>,
}
impl std::fmt::Debug for SpawnFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpawnFailure")
            .field("code", &self.code)
            .field("retains_child", &self.child.is_some())
            .finish()
    }
}
impl SpawnFailure {
    pub(crate) fn into_owned_child(self) -> Option<RunningChild> {
        self.child.map(|child| *child)
    }
}
fn refused(code: &'static str) -> SpawnFailure {
    SpawnFailure { code, child: None }
}
#[derive(Default)]
struct Facts {
    exit: Option<ExitStatus>,
    root_waited: bool,
    job_empty: bool,
    unknown: bool,
    supervisor_finished: bool,
    handles_closed_unconfirmed: bool,
}
struct NativeHandles {
    process: OwnedHandle,
    job: OwnedHandle,
}
struct Shared {
    native: Mutex<Option<NativeHandles>>,
    pid: u32,
    terminate: AtomicBool,
    #[cfg(test)]
    inject_query_failure: AtomicBool,
    facts: Mutex<Facts>,
    changed: watch::Sender<u64>,
    _image: Arc<PinnedExecutable>,
    _startup_budget: Arc<tokio::sync::OwnedSemaphorePermit>,
}
pub(crate) struct RunningChild {
    shared: Arc<Shared>,
    supervisor: AsyncMutex<Option<JoinHandle<()>>>,
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
}
pub(crate) struct SuspendedChild {
    child: RunningChild,
    thread: OwnedHandle,
    birth: ProcessIdentity,
}
impl Drop for RunningChild {
    fn drop(&mut self) {
        self.shared.terminate.store(true, Ordering::Release);
    }
}
fn lost() -> io::Error {
    io::Error::other("windows_job_cleanup_unconfirmed")
}
fn wide(value: &OsStr) -> io::Result<Vec<u16>> {
    let mut w: Vec<_> = value.encode_wide().collect();
    if w.is_empty() || w.len() > 32766 || w.contains(&0) {
        return Err(io::Error::other("invalid_windows_spawn_input"));
    }
    w.push(0);
    Ok(w)
}
fn environment(env: &BTreeMap<OsString, OsString>) -> io::Result<Vec<u16>> {
    if env.len() > 64 {
        return Err(lost());
    }
    let mut sorted = BTreeMap::new();
    for (k, v) in env {
        let k = k.to_str().ok_or_else(lost)?;
        if k.is_empty()
            || k.len() > 256
            || !k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(lost());
        }
        let upper = k.to_ascii_uppercase();
        if sorted.insert(upper, (k, v)).is_some() {
            return Err(lost());
        }
    }
    let mut block = Vec::new();
    for (_, (k, v)) in sorted {
        let mut part: Vec<_> = OsStr::new(k).encode_wide().collect();
        part.push(b'=' as u16);
        part.extend(v.encode_wide());
        if part.len() > 8192 || part.contains(&0) {
            return Err(lost());
        }
        block.extend(part);
        block.push(0);
        if block.len() > 32766 {
            return Err(lost());
        }
    }
    block.push(0);
    if block.len() == 1 {
        block.push(0)
    }
    Ok(block)
}
fn file_stamp(file: &File) -> io::Result<(u64, u64, u64, u64, u64)> {
    let m = file.metadata()?;
    if !m.is_file() {
        return Err(lost());
    }
    let (volume, index) = crate::store::windows_file_identity(file).map_err(|_| lost())?;
    Ok((
        volume,
        index,
        m.file_size(),
        m.last_write_time(),
        m.creation_time(),
    ))
}
fn image_matches(image: &PinnedExecutable, process: &OwnedHandle) -> io::Result<()> {
    image.revalidate().map_err(|_| lost())?;
    let held = image.retained_file().map_err(|_| lost())?;
    let expected = file_stamp(held)?;
    let path = ffi::image_path(process)?;
    let mut actual = File::open(path)?;
    let before = file_stamp(&actual)?;
    if before != expected || before.2 > 1024 * 1024 * 1024 {
        return Err(lost());
    }
    let mut hash = Sha256::new();
    let mut buf = [0u8; 65536];
    let mut total = 0u64;
    loop {
        let n = actual.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total = total.checked_add(n as u64).ok_or_else(lost)?;
        if total > before.2 {
            return Err(lost());
        }
        hash.update(&buf[..n]);
    }
    if total != before.2 {
        return Err(lost());
    }
    let sha: [u8; 32] = hash.finalize().into();
    if sha != *image.expected_sha256().map_err(|_| lost())?.as_bytes()
        || file_stamp(&actual)? != before
        || file_stamp(held)? != expected
    {
        return Err(lost());
    }
    image.revalidate().map_err(|_| lost())
}
const FAILURE_CLEANUP_BUDGET: Duration = Duration::from_secs(5);
fn supervise(shared: Arc<Shared>) {
    let mut terminated = false;
    let mut cleanup_deadline = None;
    let mut revision = 0u64;
    loop {
        let (root, active) = {
            let guard = shared.native.lock().unwrap_or_else(|p| p.into_inner());
            match guard.as_ref() {
                Some(native) => (ffi::poll_exit(&native.process), ffi::active(&native.job)),
                None => (Err(lost()), Err(lost())),
            }
        };
        #[cfg(test)]
        let (root, active) = if shared.inject_query_failure.load(Ordering::Acquire) {
            (Err(lost()), Err(lost()))
        } else {
            (root, active)
        };
        let failed = root.is_err() || active.is_err();
        let stopping = failed
            || shared.terminate.load(Ordering::Acquire)
            || matches!(root, Ok(Some(_))) && matches!(active, Ok(n) if n > 0);
        if stopping {
            cleanup_deadline
                .get_or_insert_with(|| std::time::Instant::now() + FAILURE_CLEANUP_BUDGET);
            if !terminated {
                terminated = true;
                let guard = shared.native.lock().unwrap_or_else(|p| p.into_inner());
                if guard
                    .as_ref()
                    .is_none_or(|native| ffi::terminate(&native.job).is_err())
                {
                    shared
                        .facts
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .unknown = true;
                }
            }
        }
        let complete = {
            let mut facts = shared.facts.lock().unwrap_or_else(|p| p.into_inner());
            match root {
                Ok(Some(exit)) => {
                    facts.exit = Some(exit);
                    facts.root_waited = true;
                }
                Ok(None) => {}
                Err(_) => facts.unknown = true,
            }
            match active {
                Ok(0) => facts.job_empty = true,
                Ok(_) => {}
                Err(_) => facts.unknown = true,
            }
            facts.root_waited && facts.job_empty
        };
        let expired = cleanup_deadline.is_some_and(|until| std::time::Instant::now() >= until);
        if complete || expired {
            // A failed wait/query does not justify retaining a blocking runtime
            // thread forever. Closing our last Job handle requests OS termination;
            // it is deliberately NOT evidence of actual root wait or job quiescence.
            let native = shared
                .native
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .take();
            drop(native);
            let mut facts = shared.facts.lock().unwrap_or_else(|p| p.into_inner());
            facts.supervisor_finished = true;
            if !complete {
                facts.unknown = true;
                facts.handles_closed_unconfirmed = true;
            }
            drop(facts);
            shared.changed.send_replace(revision.saturating_add(1));
            return;
        }
        revision = revision.saturating_add(1);
        shared.changed.send_replace(revision);
        std::thread::sleep(Duration::from_millis(20));
    }
}
impl RunningChild {
    pub(crate) fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.stdin.take()
    }
    pub(crate) fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.stdout.take()
    }
    pub(crate) fn take_stderr(&mut self) -> Option<ChildStderr> {
        self.stderr.take()
    }
    pub(crate) fn start_kill(&mut self) -> io::Result<()> {
        self.shared.terminate.store(true, Ordering::Release);
        Ok(())
    }
    pub(crate) async fn terminate_and_wait(&mut self) -> io::Result<()> {
        self.start_kill()?;
        self.wait().await.map(|_| ())
    }
    pub(crate) async fn wait(&mut self) -> io::Result<ExitStatus> {
        let mut rx = self.shared.changed.subscribe();
        loop {
            let result = {
                let f = self.shared.facts.lock().map_err(|_| lost())?;
                if f.root_waited && f.job_empty {
                    Some(Ok(f.exit.ok_or_else(lost)?))
                } else if f.supervisor_finished {
                    Some(Err(lost()))
                } else {
                    None
                }
            };
            if let Some(result) = result {
                let mut task = self.supervisor.lock().await;
                if let Some(t) = task.as_mut() {
                    t.await.map_err(|_| lost())?;
                    task.take();
                }
                return result;
            }
            rx.changed().await.map_err(|_| lost())?;
        }
    }
}
impl SuspendedChild {
    pub(crate) fn verify_and_resume(self) -> Result<RunningChild, SpawnFailure> {
        let result = (|| {
            let guard = self.child.shared.native.lock().map_err(|_| lost())?;
            let native = guard.as_ref().ok_or_else(lost)?;
            image_matches(&self.child.shared._image, &native.process)?;
            let observed = ProcessIdentity::observe(self.child.shared.pid).map_err(|_| lost())?;
            if observed != self.birth
                || !self.birth.still_current().map_err(|_| lost())?
                || ffi::birth(&native.process)? != creation(&self.birth)?
                || !ffi::in_job(&native.process, &native.job)?
            {
                return Err(lost());
            }
            ffi::resume(&self.thread)
        })();
        match result {
            Ok(()) => Ok(self.child),
            Err(_) => Err(SpawnFailure {
                code: "windows_image_verification_failed",
                child: Some(Box::new(self.child)),
            }),
        }
    }
}
fn same_owner(parent: &ProcessIdentity, child: &ProcessIdentity) -> bool {
    match (parent, child) {
        (
            ProcessIdentity::Windows { owner_sid: a, .. },
            ProcessIdentity::Windows { owner_sid: b, .. },
        ) => a == b,
        _ => false,
    }
}
fn creation(birth: &ProcessIdentity) -> io::Result<u64> {
    match birth {
        ProcessIdentity::Windows {
            creation_time_100ns,
            ..
        } => Ok(*creation_time_100ns),
        _ => Err(lost()),
    }
}
/// Fixed native Exec entry point. Caller runs this on the existing bounded blocking
/// startup job, with a Tokio runtime entered. No caller-supplied program arguments.
pub(crate) fn spawn_suspended(
    image: Arc<PinnedExecutable>,
    startup_budget: Arc<tokio::sync::OwnedSemaphorePermit>,
    cwd: PathBuf,
    env: BTreeMap<OsString, OsString>,
) -> Result<SuspendedChild, SpawnFailure> {
    spawn_fixed(image, startup_budget, cwd, env, Entry::Exec)
}
/// Fixed trusted Browser entry: no shell, Node flags, remote arguments or
/// arbitrary program selection. The same native image/Job checks precede resume.
pub(crate) fn spawn_browser_suspended(
    image: Arc<PinnedExecutable>,
    startup_budget: Arc<tokio::sync::OwnedSemaphorePermit>,
    cwd: PathBuf,
    env: BTreeMap<OsString, OsString>,
    worker: PathBuf,
    config: PathBuf,
) -> Result<SuspendedChild, SpawnFailure> {
    if !worker.is_absolute()
        || !config.is_absolute()
        || worker.file_name() != Some(OsStr::new("worker.mjs"))
        || config.extension() != Some(OsStr::new("json"))
    {
        return Err(refused("invalid_browser_spawn_input"));
    }
    spawn_fixed(
        image,
        startup_budget,
        cwd,
        env,
        Entry::Browser { worker, config },
    )
}
enum Entry {
    Exec,
    Browser { worker: PathBuf, config: PathBuf },
}
// Microsoft CRT quoting, applied only to trusted fixed-entry arguments. The
// application is separately specified to CreateProcessW, never shell resolved.
// https://learn.microsoft.com/en-us/cpp/c-language/parsing-c-command-line-arguments
fn quote_argument(value: &OsStr, output: &mut Vec<u16>) -> io::Result<()> {
    output.push(b'"' as u16);
    let mut slashes = 0;
    for unit in value.encode_wide() {
        if unit == 0 {
            return Err(lost());
        }
        if unit == b'\\' as u16 {
            slashes += 1;
            continue;
        }
        output.extend(std::iter::repeat_n(
            b'\\' as u16,
            if unit == b'"' as u16 {
                2 * slashes + 1
            } else {
                slashes
            },
        ));
        slashes = 0;
        output.push(unit);
        if output.len() > 32765 {
            return Err(lost());
        }
    }
    output.extend(std::iter::repeat_n(b'\\' as u16, 2 * slashes));
    output.push(b'"' as u16);
    if output.len() > 32765 {
        return Err(lost());
    }
    Ok(())
}
fn command_line(path: &OsStr, entry: &Entry) -> io::Result<Vec<u16>> {
    let mut result = Vec::new();
    quote_argument(path, &mut result)?;
    let args: Vec<&OsStr> = match entry {
        Entry::Exec => vec![
            OsStr::new("exec-server"),
            OsStr::new("--listen"),
            OsStr::new("stdio://"),
        ],
        Entry::Browser { worker, config } => vec![
            worker.as_os_str(),
            OsStr::new("--config"),
            config.as_os_str(),
        ],
    };
    for arg in args {
        result.push(b' ' as u16);
        quote_argument(arg, &mut result)?;
    }
    result.push(0);
    Ok(result)
}
fn spawn_fixed(
    image: Arc<PinnedExecutable>,
    startup_budget: Arc<tokio::sync::OwnedSemaphorePermit>,
    cwd: PathBuf,
    env: BTreeMap<OsString, OsString>,
    entry: Entry,
) -> Result<SuspendedChild, SpawnFailure> {
    let runtime =
        tokio::runtime::Handle::try_current().map_err(|_| refused("runtime_unavailable"))?;
    let parent_identity =
        ProcessIdentity::current().map_err(|_| refused("parent_identity_unavailable"))?;
    image.revalidate().map_err(|_| refused("image_changed"))?;
    let path = image
        .source_path_for_suspended_spawn()
        .map_err(|_| refused("image_unavailable"))?;
    if !cwd.is_absolute() || path.as_os_str().encode_wide().any(|c| c == b'"' as u16) {
        return Err(refused("invalid_spawn_input"));
    }
    let application = wide(path.as_os_str()).map_err(|_| refused("invalid_spawn_input"))?;
    let directory = wide(cwd.as_os_str()).map_err(|_| refused("invalid_spawn_input"))?;
    let mut command =
        command_line(path.as_os_str(), &entry).map_err(|_| refused("invalid_spawn_input"))?;
    let mut environment = environment(&env).map_err(|_| refused("invalid_spawn_environment"))?;
    let (input_read, input_write) = io::pipe().map_err(|_| refused("pipe_unavailable"))?;
    let (output_read, output_write) = io::pipe().map_err(|_| refused("pipe_unavailable"))?;
    let (error_read, error_write) = io::pipe().map_err(|_| refused("pipe_unavailable"))?;
    let input_read = OwnedHandle::from(input_read);
    let output_write = OwnedHandle::from(output_write);
    let error_write = OwnedHandle::from(error_write);
    let stdin = ChildStdin::from_std(std::process::ChildStdin::from(OwnedHandle::from(
        input_write,
    )))
    .map_err(|_| refused("pipe_unavailable"))?;
    let stdout = ChildStdout::from_std(std::process::ChildStdout::from(OwnedHandle::from(
        output_read,
    )))
    .map_err(|_| refused("pipe_unavailable"))?;
    let stderr = ChildStderr::from_std(std::process::ChildStderr::from(OwnedHandle::from(
        error_read,
    )))
    .map_err(|_| refused("pipe_unavailable"))?;
    let job =
        ffi::job(matches!(entry, Entry::Browser { .. })).map_err(|_| refused("job_unavailable"))?;
    let (process, thread, pid) = ffi::spawn(
        &application,
        &mut command,
        &directory,
        &mut environment,
        &job,
        [&input_read, &output_write, &error_write],
    )
    .map_err(|_| refused("spawn_unavailable"))?;
    // From this point the supervisor owns every native handle and the original pin.
    // Dropping any public response requests termination; it never aborts this task.
    let (changed, _) = watch::channel(0);
    let shared = Arc::new(Shared {
        native: Mutex::new(Some(NativeHandles { process, job })),
        pid,
        terminate: AtomicBool::new(false),
        #[cfg(test)]
        inject_query_failure: AtomicBool::new(false),
        facts: Mutex::new(Facts::default()),
        changed,
        _image: image,
        _startup_budget: startup_budget,
    });
    let owned = shared.clone();
    let supervisor = runtime.spawn_blocking(move || supervise(owned));
    let child = RunningChild {
        shared,
        supervisor: AsyncMutex::new(Some(supervisor)),
        stdin: Some(stdin),
        stdout: Some(stdout),
        stderr: Some(stderr),
    };
    let birth = match ProcessIdentity::observe(pid) {
        Ok(birth) => birth,
        Err(_) => {
            return Err(SpawnFailure {
                code: "windows_birth_unavailable",
                child: Some(Box::new(child)),
            });
        }
    };
    if !same_owner(&parent_identity, &birth) {
        return Err(SpawnFailure {
            code: "windows_process_owner_mismatch",
            child: Some(Box::new(child)),
        });
    }
    Ok(SuspendedChild {
        child,
        thread,
        birth,
    })
}

// Only this OS bridge uses raw handles/pointers. All handles are immediately
// owned; STARTUPINFOEX/attribute layouts are the official windows-sys types.
// Microsoft: PROC_THREAD_ATTRIBUTE_JOB_LIST and HANDLE_LIST (UpdateProcThreadAttribute),
// CreateProcessW/CREATE_SUSPENDED, JobObjectBasicAccountingInformation, ResumeThread.
#[allow(unsafe_code)]
mod ffi {
    use super::*;
    use std::{
        mem::{size_of, zeroed},
        os::windows::io::FromRawHandle,
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::{
            ERROR_INSUFFICIENT_BUFFER, FILETIME, GetLastError, HANDLE, HANDLE_FLAG_INHERIT,
            SetHandleInformation, WAIT_OBJECT_0, WAIT_TIMEOUT,
        },
        System::{JobObjects::*, Threading::*},
    };
    fn raw(h: &OwnedHandle) -> HANDLE {
        h.as_raw_handle()
    }
    fn ok(v: i32) -> io::Result<()> {
        if v == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
    pub(super) fn job(browser: bool) -> io::Result<OwnedHandle> {
        unsafe {
            let h = CreateJobObjectW(ptr::null(), ptr::null());
            if h.is_null() {
                return Err(io::Error::last_os_error());
            }
            let owned = OwnedHandle::from_raw_handle(h);
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = zeroed();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if browser {
                limits.BasicLimitInformation.LimitFlags |=
                    JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
                limits.BasicLimitInformation.ActiveProcessLimit = 256;
                limits.JobMemoryLimit = 2 * 1024 * 1024 * 1024;
            }
            ok(SetInformationJobObject(
                raw(&owned),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            ))?;
            let mut actual: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = zeroed();
            ok(QueryInformationJobObject(
                raw(&owned),
                JobObjectExtendedLimitInformation,
                (&mut actual as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                ptr::null_mut(),
            ))?;
            if actual.BasicLimitInformation.LimitFlags != limits.BasicLimitInformation.LimitFlags
                || browser
                    && (actual.JobMemoryLimit != limits.JobMemoryLimit
                        || actual.BasicLimitInformation.ActiveProcessLimit != 256)
            {
                return Err(lost());
            }
            Ok(owned)
        }
    }
    struct Attributes {
        storage: Vec<usize>,
    }
    impl Attributes {
        fn ptr(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
            self.storage.as_mut_ptr().cast()
        }
    }
    impl Drop for Attributes {
        fn drop(&mut self) {
            unsafe { DeleteProcThreadAttributeList(self.ptr()) }
        }
    }
    pub(super) fn spawn(
        application: &[u16],
        command: &mut [u16],
        directory: &[u16],
        environment: &mut [u16],
        job: &OwnedHandle,
        pipes: [&OwnedHandle; 3],
    ) -> io::Result<(OwnedHandle, OwnedHandle, u32)> {
        unsafe {
            let mut bytes = 0usize;
            let first = InitializeProcThreadAttributeList(ptr::null_mut(), 2, 0, &mut bytes);
            if first != 0
                || GetLastError() != ERROR_INSUFFICIENT_BUFFER
                || bytes == 0
                || bytes > 65536
            {
                return Err(lost());
            }
            let mut storage = vec![0usize; bytes.div_ceil(size_of::<usize>())];
            ok(InitializeProcThreadAttributeList(
                storage.as_mut_ptr().cast(),
                2,
                0,
                &mut bytes,
            ))?;
            let mut attributes = Attributes { storage };
            let jobs = [raw(job)];
            let inherited = pipes.map(raw);
            for h in inherited {
                ok(SetHandleInformation(
                    h,
                    HANDLE_FLAG_INHERIT,
                    HANDLE_FLAG_INHERIT,
                ))?
            }
            ok(UpdateProcThreadAttribute(
                attributes.ptr(),
                0,
                PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
                jobs.as_ptr().cast(),
                size_of_val(&jobs),
                ptr::null_mut(),
                ptr::null(),
            ))?;
            ok(UpdateProcThreadAttribute(
                attributes.ptr(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                inherited.as_ptr().cast(),
                size_of_val(&inherited),
                ptr::null_mut(),
                ptr::null(),
            ))?;
            let mut startup: STARTUPINFOEXW = zeroed();
            startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
            startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            startup.StartupInfo.hStdInput = inherited[0];
            startup.StartupInfo.hStdOutput = inherited[1];
            startup.StartupInfo.hStdError = inherited[2];
            startup.lpAttributeList = attributes.ptr();
            let mut process: PROCESS_INFORMATION = zeroed();
            ok(CreateProcessW(
                application.as_ptr(),
                command.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                1,
                CREATE_SUSPENDED
                    | CREATE_NO_WINDOW
                    | CREATE_UNICODE_ENVIRONMENT
                    | EXTENDED_STARTUPINFO_PRESENT,
                environment.as_ptr().cast(),
                directory.as_ptr(),
                &startup.StartupInfo,
                &mut process,
            ))?;
            // JOB_LIST admission happens inside CreateProcess, not a later Assign call.
            Ok((
                OwnedHandle::from_raw_handle(process.hProcess),
                OwnedHandle::from_raw_handle(process.hThread),
                process.dwProcessId,
            ))
        }
    }
    #[cfg(test)]
    pub(super) fn available(output: &ChildStdout) -> io::Result<u32> {
        unsafe {
            let mut bytes = 0;
            ok(windows_sys::Win32::System::Pipes::PeekNamedPipe(
                output.as_raw_handle(),
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                &mut bytes,
                ptr::null_mut(),
            ))?;
            Ok(bytes)
        }
    }
    pub(super) fn image_path(process: &OwnedHandle) -> io::Result<PathBuf> {
        unsafe {
            let mut path = vec![0u16; 32768];
            let mut len = path.len() as u32;
            ok(QueryFullProcessImageNameW(
                raw(process),
                0,
                path.as_mut_ptr(),
                &mut len,
            ))?;
            if len == 0 || len as usize >= path.len() {
                return Err(lost());
            }
            path.truncate(len as usize);
            Ok(PathBuf::from(OsString::from_wide(&path)))
        }
    }
    pub(super) fn birth(process: &OwnedHandle) -> io::Result<u64> {
        unsafe {
            let (mut c, mut e, mut k, mut u): (FILETIME, FILETIME, FILETIME, FILETIME) = zeroed();
            ok(GetProcessTimes(
                raw(process),
                &mut c,
                &mut e,
                &mut k,
                &mut u,
            ))?;
            Ok(((c.dwHighDateTime as u64) << 32) | c.dwLowDateTime as u64)
        }
    }
    pub(super) fn in_job(process: &OwnedHandle, job: &OwnedHandle) -> io::Result<bool> {
        unsafe {
            let mut value = 0;
            ok(IsProcessInJob(raw(process), raw(job), &mut value))?;
            Ok(value != 0)
        }
    }
    pub(super) fn resume(thread: &OwnedHandle) -> io::Result<()> {
        unsafe {
            if ResumeThread(raw(thread)) != 1 {
                Err(lost())
            } else {
                Ok(())
            }
        }
    }
    pub(super) fn terminate(job: &OwnedHandle) -> io::Result<()> {
        unsafe { ok(TerminateJobObject(raw(job), 1)) }
    }
    pub(super) fn active(job: &OwnedHandle) -> io::Result<u32> {
        unsafe {
            let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = zeroed();
            ok(QueryInformationJobObject(
                raw(job),
                JobObjectBasicAccountingInformation,
                (&mut info as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                ptr::null_mut(),
            ))?;
            Ok(info.ActiveProcesses)
        }
    }
    pub(super) fn poll_exit(process: &OwnedHandle) -> io::Result<Option<ExitStatus>> {
        unsafe {
            match WaitForSingleObject(raw(process), 0) {
                WAIT_OBJECT_0 => {
                    let mut exit = 0;
                    ok(GetExitCodeProcess(raw(process), &mut exit))?;
                    Ok(Some(ExitStatus::from_raw(exit)))
                }
                WAIT_TIMEOUT => Ok(None),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }
}
#[cfg(test)]
#[path = "windows_spawn_tests.rs"]
mod tests;
