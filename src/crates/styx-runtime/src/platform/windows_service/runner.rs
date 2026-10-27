//! SCM dispatcher owns the one original process and its foreground drain.
//! No detached supervisor, restart, service-name adoption, or terminal fallback.
use super::{Definition, Result, ServiceError, ServiceRole, ServiceScope, fixed_name};
use crate::foreground::{ForegroundEvent, ForegroundOutcome, GatewayForegroundOutcome};
use std::{
    ffi::OsStr,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    ptr,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio_util::sync::CancellationToken;
use windows_sys::Win32::{
    Foundation::{
        ERROR_CALL_NOT_IMPLEMENTED, ERROR_GEN_FAILURE, ERROR_SERVICE_SPECIFIC_ERROR, NO_ERROR,
    },
    System::Services::*,
};
struct Dispatch {
    path: PathBuf,
    role: ServiceRole,
    name: Vec<u16>,
    cancel: CancellationToken,
    entered: AtomicBool,
    definition: OnceLock<Arc<Definition>>,
    scope: OnceLock<Arc<ServiceScope>>,
    runtime: OnceLock<tokio::runtime::Runtime>,
    status: Mutex<Option<StatusOwner>>,
    result: Mutex<Option<Result<serde_json::Value>>>,
}
// SCM owns this opaque status token; it is not CloseServiceHandle-owned.
// All SetServiceStatus calls, including the final one, hold this mutex.
struct StatusOwner {
    handle: usize,
    value: SERVICE_STATUS,
    stopped: bool,
}
impl StatusOwner {
    fn publish(&mut self, state: u32, exit: u32) -> Result<()> {
        if self.stopped {
            return Err(ServiceError::Conflict);
        }
        self.value.dwCurrentState = state;
        self.value.dwControlsAccepted = if state == SERVICE_RUNNING {
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        } else {
            0
        };
        self.value.dwWin32ExitCode = exit;
        self.value.dwServiceSpecificExitCode = if exit == ERROR_SERVICE_SPECIFIC_ERROR {
            1
        } else {
            0
        };
        self.value.dwCheckPoint = if matches!(state, SERVICE_START_PENDING | SERVICE_STOP_PENDING) {
            1
        } else {
            0
        };
        self.value.dwWaitHint = if matches!(state, SERVICE_START_PENDING | SERVICE_STOP_PENDING) {
            120_000
        } else {
            0
        };
        if unsafe { SetServiceStatus(self.handle as SERVICE_STATUS_HANDLE, &self.value) } == 0 {
            return Err(ServiceError::Unknown);
        }
        if state == SERVICE_STOPPED {
            self.stopped = true;
        }
        Ok(())
    }
    fn interrogate(&self) -> Result<()> {
        if self.stopped {
            return Ok(());
        }
        if unsafe { SetServiceStatus(self.handle as SERVICE_STATUS_HANDLE, &self.value) } == 0 {
            return Err(ServiceError::Unknown);
        }
        Ok(())
    }
}
static DISPATCH: OnceLock<Arc<Dispatch>> = OnceLock::new();
fn publish(state: u32, exit: u32) -> Result<()> {
    let context = DISPATCH.get().ok_or(ServiceError::Conflict)?;
    context
        .status
        .lock()
        .map_err(|_| ServiceError::Unknown)?
        .as_mut()
        .ok_or(ServiceError::Unavailable)?
        .publish(state, exit)
}
pub(super) fn dispatched_for(path: &Path, role: ServiceRole) -> bool {
    DISPATCH
        .get()
        .is_some_and(|d| d.entered.load(Ordering::Acquire) && d.path == path && d.role == role)
}
pub(super) fn retained_definition(path: &Path, role: ServiceRole) -> Option<Arc<Definition>> {
    let context = DISPATCH.get()?;
    if !dispatched_for(path, role) {
        return None;
    }
    context.definition.get().cloned()
}
/// Call from the process entry before constructing an async runtime. Windows
/// rejects a terminal caller; there is no foreground fallback on that error.
pub(crate) fn dispatch(path: &Path, role: ServiceRole) -> Result<serde_json::Value> {
    let name = fixed_name(path, role)?;
    let mut name: Vec<u16> = OsStr::new(&name).encode_wide().collect();
    name.push(0);
    let context = Arc::new(Dispatch {
        path: path.into(),
        role,
        name,
        cancel: CancellationToken::new(),
        entered: AtomicBool::new(false),
        definition: OnceLock::new(),
        scope: OnceLock::new(),
        runtime: OnceLock::new(),
        status: Mutex::new(None),
        result: Mutex::new(None),
    });
    DISPATCH
        .set(context.clone())
        .map_err(|_| ServiceError::Conflict)?;
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: context.name.as_ptr().cast_mut(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    // The table and context stay alive until every ServiceMain has returned.
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        return Err(ServiceError::Unavailable);
    }
    let result = context
        .result
        .lock()
        .map_err(|_| ServiceError::Unknown)?
        .take()
        .ok_or(ServiceError::Unknown)?;
    result
}
unsafe extern "system" fn handler(
    control: u32,
    _: u32,
    _: *mut core::ffi::c_void,
    _: *mut core::ffi::c_void,
) -> u32 {
    let Some(context) = DISPATCH.get() else {
        return ERROR_GEN_FAILURE;
    };
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            // Handler performs no C07 write, file IO, wait, executor operation,
            // or forced stop. The original domain runner drains after cancel.
            context.cancel.cancel();
            if context
                .status
                .lock()
                .ok()
                .and_then(|s| s.as_ref().map(|s| s.stopped))
                .unwrap_or(false)
            {
                return NO_ERROR;
            }
            match publish(SERVICE_STOP_PENDING, NO_ERROR) {
                Ok(()) => NO_ERROR,
                Err(_) => ERROR_GEN_FAILURE,
            }
        }
        SERVICE_CONTROL_INTERROGATE => match context.status.lock() {
            Ok(status) => status.as_ref().map_or(ERROR_GEN_FAILURE, |s| {
                if s.interrogate().is_ok() {
                    NO_ERROR
                } else {
                    ERROR_GEN_FAILURE
                }
            }),
            Err(_) => ERROR_GEN_FAILURE,
        },
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}
unsafe extern "system" fn service_main(argc: u32, argv: *mut *mut u16) {
    // Unwinding never crosses the system ABI. Original runtime/definition/scope
    // remain in DISPATCH even on panic; a panic cannot prove cleanup.
    let result = std::panic::catch_unwind(|| main_owned(argc, argv));
    if !matches!(result, Ok(Ok(()))) {
        hold_unknown();
    }
}
fn hold_unknown() -> ! {
    let _ = publish(SERVICE_STOP_PENDING, ERROR_SERVICE_SPECIFIC_ERROR);
    // Keep the original dispatcher/runtime/handles; no STOPPED or restart claim.
    loop {
        std::thread::park();
    }
}
fn cancelled_before_admission(context: &Dispatch) -> Result<()> {
    *context.result.lock().map_err(|_| ServiceError::Unknown)? = Some(Ok(serde_json::json!({
        "schema": 1, "runtime_started": false, "service_cancelled_before_admission": true,
        "cleanup_complete": true,
    })));
    publish(SERVICE_STOPPED, NO_ERROR)
}
fn main_owned(argc: u32, argv: *mut *mut u16) -> Result<()> {
    let context = DISPATCH.get().ok_or(ServiceError::Conflict)?;
    if context.entered.swap(true, Ordering::AcqRel) || argc != 1 || argv.is_null() {
        return Err(ServiceError::Conflict);
    }
    let actual = unsafe { *argv };
    if actual.is_null() {
        return Err(ServiceError::Conflict);
    }
    // SCM supplies argv[0]; match the exact root-derived fixed registration.
    for index in 0..context.name.len() {
        if unsafe { *actual.add(index) } != context.name[index] {
            return Err(ServiceError::Conflict);
        }
    }
    let handle =
        unsafe { RegisterServiceCtrlHandlerExW(context.name.as_ptr(), Some(handler), ptr::null()) };
    if handle.is_null() {
        return Err(ServiceError::Unavailable);
    }
    *context.status.lock().map_err(|_| ServiceError::Unknown)? = Some(StatusOwner {
        handle: handle as usize,
        value: SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            ..SERVICE_STATUS::default()
        },
        stopped: false,
    });
    publish(SERVICE_START_PENDING, NO_ERROR)?;
    // Admission is synchronous before foreground starts. Failures here have no
    // runtime child or management writer and may report a determinate failure.
    let prepared = Definition::prepare(&context.path, context.role, false);
    let definition = match prepared {
        Ok(definition) => Arc::new(definition),
        Err(error) => {
            *context.result.lock().map_err(|_| ServiceError::Unknown)? = Some(Err(error));
            publish(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR)?;
            return Ok(());
        }
    };
    context
        .definition
        .set(definition.clone())
        .map_err(|_| ServiceError::Conflict)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| ServiceError::Unavailable)?;
    context
        .runtime
        .set(runtime)
        .map_err(|_| ServiceError::Conflict)?;
    let runtime = context.runtime.get().ok_or(ServiceError::Unknown)?;
    // RUNNING means SCM control-handler readiness, never paired connectivity or
    // a completed C07 execution grant. SCM then exposes a defined process PID.
    {
        let mut guard = context.status.lock().map_err(|_| ServiceError::Unknown)?;
        if context.cancel.is_cancelled() {
            drop(guard);
            return cancelled_before_admission(context);
        }
        guard
            .as_mut()
            .ok_or(ServiceError::Unknown)?
            .publish(SERVICE_RUNNING, NO_ERROR)?;
    }
    let startup = runtime.block_on(ServiceScope::authenticate(&context.path, context.role));
    let scope = match startup {
        Ok(scope) => scope,
        Err(error) => {
            *context.result.lock().map_err(|_| ServiceError::Unknown)? = Some(Err(error));
            publish(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR)?;
            return Ok(());
        }
    };
    context
        .scope
        .set(scope.clone())
        .map_err(|_| ServiceError::Conflict)?;
    if context.cancel.is_cancelled() {
        return cancelled_before_admission(context);
    }
    // Keep the async runtime in this ServiceMain through Unknown. The error
    // branch never drops a runtime containing unresolved original custody.
    let result = runtime.block_on(async {
        let (events, mut receive) = tokio::sync::mpsc::channel::<ForegroundEvent>(32);
        let observer = tokio::spawn(async move { while receive.recv().await.is_some() {} });
        let outcome: Result<serde_json::Value> = match context.role {
            ServiceRole::Host => match crate::foreground::host_run_for_service(
                scope.clone(),
                context.cancel.clone(),
                events,
            )
            .await
            {
                Ok(outcome) if ForegroundOutcome::is_complete(&outcome) => {
                    serde_json::to_value(outcome).map_err(|_| ServiceError::Unknown)
                }
                _ => Err(ServiceError::Unknown),
            },
            ServiceRole::Gateway => match crate::foreground::gateway_run_for_service(
                scope.clone(),
                context.cancel.clone(),
                events,
            )
            .await
            {
                Ok(outcome) if GatewayForegroundOutcome::is_complete(&outcome) => {
                    serde_json::to_value(outcome).map_err(|_| ServiceError::Unknown)
                }
                _ => Err(ServiceError::Unknown),
            },
        };
        if outcome.is_err() {
            let _ = publish(SERVICE_STOP_PENDING, ERROR_SERVICE_SPECIFIC_ERROR);
            std::future::pending::<()>().await;
        }
        observer.await.map_err(|_| ServiceError::Unknown)?;
        outcome
    });
    match result {
        Ok(outcome) => {
            *context.result.lock().map_err(|_| ServiceError::Unknown)? = Some(Ok(outcome));
            // Foreground's executor/process/IO/remote drain and local observer
            // have all settled before this final and only STOPPED publication.
            publish(SERVICE_STOPPED, NO_ERROR)?;
            Ok(())
        }
        Err(_) => {
            // Retain the original runtime and all its pending task custody.
            hold_unknown()
        }
    }
}
