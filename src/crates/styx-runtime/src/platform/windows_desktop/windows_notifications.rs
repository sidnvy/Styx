//! WTS notifications belong to one retained, hidden native window/thread.
//! Events only invalidate; no message can grant capability or revive a source.
#![allow(unsafe_code)]
use super::windows_native_observation::{ObservationError, Result};
use std::{
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    thread::{self, JoinHandle},
};
use windows_sys::{
    Win32::{
        Foundation::{HWND, LPARAM, LRESULT, WAIT_OBJECT_0, WPARAM},
        System::{
            LibraryLoader::GetModuleHandleW,
            RemoteDesktop::{
                NOTIFY_FOR_THIS_SESSION, ProcessIdToSessionId, WTSRegisterSessionNotification,
                WTSUnRegisterSessionNotification,
            },
            Threading::{CreateEventW, INFINITE, SetEvent},
        },
        UI::WindowsAndMessaging::{
            CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GWLP_USERDATA,
            GetWindowLongPtrW, MSG, MWMO_INPUTAVAILABLE, MsgWaitForMultipleObjectsEx, PM_REMOVE,
            PeekMessageW, QS_ALLINPUT, RegisterClassW, SetWindowLongPtrW, UnregisterClassW,
            WM_ENDSESSION, WM_NCDESTROY, WM_QUERYENDSESSION, WM_QUIT, WM_WTSSESSION_CHANGE,
            WNDCLASSW,
        },
    },
    core::w,
};
struct State {
    fenced: AtomicBool,
    epoch: AtomicU64,
    cancelled: tokio_util::sync::CancellationToken,
}
impl State {
    fn fence(&self) {
        if !self.fenced.swap(true, Ordering::AcqRel) {
            self.epoch.fetch_add(1, Ordering::AcqRel);
            self.cancelled.cancel();
        }
    }
    fn current(&self) -> Result<u64> {
        if self.fenced.load(Ordering::Acquire) {
            Err(ObservationError::Fenced)
        } else {
            Ok(self.epoch.load(Ordering::Acquire))
        }
    }
}
struct WindowContext {
    state: Arc<State>,
    session: u32,
}
unsafe extern "system" fn window_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    let pointer = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *const WindowContext;
    if !pointer.is_null() {
        let context = unsafe { &*pointer };
        if msg == WM_WTSSESSION_CHANGE {
            // NOTIFY_FOR_THIS_SESSION should only deliver this session. Both
            // matching events and a mismatching/forged observation fail closed.
            if u32::try_from(lparam).ok() != Some(context.session) {
                context.state.fence();
                return 0;
            }
            context.state.fence();
            return 0;
        }
        if matches!(msg, WM_QUERYENDSESSION | WM_ENDSESSION | WM_NCDESTROY) {
            context.state.fence();
        }
        if msg == WM_NCDESTROY {
            unsafe {
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            }
        }
    }
    unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
}
fn event() -> Result<OwnedHandle> {
    // Unnamed, noninheritable, auto-reset event; no cross-process locator.
    let raw = unsafe { CreateEventW(ptr::null(), 0, 0, ptr::null()) };
    if raw.is_null() {
        return Err(ObservationError::NativeQueryFailed);
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}
type Checkpoint = SyncSender<Result<u64>>;
pub(crate) struct NotificationWatch {
    state: Arc<State>,
    stop: Arc<OwnedHandle>,
    wake: Arc<OwnedHandle>,
    requests: SyncSender<Checkpoint>,
    worker: Option<JoinHandle<Result<()>>>,
    terminal: Option<Result<()>>,
    _context: Arc<WindowContext>,
}
impl NotificationWatch {
    pub(crate) fn start_current() -> Result<Self> {
        let mut session = 0;
        if unsafe { ProcessIdToSessionId(std::process::id(), &mut session) } == 0 {
            return Err(ObservationError::NativeQueryFailed);
        }
        if session == 0 {
            return Err(ObservationError::NonInteractive);
        }
        let state = Arc::new(State {
            fenced: AtomicBool::new(false),
            epoch: AtomicU64::new(1),
            cancelled: tokio_util::sync::CancellationToken::new(),
        });
        let stop = Arc::new(event()?);
        let wake = Arc::new(event()?);
        let (requests, rx) = mpsc::sync_channel(1);
        let (ready, answer) = mpsc::sync_channel(1);
        let context = Arc::new(WindowContext {
            state: state.clone(),
            session,
        });
        let thread_context = context.clone();
        let thread_state = state.clone();
        let thread_stop = stop.clone();
        let thread_wake = wake.clone();
        let worker = thread::Builder::new()
            .name("styx-wts-source".into())
            .spawn(move || {
                // All exits, including unwind, invalidate the same source before
                // the receiver disappears; no replacement watch is started.
                struct FenceOnExit(Arc<State>);
                impl Drop for FenceOnExit {
                    fn drop(&mut self) {
                        self.0.fence();
                    }
                }
                let _fence = FenceOnExit(thread_state.clone());
                run_window(thread_context, thread_stop, thread_wake, rx, ready)
            })
            .map_err(|_| ObservationError::NativeQueryFailed)?;
        let mut result = Self {
            state,
            stop,
            wake,
            requests,
            worker: Some(worker),
            terminal: None,
            _context: context,
        };
        match answer.recv() {
            Ok(Ok(())) => Ok(result),
            other => {
                let error = other
                    .ok()
                    .and_then(std::result::Result::err)
                    .unwrap_or(ObservationError::NativeQueryFailed);
                let _ = result.stop_and_join();
                Err(error)
            }
        }
    }
    pub(crate) fn checkpoint(&self) -> Result<u64> {
        self.state.current()?;
        let (answer, receive) = mpsc::sync_channel(1);
        self.requests.try_send(answer).map_err(|_| {
            self.state.fence();
            ObservationError::Fenced
        })?;
        if unsafe { SetEvent(self.wake.as_raw_handle()) } == 0 {
            self.state.fence();
            return Err(ObservationError::NativeQueryFailed);
        }
        // Caller runs on a retained blocking boundary. No timeout detaches the
        // reader or allows unacknowledged old snapshots to continue.
        let result = receive.recv().map_err(|_| ObservationError::Fenced)?;
        let epoch = result?;
        if self.state.current()? != epoch {
            return Err(ObservationError::Fenced);
        }
        Ok(epoch)
    }

    pub(crate) fn invalidation_token(&self) -> tokio_util::sync::CancellationToken {
        self.state.cancelled.clone()
    }

    pub(crate) fn fence(&self) {
        self.state.fence();
    }
    pub(crate) fn stop_and_join(&mut self) -> Result<()> {
        self.state.fence();
        let signalled = unsafe { SetEvent(self.stop.as_raw_handle()) } != 0;
        // Hold custody until the original OS thread actually exits. No HWND,
        // PID or thread-ID lookup is used to stop some replacement instance.
        let joined = match self.worker.take() {
            Some(worker) => worker
                .join()
                .unwrap_or(Err(ObservationError::NativeQueryFailed)),
            None => {
                return self
                    .terminal
                    .unwrap_or(Err(ObservationError::NativeQueryFailed));
            }
        };
        let result = if signalled {
            joined
        } else {
            Err(ObservationError::NativeQueryFailed)
        };
        self.terminal = Some(result);
        result
    }
}
impl Drop for NotificationWatch {
    fn drop(&mut self) {
        let _ = self.stop_and_join();
    }
}
fn drain_messages() -> Result<()> {
    let mut message = MSG::default();
    // A complete queue checkpoint, not a guessed successful poll. A flooded
    // queue fails closed rather than starving stop/reader custody indefinitely.
    for _ in 0..1024 {
        if unsafe { PeekMessageW(&mut message, ptr::null_mut(), 0, 0, PM_REMOVE) } == 0 {
            return Ok(());
        }
        if message.message == WM_QUIT {
            return Err(ObservationError::Fenced);
        }
        unsafe {
            DispatchMessageW(&message);
        }
    }
    Err(ObservationError::Fenced)
}
fn run_window(
    context: Arc<WindowContext>,
    stop: Arc<OwnedHandle>,
    wake: Arc<OwnedHandle>,
    requests: Receiver<Checkpoint>,
    ready: SyncSender<Result<()>>,
) -> Result<()> {
    let state = context.state.clone();
    let module = unsafe { GetModuleHandleW(ptr::null()) };
    if module.is_null() {
        return Err(ObservationError::NativeQueryFailed);
    }
    let class: Vec<u16> = format!("StyxSessionWatch-{}", uuid::Uuid::new_v4())
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let definition = WNDCLASSW {
        lpfnWndProc: Some(window_proc),
        hInstance: module,
        lpszClassName: class.as_ptr(),
        ..Default::default()
    };
    if unsafe { RegisterClassW(&definition) } == 0 {
        return Err(ObservationError::NativeQueryFailed);
    }
    // Invisible top-level window (no WS_VISIBLE/ShowWindow), owned by this one
    // message thread. WTS delivers sent messages through the actual WindowProc.
    let hwnd = unsafe {
        CreateWindowExW(
            0,
            class.as_ptr(),
            w!("Styx session observation"),
            0,
            0,
            0,
            0,
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            module,
            ptr::null(),
        )
    };
    if hwnd.is_null() {
        unsafe {
            UnregisterClassW(class.as_ptr(), module);
        }
        return Err(ObservationError::NativeQueryFailed);
    }
    // Bind only after actual CreateWindowEx returns; never accept a pointer
    // from incoming WM_NCCREATE or other caller-controlled message data.
    unsafe {
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, Arc::as_ptr(&context) as isize);
    }
    if unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } != Arc::as_ptr(&context) as isize {
        unsafe {
            DestroyWindow(hwnd);
            UnregisterClassW(class.as_ptr(), module);
        }
        return Err(ObservationError::NativeQueryFailed);
    }
    let registered = unsafe { WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION) } != 0;
    let result = if !registered {
        Err(ObservationError::NativeQueryFailed)
    } else {
        (|| {
            drain_messages()?;
            if ready.send(Ok(())).is_err() {
                return Err(ObservationError::Fenced);
            }
            let handles = [stop.as_raw_handle(), wake.as_raw_handle()];
            loop {
                let reason = unsafe {
                    MsgWaitForMultipleObjectsEx(
                        handles.len() as u32,
                        handles.as_ptr(),
                        INFINITE,
                        QS_ALLINPUT,
                        MWMO_INPUTAVAILABLE,
                    )
                };
                if reason == WAIT_OBJECT_0 {
                    break Ok(());
                }
                if reason != WAIT_OBJECT_0 + 1 && reason != WAIT_OBJECT_0 + 2 {
                    break Err(ObservationError::NativeQueryFailed);
                }
                drain_messages()?;
                while let Ok(answer) = requests.try_recv() {
                    let _ = answer.send(state.current());
                }
            }
        })()
    };
    state.fence();
    // Each successful registration has its corresponding unregister; an API
    // failure is retained as Unknown cleanup, never a successful close ACK.
    let unregistered = !registered || unsafe { WTSUnRegisterSessionNotification(hwnd) } != 0;
    let destroyed = unsafe { DestroyWindow(hwnd) } != 0;
    let unclassed = unsafe { UnregisterClassW(class.as_ptr(), module) } != 0;
    // Parent NotificationWatch retains the same context through actual thread
    // join, even if DestroyWindow fails or this thread unwinds. No dangling
    // WindowProc context is freed while its original OS thread could call it.
    drop(context);
    if !unregistered || !destroyed || !unclassed {
        return Err(ObservationError::NativeQueryFailed);
    }
    result
}
