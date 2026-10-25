//! Read-only observations of THIS process and its original interactive desktop.
//! No remote PID, path, pipe, session selector, impersonation or desktop switch.
//! Supported packaging baseline is Windows 10+; old WTS lock-flag inversions
//! on Windows 7/2008 R2 are deliberately not supported.
#![allow(unsafe_code)]
use crate::store::ProcessIdentity;
use std::{
    ffi::c_void,
    mem::size_of,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
};
use styx_contracts::session::SessionIdentity;
use windows_sys::Win32::{
    Foundation::{
        ERROR_ACCESS_DENIED, ERROR_CANCELLED, ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA,
        ERROR_NO_TOKEN, FILETIME, GetLastError, HANDLE, HWND, LPARAM, LocalFree, SetLastError,
    },
    Security::{
        self, Authorization::ConvertSidToStringSidW, GetTokenInformation, TOKEN_INFORMATION_CLASS,
        TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_STATISTICS, TOKEN_USER, TokenIntegrityLevel,
        TokenPrimary, TokenSessionId, TokenStatistics, TokenUser,
    },
    System::{
        RemoteDesktop::{
            ProcessIdToSessionId, WTS_CURRENT_SERVER_HANDLE, WTS_SESSIONSTATE_LOCK,
            WTS_SESSIONSTATE_UNLOCK, WTSActive, WTSFreeMemory, WTSINFOEXW,
            WTSQuerySessionInformationW, WTSSessionInfoEx,
        },
        StationsAndDesktops::{
            CloseDesktop, DESKTOP_READOBJECTS, EnumDesktopWindows, GetProcessWindowStation,
            GetThreadDesktop, GetUserObjectInformationW, HDESK, OpenInputDesktop, UOI_IO, UOI_NAME,
        },
        Threading::{
            GetCurrentProcess, GetCurrentThread, GetCurrentThreadId, GetProcessTimes, OpenProcess,
            OpenProcessToken, OpenThreadToken, PROCESS_QUERY_LIMITED_INFORMATION,
        },
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ObservationError {
    #[error("windows_session_permission_denied")]
    PermissionDenied,
    #[error("windows_session_native_query_failed")]
    NativeQueryFailed,
    #[error("windows_session_fact_malformed")]
    Malformed,
    #[error("windows_session_impersonated_thread")]
    Impersonated,
    #[error("windows_session_noninteractive")]
    NonInteractive,
    #[error("windows_session_disconnected")]
    Disconnected,
    #[error("windows_session_locked")]
    Locked,
    #[error("windows_session_lock_unknown")]
    LockUnknown,
    #[error("windows_session_input_desktop_unavailable")]
    InputDesktopUnavailable,
    #[error("windows_session_identity_changed")]
    Changed,
    #[error("windows_session_reader_busy")]
    Busy,
    #[error("windows_session_observation_stopped")]
    Stopped,
    #[error("windows_window_enumeration_limit")]
    EnumerationLimit,
    #[error("windows_session_source_fenced")]
    Fenced,
}
pub(crate) type Result<T> = std::result::Result<T, ObservationError>;
fn failed() -> ObservationError {
    if unsafe { GetLastError() } == ERROR_ACCESS_DENIED {
        ObservationError::PermissionDenied
    } else {
        ObservationError::NativeQueryFailed
    }
}
fn no_impersonation() -> Result<()> {
    let mut raw = ptr::null_mut();
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) } != 0 {
        // Even an apparently equal impersonation token is not the primary
        // process execution identity that the Cua child will inherit.
        let _token = unsafe { OwnedHandle::from_raw_handle(raw) };
        return Err(ObservationError::Impersonated);
    }
    if unsafe { GetLastError() } == ERROR_NO_TOKEN {
        Ok(())
    } else {
        Err(failed())
    }
}
fn process_token() -> Result<OwnedHandle> {
    let mut raw = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
        return Err(failed());
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}
struct TokenBuffer {
    words: Vec<usize>,
    len: usize,
}
impl TokenBuffer {
    fn read(token: &OwnedHandle, class: TOKEN_INFORMATION_CLASS) -> Result<Self> {
        let mut required = 0;
        let ok = unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                class,
                ptr::null_mut(),
                0,
                &mut required,
            )
        };
        if ok != 0
            || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER
            || !(1..=65536).contains(&required)
        {
            return Err(ObservationError::Malformed);
        }
        let capacity = required;
        let mut words = vec![0usize; (capacity as usize).div_ceil(size_of::<usize>())];
        if unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                class,
                words.as_mut_ptr().cast(),
                capacity,
                &mut required,
            )
        } == 0
        {
            return Err(failed());
        }
        if required == 0 || required > capacity {
            return Err(ObservationError::Malformed);
        }
        Ok(Self {
            words,
            len: required as usize,
        })
    }
    fn value<T: Copy>(&self) -> Result<T> {
        if size_of::<T>() > self.len {
            return Err(ObservationError::Malformed);
        }
        // Windows initialized at least size_of<T>; read_unaligned also avoids
        // assuming stronger alignment than the official token allocation.
        Ok(unsafe { ptr::read_unaligned(self.words.as_ptr().cast::<T>()) })
    }
    fn sid(&self, sid: Security::PSID) -> Result<&[u8]> {
        let start = self.words.as_ptr() as usize;
        let end = start
            .checked_add(self.len)
            .ok_or(ObservationError::Malformed)?;
        let address = sid as usize;
        if address < start || address.checked_add(8).is_none_or(|n| n > end) {
            return Err(ObservationError::Malformed);
        }
        let prefix = unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), 8) };
        let length = 8 + usize::from(prefix[1]) * 4;
        if address.checked_add(length).is_none_or(|n| n > end)
            || unsafe { Security::IsValidSid(sid) } == 0
        {
            return Err(ObservationError::Malformed);
        }
        Ok(unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), length) })
    }
}
struct LocalAllocation(*mut c_void);
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
fn user_sid(buffer: &TokenBuffer) -> Result<String> {
    let user: TOKEN_USER = buffer.value()?;
    buffer.sid(user.User.Sid)?;
    let mut text = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } == 0 {
        return Err(failed());
    }
    let _owned = LocalAllocation(text.cast());
    let mut length = 0;
    while length < 184 && unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    if length == 184 {
        return Err(ObservationError::Malformed);
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })
        .map_err(|_| ObservationError::Malformed)
}
#[derive(Clone, PartialEq, Eq)]
struct TokenFacts {
    sid: String,
    authentication_luid: u64,
    session_id: u32,
    integrity: u32,
    token_id: u64,
    modified_id: u64,
}
fn luid(value: windows_sys::Win32::Foundation::LUID) -> u64 {
    ((value.HighPart as u32 as u64) << 32) | u64::from(value.LowPart)
}
fn token_facts(token: &OwnedHandle) -> Result<TokenFacts> {
    let before: TOKEN_STATISTICS = TokenBuffer::read(token, TokenStatistics)?.value()?;
    if before.TokenType != TokenPrimary {
        return Err(ObservationError::Impersonated);
    }
    let sid = user_sid(&TokenBuffer::read(token, TokenUser)?)?;
    let session_id = TokenBuffer::read(token, TokenSessionId)?.value::<u32>()?;
    let label = TokenBuffer::read(token, TokenIntegrityLevel)?;
    let mandatory: TOKEN_MANDATORY_LABEL = label.value()?;
    let bytes = label.sid(mandatory.Label.Sid)?;
    // Mandatory label S-1-16-RID; no arbitrary SID tail interpreted as integrity.
    if bytes.len() != 12 || bytes[..8] != [1, 1, 0, 0, 0, 0, 0, 16] {
        return Err(ObservationError::Malformed);
    }
    let integrity = u32::from_le_bytes(
        bytes[8..12]
            .try_into()
            .map_err(|_| ObservationError::Malformed)?,
    );
    let after: TOKEN_STATISTICS = TokenBuffer::read(token, TokenStatistics)?.value()?;
    if luid(before.TokenId) != luid(after.TokenId)
        || luid(before.ModifiedId) != luid(after.ModifiedId)
        || luid(before.AuthenticationId) != luid(after.AuthenticationId)
        || after.TokenType != TokenPrimary
    {
        return Err(ObservationError::Changed);
    }
    Ok(TokenFacts {
        sid,
        authentication_luid: luid(before.AuthenticationId),
        session_id,
        integrity,
        token_id: luid(before.TokenId),
        modified_id: luid(before.ModifiedId),
    })
}
struct WtsMemory(*mut c_void);
impl Drop for WtsMemory {
    fn drop(&mut self) {
        unsafe {
            WTSFreeMemory(self.0);
        }
    }
}
#[derive(Clone, PartialEq, Eq)]
struct WtsInstance {
    logon_time_100ns: i64,
    connection_time_100ns: i64,
}
fn unlocked_logon(session_id: u32) -> Result<WtsInstance> {
    let mut raw = ptr::null_mut();
    let mut bytes = 0;
    if unsafe {
        WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            session_id,
            WTSSessionInfoEx,
            &mut raw,
            &mut bytes,
        )
    } == 0
    {
        return Err(failed());
    }
    let _owned = WtsMemory(raw.cast());
    if raw.is_null() || bytes as usize != size_of::<WTSINFOEXW>() {
        return Err(ObservationError::Malformed);
    }
    let info = unsafe { ptr::read_unaligned(raw.cast::<WTSINFOEXW>()) };
    if info.Level != 1 {
        return Err(ObservationError::Malformed);
    }
    let row = unsafe { info.Data.WTSInfoExLevel1 };
    if row.SessionId != session_id || row.LogonTime <= 0 || row.ConnectTime < 0 {
        return Err(ObservationError::Changed);
    }
    if row.SessionState != WTSActive {
        return Err(ObservationError::Disconnected);
    }
    match row.SessionFlags as u32 {
        WTS_SESSIONSTATE_UNLOCK => Ok(WtsInstance {
            logon_time_100ns: row.LogonTime,
            connection_time_100ns: row.ConnectTime,
        }),
        WTS_SESSIONSTATE_LOCK => Err(ObservationError::Locked),
        _ => Err(ObservationError::LockUnknown),
    }
}
fn object_name(object: HANDLE) -> Result<String> {
    if object.is_null() {
        return Err(ObservationError::InputDesktopUnavailable);
    }
    let mut text = [0u16; 256];
    let mut needed = 0;
    if unsafe {
        GetUserObjectInformationW(
            object,
            UOI_NAME,
            text.as_mut_ptr().cast(),
            (text.len() * 2) as u32,
            &mut needed,
        )
    } == 0
    {
        return Err(failed());
    }
    if needed < 2 || needed as usize > text.len() * 2 || needed % 2 != 0 {
        return Err(ObservationError::Malformed);
    }
    let length = needed as usize / 2;
    if text[length - 1] != 0 || text[..length - 1].contains(&0) {
        return Err(ObservationError::Malformed);
    }
    String::from_utf16(&text[..length - 1]).map_err(|_| ObservationError::Malformed)
}
fn receives_input(desktop: HDESK) -> Result<()> {
    let mut receives = 0i32;
    let mut needed = 0;
    if unsafe {
        GetUserObjectInformationW(
            desktop,
            UOI_IO,
            (&mut receives as *mut i32).cast(),
            size_of::<i32>() as u32,
            &mut needed,
        )
    } == 0
    {
        return Err(failed());
    }
    if needed as usize != size_of::<i32>() || receives != 1 {
        return Err(ObservationError::InputDesktopUnavailable);
    }
    Ok(())
}
struct Desktop(HDESK);
impl Drop for Desktop {
    fn drop(&mut self) {
        unsafe {
            CloseDesktop(self.0);
        }
    }
}
// This opened read-only desktop is never assigned using SetThreadDesktop.
// Win32 object queries and closing this owned handle may run on a different
// blocking thread; no COM/UIA object or thread-local desktop ownership is moved.
unsafe impl Send for Desktop {}
unsafe impl Sync for Desktop {}
fn input_desktop() -> Result<Desktop> {
    let raw = unsafe { OpenInputDesktop(0, 0, DESKTOP_READOBJECTS) };
    if raw.is_null() {
        return Err(failed());
    }
    Ok(Desktop(raw))
}
fn original_process(process: &OwnedHandle, expected: &ProcessIdentity) -> Result<()> {
    let ProcessIdentity::Windows {
        creation_time_100ns,
        ..
    } = expected
    else {
        return Err(ObservationError::Malformed);
    };
    let mut birth = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    if unsafe {
        GetProcessTimes(
            process.as_raw_handle(),
            &mut birth,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    } == 0
    {
        return Err(failed());
    }
    let value = (u64::from(birth.dwHighDateTime) << 32) | u64::from(birth.dwLowDateTime);
    if value != *creation_time_100ns
        || ProcessIdentity::current().map_err(|_| ObservationError::Changed)? != *expected
    {
        return Err(ObservationError::Changed);
    }
    Ok(())
}
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct NativeObservation {
    pub(crate) process: ProcessIdentity,
    pub(crate) identity: SessionIdentity,
    token: TokenFacts,
    wts: WtsInstance,
}
/// Retains original process, primary token and input-desktop object. No serde,
/// path constructor or caller-supplied fact can reconstruct this binding.
pub(crate) struct NativeSession {
    process: OwnedHandle,
    token: OwnedHandle,
    desktop: Desktop,
    expected: NativeObservation,
}
impl NativeSession {
    pub(crate) fn acquire_current() -> Result<Self> {
        no_impersonation()?;
        let process_identity =
            ProcessIdentity::current().map_err(|_| ObservationError::NativeQueryFailed)?;
        let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, std::process::id()) };
        if raw.is_null() {
            return Err(failed());
        }
        let process = unsafe { OwnedHandle::from_raw_handle(raw) };
        original_process(&process, &process_identity)?;
        let token = process_token()?;
        let facts = token_facts(&token)?;
        let ProcessIdentity::Windows { owner_sid, .. } = &process_identity else {
            return Err(ObservationError::Malformed);
        };
        if owner_sid != &facts.sid {
            return Err(ObservationError::Changed);
        }
        if facts.session_id == 0 {
            return Err(ObservationError::NonInteractive);
        }
        let wts = unlocked_logon(facts.session_id)?;
        let desktop = input_desktop()?;
        let expected = NativeObservation {
            process: process_identity,
            identity: SessionIdentity::Windows {
                sid: facts.sid.clone(),
                authentication_luid: facts.authentication_luid,
                session_id: facts.session_id,
                window_station: "WinSta0".into(),
                desktop: "Default".into(),
                integrity_level: facts.integrity,
            },
            token: facts,
            wts,
        };
        let source = Self {
            process,
            token,
            desktop,
            expected,
        };
        source.observe()?;
        Ok(source)
    }
    pub(crate) fn observe(&self) -> Result<NativeObservation> {
        no_impersonation()?;
        original_process(&self.process, &self.expected.process)?;
        let mut session = 0;
        if unsafe { ProcessIdToSessionId(std::process::id(), &mut session) } == 0 {
            return Err(failed());
        }
        if session != self.expected.token.session_id {
            return Err(ObservationError::Changed);
        }
        if token_facts(&self.token)? != self.expected.token
            || token_facts(&process_token()?)? != self.expected.token
        {
            return Err(ObservationError::Changed);
        }
        let before = unlocked_logon(session)?;
        if before != self.expected.wts {
            return Err(ObservationError::Changed);
        }
        let station = unsafe { GetProcessWindowStation() };
        let thread = unsafe { GetThreadDesktop(GetCurrentThreadId()) };
        if object_name(station)? != "WinSta0"
            || object_name(thread)? != "Default"
            || object_name(self.desktop.0)? != "Default"
        {
            return Err(ObservationError::NonInteractive);
        }
        receives_input(thread)?;
        receives_input(self.desktop.0)?;
        // A newly opened input object must agree too. OpenInputDesktop alone
        // is insufficient: disconnected RDP may return a future input desktop.
        let current = input_desktop()?;
        if object_name(current.0)? != "Default" {
            return Err(ObservationError::InputDesktopUnavailable);
        }
        receives_input(current.0)?;
        if unlocked_logon(session)? != before {
            return Err(ObservationError::Changed);
        }
        original_process(&self.process, &self.expected.process)?;
        if token_facts(&process_token()?)? != self.expected.token {
            return Err(ObservationError::Changed);
        }
        no_impersonation()?;
        Ok(self.expected.clone())
    }
}

/// Successful complete enumeration proves only the window-query provider.
/// Counts/empty desktop never grant screenshot, UIA or input availability.
#[derive(Clone, Copy)]
pub(crate) struct WindowReadEvidence {
    pub(crate) count: u32,
}
struct Enumeration<'a> {
    count: u32,
    stop: &'a tokio_util::sync::CancellationToken,
    terminal: Option<ObservationError>,
}
unsafe extern "system" fn count_window(_window: HWND, data: LPARAM) -> i32 {
    // EnumDesktopWindows invokes synchronously with our original stack pointer.
    let state = unsafe { &mut *(data as *mut Enumeration<'_>) };
    if state.stop.is_cancelled() {
        state.terminal = Some(ObservationError::Stopped);
        unsafe {
            SetLastError(ERROR_CANCELLED);
        }
        return 0;
    }
    if state.count == 4096 {
        state.terminal = Some(ObservationError::EnumerationLimit);
        unsafe {
            SetLastError(ERROR_MORE_DATA);
        }
        return 0;
    }
    state.count += 1;
    1
}
impl NativeSession {
    pub(crate) fn enumerate_windows(
        &self,
        stop: &tokio_util::sync::CancellationToken,
    ) -> Result<WindowReadEvidence> {
        if stop.is_cancelled() {
            return Err(ObservationError::Stopped);
        }
        let mut state = Enumeration {
            count: 0,
            stop,
            terminal: None,
        };
        // Explicit original non-null desktop. READOBJECTS is the documented
        // access right; no DESKTOP_SWITCHDESKTOP/elevation/new selector.
        let success = unsafe {
            EnumDesktopWindows(
                self.desktop.0,
                Some(count_window),
                (&mut state as *mut Enumeration<'_>) as LPARAM,
            )
        };
        if let Some(reason) = state.terminal {
            return Err(reason);
        }
        if success == 0 {
            return Err(failed());
        }
        if stop.is_cancelled() {
            return Err(ObservationError::Stopped);
        }
        Ok(WindowReadEvidence { count: state.count })
    }
}

struct WindowSearch {
    window: HWND,
    pid: u32,
    count: u32,
    found: bool,
    refused: bool,
}
unsafe extern "system" fn find_window(window: HWND, data: LPARAM) -> i32 {
    let search = unsafe { &mut *(data as *mut WindowSearch) };
    if search.count == 4096 {
        search.refused = true;
        unsafe {
            SetLastError(ERROR_MORE_DATA);
        }
        return 0;
    }
    search.count += 1;
    if window == search.window {
        let mut pid = 0;
        if unsafe {
            windows_sys::Win32::UI::WindowsAndMessaging::GetWindowThreadProcessId(window, &mut pid)
        } == 0
            || pid != search.pid
        {
            search.refused = true;
            unsafe {
                SetLastError(ERROR_CANCELLED);
            }
            return 0;
        }
        search.found = true;
    }
    1
}
impl NativeSession {
    pub(crate) fn contains_window(&self, pid: u32, window: u64) -> Result<()> {
        let raw = usize::try_from(window).map_err(|_| ObservationError::Malformed)? as HWND;
        if raw.is_null() || pid == 0 {
            return Err(ObservationError::Malformed);
        }
        let mut search = WindowSearch {
            window: raw,
            pid,
            count: 0,
            found: false,
            refused: false,
        };
        let success = unsafe {
            EnumDesktopWindows(
                self.desktop.0,
                Some(find_window),
                (&mut search as *mut WindowSearch) as LPARAM,
            )
        };
        if success == 0 || search.refused {
            return Err(failed());
        }
        if !search.found {
            return Err(ObservationError::Changed);
        }
        Ok(())
    }
}
