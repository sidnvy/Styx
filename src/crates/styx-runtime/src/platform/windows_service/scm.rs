//! Bounded official Windows APIs; every effect uses the original open service.
use super::{Result, ServiceError, ServiceRole, changed, unknown};
use crate::store::{PinnedExecutable, ProcessIdentity, windows_file_identity};
use std::{
    ffi::{OsStr, OsString},
    fs::{File, OpenOptions},
    mem::{offset_of, size_of},
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        fs::{MetadataExt, OpenOptionsExt},
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::{Path, PathBuf},
    ptr,
    sync::Mutex,
};
use styx_contracts::identity::Sha256Digest;
use windows_sys::Win32::{
    Foundation::{
        ERROR_INSUFFICIENT_BUFFER, ERROR_SERVICE_DOES_NOT_EXIST, FILETIME, GetLastError,
        WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Security::{
        Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW},
        *,
    },
    Storage::FileSystem::FILE_SHARE_READ,
    System::{
        Services::*,
        Threading::{
            GetProcessTimes, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
            QueryFullProcessImageNameW, WaitForSingleObject,
        },
    },
};
const READ_CONTROL: u32 = 0x0002_0000;
const DELETE: u32 = 0x0001_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;
fn no_impersonation() -> Result<()> {
    let mut raw = ptr::null_mut();
    if unsafe {
        windows_sys::Win32::System::Threading::OpenThreadToken(
            windows_sys::Win32::System::Threading::GetCurrentThread(),
            TOKEN_QUERY,
            1,
            &mut raw,
        )
    } != 0
    {
        let _held = unsafe { OwnedHandle::from_raw_handle(raw) };
        return Err(ServiceError::Conflict);
    }
    if unsafe { GetLastError() } != windows_sys::Win32::Foundation::ERROR_NO_TOKEN {
        return Err(ServiceError::Unavailable);
    }
    Ok(())
}
fn native() -> ServiceError {
    ServiceError::Unavailable
}
fn wide(value: &OsStr) -> Result<Vec<u16>> {
    let mut value: Vec<_> = value.encode_wide().collect();
    if value.is_empty() || value.len() > 32760 || value.contains(&0) {
        return Err(ServiceError::Invalid);
    }
    value.push(0);
    Ok(value)
}
fn quote(path: &Path) -> Result<String> {
    let text = path.to_str().ok_or(ServiceError::Invalid)?;
    if !path.is_absolute()
        || text.is_empty()
        || text.len() > 4096
        || text.ends_with(['\\', '/'])
        || text.contains(['"', '\0', '\r', '\n'])
        || path.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(ServiceError::Invalid);
    }
    Ok(format!("\"{text}\""))
}
pub(super) fn command_line(image: &Path, state: &Path, role: ServiceRole) -> Result<String> {
    Ok(format!(
        "{} __service-run --state-dir {} --role {}",
        quote(image)?,
        quote(state)?,
        role.name()
    ))
}
struct Local(*mut core::ffi::c_void);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::LocalFree(self.0);
        }
    }
}
fn sid_text(sid: PSID) -> Result<String> {
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err(ServiceError::Conflict);
    }
    let mut value = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut value) } == 0 || value.is_null() {
        return Err(native());
    }
    let _owned = Local(value.cast());
    let mut n = 0;
    while n < 192 && unsafe { *value.add(n) } != 0 {
        n += 1;
    }
    if n == 192 {
        return Err(ServiceError::Conflict);
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(value, n) }).map_err(changed)
}
/// Buffers are pointer-aligned and all nested OS pointers are bounded before use.
struct Buffer {
    words: Vec<usize>,
    length: usize,
}
impl Buffer {
    fn new(bytes: usize) -> Result<Self> {
        if bytes == 0 || bytes > 65536 {
            return Err(ServiceError::Conflict);
        }
        Ok(Self {
            words: vec![0; bytes.div_ceil(size_of::<usize>())],
            length: bytes,
        })
    }
    fn pointer(&mut self) -> *mut u8 {
        self.words.as_mut_ptr().cast()
    }
    fn base(&self) -> usize {
        self.words.as_ptr() as usize
    }
    fn contains(&self, pointer: *const core::ffi::c_void, bytes: usize) -> bool {
        let start = pointer as usize;
        start >= self.base()
            && start
                .checked_add(bytes)
                .is_some_and(|end| end <= self.base() + self.length)
    }
    fn value<T: Copy>(&self) -> Result<T> {
        if self.length < size_of::<T>() {
            return Err(ServiceError::Conflict);
        }
        Ok(unsafe { ptr::read_unaligned(self.words.as_ptr().cast::<T>()) })
    }
    fn string(&self, value: *const u16) -> Result<String> {
        if value.is_null() || (value as usize) % 2 != 0 {
            return Err(ServiceError::Conflict);
        }
        let mut n = 0;
        while n < 32768 && self.contains(unsafe { value.add(n) }.cast(), 2) {
            if unsafe { *value.add(n) } == 0 {
                return String::from_utf16(unsafe { std::slice::from_raw_parts(value, n) })
                    .map_err(changed);
            }
            n += 1;
        }
        Err(ServiceError::Conflict)
    }
    fn sid(&self, value: PSID) -> Result<String> {
        if !self.contains(value, 8) {
            return Err(ServiceError::Conflict);
        }
        let count = unsafe { *value.cast::<u8>().add(1) } as usize;
        if !self.contains(value, 8 + count * 4) {
            return Err(ServiceError::Conflict);
        }
        sid_text(value)
    }
}
fn account_sid(name: &str) -> Result<String> {
    let name = wide(OsStr::new(name))?;
    let (mut bytes, mut chars, mut kind) = (0, 0, 0);
    if unsafe {
        LookupAccountNameW(
            ptr::null(),
            name.as_ptr(),
            ptr::null_mut(),
            &mut bytes,
            ptr::null_mut(),
            &mut chars,
            &mut kind,
        )
    } != 0
        || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER
        || !(1..=32768).contains(&chars)
    {
        return Err(native());
    }
    let mut sid = Buffer::new(bytes as usize)?;
    let mut domain = vec![0u16; chars as usize];
    let capacity = bytes;
    if unsafe {
        LookupAccountNameW(
            ptr::null(),
            name.as_ptr(),
            sid.pointer().cast(),
            &mut bytes,
            domain.as_mut_ptr(),
            &mut chars,
            &mut kind,
        )
    } == 0
        || bytes > capacity
        || kind != SidTypeUser
    {
        return Err(ServiceError::Conflict);
    }
    sid.sid(sid.words.as_ptr().cast_mut().cast())
}
pub(super) fn current_account(expected_sid: &str) -> Result<String> {
    no_impersonation()?;
    let text = wide(OsStr::new(expected_sid))?;
    let mut sid = ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(text.as_ptr(), &mut sid) } == 0 {
        return Err(native());
    }
    let _owned = Local(sid);
    let (mut names, mut domains, mut kind) = (0, 0, 0);
    if unsafe {
        LookupAccountSidW(
            ptr::null(),
            sid,
            ptr::null_mut(),
            &mut names,
            ptr::null_mut(),
            &mut domains,
            &mut kind,
        )
    } != 0
        || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER
        || !(1..=32768).contains(&names)
        || !(1..=32768).contains(&domains)
    {
        return Err(native());
    }
    let (mut name, mut domain) = (vec![0; names as usize], vec![0; domains as usize]);
    let (name_cap, domain_cap) = (names, domains);
    if unsafe {
        LookupAccountSidW(
            ptr::null(),
            sid,
            name.as_mut_ptr(),
            &mut names,
            domain.as_mut_ptr(),
            &mut domains,
            &mut kind,
        )
    } == 0
        || names >= name_cap
        || domains >= domain_cap
        || kind != SidTypeUser
    {
        return Err(ServiceError::Conflict);
    }
    let value = format!(
        "{}\\{}",
        String::from_utf16(&domain[..domains as usize]).map_err(changed)?,
        String::from_utf16(&name[..names as usize]).map_err(changed)?
    );
    if account_sid(&value)? != expected_sid {
        return Err(ServiceError::Conflict);
    }
    Ok(value)
}
struct ScHandle(SC_HANDLE);
// SCM handles are kernel-managed thread-safe references; no Rust aliasable data
// is behind this pointer. Effects are serialized by the C07 operation owner.
unsafe impl Send for ScHandle {}
unsafe impl Sync for ScHandle {}
impl Drop for ScHandle {
    fn drop(&mut self) {
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}
#[derive(Clone, PartialEq, Eq)]
struct Config {
    binary: String,
    sid: String,
    start_type: u32,
}
fn configuration(handle: &ScHandle) -> Result<Config> {
    let mut required = 0;
    if unsafe { QueryServiceConfigW(handle.0, ptr::null_mut(), 0, &mut required) } != 0
        || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER
        || required > 8192
    {
        return Err(native());
    }
    let mut raw = Buffer::new(required as usize)?;
    let capacity = required;
    if unsafe { QueryServiceConfigW(handle.0, raw.pointer().cast(), capacity, &mut required) } == 0
        || required > capacity
    {
        return Err(native());
    }
    let value = raw.value::<QUERY_SERVICE_CONFIGW>()?;
    if value.dwServiceType != SERVICE_WIN32_OWN_PROCESS
        || value.dwTagId != 0
        || value.dwErrorControl != SERVICE_ERROR_NORMAL
        || !matches!(value.dwStartType, SERVICE_DEMAND_START | SERVICE_AUTO_START)
        || !raw.string(value.lpLoadOrderGroup)?.is_empty()
        || !raw.string(value.lpDependencies)?.is_empty()
    {
        return Err(ServiceError::Conflict);
    }
    let account = raw.string(value.lpServiceStartName)?;
    Ok(Config {
        binary: raw.string(value.lpBinaryPathName)?,
        sid: account_sid(&account)?,
        start_type: value.dwStartType,
    })
}
fn config2(handle: &ScHandle, class: u32) -> Result<Buffer> {
    let mut required = 0;
    if unsafe { QueryServiceConfig2W(handle.0, class, ptr::null_mut(), 0, &mut required) } != 0
        || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER
    {
        return Err(native());
    }
    let mut raw = Buffer::new(required as usize)?;
    let capacity = required;
    if unsafe { QueryServiceConfig2W(handle.0, class, raw.pointer(), capacity, &mut required) } == 0
        || required > capacity
    {
        return Err(native());
    }
    Ok(raw)
}
fn no_automatic_replay(handle: &ScHandle) -> Result<()> {
    let actions = config2(handle, SERVICE_CONFIG_FAILURE_ACTIONS)?;
    let actions = actions.value::<SERVICE_FAILURE_ACTIONSW>()?;
    if actions.cActions != 0 {
        return Err(ServiceError::Conflict);
    }
    let flags = config2(handle, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG)?
        .value::<SERVICE_FAILURE_ACTIONS_FLAG>()?;
    let triggers = config2(handle, SERVICE_CONFIG_TRIGGER_INFO)?.value::<SERVICE_TRIGGER_INFO>()?;
    let delayed = config2(handle, SERVICE_CONFIG_DELAYED_AUTO_START_INFO)?
        .value::<SERVICE_DELAYED_AUTO_START_INFO>()?;
    if flags.fFailureActionsOnNonCrashFailures != 0
        || triggers.cTriggers != 0
        || delayed.fDelayedAutostart != 0
    {
        return Err(ServiceError::Conflict);
    }
    Ok(())
}
fn security(handle: &ScHandle, sid: &str) -> Result<Sha256Digest> {
    let mut required = 0;
    let flags = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    if unsafe { QueryServiceObjectSecurity(handle.0, flags, ptr::null_mut(), 0, &mut required) }
        != 0
        || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER
    {
        return Err(native());
    }
    let mut raw = Buffer::new(required as usize)?;
    let capacity = required;
    if unsafe {
        QueryServiceObjectSecurity(
            handle.0,
            flags,
            raw.pointer().cast(),
            capacity,
            &mut required,
        )
    } == 0
        || required > capacity
    {
        return Err(native());
    }
    let descriptor = raw.pointer().cast();
    let (mut owner, mut acl) = (ptr::null_mut(), ptr::null_mut());
    let (mut defaulted, mut present) = (0, 0);
    if unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut defaulted) } == 0
        || unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted) }
            == 0
        || present == 0
        || acl.is_null()
    {
        return Err(ServiceError::Conflict);
    }
    let trusted = |s: &str| s == sid || s == "S-1-5-18" || s == "S-1-5-32-544";
    if !trusted(&raw.sid(owner)?) || !raw.contains(acl.cast(), size_of::<ACL>()) {
        return Err(ServiceError::Conflict);
    }
    let header = unsafe { ptr::read_unaligned(acl) };
    if !raw.contains(acl.cast(), usize::from(header.AclSize))
        || unsafe { IsValidAcl(acl) } == 0
        || header.AceCount > 4096
    {
        return Err(ServiceError::Conflict);
    }
    let acl_start = acl as usize;
    let acl_end = acl_start + usize::from(header.AclSize);
    for index in 0..u32::from(header.AceCount) {
        let mut ace = ptr::null_mut();
        if unsafe { GetAce(acl, index, &mut ace) } == 0
            || !raw.contains(ace, size_of::<ACE_HEADER>())
        {
            return Err(ServiceError::Conflict);
        }
        let header = unsafe { ptr::read_unaligned(ace.cast::<ACE_HEADER>()) };
        let start = ace as usize;
        let length = usize::from(header.AceSize);
        if start < acl_start
            || start.checked_add(length).is_none_or(|end| end > acl_end)
            || length < size_of::<ACE_HEADER>()
        {
            return Err(ServiceError::Conflict);
        }
        // Unknown/callback/object allow ACE semantics are refused, not skipped.
        if header.AceType == 1 {
            continue;
        } // ACCESS_DENIED_ACE cannot grant access.
        if header.AceType != 0 || length < 16 {
            return Err(ServiceError::Conflict);
        }
        let mask = unsafe { ptr::read_unaligned(ace.cast::<u8>().add(4).cast::<u32>()) };
        let trustee = unsafe { ace.cast::<u8>().add(8).cast() };
        let trustee_sid = raw.sid(trustee)?;
        let sid_bytes = unsafe { GetLengthSid(trustee) } as usize;
        if 8 + sid_bytes > length {
            return Err(ServiceError::Conflict);
        }
        // Read/query access may be public. Every write/start/stop/delete/owner/
        // DACL/generic grant is restricted to the original user or OS admins.
        const READ_ONLY: u32 = 0x8000_0000
            | READ_CONTROL
            | SERVICE_QUERY_CONFIG
            | SERVICE_QUERY_STATUS
            | SERVICE_INTERROGATE
            | SERVICE_ENUMERATE_DEPENDENTS;
        if mask & !READ_ONLY != 0 && !trusted(&trustee_sid) {
            return Err(ServiceError::Conflict);
        }
    }
    Ok(Sha256Digest::of_bytes(unsafe {
        std::slice::from_raw_parts(raw.words.as_ptr().cast::<u8>(), required as usize)
    }))
}
pub(super) struct Registration {
    handle: ScHandle,
    immutable: Config,
    security: Sha256Digest,
    // Serialize native effects even inside a single retained original owner.
    effect: Mutex<()>,
}
impl Registration {
    pub(super) fn open(name: &str, command: &str, sid: &str) -> Result<Option<Self>> {
        no_impersonation()?;
        let manager = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) };
        if manager.is_null() {
            return Err(native());
        }
        let manager = ScHandle(manager);
        let name = wide(OsStr::new(name))?;
        let service = unsafe {
            OpenServiceW(
                manager.0,
                name.as_ptr(),
                SERVICE_QUERY_CONFIG
                    | SERVICE_QUERY_STATUS
                    | SERVICE_START
                    | SERVICE_STOP
                    | SERVICE_CHANGE_CONFIG
                    | READ_CONTROL
                    | DELETE,
            )
        };
        if service.is_null() {
            return if unsafe { GetLastError() } == ERROR_SERVICE_DOES_NOT_EXIST {
                Ok(None)
            } else {
                Err(native())
            };
        }
        let handle = ScHandle(service);
        let immutable = configuration(&handle)?;
        if immutable.binary != command || immutable.sid != sid {
            return Err(ServiceError::Conflict);
        }
        no_automatic_replay(&handle)?;
        let security = security(&handle, sid)?;
        let value = Self {
            handle,
            immutable,
            security,
            effect: Mutex::new(()),
        };
        value.validate(command, sid)?;
        Ok(Some(value))
    }
    pub(super) fn validate(&self, command: &str, sid: &str) -> Result<()> {
        no_impersonation()?;
        let config = configuration(&self.handle)?;
        if config.binary != self.immutable.binary
            || config.sid != self.immutable.sid
            || config.binary != command
            || config.sid != sid
            || security(&self.handle, sid)? != self.security
        {
            return Err(ServiceError::Conflict);
        }
        no_automatic_replay(&self.handle)
    }
    pub(super) fn status(&self) -> Result<Status> {
        let mut result = SERVICE_STATUS_PROCESS::default();
        let mut bytes = 0;
        if unsafe {
            QueryServiceStatusEx(
                self.handle.0,
                SC_STATUS_PROCESS_INFO,
                (&mut result as *mut SERVICE_STATUS_PROCESS).cast(),
                size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut bytes,
            )
        } == 0
            || bytes != size_of::<SERVICE_STATUS_PROCESS>() as u32
            || result.dwServiceType != SERVICE_WIN32_OWN_PROCESS
        {
            return Err(native());
        }
        if !matches!(
            result.dwCurrentState,
            SERVICE_STOPPED | SERVICE_START_PENDING | SERVICE_RUNNING | SERVICE_STOP_PENDING
        ) {
            return Err(ServiceError::Conflict);
        }
        Ok(Status {
            state: result.dwCurrentState,
            pid: result.dwProcessId,
            exit_code: result.dwWin32ExitCode,
            checkpoint: result.dwCheckPoint,
        })
    }
    pub(super) fn enabled(&self) -> Result<bool> {
        Ok(configuration(&self.handle)?.start_type == SERVICE_AUTO_START)
    }
    pub(super) fn set_enabled(&self, enabled: bool) -> Result<()> {
        let _operation = self.effect.lock().map_err(unknown)?;
        self.validate(&self.immutable.binary, &self.immutable.sid)?;
        let target = if enabled {
            SERVICE_AUTO_START
        } else {
            SERVICE_DEMAND_START
        };
        if unsafe {
            ChangeServiceConfigW(
                self.handle.0,
                SERVICE_NO_CHANGE,
                target,
                SERVICE_NO_CHANGE,
                ptr::null(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
            )
        } == 0
        {
            return Err(ServiceError::Unknown);
        }
        self.validate(&self.immutable.binary, &self.immutable.sid)?;
        if configuration(&self.handle)?.start_type != target {
            return Err(ServiceError::Unknown);
        }
        Ok(())
    }
    pub(super) fn start(&self) -> Result<()> {
        let _operation = self.effect.lock().map_err(unknown)?;
        self.validate(&self.immutable.binary, &self.immutable.sid)?;
        if !self.status()?.stopped() {
            return Err(ServiceError::Conflict);
        }
        if unsafe { StartServiceW(self.handle.0, 0, ptr::null()) } == 0 {
            return Err(ServiceError::Unknown);
        }
        Ok(())
    }
    pub(super) fn stop(&self) -> Result<()> {
        let _operation = self.effect.lock().map_err(unknown)?;
        self.validate(&self.immutable.binary, &self.immutable.sid)?;
        let mut status = SERVICE_STATUS::default();
        if unsafe { ControlService(self.handle.0, SERVICE_CONTROL_STOP, &mut status) } == 0 {
            return Err(ServiceError::Unknown);
        }
        Ok(())
    }
    pub(super) fn delete(&self) -> Result<()> {
        let _operation = self.effect.lock().map_err(unknown)?;
        self.validate(&self.immutable.binary, &self.immutable.sid)?;
        if self.enabled()? || !self.status()?.stopped() {
            return Err(ServiceError::Conflict);
        }
        if unsafe { DeleteService(self.handle.0) } == 0 {
            return Err(ServiceError::Unknown);
        }
        Ok(())
    }
}
pub(super) struct Status {
    state: u32,
    pub(super) pid: u32,
    pub(super) exit_code: u32,
    pub(super) checkpoint: u32,
}
impl Status {
    pub(super) fn stopped(&self) -> bool {
        self.state == SERVICE_STOPPED
    }
    pub(super) fn active(&self) -> &'static str {
        match self.state {
            SERVICE_STOPPED => "inactive",
            SERVICE_START_PENDING => "activating",
            SERVICE_RUNNING => "active",
            SERVICE_STOP_PENDING => "deactivating",
            _ => "unknown",
        }
    }
}
fn birth(handle: &OwnedHandle) -> Result<u64> {
    let (mut c, mut e, mut k, mut u) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    if unsafe { GetProcessTimes(handle.as_raw_handle(), &mut c, &mut e, &mut k, &mut u) } == 0 {
        return Err(native());
    }
    Ok((u64::from(c.dwHighDateTime) << 32) | u64::from(c.dwLowDateTime))
}
fn image_path(handle: &OwnedHandle) -> Result<PathBuf> {
    let mut buffer = vec![0; 32768];
    let mut n = buffer.len() as u32;
    if unsafe { QueryFullProcessImageNameW(handle.as_raw_handle(), 0, buffer.as_mut_ptr(), &mut n) }
        == 0
        || n == 0
        || n as usize >= buffer.len()
    {
        return Err(native());
    }
    Ok(PathBuf::from(OsString::from_wide(&buffer[..n as usize])))
}
fn token_buffer(token: &OwnedHandle, class: TOKEN_INFORMATION_CLASS) -> Result<Buffer> {
    let mut required = 0;
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            class,
            ptr::null_mut(),
            0,
            &mut required,
        )
    } != 0
        || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER
    {
        return Err(native());
    }
    let mut raw = Buffer::new(required as usize)?;
    let capacity = required;
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            class,
            raw.pointer().cast(),
            capacity,
            &mut required,
        )
    } == 0
        || required > capacity
    {
        return Err(native());
    }
    Ok(raw)
}
#[derive(Clone, PartialEq, Eq)]
struct TokenFacts {
    sid: String,
    authentication: u64,
    token: u64,
    modified: u64,
}
fn luid(value: windows_sys::Win32::Foundation::LUID) -> u64 {
    ((value.HighPart as u32 as u64) << 32) | u64::from(value.LowPart)
}
fn token_facts(process: &OwnedHandle, expected_sid: &str) -> Result<TokenFacts> {
    let mut token = ptr::null_mut();
    if unsafe { OpenProcessToken(process.as_raw_handle(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(native());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let before = token_buffer(&token, TokenStatistics)?.value::<TOKEN_STATISTICS>()?;
    if before.TokenType != TokenPrimary
        || token_buffer(&token, TokenSessionId)?.value::<u32>()? != 0
    {
        return Err(ServiceError::Conflict);
    }
    let user = token_buffer(&token, TokenUser)?;
    let sid = user.sid(user.value::<TOKEN_USER>()?.User.Sid)?;
    if sid != expected_sid {
        return Err(ServiceError::Conflict);
    }
    let groups = token_buffer(&token, TokenGroups)?;
    let count = groups.value::<u32>()? as usize;
    let offset = offset_of!(TOKEN_GROUPS, Groups);
    if count > 4096
        || offset
            .checked_add(count * size_of::<SID_AND_ATTRIBUTES>())
            .is_none_or(|n| n > groups.length)
    {
        return Err(ServiceError::Conflict);
    }
    let mut service = false;
    for index in 0..count {
        let pointer = unsafe {
            groups
                .words
                .as_ptr()
                .cast::<u8>()
                .add(offset + index * size_of::<SID_AND_ATTRIBUTES>())
                .cast::<SID_AND_ATTRIBUTES>()
        };
        let value = unsafe { ptr::read_unaligned(pointer) };
        if groups.sid(value.Sid)? == "S-1-5-6"
            && value.Attributes & 4 != 0
            && value.Attributes & 16 == 0
        {
            service = true;
        }
    }
    if !service {
        return Err(ServiceError::Conflict);
    }
    let after = token_buffer(&token, TokenStatistics)?.value::<TOKEN_STATISTICS>()?;
    if before.TokenType != after.TokenType
        || luid(before.TokenId) != luid(after.TokenId)
        || luid(before.ModifiedId) != luid(after.ModifiedId)
        || luid(before.AuthenticationId) != luid(after.AuthenticationId)
    {
        return Err(ServiceError::Conflict);
    }
    Ok(TokenFacts {
        sid,
        authentication: luid(before.AuthenticationId),
        token: luid(before.TokenId),
        modified: luid(before.ModifiedId),
    })
}
/// Keeps original kernel process HANDLE plus birth/token/image. No PID-only wait,
/// adoption of a restarted service, force stop, or process-tree termination.
pub(super) struct OriginalProcess {
    handle: OwnedHandle,
    birth: ProcessIdentity,
    token: TokenFacts,
    image: PathBuf,
}
impl OriginalProcess {
    pub(super) fn capture(
        registration: &Registration,
        expected: &PinnedExecutable,
        sid: &str,
    ) -> Result<Self> {
        let before = registration.status()?;
        // PID is defined by SCM in RUNNING, not inferred from START/STOP_PENDING.
        if before.state != SERVICE_RUNNING || before.pid == 0 {
            return Err(ServiceError::Conflict);
        }
        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                0,
                before.pid,
            )
        };
        if handle.is_null() {
            return Err(native());
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
        let observed = ProcessIdentity::observe(before.pid).map_err(changed)?;
        let token = token_facts(&handle, sid)?;
        let image = image_path(&handle)?;
        let result = Self {
            handle,
            birth: observed,
            token,
            image,
        };
        result.validate(registration, expected, sid)?;
        let after = registration.status()?;
        if after.pid != before.pid || after.state != before.state {
            return Err(ServiceError::Conflict);
        }
        Ok(result)
    }
    pub(super) fn pid(&self) -> u32 {
        match self.birth {
            ProcessIdentity::Windows { pid, .. } => pid,
            _ => unreachable!("Windows process"),
        }
    }
    pub(super) fn exited(&self) -> Result<bool> {
        match unsafe { WaitForSingleObject(self.handle.as_raw_handle(), 0) } {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            _ => Err(ServiceError::Unknown),
        }
    }
    pub(super) fn exit_code(&self) -> Result<Option<u32>> {
        if !self.exited()? {
            return Ok(None);
        }
        let mut code = 0;
        if unsafe {
            windows_sys::Win32::System::Threading::GetExitCodeProcess(
                self.handle.as_raw_handle(),
                &mut code,
            )
        } == 0
        {
            return Err(ServiceError::Unknown);
        }
        Ok(Some(code))
    }
    pub(super) fn validate(
        &self,
        registration: &Registration,
        expected: &PinnedExecutable,
        sid: &str,
    ) -> Result<()> {
        if self.exited()? {
            return Err(ServiceError::Conflict);
        }
        let ProcessIdentity::Windows {
            creation_time_100ns,
            owner_sid,
            ..
        } = &self.birth
        else {
            return Err(ServiceError::Invalid);
        };
        if birth(&self.handle)? != *creation_time_100ns
            || owner_sid != sid
            || token_facts(&self.handle, sid)? != self.token
            || image_path(&self.handle)? != self.image
            || !self.birth.still_current().map_err(changed)?
        {
            return Err(ServiceError::Conflict);
        }
        expected.revalidate().map_err(changed)?;
        let actual = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(&self.image)
            .map_err(changed)?;
        let retained = expected.retained_file().map_err(changed)?;
        let stamp = |file: &File| -> Result<_> {
            let m = file.metadata().map_err(changed)?;
            if !m.is_file() {
                return Err(ServiceError::Conflict);
            }
            Ok((
                windows_file_identity(file).map_err(changed)?,
                m.file_size(),
                m.creation_time(),
                m.last_write_time(),
            ))
        };
        if stamp(&actual)? != stamp(retained)? {
            return Err(ServiceError::Conflict);
        }
        // Full original signed inventory (including this image) remains pinned
        // and checked by Definition; this is the independent running path ID.
        expected.revalidate().map_err(changed)?;
        let status = registration.status()?;
        if (status.state == SERVICE_RUNNING && status.pid != self.pid())
            || !matches!(status.state, SERVICE_RUNNING | SERVICE_STOP_PENDING)
            || self.exited()?
        {
            return Err(ServiceError::Conflict);
        }
        Ok(())
    }
}
