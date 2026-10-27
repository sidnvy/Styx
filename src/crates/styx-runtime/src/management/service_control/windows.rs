//! Windows transport for the original serviceControl domain protocol.
//! Fixed current-principal pipe, no authority from a name/PID/request/transaction.
//! Apply as service_control/windows.rs; shared schemas and C07 remain unchanged.
#![allow(unsafe_code)] // Official HANDLE/token/security descriptor APIs only.
use super::{
    FRAME, Handler, Response, Result, ServiceControlError, ServiceControlReport, ServiceRequest,
    checked_io, error, frame, validate_peer, validate_scope,
};
use crate::{
    platform::native_service::{ServicePeer, ServiceRole, ServiceScope},
    store::{PrivateRoot, ProcessIdentity, RootIdentity},
};
use std::{
    ffi::OsStr,
    mem::size_of,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::{Path, PathBuf},
    ptr,
    sync::Arc,
    time::Duration,
};
use styx_contracts::identity::Sha256Digest;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufReader},
    net::windows::named_pipe::{
        ClientOptions, NamedPipeClient, NamedPipeServer, PipeMode, ServerOptions,
    },
};
use tokio_util::sync::CancellationToken;
use windows_sys::Win32::{
    Foundation::{
        DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_TOKEN,
        ERROR_PIPE_BUSY, FILETIME, GetLastError, HANDLE, LocalFree, WAIT_TIMEOUT,
    },
    Security::{
        ACE_HEADER, ACL,
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            GetSecurityInfo, SDDL_REVISION_1, SE_KERNEL_OBJECT,
        },
        DACL_SECURITY_INFORMATION, GetAce, GetSecurityDescriptorControl,
        GetSecurityDescriptorLength, GetTokenInformation, IsValidAcl, IsValidSid,
        OWNER_SECURITY_INFORMATION, PSID, RevertToSelf, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES,
        SecurityIdentification, TOKEN_INFORMATION_CLASS, TOKEN_QUERY, TOKEN_STATISTICS, TOKEN_USER,
        TokenImpersonation, TokenImpersonationLevel, TokenPrimary, TokenSessionId, TokenStatistics,
        TokenUser,
    },
    Storage::FileSystem::SECURITY_IDENTIFICATION,
    System::{
        Pipes::{
            GetNamedPipeClientProcessId, GetNamedPipeInfo, GetNamedPipeServerProcessId,
            ImpersonateNamedPipeClient, PIPE_SERVER_END, PIPE_TYPE_MESSAGE,
        },
        Threading::{
            GetCurrentProcess, GetCurrentThread, GetProcessId, GetProcessTimes, OpenProcess,
            OpenProcessToken, OpenThreadToken, PROCESS_QUERY_LIMITED_INFORMATION,
            WaitForSingleObject,
        },
    },
};
const IO_BUDGET: Duration = Duration::from_secs(2);
const RESPONSE_BUDGET: Duration = Duration::from_secs(30);
const SYNCHRONIZE: u32 = 0x0010_0000;
// Explicit FILE_GENERIC_READ | FILE_GENERIC_WRITE; current SID is the only
// trustee. The original namespace is continuously held by at most two server instances.
const PIPE_ACCESS: u32 = 0x0012_019f;
fn wide(value: &str) -> Result<Vec<u16>> {
    let mut raw: Vec<_> = OsStr::new(value).encode_wide().collect();
    if raw.is_empty() || raw.len() > 32760 || raw.contains(&0) {
        return Err(error());
    }
    raw.push(0);
    Ok(raw)
}
fn current_sid() -> Result<String> {
    no_impersonation()?;
    match ProcessIdentity::current().map_err(|_| error())? {
        ProcessIdentity::Windows { owner_sid, .. } => Ok(owner_sid),
        _ => Err(error()),
    }
}
struct Endpoint {
    root: PrivateRoot,
    identity: RootIdentity,
    path: PathBuf,
    sid: String,
    name: String,
}
impl Endpoint {
    fn capture(path: &Path, sid: &str) -> Result<Self> {
        let root = PrivateRoot::open(path).map_err(|_| error())?;
        let identity = root.identity();
        let RootIdentity::Windows { owner_sid, .. } = &identity else {
            return Err(error());
        };
        if owner_sid != sid || current_sid()? != sid || !sid.starts_with("S-1-5-21-") {
            return Err(error());
        }
        let path_text = path.to_str().ok_or_else(error)?;
        let input =
            serde_json::to_vec(&("styx-service-control-pipe-v1", &identity, path_text, sid))
                .map_err(|_| error())?;
        let name = format!(
            r"\\.\pipe\Styx-ServiceControl-v1-{}",
            Sha256Digest::of_bytes(input).to_hex()
        );
        let result = Self {
            root,
            identity,
            path: path.into(),
            sid: sid.into(),
            name,
        };
        result.validate()?;
        Ok(result)
    }
    fn validate(&self) -> Result<()> {
        if current_sid()? != self.sid
            || self.root.identity() != self.identity
            || PrivateRoot::open(&self.path)
                .map_err(|_| error())?
                .identity()
                != self.identity
        {
            return Err(error());
        }
        self.root
            .read_raw(".styx-native-root-v1.json", 4096)
            .map_err(|_| error())?;
        Ok(())
    }
}
struct Local(*mut core::ffi::c_void);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
fn no_impersonation() -> Result<()> {
    let mut token = ptr::null_mut();
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } != 0 {
        let _held = unsafe { OwnedHandle::from_raw_handle(token) };
        return Err(error());
    }
    if unsafe { GetLastError() } != ERROR_NO_TOKEN {
        return Err(error());
    }
    Ok(())
}
fn duplicate(raw: HANDLE) -> Result<OwnedHandle> {
    let mut copy = ptr::null_mut();
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            raw,
            GetCurrentProcess(),
            &mut copy,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(error());
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(copy) })
}
fn sid_string(sid: PSID) -> Result<String> {
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err(error());
    }
    let mut text = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 || text.is_null() {
        return Err(error());
    }
    let _owned = Local(text.cast());
    let mut n = 0;
    while n < 192 && unsafe { *text.add(n) } != 0 {
        n += 1;
    }
    if n == 192 {
        return Err(error());
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(text, n) }).map_err(|_| error())
}
fn in_range(pointer: *const core::ffi::c_void, bytes: usize, start: usize, end: usize) -> bool {
    let pointer = pointer as usize;
    pointer >= start && pointer.checked_add(bytes).is_some_and(|limit| limit <= end)
}
fn bounded_sid(sid: PSID, start: usize, end: usize) -> Result<String> {
    if !in_range(sid, 8, start, end) {
        return Err(error());
    }
    let count = unsafe { *sid.cast::<u8>().add(1) } as usize;
    if count > 15 || !in_range(sid, 8 + count * 4, start, end) {
        return Err(error());
    }
    sid_string(sid)
}
fn pipe_security(pipe: &OwnedHandle, expected_sid: &str) -> Result<()> {
    let (mut owner, mut acl, mut descriptor) = (ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
    if unsafe {
        GetSecurityInfo(
            pipe.as_raw_handle(),
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut descriptor,
        )
    } != 0
        || descriptor.is_null()
    {
        return Err(error());
    }
    let _owned = Local(descriptor);
    let length = unsafe { GetSecurityDescriptorLength(descriptor) } as usize;
    if !(20..=65536).contains(&length) {
        return Err(error());
    }
    let start = descriptor as usize;
    let end = start.checked_add(length).ok_or_else(error)?;
    let (mut control, mut revision) = (0, 0);
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
        || control & SE_DACL_PROTECTED == 0
        || bounded_sid(owner, start, end)? != expected_sid
        || !in_range(acl.cast(), size_of::<ACL>(), start, end)
    {
        return Err(error());
    }
    let header = unsafe { ptr::read_unaligned(acl) };
    if !in_range(acl.cast(), usize::from(header.AclSize), start, end)
        || unsafe { IsValidAcl(acl) } == 0
        || header.AceCount != 1
    {
        return Err(error());
    }
    let mut ace = ptr::null_mut();
    if unsafe { GetAce(acl, 0, &mut ace) } == 0
        || !in_range(ace, size_of::<ACE_HEADER>(), start, end)
    {
        return Err(error());
    }
    let header = unsafe { ptr::read_unaligned(ace.cast::<ACE_HEADER>()) };
    let ace_start = ace as usize;
    let ace_end = ace_start
        .checked_add(usize::from(header.AceSize))
        .ok_or_else(error)?;
    let acl_start = acl as usize;
    let acl_end = acl_start + usize::from(unsafe { ptr::read_unaligned(acl) }.AclSize);
    if header.AceType != 0
        || header.AceFlags != 0
        || usize::from(header.AceSize) < 16
        || ace_start < acl_start
        || ace_end > acl_end
    {
        return Err(error());
    }
    let mask = unsafe { ptr::read_unaligned(ace.cast::<u8>().add(4).cast::<u32>()) };
    let sid = unsafe { ace.cast::<u8>().add(8).cast() };
    if mask != PIPE_ACCESS || bounded_sid(sid, ace_start + 8, ace_end)? != expected_sid {
        return Err(error());
    }
    Ok(())
}
fn pipe_kind(pipe: &OwnedHandle, server: bool) -> Result<()> {
    let (mut flags, mut output, mut input, mut instances) = (0, 0, 0, 0);
    if unsafe {
        GetNamedPipeInfo(
            pipe.as_raw_handle(),
            &mut flags,
            &mut output,
            &mut input,
            &mut instances,
        )
    } == 0
        || (flags & PIPE_SERVER_END != 0) != server
        || flags & PIPE_TYPE_MESSAGE != 0
        || instances != 2
    {
        return Err(error());
    }
    Ok(())
}
fn server_pid(pipe: &OwnedHandle) -> Result<u32> {
    let mut pid = 0;
    if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut pid) } == 0 || pid == 0 {
        return Err(error());
    }
    Ok(pid)
}
fn client_pid(pipe: &OwnedHandle) -> Result<u32> {
    let mut pid = 0;
    if unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle(), &mut pid) } == 0 || pid == 0 {
        return Err(error());
    }
    Ok(pid)
}
struct TokenBuffer {
    words: Vec<usize>,
    length: usize,
}
impl TokenBuffer {
    fn read(token: &OwnedHandle, class: TOKEN_INFORMATION_CLASS) -> Result<Self> {
        let mut length = 0;
        if unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                class,
                ptr::null_mut(),
                0,
                &mut length,
            )
        } != 0
            || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER
            || !(1..=65536).contains(&length)
        {
            return Err(error());
        }
        let capacity = length;
        let mut words = vec![0; (capacity as usize).div_ceil(size_of::<usize>())];
        if unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                class,
                words.as_mut_ptr().cast(),
                capacity,
                &mut length,
            )
        } == 0
            || length > capacity
        {
            return Err(error());
        }
        Ok(Self {
            words,
            length: length as usize,
        })
    }
    fn value<T: Copy>(&self) -> Result<T> {
        if self.length < size_of::<T>() {
            return Err(error());
        }
        Ok(unsafe { ptr::read_unaligned(self.words.as_ptr().cast::<T>()) })
    }
    fn sid(&self, sid: PSID) -> Result<String> {
        let start = self.words.as_ptr() as usize;
        bounded_sid(sid, start, start + self.length)
    }
}
#[derive(Clone, PartialEq, Eq)]
struct TokenFacts {
    sid: String,
    authentication_luid: u64,
    token_id: u64,
    modified_id: u64,
    session: u32,
}
fn luid(value: windows_sys::Win32::Foundation::LUID) -> u64 {
    ((value.HighPart as u32 as u64) << 32) | u64::from(value.LowPart)
}
fn token_facts(token: &OwnedHandle, primary: bool) -> Result<TokenFacts> {
    let before = TokenBuffer::read(token, TokenStatistics)?.value::<TOKEN_STATISTICS>()?;
    if before.TokenType
        != if primary {
            TokenPrimary
        } else {
            TokenImpersonation
        }
    {
        return Err(error());
    }
    if !primary
        && TokenBuffer::read(token, TokenImpersonationLevel)?.value::<i32>()?
            != SecurityIdentification
    {
        return Err(error());
    }
    let user = TokenBuffer::read(token, TokenUser)?;
    let sid = user.sid(user.value::<TOKEN_USER>()?.User.Sid)?;
    let session = TokenBuffer::read(token, TokenSessionId)?.value::<u32>()?;
    let after = TokenBuffer::read(token, TokenStatistics)?.value::<TOKEN_STATISTICS>()?;
    if before.TokenType != after.TokenType
        || luid(before.TokenId) != luid(after.TokenId)
        || luid(before.ModifiedId) != luid(after.ModifiedId)
        || luid(before.AuthenticationId) != luid(after.AuthenticationId)
    {
        return Err(error());
    }
    Ok(TokenFacts {
        sid,
        authentication_luid: luid(before.AuthenticationId),
        token_id: luid(before.TokenId),
        modified_id: luid(before.ModifiedId),
        session,
    })
}
fn primary_token(process: &OwnedHandle) -> Result<TokenFacts> {
    let mut token = ptr::null_mut();
    if unsafe { OpenProcessToken(process.as_raw_handle(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(error());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    token_facts(&token, true)
}
fn birth(process: &OwnedHandle) -> Result<u64> {
    let (mut c, mut e, mut k, mut u) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    if unsafe { GetProcessTimes(process.as_raw_handle(), &mut c, &mut e, &mut k, &mut u) } == 0 {
        return Err(error());
    }
    Ok((u64::from(c.dwHighDateTime) << 32) | u64::from(c.dwLowDateTime))
}
/// Retains the exact requesting process, not PID existence or an arbitrary peer.
struct ClientPeer {
    handle: OwnedHandle,
    identity: ProcessIdentity,
    token: TokenFacts,
}
impl ClientPeer {
    fn capture(pipe: &OwnedHandle, sid: &str) -> Result<Self> {
        no_impersonation()?;
        let pid = client_pid(pipe)?;
        let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, pid) };
        if raw.is_null() {
            return Err(error());
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        let identity = ProcessIdentity::observe(pid).map_err(|_| error())?;
        let token = primary_token(&handle)?;
        let result = Self {
            handle,
            identity,
            token,
        };
        result.validate(pipe, sid)?;
        Ok(result)
    }
    fn validate(&self, pipe: &OwnedHandle, sid: &str) -> Result<()> {
        no_impersonation()?;
        let ProcessIdentity::Windows {
            pid,
            creation_time_100ns,
            owner_sid,
        } = &self.identity
        else {
            return Err(error());
        };
        if owner_sid != sid
            || self.token.sid != sid
            || client_pid(pipe)? != *pid
            || unsafe { GetProcessId(self.handle.as_raw_handle()) } != *pid
            || unsafe { WaitForSingleObject(self.handle.as_raw_handle(), 0) } != WAIT_TIMEOUT
            || birth(&self.handle)? != *creation_time_100ns
            || primary_token(&self.handle)? != self.token
            || !self.identity.still_current().map_err(|_| error())?
        {
            return Err(error());
        }
        Ok(())
    }
    fn effective_pipe_identity(&self, pipe: &OwnedHandle, sid: &str) -> Result<()> {
        self.validate(pipe, sid)?;
        // Identification only, after framing read. No IO, file access or await
        // occurs under the temporary thread token. The original primary token
        // and pipe connection must describe the same actual logon principal.
        if unsafe { ImpersonateNamedPipeClient(pipe.as_raw_handle()) } == 0 {
            return Err(error());
        }
        let mut revert = Revert { active: true };
        let result = (|| {
            let mut token = ptr::null_mut();
            if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } == 0 {
                return Err(error());
            }
            let token = unsafe { OwnedHandle::from_raw_handle(token) };
            let effective = token_facts(&token, false)?;
            if effective.sid != sid
                || effective.authentication_luid != self.token.authentication_luid
                || effective.session != self.token.session
            {
                return Err(error());
            }
            Ok(())
        })();
        revert.finish();
        result?;
        self.validate(pipe, sid)
    }
}
struct Revert {
    active: bool,
}
impl Revert {
    fn finish(&mut self) {
        if self.active {
            if unsafe { RevertToSelf() } == 0 {
                // Never return an impersonated thread to Tokio's pool, continue
                // the handler, or drop its original permit/pipe/process custody.
                loop {
                    std::thread::park();
                }
            }
            self.active = false;
        }
    }
}
impl Drop for Revert {
    fn drop(&mut self) {
        self.finish();
    }
}
fn create(endpoint: &Endpoint, first: bool) -> Result<NamedPipeServer> {
    endpoint.validate()?;
    let descriptor_text = wide(&format!(
        "O:{}D:P(A;;0x{PIPE_ACCESS:08x};;;{})",
        endpoint.sid, endpoint.sid
    ))?;
    let mut descriptor = ptr::null_mut();
    let mut bytes = 0;
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            descriptor_text.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            &mut bytes,
        )
    } == 0
        || descriptor.is_null()
        || bytes > 65536
    {
        return Err(error());
    }
    let _descriptor = Local(descriptor);
    let mut attrs = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let mut options = ServerOptions::new();
    options
        .pipe_mode(PipeMode::Byte)
        .first_pipe_instance(first)
        .max_instances(2)
        .reject_remote_clients(true)
        .in_buffer_size(FRAME as u32)
        .out_buffer_size(FRAME as u32);
    let server = unsafe {
        options.create_with_security_attributes_raw(
            &endpoint.name,
            (&mut attrs as *mut SECURITY_ATTRIBUTES).cast(),
        )
    }
    .map_err(|_| {
        ServiceControlError::new("service_control_endpoint_exists_or_unavailable_no_adoption")
    })?;
    let held = duplicate(server.as_raw_handle())?;
    pipe_kind(&held, true)?;
    pipe_security(&held, &endpoint.sid)?;
    endpoint.validate()?;
    Ok(server)
}
pub(crate) struct ControlServer {
    server: NamedPipeServer,
    endpoint: Arc<Endpoint>,
    scope: Arc<ServiceScope>,
    handler: Handler,
}
impl ControlServer {
    pub(crate) async fn bind_owned(scope: Arc<ServiceScope>, handler: Handler) -> Result<Self> {
        let original = scope.clone();
        checked_io(move || {
            original.validate().map_err(|_| error())?;
            if original.role() != ServiceRole::Gateway {
                return Err(error());
            }
            let endpoint = Arc::new(Endpoint::capture(original.state_dir(), original.sid())?);
            let server = create(&endpoint, true)?;
            original.validate().map_err(|_| error())?;
            Ok(Self {
                server,
                endpoint,
                scope,
                handler,
            })
        })
        .await
    }
    /// One serial handler, with the next owned listener retained before the
    /// accepted instance closes. Mutation custody is awaited after disconnect
    /// or stop; only pre-dispatch IO is cancelable.
    pub(crate) async fn run(mut self, stop: CancellationToken) -> Result<()> {
        loop {
            tokio::select! { _ = stop.cancelled() => return Ok(()), result = self.server.connect() => result.map_err(|_| error())? }
            // Create the next instance while this original instance is still
            // held. There is never a namespace-absence/name-adoption window.
            // Fresh Tokio/Mio buffers prevent a previous connection's pending
            // read/completion from being interpreted as another client's frame.
            let endpoint = self.endpoint.clone();
            let next = checked_io(move || create(&endpoint, false)).await?;
            let mut accepted = std::mem::replace(&mut self.server, next);
            let connected = self.serve_one(&mut accepted, &stop).await;
            // Original domain custody, if dispatched, has already settled.
            // The next owned listener remains held during this disconnect/drop.
            accepted.disconnect().map_err(|_| error())?;
            drop(accepted);
            connected?;
            if stop.is_cancelled() {
                return Ok(());
            }
        }
    }
    async fn serve_one(
        &self,
        server: &mut NamedPipeServer,
        stop: &CancellationToken,
    ) -> Result<()> {
        let held = Arc::new(duplicate(server.as_raw_handle())?);
        let endpoint = self.endpoint.clone();
        let pipe = held.clone();
        checked_io(move || {
            endpoint.validate()?;
            pipe_kind(&pipe, true)?;
            pipe_security(&pipe, &endpoint.sid)
        })
        .await?;
        validate_scope(self.scope.clone()).await?;
        let endpoint = self.endpoint.clone();
        let pipe = held.clone();
        let client = match checked_io(move || ClientPeer::capture(&pipe, &endpoint.sid)).await {
            Ok(client) => Arc::new(client),
            Err(_) => return Ok(()),
        };
        let (read, mut write) = tokio::io::split(server);
        let mut read = BufReader::new(read);
        let bytes = tokio::select! { _ = stop.cancelled() => return Ok(()), result = tokio::time::timeout(IO_BUDGET, frame(&mut read)) => match result { Ok(Ok(bytes)) => bytes, _ => return Ok(()) } };
        let request: ServiceRequest = match serde_json::from_slice(&bytes) {
            Ok(request) => request,
            Err(_) => return Ok(()),
        };
        if !request.valid() {
            return Ok(());
        }
        let endpoint = self.endpoint.clone();
        let pipe = held.clone();
        let requester = client.clone();
        if checked_io(move || {
            endpoint.validate()?;
            pipe_security(&pipe, &endpoint.sid)?;
            requester.effective_pipe_identity(&pipe, &endpoint.sid)
        })
        .await
        .is_err()
        {
            return Ok(());
        }
        validate_scope(self.scope.clone()).await?;
        if stop.is_cancelled() {
            return Ok(());
        }
        // No timeout/select/disconnect branch around this original owner job.
        let result = (self.handler)(request).await;
        let response = match result {
            Ok(report) => Response {
                schema: 1,
                ok: true,
                report: Some(report),
                error: None,
            },
            Err(failure) => Response {
                schema: 1,
                ok: false,
                report: None,
                error: Some(failure.code().into()),
            },
        };
        let mut bytes = serde_json::to_vec(&response).map_err(|_| error())?;
        bytes.push(b'\n');
        if bytes.len() > FRAME {
            return Err(error());
        }
        // DisconnectNamedPipe discards unread buffered reply bytes. Keep the
        // same 2s response IO budget while passively awaiting client close after
        // its one response frame; no protocol ACK or second mutation is added.
        let _ = tokio::time::timeout(IO_BUDGET, async {
            write.write_all(&bytes).await?;
            let mut extra = [0u8; 1];
            let _ = read.read(&mut extra).await;
            Ok::<(), std::io::Error>(())
        })
        .await;
        drop(client);
        Ok(())
    }
}
async fn open(endpoint: &Endpoint) -> Result<NamedPipeClient> {
    let deadline = tokio::time::Instant::now() + IO_BUDGET;
    loop {
        let mut options = ClientOptions::new();
        options
            .pipe_mode(PipeMode::Byte)
            .security_qos_flags(SECURITY_IDENTIFICATION);
        match options.open(&endpoint.name) {
            Ok(client) => return Ok(client),
            Err(failure)
                if failure.raw_os_error() == Some(ERROR_PIPE_BUSY as i32)
                    && tokio::time::Instant::now() < deadline =>
            {
                // No request has been written: this retries only a known-busy
                // connection open, never an original business operation.
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(_) => return Err(error()),
        }
    }
}
pub(super) async fn exchange(path: &Path, request: ServiceRequest) -> Result<ServiceControlReport> {
    let peer = ServicePeer::observe(path, ServiceRole::Gateway)
        .await
        .map_err(|_| error())?;
    validate_peer(peer.clone()).await?;
    let original = peer.clone();
    let path = path.to_owned();
    let endpoint = Arc::new(checked_io(move || Endpoint::capture(&path, original.sid())).await?);
    let stream = open(&endpoint).await?;
    let held = Arc::new(duplicate(stream.as_raw_handle())?);
    let pipe = held.clone();
    let endpoint_before = endpoint.clone();
    let expected_pid = peer.pid();
    checked_io(move || {
        endpoint_before.validate()?;
        pipe_kind(&pipe, false)?;
        pipe_security(&pipe, &endpoint_before.sid)?;
        if server_pid(&pipe)? != expected_pid {
            return Err(error());
        }
        Ok(())
    })
    .await?;
    validate_peer(peer.clone()).await?;
    let pipe = held.clone();
    let expected_pid = peer.pid();
    checked_io(move || {
        if server_pid(&pipe)? == expected_pid {
            Ok(())
        } else {
            Err(error())
        }
    })
    .await?;
    let stopping = matches!(&request, ServiceRequest::SetStopped { .. });
    let id = request.transaction_id().clone();
    let mut bytes = serde_json::to_vec(&request).map_err(|_| error())?;
    bytes.push(b'\n');
    if bytes.len() > FRAME {
        return Err(error());
    }
    let (read, mut write) = tokio::io::split(stream);
    // Write deadline loss, including a partial write, is Unknown. Never reopen
    // or retransmit; server's one accepted handler retains the original job.
    tokio::time::timeout(IO_BUDGET, write.write_all(&bytes))
        .await
        .map_err(|_| error())?
        .map_err(|_| error())?;
    let mut read = BufReader::new(read);
    let bytes = tokio::time::timeout(RESPONSE_BUDGET, frame(&mut read))
        .await
        .map_err(|_| error())??;
    let response: Response = serde_json::from_slice(&bytes).map_err(|_| error())?;
    // A same-original-HANDLE Stop reply remains a C07 receipt after that exact
    // service exits; the caller separately proves physical completion.
    if !stopping {
        validate_peer(peer.clone()).await?;
    }
    if response.schema != 1 || !response.ok {
        return Err(error());
    }
    let report = response.report.ok_or_else(error)?;
    if report.schema != 1 || report.transaction_id != id {
        return Err(error());
    }
    Ok(report)
}
