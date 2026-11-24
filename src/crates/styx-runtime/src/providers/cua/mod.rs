//! Linux owned Cua stdio adapter. Core is the only operation/session authority.
//! Shared Linux scope owns the exact native worker tree; absence of its
//! original cgroup/InvocationID proof remains Unknown, never a close ACK fact.
#[cfg(target_os = "linux")]
use crate::providers::linux_scope::{LinuxOwnedScope, ScopeCommand, ScopeError};
#[cfg(any(target_os = "linux", target_os = "windows"))]
use crate::store::PinnedExecutable;
use crate::store::ProcessIdentity;
use rmcp::{
    ClientHandler, RoleClient, ServiceExt,
    model::{CallToolRequestParams, CallToolResponse, CallToolResult},
    service::RunningService,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use styx_contracts::{
    capability::CapabilityId,
    identity::Sha256Digest,
    operation::{OperationId, ResourceTarget},
    session::SessionBinding,
};
use styx_core::operations::{DispatchPermit, OperationPurpose, OwnerLease, ResourceDomain};
#[cfg(target_os = "macos")]
mod macos;
#[cfg(any(target_os = "macos", test))]
mod macos_cleanup;
#[cfg(target_os = "macos")]
pub(crate) mod macos_source;
#[cfg(any(target_os = "macos", test))]
mod macos_source_hint;
#[cfg(target_os = "macos")]
pub(crate) mod probe_diagnostic;
#[cfg(target_os = "macos")]
pub(crate) use macos::{MacProxySource, TrustedCuaLaunch};
#[cfg(test)]
mod deadline_tests;
mod driver_result;
#[cfg(test)]
pub(crate) mod fake_driver;
mod retention;
mod transport;
#[cfg(target_os = "windows")]
use crate::platform::windows_spawn::RunningChild as Child;
#[cfg(target_os = "linux")]
use tokio::process::Child;
use tokio::{
    sync::OwnedMutexGuard,
    task::JoinHandle,
    time::{Instant, timeout_at},
};
use tokio_util::sync::CancellationToken;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
mod windows_config;
const FRAME_BYTES: usize = styx_contracts::DESKTOP_BROWSER_FRAME_BYTES;
const REQUEST_BYTES: usize = 256 * 1024;
type Result<T> = std::result::Result<T, CuaError>;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum CuaError {
    #[error("cua_busy")]
    Busy,
    #[error("cua_invalid_request")]
    InvalidRequest,
    #[error("cua_permission_denied")]
    PermissionDenied,
    #[error("cua_stale_observation")]
    StaleObservation,
    #[error("cua_unsupported")]
    Unsupported,
    #[error("cua_protocol_mismatch")]
    ProtocolMismatch,
    #[error("cua_outcome_unknown")]
    Unknown,
    #[error("cua_cleanup_unconfirmed")]
    CleanupUnconfirmed,
}
#[cfg(target_os = "linux")]
impl From<ScopeError> for CuaError {
    fn from(value: ScopeError) -> Self {
        match value {
            ScopeError::InvalidRequest => Self::InvalidRequest,
            ScopeError::PermissionDenied => Self::PermissionDenied,
            ScopeError::Unsupported => Self::Unsupported,
            ScopeError::Unknown => Self::Unknown,
            ScopeError::CleanupUnconfirmed => Self::CleanupUnconfirmed,
        }
    }
}
impl CuaError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Busy => "cua_busy",
            Self::InvalidRequest => "cua_invalid_request",
            Self::PermissionDenied => "cua_permission_denied",
            Self::StaleObservation => "cua_stale_observation",
            Self::Unsupported => "cua_unsupported",
            Self::ProtocolMismatch => "cua_protocol_mismatch",
            Self::Unknown => "cua_outcome_unknown",
            Self::CleanupUnconfirmed => "cua_cleanup_unconfirmed",
        }
    }
}
/// Runtime association/Host bootstrap only. Not Deserialize, not a grant. The
/// associated live Session must still pass Core admission for EVERY operation.
#[cfg(target_os = "linux")]
#[derive(Clone)]
pub(crate) struct TrustedCuaLaunch {
    pub(crate) session: SessionBinding,
    pub(crate) uid: u32,
    pub(crate) runtime_dir: PathBuf,
    pub(crate) wayland_display: String,
    pub(crate) hyprland_instance: String,
    pub(crate) compositor_peer: (u32, u64),
    pub(crate) session_bus: PathBuf,
}
#[cfg(target_os = "windows")]
#[derive(Clone)]
pub(crate) struct TrustedCuaLaunch {
    pub(crate) session: SessionBinding,
    pub(crate) source: crate::platform::windows_desktop::DesktopSource,
}
#[derive(Clone)]
pub(crate) struct OwnedCuaConfig {
    // Caller has already checked this image against the original signed manifest.
    // Store's pin by itself is not a publisher signature authority.
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    pub(crate) driver: Arc<PinnedExecutable>,
    pub(crate) launch: TrustedCuaLaunch,
    pub(crate) workspace: PathBuf,
    pub(crate) home: PathBuf,
    #[cfg(target_os = "windows")]
    pub(crate) environment: BTreeMap<String, String>,
}
impl OwnedCuaConfig {
    #[cfg(target_os = "linux")]
    fn validate(&self) -> Result<()> {
        if self.launch.uid != nix::unistd::Uid::current().as_raw()
            || self.launch.compositor_peer.0 == 0
            || self.launch.compositor_peer.1 == 0
        {
            return Err(CuaError::PermissionDenied);
        }
        for path in [
            &self.launch.runtime_dir,
            &self.launch.session_bus,
            &self.workspace,
            &self.home,
        ] {
            if !path.is_absolute() || path.as_os_str().len() > 4096 {
                return Err(CuaError::InvalidRequest);
            }
        }
        let runtime = PathBuf::from(format!("/run/user/{}", self.launch.uid));
        if self.launch.runtime_dir != runtime || self.launch.session_bus != runtime.join("bus") {
            return Err(CuaError::PermissionDenied);
        }
        let Some(display) = self.launch.wayland_display.strip_prefix("wayland-") else {
            return Err(CuaError::InvalidRequest);
        };
        if display.is_empty() || display.len() > 16 || !display.bytes().all(|v| v.is_ascii_digit())
        {
            return Err(CuaError::InvalidRequest);
        }
        if self.launch.hyprland_instance.is_empty()
            || self.launch.hyprland_instance.len() > 256
            || self.launch.hyprland_instance.contains(['\0', '\n', '\r'])
        {
            return Err(CuaError::InvalidRequest);
        }
        self.driver
            .revalidate()
            .map_err(|_| CuaError::PermissionDenied)
    }
    #[cfg(target_os = "linux")]
    fn digest(&self) -> Result<Sha256Digest> {
        self.validate()?;
        bounded_bytes(&serde_json::json!({"session":self.launch.session,"uid":self.launch.uid,"runtime":self.launch.runtime_dir,"wayland":self.launch.wayland_display,"hyprland":self.launch.hyprland_instance,"compositor_peer":self.launch.compositor_peer,"bus":self.launch.session_bus,"image":self.driver.launch_path().map_err(|_|CuaError::PermissionDenied)?,"workspace":self.workspace,"home":self.home}),REQUEST_BYTES).map(|v|Sha256Digest::of_bytes(&v))
    }
    #[cfg(target_os = "macos")]
    fn validate(&self) -> Result<()> {
        macos::validate_config(self)
    }
    #[cfg(target_os = "macos")]
    fn digest(&self) -> Result<Sha256Digest> {
        macos::config_digest(self)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CuaOpenSpec {
    config_digest: Sha256Digest,
}
impl CuaOpenSpec {
    pub(crate) fn for_config(config: &OwnedCuaConfig) -> Result<Self> {
        Ok(Self {
            config_digest: config.digest()?,
        })
    }
    pub fn to_operation_payload(&self) -> Result<Vec<u8>> {
        bounded_bytes(self, REQUEST_BYTES)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CuaAction {
    ListTools {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        names: Option<Vec<String>>,
    },
    CallTool {
        name: String,
        #[serde(default)]
        arguments: Map<String, Value>,
    },
}
impl CuaAction {
    pub fn list_tools(names: Option<Vec<String>>) -> Result<Self> {
        let value = Self::ListTools { names };
        value.validate()?;
        Ok(value)
    }
    pub fn call_tool(name: String, arguments: Map<String, Value>) -> Result<Self> {
        let value = Self::CallTool { name, arguments };
        value.validate()?;
        Ok(value)
    }
    pub fn to_operation_payload(&self) -> Result<Vec<u8>> {
        self.validate()?;
        bounded_bytes(self, REQUEST_BYTES)
    }
    fn validate(&self) -> Result<()> {
        bounded_bytes(self, REQUEST_BYTES)?;
        match self {
            Self::ListTools { names } => {
                if let Some(names) = names
                    && (names.len() > 256
                        || names.iter().any(|name| {
                            name.is_empty()
                                || name.len() > 128
                                || name.chars().any(char::is_control)
                        }))
                {
                    return Err(CuaError::InvalidRequest);
                }
            }
            Self::CallTool { name, .. } => {
                if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
                    return Err(CuaError::InvalidRequest);
                }
            }
        }
        Ok(())
    }
    pub fn capability(&self) -> Result<CapabilityId> {
        self.validate()?;
        Ok(CapabilityId::DesktopWindowsRead)
    }
}
fn bounded_bytes(value: &impl Serialize, limit: usize) -> Result<Vec<u8>> {
    struct Bound {
        bytes: Vec<u8>,
        limit: usize,
    }
    impl std::io::Write for Bound {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            if self
                .bytes
                .len()
                .checked_add(b.len())
                .is_none_or(|n| n > self.limit)
            {
                return Err(std::io::Error::other("bounded Cua JSON"));
            }
            self.bytes.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut out = Bound {
        bytes: Vec::new(),
        limit,
    };
    serde_json::to_writer(&mut out, value).map_err(|_| CuaError::InvalidRequest)?;
    Ok(out.bytes)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CuaEvidence {
    Acknowledged,
    NotDispatched,
    Unknown,
}
#[derive(Debug)]
pub struct CuaReceipt {
    pub operation: OperationId,
    pub evidence: CuaEvidence,
    pub result: Option<CallToolResult>,
    pub cause: Option<CuaError>,
}
#[derive(Clone, Copy, Debug)]
pub enum CuaNativeSettlement {
    /// No native invocation could begin; actual proxy wait remains separate.
    NotStarted,
    WindowsJob {
        confirmed: bool,
    },
    LinuxScope {
        confirmed: bool,
    },
    /// Receipt from the original authenticated daemon control transport.
    MacAppTransport {
        drained: bool,
    },
    /// The originally authenticated daemon birth is definitively gone. This
    /// proves physical termination, not end_session ACK or any action outcome.
    MacOriginalDaemonExited,
}
#[derive(Clone, Copy, Debug)]
pub struct CuaCleanup {
    pub worker_exited: bool,
    pub worker_exit_success: Option<bool>,
    pub io_joined: bool,
    pub descendants_confirmed: bool,
    pub native_settlement: CuaNativeSettlement,
}
impl CuaCleanup {
    pub fn physical_settlement_confirmed(&self) -> bool {
        matches!(
            self.native_settlement,
            CuaNativeSettlement::NotStarted
                | CuaNativeSettlement::LinuxScope { confirmed: true }
                | CuaNativeSettlement::WindowsJob { confirmed: true }
                | CuaNativeSettlement::MacAppTransport { drained: true }
                | CuaNativeSettlement::MacOriginalDaemonExited
        )
    }
    pub fn complete(&self) -> bool {
        self.worker_exited && self.io_joined && self.physical_settlement_confirmed()
    }
}
#[derive(Clone)]
pub struct CuaWorker {
    inner: Arc<Inner>,
}
#[cfg(target_os = "linux")]
struct SharedLinuxDaemon {
    scope: LinuxOwnedScope,
    child: Child,
    socket: PathBuf,
    stderr: Option<JoinHandle<std::io::Result<u64>>>,
}
struct Inner {
    resources: Mutex<BTreeMap<OperationId, Arc<Resource>>>,
    stop: CancellationToken,
    #[cfg(target_os = "linux")]
    shared_daemon: tokio::sync::Mutex<Option<SharedLinuxDaemon>>,
    #[cfg(target_os = "windows")]
    shared_daemon: tokio::sync::Mutex<Option<windows::SharedWindowsDaemon>>,
}
struct Resource {
    owner: OwnerLease,
    target: ResourceTarget,
    session: SessionBinding,
    stop: CancellationToken,
    // Stop business admission before draining the original Mac session. This
    // independent token fences only its IO; it must not be a child of stop.
    #[cfg(target_os = "macos")]
    transport_stop: CancellationToken,
    live: Arc<tokio::sync::Mutex<Live>>,
    cleanup_job: Mutex<Option<tokio::sync::watch::Receiver<Option<CuaCleanup>>>>,
}
struct Live {
    #[cfg(target_os = "linux")]
    scope: Option<LinuxOwnedScope>,
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    scope_confirmed: bool,
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    child: Option<Child>,
    #[cfg(target_os = "macos")]
    mac_proxy: Option<macos::ProxyWorker>,
    #[cfg(target_os = "macos")]
    mac_probe: Option<JoinHandle<Result<()>>>,
    identity: Option<ProcessIdentity>,
    client: Option<RunningService<RoleClient, CuaClient>>,
    close_job: Option<JoinHandle<bool>>,
    stderr: Option<JoinHandle<std::io::Result<u64>>>,
    config: Arc<OwnedCuaConfig>,
    retired: bool,
    cleanup: Option<CuaCleanup>,
    uncertain: bool,
    io_failed: bool,
    exit_success: Option<bool>,
    actions: BTreeMap<OperationId, (Sha256Digest, CuaEvidence, Option<CuaError>, CapabilityId)>,
}
impl Live {
    fn was_started(&self) -> bool {
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        {
            self.child.is_some() || self.identity.is_some()
        }
        #[cfg(target_os = "macos")]
        {
            self.mac_proxy
                .as_ref()
                .is_some_and(macos::ProxyWorker::was_started)
        }
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}
struct CuaClient {}
impl ClientHandler for CuaClient {}
#[derive(Clone)]
pub struct CuaHandle {
    resource: Arc<Resource>,
    worker: Arc<Inner>,
}
impl CuaHandle {
    pub fn target(&self) -> &ResourceTarget {
        &self.resource.target
    }
    pub fn session(&self) -> &SessionBinding {
        &self.resource.session
    }
    pub fn owner(&self) -> &OwnerLease {
        &self.resource.owner
    }
    /// Original owned systemd-run wrapper, not desktop identity or authority.
    pub async fn worker_identity(&self) -> Option<ProcessIdentity> {
        self.resource.live.lock().await.identity.clone()
    }
}
pub struct CuaOpenSlot {
    worker: CuaWorker,
}
pub struct CuaActionSlot {
    resource: Arc<Resource>,
    live: OwnedMutexGuard<Live>,
}
pub struct CuaOpenReceipt {
    pub handle: CuaHandle,
    pub evidence: CuaEvidence,
}
pub struct CuaOpenFailure {
    pub operation: OperationId,
    pub handle: Option<CuaHandle>,
    pub evidence: CuaEvidence,
    pub cause: CuaError,
}
impl Default for CuaWorker {
    fn default() -> Self {
        Self::new()
    }
}
impl CuaWorker {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                resources: Mutex::new(BTreeMap::new()),
                stop: CancellationToken::new(),
                #[cfg(any(target_os = "linux", target_os = "windows"))]
                shared_daemon: tokio::sync::Mutex::new(None),
            }),
        }
    }
    #[cfg(target_os = "linux")]
    async fn ensure_linux_daemon(
        &self,
        config: &OwnedCuaConfig,
        until: Option<Instant>,
    ) -> Result<PathBuf> {
        let mut guard = self.inner.shared_daemon.lock().await;
        if let Some(daemon) = guard.as_mut() {
            let alive = daemon.child.try_wait().ok().flatten().is_none();
            if alive
                && tokio::net::UnixStream::connect(&daemon.socket)
                    .await
                    .is_ok()
            {
                return Ok(daemon.socket.clone());
            }
            if let Some(mut dead) = guard.take() {
                let _ = dead
                    .scope
                    .stop_and_confirm(&mut dead.child, Duration::from_secs(2))
                    .await;
                if let Some(stderr) = dead.stderr.take() {
                    let _ = tokio::time::timeout(Duration::from_secs(1), stderr).await;
                }
            }
        }
        let path = config
            .driver
            .launch_path()
            .map_err(|_| CuaError::PermissionDenied)?;
        let launch = ScopeCommand::cua_serve(
            path,
            config.workspace.clone(),
            config.home.clone(),
            config.launch.wayland_display.clone(),
            config.launch.hyprland_instance.clone(),
            config.launch.compositor_peer,
            until,
        )
        .await
        .map_err(CuaError::from)?;
        let (mut cmd, mut scope) = LinuxOwnedScope::command(launch).map_err(CuaError::from)?;
        let socket = scope.cua_socket_path();
        let mut child = cmd.spawn().map_err(|_| CuaError::Unknown)?;
        let stderr = child.stderr.take().map(|mut stderr| {
            tokio::spawn(async move { tokio::io::copy(&mut stderr, &mut tokio::io::sink()).await })
        });
        if let Err(err) = scope.attest_started(until).await {
            let _ = scope
                .stop_and_confirm(&mut child, Duration::from_secs(2))
                .await;
            return Err(CuaError::from(err));
        }
        let ready_deadline = until.unwrap_or_else(|| Instant::now() + Duration::from_secs(10));
        loop {
            if self.inner.stop.is_cancelled() {
                let _ = scope
                    .stop_and_confirm(&mut child, Duration::from_secs(2))
                    .await;
                return Err(CuaError::Unknown);
            }
            if tokio::net::UnixStream::connect(&socket).await.is_ok() {
                break;
            }
            if child.try_wait().ok().flatten().is_some() || Instant::now() >= ready_deadline {
                let _ = scope
                    .stop_and_confirm(&mut child, Duration::from_secs(2))
                    .await;
                return Err(CuaError::Unknown);
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        *guard = Some(SharedLinuxDaemon {
            scope,
            child,
            socket: socket.clone(),
            stderr,
        });
        Ok(socket)
    }
    pub(crate) async fn stop_shared_daemon(&self, budget: Duration) {
        #[cfg(target_os = "linux")]
        {
            let mut guard = self.inner.shared_daemon.lock().await;
            if let Some(mut daemon) = guard.take() {
                let _ = daemon
                    .scope
                    .stop_and_confirm(&mut daemon.child, budget)
                    .await;
                if let Some(stderr) = daemon.stderr.take() {
                    let _ = tokio::time::timeout(Duration::from_secs(1), stderr).await;
                }
            }
        }
        #[cfg(target_os = "windows")]
        {
            windows::stop_daemon(&self.inner.shared_daemon, budget).await;
        }
        #[cfg(target_os = "macos")]
        {
            let _ = budget;
        }
    }
    pub fn try_reserve_open(&self) -> Result<CuaOpenSlot> {
        Ok(CuaOpenSlot {
            worker: self.clone(),
        })
    }
    pub fn try_reserve_action(&self, handle: &CuaHandle) -> Result<CuaActionSlot> {
        if !Arc::ptr_eq(&self.inner, &handle.worker) {
            return Err(CuaError::PermissionDenied);
        }
        if handle.resource.stop.is_cancelled() {
            return Err(CuaError::Unknown);
        }
        let live = handle
            .resource
            .live
            .clone()
            .try_lock_owned()
            .map_err(|_| CuaError::Busy)?;
        if live.uncertain || live.retired {
            return Err(CuaError::Unknown);
        }
        Ok(CuaActionSlot {
            resource: handle.resource.clone(),
            live,
        })
    }
    pub fn resources(&self) -> Result<Vec<CuaHandle>> {
        let resources = self.inner.resources.lock().map_err(|_| CuaError::Unknown)?;
        Ok(resources
            .values()
            .map(|r| CuaHandle {
                resource: r.clone(),
                worker: self.inner.clone(),
            })
            .collect())
    }
    pub async fn cleanup_owned(&self, handle: &CuaHandle, budget: Duration) -> Result<CuaCleanup> {
        if !Arc::ptr_eq(&self.inner, &handle.worker) {
            return Err(CuaError::PermissionDenied);
        }
        let resource = handle.resource.clone();
        resource.stop.cancel();
        let until = Instant::now() + budget.min(Duration::from_secs(30));
        let mut receiver = resource
            .cleanup_job
            .lock()
            .map_err(|_| CuaError::Unknown)?
            .as_ref()
            .cloned()
            .ok_or(CuaError::CleanupUnconfirmed)?;
        loop {
            if let Some(value) = *receiver.borrow_and_update() {
                return Ok(value);
            }
            timeout_at(until, receiver.changed())
                .await
                .map_err(|_| CuaError::CleanupUnconfirmed)?
                .map_err(|_| CuaError::CleanupUnconfirmed)?;
        }
    }
}
fn permit_binding(
    permit: &DispatchPermit,
    owner: &OwnerLease,
    target: &ResourceTarget,
    session: &SessionBinding,
    capability: CapabilityId,
) -> Result<()> {
    if permit.resource_domain() != ResourceDomain::DesktopAgent
        || permit.owner() != owner
        || permit.target() != Some(target)
        || permit.context().session.as_ref() != Some(session)
        || permit.context().capability != capability
    {
        return Err(CuaError::PermissionDenied);
    }
    Ok(())
}
impl CuaOpenSlot {
    pub(crate) async fn spawn_owned(
        self,
        permit: DispatchPermit,
        config: OwnedCuaConfig,
        until: Option<Instant>,
    ) -> std::result::Result<CuaOpenReceipt, CuaOpenFailure> {
        let operation = permit.id().clone();
        let worker = self.worker.clone();
        let lost = operation.clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let _ = tx.send(self.open_inner(permit, config, until).await);
        });
        rx.await.unwrap_or_else(|_| {
            Err(CuaOpenFailure {
                operation: lost.clone(),
                handle: worker
                    .inner
                    .resources
                    .lock()
                    .ok()
                    .and_then(|m| m.get(&lost).cloned())
                    .map(|resource| CuaHandle {
                        resource,
                        worker: worker.inner.clone(),
                    }),
                evidence: CuaEvidence::Unknown,
                cause: CuaError::Unknown,
            })
        })
    }
    async fn open_inner(
        self,
        permit: DispatchPermit,
        config: OwnedCuaConfig,
        until: Option<Instant>,
    ) -> std::result::Result<CuaOpenReceipt, CuaOpenFailure> {
        let operation = permit.id().clone();
        let validation = (|| {
            config.validate()?;
            if permit.purpose() != OperationPurpose::Execute
                || permit.resource_domain() != ResourceDomain::DesktopAgent
                || permit.target().is_some()
                || permit.context().capability != CapabilityId::DesktopWindowsRead
                || permit.context().session.as_ref() != Some(&config.launch.session)
                || permit.context().observation.is_some()
            {
                return Err(CuaError::PermissionDenied);
            }
            let spec: CuaOpenSpec =
                serde_json::from_slice(permit.payload()).map_err(|_| CuaError::InvalidRequest)?;
            if spec.config_digest != config.digest()? {
                return Err(CuaError::PermissionDenied);
            }
            Ok(())
        })();
        if let Err(cause) = validation {
            return Err(CuaOpenFailure {
                operation,
                handle: None,
                evidence: CuaEvidence::NotDispatched,
                cause,
            });
        }
        let target = ResourceTarget {
            operation_id: operation.clone(),
            payload_digest: Sha256Digest::of_bytes(permit.payload()),
        };
        let config = Arc::new(config);
        let (cleanup_tx, cleanup_rx) = tokio::sync::watch::channel(None);
        #[cfg(target_os = "macos")]
        let (stop, transport_stop) = macos_cleanup::resource_stop_tokens();
        #[cfg(not(target_os = "macos"))]
        let stop = CancellationToken::new();
        let resource = Arc::new(Resource {
            owner: permit.owner().clone(),
            target,
            session: config.launch.session.clone(),
            stop,
            live: Arc::new(tokio::sync::Mutex::new(Live {
                #[cfg(target_os = "linux")]
                scope: None,
                #[cfg(any(target_os = "linux", target_os = "windows"))]
                scope_confirmed: false,
                #[cfg(any(target_os = "linux", target_os = "windows"))]
                child: None,
                #[cfg(target_os = "macos")]
                mac_proxy: None,
                #[cfg(target_os = "macos")]
                mac_probe: None,
                identity: None,
                client: None,
                close_job: None,
                stderr: None,
                config: config.clone(),
                retired: false,
                cleanup: None,
                uncertain: false,
                io_failed: false,
                exit_success: None,
                actions: BTreeMap::new(),
            })),
            cleanup_job: Mutex::new(Some(cleanup_rx)),
            #[cfg(target_os = "macos")]
            transport_stop,
        });
        self.worker
            .inner
            .resources
            .lock()
            .map_err(|_| CuaOpenFailure {
                operation: operation.clone(),
                handle: None,
                evidence: CuaEvidence::NotDispatched,
                cause: CuaError::Unknown,
            })?
            .insert(operation.clone(), resource.clone());
        // Keep the original process and image pin alive independently of public
        // waiters and even the last Worker/Handle dropping. No detached child owner.
        let owned = resource.clone();
        let host_stop = self.worker.inner.stop.clone();
        #[cfg(target_os = "windows")]
        let source = config.launch.source.clone();
        tokio::spawn(async move {
            #[cfg(target_os = "linux")]
            tokio::select! {_=host_stop.cancelled()=>{},_=owned.stop.cancelled()=>{}}
            #[cfg(target_os = "macos")]
            macos_cleanup::wait_cleanup_request(&host_stop, &owned.stop, &owned.transport_stop)
                .await;
            #[cfg(target_os = "windows")]
            tokio::select! {_=host_stop.cancelled()=>{},_=owned.stop.cancelled()=>{},_=source.invalidated()=>{}}
            owned.stop.cancel();
            loop {
                let facts = cleanup(&mut *owned.live.lock().await, Duration::from_secs(2)).await;
                let _ = cleanup_tx.send(Some(facts));
                if facts.complete() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });
        let handle = CuaHandle {
            resource: resource.clone(),
            worker: self.worker.inner.clone(),
        };
        let mut live = resource.live.clone().lock_owned().await;
        let result = async {
            config.validate()?;
            if resource.stop.is_cancelled() {
                return Err(CuaError::Unknown);
            }
            #[cfg(target_os = "linux")]
            let (stdin, stdout, mut stderr) = {
                let socket = self.worker.ensure_linux_daemon(&config, until).await?;
                let path = config
                    .driver
                    .launch_path()
                    .map_err(|_| CuaError::PermissionDenied)?;
                let launch = ScopeCommand::cua_proxy(
                    path,
                    config.workspace.clone(),
                    config.home.clone(),
                    config.launch.wayland_display.clone(),
                    config.launch.hyprland_instance.clone(),
                    config.launch.compositor_peer,
                    socket,
                    until,
                )
                .await
                .map_err(CuaError::from)?;
                let (mut cmd, scope) = LinuxOwnedScope::command(launch).map_err(CuaError::from)?;
                // Scope is retained before any command spawn or await; failed attestation
                // remains owned Unknown and is cleaned by that exact scope, never by name.
                live.scope = Some(scope);
                let child = cmd.spawn().map_err(|_| CuaError::Unknown)?;
                live.child = Some(child);
                let pid = live
                    .child
                    .as_ref()
                    .and_then(Child::id)
                    .ok_or(CuaError::Unknown)?;
                live.identity = Some(ProcessIdentity::observe(pid).map_err(|_| CuaError::Unknown)?);
                live.scope
                    .as_mut()
                    .ok_or(CuaError::Unknown)?
                    .attest_started(until)
                    .await
                    .map_err(CuaError::from)?;
                let child = live.child.as_mut().ok_or(CuaError::Unknown)?;
                let stdin = child.stdin.take().ok_or(CuaError::Unknown)?;
                let stdout = child.stdout.take().ok_or(CuaError::Unknown)?;

                let stderr = child.stderr.take().ok_or(CuaError::Unknown)?;
                (stdin, stdout, stderr)
            };
            #[cfg(target_os = "macos")]
            let (stdin, stdout, mut stderr) = macos::start_proxy(&mut live, &config, until).await?;
            #[cfg(target_os = "windows")]
            let (stdin, stdout, mut stderr) = {
                let socket = windows::ensure_daemon(
                    &self.worker.inner.shared_daemon,
                    &self.worker.inner.stop,
                    &config,
                    until,
                )
                .await?;
                windows::start(&mut live, &config, socket).await?;
                let child = live.child.as_mut().ok_or(CuaError::Unknown)?;
                (
                    child.take_stdin().ok_or(CuaError::Unknown)?,
                    child.take_stdout().ok_or(CuaError::Unknown)?,
                    child.take_stderr().ok_or(CuaError::Unknown)?,
                )
            };
            live.stderr = Some(tokio::spawn(async move {
                tokio::io::copy(&mut stderr, &mut tokio::io::sink()).await
            }));
            #[cfg(target_os = "macos")]
            let transport_stop = resource.transport_stop.clone();
            #[cfg(not(target_os = "macos"))]
            let transport_stop = resource.stop.clone();
            let transport = transport::AdmittedTransport::from_io(stdout, stdin, transport_stop);
            let handler = CuaClient {};
            let client = tokio::select! {_=resource.stop.cancelled()=>return Err(CuaError::Unknown),value=within(until,handler.serve(transport))=>value.map_err(|_|CuaError::Unknown)?.map_err(|_|CuaError::ProtocolMismatch)?};
            live.client = Some(client);
            let peer = live
                .client
                .as_ref()
                .ok_or(CuaError::Unknown)?
                .peer()
                .clone();
            let info = peer.peer_info().ok_or(CuaError::ProtocolMismatch)?;
            if !info
                .server_info
                .as_ref()
                .is_some_and(|v| v.name == "cua-driver" && v.version == "0.47.24")
            {
                return Err(CuaError::ProtocolMismatch);
            }
            let catalog = tokio::select! {_=resource.stop.cancelled()=>return Err(CuaError::Unknown),v=within(until,peer.list_tools(None))=>v.map_err(|_|CuaError::Unknown)?.map_err(|_|CuaError::ProtocolMismatch)?};
            if catalog.next_cursor.is_some() || catalog.tools.is_empty() {
                return Err(CuaError::Unsupported);
            }
            Ok(())
        };
        let result = tokio::select! {
            _ = resource.stop.cancelled() => Err(CuaError::Unknown),
            result = result => result,
        };
        match result {
            Ok(()) => Ok(CuaOpenReceipt {
                handle,
                evidence: CuaEvidence::Acknowledged,
            }),
            Err(cause) => {
                // Before Command::spawn produced an owned Child, no unit/native
                // process could have been launched through this adapter. Keep
                // this strict local no-I/O fact separate from a failed scope
                // attestation after spawn, which remains owned Unknown.
                if !live.was_started() {
                    resource.stop.cancel();
                    match self.worker.inner.resources.lock() {
                        Ok(mut resources) => {
                            resources.remove(&operation);
                        }
                        Err(_) => {
                            return Err(CuaOpenFailure {
                                operation,
                                handle: Some(handle),
                                evidence: CuaEvidence::Unknown,
                                cause: CuaError::Unknown,
                            });
                        }
                    }
                    return Err(CuaOpenFailure {
                        operation,
                        handle: None,
                        evidence: CuaEvidence::NotDispatched,
                        cause,
                    });
                }
                live.uncertain = true;
                resource.stop.cancel();
                Err(CuaOpenFailure {
                    operation,
                    handle: Some(handle),
                    evidence: CuaEvidence::Unknown,
                    cause,
                })
            }
        }
    }
}
impl CuaActionSlot {
    pub(crate) async fn call_once_until(
        self,
        permit: DispatchPermit,
        until: Option<Instant>,
    ) -> CuaReceipt {
        let operation = permit.id().clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let _ = tx.send(self.call_inner(permit, until).await);
        });
        rx.await.unwrap_or(CuaReceipt {
            operation,
            evidence: CuaEvidence::Unknown,
            result: None,
            cause: Some(CuaError::Unknown),
        })
    }
    async fn call_inner(mut self, permit: DispatchPermit, until: Option<Instant>) -> CuaReceipt {
        let operation = permit.id().clone();
        let refused = |cause: CuaError| CuaReceipt {
            operation: operation.clone(),
            evidence: CuaEvidence::NotDispatched,
            result: None,
            cause: Some(cause),
        };
        let action: CuaAction = match serde_json::from_slice(permit.payload()) {
            Ok(v) => v,
            Err(_) => return refused(CuaError::InvalidRequest),
        };
        #[cfg(target_os = "windows")]
        if self.live.config.launch.source.fenced() {
            return refused(CuaError::StaleObservation);
        }
        if let Err(e) = action.validate() {
            return refused(e);
        }
        let capability = match action.capability() {
            Ok(v) => v,
            Err(e) => return refused(e),
        };
        if permit.purpose() != OperationPurpose::Execute {
            return refused(CuaError::PermissionDenied);
        }
        if let Err(e) = permit_binding(
            &permit,
            &self.resource.owner,
            &self.resource.target,
            &self.resource.session,
            capability,
        ) {
            return refused(e);
        }
        let digest = Sha256Digest::of_bytes(permit.payload());
        if let Some((old, evidence, cause, old_capability)) = self.live.actions.get(&operation) {
            if old != &digest || old_capability != &capability {
                return refused(CuaError::PermissionDenied);
            }
            return CuaReceipt {
                operation,
                evidence: *evidence,
                result: None,
                cause: *cause,
            };
        }
        if until.is_some_and(|until| Instant::now() >= until)
            || self.live.retired
            || self.live.uncertain
            || self.resource.stop.is_cancelled()
        {
            return refused(CuaError::Unknown);
        }
        if self.live.config.validate().is_err() {
            return refused(CuaError::PermissionDenied);
        }
        #[cfg(target_os = "macos")]
        if let Err(error) = {
            let config = self.live.config.clone();
            tokio::select! {
                _ = self.resource.stop.cancelled() => Err(CuaError::Unknown),
                result = macos::preflight(&mut self.live, &config, until) => result,
            }
        } {
            return refused(error);
        }
        let Some(client) = self.live.client.as_ref() else {
            return refused(CuaError::ProtocolMismatch);
        };
        let peer = client.peer().clone();
        let (evidence, result, cause) = match action {
            CuaAction::ListTools { names } => {
                self.live.actions.insert(
                    operation.clone(),
                    (
                        digest,
                        CuaEvidence::Unknown,
                        Some(CuaError::Unknown),
                        capability,
                    ),
                );
                driver_result::invoke_list_tools(
                    &peer,
                    names.as_deref(),
                    &self.resource.stop,
                    until,
                )
                .await
            }
            CuaAction::CallTool { name, arguments } => {
                let params = CallToolRequestParams::new(name).with_arguments(arguments);
                if bounded_bytes(&params, REQUEST_BYTES - 1024).is_err() {
                    return refused(CuaError::InvalidRequest);
                }
                self.live.actions.insert(
                    operation.clone(),
                    (
                        digest,
                        CuaEvidence::Unknown,
                        Some(CuaError::Unknown),
                        capability,
                    ),
                );
                driver_result::invoke(&peer, params, &self.resource.stop, until).await
            }
        };
        if evidence == CuaEvidence::Unknown && result.is_none() {
            self.live.uncertain = true;
        }
        self.live
            .actions
            .insert(operation.clone(), (digest, evidence, cause, capability));
        CuaReceipt {
            operation,
            evidence,
            result,
            cause,
        }
    }
}
#[cfg(any(target_os = "linux", target_os = "windows"))]
async fn cleanup(live: &mut Live, budget: Duration) -> CuaCleanup {
    let until = Instant::now() + budget;
    if live.close_job.is_none()
        && let Some(mut client) = live.client.take()
    {
        live.close_job = Some(tokio::spawn(async move { client.close().await.is_ok() }));
    }
    #[cfg(target_os = "linux")]
    let mut exited;
    #[cfg(target_os = "windows")]
    let exited;
    #[cfg(target_os = "linux")]
    {
        // Incomplete handshakes may leave endpoints owned directly by Child, not by
        // the SDK. Drop these before stopping the original unit; never replace it.
        if let Some(child) = live.child.as_mut() {
            child.stdin.take();
            child.stdout.take();
            child.stderr.take();
        }
        exited = live.exit_success.is_some();
        if let Some(child) = live.child.as_mut() {
            if let Some(scope) = live.scope.as_mut()
                && let Ok(facts) = scope
                    .stop_and_confirm(child, until.saturating_duration_since(Instant::now()))
                    .await
            {
                exited = facts.wrapper_exited;
                if let Some(success) = facts.exit_success {
                    live.exit_success = Some(success)
                }
                live.scope_confirmed |= facts.confirmed;
            }
        } else {
            exited = true;
            // This is either cached actual cleanup (scope_confirmed already true)
            // or strict pre-spawn failure: no owned native Child/unit was started.
            if live.identity.is_none() {
                live.scope_confirmed = true;
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        windows::stop(live, until).await;
        exited = live.exit_success.is_some() || live.child.is_none();
    }
    let mut joined = !live.io_failed;
    if let Some(job) = live.close_job.as_mut() {
        match timeout_at(until, job).await {
            Ok(Ok(true)) => {
                live.close_job.take();
            }
            Ok(_) => {
                live.close_job.take();
                live.io_failed = true;
                joined = false;
            }
            Err(_) => joined = false,
        }
    }
    if let Some(job) = live.stderr.as_mut() {
        match timeout_at(until, job).await {
            Ok(Ok(Ok(_))) => {
                live.stderr.take();
            }
            Ok(_) => {
                live.stderr.take();
                live.io_failed = true;
                joined = false;
            }
            Err(_) => joined = false,
        }
    }
    // Physical proof is the shared scope's original manager/unit InvocationID,
    // held cgroup inode and empty/removed state plus real wrapper wait, not ACK.
    let facts = CuaCleanup {
        worker_exited: exited,
        worker_exit_success: live.exit_success,
        io_joined: joined,
        descendants_confirmed: live.scope_confirmed,
        #[cfg(target_os = "windows")]
        native_settlement: CuaNativeSettlement::WindowsJob {
            confirmed: live.scope_confirmed,
        },
        #[cfg(target_os = "linux")]
        native_settlement: CuaNativeSettlement::LinuxScope {
            confirmed: live.scope_confirmed,
        },
    };
    if facts.complete() {
        live.child.take();
        live.cleanup = Some(facts);
    } else {
        live.uncertain = true;
    }
    facts
}
#[cfg(all(test, target_os = "linux"))]
#[path = "tests.rs"]
mod tests;

#[cfg(target_os = "macos")]
async fn cleanup(live: &mut Live, budget: Duration) -> CuaCleanup {
    let until = Instant::now() + budget;
    let _daemon_exited = live
        .mac_proxy
        .as_mut()
        .is_some_and(|proxy| proxy.observe_original_daemon_exit().unwrap_or(false));
    if live.close_job.is_none()
        && let Some(mut client) = live.client.take()
    {
        live.close_job = Some(tokio::spawn(async move { client.close().await.is_ok() }));
    }
    // Normal end_session ACK and confirmed original-daemon exit are separate
    // physical facts. Neither replaces joining the original proxy and all IO.
    let mut joined = !live.io_failed;
    if let Some(job) = live.close_job.as_mut() {
        match timeout_at(until, job).await {
            Ok(Ok(true)) => {
                live.close_job.take();
            }
            Ok(_) => {
                live.close_job.take();
                live.io_failed = true;
                joined = false;
            }
            Err(_) => joined = false,
        }
    }
    if let Some(job) = live.mac_probe.as_mut() {
        match timeout_at(until, job).await {
            Ok(Ok(_)) => {
                live.mac_probe.take();
            }
            Ok(Err(_)) => {
                live.mac_probe.take();
                live.io_failed = true;
                joined = false;
            }
            Err(_) => joined = false,
        }
    }
    let (exited, success, native_settlement) = match live.mac_proxy.as_mut() {
        None => (true, None, CuaNativeSettlement::NotStarted),
        Some(proxy) => {
            let (exited, success, settlement) = proxy.settle(until).await;
            let native = if proxy.native_not_started() {
                CuaNativeSettlement::NotStarted
            } else {
                settlement
            };
            (exited, success, native)
        }
    };
    if let Some(success) = success {
        live.exit_success = Some(success);
    }
    if let Some(job) = live.stderr.as_mut() {
        match timeout_at(until, job).await {
            Ok(Ok(Ok(_))) => {
                live.stderr.take();
            }
            Ok(_) => {
                live.stderr.take();
                live.io_failed = true;
                joined = false;
            }
            Err(_) => joined = false,
        }
    }
    let facts = CuaCleanup {
        worker_exited: exited,
        worker_exit_success: live.exit_success,
        io_joined: joined,
        descendants_confirmed: false,
        native_settlement,
    };
    if facts.complete() {
        live.mac_proxy.take();
        live.cleanup = Some(facts);
    } else {
        live.uncertain = true;
    }
    facts
}

/// Await normally unless the caller supplied an actual deadline.
pub(crate) async fn within<T>(
    until: Option<Instant>,
    future: impl std::future::Future<Output = T>,
) -> std::result::Result<T, tokio::time::error::Elapsed> {
    match until {
        Some(until) => timeout_at(until, future).await,
        None => Ok(future.await),
    }
}
