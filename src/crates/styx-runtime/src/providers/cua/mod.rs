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
    sync::{Arc, Mutex, OnceLock},
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
#[cfg(target_os = "macos")]
pub(crate) mod probe_diagnostic;
#[cfg(target_os = "macos")]
pub(crate) use macos::{MacProxySource, TrustedCuaLaunch};
mod admission;
mod click;
mod driver_result;
#[cfg(test)]
pub(crate) mod fake_driver;
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub(crate) mod permissions;
pub(crate) mod public_contract;
pub(crate) use click::ClickRequest;
pub(crate) mod ax_snapshot;
mod ax_target;
mod ax_write;
pub(crate) use ax_target::{DesktopReadRequest, DesktopReadTarget};
pub(crate) use ax_write::{AxWriteGate, AxWriteRequest};
mod retention;
mod transport;
pub(crate) mod window_capture;
#[cfg(target_os = "windows")]
use crate::platform::windows_spawn::RunningChild as Child;
#[cfg(target_os = "linux")]
use tokio::process::Child;
use tokio::{
    sync::{OwnedMutexGuard, OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
    time::{Instant, timeout_at},
};
use tokio_util::sync::CancellationToken;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
mod windows_config;
const IO_BYTES: usize = 8 * 1024 * 1024;
const FRAME_BYTES: usize = 1024 * 1024;
const REQUEST_BYTES: usize = 64 * 1024;
const ACTION_RECORDS: usize = 256;
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
            ScopeError::Busy => Self::Busy,
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
    pub(crate) rpc_timeout: Duration,
    pub(crate) workspace: PathBuf,
    pub(crate) home: PathBuf,
    #[cfg(target_os = "windows")]
    pub(crate) environment: BTreeMap<String, String>,
}
impl OwnedCuaConfig {
    pub(crate) fn retained_profile_bytes(&self) -> usize {
        // Session identities have fixed contract maxima; shared source/image
        // Arcs are not multiplied by the number of owner profiles.
        let bytes =
            std::mem::size_of::<Self>() + 4096 + self.workspace.capacity() + self.home.capacity();
        #[cfg(target_os = "linux")]
        let bytes = bytes
            + self.launch.runtime_dir.capacity()
            + self.launch.session_bus.capacity()
            + self.launch.wayland_display.capacity()
            + self.launch.hyprland_instance.capacity();
        #[cfg(target_os = "windows")]
        let bytes = bytes
            + self
                .environment
                .iter()
                .map(|(k, v)| 128 + k.capacity() + v.capacity())
                .sum::<usize>();
        #[cfg(target_os = "macos")]
        let bytes = bytes + macos::profile_launch_bytes(&self.launch);
        bytes
    }
    pub(crate) fn validate_metadata_bound(&self) -> Result<()> {
        if self.retained_profile_bytes() > 128 * 1024 {
            Err(CuaError::InvalidRequest)
        } else {
            Ok(())
        }
    }

    #[cfg(target_os = "linux")]
    fn validate(&self) -> Result<()> {
        if self.launch.uid != nix::unistd::Uid::current().as_raw()
            || self.launch.compositor_peer.0 == 0
            || self.launch.compositor_peer.1 == 0
            || self.rpc_timeout.is_zero()
            || self.rpc_timeout > Duration::from_secs(30)
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
        bounded_bytes(&serde_json::json!({"session":self.launch.session,"uid":self.launch.uid,"runtime":self.launch.runtime_dir,"wayland":self.launch.wayland_display,"hyprland":self.launch.hyprland_instance,"compositor_peer":self.launch.compositor_peer,"bus":self.launch.session_bus,"image":self.driver.launch_path().map_err(|_|CuaError::PermissionDenied)?,"timeout_ms":self.rpc_timeout.as_millis(),"workspace":self.workspace,"home":self.home}),REQUEST_BYTES).map(|v|Sha256Digest::of_bytes(&v))
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
        config.validate_metadata_bound()?;
        Ok(Self {
            config_digest: config.digest()?,
        })
    }
    pub fn to_operation_payload(&self) -> Result<Vec<u8>> {
        bounded_bytes(self, REQUEST_BYTES)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CuaAction {
    name: String,
    arguments: Map<String, Value>,
}
impl CuaAction {
    pub fn new(name: String, mut arguments: Map<String, Value>) -> Result<Self> {
        public_contract::canonicalize(&name, &mut arguments);
        let value = Self { name, arguments };
        value.validate()?;
        Ok(value)
    }
    pub fn to_operation_payload(&self) -> Result<Vec<u8>> {
        self.validate()?;
        bounded_bytes(self, REQUEST_BYTES)
    }
    fn validate(&self) -> Result<()> {
        bounded_bytes(self, REQUEST_BYTES)?;
        let schemas = public_schemas()?;
        let schema = schemas.get(&self.name).ok_or(CuaError::Unsupported)?;
        // Native Cua writes this optional path directly, including overwrite.
        // Until an owned output-file port exists, capture may return image data
        // but cannot inherit arbitrary current-user filesystem write authority.
        if self.arguments.contains_key("screenshot_out_file")
            || reserved(&Value::Object(self.arguments.clone()))
            || !schema.is_valid(&Value::Object(self.arguments.clone()))
        {
            return Err(CuaError::InvalidRequest);
        }
        Ok(())
    }
    pub fn capability(&self) -> Result<CapabilityId> {
        self.required_capabilities()?
            .first()
            .copied()
            .ok_or(CuaError::Unsupported)
    }
    pub(crate) fn required_capabilities(&self) -> Result<Vec<CapabilityId>> {
        self.validate()?;
        admission::required(&self.name, &self.arguments)
    }
    pub(crate) fn requires_observed_target(&self) -> Result<bool> {
        self.validate()?;
        Ok(admission::classify(&self.name, &self.arguments)?.requires_observed_target)
    }
    /// Fixed read-only native branch; never selected by a serialized purpose flag.
    pub(crate) fn desktop_read_request(&self) -> Result<Option<DesktopReadRequest>> {
        self.validate()?;
        if let Some(value) = ax_target::AxReadRequest::classify(&self.name, &self.arguments)? {
            return Ok(Some(DesktopReadRequest::Accessibility(value)));
        }
        Ok(
            window_capture::WindowCaptureRequest::classify(&self.name, &self.arguments)?
                .map(DesktopReadRequest::WindowCapture),
        )
    }
    fn mutates(&self) -> bool {
        admission::classify(&self.name, &self.arguments).map_or(true, |r| r.side_effecting)
    }
}
fn capability(name: &str) -> Result<CapabilityId> {
    Ok(match name {
        "list_apps" | "list_windows" => CapabilityId::DesktopWindowsRead,
        "get_window_state" | "get_desktop_state" => CapabilityId::DesktopCapture,
        "click" | "scroll" => CapabilityId::DesktopPointer,
        "type_text" | "press_key" => CapabilityId::DesktopKeyboard,
        "set_value" | "verify_state" => CapabilityId::DesktopAccessibility,
        _ => return Err(CuaError::Unsupported),
    })
}
fn reserved(value: &Value) -> bool {
    match value {
        Value::Object(m) => m
            .iter()
            .any(|(k, v)| matches!(k.as_str(), "environment_id" | "_meta") || reserved(v)),
        Value::Array(a) => a.iter().any(reserved),
        _ => false,
    }
}
fn public_schemas() -> Result<&'static BTreeMap<String, jsonschema::Validator>> {
    static VALUE: OnceLock<std::result::Result<BTreeMap<String, jsonschema::Validator>, CuaError>> =
        OnceLock::new();
    VALUE
        .get_or_init(|| {
            let value: Value = serde_json::from_str(include_str!(
                "../../../../../gateway/cua-portable-0.36.0.json"
            ))
            .map_err(|_| CuaError::ProtocolMismatch)?;
            let tools = value["tools"]
                .as_array()
                .ok_or(CuaError::ProtocolMismatch)?;
            let mut schemas = BTreeMap::new();
            for tool in tools {
                let name = tool["name"].as_str().ok_or(CuaError::ProtocolMismatch)?;
                capability(name)?;
                let validator = jsonschema::validator_for(&tool["inputSchema"])
                    .map_err(|_| CuaError::ProtocolMismatch)?;
                if schemas.insert(name.into(), validator).is_some() {
                    return Err(CuaError::ProtocolMismatch);
                }
            }
            if schemas.len() != 10 {
                return Err(CuaError::ProtocolMismatch);
            }
            Ok(schemas)
        })
        .as_ref()
        .map_err(|e| *e)
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
pub(crate) fn trace_write_settlement(
    evidence: CuaEvidence,
    ledger: bool,
    audit: bool,
    delivery: bool,
) {
    if std::env::var_os("STYX_CUA_DIAGNOSTICS").as_deref() != Some(std::ffi::OsStr::new("1")) {
        return;
    }
    use std::io::Write as _;
    let _ = writeln!(
        std::io::stderr().lock(),
        "{}",
        serde_json::json!({
            "event":"styx_cua_write_settlement", "native_acknowledged":matches!(evidence,CuaEvidence::Acknowledged),
            "native_unknown":matches!(evidence,CuaEvidence::Unknown), "ledger_recorded":ledger,"audit_recorded":audit,"delivery_admitted":delivery
        })
    );
}
pub struct CuaIoBudget {
    _partition: OwnedSemaphorePermit,
    active: Arc<Semaphore>,
}
impl CuaIoBudget {
    pub fn from_reserved(partition: OwnedSemaphorePermit) -> Result<Arc<Self>> {
        if partition.num_permits() != IO_BYTES {
            return Err(CuaError::InvalidRequest);
        }
        Ok(Arc::new(Self {
            _partition: partition,
            active: Arc::new(Semaphore::new(1)),
        }))
    }
}
#[derive(Clone)]
pub struct CuaWorker {
    inner: Arc<Inner>,
}
struct Inner {
    budget: Arc<CuaIoBudget>,
    resources: Mutex<BTreeMap<OperationId, Arc<Resource>>>,
    stop: CancellationToken,
}
struct Resource {
    owner: OwnerLease,
    target: ResourceTarget,
    session: SessionBinding,
    budget: Arc<CuaIoBudget>,
    stop: CancellationToken,
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
    #[cfg(target_os = "macos")]
    mac_session: Option<String>,
    #[cfg(target_os = "macos")]
    mac_session_end: Option<JoinHandle<bool>>,
    #[cfg(target_os = "macos")]
    mac_session_end_finished: bool,
    identity: Option<ProcessIdentity>,
    client: Option<RunningService<RoleClient, CuaClient>>,
    close_job: Option<JoinHandle<bool>>,
    stderr: Option<JoinHandle<std::io::Result<u64>>>,
    config: Arc<OwnedCuaConfig>,
    slot: Option<Arc<OwnedSemaphorePermit>>,
    retired: bool,
    cleanup: Option<CuaCleanup>,
    uncertain: bool,
    io_failed: bool,
    ax_once_available: bool,
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    permissions_available: bool,
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    permissions: Option<permissions::DriverPermissions>,
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
struct CuaClient {
    _budget: Arc<CuaIoBudget>,
}
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
    slot: OwnedSemaphorePermit,
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
impl CuaWorker {
    pub fn new(budget: Arc<CuaIoBudget>) -> Self {
        Self {
            inner: Arc::new(Inner {
                budget,
                resources: Mutex::new(BTreeMap::new()),
                stop: CancellationToken::new(),
            }),
        }
    }
    pub fn try_reserve_open(&self) -> Result<CuaOpenSlot> {
        if self
            .inner
            .resources
            .lock()
            .map_err(|_| CuaError::Unknown)?
            .len()
            >= 16
        {
            return Err(CuaError::Busy);
        }
        let slot = self
            .inner
            .budget
            .active
            .clone()
            .try_acquire_owned()
            .map_err(|_| CuaError::Busy)?;
        Ok(CuaOpenSlot {
            worker: self.clone(),
            slot,
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
    ) -> std::result::Result<CuaOpenReceipt, CuaOpenFailure> {
        let operation = permit.id().clone();
        let worker = self.worker.clone();
        let lost = operation.clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let _ = tx.send(self.open_inner(permit, config).await);
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
        let resource = Arc::new(Resource {
            owner: permit.owner().clone(),
            target,
            session: config.launch.session.clone(),
            budget: self.worker.inner.budget.clone(),
            stop: CancellationToken::new(),
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
                #[cfg(target_os = "macos")]
                mac_session: None,
                #[cfg(target_os = "macos")]
                mac_session_end: None,
                #[cfg(target_os = "macos")]
                mac_session_end_finished: false,
                identity: None,
                client: None,
                close_job: None,
                stderr: None,
                config: config.clone(),
                slot: Some(Arc::new(self.slot)),
                retired: false,
                cleanup: None,
                uncertain: false,
                io_failed: false,
                ax_once_available: false,
                #[cfg(any(target_os = "linux", target_os = "windows"))]
                permissions_available: false,
                #[cfg(any(target_os = "linux", target_os = "windows"))]
                permissions: None,
                exit_success: None,
                actions: BTreeMap::new(),
            })),
            cleanup_job: Mutex::new(Some(cleanup_rx)),
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
        // Keep the original process/pin/partition alive independently of public
        // waiters and even the last Worker/Handle dropping. No detached child owner.
        let owned = resource.clone();
        let host_stop = self.worker.inner.stop.clone();
        #[cfg(target_os = "windows")]
        let source = config.launch.source.clone();
        tokio::spawn(async move {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            tokio::select! {_=host_stop.cancelled()=>{},_=owned.stop.cancelled()=>{}}
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
        let until = Instant::now() + config.rpc_timeout;
        let result=async {
   config.validate()?;
   if resource.stop.is_cancelled(){return Err(CuaError::Unknown)}
   #[cfg(target_os = "linux")]
   let (stdin,stdout,mut stderr) = {
   let path=config.driver.launch_path().map_err(|_|CuaError::PermissionDenied)?;
   let launch=ScopeCommand::cua(path,config.workspace.clone(),config.home.clone(),config.launch.wayland_display.clone(),config.launch.hyprland_instance.clone(),config.launch.compositor_peer,until).await.map_err(CuaError::from)?;
   let (mut cmd,scope)=LinuxOwnedScope::command(launch).map_err(CuaError::from)?;
   // Scope is retained before any command spawn or await; failed attestation
   // remains owned Unknown and is cleaned by that exact scope, never by name.
   live.scope=Some(scope);
   let child=cmd.spawn().map_err(|_|CuaError::Unknown)?;live.child=Some(child);
   let pid=live.child.as_ref().and_then(Child::id).ok_or(CuaError::Unknown)?;live.identity=Some(ProcessIdentity::observe(pid).map_err(|_|CuaError::Unknown)?);
   live.scope.as_mut().ok_or(CuaError::Unknown)?.attest_started(until).await.map_err(CuaError::from)?;
   let child=live.child.as_mut().ok_or(CuaError::Unknown)?;let stdin=child.stdin.take().ok_or(CuaError::Unknown)?;let stdout=child.stdout.take().ok_or(CuaError::Unknown)?;

   let stderr=child.stderr.take().ok_or(CuaError::Unknown)?;
   (stdin,stdout,stderr)
   };
   #[cfg(target_os = "macos")]
   let (stdin,stdout,mut stderr)=macos::start_proxy(&mut live,&config,resource.budget.clone(),until).await?;
   #[cfg(target_os = "windows")]
   let (stdin,stdout,mut stderr) = {
     windows::start(&mut live,&config).await?;
     let child=live.child.as_mut().ok_or(CuaError::Unknown)?;
     (child.take_stdin().ok_or(CuaError::Unknown)?,child.take_stdout().ok_or(CuaError::Unknown)?,child.take_stderr().ok_or(CuaError::Unknown)?)
   };
   let budget=resource.budget.clone();live.stderr=Some(tokio::spawn(async move{let _budget=budget;tokio::io::copy(&mut stderr,&mut tokio::io::sink()).await}));
   let transport=transport::AdmittedTransport::from_io(stdout,stdin,resource.stop.clone(),resource.budget.clone());
   let handler=CuaClient{_budget:resource.budget.clone()};let client=tokio::select!{_=resource.stop.cancelled()=>return Err(CuaError::Unknown),value=timeout_at(until,handler.serve(transport))=>value.map_err(|_|CuaError::Unknown)?.map_err(|_|CuaError::ProtocolMismatch)?};live.client=Some(client);
   let peer=live.client.as_ref().ok_or(CuaError::Unknown)?.peer().clone();let info=peer.peer_info().ok_or(CuaError::ProtocolMismatch)?;
   if !info.server_info.as_ref().is_some_and(|v|v.name=="cua-driver"&&v.version=="0.47.24"){return Err(CuaError::ProtocolMismatch)}
   let catalog=tokio::select!{_=resource.stop.cancelled()=>return Err(CuaError::Unknown),v=timeout_at(until,peer.list_tools(None))=>v.map_err(|_|CuaError::Unknown)?.map_err(|_|CuaError::ProtocolMismatch)?};
   if catalog.next_cursor.is_some(){return Err(CuaError::Unsupported)}live.ax_once_available=validate_catalog(&catalog.tools)?;
   #[cfg(target_os = "macos")]
   {
     let session = format!("styx-{}", uuid::Uuid::new_v4());
     live.mac_session = Some(session.clone());
     live.mac_proxy.as_mut().ok_or(CuaError::ProtocolMismatch)?.mark_session_started();
     let arguments = serde_json::json!({"session":session}).as_object().ok_or(CuaError::ProtocolMismatch)?.clone();
     let request = CallToolRequestParams::new("start_session").with_arguments(arguments);
     let reply = tokio::select! {
         _=resource.stop.cancelled()=>return Err(CuaError::Unknown),
         value=timeout_at(until,peer.call_tool(request))=>value.map_err(|_|CuaError::Unknown)?.map_err(|_|CuaError::Unknown)?
     };
     if reply.is_error == Some(true) || !reply.structured_content.as_ref().is_some_and(|value|
         value.get("active").and_then(Value::as_bool)==Some(true)
         && value.get("session").and_then(Value::as_str)==Some(session.as_str())) {
         return Err(CuaError::ProtocolMismatch);
     }
   }
   #[cfg(any(target_os = "linux", target_os = "windows"))]
   {
     live.permissions_available = catalog.tools.iter().any(|tool| tool.name == "check_permissions");
     permissions::query(&mut live, &resource.stop, until).await?;
   }
   Ok(())
  }.await;
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
/// Immutable platform source contract, not selected by a request/descriptor.
#[derive(Clone, Copy)]
struct FixedNativeCatalog {
    schemas_json: &'static str,
}
#[cfg(target_os = "macos")]
#[path = "macos_catalog.rs"]
mod platform_catalog;
fn selected_native_catalog() -> Result<FixedNativeCatalog> {
    #[cfg(target_os = "linux")]
    {
        Ok(FixedNativeCatalog {
            schemas_json: NATIVE_CATALOG,
        })
    }
    #[cfg(target_os = "macos")]
    {
        Ok(platform_catalog::FROZEN_MACOS_CATALOG)
    }
    #[cfg(target_os = "windows")]
    {
        Ok(FixedNativeCatalog {
            schemas_json: include_str!("windows-catalog.json"),
        })
    }
}
fn validate_catalog(tools: &[rmcp::model::Tool]) -> Result<bool> {
    // Only the consumed platform schemas are checked. Strict text writes require
    // the internal native flag; Core still owns grants and one-use dispatch.
    validate_native_catalog(tools, selected_native_catalog()?)
}
// Descriptive wording is upstream documentation, not executable compatibility.
fn schema_contract(value: Value) -> Value {
    match value {
        Value::Object(values) => Value::Object(
            values
                .into_iter()
                .filter(|(key, _)| {
                    !matches!(
                        key.as_str(),
                        "description" | "title" | "$comment" | "examples"
                    )
                })
                .map(|(key, value)| (key, schema_contract(value)))
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.into_iter().map(schema_contract).collect()),
        value => value,
    }
}
fn validate_native_catalog(
    tools: &[rmcp::model::Tool],
    contract: FixedNativeCatalog,
) -> Result<bool> {
    if !(10..=128).contains(&tools.len()) {
        return Err(CuaError::Unsupported);
    }
    let expected: Value =
        serde_json::from_str(contract.schemas_json).map_err(|_| CuaError::ProtocolMismatch)?;
    let mut actual = Map::new();
    for tool in tools {
        let value = serde_json::to_value(tool).map_err(|_| CuaError::ProtocolMismatch)?;
        if actual
            .insert(tool.name.to_string(), value["inputSchema"].clone())
            .is_some()
        {
            return Err(CuaError::ProtocolMismatch);
        }
    }
    // This optional internal flag is the only retained native extension.
    // It is never accepted in Styx's public CuaAction schema.
    let strict = actual
        .get_mut("set_value")
        .and_then(|schema| schema.get_mut("properties"))
        .and_then(Value::as_object_mut)
        .and_then(|properties| properties.remove("styx_strict_text"));
    if strict.as_ref().is_some_and(|schema| {
        schema_contract(schema.clone()) != serde_json::json!({"type":"boolean"})
    }) {
        return Err(CuaError::Unsupported);
    }
    // This projection does not expose any additional native tool. Every
    // public portable tool must match its pinned native input structure;
    // upstream descriptive wording and unrelated tools do not change it.
    let names = expected.as_object().ok_or(CuaError::ProtocolMismatch)?;
    if names.len() != 10
        || names.keys().any(|name| {
            !matches!(
                name.as_str(),
                "list_apps"
                    | "list_windows"
                    | "get_window_state"
                    | "get_desktop_state"
                    | "click"
                    | "scroll"
                    | "type_text"
                    | "press_key"
                    | "set_value"
                    | "verify_state"
            )
        })
    {
        return Err(CuaError::ProtocolMismatch);
    }
    actual.retain(|name, _| names.contains_key(name));
    if schema_contract(Value::Object(actual)) != schema_contract(expected) {
        return Err(CuaError::Unsupported);
    }
    Ok(strict.is_some())
}
impl CuaActionSlot {
    pub async fn call_once(self, permit: DispatchPermit) -> CuaReceipt {
        let budget = self.live.config.rpc_timeout;
        self.call_once_with_budget(permit, budget).await
    }
    pub(crate) async fn call_once_with_budget(
        self,
        permit: DispatchPermit,
        budget: Duration,
    ) -> CuaReceipt {
        let until = Instant::now() + budget.min(self.live.config.rpc_timeout);
        self.call_owned(permit, until, None).await
    }
    pub(crate) async fn call_once_until_with_write_gate(
        self,
        permit: DispatchPermit,
        until: Instant,
        gate: AxWriteGate,
    ) -> CuaReceipt {
        let until = until.min(Instant::now() + self.live.config.rpc_timeout);
        self.call_owned(permit, until, Some(gate)).await
    }
    async fn call_owned(
        self,
        permit: DispatchPermit,
        until: Instant,
        write_gate: Option<AxWriteGate>,
    ) -> CuaReceipt {
        let operation = permit.id().clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let _ = tx.send(self.call_inner(permit, until, write_gate).await);
        });
        rx.await.unwrap_or(CuaReceipt {
            operation,
            evidence: CuaEvidence::Unknown,
            result: None,
            cause: Some(CuaError::Unknown),
        })
    }
    async fn call_inner(
        mut self,
        permit: DispatchPermit,
        until: Instant,
        write_gate: Option<AxWriteGate>,
    ) -> CuaReceipt {
        let operation = permit.id().clone();
        let refused = |stage, cause: CuaError| {
            ax_write::diagnostic(stage, cause.code());
            CuaReceipt {
                operation: operation.clone(),
                evidence: CuaEvidence::NotDispatched,
                result: None,
                cause: Some(cause),
            }
        };
        let action: CuaAction = match serde_json::from_slice(permit.payload()) {
            Ok(v) => v,
            Err(_) => return refused("permit_payload", CuaError::InvalidRequest),
        };
        #[cfg(target_os = "windows")]
        if self.live.config.launch.source.fenced() {
            return refused("desktop_source_fenced", CuaError::StaleObservation);
        }
        if let Err(e) = action.validate() {
            return refused("action_validation", e);
        }
        let capability = match action.capability() {
            Ok(v) => v,
            Err(e) => return refused("action_capability", e),
        };
        if let Err(e) = permit_binding(
            &permit,
            &self.resource.owner,
            &self.resource.target,
            &self.resource.session,
            capability,
        ) {
            return refused("permit_binding", e);
        }
        let click = match action.click_request() {
            Ok(value) => value.is_some(),
            Err(error) => return refused("click_request", error),
        };
        if click && write_gate.is_none() {
            return refused("click_gate_missing", CuaError::PermissionDenied);
        }
        let write_request = match action.accessibility_write_request() {
            Ok(value) => value,
            Err(error) => return refused("write_request", error),
        };
        let write_attempt = permit.purpose() == OperationPurpose::DesktopAccessibilityWriteAttempt;
        if write_attempt != write_request.is_some() || (write_attempt && write_gate.is_none()) {
            return refused("write_contract", CuaError::PermissionDenied);
        }
        if write_attempt && !self.live.ax_once_available {
            // A stock worker lacks the strict text-only flag. Keep writes closed
            // rather than using upstream's alternate-setter/activation behavior.
            return refused("write_extension_missing", CuaError::Unsupported);
        }
        if permit.purpose() != OperationPurpose::Execute
            && !write_attempt
            && !matches!(action.desktop_read_request(), Ok(Some(request)) if request.purpose() == permit.purpose())
        {
            return refused("operation_purpose", CuaError::PermissionDenied);
        }
        if action.mutates() && permit.context().observation.is_none() {
            return refused("missing_observation", CuaError::PermissionDenied);
        }
        let digest = Sha256Digest::of_bytes(permit.payload());
        if let Some((old, evidence, cause, old_capability)) = self.live.actions.get(&operation) {
            if old != &digest || old_capability != &capability {
                return refused("operation_binding", CuaError::PermissionDenied);
            }
            return CuaReceipt {
                operation,
                evidence: *evidence,
                result: None,
                cause: *cause,
            };
        }
        if Instant::now() >= until
            || self.live.retired
            || self.live.uncertain
            || self.resource.stop.is_cancelled()
        {
            return refused("worker_unavailable", CuaError::Unknown);
        }
        if self.live.actions.len() >= ACTION_RECORDS {
            return refused("action_capacity", CuaError::Busy);
        }
        if self.live.config.validate().is_err() {
            return refused("configuration_revalidation", CuaError::PermissionDenied);
        }
        #[cfg(target_os = "macos")]
        if let Err(error) = {
            let config = self.live.config.clone();
            macos::preflight(&mut self.live, &config, until).await
        } {
            return refused("native_preflight", error);
        }
        let Some(client) = self.live.client.as_ref() else {
            return refused("native_client_missing", CuaError::ProtocolMismatch);
        };
        let peer = client.peer().clone();
        #[cfg(target_os = "macos")]
        let native_session = self.live.mac_session.clone();
        #[cfg(not(target_os = "macos"))]
        let native_session: Option<String> = None;
        let mut arguments = action.arguments;
        if let Some(session) = native_session.as_ref() {
            arguments.insert("session".into(), Value::String(session.clone()));
        }
        let params = CallToolRequestParams::new(action.name).with_arguments(arguments);
        if bounded_bytes(&params, REQUEST_BYTES - 1024).is_err() {
            return refused("request_bound", CuaError::InvalidRequest);
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
        let mut write_gate = write_gate;
        if click && let Err(error) = write_gate.take().expect("checked click gate")().await {
            self.live.actions.insert(
                operation.clone(),
                (digest, CuaEvidence::NotDispatched, Some(error), capability),
            );
            return refused("click_gate", error);
        }
        let (evidence, result, cause) = if let Some(request) = write_request {
            let stop = self.resource.stop.clone();
            ax_write::invoke(
                &stop,
                &mut self.live.uncertain,
                &peer,
                request,
                until,
                write_gate.expect("checked write gate"),
                native_session.as_deref(),
            )
            .await
        } else {
            driver_result::invoke(&peer, params, &self.resource.stop, until).await
        };
        if evidence == CuaEvidence::Unknown {
            self.live.uncertain = true
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
        live.slot.take();
        live.cleanup = Some(facts);
    } else {
        live.uncertain = true;
    }
    facts
}
// The ten consumed schemas from the official 0.47.24 Linux binary.
#[cfg(target_os = "linux")]
const NATIVE_CATALOG: &str = include_str!("linux-catalog.json");
#[cfg(all(test, target_os = "linux"))]
#[path = "tests.rs"]
mod tests;

#[cfg(target_os = "macos")]
async fn cleanup(live: &mut Live, budget: Duration) -> CuaCleanup {
    let until = Instant::now() + budget;
    let daemon_exited = live
        .mac_proxy
        .as_mut()
        .is_some_and(|proxy| proxy.observe_original_daemon_exit().unwrap_or(false));
    if daemon_exited
        && live.close_job.is_none()
        && let Some(mut client) = live.client.take()
    {
        // Stop and JOIN the original local MCP transport. This also releases
        // any already queued end_session waiter; never abort/detach that job.
        live.close_job = Some(tokio::spawn(async move { client.close().await.is_ok() }));
    }
    if !daemon_exited && !live.mac_session_end_finished && live.mac_session_end.is_none() {
        if let (Some(session), Some(client)) = (live.mac_session.clone(), live.client.as_ref()) {
            let peer = client.peer().clone();
            live.mac_session_end = Some(tokio::spawn(async move {
                let arguments = serde_json::json!({"session":session})
                    .as_object()
                    .expect("literal object")
                    .clone();
                let request = CallToolRequestParams::new("end_session").with_arguments(arguments);
                match peer.call_tool(request).await {
                    Ok(reply) => {
                        reply.is_error != Some(true)
                            && reply.structured_content.as_ref().is_some_and(|value| {
                                value.get("active").and_then(Value::as_bool) == Some(false)
                                    && value.get("session").and_then(Value::as_str)
                                        == Some(session.as_str())
                            })
                    }
                    Err(_) => false,
                }
            }));
        } else {
            live.mac_session_end_finished = true;
        }
    }
    if let Some(job) = live.mac_session_end.as_mut() {
        match timeout_at(until, job).await {
            Ok(result) => {
                live.mac_session_end.take();
                live.mac_session_end_finished = true;
                if matches!(result, Ok(true)) {
                    if let Some(proxy) = live.mac_proxy.as_mut() {
                        proxy.mark_session_ended();
                    }
                }
            }
            Err(_) => {
                // Do not resend end_session or drop a task still owning native work.
                return CuaCleanup {
                    worker_exited: false,
                    worker_exit_success: live.exit_success,
                    io_joined: false,
                    descendants_confirmed: false,
                    native_settlement: CuaNativeSettlement::MacAppTransport { drained: false },
                };
            }
        }
    }
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
        live.slot.take();
        live.cleanup = Some(facts);
    } else {
        live.uncertain = true;
    }
    facts
}
