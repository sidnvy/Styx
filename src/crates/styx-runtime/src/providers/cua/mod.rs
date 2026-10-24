//! Linux owned Cua stdio adapter. Core is the only operation/session authority.
//! Shared Linux scope owns the exact native worker tree; absence of its
//! original cgroup/InvocationID proof remains Unknown, never a close ACK fact.
use crate::providers::linux_scope::{LinuxOwnedScope, ScopeCommand, ScopeError};
use crate::store::{PinnedExecutable, ProcessIdentity};
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
use styx_core::operations::{DispatchPermit, OwnerLease, ResourceDomain};
mod admission;
mod retention;
mod transport;
use tokio::{
    process::Child,
    sync::{OwnedMutexGuard, OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
    time::{Instant, timeout_at},
};
use tokio_util::sync::CancellationToken;
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
    #[error("cua_unsupported")]
    Unsupported,
    #[error("cua_protocol_mismatch")]
    ProtocolMismatch,
    #[error("cua_outcome_unknown")]
    Unknown,
    #[error("cua_cleanup_unconfirmed")]
    CleanupUnconfirmed,
}
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
            Self::Unsupported => "cua_unsupported",
            Self::ProtocolMismatch => "cua_protocol_mismatch",
            Self::Unknown => "cua_outcome_unknown",
            Self::CleanupUnconfirmed => "cua_cleanup_unconfirmed",
        }
    }
}
/// Runtime association/Host bootstrap only. Not Deserialize, not a grant. The
/// associated live Session must still pass Core admission for EVERY operation.
#[derive(Clone)]
pub(crate) struct TrustedCuaLaunch {
    pub(crate) session: SessionBinding,
    pub(crate) uid: u32,
    pub(crate) runtime_dir: PathBuf,
    pub(crate) wayland_display: String,
    pub(crate) hyprland_instance: String,
    pub(crate) session_bus: PathBuf,
}
#[derive(Clone)]
pub(crate) struct OwnedCuaConfig {
    // Caller has already checked this image against the original signed manifest.
    // Store's pin by itself is not a publisher signature authority.
    pub(crate) driver: Arc<PinnedExecutable>,
    pub(crate) launch: TrustedCuaLaunch,
    pub(crate) rpc_timeout: Duration,
    pub(crate) workspace: PathBuf,
    pub(crate) home: PathBuf,
}
impl OwnedCuaConfig {
    fn validate(&self) -> Result<()> {
        if self.launch.uid != nix::unistd::Uid::current().as_raw()
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
    fn digest(&self) -> Result<Sha256Digest> {
        self.validate()?;
        bounded_bytes(&serde_json::json!({"session":self.launch.session,"uid":self.launch.uid,"runtime":self.launch.runtime_dir,"wayland":self.launch.wayland_display,"hyprland":self.launch.hyprland_instance,"bus":self.launch.session_bus,"image":self.driver.launch_path().map_err(|_|CuaError::PermissionDenied)?,"timeout_ms":self.rpc_timeout.as_millis(),"workspace":self.workspace,"home":self.home}),REQUEST_BYTES).map(|v|Sha256Digest::of_bytes(&v))
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
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CuaAction {
    name: String,
    arguments: Map<String, Value>,
}
impl CuaAction {
    pub fn new(name: String, arguments: Map<String, Value>) -> Result<Self> {
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
pub struct CuaCleanup {
    pub worker_exited: bool,
    pub worker_exit_success: Option<bool>,
    pub io_joined: bool,
    pub descendants_confirmed: bool,
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
    scope: Option<LinuxOwnedScope>,
    scope_confirmed: bool,
    child: Option<Child>,
    identity: Option<ProcessIdentity>,
    client: Option<RunningService<RoleClient, CuaClient>>,
    close_job: Option<JoinHandle<bool>>,
    stderr: Option<JoinHandle<std::io::Result<u64>>>,
    config: Arc<OwnedCuaConfig>,
    slot: Option<OwnedSemaphorePermit>,
    retired: bool,
    cleanup: Option<CuaCleanup>,
    uncertain: bool,
    io_failed: bool,
    exit_success: Option<bool>,
    actions: BTreeMap<OperationId, (Sha256Digest, CuaEvidence, Option<CuaError>, CapabilityId)>,
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
            if permit.resource_domain() != ResourceDomain::DesktopAgent
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
                scope: None,
                scope_confirmed: false,
                child: None,
                identity: None,
                client: None,
                close_job: None,
                stderr: None,
                config: config.clone(),
                slot: Some(self.slot),
                retired: false,
                cleanup: None,
                uncertain: false,
                io_failed: false,
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
        tokio::spawn(async move {
            tokio::select! {_=host_stop.cancelled()=>{},_=owned.stop.cancelled()=>{}}
            owned.stop.cancel();
            loop {
                let facts = cleanup(&mut *owned.live.lock().await, Duration::from_secs(2)).await;
                let _ = cleanup_tx.send(Some(facts));
                if facts.worker_exited && facts.io_joined && facts.descendants_confirmed {
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
   config.validate()?;if resource.stop.is_cancelled(){return Err(CuaError::Unknown)}let path=config.driver.launch_path().map_err(|_|CuaError::PermissionDenied)?;
   let launch=ScopeCommand::cua(path,config.workspace.clone(),config.home.clone(),config.launch.wayland_display.clone(),config.launch.hyprland_instance.clone()).map_err(CuaError::from)?;
   let (mut cmd,scope)=LinuxOwnedScope::command(launch).map_err(CuaError::from)?;
   // Scope is retained before any command spawn or await; failed attestation
   // remains owned Unknown and is cleaned by that exact scope, never by name.
   live.scope=Some(scope);
   let child=cmd.spawn().map_err(|_|CuaError::Unknown)?;live.child=Some(child);
   let pid=live.child.as_ref().and_then(Child::id).ok_or(CuaError::Unknown)?;live.identity=Some(ProcessIdentity::observe(pid).map_err(|_|CuaError::Unknown)?);
   live.scope.as_mut().ok_or(CuaError::Unknown)?.attest_started(until).await.map_err(CuaError::from)?;
   let child=live.child.as_mut().ok_or(CuaError::Unknown)?;let stdin=child.stdin.take().ok_or(CuaError::Unknown)?;let stdout=child.stdout.take().ok_or(CuaError::Unknown)?;
   let mut stderr=child.stderr.take().ok_or(CuaError::Unknown)?;let budget=resource.budget.clone();live.stderr=Some(tokio::spawn(async move{let _budget=budget;tokio::io::copy(&mut stderr,&mut tokio::io::sink()).await}));
   let transport=transport::AdmittedTransport::from_io(stdout,stdin,resource.stop.clone(),resource.budget.clone());
   let handler=CuaClient{_budget:resource.budget.clone()};let client=tokio::select!{_=resource.stop.cancelled()=>return Err(CuaError::Unknown),value=timeout_at(until,handler.serve(transport))=>value.map_err(|_|CuaError::Unknown)?.map_err(|_|CuaError::ProtocolMismatch)?};live.client=Some(client);
   let peer=live.client.as_ref().ok_or(CuaError::Unknown)?.peer();let info=peer.peer_info().ok_or(CuaError::ProtocolMismatch)?;
   if !info.server_info.as_ref().is_some_and(|v|v.name=="cua-driver"&&v.version=="0.36.0"){return Err(CuaError::ProtocolMismatch)}
   let catalog=tokio::select!{_=resource.stop.cancelled()=>return Err(CuaError::Unknown),v=timeout_at(until,peer.list_tools(None))=>v.map_err(|_|CuaError::Unknown)?.map_err(|_|CuaError::ProtocolMismatch)?};
   if catalog.next_cursor.is_some(){return Err(CuaError::Unsupported)}validate_catalog(&catalog.tools)?;Ok(())
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
                if live.child.is_none() && live.identity.is_none() {
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
fn validate_catalog(tools: &[rmcp::model::Tool]) -> Result<()> {
    if tools.len() != 64 {
        return Err(CuaError::Unsupported);
    }
    let expected: Value =
        serde_json::from_str(NATIVE_CATALOG).map_err(|_| CuaError::ProtocolMismatch)?;
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
    if Value::Object(actual) != expected {
        return Err(CuaError::Unsupported);
    }
    Ok(())
}
impl CuaActionSlot {
    pub async fn call_once(self, permit: DispatchPermit) -> CuaReceipt {
        let operation = permit.id().clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let _ = tx.send(self.call_inner(permit).await);
        });
        rx.await.unwrap_or(CuaReceipt {
            operation,
            evidence: CuaEvidence::Unknown,
            result: None,
            cause: Some(CuaError::Unknown),
        })
    }
    async fn call_inner(mut self, permit: DispatchPermit) -> CuaReceipt {
        let operation = permit.id().clone();
        let refused = |cause| CuaReceipt {
            operation: operation.clone(),
            evidence: CuaEvidence::NotDispatched,
            result: None,
            cause: Some(cause),
        };
        let action: CuaAction = match serde_json::from_slice(permit.payload()) {
            Ok(v) => v,
            Err(_) => return refused(CuaError::InvalidRequest),
        };
        if let Err(e) = action.validate() {
            return refused(e);
        }
        let capability = match action.capability() {
            Ok(v) => v,
            Err(e) => return refused(e),
        };
        if let Err(e) = permit_binding(
            &permit,
            &self.resource.owner,
            &self.resource.target,
            &self.resource.session,
            capability,
        ) {
            return refused(e);
        }
        if action.mutates() && permit.context().observation.is_none() {
            return refused(CuaError::PermissionDenied);
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
        if self.live.retired || self.live.uncertain || self.resource.stop.is_cancelled() {
            return refused(CuaError::Unknown);
        }
        if self.live.actions.len() >= ACTION_RECORDS {
            return refused(CuaError::Busy);
        }
        if self.live.config.validate().is_err() {
            return refused(CuaError::PermissionDenied);
        }
        let Some(client) = self.live.client.as_ref() else {
            return refused(CuaError::ProtocolMismatch);
        };
        let peer = client.peer().clone();
        let params = CallToolRequestParams::new(action.name).with_arguments(action.arguments);
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
        let until = Instant::now() + self.live.config.rpc_timeout;
        // call_tool_once has no MRTR retry loop. From its first poll onwards a lost
        // reply is possibly executed. Cancellation is not a native stop fact.
        let response = tokio::select! {_=self.resource.stop.cancelled()=>None,result=timeout_at(until,peer.call_tool_once(params))=>Some(result)};
        let (evidence, result, cause) = match response {
            Some(Ok(Ok(CallToolResponse::Complete(value)))) => {
                if value.is_error == Some(true) || bounded_bytes(&value, FRAME_BYTES).is_err() {
                    (CuaEvidence::Unknown, None, Some(CuaError::Unknown))
                } else {
                    (CuaEvidence::Acknowledged, Some(value), None)
                }
            }
            _ => (CuaEvidence::Unknown, None, Some(CuaError::Unknown)),
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
async fn cleanup(live: &mut Live, budget: Duration) -> CuaCleanup {
    let until = Instant::now() + budget;
    if live.close_job.is_none()
        && let Some(mut client) = live.client.take()
    {
        live.close_job = Some(tokio::spawn(async move { client.close().await.is_ok() }));
    }
    // Incomplete handshakes may leave endpoints owned directly by Child, not by
    // the SDK. Drop these before stopping the original unit; never replace it.
    if let Some(child) = live.child.as_mut() {
        child.stdin.take();
        child.stdout.take();
        child.stderr.take();
    }
    let mut exited = live.exit_success.is_some();
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
    };
    if facts.worker_exited && facts.io_joined && facts.descendants_confirmed {
        live.child.take();
        live.slot.take();
        live.cleanup = Some(facts);
    } else {
        live.uncertain = true;
    }
    facts
}
// Frozen private native64 catalog projection from actual signed byte-linked
// Cua0.36 audit. It is verification only; the ten public tools remain unchanged.
const NATIVE_CATALOG: &str = r###"{"bring_to_front":{"additionalProperties":false,"properties":{"pid":{"description":"Process ID of the app to activate.","type":"integer"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session.","type":"string"},"window_id":{"description":"X11 window id (xid) to activate. If omitted, the first window of `pid` is used.","type":"integer"}},"required":["pid"],"type":"object"},"browser_click":{"additionalProperties":true,"properties":{"delivery_mode":{"default":"background","description":"background (default) refuses trusted input where it would activate the browser window, including Linux Chromium and macOS Chromium configurations whose trusted route cannot stay in the background. foreground accepts that activation, for a browser whose window nobody else is using (for example inside a sandbox).","enum":["background","foreground"],"type":"string"},"input_route":{"description":"\"trusted\" (default): Input.dispatchMouseEvent. It refuses rather than foregrounding a standalone browser. \"dom_event\": synthetic full-background DOM click, only when explicitly requested. Dispatch does not prove the control activated; refresh page state and verify the expected postcondition.","enum":["trusted","dom_event"],"type":"string"},"ref":{"description":"Page element ref in the p<snapshot>:<index> namespace from get_browser_state. Refs are invalidated by navigation and by newer snapshots of the same tab.","type":"string"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session. Browser targets, tabs, and refs belong to the resolved lifecycle session.","type":"string"},"tab_id":{"description":"Opaque tab id from get_browser_state (session-scoped).","type":"string"},"target_id":{"description":"Opaque browser target id minted by get_browser_state (session-scoped; never a CDP id).","type":"string"},"x":{"description":"Viewport x (CSS px) — alternative to ref.","type":"number"},"y":{"description":"Viewport y (CSS px) — alternative to ref.","type":"number"}},"required":["target_id","tab_id"],"type":"object"},"browser_dialog":{"additionalProperties":true,"properties":{"action":{"description":"inspect returns the current dialog and its dialog_id; accept or dismiss resolves that exact dialog.","enum":["inspect","accept","dismiss"],"type":"string"},"delivery_mode":{"default":"background","description":"Requested foreground posture for accept/dismiss. Linux Chromium requires foreground; inspect is read-only.","enum":["background","foreground"],"type":"string"},"dialog_id":{"description":"Opaque current dialog generation returned by action=inspect.","type":"string"},"prompt_text":{"description":"Sensitive response text, valid only when accepting a prompt dialog.","type":"string"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session. Browser targets, tabs, and refs belong to the resolved lifecycle session.","type":"string"},"tab_id":{"description":"Opaque tab id from get_browser_state (session-scoped).","type":"string"},"target_id":{"description":"Opaque browser target id minted by get_browser_state (session-scoped; never a CDP id).","type":"string"}},"required":["target_id","tab_id","action"],"type":"object"},"browser_download":{"additionalProperties":true,"properties":{"destination_root":{"description":"Absolute, existing, canonical directory approved to receive the download.","type":"string"},"ref":{"description":"Live page ref whose activation initiates the download.","type":"string"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. This tool requires the label that owns its browser target, tab, and refs.","type":"string"},"tab_id":{"description":"Opaque exact tab id from get_browser_state.","type":"string"},"target_id":{"description":"Opaque exact browser target id from get_browser_state.","type":"string"}},"required":["session","target_id","tab_id","ref","destination_root"],"type":"object"},"browser_navigate":{"additionalProperties":true,"properties":{"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session. Browser targets, tabs, and refs belong to the resolved lifecycle session.","type":"string"},"tab_id":{"description":"Opaque tab id from get_browser_state (session-scoped).","type":"string"},"target_id":{"description":"Opaque browser target id minted by get_browser_state (session-scoped; never a CDP id).","type":"string"},"url":{"description":"Destination URL (http:, https:, or about:).","type":"string"}},"required":["target_id","tab_id","url"],"type":"object"},"browser_pointer":{"additionalProperties":true,"properties":{"action":{"description":"Pointer gesture. scroll needs delta_x or delta_y; drag needs destination_ref or to_x/to_y.","enum":["hover","right_click","double_click","scroll","drag"],"type":"string"},"delivery_mode":{"default":"background","description":"background (default) refuses trusted input where it would activate the browser window, including Linux Chromium and macOS Chromium configurations whose trusted route cannot stay in the background. foreground accepts that activation, for a browser whose window nobody else is using (for example inside a sandbox).","enum":["background","foreground"],"type":"string"},"delta_x":{"description":"Horizontal scroll delta in CSS pixels.","type":"number"},"delta_y":{"description":"Vertical scroll delta in CSS pixels.","type":"number"},"destination_ref":{"description":"Drag destination page ref in the exact same frame.","type":"string"},"input_route":{"default":"trusted","description":"trusted sends CDP Input events; dom_event synthesizes DOM events in the page and requires ref.","enum":["trusted","dom_event"],"type":"string"},"ref":{"description":"Origin page ref. Alternative to x/y.","type":"string"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. This tool requires the label that owns its browser target, tab, and refs.","type":"string"},"tab_id":{"description":"Opaque tab id minted by get_browser_state.","type":"string"},"target_id":{"description":"Opaque target id minted by get_browser_state.","type":"string"},"to_x":{"description":"Drag destination viewport x in CSS pixels.","type":"number"},"to_y":{"description":"Drag destination viewport y in CSS pixels.","type":"number"},"x":{"description":"Origin viewport x in CSS pixels.","type":"number"},"y":{"description":"Origin viewport y in CSS pixels.","type":"number"}},"required":["target_id","tab_id","session","action"],"type":"object"},"browser_prepare":{"additionalProperties":true,"properties":{"allow_launch":{"description":"Allow a separate driver-owned isolated Chromium process to be launched (default false).","type":"boolean"},"delivery_mode":{"default":"background","description":"Existing-profile attachment only. background (default) attaches in the background when the browser window is on another Space than the user's, and otherwise refuses with background_unavailable, before any visible effect, where attaching would bring the browser in front of the user's app. foreground accepts that, for a screen nobody else is using or when the user agreed; the app that was in front is brought back afterwards.","enum":["background","foreground"],"type":"string"},"pid":{"description":"Browser process id to prepare. Required except for a driver-owned isolated_new/isolated_named launch with allow_launch=true.","type":"integer"},"profile":{"additionalProperties":false,"description":"Driver-owned isolated Chromium profile to launch with allow_launch=true. mode=isolated_new creates a fresh throwaway profile; mode=isolated_named reuses the named driver-owned profile. Never an existing user profile.","properties":{"mode":{"enum":["isolated_new","isolated_named"],"type":"string"},"name":{"description":"Required only for isolated_named; 1-64 path-safe ASCII characters.","type":"string"}},"required":["mode"],"type":"object"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session. Browser targets, tabs, and refs belong to the resolved lifecycle session.","type":"string"},"strategy":{"additionalProperties":false,"description":"Attach to an already-running browser instead of launching one. Pass an object, {\"kind\":\"existing_profile\"}, not a string. kind=existing_profile attaches to the user's running profile at pid/window_id under the runtime's profile authorization.","properties":{"kind":{"enum":["existing_profile"],"type":"string"}},"required":["kind"],"type":"object"},"window_id":{"description":"Exact native window approval anchor; required for strategy.kind=existing_profile.","type":"integer"}},"required":[],"type":"object"},"browser_set_input_files":{"additionalProperties":true,"properties":{"files":{"description":"Absolute paths of 1 to 32 local regular files to assign to the input.","items":{"description":"Absolute path to one local regular file.","type":"string"},"maxItems":32,"minItems":1,"type":"array"},"ref":{"description":"Page element ref in the p<snapshot>:<index> namespace from get_browser_state. Refs are invalidated by navigation and by newer snapshots of the same tab.","type":"string"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session. Browser targets, tabs, and refs belong to the resolved lifecycle session.","type":"string"},"tab_id":{"description":"Opaque tab id from get_browser_state (session-scoped).","type":"string"},"target_id":{"description":"Opaque browser target id minted by get_browser_state (session-scoped; never a CDP id).","type":"string"}},"required":["target_id","tab_id","ref","files"],"type":"object"},"browser_type":{"additionalProperties":true,"properties":{"mode":{"description":"insert_text (default): bulk Input.insertText. keystrokes: per-character Input.dispatchKeyEvent.","enum":["insert_text","keystrokes"],"type":"string"},"ref":{"description":"Page element ref in the p<snapshot>:<index> namespace from get_browser_state. Refs are invalidated by navigation and by newer snapshots of the same tab.","type":"string"},"replace":{"description":"false (default): insert at the caret, appending to whatever the field already holds. true: select the element's whole content first so the text replaces it — with an empty text this clears the field. Replacement goes through the selection, so beforeinput/input still fire and framework state stays consistent.","type":"boolean"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session. Browser targets, tabs, and refs belong to the resolved lifecycle session.","type":"string"},"tab_id":{"description":"Opaque tab id from get_browser_state (session-scoped).","type":"string"},"target_id":{"description":"Opaque browser target id minted by get_browser_state (session-scoped; never a CDP id).","type":"string"},"text":{"description":"Text to type.","type":"string"}},"required":["target_id","tab_id","ref","text"],"type":"object"},"check_for_update":{"additionalProperties":false,"properties":{"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session.","type":"string"}},"type":"object"},"check_permissions":{"additionalProperties":false,"properties":{"prompt":{"description":"Ignored: Linux has no permission prompts.","type":"boolean"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session.","type":"string"}},"type":"object"},"click":{"additionalProperties":false,"properties":{"button":{"description":"Mouse button. Default: \"left\" (legacy back-compat). X11: routed via ButtonPress/Release with the matching evdev code. Native Wayland: only left-button is supported via the virtual-pointer protocol; right/middle return an error.","enum":["left","right","middle"],"type":"string"},"capture_id":{"description":"Optional one-shot binding to the exact PNG returned by get_window_state or get_desktop_state. When present, x/y are interpreted in that capture and admitted before native dispatch.","type":"string"},"coordinate_frame":{"description":"Frame of x/y (and from_x/from_y/to_x/to_y). Default \"window\": window-local screenshot pixels as returned by get_window_state. \"desktop\": full-screen pixels as returned by get_desktop_state, translated to the target window. Passing scope:\"desktop\" together with pid/window_id means the same thing.","enum":["window","desktop"],"type":"string"},"count":{"description":"Number of clicks in one press train: 1 (default), 2 = double-click, 3 = triple-click (line/paragraph selection). There is no separate triple_click tool — pass count: 3 here.","minimum":1,"type":"integer"},"cursor_id":{"description":"Optional multi-cursor instance id. Default: 'default'.","type":"string"},"delivery_mode":{"default":"background","description":"Input delivery mode. 'background' (default) never activates or raises the target window. On X11 it injects via XTEST / the XInput2 master pointer (no focus steal). On Wayland it goes through libei + xdg-desktop-portal, which injects to the compositor's input focus — Wayland's security model has no per-window background targeting, so a specific non-focused window cannot be aimed at; when no libei backend is available the tool returns a structured background_unavailable error. 'foreground' is the explicit escalation: activate the target (X11 _NET_ACTIVE_WINDOW; Wayland compositor activate), inject, then restore the prior active window — a brief focus swap unless the target was already active. Matches the macOS / Windows delivery_mode surface.","enum":["background","foreground"],"type":"string"},"element_token":{"description":"Element handle `<snapshot_id>:<row>` from get_window_state: row `[11]` of a read whose snapshot_id is s0000002a is \"s0000002a:11\" (also in `structuredContent.elements[].element_token`). Returns an explicit stale error naming the current snapshots once a newer read supersedes it.","pattern":"^s[0-9a-f]{8}:[0-9]+$","type":"string"},"from_zoom":{"description":"Set true after a zoom call to auto-translate zoom-image pixel coordinates back to full-window space.","type":"boolean"},"modifier":{"description":"Modifier keys held during the action: cmd, shift, option/alt, ctrl.","items":{"type":"string"},"type":"array"},"pid":{"description":"Target process ID. Required unless scope is \"desktop\" or element_token is supplied (the token carries the pid).","type":"integer"},"scope":{"default":"window","description":"Coordinate frame (default \"window\"). Pass \"desktop\" with x,y and no pid/window_id for a screen-absolute click in get_desktop_state coordinates.","enum":["window","desktop"],"type":"string"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session.","type":"string"},"target":{"additionalProperties":true,"description":"Exact window (kind \"window\", with pid and window_id) or desktop (kind \"desktop\", with display_id). \"primary\" is the portable desktop target.","properties":{"display_id":{"description":"Display id. Required when kind is desktop; use \"primary\".","type":"string"},"kind":{"description":"window requires pid and window_id; desktop requires display_id.","enum":["window","desktop"],"type":"string"},"pid":{"description":"Process id. Required when kind is window.","minimum":0,"type":"integer"},"window_id":{"description":"Window id from list_windows. Required when kind is window.","minimum":0,"type":"integer"}},"required":["kind"],"type":"object"},"window_id":{"description":"Window id from list_windows. Required with x/y or element_index; optional with element_token (the token carries it).","type":"integer"},"x":{"description":"Window-local pixel X of the target window's own get_window_state screenshot (0..screenshot_width). For get_desktop_state pixels pass scope:\"desktop\" (or coordinate_frame:\"desktop\").","type":"number"},"y":{"description":"Window-local pixel Y of the target window's own get_window_state screenshot (0..screenshot_height); see x.","type":"number"}},"required":[],"type":"object"},"clipboard_read":{"additionalProperties":false,"properties":{"include_text":{"default":false,"description":"Return plain-text clipboard content in addition to the available types.\nClipboard content is privacy-sensitive and is never retained in telemetry.","type":"boolean"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that\naccepts it. Omit it to use the authenticated transport's implicit lifecycle session.","type":"string"}},"required":[],"type":"object"},"clipboard_write":{"additionalProperties":false,"properties":{"file_path":{"description":"Absolute path to a local file to place on the clipboard as a file URL.","type":"string"},"image_path":{"description":"Absolute path to a local image to place on the clipboard.","type":"string"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that\naccepts it. Omit it to use the authenticated transport's implicit lifecycle session.","type":"string"},"text":{"description":"Plain text to place on the clipboard.","type":"string"}},"required":[],"type":"object"},"double_click":{"additionalProperties":false,"properties":{"coordinate_frame":{"description":"Frame of x/y (and from_x/from_y/to_x/to_y). Default \"window\": window-local screenshot pixels as returned by get_window_state. \"desktop\": full-screen pixels as returned by get_desktop_state, translated to the target window. Passing scope:\"desktop\" together with pid/window_id means the same thing.","enum":["window","desktop"],"type":"string"},"cursor_id":{"description":"Optional multi-cursor instance id. Default: 'default'.","type":"string"},"delivery_mode":{"default":"background","description":"Input delivery mode. 'background' (default) never activates or raises the target window. On X11 it injects via XTEST / the XInput2 master pointer (no focus steal). On Wayland it goes through libei + xdg-desktop-portal, which injects to the compositor's input focus — Wayland's security model has no per-window background targeting, so a specific non-focused window cannot be aimed at; when no libei backend is available the tool returns a structured background_unavailable error. 'foreground' is the explicit escalation: activate the target (X11 _NET_ACTIVE_WINDOW; Wayland compositor activate), inject, then restore the prior active window — a brief focus swap unless the target was already active. Matches the macOS / Windows delivery_mode surface.","enum":["background","foreground"],"type":"string"},"element_token":{"description":"Element handle `<snapshot_id>:<row>` from get_window_state: row `[11]` of a read whose snapshot_id is s0000002a is \"s0000002a:11\" (also in `structuredContent.elements[].element_token`). Returns an explicit stale error naming the current snapshots once a newer read supersedes it.","pattern":"^s[0-9a-f]{8}:[0-9]+$","type":"string"},"from_zoom":{"description":"Set true after a zoom call to auto-translate zoom-image pixel coordinates back to full-window space.","type":"boolean"},"pid":{"description":"Target process ID. Optional with element_token (the token carries the pid).","type":"integer"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session.","type":"string"},"window_id":{"description":"Window id from list_windows. Required with x/y or element_index; optional with element_token (the token carries it).","type":"integer"},"x":{"description":"Window-local pixel X of the target window's own get_window_state screenshot (0..screenshot_width). For get_desktop_state pixels pass scope:\"desktop\" (or coordinate_frame:\"desktop\").","type":"number"},"y":{"description":"Window-local pixel Y of the target window's own get_window_state screenshot (0..screenshot_height); see x.","type":"number"}},"required":[],"type":"object"},"drag":{"additionalProperties":false,"properties":{"button":{"description":"Mouse button. Default \"left\".","enum":["left","right","middle"],"type":"string"},"coordinate_frame":{"description":"Frame of x/y (and from_x/from_y/to_x/to_y). Default \"window\": window-local screenshot pixels as returned by get_window_state. \"desktop\": full-screen pixels as returned by get_desktop_state, translated to the target window. Passing scope:\"desktop\" together with pid/window_id means the same thing.","enum":["window","desktop"],"type":"string"},"cursor_id":{"description":"Optional multi-cursor instance id. Default: 'default'.","type":"string"},"delivery_mode":{"default":"background","description":"Input delivery mode. 'background' (default) never activates or raises the target window. On X11 it injects via XTEST / the XInput2 master pointer (no focus steal). On Wayland it goes through libei + xdg-desktop-portal, which injects to the compositor's input focus — Wayland's security model has no per-window background targeting, so a specific non-focused window cannot be aimed at; when no libei backend is available the tool returns a structured background_unavailable error. 'foreground' is the explicit escalation: activate the target (X11 _NET_ACTIVE_WINDOW; Wayland compositor activate), inject, then restore the prior active window — a brief focus swap unless the target was already active. Matches the macOS / Windows delivery_mode surface.","enum":["background","foreground"],"type":"string"},"duration_ms":{"description":"Total drag duration. Default: 500.","maximum":10000,"minimum":0,"type":"integer"},"from_x":{"description":"Drag start X: window-local pixels of the target window's own get_window_state screenshot; pass scope:\"desktop\" for get_desktop_state pixels.","type":"number"},"from_y":{"description":"Drag start Y (same frame as from_x).","type":"number"},"from_zoom":{"description":"Set true after a zoom call to auto-translate zoom-image pixel coordinates back to full-window space.","type":"boolean"},"modifier":{"description":"Modifier keys held during the action: cmd, shift, option/alt, ctrl.","items":{"type":"string"},"type":"array"},"pid":{"description":"Target process ID. Required unless scope is \"desktop\".","type":"integer"},"scope":{"default":"window","description":"Use \"desktop\" with no pid/window_id for get_desktop_state screen coordinates. Default \"window\".","enum":["window","desktop"],"type":"string"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session.","type":"string"},"steps":{"description":"Intermediate MotionNotify events. Default: 20.","maximum":200,"minimum":1,"type":"integer"},"target":{"additionalProperties":true,"description":"Preferred per-call target: an exact window (`kind=\"window\"`, `pid`, `window_id`) or the\nprimary desktop (`kind=\"desktop\"`, `display_id=\"primary\"`).","properties":{"display_id":{"description":"Display id. Required when kind is desktop; use \"primary\".","type":"string"},"kind":{"description":"window requires pid and window_id; desktop requires display_id.","enum":["window","desktop"],"type":"string"},"pid":{"description":"Process id. Required when kind is window.","minimum":0,"type":"integer"},"window_id":{"description":"Window id from list_windows. Required when kind is window.","minimum":0,"type":"integer"}},"required":["kind"],"type":"object"},"to_x":{"description":"Drag end X (same frame as from_x).","type":"number"},"to_y":{"description":"Drag end Y (same frame as from_x).","type":"number"},"window_id":{"description":"Target window XID. Required.","type":"integer"}},"required":["from_x","from_y","to_x","to_y"],"type":"object"},"end_session":{"additionalProperties":true,"properties":{"session":{"description":"Optional public label to end. When omitted, end the caller's attached\nimplicit session.","type":"string"}},"required":[],"type":"object"},"escalate_session":{"additionalProperties":true,"properties":{"detail":{"description":"Optional bounded diagnostic detail. Never use secrets or page content.","maxLength":200,"type":"string"},"reason":{"description":"Why the window-scoped attempt failed and desktop capture is needed.","enum":["ax_tree_pixel_mismatch","background_delivery_failed","foreground_ineffective","no_window_target","other"],"type":"string"},"session":{"description":"Public label of the legacy capture-scope session to escalate.","type":"string"}},"required":["session","reason"],"type":"object"},"get_accessibility_tree":{"additionalProperties":false,"properties":{"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session.","type":"string"}},"type":"object"},"get_agent_cursor_state":{"additionalProperties":false,"properties":{"session":{"description":"Public label of the session whose cursor to inspect.","type":"string"}},"required":["session"],"type":"object"},"get_browser_state":{"additionalProperties":true,"properties":{"continuation":{"description":"Opaque continuation minted by an earlier semantic_v2 response.","type":"string"},"include_screenshot":{"default":false,"description":"Capture the exact tab viewport as PNG through CDP without selecting the tab or foregrounding its native window. The request refuses if capture cannot be completed.","type":"boolean"},"pid":{"description":"Native browser process id (bind mode).","type":"integer"},"query":{"description":"Read-only semantic match over role, accessible name, and visible text.","type":"string"},"scope_ref":{"description":"Current semantic/content ref whose subtree should be observed.","type":"string"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session. Browser targets, tabs, and refs belong to the resolved lifecycle session.","type":"string"},"snapshot_format":{"description":"Versioned snapshot contract. dom_refs_v1 remains the compatibility default.","enum":["dom_refs_v1","semantic_v2"],"type":"string"},"tab_id":{"description":"Opaque tab id from get_browser_state (session-scoped).","type":"string"},"target_id":{"description":"Opaque browser target id minted by get_browser_state (session-scoped; never a CDP id).","type":"string"},"window_id":{"description":"Native window id owned by pid (bind mode).","type":"integer"}},"type":"object"},"get_config":{"additionalProperties":false,"properties":{"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session.","type":"string"}},"type":"object"},"get_cursor_position":{"additionalProperties":false,"properties":{"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session.","type":"string"}},"type":"object"},"get_desktop_state":{"additionalProperties":false,"properties":{"max_image_dimension":{"description":"Optional long-edge cap for the returned PNG, in pixels (aspect ratio preserved). Omitted or 0 returns the full-size capture. When the cap downsizes the image, the response reports `screenshot_original_width/height`, and x/y read off it for this session's later scope:\"desktop\" actions (or passed with its `capture_id`) are mapped back to the full-size frame automatically.","minimum":0,"type":"integer"},"screenshot_out_file":{"description":"Write PNG here instead of base64.","type":"string"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session.","type":"string"}},"type":"object"},"get_recording_state":{"additionalProperties":false,"properties":{"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session.","type":"string"}},"type":"object"},"get_screen_size":{"additionalProperties":false,"properties":{"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session.","type":"string"}},"type":"object"},"get_session":{"additionalProperties":true,"properties":{"session":{"description":"Optional public label. When omitted, inspect the caller's attached\nimplicit session.","type":"string"}},"required":[],"type":"object"},"get_session_state":{"additionalProperties":true,"properties":{"session":{"description":"Optional public label. When omitted, inspect the caller's attached\nimplicit session.","type":"string"}},"required":[],"type":"object"},"get_window_state":{"additionalProperties":false,"properties":{"capture_mode":{"description":"DEPRECATED and ignored. get_window_state always returns BOTH the element tree and a screenshot — ground on both. The modality is chosen at action time by how you address the target: an element ax action (element_token) or an element px action (x,y). Any value (including the old \"som\"/\"screenshot\" aliases) is accepted but has no effect.","enum":["ax","vision"],"type":"string"},"display_only":{"description":"Default false. With include_accessibility_tree:false, returns pixels for display without registering an action capture or replacing the agent snapshot. The image cannot ground input actions.","type":"boolean"},"full_output":{"description":"Default false. Set true to restore the previous full response: both `elements` and `tree_markdown`, all metadata, and the platform's own walk limits unless max_elements / max_depth are passed. Does not combine with `since`.","type":"boolean"},"include_accessibility_tree":{"description":"Default true — walk the AT-SPI tree and return it (per `tree_format`) alongside the screenshot. Set false to SKIP the AT-SPI walk entirely and return just the screenshot plus window metadata (window_bounds, app_name, window_title) — the capture-only path for a live window preview / picture-in-picture. Mirrors include_screenshot. Setting BOTH include_accessibility_tree:false AND include_screenshot:false is an error (nothing to return).","type":"boolean"},"include_screenshot":{"description":"Default true — returns a grounding screenshot alongside the tree. Set false to skip the grab and return tree only (the cheap path for re-indexing before an element ax action).","type":"boolean"},"max_depth":{"description":"Cap on the AT-SPI tree walk depth. Omit for the default (uncapped). Lower for deeply nested apps.","minimum":1,"type":"integer"},"max_dimension":{"description":"Legacy optional cap on the returned screenshot's long edge. Applied on top of the configured max_image_dimension ceiling when max_image_dimension is omitted.","minimum":1,"type":"integer"},"max_elements":{"description":"Cap on total AT-SPI nodes walked. Default 250 (5 000 with full_output:true); the response states when the tree was cut. Raise it to read further into a large window.","minimum":1,"type":"integer"},"max_image_dimension":{"description":"Per-call long-edge override. This value wins over configured and legacy limits; 0 returns native-resolution PNG bytes. Omit to preserve configured behavior.","minimum":0,"type":"integer"},"pid":{"description":"Process ID that owns the window.","type":"integer"},"query":{"description":"Optional case-insensitive substring. Projects both tree_markdown and structured elements to matches plus ancestors while preserving original indices. Compare total_element_count with returned_element_count.","type":"string"},"screenshot_out_file":{"description":"When set, write the PNG to this file path (~ expanded) instead of embedding base64 in the response. The structured output carries screenshot_file_path instead.","type":"string"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session.","type":"string"},"since":{"description":"A `snapshot_id` from an earlier get_window_state of the same window, or \"latest\" for this window's most recent read with the same query/max_elements/max_depth. Use it on every re-read after acting. Returns only what changed against that snapshot: `+` added rows, `~` changed rows, `-` removed rows (removed ids are the old snapshot's), or `no change`. Falls back to a full read when the snapshot is unknown, expired, belongs to another window, or was read with a different query/max_elements/max_depth; `since_status` says which. The response still carries a NEW snapshot_id and its element_tokens; rows not listed keep their previous [N] unless a `reindexed:` line says otherwise.","type":"string"},"timeout_ms":{"default":1000,"description":"Wall-clock budget in milliseconds for the accessibility-tree walk (default 1000, min 100, max 120000). Bounds the WHOLE walk. When the budget runs out the tool returns the PARTIAL tree it has, flagged with `truncated: true`, `truncation_reason`, `nodes_visited`, `nodes_pending` and `elements_complete: false`; retry with a larger value (e.g. 5000) or narrow with `query` / `max_depth`.","maximum":120000,"minimum":100,"type":"integer"},"tree_format":{"description":"Which tree representation to return. Default \"markdown\": the compact `tree_markdown` only, where a row `[N]` is addressed with element_token `<snapshot_id>:N`. \"elements\": the structured `elements` array only (per-element element_token, frame, parent_index, value). \"both\": the two together, as before; roughly doubles the size.","enum":["markdown","elements","both"],"type":"string"},"verbose":{"description":"Default false. Set true to include the `_note` string and the full `background_input` capability report (macOS), which are omitted by default to save context.","type":"boolean"},"window_id":{"description":"Native window identifier from list_windows, or the `popup.window_id` a click / right_click result named (an open context menu / popover; its menu items then get element indices). Omitted: the pid's open popup menu when one is mapped, else its focused / active / largest window.","type":"integer"}},"required":["pid"],"type":"object"},"health_report":{"additionalProperties":false,"properties":{"include":{"description":"Only run these checks (canonical names). Wins over `skip`.","items":{"type":"string"},"type":"array"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session.","type":"string"},"skip":{"description":"Skip these checks (canonical names). Ignored when `include` is set.","items":{"type":"string"},"type":"array"}},"type":"object"},"hotkey":{"additionalProperties":false,"properties":{"delivery_mode":{"default":"background","description":"Input delivery mode. 'background' (default) never activates or raises the target window. On X11 it injects via XTEST / the XInput2 master pointer (no focus steal). On Wayland it goes through libei + xdg-desktop-portal, which injects to the compositor's input focus — Wayland's security model has no per-window background targeting, so a specific non-focused window cannot be aimed at; when no libei backend is available the tool returns a structured background_unavailable error. 'foreground' is the explicit escalation: activate the target (X11 _NET_ACTIVE_WINDOW; Wayland compositor activate), inject, then restore the prior active window — a brief focus swap unless the target was already active. Matches the macOS / Windows delivery_mode surface.","enum":["background","foreground"],"type":"string"},"element_token":{"description":"Element handle `<snapshot_id>:<row>` from get_window_state: row `[11]` of a read whose snapshot_id is s0000002a is \"s0000002a:11\" (also in `structuredContent.elements[].element_token`). Returns an explicit stale error naming the current snapshots once a newer read supersedes it.","pattern":"^s[0-9a-f]{8}:[0-9]+$","type":"string"},"keys":{"description":"Modifier(s) + one non-modifier key, e.g. [\"ctrl\",\"c\"].","items":{"type":"string"},"minItems":2,"type":"array"},"pid":{"description":"Target process ID. Omit with scope \"desktop\" to send the chord to the focused application.","type":"integer"},"scope":{"default":"window","description":"Use \"desktop\" with no pid to send the chord to the focused application. Default \"window\".","enum":["window","desktop"],"type":"string"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session.","type":"string"},"target":{"additionalProperties":true,"description":"Preferred per-call target: an exact window (`kind=\"window\"`, `pid`, `window_id`) or the\nprimary desktop (`kind=\"desktop\"`, `display_id=\"primary\"`).","properties":{"display_id":{"description":"Display id. Required when kind is desktop; use \"primary\".","type":"string"},"kind":{"description":"window requires pid and window_id; desktop requires display_id.","enum":["window","desktop"],"type":"string"},"pid":{"description":"Process id. Required when kind is window.","minimum":0,"type":"integer"},"window_id":{"description":"Window id from list_windows. Required when kind is window.","minimum":0,"type":"integer"}},"required":["kind"],"type":"object"},"window_id":{"description":"Window id from list_windows. Required with x/y or element_index; optional with element_token (the token carries it).","type":"integer"},"x":{"description":"Screenshot-pixel X — the element px action form: pixel-click there to focus, then send the combo (so e.g. Ctrl+V pastes into that field). Pass with y. Use for Chromium/Electron surfaces the background combo can't reach.","type":"number"},"y":{"description":"Screenshot-pixel Y (see x).","type":"number"}},"required":["keys"],"type":"object"},"install_extension":{"additionalProperties":false,"properties":{"confirm":{"description":"Install the previewed extension. Omit or false for a read-only plan.","type":"boolean"},"name":{"description":"Extension to preview or install. Only perception (the local visual-region parser used by parse_visual_regions) is available.","enum":["perception"],"type":"string"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session.","type":"string"}},"required":["name"],"type":"object"},"install_ffmpeg":{"additionalProperties":false,"properties":{"confirm":{"description":"Run the install command. Without it, only the planned command is reported.","type":"boolean"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session.","type":"string"}},"type":"object"},"invoke_menu":{"additionalProperties":false,"description":"Exact, immediate-child application menu path to resolve and invoke through\nthe operating system's accessibility API. Path labels are matched after\ntrimming surrounding whitespace and otherwise remain case-sensitive. On\nmacOS, three periods in a label also match the ellipsis character that\nnative menu titles use (`Save As...` finds `Save As…`).","properties":{"path":{"description":"Menu labels from the top-level menu to the item, e.g. `[\"File\", \"Save As...\"]`\n(1 to 16 labels).","items":{"maxLength":200,"minLength":1,"type":"string"},"maxItems":16,"minItems":1,"type":"array"},"pid":{"description":"Process ID of the application that owns the menu.","minimum":1,"type":"integer"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that\naccepts it. Omit it to use the authenticated transport's implicit lifecycle session.","type":"string"},"window_id":{"description":"Window ID from list_windows whose menu is invoked.","minimum":1,"type":"integer"}},"required":["pid","window_id","path"],"type":"object"},"kill_app":{"additionalProperties":false,"properties":{"pid":{"description":"PID of the process to terminate.","type":"integer"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session.","type":"string"}},"required":["pid"],"type":"object"},"launch_app":{"additionalProperties":false,"properties":{"additional_arguments":{"description":"Extra command-line arguments passed to the launched process.","items":{"type":"string"},"type":"array"},"bundle_id":{"description":"Ignored on Linux (macOS/Windows concept).","type":"string"},"launch_path":{"description":"Round-trip the `launch_path` returned by `list_apps` — the Exec= command from the .desktop file with XDG field codes already stripped. Highest precedence on Linux; spawned directly via the system shell.","type":"string"},"name":{"description":"App name or command to launch. Tried as a direct command first, then matched against installed .desktop applications (exact display name, desktop-file id, or Exec basename; else an unambiguous display-name substring).","type":"string"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session.","type":"string"},"urls":{"description":"URLs to open via xdg-open.","items":{"type":"string"},"type":"array"}},"type":"object"},"list_apps":{"additionalProperties":false,"properties":{"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session.","type":"string"}},"type":"object"},"list_sessions":{"additionalProperties":true,"properties":{"cursor":{"description":"Opaque continuation cursor returned by a previous call.","type":"string"},"limit":{"description":"Maximum number of content-free summaries to return (default 50, max\n100). Ordinary agent transports are scoped to their own lease.","minimum":0,"type":"integer"}},"required":[],"type":"object"},"list_windows":{"additionalProperties":false,"properties":{"app":{"description":"Only windows of apps whose name contains this text (case-insensitive), or whose bundle id equals it. Prefer this or `pid` over an unfiltered call, which returns every window on the host.","type":"string"},"on_screen_only":{"description":"When true, filter to visible windows only. Default false.","type":"boolean"},"pid":{"description":"Only list windows owned by this process ID.","type":"integer"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session.","type":"string"}},"type":"object"},"mouse_button_down":{"additionalProperties":false,"properties":{"button":{"description":"Mouse button. Default \"left\".","enum":["left","right","middle"],"type":"string"},"coordinate_frame":{"description":"Frame of x/y (and from_x/from_y/to_x/to_y). Default \"window\": window-local screenshot pixels as returned by get_window_state. \"desktop\": full-screen pixels as returned by get_desktop_state, translated to the target window. Passing scope:\"desktop\" together with pid/window_id means the same thing.","enum":["window","desktop"],"type":"string"},"cursor_id":{"description":"Optional multi-cursor instance id. Default: 'default'.","type":"string"},"from_zoom":{"description":"Set true after a zoom call to auto-translate zoom-image pixel coordinates back to full-window space.","type":"boolean"},"pid":{"description":"Target process ID.","type":"integer"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session. When both are present, session takes precedence over cursor_id.","type":"string"},"window_id":{"description":"Window id from list_windows.","type":"integer"},"x":{"description":"Window-local pixel X of the target window's own get_window_state screenshot (0..screenshot_width). For get_desktop_state pixels pass scope:\"desktop\" (or coordinate_frame:\"desktop\").","type":"number"},"y":{"description":"Window-local pixel Y of the target window's own get_window_state screenshot (0..screenshot_height); see x.","type":"number"}},"required":["pid","window_id","x","y"],"type":"object"},"mouse_button_up":{"additionalProperties":false,"properties":{"coordinate_frame":{"description":"Frame of x/y (and from_x/from_y/to_x/to_y). Default \"window\": window-local screenshot pixels as returned by get_window_state. \"desktop\": full-screen pixels as returned by get_desktop_state, translated to the target window. Passing scope:\"desktop\" together with pid/window_id means the same thing.","enum":["window","desktop"],"type":"string"},"cursor_id":{"description":"Optional multi-cursor instance id. Default: 'default'.","type":"string"},"from_zoom":{"description":"Set true after a zoom call to auto-translate zoom-image pixel coordinates back to full-window space.","type":"boolean"},"pid":{"description":"Optional process ID; must match the held button's target.","type":"integer"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session. When both are present, session takes precedence over cursor_id.","type":"string"},"window_id":{"description":"Optional window id; must match the held button's target.","type":"integer"},"x":{"description":"Window-local pixel X of the target window's own get_window_state screenshot (0..screenshot_width). For get_desktop_state pixels pass scope:\"desktop\" (or coordinate_frame:\"desktop\").","type":"number"},"y":{"description":"Window-local pixel Y of the target window's own get_window_state screenshot (0..screenshot_height); see x.","type":"number"}},"type":"object"},"mouse_drag":{"additionalProperties":false,"properties":{"cursor_id":{"description":"Optional multi-cursor instance id. Default: 'default'.","type":"string"},"duration_ms":{"description":"Total drag duration. Default: 500.","maximum":10000,"minimum":0,"type":"integer"},"from_zoom":{"description":"Set true after a zoom call to auto-translate zoom-image pixel coordinates back to full-window space.","type":"boolean"},"pid":{"description":"Optional process ID; must match the held button's target.","type":"integer"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session. When both are present, session takes precedence over cursor_id.","type":"string"},"steps":{"description":"Intermediate MotionNotify events. Default: 20.","maximum":200,"minimum":1,"type":"integer"},"window_id":{"description":"Optional window id; must match the held button's target.","type":"integer"},"x":{"description":"Window-local pixel X of the target window's own get_window_state screenshot (0..screenshot_width). For get_desktop_state pixels pass scope:\"desktop\" (or coordinate_frame:\"desktop\").","type":"number"},"y":{"description":"Window-local pixel Y of the target window's own get_window_state screenshot (0..screenshot_height); see x.","type":"number"}},"required":["x","y"],"type":"object"},"move_cursor":{"additionalProperties":false,"properties":{"cursor_id":{"description":"Cursor instance to move. Default: 'default'.","type":"string"},"scope":{"default":"window","description":"\"window\" (default) moves only the agent cursor overlay; \"desktop\" moves the real OS pointer.","enum":["window","desktop"],"type":"string"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session.","type":"string"},"target":{"additionalProperties":true,"description":"Preferred per-call target: an exact window (`kind=\"window\"`, `pid`, `window_id`) or the\nprimary desktop (`kind=\"desktop\"`, `display_id=\"primary\"`).","properties":{"display_id":{"description":"Display id. Required when kind is desktop; use \"primary\".","type":"string"},"kind":{"description":"window requires pid and window_id; desktop requires display_id.","enum":["window","desktop"],"type":"string"},"pid":{"description":"Process id. Required when kind is window.","minimum":0,"type":"integer"},"window_id":{"description":"Window id from list_windows. Required when kind is window.","minimum":0,"type":"integer"}},"required":["kind"],"type":"object"},"x":{"description":"Destination X. Window scope: screen coordinates of the agent cursor overlay. Desktop scope: get_desktop_state screenshot pixels.","type":"number"},"y":{"description":"Destination Y, in the same space as x.","type":"number"}},"required":["x","y"],"type":"object"},"page":{"additionalProperties":false,"properties":{"action":{"description":"Action to perform.","enum":["execute_javascript","get_text","query_dom","click_element","insert_text","type_keystrokes","enable_javascript_apple_events"],"type":"string"},"attributes":{"description":"Element attributes to include in query_dom results.","items":{"type":"string"},"type":"array"},"bundle_id":{"description":"Bundle ID of the browser. Required for enable_javascript_apple_events (macOS only).","type":"string"},"cdp_port":{"description":"Optional, for execute_javascript/insert_text/type_keystrokes: use this exact CDP port instead of auto-discovering one from pid. Needed when the port was opened via the browser's own remote-debugging toggle rather than a launch-time flag, since that path may not answer the auto-discovery probe.","maximum":65535,"minimum":1,"type":"integer"},"css_selector":{"description":"CSS selector for query_dom (e.g. 'a', 'button', 'input', 'h1'-'h6', 'p', 'img', 'select', '*').","type":"string"},"javascript":{"description":"JavaScript to execute. Required for execute_javascript.","type":"string"},"pid":{"description":"Target process ID.","type":"integer"},"selector":{"description":"CSS selector for click_element (e.g. 'button.submit', '#login a').","type":"string"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session.","type":"string"},"target_url_contains":{"description":"Optional, for execute_javascript/insert_text/type_keystrokes: require exactly one browser tab whose URL contains this substring. Use this on a multi-tab browser — there's no built-in link between window_id and which tab a CDP call reaches.","type":"string"},"text":{"description":"Text to insert or type. Required for insert_text and type_keystrokes. The target field must already have DOM focus (click/focus it first).","type":"string"},"user_has_confirmed_enabling":{"description":"Must be true to proceed with enable_javascript_apple_events. This will quit and relaunch the browser.","type":"boolean"},"window_id":{"description":"Target window ID from list_windows.","type":"integer"}},"required":["action"],"type":"object"},"parallel_mouse_drag":{"additionalProperties":false,"properties":{"drags":{"description":"Two or more drag gestures to run concurrently, each on its own virtual master pointer.","items":{"additionalProperties":false,"properties":{"button":{"description":"Mouse button. Default \"left\".","enum":["left","right","middle"],"type":"string"},"duration_ms":{"description":"Default: 1500 for fn paths, 500 for straight.","maximum":10000,"minimum":0,"type":"integer"},"fn":{"description":"Expression y(x) in window-local pixels; sampled over [x_from,x_to]. Mutually exclusive with from_x/to_x.","type":"string"},"from_x":{"description":"Straight-segment start X (window-local pixels).","type":"number"},"from_y":{"description":"Straight-segment start Y (window-local pixels).","type":"number"},"path":{"description":"Explicit window-local waypoints [[x,y],...] (>=2); pressed once, glided through, released once. Takes precedence over fn/from-to.","items":{"items":{"type":"number"},"type":"array"},"type":"array"},"samples":{"description":"Waypoints sampled along `fn`. Default: 80.","maximum":400,"minimum":2,"type":"integer"},"session":{"description":"Session/cursor id; also keys the virtual master pointer.","type":"string"},"steps":{"description":"Motion sub-steps along the whole path. Default: scaled to path length.","maximum":300,"minimum":1,"type":"integer"},"to_x":{"description":"Straight-segment end X (window-local pixels).","type":"number"},"to_y":{"description":"Straight-segment end Y (window-local pixels).","type":"number"},"window_id":{"description":"Window id from list_windows.","type":"integer"},"x_from":{"description":"Domain start (window-local x) when `fn` is used.","type":"number"},"x_to":{"description":"Domain end (window-local x) when `fn` is used.","type":"number"}},"required":["session","window_id"],"type":"object"},"minItems":2,"type":"array"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session.","type":"string"}},"required":["drags"],"type":"object"},"parse_visual_regions":{"additionalProperties":false,"description":"Parse one immutable screenshot capture. Pass the `capture_id` returned by\n`get_window_state` or `get_desktop_state`; the Driver capture registry\nresolves it to the exact pixels and action-coordinate transform.","properties":{"capture_id":{"description":"`capture_id` of a screenshot returned by get_window_state or get_desktop_state.","minLength":1,"type":"string"},"options":{"additionalProperties":false,"default":{},"description":"Optional, model-neutral controls for one bounded parse.","properties":{"kinds":{"description":"Region kinds to return (`text`, `icon`). Omit for all kinds.","items":{"enum":["text","icon"],"type":"string"},"maxItems":2,"minItems":1,"type":"array"},"max_regions":{"description":"Return at most this many regions.","minimum":1,"type":"integer"},"min_confidence":{"description":"Drop regions below this confidence (0 to 1).","maximum":1,"minimum":0,"type":"number"}},"required":[],"type":"object"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session.","type":"string"}},"required":["capture_id"],"type":"object"},"press_key":{"additionalProperties":false,"properties":{"coordinate_frame":{"description":"Frame of x/y (and from_x/from_y/to_x/to_y). Default \"window\": window-local screenshot pixels as returned by get_window_state. \"desktop\": full-screen pixels as returned by get_desktop_state, translated to the target window. Passing scope:\"desktop\" together with pid/window_id means the same thing.","enum":["window","desktop"],"type":"string"},"delivery_mode":{"default":"background","description":"Input delivery mode. 'background' (default) never activates or raises the target window. On X11 it injects via XTEST / the XInput2 master pointer (no focus steal). On Wayland it goes through libei + xdg-desktop-portal, which injects to the compositor's input focus — Wayland's security model has no per-window background targeting, so a specific non-focused window cannot be aimed at; when no libei backend is available the tool returns a structured background_unavailable error. 'foreground' is the explicit escalation: activate the target (X11 _NET_ACTIVE_WINDOW; Wayland compositor activate), inject, then restore the prior active window — a brief focus swap unless the target was already active. Matches the macOS / Windows delivery_mode surface.","enum":["background","foreground"],"type":"string"},"element_token":{"description":"Element handle `<snapshot_id>:<row>` from get_window_state: row `[11]` of a read whose snapshot_id is s0000002a is \"s0000002a:11\" (also in `structuredContent.elements[].element_token`). Returns an explicit stale error naming the current snapshots once a newer read supersedes it.","pattern":"^s[0-9a-f]{8}:[0-9]+$","type":"string"},"key":{"description":"Key name: enter/return, tab, escape, space, backspace, delete, insert, home, end, pageup, pagedown, up, down, left, right, f1-f12, or any single ASCII character.","type":"string"},"modifiers":{"description":"Modifier keys held while the key is pressed: ctrl, shift, alt, super.","items":{"type":"string"},"type":"array"},"pid":{"description":"Target process ID. Omit with scope \"desktop\" to send the key to the focused application.","type":"integer"},"scope":{"default":"window","description":"Use \"desktop\" with no pid to send the key to the focused application. Default \"window\".","enum":["window","desktop"],"type":"string"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session.","type":"string"},"target":{"additionalProperties":true,"description":"Preferred per-call target: an exact window (`kind=\"window\"`, `pid`, `window_id`) or the\nprimary desktop (`kind=\"desktop\"`, `display_id=\"primary\"`).","properties":{"display_id":{"description":"Display id. Required when kind is desktop; use \"primary\".","type":"string"},"kind":{"description":"window requires pid and window_id; desktop requires display_id.","enum":["window","desktop"],"type":"string"},"pid":{"description":"Process id. Required when kind is window.","minimum":0,"type":"integer"},"window_id":{"description":"Window id from list_windows. Required when kind is window.","minimum":0,"type":"integer"}},"required":["kind"],"type":"object"},"window_id":{"description":"Window id from list_windows. Required with x/y or element_index; optional with element_token (the token carries it).","type":"integer"},"x":{"description":"Pixel X — the element px action form: pixel-click there to focus, then send the key. Use when the key must go to a Chromium/Electron surface the AX path can't focus. Pass with y, no element_token. Window-local pixels by default (same convention as click); for get_desktop_state pixels pass scope:\"desktop\" (or coordinate_frame:\"desktop\").","type":"number"},"y":{"description":"Pixel Y (see x).","type":"number"}},"required":["key"],"type":"object"},"replay_trajectory":{"additionalProperties":false,"properties":{"delay_ms":{"description":"Milliseconds to sleep between turns, for human-observable pacing. Default 500.","maximum":10000,"minimum":0,"type":"integer"},"dir":{"description":"Trajectory directory previously written by `start_recording`. Absolute or ~-rooted.","type":"string"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session.","type":"string"},"stop_on_error":{"description":"Stop replay on the first tool-call error. Default true — set false to best-effort through the full trajectory.","type":"boolean"}},"required":["dir"],"type":"object"},"right_click":{"additionalProperties":false,"properties":{"coordinate_frame":{"description":"Frame of x/y (and from_x/from_y/to_x/to_y). Default \"window\": window-local screenshot pixels as returned by get_window_state. \"desktop\": full-screen pixels as returned by get_desktop_state, translated to the target window. Passing scope:\"desktop\" together with pid/window_id means the same thing.","enum":["window","desktop"],"type":"string"},"cursor_id":{"description":"Optional multi-cursor instance id. Default: 'default'.","type":"string"},"delivery_mode":{"default":"background","description":"Input delivery mode. 'background' (default) never activates or raises the target window. On X11 it injects via XTEST / the XInput2 master pointer (no focus steal). On Wayland it goes through libei + xdg-desktop-portal, which injects to the compositor's input focus — Wayland's security model has no per-window background targeting, so a specific non-focused window cannot be aimed at; when no libei backend is available the tool returns a structured background_unavailable error. 'foreground' is the explicit escalation: activate the target (X11 _NET_ACTIVE_WINDOW; Wayland compositor activate), inject, then restore the prior active window — a brief focus swap unless the target was already active. Matches the macOS / Windows delivery_mode surface.","enum":["background","foreground"],"type":"string"},"element_token":{"description":"Element handle `<snapshot_id>:<row>` from get_window_state: row `[11]` of a read whose snapshot_id is s0000002a is \"s0000002a:11\" (also in `structuredContent.elements[].element_token`). Returns an explicit stale error naming the current snapshots once a newer read supersedes it.","pattern":"^s[0-9a-f]{8}:[0-9]+$","type":"string"},"from_zoom":{"description":"Set true after a zoom call to auto-translate zoom-image pixel coordinates back to full-window space.","type":"boolean"},"modifier":{"description":"Modifier keys held during the action: cmd, shift, option/alt, ctrl.","items":{"type":"string"},"type":"array"},"pid":{"description":"Target process ID. Optional with element_token (the token carries the pid).","type":"integer"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session.","type":"string"},"window_id":{"description":"Window id from list_windows. Required with x/y or element_index; optional with element_token (the token carries it).","type":"integer"},"x":{"description":"Window-local pixel X of the target window's own get_window_state screenshot (0..screenshot_width). For get_desktop_state pixels pass scope:\"desktop\" (or coordinate_frame:\"desktop\").","type":"number"},"y":{"description":"Window-local pixel Y of the target window's own get_window_state screenshot (0..screenshot_height); see x.","type":"number"}},"required":[],"type":"object"},"run_script":{"additionalProperties":false,"properties":{"max_calls":{"description":"Most driver calls the script may make. Default 100.","maximum":500,"minimum":1,"type":"integer"},"script":{"description":"JavaScript: the body of an async function. `return` the result.","maxLength":65536,"minLength":1,"type":"string"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session.","type":"string"},"timeout_ms":{"description":"Wall-time limit. Default 30000.","maximum":120000,"minimum":100,"type":"integer"}},"required":["script"],"type":"object"},"run_steps":{"additionalProperties":false,"properties":{"app":{"description":"Default app (name or bundle id) for steps that name no window.","type":"string"},"delay_ms":{"description":"Pause between steps in milliseconds (not after the last). Default 0.","maximum":2000,"minimum":0,"type":"integer"},"delivery_mode":{"description":"Default delivery_mode for steps whose tool takes one and that set none.","enum":["background","foreground"],"type":"string"},"foreground_fallback":{"description":"When a step is refused because its target ignores background input (Electron, LibreOffice and other toolkits), retry it once with delivery_mode:\"foreground\": the window is activated and the pointer may move. Default false.","type":"boolean"},"observe":{"description":"Optional end-of-batch observation: arguments for ONE get_window_state call. `pid` and `window_id` default to those of the last step that names both. Defaults to since=\"latest\" (only what changed since your last read of that window with the same query/max_elements/max_depth; a full read when there is none), include_screenshot=false and max_elements=250; pass include_screenshot=true to see the window, or since=null for a full read. Omit to read nothing. {} observes the last window.","type":"object"},"pid":{"description":"Default pid for steps that name no window (a step's own pid/window_id/app/window wins).","type":"integer"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session.","type":"string"},"steps":{"description":"Ordered actions. Execution stops at the first failing step. Each step is {tool, args} or {<tool>: args}, plus optional wait_for / expect / timeout_ms; a step may also be only a wait_for or expect check.","items":{"additionalProperties":true,"properties":{"args":{"description":"Arguments for that tool, as in a direct call, optionally with role/name/nth/app/window to name the target instead of pid/window_id/element_token.","type":"object"},"expect":{"description":"Up to 4 checks that must hold after the action: {role?, name?, text?, gone?, value?, value_contains?, enabled?, selected?, app?, window?, timeout_ms?}. Default timeout 2000 ms.","items":{"type":"object"},"maxItems":4,"type":"array"},"timeout_ms":{"description":"How long a named target may take to appear. Default 3000.","maximum":10000,"minimum":0,"type":"integer"},"tool":{"description":"Action tool to run.","enum":["click","double_click","right_click","set_value","type_text","press_key","hotkey","scroll","drag","move_cursor"],"type":"string"},"wait_for":{"description":"Check that must hold before the action: {role?, name?, text?, gone?, app?, window?, timeout_ms?}. Default timeout 5000 ms.","type":"object"}},"type":"object"},"maxItems":64,"minItems":1,"type":"array"},"window":{"description":"Default window title substring for steps that name no window.","type":"string"},"window_id":{"description":"Default window_id for steps that name no window, with `pid`.","type":"integer"}},"required":["steps"],"type":"object"},"scroll":{"additionalProperties":false,"properties":{"amount":{"description":"Number of scroll steps. Default: 3.","maximum":50,"minimum":1,"type":"integer"},"by":{"description":"Scroll granularity. Default: line.","enum":["line","page"],"type":"string"},"coordinate_frame":{"description":"Frame of x/y (and from_x/from_y/to_x/to_y). Default \"window\": window-local screenshot pixels as returned by get_window_state. \"desktop\": full-screen pixels as returned by get_desktop_state, translated to the target window. Passing scope:\"desktop\" together with pid/window_id means the same thing.","enum":["window","desktop"],"type":"string"},"cursor_id":{"description":"Optional multi-cursor instance id. Default: 'default'.","type":"string"},"delivery_mode":{"default":"background","description":"Input delivery mode. 'background' (default) never activates or raises the target window. On X11 it injects via XTEST / the XInput2 master pointer (no focus steal). On Wayland it goes through libei + xdg-desktop-portal, which injects to the compositor's input focus — Wayland's security model has no per-window background targeting, so a specific non-focused window cannot be aimed at; when no libei backend is available the tool returns a structured background_unavailable error. 'foreground' is the explicit escalation: activate the target (X11 _NET_ACTIVE_WINDOW; Wayland compositor activate), inject, then restore the prior active window — a brief focus swap unless the target was already active. Matches the macOS / Windows delivery_mode surface.","enum":["background","foreground"],"type":"string"},"direction":{"description":"Scroll direction.","enum":["up","down","left","right"],"type":"string"},"element_token":{"description":"Element handle `<snapshot_id>:<row>` from get_window_state: row `[11]` of a read whose snapshot_id is s0000002a is \"s0000002a:11\" (also in `structuredContent.elements[].element_token`). Returns an explicit stale error naming the current snapshots once a newer read supersedes it.","pattern":"^s[0-9a-f]{8}:[0-9]+$","type":"string"},"pid":{"description":"Target process ID. Required unless scope is \"desktop\" or element_token is supplied (the token carries the pid).","type":"integer"},"scope":{"default":"window","description":"Use \"desktop\" with x,y and no pid/window_id for get_desktop_state screen coordinates. Default \"window\".","enum":["window","desktop"],"type":"string"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session.","type":"string"},"target":{"additionalProperties":true,"description":"Preferred per-call target: an exact window (`kind=\"window\"`, `pid`, `window_id`) or the\nprimary desktop (`kind=\"desktop\"`, `display_id=\"primary\"`).","properties":{"display_id":{"description":"Display id. Required when kind is desktop; use \"primary\".","type":"string"},"kind":{"description":"window requires pid and window_id; desktop requires display_id.","enum":["window","desktop"],"type":"string"},"pid":{"description":"Process id. Required when kind is window.","minimum":0,"type":"integer"},"window_id":{"description":"Window id from list_windows. Required when kind is window.","minimum":0,"type":"integer"}},"required":["kind"],"type":"object"},"window_id":{"description":"Window id from list_windows. Required with x/y; optional with element_token (the token carries it).","type":"integer"},"x":{"description":"Window-local screenshot-pixel X of the scroll target. Pass with y and without element_token.","type":"number"},"y":{"description":"Window-local screenshot-pixel Y of the scroll target. Pass with x and without element_token.","type":"number"}},"required":["direction"],"type":"object"},"set_agent_cursor_enabled":{"additionalProperties":false,"properties":{"enabled":{"description":"`true` shows the session's agent cursor overlay; `false` hides it.","type":"boolean"},"session":{"description":"Public label of the session that owns the cursor.","type":"string"}},"required":["session","enabled"],"type":"object"},"set_agent_cursor_motion":{"additionalProperties":false,"properties":{"arc_flow":{"description":"Added to the arc asymmetry of `signature_arc`, `spring_settle` and `comet_swoop`:\npositive moves the apex toward the destination. Clamped to -1..1 (default 0).","type":"number"},"arc_size":{"description":"Scales the arc of `signature_arc`, `spring_settle` and `comet_swoop`: 0.25 (default)\nkeeps the style's arc, 0 is a straight line, 0.5 doubles it. Clamped to 0..1.","type":"number"},"dwell_after_click_ms":{"description":"Pause after a click animation, in milliseconds. Clamped to 0..5000 (default 80).","type":"number"},"effects":{"additionalProperties":false,"description":"Turn effects on or off. Omit a field to keep it; `\"default\"` restores the style default.","properties":{"glow":{"description":"Soft glow around the cursor that grows with speed.","enum":["on","off","default"],"type":"string"},"magnet":{"description":"Target glow when the `magnetic` style locks on.","enum":["on","off","default"],"type":"string"},"ripple":{"description":"Ring that expands from the hotspot on click.","enum":["on","off","default"],"type":"string"},"squish":{"description":"Brief scale-down of the cursor on click.","enum":["on","off","default"],"type":"string"},"trail":{"description":"Short fading trail behind the cursor.","enum":["on","off","default"],"type":"string"}},"required":[],"type":"object"},"end_handle":{"description":"Arc control-point offset from the end, as a fraction of the distance, for\n`signature_arc`, `spring_settle` and `comet_swoop`. Clamped to 0..1 (default 0.3).","type":"number"},"glide_duration_ms":{"description":"Move duration in milliseconds for `fixed` timing (1430 ms when 0, the default). A\nnonzero value with `native` or the default `steady` timing also fixes the duration.\nClamped to 0..5000.","type":"number"},"idle_hide_ms":{"description":"Hide the cursor after this many idle milliseconds; 0 never hides it. Clamped to\n0..60000 (default 15000).","type":"number"},"session":{"description":"Public label of the session that owns the cursor. Omitted or null motion fields keep\ntheir current value.","type":"string"},"spring":{"description":"Arrival spring damping for `classic`: 1 is critically damped, 0.3 is bouncy. Clamped\nto 0.3..1 (default 0.72).","type":"number"},"start_handle":{"description":"Arc control-point offset from the start, as a fraction of the distance, for\n`signature_arc`, `spring_settle` and `comet_swoop`. Clamped to 0..1 (default 0.3).","type":"number"},"style":{"description":"Trajectory style. `signature_arc` (default) is one arc with a small follow-through;\n`spring_settle` lands with one soft bounce; `magnetic` is pulled into the target;\n`comet_swoop` is a wide arc with a short trail; `adaptive` picks a careful approach for\nsmall targets and a swoop for long moves; `classic` is the previous Dubins glide. When\nthe theme's reduced motion is on, every move is a short straight glide with no effects.","enum":["signature_arc","spring_settle","magnetic","comet_swoop","adaptive","classic"],"type":"string"},"timing":{"description":"`steady` (default) keeps the style's timing but makes every move take at least 600 ms,\nwith a gentler ease; `relaxed` and `calm` do the same with a 450 or 750 ms floor.\n`native` uses the style's own timing; `fitts` scales the move time with distance and\ntarget size; `deliberate` is a slower Fitts curve (450..1300 ms); `fixed` uses\nglide_duration_ms (1430 ms when 0).","enum":["native","fitts","fixed","relaxed","steady","calm","deliberate"],"type":"string"},"turn_radius":{"description":"Minimum turning radius of the `classic` glide path, in points; smaller turns tighter.\nClamped to 1..1000 (default 80).","type":"number"}},"required":["session"],"type":"object"},"set_agent_cursor_theme":{"additionalProperties":false,"properties":{"reduced_motion":{"default":"auto","description":"Theme animation policy: `on` uses the theme's reduced-motion frames, `off` always\nanimates, `auto` (default) leaves the choice to the host.","enum":["auto","on","off"],"type":"string"},"session":{"description":"Public label of the session that owns the cursor.","type":"string"},"theme_id":{"description":"Id of an installed cursor theme (see `cua-driver cursor-theme list`).","maxLength":200,"minLength":1,"type":"string"}},"required":["session","theme_id"],"type":"object"},"set_config":{"additionalProperties":false,"properties":{"capture_mode":{"description":"Default capture mode for get_window_state. (\"som\"/\"screenshot\" still decode as deprecated aliases.)","enum":["ax","vision"],"type":"string"},"cursor.badges":{"description":"Agent cursor badge. minimal (default): no badge at rest; a brief chip for a foreground moment or a key combo, and the session name on hover or when two or more agent cursors are on screen. verbose: the earlier badge with the session name and delivery/target chips on every action. off: no badge. Applies immediately to every cursor.","enum":["minimal","verbose","off","default"],"type":"string"},"cursor.motion":{"description":"Pass `default` to clear every saved cursor motion default.","enum":["default"],"type":"string"},"cursor.motion.effects.glow":{"description":"Saved default for the `glow` cursor effect: on, off, or default (the style's own). Omit the key to leave it unchanged.","enum":["on","off","default"],"type":"string"},"cursor.motion.effects.magnet":{"description":"Saved default for the `magnet` cursor effect: on, off, or default (the style's own). Omit the key to leave it unchanged.","enum":["on","off","default"],"type":"string"},"cursor.motion.effects.ripple":{"description":"Saved default for the `ripple` cursor effect: on, off, or default (the style's own). Omit the key to leave it unchanged.","enum":["on","off","default"],"type":"string"},"cursor.motion.effects.squish":{"description":"Saved default for the `squish` cursor effect: on, off, or default (the style's own). Omit the key to leave it unchanged.","enum":["on","off","default"],"type":"string"},"cursor.motion.effects.trail":{"description":"Saved default for the `trail` cursor effect: on, off, or default (the style's own). Omit the key to leave it unchanged.","enum":["on","off","default"],"type":"string"},"cursor.motion.style":{"description":"Saved default cursor motion style for new sessions. Overridden by start_session cursor_motion and set_agent_cursor_motion; reduced motion always wins. Built-in default: signature_arc.","enum":["signature_arc","spring_settle","magnetic","comet_swoop","adaptive","classic"],"type":"string"},"cursor.motion.timing":{"description":"Saved default cursor move timing for new sessions. Built-in default: steady (a 600 ms floor on every move).","enum":["native","fitts","fixed","relaxed","steady","calm","deliberate"],"type":"string"},"experimental_pip":{"description":"Enable the experimental PiP preview window (applies next restart; Linux backend stubbed).","type":"boolean"},"experimental_pip_geometry":{"description":"PiP window size + optional position in `WxH` or `WxH+X+Y` form.","type":"string"},"max_image_dimension":{"description":"Max dimension for screenshot resizing (0 = no limit).","type":"integer"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session.","type":"string"}},"type":"object"},"set_value":{"additionalProperties":false,"properties":{"delivery_mode":{"default":"background","description":"Input delivery mode. 'background' (default) never activates or raises the target window. On X11 it injects via XTEST / the XInput2 master pointer (no focus steal). On Wayland it goes through libei + xdg-desktop-portal, which injects to the compositor's input focus — Wayland's security model has no per-window background targeting, so a specific non-focused window cannot be aimed at; when no libei backend is available the tool returns a structured background_unavailable error. 'foreground' is the explicit escalation: activate the target (X11 _NET_ACTIVE_WINDOW; Wayland compositor activate), inject, then restore the prior active window — a brief focus swap unless the target was already active. Matches the macOS / Windows delivery_mode surface.","enum":["background","foreground"],"type":"string"},"element_token":{"description":"Element handle `<snapshot_id>:<row>` from get_window_state: row `[11]` of a read whose snapshot_id is s0000002a is \"s0000002a:11\" (also in `structuredContent.elements[].element_token`). Returns an explicit stale error naming the current snapshots once a newer read supersedes it.","pattern":"^s[0-9a-f]{8}:[0-9]+$","type":"string"},"pid":{"description":"Target process ID. Optional with element_token (the token carries the pid).","type":"integer"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session.","type":"string"},"value":{"description":"New value. Written through AT-SPI EditableText/Value when the element exposes them; otherwise (GTK2 spin scales, VCL spin buttons) the field is clicked with the session's real pointer, its text selected and replaced through the virtual keyboard and committed with Tab, then read back.","type":"string"},"window_id":{"description":"Omit when element_token is supplied (the token carries it).","type":"integer"}},"required":["value"],"type":"object"},"set_window_frame":{"additionalProperties":false,"properties":{"height":{"description":"New height, in the same units as list_windows bounds.","minimum":1,"type":"number"},"pid":{"description":"Process ID that owns the window.","minimum":1,"type":"integer"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that\naccepts it. Omit it to use the authenticated transport's implicit lifecycle session.","type":"string"},"width":{"description":"New width, in the same units as list_windows bounds.","minimum":1,"type":"number"},"window_id":{"description":"Window ID from list_windows.","minimum":1,"type":"integer"},"x":{"description":"New left edge in the desktop coordinate space reported by list_windows.","type":"number"},"y":{"description":"New top edge in the desktop coordinate space reported by list_windows.","type":"number"}},"required":["pid","window_id","x","y","width","height"],"type":"object"},"start_recording":{"additionalProperties":false,"properties":{"include_accessibility_tree":{"default":true,"description":"Default true. Set false to skip the per-turn before/after accessibility walks entirely; screenshots, click markers and action.json are still recorded and state is classified `state_capture_disabled`.","type":"boolean"},"output_dir":{"description":"Absolute or ~-rooted directory where turn folders and (when enabled) the video file are written.","type":"string"},"record_video":{"description":"Capture the main display to <output_dir>/recording.mp4. Default: false. Set to true to also capture the main display to recording.mp4 (otherwise only the per-turn screenshots + JSON are recorded). On macOS this uses native ScreenCaptureKit (macOS 15.0+); macOS 26 can show a one-time direct screen-capture consent on first use (see `cua-driver permissions grant`). On Windows + Linux it requires ffmpeg on PATH.","type":"boolean"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session.","type":"string"},"state_timeout_ms":{"default":1000,"description":"Wall-clock budget in milliseconds for EACH per-turn before/after accessibility walk (same default and bounds as get_window_state's timeout_ms). A walk that runs out records the partial tree and marks it truncated in evidence.json.","maximum":120000,"minimum":100,"type":"integer"}},"required":["output_dir"],"type":"object"},"start_session":{"additionalProperties":true,"properties":{"capture_scope":{"description":"Deprecated compatibility policy. New callers select window or desktop\nmodality on each action instead of storing it on the session.","enum":["auto","window","desktop"],"type":"string"},"cursor_motion":{"additionalProperties":false,"description":"Optional initial cursor motion (style, timing, effects and tuning). The host applies it\nbefore the cursor is first made visible. A later `set_agent_cursor_motion` call wins;\nthis wins over the saved default (`cursor.motion.*` in the driver config) and the\nbuilt-in `signature_arc`. Reduced motion always wins.","properties":{"arc_flow":{"description":"Added to the arc asymmetry of `signature_arc`, `spring_settle` and `comet_swoop`:\npositive moves the apex toward the destination. Clamped to -1..1 (default 0).","type":"number"},"arc_size":{"description":"Scales the arc of `signature_arc`, `spring_settle` and `comet_swoop`: 0.25 (default)\nkeeps the style's arc, 0 is a straight line, 0.5 doubles it. Clamped to 0..1.","type":"number"},"dwell_after_click_ms":{"description":"Pause after a click animation, in milliseconds. Clamped to 0..5000 (default 80).","type":"number"},"effects":{"additionalProperties":false,"description":"Turn effects on or off. Omit a field to keep it; `\"default\"` restores the style default.","properties":{"glow":{"description":"Soft glow around the cursor that grows with speed.","enum":["on","off","default"],"type":"string"},"magnet":{"description":"Target glow when the `magnetic` style locks on.","enum":["on","off","default"],"type":"string"},"ripple":{"description":"Ring that expands from the hotspot on click.","enum":["on","off","default"],"type":"string"},"squish":{"description":"Brief scale-down of the cursor on click.","enum":["on","off","default"],"type":"string"},"trail":{"description":"Short fading trail behind the cursor.","enum":["on","off","default"],"type":"string"}},"required":[],"type":"object"},"end_handle":{"description":"Arc control-point offset from the end, as a fraction of the distance, for\n`signature_arc`, `spring_settle` and `comet_swoop`. Clamped to 0..1 (default 0.3).","type":"number"},"glide_duration_ms":{"description":"Move duration in milliseconds for `fixed` timing (1430 ms when 0, the default). A\nnonzero value with `native` or the default `steady` timing also fixes the duration.\nClamped to 0..5000.","type":"number"},"idle_hide_ms":{"description":"Hide the cursor after this many idle milliseconds; 0 never hides it. Clamped to\n0..60000 (default 15000).","type":"number"},"spring":{"description":"Arrival spring damping for `classic`: 1 is critically damped, 0.3 is bouncy. Clamped\nto 0.3..1 (default 0.72).","type":"number"},"start_handle":{"description":"Arc control-point offset from the start, as a fraction of the distance, for\n`signature_arc`, `spring_settle` and `comet_swoop`. Clamped to 0..1 (default 0.3).","type":"number"},"style":{"description":"Trajectory style. `signature_arc` (default) is one arc with a small follow-through;\n`spring_settle` lands with one soft bounce; `magnetic` is pulled into the target;\n`comet_swoop` is a wide arc with a short trail; `adaptive` picks a careful approach for\nsmall targets and a swoop for long moves; `classic` is the previous Dubins glide. When\nthe theme's reduced motion is on, every move is a short straight glide with no effects.","enum":["signature_arc","spring_settle","magnetic","comet_swoop","adaptive","classic"],"type":"string"},"timing":{"description":"`steady` (default) keeps the style's timing but makes every move take at least 600 ms,\nwith a gentler ease; `relaxed` and `calm` do the same with a 450 or 750 ms floor.\n`native` uses the style's own timing; `fitts` scales the move time with distance and\ntarget size; `deliberate` is a slower Fitts curve (450..1300 ms); `fixed` uses\nglide_duration_ms (1430 ms when 0).","enum":["native","fitts","fixed","relaxed","steady","calm","deliberate"],"type":"string"},"turn_radius":{"description":"Minimum turning radius of the `classic` glide path, in points; smaller turns tighter.\nClamped to 1..1000 (default 80).","type":"number"}},"required":[],"type":"object"},"cursor_theme":{"additionalProperties":true,"description":"Optional initial cursor theme. The host applies it before the cursor is\nfirst made visible, avoiding a flash of the default theme.","properties":{"reduced_motion":{"default":"auto","enum":["auto","on","off"],"type":"string"},"theme_id":{"type":"string"}},"required":["theme_id"],"type":"object"},"session":{"description":"Optional stable public label for this run (e.g. \"research-run-1\").\nWhen omitted, the authenticated transport lease's implicit session is\ncreated or returned.","type":"string"}},"required":[],"type":"object"},"stop_recording":{"additionalProperties":false,"properties":{"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session.","type":"string"}},"type":"object"},"type_text":{"additionalProperties":false,"properties":{"coordinate_frame":{"description":"Frame of x/y (and from_x/from_y/to_x/to_y). Default \"window\": window-local screenshot pixels as returned by get_window_state. \"desktop\": full-screen pixels as returned by get_desktop_state, translated to the target window. Passing scope:\"desktop\" together with pid/window_id means the same thing.","enum":["window","desktop"],"type":"string"},"delivery_mode":{"default":"background","description":"Input delivery mode. 'background' (default) never activates or raises the target window. On X11 it injects via XTEST / the XInput2 master pointer (no focus steal). On Wayland it goes through libei + xdg-desktop-portal, which injects to the compositor's input focus — Wayland's security model has no per-window background targeting, so a specific non-focused window cannot be aimed at; when no libei backend is available the tool returns a structured background_unavailable error. 'foreground' is the explicit escalation: activate the target (X11 _NET_ACTIVE_WINDOW; Wayland compositor activate), inject, then restore the prior active window — a brief focus swap unless the target was already active. Matches the macOS / Windows delivery_mode surface.","enum":["background","foreground"],"type":"string"},"element_token":{"description":"Element handle `<snapshot_id>:<row>` from get_window_state: row `[11]` of a read whose snapshot_id is s0000002a is \"s0000002a:11\" (also in `structuredContent.elements[].element_token`). Returns an explicit stale error naming the current snapshots once a newer read supersedes it.","pattern":"^s[0-9a-f]{8}:[0-9]+$","type":"string"},"pid":{"description":"Target process ID. Omit with scope \"desktop\" to type into the focused application.","type":"integer"},"scope":{"default":"window","description":"Use \"desktop\" with no pid to type into the focused application. Default \"window\".","enum":["window","desktop"],"type":"string"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session.","type":"string"},"target":{"additionalProperties":true,"description":"Preferred per-call target: an exact window (`kind=\"window\"`, `pid`, `window_id`) or the\nprimary desktop (`kind=\"desktop\"`, `display_id=\"primary\"`).","properties":{"display_id":{"description":"Display id. Required when kind is desktop; use \"primary\".","type":"string"},"kind":{"description":"window requires pid and window_id; desktop requires display_id.","enum":["window","desktop"],"type":"string"},"pid":{"description":"Process id. Required when kind is window.","minimum":0,"type":"integer"},"window_id":{"description":"Window id from list_windows. Required when kind is window.","minimum":0,"type":"integer"}},"required":["kind"],"type":"object"},"text":{"description":"Text to type.","type":"string"},"window_id":{"description":"Window id from list_windows. Required with x/y; optional with element_token (the token carries it).","type":"integer"},"x":{"description":"Pixel X of the field to type into — the element px action form. Pass x,y (no element_token) and the tool pixel-clicks there to establish real renderer focus, then types. Use for Chromium/Electron inputs the AX path can't reach. Window-local pixels of the target window's own get_window_state screenshot by default (same convention as click); for get_desktop_state pixels pass scope:\"desktop\" (or coordinate_frame:\"desktop\") — a bare pid+x/y is otherwise misinterpreted as window-local and can focus the wrong widget.","type":"number"},"y":{"description":"Pixel Y of the field (see x).","type":"number"}},"required":["text"],"type":"object"},"verify_state":{"additionalProperties":false,"properties":{"expect":{"description":"One to eight predicates, combined with logical AND.","items":{"additionalProperties":false,"properties":{"element":{"additionalProperties":false,"properties":{"enabled":{"type":"boolean"},"exists":{"description":"Assert that at least one trusted element matches the selector.\n\nElement walks are not yet exhaustive on every platform, so absence\ncannot be proven. `false` is rejected instead of returning an\nindefinitely-unknown predicate.","type":"boolean"},"selected":{"type":"boolean"},"selector":{"additionalProperties":false,"properties":{"label_contains":{"minLength":1,"type":"string"},"role":{"minLength":1,"type":"string"}},"required":[],"type":"object"},"value_equals":{"type":"string"}},"required":["selector"],"type":"object"},"window":{"additionalProperties":false,"properties":{"bounds":{"additionalProperties":false,"properties":{"height":{"type":"number"},"tolerance_px":{"maximum":100,"minimum":0,"type":"number"},"width":{"type":"number"},"x":{"type":"number"},"y":{"type":"number"}},"required":["x","y","width","height"],"type":"object"},"exists":{"type":"boolean"}},"required":[],"type":"object"}},"required":[],"type":"object"},"maxItems":8,"minItems":1,"type":"array"},"include_screenshot":{"description":"Return the final window screenshot as image content for a multimodal\ncaller. The driver does not interpret that image.","type":"boolean"},"pid":{"description":"Exact process whose window may be observed.","minimum":1,"type":"integer"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that\naccepts it. Omit it to use the authenticated transport's implicit lifecycle session. This\nfield never selects capture modality or authorization.","type":"string"},"stable_samples":{"default":2,"description":"Consecutive satisfied samples required before returning success.","maximum":5,"minimum":1,"type":"integer"},"timeout_ms":{"default":5000,"description":"Bounded wait. Zero performs one sample.","maximum":10000,"minimum":0,"type":"integer"},"window_id":{"description":"Exact native window identifier.","type":"integer"}},"required":["pid","window_id","expect"],"type":"object"},"zoom":{"additionalProperties":false,"properties":{"pid":{"description":"Optional target pid. When omitted, the driver resolves the unique current snapshot for this session and window.","type":"integer"},"session":{"description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session.","type":"string"},"window_id":{"description":"Window id of the window captured by get_window_state.","type":"integer"},"x1":{"description":"Left edge of the region in window-local screenshot pixels.","type":"number"},"x2":{"description":"Right edge of the region in window-local screenshot pixels.","type":"number"},"y1":{"description":"Top edge of the region in window-local screenshot pixels.","type":"number"},"y2":{"description":"Bottom edge of the region in window-local screenshot pixels.","type":"number"}},"required":["window_id","x1","y1","x2","y2"],"type":"object"}}"###;
#[cfg(test)]
#[path = "tests.rs"]
mod tests;
