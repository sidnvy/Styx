//! One external Browser executor lane. Core permits, owner/profile/reference
//! policy and operation outcomes stay in Rust; this module creates no ledger.
use rmcp::{
    ClientHandler, RoleClient, ServiceExt,
    model::{CallToolRequestParams, CallToolResponse, CallToolResult},
    service::RunningService,
    transport::async_rw::AsyncRwTransport,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::File,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex},
    time::Duration,
};
use styx_contracts::{capability::CapabilityId, identity::Sha256Digest, operation::OperationId};
use styx_core::operations::{DispatchPermit, OwnerLease};
use tokio::{
    process::Child,
    sync::{OwnedMutexGuard, OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
    time::{Instant, timeout_at},
};
use tokio_util::sync::CancellationToken;

const IO_BYTES: usize = 16 * 1024 * 1024;
const FRAME_BYTES: usize = 8 * 1024 * 1024;
// One MiB logical retained metadata, conservatively 8KiB per record.
// This is not an I/O pool or a second Host byte allocator. No live eviction.
const MAX_RECORDS: usize = 128;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum BrowserError {
    #[error("browser_busy")]
    Busy,
    #[error("browser_invalid_request")]
    InvalidRequest,
    #[error("browser_permission_denied")]
    PermissionDenied,
    #[error("browser_unsupported")]
    Unsupported,
    #[error("browser_spawn_failed")]
    SpawnFailed,
    #[error("browser_protocol_mismatch")]
    ProtocolMismatch,
    #[error("browser_outcome_unknown")]
    Unknown,
    #[error("browser_already_dispatched")]
    AlreadyDispatched,
    #[error("browser_cleanup_unconfirmed")]
    CleanupUnconfirmed,
    #[error("browser_stale_observation")]
    StaleObservation,
}
type Result<T> = std::result::Result<T, BrowserError>;
/// Trusted bootstrap input only, never a network DTO. Caller verifies release
/// provenance before construction; absolute paths alone are not that proof.
#[derive(Clone)]
pub struct OwnedBrowserConfig {
    pub node_binary: PathBuf,
    pub worker_entry: PathBuf,
    pub browser_binary: PathBuf,
    pub workspace_dir: PathBuf,
    pub profile_dir: PathBuf,
    pub output_dir: PathBuf,
    pub rpc_timeout: Duration,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserOpenSpec {
    mode: String,
    config_digest: Sha256Digest,
}
impl BrowserOpenSpec {
    pub fn for_config(config: &OwnedBrowserConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            mode: "headless".into(),
            config_digest: config.digest()?,
        })
    }
    pub fn to_operation_payload(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|_| BrowserError::InvalidRequest)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BrowserAction {
    Navigate {
        url: String,
    },
    Evaluate {
        function: String,
    },
    Close,
    Tool {
        name: String,
        arguments: serde_json::Map<String, serde_json::Value>,
    },
}
impl BrowserAction {
    pub fn to_operation_payload(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| BrowserError::InvalidRequest)
    }
    fn validate(&self) -> Result<()> {
        match self {
            Self::Tool { name, arguments } => policy::validate(name, arguments),
            Self::Navigate { url } if url.len() > 8192 => Err(BrowserError::InvalidRequest),
            Self::Evaluate { function } if function.len() > 65536 => {
                Err(BrowserError::InvalidRequest)
            }
            _ => {
                let (name, args) = policy::tool(self);
                policy::validate(&name, &args)
            }
        }
    }
    pub fn is_close(&self) -> bool {
        matches!(self, Self::Close) || matches!(self,Self::Tool{name,..} if name=="browser_close")
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BrowserActionEvidence {
    Acknowledged,
    NotDispatched,
    Unknown,
}
pub struct BrowserActionReceipt {
    pub operation: OperationId,
    pub evidence: BrowserActionEvidence,
    pub result: Option<CallToolResult>,
    pub cause: Option<BrowserError>,
}
impl std::fmt::Debug for BrowserActionReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrowserActionReceipt")
            .field("operation", &self.operation)
            .field("evidence", &self.evidence)
            .field("result", &"[REDACTED]")
            .field("cause", &self.cause)
            .finish()
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserDescendants {
    Confirmed,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrowserCleanup {
    pub worker_exited: bool,
    pub worker_exit_success: Option<bool>,
    pub stdio_joined: bool,
    pub context_closed: bool,
    pub descendants: BrowserDescendants,
}
/// Exclusive lane reservation from the SAME Host allocator. Metadata retention
/// does not own the physical single-worker slot; only actual cleanup releases it.
pub struct BrowserIoBudget {
    _partition: OwnedSemaphorePermit,
    active: Arc<Semaphore>,
}
impl BrowserIoBudget {
    pub fn from_reserved(partition: OwnedSemaphorePermit) -> Result<Arc<Self>> {
        if partition.num_permits() != IO_BYTES {
            return Err(BrowserError::InvalidRequest);
        }
        Ok(Arc::new(Self {
            _partition: partition,
            active: Arc::new(Semaphore::new(1)),
        }))
    }
}
#[derive(Clone)]
pub struct BrowserWorker {
    inner: Arc<Inner>,
}
struct Inner {
    budget: Arc<BrowserIoBudget>,
    resources: Mutex<BTreeMap<OperationId, Arc<Resource>>>,
    metadata: Arc<Semaphore>,
}
struct Resource {
    metadata_record: Mutex<Option<OwnedSemaphorePermit>>,
    metadata: Arc<Semaphore>,
    stop: CancellationToken,
    cleanup_job: Mutex<Option<tokio::sync::watch::Receiver<Option<BrowserCleanup>>>>,
    operation: OperationId,
    digest: Sha256Digest,
    owner: OwnerLease,
    state: Arc<tokio::sync::Mutex<Live>>,
    _budget: Arc<BrowserIoBudget>,
}
struct Live {
    child: Option<Child>,
    client: Option<RunningService<RoleClient, BrowserClient>>,
    stderr: Option<JoinHandle<()>>,
    client_close: Option<JoinHandle<bool>>,
    io_join_failed: bool,
    retired: bool,
    references: styx_core::browser::BrowserReferenceScope,
    workspace: PathBuf,
    output: PathBuf,
    slot: Option<OwnedSemaphorePermit>,
    pins: Vec<File>,
    uncertain: bool,
    context_closed: bool,
    timeout: Duration,
    actions: BTreeMap<
        OperationId,
        (
            Sha256Digest,
            BrowserActionEvidence,
            Option<BrowserError>,
            OwnedSemaphorePermit,
        ),
    >,
    config_file: PathBuf,
    scope: Option<LinuxOwnedScope>,
    cleanup: Option<BrowserCleanup>,
}
#[derive(Clone)]
pub struct BrowserHandle {
    resource: Arc<Resource>,
    host: Arc<Inner>,
}
impl std::fmt::Debug for BrowserHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrowserHandle")
            .field("operation", &self.resource.operation)
            .finish_non_exhaustive()
    }
}
impl BrowserHandle {
    pub fn operation(&self) -> &OperationId {
        &self.resource.operation
    }
    pub fn payload_digest(&self) -> Sha256Digest {
        self.resource.digest
    }
    pub fn owner(&self) -> &OwnerLease {
        &self.resource.owner
    }
}
#[derive(Debug)]
pub struct BrowserOpenReceipt {
    pub handle: BrowserHandle,
    pub evidence: BrowserActionEvidence,
}
pub struct BrowserOpenSlot {
    worker: BrowserWorker,
    slot: OwnedSemaphorePermit,
    metadata: OwnedSemaphorePermit,
}
pub struct BrowserActionSlot {
    resource: Arc<Resource>,
    state: OwnedMutexGuard<Live>,
}
impl BrowserWorker {
    pub fn new(budget: Arc<BrowserIoBudget>) -> Self {
        Self {
            inner: Arc::new(Inner {
                budget,
                resources: Mutex::new(BTreeMap::new()),
                metadata: Arc::new(Semaphore::new(MAX_RECORDS)),
            }),
        }
    }
    pub fn try_reserve_open(&self) -> Result<BrowserOpenSlot> {
        if self
            .inner
            .resources
            .lock()
            .map_err(|_| BrowserError::Unknown)?
            .len()
            >= MAX_RECORDS
        {
            return Err(BrowserError::Busy);
        }
        let slot = self
            .inner
            .budget
            .active
            .clone()
            .try_acquire_owned()
            .map_err(|_| BrowserError::Busy)?;
        let metadata = self
            .inner
            .metadata
            .clone()
            .try_acquire_owned()
            .map_err(|_| BrowserError::Busy)?;
        Ok(BrowserOpenSlot {
            metadata,
            worker: self.clone(),
            slot,
        })
    }
    pub fn try_reserve_action(&self, handle: &BrowserHandle) -> Result<BrowserActionSlot> {
        if !Arc::ptr_eq(&self.inner, &handle.host) {
            return Err(BrowserError::PermissionDenied);
        }
        if handle.resource.stop.is_cancelled() {
            return Err(BrowserError::Unknown);
        }
        let state = handle
            .resource
            .state
            .clone()
            .try_lock_owned()
            .map_err(|_| BrowserError::Busy)?;
        if state.retired {
            return Err(BrowserError::PermissionDenied);
        }
        Ok(BrowserActionSlot {
            resource: handle.resource.clone(),
            state,
        })
    }
    pub async fn cleanup_owned(
        &self,
        handle: &BrowserHandle,
        budget: Duration,
    ) -> Result<BrowserCleanup> {
        if !Arc::ptr_eq(&self.inner, &handle.host) {
            return Err(BrowserError::PermissionDenied);
        }
        let resource = handle.resource.clone();
        resource.stop.cancel();
        let until = Instant::now() + budget.min(Duration::from_secs(30));
        let mut receiver = {
            let mut job = resource
                .cleanup_job
                .lock()
                .map_err(|_| BrowserError::CleanupUnconfirmed)?;
            if let Some(existing) = job.as_ref() {
                existing.clone()
            } else {
                let (sender, receiver) = tokio::sync::watch::channel(None);
                *job = Some(receiver.clone());
                let owned = resource.clone();
                tokio::spawn(async move {
                    let mut state = owned.state.clone().lock_owned().await;
                    loop {
                        let facts = cleanup(&mut state, Duration::from_secs(2)).await;
                        let done = facts.worker_exited
                            && facts.stdio_joined
                            && facts.descendants == BrowserDescendants::Confirmed;
                        let _ = sender.send(Some(facts));
                        if done {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(250)).await;
                    }
                });
                receiver
            }
        };
        loop {
            if let Some(facts) = *receiver.borrow_and_update() {
                return Ok(facts);
            }
            if !matches!(timeout_at(until, receiver.changed()).await, Ok(Ok(()))) {
                return Err(BrowserError::CleanupUnconfirmed);
            }
        }
    }
}
// The worker receives its fixed workspace in the Rust-owned config. Roots
// discovery is unnecessary for these three tools and grants no additional scope.
#[derive(Clone)]
struct BrowserClient {
    _budget: Arc<BrowserIoBudget>,
}
impl ClientHandler for BrowserClient {}
mod linux_scope;
mod policy;
mod references;
mod retention;
use linux_scope::{LinuxOwnedScope, ScopeCommand};

pub struct BrowserOpenFailure {
    pub operation: OperationId,
    pub handle: Option<BrowserHandle>,
    pub evidence: BrowserActionEvidence,
    pub cause: BrowserError,
}
impl std::fmt::Debug for BrowserOpenFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrowserOpenFailure")
            .field("operation", &self.operation)
            .field("evidence", &self.evidence)
            .field("cause", &self.cause)
            .finish()
    }
}
impl OwnedBrowserConfig {
    fn validate(&self) -> Result<()> {
        if self.rpc_timeout.is_zero() || self.rpc_timeout > Duration::from_secs(35) {
            return Err(BrowserError::InvalidRequest);
        }
        for path in [
            &self.node_binary,
            &self.worker_entry,
            &self.browser_binary,
            &self.workspace_dir,
            &self.profile_dir,
            &self.output_dir,
        ] {
            if path.as_os_str().len() > 4096
                || !path.is_absolute()
                || std::fs::canonicalize(path).map_err(|_| BrowserError::InvalidRequest)? != *path
            {
                return Err(BrowserError::InvalidRequest);
            }
        }
        for path in [&self.profile_dir, &self.output_dir] {
            crate::store::PrivateRoot::open(path).map_err(|_| BrowserError::PermissionDenied)?;
        }
        for (a, b) in [
            (&self.workspace_dir, &self.profile_dir),
            (&self.workspace_dir, &self.output_dir),
            (&self.profile_dir, &self.output_dir),
        ] {
            if a.starts_with(b) || b.starts_with(a) {
                return Err(BrowserError::InvalidRequest);
            }
        }
        Ok(())
    }
    fn digest(&self) -> Result<Sha256Digest> {
        let bytes = serde_json::to_vec(&(
            "styx.browser.open.config.v1",
            &self.node_binary,
            &self.worker_entry,
            &self.browser_binary,
            &self.workspace_dir,
            &self.profile_dir,
            &self.output_dir,
            self.rpc_timeout.as_millis(),
        ))
        .map_err(|_| BrowserError::InvalidRequest)?;
        Ok(Sha256Digest::of_bytes(&bytes))
    }
}
impl BrowserOpenSlot {
    pub async fn spawn_owned(
        self,
        permit: DispatchPermit,
        config: OwnedBrowserConfig,
    ) -> std::result::Result<BrowserOpenReceipt, BrowserOpenFailure> {
        let operation = permit.id().clone();
        let validate = || -> Result<()> {
            config.validate()?;
            if permit.target().is_some()
                || permit.context().capability != CapabilityId::BrowserHeadless
                || permit.context().session.is_some()
                || permit.context().observation.is_some()
            {
                return Err(BrowserError::PermissionDenied);
            }
            let spec: BrowserOpenSpec = serde_json::from_slice(permit.payload())
                .map_err(|_| BrowserError::InvalidRequest)?;
            if spec.mode != "headless" || spec.config_digest != config.digest()? {
                return Err(BrowserError::InvalidRequest);
            }
            Ok(())
        };
        if let Err(cause) = validate() {
            return Err(BrowserOpenFailure {
                operation,
                handle: None,
                evidence: BrowserActionEvidence::NotDispatched,
                cause,
            });
        }
        let (tx, rx) = tokio::sync::oneshot::channel();
        let worker = self.worker.clone();
        let lost_operation = operation.clone();
        tokio::spawn(async move {
            let result = self.open_inner(permit, config).await;
            let _ = tx.send(result);
        });
        match rx.await {
            Ok(result) => result,
            Err(_) => {
                let handle = worker
                    .inner
                    .resources
                    .lock()
                    .ok()
                    .and_then(|m| m.get(&lost_operation).cloned())
                    .map(|resource| BrowserHandle {
                        resource,
                        host: worker.inner.clone(),
                    });
                Err(BrowserOpenFailure {
                    operation: lost_operation,
                    handle,
                    evidence: BrowserActionEvidence::Unknown,
                    cause: BrowserError::Unknown,
                })
            }
        }
    }
    async fn open_inner(
        self,
        permit: DispatchPermit,
        config: OwnedBrowserConfig,
    ) -> std::result::Result<BrowserOpenReceipt, BrowserOpenFailure> {
        let operation = permit.id().clone();
        let digest = Sha256Digest::of_bytes(permit.payload());
        let owner = permit.owner().clone();
        let mut entropy = [0_u8; 32];
        if getrandom::fill(&mut entropy).is_err() {
            return Err(BrowserOpenFailure {
                operation,
                handle: None,
                evidence: BrowserActionEvidence::NotDispatched,
                cause: BrowserError::Unknown,
            });
        }
        let references = styx_core::browser::BrowserReferenceScope::new(
            owner.clone(),
            styx_contracts::operation::ResourceTarget {
                operation_id: operation.clone(),
                payload_digest: digest,
            },
            entropy,
        );
        let resource = Arc::new(Resource {
            metadata_record: Mutex::new(Some(self.metadata)),
            metadata: self.worker.inner.metadata.clone(),
            stop: CancellationToken::new(),
            cleanup_job: Mutex::new(None),
            operation: operation.clone(),
            digest,
            owner,
            state: Arc::new(tokio::sync::Mutex::new(Live {
                child: None,
                client: None,
                stderr: None,
                client_close: None,
                io_join_failed: false,
                retired: false,
                references,
                workspace: config.workspace_dir.clone(),
                output: config.output_dir.clone(),
                slot: Some(self.slot),
                pins: Vec::new(),
                uncertain: false,
                context_closed: false,
                timeout: config.rpc_timeout,
                actions: BTreeMap::new(),
                config_file: PathBuf::new(),
                scope: None,
                cleanup: None,
            })),
            _budget: self.worker.inner.budget.clone(),
        });
        let handle = BrowserHandle {
            resource: resource.clone(),
            host: self.worker.inner.clone(),
        };
        match self.worker.inner.resources.lock() {
            Ok(mut map) if !map.contains_key(&operation) => {
                map.insert(operation.clone(), resource.clone());
            }
            _ => {
                return Err(BrowserOpenFailure {
                    operation,
                    handle: None,
                    evidence: BrowserActionEvidence::NotDispatched,
                    cause: BrowserError::AlreadyDispatched,
                });
            }
        }
        let mut live = resource.state.clone().lock_owned().await;
        let started = Instant::now();
        let until = started + config.rpc_timeout;
        let result = async {
            let node = pin(&config.node_binary, &mut live.pins)?;
            let worker = pin(&config.worker_entry, &mut live.pins)?;
            let browser = pin(&config.browser_binary, &mut live.pins)?;
            use std::os::unix::fs::OpenOptionsExt;
            let config_file = config.output_dir.join(format!("worker-{}.json",uuid::Uuid::new_v4()));
            let mut file = std::fs::OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(&config_file).map_err(|_|BrowserError::SpawnFailed)?;
            let bytes = serde_json::to_vec(&serde_json::json!({"schema":1,"profile_dir":config.profile_dir,"output_dir":config.output_dir,"workspace_dir":config.workspace_dir,"browser_executable":browser})).map_err(|_|BrowserError::InvalidRequest)?;
            use std::io::Write;
            file.write_all(&bytes).and_then(|_|file.sync_all()).map_err(|_|BrowserError::SpawnFailed)?;
            live.config_file = config_file;
            let cfg = fd_path(&file);live.pins.push(file);
            let (mut command, scope) = LinuxOwnedScope::command(ScopeCommand { node,worker,config:cfg,workspace:config.workspace_dir.clone(),home:config.output_dir.clone() })?;
            live.scope = Some(scope);
            live.child = Some(command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true).spawn().map_err(|_|BrowserError::SpawnFailed)?);
            tokio::select! {
                _=resource.stop.cancelled()=>return Err(BrowserError::Unknown),
                result=live.scope.as_mut().ok_or(BrowserError::Unknown)?.attest_started(until)=>result?,
            }
            let child = live.child.as_mut().ok_or(BrowserError::Unknown)?;
            let stdin = child.stdin.take().ok_or(BrowserError::SpawnFailed)?;
            let stdout = child.stdout.take().ok_or(BrowserError::SpawnFailed)?;
            if let Some(mut stderr) = child.stderr.take() {
                let budget = resource._budget.clone();
                live.stderr = Some(tokio::spawn(async move {let _budget=budget;let _=tokio::io::copy(&mut stderr,&mut tokio::io::sink()).await;}));
            }
            let handler = BrowserClient { _budget:resource._budget.clone() };
            let transport = AsyncRwTransport::<RoleClient,_,_>::new(stdout,stdin).with_max_line_length(FRAME_BYTES);
            let client=tokio::select! {
                _=resource.stop.cancelled()=>return Err(BrowserError::Unknown),
                result=timeout_at(until,handler.serve(transport))=>result.map_err(|_|BrowserError::Unknown)?.map_err(|_|BrowserError::ProtocolMismatch)?,
            };
            live.client = Some(client);
            let info=live.client.as_ref().ok_or(BrowserError::Unknown)?.peer().peer_info()
                .ok_or(BrowserError::ProtocolMismatch)?;
            if !info.server_info.as_ref().is_some_and(|server|server.name=="styx-browser-native-worker" && server.version=="0.2.0") {
                return Err(BrowserError::ProtocolMismatch);
            }
            let listed = tokio::select! {
                _=resource.stop.cancelled()=>return Err(BrowserError::Unknown),
                result=timeout_at(until,live.client.as_ref().ok_or(BrowserError::Unknown)?.peer().list_all_tools())=>result.map_err(|_|BrowserError::Unknown)?.map_err(|_|BrowserError::ProtocolMismatch)?,
            };
            validate_tools(&listed)?;
            Ok(())
        }.await;
        match result {
            Ok(()) => Ok(BrowserOpenReceipt {
                handle,
                evidence: BrowserActionEvidence::Acknowledged,
            }),
            Err(cause) => {
                live.uncertain = true;
                Err(BrowserOpenFailure {
                    operation,
                    handle: Some(handle),
                    evidence: BrowserActionEvidence::Unknown,
                    cause,
                })
            }
        }
    }
}
fn validate_tools(tools: &[rmcp::model::Tool]) -> Result<()> {
    let pinned: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../packages/styx-browser-provider/playwright-contract-0.0.83.json"
    ))
    .map_err(|_| BrowserError::ProtocolMismatch)?;
    let expected = pinned
        .get("tools")
        .and_then(|v| v.as_array())
        .ok_or(BrowserError::ProtocolMismatch)?;
    let omitted = pinned
        .get("omitted")
        .and_then(|v| v.as_array())
        .ok_or(BrowserError::ProtocolMismatch)?;
    let mut actual = BTreeMap::new();
    let mut native_state = false;
    for tool in tools {
        if tool.name.as_ref() == "styx_browser_state" {
            if native_state {
                return Err(BrowserError::ProtocolMismatch);
            }
            native_state = true;
            continue;
        }
        if omitted
            .iter()
            .any(|name| name.as_str() == Some(tool.name.as_ref()))
        {
            continue;
        }
        if actual.insert(tool.name.as_ref(), tool).is_some() {
            return Err(BrowserError::ProtocolMismatch);
        }
    }
    if !native_state || actual.len() != expected.len() {
        return Err(BrowserError::ProtocolMismatch);
    }
    for expected in expected {
        let name = expected
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or(BrowserError::ProtocolMismatch)?;
        let got = actual.get(name).ok_or(BrowserError::ProtocolMismatch)?;
        if Some(&serde_json::Value::Object((*got.input_schema).clone()))
            != expected.get("inputSchema")
        {
            return Err(BrowserError::ProtocolMismatch);
        }
    }
    Ok(())
}
fn fd_path(file: &File) -> PathBuf {
    PathBuf::from(format!(
        "/proc/{}/fd/{}",
        std::process::id(),
        file.as_raw_fd()
    ))
}
fn pin(path: &Path, pins: &mut Vec<File>) -> Result<PathBuf> {
    let file = File::open(path).map_err(|_| BrowserError::SpawnFailed)?;
    if !file
        .metadata()
        .map_err(|_| BrowserError::SpawnFailed)?
        .is_file()
    {
        return Err(BrowserError::SpawnFailed);
    }
    let path = fd_path(&file);
    pins.push(file);
    Ok(path)
}
impl BrowserActionSlot {
    pub async fn call_once(self, permit: DispatchPermit) -> BrowserActionReceipt {
        let operation = permit.id().clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let result = self.call_inner(permit).await;
            let _ = tx.send(result);
        });
        rx.await.unwrap_or(BrowserActionReceipt {
            operation,
            evidence: BrowserActionEvidence::Unknown,
            result: None,
            cause: Some(BrowserError::Unknown),
        })
    }
    async fn call_inner(mut self, permit: DispatchPermit) -> BrowserActionReceipt {
        let operation = permit.id().clone();
        let digest = Sha256Digest::of_bytes(permit.payload());
        let refuse = |cause| BrowserActionReceipt {
            operation: operation.clone(),
            evidence: BrowserActionEvidence::NotDispatched,
            result: None,
            cause: Some(cause),
        };
        let Some(target) = permit.target() else {
            return refuse(BrowserError::PermissionDenied);
        };
        if self.state.retired
            || permit.owner() != &self.resource.owner
            || target.operation_id != self.resource.operation
            || target.payload_digest != self.resource.digest
            || permit.context().capability != CapabilityId::BrowserHeadless
            || permit.context().session.is_some()
            || permit.context().observation.is_some()
        {
            return refuse(BrowserError::PermissionDenied);
        }
        if let Some((previous, evidence, cause, _metadata)) = self.state.actions.get(&operation) {
            if *previous != digest {
                return refuse(BrowserError::PermissionDenied);
            }
            return BrowserActionReceipt {
                operation,
                evidence: *evidence,
                result: None,
                cause: *cause,
            };
        }
        if permit.payload().len() > 128 * 1024 {
            return refuse(BrowserError::InvalidRequest);
        }
        let action = match serde_json::from_slice::<BrowserAction>(permit.payload()) {
            Ok(action) => action,
            Err(_) => return refuse(BrowserError::Unsupported),
        };
        if let Err(error) = action.validate() {
            return refuse(error);
        }
        if self.state.actions.len() >= MAX_RECORDS {
            return refuse(BrowserError::Busy);
        }
        if self.state.uncertain && !action.is_close() {
            return refuse(BrowserError::Unknown);
        }
        if self
            .state
            .child
            .as_mut()
            .and_then(|c| c.try_wait().ok())
            .flatten()
            .is_some()
        {
            self.state.uncertain = true;
            return refuse(BrowserError::Unknown);
        }
        let (tool_name, mut arguments) = policy::tool(&action);
        if let Err(error) =
            policy::check_files(&mut arguments, &self.state.workspace, &self.state.output)
        {
            return refuse(error);
        }
        let until = Instant::now() + self.state.timeout;
        // This read is a native epoch observation, not Core authorization and
        // not an atomic browser navigation lock. It never starts the context.
        let observed = match &self.state.client {
            Some(client) => tokio::select! {
                _=self.resource.stop.cancelled()=>None,
                value=timeout_at(until,client.call_tool_once(CallToolRequestParams::new("styx_browser_state")))=>Some(value),
            },
            None => None,
        };
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ObservedState {
            schema: u8,
            epoch: u64,
            ready: bool,
            closed: bool,
        }
        let observed_state = match observed {
            Some(Ok(Ok(CallToolResponse::Complete(value)))) if value.is_error != Some(true) => {
                value
                    .structured_content
                    .and_then(|v| serde_json::from_value::<ObservedState>(v).ok())
                    .filter(|s| s.schema == 1 && s.epoch > 0 && s.epoch <= 9_007_199_254_740_991)
            }
            _ => None,
        };
        let Some(observed_state) = observed_state else {
            self.state.references.invalidate();
            self.state.uncertain = true;
            // The management observation is malformed/lost; no user tool was
            // dispatched. Fence this executor rather than infer a false Ready.
            return refuse(BrowserError::ProtocolMismatch);
        };
        if observed_state.closed {
            self.state.references.invalidate();
            self.state.uncertain = true;
            return refuse(BrowserError::StaleObservation);
        }
        let epoch = observed_state.epoch;
        let ready = observed_state.ready;
        if !ready && self.state.references.current_epoch().is_some() {
            self.state.references.invalidate();
            self.state.uncertain = true;
            return refuse(BrowserError::StaleObservation);
        }
        let mut targets = serde_json::Value::Object(arguments);
        let resolved = references::resolve_targets(
            &mut targets,
            &self.state.references,
            permit.owner(),
            target,
            epoch,
        );
        // Native-ref safety is conditional on snapshot mode none plus this
        // complete resource mutex. Never start a concurrent snapshot while a
        // lazy upstream locator is pending. Native errors remain Unknown and
        // poison all later actions except terminal Close.
        if let Err(error) = resolved {
            self.state.references.invalidate();
            return refuse(error);
        }
        arguments = targets.as_object().cloned().unwrap_or_default();
        if policy::invalidates(&tool_name, &arguments) {
            self.state.references.invalidate();
        }
        let snapshot = policy::snapshot(&tool_name, &arguments);
        let mut params = CallToolRequestParams::new(tool_name).with_arguments(arguments);
        // A never-created context has no stable page observation to guard.
        // Existing opaque tokens were still resolved above and cannot take this
        // path without a scope. Do not manufacture epoch equality across init.
        if ready {
            params.meta = Some(
                serde_json::Map::from_iter([(
                    references::META.into(),
                    serde_json::json!({"schema":1,"expected_epoch":epoch}),
                )])
                .into(),
            );
        }
        let metadata = match self.resource.metadata.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => return refuse(BrowserError::Busy),
        };
        self.state.actions.insert(
            operation.clone(),
            (
                digest,
                BrowserActionEvidence::Unknown,
                Some(BrowserError::Unknown),
                metadata,
            ),
        );
        let response = match &self.state.client {
            Some(client) => tokio::select! {
                _=self.resource.stop.cancelled()=>None,
                result=timeout_at(until,client.call_tool_once(params))=>Some(result),
            },
            None => {
                self.state.uncertain = true;
                return BrowserActionReceipt {
                    operation,
                    evidence: BrowserActionEvidence::Unknown,
                    result: None,
                    cause: Some(BrowserError::Unknown),
                };
            }
        };
        let (evidence, result, cause) = match response {
            Some(Ok(Ok(CallToolResponse::Complete(mut result)))) => {
                match references::fact(&result) {
                    Ok(native)
                        if !native.dispatched
                            && result.is_error == Some(true)
                            && native.before == native.after
                            && matches!(native.reason.as_deref(), Some("stale" | "invalid")) =>
                    {
                        self.state.references.invalidate();
                        (
                            BrowserActionEvidence::NotDispatched,
                            None,
                            Some(if native.reason.as_deref() == Some("stale") {
                                BrowserError::StaleObservation
                            } else {
                                BrowserError::InvalidRequest
                            }),
                        )
                    }
                    Ok(native)
                        if native.dispatched
                            && (if ready {
                                native.before == epoch
                            } else {
                                native.before >= epoch
                            })
                            && result.is_error != Some(true) =>
                    {
                        let valid_close = !action.is_close()
                            || result
                                .structured_content
                                .as_ref()
                                .and_then(|v| v.get("styx_context_closed"))
                                .and_then(serde_json::Value::as_bool)
                                == Some(true);
                        if action.is_close() && valid_close {
                            self.state.context_closed = true;
                        }
                        if native.before != native.after {
                            self.state.references.invalidate();
                        }
                        // A lazy first snapshot may itself create the context
                        // and change epoch. It completed as a read, but cannot
                        // mint stable refs. Return ACK + stale warning and scrub
                        // native refs; do not retry or poison a healthy context.
                        let stale_snapshot = snapshot && native.before != native.after;
                        let refs = references::result_refs(
                            &mut result,
                            &mut self.state.references,
                            snapshot && !stale_snapshot,
                            &native,
                        );
                        if valid_close && refs.is_ok() {
                            (
                                BrowserActionEvidence::Acknowledged,
                                Some(result),
                                stale_snapshot.then_some(BrowserError::StaleObservation),
                            )
                        } else {
                            (
                                BrowserActionEvidence::Unknown,
                                None,
                                Some(if valid_close {
                                    refs.err().unwrap_or(BrowserError::Unknown)
                                } else {
                                    BrowserError::ProtocolMismatch
                                }),
                            )
                        }
                    }
                    _ => (
                        BrowserActionEvidence::Unknown,
                        None,
                        Some(BrowserError::Unknown),
                    ),
                }
            }
            _ => (
                BrowserActionEvidence::Unknown,
                None,
                Some(BrowserError::Unknown),
            ),
        };
        if evidence == BrowserActionEvidence::Unknown {
            self.state.references.invalidate();
            self.state.uncertain = true;
        }
        if let Some(record) = self.state.actions.get_mut(&operation) {
            record.1 = evidence;
            record.2 = cause;
        }
        BrowserActionReceipt {
            operation,
            evidence,
            result,
            cause,
        }
    }
}
async fn cleanup(live: &mut Live, budget: Duration) -> BrowserCleanup {
    live.references.clear();
    if let Some(facts) = live.cleanup {
        return facts;
    }
    let until = Instant::now() + budget.min(Duration::from_secs(30));
    let mut joined = !live.io_join_failed;
    if live.client_close.is_none()
        && let Some(mut client) = live.client.take()
    {
        live.client_close = Some(tokio::spawn(async move { client.close().await.is_ok() }));
    }
    let worker_exited;
    let worker_exit_success;
    let descendants;
    if let Some(child) = &mut live.child {
        if let Some(scope) = &mut live.scope {
            match scope
                .stop_and_confirm(child, until.saturating_duration_since(Instant::now()))
                .await
            {
                Ok(proof) => {
                    worker_exited = proof.wrapper_exited;
                    worker_exit_success = proof.exit_success;
                    descendants = if proof.confirmed {
                        BrowserDescendants::Confirmed
                    } else {
                        BrowserDescendants::Unknown
                    };
                }
                Err(_) => {
                    worker_exited = false;
                    worker_exit_success = None;
                    descendants = BrowserDescendants::Unknown;
                }
            }
        } else {
            worker_exited = false;
            worker_exit_success = None;
            descendants = BrowserDescendants::Unknown;
        }
    } else {
        worker_exited = true;
        worker_exit_success = None;
        descendants = BrowserDescendants::Confirmed;
    }
    if let Some(task) = &mut live.client_close {
        match timeout_at(until, task).await {
            Ok(Ok(true)) => {
                live.client_close.take();
            }
            Ok(Ok(false) | Err(_)) => {
                live.client_close.take();
                live.io_join_failed = true;
                joined = false;
            }
            Err(_) => joined = false,
        }
    }
    if let Some(task) = &mut live.stderr {
        match timeout_at(until, task).await {
            Ok(Ok(())) => {
                live.stderr.take();
            }
            Ok(Err(_)) => {
                live.stderr.take();
                live.io_join_failed = true;
                joined = false;
            }
            Err(_) => joined = false,
        }
    }
    let facts = BrowserCleanup {
        worker_exited,
        worker_exit_success,
        stdio_joined: joined,
        context_closed: live.context_closed
            || (worker_exited && descendants == BrowserDescendants::Confirmed),
        descendants,
    };
    if worker_exited && joined && descendants == BrowserDescendants::Confirmed {
        live.child.take();
        live.pins.clear();
        live.slot.take();
        live.cleanup = Some(facts);
        if !live.config_file.as_os_str().is_empty() {
            let _ = std::fs::remove_file(&live.config_file);
        }
    } else {
        live.uncertain = true;
    }
    facts
}
impl BrowserWorker {
    pub fn lookup_operation(
        &self,
        owner: &OwnerLease,
        operation: &OperationId,
    ) -> Result<BrowserHandle> {
        let map = self
            .inner
            .resources
            .lock()
            .map_err(|_| BrowserError::Unknown)?;
        let resource = map.get(operation).ok_or(BrowserError::InvalidRequest)?;
        if &resource.owner != owner {
            return Err(BrowserError::PermissionDenied);
        }
        Ok(BrowserHandle {
            resource: resource.clone(),
            host: self.inner.clone(),
        })
    }
    pub fn handles(&self) -> Result<Vec<BrowserHandle>> {
        Ok(self
            .inner
            .resources
            .lock()
            .map_err(|_| BrowserError::Unknown)?
            .values()
            .map(|r| BrowserHandle {
                resource: r.clone(),
                host: self.inner.clone(),
            })
            .collect())
    }
    pub fn resources(&self) -> Result<Vec<BrowserHandle>> {
        self.handles()
    }
    pub async fn cleanup_all_owned(
        &self,
        budget: Duration,
    ) -> Result<Vec<(BrowserHandle, Result<BrowserCleanup>)>> {
        let until = Instant::now() + budget.min(Duration::from_secs(30));
        let mut results = Vec::new();
        for handle in self.handles()? {
            let result = self
                .cleanup_owned(&handle, until.saturating_duration_since(Instant::now()))
                .await;
            results.push((handle, result));
        }
        Ok(results)
    }
}
#[cfg(test)]
mod tests;
