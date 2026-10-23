//! A bounded native Codex Exec Server stdio adapter, not an authorization service.
//!
//! The Core caller must validate its current OwnerLease and dispatch ledger on
//! every call. This adapter only binds executor resources to that opaque lease
//! and OperationId, reports facts, and never replays a mutation or respawns an
//! executor. `spawn_owned` starts a NEW caller-owned executor; no live executor
//! is discovered, adopted, restarted or replaced.
mod continuation;
mod output;
mod rpc;
use base64::{Engine as _, engine::general_purpose::STANDARD};
pub use continuation::{ActionAcknowledgment, ActionEvidence, ActionReceipt, ProcessAction};
pub use output::OutputChunk;
use output::{OutputDecoder, ReadPage};
use rpc::Rpc;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use styx_contracts::identity::Sha256Digest;
use styx_contracts::operation::{ExecutionLiveness, OperationId, OutputDrain};
use styx_core::operations::{DispatchPermit, OwnerLease};
use tokio::process::{Child, Command};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExecError {
    #[error("invalid prepared executor request")]
    InvalidRequest,
    #[error("executor capacity exhausted")]
    Capacity,
    #[error("executor transport lost; no automatic replay")]
    TransportLost,
    #[error("request could not emit any action frame bytes")]
    NotSent,
    #[error("executor request timed out; outcome unknown")]
    TimeoutUnknown,
    #[error("invalid bounded executor protocol frame")]
    InvalidFrame,
    #[error("executor rejected request ({0})")]
    Rejected(i64),
    #[error("resource does not belong to this verified owner lease")]
    OwnerMismatch,
    #[error("unknown executor handle")]
    UnknownHandle,
    #[error("operation was already dispatched; no replay")]
    AlreadyDispatched,
    #[error("executor process record lost; outcome unknown")]
    ProcessLost,
    #[error("prior stdin mutation has unknown outcome; no replay")]
    InputUnknown,
    #[error("executor reported a process failure")]
    ProcessFailure,
    #[error("owned executor could not start")]
    SpawnFailed,
    #[error("resource is live, unread, or has unknown mutations")]
    ResourceUnsettled,
    #[error("raw and decoded reads cannot consume the same process")]
    ReadModeMismatch,
}
/// This configuration is from the native Host, never tool/network parameters.
pub struct OwnedExecutorConfig {
    pub binary: PathBuf,
    pub cwd: PathBuf,
    pub environment: BTreeMap<String, String>,
    pub rpc_timeout: Duration,
    /// Bounded retained operation resources (including exited unread handles).
    /// Exhaustion is reported; resources are never evicted to permit a replay.
    pub retained_process_limit: usize,
}
/// Already-authorized exact argv/environment/file URI, not public tool arguments.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartProcess {
    pub argv: Vec<String>,
    pub cwd_file_uri: String,
    pub environment: BTreeMap<String, String>,
    pub tty: bool,
}
impl StartProcess {
    pub fn to_operation_payload(&self) -> Result<Vec<u8>, ExecError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| ExecError::InvalidRequest)
    }
    fn validate(&self) -> Result<(), ExecError> {
        if self.cwd_file_uri.len() > 16384 || self.cwd_file_uri.to_ascii_lowercase().contains("%00")
        {
            return Err(ExecError::InvalidRequest);
        }
        if self.argv.is_empty()
            || self.argv[0].is_empty()
            || self.argv.iter().any(|x| x.contains('\0'))
            || self.argv.iter().map(String::len).sum::<usize>() > 65536
        {
            return Err(ExecError::InvalidRequest);
        }
        let cwd = url::Url::parse(&self.cwd_file_uri).map_err(|_| ExecError::InvalidRequest)?;
        if cwd.scheme() != "file"
            || cwd.query().is_some()
            || cwd.fragment().is_some()
            || !cwd.username().is_empty()
            || cwd.password().is_some()
            || cwd
                .host_str()
                .is_some_and(|h| !h.is_empty() && h != "localhost")
            || !cwd.path().starts_with('/')
        {
            return Err(ExecError::InvalidRequest);
        }
        if self
            .environment
            .iter()
            .any(|(k, v)| k.is_empty() || k.contains(['\0', '=']) || v.contains('\0'))
        {
            return Err(ExecError::InvalidRequest);
        }
        // The caller supplies a prepared least-privilege env; the adapter must
        // not silently inherit native Host credentials or session variables.
        if serde_json::to_vec(&self.environment)
            .map_err(|_| ExecError::InvalidRequest)?
            .len()
            > 65536
        {
            return Err(ExecError::InvalidRequest);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessHandle {
    process_id: String,
    operation: OperationId,
}
impl ProcessHandle {
    pub fn process_uuid(&self) -> &str {
        &self.process_id
    }
    pub fn operation(&self) -> &OperationId {
        &self.operation
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchEvidence {
    NotDispatched,
    Started,
    Unknown,
}
#[derive(Debug)]
pub struct StartReceipt {
    pub handle: ProcessHandle,
    pub dispatch: DispatchEvidence,
    pub cause: Option<ExecError>,
}
#[derive(Debug)]
pub struct StartFailure {
    pub operation: OperationId,
    pub evidence: DispatchEvidence,
    pub error: ExecError,
}
#[derive(Debug)]
pub struct ProcessOutput {
    pub chunks: Vec<OutputChunk>,
    pub liveness: ExecutionLiveness,
    pub drain: OutputDrain,
    pub exit_code: Option<i32>,
}
/// A validated native process/read response, including its original base64,
/// sequence numbers, optional-field presence and unknown extension fields.
/// This is not an arbitrary executor RPC capability.
#[derive(Debug)]
pub struct RawProcessPage {
    native: Value,
}
impl RawProcessPage {
    pub fn as_native(&self) -> &Value {
        &self.native
    }
    pub fn into_native(self) -> Value {
        self.native
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum ReadMode {
    Decoded,
    Raw,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminationEvidence {
    ProcessExited(i32),
    Unknown,
}
#[derive(Debug)]
pub struct CleanupReceipt {
    pub processes: Vec<(ProcessHandle, TerminationEvidence)>,
    pub executor_exited: bool,
    pub reader_task_reaped: bool,
    pub stderr_task_reaped: bool,
}
struct Record {
    read_mode: Option<ReadMode>,
    cursor: Option<u64>,
    gaps: u64,
    decoder: OutputDecoder,
    drained: bool,
    input_unknown: Option<OperationId>,
    last_exit: Option<i32>,
}
impl Record {
    fn select_read_mode(&mut self, mode: ReadMode) -> Result<(), ExecError> {
        if self.read_mode.is_some_and(|current| current != mode) {
            return Err(ExecError::ReadModeMismatch);
        }
        self.read_mode = Some(mode);
        Ok(())
    }
}
struct Resource {
    start_digest: Sha256Digest,
    owner: OwnerLease,
    handle: ProcessHandle,
    state: Arc<tokio::sync::Mutex<Record>>,
}
type Records = HashMap<String, Arc<Resource>>;
pub struct CodexStdio {
    rpc: Arc<Rpc>,
    _rpc_partition: Arc<tokio::sync::OwnedSemaphorePermit>,
    child: tokio::sync::Mutex<Option<Child>>,
    stderr_task: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    records: Mutex<Records>,
    actions: Mutex<continuation::ActionRecords>,
    operations: Mutex<BTreeMap<OperationId, ProcessHandle>>,
    limit: usize,
    session_id: String,
    provider_id: String,
}
impl CodexStdio {
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }
    /// Standalone adapter convenience. Host composition must provide its own
    /// reserved partition through spawn_owned_with_reserved_budget instead.
    pub async fn spawn_owned(config: OwnedExecutorConfig) -> Result<Self, ExecError> {
        let partition = Arc::new(tokio::sync::Semaphore::new(16 * 1024 * 1024))
            .try_acquire_many_owned(16 * 1024 * 1024)
            .map_err(|_| ExecError::Capacity)?;
        Self::spawn_owned_with_reserved_budget(config, partition).await
    }
    /// One exclusive, conservatively sized RPC partition from the Host budget.
    pub async fn spawn_owned_with_reserved_budget(
        config: OwnedExecutorConfig,
        partition: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<Self, ExecError> {
        if partition.num_permits() != 16 * 1024 * 1024 {
            return Err(ExecError::InvalidRequest);
        }
        let partition = Arc::new(partition);
        if !config.binary.is_absolute()
            || !config.cwd.is_absolute()
            || config.rpc_timeout.is_zero()
            || config.rpc_timeout > Duration::from_secs(60)
            || config.retained_process_limit == 0
            || config.retained_process_limit > 4096
        {
            return Err(ExecError::InvalidRequest);
        }
        let mut child = Command::new(&config.binary)
            .args(["exec-server", "--listen", "stdio://"])
            .current_dir(&config.cwd)
            .env_clear()
            .envs(config.environment)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| ExecError::SpawnFailed)?;
        let stdin = child.stdin.take().ok_or(ExecError::SpawnFailed)?;
        let stdout = child.stdout.take().ok_or(ExecError::SpawnFailed)?;
        let stderr_task = child.stderr.take().map(|mut stderr| {
            let stderr_partition = partition.clone();
            tokio::spawn(async move {
                let _partition = stderr_partition;
                let _ = tokio::io::copy(&mut stderr, &mut tokio::io::sink()).await;
            })
        });
        let rpc = Rpc::new_with_reserved_partition(
            stdin,
            stdout,
            config.rpc_timeout,
            config.retained_process_limit,
            partition.clone(),
        );
        let initialized = match rpc
            .request("initialize", json!({"clientName":"styx-rust-native-host"}))
            .await
        {
            Ok(v) => v,
            Err(e) => {
                rpc.close().await;
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(e);
            }
        };
        let identity = |v: &Value| {
            v.as_str()
                .filter(|s| !s.is_empty() && s.len() <= 512)
                .map(str::to_owned)
                .ok_or(ExecError::InvalidFrame)
        };
        let (session_id, provider_id) = match (
            identity(&initialized["sessionId"]),
            identity(&initialized["environmentInfo"]["providerId"]),
        ) {
            (Ok(s), Ok(p)) => (s, p),
            _ => {
                rpc.close().await;
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(ExecError::InvalidFrame);
            }
        };
        if let Err(e) = rpc.notify("initialized").await {
            rpc.close().await;
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err(e);
        }
        Ok(Self {
            rpc,
            _rpc_partition: partition,
            child: tokio::sync::Mutex::new(Some(child)),
            stderr_task: tokio::sync::Mutex::new(stderr_task),
            records: Mutex::new(HashMap::new()),
            actions: Mutex::new(BTreeMap::new()),
            operations: Mutex::new(BTreeMap::new()),
            limit: config.retained_process_limit,
            session_id,
            provider_id,
        })
    }
    pub async fn start(&self, permit: DispatchPermit) -> Result<StartReceipt, StartFailure> {
        let operation = permit.id().clone();
        let not_dispatched = |error| StartFailure {
            operation: operation.clone(),
            evidence: DispatchEvidence::NotDispatched,
            error,
        };
        if permit.target().is_some()
            || permit.context().capability != styx_contracts::capability::CapabilityId::ExecRun
        {
            // A continuation owns no new process. Even a valid StartProcess
            // payload cannot turn a target-bound action permit into a start.
            return Err(not_dispatched(ExecError::InvalidRequest));
        }
        if permit.payload().len() > styx_contracts::EXEC_FRAME_BYTES {
            return Err(not_dispatched(ExecError::InvalidRequest));
        }
        let spec: StartProcess = serde_json::from_slice(permit.payload())
            .map_err(|_| not_dispatched(ExecError::InvalidRequest))?;
        spec.validate().map_err(not_dispatched)?;
        let owner = permit.owner().clone();
        let handle = ProcessHandle {
            process_id: Uuid::new_v4().to_string(),
            operation: operation.clone(),
        };
        {
            let mut operations = self.operations.lock().expect("operation mutex");
            if operations.contains_key(&operation) {
                return Err(StartFailure {
                    operation,
                    evidence: DispatchEvidence::Unknown,
                    error: ExecError::AlreadyDispatched,
                });
            }
            if operations.len() >= self.limit {
                return Err(not_dispatched(ExecError::Capacity));
            }
            operations.insert(operation.clone(), handle.clone());
        }
        let resource = Arc::new(Resource {
            start_digest: Sha256Digest::of_bytes(permit.payload()),
            owner,
            handle: handle.clone(),
            state: Arc::new(tokio::sync::Mutex::new(Record {
                read_mode: None,
                cursor: None,
                gaps: 0,
                decoder: OutputDecoder::default(),
                drained: false,
                input_unknown: None,
                last_exit: None,
            })),
        });
        self.records
            .lock()
            .expect("records mutex")
            .insert(handle.process_id.clone(), resource);
        if let Err(error) = self.rpc.register(&handle.process_id) {
            self.discard_unstarted(&handle);
            return Err(not_dispatched(error));
        }
        // Registration precedes the first action byte so start cancellation can
        // be reconciled via lookup_operation, never by dispatching again.
        let result=self.rpc.request("process/start",json!({"processId":handle.process_id,"argv":spec.argv,"cwd":spec.cwd_file_uri,"env":spec.environment,"envPolicy":{"inherit":"none","ignoreDefaultExcludes":false,"exclude":[],"set":{},"includeOnly":[]},"tty":spec.tty,"pipeStdin":!spec.tty,"arg0":null})).await;
        match result {
            Ok(reply)
                if reply.get("processId").and_then(Value::as_str) == Some(&handle.process_id) =>
            {
                Ok(StartReceipt {
                    handle,
                    dispatch: DispatchEvidence::Started,
                    cause: None,
                })
            }
            Err(error @ (ExecError::NotSent | ExecError::Capacity | ExecError::InvalidRequest)) => {
                self.discard_unstarted(&handle);
                Err(not_dispatched(error))
            }
            Err(error) => Ok(StartReceipt {
                handle,
                dispatch: DispatchEvidence::Unknown,
                cause: Some(error),
            }),
            Ok(_) => Ok(StartReceipt {
                handle,
                dispatch: DispatchEvidence::Unknown,
                cause: Some(ExecError::InvalidFrame),
            }),
        }
    }
    fn discard_unstarted(&self, handle: &ProcessHandle) {
        self.records
            .lock()
            .expect("records mutex")
            .remove(&handle.process_id);
        self.operations
            .lock()
            .expect("operation mutex")
            .remove(&handle.operation);
        self.rpc.unregister(&handle.process_id);
    }
    async fn owned(
        &self,
        owner: &OwnerLease,
        handle: &ProcessHandle,
    ) -> Result<tokio::sync::OwnedMutexGuard<Record>, ExecError> {
        let record = self
            .records
            .lock()
            .expect("records mutex")
            .get(&handle.process_id)
            .cloned()
            .ok_or(ExecError::UnknownHandle)?;
        if &record.owner != owner || record.handle != *handle {
            return Err(ExecError::OwnerMismatch);
        }
        Ok(record.state.clone().lock_owned().await)
    }
    /// Read-only recovery for a cancelled start future. Never re-dispatches.
    pub async fn lookup_operation(
        &self,
        owner: &OwnerLease,
        operation: &OperationId,
    ) -> Result<ProcessHandle, ExecError> {
        let handle = self
            .operations
            .lock()
            .expect("operation mutex")
            .get(operation)
            .cloned()
            .ok_or(ExecError::UnknownHandle)?;
        let resource = self
            .records
            .lock()
            .expect("records mutex")
            .get(&handle.process_id)
            .cloned()
            .ok_or(ExecError::UnknownHandle)?;
        if &resource.owner != owner {
            return Err(ExecError::OwnerMismatch);
        }
        Ok(handle)
    }
    pub async fn read(
        &self,
        owner: &OwnerLease,
        handle: &ProcessHandle,
        max_bytes: usize,
        wait: Duration,
    ) -> Result<ProcessOutput, ExecError> {
        if max_bytes == 0 || max_bytes > 65536 || wait > Duration::from_secs(1) {
            return Err(ExecError::InvalidRequest);
        }
        let mut record = self.owned(owner, handle).await?;
        record.select_read_mode(ReadMode::Decoded)?;
        if record.drained {
            if let Some(observation) = self.rpc.observation(&handle.process_id) {
                if observation.invalid {
                    return Err(ExecError::InvalidFrame);
                }
                if record.last_exit.is_none() {
                    record.last_exit = observation.exited.map(|(_, code)| code);
                }
                if record.last_exit.is_some() {
                    self.rpc.unregister(&handle.process_id);
                }
            }
            return Ok(ProcessOutput {
                chunks: vec![],
                liveness: if record.last_exit.is_some() {
                    ExecutionLiveness::Exited
                } else {
                    ExecutionLiveness::Unknown
                },
                drain: OutputDrain::Drained,
                exit_code: record.last_exit,
            });
        }
        let reply=self.rpc.request("process/read",json!({"processId":handle.process_id,"afterSeq":record.cursor,"maxBytes":max_bytes,"waitMs":wait.as_millis() as u64})).await?;
        let page: ReadPage = serde_json::from_value(reply).map_err(|_| ExecError::InvalidFrame)?;
        let validated = output::validate(&page, record.cursor, record.gaps, max_bytes)?;
        if page.failure.is_some() {
            return Err(ExecError::ProcessFailure);
        }
        let observation = self
            .rpc
            .observation(&handle.process_id)
            .ok_or(ExecError::UnknownHandle)?;
        if observation.invalid {
            return Err(ExecError::InvalidFrame);
        }
        let drained = page.closed && page.chunks.is_empty();
        let chunks = record.decoder.decode(validated.chunks, drained)?;
        record.cursor = Some(validated.cursor);
        record.gaps = validated.gaps;
        record.drained = drained;
        if page.exited {
            record.last_exit = page.exit_code;
        }
        // A closed pipe does not imply process exit. Native process/read or an
        // authenticated process/exited notification must independently prove it.
        if record.last_exit.is_none() {
            record.last_exit = observation.exited.map(|(_, code)| code);
        }
        if record.drained && record.last_exit.is_some() {
            self.rpc.unregister(&handle.process_id);
        }
        let liveness = if record.last_exit.is_some() {
            ExecutionLiveness::Exited
        } else if page.closed || observation.lost {
            ExecutionLiveness::Unknown
        } else {
            ExecutionLiveness::Running
        };
        Ok(ProcessOutput {
            chunks,
            liveness,
            drain: if drained {
                OutputDrain::Drained
            } else {
                OutputDrain::Open
            },
            exit_code: record.last_exit,
        })
    }
    /// Read the native page using the caller's cursor, never the decoded
    /// consumer's cursor or a synthesized drained cache. The Core coordinator
    /// must still validate current authority on every continuation.
    pub async fn read_raw(
        &self,
        owner: &OwnerLease,
        handle: &ProcessHandle,
        after_seq: Option<u64>,
        max_bytes: usize,
        wait: Duration,
    ) -> Result<RawProcessPage, ExecError> {
        if max_bytes == 0 || max_bytes > 65536 || wait > Duration::from_secs(1) {
            return Err(ExecError::InvalidRequest);
        }
        let mut record = self.owned(owner, handle).await?;
        // Select before the first await that can emit an RPC. Cancelling a
        // waiting read does not grant another consumer access to this process.
        record.select_read_mode(ReadMode::Raw)?;
        let native = self
            .rpc
            .request(
                "process/read",
                json!({
                    "processId": handle.process_id, "afterSeq": after_seq,
                    "maxBytes": max_bytes, "waitMs": wait.as_millis() as u64
                }),
            )
            .await?;
        let page: ReadPage =
            serde::Deserialize::deserialize(&native).map_err(|_| ExecError::InvalidFrame)?;
        // Validation is per request: repeats and earlier cursors remain native
        // read-only operations, not consumption of the decoded stream.
        output::validate(&page, after_seq, 0, max_bytes)?;
        let observation = self
            .rpc
            .observation(&handle.process_id)
            .ok_or(ExecError::UnknownHandle)?;
        if observation.invalid {
            return Err(ExecError::InvalidFrame);
        }
        let observed_exit = observation.exited.map(|(_, code)| code);
        if page
            .exit_code
            .zip(observed_exit)
            .is_some_and(|(a, b)| a != b)
        {
            return Err(ExecError::InvalidFrame);
        }
        let exit = page.exit_code.or(observed_exit);
        if record
            .last_exit
            .zip(exit)
            .is_some_and(|(old, new)| old != new)
        {
            return Err(ExecError::InvalidFrame);
        }
        record.last_exit = record.last_exit.or(exit);
        record.drained |= page.closed && page.chunks.is_empty();
        // Keep the bounded observer until explicit retirement/cleanup. A caller
        // may still request a real earlier page after EOF. Failure is preserved
        // in the page, never recast as a fabricated success or generic RPC error.
        Ok(RawProcessPage { native })
    }
    #[cfg(test)]
    async fn write_stdin(
        &self,
        owner: &OwnerLease,
        handle: &ProcessHandle,
        input: &[u8],
    ) -> Result<(), ExecError> {
        if input.is_empty() || input.len() > 65536 {
            return Err(ExecError::InvalidRequest);
        }
        let mut record = self.owned(owner, handle).await?;
        if record.input_unknown.is_some() {
            return Err(ExecError::InputUnknown);
        }
        if record.last_exit.is_some() || record.drained {
            return Err(ExecError::InvalidRequest);
        }
        // Set before the mutation's first await. Dropping this future after
        // dispatch must preserve uncertainty instead of permitting another write.
        record.input_unknown = Some(handle.operation.clone());
        let result=self.rpc.request("process/write",json!({"processId":handle.process_id,"writeId":Uuid::new_v4().to_string(),"chunk":STANDARD.encode(input)})).await;
        match result {
            Ok(v) if v.get("status").and_then(Value::as_str) == Some("accepted") => {
                record.input_unknown = None;
                Ok(())
            }
            Err(
                e @ (ExecError::Rejected(_)
                | ExecError::Capacity
                | ExecError::InvalidRequest
                | ExecError::NotSent),
            ) => {
                record.input_unknown = None;
                Err(e)
            }
            _ => {
                record.input_unknown = Some(handle.operation.clone());
                Err(ExecError::InputUnknown)
            }
        }
    }
    async fn cancel(
        &self,
        owner: &OwnerLease,
        handle: &ProcessHandle,
        deadline: Duration,
    ) -> Result<TerminationEvidence, ExecError> {
        if deadline.is_zero() || deadline > Duration::from_secs(10) {
            return Err(ExecError::InvalidRequest);
        }
        // Only a process/read.exited fact below can confirm cancellation, never
        // a terminate acknowledgement or stdout/PTY closure.
        let until = tokio::time::Instant::now() + deadline;
        let cancel = async {
            let mut record = self.owned(owner, handle).await?;
            if let Some(code) = record.last_exit {
                return Ok(TerminationEvidence::ProcessExited(code));
            }
            if let Some(observation) = self.rpc.observation(&handle.process_id) {
                if observation.invalid {
                    return Ok(TerminationEvidence::Unknown);
                }
                if let Some((_, code)) = observation.exited {
                    record.last_exit = Some(code);
                    return Ok(TerminationEvidence::ProcessExited(code));
                }
            }
            let _ = self
                .rpc
                .request("process/terminate", json!({"processId":handle.process_id}))
                .await;
            loop {
                let reply=self.rpc.request("process/read",json!({"processId":handle.process_id,"afterSeq":null,"maxBytes":65536,"waitMs":50})).await?;
                let page: ReadPage =
                    serde_json::from_value(reply).map_err(|_| ExecError::InvalidFrame)?;
                output::validate(&page, None, 0, 65536)?;
                if page.failure.is_some() {
                    return Ok::<TerminationEvidence, ExecError>(TerminationEvidence::Unknown);
                }
                if let Some(code) = page.exit_code.filter(|_| page.exited) {
                    record.last_exit = Some(code);
                    return Ok(TerminationEvidence::ProcessExited(code));
                }
                if page.closed {
                    return Ok::<TerminationEvidence, ExecError>(TerminationEvidence::Unknown);
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        match tokio::time::timeout_at(until, cancel).await {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(error @ (ExecError::OwnerMismatch | ExecError::UnknownHandle))) => Err(error),
            _ => Ok(TerminationEvidence::Unknown),
        }
    }
    /// Retire a fully observed resource. Core's linear DispatchPermit and
    /// authoritative ledger retain old-operation rejection after this cleanup.
    pub async fn retire(
        &self,
        owner: &OwnerLease,
        handle: &ProcessHandle,
    ) -> Result<(), ExecError> {
        let record = self.owned(owner, handle).await?;
        if !record.drained || record.last_exit.is_none() || record.input_unknown.is_some() {
            return Err(ExecError::ResourceUnsettled);
        }
        self.records
            .lock()
            .expect("records mutex")
            .remove(&handle.process_id);
        self.operations
            .lock()
            .expect("operation mutex")
            .remove(&handle.operation);
        self.rpc.unregister(&handle.process_id);
        Ok(())
    }
    /// Stops only resources/executor created by this instance; unknown process
    /// termination is returned explicitly even if the owned executor then exits.
    pub async fn shutdown_owned(&self, budget: Duration) -> CleanupReceipt {
        let until = tokio::time::Instant::now() + budget.min(Duration::from_secs(30));
        let records = self
            .records
            .lock()
            .expect("records mutex")
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let mut processes = vec![];
        for record in records {
            let remaining = until.saturating_duration_since(tokio::time::Instant::now());
            let result = if remaining.is_zero() {
                TerminationEvidence::Unknown
            } else {
                self.cancel(
                    &record.owner,
                    &record.handle,
                    remaining.min(Duration::from_secs(2)),
                )
                .await
                .unwrap_or(TerminationEvidence::Unknown)
            };
            processes.push((record.handle.clone(), result));
        }
        let _ = tokio::time::timeout_at(until, self.rpc.close()).await;
        self.rpc.fail(ExecError::TransportLost);
        let mut executor_exited = false;
        if let Ok(mut child_guard) = tokio::time::timeout_at(until, self.child.lock()).await
            && let Some(mut child) = child_guard.take()
        {
            if tokio::time::timeout_at(until, child.wait())
                .await
                .is_ok_and(|r| r.is_ok())
            {
                executor_exited = true;
            } else {
                let _ = child.start_kill();
                if tokio::time::timeout_at(until, child.wait())
                    .await
                    .is_ok_and(|r| r.is_ok())
                {
                    executor_exited = true;
                }
            }
            if !executor_exited {
                *child_guard = Some(child);
            }
        }
        let reader_task_reaped = self.rpc.finish_reader(until).await;
        let stderr_task_reaped = if let Ok(mut task_guard) =
            tokio::time::timeout_at(until, self.stderr_task.lock()).await
        {
            if let Some(mut task) = task_guard.take() {
                match tokio::time::timeout_at(until, &mut task).await {
                    Ok(result) => result.is_ok(),
                    Err(_) => {
                        task.abort();
                        if task.is_finished() {
                            task.await.is_err_and(|e| e.is_cancelled())
                        } else {
                            *task_guard = Some(task);
                            false
                        }
                    }
                }
            } else {
                true
            }
        } else {
            false
        };
        CleanupReceipt {
            processes,
            executor_exited,
            reader_task_reaped,
            stderr_task_reaped,
        }
    }
}
#[cfg(test)]
mod tests;
