//! Bounded Control-v1 management-read transport, not Desktop authentication.
//! Kernel credentials grant only ManagementRead. Identity DTOs never grant scope.
use crate::store::ProcessIdentity;
#[cfg(target_os = "linux")]
use serde::Deserialize;
use serde::Serialize;
use std::{future::Future, io::Write, pin::Pin, time::Duration};
use styx_contracts::{
    CONTROL_FRAME_BYTES, HOST_QUEUED_BYTES, PER_PEER_QUEUED_BYTES,
    control::*,
    error::{ErrorCategory, ErrorEnvelope, ExecutionCertainty, Recovery},
    identity::*,
};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{EndpointRoot, ManagementClient, ManagementServer};
#[cfg(not(target_os = "linux"))]
mod unsupported;
#[cfg(not(target_os = "linux"))]
pub use unsupported::{EndpointRoot, ManagementClient, ManagementServer};
mod stdio;
pub use stdio::BackendStdio;

/// Per connection: conservative geometric codec input allocation (two frames plus
/// read slack), decoded line, gate-parser scratch, typed-parser scratch, response.
/// Only read-call DTOs are fully parsed; denied Session descriptors are skipped.
/// No application request queue, concurrent requests, or unbounded encoder buffer.
pub const CONNECTION_WIRE_RESERVATION: usize =
    (2 * (CONTROL_FRAME_BYTES + 8192) + 4 * CONTROL_FRAME_BYTES).next_power_of_two();
pub const MAX_CONNECTIONS: usize = HOST_QUEUED_BYTES / CONNECTION_WIRE_RESERVATION;
const _: () = assert!(CONNECTION_WIRE_RESERVATION <= PER_PEER_QUEUED_BYTES);
const _: () = assert!(MAX_CONNECTIONS > 0);
#[derive(Clone, Debug, Serialize)]
pub struct ServerReport {
    pub accepted: u64,
    pub rejected_capacity: u64,
    pub rejected_identity: u64,
    pub rejected_frame: u64,
    pub denied_scope: u64,
    pub wait_expired: u64,
    pub socket_removed: bool,
}
pub const SOCKET_FILENAME: &str = "control-v1.sock";
const IO_DEADLINE: Duration = Duration::from_millis(MAX_RESPONSE_WAIT_MS as u64);

#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    #[error("IPC platform unsupported")]
    Unsupported,
    #[error("IPC endpoint identity or private permissions invalid")]
    EndpointIdentity,
    #[error("kernel peer did not match trusted identity")]
    PeerIdentity,
    #[error("management-read endpoint does not authorize this method")]
    Unauthorized,
    #[error("IPC frame or response invalid")]
    InvalidFrame,
    #[error("IPC frame exceeds budget")]
    FrameBudget,
    #[error("IPC wait expired; backend termination is not implied")]
    WaitExpired,
    #[error("IPC has a pending response; operation was not replayed")]
    PendingResponse,
    #[error("IPC response correlation mismatch")]
    Correlation,
    #[error("IPC connection closed")]
    Disconnected,
    #[error("owned child stdio unavailable")]
    MissingStdio,
    #[error("store validation failed")]
    Store(#[from] crate::store::StoreError),
    #[error("IPC I/O failed")]
    Io(#[from] std::io::Error),
}
pub type Result<T> = std::result::Result<T, IpcError>;

/// Construct from a trusted manager receipt/owned launch chain, never data sent
/// by the socket being authenticated. This type is deliberately not Deserialize.
#[derive(Clone, Debug)]
pub struct ExpectedServer {
    uid: u32,
    process: ProcessIdentity,
}
impl ExpectedServer {
    pub fn uid(&self) -> u32 {
        self.uid
    }
    pub fn process_identity(&self) -> &ProcessIdentity {
        &self.process
    }
    pub fn from_trusted_manager(uid: u32, process: ProcessIdentity) -> Self {
        Self { uid, process }
    }
}
/// Kernel evidence from the connector, not a self-asserted username or PID.
/// Linux SO_PEERCRED identifies connect-time credentials, not a per-message sender
/// after descriptor passing. This endpoint grants no Desktop/privileged scope.
#[derive(Clone, Debug)]
pub struct ReadPeer {
    uid: u32,
    gid: u32,
    pid: u32,
    process: ProcessIdentity,
}
impl ReadPeer {
    pub fn uid(&self) -> u32 {
        self.uid
    }
    pub fn gid(&self) -> u32 {
        self.gid
    }
    pub fn pid(&self) -> u32 {
        self.pid
    }
    pub fn process_identity(&self) -> &ProcessIdentity {
        &self.process
    }
    pub fn scope(&self) -> ControlScope {
        ControlScope::ManagementRead
    }
}
#[derive(Clone, Debug)]
pub enum ReadCall {
    Snapshot,
    Transaction { transaction_id: TransactionId },
}
#[derive(Clone, Debug)]
pub struct ReadRequest {
    pub request_id: RequestId,
    /// Correlation claim only. Not an authenticated remote owner or OS identity.
    pub client_instance: AgentInstanceId,
    pub call: ReadCall,
}
/// May be cancelled when the read wait expires. Must observe existing state only:
/// never dispatch/cancel mutations or make provider lifetime depend on this future.
pub trait ReadHandler: Send + Sync + 'static {
    fn read(
        &self,
        peer: ReadPeer,
        request: ReadRequest,
    ) -> Pin<Box<dyn Future<Output = ControlOutcome> + Send + '_>>;
}
impl<F, Fut> ReadHandler for F
where
    F: Fn(ReadPeer, ReadRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ControlOutcome> + Send + 'static,
{
    fn read(
        &self,
        peer: ReadPeer,
        request: ReadRequest,
    ) -> Pin<Box<dyn Future<Output = ControlOutcome> + Send + '_>> {
        Box::pin(self(peer, request))
    }
}
/// There is no success stub for Core methods not wired to a real adapter.
pub fn unsupported_read() -> ControlOutcome {
    error_outcome(
        ErrorCategory::CapabilityUnsupported,
        "read_adapter",
        ExecutionCertainty::NotDispatched,
        "This management query is not implemented by the connected adapter.",
    )
}
fn error_outcome(
    category: ErrorCategory,
    stage: &str,
    certainty: ExecutionCertainty,
    message: &str,
) -> ControlOutcome {
    ControlOutcome::Error(ErrorEnvelope {
        category,
        provider_code: None,
        stage: stage.into(),
        retry_class: Recovery::None,
        execution_certainty: certainty,
        operation_id: None,
        transaction_id: None,
        generation: None,
        public_message: message.into(),
    })
}
fn response(request_id: RequestId, outcome: ControlOutcome) -> ControlResponse {
    ControlResponse {
        protocol_version: CONTROL_PROTOCOL_VERSION,
        request_id,
        outcome,
    }
}

/// Thin bounded serializer, not a JSON/frame decoder. Check before allocation;
/// never serialize an arbitrary Value to an unbounded Vec then check its length.
struct BoundedJson {
    bytes: Vec<u8>,
}
impl Write for BoundedJson {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > CONTROL_FRAME_BYTES.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other("control_frame_budget"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut writer = BoundedJson {
        bytes: Vec::with_capacity(CONTROL_FRAME_BYTES),
    };
    serde_json::to_writer(&mut writer, value).map_err(|_| IpcError::FrameBudget)?;
    Ok(writer.bytes)
}
#[cfg(target_os = "linux")]
fn read_call(call: ControlCall) -> Result<ReadCall> {
    match call {
        ControlCall::ReadSnapshot => Ok(ReadCall::Snapshot),
        ControlCall::ReadTransaction { transaction_id } => {
            Ok(ReadCall::Transaction { transaction_id })
        }
        _ => Err(IpcError::Unauthorized),
    }
}
fn wait_budget(wait: Duration) -> Result<Duration> {
    if wait.is_zero() || wait > IO_DEADLINE {
        return Err(IpcError::InvalidFrame);
    }
    Ok(wait)
}

// Parse only the envelope/method before authorization. IgnoredAny does not build
// untrusted Session descriptor vectors/Values on this read-only endpoint.
#[cfg(target_os = "linux")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GateRequest {
    protocol_version: u16,
    client_instance: AgentInstanceId,
    request_id: RequestId,
    timeout_ms: u32,
    call: GateCall,
}
#[cfg(target_os = "linux")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GateCall {
    method: String,
    #[serde(default)]
    params: serde::de::IgnoredAny,
}
#[cfg(target_os = "linux")]
impl GateRequest {
    fn validate(&self) -> std::result::Result<(), ErrorCategory> {
        if self.protocol_version != CONTROL_PROTOCOL_VERSION {
            return Err(ErrorCategory::ProtocolMismatch);
        }
        if self.timeout_ms == 0 || self.timeout_ms > MAX_RESPONSE_WAIT_MS {
            return Err(ErrorCategory::InvalidRequest);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
