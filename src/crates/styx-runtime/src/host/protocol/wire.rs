//! Private Host wire DTOs; parsing these values alone grants no authority.
use serde::{Deserialize, Serialize};
use styx_contracts::{
    error::{ErrorCategory, ExecutionCertainty},
    identity::*,
    operation::*,
};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub request_id: RequestId,
    #[serde(default)]
    pub connection_generation: Option<ConnectionGeneration>,
    pub call: Call,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Call {
    Negotiate {
        version: u16,
        challenge: String,
        gateway_namespace: GatewayId,
        gateway_epoch: GatewayEpoch,
    },
    PrepareStart {
        owner: OwnerRef,
        grant_revision: u64,
        timeout_ms: u32,
        spec: Box<serde_json::value::RawValue>,
    },
    DispatchStart {
        owner: OwnerRef,
        target: ResourceTarget,
    },
    InspectStart {
        owner: OwnerRef,
        target: ResourceTarget,
    },
    Read {
        owner: OwnerRef,
        target: ResourceTarget,
        grant_revision: u64,
        timeout_ms: u32,
        max_bytes: u32,
        wait_ms: u32,
    },
    PrepareAction {
        owner: OwnerRef,
        target: ResourceTarget,
        grant_revision: u64,
        timeout_ms: u32,
        action: Box<serde_json::value::RawValue>,
    },
    DispatchAction {
        owner: OwnerRef,
        action: ActionRef,
    },
    InspectAction {
        owner: OwnerRef,
        action: ActionRef,
    },
    Browser {
        owner: OwnerRef,
        grant_revision: u64,
        timeout_ms: u32,
        command: BrowserCommand,
    },
    Computer {
        owner: OwnerRef,
        grant_revision: u64,
        timeout_ms: u32,
        command: ComputerCommand,
    },
    /// Same authenticated connection only; the Host first advertises support.
    EnableTransportDrain,
    /// Result of the one original transport drain, not a native-exit proof.
    TransportDrainResult {
        drain_id: RequestId,
        host_generation: HostGeneration,
        complete: bool,
    },
    OwnerOpen {
        owner: OwnerRef,
        grant_revision: u64,
    },
    OwnerRevoke {
        owner: OwnerRef,
    },
    OwnerCleanup {
        owner: OwnerRef,
        timeout_ms: u32,
    },
    // Direct native mutations have no authority; use Host prepare+dispatch.
    Write {},
    Terminate {},
}
pub const BROWSER_HEADLESS_V1: &str = "browser_headless_v1";
pub const COMPUTER_V1: &str = "computer_v1";
pub const TRANSPORT_DRAIN_V1: &str = "transport_drain_v1";
/// Private negotiated total stop budget, not a business-operation deadline.
pub(crate) const TRANSPORT_DRAIN_TIMEOUT_MS: u32 = 15_000;

/// Host-initiated request on the original authenticated socket. Identity and
/// authority come from the retained Entry, never these untrusted wire fields.
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostControl {
    TransportDrainV1 {
        drain_id: RequestId,
        connection_generation: ConnectionGeneration,
        host_generation: HostGeneration,
        timeout_ms: u32,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportDrainOutcome {
    Complete,
    Unknown,
    Unsupported,
}
/// Existing wait_for permits thirty seconds. Keep an explicit bounded margin
/// for provider settlement; ordinary operations and owner cleanup are unchanged.
pub(crate) const BROWSER_WAIT_PREPARE_TIMEOUT_MS: u32 = 35_000;
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub(crate) const BROWSER_WAIT_RESPONSE_SECS: u64 = 40;
impl Call {
    pub(crate) fn response_budget(&self) -> std::time::Duration {
        match self {
            Self::Browser { timeout_ms, .. } if *timeout_ms > 10_000 => {
                std::time::Duration::from_millis(
                    u64::from((*timeout_ms).min(BROWSER_WAIT_PREPARE_TIMEOUT_MS)) + 10_000,
                )
            }
            _ => std::time::Duration::from_secs(35),
        }
    }
    pub(crate) fn is_browser(&self) -> bool {
        matches!(self, Self::Browser { .. })
    }
    pub(crate) fn is_computer(&self) -> bool {
        matches!(self, Self::Computer { .. })
    }
}
/// Additive private v3 feature. No paths, credentials or native profile choices
/// are accepted from a wire peer; prepare/dispatch stay distinct Core actions.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum BrowserCommand {
    PrepareOpen,
    DispatchOpen {
        target: ResourceTarget,
    },
    InspectOpen {
        target: ResourceTarget,
    },
    PrepareAction {
        target: ResourceTarget,
        action: Box<serde_json::value::RawValue>,
    },
    DispatchAction {
        action: ActionRef,
    },
    InspectAction {
        action: ActionRef,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ComputerCommand {
    PrepareOpen,
    DispatchOpen {
        target: ResourceTarget,
    },
    InspectOpen {
        target: ResourceTarget,
    },
    PrepareAction {
        target: ResourceTarget,
        action: Box<serde_json::value::RawValue>,
    },
    DispatchAction {
        action: ActionRef,
    },
    InspectAction {
        action: ActionRef,
    },
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerRef {
    pub owner_id: OwnerId,
    pub owner_epoch: OwnerEpoch,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionRef {
    pub operation_id: OperationId,
    pub payload_digest: Sha256Digest,
}
#[derive(Serialize, Deserialize)]
pub struct Snapshot {
    pub operation_id: OperationId,
    pub payload_digest: Sha256Digest,
    pub target: Option<ResourceTarget>,
    pub state: OperationState,
    pub liveness: ExecutionLiveness,
    pub output_drain: OutputDrain,
}
#[derive(Serialize, Deserialize)]
pub struct Chunk {
    pub stream: String,
    pub text: String,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Reply {
    Negotiated {
        version: u16,
        challenge: String,
        device_id: DeviceId,
        host_generation: HostGeneration,
        connection_generation: ConnectionGeneration,
        features: Vec<String>,
        write: bool,
        terminate: bool,
        read_resume: bool,
        owner_issuance: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        grant_revision: Option<u64>,
    },
    TransportDrainEnabled,
    TransportDrainResultAccepted {
        drain_id: RequestId,
    },
    OwnerOpened {
        owner: OwnerRef,
        grant_revision: u64,
    },
    OwnerRevoked {
        owner: OwnerRef,
        fenced: bool,
        cleanup: String,
    },
    OwnerCleanup {
        owner: OwnerRef,
        complete: bool,
    },
    Prepared {
        snapshot: Snapshot,
    },
    /// Host/Core may translate a presentation alias into a private native token.
    /// Bind the original request independently from the canonical Core payload.
    ComputerPrepared {
        request_digest: Sha256Digest,
        snapshot: Snapshot,
    },
    Start {
        snapshot: Snapshot,
        dispatch: String,
    },
    Inspected {
        snapshot: Snapshot,
    },
    Read {
        chunks: Vec<Chunk>,
        liveness: ExecutionLiveness,
        output_drain: OutputDrain,
        exit_code: Option<i32>,
        read_resume: bool,
    },
    Action {
        snapshot: Snapshot,
        dispatch: String,
        acknowledgment: Option<ActionAcknowledgmentDto>,
        write_id: Option<String>,
    },
    BrowserAction {
        snapshot: Snapshot,
        dispatch: String,
        result: Option<serde_json::Value>,
        cause: Option<ErrorCategory>,
        cleanup_complete: Option<bool>,
    },
    ComputerAction {
        snapshot: Snapshot,
        dispatch: String,
        result: Option<serde_json::Value>,
        cause: Option<ErrorCategory>,
        cleanup_complete: Option<bool>,
    },
    Unsupported {
        feature: String,
    },
    Error {
        category: ErrorCategory,
        certainty: ExecutionCertainty,
        cursor_may_be_consumed: bool,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ActionAcknowledgmentDto {
    WriteAccepted,
    // Request acknowledgment, never process-exit proof.
    TerminateRequested { was_running: bool },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub request_id: RequestId,
    pub connection_generation: ConnectionGeneration,
    pub reply: Reply,
}
