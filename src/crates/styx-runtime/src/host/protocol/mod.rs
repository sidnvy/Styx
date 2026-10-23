//! Private, explicitly negotiated Host protocol slice. Not public MCP and not
//! complete Host v2: owners are still bootstrap-preverified; resource reads
//! are not resumable. Every mutation uses separate Host prepare/dispatch.
//! Connection loss never shuts down the coordinator/executor or replays reads.
use super::{
    coordinator::{
        ActionSubmission, CoordinatorError, HostAuthority, HostCoordinator, StartSubmission,
    },
    link::{HostWssLink, LinkEndpoint},
};
use crate::providers::codex::{
    ActionAcknowledgment, ActionEvidence, ActionReceipt, DispatchEvidence, ProcessAction,
    StartProcess,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, io::Write, time::Duration};
use styx_contracts::{
    capability::CapabilityId,
    error::{ErrorCategory, ExecutionCertainty},
    identity::*,
    operation::*,
};
use styx_core::operations::{OperationSnapshot, OwnerLease};

const FRAME_LIMIT: usize = 256 * 1024;
const SPEC_LIMIT: usize = 128 * 1024;
const RESPONSE_LIMIT: usize = 128 * 1024;
const OWNER_LIMIT: usize = 128;

/// All fields come from protected bootstrap configuration, never wire hello.
/// Epoch is scoped to this fixed Gateway namespace and Host generation.
pub struct TrustedProfile {
    pub endpoint: String,
    pub gateway_namespace: GatewayId,
    pub gateway_epoch: GatewayEpoch,
    pub device_id: DeviceId,
    pub host_generation: HostGeneration,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProtocolError {
    #[error("trusted bootstrap binding does not match Host or link")]
    BootstrapMismatch,
    #[error("invalid bounded Host protocol frame")]
    InvalidFrame,
    #[error("explicit Host protocol negotiation required or rejected")]
    NegotiationRejected,
    #[error("connection handler capacity exhausted")]
    Busy,
    #[error("connection response lost; operation/read must not be replayed")]
    ResponseLost,
    #[error("verified bootstrap owner registration rejected")]
    OwnerRegistrationRejected,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request<'a> {
    request_id: RequestId,
    #[serde(default)]
    connection_generation: Option<ConnectionGeneration>,
    #[serde(borrow)]
    call: Call<'a>,
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum Call<'a> {
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
        #[serde(borrow)]
        spec: &'a serde_json::value::RawValue,
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
        #[serde(borrow)]
        action: &'a serde_json::value::RawValue,
    },
    DispatchAction {
        owner: OwnerRef,
        action: ActionRef,
    },
    InspectAction {
        owner: OwnerRef,
        action: ActionRef,
    },
    // Direct native mutations have no authority; use Host prepare+dispatch.
    Write {},
    Terminate {},
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerRef {
    owner_id: OwnerId,
    owner_epoch: OwnerEpoch,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionRef {
    operation_id: OperationId,
    payload_digest: Sha256Digest,
}
#[derive(Serialize)]
struct Snapshot {
    operation_id: OperationId,
    payload_digest: Sha256Digest,
    target: Option<ResourceTarget>,
    state: OperationState,
    liveness: ExecutionLiveness,
    output_drain: OutputDrain,
}
impl From<OperationSnapshot> for Snapshot {
    fn from(value: OperationSnapshot) -> Self {
        Self {
            operation_id: value.id,
            payload_digest: value.payload_digest,
            target: value.target,
            state: value.state,
            liveness: value.liveness,
            output_drain: value.output_drain,
        }
    }
}
#[derive(Serialize)]
struct Chunk {
    stream: String,
    text: String,
}
#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Reply {
    Negotiated {
        version: u16,
        challenge: String,
        device_id: DeviceId,
        host_generation: HostGeneration,
        connection_generation: ConnectionGeneration,
        features: &'static [&'static str],
        write: bool,
        terminate: bool,
        read_resume: bool,
        owner_issuance: &'static str,
    },
    Prepared {
        snapshot: Snapshot,
    },
    Start {
        snapshot: Snapshot,
        dispatch: &'static str,
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
        dispatch: &'static str,
        acknowledgment: Option<ActionAcknowledgmentDto>,
        write_id: Option<String>,
    },
    Unsupported {
        feature: &'static str,
    },
    Error {
        category: ErrorCategory,
        certainty: ExecutionCertainty,
        cursor_may_be_consumed: bool,
    },
}
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ActionAcknowledgmentDto {
    WriteAccepted,
    // Request acknowledgment, never process-exit proof.
    TerminateRequested { was_running: bool },
}
fn action_reply(
    snapshot: OperationSnapshot,
    receipt: Option<ActionReceipt>,
    existing: bool,
) -> Reply {
    let dispatch = if existing {
        "existing_no_replay"
    } else {
        match receipt.as_ref().map(|r| r.evidence) {
            Some(ActionEvidence::Acknowledged) => "acknowledged",
            Some(ActionEvidence::NotDispatched) => "not_dispatched",
            Some(ActionEvidence::Unknown) | None => "unknown",
        }
    };
    let acknowledgment = receipt
        .as_ref()
        .and_then(|r| r.acknowledgment.as_ref())
        .map(|ack| match ack {
            ActionAcknowledgment::WriteAccepted => ActionAcknowledgmentDto::WriteAccepted,
            ActionAcknowledgment::TerminateRequested { was_running } => {
                ActionAcknowledgmentDto::TerminateRequested {
                    was_running: *was_running,
                }
            }
        });
    Reply::Action {
        snapshot: snapshot.into(),
        dispatch,
        acknowledgment,
        write_id: receipt.and_then(|r| r.write_id),
    }
}
#[derive(Serialize)]
struct Response {
    request_id: RequestId,
    connection_generation: ConnectionGeneration,
    reply: Reply,
}

/// This registry's authority is established only through bootstrap calls. JSON
/// can reference an existing lease but never construct, register or renew one.
pub struct HostProtocol<'a> {
    profile: TrustedProfile,
    coordinator: HostCoordinator,
    authority: &'a HostAuthority,
    owners: BTreeMap<(OwnerId, OwnerEpoch), OwnerLease>,
    connection_slot: tokio::sync::Semaphore,
}
impl<'a> HostProtocol<'a> {
    pub fn new(
        profile: TrustedProfile,
        coordinator: HostCoordinator,
        authority: &'a HostAuthority,
    ) -> Result<Self, ProtocolError> {
        let (device, generation) = coordinator.bootstrap_identity();
        if &profile.device_id != device
            || &profile.host_generation != generation
            || !coordinator.shares_authority(authority)
        {
            return Err(ProtocolError::BootstrapMismatch);
        }
        let endpoint =
            LinkEndpoint::parse(&profile.endpoint).map_err(|_| ProtocolError::BootstrapMismatch)?;
        // Require one canonical endpoint, not aliases supplied by a wire peer.
        let canonical = url::Url::parse(&profile.endpoint)
            .map_err(|_| ProtocolError::BootstrapMismatch)?
            .to_string();
        drop(endpoint);
        if canonical != profile.endpoint {
            return Err(ProtocolError::BootstrapMismatch);
        }
        Ok(Self {
            profile,
            coordinator,
            authority,
            owners: BTreeMap::new(),
            connection_slot: tokio::sync::Semaphore::new(1),
        })
    }
    pub fn register_bootstrap_verified_owner(
        &mut self,
        owner: OwnerId,
        epoch: OwnerEpoch,
    ) -> Result<(), ProtocolError> {
        let key = (owner.clone(), epoch.clone());
        if self.owners.contains_key(&key) {
            return Ok(());
        }
        if self.owners.len() >= OWNER_LIMIT {
            return Err(ProtocolError::Busy);
        }
        let lease = self
            .authority
            .register_verified_owner(owner, epoch)
            .map_err(|_| ProtocolError::OwnerRegistrationRejected)?;
        self.owners.insert(key, lease);
        Ok(())
    }
    fn owner(&self, reference: &OwnerRef) -> Result<&OwnerLease, ErrorCategory> {
        self.owners
            .get(&(reference.owner_id.clone(), reference.owner_epoch.clone()))
            .ok_or(ErrorCategory::Unauthorized)
    }
    fn context(&self, revision: u64, timeout_ms: u32) -> Result<PreparedContext, ErrorCategory> {
        if timeout_ms == 0 || timeout_ms > 10_000 {
            return Err(ErrorCategory::InvalidRequest);
        }
        Ok(PreparedContext {
            device_id: self.profile.device_id.clone(),
            grant_revision: revision,
            session: None,
            observation: None,
            capability: CapabilityId::ExecRun,
            deadline: MonotonicMillis(
                self.coordinator
                    .now()
                    .0
                    .saturating_add(u64::from(timeout_ms)),
            ),
            disconnect_policy: DisconnectPolicy::RetainForOwner,
        })
    }
    async fn handle(&self, call: Call<'_>) -> Reply {
        match call {
            Call::PrepareStart {
                owner,
                grant_revision,
                timeout_ms,
                spec,
            } => {
                if spec.get().len() > SPEC_LIMIT {
                    return invalid();
                }
                let owner = match self.owner(&owner) {
                    Ok(v) => v,
                    Err(e) => return rejection(e),
                };
                let context = match self.context(grant_revision, timeout_ms) {
                    Ok(v) => v,
                    Err(e) => return rejection(e),
                };
                let spec: StartProcess = match serde_json::from_str(spec.get()) {
                    Ok(v) => v,
                    Err(_) => return invalid(),
                };
                match self.coordinator.prepare_start(owner, context, &spec) {
                    Ok(v) => Reply::Prepared { snapshot: v.into() },
                    Err(e) => coordinator_error(e, false),
                }
            }
            Call::DispatchStart { owner, target } => {
                let owner = match self.owner(&owner) {
                    Ok(v) => v,
                    Err(e) => return rejection(e),
                };
                match self.coordinator.dispatch_start(
                    owner,
                    &target.operation_id,
                    target.payload_digest,
                ) {
                    Ok(StartSubmission::Existing(v)) => Reply::Start {
                        snapshot: v.into(),
                        dispatch: "existing_no_replay",
                    },
                    Ok(StartSubmission::Submitted(ticket)) => match ticket.wait().await {
                        Ok(v) => Reply::Start {
                            snapshot: v.snapshot.into(),
                            dispatch: match v.dispatch {
                                DispatchEvidence::NotDispatched => "not_dispatched",
                                DispatchEvidence::Started => "started",
                                DispatchEvidence::Unknown => "unknown",
                            },
                        },
                        Err(e) => coordinator_error(e, false),
                    },
                    Err(e) => coordinator_error(e, false),
                }
            }
            Call::InspectStart { owner, target } => {
                let owner = match self.owner(&owner) {
                    Ok(v) => v,
                    Err(e) => return rejection(e),
                };
                match self.coordinator.inspect_start(
                    owner,
                    &target.operation_id,
                    target.payload_digest,
                ) {
                    Ok(v) => Reply::Inspected { snapshot: v.into() },
                    Err(e) => coordinator_error(e, false),
                }
            }
            Call::Read {
                owner,
                target,
                grant_revision,
                timeout_ms,
                max_bytes,
                wait_ms,
            } => {
                if max_bytes == 0 || max_bytes > 16384 || wait_ms > 100 {
                    return invalid();
                }
                let owner = match self.owner(&owner) {
                    Ok(v) => v,
                    Err(e) => return rejection(e),
                };
                let context = match self.context(grant_revision, timeout_ms) {
                    Ok(v) => v,
                    Err(e) => return rejection(e),
                };
                match self
                    .coordinator
                    .read(
                        owner,
                        &target.operation_id,
                        target.payload_digest,
                        &context,
                        max_bytes as usize,
                        Duration::from_millis(u64::from(wait_ms)),
                    )
                    .await
                {
                    Ok(v) => Reply::Read {
                        chunks: v
                            .chunks
                            .into_iter()
                            .map(|c| Chunk {
                                stream: c.stream,
                                text: c.text,
                            })
                            .collect(),
                        liveness: v.liveness,
                        output_drain: v.drain,
                        exit_code: v.exit_code,
                        read_resume: false,
                    },
                    Err(e) => coordinator_error(e, true),
                }
            }
            Call::PrepareAction {
                owner,
                target,
                grant_revision,
                timeout_ms,
                action,
            } => {
                if action.get().len() > SPEC_LIMIT {
                    return invalid();
                }
                let owner = match self.owner(&owner) {
                    Ok(v) => v,
                    Err(e) => return rejection(e),
                };
                let context = match self.context(grant_revision, timeout_ms) {
                    Ok(v) => v,
                    Err(e) => return rejection(e),
                };
                let action: ProcessAction = match serde_json::from_str(action.get()) {
                    Ok(v) => v,
                    Err(_) => return invalid(),
                };
                match self
                    .coordinator
                    .prepare_action(owner, target, context, &action)
                {
                    Ok(v) => Reply::Prepared { snapshot: v.into() },
                    Err(e) => coordinator_error(e, false),
                }
            }
            Call::DispatchAction { owner, action } => {
                let owner = match self.owner(&owner) {
                    Ok(v) => v,
                    Err(e) => return rejection(e),
                };
                match self.coordinator.dispatch_action(
                    owner,
                    &action.operation_id,
                    action.payload_digest,
                ) {
                    Ok(ActionSubmission::Existing(snapshot)) => {
                        match self.coordinator.lookup_action(
                            owner,
                            &action.operation_id,
                            action.payload_digest,
                        ) {
                            Ok(receipt) => action_reply(snapshot, receipt, true),
                            Err(e) => coordinator_error(e, false),
                        }
                    }
                    Ok(ActionSubmission::Submitted(ticket)) => match ticket.wait().await {
                        Ok(v) => action_reply(v.snapshot, Some(v.receipt), false),
                        Err(e) => coordinator_error(e, false),
                    },
                    Err(e) => coordinator_error(e, false),
                }
            }
            Call::InspectAction { owner, action } => {
                let owner = match self.owner(&owner) {
                    Ok(v) => v,
                    Err(e) => return rejection(e),
                };
                match self.coordinator.inspect_action(
                    owner,
                    &action.operation_id,
                    action.payload_digest,
                ) {
                    Ok(snapshot) => match self.coordinator.lookup_action(
                        owner,
                        &action.operation_id,
                        action.payload_digest,
                    ) {
                        Ok(receipt) => action_reply(snapshot, receipt, true),
                        Err(e) => coordinator_error(e, false),
                    },
                    Err(e) => coordinator_error(e, false),
                }
            }
            Call::Write {} => Reply::Unsupported { feature: "write" },
            Call::Terminate {} => Reply::Unsupported {
                feature: "terminate",
            },
            Call::Negotiate { .. } => invalid(),
        }
    }
    /// Does not send until the Gateway's explicit side-effect-free challenge.
    /// One bounded business handler; the transport's reader still handles pings.
    /// Response loss ends this link only. Starts remain supervised by Host and
    /// consumed read cursors are explicitly not resumable by this first slice.
    pub async fn run_connection(&self, link: &mut HostWssLink) -> Result<(), ProtocolError> {
        let _slot = self
            .connection_slot
            .try_acquire()
            .map_err(|_| ProtocolError::Busy)?;
        if link.endpoint() != self.profile.endpoint {
            return Err(ProtocolError::BootstrapMismatch);
        }
        let generation = link.generation().clone();
        let mut negotiated = false;
        while let Some(frame) = link.recv().await {
            if frame.generation != generation || frame.as_str().len() > FRAME_LIMIT {
                return Err(ProtocolError::InvalidFrame);
            }
            let request: Request<'_> =
                serde_json::from_str(frame.as_str()).map_err(|_| ProtocolError::InvalidFrame)?;
            if (!negotiated && request.connection_generation.is_some())
                || (negotiated && request.connection_generation.as_ref() != Some(&generation))
            {
                return Err(ProtocolError::NegotiationRejected);
            }
            let reply = if !negotiated {
                match request.call {
                    Call::Negotiate {
                        version: 2,
                        challenge,
                        gateway_namespace,
                        gateway_epoch,
                    } if gateway_namespace == self.profile.gateway_namespace
                        && gateway_epoch == self.profile.gateway_epoch
                        && challenge.len() >= 16
                        && challenge.len() <= 128
                        && challenge
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)) =>
                    {
                        negotiated = true;
                        Reply::Negotiated {
                            version: 2,
                            challenge,
                            device_id: self.profile.device_id.clone(),
                            host_generation: self.profile.host_generation.clone(),
                            connection_generation: generation.clone(),
                            features: &[
                                "prepare_start",
                                "dispatch_start",
                                "inspect_start",
                                "read",
                                "prepare_action",
                                "dispatch_action",
                                "inspect_action",
                            ],
                            write: true,
                            terminate: true,
                            read_resume: false,
                            owner_issuance: "bootstrap_preverified_only",
                        }
                    }
                    _ => return Err(ProtocolError::NegotiationRejected),
                }
            } else {
                self.handle(request.call).await
            };
            let response = Response {
                request_id: request.request_id,
                connection_generation: generation.clone(),
                reply,
            };
            let mut bytes = BoundedJson(Vec::new());
            serde_json::to_writer(&mut bytes, &response)
                .map_err(|_| ProtocolError::ResponseLost)?;
            let text = String::from_utf8(bytes.0).map_err(|_| ProtocolError::ResponseLost)?;
            link.sender()
                .send_text(text, Duration::from_secs(5))
                .await
                .map_err(|_| ProtocolError::ResponseLost)?;
        }
        Ok(())
    }
}
fn invalid() -> Reply {
    rejection(ErrorCategory::InvalidRequest)
}
fn rejection(category: ErrorCategory) -> Reply {
    Reply::Error {
        category,
        certainty: ExecutionCertainty::NotDispatched,
        cursor_may_be_consumed: false,
    }
}
fn coordinator_error(error: CoordinatorError, read: bool) -> Reply {
    let (category, certainty) = match error {
        CoordinatorError::Admission(category) => (category, ExecutionCertainty::NotDispatched),
        CoordinatorError::Busy => (ErrorCategory::Busy, ExecutionCertainty::NotDispatched),
        CoordinatorError::OutputDeliveryDenied(category) => (category, ExecutionCertainty::Unknown),
        CoordinatorError::ReadDeadline => {
            (ErrorCategory::OperationTimeout, ExecutionCertainty::Unknown)
        }
        CoordinatorError::ResponseLost | CoordinatorError::Executor(_) => {
            (ErrorCategory::ResultUnknown, ExecutionCertainty::Unknown)
        }
    };
    Reply::Error {
        category,
        certainty,
        cursor_may_be_consumed: read,
    }
}
struct BoundedJson(Vec<u8>);
impl Write for BoundedJson {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > RESPONSE_LIMIT.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("bounded response exceeded"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
#[cfg(test)]
mod tests;
