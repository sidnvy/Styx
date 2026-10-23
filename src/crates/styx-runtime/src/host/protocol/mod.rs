//! Private, explicitly negotiated Host protocol slice. Not public MCP and not
//! complete public protocol: v2 uses bootstrap owners; v3 accepts owner control
//! only from the fixed authenticated paired Gateway. Reads are not resumable. Every mutation uses separate Host prepare/dispatch.
//! Connection loss never shuts down the coordinator/executor or replays reads.
use super::{
    coordinator::{
        ActionSubmission, CoordinatorError, HostAuthority, HostCoordinator, OwnerCleanupHandle,
        StartSubmission,
    },
    link::{HostWssLink, LinkEndpoint},
};
use crate::providers::codex::{
    ActionAcknowledgment, ActionEvidence, ActionReceipt, DispatchEvidence, ProcessAction,
    StartProcess,
};
pub mod wire;
use futures_util::{FutureExt, StreamExt, stream::FuturesUnordered};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    sync::Mutex,
    time::Duration,
};
use styx_contracts::{
    capability::CapabilityId,
    error::{ErrorCategory, ExecutionCertainty},
    identity::*,
    operation::*,
};
use styx_core::operations::{OperationSnapshot, OwnerLease};
use wire::*;

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
/// Protected pairing bootstrap: the authenticated fixed Gateway endpoint is
/// trusted to announce its process epoch, never an ordinary MCP client.
pub struct PairedTrustedProfile {
    pub endpoint: String,
    pub gateway_namespace: GatewayId,
    pub device_id: DeviceId,
    pub host_generation: HostGeneration,
}
struct ProfileBinding {
    endpoint: String,
    gateway_namespace: GatewayId,
    gateway_epoch: Option<GatewayEpoch>,
    device_id: DeviceId,
    host_generation: HostGeneration,
}
impl From<TrustedProfile> for ProfileBinding {
    fn from(p: TrustedProfile) -> Self {
        Self {
            endpoint: p.endpoint,
            gateway_namespace: p.gateway_namespace,
            gateway_epoch: Some(p.gateway_epoch),
            device_id: p.device_id,
            host_generation: p.host_generation,
        }
    }
}
impl From<PairedTrustedProfile> for ProfileBinding {
    fn from(p: PairedTrustedProfile) -> Self {
        Self {
            endpoint: p.endpoint,
            gateway_namespace: p.gateway_namespace,
            gateway_epoch: None,
            device_id: p.device_id,
            host_generation: p.host_generation,
        }
    }
}
struct OwnerRecord {
    lease: Option<OwnerLease>,
    revision: u64,
    cleanup: Option<OwnerCleanupHandle>,
}
#[derive(Default)]
struct OwnerRegistry {
    owners: BTreeMap<(OwnerId, OwnerEpoch), OwnerRecord>,
    active_epoch: Option<GatewayEpoch>,
    retired_epochs: BTreeSet<GatewayEpoch>,
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
        dispatch: dispatch.into(),
        acknowledgment,
        write_id: receipt.and_then(|r| r.write_id),
    }
}
/// v2 authority comes only from bootstrap; v3 owner-control DTOs are admitted
/// only after fixed-endpoint TLS and explicit Gateway namespace negotiation.
pub struct HostProtocol<'a> {
    profile: ProfileBinding,
    coordinator: HostCoordinator,
    authority: &'a HostAuthority,
    owners: Mutex<OwnerRegistry>,
    paired: bool,
    connection_slot: tokio::sync::Semaphore,
}
impl<'a> HostProtocol<'a> {
    pub fn new(
        profile: TrustedProfile,
        coordinator: HostCoordinator,
        authority: &'a HostAuthority,
    ) -> Result<Self, ProtocolError> {
        Self::build(profile.into(), coordinator, authority, false)
    }
    pub fn new_paired(
        profile: PairedTrustedProfile,
        coordinator: HostCoordinator,
        authority: &'a HostAuthority,
    ) -> Result<Self, ProtocolError> {
        Self::build(profile.into(), coordinator, authority, true)
    }
    fn build(
        profile: ProfileBinding,
        coordinator: HostCoordinator,
        authority: &'a HostAuthority,
        paired: bool,
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
            owners: Mutex::new(OwnerRegistry::default()),
            paired,
            connection_slot: tokio::sync::Semaphore::new(1),
        })
    }
    pub fn register_bootstrap_verified_owner(
        &mut self,
        owner: OwnerId,
        epoch: OwnerEpoch,
    ) -> Result<(), ProtocolError> {
        if self.paired {
            return Err(ProtocolError::OwnerRegistrationRejected);
        }
        let mut registry = self.owners.lock().expect("owner registry");
        let key = (owner.clone(), epoch.clone());
        if registry.owners.contains_key(&key) {
            return Ok(());
        }
        if registry.owners.len() >= OWNER_LIMIT {
            return Err(ProtocolError::Busy);
        }
        let lease = self
            .authority
            .register_verified_owner(owner, epoch)
            .map_err(|_| ProtocolError::OwnerRegistrationRejected)?;
        registry.owners.insert(
            key,
            OwnerRecord {
                lease: Some(lease),
                revision: self.coordinator.grant_revision(),
                cleanup: None,
            },
        );
        Ok(())
    }
    fn owner(&self, reference: &OwnerRef) -> Result<OwnerLease, ErrorCategory> {
        self.owners
            .lock()
            .expect("owner registry")
            .owners
            .get(&(reference.owner_id.clone(), reference.owner_epoch.clone()))
            .and_then(|entry| entry.lease.clone())
            .ok_or(ErrorCategory::Unauthorized)
    }
    fn accept_epoch(&self, epoch: &GatewayEpoch) -> Result<(), ProtocolError> {
        if !self.paired {
            return if self.profile.gateway_epoch.as_ref() == Some(epoch) {
                Ok(())
            } else {
                Err(ProtocolError::NegotiationRejected)
            };
        }
        let mut registry = self.owners.lock().expect("owner registry");
        if registry.active_epoch.as_ref() == Some(epoch) {
            return Ok(());
        }
        if registry.retired_epochs.contains(epoch)
            || (registry.active_epoch.is_some() && registry.retired_epochs.len() >= 64)
        {
            return Err(ProtocolError::NegotiationRejected);
        }
        // Fence all old scope leases before accepting a new authenticated server epoch.
        for entry in registry.owners.values_mut() {
            if let Some(lease) = entry.lease.as_ref() {
                let cleanup = self
                    .authority
                    .fence_owner_for_cleanup(lease)
                    .map_err(|_| ProtocolError::OwnerRegistrationRejected)?;
                entry.cleanup = Some(cleanup);
                entry.lease = None;
            }
        }
        if let Some(old) = registry.active_epoch.replace(epoch.clone()) {
            registry.retired_epochs.insert(old);
        }
        Ok(())
    }
    fn control(&self, call: &Call) -> Option<Reply> {
        let (owner, revision) = match call {
            Call::OwnerOpen {
                owner,
                grant_revision,
            } => (owner, Some(*grant_revision)),
            Call::OwnerRevoke { owner } => (owner, None),
            _ => return None,
        };
        if !self.paired {
            return Some(Reply::Unsupported {
                feature: "gateway_owner_control".into(),
            });
        }
        let mut registry = self.owners.lock().expect("owner registry");
        let key = (owner.owner_id.clone(), owner.owner_epoch.clone());
        if let Some(revision) = revision {
            if revision != self.coordinator.grant_revision() {
                return Some(rejection(ErrorCategory::StateConflict));
            }
            if let Some(entry) = registry.owners.get(&key) {
                return Some(if entry.lease.is_some() && entry.revision == revision {
                    Reply::OwnerOpened {
                        owner: owner.clone(),
                        grant_revision: revision,
                    }
                } else {
                    rejection(ErrorCategory::Unauthorized)
                });
            }
            if registry.owners.len() >= OWNER_LIMIT {
                return Some(rejection(ErrorCategory::Busy));
            }
            match self
                .authority
                .register_verified_owner(owner.owner_id.clone(), owner.owner_epoch.clone())
            {
                Ok(lease) => {
                    registry.owners.insert(
                        key,
                        OwnerRecord {
                            lease: Some(lease),
                            revision,
                            cleanup: None,
                        },
                    );
                }
                Err(e) => return Some(coordinator_error(e, false)),
            }
            Some(Reply::OwnerOpened {
                owner: owner.clone(),
                grant_revision: revision,
            })
        } else {
            if let Some(entry) = registry.owners.get_mut(&key) {
                if let Some(lease) = entry.lease.as_ref() {
                    match self.authority.fence_owner_for_cleanup(lease) {
                        Ok(cleanup) => entry.cleanup = Some(cleanup),
                        Err(e) => return Some(coordinator_error(e, false)),
                    }
                    entry.lease = None;
                }
            } else {
                if registry.owners.len() >= OWNER_LIMIT {
                    return Some(rejection(ErrorCategory::Busy));
                }
                registry.owners.insert(
                    key,
                    OwnerRecord {
                        lease: None,
                        revision: self.coordinator.grant_revision(),
                        cleanup: None,
                    },
                );
            }
            Some(Reply::OwnerRevoked {
                owner: owner.clone(),
                fenced: true,
                cleanup: "unknown".into(),
            })
        }
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
    async fn handle(&self, call: Call) -> Reply {
        match call {
            Call::OwnerCleanup { owner, timeout_ms } => {
                if !self.paired || timeout_ms == 0 || timeout_ms > 5000 {
                    return invalid();
                }
                let cleanup = self
                    .owners
                    .lock()
                    .expect("owner registry")
                    .owners
                    .get(&(owner.owner_id.clone(), owner.owner_epoch.clone()))
                    .and_then(|entry| entry.cleanup.clone());
                let Some(cleanup) = cleanup else {
                    return rejection(ErrorCategory::Unauthorized);
                };
                let complete = match self
                    .authority
                    .cleanup_owner(&cleanup, Duration::from_millis(u64::from(timeout_ms)))
                {
                    Ok(ticket) => ticket
                        .wait()
                        .await
                        .is_ok_and(|facts| facts.physical_complete),
                    Err(_) => false,
                };
                Reply::OwnerCleanup { owner, complete }
            }
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
                match self.coordinator.prepare_start(&owner, context, &spec) {
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
                    &owner,
                    &target.operation_id,
                    target.payload_digest,
                ) {
                    Ok(StartSubmission::Existing(v)) => Reply::Start {
                        snapshot: v.into(),
                        dispatch: "existing_no_replay".into(),
                    },
                    Ok(StartSubmission::Submitted(ticket)) => match ticket.wait().await {
                        Ok(v) => Reply::Start {
                            snapshot: v.snapshot.into(),
                            dispatch: match v.dispatch {
                                DispatchEvidence::NotDispatched => "not_dispatched",
                                DispatchEvidence::Started => "started",
                                DispatchEvidence::Unknown => "unknown",
                            }
                            .into(),
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
                    &owner,
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
                        &owner,
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
                    .prepare_action(&owner, target, context, &action)
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
                    &owner,
                    &action.operation_id,
                    action.payload_digest,
                ) {
                    Ok(ActionSubmission::Existing(snapshot)) => {
                        match self.coordinator.lookup_action(
                            &owner,
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
                    &owner,
                    &action.operation_id,
                    action.payload_digest,
                ) {
                    Ok(snapshot) => match self.coordinator.lookup_action(
                        &owner,
                        &action.operation_id,
                        action.payload_digest,
                    ) {
                        Ok(receipt) => action_reply(snapshot, receipt, true),
                        Err(e) => coordinator_error(e, false),
                    },
                    Err(e) => coordinator_error(e, false),
                }
            }
            Call::Write {} => Reply::Unsupported {
                feature: "write".into(),
            },
            Call::Terminate {} => Reply::Unsupported {
                feature: "terminate".into(),
            },
            Call::Negotiate { .. } | Call::OwnerOpen { .. } | Call::OwnerRevoke { .. } => invalid(),
        }
    }
    /// Scoped business waiters never own the native executor. Control admission
    /// remains live while at most two business handlers await upstream work.
    pub async fn run_connection(&self, link: &mut HostWssLink) -> Result<(), ProtocolError> {
        let _slot = self
            .connection_slot
            .try_acquire()
            .map_err(|_| ProtocolError::Busy)?;
        if link.endpoint() != self.profile.endpoint {
            return Err(ProtocolError::BootstrapMismatch);
        }
        let generation = link.generation().clone();
        let sender = link.sender();
        let mut negotiated = false;
        let mut pending: FuturesUnordered<
            futures_util::future::BoxFuture<'_, (RequestId, Option<OwnerRef>, Reply)>,
        > = FuturesUnordered::new();
        loop {
            let (request_id, reply) = tokio::select! {
                finished = pending.next(), if !pending.is_empty() => {
                    let Some((id, owner, mut reply)) = finished else { continue; };
                    // A revoked owner may not receive an in-flight result.
                    if owner.as_ref().is_some_and(|owner| self.owner(owner).is_err()) {
                        reply = Reply::Error { category: ErrorCategory::Unauthorized, certainty: ExecutionCertainty::Unknown, cursor_may_be_consumed: true };
                    }
                    (id, reply)
                }
                frame = link.recv() => {
                    let Some(frame) = frame else {
                        if !pending.is_empty() { return Err(ProtocolError::ResponseLost); }
                        break;
                    };
                    if frame.generation != generation || frame.as_str().len() > FRAME_LIMIT { return Err(ProtocolError::InvalidFrame); }
                    let request: Request = serde_json::from_str(frame.as_str()).map_err(|_| ProtocolError::InvalidFrame)?;
                    if (!negotiated && request.connection_generation.is_some()) ||
                       (negotiated && request.connection_generation.as_ref() != Some(&generation)) {
                        return Err(ProtocolError::NegotiationRejected);
                    }
                    let request_id = request.request_id.clone();
                    let reply = if !negotiated {
                        match request.call {
                            Call::Negotiate { version, challenge, gateway_namespace, gateway_epoch }
                                if version == (if self.paired { 3 } else { 2 })
                                && gateway_namespace == self.profile.gateway_namespace
                                && (16..=128).contains(&challenge.len())
                                && challenge.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)) => {
                                self.accept_epoch(&gateway_epoch)?;
                                negotiated = true;
                                Reply::Negotiated {
                                    version, challenge, device_id: self.profile.device_id.clone(),
                                    host_generation: self.profile.host_generation.clone(), connection_generation: generation.clone(),
                                    features: ["prepare_start", "dispatch_start", "inspect_start", "read", "prepare_action", "dispatch_action", "inspect_action"].into_iter().chain(if self.paired { vec!["owner_open", "owner_revoke", "owner_cleanup"] } else { vec![] }).map(str::to_owned).collect(),
                                    write: true, terminate: true, read_resume: false,
                                    owner_issuance: if self.paired { "gateway_authenticated" } else { "bootstrap_preverified_only" }.into(),
                                    grant_revision: self.paired.then(|| self.coordinator.grant_revision()),
                                }
                            }
                            _ => return Err(ProtocolError::NegotiationRejected),
                        }
                    } else if let Some(reply) = self.control(&request.call) { reply }
                    else if pending.len() >= 2 { rejection(ErrorCategory::Busy) }
                    else {
                        let owner = call_owner(&request.call).cloned();
                        // Poll once at admission: dispatch/cleanup synchronously
                        // register Host-owned work before waiting for its result.
                        // A concurrently ready EOF may abandon only the waiter,
                        // not an unpolled, already parsed dispatch request.
                        let mut handler: futures_util::future::BoxFuture<'_, (RequestId, Option<OwnerRef>, Reply)> = Box::pin(async move { (request.request_id, owner, self.handle(request.call).await) });
                        match handler.as_mut().now_or_never() {
                            Some((_, _, reply)) => reply,
                            None => { pending.push(handler); continue; }
                        }
                    };
                    (request_id, reply)
                }
            };
            let response = Response {
                request_id,
                connection_generation: generation.clone(),
                reply,
            };
            let mut bytes = BoundedJson(Vec::new());
            serde_json::to_writer(&mut bytes, &response)
                .map_err(|_| ProtocolError::ResponseLost)?;
            let text = String::from_utf8(bytes.0).map_err(|_| ProtocolError::ResponseLost)?;
            sender
                .send_text(text, Duration::from_secs(5))
                .await
                .map_err(|_| ProtocolError::ResponseLost)?;
        }
        // Dropping scoped waiters does not cancel supervised Host work or replay it.
        Ok(())
    }
}
fn call_owner(call: &Call) -> Option<&OwnerRef> {
    match call {
        Call::PrepareStart { owner, .. }
        | Call::DispatchStart { owner, .. }
        | Call::InspectStart { owner, .. }
        | Call::Read { owner, .. }
        | Call::PrepareAction { owner, .. }
        | Call::DispatchAction { owner, .. }
        | Call::InspectAction { owner, .. } => Some(owner),
        _ => None,
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

#[cfg(test)]
mod paired_tests;
