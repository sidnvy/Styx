//! Bounded presentation mappings over the existing authenticated paired owner.
//! This is not a Desktop authority, grant, session selector or retry engine.
use super::*;
use crate::{
    host::protocol::wire::{ComputerCommand, Snapshot},
    providers::cua::CuaAction,
};
use styx_contracts::error::{ErrorCategory, ExecutionCertainty};
const MAX_COMPUTER_CONTEXTS: usize = 16;
const MAX_COMPUTER_RESULT_BYTES: usize = styx_contracts::DESKTOP_BROWSER_FRAME_BYTES;

/// Only Computer tools already present in the frozen public contract are routed.
/// Provider validation below independently requires the pinned native schema.
pub(super) fn is_public_computer_tool(name: &str) -> bool {
    matches!(
        name,
        "list_apps"
            | "list_windows"
            | "get_window_state"
            | "get_desktop_state"
            | "click"
            | "set_value"
            | "type_text"
            | "press_key"
            | "scroll"
            | "verify_state"
    ) && PUBLIC.iter().any(|tool| tool.name == name)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ComputerBudget {
    host_timeout_ms: u32,
    response_secs: u64,
}
impl ComputerBudget {
    fn for_tool(_name: &str) -> Self {
        Self {
            host_timeout_ms: 10_000,
            response_secs: 12,
        }
    }
}
struct ComputerRequest {
    environment_id: Option<String>,
    action: CuaAction,
    budget: ComputerBudget,
}
impl ComputerRequest {
    fn parse(name: &str, args: Option<Map<String, Value>>) -> Result<Self, &'static str> {
        if !is_public_computer_tool(name) {
            return Err("unsupported");
        }
        let mut arguments = args.unwrap_or_default();
        let environment_id = match arguments.remove("environment_id") {
            None => None,
            Some(Value::String(value)) if !value.is_empty() && value.len() <= 128 => Some(value),
            _ => return Err("invalid_arguments"),
        };
        let value = Self {
            environment_id,
            budget: ComputerBudget::for_tool(name),
            action: CuaAction::new(name.into(), arguments)
                .map_err(|_| "unsupported_or_invalid_computer_arguments")?,
        };
        // Reuse frozen Computer schemas and the actual Cua provider validator.
        // No public argument can supply a session authority or native path.
        value
            .action
            .to_operation_payload()
            .map_err(|_| "unsupported_or_invalid_computer_arguments")?;
        Ok(value)
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    New,
    Opening,
    Ready,
    ActionUnknown,
    Unknown,
}
impl Phase {
    fn blocks_dispatch(self) -> bool {
        matches!(self, Self::Opening | Self::ActionUnknown | Self::Unknown)
    }
}
struct ComputerResource {
    binding: Option<BoundOwner>,
    target: Option<ResourceTarget>,
    phase: Phase,
    pending_action: Option<ActionRef>,
}
struct ComputerEntry {
    principal: Sha256Digest,
    resource: Arc<AsyncMutex<ComputerResource>>,
}
#[derive(Default)]
pub(super) struct ComputerContexts {
    entries: BTreeMap<(OwnerId, DeviceId), ComputerEntry>,
}
impl ComputerContexts {
    pub(super) fn collect_settled(&mut self) {
        self.entries.retain(|_, entry| {
            !entry.resource.try_lock().is_ok_and(|resource| {
                resource
                    .binding
                    .as_ref()
                    .is_some_and(BoundOwner::physically_settled)
            })
        });
    }
    pub(super) fn clear_owner(&mut self, owner: &VerifiedGatewayOwner) {
        self.entries.retain(|(id, _), entry| {
            id != owner.owner_id() || entry.principal != owner.principal_fingerprint()
        });
    }
}
fn open_started(snapshot: &Snapshot, dispatch: &str, target: &ResourceTarget) -> bool {
    dispatch == "started"
        && snapshot.state == OperationState::Running
        && same_resource(snapshot, target)
}
fn same_resource(snapshot: &Snapshot, target: &ResourceTarget) -> bool {
    snapshot.operation_id == target.operation_id
        && snapshot.payload_digest == target.payload_digest
        && snapshot.target.is_none()
}
fn same_action(snapshot: &Snapshot, action: &ActionRef, target: &ResourceTarget) -> bool {
    snapshot.operation_id == action.operation_id
        && snapshot.payload_digest == action.payload_digest
        && snapshot.target.as_ref() == Some(target)
}
fn computer_error(category: ErrorCategory, certainty: ExecutionCertainty) -> CallToolResult {
    let code = serde_json::to_value(category).expect("fixed category");
    CallToolResult::error(vec![ContentBlock::text(json!({"error":code.as_str().unwrap_or("RESULT_UNKNOWN").to_ascii_lowercase(),"category":code,"execution_certainty":certainty,"uncertain":certainty!=ExecutionCertainty::NotDispatched}).to_string())])
}
fn typed_error(reply: &Reply) -> Option<(ErrorCategory, ExecutionCertainty)> {
    match reply {
        Reply::Error {
            category,
            certainty,
            ..
        } => Some((*category, *certainty)),
        _ => None,
    }
}
fn result(value: Value) -> Result<CallToolResult, &'static str> {
    struct Bound(usize);
    impl std::io::Write for Bound {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .filter(|n| *n <= MAX_COMPUTER_RESULT_BYTES)
                .ok_or_else(|| std::io::Error::other("computer result bound"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(&mut Bound(0), &value).map_err(|_| "outcome_unknown")?;
    serde_json::from_value(value).map_err(|_| "outcome_unknown")
}
impl PairedGatewayBackend {
    fn computer_context(
        &self,
        owner: &VerifiedGatewayOwner,
        device: &DeviceId,
        create: bool,
    ) -> Result<Option<Arc<AsyncMutex<ComputerResource>>>, &'static str> {
        let mut state = self.state.lock().expect("paired state");
        state.collect_settled();
        if state
            .owners
            .get(owner.owner_id())
            .is_some_and(|o| o.closing || o.principal != owner.principal_fingerprint())
        {
            return Err("permission_denied");
        }
        let key = (owner.owner_id().clone(), device.clone());
        if let Some(entry) = state.computers.entries.get(&key) {
            return if entry.principal == owner.principal_fingerprint() {
                Ok(Some(entry.resource.clone()))
            } else {
                Err("permission_denied")
            };
        }
        if !create {
            return Ok(None);
        }
        if state.computers.entries.len() >= MAX_COMPUTER_CONTEXTS
            || (!state.owners.contains_key(owner.owner_id()) && state.owners.len() >= MAX_OWNERS)
        {
            return Err("capacity");
        }
        state
            .owners
            .entry(owner.owner_id().clone())
            .or_insert(OwnerState {
                principal: owner.principal_fingerprint(),
                closing: false,
            });
        let resource = Arc::new(AsyncMutex::new(ComputerResource {
            binding: None,
            target: None,
            phase: Phase::New,
            pending_action: None,
        }));
        state.computers.entries.insert(
            key,
            ComputerEntry {
                principal: owner.principal_fingerprint(),
                resource: resource.clone(),
            },
        );
        Ok(Some(resource))
    }
    fn retire_computer(
        &self,
        owner: &VerifiedGatewayOwner,
        device: &DeviceId,
        cell: &Arc<AsyncMutex<ComputerResource>>,
    ) {
        let mut state = self.state.lock().expect("paired state");
        let key = (owner.owner_id().clone(), device.clone());
        if state.computers.entries.get(&key).is_some_and(|e| {
            e.principal == owner.principal_fingerprint() && Arc::ptr_eq(&e.resource, cell)
        }) {
            state.computers.entries.remove(&key);
        }
    }
    async fn computer_exchange(
        &self,
        binding: &BoundOwner,
        command: ComputerCommand,
        budget: ComputerBudget,
    ) -> Result<Reply, super::super::RelayError> {
        tokio::time::timeout(
            Duration::from_secs(budget.response_secs),
            self.relay.call(
                binding,
                Call::Computer {
                    owner: binding.owner_ref(),
                    grant_revision: binding.grant_revision(),
                    timeout_ms: budget.host_timeout_ms,
                    command,
                },
            ),
        )
        .await
        .unwrap_or(Err(super::super::RelayError::Unknown))
    }
    pub(super) async fn computer_call(
        &self,
        owner: &VerifiedGatewayOwner,
        name: &str,
        args: Option<Map<String, Value>>,
    ) -> CallToolResult {
        let request = match ComputerRequest::parse(name, args) {
            Ok(v) => v,
            Err(e) => return failure(e, None, false),
        };
        let device = match request
            .environment_id
            .as_ref()
            .map(|s| DeviceId::try_from(s.as_str()))
            .transpose()
        {
            Ok(Some(d)) => d,
            Ok(None) => match &self.default_device {
                Some(d) => d.clone(),
                None => return failure("environment_required", None, false),
            },
            Err(_) => return failure("invalid_arguments", None, false),
        };
        let cell = match self.computer_context(owner, &device, true) {
            Ok(Some(c)) => c,
            Ok(None) => return failure("computer_not_open", None, false),
            Err(e) => return failure(e, None, false),
        };
        // No unbounded per-context waiter queue. The caller can issue a new
        // independent request after Busy; no pending request is replayed here.
        let mut record = match cell.try_lock() {
            Ok(r) => r,
            Err(_) => return failure("busy", None, false),
        };
        if !self.active(owner) {
            return failure("permission_denied", None, false);
        }
        if record.phase.blocks_dispatch() {
            return failure("outcome_unknown", None, true);
        }
        if record.binding.is_none() {
            let binding = match tokio::time::timeout(
                Duration::from_secs(5),
                self.relay.bind_computer(owner, &device),
            )
            .await
            {
                Ok(Ok(b)) => b,
                Ok(Err(e)) => {
                    if !matches!(e, super::super::RelayError::Unknown) {
                        self.retire_computer(owner, &device, &cell);
                    }
                    return failure(
                        e.code(),
                        None,
                        matches!(e, super::super::RelayError::Unknown),
                    );
                }
                Err(_) => return failure("outcome_unknown", None, true),
            };
            if !binding.defaults().computer_approved {
                return failure("permission_denied", None, false);
            }
            if binding.closed() {
                self.retire_computer(owner, &device, &cell);
                return failure("permission_denied", None, false);
            }
            record.binding = Some(binding);
        }
        let binding = record.binding.as_ref().expect("stored binding").clone();
        if record.phase == Phase::New {
            // Poison BEFORE the first await. Lost preparation/dispatch replies
            // and dropped futures cannot cause a later automatic reopen.
            record.phase = Phase::Opening;
            let prepared = self
                .computer_exchange(&binding, ComputerCommand::PrepareOpen, request.budget)
                .await;
            let snapshot = match prepared {
                Ok(Reply::Prepared { snapshot }) => snapshot,
                Ok(reply) => {
                    if let Some((category, certainty)) = typed_error(&reply) {
                        if certainty == ExecutionCertainty::NotDispatched {
                            self.retire_computer(owner, &device, &cell);
                        }
                        return computer_error(category, certainty);
                    }
                    return failure("outcome_unknown", None, true);
                }
                Err(_) => return failure("outcome_unknown", None, true),
            };
            if snapshot.target.is_some()
                || snapshot.state != OperationState::Reserved
                || snapshot.operation_id.host_generation != *binding.host_generation()
                || snapshot.operation_id.owner_epoch != binding.owner_ref().owner_epoch
            {
                return failure("outcome_unknown", None, true);
            }
            let target = ResourceTarget {
                operation_id: snapshot.operation_id,
                payload_digest: snapshot.payload_digest,
            };
            record.target = Some(target.clone());
            if !self.active(owner) {
                return failure("permission_denied", None, true);
            }
            match self
                .computer_exchange(
                    &binding,
                    ComputerCommand::DispatchOpen {
                        target: target.clone(),
                    },
                    request.budget,
                )
                .await
            {
                Ok(Reply::Start { snapshot, dispatch })
                    if open_started(&snapshot, &dispatch, &target) =>
                {
                    record.phase = Phase::Ready
                }
                Ok(Reply::Start { snapshot, dispatch })
                    if dispatch == "not_dispatched"
                        && snapshot.state == OperationState::Failed
                        && same_resource(&snapshot, &target) =>
                {
                    self.retire_computer(owner, &device, &cell);
                    return failure("computer_not_dispatched", None, false);
                }
                Ok(reply) => {
                    if let Some((category, certainty)) = typed_error(&reply) {
                        // A typed refusal proves no native dispatch, not that
                        // the original Reserved Core record was released. Keep
                        // its exact target and block automatic re-open/retry.
                        return computer_error(category, certainty);
                    }
                    return failure("outcome_unknown", None, true);
                }
                Err(_) => return failure("outcome_unknown", None, true),
            }
        }
        let Some(target) = record.target.clone() else {
            record.phase = Phase::Unknown;
            return failure("outcome_unknown", None, true);
        };
        if !self.active(owner) {
            return failure("permission_denied", None, false);
        }
        let payload = match request.action.to_operation_payload() {
            Ok(p) if p.len() <= 128 * 1024 => p,
            _ => return failure("invalid_arguments", None, false),
        };
        let digest = Sha256Digest::of_bytes(&payload);
        let raw = match String::from_utf8(payload)
            .ok()
            .and_then(|p| serde_json::value::RawValue::from_string(p).ok())
        {
            Some(v) => v,
            None => return failure("invalid_arguments", None, false),
        };
        record.phase = Phase::ActionUnknown;
        let prepared = self
            .computer_exchange(
                &binding,
                ComputerCommand::PrepareAction {
                    target: target.clone(),
                    action: raw,
                },
                request.budget,
            )
            .await;
        let snapshot = match prepared {
            Ok(Reply::Prepared { snapshot }) if snapshot.payload_digest == digest => snapshot,
            Ok(Reply::ComputerPrepared {
                request_digest,
                snapshot,
            }) if request_digest == digest => snapshot,
            Ok(reply) => {
                if let Some((category, certainty)) = typed_error(&reply) {
                    if certainty == ExecutionCertainty::NotDispatched {
                        record.phase = Phase::Ready;
                    }
                    return computer_error(category, certainty);
                }
                return failure("outcome_unknown", None, true);
            }
            Err(_) => return failure("outcome_unknown", None, true),
        };
        // Request identity was checked above. Core owns the translated payload
        // digest; retain it through dispatch/result checks without exposing tokens.
        if snapshot.target.as_ref() != Some(&target)
            || snapshot.state != OperationState::Reserved
            || snapshot.operation_id.host_generation != *binding.host_generation()
            || snapshot.operation_id.owner_epoch != binding.owner_ref().owner_epoch
        {
            return failure("outcome_unknown", None, true);
        }
        let action = ActionRef {
            operation_id: snapshot.operation_id,
            payload_digest: snapshot.payload_digest,
        };
        record.pending_action = Some(ActionRef {
            operation_id: action.operation_id.clone(),
            payload_digest: action.payload_digest,
        });
        if !self.active(owner) {
            return failure("permission_denied", None, true);
        }
        let reply = self
            .computer_exchange(
                &binding,
                ComputerCommand::DispatchAction { action },
                request.budget,
            )
            .await;
        if !self.active(owner) {
            return failure("permission_denied", None, true);
        }
        match reply {
            Ok(Reply::ComputerAction {
                snapshot,
                dispatch,
                result: Some(value),
                cause: None,
                cleanup_complete: _,
            }) if dispatch == "acknowledged"
                && matches!(
                    snapshot.state,
                    OperationState::Succeeded | OperationState::Failed
                )
                && record
                    .pending_action
                    .as_ref()
                    .is_some_and(|a| same_action(&snapshot, a, &target)) =>
            {
                let output = match result(value) {
                    Ok(v) => v,
                    Err(e) => return failure(e, None, true),
                };
                record.phase = Phase::Ready;
                record.pending_action = None;
                output
            }
            Ok(Reply::ComputerAction {
                snapshot,
                dispatch,
                cause,
                ..
            }) if dispatch == "not_dispatched"
                && snapshot.state == OperationState::Failed
                && record
                    .pending_action
                    .as_ref()
                    .is_some_and(|a| same_action(&snapshot, a, &target)) =>
            {
                record.phase = Phase::Ready;
                record.pending_action = None;
                computer_error(
                    cause.unwrap_or(ErrorCategory::CapabilityUnsupported),
                    ExecutionCertainty::NotDispatched,
                )
            }
            Ok(reply) => {
                if let Some((category, certainty)) = typed_error(&reply) {
                    if certainty == ExecutionCertainty::NotDispatched {
                        record.phase = Phase::Ready;
                        record.pending_action = None;
                    }
                    return computer_error(category, certainty);
                }
                failure("outcome_unknown", None, true)
            }
            Err(_) => failure("outcome_unknown", None, true),
        }
    }
}
#[cfg(test)]
#[path = "backend_computer_tests.rs"]
mod tests;
