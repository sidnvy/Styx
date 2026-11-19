//! Bounded presentation mappings over the existing authenticated paired owner.
//! This is not a Desktop authority, grant, session selector or retry engine.
use super::*;
use crate::{
    host::protocol::wire::{ComputerCommand, Snapshot},
    providers::cua::{CuaAction, public_contract},
};
use styx_contracts::error::{ErrorCategory, ExecutionCertainty};
const MAX_COMPUTER_RESULT_BYTES: usize = styx_contracts::DESKTOP_BROWSER_FRAME_BYTES;

/// Route only the supported Styx surface. The wider pinned native catalog is
/// compatibility evidence and never creates an additional public input route.
pub(super) fn is_public_computer_tool(name: &str) -> bool {
    public_contract::route(name).is_some() && PUBLIC.iter().any(|tool| tool.name == name)
}
struct ComputerRequest {
    environment_id: Option<String>,
    action: CuaAction,
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
            action: public_contract::decode(name, arguments)
                .map_err(|_| "unsupported_or_invalid_computer_arguments")?,
        };
        // The Styx public schema and exact request shape already passed; retain
        // the independent native operation/payload boundary before dispatch.
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
        matches!(self, Self::Opening | Self::Unknown)
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
    pub(super) fn clear_device(&mut self, device: &DeviceId) {
        self.entries.retain(|(_, id), _| id != device);
    }
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
fn is_computer_read(name: &str) -> bool {
    matches!(
        public_contract::route(name),
        Some(
            public_contract::PublicComputerRoute::Metadata
                | public_contract::PublicComputerRoute::WindowRead
                | public_contract::PublicComputerRoute::DesktopRead
                | public_contract::PublicComputerRoute::VerifyRead
        )
    )
}
fn inspected_open_running(reply: &Reply, target: &ResourceTarget) -> bool {
    matches!(reply, Reply::Inspected { snapshot }
        if snapshot.state == OperationState::Running && same_resource(snapshot, target))
}
fn open_started(snapshot: &Snapshot, dispatch: &str, target: &ResourceTarget) -> bool {
    dispatch == "started"
        && snapshot.state == OperationState::Running
        && same_resource(snapshot, target)
}
fn open_not_dispatched(snapshot: &Snapshot, dispatch: &str, target: &ResourceTarget) -> bool {
    dispatch == "not_dispatched"
        && same_resource(snapshot, target)
        && matches!(
            snapshot.state,
            OperationState::Failed | OperationState::Cancelled
        )
        && snapshot.liveness == ExecutionLiveness::NotStarted
        && snapshot.output_drain == OutputDrain::NotOpened
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
    if category == ErrorCategory::Busy && certainty == ExecutionCertainty::NotDispatched {
        return failure("capacity_busy", None, false);
    }
    let code = serde_json::to_value(category).expect("fixed category");
    CallToolResult::error(vec![ContentBlock::text(json!({"error":code.as_str().unwrap_or("RESULT_UNKNOWN").to_ascii_lowercase(),"category":code,"execution_certainty":certainty,"uncertain":certainty!=ExecutionCertainty::NotDispatched}).to_string())])
}
fn reusable_open_refusal(certainty: ExecutionCertainty) -> bool {
    // This is a new explicit request, not a replay of the old operation.
    // Unknown/acknowledged native dispatch must retain the original target.
    certainty == ExecutionCertainty::NotDispatched
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
        if owner.is_fenced()
            || state
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
    ) -> Result<Reply, super::super::RelayError> {
        self.relay
            .call(
                binding,
                Call::Computer {
                    owner: binding.owner_ref(),
                    grant_revision: binding.grant_revision(),
                    timeout_ms: None,
                    command,
                },
            )
            .await
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
        let device = match self.resolve_device(request.environment_id.as_deref()).await {
            Ok(device) => device,
            Err(error) => return failure(error, None, false),
        };
        if let Err(error) = self.refresh_host_capabilities(&device).await {
            return failure(error, None, false);
        }
        let cell = match self.computer_context(owner, &device, true) {
            Ok(Some(c)) => c,
            Ok(None) => return failure("computer_not_open", None, false),
            Err(e) => return failure(e, None, false),
        };
        // Preserve this context's operation order without refusing another read.
        let mut record = cell.lock().await;
        if !self.active(owner) {
            return failure("permission_denied", None, false);
        }
        if record.phase == Phase::Opening && is_computer_read(name) {
            // A lost open reply does not prove the original worker failed.
            // Inspect only that resource; never reopen it or replay an action.
            if let (Some(binding), Some(target)) = (record.binding.as_ref(), record.target.as_ref())
                && let Ok(reply) = self
                    .computer_exchange(
                        binding,
                        ComputerCommand::InspectOpen {
                            target: target.clone(),
                        },
                    )
                    .await
                && inspected_open_running(&reply, target)
            {
                record.phase = Phase::Ready;
            }
        }
        if record.phase.blocks_dispatch() {
            return failure("outcome_unknown", None, true);
        }
        if record.phase == Phase::ActionUnknown {
            // Inspect the original action; never dispatch it again. Its outcome
            // belongs to the Host ledger, not to this new read request.
            if !is_computer_read(name) {
                return failure("fresh_observation_required", None, false);
            }
            let (Some(binding), Some(target), Some(action)) = (
                record.binding.as_ref(),
                record.target.as_ref(),
                record.pending_action.as_ref(),
            ) else {
                return failure("previous_action_unresolved", None, false);
            };
            match self
                .computer_exchange(
                    binding,
                    ComputerCommand::InspectAction {
                        action: ActionRef {
                            operation_id: action.operation_id.clone(),
                            payload_digest: action.payload_digest,
                        },
                    },
                )
                .await
            {
                Ok(Reply::Inspected { snapshot }) if same_action(&snapshot, action, target) => {}
                _ => return failure("previous_action_unresolved", None, false),
            }
            // Host admission still owns actual transport availability. Inspection
            // is not proof that an unknown native operation finished.
            record.phase = Phase::Ready;
            record.pending_action = None;
        }
        if record.binding.is_none() {
            let binding = match self.relay.bind_computer(owner, &device).await {
                Ok(binding) => binding,
                Err(error) => {
                    self.retire_computer(owner, &device, &cell);
                    return failure(error.code(), None, false);
                }
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
                .computer_exchange(&binding, ComputerCommand::PrepareOpen)
                .await;
            let snapshot = match prepared {
                Ok(Reply::Prepared { snapshot }) => snapshot,
                Ok(reply) => {
                    if let Some((category, certainty)) = typed_error(&reply) {
                        if reusable_open_refusal(certainty) {
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
                )
                .await
            {
                Ok(Reply::Start { snapshot, dispatch })
                    if open_started(&snapshot, &dispatch, &target) =>
                {
                    record.phase = Phase::Ready
                }
                Ok(Reply::Start { snapshot, dispatch })
                    if open_not_dispatched(&snapshot, &dispatch, &target) =>
                {
                    self.retire_computer(owner, &device, &cell);
                    return failure("computer_not_dispatched", None, false);
                }
                Ok(reply) => {
                    if let Some((category, certainty)) = typed_error(&reply) {
                        // The Host explicitly guarantees no native dispatch.
                        // Retire only this unstarted presentation context: a
                        // subsequent user read may establish a fresh one after
                        // the desktop recovers. An unknown dispatch remains
                        // blocked and is NEVER replayed automatically.
                        if reusable_open_refusal(certainty) {
                            self.retire_computer(owner, &device, &cell);
                        }
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
            .computer_exchange(&binding, ComputerCommand::DispatchAction { action })
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

#[cfg(test)]
mod public_contract_regressions {
    use super::*;

    #[test]
    fn public_contract_gateway_request_uses_published_window_branches_before_context_creation() {
        for branch in ["include_screenshot", "include_accessibility_tree"] {
            let mut arguments = json!({"pid":42,"window_id":43,"environment_id":"selected-host"})
                .as_object()
                .unwrap()
                .clone();
            arguments.insert(branch.into(), Value::Bool(false));
            let request =
                ComputerRequest::parse("get_window_state", Some(arguments.clone())).unwrap();
            assert_eq!(request.environment_id.as_deref(), Some("selected-host"));
            assert!(request.action.desktop_read_request().unwrap().is_some());
            let payload: Value =
                serde_json::from_slice(&request.action.to_operation_payload().unwrap()).unwrap();
            assert!(payload["arguments"].get("environment_id").is_none());

            arguments.insert("full_output".into(), Value::Bool(true));
            assert!(ComputerRequest::parse("get_window_state", Some(arguments)).is_err());
        }
        for name in ["type_text", "press_key", "scroll"] {
            assert!(!is_public_computer_tool(name));
            assert!(ComputerRequest::parse(name, None).is_err());
        }
    }
}
