//! Bounded presentation mappings over the existing authenticated paired owner.
//! This is not a Browser authority, grant, profile selector or retry engine.
use super::*;
use crate::{
    host::protocol::wire::{
        BROWSER_WAIT_PREPARE_TIMEOUT_MS, BROWSER_WAIT_RESPONSE_SECS, BrowserCommand, Snapshot,
    },
    providers::browser::BrowserAction,
};
use styx_contracts::error::{ErrorCategory, ExecutionCertainty};
const MAX_BROWSER_CONTEXTS: usize = 16;
const MAX_BROWSER_RESULT_BYTES: usize = 128 * 1024;

/// Only Browser tools already present in the frozen public contract are routed.
/// Provider validation below independently requires the pinned native schema.
pub(super) fn is_public_browser_tool(name: &str) -> bool {
    name.starts_with("browser_") && PUBLIC.iter().any(|tool| tool.name == name)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BrowserBudget {
    host_timeout_ms: u32,
    response_secs: u64,
}
impl BrowserBudget {
    fn for_tool(name: &str) -> Self {
        if name == "browser_wait_for" {
            Self {
                host_timeout_ms: BROWSER_WAIT_PREPARE_TIMEOUT_MS,
                response_secs: BROWSER_WAIT_RESPONSE_SECS,
            }
        } else {
            Self {
                host_timeout_ms: 5_000,
                response_secs: 5,
            }
        }
    }
}
struct BrowserRequest {
    environment_id: Option<String>,
    action: BrowserAction,
    budget: BrowserBudget,
}
impl BrowserRequest {
    fn parse(name: &str, args: Option<Map<String, Value>>) -> Result<Self, &'static str> {
        if !is_public_browser_tool(name) {
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
            budget: BrowserBudget::for_tool(name),
            action: BrowserAction::Tool {
                name: name.into(),
                arguments,
            },
        };
        // Reuse the frozen mature-tool schema + actual provider policy, including
        // URL/path/ref restrictions. No public metadata can create an owner.
        value
            .action
            .to_operation_payload()
            .map_err(|_| "unsupported_or_invalid_browser_arguments")?;
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
struct BrowserResource {
    binding: Option<BoundOwner>,
    target: Option<ResourceTarget>,
    phase: Phase,
    pending_action: Option<ActionRef>,
}
struct BrowserEntry {
    principal: Sha256Digest,
    resource: Arc<AsyncMutex<BrowserResource>>,
}
#[derive(Default)]
pub(super) struct BrowserContexts {
    entries: BTreeMap<(OwnerId, DeviceId), BrowserEntry>,
}
impl BrowserContexts {
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
fn browser_error(category: ErrorCategory, certainty: ExecutionCertainty) -> CallToolResult {
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
                .filter(|n| *n <= MAX_BROWSER_RESULT_BYTES)
                .ok_or_else(|| std::io::Error::other("browser result bound"))?;
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
    fn browser_context(
        &self,
        owner: &VerifiedGatewayOwner,
        device: &DeviceId,
        create: bool,
    ) -> Result<Option<Arc<AsyncMutex<BrowserResource>>>, &'static str> {
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
        if let Some(entry) = state.browsers.entries.get(&key) {
            return if entry.principal == owner.principal_fingerprint() {
                Ok(Some(entry.resource.clone()))
            } else {
                Err("permission_denied")
            };
        }
        if !create {
            return Ok(None);
        }
        if state.browsers.entries.len() >= MAX_BROWSER_CONTEXTS
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
        let resource = Arc::new(AsyncMutex::new(BrowserResource {
            binding: None,
            target: None,
            phase: Phase::New,
            pending_action: None,
        }));
        state.browsers.entries.insert(
            key,
            BrowserEntry {
                principal: owner.principal_fingerprint(),
                resource: resource.clone(),
            },
        );
        Ok(Some(resource))
    }
    fn retire_browser(
        &self,
        owner: &VerifiedGatewayOwner,
        device: &DeviceId,
        cell: &Arc<AsyncMutex<BrowserResource>>,
    ) {
        let mut state = self.state.lock().expect("paired state");
        let key = (owner.owner_id().clone(), device.clone());
        if state.browsers.entries.get(&key).is_some_and(|e| {
            e.principal == owner.principal_fingerprint() && Arc::ptr_eq(&e.resource, cell)
        }) {
            state.browsers.entries.remove(&key);
        }
    }
    async fn browser_exchange(
        &self,
        binding: &BoundOwner,
        command: BrowserCommand,
        budget: BrowserBudget,
    ) -> Result<Reply, super::super::RelayError> {
        tokio::time::timeout(
            Duration::from_secs(budget.response_secs),
            self.relay.call(
                binding,
                Call::Browser {
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
    pub(super) async fn browser_call(
        &self,
        owner: &VerifiedGatewayOwner,
        name: &str,
        args: Option<Map<String, Value>>,
    ) -> CallToolResult {
        let request = match BrowserRequest::parse(name, args) {
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
        let close = request.action.is_close();
        let cell = match self.browser_context(owner, &device, !close) {
            Ok(Some(c)) => c,
            Ok(None) => return failure("browser_not_open", None, false),
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
        if close && record.phase == Phase::New {
            return failure("browser_not_open", None, false);
        }
        if record.binding.is_none() {
            let binding = match tokio::time::timeout(
                Duration::from_secs(5),
                self.relay.bind_browser(owner, &device),
            )
            .await
            {
                Ok(Ok(b)) => b,
                Ok(Err(e)) => {
                    if !matches!(e, super::super::RelayError::Unknown) {
                        self.retire_browser(owner, &device, &cell);
                    }
                    return failure(
                        e.code(),
                        None,
                        matches!(e, super::super::RelayError::Unknown),
                    );
                }
                Err(_) => return failure("outcome_unknown", None, true),
            };
            if !binding.defaults().browser_approved {
                return failure("permission_denied", None, false);
            }
            if binding.closed() {
                self.retire_browser(owner, &device, &cell);
                return failure("permission_denied", None, false);
            }
            record.binding = Some(binding);
        }
        let binding = record.binding.as_ref().expect("stored binding").clone();
        if record.phase == Phase::New {
            if close {
                return failure("browser_not_open", None, false);
            }
            // Poison BEFORE the first await. Lost preparation/dispatch replies
            // and dropped futures cannot cause a later automatic reopen.
            record.phase = Phase::Opening;
            let prepared = self
                .browser_exchange(&binding, BrowserCommand::PrepareOpen, request.budget)
                .await;
            let snapshot = match prepared {
                Ok(Reply::Prepared { snapshot }) => snapshot,
                Ok(reply) => {
                    if let Some((category, certainty)) = typed_error(&reply) {
                        if certainty == ExecutionCertainty::NotDispatched {
                            self.retire_browser(owner, &device, &cell);
                        }
                        return browser_error(category, certainty);
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
                .browser_exchange(
                    &binding,
                    BrowserCommand::DispatchOpen {
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
                    self.retire_browser(owner, &device, &cell);
                    return failure("browser_not_dispatched", None, false);
                }
                Ok(reply) => {
                    if let Some((category, certainty)) = typed_error(&reply) {
                        if certainty == ExecutionCertainty::NotDispatched {
                            self.retire_browser(owner, &device, &cell);
                        }
                        return browser_error(category, certainty);
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
            .browser_exchange(
                &binding,
                BrowserCommand::PrepareAction {
                    target: target.clone(),
                    action: raw,
                },
                request.budget,
            )
            .await;
        let snapshot = match prepared {
            Ok(Reply::Prepared { snapshot }) => snapshot,
            Ok(reply) => {
                if let Some((category, certainty)) = typed_error(&reply) {
                    if certainty == ExecutionCertainty::NotDispatched {
                        record.phase = Phase::Ready;
                    }
                    return browser_error(category, certainty);
                }
                return failure("outcome_unknown", None, true);
            }
            Err(_) => return failure("outcome_unknown", None, true),
        };
        if snapshot.target.as_ref() != Some(&target)
            || snapshot.state != OperationState::Reserved
            || snapshot.payload_digest != digest
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
            .browser_exchange(
                &binding,
                BrowserCommand::DispatchAction { action },
                request.budget,
            )
            .await;
        if !self.active(owner) {
            return failure("permission_denied", None, true);
        }
        match reply {
            Ok(Reply::BrowserAction {
                snapshot,
                dispatch,
                result: Some(value),
                cause: None,
                cleanup_complete,
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
                if close && cleanup_complete != Some(true) {
                    return failure("outcome_unknown", None, true);
                }
                record.phase = Phase::Ready;
                record.pending_action = None;
                if close {
                    self.retire_browser(owner, &device, &cell);
                }
                output
            }
            Ok(Reply::BrowserAction {
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
                browser_error(
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
                    return browser_error(category, certainty);
                }
                failure("outcome_unknown", None, true)
            }
            Err(_) => failure("outcome_unknown", None, true),
        }
    }
}
#[cfg(test)]
#[path = "backend_browser_tests.rs"]
mod tests;
