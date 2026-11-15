//! Host-owned Browser contexts; a conversation holds only the current operator slot.
//! Transfers reuse the existing worker, profile, tabs and Core resource identity.
pub(crate) mod operations;
use crate::host::{coordinator::OwnerCleanupHandle, protocol::wire::*};
use crate::providers::browser_contract::BrowserAction;
use operations::BrowserPort;
use rmcp::model::{CallToolResult, ContentBlock};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use styx_contracts::{
    error::{ErrorCategory, ExecutionCertainty},
    identity::*,
    operation::*,
};
use styx_core::operations::OwnerLease;
use tokio::sync::Mutex as AsyncMutex;

const MAX_BROWSER_RESULT_BYTES: usize = 128 * 1024;

type Caller = (OwnerId, OwnerEpoch);
type Cell = Arc<AsyncMutex<Session>>;
#[derive(Default)]
pub(crate) struct State {
    registry: Mutex<Registry>,
    inputs: std::sync::OnceLock<Arc<operations::BrowserInputs>>,
}
impl State {
    pub(crate) fn inputs(
        &self,
        source: Arc<dyn operations::BrowserBootstrap>,
    ) -> Arc<operations::BrowserInputs> {
        self.inputs
            .get_or_init(|| Arc::new(operations::BrowserInputs::new(source)))
            .clone()
    }
    pub(crate) fn forget_caller(&self, owner: &OwnerRef) {
        self.registry
            .lock()
            .expect("Browser sessions")
            .defaults
            .remove(&caller(owner));
    }
}
#[derive(Default)]
struct Registry {
    sessions: BTreeMap<String, Cell>,
    defaults: BTreeMap<Caller, String>,
}
struct Session {
    operator: OwnerRef,
    lease: OwnerLease,
    target: Option<ResourceTarget>,
    phase: Phase,
    cleanup: Option<OwnerCleanupHandle>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    New,
    Ready,
    Unknown,
}
pub(crate) struct Engine<'a> {
    pub(crate) port: BrowserPort<'a>,
}
fn caller(owner: &OwnerRef) -> Caller {
    (owner.owner_id.clone(), owner.owner_epoch.clone())
}
fn failure(code: &str, unknown: bool) -> CallToolResult {
    let busy = matches!(code, "busy" | "capacity_busy") && !unknown;
    CallToolResult::error(vec![ContentBlock::text(
        json!({"error":if busy {"capacity_busy"} else {code},"uncertain":unknown,"retryable":busy})
            .to_string(),
    )])
}
fn success(value: Value) -> CallToolResult {
    CallToolResult::structured(value)
}
fn refusal(reply: &Reply) -> CallToolResult {
    match reply {
        Reply::Error {
            category,
            certainty,
            ..
        } => {
            let code = serde_json::to_value(category).expect("fixed category");
            failure(
                &code
                    .as_str()
                    .unwrap_or("RESULT_UNKNOWN")
                    .to_ascii_lowercase(),
                *certainty != ExecutionCertainty::NotDispatched,
            )
        }
        _ => failure("outcome_unknown", true),
    }
}
fn not_dispatched(reply: &Reply) -> bool {
    matches!(
        reply,
        Reply::Error {
            certainty: ExecutionCertainty::NotDispatched,
            ..
        }
    )
}
fn action_timeout(name: &str) -> u32 {
    if matches!(
        name,
        "browser_navigate" | "browser_navigate_back" | "browser_wait_for"
    ) {
        BROWSER_WAIT_PREPARE_TIMEOUT_MS
    } else {
        5_000
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

impl Engine<'_> {
    fn state(&self) -> &State {
        self.port.coordinator.browser_sessions()
    }
    fn resolve(
        &self,
        owner: &OwnerRef,
        id: Option<String>,
        create: bool,
    ) -> Result<(String, Cell), &'static str> {
        let mut state = self.state().registry.lock().expect("Browser sessions");
        if let Some(id) = id.or_else(|| state.defaults.get(&caller(owner)).cloned()) {
            return state
                .sessions
                .get(&id)
                .cloned()
                .map(|cell| (id, cell))
                .ok_or("browser_session_not_found");
        }
        if !create {
            return Err("browser_not_open");
        }
        let id = uuid::Uuid::new_v4().simple().to_string();
        let lease = self
            .port
            .authority
            .register_verified_owner(
                format!("host-browser-{id}").try_into().expect("UUID owner"),
                uuid::Uuid::new_v4()
                    .to_string()
                    .try_into()
                    .expect("UUID epoch"),
            )
            .map_err(|_| "capacity_busy")?;
        let cell = Arc::new(AsyncMutex::new(Session {
            operator: owner.clone(),
            lease,
            target: None,
            phase: Phase::New,
            cleanup: None,
        }));
        state.sessions.insert(id.clone(), cell.clone());
        state.defaults.insert(caller(owner), id.clone());
        Ok((id, cell))
    }
    fn remove(&self, id: &str) {
        let mut state = self.state().registry.lock().expect("Browser sessions");
        state.sessions.remove(id);
        state.defaults.retain(|_, value| value != id);
    }
    async fn close(&self, id: &str, session: &mut Session) -> CallToolResult {
        if session.cleanup.is_none() {
            match self.port.authority.fence_owner_for_cleanup(&session.lease) {
                Ok(handle) => session.cleanup = Some(handle),
                Err(_) => return failure("outcome_unknown", true),
            }
        }
        session.phase = Phase::Unknown;
        let clean = match self.port.authority.cleanup_owner(
            session.cleanup.as_ref().expect("original cleanup"),
            Duration::from_secs(5),
        ) {
            Ok(ticket) => ticket.wait().await.is_ok_and(|r| r.physical_complete),
            Err(_) => false,
        };
        if !clean
            || self
                .port
                .release_browser_profile(session.lease.clone())
                .await
                .is_err()
        {
            return failure("outcome_unknown", true);
        }
        self.remove(id);
        success(json!({"browser_session_id":id,"closed":true}))
    }
    /// Capability shutdown already proved physical exit. Reclaim that context's
    /// local owner/profile on the next request, without starting a browser.
    async fn collect_closed(&self) {
        let entries: Vec<_> = self
            .state()
            .registry
            .lock()
            .expect("Browser sessions")
            .sessions
            .iter()
            .map(|(id, c)| (id.clone(), c.clone()))
            .collect();
        for (id, cell) in entries {
            let Ok(mut s) = cell.try_lock() else { continue };
            if s.cleanup.is_none()
                && s.target.as_ref().is_some_and(|target| {
                    self.port
                        .coordinator
                        .inspect_browser(
                            &s.lease,
                            &target.operation_id,
                            target.payload_digest,
                            false,
                        )
                        .is_ok_and(|snap| {
                            snap.liveness == ExecutionLiveness::Exited
                                && snap.output_drain == OutputDrain::Drained
                        })
                })
            {
                let _ = self.close(&id, &mut s).await;
            }
        }
    }
    pub(crate) async fn handle(
        &self,
        owner: OwnerRef,
        command: BrowserSessionCommand,
    ) -> CallToolResult {
        self.collect_closed().await;
        match command {
            BrowserSessionCommand::List => {
                let entries: Vec<_> = self
                    .state()
                    .registry
                    .lock()
                    .expect("Browser sessions")
                    .sessions
                    .iter()
                    .map(|(id, c)| (id.clone(), c.clone()))
                    .collect();
                let mut sessions = Vec::new();
                for (id, cell) in entries {
                    sessions.push(match cell.try_lock() {
                        Ok(session) => json!({
                            "browser_session_id": id,
                            "current_operator": session.operator == owner,
                            "status": match session.phase {
                                Phase::New => "not_opened",
                                Phase::Ready => "open",
                                Phase::Unknown => "outcome_unknown",
                            },
                        }),
                        Err(_) => json!({"browser_session_id": id, "status": "busy"}),
                    });
                }
                success(json!({"sessions":sessions}))
            }
            BrowserSessionCommand::TakeOver { session_id } => {
                let (id, cell) = match self.resolve(&owner, Some(session_id), false) {
                    Ok(v) => v,
                    Err(e) => return failure(e, false),
                };
                let Ok(mut s) = cell.try_lock() else {
                    return failure("busy", false);
                };
                if s.cleanup.is_some() {
                    return failure("outcome_unknown", true);
                }
                if s.operator != owner {
                    if let Some(target) = &s.target
                        && self
                            .port
                            .coordinator
                            .invalidate_browser_session_references(&s.lease, target)
                            .is_err()
                    {
                        return failure("busy", false);
                    }
                    s.operator = owner.clone();
                }
                // An old operator's default remains bound to this ID and is
                // refused; an implicit action must never take the context back.
                self.state()
                    .registry
                    .lock()
                    .expect("Browser sessions")
                    .defaults
                    .insert(caller(&owner), id.clone());
                success(
                    json!({"browser_session_id":id,"current_operator":true,"status":if s.phase==Phase::Unknown{"outcome_unknown"}else{"open"},"refresh_snapshot":true}),
                )
            }
            BrowserSessionCommand::Action {
                session_id,
                name,
                arguments,
            } => {
                let action = BrowserAction::Tool {
                    name: name.clone(),
                    arguments,
                };
                if action.to_operation_payload().is_err() {
                    return failure("invalid_arguments", false);
                }
                let close = action.is_close();
                let (id, cell) = match self.resolve(&owner, session_id, !close) {
                    Ok(v) => v,
                    Err(e) => return failure(e, false),
                };
                let mut session = cell.lock().await;
                if session.operator != owner {
                    return failure("browser_session_transferred", false);
                }
                let mut result = if close {
                    self.close(&id, &mut session).await
                } else {
                    self.execute(&mut session, action, &name).await
                };
                let metadata = result.structured_content.get_or_insert_with(|| json!({}));
                if metadata.is_object() {
                    metadata["browser_session_id"] = json!(id);
                }
                result
            }
        }
    }
    async fn exchange(&self, s: &Session, command: BrowserCommand, timeout: u32) -> Reply {
        self.port
            .handle_browser(
                s.lease.clone(),
                self.port.coordinator.grant_revision(),
                timeout,
                command,
            )
            .await
    }
    async fn execute(&self, s: &mut Session, action: BrowserAction, name: &str) -> CallToolResult {
        if s.phase == Phase::Unknown {
            return failure("outcome_unknown", true);
        }
        if s.phase == Phase::New {
            s.phase = Phase::Unknown; // Dropped waiters never cause automatic replay.
            let reply = self
                .exchange(
                    s,
                    BrowserCommand::PrepareOpen,
                    BROWSER_WAIT_PREPARE_TIMEOUT_MS,
                )
                .await;
            let target = match reply {
                Reply::Prepared { snapshot }
                    if snapshot.state == OperationState::Reserved && snapshot.target.is_none() =>
                {
                    ResourceTarget {
                        operation_id: snapshot.operation_id,
                        payload_digest: snapshot.payload_digest,
                    }
                }
                other => {
                    if not_dispatched(&other) {
                        s.phase = Phase::New;
                    }
                    return refusal(&other);
                }
            };
            s.target = Some(target.clone());
            match self
                .exchange(
                    s,
                    BrowserCommand::DispatchOpen {
                        target: target.clone(),
                    },
                    BROWSER_WAIT_PREPARE_TIMEOUT_MS,
                )
                .await
            {
                Reply::Start { snapshot, dispatch }
                    if dispatch == "started"
                        && snapshot.state == OperationState::Running
                        && snapshot.operation_id == target.operation_id
                        && snapshot.payload_digest == target.payload_digest =>
                {
                    s.phase = Phase::Ready
                }
                other => return refusal(&other),
            }
        }
        let target = s.target.clone().expect("opened resource");
        let payload = action.to_operation_payload().expect("validated action");
        let digest = Sha256Digest::of_bytes(&payload);
        let raw =
            serde_json::value::RawValue::from_string(String::from_utf8(payload).expect("JSON"))
                .expect("JSON action");
        s.phase = Phase::Unknown;
        let reply = self
            .exchange(
                s,
                BrowserCommand::PrepareAction {
                    target: target.clone(),
                    action: raw,
                },
                action_timeout(name),
            )
            .await;
        let action = match reply {
            Reply::Prepared { snapshot }
                if snapshot.state == OperationState::Reserved
                    && snapshot.target.as_ref() == Some(&target)
                    && snapshot.payload_digest == digest =>
            {
                ActionRef {
                    operation_id: snapshot.operation_id,
                    payload_digest: snapshot.payload_digest,
                }
            }
            other => {
                if not_dispatched(&other) {
                    s.phase = Phase::Ready;
                }
                return refusal(&other);
            }
        };
        let operation_id = action.operation_id.clone();
        match self
            .exchange(
                s,
                BrowserCommand::DispatchAction { action },
                action_timeout(name),
            )
            .await
        {
            Reply::BrowserAction {
                snapshot,
                dispatch,
                result: Some(value),
                cause: None,
                ..
            } if dispatch == "acknowledged"
                && matches!(
                    snapshot.state,
                    OperationState::Succeeded | OperationState::Failed
                )
                && snapshot.operation_id == operation_id
                && snapshot.payload_digest == digest
                && snapshot.target.as_ref() == Some(&target) =>
            {
                match result(value) {
                    Ok(result) => {
                        s.phase = Phase::Ready;
                        result
                    }
                    Err(_) => failure("outcome_unknown", true),
                }
            }
            Reply::BrowserAction {
                snapshot,
                dispatch,
                cause,
                ..
            } if dispatch == "not_dispatched"
                && snapshot.state == OperationState::Failed
                && snapshot.operation_id == operation_id
                && snapshot.payload_digest == digest
                && snapshot.target.as_ref() == Some(&target) =>
            {
                s.phase = Phase::Ready;
                refusal(&Reply::Error {
                    category: cause.unwrap_or(ErrorCategory::CapabilityUnsupported),
                    certainty: ExecutionCertainty::NotDispatched,
                    cursor_may_be_consumed: false,
                })
            }
            other => {
                if not_dispatched(&other) {
                    s.phase = Phase::Ready;
                }
                refusal(&other)
            }
        }
    }
}
