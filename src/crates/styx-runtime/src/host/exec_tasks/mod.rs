//! Host-runtime Exec tasks. Conversations authorize calls; they never own tasks.
//! Task IDs, cursor/unknown state and terminal results survive Gateway reconnects.
pub(crate) mod operations;
use crate::host::coordinator::{HostAuthority, HostCoordinator};
use crate::host::protocol::wire::*;
use crate::providers::codex::ProcessAction;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use styx_contracts::{capability::CapabilityId, error::ErrorCategory, identity::*, operation::*};
use styx_core::operations::OwnerLease;
use tokio::sync::Mutex as AsyncMutex;
const SPEC_LIMIT: usize = 128 * 1024;

#[derive(Default)]
pub(crate) struct State {
    sessions: Mutex<BTreeMap<u64, Arc<AsyncMutex<Resource>>>>,
    binding: Mutex<Option<Binding>>,
}
#[derive(Clone)]
struct Binding {
    lease: OwnerLease,
    reference: OwnerRef,
    revision: u64,
    generation: HostGeneration,
}
impl Binding {
    fn owner_ref(&self) -> OwnerRef {
        self.reference.clone()
    }
    fn grant_revision(&self) -> u64 {
        self.revision
    }
    fn host_generation(&self) -> &HostGeneration {
        &self.generation
    }
}
struct Resource {
    binding: Binding,
    target: Option<ResourceTarget>,
    start_unknown: bool,
    input_unknown: bool,
    cursor_unknown: bool,
    pending_action: Option<ActionRef>,
    start_refusal: Option<HostFailure>,
    completed: Option<Value>,
    stop_action: Option<ActionRef>,
    stop_unknown: bool,
    stop_requested: bool,
}
struct PollArgs {
    session_id: u64,
    chars: Option<String>,
    max_output_tokens: Option<usize>,
    yield_time_ms: Option<u32>,
}
pub(crate) struct Engine<'a> {
    pub(crate) port: operations::ExecPort<'a>,
}
fn error(value: Value) -> ExecTaskResult {
    ExecTaskResult {
        value,
        is_error: true,
    }
}
fn failure(code: &str, session: Option<u64>, uncertain: bool) -> ExecTaskResult {
    let busy = !uncertain && matches!(code, "busy" | "capacity" | "capacity_busy");
    let mut value = json!({"error":if busy {"capacity_busy"} else {code}, "uncertain": uncertain});
    if busy {
        value["retryable"] = json!(true);
    }
    if let Some(id) = session {
        value["session_id"] = json!(id);
    }
    error(value)
}
/// Facts from an explicit authenticated Host reply. Never constructed from a
/// generic Relay error, missing reply, timeout, ACK, or public arguments.
#[derive(Clone, Copy)]
struct HostFailure {
    category: styx_contracts::error::ErrorCategory,
    certainty: styx_contracts::error::ExecutionCertainty,
    cursor_may_be_consumed: bool,
}
impl HostFailure {
    fn from_exchange(reply: &Result<Reply, ()>) -> Option<Self> {
        match reply {
            Ok(Reply::Error {
                category,
                certainty,
                cursor_may_be_consumed,
            }) => Some(Self {
                category: *category,
                certainty: *certainty,
                cursor_may_be_consumed: *cursor_may_be_consumed,
            }),
            _ => None,
        }
    }
    fn result(self, session: u64) -> ExecTaskResult {
        let category = serde_json::to_value(self.category).expect("fixed error enum");
        let busy = self.category == styx_contracts::error::ErrorCategory::Busy
            && self.certainty == styx_contracts::error::ExecutionCertainty::NotDispatched
            && !self.cursor_may_be_consumed;
        let code = if busy {
            "capacity_busy".to_owned()
        } else {
            category
                .as_str()
                .expect("fixed error name")
                .to_ascii_lowercase()
        };
        error(json!({
            "error":code,"category":category,"execution_certainty":self.certainty,
            "cursor_may_be_consumed":self.cursor_may_be_consumed,
            "uncertain":self.certainty == styx_contracts::error::ExecutionCertainty::Unknown || self.cursor_may_be_consumed,
            "session_id":session,"retryable":busy,
        }))
    }
    fn mutation_result(self, uncertain: &mut bool, session: u64) -> ExecTaskResult {
        // Only this explicit Host proof clears action ambiguity. In particular,
        // Completed without a WriteAccepted/resource snapshot is not synthesized
        // into a successful action or a usable process resource.
        if self.certainty == styx_contracts::error::ExecutionCertainty::NotDispatched {
            *uncertain = false;
        }
        self.result(session)
    }
    fn read_result(self, cursor_unknown: &mut bool, session: u64) -> ExecTaskResult {
        // The caller checked the cursor was known, then poisoned it before I/O.
        // A typed proof that this read did not consume it safely clears only
        // that temporary poison. Missing/generic replies never enter here.
        *cursor_unknown = self.cursor_may_be_consumed;
        self.result(session)
    }
}

fn success(value: Value) -> ExecTaskResult {
    ExecTaskResult {
        value,
        is_error: false,
    }
}

impl Engine<'_> {
    pub(crate) async fn handle(&self, command: ExecTaskCommand) -> ExecTaskResult {
        match command {
            ExecTaskCommand::Run {
                spec,
                max_output_tokens,
                yield_time_ms,
            } => {
                if spec.get().len() > SPEC_LIMIT
                    || !(1..=10_000).contains(&max_output_tokens)
                    || yield_time_ms > 30_000
                {
                    return failure("invalid_arguments", None, false);
                }
                self.execute(spec, max_output_tokens, yield_time_ms).await
            }
            ExecTaskCommand::Poll {
                session_id,
                chars,
                max_output_tokens,
                yield_time_ms,
            } => {
                if !(1..=10_000).contains(&max_output_tokens)
                    || yield_time_ms > 30_000
                    || chars.len() > 65536
                {
                    return failure("invalid_arguments", None, false);
                }
                self.write(PollArgs {
                    session_id,
                    chars: Some(chars),
                    max_output_tokens: Some(max_output_tokens),
                    yield_time_ms: Some(yield_time_ms),
                })
                .await
            }
            ExecTaskCommand::List => self.list().await,
            ExecTaskCommand::Stop { session_id } => self.stop(session_id).await,
        }
    }
    async fn exchange(&self, binding: &Binding, call: Call) -> Result<Reply, ()> {
        Ok(self.port.exec_operation(&binding.lease, call).await)
    }
    fn lookup(&self, id: u64) -> Result<Arc<AsyncMutex<Resource>>, &'static str> {
        self.port
            .coordinator
            .exec_tasks()
            .sessions
            .lock()
            .expect("Host tasks")
            .get(&id)
            .cloned()
            .ok_or("unknown_session")
    }
    fn reserve(&self) -> Result<(u64, Arc<AsyncMutex<Resource>>), &'static str> {
        let mut binding = self
            .port
            .coordinator
            .exec_tasks()
            .binding
            .lock()
            .expect("Host task owner");
        if binding.is_none() {
            let reference = OwnerRef {
                owner_id: format!("host-exec-{}", uuid::Uuid::new_v4().simple())
                    .try_into()
                    .expect("UUID owner"),
                owner_epoch: uuid::Uuid::new_v4()
                    .to_string()
                    .try_into()
                    .expect("UUID epoch"),
            };
            let lease = self
                .port
                .authority
                .register_verified_owner(reference.owner_id.clone(), reference.owner_epoch.clone())
                .map_err(|_| "capacity")?;
            *binding = Some(Binding {
                lease,
                reference,
                revision: self.port.coordinator.grant_revision(),
                generation: self.port.coordinator.bootstrap_identity().1.clone(),
            });
        }
        let mut sessions = self
            .port
            .coordinator
            .exec_tasks()
            .sessions
            .lock()
            .expect("Host tasks");
        let id = loop {
            let id = (uuid::Uuid::new_v4().as_u128() & ((1u128 << 48) - 1)) as u64;
            if id != 0 && !sessions.contains_key(&id) {
                break id;
            }
        };
        let resource = Arc::new(AsyncMutex::new(Resource {
            binding: binding.as_ref().expect("Host owner").clone(),
            target: None,
            start_unknown: true,
            input_unknown: false,
            cursor_unknown: false,
            pending_action: None,
            start_refusal: None,
            completed: None,
            stop_action: None,
            stop_unknown: false,
            stop_requested: false,
        }));
        sessions.insert(id, resource.clone());
        Ok((id, resource))
    }
    async fn list(&self) -> ExecTaskResult {
        let sessions: Vec<_> = self
            .port
            .coordinator
            .exec_tasks()
            .sessions
            .lock()
            .expect("Host tasks")
            .iter()
            .map(|(id, r)| (*id, r.clone()))
            .collect();
        let mut tasks = Vec::new();
        for (id, cell) in sessions {
            let Ok(r) = cell.try_lock() else {
                tasks.push(json!({"session_id":id,"status":"busy"}));
                continue;
            };
            let status = if r.completed.is_some() {
                "completed"
            } else if r.start_unknown || r.input_unknown || r.cursor_unknown || r.stop_unknown {
                "unknown"
            } else {
                "pending"
            };
            tasks.push(json!({"session_id":id,"status":status,"exit_code":r.completed.as_ref().and_then(|v|v.get("exit_code"))}));
        }
        success(json!({"tasks":tasks}))
    }
    async fn inspect_stop(&self, r: &mut Resource) {
        let Some(original) = &r.stop_action else {
            return;
        };
        let action = ActionRef {
            operation_id: original.operation_id.clone(),
            payload_digest: original.payload_digest,
        };
        let reply = self
            .exchange(
                &r.binding,
                Call::InspectAction {
                    owner: r.binding.owner_ref(),
                    action,
                },
            )
            .await;
        if let Ok(Reply::Action {
            snapshot,
            acknowledgment: Some(ActionAcknowledgmentDto::TerminateRequested { .. }),
            ..
        }) = reply
            && snapshot.state == OperationState::Succeeded
            && snapshot.target == r.target
            && r.stop_action.as_ref().is_some_and(|a| {
                a.operation_id == snapshot.operation_id
                    && a.payload_digest == snapshot.payload_digest
            })
        {
            r.stop_unknown = false;
            r.stop_requested = true;
        }
    }
    async fn stop(&self, id: u64) -> ExecTaskResult {
        let cell = match self.lookup(id) {
            Ok(r) => r,
            Err(e) => return failure(e, None, false),
        };
        let mut r = match tokio::time::timeout(Duration::from_secs(5), cell.lock()).await {
            Ok(r) => r,
            Err(_) => return failure("busy", Some(id), false),
        };
        if let Some(result) = &r.completed {
            return success(result.clone());
        }
        if r.stop_unknown {
            self.inspect_stop(&mut r).await;
        }
        if r.stop_unknown {
            return failure("outcome_unknown", Some(id), true);
        }
        if !r.stop_requested {
            let Some(target) = r.target.clone() else {
                return failure("outcome_unknown", Some(id), true);
            };
            let action = serde_json::value::to_raw_value(&ProcessAction::Terminate {})
                .expect("terminate payload");
            // Retain ambiguity before any await, including cancellation of the
            // caller. Repeated stop calls inspect this action, never redispatch.
            r.stop_unknown = true;
            let prepared = self
                .exchange(
                    &r.binding,
                    Call::PrepareAction {
                        owner: r.binding.owner_ref(),
                        target: target.clone(),
                        grant_revision: r.binding.grant_revision(),
                        timeout_ms: 5000,
                        action,
                    },
                )
                .await;
            let action = match prepared {
                Ok(Reply::Prepared { snapshot }) if snapshot.target == Some(target) => ActionRef {
                    operation_id: snapshot.operation_id,
                    payload_digest: snapshot.payload_digest,
                },
                other => {
                    return match HostFailure::from_exchange(&other) {
                        Some(e) => e.mutation_result(&mut r.stop_unknown, id),
                        None => failure("outcome_unknown", Some(id), true),
                    };
                }
            };
            r.stop_action = Some(ActionRef {
                operation_id: action.operation_id.clone(),
                payload_digest: action.payload_digest,
            });
            let reply = self
                .exchange(
                    &r.binding,
                    Call::DispatchAction {
                        owner: r.binding.owner_ref(),
                        action,
                    },
                )
                .await;
            if let Some(error) = HostFailure::from_exchange(&reply) {
                return error.mutation_result(&mut r.stop_unknown, id);
            }
            self.inspect_stop(&mut r).await;
            if r.stop_unknown {
                return failure("outcome_unknown", Some(id), true);
            }
        }
        self.read(id, &mut r, 10_000, 100, Instant::now()).await
    }
    async fn execute(
        &self,
        spec: Box<serde_json::value::RawValue>,
        max_output_tokens: usize,
        yield_time_ms: u32,
    ) -> ExecTaskResult {
        let began = Instant::now();
        let (id, cell) = match self.reserve() {
            Ok(value) => value,
            Err(error) => return failure(error, None, false),
        };
        let mut r = match tokio::time::timeout(Duration::from_secs(5), cell.lock()).await {
            Ok(r) => r,
            Err(_) => return failure("busy", None, false),
        };
        let call = Call::PrepareStart {
            owner: r.binding.owner_ref(),
            grant_revision: r.binding.grant_revision(),
            timeout_ms: 5_000,
            spec,
        };
        let snapshot = match self.exchange(&r.binding, call).await {
            Ok(Reply::Prepared { snapshot }) => snapshot,
            Ok(Reply::Error {
                category,
                certainty,
                cursor_may_be_consumed,
            }) => {
                let error = HostFailure {
                    category,
                    certainty,
                    cursor_may_be_consumed,
                };
                if certainty == styx_contracts::error::ExecutionCertainty::NotDispatched {
                    r.start_refusal = Some(error);
                }
                if certainty == styx_contracts::error::ExecutionCertainty::NotDispatched {
                    self.port
                        .coordinator
                        .exec_tasks()
                        .sessions
                        .lock()
                        .expect("Host tasks")
                        .remove(&id);
                }
                return error.mutation_result(&mut r.start_unknown, id);
            }
            _ => return failure("outcome_unknown", Some(id), true),
        };
        if snapshot.target.is_some()
            || snapshot.operation_id.host_generation != *r.binding.host_generation()
        {
            return failure("outcome_unknown", Some(id), true);
        }
        let target = ResourceTarget {
            operation_id: snapshot.operation_id,
            payload_digest: snapshot.payload_digest,
        };
        r.target = Some(target.clone());
        match self
            .exchange(
                &r.binding,
                Call::DispatchStart {
                    owner: r.binding.owner_ref(),
                    target,
                },
            )
            .await
        {
            Ok(Reply::Start { snapshot, .. })
                if r.target.as_ref().is_some_and(|t| {
                    t.operation_id == snapshot.operation_id
                        && t.payload_digest == snapshot.payload_digest
                }) && snapshot.target.is_none()
                    && snapshot.state != OperationState::Unknown
                    && snapshot.liveness != ExecutionLiveness::NotStarted =>
            {
                r.start_unknown = false
            }
            Ok(Reply::Error {
                category,
                certainty,
                cursor_may_be_consumed,
            }) => {
                let error = HostFailure {
                    category,
                    certainty,
                    cursor_may_be_consumed,
                };
                if certainty == styx_contracts::error::ExecutionCertainty::NotDispatched {
                    r.start_refusal = Some(error);
                }
                if certainty == styx_contracts::error::ExecutionCertainty::NotDispatched {
                    self.port
                        .coordinator
                        .exec_tasks()
                        .sessions
                        .lock()
                        .expect("Host tasks")
                        .remove(&id);
                }
                return error.mutation_result(&mut r.start_unknown, id);
            }
            _ => return failure("outcome_unknown", Some(id), true),
        }
        self.read(id, &mut r, max_output_tokens, yield_time_ms, began)
            .await
    }
    async fn write(&self, args: PollArgs) -> ExecTaskResult {
        let began = Instant::now();
        let cell = match self.lookup(args.session_id) {
            Ok(r) => r,
            Err(e) => return failure(e, None, false),
        };
        let mut r = match tokio::time::timeout(Duration::from_secs(5), cell.lock()).await {
            Ok(r) => r,
            Err(_) => return failure("busy", None, false),
        };
        if let Some(result) = &r.completed {
            return if args.chars.as_ref().is_some_and(|s| !s.is_empty()) {
                failure("task_completed", Some(args.session_id), false)
            } else {
                success(result.clone())
            };
        }
        if let Some(error) = r.start_refusal {
            return error.result(args.session_id);
        }
        let Some(target) = r.target.clone() else {
            return failure("outcome_unknown", Some(args.session_id), true);
        };
        let chars = args.chars.unwrap_or_default();
        if !chars.is_empty() {
            if r.start_unknown || r.input_unknown || r.cursor_unknown || r.stop_unknown {
                return failure("outcome_unknown", Some(args.session_id), true);
            }
            let action = match serde_json::value::to_raw_value(
                &crate::providers::codex::ProcessAction::WriteStdin {
                    input_base64: STANDARD.encode(chars.as_bytes()),
                },
            ) {
                Ok(a) => a,
                Err(_) => return failure("invalid_arguments", Some(args.session_id), false),
            };
            // Set before any await that can lose an action response. Never send
            // the same input again after ambiguity.
            r.input_unknown = true;
            let prepared = self
                .exchange(
                    &r.binding,
                    Call::PrepareAction {
                        owner: r.binding.owner_ref(),
                        target,
                        grant_revision: r.binding.grant_revision(),
                        timeout_ms: 5_000,
                        action,
                    },
                )
                .await;
            let action = match prepared {
                Ok(Reply::Prepared { snapshot }) if snapshot.target == r.target => ActionRef {
                    operation_id: snapshot.operation_id,
                    payload_digest: snapshot.payload_digest,
                },
                Ok(Reply::Error {
                    category,
                    certainty,
                    cursor_may_be_consumed,
                }) => {
                    return HostFailure {
                        category,
                        certainty,
                        cursor_may_be_consumed,
                    }
                    .mutation_result(&mut r.input_unknown, args.session_id);
                }
                _ => return failure("outcome_unknown", Some(args.session_id), true),
            };
            r.pending_action = Some(ActionRef {
                operation_id: action.operation_id.clone(),
                payload_digest: action.payload_digest,
            });
            match self
                .exchange(
                    &r.binding,
                    Call::DispatchAction {
                        owner: r.binding.owner_ref(),
                        action,
                    },
                )
                .await
            {
                Ok(Reply::Action {
                    acknowledgment: Some(ActionAcknowledgmentDto::WriteAccepted),
                    snapshot,
                    ..
                }) if snapshot.state == OperationState::Succeeded
                    && snapshot.target == r.target
                    && r.pending_action.as_ref().is_some_and(|a| {
                        a.operation_id == snapshot.operation_id
                            && a.payload_digest == snapshot.payload_digest
                    }) =>
                {
                    r.input_unknown = false;
                    r.pending_action = None;
                }
                Ok(Reply::Error {
                    category,
                    certainty,
                    cursor_may_be_consumed,
                }) => {
                    return HostFailure {
                        category,
                        certainty,
                        cursor_may_be_consumed,
                    }
                    .mutation_result(&mut r.input_unknown, args.session_id);
                }
                _ => return failure("outcome_unknown", Some(args.session_id), true),
            }
        } else if r.start_unknown {
            // Inspection is not a second dispatch. Unknown history stays sticky.
            let inspected = self
                .exchange(
                    &r.binding,
                    Call::InspectStart {
                        owner: r.binding.owner_ref(),
                        target: target.clone(),
                    },
                )
                .await;
            if let Some(error) = HostFailure::from_exchange(&inspected) {
                return error.result(args.session_id);
            }
            if let Ok(Reply::Inspected { snapshot }) = inspected
                && snapshot.operation_id == target.operation_id
                && snapshot.payload_digest == target.payload_digest
                && snapshot.state != OperationState::Unknown
                && matches!(
                    snapshot.liveness,
                    ExecutionLiveness::Running | ExecutionLiveness::Exited
                )
            {
                r.start_unknown = false;
            }
        }
        if chars.is_empty()
            && r.input_unknown
            && let Some(original) = r.pending_action.as_ref()
        {
            let action = ActionRef {
                operation_id: original.operation_id.clone(),
                payload_digest: original.payload_digest,
            };
            let inspected = self
                .exchange(
                    &r.binding,
                    Call::InspectAction {
                        owner: r.binding.owner_ref(),
                        action,
                    },
                )
                .await;
            if let Some(error) = HostFailure::from_exchange(&inspected) {
                return error.result(args.session_id);
            }
            if let Ok(Reply::Action {
                snapshot,
                acknowledgment: Some(ActionAcknowledgmentDto::WriteAccepted),
                ..
            }) = inspected
                && snapshot.state == OperationState::Succeeded
                && snapshot.target == r.target
                && r.pending_action.as_ref().is_some_and(|a| {
                    a.operation_id == snapshot.operation_id
                        && a.payload_digest == snapshot.payload_digest
                })
            {
                r.input_unknown = false;
                r.pending_action = None;
            }
        }

        self.read(
            args.session_id,
            &mut r,
            args.max_output_tokens.unwrap_or(10_000),
            args.yield_time_ms
                .unwrap_or(if chars.is_empty() { 5_000 } else { 250 }),
            began,
        )
        .await
    }
    async fn read(
        &self,
        id: u64,
        r: &mut Resource,
        max_bytes: usize,
        wait_ms: u32,
        began: Instant,
    ) -> ExecTaskResult {
        if r.stop_unknown {
            self.inspect_stop(r).await;
        }
        if r.cursor_unknown {
            return failure("read_cursor_unknown", Some(id), true);
        }
        let Some(target) = r.target.clone() else {
            return failure("outcome_unknown", Some(id), true);
        };
        // Current decoded cursor cannot resume. Conservatively poison before
        // await; only a complete typed read clears the delivery uncertainty.
        r.cursor_unknown = true;
        let reply = self
            .exchange(
                &r.binding,
                Call::Read {
                    owner: r.binding.owner_ref(),
                    target,
                    grant_revision: r.binding.grant_revision(),
                    timeout_ms: 5_000,
                    max_bytes: max_bytes as u32,
                    wait_ms: wait_ms.min(100),
                },
            )
            .await;
        let (chunks, liveness, drain, exit) = match reply {
            Ok(Reply::Read {
                chunks,
                liveness,
                output_drain,
                exit_code,
                ..
            }) => (chunks, liveness, output_drain, exit_code),
            Ok(Reply::Error {
                category,
                certainty,
                cursor_may_be_consumed,
            }) => {
                return HostFailure {
                    category,
                    certainty,
                    cursor_may_be_consumed,
                }
                .read_result(&mut r.cursor_unknown, id);
            }
            _ => return failure("read_cursor_unknown", Some(id), true),
        };
        let output: String = chunks.into_iter().map(|c| c.text).collect();
        if output.len() > max_bytes.saturating_mul(4).saturating_add(4) {
            return failure("read_cursor_unknown", Some(id), true);
        }
        r.cursor_unknown = false;
        if r.start_unknown
            || r.input_unknown
            || r.stop_unknown
            || liveness == ExecutionLiveness::Unknown
            || (drain == OutputDrain::Drained && liveness != ExecutionLiveness::Exited)
        {
            let mut result =
                json!({"error":"outcome_unknown","uncertain":true,"session_id":id,"output":output});
            if let Some(code) = exit {
                result["observed_exit_code"] = json!(code);
            }
            return error(result);
        }
        let mut result = json!({"wall_time_seconds":began.elapsed().as_secs_f64(),"output":output});
        if liveness == ExecutionLiveness::Exited && drain == OutputDrain::Drained {
            let Some(code) = exit else {
                return failure("outcome_unknown", Some(id), true);
            };
            result["exit_code"] = json!(code);
            r.completed = Some(result.clone());
        } else {
            result["session_id"] = json!(id);
        }
        success(result)
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
