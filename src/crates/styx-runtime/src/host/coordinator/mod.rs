//! Host-owned start/read/targeted-action composition.
//! No network DTO can construct control authority. Physical retention is Core-
//! attested; legacy raw-wire mode remains outside this composition.
mod legacy;
mod owner_cleanup;
pub(crate) use legacy::{LegacyActionSubmission, LegacyStartSubmission};
mod retention;
pub use owner_cleanup::{OwnerCleanupFacts, OwnerCleanupHandle, OwnerCleanupTicket};
pub use retention::{RetentionBlock, RetentionCollection};

use crate::providers::codex::{
    ActionEvidence, ActionReceipt, CleanupReceipt, CodexStdio, DispatchEvidence, ExecError,
    ProcessAction, ProcessOutput, StartProcess, TerminationEvidence,
};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use styx_contracts::{error::ErrorCategory, identity::*, operation::*};
use styx_core::{operations::*, policy::AdmissionFacts};
use tokio::sync::{OwnedRwLockReadGuard, RwLock, Semaphore, oneshot};
use tokio::task::JoinSet;

#[derive(Debug, thiserror::Error)]
pub enum CoordinatorError {
    #[error("Host admission refused ({0:?})")]
    Admission(ErrorCategory),
    #[error("executor refused or could not resolve resource")]
    Executor(#[from] ExecError),
    #[error("Host work budget exhausted or maintenance is active")]
    Busy,
    #[error("Host response delivery ended; reconcile original operation without replay")]
    ResponseLost,
    #[error("read deadline expired; process outcome is unchanged")]
    ReadDeadline,
    #[error("read output was consumed but delivery authorization is no longer valid ({0:?})")]
    OutputDeliveryDenied(ErrorCategory),
}
impl From<ErrorCategory> for CoordinatorError {
    fn from(value: ErrorCategory) -> Self {
        Self::Admission(value)
    }
}
struct State {
    ledger: OperationLedger,
    facts: AdmissionFacts,
    shutting_down: bool,
}
struct Inner {
    bootstrap_device: DeviceId,
    host_generation: HostGeneration,
    adapter: CodexStdio,
    state: Mutex<State>,
    jobs: Mutex<JoinSet<()>>,
    slots: Arc<Semaphore>,
    cleanup_lock: tokio::sync::Mutex<()>,
    execution_gate: Arc<RwLock<()>>,
    origin: Instant,
    #[cfg(test)]
    delivery_gate: Mutex<Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>>,
}
impl Inner {
    fn now(&self) -> MonotonicMillis {
        MonotonicMillis(u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX))
    }
}
/// Request plane. Cloning this handle never creates/restarts an executor.
#[derive(Clone)]
pub struct HostCoordinator {
    inner: Arc<Inner>,
}
/// Bootstrap-only control plane. No Deserialize, Clone or public field constructor.
/// Pass only to authenticated Host composition, never to a network request handler.
pub struct HostAuthority {
    inner: Arc<Inner>,
}
#[derive(Debug)]
pub struct StartCompletion {
    pub snapshot: OperationSnapshot,
    pub dispatch: DispatchEvidence,
    pub cause: Option<ExecError>,
}
pub struct StartTicket {
    response: oneshot::Receiver<Result<StartCompletion, CoordinatorError>>,
}
impl StartTicket {
    pub async fn wait(self) -> Result<StartCompletion, CoordinatorError> {
        self.response
            .await
            .map_err(|_| CoordinatorError::ResponseLost)?
    }
}
pub enum StartSubmission {
    Submitted(StartTicket),
    Existing(OperationSnapshot),
}
#[derive(Debug)]
pub struct ActionCompletion {
    pub snapshot: OperationSnapshot,
    pub receipt: ActionReceipt,
    /// Operation result is unchanged if physical retention needs supervision.
    pub retention_error: Option<CoordinatorError>,
}
pub struct ActionTicket {
    response: oneshot::Receiver<Result<ActionCompletion, CoordinatorError>>,
}
impl ActionTicket {
    pub async fn wait(self) -> Result<ActionCompletion, CoordinatorError> {
        self.response
            .await
            .map_err(|_| CoordinatorError::ResponseLost)?
    }
}
pub enum ActionSubmission {
    Submitted(ActionTicket),
    Existing(OperationSnapshot),
}
#[derive(Debug)]
pub struct HostCleanup {
    pub native: CleanupReceipt,
    pub supervised_jobs_joined: bool,
}

impl HostCoordinator {
    /// Takes exclusive ownership of one already-started executor, never spawns a second.
    pub fn new_owned(
        adapter: CodexStdio,
        ledger: OperationLedger,
        trusted_facts: AdmissionFacts,
        max_jobs: usize,
    ) -> Result<(Self, HostAuthority), CoordinatorError> {
        if max_jobs == 0 || max_jobs > 64 {
            return Err(CoordinatorError::Busy);
        }
        let inner = Arc::new(Inner {
            bootstrap_device: trusted_facts.device_id.clone(),
            host_generation: ledger.host_generation().clone(),
            adapter,
            state: Mutex::new(State {
                ledger,
                facts: trusted_facts,
                shutting_down: false,
            }),
            jobs: Mutex::new(JoinSet::new()),
            slots: Arc::new(Semaphore::new(max_jobs)),
            cleanup_lock: tokio::sync::Mutex::new(()),
            execution_gate: Arc::new(RwLock::new(())),
            origin: Instant::now(),
            #[cfg(test)]
            delivery_gate: Mutex::new(None),
        });
        Ok((
            Self {
                inner: inner.clone(),
            },
            HostAuthority { inner },
        ))
    }
    /// Immutable, non-secret bootstrap identity; policy refresh cannot rebind it.
    pub fn bootstrap_identity(&self) -> (&DeviceId, &HostGeneration) {
        (&self.inner.bootstrap_device, &self.inner.host_generation)
    }
    /// Prevent cross-wiring independent Host instances with identical public IDs.
    pub fn shares_authority(&self, authority: &HostAuthority) -> bool {
        Arc::ptr_eq(&self.inner, &authority.inner)
    }
    /// Host-local policy revision; never derived from Gateway enrollment generations.
    pub(crate) fn grant_revision(&self) -> u64 {
        self.inner
            .state
            .lock()
            .expect("Host state mutex")
            .facts
            .grant_revision
    }
    pub fn now(&self) -> MonotonicMillis {
        self.inner.now()
    }
    /// No action occurs until the returned reservation is explicitly dispatched.
    pub fn prepare_start(
        &self,
        owner: &OwnerLease,
        context: PreparedContext,
        spec: &StartProcess,
    ) -> Result<OperationSnapshot, CoordinatorError> {
        let payload = spec.to_operation_payload()?;
        let mut state = self.inner.state.lock().expect("Host state mutex");
        if state.shutting_down {
            return Err(CoordinatorError::Busy);
        }
        Ok(state.ledger.prepare(owner, context, payload, self.now())?)
    }
    /// Admission commits before returning a ticket. Dropping the ticket cannot drop the job.
    pub fn dispatch_start(
        &self,
        owner: &OwnerLease,
        id: &OperationId,
        digest: Sha256Digest,
    ) -> Result<StartSubmission, CoordinatorError> {
        // Existing requests do not need another worker slot, but remain owner/digest checked.
        {
            let state = self.inner.state.lock().expect("Host state mutex");
            let snapshot = state.ledger.inspect(owner, id, digest)?;
            if snapshot.target.is_some() {
                return Err(ErrorCategory::StateConflict.into());
            }
            if snapshot.state != OperationState::Reserved {
                return Ok(StartSubmission::Existing(snapshot));
            }
        }
        let execution = self
            .inner
            .execution_gate
            .clone()
            .try_read_owned()
            .map_err(|_| CoordinatorError::Busy)?;
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| CoordinatorError::Busy)?;
        let slot = self
            .inner
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| CoordinatorError::Busy)?;
        let mut state = self.inner.state.lock().expect("Host state mutex");
        if state.shutting_down {
            return Err(CoordinatorError::Busy);
        }
        let facts = state.facts.clone();
        let permit = match state
            .ledger
            .dispatch(owner, id, digest, &facts, self.now())?
        {
            DispatchDisposition::Existing(snapshot) => {
                return Ok(StartSubmission::Existing(snapshot));
            }
            DispatchDisposition::ExecuteOnce(permit) => permit,
        };
        let (response, receiver) = oneshot::channel();
        let inner = self.inner.clone();
        let operation = id.clone();
        // This synchronous spawn + owned handle registration occurs under admission lock.
        // Revocation after this point fences later admissions, not already committed I/O.
        let mut jobs = self.inner.jobs.lock().expect("Host jobs mutex");
        while jobs.try_join_next().is_some() {}
        // Captured before first poll: even a supervisor task dropped before it starts
        // leaves a consumed reservation Unknown rather than reopening dispatch.
        let mut guard = UnsettledStart {
            inner: inner.clone(),
            operation: operation.clone(),
            settled: false,
            _execution: execution,
        };
        jobs.spawn_on(
            async move {
                let _slot = slot;
                let result = inner.adapter.start(permit).await;
                let (dispatch, cause) = match result {
                    Ok(receipt) => (receipt.dispatch, receipt.cause),
                    Err(failure) => (failure.evidence, Some(failure.error)),
                };
                let mut state = inner.state.lock().expect("Host state mutex");
                let settled = match dispatch {
                    DispatchEvidence::NotDispatched => state.ledger.record_executor_fact(
                        &operation,
                        ExecutorFact::NotDispatched,
                        inner.now(),
                    ),
                    DispatchEvidence::Started => state.ledger.record_executor_fact(
                        &operation,
                        ExecutorFact::Running,
                        inner.now(),
                    ),
                    DispatchEvidence::Unknown => state.ledger.mark_result_unknown(&operation),
                };
                guard.settled = settled.is_ok();
                // Never hold state while a Drop guard may reacquire it.
                drop(state);
                // Capture the complete Drop guard (not merely its boolean field)
                // into the async task and settle it outside the state lock.
                drop(guard);
                let _ = response.send(
                    settled
                        .map(|snapshot| StartCompletion {
                            snapshot,
                            dispatch,
                            cause,
                        })
                        .map_err(CoordinatorError::from),
                );
            },
            &runtime,
        );
        drop(jobs);
        drop(state);
        Ok(StartSubmission::Submitted(StartTicket {
            response: receiver,
        }))
    }
    /// Reserve an independent, immutable action against an exact original
    /// resource. First dispatch rechecks fresh policy, target and deadline.
    pub fn prepare_action(
        &self,
        owner: &OwnerLease,
        target: ResourceTarget,
        context: PreparedContext,
        action: &ProcessAction,
    ) -> Result<OperationSnapshot, CoordinatorError> {
        let payload = action.to_operation_payload()?;
        let mut state = self.inner.state.lock().expect("Host state mutex");
        if state.shutting_down {
            return Err(CoordinatorError::Busy);
        }
        Ok(state
            .ledger
            .prepare_targeted(owner, target, context, payload, self.now())?)
    }
    /// Commit one action before returning a response ticket. Receiver loss does
    /// not cancel the supervised job or permit a second dispatch.
    pub fn dispatch_action(
        &self,
        owner: &OwnerLease,
        id: &OperationId,
        digest: Sha256Digest,
    ) -> Result<ActionSubmission, CoordinatorError> {
        {
            let state = self.inner.state.lock().expect("Host state mutex");
            let snapshot = state.ledger.inspect(owner, id, digest)?;
            if snapshot.target.is_none() {
                return Err(ErrorCategory::StateConflict.into());
            }
            if snapshot.state != OperationState::Reserved {
                return Ok(ActionSubmission::Existing(snapshot));
            }
        }
        let execution = self
            .inner
            .execution_gate
            .clone()
            .try_read_owned()
            .map_err(|_| CoordinatorError::Busy)?;
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| CoordinatorError::Busy)?;
        let slot = self
            .inner
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| CoordinatorError::Busy)?;
        let mut state = self.inner.state.lock().expect("Host state mutex");
        if state.shutting_down {
            return Err(CoordinatorError::Busy);
        }
        let facts = state.facts.clone();
        let permit = match state
            .ledger
            .dispatch(owner, id, digest, &facts, self.now())?
        {
            DispatchDisposition::Existing(snapshot) => {
                return Ok(ActionSubmission::Existing(snapshot));
            }
            DispatchDisposition::ExecuteOnce(permit) => permit,
        };
        let (response, receiver) = oneshot::channel();
        let inner = self.inner.clone();
        let operation = id.clone();
        let mut guard = UnsettledAction {
            inner: inner.clone(),
            operation: operation.clone(),
            settled: false,
            _execution: execution,
        };
        let mut jobs = self.inner.jobs.lock().expect("Host jobs mutex");
        while jobs.try_join_next().is_some() {}
        jobs.spawn_on(
            async move {
                let _slot = slot;
                let receipt = run_action(&inner.adapter, permit).await;
                let fact = match receipt.evidence {
                    ActionEvidence::Acknowledged => ActionResult::Acknowledged,
                    ActionEvidence::NotDispatched => ActionResult::NotDispatched,
                    ActionEvidence::Unknown => ActionResult::Unknown,
                };
                let mut state = inner.state.lock().expect("Host state mutex");
                let settled = state
                    .ledger
                    .record_action_result(&operation, fact, inner.now());
                guard.settled = settled.is_ok();
                let retention_error = if let Ok(snapshot) = &settled {
                    transfer_known_action(
                        &mut state.ledger,
                        &inner.adapter,
                        &receipt,
                        snapshot.state,
                    )
                    .err()
                } else {
                    None
                };
                drop(state);
                // Explicitly move/drop the WHOLE guard inside this supervised task;
                // Rust disjoint-field capture must not leave the guard in the caller.
                drop(guard);
                let _ = response.send(
                    settled
                        .map(|snapshot| ActionCompletion {
                            snapshot,
                            receipt,
                            retention_error,
                        })
                        .map_err(CoordinatorError::from),
                );
            },
            &runtime,
        );
        drop(jobs);
        drop(state);
        Ok(ActionSubmission::Submitted(ActionTicket {
            response: receiver,
        }))
    }
    /// Read existing action history, never another dispatch instruction.
    pub fn inspect_action(
        &self,
        owner: &OwnerLease,
        id: &OperationId,
        digest: Sha256Digest,
    ) -> Result<OperationSnapshot, CoordinatorError> {
        let state = self.inner.state.lock().expect("Host state mutex");
        let snapshot = state.ledger.inspect(owner, id, digest)?;
        if snapshot.target.is_none() {
            return Err(ErrorCategory::StateConflict.into());
        }
        Ok(snapshot)
    }
    /// Optional provider receipt under current Core owner authority. None only
    /// means no retained provider receipt; it never proves that I/O did not occur.
    pub fn lookup_action(
        &self,
        owner: &OwnerLease,
        id: &OperationId,
        digest: Sha256Digest,
    ) -> Result<Option<ActionReceipt>, CoordinatorError> {
        let state = self.inner.state.lock().expect("Host state mutex");
        let snapshot = state.ledger.inspect(owner, id, digest)?;
        if snapshot.target.is_none() {
            return Err(ErrorCategory::StateConflict.into());
        }
        match self.inner.adapter.lookup_action(owner, id) {
            Ok(receipt) => Ok(Some(receipt)),
            Err(ExecError::UnknownHandle) => match state.ledger.provider_audit(id) {
                Some(bytes) => Ok(Some(CodexStdio::action_from_audit(
                    id.clone(),
                    snapshot.target.expect("checked action"),
                    bytes,
                )?)),
                None => Ok(None),
            },
            Err(error) => Err(error.into()),
        }
    }
    pub fn inspect_start(
        &self,
        owner: &OwnerLease,
        id: &OperationId,
        digest: Sha256Digest,
    ) -> Result<OperationSnapshot, CoordinatorError> {
        let snapshot = self
            .inner
            .state
            .lock()
            .expect("Host state mutex")
            .ledger
            .inspect(owner, id, digest)?;
        if snapshot.target.is_some() {
            return Err(ErrorCategory::StateConflict.into());
        }
        Ok(snapshot)
    }
    /// Fresh access deadline/grant facts, not the start deadline. Read failure does not
    /// rewrite historical start outcome or synthesize an empty successful page.
    pub async fn read(
        &self,
        owner: &OwnerLease,
        id: &OperationId,
        digest: Sha256Digest,
        context: &PreparedContext,
        max_bytes: usize,
        wait: Duration,
    ) -> Result<ProcessOutput, CoordinatorError> {
        let _execution = self
            .inner
            .execution_gate
            .clone()
            .try_read_owned()
            .map_err(|_| CoordinatorError::Busy)?;
        let now = self.now();
        {
            let state = self.inner.state.lock().expect("Host state mutex");
            let snapshot = state.ledger.authorize_resource_access(
                owner,
                id,
                digest,
                context,
                &state.facts,
                now,
            )?;
            if snapshot.target.is_some() {
                return Err(ErrorCategory::StateConflict.into());
            }
        }
        let _slot = self
            .inner
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| CoordinatorError::Busy)?;
        let budget = Duration::from_millis(context.deadline.0.saturating_sub(now.0));
        let output = tokio::time::timeout(budget, async {
            let handle = self.inner.adapter.lookup_operation(owner, id).await?;
            if handle.operation() != id {
                return Err(ExecError::OwnerMismatch);
            }
            self.inner
                .adapter
                .read(owner, &handle, max_bytes, wait)
                .await
        })
        .await
        .map_err(|_| CoordinatorError::ReadDeadline)??;
        #[cfg(test)]
        {
            // Deterministic policy-revocation boundary only. No production path
            // or wire request can install or trigger this gate.
            let gate = self
                .inner
                .delivery_gate
                .lock()
                .expect("test delivery gate")
                .take();
            if let Some((arrived, release)) = gate {
                arrived.notify_one();
                release.notified().await;
            }
        }
        let mut state = self.inner.state.lock().expect("Host state mutex");
        // Settlement is trusted executor evidence even if owner was revoked while awaiting.
        // It updates original operation, never grants a new action or access to the caller.
        if output.liveness == ExecutionLiveness::Exited {
            let successful = output
                .exit_code
                .ok_or(CoordinatorError::Executor(ExecError::InvalidFrame))?
                == 0;
            match state.ledger.record_executor_fact(
                id,
                ExecutorFact::Exited { successful },
                self.now(),
            ) {
                Ok(_) | Err(ErrorCategory::StateConflict) => {}
                Err(e) => return Err(e.into()),
            }
        }
        if output.drain == OutputDrain::Drained {
            state
                .ledger
                .record_executor_fact(id, ExecutorFact::OutputDrained, self.now())?;
        }
        // A later revoke does not roll back an already admitted native read.
        // However, sensitive output must not cross a now-invalid owner/policy
        // boundary. This explicit error acknowledges possible cursor consumption.
        state
            .ledger
            .authorize_resource_access(owner, id, digest, context, &state.facts, self.now())
            .map_err(CoordinatorError::OutputDeliveryDenied)?;
        Ok(output)
    }
}
async fn run_action(adapter: &CodexStdio, permit: DispatchPermit) -> ActionReceipt {
    let refused = |error| ActionReceipt {
        operation: permit.id().clone(),
        target: permit.target().cloned(),
        evidence: ActionEvidence::NotDispatched,
        write_id: None,
        acknowledgment: None,
        cause: Some(error),
    };
    let Some(target) = permit.target() else {
        return refused(ExecError::InvalidRequest);
    };
    if permit.payload().len() > 131072 {
        return refused(ExecError::InvalidRequest);
    }
    let action: ProcessAction = match serde_json::from_slice(permit.payload()) {
        Ok(action) => action,
        Err(_) => return refused(ExecError::InvalidRequest),
    };
    let handle = match adapter
        .lookup_operation(permit.owner(), &target.operation_id)
        .await
    {
        Ok(handle) if handle.operation() == &target.operation_id => handle,
        Ok(_) => return refused(ExecError::OwnerMismatch),
        Err(error) => return refused(error),
    };
    match action {
        ProcessAction::WriteStdin { .. } => adapter.write(permit, &handle).await,
        ProcessAction::Terminate {} => adapter.terminate(permit, &handle).await,
    }
}
fn transfer_known_action(
    ledger: &mut OperationLedger,
    adapter: &CodexStdio,
    receipt: &ActionReceipt,
    historical_state: OperationState,
) -> Result<(), CoordinatorError> {
    ledger.record_provider_audit(&receipt.operation, adapter.action_audit(receipt)?)?;
    if matches!(
        historical_state,
        OperationState::Succeeded | OperationState::Failed | OperationState::Cancelled
    ) {
        let permit = ledger.begin_action_release(&receipt.operation)?;
        let proof = adapter.release_action(permit)?;
        ledger.record_provider_release(proof)?;
    }
    Ok(())
}

struct UnsettledAction {
    inner: Arc<Inner>,
    operation: OperationId,
    settled: bool,
    _execution: OwnedRwLockReadGuard<()>,
}
impl Drop for UnsettledAction {
    fn drop(&mut self) {
        if !self.settled {
            let mut state = self.inner.state.lock().expect("Host state mutex");
            let _ = state.ledger.record_action_result(
                &self.operation,
                ActionResult::Unknown,
                self.inner.now(),
            );
        }
    }
}
struct UnsettledStart {
    inner: Arc<Inner>,
    operation: OperationId,
    settled: bool,
    _execution: OwnedRwLockReadGuard<()>,
}
impl Drop for UnsettledStart {
    fn drop(&mut self) {
        if !self.settled {
            let _ = self
                .inner
                .state
                .lock()
                .expect("Host state mutex")
                .ledger
                .mark_result_unknown(&self.operation);
        }
    }
}
impl HostAuthority {
    pub fn register_verified_owner(
        &self,
        owner: OwnerId,
        epoch: OwnerEpoch,
    ) -> Result<OwnerLease, CoordinatorError> {
        Ok(self
            .inner
            .state
            .lock()
            .expect("Host state mutex")
            .ledger
            .register_verified_owner(owner, epoch)?)
    }
    pub fn replace_trusted_facts(&self, facts: AdmissionFacts) {
        self.inner.state.lock().expect("Host state mutex").facts = facts;
    }
    pub fn revoke_owner(&self, owner: &OwnerLease) -> Result<(), CoordinatorError> {
        Ok(self
            .inner
            .state
            .lock()
            .expect("Host state mutex")
            .ledger
            .revoke_owner(owner)?)
    }
    /// Explicit Host supervision action, never implicitly called on transport drop.
    /// Retains unfinished JoinHandles and real cleanup facts on deadline exhaustion.
    pub async fn shutdown_owned(&self, budget: Duration) -> Result<HostCleanup, CoordinatorError> {
        let until = tokio::time::Instant::now() + budget.min(Duration::from_secs(30));
        let _cleanup = tokio::time::timeout_at(until, self.inner.cleanup_lock.lock())
            .await
            .map_err(|_| CoordinatorError::Busy)?;
        {
            let mut state = self.inner.state.lock().expect("Host state mutex");
            state.shutting_down = true;
            state.ledger.begin_maintenance();
        }
        let mut jobs = std::mem::replace(
            &mut *self.inner.jobs.lock().expect("Host jobs mutex"),
            JoinSet::new(),
        );
        let mut joined = true;
        while !jobs.is_empty() {
            match tokio::time::timeout_at(until, jobs.join_next()).await {
                Ok(Some(Ok(()))) => {}
                Ok(Some(Err(_))) => joined = false,
                Ok(None) => break,
                Err(_) => {
                    joined = false;
                    break;
                }
            }
        }
        // A JoinSet aborts on drop; preserve unfinished jobs rather than implicitly
        // canceling a possible native start while forgetting its result.
        *self.inner.jobs.lock().expect("Host jobs mutex") = jobs;
        let native = self
            .inner
            .adapter
            .shutdown_owned(until.saturating_duration_since(tokio::time::Instant::now()))
            .await;
        for (handle, evidence) in &native.processes {
            if let TerminationEvidence::ProcessExited(code) = evidence {
                let _ = self
                    .inner
                    .state
                    .lock()
                    .expect("Host state mutex")
                    .ledger
                    .record_executor_fact(
                        handle.operation(),
                        ExecutorFact::Exited {
                            successful: *code == 0,
                        },
                        self.inner.now(),
                    );
            }
        }
        Ok(HostCleanup {
            native,
            supervised_jobs_joined: joined,
        })
    }
}
#[cfg(test)]
mod tests;
