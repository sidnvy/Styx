//! Codex process execution; common Host identity and lifecycle live in the parent.
use super::*;

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
impl HostCoordinator {
    /// No action occurs until the returned reservation is explicitly dispatched.
    pub fn prepare_start(
        &self,
        owner: &OwnerLease,
        context: PreparedContext,
        spec: &StartProcess,
    ) -> Result<OperationSnapshot, CoordinatorError> {
        let _adapter = self.inner.exec_adapter()?;
        let payload = spec.to_operation_payload()?;
        let mut state = self.inner.state.lock().expect("Host state mutex");
        if state.shutting_down {
            return Err(CoordinatorError::Busy);
        }
        self.inner.check_exec_admission()?;
        state.reserve_exec(owner, context, payload, None, self.now())
    }
    /// Admission commits before returning a ticket. Dropping the ticket cannot drop the job.
    pub async fn dispatch_start(
        &self,
        owner: &OwnerLease,
        id: &OperationId,
        digest: Sha256Digest,
    ) -> Result<StartSubmission, CoordinatorError> {
        // Existing requests do not need another worker slot, but remain owner/digest checked.
        {
            let state = self.inner.state.lock().expect("Host state mutex");
            validate_exec_context(&state.ledger.inspect_context(owner, id, digest)?)?;
            let snapshot = state.ledger.inspect(owner, id, digest)?;
            if snapshot.target.is_some() {
                return Err(ErrorCategory::StateConflict.into());
            }
            if snapshot.state != OperationState::Reserved {
                return Ok(StartSubmission::Existing(snapshot));
            }
        }
        let adapter = self.inner.exec_adapter()?;
        let execution = self.execution_for_operation(owner, id, digest).await?;
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| CoordinatorError::Busy)?;

        let mut state = self.inner.state.lock().expect("Host state mutex");
        if state.shutting_down {
            return Err(CoordinatorError::Busy);
        }
        let snapshot = state.ledger.inspect(owner, id, digest)?;
        if snapshot.state != OperationState::Reserved {
            return Ok(StartSubmission::Existing(snapshot));
        }
        self.inner.check_exec_admission()?;
        let permit = match state.dispatch_exec(owner, id, digest, self.now())? {
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
                let result = adapter.start(permit).await;
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
        let _adapter = self.inner.exec_adapter()?;
        let payload = action.to_operation_payload()?;
        let mut state = self.inner.state.lock().expect("Host state mutex");
        if state.shutting_down {
            return Err(CoordinatorError::Busy);
        }
        if matches!(action, ProcessAction::WriteStdin { .. }) {
            self.inner.check_exec_admission()?;
        }
        state.reserve_exec(owner, context, payload, Some(target), self.now())
    }
    /// Commit one action before returning a response ticket. Receiver loss does
    /// not cancel the supervised job or permit a second dispatch.
    pub async fn dispatch_action(
        &self,
        owner: &OwnerLease,
        id: &OperationId,
        digest: Sha256Digest,
    ) -> Result<ActionSubmission, CoordinatorError> {
        {
            let state = self.inner.state.lock().expect("Host state mutex");
            validate_exec_context(&state.ledger.inspect_context(owner, id, digest)?)?;
            let snapshot = state.ledger.inspect(owner, id, digest)?;
            if snapshot.target.is_none() {
                return Err(ErrorCategory::StateConflict.into());
            }
            if snapshot.state != OperationState::Reserved {
                return Ok(ActionSubmission::Existing(snapshot));
            }
        }
        let adapter = self.inner.exec_adapter()?;
        let execution = self.execution_for_operation(owner, id, digest).await?;
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| CoordinatorError::Busy)?;

        let mut state = self.inner.state.lock().expect("Host state mutex");
        if state.shutting_down {
            return Err(CoordinatorError::Busy);
        }
        let snapshot = state.ledger.inspect(owner, id, digest)?;
        if snapshot.state != OperationState::Reserved {
            return Ok(ActionSubmission::Existing(snapshot));
        }
        // Classify only the immutable payload in the original Core record.
        // Existing receipts and Terminate retain their normal cleanup path.
        let action: ProcessAction =
            serde_json::from_slice(state.ledger.inspect_payload(owner, id, digest)?)
                .map_err(|_| CoordinatorError::Admission(ErrorCategory::ProtocolMismatch))?;
        if matches!(action, ProcessAction::WriteStdin { .. }) {
            self.inner.check_exec_admission()?;
        }
        let permit = match state.dispatch_exec(owner, id, digest, self.now())? {
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
                let receipt = run_action(&adapter, permit).await;
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
                    transfer_known_action(&mut state.ledger, &adapter, &receipt, snapshot.state)
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
        validate_exec_context(&state.ledger.inspect_context(owner, id, digest)?)?;
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
        validate_exec_context(&state.ledger.inspect_context(owner, id, digest)?)?;
        let snapshot = state.ledger.inspect(owner, id, digest)?;
        if snapshot.target.is_none() {
            return Err(ErrorCategory::StateConflict.into());
        }
        match self.inner.exec_adapter()?.lookup_action(owner, id) {
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
    /// Delivery after physical release is historical output, never permission
    /// to access the retired provider again. Recheck owner/policy under State.
    pub(crate) fn validate_settled_exec_delivery(
        &self,
        owner: &OwnerLease,
        id: &OperationId,
        digest: Sha256Digest,
        context: &PreparedContext,
    ) -> Result<(), CoordinatorError> {
        let state = self.inner.state.lock().expect("Host state mutex");
        let check = || -> Result<(), ErrorCategory> {
            validate_exec_context(context)?;
            state.ledger.inspect(owner, id, digest)?;
            styx_core::policy::check_admission(context, &state.exec_facts()?, self.now())
        };
        check().map_err(CoordinatorError::OutputDeliveryDenied)
    }
    pub async fn read(
        &self,
        owner: &OwnerLease,
        id: &OperationId,
        digest: Sha256Digest,
        context: &PreparedContext,
        max_bytes: usize,
        wait: Duration,
    ) -> Result<ProcessOutput, CoordinatorError> {
        let adapter = self.inner.exec_adapter()?;
        let _execution = self.execution_before(context.deadline).await?;
        let now = self.now();
        {
            let state = self.inner.state.lock().expect("Host state mutex");
            let snapshot = state.authorize_exec_read(owner, id, digest, context, now)?;
            if snapshot.target.is_some() {
                return Err(ErrorCategory::StateConflict.into());
            }
        }

        let budget = Duration::from_millis(
            context
                .deadline
                .ok_or(ErrorCategory::InvalidRequest)?
                .0
                .saturating_sub(now.0),
        );
        let output = tokio::time::timeout(budget, async {
            let handle = adapter.lookup_operation(owner, id).await?;
            if handle.operation() != id {
                return Err(ExecError::OwnerMismatch);
            }
            adapter.read(owner, &handle, max_bytes, wait).await
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
            .authorize_exec_read(owner, id, digest, context, self.now())
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
pub(super) fn transfer_known_action(
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
