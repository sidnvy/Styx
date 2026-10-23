//! Explicit legacy Core admission over the same Host/native executor.
use super::*;
use crate::providers::codex::{
    LegacyAction, LegacyActionReceipt, LegacyStartProcess, RawProcessPage,
};
use serde_json::Value;

pub(crate) struct LegacyStartCompletion {
    pub snapshot: OperationSnapshot,
    pub dispatch: DispatchEvidence,
    pub cause: Option<ExecError>,
    pub raw_result: Option<Value>,
}
pub(crate) struct LegacyActionCompletion {
    pub snapshot: OperationSnapshot,
    pub receipt: ActionReceipt,
    pub retention_error: Option<CoordinatorError>,
    pub raw_result: Option<Value>,
}
pub(crate) struct LegacyStartTicket {
    response: oneshot::Receiver<Result<LegacyStartCompletion, CoordinatorError>>,
}
impl LegacyStartTicket {
    pub async fn wait(self) -> Result<LegacyStartCompletion, CoordinatorError> {
        self.response
            .await
            .map_err(|_| CoordinatorError::ResponseLost)?
    }
}
pub(crate) struct LegacyActionTicket {
    response: oneshot::Receiver<Result<LegacyActionCompletion, CoordinatorError>>,
}
impl LegacyActionTicket {
    pub async fn wait(self) -> Result<LegacyActionCompletion, CoordinatorError> {
        self.response
            .await
            .map_err(|_| CoordinatorError::ResponseLost)?
    }
}
pub(crate) enum LegacyStartSubmission {
    Submitted(LegacyStartTicket),
    Existing(OperationSnapshot),
}
pub(crate) enum LegacyActionSubmission {
    Submitted(LegacyActionTicket),
    Existing(OperationSnapshot),
}
impl HostCoordinator {
    pub(crate) fn legacy_initialization(&self) -> Value {
        self.inner.adapter.initialization().clone()
    }
    pub(crate) fn legacy_terminal(
        &self,
    ) -> tokio::sync::broadcast::Receiver<crate::providers::codex::TerminalEvent> {
        self.inner.adapter.legacy_terminal()
    }
    pub(crate) fn legacy_context(&self) -> PreparedContext {
        let state = self.inner.state.lock().expect("Host state mutex");
        PreparedContext {
            device_id: state.facts.device_id.clone(),
            grant_revision: state.facts.grant_revision,
            session: None,
            observation: None,
            capability: styx_contracts::capability::CapabilityId::ExecRun,
            deadline: MonotonicMillis(self.now().0.saturating_add(10000)),
            disconnect_policy: DisconnectPolicy::RetainForOwner,
        }
    }
    pub(crate) fn prepare_legacy_start(
        &self,
        owner: &OwnerLease,
        spec: &LegacyStartProcess,
    ) -> Result<OperationSnapshot, CoordinatorError> {
        let context = self.legacy_context();
        let payload = spec.to_operation_payload()?;
        let mut state = self.inner.state.lock().expect("Host state mutex");
        if state.shutting_down {
            return Err(CoordinatorError::Busy);
        }
        Ok(state.ledger.prepare(owner, context, payload, self.now())?)
    }
    pub(crate) fn prepare_legacy_action(
        &self,
        owner: &OwnerLease,
        target: ResourceTarget,
        action: &LegacyAction,
    ) -> Result<OperationSnapshot, CoordinatorError> {
        let context = self.legacy_context();
        let payload = action.to_operation_payload()?;
        let mut state = self.inner.state.lock().expect("Host state mutex");
        if state.shutting_down {
            return Err(CoordinatorError::Busy);
        }
        Ok(state
            .ledger
            .prepare_targeted(owner, target, context, payload, self.now())?)
    }
    pub(crate) fn dispatch_legacy_start(
        &self,
        owner: &OwnerLease,
        id: &OperationId,
        digest: Sha256Digest,
    ) -> Result<LegacyStartSubmission, CoordinatorError> {
        // Existing requests do not need another worker slot, but remain owner/digest checked.
        {
            let state = self.inner.state.lock().expect("Host state mutex");
            let snapshot = state.ledger.inspect(owner, id, digest)?;
            if snapshot.target.is_some() {
                return Err(ErrorCategory::StateConflict.into());
            }
            if snapshot.state != OperationState::Reserved {
                return Ok(LegacyStartSubmission::Existing(snapshot));
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
                return Ok(LegacyStartSubmission::Existing(snapshot));
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
                let result = inner.adapter.start_legacy(permit).await;
                let (dispatch, cause, raw_result) = match result {
                    Ok(receipt) => (
                        receipt.start.dispatch,
                        receipt.start.cause,
                        receipt.raw_result,
                    ),
                    Err(failure) => (failure.evidence, Some(failure.error), None),
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
                        .map(|snapshot| LegacyStartCompletion {
                            snapshot,
                            dispatch,
                            cause,
                            raw_result,
                        })
                        .map_err(CoordinatorError::from),
                );
            },
            &runtime,
        );
        drop(jobs);
        drop(state);
        Ok(LegacyStartSubmission::Submitted(LegacyStartTicket {
            response: receiver,
        }))
    }
    pub(crate) fn dispatch_legacy_action(
        &self,
        owner: &OwnerLease,
        id: &OperationId,
        digest: Sha256Digest,
    ) -> Result<LegacyActionSubmission, CoordinatorError> {
        {
            let state = self.inner.state.lock().expect("Host state mutex");
            let snapshot = state.ledger.inspect(owner, id, digest)?;
            if snapshot.target.is_none() {
                return Err(ErrorCategory::StateConflict.into());
            }
            if snapshot.state != OperationState::Reserved {
                return Ok(LegacyActionSubmission::Existing(snapshot));
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
                return Ok(LegacyActionSubmission::Existing(snapshot));
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
                let legacy = run_legacy_action(&inner.adapter, permit).await;
                let receipt = legacy.action;
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
                        .map(|snapshot| LegacyActionCompletion {
                            snapshot,
                            receipt,
                            retention_error,
                            raw_result: legacy.raw_result,
                        })
                        .map_err(CoordinatorError::from),
                );
            },
            &runtime,
        );
        drop(jobs);
        drop(state);
        Ok(LegacyActionSubmission::Submitted(LegacyActionTicket {
            response: receiver,
        }))
    }
    pub(crate) async fn read_legacy_raw(
        &self,
        owner: &OwnerLease,
        target: &ResourceTarget,
        after_seq: Option<u64>,
        max_bytes: usize,
        wait: Duration,
    ) -> Result<RawProcessPage, CoordinatorError> {
        let _execution = self
            .inner
            .execution_gate
            .clone()
            .try_read_owned()
            .map_err(|_| CoordinatorError::Busy)?;
        let context = self.legacy_context();
        {
            let state = self.inner.state.lock().expect("Host state mutex");
            state.ledger.authorize_resource_access(
                owner,
                &target.operation_id,
                target.payload_digest,
                &context,
                &state.facts,
                self.now(),
            )?;
        }
        let _slot = self
            .inner
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| CoordinatorError::Busy)?;
        let page = tokio::time::timeout(Duration::from_secs(10), async {
            let handle = self
                .inner
                .adapter
                .lookup_operation(owner, &target.operation_id)
                .await?;
            self.inner
                .adapter
                .read_raw(owner, &handle, after_seq, max_bytes, wait)
                .await
        })
        .await
        .map_err(|_| CoordinatorError::ReadDeadline)??;
        let native = page.as_native();
        let mut state = self.inner.state.lock().expect("Host state mutex");
        if native["exited"].as_bool() == Some(true) {
            let code = native["exitCode"]
                .as_i64()
                .ok_or(CoordinatorError::Executor(ExecError::InvalidFrame))?;
            match state.ledger.record_executor_fact(
                &target.operation_id,
                ExecutorFact::Exited {
                    successful: code == 0,
                },
                self.now(),
            ) {
                Ok(_) | Err(ErrorCategory::StateConflict) => {}
                Err(e) => return Err(e.into()),
            }
        }
        if native["closed"].as_bool() == Some(true)
            && native["chunks"].as_array().is_some_and(Vec::is_empty)
        {
            state.ledger.record_executor_fact(
                &target.operation_id,
                ExecutorFact::OutputDrained,
                self.now(),
            )?;
        }
        state
            .ledger
            .authorize_resource_access(
                owner,
                &target.operation_id,
                target.payload_digest,
                &context,
                &state.facts,
                self.now(),
            )
            .map_err(CoordinatorError::OutputDeliveryDenied)?;
        Ok(page)
    }
}
async fn run_legacy_action(adapter: &CodexStdio, permit: DispatchPermit) -> LegacyActionReceipt {
    let reject = |error| LegacyActionReceipt {
        action: ActionReceipt {
            operation: permit.id().clone(),
            target: permit.target().cloned(),
            evidence: ActionEvidence::NotDispatched,
            write_id: None,
            acknowledgment: None,
            cause: Some(error),
        },
        raw_result: None,
    };
    let Some(target) = permit.target() else {
        return reject(ExecError::InvalidRequest);
    };
    let action: LegacyAction = match serde_json::from_slice(permit.payload()) {
        Ok(a) => a,
        Err(_) => return reject(ExecError::InvalidRequest),
    };
    let handle = match adapter
        .lookup_operation(permit.owner(), &target.operation_id)
        .await
    {
        Ok(h) => h,
        Err(e) => return reject(e),
    };
    let write = matches!(action, LegacyAction::Write { .. });
    adapter.perform_legacy_action(permit, &handle, write).await
}
