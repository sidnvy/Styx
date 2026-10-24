//! Explicit Host-owned collection, separate from operation outcome/transport.
use super::*;

#[derive(Debug)]
pub struct RetentionBlock {
    pub operation: OperationId,
    pub error: CoordinatorError,
}
#[derive(Debug)]
pub struct RetentionCollection {
    pub actions_released: usize,
    pub resources_released: usize,
    pub metadata_reaped: usize,
    pub unreleased_records: usize,
    pub deadline_exhausted: bool,
    pub blocked: Vec<RetentionBlock>,
}
impl HostAuthority {
    /// Trusted lifecycle port, never a tool request. Tokio's fair write lock
    /// waits for real jobs/reads, prevents new I/O admission, and stays held
    /// through physical release + Core confirmation + metadata collection.
    /// Cancellation never means release succeeded; a begun token stays fenced.
    pub async fn collect_provider_retention(
        &self,
        budget: Duration,
    ) -> Result<RetentionCollection, CoordinatorError> {
        let until = tokio::time::Instant::now() + budget.min(Duration::from_secs(30));
        let _cleanup = tokio::time::timeout_at(until, self.inner.cleanup_lock.lock())
            .await
            .map_err(|_| CoordinatorError::Busy)?;
        let _quiescent =
            tokio::time::timeout_at(until, self.inner.execution_gate.clone().write_owned())
                .await
                .map_err(|_| CoordinatorError::Busy)?;
        let mut receipt = RetentionCollection {
            actions_released: 0,
            resources_released: 0,
            metadata_reaped: 0,
            unreleased_records: 0,
            deadline_exhausted: false,
            blocked: vec![],
        };
        let inventory = self
            .inner
            .state
            .lock()
            .expect("Host state mutex")
            .ledger
            .retained_provider_records();
        for key in inventory.iter().filter(|k| {
            k.capability() == styx_contracts::capability::CapabilityId::ExecRun
                && k.snapshot().target.is_some()
        }) {
            if tokio::time::Instant::now() >= until {
                receipt.deadline_exhausted = true;
                break;
            }
            let adapter = match self.inner.exec_adapter() {
                Ok(adapter) => adapter,
                Err(error) => {
                    receipt.blocked.push(RetentionBlock {
                        operation: key.snapshot().id.clone(),
                        error,
                    });
                    continue;
                }
            };
            let snapshot = key.snapshot();
            if matches!(
                snapshot.state,
                OperationState::Dispatched | OperationState::Running
            ) {
                receipt.blocked.push(RetentionBlock {
                    operation: snapshot.id.clone(),
                    error: ErrorCategory::StateConflict.into(),
                });
                continue;
            }
            let evidence = match adapter.lookup_action(key.owner(), &snapshot.id) {
                Ok(evidence) => Ok(evidence),
                Err(ExecError::UnknownHandle)
                    if matches!(
                        snapshot.state,
                        OperationState::Unknown
                            | OperationState::Failed
                            | OperationState::Cancelled
                    ) =>
                {
                    Ok(ActionReceipt {
                        operation: snapshot.id.clone(),
                        target: snapshot.target.clone(),
                        evidence: if snapshot.state == OperationState::Unknown {
                            ActionEvidence::Unknown
                        } else {
                            ActionEvidence::NotDispatched
                        },
                        write_id: None,
                        acknowledgment: None,
                        cause: Some(ExecError::UnknownHandle),
                    })
                }
                Err(error) => Err(CoordinatorError::Executor(error)),
            };
            let result = evidence.and_then(|evidence| {
                let mut state = self.inner.state.lock().expect("Host state mutex");
                transfer_known_action(&mut state.ledger, &adapter, &evidence, snapshot.state)
            });
            match result {
                Ok(()) if snapshot.state != OperationState::Unknown => {
                    receipt.actions_released += 1
                }
                Ok(()) => {}
                Err(error) => receipt.blocked.push(RetentionBlock {
                    operation: snapshot.id.clone(),
                    error,
                }),
            }
        }
        let resources = self
            .inner
            .state
            .lock()
            .expect("Host state mutex")
            .ledger
            .retained_provider_records();
        for key in resources.iter().filter(|k| {
            k.capability() == styx_contracts::capability::CapabilityId::ExecRun
                && k.snapshot().target.is_none()
        }) {
            if tokio::time::Instant::now() >= until {
                receipt.deadline_exhausted = true;
                break;
            }
            let adapter = match self.inner.exec_adapter() {
                Ok(adapter) => adapter,
                Err(error) => {
                    receipt.blocked.push(RetentionBlock {
                        operation: key.snapshot().id.clone(),
                        error,
                    });
                    continue;
                }
            };
            let snapshot = key.snapshot();
            if !matches!(
                snapshot.liveness,
                ExecutionLiveness::NotStarted | ExecutionLiveness::Exited
            ) || !matches!(
                snapshot.output_drain,
                OutputDrain::NotOpened | OutputDrain::Drained
            ) {
                continue;
            }
            let target = ResourceTarget {
                operation_id: snapshot.id.clone(),
                payload_digest: snapshot.payload_digest,
            };
            let permit = self
                .inner
                .state
                .lock()
                .expect("Host state mutex")
                .ledger
                .begin_resource_release(&target);
            let result = match permit {
                Err(error) => Err(error.into()),
                Ok(permit) => {
                    match tokio::time::timeout_at(until, adapter.release_resource(permit)).await {
                        Ok(Ok(proof)) => self
                            .inner
                            .state
                            .lock()
                            .expect("Host state mutex")
                            .ledger
                            .record_provider_release(proof)
                            .map_err(CoordinatorError::from),
                        Ok(Err(error)) => Err(error.into()),
                        Err(_) => {
                            receipt.deadline_exhausted = true;
                            Err(CoordinatorError::Busy)
                        }
                    }
                }
            };
            match result {
                Ok(()) => receipt.resources_released += 1,
                Err(error) => receipt.blocked.push(RetentionBlock {
                    operation: snapshot.id.clone(),
                    error,
                }),
            }
        }
        #[cfg(target_os = "linux")]
        {
            let browser = super::browser::collect_browser_retention(&self.inner, None, until).await;
            receipt.actions_released += browser.actions_released;
            receipt.resources_released += browser.resources_released;
            receipt.deadline_exhausted |= browser.deadline_exhausted;
            receipt.blocked.extend(browser.blocked);
        }
        #[cfg(target_os = "linux")]
        {
            let desktop =
                super::desktop_cleanup::collect_desktop_retention(&self.inner, None, until).await;
            receipt.actions_released += desktop.actions_released;
            receipt.resources_released += desktop.resources_released;
            receipt.deadline_exhausted |= desktop.deadline_exhausted;
            receipt.blocked.extend(desktop.blocked);
        }
        let mut state = self.inner.state.lock().expect("Host state mutex");
        receipt.metadata_reaped = state.ledger.reap(self.inner.now());
        receipt.unreleased_records = state.ledger.unreleased_provider_records();
        Ok(receipt)
    }
}
