//! Host-owned revoked-owner physical cleanup. No ordinary dispatch is revived.
use super::*;

#[derive(Clone)]
pub struct OwnerCleanupHandle {
    inner: Arc<Inner>,
    authority: Arc<OwnerCleanupAuthority>,
}
impl std::fmt::Debug for OwnerCleanupHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OwnerCleanupHandle([REDACTED])")
    }
}
#[derive(Debug)]
pub struct OwnerCleanupFacts {
    /// Only physical settlement/release, not operation success or rollback.
    pub physical_complete: bool,
    pub quiescent: bool,
    pub resources_released: usize,
    pub unreleased_records: usize,
    pub deadline_exhausted: bool,
    /// The shared JoinSet has no per-owner join proof. Never fabricate one.
    pub supervised_jobs_joined: Option<bool>,
    pub blocked: Vec<RetentionBlock>,
}
pub struct OwnerCleanupTicket {
    response: oneshot::Receiver<Result<OwnerCleanupFacts, CoordinatorError>>,
}
impl OwnerCleanupTicket {
    pub async fn wait(self) -> Result<OwnerCleanupFacts, CoordinatorError> {
        self.response
            .await
            .map_err(|_| CoordinatorError::ResponseLost)?
    }
}
impl HostAuthority {
    /// Fences ordinary authority synchronously before minting cleanup authority.
    pub fn fence_owner_for_cleanup(
        &self,
        owner: &OwnerLease,
    ) -> Result<OwnerCleanupHandle, CoordinatorError> {
        let authority = self
            .inner
            .state
            .lock()
            .expect("Host state mutex")
            .ledger
            .fence_owner_for_cleanup(owner, self.inner.now())?;
        Ok(OwnerCleanupHandle {
            inner: self.inner.clone(),
            authority: Arc::new(authority),
        })
    }
    /// Dropping the ticket abandons the wait, not this Host-supervised job.
    pub fn cleanup_owner(
        &self,
        handle: &OwnerCleanupHandle,
        budget: Duration,
    ) -> Result<OwnerCleanupTicket, CoordinatorError> {
        if !Arc::ptr_eq(&self.inner, &handle.inner)
            || budget.is_zero()
            || budget > Duration::from_secs(5)
        {
            return Err(ErrorCategory::Unauthorized.into());
        }
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| CoordinatorError::Busy)?;
        let slot = self
            .inner
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| CoordinatorError::Busy)?;
        let until = tokio::time::Instant::now() + budget;
        let handle = handle.clone();
        let (response, receiver) = oneshot::channel();
        let state = self.inner.state.lock().expect("Host state mutex");
        if state.shutting_down {
            return Err(CoordinatorError::Busy);
        }
        let mut jobs = self.inner.jobs.lock().expect("Host jobs mutex");
        while jobs.try_join_next().is_some() {}
        jobs.spawn_on(
            async move {
                let _slot = slot;
                let result = run_cleanup(&handle, until).await;
                let _ = response.send(result);
            },
            &runtime,
        );
        Ok(OwnerCleanupTicket { response: receiver })
    }
}
fn owner_inventory(
    handle: &OwnerCleanupHandle,
) -> Result<Vec<ProviderRecordKey>, CoordinatorError> {
    let state = handle.inner.state.lock().expect("Host state mutex");
    state.ledger.owner_cleanup_inventory(&handle.authority)?;
    Ok(state
        .ledger
        .retained_provider_records()
        .into_iter()
        .filter(|key| key.owner() == handle.authority.owner())
        .collect())
}
async fn run_cleanup(
    handle: &OwnerCleanupHandle,
    until: tokio::time::Instant,
) -> Result<OwnerCleanupFacts, CoordinatorError> {
    let inner = &handle.inner;
    let _cleanup = tokio::time::timeout_at(until, inner.cleanup_lock.lock())
        .await
        .map_err(|_| CoordinatorError::Busy)?;
    // Browser ownership ends independently of Codex resources. Cancel its
    // in-flight wait before seeking global I/O quiescence; the original action
    // remains Unknown, and only exact native scope evidence settles liveness.
    #[cfg(target_os = "linux")]
    let _browser = super::browser::cleanup_browser_owner(
        inner.clone(),
        handle.authority.owner(),
        until.saturating_duration_since(tokio::time::Instant::now()),
    )
    .await;
    // Existing fair global gate provides real quiescence. Other owners' I/O can
    // briefly wait, but no other owner's resource/action is cancelled or released.
    let _quiescent = tokio::time::timeout_at(until, inner.execution_gate.clone().write_owned())
        .await
        .map_err(|_| CoordinatorError::Busy)?;
    let mut facts = OwnerCleanupFacts {
        physical_complete: false,
        quiescent: true,
        resources_released: 0,
        unreleased_records: 0,
        deadline_exhausted: false,
        supervised_jobs_joined: None,
        blocked: vec![],
    };
    // Persist whitelist action evidence first, including original Unknown/writeId.
    // This never sends a stdin mutation or retries an action.
    for key in owner_inventory(handle)?.iter().filter(|key| {
        key.capability() == styx_contracts::capability::CapabilityId::ExecRun
            && key.snapshot().target.is_some()
    }) {
        if tokio::time::Instant::now() >= until {
            facts.deadline_exhausted = true;
            break;
        }
        let snapshot = key.snapshot();
        let evidence = match inner.adapter.lookup_action(key.owner(), &snapshot.id) {
            Ok(receipt) => Ok(receipt),
            Err(ExecError::UnknownHandle)
                if matches!(
                    snapshot.state,
                    OperationState::Unknown | OperationState::Failed | OperationState::Cancelled
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
        let result = evidence.and_then(|receipt| {
            transfer_known_action(
                &mut inner.state.lock().expect("Host state mutex").ledger,
                &inner.adapter,
                &receipt,
                snapshot.state,
            )
        });
        if let Err(error) = result {
            facts.blocked.push(RetentionBlock {
                operation: snapshot.id.clone(),
                error,
            });
        }
    }
    for key in owner_inventory(handle)?.iter().filter(|key| {
        key.capability() == styx_contracts::capability::CapabilityId::ExecRun
            && key.snapshot().target.is_none()
    }) {
        let snapshot = key.snapshot();
        if tokio::time::Instant::now() >= until {
            facts.deadline_exhausted = true;
            break;
        }
        let result = settle_resource(handle, key, until).await;
        match result {
            Ok(()) => facts.resources_released += 1,
            Err(error) => facts.blocked.push(RetentionBlock {
                operation: snapshot.id.clone(),
                error,
            }),
        }
    }
    #[cfg(target_os = "linux")]
    {
        let browser =
            super::browser::collect_browser_retention(inner, Some(handle.authority.owner()), until)
                .await;
        facts.resources_released += browser.resources_released;
        facts.deadline_exhausted |= browser.deadline_exhausted;
        facts.blocked.extend(browser.blocked);
    }
    let state = inner.state.lock().expect("Host state mutex");
    facts.unreleased_records = state
        .ledger
        .owner_unreleased_provider_records(&handle.authority)?;
    facts.deadline_exhausted |= tokio::time::Instant::now() >= until;
    facts.physical_complete = facts.unreleased_records == 0 && facts.blocked.is_empty();
    drop(state);
    #[cfg(target_os = "linux")]
    if facts.physical_complete {
        // Core includes ReleasePending in the original owner's inventory.
        // Only its empty cleanup proof permits retiring this scope metadata.
        super::browser::release_browser_profile(inner, handle.authority.owner());
    }
    Ok(facts)
}
async fn settle_resource(
    handle: &OwnerCleanupHandle,
    key: &ProviderRecordKey,
    until: tokio::time::Instant,
) -> Result<(), CoordinatorError> {
    let inner = &handle.inner;
    let snapshot = key.snapshot();
    if !(snapshot.liveness == ExecutionLiveness::NotStarted
        && snapshot.output_drain == OutputDrain::NotOpened)
    {
        let process = tokio::time::timeout_at(
            until,
            inner
                .adapter
                .lookup_for_cleanup(&handle.authority, &snapshot.id),
        )
        .await
        .map_err(|_| CoordinatorError::Busy)??;
        let remaining = until.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(CoordinatorError::Busy);
        }
        let termination = tokio::time::timeout_at(
            until,
            inner
                .adapter
                .cancel_for_cleanup(&handle.authority, &process, remaining),
        )
        .await
        .map_err(|_| CoordinatorError::Busy)??;
        // A terminate ACK is deliberately not sufficient. Continue bounded
        // read-only observation/discard and require an independent real exit.
        if let TerminationEvidence::ProcessExited(code) = termination {
            note_exit(inner, &snapshot.id, code)?;
        }
        loop {
            let evidence = tokio::time::timeout_at(
                until,
                inner
                    .adapter
                    .discard_for_cleanup(&handle.authority, &process),
            )
            .await
            .map_err(|_| CoordinatorError::Busy)??;
            if let Some(code) = evidence.exit_code {
                note_exit(inner, &snapshot.id, code)?;
            }
            if evidence.drained {
                inner
                    .state
                    .lock()
                    .expect("Host state mutex")
                    .ledger
                    .record_executor_fact(&snapshot.id, ExecutorFact::OutputDrained, inner.now())?;
            }
            if evidence.exit_code.is_some() && evidence.drained {
                break;
            }
            if tokio::time::Instant::now() >= until {
                return Err(CoordinatorError::Busy);
            }
            tokio::time::timeout_at(until, tokio::time::sleep(Duration::from_millis(10)))
                .await
                .map_err(|_| CoordinatorError::Busy)?;
        }
    }
    let target = ResourceTarget {
        operation_id: snapshot.id.clone(),
        payload_digest: snapshot.payload_digest,
    };
    let permit = inner
        .state
        .lock()
        .expect("Host state mutex")
        .ledger
        .begin_resource_release(&target)?;
    let proof = tokio::time::timeout_at(until, inner.adapter.release_resource(permit))
        .await
        .map_err(|_| CoordinatorError::Busy)??;
    inner
        .state
        .lock()
        .expect("Host state mutex")
        .ledger
        .record_provider_release(proof)?;
    Ok(())
}
fn note_exit(inner: &Inner, operation: &OperationId, code: i32) -> Result<(), CoordinatorError> {
    match inner
        .state
        .lock()
        .expect("Host state mutex")
        .ledger
        .record_executor_fact(
            operation,
            ExecutorFact::Exited {
                successful: code == 0,
            },
            inner.now(),
        ) {
        Ok(_) | Err(ErrorCategory::StateConflict) => Ok(()),
        Err(error) => Err(error.into()),
    }
}
