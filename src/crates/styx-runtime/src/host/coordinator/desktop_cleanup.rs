//! Cua physical cleanup and Core-attested retention share the Host's sole ledger.
//! Native scope/IO facts are distinct from action ACK and historical outcome.
use super::desktop_source::{DesktopSourceStop, source_stop_complete};
use super::*;
use crate::providers::cua::{CuaCleanup, CuaError, CuaEvidence, CuaHandle, CuaReceipt, CuaWorker};
use std::collections::{BTreeMap, BTreeSet};
use styx_contracts::capability::CapabilityId;
use styx_core::operations::{ProviderRecordKey, ResourceDomain};

#[derive(Debug)]
pub struct DesktopLaneCleanup {
    pub resources: Vec<(OperationId, CuaCleanup)>,
    pub errors: Vec<(Option<OperationId>, CuaError)>,
    pub complete: bool,
    pub source_report: Option<DesktopSourceStop>,
    pub source_error: bool,
}
#[derive(Debug)]
pub(super) struct DesktopRetentionCollection {
    pub(super) actions_released: usize,
    pub(super) resources_released: usize,
    pub(super) deadline_exhausted: bool,
    pub(super) blocked: Vec<RetentionBlock>,
}
fn physical_complete(facts: &CuaCleanup) -> bool {
    facts.complete()
}
fn strict_no_io(snapshot: &OperationSnapshot) -> bool {
    snapshot.state == OperationState::Failed
        && snapshot.liveness == ExecutionLiveness::NotStarted
        && snapshot.output_drain == OutputDrain::NotOpened
}
fn key_for_handle(key: &ProviderRecordKey, handle: &CuaHandle) -> bool {
    let snapshot = key.snapshot();
    key.resource_domain() == ResourceDomain::DesktopAgent
        && key.capability() == CapabilityId::DesktopWindowsRead
        && key.owner() == handle.owner()
        && snapshot.target.is_none()
        && snapshot.id == handle.target().operation_id
        && snapshot.payload_digest == handle.target().payload_digest
}
/// Original typed adapter handle is an additional authority boundary. An
/// arbitrary WindowsRead record cannot be settled as a native Cua resource.
pub(super) fn settle_desktop_physical(
    ledger: &mut OperationLedger,
    handle: &CuaHandle,
    facts: &CuaCleanup,
    now: MonotonicMillis,
) -> Result<(), ErrorCategory> {
    if !physical_complete(facts) {
        return Ok(());
    }
    let key = ledger
        .retained_provider_records()
        .into_iter()
        .find(|key| key_for_handle(key, handle))
        .ok_or(ErrorCategory::StateConflict)?;
    let snapshot = key.snapshot();
    let id = &handle.target().operation_id;
    if snapshot.liveness == ExecutionLiveness::Exited {
        if matches!(
            (facts.worker_exit_success, snapshot.state),
            (Some(true), OperationState::Failed) | (Some(false), OperationState::Succeeded)
        ) {
            return Err(ErrorCategory::IntegrityFailure);
        }
        if snapshot.output_drain != OutputDrain::Drained {
            ledger.record_executor_fact(id, ExecutorFact::OutputDrained, now)?;
        }
        return Ok(());
    }
    // A real wait without usable exit status does not mint successful outcome.
    // mark_result_unknown preserves uncertainty while independent exit/drain
    // facts permit physical reclamation. No action record is modified here.
    let successful = match facts.worker_exit_success {
        Some(success) => success,
        None => {
            ledger.mark_result_unknown(id)?;
            false
        }
    };
    ledger.record_executor_fact(id, ExecutorFact::Exited { successful }, now)?;
    ledger.record_executor_fact(id, ExecutorFact::OutputDrained, now)?;
    Ok(())
}

/// Total Host shutdown invokes this only after its ordinary admission fence.
/// Includes adapter-registered failed starts even if no ticket was delivered.
pub(super) async fn cleanup_desktop_lane(
    inner: Arc<Inner>,
    budget: Duration,
) -> Option<DesktopLaneCleanup> {
    let source = {
        let state = inner.state.lock().expect("Host state mutex");
        state.desktop.as_ref().map(|lane| lane.source.clone())
    }?;
    let until = tokio::time::Instant::now() + budget.min(Duration::from_secs(30));
    // Both futures are polled together: fence/cancel the shared source and native
    // wait promptly. Source::stop preserves its original JoinHandle on timeout.
    let (native, source_result) = tokio::join!(
        cleanup_selected(inner, None, budget),
        tokio::time::timeout_at(until, source.stop())
    );
    let mut report = native?;
    match source_result {
        Ok(Ok(facts)) => {
            report.source_error = !source_stop_complete(&facts);
            report.source_report = Some(facts);
        }
        _ => report.source_error = true,
    }
    report.complete &= !report.source_error;
    Some(report)
}
/// Uses the original opaque revoked-owner incarnation, never a name/remote PID.
pub(super) async fn cleanup_desktop_owner(
    inner: Arc<Inner>,
    owner: &OwnerLease,
    budget: Duration,
) -> Option<DesktopLaneCleanup> {
    cleanup_selected(inner, Some(owner), budget).await
}
async fn cleanup_selected(
    inner: Arc<Inner>,
    owner: Option<&OwnerLease>,
    budget: Duration,
) -> Option<DesktopLaneCleanup> {
    let worker = {
        let mut state = inner.state.lock().expect("Host state mutex");
        super::desktop_observation::invalidate(state.desktop.as_mut(), owner);
        state.desktop.as_ref().map(|lane| lane.worker.clone())
    }?;
    let until = tokio::time::Instant::now() + budget.min(Duration::from_secs(30));
    let mut resources = BTreeMap::new();
    let mut errors = BTreeMap::new();
    let mut finished = BTreeSet::new();
    loop {
        let mut handles = BTreeMap::<OperationId, CuaHandle>::new();
        match worker.resources() {
            Ok(provider) => {
                for handle in provider
                    .into_iter()
                    .filter(|handle| owner.is_none_or(|owner| handle.owner() == owner))
                {
                    handles.insert(handle.target().operation_id.clone(), handle);
                }
            }
            Err(error) => {
                errors.insert(None, error);
            }
        }
        // The provider inventory is primary; returned handles additionally retain
        // exact ownership during interrupted registration/delivery settlement.
        {
            let state = inner.state.lock().expect("Host state mutex");
            if let Some(lane) = &state.desktop {
                for handle in lane
                    .handles
                    .values()
                    .filter(|handle| owner.is_none_or(|owner| handle.owner() == owner))
                {
                    let id = handle.target().operation_id.clone();
                    if let Some(previous) = handles.get(&id) {
                        if previous.target() != handle.target()
                            || previous.owner() != handle.owner()
                        {
                            errors.insert(Some(id), CuaError::ProtocolMismatch);
                            continue;
                        }
                    } else {
                        handles.insert(id, handle.clone());
                    }
                }
            }
        }
        for (id, handle) in handles.iter() {
            if finished.contains(id) {
                continue;
            }
            let remaining = until.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                errors.insert(Some(id.clone()), CuaError::CleanupUnconfirmed);
                continue;
            }
            match worker.cleanup_owned(handle, remaining).await {
                Err(error) => {
                    errors.insert(Some(id.clone()), error);
                }
                Ok(facts) => {
                    resources.insert(id.clone(), facts);
                    if physical_complete(&facts) {
                        let settled = {
                            let mut state = inner.state.lock().expect("Host state mutex");
                            settle_desktop_physical(&mut state.ledger, handle, &facts, inner.now())
                        };
                        match settled {
                            Ok(()) => {
                                finished.insert(id.clone());
                                errors.remove(&Some(id.clone()));
                            }
                            Err(_) => {
                                errors.insert(Some(id.clone()), CuaError::ProtocolMismatch);
                            }
                        }
                    } else {
                        errors.insert(Some(id.clone()), CuaError::CleanupUnconfirmed);
                    }
                }
            }
        }
        let pending = {
            let state = inner.state.lock().expect("Host state mutex");
            state
                .ledger
                .retained_provider_records()
                .into_iter()
                .filter(|key| {
                    key.resource_domain() == ResourceDomain::DesktopAgent
                        && key.snapshot().target.is_none()
                        && owner.is_none_or(|owner| key.owner() == owner)
                        && !strict_no_io(key.snapshot())
                        && !finished.contains(&key.snapshot().id)
                })
                .map(|key| key.snapshot().id.clone())
                .collect::<Vec<_>>()
        };
        let all_handles_finished = handles.keys().all(|id| finished.contains(id));
        if pending.is_empty() && all_handles_finished {
            break;
        }
        if tokio::time::Instant::now() >= until {
            for id in pending {
                errors.insert(Some(id), CuaError::CleanupUnconfirmed);
            }
            break;
        }
        tokio::time::sleep(
            Duration::from_millis(10)
                .min(until.saturating_duration_since(tokio::time::Instant::now())),
        )
        .await;
    }
    Some(DesktopLaneCleanup {
        resources: resources.into_iter().collect(),
        complete: errors.is_empty(),
        errors: errors.into_iter().collect(),
        source_report: None,
        source_error: false,
    })
}

/// Caller holds cleanup_lock plus execution_gate.write throughout. This port
/// never terminates a live agent or sends a native call. Cancellation after a
/// linear release begins leaves Core ReleasePending; it cannot imply success.
pub(super) async fn collect_desktop_retention(
    inner: &Arc<Inner>,
    owner: Option<&OwnerLease>,
    until: tokio::time::Instant,
) -> DesktopRetentionCollection {
    let mut report = DesktopRetentionCollection {
        actions_released: 0,
        resources_released: 0,
        deadline_exhausted: false,
        blocked: Vec::new(),
    };
    let worker = {
        let state = inner.state.lock().expect("Host state mutex");
        state.desktop.as_ref().map(|lane| lane.worker.clone())
    };
    let Some(worker) = worker else { return report };
    let inventory = inner
        .state
        .lock()
        .expect("Host state mutex")
        .ledger
        .retained_provider_records();
    for key in inventory.iter().filter(|key| {
        key.resource_domain() == ResourceDomain::DesktopAgent
            && key.snapshot().target.is_some()
            && owner.is_none_or(|owner| key.owner() == owner)
    }) {
        if tokio::time::Instant::now() >= until {
            report.deadline_exhausted = true;
            break;
        }
        let snapshot = key.snapshot();
        let result = async {
            if matches!(
                snapshot.state,
                OperationState::Reserved | OperationState::Dispatched | OperationState::Running
            ) {
                return Err(CoordinatorError::Busy);
            }
            let target = snapshot
                .target
                .as_ref()
                .ok_or(ErrorCategory::StateConflict)?;
            let owned = worker.resources()?;
            if owned.iter().any(|handle| {
                handle.target().operation_id == target.operation_id
                    && (handle.target() != target || handle.owner() != key.owner())
            }) {
                return Err(ErrorCategory::IntegrityFailure.into());
            }
            let parent_registered = owned
                .iter()
                .any(|handle| handle.target() == target && handle.owner() == key.owner());
            let audit = inner
                .state
                .lock()
                .expect("Host state mutex")
                .ledger
                .provider_audit(&snapshot.id)
                .map(<[u8]>::to_vec);
            let receipt = if let Some(bytes) = audit {
                if key.audit_digest() != Some(Sha256Digest::of_bytes(&bytes)) {
                    return Err(ErrorCategory::IntegrityFailure.into());
                }
                CuaWorker::action_from_audit(snapshot.id.clone(), &bytes)?
            } else {
                match tokio::time::timeout_at(until, worker.action_receipt(key))
                    .await
                    .map_err(|_| CoordinatorError::Busy)?
                {
                    Ok(receipt) => receipt,
                    Err(CuaError::Unknown) if snapshot.state == OperationState::Unknown => {
                        CuaReceipt {
                            operation: snapshot.id.clone(),
                            evidence: CuaEvidence::Unknown,
                            result: None,
                            cause: Some(CuaError::Unknown),
                        }
                    }
                    // Missing data alone is never NotSent. Only Core's original strict
                    // targeted no-dispatch state permits its canonical historical audit.
                    Err(CuaError::Unknown)
                        if snapshot.state == OperationState::Failed
                            && snapshot.liveness == ExecutionLiveness::NotApplicable
                            && snapshot.output_drain == OutputDrain::NotOpened =>
                    {
                        CuaReceipt {
                            operation: snapshot.id.clone(),
                            evidence: CuaEvidence::NotDispatched,
                            result: None,
                            cause: Some(CuaError::Unknown),
                        }
                    }
                    Err(error) => return Err(error.into()),
                }
            };
            let audit = worker.action_audit(&receipt)?;
            let permit = {
                let mut state = inner.state.lock().expect("Host state mutex");
                state.ledger.record_provider_audit(&snapshot.id, audit)?;
                if snapshot.state == OperationState::Unknown || !parent_registered {
                    None
                } else {
                    Some(state.ledger.begin_action_release(&snapshot.id)?)
                }
            };
            if let Some(permit) = permit {
                let proof = tokio::time::timeout_at(until, worker.release_action(permit))
                    .await
                    .map_err(|_| CoordinatorError::Busy)??;
                inner
                    .state
                    .lock()
                    .expect("Host state mutex")
                    .ledger
                    .record_provider_release(proof)?;
                report.actions_released += 1;
            }
            Ok::<(), CoordinatorError>(())
        }
        .await;
        if let Err(error) = result {
            report.blocked.push(RetentionBlock {
                operation: snapshot.id.clone(),
                error,
            });
        }
    }
    let inventory = inner
        .state
        .lock()
        .expect("Host state mutex")
        .ledger
        .retained_provider_records();
    for key in inventory.iter().filter(|key| {
        key.resource_domain() == ResourceDomain::DesktopAgent
            && key.snapshot().target.is_none()
            && owner.is_none_or(|owner| key.owner() == owner)
    }) {
        if tokio::time::Instant::now() >= until {
            report.deadline_exhausted = true;
            break;
        }
        let snapshot = key.snapshot();
        let result = async {
            let ended = snapshot.liveness == ExecutionLiveness::Exited
                && snapshot.output_drain == OutputDrain::Drained
                || strict_no_io(snapshot);
            if !ended {
                return Err(CoordinatorError::Busy);
            }
            // Reconcile the exact native resource if it exists. Domain metadata alone
            // cannot turn an unrelated WindowsRead record into physical proof.
            let provider = worker.resources()?;
            let found = provider.iter().find(|handle| key_for_handle(key, handle));
            if !strict_no_io(snapshot) && found.is_none() {
                return Err(CuaError::CleanupUnconfirmed.into());
            }
            if provider.iter().any(|handle| {
                handle.target().operation_id == snapshot.id && !key_for_handle(key, handle)
            }) {
                return Err(ErrorCategory::IntegrityFailure.into());
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
            let proof = tokio::time::timeout_at(until, worker.release_resource(permit))
                .await
                .map_err(|_| CoordinatorError::Busy)??;
            let mut state = inner.state.lock().expect("Host state mutex");
            state.ledger.record_provider_release(proof)?;
            if let Some(lane) = &mut state.desktop {
                lane.handles.remove(&snapshot.id);
            }
            report.resources_released += 1;
            Ok::<(), CoordinatorError>(())
        }
        .await;
        if let Err(error) = result {
            report.blocked.push(RetentionBlock {
                operation: snapshot.id.clone(),
                error,
            });
        }
    }
    report.deadline_exhausted |= tokio::time::Instant::now() >= until;
    report
}
