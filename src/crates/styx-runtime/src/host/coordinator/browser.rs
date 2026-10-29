//! Browser shares the Host's sole Core ledger and admission/supervision locks.
//! Context acknowledgements never prove physical Browser process cleanup.
use super::*;
use crate::providers::browser::{
    BrowserAction, BrowserActionEvidence, BrowserActionReceipt, BrowserCleanup, BrowserDescendants,
    BrowserError, BrowserHandle, BrowserIoBudget, BrowserOpenSpec, BrowserWorker,
    OwnedBrowserConfig,
};
use std::collections::BTreeMap;
use styx_contracts::capability::{CapabilityId, Scope};

const MAX_BROWSER_HANDLES: usize = 128;

pub(super) struct ProfileBinding {
    owner: OwnerLease,
    config: OwnedBrowserConfig,
    open_payload: Vec<u8>,
}
pub(super) struct BrowserLane {
    pub(super) worker: BrowserWorker,
    pub(super) facts: AdmissionFacts,
    pub(super) profiles: BTreeMap<OwnerId, ProfileBinding>,
    pub(super) handles: BTreeMap<OperationId, BrowserHandle>,
}
#[derive(Debug)]
pub struct BrowserLaneCleanup {
    pub resources: Vec<(OperationId, BrowserCleanup)>,
    pub errors: Vec<(Option<OperationId>, BrowserError)>,
    pub complete: bool,
}
#[derive(Debug)]
pub struct BrowserOpenCompletion {
    pub snapshot: OperationSnapshot,
    pub evidence: BrowserActionEvidence,
    pub cause: Option<BrowserError>,
    pub cleanup_required: bool,
}
pub struct BrowserOpenTicket {
    response: oneshot::Receiver<Result<BrowserOpenCompletion, CoordinatorError>>,
}
impl BrowserOpenTicket {
    pub async fn wait(self) -> Result<BrowserOpenCompletion, CoordinatorError> {
        self.response
            .await
            .map_err(|_| CoordinatorError::ResponseLost)?
    }
}
pub enum BrowserOpenSubmission {
    Submitted(BrowserOpenTicket),
    Existing(OperationSnapshot),
}
#[derive(Debug)]
pub struct BrowserActionCompletion {
    pub snapshot: OperationSnapshot,
    pub receipt: BrowserActionReceipt,
    pub cleanup: Option<BrowserCleanup>,
    pub cleanup_error: Option<BrowserError>,
    pub retention_error: Option<CoordinatorError>,
}
pub struct BrowserActionTicket {
    response: oneshot::Receiver<Result<BrowserActionCompletion, CoordinatorError>>,
}
impl BrowserActionTicket {
    pub async fn wait(self) -> Result<BrowserActionCompletion, CoordinatorError> {
        self.response
            .await
            .map_err(|_| CoordinatorError::ResponseLost)?
    }
}
pub enum BrowserActionSubmission {
    Submitted(BrowserActionTicket),
    Existing(OperationSnapshot),
}
fn validate_facts(inner: &Inner, facts: &AdmissionFacts) -> Result<(), CoordinatorError> {
    if facts.device_id != inner.bootstrap_device
        || facts.descriptor.capability_id != CapabilityId::BrowserHeadless
        || facts.descriptor.scope != Scope::Browser
        || facts.descriptor.target_session.is_some()
        || facts.session_state.is_some()
        || facts.current_observation.is_some()
    {
        return Err(ErrorCategory::StateConflict.into());
    }
    Ok(())
}
fn validate_context(context: &PreparedContext) -> Result<(), CoordinatorError> {
    if context.capability != CapabilityId::BrowserHeadless
        || context.session.is_some()
        || context.observation.is_some()
    {
        return Err(ErrorCategory::StateConflict.into());
    }
    Ok(())
}
fn lane(state: &State) -> Result<&BrowserLane, CoordinatorError> {
    state
        .browser
        .as_ref()
        .ok_or_else(|| BrowserError::Unsupported.into())
}
fn profile<'a>(
    lane: &'a BrowserLane,
    owner: &OwnerLease,
) -> Result<&'a ProfileBinding, CoordinatorError> {
    lane.profiles
        .get(owner.owner_id())
        .filter(|p| &p.owner == owner)
        .ok_or_else(|| ErrorCategory::Unauthorized.into())
}
fn overlaps(a: &std::path::Path, b: &std::path::Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}
fn profiles_disjoint(a: &OwnedBrowserConfig, b: &OwnedBrowserConfig) -> bool {
    let a_private = [&a.profile_dir, &a.output_dir];
    let b_private = [&b.profile_dir, &b.output_dir];
    !a_private.iter().any(|p| overlaps(p, &b.workspace_dir))
        && !b_private.iter().any(|p| overlaps(p, &a.workspace_dir))
        && !a_private
            .iter()
            .any(|p| b_private.iter().any(|q| overlaps(p, q)))
}
fn handle(
    lane: &BrowserLane,
    owner: &OwnerLease,
    target: &ResourceTarget,
) -> Result<BrowserHandle, CoordinatorError> {
    let handle = match lane.handles.get(&target.operation_id) {
        Some(handle) => handle.clone(),
        // Includes an open whose response/settlement task was interrupted after
        // the adapter registered its physical cleanup obligation.
        None => lane.worker.lookup_operation(owner, &target.operation_id)?,
    };
    if handle.owner() != owner
        || handle.operation() != &target.operation_id
        || handle.payload_digest() != target.payload_digest
    {
        return Err(ErrorCategory::Unauthorized.into());
    }
    Ok(handle)
}
impl HostAuthority {
    pub fn configure_browser(
        &self,
        facts: AdmissionFacts,
        budget: Arc<BrowserIoBudget>,
    ) -> Result<(), CoordinatorError> {
        validate_facts(&self.inner, &facts)?;
        let mut state = self.inner.state.lock().expect("Host state mutex");
        if state.shutting_down {
            return Err(CoordinatorError::Busy);
        }
        if state.browser.is_some() {
            return Err(ErrorCategory::StateConflict.into());
        }
        state.browser = Some(BrowserLane {
            worker: BrowserWorker::new(budget),
            facts,
            profiles: BTreeMap::new(),
            handles: BTreeMap::new(),
        });
        Ok(())
    }
    /// Bootstrap-only scope, not caller-controlled tool parameters. Same-owner
    /// re-registration must be byte-identical and never switches profiles.
    pub fn register_browser_profile(
        &self,
        owner: &OwnerLease,
        config: OwnedBrowserConfig,
    ) -> Result<(), CoordinatorError> {
        let open_payload = BrowserOpenSpec::for_config(&config)?.to_operation_payload()?;
        let mut state = self.inner.state.lock().expect("Host state mutex");
        if state.shutting_down {
            return Err(CoordinatorError::Busy);
        }
        state.ledger.validate_owner(owner)?;
        let lane = state.browser.as_mut().ok_or(BrowserError::Unsupported)?;
        if let Some(old) = lane.profiles.get(owner.owner_id()) {
            return if old.owner == *owner && old.open_payload == open_payload {
                Ok(())
            } else {
                Err(ErrorCategory::StateConflict.into())
            };
        }
        if lane.profiles.len() >= 64 {
            return Err(CoordinatorError::Busy);
        }
        for other in lane.profiles.values() {
            if !profiles_disjoint(&config, &other.config) {
                return Err(ErrorCategory::StateConflict.into());
            }
        }
        lane.profiles.insert(
            owner.owner_id().clone(),
            ProfileBinding {
                owner: owner.clone(),
                config,
                open_payload,
            },
        );
        Ok(())
    }
    pub fn replace_browser_facts(&self, facts: AdmissionFacts) -> Result<(), CoordinatorError> {
        validate_facts(&self.inner, &facts)?;
        let mut state = self.inner.state.lock().expect("Host state mutex");
        if state.shutting_down {
            return Err(CoordinatorError::Busy);
        }
        state
            .browser
            .as_mut()
            .ok_or(BrowserError::Unsupported)?
            .facts = facts;
        Ok(())
    }
}
impl HostCoordinator {
    /// Local paired transport lifecycle, not a caller-provided generation or
    /// operation cancellation. Contexts/owners/native work remain unchanged.
    pub(crate) fn invalidate_browser_link_references(&self) {
        let state = self.inner.state.lock().expect("Host state mutex");
        if let Some(browser) = &state.browser {
            browser.worker.invalidate_link_references();
        }
    }
    pub(crate) fn browser_configured(&self) -> bool {
        self.inner
            .state
            .lock()
            .expect("Host state mutex")
            .browser
            .is_some()
    }
    /// History is capability- and target-kind-bound. It does not replay output
    /// or synthesize a fresh execution permit for a prior browser operation.
    pub(crate) fn inspect_browser(
        &self,
        owner: &OwnerLease,
        id: &OperationId,
        digest: Sha256Digest,
        action: bool,
    ) -> Result<OperationSnapshot, CoordinatorError> {
        let state = self.inner.state.lock().expect("Host state mutex");
        validate_context(&state.ledger.inspect_context(owner, id, digest)?)?;
        let snapshot = state.ledger.inspect(owner, id, digest)?;
        if snapshot.target.is_some() != action {
            return Err(ErrorCategory::StateConflict.into());
        }
        Ok(snapshot)
    }
    pub fn prepare_browser_open(
        &self,
        owner: &OwnerLease,
        context: PreparedContext,
    ) -> Result<OperationSnapshot, CoordinatorError> {
        validate_context(&context)?;
        let mut state = self.inner.state.lock().expect("Host state mutex");
        if state.shutting_down {
            return Err(CoordinatorError::Busy);
        }
        let payload = profile(lane(&state)?, owner)?.open_payload.clone();
        Ok(state.ledger.prepare(owner, context, payload, self.now())?)
    }
    pub fn dispatch_browser_open(
        &self,
        owner: &OwnerLease,
        id: &OperationId,
        digest: Sha256Digest,
    ) -> Result<BrowserOpenSubmission, CoordinatorError> {
        {
            let state = self.inner.state.lock().expect("Host state mutex");
            validate_context(&state.ledger.inspect_context(owner, id, digest)?)?;
            let snapshot = state.ledger.inspect(owner, id, digest)?;
            if snapshot.target.is_some() {
                return Err(ErrorCategory::StateConflict.into());
            }
            if snapshot.state != OperationState::Reserved {
                return Ok(BrowserOpenSubmission::Existing(snapshot));
            }
        }
        let execution = self
            .inner
            .execution_gate
            .clone()
            .try_read_owned()
            .map_err(|_| CoordinatorError::Busy)?;
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| CoordinatorError::Busy)?;
        let job_slot = self
            .inner
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| CoordinatorError::Busy)?;
        let mut state = self.inner.state.lock().expect("Host state mutex");
        // A concurrent duplicate can pass the first observation. Recheck under
        // the final admission lock before reserving another physical worker.
        let snapshot = state.ledger.inspect(owner, id, digest)?;
        if snapshot.state != OperationState::Reserved {
            return Ok(BrowserOpenSubmission::Existing(snapshot));
        }
        if state.shutting_down {
            return Err(CoordinatorError::Busy);
        }
        let browser = lane(&state)?;
        if browser.handles.len() >= MAX_BROWSER_HANDLES {
            return Err(CoordinatorError::Busy);
        }
        let config = profile(browser, owner)?.config.clone();
        let facts = browser.facts.clone();
        let slot = match browser.worker.try_reserve_open() {
            Ok(slot) => slot,
            Err(BrowserError::Busy) => {
                // The physical slot refused before spawn/config/native I/O.
                // Consume this exact Reserved operation under the same Core
                // lock: its permit must never become usable on a later retry.
                let permit = match state
                    .ledger
                    .dispatch(owner, id, digest, &facts, self.now())?
                {
                    DispatchDisposition::Existing(snapshot) => {
                        return Ok(BrowserOpenSubmission::Existing(snapshot));
                    }
                    DispatchDisposition::ExecuteOnce(permit) => permit,
                };
                drop(permit); // Never passed to the native provider.
                let snapshot = state.ledger.record_executor_fact(
                    id,
                    ExecutorFact::NotDispatched,
                    self.now(),
                )?;
                let (response, receiver) = oneshot::channel();
                // Submitted is a ready logical completion here, not evidence
                // of native submission or a worker which requires cleanup.
                let _ = response.send(Ok(BrowserOpenCompletion {
                    snapshot,
                    evidence: BrowserActionEvidence::NotDispatched,
                    cause: Some(BrowserError::Busy),
                    cleanup_required: false,
                }));
                return Ok(BrowserOpenSubmission::Submitted(BrowserOpenTicket {
                    response: receiver,
                }));
            }
            Err(error) => return Err(error.into()),
        };
        let permit = match state
            .ledger
            .dispatch(owner, id, digest, &facts, self.now())?
        {
            DispatchDisposition::Existing(snapshot) => {
                return Ok(BrowserOpenSubmission::Existing(snapshot));
            }
            DispatchDisposition::ExecuteOnce(permit) => permit,
        };
        let operation = id.clone();
        let inner = self.inner.clone();
        let (response, receiver) = oneshot::channel();
        let mut guard = UnsettledStart {
            inner: inner.clone(),
            operation: operation.clone(),
            settled: false,
            _execution: execution,
        };
        let mut jobs = self.inner.jobs.lock().expect("Host jobs mutex");
        while jobs.try_join_next().is_some() {}
        jobs.spawn_on(
            async move {
                let _slot = job_slot;
                let (evidence, cause, opened) = match slot.spawn_owned(permit, config).await {
                    Ok(receipt) => (receipt.evidence, None, Some(receipt.handle)),
                    Err(failure) => (failure.evidence, Some(failure.cause), failure.handle),
                };
                let cleanup_required = opened.is_some();
                let mut state = inner.state.lock().expect("Host state mutex");
                if let Some(opened) = opened
                    && let Some(lane) = &mut state.browser
                {
                    lane.handles.insert(operation.clone(), opened);
                }
                let result = match evidence {
                    BrowserActionEvidence::Acknowledged => state.ledger.record_executor_fact(
                        &operation,
                        ExecutorFact::Running,
                        inner.now(),
                    ),
                    BrowserActionEvidence::NotDispatched => state.ledger.record_executor_fact(
                        &operation,
                        ExecutorFact::NotDispatched,
                        inner.now(),
                    ),
                    BrowserActionEvidence::Unknown => state.ledger.mark_result_unknown(&operation),
                };
                guard.settled = result.is_ok();
                drop(state);
                drop(guard);
                let _ = response.send(
                    result
                        .map(|snapshot| BrowserOpenCompletion {
                            snapshot,
                            evidence,
                            cause,
                            cleanup_required,
                        })
                        .map_err(CoordinatorError::from),
                );
            },
            &runtime,
        );
        drop(jobs);
        drop(state);
        Ok(BrowserOpenSubmission::Submitted(BrowserOpenTicket {
            response: receiver,
        }))
    }
    pub fn prepare_browser_action(
        &self,
        owner: &OwnerLease,
        target: ResourceTarget,
        context: PreparedContext,
        action: &BrowserAction,
    ) -> Result<OperationSnapshot, CoordinatorError> {
        validate_context(&context)?;
        let payload = action.to_operation_payload()?;
        let mut state = self.inner.state.lock().expect("Host state mutex");
        if state.shutting_down {
            return Err(CoordinatorError::Busy);
        }
        handle(lane(&state)?, owner, &target)?;
        Ok(state
            .ledger
            .prepare_targeted(owner, target, context, payload, self.now())?)
    }
    pub fn dispatch_browser_action(
        &self,
        owner: &OwnerLease,
        id: &OperationId,
        digest: Sha256Digest,
    ) -> Result<BrowserActionSubmission, CoordinatorError> {
        {
            let state = self.inner.state.lock().expect("Host state mutex");
            validate_context(&state.ledger.inspect_context(owner, id, digest)?)?;
            let snapshot = state.ledger.inspect(owner, id, digest)?;
            if snapshot.target.is_none() {
                return Err(ErrorCategory::StateConflict.into());
            }
            if snapshot.state != OperationState::Reserved {
                return Ok(BrowserActionSubmission::Existing(snapshot));
            }
        }
        let execution = self
            .inner
            .execution_gate
            .clone()
            .try_read_owned()
            .map_err(|_| CoordinatorError::Busy)?;
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| CoordinatorError::Busy)?;
        let job_slot = self
            .inner
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| CoordinatorError::Busy)?;
        let mut state = self.inner.state.lock().expect("Host state mutex");
        let snapshot = state.ledger.inspect(owner, id, digest)?;
        if snapshot.state != OperationState::Reserved {
            return Ok(BrowserActionSubmission::Existing(snapshot));
        }
        if state.shutting_down {
            return Err(CoordinatorError::Busy);
        }
        let target = snapshot
            .target
            .as_ref()
            .ok_or(ErrorCategory::StateConflict)?;
        let browser = lane(&state)?;
        let bound = handle(browser, owner, target)?;
        let worker = browser.worker.clone();
        let slot = worker.try_reserve_action(&bound)?;
        let facts = browser.facts.clone();
        let permit = match state
            .ledger
            .dispatch(owner, id, digest, &facts, self.now())?
        {
            DispatchDisposition::Existing(snapshot) => {
                return Ok(BrowserActionSubmission::Existing(snapshot));
            }
            DispatchDisposition::ExecuteOnce(permit) => permit,
        };
        let delivery_context = permit.context().clone();
        let is_close = serde_json::from_slice::<BrowserAction>(permit.payload())
            .is_ok_and(|action| action.is_close());
        let operation = id.clone();
        let inner = self.inner.clone();
        let (response, receiver) = oneshot::channel();
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
                let _slot = job_slot;
                let receipt = slot.call_once(permit).await;
                let fact = match receipt.evidence {
                    BrowserActionEvidence::Acknowledged => ActionResult::Acknowledged,
                    BrowserActionEvidence::NotDispatched => ActionResult::NotDispatched,
                    BrowserActionEvidence::Unknown => ActionResult::Unknown,
                };
                let (cleanup, cleanup_error) = if is_close {
                    match worker.cleanup_owned(&bound, Duration::from_secs(5)).await {
                        Ok(facts) => (Some(facts), None),
                        Err(e) => (None, Some(e)),
                    }
                } else {
                    (None, None)
                };
                let mut state = inner.state.lock().expect("Host state mutex");
                let result = state
                    .ledger
                    .record_action_result(&operation, fact, inner.now());
                guard.settled = result.is_ok();
                let retention_error = worker
                    .action_audit(&receipt)
                    .map_err(CoordinatorError::from)
                    .and_then(|audit| {
                        state
                            .ledger
                            .record_provider_audit(&operation, audit)
                            .map_err(CoordinatorError::from)
                    })
                    .err();
                if let Some(cleanup) = &cleanup {
                    let _ =
                        settle_physical(&mut state.ledger, bound.operation(), cleanup, inner.now());
                }
                let delivery = if is_close {
                    Ok(())
                } else if state.shutting_down {
                    Err(ErrorCategory::StateConflict)
                } else {
                    let facts = state
                        .browser
                        .as_ref()
                        .map(|b| b.facts.clone())
                        .ok_or(ErrorCategory::CapabilityUnsupported);
                    facts.and_then(|facts| {
                        state
                            .ledger
                            .authorize_resource_access(
                                bound.owner(),
                                bound.operation(),
                                bound.payload_digest(),
                                &delivery_context,
                                &facts,
                                inner.now(),
                            )
                            .map(|_| ())
                    })
                };
                drop(state);
                drop(guard);
                if let Err(reason) = delivery {
                    let _ = response.send(Err(CoordinatorError::OutputDeliveryDenied(reason)));
                    return;
                }
                let _ = response.send(
                    result
                        .map(|snapshot| BrowserActionCompletion {
                            snapshot,
                            receipt,
                            cleanup,
                            cleanup_error,
                            retention_error,
                        })
                        .map_err(CoordinatorError::from),
                );
            },
            &runtime,
        );
        drop(jobs);
        drop(state);
        Ok(BrowserActionSubmission::Submitted(BrowserActionTicket {
            response: receiver,
        }))
    }
}
fn physical_complete(facts: &BrowserCleanup) -> bool {
    facts.worker_exited && facts.stdio_joined && facts.descendants == BrowserDescendants::Confirmed
}
fn settle_physical(
    ledger: &mut OperationLedger,
    operation: &OperationId,
    facts: &BrowserCleanup,
    now: MonotonicMillis,
) -> Result<(), ErrorCategory> {
    if physical_complete(facts) {
        let previous = ledger
            .retained_provider_records()
            .into_iter()
            .find(|key| key.snapshot().id == *operation)
            .ok_or(ErrorCategory::StateConflict)?;
        let snapshot = previous.snapshot();
        if previous.capability() != CapabilityId::BrowserHeadless || snapshot.target.is_some() {
            return Err(ErrorCategory::StateConflict);
        }
        if snapshot.liveness == ExecutionLiveness::Exited {
            if matches!(
                (facts.worker_exit_success, snapshot.state),
                (Some(true), OperationState::Failed) | (Some(false), OperationState::Succeeded)
            ) {
                return Err(ErrorCategory::IntegrityFailure);
            }
            // Same physical fact is idempotent; do not refresh terminal time or
            // overwrite sticky Unknown. Less informative status isn't a rewrite.
            if snapshot.output_drain != OutputDrain::Drained {
                ledger.record_executor_fact(operation, ExecutorFact::OutputDrained, now)?;
            }
            return Ok(());
        }
        // Actual worker exit status describes this resource lifetime only.
        // No status proof means Unknown, not invented success; action records
        // remain independent and an earlier Unknown is sticky in Core.
        let successful = match facts.worker_exit_success {
            Some(success) => success,
            None => {
                ledger.mark_result_unknown(operation)?;
                false
            }
        };
        ledger.record_executor_fact(operation, ExecutorFact::Exited { successful }, now)?;
        ledger.record_executor_fact(operation, ExecutorFact::OutputDrained, now)?;
    }
    Ok(())
}
/// Called only from the Host's total-budget shutdown, after its admission fence.
/// Includes adapter-owned failed starts, not only returned successful handles.
pub(super) async fn cleanup_browser_lane(
    inner: Arc<Inner>,
    budget: Duration,
) -> Option<BrowserLaneCleanup> {
    let worker = {
        let state = inner.state.lock().expect("Host state mutex");
        state.browser.as_ref().map(|b| b.worker.clone())
    };
    let mut report = BrowserLaneCleanup {
        resources: Vec::new(),
        errors: Vec::new(),
        complete: true,
    };
    let worker = worker?;
    match worker.cleanup_all_owned(budget).await {
        Err(error) => {
            report.errors.push((None, error));
            report.complete = false;
        }
        Ok(results) => {
            for (handle, result) in results {
                match result {
                    Err(error) => {
                        report
                            .errors
                            .push((Some(handle.operation().clone()), error));
                        report.complete = false;
                    }
                    Ok(facts) => {
                        if !physical_complete(&facts) {
                            report.complete = false;
                        }
                        let mut state = inner.state.lock().expect("Host state mutex");
                        if settle_physical(
                            &mut state.ledger,
                            handle.operation(),
                            &facts,
                            inner.now(),
                        )
                        .is_err()
                        {
                            report.complete = false;
                        }
                        report.resources.push((handle.operation().clone(), facts));
                    }
                }
            }
        }
    }
    Some(report)
}
/// Revoked-owner cleanup uses the original opaque incarnation and never
/// touches another owner's contexts. Core-dispatched but not yet registered
/// adapter starts keep this report incomplete rather than looking like emptiness.
pub(super) async fn cleanup_browser_owner(
    inner: Arc<Inner>,
    owner: &OwnerLease,
    budget: Duration,
) -> Option<BrowserLaneCleanup> {
    let worker = {
        let state = inner.state.lock().expect("Host state mutex");
        state.browser.as_ref().map(|b| b.worker.clone())
    }?;
    let until = tokio::time::Instant::now() + budget.min(Duration::from_secs(30));
    let mut report = BrowserLaneCleanup {
        resources: Vec::new(),
        errors: Vec::new(),
        complete: true,
    };
    let mut processed = std::collections::BTreeSet::new();
    loop {
        let handles = match worker.handles() {
            Ok(handles) => handles,
            Err(e) => {
                report.errors.push((None, e));
                report.complete = false;
                break;
            }
        };
        for handle in handles.into_iter().filter(|h| h.owner() == owner) {
            if !processed.insert(handle.operation().clone()) {
                continue;
            }
            match worker
                .cleanup_owned(
                    &handle,
                    until.saturating_duration_since(tokio::time::Instant::now()),
                )
                .await
            {
                Err(error) => {
                    report
                        .errors
                        .push((Some(handle.operation().clone()), error));
                    report.complete = false;
                }
                Ok(facts) => {
                    if !physical_complete(&facts) {
                        report.complete = false;
                    }
                    let mut state = inner.state.lock().expect("Host state mutex");
                    if settle_physical(&mut state.ledger, handle.operation(), &facts, inner.now())
                        .is_err()
                    {
                        report.complete = false;
                    }
                    report.resources.push((handle.operation().clone(), facts));
                }
            }
        }
        let missing = {
            let state = inner.state.lock().expect("Host state mutex");
            state.ledger.retained_provider_records().iter().any(|key| {
                key.owner() == owner
                    && key.capability() == CapabilityId::BrowserHeadless
                    && key.snapshot().target.is_none()
                    && !processed.contains(&key.snapshot().id)
            })
        };
        if !missing {
            break;
        }
        if tokio::time::Instant::now() >= until {
            report.complete = false;
            report.errors.push((None, BrowserError::CleanupUnconfirmed));
            break;
        }
        tokio::time::sleep(
            Duration::from_millis(5)
                .min(until.saturating_duration_since(tokio::time::Instant::now())),
        )
        .await;
    }
    Some(report)
}
#[derive(Debug)]
pub(super) struct BrowserRetentionCollection {
    pub(super) actions_released: usize,
    pub(super) resources_released: usize,
    pub(super) deadline_exhausted: bool,
    pub(super) blocked: Vec<RetentionBlock>,
}
/// Caller holds cleanup_lock and execution_gate.write across this entire port.
/// No native action, context closure or implicit business replay occurs here.
pub(super) async fn collect_browser_retention(
    inner: &Arc<Inner>,
    owner: Option<&OwnerLease>,
    until: tokio::time::Instant,
) -> BrowserRetentionCollection {
    let mut report = BrowserRetentionCollection {
        actions_released: 0,
        resources_released: 0,
        deadline_exhausted: false,
        blocked: Vec::new(),
    };
    let worker = {
        let state = inner.state.lock().expect("Host state mutex");
        state.browser.as_ref().map(|b| b.worker.clone())
    };
    let Some(worker) = worker else { return report };
    let inventory = inner
        .state
        .lock()
        .expect("Host state mutex")
        .ledger
        .retained_provider_records();
    for key in inventory.iter().filter(|k| {
        k.capability() == CapabilityId::BrowserHeadless
            && k.snapshot().target.is_some()
            && owner.is_none_or(|o| k.owner() == o)
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
            let existing_audit = inner
                .state
                .lock()
                .expect("Host state mutex")
                .ledger
                .provider_audit(&snapshot.id)
                .map(<[u8]>::to_vec);
            let receipt = if let Some(bytes) = existing_audit {
                if key.audit_digest() != Some(Sha256Digest::of_bytes(&bytes)) {
                    return Err(ErrorCategory::IntegrityFailure.into());
                }
                BrowserWorker::action_from_audit(snapshot.id.clone(), &bytes)?
            } else {
                match tokio::time::timeout_at(until, worker.action_receipt(key))
                    .await
                    .map_err(|_| CoordinatorError::Busy)?
                {
                    Ok(receipt) => receipt,
                    Err(BrowserError::Unknown)
                        if matches!(
                            snapshot.state,
                            OperationState::Unknown | OperationState::Failed
                        ) =>
                    {
                        BrowserActionReceipt {
                            operation: snapshot.id.clone(),
                            evidence: if snapshot.state == OperationState::Unknown {
                                BrowserActionEvidence::Unknown
                            } else {
                                BrowserActionEvidence::NotDispatched
                            },
                            result: None,
                            cause: Some(BrowserError::Unknown),
                        }
                    }
                    Err(error) => return Err(error.into()),
                }
            };
            let audit = worker.action_audit(&receipt)?;
            let permit = {
                let mut state = inner.state.lock().expect("Host state mutex");
                state.ledger.record_provider_audit(&snapshot.id, audit)?;
                if snapshot.state == OperationState::Unknown {
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
    for key in inventory.iter().filter(|k| {
        k.capability() == CapabilityId::BrowserHeadless
            && k.snapshot().target.is_none()
            && owner.is_none_or(|o| k.owner() == o)
    }) {
        if tokio::time::Instant::now() >= until {
            report.deadline_exhausted = true;
            break;
        }
        let snapshot = key.snapshot();
        let result = async {
            let ended = matches!(
                snapshot.liveness,
                ExecutionLiveness::Exited | ExecutionLiveness::NotStarted
            ) && matches!(
                snapshot.output_drain,
                OutputDrain::Drained | OutputDrain::NotOpened
            ) && snapshot.state != OperationState::Reserved;
            if !ended {
                return Err(CoordinatorError::Busy);
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
            if let Some(lane) = &mut state.browser {
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
    report
}
/// Caller has separately proved original-owner cleanup inventory empty. Dropping
/// this scope metadata never deletes the private profile or its login bytes.
pub(super) fn release_browser_profile(inner: &Arc<Inner>, owner: &OwnerLease) {
    let mut state = inner.state.lock().expect("Host state mutex");
    if let Some(lane) = &mut state.browser
        && lane
            .profiles
            .get(owner.owner_id())
            .is_some_and(|p| &p.owner == owner)
    {
        lane.profiles.remove(owner.owner_id());
    }
}
// These existing fixtures use Unix paths/native Linux process scopes.
// Windows acceptance uses its actual protected Job and platform journey.
#[cfg(all(test, target_os = "linux"))]
#[path = "browser_tests.rs"]
mod browser_tests;
