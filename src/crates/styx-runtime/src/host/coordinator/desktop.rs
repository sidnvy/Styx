//! Desktop operations share the original Host ledger, grants and job ownership.
//! A live local session supervisor is distinct from the native Cua backend.
use super::desktop_source::DesktopSource;
use super::*;
use crate::providers::cua::{
    CuaAction, CuaError, CuaEvidence, CuaHandle, CuaOpenSlot, CuaOpenSpec, CuaReceipt, CuaWorker,
    OwnedCuaConfig,
};
use crate::session::ProviderEvidence;
use std::collections::BTreeMap;
use styx_contracts::{capability::*, session::SessionBinding};

/// Trusted configuration/grant facts. Native availability is NEVER stored here.
#[derive(Clone)]
pub(crate) struct DesktopGrant {
    pub(crate) configured: bool,
    pub(crate) remote_grant: bool,
    pub(crate) local_policy_allowed: bool,
}
pub(super) struct DesktopProfile {
    owner: OwnerLease,
    config: OwnedCuaConfig,
    payload: Vec<u8>,
}
pub(super) struct DesktopResource {
    pub(super) handle: CuaHandle,
}
pub(super) struct DesktopLane {
    pub(super) worker: CuaWorker,
    pub(super) source: DesktopSource,
    pub(super) binding: SessionBinding,
    pub(super) grants: BTreeMap<CapabilityId, DesktopGrant>,
    profiles: BTreeMap<OwnerId, DesktopProfile>,
    pub(super) handles: BTreeMap<OperationId, DesktopResource>,
    #[cfg(all(test, target_os = "linux"))]
    open_history: Vec<(OwnerLease, ResourceTarget)>,
}
struct DesktopOpenAdmission {
    execution: OwnedRwLockReadGuard<()>,
    slot: Result<CuaOpenSlot, CuaError>,
    waited: bool,
}
#[derive(Debug)]
pub(crate) struct DesktopOpenCompletion {
    pub(crate) snapshot: OperationSnapshot,
    pub(crate) evidence: CuaEvidence,
    pub(crate) cause: Option<CuaError>,
}
pub(crate) enum DesktopOpenSubmission {
    Completed(DesktopOpenCompletion),
    Existing(OperationSnapshot),
}
#[derive(Debug)]
pub(crate) struct DesktopActionCompletion {
    pub(crate) snapshot: OperationSnapshot,
    pub(crate) receipt: CuaReceipt,
}
pub(crate) enum DesktopActionSubmission {
    Completed(DesktopActionCompletion),
    Existing(OperationSnapshot),
}
pub(super) fn desktop(state: &State) -> Result<&DesktopLane, CoordinatorError> {
    state
        .desktop
        .as_ref()
        .ok_or_else(|| CuaError::Unsupported.into())
}
fn validate_context(lane: &DesktopLane, context: &PreparedContext) -> Result<(), CoordinatorError> {
    if context.session.as_ref() != Some(&lane.binding)
        || !matches!(
            context.capability,
            CapabilityId::DesktopWindowsRead
                | CapabilityId::DesktopWindowsControl
                | CapabilityId::DesktopCapture
                | CapabilityId::DesktopPointer
                | CapabilityId::DesktopKeyboard
                | CapabilityId::DesktopAccessibility
        )
        || lane.source.fenced()
    {
        return Err(ErrorCategory::SessionDisconnected.into());
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn window_read_evidence(source: &DesktopSource) -> Result<ProviderEvidence, CoordinatorError> {
    let evidence = source
        .window_read_evidence()
        .map_err(|_| CuaError::PermissionDenied)?;
    let (pid, birth) = evidence.source_peer();
    let (device, inode) = evidence.socket_identity();
    let (monitors, clients) = evidence.query_counts();
    let (monitor_hash, client_hash) = evidence.response_sha256();
    Ok(ProviderEvidence {
        capability: CapabilityId::DesktopWindowsRead,
        provider: "hyprland-authenticated-read"
            .try_into()
            .expect("fixed provider"),
        availability: Availability::Available,
        authorization: Authorization::Granted,
        provenance: format!(
            "bounded EOF read peer={pid}:{birth} socket={device}:{inode} monitors={monitors}:{} clients={clients}:{}",
            monitor_hash.to_hex(),
            client_hash.to_hex()
        ),
        reason: None,
        recovery: styx_contracts::error::Recovery::None,
    })
}
#[cfg(target_os = "macos")]
fn window_read_evidence(source: &DesktopSource) -> Result<ProviderEvidence, CoordinatorError> {
    source
        .provider_evidence(CapabilityId::DesktopWindowsRead)
        .map_err(|_| CuaError::PermissionDenied.into())
}

#[cfg(target_os = "windows")]
fn window_read_evidence(source: &DesktopSource) -> Result<ProviderEvidence, CoordinatorError> {
    let evidence = source
        .window_read_evidence()
        .map_err(|_| CuaError::PermissionDenied)?;
    Ok(ProviderEvidence {
        capability: CapabilityId::DesktopWindowsRead,
        provider: "windows-owned-desktop-read"
            .try_into()
            .expect("fixed provider"),
        availability: Availability::Available,
        authorization: Authorization::Granted,
        provenance: format!(
            "original held desktop EnumDesktopWindows complete; count={}",
            evidence.count
        ),
        reason: None,
        recovery: styx_contracts::error::Recovery::None,
    })
}
pub(super) fn facts(state: &State, cap: CapabilityId) -> Result<AdmissionFacts, CoordinatorError> {
    let lane = desktop(state)?;
    if lane.source.fenced() {
        return Err(ErrorCategory::SessionDisconnected.into());
    }
    let grant = lane
        .grants
        .get(&cap)
        .ok_or(ErrorCategory::PermissionDenied)?;
    let view = state
        .sessions
        .project(&lane.binding, cap)
        .map_err(|_| CoordinatorError::Admission(ErrorCategory::PermissionRequired))?;
    let provider = view.provider;
    Ok(AdmissionFacts {
        device_id: state.facts.device_id.clone(),
        grant_revision: state.facts.grant_revision,
        local_policy_allowed: grant.local_policy_allowed,
        descriptor: CapabilityDescriptor {
            contract_version: styx_contracts::CONTRACT_VERSION,
            capability_id: cap,
            scope: Scope::Session,
            provider_id: provider.facts.provider,
            configured: grant.configured,
            remote_grant: grant.remote_grant,
            availability: provider.facts.availability,
            authorization: provider.facts.authorization,
            target_session: Some(lane.binding.clone()),
            reason: provider.facts.reason,
            observed_at: provider.facts.observed_at,
            observation_generation: provider.revision,
            recovery: provider.facts.recovery,
        },
        session_state: Some(view.state),
        current_observation: provider.observation,
    })
}
pub(super) fn handle(
    lane: &DesktopLane,
    owner: &OwnerLease,
    target: &ResourceTarget,
) -> Result<CuaHandle, CoordinatorError> {
    let bound = &lane
        .handles
        .get(&target.operation_id)
        .ok_or(ErrorCategory::TargetNotFound)?
        .handle;
    if bound.owner() != owner || bound.target() != target || bound.session() != &lane.binding {
        return Err(ErrorCategory::Unauthorized.into());
    }
    Ok(bound.clone())
}
fn profile<'a>(
    lane: &'a DesktopLane,
    owner: &OwnerLease,
) -> Result<&'a DesktopProfile, CoordinatorError> {
    lane.profiles
        .get(owner.owner_id())
        .filter(|p| &p.owner == owner)
        .ok_or_else(|| ErrorCategory::Unauthorized.into())
}
impl HostAuthority {
    /// Called by trusted profile bootstrap only. The actual owned source must
    /// already exist; no candidate, environment value or network DTO registers.
    pub(crate) async fn configure_desktop(
        &self,
        source: DesktopSource,

        grants: BTreeMap<CapabilityId, DesktopGrant>,
    ) -> Result<SessionBinding, CoordinatorError> {
        let source_copy = source.clone();
        let agent: AgentInstanceId =
            format!("desktop-supervisor-{}", uuid::Uuid::new_v4().simple())
                .try_into()
                .map_err(|_| CuaError::Unknown)?;
        let registration = tokio::task::spawn_blocking(move || source_copy.initial_facts(agent))
            .await
            .map_err(|_| CuaError::Unknown)?
            .map_err(|_| CuaError::PermissionDenied)?;
        // Collect every fallible source-derived projection BEFORE registration.
        // No native query occurs while the Host state mutex is held. Missing or
        // expired Mac facts cannot strand a registered session without its lane.
        let providers = vec![(window_read_evidence(&source)?, Duration::from_secs(1))];
        let mut state = self.inner.state.lock().expect("Host state mutex");
        if state.shutting_down || state.desktop.is_some() {
            return Err(CoordinatorError::Busy);
        }
        if source.fenced() {
            return Err(ErrorCategory::SessionDisconnected.into());
        }
        let registration = state
            .sessions
            .attest(registration)
            .map_err(|_| CuaError::PermissionDenied)?;
        let binding = state
            .sessions
            .register(registration)
            .map_err(|_| CuaError::PermissionDenied)?;
        let binding = state
            .sessions
            .set_state(&binding, styx_contracts::session::SessionState::Connecting)
            .map_err(|_| CuaError::PermissionDenied)?;
        for (evidence, lifetime) in providers {
            state
                .sessions
                .provider(&binding, evidence, lifetime)
                .map_err(|_| CuaError::PermissionDenied)?;
        }
        state.desktop = Some(DesktopLane {
            worker: CuaWorker::new(),
            source,
            binding: binding.clone(),
            grants,
            profiles: BTreeMap::new(),
            handles: BTreeMap::new(),
            #[cfg(all(test, target_os = "linux"))]
            open_history: Vec::new(),
        });
        Ok(binding)
    }
    pub(crate) fn register_desktop_profile(
        &self,
        owner: &OwnerLease,
        config: OwnedCuaConfig,
    ) -> Result<(), CoordinatorError> {
        let payload = CuaOpenSpec::for_config(&config)?.to_operation_payload()?;
        let mut state = self.inner.state.lock().expect("Host state mutex");
        if state.shutting_down {
            return Err(CoordinatorError::Busy);
        }
        state.ledger.validate_owner(owner)?;
        let lane = state.desktop.as_mut().ok_or(CuaError::Unsupported)?;
        if config.launch.session != lane.binding || lane.source.fenced() {
            return Err(ErrorCategory::SessionDisconnected.into());
        }
        if let Some(old) = lane.profiles.get(owner.owner_id()) {
            return if old.owner == *owner && old.payload == payload {
                Ok(())
            } else {
                Err(ErrorCategory::StateConflict.into())
            };
        }

        for old in lane.profiles.values() {
            if config.workspace.starts_with(&old.config.workspace)
                || old.config.workspace.starts_with(&config.workspace)
                || config.home.starts_with(&old.config.home)
                || old.config.home.starts_with(&config.home)
            {
                return Err(ErrorCategory::StateConflict.into());
            }
        }
        lane.profiles.insert(
            owner.owner_id().clone(),
            DesktopProfile {
                owner: owner.clone(),
                config,
                payload,
            },
        );
        Ok(())
    }
}
impl HostCoordinator {
    pub(crate) fn desktop_configured(&self) -> bool {
        self.inner
            .state
            .lock()
            .expect("Host state mutex")
            .desktop
            .is_some()
    }
    pub(crate) fn desktop_binding(&self) -> Result<SessionBinding, CoordinatorError> {
        let state = self.inner.state.lock().expect("Host state mutex");
        let lane = desktop(&state)?;
        if lane.source.fenced() {
            return Err(ErrorCategory::SessionDisconnected.into());
        }
        Ok(lane.binding.clone())
    }
    pub(crate) fn inspect_desktop(
        &self,
        owner: &OwnerLease,
        id: &OperationId,
        digest: Sha256Digest,
        action: bool,
    ) -> Result<OperationSnapshot, CoordinatorError> {
        let state = self.inner.state.lock().expect("Host state mutex");
        if state.ledger.inspect_domain(owner, id, digest)? != ResourceDomain::DesktopAgent {
            return Err(ErrorCategory::StateConflict.into());
        }
        let snapshot = state.ledger.inspect(owner, id, digest)?;
        if snapshot.target.is_some() != action {
            return Err(ErrorCategory::StateConflict.into());
        }
        Ok(snapshot)
    }
    /// Ends only this original never-dispatched desktop-open reservation.
    /// The caller must already hold a typed pre-dispatch refusal. The ledger
    /// lock arbitrates against a concurrent dispatch; no executor fact is
    /// inferred for a record which has left Reserved.
    pub(crate) fn cancel_refused_desktop_open(
        &self,
        owner: &OwnerLease,
        id: &OperationId,
        digest: Sha256Digest,
    ) -> Result<Option<OperationSnapshot>, CoordinatorError> {
        let mut state = self.inner.state.lock().expect("Host state mutex");
        if state.ledger.inspect_domain(owner, id, digest)? != ResourceDomain::DesktopAgent
            || state.ledger.inspect_context(owner, id, digest)?.capability
                != CapabilityId::DesktopWindowsRead
        {
            return Err(ErrorCategory::StateConflict.into());
        }
        let snapshot = state.ledger.inspect(owner, id, digest)?;
        if snapshot.target.is_some() {
            return Err(ErrorCategory::StateConflict.into());
        }
        if snapshot.state != OperationState::Reserved {
            return Ok(None);
        }
        Ok(Some(state.ledger.request_cancel(
            owner,
            id,
            digest,
            self.now(),
        )?))
    }
    /// Refreshes through the original collector, not cached environment state.
    /// A failed read invalidates old observations. Only a confirmed source fence
    /// disconnects the session; transient probe errors may be revalidated by the
    /// next read against the SAME kernel-pinned source.
    pub(crate) async fn refresh_desktop_source(&self) -> Result<(), CoordinatorError> {
        let source = {
            let state = self.inner.state.lock().expect("Host state mutex");
            desktop(&state)?.source.clone()
        };
        let result = source.fresh().await;
        let mut state = self.inner.state.lock().expect("Host state mutex");
        if result.is_err() || source.fenced() {
            // A failed probe without an identity fence must not permanently
            // disconnect the Linux binding. Both Linux and macOS require fresh
            // native evidence on the next call; neither replays this operation.
            if !source.fenced() {
                return Err(CuaError::StaleObservation.into());
            }
            if let Some(lane) = state.desktop.as_ref() {
                let binding = lane.binding.clone();
                let _ = state.sessions.set_state(
                    &binding,
                    styx_contracts::session::SessionState::Disconnected,
                );
            }
            return Err(ErrorCategory::SessionDisconnected.into());
        }
        if state.shutting_down {
            return Err(CoordinatorError::Busy);
        }
        let binding = desktop(&state)?.binding.clone();
        state
            .sessions
            .provider(
                &binding,
                window_read_evidence(&source)?,
                Duration::from_secs(1),
            )
            .map_err(|_| CuaError::PermissionDenied)?;
        #[cfg(target_os = "macos")]
        for cap in [
            CapabilityId::DesktopWindowsControl,
            CapabilityId::DesktopCapture,
            CapabilityId::DesktopPointer,
            CapabilityId::DesktopKeyboard,
            CapabilityId::DesktopAccessibility,
        ] {
            state
                .sessions
                .provider(
                    &binding,
                    source
                        .provider_evidence(cap)
                        .map_err(|_| CuaError::PermissionDenied)?,
                    Duration::from_secs(1),
                )
                .map_err(|_| CuaError::PermissionDenied)?;
        }
        Ok(())
    }
    pub(crate) fn prepare_desktop_open(
        &self,
        owner: &OwnerLease,
        context: PreparedContext,
    ) -> Result<OperationSnapshot, CoordinatorError> {
        let mut state = self.inner.state.lock().expect("Host state mutex");
        if state.shutting_down {
            return Err(CoordinatorError::Busy);
        }
        validate_context(desktop(&state)?, &context)?;
        let payload = profile(desktop(&state)?, owner)?.payload.clone();
        let snapshot = state
            .ledger
            .prepare_desktop_agent(owner, context, payload, self.now())?;
        #[cfg(all(test, target_os = "linux"))]
        state.desktop.as_mut().unwrap().open_history.push((
            owner.clone(),
            ResourceTarget {
                operation_id: snapshot.id.clone(),
                payload_digest: snapshot.payload_digest,
            },
        ));
        Ok(snapshot)
    }
    /// Cleanup still serializes through the existing execution gate. Independent
    /// owners do not wait for another conversation's native worker to exit.
    async fn reserve_desktop_open(
        &self,
        owner: &OwnerLease,
        id: &OperationId,
        digest: Sha256Digest,
    ) -> Result<DesktopOpenAdmission, CoordinatorError> {
        let deadline = {
            let state = self.inner.state.lock().expect("Host state mutex");
            state.ledger.inspect_context(owner, id, digest)?.deadline
        };
        if deadline.is_some_and(|deadline| self.now().0 >= deadline.0) {
            return Err(CoordinatorError::Busy);
        }
        let until = deadline.map(|deadline| {
            tokio::time::Instant::now()
                + Duration::from_millis(deadline.0.saturating_sub(self.now().0))
        });
        let mut waited = false;
        let execution = match self.inner.execution_gate.clone().try_read_owned() {
            Ok(execution) => execution,
            Err(_) => {
                waited = true;
                crate::providers::cua::within(until, self.inner.execution_gate.clone().read_owned())
                    .await
                    .map_err(|_| CoordinatorError::Busy)?
            }
        };
        let state = self.inner.state.lock().expect("Host state mutex");
        let context = state.ledger.inspect_context(owner, id, digest)?;
        let lane = desktop(&state)?;
        validate_context(lane, &context)?;
        if state.shutting_down || deadline.is_some_and(|deadline| self.now().0 >= deadline.0) {
            return Err(CoordinatorError::Busy);
        }
        Ok(DesktopOpenAdmission {
            execution,
            slot: lane.worker.try_reserve_open(),
            waited,
        })
    }
    pub(crate) async fn dispatch_desktop_open(
        &self,
        owner: &OwnerLease,
        id: &OperationId,
        digest: Sha256Digest,
    ) -> Result<DesktopOpenSubmission, CoordinatorError> {
        let snapshot = self.inspect_desktop(owner, id, digest, false)?;
        if snapshot.state != OperationState::Reserved {
            return Ok(DesktopOpenSubmission::Existing(snapshot));
        }
        let admission = loop {
            // This refresh precedes dispatch and cannot have started a worker.
            // Preserve unknown outcomes from refreshes after native actions.
            self.refresh_desktop_source()
                .await
                .map_err(|error| match error {
                    CoordinatorError::Desktop(CuaError::StaleObservation) => {
                        CoordinatorError::Admission(ErrorCategory::StaleObservation)
                    }
                    other => other,
                })?;
            let admission = self.reserve_desktop_open(owner, id, digest).await?;
            if !admission.waited {
                break admission;
            }
            // Source/provider facts can expire while cleanup holds the gate. Release this
            // provisional reservation and refresh before the final reservation;
            // never hold a worker slot across a fresh asynchronous observation.
        };
        let DesktopOpenAdmission {
            execution, slot, ..
        } = admission;
        let rx = {
            let runtime =
                tokio::runtime::Handle::try_current().map_err(|_| CoordinatorError::Busy)?;
            let mut state = self.inner.state.lock().expect("Host state mutex");
            let context = state.ledger.inspect_context(owner, id, digest)?;
            validate_context(desktop(&state)?, &context)?;
            let snapshot = state.ledger.inspect(owner, id, digest)?;
            if snapshot.target.is_some() {
                return Err(ErrorCategory::StateConflict.into());
            }
            if snapshot.state != OperationState::Reserved {
                return Ok(DesktopOpenSubmission::Existing(snapshot));
            }
            if state.shutting_down {
                return Err(CoordinatorError::Busy);
            }
            let config = profile(desktop(&state)?, owner)?.config.clone();
            let until = context.deadline.map(|deadline| {
                tokio::time::Instant::now()
                    + Duration::from_millis(deadline.0.saturating_sub(self.now().0))
            });
            let admission = facts(&state, CapabilityId::DesktopWindowsRead)?;
            let slot = match slot {
                Ok(slot) => slot,
                Err(CuaError::Busy) => {
                    let permit =
                        match state
                            .ledger
                            .dispatch(owner, id, digest, &admission, self.now())?
                        {
                            DispatchDisposition::Existing(s) => {
                                return Ok(DesktopOpenSubmission::Existing(s));
                            }
                            DispatchDisposition::ExecuteOnce(p) => p,
                        };
                    drop(permit);
                    let snapshot = state.ledger.record_executor_fact(
                        id,
                        ExecutorFact::NotDispatched,
                        self.now(),
                    )?;
                    return Ok(DesktopOpenSubmission::Completed(DesktopOpenCompletion {
                        snapshot,
                        evidence: CuaEvidence::NotDispatched,
                        cause: Some(CuaError::Busy),
                    }));
                }
                Err(e) => return Err(e.into()),
            };
            let permit = match state
                .ledger
                .dispatch(owner, id, digest, &admission, self.now())?
            {
                DispatchDisposition::Existing(s) => return Ok(DesktopOpenSubmission::Existing(s)),
                DispatchDisposition::ExecuteOnce(p) => p,
            };
            let operation = id.clone();
            let inner = self.inner.clone();
            let (tx, rx) = oneshot::channel();
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
                    let (evidence, cause, opened) =
                        match slot.spawn_owned(permit, config, until).await {
                            Ok(r) => (r.evidence, None, Some(r.handle)),
                            Err(r) => (r.evidence, Some(r.cause), r.handle),
                        };
                    let mut state = inner.state.lock().expect("Host state mutex");
                    if let (Some(h), Some(lane)) = (opened, state.desktop.as_mut()) {
                        lane.handles
                            .insert(operation.clone(), DesktopResource { handle: h });
                    }
                    let result = match evidence {
                        CuaEvidence::Acknowledged => state.ledger.record_executor_fact(
                            &operation,
                            ExecutorFact::Running,
                            inner.now(),
                        ),
                        CuaEvidence::NotDispatched => state.ledger.record_executor_fact(
                            &operation,
                            ExecutorFact::NotDispatched,
                            inner.now(),
                        ),
                        CuaEvidence::Unknown => state.ledger.mark_result_unknown(&operation),
                    };
                    guard.settled = result.is_ok();
                    drop(state);
                    drop(guard);
                    let _ = tx.send(
                        result
                            .map(|snapshot| {
                                DesktopOpenSubmission::Completed(DesktopOpenCompletion {
                                    snapshot,
                                    evidence,
                                    cause,
                                })
                            })
                            .map_err(CoordinatorError::from),
                    );
                },
                &runtime,
            );
            drop(jobs);
            drop(state);
            rx
        };
        rx.await.map_err(|_| CoordinatorError::ResponseLost)?
    }
    pub(crate) fn prepare_desktop_action(
        &self,
        owner: &OwnerLease,
        target: ResourceTarget,
        context: PreparedContext,
        action: &CuaAction,
    ) -> Result<OperationSnapshot, CoordinatorError> {
        let mut state = self.inner.state.lock().expect("Host state mutex");
        if state.shutting_down {
            return Err(CoordinatorError::Busy);
        }
        validate_context(desktop(&state)?, &context)?;
        if context.capability != action.capability()? {
            return Err(ErrorCategory::ProtocolMismatch.into());
        }
        handle(desktop(&state)?, owner, &target)?;
        let payload = action.to_operation_payload()?;
        Ok(state
            .ledger
            .prepare_targeted(owner, target, context, payload, self.now())?)
    }
    pub(crate) async fn dispatch_desktop_action(
        &self,
        owner: &OwnerLease,
        id: &OperationId,
        digest: Sha256Digest,
    ) -> Result<DesktopActionSubmission, CoordinatorError> {
        self.refresh_desktop_source().await?;
        let rx = {
            let execution = self.execution_for_operation(owner, id, digest).await?;

            let runtime =
                tokio::runtime::Handle::try_current().map_err(|_| CoordinatorError::Busy)?;
            let mut state = self.inner.state.lock().expect("Host state mutex");
            let context = state.ledger.inspect_context(owner, id, digest)?;
            validate_context(desktop(&state)?, &context)?;
            let snapshot = state.ledger.inspect(owner, id, digest)?;
            if snapshot.state != OperationState::Reserved {
                return Ok(DesktopActionSubmission::Existing(snapshot));
            }
            if state.shutting_down {
                return Err(CoordinatorError::Busy);
            }
            let target = snapshot
                .target
                .as_ref()
                .ok_or(ErrorCategory::StateConflict)?;
            let bound = handle(desktop(&state)?, owner, target)?;
            let primary = facts(&state, context.capability)?;
            let worker = desktop(&state)?.worker.clone();
            let slot = worker.try_reserve_action(&bound)?;
            let permit = match state
                .ledger
                .dispatch(owner, id, digest, &primary, self.now())?
            {
                DispatchDisposition::Existing(s) => {
                    return Ok(DesktopActionSubmission::Existing(s));
                }
                DispatchDisposition::ExecuteOnce(p) => p,
            };
            let delivery_context = permit.context().clone();
            let write_until = delivery_context.deadline.map(|deadline| {
                tokio::time::Instant::now()
                    + Duration::from_millis(deadline.0.saturating_sub(self.now().0))
            });
            let operation = id.clone();
            let inner = self.inner.clone();
            let coordinator = self.clone();
            let (tx, rx) = oneshot::channel();
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
                    let receipt = slot.call_once_until(permit, write_until).await;
                    let fresh = coordinator.refresh_desktop_source().await;
                    let mut state = inner.state.lock().expect("Host state mutex");
                    let fact = match receipt.evidence {
                        CuaEvidence::Acknowledged => ActionResult::Acknowledged,
                        CuaEvidence::NotDispatched => ActionResult::NotDispatched,
                        CuaEvidence::Unknown => ActionResult::Unknown,
                    };
                    let result = state
                        .ledger
                        .record_action_result(&operation, fact, inner.now());
                    guard.settled = result.is_ok();
                    let audit = worker
                        .action_audit(&receipt)
                        .map_err(CoordinatorError::from)
                        .and_then(|a| {
                            state
                                .ledger
                                .record_provider_audit(&operation, a)
                                .map_err(CoordinatorError::from)
                        });
                    let delivery = if fresh.is_err() {
                        Err(ErrorCategory::SessionDisconnected.into())
                    } else {
                        facts(&state, delivery_context.capability).and_then(|f| {
                            state
                                .ledger
                                .authorize_resource_access(
                                    bound.owner(),
                                    &bound.target().operation_id,
                                    bound.target().payload_digest,
                                    &delivery_context,
                                    &f,
                                    inner.now(),
                                )
                                .map(|_| ())
                                .map_err(CoordinatorError::from)
                        })
                    };
                    drop(state);
                    drop(guard);
                    let response = result.map_err(CoordinatorError::from).and_then(|snapshot| {
                        audit?;
                        delivery?;
                        Ok(DesktopActionSubmission::Completed(
                            DesktopActionCompletion { snapshot, receipt },
                        ))
                    });
                    let _ = tx.send(response);
                },
                &runtime,
            );
            drop(jobs);
            drop(state);
            rx
        };
        rx.await.map_err(|_| CoordinatorError::ResponseLost)?
    }
}

#[cfg(all(test, target_os = "linux"))]
pub(super) fn test_lane(binding: SessionBinding) -> DesktopLane {
    DesktopLane {
        worker: CuaWorker::new(),
        source: DesktopSource::for_tests(),
        binding,
        grants: [
            CapabilityId::DesktopWindowsRead,
            CapabilityId::DesktopCapture,
            CapabilityId::DesktopAccessibility,
            CapabilityId::DesktopPointer,
            CapabilityId::DesktopKeyboard,
            CapabilityId::DesktopWindowsControl,
        ]
        .into_iter()
        .map(|cap| {
            (
                cap,
                DesktopGrant {
                    configured: true,
                    remote_grant: true,
                    local_policy_allowed: true,
                },
            )
        })
        .collect(),
        profiles: BTreeMap::new(),
        handles: BTreeMap::new(),
        open_history: Vec::new(),
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "desktop_open_tests.rs"]
mod open_tests;

// Deliberately unavailable native source for real Core/Host/TLS refusal tests.
// The fixture never grants a platform capability or starts a native executor.
#[cfg(all(test, target_os = "linux"))]
impl HostCoordinator {
    pub(crate) async fn install_desktop_refusal_fixture(&self) -> SessionBinding {
        use styx_contracts::{
            error::Recovery,
            session::{SessionIdentity, SessionState},
        };
        let mut state = self.inner.state.lock().unwrap();
        assert!(state.desktop.is_none());
        let registration = state
            .sessions
            .attest(styx_core::session::RegistrationFacts {
                id: "open-refusal-session".try_into().unwrap(),
                identity: SessionIdentity::Linux {
                    uid: nix::unistd::Uid::current().as_raw(),
                    login_instance: "refusal-fixture-login".into(),
                    seat: None,
                    compositor_instance: "refusal-fixture-compositor".into(),
                    display_identity: "refusal-fixture-display".into(),
                },
                agent_instance: "refusal-fixture-agent".try_into().unwrap(),
                protocol_version: 1,
                provenance: "synthetic source; no OS acceptance".into(),
            })
            .unwrap();
        let binding = state.sessions.register(registration).unwrap();
        let binding = state
            .sessions
            .set_state(&binding, SessionState::Connecting)
            .unwrap();
        state
            .sessions
            .provider(
                &binding,
                ProviderEvidence {
                    capability: CapabilityId::DesktopWindowsRead,
                    provider: "refusal-fixture".try_into().unwrap(),
                    availability: Availability::Available,
                    authorization: Authorization::Granted,
                    provenance: "synthetic pre-dispatch source boundary only".into(),
                    reason: None,
                    recovery: Recovery::None,
                },
                Duration::from_secs(60),
            )
            .unwrap();
        state.desktop = Some(test_lane(binding.clone()));
        binding
    }
    /// Synthetic ledger evidence for the paired lost-reply regression only.
    /// No native worker or successful desktop permission is claimed.
    pub(crate) fn simulate_desktop_open_running(&self, owner_id: &OwnerId) -> ResourceTarget {
        let mut state = self.inner.state.lock().unwrap();
        let lane = state.desktop.as_ref().unwrap();
        assert!(lane.worker.resources().unwrap().is_empty());
        let (owner, target) = lane
            .open_history
            .iter()
            .find(|(owner, _)| owner.owner_id() == owner_id)
            .cloned()
            .unwrap();
        let admission = facts(&state, CapabilityId::DesktopWindowsRead).unwrap();
        assert!(matches!(
            state
                .ledger
                .dispatch(
                    &owner,
                    &target.operation_id,
                    target.payload_digest,
                    &admission,
                    self.now()
                )
                .unwrap(),
            DispatchDisposition::ExecuteOnce(_)
        ));
        state
            .ledger
            .record_executor_fact(&target.operation_id, ExecutorFact::Running, self.now())
            .unwrap();
        target
    }
    pub(crate) async fn finish_simulated_desktop_open(&self, target: &ResourceTarget) {
        let _execution = self.inner.execution_gate.clone().write_owned().await;
        let mut state = self.inner.state.lock().unwrap();
        assert!(
            state
                .desktop
                .as_ref()
                .unwrap()
                .worker
                .resources()
                .unwrap()
                .is_empty()
        );
        // Settle only this synthetic record; there was no native resource to end.
        for fact in [
            ExecutorFact::Exited { successful: false },
            ExecutorFact::OutputDrained,
        ] {
            state
                .ledger
                .record_executor_fact(&target.operation_id, fact, self.now())
                .unwrap();
        }
        let permit = state.ledger.begin_resource_release(target).unwrap();
        state
            .ledger
            .record_provider_release(permit.confirm_released())
            .unwrap();
    }
    pub(crate) fn desktop_refusal_records(&self) -> (Vec<OperationSnapshot>, usize) {
        let state = self.inner.state.lock().unwrap();
        let records = state
            .desktop
            .as_ref()
            .unwrap()
            .open_history
            .iter()
            .filter_map(|(owner, target)| {
                state
                    .ledger
                    .inspect(owner, &target.operation_id, target.payload_digest)
                    .ok()
            })
            .collect();
        let workers = state
            .desktop
            .as_ref()
            .map_or(0, |lane| lane.worker.resources().unwrap().len());
        (records, workers)
    }
}
