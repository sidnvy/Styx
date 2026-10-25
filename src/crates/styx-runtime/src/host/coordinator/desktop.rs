//! Desktop operations share the original Host ledger, grants and job ownership.
//! A live local session supervisor is distinct from the native Cua backend.
use super::desktop_source::DesktopSource;
use super::*;
use crate::providers::cua::{
    CuaAction, CuaError, CuaEvidence, CuaHandle, CuaIoBudget, CuaOpenSpec, CuaReceipt, CuaWorker,
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
pub(super) struct DesktopLane {
    pub(super) worker: CuaWorker,
    pub(super) source: DesktopSource,
    pub(super) binding: SessionBinding,
    pub(super) grants: BTreeMap<CapabilityId, DesktopGrant>,
    pub(super) next_read_alias: u32,
    pub(super) ax_observation: Option<super::desktop_observation::OwnedAxObservation>,
    profiles: BTreeMap<OwnerId, DesktopProfile>,
    pub(super) handles: BTreeMap<OperationId, CuaHandle>,
}
#[derive(Debug)]
pub(crate) struct DesktopOpenCompletion {
    pub(crate) snapshot: OperationSnapshot,
    pub(crate) evidence: CuaEvidence,
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
fn facts(state: &State, cap: CapabilityId) -> Result<AdmissionFacts, CoordinatorError> {
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
fn handle(
    lane: &DesktopLane,
    owner: &OwnerLease,
    target: &ResourceTarget,
) -> Result<CuaHandle, CoordinatorError> {
    let bound = lane
        .handles
        .get(&target.operation_id)
        .ok_or(ErrorCategory::TargetNotFound)?;
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
        budget: Arc<CuaIoBudget>,
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
        // Only this actual read API has evidence. Other providers remain absent.
        state
            .sessions
            .provider(
                &binding,
                window_read_evidence(&source)?,
                Duration::from_secs(1),
            )
            .map_err(|_| CuaError::PermissionDenied)?;
        // Publish missing native provider facts explicitly, preserving a
        // Degraded aggregate instead of implying all Computer permissions.
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
                    ProviderEvidence {
                        capability: cap,
                        provider: "cua-native".try_into().expect("fixed provider"),
                        availability: Availability::Unavailable,
                        authorization: Authorization::Unknown,
                        provenance: "native provider permission acquisition not yet observed"
                            .into(),
                        reason: Some(ErrorCategory::PermissionRequired),
                        recovery: styx_contracts::error::Recovery::Rediscover,
                    },
                    Duration::from_secs(60),
                )
                .map_err(|_| CuaError::PermissionDenied)?;
        }
        state.desktop = Some(DesktopLane {
            worker: CuaWorker::new(budget),
            source,
            binding: binding.clone(),
            grants,
            next_read_alias: 0,
            ax_observation: None,
            profiles: BTreeMap::new(),
            handles: BTreeMap::new(),
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
        if lane.profiles.len() >= 16 {
            return Err(CoordinatorError::Busy);
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
    /// Refreshes through the original collector, not cached environment state.
    /// Failed or changed association permanently fences this source; callers
    /// must explicitly attach a new generation instead of switching targets.
    pub(crate) async fn refresh_desktop_source(&self) -> Result<(), CoordinatorError> {
        let source = {
            let state = self.inner.state.lock().expect("Host state mutex");
            desktop(&state)?.source.clone()
        };
        let result = source.fresh().await;
        if matches!(result, Err(super::desktop_source::DesktopSourceError::Busy)) {
            return Err(CoordinatorError::Busy);
        }
        let mut state = self.inner.state.lock().expect("Host state mutex");
        if result.is_err() || source.fenced() {
            super::desktop_observation::invalidate(state.desktop.as_mut(), None);
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
        Ok(state
            .ledger
            .prepare_desktop_agent(owner, context, payload, self.now())?)
    }
    pub(crate) async fn dispatch_desktop_open(
        &self,
        owner: &OwnerLease,
        id: &OperationId,
        digest: Sha256Digest,
    ) -> Result<DesktopOpenSubmission, CoordinatorError> {
        self.refresh_desktop_source().await?;
        let rx = {
            let execution = self
                .inner
                .execution_gate
                .clone()
                .try_read_owned()
                .map_err(|_| CoordinatorError::Busy)?;
            let job_slot = self
                .inner
                .slots
                .clone()
                .try_acquire_owned()
                .map_err(|_| CoordinatorError::Busy)?;
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
            let admission = facts(&state, CapabilityId::DesktopWindowsRead)?;
            let slot = match desktop(&state)?.worker.try_reserve_open() {
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
                    let _slot = job_slot;
                    let (evidence, _cause, opened) = match slot.spawn_owned(permit, config).await {
                        Ok(r) => (r.evidence, None, Some(r.handle)),
                        Err(r) => (r.evidence, Some(r.cause), r.handle),
                    };
                    let mut state = inner.state.lock().expect("Host state mutex");
                    if let (Some(h), Some(lane)) = (opened, state.desktop.as_mut()) {
                        lane.handles.insert(operation.clone(), h);
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
        mut context: PreparedContext,
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
        if let Some(request) = action.accessibility_write_request()? {
            let (translated, observation) =
                super::desktop_observation::prepare(&state, owner, &target, &request)?;
            context.observation = Some(observation);
            return Ok(state.ledger.prepare_desktop_accessibility_write_attempt(
                owner,
                target,
                context,
                translated.to_operation_payload()?,
                self.now(),
            )?);
        }
        let payload = action.to_operation_payload()?;
        if let Some(read) = action.desktop_read_request()? {
            Ok(match read {
                crate::providers::cua::DesktopReadRequest::Accessibility(_) => {
                    state.ledger.prepare_desktop_read_acquisition(
                        owner,
                        target,
                        context,
                        payload,
                        self.now(),
                    )?
                }
                crate::providers::cua::DesktopReadRequest::WindowCapture(_) => {
                    state.ledger.prepare_desktop_window_capture_acquisition(
                        owner,
                        target,
                        context,
                        payload,
                        self.now(),
                    )?
                }
            })
        } else {
            Ok(state
                .ledger
                .prepare_targeted(owner, target, context, payload, self.now())?)
        }
    }
    pub(crate) async fn dispatch_desktop_action(
        &self,
        owner: &OwnerLease,
        id: &OperationId,
        digest: Sha256Digest,
    ) -> Result<DesktopActionSubmission, CoordinatorError> {
        self.refresh_desktop_source().await?;
        let rx = {
            let execution = self
                .inner
                .execution_gate
                .clone()
                .try_read_owned()
                .map_err(|_| CoordinatorError::Busy)?;
            let job_slot = self
                .inner
                .slots
                .clone()
                .try_acquire_owned()
                .map_err(|_| CoordinatorError::Busy)?;
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
            let action: CuaAction =
                serde_json::from_slice(state.ledger.inspect_payload(owner, id, digest)?)
                    .map_err(|_| CuaError::InvalidRequest)?;
            let acquisition = action.desktop_read_request()?;
            let write = action.accessibility_write_request()?;
            if write.is_some()
                != (state.ledger.inspect_purpose(owner, id, digest)?
                    == styx_core::operations::OperationPurpose::DesktopAccessibilityWriteAttempt)
            {
                return Err(ErrorCategory::StateConflict.into());
            }
            let primary = if let Some(request) = write.as_ref() {
                super::desktop_observation::validate_dispatch(
                    &state,
                    owner,
                    target,
                    &context,
                    request,
                    self.now(),
                )?
            } else if acquisition.is_some() {
                super::desktop_read::acquisition_facts(&state, context.capability)?
            } else {
                facts(&state, context.capability)?
            };
            if let Some(read) = acquisition {
                if read.capability() != context.capability {
                    return Err(ErrorCategory::StateConflict.into());
                }
                match read {
                    crate::providers::cua::DesktopReadRequest::Accessibility(_) => {
                        styx_core::policy::check_desktop_read_acquisition(
                            &context,
                            &primary,
                            self.now(),
                        )?
                    }
                    crate::providers::cua::DesktopReadRequest::WindowCapture(_) => {
                        styx_core::policy::check_desktop_window_capture_acquisition(
                            &context,
                            &primary,
                            self.now(),
                        )?
                    }
                }
            }
            for cap in action.required_capabilities()? {
                if acquisition.is_some() || write.is_some() {
                    continue;
                }
                let required = facts(&state, cap)?;
                let mut requested = context.clone();
                requested.capability = cap;
                // Additional provider facts never fabricate an observed input target.
                if cap != context.capability {
                    requested.observation = None;
                }
                styx_core::policy::check_admission(&requested, &required, self.now())?;
            }
            if write.is_none() && action.requires_observed_target()? {
                // The owned native observation map must authorize the exact target;
                // a caller-provided observation ID alone is insufficient. This gate
                // stays closed until a real native snapshot is installed below.
                return Err(ErrorCategory::StaleObservation.into());
            }
            let mut acquired_target = acquisition
                .map(crate::providers::cua::DesktopReadTarget::acquire)
                .transpose()?;
            let acquired_epoch = desktop(&state)?.source.epoch();
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
            // Consume only after the one Core dispatch; a dropped waiter or
            // failed/unknown native reply can never restore this target map.
            let write_observation = if write.is_some() {
                state
                    .desktop
                    .as_mut()
                    .and_then(|lane| lane.ax_observation.take())
                    .map(Arc::new)
            } else {
                super::desktop_observation::invalidate(state.desktop.as_mut(), None);
                None
            };
            let delivery_context = permit.context().clone();
            let write_until = tokio::time::Instant::now()
                + Duration::from_millis(delivery_context.deadline.0.saturating_sub(self.now().0));
            let gate_owner = owner.clone();
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
                    let _slot = job_slot;
                    let mut receipt = if let Some(observation) = write_observation.as_ref() {
                        let retained = observation.clone();
                        let gate_coordinator = coordinator.clone();
                        let gate_inner = inner.clone();
                        let gate_operation = operation.clone();
                        let gate: crate::providers::cua::AxWriteGate = Box::new(move || {
                            Box::pin(async move {
                                gate_coordinator
                                    .refresh_desktop_source()
                                    .await
                                    .map_err(|_| CuaError::StaleObservation)?;
                                let state =
                                    gate_inner.state.lock().map_err(|_| CuaError::Unknown)?;
                                if state.shutting_down {
                                    return Err(CuaError::StaleObservation);
                                }
                                retained
                                    .recheck_write(
                                        &state,
                                        &gate_owner,
                                        &gate_operation,
                                        digest,
                                        gate_inner.now(),
                                    )
                                    .map_err(|_| CuaError::StaleObservation)
                            })
                        });
                        slot.call_once_until_with_write_gate(permit, write_until, gate)
                            .await
                    } else {
                        slot.call_once(permit).await
                    };
                    // A late response cannot mint observations or be delivered into a
                    // replaced/locked source, even if the original native call ACKed.
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
                        let f = if acquired_target.is_some() || write_observation.is_some() {
                            super::desktop_read::acquisition_facts(
                                &state,
                                delivery_context.capability,
                            )
                        } else {
                            facts(&state, delivery_context.capability)
                        };
                        f.and_then(|f| {
                            if let Some(observation) = write_observation.as_ref() {
                                observation.validate_delivery(&state)?;
                                if receipt.evidence != CuaEvidence::Acknowledged {
                                    return Ok(());
                                }
                                return state
                                    .ledger
                                    .authorize_desktop_accessibility_write_result(
                                        bound.owner(),
                                        &operation,
                                        digest,
                                        &f,
                                        inner.now(),
                                    )
                                    .map(|_| ())
                                    .map_err(CoordinatorError::from);
                            }
                            if acquired_target.is_some() {
                                return state
                                    .ledger
                                    .authorize_desktop_read_result(
                                        bound.owner(),
                                        &operation,
                                        digest,
                                        &f,
                                        inner.now(),
                                    )
                                    .map(|_| ())
                                    .map_err(CoordinatorError::from);
                            }
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
                    let delivery = delivery.and_then(|()| {
                        if let Some(target) = acquired_target.as_ref() {
                            let lane = state.desktop.as_mut().ok_or(CuaError::Unsupported)?;
                            if lane.source.fenced() || lane.source.epoch() != acquired_epoch {
                                return Err(ErrorCategory::SessionDisconnected.into());
                            }
                            let parsed = super::desktop_read::settle_acquired_read(
                                lane,
                                target,
                                &mut receipt,
                            );
                            if let Some((parsed, alias)) = parsed {
                                let original =
                                    acquired_target.take().ok_or(ErrorCategory::StateConflict)?;
                                super::desktop_observation::install(
                                    &mut state,
                                    bound.owner(),
                                    bound.target(),
                                    super::desktop_observation::AcquiredAxObservation {
                                        target: original,
                                        parsed,
                                        alias,
                                        source_epoch: acquired_epoch,
                                    },
                                )?;
                            }
                        }
                        Ok(())
                    });
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
