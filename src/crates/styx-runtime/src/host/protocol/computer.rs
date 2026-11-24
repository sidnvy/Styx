//! Protected local Desktop session ownership and inputs; no path or profile
//! choice comes from WSS. Blocking validation jobs outlive dropped connection
//! waiters and are joined before explicit Host shutdown releases their owners.
use super::*;
use crate::{
    host::coordinator::{DesktopActionSubmission, DesktopOpenSubmission, DesktopSessionPhase},
    providers::cua::{CuaAction, CuaError, CuaEvidence, OwnedCuaConfig},
};
use std::sync::Arc;
use tokio_util::task::TaskTracker;

pub(crate) trait ComputerBootstrap: Send + Sync {
    fn release_profile(&self, _owner: &OwnerLease) {}
    fn prepare_profile(&self, owner: &OwnerLease) -> Result<OwnedCuaConfig, ErrorCategory>;
    fn validate_before_spawn(&self) -> Result<(), ErrorCategory>;
    fn validate_control(&self) -> Result<(), ErrorCategory>;
}
pub(super) struct ComputerInputs {
    source: Arc<dyn ComputerBootstrap>,
    tasks: TaskTracker,
    gate: Arc<tokio::sync::RwLock<()>>,
}
impl ComputerInputs {
    async fn run<T: Send + 'static>(
        &self,
        work: impl FnOnce(Arc<dyn ComputerBootstrap>) -> Result<T, ErrorCategory> + Send + 'static,
    ) -> Result<T, ErrorCategory> {
        if self.tasks.is_closed() {
            return Err(ErrorCategory::Busy);
        }
        // Profile retirement waits for the original validation tasks.
        let guard = self.gate.clone().read_owned().await;
        if self.tasks.is_closed() {
            return Err(ErrorCategory::Busy);
        }
        let source = self.source.clone();
        self.tasks
            .spawn_blocking(move || {
                let _guard = guard;
                work(source)
            })
            .await
            .map_err(|_| ErrorCategory::IntegrityFailure)?
    }
}
impl HostProtocol<'_> {
    pub(crate) fn with_computer_profiles(
        mut self,
        source: Arc<dyn ComputerBootstrap>,
    ) -> Result<Self, ProtocolError> {
        if !self.paired || self.computer.is_some() {
            return Err(ProtocolError::BootstrapMismatch);
        }
        // A trusted deferred factory may still be Pending. Its own original
        // readiness check runs before looking up any Core desktop session.
        self.computer = Some(ComputerInputs {
            source,
            tasks: TaskTracker::new(),
            gate: Arc::new(tokio::sync::RwLock::new(())),
        });
        Ok(self)
    }
    pub(super) async fn release_computer_profile(
        &self,
        owner: OwnerLease,
    ) -> Result<(), ErrorCategory> {
        let Some(inputs) = &self.computer else {
            return Ok(());
        };
        let guard = inputs.gate.clone().write_owned().await;
        let source = inputs.source.clone();
        inputs
            .tasks
            .spawn_blocking(move || {
                let _guard = guard;
                source.release_profile(&owner);
            })
            .await
            .map_err(|_| ErrorCategory::IntegrityFailure)
    }
    pub(crate) async fn drain_computer_inputs(&self) {
        if let Some(inputs) = &self.computer {
            inputs.tasks.close();
            inputs.tasks.wait().await;
        }
    }
    async fn computer_input<T: Send + 'static>(
        &self,
        work: impl FnOnce(Arc<dyn ComputerBootstrap>) -> Result<T, ErrorCategory> + Send + 'static,
    ) -> Result<T, ErrorCategory> {
        self.computer
            .as_ref()
            .ok_or(ErrorCategory::CapabilityUnsupported)?
            .run(work)
            .await
    }
    fn context(&self, revision: u64, timeout: Option<u32>) -> PreparedContext {
        PreparedContext {
            device_id: self.coordinator.bootstrap_identity().0.clone(),
            grant_revision: revision,
            session: None,
            observation: None,
            capability: CapabilityId::DesktopWindowsRead,
            deadline: timeout.map(|timeout| {
                MonotonicMillis(self.coordinator.now().0.saturating_add(u64::from(timeout)))
            }),
            disconnect_policy: DisconnectPolicy::RetainForOwner,
        }
    }
    async fn ensure_desktop_open(
        &self,
        reference: &OwnerRef,
        owner: &OwnerLease,
        revision: u64,
        timeout: Option<u32>,
        phase: &mut DesktopSessionPhase,
    ) -> Result<ResourceTarget, Reply> {
        match phase {
            DesktopSessionPhase::Ready(target) => return Ok(target.clone()),
            DesktopSessionPhase::Opening | DesktopSessionPhase::Unknown => {
                return Err(Reply::Error {
                    category: ErrorCategory::ResultUnknown,
                    certainty: ExecutionCertainty::Unknown,
                    cursor_may_be_consumed: false,
                });
            }
            DesktopSessionPhase::New => {}
        }
        // Poison BEFORE the first await so dropped/cancelled futures never
        // reopen an unsettled or unknown Desktop resource.
        *phase = DesktopSessionPhase::Opening;

        let bound = owner.clone();
        let current = self.coordinator.clone();
        let config = match self
            .computer_input(move |source| {
                if !current.owner_is_active(&bound) {
                    return Err(ErrorCategory::Unauthorized);
                }
                source.validate_control()?;
                source.prepare_profile(&bound)
            })
            .await
        {
            Ok(v) => v,
            Err(e) => {
                *phase = DesktopSessionPhase::New;
                return Err(rejection(e));
            }
        };
        if !self.coordinator.desktop_configured() {
            *phase = DesktopSessionPhase::New;
            return Err(rejection(ErrorCategory::CapabilityUnsupported));
        }
        let mut open_context = self.context(revision, timeout);
        open_context.session = match self.coordinator.desktop_binding() {
            Ok(v) => Some(v),
            Err(e) => {
                *phase = DesktopSessionPhase::New;
                return Err(coordinator_error(e, false));
            }
        };
        if self.owner(reference).as_ref() != Ok(owner) {
            *phase = DesktopSessionPhase::New;
            return Err(rejection(ErrorCategory::Unauthorized));
        }
        if let Err(e) = self.authority.register_desktop_profile(owner, config) {
            *phase = DesktopSessionPhase::New;
            return Err(coordinator_error(e, false));
        }
        let snapshot = match self.coordinator.prepare_desktop_open(owner, open_context) {
            Ok(snapshot) => snapshot,
            Err(e) => {
                *phase = DesktopSessionPhase::New;
                return Err(coordinator_error(e, false));
            }
        };
        let target = ResourceTarget {
            operation_id: snapshot.id,
            payload_digest: snapshot.payload_digest,
        };
        if let Err(category) = self
            .computer_input(|source| source.validate_before_spawn())
            .await
        {
            *phase = DesktopSessionPhase::Unknown;
            return Err(uncertain(rejection(category)));
        }
        match self
            .coordinator
            .dispatch_desktop_open(owner, &target.operation_id, target.payload_digest)
            .await
        {
            Ok(DesktopOpenSubmission::Completed(done))
                if done.evidence == CuaEvidence::Acknowledged
                    && done.snapshot.state == OperationState::Running =>
            {
                *phase = DesktopSessionPhase::Ready(target.clone());
                Ok(target)
            }
            Ok(DesktopOpenSubmission::Completed(done))
                if done.evidence == CuaEvidence::NotDispatched =>
            {
                *phase = DesktopSessionPhase::New;
                if done.cause == Some(CuaError::Busy) {
                    Err(rejection(ErrorCategory::Busy))
                } else {
                    Err(rejection(
                        done.cause
                            .map(category)
                            .unwrap_or(ErrorCategory::SessionDisconnected),
                    ))
                }
            }
            Ok(_) => {
                *phase = DesktopSessionPhase::Unknown;
                Err(Reply::Error {
                    category: ErrorCategory::ResultUnknown,
                    certainty: ExecutionCertainty::Unknown,
                    cursor_may_be_consumed: false,
                })
            }
            Err(e) => {
                let reply = coordinator_error(e, false);
                if matches!(
                    &reply,
                    Reply::Error {
                        certainty: ExecutionCertainty::NotDispatched,
                        ..
                    }
                ) && matches!(
                    self.coordinator.cancel_refused_desktop_open(
                        owner,
                        &target.operation_id,
                        target.payload_digest,
                    ),
                    Ok(Some(_))
                ) {
                    *phase = DesktopSessionPhase::New;
                    Err(reply)
                } else {
                    *phase = DesktopSessionPhase::Unknown;
                    Err(uncertain(reply))
                }
            }
        }
    }
    pub(super) async fn handle_desktop_session(
        &self,
        reference: OwnerRef,
        revision: u64,
        timeout: Option<u32>,
        action_raw: Box<serde_json::value::RawValue>,
    ) -> Reply {
        if !self.paired || self.computer.is_none() {
            return Reply::Unsupported {
                feature: COMPUTER_V3.into(),
            };
        }
        let owner = match self.owner(&reference) {
            Ok(v) => v,
            Err(e) => return rejection(e),
        };
        if timeout == Some(0) || action_raw.get().len() > SPEC_LIMIT {
            return invalid();
        }
        let action: CuaAction = match serde_json::from_str(action_raw.get()) {
            Ok(v) => v,
            Err(_) => return invalid(),
        };
        if let Err(error) = action.to_operation_payload() {
            return rejection(category(error));
        }
        // Deferred startup factories validate readiness before looking up a desktop lane.
        if !self.coordinator.desktop_configured() {
            return match self
                .computer_input(|source| source.validate_control())
                .await
            {
                Ok(()) => rejection(ErrorCategory::CapabilityUnsupported),
                Err(e) => rejection(e),
            };
        }
        let session_cell = match self.coordinator.desktop_owner_session(&owner) {
            Ok(cell) => cell,
            Err(e) => return coordinator_error(e, false),
        };
        let mut session = session_cell.lock().await;
        let target = match self
            .ensure_desktop_open(&reference, &owner, revision, timeout, &mut session.phase)
            .await
        {
            Ok(target) => target,
            Err(reply) => return reply,
        };
        if let Err(e) = self
            .computer_input(|source| source.validate_control())
            .await
        {
            return rejection(e);
        }
        let mut action_context = self.context(revision, timeout);
        action_context.session = match self.coordinator.desktop_binding() {
            Ok(v) => Some(v),
            Err(e) => return coordinator_error(e, false),
        };
        let prepared =
            match self
                .coordinator
                .prepare_desktop_action(&owner, target, action_context, &action)
            {
                Ok(snapshot) => snapshot,
                Err(e) => return coordinator_error(e, false),
            };
        match self
            .coordinator
            .dispatch_desktop_action(&owner, &prepared.id, prepared.payload_digest)
            .await
        {
            Ok(DesktopActionSubmission::Completed(done)) => match done.receipt.evidence {
                CuaEvidence::Acknowledged => match done.receipt.result {
                    Some(result) => Reply::DesktopSession { result },
                    None => Reply::Error {
                        category: ErrorCategory::ResultUnknown,
                        certainty: ExecutionCertainty::Unknown,
                        cursor_may_be_consumed: false,
                    },
                },
                CuaEvidence::NotDispatched => Reply::Error {
                    category: done
                        .receipt
                        .cause
                        .map(category)
                        .unwrap_or(ErrorCategory::SessionDisconnected),
                    certainty: ExecutionCertainty::NotDispatched,
                    cursor_may_be_consumed: false,
                },
                CuaEvidence::Unknown => Reply::Error {
                    category: done
                        .receipt
                        .cause
                        .map(category)
                        .unwrap_or(ErrorCategory::ResultUnknown),
                    certainty: ExecutionCertainty::Unknown,
                    cursor_may_be_consumed: false,
                },
            },
            Ok(DesktopActionSubmission::Existing) => Reply::Error {
                category: ErrorCategory::ResultUnknown,
                certainty: ExecutionCertainty::Unknown,
                cursor_may_be_consumed: false,
            },
            Err(e) => coordinator_error(e, false),
        }
    }
}
fn category(error: CuaError) -> ErrorCategory {
    match error {
        CuaError::Busy => ErrorCategory::Busy,
        CuaError::InvalidRequest => ErrorCategory::InvalidRequest,
        CuaError::PermissionDenied => ErrorCategory::PermissionDenied,
        CuaError::StaleObservation => ErrorCategory::StaleObservation,
        CuaError::Unsupported => ErrorCategory::CapabilityUnsupported,
        CuaError::ProtocolMismatch => ErrorCategory::ProtocolMismatch,
        CuaError::Unknown | CuaError::CleanupUnconfirmed => ErrorCategory::ResultUnknown,
    }
}
fn uncertain(mut reply: Reply) -> Reply {
    if let Reply::Error { certainty, .. } = &mut reply {
        *certainty = ExecutionCertainty::Unknown;
    }
    reply
}

/// Real Host/Core owner and protocol preparation ports for the retained-startup
/// fault test. No native executor, desktop association or platform PASS is faked.
#[cfg(test)]
pub(crate) async fn assert_pending_factory_keeps_owner_control_live(
    source: Arc<dyn ComputerBootstrap>,
) {
    use styx_contracts::{capability::*, error::Recovery};
    use styx_core::policy::AdmissionFacts;
    let device: DeviceId = "desktop-startup-fault-device".try_into().unwrap();
    let generation: HostGeneration = "desktop-startup-fault-generation".try_into().unwrap();
    let host = crate::host::bootstrap::OwnedExecHost::reserve(
        generation.clone(),
        AdmissionFacts {
            device_id: device.clone(),
            grant_revision: 1,
            local_policy_allowed: true,
            descriptor: CapabilityDescriptor {
                contract_version: 1,
                capability_id: CapabilityId::ExecRun,
                scope: Scope::Host,
                provider_id: "codex".try_into().unwrap(),
                configured: true,
                remote_grant: true,
                availability: Availability::Available,
                authorization: Authorization::Granted,
                target_session: None,
                reason: None,
                observed_at: 1,
                observation_generation: 1,
                recovery: Recovery::None,
            },
            session_state: None,
            current_observation: None,
        },
    )
    .unwrap()
    .without_executor()
    .unwrap();
    let protocol = host
        .paired_protocol(PairedTrustedProfile {
            endpoint: "wss://localhost/desktop-startup-fault".into(),
            gateway_namespace: "desktop-startup-gateway".try_into().unwrap(),
            device_id: device,
            host_generation: generation,
        })
        .unwrap()
        .with_computer_profiles(source)
        .unwrap();
    protocol
        .accept_epoch(&"desktop-startup-gateway-epoch".try_into().unwrap())
        .unwrap();
    let owner = OwnerRef {
        owner_id: "desktop-startup:owner".try_into().unwrap(),
        owner_epoch: paired_owner_epoch(&"desktop-startup-gateway-epoch".try_into().unwrap(), 1),
    };
    assert!(matches!(
        protocol.control(&Call::OwnerOpen {
            owner: owner.clone(),
            grant_revision: 1
        }),
        Some(Reply::OwnerOpened { .. })
    ));
    let action = serde_json::value::RawValue::from_string(
        serde_json::to_string(&CuaAction::list_tools(None).unwrap()).unwrap(),
    )
    .unwrap();
    let reply = tokio::time::timeout(
        Duration::from_secs(1),
        protocol.handle(Call::DesktopSession {
            owner: owner.clone(),
            grant_revision: 1,
            timeout_ms: Some(1000),
            action: action.clone(),
        }),
    )
    .await
    .unwrap();
    assert!(matches!(
        reply,
        Reply::Error {
            category: ErrorCategory::Busy,
            certainty: ExecutionCertainty::NotDispatched,
            ..
        }
    ));
    assert!(!host.coordinator().desktop_configured());
    // Actual control authority still advances the SAME Core owner while the
    // separate initialization job remains blocked; no synthetic grant is added.
    assert!(matches!(
        protocol.control(&Call::OwnerRevoke {
            owner: owner.clone()
        }),
        Some(Reply::OwnerRevoked { fenced: true, .. })
    ));
    let reply = protocol
        .handle(Call::DesktopSession {
            owner,
            grant_revision: 1,
            timeout_ms: Some(1000),
            action,
        })
        .await;
    assert!(matches!(
        reply,
        Reply::Error {
            category: ErrorCategory::Unauthorized,
            ..
        }
    ));
    protocol.drain_computer_inputs().await;
    drop(protocol);
    let cleanup = host.shutdown_owned(Duration::from_secs(1)).await.unwrap();
    assert!(cleanup.supervised_jobs_joined);
}

#[cfg(test)]
mod input_tests {
    use super::*;

    struct Bootstrap;
    impl ComputerBootstrap for Bootstrap {
        fn prepare_profile(&self, _: &OwnerLease) -> Result<OwnedCuaConfig, ErrorCategory> {
            unreachable!("input gate test never opens a native profile")
        }
        fn validate_before_spawn(&self) -> Result<(), ErrorCategory> {
            Ok(())
        }
        fn validate_control(&self) -> Result<(), ErrorCategory> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn computer_input_readers_survive_profile_release() {
        let inputs = ComputerInputs {
            source: Arc::new(Bootstrap),
            tasks: TaskTracker::new(),
            gate: Arc::new(tokio::sync::RwLock::new(())),
        };
        let writer = inputs.gate.clone().write_owned().await;
        {
            let first = inputs.run(|source| source.validate_control());
            let second = inputs.run(|source| source.validate_control());
            let third = inputs.run(|source| source.validate_control());
            tokio::pin!(first, second, third);
            assert!(futures_util::poll!(&mut first).is_pending());
            assert!(futures_util::poll!(&mut second).is_pending());
            assert!(futures_util::poll!(&mut third).is_pending());

            // Cancel queued readers while profile release still holds the gate.
        }
        drop(writer);
        inputs
            .run(|source| source.validate_control())
            .await
            .unwrap();
        inputs.tasks.close();
        inputs.tasks.wait().await;
    }
}
