//! Protected local Computer inputs; no path or profile choice comes from WSS.
//! Blocking validation jobs outlive dropped connection waiters and are joined
//! before explicit Host shutdown can release its original input/lease owners.
use super::*;
use crate::{
    host::coordinator::{DesktopActionSubmission, DesktopOpenSubmission},
    providers::cua::{CuaAction, CuaError, CuaEvidence, OwnedCuaConfig},
};
use std::sync::Arc;
use tokio_util::task::TaskTracker;

pub(crate) trait ComputerBootstrap: Send + Sync {
    fn prepare_profile(&self, owner: &OwnerLease) -> Result<OwnedCuaConfig, ErrorCategory>;
    fn validate_before_spawn(&self) -> Result<(), ErrorCategory>;
    fn validate_control(&self) -> Result<(), ErrorCategory>;
}
pub(super) struct ComputerInputs {
    source: Arc<dyn ComputerBootstrap>,
    tasks: TaskTracker,
    slots: Arc<tokio::sync::Semaphore>,
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
            slots: Arc::new(tokio::sync::Semaphore::new(2)),
        });
        Ok(self)
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
        let inputs = self
            .computer
            .as_ref()
            .ok_or(ErrorCategory::CapabilityUnsupported)?;
        if inputs.tasks.is_closed() {
            return Err(ErrorCategory::Busy);
        }
        let permit = inputs
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| ErrorCategory::Busy)?;
        let source = inputs.source.clone();
        inputs
            .tasks
            .spawn_blocking(move || {
                let _permit = permit;
                work(source)
            })
            .await
            .map_err(|_| ErrorCategory::IntegrityFailure)?
    }
    fn existing_computer_dispatch(
        &self,
        owner: &OwnerLease,
        id: &OperationId,
        digest: Sha256Digest,
        action: bool,
    ) -> Result<Option<Reply>, CoordinatorError> {
        let snapshot = self
            .coordinator
            .inspect_desktop(owner, id, digest, action)?;
        if snapshot.state == OperationState::Reserved {
            return Ok(None);
        }
        Ok(Some(if action {
            Reply::ComputerAction {
                snapshot: snapshot.into(),
                dispatch: "existing_no_replay".into(),
                result: None,
                cause: None,
                cleanup_complete: None,
            }
        } else {
            Reply::Start {
                snapshot: snapshot.into(),
                dispatch: "existing_no_replay".into(),
            }
        }))
    }
    fn computer_dispatch_error(
        &self,
        owner: &OwnerLease,
        id: &OperationId,
        digest: Sha256Digest,
        action: bool,
        error: CoordinatorError,
    ) -> Reply {
        match self.existing_computer_dispatch(owner, id, digest, action) {
            Ok(Some(reply)) => reply,
            _ => coordinator_error(error, false),
        }
    }
    async fn validate_computer_dispatch(
        &self,
        owner: &OwnerLease,
        id: &OperationId,
        digest: Sha256Digest,
        action: bool,
    ) -> Result<(), Reply> {
        // Local input validation must never downgrade an original dispatched
        // operation's history to NotDispatched after a file/permission change.
        match self.existing_computer_dispatch(owner, id, digest, action) {
            Ok(Some(reply)) => return Err(reply),
            Ok(None) => {}
            Err(e) => return Err(uncertain(coordinator_error(e, false))),
        }
        let validation = self
            .computer_input(move |source| {
                if action {
                    source.validate_control()
                } else {
                    source.validate_before_spawn()
                }
            })
            .await;
        if let Err(category) = validation {
            return Err(
                match self.existing_computer_dispatch(owner, id, digest, action) {
                    Ok(Some(reply)) => reply,
                    // Another request may have consumed this original token while
                    // the blocking validator ran. A local refusal is not proof of
                    // its historical outcome, and never authorizes replay.
                    _ => uncertain(rejection(category)),
                },
            );
        }
        Ok(())
    }
    pub(super) async fn handle_computer(
        &self,
        reference: OwnerRef,
        revision: u64,
        timeout: u32,
        command: ComputerCommand,
    ) -> Reply {
        if !self.paired || self.computer.is_none() {
            return Reply::Unsupported {
                feature: COMPUTER_V1.into(),
            };
        }
        let owner = match self.owner(&reference) {
            Ok(v) => v,
            Err(e) => return rejection(e),
        };
        let mut context = match self.context(revision, timeout) {
            Ok(v) => v,
            Err(e) => return rejection(e),
        };
        // Never import a SessionBinding/observation from the Gateway JSON. The
        // source-backed Host owns session selection, generation and evidence.
        // Resolve it only for new preparations; historical inspect/dispatch
        // must remain readable after the live association becomes unavailable.
        context.capability = CapabilityId::DesktopWindowsRead;
        context.observation = None;
        match command {
            ComputerCommand::PrepareOpen => {
                let bound = owner.clone();
                let config = match self
                    .computer_input(move |source| {
                        source.validate_control()?;
                        source.prepare_profile(&bound)
                    })
                    .await
                {
                    Ok(v) => v,
                    Err(e) => return rejection(e),
                };
                if !self.coordinator.desktop_configured() {
                    return rejection(ErrorCategory::CapabilityUnsupported);
                }
                context.session = match self.coordinator.desktop_binding() {
                    Ok(v) => Some(v),
                    Err(e) => return coordinator_error(e, false),
                };
                if self.owner(&reference).as_ref() != Ok(&owner) {
                    return rejection(ErrorCategory::Unauthorized);
                }
                if let Err(e) = self.authority.register_desktop_profile(&owner, config) {
                    return coordinator_error(e, false);
                }
                match self.coordinator.prepare_desktop_open(&owner, context) {
                    Ok(snapshot) => Reply::Prepared {
                        snapshot: snapshot.into(),
                    },
                    Err(e) => coordinator_error(e, false),
                }
            }
            ComputerCommand::DispatchOpen { target } => {
                if let Err(reply) = self
                    .validate_computer_dispatch(
                        &owner,
                        &target.operation_id,
                        target.payload_digest,
                        false,
                    )
                    .await
                {
                    return reply;
                }
                match self
                    .coordinator
                    .dispatch_desktop_open(&owner, &target.operation_id, target.payload_digest)
                    .await
                {
                    Ok(DesktopOpenSubmission::Existing(snapshot)) => Reply::Start {
                        snapshot: snapshot.into(),
                        dispatch: "existing_no_replay".into(),
                    },
                    Ok(DesktopOpenSubmission::Completed(done)) => Reply::Start {
                        snapshot: done.snapshot.into(),
                        dispatch: match done.evidence {
                            CuaEvidence::Acknowledged => "started",
                            CuaEvidence::NotDispatched => "not_dispatched",
                            CuaEvidence::Unknown => "unknown",
                        }
                        .into(),
                    },
                    Err(e) => self.computer_dispatch_error(
                        &owner,
                        &target.operation_id,
                        target.payload_digest,
                        false,
                        e,
                    ),
                }
            }
            ComputerCommand::InspectOpen { target } => match self.coordinator.inspect_desktop(
                &owner,
                &target.operation_id,
                target.payload_digest,
                false,
            ) {
                Ok(snapshot) => Reply::Inspected {
                    snapshot: snapshot.into(),
                },
                Err(e) => coordinator_error(e, false),
            },
            ComputerCommand::PrepareAction { target, action } => {
                if action.get().len() > SPEC_LIMIT {
                    return invalid();
                }
                let action: CuaAction = match serde_json::from_str(action.get()) {
                    Ok(v) => v,
                    Err(_) => return invalid(),
                };
                let request_digest = match action.to_operation_payload() {
                    Ok(payload) => Sha256Digest::of_bytes(&payload),
                    Err(error) => return rejection(category(error)),
                };
                context.capability = match action.capability() {
                    Ok(v) => v,
                    Err(e) => return rejection(category(e)),
                };
                // Observation remains absent. Input requires the Coordinator's
                // real native snapshot map; no token is invented to open it.
                if let Err(e) = self
                    .computer_input(|source| source.validate_control())
                    .await
                {
                    return rejection(e);
                }
                if !self.coordinator.desktop_configured() {
                    return rejection(ErrorCategory::CapabilityUnsupported);
                }
                context.session = match self.coordinator.desktop_binding() {
                    Ok(v) => Some(v),
                    Err(e) => return coordinator_error(e, false),
                };
                match self
                    .coordinator
                    .prepare_desktop_action(&owner, target, context, &action)
                {
                    Ok(snapshot) if snapshot.payload_digest != request_digest => {
                        Reply::ComputerPrepared {
                            request_digest,
                            snapshot: snapshot.into(),
                        }
                    }
                    Ok(snapshot) => Reply::Prepared {
                        snapshot: snapshot.into(),
                    },
                    Err(e) => coordinator_error(e, false),
                }
            }
            ComputerCommand::DispatchAction { action } => {
                if let Err(reply) = self
                    .validate_computer_dispatch(
                        &owner,
                        &action.operation_id,
                        action.payload_digest,
                        true,
                    )
                    .await
                {
                    return reply;
                }
                match self
                    .coordinator
                    .dispatch_desktop_action(&owner, &action.operation_id, action.payload_digest)
                    .await
                {
                    Ok(DesktopActionSubmission::Existing(snapshot)) => Reply::ComputerAction {
                        snapshot: snapshot.into(),
                        dispatch: "existing_no_replay".into(),
                        result: None,
                        cause: None,
                        cleanup_complete: None,
                    },
                    Ok(DesktopActionSubmission::Completed(done)) => {
                        let result = done
                            .receipt
                            .result
                            .and_then(|value| serde_json::to_value(value).ok());
                        Reply::ComputerAction {
                            snapshot: done.snapshot.into(),
                            dispatch: match done.receipt.evidence {
                                CuaEvidence::Acknowledged => "acknowledged",
                                CuaEvidence::NotDispatched => "not_dispatched",
                                CuaEvidence::Unknown => "unknown",
                            }
                            .into(),
                            result,
                            cause: done.receipt.cause.map(category),
                            // None of the ten native tools proves driver exit,
                            // joined I/O and cgroup emptiness. No false Complete.
                            cleanup_complete: None,
                        }
                    }
                    Err(e) => self.computer_dispatch_error(
                        &owner,
                        &action.operation_id,
                        action.payload_digest,
                        true,
                        e,
                    ),
                }
            }
            ComputerCommand::InspectAction { action } => match self.coordinator.inspect_desktop(
                &owner,
                &action.operation_id,
                action.payload_digest,
                true,
            ) {
                Ok(snapshot) => Reply::Inspected {
                    snapshot: snapshot.into(),
                },
                Err(e) => coordinator_error(e, false),
            },
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
        2,
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
        owner_epoch: "desktop-startup-owner-epoch".try_into().unwrap(),
    };
    assert!(matches!(
        protocol.control(&Call::OwnerOpen {
            owner: owner.clone(),
            grant_revision: 1
        }),
        Some(Reply::OwnerOpened { .. })
    ));
    let reply = tokio::time::timeout(
        Duration::from_secs(1),
        protocol.handle(Call::Computer {
            owner: owner.clone(),
            grant_revision: 1,
            timeout_ms: 1000,
            command: ComputerCommand::PrepareOpen,
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
        .handle(Call::Computer {
            owner,
            grant_revision: 1,
            timeout_ms: 1000,
            command: ComputerCommand::PrepareOpen,
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
