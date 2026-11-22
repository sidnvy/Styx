//! Browser operation port over the existing Core and pinned executor.
use crate::host::coordinator::{
    BrowserActionSubmission, BrowserOpenSubmission, CoordinatorError, HostAuthority,
    HostCoordinator,
};
use crate::host::protocol::wire::{self, ActionRef, Reply, Snapshot};
use crate::host::replies::{coordinator_error, invalid, rejection};
use crate::providers::browser::{
    BrowserAction, BrowserActionEvidence, BrowserDescendants, BrowserError, OwnedBrowserConfig,
};
use std::{sync::Arc, time::Duration};
use styx_contracts::{
    capability::CapabilityId,
    error::{ErrorCategory, ExecutionCertainty},
    identity::*,
    operation::*,
};
use styx_core::operations::OwnerLease;
use tokio_util::task::TaskTracker;
const SPEC_LIMIT: usize = 128 * 1024;
pub(crate) enum BrowserCommand {
    PrepareOpen,
    DispatchOpen {
        target: ResourceTarget,
    },
    PrepareAction {
        target: ResourceTarget,
        action: Box<serde_json::value::RawValue>,
    },
    DispatchAction {
        action: ActionRef,
    },
}
pub(crate) enum BrowserReply {
    Prepared {
        snapshot: Snapshot,
    },
    Start {
        snapshot: Snapshot,
        dispatch: String,
    },
    Action {
        snapshot: Snapshot,
        dispatch: String,
        result: Option<serde_json::Value>,
        cause: Option<ErrorCategory>,
        #[cfg_attr(not(test), allow(dead_code))]
        cleanup_complete: Option<bool>,
    },
    Error {
        category: ErrorCategory,
        certainty: ExecutionCertainty,
    },
}
impl From<Reply> for BrowserReply {
    fn from(reply: Reply) -> Self {
        match reply {
            Reply::Error {
                category,
                certainty,
                ..
            } => Self::Error {
                category,
                certainty,
            },
            _ => Self::Error {
                category: ErrorCategory::ResultUnknown,
                certainty: ExecutionCertainty::Unknown,
            },
        }
    }
}
pub(crate) trait BrowserBootstrap: Send + Sync {
    /// Saved local profiles, without caller identities or execution state.
    /// Adapters must explicitly forward discovery rather than hide saved logins.
    fn saved_profiles(&self) -> Result<Vec<String>, ErrorCategory>;
    // Every adapter must explicitly forward or implement metadata retirement.
    fn release_profile(&self, owner: &OwnerLease);
    /// Includes control and full worker-input validation before profile creation.
    fn prepare_profile(&self, owner: &OwnerLease) -> Result<OwnedBrowserConfig, ErrorCategory>;
    fn validate_before_spawn(&self) -> Result<(), ErrorCategory>;
    fn validate_control(&self) -> Result<(), ErrorCategory>;
}
pub(crate) struct BrowserInputs {
    source: Arc<dyn BrowserBootstrap>,
    tasks: TaskTracker,
    gate: Arc<tokio::sync::RwLock<()>>,
}
impl BrowserInputs {
    pub(crate) fn new(source: Arc<dyn BrowserBootstrap>) -> Self {
        Self {
            source,
            tasks: TaskTracker::new(),

            gate: Arc::new(tokio::sync::RwLock::new(())),
        }
    }
}
pub(crate) struct BrowserPort<'a> {
    pub(crate) coordinator: &'a HostCoordinator,
    pub(crate) authority: &'a HostAuthority,
    pub(crate) inputs: &'a BrowserInputs,
}
impl BrowserPort<'_> {
    pub(crate) async fn saved_profiles(&self) -> Result<Vec<String>, ErrorCategory> {
        self.browser_input(|source| source.saved_profiles()).await
    }
    fn context(&self, revision: u64, timeout: u32) -> Result<PreparedContext, ErrorCategory> {
        if timeout == 0 || timeout > 10_000 {
            return Err(ErrorCategory::InvalidRequest);
        }
        Ok(PreparedContext {
            device_id: self.coordinator.bootstrap_identity().0.clone(),
            grant_revision: revision,
            session: None,
            observation: None,
            capability: CapabilityId::Browser,
            deadline: Some(MonotonicMillis(
                self.coordinator.now().0.saturating_add(u64::from(timeout)),
            )),
            disconnect_policy: DisconnectPolicy::RetainForOwner,
        })
    }
    pub(crate) async fn release_browser_profile(
        &self,
        owner: OwnerLease,
    ) -> Result<(), ErrorCategory> {
        let inputs = self.inputs;
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
    pub(crate) async fn drain_browser_inputs(&self) {
        self.inputs.tasks.close();
        self.inputs.tasks.wait().await;
    }
    async fn browser_input<T: Send + 'static>(
        &self,
        work: impl FnOnce(Arc<dyn BrowserBootstrap>) -> Result<T, ErrorCategory> + Send + 'static,
    ) -> Result<T, ErrorCategory> {
        let inputs = self.inputs;
        if inputs.tasks.is_closed() {
            return Err(ErrorCategory::Busy);
        }
        let source = inputs.source.clone();
        let guard = inputs.gate.clone().read_owned().await;
        inputs
            .tasks
            .spawn_blocking(move || {
                let _guard = guard;
                work(source)
            })
            .await
            .map_err(|_| ErrorCategory::IntegrityFailure)?
    }
    fn existing_browser_dispatch(
        &self,
        owner: &OwnerLease,
        id: &OperationId,
        digest: Sha256Digest,
        action: bool,
    ) -> Result<Option<BrowserReply>, CoordinatorError> {
        let snapshot = self
            .coordinator
            .inspect_browser(owner, id, digest, action)?;
        if snapshot.state == OperationState::Reserved {
            return Ok(None);
        }
        Ok(Some(if action {
            BrowserReply::Action {
                snapshot: snapshot.into(),
                dispatch: "existing_no_replay".into(),
                result: None,
                cause: None,
                cleanup_complete: None,
            }
        } else {
            BrowserReply::Start {
                snapshot: snapshot.into(),
                dispatch: "existing_no_replay".into(),
            }
        }))
    }
    fn browser_dispatch_error(
        &self,
        owner: &OwnerLease,
        id: &OperationId,
        digest: Sha256Digest,
        action: bool,
        error: CoordinatorError,
    ) -> BrowserReply {
        match self.existing_browser_dispatch(owner, id, digest, action) {
            Ok(Some(reply)) => reply,
            _ => coordinator_error(error, false).into(),
        }
    }
    async fn validate_browser_dispatch(
        &self,
        owner: &OwnerLease,
        id: &OperationId,
        digest: Sha256Digest,
        action: bool,
    ) -> Result<(), BrowserReply> {
        // Local input validation must never downgrade an original dispatched
        // operation's history to NotDispatched after a file/permission change.
        match self.existing_browser_dispatch(owner, id, digest, action) {
            Ok(Some(reply)) => return Err(reply),
            Ok(None) => {}
            Err(e) => return Err(uncertain(coordinator_error(e, false).into())),
        }
        let validation = self
            .browser_input(move |source| {
                if action {
                    source.validate_control()
                } else {
                    source.validate_before_spawn()
                }
            })
            .await;
        if let Err(category) = validation {
            return Err(
                match self.existing_browser_dispatch(owner, id, digest, action) {
                    Ok(Some(reply)) => reply,
                    // Another request may have consumed this original token while
                    // the blocking validator ran. A local refusal is not proof of
                    // its historical outcome, and never authorizes replay.
                    _ => uncertain(rejection(category).into()),
                },
            );
        }
        Ok(())
    }
    pub(crate) async fn handle_browser(
        &self,
        owner: OwnerLease,
        revision: u64,
        timeout: u32,
        command: BrowserCommand,
    ) -> BrowserReply {
        if timeout > wire::BROWSER_WAIT_PREPARE_TIMEOUT_MS {
            return rejection(ErrorCategory::InvalidRequest).into();
        }
        // Exec's ten-second admission bound remains unchanged. Only this
        // independently authorized Browser context may admit a native wait.
        let mut context = match self.context(revision, timeout.min(10_000)) {
            Ok(v) => v,
            Err(e) => return rejection(e).into(),
        };
        context.capability = CapabilityId::Browser;
        context.deadline = Some(MonotonicMillis(
            self.coordinator.now().0.saturating_add(u64::from(timeout)),
        ));
        match command {
            BrowserCommand::PrepareOpen => {
                let bound = owner.clone();
                let current = self.coordinator.clone();
                let config = match self
                    .browser_input(move |source| {
                        if !current.owner_is_active(&bound) {
                            return Err(ErrorCategory::Unauthorized);
                        }
                        source.prepare_profile(&bound)
                    })
                    .await
                {
                    Ok(v) => v,
                    Err(e) => return rejection(e).into(),
                };
                // Blocking input work grants no authority; Core rechecks this
                // original owner after it returns, including an in-flight revoke.
                if !self.coordinator.owner_is_active(&owner) {
                    return rejection(ErrorCategory::Unauthorized).into();
                }
                if let Err(e) = self.authority.register_browser_profile(&owner, config) {
                    return coordinator_error(e, false).into();
                }
                match self.coordinator.prepare_browser_open(&owner, context) {
                    Ok(snapshot) => BrowserReply::Prepared {
                        snapshot: snapshot.into(),
                    },
                    Err(e) => coordinator_error(e, false).into(),
                }
            }
            BrowserCommand::DispatchOpen { target } => {
                if let Err(reply) = self
                    .validate_browser_dispatch(
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
                    .dispatch_browser_open(&owner, &target.operation_id, target.payload_digest)
                    .await
                {
                    Ok(BrowserOpenSubmission::Existing(snapshot)) => BrowserReply::Start {
                        snapshot: snapshot.into(),
                        dispatch: "existing_no_replay".into(),
                    },
                    Ok(BrowserOpenSubmission::Submitted(ticket)) => match ticket.wait().await {
                        Ok(done) if done.evidence == BrowserActionEvidence::NotDispatched => {
                            // No Browser was started. Deferred metadata collection
                            // cannot change that fact or require replay of this request.
                            let _ = self
                                .authority
                                .collect_provider_retention(Duration::from_secs(1))
                                .await;
                            rejection(
                                done.cause
                                    .map(category)
                                    .unwrap_or(ErrorCategory::CapabilityUnsupported),
                            )
                            .into()
                        }
                        Ok(done) => BrowserReply::Start {
                            snapshot: done.snapshot.into(),
                            dispatch: match done.evidence {
                                BrowserActionEvidence::Acknowledged => "started",
                                BrowserActionEvidence::NotDispatched => "not_dispatched",
                                BrowserActionEvidence::Unknown => "unknown",
                            }
                            .into(),
                        },
                        Err(e) => coordinator_error(e, false).into(),
                    },
                    Err(e) => self.browser_dispatch_error(
                        &owner,
                        &target.operation_id,
                        target.payload_digest,
                        false,
                        e,
                    ),
                }
            }
            BrowserCommand::PrepareAction { target, action } => {
                if action.get().len() > SPEC_LIMIT {
                    return invalid().into();
                }
                let action: BrowserAction = match serde_json::from_str(action.get()) {
                    Ok(v) => v,
                    Err(_) => return invalid().into(),
                };
                if let Err(e) = self.browser_input(|source| source.validate_control()).await {
                    return rejection(e).into();
                }
                match self
                    .coordinator
                    .prepare_browser_action(&owner, target, context, &action)
                {
                    Ok(snapshot) => BrowserReply::Prepared {
                        snapshot: snapshot.into(),
                    },
                    Err(e) => coordinator_error(e, false).into(),
                }
            }
            BrowserCommand::DispatchAction { action } => {
                if let Err(reply) = self
                    .validate_browser_dispatch(
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
                    .dispatch_browser_action(&owner, &action.operation_id, action.payload_digest)
                    .await
                {
                    Ok(BrowserActionSubmission::Existing(snapshot)) => BrowserReply::Action {
                        snapshot: snapshot.into(),
                        dispatch: "existing_no_replay".into(),
                        result: None,
                        cause: None,
                        cleanup_complete: None,
                    },
                    Ok(BrowserActionSubmission::Submitted(ticket)) => match ticket.wait().await {
                        Ok(done) => {
                            let result = done
                                .receipt
                                .result
                                .and_then(|result| serde_json::to_value(result).ok());
                            let cleanup_complete = done.cleanup.map(|facts| {
                                facts.worker_exited
                                    && facts.stdio_joined
                                    && facts.descendants == BrowserDescendants::Confirmed
                                    && done.cleanup_error.is_none()
                                    && done.retention_error.is_none()
                            });
                            if cleanup_complete == Some(true) {
                                // A closed native context must not consume the
                                // provider's retained-record quota until DELETE.
                                self.authority
                                    .collect_provider_retention(Duration::from_secs(1))
                                    .await
                                    .ok();
                            }
                            BrowserReply::Action {
                                snapshot: done.snapshot.into(),
                                dispatch: match done.receipt.evidence {
                                    BrowserActionEvidence::Acknowledged => "acknowledged",
                                    BrowserActionEvidence::NotDispatched => "not_dispatched",
                                    BrowserActionEvidence::Unknown => "unknown",
                                }
                                .into(),
                                result,
                                cause: done.receipt.cause.map(category),
                                cleanup_complete,
                            }
                        }
                        Err(e) => coordinator_error(e, false).into(),
                    },
                    Err(e) => self.browser_dispatch_error(
                        &owner,
                        &action.operation_id,
                        action.payload_digest,
                        true,
                        e,
                    ),
                }
            }
        }
    }
}
fn category(error: BrowserError) -> ErrorCategory {
    match error {
        BrowserError::Busy => ErrorCategory::Busy,
        BrowserError::InvalidRequest => ErrorCategory::InvalidRequest,
        BrowserError::PermissionDenied => ErrorCategory::PermissionDenied,
        BrowserError::Unsupported => ErrorCategory::CapabilityUnsupported,
        BrowserError::StaleObservation => ErrorCategory::StaleObservation,
        BrowserError::ProtocolMismatch => ErrorCategory::ProtocolMismatch,
        BrowserError::AlreadyDispatched => ErrorCategory::StateConflict,
        BrowserError::SpawnFailed | BrowserError::Unknown | BrowserError::CleanupUnconfirmed => {
            ErrorCategory::ResultUnknown
        }
    }
}

fn uncertain(mut reply: BrowserReply) -> BrowserReply {
    if let BrowserReply::Error { certainty, .. } = &mut reply {
        *certainty = ExecutionCertainty::Unknown;
    }
    reply
}
