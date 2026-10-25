//! Protected local Browser inputs; no path or profile choice comes from WSS.
//! Blocking validation jobs outlive dropped connection waiters and are joined
//! before explicit Host shutdown can release its original input/lease owners.
use super::*;
use crate::{
    host::coordinator::{BrowserActionSubmission, BrowserOpenSubmission},
    providers::browser::{
        BrowserAction, BrowserActionEvidence, BrowserDescendants, BrowserError, OwnedBrowserConfig,
    },
};
use std::sync::Arc;
use tokio_util::task::TaskTracker;

pub(crate) trait BrowserBootstrap: Send + Sync {
    /// Includes control and full worker-input validation before profile creation.
    fn prepare_profile(&self, owner: &OwnerLease) -> Result<OwnedBrowserConfig, ErrorCategory>;
    fn validate_before_spawn(&self) -> Result<(), ErrorCategory>;
    fn validate_control(&self) -> Result<(), ErrorCategory>;
}
pub(super) struct BrowserInputs {
    source: Arc<dyn BrowserBootstrap>,
    tasks: TaskTracker,
    slots: Arc<tokio::sync::Semaphore>,
}
impl HostProtocol<'_> {
    pub(crate) fn with_browser_profiles(
        mut self,
        source: Arc<dyn BrowserBootstrap>,
    ) -> Result<Self, ProtocolError> {
        if !self.paired || !self.coordinator.browser_configured() || self.browser.is_some() {
            return Err(ProtocolError::BootstrapMismatch);
        }
        self.browser = Some(BrowserInputs {
            source,
            tasks: TaskTracker::new(),
            slots: Arc::new(tokio::sync::Semaphore::new(2)),
        });
        Ok(self)
    }
    pub(crate) async fn drain_browser_inputs(&self) {
        if let Some(inputs) = &self.browser {
            inputs.tasks.close();
            inputs.tasks.wait().await;
        }
    }
    async fn browser_input<T: Send + 'static>(
        &self,
        work: impl FnOnce(Arc<dyn BrowserBootstrap>) -> Result<T, ErrorCategory> + Send + 'static,
    ) -> Result<T, ErrorCategory> {
        let inputs = self
            .browser
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
    fn existing_browser_dispatch(
        &self,
        owner: &OwnerLease,
        id: &OperationId,
        digest: Sha256Digest,
        action: bool,
    ) -> Result<Option<Reply>, CoordinatorError> {
        let snapshot = self
            .coordinator
            .inspect_browser(owner, id, digest, action)?;
        if snapshot.state == OperationState::Reserved {
            return Ok(None);
        }
        Ok(Some(if action {
            Reply::BrowserAction {
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
    fn browser_dispatch_error(
        &self,
        owner: &OwnerLease,
        id: &OperationId,
        digest: Sha256Digest,
        action: bool,
        error: CoordinatorError,
    ) -> Reply {
        match self.existing_browser_dispatch(owner, id, digest, action) {
            Ok(Some(reply)) => reply,
            _ => coordinator_error(error, false),
        }
    }
    async fn validate_browser_dispatch(
        &self,
        owner: &OwnerLease,
        id: &OperationId,
        digest: Sha256Digest,
        action: bool,
    ) -> Result<(), Reply> {
        // Local input validation must never downgrade an original dispatched
        // operation's history to NotDispatched after a file/permission change.
        match self.existing_browser_dispatch(owner, id, digest, action) {
            Ok(Some(reply)) => return Err(reply),
            Ok(None) => {}
            Err(e) => return Err(uncertain(coordinator_error(e, false))),
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
                    _ => uncertain(rejection(category)),
                },
            );
        }
        Ok(())
    }
    pub(super) async fn handle_browser(
        &self,
        reference: OwnerRef,
        revision: u64,
        timeout: u32,
        command: BrowserCommand,
    ) -> Reply {
        if !self.paired || self.browser.is_none() {
            return Reply::Unsupported {
                feature: BROWSER_HEADLESS_V1.into(),
            };
        }
        let owner = match self.owner(&reference) {
            Ok(v) => v,
            Err(e) => return rejection(e),
        };
        if timeout > wire::BROWSER_WAIT_PREPARE_TIMEOUT_MS {
            return rejection(ErrorCategory::InvalidRequest);
        }
        // Exec's ten-second admission bound remains unchanged. Only this
        // independently authorized Browser context may admit a native wait.
        let mut context = match self.context(revision, timeout.min(10_000)) {
            Ok(v) => v,
            Err(e) => return rejection(e),
        };
        context.capability = CapabilityId::BrowserHeadless;
        context.deadline =
            MonotonicMillis(self.coordinator.now().0.saturating_add(u64::from(timeout)));
        match command {
            BrowserCommand::PrepareOpen => {
                let bound = owner.clone();
                let config = match self
                    .browser_input(move |source| source.prepare_profile(&bound))
                    .await
                {
                    Ok(v) => v,
                    Err(e) => return rejection(e),
                };
                // Blocking input work grants no authority; Core rechecks this
                // original owner after it returns, including an in-flight revoke.
                if self.owner(&reference).as_ref() != Ok(&owner) {
                    return rejection(ErrorCategory::Unauthorized);
                }
                if let Err(e) = self.authority.register_browser_profile(&owner, config) {
                    return coordinator_error(e, false);
                }
                match self.coordinator.prepare_browser_open(&owner, context) {
                    Ok(snapshot) => Reply::Prepared {
                        snapshot: snapshot.into(),
                    },
                    Err(e) => coordinator_error(e, false),
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
                match self.coordinator.dispatch_browser_open(
                    &owner,
                    &target.operation_id,
                    target.payload_digest,
                ) {
                    Ok(BrowserOpenSubmission::Existing(snapshot)) => Reply::Start {
                        snapshot: snapshot.into(),
                        dispatch: "existing_no_replay".into(),
                    },
                    Ok(BrowserOpenSubmission::Submitted(ticket)) => match ticket.wait().await {
                        Ok(done) => Reply::Start {
                            snapshot: done.snapshot.into(),
                            dispatch: match done.evidence {
                                BrowserActionEvidence::Acknowledged => "started",
                                BrowserActionEvidence::NotDispatched => "not_dispatched",
                                BrowserActionEvidence::Unknown => "unknown",
                            }
                            .into(),
                        },
                        Err(e) => coordinator_error(e, false),
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
            BrowserCommand::InspectOpen { target } => match self.coordinator.inspect_browser(
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
            BrowserCommand::PrepareAction { target, action } => {
                if action.get().len() > SPEC_LIMIT {
                    return invalid();
                }
                let action: BrowserAction = match serde_json::from_str(action.get()) {
                    Ok(v) => v,
                    Err(_) => return invalid(),
                };
                if let Err(e) = self.browser_input(|source| source.validate_control()).await {
                    return rejection(e);
                }
                match self
                    .coordinator
                    .prepare_browser_action(&owner, target, context, &action)
                {
                    Ok(snapshot) => Reply::Prepared {
                        snapshot: snapshot.into(),
                    },
                    Err(e) => coordinator_error(e, false),
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
                match self.coordinator.dispatch_browser_action(
                    &owner,
                    &action.operation_id,
                    action.payload_digest,
                ) {
                    Ok(BrowserActionSubmission::Existing(snapshot)) => Reply::BrowserAction {
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
                            Reply::BrowserAction {
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
                        Err(e) => coordinator_error(e, false),
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
            BrowserCommand::InspectAction { action } => match self.coordinator.inspect_browser(
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

fn uncertain(mut reply: Reply) -> Reply {
    if let Reply::Error { certainty, .. } = &mut reply {
        *certainty = ExecutionCertainty::Unknown;
    }
    reply
}

// These existing fixtures use Unix paths/native Linux process scopes.
// Windows acceptance uses its actual protected Job and platform journey.
#[cfg(all(test, target_os = "linux"))]
#[path = "browser_history_tests.rs"]
pub(crate) mod history_tests;
