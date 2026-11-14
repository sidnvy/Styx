//! Request-scoped Exec adapter over the Host's existing Core operations.
//! Contains no connection or conversation state.
use super::*;
use crate::host::coordinator::{ActionSubmission, CoordinatorError, StartSubmission};
use crate::host::replies::{action_reply, coordinator_error, invalid, rejection};
use crate::providers::codex::{DispatchEvidence, ExecError, StartProcess};
use std::collections::BTreeSet;
pub(crate) struct ExecPort<'a> {
    pub(crate) coordinator: &'a HostCoordinator,
    pub(crate) authority: &'a HostAuthority,
    pub(crate) command_environment: &'a BTreeMap<String, String>,
}
impl ExecPort<'_> {
    pub(crate) fn command_spec(
        &self,
        mut spec: StartProcess,
    ) -> Result<StartProcess, ErrorCategory> {
        // Windows variable names are case-insensitive; Unix names are exact.
        let fold = |key: &str| {
            if cfg!(target_os = "windows") {
                key.to_ascii_uppercase()
            } else {
                key.to_owned()
            }
        };
        let mut names = BTreeSet::new();
        if spec.environment.len() > 64
            || spec.environment.keys().any(|key| {
                key.is_empty()
                    || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                    || !names.insert(fold(key))
            })
        {
            return Err(ErrorCategory::InvalidRequest);
        }
        for (key, value) in self.command_environment {
            if let Some(alias) = spec
                .environment
                .keys()
                .find(|name| fold(name) == fold(key))
                .cloned()
            {
                if spec.environment.get(&alias) != Some(value) {
                    return Err(ErrorCategory::InvalidRequest);
                }
                spec.environment.remove(&alias);
            }
            spec.environment.insert(key.clone(), value.clone());
        }
        if spec
            .to_operation_payload()
            .map_err(|_| ErrorCategory::InvalidRequest)?
            .len()
            > SPEC_LIMIT
        {
            return Err(ErrorCategory::InvalidRequest);
        }
        Ok(spec)
    }
    async fn read_exec(
        &self,
        owner: &OwnerLease,
        id: &OperationId,
        digest: Sha256Digest,
        context: &PreparedContext,
        max_bytes: usize,
        wait: Duration,
    ) -> Result<crate::providers::codex::ProcessOutput, CoordinatorError> {
        let output = self
            .coordinator
            .read(owner, id, digest, context, max_bytes, wait)
            .await?;
        if output.liveness == ExecutionLiveness::Exited && output.drain == OutputDrain::Drained {
            // Release provider storage before reporting terminal success. This
            // uses the existing fair quiescence gate and Core release proofs;
            // it neither fences the still-open owner nor cancels live work.
            let remaining =
                Duration::from_millis(context.deadline.0.saturating_sub(self.coordinator.now().0));
            self.authority.collect_provider_retention(remaining).await?;
            self.coordinator
                .validate_settled_exec_delivery(owner, id, digest, context)?;
        }
        Ok(output)
    }
    pub(crate) fn context(
        &self,
        revision: u64,
        timeout_ms: u32,
    ) -> Result<PreparedContext, ErrorCategory> {
        if timeout_ms == 0 || timeout_ms > 10_000 {
            return Err(ErrorCategory::InvalidRequest);
        }
        Ok(PreparedContext {
            device_id: self.coordinator.bootstrap_identity().0.clone(),
            grant_revision: revision,
            session: None,
            observation: None,
            capability: CapabilityId::ExecRun,
            deadline: MonotonicMillis(
                self.coordinator
                    .now()
                    .0
                    .saturating_add(u64::from(timeout_ms)),
            ),
            disconnect_policy: DisconnectPolicy::RetainForOwner,
        })
    }
    pub(crate) async fn exec_operation(&self, owner: &OwnerLease, call: Call) -> Reply {
        match call {
            Call::PrepareStart {
                owner: _,
                grant_revision,
                timeout_ms,
                spec,
            } => {
                if spec.get().len() > SPEC_LIMIT {
                    return invalid();
                }
                let context = match self.context(grant_revision, timeout_ms) {
                    Ok(v) => v,
                    Err(e) => return rejection(e),
                };
                let spec: StartProcess = match serde_json::from_str(spec.get()) {
                    Ok(v) => v,
                    Err(_) => return invalid(),
                };
                let spec = match self.command_spec(spec) {
                    Ok(spec) => spec,
                    Err(_) => return invalid(),
                };
                match self.coordinator.prepare_start(owner, context, &spec) {
                    Ok(v) => Reply::Prepared { snapshot: v.into() },
                    Err(e) => coordinator_error(e, false),
                }
            }
            Call::DispatchStart { owner: _, target } => {
                match self.coordinator.dispatch_start(
                    owner,
                    &target.operation_id,
                    target.payload_digest,
                ) {
                    Ok(StartSubmission::Existing(v)) => Reply::Start {
                        snapshot: v.into(),
                        dispatch: "existing_no_replay".into(),
                    },
                    Ok(StartSubmission::Submitted(ticket)) => match ticket.wait().await {
                        Ok(v) if v.dispatch == DispatchEvidence::NotDispatched => {
                            // This typed completion proves the adapter sent no
                            // action bytes. Do not erase it into a generic Start.
                            rejection(match v.cause {
                                Some(ExecError::Capacity) => ErrorCategory::Busy,
                                Some(ExecError::InvalidRequest) => ErrorCategory::InvalidRequest,
                                _ => ErrorCategory::StateConflict,
                            })
                        }
                        Ok(v) => Reply::Start {
                            snapshot: v.snapshot.into(),
                            dispatch: match v.dispatch {
                                DispatchEvidence::NotDispatched => "not_dispatched",
                                DispatchEvidence::Started => "started",
                                DispatchEvidence::Unknown => "unknown",
                            }
                            .into(),
                        },
                        Err(e) => coordinator_error(e, false),
                    },
                    Err(e) => coordinator_error(e, false),
                }
            }
            Call::InspectStart { owner: _, target } => {
                match self.coordinator.inspect_start(
                    owner,
                    &target.operation_id,
                    target.payload_digest,
                ) {
                    Ok(v) => Reply::Inspected { snapshot: v.into() },
                    Err(e) => coordinator_error(e, false),
                }
            }
            Call::Read {
                owner: _,
                target,
                grant_revision,
                timeout_ms,
                max_bytes,
                wait_ms,
            } => {
                if max_bytes == 0 || max_bytes > 16384 || wait_ms > 100 {
                    return invalid();
                }
                let context = match self.context(grant_revision, timeout_ms) {
                    Ok(v) => v,
                    Err(e) => return rejection(e),
                };
                match self
                    .read_exec(
                        owner,
                        &target.operation_id,
                        target.payload_digest,
                        &context,
                        max_bytes as usize,
                        Duration::from_millis(u64::from(wait_ms)),
                    )
                    .await
                {
                    Ok(v) => Reply::Read {
                        chunks: v
                            .chunks
                            .into_iter()
                            .map(|c| Chunk {
                                stream: c.stream,
                                text: c.text,
                            })
                            .collect(),
                        liveness: v.liveness,
                        output_drain: v.drain,
                        exit_code: v.exit_code,
                        read_resume: false,
                    },
                    Err(e) => coordinator_error(e, true),
                }
            }
            Call::PrepareAction {
                owner: _,
                target,
                grant_revision,
                timeout_ms,
                action,
            } => {
                if action.get().len() > SPEC_LIMIT {
                    return invalid();
                }
                let context = match self.context(grant_revision, timeout_ms) {
                    Ok(v) => v,
                    Err(e) => return rejection(e),
                };
                let action: ProcessAction = match serde_json::from_str(action.get()) {
                    Ok(v) => v,
                    Err(_) => return invalid(),
                };
                match self
                    .coordinator
                    .prepare_action(owner, target, context, &action)
                {
                    Ok(v) => Reply::Prepared { snapshot: v.into() },
                    Err(e) => coordinator_error(e, false),
                }
            }
            Call::DispatchAction { owner: _, action } => {
                match self.coordinator.dispatch_action(
                    owner,
                    &action.operation_id,
                    action.payload_digest,
                ) {
                    Ok(ActionSubmission::Existing(snapshot)) => {
                        match self.coordinator.lookup_action(
                            owner,
                            &action.operation_id,
                            action.payload_digest,
                        ) {
                            Ok(receipt) => action_reply(snapshot, receipt, true),
                            Err(e) => coordinator_error(e, false),
                        }
                    }
                    Ok(ActionSubmission::Submitted(ticket)) => match ticket.wait().await {
                        Ok(v) => action_reply(v.snapshot, Some(v.receipt), false),
                        Err(e) => coordinator_error(e, false),
                    },
                    Err(e) => coordinator_error(e, false),
                }
            }
            Call::InspectAction { owner: _, action } => {
                match self.coordinator.inspect_action(
                    owner,
                    &action.operation_id,
                    action.payload_digest,
                ) {
                    Ok(snapshot) => match self.coordinator.lookup_action(
                        owner,
                        &action.operation_id,
                        action.payload_digest,
                    ) {
                        Ok(receipt) => action_reply(snapshot, receipt, true),
                        Err(e) => coordinator_error(e, false),
                    },
                    Err(e) => coordinator_error(e, false),
                }
            }
            _ => invalid(),
        }
    }
}
