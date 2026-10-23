//! Fixed, input-free audit encoding and Core-attested physical release.
use super::*;
use styx_contracts::operation::{OperationState, ResourceTarget};
use styx_core::operations::{
    ProviderRecordKey, ProviderReleaseConfirmation, ProviderReleasePermit,
};

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionAuditV1 {
    version: u8,
    native_process_uuid: Option<String>,
    evidence: ActionEvidence,
    write_id: Option<String>,
    acknowledgment: Option<ActionAcknowledgment>,
    cause: Option<AuditCause>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum AuditCause {
    InvalidRequest,
    Capacity,
    TransportLost,
    NotSent,
    TimeoutUnknown,
    InvalidFrame,
    Rejected(i64),
    OwnerMismatch,
    UnknownHandle,
    AlreadyDispatched,
    ProcessLost,
    InputUnknown,
    ProcessFailure,
    SpawnFailed,
    ResourceUnsettled,
    ReadModeMismatch,
}
macro_rules! cause_conversion {
    ($($v:ident),* $(,)?) => {
        impl From<ExecError> for AuditCause { fn from(v: ExecError) -> Self { match v {
            $(ExecError::$v => Self::$v,)* ExecError::Rejected(n) => Self::Rejected(n),
        } } }
        impl From<AuditCause> for ExecError { fn from(v: AuditCause) -> Self { match v {
            $(AuditCause::$v => Self::$v,)* AuditCause::Rejected(n) => Self::Rejected(n),
        } } }
    }
}
cause_conversion!(
    InvalidRequest,
    Capacity,
    TransportLost,
    NotSent,
    TimeoutUnknown,
    InvalidFrame,
    OwnerMismatch,
    UnknownHandle,
    AlreadyDispatched,
    ProcessLost,
    InputUnknown,
    ProcessFailure,
    SpawnFailed,
    ResourceUnsettled,
    ReadModeMismatch
);

impl CodexStdio {
    /// Explicit whitelist: no argv, environment, stdin, stdout or arbitrary
    /// executor fields are persisted by this correlation format.
    pub fn action_audit(&self, receipt: &ActionReceipt) -> Result<Vec<u8>, ExecError> {
        let stored_uuid = self
            .actions
            .lock()
            .expect("actions mutex")
            .get(&receipt.operation)
            .map(|stored| stored.native_process_uuid.clone());
        let native_process_uuid = stored_uuid.or_else(|| {
            receipt.target.as_ref().and_then(|t| {
                self.operations
                    .lock()
                    .expect("operation mutex")
                    .get(&t.operation_id)
                    .map(|h| h.process_id.clone())
            })
        });
        Self::encode_action_audit(receipt, native_process_uuid)
    }
    fn encode_action_audit(
        receipt: &ActionReceipt,
        native_process_uuid: Option<String>,
    ) -> Result<Vec<u8>, ExecError> {
        let audit = ActionAuditV1 {
            version: 1,
            native_process_uuid,
            evidence: receipt.evidence,
            write_id: receipt.write_id.clone(),
            acknowledgment: receipt.acknowledgment.clone(),
            cause: receipt.cause.clone().map(Into::into),
        };
        let bytes = serde_json::to_vec(&audit).map_err(|_| ExecError::InvalidFrame)?;
        if bytes.len() > 1024 {
            return Err(ExecError::Capacity);
        }
        Ok(bytes)
    }
    /// Historical lookup only. Caller already checked current Core authority.
    pub fn action_from_audit(
        id: OperationId,
        target: ResourceTarget,
        bytes: &[u8],
    ) -> Result<ActionReceipt, ExecError> {
        if bytes.len() > 1024 {
            return Err(ExecError::InvalidFrame);
        }
        let audit: ActionAuditV1 =
            serde_json::from_slice(bytes).map_err(|_| ExecError::InvalidFrame)?;
        if audit.version != 1
            || audit
                .native_process_uuid
                .as_ref()
                .is_some_and(|s| Uuid::parse_str(s).is_err())
            || audit
                .write_id
                .as_ref()
                .is_some_and(|s| Uuid::parse_str(s).is_err())
        {
            return Err(ExecError::InvalidFrame);
        }
        Ok(ActionReceipt {
            operation: id,
            target: Some(target),
            evidence: audit.evidence,
            write_id: audit.write_id,
            acknowledgment: audit.acknowledgment,
            cause: audit.cause.map(Into::into),
        })
    }
    fn validate_release_action(
        &self,
        key: &ProviderRecordKey,
        stored: Option<&continuation::StoredAction>,
        ended: bool,
    ) -> Result<(), ExecError> {
        let snapshot = key.snapshot();
        if snapshot.target.is_none() || snapshot.state == OperationState::Unknown && !ended {
            return Err(ExecError::ResourceUnsettled);
        }
        if let Some(stored) = stored {
            if &stored.owner != key.owner()
                || stored.payload_digest != snapshot.payload_digest
                || stored.receipt.target != snapshot.target
                || stored.receipt.operation != snapshot.id
            {
                return Err(ExecError::OwnerMismatch);
            }
            let evidence_matches = matches!(
                (snapshot.state, stored.receipt.evidence),
                (OperationState::Succeeded, ActionEvidence::Acknowledged)
                    | (OperationState::Failed, ActionEvidence::NotDispatched)
                    | (OperationState::Unknown, _)
            );
            if !evidence_matches
                || Some(Sha256Digest::of_bytes(&Self::encode_action_audit(
                    &stored.receipt,
                    Some(stored.native_process_uuid.clone()),
                )?)) != key.audit_digest()
            {
                return Err(ExecError::InvalidFrame);
            }
        } else if !matches!(
            snapshot.state,
            OperationState::Failed | OperationState::Cancelled
        ) && !ended
        {
            // Missing receipt is never proof of no I/O or acknowledgment.
            return Err(ExecError::UnknownHandle);
        }
        Ok(())
    }
    /// Known receipt transfer is synchronous and holds the provider map lock
    /// through validation+removal. Core retains the historical correlation bytes.
    pub fn release_action(
        &self,
        permit: ProviderReleasePermit,
    ) -> Result<ProviderReleaseConfirmation, ExecError> {
        if permit.resource().is_some() || permit.actions().len() != 1 {
            return Err(ExecError::InvalidRequest);
        }
        let key = &permit.actions()[0];
        let mut actions = self.actions.lock().expect("actions mutex");
        self.validate_release_action(key, actions.get(&key.snapshot().id), false)?;
        actions.remove(&key.snapshot().id);
        Ok(permit.confirm_released())
    }
    /// Requires actual Host quiescence plus the linear Core ended/drained token.
    /// It removes an ended record as a whole, never clears input_unknown to make
    /// it appear settled. A rejected/cancelled future leaves Core release fenced.
    pub async fn release_resource(
        &self,
        permit: ProviderReleasePermit,
    ) -> Result<ProviderReleaseConfirmation, ExecError> {
        let key = permit.resource().ok_or(ExecError::InvalidRequest)?;
        let snapshot = key.snapshot();
        let resource = self
            .records
            .lock()
            .expect("records mutex")
            .values()
            .find(|r| r.handle.operation == snapshot.id)
            .cloned();
        if let Some(resource) = resource {
            if &resource.owner != key.owner() || resource.start_digest != snapshot.payload_digest {
                return Err(ExecError::OwnerMismatch);
            }
            let mut state = resource.state.clone().lock_owned().await;
            if state.retired
                || !state.drained
                || state.last_exit.is_none()
                || snapshot.liveness != ExecutionLiveness::Exited
                || snapshot.output_drain != OutputDrain::Drained
            {
                return Err(ExecError::ResourceUnsettled);
            }
            let mut actions = self.actions.lock().expect("actions mutex");
            if state.input_unknown.as_ref().is_some_and(|unknown| {
                !permit.actions().iter().any(|k| {
                    &k.snapshot().id == unknown && k.snapshot().state == OperationState::Unknown
                })
            }) {
                return Err(ExecError::ResourceUnsettled);
            }
            for action in permit.actions() {
                self.validate_release_action(action, actions.get(&action.snapshot().id), true)?;
            }
            // A provider record absent from the Core token must never be silently
            // deleted; it signals a mismatched supervisor or an in-flight action.
            if actions.values().any(|a| {
                a.receipt
                    .target
                    .as_ref()
                    .is_some_and(|t| t.operation_id == snapshot.id)
                    && !permit
                        .actions()
                        .iter()
                        .any(|k| k.snapshot().id == a.receipt.operation)
            }) {
                return Err(ExecError::ResourceUnsettled);
            }
            state.retired = true;
            for action in permit.actions() {
                actions.remove(&action.snapshot().id);
            }
            self.records
                .lock()
                .expect("records mutex")
                .remove(&resource.handle.process_id);
            self.operations
                .lock()
                .expect("operation mutex")
                .remove(&snapshot.id);
            self.rpc.unregister(&resource.handle.process_id);
        } else {
            // Only original strict pre-I/O refusal can confirm no resource was
            // created. An absent/unknown handle after a possible start is not exit.
            if snapshot.liveness != ExecutionLiveness::NotStarted
                || snapshot.output_drain != OutputDrain::NotOpened
                || snapshot.state != OperationState::Failed
                || self
                    .operations
                    .lock()
                    .expect("operation mutex")
                    .contains_key(&snapshot.id)
            {
                return Err(ExecError::ResourceUnsettled);
            }
            let mut actions = self.actions.lock().expect("actions mutex");
            for action in permit.actions() {
                self.validate_release_action(action, actions.get(&action.snapshot().id), true)?;
            }
            if actions.values().any(|a| {
                a.receipt
                    .target
                    .as_ref()
                    .is_some_and(|t| t.operation_id == snapshot.id)
                    && !permit
                        .actions()
                        .iter()
                        .any(|k| k.snapshot().id == a.receipt.operation)
            }) {
                return Err(ExecError::ResourceUnsettled);
            }
            for action in permit.actions() {
                actions.remove(&action.snapshot().id);
            }
        }
        Ok(permit.confirm_released())
    }
}
