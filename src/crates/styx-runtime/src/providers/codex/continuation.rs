//! Target-bound request-level actions within the same owned executor.
use super::*;
use styx_contracts::operation::ResourceTarget;

// Independent provider-local metadata allowance; not the Core retention budget.
// No payload bytes are retained. Core-attested audit transfer frees known
// receipts; uncertain receipts remain until ended-resource archival.
const ACTION_METADATA_BYTES: usize = 1024 * 1024;
const ACTION_ENTRY_ACCOUNTING_BYTES: usize = 4096;
const MAX_ACTIONS: usize = ACTION_METADATA_BYTES / ACTION_ENTRY_ACCOUNTING_BYTES;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProcessAction {
    WriteStdin { input_base64: String },
    Terminate {},
}
impl std::fmt::Debug for ProcessAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WriteStdin { input_base64 } => f
                .debug_struct("WriteStdin")
                .field("encoded_bytes", &input_base64.len())
                .finish(),
            Self::Terminate {} => f.write_str("Terminate"),
        }
    }
}
impl ProcessAction {
    pub fn to_operation_payload(&self) -> Result<Vec<u8>, ExecError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| ExecError::InvalidRequest)
    }
    fn validate(&self) -> Result<(), ExecError> {
        if let Self::WriteStdin { input_base64 } = self {
            if input_base64.len() > 4 * 65536usize.div_ceil(3) {
                return Err(ExecError::InvalidRequest);
            }
            let bytes = STANDARD
                .decode(input_base64)
                .map_err(|_| ExecError::InvalidRequest)?;
            if bytes.is_empty() || bytes.len() > 65536 || STANDARD.encode(&bytes) != *input_base64 {
                return Err(ExecError::InvalidRequest);
            }
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionEvidence {
    Acknowledged,
    NotDispatched,
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionAcknowledgment {
    WriteAccepted,
    /// Native process/terminate replied to the request. This is NOT exit proof.
    TerminateRequested {
        was_running: bool,
    },
}
#[derive(Debug, Clone)]
pub struct ActionReceipt {
    pub operation: OperationId,
    pub target: Option<ResourceTarget>,
    pub evidence: ActionEvidence,
    pub write_id: Option<String>,
    pub acknowledgment: Option<ActionAcknowledgment>,
    pub cause: Option<ExecError>,
}
pub(super) struct StoredAction {
    pub(super) native_process_uuid: String,
    pub(super) owner: OwnerLease,
    pub(super) payload_digest: Sha256Digest,
    pub(super) receipt: ActionReceipt,
}
pub(super) type ActionRecords = BTreeMap<OperationId, StoredAction>;

impl CodexStdio {
    /// Consume exactly the prepared stdin action; no independent input argument.
    pub async fn write(&self, permit: DispatchPermit, handle: &ProcessHandle) -> ActionReceipt {
        self.perform_action(permit, handle, true).await
    }
    /// Consume one terminate request. Observe target exit separately with read.
    pub async fn terminate(&self, permit: DispatchPermit, handle: &ProcessHandle) -> ActionReceipt {
        self.perform_action(permit, handle, false).await
    }
    /// Read-only reconciliation after a dropped/timed-out action future.
    /// The Core coordinator must still verify current owner authority.
    pub fn lookup_action(
        &self,
        owner: &OwnerLease,
        id: &OperationId,
    ) -> Result<ActionReceipt, ExecError> {
        let actions = self.actions.lock().expect("actions mutex");
        let action = actions.get(id).ok_or(ExecError::UnknownHandle)?;
        if &action.owner != owner {
            return Err(ExecError::OwnerMismatch);
        }
        Ok(action.receipt.clone())
    }
    async fn perform_action(
        &self,
        permit: DispatchPermit,
        handle: &ProcessHandle,
        write: bool,
    ) -> ActionReceipt {
        let mut receipt = ActionReceipt {
            operation: permit.id().clone(),
            target: permit.target().cloned(),
            evidence: ActionEvidence::NotDispatched,
            write_id: None,
            acknowledgment: None,
            cause: None,
        };
        let reject = |mut receipt: ActionReceipt, error| {
            receipt.cause = Some(error);
            receipt
        };
        if permit.context().capability != styx_contracts::capability::CapabilityId::ExecRun
            || permit.payload().len() > 131072
        {
            return reject(receipt, ExecError::InvalidRequest);
        }
        // Retained actions remain fenced even after their resource retires.
        // A reconstructed producer must not make an old operation fresh again.
        if let Some(stored) = self.actions.lock().expect("actions mutex").get(permit.id()) {
            if &stored.owner != permit.owner() {
                return reject(receipt, ExecError::OwnerMismatch);
            }
            if stored.payload_digest != Sha256Digest::of_bytes(permit.payload())
                || stored.receipt.target.as_ref() != permit.target()
            {
                return reject(receipt, ExecError::InvalidRequest);
            }
            // Existing acknowledgment/uncertainty is historical evidence, not
            // a new dispatch. Preserve it exactly; only annotate this lookup.
            return reject(stored.receipt.clone(), ExecError::AlreadyDispatched);
        }
        let action: ProcessAction = match serde_json::from_slice(permit.payload()) {
            Ok(action) => action,
            Err(_) => return reject(receipt, ExecError::InvalidRequest),
        };
        if let Err(e) = action.validate() {
            return reject(receipt, e);
        }
        if write != matches!(action, ProcessAction::WriteStdin { .. }) {
            return reject(receipt, ExecError::InvalidRequest);
        }
        let resource = {
            let records = self.records.lock().expect("records mutex");
            match records.get(&handle.process_id).cloned() {
                Some(r) => r,
                None => return reject(receipt, ExecError::UnknownHandle),
            }
        };
        if &resource.owner != permit.owner() || resource.handle != *handle {
            return reject(receipt, ExecError::OwnerMismatch);
        }
        if permit.target()
            != Some(&ResourceTarget {
                operation_id: handle.operation.clone(),
                payload_digest: resource.start_digest,
            })
        {
            return reject(receipt, ExecError::InvalidRequest);
        }
        {
            let mut actions = self.actions.lock().expect("actions mutex");
            if let Some(stored) = actions.get(permit.id()) {
                if &stored.owner != permit.owner() {
                    return reject(receipt, ExecError::OwnerMismatch);
                }
                if stored.payload_digest != Sha256Digest::of_bytes(permit.payload())
                    || stored.receipt.target.as_ref() != permit.target()
                {
                    return reject(receipt, ExecError::InvalidRequest);
                }
                return reject(stored.receipt.clone(), ExecError::AlreadyDispatched);
            }
            if actions.len() >= MAX_ACTIONS {
                return reject(receipt, ExecError::Capacity);
            }
            if write {
                receipt.write_id = Some(Uuid::new_v4().to_string());
            }
            receipt.evidence = ActionEvidence::Unknown;
            actions.insert(
                permit.id().clone(),
                StoredAction {
                    native_process_uuid: handle.process_id.clone(),
                    owner: permit.owner().clone(),
                    payload_digest: Sha256Digest::of_bytes(permit.payload()),
                    receipt: receipt.clone(),
                },
            );
        }
        // No mutation has happened yet. Dropping even this lock wait leaves a
        // conservative, queryable Unknown; it never permits a second action ID.
        let mut record = match self.owned(permit.owner(), handle).await {
            Ok(record) => record,
            Err(e) => {
                return self.finish_action(receipt, ActionEvidence::NotDispatched, None, Some(e));
            }
        };
        if write && record.input_unknown.is_some() {
            return self.finish_action(
                receipt,
                ActionEvidence::NotDispatched,
                None,
                Some(ExecError::InputUnknown),
            );
        }
        if record.last_exit.is_some() || record.drained {
            return self.finish_action(
                receipt,
                ActionEvidence::NotDispatched,
                None,
                Some(ExecError::InvalidRequest),
            );
        }
        if write {
            record.input_unknown = Some(permit.id().clone());
        }
        let (method, params) = match action {
            ProcessAction::WriteStdin { input_base64 } => (
                "process/write",
                json!({"processId":handle.process_id,
                "writeId":receipt.write_id,"chunk":input_base64}),
            ),
            ProcessAction::Terminate {} => {
                ("process/terminate", json!({"processId":handle.process_id}))
            }
        };
        let result = self.rpc.request(method, params).await;
        let (evidence, ack, cause) = match result {
            Ok(v) if write && v.get("status").and_then(Value::as_str) == Some("accepted") => (
                ActionEvidence::Acknowledged,
                Some(ActionAcknowledgment::WriteAccepted),
                None,
            ),
            Ok(v) if !write && v.get("running").and_then(Value::as_bool).is_some() => (
                ActionEvidence::Acknowledged,
                Some(ActionAcknowledgment::TerminateRequested {
                    was_running: v["running"].as_bool().unwrap(),
                }),
                None,
            ),
            Err(e @ (ExecError::NotSent | ExecError::Capacity | ExecError::InvalidRequest)) => {
                (ActionEvidence::NotDispatched, None, Some(e))
            }
            Err(e) => (ActionEvidence::Unknown, None, Some(e)),
            Ok(_) => (ActionEvidence::Unknown, None, Some(ExecError::InvalidFrame)),
        };
        if write
            && evidence != ActionEvidence::Unknown
            && record.input_unknown.as_ref() == Some(permit.id())
        {
            record.input_unknown = None;
        }
        self.finish_action(receipt, evidence, ack, cause)
    }
    fn finish_action(
        &self,
        mut receipt: ActionReceipt,
        evidence: ActionEvidence,
        ack: Option<ActionAcknowledgment>,
        cause: Option<ExecError>,
    ) -> ActionReceipt {
        receipt.evidence = evidence;
        receipt.acknowledgment = ack;
        receipt.cause = cause;
        if let Some(stored) = self
            .actions
            .lock()
            .expect("actions mutex")
            .get_mut(&receipt.operation)
        {
            stored.receipt = receipt.clone();
        }
        receipt
    }
}
