use crate::{
    identity::{SessionGeneration, TransactionId},
    operation::OperationId,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCategory {
    NoGraphicalSession,
    SessionAmbiguous,
    SessionDisconnected,
    SessionLocked,
    CompositorRestarted,
    PermissionRequired,
    PermissionDenied,
    CapabilityUnsupported,
    StaleObservation,
    TargetNotFound,
    BrowserNotAttachable,
    OperationTimeout,
    ResultUnknown,
    Unauthorized,
    Busy,
    ProtocolMismatch,
    IntegrityFailure,
    StateConflict,
    StaleOperation,
    InvalidRequest,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Recovery {
    None,
    Reobserve,
    Rediscover,
    Reconnect,
    ReadTransaction,
    ExplicitAuthorization,
    ManualReview,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionCertainty {
    NotDispatched,
    Completed,
    Unknown,
}

/// Public text must be curated by the adapter; never serialize arbitrary stderr or secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorEnvelope {
    pub category: ErrorCategory,
    pub provider_code: Option<String>,
    pub stage: String,
    pub retry_class: Recovery,
    pub execution_certainty: ExecutionCertainty,
    pub operation_id: Option<OperationId>,
    pub transaction_id: Option<TransactionId>,
    pub generation: Option<SessionGeneration>,
    pub public_message: String,
}
