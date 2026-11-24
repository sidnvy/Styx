//! Styx-local Control v1. This is not an extension of public MCP tool arguments.
//! Claims are untrusted DTOs; endpoint policy and OS peer facts grant scope.
use crate::{
    error::{ErrorCategory, ErrorEnvelope},
    identity::*,
    operation::OperationId,
    session::SessionDescriptor,
};
use serde::{Deserialize, Serialize};

pub const CONTROL_PROTOCOL_VERSION: u16 = 1;
pub const MAX_RESPONSE_WAIT_MS: u32 = 35_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlScope {
    ManagementRead,
    ManagementMutation,
    AgentRegistration,
    ProviderDispatch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "method",
    content = "params",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ControlCall {
    ReadSnapshot,
    ReadTransaction {
        transaction_id: TransactionId,
    },
    CancelOperation {
        operation_id: OperationId,
    },
    /// A registration claim; never proof of a real authorized desktop session.
    RegisterSession {
        descriptor: SessionDescriptor,
    },
}
impl ControlCall {
    pub fn required_scope(&self) -> ControlScope {
        match self {
            Self::ReadSnapshot | Self::ReadTransaction { .. } => ControlScope::ManagementRead,
            Self::CancelOperation { .. } => ControlScope::ManagementMutation,
            Self::RegisterSession { .. } => ControlScope::AgentRegistration,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlRequest {
    pub protocol_version: u16,
    pub client_instance: AgentInstanceId,
    pub request_id: RequestId,
    /// Relative wait budget starts at server receipt, bounded by server policy.
    /// It never confirms cancellation or backend termination on expiry.
    pub timeout_ms: u32,
    pub call: ControlCall,
}
impl ControlRequest {
    pub fn validate(&self) -> Result<(), ErrorCategory> {
        if self.protocol_version != CONTROL_PROTOCOL_VERSION {
            return Err(ErrorCategory::ProtocolMismatch);
        }
        if self.timeout_ms == 0 || self.timeout_ms > MAX_RESPONSE_WAIT_MS {
            return Err(ErrorCategory::InvalidRequest);
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", content = "value", rename_all = "snake_case")]
pub enum ControlOutcome {
    Ok(serde_json::Value),
    Error(ErrorEnvelope),
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlResponse {
    pub protocol_version: u16,
    pub request_id: RequestId,
    pub outcome: ControlOutcome,
}
