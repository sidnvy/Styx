//! Shared conversion from Core/provider evidence to the private Host contract.
use super::{coordinator::CoordinatorError, protocol::wire::*};
#[cfg(not(target_os = "android"))]
use crate::providers::codex::{ActionAcknowledgment, ActionEvidence, ActionReceipt};
use styx_contracts::error::{ErrorCategory, ExecutionCertainty};
#[cfg(not(target_os = "android"))]
use styx_core::operations::OperationSnapshot;
#[cfg(not(target_os = "android"))]
pub(crate) fn action_reply(
    snapshot: OperationSnapshot,
    receipt: Option<ActionReceipt>,
    existing: bool,
) -> Reply {
    let dispatch = if existing {
        "existing_no_replay"
    } else {
        match receipt.as_ref().map(|r| r.evidence) {
            Some(ActionEvidence::Acknowledged) => "acknowledged",
            Some(ActionEvidence::NotDispatched) => "not_dispatched",
            Some(ActionEvidence::Unknown) | None => "unknown",
        }
    };
    let acknowledgment = receipt
        .as_ref()
        .and_then(|r| r.acknowledgment.as_ref())
        .map(|ack| match ack {
            ActionAcknowledgment::WriteAccepted => ActionAcknowledgmentDto::WriteAccepted,
            ActionAcknowledgment::TerminateRequested { was_running } => {
                ActionAcknowledgmentDto::TerminateRequested {
                    was_running: *was_running,
                }
            }
        });
    Reply::Action {
        snapshot: snapshot.into(),
        dispatch: dispatch.into(),
        acknowledgment,
        write_id: receipt.and_then(|r| r.write_id),
    }
}
pub(crate) fn invalid() -> Reply {
    rejection(ErrorCategory::InvalidRequest)
}
pub(crate) fn rejection(category: ErrorCategory) -> Reply {
    Reply::Error {
        category,
        certainty: ExecutionCertainty::NotDispatched,
        cursor_may_be_consumed: false,
    }
}
pub(crate) fn coordinator_error(error: CoordinatorError, read: bool) -> Reply {
    let (category, certainty) = match error {
        CoordinatorError::Admission(category) => (category, ExecutionCertainty::NotDispatched),
        CoordinatorError::Busy => (ErrorCategory::Busy, ExecutionCertainty::NotDispatched),
        CoordinatorError::OutputDeliveryDenied(category) => (category, ExecutionCertainty::Unknown),
        CoordinatorError::ReadDeadline => {
            (ErrorCategory::OperationTimeout, ExecutionCertainty::Unknown)
        }
        #[cfg(not(target_os = "android"))]
        CoordinatorError::Executor(crate::providers::codex::ExecError::Capacity) if read => {
            // A decoded read buffer is reserved before any native request or
            // cursor advance. A saturated caller may wait without poisoning it.
            (ErrorCategory::Busy, ExecutionCertainty::NotDispatched)
        }
        CoordinatorError::ResponseLost => {
            (ErrorCategory::ResultUnknown, ExecutionCertainty::Unknown)
        }
        #[cfg(not(target_os = "android"))]
        CoordinatorError::Executor(_) => {
            (ErrorCategory::ResultUnknown, ExecutionCertainty::Unknown)
        }
        // An executor error crossing the shared boundary carries no proof that a
        // native dispatch did not happen; preserve uncertainty.
        #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
        CoordinatorError::Browser(_) => (ErrorCategory::ResultUnknown, ExecutionCertainty::Unknown),
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        CoordinatorError::Desktop(error) => match error {
            crate::providers::cua::CuaError::Busy => {
                (ErrorCategory::Busy, ExecutionCertainty::NotDispatched)
            }
            crate::providers::cua::CuaError::InvalidRequest => (
                ErrorCategory::InvalidRequest,
                ExecutionCertainty::NotDispatched,
            ),
            crate::providers::cua::CuaError::PermissionDenied => (
                ErrorCategory::PermissionDenied,
                ExecutionCertainty::NotDispatched,
            ),
            crate::providers::cua::CuaError::Unsupported => (
                ErrorCategory::CapabilityUnsupported,
                ExecutionCertainty::NotDispatched,
            ),
            _ => (ErrorCategory::ResultUnknown, ExecutionCertainty::Unknown),
        },
    };
    Reply::Error {
        category,
        certainty,
        cursor_may_be_consumed: read && certainty != ExecutionCertainty::NotDispatched,
    }
}
