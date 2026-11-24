//! Physical termination of the original daemon is separate from session ACK.
use super::CuaNativeSettlement;
use crate::store::{ProcessIdentity, StoreError};
use tokio_util::sync::CancellationToken;

pub(super) fn resource_stop_tokens() -> (CancellationToken, CancellationToken) {
    // Independent lifetimes: stopping business admission must leave its
    // original transport alive long enough to finish native session cleanup.
    (CancellationToken::new(), CancellationToken::new())
}

pub(super) async fn wait_cleanup_request(
    host_stop: &CancellationToken,
    business_stop: &CancellationToken,
    transport_stop: &CancellationToken,
) {
    tokio::select! {
        _ = host_stop.cancelled() => {},
        _ = business_stop.cancelled() => {},
        _ = transport_stop.cancelled() => {},
    }
    business_stop.cancel();
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EndSessionOutcome {
    Ended,
    RetryKnown,
    Unknown,
}

fn end_session_outcome(session: &str, reply: &rmcp::model::CallToolResult) -> EndSessionOutcome {
    let Some(value) = reply.structured_content.as_ref() else {
        return EndSessionOutcome::Unknown;
    };
    if value.get("session").and_then(serde_json::Value::as_str) != Some(session) {
        return EndSessionOutcome::Unknown;
    }
    if reply.is_error != Some(true) && value.get("active") == Some(&serde_json::Value::Bool(false))
    {
        return EndSessionOutcome::Ended;
    }
    if reply.is_error == Some(true)
        && value.get("cleanup_complete") == Some(&serde_json::Value::Bool(false))
        && matches!(
            (
                value.get("code").and_then(serde_json::Value::as_str),
                value
                    .get("cleanup_in_progress")
                    .and_then(serde_json::Value::as_bool)
            ),
            (Some("session_cleanup_pending"), Some(true))
                | (Some("session_cleanup_partial"), Some(false))
        )
    {
        EndSessionOutcome::RetryKnown
    } else {
        EndSessionOutcome::Unknown
    }
}

pub(super) async fn end_session(
    peer: rmcp::Peer<rmcp::RoleClient>,
    session: String,
) -> EndSessionOutcome {
    let arguments = serde_json::json!({"session":session})
        .as_object()
        .expect("literal object")
        .clone();
    let request = rmcp::model::CallToolRequestParams::new("end_session").with_arguments(arguments);
    match peer.call_tool(request).await {
        Ok(reply) => end_session_outcome(&session, &reply),
        Err(_) => EndSessionOutcome::Unknown,
    }
}

pub(super) fn original_daemon_ended(identity: &ProcessIdentity) -> Result<bool, StoreError> {
    ended_from_observation(identity.still_current())
}

fn ended_from_observation<E>(observation: Result<bool, E>) -> Result<bool, E> {
    // still_current distinguishes a confirmed departed birth from an unreadable
    // process. Never collapse permission/observation errors into absence.
    observation.map(|current| !current)
}

pub(super) fn proxy_native_settlement(
    session_started: bool,
    session_ended: bool,
    daemon_ended: bool,
    proxy_exited: bool,
    proxy_success: Option<bool>,
) -> CuaNativeSettlement {
    if daemon_ended {
        CuaNativeSettlement::MacOriginalDaemonExited
    } else {
        CuaNativeSettlement::MacAppTransport {
            drained: (!session_started || session_ended)
                && proxy_exited
                && proxy_success == Some(true),
        }
    }
}

#[cfg(test)]
#[path = "macos_cleanup_tests.rs"]
mod tests;
