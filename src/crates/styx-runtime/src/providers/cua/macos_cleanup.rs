//! Physical termination of the original daemon is separate from session ACK.
use super::CuaNativeSettlement;
use crate::store::{ProcessIdentity, StoreError};

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
