//! Pure native-state semantics. A valid DTO grants no OS, pairing or writer authority.
use styx_contracts::{management::DesiredStateCommit, native_management::*};
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NativeStateRuleError {
    #[error("native_marker_invalid")]
    InvalidMarker,
    #[error("native_state_invalid")]
    InvalidState,
    #[error("native_transition_invalid")]
    InvalidTransition,
    #[error("native_extensions_changed")]
    ChangedExtensions,
}
pub fn validate_marker(marker: &NativeRootMarker) -> Result<(), NativeStateRuleError> {
    if marker.schema != NATIVE_MARKER_SCHEMA {
        return Err(NativeStateRuleError::InvalidMarker);
    }
    Ok(())
}
pub fn validate_state(
    state: &NativeState,
    marker: &NativeRootMarker,
) -> Result<(), NativeStateRuleError> {
    validate_marker(marker)?;
    if state.schema != NATIVE_STATE_SCHEMA || state.scope_generation != marker.scope_generation {
        return Err(NativeStateRuleError::InvalidState);
    }
    runtime_update::validate_runtime_state(state)?;
    match (state.revision, state.last_transaction.as_ref()) {
        (0, None) => (),
        (1.., Some(tx)) if tx.sequence > 0 => (),
        _ => return Err(NativeStateRuleError::InvalidState),
    }
    match state.mode {
        NativeDeploymentMode::CreateLocal if state.desired.gateway.is_none() => {
            return Err(NativeStateRuleError::InvalidState);
        }
        NativeDeploymentMode::JoinExisting
            if state.desired.gateway.is_some() || state.desired.host.is_none() =>
        {
            return Err(NativeStateRuleError::InvalidState);
        }
        _ => (),
    }
    for component in state
        .desired
        .gateway
        .iter()
        .chain(state.desired.host.iter())
    {
        if (component.manager == NativeManager::ForegroundCli
            && component.autostart == NativeAutostartDesired::Enabled)
            || (component.manager == NativeManager::PersistentService
                && !matches!(marker.root_identity, NativeRootIdentity::Linux { .. }))
        {
            return Err(NativeStateRuleError::InvalidState);
        }
    }
    Ok(())
}
pub fn validate_transition(
    before: &NativeState,
    target: &NativeState,
    marker: &NativeRootMarker,
    intent: &DesiredStateCommit,
) -> Result<(), NativeStateRuleError> {
    validate_state(before, marker)?;
    validate_state(target, marker)?;
    let Some(tx) = target.last_transaction.as_ref() else {
        return Err(NativeStateRuleError::InvalidTransition);
    };
    if intent.validate().is_err()
        || target.revision
            != before
                .revision
                .checked_add(1)
                .ok_or(NativeStateRuleError::InvalidTransition)?
        || target.schema != before.schema
        || target.mode != before.mode
        || target.deployment_raw_sha256 != before.deployment_raw_sha256
        || target.deployment_raw_sha256 != intent.deployment_raw_sha256
        || tx.transaction_id != intent.transaction_id
        || tx.sequence != intent.sequence
        || before
            .last_transaction
            .as_ref()
            .is_some_and(|prior| tx.sequence <= prior.sequence)
        || before.desired.gateway.is_some() != target.desired.gateway.is_some()
        || before.desired.host.is_some() != target.desired.host.is_some()
    {
        return Err(NativeStateRuleError::InvalidTransition);
    }
    if !before.extensions_preserved_in(target) {
        return Err(NativeStateRuleError::ChangedExtensions);
    }
    Ok(())
}

/// Runtime policy compatibility for a committed metadata-only successor. This
/// predicate is not journal, writer, or OS-service authority. Callers must also
/// validate the complete original C07 chain and every intermediate transition.
pub fn autostart_only_compatible(before: &NativeState, target: &NativeState) -> bool {
    runtime_policy_compatible(before, target, false)
}
/// A service may observe another role's run request without stopping itself.
/// Its own Stopped request MUST withdraw admission and initiate owned cleanup;
/// compatibility alone is never proof of actual process or executor settlement.
pub fn service_desired_compatible(before: &NativeState, target: &NativeState) -> bool {
    runtime_policy_compatible(before, target, true)
}
fn runtime_policy_compatible(before: &NativeState, target: &NativeState, follow_run: bool) -> bool {
    fn role(
        a: Option<NativeComponentDesired>,
        b: Option<NativeComponentDesired>,
        follow_run: bool,
    ) -> bool {
        match (a, b) {
            (None, None) => true,
            (Some(a), Some(b)) => {
                a.manager == b.manager
                    && (a.run == b.run
                        || (follow_run && a.manager == NativeManager::PersistentService))
                    && (a.autostart == b.autostart || a.manager == NativeManager::PersistentService)
            }
            _ => false,
        }
    }
    before.schema == target.schema
        && before.kind == target.kind
        && before.runtime_format == target.runtime_format
        && before.scope_generation == target.scope_generation
        && before.deployment_raw_sha256 == target.deployment_raw_sha256
        && before.mode == target.mode
        && before.extensions_preserved_in(target)
        && role(before.desired.host, target.desired.host, follow_run)
        && role(before.desired.gateway, target.desired.gateway, follow_run)
}

#[path = "runtime_update.rs"]
mod runtime_update;
pub use runtime_update::{validate_committed_transition, validate_runtime_transition};
