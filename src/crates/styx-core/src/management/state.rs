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
    if state.schema != NATIVE_STATE_SCHEMA
        || state.scope_generation != marker.scope_generation
        || state.reader_contract != marker.reader_floor
    {
        return Err(NativeStateRuleError::InvalidState);
    }
    let migration_v2 = state
        .migration_v2()
        .map_err(|_| NativeStateRuleError::InvalidState)?;
    match (&state.migration, state.reader_contract) {
        (None, styx_contracts::management::ReaderContract::NativeManagementStateV1) => (),
        (Some(migration), styx_contracts::management::ReaderContract::NativeMigratedStateV1)
            if state.revision > 0
                && migration.original_token_relative_path
                    == format!(
                        "device/.styx-retired-host-token-{}",
                        migration.transaction_id.as_str()
                    ) => {}
        (None, styx_contracts::management::ReaderContract::NativeMigratedStateV2) => {
            let migration = migration_v2
                .as_ref()
                .ok_or(NativeStateRuleError::InvalidState)?;
            if migration.schema != 2
                || state.revision == 0
                || migration.root_identity != marker.root_identity
                || migration.original_token_relative_path
                    != format!(
                        "device/.styx-retired-host-token-{}",
                        migration.transaction_id.as_str()
                    )
            {
                return Err(NativeStateRuleError::InvalidState);
            }
            match (&migration.history, migration.endpoint_mode, state.mode) {
                (
                    NativeMigrationHistory::PreservedHostPair {
                        source_bindings_sha256,
                    },
                    NativeMigrationEndpointMode::PreservedRemote,
                    NativeDeploymentMode::JoinExisting,
                ) if state.desired.gateway.is_none()
                    && state.desired.host.is_some()
                    && *source_bindings_sha256 == migration.host_pair_sha256 => {}
                (
                    NativeMigrationHistory::ImportedLocalGateway { .. },
                    NativeMigrationEndpointMode::IssuedLocal,
                    NativeDeploymentMode::CreateLocal,
                ) if state.desired.gateway.is_some() => {}
                _ => return Err(NativeStateRuleError::InvalidState),
            }
        }
        _ => return Err(NativeStateRuleError::InvalidState),
    }
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
        if component.manager == NativeManager::ForegroundCli
            && component.autostart == NativeAutostartDesired::Enabled
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
        || target.mode != before.mode
        || target.migration != before.migration
        || target.deployment_raw_sha256 != before.deployment_raw_sha256
        || target.deployment_raw_sha256 != intent.deployment_raw_sha256
        || target.reader_contract != intent.reader
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
