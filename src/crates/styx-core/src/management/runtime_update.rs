//! Pure C07 runtime-update grammar. This validates data, never C08 trust,
//! process settlement, a writer lease, or permission to execute a selected image.
use super::{NativeStateRuleError, validate_state, validate_transition};
use styx_contracts::{
    management::{DesiredStateCommit, ReaderContract},
    native_management::*,
};

type Result<T> = std::result::Result<T, NativeStateRuleError>;
fn invalid() -> NativeStateRuleError {
    NativeStateRuleError::InvalidTransition
}
fn selection(state: &NativeState) -> Result<NativeRuntimeSelection> {
    state
        .runtime_selection()
        .map_err(|_| invalid())?
        .ok_or_else(invalid)
}
fn record(state: &NativeState) -> Result<NativeRuntimeUpdate> {
    state
        .runtime_update()
        .map_err(|_| invalid())?
        .ok_or_else(invalid)
}
fn valid_selection(value: &NativeRuntimeSelection) -> bool {
    // Platform-specific locator/owner/target checks belong to the native store.
    value.schema == 1
        && !value.payload_path.is_empty()
        && value.payload_path.len() <= 4096
        && !value.publisher_file.is_empty()
        && value.publisher_file.len() <= 4096
        && !value.payload_path.contains('\0')
        && !value.publisher_file.contains('\0')
}
pub(super) fn validate_selected_state(state: &NativeState) -> Result<()> {
    let current = selection(state)?;
    let update = record(state)?;
    if state.schema != NATIVE_RUNTIME_SELECTED_STATE_SCHEMA
        || state.migration.is_some()
        || state.extensions.contains_key(NATIVE_MIGRATION_V2_KEY)
        || state.revision == 0
        || update.schema != 1
        || update.transaction.sequence == 0
        || state
            .last_transaction
            .as_ref()
            .is_none_or(|last| last.sequence < update.transaction.sequence)
        || !valid_selection(&current)
        || !valid_selection(&update.previous_runtime)
        || !valid_selection(&update.bootstrap_runtime)
        || current.publisher_spki_sha256 != update.bootstrap_runtime.publisher_spki_sha256
        || current.publisher_spki_sha256 != update.previous_runtime.publisher_spki_sha256
    {
        return Err(NativeStateRuleError::InvalidState);
    }
    Ok(())
}
/// History reader only. A generic desired-state writer must use
/// `validate_transition`, which cannot manufacture a runtime update.
pub fn validate_committed_transition(
    before: &NativeState,
    target: &NativeState,
    marker: &NativeRootMarker,
    intent: &DesiredStateCommit,
) -> Result<()> {
    validate_transition(before, target, marker, intent)
        .or_else(|_| validate_runtime_transition(before, target, marker, intent))
}
/// Closed fresh-root, stopped foreground transition. Callers must retain the
/// original writer/execution exclusion and both verified C08 releases as well.
pub fn validate_runtime_transition(
    before: &NativeState,
    target: &NativeState,
    marker: &NativeRootMarker,
    intent: &DesiredStateCommit,
) -> Result<()> {
    validate_state(before, marker)?;
    validate_state(target, marker)?;
    let current = selection(before)?;
    let next = selection(target)?;
    let update = record(target)?;
    let transaction = target.last_transaction.as_ref().ok_or_else(invalid)?;
    if marker.reader_floor != ReaderContract::NativeManagementStateV1
        || !matches!(
            before.reader_contract,
            ReaderContract::NativeManagementStateV1 | ReaderContract::NativeRuntimeSelectedStateV1
        )
        || target.reader_contract != ReaderContract::NativeRuntimeSelectedStateV1
        || target.schema != NATIVE_RUNTIME_SELECTED_STATE_SCHEMA
        || before.has_migration_binding()
        || target.has_migration_binding()
        || before.extensions.contains_key(NATIVE_MIGRATION_V2_KEY)
        || intent.validate().is_err()
        || target.revision != before.revision.checked_add(1).ok_or_else(invalid)?
        || before.mode != target.mode
        || before.desired != target.desired
        || before.deployment_raw_sha256 != target.deployment_raw_sha256
        || target.deployment_raw_sha256 != intent.deployment_raw_sha256
        || intent.reader != target.reader_contract
        || transaction.transaction_id != intent.transaction_id
        || transaction.sequence != intent.sequence
        || before
            .last_transaction
            .as_ref()
            .is_some_and(|last| last.sequence >= transaction.sequence)
        || update.transaction != *transaction
        || update.previous_runtime != current
        || next == current
        || before
            .desired
            .host
            .iter()
            .chain(before.desired.gateway.iter())
            .any(|role| {
                role.manager != NativeManager::ForegroundCli
                    || role.run != NativeRunDesired::Stopped
                    || role.autostart != NativeAutostartDesired::Disabled
            })
    {
        return Err(invalid());
    }
    let bootstrap = match before.reader_contract {
        ReaderContract::NativeManagementStateV1 => {
            if before.extensions.contains_key(NATIVE_RUNTIME_UPDATE_KEY) {
                return Err(invalid());
            }
            current
        }
        ReaderContract::NativeRuntimeSelectedStateV1 => record(before)?.bootstrap_runtime,
        _ => return Err(invalid()),
    };
    if update.bootstrap_runtime != bootstrap {
        return Err(invalid());
    }
    let retained = |key: &str| {
        !matches!(
            key,
            NATIVE_RUNTIME_SELECTION_KEY | NATIVE_RUNTIME_UPDATE_KEY
        )
    };
    if before
        .extensions
        .iter()
        .filter(|(key, _)| retained(key))
        .count()
        != target
            .extensions
            .iter()
            .filter(|(key, _)| retained(key))
            .count()
        || before
            .extensions
            .iter()
            .filter(|(key, _)| retained(key))
            .any(|(key, raw)| {
                target
                    .extensions
                    .get(key)
                    .is_none_or(|other| raw.get().as_bytes() != other.get().as_bytes())
            })
    {
        return Err(NativeStateRuleError::ChangedExtensions);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use styx_contracts::identity::Sha256Digest;
    fn selection_at(name: &str) -> NativeRuntimeSelection {
        NativeRuntimeSelection {
            schema: 1,
            payload_path: format!("/private/{name}/payload"),
            payload_root: NativeRootIdentity::Linux {
                device: 1,
                inode: if name == "old" { 2 } else { 3 },
                uid: 1000,
            },
            manifest_sha256: Sha256Digest::of_bytes(name.as_bytes()),
            publisher_file: format!("/private/{name}/publisher.pem"),
            publisher_spki_sha256: Sha256Digest::of_bytes(b"original publisher"),
        }
    }
    fn fixture() -> (NativeRootMarker, NativeState) {
        let marker = NativeRootMarker {
            schema: 1,
            kind: NativeRootKind::StyxConfigurationRoot,
            runtime_format: NativeRuntimeFormat::NativeRustV1,
            root_identity: NativeRootIdentity::Linux {
                device: 1,
                inode: 4,
                uid: 1000,
            },
            scope_generation: Sha256Digest::of_bytes(b"scope"),
            reader_floor: ReaderContract::NativeManagementStateV1,
        };
        let state = NativeState {
            schema: 2,
            kind: NativeStateKind::StyxDesiredState,
            runtime_format: NativeRuntimeFormat::NativeRustV1,
            reader_contract: ReaderContract::NativeManagementStateV1,
            scope_generation: marker.scope_generation,
            deployment_raw_sha256: Sha256Digest::of_bytes(b"deployment"),
            mode: NativeDeploymentMode::JoinExisting,
            revision: 0,
            last_transaction: None,
            desired: NativeDesired {
                gateway: None,
                host: Some(NativeComponentDesired {
                    manager: NativeManager::ForegroundCli,
                    run: NativeRunDesired::Stopped,
                    autostart: NativeAutostartDesired::Disabled,
                }),
            },
            migration: None,
            extensions: BTreeMap::from([
                (
                    NATIVE_RUNTIME_SELECTION_KEY.into(),
                    serde_json::value::to_raw_value(&selection_at("old")).unwrap(),
                ),
                (
                    "preserve".into(),
                    serde_json::value::RawValue::from_string(
                        "{\"large\":900719925474099312345,\"number\":1e999}".into(),
                    )
                    .unwrap(),
                ),
            ]),
        };
        (marker, state)
    }
    fn update(
        before: &NativeState,
        next: NativeRuntimeSelection,
        seq: u64,
    ) -> (NativeState, DesiredStateCommit) {
        let mut target = before.clone();
        target.schema = 3;
        target.reader_contract = ReaderContract::NativeRuntimeSelectedStateV1;
        target.revision += 1;
        let transaction = NativeStateTransaction {
            transaction_id: format!("update-{seq}").try_into().unwrap(),
            sequence: seq,
        };
        target.last_transaction = Some(transaction.clone());
        let previous = selection(before).unwrap();
        let bootstrap = before
            .runtime_update()
            .unwrap()
            .map(|v| v.bootstrap_runtime)
            .unwrap_or_else(|| previous.clone());
        target.extensions.insert(
            NATIVE_RUNTIME_SELECTION_KEY.into(),
            serde_json::value::to_raw_value(&next).unwrap(),
        );
        target.extensions.insert(
            NATIVE_RUNTIME_UPDATE_KEY.into(),
            serde_json::value::to_raw_value(&NativeRuntimeUpdate {
                schema: 1,
                bootstrap_runtime: bootstrap,
                previous_runtime: previous,
                transaction: transaction.clone(),
            })
            .unwrap(),
        );
        let intent = DesiredStateCommit {
            transaction_id: transaction.transaction_id,
            sequence: seq,
            deployment_raw_sha256: target.deployment_raw_sha256,
            before_state_sha256: Sha256Digest::of_bytes(&serde_json::to_vec(before).unwrap()),
            target_state_sha256: Sha256Digest::of_bytes(&serde_json::to_vec(&target).unwrap()),
            reader: target.reader_contract,
        };
        (target, intent)
    }
    #[test]
    fn typed_promotion_and_forward_rollback_preserve_authority_boundaries() {
        let (marker, before) = fixture();
        let (target, intent) = update(&before, selection_at("new"), 1);
        assert!(validate_runtime_transition(&before, &target, &marker, &intent).is_ok());
        assert!(validate_transition(&before, &target, &marker, &intent).is_err());
        assert!(validate_committed_transition(&before, &target, &marker, &intent).is_ok());
        let (rollback, rollback_intent) = update(&target, selection_at("old"), 2);
        assert!(validate_runtime_transition(&target, &rollback, &marker, &rollback_intent).is_ok());
        assert_eq!(
            rollback.reader_contract,
            ReaderContract::NativeRuntimeSelectedStateV1
        );
        assert_eq!(rollback.schema, 3);
        assert!(validate_committed_transition(&rollback, &before, &marker, &intent).is_err());
        for mutate in [
            |state: &mut NativeState| {
                state.desired.host.as_mut().unwrap().run = NativeRunDesired::Running;
            },
            |state: &mut NativeState| {
                state.desired.host.as_mut().unwrap().manager = NativeManager::AppManaged;
            },
            |state: &mut NativeState| {
                state.extensions.insert(
                    "preserve".into(),
                    serde_json::value::to_raw_value(&0).unwrap(),
                );
            },
        ] {
            let mut changed = before.clone();
            mutate(&mut changed);
            assert!(validate_runtime_transition(&changed, &target, &marker, &intent).is_err());
        }
        let mut wrong_publisher = selection_at("foreign");
        wrong_publisher.publisher_spki_sha256 = Sha256Digest::of_bytes(b"unapproved");
        let (foreign, foreign_intent) = update(&before, wrong_publisher, 1);
        assert!(validate_runtime_transition(&before, &foreign, &marker, &foreign_intent).is_err());
        let mut unbound = before.clone();
        unbound.schema = 3;
        unbound.reader_contract = ReaderContract::NativeRuntimeSelectedStateV1;
        assert!(validate_state(&unbound, &marker).is_err());
    }
}
