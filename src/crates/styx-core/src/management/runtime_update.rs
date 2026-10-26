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
    let expected_schema = match state.reader_contract {
        ReaderContract::NativeRuntimeSelectedStateV1 => NATIVE_RUNTIME_SELECTED_STATE_SCHEMA,
        ReaderContract::NativeAppRuntimeSelectedStateV1 => {
            // App history is a separate reader contract, never a foreground-reader extension.
            if state.desired.host.is_some() == state.desired.gateway.is_some()
                || state
                    .desired
                    .host
                    .iter()
                    .chain(state.desired.gateway.iter())
                    .any(|role| {
                        role.manager != NativeManager::AppManaged
                            || role.autostart != NativeAutostartDesired::Disabled
                    })
            {
                return Err(NativeStateRuleError::InvalidState);
            }
            NATIVE_APP_RUNTIME_SELECTED_STATE_SCHEMA
        }
        ReaderContract::NativeServiceRuntimeSelectedStateV1 => {
            if state.mode != NativeDeploymentMode::CreateLocal
                || state.desired.host.is_some()
                || state
                    .desired
                    .gateway
                    .as_ref()
                    .is_none_or(|role| role.manager != NativeManager::PersistentService)
            {
                return Err(NativeStateRuleError::InvalidState);
            }
            NATIVE_SERVICE_RUNTIME_SELECTED_STATE_SCHEMA
        }
        _ => return Err(NativeStateRuleError::InvalidState),
    };
    if state.schema != expected_schema
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
        .or_else(|_| validate_app_runtime_transition(before, target, marker, intent))
        .or_else(|_| validate_service_runtime_repair_transition(before, target, marker, intent))
}
/// Closed fresh-root, stopped foreground transition. Callers must retain the
/// original writer/execution exclusion and both verified C08 releases as well.
pub fn validate_runtime_transition(
    before: &NativeState,
    target: &NativeState,
    marker: &NativeRootMarker,
    intent: &DesiredStateCommit,
) -> Result<()> {
    validate_selection_transition(
        before,
        target,
        marker,
        intent,
        NativeManager::ForegroundCli,
        ReaderContract::NativeRuntimeSelectedStateV1,
        NATIVE_RUNTIME_SELECTED_STATE_SCHEMA,
    )
}
/// Pure App update grammar. Only a retained native App scope can authorize its
/// publication; neither this function nor decoded state grants that scope.
pub fn validate_app_runtime_transition(
    before: &NativeState,
    target: &NativeState,
    marker: &NativeRootMarker,
    intent: &DesiredStateCommit,
) -> Result<()> {
    validate_selection_transition(
        before,
        target,
        marker,
        intent,
        NativeManager::AppManaged,
        ReaderContract::NativeAppRuntimeSelectedStateV1,
        NATIVE_APP_RUNTIME_SELECTED_STATE_SCHEMA,
    )
}
/// Pure history grammar for explicitly repairing a failed registered Gateway.
/// Native publication also requires the original non-deserializable registration
/// proof, writer/operation/execution exclusion and both original signed releases.
/// Running/Enabled is only the requested post-installer intent, never readiness.
pub fn validate_service_runtime_repair_transition(
    before: &NativeState,
    target: &NativeState,
    marker: &NativeRootMarker,
    intent: &DesiredStateCommit,
) -> Result<()> {
    let NativeRootIdentity::Macos { uid, .. } = marker.root_identity else {
        return Err(invalid());
    };
    if uid == 0
        || before.mode != NativeDeploymentMode::CreateLocal
        || before.desired.host.is_some()
        || target.desired.host.is_some()
        || target.desired.gateway
            != Some(NativeComponentDesired {
                manager: NativeManager::PersistentService,
                run: NativeRunDesired::Running,
                autostart: NativeAutostartDesired::Enabled,
            })
    {
        return Err(invalid());
    }
    for value in [
        selection(before)?,
        selection(target)?,
        record(target)?.bootstrap_runtime,
    ] {
        if !matches!(value.payload_root, NativeRootIdentity::Macos { uid: owner, .. } if owner == uid)
        {
            return Err(invalid());
        }
    }
    validate_selection_transition(
        before,
        target,
        marker,
        intent,
        NativeManager::PersistentService,
        ReaderContract::NativeServiceRuntimeSelectedStateV1,
        NATIVE_SERVICE_RUNTIME_SELECTED_STATE_SCHEMA,
    )
}
fn validate_selection_transition(
    before: &NativeState,
    target: &NativeState,
    marker: &NativeRootMarker,
    intent: &DesiredStateCommit,
    manager: NativeManager,
    reader: ReaderContract,
    schema: u16,
) -> Result<()> {
    validate_state(before, marker)?;
    validate_state(target, marker)?;
    let current = selection(before)?;
    let next = selection(target)?;
    let update = record(target)?;
    let transaction = target.last_transaction.as_ref().ok_or_else(invalid)?;
    let service_repair = manager == NativeManager::PersistentService;
    let mut expected_desired = before.desired.clone();
    if service_repair {
        let gateway = expected_desired.gateway.as_mut().ok_or_else(invalid)?;
        gateway.run = NativeRunDesired::Running;
        gateway.autostart = NativeAutostartDesired::Enabled;
    }
    if marker.reader_floor != ReaderContract::NativeManagementStateV1
        || (before.reader_contract != ReaderContract::NativeManagementStateV1
            && before.reader_contract != reader
            && !(service_repair
                && before.reader_contract == ReaderContract::NativeRuntimeSelectedStateV1))
        || target.reader_contract != reader
        || target.schema != schema
        || before.has_migration_binding()
        || target.has_migration_binding()
        || before.extensions.contains_key(NATIVE_MIGRATION_V2_KEY)
        || intent.validate().is_err()
        || target.revision != before.revision.checked_add(1).ok_or_else(invalid)?
        || before.mode != target.mode
        || expected_desired != target.desired
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
                role.manager != manager
                    || role.run != NativeRunDesired::Stopped
                    || role.autostart != NativeAutostartDesired::Disabled
            })
    {
        return Err(invalid());
    }
    let bootstrap = if before.reader_contract == ReaderContract::NativeManagementStateV1 {
        if before.extensions.contains_key(NATIVE_RUNTIME_UPDATE_KEY) {
            return Err(invalid());
        }
        current
    } else if before.reader_contract == reader
        || (service_repair
            && before.reader_contract == ReaderContract::NativeRuntimeSelectedStateV1)
    {
        record(before)?.bootstrap_runtime
    } else {
        return Err(invalid());
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
        let app = before
            .desired
            .host
            .is_some_and(|role| role.manager == NativeManager::AppManaged);
        let service = before
            .desired
            .gateway
            .is_some_and(|role| role.manager == NativeManager::PersistentService);
        target.schema = if service {
            NATIVE_SERVICE_RUNTIME_SELECTED_STATE_SCHEMA
        } else if app {
            NATIVE_APP_RUNTIME_SELECTED_STATE_SCHEMA
        } else {
            NATIVE_RUNTIME_SELECTED_STATE_SCHEMA
        };
        target.reader_contract = if service {
            let role = target.desired.gateway.as_mut().unwrap();
            role.run = NativeRunDesired::Running;
            role.autostart = NativeAutostartDesired::Enabled;
            ReaderContract::NativeServiceRuntimeSelectedStateV1
        } else if app {
            ReaderContract::NativeAppRuntimeSelectedStateV1
        } else {
            ReaderContract::NativeRuntimeSelectedStateV1
        };
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
    #[test]
    fn failed_service_repair_has_a_distinct_reader_and_cannot_adopt_other_roles() {
        use styx_contracts::native_release::NativeReleaseReader;
        let (mut marker, mut before) = fixture();
        marker.root_identity = NativeRootIdentity::Macos {
            device: 1,
            inode: 4,
            uid: 501,
        };
        before.mode = NativeDeploymentMode::CreateLocal;
        let mut gateway = before.desired.host.take().unwrap();
        gateway.manager = NativeManager::PersistentService;
        before.desired.gateway = Some(gateway);
        let mut old = selection_at("old");
        old.payload_root = NativeRootIdentity::Macos {
            device: 1,
            inode: 2,
            uid: 501,
        };
        before.extensions.insert(
            NATIVE_RUNTIME_SELECTION_KEY.into(),
            serde_json::value::to_raw_value(&old).unwrap(),
        );
        let mut next = selection_at("new");
        next.payload_root = NativeRootIdentity::Macos {
            device: 1,
            inode: 3,
            uid: 501,
        };
        let (target, intent) = update(&before, next.clone(), 1);
        assert!(
            validate_service_runtime_repair_transition(&before, &target, &marker, &intent).is_ok()
        );
        assert!(validate_committed_transition(&before, &target, &marker, &intent).is_ok());
        assert!(validate_transition(&before, &target, &marker, &intent).is_err());
        assert!(validate_runtime_transition(&before, &target, &marker, &intent).is_err());
        assert!(validate_app_runtime_transition(&before, &target, &marker, &intent).is_err());
        assert_eq!(target.schema, 5);
        assert!(
            !NativeReleaseReader::NativeAppRuntimeSelectedV1
                .supports_state_reader(target.reader_contract)
        );
        assert!(
            NativeReleaseReader::NativeServiceRuntimeSelectedV1
                .supports_state_reader(target.reader_contract)
        );
        assert_eq!(record(&target).unwrap().bootstrap_runtime, old);
        assert_eq!(
            before.extensions["preserve"].get(),
            target.extensions["preserve"].get()
        );
        for mutate in [
            |state: &mut NativeState| state.desired.host = state.desired.gateway,
            |state: &mut NativeState| {
                state.desired.gateway.as_mut().unwrap().run = NativeRunDesired::Running
            },
            |state: &mut NativeState| {
                state.desired.gateway.as_mut().unwrap().manager = NativeManager::ForegroundCli
            },
        ] {
            let mut changed = before.clone();
            mutate(&mut changed);
            assert!(
                validate_service_runtime_repair_transition(&changed, &target, &marker, &intent)
                    .is_err()
            );
        }
        let mut other = next.clone();
        other.publisher_spki_sha256 = Sha256Digest::of_bytes(b"foreign");
        let (foreign, foreign_intent) = update(&before, other, 1);
        assert!(
            validate_service_runtime_repair_transition(&before, &foreign, &marker, &foreign_intent)
                .is_err()
        );
        let mut wrong_uid = next;
        wrong_uid.payload_root = NativeRootIdentity::Macos {
            device: 1,
            inode: 3,
            uid: 502,
        };
        let (foreign, foreign_intent) = update(&before, wrong_uid, 1);
        assert!(
            validate_service_runtime_repair_transition(&before, &foreign, &marker, &foreign_intent)
                .is_err()
        );
        let mut old_reader = target.clone();
        old_reader.schema = 4;
        old_reader.reader_contract = ReaderContract::NativeAppRuntimeSelectedStateV1;
        assert!(validate_committed_transition(&before, &old_reader, &marker, &intent).is_err());
        assert!(
            validate_service_runtime_repair_transition(&before, &target, &marker, &intent).is_ok()
        );
        // Pure grammar grants no native inactive-registration or writer custody.
    }
    #[test]
    fn app_update_reader_barrier_and_forward_rollback_keep_original_authority() {
        use styx_contracts::native_release::NativeReleaseReader;
        let (marker, mut before) = fixture();
        before.desired.host.as_mut().unwrap().manager = NativeManager::AppManaged;
        let (target, intent) = update(&before, selection_at("app-new"), 1);
        assert!(validate_app_runtime_transition(&before, &target, &marker, &intent).is_ok());
        assert!(validate_committed_transition(&before, &target, &marker, &intent).is_ok());
        assert!(validate_runtime_transition(&before, &target, &marker, &intent).is_err());
        assert!(validate_transition(&before, &target, &marker, &intent).is_err());
        assert!(
            !NativeReleaseReader::NativeRuntimeSelectedV1
                .supports_state_reader(target.reader_contract)
        );
        assert!(
            NativeReleaseReader::NativeAppRuntimeSelectedV1
                .supports_state_reader(target.reader_contract)
        );
        let (rollback, rollback_intent) = update(&target, selection_at("old"), 2);
        assert!(
            validate_app_runtime_transition(&target, &rollback, &marker, &rollback_intent).is_ok()
        );
        assert_eq!(rollback.schema, NATIVE_APP_RUNTIME_SELECTED_STATE_SCHEMA);
        assert_eq!(
            record(&rollback).unwrap().bootstrap_runtime,
            selection_at("old")
        );
        assert_eq!(
            before.extensions["preserve"].get(),
            rollback.extensions["preserve"].get()
        );
        let mut old_reader = rollback.clone();
        old_reader.schema = NATIVE_RUNTIME_SELECTED_STATE_SCHEMA;
        old_reader.reader_contract = ReaderContract::NativeRuntimeSelectedStateV1;
        assert!(
            validate_committed_transition(&target, &old_reader, &marker, &rollback_intent).is_err()
        );
        let mut wrong_marker = marker.clone();
        wrong_marker.reader_floor = ReaderContract::NativeAppRuntimeSelectedStateV1;
        assert!(validate_state(&target, &wrong_marker).is_err());
        for mutate in [
            |state: &mut NativeState| {
                state.desired.host.as_mut().unwrap().run = NativeRunDesired::Running
            },
            |state: &mut NativeState| {
                state.desired.host.as_mut().unwrap().manager = NativeManager::ForegroundCli
            },
            |state: &mut NativeState| {
                state.desired.host.as_mut().unwrap().autostart = NativeAutostartDesired::Enabled
            },
        ] {
            let mut changed = before.clone();
            mutate(&mut changed);
            assert!(validate_app_runtime_transition(&changed, &target, &marker, &intent).is_err());
        }
        let mut foreign = selection_at("foreign");
        foreign.publisher_spki_sha256 = Sha256Digest::of_bytes(b"foreign publisher");
        let (foreign_target, foreign_intent) = update(&before, foreign, 1);
        assert!(
            validate_app_runtime_transition(&before, &foreign_target, &marker, &foreign_intent)
                .is_err()
        );
    }
}
