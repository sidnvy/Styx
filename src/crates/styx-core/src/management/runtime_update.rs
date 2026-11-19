//! Pure C07 runtime-update grammar. This validates data, never C08 trust,
//! process settlement, a writer lease, or permission to execute a selected image.
use super::{NativeStateRuleError, validate_state, validate_transition};
use styx_contracts::{management::DesiredStateCommit, native_management::*};

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
/// Runtime update history is optional in the one current configuration format.
/// Fresh profiles retain their selected runtime without inventing an update.
pub(super) fn validate_runtime_state(state: &NativeState) -> Result<()> {
    let current = state.runtime_selection().map_err(|_| invalid())?;
    if current
        .as_ref()
        .is_some_and(|selected| !valid_selection(selected))
    {
        return Err(NativeStateRuleError::InvalidState);
    }
    let Some(update) = state.runtime_update().map_err(|_| invalid())? else {
        return Ok(());
    };
    let current = current.ok_or(NativeStateRuleError::InvalidState)?;
    if state.revision == 0
        || update.schema != 1
        || update.transaction.sequence == 0
        || state
            .last_transaction
            .as_ref()
            .is_none_or(|last| last.sequence < update.transaction.sequence)
        || !valid_selection(&update.previous_runtime)
        || !valid_selection(&update.bootstrap_runtime)
        || current.publisher_spki_sha256 != update.bootstrap_runtime.publisher_spki_sha256
        || current.publisher_spki_sha256 != update.previous_runtime.publisher_spki_sha256
        || state
            .desired
            .host
            .iter()
            .chain(state.desired.gateway.iter())
            .any(|role| role.manager == NativeManager::AppManaged)
    {
        return Err(NativeStateRuleError::InvalidState);
    }
    Ok(())
}
/// The journal contains ordinary configuration commits and stopped runtime updates.
pub fn validate_committed_transition(
    before: &NativeState,
    target: &NativeState,
    marker: &NativeRootMarker,
    intent: &DesiredStateCommit,
) -> Result<()> {
    validate_transition(before, target, marker, intent)
        .or_else(|_| validate_runtime_transition(before, target, marker, intent))
}
/// Only a stopped foreground profile can select a runtime. The store retains
/// writer/execution exclusion and verifies both releases before publication.
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
    if intent.validate().is_err()
        || target.revision != before.revision.checked_add(1).ok_or_else(invalid)?
        || before.mode != target.mode
        || before.desired != target.desired
        || before.deployment_raw_sha256 != target.deployment_raw_sha256
        || target.deployment_raw_sha256 != intent.deployment_raw_sha256
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
    let bootstrap = before
        .runtime_update()
        .map_err(|_| invalid())?
        .map(|previous| previous.bootstrap_runtime)
        .unwrap_or(current);
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
    use styx_contracts::management::ReaderContract;
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
            reader_floor: ReaderContract::NativeStateV1,
        };
        let state = NativeState {
            schema: NATIVE_STATE_SCHEMA,
            kind: NativeStateKind::StyxDesiredState,
            runtime_format: NativeRuntimeFormat::NativeRustV1,
            reader_contract: ReaderContract::NativeStateV1,
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
        target.schema = NATIVE_STATE_SCHEMA;
        target.reader_contract = ReaderContract::NativeStateV1;
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
    fn stopped_update_and_forward_rollback_preserve_authority_boundaries() {
        let (marker, before) = fixture();
        let (target, intent) = update(&before, selection_at("new"), 1);
        assert!(validate_runtime_transition(&before, &target, &marker, &intent).is_ok());
        assert!(validate_transition(&before, &target, &marker, &intent).is_err());
        assert!(validate_committed_transition(&before, &target, &marker, &intent).is_ok());
        let (rollback, rollback_intent) = update(&target, selection_at("old"), 2);
        assert!(validate_runtime_transition(&target, &rollback, &marker, &rollback_intent).is_ok());
        assert_eq!(rollback.reader_contract, ReaderContract::NativeStateV1);
        assert_eq!(rollback.schema, NATIVE_STATE_SCHEMA);
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
        let mut unbound = target.clone();
        unbound.extensions.remove(NATIVE_RUNTIME_SELECTION_KEY);
        assert!(validate_state(&unbound, &marker).is_err());
    }
    #[test]
    fn fresh_configuration_preserves_linux_service_setup_without_update_history() {
        let (marker, state) = fixture();
        let mut fresh = state;
        assert!(validate_state(&fresh, &marker).is_ok());
        assert!(fresh.runtime_update().unwrap().is_none());
        fresh.desired.host.as_mut().unwrap().manager = NativeManager::PersistentService;
        fresh.desired.host.as_mut().unwrap().autostart = NativeAutostartDesired::Enabled;
        assert!(validate_state(&fresh, &marker).is_ok());
        let mut mac = marker.clone();
        mac.root_identity = NativeRootIdentity::Macos {
            device: 1,
            inode: 4,
            uid: 1000,
        };
        assert!(validate_state(&fresh, &mac).is_err());
        let mut invalid_marker = marker.clone();
        invalid_marker.schema += 1;
        assert!(
            validate_state(&fresh, &invalid_marker).is_err(),
            "unknown marker formats are rejected"
        );
    }
    #[test]
    fn updated_linux_runtime_can_restore_and_cycle_original_service() {
        let (marker, fresh) = fixture();
        let (mut before, _) = update(&fresh, selection_at("new"), 1);
        let extensions = before.extensions.clone();
        for (manager, run, autostart) in [
            (
                NativeManager::PersistentService,
                NativeRunDesired::Stopped,
                NativeAutostartDesired::Disabled,
            ),
            (
                NativeManager::PersistentService,
                NativeRunDesired::Running,
                NativeAutostartDesired::Enabled,
            ),
            (
                NativeManager::PersistentService,
                NativeRunDesired::Stopped,
                NativeAutostartDesired::Disabled,
            ),
            (
                NativeManager::ForegroundCli,
                NativeRunDesired::Stopped,
                NativeAutostartDesired::Disabled,
            ),
        ] {
            let mut target = before.clone();
            let role = target.desired.host.as_mut().unwrap();
            role.manager = manager;
            role.run = run;
            role.autostart = autostart;
            target.revision += 1;
            let sequence = before.last_transaction.as_ref().unwrap().sequence + 1;
            let transaction_id = format!("service-{sequence}").try_into().unwrap();
            target.last_transaction = Some(NativeStateTransaction {
                transaction_id,
                sequence,
            });
            let mut intent = update(&before, selection_at("unused"), sequence).1;
            intent.transaction_id = target
                .last_transaction
                .as_ref()
                .unwrap()
                .transaction_id
                .clone();
            intent.target_state_sha256 =
                Sha256Digest::of_bytes(&serde_json::to_vec(&target).unwrap());
            assert!(validate_transition(&before, &target, &marker, &intent).is_ok());
            assert!(before.extensions_preserved_in(&target));
            assert_eq!(
                target.extensions.keys().collect::<Vec<_>>(),
                extensions.keys().collect::<Vec<_>>()
            );
            if manager == NativeManager::PersistentService {
                let mut foreign = marker.clone();
                foreign.root_identity = NativeRootIdentity::Macos {
                    device: 1,
                    inode: 4,
                    uid: 1000,
                };
                assert!(validate_state(&target, &foreign).is_err());
                foreign.root_identity = NativeRootIdentity::Windows {
                    volume_serial: 1,
                    file_id: 4,
                    owner_sid: "S-1-5-21-1000".into(),
                };
                assert!(validate_state(&target, &foreign).is_err());
            }
            let mut forged = target.clone();
            forged.desired.host.as_mut().unwrap().manager = NativeManager::AppManaged;
            assert!(validate_state(&forged, &marker).is_err());
            before = target;
        }
    }
    #[test]
    fn runtime_updates_preserve_bootstrap_and_unrelated_extensions() {
        let (marker, fresh) = fixture();
        let (selected, _) = update(&fresh, selection_at("selected"), 1);
        for before in [fresh, selected] {
            assert!(validate_state(&before, &marker).is_ok());
            let (target, intent) = update(&before, selection_at("next"), 2);
            assert!(validate_runtime_transition(&before, &target, &marker, &intent).is_ok());
            assert!(validate_committed_transition(&before, &target, &marker, &intent).is_ok());
            assert!(validate_transition(&before, &target, &marker, &intent).is_err());
            let bootstrap = before
                .runtime_update()
                .unwrap()
                .map(|v| v.bootstrap_runtime)
                .unwrap_or_else(|| before.runtime_selection().unwrap().unwrap());
            assert_eq!(
                target.runtime_update().unwrap().unwrap().bootstrap_runtime,
                bootstrap
            );
            assert_eq!(
                before.extensions["preserve"].get(),
                target.extensions["preserve"].get()
            );
            let (rollback, rollback_intent) = update(&target, selection_at("old"), 3);
            assert!(
                validate_runtime_transition(&target, &rollback, &marker, &rollback_intent).is_ok()
            );
        }
    }
}
