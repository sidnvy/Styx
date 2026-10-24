//! Real owned filesystem and process-exit ports. No legacy/user profile, native
//! service action, device permission or power-loss acceptance is implied.
#![cfg(all(target_os = "linux", target_env = "gnu"))]
use super::*;
use crate::store::{
    PrivateRoot,
    native_root::{create_fresh, reopen_native},
};
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};
use styx_contracts::{management::ReaderContract, native_management::*};
const DEPLOYMENT: &[u8] =
    b"{\"synthetic_native_transaction\":true,\"opaque\":900719925474099312345}\n";
fn genesis(marker: &NativeRootMarker) -> NativeState {
    NativeState {
        schema: 2,
        kind: NativeStateKind::StyxDesiredState,
        runtime_format: NativeRuntimeFormat::NativeRustV1,
        reader_contract: ReaderContract::NativeManagementStateV1,
        scope_generation: marker.scope_generation,
        deployment_raw_sha256: Sha256Digest::of_bytes(DEPLOYMENT),
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
        extensions: BTreeMap::from([(
            "opaque_extension".into(),
            serde_json::value::RawValue::from_string(
                "{\"integer\":900719925474099312345,\"decimal\":1e99999}".into(),
            )
            .unwrap(),
        )]),
    }
}
fn private_write(path: &Path, bytes: &[u8]) {
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
fn create(base: &Path) -> NativeTransactions {
    let parent = PrivateRoot::open(base).unwrap();
    let fresh = create_fresh(&parent, OsStr::new("native"))
        .unwrap_or_else(|e| panic!("fresh: {:?}", e.error()));
    let state = genesis(fresh.marker());
    let binding = fresh
        .initialize(DEPLOYMENT, &state)
        .unwrap_or_else(|e| panic!("genesis: {:?}", e.error()));
    NativeTransactions::open(binding).unwrap_or_else(|e| panic!("coordinator: {:?}", e.error()))
}
fn reopen(base: &Path) -> NativeTransactions {
    let root = PrivateRoot::open(base.join("native")).unwrap();
    let writer = root.try_configuration_writer().unwrap();
    let binding = reopen_native(root, writer).unwrap_or_else(|e| panic!("reopen: {:?}", e.error()));
    NativeTransactions::open(binding).unwrap_or_else(|e| panic!("coordinator: {:?}", e.error()))
}
fn target(coordinator: &NativeTransactions, id: &str, seq: u64) -> Vec<u8> {
    let raw = coordinator.readstate().unwrap();
    // Decode via the actual formal reader so opaque JSON numbers never travel
    // through Value/f64, including the synthetic 1e99999 extension.
    let mut state = native_state::decode_state(raw.raw_bytes(), coordinator.binding.marker())
        .unwrap()
        .state()
        .clone();
    state.revision += 1;
    state.last_transaction = Some(NativeStateTransaction {
        transaction_id: id.try_into().unwrap(),
        sequence: seq,
    });
    state.desired.host.as_mut().unwrap().run =
        if state.desired.host.unwrap().run == NativeRunDesired::Stopped {
            NativeRunDesired::Running
        } else {
            NativeRunDesired::Stopped
        };
    serde_json::to_vec(&state).unwrap()
}
#[test]
#[ignore = "requires STYX_TEST_NATIVE_TRANSACTION_ROOT; actual owned native reader/transaction/close-reopen aggregate"]
fn native_commit_reopen_and_scope_rejections_batch() {
    let base =
        std::path::PathBuf::from(std::env::var("STYX_TEST_NATIVE_TRANSACTION_ROOT").unwrap());
    fs::create_dir_all(&base).unwrap();
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
    let mut coordinator = create(&base);
    let before = coordinator.readstate().unwrap().raw_bytes().to_vec();
    let first = target(&coordinator, "native-1", 1);
    let original_marker = fs::read(base.join("native/.styx-native-root-v1.json")).unwrap();
    let result = coordinator.apply_target(&first).unwrap();
    assert_eq!(result.committed.stage, DurableStage::Committed);
    assert!(!result.recovered);
    assert_eq!(coordinator.readstate().unwrap().raw_bytes(), first);
    assert!(coordinator.configuration_root().ensure_admission().is_ok());
    assert_eq!(
        fs::read(base.join("native/deployment.json")).unwrap(),
        DEPLOYMENT
    );
    assert_ne!(before, first);
    assert_eq!(
        coordinator.apply_target(&first),
        Err(NativeTransactionError::InvalidInput)
    );
    let reused = target(&coordinator, "native-1", 2);
    assert_eq!(
        coordinator.apply_target(&reused),
        Err(NativeTransactionError::Conflict)
    );
    assert!(coordinator.configuration_root().ensure_admission().is_ok());
    drop(coordinator);
    let mut coordinator = reopen(&base);
    assert!(coordinator.configuration_root().ensure_admission().is_err());
    let recovered = coordinator
        .recover_original(&"native-1".try_into().unwrap())
        .unwrap();
    assert_eq!(recovered.committed, result.committed);
    assert!(recovered.recovered);
    assert!(coordinator.configuration_root().ensure_admission().is_ok());
    let second = target(&coordinator, "native-2", 2);
    coordinator.apply_target(&second).unwrap();
    assert_eq!(coordinator.readstate().unwrap().raw_bytes(), second);
    assert_eq!(
        fs::read(base.join("native/.styx-native-root-v1.json")).unwrap(),
        original_marker
    );
    // A valid maintenance capability for another actual root is not authority.
    let foreign_base = base.join("foreign");
    fs::create_dir(&foreign_base).unwrap();
    fs::set_permissions(&foreign_base, fs::Permissions::from_mode(0o700)).unwrap();
    let foreign = create(&foreign_base);
    let foreign_maintenance = foreign
        .configuration_root()
        .begin_standalone_native("native-3".try_into().unwrap(), false)
        .unwrap();
    let third = target(&coordinator, "native-3", 3);
    assert_eq!(
        coordinator.apply_with_maintenance(&foreign_maintenance, &third),
        Err(NativeTransactionError::Conflict)
    );
    assert!(coordinator.configuration_root().ensure_admission().is_ok());
    assert_eq!(coordinator.readstate().unwrap().raw_bytes(), second);
    drop(foreign_maintenance);
    drop(foreign);
    // Stale original transaction cannot release a newer pending transaction.
    let third = target(&coordinator, "native-3", 3);
    let (before, intent) = coordinator.plan(&third).unwrap();
    let maintenance = coordinator
        .configuration_root()
        .begin_standalone_native(intent.transaction_id.clone(), false)
        .unwrap();
    coordinator
        .journal
        .prepare(
            &maintenance,
            &serde_json::to_vec(&intent).unwrap(),
            &before,
            &third,
        )
        .unwrap();
    drop(maintenance);
    drop(coordinator);
    let mut coordinator = reopen(&base);
    assert_eq!(
        coordinator.recover_original(&"native-2".try_into().unwrap()),
        Err(NativeTransactionError::UnknownInspect)
    );
    assert!(coordinator.configuration_root().ensure_admission().is_err());
    assert_eq!(coordinator.readstate().unwrap().raw_bytes(), second);
    assert!(
        coordinator
            .recover_original(&"native-3".try_into().unwrap())
            .unwrap()
            .recovered
    );
    assert_eq!(coordinator.readstate().unwrap().raw_bytes(), third);
    assert!(coordinator.configuration_root().ensure_admission().is_ok());
    // An instantiated enrollment authority requires its existing complete gate;
    // the standalone route cannot bypass it, even with valid desired bytes.
    let _enrollment = crate::store::enrollment::OwnedEnrollmentJournal::from_configuration(
        coordinator.configuration_root(),
        JournalBudget::default(),
    )
    .unwrap();
    let fourth = target(&coordinator, "native-4", 4);
    assert_eq!(
        coordinator.apply_target(&fourth),
        Err(NativeTransactionError::Conflict)
    );
    assert!(coordinator.configuration_root().ensure_admission().is_ok());
    assert_eq!(coordinator.readstate().unwrap().raw_bytes(), third);
}
#[test]
#[ignore = "cfg(test) subprocess port only; requires explicit owned root/action; process-exit faults never production CLI"]
fn native_transaction_child() {
    let base =
        std::path::PathBuf::from(std::env::var("STYX_TEST_NATIVE_TRANSACTION_ROOT").unwrap());
    let action = std::env::var("STYX_TEST_NATIVE_TRANSACTION_ACTION").unwrap();
    let fault = std::env::var("STYX_TEST_NATIVE_TRANSACTION_FAULT").unwrap_or_default();
    let id: TransactionId = "native-1".try_into().unwrap();
    let mut coordinator = if action == "apply" {
        create(&base)
    } else {
        reopen(&base)
    };
    let result = match action.as_str() {
        "apply" => {
            let before = coordinator.readstate().unwrap();
            let target = target(&coordinator, "native-1", 1);
            private_write(&base.join("before.bin"), before.raw_bytes());
            private_write(&base.join("target.bin"), &target);
            fs::File::open(&base).unwrap().sync_all().unwrap();
            Some(coordinator.apply_observing(&target, &|record, phase| {
                if fault == format!("{record}.{phase}") {
                    std::process::exit(86);
                }
            }))
        }
        "recover" => Some(coordinator.recover_original(&id)),
        "observe" => None,
        _ => panic!("unknown explicit child action"),
    };
    let state = coordinator.readstate().unwrap();
    let query = coordinator.query(&id).unwrap();
    let stage = query.as_ref().and_then(|tx| {
        tx.phase_receipts
            .last()
            .map(|r| r.stage)
            .or_else(|| tx.prepared.as_ref().map(|r| r.journal.stage))
    });
    let outcome = match &result {
        Some(Ok(_)) => "committed",
        Some(Err(_)) => "rejected",
        None => "observed",
    };
    let error = result
        .as_ref()
        .and_then(|r| r.as_ref().err())
        .map(ToString::to_string);
    let recovered = result
        .as_ref()
        .and_then(|r| r.as_ref().ok())
        .is_some_and(|r| r.recovered);
    println!(
        "STYX_NATIVE_TRANSACTION_JSON={}",
        serde_json::json!({"schema":1,"action":action,"outcome":outcome,
        "transaction_id":id,"admission_fenced":coordinator.configuration_root().ensure_admission().is_err(),
        "canonical_sha256":state.raw_sha256(),"last_durable_stage":stage,"recovered":recovered,"error":error})
    );
}
