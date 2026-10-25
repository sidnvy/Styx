//! Actual owned Windows/macOS configuration files/process exit only. This is neither
//! service activation, pairing, hostile-writer CAS nor power-loss acceptance.
#![cfg(any(target_os = "windows", target_os = "macos"))]
use super::*;
use crate::store::{
    PrivateRoot, ProcessIdentity,
    native_root::{NATIVE_MARKER_FILE, create_fresh, reopen_native},
};
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use styx_contracts::{management::ReaderContract, native_management::*};

const DEPLOYMENT: &[u8] =
    b"{\"schema\":1,\"mode\":\"join-existing\",\"host\":{},\"opaque\":900719925474099312345}\n";
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
fn create(parent: &PrivateRoot, parent_path: &Path) -> (PathBuf, NativeTransactions) {
    let name = format!("native-c07-{}", uuid::Uuid::new_v4());
    let fresh = create_fresh(parent, OsStr::new(&name))
        .unwrap_or_else(|e| panic!("fresh native root: {:?}", e.error()));
    let state = genesis(fresh.marker());
    let binding = fresh
        .initialize(DEPLOYMENT, &state)
        .unwrap_or_else(|e| panic!("native genesis: {:?}", e.error()));
    let coordinator = NativeTransactions::open(binding)
        .unwrap_or_else(|e| panic!("native coordinator: {:?}", e.error()));
    (parent_path.join(name), coordinator)
}
fn reopen(path: &Path) -> NativeTransactions {
    let root = PrivateRoot::open(path).unwrap();
    let writer = root.try_configuration_writer().unwrap();
    let binding = reopen_native(root, writer)
        .unwrap_or_else(|e| panic!("original native root: {:?}", e.error()));
    NativeTransactions::open(binding)
        .unwrap_or_else(|e| panic!("original native coordinator: {:?}", e.error()))
}
fn target(coordinator: &NativeTransactions, id: &str, sequence: u64) -> Vec<u8> {
    let raw = coordinator.readstate().unwrap();
    let mut state = native_state::decode_state(raw.raw_bytes(), coordinator.marker())
        .unwrap()
        .state()
        .clone();
    state.revision += 1;
    state.last_transaction = Some(NativeStateTransaction {
        transaction_id: id.try_into().unwrap(),
        sequence,
    });
    let host = state.desired.host.as_mut().unwrap();
    host.run = match host.run {
        NativeRunDesired::Stopped => NativeRunDesired::Running,
        NativeRunDesired::Running => NativeRunDesired::Stopped,
    };
    serde_json::to_vec(&state).unwrap()
}
fn fixed(path: &Path) -> (RootIdentity, Vec<u8>, Vec<u8>) {
    (
        PrivateRoot::open(path).unwrap().identity(),
        fs::read(path.join(NATIVE_MARKER_FILE)).unwrap(),
        fs::read(path.join("deployment.json")).unwrap(),
    )
}
fn assert_committed(coordinator: &NativeTransactions, id: &TransactionId, expected: &[u8]) {
    let original = coordinator.journal.read_original(id).unwrap();
    assert_eq!(original.target, expected);
    assert_eq!(
        original.intent.target_state_sha256,
        Sha256Digest::of_bytes(expected)
    );
    assert_eq!(original.phases[0].stage, DurableStage::Prepared);
    assert_eq!(original.phases[1].stage, DurableStage::Applied);
    assert_eq!(original.phases[2].stage, DurableStage::Verified);
    assert_eq!(original.phases[3].stage, DurableStage::Committed);
    assert_eq!(original.phases.len(), 4);
    for pair in original.phases.windows(2) {
        assert_eq!(pair[1].previous, Some(pair[0].record_sha256));
        assert_eq!(pair[1].transaction_id, *id);
    }
    assert_eq!(coordinator.readstate().unwrap().raw_bytes(), expected);
    assert_eq!(
        replay(&original).unwrap().snapshot().last_durable_stage,
        DurableStage::Committed
    );
}

#[test]
#[ignore = "requires STYX_TEST_NATIVE_STORE_ROOT; owned Windows/macOS C07 desired-state files and original process-exit recovery only, no services/power-loss"]
fn native_c07_commit_and_original_recovery_batch() {
    let parent_path = PathBuf::from(std::env::var_os("STYX_TEST_NATIVE_STORE_ROOT").unwrap());
    let parent = PrivateRoot::open(&parent_path).unwrap();
    let (path, mut coordinator) = create(&parent, &parent_path);
    let original_fixed = fixed(&path);
    let stopped = coordinator.readstate().unwrap().raw_bytes().to_vec();
    assert_eq!(
        coordinator
            .readstate()
            .unwrap()
            .state()
            .desired
            .host
            .unwrap()
            .run,
        NativeRunDesired::Stopped
    );
    let id: TransactionId = "native-c07-1".try_into().unwrap();
    let running = target(&coordinator, id.as_str(), 1);
    let plan_name = coordinator.save_plan(&id, &running).unwrap();
    let plan_pin = PrivateRoot::open(&path)
        .unwrap()
        .read_raw(&plan_name, 1024 * 1024)
        .unwrap();
    assert_eq!(plan_pin.bytes(), running);
    assert_eq!(
        coordinator.save_plan(&id, b"do not overwrite"),
        Err(NativeTransactionError::Conflict)
    );
    let unchanged = PrivateRoot::open(&path)
        .unwrap()
        .read_raw(&plan_name, 1024 * 1024)
        .unwrap();
    assert_eq!(unchanged.observation(), plan_pin.observation());
    assert_eq!(unchanged.bytes(), running);
    drop(unchanged);
    drop(plan_pin);
    assert_eq!(coordinator.readstate().unwrap().raw_bytes(), stopped);
    assert!(coordinator.query(&id).unwrap().is_none());
    let committed = coordinator.apply_target(&running).unwrap();
    assert!(!committed.recovered);
    assert_committed(&coordinator, &id, &running);
    assert!(coordinator.configuration_root().ensure_admission().is_ok());
    assert_eq!(
        coordinator.apply_target(&running),
        Err(NativeTransactionError::InvalidInput)
    );
    let reused = target(&coordinator, id.as_str(), 2);
    assert_eq!(
        coordinator.apply_target(&reused),
        Err(NativeTransactionError::Conflict)
    );
    assert!(coordinator.configuration_root().ensure_admission().is_ok());
    drop(coordinator);
    let mut coordinator = reopen(&path);
    assert_eq!(fixed(&path), original_fixed);
    assert_eq!(coordinator.readstate().unwrap().raw_bytes(), running);
    assert!(coordinator.configuration_root().ensure_admission().is_err());
    let recovered = coordinator.recover_original(&id).unwrap();
    assert!(recovered.recovered);
    assert_eq!(recovered.committed, committed.committed);
    assert_committed(&coordinator, &id, &running);
    assert!(coordinator.configuration_root().ensure_admission().is_ok());

    // A real capability held by a different original root cannot authorize this root.
    let (_foreign_path, foreign) = create(&parent, &parent_path);
    let next_id: TransactionId = "native-c07-2".try_into().unwrap();
    let second = target(&coordinator, next_id.as_str(), 2);
    let foreign_maintenance = foreign
        .configuration_root()
        .begin_standalone_native(next_id.clone(), false)
        .unwrap();
    assert_eq!(
        coordinator.apply_with_maintenance(&foreign_maintenance, &second),
        Err(NativeTransactionError::Conflict)
    );
    assert_eq!(coordinator.readstate().unwrap().raw_bytes(), running);
    assert!(coordinator.configuration_root().ensure_admission().is_ok());
    drop(foreign_maintenance);
    drop(foreign);

    // Prepare the next original intent, then lose the process-local owner.
    // Recovery of an older committed ID must not clear this newer fence.
    let (before, intent) = coordinator.plan(&second).unwrap();
    let maintenance = coordinator
        .configuration_root()
        .begin_standalone_native(next_id.clone(), false)
        .unwrap();
    coordinator
        .journal
        .prepare(
            &maintenance,
            &serde_json::to_vec(&intent).unwrap(),
            &before,
            &second,
        )
        .unwrap();
    drop(maintenance);
    drop(coordinator);
    let mut coordinator = reopen(&path);
    assert_eq!(
        coordinator.recover_original(&id),
        Err(NativeTransactionError::UnknownInspect)
    );
    assert!(coordinator.configuration_root().ensure_admission().is_err());
    assert_eq!(coordinator.readstate().unwrap().raw_bytes(), running);
    assert!(coordinator.recover_original(&next_id).unwrap().recovered);
    assert_committed(&coordinator, &next_id, &second);
    assert_eq!(fixed(&path), original_fixed);
    assert!(coordinator.configuration_root().ensure_admission().is_ok());
    drop(coordinator);

    // Two real process exits: rename before Applied persistence, then committed
    // receipt before reply. Neither is a simulated power cut or native OS action.
    for fault in ["canonical.rename", "committed.reply"] {
        let (crash_path, crash) = create(&parent, &parent_path);
        let immutable = fixed(&crash_path);
        let before = crash.readstate().unwrap().raw_bytes().to_vec();
        let expected = target(&crash, "native-c07-fault-1", 1);
        drop(crash);
        let test_name = format!(
            "{}::native_transaction_exit_child",
            module_path!().split_once("::").unwrap().1
        );
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", &test_name, "--nocapture"])
            .env("STYX_TEST_NATIVE_C07_CHILD_ROOT", &crash_path)
            .env("STYX_TEST_NATIVE_C07_CHILD_FAULT", fault)
            .stdin(Stdio::piped())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        // The child blocks on its single control byte, so the original kernel
        // birth is captured before it can reach the intended process-exit port.
        let original = ProcessIdentity::observe(child.id());
        let send = if original.is_ok() {
            child.stdin.take().unwrap().write_all(b"1")
        } else {
            drop(child.stdin.take());
            Ok(())
        };
        let until = Instant::now() + Duration::from_secs(60);
        let mut timed_out = false;
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if Instant::now() >= until {
                timed_out = true;
                // Only this original std::Child HANDLE; never PID/name lookup.
                // A timeout is failure, even if exact owned termination works.
                child.kill().unwrap();
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let status = child.wait().unwrap();
        let original = original.unwrap();
        send.unwrap();
        let gone = !original.still_current().unwrap();
        println!(
            "STYX_NATIVE_C07_CHILD_JSON={}",
            serde_json::json!({"schema":1,"platform":std::env::consts::OS,"fault":fault,"original":original,"actual_wait":true,"exit_code":status.code(),"original_birth_absent":gone,"timeout_exact_child_terminated":timed_out})
        );
        assert!(!timed_out, "original C07 child exceeded owned deadline");
        assert_eq!(status.code(), Some(86));
        assert!(gone);
        assert_eq!(fixed(&crash_path), immutable);
        assert_eq!(fs::read(crash_path.join("state.json")).unwrap(), expected);
        let mut crash = reopen(&crash_path);
        assert!(crash.configuration_root().ensure_admission().is_err());
        let fault_id: TransactionId = "native-c07-fault-1".try_into().unwrap();
        let original = crash.journal.read_original(&fault_id).unwrap();
        assert_eq!(original.before, before);
        assert_eq!(original.target, expected);
        if fault == "canonical.rename" {
            assert_eq!(original.phases.len(), 1);
            assert_eq!(original.phases[0].stage, DurableStage::Prepared);
        } else {
            assert_eq!(
                original.phases.last().unwrap().stage,
                DurableStage::Committed
            );
        }
        let recovered = crash.recover_original(&fault_id).unwrap();
        assert!(recovered.recovered);
        let after = crash.journal.read_original(&fault_id).unwrap();
        assert_eq!(after.raw_intent, original.raw_intent);
        assert_eq!(after.before, original.before);
        assert_eq!(after.target, original.target);
        assert_eq!(after.phases[0], original.phases[0]);
        if fault == "committed.reply" {
            assert_eq!(after.phases, original.phases);
        }
        assert_committed(&crash, &fault_id, &expected);
        assert_eq!(fixed(&crash_path), immutable);
        assert!(crash.configuration_root().ensure_admission().is_ok());
    }
    println!(
        "STYX_NATIVE_C07_RESULT_JSON={}",
        serde_json::json!({"schema":1,"platform":std::env::consts::OS,"status":"PASS_OWNED_NATIVE_C07_ORIGINAL_RECOVERY_ONLY","service_started":false,"power_loss_tested":false,"fixtures_preserved":true})
    );
}

#[test]
#[ignore = "private owned subprocess port for native C07 aggregate; explicit original root/fault/control byte required"]
fn native_transaction_exit_child() {
    let path = PathBuf::from(std::env::var_os("STYX_TEST_NATIVE_C07_CHILD_ROOT").unwrap());
    let fault = std::env::var("STYX_TEST_NATIVE_C07_CHILD_FAULT").unwrap();
    assert!(matches!(
        fault.as_str(),
        "canonical.rename" | "committed.reply"
    ));
    let mut control = [0u8; 1];
    std::io::stdin().read_exact(&mut control).unwrap();
    assert_eq!(control, *b"1");
    let mut coordinator = reopen(&path);
    let target = target(&coordinator, "native-c07-fault-1", 1);
    let _ = coordinator.apply_observing(&target, &|record, phase| {
        if (record == "canonical" && phase == "rename" && fault == "canonical.rename")
            || (record == "committed" && phase == "reply" && fault == "committed.reply")
        {
            std::process::exit(86);
        }
    });
    panic!("required original process-exit boundary was not reached");
}
