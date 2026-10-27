//! Real C07 update/recovery and synthetic, legally signed C08 fixtures. No image
//! execution, user publisher, Host enrollment, service or power-loss acceptance.
use super::*;
use crate::{
    crypto::DevicePrivateKey,
    release,
    store::{PrivateRoot, native_root},
};
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey, pkcs8::EncodePublicKey as _};
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs,
    io::Write as _,
    os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use styx_contracts::{native_management::*, native_release::NativeReleaseMember};

const DEPLOYMENT: &[u8] = b"{\"runtime_update_fixture\":true}\n";
const ID: &str = "interrupted-runtime-update";
fn directory(path: &Path) {
    fs::DirBuilder::new().mode(0o700).create(path).unwrap();
}
fn write(path: &Path, bytes: &[u8], executable: bool) {
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(if executable { 0o700 } else { 0o600 })
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
fn candidate(base: &Path, name: &str, key: &SigningKey, selected: bool) -> NativeRuntimeSelection {
    candidate_reader(
        base,
        name,
        key,
        if selected {
            "native_runtime_selected_v1"
        } else {
            "native_runtime_migrated_v3"
        },
    )
}
fn candidate_reader(
    base: &Path,
    name: &str,
    key: &SigningKey,
    reader: &str,
) -> NativeRuntimeSelection {
    let payload = base.join(name);
    directory(&payload);
    directory(&payload.join("bin"));
    let members = [
        (
            "LICENSE",
            b"synthetic C07/C08 fixture license".as_slice(),
            false,
        ),
        (
            "bin/styx",
            b"\x7fELF synthetic immutable fixture; never executed".as_slice(),
            true,
        ),
        (
            "source-inputs.json",
            b"{\"synthetic_fixture\":true}".as_slice(),
            false,
        ),
    ];
    let files: Vec<_> = members
        .iter()
        .map(|(path, bytes, executable)| {
            write(&payload.join(path), bytes, *executable);
            NativeReleaseMember {
                path: (*path).into(),
                size: bytes.len() as u64,
                sha256: Sha256Digest::of_bytes(bytes),
                executable: *executable,
            }
        })
        .collect();
    let pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        base64::engine::general_purpose::STANDARD
            .encode(key.verifying_key().to_public_key_der().unwrap().as_bytes())
    );
    let publisher = base.join(format!("{name}-publisher.pem"));
    write(&publisher, pem.as_bytes(), false);
    let expected = crate::crypto::PublisherVerifyingKey::from_spki_pem(pem.as_bytes())
        .unwrap()
        .fingerprint()
        .unwrap();
    let manifest = serde_json::json!({"schema":2,"runtime_format":"native_rust_v1","component":"styx", "scope":"runtime_candidate",
        "minimum_reader": reader,
        "target":"x86_64-unknown-linux-gnu","version":format!("0.4.0-test.{name}"),"entrypoint":"bin/styx",
        "source":{"revision":"1".repeat(40),"inputs_sha256":Sha256Digest::of_bytes(members[2].1)},
        "contracts":{"control":1,"management_state":match reader { "native_app_service_transferred_v1" => 6, "native_app_runtime_selected_v1" => 4, "native_runtime_selected_v1" => 3, _ => 2 }},"files":files,"external_workers":[]});
    let raw = serde_json::to_vec(&manifest).unwrap();
    write(&payload.join("manifest.json"), &raw, false);
    write(
        &payload.join("manifest.sig"),
        &key.sign(&raw).to_bytes(),
        false,
    );
    let selected = release::verify(&payload, &publisher, &expected)
        .unwrap()
        .runtime_selection()
        .unwrap();
    write(
        &base.join(format!("selection-{name}.json")),
        &serde_json::to_vec(&selected).unwrap(),
        false,
    );
    selected
}
fn selection_file(base: &Path, name: &str) -> NativeRuntimeSelection {
    serde_json::from_slice(&fs::read(base.join(format!("selection-{name}.json"))).unwrap()).unwrap()
}
fn verified(base: &Path, name: &str) -> VerifiedNativeRelease {
    release::verify_selected(&selection_file(base, name)).unwrap()
}
fn create(base: &Path, bootstrap: &NativeRuntimeSelection, identity: &[u8]) -> NativeTransactions {
    create_for_manager(base, bootstrap, identity, NativeManager::ForegroundCli)
}
fn create_for_manager(
    base: &Path,
    bootstrap: &NativeRuntimeSelection,
    identity: &[u8],
    manager: NativeManager,
) -> NativeTransactions {
    directory(base);
    let parent = PrivateRoot::open(base).unwrap();
    let fresh = native_root::create_fresh(&parent, OsStr::new("native"))
        .unwrap_or_else(|e| panic!("fresh: {:?}", e.error()));
    let state = NativeState {
        schema: 2,
        kind: NativeStateKind::StyxDesiredState,
        runtime_format: NativeRuntimeFormat::NativeRustV1,
        reader_contract: ReaderContract::NativeManagementStateV1,
        scope_generation: fresh.marker().scope_generation,
        deployment_raw_sha256: Sha256Digest::of_bytes(DEPLOYMENT),
        mode: NativeDeploymentMode::JoinExisting,
        revision: 0,
        last_transaction: None,
        desired: NativeDesired {
            gateway: None,
            host: Some(NativeComponentDesired {
                manager,
                run: NativeRunDesired::Stopped,
                autostart: NativeAutostartDesired::Disabled,
            }),
        },
        migration: None,
        extensions: BTreeMap::from([
            (
                NATIVE_RUNTIME_SELECTION_KEY.into(),
                serde_json::value::to_raw_value(bootstrap).unwrap(),
            ),
            (
                "opaque_fixture_identity_sha256".into(),
                serde_json::value::to_raw_value(&Sha256Digest::of_bytes(identity)).unwrap(),
            ),
        ]),
    };
    let binding = fresh
        .initialize(DEPLOYMENT, &state)
        .unwrap_or_else(|e| panic!("initialize: {:?}", e.error()));
    // Real protected identity bytes are immutable inputs, not a claim that the
    // synthetic configuration completed native enrollment or can execute work.
    write(&base.join("native/host-identity.pem"), identity, false);
    NativeTransactions::open(binding).unwrap_or_else(|e| panic!("open: {:?}", e.error()))
}
fn open(base: &Path) -> NativeTransactions {
    let root = PrivateRoot::open(base.join("native")).unwrap();
    let writer = root.try_configuration_writer().unwrap();
    let binding = native_root::reopen_native(root, writer)
        .unwrap_or_else(|e| panic!("reopen: {:?}", e.error()));
    NativeTransactions::open(binding).unwrap_or_else(|e| panic!("open: {:?}", e.error()))
}
fn complete_chain(tx: &NativeTransactions) {
    let state = tx.readstate().unwrap();
    tx.validate_complete_chain(&state).unwrap();
}
fn successor(tx: &NativeTransactions, id: &str, sequence: u64) -> Vec<u8> {
    let mut target = tx.readstate().unwrap().state().clone();
    target.revision += 1;
    target.last_transaction = Some(NativeStateTransaction {
        transaction_id: id.try_into().unwrap(),
        sequence,
    });
    // Ordinary desired transaction leaves immutable bootstrap/current/history
    // untouched. Stopped is intentionally preserved for the next update.
    serde_json::to_vec(&target).unwrap()
}
#[test]
#[ignore = "test-only subprocess; parent aggregate supplies the exact owned fixture and fault"]
fn runtime_update_interruption_child() {
    let base = PathBuf::from(std::env::var_os("STYX_TEST_NATIVE_RUNTIME_UPDATE_CASE").unwrap());
    let packages =
        PathBuf::from(std::env::var_os("STYX_TEST_NATIVE_RUNTIME_UPDATE_PACKAGES").unwrap());
    let fault = std::env::var("STYX_TEST_NATIVE_RUNTIME_UPDATE_FAULT").unwrap();
    let mut tx = open(&base);
    tx.update_runtime_observing(
        verified(&packages, "bootstrap"),
        verified(&packages, "new"),
        ID.try_into().unwrap(),
        1,
        &|record, phase| {
            if fault == format!("{record}.{phase}") {
                std::process::exit(86);
            }
        },
    )
    .unwrap();
    panic!("requested persisted-step interruption was not observed");
}
fn interrupt(base: &Path, packages: &Path, fault: &str) {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "store::native_transaction::runtime_update::tests::runtime_update_interruption_child",
            "--ignored",
            "--nocapture",
        ])
        .env("STYX_TEST_NATIVE_RUNTIME_UPDATE_CASE", base)
        .env("STYX_TEST_NATIVE_RUNTIME_UPDATE_PACKAGES", packages)
        .env("STYX_TEST_NATIVE_RUNTIME_UPDATE_FAULT", fault)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert_eq!(status.code(), Some(86), "actual child exit at {fault}");
            assert_eq!(child.wait().unwrap().code(), Some(86));
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let actual = child.wait().unwrap();
            panic!("owned child deadline; actualwait={actual}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
#[test]
#[ignore = "requires fresh STYX_TEST_NATIVE_RUNTIME_UPDATE_ROOT; real protected C07, signed synthetic C08, actual process-exit recovery"]
fn runtime_update_interruption_and_forward_rollback_batch() {
    let base = PathBuf::from(std::env::var_os("STYX_TEST_NATIVE_RUNTIME_UPDATE_ROOT").unwrap());
    assert!(base.is_absolute());
    directory(&base);
    let key = SigningKey::from_bytes(&[37u8; 32]);
    let foreign = SigningKey::from_bytes(&[91u8; 32]);
    let bootstrap = candidate(&base, "bootstrap", &key, false);
    let next = candidate(&base, "new", &key, true);
    let rollback = candidate(&base, "rollback", &key, true);
    let _foreign = candidate(&base, "foreign", &foreign, true);
    let identity = DevicePrivateKey::generate_rsa3072().unwrap();
    for (index, fault) in ["prepared.persisted", "canonical.directory_sync"]
        .into_iter()
        .enumerate()
    {
        let case = base.join(format!("case-{index}"));
        let tx = create(&case, &bootstrap, identity.protected_pkcs8_pem());
        let marker = fs::read(case.join("native/.styx-native-root-v1.json")).unwrap();
        let original = tx.readstate().unwrap().raw_bytes().to_vec();
        drop(tx);
        interrupt(&case, &base, fault);
        let mut tx = open(&case);
        let id: TransactionId = ID.try_into().unwrap();
        assert_eq!(
            tx.runtime_update_selections(&id).unwrap(),
            Some((bootstrap.clone(), next.clone()))
        );
        assert_eq!(
            tx.recover_original(&id),
            Err(NativeTransactionError::UnknownInspect),
            "incomplete update cannot use generic recovery"
        );
        assert!(tx.configuration_root().ensure_admission().is_err());
        assert_eq!(
            tx.query(&id).unwrap().unwrap().intent.reader,
            ReaderContract::NativeRuntimeSelectedStateV1
        );
        if index == 0 {
            assert_eq!(tx.readstate().unwrap().raw_bytes(), original);
        } else {
            assert_eq!(
                tx.readstate().unwrap().state().schema,
                NATIVE_RUNTIME_SELECTED_STATE_SCHEMA
            );
        }
        let result = tx
            .recover_runtime_update(verified(&base, "bootstrap"), verified(&base, "new"), &id)
            .unwrap();
        assert!(result.recovered);
        assert_eq!(result.committed.stage, DurableStage::Committed);
        assert_eq!(tx.readstate().unwrap().state().revision, 1);
        complete_chain(&tx);
        assert_eq!(
            fs::read(case.join("native/.styx-native-root-v1.json")).unwrap(),
            marker
        );
        assert_eq!(
            fs::read(case.join("native/host-identity.pem")).unwrap(),
            identity.protected_pkcs8_pem()
        );
        drop(tx);
        let retired_locator = base.join("bootstrap-temporarily-unavailable");
        fs::rename(base.join("bootstrap"), &retired_locator).unwrap();
        assert!(release::verify_selected(&bootstrap).is_err());
        let mut tx = open(&case);
        let complete = tx.recover_original(&id).unwrap();
        assert!(complete.recovered);
        complete_chain(&tx);
        fs::rename(&retired_locator, base.join("bootstrap")).unwrap();
        let state = tx.readstate().unwrap();
        assert_eq!(
            state.state().runtime_selection().unwrap(),
            Some(next.clone())
        );
        assert_eq!(
            state
                .state()
                .runtime_update()
                .unwrap()
                .unwrap()
                .bootstrap_runtime,
            bootstrap
        );
        let mut forged = state.state().clone();
        forged.revision += 1;
        forged.last_transaction = Some(NativeStateTransaction {
            transaction_id: "forged-selection".try_into().unwrap(),
            sequence: 2,
        });
        forged.extensions.insert(
            NATIVE_RUNTIME_SELECTION_KEY.into(),
            serde_json::value::to_raw_value(&rollback).unwrap(),
        );
        assert_eq!(
            tx.apply_target(&serde_json::to_vec(&forged).unwrap()),
            Err(NativeTransactionError::InvalidInput)
        );
        tx.apply_target(&successor(&tx, "ordinary-successor", 2))
            .unwrap();
        complete_chain(&tx);
        let before_rejections = tx.readstate().unwrap().raw_bytes().to_vec();
        drop(tx);
        // Reopening a completed update is pure chain reconciliation; no permanent
        // dependence on the superseded bootstrap locator is introduced.
        let mut tx = open(&case);
        tx.recover_original(&"ordinary-successor".try_into().unwrap())
            .unwrap();
        assert_eq!(
            tx.update_runtime(
                verified(&base, "new"),
                verified(&base, "foreign"),
                "wrong-publisher".try_into().unwrap(),
                3
            ),
            Err(NativeTransactionError::InvalidInput)
        );
        assert_eq!(tx.readstate().unwrap().raw_bytes(), before_rejections);
        drop(tx);
        let mut tx = open(&case);
        tx.recover_original(&"ordinary-successor".try_into().unwrap())
            .unwrap();
        // The old legal package cannot become a schema3 target: its signed
        // reader declaration supports only the original state contract.
        assert!(
            !verified(&base, "bootstrap")
                .supports_state_reader(ReaderContract::NativeRuntimeSelectedStateV1)
                .unwrap()
        );
        assert_eq!(
            tx.update_runtime(
                verified(&base, "new"),
                verified(&base, "bootstrap"),
                "old-reader-target".try_into().unwrap(),
                3
            ),
            Err(NativeTransactionError::InvalidInput)
        );
        assert_eq!(tx.readstate().unwrap().raw_bytes(), before_rejections);
        drop(tx);
        let root = PrivateRoot::open(case.join("native")).unwrap();
        let executing = root.try_execution_lease().unwrap();
        let mut tx = open(&case);
        tx.recover_original(&"ordinary-successor".try_into().unwrap())
            .unwrap();
        assert_eq!(
            tx.update_runtime(
                verified(&base, "new"),
                verified(&base, "rollback"),
                "live-execution".try_into().unwrap(),
                3
            ),
            Err(NativeTransactionError::Conflict)
        );
        assert_eq!(tx.readstate().unwrap().raw_bytes(), before_rejections);
        drop(tx);
        executing.validate().unwrap();
        drop(executing);
        let mut tx = open(&case);
        tx.recover_original(&"ordinary-successor".try_into().unwrap())
            .unwrap();
        let rollback_id: TransactionId = "compatible-forward-rollback".try_into().unwrap();
        tx.update_runtime(
            verified(&base, "new"),
            verified(&base, "rollback"),
            rollback_id.clone(),
            3,
        )
        .unwrap();
        let final_state = tx.readstate().unwrap();
        assert_eq!(final_state.state().revision, 3);
        assert_eq!(
            final_state.state().runtime_selection().unwrap(),
            Some(rollback.clone())
        );
        let history = final_state.state().runtime_update().unwrap().unwrap();
        assert_eq!(history.bootstrap_runtime, bootstrap);
        assert_eq!(history.previous_runtime, next);
        assert_eq!(history.transaction.transaction_id, rollback_id);
        assert_eq!(
            tx.query(&id)
                .unwrap()
                .unwrap()
                .phase_receipts
                .last()
                .unwrap()
                .stage,
            DurableStage::Committed
        );
        assert_eq!(tx.journal.observe().unwrap().transactions.len(), 3);
        complete_chain(&tx);
        assert_eq!(
            fs::read(case.join("native/.styx-native-root-v1.json")).unwrap(),
            marker
        );
        assert_eq!(
            fs::read(case.join("native/host-identity.pem")).unwrap(),
            identity.protected_pkcs8_pem()
        );
    }
    // Retain every original fixture and interrupted journal for independent read.
}

#[test]
fn app_scope_update_retains_original_writer_and_recovers_exact_transaction() {
    use std::{
        panic::{AssertUnwindSafe, catch_unwind},
        sync::Arc,
    };
    let base =
        std::env::temp_dir().join(format!("styx-app-runtime-update-{}", uuid::Uuid::new_v4()));
    directory(&base);
    let key = SigningKey::from_bytes(&[63; 32]);
    let initial = candidate(&base, "initial-app", &key, false);
    let target = candidate_reader(
        &base,
        "selected-app",
        &key,
        "native_app_runtime_selected_v1",
    );
    candidate(&base, "fore-only", &key, true);
    let identity = b"synthetic original private identity, never exported";
    let parent = base.join("app-container");
    let mut tx = create_for_manager(&parent, &initial, identity, NativeManager::AppManaged);
    let scope = Arc::new(crate::app::HostScope::open_for_test(&parent.join("native")).unwrap());
    let foreign_parent = base.join("foreign-container");
    let foreign_tx = create_for_manager(
        &foreign_parent,
        &initial,
        identity,
        NativeManager::AppManaged,
    );
    let foreign_scope =
        Arc::new(crate::app::HostScope::open_for_test(&foreign_parent.join("native")).unwrap());
    let id: TransactionId = "app-original-update".try_into().unwrap();
    let before = tx.readstate().unwrap().raw_sha256();
    assert!(
        tx.update_runtime_for_app(
            verified(&base, "initial-app"),
            verified(&base, "selected-app"),
            id.clone(),
            1,
            foreign_scope.clone()
        )
        .is_err()
    );
    assert_eq!(tx.readstate().unwrap().raw_sha256(), before);
    assert!(!tx.has_runtime_update_custody());
    // Lose only the response after the real original commit. The coordinator,
    // C08 observations, actual scope and execution lock remain in this process.
    let lost = catch_unwind(AssertUnwindSafe(|| {
        tx.update_runtime_scoped_observing(
            verified(&base, "initial-app"),
            verified(&base, "selected-app"),
            id.clone(),
            1,
            Some(scope.clone()),
            &|stage, event| {
                if (stage, event) == ("committed", "reply") {
                    panic!("synthetic_original_reply_loss");
                }
            },
        )
    }));
    assert!(lost.is_err());
    assert!(tx.has_runtime_update_custody());
    // finish_native already ran: response loss does not recreate a recovery
    // fence, but the original C08/execution custody must still be settled.
    assert!(tx.configuration_root().ensure_admission().is_ok());
    assert!(tx.retained_maintenance.is_none());
    assert_eq!(
        tx.query(&id)
            .unwrap()
            .unwrap()
            .phase_receipts
            .last()
            .unwrap()
            .stage,
        DurableStage::Committed
    );
    assert!(matches!(
        PrivateRoot::open(parent.join("native"))
            .unwrap()
            .try_configuration_writer(),
        Err(crate::store::StoreError::Busy(_))
    ));
    assert!(
        tx.recover_retained_runtime_update_for_app(&foreign_scope, &id)
            .is_err()
    );
    let wrong: TransactionId = "foreign-update-id".try_into().unwrap();
    assert!(
        tx.recover_retained_runtime_update_for_app(&scope, &wrong)
            .is_err()
    );
    assert!(tx.has_runtime_update_custody());
    let recovered = tx
        .recover_retained_runtime_update_for_app(&scope, &id)
        .unwrap();
    assert!(recovered.recovered);
    assert_eq!(recovered.transaction_id, id);
    let current = tx.readstate().unwrap();
    assert_eq!(
        current.state().schema,
        NATIVE_APP_RUNTIME_SELECTED_STATE_SCHEMA
    );
    assert_eq!(
        current.state().reader_contract,
        ReaderContract::NativeAppRuntimeSelectedStateV1
    );
    assert_eq!(
        current.state().runtime_selection().unwrap().unwrap(),
        target
    );
    assert!(!tx.has_runtime_update_custody());
    complete_chain(&tx);
    // The same confirmation also serves an ordinary desired-state stop reply,
    // without runtime custody, new phases, or reopening the writer.
    let desired_id: TransactionId = "app-original-desired".try_into().unwrap();
    let desired = successor(&tx, desired_id.as_str(), 2);
    let applied = tx.apply_target(&desired).unwrap();
    let phases = tx.query(&desired_id).unwrap().unwrap().phase_receipts;
    let confirmed = tx.recover_original(&desired_id).unwrap();
    assert_eq!(confirmed.committed, applied.committed);
    assert!(confirmed.recovered);
    assert_eq!(
        tx.query(&desired_id).unwrap().unwrap().phase_receipts,
        phases
    );
    assert_eq!(tx.readstate().unwrap().raw_bytes(), desired);
    assert!(tx.configuration_root().ensure_admission().is_ok());
    assert!(tx.recover_original(&id).is_err());
    assert!(tx.configuration_root().ensure_admission().is_ok());
    assert_eq!(
        fs::read(parent.join("native/host-identity.pem")).unwrap(),
        identity
    );
    // A foreground-only new reader cannot be projected into App schema4.
    let bad_parent = base.join("wrong-reader-container");
    let mut bad = create_for_manager(&bad_parent, &initial, identity, NativeManager::AppManaged);
    let bad_scope =
        Arc::new(crate::app::HostScope::open_for_test(&bad_parent.join("native")).unwrap());
    let original = bad.readstate().unwrap().raw_sha256();
    assert!(
        bad.update_runtime_for_app(
            verified(&base, "initial-app"),
            verified(&base, "fore-only"),
            "wrong-reader".try_into().unwrap(),
            1,
            bad_scope
        )
        .is_err()
    );
    assert_eq!(bad.readstate().unwrap().raw_sha256(), original);
    assert!(
        bad.query(&"wrong-reader".try_into().unwrap())
            .unwrap()
            .is_none()
    );
    // Running desired intent is rejected even if no process is currently live.
    let run_parent = base.join("running-container");
    let mut running =
        create_for_manager(&run_parent, &initial, identity, NativeManager::AppManaged);
    let run_scope =
        Arc::new(crate::app::HostScope::open_for_test(&run_parent.join("native")).unwrap());
    let mut bytes = running.readstate().unwrap().state().clone();
    bytes.revision += 1;
    bytes.last_transaction = Some(NativeStateTransaction {
        transaction_id: "running-desired".try_into().unwrap(),
        sequence: 1,
    });
    bytes.desired.host.as_mut().unwrap().run = NativeRunDesired::Running;
    running
        .apply_target(&serde_json::to_vec(&bytes).unwrap())
        .unwrap();
    let original = running.readstate().unwrap().raw_sha256();
    assert!(
        running
            .update_runtime_for_app(
                verified(&base, "initial-app"),
                verified(&base, "selected-app"),
                "running-update".try_into().unwrap(),
                2,
                run_scope
            )
            .is_err()
    );
    assert_eq!(running.readstate().unwrap().raw_sha256(), original);
    assert!(
        running
            .query(&"running-update".try_into().unwrap())
            .unwrap()
            .is_none()
    );
    drop(foreign_tx);
    // All private fixture files and failed observations intentionally remain.
}

// A descendant reuses only the existing disposable signed-fixture builders.
#[path = "native_app_service_tests.rs"]
mod app_service_tests;
