//! Actual original C07/private roots and a disposable synthetic test publisher.
//! No native image is executed, and no installed profile or service is opened.
use super::*;
use crate::app::HostScope;
use std::sync::Arc;

fn files(path: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    fn visit(base: &Path, path: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
        let mut entries = fs::read_dir(path)
            .unwrap()
            .map(Result::unwrap)
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let metadata = fs::symlink_metadata(entry.path()).unwrap();
            assert!(!metadata.file_type().is_symlink());
            if metadata.is_dir() {
                visit(base, &entry.path(), out);
            } else {
                out.push((
                    entry.path().strip_prefix(base).unwrap().to_owned(),
                    fs::read(entry.path()).unwrap(),
                ));
            }
        }
    }
    let mut result = Vec::new();
    visit(path, path, &mut result);
    result
}
fn app_case(base: &Path, bootstrap: &NativeRuntimeSelection) -> NativeTransactions {
    directory(base);
    let parent = PrivateRoot::open(base).unwrap();
    let fresh = native_root::create_fresh(&parent, OsStr::new("native"))
        .unwrap_or_else(|error| panic!("fresh: {:?}", error.error()));
    let state = NativeState {
        schema: 2, kind: NativeStateKind::StyxDesiredState, runtime_format: NativeRuntimeFormat::NativeRustV1,
        reader_contract: ReaderContract::NativeManagementStateV1,
        scope_generation: fresh.marker().scope_generation, deployment_raw_sha256: Sha256Digest::of_bytes(DEPLOYMENT),
        mode: NativeDeploymentMode::JoinExisting, revision: 0, last_transaction: None,
        desired: NativeDesired { gateway: None, host: Some(NativeComponentDesired {
            manager: NativeManager::AppManaged, run: NativeRunDesired::Stopped, autostart: NativeAutostartDesired::Disabled,
        }) }, migration: None,
        extensions: BTreeMap::from([
            (NATIVE_RUNTIME_SELECTION_KEY.into(), serde_json::value::to_raw_value(bootstrap).unwrap()),
            ("opaque_transfer_fixture".into(), serde_json::value::RawValue::from_string(
                "{\"large\":123456789012345678901234567890,\"exponent\":1e999,\"spacing\": [ true, null ]}".into()).unwrap()),
        ]),
    };
    let binding = fresh
        .initialize(DEPLOYMENT, &state)
        .unwrap_or_else(|error| panic!("initialize: {:?}", error.error()));
    write(
        &base.join("native/host-identity.pem"),
        b"private identity fixture; not an enrolled Host",
        false,
    );
    NativeTransactions::open(binding).unwrap_or_else(|error| panic!("open: {:?}", error.error()))
}
#[test]
#[ignore = "requires fresh STYX_TEST_APP_SERVICE_TRANSFER_ROOT; real private roots/C07 and disposable signed synthetic C08, no native execution"]
fn original_app_scope_transfer_preserves_c07_and_refuses_generic_or_other_root_authority() {
    let base = PathBuf::from(std::env::var_os("STYX_TEST_APP_SERVICE_TRANSFER_ROOT").unwrap());
    assert!(base.is_absolute());
    directory(&base);
    let key = SigningKey::from_bytes(&[63u8; 32]);
    let bootstrap = candidate_reader(
        &base,
        "bootstrap",
        &key,
        "native_app_service_transferred_v1",
    );
    let container = base.join("container");
    let mut transactions = app_case(&container, &bootstrap);
    let scope = Arc::new(HostScope::open_for_test(&container.join("native")).unwrap());
    let versions = container.join("runtime-versions");
    directory(&versions);
    let next = candidate_reader(
        &versions,
        "staged",
        &key,
        "native_app_service_transferred_v1",
    );
    transactions
        .update_runtime_for_app(
            release::verify_selected(&bootstrap).unwrap(),
            release::verify_selected(&next).unwrap(),
            "original-app-runtime-update".try_into().unwrap(),
            1,
            scope.clone(),
        )
        .unwrap();
    let original = transactions.readstate().unwrap();
    assert_eq!(
        original.state().reader_contract,
        ReaderContract::NativeAppRuntimeSelectedStateV1
    );
    let before_raw = original.raw_bytes().to_vec();
    let root_before = files(&container.join("native"));
    let marker_before = fs::read(container.join("native/.styx-native-root-v1.json")).unwrap();
    let identity_before = fs::read(container.join("native/host-identity.pem")).unwrap();
    let opaque_before = original.state().extensions["opaque_transfer_fixture"]
        .get()
        .to_owned();
    let selection_before = original.state().extensions[NATIVE_RUNTIME_SELECTION_KEY]
        .get()
        .to_owned();
    let history_before = original.state().extensions[NATIVE_RUNTIME_UPDATE_KEY]
        .get()
        .to_owned();
    let mut untrusted_target = original.state().clone();
    untrusted_target.schema = NATIVE_APP_SERVICE_TRANSFERRED_STATE_SCHEMA;
    untrusted_target.reader_contract = ReaderContract::NativeAppServiceTransferredStateV1;
    untrusted_target.revision += 1;
    untrusted_target.desired.host.as_mut().unwrap().manager = NativeManager::PersistentService;
    untrusted_target.last_transaction = Some(NativeStateTransaction {
        transaction_id: "generic-cannot-mint-transfer".try_into().unwrap(),
        sequence: 2,
    });
    assert_eq!(
        transactions.apply_target(&serde_json::to_vec(&untrusted_target).unwrap()),
        Err(NativeTransactionError::InvalidInput)
    );
    assert_eq!(files(&container.join("native")), root_before);
    let foreign_container = base.join("foreign-container");
    let foreign_transactions = app_case(&foreign_container, &bootstrap);
    let foreign_scope =
        Arc::new(HostScope::open_for_test(&foreign_container.join("native")).unwrap());
    assert_eq!(
        transactions.transfer_app_to_service(
            foreign_scope.clone(),
            release::verify_selected(&next).unwrap(),
            "other-root-cannot-transfer".try_into().unwrap(),
            2
        ),
        Err(NativeTransactionError::Conflict)
    );
    assert_eq!(transactions.readstate().unwrap().raw_bytes(), before_raw);
    assert_eq!(files(&container.join("native")), root_before);
    assert!(!transactions.has_app_service_custody());
    let original_root = PrivateRoot::open(container.join("native"))
        .unwrap()
        .identity();
    let receipt = transactions
        .transfer_app_to_service(
            scope.clone(),
            release::verify_selected(&next).unwrap(),
            "original-app-service-transfer".try_into().unwrap(),
            2,
        )
        .unwrap();
    let after = transactions.readstate().unwrap();
    transactions.validate_complete_chain(&after).unwrap();
    assert_eq!(receipt.committed.stage, DurableStage::Committed);
    assert_eq!(after.raw_sha256(), receipt.canonical_raw_sha256);
    assert_eq!(
        after.state().reader_contract,
        ReaderContract::NativeAppServiceTransferredStateV1
    );
    assert_eq!(
        after.state().desired.host.unwrap().manager,
        NativeManager::PersistentService
    );
    assert_eq!(
        after.state().extensions["opaque_transfer_fixture"].get(),
        opaque_before
    );
    assert_eq!(
        after.state().extensions[NATIVE_RUNTIME_SELECTION_KEY].get(),
        selection_before
    );
    assert_eq!(
        after.state().extensions[NATIVE_RUNTIME_UPDATE_KEY].get(),
        history_before
    );
    assert_eq!(
        fs::read(container.join("native/.styx-native-root-v1.json")).unwrap(),
        marker_before
    );
    assert_eq!(
        fs::read(container.join("native/deployment.json")).unwrap(),
        DEPLOYMENT
    );
    assert_eq!(
        fs::read(container.join("native/host-identity.pem")).unwrap(),
        identity_before
    );
    assert_eq!(
        PrivateRoot::open(container.join("native"))
            .unwrap()
            .identity(),
        original_root
    );
    assert!(!transactions.has_app_service_custody());
    let read_root = PrivateRoot::open(container.join("native")).unwrap();
    let after_files = files(&container.join("native"));
    assert_eq!(
        crate::store::native_host_snapshot::validated_runtime_selection(
            &read_root,
            &after,
            transactions.marker(),
        )
        .unwrap(),
        next
    );
    assert_eq!(files(&container.join("native")), after_files);
    // The complete readonly C07 reader above succeeds while this original
    // configuration writer remains held, as required by service-client mode.
    // Exact committed readback releases the execution exclusion; the existing
    // C07 writer still belongs to this original transactions object.
    let exclusion = PrivateRoot::open(container.join("native"))
        .unwrap()
        .try_execution_lease()
        .unwrap();
    exclusion.validate().unwrap();
    drop(exclusion);
    assert!(
        PrivateRoot::open(container.join("native"))
            .unwrap()
            .try_existing_configuration_writer()
            .is_err()
    );
    drop(transactions);
    drop(scope);
    drop(foreign_transactions);
    drop(foreign_scope);
    let reopened_root = PrivateRoot::open(container.join("native")).unwrap();
    let writer = reopened_root.try_existing_configuration_writer().unwrap();
    let binding = native_root::reopen_native(reopened_root, writer)
        .unwrap_or_else(|error| panic!("reopen: {:?}", error.error()));
    let reopened = NativeTransactions::open(binding)
        .unwrap_or_else(|error| panic!("transactions: {:?}", error.error()));
    transactions_readonly_tip(&reopened);
    assert_eq!(
        reopened.readstate().unwrap().raw_sha256(),
        receipt.canonical_raw_sha256
    );
    drop(reopened);
    fs::remove_dir_all(&base).unwrap();
    println!(
        "original_scope_transfer=committed; generic_and_other_root=refused; opaque_selection_history_identity=preserved; execution_exclusion=released_after_readback; service_registration=NOT_ATTEMPTED; native_execution=NOT_ATTEMPTED"
    );
}
fn transactions_readonly_tip(transactions: &NativeTransactions) {
    let state = transactions.readstate().unwrap();
    transactions.validate_complete_chain(&state).unwrap();
}
