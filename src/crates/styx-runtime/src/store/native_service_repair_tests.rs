//! Darwin protected-file C07 evidence only. Synthetic selection/registration
//! DATA does not establish signed C08 trust, launchd custody or administrator
//! settlement. No OS service or executable is started by this batch.
use super::*;
use crate::store::{PrivateRoot, native_root};
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs,
    io::Write as _,
    os::unix::fs::DirBuilderExt as _,
    path::{Path, PathBuf},
    sync::Arc,
};
use styx_contracts::native_management::*;

const DEPLOYMENT: &[u8] = b"{\"service_repair_file_fixture\":true}\n";
const ID: &str = "original-service-repair";
fn directory(path: &Path) {
    fs::DirBuilder::new().mode(0o700).create(path).unwrap();
}
fn create(base: &Path) -> NativeTransactions {
    directory(base);
    let parent = PrivateRoot::open(base).unwrap();
    let fresh = native_root::create_fresh(&parent, OsStr::new("native"))
        .unwrap_or_else(|e| panic!("fresh: {:?}", e.error()));
    let selection = NativeRuntimeSelection {
        schema: 1,
        payload_path: base.join("synthetic-A").to_str().unwrap().into(),
        payload_root: fresh.marker().root_identity.clone(),
        manifest_sha256: Sha256Digest::of_bytes(b"synthetic A manifest DATA"),
        publisher_file: base
            .join("synthetic-publisher.pem")
            .to_str()
            .unwrap()
            .into(),
        publisher_spki_sha256: Sha256Digest::of_bytes(b"synthetic publisher DATA"),
    };
    let state = NativeState {
        schema: 2,
        kind: NativeStateKind::StyxDesiredState,
        runtime_format: NativeRuntimeFormat::NativeRustV1,
        reader_contract: ReaderContract::NativeManagementStateV1,
        scope_generation: fresh.marker().scope_generation,
        deployment_raw_sha256: Sha256Digest::of_bytes(DEPLOYMENT),
        mode: NativeDeploymentMode::CreateLocal,
        revision: 0,
        last_transaction: None,
        desired: NativeDesired {
            host: None,
            gateway: Some(NativeComponentDesired {
                manager: NativeManager::PersistentService,
                run: NativeRunDesired::Stopped,
                autostart: NativeAutostartDesired::Disabled,
            }),
        },
        migration: None,
        extensions: BTreeMap::from([(
            NATIVE_RUNTIME_SELECTION_KEY.into(),
            serde_json::value::to_raw_value(&selection).unwrap(),
        )]),
    };
    let binding = fresh
        .initialize(DEPLOYMENT, &state)
        .unwrap_or_else(|e| panic!("initialize: {:?}", e.error()));
    NativeTransactions::open(binding).unwrap_or_else(|e| panic!("open: {:?}", e.error()))
}
fn open(base: &Path) -> NativeTransactions {
    let root = PrivateRoot::open(base.join("native")).unwrap();
    let writer = root.try_configuration_writer().unwrap();
    let binding = native_root::reopen_native(root, writer)
        .unwrap_or_else(|e| panic!("cold binding: {:?}", e.error()));
    NativeTransactions::open(binding).unwrap_or_else(|e| panic!("cold journal: {:?}", e.error()))
}
fn materials(tx: &NativeTransactions) -> (Vec<u8>, Vec<u8>, DesiredStateCommit) {
    let before = tx.readstate().unwrap();
    let old = before.state().runtime_selection().unwrap().unwrap();
    let mut next = old.clone();
    next.payload_path = format!("{}-B", old.payload_path);
    next.manifest_sha256 = Sha256Digest::of_bytes(b"synthetic B manifest DATA");
    let NativeRootIdentity::Macos { device, inode, uid } = tx.marker().root_identity else {
        panic!("Darwin root required")
    };
    assert_ne!(uid, 0, "ordinary UID fixture required");
    let label_hash = Sha256Digest::of_bytes(
        format!("styx-native-system-service-v1:{device}:{inode}:{uid}").as_bytes(),
    )
    .to_hex();
    let program = format!("{}/bin/styx", old.payload_path);
    let binding = NativeServiceRepairBinding {
        schema: 1,
        old_definition_identity: NativeServiceDefinitionIdentity {
            device,
            inode: 88,
            uid: 0,
            mode: 0o644,
            links: 1,
        },
        old_definition_sha256: Sha256Digest::of_bytes(b"synthetic original plist DATA"),
        original_registration: NativeServiceRegistrationObservation {
            path: PathBuf::from(format!(
                "/Library/LaunchDaemons/app.styx.native.{uid}.{}.gateway.plist",
                &label_hash[..32]
            )),
            program: PathBuf::from(&program),
            username: "fixture".into(),
            arguments: vec![
                program,
                "__service-run".into(),
                "--state-dir".into(),
                old.payload_path.clone(),
                "--role".into(),
                "gateway".into(),
            ],
            pid: None,
            runs: 3,
            last_exit_code: Some(78),
            signaled_exit: false,
            state: "not running".into(),
        },
    };
    let mut target = before.state().clone();
    target.schema = NATIVE_SERVICE_RUNTIME_SELECTED_STATE_SCHEMA;
    target.reader_contract = ReaderContract::NativeServiceRuntimeSelectedStateV1;
    target.revision += 1;
    let last = NativeStateTransaction {
        transaction_id: ID.try_into().unwrap(),
        sequence: 1,
    };
    target.last_transaction = Some(last.clone());
    let role = target.desired.gateway.as_mut().unwrap();
    role.run = NativeRunDesired::Running;
    role.autostart = NativeAutostartDesired::Enabled;
    target.extensions.insert(
        NATIVE_RUNTIME_SELECTION_KEY.into(),
        serde_json::value::to_raw_value(&next).unwrap(),
    );
    target.extensions.insert(
        NATIVE_RUNTIME_UPDATE_KEY.into(),
        serde_json::value::to_raw_value(&NativeRuntimeUpdate {
            schema: 1,
            bootstrap_runtime: old.clone(),
            previous_runtime: old,
            transaction: last.clone(),
            service_repair: Some(binding),
        })
        .unwrap(),
    );
    let bytes = serde_json::to_vec(&target).unwrap();
    let intent = DesiredStateCommit {
        transaction_id: last.transaction_id,
        sequence: 1,
        deployment_raw_sha256: before.state().deployment_raw_sha256,
        before_state_sha256: before.raw_sha256(),
        target_state_sha256: Sha256Digest::of_bytes(&bytes),
        reader: target.reader_contract,
    };
    styx_core::management::state::validate_service_runtime_repair_transition(
        before.state(),
        &target,
        tx.marker(),
        &intent,
    )
    .unwrap();
    (before.raw_bytes().to_vec(), bytes, intent)
}
// Persist through production protected-file ports, stopping at the requested
// durable prefix. This is intentionally not the C08/OS-proof update entrypoint.
fn persist(tx: &NativeTransactions, prefix: usize) -> (Vec<u8>, Vec<u8>, ConfigurationMaintenance) {
    let (a, b, intent) = materials(tx);
    let maintenance = tx
        .configuration_root()
        .begin_standalone_native(intent.transaction_id.clone(), false)
        .unwrap();
    let prepared = tx
        .journal
        .prepare(&maintenance, &serde_json::to_vec(&intent).unwrap(), &a, &b)
        .unwrap();
    if prefix > 0 {
        // Test-only publication deliberately supplies DATA without inventing a
        // RegisteredInactiveProof or C08 custody. Use the original writer FD,
        // journal FD, exclusive temporary and actual Darwin sync barriers.
        use crate::store::secure_journal::files;
        tx.binding
            .with_binding(|state, _| {
                state.require_native_maintenance(&intent.transaction_id)?;
                assert_eq!(
                    state
                        .root
                        .read_raw("state.json", 1024 * 1024)
                        .unwrap()
                        .bytes(),
                    a
                );
                tx.journal.with_directory_locked(state, |journal| {
                    files::immutable(
                        journal,
                        "repair-test.state-temporary",
                        &b,
                        tx.journal.budget(),
                        &|_| {},
                    )?;
                    state
                        .root
                        .inner
                        .with_configuration_writer_directory(&state.writer, |root| {
                            let result = (|| {
                                nix::fcntl::renameat(
                                    journal,
                                    "repair-test.state-temporary",
                                    root,
                                    "state.json",
                                )
                                .map_err(|_| JournalError::Unknown)?;
                                files::sync_file(root, "state.json")?;
                                files::sync_directory(root)?;
                                files::sync_directory(journal)
                            })();
                            Ok(result)
                        })
                        .map_err(|_| JournalError::Unknown)?
                })
            })
            .unwrap();
    }
    let mut head = prepared.journal.record_sha256;
    for stage in [
        DurableStage::Applied,
        DurableStage::Verified,
        DurableStage::Committed,
    ]
    .into_iter()
    .take(prefix.saturating_sub(1))
    {
        head = tx
            .journal
            .append_phase(&maintenance, &intent, stage, head, false)
            .unwrap()
            .record_sha256;
    }
    (a, b, maintenance)
}
fn assert_writer_held(base: &Path) {
    let root = PrivateRoot::open(base.join("native")).unwrap();
    assert!(
        root.try_configuration_writer().is_err(),
        "original authority must retain writer"
    );
}
fn overwrite(path: &Path, bytes: &[u8]) {
    // Deliberate hostile mutation of this batch's own file, not a recovery port.
    let mut file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
fn original_material(base: &Path, bytes: &[u8]) -> PathBuf {
    let journal = base.join("native/.styx-management-journal-v1");
    let matches: Vec<_> = fs::read_dir(journal)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_file() && fs::read(p).unwrap() == bytes)
        .collect();
    assert_eq!(matches.len(), 1);
    matches.into_iter().next().unwrap()
}

#[test]
#[ignore = "requires explicit owned Darwin private STYX_TEST_NATIVE_SERVICE_REPAIR_ROOT"]
fn native_service_repair_original_cold_protected_file_batch() {
    let parent = PathBuf::from(
        std::env::var_os("STYX_TEST_NATIVE_SERVICE_REPAIR_ROOT")
            .expect("explicit private parent required"),
    );
    let _parent_pin = PrivateRoot::open(&parent).unwrap();
    let batch = parent.join(format!("service-repair-files-{}", uuid::Uuid::new_v4()));
    directory(&batch);
    let id: TransactionId = ID.try_into().unwrap();
    let foreign_base = batch.join("foreign");
    let foreign = create(&foreign_base);
    for prefix in 0..=4 {
        let base = batch.join(format!("prefix-{prefix}"));
        let tx = create(&base);
        let marker = fs::read(base.join("native/.styx-native-root-v1.json")).unwrap();
        let (a, b, maintenance) = persist(&tx, prefix);
        drop(maintenance);
        drop(tx); // Actual original writer/namespace destruction before cold open.
        let tx = open(&base);
        let frame = tx.original_service_runtime_repair(&id).unwrap();
        assert!(
            Arc::ptr_eq(&frame.journal, &tx.journal),
            "must reuse the already-claimed namespace"
        );
        frame.validate_owner(&tx.configuration_root()).unwrap();
        assert!(frame.validate_owner(&foreign.configuration_root()).is_err());
        assert_eq!(frame.initially_committed(), prefix == 4);
        assert_eq!(frame.before_bytes(), a);
        assert_eq!(frame.target_bytes(), b);
        assert_eq!(frame.transaction_id(), &id);
        assert_eq!(frame.target().revision, 1);
        assert_eq!(frame.binding().original_registration.runs, 3);
        assert_eq!(
            fs::read(base.join("native/state.json")).unwrap(),
            if prefix == 0 { a.clone() } else { b.clone() }
        );
        assert_eq!(
            fs::read(base.join("native/.styx-native-root-v1.json")).unwrap(),
            marker
        );
        assert_writer_held(&base);
        // A retained opaque frame also retains the original writer after its
        // coordinator is dropped; it is not a deserializable authorization DTO.
        drop(tx);
        assert_writer_held(&base);
        drop(frame);
        let reopened = open(&base);
        assert_eq!(
            reopened
                .original_service_runtime_repair(&id)
                .unwrap()
                .initially_committed(),
            prefix == 4
        );
    }
    // An already-issued incomplete frame must not become an initially-Committed
    // frame when its SAME coordinator later persists the remaining phases.
    let base = batch.join("same-owner-advance");
    let tx = create(&base);
    let (a, b, maintenance) = persist(&tx, 1);
    let frame = tx.original_service_runtime_repair(&id).unwrap();
    assert!(!frame.initially_committed());
    let original = tx.journal.read_original(&id).unwrap();
    let mut head = original.phases.last().unwrap().record_sha256;
    for stage in [
        DurableStage::Applied,
        DurableStage::Verified,
        DurableStage::Committed,
    ] {
        head = tx
            .journal
            .append_phase(&maintenance, &original.intent, stage, head, true)
            .unwrap()
            .record_sha256;
        frame.validate_owner(&tx.configuration_root()).unwrap();
        assert!(!frame.initially_committed());
    }
    assert!(
        tx.original_service_runtime_repair(&id)
            .unwrap()
            .initially_committed()
    );
    assert_eq!(frame.before_bytes(), a);
    assert_eq!(frame.target_bytes(), b);
    // Independent adversarial cases preserve the failed original owner/writer.
    for kind in [
        "before",
        "target",
        "canonical",
        "applied-before",
        "receipt",
        "orphan",
    ] {
        let base = batch.join(format!("tamper-{kind}"));
        let tx = create(&base);
        let (a, b, _maintenance) = persist(
            &tx,
            if matches!(kind, "applied-before" | "receipt") {
                2
            } else {
                1
            },
        );
        let frame = tx.original_service_runtime_repair(&id).unwrap();
        match kind {
            "before" => overwrite(&original_material(&base, &a), b"{}"),
            "target" => overwrite(&original_material(&base, &b), b"{}"),
            "canonical" => overwrite(&base.join("native/state.json"), b"{}\n"),
            "applied-before" => overwrite(&base.join("native/state.json"), &a),
            "receipt" => {
                let dir = base.join("native/.styx-management-journal-v1");
                let paths: Vec<_> = fs::read_dir(dir)
                    .unwrap()
                    .map(|e| e.unwrap().path())
                    .filter(|p| p.file_name().unwrap().to_str().unwrap().contains("applied"))
                    .collect();
                assert_eq!(paths.len(), 1);
                overwrite(&paths[0], b"{}\n");
            }
            "orphan" => {
                use std::os::unix::fs::OpenOptionsExt as _;
                fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(base.join("native/.styx-management-journal-v1/foreign-tip"))
                    .unwrap()
                    .sync_all()
                    .unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            frame.validate_owner(&tx.configuration_root()).is_err(),
            "{kind}"
        );
        assert!(tx.original_service_runtime_repair(&id).is_err(), "{kind}");
        assert_writer_held(&base);
    }
    // Fixtures intentionally remain for independent inspection; no user state,
    // launchd registration, signed payload, child process or service was used.
}
