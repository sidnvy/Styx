//! Real signed C08 + completed strict-TLS local enrollment and original C07.
//! No installed root, Host executor, publisher private key or canonical edit.
use super::*;
use crate::{release, store::native_host_snapshot, store::native_state};
use std::{
    ffi::OsStr,
    fs,
    io::Write as _,
    os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _},
};
use styx_contracts::{
    identity::Sha256Digest,
    management::ReaderContract,
    native_management::{NATIVE_MARKER_BYTES, NATIVE_STATE_BYTES, NativeRuntimeSelection},
};

fn raw(value: Value) -> Box<serde_json::value::RawValue> {
    serde_json::value::to_raw_value(&value).unwrap()
}
fn directory(path: &Path) {
    fs::DirBuilder::new().mode(0o700).create(path).unwrap();
}
fn write_new(path: &Path, bytes: &[u8]) {
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
// Hashes avoid exposing private enrollment material if an assertion fails.
fn tree(path: &Path) -> Vec<(PathBuf, u64, String)> {
    fn visit(base: &Path, path: &Path, result: &mut Vec<(PathBuf, u64, String)>) {
        let mut entries = fs::read_dir(path)
            .unwrap()
            .map(Result::unwrap)
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let metadata = fs::symlink_metadata(entry.path()).unwrap();
            assert!(!metadata.file_type().is_symlink());
            let digest = if metadata.is_dir() {
                "directory".to_owned()
            } else {
                assert!(metadata.is_file());
                Sha256Digest::of_bytes(&fs::read(entry.path()).unwrap()).to_hex()
            };
            result.push((
                entry.path().strip_prefix(base).unwrap().to_owned(),
                metadata.ino(),
                digest,
            ));
            if metadata.is_dir() {
                visit(base, &entry.path(), result);
            }
        }
    }
    let mut result = Vec::new();
    visit(path, path, &mut result);
    result
}
fn prepare(install: &Path) -> Box<serde_json::value::RawValue> {
    raw(json!({"schema":1,"authorize":true,"operation":"upgrade",
        "requestId":uuid::Uuid::new_v4().simple().to_string(),"installRoot":install,
        "packageSha256":null,"candidatePackageSha256":null,"loginObservation":null}))
}
async fn enroll(container: &Path, selection: &NativeRuntimeSelection) -> (HostApp, PathBuf) {
    directory(container);
    let candidates = container.join("migration-candidates");
    directory(&candidates);
    let bytes = serde_json::to_vec(selection).unwrap();
    let candidate = candidates.join(format!("{}.json", Sha256Digest::of_bytes(&bytes).to_hex()));
    write_new(&candidate, &bytes);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let mut app = HostApp::open_native(&container.join("profile"), &candidate)
        .await
        .unwrap();
    // Direct existing enrollment entry avoids the UI dispatch's later Connect.
    // Only the original local Gateway executes, over strict pinned TLS.
    app.create_local(LocalInput {
        label: "App maintenance fixture".into(),
        computer: false,
        browser: false,
        browser_channel: None,
        persist_login: false,
        port,
    })
    .await
    .unwrap();
    assert_eq!(
        app.enrollment.as_ref().unwrap()["status"],
        "ready_to_connect"
    );
    assert!(app.running.is_none());
    app.settle_all().await.unwrap();
    app.set_desired(NativeRunDesired::Stopped).await.unwrap();
    assert!(app.running.is_none());
    assert!(!app.local_gateway.as_ref().unwrap().is_running());
    (app, candidate)
}
async fn await_runtime(app: &mut HostApp, expected: &str) {
    tokio::time::timeout(Duration::from_secs(150), async {
        loop {
            let status = app
                .dispatch(Operation::RuntimeUpdateStatus, raw(json!({})))
                .await
                .unwrap();
            let phase = status["runtimeUpdate"]["status"].as_str().unwrap();
            assert_ne!(phase, "unknown", "original runtime update must settle");
            if phase == expected {
                break;
            }
            assert!(matches!(phase, "staging" | "updating"));
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("original runtime update did not settle within fixture deadline");
}
fn role_history(app: &HostApp, initial: &NativeRuntimeSelection, install: &Path) {
    let gateway = app.local_gateway.as_ref().unwrap();
    for scope in [&app.scope, &gateway.scope] {
        let root = scope.root.get().unwrap();
        let marker_raw = root
            .read_raw(".styx-native-root-v1.json", NATIVE_MARKER_BYTES)
            .unwrap();
        let marker = native_state::decode_marker(marker_raw.bytes()).unwrap();
        let state_raw = root.read_raw("state.json", NATIVE_STATE_BYTES).unwrap();
        let state = native_state::decode_state(state_raw.bytes(), &marker).unwrap();
        let current =
            native_host_snapshot::validated_runtime_selection(root, &state, &marker).unwrap();
        assert!(!Path::new(&current.payload_path).starts_with(install));
        assert!(!Path::new(&current.publisher_file).starts_with(install));
        release::verify_selected(&current).unwrap();
        let history = state.state().runtime_update().unwrap().unwrap();
        assert_eq!(history.bootstrap_runtime, *initial);
        assert_eq!(history.previous_runtime, *initial);
        assert!(Path::new(&history.bootstrap_runtime.payload_path).starts_with(install));
        assert!(Path::new(&history.bootstrap_runtime.publisher_file).starts_with(install));
        assert_eq!(
            state.state().reader_contract,
            ReaderContract::NativeAppRuntimeSelectedStateV1
        );
        for role in state
            .state()
            .desired
            .host
            .iter()
            .chain(state.state().desired.gateway.iter())
        {
            assert_eq!(role.manager, NativeManager::AppManaged);
            assert_eq!(role.run, NativeRunDesired::Stopped);
            assert_eq!(role.autostart, NativeAutostartDesired::Disabled);
        }
    }
}
fn immutable_origins(container: &Path) -> Vec<(PathBuf, u64, String)> {
    tree(container)
        .into_iter()
        .filter(|(path, _, _)| {
            path.components()
                .any(|part| part.as_os_str() == ".styx-management-journal-v1")
                || matches!(
                    path.file_name().and_then(OsStr::to_str),
                    Some(
                        "host-join-seed-v1.json"
                            | "host-ready-v1.json"
                            | "gateway-ready-v1.json"
                            | "deployment.json"
                            | ".styx-native-root-v1.json"
                    )
                )
        })
        .collect()
}
fn origins_unchanged(container: &Path, origins: &[(PathBuf, u64, String)]) {
    let after = tree(container);
    for original in origins {
        assert!(
            after.contains(original),
            "original seed/Ready/deployment/C07 history changed"
        );
    }
}
async fn inside_reference_refused(
    container: &Path,
    selected: &NativeRuntimeSelection,
    install: &Path,
) {
    let (mut app, _) = enroll(container, selected).await;
    let before = tree(container);
    assert_eq!(
        app.dispatch(Operation::PrepareAppMaintenance, prepare(install))
            .await
            .unwrap_err()
            .code(),
        "app_maintenance_runtime_in_install_root"
    );
    assert!(!app.maintenance_fenced());
    let quit = app
        .dispatch(Operation::QuitAdmission, raw(json!({})))
        .await
        .unwrap();
    assert_eq!(quit["quit"]["status"], "ready_to_quit");
    assert_eq!(tree(container), before);
    drop(app);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires STYX_TEST_APP_CONTROL_SELECTION: real signed Linux native runtime supporting App-selected reader; disposable strict-TLS enrollment/C07/filesystem, no Host executor"]
async fn original_app_maintenance_distinguishes_live_c07_from_launch_and_history() {
    let selection_file = PathBuf::from(std::env::var("STYX_TEST_APP_CONTROL_SELECTION").unwrap());
    assert!(selection_file.is_absolute());
    let fixture_raw = fs::read(&selection_file).unwrap();
    let source: NativeRuntimeSelection = serde_json::from_slice(&fixture_raw).unwrap();
    let verified = release::verify_selected(&source).unwrap();
    assert!(
        verified
            .supports_state_reader(ReaderContract::NativeAppRuntimeSelectedStateV1)
            .unwrap(),
        "fixture lacks the real App-selected state reader; do not fake an updated C07"
    );
    let top =
        std::env::temp_dir().join(format!("styx-app-maintenance-c07-{}", uuid::Uuid::new_v4()));
    directory(&top);
    let install = top.join("Styx.app");
    directory(&install);
    // Existing immutable stage constructs only a disposable outer-package
    // fixture. It copies original signed bytes, never signs or activates them.
    let initial = release::stage(
        Path::new(&source.payload_path),
        Path::new(&source.publisher_file),
        &source.publisher_spki_sha256.to_hex(),
        &install,
        OsStr::new("native"),
    )
    .await
    .unwrap();
    let container = top.join("original-app");
    let (mut app, launch) = enroll(&container, &initial).await;
    let before_stage = immutable_origins(&container);
    let launch_before = fs::read(&launch).unwrap();
    assert_eq!(
        app.dispatch(Operation::PrepareAppMaintenance, prepare(&install))
            .await
            .unwrap_err()
            .code(),
        "app_maintenance_runtime_in_install_root"
    );
    app.dispatch(Operation::StageRuntime, raw(json!({"authorize":true})))
        .await
        .unwrap();
    await_runtime(&mut app, "staged").await;
    app.dispatch(
        Operation::UpdateRuntime,
        raw(json!({"authorize":true,
        "transactionId":format!("maintenance-{}", uuid::Uuid::new_v4().simple())})),
    )
    .await
    .unwrap();
    await_runtime(&mut app, "committed").await;
    assert!(app.running.is_none());
    assert!(!app.local_gateway.as_ref().unwrap().is_running());
    role_history(&app, &initial, &install);
    origins_unchanged(&container, &before_stage);
    assert!(fs::read(&launch).unwrap() == launch_before);
    let stable_before = tree(&container);
    let admission = app
        .dispatch(Operation::PrepareAppMaintenance, prepare(&install))
        .await
        .unwrap();
    let ticket = admission["maintenance"]["ticketId"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(admission["maintenance"]["status"], "prepared");
    let cancelled = app
        .dispatch(
            Operation::CancelAppMaintenance,
            raw(json!({"authorize":true,"ticketId":ticket})),
        )
        .await
        .unwrap();
    assert_eq!(cancelled["maintenance"]["status"], "cancelled");
    assert_eq!(tree(&container), stable_before);
    let admission = app
        .dispatch(Operation::PrepareAppMaintenance, prepare(&install))
        .await
        .unwrap();
    let quit = app
        .dispatch(Operation::QuitAdmission, raw(json!({})))
        .await
        .unwrap();
    assert_eq!(quit["quit"]["status"], "ready_to_quit");
    assert_eq!(quit["maintenance"]["status"], "ready_to_exit");
    assert_eq!(
        quit["maintenance"]["ticketId"],
        admission["maintenance"]["ticketId"]
    );
    assert!(app.running.is_none());
    assert!(!app.local_gateway.as_ref().unwrap().is_running());
    assert_eq!(tree(&container), stable_before);
    drop(app);

    // Reopen reads committed external CURRENT runtime; retained historical
    // install-root locators do not become an implicit rollback candidate.
    let mut app = HostApp::open_native(&container.join("profile"), &launch)
        .await
        .unwrap();
    role_history(&app, &initial, &install);
    let admission = app
        .dispatch(Operation::PrepareAppMaintenance, prepare(&install))
        .await
        .unwrap();
    let original_inode = fs::metadata(&launch).unwrap().ino();
    let replacement = launch.with_extension("replacement");
    write_new(&replacement, &launch_before);
    fs::rename(&replacement, &launch).unwrap();
    assert_ne!(fs::metadata(&launch).unwrap().ino(), original_inode);
    assert!(fs::read(&launch).unwrap() == launch_before);
    let after_replacement = tree(&container);
    assert!(
        app.dispatch(
            Operation::CancelAppMaintenance,
            raw(json!({"authorize":true,"ticketId":admission["maintenance"]["ticketId"]}))
        )
        .await
        .is_err()
    );
    assert_eq!(app.maintenance_status()["maintenance"]["status"], "unknown");
    assert!(
        app.dispatch(Operation::QuitAdmission, raw(json!({})))
            .await
            .is_err()
    );
    assert!(
        app.dispatch(Operation::PrepareAppMaintenance, prepare(&install))
            .await
            .is_err()
    );
    assert_eq!(
        app.maintenance_status()["maintenance"]["ticketId"],
        admission["maintenance"]["ticketId"]
    );
    assert!(matches!(
        HostScope::open(&container.join("profile")),
        Err(AppError("app_instance_busy"))
    ));
    assert_eq!(tree(&container), after_replacement);
    drop(app);

    // Independent negatives use the official verifier to derive each initial
    // locator, never a hand-edited C07 or an invented signed candidate.
    let payload_inside = release::inspect_selection(
        Path::new(&initial.payload_path),
        Path::new(&source.publisher_file),
        &source.publisher_spki_sha256.to_hex(),
    )
    .await
    .unwrap();
    assert!(Path::new(&payload_inside.payload_path).starts_with(&install));
    assert!(!Path::new(&payload_inside.publisher_file).starts_with(&install));
    inside_reference_refused(&top.join("payload-only"), &payload_inside, &install).await;
    let publisher_inside = release::inspect_selection(
        Path::new(&source.payload_path),
        Path::new(&initial.publisher_file),
        &source.publisher_spki_sha256.to_hex(),
    )
    .await
    .unwrap();
    assert!(!Path::new(&publisher_inside.payload_path).starts_with(&install));
    assert!(Path::new(&publisher_inside.publisher_file).starts_with(&install));
    inside_reference_refused(&top.join("publisher-only"), &publisher_inside, &install).await;
    verified.revalidate().unwrap();
    assert!(fs::read(&selection_file).unwrap() == fixture_raw);
    fs::remove_dir_all(&top).unwrap();
    println!(
        "completed_strict_tls_enrollment=true; original_stage_update_both_roles=true; launch_and_bootstrap_inside=true; current_runtime_external=true; prepare_cancel_full_quit_admission=true; original_history_preserved=true; payload_only_and_publisher_only_inside_refused=true; same_bytes_launch_replacement_unknown=true; original_instance_retained=true; installed_root=NOT_OPENED; Host_executor=NOT_STARTED; native_Core_process_exit=NOT_TESTED"
    );
}
