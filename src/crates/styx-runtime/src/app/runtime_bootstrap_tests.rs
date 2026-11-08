//! Actual Ed25519 verification and private-filesystem effects, no execution.
//! Synthetic publisher/payload fixtures do not stand in for native acceptance.
use super::*;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey, pkcs8::EncodePublicKey as _};
use std::{
    collections::BTreeMap,
    fs,
    io::Write as _,
    os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _},
};
use styx_contracts::native_management::NativeRuntimeSelection;

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
struct Fixture {
    top: PathBuf,
    container: PathBuf,
    bundle: PathBuf,
    candidate: PathBuf,
    selection: NativeRuntimeSelection,
}
impl Fixture {
    fn new() -> Self {
        let top = std::env::temp_dir().join(format!("styx-bootstrap-{}", uuid::Uuid::new_v4()));
        directory(&top);
        let bundle = top.join("Styx.app");
        directory(&bundle);
        let payload = bundle.join("native");
        directory(&payload);
        directory(&payload.join("bin"));
        let files: Vec<_> = [
            ("LICENSE", b"bootstrap fixture".as_slice(), false),
            (
                "bin/styx",
                b"\x7fELF fixture never executed".as_slice(),
                true,
            ),
            ("source-inputs.json", b"{}".as_slice(), false),
        ]
        .into_iter()
        .map(|(path, bytes, executable)| {
            write(&payload.join(path), bytes, executable);
            serde_json::json!({"path":path,"size":bytes.len(),
                "sha256":Sha256Digest::of_bytes(bytes),"executable":executable})
        })
        .collect();
        let key = SigningKey::from_bytes(&[51u8; 32]);
        let der = key.verifying_key().to_public_key_der().unwrap();
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            base64::engine::general_purpose::STANDARD.encode(der.as_bytes())
        );
        let publisher = bundle.join("publisher.pem");
        write(&publisher, pem.as_bytes(), false);
        let pin = crate::crypto::PublisherVerifyingKey::from_spki_pem(pem.as_bytes())
            .unwrap()
            .fingerprint()
            .unwrap();
        let manifest = serde_json::to_vec(&json!({"schema":2,"runtime_format":"native_rust_v1",
            "component":"styx","scope":"runtime_candidate","minimum_reader":"native_pairing_lifecycle_v1",
            "target":"x86_64-unknown-linux-gnu","version":"0.4.0-test.1","entrypoint":"bin/styx",
            "source":{"revision":"1".repeat(40),"inputs_sha256":Sha256Digest::of_bytes(b"{}")},
            "contracts":{"control":1,"management_state":7},"files":files,"external_workers":[]})).unwrap();
        write(&payload.join("manifest.json"), &manifest, false);
        write(
            &payload.join("manifest.sig"),
            &key.sign(&manifest).to_bytes(),
            false,
        );
        let selection = release::verify(&payload, &publisher, &pin)
            .unwrap()
            .runtime_selection()
            .unwrap();
        let container = top.join("app");
        directory(&container);
        let candidates = container.join("migration-candidates");
        directory(&candidates);
        let candidate = candidates.join("fixture.json");
        write(&candidate, &serde_json::to_vec(&selection).unwrap(), false);
        Self {
            top,
            container,
            bundle,
            candidate,
            selection,
        }
    }
    async fn open(&self) -> HostApp {
        HostApp::open_native(&self.container.join("profile"), &self.candidate)
            .await
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.top);
    }
}

fn inventory(root: &Path) -> BTreeMap<PathBuf, (u64, u64, u64, String)> {
    fn visit(root: &Path, path: &Path, out: &mut BTreeMap<PathBuf, (u64, u64, u64, String)>) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            let metadata = fs::symlink_metadata(&path).unwrap();
            assert!(!metadata.file_type().is_symlink());
            let digest = if metadata.is_dir() {
                String::new()
            } else {
                Sha256Digest::of_bytes(&fs::read(&path).unwrap()).to_hex()
            };
            out.insert(
                path.strip_prefix(root).unwrap().to_owned(),
                (metadata.dev(), metadata.ino(), metadata.len(), digest),
            );
            if metadata.is_dir() {
                visit(root, &path, out);
            }
        }
    }
    let mut out = BTreeMap::new();
    visit(root, root, &mut out);
    out
}

#[tokio::test]
async fn completed_bootstrap_is_observed_without_copying_after_bundle_replacement() {
    let fixture = Fixture::new();
    let mut app = fixture.open().await;
    app.bootstrap_runtime_selection().await.unwrap();
    let input = app.runtime_selection_file.clone().unwrap();
    let selected: NativeRuntimeSelection =
        serde_json::from_slice(&fs::read(&input).unwrap()).unwrap();
    assert!(Path::new(&selected.payload_path).starts_with(&fixture.container));
    assert!(!Path::new(&selected.payload_path).starts_with(&fixture.bundle));
    assert_ne!(selected.payload_root, fixture.selection.payload_root);
    assert_eq!(selected.manifest_sha256, fixture.selection.manifest_sha256);
    assert!(app.scope.root.get().is_none());
    assert!(!fixture.container.join("app-join-input-v1.json").exists());
    let before = inventory(&fixture.container.join("runtime-versions"));
    // Only the disposable source bundle is replaced. The selected signed copy
    // and its original file identities must remain valid and unchanged.
    fs::rename(&fixture.bundle, fixture.top.join("retained-old-app")).unwrap();
    directory(&fixture.bundle);
    release::verify_selected(&selected).unwrap();
    app.bootstrap_runtime_selection().await.unwrap();
    assert_eq!(app.runtime_selection_file.as_ref(), Some(&input));
    assert_eq!(
        inventory(&fixture.container.join("runtime-versions")),
        before
    );
    drop(app);
}

#[tokio::test]
async fn partial_bootstrap_is_never_adopted_or_replayed_by_a_new_app() {
    let fixture = Fixture::new();
    let versions = fixture.container.join("runtime-versions");
    directory(&versions);
    let (version, _) = names(fixture.selection.manifest_sha256);
    let partial = versions.join(version);
    directory(&partial);
    write(&partial.join("partial"), b"original incomplete copy", false);
    let before = inventory(&versions);
    for _ in 0..2 {
        let mut app = fixture.open().await;
        assert_eq!(
            app.bootstrap_runtime_selection().await.unwrap_err().code(),
            "app_runtime_bootstrap_unknown"
        );
        assert!(app.unknown);
        assert!(app.scope.root.get().is_none());
        assert_eq!(inventory(&versions), before);
        drop(app);
    }
}

#[tokio::test]
async fn invalid_source_is_refused_before_any_version_or_setup_write() {
    let fixture = Fixture::new();
    fs::write(fixture.bundle.join("native/bin/styx"), b"tampered").unwrap();
    let mut app = fixture.open().await;
    assert!(app.bootstrap_runtime_selection().await.is_err());
    assert!(
        !app.unknown,
        "known pre-copy refusal is not an unknown write"
    );
    assert!(!fixture.container.join("runtime-versions").exists());
    assert!(app.scope.root.get().is_none());
    drop(app);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires STYX_TEST_APP_CONTROL_SELECTION supporting the current writer/reader; disposable real signed Runtime + strict-TLS enrollment, no Host executor"]
async fn fresh_profile_reopens_from_external_runtime_after_bundle_replacement() {
    use crate::store::{native_host_snapshot, native_state};
    use styx_contracts::native_management::{NATIVE_MARKER_BYTES, NATIVE_STATE_BYTES};
    let original: NativeRuntimeSelection = serde_json::from_slice(
        &fs::read(std::env::var("STYX_TEST_APP_CONTROL_SELECTION").unwrap()).unwrap(),
    )
    .unwrap();
    release::verify_selected(&original).unwrap();
    // Retain the whole reference tree on failure: no unknown/live child path is
    // removed by a fixture Drop implementation.
    let top = std::env::temp_dir().join(format!("styx-bootstrap-tls-{}", uuid::Uuid::new_v4()));
    directory(&top);
    let bundle = top.join("Styx.app");
    directory(&bundle);
    let bundled = release::stage(
        Path::new(&original.payload_path),
        Path::new(&original.publisher_file),
        &original.publisher_spki_sha256.to_hex(),
        &bundle,
        OsStr::new("native"),
    )
    .await
    .unwrap();
    let container = top.join("app");
    directory(&container);
    let candidates = container.join("migration-candidates");
    directory(&candidates);
    let candidate = candidates.join("original.json");
    write(&candidate, &serde_json::to_vec(&bundled).unwrap(), false);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let profile = container.join("profile");
    let mut app = HostApp::open_native(&profile, &candidate).await.unwrap();
    // This calls the actual first-setup entry, including default external
    // staging. The original signed Gateway performs real strict-TLS pairing.
    app.create_local(LocalInput {
        label: "Runtime bootstrap reference".into(),
        computer: false,
        browser: false,
        browser_channel: None,
        persist_login: false,
        port,
        lan_address: None,
        allow_remote_hosts: false,
    })
    .await
    .unwrap();
    assert_eq!(
        app.enrollment.as_ref().unwrap()["status"],
        "ready_to_connect"
    );
    assert!(
        app.running.is_none(),
        "reference does not start a Host executor"
    );
    async fn paired_devices(app: &mut HostApp) -> Vec<Value> {
        let rows = app
            .gateway_ui_request(
                Operation::Computers,
                serde_json::value::to_raw_value(&json!({})).unwrap(),
            )
            .await
            .unwrap();
        let mut rows: Vec<_> = rows["devices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| {
                json!({"device_id":row["device_id"],"label":row["label"],
                "platform":row["platform"],"is_local":row["is_local"]})
            })
            .collect();
        rows.sort_by_key(|row| row["device_id"].as_str().unwrap().to_owned());
        rows
    }
    let approved = paired_devices(&mut app).await;
    assert_eq!(approved.len(), 1);
    app.settle_all().await.unwrap();
    app.set_desired(NativeRunDesired::Stopped).await.unwrap();
    assert!(!app.local_gateway.as_ref().unwrap().is_running());
    fn selections(app: &HostApp, bundle: &Path) -> Vec<NativeRuntimeSelection> {
        [&app.scope, &app.local_gateway.as_ref().unwrap().scope]
            .into_iter()
            .map(|scope| {
                let root = scope.root.get().unwrap();
                let marker_raw = root
                    .read_raw(".styx-native-root-v1.json", NATIVE_MARKER_BYTES)
                    .unwrap();
                let marker = native_state::decode_marker(marker_raw.bytes()).unwrap();
                let state_raw = root.read_raw("state.json", NATIVE_STATE_BYTES).unwrap();
                let state = native_state::decode_state(state_raw.bytes(), &marker).unwrap();
                let selection =
                    native_host_snapshot::validated_runtime_selection(root, &state, &marker)
                        .unwrap();
                assert!(!Path::new(&selection.payload_path).starts_with(bundle));
                assert!(!Path::new(&selection.publisher_file).starts_with(bundle));
                release::verify_selected(&selection).unwrap();
                selection
            })
            .collect()
    }
    let before = selections(&app, &bundle);
    assert_eq!(
        before[0], before[1],
        "both roles select the external signed version"
    );
    fn materials(root: &Path, host: bool) -> BTreeMap<PathBuf, (u64, u64, u64, String)> {
        let required: &[&str] = if host {
            &[
                ".styx-native-root-v1.json",
                "deployment.json",
                "host-ca.pem",
                "host-identity.pem",
                "host-join-seed-v1.json",
                "host-credential.token",
                "host-ready-v1.json",
            ]
        } else {
            &[
                ".styx-native-root-v1.json",
                "deployment.json",
                "gateway-ca.pem",
                "gateway-ca-key.pem",
                "gateway-chain.pem",
                "gateway-key.pem",
                "gateway-admin.token",
                "gateway-model.token",
                "gateway-ready-v1.json",
            ]
        };
        required
            .iter()
            .map(|name| {
                let path = root.join(name);
                let metadata = fs::symlink_metadata(&path).unwrap();
                assert!(metadata.is_file() && !metadata.file_type().is_symlink());
                (
                    PathBuf::from(name),
                    (
                        metadata.dev(),
                        metadata.ino(),
                        metadata.len(),
                        Sha256Digest::of_bytes(&fs::read(&path).unwrap()).to_hex(),
                    ),
                )
            })
            .collect()
    }
    let quit = app
        .dispatch(
            Operation::QuitAdmission,
            serde_json::value::to_raw_value(&json!({})).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(quit["quit"]["status"], "ready_to_quit");
    // Run intent/revisions and new journal records may legitimately change.
    // Preserve the independently identified keys, enrollment, configuration
    // inputs and directory identity instead of freezing every profile byte.
    let roots = [
        materials(&profile, true),
        materials(&container.join("gateway"), false),
    ];
    drop(app);
    fs::rename(&bundle, top.join("retained-old-app")).unwrap();
    directory(&bundle);
    // The new App control plane provides a verified current candidate. Keeping
    // the profile must use its canonical external selection, not the old App.
    let replacement = release::stage(
        Path::new(&original.payload_path),
        Path::new(&original.publisher_file),
        &original.publisher_spki_sha256.to_hex(),
        &bundle,
        OsStr::new("native"),
    )
    .await
    .unwrap();
    let replacement_input = candidates.join("replacement.json");
    write(
        &replacement_input,
        &serde_json::to_vec(&replacement).unwrap(),
        false,
    );
    let mut reopened = HostApp::open_native(&profile, &replacement_input)
        .await
        .unwrap();
    assert_eq!(selections(&reopened, &bundle), before);
    assert_eq!(
        reopened.enrollment.as_ref().unwrap()["status"],
        "ready_to_connect"
    );
    assert!(!reopened.unknown);
    assert_eq!(
        [
            materials(&profile, true),
            materials(&container.join("gateway"), false)
        ],
        roots,
        "profile identity, keys, enrollment and configuration inputs survived App replacement"
    );
    reopened
        .local_gateway
        .as_mut()
        .unwrap()
        .start()
        .await
        .unwrap();
    assert_eq!(
        paired_devices(&mut reopened).await,
        approved,
        "the original Gateway still authorizes the same paired computer"
    );
    reopened.settle_all().await.unwrap();
    let quit = reopened
        .dispatch(
            Operation::QuitAdmission,
            serde_json::value::to_raw_value(&json!({})).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(quit["quit"]["status"], "ready_to_quit");
    drop(reopened);
    fs::remove_dir_all(top).unwrap();
}
