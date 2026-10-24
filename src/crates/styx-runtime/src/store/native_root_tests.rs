//! Actual private-file bootstrap/retention/reopen boundaries. Synthetic desired
//! state is not onboarding, pairing, native activation, or a power-loss test.
#![cfg(all(target_os = "linux", target_env = "gnu"))]
use super::*;
use crate::store::{LockResource, StoreError};
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use styx_contracts::{identity::Sha256Digest, management::ReaderContract, native_management::*};
const DEPLOYMENT: &[u8] = b"{\"synthetic\":true,\"unknown\":900719925474099312345}\n";
fn own_directory(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}
fn fixture(base: &Path) -> (PathBuf, PrivateRoot) {
    let path = base.join(uuid::Uuid::new_v4().to_string());
    own_directory(&path);
    let root = PrivateRoot::open(&path).unwrap();
    (path, root)
}
fn private_file(path: &Path, bytes: &[u8]) {
    use std::io::Write;
    let mut f = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    f.write_all(bytes).unwrap();
    f.sync_all().unwrap();
}
fn genesis(fresh: &FreshNativeRoot) -> NativeState {
    NativeState {
        schema: NATIVE_STATE_SCHEMA,
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
                manager: NativeManager::ForegroundCli,
                run: NativeRunDesired::Stopped,
                autostart: NativeAutostartDesired::Disabled,
            }),
        },
        migration: None,
        extensions: BTreeMap::from([(
            "preserved_unknown".into(),
            serde_json::value::RawValue::from_string("900719925474099312345".into()).unwrap(),
        )]),
    }
}
fn busy(path: &Path) {
    let root = PrivateRoot::open(path).unwrap();
    assert!(matches!(
        root.try_configuration_writer(),
        Err(StoreError::Busy(LockResource::ConfigurationWriter))
    ));
}
fn create(parent: &PrivateRoot, name: &str) -> FreshNativeRoot {
    create_fresh(parent, OsStr::new(name))
        .unwrap_or_else(|e| panic!("fresh create failed: {:?}", e.error()))
}
#[test]
#[ignore = "requires STYX_TEST_NATIVE_ROOT_ROOT; actual owned fresh/bootstrap/reopen/uncertain-writer aggregate, not canonical apply or powerloss"]
fn fresh_native_root_genesis_reopen_and_retained_unknown_batch() {
    let base = PathBuf::from(std::env::var("STYX_TEST_NATIVE_ROOT_ROOT").unwrap());
    fs::create_dir_all(&base).unwrap();
    let (parent_path, parent) = fixture(&base);
    let fresh = create(&parent, "native-a");
    let path = parent_path.join("native-a");
    busy(&path);
    let marker = fs::read(path.join(NATIVE_MARKER_FILE)).unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
        0o700
    );
    assert_eq!(
        fs::metadata(path.join(NATIVE_MARKER_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
    let exists = create_fresh(&parent, OsStr::new("native-a")).err().unwrap();
    assert_eq!(exists.error(), NativeRootError::AlreadyExists);
    assert!(!exists.writer_held());
    assert_eq!(fs::read(path.join(NATIVE_MARKER_FILE)).unwrap(), marker);
    for invalid in ["", ".", "..", "nested/child", "name/", "name/.", "name\0"] {
        assert_eq!(
            create_fresh(&parent, OsStr::new(invalid))
                .err()
                .unwrap()
                .error(),
            NativeRootError::InvalidInput
        )
    }
    let state = genesis(&fresh);
    let binding = fresh
        .initialize(DEPLOYMENT, &state)
        .unwrap_or_else(|e| panic!("genesis failed: {:?}", e.error()));
    let canonical = fs::read(path.join("state.json")).unwrap();
    assert_eq!(fs::read(path.join("deployment.json")).unwrap(), DEPLOYMENT);
    let read = binding.validated_readstate().unwrap();
    assert_eq!(read.state().schema, 2);
    assert_eq!(read.state().revision, 0);
    assert_eq!(
        read.state().extensions["preserved_unknown"].get(),
        "900719925474099312345"
    );
    assert_eq!(
        read.state().desired.host.unwrap().run,
        NativeRunDesired::Stopped
    );
    assert_eq!(read.raw_bytes(), canonical);
    busy(&path);
    // A read/reopen is not durability. Explicit maintenance resync must
    // actually fsync the original files, preserve bytes and leave admission fenced.
    let maintenance_owner = binding.configuration_root();
    let maintenance = maintenance_owner
        .begin_maintenance("native-root-resync".try_into().unwrap())
        .unwrap();
    let synced = maintenance_owner
        .with_maintenance(&maintenance, |state| binding.resync_locked(state))
        .unwrap();
    assert_eq!(synced.raw_bytes(), canonical);
    assert_eq!(synced.raw_sha256(), read.raw_sha256());
    assert!(maintenance_owner.ensure_admission().is_err());
    busy(&path);
    drop(maintenance);
    drop(maintenance_owner);
    let clone = binding.configuration_root();
    drop(binding);
    busy(&path);
    drop(clone);
    let root = PrivateRoot::open(&path).unwrap();
    let writer = root.try_configuration_writer().unwrap();
    let binding =
        reopen_native(root, writer).unwrap_or_else(|e| panic!("reopen failed: {:?}", e.error()));
    assert_eq!(
        binding.validated_readstate().unwrap().raw_bytes(),
        canonical
    );
    assert_eq!(fs::read(path.join(NATIVE_MARKER_FILE)).unwrap(), marker);
    drop(binding);

    // A copied/recreated root cannot inherit the original kernel-root identity.
    let (copy_path, copy) = fixture(&base);
    for name in [NATIVE_MARKER_FILE, "deployment.json", "state.json"] {
        private_file(&copy_path.join(name), &fs::read(path.join(name)).unwrap())
    }
    let writer = copy.try_configuration_writer().unwrap();
    let failure = reopen_native(copy, writer).err().unwrap();
    assert!(failure.writer_held());
    assert_eq!(failure.error(), NativeRootError::Unknown);
    busy(&copy_path);
    drop(failure);

    // Original legacy bytes cannot authorize native bootstrap or be rewritten.
    let (legacy_path, legacy) = fixture(&base);
    private_file(&legacy_path.join("state.json"), b"{\"schema\":1}");
    let writer = legacy.try_configuration_writer().unwrap();
    let failure = reopen_native(legacy, writer).err().unwrap();
    assert!(failure.writer_held());
    assert_eq!(
        fs::read(legacy_path.join("state.json")).unwrap(),
        b"{\"schema\":1}"
    );
    assert!(!legacy_path.join(NATIVE_MARKER_FILE).exists());
    drop(failure);

    // An actual alias introduced after marker fsync makes its observation
    // unsafe. The result owns the writer and bytes remain for reconciliation.
    let marker_path = parent_path.join("marker-unknown");
    let failure = platform::create(&parent, OsStr::new("marker-unknown"), &|record, phase| {
        if record == "marker" && phase == "file_sync" {
            fs::hard_link(
                marker_path.join(NATIVE_MARKER_FILE),
                marker_path.join("retained-alias"),
            )
            .unwrap();
        }
    })
    .err()
    .unwrap();
    assert_eq!(failure.error(), NativeRootError::Unknown);
    assert!(failure.writer_held());
    busy(&marker_path);
    assert!(!marker_path.join("state.json").exists());
    drop(failure);

    // Actual post-write corruption, not a caller-supplied durability boolean.
    // State bytes exist, but no binding is returned and the original writer stays.
    let fresh = create(&parent, "genesis-unknown");
    let path = parent_path.join("genesis-unknown");
    let state = genesis(&fresh);
    let failure = platform::initialize(fresh, DEPLOYMENT, &state, &|record, phase| {
        if record == "state" && phase == "file_sync" {
            fs::hard_link(path.join("state.json"), path.join("retained-state-alias")).unwrap();
        }
    })
    .err()
    .unwrap();
    assert!(failure.writer_held());
    assert_eq!(failure.error(), NativeRootError::Unknown);
    busy(&path);
    assert_eq!(fs::read(path.join("deployment.json")).unwrap(), DEPLOYMENT);
    assert!(path.join("state.json").exists());
    drop(failure);
    let root = PrivateRoot::open(&path).unwrap();
    let writer = root.try_configuration_writer().unwrap();
    let failure = reopen_native(root, writer).err().unwrap();
    assert!(failure.writer_held());
    drop(failure);

    // Bad genesis input is refused before canonical IO, retaining bootstrap.
    let fresh = create(&parent, "bad-genesis");
    let path = parent_path.join("bad-genesis");
    let mut state = genesis(&fresh);
    state.revision = 1;
    let failure = fresh.initialize(DEPLOYMENT, &state).err().unwrap();
    assert_eq!(failure.error(), NativeRootError::InvalidInput);
    assert!(failure.writer_held());
    assert!(!path.join("deployment.json").exists());
    assert!(!path.join("state.json").exists());
    drop(failure);

    // A later marker replacement poisons the same shared owner; a cached DTO
    // cannot bypass this per-sensitive-access observation or release the writer.
    let fresh = create(&parent, "marker-replaced");
    let path = parent_path.join("marker-replaced");
    let state = genesis(&fresh);
    let binding = fresh
        .initialize(DEPLOYMENT, &state)
        .unwrap_or_else(|e| panic!("genesis failed: {:?}", e.error()));
    fs::rename(
        path.join(NATIVE_MARKER_FILE),
        path.join("retained-original-marker"),
    )
    .unwrap();
    private_file(
        &path.join(NATIVE_MARKER_FILE),
        &fs::read(path.join("retained-original-marker")).unwrap(),
    );
    assert!(matches!(
        binding.validated_readstate(),
        Err(NativeRootError::Unknown)
    ));
    busy(&path);
    assert!(binding.configuration_root().ensure_admission().is_err());
}
