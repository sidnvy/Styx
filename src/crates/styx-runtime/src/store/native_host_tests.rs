//! Actual Linux private-file custody, not real identity generation/TLS/enrollment.
//! Opaque fixtures must never be promoted to authenticated protocol evidence.
#![cfg(all(target_os = "linux", target_env = "gnu"))]
use super::*;
use crate::store::{LockResource, StoreError};
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};
use styx_contracts::{management::ReaderContract, native_management::*};
const DEPLOYMENT: &[u8] = b"{\"schema\":1,\"mode\":\"join-existing\",\"test_custody\":true}\n";
const SEED_BYTES: &[u8] =
    b"{\"schema\":1,\"scope\":\"owned-host-store-fixture-not-network-proof\"}\n";
const NOW: u64 = 1_800_000_000;
fn material() -> FreshHostFiles<'static> {
    FreshHostFiles {
        ca_certificate_pem: b"opaque-test-CA-not-TLS",
        private_identity_pem: b"opaque-test-private-identity-not-real-key",
        seed_binding: SEED_BYTES,
    }
}
fn fresh(parent: &PrivateRoot, name: &str) -> FreshNativeRoot {
    super::super::create_fresh(parent, OsStr::new(name))
        .unwrap_or_else(|f| panic!("fresh root: {:?}", f.error()))
}
fn state(root: &FreshNativeRoot) -> NativeState {
    NativeState {
        schema: NATIVE_STATE_SCHEMA,
        kind: NativeStateKind::StyxDesiredState,
        runtime_format: NativeRuntimeFormat::NativeRustV1,
        reader_contract: ReaderContract::NativeManagementStateV1,
        scope_generation: root.marker().scope_generation,
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
            SEED_EXTENSION.into(),
            serde_json::value::RawValue::from_string(
                serde_json::to_string(&Sha256Digest::of_bytes(SEED_BYTES)).unwrap(),
            )
            .unwrap(),
        )]),
    }
}
fn busy(path: &Path) {
    assert!(matches!(
        PrivateRoot::open(path).unwrap().try_configuration_writer(),
        Err(StoreError::Busy(LockResource::ConfigurationWriter))
    ));
}
#[test]
#[ignore = "requires STYX_TEST_NATIVE_HOST_ROOT; actual private-FS closed phase chain/reopen/retained failure, NOT native join or remote proof"]
fn native_host_pending_closed_chain_reopen_and_sticky_unknown_aggregate() {
    let base = PathBuf::from(std::env::var("STYX_TEST_NATIVE_HOST_ROOT").unwrap());
    let _ = PrivateRoot::open(&base).unwrap();
    let path = base.join(uuid::Uuid::new_v4().to_string());
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let parent = PrivateRoot::open(&path).unwrap();
    let root = fresh(&parent, "normal");
    let s = state(&root);
    let normal = path.join("normal");
    let mut store = root
        .initialize_host_pending(DEPLOYMENT, &s, material(), NOW)
        .unwrap_or_else(|f| panic!("pending init: {:?}", f.error()));
    busy(&normal);
    assert!(store.seed_binding().unwrap() == SEED_BYTES);
    assert!(store.read(NativeHostJoinFile::Ready).unwrap().is_none());
    assert!(!normal.join(NativeHostJoinFile::Ready.path()).exists());
    assert!(
        fs::read(normal.join(".styx-enrollment-journal-v1/clock.floor")).unwrap()
            == NOW.checked_mul(1000).unwrap().to_be_bytes()
    );
    assert!(matches!(
        store.append(
            NativeHostJoinFile::Credential,
            b"owned_token_012345678901234567890123456789"
        ),
        Err(JournalError::Conflict)
    ));
    assert!(!normal.join(NativeHostJoinFile::Credential.path()).exists());
    assert!(store.readstate().is_ok());
    let owner = store.configuration_root();
    assert!(owner.identity().is_ok());
    drop(owner);
    let phases: [&[u8]; 5] = [
        b"{\"fixture\":\"join-dispatched\"}",
        b"{\"fixture\":\"join-reply\"}",
        b"owned_token_012345678901234567890123456789",
        b"{\"fixture\":\"confirm-dispatched\"}",
        b"{\"fixture\":\"ready-is-opaque-not-OS-or-network\"}",
    ];
    for (file, raw) in NativeHostJoinFile::ALL.into_iter().zip(phases) {
        store.append(file, raw).unwrap();
        assert!(store.read(file).unwrap().unwrap().as_slice() == raw);
        let m = fs::symlink_metadata(normal.join(file.path())).unwrap();
        assert!(m.is_file() && m.nlink() == 1 && m.permissions().mode() & 0o7777 == 0o600);
    }
    let ready = PrivateRoot::open(&normal)
        .unwrap()
        .read_raw(NativeHostJoinFile::Ready.path(), NATIVE_STATE_BYTES)
        .unwrap();
    assert!(matches!(
        store.append(NativeHostJoinFile::Ready, b"replacement-refused"),
        Err(JournalError::Conflict)
    ));
    let after = PrivateRoot::open(&normal)
        .unwrap()
        .read_raw(NativeHostJoinFile::Ready.path(), NATIVE_STATE_BYTES)
        .unwrap();
    assert!(after.bytes() == ready.bytes() && after.observation() == ready.observation());
    drop(store);
    let existing = PrivateRoot::open(&normal).unwrap();
    let writer = existing.try_existing_configuration_writer().unwrap();
    let binding = super::super::reopen_native(existing, writer)
        .unwrap_or_else(|f| panic!("native reopen: {:?}", f.error()));
    let reopened = NativeHostJoinStore::from_binding(binding)
        .unwrap_or_else(|f| panic!("host reopen: {:?}", f.error()));
    assert!(
        reopened
            .read(NativeHostJoinFile::Ready)
            .unwrap()
            .unwrap()
            .as_slice()
            == phases[4]
    );
    assert!(reopened.readstate().unwrap().state().migration.is_none());
    busy(&normal);
    // An exact material change poisons the SAME original owner. Restoring bytes
    // does not clear it, discard the writer, mint Ready, or retry network work.
    let root = fresh(&parent, "changed");
    let s = state(&root);
    let changed = path.join("changed");
    let store = root
        .initialize_host_pending(DEPLOYMENT, &s, material(), NOW)
        .unwrap_or_else(|f| panic!("changed init: {:?}", f.error()));
    fs::write(
        changed.join("host-identity.pem"),
        b"changed-test-private-material",
    )
    .unwrap();
    assert!(matches!(store.readstate(), Err(JournalError::Unknown)));
    fs::write(
        changed.join("host-identity.pem"),
        material().private_identity_pem,
    )
    .unwrap();
    assert!(matches!(store.readstate(), Err(JournalError::Unknown)));
    busy(&changed);
    assert!(!changed.join(NativeHostJoinFile::Ready.path()).exists());
    // Wrong seed hash is rejected before any identity/canonical material write.
    let root = fresh(&parent, "wrong-seed");
    let mut s = state(&root);
    s.extensions.insert(
        SEED_EXTENSION.into(),
        serde_json::value::RawValue::from_string(
            serde_json::to_string(&Sha256Digest::of_bytes(b"different")).unwrap(),
        )
        .unwrap(),
    );
    let wrong = path.join("wrong-seed");
    let failure = root
        .initialize_host_pending(DEPLOYMENT, &s, material(), NOW)
        .err()
        .unwrap();
    assert_eq!(failure.error(), NativeRootError::InvalidInput);
    assert!(failure.writer_held());
    busy(&wrong);
    for name in MATERIALS
        .iter()
        .map(|(n, _)| *n)
        .chain(["deployment.json", "state.json"])
    {
        assert!(!wrong.join(name).exists());
    }
    println!(
        "native_host_store_closed_chain=true; root_writer_retained=true; remote_join_and_TLS=NOT_RUN"
    );
}

#[test]
fn unsent_join_move_preserves_private_root_and_refuses_backup_collision() {
    use std::os::unix::fs::DirBuilderExt as _;
    let parent = std::env::temp_dir().join(format!("styx-unsent-store-{}", uuid::Uuid::new_v4()));
    fs::DirBuilder::new().mode(0o700).create(&parent).unwrap();
    let path = parent.join("host");
    fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
    let identity = PrivateRoot::open(&path).unwrap().identity();
    // A raced/pre-existing destination is never replaced, even when empty.
    let backup = parent.join("host.join-not-sent-1000");
    fs::DirBuilder::new().mode(0o700).create(&backup).unwrap();
    let original = fs::metadata(&backup).unwrap().ino();
    assert!(move_unsent_join(&path, &identity, 1000, &[]).is_err());
    assert_eq!(fs::metadata(&backup).unwrap().ino(), original);
    assert_eq!(PrivateRoot::open(&path).unwrap().identity(), identity);
    // Failure to preserve an App input also leaves the root at the old path.
    let input = parent.join("app-join-input-v1.json");
    fs::write(&input, b"attempt data").unwrap();
    fs::write(
        parent.join("app-join-input-v1.json.join-not-sent-1001"),
        b"existing data",
    )
    .unwrap();
    assert!(move_unsent_join(&path, &identity, 1001, std::slice::from_ref(&input)).is_err());
    assert!(path.is_dir());
    assert_eq!(fs::read(input).unwrap(), b"attempt data");
    move_unsent_join(&path, &identity, 1002, &[]).unwrap();
    assert!(!path.exists());
    let saved = parent.join("host.join-not-sent-1002");
    assert_eq!(PrivateRoot::open(&saved).unwrap().identity(), identity);
    assert_eq!(
        fs::metadata(saved).unwrap().permissions().mode() & 0o777,
        0o700
    );
    fs::remove_dir_all(parent).unwrap();
}

// Small real private-FS regressions. Opaque bytes prove store custody only.
struct PrefixFixture(PathBuf);
impl PrefixFixture {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("styx-native-prefix-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn store(&self) -> NativeHostJoinStore {
        let parent = PrivateRoot::open(&self.0).unwrap();
        let root = fresh(&parent, "host");
        let s = state(&root);
        root.initialize_host_pending(DEPLOYMENT, &s, material(), NOW)
            .unwrap_or_else(|failure| panic!("opaque store fixture: {:?}", failure.error()))
    }
}
impl Drop for PrefixFixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
const PREFIX_PHASES: [&[u8]; 5] = [
    b"dispatch",
    b"reply",
    b"credential_012345678901234567890123456789",
    b"confirm",
    b"ready",
];
#[test]
fn coherent_prefix_keeps_partial_absence_and_complete_original_bytes() {
    let f = PrefixFixture::new();
    let mut store = f.store();
    for count in 0..=5 {
        let prefix = store.read_prefix().unwrap();
        for (index, observed) in prefix.iter().enumerate() {
            assert_eq!(
                observed.as_deref().map(Vec::as_slice),
                (index < count).then_some(PREFIX_PHASES[index])
            );
        }
        let (canonical, seed) = store.readstate_and_seed().unwrap();
        assert_eq!(canonical.state().revision, 0);
        assert_eq!(seed, SEED_BYTES);
        if count < 5 {
            store
                .append(NativeHostJoinFile::ALL[count], PREFIX_PHASES[count])
                .unwrap();
        }
    }
}
#[test]
fn changed_phase_material_or_journal_during_prefix_never_delivers_captured_bytes() {
    for fault in [
        "same_content_phase_replacement",
        "credential_changed",
        "identity_changed",
        "namespace_replaced",
    ] {
        let f = PrefixFixture::new();
        let mut store = f.store();
        for (file, bytes) in NativeHostJoinFile::ALL.into_iter().zip(PREFIX_PHASES) {
            store.append(file, bytes).unwrap();
        }
        let root = f.0.join("host");
        let result = store.read_prefix_inner(|| {
            match fault {
                "same_content_phase_replacement" => {
                    let path = root.join(NativeHostJoinFile::Ready.path());
                    fs::rename(&path, root.join("original-ready-retained")).unwrap();
                    fs::write(&path, PREFIX_PHASES[4]).unwrap();
                    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
                }
                "credential_changed" => {
                    fs::write(root.join(NativeHostJoinFile::Credential.path()), b"changed").unwrap()
                }
                "identity_changed" => {
                    fs::write(root.join("host-identity.pem"), b"changed").unwrap()
                }
                "namespace_replaced" => {
                    let path = root.join(".styx-management-journal-v1");
                    fs::rename(&path, root.join("original-namespace-retained")).unwrap();
                    fs::create_dir(&path).unwrap();
                    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
                }
                _ => unreachable!(),
            }
            Ok(())
        });
        assert!(matches!(result, Err(JournalError::Unknown)), "{fault}");
        assert!(
            store.read_prefix().is_err(),
            "{fault}: no cached prefix admission"
        );
    }
}
