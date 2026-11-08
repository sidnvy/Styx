//! Actual Linux private-file custody. The rejection fixtures add typed seeds
//! and real synthetic signatures, never authenticated remote enrollment or execution.
//! Historical opaque prefix fixtures remain custody-only evidence.
#![cfg(all(target_os = "linux", target_env = "gnu"))]
use super::*;
use crate::store::{LockResource, StoreError};
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey, pkcs8::EncodePublicKey as _};
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs,
    io::Write as _,
    os::unix::fs::{DirBuilderExt as _, MetadataExt, OpenOptionsExt as _, PermissionsExt},
    path::{Path, PathBuf},
};
use styx_contracts::{
    management::ReaderContract,
    native_host::{NATIVE_HOST_JOIN_SEED_SCHEMA, NativeHostJoinSeed, NativeHostRejected},
    native_management::*,
};
const DEPLOYMENT: &[u8] = b"{\"schema\":1,\"mode\":\"join-existing\",\"test_custody\":true}\n";
const SEED_BYTES: &[u8] =
    b"{\"schema\":1,\"scope\":\"owned-host-store-fixture-not-network-proof\"}\n";
const NOW: u64 = 1_800_000_000;

/// Only the new rejection-format tests use this complete seed/signed reader.
/// Existing opaque schema2 prefix fixtures below deliberately stay unchanged.
struct RejectionInputs {
    selection: NativeRuntimeSelection,
    identity: crate::crypto::GeneratedDeviceIdentity,
    ca: Vec<u8>,
    anchor_sha256: Sha256Digest,
}
fn rejection_fixture_file(path: &Path, bytes: &[u8], executable: bool) {
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(if executable { 0o700 } else { 0o600 })
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
impl RejectionInputs {
    fn new(parent: &Path) -> Self {
        let package = parent.join("signed-rejection-input");
        fs::DirBuilder::new().mode(0o700).create(&package).unwrap();
        let payload = package.join("payload");
        fs::DirBuilder::new().mode(0o700).create(&payload).unwrap();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(payload.join("bin"))
            .unwrap();
        let files: Vec<_> = [
            ("LICENSE", b"synthetic store fixture".as_slice(), false),
            (
                "bin/styx",
                b"\x7fELF synthetic fixture; never executed".as_slice(),
                true,
            ),
            ("source-inputs.json", b"{}".as_slice(), false),
        ]
        .into_iter()
        .map(|(name, bytes, executable)| {
            rejection_fixture_file(&payload.join(name), bytes, executable);
            serde_json::json!({"path":name,"size":bytes.len(),
                "sha256":Sha256Digest::of_bytes(bytes),"executable":executable})
        })
        .collect();
        // This key is deterministic test material, unrelated to a publisher's
        // original private key. The resulting image is never launched.
        let signer = SigningKey::from_bytes(&[76u8; 32]);
        let der = signer.verifying_key().to_public_key_der().unwrap();
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            base64::engine::general_purpose::STANDARD.encode(der.as_bytes())
        );
        let publisher = package.join("publisher.pem");
        rejection_fixture_file(&publisher, pem.as_bytes(), false);
        let pin = crate::crypto::PublisherVerifyingKey::from_spki_pem(pem.as_bytes())
            .unwrap()
            .fingerprint()
            .unwrap();
        let manifest = serde_json::to_vec(&serde_json::json!({
            "schema":2,"runtime_format":"native_rust_v1","component":"styx",
            "scope":"runtime_candidate","minimum_reader":"native_pairing_lifecycle_v1",
            "target":"x86_64-unknown-linux-gnu","version":"0.4.0-test.1","entrypoint":"bin/styx",
            "source":{"revision":"1".repeat(40),"inputs_sha256":Sha256Digest::of_bytes(b"{}")},
            "contracts":{"control":1,"management_state":7},"files":files,"external_workers":[]
        }))
        .unwrap();
        rejection_fixture_file(&payload.join("manifest.json"), &manifest, false);
        rejection_fixture_file(
            &payload.join("manifest.sig"),
            &signer.sign(&manifest).to_bytes(),
            false,
        );
        let selection = crate::release::verify(&payload, &publisher, &pin)
            .unwrap()
            .runtime_selection()
            .unwrap();
        let ca = crate::tls::generate_gateway_ca(NOW, NOW - 60, NOW + 86400).unwrap();
        let der = rustls_pemfile::certs(&mut std::io::Cursor::new(&ca.certificate_pem))
            .next()
            .unwrap()
            .unwrap();
        let anchor_sha256 = Sha256Digest::of_bytes(der.as_ref());
        Self {
            selection,
            identity: crate::crypto::DevicePrivateKey::generate_rsa3072().unwrap(),
            ca: ca.certificate_pem,
            anchor_sha256,
        }
    }
    fn store(
        &self,
        parent: &PrivateRoot,
        name: &str,
        reader: ReaderContract,
        seed_schema: u16,
    ) -> (NativeHostJoinStore, Vec<u8>) {
        let root = fresh(parent, name);
        let seed = NativeHostJoinSeed {
            schema: seed_schema,
            root_identity: root.marker().root_identity.clone(),
            scope_generation: root.marker().scope_generation,
            deployment_raw_sha256: Sha256Digest::of_bytes(DEPLOYMENT),
            runtime: self.selection.clone(),
            gateway_origin: "https://127.0.0.1:9443".into(),
            anchor_sha256: self.anchor_sha256,
            device_id: format!("store-rejection-{name}").try_into().unwrap(),
            fingerprint: Sha256Digest::of_bytes(self.identity.public_key().spki_der()),
            public_key_pem: self.identity.public_key_pem().into(),
            label: "Typed local store fixture".into(),
            platform: "linux".into(),
            cwd: "/".into(),
            shell: "/bin/sh".into(),
            computer_requested: true,
            browser_requested: true,
        };
        let raw_seed = serde_json::to_vec(&seed).unwrap();
        let mut canonical = state(&root);
        canonical.schema = match reader {
            ReaderContract::NativePairingLifecycleStateV1 => NATIVE_PAIRING_LIFECYCLE_STATE_SCHEMA,
            ReaderContract::NativeManagementStateV1 => NATIVE_STATE_SCHEMA,
            _ => panic!("fixture reader"),
        };
        canonical.reader_contract = reader;
        canonical.extensions.insert(
            SEED_EXTENSION.into(),
            serde_json::value::to_raw_value(&Sha256Digest::of_bytes(&raw_seed)).unwrap(),
        );
        canonical.extensions.insert(
            NATIVE_RUNTIME_SELECTION_KEY.into(),
            serde_json::value::to_raw_value(&self.selection).unwrap(),
        );
        let store = root
            .initialize_host_pending(
                DEPLOYMENT,
                &canonical,
                FreshHostFiles {
                    ca_certificate_pem: &self.ca,
                    private_identity_pem: self.identity.protected_pkcs8_pem(),
                    seed_binding: &raw_seed,
                },
                NOW,
            )
            .unwrap_or_else(|failure| panic!("typed pending init: {:?}", failure.error()));
        let (stored, stored_seed) = store.readstate_and_seed().unwrap();
        assert_eq!(stored_seed, raw_seed.as_slice());
        assert_eq!(stored.state().reader_contract, reader);
        assert!(stored.state().runtime_update().unwrap().is_none());
        let rejected = serde_json::to_vec(&NativeHostRejected {
            schema: 1,
            seed_sha256: Sha256Digest::of_bytes(&raw_seed),
            request_id: "local-store-request-not-remote-proof".into(),
            device_id: seed.device_id,
            fingerprint: seed.fingerprint,
        })
        .unwrap();
        (store, rejected)
    }
}

#[test]
fn native_host_rejection_requires_both_new_seed_and_canonical_reader_before_file_write() {
    let fixture = PrefixFixture::new();
    let parent = PrivateRoot::open(&fixture.0).unwrap();
    let inputs = RejectionInputs::new(&fixture.0);
    for (name, reader, seed_schema) in [
        (
            "old-seed-old-reader",
            ReaderContract::NativeManagementStateV1,
            1,
        ),
        (
            "old-seed-new-reader",
            ReaderContract::NativePairingLifecycleStateV1,
            1,
        ),
        (
            "new-seed-old-reader",
            ReaderContract::NativeManagementStateV1,
            NATIVE_HOST_JOIN_SEED_SCHEMA,
        ),
    ] {
        let (mut store, rejected) = inputs.store(&parent, name, reader, seed_schema);
        if reader == ReaderContract::NativePairingLifecycleStateV1 {
            store
                .configuration_root()
                .require_pairing_lifecycle_reader()
                .unwrap();
        } else {
            assert!(
                store
                    .configuration_root()
                    .require_pairing_lifecycle_reader()
                    .is_err()
            );
        }
        // Complete original prefix, so refusal is the format gate rather than
        // a missing JoinReply or an opaque/malformed schema1 seed.
        store
            .append(NativeHostJoinFile::JoinDispatched, b"dispatch")
            .unwrap();
        store
            .append(NativeHostJoinFile::JoinReply, b"reply")
            .unwrap();
        assert!(matches!(
            store.append(NativeHostJoinFile::Rejected, &rejected),
            Err(JournalError::Conflict)
        ));
        assert!(
            !fixture
                .0
                .join(name)
                .join(NativeHostJoinFile::Rejected.path())
                .exists()
        );
        assert!(store.read(NativeHostJoinFile::Rejected).unwrap().is_none());
        assert!(
            store.readstate().is_ok(),
            "known refusal retains readable original store"
        );
        busy(&fixture.0.join(name));
    }
}

#[test]
#[ignore = "requires STYX_TEST_NATIVE_HOST_ROOT; protected fresh7 + typed seed2 + synthetic signed reader, not remote rejection or worker acceptance"]
fn native_host_rejection_branch_survives_reopen_and_never_admits_credentials() {
    let base = PathBuf::from(std::env::var("STYX_TEST_NATIVE_HOST_ROOT").unwrap());
    let _ = PrivateRoot::open(&base).unwrap();
    let path = base.join(uuid::Uuid::new_v4().to_string());
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let parent = PrivateRoot::open(&path).unwrap();
    let inputs = RejectionInputs::new(&path);
    let rejected_path = path.join("rejected");
    let (mut store, rejected) = inputs.store(
        &parent,
        "rejected",
        ReaderContract::NativePairingLifecycleStateV1,
        NATIVE_HOST_JOIN_SEED_SCHEMA,
    );
    store
        .configuration_root()
        .require_pairing_lifecycle_reader()
        .unwrap();
    assert!(matches!(
        store.append(NativeHostJoinFile::Rejected, &rejected),
        Err(JournalError::Conflict)
    ));
    store
        .append(
            NativeHostJoinFile::JoinDispatched,
            b"{\"fixture\":\"dispatched\"}",
        )
        .unwrap();
    assert!(matches!(
        store.append(NativeHostJoinFile::Rejected, &rejected),
        Err(JournalError::Conflict)
    ));
    store
        .append(NativeHostJoinFile::JoinReply, b"{\"fixture\":\"reply\"}")
        .unwrap();
    store
        .append(NativeHostJoinFile::Rejected, &rejected)
        .unwrap();
    let actual = fs::read(rejected_path.join(NativeHostJoinFile::Rejected.path())).unwrap();
    assert_eq!(actual.as_slice(), rejected.as_slice());
    let prefix = store.read_prefix().unwrap();
    assert!(prefix[..2].iter().all(Option::is_some));
    assert!(prefix[2..].iter().all(Option::is_none));
    drop(store);

    let existing = PrivateRoot::open(&rejected_path).unwrap();
    let writer = existing.try_existing_configuration_writer().unwrap();
    let binding = super::super::reopen_native(existing, writer)
        .unwrap_or_else(|failure| panic!("native reopen: {:?}", failure.error()));
    let mut store = NativeHostJoinStore::from_binding(binding)
        .unwrap_or_else(|failure| panic!("join reopen: {:?}", failure.error()));
    assert_eq!(
        store
            .read(NativeHostJoinFile::Rejected)
            .unwrap()
            .unwrap()
            .as_slice(),
        rejected.as_slice()
    );
    for (file, bytes) in [
        (NativeHostJoinFile::Rejected, rejected.as_slice()),
        (
            NativeHostJoinFile::Credential,
            b"owned_token_012345678901234567890123456789".as_slice(),
        ),
        (
            NativeHostJoinFile::ConfirmDispatched,
            b"{\"fixture\":\"confirm\"}".as_slice(),
        ),
        (
            NativeHostJoinFile::Ready,
            b"{\"fixture\":\"ready\"}".as_slice(),
        ),
    ] {
        assert!(matches!(
            store.append(file, bytes),
            Err(JournalError::Conflict)
        ));
    }
    for file in [
        NativeHostJoinFile::Credential,
        NativeHostJoinFile::ConfirmDispatched,
        NativeHostJoinFile::Ready,
    ] {
        assert!(
            !rejected_path.join(file.path()).exists(),
            "independent filesystem absence: {}",
            file.path()
        );
    }
    // Change the terminal file between the batch's capture and final check.
    // The retained marker pin, not merely the phase count, must deny delivery.
    assert!(
        store
            .read_prefix_inner(|| {
                fs::write(
                    rejected_path.join(NativeHostJoinFile::Rejected.path()),
                    b"{\"fixture\":\"changed\"}",
                )
                .unwrap();
                Ok(())
            })
            .is_err()
    );
    assert!(matches!(
        store.read(NativeHostJoinFile::Rejected),
        Err(JournalError::Unknown)
    ));
    assert!(store.read_prefix().is_err());
    drop(store);

    let contradictory = path.join("contradictory");
    let (mut store, rejected) = inputs.store(
        &parent,
        "contradictory",
        ReaderContract::NativePairingLifecycleStateV1,
        NATIVE_HOST_JOIN_SEED_SCHEMA,
    );
    store
        .configuration_root()
        .require_pairing_lifecycle_reader()
        .unwrap();
    store
        .append(
            NativeHostJoinFile::JoinDispatched,
            b"{\"fixture\":\"dispatched\"}",
        )
        .unwrap();
    store
        .append(NativeHostJoinFile::JoinReply, b"{\"fixture\":\"reply\"}")
        .unwrap();
    store
        .append(
            NativeHostJoinFile::Credential,
            b"owned_token_012345678901234567890123456789",
        )
        .unwrap();
    // Simulate a malformed retained prefix, never a legitimate product write.
    fs::write(
        contradictory.join(NativeHostJoinFile::Rejected.path()),
        &rejected,
    )
    .unwrap();
    fs::set_permissions(
        contradictory.join(NativeHostJoinFile::Rejected.path()),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    drop(store);
    let existing = PrivateRoot::open(&contradictory).unwrap();
    let writer = existing.try_existing_configuration_writer().unwrap();
    let binding = super::super::reopen_native(existing, writer)
        .unwrap_or_else(|failure| panic!("native reopen: {:?}", failure.error()));
    let failure = NativeHostJoinStore::from_binding(binding)
        .err()
        .expect("credential and rejection cannot coexist");
    assert_eq!(failure.error(), NativeRootError::Unknown);
    assert!(failure.writer_held());
    assert!(
        contradictory
            .join(NativeHostJoinFile::Credential.path())
            .exists()
    );
    assert!(
        contradictory
            .join(NativeHostJoinFile::Rejected.path())
            .exists()
    );
}

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
    for (count, next) in NativeHostJoinFile::ALL
        .into_iter()
        .zip(PREFIX_PHASES)
        .map(Some)
        .chain(std::iter::once(None))
        .enumerate()
    {
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
        if let Some((file, raw)) = next {
            store.append(file, raw).unwrap();
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
