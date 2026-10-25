//! Actual Linux private FS custody only. Opaque fixture material is not a valid
//! certificate/publisher/runtime bootstrap, enrollment or C07 proof.
#![cfg(all(target_os = "linux", target_env = "gnu"))]
use super::*;
use crate::store::{LockResource, StoreError};
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};
use styx_contracts::{identity::Sha256Digest, management::ReaderContract, native_management::*};

const DEPLOYMENT: &[u8] =
    b"{\"schema\":1,\"mode\":\"create-local\",\"gateway\":{\"url\":\"https://127.0.0.1:4444\"}}\n";
const NOW: u64 = 1_800_000_000;
const FILES: [&str; 7] = [
    "gateway-ca.pem",
    "gateway-ca-key.pem",
    "gateway-chain.pem",
    "gateway-key.pem",
    "gateway-admin.token",
    "gateway-model.token",
    "gateway-ready-v1.json",
];
fn material() -> FreshGatewayFiles<'static> {
    FreshGatewayFiles {
        certificate_pem: b"opaque-owned-test-ca",
        ca_private_key_pem: b"opaque-owned-test-ca-key",
        endpoint_chain_pem: b"opaque-owned-test-endpoint-chain",
        endpoint_private_key_pem: b"opaque-owned-test-endpoint-key",
        admin_token: b"owned_test_admin_012345678901234567890123456789",
        model_token: b"owned_test_model_012345678901234567890123456789",
        ready_binding: b"{\"schema\":1,\"test_custody_only\":true}\n",
    }
}
fn state(fresh: &FreshNativeRoot) -> NativeState {
    NativeState {
        schema: NATIVE_STATE_SCHEMA,
        kind: NativeStateKind::StyxDesiredState,
        runtime_format: NativeRuntimeFormat::NativeRustV1,
        reader_contract: ReaderContract::NativeManagementStateV1,
        scope_generation: fresh.marker().scope_generation,
        deployment_raw_sha256: Sha256Digest::of_bytes(DEPLOYMENT),
        mode: NativeDeploymentMode::CreateLocal,
        revision: 0,
        last_transaction: None,
        desired: NativeDesired {
            gateway: Some(NativeComponentDesired {
                manager: NativeManager::ForegroundCli,
                run: NativeRunDesired::Stopped,
                autostart: NativeAutostartDesired::Disabled,
            }),
            host: None,
        },
        migration: None,
        extensions: BTreeMap::new(),
    }
}
fn fresh(parent: &PrivateRoot, name: &str) -> FreshNativeRoot {
    create_fresh(parent, OsStr::new(name)).unwrap_or_else(|e| panic!("fresh_root: {:?}", e.error()))
}
fn private_file(path: &Path, raw: &[u8]) {
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(raw).unwrap();
    file.sync_all().unwrap();
}
fn busy(path: &Path) {
    assert!(matches!(
        PrivateRoot::open(path).unwrap().try_configuration_writer(),
        Err(StoreError::Busy(LockResource::ConfigurationWriter))
    ));
}
#[test]
#[ignore = "requires STYX_TEST_NATIVE_GATEWAY_ROOT; owned actual FS custody/floor/final-ready and retained failure, not TLS or runtime acceptance"]
fn fresh_gateway_material_floor_ready_and_failure_custody() {
    let base = PathBuf::from(std::env::var("STYX_TEST_NATIVE_GATEWAY_ROOT").unwrap());
    let _base = PrivateRoot::open(&base).unwrap();
    let parent_path = base.join(uuid::Uuid::new_v4().to_string());
    fs::create_dir(&parent_path).unwrap();
    fs::set_permissions(&parent_path, fs::Permissions::from_mode(0o700)).unwrap();
    let parent = PrivateRoot::open(&parent_path).unwrap();
    let root = fresh(&parent, "normal");
    let original_state = state(&root);
    let path = parent_path.join("normal");
    let binding = root
        .initialize_gateway(DEPLOYMENT, &original_state, material(), NOW)
        .unwrap_or_else(|e| panic!("gateway_init: {:?}", e.error()));
    busy(&path);
    let reader = PrivateRoot::open(&path).unwrap();
    let m = material();
    let expected = [
        m.certificate_pem,
        m.ca_private_key_pem,
        m.endpoint_chain_pem,
        m.endpoint_private_key_pem,
        m.admin_token,
        m.model_token,
        m.ready_binding,
    ];
    let mut originals = Vec::new();
    for (name, bytes) in FILES.iter().zip(expected) {
        let raw = reader.read_raw(name, 1024 * 1024).unwrap();
        assert!(raw.bytes() == bytes);
        let metadata = fs::symlink_metadata(path.join(name)).unwrap();
        assert!(
            metadata.is_file()
                && metadata.permissions().mode() & 0o7777 == 0o600
                && metadata.nlink() == 1
        );
        originals.push((name, raw.observation().clone(), raw.bytes().to_vec()));
    }
    let validated = binding.validated_readstate().unwrap();
    assert_eq!(validated.state().revision, 0);
    assert!(validated.state().migration.is_none());
    assert_eq!(
        validated.state().desired.gateway.as_ref().unwrap().run,
        NativeRunDesired::Stopped
    );
    let floor = fs::read(path.join(".styx-enrollment-journal-v1/clock.floor")).unwrap();
    assert!(floor.as_slice() == NOW.checked_mul(1000).unwrap().to_be_bytes().as_slice());
    let inventory: Vec<_> = fs::read_dir(path.join(".styx-enrollment-journal-v1"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(inventory, vec![std::ffi::OsString::from("clock.floor")]);
    let second = create_fresh(&parent, OsStr::new("normal")).err().unwrap();
    assert_eq!(second.error(), NativeRootError::AlreadyExists);
    assert!(!second.writer_held());
    for (name, observation, bytes) in originals {
        let raw = reader.read_raw(name, 1024 * 1024).unwrap();
        assert!(raw.observation() == &observation && raw.bytes() == bytes);
    }
    drop(second);
    // Malformed clock is rejected before material/canonical IO; same fresh
    // writer remains owned by the failure and cannot be acquired elsewhere.
    let root = fresh(&parent, "bad-clock");
    let s = state(&root);
    let bad = parent_path.join("bad-clock");
    let failure = root
        .initialize_gateway(DEPLOYMENT, &s, material(), 0)
        .err()
        .unwrap();
    assert_eq!(failure.error(), NativeRootError::InvalidInput);
    assert!(failure.writer_held());
    busy(&bad);
    for name in FILES.into_iter().chain(["deployment.json", "state.json"]) {
        assert!(!bad.join(name).exists());
    }
    assert!(!bad.join(".styx-enrollment-journal-v1/clock.floor").exists());
    // Concrete post-first-file collision: exclusive create refuses it, retains
    // the original writer, and cannot publish canonical genesis or final ready.
    let root = fresh(&parent, "interrupted");
    let s = state(&root);
    let interrupted = parent_path.join("interrupted");
    let injected = AtomicBool::new(false);
    let failure =
        platform::initialize_gateway(root, DEPLOYMENT, &s, material(), NOW, &|name, phase| {
            if name == "gateway-ca.pem"
                && phase == "directory_sync"
                && !injected.swap(true, Ordering::SeqCst)
            {
                private_file(
                    &interrupted.join("gateway-ca-key.pem"),
                    b"owned-collision-preserve",
                );
            }
        })
        .err()
        .unwrap();
    assert!(injected.load(Ordering::SeqCst));
    assert_eq!(failure.error(), NativeRootError::Unknown);
    assert!(failure.writer_held());
    busy(&interrupted);
    assert!(!interrupted.join("gateway-ready-v1.json").exists());
    assert!(!interrupted.join("state.json").exists());
    assert!(
        fs::read(interrupted.join("gateway-ca-key.pem")).unwrap() == b"owned-collision-preserve"
    );
    // The original partial material remains readable; no hidden completion.
    let partial = PrivateRoot::open(&interrupted)
        .unwrap()
        .read_raw("gateway-ca.pem", 128 * 1024)
        .unwrap();
    assert!(partial.bytes() == material().certificate_pem);
    println!(
        "native_gateway_store_custody=true; ready_last=true; floor_unix_milliseconds=true; runtime_tls_pairing=NOT_RUN"
    );
}
