//! Protected canonical + real signed-reader projection, never activation/GUI acceptance.
use super::*;
use crate::store::native_root;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey, pkcs8::EncodePublicKey as _};
use std::{
    fs,
    io::Write as _,
    os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _},
};
use styx_contracts::native_management::*;

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
fn candidate(top: &Path, name: &str, capable: bool) -> VerifiedNativeRelease {
    let container = top.join(name);
    directory(&container);
    let payload = container.join("payload");
    directory(&payload);
    directory(&payload.join("bin"));
    let files: Vec<_> = [
        (
            "LICENSE",
            b"advertisement projection fixture".as_slice(),
            false,
        ),
        (
            "bin/styx",
            b"\x7fELF fixture image, never executed".as_slice(),
            true,
        ),
        ("source-inputs.json", b"{}".as_slice(), false),
    ]
    .into_iter()
    .map(|(name, bytes, executable)| {
        write(&payload.join(name), bytes, executable);
        serde_json::json!({"path":name,"size":bytes.len(),
            "sha256":Sha256Digest::of_bytes(bytes),"executable":executable})
    })
    .collect();
    let signer = SigningKey::from_bytes(&[67; 32]);
    let pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        base64::engine::general_purpose::STANDARD.encode(
            signer
                .verifying_key()
                .to_public_key_der()
                .unwrap()
                .as_bytes()
        )
    );
    let publisher = container.join("publisher.pem");
    write(&publisher, pem.as_bytes(), false);
    let pin = crate::crypto::PublisherVerifyingKey::from_spki_pem(pem.as_bytes())
        .unwrap()
        .fingerprint()
        .unwrap();
    let raw = serde_json::to_vec(&serde_json::json!({"schema":2,"runtime_format":"native_rust_v1",
        "component":"styx","scope":"runtime_candidate","minimum_reader":if capable {"native_pairing_lifecycle_v1"} else {"native_runtime_migrated_v3"},
        "target":"x86_64-unknown-linux-gnu","version":"0.4.0-test.advertisement","entrypoint":"bin/styx",
        "source":{"revision":"1".repeat(40),"inputs_sha256":Sha256Digest::of_bytes(b"{}")},
        "contracts":{"control":1,"management_state":if capable {7} else {2}},"files":files,"external_workers":[]})).unwrap();
    write(&payload.join("manifest.json"), &raw, false);
    write(
        &payload.join("manifest.sig"),
        &signer.sign(&raw).to_bytes(),
        false,
    );
    release::verify(&payload, &publisher, &pin).unwrap()
}
fn canonical(
    top: &Path,
    name: &str,
    capable: bool,
    candidate: &VerifiedNativeRelease,
) -> (
    native_root::NativeRootBinding,
    native_state::ValidatedNativeState,
) {
    let parent = PrivateRoot::open(top).unwrap();
    let fresh = native_root::create_fresh(&parent, std::ffi::OsStr::new(name))
        .unwrap_or_else(|failure| panic!("fresh root: {:?}", failure.error()));
    let deployment = b"{\"advertisement_projection_fixture\":true}";
    let state = NativeState {
        schema: if capable { 7 } else { 2 },
        kind: NativeStateKind::StyxDesiredState,
        runtime_format: NativeRuntimeFormat::NativeRustV1,
        reader_contract: if capable {
            ReaderContract::NativePairingLifecycleStateV1
        } else {
            ReaderContract::NativeManagementStateV1
        },
        scope_generation: fresh.marker().scope_generation,
        deployment_raw_sha256: Sha256Digest::of_bytes(deployment),
        mode: NativeDeploymentMode::CreateLocal,
        revision: 0,
        last_transaction: None,
        migration: None,
        desired: NativeDesired {
            host: None,
            gateway: Some(NativeComponentDesired {
                manager: NativeManager::AppManaged,
                run: NativeRunDesired::Running,
                autostart: NativeAutostartDesired::Disabled,
            }),
        },
        extensions: BTreeMap::from([(
            NATIVE_RUNTIME_SELECTION_KEY.into(),
            serde_json::value::to_raw_value(&candidate.runtime_selection().unwrap()).unwrap(),
        )]),
    };
    let binding = fresh
        .initialize(deployment, &state)
        .unwrap_or_else(|failure| panic!("genesis: {:?}", failure.error()));
    let captured = binding.validated_readstate().unwrap();
    let root = PrivateRoot::open(top.join(name)).unwrap();
    crate::store::native_host_snapshot::validated_runtime_selection(
        &root,
        &captured,
        binding.marker(),
    )
    .unwrap();
    (binding, captured)
}

#[test]
fn rejection_advertisement_requires_canonical_seven_and_a_verified_compatible_reader() {
    let top = std::env::temp_dir().join(format!(
        "styx-rejection-advertisement-{}",
        uuid::Uuid::new_v4()
    ));
    directory(&top);
    let capable = candidate(&top, "reader-seven", true);
    let old = candidate(&top, "reader-old", false);
    let (old_binding, old_state) = canonical(&top, "old-state", false, &capable);
    assert!(
        !pairing_rejection_projection(&old_state, &capable),
        "a capable App cannot upgrade a canonical old profile by advertising"
    );
    let (new_binding, new_state) = canonical(&top, "new-state", true, &capable);
    assert!(pairing_rejection_projection(&new_state, &capable));
    let (mixed_binding, mixed_state) = canonical(&top, "incompatible-selection", true, &old);
    assert!(
        !pairing_rejection_projection(&mixed_state, &old),
        "schema seven alone cannot make an old signed runtime support rejection"
    );
    // The real original configuration writers remain held by these bindings;
    // this metadata projection never requests another writer or starts an image.
    drop(mixed_binding);
    drop(new_binding);
    drop(old_binding);
    drop(old);
    drop(capable);
    fs::remove_dir_all(top).unwrap();
}
