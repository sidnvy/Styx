//! Real protected roots, Ed25519 releases and C07 preparation; no activation.
//! Synthetic publisher keys are test fixtures, never the user's signer.
use super::*;
use crate::store::{
    enrollment::{EnrollmentJournal, JournalBudget, OwnedEnrollmentJournal},
    management::OwnedManagementJournal,
    native_root::{self, NativeRootBinding},
};
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey, pkcs8::EncodePublicKey as _};
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs,
    io::Write as _,
    os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
};
use styx_contracts::{enrollment as contract, native_management::*};

const DEPLOYMENT: &[u8] = b"{\"pairing_reader_fixture\":true}\n";
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
fn signed_selection(top: &Path, capable: bool) -> NativeRuntimeSelection {
    let payload = top.join("payload");
    directory(&payload);
    directory(&payload.join("bin"));
    let files: Vec<_> = [
        ("LICENSE", b"reader-floor fixture".as_slice(), false),
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
    let key = SigningKey::from_bytes(&[53u8; 32]);
    let pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        base64::engine::general_purpose::STANDARD
            .encode(key.verifying_key().to_public_key_der().unwrap().as_bytes())
    );
    let publisher = top.join("publisher.pem");
    write(&publisher, pem.as_bytes(), false);
    let pin = crate::crypto::PublisherVerifyingKey::from_spki_pem(pem.as_bytes())
        .unwrap()
        .fingerprint()
        .unwrap();
    let manifest = serde_json::to_vec(&serde_json::json!({"schema":2,"runtime_format":"native_rust_v1",
        "component":"styx","scope":"runtime_candidate",
        "minimum_reader":if capable {"native_pairing_lifecycle_v1"} else {"native_runtime_migrated_v3"},
        "target":"x86_64-unknown-linux-gnu","version":"0.4.0-test.1","entrypoint":"bin/styx",
        "source":{"revision":"1".repeat(40),"inputs_sha256":Sha256Digest::of_bytes(b"{}")},
        "contracts":{"control":1,"management_state":if capable {7} else {2}},
        "files":files,"external_workers":[]})).unwrap();
    write(&payload.join("manifest.json"), &manifest, false);
    write(
        &payload.join("manifest.sig"),
        &key.sign(&manifest).to_bytes(),
        false,
    );
    crate::release::verify(&payload, &publisher, &pin)
        .unwrap()
        .runtime_selection()
        .unwrap()
}
fn fresh(top: &Path, selected: &NativeRuntimeSelection, capable: bool) -> NativeRootBinding {
    let parent = PrivateRoot::open(top).unwrap();
    let fresh = native_root::create_fresh(&parent, OsStr::new("native"))
        .unwrap_or_else(|e| panic!("fresh fixture refused: {:?}", e.error()));
    let state = NativeState {
        schema: if capable { 7 } else { NATIVE_STATE_SCHEMA },
        kind: NativeStateKind::StyxDesiredState,
        runtime_format: NativeRuntimeFormat::NativeRustV1,
        reader_contract: if capable {
            ReaderContract::NativePairingLifecycleStateV1
        } else {
            ReaderContract::NativeManagementStateV1
        },
        scope_generation: fresh.marker().scope_generation,
        deployment_raw_sha256: Sha256Digest::of_bytes(DEPLOYMENT),
        mode: NativeDeploymentMode::CreateLocal,
        revision: 0,
        last_transaction: None,
        desired: NativeDesired {
            host: None,
            gateway: Some(NativeComponentDesired {
                manager: NativeManager::ForegroundCli,
                run: NativeRunDesired::Stopped,
                autostart: NativeAutostartDesired::Disabled,
            }),
        },
        migration: None,
        extensions: BTreeMap::from([(
            NATIVE_RUNTIME_SELECTION_KEY.to_owned(),
            serde_json::value::to_raw_value(selected).unwrap(),
        )]),
    };
    fresh
        .initialize(DEPLOYMENT, &state)
        .unwrap_or_else(|e| panic!("genesis fixture refused: {:?}", e.error()))
}
fn fixture(capable: bool, signed_capable: bool) -> (PathBuf, NativeRootBinding) {
    let top = std::env::temp_dir().join(format!("styx-pairing-reader-{}", uuid::Uuid::new_v4()));
    directory(&top);
    let selected = signed_selection(&top, signed_capable);
    let binding = fresh(&top, &selected, capable);
    (top, binding)
}
fn rejected_intent() -> Vec<u8> {
    contract::encode(&contract::IntentBody {
        schema: 1,
        gateway_epoch: "reader-fixture".try_into().unwrap(),
        transaction: "reject-fixture".try_into().unwrap(),
        sequence: 1,
        expected_revision: 0,
        prepared_at: 100,
        required_materials: vec![],
        mutation: contract::Mutation::Reject {
            target: contract::CredentialTarget {
                request: "request-fixture".try_into().unwrap(),
                device: "device-fixture".try_into().unwrap(),
                fingerprint: Sha256Digest::of_bytes(b"device"),
                profile: contract::OpaqueProfileRef(Sha256Digest::of_bytes(b"profile")),
                pending_facts_digest: Sha256Digest::of_bytes(b"facts"),
            },
        },
    })
    .unwrap()
}
fn bytes(journal: &EnrollmentJournal<'_>) -> Vec<(String, Vec<u8>)> {
    journal
        .scan()
        .unwrap()
        .files
        .into_iter()
        .map(|f| (f.name.clone(), f.bytes().to_vec()))
        .collect()
}

#[test]
fn signed_fresh_reader_gate_uses_the_same_owner_without_writing() {
    let (top, binding) = fixture(true, true);
    let owner = binding.configuration_root();
    owner.require_pairing_lifecycle_reader().unwrap();
    let mut journal =
        OwnedEnrollmentJournal::from_configuration(owner.clone(), JournalBudget::default())
            .unwrap();
    journal
        .with_journal(|j| {
            let before = bytes(j);
            j.require_pairing_lifecycle_reader()?;
            assert_eq!(bytes(j), before);
            Ok(())
        })
        .unwrap();
    assert!(owner.ensure_admission().is_ok());
    drop(journal);
    drop(owner);
    drop(binding);
    fs::remove_dir_all(top).unwrap();
}

#[test]
fn generic_and_old_native_journals_cannot_prepare_reject() {
    let top = std::env::temp_dir().join(format!("styx-generic-reject-{}", uuid::Uuid::new_v4()));
    directory(&top);
    let root = PrivateRoot::open(&top).unwrap();
    let mut writer = root.try_configuration_writer().unwrap();
    // OwnedConfigurationRoot claims existing domain resources; it never
    // initializes or adopts a namespace that appeared after owner discovery.
    // Use the ordinary initializer under this original writer before moving it.
    {
        let mut journal =
            EnrollmentJournal::open(&root, &mut writer, JournalBudget::default()).unwrap();
        journal.record_time_floor(100).unwrap();
    }
    let owner = OwnedConfigurationRoot::open_existing(root, writer).unwrap();
    assert!(owner.ensure_admission().is_ok());
    let mut generic =
        OwnedEnrollmentJournal::from_configuration(owner.clone(), JournalBudget::default())
            .unwrap();
    assert_eq!(
        owner.require_pairing_lifecycle_reader(),
        Err(JournalError::Conflict)
    );
    assert!(owner.ensure_admission().is_ok());
    generic
        .with_journal(|j| {
            let before = bytes(j);
            assert_eq!(
                j.prepare(&rejected_intent(), None),
                Err(JournalError::Conflict)
            );
            assert_eq!(bytes(j), before);
            Ok(())
        })
        .unwrap();
    assert!(owner.ensure_admission().is_ok());
    drop(generic);
    drop(owner);
    fs::remove_dir_all(top).unwrap();

    let (top, binding) = fixture(false, false);
    let owner = binding.configuration_root();
    let mut old =
        OwnedEnrollmentJournal::from_configuration(owner.clone(), JournalBudget::default())
            .unwrap();
    assert_eq!(
        owner.require_pairing_lifecycle_reader(),
        Err(JournalError::Conflict)
    );
    old.with_journal(|j| {
        let before = bytes(j);
        assert_eq!(
            j.prepare(&rejected_intent(), None),
            Err(JournalError::Conflict)
        );
        assert_eq!(bytes(j), before);
        Ok(())
    })
    .unwrap();
    assert!(owner.ensure_admission().is_ok());
    drop(old);
    drop(owner);
    drop(binding);
    fs::remove_dir_all(top).unwrap();
}

#[test]
fn schema_seven_alone_cannot_authorize_reject_with_an_old_signed_runtime() {
    let (top, binding) = fixture(true, false);
    let owner = binding.configuration_root();
    let mut journal =
        OwnedEnrollmentJournal::from_configuration(owner.clone(), JournalBudget::default())
            .unwrap();
    assert_eq!(
        owner.require_pairing_lifecycle_reader(),
        Err(JournalError::Conflict)
    );
    journal
        .with_journal(|j| {
            let before = bytes(j);
            assert_eq!(
                j.prepare(&rejected_intent(), None),
                Err(JournalError::Conflict)
            );
            assert_eq!(bytes(j), before);
            Ok(())
        })
        .unwrap();
    assert!(owner.ensure_admission().is_ok());
    drop(journal);
    drop(owner);
    drop(binding);
    fs::remove_dir_all(top).unwrap();
}

#[test]
fn actual_prepare_only_c07_tip_cannot_pass_the_floor_gate() {
    use styx_contracts::management::DesiredStateCommit;
    let (top, binding) = fixture(true, true);
    let owner = binding.configuration_root();
    let before = binding.validated_readstate().unwrap();
    let mut target = before.state().clone();
    target.revision = 1;
    target.last_transaction = Some(NativeStateTransaction {
        transaction_id: "prepare-only".try_into().unwrap(),
        sequence: 1,
    });
    target.desired.gateway.as_mut().unwrap().run = NativeRunDesired::Running;
    let target = serde_json::to_vec(&target).unwrap();
    let intent = DesiredStateCommit {
        transaction_id: "prepare-only".try_into().unwrap(),
        sequence: 1,
        deployment_raw_sha256: Sha256Digest::of_bytes(DEPLOYMENT),
        before_state_sha256: before.raw_sha256(),
        target_state_sha256: Sha256Digest::of_bytes(&target),
        reader: ReaderContract::NativePairingLifecycleStateV1,
    };
    let management =
        OwnedManagementJournal::open_existing(owner.clone(), JournalBudget::default()).unwrap();
    let maintenance = owner
        .begin_standalone_native(intent.transaction_id.clone(), false)
        .unwrap();
    management
        .prepare(
            &maintenance,
            &serde_json::to_vec(&intent).unwrap(),
            before.raw_bytes(),
            &target,
        )
        .unwrap();
    assert_eq!(
        owner.require_pairing_lifecycle_reader(),
        Err(JournalError::Conflict)
    );
    // Exercise the underlying final gate too, independently of the ordinary
    // owner's explicit maintenance fence. It must reject incomplete C07.
    assert_eq!(
        owner.with_state(|state| require(&state.root, &state.writer)),
        Err(JournalError::Conflict)
    );
    assert_eq!(
        fs::read(top.join("native/state.json")).unwrap(),
        before.raw_bytes()
    );
    drop(maintenance);
    drop(management);
    drop(owner);
    drop(binding);
    fs::remove_dir_all(top).unwrap();
}

#[test]
fn same_bytes_input_replacement_fails_the_original_file_pin() {
    let (top, binding) = fixture(true, true);
    let owner = binding.configuration_root();
    assert_eq!(
        owner.with_state(|state| {
            let deployment = state
                .root
                .read_raw("deployment.json", NATIVE_STATE_BYTES)
                .unwrap();
            let replacement = top.join("native/replacement.json");
            write(&replacement, deployment.bytes(), false);
            assert_ne!(
                fs::metadata(&replacement).unwrap().ino(),
                deployment.observation().inode
            );
            fs::rename(replacement, top.join("native/deployment.json")).unwrap();
            revalidate_inputs(&state.root, &[&deployment])
        }),
        Err(JournalError::Unknown)
    );
    assert_eq!(owner.ensure_admission(), Err(JournalError::Unknown));
    drop(owner);
    drop(binding);
    fs::remove_dir_all(top).unwrap();
}
