//! Actual private journal I/O with explicitly synthetic material DATA. No crypto,
//! process settlement, Darwin rename, candidate execution or migration acceptance.
use super::*;
use crate::store::PrivateRoot;
use handoff::{NativeRetirementFileStamp, RetirementFileStamp, RetirementKind};
use std::{
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

fn mkdir(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}
fn write(path: &Path, raw: &[u8]) {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    f.write_all(raw).unwrap();
    f.sync_all().unwrap();
}
fn observed(path: &Path) -> NativeRetirementFileStamp {
    let m = fs::metadata(path).unwrap();
    NativeRetirementFileStamp::Linux {
        stamp: RetirementFileStamp {
            device: m.dev(),
            inode: m.ino(),
            uid: m.uid(),
            mode: m.mode(),
            nlink: m.nlink(),
            byte_len: m.len(),
            modified_seconds: m.mtime(),
            modified_nanoseconds: m.mtime_nsec(),
            changed_seconds: m.ctime(),
            changed_nanoseconds: m.ctime_nsec(),
            sha256: Sha256Digest::of_bytes(&fs::read(path).unwrap()),
        },
    }
}
fn json<T: Serialize>(v: &T) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}
struct Fixture {
    path: PathBuf,
    host: PathBuf,
    owner: OwnedConfigurationRoot,
    maintenance: ConfigurationMaintenance,
    journal: OwnedManagementJournal,
    input: MigrationPlanInputs,
}
fn fixture(parent: &Path, budget: JournalBudget) -> Fixture {
    let path = parent.join(format!("native-pre-effect-plan-{}", uuid::Uuid::new_v4()));
    mkdir(&path);
    let host = path.join("host");
    mkdir(&host);
    mkdir(&host.join("device"));
    let deployment = br#"{"schema":1,"mode":"join-existing","host":{}}"#;
    let before =
        br#"{ "schema":1, "historicalOutcome":"unknown", "opaque":900719925474099312345 }"#;
    write(&path.join("deployment.json"), deployment);
    write(&path.join("state.json"), before);
    write(
        &host.join("device/host.token"),
        b"synthetic-original-token-no-production-credential",
    );
    let root = PrivateRoot::open(&path).unwrap();
    let host_root = PrivateRoot::open(&host).unwrap();
    let config_identity = actual_root(root.identity()).unwrap();
    let host_identity = actual_root(host_root.identity()).unwrap();
    let writer = root.try_configuration_writer().unwrap();
    let owner = OwnedConfigurationRoot::open_existing(root, writer).unwrap();
    let tx: TransactionId = "pre-effect-plan".try_into().unwrap();
    let maintenance = owner.begin_standalone_native(tx.clone(), false).unwrap();
    let journal =
        OwnedManagementJournal::open_for_native_retirement(owner.clone(), &maintenance, budget)
            .unwrap();
    let preservation = br#"[{"fixture":"full-original-manifest"}]"#.to_vec();
    let selected = br#"[{"fixture":"selected-legacy-material"}]"#.to_vec();
    let candidate = Sha256Digest::of_bytes(b"synthetic-candidate-no-signature-authority");
    let publisher = Sha256Digest::of_bytes(b"synthetic-publisher-data");
    let token = observed(&host.join("device/host.token"));
    let retirement = NativeRetirementIntent {
        schema: 3,
        kind: RetirementKind::LegacyCredentialRetirement,
        transaction_id: tx.clone(),
        sequence: 1,
        config_root: config_identity.clone(),
        host_root: host_identity.clone(),
        deployment_raw_sha256: Sha256Digest::of_bytes(deployment),
        before_state_sha256: Sha256Digest::of_bytes(before),
        preservation_sha256: Sha256Digest::of_bytes(&selected),
        service_descriptor_sha256: Sha256Digest::of_bytes(b"synthetic-service"),
        candidate_manifest_sha256: candidate,
        publisher_spki_sha256: publisher,
        original_token: token.clone(),
    };
    let material = Sha256Digest::of_bytes(b"synthetic-public-material-data");
    let pair = NativePreservedHostPair {
        schema: 1,
        transaction_id: tx,
        config_root: config_identity.clone(),
        host_root: host_identity,
        deployment_raw_sha256: Sha256Digest::of_bytes(deployment),
        device_id: "styx-0123456789abcdef01234567".try_into().unwrap(),
        fingerprint: material,
        gateway_origin: "https://127.0.0.1:22022".into(),
        gateway_ca_pem_sha256: material,
        identity_json_sha256: material,
        identity_private_pem_sha256: material,
        host_profile_sha256: material,
        credential_sha256: token.content_sha256(),
        preservation_sha256: Sha256Digest::of_bytes(&preservation),
    };
    let marker = NativeRootMarker {
        schema: NATIVE_MARKER_SCHEMA,
        kind: NativeRootKind::StyxConfigurationRoot,
        runtime_format: NativeRuntimeFormat::NativeRustV1,
        root_identity: config_identity.clone(),
        scope_generation: Sha256Digest::of_bytes(b"explicit-synthetic-once-marker"),
        reader_floor: styx_contracts::management::ReaderContract::NativeMigratedStateV2,
    };
    let desired = NativeDesired {
        gateway: None,
        host: Some(NativeComponentDesired {
            run: NativeRunDesired::Stopped,
            autostart: NativeAutostartDesired::Disabled,
            manager: NativeManager::ForegroundCli,
        }),
    };
    let selection = NativeRuntimeSelection {
        schema: 1,
        payload_path: path.join("candidate").to_str().unwrap().into(),
        payload_root: config_identity,
        manifest_sha256: candidate,
        publisher_file: path.join("publisher.pem").to_str().unwrap().into(),
        publisher_spki_sha256: publisher,
    };
    let input = MigrationPlanInputs {
        retirement: json(&retirement),
        host_pair: json(&pair),
        desired: json(&desired),
        marker: json(&marker),
        runtime_selection: json(&selection),
        owner_recovery: None,
        before: before.to_vec(),
        preservation,
        selected,
    };
    Fixture {
        path,
        host,
        owner,
        maintenance,
        journal,
        input,
    }
}
fn snapshot(path: &Path) -> Vec<(String, Vec<u8>, u64, i64, i64)> {
    let mut files: Vec<_> = fs::read_dir(path)
        .unwrap()
        .map(|f| {
            let p = f.unwrap().path();
            let m = fs::metadata(&p).unwrap();
            (
                p.file_name().unwrap().to_str().unwrap().to_owned(),
                fs::read(&p).unwrap(),
                m.ino(),
                m.ctime(),
                m.ctime_nsec(),
            )
        })
        .collect();
    files.sort_by(|a, b| a.0.cmp(&b.0));
    files
}
#[test]
#[ignore = "STYX_TEST_MANAGEMENT_HANDOFF_ROOT; actual Linux private-journal plan/reopen/partial refusal, not Mac native acceptance"]
fn original_pre_effect_plan_survives_reopen_and_partial_publication() {
    let parent = PathBuf::from(std::env::var_os("STYX_TEST_MANAGEMENT_HANDOFF_ROOT").unwrap());
    let mut f = fixture(&parent, JournalBudget::default());
    let state = fs::read(f.path.join("state.json")).unwrap();
    let state_id = fs::metadata(f.path.join("state.json")).unwrap().ino();
    let source = fs::read(f.host.join("device/host.token")).unwrap();
    let source_id = fs::metadata(f.host.join("device/host.token"))
        .unwrap()
        .ino();
    let p = f
        .journal
        .persist_native_migration_plan(&f.maintenance, &f.input)
        .unwrap();
    assert!(p.complete());
    assert_eq!(p.marker_raw(), f.input.marker);
    let inv = f.journal.observe().unwrap();
    assert_eq!(inv.high_water, 1);
    assert!(inv.orphans.is_empty());
    assert!(inv.transactions.is_empty());
    assert!(inv.has_unresolved_legacy_handoffs());
    assert!(f.owner.ensure_admission().is_err());
    let ns = f.path.join(".styx-management-journal-v1");
    let original_files = snapshot(&ns);
    let saved_marker = f.input.marker.clone();
    let mut changed: NativeRootMarker = serde_json::from_slice(&saved_marker).unwrap();
    changed.scope_generation = Sha256Digest::of_bytes(b"different-marker-must-not-replace");
    f.input.marker = json(&changed);
    assert!(matches!(
        f.journal
            .persist_native_migration_plan(&f.maintenance, &f.input),
        Err(JournalError::Conflict)
    ));
    assert_eq!(snapshot(&ns), original_files);
    f.input.marker = saved_marker;
    let tx = p.retirement.transaction_id.clone();
    drop(p);
    drop(f.journal);
    drop(f.maintenance);
    drop(f.owner);
    let root = PrivateRoot::open(&f.path).unwrap();
    let writer = root.try_configuration_writer().unwrap();
    let owner = OwnedConfigurationRoot::open_existing(root, writer).unwrap();
    let maintenance = owner.begin_standalone_native(tx, true).unwrap();
    let mut journal =
        OwnedManagementJournal::open_existing(owner.clone(), JournalBudget::default()).unwrap();
    let original = journal.resync_native_migration_plan(&maintenance).unwrap();
    assert_eq!(original.marker_raw(), f.input.marker);
    assert_eq!(original.before.as_deref(), Some(state.as_slice()));
    assert_eq!(snapshot(&ns), original_files);
    // Real original journal retirement, using the SAME plan tx/sequence: no
    // second planned transaction or duplicate high-water entry is invented.
    let prepared = journal
        .prepare_native_credential_retirement(&maintenance, &original.retirement)
        .unwrap();
    let destination = f.host.join(original.retirement.token_destination());
    fs::rename(f.host.join("device/host.token"), &destination).unwrap();
    fs::File::open(&destination).unwrap().sync_all().unwrap();
    fs::File::open(f.host.join("device"))
        .unwrap()
        .sync_all()
        .unwrap();
    let post = observed(&destination);
    let retired = journal
        .record_native_credential_retired(&maintenance, &prepared, &post)
        .unwrap();
    assert!(retired.post_stamp() == &post);
    assert_eq!(journal.observe().unwrap().high_water, 1);
    assert!(journal.observe().unwrap().has_unresolved_legacy_handoffs());
    assert_eq!(fs::read(f.path.join("state.json")).unwrap(), state);
    assert_eq!(
        fs::metadata(f.path.join("state.json")).unwrap().ino(),
        state_id
    );
    assert_eq!(fs::read(&destination).unwrap(), source);
    assert_eq!(fs::metadata(&destination).unwrap().ino(), source_id);
    assert!(!f.host.join("device/host.token").exists());
    assert!(owner.ensure_admission().is_err());
    // Retain all fixtures for independent inspection. This is not scope cleanup
    // or migration commit; no old process was started by this fixture.

    let mut partial = fixture(&parent, JournalBudget::default());
    let header = encode(&partial.input).unwrap();
    let data = parse(&header).unwrap();
    let n = names(&data.retirement.transaction_id);
    partial
        .owner
        .with_maintenance(&partial.maintenance, |state| {
            partial.journal.with_directory_locked(state, |dir| {
                files::immutable(dir, &n[0], &header, JournalBudget::default(), &|_| {})
            })
        })
        .unwrap();
    let inv = partial.journal.observe().unwrap();
    assert_eq!(inv.high_water, 1);
    assert!(inv.orphans.is_empty());
    assert!(inv.has_unresolved_legacy_handoffs());
    assert!(
        !partial
            .journal
            .resync_native_migration_plan(&partial.maintenance)
            .unwrap()
            .complete()
    );
    assert!(matches!(
        partial
            .journal
            .prepare_native_credential_retirement(&partial.maintenance, &data.retirement),
        Err(JournalError::Conflict)
    ));
    let done = partial
        .journal
        .persist_native_migration_plan(&partial.maintenance, &partial.input)
        .unwrap();
    assert!(done.complete());
    assert_eq!(done.marker_raw(), partial.input.marker);
    assert!(partial.host.join("device/host.token").exists());
}
#[test]
#[ignore = "STYX_TEST_MANAGEMENT_HANDOFF_ROOT; actual journal zero-write budget refusal, not migration acceptance"]
fn pre_effect_plan_budget_refuses_before_header_publication() {
    let parent = PathBuf::from(std::env::var_os("STYX_TEST_MANAGEMENT_HANDOFF_ROOT").unwrap());
    let mut f = fixture(
        &parent,
        JournalBudget {
            max_files: 3,
            max_bytes: 1024 * 1024,
            max_file_bytes: 1024 * 1024,
        },
    );
    // Four immutable members are required. Preflight must reject a three-file
    // budget before publishing even the header; the source remains untouched.
    assert!(matches!(
        f.journal
            .persist_native_migration_plan(&f.maintenance, &f.input),
        Err(JournalError::BudgetExceeded)
    ));
    assert!(snapshot(&f.path.join(".styx-management-journal-v1")).is_empty());
    assert!(f.host.join("device/host.token").exists());
}

fn original_c_inputs(f: &Fixture) -> handoff::OwnerRecoveryPlan {
    use handoff::{
        LegacyOwnerRecoveryIntent, OwnerRecoveryPlan, RecoveryBoot, RecoveryGuard,
        RecoveryGuardBinding, RecoveryGuardName, RecoveryKind, RecoveryOriginal,
        RecoveryOriginalBinding, RecoveryOriginalName, RecoveryRestartBinding,
    };
    let successor: NativeRetirementIntent = serde_json::from_slice(&f.input.retirement).unwrap();
    // Original fixture files are private ordinary DATA. Their raw bytes and
    // actual filesystem stamps are captured before any C journal publication.
    let originals = [
        (
            RecoveryOriginalName::Lock,
            b"synthetic-original-lock-unknown-work".as_slice(),
        ),
        (
            RecoveryOriginalName::Owner,
            b"synthetic-original-owner-no-process-claim".as_slice(),
        ),
    ]
    .into_iter()
    .map(|(name, raw)| {
        let path = f.path.join(name.source_name());
        write(&path, raw);
        RecoveryOriginal {
            name,
            raw: raw.to_vec(),
            stamp: observed(&path),
        }
    })
    .collect::<Vec<_>>();
    let guards = [
        RecoveryGuardName::Advance,
        RecoveryGuardName::Background,
        RecoveryGuardName::Capabilities,
        RecoveryGuardName::Foreground,
    ]
    .into_iter()
    .map(|name| {
        // Distinct synthetic nonces chosen ONCE in the original captured
        // inputs, never generated by the recovery path.
        let raw = json(&serde_json::json!({"schema":1,"kind":"synthetic_c_guard",
                "scope":name,"nonce":Sha256Digest::of_bytes(name.source_name().as_bytes())}));
        RecoveryGuard { name, raw }
    })
    .collect::<Vec<_>>();
    let intent = LegacyOwnerRecoveryIntent {
        schema: 1,
        kind: RecoveryKind::LegacyOwnerRecovery,
        transaction_id: successor.transaction_id.clone(),
        sequence: successor.sequence,
        config_root: successor.config_root.clone(),
        deployment_raw_sha256: successor.deployment_raw_sha256,
        before_state_sha256: successor.before_state_sha256,
        candidate_manifest_sha256: successor.candidate_manifest_sha256,
        publisher_spki_sha256: successor.publisher_spki_sha256,
        previous_boot: Some(RecoveryBoot {
            id: "synthetic-previous-boot-not-OS-proof".into(),
            started_at_ms: 1000,
        }),
        current_boot: RecoveryBoot {
            id: "synthetic-current-boot-not-OS-proof".into(),
            started_at_ms: 2000,
        },
        basis: None,
        restart: RecoveryRestartBinding::ForegroundOnlyNoInstalledManager,
        successor_retirement_intent_sha256: Sha256Digest::of_bytes(&f.input.retirement),
        originals: originals
            .iter()
            .map(|o| RecoveryOriginalBinding {
                name: o.name,
                stamp: o.stamp.clone(),
            })
            .collect(),
        guards: guards
            .iter()
            .map(|g| RecoveryGuardBinding {
                name: g.name,
                sha256: Sha256Digest::of_bytes(&g.raw),
                byte_len: g.raw.len() as u64,
            })
            .collect(),
        startup_checkpoint: None,
    };
    OwnerRecoveryPlan {
        intent: raw(&json(&intent)).unwrap(),
        originals,
        guards,
        authorization_plan: None,
        startup_raw: None,
    }
}
#[test]
#[ignore = "STYX_TEST_MANAGEMENT_HANDOFF_ROOT; actual Linux partial-C journal recovery from original plan, not Mac OS settlement"]
fn saved_c_inputs_restore_partial_preparation_without_new_guard_nonce() {
    let parent = PathBuf::from(std::env::var_os("STYX_TEST_MANAGEMENT_HANDOFF_ROOT").unwrap());
    let mut f = fixture(&parent, JournalBudget::default());
    let saved = original_c_inputs(&f);
    let c_intent = saved.validated_intent().unwrap();
    let original_guard_bytes: Vec<_> = saved
        .guards
        .iter()
        .map(|g| (g.name, g.raw.clone()))
        .collect();
    let original_source_bytes: Vec<_> = saved
        .originals
        .iter()
        .map(|o| {
            (
                o.name,
                o.raw.clone(),
                fs::metadata(f.path.join(o.name.source_name()))
                    .unwrap()
                    .ino(),
            )
        })
        .collect();
    let raw_intent = saved.intent.get().as_bytes().to_vec();
    f.input.owner_recovery = Some(json(&saved));
    let plan = f
        .journal
        .persist_native_migration_plan(&f.maintenance, &f.input)
        .unwrap();
    assert!(plan.complete());
    let id = c_intent.transaction_id.clone();
    let member = |suffix: &str| format!("txn-{}.owner-recovery-{suffix}", id.as_str());
    let partial = saved
        .preparation_entries()
        .unwrap()
        .into_iter()
        .take(3)
        .collect::<Vec<_>>();
    assert_eq!(partial[0].0, member("intent"));
    assert_eq!(partial[1].0, member("prepared"));
    // Simulate an actual schema1 prepare prefix: intent, Prepared record bytes,
    // first original. Missing originals/guards mean NO complete Prepared
    // capability or physical archive effect, despite the phase file's name.
    f.owner
        .with_maintenance(&f.maintenance, |state| {
            f.journal.with_directory_locked(state, |dir| {
                for (name, bytes) in &partial {
                    files::immutable(dir, name, bytes, JournalBudget::default(), &|_| {})?;
                }
                Ok(())
            })
        })
        .unwrap();
    let ns = f.path.join(".styx-management-journal-v1");
    assert!(ns.join(member("prepared")).exists());
    assert!(!ns.join(member("original-owner")).exists());
    let partial_observations = snapshot(&ns);
    drop(saved);
    drop(plan);
    drop(f.journal);
    drop(f.maintenance);
    drop(f.owner);
    // Actual writer close/reopen: the inputs below come from the durable plan,
    // not a surviving original DTO or a fresh nonce generator.
    let root = PrivateRoot::open(&f.path).unwrap();
    let writer = root.try_configuration_writer().unwrap();
    let owner = OwnedConfigurationRoot::open_existing(root, writer).unwrap();
    let maintenance = owner.begin_standalone_native(id.clone(), true).unwrap();
    let mut journal =
        OwnedManagementJournal::open_existing(owner.clone(), JournalBudget::default()).unwrap();
    let recovered_plan = journal.resync_native_migration_plan(&maintenance).unwrap();
    let recovered = recovered_plan.owner_recovery_inputs().unwrap().unwrap();
    let recovered_intent = recovered.validated_intent().unwrap();
    assert!(recovered_intent == c_intent);
    assert_eq!(recovered.intent.get().as_bytes(), raw_intent);
    assert_eq!(
        recovered
            .guards
            .iter()
            .map(|g| (g.name, g.raw.clone()))
            .collect::<Vec<_>>(),
        original_guard_bytes
    );
    assert_eq!(snapshot(&ns), partial_observations);
    let prepared = journal
        .prepare_legacy_owner_recovery(
            &maintenance,
            &recovered_intent,
            recovered.originals,
            recovered.guards,
        )
        .unwrap();
    assert_eq!(
        prepared.stage(),
        Some(handoff::OwnerRecoveryStage::Prepared)
    );
    let original = journal
        .resync_legacy_owner_recovery(&maintenance, &id)
        .unwrap();
    assert_eq!(fs::read(ns.join(member("intent"))).unwrap(), raw_intent);
    assert_eq!(
        original
            .guard_bytes()
            .iter()
            .map(|g| (g.name, g.raw.clone()))
            .collect::<Vec<_>>(),
        original_guard_bytes
    );
    let inventory = journal.observe().unwrap();
    assert_eq!(inventory.high_water, 1);
    assert!(inventory.orphans.is_empty());
    assert!(inventory.has_unresolved_legacy_handoffs());
    for (name, bytes, inode) in &original_source_bytes {
        let path = f.path.join(name.source_name());
        assert_eq!(fs::read(&path).unwrap(), *bytes);
        assert_eq!(fs::metadata(path).unwrap().ino(), *inode);
    }
    // A later/unrecognized phase is never erased from the validation baseline
    // to make a fresh prepare look safe. Original fixed bytes remain untouched.
    owner
        .with_maintenance(&maintenance, |state| {
            journal.with_directory_locked(state, |dir| {
                files::immutable(
                    dir,
                    &member("unrecognized-phase"),
                    b"synthetic-unknown-phase",
                    JournalBudget::default(),
                    &|_| {},
                )
            })
        })
        .unwrap();
    let unknown_before = snapshot(&ns);
    assert!(journal.resync_native_migration_plan(&maintenance).is_err());
    let saved_again = recovered_plan.owner_recovery_inputs().unwrap().unwrap();
    assert!(
        journal
            .prepare_legacy_owner_recovery(
                &maintenance,
                &recovered_intent,
                saved_again.originals,
                saved_again.guards
            )
            .is_err()
    );
    assert_eq!(snapshot(&ns), unknown_before);
    assert!(owner.ensure_admission().is_err());

    // Independently corrupted saved guard raw (unchanged expected hash) must
    // reject BEFORE any header/C file is created, not repair or regenerate it.
    let mut bad = fixture(&parent, JournalBudget::default());
    let mut bad_saved = original_c_inputs(&bad);
    bad_saved.guards[0].raw[0] ^= 1; // same length, wrong content hash only
    bad.input.owner_recovery = Some(json(&bad_saved));
    let bad_ns = bad.path.join(".styx-management-journal-v1");
    let before = snapshot(&bad_ns);
    assert!(
        bad.journal
            .persist_native_migration_plan(&bad.maintenance, &bad.input)
            .is_err()
    );
    assert_eq!(snapshot(&bad_ns), before);
    assert!(before.is_empty());
    assert!(bad.host.join("device/host.token").exists());
    // All fixture files are retained; no physical C GuardsHeld, Mac boot,
    // process exit, authorization or migration commit is claimed here.
}
