//! Actual owned private files and canonical writes, with synthetic retirement,
//! history-hash and scope facts. This is not live service/credential authority,
//! Core enrollment recovery, power-loss durability or native activation proof.
use super::*;
use crate::store::{PrivateRoot, secure_journal::NamespaceName};
use std::{
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use styx_contracts::native_management::*;
const DEPLOYMENT: &[u8] = b"{\"schema\":1,\"mode\":\"create-local\",\"host\":{}}\n";
const BEFORE: &[u8] =
    b"{\"schema\":1,\"mode\":\"create-local\",\"opaque\":900719925474099312345}\n";
const PRESERVATION: &[u8] = b"owned preservation fixture, not a source-authority proof";
const FULL_PRESERVATION: &[u8] =
    b"full preservation artifact including original gateway and installation bindings";
const HISTORY: &[u8] = b"owned baseline hash fixture, not enrollment replay";
const COMMITTED: &[u8] = b"owned committed hash fixture, not enrollment durability attestation";
struct Fixture {
    path: PathBuf,
    journal: OwnedManagementJournal,
    owner: OwnedConfigurationRoot,
    maintenance: ConfigurationMaintenance,
    retired: handoff::LegacyCredentialRetirementIntent,
    marker: Vec<u8>,
    target: Vec<u8>,
}
fn directory(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}
fn write(path: &Path, raw: &[u8]) {
    let mut f = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    f.write_all(raw).unwrap();
    f.sync_all().unwrap();
}
fn stamp(path: &Path) -> handoff::RetirementFileStamp {
    let m = fs::metadata(path).unwrap();
    handoff::RetirementFileStamp {
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
    }
}
fn identity(root: &PrivateRoot) -> handoff::RetirementLinuxRoot {
    let RootIdentity::Linux { device, inode, uid } = root.identity();
    handoff::RetirementLinuxRoot { device, inode, uid }
}
fn fixture(parent: &Path, budget: JournalBudget) -> Fixture {
    let path = parent.join(uuid::Uuid::new_v4().to_string());
    directory(&path);
    directory(&path.join(NamespaceName::ManagementV1.as_str()));
    let history = path.join(NamespaceName::EnrollmentV1.as_str());
    directory(&history);
    write(&history.join("historical-baseline.intent"), HISTORY);
    write(&history.join("historical-baseline.committed"), COMMITTED);
    write(&path.join("deployment.json"), DEPLOYMENT);
    write(&path.join("state.json"), BEFORE);
    let host = path.join("host");
    directory(&host);
    directory(&host.join("device"));
    write(
        &host.join("device/host.token"),
        b"owned-fixture-token-not-production\n",
    );
    let config = PrivateRoot::open(&path).unwrap();
    let config_id = identity(&config);
    let host_id = identity(&PrivateRoot::open(&host).unwrap());
    let retired = handoff::LegacyCredentialRetirementIntent {
        schema: 1,
        kind: handoff::RetirementKind::LegacyCredentialRetirement,
        transaction_id: "cutover-owned-original".try_into().unwrap(),
        sequence: 9,
        config_root: config_id.clone(),
        host_root: host_id,
        deployment_raw_sha256: Sha256Digest::of_bytes(DEPLOYMENT),
        before_state_sha256: Sha256Digest::of_bytes(BEFORE),
        preservation_sha256: Sha256Digest::of_bytes(PRESERVATION),
        service_descriptor_sha256: Sha256Digest::of_bytes(b"original service fixture"),
        candidate_manifest_sha256: Sha256Digest::of_bytes(b"candidate fixture"),
        publisher_spki_sha256: Sha256Digest::of_bytes(b"publisher fixture"),
        original_token: stamp(&host.join("device/host.token")),
    };
    let writer = config.try_configuration_writer().unwrap();
    let owner = OwnedConfigurationRoot::open_existing(config, writer).unwrap();
    let maintenance = owner
        .begin_maintenance(retired.transaction_id.clone())
        .unwrap();
    let mut journal = OwnedManagementJournal::open_existing(owner.clone(), budget).unwrap();
    let prepared = journal
        .prepare_credential_retirement(&maintenance, &retired)
        .unwrap();
    let destination = host.join(retired.token_destination());
    fs::rename(host.join(retired.token_source()), &destination).unwrap();
    fs::File::open(host.join("device"))
        .unwrap()
        .sync_all()
        .unwrap();
    let retired_record = journal
        .record_credential_retired(&maintenance, &prepared, &stamp(&destination))
        .unwrap();
    let marker = NativeRootMarker {
        schema: 1,
        kind: NativeRootKind::StyxConfigurationRoot,
        runtime_format: NativeRuntimeFormat::NativeRustV1,
        root_identity: NativeRootIdentity::Linux {
            device: config_id.device,
            inode: config_id.inode,
            uid: config_id.uid,
        },
        scope_generation: Sha256Digest::of_bytes(b"synthetic scope entropy fixture"),
        reader_floor: ReaderContract::NativeMigratedStateV1,
    };
    let desired = NativeComponentDesired {
        manager: NativeManager::ForegroundCli,
        run: NativeRunDesired::Stopped,
        autostart: NativeAutostartDesired::Disabled,
    };
    let target = NativeState {
        schema: 2,
        kind: NativeStateKind::StyxDesiredState,
        runtime_format: NativeRuntimeFormat::NativeRustV1,
        reader_contract: ReaderContract::NativeMigratedStateV1,
        scope_generation: marker.scope_generation,
        deployment_raw_sha256: retired.deployment_raw_sha256,
        mode: NativeDeploymentMode::CreateLocal,
        revision: 1,
        last_transaction: Some(NativeStateTransaction {
            transaction_id: retired.transaction_id.clone(),
            sequence: retired.sequence,
        }),
        desired: NativeDesired {
            gateway: Some(desired),
            host: Some(desired),
        },
        migration: Some(NativeMigrationBinding {
            transaction_id: retired.transaction_id.clone(),
            original_state_sha256: retired.before_state_sha256,
            retired_receipt_sha256: retired_record.record_sha256(),
            enrollment_baseline_sha256: Sha256Digest::of_bytes(HISTORY),
            enrollment_committed_sha256: Sha256Digest::of_bytes(COMMITTED),
            candidate_manifest_sha256: retired.candidate_manifest_sha256,
            publisher_spki_sha256: retired.publisher_spki_sha256,
            preservation_sha256: Sha256Digest::of_bytes(FULL_PRESERVATION),
            scope_bindings_sha256: Sha256Digest::of_bytes(b"owned original scope facts fixture"),
            original_token_relative_path: retired.token_destination().to_str().unwrap().to_owned(),
        }),
        extensions: BTreeMap::new(),
    };
    Fixture {
        path,
        journal,
        owner,
        maintenance,
        retired,
        marker: serde_json::to_vec(&marker).unwrap(),
        target: serde_json::to_vec(&target).unwrap(),
    }
}
fn inputs(f: &Fixture) -> CutoverInputs {
    CutoverInputs {
        history_baseline_sha256: Sha256Digest::of_bytes(HISTORY),
        history_committed_sha256: Sha256Digest::of_bytes(COMMITTED),
        preservation: FULL_PRESERVATION.to_vec(),
        scope_bindings: b"owned original scope facts fixture".to_vec(),
        marker: f.marker.clone(),
        before: BEFORE.to_vec(),
        target: f.target.clone(),
        endpoint: None,
    }
}
// Endpoint bytes here are synthetic storage inputs, NOT certificates/TLS proof.
fn endpoint_inputs(f: &Fixture) -> CutoverInputs {
    let mut result = inputs(f);
    let marker = decode_marker(&f.marker).unwrap();
    let chain = b"synthetic chain bytes, no TLS assertion".to_vec();
    let binding = NativeGatewayEndpointBinding {
        schema: 1,
        transaction_id: f.retired.transaction_id.clone(),
        root_identity: marker.root_identity,
        candidate_manifest_sha256: f.retired.candidate_manifest_sha256,
        origin: "https://127.0.0.1:8443".to_owned(),
        anchor_sha256: Sha256Digest::of_bytes(b"synthetic anchor"),
        leaf_sha256: Sha256Digest::of_bytes(b"synthetic leaf"),
        chain_sha256: Sha256Digest::of_bytes(&chain),
        not_before_unix: 1,
        not_after_unix: 2,
    };
    let binding = serde_json::to_vec(&binding).unwrap();
    result.endpoint = Some(CutoverEndpointInputs {
        binding,
        chain,
        key: Zeroizing::new(b"synthetic key bytes, not production".to_vec()),
    });
    bind_endpoint_target(&mut result);
    result
}
fn bind_endpoint_target(inputs: &mut CutoverInputs) {
    let marker = decode_marker(&inputs.marker).unwrap();
    let mut target = decode_state(&inputs.target, &marker)
        .unwrap()
        .state()
        .clone();
    let binding = &inputs.endpoint.as_ref().unwrap().binding;
    target.extensions.insert(
        "gateway_endpoint_v1".to_owned(),
        serde_json::value::RawValue::from_string(String::from_utf8(binding.clone()).unwrap())
            .unwrap(),
    );
    inputs.target = serde_json::to_vec(&target).unwrap();
}
fn synthetic_validation(f: &Fixture) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schema":1,"status":"SYNTHETIC_STORAGE_DATA_NOT_A_NATIVE_PROBE",
        "transaction_id":f.retired.transaction_id,
        "candidate_manifest_sha256":f.retired.candidate_manifest_sha256,
        "exit_code":0,"liveness":"exited","drain":"drained",
        "executor_exited":true,"processes_exited":true,"reader_task_reaped":true,
        "stderr_task_reaped":true,"supervised_jobs_joined":true,"probe_task_joined":true
    }))
    .unwrap()
}
fn scan(f: &Fixture) -> JournalObservation {
    f.owner
        .with_state(|s| {
            f.journal
                .with_directory_locked(s, |d| files::scan(d, f.journal.budget))
        })
        .unwrap()
}
fn cleanup(f: Fixture) {
    let p = f.path.clone();
    drop(f);
    fs::remove_dir_all(p).unwrap();
}

#[test]
#[ignore = "STYX_TEST_MANAGEMENT_CUTOVER_ROOT; actual scratch same-journal successor/phase/crash-residue test, not C07 service or activation acceptance"]
fn same_original_cutover_chain_files_and_interruption_boundaries() {
    let parent = PathBuf::from(
        std::env::var_os("STYX_TEST_MANAGEMENT_CUTOVER_ROOT").expect("explicit fresh owned parent"),
    );
    // The gate supplies a fresh owned parent locator, as for the other private
    // journal scenarios. Create only that explicit scratch parent.
    fs::create_dir_all(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    let mut f = fixture(&parent, JournalBudget::default());
    let prepared = f
        .journal
        .prepare_cutover(&f.maintenance, inputs(&f))
        .unwrap();
    assert!(prepared.matches_owner(&f.owner));
    assert_eq!(
        prepared.intent().retirement_preservation_sha256,
        Sha256Digest::of_bytes(PRESERVATION)
    );
    assert_eq!(
        prepared.intent().preservation_sha256,
        Sha256Digest::of_bytes(FULL_PRESERVATION)
    );
    assert_ne!(
        prepared.intent().retirement_preservation_sha256,
        prepared.intent().preservation_sha256
    );
    assert_eq!(prepared.before(), BEFORE);
    assert_eq!(prepared.target(), f.target);
    assert_eq!(prepared.marker(), f.marker);
    assert_eq!(prepared.journal().stage, DurableStage::Prepared);
    assert_eq!(prepared.intent().schema, 1);
    assert!(prepared.endpoint_binding().is_none());
    let legacy_shape: serde_json::Value =
        serde_json::from_slice(&prepared.original.raw_intent).unwrap();
    for key in [
        "endpoint_binding_sha256",
        "endpoint_chain_sha256",
        "endpoint_key_sha256",
    ] {
        assert!(legacy_shape.get(key).is_none());
    }
    assert_eq!(
        serde_json::to_vec(prepared.intent()).unwrap(),
        prepared.original.raw_intent
    );
    assert_eq!(fs::read(f.path.join("state.json")).unwrap(), BEFORE);
    assert!(matches!(
        f.journal.prepare_cutover(&f.maintenance, inputs(&f)),
        Err(JournalError::Conflict)
    ));
    assert!(matches!(
        f.journal
            .append_cutover_phase(&f.maintenance, &prepared, DurableStage::Verified),
        Err(JournalError::Conflict)
    ));
    assert!(matches!(
        f.journal
            .append_cutover_phase(&f.maintenance, &prepared, DurableStage::Applied),
        Err(JournalError::Conflict)
    ));
    let original = f
        .journal
        .resync_original_cutover(&f.maintenance, &f.retired.transaction_id)
        .unwrap();
    assert_eq!(original.last_stage, DurableStage::Prepared);
    assert_eq!(original.phases.len(), 1);
    let observed = scan(&f);
    let inventory = scan_cutovers(&observed).unwrap();
    assert_eq!(inventory.records.len(), 1);
    assert_eq!(inventory.used.len(), 7);
    // Trusted test-only effect, separate from journal preparation: native marker
    // creation and canonical replacement do not occur inside prepare/append.
    write(&f.path.join(MARKER), &f.marker);
    fs::write(f.path.join("state.json"), &f.target).unwrap();
    fs::File::open(f.path.join("state.json"))
        .unwrap()
        .sync_all()
        .unwrap();
    fs::File::open(&f.path).unwrap().sync_all().unwrap();
    assert!(
        f.owner
            .with_state(|state| canonical_matches_retired_cutover_locked(
                &f.journal, state, &f.retired
            ))
            .unwrap()
    );
    let report = synthetic_validation(&f);
    assert!(matches!(
        f.journal
            .record_cutover_validation(&f.maintenance, &prepared, &report),
        Err(JournalError::Conflict)
    ));
    for stage in [
        DurableStage::Applied,
        DurableStage::Verified,
        DurableStage::Committed,
    ] {
        if stage == DurableStage::Verified {
            assert!(matches!(
                f.journal
                    .append_cutover_phase(&f.maintenance, &prepared, stage),
                Err(JournalError::Conflict)
            ));
            let mut bad: serde_json::Value = serde_json::from_slice(&report).unwrap();
            bad["probe_task_joined"] = false.into();
            assert!(matches!(
                f.journal.record_cutover_validation(
                    &f.maintenance,
                    &prepared,
                    &serde_json::to_vec(&bad).unwrap()
                ),
                Err(JournalError::Conflict)
            ));
            bad["probe_task_joined"] = true.into();
            bad["candidate_manifest_sha256"] =
                Sha256Digest::of_bytes(b"foreign candidate").to_hex().into();
            assert!(matches!(
                f.journal.record_cutover_validation(
                    &f.maintenance,
                    &prepared,
                    &serde_json::to_vec(&bad).unwrap()
                ),
                Err(JournalError::Conflict)
            ));
            let validation = f
                .journal
                .record_cutover_validation(&f.maintenance, &prepared, &report)
                .unwrap();
            assert_eq!(validation, Sha256Digest::of_bytes(&report));
            let original = f
                .journal
                .resync_original_cutover(&f.maintenance, &f.retired.transaction_id)
                .unwrap();
            assert_eq!(original.last_stage, DurableStage::Applied);
            assert_eq!(original.validation_report(), Some(report.as_slice()));
            assert_eq!(original.validation_sha256, Some(validation));
        }
        let receipt = f
            .journal
            .append_cutover_phase(&f.maintenance, &prepared, stage)
            .unwrap();
        assert_eq!(receipt.stage, stage);
        assert!(matches!(
            f.journal
                .append_cutover_phase(&f.maintenance, &prepared, stage),
            Err(JournalError::Conflict)
        ));
    }
    let original = f
        .journal
        .resync_original_cutover(&f.maintenance, &f.retired.transaction_id)
        .unwrap();
    assert_eq!(original.phases.len(), 4);
    assert_eq!(original.last_stage, DurableStage::Committed);
    assert_eq!(original.validation_report(), Some(report.as_slice()));
    assert!(matches!(
        f.journal
            .record_cutover_validation(&f.maintenance, &prepared, &report),
        Err(JournalError::Conflict)
    ));
    assert!(f.owner.ensure_admission().is_err()); // no final-proof/clear-fence port
    assert_eq!(f.journal.observe().unwrap().high_water, f.retired.sequence); // no new sequence
    assert!(
        f.owner
            .with_state(|s| f
                .journal
                .assert_complete_locked(s, &f.retired.transaction_id))
            .is_err()
    );
    // Copy exact original bytes into a DIFFERENT actual private kernel root.
    // A storage inspector must not turn this into a positive scoped summary.
    // All scope/retirement records here remain synthetic storage fixtures.
    let copied = parent.join(uuid::Uuid::new_v4().to_string());
    directory(&copied);
    for namespace in [NamespaceName::ManagementV1, NamespaceName::EnrollmentV1] {
        directory(&copied.join(namespace.as_str()));
    }
    let copy_scan = scan(&f);
    for file in &copy_scan.files {
        write(
            &copied
                .join(NamespaceName::ManagementV1.as_str())
                .join(&file.name),
            file.bytes(),
        );
    }
    for name in ["deployment.json", "state.json", MARKER] {
        let raw = fs::read(f.path.join(name)).unwrap();
        write(&copied.join(name), &raw);
    }
    for (name, raw) in [
        ("historical-baseline.intent", HISTORY),
        ("historical-baseline.committed", COMMITTED),
    ] {
        write(
            &copied.join(NamespaceName::EnrollmentV1.as_str()).join(name),
            raw,
        );
    }
    let copied_root = PrivateRoot::open(&copied).unwrap();
    assert_ne!(copied_root.identity(), f.owner.identity().unwrap());
    // A valid marker/state DTO pair alone is intentionally NOT an OS root proof.
    let copied_marker = decode_marker(&fs::read(copied.join(MARKER)).unwrap()).unwrap();
    decode_state(
        &fs::read(copied.join("state.json")).unwrap(),
        &copied_marker,
    )
    .unwrap();
    let copied_writer = copied_root.try_configuration_writer().unwrap();
    let copied_owner = OwnedConfigurationRoot::open_existing(copied_root, copied_writer).unwrap();
    assert!(copied_owner.ensure_admission().is_err());
    assert!(matches!(
        crate::store::legacy_handoff::inspect_pending_native_cutover(copied_owner.clone()),
        Err(JournalError::Conflict)
    ));
    assert!(copied_owner.ensure_admission().is_err());
    for file in &copy_scan.files {
        assert_eq!(
            fs::read(
                copied
                    .join(NamespaceName::ManagementV1.as_str())
                    .join(&file.name)
            )
            .unwrap(),
            file.bytes()
        );
    }
    assert_eq!(fs::read(copied.join("state.json")).unwrap(), f.target);
    assert_eq!(fs::read(copied.join(MARKER)).unwrap(), f.marker);
    drop(copied_owner);
    fs::remove_dir_all(copied).unwrap();

    // A genuinely missing report after Verified/Committed cannot be hidden by
    // a known stage receipt. Original history remains Unknown/fenced.
    fs::remove_file(
        f.path
            .join(NamespaceName::ManagementV1.as_str())
            .join(name(&f.retired.transaction_id, "validation")),
    )
    .unwrap();
    assert!(
        f.journal
            .resync_original_cutover(&f.maintenance, &f.retired.transaction_id)
            .is_err()
    );
    assert!(f.owner.ensure_usable().is_err());
    cleanup(f);

    // Reserve ALL future phase records before any cutover write, even though
    // preparation itself writes only seven. Original retirement remains intact.
    let mut bounded = fixture(
        &parent,
        JournalBudget {
            max_files: 9,
            ..JournalBudget::default()
        },
    );
    let before = scan(&bounded);
    assert!(matches!(
        bounded
            .journal
            .prepare_cutover(&bounded.maintenance, inputs(&bounded)),
        Err(JournalError::BudgetExceeded)
    ));
    assert_eq!(scan(&bounded).files.len(), before.files.len());
    assert!(scan_cutovers(&scan(&bounded)).unwrap().records.is_empty());
    cleanup(bounded);

    // A large target makes apply's temporary copy the dominant peak. First
    // measure a complete valid reservation using the same owned fixture, then
    // remove ONLY its known cutover files to reset this synthetic budget case.
    // This is test setup, not a product recovery or journal-deletion operation.
    let mut peak = fixture(&parent, JournalBudget::default());
    let marker = decode_marker(&peak.marker).unwrap();
    let mut target = decode_state(&peak.target, &marker).unwrap().state().clone();
    target.extensions.insert(
        "budget_padding".into(),
        serde_json::value::RawValue::from_string(
            serde_json::to_string(&"x".repeat(256 * 1024)).unwrap(),
        )
        .unwrap(),
    );
    peak.target = serde_json::to_vec(&target).unwrap();
    let untouched = scan(&peak);
    let prepared = peak
        .journal
        .prepare_cutover(&peak.maintenance, inputs(&peak))
        .unwrap();
    let prepared_scan = scan(&peak);
    let mut reserved = prepared.original.clone();
    reserved.validation_sha256 = Some(Sha256Digest::from_bytes([0; 32]));
    let mut future_entries: Vec<_> = prepared_scan
        .files
        .iter()
        .filter(|file| !untouched.files.iter().any(|old| old.name == file.name))
        .map(|file| (file.name.clone(), file.bytes().to_vec()))
        .collect();
    assert_eq!(future_entries.len(), 7);
    let mut previous = Some(prepared.journal().record_sha256);
    for stage in [
        DurableStage::Applied,
        DurableStage::Verified,
        DurableStage::Committed,
    ] {
        let raw = phase_bytes(&reserved, stage, previous).unwrap();
        previous = Some(receipt(&reserved.intent, stage, previous, &raw).record_sha256);
        future_entries.push((
            name(&reserved.intent.transaction_id, stage_name(stage).unwrap()),
            raw,
        ));
    }
    future_entries.push((
        name(&reserved.intent.transaction_id, "validation"),
        vec![0; MAX_VALIDATION],
    ));
    let complete_bytes = untouched.total_bytes
        + future_entries
            .iter()
            .map(|(_, raw)| raw.len())
            .sum::<usize>();
    let initial_bytes = prepared_scan.total_bytes;
    assert!(initial_bytes + peak.target.len() > complete_bytes);
    let namespace = peak.path.join(NamespaceName::ManagementV1.as_str());
    for (n, _) in future_entries.iter().take(7) {
        fs::remove_file(namespace.join(n)).unwrap();
    }
    fs::File::open(&namespace).unwrap().sync_all().unwrap();
    drop(prepared);
    peak.journal.budget.max_bytes = complete_bytes;
    peak.journal.budget.max_file_bytes = peak.target.len();
    assert!(peak.journal.budget.valid());
    // Prove the prior initial+all-future reservation alone fits exactly.
    let reset_scan = scan(&peak);
    peak.owner
        .with_state(|state| preflight(state, &reset_scan, &future_entries, peak.journal.budget))
        .unwrap();
    assert!(matches!(
        peak.journal
            .prepare_cutover(&peak.maintenance, inputs(&peak)),
        Err(JournalError::BudgetExceeded)
    ));
    let refused = scan(&peak);
    assert_eq!(refused.total_bytes, untouched.total_bytes);
    assert_eq!(refused.files.len(), untouched.files.len());
    for original in &untouched.files {
        let actual = refused
            .files
            .iter()
            .find(|file| file.name == original.name)
            .unwrap();
        assert_eq!(actual.bytes(), original.bytes());
    }
    assert!(scan_cutovers(&refused).unwrap().records.is_empty());
    assert!(
        !namespace
            .join(format!(
                "txn-{}.state-temporary",
                peak.retired.transaction_id.as_str()
            ))
            .exists()
    );
    cleanup(peak);

    // Existing intent/materials with a missing Prepared is retained observation,
    // never auto-completed by resync or by a second prepare attempt.
    let mut interrupted = fixture(&parent, JournalBudget::default());
    let p = interrupted
        .journal
        .prepare_cutover(&interrupted.maintenance, inputs(&interrupted))
        .unwrap();
    let namespace = interrupted.path.join(NamespaceName::ManagementV1.as_str());
    let prepared_path = namespace.join(name(&interrupted.retired.transaction_id, "prepared"));
    fs::remove_file(&prepared_path).unwrap();
    let original = interrupted
        .journal
        .resync_original_cutover(
            &interrupted.maintenance,
            &interrupted.retired.transaction_id,
        )
        .unwrap();
    assert_eq!(original.last_stage, DurableStage::Planned);
    assert!(original.phases.is_empty());
    assert!(!prepared_path.exists());
    assert!(matches!(
        interrupted
            .journal
            .prepare_cutover(&interrupted.maintenance, inputs(&interrupted)),
        Err(JournalError::Conflict)
    ));
    assert!(matches!(
        interrupted.journal.append_cutover_phase(
            &interrupted.maintenance,
            &p,
            DurableStage::Applied
        ),
        Err(JournalError::Conflict)
    ));
    // Actual retained missing attachment cannot be legitimized by merely having
    // an original intent. The owner's Unknown poison remains sticky.
    fs::remove_file(namespace.join(name(&interrupted.retired.transaction_id, "target"))).unwrap();
    assert!(
        interrupted
            .journal
            .resync_original_cutover(
                &interrupted.maintenance,
                &interrupted.retired.transaction_id
            )
            .is_err()
    );
    assert!(interrupted.owner.ensure_usable().is_err());
    cleanup(interrupted);
    // Complete endpoint attachments share the exact original namespace/owner.
    let mut endpoint = fixture(&parent, JournalBudget::default());
    let data = endpoint_inputs(&endpoint);
    let expected_binding = data.endpoint.as_ref().unwrap().binding.clone();
    let expected_chain = data.endpoint.as_ref().unwrap().chain.clone();
    let expected_key = data.endpoint.as_ref().unwrap().key.clone();
    let p = endpoint
        .journal
        .prepare_cutover(&endpoint.maintenance, data)
        .unwrap();
    assert_eq!(p.intent().schema, 2);
    assert_eq!(p.endpoint_binding(), Some(expected_binding.as_slice()));
    assert_eq!(p.endpoint_chain(), Some(expected_chain.as_slice()));
    assert!(p.endpoint_key() == Some(expected_key.as_slice()));
    assert_eq!(p.history_baseline_sha256(), Sha256Digest::of_bytes(HISTORY));
    assert_eq!(
        p.history_committed_sha256(),
        Sha256Digest::of_bytes(COMMITTED)
    );
    assert_eq!(scan_cutovers(&scan(&endpoint)).unwrap().used.len(), 10);
    assert!(matches!(
        endpoint
            .journal
            .append_cutover_phase(&endpoint.maintenance, &p, DurableStage::Verified),
        Err(JournalError::Conflict)
    ));
    let namespace = endpoint.path.join(NamespaceName::ManagementV1.as_str());
    fs::write(
        namespace.join(name(&endpoint.retired.transaction_id, "endpoint-chain")),
        b"changed chain",
    )
    .unwrap();
    assert!(
        endpoint
            .journal
            .resync_original_cutover(&endpoint.maintenance, &endpoint.retired.transaction_id)
            .is_err()
    );
    cleanup(endpoint);

    let mut missing = fixture(&parent, JournalBudget::default());
    let data = endpoint_inputs(&missing);
    missing
        .journal
        .prepare_cutover(&missing.maintenance, data)
        .unwrap();
    fs::remove_file(
        missing
            .path
            .join(NamespaceName::ManagementV1.as_str())
            .join(name(&missing.retired.transaction_id, "endpoint-key")),
    )
    .unwrap();
    assert!(
        missing
            .journal
            .resync_original_cutover(&missing.maintenance, &missing.retired.transaction_id)
            .is_err()
    );
    cleanup(missing);

    // Refusals are checked before the first immutable cutover write.
    for variant in 0..4 {
        let mut rejected = fixture(&parent, JournalBudget::default());
        let before = scan(&rejected);
        let mut data = endpoint_inputs(&rejected);
        match variant {
            0 => data.endpoint = None, // old intent cannot carry the new extension
            1 => data.endpoint.as_mut().unwrap().binding.push(b' '), // same JSON, wrong exact raw binding
            2 => data.endpoint.as_mut().unwrap().key.clear(),
            _ => {
                let endpoint = data.endpoint.as_mut().unwrap();
                let mut binding: NativeGatewayEndpointBinding =
                    serde_json::from_slice(&endpoint.binding).unwrap();
                binding.transaction_id = "foreign-endpoint-transaction".try_into().unwrap();
                endpoint.binding = serde_json::to_vec(&binding).unwrap();
                bind_endpoint_target(&mut data);
            }
        }
        assert!(
            rejected
                .journal
                .prepare_cutover(&rejected.maintenance, data)
                .is_err()
        );
        // Input rejection never publishes intent/material/Prepared, even if its
        // conservative error leaves this synthetic owner's admission poisoned.
        let root = PrivateRoot::open(&rejected.path).unwrap();
        for suffix in [
            "intent",
            "endpoint-binding",
            "endpoint-chain",
            "endpoint-key",
            "prepared",
        ] {
            root.ensure_absent(
                Path::new(NamespaceName::ManagementV1.as_str())
                    .join(name(&rejected.retired.transaction_id, suffix)),
            )
            .unwrap();
        }
        assert!(!before.files.iter().any(|f| f.name.contains(".cutover-")));
        cleanup(rejected);
    }
    // Original retired records + all schema1 future records fit16 files; the
    // schema2 endpoint bundle needs three MORE before any file is written.
    let mut endpoint_budget = fixture(
        &parent,
        JournalBudget {
            max_files: 16,
            ..JournalBudget::default()
        },
    );
    let data = endpoint_inputs(&endpoint_budget);
    assert!(matches!(
        endpoint_budget
            .journal
            .prepare_cutover(&endpoint_budget.maintenance, data),
        Err(JournalError::BudgetExceeded)
    ));
    let root = PrivateRoot::open(&endpoint_budget.path).unwrap();
    root.ensure_absent(
        Path::new(NamespaceName::ManagementV1.as_str())
            .join(name(&endpoint_budget.retired.transaction_id, "intent")),
    )
    .unwrap();
    cleanup(endpoint_budget);
}
