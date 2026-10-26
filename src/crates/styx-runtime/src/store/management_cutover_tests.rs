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
// Synthetic report bytes test storage validation, never physical execution.
fn synthetic_paired(p: &PreparedCutover) -> Vec<u8> {
    let endpoint: serde_json::Value =
        serde_json::from_slice(p.endpoint_binding().unwrap()).unwrap();
    serde_json::to_vec(&serde_json::json!({
        "schema":1, "transaction_id":p.intent().transaction_id,
        "candidate_manifest_sha256":p.intent().candidate_manifest_sha256,
        "target_sha256":p.intent().target_state_sha256,"endpoint":endpoint,
        "exit_code":0,"drained":true,"connections_joined":true,
        "blocking_jobs_joined":true,"mcp_lifecycle_jobs_joined":true,
        "mcp_session_transports_joined":true,"unconfirmed_owner_cleanups":0,
        "sdk_service_joined":true,"sdk_detached_tasks_joined":null,
        "host_protocol_joined":true,"host_link_io_joined":true,
        "executor_exited":true,"processes_exited":true,"reader_task_reaped":true,
        "stderr_task_reaped":true,"supervised_jobs_joined":true,
        "validation_task_joined":true,"migration_committed":false,
        "ordinary_admission_open":false
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
    let original_phase = fs::read(
        f.path
            .join(NamespaceName::ManagementV1.as_str())
            .join(name(&f.retired.transaction_id, "prepared")),
    )
    .unwrap();
    let old_phase: serde_json::Value = serde_json::from_slice(&original_phase).unwrap();
    assert_eq!(old_phase["schema"], 1);
    assert!(old_phase.get("paired_validation_sha256").is_none());
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
    let pair = synthetic_paired(&p);
    // Neither a Prepared record nor missing local evidence permits pair storage.
    assert!(matches!(
        endpoint
            .journal
            .record_cutover_paired_validation(&endpoint.maintenance, &p, &pair),
        Err(JournalError::Conflict)
    ));
    write(&endpoint.path.join(MARKER), &endpoint.marker);
    fs::write(endpoint.path.join("state.json"), p.target()).unwrap();
    endpoint
        .journal
        .append_cutover_phase(&endpoint.maintenance, &p, DurableStage::Applied)
        .unwrap();
    assert!(matches!(
        endpoint
            .journal
            .record_cutover_paired_validation(&endpoint.maintenance, &p, &pair),
        Err(JournalError::Conflict)
    ));
    let local = synthetic_validation(&endpoint);
    endpoint
        .journal
        .record_cutover_validation(&endpoint.maintenance, &p, &local)
        .unwrap();
    assert!(matches!(
        endpoint
            .journal
            .append_cutover_phase(&endpoint.maintenance, &p, DurableStage::Verified),
        Err(JournalError::Conflict)
    ));
    for field in [
        "validation_task_joined",
        "connections_joined",
        "executor_exited",
    ] {
        let mut bad: serde_json::Value = serde_json::from_slice(&pair).unwrap();
        bad[field] = false.into();
        assert!(matches!(
            endpoint.journal.record_cutover_paired_validation(
                &endpoint.maintenance,
                &p,
                &serde_json::to_vec(&bad).unwrap()
            ),
            Err(JournalError::Conflict)
        ));
    }
    for field in ["target_sha256", "candidate_manifest_sha256"] {
        let mut bad: serde_json::Value = serde_json::from_slice(&pair).unwrap();
        bad[field] = Sha256Digest::of_bytes(b"foreign binding").to_hex().into();
        assert!(matches!(
            endpoint.journal.record_cutover_paired_validation(
                &endpoint.maintenance,
                &p,
                &serde_json::to_vec(&bad).unwrap()
            ),
            Err(JournalError::Conflict)
        ));
    }
    let mut bad: serde_json::Value = serde_json::from_slice(&pair).unwrap();
    bad["endpoint"]["root_identity"]["inode"] = 1.into();
    assert!(matches!(
        endpoint.journal.record_cutover_paired_validation(
            &endpoint.maintenance,
            &p,
            &serde_json::to_vec(&bad).unwrap()
        ),
        Err(JournalError::Conflict)
    ));
    assert!(matches!(
        endpoint.journal.record_cutover_paired_validation(
            &endpoint.maintenance,
            &p,
            &vec![b' '; MAX_VALIDATION + 1]
        ),
        Err(JournalError::BudgetExceeded)
    ));
    let digest = endpoint
        .journal
        .record_cutover_paired_validation(&endpoint.maintenance, &p, &pair)
        .unwrap();
    assert_eq!(digest, Sha256Digest::of_bytes(&pair));
    let mut previous = scan_cutovers(&scan(&endpoint)).unwrap().records[0]
        .phases
        .last()
        .unwrap()
        .record_sha256;
    for stage in [DurableStage::Verified, DurableStage::Committed] {
        let receipt = endpoint
            .journal
            .append_cutover_phase(&endpoint.maintenance, &p, stage)
            .unwrap();
        assert_eq!(receipt.previous, Some(previous));
        previous = receipt.record_sha256;
        let raw = fs::read(
            endpoint
                .path
                .join(NamespaceName::ManagementV1.as_str())
                .join(name(
                    &endpoint.retired.transaction_id,
                    stage_name(stage).unwrap(),
                )),
        )
        .unwrap();
        let phase: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(phase["schema"], 2);
        assert_eq!(phase["paired_validation_sha256"], digest.to_hex());
    }
    let observed = endpoint
        .journal
        .resync_original_cutover(&endpoint.maintenance, &endpoint.retired.transaction_id)
        .unwrap();
    assert_eq!(observed.paired_validation_report(), Some(pair.as_slice()));
    assert_eq!(observed.last_stage, DurableStage::Committed);
    // Reopened original journal custody must bind the complete recorded prefix
    // and exact historical reports too. Use this fixture's real committed bytes;
    // the private test construction does not attest native OS settlement.
    let mut reopened = PreparedCutover {
        owner: endpoint.owner.clone(),
        namespace: p.namespace,
        original: observed.clone(),
        candidate: None,
    };
    let committed = observed.phases.last().unwrap();
    let verify = |prepared: &PreparedCutover| {
        endpoint
            .owner
            .with_maintenance(&endpoint.maintenance, |state| {
                endpoint
                    .journal
                    .validate_committed_cutover_locked(state, prepared, committed)
            })
    };
    assert!(verify(&reopened).is_ok());
    reopened.original.validation.as_mut().unwrap().push(b' ');
    assert!(matches!(verify(&reopened), Err(JournalError::Conflict)));
    reopened.original = observed.clone();
    reopened
        .original
        .paired_validation
        .as_mut()
        .unwrap()
        .push(b' ');
    assert!(matches!(verify(&reopened), Err(JournalError::Conflict)));
    reopened.original = observed.clone();
    reopened.original.phases[0].record_sha256 =
        Sha256Digest::of_bytes(b"foreign historical prefix");
    assert!(matches!(verify(&reopened), Err(JournalError::Conflict)));
    let pairpath = endpoint
        .path
        .join(NamespaceName::ManagementV1.as_str())
        .join(name(&endpoint.retired.transaction_id, "paired-validation"));
    // Missing final-phase dependency and same-file tamper both fail the pure scan,
    // without manufacturing a new phase or invoking recovery.
    fs::remove_file(&pairpath).unwrap();
    assert!(scan_cutovers(&scan(&endpoint)).is_err());
    write(&pairpath, b"truncated");
    assert!(scan_cutovers(&scan(&endpoint)).is_err());
    fs::remove_file(&pairpath).unwrap();
    write(&pairpath, &pair);
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

// These versioned reader fixtures are synthetic data, not a native stopped-owner,
// token-retirement, TLS, writer-handoff or activation attestation. Only the legacy
// fixture's isolated scratch writer is exercised; no v3 writer is introduced.
fn with_reader_seed(test: impl FnOnce(&mut Fixture, &PreparedCutover)) {
    struct RemoveScratch(PathBuf);
    impl Drop for RemoveScratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let parent = std::env::temp_dir().join(format!("styx-cutover-reader-{}", uuid::Uuid::new_v4()));
    directory(&parent);
    let _cleanup = RemoveScratch(parent.clone());
    let mut f = fixture(&parent, JournalBudget::default());
    let p = f
        .journal
        .prepare_cutover(&f.maintenance, endpoint_inputs(&f))
        .unwrap();
    test(&mut f, &p);
}
fn fixture_raw(v: &serde_json::Value) -> Vec<u8> {
    // Original whitespace is deliberately hash-significant. The reader must
    // retain these bytes, not hash a freshly normalized serialization.
    format!(" {}\n", serde_json::to_string(v).unwrap()).into_bytes()
}
fn reader_chain(
    f: &Fixture,
    p: &PreparedCutover,
    version: u16,
    platform: &str,
) -> JournalObservation {
    use crate::store::secure_journal::ObservedJournalFile;
    use serde_json::json;
    let native = version == 3;
    let mut retirement = serde_json::to_value(&f.retired).unwrap();
    if native {
        retirement["schema"] = 3.into();
        for (field, id) in [("config_root", 10), ("host_root", 11)] {
            retirement[field] = match platform {
                "windows" => {
                    json!({"platform":"windows","volume_serial":7,"file_id":id,"owner_sid":"S-1-5-21-123"})
                }
                "linux" | "macos" => json!({"platform":platform,"device":7,"inode":id,"uid":501}),
                _ => panic!("fixed fixture platform"),
            };
        }
        let stamp = &f.retired.original_token;
        retirement["original_token"] = if platform == "windows" {
            json!({"platform":"windows","volume_serial":7,"file_id":12,"owner_sid":"S-1-5-21-123",
                "nlink":1,"byte_len":stamp.byte_len,"modified_seconds":100,"modified_nanoseconds":100,
                "changed_seconds":100,"changed_nanoseconds":200,"sha256":stamp.sha256})
        } else {
            let mut stamp = serde_json::to_value(stamp).unwrap();
            stamp["device"] = 7.into();
            stamp["inode"] = 12.into();
            stamp["uid"] = 501.into();
            json!({"platform":platform,"stamp":stamp})
        };
    }
    let id = f.retired.transaction_id.clone();
    let mut members = BTreeMap::<String, Vec<u8>>::new();
    let retirement_raw = fixture_raw(&retirement);
    let prepared = fixture_raw(
        &json!({"schema":retirement["schema"],"kind":"legacy_credential_retirement",
        "transaction_id":id,"sequence":f.retired.sequence,"raw_intent_sha256":Sha256Digest::of_bytes(&retirement_raw),
        "stage":"prepared","previous":null,"post_stamp":null}),
    );
    let retired = fixture_raw(
        &json!({"schema":retirement["schema"],"kind":"legacy_credential_retirement",
        "transaction_id":id,"sequence":f.retired.sequence,"raw_intent_sha256":Sha256Digest::of_bytes(&retirement_raw),
        "stage":"retired","previous":Sha256Digest::of_bytes(&prepared),"post_stamp":retirement["original_token"]}),
    );
    let retired_hash = Sha256Digest::of_bytes(&retired);
    for (name, bytes) in ["intent", "prepared", "retired"]
        .map(|phase| format!("txn-{}.handoff-{phase}", id.as_str()))
        .into_iter()
        .zip([retirement_raw, prepared, retired])
    {
        members.insert(name, bytes);
    }
    let mut intent = serde_json::to_value(p.intent()).unwrap();
    intent["schema"] = version.into();
    intent["retired_record_sha256"] = json!(retired_hash);
    intent["config_root"] = retirement["config_root"].clone();
    intent["host_root"] = retirement["host_root"].clone();
    let mut marker: serde_json::Value = serde_json::from_slice(p.marker()).unwrap();
    if native {
        marker["root_identity"] = retirement["config_root"].clone();
    }
    let marker_raw = fixture_raw(&marker);
    intent["marker_sha256"] = json!(Sha256Digest::of_bytes(&marker_raw));
    let mut target: NativeState = decode_state(p.target(), &decode_marker(p.marker()).unwrap())
        .unwrap()
        .state()
        .clone();
    target.migration.as_mut().unwrap().retired_receipt_sha256 = retired_hash;
    let mut endpoint: serde_json::Value =
        serde_json::from_slice(p.endpoint_binding().unwrap()).unwrap();
    endpoint["root_identity"] = marker["root_identity"].clone();
    if version == 1 {
        target.extensions.remove("gateway_endpoint_v1");
        for field in [
            "endpoint_binding_sha256",
            "endpoint_chain_sha256",
            "endpoint_key_sha256",
        ] {
            intent.as_object_mut().unwrap().remove(field);
        }
    } else {
        let binding = serde_json::to_vec(&endpoint).unwrap();
        target.extensions.insert(
            "gateway_endpoint_v1".into(),
            serde_json::value::RawValue::from_string(String::from_utf8(binding.clone()).unwrap())
                .unwrap(),
        );
        intent["endpoint_binding_sha256"] = json!(Sha256Digest::of_bytes(&binding));
        members.insert(name(&id, "endpoint-binding"), binding);
        members.insert(
            name(&id, "endpoint-chain"),
            p.endpoint_chain().unwrap().to_vec(),
        );
        members.insert(
            name(&id, "endpoint-key"),
            p.endpoint_key().unwrap().to_vec(),
        );
    }
    let target_raw = serde_json::to_vec(&target).unwrap();
    intent["target_state_sha256"] = json!(Sha256Digest::of_bytes(&target_raw));
    let raw_intent = fixture_raw(&intent);
    for (suffix, bytes) in [
        ("preservation", p.original.preservation.clone()),
        ("scopes", p.original.scope_bindings.clone()),
        ("marker", marker_raw),
        ("before", p.before().to_vec()),
        ("target", target_raw),
        ("intent", raw_intent.clone()),
    ] {
        members.insert(name(&id, suffix), bytes);
    }
    let validation = synthetic_validation(f);
    let mut paired: serde_json::Value = serde_json::from_slice(&synthetic_paired(p)).unwrap();
    paired["target_sha256"] = intent["target_state_sha256"].clone();
    paired["endpoint"] = endpoint;
    let paired_raw = fixture_raw(&paired);
    members.insert(name(&id, "validation"), validation.clone());
    if version != 1 {
        members.insert(name(&id, "paired-validation"), paired_raw.clone());
    }
    let mut previous = serde_json::Value::Null;
    for stage in ["prepared", "applied", "verified", "committed"] {
        let final_stage = matches!(stage, "verified" | "committed");
        let mut phase = json!({"schema":if native {3} else if version == 2 && final_stage {2} else {1},
            "intent":intent,"raw_intent_sha256":Sha256Digest::of_bytes(&raw_intent),"stage":stage,"previous":previous,
            "canonical_raw_sha256":intent[if stage == "prepared" {"before_state_sha256"} else {"target_state_sha256"}],
            "validation_sha256":if final_stage {json!(Sha256Digest::of_bytes(&validation))} else {serde_json::Value::Null}});
        if version != 1 && final_stage {
            phase["paired_validation_sha256"] = json!(Sha256Digest::of_bytes(&paired_raw));
        }
        let raw = fixture_raw(&phase);
        previous = json!(Sha256Digest::of_bytes(&raw));
        members.insert(name(&id, stage), raw);
    }
    JournalObservation {
        total_bytes: members.values().map(Vec::len).sum(),
        files: members
            .into_iter()
            .map(|(name, bytes)| ObservedJournalFile { name, bytes })
            .collect(),
    }
}
fn rewrite_fixture(
    scan: &mut JournalObservation,
    suffix: &str,
    change: impl FnOnce(&mut serde_json::Value),
) {
    let f = scan
        .files
        .iter_mut()
        .find(|f| f.name.ends_with(suffix))
        .unwrap();
    let mut value = serde_json::from_slice(f.bytes()).unwrap();
    change(&mut value);
    f.bytes = fixture_raw(&value);
    scan.total_bytes = scan.files.iter().map(|f| f.bytes().len()).sum();
}
fn raw_members(scan: &JournalObservation) -> BTreeMap<String, Vec<u8>> {
    scan.files
        .iter()
        .map(|f| (f.name.clone(), f.bytes().to_vec()))
        .collect()
}
#[test]
fn versioned_cutover_reader_preserves_original_bytes_and_requires_paired_completion() {
    with_reader_seed(|f, p| {
        for (version, platform) in [
            (1, "linux"),
            (2, "linux"),
            (3, "linux"),
            (3, "macos"),
            (3, "windows"),
        ] {
            let scan = reader_chain(f, p, version, platform);
            let parsed = scan_cutovers(&scan).unwrap();
            let (raw, phases, last) = if version == 3 {
                assert!(parsed.records.is_empty());
                let record = &parsed.native_records[0];
                (&record.raw_intent, &record.phases, record.last_stage)
            } else {
                assert!(parsed.native_records.is_empty());
                let record = &parsed.records[0];
                // The legacy writer's serializer is deliberately unchanged.
                assert_ne!(
                    serde_json::to_vec(&record.intent).unwrap(),
                    record.raw_intent
                );
                (&record.raw_intent, &record.phases, record.last_stage)
            };
            assert_eq!(last, DurableStage::Committed);
            let members = raw_members(&scan);
            assert_eq!(raw, &members[&name(&f.retired.transaction_id, "intent")]);
            for phase in phases {
                assert_eq!(
                    phase.record_sha256,
                    Sha256Digest::of_bytes(
                        &members
                            [&name(&f.retired.transaction_id, stage_name(phase.stage).unwrap())]
                    )
                );
            }
            assert!(
                super::super::readonly_inventory(&scan)
                    .unwrap()
                    .orphans
                    .is_empty()
            );
        }
        let original_scan = scan(f);
        let original = scan_cutovers(&original_scan).unwrap().records.remove(0);
        let original_bytes = raw_members(&original_scan);
        assert_eq!(
            phase_bytes(&original, DurableStage::Prepared, None).unwrap(),
            original_bytes[&name(&f.retired.transaction_id, "prepared")]
        );
        let mut partial = reader_chain(f, p, 3, "windows");
        partial
            .files
            .retain(|f| !f.name.ends_with(".cutover-committed"));
        assert_eq!(
            scan_cutovers(&partial).unwrap().native_records[0].last_stage,
            DurableStage::Verified
        );
        let mut no_paired = reader_chain(f, p, 3, "windows");
        no_paired
            .files
            .retain(|f| !f.name.ends_with(".cutover-paired-validation"));
        assert!(scan_cutovers(&no_paired).is_err());
    });
}
#[test]
fn versioned_cutover_reader_rejects_foreign_roots_versions_and_broken_original_chains() {
    with_reader_seed(|f, p| {
        for root in [
            serde_json::json!({"platform":"macos","device":7,"inode":10,"uid":501}),
            serde_json::json!({"platform":"windows","volume_serial":7,"file_id":10,"owner_sid":"S-1-5-21-999"}),
            serde_json::json!({"platform":"windows","volume_serial":7,"file_id":99,"owner_sid":"S-1-5-21-123"}),
        ] {
            let mut bad = reader_chain(f, p, 3, "windows");
            rewrite_fixture(&mut bad, ".cutover-intent", |v| v["config_root"] = root);
            assert!(scan_cutovers(&bad).is_err());
        }
        // Rehash a foreign marker so this tests root binding, not merely a
        // stale attachment digest. The decoded original native record is not
        // a writer capability, even with complete synthetic phase evidence.
        let scan = reader_chain(f, p, 3, "windows");
        let mut foreign = scan_cutovers(&scan).unwrap().native_records.remove(0);
        let mut marker: serde_json::Value = serde_json::from_slice(&foreign.marker).unwrap();
        marker["root_identity"]["file_id"] = 99.into();
        foreign.marker = fixture_raw(&marker);
        foreign.intent.marker_sha256 = Sha256Digest::of_bytes(&foreign.marker);
        foreign.raw_intent = serde_json::to_vec(&foreign.intent).unwrap();
        assert!(validate_materials(&foreign).is_err());
        // Both directions select the wrong retirement version before any
        // legacy projection or phase decoding; no fallback is permitted.
        for (version, replacement) in [(3, 2), (2, 3)] {
            let mut bad = reader_chain(f, p, version, "windows");
            rewrite_fixture(&mut bad, ".cutover-intent", |v| {
                v["schema"] = replacement.into()
            });
            assert!(scan_cutovers(&bad).is_err());
        }
        for suffix in [
            ".cutover-prepared",
            ".cutover-applied",
            ".cutover-verified",
            ".cutover-committed",
        ] {
            let mut bad = reader_chain(f, p, 3, "windows");
            rewrite_fixture(&mut bad, suffix, |v| v["schema"] = 1.into());
            assert!(scan_cutovers(&bad).is_err());
        }
        let mut changed = reader_chain(f, p, 3, "windows");
        rewrite_fixture(&mut changed, ".cutover-applied", |v| {
            v["previous"] = serde_json::json!(Sha256Digest::of_bytes(b"foreign predecessor"))
        });
        assert!(scan_cutovers(&changed).is_err());
        let mut missing = reader_chain(f, p, 3, "windows");
        missing
            .files
            .retain(|f| !f.name.ends_with(".cutover-applied"));
        assert!(scan_cutovers(&missing).is_err());
        let mut missing_field = reader_chain(f, p, 3, "windows");
        rewrite_fixture(&mut missing_field, ".cutover-prepared", |v| {
            v.as_object_mut().unwrap().remove("previous");
        });
        assert!(scan_cutovers(&missing_field).is_err());
    });
}
#[test]
fn old_cutover_mutations_reject_native_chain_before_writing_scratch_members() {
    with_reader_seed(|f, p| {
        let native = reader_chain(f, p, 3, "windows");
        // Install only synthetic test journal bytes into this test's freshly
        // owned root. This is never a production migration or native receipt.
        let dir = f.path.join(NamespaceName::ManagementV1.as_str());
        for old in scan(f).files {
            fs::remove_file(dir.join(old.name)).unwrap();
        }
        for entry in &native.files {
            write(&dir.join(&entry.name), entry.bytes());
        }
        assert!(scan_cutovers(&scan(f)).unwrap().records.is_empty());
        let before = raw_members(&scan(f));
        let canonical_before = fs::read(f.path.join("state.json")).unwrap();
        assert!(original(&scan(f), &f.retired.transaction_id).is_err());
        let input = endpoint_inputs(f);
        assert!(f.journal.prepare_cutover(&f.maintenance, input).is_err());
        let report = synthetic_validation(f);
        assert!(
            f.journal
                .record_cutover_validation(&f.maintenance, p, &report)
                .is_err()
        );
        assert!(
            f.journal
                .record_cutover_paired_validation(&f.maintenance, p, &synthetic_paired(p))
                .is_err()
        );
        assert!(
            f.journal
                .append_cutover_phase(&f.maintenance, p, DurableStage::Applied)
                .is_err()
        );
        assert!(
            f.journal
                .resync_original_cutover(&f.maintenance, &f.retired.transaction_id)
                .is_err()
        );
        assert_eq!(raw_members(&scan(f)), before);
        assert_eq!(
            fs::read(f.path.join("state.json")).unwrap(),
            canonical_before
        );
        assert!(!f.path.join(MARKER).exists());
        // The earlier partial boundary is equally closed: native retirement
        // alone must not start a fresh legacy cutover or add any attachments.
        for entry in native.files.iter().filter(|f| f.name.contains(".cutover-")) {
            fs::remove_file(dir.join(&entry.name)).unwrap();
        }
        let before_partial = raw_members(&scan(f));
        let input = endpoint_inputs(f);
        assert!(f.journal.prepare_cutover(&f.maintenance, input).is_err());
        assert_eq!(raw_members(&scan(f)), before_partial);
    });
}

// Report codec/data-link evidence only: original files use the existing journal
// fixture; the derived remote observation is synthetic and never activated.
#[test]
#[ignore = "STYX_TEST_MANAGEMENT_CUTOVER_ROOT; report versions/data links with existing owned journal fixture, not network/native migration acceptance"]
fn preserved_remote_report_versions_keep_exact_bytes_and_refuse_mixed_evidence() {
    let parent = PathBuf::from(
        std::env::var_os("STYX_TEST_MANAGEMENT_CUTOVER_ROOT").expect("explicit fresh owned parent"),
    );
    let mut f = fixture(&parent, JournalBudget::default());
    let data = inputs(&f);
    let p = f.journal.prepare_cutover(&f.maintenance, data).unwrap();
    let before_scan = scan(&f);
    let mut remote = original(&before_scan, &f.retired.transaction_id).unwrap();
    let root = NativeRootIdentity::Linux {
        device: 1,
        inode: 2,
        uid: 1000,
    };
    let hash = Sha256Digest::of_bytes(b"synthetic original remote pairing");
    let pair = NativePreservedHostPair {
        schema: 1,
        transaction_id: remote.intent.transaction_id.clone(),
        config_root: root.clone(),
        host_root: root,
        deployment_raw_sha256: remote.intent.deployment_raw_sha256,
        device_id: "styx-0123456789abcdef01234567".try_into().unwrap(),
        fingerprint: hash,
        gateway_origin: "https://original-gateway.invalid:22022".into(),
        gateway_ca_pem_sha256: hash,
        identity_json_sha256: hash,
        identity_private_pem_sha256: hash,
        host_profile_sha256: hash,
        credential_sha256: hash,
        preservation_sha256: hash,
    };
    let pair_bytes = serde_json::to_vec(&pair).unwrap();
    let source_hash = Sha256Digest::of_bytes(&pair_bytes);
    remote.intent.schema = 4;
    remote.intent.endpoint_mode = Some(NativeMigrationEndpointMode::PreservedRemote);
    remote.intent.history = Some(NativeMigrationHistory::PreservedHostPair {
        source_bindings_sha256: source_hash,
    });
    remote.host_pair = Some(pair_bytes);
    let v2 = serde_json::json!({
        "schema":2, "kind":"preserved_remote_host_admission",
        "transaction_id": remote.intent.transaction_id,
        "candidate_manifest_sha256":remote.intent.candidate_manifest_sha256,
        "target_sha256":remote.intent.target_state_sha256,
        "source_bindings_sha256":source_hash,
        "origin":pair.gateway_origin, "device_id":pair.device_id,
        "fingerprint":pair.fingerprint, "gateway_ca_pem_sha256":pair.gateway_ca_pem_sha256,
        "host_authenticated":true, "protocol_ready":true,
        "host_protocol_joined":true, "host_link_io_joined":true,
        "validation_task_joined":true,
        "migration_committed":false, "ordinary_admission_open":false
    });
    let check = |value: &serde_json::Value| {
        validate_paired_report(&serde_json::to_vec(value).unwrap(), &remote)
    };
    assert!(check(&v2).is_ok());
    // Reopening must respect the SIGNED reader feature declaration too, not
    // merely the broad StateV2 reader floor. These are full codec fixtures;
    // no actual candidate signature or native reopening is claimed here.
    use crate::store::committed_runtime_native::validate_selected_reader_features;
    use styx_contracts::native_release::NativeReleaseReader;
    let v2_raw = serde_json::to_vec(&v2).unwrap();
    assert!(
        validate_selected_reader_features(
            NativeReleaseReader::NativeRuntimeMigratedV2,
            false,
            &v2_raw
        )
        .is_err()
    );
    assert!(
        validate_selected_reader_features(
            NativeReleaseReader::NativeRuntimeMigratedV3,
            false,
            &v2_raw
        )
        .is_ok()
    );

    // Required observations cannot be omitted or replaced with Unknown/false.
    for field in [
        "host_authenticated",
        "protocol_ready",
        "host_protocol_joined",
        "host_link_io_joined",
        "validation_task_joined",
    ] {
        for replacement in [
            None,
            Some(serde_json::json!(false)),
            Some(serde_json::json!("unknown")),
        ] {
            let mut bad = v2.clone();
            match replacement {
                Some(value) => {
                    bad[field] = value;
                }
                None => {
                    bad.as_object_mut().unwrap().remove(field);
                }
            }
            assert!(check(&bad).is_err(), "{field}");
        }
    }
    for field in [
        "transaction_id",
        "candidate_manifest_sha256",
        "target_sha256",
        "source_bindings_sha256",
        "origin",
        "device_id",
        "fingerprint",
        "gateway_ca_pem_sha256",
    ] {
        let mut bad = v2.clone();
        bad[field] = match field {
            "transaction_id" => serde_json::json!("foreign-transaction"),
            "origin" => serde_json::json!("https://other-gateway.invalid:22022"),
            "device_id" => serde_json::json!("styx-ffffffffffffffffffffffff"),
            _ => serde_json::json!(Sha256Digest::of_bytes(b"foreign binding")),
        };
        assert!(check(&bad).is_err(), "{field}");
    }
    for field in ["migration_committed", "ordinary_admission_open"] {
        let mut bad = v2.clone();
        bad[field] = serde_json::json!(true);
        assert!(check(&bad).is_err());
    }
    for field in [
        "sdk_service_joined",
        "sdk_detached_tasks_joined",
        "mcp_session_closed",
        "foreign_owner_refused",
        "mcp_effect_verified",
        "executor_exited",
        "unknown_field",
    ] {
        let mut bad = v2.clone();
        bad[field] = serde_json::json!(true);
        assert!(check(&bad).is_err(), "{field}");
    }
    for version in [0, 1, 3] {
        let mut bad = v2.clone();
        bad["schema"] = serde_json::json!(version);
        assert!(check(&bad).is_err());
    }
    let mut bad = v2.clone();
    bad["kind"] = serde_json::json!("preserved_remote_host");
    assert!(check(&bad).is_err());
    let mut v1 = v2.clone();
    v1["schema"] = serde_json::json!(1);
    v1["kind"] = serde_json::json!("preserved_remote_host");
    v1.as_object_mut().unwrap().remove("protocol_ready");
    v1["exit_code"] = serde_json::json!(0);
    for field in [
        "mcp_effect_verified",
        "foreign_owner_refused",
        "sdk_service_joined",
        "sdk_detached_tasks_joined",
        "mcp_session_closed",
        "executor_exited",
        "processes_exited",
        "reader_task_reaped",
        "stderr_task_reaped",
        "supervised_jobs_joined",
    ] {
        v1[field] = serde_json::json!(true);
    }
    let raw = format!(" \n{}\n ", serde_json::to_string_pretty(&v1).unwrap()).into_bytes();
    let saved = raw.clone();
    assert!(validate_paired_report(&raw, &remote).is_ok());
    assert_eq!(raw, saved); // Original bytes, never normalized into a new hash chain.
    assert!(
        validate_selected_reader_features(
            NativeReleaseReader::NativeRuntimeMigratedV2,
            false,
            &raw
        )
        .is_ok()
    );
    assert!(
        validate_selected_reader_features(NativeReleaseReader::NativeRuntimeMigratedV2, true, &raw)
            .is_err()
    );
    assert!(
        validate_selected_reader_features(NativeReleaseReader::NativeRuntimeMigratedV3, true, &raw)
            .is_ok()
    );

    for field in [
        "mcp_effect_verified",
        "foreign_owner_refused",
        "sdk_service_joined",
        "sdk_detached_tasks_joined",
        "mcp_session_closed",
    ] {
        let mut bad = v1.clone();
        bad[field] = serde_json::json!(false);
        assert!(check(&bad).is_err());
    }
    let mut mixed = v1.clone();
    mixed["schema"] = serde_json::json!(2);
    mixed["kind"] = serde_json::json!("preserved_remote_host_admission");
    mixed["protocol_ready"] = serde_json::json!(true);
    assert!(check(&mixed).is_err());
    let duplicate = serde_json::to_string(&v2)
        .unwrap()
        .replacen('{', "{\"schema\":2,", 1);
    assert!(validate_paired_report(duplicate.as_bytes(), &remote).is_err());
    // The real original fixture has no local Exec report: the shared writer must
    // still refuse a pair report before local validation, irrespective of parser.
    assert!(
        f.journal
            .record_cutover_paired_validation(&f.maintenance, &p, &serde_json::to_vec(&v2).unwrap())
            .is_err()
    );
    assert!(
        original(&scan(&f), &f.retired.transaction_id)
            .unwrap()
            .paired_validation_report()
            .is_none()
    );
    drop(p);
    cleanup(f);
}
