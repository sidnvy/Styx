//! One actual original signed Host+Gateway to fenced native cutover scene.
//! The external controller owns original Core preparation/pairing/doctor, unit
//! registration and all final cleanup. This test neither installs a service nor
//! proves final C07 commit, ordinary native activation, or account acceptance.
use super::*;
use crate::{
    crypto::PublisherFingerprint,
    store::{PreservationInput, PreservationRole, PrivateRoot, legacy_handoff::LegacyMaterialRoot},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{fs, io::Write, os::unix::fs::OpenOptionsExt, path::PathBuf};
use tokio::time::{Instant, sleep, timeout};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    schema: u32,
    status: String,
    state_dir: PathBuf,
    host_base: PathBuf,
    publisher_pin: String,
    source_scope_notes: String,
}
fn materials() -> Vec<LegacyMaterialInput> {
    use LegacyMaterialRoot::{Configuration, Host};
    use PreservationRole::{
        DeploymentConfiguration, DeviceIdentity, DevicePrivateKey, PairingCredential,
        PublisherTrust,
    };
    [
        (Configuration, "state.json", DeploymentConfiguration),
        (Configuration, "deployment.json", DeploymentConfiguration),
        (Host, "device/identity.json", DeviceIdentity),
        (Host, "device/identity.pem", DevicePrivateKey),
        (Host, "device/host.json", PairingCredential),
        (Host, "device/host.token", PairingCredential),
        (Host, "publisher.pem", PublisherTrust),
        (Host, "install/active.json", PublisherTrust),
    ]
    .into_iter()
    .map(|(root, path, role)| LegacyMaterialInput {
        root,
        input: PreservationInput {
            relative_path: path.into(),
            role,
            json_version: None,
        },
        max_bytes: 128 * 1024,
    })
    .collect()
}
fn save(root: &Path, name: &str, value: &Value) {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join(name))
        .unwrap();
    file.write_all(&serde_json::to_vec_pretty(value).unwrap())
        .unwrap();
    file.sync_all().unwrap();
    fs::File::open(root).unwrap().sync_all().unwrap();
}
fn observation(fact: SettlementObservation) -> Value {
    json!({
        "status":match fact.status {
            SettlementStatus::Registered=>"registered",SettlementStatus::Stopping=>"stopping",
            SettlementStatus::Unknown=>"unknown",SettlementStatus::Confirmed=>"confirmed",SettlementStatus::Consumed=>"consumed",
        },
        "term_attempted":fact.term_attempted,"signal_accepted":fact.signal_accepted,
        "original_main_exited":fact.original_main_exited,"original_cgroup_empty":fact.original_cgroup_empty,
        "manager_reported_success":fact.manager_reported_success,"worker_joined":fact.worker_joined,
        "checkpoint":fact.checkpoint,"elapsed_millis":fact.elapsed_millis,
        "failure":fact.failure.map(|error| error.to_string()),
    })
}
fn assert_consumed(fact: SettlementObservation) {
    assert_eq!(fact.status, SettlementStatus::Consumed);
    assert!(
        fact.term_attempted
            && fact.signal_accepted
            && fact.original_main_exited
            && fact.original_cgroup_empty
            && fact.manager_reported_success
            && fact.worker_joined
    );
}
async fn capture_host(t: &mut LegacyServiceTransition) {
    timeout(Duration::from_secs(15), async {
        loop {
            match t.capture_status() {
                CaptureStatus::Pending => {
                    t.capture_changed().await;
                }
                CaptureStatus::Ready => match t.complete_capture() {
                    Ok(()) => return,
                    Err(TransitionError::Busy) => sleep(Duration::from_millis(5)).await,
                    Err(e) => panic!("Host capture actual join failed: {e}"),
                },
                CaptureStatus::Failed(e) => panic!("Host capture refused: {e}"),
            }
        }
    })
    .await
    .expect("Host original capture deadline; no stop retry");
}
async fn capture_gateway(t: &mut LegacyGatewayTransition) {
    timeout(Duration::from_secs(15), async {
        loop {
            match t.capture_status() {
                CaptureStatus::Pending => {
                    t.capture_changed().await;
                }
                CaptureStatus::Ready => match t.complete_capture() {
                    Ok(()) => return,
                    Err(TransitionError::Busy) => sleep(Duration::from_millis(5)).await,
                    Err(e) => panic!("Gateway capture actual join failed: {e}"),
                },
                CaptureStatus::Failed(e) => panic!("Gateway capture refused: {e}"),
            }
        }
    })
    .await
    .expect("Gateway original capture deadline; no stop retry");
}
async fn settle_host(t: &LegacyServiceTransition) -> SettledLegacyService {
    timeout(Duration::from_secs(20), async {
        loop {
            let fact = t
                .settlement_observation()
                .unwrap()
                .expect("registered Host settlement");
            match fact.status {
                SettlementStatus::Unknown => {
                    panic!("Host settlement Unknown; retain original scope: {fact:?}")
                }
                SettlementStatus::Confirmed => match t.consume_settlement() {
                    Ok(proof) => return proof,
                    Err(TransitionError::Busy) => {}
                    Err(e) => panic!("Host settlement join refused: {e}"),
                },
                _ => {}
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("Host settlement deadline; no automatic replay")
}
async fn settle_gateway(t: &LegacyGatewayTransition) -> SettledLegacyRuntime {
    timeout(Duration::from_secs(20), async {
        loop {
            let fact = t
                .settlement_observation()
                .unwrap()
                .expect("registered Gateway settlement");
            match fact.status {
                SettlementStatus::Unknown => {
                    panic!("Gateway settlement Unknown; retain original scope: {fact:?}")
                }
                SettlementStatus::Confirmed => match t.consume_settlement() {
                    Ok(proof) => return proof,
                    Err(TransitionError::Busy) => {}
                    Err(e) => panic!("Gateway settlement join refused: {e}"),
                },
                _ => {}
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("Gateway settlement deadline; no automatic replay")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires STYX_TEST_LEGACY_GATEWAY_FIXTURE, external original Core preparation/pairing/doctor and owned installed signed systemd Host/Gateway units; not C07 activation or account acceptance"]
async fn actual_original_runtime_cutover_preparation_probe_and_application() {
    let root = PathBuf::from(
        std::env::var_os("STYX_TEST_LEGACY_GATEWAY_FIXTURE").expect("explicit fresh fixture root"),
    );
    let fixture_root = PrivateRoot::open(&root).unwrap();
    let raw = fixture_root.read_raw("fixture.json", 32 * 1024).unwrap();
    let fixture: Fixture = serde_json::from_slice(raw.bytes()).unwrap();
    assert_eq!(fixture.schema, 1);
    assert_eq!(
        fixture.status,
        "PREPARED_ORIGINAL_CORE_NOT_REGISTERED_NOT_STARTED"
    );
    assert!(!fixture.source_scope_notes.is_empty() && fixture.source_scope_notes.len() <= 2048);
    assert!(fixture.state_dir.starts_with(&root) && fixture.host_base.starts_with(&root));
    assert!(fixture.state_dir != root && fixture.host_base != root);
    for name in [
        "native-ready.json",
        "observer-continue",
        "native-result.json",
    ] {
        fixture_root.ensure_absent(name).unwrap();
    }
    let original = crate::foreground::profile::load_paired(&fixture.state_dir).unwrap();
    let host_root = PrivateRoot::open(&fixture.host_base).unwrap();
    let token = host_root.read_raw("device/host.token", 4096).unwrap();
    let original_token = zeroize::Zeroizing::new(token.bytes().to_vec());
    let configuration = PrivateRoot::open(&fixture.state_dir).unwrap();
    let writer = configuration.try_configuration_writer().unwrap();
    let owner = OwnedConfigurationRoot::open_existing(configuration, writer).unwrap();
    let original_root = owner.identity().unwrap();
    let maintenance = owner
        .begin_maintenance("owned-host-gateway-settlement".try_into().unwrap())
        .unwrap();
    let payload =
        PathBuf::from(std::env::var_os("STYX_TEST_LEGACY_SERVICE_NATIVE_PAYLOAD").unwrap());
    let publisher = PathBuf::from(std::env::var_os("STYX_TEST_LEGACY_SERVICE_PUBLISHER").unwrap());
    let expected = PublisherFingerprint::parse(&fixture.publisher_pin).unwrap();
    let candidate = crate::release::verify(&payload, &publisher, &expected).unwrap();
    let mut host = match LegacyServiceTransition::prepare(
        &fixture.state_dir,
        owner.clone(),
        maintenance,
        &materials(),
        candidate,
    )
    .await
    {
        Ok(t) => t,
        Err(e) => panic!("original Host preparation refused: {:?}", e.code()),
    };
    capture_host(&mut host).await;
    assert!(matches!(
        host.complete_capture(),
        Err(TransitionError::Conflict)
    ));
    assert!(owner.ensure_admission().is_err());
    assert!(host.settlement_observation().unwrap().is_none());
    host.begin_settlement(Duration::from_secs(12), CancellationToken::new())
        .unwrap();
    assert_eq!(
        host.begin_settlement(Duration::from_secs(12), CancellationToken::new()),
        Err(TransitionError::Conflict)
    );
    let host_proof = settle_host(&host).await;
    assert_consumed(host_proof.observation());
    assert!(matches!(
        host.consume_settlement(),
        Err(TransitionError::Conflict)
    ));
    let retired = Arc::new(match host_proof.retire_legacy_credential() {
        Ok(r) => r,
        Err(e) => panic!("original token retirement refused: {:?}", e.code()),
    });
    let retirement = retired.observation().unwrap();
    assert!(
        retirement.original_locator_absent
            && retirement.original_inode_preserved
            && retirement.original_bytes_preserved
    );
    assert!(crate::foreground::profile::load_legacy(&fixture.state_dir).is_err());
    assert!(crate::foreground::profile::load_paired(&fixture.state_dir).is_err());
    assert!(original.revalidate().is_err());
    let binding = retired.reader_binding();
    let configuration = PrivateRoot::open(&fixture.state_dir).unwrap();
    assert!(
        binding
            .read_token(&configuration, &host_root)
            .unwrap()
            .as_slice()
            == original_token.as_slice()
    );
    let mut gateway = retired
        .prepare_gateway()
        .await
        .unwrap_or_else(|e| panic!("original Gateway preparation refused: {e}"));
    assert!(matches!(
        retired.prepare_gateway().await,
        Err(TransitionError::Conflict)
    ));
    capture_gateway(&mut gateway).await;
    assert!(matches!(
        gateway.complete_capture(),
        Err(TransitionError::Conflict)
    ));
    assert!(gateway.settlement_observation().unwrap().is_none());
    gateway
        .begin_settlement(Duration::from_secs(15), CancellationToken::new())
        .unwrap();
    assert_eq!(
        gateway.begin_settlement(Duration::from_secs(15), CancellationToken::new()),
        Err(TransitionError::Conflict)
    );
    let combined = Arc::new(settle_gateway(&gateway).await);
    assert!(matches!(
        gateway.consume_settlement(),
        Err(TransitionError::Conflict)
    ));
    assert_consumed(combined.host_observation());
    assert_consumed(combined.gateway_observation());
    combined.revalidate().await.unwrap();
    assert_eq!(
        combined.configuration_root().identity().unwrap(),
        original_root
    );
    assert!(combined.configuration_root().ensure_admission().is_err());
    combined.target().revalidate().unwrap();
    assert!(
        binding
            .read_token(&configuration, &host_root)
            .unwrap()
            .as_slice()
            == original_token.as_slice()
    );
    // Compose actual original dual-scope settlement and projection under the
    // SAME owner/maintenance. The old enrollment directory stays a source.
    let old_enrollment = PrivateRoot::open(fixture.state_dir.join("gateway/enrollment")).unwrap();
    old_enrollment
        .ensure_absent(".styx-configuration-writer.lock")
        .unwrap();
    old_enrollment
        .ensure_absent(".styx-enrollment-journal-v1")
        .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let (mut history_journal, history) = combined
        .with_original_history(
            &fixture.state_dir,
            |snapshot, same_owner, same_maintenance| {
                snapshot.validate_preparation()?;
                assert_eq!(same_owner.identity().unwrap(), original_root);
                let mut journal = snapshot.claim_history_store(same_owner, same_maintenance)?;
                let committed = snapshot.persist_candidate_history(
                    &mut journal,
                    same_maintenance,
                    "original-settled-history".try_into().unwrap(),
                    now,
                )?;
                Ok((journal, committed))
            },
        )
        .unwrap();
    assert!(history_journal.with_journal(|_| Ok(())).is_err());
    // Boot inspection is not a bypass of the live original maintenance fence.
    assert!(
        crate::migration::legacy_enrollment::inspect_pending_history(&mut history_journal).is_err()
    );
    old_enrollment
        .ensure_absent(".styx-configuration-writer.lock")
        .unwrap();
    old_enrollment
        .ensure_absent(".styx-enrollment-journal-v1")
        .unwrap();
    combined.revalidate().await.unwrap();
    let desired_component = styx_contracts::native_management::NativeComponentDesired {
        manager: styx_contracts::native_management::NativeManager::ForegroundCli,
        run: styx_contracts::native_management::NativeRunDesired::Running,
        autostart: styx_contracts::native_management::NativeAutostartDesired::Disabled,
    };
    let mut cutover = combined
        .prepare_native_transition(
            &fixture.state_dir,
            &mut history_journal,
            styx_contracts::native_management::NativeDesired {
                gateway: Some(desired_component),
                host: Some(desired_component),
            },
        )
        .unwrap();
    assert!(!cutover.report().migration_committed && !cutover.report().network_ready);
    let probe = combined
        .validate_candidate_exec(&fixture.state_dir)
        .await
        .unwrap();
    let probe_report = serde_json::to_value(probe.report()).unwrap();
    assert!(matches!(
        combined.validate_candidate_exec(&fixture.state_dir).await,
        Err(TransitionError::Busy)
    ));
    cutover.apply_candidate(probe).unwrap();
    assert!(cutover.report().applied_sha256.is_some());
    assert!(cutover.report().candidate_exec_validation_sha256.is_some());
    assert!(!cutover.report().migration_committed && !cutover.report().network_ready);
    combined.revalidate().await.unwrap();
    assert!(combined.configuration_root().ensure_admission().is_err());
    let marker_raw = configuration
        .read_raw(crate::store::native_root::NATIVE_MARKER_FILE, 4096)
        .unwrap();
    let marker = crate::store::native_state::decode_marker(marker_raw.bytes()).unwrap();
    let canonical_raw = configuration.read_raw("state.json", 1024 * 1024).unwrap();
    let canonical =
        crate::store::native_state::decode_state(canonical_raw.bytes(), &marker).unwrap();
    assert_eq!(canonical.raw_sha256(), cutover.report().target_sha256);
    assert_eq!(
        canonical.state().reader_contract,
        styx_contracts::management::ReaderContract::NativeMigratedStateV1
    );
    assert!(crate::foreground::profile::load_paired(&fixture.state_dir).is_err());
    let facts = json!({
        "schema":1,"status":"ORIGINAL_CUTOVER_APPLIED_PROBE_OBSERVER_REQUIRED",
        "scope":"actual original signed scopes to same-writer cutover preparation, candidate Core Exec and canonical application; final Gateway validation/C07 commit/ordinary startup still required",
        "cutover":cutover.report(),"candidate_probe":probe_report,
        "host":observation(combined.host_observation()),"gateway":observation(combined.gateway_observation()),
        "configuration_root":original_root,
        "history":{"schema":history.schema,"baseline_sha256":history.prepared.baseline_digest.to_hex(),
            "committed_sha256":history.digest().unwrap().to_hex(),"migration":history.prepared.migration.as_str(),
            "source_enrollment_root":history.prepared.enrollment_root,"journal_root":history.prepared.journal_root,
            "same_original_owner":true,"original_enrollment_writer_created":false,
            "original_enrollment_namespace_created":false,"ordinary_admission_open":false,
            "live_fence_inspection_refused":true,"c07_committed":false},
        "candidate_manifest_sha256":combined.target().report().manifest_sha256.to_hex(),
        "retirement_transaction":retirement.transaction_id.as_str(),
        "retired_receipt_sha256":retirement.retired_receipt_sha256.to_hex(),
        "retired_relative_path":retirement.retired_relative_path,
        "original_token_bytes_preserved":retirement.original_bytes_preserved,
        "ordinary_profile_refused":crate::foreground::profile::load_paired(&fixture.state_dir).is_err(),
        "ordinary_admission_refused":owner.ensure_admission().is_err(),
    });
    save(&root, "native-ready.json", &facts);
    // Keep transitions, combined scope, retirement and reader bindings alive
    // through the independent original birth/cgroup/profile observations.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        assert!(
            Instant::now() < deadline,
            "independent observer missing; no final PASS and no forced stop/replay"
        );
        match fs::symlink_metadata(root.join("observer-continue")) {
            Ok(_) => {
                let ack = fixture_root.read_raw("observer-continue", 128).unwrap();
                assert_eq!(ack.bytes(), b"OBSERVED_ORIGINAL_SCOPES\n");
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                sleep(Duration::from_millis(25)).await
            }
            Err(_) => panic!("independent observer barrier became unreadable"),
        }
    }
    combined.revalidate().await.unwrap();
    binding.revalidate().unwrap();
    assert!(
        binding
            .read_token(&configuration, &host_root)
            .unwrap()
            .as_slice()
            == original_token.as_slice()
    );
    assert!(owner.ensure_admission().is_err());
    let mut result = facts;
    result["status"] = json!("PASS_ORIGINAL_CUTOVER_APPLIED_PROBE_WITH_EXTERNAL_ACK");
    result["host"] = observation(combined.host_observation());
    result["gateway"] = observation(combined.gateway_observation());
    save(&root, "native-result.json", &result);
    drop((
        cutover,
        history_journal,
        combined,
        gateway,
        host,
        binding,
        retired,
        original,
    ));
}

/// Independent process only, after the original test actually exited and
/// released its writer. Pending management may be inspected, never bypassed.
#[test]
#[ignore = "requires STYX_TEST_LEGACY_GATEWAY_FIXTURE and completed externally observed original-scope history scene; pending storage inspection only, not Core/C07 recovery"]
fn original_settled_history_reopens_same_state_writer_fenced() {
    use crate::store::enrollment::{JournalBudget, OwnedEnrollmentJournal};
    let root = PathBuf::from(std::env::var_os("STYX_TEST_LEGACY_GATEWAY_FIXTURE").unwrap());
    let fixture_root = PrivateRoot::open(&root).unwrap();
    let raw = fixture_root.read_raw("fixture.json", 32 * 1024).unwrap();
    let fixture: Fixture = serde_json::from_slice(raw.bytes()).unwrap();
    let result_raw = fixture_root
        .read_raw("native-result.json", 32 * 1024)
        .unwrap();
    let result: Value = serde_json::from_slice(result_raw.bytes()).unwrap();
    assert_eq!(
        result["status"],
        "PASS_ORIGINAL_CUTOVER_APPLIED_PROBE_WITH_EXTERNAL_ACK"
    );
    let original_enrollment =
        PrivateRoot::open(fixture.state_dir.join("gateway/enrollment")).unwrap();
    original_enrollment
        .ensure_absent(".styx-configuration-writer.lock")
        .unwrap();
    original_enrollment
        .ensure_absent(".styx-enrollment-journal-v1")
        .unwrap();
    let configuration = PrivateRoot::open(&fixture.state_dir).unwrap();
    let writer = configuration.try_existing_configuration_writer().unwrap();
    let owner = OwnedConfigurationRoot::open_existing(configuration, writer).unwrap();
    assert_eq!(
        serde_json::to_value(owner.identity().unwrap()).unwrap(),
        result["configuration_root"]
    );
    assert!(owner.ensure_admission().is_err());
    let mut journal =
        OwnedEnrollmentJournal::from_configuration(owner.clone(), JournalBudget::default())
            .unwrap();
    assert!(journal.with_journal(|_| Ok(())).is_err());
    let state_root = PrivateRoot::open(&fixture.state_dir).unwrap();
    let marker_raw = state_root
        .read_raw(crate::store::native_root::NATIVE_MARKER_FILE, 4096)
        .unwrap();
    let marker = crate::store::native_state::decode_marker(marker_raw.bytes()).unwrap();
    let canonical_raw = state_root.read_raw("state.json", 1024 * 1024).unwrap();
    let canonical =
        crate::store::native_state::decode_state(canonical_raw.bytes(), &marker).unwrap();
    assert_eq!(
        canonical.raw_sha256().to_hex(),
        result["cutover"]["target_sha256"]
    );
    assert_eq!(
        canonical.state().reader_contract,
        styx_contracts::management::ReaderContract::NativeMigratedStateV1
    );
    let observation =
        crate::migration::legacy_enrollment::inspect_pending_history(&mut journal).unwrap();
    assert_eq!(
        observation.baseline_digest.to_hex(),
        result["history"]["baseline_sha256"]
    );
    assert_eq!(
        observation.committed_digest.to_hex(),
        result["history"]["committed_sha256"]
    );
    assert_eq!(
        observation.migration.as_str(),
        result["history"]["migration"]
    );
    assert_eq!(observation.source_root, observation.journal_root);
    assert_ne!(observation.source_root, observation.enrollment_root);
    assert_eq!(observation.devices, 1);
    assert_eq!(observation.revoked, 0);
    assert!(owner.ensure_admission().is_err());
    assert!(journal.with_journal(|_| Ok(())).is_err());
    let pending_cutover =
        crate::migration::legacy_service::inspect_pending_cutover(owner.clone()).unwrap();
    assert_eq!(
        pending_cutover.stage,
        styx_contracts::management::DurableStage::Applied
    );
    assert_eq!(pending_cutover.target_sha256, canonical.raw_sha256());
    assert!(pending_cutover.validation_sha256.is_some());
    assert!(!pending_cutover.ordinary_admission_open);
    assert!(crate::foreground::profile::load_paired(&fixture.state_dir).is_err());
    original_enrollment
        .ensure_absent(".styx-configuration-writer.lock")
        .unwrap();
    original_enrollment
        .ensure_absent(".styx-enrollment-journal-v1")
        .unwrap();
    save(
        &root,
        "history-reopen.json",
        &json!({
            "schema":1,"status":"PASS_PENDING_HISTORY_STORAGE_INSPECTION_ONLY",
        "canonical_target_sha256":canonical.raw_sha256(),"native_reader_barrier":"native_migrated_state_v1",
        "pending_cutover":pending_cutover,
            "baseline_sha256":observation.baseline_digest.to_hex(),
            "committed_sha256":observation.committed_digest.to_hex(),
            "single_state_writer":true,"original_enrollment_writer_created":false,
            "original_enrollment_namespace_created":false,"ordinary_admission_open":false,
            "ordinary_profile_refused":true,"core_recovery":false,"c07_committed":false,
            "native_activated":false,
        }),
    );
}
