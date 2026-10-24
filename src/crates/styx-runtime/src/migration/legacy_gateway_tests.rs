//! One actual original signed Host+Gateway installed-service settlement scene.
//! The external controller owns original Core preparation/pairing/doctor, unit
//! registration and all final cleanup. This test neither installs a service nor
//! proves C07 commit, native activation, or account acceptance.
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
async fn actual_original_host_and_gateway_scope_settlement() {
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
    let combined = settle_gateway(&gateway).await;
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
    let facts = json!({
        "schema":1,"status":"ORIGINAL_SCOPES_SETTLED_RETIRED_READER_OBSERVER_REQUIRED",
        "scope":"actual installed signed Host and Gateway physical settlement; no C07 commit/activation/account acceptance",
        "host":observation(combined.host_observation()),"gateway":observation(combined.gateway_observation()),
        "configuration_root":original_root,
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
    result["status"] =
        json!("PASS_ORIGINAL_HOST_GATEWAY_SETTLEMENT_RETIRED_READER_WITH_EXTERNAL_ACK");
    result["host"] = observation(combined.host_observation());
    result["gateway"] = observation(combined.gateway_observation());
    save(&root, "native-result.json", &result);
    drop((combined, gateway, host, binding, retired, original));
}
