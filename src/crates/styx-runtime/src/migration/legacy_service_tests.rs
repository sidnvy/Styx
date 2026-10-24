//! Explicit real managed-service scene, never run by the default unit suite.
//! The external owner registers only two unique original signed fixture units,
//! observes their original births/cgroups, and retains cleanup responsibility.
use super::*;
use crate::{
    crypto::PublisherFingerprint,
    store::{PreservationInput, PreservationRole, PrivateRoot, legacy_handoff::LegacyMaterialRoot},
};
use serde_json::json;
use std::{fs, path::PathBuf};
use tokio::time::{Instant, sleep, timeout};

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
async fn captured(transition: &mut LegacyServiceTransition) {
    timeout(Duration::from_secs(15), async {
        loop {
            match transition.capture_status() {
                CaptureStatus::Pending => {
                    transition.capture_changed().await;
                }
                CaptureStatus::Ready => match transition.complete_capture() {
                    Ok(()) => break,
                    Err(TransitionError::Busy) => sleep(Duration::from_millis(5)).await,
                    Err(error) => panic!("original capture consumption refused: {error}"),
                },
                CaptureStatus::Failed(error) => panic!("original service capture refused: {error}"),
            }
        }
    })
    .await
    .expect("original service capture deadline; ownership remains retained");
}
async fn settled(transition: &LegacyServiceTransition) -> SettledLegacyService {
    timeout(Duration::from_secs(20), async {
        loop {
            let fact = transition
                .settlement_observation()
                .expect("scope observation")
                .expect("registered stop");
            match fact.status {
                SettlementStatus::Unknown => panic!("original scope settlement Unknown: {fact:?}"),
                SettlementStatus::Confirmed => match transition.consume_settlement() {
                    Ok(proof) => return proof,
                    Err(TransitionError::Busy) => sleep(Duration::from_millis(5)).await,
                    Err(error) => panic!("original settlement consumption refused: {error}"),
                },
                _ => sleep(Duration::from_millis(10)).await,
            }
        }
    })
    .await
    .expect("original scope settlement deadline; never force cleanup")
}
fn save(path: &Path, value: &serde_json::Value) {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(serde_json::to_vec_pretty(value).unwrap().as_slice())
        .unwrap();
    file.sync_all().unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires fresh STYX_TEST_LEGACY_SERVICE_FIXTURE, native signed target and externally owned original user units; not migration/activation"]
async fn actual_original_service_scope_settlement() {
    original_service_scene(false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires fresh externally owned original service fixture, candidate and explicit credential-retirement observer; not migration/activation"]
async fn actual_original_service_scope_credential_retirement() {
    original_service_scene(true).await;
}
async fn original_service_scene(retire_credential: bool) {
    let root = PathBuf::from(std::env::var("STYX_TEST_LEGACY_SERVICE_FIXTURE").unwrap());
    PrivateRoot::open(&root).unwrap();
    let fixture: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("fixture.json")).unwrap()).unwrap();
    assert_eq!(fixture["status"], "PREPARED_NOT_REGISTERED_NOT_STARTED");
    let payload = PathBuf::from(std::env::var("STYX_TEST_LEGACY_SERVICE_NATIVE_PAYLOAD").unwrap());
    let publisher = PathBuf::from(std::env::var("STYX_TEST_LEGACY_SERVICE_PUBLISHER").unwrap());
    let expected = PublisherFingerprint::parse(fixture["publisher_pin"].as_str().unwrap()).unwrap();
    let mut records = vec![];
    // Keep both original manager references and fences until the independent
    // controller has sampled terminal facts and its retained cgroups.
    let mut retained_proofs = Vec::with_capacity(2);
    let mut retired_credentials = Vec::with_capacity(2);
    for role in ["normal", "side"] {
        let spec = &fixture["roles"][role];
        let state = PathBuf::from(spec["state_dir"].as_str().unwrap());
        assert!(state.starts_with(root.join(role)));
        let private = PrivateRoot::open(&state).unwrap();
        let writer = private.try_configuration_writer().unwrap();
        let owner = OwnedConfigurationRoot::open_existing(private, writer).unwrap();
        let maintenance = owner
            .begin_maintenance(format!("owned-service-{role}").try_into().unwrap())
            .unwrap();
        let target = crate::release::verify(&payload, &publisher, &expected).unwrap();
        let mut transition = match LegacyServiceTransition::prepare(
            &state,
            owner.clone(),
            maintenance,
            &materials(),
            target,
        )
        .await
        {
            Ok(value) => value,
            Err(error) => panic!("service preparation refused: {:?}", error.code()),
        };
        captured(&mut transition).await;
        assert!(owner.ensure_admission().is_err());
        assert!(transition.settlement_observation().unwrap().is_none());
        transition
            .begin_settlement(Duration::from_secs(12), CancellationToken::new())
            .unwrap();
        assert_eq!(
            transition.begin_settlement(Duration::from_secs(12), CancellationToken::new()),
            Err(TransitionError::Conflict)
        );
        let proof = settled(&transition).await;
        let fact = proof.observation();
        assert_eq!(fact.status, SettlementStatus::Consumed);
        assert!(
            fact.term_attempted
                && fact.signal_accepted
                && fact.original_main_exited
                && fact.original_cgroup_empty
                && fact.manager_reported_success
                && fact.worker_joined
        );
        assert!(matches!(
            transition.consume_settlement(),
            Err(TransitionError::Conflict)
        ));
        assert_eq!(
            transition.settlement_observation().unwrap().unwrap().status,
            SettlementStatus::Consumed
        );
        assert_eq!(
            proof.configuration_root().identity().unwrap(),
            owner.identity().unwrap()
        );
        assert!(proof.configuration_root().ensure_admission().is_err());
        proof.target().revalidate().unwrap();
        let mut row = json!({"role":role,"unit":spec["unit"],"scope":"original managed service physical settlement only; not activation/handoff",
            "term_attempted":fact.term_attempted,"signal_accepted":fact.signal_accepted,
            "original_main_exited":fact.original_main_exited,"original_cgroup_empty":fact.original_cgroup_empty,
            "systemd_parent_reported_exit0":fact.manager_reported_success,"settlement_worker_joined":fact.worker_joined,
            "writer_still_fenced":true,"descriptor_sha256":proof.descriptor_sha256().to_hex(),
            "candidate_manifest_sha256":proof.target().report().manifest_sha256.to_hex()});
        if retire_credential {
            let retired = match proof.retire_legacy_credential() {
                Ok(value) => value,
                Err(failure) => panic!(
                    "original credential retirement refused: {:?}",
                    failure.code()
                ),
            };
            let observation = retired.observation().unwrap();
            assert!(
                observation.original_locator_absent
                    && observation.original_inode_preserved
                    && observation.original_bytes_preserved
            );
            assert!(retired.configuration_root().ensure_admission().is_err());
            row["credential_retired"] = true.into();
            row["transaction_id"] = observation.transaction_id.as_str().into();
            row["retired_relative_path"] =
                observation.retired_relative_path.to_str().unwrap().into();
            row["retired_receipt_sha256"] = observation.retired_receipt_sha256.to_hex().into();
            retired_credentials.push(retired);
        } else {
            retained_proofs.push(proof);
        }
        save(&root.join(format!("{role}-confirmed.json")), &row);
        records.push(row);
        if role == "normal" {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !root.join("side-independently-witnessed.json").exists() {
                assert!(
                    Instant::now() < deadline,
                    "independent side survival not observed"
                );
                sleep(Duration::from_millis(20)).await;
            }
        }
    }
    save(
        &root.join("service-settlement.json"),
        &json!({"schema":1,"status":if retire_credential {"PASS_ORIGINAL_SERVICE_CREDENTIAL_RETIREMENT_ONLY"} else {"PASS_ORIGINAL_SERVICE_SETTLEMENT_ONLY"},
        "records":records,"migration_committed":false,"native_activated":false,"runtime_ready":false}),
    );
    let deadline = Instant::now() + Duration::from_secs(if retire_credential { 45 } else { 15 });
    while !root
        .join("settlement-independently-witnessed.json")
        .exists()
    {
        assert!(
            Instant::now() < deadline,
            "independent terminal manager and cgroup facts not acknowledged"
        );
        sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(retained_proofs.len() + retired_credentials.len(), 2);
    drop(retained_proofs);
    drop(retired_credentials);
}
