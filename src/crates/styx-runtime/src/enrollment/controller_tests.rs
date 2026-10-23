//! Controller-specific regressions. Historical Core attestations are trusted
//! synthetic fixtures, not TLS/human-approval or native-device acceptance. One
//! explicit anonymous Node child supplies public SPKIs and one current signature.
#![cfg(all(target_os = "linux", target_env = "gnu"))]
use super::tests::NodeClient;
use super::*;
use crate::store::{
    PrivateRoot,
    enrollment::{EnrollmentJournal, JournalBudget},
};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

const ADMIN: &[u8] = b"owned-controller-admin-AAAAAAAAAAAAAAAAAAAAAAAA";
const ORIGINAL_TOKEN: &[u8] = b"Controller_original_token_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_-";
const HISTORICAL_INVITE: &str = "historical_invite_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const REQUEST: &str = "0123456789abcdef0123456789abcdef";
const NAMESPACE: &str = ".styx-enrollment-journal-v1";
fn limits() -> Limits {
    Limits {
        pending: 1,
        ..Limits::default()
    }
}
fn context() -> PairingContext {
    PairingContext {
        origin: "https://controller.fixture.invalid".into(),
        leaf: Sha256Digest::of_bytes(b"synthetic-listener-not-TLS-evidence"),
        ingress_generation: "controller-fixture-ingress".try_into().unwrap(),
        window: None,
    }
}
fn headers(token: Option<&[u8]>) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(HOST, "controller.fixture.invalid".parse().unwrap());
    if let Some(token) = token {
        h.insert(
            AUTHORIZATION,
            format!("Bearer {}", std::str::from_utf8(token).unwrap())
                .parse()
                .unwrap(),
        );
    }
    h
}
fn root(parent: &Path) -> PathBuf {
    let p = parent.join(uuid::Uuid::new_v4().to_string());
    fs::create_dir(&p).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
    p
}
fn payload(public: &str, device: &str, invitation: &str) -> JoinPayload {
    JoinPayload {
        invitation: invitation.into(),
        device_id: device.try_into().unwrap(),
        label: "Owned controller fixture".into(),
        platform: "linux".into(),
        cwd: "/tmp/owned-controller".into(),
        shell: "/bin/sh".into(),
        computer_requested: true,
        browser_requested: Some(true),
        public_key_pem: public.into(),
    }
}
fn stored_profile(payload: &JoinPayload, fingerprint: Sha256Digest) -> Vec<u8> {
    serde_json::to_vec(&profile::StoredProfile {
        schema: 1,
        device_id: payload.device_id.clone(),
        fingerprint,
        label: payload.label.clone(),
        platform: payload.platform.clone(),
        cwd: payload.cwd.clone(),
        shell: payload.shell.clone(),
        public_key_pem: payload.public_key_pem.clone(),
    })
    .unwrap()
}
fn commit(
    j: &mut EnrollmentJournal<'_>,
    ledger: &mut EnrollmentLedger,
    control: &EnrollmentControl,
    intent: PendingIntent,
    head: &mut Option<Sha256Digest>,
) {
    let prepared = j.prepare(intent.original_bytes(), *head).unwrap();
    let receipt = j.commit(&prepared).unwrap().digest().unwrap();
    ledger
        .confirm_durable(control.attest_durable(&intent, receipt))
        .unwrap();
    *head = Some(receipt);
}
fn historical_store(
    path: &Path,
    public: &str,
    fingerprint: Sha256Digest,
    approved: bool,
) -> (OwnedEnrollmentJournal, DeviceId, OpaqueProfileRef) {
    let root = PrivateRoot::open(path).unwrap();
    let mut writer = root.try_configuration_writer().unwrap();
    let device: DeviceId = "styx-aaaaaaaaaaaaaaaaaaaaaaaa".try_into().unwrap();
    let profile_ref;
    {
        let mut journal =
            EnrollmentJournal::open(&root, &mut writer, JournalBudget::default()).unwrap();
        let now = wall_now().unwrap().checked_sub(2 * 60 * 60 * 1000).unwrap();
        journal.record_time_floor(now).unwrap();
        let recovered = recovery::recover_journal(
            &mut journal,
            "trusted-historical-controller".try_into().unwrap(),
            limits(),
            now,
        )
        .unwrap();
        let mut ledger = recovered.ledger;
        let control = recovered.control;
        let mut head = None;
        journal.record_time_floor(now + 1).unwrap();
        let invitation = ledger
            .invite(
                &control.admin(),
                Sha256Digest::of_bytes(HISTORICAL_INVITE.as_bytes()),
                60,
                None,
                now + 1,
            )
            .unwrap();
        commit(&mut journal, &mut ledger, &control, invitation, &mut head);
        let join = payload(public, device.as_str(), HISTORICAL_INVITE);
        let raw = stored_profile(&join, fingerprint);
        profile_ref = OpaqueProfileRef(
            journal
                .put_material(MaterialKind::Profile, &raw)
                .unwrap()
                .digest,
        );
        journal.record_time_floor(now + 2).unwrap();
        // Explicit historical trusted evidence: no claim to verify this old
        // signature or an actual TLS leaf/human comparison in this fixture.
        let proof = control
            .attest_join(
                &join,
                fingerprint,
                REQUEST.try_into().unwrap(),
                Sha256Digest::of_bytes(b"historical-claim-secret"),
                profile_ref.clone(),
                context(),
            )
            .unwrap();
        let joined = ledger.join(proof, now + 2).unwrap();
        commit(&mut journal, &mut ledger, &control, joined, &mut head);
        if approved {
            let profile = VerifiedProfile::from_stored(&raw).unwrap();
            let sealed = profile
                .public_key()
                .wrap_credential(ORIGINAL_TOKEN)
                .unwrap();
            let token = journal
                .put_material(MaterialKind::Token, ORIGINAL_TOKEN)
                .unwrap();
            let sealed = journal.put_material(MaterialKind::Sealed, &sealed).unwrap();
            let target = ledger
                .approval_target(&control.admin(), &REQUEST.try_into().unwrap())
                .unwrap();
            let pending = ledger
                .pending_for_admin(&control.admin(), now + 3)
                .unwrap()
                .pop()
                .unwrap();
            let prepared = control
                .attest_prepared_credential(
                    target,
                    CredentialRef(token.digest),
                    token.digest,
                    SealedCredentialRef(sealed.digest),
                )
                .unwrap();
            journal.record_time_floor(now + 3).unwrap();
            let intent = ledger
                .approve(
                    &control.admin(),
                    styx_core::enrollment::ApprovalRequest {
                        request: REQUEST.try_into().unwrap(),
                        fingerprint,
                        comparison: pending.facts.comparison,
                        grant: Grant {
                            computer: true,
                            browser: true,
                        },
                    },
                    prepared,
                    now + 3,
                )
                .unwrap();
            commit(&mut journal, &mut ledger, &control, intent, &mut head);
        }
    }
    (
        OwnedEnrollmentJournal::open_existing(root, writer, JournalBudget::default()).unwrap(),
        device,
        profile_ref,
    )
}
fn recover_service(store: OwnedEnrollmentJournal) -> EnrollmentService {
    EnrollmentService::recover_existing(
        store,
        ADMIN,
        Sha256Digest::of_bytes(b"different-ordinary-mcp-fixture"),
        vec!["controller.fixture.invalid".into()],
        limits(),
    )
    .unwrap()
}
fn assert_sticky(error: ServiceError) {
    assert_eq!(error.status(), 503);
    assert_eq!(error.code(), "enrollment_recovery_required");
}

#[tokio::test]
#[ignore = "requires STYX_TEST_ENROLLMENT_CONTROLLER_ROOT and fixed STYX_TEST_NODE22; trusted historical Core + real private store regressions, not TLS"]
async fn expired_pending_collection_and_observed_store_failure_sticky_fence() {
    let base = PathBuf::from(std::env::var("STYX_TEST_ENROLLMENT_CONTROLLER_ROOT").unwrap());
    fs::create_dir_all(&base).unwrap();
    let mut node = NodeClient::start().await;
    let path = root(&base);
    let (store, _, _) =
        historical_store(&path, &node.hello.public_a, node.hello.fingerprint_a, false);
    let mut service = recover_service(store);
    let (_, invite) = service
        .request(
            &Method::POST,
            "/styx/enroll/invitations",
            &headers(Some(ADMIN)),
            b"{}",
            &context(),
        )
        .unwrap();
    let invitation = invite["invitation"].as_str().unwrap();
    let join = payload(
        &node.hello.public_b,
        "styx-bbbbbbbbbbbbbbbbbbbbbbbb",
        invitation,
    );
    let signature = node.sign_join("b", &join).await;
    let mut body = serde_json::to_value(&join).unwrap();
    body.as_object_mut()
        .unwrap()
        .insert("signature".into(), Value::String(signature));
    let body = Zeroizing::new(serde_json::to_vec(&body).unwrap());
    let (status, joined) = service
        .request(
            &Method::POST,
            "/styx/enroll/join",
            &headers(None),
            &body,
            &context(),
        )
        .unwrap();
    assert_eq!(
        status, 202,
        "expired single retained slot must be durably collected, not permanent429"
    );
    let pending = service
        .ledger
        .pending_for_admin(&service.control.admin(), wall_now().unwrap())
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].facts.device, join.device_id);
    let new_request = joined["request_id"].as_str().unwrap();
    // Independent raw disk oracle sees a committed maintenance record before
    // the replacement Join. No call to controller's persist helper to inspect it.
    let mut committed = vec![];
    for entry in fs::read_dir(path.join(NAMESPACE)).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".committed") {
            continue;
        }
        let marker: Value = serde_json::from_slice(&fs::read(entry.path()).unwrap()).unwrap();
        let id = marker["binding"]["transaction"].as_str().unwrap();
        let raw = fs::read(path.join(NAMESPACE).join(format!("txn-{id}.intent"))).unwrap();
        let intent: Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(
            Sha256Digest::of_bytes(&raw).to_hex(),
            marker["binding"]["intent_digest"].as_str().unwrap()
        );
        committed.push((intent["sequence"].as_u64().unwrap(), intent));
    }
    committed.sort_by_key(|(sequence, _)| *sequence);
    let collection = committed
        .iter()
        .position(|(_, i)| {
            i["mutation"]["kind"] == "collect_pending"
                && i["mutation"]["requests"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|r| r == REQUEST)
        })
        .unwrap();
    let replacement = committed
        .iter()
        .position(|(_, i)| {
            i["mutation"]["kind"] == "join"
                && i["mutation"]["pending"]["facts"]["request"] == new_request
        })
        .unwrap();
    assert!(collection < replacement);
    drop(service);

    for fault in ["nonprivate_profile", "missing_token", "replaced_namespace"] {
        let path = root(&base);
        let (store, device, profile_ref) =
            historical_store(&path, &node.hello.public_a, node.hello.fingerprint_a, true);
        let mut service = recover_service(store);
        let snapshot = service
            .ledger
            .authentication_target(&service.control, &device)
            .unwrap();
        for lane in [Lane::Exec, Lane::Computer, Lane::Browser] {
            // This synthetic predecessor never listened/owned transport jobs.
            // Trusted fixture quiescence is NOT production/native exit proof.
            service
                .ledger
                .reconcile_recovered_lane(
                    service
                        .control
                        .attest_recovered_lane_closed(&snapshot, lane),
                )
                .unwrap();
        }
        let lease = service
            .admit_host(
                &device,
                ORIGINAL_TOKEN,
                Lane::Exec,
                "baseline-exec".try_into().unwrap(),
            )
            .unwrap();
        service.authorize_host_frame(&lease).unwrap();
        let endpoint = format!("/styx/enroll/self/{}/capabilities", device.as_str());
        assert_eq!(
            service
                .request(
                    &Method::GET,
                    &endpoint,
                    &headers(Some(ORIGINAL_TOKEN)),
                    b"",
                    &context()
                )
                .unwrap()
                .0,
            200
        );
        let token = path.join(NAMESPACE).join(format!(
            "token-{}.material",
            Sha256Digest::of_bytes(ORIGINAL_TOKEN).to_hex()
        ));
        let token_before = fs::read(&token).unwrap();
        let profile = path
            .join(NAMESPACE)
            .join(format!("profile-{}.material", profile_ref.0.to_hex()));
        let (kind, digest) = match fault {
            "nonprivate_profile" => {
                fs::set_permissions(&profile, fs::Permissions::from_mode(0o644)).unwrap();
                (MaterialKind::Profile, profile_ref.0)
            }
            "missing_token" => {
                fs::rename(&token, path.join("original-token-retained")).unwrap();
                (MaterialKind::Token, Sha256Digest::of_bytes(ORIGINAL_TOKEN))
            }
            _ => {
                fs::rename(
                    path.join(NAMESPACE),
                    path.join("original-namespace-retained"),
                )
                .unwrap();
                fs::create_dir(path.join(NAMESPACE)).unwrap();
                fs::set_permissions(path.join(NAMESPACE), fs::Permissions::from_mode(0o700))
                    .unwrap();
                (MaterialKind::Token, Sha256Digest::of_bytes(ORIGINAL_TOKEN))
            }
        };
        assert!(
            service.read_material(kind, digest).is_err(),
            "actual protected read must observe fault"
        );
        match fault {
            "nonprivate_profile" => {
                fs::set_permissions(&profile, fs::Permissions::from_mode(0o600)).unwrap()
            }
            "missing_token" => fs::rename(path.join("original-token-retained"), &token).unwrap(),
            _ => {
                fs::rename(
                    path.join(NAMESPACE),
                    path.join("replacement-namespace-retained"),
                )
                .unwrap();
                fs::rename(
                    path.join("original-namespace-retained"),
                    path.join(NAMESPACE),
                )
                .unwrap();
            }
        }
        assert_eq!(
            Sha256Digest::of_bytes(&fs::read(&token).unwrap()),
            Sha256Digest::of_bytes(&token_before)
        );
        assert_eq!(token_before.as_slice(), ORIGINAL_TOKEN);
        assert_sticky(service.authorize_host_frame(&lease).unwrap_err());
        let admission = service.admit_host(
            &device,
            ORIGINAL_TOKEN,
            Lane::Computer,
            "new-computer".try_into().unwrap(),
        );
        assert!(
            matches!(admission,Err(e) if e.status()==503 && e.code()=="enrollment_recovery_required")
        );
        assert_sticky(
            service
                .request(
                    &Method::GET,
                    &endpoint,
                    &headers(Some(ORIGINAL_TOKEN)),
                    b"",
                    &context(),
                )
                .unwrap_err(),
        );
        assert_eq!(fs::read(&token).unwrap(), token_before);
    }
    node.stop().await;
    println!(
        "Controller regression fixture={}: pendinglimit1 historical expiry collected durably before new real-signedjoin; actual material mode/missing/namespace faults remain sticky503 after exact restoration for oldframe/newlane/self, originaltokenbytes preserved. Trusted historical Core attestations; NOT TLS/native/profile-migration acceptance",
        base.display()
    );
}
