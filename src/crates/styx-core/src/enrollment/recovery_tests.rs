//! Independent pure-Core recovery scenarios. Every storage/crypto fact here is
//! explicitly synthetic; no real durability, restart, TLS or device is claimed.
use super::*;

fn hash(s: &str) -> Sha256Digest {
    Sha256Digest::of_bytes(s.as_bytes())
}
fn id<T: TryFrom<&'static str>>(s: &'static str) -> T
where
    T::Error: std::fmt::Debug,
{
    T::try_from(s).unwrap()
}
struct Entry {
    bytes: Vec<u8>,
    digest: Sha256Digest,
    receipt: Sha256Digest,
}
struct History {
    entries: Vec<Entry>,
    device: Device,
    request: RequestId,
    claim: Sha256Digest,
}
fn save(
    l: &mut EnrollmentLedger,
    c: &EnrollmentControl,
    p: PendingIntent,
    entries: &mut Vec<Entry>,
) {
    let receipt = hash(&format!("synthetic-only-receipt-{}", entries.len()));
    entries.push(Entry {
        bytes: p.original_bytes().to_vec(),
        digest: p.digest(),
        receipt,
    });
    l.confirm_durable(c.attest_durable(&p, receipt)).unwrap();
}
fn history() -> History {
    let (mut l, c) =
        EnrollmentLedger::new_owned(id("previous-process"), Limits::default()).unwrap();
    let mut entries = vec![];
    let payload = JoinPayload {
        invitation: "synthetic-invitation".into(),
        device_id: id("recovered-device"),
        label: "fixture".into(),
        platform: "linux".into(),
        cwd: "/tmp".into(),
        shell: "/bin/sh".into(),
        computer_requested: true,
        public_key_pem: "synthetic-runtime-verified-key".into(),
        browser_requested: Some(true),
    };
    let p = l
        .invite(&c.admin(), hash(&payload.invitation), 60, None, 1)
        .unwrap();
    save(&mut l, &c, p, &mut entries);
    let aborted = l.close_window(&c.admin(), None, 2).unwrap();
    l.abort_proven_not_written(c.attest_not_written(&aborted))
        .unwrap();
    let request: RequestId = id("0123456789abcdef0123456789abcdef");
    let claim = hash("synthetic-claim");
    let proof = c
        .attest_join(
            &payload,
            hash("original-spki"),
            request.clone(),
            claim,
            OpaqueProfileRef(hash("profile-bytes")),
            PairingContext {
                origin: "https://fixture.test".into(),
                leaf: hash("leaf"),
                ingress_generation: id("ingress"),
                window: None,
            },
        )
        .unwrap();
    let comparison = proof.facts.comparison.clone();
    let p = l.join(proof, 3).unwrap();
    save(&mut l, &c, p, &mut entries);
    let target = l.approval_target(&c.admin(), &request).unwrap();
    let prepared = c
        .attest_prepared_credential(
            target,
            CredentialRef(hash("synthetic-token")),
            hash("synthetic-token"),
            SealedCredentialRef(hash("sealed-bytes")),
        )
        .unwrap();
    let p = l
        .approve(
            &c.admin(),
            ApprovalRequest {
                request: request.clone(),
                fingerprint: hash("original-spki"),
                comparison,
                grant: Grant {
                    computer: true,
                    browser: true,
                },
            },
            prepared,
            4,
        )
        .unwrap();
    save(&mut l, &c, p, &mut entries);
    let confirmation = c
        .attest_confirmation(
            c.attest_claim(request.clone(), claim),
            payload.device_id.clone(),
            CredentialRef(hash("synthetic-token")),
        )
        .unwrap();
    let p = l.confirm(confirmation, 5).unwrap();
    save(&mut l, &c, p, &mut entries);
    History {
        entries,
        device: l
            .self_device(&c.attest_device(
                payload.device_id,
                hash("original-spki"),
                hash("synthetic-token"),
            ))
            .unwrap()
            .clone(),
        request,
        claim,
    }
}
fn recovering() -> (EnrollmentLedger, EnrollmentControl) {
    EnrollmentLedger::new_recovering(id("new-process"), Limits::default()).unwrap()
}
fn replay(l: &mut EnrollmentLedger, c: &EnrollmentControl, h: &History) {
    let mut previous = None;
    for e in &h.entries {
        l.recover_committed(
            c.attest_recovery_record(&e.bytes, e.digest, previous, e.receipt)
                .unwrap(),
        )
        .unwrap();
        previous = Some(e.receipt);
    }
}
fn auth(c: &EnrollmentControl, d: &Device) -> DeviceSelfProof {
    c.attest_device(d.id.clone(), d.fingerprint, d.credential_hash)
}
fn seal(
    l: &mut EnrollmentLedger,
    c: &EnrollmentControl,
    h: &History,
    unresolved: Option<Sha256Digest>,
    highwater: u64,
) {
    l.finish_recovery(c.attest_recovery_closure(
        h.entries.len() as u64,
        highwater,
        h.entries.last().map(|e| e.receipt),
        unresolved,
        50,
        100,
    ))
    .unwrap();
}
#[test]
fn original_history_all_authority_gates_chain_and_exact_dependencies() {
    let h = history();
    let (mut l, c) = recovering();
    let first = &h.entries[0];
    let mut altered = first.bytes.clone();
    altered.push(b' ');
    assert_eq!(
        c.attest_recovery_record(&altered, first.digest, None, first.receipt)
            .unwrap_err(),
        EnrollmentError::DurableMismatch
    );
    let foreign = EnrollmentLedger::new_recovering(id("new-process"), Limits::default())
        .unwrap()
        .1;
    assert_eq!(
        l.recover_committed(
            foreign
                .attest_recovery_record(&first.bytes, first.digest, None, first.receipt)
                .unwrap()
        ),
        Err(EnrollmentError::Authority)
    );
    assert_eq!(
        l.recover_committed(
            c.attest_recovery_record(
                &first.bytes,
                first.digest,
                Some(hash("wrong-head")),
                first.receipt
            )
            .unwrap()
        ),
        Err(EnrollmentError::DurableMismatch)
    );
    l.recover_committed(
        c.attest_recovery_record(&first.bytes, first.digest, None, first.receipt)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        l.recover_committed(
            c.attest_recovery_record(&first.bytes, first.digest, None, first.receipt)
                .unwrap()
        ),
        Err(EnrollmentError::DurableMismatch)
    );
    let join = &h.entries[1];
    let mut bad = intent_contract::decode(&join.bytes).unwrap();
    bad.required_materials.clear();
    let bytes = intent_contract::encode(&bad).unwrap();
    assert!(
        l.recover_committed(
            c.attest_recovery_record(
                &bytes,
                Sha256Digest::of_bytes(&bytes),
                Some(first.receipt),
                join.receipt
            )
            .unwrap()
        )
        .is_err()
    );
    assert_eq!(l.revision, 1);
    assert!(l.recovery_devices(&c).unwrap().is_empty());
    assert_eq!(
        l.finish_recovery(c.attest_recovery_closure(
            4,
            17,
            h.entries.last().map(|e| e.receipt),
            None,
            50,
            100
        )),
        Err(EnrollmentError::DurableMismatch)
    );
    let mut previous = Some(first.receipt);
    for e in &h.entries[1..] {
        l.recover_committed(
            c.attest_recovery_record(&e.bytes, e.digest, previous, e.receipt)
                .unwrap(),
        )
        .unwrap();
        previous = Some(e.receipt);
    }
    assert_eq!(
        l.self_device(&auth(&c, &h.device)).unwrap_err(),
        EnrollmentError::Recovering
    );
    assert_eq!(
        l.claim(&c.attest_claim(h.request.clone(), h.claim), 100)
            .unwrap_err(),
        EnrollmentError::Recovering
    );
    assert_eq!(
        l.approval_target(&c.admin(), &h.request).unwrap_err(),
        EnrollmentError::Recovering
    );
    assert_eq!(
        l.admit_connection(auth(&c, &h.device), Lane::Exec, id("pre-ready"))
            .unwrap_err(),
        EnrollmentError::Recovering
    );
    let lease = ConnectionLease {
        brand: c.brand.clone(),
        device: h.device.id.clone(),
        lane: Lane::Exec,
        generation: id("not-installed"),
        capability_generation: h.device.generation.clone(),
    };
    assert_eq!(
        l.authorize_connection(&lease).unwrap_err(),
        EnrollmentError::Recovering
    );
    assert_eq!(
        l.invite(&c.admin(), hash("next invitation"), 60, None, 100)
            .unwrap_err(),
        EnrollmentError::Recovering
    );
    assert_eq!(
        l.collect_pending(&c.admin(), 100).unwrap_err(),
        EnrollmentError::Recovering
    );
    assert_eq!(
        l.finish_recovery(c.attest_recovery_closure(4, 17, previous, None, 50, 49)),
        Err(EnrollmentError::Clock)
    );
    seal(&mut l, &c, &h, None, 17);
    assert_eq!(l.self_device(&auth(&c, &h.device)).unwrap(), &h.device);
    assert_eq!(
        l.admit_connection(auth(&c, &h.device), Lane::Exec, id("still-unknown"))
            .unwrap_err(),
        EnrollmentError::Conflict
    );
    let next = l
        .invite(&c.admin(), hash("next invitation"), 60, None, 100)
        .unwrap();
    assert_eq!(next.body().sequence, 18);
    assert_eq!(next.body().gateway_epoch, id::<GatewayEpoch>("new-process"));
    assert_eq!(
        l.recover_committed(
            c.attest_recovery_record(&first.bytes, first.digest, None, first.receipt)
                .unwrap()
        ),
        Err(EnrollmentError::Conflict)
    );
}
#[test]
fn unresolved_revoke_restores_exact_fence_and_strong_abort_keeps_highwater() {
    let h = history();
    let (mut l, c) = recovering();
    replay(&mut l, &c, &h);
    let mut body = intent_contract::decode(&h.entries.last().unwrap().bytes).unwrap();
    body.sequence = 6;
    body.expected_revision = 4;
    body.prepared_at = 6;
    body.transaction = TransactionId::try_from(format!(
        "enrollment-{}",
        intent_contract::allocated_identity(
            "styx-enrollment-transaction-v1",
            &body.gateway_epoch,
            6,
            None
        )
        .unwrap()
        .to_hex()
    ))
    .unwrap();
    body.required_materials.clear();
    body.mutation = Mutation::Revoke {
        device: h.device.id.clone(),
        fingerprint: h.device.fingerprint,
    };
    let raw = intent_contract::encode(&body).unwrap();
    let digest = Sha256Digest::of_bytes(&raw);
    l.recover_unresolved(c.attest_recovery_unresolved(&raw, digest).unwrap())
        .unwrap();
    seal(&mut l, &c, &h, Some(digest), 19);
    assert_eq!(l.pending_intent().unwrap().original_bytes(), raw);
    assert_eq!(l.pending_intent().unwrap().digest(), digest);
    assert_eq!(
        l.self_device(&auth(&c, &h.device)).unwrap_err(),
        EnrollmentError::Busy
    );
    assert_eq!(
        l.claim(&c.attest_claim(h.request.clone(), h.claim), 100)
            .unwrap_err(),
        EnrollmentError::Busy
    );
    assert_eq!(
        l.admit_connection(auth(&c, &h.device), Lane::Exec, id("fenced"))
            .unwrap_err(),
        EnrollmentError::Busy
    );
    assert_eq!(
        l.invite(&c.admin(), hash("unrelated mutation"), 60, None, 100)
            .unwrap_err(),
        EnrollmentError::Busy
    );
    let (_, foreign) = recovering();
    let staged = l.pending_intent().unwrap().clone();
    assert_eq!(
        l.abort_proven_not_written(foreign.attest_not_written(&staged)),
        Err(EnrollmentError::Authority)
    );
    assert_eq!(l.pending_intent().unwrap().original_bytes(), raw);
    l.abort_proven_not_written(c.attest_not_written(&staged))
        .unwrap();
    assert_eq!(l.self_device(&auth(&c, &h.device)).unwrap(), &h.device);
    let next = l.revoke(&c.admin(), &h.device.id, 100).unwrap();
    assert_eq!(next.body().sequence, 20);
    assert_ne!(next.body().transaction, body.transaction);

    // The other real outcome of the SAME unresolved original bytes is durable
    // commit, not a fabricated no-write proof. Restart clock advancement cannot
    // invalidate that historical intent or roll the clock floor backward.
    let (mut committed, control) = recovering();
    replay(&mut committed, &control, &h);
    committed
        .recover_unresolved(control.attest_recovery_unresolved(&raw, digest).unwrap())
        .unwrap();
    seal(&mut committed, &control, &h, Some(digest), 19);
    let staged = committed.pending_intent().unwrap().clone();
    assert_eq!(
        committed
            .confirm_durable(foreign.attest_durable(&staged, hash("wrong-brand")))
            .unwrap_err(),
        EnrollmentError::Authority
    );
    assert_eq!(committed.pending_intent().unwrap().original_bytes(), raw);
    let result = committed
        .confirm_durable(control.attest_durable(&staged, hash("exact recovered commit receipt")))
        .unwrap();
    assert_eq!(result.intent_digest, digest);
    assert_eq!(result.revision, 5);
    assert!(committed.pending_intent().is_none());
    assert!(committed.devices.get(&h.device.id).unwrap().revoked);
    assert!(committed.time_floor >= 50);
    assert_eq!(
        committed
            .self_device(&auth(&control, &h.device))
            .unwrap_err(),
        EnrollmentError::Proof
    );
    assert_eq!(
        committed
            .invite(
                &control.admin(),
                hash("post commit next invitation"),
                60,
                None,
                49
            )
            .unwrap_err(),
        EnrollmentError::Clock
    );
    let fresh = committed
        .invite(
            &control.admin(),
            hash("post commit next invitation"),
            60,
            None,
            100,
        )
        .unwrap();
    assert_eq!(fresh.body().sequence, 20);
}
#[test]
fn startup_lane_closure_fact_cannot_clear_new_connection_uncertainty() {
    let h = history();
    let (mut l, c) = recovering();
    replay(&mut l, &c, &h);
    seal(&mut l, &c, &h, None, 5);
    let stale = c.attest_recovered_lane_closed(&h.device, Lane::Exec);
    let first = c.attest_recovered_lane_closed(&h.device, Lane::Exec);
    let mut wrong = h.device.clone();
    wrong.credential_hash = hash("different-token");
    assert_eq!(
        l.reconcile_recovered_lane(c.attest_recovered_lane_closed(&wrong, Lane::Exec)),
        Err(EnrollmentError::Proof)
    );
    let (_, foreign) = recovering();
    assert_eq!(
        l.reconcile_recovered_lane(foreign.attest_recovered_lane_closed(&h.device, Lane::Exec)),
        Err(EnrollmentError::Authority)
    );
    l.reconcile_recovered_lane(first).unwrap();
    let live = l
        .admit_connection(auth(&c, &h.device), Lane::Exec, id("new-current-session"))
        .unwrap();
    assert!(l.authorize_connection(&live).is_ok());
    l.connection_ended(live, false).unwrap();
    assert_eq!(
        l.reconcile_recovered_lane(stale),
        Err(EnrollmentError::Conflict)
    );
    assert_eq!(
        l.reconcile_recovered_lane(c.attest_recovered_lane_closed(&h.device, Lane::Exec)),
        Err(EnrollmentError::Conflict)
    );
    for lane in [Lane::Computer, Lane::Browser] {
        l.reconcile_recovered_lane(c.attest_recovered_lane_closed(&h.device, lane))
            .unwrap();
    }
    let proof = c
        .attest_self_cas(
            &CapabilityPayload {
                device_id: h.device.id.clone(),
                fingerprint: h.device.fingerprint,
                generation: h.device.generation.clone(),
                enable_computer: None,
                enable_browser: Some(false),
            },
            h.device.credential_hash,
        )
        .unwrap();
    assert_eq!(
        l.self_cas(proof, 100).unwrap_err(),
        EnrollmentError::OfflineRequired
    );
}
