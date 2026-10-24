//! Pure contract counterexamples only. Durable records, SPKI verification and
//! original Gateway settlement are synthetic trusted fixtures, NOT OS proof.
use super::*;
use styx_contracts::historical_enrollment::{HistoricalTokenBinding, SourceRoot};
fn hash(value: &str) -> Sha256Digest {
    Sha256Digest::of_bytes(value.as_bytes())
}
fn id<T: TryFrom<&'static str>>(value: &'static str) -> T
where
    T::Error: std::fmt::Debug,
{
    T::try_from(value).unwrap()
}
fn baseline() -> HistoricalEnrollmentBaseline {
    let active = Device {
        id: id("active"),
        fingerprint: hash("active-spki"),
        grant: Grant {
            computer: true,
            browser: true,
        },
        generation: "legacy-self-cas-generation".into(),
        credential: CredentialRef(hash("normalized-token")),
        credential_hash: hash("normalized-token"),
        profile: OpaqueProfileRef(hash("active-profile")),
        revoked: false,
    };
    let revoked = HistoricalRevoked {
        id: id("retired"),
        fingerprint: hash("retired-spki"),
        grant: Grant {
            computer: true,
            browser: false,
        },
        generation: "legacy-retired-generation".into(),
        profile: OpaqueProfileRef(hash("retired-profile")),
    };
    let token = HistoricalTokenBinding {
        device: active.id.clone(),
        original_relative_path: "gateway/enrollment/tokens/active.token".into(),
        raw_material: MaterialRef {
            kind: MaterialKind::Token,
            digest: hash("normalized-token\n"),
        },
        normalized_material: MaterialRef {
            kind: MaterialKind::Token,
            digest: active.credential_hash,
        },
    };
    let mut required_materials = vec![
        MaterialRef {
            kind: MaterialKind::Profile,
            digest: active.profile.0,
        },
        MaterialRef {
            kind: MaterialKind::Profile,
            digest: revoked.profile.0,
        },
        token.raw_material.clone(),
        token.normalized_material.clone(),
    ];
    required_materials.sort_by_key(material_key);
    HistoricalEnrollmentBaseline {
        schema: 1,
        migration: id("historical-migration"),
        gateway_epoch: id("historical-gateway"),
        sequence: 1,
        expected_revision: 0,
        prepared_at: 10,
        source_bindings_sha256: hash("original-bindings"),
        source_root: SourceRoot::Linux {
            device: 1,
            inode: 2,
            uid: 1000,
        },
        enrollment_root: SourceRoot::Linux {
            device: 1,
            inode: 3,
            uid: 1000,
        },
        default_device: Some(active.id.clone()),
        devices: vec![active],
        revoked: vec![revoked],
        token_bindings: vec![token],
        required_materials,
    }
}
fn attest(c: &EnrollmentControl, b: &HistoricalEnrollmentBaseline) -> HistoricalBaselineRecovery {
    let raw = contract::encode(b).unwrap();
    c.attest_historical_baseline(&raw, Sha256Digest::of_bytes(&raw), hash("baseline-receipt"))
        .unwrap()
}
fn fresh() -> (EnrollmentLedger, EnrollmentControl) {
    EnrollmentLedger::new_recovering(id("current-process"), Limits::default()).unwrap()
}
fn assert_pristine(l: &EnrollmentLedger) {
    assert_eq!(l.revision, 0);
    assert_eq!(l.sequence, 0);
    assert!(l.devices.is_empty());
    assert!(l.historical_revoked.is_empty());
    assert!(l.default_device.is_none());
    assert!(l.recovered_head.is_none());
}
fn seal(
    l: &mut EnrollmentLedger,
    c: &EnrollmentControl,
    revision: u64,
    sequence: u64,
    head: Sha256Digest,
) {
    let floor = l.time_floor.max(20);
    l.finish_recovery(c.attest_recovery_closure(
        revision,
        sequence,
        Some(head),
        None,
        floor,
        floor,
    ))
    .unwrap();
}
fn join_attempt(
    l: &mut EnrollmentLedger,
    c: &EnrollmentControl,
    device: DeviceId,
    fingerprint: Sha256Digest,
    now: u64,
) -> Result<PendingIntent> {
    let payload = JoinPayload {
        invitation: "new-invitation".into(),
        device_id: device,
        label: "fixture".into(),
        platform: "linux".into(),
        cwd: "/tmp".into(),
        shell: "/bin/sh".into(),
        computer_requested: false,
        public_key_pem: "synthetic-trusted-spki".into(),
        browser_requested: Some(false),
    };
    let proof = c
        .attest_join(
            &payload,
            fingerprint,
            id("0123456789abcdef0123456789abcdef"),
            hash("claim"),
            OpaqueProfileRef(hash("profile")),
            PairingContext {
                origin: "https://fixture.test".into(),
                leaf: hash("leaf"),
                ingress_generation: id("ingress"),
                window: None,
            },
        )
        .unwrap();
    l.join(proof, now)
}
#[test]
fn historical_baseline_is_atomic_branded_pristine_and_preserves_native_continuation() {
    let b = baseline();
    let (mut l, c) = fresh();
    let (_, foreign) = fresh();
    assert!(matches!(
        l.recover_historical_baseline(attest(&foreign, &b)),
        Err(EnrollmentError::Authority)
    ));
    assert_pristine(&l);
    drop(attest(&c, &b));
    assert_pristine(&l);
    let raw = contract::encode(&b).unwrap();
    assert!(matches!(
        c.attest_historical_baseline(&raw, hash("wrong"), hash("receipt")),
        Err(EnrollmentError::DurableMismatch)
    ));
    let (mut small, sc) = EnrollmentLedger::new_recovering(
        id("small"),
        Limits {
            devices: 1,
            ..Limits::default()
        },
    )
    .unwrap();
    assert!(matches!(
        small.recover_historical_baseline(attest(&sc, &b)),
        Err(EnrollmentError::Capacity)
    ));
    assert_pristine(&small);
    // Each pure-link refusal is atomic, including failures after several
    // individually valid rows have already been examined.
    let mut repeated_fingerprint = b.clone();
    repeated_fingerprint.revoked[0].fingerprint = repeated_fingerprint.devices[0].fingerprint;
    let mut wrong_credential = b.clone();
    wrong_credential.token_bindings[0]
        .normalized_material
        .digest = hash("other-token");
    let mut revoked_default = b.clone();
    revoked_default.default_device = Some(id("retired"));
    for invalid in [repeated_fingerprint, wrong_credential, revoked_default] {
        let (mut rejected, control) = fresh();
        assert!(matches!(
            rejected.recover_historical_baseline(attest(&control, &invalid)),
            Err(EnrollmentError::Invalid)
        ));
        assert_pristine(&rejected);
    }
    // A pre-existing unresolved native intent must not be overwritten/merged.
    let (mut native, nc) = EnrollmentLedger::new_owned(id("prior"), Limits::default()).unwrap();
    let prior = native
        .invite(&nc.admin(), hash("prior-invitation"), 60, None, 1)
        .unwrap();
    let (mut blocked, bc) = fresh();
    blocked
        .recover_unresolved(
            bc.attest_recovery_unresolved(prior.original_bytes(), prior.digest())
                .unwrap(),
        )
        .unwrap();
    let staged = blocked.staged.as_ref().unwrap().digest();
    assert!(matches!(
        blocked.recover_historical_baseline(attest(&bc, &b)),
        Err(EnrollmentError::Conflict)
    ));
    assert_eq!(blocked.staged.as_ref().unwrap().digest(), staged);
    assert!(blocked.devices.is_empty());
    l.recover_historical_baseline(attest(&c, &b)).unwrap();
    assert_eq!((l.revision, l.sequence), (1, 1));
    assert!(l.recovering);
    assert_eq!(l.devices.get(&id("active")).unwrap(), &b.devices[0]);
    assert_eq!(l.historical_revoked_for_recovery(&c).unwrap(), b.revoked);
    for lane in [Lane::Exec, Lane::Computer, Lane::Browser] {
        assert_eq!(
            l.lanes.get(&(id("active"), lane)),
            Some(&LaneState::RecoveredUnknown)
        );
    }
    assert!(matches!(
        l.recover_historical_baseline(attest(&c, &b)),
        Err(EnrollmentError::Conflict)
    ));
    assert!(matches!(
        l.authentication_target(&c, &id("active")),
        Err(EnrollmentError::Recovering)
    ));
    seal(&mut l, &c, 1, 1, hash("baseline-receipt"));
    assert_eq!(
        l.default_device_for_admin(&c.admin()).unwrap(),
        Some(id("active"))
    );
    let active = &b.devices[0];
    let auth = c.attest_device(
        active.id.clone(),
        active.fingerprint,
        active.credential_hash,
    );
    assert_eq!(
        l.connection_observations(&auth).unwrap(),
        [ConnectionObservation::Unknown; 3]
    );
    assert!(l.authentication_target(&c, &id("retired")).is_err());
    let retired_auth = c.attest_device(
        id("retired"),
        b.revoked[0].fingerprint,
        hash("invented-token"),
    );
    assert!(l.self_device(&retired_auth).is_err());
    assert!(
        l.admit_connection(retired_auth, Lane::Exec, id("new-connection"))
            .is_err()
    );
    let invite = l
        .invite(&c.admin(), hash("new-invitation"), 60, None, 21)
        .unwrap();
    l.confirm_durable(c.attest_durable(&invite, hash("invitation-receipt")))
        .unwrap();
    assert!(matches!(
        join_attempt(&mut l, &c, id("retired"), hash("different-spki"), 22),
        Err(EnrollmentError::Conflict)
    ));
    assert!(matches!(
        join_attempt(&mut l, &c, id("different-id"), b.revoked[0].fingerprint, 23),
        Err(EnrollmentError::Retired)
    ));
    // Continue directly from baseline in a separate recovered instance so this
    // record is sequence 2/revision 1 with the baseline receipt predecessor.
    let (mut source, source_control) = fresh();
    source
        .recover_historical_baseline(attest(&source_control, &b))
        .unwrap();
    seal(&mut source, &source_control, 1, 1, hash("baseline-receipt"));
    let revoke = source
        .revoke(&source_control.admin(), &id("active"), 21)
        .unwrap();
    assert_eq!(
        (revoke.body().sequence, revoke.body().expected_revision),
        (2, 1)
    );
    source
        .confirm_durable(source_control.attest_durable(&revoke, hash("revoke-receipt")))
        .unwrap();
    assert_eq!(
        source
            .default_device_for_admin(&source_control.admin())
            .unwrap(),
        None
    );
    let (mut replay, rc) = fresh();
    replay.recover_historical_baseline(attest(&rc, &b)).unwrap();
    let record = rc
        .attest_recovery_record(
            revoke.original_bytes(),
            revoke.digest(),
            Some(hash("baseline-receipt")),
            hash("revoke-receipt"),
        )
        .unwrap();
    replay.recover_committed(record).unwrap();
    seal(&mut replay, &rc, 2, 2, hash("revoke-receipt"));
    assert!(replay.authentication_target(&rc, &id("active")).is_err());
    assert_eq!(replay.default_device_for_admin(&rc.admin()).unwrap(), None);
    assert_eq!(
        replay.historical_revoked_for_admin(&rc.admin()).unwrap(),
        b.revoked
    );
}
