use super::*;
fn hash(s: &str) -> Sha256Digest {
    Sha256Digest::of_bytes(s.as_bytes())
}
fn request() -> RequestId {
    RequestId::try_from("0123456789abcdef0123456789abcdef").unwrap()
}
fn pairing() -> PairingContext {
    PairingContext {
        origin: "https://gateway.test".into(),
        leaf: hash("actual leaf"),
        ingress_generation: PairingIngressGeneration::try_from("ingress-1").unwrap(),
        window: None,
    }
}
fn payload() -> JoinPayload {
    JoinPayload {
        invitation: "owned-one-use-invitation-not-a-real-secret".into(),
        device_id: DeviceId::try_from("styx-owned").unwrap(),
        label: "owned".into(),
        platform: "linux".into(),
        cwd: "/tmp".into(),
        shell: "/bin/sh".into(),
        computer_requested: true,
        public_key_pem: "runtime-verified-placeholder-not-real-key".into(),
        browser_requested: Some(true),
    }
}
fn setup() -> (EnrollmentLedger, EnrollmentControl) {
    EnrollmentLedger::new_owned(
        GatewayEpoch::try_from("owned-gateway-epoch").unwrap(),
        Limits::default(),
    )
    .unwrap()
}
fn commit(l: &mut EnrollmentLedger, c: &EnrollmentControl, p: &PendingIntent) {
    l.confirm_durable(c.attest_durable(p, hash("owned test-only durable attestation")))
        .unwrap();
}
fn pending(l: &mut EnrollmentLedger, c: &EnrollmentControl) -> (JoinPayload, String) {
    let p = payload();
    let invite = l
        .invite(&c.admin(), hash(&p.invitation), 60, None, 1)
        .unwrap();
    commit(l, c, &invite);
    let proof = c
        .attest_join(
            &p,
            hash("spki"),
            request(),
            hash("claim"),
            OpaqueProfileRef(hash("profile")),
            pairing(),
        )
        .unwrap();
    let code = proof.facts.comparison.clone();
    let join = l.join(proof, 2).unwrap();
    commit(l, c, &join);
    (p, code)
}
fn approved(l: &mut EnrollmentLedger, c: &EnrollmentControl) -> DeviceId {
    let (p, code) = pending(l, c);
    let approve = l
        .approve(
            &c.admin(),
            ApprovalRequest {
                request: request(),
                fingerprint: hash("spki"),
                comparison: code.to_string(),
                grant: Grant {
                    computer: true,
                    browser: true,
                },
            },
            c.attest_prepared_credential(
                l.approval_target(&c.admin(), &(request())).unwrap(),
                CredentialRef(hash("token")),
                hash("token"),
                SealedCredentialRef(hash("sealed-ref")),
            )
            .unwrap(),
            3,
        )
        .unwrap();
    commit(l, c, &approve);
    p.device_id
}
fn auth(c: &EnrollmentControl, d: &DeviceId) -> DeviceSelfProof {
    c.attest_device(d.clone(), hash("spki"), hash("token"))
}
fn cas(
    c: &EnrollmentControl,
    d: &DeviceId,
    generation: &str,
    browser: Option<bool>,
) -> VerifiedSelfCas {
    c.attest_self_cas(
        &CapabilityPayload {
            device_id: d.clone(),
            fingerprint: hash("spki"),
            generation: generation.into(),
            enable_computer: None,
            enable_browser: browser,
        },
        hash("token"),
    )
    .unwrap()
}
#[test]
fn invite_join_exact_approval_and_same_credential_claim_confirm() {
    let (mut l, c) = setup();
    let p = payload();
    let invite = l
        .invite(&c.admin(), hash(&p.invitation), 60, None, 1)
        .unwrap();
    let joinproof = || {
        c.attest_join(
            &p,
            hash("spki"),
            request(),
            hash("claim"),
            OpaqueProfileRef(hash("profile")),
            pairing(),
        )
        .unwrap()
    };
    assert_eq!(l.join(joinproof(), 2).unwrap_err(), EnrollmentError::Busy);
    assert!(
        !invite
            .original_bytes()
            .windows(p.invitation.len())
            .any(|w| w == p.invitation.as_bytes())
    );
    commit(&mut l, &c, &invite);
    let proof = joinproof();
    let code = proof.facts.comparison.clone();
    let join = l.join(proof, 2).unwrap();
    commit(&mut l, &c, &join);
    assert_eq!(
        l.join(joinproof(), 3).unwrap_err(),
        EnrollmentError::Expired
    );
    assert_eq!(
        l.approve(
            &c.admin(),
            ApprovalRequest {
                request: request(),
                fingerprint: hash("spki"),
                comparison: ("WRONG-CODE").to_string(),
                grant: Grant {
                    computer: true,
                    browser: true
                }
            },
            c.attest_prepared_credential(
                l.approval_target(&c.admin(), &(request())).unwrap(),
                CredentialRef(hash("token")),
                hash("token"),
                SealedCredentialRef(hash("sealed-ref"))
            )
            .unwrap(),
            3
        )
        .unwrap_err(),
        EnrollmentError::Proof
    );
    let approved = l
        .approve(
            &c.admin(),
            ApprovalRequest {
                request: request(),
                fingerprint: hash("spki"),
                comparison: code.to_string(),
                grant: Grant {
                    computer: true,
                    browser: true,
                },
            },
            c.attest_prepared_credential(
                l.approval_target(&c.admin(), &(request())).unwrap(),
                CredentialRef(hash("token")),
                hash("token"),
                SealedCredentialRef(hash("sealed-ref")),
            )
            .unwrap(),
            3,
        )
        .unwrap();
    assert_eq!(
        l.self_device(&auth(&c, &p.device_id)).unwrap_err(),
        EnrollmentError::Busy
    );
    commit(&mut l, &c, &approved);
    let claim = c.attest_claim(request(), hash("claim"));
    let expected = ClaimView::Approved {
        credential: CredentialRef(hash("token")),
        sealed: SealedCredentialRef(hash("sealed-ref")),
        device: p.device_id.clone(),
        grant: Grant {
            computer: true,
            browser: true,
        },
    };
    assert_eq!(l.claim(&claim, 4).unwrap(), expected);
    assert_eq!(l.claim(&claim, 4).unwrap(), expected);
    let wrong = c
        .attest_confirmation(
            c.attest_claim(request(), hash("claim")),
            p.device_id.clone(),
            CredentialRef(hash("changed credential")),
        )
        .unwrap();
    assert_eq!(l.confirm(wrong, 4).unwrap_err(), EnrollmentError::Proof);
    let confirmation = || {
        c.attest_confirmation(
            c.attest_claim(request(), hash("claim")),
            p.device_id.clone(),
            CredentialRef(hash("token")),
        )
        .unwrap()
    };
    let confirm = l.confirm(confirmation(), 4).unwrap();
    assert_eq!(l.claim(&claim, 4).unwrap(), expected);
    commit(&mut l, &c, &confirm);
    assert_eq!(l.claim(&claim, 5).unwrap_err(), EnrollmentError::Expired);
    let retry = l.confirm(confirmation(), 5).unwrap();
    commit(&mut l, &c, &retry); // Lost confirm ACK uses same credential; no rotation.
    assert_eq!(
        l.self_device(&auth(&c, &p.device_id)).unwrap().credential,
        CredentialRef(hash("token"))
    );
}
#[test]
fn scoped_approval_bounds_and_ttl_are_fail_closed() {
    let (mut l, c) = setup();
    assert_eq!(
        l.invite(&c.admin(), hash("bad"), 59, None, 0).unwrap_err(),
        EnrollmentError::Invalid
    );
    let mut p = payload();
    p.browser_requested = Some(false);
    let mut scoped = pairing();
    scoped.window = Some(PairingWindowId::try_from("window-a").unwrap());
    let i = l
        .invite(&c.admin(), hash(&p.invitation), 60, Some(scoped.clone()), 0)
        .unwrap();
    commit(&mut l, &c, &i);
    let mismatch = c
        .attest_join(
            &p,
            hash("spki"),
            request(),
            hash("claim"),
            OpaqueProfileRef(hash("profile")),
            pairing(),
        )
        .unwrap();
    assert_eq!(l.join(mismatch, 1).unwrap_err(), EnrollmentError::Proof);
    let proof = c
        .attest_join(
            &p,
            hash("spki"),
            request(),
            hash("claim"),
            OpaqueProfileRef(hash("profile")),
            scoped,
        )
        .unwrap();
    let code = proof.facts.comparison.clone();
    let j = l.join(proof, 1).unwrap();
    commit(&mut l, &c, &j);
    assert_eq!(
        l.approve(
            &c.admin(),
            ApprovalRequest {
                request: request(),
                fingerprint: hash("spki"),
                comparison: code.to_string(),
                grant: Grant {
                    computer: false,
                    browser: true
                }
            },
            c.attest_prepared_credential(
                l.approval_target(&c.admin(), &(request())).unwrap(),
                CredentialRef(hash("t")),
                hash("t"),
                SealedCredentialRef(hash("s"))
            )
            .unwrap(),
            2
        )
        .unwrap_err(),
        EnrollmentError::Invalid
    );
    assert_eq!(
        l.approve(
            &c.admin(),
            ApprovalRequest {
                request: request(),
                fingerprint: hash("spki"),
                comparison: code.to_string(),
                grant: Grant {
                    computer: false,
                    browser: false
                }
            },
            c.attest_prepared_credential(
                l.approval_target(&c.admin(), &(request())).unwrap(),
                CredentialRef(hash("t")),
                hash("t"),
                SealedCredentialRef(hash("s"))
            )
            .unwrap(),
            900_001
        )
        .unwrap_err(),
        EnrollmentError::Expired
    );
}
#[test]
fn self_cas_admission_fence_and_retired_identity() {
    let (mut l, c) = setup();
    let d = approved(&mut l, &c);
    let lease = l
        .admit_connection(
            auth(&c, &d),
            Lane::Exec,
            ConnectionGeneration::try_from("connection-a").unwrap(),
        )
        .unwrap();
    assert_eq!(
        l.self_cas(
            cas(
                &c,
                &d,
                &l.self_device(&auth(&c, &d)).unwrap().generation,
                Some(false)
            ),
            4
        )
        .unwrap_err(),
        EnrollmentError::OfflineRequired
    );
    l.connection_ended(lease, true).unwrap();
    assert_eq!(
        l.self_cas(cas(&c, &d, "stale", Some(false)), 4)
            .unwrap_err(),
        EnrollmentError::Conflict
    );
    let intent = l
        .self_cas(
            cas(
                &c,
                &d,
                &l.self_device(&auth(&c, &d)).unwrap().generation,
                Some(false),
            ),
            4,
        )
        .unwrap();
    assert_eq!(
        l.admit_connection(
            auth(&c, &d),
            Lane::Exec,
            ConnectionGeneration::try_from("connection-b").unwrap()
        )
        .unwrap_err(),
        EnrollmentError::Busy
    );
    assert_eq!(
        l.self_device(&auth(&c, &d)).unwrap_err(),
        EnrollmentError::Busy
    );
    assert!(l.pending_intent().is_some()); // Ambiguous storage outcome leaves fence.
    let original = intent.original_bytes().to_vec();
    assert_eq!(
        hash(std::str::from_utf8(&original).unwrap()),
        intent.digest()
    );
    commit(&mut l, &c, &intent);
    assert!(
        l.self_device(&auth(&c, &d))
            .unwrap()
            .generation
            .starts_with("capability-")
    );
    let revoke = l.revoke(&c.admin(), &d, 5).unwrap();
    assert_eq!(
        l.self_device(&auth(&c, &d)).unwrap_err(),
        EnrollmentError::Busy
    );
    commit(&mut l, &c, &revoke);
    assert_eq!(
        l.self_device(&auth(&c, &d)).unwrap_err(),
        EnrollmentError::Proof
    );
    let mut p = payload();
    p.device_id = DeviceId::try_from("styx-new-id-same-key").unwrap();
    let invite = l
        .invite(&c.admin(), hash(&p.invitation), 60, None, 6)
        .unwrap();
    commit(&mut l, &c, &invite);
    let proof = c
        .attest_join(
            &p,
            hash("spki"),
            RequestId::try_from("1123456789abcdef0123456789abcdef").unwrap(),
            hash("claim2"),
            OpaqueProfileRef(hash("profile")),
            pairing(),
        )
        .unwrap();
    assert_eq!(l.join(proof, 7).unwrap_err(), EnrollmentError::Retired);
}
#[test]
fn foreign_control_cannot_admin_durable_abort_or_self_authenticate() {
    let (mut l, c) = setup();
    let (_, foreign) = setup();
    assert_eq!(
        l.invite(&foreign.admin(), hash("invite"), 60, None, 0)
            .unwrap_err(),
        EnrollmentError::Authority
    );
    let invite = l.invite(&c.admin(), hash("invite"), 60, None, 0).unwrap();
    assert_eq!(
        l.confirm_durable(foreign.attest_durable(&invite, hash("fake")))
            .unwrap_err(),
        EnrollmentError::Authority
    );
    assert_eq!(
        l.abort_proven_not_written(foreign.attest_not_written(&invite)),
        Err(EnrollmentError::Authority)
    );
    l.abort_proven_not_written(c.attest_not_written(&invite))
        .unwrap();
    assert!(l.pending_intent().is_none());
    let d = approved(&mut l, &c);
    assert_eq!(
        l.self_device(&auth(&foreign, &d)).unwrap_err(),
        EnrollmentError::Authority
    );
    let lease = l
        .admit_connection(
            auth(&c, &d),
            Lane::Exec,
            ConnectionGeneration::try_from("unknown-connection").unwrap(),
        )
        .unwrap();
    l.connection_ended(lease, false).unwrap();
    assert_eq!(
        l.self_cas(
            cas(
                &c,
                &d,
                &l.self_device(&auth(&c, &d)).unwrap().generation,
                Some(false)
            ),
            4
        )
        .unwrap_err(),
        EnrollmentError::OfflineRequired
    );
}

#[test]
fn generation_fence_is_local_and_metadata_has_explicit_bounded_collection() {
    let (mut l, c) = setup();
    let a = approved(&mut l, &c);
    let mut p = payload();
    p.invitation = "second invitation".into();
    p.device_id = DeviceId::try_from("styx-second").unwrap();
    let rid = RequestId::try_from("1123456789abcdef0123456789abcdef").unwrap();
    let inv = l
        .invite(&c.admin(), hash(&p.invitation), 60, None, 4)
        .unwrap();
    commit(&mut l, &c, &inv);
    let proof = c
        .attest_join(
            &p,
            hash("spki-b"),
            rid.clone(),
            hash("claim-b"),
            OpaqueProfileRef(hash("profile-b")),
            pairing(),
        )
        .unwrap();
    let code = proof.facts.comparison.clone();
    let j = l.join(proof, 5).unwrap();
    commit(&mut l, &c, &j);
    let ap = l
        .approve(
            &c.admin(),
            ApprovalRequest {
                request: rid.clone(),
                fingerprint: hash("spki-b"),
                comparison: code.to_string(),
                grant: Grant {
                    computer: true,
                    browser: true,
                },
            },
            c.attest_prepared_credential(
                l.approval_target(&c.admin(), &(rid.clone())).unwrap(),
                CredentialRef(hash("token-b")),
                hash("token-b"),
                SealedCredentialRef(hash("sealed-b")),
            )
            .unwrap(),
            6,
        )
        .unwrap();
    commit(&mut l, &c, &ap);
    let old = l
        .admit_connection(
            auth(&c, &a),
            Lane::Exec,
            ConnectionGeneration::try_from("old-exec").unwrap(),
        )
        .unwrap();
    let proof = c
        .attest_self_cas(
            &CapabilityPayload {
                device_id: a.clone(),
                fingerprint: hash("spki"),
                generation: l.self_device(&auth(&c, &a)).unwrap().generation.clone(),
                enable_computer: Some(false),
                enable_browser: None,
            },
            hash("token"),
        )
        .unwrap();
    let intent = l.self_cas(proof, 7).unwrap();
    assert_eq!(
        l.authorize_connection(&old).unwrap_err(),
        EnrollmentError::Busy
    );
    let b = l
        .admit_connection(
            c.attest_device(p.device_id.clone(), hash("spki-b"), hash("token-b")),
            Lane::Exec,
            ConnectionGeneration::try_from("other-exec").unwrap(),
        )
        .unwrap();
    assert!(
        l.authorize_connection(&b).is_ok(),
        "unrelated relay remains admitted during durable CAS"
    );
    commit(&mut l, &c, &intent);
    assert_eq!(
        l.authorize_connection(&old).unwrap_err(),
        EnrollmentError::Proof,
        "old generation cannot serve while disconnect is pending"
    );
    assert!(l.authorize_connection(&b).is_ok());
    l.connection_ended(old, true).unwrap();
    l.connection_ended(b, true).unwrap();
    let gc = l.collect_pending(&c.admin(), 1_200_007).unwrap();
    assert_eq!(
        l.pending.len(),
        2,
        "prepare GC does not free durable history"
    );
    commit(&mut l, &c, &gc);
    assert_eq!(l.pending.len(), 0);
    assert!(
        l.self_device(&auth(&c, &a)).is_ok(),
        "claim metadata expiry never revokes device credentials"
    );
}

#[test]
fn failed_expired_claim_and_join_advance_observed_clock_highwater() {
    let (mut l, c) = setup();
    let p = payload();
    let inv = l
        .invite(&c.admin(), hash(&p.invitation), 60, None, 1)
        .unwrap();
    commit(&mut l, &c, &inv);
    let proof = || {
        c.attest_join(
            &p,
            hash("spki"),
            request(),
            hash("claim"),
            OpaqueProfileRef(hash("profile")),
            pairing(),
        )
        .unwrap()
    };
    assert_eq!(
        l.join(proof(), 60_001).unwrap_err(),
        EnrollmentError::Expired
    );
    assert_eq!(
        l.join(proof(), 2).unwrap_err(),
        EnrollmentError::Clock,
        "TTL cannot revive after failed expired join"
    );
    let (mut l, c) = setup();
    let _ = approved(&mut l, &c);
    let claim = c.attest_claim(request(), hash("claim"));
    assert_eq!(
        l.claim(&claim, 1_200_003).unwrap_err(),
        EnrollmentError::Expired
    );
    assert_eq!(
        l.claim(&claim, 4).unwrap_err(),
        EnrollmentError::Clock,
        "read-only failed claim also advances highwater"
    );
}

#[test]
fn security_regression_prepared_credential_target_cannot_cross_same_brand_pending_requests() {
    let (mut l, c) = setup();
    let (_a, _code_a) = pending(&mut l, &c);
    let a_target = l.approval_target(&c.admin(), &request()).unwrap();
    let mut b = payload();
    b.invitation = "separate invitation b".into();
    b.device_id = DeviceId::try_from("styx-pending-b").unwrap();
    let bid = RequestId::try_from("2123456789abcdef0123456789abcdef").unwrap();
    let inv = l
        .invite(&c.admin(), hash(&b.invitation), 60, None, 3)
        .unwrap();
    commit(&mut l, &c, &inv);
    let proof = c
        .attest_join(
            &b,
            hash("spki-b"),
            bid.clone(),
            hash("claim-b"),
            OpaqueProfileRef(hash("profile-b")),
            pairing(),
        )
        .unwrap();
    let code_b = proof.facts.comparison.clone();
    let join = l.join(proof, 4).unwrap();
    commit(&mut l, &c, &join);
    let b_target = l.approval_target(&c.admin(), &bid).unwrap();
    assert_ne!(a_target, b_target);
    let before_a = l.pending.get(&request()).unwrap().clone();
    let before_b = l.pending.get(&bid).unwrap().clone();
    let before_revision = l.revision;
    let request_b = || ApprovalRequest {
        request: bid.clone(),
        fingerprint: hash("spki-b"),
        comparison: code_b.clone(),
        grant: Grant {
            computer: true,
            browser: true,
        },
    };
    let sealed_a = || {
        c.attest_prepared_credential(
            a_target.clone(),
            CredentialRef(hash("token-a")),
            hash("token-a"),
            SealedCredentialRef(hash("sealed-to-a")),
        )
        .unwrap()
    };
    assert_eq!(
        l.approve(&c.admin(), request_b(), sealed_a(), 5)
            .unwrap_err(),
        EnrollmentError::Proof
    );
    assert!(l.staged.is_none());
    assert!(l.devices.is_empty());
    assert_eq!(l.revision, before_revision);
    assert_eq!(l.pending.get(&request()).unwrap(), &before_a);
    assert_eq!(l.pending.get(&bid).unwrap(), &before_b);
    // The complete facts digest is checked as well as the visible tuple: stale
    // comparison/claim/pairing facts cannot be smuggled by matching public IDs.
    let mut stale = b_target.clone();
    stale.pending_facts_digest = hash("different original pending facts");
    let prepared = c
        .attest_prepared_credential(
            stale,
            CredentialRef(hash("token-b")),
            hash("token-b"),
            SealedCredentialRef(hash("sealed-to-b")),
        )
        .unwrap();
    assert_eq!(
        l.approve(&c.admin(), request_b(), prepared, 5).unwrap_err(),
        EnrollmentError::Proof
    );
    assert!(l.staged.is_none());
    assert!(l.devices.is_empty());
    assert_eq!(l.pending.get(&bid).unwrap(), &before_b);
    let matching = c
        .attest_prepared_credential(
            b_target.clone(),
            CredentialRef(hash("token-b")),
            hash("token-b"),
            SealedCredentialRef(hash("sealed-to-b")),
        )
        .unwrap();
    let intent = l.approve(&c.admin(), request_b(), matching, 5).unwrap();
    let Mutation::Approve { target, .. } = &intent.body().mutation else {
        panic!("approval intent")
    };
    assert_eq!(
        target, &b_target,
        "durable receipt must cover exact same target"
    );
    assert!(l.devices.is_empty());
    commit(&mut l, &c, &intent);
    assert_eq!(
        l.devices.get(&b.device_id).unwrap().credential,
        CredentialRef(hash("token-b"))
    );
    assert_eq!(
        l.pending.get(&request()).unwrap(),
        &before_a,
        "A request was never consumed by B preparation"
    );
}

#[test]
fn security_regression_core_allocates_generation_and_rechecks_lane_grant() {
    let (mut l, c) = setup();
    let d = approved(&mut l, &c);
    let original = l.self_device(&auth(&c, &d)).unwrap().generation.clone();
    let old = l
        .admit_connection(
            auth(&c, &d),
            Lane::Computer,
            ConnectionGeneration::try_from("retained-computer-socket").unwrap(),
        )
        .unwrap();
    assert!(l.authorize_connection(&old).is_ok());
    let make = |generation: &str, enabled: bool| {
        c.attest_self_cas(
            &CapabilityPayload {
                device_id: d.clone(),
                fingerprint: hash("spki"),
                generation: generation.into(),
                enable_computer: Some(enabled),
                enable_browser: None,
            },
            hash("token"),
        )
        .unwrap()
    };
    let disabled = l.self_cas(make(&original, false), 4).unwrap();
    let first_sequence = disabled.body().sequence;
    commit(&mut l, &c, &disabled);
    let second = l.self_device(&auth(&c, &d)).unwrap().generation.clone();
    assert_ne!(second, original);
    assert!(!l.self_device(&auth(&c, &d)).unwrap().grant.computer);
    assert_eq!(
        l.authorize_connection(&old).unwrap_err(),
        EnrollmentError::Proof,
        "current disabled lane refuses before queued disconnect"
    );
    assert_eq!(
        l.admit_connection(
            auth(&c, &d),
            Lane::Computer,
            ConnectionGeneration::try_from("disabled-lane").unwrap()
        )
        .unwrap_err(),
        EnrollmentError::Proof
    );
    assert_eq!(
        l.self_cas(make(&original, true), 5).unwrap_err(),
        EnrollmentError::Conflict,
        "old expected generation is stale, never a desired new generation"
    );
    let reenabled = l.self_cas(make(&second, true), 5).unwrap();
    assert!(reenabled.body().sequence > first_sequence);
    assert_ne!(reenabled.body().transaction, disabled.body().transaction);
    commit(&mut l, &c, &reenabled);
    let third = l.self_device(&auth(&c, &d)).unwrap().generation.clone();
    assert_ne!(third, original);
    assert_ne!(third, second);
    assert!(l.self_device(&auth(&c, &d)).unwrap().grant.computer);
    assert_eq!(
        l.authorize_connection(&old).unwrap_err(),
        EnrollmentError::Proof,
        "even re-enabled capability cannot revive retained old-generation lease"
    );
    l.connection_ended(old, true).unwrap();
    let current = l
        .admit_connection(
            auth(&c, &d),
            Lane::Computer,
            ConnectionGeneration::try_from("current-computer-socket").unwrap(),
        )
        .unwrap();
    assert!(l.authorize_connection(&current).is_ok());
    // Counter/epoch domains are explicit inputs to the mature Serde codec.
    assert_ne!(
        intent_contract::allocated_identity(
            "styx-enrollment-transaction-v1",
            &GatewayEpoch::try_from("other-epoch").unwrap(),
            first_sequence,
            None
        )
        .unwrap(),
        intent_contract::allocated_identity(
            "styx-enrollment-transaction-v1",
            &l.epoch,
            first_sequence,
            None
        )
        .unwrap()
    );
    let revoke = l.revoke(&c.admin(), &d, 6).unwrap();
    let allocated_sequence = revoke.body().sequence;
    let allocated_id = revoke.body().transaction.clone();
    l.abort_proven_not_written(c.attest_not_written(&revoke))
        .unwrap();
    let retry = l.revoke(&c.admin(), &d, 6).unwrap();
    assert!(retry.body().sequence > allocated_sequence);
    assert_ne!(
        retry.body().transaction,
        allocated_id,
        "proven aborted mutations still consume identity highwater"
    );
}

#[test]
fn security_regression_retirement_capacity_reserved_before_approval() {
    let (mut l, c) = EnrollmentLedger::new_owned(
        GatewayEpoch::try_from("capacity-gateway").unwrap(),
        Limits {
            devices: 2,
            retired: 1,
            ..Limits::default()
        },
    )
    .unwrap();
    let a = approved(&mut l, &c);
    let mut b = payload();
    b.invitation = "capacity-second-invitation".into();
    b.device_id = DeviceId::try_from("styx-capacity-b").unwrap();
    let bid = RequestId::try_from("3123456789abcdef0123456789abcdef").unwrap();
    let invite = l
        .invite(&c.admin(), hash(&b.invitation), 60, None, 4)
        .unwrap();
    commit(&mut l, &c, &invite);
    let proof = c
        .attest_join(
            &b,
            hash("capacity-spki-b"),
            bid.clone(),
            hash("claim-b"),
            OpaqueProfileRef(hash("profile-b")),
            pairing(),
        )
        .unwrap();
    let code = proof.facts.comparison.clone();
    let join = l.join(proof, 5).unwrap();
    commit(&mut l, &c, &join);
    let target = l.approval_target(&c.admin(), &bid).unwrap();
    let prepared = || {
        c.attest_prepared_credential(
            target.clone(),
            CredentialRef(hash("token-b")),
            hash("token-b"),
            SealedCredentialRef(hash("sealed-b")),
        )
        .unwrap()
    };
    let request = || ApprovalRequest {
        request: bid.clone(),
        fingerprint: hash("capacity-spki-b"),
        comparison: code.clone(),
        grant: Grant {
            computer: true,
            browser: true,
        },
    };
    let pending_before = l.pending.get(&bid).unwrap().clone();
    assert_eq!(
        l.approve(&c.admin(), request(), prepared(), 6).unwrap_err(),
        EnrollmentError::Capacity,
        "B cannot consume the only slot already reserved for A's future revocation"
    );
    assert!(l.staged.is_none());
    assert_eq!(l.devices.len(), 1);
    assert_eq!(l.pending.get(&bid).unwrap(), &pending_before);
    let revoke = l.revoke(&c.admin(), &a, 6).unwrap();
    commit(&mut l, &c, &revoke);
    assert_eq!(l.retired, vec![hash("spki")]);
    assert_eq!(
        l.approve(&c.admin(), request(), prepared(), 7).unwrap_err(),
        EnrollmentError::Capacity,
        "committed tombstone is not evicted to publish B"
    );
    assert!(l.staged.is_none());
    assert_eq!(l.pending.get(&bid).unwrap(), &pending_before);
}

mod independent_review_cases {
    use super::*;

    #[test]
    fn credential_target_each_field_and_core_material_closure_are_independent() {
        let (mut ledger, control) = setup();
        let payload = payload();
        let invitation = ledger
            .invite(&control.admin(), hash(&payload.invitation), 60, None, 1)
            .unwrap();
        assert!(invitation.body().required_materials.is_empty());
        commit(&mut ledger, &control, &invitation);
        let proof = control
            .attest_join(
                &payload,
                hash("spki"),
                request(),
                hash("claim"),
                OpaqueProfileRef(hash("profile")),
                pairing(),
            )
            .unwrap();
        let comparison = proof.facts.comparison.clone();
        let join = ledger.join(proof, 2).unwrap();
        let profile = MaterialRef {
            kind: MaterialKind::Profile,
            digest: hash("profile"),
        };
        let token = MaterialRef {
            kind: MaterialKind::Token,
            digest: hash("token"),
        };
        let sealed = MaterialRef {
            kind: MaterialKind::Sealed,
            digest: hash("sealed-ref"),
        };
        assert_eq!(join.body().required_materials, vec![profile.clone()]);
        commit(&mut ledger, &control, &join);
        let target = ledger
            .approval_target(&control.admin(), &request())
            .unwrap();
        let before = ledger.pending.get(&request()).unwrap().clone();
        let before_sequence = ledger.sequence;
        let before_revision = ledger.revision;
        let approval = || ApprovalRequest {
            request: request(),
            fingerprint: hash("spki"),
            comparison: comparison.clone(),
            grant: Grant {
                computer: true,
                browser: true,
            },
        };
        for field in 0..5 {
            let mut changed = target.clone();
            match field {
                0 => {
                    changed.request =
                        RequestId::try_from("4123456789abcdef0123456789abcdef").unwrap()
                }
                1 => changed.device = DeviceId::try_from("other-original-device").unwrap(),
                2 => changed.fingerprint = hash("another-original-key"),
                3 => changed.profile = OpaqueProfileRef(hash("another-profile")),
                _ => changed.pending_facts_digest = hash("another-join-facts-digest"),
            }
            let prepared = control
                .attest_prepared_credential(
                    changed,
                    CredentialRef(hash("token")),
                    hash("token"),
                    SealedCredentialRef(hash("sealed-ref")),
                )
                .unwrap();
            assert_eq!(
                ledger
                    .approve(&control.admin(), approval(), prepared, 3)
                    .unwrap_err(),
                EnrollmentError::Proof
            );
            assert!(ledger.pending_intent().is_none());
            assert_eq!(ledger.sequence, before_sequence);
            assert_eq!(ledger.revision, before_revision);
            assert_eq!(ledger.pending.get(&request()).unwrap(), &before);
            assert!(ledger.devices.is_empty());
        }
        let prepared = control
            .attest_prepared_credential(
                target.clone(),
                CredentialRef(hash("token")),
                hash("token"),
                SealedCredentialRef(hash("sealed-ref")),
            )
            .unwrap();
        let approve = ledger
            .approve(&control.admin(), approval(), prepared, 3)
            .unwrap();
        assert_eq!(
            approve.body().required_materials,
            vec![profile.clone(), token.clone(), sealed]
        );
        assert_eq!(
            approve.digest(),
            Sha256Digest::of_bytes(approve.original_bytes())
        );
        assert_eq!(
            intent_contract::decode(approve.original_bytes()).unwrap(),
            *approve.body()
        );
        let original = approve.original_bytes().to_vec();
        // Malformed/unknown data stays data, and codec diagnostics cannot echo it.
        let marker = "UNTRUSTED_SECRET_MUST_NOT_APPEAR_IN_ERROR";
        let mut invalid = original[..original.len() - 1].to_vec();
        invalid.extend_from_slice(format!(",\"unknown\":\"{marker}\"}}").as_bytes());
        let error = intent_contract::decode(&invalid).unwrap_err();
        assert!(!error.to_string().contains(marker));
        assert!(!format!("{error:?}").contains(marker));
        assert_eq!(approve.original_bytes(), original);
        assert!(ledger.devices.is_empty());
        commit(&mut ledger, &control, &approve);
        let confirmation = control
            .attest_confirmation(
                control.attest_claim(request(), hash("claim")),
                payload.device_id.clone(),
                CredentialRef(hash("token")),
            )
            .unwrap();
        let confirm = ledger.confirm(confirmation, 4).unwrap();
        assert_eq!(
            confirm.body().required_materials,
            vec![profile.clone(), token.clone()]
        );
        commit(&mut ledger, &control, &confirm);
        let generation = ledger
            .self_device(&auth(&control, &payload.device_id))
            .unwrap()
            .generation
            .clone();
        let proof = control
            .attest_self_cas(
                &CapabilityPayload {
                    device_id: payload.device_id.clone(),
                    fingerprint: hash("spki"),
                    generation,
                    enable_computer: Some(false),
                    enable_browser: None,
                },
                hash("token"),
            )
            .unwrap();
        let cas = ledger.self_cas(proof, 5).unwrap();
        assert_eq!(cas.body().required_materials, vec![profile, token]);
        assert_eq!(
            ledger
                .self_device(&auth(&control, &payload.device_id))
                .unwrap_err(),
            EnrollmentError::Busy
        );
        commit(&mut ledger, &control, &cas);
        assert_eq!(
            ledger
                .self_device(&auth(&control, &payload.device_id))
                .unwrap()
                .credential,
            CredentialRef(hash("token"))
        );
        let revoke = ledger
            .revoke(&control.admin(), &payload.device_id, 6)
            .unwrap();
        assert!(revoke.body().required_materials.is_empty());
        commit(&mut ledger, &control, &revoke);
        assert_eq!(
            ledger
                .self_device(&auth(&control, &payload.device_id))
                .unwrap_err(),
            EnrollmentError::Proof
        );
    }

    #[test]
    fn frame_grant_fence_is_independent_of_capability_generation_comparison() {
        let (mut ledger, control) = setup();
        let device = approved(&mut ledger, &control);
        let computer = ledger
            .admit_connection(
                auth(&control, &device),
                Lane::Computer,
                ConnectionGeneration::try_from("computer-current").unwrap(),
            )
            .unwrap();
        let browser = ledger
            .admit_connection(
                auth(&control, &device),
                Lane::Browser,
                ConnectionGeneration::try_from("browser-current").unwrap(),
            )
            .unwrap();
        let exec = ledger
            .admit_connection(
                auth(&control, &device),
                Lane::Exec,
                ConnectionGeneration::try_from("exec-current").unwrap(),
            )
            .unwrap();
        let original_generation = ledger.devices.get(&device).unwrap().generation.clone();
        // Explicit test-only inconsistent-state injection isolates the grant
        // predicate. Normal production CAS also changes generation; that must
        // not allow a missing grant check to hide behind generation rejection.
        ledger.devices.get_mut(&device).unwrap().grant.computer = false;
        assert_eq!(
            ledger.authorize_connection(&computer).unwrap_err(),
            EnrollmentError::Proof
        );
        assert!(ledger.authorize_connection(&browser).is_ok());
        assert!(ledger.authorize_connection(&exec).is_ok());
        ledger.devices.get_mut(&device).unwrap().grant.computer = true;
        ledger.devices.get_mut(&device).unwrap().grant.browser = false;
        assert_eq!(
            ledger.authorize_connection(&browser).unwrap_err(),
            EnrollmentError::Proof
        );
        assert!(ledger.authorize_connection(&computer).is_ok());
        assert!(ledger.authorize_connection(&exec).is_ok());
        assert_eq!(
            ledger.devices.get(&device).unwrap().generation,
            original_generation
        );
    }

    #[test]
    fn every_published_key_remains_revocable_at_the_retirement_capacity_boundary() {
        let (mut ledger, control) = EnrollmentLedger::new_owned(
            GatewayEpoch::try_from("retire-two").unwrap(),
            Limits {
                devices: 2,
                retired: 2,
                ..Limits::default()
            },
        )
        .unwrap();
        let first = approved(&mut ledger, &control);
        let mut payload = payload();
        payload.invitation = "separate bounded invitation".into();
        payload.device_id = DeviceId::try_from("bounded-second-device").unwrap();
        let request = RequestId::try_from("5123456789abcdef0123456789abcdef").unwrap();
        let invite = ledger
            .invite(&control.admin(), hash(&payload.invitation), 60, None, 4)
            .unwrap();
        commit(&mut ledger, &control, &invite);
        let proof = control
            .attest_join(
                &payload,
                hash("second-spki"),
                request.clone(),
                hash("second-claim"),
                OpaqueProfileRef(hash("second-profile")),
                pairing(),
            )
            .unwrap();
        let comparison = proof.facts.comparison.clone();
        let join = ledger.join(proof, 5).unwrap();
        commit(&mut ledger, &control, &join);
        let prepared = control
            .attest_prepared_credential(
                ledger.approval_target(&control.admin(), &request).unwrap(),
                CredentialRef(hash("second-token")),
                hash("second-token"),
                SealedCredentialRef(hash("second-sealed")),
            )
            .unwrap();
        let approve = ledger
            .approve(
                &control.admin(),
                ApprovalRequest {
                    request,
                    fingerprint: hash("second-spki"),
                    comparison,
                    grant: Grant {
                        computer: true,
                        browser: true,
                    },
                },
                prepared,
                6,
            )
            .unwrap();
        commit(&mut ledger, &control, &approve);
        assert_eq!(ledger.devices.len(), 2);
        assert!(ledger.retired.is_empty());
        for (at, device) in [(7, first), (8, payload.device_id)] {
            let revoke = ledger.revoke(&control.admin(), &device, at).unwrap();
            commit(&mut ledger, &control, &revoke);
            assert!(ledger.devices.get(&device).unwrap().revoked);
        }
        assert_eq!(ledger.retired.len(), 2);
        assert_eq!(
            ledger.devices.len(),
            2,
            "revoked identities were retained, not evicted for capacity"
        );
    }
}
