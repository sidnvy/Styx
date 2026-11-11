//! Synthetic Core facts and real private journal, never real identity or TLS.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
mod linux {
    use super::super::*;
    use crate::{
        enrollment::{EnrollmentBootstrap, recovery},
        store::{
            PrivateRoot,
            enrollment::{EnrollmentJournal, JournalBudget, MaterialKind},
        },
    };
    use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};
    use styx_contracts::{
        enrollment::{OpaqueProfileRef, PendingStatus},
        identity::{GatewayEpoch, Sha256Digest},
        legacy::JoinPayload,
    };
    use styx_core::enrollment::{
        EnrollmentControl, EnrollmentLedger, Limits, PendingIntent, RejectionRequest,
    };

    fn hash(s: &str) -> Sha256Digest {
        Sha256Digest::of_bytes(s.as_bytes())
    }
    fn commit(
        j: &mut EnrollmentJournal<'_>,
        l: &mut EnrollmentLedger,
        c: &EnrollmentControl,
        intent: &PendingIntent,
        head: &mut Option<Sha256Digest>,
    ) {
        let prepared = j.prepare(intent.original_bytes(), *head).unwrap();
        let receipt = j.commit(&prepared).unwrap().digest().unwrap();
        l.confirm_durable(c.attest_durable(intent, receipt))
            .unwrap();
        *head = Some(receipt);
    }
    fn fixture(
        age_ms: u64,
        approve_first: bool,
    ) -> (PathBuf, Vec<RejectionRequest>, PairingContext, Vec<u64>) {
        let path = std::env::temp_dir().join(format!("styx-retirement-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let root = PrivateRoot::open(&path).unwrap();
        let mut writer = root.try_configuration_writer().unwrap();
        let mut j = EnrollmentJournal::open(&root, &mut writer, JournalBudget::default()).unwrap();
        let time = now().unwrap() - age_ms;
        j.record_time_floor(time).unwrap();
        let recovered = recovery::recover_journal(
            &mut j,
            GatewayEpoch::try_from("retire-fixture").unwrap(),
            Limits::default(),
            time,
        )
        .unwrap();
        let mut ledger = recovered.ledger;
        let control = recovered.control;
        let mut head = None;
        let pairing = PairingContext {
            origin: "https://fixture.invalid".into(),
            leaf: hash("old-leaf"),
            ingress_generation: "fixture-generation".try_into().unwrap(),
            window: None,
        };
        let mut result = Vec::new();
        let mut expiries = Vec::new();
        for i in 0..2 {
            let invitation = format!("synthetic-invitation-{i}-0123456789");
            let at = time + i as u64 * 2;
            j.record_time_floor(at).unwrap();
            let invite = ledger
                .invite(&control.admin(), hash(&invitation), 60, None, at)
                .unwrap();
            commit(&mut j, &mut ledger, &control, &invite, &mut head);
            let payload = JoinPayload {
                invitation,
                device_id: format!("styx-fixture-{i}").try_into().unwrap(),
                label: "Synthetic".into(),
                platform: "linux".into(),
                cwd: "/tmp".into(),
                shell: "/bin/sh".into(),
                computer_requested: false,
                browser_requested: Some(false),
                public_key_pem: "synthetic-key-not-crypto-evidence".into(),
            };
            let profile = j
                .put_material(
                    MaterialKind::Profile,
                    format!("original-profile-{i}").as_bytes(),
                )
                .unwrap();
            let fingerprint = hash(&format!("fingerprint-{i}"));
            let request = format!("{:032x}", i + 1).try_into().unwrap();
            let proof = control
                .attest_join(
                    &payload,
                    fingerprint,
                    request,
                    hash(&format!("claim-{i}")),
                    OpaqueProfileRef(profile.digest),
                    pairing.clone(),
                )
                .unwrap();
            j.record_time_floor(at + 1).unwrap();
            let joined = ledger.join(proof, at + 1).unwrap();
            commit(&mut j, &mut ledger, &control, &joined, &mut head);
            let row = ledger
                .recovery_pending(&control)
                .unwrap()
                .into_iter()
                .find(|p| p.facts.device == payload.device_id)
                .unwrap();
            expiries.push(row.expires);
            result.push(RejectionRequest {
                request: row.facts.request,
                device: row.facts.device,
                fingerprint: row.facts.fingerprint,
                comparison: row.facts.comparison,
            });
        }
        if approve_first {
            use styx_contracts::enrollment::{CredentialRef, Grant, SealedCredentialRef};
            use styx_core::enrollment::ApprovalRequest;
            let selected = &result[0];
            let token = j
                .put_material(MaterialKind::Token, b"synthetic-token-not-a-credential")
                .unwrap();
            let sealed = j
                .put_material(MaterialKind::Sealed, b"synthetic-sealed-value")
                .unwrap();
            let prepared = control
                .attest_prepared_credential(
                    ledger
                        .approval_target(&control.admin(), &selected.request)
                        .unwrap(),
                    CredentialRef(token.digest),
                    token.digest,
                    SealedCredentialRef(sealed.digest),
                )
                .unwrap();
            let at = time + 5;
            j.record_time_floor(at).unwrap();
            let approval = ledger
                .approve(
                    &control.admin(),
                    ApprovalRequest {
                        request: selected.request.clone(),
                        fingerprint: selected.fingerprint,
                        comparison: selected.comparison.clone(),
                        grant: Grant {
                            computer: false,
                            browser: false,
                        },
                    },
                    prepared,
                    at,
                )
                .unwrap();
            commit(&mut j, &mut ledger, &control, &approval, &mut head);
        }
        drop(j);
        drop(writer);
        drop(root);
        (path, result, pairing, expiries)
    }
    #[test]
    fn expired_target_without_reader7_is_refused_and_all_pending_preserved() {
        let (path, mut selections, context, expiries) = fixture(1_000_000, false);
        let target = selections.remove(0);
        let other = selections.remove(0);
        let root = PrivateRoot::open(&path).unwrap();
        let mut writer = root.try_configuration_writer().unwrap();
        let bootstrap =
            EnrollmentBootstrap::recover_existing(&root, &mut writer, Limits::default()).unwrap();
        let mut wrong = context.clone();
        wrong.leaf = hash("different-leaf");
        assert_eq!(
            bootstrap
                .retirement_preflight(&target, &wrong, expiries[0])
                .unwrap_err()
                .category(),
            "retirement_target_mismatch"
        );
        assert_eq!(
            bootstrap
                .retirement_preflight(&target, &context, expiries[0])
                .unwrap(),
            RetirementOutcome::Expired
        );
        let error = bootstrap
            .abandon_pending_for_retirement(target, &context, expiries[0])
            .unwrap_err();
        assert_eq!(error.category(), "store_unproven");
        let recovered =
            EnrollmentBootstrap::recover_existing(&root, &mut writer, Limits::default()).unwrap();
        let pending = recovered
            .ledger
            .recovery_pending(&recovered.control)
            .unwrap();
        assert_eq!(pending.len(), 2);
        assert!(
            pending
                .iter()
                .any(|p| p.facts.request == other.request && p.status == PendingStatus::Pending)
        );
        drop(recovered);
        drop(writer);
        drop(root);
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn mismatched_identity_and_clock_rollback_are_refused_before_settlement() {
        let (path, mut selections, context, expiries) = fixture(10_000, false);
        let mut target = selections.remove(0);
        let root = PrivateRoot::open(&path).unwrap();
        let mut writer = root.try_configuration_writer().unwrap();
        let bootstrap =
            EnrollmentBootstrap::recover_existing(&root, &mut writer, Limits::default()).unwrap();
        assert_eq!(
            bootstrap
                .retirement_preflight(&target, &context, expiries[0])
                .unwrap(),
            RetirementOutcome::Rejected
        );
        assert_eq!(
            bootstrap
                .retirement_preflight_at(
                    &target,
                    &context,
                    expiries[0],
                    bootstrap.facts.clock_floor - 1
                )
                .unwrap_err()
                .category(),
            "clock_rollback"
        );
        for wrong_expiry in [0, expiries[0] + 1] {
            assert_eq!(
                bootstrap
                    .retirement_preflight(&target, &context, wrong_expiry)
                    .unwrap_err()
                    .category(),
                "retirement_target_mismatch"
            );
        }
        target.fingerprint = hash("foreign");
        assert_eq!(
            bootstrap
                .retirement_preflight(&target, &context, expiries[0])
                .unwrap_err()
                .category(),
            "retirement_target_mismatch"
        );
        assert!(bootstrap.ledger.pending_intent().is_none());
        assert_eq!(
            bootstrap
                .ledger
                .recovery_pending(&bootstrap.control)
                .unwrap()
                .len(),
            2
        );
        drop(bootstrap);
        drop(writer);
        drop(root);
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn approved_target_cannot_be_abandoned() {
        let (path, mut selections, context, expiries) = fixture(10_000, true);
        let target = selections.remove(0);
        let root = PrivateRoot::open(&path).unwrap();
        let mut writer = root.try_configuration_writer().unwrap();
        let bootstrap =
            EnrollmentBootstrap::recover_existing(&root, &mut writer, Limits::default()).unwrap();
        assert_eq!(
            bootstrap
                .retirement_preflight(&target, &context, expiries[0])
                .unwrap_err()
                .category(),
            "retirement_target_mismatch"
        );
        assert!(bootstrap.ledger.pending_intent().is_none());
        drop(bootstrap);
        drop(writer);
        drop(root);
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn durable_unresolved_intent_blocks_retirement_without_dispatch() {
        let (path, mut selections, context, expiries) = fixture(10_000, false);
        let target = selections.remove(0);
        let root = PrivateRoot::open(&path).unwrap();
        let mut writer = root.try_configuration_writer().unwrap();
        let mut bootstrap =
            EnrollmentBootstrap::recover_existing(&root, &mut writer, Limits::default()).unwrap();
        let at = now().unwrap();
        bootstrap.journal.record_time_floor(at).unwrap();
        let intent = bootstrap
            .ledger
            .close_window(&bootstrap.control.admin(), None, at)
            .unwrap();
        bootstrap
            .journal
            .prepare(intent.original_bytes(), bootstrap.facts.head)
            .unwrap();
        drop(bootstrap);
        let recovered =
            EnrollmentBootstrap::recover_existing(&root, &mut writer, Limits::default()).unwrap();
        assert!(recovered.diagnostics().unwrap().unresolved);
        assert_eq!(
            recovered
                .retirement_preflight(&target, &context, expiries[0])
                .unwrap_err()
                .category(),
            "retirement_unresolved"
        );
        assert_eq!(
            recovered.ledger.pending_intent().unwrap().digest(),
            intent.digest()
        );
        drop(recovered);
        drop(writer);
        drop(root);
        fs::remove_dir_all(path).unwrap();
    }
    /// Real signed reader7 Gateway and typed original Host proof; the sole
    /// synthetic element is the future clock passed to this private method.
    #[tokio::test]
    #[ignore = "requires loopback, new CLI and explicit signed reader7 payload/publisher/pin"]
    async fn signed_reader7_expired_pending_only_advances_durable_floor() {
        use crate::management::{
            native_join, setup_pending_restart_reference_tests::fresh_signed_pending_fixture,
        };
        use std::collections::BTreeMap;
        let f = fresh_signed_pending_fixture().await;
        let host_path = f.state.join("host");
        let host_root = PrivateRoot::open(&host_path).unwrap();
        let _host_execution = host_root.try_execution_lease().unwrap();
        let host_writer = host_root.try_configuration_writer().unwrap();
        let proof = native_join::retirement_host_preflight(&host_path, host_root, host_writer)
            .expect("authenticated original Host facts");
        let expires = proof.expires_at;
        assert!(expires > now().unwrap());
        let gateway_path = f.state.join("gateway");
        let gateway_root = PrivateRoot::open(&gateway_path).unwrap();
        let _gateway_execution = gateway_root.try_execution_lease().unwrap();
        let mut gateway_writer = gateway_root.try_configuration_writer().unwrap();
        proof
            .validate_gateway_ca(&fs::read(gateway_path.join("gateway-ca.pem")).unwrap())
            .unwrap();
        EnrollmentBootstrap::validate_retirement_reader(&gateway_root, &mut gateway_writer)
            .unwrap();
        let dir = gateway_path.join(".styx-enrollment-journal-v1");
        let records = |path: &std::path::Path| -> BTreeMap<String, Vec<u8>> {
            fs::read_dir(path)
                .unwrap()
                .map(|entry| entry.unwrap())
                .filter_map(|entry| {
                    let name = entry.file_name().into_string().unwrap();
                    if name == "clock.floor" {
                        return None;
                    }
                    assert!(entry.file_type().unwrap().is_file());
                    Some((name, fs::read(entry.path()).unwrap()))
                })
                .collect()
        };
        let before = records(&dir);
        let bootstrap = EnrollmentBootstrap::recover_existing_for_retirement(
            &gateway_root,
            &mut gateway_writer,
            Limits::default(),
        )
        .unwrap();
        let pending_before = bootstrap
            .ledger
            .recovery_pending(&bootstrap.control)
            .unwrap();
        let original = pending_before
            .iter()
            .find(|p| p.facts.request == proof.selection.request)
            .unwrap();
        assert_eq!(original.expires, expires);
        assert_eq!(original.facts.pairing, proof.pairing);
        assert_eq!(original.status, PendingStatus::Pending);
        let selection = RejectionRequest {
            request: proof.selection.request.clone(),
            device: proof.selection.device.clone(),
            fingerprint: proof.selection.fingerprint,
            comparison: proof.selection.comparison.clone(),
        };
        let receipt = bootstrap
            .abandon_pending_at(selection, &proof.pairing, expires, expires)
            .unwrap();
        assert_eq!(receipt.outcome, RetirementOutcome::Expired);
        assert!(receipt.intent_digest.is_none() && receipt.durable_receipt.is_none());
        assert!(receipt.durable_clock_floor >= expires);
        let floor: [u8; 8] = fs::read(dir.join("clock.floor"))
            .unwrap()
            .try_into()
            .unwrap();
        assert!(u64::from_be_bytes(floor) >= expires);
        assert_eq!(
            records(&dir),
            before,
            "all pending, materials, and other durable records remain byte-exact"
        );
        proof.validate().unwrap();
        // Do not reopen this synthetic future-clock fixture: current wall clock
        // is intentionally behind its durable floor and must be refused.
    }
}
