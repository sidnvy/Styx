//! Actual owned-file boot recovery with synthetic historical profile/clock
//! evidence. This is not original Gateway settlement, crypto enrollment, or C07
//! migration publication acceptance.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
mod linux {
    use super::super::*;
    use crate::store::{
        PrivateRoot, RootIdentity,
        enrollment::{JournalBudget, OwnedEnrollmentJournal},
    };
    use std::{fs, os::unix::fs::PermissionsExt, path::Path};
    use styx_contracts::{
        enrollment::*,
        historical_enrollment::{
            self as historical_contract, HistoricalEnrollmentBaseline, HistoricalRevoked,
            HistoricalTokenBinding, SourceRoot,
        },
    };

    fn id<T: TryFrom<&'static str>>(s: &'static str) -> T
    where
        T::Error: std::fmt::Debug,
    {
        T::try_from(s).unwrap()
    }
    fn child(parent: &Path) -> std::path::PathBuf {
        let p = parent.join(uuid::Uuid::new_v4().to_string());
        fs::create_dir(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        p
    }
    fn body(
        journal: &mut EnrollmentJournal<'_>,
        root: &PrivateRoot,
        include_devices: bool,
    ) -> HistoricalEnrollmentBaseline {
        let (device, inode, uid) = match root.identity() {
            RootIdentity::Linux { device, inode, uid } => (device, inode, uid),
        };
        let mut b = HistoricalEnrollmentBaseline {
            schema: 1,
            migration: id("historical-boot"),
            gateway_epoch: id("old-gateway"),
            sequence: 1,
            expected_revision: 0,
            prepared_at: 100,
            source_bindings_sha256: Sha256Digest::of_bytes(
                b"synthetic original bindings, not physical settlement",
            ),
            source_root: SourceRoot::Linux { device, inode, uid },
            enrollment_root: SourceRoot::Linux { device, inode, uid },
            journal_root: None,
            devices: vec![],
            revoked: vec![],
            default_device: None,
            token_bindings: vec![],
            required_materials: vec![],
        };
        if include_devices {
            // Deliberately synthetic public profiles: recovery restores references;
            // EnrollmentService separately validates real RSA/SPKI profile bytes.
            let profile = journal
                .put_material(MaterialKind::Profile, b"active-profile-fixture")
                .unwrap();
            let revoked_profile = journal
                .put_material(MaterialKind::Profile, b"revoked-profile-fixture")
                .unwrap();
            let raw = journal
                .put_material(MaterialKind::Token, b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n")
                .unwrap();
            let normalized = journal
                .put_material(MaterialKind::Token, b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                .unwrap();
            let active = Device {
                id: id("active"),
                fingerprint: Sha256Digest::of_bytes(b"active-spki"),
                grant: Grant {
                    computer: true,
                    browser: false,
                },
                generation: "original-gen".into(),
                credential: CredentialRef(normalized.digest),
                credential_hash: normalized.digest,
                profile: OpaqueProfileRef(profile.digest),
                revoked: false,
            };
            b.default_device = Some(active.id.clone());
            b.token_bindings.push(HistoricalTokenBinding {
                device: active.id.clone(),
                original_relative_path: "gateway/enrollment/tokens/active.token".into(),
                raw_material: raw.clone(),
                normalized_material: normalized.clone(),
            });
            b.devices.push(active);
            b.revoked.push(HistoricalRevoked {
                id: id("revoked"),
                fingerprint: Sha256Digest::of_bytes(b"revoked-spki"),
                grant: Grant {
                    computer: true,
                    browser: true,
                },
                generation: "retired-gen".into(),
                profile: OpaqueProfileRef(revoked_profile.digest),
            });
            b.required_materials = vec![profile, revoked_profile, raw, normalized];
            b.required_materials.sort_by_key(|r| {
                (
                    match r.kind {
                        MaterialKind::Profile => "profile",
                        MaterialKind::Token => "token",
                        MaterialKind::Sealed => "sealed",
                    },
                    r.digest.to_hex(),
                )
            });
        }
        b
    }
    fn inventory(j: &EnrollmentJournal<'_>) -> BTreeMap<String, Vec<u8>> {
        j.scan()
            .unwrap()
            .files
            .into_iter()
            .map(|f| (f.name.clone(), f.bytes().to_vec()))
            .collect()
    }
    #[test]
    #[ignore = "requires STYX_TEST_HISTORICAL_RECOVERY_ROOT; actual owned journal recovery, synthetic historical authority"]
    fn historical_baseline_boot_chain_and_publication_fence() {
        let parent = std::path::PathBuf::from(
            std::env::var_os("STYX_TEST_HISTORICAL_RECOVERY_ROOT")
                .expect("explicit owned fixture parent"),
        );
        // The explicit test parent must be fresh; do not adopt an existing
        // directory or require the gate to fabricate fixture initialization.
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        PrivateRoot::open(&parent).unwrap();
        let p = child(&parent);
        {
            let root = PrivateRoot::open(&p).unwrap();
            let mut writer = root.try_configuration_writer().unwrap();
            let mut j =
                EnrollmentJournal::open(&root, &mut writer, JournalBudget::default()).unwrap();
            j.record_time_floor(100).unwrap();
            let b = body(&mut j, &root, true);
            let raw = historical_contract::encode(&b).unwrap();
            let prepared = j.prepare_historical(&raw).unwrap();
            let before = inventory(&j);
            assert!(matches!(
                recover_journal(&mut j, id("new-process"), Limits::default(), 100),
                Err(RecoveryBlocked::UnresolvedInventory)
            ));
            assert_eq!(before, inventory(&j)); // no promotion of Prepared
            let committed = j.commit_historical(&prepared).unwrap();
            let baseline_head = committed.digest().unwrap();
            let mut recovered =
                recover_journal(&mut j, id("new-process"), Limits::default(), 100).unwrap();
            assert_eq!(recovered.facts.historical_baseline, Some(baseline_head));
            assert_eq!(recovered.facts.revision, 1);
            assert_eq!(
                recovered
                    .ledger
                    .default_device_for_admin(&recovered.control.admin())
                    .unwrap(),
                b.default_device
            );
            assert_eq!(
                recovered
                    .ledger
                    .historical_revoked_for_admin(&recovered.control.admin())
                    .unwrap(),
                b.revoked
            );
            let d = &b.devices[0];
            let proof =
                recovered
                    .control
                    .attest_device(d.id.clone(), d.fingerprint, d.credential_hash);
            assert_eq!(
                recovered.ledger.connection_observations(&proof).unwrap(),
                [styx_core::enrollment::ConnectionObservation::Unknown; 3]
            );
            let pending = recovered
                .ledger
                .invite(
                    &recovered.control.admin(),
                    Sha256Digest::of_bytes(b"next-invitation"),
                    60,
                    None,
                    101,
                )
                .unwrap();
            let native = j
                .prepare(pending.original_bytes(), Some(baseline_head))
                .unwrap();
            let native_commit = j.commit(&native).unwrap();
            recovered
                .ledger
                .confirm_durable(
                    recovered
                        .control
                        .attest_durable(&pending, native_commit.digest().unwrap()),
                )
                .unwrap();
            j.record_time_floor(101).unwrap();
            let reread =
                recover_journal(&mut j, id("next-process"), Limits::default(), 101).unwrap();
            assert_eq!(reread.facts.revision, 2);
            assert_eq!(reread.facts.sequence_high_water, 2);
            assert_eq!(reread.facts.head, Some(native_commit.digest().unwrap()));
            let namespace = p.join(".styx-enrollment-journal-v1");
            let token = namespace.join(material_name(&b.token_bindings[0].normalized_material));
            let original = fs::read(&token).unwrap();
            fs::remove_file(&token).unwrap();
            assert!(
                recover_journal(&mut j, id("missing-material"), Limits::default(), 101).is_err()
            );
            fs::write(&token, original).unwrap();
            fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
            let mut collision: IntentBody = contract::decode(pending.original_bytes()).unwrap();
            collision.transaction = id("sequence-collision");
            collision.sequence = 1;
            let collision_path = namespace.join("txn-sequence-collision.intent");
            fs::write(&collision_path, contract::encode(&collision).unwrap()).unwrap();
            fs::set_permissions(&collision_path, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(
                recover_journal(&mut j, id("colliding-process"), Limits::default(), 101).is_err()
            );
            fs::remove_file(collision_path).unwrap();
            let orphan = namespace.join("historical-baseline.tmp");
            fs::write(&orphan, b"unresolved original residue").unwrap();
            fs::set_permissions(&orphan, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(recover_journal(&mut j, id("orphan-process"), Limits::default(), 101).is_err());
            fs::remove_file(orphan).unwrap();
            assert!(
                recover_journal(&mut j, id("restored-process"), Limits::default(), 101).is_ok()
            );
        }
        // A committed, empty historical baseline can recover, but is not a C07
        // migration commit. Ordinary HTTP must remain fenced without any token.
        let gate = child(&parent);
        let root = PrivateRoot::open(&gate).unwrap();
        let mut writer = root.try_configuration_writer().unwrap();
        {
            let mut j =
                EnrollmentJournal::open(&root, &mut writer, JournalBudget::default()).unwrap();
            j.record_time_floor(100).unwrap();
            let b = body(&mut j, &root, false);
            let p = j
                .prepare_historical(&historical_contract::encode(&b).unwrap())
                .unwrap();
            j.commit_historical(&p).unwrap();
        }
        let store =
            OwnedEnrollmentJournal::open_existing(root, writer, JournalBudget::default()).unwrap();
        let service = crate::enrollment::service::EnrollmentService::recover_existing(
            store,
            b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            Sha256Digest::of_bytes(b"ordinary MCP authority"),
            vec!["localhost:8443".into()],
            Limits::default(),
        )
        .unwrap();
        let pairing = PairingContext {
            origin: "https://localhost:8443".into(),
            leaf: Sha256Digest::of_bytes(b"synthetic leaf"),
            ingress_generation: id("test-ingress"),
            window: None,
        };
        let error = service
            .preflight(
                &http::Method::GET,
                "/styx/enrollment/devices",
                &http::HeaderMap::new(),
                &pairing,
            )
            .unwrap_err();
        assert_eq!(error.code(), "migration_commit_required");
        drop(service);
        fs::remove_dir_all(p).unwrap();
        fs::remove_dir_all(gate).unwrap();
    }
}
