//! Real owned protected-file recovery, synthetic clock/admin evidence. This is
//! not TLS/crypto enrollment or live-profile migration acceptance.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
mod linux {
    use super::super::*;
    use crate::store::{PrivateRoot, enrollment::JournalBudget};
    use std::{
        fs::{self, OpenOptions},
        io::Write,
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
        path::{Path, PathBuf},
    };
    const NAMESPACE: &str = ".styx-enrollment-journal-v1";
    fn hash(s: &str) -> Sha256Digest {
        Sha256Digest::of_bytes(s.as_bytes())
    }
    fn owned_root(parent: &Path) -> PathBuf {
        let root = parent.join(uuid::Uuid::new_v4().to_string());
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        root
    }
    fn with_journal<T>(path: &Path, body: impl FnOnce(&mut EnrollmentJournal<'_>) -> T) -> T {
        let root = PrivateRoot::open(path).unwrap();
        let mut writer = root.try_configuration_writer().unwrap();
        let mut journal =
            EnrollmentJournal::open(&root, &mut writer, JournalBudget::default()).unwrap();
        body(&mut journal)
    }
    fn inventory(journal: &EnrollmentJournal<'_>) -> BTreeMap<String, Vec<u8>> {
        journal
            .scan()
            .unwrap()
            .files
            .into_iter()
            .map(|f| (f.name.clone(), f.bytes().to_vec()))
            .collect()
    }
    fn commit(
        journal: &mut EnrollmentJournal<'_>,
        ledger: &mut EnrollmentLedger,
        control: &EnrollmentControl,
        intent: &styx_core::enrollment::PendingIntent,
        previous: Option<Sha256Digest>,
    ) -> Sha256Digest {
        let prepared = journal.prepare(intent.original_bytes(), previous).unwrap();
        let durable = journal.commit(&prepared).unwrap();
        let digest = durable.digest().unwrap();
        ledger
            .confirm_durable(control.attest_durable(intent, digest))
            .unwrap();
        digest
    }
    fn epoch(s: &str) -> GatewayEpoch {
        GatewayEpoch::try_from(s).unwrap()
    }
    fn seed_one(path: &Path, name: &str, abort_first: bool) -> BTreeMap<String, Vec<u8>> {
        with_journal(path, |journal| {
            // This path was explicitly created by this fixture, not inferred
            // fresh from missing state in a previous user's profile.
            journal.record_time_floor(1000).unwrap();
            let RecoveredEnrollment {
                mut ledger,
                control,
                ..
            } = recover_journal(journal, epoch(name), Limits::default(), 1000).unwrap();
            if abort_first {
                journal.record_time_floor(1001).unwrap();
                let aborted = ledger.close_window(&control.admin(), None, 1001).unwrap();
                ledger
                    .abort_proven_not_written(control.attest_not_written(&aborted))
                    .unwrap();
            }
            journal.record_time_floor(1002).unwrap();
            let first = ledger
                .invite(&control.admin(), hash(name), 60, None, 1002)
                .unwrap();
            commit(journal, &mut ledger, &control, &first, None);
            inventory(journal)
        })
    }
    /// One new aggregate only; the old journal sixteen-cut crash matrix is not
    /// repeated here. Every root is owned, no original identity/private profile.
    #[test]
    #[ignore = "requires STYX_TEST_ENROLLMENT_RECOVERY_ROOT; owned actual Core/journal boot recovery"]
    fn actual_core_journal_recovery_safety_scenario() {
        let parent = PathBuf::from(std::env::var("STYX_TEST_ENROLLMENT_RECOVERY_ROOT").unwrap());
        fs::create_dir_all(&parent).unwrap();
        let no_namespace = owned_root(&parent);
        {
            let root = PrivateRoot::open(&no_namespace).unwrap();
            let mut writer = root.try_configuration_writer().unwrap();
            let result = crate::enrollment::EnrollmentBootstrap::recover_existing(
                &root,
                &mut writer,
                Limits::default(),
            );
            assert!(
                result.is_err(),
                "existing bootstrap cannot create a native enrollment namespace"
            );
            drop(result);
            assert!(
                !no_namespace.join(NAMESPACE).exists(),
                "independent raw-filesystem oracle: recovery did not mkdir"
            );
        }
        let path = owned_root(&parent);
        let (first_raw, head_two, second_sequence) = with_journal(&path, |journal| {
            journal.record_time_floor(1000).unwrap();
            let RecoveredEnrollment {
                mut ledger,
                control,
                facts,
            } = recover_journal(journal, epoch("original-process"), Limits::default(), 1000)
                .unwrap();
            assert_eq!(facts.revision, 0);
            journal.record_time_floor(1001).unwrap();
            let first = ledger
                .invite(&control.admin(), hash("invite-first"), 60, None, 1001)
                .unwrap();
            let original = first.original_bytes().to_vec();
            let first_head = commit(journal, &mut ledger, &control, &first, None);
            journal.record_time_floor(1002).unwrap();
            let aborted = ledger.close_window(&control.admin(), None, 1002).unwrap();
            let skipped = aborted.body().sequence;
            ledger
                .abort_proven_not_written(control.attest_not_written(&aborted))
                .unwrap();
            journal.record_time_floor(1003).unwrap();
            let second = ledger
                .invite(&control.admin(), hash("invite-second"), 60, None, 1003)
                .unwrap();
            assert!(second.body().sequence > skipped);
            assert_eq!(second.body().expected_revision, 1);
            let head = commit(journal, &mut ledger, &control, &second, Some(first_head));
            (original, head, second.body().sequence)
        });
        let (head_three, pending_transaction, pending_digest, pending_raw) =
            with_journal(&path, |journal| {
                let RecoveredEnrollment {
                    mut ledger,
                    control,
                    facts,
                } = recover_journal(journal, epoch("restarted-process"), Limits::default(), 1004)
                    .unwrap();
                assert_eq!(facts.head, Some(head_two));
                assert_eq!(facts.revision, 2);
                assert_eq!(facts.sequence_high_water, second_sequence);
                assert!(
                    journal
                        .scan()
                        .unwrap()
                        .files
                        .iter()
                        .any(|f| f.name.ends_with(".intent") && f.bytes() == first_raw)
                );
                journal.record_time_floor(1005).unwrap();
                let third = ledger
                    .invite(&control.admin(), hash("invite-new-epoch"), 60, None, 1005)
                    .unwrap();
                assert_eq!(third.body().gateway_epoch, epoch("restarted-process"));
                let head = commit(journal, &mut ledger, &control, &third, Some(head_two));
                journal.record_time_floor(1006).unwrap();
                let pending = ledger
                    .invite(&control.admin(), hash("invite-unknown"), 60, None, 1006)
                    .unwrap();
                journal
                    .prepare(pending.original_bytes(), Some(head))
                    .unwrap();
                (
                    head,
                    pending.body().transaction.clone(),
                    pending.digest(),
                    pending.original_bytes().to_vec(),
                )
            });
        with_journal(&path, |journal| {
            let RecoveredEnrollment {
                mut ledger,
                control,
                facts,
            } = recover_journal(journal, epoch("third-process"), Limits::default(), 1007).unwrap();
            assert_eq!(facts.head, Some(head_three));
            assert_eq!(facts.revision, 3);
            assert_eq!(facts.unresolved, Some(pending_digest));
            assert_eq!(facts.unresolved_kind, Some(UnresolvedKind::PreparedOnly));
            assert_eq!(
                ledger.pending_intent().unwrap().original_bytes(),
                pending_raw
            );
            journal.record_time_floor(1008).unwrap();
            assert_eq!(
                ledger
                    .invite(&control.admin(), hash("never-sent"), 60, None, 1008)
                    .unwrap_err(),
                EnrollmentError::Busy
            );
            let files = inventory(journal);
            assert!(
                !files.contains_key(&record_name(&pending_transaction, "committed")),
                "recovery never promotes a prepared-only transaction"
            );
            assert_eq!(
                files
                    .get(&record_name(&pending_transaction, "intent"))
                    .unwrap(),
                &pending_raw
            );
            assert!(matches!(
                recover_journal(journal, epoch("backward-clock"), Limits::default(), 1006),
                Err(RecoveryBlocked::ClockRollback)
            ));
            assert_eq!(
                inventory(journal),
                files,
                "clock rollback cannot rewrite state or initialize a new floor"
            );
        });
        // Nonempty namespace without a clock is not fresh; adapter cannot create
        // clock.floor or publish an empty default ledger to hide it.
        let missing_clock = owned_root(&parent);
        with_journal(&missing_clock, |journal| {
            journal.prepare(&first_raw, None).unwrap();
            let before = inventory(journal);
            assert!(matches!(
                recover_journal(journal, epoch("missing-clock"), Limits::default(), 2000),
                Err(RecoveryBlocked::ClockUnproven)
            ));
            assert_eq!(journal.read_time_floor().unwrap(), None);
            assert_eq!(inventory(journal), before);
        });
        // Deliberately corrupted policy history: an actual immutable journal can
        // contain an extra valid material ref not authorized by the Core intent.
        // Core exact-set validation must reject despite valid file hashes.
        let wrong_refs = owned_root(&parent);
        with_journal(&wrong_refs, |journal| {
            journal.record_time_floor(2000).unwrap();
            let extra = journal
                .put_material(MaterialKind::Profile, b"owned extraneous profile bytes")
                .unwrap();
            let mut body = contract::decode(&first_raw).unwrap();
            body.required_materials = vec![extra];
            let altered = contract::encode(&body).unwrap();
            let prepared = journal.prepare(&altered, None).unwrap();
            journal.commit(&prepared).unwrap();
            let before = inventory(journal);
            assert!(matches!(
                recover_journal(
                    journal,
                    epoch("wrong-material-restore"),
                    Limits::default(),
                    2001
                ),
                Err(RecoveryBlocked::Core(EnrollmentError::DurableMismatch))
            ));
            assert_eq!(inventory(journal), before);
        });
        // Real bounded files from independently valid branches create a fork.
        // This is an explicit corruption fixture, never product writer behavior.
        let fork_a = owned_root(&parent);
        seed_one(&fork_a, "fork-a", false);
        let fork_b = owned_root(&parent);
        let branch = seed_one(&fork_b, "fork-b", true);
        for (name, bytes) in branch.iter().filter(|(name, _)| name.starts_with("txn-")) {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(fork_a.join(NAMESPACE).join(name))
                .unwrap();
            file.write_all(bytes).unwrap();
            file.sync_all().unwrap();
        }
        fs::File::open(fork_a.join(NAMESPACE))
            .unwrap()
            .sync_all()
            .unwrap();
        with_journal(&fork_a, |journal| {
            let before = inventory(journal);
            assert!(matches!(
                recover_journal(journal, epoch("fork-restore"), Limits::default(), 2000),
                Err(RecoveryBlocked::ConflictingChain
                    | RecoveryBlocked::Store(JournalError::Conflict))
            ));
            assert_eq!(inventory(journal), before);
        });
        // Unknown temporary bytes are retained and block boot; no best-effort
        // sweep is allowed to turn this into a successful startup.
        let orphan = path.join(NAMESPACE).join("orphan-owned-negative.temporary");
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&orphan)
            .unwrap();
        file.write_all(b"owned unknown persistence boundary")
            .unwrap();
        file.sync_all().unwrap();
        drop(file);
        with_journal(&path, |journal| {
            let before = inventory(journal);
            assert!(matches!(
                recover_journal(journal, epoch("orphan-restore"), Limits::default(), 3000),
                Err(RecoveryBlocked::UnknownEntry)
            ));
            assert_eq!(inventory(journal), before);
            assert_eq!(
                fs::read(&orphan).unwrap(),
                b"owned unknown persistence boundary"
            );
        });
        println!(
            "ENROLLMENT_RECOVERY_OBSERVATION {}",
            serde_json::json!({"root":parent,"oldEpochPreserved":true,"committedRevisions":3,"sequenceGapAccepted":true,"preparedOnlyStillUnknown":pending_transaction,"missingNamespaceNotCreated":true,"missingClockNonemptyBlocked":true,"clockRollbackBlocked":true,"exactRefSetRefused":true,"forkRefused":true,"unknownOrphanRetained":true,"tlsCryptoOrNetworkReadyClaim":false})
        );
    }
}
