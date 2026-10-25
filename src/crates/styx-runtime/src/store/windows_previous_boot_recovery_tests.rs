//! Native file effects and durable same-journal recovery. Boot receipts/candidate
//! are synthetic: this test does NOT attest a prior real reboot or signed upgrade.
use super::*;
use crate::store::secure_journal::JournalBudget;
struct Cleanup(PathBuf);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
#[test]
#[ignore = "requires STYX_TEST_WINDOWS_STORE_ROOT; native private NTFS and WMI/TaskScheduler"]
fn first_archive_drop_all_handles_reopen_original_prepared_and_finish() {
    let base = PathBuf::from(std::env::var_os("STYX_TEST_WINDOWS_STORE_ROOT").unwrap());
    let parent = Root::open(&base).unwrap();
    for conflict in [false, true] {
        let name = format!("r60-recovery-{}", uuid::Uuid::new_v4().simple());
        let path = base.join(&name);
        let cleanup = Cleanup(path.clone());
        let root = parent.create_fresh_child(OsStr::new(&name)).unwrap();
        let private = PrivateRoot {
            inner: root.clone(),
        };
        let writer = private.try_configuration_writer().unwrap();
        for (name, raw) in [
            ("deployment.json", b"{}".as_slice()),
            ("state.json", b"{}".as_slice()),
            (
                "foreground-owner.json",
                b"synthetic-original-owner".as_slice(),
            ),
            ("foreground.lock", b"synthetic-original-lock".as_slice()),
        ] {
            root.create_fixed(&writer, name, raw, &|_| {}).unwrap();
        }
        let owner = OwnedConfigurationRoot::open_existing(private, writer).unwrap();
        let tx: TransactionId = "original-durable-recovery".try_into().unwrap();
        let maintenance = owner.begin_standalone_native(tx.clone(), false).unwrap();
        let mut journal = OwnedManagementJournal::open_for_native_retirement(
            owner.clone(),
            &maintenance,
            JournalBudget::default(),
        )
        .unwrap();
        let task_name = format!(
            "StyxPilot-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..20]
        );
        let observation = WindowsLegacyObservation::capture_foreground_only(&task_name).unwrap();
        let boot = observation.checkpoint().unwrap();
        let originals: Vec<_> = [RecoveryOriginalName::Lock, RecoveryOriginalName::Owner]
            .into_iter()
            .map(|name| {
                let raw = root.read_raw(Path::new(name.source_name()), 4096).unwrap();
                let pin =
                    ffi::open(&root.path.join(name.source_name()), false, false, false).unwrap();
                RecoveryOriginal {
                    name,
                    stamp: native_stamp(&pin, raw.bytes()).unwrap(),
                    raw: raw.bytes().to_vec(),
                }
            })
            .collect();
        let raw_guard = b"synthetic-owned-recovery-guard".to_vec();
        let guards: Vec<_> = [
            RecoveryGuardName::Advance,
            RecoveryGuardName::Background,
            RecoveryGuardName::Capabilities,
            RecoveryGuardName::Foreground,
        ]
        .into_iter()
        .map(|name| RecoveryGuard {
            name,
            raw: raw_guard.clone(),
        })
        .collect();
        let hash = Sha256Digest::of_bytes(b"synthetic-candidate-not-admission-proof");
        let intent = LegacyOwnerRecoveryIntent {
            schema: 1,
            startup_checkpoint: None,
            kind: RecoveryKind::LegacyOwnerRecovery,
            transaction_id: tx.clone(),
            sequence: 1,
            config_root: root_native(root.identity()).unwrap(),
            deployment_raw_sha256: Sha256Digest::of_bytes(b"{}"),
            before_state_sha256: Sha256Digest::of_bytes(b"{}"),
            candidate_manifest_sha256: hash,
            publisher_spki_sha256: hash,
            previous_boot: Some(RecoveryBoot {
                id: "synthetic-old-boot".into(),
                started_at_ms: 1,
            }),
            basis: None,
            current_boot: RecoveryBoot {
                id: "synthetic-new-boot".into(),
                started_at_ms: 2,
            },
            restart: RecoveryRestartBinding::ForegroundOnlyNoInstalledManager,
            successor_retirement_intent_sha256: hash,
            originals: originals
                .iter()
                .map(|o| RecoveryOriginalBinding {
                    name: o.name,
                    stamp: o.stamp.clone(),
                })
                .collect(),
            guards: guards
                .iter()
                .map(|g| RecoveryGuardBinding {
                    name: g.name,
                    sha256: Sha256Digest::of_bytes(&g.raw),
                    byte_len: g.raw.len() as u64,
                })
                .collect(),
        };
        let prepared = journal
            .prepare_legacy_owner_recovery(&maintenance, &intent, originals, guards)
            .unwrap();
        let original_owner = root
            .read_raw(Path::new("foreground-owner.json"), 4096)
            .unwrap();
        let original_lock = root.read_raw(Path::new("foreground.lock"), 4096).unwrap();
        let owner_id = original_owner.observation().clone();
        let lock_id = original_lock.observation().clone();
        let evidence = WindowsPreviousBootEvidence {
            root: root.clone(),
            current_boot: boot,
            originals: vec![
                root.read_raw(Path::new("deployment.json"), 4096).unwrap(),
                original_owner,
                original_lock,
            ],
        };
        let mut effect = WindowsBootRecoveryEffects::new(
            evidence,
            owner.clone(),
            maintenance,
            tx.clone(),
            raw_guard,
        )
        .unwrap();
        effect.match_prepared(&journal, &prepared).unwrap();
        // Simulate the precise loss boundary with real OS effects: durable
        // Prepared, recovery marker + three guards, only first original renamed.
        effect
            .ensure_guard("foreground-recovery.lock", false)
            .unwrap();
        for name in &GUARDS[..3] {
            effect.ensure_guard(name, false).unwrap();
        }
        effect.ensure_archive(false).unwrap();
        effect.archive_one(1, false).unwrap();
        assert!(
            root.ensure_absent(Path::new("foreground-owner.json"))
                .is_ok()
        );
        assert_eq!(
            root.read_raw(Path::new("foreground.lock"), 4096)
                .unwrap()
                .observation(),
            &lock_id
        );
        drop(effect);
        drop(prepared);
        drop(journal);
        drop(owner);
        drop(observation);
        drop(root);
        // All old writer, original/created file handles, COM observation and
        // opaque phase objects have gone. Reopen through actual journal bytes.
        let private = PrivateRoot::open(&path).unwrap();
        let root = private.inner.clone();
        let writer = private.try_configuration_writer().unwrap();
        let owner = OwnedConfigurationRoot::open_existing(private, writer).unwrap();
        assert!(owner.ensure_admission().is_err());
        let maintenance = owner.begin_standalone_native(tx.clone(), true).unwrap();
        let mut journal = OwnedManagementJournal::open_for_native_retirement(
            owner.clone(),
            &maintenance,
            JournalBudget::default(),
        )
        .unwrap();
        let prepared = journal
            .resync_legacy_owner_recovery(&maintenance, &tx)
            .unwrap();
        assert_eq!(prepared.stage(), Some(OwnerRecoveryStage::Prepared));
        let observation = WindowsLegacyObservation::capture_foreground_only(&task_name).unwrap();
        assert_eq!(observation.checkpoint().unwrap(), boot);
        // This is only a synthetic OS-effect fixture. Production from_prepared
        // also validates original boot receipt, signed candidate and descriptor.
        let saved = |name| {
            original_raw(
                prepared
                    .originals()
                    .iter()
                    .find(|o| o.name == name)
                    .unwrap(),
                &prepared.intent().config_root,
            )
            .unwrap()
        };
        let evidence = WindowsPreviousBootEvidence {
            root: root.clone(),
            current_boot: boot,
            originals: vec![
                root.read_raw(Path::new("deployment.json"), 4096).unwrap(),
                saved(RecoveryOriginalName::Owner),
                saved(RecoveryOriginalName::Lock),
            ],
        };
        let mut effect = WindowsBootRecoveryEffects::new(
            evidence,
            owner.clone(),
            maintenance,
            tx.clone(),
            prepared.guard_bytes()[0].raw.clone(),
        )
        .unwrap();
        effect.match_prepared(&journal, &prepared).unwrap();
        if conflict {
            // Owned fixture only: a conflicting original source and archived
            // target must stop without moving the second original.
            owner
                .with_maintenance(&effect.maintenance, |state| {
                    state
                        .root
                        .inner
                        .create_fixed(
                            &state.writer,
                            "foreground-owner.json",
                            b"foreign-conflict",
                            &|_| {},
                        )
                        .map_err(failed)
                })
                .unwrap();
            assert!(effect.resume_archive(&observation).is_err());
            assert_eq!(
                root.read_raw(Path::new("foreground.lock"), 4096)
                    .unwrap()
                    .observation(),
                &lock_id
            );
            assert_eq!(
                journal
                    .resync_legacy_owner_recovery(&effect.maintenance, &tx)
                    .unwrap()
                    .stage(),
                Some(OwnerRecoveryStage::Prepared)
            );
        } else {
            effect.resume_archive(&observation).unwrap();
            let archived = journal
                .record_legacy_owner_archived(
                    &effect.maintenance,
                    &prepared,
                    effect.archive_posts(&prepared).unwrap(),
                )
                .unwrap();
            effect.resume_guards(&observation).unwrap();
            let held = journal
                .record_legacy_guards_held(
                    &effect.maintenance,
                    &archived,
                    effect.guard_posts(archived.prepared()).unwrap(),
                )
                .unwrap();
            effect.observe_complete(&observation).unwrap();
            assert_eq!(
                held.prepared().stage(),
                Some(OwnerRecoveryStage::GuardsHeld)
            );
            for (name, old) in [
                ("foreground-owner.json", owner_id),
                ("foreground.lock", lock_id),
            ] {
                let archive = effect.archive.as_ref().unwrap();
                let now = archive
                    .read_raw(Path::new(&format!("{name}.retired")), 4096)
                    .unwrap();
                assert!(same_moved(&old, now.observation()));
            }
            assert!(
                root.ensure_absent(Path::new("foreground-recovery.lock"))
                    .is_ok()
            );
            assert!(owner.ensure_admission().is_err()); // guards are not cutover
            drop(held);
            drop(archived);
        }
        drop(effect);
        drop(prepared);
        drop(journal);
        drop(owner);
        drop(observation);
        drop(root);
        std::fs::remove_dir_all(&path).unwrap();
        drop(cleanup);
    }
}

#[test]
fn admitted_boot_accepts_same_or_strict_later_epoch_without_rewriting_receipt() {
    let original = RecoveryBoot {
        id: "wmi-lastboot-unix-micros:1000000123".into(),
        started_at_ms: 1000000,
    };
    let admitted = admitted_boot(
        &original,
        BootStamp {
            unix_micros: 1000000123,
        },
    )
    .unwrap();
    assert_eq!(admitted.unix_micros, 1000000123);
    assert_eq!(
        admitted_boot(
            &original,
            BootStamp {
                unix_micros: 1001000000
            }
        )
        .unwrap(),
        admitted
    );
    for micros in [999999999, 1000000000, 1000000124, 1000999999] {
        assert!(
            admitted_boot(
                &original,
                BootStamp {
                    unix_micros: micros
                }
            )
            .is_err()
        );
    }
    let invalid = RecoveryBoot {
        id: original.id.clone(),
        started_at_ms: original.started_at_ms + 1,
    };
    assert!(
        admitted_boot(
            &invalid,
            BootStamp {
                unix_micros: 1001000000
            }
        )
        .is_err()
    );
    assert_eq!(original.id, "wmi-lastboot-unix-micros:1000000123");
}
