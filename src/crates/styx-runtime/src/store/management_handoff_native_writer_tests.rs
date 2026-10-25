//! Owned private-file refusal evidence; not Mac process or migration acceptance.
use super::*;
use crate::store::PrivateRoot;
use std::{
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
};

fn write(path: &std::path::Path, raw: &[u8]) {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    f.write_all(raw).unwrap();
    f.sync_all().unwrap();
}
fn mkdir(path: &std::path::Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}
#[test]
#[ignore = "STYX_TEST_MANAGEMENT_HANDOFF_ROOT; actual private-files collision refusal before any retirement stage, not migration acceptance"]
fn native_first_promotion_collision_preserves_original_files() {
    let base =
        std::path::PathBuf::from(std::env::var_os("STYX_TEST_MANAGEMENT_HANDOFF_ROOT").unwrap());
    for before in [
        br#"{ "schema":1, "migration_v2" : { "opaque":900719925474099312345 } }"#.as_slice(),
        br#"{ "schema":1, "migration_\u00762" : null }"#.as_slice(),
    ] {
        let path = base.join(format!("native-collision-{}", uuid::Uuid::new_v4()));
        mkdir(&path);
        let host = path.join("host");
        mkdir(&host);
        mkdir(&host.join("device"));
        let deployment = br#"{"schema":1,"mode":"join-existing","host":{}}"#;
        write(&path.join("deployment.json"), deployment);
        write(&path.join("state.json"), before);
        let token_path = host.join("device/host.token");
        let token = b"synthetic-owned-token-not-production";
        write(&token_path, token);
        let meta = fs::metadata(&token_path).unwrap();
        let root = PrivateRoot::open(&path).unwrap();
        let host_root = PrivateRoot::open(&host).unwrap();
        let config_identity = actual_root(root.identity()).unwrap();
        let host_identity = actual_root(host_root.identity()).unwrap();
        let writer = root.try_configuration_writer().unwrap();
        let owner = OwnedConfigurationRoot::open_existing(root, writer).unwrap();
        let tx: TransactionId = "collision-refusal".try_into().unwrap();
        let maintenance = owner.begin_maintenance(tx.clone()).unwrap();
        let mut journal = OwnedManagementJournal::open_for_native_retirement(
            owner.clone(),
            &maintenance,
            JournalBudget::default(),
        )
        .unwrap();
        let hash = Sha256Digest::of_bytes(b"synthetic-material");
        let intent = NativeRetirementIntent {
            schema: 3,
            kind: RetirementKind::LegacyCredentialRetirement,
            transaction_id: tx,
            sequence: 1,
            config_root: config_identity,
            host_root: host_identity,
            deployment_raw_sha256: Sha256Digest::of_bytes(deployment),
            before_state_sha256: Sha256Digest::of_bytes(before),
            preservation_sha256: hash,
            service_descriptor_sha256: hash,
            candidate_manifest_sha256: hash,
            publisher_spki_sha256: hash,
            original_token: NativeRetirementFileStamp::Linux {
                stamp: RetirementFileStamp {
                    device: meta.dev(),
                    inode: meta.ino(),
                    uid: meta.uid(),
                    mode: meta.mode(),
                    nlink: meta.nlink(),
                    byte_len: meta.len(),
                    modified_seconds: meta.mtime(),
                    modified_nanoseconds: meta.mtime_nsec(),
                    changed_seconds: meta.ctime(),
                    changed_nanoseconds: meta.ctime_nsec(),
                    sha256: Sha256Digest::of_bytes(token),
                },
            },
        };
        let namespace = path.join(".styx-management-journal-v1");
        let entries_before: Vec<_> = fs::read_dir(&namespace)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert!(matches!(
            journal.prepare_native_credential_retirement(&maintenance, &intent),
            Err(JournalError::Conflict)
        ));
        let entries_after: Vec<_> = fs::read_dir(&namespace)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(entries_before, entries_after);
        assert!(entries_after.is_empty());
        assert_eq!(fs::read(path.join("state.json")).unwrap(), before);
        assert_eq!(fs::read(path.join("deployment.json")).unwrap(), deployment);
        assert_eq!(fs::read(&token_path).unwrap(), token);
        let post = fs::metadata(&token_path).unwrap();
        assert_eq!(
            (meta.dev(), meta.ino(), meta.ctime(), meta.ctime_nsec()),
            (post.dev(), post.ino(), post.ctime(), post.ctime_nsec())
        );
        assert!(!host.join(intent.token_destination()).exists());
        assert!(owner.ensure_admission().is_err());
        // Keep the private original fixture for independent inspection.
    }
}

fn observed(path: &std::path::Path) -> NativeRetirementFileStamp {
    let m = fs::metadata(path).unwrap();
    NativeRetirementFileStamp::Linux {
        stamp: RetirementFileStamp {
            device: m.dev(),
            inode: m.ino(),
            uid: m.uid(),
            mode: m.mode(),
            nlink: m.nlink(),
            byte_len: m.len(),
            modified_seconds: m.mtime(),
            modified_nanoseconds: m.mtime_nsec(),
            changed_seconds: m.ctime(),
            changed_nanoseconds: m.ctime_nsec(),
            sha256: Sha256Digest::of_bytes(&fs::read(path).unwrap()),
        },
    }
}
/// Real files and original journal continuation, with deliberately synthetic boot
/// observations. This proves stage persistence/refusal, not any OS boot fact.
#[test]
#[ignore = "STYX_TEST_MANAGEMENT_HANDOFF_ROOT; actual same-journal original recovery and partial archive files, synthetic boot facts only"]
fn native_owner_recovery_continues_original_partial_archive_without_second_transaction() {
    let base =
        std::path::PathBuf::from(std::env::var_os("STYX_TEST_MANAGEMENT_HANDOFF_ROOT").unwrap());
    let path = base.join(format!("native-owner-recovery-{}", uuid::Uuid::new_v4()));
    mkdir(&path);
    let deployment = br#"{"schema":1,"mode":"join-existing","host":{}}"#;
    let before = br#"{ "schema":1,"opaque":900719925474099312345 }"#;
    write(&path.join("deployment.json"), deployment);
    write(&path.join("state.json"), before);
    let host = path.join("host");
    mkdir(&host);
    mkdir(&host.join("device"));
    write(
        &host.join("device/host.token"),
        b"synthetic-original-credential",
    );
    let original_data = [
        (
            RecoveryOriginalName::Lock,
            b"original-foreground-lock".as_slice(),
        ),
        (
            RecoveryOriginalName::Owner,
            br#"{"schema":1,"fixture":"original-owner"}"#.as_slice(),
        ),
    ];
    for (name, raw) in original_data {
        write(&path.join(name.source_name()), raw);
    }
    let root = PrivateRoot::open(&path).unwrap();
    let config_root = actual_root(root.identity()).unwrap();
    let host_root = actual_root(PrivateRoot::open(&host).unwrap().identity()).unwrap();
    let writer = root.try_configuration_writer().unwrap();
    let owner = OwnedConfigurationRoot::open_existing(root, writer).unwrap();
    let tx: TransactionId = "same-native-recovery".try_into().unwrap();
    let maintenance = owner.begin_maintenance(tx.clone()).unwrap();
    let mut journal = OwnedManagementJournal::open_for_native_retirement(
        owner.clone(),
        &maintenance,
        JournalBudget::default(),
    )
    .unwrap();
    let hash = Sha256Digest::of_bytes(b"synthetic-preservation");
    let successor = NativeRetirementIntent {
        schema: 3,
        kind: RetirementKind::LegacyCredentialRetirement,
        transaction_id: tx.clone(),
        sequence: 1,
        config_root: config_root.clone(),
        host_root,
        deployment_raw_sha256: Sha256Digest::of_bytes(deployment),
        before_state_sha256: Sha256Digest::of_bytes(before),
        preservation_sha256: hash,
        service_descriptor_sha256: hash,
        candidate_manifest_sha256: hash,
        publisher_spki_sha256: hash,
        original_token: observed(&host.join("device/host.token")),
    };
    let originals: Vec<_> = original_data
        .into_iter()
        .map(|(name, raw)| RecoveryOriginal {
            name,
            raw: raw.to_vec(),
            stamp: observed(&path.join(name.source_name())),
        })
        .collect();
    let guards: Vec<_> = [
        RecoveryGuardName::Advance,
        RecoveryGuardName::Background,
        RecoveryGuardName::Capabilities,
        RecoveryGuardName::Foreground,
    ]
    .into_iter()
    .map(|name| RecoveryGuard {
        name,
        raw: format!("owned-fixture-guard-{}", uuid::Uuid::new_v4()).into_bytes(),
    })
    .collect();
    let intent = LegacyOwnerRecoveryIntent {
        schema: 1,
        kind: RecoveryKind::LegacyOwnerRecovery,
        startup_checkpoint: None,
        transaction_id: tx.clone(),
        sequence: 1,
        config_root,
        deployment_raw_sha256: successor.deployment_raw_sha256,
        before_state_sha256: successor.before_state_sha256,
        candidate_manifest_sha256: hash,
        publisher_spki_sha256: hash,
        previous_boot: Some(RecoveryBoot {
            id: "synthetic-old-boot-not-platform-proof".into(),
            started_at_ms: 1,
        }),
        current_boot: RecoveryBoot {
            id: "synthetic-new-boot-not-platform-proof".into(),
            started_at_ms: 2,
        },
        basis: None,
        restart: RecoveryRestartBinding::ForegroundOnlyNoInstalledManager,
        successor_retirement_intent_sha256: Sha256Digest::of_bytes(
            &serde_json::to_vec(&successor).unwrap(),
        ),
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
    assert!(owner.ensure_admission().is_err());
    assert!(journal.owner_recovery_prepared_matches(&prepared));
    let archive = path.join("foreground-recovery");
    mkdir(&archive);
    let archive = archive.join(tx.as_str());
    mkdir(&archive);
    // Crash boundary analogue: one actual rename happened, no Archived receipt.
    fs::rename(
        path.join("foreground.lock"),
        archive.join("foreground.lock.retired"),
    )
    .unwrap();
    fs::File::open(&path).unwrap().sync_all().unwrap();
    fs::File::open(&archive).unwrap().sync_all().unwrap();
    drop(prepared);
    let resumed = journal
        .resync_legacy_owner_recovery(&maintenance, &tx)
        .unwrap();
    assert_eq!(resumed.stage(), Some(OwnerRecoveryStage::Prepared));
    journal
        .validate_legacy_owner_prepared(&maintenance, &resumed)
        .unwrap();
    for original in resumed.originals() {
        let source = path.join(original.name.source_name());
        let destination = archive.join(format!("{}.retired", original.name.source_name()));
        if source.exists() {
            assert!(!destination.exists());
            fs::rename(&source, &destination).unwrap();
        }
        assert!(!source.exists());
        assert_eq!(fs::read(&destination).unwrap(), original.raw);
    }
    fs::File::open(&path).unwrap().sync_all().unwrap();
    fs::File::open(&archive).unwrap().sync_all().unwrap();
    let posts: Vec<_> = resumed
        .originals()
        .iter()
        .map(|o| RecoveryOriginalPost {
            name: o.name,
            stamp: observed(&archive.join(format!("{}.retired", o.name.source_name()))),
        })
        .collect();
    let mut false_posts = posts.clone();
    false_posts.swap(0, 1);
    assert!(
        journal
            .record_legacy_owner_archived(&maintenance, &resumed, false_posts)
            .is_err()
    );
    let archived = journal
        .record_legacy_owner_archived(&maintenance, &resumed, posts)
        .unwrap();
    let resumed_archived = journal
        .resync_legacy_owner_recovery(&maintenance, &tx)
        .unwrap()
        .into_archived()
        .unwrap();
    let mut guard_posts = Vec::new();
    for g in resumed_archived.prepared().guard_bytes() {
        write(&path.join(g.name.source_name()), &g.raw);
        guard_posts.push(RecoveryGuardPost {
            name: g.name,
            stamp: observed(&path.join(g.name.source_name())),
        });
    }
    fs::File::open(&path).unwrap().sync_all().unwrap();
    let held = journal
        .record_legacy_guards_held(&maintenance, &resumed_archived, guard_posts)
        .unwrap();
    assert!(held.prepared().matches_owner(&owner));
    drop(archived);
    let namespace = path.join(".styx-management-journal-v1");
    let before_names: BTreeSet<_> = fs::read_dir(&namespace)
        .unwrap()
        .map(|f| f.unwrap().file_name())
        .collect();
    let mut wrong = successor.clone();
    wrong.sequence = 2;
    assert!(
        journal
            .prepare_native_credential_retirement(&maintenance, &wrong)
            .is_err()
    );
    assert_eq!(
        before_names,
        fs::read_dir(&namespace)
            .unwrap()
            .map(|f| f.unwrap().file_name())
            .collect()
    );
    let retirement = journal
        .prepare_native_credential_retirement(&maintenance, &successor)
        .unwrap();
    assert!(journal.native_prepared_matches(&retirement));
    let inventory = journal.observe().unwrap();
    assert_eq!(inventory.high_water, 1);
    assert_eq!(inventory.handoffs.len(), 1);
    assert_eq!(inventory.owner_recoveries.len(), 1);
    assert!(inventory.orphans.is_empty());
    assert_eq!(
        fs::read(host.join("device/host.token")).unwrap(),
        b"synthetic-original-credential"
    );
    assert_eq!(fs::read(path.join("state.json")).unwrap(), before);
    assert!(owner.ensure_admission().is_err());
}
