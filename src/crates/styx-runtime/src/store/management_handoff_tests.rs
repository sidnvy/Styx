//! Real private scratch files; metadata DTO persistence is NOT OS retirement,
//! stopped-service evidence, writer handoff or power-loss filesystem acceptance.
use super::*;
use crate::store::{PrivateRoot, secure_journal::NamespaceName};
use std::{
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use styx_contracts::management::ReaderContract;
const DEPLOYMENT: &[u8] = b"{\"schema\":1,\"unknown\":900719925474099312345}\n";
const BEFORE: &[u8] = b"{ \"schema\":1, \"opaque\":true }\n";
const TOKEN: &[u8] = b"owned-synthetic-token-not-production\n";
struct Fixture {
    path: PathBuf,
    host: PathBuf,
    owner: OwnedConfigurationRoot,
    journal: OwnedManagementJournal,
    maintenance: ConfigurationMaintenance,
    intent: LegacyCredentialRetirementIntent,
}
fn write(path: &Path, bytes: &[u8]) {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    f.write_all(bytes).unwrap();
    f.sync_all().unwrap();
}
fn directory(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}
fn root_id(root: &PrivateRoot) -> RetirementLinuxRoot {
    let RootIdentity::Linux { device, inode, uid } = root.identity();
    RetirementLinuxRoot { device, inode, uid }
}
fn stamp(path: &Path) -> RetirementFileStamp {
    let m = fs::metadata(path).unwrap();
    RetirementFileStamp {
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
    }
}
fn fixture(base: &Path, budget: JournalBudget) -> Fixture {
    fixture_mode(base, budget, true)
}
fn fixture_mode(base: &Path, budget: JournalBudget, existing_namespace: bool) -> Fixture {
    let path = base.join(uuid::Uuid::new_v4().to_string());
    directory(&path);
    if existing_namespace {
        directory(&path.join(NamespaceName::ManagementV1.as_str()));
    }
    write(&path.join("deployment.json"), DEPLOYMENT);
    write(&path.join("state.json"), BEFORE);
    let host = path.join("host");
    directory(&host);
    directory(&host.join("device"));
    write(&host.join("device/host.token"), TOKEN);
    let config = PrivateRoot::open(&path).unwrap();
    let host_root = PrivateRoot::open(&host).unwrap();
    let config_root = root_id(&config);
    let host_identity = root_id(&host_root);
    let writer = config.try_configuration_writer().unwrap();
    let owner = OwnedConfigurationRoot::open_existing(config, writer).unwrap();
    let intent = LegacyCredentialRetirementIntent {
        schema: 1,
        kind: RetirementKind::LegacyCredentialRetirement,
        transaction_id: "owned-retire".try_into().unwrap(),
        sequence: 17,
        config_root,
        host_root: host_identity,
        deployment_raw_sha256: Sha256Digest::of_bytes(DEPLOYMENT),
        before_state_sha256: Sha256Digest::of_bytes(BEFORE),
        preservation_sha256: Sha256Digest::of_bytes(b"preservation"),
        service_descriptor_sha256: Sha256Digest::of_bytes(b"service"),
        candidate_manifest_sha256: Sha256Digest::of_bytes(b"candidate"),
        publisher_spki_sha256: Sha256Digest::of_bytes(b"publisher"),
        original_token: stamp(&host.join("device/host.token")),
    };
    let maintenance = owner
        .begin_maintenance(intent.transaction_id.clone())
        .unwrap();
    let journal = if existing_namespace {
        OwnedManagementJournal::open_existing(owner.clone(), budget).unwrap()
    } else {
        OwnedManagementJournal::open_for_legacy_retirement(owner.clone(), &maintenance, budget)
            .unwrap()
    };
    Fixture {
        path,
        host,
        owner,
        journal,
        maintenance,
        intent,
    }
}
fn cleanup(f: Fixture) {
    let path = f.path.clone();
    drop(f);
    fs::remove_dir_all(path).unwrap();
}

#[test]
#[ignore = "STYX_TEST_MANAGEMENT_HANDOFF_ROOT; actual private journal/rename/crash-retention aggregate, not service or handoff acceptance"]
fn credential_retirement_same_journal_and_pending_barrier_files_batch() {
    let base = PathBuf::from(std::env::var("STYX_TEST_MANAGEMENT_HANDOFF_ROOT").unwrap());
    fs::create_dir_all(&base).unwrap();
    // Real legacy roots have no native management directory. Initialize it only
    // under the original maintenance writer, and never claim a second handle.
    let mut bootstrap = fixture_mode(&base, JournalBudget::default(), false);
    let namespace = bootstrap.path.join(NamespaceName::ManagementV1.as_str());
    let original_namespace = fs::metadata(&namespace).unwrap();
    assert_eq!(original_namespace.mode() & 0o7777, 0o700);
    assert!(matches!(
        OwnedManagementJournal::open_for_legacy_retirement(
            bootstrap.owner.clone(),
            &bootstrap.maintenance,
            JournalBudget::default()
        ),
        Err(JournalError::Conflict)
    ));
    bootstrap
        .journal
        .prepare_credential_retirement(&bootstrap.maintenance, &bootstrap.intent)
        .unwrap();
    let now = fs::metadata(&namespace).unwrap();
    assert_eq!(
        (now.dev(), now.ino()),
        (original_namespace.dev(), original_namespace.ino())
    );
    assert!(bootstrap.owner.ensure_admission().is_err());
    cleanup(bootstrap);
    let mut f = fixture(&base, JournalBudget::default());
    let before_token = fs::read(f.host.join("device/host.token")).unwrap();
    let mut wrong = f.intent.clone();
    wrong.config_root.inode += 1;
    assert!(matches!(
        f.journal
            .prepare_credential_retirement(&f.maintenance, &wrong),
        Err(JournalError::Conflict)
    ));
    assert!(f.journal.observe().unwrap().handoffs.is_empty());
    let mut phases = Vec::new();
    let events = std::cell::RefCell::new(&mut phases);
    let prepared = f
        .journal
        .prepare_credential_retirement_observing(&f.maintenance, &f.intent, &|record, phase| {
            events
                .borrow_mut()
                .push((record.to_owned(), phase.to_owned()))
        })
        .unwrap();
    assert_eq!(phases.len(), 8);
    assert_eq!(
        phases.last().unwrap(),
        &("handoff_prepared".to_owned(), "directory_sync".to_owned())
    );
    let again = f
        .journal
        .prepare_credential_retirement(&f.maintenance, &f.intent)
        .unwrap();
    assert_eq!(prepared.record_sha256(), again.record_sha256());
    assert_eq!(
        fs::read(f.host.join("device/host.token")).unwrap(),
        before_token
    );
    assert!(!f.host.join(f.intent.token_destination()).exists());
    let inventory = f.journal.observe().unwrap();
    assert_eq!(inventory.high_water, 17);
    assert!(inventory.orphans.is_empty());
    assert_eq!(inventory.handoffs.len(), 1);
    assert_eq!(
        inventory.handoffs[0].stage,
        CredentialRetirementStage::Prepared
    );
    let native = DesiredStateCommit {
        transaction_id: f.intent.transaction_id.clone(),
        sequence: 17,
        deployment_raw_sha256: f.intent.deployment_raw_sha256,
        before_state_sha256: f.intent.before_state_sha256,
        target_state_sha256: Sha256Digest::of_bytes(b"target"),
        reader: ReaderContract::NativeManagementStateV1,
    };
    assert!(matches!(
        f.journal.prepare(
            &f.maintenance,
            &serde_json::to_vec(&native).unwrap(),
            BEFORE,
            b"target"
        ),
        Err(JournalError::Conflict)
    ));
    assert!(
        f.owner
            .with_state(|s| f
                .journal
                .assert_complete_locked(s, &f.intent.transaction_id))
            .is_err()
    );
    let other = fixture(&base, JournalBudget::default());
    assert!(matches!(
        f.journal.record_credential_retired(
            &other.maintenance,
            &prepared,
            &f.intent.original_token
        ),
        Err(JournalError::Conflict)
    ));
    let mut bad = f.intent.original_token.clone();
    bad.inode += 1;
    assert!(matches!(
        f.journal
            .record_credential_retired(&f.maintenance, &prepared, &bad),
        Err(JournalError::Conflict)
    ));
    assert_eq!(
        f.journal.observe().unwrap().handoffs[0].stage,
        CredentialRetirementStage::Prepared
    );
    // Actual test-owned OS rename performed OUTSIDE the journal, with independent
    // inode/bytes checks. Passing a DTO to the journal alone proves none of this.
    let destination = f.host.join(f.intent.token_destination());
    fs::rename(f.host.join(f.intent.token_source()), &destination).unwrap();
    fs::File::open(f.host.join("device"))
        .unwrap()
        .sync_all()
        .unwrap();
    let post = stamp(&destination);
    assert_eq!(post.inode, f.intent.original_token.inode);
    assert_eq!(fs::read(&destination).unwrap(), before_token);
    let retired = f
        .journal
        .record_credential_retired(&f.maintenance, &prepared, &post)
        .unwrap();
    let repeated = f
        .journal
        .record_credential_retired(&f.maintenance, &prepared, &post)
        .unwrap();
    assert_eq!(retired.record_sha256(), repeated.record_sha256());
    assert_eq!(
        f.journal.observe().unwrap().handoffs[0].stage,
        CredentialRetirementStage::Retired
    );
    assert!(matches!(
        f.journal
            .prepare_credential_retirement(&f.maintenance, &f.intent),
        Err(JournalError::Conflict)
    ));
    let original = f
        .journal
        .resync_original_retirement(&f.maintenance, &f.intent.transaction_id)
        .unwrap();
    assert_eq!(original.retired_sha256, Some(retired.record_sha256()));
    assert!(original.post_stamp.as_ref() == Some(&post));
    assert_eq!(
        fs::read(f.path.join("deployment.json")).unwrap(),
        DEPLOYMENT
    );
    assert_eq!(fs::read(f.path.join("state.json")).unwrap(), BEFORE);
    assert!(f.owner.ensure_admission().is_err());
    // Recognized Retired still never satisfies the native complete barrier.
    assert!(
        f.owner
            .with_state(|s| f
                .journal
                .assert_complete_locked(s, &f.intent.transaction_id))
            .is_err()
    );
    drop(retired);
    drop(repeated);
    drop(prepared);
    drop(again);
    cleanup(other);
    cleanup(f);
}

#[test]
#[ignore = "STYX_TEST_MANAGEMENT_HANDOFF_ROOT; preflight/crash/orphan/sequence actual files, not power-loss acceptance"]
fn credential_retirement_preflight_and_interrupted_originals_batch() {
    let base = PathBuf::from(std::env::var("STYX_TEST_MANAGEMENT_HANDOFF_ROOT").unwrap());
    fs::create_dir_all(&base).unwrap();
    let mut f = fixture(
        &base,
        JournalBudget {
            max_files: 1,
            ..JournalBudget::default()
        },
    );
    assert!(matches!(
        f.journal
            .prepare_credential_retirement(&f.maintenance, &f.intent),
        Err(JournalError::BudgetExceeded)
    ));
    assert!(
        fs::read_dir(f.path.join(NamespaceName::ManagementV1.as_str()))
            .unwrap()
            .next()
            .is_none()
    );
    cleanup(f);
    let f = fixture(&base, JournalBudget::default());
    let namespace = f.path.join(NamespaceName::ManagementV1.as_str());
    let raw = serde_json::to_vec(&f.intent).unwrap();
    let [intent_name, _, _] = names(&f.intent.transaction_id);
    write(&namespace.join(intent_name), &raw);
    let observed = f.journal.observe().unwrap();
    assert_eq!(observed.high_water, 17);
    assert_eq!(
        observed.handoffs[0].stage,
        CredentialRetirementStage::IntentOnly
    );
    let recovered = f
        .journal
        .resync_original_retirement(&f.maintenance, &f.intent.transaction_id)
        .unwrap();
    assert!(recovered.prepared_sha256.is_none());
    assert_eq!(recovered.raw_intent, raw);
    assert_eq!(fs::read(f.host.join("device/host.token")).unwrap(), TOKEN);
    // A separate desired intent sharing this ID/sequence is not another ledger.
    let collision = DesiredStateCommit {
        transaction_id: f.intent.transaction_id.clone(),
        sequence: 17,
        deployment_raw_sha256: f.intent.deployment_raw_sha256,
        before_state_sha256: f.intent.before_state_sha256,
        target_state_sha256: Sha256Digest::of_bytes(b"target"),
        reader: ReaderContract::NativeManagementStateV1,
    };
    write(
        &namespace.join(format!("txn-{}.intent", collision.transaction_id.as_str())),
        &serde_json::to_vec(&collision).unwrap(),
    );
    assert!(matches!(f.journal.observe(), Err(JournalError::Conflict)));
    cleanup(f);
    let mut f = fixture(&base, JournalBudget::default());
    let namespace = f.path.join(NamespaceName::ManagementV1.as_str());
    let fault = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = f.journal.prepare_credential_retirement_observing(
            &f.maintenance,
            &f.intent,
            &|record, phase| {
                if record == "handoff_prepared" && phase == "file_sync" {
                    panic!("owned injected preparation crash");
                }
            },
        );
    }));
    assert!(fault.is_err());
    assert!(f.owner.ensure_admission().is_err());
    // Inspect actual retained bytes independently, without claiming poisoned
    // owner can automatically resume or deleting unknown temporary materials.
    let files: Vec<_> = fs::read_dir(&namespace)
        .unwrap()
        .map(|r| r.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(files.iter().any(|n| n.ends_with(".handoff-intent")));
    assert!(files.iter().any(|n| n.starts_with("orphan-")));
    assert!(!files.iter().any(|n| n.ends_with(".handoff-prepared")));
    assert_eq!(fs::read(f.host.join("device/host.token")).unwrap(), TOKEN);
    let path = f.path.clone();
    drop(f);
    let root = PrivateRoot::open(&path).unwrap();
    let writer = root.try_configuration_writer().unwrap();
    let owner = OwnedConfigurationRoot::open_existing(root, writer).unwrap();
    let journal =
        OwnedManagementJournal::open_existing(owner.clone(), JournalBudget::default()).unwrap();
    let observed = journal.observe().unwrap();
    assert_eq!(observed.high_water, 17);
    assert_eq!(
        observed.handoffs[0].stage,
        CredentialRetirementStage::IntentOnly
    );
    assert!(observed.orphans.iter().any(|n| n.starts_with("orphan-")));
    assert!(owner.ensure_admission().is_err());
    drop(journal);
    drop(owner);
    fs::remove_dir_all(path).unwrap();
}
