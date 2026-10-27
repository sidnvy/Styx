//! Private synthetic configuration fixtures, not onboarding/cutover or power-loss
//! acceptance. Canonical files are independently read after every store action.
#![cfg(all(target_os = "linux", target_env = "gnu"))]
use super::*;
use crate::store::{PrivateRoot, secure_journal::NamespaceName};
use std::{
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use styx_contracts::identity::{Sha256Digest, TransactionId};
use styx_core::management::transaction::ReaderContract;

const DEPLOYMENT: &[u8] = b"{\"unknown\":900719925474099312345,\"mode\":\"synthetic\"}\n";
const BEFORE: &[u8] = b"{ \"schema\":1, \"opaque\":900719925474099312345 }\n";
const TARGET: &[u8] = b"{ \"schema\":1, \"opaque\":900719925474099312346 }\n";
fn write_private(path: &Path, bytes: &[u8]) {
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
fn fixture(base: &Path) -> (PathBuf, OwnedConfigurationRoot) {
    let path = base.join(uuid::Uuid::new_v4().to_string());
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let namespace = path.join(NamespaceName::ManagementV1.as_str());
    fs::create_dir(&namespace).unwrap();
    fs::set_permissions(namespace, fs::Permissions::from_mode(0o700)).unwrap();
    write_private(&path.join("deployment.json"), DEPLOYMENT);
    write_private(&path.join("state.json"), BEFORE);
    (path.clone(), reopen(&path))
}
fn reopen(path: &Path) -> OwnedConfigurationRoot {
    let root = PrivateRoot::open(path).unwrap();
    let writer = root.try_configuration_writer().unwrap();
    OwnedConfigurationRoot::open_existing(root, writer).unwrap()
}
fn intent(id: &str, sequence: u64) -> DesiredStateCommit {
    DesiredStateCommit {
        transaction_id: TransactionId::try_from(id).unwrap(),
        sequence,
        deployment_raw_sha256: Sha256Digest::of_bytes(DEPLOYMENT),
        before_state_sha256: Sha256Digest::of_bytes(BEFORE),
        target_state_sha256: Sha256Digest::of_bytes(TARGET),
        reader: ReaderContract::NativeManagementStateV1,
    }
}
#[test]
#[ignore = "requires STYX_TEST_MANAGEMENT_ROOT; real private files, preparation/fence/restart/orphan aggregate, not canonical apply"]
fn durable_prepare_preserves_exact_bytes_and_unsettled_high_water_batch() {
    let base = PathBuf::from(std::env::var("STYX_TEST_MANAGEMENT_ROOT").unwrap());
    fs::create_dir_all(&base).unwrap();
    let (path, owner) = fixture(&base);
    let journal =
        OwnedManagementJournal::open_existing(owner.clone(), JournalBudget::default()).unwrap();
    let original = intent("management-original", 7);
    // Preserve whitespace/field order of the exact caller-approved intent too.
    let raw = format!(" {}\n", serde_json::to_string(&original).unwrap()).into_bytes();
    let fence = owner
        .begin_maintenance(original.transaction_id.clone())
        .unwrap();
    assert!(matches!(
        journal.prepare(&fence, &raw, b"different", TARGET),
        Err(JournalError::InvalidInput)
    ));
    assert_eq!(journal.observe().unwrap().high_water, 0);
    let phases = std::cell::RefCell::new(Vec::new());
    let first = journal
        .prepare_observing(&fence, &raw, BEFORE, TARGET, &|record, phase| {
            phases
                .borrow_mut()
                .push((record.to_owned(), phase.to_owned()));
        })
        .unwrap();
    assert_eq!(phases.borrow().len(), 16);
    assert_eq!(
        phases.borrow().last().unwrap(),
        &("prepared".to_owned(), "directory_sync".to_owned())
    );
    let second = journal.prepare(&fence, &raw, BEFORE, TARGET).unwrap();
    assert_eq!(first.journal, second.journal);
    assert_eq!(fs::read(path.join("state.json")).unwrap(), BEFORE);
    assert_eq!(fs::read(path.join("deployment.json")).unwrap(), DEPLOYMENT);
    let directory = path.join(NamespaceName::ManagementV1.as_str());
    assert_eq!(
        fs::read(directory.join("txn-management-original.intent")).unwrap(),
        raw
    );
    assert_eq!(
        fs::read(directory.join(format!(
            "before-{}.material",
            Sha256Digest::of_bytes(BEFORE).to_hex()
        )))
        .unwrap(),
        BEFORE
    );
    assert_eq!(
        fs::read(directory.join(format!(
            "target-{}.material",
            Sha256Digest::of_bytes(TARGET).to_hex()
        )))
        .unwrap(),
        TARGET
    );
    assert!(matches!(
        owner.ensure_admission(),
        Err(JournalError::Conflict)
    ));
    assert!(matches!(
        owner.begin_maintenance(TransactionId::try_from("different").unwrap()),
        Err(JournalError::Conflict)
    ));
    let other = intent("different", 8);
    assert!(matches!(
        journal.prepare(&fence, &serde_json::to_vec(&other).unwrap(), BEFORE, TARGET),
        Err(JournalError::InvalidInput)
    ));
    drop(fence);
    drop(journal);
    drop(owner);
    let owner = reopen(&path);
    assert!(matches!(
        owner.ensure_admission(),
        Err(JournalError::Conflict)
    ));
    let journal =
        OwnedManagementJournal::open_existing(owner.clone(), JournalBudget::default()).unwrap();
    let inventory = journal.observe().unwrap();
    assert_eq!(inventory.high_water, 7);
    assert_eq!(inventory.transactions.len(), 1);
    assert!(inventory.transactions[0].prepared.is_some());
    assert!(inventory.orphans.is_empty());
    drop(journal);
    drop(owner);

    // Intent-only and an orphan temporary survive restart; not silently
    // completed, not recycled and not counted as durable Prepared.
    let (path, owner) = fixture(&base);
    let journal =
        OwnedManagementJournal::open_existing(owner.clone(), JournalBudget::default()).unwrap();
    let original = intent("interrupted", 19);
    let raw = serde_json::to_vec(&original).unwrap();
    let fence = owner
        .begin_maintenance(original.transaction_id.clone())
        .unwrap();
    let directory = path.join(NamespaceName::ManagementV1.as_str());
    write_private(&directory.join("txn-interrupted.intent"), &raw);
    write_private(
        &directory.join("retained-unknown.tmp"),
        b"partial synthetic write",
    );
    let observed = journal.observe().unwrap();
    assert_eq!(observed.high_water, 19);
    assert!(observed.transactions[0].prepared.is_none());
    assert_eq!(observed.orphans, vec!["retained-unknown.tmp"]);
    assert!(matches!(
        journal.prepare(&fence, &raw, BEFORE, TARGET),
        Err(JournalError::Conflict)
    ));
    assert!(!directory.join("txn-interrupted.prepared").exists());
    assert_eq!(fs::read(path.join("state.json")).unwrap(), BEFORE);
    drop(fence);
    drop(journal);
    drop(owner);
    let owner = reopen(&path);
    assert!(matches!(
        owner.begin_maintenance(original.transaction_id),
        Err(JournalError::Conflict)
    ));
    let journal = OwnedManagementJournal::open_existing(owner, JournalBudget::default()).unwrap();
    assert_eq!(journal.observe().unwrap().high_water, 19);

    // Independently found regression: standalone management must include an
    // existing enrollment namespace even without minting its domain handle.
    let (budget_path, budget_owner) = fixture(&base);
    drop(budget_owner);
    let enrollment_namespace = budget_path.join(NamespaceName::EnrollmentV1.as_str());
    fs::create_dir(&enrollment_namespace).unwrap();
    fs::set_permissions(&enrollment_namespace, fs::Permissions::from_mode(0o700)).unwrap();
    for index in 0..64 {
        let file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(enrollment_namespace.join(format!("retained-{index}")))
            .unwrap();
        file.set_len(1024 * 1024).unwrap();
    }
    let budget_owner = reopen(&budget_path);
    let budget_journal =
        OwnedManagementJournal::open_existing(budget_owner.clone(), JournalBudget::default())
            .unwrap();
    let budget_intent = intent("budget-original", 1);
    let budget_fence = budget_owner
        .begin_maintenance(budget_intent.transaction_id.clone())
        .unwrap();
    assert!(matches!(
        budget_journal.prepare(
            &budget_fence,
            &serde_json::to_vec(&budget_intent).unwrap(),
            BEFORE,
            TARGET
        ),
        Err(JournalError::BudgetExceeded)
    ));
    assert_eq!(
        fs::read_dir(budget_path.join(NamespaceName::ManagementV1.as_str()))
            .unwrap()
            .count(),
        0,
        "whole-root budget must refuse before any journal write"
    );
    assert_eq!(fs::read(budget_path.join("state.json")).unwrap(), BEFORE);
    assert!(
        budget_owner.ensure_usable().is_ok(),
        "preflight refusal is not an unknown write"
    );
    drop(budget_fence);
    drop(budget_journal);
    drop(budget_owner);
    fs::remove_dir_all(budget_path).unwrap();

    // A foreign change after durable Prepared cannot be reported as ordinary
    // pre-write Conflict. This test changes only its own synthetic canonical file.
    let (changed_path, changed_owner) = fixture(&base);
    let changed_journal =
        OwnedManagementJournal::open_existing(changed_owner.clone(), JournalBudget::default())
            .unwrap();
    let changed_intent = intent("changed-after-prepare", 1);
    let changed_fence = changed_owner
        .begin_maintenance(changed_intent.transaction_id.clone())
        .unwrap();
    let result = changed_journal.prepare_observing(
        &changed_fence,
        &serde_json::to_vec(&changed_intent).unwrap(),
        BEFORE,
        TARGET,
        &|record, phase| {
            if record == "prepared" && phase == "directory_sync" {
                fs::write(
                    changed_path.join("state.json"),
                    b"foreign-test-owned-change",
                )
                .unwrap();
            }
        },
    );
    assert!(matches!(result, Err(JournalError::Unknown)));
    assert_eq!(changed_owner.ensure_usable(), Err(JournalError::Unknown));
    assert_eq!(
        fs::read(changed_path.join("state.json")).unwrap(),
        b"foreign-test-owned-change"
    );
    assert!(
        changed_path
            .join(NamespaceName::ManagementV1.as_str())
            .join("txn-changed-after-prepare.prepared")
            .exists()
    );

    // Unrelated writer/transaction capabilities cannot be substituted.
    let (_, owner_a) = fixture(&base);
    let (_, owner_b) = fixture(&base);
    let journal = OwnedManagementJournal::open_existing(owner_a, JournalBudget::default()).unwrap();
    let original = intent("foreign-fence", 1);
    let foreign = owner_b
        .begin_maintenance(original.transaction_id.clone())
        .unwrap();
    assert!(matches!(
        journal.prepare(
            &foreign,
            &serde_json::to_vec(&original).unwrap(),
            BEFORE,
            TARGET
        ),
        Err(JournalError::Conflict)
    ));
    assert_eq!(journal.observe().unwrap().high_water, 0);
}

/// Actual independently launched test-only process boundary. No production CLI
/// or bootstrap bypass is exposed; every input belongs to the external oracle.
#[test]
#[ignore = "owned subprocess helper; independent preparation crash oracle supplies exact root/action"]
fn management_preparation_child() {
    let path = PathBuf::from(std::env::var_os("STYX_TEST_MANAGEMENT_JOURNAL_ROOT").unwrap());
    assert!(path.is_absolute());
    let action = std::env::var("STYX_TEST_MANAGEMENT_JOURNAL_ACTION").unwrap();
    let fault = std::env::var("STYX_TEST_MANAGEMENT_FAULT").unwrap_or_default();
    let root = PrivateRoot::open(&path).unwrap();
    let deployment = root.read_raw("deployment.json", 1024 * 1024).unwrap();
    let before = root.read_raw("state.json", 1024 * 1024).unwrap();
    let target = root
        .read_raw("approved-target.fixture", 1024 * 1024)
        .unwrap();
    let writer = root.try_configuration_writer().unwrap();
    let owner = OwnedConfigurationRoot::open_existing(root, writer).unwrap();
    let journal =
        OwnedManagementJournal::open_existing(owner.clone(), JournalBudget::default()).unwrap();
    if action == "prepare" {
        let intent = DesiredStateCommit {
            transaction_id: TransactionId::try_from("management-owned-1").unwrap(),
            sequence: 1,
            deployment_raw_sha256: Sha256Digest::of_bytes(deployment.bytes()),
            before_state_sha256: Sha256Digest::of_bytes(before.bytes()),
            target_state_sha256: Sha256Digest::of_bytes(target.bytes()),
            reader: ReaderContract::NativeManagementStateV1,
        };
        let raw = serde_json::to_vec(&intent).unwrap();
        let fence = owner
            .begin_maintenance(intent.transaction_id.clone())
            .unwrap();
        let _prepared = journal
            .prepare_observing(
                &fence,
                &raw,
                before.bytes(),
                target.bytes(),
                &|record, phase| {
                    if fault == format!("{record}.{phase}") {
                        std::process::exit(86);
                    }
                },
            )
            .unwrap();
        if fault == "reply_lost" {
            std::process::exit(86);
        }
    } else {
        assert_eq!(action, "observe");
    }
    let observed = journal.observe().unwrap();
    let transactions: Vec<_> = observed
        .transactions
        .iter()
        .map(|tx| {
            serde_json::json!({
                "transaction_id": tx.intent.transaction_id, "sequence": tx.intent.sequence,
                "prepared": tx.prepared.is_some(),
                "record_sha256": tx.prepared.as_ref().map(|p|p.journal.record_sha256),
            })
        })
        .collect();
    println!(
        "STYX_PREPARATION_JSON={}",
        serde_json::json!({
            "action": action, "admission_fenced": owner.ensure_admission().is_err(),
            "high_water": observed.high_water, "transactions": transactions,
        })
    );
}
