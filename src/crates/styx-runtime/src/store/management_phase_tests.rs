//! Actual owned files for journal phase protocol; canonical replacement here is
//! a synthetic checkpoint, NOT the native-root/formal-reader apply coordinator.
#![cfg(all(target_os = "linux", target_env = "gnu"))]
use super::*;
use crate::store::{PrivateRoot, secure_journal::NamespaceName};
use std::{
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use styx_contracts::management::ReaderContract;
const DEPLOYMENT: &[u8] = b"{\"schema\":1}";
const BEFORE: &[u8] = b"{\"schema\":2,\"synthetic\":0}";
const TARGET: &[u8] = b"{\"schema\":2,\"synthetic\":1}";
fn write(path: &Path, bytes: &[u8]) {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
fn fixture(
    base: &Path,
) -> (
    PathBuf,
    OwnedConfigurationRoot,
    OwnedManagementJournal,
    ConfigurationMaintenance,
    DesiredStateCommit,
    JournalReceipt,
) {
    let path = base.join(uuid::Uuid::new_v4().to_string());
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let namespace = path.join(NamespaceName::ManagementV1.as_str());
    fs::create_dir(&namespace).unwrap();
    fs::set_permissions(namespace, fs::Permissions::from_mode(0o700)).unwrap();
    write(&path.join("deployment.json"), DEPLOYMENT);
    write(&path.join("state.json"), BEFORE);
    let root = PrivateRoot::open(&path).unwrap();
    let writer = root.try_configuration_writer().unwrap();
    let owner = OwnedConfigurationRoot::open_existing(root, writer).unwrap();
    let mut journal =
        OwnedManagementJournal::open_existing(owner.clone(), JournalBudget::default()).unwrap();
    let intent = DesiredStateCommit {
        transaction_id: "phases-1".try_into().unwrap(),
        sequence: 9,
        deployment_raw_sha256: Sha256Digest::of_bytes(DEPLOYMENT),
        before_state_sha256: Sha256Digest::of_bytes(BEFORE),
        target_state_sha256: Sha256Digest::of_bytes(TARGET),
        reader: ReaderContract::NativeManagementStateV1,
    };
    let fence = owner
        .begin_maintenance(intent.transaction_id.clone())
        .unwrap();
    let prepared = journal
        .prepare(
            &fence,
            &serde_json::to_vec(&intent).unwrap(),
            BEFORE,
            TARGET,
        )
        .unwrap();
    (path, owner, journal, fence, intent, prepared.journal)
}
fn checkpoint(path: &Path) {
    fs::write(path.join("state.json"), TARGET).unwrap();
    fs::File::open(path.join("state.json"))
        .unwrap()
        .sync_all()
        .unwrap();
}
#[test]
#[ignore = "STYX_TEST_MANAGEMENT_PHASE_ROOT; owned real-file phase-chain aggregate, not native apply acceptance"]
fn original_phase_chain_and_unknown_orphans_are_preserved_batch() {
    let base = PathBuf::from(std::env::var("STYX_TEST_MANAGEMENT_PHASE_ROOT").unwrap());
    fs::create_dir_all(&base).unwrap();
    let (path, owner, mut journal, fence, intent, prepared) = fixture(&base);
    assert!(matches!(
        journal.append_phase(
            &fence,
            &intent,
            DurableStage::Applied,
            prepared.record_sha256,
            false
        ),
        Err(JournalError::Conflict)
    ));
    assert!(
        journal.observe().unwrap().transactions[0]
            .phase_receipts
            .is_empty()
    );
    let (other_path, other_owner, other_journal, other_fence, _, _) = fixture(&base);
    assert!(matches!(
        other_owner.with_state(|state| journal.read_original_locked(state, &intent.transaction_id)),
        Err(JournalError::Conflict)
    ));
    assert!(matches!(
        journal.resync_original(&other_fence, &intent.transaction_id),
        Err(JournalError::Conflict)
    ));
    drop(other_fence);
    drop(other_journal);
    drop(other_owner);
    fs::remove_dir_all(other_path).unwrap();
    checkpoint(&path);
    assert!(matches!(
        journal.append_phase(
            &fence,
            &intent,
            DurableStage::Verified,
            prepared.record_sha256,
            false
        ),
        Err(JournalError::Conflict)
    ));
    assert!(matches!(
        journal.append_phase(
            &fence,
            &intent,
            DurableStage::Applied,
            Sha256Digest::of_bytes(b"wrong previous"),
            false
        ),
        Err(JournalError::Conflict)
    ));
    let phases = std::cell::RefCell::new(Vec::new());
    let applied = journal
        .append_phase_observing(
            &fence,
            &intent,
            DurableStage::Applied,
            prepared.record_sha256,
            false,
            &|name, phase| {
                phases
                    .borrow_mut()
                    .push((name.to_owned(), phase.to_owned()))
            },
        )
        .unwrap();
    assert_eq!(phases.borrow().len(), 4);
    assert_eq!(
        phases.borrow().last().unwrap(),
        &("applied".into(), "directory_sync".into())
    );
    assert_eq!(
        journal
            .append_phase(
                &fence,
                &intent,
                DurableStage::Applied,
                prepared.record_sha256,
                false
            )
            .unwrap(),
        applied
    );
    assert!(matches!(
        journal.append_phase(
            &fence,
            &intent,
            DurableStage::Applied,
            prepared.record_sha256,
            true
        ),
        Err(JournalError::Conflict)
    ));
    let verified = journal
        .append_phase(
            &fence,
            &intent,
            DurableStage::Verified,
            applied.record_sha256,
            true,
        )
        .unwrap();
    let committed = journal
        .append_phase(
            &fence,
            &intent,
            DurableStage::Committed,
            verified.record_sha256,
            true,
        )
        .unwrap();
    assert_eq!(committed.previous, Some(verified.record_sha256));
    let original = journal.read_original(&intent.transaction_id).unwrap();
    assert_eq!(original.intent, intent);
    assert_eq!(original.before, BEFORE);
    assert_eq!(original.target, TARGET);
    assert_eq!(original.raw_intent, serde_json::to_vec(&intent).unwrap());
    assert_eq!(
        original.phases,
        vec![prepared, applied, verified, committed]
    );
    let applied_file = path
        .join(NamespaceName::ManagementV1.as_str())
        .join("txn-phases-1.applied");
    let recorded_bytes = fs::read(&applied_file).unwrap();
    let resynced = journal
        .resync_original(&fence, &intent.transaction_id)
        .unwrap();
    assert_eq!(resynced.phases, original.phases);
    assert_eq!(resynced.raw_intent, original.raw_intent);
    assert_eq!(fs::read(&applied_file).unwrap(), recorded_bytes);
    assert_eq!(
        journal.budget().max_file_bytes,
        JournalBudget::default().max_file_bytes
    );

    assert!(matches!(
        journal.append_phase(
            &fence,
            &intent,
            DurableStage::Applied,
            original.phases[0].record_sha256,
            false
        ),
        Err(JournalError::Conflict)
    ));
    assert_eq!(fs::read(path.join("state.json")).unwrap(), TARGET);
    assert!(matches!(
        journal.prepare(&fence, &original.raw_intent, BEFORE, TARGET),
        Err(JournalError::Conflict)
    ));
    drop(fence);
    drop(journal);
    drop(owner);
    let root = PrivateRoot::open(&path).unwrap();
    let writer = root.try_configuration_writer().unwrap();
    let reopened = OwnedConfigurationRoot::open_existing(root, writer).unwrap();
    assert!(reopened.ensure_admission().is_err()); // no journal recovery authority implied
    let journal =
        OwnedManagementJournal::open_existing(reopened, JournalBudget::default()).unwrap();
    assert_eq!(
        journal
            .read_original(&intent.transaction_id)
            .unwrap()
            .phases
            .len(),
        4
    );
    drop(journal);
    fs::remove_dir_all(&path).unwrap();

    let (path, owner, mut journal, fence, intent, prepared) = fixture(&base);
    checkpoint(&path);
    let namespace = path.join(NamespaceName::ManagementV1.as_str());
    let orphan = namespace.join("txn-phases-1.state-temporary");
    write(&orphan, TARGET);
    assert_eq!(
        journal
            .read_original(&intent.transaction_id)
            .unwrap()
            .before,
        BEFORE
    );
    assert!(matches!(
        journal.append_phase(
            &fence,
            &intent,
            DurableStage::Applied,
            prepared.record_sha256,
            false
        ),
        Err(JournalError::Conflict)
    ));
    assert_eq!(fs::read(&orphan).unwrap(), TARGET);
    let resynced = journal
        .resync_original(&fence, &intent.transaction_id)
        .unwrap();
    assert_eq!(resynced.phases.len(), 1);
    assert_eq!(fs::read(&orphan).unwrap(), TARGET);

    assert_eq!(
        journal.observe().unwrap().orphans,
        vec!["txn-phases-1.state-temporary"]
    );
    drop(fence);
    drop(journal);
    drop(owner);
    fs::remove_dir_all(&path).unwrap();

    // Tampered chain is not silently repaired or treated as an observed ACK.
    let (path, owner, mut journal, fence, intent, prepared) = fixture(&base);
    checkpoint(&path);
    journal
        .append_phase(
            &fence,
            &intent,
            DurableStage::Applied,
            prepared.record_sha256,
            false,
        )
        .unwrap();
    let phase_path = path
        .join(NamespaceName::ManagementV1.as_str())
        .join("txn-phases-1.applied");
    let mut record: serde_json::Value =
        serde_json::from_slice(&fs::read(&phase_path).unwrap()).unwrap();
    record["previous"] =
        serde_json::Value::String(Sha256Digest::of_bytes(b"foreign previous").to_hex());
    fs::write(&phase_path, serde_json::to_vec(&record).unwrap()).unwrap();
    assert!(matches!(
        journal.read_original(&intent.transaction_id),
        Err(JournalError::Unknown)
    ));
    assert!(matches!(owner.ensure_usable(), Err(JournalError::Unknown)));
    drop(fence);
    drop(journal);
    drop(owner);
    fs::remove_dir_all(&path).unwrap();
    println!(
        "owned original journal phases: exact chain, pre-target refusal, skip/previous/reconciled mutation rejection, repeat resync, raw material identity, committed restart remains fenced, temp orphan preserved, corrupt chain stickyUnknown; native apply/reader/OS/cutover NOT_RUN"
    );
}
