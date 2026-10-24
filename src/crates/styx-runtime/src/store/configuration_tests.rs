//! Real test-owned files/locks; not legacy handoff, HTTP settlement or fsync
//! fault-injection acceptance. Root registers this module after source freeze.
#![cfg(all(target_os = "linux", target_env = "gnu"))]
use super::*;
use crate::store::{
    LockResource, StoreError,
    enrollment::{EnrollmentJournal, OwnedEnrollmentJournal},
};
use std::{
    fs,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

fn private_directory(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}
fn fixture(base: &Path) -> (PathBuf, OwnedConfigurationRoot) {
    let path = base.join(uuid::Uuid::new_v4().to_string());
    private_directory(&path);
    let root = PrivateRoot::open(&path).unwrap();
    let mut writer = root.try_configuration_writer().unwrap();
    // Existing production initializer creates only the enrollment namespace.
    {
        let mut journal =
            EnrollmentJournal::open(&root, &mut writer, JournalBudget::default()).unwrap();
        journal.record_time_floor(100).unwrap();
    }
    private_directory(&path.join(NamespaceName::ManagementV1.as_str()));
    (
        path,
        OwnedConfigurationRoot::open_existing(root, writer).unwrap(),
    )
}
fn busy(path: &Path) {
    let root = PrivateRoot::open(path).unwrap();
    assert!(matches!(
        root.try_configuration_writer(),
        Err(StoreError::Busy(LockResource::ConfigurationWriter))
    ));
}
fn claim_both(owner: &OwnedConfigurationRoot) -> OwnedEnrollmentJournal {
    let enrollment =
        OwnedEnrollmentJournal::from_configuration(owner.clone(), JournalBudget::default())
            .unwrap();
    owner
        .claim_namespace(NamespaceName::ManagementV1, JournalBudget::default())
        .unwrap();
    enrollment
}
fn add_megabyte(path: &Path, name: &str) {
    let f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path.join(name))
        .unwrap();
    f.set_len(1024 * 1024).unwrap();
}
#[test]
#[ignore = "requires STYX_TEST_CONFIGURATION_ROOT; owned real-FS two-namespace writer/fence/Unknown/budget aggregate"]
fn shared_configuration_writer_fence_and_sticky_unknown_batch() {
    let base = PathBuf::from(std::env::var("STYX_TEST_CONFIGURATION_ROOT").unwrap());
    fs::create_dir_all(&base).unwrap();
    let (path, owner) = fixture(&base);
    let mut enrollment = claim_both(&owner);
    assert!(matches!(
        OwnedEnrollmentJournal::from_configuration(owner.clone(), JournalBudget::default()),
        Err(JournalError::Conflict)
    ));
    assert_eq!(
        owner.claim_namespace(NamespaceName::ManagementV1, JournalBudget::default()),
        Err(JournalError::Conflict)
    );
    let clone = owner.clone();
    let clone = std::thread::spawn(move || {
        clone.ensure_usable().unwrap();
        clone
    })
    .join()
    .unwrap();
    busy(&path);
    drop(owner);
    busy(&path);
    assert_eq!(
        enrollment.with_journal(|j| j.read_time_floor()).unwrap(),
        Some(100)
    );
    let fence = clone
        .begin_maintenance("maintenance-original".try_into().unwrap())
        .unwrap();
    assert!(fence.matches(&clone));
    assert_eq!(fence.transaction_id().as_str(), "maintenance-original");
    assert_eq!(clone.ensure_admission(), Err(JournalError::Conflict));
    assert!(clone.ensure_usable().is_ok());
    assert_eq!(
        enrollment.with_journal(|_| Ok(())),
        Err(JournalError::Conflict)
    );
    assert!(matches!(
        clone.begin_maintenance("replacement".try_into().unwrap()),
        Err(JournalError::Conflict)
    ));
    drop(fence); // A dropped waiter cannot reopen the mutation gate.
    assert_eq!(clone.ensure_admission(), Err(JournalError::Conflict));
    busy(&path);
    drop(enrollment);
    busy(&path);
    drop(clone);
    let root = PrivateRoot::open(&path).unwrap();
    drop(root.try_configuration_writer().unwrap());
    drop(root);
    fs::remove_dir_all(&path).unwrap();

    // Unknown retained management bytes survive owner teardown: reopening is
    // inspection-only, not a fresh writer transaction or implicit recovery.
    let (path, owner) = fixture(&base);
    let retained = path
        .join(NamespaceName::ManagementV1.as_str())
        .join("unresolved-opaque");
    {
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&retained)
            .unwrap();
        file.write_all(b"?").unwrap();
        file.sync_all().unwrap();
    }
    drop(owner);
    for _ in 0..2 {
        let root = PrivateRoot::open(&path).unwrap();
        let writer = root.try_configuration_writer().unwrap();
        let reopened = OwnedConfigurationRoot::open_existing(root, writer).unwrap();
        assert!(reopened.ensure_usable().is_ok());
        assert_eq!(reopened.ensure_admission(), Err(JournalError::Conflict));
        assert!(matches!(
            reopened.begin_maintenance("new-transaction".try_into().unwrap()),
            Err(JournalError::Conflict)
        ));
        let mut enrollment = claim_both(&reopened);
        assert_eq!(
            enrollment.with_journal(|_| Ok(())),
            Err(JournalError::Conflict)
        );
        assert_eq!(fs::read(&retained).unwrap(), b"?");
        busy(&path);
        drop(enrollment);
        drop(reopened);
    }
    assert_eq!(fs::read(&retained).unwrap(), b"?");
    fs::remove_dir_all(&path).unwrap();

    // Corruption in either claimed namespace fences every handle. Restoring the
    // original directory pathname does not heal the in-process Unknown state.
    let (path, owner) = fixture(&base);
    let mut enrollment = claim_both(&owner);
    let management = path.join(NamespaceName::ManagementV1.as_str());
    let original = path.join("saved-management");
    fs::rename(&management, &original).unwrap();
    private_directory(&management);
    assert_eq!(
        enrollment.with_journal(|_| Ok(())),
        Err(JournalError::Unknown)
    );
    fs::remove_dir(&management).unwrap();
    fs::rename(&original, &management).unwrap();
    assert_eq!(owner.ensure_usable(), Err(JournalError::Unknown));
    assert_eq!(
        enrollment.with_journal(|j| j.read_time_floor()),
        Err(JournalError::Unknown)
    );
    busy(&path);
    drop(enrollment);
    drop(owner);
    fs::remove_dir_all(&path).unwrap();

    // A closure error must not suppress the post-check, including cross-
    // namespace replacement performed while the shared writer is held.
    let (path, owner) = fixture(&base);
    let mut enrollment = claim_both(&owner);
    let management = path.join(NamespaceName::ManagementV1.as_str());
    assert_eq!(
        enrollment.with_journal(|_| {
            fs::rename(&management, path.join("preserved-management")).unwrap();
            private_directory(&management);
            Err::<(), _>(JournalError::Conflict)
        }),
        Err(JournalError::Unknown)
    );
    assert_eq!(owner.ensure_usable(), Err(JournalError::Unknown));
    drop(enrollment);
    drop(owner);
    fs::remove_dir_all(&path).unwrap();

    // Each namespace stays below its own 64MiB cap; their aggregate exceeds the
    // configuration-root cap. Ordinary work must not enter, and deleting these
    // test-owned files afterwards must not silently clear the poison.
    let (path, owner) = fixture(&base);
    let mut enrollment = claim_both(&owner);
    for index in 0..33 {
        add_megabyte(
            &path.join(NamespaceName::EnrollmentV1.as_str()),
            &format!("opaque-{index}"),
        );
    }
    for index in 0..32 {
        add_megabyte(
            &path.join(NamespaceName::ManagementV1.as_str()),
            &format!("opaque-{index}"),
        );
    }
    let entered = std::sync::atomic::AtomicBool::new(false);
    assert_eq!(
        enrollment.with_journal(|_| {
            entered.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }),
        Err(JournalError::BudgetExceeded)
    );
    assert!(!entered.load(std::sync::atomic::Ordering::SeqCst));
    fs::remove_file(
        path.join(NamespaceName::ManagementV1.as_str())
            .join("opaque-0"),
    )
    .unwrap();
    assert_eq!(owner.ensure_usable(), Err(JournalError::Unknown));
    busy(&path);
    drop(enrollment);
    drop(owner);
    fs::remove_dir_all(&path).unwrap();
    println!(
        "configuration owned-FS aggregate: shared move-owned writer lifetime, singleton enrollment/management claims, two-namespace pin, dropped-maintenance sticky fence, closure-error postcheck, aggregate 65MiB budget poison, cleanup complete; NOT service/HTTP/legacy-writer acceptance"
    );
}
