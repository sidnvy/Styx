//! Real owned-file/thread boundary checks, not cross-process guard transfer or
//! HTTP/native/profile acceptance. No separate filesystem implementation.
#![cfg(all(target_os = "linux", target_env = "gnu"))]
use super::*;
use crate::store::{LockResource, StoreError};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

fn owned_root(parent: &Path) -> PathBuf {
    let path = parent.join(uuid::Uuid::new_v4().to_string());
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}
fn initialize_namespace(path: &Path) {
    let root = PrivateRoot::open(path).unwrap();
    let mut writer = root.try_configuration_writer().unwrap();
    let mut journal =
        EnrollmentJournal::open(&root, &mut writer, JournalBudget::default()).unwrap();
    journal.record_time_floor(100).unwrap();
}
fn claim(path: &Path) -> OwnedEnrollmentJournal {
    let root = PrivateRoot::open(path).unwrap();
    let writer = root.try_configuration_writer().unwrap();
    OwnedEnrollmentJournal::open_existing(root, writer, JournalBudget::default()).unwrap()
}
fn assert_writer_busy(path: &Path) {
    let another = PrivateRoot::open(path).unwrap();
    assert!(matches!(
        another.try_configuration_writer(),
        Err(StoreError::Busy(LockResource::ConfigurationWriter))
    ));
}

#[test]
#[ignore = "requires STYX_TEST_ENROLLMENT_OWNED_ROOT; owned real-file same-process thread/lock/namespace scenario"]
fn owned_journal_thread_move_keeps_writer_and_initial_namespace_identity() {
    let base = PathBuf::from(std::env::var("STYX_TEST_ENROLLMENT_OWNED_ROOT").unwrap());
    fs::create_dir_all(&base).unwrap();
    let path = owned_root(&base);
    initialize_namespace(&path);
    let mut owner = claim(&path);
    assert_writer_busy(&path);
    // The type must actually move into an owned std thread. Kernel process
    // birth identity stays the same; no claim of fork/process transfer support.
    let main_pid = std::process::id();
    let (mut owner, reference) = std::thread::spawn(move || {
        assert_eq!(std::process::id(), main_pid);
        let reference = owner
            .with_journal(|journal| {
                assert_eq!(journal.read_time_floor()?, Some(100));
                journal.record_time_floor(101)?;
                journal.put_material(MaterialKind::Token, b"synthetic thread-owned bytes")
            })
            .unwrap();
        (owner, reference)
    })
    .join()
    .unwrap();
    assert_writer_busy(&path);
    assert_eq!(
        owner
            .with_journal(|journal| journal.read_material(&reference))
            .unwrap(),
        b"synthetic thread-owned bytes"
    );
    assert_eq!(
        owner.with_journal(|_| Err::<(), _>(JournalError::Conflict)),
        Err(JournalError::Conflict)
    );
    assert_writer_busy(&path);
    drop(owner);
    let root = PrivateRoot::open(&path).unwrap();
    let mut writer = root.try_configuration_writer().unwrap();
    let journal =
        EnrollmentJournal::open_existing(&root, &mut writer, JournalBudget::default()).unwrap();
    assert_eq!(journal.read_time_floor().unwrap(), Some(101));
    drop(writer);
    drop(root);

    // A plausible new private namespace at the same pathname is never adopted.
    let path = owned_root(&base);
    initialize_namespace(&path);
    let mut owner = claim(&path);
    let namespace = path.join(NAMESPACE);
    let saved = path.join("original-namespace-retained");
    fs::rename(&namespace, &saved).unwrap();
    fs::create_dir(&namespace).unwrap();
    fs::set_permissions(&namespace, fs::Permissions::from_mode(0o700)).unwrap();
    let entered = std::sync::atomic::AtomicBool::new(false);
    let result = owner.with_journal(|_| {
        entered.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    });
    assert_eq!(result, Err(JournalError::Unknown));
    assert!(!entered.load(std::sync::atomic::Ordering::SeqCst));
    assert!(fs::read_dir(&namespace).unwrap().next().is_none());
    assert_writer_busy(&path);
    drop(owner);
    // Explicitly restore only this test-owned original directory so a new owner
    // can observe the original durable bytes. No unknown directory is deleted.
    fs::rename(&namespace, path.join("replacement-namespace-retained")).unwrap();
    fs::rename(&saved, &namespace).unwrap();
    let mut reclaimed = claim(&path);
    assert_eq!(
        reclaimed.with_journal(|j| j.read_time_floor()).unwrap(),
        Some(100)
    );
    drop(reclaimed);

    // Post-check must run even when the closure returns an ordinary error.
    let path = owned_root(&base);
    initialize_namespace(&path);
    let mut owner = claim(&path);
    let result = owner.with_journal(|_| {
        fs::rename(
            path.join(NAMESPACE),
            path.join("namespace-replaced-inside-closure"),
        )
        .unwrap();
        fs::create_dir(path.join(NAMESPACE)).unwrap();
        fs::set_permissions(path.join(NAMESPACE), fs::Permissions::from_mode(0o700)).unwrap();
        Err::<(), _>(JournalError::Conflict)
    });
    assert_eq!(result, Err(JournalError::Unknown));
    drop(owner);

    // Move construction cannot use another root's configuration authority.
    let left = owned_root(&base);
    let right = owned_root(&base);
    initialize_namespace(&left);
    initialize_namespace(&right);
    let left_root = PrivateRoot::open(&left).unwrap();
    let right_root = PrivateRoot::open(&right).unwrap();
    let wrong_writer = right_root.try_configuration_writer().unwrap();
    assert!(matches!(
        OwnedEnrollmentJournal::open_existing(left_root, wrong_writer, JournalBudget::default()),
        Err(JournalError::Unknown)
    ));
    // Failed constructor consumed/dropped, rather than leaked, the wrong guard.
    right_root.try_configuration_writer().unwrap();
    println!(
        "Owned journal fixture={}: real std-thread move within same PID, second writer excluded, closure error preserves ownership, original namespace pin refuses replacement before/after closure, wrong-root guard refused, owner drop permits exact writer reacquisition; NOT cross-process/native/HTTP/profile acceptance",
        base.display()
    );
}
