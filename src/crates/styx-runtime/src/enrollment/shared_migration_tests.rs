//! Shared gate mechanics only. No committed cutover authority is fabricated;
//! the actual original migration scene supplies that opaque proof separately.
#![cfg(all(target_os = "linux", target_env = "gnu"))]
use super::*;
use crate::store::{
    PrivateRoot,
    enrollment::{EnrollmentJournal, JournalBudget, OwnedEnrollmentJournal},
};
use std::{
    os::unix::fs::PermissionsExt,
    time::{SystemTime, UNIX_EPOCH},
};
use styx_contracts::identity::{Sha256Digest, TransactionId};

fn ordinary_fixture() -> (SharedEnrollment, std::path::PathBuf) {
    let path = std::env::temp_dir().join(format!("styx-shared-epoch-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = PrivateRoot::open(&path).unwrap();
    let mut writer = root.try_configuration_writer().unwrap();
    {
        let mut journal =
            EnrollmentJournal::open(&root, &mut writer, JournalBudget::default()).unwrap();
        let now = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap();
        journal.record_time_floor(now).unwrap();
    }
    let journal =
        OwnedEnrollmentJournal::open_existing(root, writer, JournalBudget::default()).unwrap();
    let service = EnrollmentService::recover_existing(
        journal,
        b"shared-epoch-test-admin-token-0000000000000000",
        Sha256Digest::of_bytes(b"different-test-mcp-authority"),
        vec!["epoch.fixture.invalid".into()],
        styx_core::enrollment::Limits::default(),
    )
    .unwrap();
    (SharedEnrollment::new(service), path)
}

#[tokio::test(flavor = "current_thread")]
async fn shared_epoch_retires_queued_and_future_requests_without_reopening_old_gate() {
    let (old, path) = ordinary_fixture();
    let clone = old.clone();
    assert!(old.same_authority(&clone));
    assert_eq!(old.with(|_| 7).await.unwrap(), 7);
    old.close_readers();
    assert!(old.profiles().await.is_err());
    assert!(
        old.wait_readers(tokio::time::Instant::now() + std::time::Duration::from_secs(1))
            .await
    );
    // Model only the private gate publication while keeping the actual same
    // service. This does NOT exercise/claim a migration commit or promotion.
    let held = old.inner.lock().await;
    let queued_old = old.clone();
    let queued = tokio::spawn(async move {
        queued_old
            .with(|_| -> u8 { panic!("retired waiter entered service") })
            .await
    });
    tokio::task::yield_now().await;
    let mut current = old.clone();
    current.epoch = 2;
    current.jobs = Arc::new(tokio::sync::Semaphore::new(8));
    current.readers_closing = Arc::new(AtomicBool::new(false));
    old.active_generation.store(2, Ordering::Release);
    drop(held);
    assert!(queued.await.unwrap().is_err());
    assert!(Arc::ptr_eq(&old.inner, &current.inner));
    assert!(Arc::ptr_eq(&old.failed, &current.failed));
    assert!(!old.same_authority(&current));
    assert!(!old.same_authority(&clone));
    assert!(current.same_authority(&current.clone()));
    assert!(
        old.with(|_| -> u8 { panic!("retired request entered service") })
            .await
            .is_err()
    );
    assert!(old.profiles().await.is_err());
    assert!(
        old.begin_configuration_maintenance(
            TransactionId::try_from("retired-must-not-fence").unwrap()
        )
        .await
        .is_err()
    );
    let blocked = old.clone();
    assert!(
        tokio::task::spawn_blocking(move || blocked
            .blocking(|_| -> u8 { panic!("retired blocking request entered service") }))
        .await
        .unwrap()
        .is_err()
    );
    assert_eq!(current.with(|_| 11).await.unwrap(), 11);
    assert!(current.profiles().await.unwrap().is_empty());
    assert!(old.readers_closing.load(Ordering::Acquire));
    assert!(!current.readers_closing.load(Ordering::Acquire));
    assert!(!old.failed.load(Ordering::Acquire));
    drop(current);
    drop(clone);
    drop(old);
    std::fs::remove_dir_all(path).unwrap();
}
