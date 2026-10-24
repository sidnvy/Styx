//! Actual private-filesystem/service-gate composition; no invite or TLS action.
//! The held closure models the stage->persist interval under the real complete
//! SharedEnrollment method gate. It does not fabricate an enrollment mutation.
#![cfg(all(target_os = "linux", target_env = "gnu"))]

use super::SharedEnrollment;
use crate::{
    enrollment::service::EnrollmentService,
    store::{
        ConfigurationMaintenance, LockResource, PrivateRoot, StoreError,
        enrollment::{EnrollmentJournal, JournalBudget, OwnedEnrollmentJournal},
    },
};
use http::{HeaderMap, Method};
use std::{
    future::{Future, poll_fn},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::mpsc,
    task::Poll,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use styx_contracts::{
    enrollment::PairingContext,
    identity::{PairingIngressGeneration, Sha256Digest, TransactionId},
};
use styx_core::enrollment::Limits;
use tokio::{sync::oneshot, time::timeout};

const BOUND: Duration = Duration::from_secs(5);

fn fresh_service(path: &Path) -> SharedEnrollment {
    assert!(!path.exists(), "fixture must be fresh");
    std::fs::create_dir(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = PrivateRoot::open(path).unwrap();
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
        b"maintenance-test-admin-token-only-000000000000",
        Sha256Digest::of_bytes(b"distinct-ordinary-mcp-test-only"),
        vec!["maintenance.fixture.invalid".into()],
        Limits::default(),
    )
    .unwrap();
    SharedEnrollment::new(service)
}

fn writer_remains_busy(path: &Path) {
    assert!(matches!(
        PrivateRoot::open(path).unwrap().try_configuration_writer(),
        Err(StoreError::Busy(LockResource::ConfigurationWriter))
    ));
}

async fn assert_admission_fenced(shared: &SharedEnrollment) {
    let pair = PairingContext {
        origin: "https://maintenance.fixture.invalid".into(),
        leaf: Sha256Digest::of_bytes(b"not-an-actual-tls-certificate"),
        ingress_generation: PairingIngressGeneration::try_from("maintenance-ingress").unwrap(),
        window: None,
    };
    timeout(
        BOUND,
        shared.with(|service| {
            let profile_error = service
                .exec_profiles()
                .expect_err("new profile admission fenced");
            assert_eq!(profile_error.status(), 503);
            assert_eq!(profile_error.code(), "configuration_maintenance");
            let preflight_error = service
                .preflight(
                    &Method::GET,
                    "/v1/devices/pending",
                    &HeaderMap::new(),
                    &pair,
                )
                .expect_err("maintenance must reject before auth/route work");
            assert_eq!(preflight_error.status(), 503);
            assert_eq!(preflight_error.code(), "configuration_maintenance");
        }),
    )
    .await
    .unwrap()
    .unwrap();
    // This successful ordinary SharedEnrollment closure proves root fencing
    // does not turn SharedEnrollment::apply into a blanket rejection. There is
    // no valid ConnectionLease in this empty fixture: actual
    // host_connection_ended remains source-reviewed, not falsely exercised.
    assert_eq!(
        timeout(BOUND, shared.with(|_| 17u8))
            .await
            .unwrap()
            .unwrap(),
        17
    );
}

fn hold_complete_method(
    shared: SharedEnrollment,
) -> (
    oneshot::Receiver<()>,
    mpsc::SyncSender<()>,
    tokio::task::JoinHandle<()>,
) {
    let (entered_tx, entered_rx) = oneshot::channel();
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let job = tokio::task::spawn_blocking(move || {
        shared
            .blocking(|_| {
                entered_tx.send(()).unwrap();
                // A bounded blocking receiver is confined to spawn_blocking;
                // the async runtime is never blocked by Barrier/recv/sleep.
                release_rx.recv_timeout(BOUND).unwrap();
            })
            .unwrap();
    });
    (entered_rx, release_tx, job)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "actual private configuration root; STYX_TEST_CONFIGURATION_ROOT must name a fresh path"]
async fn actual_configuration_maintenance_complete_gate_and_dropped_waiter() {
    let base = PathBuf::from(
        std::env::var_os("STYX_TEST_CONFIGURATION_ROOT").expect("owned fixture root"),
    );
    assert!(
        base.is_absolute() && !base.exists(),
        "fresh absolute fixture root required"
    );
    std::fs::create_dir(&base).unwrap();
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();

    let path = base.join("complete-method");
    let shared = fresh_service(&path);
    let owner = timeout(BOUND, shared.with(|s| s.configuration_root()))
        .await
        .unwrap()
        .unwrap();
    assert!(owner.ensure_admission().is_ok());
    let (entered, release, holder) = hold_complete_method(shared.clone());
    timeout(BOUND, entered).await.unwrap().unwrap();
    let transaction = TransactionId::try_from("maintenance-complete-method").unwrap();
    let mut begin = Box::pin(shared.begin_configuration_maintenance(transaction.clone()));
    poll_fn(|cx| {
        assert!(
            begin.as_mut().poll(cx).is_pending(),
            "must wait for the whole existing method"
        );
        Poll::Ready(())
    })
    .await;
    assert_eq!(shared.jobs.available_permits(), 7);
    assert!(
        owner.ensure_admission().is_ok(),
        "fence cannot pass held service method"
    );
    release.send(()).unwrap();
    timeout(BOUND, holder).await.unwrap().unwrap();
    let maintenance: ConfigurationMaintenance = timeout(BOUND, begin).await.unwrap().unwrap();
    assert_eq!(maintenance.transaction_id(), &transaction);
    assert!(maintenance.matches(&owner));
    assert_eq!(
        maintenance.root_identity().unwrap(),
        owner.identity().unwrap()
    );
    assert_admission_fenced(&shared).await;
    writer_remains_busy(&path);

    let different = fresh_service(&base.join("different-owner"));
    let different_owner = timeout(BOUND, different.with(|s| s.configuration_root()))
        .await
        .unwrap()
        .unwrap();
    // Exercise the production capability-binding predicate; a same-shaped
    // transaction string cannot confer authority over another root/owner.
    assert!(!maintenance.matches(&different_owner));
    assert!(different_owner.ensure_admission().is_ok());
    drop(maintenance);
    assert!(
        owner.ensure_admission().is_err(),
        "Drop never resumes admission"
    );
    writer_remains_busy(&path);

    let dropped_path = base.join("dropped-waiter");
    let dropped = fresh_service(&dropped_path);
    let dropped_owner = timeout(BOUND, dropped.with(|s| s.configuration_root()))
        .await
        .unwrap()
        .unwrap();
    let (entered, release, holder) = hold_complete_method(dropped.clone());
    timeout(BOUND, entered).await.unwrap().unwrap();
    let mut abandoned = Box::pin(dropped.begin_configuration_maintenance(
        TransactionId::try_from("maintenance-dropped-waiter").unwrap(),
    ));
    poll_fn(|cx| {
        assert!(abandoned.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert_eq!(dropped.jobs.available_permits(), 7);
    drop(abandoned);
    assert_eq!(
        dropped.jobs.available_permits(),
        7,
        "waiter Drop cannot release active blocking-job slot"
    );
    let remaining = dropped.jobs.clone().try_acquire_many_owned(7).unwrap();
    let busy = timeout(
        BOUND,
        dropped.begin_configuration_maintenance(
            TransactionId::try_from("maintenance-capacity-refused").unwrap(),
        ),
    )
    .await
    .unwrap();
    assert!(busy.is_err(), "bounded admission cannot queue a ninth job");
    assert!(dropped_owner.ensure_admission().is_ok());
    release.send(()).unwrap();
    timeout(BOUND, holder).await.unwrap().unwrap();
    drop(remaining);
    // Acquiring every actual job permit waits for the detached spawn_blocking
    // closure to finish, including setting the real root fence; no sleep/poll
    // heuristic or fabricated completion channel substitutes for its lifetime.
    let all = timeout(BOUND, dropped.jobs.clone().acquire_many_owned(8))
        .await
        .unwrap()
        .unwrap();
    assert!(dropped_owner.ensure_admission().is_err());
    drop(all);
    assert_eq!(dropped.jobs.available_permits(), 8);
    assert_admission_fenced(&dropped).await;
    writer_remains_busy(&dropped_path);
    println!(
        "maintenance gate actual-filesystem complete; invite/TLS/host_connection_ended/native cutover NOT_RUN"
    );
}
