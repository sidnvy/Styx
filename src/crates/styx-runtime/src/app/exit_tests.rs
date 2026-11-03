//! Contract fixtures only; actual process/desktop acceptance is independent.
use super::*;
use crate::host::protocol::wire::TransportDrainOutcome;
use std::{fs, os::unix::fs::DirBuilderExt};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("styx-local-exit-{}", uuid::Uuid::new_v4()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    async fn app(&self) -> HostApp {
        HostApp::open(&self.0.join("profile"), &self.0.join("input.json"))
            .await
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn outcome() -> ForegroundOutcome {
    ForegroundOutcome {
        schema: 1,
        executor_started: true,
        executor_exited: true,
        processes_exited: true,
        io_tasks_joined: true,
        supervised_jobs_joined: true,
        remote_transport_drain: Some(TransportDrainOutcome::Unknown),
    }
}
fn raw() -> Box<serde_json::value::RawValue> {
    serde_json::value::to_raw_value(&json!({})).unwrap()
}

#[tokio::test]
async fn local_quit_joins_original_worker_and_events_and_preserves_remote_unknown() {
    let f = Fixture::new();
    let mut app = f.app().await;
    let cancel = CancellationToken::new();
    let observe_cancel = cancel.clone();
    let (worker_tx, worker_rx) = tokio::sync::oneshot::channel();
    let (events_tx, events_rx) = tokio::sync::oneshot::channel();
    app.running = Some(RunningHost {
        desktop_intent: None,
        cancel: cancel.clone(),
        worker: tokio::spawn(async move {
            worker_rx.await.unwrap();
            Ok(outcome())
        }),
        events: tokio::spawn(async move {
            events_rx.await.unwrap();
        }),
        _cancel_on_drop: cancel.drop_guard(),
    });
    let quitting = tokio::spawn(async move {
        let reply = app.dispatch(Operation::QuitAdmission, raw()).await;
        (app, reply)
    });
    observe_cancel.cancelled().await;
    assert!(!quitting.is_finished());
    worker_tx.send(()).unwrap();
    tokio::task::yield_now().await;
    assert!(!quitting.is_finished(), "events still owned");
    events_tx.send(()).unwrap();
    let (mut app, reply) = quitting.await.unwrap();
    let reply = reply.unwrap();
    assert_eq!(reply["quit"]["status"], "ready_to_quit");
    assert_eq!(reply["quit"]["scope"], "local_app");
    assert_eq!(reply["cleanup"]["remote_transport_drain"], "unknown");
    assert!(app.admission_fenced());
    assert!(app.available().is_err());
    assert!(app.dispatch(Operation::Connect, raw()).await.is_err());
    assert!(app.cleanup.as_ref().unwrap().local_stop_complete());
    assert!(!app.cleanup.as_ref().unwrap().is_complete());
    let name = format!(
        "app-local-exit-{}.json",
        reply["quit"]["ticketId"].as_str().unwrap()
    );
    let bytes = fs::read(f.0.join(&name)).unwrap();
    let receipt: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(receipt["remote_cleanup_confirmed"], false);
    assert_eq!(receipt["operations_replayed"], false);
    assert!(
        app.record_exit_uncertainty(reply["quit"]["ticketId"].as_str().unwrap())
            .await
            .is_err()
    );
    assert_eq!(
        fs::read(f.0.join(&name)).unwrap(),
        bytes,
        "immutable original receipt"
    );
    app.settle_for_quit().await.unwrap();
}

#[tokio::test]
async fn strict_control_refusal_does_not_destroy_local_facts_or_clear_other_unknowns() {
    let f = Fixture::new();
    let mut app = f.app().await;
    app.cleanup = Some(outcome());
    assert!(app.settle().await.is_err());
    assert!(app.available().is_err());
    assert!(!app.unknown, "remote uncertainty stays distinct");
    let reply = app.dispatch(Operation::QuitAdmission, raw()).await.unwrap();
    assert_eq!(reply["cleanup"]["remote_transport_drain"], "unknown");
    drop(app);
    let mut app = f.app().await;
    app.cleanup = Some(outcome());
    app.unknown = true;
    assert!(app.dispatch(Operation::QuitAdmission, raw()).await.is_err());
    assert!(app.unknown);
    assert!(app.quit_ticket.is_none());
}

#[tokio::test]
async fn incomplete_local_cleanup_never_admits_a_local_exit() {
    let f = Fixture::new();
    let mut app = f.app().await;
    let mut facts = outcome();
    facts.io_tasks_joined = false;
    let cancel = CancellationToken::new();
    app.running = Some(RunningHost {
        desktop_intent: None,
        cancel: cancel.clone(),
        worker: tokio::spawn(async move { Ok(facts) }),
        events: tokio::spawn(async {}),
        _cancel_on_drop: cancel.drop_guard(),
    });
    assert!(app.dispatch(Operation::QuitAdmission, raw()).await.is_err());
    assert!(app.unknown);
    assert!(app.quit_ticket.is_none());
    assert!(!fs::read_dir(&f.0).unwrap().any(|e| {
        e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("app-local-exit-")
    }));
}

#[tokio::test]
async fn remote_unknown_cannot_authorize_installation_handoff() {
    let _serial = super::super::maintenance::TEST_SERIAL.lock().await;
    let f = Fixture::new();
    let mut app = f.app().await;
    let install = f.0.join("Styx.app");
    fs::DirBuilder::new().mode(0o700).create(&install).unwrap();
    let request = serde_json::value::to_raw_value(&json!({"schema":1,"authorize":true,
        "operation":"upgrade","requestId":"1".repeat(32),"installRoot":install,
        "packageSha256":null,"candidatePackageSha256":null,"loginObservation":null}))
    .unwrap();
    app.dispatch(Operation::PrepareAppMaintenance, request)
        .await
        .unwrap();
    app.cleanup = Some(outcome());
    assert!(app.dispatch(Operation::QuitAdmission, raw()).await.is_err());
    assert!(app.quit_ticket.is_none());
    assert!(app.admission_fenced());
}

#[tokio::test]
async fn local_stop_exception_cannot_start_work_and_pause_receipt_keeps_unknown() {
    let f = Fixture::new();
    let mut app = f.app().await;
    app.cleanup = Some(outcome());
    assert!(
        app.set_desired_for(NativeRunDesired::Running, true)
            .await
            .is_err()
    );
    app.record_pause_uncertainty(&"2".repeat(32)).await.unwrap();
    let receipt: Value = serde_json::from_slice(
        &fs::read(f.0.join(format!("app-local-pause-{}.json", "2".repeat(32)))).unwrap(),
    )
    .unwrap();
    assert_eq!(receipt["kind"], "app_host_pause");
    assert_eq!(receipt["host_cleanup"]["remote_transport_drain"], "unknown");
    assert!(app.available().is_err());
}
