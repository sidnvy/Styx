//! Synthetic supervisor boundary controls, not native association/GUI evidence.
use super::*;
use crate::platform::linux::Association;
use watch::{Invalidation, InvalidationReason};

fn selected() -> LinuxCandidate {
    LinuxCandidate {
        session_id: "owned-session".into(),
        uid: 1000,
        seat: Some("seat0".into()),
        leader_pid: 42,
        leader_birth: 10,
        login_timestamp_monotonic: 20,
        backend: "wayland".into(),
        active: true,
        state: "active".into(),
        locked_hint: false,
        compositor_association: Association::Unknown,
        agent_association: Association::Unknown,
    }
}
fn observation(sequence: u64, change: WatchChange) -> WatchObservation {
    WatchObservation {
        stream_instance: AgentInstanceId::try_from("owned-watch".to_owned()).unwrap(),
        event: watch::WatchEvent {
            schema: 1,
            sequence,
            change,
        },
    }
}
#[test]
fn selected_source_never_falls_back_or_adopts_another_watch_generation() {
    let c = selected();
    let mut owner = None;
    let mut instance = None;
    let snapshot = |candidates| WatchChange::Snapshot {
        login_unique_owner: ":1.10".into(),
        candidates,
    };
    assert_eq!(
        accept_event(
            &c,
            &mut owner,
            &mut instance,
            &observation(1, snapshot(vec![c.clone()]))
        ),
        Ok(true)
    );
    let mut unrelated = c.clone();
    unrelated.session_id = "other-session".into();
    assert_eq!(
        accept_event(
            &c,
            &mut owner,
            &mut instance,
            &observation(2, snapshot(vec![c.clone(), unrelated.clone()]))
        ),
        Ok(true)
    );
    let invalidated = |candidate: &LinuxCandidate| WatchChange::Invalidations {
        items: vec![Invalidation {
            key: candidate.into(),
            reason: InvalidationReason::LockBoundary,
        }],
    };
    assert_eq!(
        accept_event(
            &c,
            &mut owner,
            &mut instance,
            &observation(3, invalidated(&unrelated))
        ),
        Ok(false)
    );
    assert_eq!(
        accept_event(
            &c,
            &mut owner,
            &mut instance,
            &observation(4, invalidated(&c))
        ),
        Err(DesktopSourceError::Fenced)
    );
    assert_eq!(
        accept_event(
            &c,
            &mut owner,
            &mut instance,
            &observation(5, snapshot(vec![unrelated]))
        ),
        Err(DesktopSourceError::Fenced)
    );
    let mut event = observation(6, snapshot(vec![c.clone()]));
    event.stream_instance = AgentInstanceId::try_from("replacement-watch".to_owned()).unwrap();
    assert_eq!(
        accept_event(&c, &mut owner, &mut instance, &event),
        Err(DesktopSourceError::Fenced)
    );
    let changed_owner = WatchChange::Snapshot {
        login_unique_owner: ":1.11".into(),
        candidates: vec![c],
    };
    assert_eq!(
        accept_event(
            &selected(),
            &mut owner,
            &mut instance,
            &observation(7, changed_owner)
        ),
        Err(DesktopSourceError::Fenced)
    );
    let state = State {
        fenced: AtomicBool::new(false),
        epoch: AtomicU64::new(1),
        lease: Mutex::new(None),
    };
    state.fence();
    state.fence();
    assert!(state.fenced.load(Ordering::Acquire));
    assert_eq!(state.epoch.load(Ordering::Acquire), 2);
}

#[tokio::test]
async fn cancelled_stop_waiter_retains_original_supervisor_join_handle() {
    let cancel = CancellationToken::new();
    let (release, released) = oneshot::channel();
    let (entered, entry) = oneshot::channel();
    let (requests, _rx) = mpsc::channel(1);
    let worker = tokio::spawn(async move {
        let _ = entered.send(());
        let _ = released.await;
        WatchReport {
            stream_instance: None,
            owned_worker_identity: None,
            fenced: true,
            reason: watch::ParentStop::Cancelled,
            child_reaped: false,
            worker_exit_success: None,
            stdout_eof: false,
            stdout_joined: true,
            worker_shutdown: None,
            final_invalidation_delivered: false,
        }
    });
    let source = DesktopSource {
        inner: Arc::new(Handle {
            state: Arc::new(State {
                fenced: AtomicBool::new(false),
                epoch: AtomicU64::new(1),
                lease: Mutex::new(None),
            }),
            cancel,
            requests,
            job: AsyncMutex::new(Some(worker)),
            terminal: Mutex::new(None),
        }),
    };
    entry.await.unwrap();
    let first = source.clone();
    let waiter = tokio::spawn(async move { first.stop().await });
    // Taking this same lock proves stop has reached its retained job slot after
    // its cancellation request; no sleep-based pretend cleanup is used.
    while !source.inner.cancel.is_cancelled() {
        tokio::task::yield_now().await;
    }
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    assert!(source.inner.job.lock().await.is_some());
    release.send(()).unwrap();
    let report = source.stop().await.unwrap();
    assert!(!report.child_reaped); // Synthetic job never attested an OS child.
    assert!(source.inner.job.lock().await.is_none());
    assert!(source.stop().await.is_ok());
}
