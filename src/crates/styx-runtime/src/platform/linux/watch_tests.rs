//! Synthetic SDK messages and candidate deltas; no real bus/session mutation.
use super::*;
fn candidate_sample() -> LinuxCandidate {
    LinuxCandidate {
        session_id: "c7".into(),
        uid: 1000,
        seat: Some("seat0".into()),
        leader_pid: 1234,
        leader_birth: 9876,
        login_timestamp_monotonic: 4567,
        backend: "wayland".into(),
        active: true,
        state: "active".into(),
        locked_hint: false,
        compositor_association: Association::Unknown,
        agent_association: Association::Unknown,
    }
}
fn snapshot(candidates: Vec<LinuxCandidate>) -> LinuxDiscoverySnapshot {
    LinuxDiscoverySnapshot {
        schema: 1,
        login_unique_owner: ":1.7".into(),
        candidates,
        connection_closed: false,
    }
}
fn state() -> State {
    State {
        owner: ":1.7".into(),
        previous: vec![],
        sequence: 0,
    }
}
#[tokio::test]
async fn watcher_deltas_signals_backpressure_and_cancel_are_fenced_batch() {
    let original = candidate_sample();
    for mutate in 0..6 {
        let mut next = original.clone();
        let expected = match mutate {
            0 => {
                next.leader_birth += 1;
                InvalidationReason::IdentityChanged
            }
            1 => {
                next.login_timestamp_monotonic += 1;
                InvalidationReason::IdentityChanged
            }
            2 => {
                next.seat = Some("seat1".into());
                InvalidationReason::IdentityChanged
            }
            3 => {
                next.locked_hint = true;
                InvalidationReason::LockBoundary
            }
            4 => {
                next.active = false;
                InvalidationReason::PropertiesChanged
            }
            _ => {
                next.state = "closing".into();
                InvalidationReason::PropertiesChanged
            }
        };
        let items = changes(std::slice::from_ref(&original), std::slice::from_ref(&next));
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].reason, expected);
        assert_eq!(items[0].key, CandidateKey::from(&original));
    }
    let mut locked = original.clone();
    locked.locked_hint = true;
    assert_eq!(
        changes(&[locked], std::slice::from_ref(&original))[0].reason,
        InvalidationReason::LockBoundary,
        "unlock invalidates too"
    );
    assert_eq!(
        changes(std::slice::from_ref(&original), &[])[0].reason,
        InvalidationReason::Removed
    );
    let (events, mut receive) = mpsc::channel(QUEUE);
    let mut current = state();
    current
        .reconcile(&events, snapshot(vec![original.clone()]), 1000)
        .unwrap();
    let event = receive.recv().await.unwrap();
    assert_eq!(event.sequence, 1);
    let WatchChange::Snapshot { candidates, .. } = event.change else {
        panic!("snapshot");
    };
    assert_eq!(candidates[0].agent_association, Association::Unknown);
    assert_eq!(candidates[0].compositor_association, Association::Unknown);
    let before = current.previous.clone();
    let mut wrong_uid = original.clone();
    wrong_uid.uid = 1001;
    assert!(
        current
            .reconcile(&events, snapshot(vec![wrong_uid]), 1000)
            .is_err()
    );
    assert_eq!(current.previous, before);
    assert!(receive.try_recv().is_err());
    assert!(
        current
            .reconcile(
                &events,
                snapshot(vec![original.clone(); MAX_SESSIONS + 1]),
                1000
            )
            .is_err()
    );
    let mut other_owner = snapshot(vec![original.clone()]);
    other_owner.login_unique_owner = ":1.8".into();
    assert_eq!(
        current.reconcile(&events, other_owner, 1000),
        Err(WatchStop::SourceChanged)
    );
    current.reconcile(&events, snapshot(vec![]), 1000).unwrap();
    let invalid = receive.recv().await.unwrap();
    assert_eq!(invalid.sequence, 2);
    let WatchChange::Invalidations { items } = invalid.change else {
        panic!("invalidations");
    };
    assert_eq!(items[0].reason, InvalidationReason::Removed);
    assert!(matches!(
        receive.recv().await.unwrap().change,
        WatchChange::Snapshot { .. }
    ));

    let property = Message::signal(
        "/org/freedesktop/login1/session/c7",
        "org.freedesktop.DBus.Properties",
        "PropertiesChanged",
    )
    .unwrap()
    .sender(":1.7")
    .unwrap()
    .build(&(
        SESSION_INTERFACE,
        HashMap::from([("LockedHint", OwnedValue::from(false))]),
        Vec::<String>::new(),
    ))
    .unwrap();
    assert_eq!(
        signal_reason(&property, ":1.7").unwrap(),
        Some(InvalidationReason::LockBoundary)
    );
    assert_eq!(
        signal_reason(&property, ":1.8").unwrap(),
        None,
        "foreign signal cannot supply facts"
    );
    let removed = Message::signal(
        "/org/freedesktop/login1",
        "org.freedesktop.login1.Manager",
        "SessionRemoved",
    )
    .unwrap()
    .sender(":1.7")
    .unwrap()
    .build(&(
        "c7",
        OwnedObjectPath::try_from("/org/freedesktop/login1/session/c7").unwrap(),
    ))
    .unwrap();
    assert_eq!(
        signal_reason(&removed, ":1.7").unwrap(),
        Some(InvalidationReason::TopologyChanged),
        "signal hint cannot terminate unrelated candidates"
    );
    let owner = Message::signal(
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "NameOwnerChanged",
    )
    .unwrap()
    .sender("org.freedesktop.DBus")
    .unwrap()
    .build(&(LOGIN, ":1.7", ":1.8"))
    .unwrap();
    assert!(owner_changed(&owner, ":1.7").unwrap());

    let (events, _blocked) = mpsc::channel(QUEUE);
    let mut full = state();
    full.previous = vec![original];
    for _ in 0..QUEUE {
        full.invalidate(&events, InvalidationReason::PropertiesChanged)
            .unwrap();
    }
    assert_eq!(
        full.invalidate(&events, InvalidationReason::SourceLost),
        Err(WatchStop::Overflow),
        "terminal delivery cannot pretend success when full"
    );
    full.sequence = u64::MAX;
    assert_eq!(
        full.invalidate(&events, InvalidationReason::SourceLost),
        Err(WatchStop::SequenceExhausted)
    );
    let (events, receiver) = mpsc::channel(QUEUE);
    drop(receiver);
    let mut gone = state();
    gone.previous = full.previous;
    assert_eq!(
        gone.invalidate(&events, InvalidationReason::Cancelled),
        Err(WatchStop::ConsumerGone)
    );
    let cancel = CancellationToken::new();
    cancel.cancel();
    let (events, _receiver) = mpsc::channel(QUEUE);
    let closed = watch_current_user(events, cancel).await;
    assert!(closed.fenced);
    assert_eq!(closed.reason, WatchStop::Cancelled);
    assert!(
        !closed.connection_closed && !closed.sdk_tasks_joined,
        "pre-cancel never opened a bus or joined SDK tasks"
    );
    println!(
        "synthetic watcher SDK-message/delta batch: full identity and lock/unlock invalidation; owner replacement; atomic invalid snapshots; bounded overflow/EOF fence; no real logind subscription, Desktop or device operation"
    );
}
