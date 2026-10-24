//! Targeted source/association controls, not native UWSM/Desktop acceptance.
use super::super::Association;
use super::*;

fn candidate() -> LinuxCandidate {
    LinuxCandidate {
        session_id: "test-login".into(),
        uid: 1000,
        seat: Some("seat0".into()),
        leader_pid: 42,
        leader_birth: 7,
        login_timestamp_monotonic: 9,
        backend: "wayland".into(),
        active: true,
        state: "active".into(),
        locked_hint: false,
        compositor_association: Association::Unknown,
        agent_association: Association::Unknown,
    }
}
fn process(cgroup: &str) -> ProcessFact {
    ProcessFact {
        pid: 43,
        birth: 8,
        uid: 1000,
        proc_device: 1,
        proc_inode: 2,
        cgroup: cgroup.into(),
    }
}
fn unit(name: &str) -> UnitFact {
    UnitFact{name:name.into(),path:OwnedObjectPath::try_from("/org/freedesktop/systemd1/unit/test").unwrap(),invocation:vec![1;16],cgroup:"/user.slice/user-1000.slice/user@1000.service/session.slice/wayland-wm@hyprland.desktop.service".into(),main_pid:Some(43),binds:vec![],wants:vec![],on_success:vec![],on_failure:vec![],conflicts:vec![],restart:Some("no".into()),service_type:Some("notify".into()),bind_start:None}
}
#[test]
fn exact_uwsm_chain_refuses_cross_target_and_unrecognized_anchor() {
    let mut c = candidate();
    assert!(check_candidate(&c, 1000).is_ok());
    // Candidate Unknown is preserved; it cannot itself register any Agent.
    assert_eq!(c.compositor_association, Association::Unknown);
    assert_eq!(
        check_candidate(&c, 1001),
        Err(AssociationError::Unsupported)
    );
    c.locked_hint = true;
    assert_eq!(check_candidate(&c, 1000), Err(AssociationError::Inactive));
    c.locked_hint = false;
    c.seat = None;
    assert_eq!(
        check_candidate(&c, 1000),
        Err(AssociationError::Unsupported)
    );
    let argv = vec![
        "/bin/sh".into(),
        "/usr/lib/uwsm/signal-handler.sh".into(),
        "wayland-session-envelope@hyprland.desktop.target".into(),
    ];
    assert_eq!(anchor_envelope(&argv).unwrap(), "hyprland.desktop");
    let mut wrong = argv.clone();
    wrong.push("arbitrary argument".into());
    assert!(anchor_envelope(&wrong).is_err());
    wrong = argv.clone();
    wrong[1] = "/tmp/signal-handler.sh".into();
    assert!(anchor_envelope(&wrong).is_err());
    wrong = argv;
    wrong[2] = "wayland-session-envelope@../other.target".into();
    assert!(anchor_envelope(&wrong).is_err());
    assert_eq!(one(vec![1, 2]), Err(AssociationError::Ambiguous));
    assert_eq!(one(Vec::<u8>::new()), Err(AssociationError::Unavailable));
    let wm = unit("wayland-wm@hyprland.desktop.service");
    assert!(belongs(&process(&wm.cgroup), &wm, 1000));
    assert!(belongs(
        &process(&(wm.cgroup.clone() + "/owned-child")),
        &wm,
        1000
    ));
    assert!(!belongs(
        &process(&(wm.cgroup.clone() + "-another")),
        &wm,
        1000
    ));
    assert!(!belongs(&process(&wm.cgroup), &wm, 1001));
    let mut changed = process(&wm.cgroup);
    let original = changed.clone();
    changed.birth += 1;
    assert_eq!(same(&original, &changed), Err(AssociationError::Changed));
    changed = original.clone();
    changed.proc_inode += 1;
    assert!(same(&original, &changed).is_err());
}
#[test]
fn effective_unit_binding_and_same_uid_do_not_substitute_for_exact_invocation() {
    let shutdown = "wayland-session-shutdown.target".to_owned();
    let mut bind = unit("wayland-session-bindpid@42.service");
    bind.service_type = Some("exec".into());
    bind.on_success = vec![shutdown.clone()];
    bind.on_failure = vec![shutdown.clone()];
    bind.conflicts = vec![shutdown.clone()];
    bind.bind_start=Some(vec![("/bin/sh".into(),vec!["/bin/sh".into(),"-c".into(),"if command -v waitpid >/dev/null; then exec waitpid -e 42; else exec /usr/bin/uwsm aux waitpid 42; fi".into(),"waitpid".into()],false,0,0,0,0,0,0,0)]);
    let mut wm = unit("wayland-wm@hyprland.desktop.service");
    wm.binds = vec!["wayland-session@hyprland.desktop.target".into()];
    wm.on_success = vec![shutdown.clone()];
    wm.on_failure = vec![shutdown.clone()];
    wm.wants = vec!["wayland-session-envelope@hyprland.desktop.target".into()];
    let mut env = unit("wayland-wm-env@hyprland.desktop.service");
    env.service_type = Some("oneshot".into());
    env.binds = vec!["wayland-session-pre@hyprland.desktop.target".into()];
    let mut envelope = unit("wayland-session-envelope@hyprland.desktop.target");
    envelope.binds = vec![wm.name.clone(), env.name.clone()];
    envelope.conflicts = vec![shutdown];
    assert!(check_units(&bind, &envelope, &wm, &env, "hyprland.desktop").is_ok());
    let mut wrong = envelope.clone();
    wrong.binds = vec!["wayland-wm@other.desktop.service".into(), env.name.clone()];
    assert!(check_units(&bind, &wrong, &wm, &env, "hyprland.desktop").is_err());
    let mut wrong = bind.clone();
    wrong.bind_start.as_mut().unwrap()[0].1[2] = "waitpid -e 99".into();
    assert!(check_units(&wrong, &envelope, &wm, &env, "hyprland.desktop").is_err());
    let mut wrong = wm.clone();
    wrong.restart = Some("always".into());
    assert!(check_units(&bind, &envelope, &wrong, &env, "hyprland.desktop").is_err());
    let mut replacement = wm.clone();
    replacement.invocation[0] = 2;
    assert_eq!(same(&wm, &replacement), Err(AssociationError::Changed));
}
#[test]
fn kernel_process_observation_retains_birth_and_rejects_zombie_or_malformed_stat() {
    // Actual read-only current-process observation. No GUI, child or service.
    let (pin, first) = proc_read(std::process::id()).unwrap();
    let (_, again) = proc_read(std::process::id()).unwrap();
    assert_eq!(first, again);
    assert_eq!(pin.metadata().unwrap().ino(), first.proc_inode);
    let mut wrong = first.clone();
    wrong.birth += 1;
    assert_eq!(same(&first, &wrong), Err(AssociationError::Changed));
    assert!(parse_stat(b"42 (a tricky ) name) Z 1 2 3").is_err());
    assert!(parse_stat(b"malformed").is_err());
}

#[tokio::test]
async fn window_read_requires_typed_complete_reply_and_preserves_no_window_content() {
    // Synthetic owned bytes/streams only, not a compositor or GUI acceptance.
    let monitors=br#"[{"id":0,"name":"owned-monitor","width":1920,"height":1080,"scale":1.0,"activeWorkspace":{"id":1},"specialWorkspace":{"id":0}}]"#;
    let monitor = decode_window_reply(WindowQuery::Monitors, monitors).unwrap();
    assert_eq!(monitor.object_count, 1);
    assert_eq!(monitor.raw_sha256, Sha256Digest::of_bytes(monitors));
    let clients=br#"[{"address":"0x123","pid":42,"mapped":true,"hidden":false,"at":[0,0],"size":[100,100],"workspace":{"id":1},"title":"private-owned-title","class":"private-owned-class"}]"#;
    let read = decode_window_reply(WindowQuery::Clients, clients).unwrap();
    assert_eq!(read.object_count, 1);
    let encoded = serde_json::to_string(&read).unwrap();
    assert!(!encoded.contains("private-owned"));
    assert!(!encoded.contains("title"));
    assert_eq!(
        decode_window_reply(WindowQuery::Clients, b"[]")
            .unwrap()
            .object_count,
        0
    );
    for bad in [
        b"".as_slice(),
        b"null",
        b"{}",
        b"[{}]",
        b"[{",
        b"[] trailing",
    ] {
        assert!(decode_window_reply(WindowQuery::Monitors, bad).is_err());
        assert!(decode_window_reply(WindowQuery::Clients, bad).is_err());
    }
    assert!(decode_window_reply(WindowQuery::Monitors, b"[]").is_err());
    assert!(matches!(
        decode_window_reply(WindowQuery::Clients, &vec![b' '; CLIENTS_REPLY + 1]),
        Err(AssociationError::Capacity)
    ));
    let (mut sender, mut receiver) = tokio::io::duplex(64);
    sender.write_all(b"[]").await.unwrap();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(5),
            read_window_reply(WindowQuery::Clients, &mut receiver)
        )
        .await
        .is_err(),
        "valid prefix without EOF cannot become success"
    );
    drop(sender);
    drop(receiver); // No partial-read replay on the same stream.
    let (mut sender, mut receiver) = tokio::io::duplex(64);
    sender.write_all(b"[]").await.unwrap();
    drop(sender);
    assert_eq!(
        read_window_reply(WindowQuery::Clients, &mut receiver)
            .await
            .unwrap()
            .object_count,
        0
    );
    let (mut sender, mut receiver) = tokio::io::duplex(64);
    sender.write_all(b"[{").await.unwrap();
    drop(sender);
    assert!(
        read_window_reply(WindowQuery::Clients, &mut receiver)
            .await
            .is_err()
    );
}

fn source_facts() -> AssociationFacts {
    let peer = process("/owned/compositor");
    let endpoint = EndpointFact {
        path: PathBuf::from("/run/user/1000/owned-test-socket"),
        device: 1,
        inode: 3,
        peer: peer.clone(),
    };
    let query = |query| QueryReadEvidence {
        query,
        object_count: 1,
        raw_bytes: 2,
        raw_sha256: Sha256Digest::of_bytes(b"[]"),
    };
    AssociationFacts {
        schema: 1,
        boot: "synthetic-boot".into(),
        uid: 1000,
        candidate: candidate(),
        login_owner: ":1.1".into(),
        manager_owner: ":1.2".into(),
        manager_process: peer.clone(),
        leader: process("/owned/login"),
        anchor: process("/owned/anchor"),
        anchor_argv: vec!["/owned/anchor".into()],
        bind: unit("bind"),
        envelope: unit("envelope"),
        wm: unit("wm"),
        wm_env: unit("wm-env"),
        bind_process: process("/owned/bind"),
        wm_main: peer.clone(),
        wayland: endpoint.clone(),
        hyprland: endpoint.clone(),
        hyprland_events: endpoint,
        window_read: WindowReadEvidence {
            schema: 1,
            peer,
            socket_device: 1,
            socket_inode: 3,
            monitors: query(WindowQuery::Monitors),
            clients: query(WindowQuery::Clients),
        },
        sources: vec![SourceFact {
            path: PathBuf::from("/owned/source"),
            device: 1,
            inode: 4,
            digest: Sha256Digest::of_bytes(b"fixed source"),
        }],
    }
}

#[test]
fn fresh_source_comparison_preserves_identity_but_not_window_contents() {
    // Synthetic source boundary only, not a native collector/Agent attestation.
    let lease = |facts| LinuxAssociationLease {
        facts,
        _kernel_pins: vec![],
        _endpoints: vec![],
    };
    let original = source_facts();
    let held = lease(original.clone());
    let mut fresh = original.clone();
    fresh.window_read.clients.object_count += 1;
    fresh.window_read.clients.raw_sha256 = Sha256Digest::of_bytes(b"changed windows");
    assert!(held.same_source(&lease(fresh)));
    let mutations: &[fn(&mut AssociationFacts)] = &[
        |f| f.boot.push('x'),
        |f| f.uid += 1,
        |f| f.candidate.session_id.push('x'),
        |f| f.candidate.locked_hint = true,
        |f| f.leader.birth += 1,
        |f| f.login_owner.push('x'),
        |f| f.manager_owner.push('x'),
        |f| f.manager_process.birth += 1,
        |f| f.anchor_argv.push("changed".into()),
        |f| f.bind.invocation[0] += 1,
        |f| f.envelope.invocation[0] += 1,
        |f| f.wm.invocation[0] += 1,
        |f| f.wm_env.invocation[0] += 1,
        |f| f.wm.cgroup.push('x'),
        |f| f.wm_main.birth += 1,
        |f| f.wayland.inode += 1,
        |f| f.hyprland.inode += 1,
        |f| f.hyprland_events.inode += 1,
        |f| f.sources[0].digest = Sha256Digest::of_bytes(b"changed source"),
    ];
    for mutate in mutations {
        let mut changed = original.clone();
        mutate(&mut changed);
        let changed = lease(changed);
        assert!(!held.same_source(&changed));
        assert!(!changed.same_source(&held));
    }
    let evidence = held.window_read_evidence();
    assert_eq!(evidence.source_peer(), (43, 8));
    assert_eq!(evidence.socket_identity(), (1, 3));
    assert_eq!(evidence.query_counts(), (1, 1));
    assert_eq!(evidence.response_sha256().0, Sha256Digest::of_bytes(b"[]"));
}
