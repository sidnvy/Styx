use super::*;

#[test]
fn original_unit_policy_and_unambiguous_scope_selection() {
    let layout = ServiceLayout {
        unit_name: "styx-host.service".into(),
        install_root: "/home/owner/styx/install".into(),
        host_config_file: "/home/owner/styx/device/host.json".into(),
        trust_public_key_file: "/home/owner/styx/publisher.pem".into(),
        node_binary: "/home/owner/styx/install/node".into(),
        restart_sec: 3,
    };
    let original = generated_unit(&layout, "exec");
    assert!(original.ends_with("WantedBy=default.target\n"));
    assert!(original.contains(
        "\nRestart=on-failure\nRestartSec=3\nTimeoutStopSec=12\nKillMode=control-group\n"
    ));
    assert_eq!(
        generated_unit(&layout, "simple"),
        original.replace("\nType=exec\n", "\nType=simple\n")
    );
    // Installed service selection never widens native transient check_scope.
    for valid in ["styx-host.service", "styx-vnext-pilot.service"] {
        assert!(unit_name(valid));
    }
    for invalid in [
        "ssh.service",
        "../styx-host.service",
        "styx-X.service",
        "styx-host.service\nOther=1",
        "styx-.service",
    ] {
        assert!(!unit_name(invalid));
    }
    for invalid in [
        "/home/owner/a b",
        "/home/owner/%n",
        "/home/owner/a/../b",
        "relative",
    ] {
        assert_eq!(
            safe_unit_path(Path::new(invalid)),
            Err(LegacyError::Unsupported)
        );
    }
    // No remote/unit text can choose shell quoting, argument expansion or paths.
    assert!(safe_unit_path(Path::new("/home/owner/styx/install/node")).is_ok());
}

#[test]
fn settlement_needs_all_original_physical_and_manager_facts() {
    assert_eq!(parse_cgroup_empty(b"populated 0\nfrozen 0\n"), Ok(true));
    assert_eq!(parse_cgroup_empty(b"populated 1\n"), Ok(false));
    for raw in [
        &b""[..],
        &b"populated 0\npopulated 1\n"[..],
        &b"populated 2\n"[..],
        &b"populated\n"[..],
        &b"\xff"[..],
    ] {
        assert!(parse_cgroup_empty(raw).is_err());
    }
    for absent in 0..3 {
        let observation = OriginalObservation {
            original_main_exited: absent != 0,
            original_cgroup_empty: absent != 1,
            manager_reported_success: absent != 2,
        };
        assert!(!observation.confirmed());
    }
    assert!(
        OriginalObservation {
            original_main_exited: true,
            original_cgroup_empty: true,
            manager_reported_success: true
        }
        .confirmed()
    );
    let unobserved = LegacySettlementObservation::registered();
    assert!(!unobserved.term_attempted && !unobserved.signal_accepted && !unobserved.worker_joined);
    // These are pure fact reduction/schema controls, not a native stop test.
}

#[test]
fn original_pidfd_distinguishes_live_read_failure_zombie_and_reaped_birth() {
    use std::io::Write as _;
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            self.0.stdin.take();
            let _ = self.0.wait();
        }
    }
    let mut child = Child(
        std::process::Command::new("/bin/sh")
            .args(["-c", "read line; exit 0"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .expect("owned child"),
    );
    let original = ProcessIdentity::observe(child.0.id()).expect("original birth");
    let pidfd = pidfd_open(
        Pid::from_raw(child.0.id() as i32).unwrap(),
        PidfdFlags::empty(),
    )
    .expect("original pidfd");
    assert!(original.still_current().unwrap());
    assert_eq!(
        observe_main_exit(&original, Some(&pidfd), || Err(LegacyError::Unknown)),
        Err(LegacyError::Unknown)
    );
    assert_eq!(
        observe_main_exit(&original, Some(&pidfd), || Err(LegacyError::Conflict)),
        Err(LegacyError::Conflict)
    );
    let exited = observe_main_exit(&original, Some(&pidfd), || {
        child.0.stdin.take().unwrap().write_all(b"exit\n").unwrap();
        use nix::poll::{PollFd, PollFlags, poll};
        let mut watched = [PollFd::new(pidfd.as_fd(), PollFlags::POLLIN)];
        assert_eq!(poll(&mut watched, 5000u16).unwrap(), 1);
        // Deliberately do not wait yet: /proc/stat retains the original birth
        // while /proc/exe is already gone. The production read really fails.
        assert!(original.still_current().unwrap());
        let error = File::open(format!("/proc/{}/exe", child.0.id())).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        Err(unknown(error))
    })
    .unwrap();
    assert!(!exited, "pidfd readiness is not final birth disappearance");
    assert!(
        !OriginalObservation {
            original_main_exited: exited,
            original_cgroup_empty: true,
            manager_reported_success: true
        }
        .confirmed()
    );
    assert!(child.0.wait().unwrap().success());
    assert!(!original.still_current().unwrap());
    assert!(
        observe_main_exit(&original, Some(&pidfd), || panic!(
            "reaped original is not live"
        ))
        .unwrap()
    );
}

#[test]
fn removed_held_directory_is_not_a_replacement_or_an_unreadable_live_scope() {
    let root = std::env::temp_dir().join(format!("styx-held-cgroup-race-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    let path = root.join("original");
    std::fs::create_dir(&path).unwrap();
    let held = File::open(&path).unwrap();
    let original = stat(&held).unwrap();
    let events_path = root.join("events");
    std::fs::write(&events_path, b"populated 0\n").unwrap();
    let events = File::open(&events_path).unwrap();
    assert_eq!(
        observe_held_cgroup(&held, &original, &events, || Err(LegacyError::Unavailable)),
        Err(LegacyError::Unavailable)
    );
    // Deterministically remove between held-nlink observation and pathname open.
    assert!(
        observe_held_cgroup(&held, &original, &events, || {
            std::fs::remove_dir(&path).unwrap();
            File::open(&path).map_err(unavailable)
        })
        .unwrap()
    );
    let replacement_path = root.join("replacement");
    std::fs::create_dir(&replacement_path).unwrap();
    let replacement = File::open(&replacement_path).unwrap();
    let replacement_stat = stat(&replacement).unwrap();
    assert_eq!(
        observe_held_cgroup(&replacement, &replacement_stat, &events, || {
            File::open(&root).map_err(unavailable)
        }),
        Err(LegacyError::Conflict)
    );
    std::fs::remove_dir(&replacement_path).unwrap();
    std::fs::remove_file(&events_path).unwrap();
    std::fs::remove_dir(&root).unwrap();
}
