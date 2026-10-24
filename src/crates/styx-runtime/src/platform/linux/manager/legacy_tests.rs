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
