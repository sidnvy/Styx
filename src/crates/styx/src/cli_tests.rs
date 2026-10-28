//! Argument boundaries only. Subprocess/OS effects belong to interop acceptance.
use super::*;
#[test]
fn cli_host_mode_rejects_legacy_gateway_and_raw_credentials() {
    let cli =
        Cli::try_parse_from(["styx", "host", "run", "--state-dir", "/owned/private"]).unwrap();
    assert!(matches!(
        cli.command,
        Command::Host {
            command: HostCommand::Run { .. }
        }
    ));
    assert!(
        Cli::try_parse_from([
            "styx",
            "host",
            "run",
            "--state-dir",
            "/owned/private",
            "--legacy-gateway",
        ])
        .is_err()
    );
    for option in ["--token", "--bearer", "--codex-bin", "--publisher-pin"] {
        assert!(
            Cli::try_parse_from([
                "styx",
                "host",
                "run",
                "--state-dir",
                "/owned/private",
                option,
                "untrusted"
            ])
            .is_err()
        );
    }
    assert!(Cli::try_parse_from(["styx", "host", "run"]).is_err());
    assert!(
        Cli::try_parse_from(["styx", "doctor", "--state-dir", "/owned/private", "--json"]).is_ok()
    );
    assert!(Cli::try_parse_from(["styx", "gateway", "run"]).is_ok());
}

#[test]
fn desktop_candidate_diagnostics_cannot_supply_authority_or_change_profile_mode() {
    let cli = Cli::try_parse_from(["styx", "doctor", "--desktop-sessions", "--json"]).unwrap();
    assert!(matches!(
        cli.command,
        Command::Doctor {
            state_dir: None,
            desktop_sessions: true,
            watch: false,
            json: true
        }
    ));
    assert!(Cli::try_parse_from(["styx", "doctor"]).is_err());
    assert!(
        Cli::try_parse_from([
            "styx",
            "doctor",
            "--desktop-sessions",
            "--state-dir",
            "/owned/private"
        ])
        .is_err()
    );
    for option in ["--uid", "--socket", "--session", "--display", "--grant"] {
        assert!(
            Cli::try_parse_from(["styx", "doctor", "--desktop-sessions", option, "untrusted"])
                .is_err()
        );
    }
}

#[test]
fn native_management_explicit_inputs_and_legacy_routes_are_separate_batch() {
    let init = Cli::try_parse_from([
        "styx",
        "init",
        "--parent-dir",
        "/owned/private",
        "--name",
        "fresh-native",
        "--deployment-file",
        "/owned/deployment.json",
        "--mode",
        "join-existing",
        "--manager",
        "foreground-cli",
        "--host",
        "--json",
    ])
    .unwrap();
    assert!(matches!(
        init.command,
        Command::Init {
            mode: NativeModeArg::JoinExisting,
            manager: NativeManagerArg::ForegroundCli,
            host: true,
            gateway: false,
            json: true,
            ..
        }
    ));
    let plan = [
        "styx",
        "plan",
        "--native",
        "--state-dir",
        "/owned/private",
        "--component",
        "host",
        "--run",
        "stopped",
        "--transaction-id",
        "native-17",
        "--sequence",
        "17",
        "--json",
    ];
    let parsed = Cli::try_parse_from(plan).unwrap();
    assert!(matches!(
        parsed.command,
        Command::Plan {
            native: true,
            component: Some(NativeComponentArg::Host),
            run: Some(NativeRunArg::Stopped),
            sequence: Some(17),
            ..
        }
    ));
    for missing in ["--component", "--run", "--transaction-id", "--sequence"] {
        let mut args = Vec::new();
        let mut skip = false;
        for arg in plan {
            if skip {
                skip = false;
                continue;
            }
            if arg == missing {
                skip = true;
                continue;
            }
            args.push(arg);
        }
        assert!(Cli::try_parse_from(args).is_err());
    }
    let without_native: Vec<_> = plan.into_iter().filter(|arg| *arg != "--native").collect();
    assert!(Cli::try_parse_from(without_native).is_err());
    for sequence in ["0", "-1", "18446744073709551616"] {
        let invalid: Vec<_> = plan
            .into_iter()
            .map(|arg| if arg == "17" { sequence } else { arg })
            .collect();
        assert!(Cli::try_parse_from(invalid).is_err());
    }
    assert!(
        Cli::try_parse_from([
            "styx",
            "apply",
            "--state-dir",
            "/owned/private",
            "--plan-file",
            "/owned/plan.json"
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from([
            "styx",
            "recover",
            "--state-dir",
            "/owned/private",
            "--transaction-id",
            "native-17"
        ])
        .is_err()
    );
    let apply = Cli::try_parse_from([
        "styx",
        "apply",
        "--state-dir",
        "/owned/private",
        "--plan-file",
        "/owned/plan.json",
        "--authorize",
        "--json",
    ])
    .unwrap();
    assert!(matches!(
        apply.command,
        Command::Apply {
            authorize: true,
            json: true,
            ..
        }
    ));
    let recover = Cli::try_parse_from([
        "styx",
        "recover",
        "--state-dir",
        "/owned/private",
        "--transaction-id",
        "native-17",
        "--authorize",
    ])
    .unwrap();
    assert!(matches!(
        recover.command,
        Command::Recover {
            authorize: true,
            ..
        }
    ));
    assert!(matches!(
        Cli::try_parse_from([
            "styx",
            "transaction",
            "--state-dir",
            "/owned/private",
            "--transaction-id",
            "native-17",
            "--json"
        ])
        .unwrap()
        .command,
        Command::Transaction { json: true, .. }
    ));
    assert!(matches!(
        Cli::try_parse_from([
            "styx",
            "status",
            "--native",
            "--state-dir",
            "/owned/private"
        ])
        .unwrap()
        .command,
        Command::Status { native: true, .. }
    ));
    assert!(matches!(
        Cli::try_parse_from(["styx", "status", "--state-dir", "/owned/private"])
            .unwrap()
            .command,
        Command::Status { native: false, .. }
    ));
    assert!(matches!(
        Cli::try_parse_from(["styx", "plan", "--state-dir", "/owned/private", "--json"])
            .unwrap()
            .command,
        Command::Plan {
            native: false,
            component: None,
            run: None,
            transaction_id: None,
            sequence: None,
            ..
        }
    ));
    for option in [
        "--token",
        "--bearer",
        "--publisher-pin",
        "--codex-bin",
        "--writer-stopped",
        "--adopt-legacy",
    ] {
        let mut args = vec![
            "styx",
            "apply",
            "--state-dir",
            "/owned/private",
            "--plan-file",
            "/owned/plan.json",
            "--authorize",
        ];
        args.extend([option, "untrusted"]);
        assert!(Cli::try_parse_from(args).is_err());
    }
    assert!(
        Cli::try_parse_from([
            "styx",
            "transaction",
            "--state-dir",
            "/owned/private",
            "--transaction-id",
            "native-17",
            "--authorize"
        ])
        .is_err()
    );
    let invalid_run: Vec<_> = plan
        .into_iter()
        .map(|arg| if arg == "stopped" { "auto" } else { arg })
        .collect();
    assert!(Cli::try_parse_from(invalid_run).is_err());
}

#[test]
fn release_verification_requires_external_pin_and_has_no_execution_overrides() {
    let pin = "a".repeat(64);
    let args = [
        "styx",
        "release",
        "verify",
        "--payload-dir",
        "/owned/payload",
        "--publisher-file",
        "/owned/trusted-publisher.pem",
        "--expected-publisher",
        pin.as_str(),
        "--json",
    ];
    assert!(matches!(
        Cli::try_parse_from(args).unwrap().command,
        Command::Release {
            command: ReleaseCommand::Verify { json: true, .. }
        }
    ));
    assert!(
        Cli::try_parse_from([
            "styx",
            "release",
            "verify",
            "--payload-dir",
            "/owned/payload",
            "--publisher-file",
            "/owned/trusted-publisher.pem"
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from([
            "styx",
            "release",
            "verify",
            "--payload-dir",
            "/owned/payload",
            "--expected-publisher",
            pin.as_str()
        ])
        .is_err()
    );
    for option in [
        "--key",
        "--private-key",
        "--entrypoint",
        "--binary",
        "--trust-package-key",
        "--install",
        "--run",
    ] {
        let mut invalid = args.to_vec();
        invalid.extend([option, "untrusted"]);
        assert!(Cli::try_parse_from(invalid).is_err());
    }
    // Release verification input is not a new Host publisher-policy override.
    assert!(
        Cli::try_parse_from([
            "styx",
            "host",
            "run",
            "--state-dir",
            "/owned/private",
            "--expected-publisher",
            pin.as_str()
        ])
        .is_err()
    );
}

#[test]
fn transient_manager_requires_explicit_mode_and_exact_stop_observation() {
    assert!(Cli::try_parse_from(["styx", "host", "start", "--state-dir", "/owned/state"]).is_err());
    assert!(
        Cli::try_parse_from([
            "styx",
            "host",
            "start",
            "--transient",
            "--state-dir",
            "/owned/state",
            "--json"
        ])
        .is_ok()
    );
    assert!(
        Cli::try_parse_from([
            "styx",
            "host",
            "status",
            "--transient",
            "--state-dir",
            "/owned/state"
        ])
        .is_ok()
    );
    assert!(
        Cli::try_parse_from([
            "styx",
            "host",
            "stop",
            "--transient",
            "--state-dir",
            "/owned/state"
        ])
        .is_err()
    );
    let stop = [
        "styx",
        "host",
        "stop",
        "--transient",
        "--state-dir",
        "/owned/state",
        "--owner-file",
        "/owned/owner.json",
        "--expected-invocation",
        "public-invocation",
    ];
    assert!(Cli::try_parse_from(stop).is_ok());
    for option in ["--unit", "--pid", "--token", "--exec-bin", "--bus-address"] {
        assert!(
            Cli::try_parse_from([
                "styx",
                "host",
                "start",
                "--transient",
                "--state-dir",
                "/owned/state",
                option,
                "untrusted"
            ])
            .is_err()
        );
    }
}

#[test]
fn cli_tunnel_requires_authorization_and_only_file_credentials() {
    let args = [
        "styx",
        "gateway",
        "tunnel",
        "configure",
        "--state-dir",
        "/private/gateway",
        "--tunnel-id",
        "tunnel_abcdefgh",
        "--api-key-file",
        "/private/key",
    ];
    assert!(Cli::try_parse_from(args).is_err());
    let mut authorized = args.to_vec();
    authorized.extend(["--auto-start", "--authorize", "--json"]);
    assert!(matches!(
        Cli::try_parse_from(authorized.clone()).unwrap().command,
        Command::Gateway {
            command: GatewayCommand::Tunnel {
                command: GatewayTunnelCommand::Configure {
                    auto_start: true,
                    authorize: true,
                    json: true,
                    ..
                }
            }
        }
    ));
    for flag in [
        "--api-key",
        "--key",
        "--binary",
        "--tunnel-client",
        "--proxy",
    ] {
        let mut invalid = authorized.clone();
        invalid.extend([flag, "untrusted"]);
        assert!(Cli::try_parse_from(invalid).is_err());
    }
    assert!(
        Cli::try_parse_from([
            "styx",
            "gateway",
            "tunnel",
            "status",
            "--state-dir",
            "/private/gateway",
            "--json"
        ])
        .is_ok()
    );
    let remove = [
        "styx",
        "gateway",
        "tunnel",
        "remove",
        "--state-dir",
        "/private/gateway",
    ];
    assert!(Cli::try_parse_from(remove).is_err());
    let mut authorized = remove.to_vec();
    authorized.extend(["--authorize", "--json"]);
    assert!(Cli::try_parse_from(authorized).is_ok());
}

#[test]
fn cli_role_retire_has_explicit_roots_and_authorization_boundary() {
    let cli = Cli::try_parse_from([
        "styx",
        "role",
        "retire",
        "--state-dir",
        "/owned/host",
        "--gateway-state-dir",
        "/owned/gateway",
        "--allow-other-devices",
        "--authorize",
        "--json",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Command::Role {
            command: RoleCommand::Retire {
                authorize: true,
                allow_other_devices: true,
                gateway_state_dir: Some(_),
                json: true,
                ..
            }
        }
    ));
    assert!(Cli::try_parse_from(["styx", "role", "retire", "--authorize", "--json"]).is_err());
    assert!(
        Cli::try_parse_from([
            "styx",
            "role",
            "retire",
            "--state-dir",
            "/owned/host",
            "--token",
            "secret"
        ])
        .is_err()
    );
}
#[tokio::test]
async fn cli_role_retire_refuses_without_authorize_before_opening_roots() {
    let cli = Cli::try_parse_from([
        "styx",
        "role",
        "retire",
        "--state-dir",
        "/nonexistent/host",
        "--json",
    ])
    .unwrap();
    assert_eq!(run(cli).await, ExitCode::from(2));
}
