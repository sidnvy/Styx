//! Argument boundaries only. Subprocess/OS effects belong to interop acceptance.
use super::*;
#[test]
fn cli_host_mode_requires_explicit_legacy_and_never_accepts_raw_credentials() {
    let cli =
        Cli::try_parse_from(["styx", "host", "run", "--state-dir", "/owned/private"]).unwrap();
    assert!(matches!(
        cli.command,
        Command::Host {
            command: HostCommand::Run {
                legacy_gateway: false,
                ..
            }
        }
    ));
    let cli = Cli::try_parse_from([
        "styx",
        "host",
        "run",
        "--state-dir",
        "/owned/private",
        "--legacy-gateway",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Command::Host {
            command: HostCommand::Run {
                legacy_gateway: true,
                ..
            }
        }
    ));
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
