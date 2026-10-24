//! Pure verifier policy regression only. No service capture/stop or filesystem
//! signature acceptance is claimed by these assertions.
use super::*;

#[test]
fn gateway_definition_and_signed_member_boundary() {
    let state = Path::new("/home/owner/private state%fixture");
    let node = Path::new("/home/owner/gateway/install/node");
    let runner = Path::new(
        "/home/owner/gateway/install/releases/rc16/app/onboarding/gateway-signed-runner.mjs",
    );
    let (name, bytes) = unit(state, node, runner).unwrap();
    let identity = Sha256Digest::of_bytes(state.to_str().unwrap().as_bytes()).to_hex();
    assert_eq!(name, format!("styx-gateway-{}.service", &identity[..12]));
    let raw = std::str::from_utf8(&bytes).unwrap();
    assert!(raw.contains("ExecStart=\"/home/owner/gateway/install/node\" \"/home/owner/gateway/install/releases/rc16/app/onboarding/gateway-signed-runner.mjs\" \"/home/owner/private state%%fixture\"\n"));
    assert!(raw.contains("\nTimeoutStopSec=15\n"));
    assert!(!raw.contains("WorkingDirectory=") && !raw.contains("KillMode="));
    assert_eq!(
        quote(Path::new("/private/a\\b\"c%")).unwrap(),
        "\"/private/a\\\\b\\\"c%%\""
    );
    assert!(unit(Path::new("relative"), node, runner).is_err());
    assert!(unit(Path::new("/private/../other"), node, runner).is_err());
    assert!(unit(Path::new("/private/new\nunit"), node, runner).is_err());
    for member in [
        "app/onboarding/gateway-signed-runner.mjs",
        "app/node_modules/zod/v4/index.cjs",
        "app/node_modules/@modelcontextprotocol/sdk/dist/esm/client/index.js",
        "app/node_modules/package/node_modules/nested/lib/main.mjs",
        "licenses/node-LICENSE",
    ] {
        assert!(relative(member) && application_file(member), "{member}");
    }
    for member in [
        "host/launch.mjs",
        "bin/codex",
        "app/unrecognized-source.mjs",
        "app/node_modules/package/credentials/token.json",
        "app/node_modules/package/.env.json",
        "app/node_modules/package/runtime.node",
        "app/node_modules/@scope//index.js",
        "app/node_modules/package/node_modules/nested/node_modules/index.js",
    ] {
        assert!(!application_file(member), "{member}");
    }
    for member in [
        "/app/gateway/index.mjs",
        "app/../private.json",
        "app//gateway/index.mjs",
        "app\\gateway\\index.mjs",
    ] {
        assert!(!relative(member), "{member}");
    }
    assert!(version("0.3.0-rc.20261023.16"));
    assert!(!version("../foreign"));
    assert!(!version(""));
}
