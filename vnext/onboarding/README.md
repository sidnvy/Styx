# Deterministic onboarding development

This directory implements the next onboarding workflow. It is not included in
`v0.1.0-dev.20261019`, whose source remains pinned to d34fe57. It is not a shipped
cross-platform native graphical installer, public signing service or automatic
account login. A self-contained macOS preview launcher can bundle this core; see
[macOS installation](../docs/macos-preview-install.md).

## Ownership and trust

Codex explains choices and invokes fixed operations within the user's scope.
The local installer validates configuration, executes steps and journals actual
results. Gateway owns device registration and grants; device keys remain local.
The authenticated local UI is an owner control plane, not a model-facing MCP
admin tool. Platform login and native OS grants remain separate user actions.

Each configuration field has one authority. `deployment.json` is the immutable
installation specification; `state.json` records progress and evidence. Generated
Host and service configurations are bound by hashes before later actions. Native
service status is observed separately from the historical journal. Account-side
acceptance is never inferred from SDK discovery or a connected outbound socket.

## Entry points

Use trusted Node 22+ from this checked source, with locked dependencies installed
in vnext. No unverified bootstrap downloads or arbitrary browser-supplied commands
are executed. A trusted signed native bundle, publisher key and independently
confirmed fingerprint are still prerequisites; this workflow does not invent
public artifacts or silently trust a key downloaded beside a bundle.

Local browser setup:

    node vnext/onboarding/server.mjs --state ABS_PRIVATE_PARENT/NEW_STATE

Open the private local URL in a trusted browser. The random fragment bootstraps
that browser tab and is removed from navigation history. See ui/README.md for
fixed loopback binding, request authentication, CSRF and trusted forwarding.

CLI uses the SAME core:

    node vnext/onboarding/cli.mjs create ABS_PRIVATE_CONFIG ABS_NEW_STATE
    node vnext/onboarding/cli.mjs plan ABS_STATE
    node vnext/onboarding/cli.mjs status ABS_STATE
    node vnext/onboarding/cli.mjs advance ABS_STATE gateway.prepare gateway.start gateway.verify host.prepare
    node vnext/onboarding/cli.mjs advance ABS_STATE host.pair --approve-local-device

The approval flag authorizes the exact local device scope from the private plan;
it must not be supplied without the user's authorization for that device and
capabilities. `resume` accepts the same explicitly authorized step IDs. It does
not steal a crashed process lock or replay an uncertain side effect.

The `create-local` mode prepares private TLS, separate owner/model credentials,
an empty registry and native Host configuration. The default listener is
127.0.0.1. An explicit LAN profile may choose an IPv4 address actually assigned
to this computer, with separate permission to accept remote Host connections;
this does not configure router forwarding or establish public account reachability.
The owner must configure and verify an actual reachable deployment before
claiming remote device or account connectivity. A local development certificate
expires after 30 days; automatic production certificate renewal is not provided.

`join-existing` uses a reachable HTTPS origin and separately established trust.
There is no central shortcode discovery or network relay service. The owner can issue a short-lived pairing link. The receiving local UI inspects
the origin and optional CA fingerprint before explicit trust confirmation, then
writes private invitation/config references without exposing credentials to
chat or URLs sent to servers. Device fingerprint approval remains independent.
The private invitation-file path remains an advanced compatibility route. No SSH is required
by enrollment itself. The trusted SSH transport uses existing verified host keys,
a previously verified installed runtime, and stdin-only invitation delivery; it
is not an arbitrary remote installation mechanism.

## Services and maintenance

Host service actions follow signed preparation, scoped pairing and Doctor:

    node vnext/onboarding/cli.mjs host-service ABS_STATE install --authorize
    node vnext/onboarding/cli.mjs host-service ABS_STATE start --authorize
    node vnext/onboarding/cli.mjs host-service ABS_STATE status
    node vnext/onboarding/cli.mjs host-service ABS_STATE stop --authorize

Host start enables its user-session startup mechanism; stop disables recovery
and startup before stopping. Neither asserts actual tool health just because the
service manager reports running. macOS TCC and Windows interactive-session
requirements still apply. This is not a system/SYSTEM/root service installer.

Persistent Gateway uses an owned user service on Linux, a LaunchAgent on macOS,
and an interactive scheduled task on Windows:

    node vnext/onboarding/cli.mjs gateway-service ABS_STATE install --authorize
    node vnext/onboarding/cli.mjs gateway-service ABS_STATE start --authorize
    node vnext/onboarding/cli.mjs gateway-service ABS_STATE enable --authorize
    node vnext/onboarding/cli.mjs gateway-service ABS_STATE status

Stop the current process-owned foreground Gateway explicitly before starting
its persistent service; the installer refuses duplicate owners. Linux Gateway startup
and enablement are separate choices. On macOS and Windows, start also enables
login startup, and stop disables it. Stop, disable and uninstall are fixed
supported actions; uninstall preserves deployment/device state. The runner needs
the stable trusted source checkout and verified bundled Node. User-service start
at login is not unattended boot without a user session; linger is not changed.
These mechanisms require the owning user session; they do not install a system
service. Native isolated manager lifecycle checks have passed on all three
platforms; they are separate from account-side and GUI permission acceptance.

## Failure and acceptance boundaries

- A crash during a mutation leaves evidence and an uncertain step. Inspect actual
  state; do not delete a lock just to make a retry proceed.
- A failed native operation can leave partial installation. Preserve evidence;
  never claim rollback without verifying it.
- Gateway TLS discovery generates real native MCP tool evidence, scoped to SDK
  connectivity. Public reachability, tunnel ownership and account-side testing
  are separate checks.
- Browser tests using signed native artifacts cover local preparation, explicit
  pairing and Doctor. They do not grant OS permissions or prove account access.
- Owned native service pilots clean up only their unique test resources. Existing
  Charon/Chat-Codex installations are not removed by these development tests.

## Checks

    npm --prefix vnext run test:onboarding

Opt-in browser and native-service tests require explicit environment flags and
actual trusted binaries. Their defaults skip mutations. CI fixture receipts count
skips separately; an optional test is not reported as passed merely because it
was skipped. See ui/README.md and test files for the exact opt-in configuration.
