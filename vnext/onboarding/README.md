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

Each configuration field has one authority. `deployment.json` is the desired
installation specification, changed only through reviewed migrations; `state.json` records progress and evidence. Generated
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
its persistent service; the installer refuses duplicate owners. Gateway start
enables user-login startup and stop disables it on Linux, macOS and Windows. Stop, disable and uninstall are fixed
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

## Architecture refactor development branch

`deployment.json` remains the sole desired deployment configuration. Omitting
`host` in `create-local` selects Gateway-only and requires `gateway.runtime`:
`{bundle,publisherKeyFile,publisherSha256,baseDir}`. The runtime root must be
independent from the Host root. Existing configurations with a Host remain valid;
`join-existing` rejects every local Gateway/runtime preparation field.
`roles.computer=requested` never establishes an OS grant or desktop readiness.
Linux Host preparation with requested Cua blocks without a graphical session;
Gateway preparation and execution have no desktop-permission precondition.

`gateway-release.mjs` builds a contained signed Gateway application with its
Node runtime, explicit production source closure and locked dependencies. It
contains no Codex/Cua executables, Host enrollment or onboarding Core. The normal
Core workflow prepares private identity/configuration, installs the signed
application, and generates the persistent service descriptor. The service uses
the installed signed runner, and can run after the publisher checkout disappears.
The Node-only `gateway-runtime.mjs build` artifact remains a source-checkout
preview; `gatewayServicePlan.application` distinguishes these two cases.

App `/api/service`, CLI `gateway-service` and background handoff now call the
same Core management API and journal. Gateway start enables user-session startup;
stop disables startup before stopping on all supported platforms. Unknown or
unconfirmed target state is `needs_attention`, never success inferred from a
command's exit code. `inspect STATE` and App status share fresh process/service
observations separately from `status STATE` historical step evidence. Neither is
a chat-account acceptance receipt. Unattended boot without login remains
unconfigured; these commands do not enable Linux linger or install root services.

Run `node vnext/onboarding/cli.mjs help` for fixed commands. Owner pairing links
are written to a new private local file instead of printed into command output.
The CLI can inspect/accept a link with exact origin/CA approval, list pending
requests, approve a full fingerprint/capability scope, and select the default
device through the same Core functions as App.

`device-ingress` and `verify-ingress` support the App's add-computer preflight.
The probe verifies the configured TLS endpoint and that unauthenticated access
to the owner enrollment route is rejected. Its scope is **current machine**;
it does not prove another computer can connect, open network interfaces, change
trust, create a relay, or perform two-ended short-code authentication. A reachable
entrypoint and independent joining-device verification remain prerequisites.
Certificate expiry is observed; automatic renewal is not implemented.

`runtime-plan STATE BUNDLE` and `runtime-rollback-plan STATE` produce reviewable
plans. Save the plan as an owner-private JSON file before `runtime-apply STATE
PLAN --authorize`. Updates require the Gateway service definition to be absent
and runtime processes independently confirmed stopped. They preserve deployment
identity, credentials, approval state and certificate bytes. Interrupted changes
are inspected with `runtime-change-status`; `runtime-recover STATE ID --authorize`
restores the previous verified generation without replaying service mutations.
Native manager observations, not an operator-supplied boolean, enforce the
preconditions. A failed/inaccessible observer blocks the change.

The native Mac supervisor is an explicit Team-ID-pinned opt-in. A new Mac Host
with `macTeamID` writes `service.json.nativeApp`; the native App `--host-service`
mode supervises the real Host Node launcher without starting Cua or settings.
Ad-hoc previews and old service definitions stay unchanged. The configured native
chain is `configured_unverified`; TCC responsibility remains **NOT RUN**.
Accessibility, Screen Recording and app-script Automation require distinct
native verification and user approval.

`native-migration-plan STATE TEAM_ID` reviews a legacy Mac configuration change.
`native-migration-apply STATE PLAN --authorize` requires a freshly observed absent
Host service and a verified signed App. It changes desired configuration, the
derived service descriptor, completed file-evidence hashes and existing auxiliary
journal scope together. Private before/after backups retain exact rollback bytes;
identity, pairing, credentials and system permission data are preserved. Three
shared mutation locks prevent concurrent onboarding/background/capability work.
`native-migration-rollback STATE ID --authorize` restores the reviewed original
configuration; it never replaces an installed/running native job.

These APIs are development results. Native compilation, signing/TCC attribution,
macOS/Windows reboot/login/update behavior, mixed-platform physical devices and
new-user chat-account acceptance must each be verified before a product release.

Host upgrades currently expose only `host-update-plan`, `host-rollback-plan` and
`host-update-status` through Core, CLI and App API. They verify signed generations,
configuration bindings, preserved identity hashes and existing update receipts
without writing files. Execution stays blocked: the common native adapter enables
persistence on start, some descriptors pin an old generation's Node, and Doctor's
version check is not real candidate Exec/connection health. No dummy start/health
callbacks are used to claim this lifecycle has been implemented.

### Existing macOS login recovery

For an existing signed Styx App, the authorized background transaction also installs
an Aqua-only LaunchServices waiter. It restarts the App after exit and leaves Cua
creation to that App. Headless Gateway/Host operation does not require it. Stop
login recovery before intentionally quitting the App for maintenance.

The owner-local CLI also supports `mac-login-recovery CONFIG ACTION [--authorize]`.
CONFIG is a private JSON file with absolute `appPath`, `logDir`, and optional
`tunnelRoot` for an existing external Bieber profile (`profiles/bieber.yaml` and
`bin/tunnel-client`). Actions: install, status, start, stop, uninstall. This command
never reads or prints tunnel secrets, replaces credentials, or edits the App bundle.
Keep the exact config for later status/stop/uninstall; foreign definitions fail closed.
Neither a running job nor a tunnel health response establishes account-side acceptance.

Recovery ownership is deliberately conservative. Both runtime and configuration
recovery hold an exclusive guard and verify PID, token and file identity before
adopting an abandoned transaction. A still-live owner is never displaced. If the
recovery process itself dies while holding its guard, status remains recovery
required and that guard needs explicit owner inspection; there is no blind
stale-lock deletion or guarantee of automatic recovery from every interruption.
