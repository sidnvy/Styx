# Styx.app release candidate: packaging and native gates

The stable host identity is `app.styx.host`, executable `Styx`, bundle
`Styx.app`. The native AppKit menu bar application directly spawns its bundled
`cua-driver serve --embedded --socket` child. The existing user LaunchAgent
owns the outbound Host connector only; it must not start the native daemon.
Gateway clients use the existing `computerMcpArgs` path with `mcp --embedded
--socket`. There is no new Cua protocol or permission transfer through a Gateway.

This implements the daemon host arrangement in the pinned upstream
[Cua 0.36.0 embedding contract](https://github.com/trycua/cua/blob/cua-driver-rs-v0.36.0/libs/cua-driver/rust/Skills/cua-driver/EMBEDDING.md).
App Sandbox entitlements do not establish TCC responsibility; this bundle is
not sandboxed. It adds no unrestricted/bypass flag. Its child environment is
allowlisted and selects the upstream `standard` runtime mode. Residual native
approval boundaries still follow Cua; unsupported approval cases must fail.

## Precompiled preview without Apple membership

A downloadable macOS preview can be compiled and packaged by the project without
Developer ID or notarization. Ad-hoc code signing seals the bundle but does not
identify an Apple-verified publisher. This is distinct from the optional
Developer ID distribution path below; it must not be labeled notarized.

Users do not need Xcode, Node, a developer account or a local source build for a
self-contained preview. The bundle supplies its own runtime, Host payload and
local onboarding interface. Gatekeeper may require the user to explicitly allow
this particular app in System Settings. Do not disable Gatekeeper globally or
instruct users to recursively remove quarantine. Managed devices can disallow
such exceptions. Native Accessibility and Screen Recording grants remain
separate from first-launch approval.

See [macOS preview installation](macos-preview-install.md) for the end-user flow.

## Build on the target Mac

Use Node >=22, Xcode command line tools, and a trusted, native architecture
Cua Driver 0.36.0 executable. No driver is downloaded by the builder. Native
compilation targets macOS 13.0. Build on each required architecture; the builder
does not claim a universal binary. Put this JSON outside the output directory:

```json
{
  "app": "/absolute/staging/Styx.app",
  "cuaBinary": "/absolute/trusted/cua-driver",
  "version": "0.1.0"
}
```

Run `node vnext/host/build-macos-app.mjs /absolute/build-config.json`.
The output path and companion notarization archive must not already exist.
Without signing fields this is an **UNSIGNED development build**. The external
`Styx.app.build.json` receipt explicitly records signing, notarization and
physical acceptance boundaries. A partial failed bundle is preserved for
inspection and is not a release artifact.

For a publisher build add `identity` (the exact Developer ID Application
identity), `teamID` (10 uppercase letters/digits) and `notaryProfile` (a
previously configured `notarytool` keychain profile). Credentials are never
accepted in the JSON. The builder signs nested Cua first, then the enclosing
app with hardened runtime and timestamp; verifies the sealed code and exact
bundle/team requirement; submits an archive and requires `Accepted`; staples,
validates and assesses the resulting app with Gatekeeper. It never mutates
source Cua or the bundle after signing. Ed25519 Host payload signatures remain
a separate existing installer mechanism.

No signing/notarization runs occur in pull-request CI. The dedicated macOS
workflow compiles the actual Swift source and runs the ownership self-test
without starting AppKit or requesting grants. A separate headless test starts the
checksum-pinned native Cua through the exact production helper, kills only its
own test owner subprocess, and checks both daemon exit and socket removal. It
invokes no GUI tool and does not verify TCC. CI must pass for the current commit.

## Local operator flow and connection boundary

Install the finished bundle at a stable `/Applications/Styx.app` path and launch
it through Finder/LaunchServices (`open /Applications/Styx.app`). Do not launch
`Contents/MacOS/Styx` from a terminal for TCC acceptance. Open the Styx menu
and select **Request macOS permissions…** to invoke the two OS-owned permission
requests. Complete grants manually in System Settings. Quit and reopen Styx
when grants change. Neither packaging nor the Host LaunchAgent grants TCC.

A private `/tmp/styx-cua-<uid>` directory must belong to the login user, be a
real directory, and deny group/other access. A nonblocking exclusive lock
allows one owner generation; unsafe paths and public lock files are rejected.
Only that owner removes its socket/descriptor. Startup refuses a pre-existing
socket instead of unlinking a possibly live orphan; inspect and stop that
owned daemon before manually removing a stale socket. The app advertises a fresh
`connection.json` after a connection to `cua.sock` succeeds. This is only
`socket_accepting`, not a successful MCP initialize, attribution or GUI test.
The descriptor is private and contains no bearer credential. Same-UID code is
inside the local trust boundary. Do not expose the socket over TCP.

Configure the Host's `computer.binary` to the installed app's
`Contents/MacOS/cua-driver`, and `computer.socket` to the descriptor's exact
socket path, using the existing trusted Host config. The connector may attach
MCP proxies but cannot own/restart the daemon. Record the descriptor generation
when collecting acceptance evidence. Restart invalidates all old sessions and
requires new MCP connections, even though the private pathname is stable.

Quit/SIGTERM/SIGINT withdraws the descriptor, terminates the child, waits up to
three seconds for EOF shutdown, then sends SIGTERM and, after one further
second, SIGKILL only to its owned child, waits for exit and removes its socket.
Unexpected daemon exit invalidates the descriptor and requires an explicit
menu restart. A permission-state change withdraws the generation and asks for
an app relaunch. Interrupted GUI actions are never replayed automatically.

## Notarized production release gates still blocked / NOT RUN

Linux contract tests do not satisfy any native acceptance gate. Before calling
Milestone C a release candidate, retain actual evidence for:

- Native Swift compilation and ownership self-test on arm64 and x86_64 Macs.
- Trusted Developer ID signing, accepted notarization, stapled/validated ticket,
  Gatekeeper assessment and a fresh download/quarantine installation.
- A real login-session LaunchServices parent chain: `health_report` including
  `bundle_identity` must report the expected app ID, parent PID and
  `parent_application` identity source. `check_permissions` must independently
  report host attribution, embedded mode and the expected host bundle.
- User-approved Accessibility/Screen Recording, explicit pixel capture and a
  scratch AX read/action with independent post-action verification. Host-side
  TCC booleans alone are insufficient.
- Quitting, explicit restart, daemon failure, connector reconnect, user logout,
  concurrent launch, OS restart and permission revocation. No action replay.
- Full-app crash/relaunch and existing MCP-client invalidation remain native
  release gates. The isolated native owner-death test is narrower: it verifies
  the real Cua daemon exits and removes its socket after the production launch
  helper's owner receives SIGKILL, without asserting GUI permission inheritance.
- Signed upgrade at the same bundle ID/team/install path retaining intended
  grants, with old clients disconnected; rollback and uninstall preserving only
  intentionally retained Host config. Removing the `.app` alone is insufficient
  while a separate user LaunchAgent still points into it.

The build receipt cannot promote any of these physical checks to PASS. Stable
identity, signing and an accepting private socket establish distinct boundaries.

## Source-backed lifetime contract and observed evidence

Pinned upstream [CLI parsing](https://github.com/trycua/cua/blob/cua-driver-rs-v0.36.0/libs/cua-driver/rust/crates/cua-driver/src/cli.rs)
recognizes `--parent-liveness-stdio`; its [core guard](https://github.com/trycua/cua/blob/cua-driver-rs-v0.36.0/libs/cua-driver/rust/crates/cua-driver-core/src/lib.rs)
requires both the lifetime sentinel and embedded mode. The
[serve loop](https://github.com/trycua/cua/blob/cua-driver-rs-v0.36.0/libs/cua-driver/rust/crates/cua-driver/src/serve.rs)
waits for EOF and shuts down the SDK runtime, removes its PID file and releases
its socket. This is an upstream internal host contract pinned to 0.36.0, not a
new Styx protocol or an argument forwarded from an agent.

Styx supplies a dedicated stdin pipe, retains only its writer while the daemon
runs, and closes it on orderly stop. OS closure on app death triggers the same
upstream shutdown. The child gets a private PID-file path as well as its private
socket; standalone Cua PID files are not overwritten. There is no watchdog
sending signals to a PID discovered on disk.

On 2026-10-19 an authorized arm64 Mac (macOS 27.0.1) compiled the updated source
with warnings as errors, passed the native ownership test, and passed
`native_cua_owner_sigkill_eof` using the checksum-pinned official universal
0.36.0 binary (`584e44435a26f5aa90c2f0097242307efbd63e843fc3f61072147c1963b0e592`).
The isolated owner subprocess was killed; the daemon exited and its socket
vanished. No NSApplication was started by that harness and no TCC/GUI claim
follows. The available signing identity was Apple Development, not Developer ID
Application, so notarized publisher release validation remains blocked.

The harness entrypoint exists only in a `-D STYX_TESTING` build. Publisher
bundles omit both headless entrypoints and cannot launch a caller-selected
driver through a test argument. The production driver path is bundle-relative.

Evidence fields use only PASS / FAIL / BLOCKED / NOT RUN. Signing and
notarization mechanics are described separately in `signing_detail` and
`notarization_detail`; an unsigned bundle has signing and notarization NOT RUN.
