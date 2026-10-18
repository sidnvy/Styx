# Isolated Styx GUI Broker and Cua session prototype

This prototype adds a GUI execution lane to the existing Exec Adapter without
changing the Charon service, production catalogs, plugin or root dependencies.
ChatGPT remains the reasoning layer. No model API, agent loop or legacy tool aliases
are introduced.

## Architecture and ownership

Styx.app directly starts the embedded Cua daemon. The Node broker never starts a
driver. Its Python worker uses only the SDK's socket-connect compatibility client,
keeps the same client across calls and closes only that client. It cannot create
an in-process runtime or start a daemon.

A trusted resolver supplies an admitted context, OS user, login generation, app
generation and runtime generation. A separate trusted target verifier supplies
the exact PID/window generation. Neither callback is a model argument.
The gateway supplies an authenticated principal AND conversation identity as owner.

GUI tokens and snapshots are random gateway references. Native tokens never leave
the broker as callable authority. They bind owner, context, Host, OS user, login,
app/driver generation, persistent client, exact window and target process generation.
New snapshots, disconnects, revocation and generation changes invalidate old references.
Actions consume the observation before dispatch and serialize across the same Host
and window. Reconnect does not replay a mutation or preserve old tokens.

Native `effect`, `route`, `delivery` and `evidence` remain separate from independent
application verification. Ambiguous transport errors or native error results remain
`outcome_unknown`. No "success" is inferred from an AXPress acknowledgement.

## Modules

- `broker.mjs`: scoped GUI state, target binding, token projection, invalidation,
  per-window serialization and conservative outcome handling.
- `sdk-client.mjs` / `sdk-client.py`: one persistent SDK client per scope, bounded
  requests, UTF-8 framing, no default socket or automatic daemon launch.
- `socket-policy.mjs`: private-directory/owner/type/inode checks and refusal-only
  stale-socket removal. The trusted controller must prove the old process dead.
- `mcp.mjs`: in-memory-testable MCP gateway combining the real Exec Adapter and
  three GUI tools: get_window_state, click and set_value.
- `native/Styx.swift`: non-sandboxed AppKit host, direct embedded child, orderly
  stop and a same-executable watchdog armed BEFORE driver spawn. Direct
  posix_spawn keeps Cua in the host's dedicated process group and resets inherited
  ignored exit signals. Parent PID/start-time/executable stamps, group lifetime,
  a refused socket probe and device/inode checks govern cleanup.
- `native/`: explicit scratch build and native acceptance runners.
- `evidence/`: bounded native receipts and cleanup records.

## Reproduce development tests

The two prototype directories must remain siblings. Node 22+, Python 3 and Linux
x86_64 are required for the fixed Exec Server test binary:

```sh
cd ../styx-exec-adapter
npm ci --ignore-scripts --no-audit --no-fund
python3 prepare-runtime.py
cd ../styx-gui-broker
npm ci --ignore-scripts --no-audit --no-fund
npm test
```

The unified MCP test uses an actual Codex 0.163.0 executor with a fixture GUI
transport. It verifies that GUI reconnect invalidates GUI tokens while an existing
shell stdin session continues. Native Cua tests below establish the real GUI path
separately; this is not a single cross-network ChatGPT end-to-end acceptance.

The original Exec Adapter regression suite is run independently with
`npm run test:all` in its own directory. Runtime preparation verifies the official
archive digest. Tests use scratch HOME/CODEX_HOME and no OS sandbox is claimed.

## Reproduce native tests

Use the reviewed Cua 0.36.0 arm64 driver and matching SDK. Its executable SHA-256 is
`87c7e782e69703d95524e4ceb7ceba03c8a159caabf1f1ce2c118eade7d2a5ec`.
No permission request is part of these runners.

Build a NEW private directory under /private/tmp/styx-gb- and run:

```sh
python3 native/build.py /private/tmp/styx-gb-YOUR-UNIQUE-RUN
python3 native/lifecycle.py /private/tmp/styx-gb-YOUR-UNIQUE-RUN /reviewed/path/cua-driver
```

Keep the native/ directory beside broker.mjs, socket-policy.mjs and the SDK
helper files, preserving the repository layout in the task-local staging directory. Pass task root, reviewed driver, Python and
SDK paths explicitly. Do not run GUI acceptance until same-user active/unlocked
console and host-sourced permissions have been established.

The historical gui-integration.mjs runner uses the earlier granted Pilot app.
For acceptance of the NEW host, use native/new-host-gui.mjs with six absolute args:
task evidence root, an already launched fresh private run root, the fixed signed
prototype App, reviewed driver, Python, and matching SDK directory. Launch the APP
through LaunchServices with --args runRoot driver; only the App launches Cua.
The user grants Accessibility and Screen Recording manually to the fixed App.
Never recompile or replace that binary after permission grant during a run.
The runner uses only the exact scratch window belonging to this App's PID.

## Verified scope (startup and new-host follow-up)

- 14 lifecycle tests pass: SIGKILL at before_guard, guard_spawned, guard_armed,
  spawn_returned before PID handoff, child_registered and socket_created;
  orderly/forced ready-host exit; driver crash; guard crash; driver spawn failure;
  existing regular file and dangling symlink refusal; replacement file preservation.
- 12 native GUI assertions pass under the NEW signed Styx.app after user manual
  grants. These cover host identity twice (before and after restart), window-only
  PNG capture, fresh-observation enforcement, Unicode write/readback, button action
  plus independent fixture counter, abrupt SDK connection death and recovery,
  explicit reconnect, actual 31-second wait for the 30-second gateway token TTL,
  raw Cua stale-token refusal, host SIGKILL cleanup and new-generation rebinding.
- The button's native effect remains unverifiable; its independent fixture counter
  changed from 0 to 1. No native acknowledgement alone is promoted to verified.
- Native observations still report elements_complete=false.
- 27 broker/socket regression tests passed in the development environment, and the
  same 6 socket-policy tests passed on macOS. No shared broker/MCP/Exec source changed.
- Earlier 28-test unified MCP and 35-test Exec regression evidence remains historical,
  with source/dependency identity checked; those full suites were not rerun here.
- First post-grant attempt correctly stopped with Accessibility=false while Screen
  Recording=true. User re-added the exact App to Accessibility; the unchanged
  signed binary then passed both grants and all GUI assertions.

## Remaining boundaries

The prearmed group watchdog closes the known spawn-to-PID-handoff gap for the
non-escaping embedded driver used in these tests. These are deterministic phase
injections, not exhaustive kernel-scheduling tests. Simultaneous host+watchdog
failure and children escaping the owned process group are not accepted.

The directory/owner/probe/inode checks do not establish an OS boundary against
hostile same-UID processes. PID/PGID reuse hardening, peer credentials, production
signing/notarization and update identity remain future work. The ad-hoc prototype
App is retained without a running daemon so the user's manual grants remain usable.

All mappings are in memory. ChatGPT stays the sole reasoning layer. No production
deployment, tool registration, root dependency changes or legacy interface is
included. Lock-screen tests remain deferred at the user's request. Other apps,
other OS backends, cross-network transport, durable recovery, sandboxing and
telemetry/network behavior are outside these isolated acceptance tests.
