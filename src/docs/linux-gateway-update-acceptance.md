# Linux Gateway update native acceptance

`host/linux-gateway-update-acceptance.mjs` exercises the existing Core and signed
Gateway application release path in an independent temporary deployment. It
does not replace the production offline/quiescence observer, install a service,
change user-session policy, or touch an existing deployment.

## Invocation

Prepare the locked root dependencies without lifecycle scripts. Use the official
Linux x64 Node 22.23.3 binary, its license, and the recorded download provenance
from the Linux CLI distribution. The input JSON has absolute normalized paths:

```json
{
  "directory": "/absolute/evidence/linux-update-20261021-run3",
  "nodeBinary": "/absolute/distribution/runtime/node",
  "nodeLicenseFile": "/absolute/distribution/runtime/LICENSE",
  "nodeProvenanceFile": "/absolute/distribution/runtime/node-provenance.json",
  "sourceRoot": "/absolute/tracked-checkout/src",
  "dependenciesRoot": "/absolute/tracked-checkout/src/node_modules"
}
```

```sh
STYX_RUN_LINUX_GATEWAY_UPDATE_ACCEPTANCE=1 \
  /absolute/distribution/runtime/node \
  host/linux-gateway-update-acceptance.mjs /absolute/input.json
```

The evidence directory must be fresh and named `linux-update-20261021` with an
optional task suffix. Signing keys, releases, deployment configuration, TLS keys,
tokens, and process input files stay inside its private subdirectory. Successful
cleanup deletes that private subdirectory; the receipt contains hashes and
bounded observations, never credential values. A refusal exits 2 and records
`BLOCKED`; that outcome is not a passed update test.

For an actual application payload change, additionally provide an independent
absolute `previousSourceRoot` pointing to a tracked historical checkout. Its own
`onboarding/gateway-release.mjs` builds the old generation with its historical
source closure; the current builder builds the new one. This mode requires real
`app/` payload differences and records their names. The same verified official
Node binary is used in both generations, so this still does not claim a Node
version upgrade.

## Intended sequence and scope

1. Verify official Node provenance, binary/license hashes and actual version.
2. Build and verify two complete signed Gateway application releases with a fresh
   temporary Ed25519 test publisher. Compare their complete payload inventories.
3. Prepare a real Gateway-only deployment through Core; stop its foreground
   Gateway. No Host, Exec binary, or Cua binary is installed.
4. Start the installed signed runner with its verified service Node. Confirm the
   actual process executable and runner arguments, perform authenticated TLS MCP
   initialization and `tools/list`, then stop only that owned child.
5. Review and apply the second generation using the **unmodified production**
   systemd/process quiescence observer; verify exact configuration preservation.
6. Run and probe the new signed runner, stop it, plan/apply offline rollback, and
   run/probe the old signed runner again.
7. In a separate owned installer child, deliberately SIGKILL at the flushed
   `pointer_switched` checkpoint. Use the real observer and explicit transaction
   recovery, then run/probe the recovered signed runner.
8. Confirm owned child process identities have exited and remove task secrets.

When `previousSourceRoot` is omitted, the payloads are identical; only signed
generation metadata differs. Even a fully passing sequence would prove generation transaction,
startup, rollback and recovery behavior, **not an upgrade to a different Node
binary or application revision**. The test publisher is not official product
distribution trust. The fresh Gateway has no approved remote devices; populated
device approval migration remains a separate acceptance gate. No real reboot,
power loss, ChatGPT account, or production deployment is tested.

## Workstation result — 2026-10-21

Native evidence is under task outputs `linux-update-20261021-run2/receipt.json`.
The Charon invocation was session `24cf2ba47252323ca2df00c6`, exited 2 (`failed`,
receipt `BLOCKED`). The first attempt remains in `linux-update-20261021-run1`.

Observed and passed:

- Two complete signed application generations: 1,528 files and 96 locked
  dependencies each, identical payload hashes. Official Node binary SHA256 is
  `fde6a4bf8d0562f7751d1a2d6cb9b417c4cfe107bbcb0aa3e9a24e125e348f48`.
- Real Core Gateway-only preparation, followed by actual installed signed runner
  TLS MCP initialization and tools listing. The runner was PID 190112; executable
  and argument binding were read back from its own `/proc` entry.
- The attempted update refused **before staging or generation mutation**.
  The old active signed generation and all eight configuration/TLS/credential
  file hashes remained identical. No runtime-change journal or transaction lock
  remained.
- All owned child processes exited; signing private key and private test state
  were deleted. No service was installed or changed.
- The two focused acceptance guard/inventory tests passed under actual Node
  22.23.3 on workstation. These are engineering checks, not update acceptance.

Actual blocker:

The real user-systemd observation for this deployment's unit was
`LoadState=not-found`, `ActiveState=inactive`, `MainPID=0`. The production process
observer also requires reading every nonempty current-user process's executable.
Five pre-existing processes refused `/proc/<pid>/exe` with `EACCES`. The observer
correctly refused to infer absence from an unknown observation and raised
`gateway_process_quiescence_unknown`. Diagnostics retain only numeric PID,
operation, and errno; unrelated command lines and process contents are omitted.

Consequently **successful update, new-generation startup, offline rollback and
SIGKILL recovery remain NOT RUN on this native environment**. No observer override,
mocked success, permission change, process-security policy change, or unrelated
process termination was used. The next implementation decision is how Core can
prove its own runtime is offline on ordinary desktops with inaccessible same-user
processes, without weakening unknown observations into a false clean state.

## Additional PID namespace attempt — also blocked

The existing host permits the unprivileged preflight
`unshare --user --map-root-user --pid --fork --mount-proc /usr/bin/true` (exit 0).
No system setting, sudo access, or process-security policy was changed.

A second complete fixture invocation used that existing user/PID isolation and
a fresh `linux-update-20261021-pid-isolated` directory. Its fresh signed runtime
and deployment were created exclusively inside the namespace, and its own
signed runner again passed authenticated TLS MCP. However, the original user
systemd manager could not be queried from that namespace: `systemctl --user`
reported `Failed to connect to user scope bus via local transport: No data
available`. This invocation exited 2 before applying an update. Its receipt,
execution context and independent cleanup observation remain in that output
directory (Charon session `9accb1a639de81ab61d8455a`). Namespace-local process IDs
in that receipt must not be interpreted as host process IDs. The outer owned
namespace process exited; private state and keys were removed. An outside,
read-only query still found the fixture's unit absent/inactive/PID 0.

A subsequent lightweight `--map-current-user` preflight preserved UID 1000
inside the namespace but produced the same real user-bus error (exit 1). The
full fixture was **not** started for this mapping. Evidence is
`linux-update-20261021-current-user-preflight.json` in task outputs.

No alternative bus, observer injection, authorization bypass, or policy change
was attempted. These failed isolation attempts neither pass generation
transactions nor resolve the ordinary workstation's `EACCES` blocker. Native
successful update, rollback and interruption recovery remain unaccepted.


## Native repair and changed-application acceptance — 2026-10-22

The ordinary Arch workstation now passes the real signed application update,
offline rollback and interruption recovery sequence. Evidence is task output
`linux-update-20261021-run3-20261022/receipt.json` (native Exec session 49114,
exit 0). Independent cleanup is in the adjacent `cleanup-observation.json`.
The older blocked receipts above remain unchanged historical evidence.

The production Linux observer was repaired as described in
[Linux Gateway offline observation](linux-gateway-quiescence.md). It combines
kernel exclusion of current executable inodes with complete same-user command
lines, and still refuses unknown arguments, loaded units and active runtimes.
The same five pre-existing protected processes still denied executable links;
no process-security policy or existing process was changed. There was no PID
namespace, observer override or substituted user bus.

The old signed application was built by the real `4c91cfc` checkout's own
publisher module, and the new signed application by the current source. The
signed inventories contained 1,658 and 1,662 files with 96 dependencies each;
14 application payload paths differed. This includes actual Gateway and Exec
adapter source changes, rather than only manifest version metadata.

Passed in the independent temporary deployment:

- Old signed application startup with its installed Node and authenticated
  TLS MCP initialization/tools listing.
- Review-bound offline application update, followed by actual new-generation
  signed startup and TLS MCP.
- Offline signed rollback, followed by actual old-generation signed startup
  and TLS MCP.
- A real owned installer killed with SIGKILL after `pointer_switched`, then
  explicit verified transaction recovery and recovered old-generation TLS MCP.
- All four running signed processes were also refused by the production
  quiescence observer as `gateway_runtime_process_still_running`.
- All nine deployment/Gateway configuration, identity, TLS and credential file
  hashes, including the Gateway tunnel-context token, remained identical.
- All owned processes exited; private fixtures and the ephemeral signing key
  were removed. A separate read-back found the unit absent/inactive/PID 0,
  no unit definition, no known runner PID and no fixture-path process.

The official Node 22.23.3 binary is identical in both generations. This passes
an actual Gateway application update, not a Node version change. Signing trust
is an ephemeral test publisher. Real reboot/power loss, populated remote-device
approval migration, Exec/Cua/Browser installation, ChatGPT account use and a
production deployment remain outside this acceptance.
