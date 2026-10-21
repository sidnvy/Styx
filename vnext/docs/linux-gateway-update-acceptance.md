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
  "sourceRoot": "/absolute/tracked-checkout/vnext",
  "dependenciesRoot": "/absolute/tracked-checkout/vnext/node_modules"
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

The payloads in this fixture are identical; only signed generation metadata
differs. Even a fully passing sequence would prove generation transaction,
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
