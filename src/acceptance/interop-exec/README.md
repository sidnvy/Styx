# Owned legacy Gateway ↔ Rust Host CLI interoperability

These scripts are external acceptance tools, not product runtime, another policy
store, or a new Gateway implementation. `prepare.py` obtains exact Git archive
`44cf1470e6b0cfdfd2c2372e54e84ebd279c59c3`, copies the unchanged matching npm
closure, verifies locked SDK1.32.1/ws8.22.0 and records every source/dependency
byte. No old Gateway code is patched. Node22 is the fixed rc16 input.

`run.py` launches the original Gateway CLI, the new Rust `styx host run`, and an
actual official legacy SDK client over fixture-only TLS. A fresh private layout
contains original rc16 signed payload bytes and the original development
publisher pin, new isolated identity/CA/bearers, and explicit **synthetic trusted
bootstrap** legacy state. Its historical `steps:succeeded` are fixture admission
attestations, not evidence that onboarding, legacy doctor or pairing executed.
The runtime's actual read-only `styx doctor/status --json` are then run. No real
profile, service manager, account, hardware permission or three-platform package
acceptance is used or claimed. Executor state goes into an owned CODEX_HOME.

The native command workload uses `/bin/sh` builtins, fresh unpredictable nonces,
independent file bytes and kernel PID/starttime/executable hash observations.
Pipe and PTY stdin are separate real executor paths. Cross-MCP-owner input must
be refused without a file effect. Network loss must neither re-execute a command
nor recreate the Codex executor; explicit foreground SIGTERM must await native
cleanup. A force-kill fallback is cleanup of test ownership, never a passing
termination assertion. All failures retain original private logs and receipt.

Important original-baseline limitation: `gateway/index.mjs::closeOwner` does not
terminate Exec processes on MCP DELETE. Only original Gateway shutdown invokes
`exec.cleanup`. The final harness cases must preserve and report this limitation;
they must not modify that original source or call a private fake success hook.

Prepare once (paths below are inputs, never credential values):

```sh
python3 src/acceptance/interop-exec/prepare.py \
  --repo /absolute/existing/source \
  --node22 /absolute/frozen/rc16/bin/node \
  --evidence /absolute/fresh/external/inputs
```

`run.py --help` documents owned run inputs. Actual execution must wait for the
integrator's complete foreground/profile/legacy ports and scoped preflight.
`--signed-host` is the original immutable signed Host payload directory;
`--publisher-key` is the existing matching PUBLIC publisher PEM. No signer key,
credential argument, package resigning, global toolchain change or worktree is
needed. Public frozen payload verification belongs to the real runtime loader;
the harness never marks arbitrary raw executables as signed.
