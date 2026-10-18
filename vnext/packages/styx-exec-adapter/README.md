# Isolated Styx Exec Adapter prototype

This directory is independent of the Charon service entrypoint, production catalogs,
plugin and root dependency lockfile. It exposes only Codex-style `exec_command`
and `write_stdin`. It does not call a model, plan work or provide old tool aliases.
ChatGPT remains the reasoning layer.

## Run the tests

On Linux x86_64 with Node 22+ and Python 3:

```sh
npm ci --ignore-scripts --no-audit --no-fund
python3 prepare-runtime.py
npm run test:all
```

Run these commands inside this prototype directory, not the repository root.
The runtime preparation downloads official Codex `rust-v0.163.0`, verifies the
pinned archive SHA-256 and extracts only the expected executable. It refuses to
overwrite an existing executable. The ignored `.runtime/` contains no sign-in state.
Tests use temporary HOME and CODEX_HOME directories and loopback listeners with
ephemeral random authentication tokens. They neither register a remote environment
nor touch an existing desktop, service listener or model API.

Scratch directories are not a security sandbox. The pilot sends no sandbox policy,
so its trusted test commands execute with the development environment's OS rights.
No root/product build or container release checks are claimed; this directory is
not wired into the product or proposed for production rollout.

## Components

- `schema.mjs`: the two model-facing tool schemas and Codex-shaped success result.
- `adapter.mjs`: trusted target resolution, session ownership, process mapping,
  output cursors, incremental UTF-8 decoding, bounded output and MCP projection.
- `rpc.mjs`: bounded stdio/WebSocket JSON-RPC clients and explicit session recovery.
- `mcp.mjs`: standard MCP server factory without a listener. The embedding gateway
  supplies the authenticated principal plus conversation identity out of band.
- `test/`: deterministic failure tests and real-executor/MCP integration tests.

## Ownership and recovery contract

A trusted resolver receives `(environment_id, owner)` and supplies the admitted
context ID, immutable generation, initialized ExecConnection, absolute cwd,
platform, default shell, permitted shell paths and command environment.
An omitted environment ID is resolved only by the embedding gateway's explicitly
bound default; this prototype discovers no machines or credentials.

The opaque owner must bind both principal and conversation. It is never a tool
argument. A gateway session ID binds that owner, resolved context, context generation,
the exact ExecConnection object, its server session ID, process ID and output cursor.
Every operation rechecks admission; queued writes serialize per process. The caller
cannot retarget `write_stdin`. Active sessions are not evicted to make room.
Completed sessions are removed after terminal output has been drained. IDs are not
reused during the adapter instance's lifetime.

Mutation RPCs are sent once. An uncertain start retains a recovery handle; a later
read may establish that the process exists. An uncertain write permits observation
but blocks additional input until trusted reconciliation or cleanup. The prototype
does not expose a model-callable operation that clears this uncertainty.

Reconnect is an explicit controller operation on ExecConnection, never an automatic
replay. It must recover the original server session and provider identity. The pinned
executor retains detached sessions for 30 seconds. Expiry or executor restart fails
closed. Adapter mappings are memory-only: gateway restart loses them rather than
guessing or launching replacements. Durable gateway recovery is future work.

Successful dispatch, termination acknowledgement, process exit and test acceptance
are separate facts. Cleanup checks terminal read evidence. Nonzero command exits
are normal tool results with `exit_code`, not MCP transport failures.

## Deliberate prototype limits

This is a Codex-shaped subset, not a complete Codex harness:
- POSIX sh/bash/zsh only; no Windows shell semantics.
- Permission escalation fields are rejected until there is an enforceable approval
  implementation. No approval or security boundary is inferred from tool wording.
- Yield waits are bounded to 0..30000ms, including zero for deterministic tests;
  empty polls default to 5000ms. Codex's longer empty-poll range is not implemented.
- Output is conservatively capped at one UTF-8 byte per requested output token.
  `original_token_count` is a byte-based upper-bound estimate, not a model tokenizer
  measurement. A truncated chunk is intentionally discarded; later pages remain
  pollable. Output sequence gaps fail explicitly.
- Runtime RPC error details are sanitized. Public errors carry a recovery session ID
  when one exists; these are not successful output-schema objects.
- Runtime clients are intended for a single controller; recovery must not run
  concurrently with active calls. No persistent mapping journal, outbound Noise
  relay, TLS deployment, authentication provider or production MCP endpoint is added.
- The standard MCP client test uses an in-memory transport and real Exec Server.
  Actual ChatGPT registration, composer behavior and remote UI acceptance are not
  established by this test.
- macOS GUI/lock-screen tests are deferred by user request. Browser and Desktop tool
  contracts, macOS execution and cross-network transport are outside this prototype.

## Protocol evidence

The baseline is the fixed release source, not README examples:
- [Codex tool schema](https://github.com/openai/codex/blob/rust-v0.163.0/codex-rs/core/src/tools/handlers/shell_spec.rs)
- [Executor protocol](https://github.com/openai/codex/blob/rust-v0.163.0/codex-rs/exec-server-protocol/src/protocol.rs)
- [30-second detached-session retention](https://github.com/openai/codex/blob/rust-v0.163.0/codex-rs/exec-server/src/server/session_registry.rs)
- [Cursor and bounded reads](https://github.com/openai/codex/blob/rust-v0.163.0/codex-rs/exec-server/src/local_process.rs)

In particular `process/write` requires `writeId`, and `nextSeq - 1` is the
cursor for the next `afterSeq`. Process exit does not prove every bounded output
page has been returned.
