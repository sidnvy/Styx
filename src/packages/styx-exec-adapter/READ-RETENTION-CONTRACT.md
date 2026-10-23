# Native process retention and lost read results

Codex `rust-v0.163.0`, pinned commit
`83086188ae0614bd882818ff1aa23f3194962012`, retains a closed process for
30 seconds. This is an upstream record lifetime, separate from a Styx owner
handle or a live transport. It is not a Styx active-process limit.

The pinned [native implementation](https://github.com/openai/codex/blob/83086188ae0614bd882818ff1aa23f3194962012/codex-rs/exec-server/src/local_process.rs)
defines `EXITED_PROCESS_RETENTION` at lines 91–94. `maybe_emit_closed` starts
the eviction timer only after exit and output EOF, then removes the record at
lines 1150–1159. `exec_read` returns JSON-RPC `-32600` with
`unknown process id <id>` when that record is absent (lines 538–541).
The same code is used for a still-starting process, with a different message.
A connected executor can therefore lose a completed process's unread result.

## Actual native evidence, 2026-10-22

A one-shot Python stdio probe ran the repository's official Linux x64 executor
in temporary, isolated HOME and CODEX_HOME directories. It neither changed a
service nor connected to a model. CLI version was `codex-cli 0.163.0`;
binary SHA-256 was
`399ff69c431c066e40de318fba45c2b07f45a76b19939d247ee4828fc70c4215`.
The initialize response reported `executorVersion: "0.0.0"` and provider ID
`sha256:3a89f79da9ba07bff0e916004568a87891b57a30269c0e58aba2b41e853974b5`;
we do not substitute the CLI version for that returned field.

The single command was `/bin/sh -c 'printf STYX_EXPIRY_ONLY; exit 7'`, with
process ID `styx-fixed-expiry-probe`. These selected request/response fields
were copied from its actual tool transcript; initialization and temporary
paths are omitted. Elapsed times are measured from probe startup.

```json
{
  "elapsed_s": 0.163,
  "request": {"processId":"styx-fixed-expiry-probe","afterSeq":null,"maxBytes":65536,"waitMs":1000},
  "response": {"id":3,"result":{"chunks":[{"seq":1,"stream":"stdout","chunk":"U1RZWF9FWFBJUllfT05MWQ=="}],"nextSeq":2,"exited":false,"exitCode":null,"closed":false,"failure":null,"sandboxDenied":false}}
}
```

After deliberately leaving the handle unpolled for 31 seconds:

```json
{
  "elapsed_s": 31.164,
  "request": {"processId":"styx-fixed-expiry-probe","afterSeq":1,"maxBytes":65536,"waitMs":0},
  "response": {"error":{"code":-32600,"message":"unknown process id styx-fixed-expiry-probe"},"id":4}
}
```

The command's requested `exit 7` is fixture intent, not a read receipt. The
second read cannot confirm the exit code or recover any remaining output.

In the same investigation, the existing Styx-connected Mac returned stdout
and an owned handle; prompt `write_stdin` polls completed with exit0. A
separate read-only version/hash probe deliberately left unpolled for at least
69.16 seconds returned the old adapter's `read_unavailable`, `uncertain:false`.
The environment remained connected. The installed Mac executor printed
`codex-cli 0.163.0`; a separate hash command, promptly polled to exit0, returned
SHA-256 `c8957f91ed87ed1270536e3560dc529a8082fa4dd4d8248e54bf3ee4a2f00536`.
That Mac failure is consistent with the native retention contract, but the
Mac's raw process/read error was not captured. Earlier internal errors cannot
all be attributed to expiry from this evidence. No Mac installation, service,
or repository was modified, and this local patch was not deployed there.

## Error and recovery contract

RpcClient classifies a lost record only when all three facts match: the
pending request is `process/read`, its response code is `-32600`, and its
message exactly equals `unknown process id ` plus that request's process ID.
It retains only a fixed internal reason, never arbitrary executor text.

For a start-acknowledged owned process, that reason now produces
`{error:"process_lost",session_id:<old handle>,uncertain:true}` and retires the
handle. This means the native record is absent; expiry is one cause, not a
claim that the command failed, succeeded, or was terminated. Previously
returned stdout remains evidence, but completion or remaining output is not
inferred. Check the command's expected artifact or known process state before
deciding whether to run anything again. The adapter never replays start/input
and does not expose a new handle that silently replaces the lost command.

A later use of the retired handle returns `unknown_session`. A different
message, different process ID, different RPC method, generic internal error,
or transport failure remains `read_unavailable` with the handle retained.
An uncertain start remains `outcome_unknown`; an absent record at one read
does not reconcile an earlier unacknowledged mutation.

This patch adds no background reader and does not extend native retention.
Read/drain ordering, owner checks, cursor and incremental UTF-8 validation
remain in force. A prompt poll remains the way to obtain the actual terminal
result before upstream eviction.

## Reproduction and validation

The deterministic unit regressions first failed on missing classification and
on the former `read_unavailable/uncertain:false` mapping, while unrelated-read
and uncertain-start counterexamples passed. With the patch, all 37 unit/Windows contract tests and all 15 real-native
integration tests passed. The unit regressions
verify exact matching, text sanitization, handle retirement, and no replay.

The real native integration test named
`native closed-process retention expiry reports process_lost without replay`
uses isolated runtime state, leaves one deliberate fixture unpolled for 31
seconds, requires `process_lost/uncertain:true`, confirms the executor is still
ready, and verifies one start and no writes. Run it from this package with:

```sh
node --test --test-name-pattern='native closed-process retention expiry' test/integration.test.mjs
```

This is a Linux native regression. Passing deterministic tests and Linux
execution do not constitute deployment or a patched Mac acceptance result.
