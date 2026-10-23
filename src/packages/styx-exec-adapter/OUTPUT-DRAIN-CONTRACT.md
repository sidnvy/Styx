# Process exit and output EOF are independent

The fixed official [rust-v0.163.0 local process implementation](https://github.com/openai/codex/blob/rust-v0.163.0/codex-rs/exec-server/src/local_process.rs)
records the exit code in `watch_exit` (lines 1033–1037). `maybe_emit_closed`
(lines 1117–1134) waits for every output stream to finish. Its upstream
`exited_process_retains_late_output_past_retention` test (lines 1656–1710)
explicitly covers an empty exited-but-open read followed by late stdout.
The [read protocol](https://github.com/openai/codex/blob/rust-v0.163.0/codex-rs/exec-server-protocol/src/protocol.rs#L461-L473)
therefore exposes separate exited, closed and exitCode fields.

Styx previously returned exit_code and deleted its output cursor/UTF-8 decoders
on an exited response with no chunks, even while closed was false. It now keeps
the session until exited and closed are both true and an empty cursor page
confirms all retained output pages were consumed. Exited-but-open observations
honor the yield deadline and use bounded polling; they do not hot spin. No
start/write is resent and no process is replayed.

The original duplicate push CI failure is preserved by run
[39146156272](https://github.com/sidnvy/Styx/actions/runs/39146156272), native-exec
artifact: outbound stdin expected ACK:PING but received empty output/exit0.
That incident did not capture raw RPC replies, so its exact event ordering is
not claimed as directly observed. The same faulty assumption is independently
reproduced with the official checksum-verified Linux x64 executable using
`(sleep 0.2; printf LATE_ACK) & exit 0`: the parent exits while the child retains
stdout. Raw reads observe the late output; the old adapter returns empty output
with exit0 after its first exited-but-open reply. After the fix it returns
LATE_ACK and exit0. Full benign raw read transcripts are retained in
`test/fixtures/terminal-before-output.native-before.json` and
`test/fixtures/terminal-before-output.native-after.json`. They contain only this fixed fixture
command/output and cursor metadata, with no host tokens or user configuration.
The pinned native binary SHA-256 is recorded in each transcript.

The deterministic regression preserves split UTF-8 after an exit event and
through a later closed response, then drains the final empty page. The real
native integration regression asserts delayed inherited stdout is returned
before completion. Neither a passing retry nor timing sleeps replace the
source contract or deterministic failing-before/passing-after evidence.
