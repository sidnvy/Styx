# ADR-001 · Host admission and legacy Codex wire compatibility

Status: implementation decision after source review, 2026-10-24. The Rust Host now has a tested local TLS/WSS start/read/action slice with bootstrap-preverified owners and explicit negotiation. Full Gateway-issued owner coordination, Core-attested physical resource archival and the legacy frontend below remain incomplete. This does not lower final native or security acceptance.

## Evidence

- `src/host/connect.mjs` forwards Exec WebSocket frames to/from Codex without an owner envelope. `src/gateway/outbound.mjs` supplies that channel as an RpcClient to the shared RuntimePool. `src/packages/styx-exec-adapter/adapter.mjs` owns MCP chat/session membership at the Gateway, not on this wire.
- The old Gateway chooses native process UUID and writeId. Native read results contain sequenced base64 chunks plus independent exited/closed facts. `CodexStdio` currently exposes decoded output and internally advances its cursor; converting text back to base64 cannot reconstruct the original wire contract.
- The old RpcFault/ExecError mapping treats native RPC error responses as definite rejection. Encoding a new Unknown as an arbitrary JSON-RPC error would misreport a potentially completed action. Old transport loss, by contrast, must remain uncertain.
- Unsolicited Host messages before Gateway channel acquisition can terminate the old connection. A WebSocket subprotocol echo does not prove that the old server implements Styx v2.
- R09 actual Codex testing confirms that a long read can queue a later start acknowledgement. Lost acknowledgement never permits replay. Source findings and original failure/reproduction identities are preserved in external execution evidence.

## Decision

Styx-owned Gateway↔Host admission and native Codex protocol are separate boundaries. Native executor code remains mature upstream code. The Host coordinator must use the same owned CodexStdio resource, not spawn a second executor for compatibility or bypass Core with a raw-process authority.

The final strong path explicitly negotiates a versioned Host protocol, initiated by the Gateway after the authenticated channel is acquired. Its response must bind the challenge and actual supported capabilities/identity. Do not infer support from an unsolicited hello, a WebSocket protocol echo, a registry generation, or an error string. HostGeneration, registry/device generation, connection generation and owner epoch remain distinct. Failed negotiation is not permission to downgrade.

The authenticated Gateway assigns its owner namespace. The Host issues/reserves operation tokens and admits every side effect, including stdin and termination, under current owner/grant/session policy. A consumed permit binds the exact prepared payload. Host supervision outlives a temporary network connection. Core keeps historical outcome/audit authority; a provider retires only proven-ended/drained resources without rewriting Unknown to Success.

A legacy-v1 frontend is allowed only for an explicitly selected, verified legacy Gateway/profile. Its authority is gateway-scoped: it cannot claim Host-side per-chat ownership or the new token guarantee. Public MCP arguments remain compatible. Legacy byte framing, UUID/writeId behavior and raw cursor/base64 semantics must be preserved by an explicit raw-page mode inside the same adapter; raw and decoded cursor consumption cannot silently mix on one process. Unknown is never forged into native success or a definite rejection. If the legacy peer cannot represent it, invalidate the affected legacy transport while retaining Host uncertainty; document that its failure domain may span that shared Exec channel.

The final Rust↔Rust candidate must pass the strong contract. Passing the legacy compatibility slice does not discharge those obligations, remote reconnection, same-SHA migration or real-account acceptance. No permanent JS Core fallback is introduced.

## Implementation order and required counterexamples

1. Freeze typed Host-v2 negotiation/owner/prepare-dispatch/read/cancel messages and error certainty; implement current Core coordination for every continuation.
2. Add bounded native raw-page mode and explicit Core-attested archival for ended historical stdin uncertainty; preserve native event sequence and writeId.
3. Compose one Host supervisor with strict TLS/WebSocket adapters; run an isolated real old-Gateway→Rust-Host journey under the declared v1 limitations.
4. Complete Rust Gateway transport/registry/auth and Rust↔Rust tests, then migration through signed versioned payloads.

Required negative controls include spoofed owner metadata, registry generation substituted for HostGeneration, stale connection/owner token, duplicate start/write, changed payload, ambiguous ACK, queued read before start, transport resume without executor respawn, raw/decoded mode mixing, fake v2 WebSocket echo, and silent downgrade. Effects and cleanup must be observed independently. No live profile or signed artifact was changed to make this decision.

## Native output pagination correction, 2026-11-04

The pinned Windows Codex executor returns whole output chunks: a `process/read` with `maxBytes:1500` returned a valid 1544-byte chunk. This is a batching hint, not a native frame limit. The adapter retains the existing hard wire-frame bound, sequence/base64 checks, owner checks and independent process-exit/output-drain facts.

Decoded consumers retain each validated native page under its original RPC memory reservation and deliver bounded byte slices through the same incremental UTF-8 decoder. They advance the native cursor only after retaining the validated page, never issue a second native read while bytes remain, and require an empty closed page to prove drain. Two retained pages leave one original RPC slot for control/cleanup. Saturation refuses a decoded read before dispatch, with its cursor unchanged; unknown reads still prohibit replay. Revoked-owner cleanup discards and zeroizes the original retained bytes. Raw-page mode preserves the upstream page and cursor without splitting or re-encoding it. Cancellation and cleanup apply the hard frame bound rather than the batching hint.

Contract regressions are separate from signed Gateway/Host native acceptance. Original failed reads and their independent one-time effects remain evidence; they are never retried to validate this correction.


## Native terminal-output retention correction, 2026-11-04

The pinned `codex-cli 0.163.0` removes exited native process read records after 30 seconds ([upstream local_process.rs](https://github.com/openai/codex/blob/rust-v0.163.0/codex-rs/exec-server/src/local_process.rs#L94)). A real Windows diagnostic delivered a normal output chunk and exit/closed notifications, then returned `unknown process id` when a new terminal-page read followed 32 seconds later. The original Styx failure and its independent one-time file effect remain unmodified; neither that command nor its uncertain read is replayed.

Decoded delivery can also use a complete, contiguous `process/output` → `process/exited` → `process/closed` event prefix from the same already registered process and the same original stdio reader. Sequence, stream, canonical base64, exit/close identity and prior exit-code agreement are checked. This is retained executor DATA, never owner, policy, action or recovery authority. Current Core read admission and post-read delivery admission remain unchanged; prior unknown start/input/cursor outcomes stay unknown.

The event cache uses only the unused 2MiB in the existing 16MiB peer reservation, including a conservative per-chunk metadata charge. Registration remains bounded by the original process-observation limit. Decoded bytes keep their reservation during bounded UTF-8 delivery and are zeroized on drop. No release or delivered drain is reported while bytes remain. Missing, malformed, duplicate, out-of-sequence or over-budget events disable this proof; the original strict native-page path remains available and its failures stay uncertain. Raw reads disable the event cache and preserve original upstream pages/cursors. An incomplete stream, a native missing-record error by itself, or a timeout never proves EOF.

Thus native page mode still requires an empty closed page; a complete original native event stream is an independent terminal proof. No process is respawned, no mutation is replayed and no standard executor is replaced. Contract tests are separate from final same-source Windows/Linux native acceptance, including an intentional delay beyond the native retention period.
