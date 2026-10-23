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
