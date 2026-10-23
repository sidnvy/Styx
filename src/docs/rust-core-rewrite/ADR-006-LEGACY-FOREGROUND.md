# ADR-006 — Explicit protected legacy foreground

Decision: implement the frozen R13 vertical slice by reusing existing runtime ports,
without another core authority, a new worktree, a rewritten executor or a weakened
TLS verifier. This is an implementation decision within the approved rewrite.

The only product entry is `styx host run --state-dir PATH --legacy-gateway`.
`doctor/status --json` are read-only observations, not live readiness or account
acceptance. The normal paired-profile CLI path remains explicitly unsupported until
its protected bootstrap exists; legacy mode is never inferred or silently selected.

Original publisher SPKI, raw Ed25519-signed manifest, active-pointer digest, exact
platform/member closure, device RSA SPKI/fingerprint, token location and CA/origin
must agree. Only the signed `bin/codex` is selected. Mature AWS-LC, ed25519-dalek,
rustls/webpki, Tokio, nix, serde and clap provide standard primitives. The product
CLI cannot supply an executable, bearer, publisher override or insecure TLS flag.
A retained Linux ELF FD and secure private-root observations pin the actual image;
streamed bounded hashing avoids loading the native payload into memory.

Gateway/Host/Core/provider ownership is unchanged. A move-only bootstrap reservation
shares the original queued-I/O byte source before connecting; strict WSS admission
precedes native spawn. Original JSON-RPC IDs/process UUIDs/writeIds/raw cursors and
native terminal frames pass through typed translation and move-only Core permits.
No arbitrary RPC forwarding port is introduced. The old wire has no per-chat grant
or operation token; all legacy requests belong to its protected Gateway session.
A duplicate possible-dispatched original start remains Unknown, and an ambiguous
input ACK is not replayed. Reconnect requires the original actual native session.

The public runtime call waits for an owned Tokio worker. Waiter cancellation/drop
signals an official cancellation drop guard; it cannot release native ownership.
Network EOF only closes its joined link tasks. Host stop separately gathers command
exit evidence, server wait, reader/stderr joins and supervised job joins. Unknown
cleanup holds the same signed pin/lease/worker until reconciliation; a server wait
cannot substitute for command exit. The API's runtime must remain alive for this
supervision; process/runtime destruction is not a successful graceful stop.

Known original foreground/background/recovery/advance/capability/health owners refuse
admission. Presence of service configuration requires an actual OS observer, which
is not implemented here; it is never assumed stopped. The new flock does not lock
old JS and does not constitute migration/cutover. Existing installed identities,
permissions, services and signed bytes remain untouched.

Verification is split: private loader/payload negatives, Core duplicate/Unknown
counterexamples, independent source review, and actual immutable old Gateway/native
CLI scenes. Synthetic prepared state attests fixture admission only. Original default
self-signed CA-as-leaf compatibility, measured startup, API-drop native faults and
final platform/accounts must retain their own actual result; a standard PKI scene
cannot silently close a different certificate migration. Evidence and exact SHA are
recorded outside source after the freeze.
