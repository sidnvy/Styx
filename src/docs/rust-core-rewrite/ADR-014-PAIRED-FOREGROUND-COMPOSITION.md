# ADR-014 · Ordinary CLI paired foreground composition

2026-10-24. Incremental R22 execution slice; original rewrite goal remains active.

## Decision

Compose the already implemented strict TLS enrollment/MCP/paired relay and Host
protocol through ordinary Rust CLI foreground commands. Reuse the existing
protected deployment authority and explicitly existing native enrollment journal.
No tokens, CA, identity, publisher or installed service are generated or replaced.
The initial implementation is Linux GNU/current UID/numeric loopback Gateway;
persistent managers, native UI and original owner migration remain separate.

Host may read the existing publisher-signed legacy worker closure to locate and
pin Codex. This is an explicit transitional worker bootstrap, not JS Host/Core
execution or a native runtime package. The configuration-preview package does not
contain external workers and cannot be used as a runtime candidate for this slice.

Both endpoints derive the fixed paired namespace as `paired.` plus SHA256 of the
normalized HTTPS origin (`url::Origin::ascii_serialization`, no trailing slash).
Host route selection is explicit: paired v3 by default, old protocol only with
`--legacy-gateway`. A failed paired admission never falls back to legacy. Device
credential admission does not mint per-chat owner authority; the authenticated
fixed Gateway announces the process epoch and original owner/grant control.

## Ownership and cleanup

Foreground owns only its exact local invocation and children. Protected input
read/revalidation, existing execution lease and legacy owner/service/maintenance
refusals remain in effect; an observed empty path is not proof that old JS can
never race. Same-identity single-writer migration is NOT satisfied by this bridge.
Gateway requires a native journal with its original writer; a legacy journal or
uninitialized directory is not silently adopted. No second policy ledger exists.

Dropping a waiter requests cancellation of the owned task. Output closure and OS
TERM request stop; the same future remains alive for real connection/task/native
cleanup. Unknown effects are not replayed. Reconnect preserves the same Host
executor and protocol/session registry. Foreground stop is not durable desired
Stop, autostart disable, or a public cross-process management endpoint.

Gateway reports SDK detached-task join observability as optional. Existing RMCP
ports cannot establish that fact; None must remain None. All Styx tracked
connections, lifecycle jobs, relay cleanup and blocking work must be joined before
known foreground scope teardown. Do not invent a new SDK supervision framework
only to make that field true. A startup error after joined readers closes its
scope without asserting recovery success.

## Required evidence

Use actual ordinary CLI processes, strict TLS/WSS, real paired enrollment and
mature Codex Exec/PTY effect readback. Independent observers check exact process
birth/exit, preserved original input bytes, second-owner refusal, reconnect with
same executor and lease reuse after cleanup. Prepared fixture inputs are clearly
test-owned imports, not evidence of product fresh onboarding/profile persistence.
No system registration, root/SYSTEM workaround, original service disruption or
final package/platform/account claim is authorized by this slice.

## Startup transport reconciliation correction

The first actual ordinary-CLI restart exposed a missing bootstrap composition:
recovered devices intentionally retain RecoveredUnknown lanes, so the new Gateway
cannot admit the retained Host until old transport authority is proven closed.
Generic EnrollmentService::recover_existing continues to preserve Unknown.

Only foreground startup can mint a non-Clone/non-Serde local closure borrowing the
actual Admitted resources, before any SharedEnrollment/Relay/listener exists. It
validates the original Gateway execution lock and protected roots/inputs, existing
old-owner/service refusals and the exact same OwnedConfigurationRoot authority
(Arc identity, not path spelling). The old cooperating Rust owner retains both
execution lease and shared configuration writer through transport/blocking cleanup;
new acquisition therefore excludes those old authority holders. Gateway transport
is in process, not delegated to an untracked OS child; process death also closes
its sockets. This is not evidence that a remote Host command exited.

The private service port consumes the closure once, validates before and after,
and reconciles only exact current nonrevoked device/fingerprint/credential-hash/
capability-generation startup lanes through existing Core attest/reconcile ports.
Core refuses Connected and later runtime Unknown. A failed partial reconciliation
poisons this service instead of publishing a partly ready listener. No operation
result, credential or journal is rewritten, and no side effect is replayed.

These facts apply to the cooperating native foreground scope only. JS does not
participate in Rust locks; nonempty old catalogs/enrollment and original owner
resources still require migration, never an inferred cutover authorization.
