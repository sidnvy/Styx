# ADR-025 · Native runtime candidate and retained worker closures

2026-10-25. Incremental C08 packaging and Host reader integration; no new
management authority, public tool, installer or permission grant.

## Decision

Keep schema2 `native_rust_v1`. Preserve the existing exact-three-member
configuration preview wire format and `native_release_v1` reader. Introduce
`runtime_candidate` scope and `native_runtime_v1` reader for an exact signed
native CLI plus explicitly declared mature executor closures. An omitted empty
`worker_closures` field preserves the preview serialization.

Each closure declares its fixed kind, upstream version, original signed manifest
hash, original publisher SPKI hash, fixed native entrypoint and exact members.
The externally approved outer publisher must match every source publisher. These
source hashes are publisher attestations, not independent reproducible-build proof.
The builder verifies the whole original signed source before and after copying;
no old signed bytes are modified. OpenSSL signs exact new manifest bytes with the
existing publisher; no new identity or implicit trust from a bundled key.

Codex, bounded Browser Node/NPM and Cua have separate fixed prefixes. Browser
assets owned by Styx remain embedded in Rust; only the mature Browser executor
closure is copied. No legacy JS Host/Core/Gateway or launch shim enters the new
payload. Mac standalone Cua is refused: its App-owned embedded executor and TCC
responsibility require a separate retained App binding. Zero workers is permitted
for a Gateway-only candidate and says nothing about Host readiness.

## Reader and lifecycle boundaries

The Host selects exactly one release reader from the manifest schema and one
signature codec: legacy schema1/base64url or native schema2/raw64. No fallback on
failure. Active schema1 admits only legacy format; active schema2 must explicitly
name native_rust_v1. Native bootstrap requires runtime_candidate scope, exact
active version/hash, current native target, approved publisher and full inventory.

The protected profile retains one opaque legacy inventory or the entire native
verified release through physical cleanup. Executor pins derive from that retained
inventory. Browser root and upstream metadata derive from its signed closure,
never a client pathname or a second configuration source. Membership is not a Core
grant, runtime health observation or OS desktop permission.

This reader accepts a prepared native fixture. Existing state/identity reading is
still transitional. It does not migrate original state, prove old-runtime
quiescence, retire JS writers, activate a service or implement rollback. C07 must
perform that handoff under the original single-writer transaction before installed
profiles can be reported as migrated. Do not fabricate legacy succeeded steps to
represent a completed migration.

## Verification required

Keep contract negatives for reader/target/membership/licensing/duplicate/path
boundaries, but do not count them as platform acceptance. Freeze clean source,
run one complete local quality gate, build a receipt-bound actual native binary,
and package it with the original development publisher. Independently inspect
archive closure and signature, reject tampered/wrong-reader packages, then run
real Exec and Browser effects from packaged workers in an owned private profile.
Record exact source/artifact hashes and retain failed runs. Candidate extraction
is not installation, deployment or final three-platform acceptance.
