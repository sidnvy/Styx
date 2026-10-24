# ADR-013 · Native configuration roots and original transaction recovery

2026-10-24. Incremental C07 implementation. This does not authorize legacy
migration, retire the installed runtime, or claim OS service activation.

## Retained architecture

Core validates configuration semantics and transaction facts without filesystem
or platform dependencies. Runtime owns the existing descriptor-relative store,
one move-owned writer, pinned namespaces and complete service maintenance gate.
Contracts contain data only. No new dependency, service, executor, trust root or
configuration authority is introduced.

Native canonical state uses schema 2 and the closed NativeRustV1 discriminator;
the existing schema-1 reader must refuse it. Reader contract version 1 is separate
from the canonical schema. The formal native reader preserves exact input and
opaque RawValue extension bytes, including numbers outside machine float range.
It rejects decoded duplicate keys at every nesting level and bounds bytes,
container depth, member count and decoded key length. This is not a constant-RSS
or zero-allocation parser claim.

## Authority and lifecycle

`native_root::create_fresh` requires successful atomic creation of a new private
child. Existing directories are refused. The marker binds actual root identity
and fresh OS-random scope; these are not device identity or publisher trust.
Bootstrap failures retain the original root/writer, or parent locator when writer
acquisition has not occurred. A private path/flock/marker is not evidence that an
old JS owner quiesced. Reopen observes bytes; explicit resynchronization under
original writer is required before they support new durable facts.

`native_transaction::NativeTransactions` consumes the opaque native binding and
one management namespace handle. Standalone maintenance refuses an instantiated
enrollment authority. Its complete existing service gate must supply the opaque
maintenance capability instead. A capability from another root is refused.

A native-only configuration assignment records exact raw intent/before/target,
then Prepared. It conditionally replaces canonical state through a private,
fsynced same-filesystem management temporary and atomic rename, syncs both source
and destination directories, formally reads target, and records hash-linked
Applied, Verified and Committed. Rename serializes cooperating exclusive writers;
it is not an atomic content CAS against a hostile same-UID writer.

Only the coordinator can mint an in-process commit proof. In the same final owner
closure it validates actual canonical bytes, marker, complete original chain,
latest transaction and every earlier complete chain, with no unknown orphan or
pending transaction. Then it clears the fence. The atomic rejection snapshot
allows this verified fence release while keeping poison permanently monotonic.
Dropping a waiter, maintenance handle, failed transaction or failure resource
never proves commit or resumes admission.

## Explicit recovery policy

Recovery targets the original transaction ID and materials, not a new request.
Original files and phase records are resynced without reencoding reconciled flags.
Prepared with canonical-before may resume the same pure configuration assignment;
canonical-target is verified and missing successor records can be appended without
renaming again. Committed reply loss returns the original receipt after resync.
An old committed transaction cannot release a newer pending transaction's fence.

Unknown temporary/orphan, incomplete material, neither-hash canonical, or
Applied-to-before contradiction remains fenced and retained for inspection.
Recovery does not adopt/delete unknown temporary files. No native input, command,
service change or other unknown side effect is replayed by this adapter.
Saved desired running/stopped or autostart settings are not actual OS state.

## Verification and limitations

Use the current Owner Control Report and immutable receipts for exact tested
source/binary. The required slice checks include formal malformed/raw-number
reader cases; real fresh-root/bootstrap/writer retention; actual phase resync and
orphan preservation; canonical commit, close/reopen and subsequent transaction;
foreign root and enrollment-gate refusal; stale committed recovery refusal; and
independent process exits at temporary write/fsync/rename, canonical rename,
phase persistence and committed reply loss. A separate process independently
inspects raw canonical/materials and phase hashes. Process exit is not power loss.

The source-local helper is cfg(test) only, not a production CLI mutation path.
Existing legacy identity/pairing/signatures/permissions remain untouched. Abort,
update/rollback, authenticated Desktop Agent, Host execution maintenance,
macOS/Windows store adapters and same-identity old-owner handoff remain separate
unfinished work. Platform compile, packaging, installation and real user acceptance
must retain their own source/artifact evidence.
