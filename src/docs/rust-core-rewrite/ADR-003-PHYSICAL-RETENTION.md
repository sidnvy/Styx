# ADR-003 · Physical retention, audit transfer and Host quiescence

Status: incrementally implemented, native verification in progress, 2026-10-24.
This changes an internal pre-release contract. Public MCP and native Codex wire
formats do not change. M4 is the last frozen fully checked checkpoint; receipts
outside source identify the later exact source revision.

## Problem and boundary

Core metadata collection does not release native process buffers, observation
subscriptions or the provider's bounded action map. The old `retire(owner,
handle)` also refused uncertain input and retained all action receipts, so it
could not reclaim that capacity. Neither deleting metadata first nor clearing
`input_unknown` is a valid repair. Native writeId and request acknowledgment must
remain available while their operation history remains retained.

Every dispatched Core record now automatically enters `Retained`. Reserved
records are `NotOpened`; no optional caller registration can leave a dispatched
resource untracked. Reaping accepts only `NotOpened` or `Released`. A physical
release changes no historical outcome, cancellation, exit or output-drain fact.
An operation that was Unknown stays Unknown, even if a later acknowledgment or
exit supplies additional evidence.

Core owns `ProviderReleasePermit` and its confirmation, with no Clone or
Deserialize. Typed bindings retain the original owner incarnation, Host,
operation, payload digest and target. Cleanup remains possible after revocation;
this authority cannot execute or read user output. Runtime reports physical
release as a trusted adapter fact, analogous to ExecutorFact, not an OS proof
accepted from a client. An abandoned/rejected release stays fenced and consumes
capacity; there is no force-release boolean or automatic success on drop.

## Audit and release sequence

Runtime uses an explicit versioned whitelist for Codex correlation: native
process UUID, writeId, evidence, request acknowledgment and a closed error code.
No argv, environment, stdin, stdout, screen data or arbitrary executor fields are
encoded. Core retains at most 1KiB of opaque immutable audit per action inside
its existing conservative accounting allowance. Core does not interpret audit
bytes or derive authorization from them. A changed second audit is refused.

Known action receipts transfer into Core immediately after settlement. A linear
action-release permit then frees their duplicate provider entry while the target
may still run. Host historical lookup falls back to that Core audit, preserving
writeId/ACK rather than manufacturing an empty successful response. Metadata and
audit remain until the original policy retention expires. Thus a long-lived
process is not permanently limited to 256 acknowledged inputs.

Unknown provider actions require an exact ended/drained resource bundle. The
trusted collector first records available correlation evidence. Missing provider
receipts remain explicitly unknown, never become proof of no I/O. Core verifies
independent exit/drain, exact target and absence of unsettled dispatched actions.
The adapter rechecks its own exit/drain, owner/digest, audit hashes and exact
uncertain input operation. It marks the record retired before removing the whole
record, action entries, operation map and observer. It never clears the input
marker and reuses the old resource. Queued old handle lookups recheck `retired`
after obtaining the record lock. Only then does Core record physical release;
normal retention can later remove metadata. A strict NotDispatched resource also supplies a first settlement timestamp for associated Unknown action retention; missing handles or ordinary timeouts never supply that proof. Native UUID is captured when the provider action is created, not rediscovered from a potentially removed operation map.

## Concurrency and lifetime

Host uses Tokio's fair `RwLock`, not a custom in-flight counter or another
service. Start/action obtain an owned read lease before Core commits dispatch;
the complete unsettled Drop guard retains it until outcome settlement. Native
read retains a lease through settlement and the second sensitive-delivery check.
A collector holds `cleanup_lock`, then an actual execution write lease, then
short Core mutex sections; it never waits for a write lease while holding Core.
A waiting writer makes new first dispatch return Busy with its reservation
unconsumed. Historical inspect/duplicate responses remain read-only.

The collector is an explicit trusted lifecycle port with a total bounded budget.
It reports blocked/unreleased records and deadline exhaustion separately from
success counts. It is not yet the final persistent service's periodic collection
scheduler. Final supervision, durable audit/journal, upgrade and restart recovery
remain separate obligations; this in-memory slice cannot discharge them.

## Required evidence

Pure Core contract scenarios must refuse metadata collection before physical
release, missing/changed audit, standalone Unknown action release, undrained
resource and in-flight action bundles. They must retain original-incarnation
cleanup, historical Unknown and fenced read/target access.

The first focused native Host scenario passed before a subsequent strict-NoIO metadata-GC correction (receipt preserves both source hashes). The final frozen gate must verify the final combined source. A native Host scenario must cross the actual old provider action capacity with
one long-lived process and independent effects, then prove low-capacity resource
reuse after actual exit/drain and collection. An ambiguous input must retain its
original writeId/Unknown through physical archival without replay. Collector
quiescence and Busy-before-commit require explicit concurrency controls. Mock
provider confirmations in Core tests are not physical/native acceptance.
