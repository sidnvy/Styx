# ADR-002 · Continuation authority and action settlement

Status: accepted implementation decision, 2026-10-24. Core target-bound actions, Codex permit-consuming continuation adapters and Host/WSS prepare-dispatch-inspect routes are implemented. Physical resource archival remains incomplete.

## Problem and decision

A consumed start permit cannot authorize unlimited later stdin or termination. A stdin acknowledgment proves request delivery, not process exit or command success. The existing `ExecutorFact::Exited` is therefore unsuitable for settling a continuation. Source review found this before exposing a Host continuation route.

Core keeps an independent action reservation and exact `ResourceTarget { operation_id, payload_digest }`. The target is stored separately from untrusted payload bytes and exposed on the private, linear DispatchPermit. Prepare and first dispatch verify the original target's owner incarnation, Host generation, device, capability and session binding, and current policy. The target must be a standalone, already-dispatched resource operation; actions cannot impersonate resources. Repeated tokens remain inspect-only, never second I/O.

A targeted action owns no process, so its execution-liveness is `not_applicable`, not a fabricated `exited`. Explicit action result facts settle only that action: acknowledged means its particular request was acknowledged; pre-I/O refusal requires real NotDispatched proof; unknown stays unknown. Neither stdin ACK nor terminate ACK mutates target liveness, output drain or outcome. Native target exit/drain facts still settle the original resource record independently. These are internal Rust model additions before any released Rust reader; public MCP and native Codex protocols do not change. Frozen semantic revision2 records the rationale.

Fresh resource reads recheck the same original target binding/current owner/current grant/local policy with their own deadline. Expiration of start admission does not invalidate the ability to observe a still-authorized long-lived process. Session Degraded is aggregate: an individually Available and Granted provider can continue, while locked, stale and unauthorized operations remain denied.

## Retention and maintenance

Known request-level action completion can be retained/pruned as an action without inventing a child process. Unknown targeted actions cannot be evicted while their target may still execute. They become eligible under the declared retention policy only after the exact original target is independently proven Exited and Drained; Unknown history is preserved. Parent target metadata cannot disappear first in a way that fabricates that proof. Maintenance cannot use `not_applicable` to skip unsettled target uncertainty.

Core-attested physical retirement of provider buffers after ambiguous stdin is a separate follow-up. It must bind exact uncertain action and ended target, fence resource mutation and preserve audit state; no force-retire boolean or clearing input_unknown is authorized by this ADR.

## Callers and verification impact

Core gains additive targeted prepare/dispatch/action-fact APIs. Codex continuation APIs consume the target-bound permit and exact immutable action bytes; legacy owner-only write helpers are test-private. Host-owned jobs consume permits and preserve independent action ACK versus process exit/drain. Bootstrap fixture owners do not discharge Gateway-issued owner coordination.

Required counterexamples: A-owner action on B-resource, same-epoch re-registration, target action mistaken for a process, changed payload or target, grant revoked between prepare/dispatch, duplicate action, ACK while target still runs, unknown action followed by target exit with unknown history unchanged, retention while target live, and metadata/resource archival ordering. Mock contract checks do not replace real stdin effect and cancellation observations through the eventual integrated Host.

Standalone resource retention preserves the existing policy: first terminal evidence starts retention; drain is an eligibility gate. Repeated observations of the same exit/termination cannot refresh that timestamp. Unknown targeted actions deliberately use the later of their first Unknown and the parent's first fully Exited+Drained observation, so referenced parent metadata remains pinned for the full additional audit interval. These two policies are explicit rather than silently changing the prior standalone contract.
