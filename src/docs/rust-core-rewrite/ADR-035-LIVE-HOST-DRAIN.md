# ADR 035 — Stop one Host while its Chat owner remains active

Status: implementation in progress; no acceptance claimed. Base: `84127f6`.

## Trigger and boundary

R43 actually established two Host links, independent Exec effects across owned App Pause/reconnect/Quit, and complete Gateway cleanup when explicit MCP termination precedes App stop. A user can also Pause or Quit while Chat remains open. Closing the socket first makes the original remote owner cleanup unprovable. Local process exit, a new Host generation, or a later successful reconnect cannot settle that missing proof.

Drain only the original authenticated Host connection and its original binding cohort. A Chat owner may simultaneously use another Host. Do not globally close or fence that owner, silently bind its old resources to a restarted Host, or replay an action. Core retains sole authority for owner leases, grants, operations and physical provider cleanup.

## Private contract

The paired Host advertises `transport_drain_v1`. Only a Gateway which sees that advertisement sends `EnableTransportDrain` and receives `TransportDrainEnabled` on the same connection. A normal stop then sends one bounded HostControl carrying a drain request ID, original connection/Host generations and a capped 15-second total budget. Identity comes from the authenticated Entry, never this DTO.

The Gateway fences new business and OwnerOpen admission, atomically captures bindings at the same entry gate, and retains the original socket loop while it requests existing OwnerRevoke and OwnerCleanup controls. A reserved but unconfirmed open remains Unknown. The existing per-owner cleanup maximum remains five seconds within the total budget. The original Entry/task owners retain cleanup jobs through response waiter or socket loss and actually join them; no second reader, new network endpoint, new journal or business replay is introduced.

Only exact matching `OwnerRevoked.fenced=true` and `OwnerCleanup.complete=true` record completion for the original Binding and Entry incarnation. Concurrent DELETE/drain observes the same serialized cleanup. Later DELETE consumes retained completion before requiring an online socket. Unconfirmed state remains Unknown. Presentation resources retire only for proven bindings; the same owner's other devices and global owner stay usable.

The Gateway sends `TransportDrainResult` for the exact outstanding ID and Host generation; the Host accepts it only on its original enabled connection and returns the matching acceptance. Missing result/acceptance stays unconfirmed for its observer. Already observed per-binding physical proof stays true; a missing final packet cannot invent or erase that proof.

## Local lifecycle and failure

On local stop the original Host protocol future remains polled to handle revoke/cleanup. Host owner fences reject new operations, while original supervised operations and resource cleanup retain their custody. Unsupported old peers, stale IDs/generations, socket loss or deadline cannot produce remote Complete. No reconnect is attempted as drain recovery.

Local executor/process/I/O/job shutdown always runs and retains its original leases until actual settlement. `ForegroundOutcome.remote_transport_drain` separately records Complete, Unknown or Unsupported; legacy paths may omit it. Local completion controls the cleanup loop, so remote Unknown cannot cause a fake success or an infinite local cleanup retry. The App retains actual local facts and fences subsequent control mutations when remote outcome is Unknown. Ordinary App exit uses proven local settlement; the ticket is explicitly scoped to `local_app` and does not certify remote cleanup. Update/maintenance handoff still requires full remote settlement. See the 2026-11-04 correction below.

## Acceptance and migration

One real suite must keep the same official MCP owner using App Host A and independent Host B. After a confirmed A effect and a confirmed running A operation, Pause A with Chat open: A original resources fence and settle, old SID/actions refuse without effects, B keeps its original Host/executor births and executes once. Explicit A restart uses a fresh owner; later DELETE of the old owner consumes only original retained binding proof. Final Gateway tracked cleanup requires zero unconfirmed owners and actual original child waits.

Controlled result/acceptance loss, in-flight OwnerOpen/DELETE races, stale IDs/generations, old-peer negotiation, bounded-capacity refusal and Browser-only control admission require separate contract/fault evidence. A positive real journey does not substitute for these. Native UI integration, same-identity migration/rollback, JS retirement, signed candidates and platform/account/permission/lifecycle acceptance remain full goal requirements. Public MCP38/Computer10 are unchanged.

## 2026-11-04 — Separate ordinary App exit from remote completeness

Owner-directed design audit after a real unavailable-Gateway Windows Quit: original local executor/process/I/O/jobs/events all joined, but `remote_transport_drain=unknown` caused Core2/App4. Ordinary local lifetime must not depend on a live Gateway.

- Ordinary Quit and stdio EOF await the same original local work. Only proven local joins allow a clean local exit. Other local/identity/configuration/update failures remain failures; service and maintenance ownership remain independent.
- A `ready_to_quit` ticket with `scope=local_app` certifies local admission only. The unchanged cleanup object retains the exact remote result. It never means remote Complete or release success.
- A missing remote receipt remains a control fence. A fresh link's successful drain cannot erase an older link's Unknown/Unsupported result in the same run.
- Before a clean local exit with remote uncertainty, preserve a bounded, private, exclusively created `app-local-exit-<ticket>.json` observation beside the App's profile container. It contains fixed cleanup facts, never credentials or arbitrary provider output. Failure to preserve the observation stays an error. This is not a configuration authority, recovery journal or permission to replay/adopt old work.
- Pause may commit the existing local C07 Stopped intent only after actual Host joins, preserving a separate immutable `app-local-pause-<id>.json` Unknown receipt; network loss must not turn a requested Pause into automatic reconnect on reopen. Role changes, runtime update and installation handoff retain full settlement requirements. This correction does not turn an old uncertain action into a successful action.

Required evidence: ordinary online exit; Gateway unavailable exit with local joins and retained remote Unknown; reconnect preserving older Unknown; incomplete local cleanup and unrelated pending-operation negatives; default/independent owner preservation. Contract fixtures alone do not establish native acceptance.
