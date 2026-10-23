# Architecture boundaries and incremental evolution
> 2026-10-24 owner update: the technology choice below is superseded by [Rust rewrite execution baseline](rust-core-rewrite/README.md). Rust will replace the Styx-owned core; the earlier no-rewrite/Node decision is historical. Identity, permissions, ownership and unknown-result safety remain requirements. This file records the pre-rewrite architecture review, not the current execution plan.

Review baseline: `8e4e645f741573242aaf4dbe2abd2cccbb4678a3` (2026-10-24). This document records current contracts and proposed changes; it does not claim the proposed session APIs or unattended desktop scenarios are implemented.

## ADR-001 — Keep the existing management and execution composition (Accepted)

`onboarding/core.mjs` is the shared deployment/configuration/transaction management API. CLI and native clients call it; it composes Gateway, Host and platform adapters. It is not a domain library located after Host on every remote operation. Remote execution follows Gateway providers → authenticated outbound Host lanes → existing executors. These two logical paths share policy and contracts without reversing imports or adding a second configuration authority.

Keep Node orchestration and the existing Codex Exec, Playwright Browser and native Cua backends. No Rust rewrite, new router service or microservice split is justified by current evidence. A measured hotspot can later be replaced behind its existing contract.

## ADR-002 — Separate availability, authority and lifetime (Accepted)

- Deployment roles express requested configuration; Gateway device approval expresses remote authority; platform observations express actual desktop capability. None substitutes for the others.
- Exec, Browser and Computer have separate lanes. No desktop, lock, lost permission or compositor loss should downgrade unrelated lanes. Identity, signed release, configuration scope or authorization failure remains an owner-wide fail-closed condition.
- Closing Settings hides it. Explicit Quit stops components owned by that App. Independently managed CLI/services retain their existing ownership. GUI-optional does not silently reverse this established Quit policy.
- App-owned foreground mode and independently managed persistent Host mode must be reported separately. Persistence beyond graphical logout is not established by an App login task or a running systemd user manager.
- Gateway transport reconnection is not operation recovery. Current Exec connector closes its owned executor when the transport lifetime ends; old handles become invalid. This does not establish durable jobs or permission to replay a command. Browser keeps its owned supervisor outside transport reconnects. Any future executor-lifetime change needs its own ownership/cleanup contract.

## ADR-003 — Bind desktop sessions before adding processes (Proposed; implementation incomplete)

Use a logical session registry backed by the existing host/platform adapters first. A session-owned native agent is appropriate when desktop environment, permissions or failure isolation require it; do not add another always-on broker merely to match a diagram.

Proposed `SessionDescriptor` includes opaque identity, user, login/session instance, seat when available, platform desktop/compositor instance, displays, generation, lock/authorization state and observation provenance. Missing platform facts remain unknown. Generation is valid only within one observed lifetime; PID, username or session number alone is insufficient.

Separate three selection inputs: explicit target, previously approved binding, environment hint. Explicit or approved target failure must not fall through to another session. A hint may help discover candidates but cannot authorize switching. Ambiguity fails closed and exposes candidates for explicit selection. Existing `XDG_SESSION_ID` fallback is not this public contract.

Existing Linux resolver checks logind/UID/lock/runtime/display socket. It does not authenticate the association between a forwarded compositor environment and that login session. Its synchronous subprocess calls also block the Host event loop. First evolve acquisition into bounded, cancellable asynchronous adapter probes; then bind descriptor/generation to Computer and headed Browser. Keep native Cua responsible for its supported capture/input/window operations. Portal/PipeWire/libei/AT-SPI implementations are not introduced by this decision.

Windows keeps ordinary user-session, WinSta0 and Default desktop restrictions; enrich session identity and invalidation instead of using SYSTEM/Session0 to obtain desktop authority. macOS keeps the signed embedded native permission-bearing process and TCC attribution; a hidden native session agent is compatible with GUI-optional, but moving that responsibility to generic Node/CLI is not accepted.

## ADR-004 — Project capability facts without broadening grants (Proposed)

An internal versioned capability descriptor should express `id`, `scope`, `provider`, `availability`, `authorization_state`, optional session/generation, reason and recoverability. Keep configured, authorized, connected and operation-verified facts separate. Expose unsupported/unknown honestly; capture support does not imply input or accessibility support.

Preserve existing approved `exec/computer/browser` grants. A finer availability projection does not silently create new grants or a new permissions database. Headless and headed managed Browser are implemented; arbitrary attach/CDP takeover is intentionally unsupported in this convergence scope.

## ADR-005 — Preserve native tool contracts and operation uncertainty (Accepted direction; uniform envelope proposed)

Keep native tool names/schemas. Internally associate request/owner/device/generation, optional session/snapshot/target, deadline, cancellation owner and dispatch phase. Do not add a competing public task scheduler or require new fields on every upstream tool during release convergence.

Lifecycle: created → validated → dispatched/running → succeeded, failed, cancelled or unknown. Pre-dispatch refusal proves not dispatched; transport timeout after dispatch cannot prove cancellation or rollback. A cancellation request becomes confirmed only after backend evidence; unknown input/click/command results are never replayed automatically. Session invalidation rejects old references and starts discovery, not continuation of old input.

The Exec cleanup fix in this change validates `process/read` using an independent cursor. An independently reported valid process exit can confirm termination before output EOF. Output closure without exit, malformed replies and executor failures cannot confirm termination. Cleanup confirmation is not proof that earlier side effects were rolled back or output was fully drained.

## ADR-006 — Reuse secure local channels (Accepted direction; session binding proposed)

Existing owned parent/child stdio is the default private local channel, not a public Desktop Agent service. macOS also uses a fixed App-owned private socket. Keep signed path, owner, directory permissions and generation constraints. Do not claim the experimental `GuiBroker` socket policy or target-generation checks are guarantees of default `CuaProvider`.

If a separately attachable desktop agent is introduced, require protocol version, authenticated local peer/owner, explicit user/session/generation, bounded discovery/events/requests, deadline/cancel/disconnect semantics and resource ownership. Do not accept arbitrary remote socket paths or expose its management endpoint on the network. Verify actual native listener authentication before claiming peer-credential protection.

## Error and failure-domain contract

Keep existing machine-readable provider error codes and `uncertain` facts. Add a versioned category projection only from verified structured observations: no graphical session, ambiguous session, disconnected/locked/restarted session, permission required/denied, unsupported capability, stale observation, missing target, unattached browser, timeout, unknown result. Preserve original provider code. Never infer a permission grant or definitive error from arbitrary stderr text.

Routine desktop unavailability stays local. Unexpected provider crashes should close that lane and retain unknown in-flight results. Credential, signature or owner-scope compromise stops the whole owner. The current generic foreground task rejection path does not yet distinguish these classes; do not fix it by swallowing every exception.

## Verification and release boundaries

Current deterministic tests cover owner/generation, snapshot isolation, unknown mutation results, Browser context closure and observed Linux/Windows desktop cancellation. They do not establish real logout, compositor restart, multi-seat, lock/revocation, SSH-to-old-tmux or cross-platform unattended acceptance.

Next sequence: (1) fix demonstrated contract errors; (2) approve explicit session/ownership semantics; (3) implement async session probe, classification and internal descriptors; (4) verify IPC/session generation and action-time revalidation; (5) batch existing native journeys plus missing lifecycle scenarios on one frozen candidate. Native platform topology may differ. Do not disturb the current Workstation session or reboot it to satisfy this matrix.

All implementation changes require their own source/test/package/install/acceptance evidence. Existing `0.3.0-rc.20261024.1` artifacts remain tied to `8e4e645`; a later source fix does not retroactively change their acceptance status.
