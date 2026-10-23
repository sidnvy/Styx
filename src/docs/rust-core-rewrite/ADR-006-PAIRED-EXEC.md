# ADR-006 — Paired Gateway to native Exec vertical slice

Status: implemented development slice; acceptance evidence is external and bound to source inputs. This document alone is not verification, a migration or a release gate.

The existing frozen public MCP table remains 38 tools. Four have paired Exec routing: `exec_command`, `write_stdin`, `list_execution_environments`, and `get_execution_environment_status`. The other tools explicitly report unsupported. There is no added public terminate tool, no new UI or second configuration authority.

## Responsibilities and dependencies

`enrollment/service.rs` owns durable pairing/self/admin authorization through the existing Core and owned journal. `enrollment/shared.rs` shares this exact object; a composed listener rejects a relay backed by another object. Tokio's mutex bridges async authorization with blocking durable work. Bounded profile readers retain the same authority and permits until actual completion; a panic fences further use. No device/admin bearer is exposed in routing metadata.

`enrollment/http.rs` composes enrollment HTTP, official MCP SDK HTTP and paired WSS on one strict TLS listener. Hyper owns the HTTP upgrade; tokio-tungstenite owns WebSocket framing. Upgrade tasks retain the original connection permit after HTTP101. All negotiating and established actors are registered against the same closing fence and joined. Socket closure and native executor exit are separate facts. Official SDK tasks without an exposed join remain explicitly unknown.

`gateway/paired/relay.rs` resolves explicitly selected approved devices and mints an owner epoch only after `VerifiedGatewayOwner` was obtained from the authenticated MCP ingress. The principal fingerprint and exact HTTP owner remain bound to that epoch. Its resource references are routing ACLs and correlation metadata; the Host Core remains the sole reservation, dispatch, action and native-resource authority.

`gateway/paired/backend.rs` maps the frozen public arguments to Host prepare/dispatch/read/action calls. A numeric session ID is a presentation handle scoped to the exact authenticated HTTP owner and principal. Per-resource async serialization, fresh action reservations and original resource digests prevent overlapping writes or retargeting. The device's verified platform/cwd/shell profile supplies defaults; the Gateway's shell, credentials, PATH or graphical-session environment are not inherited. Headless Exec does not imply desktop authority. No configured default means explicit selection is required.

`host/protocol` version3 admits owner control only after fixed paired endpoint TLS, fixed Gateway namespace and explicit challenge/version negotiation. Version2 remains its existing bootstrap-owner protocol; the legacy Host endpoint is not silently interpreted as version3. The protected Host bootstrap owns one Codex executor across link changes.

The test client uses official rmcp with pinned reqwest/Rustls and explicit AWS-LC/owned CA configuration. It does not implement SSE, TLS or a custom certificate verifier. Its extra platform TLS closure is dev-only, outside the CLI's normal dependency graph.

## Independent identity and lifecycle facts

Keep device ID/fingerprint, enrollment capability generation, Gateway execution epoch, Host generation, Gateway admission connection generation, Host wire connection generation, HTTP owner ID, owner epoch and Host policy revision distinct. Host policy revision is reported by the Host, never cast from enrollment capability generation.

The same Host link generation cannot be replaced by a late close for another generation. Revocation/CAS invalidates Core connection authority. The actor checks current device authority and owner fence at the actual synchronous `start_send` boundary after socket readiness, and at response delivery. Business requests have bounded multiplexing and a separate control allowance. A queued request cannot bypass an owner fence simply because it passed an earlier check.

A new Gateway execution epoch fences prior Gateway-issued owners. Retired epochs prevent A→B→A resurrection within retained process history. Host generation changes invalidate old native references. Connection loss neither restarts the executor nor redispatches operations or consumed reads. Durable restart/resume of this routing inventory is not implemented by this slice.

## Owner close and unknown outcomes

Gateway owner close synchronously blocks new/queued business admission before asynchronous cleanup. Host owner revocation mints an opaque exact-incarnation cleanup authority. It does not restore ordinary revoked dispatch/read permissions. Cleanup runs in the Host's existing supervised job set; dropping its waiter does not cancel the actual job.

Cleanup may terminate and discard output only for that owner's original resources. It uses the existing provider ownership checks and Core physical-release permits, never global executor shutdown or replayed stdin. The fair execution gate provides bounded physical quiescence; another owner's I/O may briefly wait, but its resources are not killed or released. Physical completion requires real exit/drain/release, not a termination ACK. Per-owner JoinHandle proof is not available and remains `None`.

Only explicit typed Host evidence can establish `not_dispatched`. A lost/late transport response, unknown mutation or consumed read cursor remains unknown. Explicit inspection can reconcile original operation facts; it never substitutes a fresh dispatch or silently transfers a handle to a new Host/owner/session. Capacity remains reserved when cleanup or history is uncertain.

## Limits and remaining scope

This is bounded first-slice routing: 16MiB WSS reservation units, two business pending calls plus a control allowance, retained owner/fence/connection-history limits, at most64 backend resources, and256 admitted records per binding. There is no automatic eviction to make room for ambiguous operations. Long-lived use can reach a deliberate capacity refusal; persistent retention/GC scheduling is separate work.

Environment listing currently projects approved Exec-capable devices, not a completed Browser/Desktop inventory. Missing Browser/Desktop facts are unknown/unsupported rather than fabricated readiness. Shells are restricted to the verified configured shell. Extreme escape-heavy legal public strings can exceed the smaller bounded Host frame/spec contract and be rejected before execution. A read waits at most100ms per native call and cannot resume a lost cursor.

The owned Linux acceptance journey exercises actual signed synthetic enrollment, official MCP TLS client, outbound paired WSS, real Codex nonce/stdin, wrong device/credential/legacy-route upgrades, cross-owner input rejection, exact PID/starttime disappearance plus Host physical completion, other-owner survival and device revocation. Mock or source reviews do not prove old-epoch reconnect, dropped-cleanup-waiter, OS login/session behavior, original identity migration, Mac/Windows native operation, signed packages or real account acceptance. Those require separate actual evidence and remain outside this checkpoint.
