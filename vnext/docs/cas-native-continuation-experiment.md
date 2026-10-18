# CAS P0 — native MCP App turn-continuation spike

**Status:** experimental implementation with local contract and simulated-Host tests.
**Source baseline:** created from c81a111f, then integrated VNext 236c7bbb (same-host multi-user isolation release gate).
**Production:** NOT installed, NOT deployed, NOT accepted by a real ChatGPT Host.

## Goal and non-goals

Test whether an explicitly started, harmless Run in ordinary ChatGPT Chat
can use one native MCP App card to request subsequent model turns with
the standard ui/message host bridge. Preserve the official ChatGPT Mobile/Web
as the user entry point. This is NOT Work, Codex-agent orchestration,
a browser extension, a shell executor, quota extension or a Stop interceptor.

This is a bounded, single-user experiment. It does not authorize real file
writes, shell, desktop actions, deployment or automatic host mutation.
All follow-ups ask only for cas_experiment_consume, which records a single
confirmed model-turn receipt. Maximum four rounds, 15–180 seconds between
rounds, maximum one hour per Run. The operator must use a dedicated test
Gateway with independent credentials, Run directory and connection.

## Strict protocol and lab-only access

The ui/message request keeps MCP Apps ContentBlock[] array semantics;
it is NOT a single TextContent object. Simulated-Host tests validate
the exact outgoing message against the pinned official
@modelcontextprotocol/ext-apps@2.0.3 McpUiMessageRequest JSON Schema.
The Host must advertise message.text or OpenAI's experimental openai/message
capability, otherwise the View does not dispatch.

For a real ChatGPT test use STYX_CAS_EXPERIMENT_ONLY=1 and an empty
Target Catalog. The Gateway then advertises only the nine CAS tools and
rejects native Exec/Cua requests even if the caller guesses their names.
A separate local-only Gateway has been smoke-tested on workstation at
127.0.0.1:18895/mcp; no OpenAI Tunnel or Custom Plugin was installed
when this section was written. See
[CAS Lab connection runbook](cas-lab-connection.md).

## VNext integration boundaries

- VNext retains the exact Codex Exec and native Cua tools and session owners.
- The optional CAS tools/resources are registered only if an operator passes
  STYX_CAS_EXPERIMENT_STATE_DIR in the Gateway launch environment.
- CAS Run ID is durable and is not an MCP HTTP session ID, Codex process
  session, Cua lease, target identity, or ChatGPT Conversation ID.
- A single private JSON record per Run is atomically replaced (mode 0600)
  before tool acknowledgement. The directory must be private mode 0700.
- All CAS operations run through the authenticated existing MCP Gateway;
  no independent public listener, credential or second provider is created.
- The App View is a lightweight carrier. It is never the canonical owner
  of Run state, execution results or retry permission.
- The Server is the only authority for Wake claims, dispatch fences,
  follow-up identity and exact consumption.
- The experiment uses one process per CAS state directory. It is not
  distributed locking or durable execution across Host reconnects.
- The experiment currently uses the existing VNext stateful MCP SDK
  and transport; real ChatGPT MCP App admission and protocol compatibility
  must be checked separately. Passing local SDK tests is insufficient.

## Model-visible flow

1. The user explicitly requests a harmless CAS test.
2. Model calls cas_experiment_create with bounded objective, rounds and delay_ms.
3. Model calls cas_experiment_present with the exact returned run_id.
4. Model promptly finishes its CURRENT assistant turn with a normal final
   answer. The tool card alone is not a final; do not keep doing other work
   in that turn after presenting the carrier.
5. The hosted App initializes through ui/initialize, receives the exact
   run_id through ui/notifications/tool-input, and polls App-only state.
6. After the server-owned due time the App atomically claims one Wake,
   then calls prepare. Prepare durably spends that exact dispatch attempt.
7. The App calls Host ui/message with the one server-authored safe message,
   and reports accepted vs unknown dispatch. It never reissues that attempt.
8. If ChatGPT truly starts a later MODEL turn, that turn calls
   cas_experiment_consume with the exact Run, round, Wake and token.
9. Only exact consume advances the round, creates the next due Wake,
   and eventually completes the bounded Run.
10. cas_experiment_status can inspect progress from any authorized Chat.
    cas_experiment_stop permanently halts further automatic dispatch.

App-only tool names are cas_experiment_poll, cas_experiment_claim,
cas_experiment_prepare and cas_experiment_finish. Their metadata declares
ui.visibility=["app"] and deliberately does not bind a new App card.
The presenting tool alone binds ui://styx/cas-continuation/v2.

## Delivery safety

States include pending, claimed, prepared, dispatch_accepted,
delivery_unknown, and consumed (subsequent run may be running/completed,
stopped, or expired). Dispatch accepted means Host acknowledged ui/message,
NOT that a model turn began. Delivery unknown NEVER authorizes replay.

An unprepared claim may expire and be taken by a different View. Once
prepared, no View may automatically prepare or send that Wake again.
A follow-up model may consume a prepared Wake before the iframe receives
the ui/message ACK; the Server accepts that exact consume and prevents
a later ACK from undoing it. Duplicate exact consumes are idempotent.
Stale and foreign claim IDs fail closed.

This experiment does not infer the source ChatGPT Conversation ID from the
Gateway's MCP owner, page recency or Host target. A real CAS product will
need an exact Session Binder and user-account scoping before multiclient use.

## Local tests — no ChatGPT account involved

Run only inside a disposable checkout of the experiment branch:

    cd vnext
    npm ci --ignore-scripts --no-audit --no-fund
    node --test gateway/test/cas-*.test.mjs
    npm run test

The tests check state persistence, expiry, concurrency, identity mismatches,
restart recovery, tool/resource metadata, isolated MCP HTTP clients, the
real iframe controller script through a simulated MCP Apps Host, ui/message
ACK versus exact consume, and never-resend on Host refusal.

The complete VNext test suite additionally needs the documented pinned,
checksum-validated Codex Exec binary prepared ONLY in this checkout:

    python3 packages/styx-exec-adapter/prepare-runtime.py
    npm run test:all

Running local tests proves only our code and simulated Host contract.
It does not prove a current ChatGPT account permits unattended turns.

## Real Host observation: first follow-up passed, second dispatch unresolved

On October 18, the first `ui/message` produced an actual new ordinary-Chat
model turn and an exact `cas_experiment_consume` receipt. The next scheduled
wake was prepared and subsequently marked `delivery_unknown` without a
second consume. The original controller discarded the `ui/message` exception.
This does NOT prove a Host-wide continuation limit or a failed model turn.

The lab-only follow-up adds bounded diagnostic fields `failure_kind` and
`host_rpc_code` to Wake public status. It never stores the raw Host response,
private tokens, or user conversation text in a dispatch diagnostic.
`delivery_unknown` is still fenced against automatic replay. The next
separate trial should use a longer interval after the first consumption,
and compare RPC rejection versus timeout before changing scheduling policy.

## P0 Host lifecycle isolation: ui/message method not found

A real ordinary Chat produced one automatic cas_experiment_consume receipt,
then the second scheduled Wake received failure_kind=rpc_rejected and
host_rpc_code=-32601. JSON-RPC -32601 means method not found. This is
distinct from the separate MCP Gateway HTTP 503 session-exhaustion issue
previously fixed in CAS-only lab mode. This evidence alone cannot establish
whether the Host's App bridge lifecycle changed or a platform restriction
applies.

The v2 App resource persists only bounded lifecycle information: View
controller UUID, last seen/poll time, visibility, initialized message
capability, and presence of the documented ChatGPT compatibility function.
Never record raw Host error strings, sensitive tool arguments, user messages,
or continuation tokens in diagnostics.

First use MCP Apps ui/message. Only on an exact JSON-RPC -32601 response,
and only if window.openai.sendFollowUpMessage is feature-detected, invoke
that documented compatibility bridge once for the SAME prepared Wake.
No fallback after a generic rejection, timeout, or uncertain delivery.
Accepted transport and initial error code are recorded separately.
A compatibility API acknowledgement is not a resumed model Turn: only
an exact new cas_experiment_consume call qualifies as completion evidence.

Retest two rounds using a NEW v2 View in ordinary Chat. Compare the
view.last_seen_at, view_events, wake.dispatch_transport, and
wake.primary_rpc_code against the actual new model Turn and consume.
If repeated turns are not supported reliably, separately investigate
new explicit App cards per Turn and the optional workstation Browser
Companion; never silently retry an uncertain attempt or bypass limits.

## Future real-Host acceptance (NOT performed)

Use a disposable Gateway, separate credentials, separate tunnel/custom Plugin
and an explicit user-initiated test conversation. Do not replace production
Styx, Charon, Coder, Tunnel, existing Plugin or OS service.

For each of the following conditions, collect an exact Run ID, Wake ID,
attempt ID, dispatch state, first new ChatGPT turn and consume receipt:

1. Web foreground, 30 seconds, two rounds without another user message.
2. Web foreground, five minutes, two rounds.
3. Web background tab, five minutes, two rounds.
4. Web tab closed then reopened; note that no View can poll while unmounted.
5. Mobile foreground, then background/locked, under account-supported Apps UI.
6. Host ui/message refusal, View teardown, and ambiguous Host ACK.
7. Two mounted Views for one Run; prove no duplicate Send or consume.

**Acceptance:** cas_experiment_consume must actually be dispatched by a
fresh model turn for every claimed success. A rendered card, successful
tools/call, accepted ui/message RPC, displayed user text, or status poll alone
does not prove resumption. Do not advertise unattended based on local tests.
Hosts may request user consent, throttle background Apps, discard hidden
Views or lack ui/message support entirely.

If the real ChatGPT protocol/tool-registration path differs from the current
stateful VNext Gateway, implement a separate reviewed compatibility adapter.
Do NOT casually replace VNext's authenticated MCP session and native Cua
transport contracts.

## CAS-only MCP session capacity recovery

The real ChatGPT Host can create many Streamable HTTP MCP sessions and leave
passive SSE subscriptions open without sending a matching DELETE. In one
live experiment the Gateway exhausted its 32-session limit and authenticated
new `initialize` requests returned HTTP 503 even while the Tunnel Client
reported ready. This is separate from the App View's `ui/message` dispatch.

Only when the CAS-only CLI profile is active, the Gateway now uses an
`idleSessionTimeoutMs=120000` policy and reaps idle sessions at saturation.
A passive long-lived GET/SSE subscription does not count as an in-flight
operation; active POST operations are protected against eviction. A stale
client may have to reconnect after its session is reclaimed. This is a
capacity recovery mechanism, not a guarantee that the Host continues to
mount an MCP App View or schedules another model turn. Production Gateway
retains the previous default without idle eviction.

The isolated test suite covers default maxSessions behavior, idle recovery,
and preservation of an active in-flight request. Do not infer that this
fix alone establishes multi-turn autonomous continuation reliability.

## Future CAS (out of P0)

Native MCP App and workstation Browser Companion remain alternative,
separately authorized continuation carriers above one durable CAS Run Ledger.
Only one carrier may own a Wake. Execution remains on Styx VNext's Codex Exec,
Cua and typed Host registry; no duplicate execution plane. Deterministic
task acceptance would precede Goal-helper decisions, with user Stop always
taking precedence over further dispatch.

Background-browser automation must be separately reviewed for applicable
ChatGPT terms and safety. This P0 does not automate ChatGPT DOM, browser
navigation, account selection, or model-access restrictions.
