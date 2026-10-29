# Shared ports integrated for this slice

The integrator owns shared manifest/auth registration. The following ports are present.

- Add Gateway auth `AuthenticatedGatewayPrincipal::matches_owner(&VerifiedGatewayOwner) -> bool`, comparing its private principal digest to the owner's private principal digest. This does not mint an owner or expose a digest.
- Add pinned hyper1.12.0 server/http1, hyper-util0.1.21 tokio/server/service/http1, tower0.5.3 util; existing bytes/http/http-body/http-body-util/futures-util remain mature adapters.
- Dev official rmcp Streamable HTTP client with reqwest0.13.5 (matching SDK3.7 client), default features false. Do not enable a new production JS core or custom MCP parser.
- Register gateway::http only when all files exist. GatewayMcp remains read-only and prebound constructor is sufficient.
- Separate required GatewayOwnerLifecycle is defined in this subtree. Real backend must implement synchronous Core fence plus cancellation-safe owned observed cleanup. There is no successful default.

Development slice only: 256KiB input/output message ceiling is narrower than future real Cua/Browser images. One session's HTTP owner is not ChatGPT account proof. Session-header compatibility shim is exact2024-10-07 only under authenticated body/actual negotiated-session binding.

## Session capacity and turnover (2026-10-29)

HTTP has an independent `GATEWAY_HTTP_BYTES` reservation: 8 MiB fixed plus
64 × 1.5 MiB = **104 MiB**. `HttpBudget` rejects partitions over 128 MiB.
`HOST_QUEUED_BYTES` and the relay reservation are unchanged. This bounds logical
HTTP queue reservations, not process RSS or native Browser/Codex processes.
The listener admits 128 connections, sufficient for 64 SSE connections plus
POST/control traffic; global POST/body-reader/control limits remain 16/16/2.

A single cancellable, joined supervisor scans every 15 seconds. Ten minutes
without requests or streams makes a session eligible for expiry. At capacity,
initialization instead selects the least recently active eligible owner aged at
least 60 seconds and waits within the existing five-second close budget.
Expiry and eviction use the same fence, owner cleanup and observed SDK transport
join as DELETE. An active response body, GET stream, request, owned backend call,
running/uncertain/undrained exec or open Browser context prevents automatic close.
Computer actions in flight or with uncertain state also prevent it. An absent
liveness implementation defaults to live. The SDK's independent 60-second idle
timer is disabled because it cannot observe owner work. Old session IDs get 404.

The POST semaphore and backend call semaphore remain single-permit, but acquisition
waits up to the request deadline instead of immediately returning 429. The second
concurrent POST scenario observed **200 after the first stream's EOF**; a request
whose bounded admission wait expires gets 408. A second GET still gets 429.

### Owner storage and unchanged frame schemas

Each authenticated policy shares a ledger with private process-unique monotonic
u64 sequences. Minting reserves a record, including its future fence, before a
session is created. The ledger keeps a low watermark and bounded records above
it. Only cleanup Complete advances the watermark; Unknown pins it. At 4096
outstanding/history records NEW initialization is refused, while fencing needs
no additional record and cannot fail for capacity. Completed history beyond an
old active/Unknown owner counts against this cap. Backend owner maps and relay
bindings are removed only after successful physical cleanup. Both adapters use
the same permanent fence ledger, including late reply and final bind checks.

The relay encodes an epoch digest and increasing binding sequence into the
**existing opaque OwnerEpoch string**, and serializes new OwnerOpen exchanges.
Host first sight is therefore monotonic, with legal gaps for other devices.
There are no changes to styx-contracts, DTOs, field sets or frame schemas.
The Host records a high-water admission fence as well as the cleanup watermark:
a compacted or previously skipped sequence cannot be reopened. It reserves at
most the original 128 owner records; Unknown and out-of-order Complete records
keep their slots. Revoking an unseen key advances admission fencing without
allocating a tombstone. Cleanup Complete compacts contiguous observed completed
owners and releases native input-owner maps only after in-flight preparation
jobs join. The native factories recheck Core ownership after waiting for that
preparation/release gate.

`HostProtocol::accept_epoch` fences old leases and rejects retired Gateway epochs;
its existing bounded retired-epoch inventory remains in force. It does not reset
Unknown owner records on reconnect or epoch change. `foreground/run.rs` retains
the same HostProtocol across reconnects. Core owner incarnations, original owner
keys and revoked relay delivery gates prevent late completions being adopted by
another live owner. The wire serialization regression still checks exact v2 bytes.

### Measurements and margin

Method: run the real official HTTP service and LocalSessionWorker, using direct
HTTP bodies because sockets are unavailable in the worker sandbox. Warm one
session, sample glibc live allocations (`mallinfo2`, arenas plus mmap allocations),
initialize 64 idle sessions, then hold one near-ceiling SSE frame and its body.
Run alone so other tests cannot contaminate this process-wide sample:

```sh
cargo test -p styx-runtime --lib \
  gateway::http::tests::capacity::session_memory_measurement \
  -- --exact --nocapture --test-threads=1
```

Observed Linux sample: idle 64-session delta **6,392,176 bytes**, or **99,877 bytes
per session**; near-ceiling streaming incremental live allocations **529,504
bytes**, with an actual **261,225-byte SSE frame**. Combined idle plus streaming
is about 615 KiB; 1.5 MiB reserves roughly 2.5× that measured live allocation and
at least six 256 KiB message units. SDK channel capacity is one, completed cache
TTL is zero, and response sizes are checked before SDK caching. RSS is not used
to size the reservation: a separate RSS sample retained approximately 2.9 MiB of
allocator pages during streaming, including freed allocations.

**Open native Browser-tab measurement is pending reviewer execution.** The paired
socket scenario below opens a real tab, prints a live-allocation delta (combined
Gateway/Host Rust fixture, excluding child browser processes), and independently
checks running Exec and Browser-only protection from expiry. No native-tab memory
result is claimed from compilation or from the message-buffer estimate.

### Scenarios and observability

Non-socket tests execute 1050 initialize/DELETE cycles and 1050 abandoned-session
cycles through official SDK workers, 64-slot live-work overload, LRU eviction,
active GET protection, 404 and reinitialization, concurrent POST waiting and
near-ceiling output. A separate production HostProtocol scenario executes 1100
open/revoke/physical-cleanup cycles, rejects stale keys after compaction and an
epoch change, and checks Unknown cleanup and preparation/release races.

The registered ignored scenario
`enrollment::service::tests::paired_journey::paired_session_capacity_turnover_requires_sockets`
performs 1050 DELETE and 1050 abandon/evict cycles through actual paired TLS/WSS,
Gateway, Host and Codex, checks 2100 independent file effects, and tests live
Exec/open Browser protection. It requires the existing isolated paired fixture
inputs plus `STYX_TEST_BROWSER_NODE`, `STYX_TEST_BROWSER_WORKER` and
`STYX_TEST_BROWSER_EXECUTABLE`. It has been compiled, not run in this sandbox.

Authenticated MCP responses, including an unknown-session 404 probe, report only
`x-styx-sessions-{open,capacity,expired,evicted}` counters. Unauthenticated responses
carry none. Admin observe reads these after closing its discovery session, and
`styx status` displays `MCP sessions: open/capacity; expired; evicted`. No request
content, owner identity or tool arguments enter these counters.

### Review correction: settled Exec quota (2026-10-29)

The reviewer's paired run exposed `CodexStdio::limit`: the fixture intentionally
keeps `retained_process_limit = 16`. Decoded reads already removed RPC observations
on exit+drain, but did not remove the adapter's `records` or `operations` entries.
DELETE triggered physical collection; an abandoned MCP owner did not. Thus the
17th abandoned owner's start was refused locally, with no `process/start` frame.
The adapter correctly returned NotDispatched/Capacity. HostProtocol discarded
that cause into a generic Start reply (Failed/NotStarted); the Gateway's success
match rejected it and fell through to `outcome_unknown`.

Terminal paired reads now collect provider retention under the existing fair
quiescence gate and Core release permits before returning exit+drain success.
The owner remains open, Core history remains immutable, and delivery checks owner
and policy again after collection. Running, undrained and uncertain resources
are not guessed complete. The 16-process fixture limit and its 2100-cycle socket
scenario remain unchanged. A new cheap framed-pipe fixture exercises the real
Host/Core/Codex adapter with **64 owners kept open**, a separate 16-live-process
negative control, and historical no-replay checks. It observes zero retained
provider processes after each terminal read and no native start frame on refusal.

Relay routing entries for settled resources and their child actions are also
released. Action correlations remain available for reconciliation until that
resource settlement; uncertain prepares/actions still reserve bounded space. Typed
adapter NotDispatched capacity failures and proven pre-send relay Busy refusals
now report `capacity_busy`, `uncertain:false`, `retryable:true`. Browser and
Computer open completions preserve their proven Busy cause too. A genuine lost
reply or unknown dispatch keeps its uncertainty.

The Gateway Browser/Computer context maps, native profile factories, and Host
profile maps now admit **64 metadata owners** rather than 16. A config copy has an
enforced **128 KiB owned-metadata bound** (including allocated path/string capacity
and conservative map/session overhead), at most **8 MiB for 64 copies** per map.
Shared executable/source Arcs and native I/O reservations are not multiplied.
The Linux sizing fixture, using six 4095-byte Browser paths, measured
**160 inline bytes and 24,730 owned bytes per config; 1,582,720 bytes for 64**.
It also rejects an over-budget retained allocation. Native directory wrappers
retain bounded private paths separately; their cached records remain capped at
64 and are released on completed owner cleanup.

This raises metadata capacity, not native I/O concurrency: Browser and Computer
worker reservations still use their existing shared 16/8 MiB pools. Those limits
follow actual owned native workers, not a count of abandoned MCP identities.
When full, a new open gets a known capacity refusal. Closed Browser resources
are physically collected before their settled close response; they no longer
need DELETE to free retained provider/routing records.

Reviewer must rerun the unchanged paired socket scenario for the real Codex,
Node22 and Chrome proof. The cheap fixture and metadata measurements are not
claimed as that native acceptance.
