# ADR-010 · Frozen Browser tools and resource-local references

Status: incremental implementation; focused pure-Core/provider and actual Linux
headless Host reference journey passed. Complete frozen integration gate remains
a separate receipt. No R19/release completion.

The existing24 Playwright tool definitions remain the single schema source at
src/packages/styx-browser-provider/playwright-contract-0.0.83.json. Rust includes
that exact artifact; it does not create a second tool catalog or schema dialect.
The mature jsonschema0.60.1 validator compiles fixed schemas once, with default
HTTP/file retrieval and async retrieval features disabled. Tool arguments cannot
supply schema documents, environment routing or internal metadata. The added
locked dependency closure replaces none of the previous package versions.

BrowserAction::Tool extends the existing Core permit path. Navigate/Evaluate/Close
payload aliases stay compatible. Host detects both Close encodings and uses the
same real native cleanup. URL/file policy and result delivery remain Rust-owned.
The controlled workspace/output checks are not a filesystem sandbox against a
compromised same-UID process. File-transfer and output artifact behavior require
actual independent oracles before they can be called accepted.

Core BrowserReferenceScope is resource-local domain state, not a new owner issuer
or operation ledger. It holds the original opaque OwnerLease and ResourceTarget.
Fresh OS entropy from the runtime, exact operation/digest, snapshot revision and
native reference produce public styx-128bit opaque tokens. References are replaced
rather than merged. Replacement failure clears old references; monotonic overflow
fails closed. Limits are2048 input references and256KiB logical retained metadata
for the one active context. This is separate from native process memory and I/O
budgets. The scope itself performs no I/O/RNG and is neither serializable nor
cloneable. A token's syntax alone grants nothing.

The provider holds its original resource mutex across the entire native request,
including the response. The trusted Host still checks current owner/grant under its
existing Core admission lock. Target fields, including nested form targets, are
resolved only inside the original scope; raw native references, unknown opaque
references and direct aria-ref selectors are refused. Unique selectors from the
existing public contract remain supported. Mutations and new observations invalidate
old references. Result delivery is still separately reauthorized; ref lookup is
not a substitute for owner/grant authority.

The thin Node0.2.0 worker reports factual native epochs. Page/frame navigation,
page/context closure and tab changes advance a bounded safe integer. Its internal
state query creates no browser. Request metadata can require an expected epoch;
the worker checks it synchronously immediately before forwarding through the
original official MCP client. Response metadata overwrites the reserved native
fact field so upstream/page output cannot impersonate this fact. Rust, not Node,
mints refs and decides policy. Only a successful stable native observation can
mint new references. Missing/malformed protocol facts fail closed.

First real tool startup may create the owned context. When no context/observation
exists, Rust may omit an expected epoch; it cannot downgrade an existing reference
or stale scope to that path. The worker uses the same cached context getter before
capturing the dispatch epoch, then rechecks the original guard. Neither initialization,
listTools nor state queries start Chrome. No snapshot/action is silently retried.

Native epoch checking is not an atomic navigation lock. Independent source review
found that upstream lazy aria-ref locators can reuse iframe reference IDs after a
new document obtains a new snapshot. The actual isolated SDK spike confirmed both
sides: with one in-flight request, snapshot mode none and no concurrent snapshot,
a disabled old iframe target followed by autonomous navigation timed out and the
new page received zero trap POSTs. Deliberately violating serialization with a
concurrent snapshot reused the old native ID and produced one trap POST. The oracle
therefore detects the danger; this is a necessary configuration invariant rather
than a global no-race claim. The scope must never allow another snapshot while a
prior native action is unresolved. Unknown poisons further actions until real Close.
No second SDK/debug client may refresh the context's snapshot cache. A future change
to these constraints requires a fresh native safety proof or a mature fixed-node
execution boundary; this checkpoint does not patch Playwright or invent CDP input.

Required actual Host journey: first direct Snapshot; cross-owner/raw/stale-ref
refusal with zero HTTP effects; newly observed input/click and independent nonce;
autonomous navigation and tab selection invalidation; same-owner/profile resource
reopen without old-token resurrection; Core/provider physical archival and actual
process/cgroup exit. A new user-requested snapshot after invalidation is a new
observation, never a replay of the failed input. Native and pure-Core results remain
separate. Whole Browser login continuity, full file transfers, headed/native platform
ownership, public paired routing, signed packaging and migration are still required.

The actual Host reference batch completed with two independent HTTP nonce effects,
zero internal reference retries, and stale attempts recorded NotDispatched. Both
resources retired with Core unreleased count zero. A separate read-only observer
retained original cgroup identities, saw both cgroups removed and all25 observed
PID/birth identities gone, with exact2GiB/swap0/tasks256 controls. Its20ms sampling
cannot enumerate every short-lived child. The first strict-lint failure was a
nonminimal boolean expression; its equivalent De Morgan simplification changes
no policy. External receipts retain each original failure and source hashes.
