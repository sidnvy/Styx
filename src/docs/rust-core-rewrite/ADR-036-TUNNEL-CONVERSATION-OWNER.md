# ADR-036 — Authenticated Tunnel conversation ownership

Status: implementation decision for native GUI convergence; not acceptance.

C11's corrected full-request diagnostic proves that consecutive Work calls in
one chat use different MCP transport sessions while the organization, subject
and conversation correlations remain identical. Binding resources only to an
HTTP transport prevents valid continuation. Treating all Tunnel calls as one
owner would instead break the frozen isolation contract.

The Gateway creates a fresh 256-bit forwarding bearer for its verified,
configured Tunnel worker. It is distinct from the ordinary model/admin/device
credentials, supplied only through the existing private header file, and
accepted only by the existing MCP ingress. The ordinary model bearer cannot
select this domain. `X-Styx-Tunnel-Context` remains refused. Diagnostic markers
remain observations, not authorization. No OpenAI runtime key is forwarded to
MCP or exposed in arguments, environment, tool output or logs.

Only after this service principal is authenticated may the outer HTTP adapter
use the canonical SDK envelope's organization/subject/conversation fields as
bounded correlation keys within that ingress domain. All three are required;
missing, empty, oversized or control-bearing values refuse before backend
dispatch. The adapter mints an opaque random Gateway owner; the correlation is
not an OwnerId, grant or independent ChatGPT-account authentication claim.
Ordinary HTTP metadata continues to have no owner-selection authority. This
trusts OpenAI's authenticated Tunnel delivery to supply its own correlations;
it does not accept such identity claims from an arbitrary bearer holder or tool
arguments. This implements the dedicated authenticated adapter foreseen by
C01 and the existing ingress refusal, rather than weakening ordinary sessions.

The outer adapter puts an unforgeable Rust-only call binding in HTTP request
extensions. The pinned official SDK forwards HTTP Parts into RequestContext.
The MCP handler passes those extensions to the HTTP backend adapter; neither
the public backend nor the handler constructs authority from JSON metadata.
Each request retains both its original transport admission and the selected
logical owner. Different chats, subjects, organizations, forwarding principals
or Gateway executions cannot share an owner.

Logical owners and MCP transports have distinct lifetimes. Transport DELETE or
EOF closes only that transport. Logical owners use the existing fence/cleanup
supervisor and actual Host receipts; no transport close is invented for an
authority that owns no SDK transport. Both consume the existing bounded HTTP
reservation pool. No active or liveness-unknown owner is evicted. Idle collection
requires no in-flight calls, no live work and the existing ten-minute idle
interval. Gateway stop fences both registries, retains unknown cleanup and
reports unresolved reservations. No business request, consumed output or native
input is replayed. Restart creates a new domain; old handles do not resurrect.

Compatibility: the frozen public tool names, schemas and numeric presentation
handles remain unchanged. Ordinary HTTP ownership and its negative controls
remain unchanged. Local private runtime header bytes change per Gateway run;
no durable profile, device identity, grant, publisher key or paired Host wire
schema changes. Callers are the Gateway bootstrap, private Tunnel supervisor,
HTTP/MCP adapters and existing lifecycle ports. No JS authority or new remote
management endpoint is introduced.

Required evidence before packaging: actual official-SDK separate connections
continue one logical resource; different correlation/principal and ordinary
forgery fail; missing/malformed context never dispatches; transport deletion
does not revoke another connection's logical work; idle/capacity, shutdown and
dropped waiters preserve ownership. The existing real paired TLS/Codex scenario
must repeat continuation and independent effects, followed by the installed
ChatGPT Exec/Browser/Computer journey on both platforms. Fixtures alone do not
close native or account acceptance.

Primary references: the pinned rmcp 3.7.0 source (`model/meta.rs`,
`streamable_http_server/tower.rs`) and the official
[tool-call metadata reference](https://developers.openai.com/plugins/reference),
[Secure MCP Tunnel guide](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels).
