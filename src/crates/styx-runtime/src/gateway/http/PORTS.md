# Shared ports integrated for this slice

The integrator owns shared manifest/auth registration. The following ports are present.

- Add Gateway auth `AuthenticatedGatewayPrincipal::matches_owner(&VerifiedGatewayOwner) -> bool`, comparing its private principal digest to the owner's private principal digest. This does not mint an owner or expose a digest.
- Add pinned hyper1.12.0 server/http1, hyper-util0.1.21 tokio/server/service/http1, tower0.5.3 util; existing bytes/http/http-body/http-body-util/futures-util remain mature adapters.
- Dev official rmcp Streamable HTTP client with reqwest0.13.5 (matching SDK3.7 client), default features false. Do not enable a new production JS core or custom MCP parser.
- Register gateway::http only when all files exist. GatewayMcp remains read-only and prebound constructor is sufficient.
- Separate required GatewayOwnerLifecycle is defined in this subtree. Real backend must implement synchronous Core fence plus cancellation-safe owned observed cleanup. There is no successful default.

Development slice only: 256KiB input/output message ceiling is narrower than future real Cua/Browser images. One session's HTTP owner is not ChatGPT account proof. Session-header compatibility shim is exact2024-10-07 only under authenticated body/actual negotiated-session binding.
