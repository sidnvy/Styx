//! Gateway adapters. Session creation authenticates the opener; an eventual HTTP
//! listener must also authenticate every established-session request, apply
//! bounded-body/method admission, and coordinate owner shutdown. This module
//! alone does not claim a deployed Gateway, WSS relay or persistent enrollment.
pub mod auth;
pub mod http;
pub mod mcp;

use auth::{GatewayAuthError, GatewayBearerPolicy};
use mcp::{GatewayMcp, GatewayToolBackend};
use std::sync::{Arc, LazyLock};

static INSTRUCTIONS: LazyLock<String> = LazyLock::new(|| {
    #[derive(serde::Deserialize)]
    struct Instructions {
        instructions: String,
    }
    serde_json::from_str::<Instructions>(include_str!(
        "../../../../docs/rust-core-rewrite/PUBLIC-MCP-V1.json"
    ))
    .expect("source-controlled frozen public MCP contract")
    .instructions
});

/// Construct one server-side SDK session only after bearer/ingress checks.
/// Ordinary sessions get distinct Host-bound owners; tool metadata cannot mint
/// one. No socket, native executor or desktop operation starts here.
pub fn authenticated_mcp_session<B: GatewayToolBackend>(
    policy: &GatewayBearerPolicy,
    headers: &::http::HeaderMap,
    backend: Arc<B>,
) -> Result<GatewayMcp<B>, GatewayAuthError> {
    let principal = policy.authorize(headers)?;
    Ok(GatewayMcp::new(
        backend,
        principal.new_mcp_session_owner(),
        INSTRUCTIONS.clone(),
    ))
}
