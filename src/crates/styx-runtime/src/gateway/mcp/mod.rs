//! Official MCP SDK handler for an already-authenticated Gateway owner.
//!
//! Authentication/session binding belongs to the outer HTTP adapter; tool
//! membership, schema validation and execution belong to the backend. This
//! handler cannot construct authority from request arguments or metadata.
use crate::gateway::auth::VerifiedGatewayOwner;
use rmcp::{ErrorData, RoleServer, ServerHandler, model::*, service::RequestContext};
use std::{
    borrow::Cow,
    future::Future,
    sync::{Arc, LazyLock},
};

/// Backend operations retain their own authorization/operation lifecycle. A
/// dropped SDK request is not evidence that a side effect stopped or rolled back.
/// Returning CallToolResult rather than CallToolResponse prevents a backend from
/// adding SDK task/input-response extensions to the frozen public surface.
pub trait GatewayToolBackend: Send + Sync + 'static {
    fn list_tools(
        &self,
        owner: &VerifiedGatewayOwner,
        request: Option<PaginatedRequestParams>,
    ) -> impl Future<Output = Result<ListToolsResult, ErrorData>> + Send;
    fn call_tool(
        &self,
        owner: &VerifiedGatewayOwner,
        request: CallToolRequestParams,
    ) -> impl Future<Output = Result<CallToolResult, ErrorData>> + Send;
}

/// All five frozen legacy versions, including the oldest JS SDK version that
/// the Rust SDK can deserialize but does not name with a built-in constant.
static LEGACY_VERSIONS: LazyLock<Vec<ProtocolVersion>> = LazyLock::new(|| {
    vec![
        serde_json::from_str::<ProtocolVersion>("\"2024-10-07\"")
            .expect("fixed legacy MCP protocol-version literal"),
        ProtocolVersion::V_2024_11_05,
        ProtocolVersion::V_2025_03_26,
        ProtocolVersion::V_2025_06_18,
        ProtocolVersion::V_2025_11_25,
    ]
});

pub struct GatewayMcp<B: GatewayToolBackend> {
    backend: Arc<B>,
    owner: VerifiedGatewayOwner,
    instructions: String,
}
impl<B: GatewayToolBackend> GatewayMcp<B> {
    /// Called only by the authenticated outer adapter with frozen instructions.
    /// No public constructor or JSON-deserialization path accepts a claimed owner.
    pub(crate) fn new(backend: Arc<B>, owner: VerifiedGatewayOwner, instructions: String) -> Self {
        Self {
            backend,
            owner,
            instructions,
        }
    }
}

// The SDK retains deprecated methods for compatibility; explicitly refuse their
// non-product surfaces instead of inheriting successful empty default handlers.
#[allow(deprecated)]
impl<B: GatewayToolBackend> ServerHandler for GatewayMcp<B> {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(ProtocolVersion::V_2025_11_25)
            .with_server_info(Implementation::new("styx-vnext", "0.1.0"))
            .with_instructions(self.instructions.clone())
    }
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Borrowed(LEGACY_VERSIONS.as_slice())
    }
    // Use the SDK's default initialize + negotiate_initialize. In particular, a
    // future/unknown requested version negotiates the frozen ceiling, not SDK LATEST.
    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        self.backend.list_tools(&self.owner, request).await
    }
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        // No owner or capability is inferred from model-supplied arguments/_meta.
        self.backend
            .call_tool(&self.owner, request)
            .await
            .map(Into::into)
    }
    async fn discover(
        &self,
        _context: RequestContext<RoleServer>,
    ) -> Result<DiscoverResult, ErrorData> {
        Err(ErrorData::method_not_found::<DiscoverRequestMethod>())
    }
    async fn complete(
        &self,
        _request: CompleteRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CompleteResult, ErrorData> {
        Err(ErrorData::method_not_found::<CompleteRequestMethod>())
    }
    async fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, ErrorData> {
        Err(ErrorData::method_not_found::<ListPromptsRequestMethod>())
    }
    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        Err(ErrorData::method_not_found::<ListResourcesRequestMethod>())
    }
    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, ErrorData> {
        Err(ErrorData::method_not_found::<
            ListResourceTemplatesRequestMethod,
        >())
    }
    async fn on_custom_request(
        &self,
        _request: CustomRequest,
        _context: RequestContext<RoleServer>,
    ) -> Result<CustomResult, ErrorData> {
        Err(ErrorData::new(
            ErrorCode::METHOD_NOT_FOUND,
            "Unsupported MCP method",
            None,
        ))
    }
}

#[cfg(test)]
mod tests;
