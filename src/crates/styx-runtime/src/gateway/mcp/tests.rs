//! Development-slice official SDK tests. Backend is a recording fake; no tools,
//! network listeners, executors, operating-system grants or native apps are run.
use super::*;
use crate::gateway::auth::GatewayBearerPolicy;
use http::{
    HeaderMap, HeaderValue,
    header::{AUTHORIZATION, HOST},
};
use rmcp::{
    ServiceExt,
    model::ContentBlock,
    service::{ClientLifecycleMode, ClientServiceExt, ServiceError},
};
use serde_json::{Value, json};
use std::sync::Mutex;
use std::time::Duration;

fn public_surface() -> Value {
    serde_json::from_str(include_str!(
        "../../../../../docs/rust-core-rewrite/PUBLIC-MCP-V1.json"
    ))
    .unwrap()
}
fn verified_owner() -> VerifiedGatewayOwner {
    let policy = GatewayBearerPolicy::new(
        b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        vec!["owned-fixture.invalid".to_owned()],
        vec![],
    )
    .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(HOST, HeaderValue::from_static("owned-fixture.invalid"));
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_static("Bearer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    );
    policy.authorize(&headers).unwrap().new_mcp_session_owner()
}
struct RecordingBackend {
    calls: Mutex<Vec<(String, String)>>,
    tools: Vec<Tool>,
}
impl RecordingBackend {
    fn new() -> Self {
        Self {
            calls: Mutex::new(vec![]),
            tools: serde_json::from_value(public_surface()["tools"].clone()).unwrap(),
        }
    }
}
impl GatewayToolBackend for RecordingBackend {
    async fn list_tools(
        &self,
        owner: &VerifiedGatewayOwner,
        _request: Option<PaginatedRequestParams>,
    ) -> Result<ListToolsResult, ErrorData> {
        self.calls.lock().unwrap().push((
            owner.owner_id().as_str().to_owned(),
            "tools/list".to_owned(),
        ));
        Ok(ListToolsResult {
            tools: self.tools.clone(),
            ..Default::default()
        })
    }
    async fn call_tool(
        &self,
        owner: &VerifiedGatewayOwner,
        request: CallToolRequestParams,
    ) -> Result<CallToolResult, ErrorData> {
        if !self.tools.iter().any(|t| t.name == request.name) {
            return Err(ErrorData::method_not_found::<CallToolRequestMethod>());
        }
        self.calls.lock().unwrap().push((
            owner.owner_id().as_str().to_owned(),
            request.name.into_owned(),
        ));
        Ok(CallToolResult::success(vec![ContentBlock::text(
            "recording-backend-only; no native execution",
        )]))
    }
}
fn assert_method_not_found(error: ServiceError) {
    assert!(
        matches!(error, ServiceError::McpError(ref e) if e.code == ErrorCode::METHOD_NOT_FOUND),
        "{error:?}"
    );
}

#[tokio::test]
async fn official_sdk_negotiates_all_five_versions_and_preserves_public_tools() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let surface = public_surface();
        for version in LEGACY_VERSIONS.iter().cloned().chain([ProtocolVersion::V_2026_07_28]) {
            let expected = if version == ProtocolVersion::V_2026_07_28 { ProtocolVersion::V_2025_11_25 } else { version.clone() };
            let backend = Arc::new(RecordingBackend::new());
            let owner = verified_owner();
            let expected_owner = owner.owner_id().as_str().to_owned();
            let handler = GatewayMcp::new(backend.clone(), owner, surface["instructions"].as_str().unwrap().to_owned());
            let (server_io, client_io) = tokio::io::duplex(256 * 1024);
            let server_task = tokio::spawn(async move { handler.serve(server_io).await.unwrap() });
            let config = ClientConfig::new(ClientCapabilities::default(), Implementation::new("owned-sdk-fixture", "1"))
                .with_protocol_version(version);
            let client = config.serve_with_lifecycle(client_io, ClientLifecycleMode::Initialize).await.unwrap();
            let info = client.peer_info().unwrap();
            assert_eq!(info.protocol_version, expected);
            assert_eq!(info.server_info.as_ref().unwrap().name, "styx-vnext");
            assert_eq!(info.server_info.as_ref().unwrap().version, "0.1.0");
            assert_eq!(info.instructions.as_deref(), surface["instructions"].as_str());
            assert_eq!(serde_json::to_value(&info.capabilities).unwrap(), json!({"tools": {}}));
            let actual = client.list_tools(None).await.unwrap();
            assert_eq!(serde_json::to_value(&actual.tools).unwrap(), surface["tools"]);
            let request: CallToolRequestParams = serde_json::from_value(json!({"name":"exec_command", "arguments":{"cmd":"never-executed"}, "_meta":{"owner":"forged"}})).unwrap();
            let result = client.call_tool(request).await.unwrap();
            assert_eq!(result.is_error, Some(false));
            let observed = backend.calls.lock().unwrap().clone();
            assert_eq!(observed, vec![(expected_owner.clone(), "tools/list".to_owned()), (expected_owner, "exec_command".to_owned())]);
            client.cancel().await.unwrap();
            server_task.await.unwrap().cancel().await.unwrap();
        }
    }).await.expect("official SDK matrix must settle without leftover service waits");
}

#[tokio::test]
async fn official_sdk_rejects_unknown_tools_and_nonproduct_methods_without_delegation() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let backend = Arc::new(RecordingBackend::new());
        let owner = verified_owner();
        let handler = GatewayMcp::new(backend.clone(), owner, public_surface()["instructions"].as_str().unwrap().to_owned());
        let (server_io, client_io) = tokio::io::duplex(256 * 1024);
        let server_task = tokio::spawn(async move { handler.serve(server_io).await.unwrap() });
        let client = ClientConfig::new(ClientCapabilities::default(), Implementation::new("owned-sdk-fixture", "1"))
            .with_protocol_version(ProtocolVersion::V_2025_11_25).serve(client_io).await.unwrap();
        assert_method_not_found(client.call_tool(CallToolRequestParams::new("unadvertised_tool")).await.unwrap_err());
        assert_method_not_found(client.list_resources(None).await.unwrap_err());
        assert_method_not_found(client.list_resource_templates(None).await.unwrap_err());
        assert_method_not_found(client.list_prompts(None).await.unwrap_err());
        for value in [
            json!({"method":"not/a/product/method"}),
            json!({"method":"tasks/get","params":{"taskId":"not-a-task"}}),
            json!({"method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"not-a-prompt"},"argument":{"name":"x","value":"x"}}}),
        ] {
            let request: ClientRequest = serde_json::from_value(value).unwrap();
            assert_method_not_found(client.send_request(request).await.unwrap_err());
        }
        // A fully formed official discovery request must also be refused. New
        // SDK discovery metadata cannot implicitly enable a product surface.
        let mut meta = RequestMetaObject::default();
        meta.set_protocol_version(ProtocolVersion::V_2025_11_25);
        meta.set_client_info(Implementation::new("owned-sdk-fixture", "1"));
        meta.set_client_capabilities(ClientCapabilities::default());
        assert_method_not_found(client.discover(meta).await.unwrap_err());
        assert!(backend.calls.lock().unwrap().is_empty());
        client.cancel().await.unwrap();
        server_task.await.unwrap().cancel().await.unwrap();
    }).await.expect("unsupported SDK methods must reject promptly");
}
