//! Official MCP client for the one fixed maintenance validation journey.
//! SDK-local join is not remote owner cleanup: rmcp deliberately logs and
//! swallows DELETE failures. Only the outer owned server/Host can prove that.
use super::TransitionError;
use rmcp::{
    ClientServiceExt, RoleClient,
    model::{
        CallToolRequestParams, CallToolResult, ClientCapabilities, ClientConfig, Implementation,
    },
    service::{ClientLifecycleMode, RunningService},
    transport::{
        StreamableHttpClientTransport, streamable_http_client::StreamableHttpClientTransportConfig,
    },
};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    path::{Component, Path},
    time::Duration,
};
use styx_contracts::identity::DeviceId;
use zeroize::Zeroizing;

const RPC_BUDGET: Duration = Duration::from_secs(15);
const JOURNEY_BUDGET: Duration = Duration::from_secs(40);
const CLOSE_BUDGET: Duration = Duration::from_secs(10);

#[derive(Serialize)]
pub(super) struct ClientObservation {
    pub stdout_bytes: usize,
    pub exit_code: i32,
    /// Public Exec contract: exit0 and no live session_id, not an independent
    /// native process observer or proof of the entire Host shutdown.
    pub drained: bool,
    /// Always false here: official SDK cancellation exposes no remote physical
    /// cleanup receipt, including when its own local service joined normally.
    pub owner_close_confirmed: bool,
    pub sdk_service_joined: bool,
    pub tools_contract_matched: bool,
}
fn atom(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}
fn call(name: &str, arguments: Value) -> Result<CallToolRequestParams, TransitionError> {
    serde_json::from_value(json!({"name":name,"arguments":arguments}))
        .map_err(|_| TransitionError::Conflict)
}
fn data(result: CallToolResult) -> Result<Value, TransitionError> {
    if result.is_error == Some(true) {
        return Err(TransitionError::Unknown);
    }
    result.structured_content.ok_or(TransitionError::Unknown)
}
/// Caller supplies the original-CA-only reqwest client. This helper never
/// constructs a dangerous TLS verifier, credential, alternative endpoint or tool.
pub(super) async fn exercise(
    client: reqwest::Client,
    origin: &str,
    model_token: &str,
    device: &DeviceId,
    cwd: &str,
    nonce_name: &str,
    nonce: &str,
) -> Result<ClientObservation, TransitionError> {
    if !atom(nonce_name)
        || !atom(nonce)
        || !(32..=4096).contains(&model_token.len())
        || !model_token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        || cwd.len() > 4096
        || !Path::new(cwd).is_absolute()
        || cwd.bytes().any(|b| b == 0)
        || Path::new(cwd)
            .components()
            .any(|p| matches!(p, Component::ParentDir | Component::CurDir))
    {
        return Err(TransitionError::Conflict);
    }
    let url = url::Url::parse(origin).map_err(|_| TransitionError::Conflict)?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
        || !url
            .host_str()
            .and_then(|s| s.parse::<std::net::IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback())
    {
        return Err(TransitionError::Conflict);
    }
    let uri = url
        .join("mcp")
        .map_err(|_| TransitionError::Conflict)?
        .to_string();
    let token = Zeroizing::new(model_token.to_owned());
    let device = device.clone();
    let cwd = cwd.to_owned();
    let nonce_name = nonce_name.to_owned();
    let nonce = nonce.to_owned();
    // Caller cancellation detaches this ONE owned journey instead of dropping
    // its session mid-dispatch. There is no start/action retry in this worker.
    let job = tokio::spawn(async move {
        exercise_owned(client, uri, token, device, cwd, nonce_name, nonce).await
    });
    job.await.map_err(|_| TransitionError::Unknown)?
}
async fn exercise_owned(
    client: reqwest::Client,
    uri: String,
    token: Zeroizing<String>,
    device: DeviceId,
    cwd: String,
    nonce_name: String,
    nonce: String,
) -> Result<ClientObservation, TransitionError> {
    let config = StreamableHttpClientTransportConfig::with_uri(uri)
        .auth_header(token.to_string())
        .reinit_on_expired_session(false)
        .max_sse_event_size(1024 * 1024)
        .max_concurrent_requests(1);
    let transport = StreamableHttpClientTransport::with_client(client, config);
    let protocol =
        serde_json::from_value(json!("2025-11-25")).map_err(|_| TransitionError::Conflict)?;
    let connect = ClientConfig::new(
        ClientCapabilities::default(),
        Implementation::new("styx-owned-migration-validation", "1"),
    )
    .with_protocol_version(protocol)
    .serve_with_lifecycle(transport, ClientLifecycleMode::Initialize);
    // Before initialize yields a RunningService there is no owner.cancel API.
    // An initialize error/timeout is Unknown, never a known clean session.
    let owner = tokio::time::timeout(RPC_BUDGET, connect)
        .await
        .map_err(|_| TransitionError::Unknown)?
        .map_err(|_| TransitionError::Unknown)?;
    let result = tokio::time::timeout(
        JOURNEY_BUDGET,
        calls(&owner, &device, &cwd, &nonce_name, &nonce),
    )
    .await
    .unwrap_or(Err(TransitionError::Unknown));
    // Always attempt explicit SDK cancellation after any initialized-session
    // outcome, including schema, readiness, dispatch or read failure. Timeout
    // never aborts the cleanup future: its owned task keeps the local service.
    let mut close = tokio::spawn(async move { owner.cancel().await });
    let joined = matches!(
        tokio::time::timeout(CLOSE_BUDGET, &mut close).await,
        Ok(Ok(Ok(_)))
    );
    if !joined {
        return Err(TransitionError::Unknown);
    }
    let stdout_bytes = result?;
    Ok(ClientObservation {
        stdout_bytes,
        exit_code: 0,
        drained: true,
        owner_close_confirmed: false,
        sdk_service_joined: true,
        tools_contract_matched: true,
    })
}
async fn calls(
    owner: &RunningService<RoleClient, ClientConfig>,
    device: &DeviceId,
    cwd: &str,
    nonce_name: &str,
    nonce: &str,
) -> Result<usize, TransitionError> {
    let listed = tokio::time::timeout(RPC_BUDGET, owner.list_tools(None))
        .await
        .map_err(|_| TransitionError::Unknown)?
        .map_err(|_| TransitionError::Unknown)?;
    let frozen: Value = serde_json::from_str(include_str!(
        "../../../../docs/rust-core-rewrite/PUBLIC-MCP-V1.json"
    ))
    .map_err(|_| TransitionError::Conflict)?;
    if listed.next_cursor.is_some()
        || serde_json::to_value(listed.tools).map_err(|_| TransitionError::Unknown)?
            != frozen["tools"]
    {
        return Err(TransitionError::Conflict);
    }
    let until = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let status = tokio::time::timeout_at(
            until,
            owner.call_tool(call(
                "get_execution_environment_status",
                json!({"environment_id":device.as_str()}),
            )?),
        )
        .await
        .map_err(|_| TransitionError::Unknown)?
        .map_err(|_| TransitionError::Unknown)?;
        let status = data(status)?;
        if status["environment_id"].as_str() != Some(device.as_str())
            || status["kind"].as_str() != Some("paired")
            || status["access"].as_str() != Some("allowed")
        {
            return Err(TransitionError::Unknown);
        }
        // Current public contract reports readiness=unknown. Do not invent an
        // OS permission/desktop readiness claim from an Exec transport fact.
        if status["exec"]["connection"].as_str() == Some("connected") {
            break;
        }
        if tokio::time::Instant::now() >= until {
            return Err(TransitionError::Unknown);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Both substitutions have the strict ASCII atom grammar checked before IO;
    // cwd is a separate official workdir argument, never shell interpolation.
    let command = format!(
        "set -e; umask 077; set -C; printf '%s' '{nonce}' > './{nonce_name}'; printf '%s' '{nonce}'"
    );
    let started = tokio::time::timeout(
        RPC_BUDGET,
        owner.call_tool(call(
            "exec_command",
            json!({
                "cmd":command,"environment_id":device.as_str(),"workdir":cwd,"login":false,
                "tty":false,"yield_time_ms":100,"max_output_tokens":128
            }),
        )?),
    )
    .await
    .map_err(|_| TransitionError::Unknown)?
    .map_err(|_| TransitionError::Unknown)?;
    let mut page = data(started)?;
    let mut stdout = String::new();
    let mut original_session = None;
    loop {
        let output = page
            .get("output")
            .and_then(Value::as_str)
            .ok_or(TransitionError::Unknown)?;
        if stdout.len().saturating_add(output.len()) > 256 {
            return Err(TransitionError::Unknown);
        }
        stdout.push_str(output);
        if let Some(code) = page.get("exit_code") {
            if code.as_i64() != Some(0) || page.get("session_id").is_some() || stdout != nonce {
                return Err(TransitionError::Unknown);
            }
            return Ok(stdout.len());
        }
        let session = page
            .get("session_id")
            .and_then(Value::as_u64)
            .filter(|id| (1..(1_u64 << 48)).contains(id))
            .ok_or(TransitionError::Unknown)?;
        if original_session.is_some_and(|id| id != session) {
            return Err(TransitionError::Unknown);
        }
        original_session = Some(session);
        // Empty stdin is strictly a read. A lost reply is Unknown, never a new
        // start, repeated input, cursor restart, or automatic session reinit.
        page = data(
            tokio::time::timeout(
                RPC_BUDGET,
                owner.call_tool(call(
                    "write_stdin",
                    json!({
                        "session_id":session,"chars":"","yield_time_ms":100,"max_output_tokens":128
                    }),
                )?),
            )
            .await
            .map_err(|_| TransitionError::Unknown)?
            .map_err(|_| TransitionError::Unknown)?,
        )?;
    }
}
