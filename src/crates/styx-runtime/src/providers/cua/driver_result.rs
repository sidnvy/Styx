//! Preserve correlated native CUA MCP responses verbatim; only transport or
//! framing loss after dispatch produces Unknown.
use super::*;
use rmcp::{
    ServiceError,
    model::{ContentBlock, ListToolsResult},
};

pub(super) fn outcome(
    value: CallToolResult,
) -> (CuaEvidence, Option<CallToolResult>, Option<CuaError>) {
    if bounded_bytes(&value, FRAME_BYTES).is_err() {
        return (CuaEvidence::Unknown, None, Some(CuaError::Unknown));
    }
    if std::env::var_os("STYX_CUA_DIAGNOSTICS").as_deref() == Some(std::ffi::OsStr::new("1")) {
        use std::io::Write as _;
        let _ = writeln!(
            std::io::stderr().lock(),
            "{}",
            serde_json::json!({
                "event": "styx_cua_native_action_reply",
                "is_error": value.is_error,
                "structured": value.structured_content.is_some(),
            })
        );
    }
    (CuaEvidence::Acknowledged, Some(value), None)
}

pub(super) async fn invoke(
    peer: &rmcp::Peer<RoleClient>,
    params: CallToolRequestParams,
    stop: &CancellationToken,
    until: Option<Instant>,
) -> (CuaEvidence, Option<CallToolResult>, Option<CuaError>) {
    // One poll of one driver call. Transport loss is Unknown; never replay.
    let response = tokio::select! {
        _ = stop.cancelled() => None,
        result = within(until, peer.call_tool_once(params)) => Some(result),
    };
    match response {
        Some(Ok(Ok(CallToolResponse::Complete(value)))) => outcome(value),
        Some(Ok(Err(ServiceError::McpError(err)))) => {
            let structured = serde_json::json!({
                "native_mcp_error": {
                    "code": err.code.0,
                    "message": err.message,
                    "data": err.data,
                }
            });
            let mut result =
                CallToolResult::error(vec![ContentBlock::text(err.message.to_string())]);
            result.structured_content = Some(structured);
            outcome(result)
        }
        _ => (CuaEvidence::Unknown, None, Some(CuaError::Unknown)),
    }
}

fn first_line(text: Option<&str>) -> String {
    text.and_then(|s| s.lines().find(|l| !l.trim().is_empty()))
        .map(|s| s.trim().chars().take(180).collect())
        .unwrap_or_default()
}

pub(super) async fn invoke_list_tools(
    peer: &rmcp::Peer<RoleClient>,
    names: Option<&[String]>,
    stop: &CancellationToken,
    until: Option<Instant>,
) -> (CuaEvidence, Option<CallToolResult>, Option<CuaError>) {
    let response = tokio::select! {
        _ = stop.cancelled() => None,
        result = within(until, peer.list_tools(None)) => Some(result),
    };
    let ListToolsResult { tools, .. } = match response {
        Some(Ok(Ok(value))) => value,
        _ => return (CuaEvidence::Unknown, None, Some(CuaError::Unknown)),
    };
    let info = peer.peer_info();
    let server_info = info.as_ref().and_then(|i| i.server_info.as_ref()).map(|s| {
        serde_json::json!({
            "name": s.name,
            "version": s.version,
        })
    });
    let instructions = info.as_ref().and_then(|i| i.instructions.as_deref());

    let structured = match names {
        Some(requested) if !requested.is_empty() => {
            let mut matched = Vec::new();
            let mut missing = Vec::new();
            for req in requested {
                if let Some(tool) = tools.iter().find(|t| t.name.as_ref() == req.as_str()) {
                    if let Ok(val) = serde_json::to_value(tool) {
                        matched.push(val);
                    }
                } else {
                    missing.push(req.clone());
                }
            }
            let mut obj = serde_json::json!({
                "server_info": server_info,
                "instructions": instructions,
                "tools": matched,
            });
            if !missing.is_empty() {
                obj["unavailable_tools"] = serde_json::json!(missing);
            }
            obj
        }
        _ => {
            let summaries: Vec<Value> = tools
                .iter()
                .map(|t| {
                    let schema = serde_json::to_value(&t.input_schema).unwrap_or(Value::Null);
                    let required = schema
                        .get("required")
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default();
                    let parameters: Vec<String> = schema
                        .get("properties")
                        .and_then(Value::as_object)
                        .map(|m| m.keys().cloned().collect())
                        .unwrap_or_default();
                    serde_json::json!({
                        "name": t.name,
                        "summary": first_line(t.description.as_deref()),
                        "required": required,
                        "parameters": parameters,
                    })
                })
                .collect();
            serde_json::json!({
                "server_info": server_info,
                "instructions": instructions,
                "tool_count": summaries.len(),
                "tools": summaries,
            })
        }
    };
    let text = serde_json::to_string(&structured).unwrap_or_else(|_| "{}".into());
    let mut result = CallToolResult::success(vec![ContentBlock::text(text)]);
    result.structured_content = Some(structured);
    outcome(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_refusal_and_unknown_effect_are_preserved_verbatim() {
        let mut reply = CallToolResult::structured(
            serde_json::json!({"code": "element_not_visible", "effect": "refused"}),
        );
        reply.is_error = Some(true);
        let (evidence, returned, cause) = outcome(reply.clone());
        assert_eq!(evidence, CuaEvidence::Acknowledged);
        assert_eq!(returned, Some(reply));
        assert_eq!(cause, None);

        let unknown_effect =
            CallToolResult::structured(serde_json::json!({"effect": "unknown", "detail": "focus"}));
        let (evidence, returned, cause) = outcome(unknown_effect.clone());
        assert_eq!(evidence, CuaEvidence::Acknowledged);
        assert_eq!(returned, Some(unknown_effect));
        assert_eq!(cause, None);
    }
}
