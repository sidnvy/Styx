//! Projection of official Tunnel JSON logs. Never retain messages or payloads.
use serde_json::{Map, Value};

pub(super) fn project_diagnostic_line(bytes: &[u8]) -> Option<Value> {
    let input: Value = serde_json::from_slice(bytes).ok()?;
    let input = input.as_object()?;
    let level = input.get("level")?.as_str()?;
    if !matches!(level, "WARN" | "ERROR" | "INFO") {
        return None;
    }
    let mut out = Map::new();
    out.insert("level".into(), level.into());
    if let Some(component) = input.get("component").and_then(Value::as_str)
        && matches!(
            component,
            "health"
                | "dispatcher"
                | "controlplane"
                | "mcpclient"
                | "process"
                | "cloudflared"
                | "harpoon"
        )
    {
        out.insert("component".into(), component.into());
    }
    for key in [
        "request_id",
        "cmd_request_id",
        "tunnel_request_id",
        "rpc_request_id",
    ] {
        if let Some(value) = input.get(key) {
            let valid = value.as_str().is_some_and(valid_id)
                || (key == "rpc_request_id" && (value.is_i64() || value.is_u64()));
            if valid {
                out.insert(key.into(), value.clone());
            }
        }
    }
    let event = match input.get("msg").and_then(Value::as_str) {
        Some("dispatcher forwarded command to MCP server") => "command_forwarded",
        Some("dispatcher acknowledged notification with control plane") => {
            "notification_acknowledged"
        }
        Some("dispatcher terminated MCP session and posted response to control plane") => {
            "session_terminated"
        }
        Some("dispatcher delivered OAuth discovery response to control plane") => {
            "discovery_response_delivered"
        }
        Some("dispatcher received MCP upstream error; posted error response to control plane") => {
            "upstream_error"
        }
        Some("dispatcher posted terminal downstream error response to control plane") => {
            "downstream_error"
        }
        Some("failed to connect to MCP transport") => "transport_connect_failed",
        Some(
            "dispatcher failed to connect to MCP transport; posted error response to control plane",
        ) => "transport_connect_failed",
        _ if level != "INFO" => "unclassified_warning",
        _ => return None,
    };
    if level == "INFO"
        && ![
            "request_id",
            "cmd_request_id",
            "tunnel_request_id",
            "rpc_request_id",
        ]
        .iter()
        .any(|k| out.contains_key(*k))
    {
        return None;
    }
    out.insert("event".into(), event.into());
    for key in ["status_code", "upstream_status"] {
        if let Some(status) = input.get(key).and_then(Value::as_u64)
            && (100..=599).contains(&status)
        {
            out.insert(key.into(), status.into());
        }
    }
    if let Some(source) = input.get("failure_source").and_then(Value::as_str)
        && matches!(
            source,
            "target_http"
                | "dns"
                | "tls"
                | "connect"
                | "transport_closed"
                | "timeout"
                | "protocol"
                | "client_internal"
        )
    {
        out.insert("failure_source".into(), source.into());
    }
    if let Some(kind) = input.get("transport_error_kind").and_then(Value::as_str)
        && matches!(
            kind,
            "closed_pipe"
                | "connection_aborted"
                | "connection_closed"
                | "connection_refused"
                | "connection_reset"
                | "dial"
                | "dns"
                | "eof"
                | "host_unreachable"
                | "http_status"
                | "invalid_mcp_error"
                | "invalid_protocol_response"
                | "malformed_json"
                | "network_unreachable"
                | "non_protocol_response"
                | "response_body_missing"
                | "response_body_too_large"
                | "response_body_unreadable"
                | "timeout"
                | "tls"
                | "unexpected_eof"
                | "unknown"
                | "canceled"
        )
    {
        out.insert("transport_error_kind".into(), kind.into());
    }
    Some(Value::Object(out))
}

fn valid_id(value: &str) -> bool {
    if let Some(id) = value.strip_prefix("req_") {
        return (16..=64).contains(&id.len()) && id.bytes().all(|c| c.is_ascii_alphanumeric());
    }
    value.len() == 36
        && value.bytes().enumerate().all(|(i, c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn projects_official_failure_fields_without_payload_or_secret() {
        let raw = json!({"level":"WARN","component":"dispatcher","msg":"dispatcher posted terminal downstream error response to control plane","status_code":502,"failure_source":"transport_closed","transport_error_kind":"eof","request_id":"84fc8c1d-9f88-4aba-a768-5ce01658ce1b","cmd_request_id":"req_0123456789abcdef","rpc_request_id":12,"error":"SECRET","body":"SECRET","session_id":"SECRET","tunnel_request_id":"sk-SECRET"});
        let result = project_diagnostic_line(&serde_json::to_vec(&raw).unwrap()).unwrap();
        assert_eq!(result["event"], "downstream_error");
        assert_eq!(result["status_code"], 502);
        assert_eq!(result["cmd_request_id"], "req_0123456789abcdef");
        assert_eq!(result["rpc_request_id"], 12);
        assert_eq!(result["request_id"], "84fc8c1d-9f88-4aba-a768-5ce01658ce1b");
        assert!(!result.to_string().contains("SECRET"));
    }

    #[test]
    fn ignores_invalid_json_and_unrelated_info() {
        for raw in [
            b"not json".as_slice(),
            b"[]",
            br#"{"level":"DEBUG"}"#,
            br#"{"level":"INFO","msg":"secret payload"}"#,
        ] {
            assert!(project_diagnostic_line(raw).is_none());
        }
        let raw = br#"{"level":"INFO","msg":"dispatcher forwarded command to MCP server","cmd_request_id":"84fc8c1d-9f88-4aba-a768-5ce01658ce1b"}"#;
        assert_eq!(
            project_diagnostic_line(raw).unwrap()["event"],
            "command_forwarded"
        );
    }

    #[test]
    fn unknown_fields_cannot_smuggle_text_into_projection() {
        let raw = br#"{"level":"ERROR","component":"SECRET","msg":"SECRET","failure_source":"SECRET","transport_error_kind":"SECRET","status_code":600,"rpc_request_id":"SECRET","cmd_request_id":{"value":"SECRET"}}"#;
        assert_eq!(
            project_diagnostic_line(raw).unwrap(),
            json!({"level":"ERROR","event":"unclassified_warning"})
        );
    }
}
