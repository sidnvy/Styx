//! Presentation and schema controls; not a native Cua/permission attestation.
use super::*;

fn args(value: Value) -> Option<Map<String, Value>> {
    Some(value.as_object().unwrap().clone())
}

#[test]
fn computer_routes_validate_native_arguments_and_preserve_typed_results() {
    let request = ComputerRequest::parse(
        "desktop_call",
        args(json!({"environment_id":"owned-device","tool":"list_windows","arguments":{}})),
    )
    .unwrap();
    assert_eq!(request.environment_id.as_deref(), Some("owned-device"));
    let action: Value =
        serde_json::from_slice(&request.action.to_operation_payload().unwrap()).unwrap();
    assert_eq!(action["kind"], "call_tool");
    assert_eq!(action["name"], "list_windows");
    assert_eq!(action["arguments"], json!({}));
    assert!(action.get("environment_id").is_none());
    for invalid in [
        json!({"environment_id":null,"tool":"list_windows"}),
        json!({"environment_id":"","tool":"list_windows"}),
        json!({"environment_id":"x".repeat(129),"tool":"list_windows"}),
        json!({"tool":"list_windows","owner":"forged"}),
        json!({"tool":"list_windows","_meta":{"session":"forged"}}),
        json!({"tool":"list_windows","unknown_argument":true}),
        json!({"tool":""}),
        json!({}),
    ] {
        assert!(ComputerRequest::parse("desktop_call", args(invalid)).is_err());
    }
    assert!(ComputerRequest::parse("list_windows", None).is_err());
    assert!(ComputerRequest::parse("browser_snapshot", None).is_err());
    assert!(ComputerRequest::parse("future_computer_tool", None).is_err());
    // Cua result images retain the frozen MCP shape; the old Browser text-sized
    // 128KiB cap must not truncate/strip a valid within-frame Computer image.
    let data = "A".repeat(256 * 1024);
    let parsed: CallToolResult = serde_json::from_value(
        json!({"content":[{"type":"image","mimeType":"image/png","data":data}],"isError":false}),
    )
    .unwrap();
    let output = bounded_result(parsed).unwrap();
    let serialized = serde_json::to_value(output).unwrap();
    assert_eq!(serialized["content"][0]["type"], "image");
    assert_eq!(
        serialized["content"][0]["data"].as_str().unwrap().len(),
        256 * 1024
    );
    let denied = serde_json::to_value(computer_error(
        ErrorCategory::PermissionDenied,
        ExecutionCertainty::NotDispatched,
    ))
    .unwrap();
    let denied: Value =
        serde_json::from_str(denied["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(denied["category"], "PERMISSION_DENIED");
    assert_eq!(denied["execution_certainty"], "not_dispatched");
    assert_eq!(denied["uncertain"], false);
}

#[test]
fn pre_dispatch_capacity_is_known_and_retryable() {
    let result = computer_error(ErrorCategory::Busy, ExecutionCertainty::NotDispatched);
    let value: Value = serde_json::from_str(&result.content[0].as_text().unwrap().text).unwrap();
    assert_eq!(value["error"], "capacity_busy");
    assert_eq!(value["uncertain"], false);
    assert_eq!(value["retryable"], true);
}

#[test]
fn computer_wire_preserves_explicit_timeout_and_has_no_default_response_budget() {
    let raw = RawValue::from_string(
        serde_json::to_string(&CuaAction::list_tools(None).unwrap()).unwrap(),
    )
    .unwrap();
    let call = Call::DesktopSession {
        owner: crate::host::protocol::wire::OwnerRef {
            owner_id: "computer-owner".try_into().unwrap(),
            owner_epoch: "computer-epoch".try_into().unwrap(),
        },
        grant_revision: 1,
        timeout_ms: None,
        action: raw.clone(),
    };
    assert!(call.is_computer());
    assert!(call.response_budget().is_none());
    let wire = serde_json::to_value(&call).unwrap();
    assert_eq!(wire["timeout_ms"], Value::Null);
    let explicit: Call = serde_json::from_value(json!({
        "desktop_session": {
            "owner": {"owner_id": "computer-owner", "owner_epoch": "computer-epoch"},
            "grant_revision": 1,
            "timeout_ms": 12000,
            "action": serde_json::from_str::<Value>(raw.get()).unwrap(),
        }
    }))
    .unwrap();
    assert!(matches!(
        explicit,
        Call::DesktopSession {
            timeout_ms: Some(12000),
            ..
        }
    ));
    assert!(explicit.response_budget().is_none());
}
