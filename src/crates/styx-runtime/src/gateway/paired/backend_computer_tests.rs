//! Presentation and schema controls; not a native Cua/permission attestation.
use super::*;
fn args(value: Value) -> Option<Map<String, Value>> {
    Some(value.as_object().unwrap().clone())
}
#[test]
fn computer_routes_validate_native_arguments_and_preserve_typed_results() {
    let request = ComputerRequest::parse(
        "list_windows",
        args(json!({"environment_id":"owned-device"})),
    )
    .unwrap();
    assert_eq!(request.environment_id.as_deref(), Some("owned-device"));
    let action: Value =
        serde_json::from_slice(&request.action.to_operation_payload().unwrap()).unwrap();
    assert_eq!(action["name"], "list_windows");
    assert_eq!(action["arguments"], json!({}));
    assert!(action.get("environment_id").is_none());
    for invalid in [
        json!({"environment_id":null}),
        json!({"environment_id":""}),
        json!({"environment_id":"x".repeat(129)}),
        json!({"owner":"forged"}),
        json!({"_meta":{"session":"forged"}}),
        json!({"unknown_argument":true}),
    ] {
        assert!(ComputerRequest::parse("list_windows", args(invalid)).is_err());
    }
    assert!(
        ComputerRequest::parse(
            "get_desktop_state",
            args(json!({"screenshot_out_file":"/tmp/foreign.png"}))
        )
        .is_err()
    );
    assert!(ComputerRequest::parse("browser_snapshot", None).is_err());
    assert!(ComputerRequest::parse("future_computer_tool", None).is_err());
    // Cua result images retain the frozen MCP shape; the old Browser text-sized
    // 128KiB cap must not truncate/strip a valid within-frame Computer image.
    let data = "A".repeat(256 * 1024);
    let output = result(
        json!({"content":[{"type":"image","mimeType":"image/png","data":data}],"isError":false}),
    )
    .unwrap();
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
    assert!(Phase::Opening.blocks_dispatch());
    assert!(Phase::ActionUnknown.blocks_dispatch());
    assert!(Phase::Unknown.blocks_dispatch());
    assert!(!Phase::Ready.blocks_dispatch());
}
