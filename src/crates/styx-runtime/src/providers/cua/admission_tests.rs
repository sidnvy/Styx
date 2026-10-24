//! Payload classification contracts, not native permission or GUI acceptance.
use super::*;
use serde_json::json;
fn args(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}
fn check(name: &str, value: Value, expected: &[CapabilityId]) {
    let facts = classify(name, &args(value)).unwrap();
    assert_eq!(facts.capabilities.len(), expected.len());
    for capability in expected {
        assert!(facts.capabilities.contains(capability));
    }
}
#[test]
fn observation_flags_describe_actual_native_branches_not_capture_mode_alias() {
    use CapabilityId::*;
    check("list_apps", json!({}), &[DesktopWindowsRead]);
    check("list_windows", json!({"pid":42}), &[DesktopWindowsRead]);
    check(
        "get_window_state",
        json!({}),
        &[DesktopCapture, DesktopAccessibility],
    );
    check(
        "get_window_state",
        json!({"include_accessibility_tree":false}),
        &[DesktopCapture],
    );
    check(
        "get_window_state",
        json!({"include_screenshot":false}),
        &[DesktopAccessibility],
    );
    check(
        "get_window_state",
        json!({"capture_mode":"vision"}),
        &[DesktopCapture, DesktopAccessibility],
    );
    check("get_desktop_state", json!({}), &[DesktopCapture]);
    check("verify_state", json!({}), &[DesktopAccessibility]);
    check(
        "verify_state",
        json!({"include_screenshot":true}),
        &[DesktopAccessibility, DesktopCapture],
    );
    assert!(
        required(
            "get_window_state",
            &args(json!({"include_screenshot":false,"include_accessibility_tree":false}))
        )
        .is_err()
    );
    for name in ["get_window_state", "get_desktop_state"] {
        assert!(
            required(
                name,
                &args(json!({"screenshot_out_file":"/tmp/arbitrary.png"}))
            )
            .is_err()
        );
    }
}
#[test]
fn input_compound_routes_retain_primary_permission_and_target_requirement() {
    use CapabilityId::*;
    check(
        "set_value",
        json!({"element_token":"s00000001:1"}),
        &[DesktopAccessibility],
    );
    check("click", json!({"x":4,"y":8}), &[DesktopPointer]);
    check(
        "click",
        json!({"x":4,"y":8,"modifier":"ctrl","delivery_mode":"foreground"}),
        &[DesktopPointer, DesktopKeyboard, DesktopWindowsControl],
    );
    check(
        "click",
        json!({"element_token":"s00000001:1"}),
        &[DesktopPointer, DesktopAccessibility, DesktopWindowsControl],
    );
    check(
        "scroll",
        json!({"element_token":"s00000001:1","delivery_mode":"foreground"}),
        &[DesktopPointer, DesktopAccessibility, DesktopWindowsControl],
    );
    check(
        "type_text",
        json!({"x":4,"y":8,"delivery_mode":"foreground"}),
        &[DesktopKeyboard, DesktopPointer, DesktopWindowsControl],
    );
    check(
        "type_text",
        json!({"pid":42}),
        &[DesktopKeyboard, DesktopAccessibility],
    );
    check("type_text", json!({"scope":"desktop"}), &[DesktopKeyboard]);
    check(
        "press_key",
        json!({"element_token":"s00000001:1"}),
        &[DesktopKeyboard, DesktopAccessibility],
    );
    check(
        "press_key",
        json!({"x":4,"y":8}),
        &[DesktopKeyboard, DesktopPointer],
    );
    for name in ["click", "scroll", "set_value", "type_text", "press_key"] {
        let payload = if name == "set_value" {
            json!({"element_token":"s00000001:1"})
        } else {
            json!({})
        };
        let facts = classify(name, &args(payload)).unwrap();
        assert!(facts.side_effecting && facts.requires_observed_target);
    }
    for name in [
        "list_apps",
        "list_windows",
        "get_window_state",
        "get_desktop_state",
        "verify_state",
    ] {
        let facts = classify(name, &args(json!({}))).unwrap();
        assert!(!facts.side_effecting && !facts.requires_observed_target);
    }
}
#[test]
fn unsupported_route_shapes_do_not_silently_drop_arguments_or_expand_surface() {
    for payload in [
        json!({"x":1}),
        json!({"x":1,"y":2,"element_token":"s00000001:1"}),
        json!({"delivery_mode":"auto"}),
        json!({"target":{"kind":"desktop"},"pid":42}),
        json!({"target":{"kind":"window","pid":42,"window_id":7},"pid":43}),
        json!({"target":{"kind":"window","pid":42,"window_id":7},"scope":"desktop"}),
    ] {
        let original = args(payload);
        let copy = original.clone();
        assert!(required("click", &original).is_err());
        assert_eq!(original, copy);
    }
    assert!(required("run_steps", &args(json!({}))).is_err());
    assert!(required("browser_navigate", &args(json!({}))).is_err());
}
