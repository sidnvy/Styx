//! Cross-boundary public shape/native request regressions. These do not claim
//! OS permission, native dispatch, pixels, independent effects or device acceptance.
use super::*;
use crate::providers::cua::DesktopReadRequest;
use serde_json::json;

fn raw(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}
fn surface() -> Value {
    serde_json::from_str(include_str!(
        "../../../../../docs/rust-core-rewrite/PUBLIC-MCP-V1.json"
    ))
    .unwrap()
}
fn advertised_schema(name: &str) -> jsonschema::Validator {
    let public = surface();
    let schema = &public["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == name)
        .unwrap()["inputSchema"];
    jsonschema::validator_for(schema).unwrap()
}

#[test]
fn branch_only_tool_projection_preserves_bound_targets_and_environment() {
    let public = surface();
    for (name, branch, input) in [
        (
            "get_window_state",
            0,
            json!({"pid":42,"window_id":43,"environment_id":"test-host","include_screenshot":false}),
        ),
        (
            "get_window_state",
            1,
            json!({"pid":42,"window_id":43,"environment_id":"test-host","include_accessibility_tree":false}),
        ),
        (
            "click",
            0,
            json!({"element_token":"s00000001:0","environment_id":"test-host"}),
        ),
        (
            "click",
            1,
            json!({"element_token":"s00000001:0","environment_id":"test-host","button":"right","delivery_mode":"foreground"}),
        ),
    ] {
        let tool = public["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == name)
            .unwrap();
        let schema = &tool["inputSchema"];
        let variant = &schema["oneOf"][branch];
        let fields = variant["properties"].as_object().unwrap();
        for required in schema["required"].as_array().unwrap() {
            assert!(
                variant["required"].as_array().unwrap().contains(required),
                "{name} branch {branch} omitted required target {required}"
            );
        }
        // Model the observed branch-only declaration, not the unavailable
        // connector implementation. Discarded common fields must fail here
        // before they can become a misleading native/permission diagnosis.
        let projected: Map<String, Value> = input
            .as_object()
            .unwrap()
            .iter()
            .filter(|(key, _)| fields.contains_key(*key))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        assert_eq!(
            Value::Object(projected.clone()),
            input,
            "{name} branch {branch} lost caller fields"
        );
        let mut arguments = projected;
        assert_eq!(arguments.remove("environment_id"), Some(json!("test-host")));
        let action = decode(name, arguments).unwrap();
        action.to_operation_payload().unwrap();
    }
}

#[test]
fn complete_branch_declarations_keep_the_existing_schema_admission() {
    let public = surface();
    for (name, samples) in [
        (
            "get_window_state",
            vec![
                (
                    true,
                    json!({"pid":42,"window_id":43,"include_screenshot":false}),
                ),
                (
                    true,
                    json!({"pid":42,"window_id":43,"environment_id":"test-host","include_accessibility_tree":false,"max_image_dimension":1024}),
                ),
                (
                    true,
                    json!({"pid":42,"window_id":43,"include_screenshot":false,"include_accessibility_tree":true,"tree_format":"elements","max_elements":250,"max_depth":25,"timeout_ms":1000}),
                ),
                (false, json!({"window_id":43,"include_screenshot":false})),
                (false, json!({"pid":42,"include_screenshot":false})),
                (
                    false,
                    json!({"pid":"42","window_id":43,"include_screenshot":false}),
                ),
                (
                    false,
                    json!({"pid":0,"window_id":43,"include_screenshot":false}),
                ),
                (
                    false,
                    json!({"pid":42,"window_id":43,"include_screenshot":true,"include_accessibility_tree":true}),
                ),
                (
                    false,
                    json!({"pid":42,"window_id":43,"include_screenshot":false,"include_accessibility_tree":false}),
                ),
                (
                    false,
                    json!({"pid":42,"window_id":43,"include_screenshot":false,"max_image_dimension":100}),
                ),
                (
                    false,
                    json!({"pid":42,"window_id":43,"include_accessibility_tree":false,"max_depth":25}),
                ),
                (
                    false,
                    json!({"pid":42,"window_id":43,"include_screenshot":false,"unknown":true}),
                ),
            ],
        ),
        (
            "click",
            vec![
                (true, json!({"element_token":"s00000001:0"})),
                (
                    true,
                    json!({"pid":42,"window_id":43,"environment_id":"test-host","element_token":"s00000001:0","button":"left","delivery_mode":"background"}),
                ),
                (
                    true,
                    json!({"element_token":"s00000001:0","button":"right","delivery_mode":"foreground"}),
                ),
                (false, json!({"button":"left"})),
                (false, json!({"element_token":42})),
                (
                    false,
                    json!({"element_token":"s00000001:0","button":"right","delivery_mode":"background"}),
                ),
                (
                    false,
                    json!({"element_token":"s00000001:0","button":"left","delivery_mode":"foreground"}),
                ),
                (false, json!({"element_token":"s00000001:0","unknown":true})),
            ],
        ),
    ] {
        let mut previous = public["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == name)
            .unwrap()["inputSchema"]
            .clone();
        let current = jsonschema::validator_for(&previous).unwrap();
        let common = previous["properties"].as_object().unwrap().clone();
        let required = previous["required"].as_array().unwrap().clone();
        // Undo only the redundant common declarations. The previous oneOf
        // constants, exclusions and outer closed shape remain identical.
        for branch in previous["oneOf"].as_array_mut().unwrap() {
            branch["properties"]
                .as_object_mut()
                .unwrap()
                .retain(|key, value| common.get(key) != Some(value));
            branch["required"]
                .as_array_mut()
                .unwrap()
                .retain(|field| !required.contains(field));
        }
        let previous = jsonschema::validator_for(&previous).unwrap();
        for (accepted, input) in samples {
            assert_eq!(
                previous.is_valid(&input),
                accepted,
                "previous {name}: {input}"
            );
            assert_eq!(
                current.is_valid(&input),
                accepted,
                "current {name}: {input}"
            );
        }
    }
}

#[test]
fn styx_discovery_is_a_subset_of_the_unchanged_upstream_catalog() {
    let public = surface();
    let native: Value = serde_json::from_str(include_str!(
        "../../../../../gateway/cua-portable-0.36.0.json"
    ))
    .unwrap();
    let native_names: Vec<_> = native["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert_eq!(native_names.len(), 10);
    let public_names: Vec<_> = public["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    let supported: Vec<_> = native_names
        .iter()
        .copied()
        .filter(|name| public_names.contains(name))
        .collect();
    assert_eq!(supported.len(), 7);
    for name in supported {
        assert!(route(name).is_some(), "advertised Computer route {name}");
        assert!(schemas().unwrap().contains_key(name));
    }
    for name in ["type_text", "press_key", "scroll"] {
        assert!(
            native_names.contains(&name),
            "upstream catalog stays pinned"
        );
        assert!(!public_names.contains(&name));
        assert!(route(name).is_none());
        assert!(matches!(
            decode(name, Map::new()),
            Err(CuaError::Unsupported)
        ));
    }
}

#[test]
fn advertised_window_defaults_reach_the_exact_native_acquisition_branches() {
    let schema = advertised_schema("get_window_state");
    let tree = json!({"pid":42,"window_id":43,"include_screenshot":false});
    assert!(schema.is_valid(&tree));
    let tree = decode("get_window_state", raw(tree)).unwrap();
    assert!(matches!(
        tree.desktop_read_request().unwrap(),
        Some(DesktopReadRequest::Accessibility(_))
    ));
    let payload: Value = serde_json::from_slice(&tree.to_operation_payload().unwrap()).unwrap();
    assert_eq!(
        payload["arguments"],
        json!({"pid":42,"window_id":43,"include_screenshot":false,
            "include_accessibility_tree":true,"tree_format":"elements",
            "max_elements":250,"max_depth":25,"timeout_ms":1000})
    );

    let screenshot = json!({"pid":42,"window_id":43,"include_accessibility_tree":false});
    assert!(schema.is_valid(&screenshot));
    let screenshot = decode("get_window_state", raw(screenshot)).unwrap();
    assert!(matches!(
        screenshot.desktop_read_request().unwrap(),
        Some(DesktopReadRequest::WindowCapture(_))
    ));
    let payload: Value =
        serde_json::from_slice(&screenshot.to_operation_payload().unwrap()).unwrap();
    assert_eq!(
        payload["arguments"],
        json!({"pid":42,"window_id":43,"include_screenshot":true,
            "include_accessibility_tree":false,"max_image_dimension":1024,"timeout_ms":1000})
    );
    for value in [
        json!({"pid":1,"window_id":1,"include_screenshot":false,
            "max_elements":1,"max_depth":1,"timeout_ms":100}),
        json!({"pid":2147483647,"window_id":9007199254740991u64,
            "include_screenshot":false,"include_accessibility_tree":true,
            "tree_format":"elements","max_elements":2048,"max_depth":64,"timeout_ms":2000}),
        json!({"pid":1,"window_id":1,"include_accessibility_tree":false,
            "max_image_dimension":1,"timeout_ms":100}),
    ] {
        assert!(schema.is_valid(&value));
        assert!(decode("get_window_state", raw(value)).is_ok());
    }
}

#[test]
fn old_sdk_options_and_mixed_window_modalities_are_rejected_before_operation_creation() {
    let schema = advertised_schema("get_window_state");
    for (field, value) in [
        ("full_output", json!(true)),
        ("query", json!("Sheet")),
        ("since", json!("latest")),
        ("capture_mode", json!("ax")),
        ("verbose", json!(false)),
        ("screenshot_out_file", json!("/tmp/unowned.png")),
        ("max_image_dimension", json!(32)),
        ("max_elements", json!(2049)),
        ("max_depth", json!(65)),
        ("timeout_ms", json!(2001)),
        ("timeout_ms", json!(99)),
        ("pid", json!(0)),
        ("pid", json!(2147483648u64)),
        ("window_id", json!(9007199254740992u64)),
    ] {
        let mut value_tree = raw(json!({"pid":42,"window_id":43,"include_screenshot":false}));
        value_tree.insert(field.into(), value);
        assert!(
            !schema.is_valid(&Value::Object(value_tree.clone())),
            "{field}"
        );
        assert!(decode("get_window_state", value_tree).is_err());
    }
    for value in [
        json!({"pid":42,"window_id":43}),
        json!({"pid":42,"window_id":43,"include_screenshot":true,"include_accessibility_tree":true}),
        json!({"pid":42,"window_id":43,"include_screenshot":false,"include_accessibility_tree":false}),
        json!({"pid":42,"window_id":43,"include_accessibility_tree":false,"tree_format":"elements"}),
        json!({"pid":42,"window_id":43,"include_accessibility_tree":false,"max_depth":1}),
    ] {
        assert!(!schema.is_valid(&value));
        assert!(decode("get_window_state", raw(value)).is_err());
    }
    // The upstream complete schema still accepts full_output; Styx's new
    // schema must be a deliberate supported contract, not a modified catalog.
    let native: Value = serde_json::from_str(include_str!(
        "../../../../../gateway/cua-portable-0.36.0.json"
    ))
    .unwrap();
    let native = native["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "get_window_state")
        .unwrap();
    assert!(
        jsonschema::validator_for(&native["inputSchema"])
            .unwrap()
            .is_valid(
                &json!({"pid":42,"window_id":43,"include_screenshot":false,"full_output":true})
            )
    );
}

#[test]
fn exact_value_contract_checks_required_target_and_utf8_bytes() {
    let schema = advertised_schema("set_value");
    let value =
        json!({"pid":42,"window_id":43,"element_token":"s00000002:1","value":"值".repeat(5461)});
    assert!(schema.is_valid(&value));
    let action = decode("set_value", raw(value)).unwrap();
    assert_eq!(
        action
            .accessibility_write_request()
            .unwrap()
            .unwrap()
            .value
            .len(),
        16383
    );
    let value =
        json!({"pid":42,"window_id":43,"element_token":"s00000002:1","value":"值".repeat(5462)});
    // JSON Schema maxLength counts characters; this documented semantic byte
    // bound is enforced by the same request decoder used by Host preparation.
    assert!(schema.is_valid(&value));
    assert!(matches!(
        decode("set_value", raw(value)),
        Err(CuaError::InvalidRequest)
    ));
    assert!(
        schema.is_valid(&json!({"pid":42,"window_id":43,"element_token":"s00000002:1","value":""}))
    );
    assert!(!schema.is_valid(&json!({"value":"missing exact target"})));
    for token in ["s00000000:1", "s00000002:2048", "s00000002:01"] {
        assert!(
            decode(
                "set_value",
                raw(json!({"pid":42,"window_id":43,
            "element_token":token,"value":"x"}))
            )
            .is_err()
        );
    }
}

#[test]
fn element_click_contract_preserves_optional_observed_target_and_explicit_windows_posture() {
    let schema = advertised_schema("click");
    for value in [
        json!({"element_token":"s00000002:1"}),
        json!({"element_token":"s00000002:1","button":"left","delivery_mode":"background"}),
        json!({"pid":42,"window_id":43,"element_token":"s00000002:1"}),
    ] {
        assert!(schema.is_valid(&value));
        let action = decode("click", raw(value)).unwrap();
        let request = action.click_request().unwrap().unwrap();
        assert_eq!(request.element_token, "s00000002:1");
    }
    let right =
        json!({"element_token":"s00000002:1","button":"right","delivery_mode":"foreground"});
    assert!(schema.is_valid(&right));
    let action = decode("click", raw(right)).unwrap();
    if cfg!(target_os = "windows") {
        assert!(action.click_request().unwrap().is_some());
    } else {
        assert!(matches!(action.click_request(), Err(CuaError::Unsupported)));
    }
    for value in [
        json!({"x":1,"y":2}),
        json!({"element_token":"s00000002:1","button":"right"}),
        json!({"element_token":"s00000002:1","delivery_mode":"foreground"}),
        json!({"element_token":"s00000002:1","button":"middle"}),
        json!({"element_token":"s00000002:1","modifier":["shift"]}),
    ] {
        assert!(!schema.is_valid(&value));
        assert!(decode("click", raw(value)).is_err());
    }
}

#[test]
fn read_only_metadata_and_verification_routes_remain_available_without_file_output() {
    for (name, value) in [
        ("list_apps", json!({})),
        ("list_windows", json!({"pid":42,"on_screen_only":true})),
        ("get_desktop_state", json!({"max_image_dimension":512})),
        (
            "verify_state",
            json!({"pid":42,"window_id":43,"expect":[{"window":{"exists":true}}]}),
        ),
    ] {
        assert!(advertised_schema(name).is_valid(&value), "{name}");
        let action = decode(name, raw(value)).unwrap();
        assert!(!action.mutates(), "{name} must stay read-only");
        assert!(!action.requires_observed_target().unwrap());
    }
    for name in ["get_desktop_state", "verify_state"] {
        assert!(
            !advertised_schema(name).is_valid(&json!({"screenshot_out_file":"/tmp/unowned.png"}))
        );
    }
}
