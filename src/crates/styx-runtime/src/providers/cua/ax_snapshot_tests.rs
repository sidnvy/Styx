//! Source-shaped protocol controls, not a native AT-SPI or input permission test.
use super::*;
use serde_json::json;
fn acquired() -> CallToolResult {
    let structured = json!({
        "pid":42,"window_id":1234,"tree_format":"elements",
        "snapshot_id":"s000000a1","element_count":2,
        "total_element_count":2,"returned_element_count":2,
        "elements_complete":true,"truncated":false,"bounds_complete":false,
        "invalidated_snapshot_ids":["s00000099"],
        "elements":[
            {"element_index":7,"element_token":"s000000a1:7","role":"push button","depth":2,"label":"Record fixture-nonce","enabled":true},
            {"element_index":2,"element_token":"s000000a1:2","role":"entry","depth":1,"label":"Fixture input","value":"fixture-nonce"}
        ]
    });
    let mut result = CallToolResult::structured(structured);
    // Upstream's original text includes native correlation even with elements.
    result.content = vec![rmcp::model::ContentBlock::text(
        "snapshot_id=s000000a1; element_token s000000a1:7",
    )];
    result
}
#[test]
fn owned_ax_projection_preserves_actual_indices_and_labels_without_native_tokens() {
    let original = acquired();
    let parsed = parse_acquired(&original, 42, 1234).unwrap();
    assert_eq!(parsed.native_snapshot_id(), "s000000a1");
    assert_eq!(parsed.tokens.len(), 2);
    assert_eq!(
        parsed.tokens.get(&7).map(String::as_str),
        Some("s000000a1:7")
    );
    assert_eq!(
        parsed.result.structured_content,
        original.structured_content
    );
    let rewritten = parsed.rewrite_result("s000000b2").unwrap();
    let raw = serde_json::to_string(&rewritten).unwrap();
    assert!(!raw.contains("s000000a1"));
    assert!(!raw.contains("s00000099"));
    let structured = rewritten.structured_content.as_ref().unwrap();
    assert_eq!(structured["snapshot_id"], "s000000b2");
    assert_eq!(structured["elements"][0]["element_index"], 7);
    assert_eq!(structured["elements"][0]["element_token"], "s000000b2:7");
    assert_eq!(structured["elements"][1]["element_token"], "s000000b2:2");
    assert_eq!(structured["elements"][1]["value"], "fixture-nonce");
    assert!(parsed.rewrite_result("s000000a1").is_err());
    assert!(parsed.rewrite_result("s00000000").is_err());
    let mut changed = original;
    changed.structured_content.as_mut().unwrap()["pid"] = json!(43);
    assert_ne!(parsed.result.structured_content, changed.structured_content);
    assert_eq!(
        parsed
            .rewrite_result("s000000b2")
            .unwrap()
            .structured_content
            .unwrap()["pid"],
        42
    );
}
#[test]
fn success_with_degradation_partial_or_conflicting_native_rows_never_installs() {
    for (key, value) in [
        ("degraded", json!(true)),
        ("truncated", json!(true)),
        ("display_only", json!(true)),
        ("returned_element_count", json!(1)),
        ("total_element_count", json!(3)),
        ("snapshot_id", json!("s00000000")),
        ("since_status", json!("no_change")),
        ("pid", json!(43)),
        ("window_id", json!(1235)),
    ] {
        let mut result = acquired();
        result.structured_content.as_mut().unwrap()[key] = value;
        assert!(parse_acquired(&result, 42, 1234).is_err());
    }
    // Windows UIA reports elements_complete:false with every element returned:
    // matching counts prove completeness, missing elements still never install.
    let mut counted = acquired();
    counted.structured_content.as_mut().unwrap()["elements_complete"] = json!(false);
    assert!(parse_acquired(&counted, 42, 1234).is_ok());
    for (key, value) in [
        ("total_element_count", json!(3)),
        ("element_count", json!(3)),
    ] {
        let mut partial = counted.clone();
        partial.structured_content.as_mut().unwrap()[key] = value;
        assert!(parse_acquired(&partial, 42, 1234).is_err());
    }
    // A filtered ordinary read on Windows: fewer rows than the window has, all of
    // them returned. Observed reads accept it; acquisition still requires the whole tree.
    let mut filtered = counted.clone();
    filtered.structured_content.as_mut().unwrap()["total_element_count"] = json!(6);
    filtered.structured_content.as_mut().unwrap()["element_count"] = json!(6);
    assert!(parse_observed(&filtered, 42, 1234).is_ok());
    assert!(parse_acquired(&filtered, 42, 1234).is_err());
    let mut short = filtered.clone();
    short.structured_content.as_mut().unwrap()["returned_element_count"] = json!(3);
    assert!(parse_observed(&short, 42, 1234).is_err());
    for token in ["7", "s00000099:7", "s000000a1:2", "s000000a1:07"] {
        let mut result = acquired();
        result.structured_content.as_mut().unwrap()["elements"][0]["element_token"] = json!(token);
        assert!(parse_acquired(&result, 42, 1234).is_err());
    }
    let mut duplicate = acquired();
    let repeated = duplicate.structured_content.as_ref().unwrap()["elements"][1].clone();
    duplicate.structured_content.as_mut().unwrap()["elements"][0] = repeated;
    assert!(parse_acquired(&duplicate, 42, 1234).is_err());
    let mut image = acquired();
    image.content =
        serde_json::from_value(json!([{"type":"image","mimeType":"image/png","data":"AA=="}]))
            .unwrap();
    assert!(matches!(
        parse_acquired(&image, 42, 1234),
        Err(CuaError::Unsupported)
    ));
    let mut prose = acquired();
    prose.structured_content.as_mut().unwrap()["elements"][1]["label"] =
        json!("literal s000000a1 in user label");
    let parsed = parse_acquired(&prose, 42, 1234).unwrap();
    // Only typed reference fields carry authority. Arbitrary page text must
    // remain readable even when it looks like a native snapshot identifier.
    let display = parsed.rewrite_result("s000000b2").unwrap();
    assert_eq!(
        display.structured_content.unwrap()["elements"][1]["label"],
        prose.structured_content.as_ref().unwrap()["elements"][1]["label"]
    );
}
#[test]
fn whole_response_and_reference_limits_fail_without_returning_partial_maps() {
    let mut huge = acquired();
    huge.structured_content.as_mut().unwrap()["unrelated"] = json!("x".repeat(RESPONSE_BYTES));
    assert!(matches!(
        parse_acquired(&huge, 42, 1234),
        Err(CuaError::Busy)
    ));
    let mut excessive = acquired();
    let elements:Vec<Value>=(0..=2048).map(|i|json!({"element_index":i,"element_token":format!("s000000a1:{i}"),"role":"entry","depth":1})).collect();
    let value = excessive.structured_content.as_mut().unwrap();
    for field in [
        "element_count",
        "total_element_count",
        "returned_element_count",
    ] {
        value[field] = json!(elements.len());
    }
    value["elements"] = json!(elements);
    assert!(parse_acquired(&excessive, 42, 1234).is_ok());
}

#[test]
fn read_only_rows_never_mint_native_or_host_input_refs() {
    let mut original = acquired();
    let row = &mut original.structured_content.as_mut().unwrap()["elements"][0];
    row["read_only"] = json!(true);
    row["role"] = json!("AXStaticText");
    row.as_object_mut().unwrap().remove("element_token");
    let parsed = parse_acquired(&original, 42, 1234).unwrap();
    assert!(!parsed.contains_native_token("s000000a1:7"));
    assert!(parsed.native_token_for("s000000b2", "s000000b2:7").is_err());
    assert_eq!(
        parsed.native_token_for("s000000b2", "s000000b2:2").unwrap(),
        "s000000a1:2"
    );
    let projected = parsed.rewrite_result("s000000b2").unwrap();
    let rows = &projected.structured_content.as_ref().unwrap()["elements"];
    assert_eq!(rows[0]["read_only"], json!(true));
    assert!(rows[0].get("element_token").is_none());
    assert_eq!(rows[1]["element_token"], json!("s000000b2:2"));
    // Neither contradictory tokens nor a type-confused/duplicated read-only
    // record may enter the retained map, even while another row is actionable.
    for flag in [json!(false), json!("true"), Value::Null] {
        let mut bad = original.clone();
        bad.structured_content.as_mut().unwrap()["elements"][0]["read_only"] = flag;
        assert!(parse_acquired(&bad, 42, 1234).is_err());
    }
    let mut bad = original.clone();
    bad.structured_content.as_mut().unwrap()["elements"][0]["element_token"] = json!("s000000a1:7");
    assert!(parse_acquired(&bad, 42, 1234).is_err());
    let mut bad = original;
    bad.structured_content.as_mut().unwrap()["elements"][0]["element_index"] = json!(2);
    assert!(parse_acquired(&bad, 42, 1234).is_err());
}

fn native_linux_chrome_metadata() -> CallToolResult {
    // Shape observed from installed Cua 0.47.24 on niuda, Chrome 157, Wayland.
    // PID/window are normalized; no profile, authentication or browser data.
    CallToolResult::structured(json!({
        "pid":42,"window_id":1234,"tree_format":"elements",
        "snapshot_id":"s00000001","element_count":1,
        "returned_element_count":1,"total_element_count":1,
        "elements_complete":false,"truncated":false,"degraded":true,
        "degraded_reason":"x11_property_fallback_partial: AT-SPI was unavailable and Cua Driver only recovered window metadata.",
        "elements":[{"element_index":0,"element_token":"s00000001:0", "role":"window","depth":0,"actions":["activate"]}]
    }))
}
#[test]
fn real_linux_metadata_fallback_remains_visible_but_cannot_authorize_input() {
    let native = native_linux_chrome_metadata();
    assert!(parse_acquired(&native, 42, 1234).is_err());
    let output = project_descriptive_read(&native, 42, 1234, false)
        .unwrap()
        .unwrap();
    assert_ne!(output.is_error, Some(true));
    let value = output.structured_content.unwrap();
    assert_eq!(value["read_status"], "window_metadata_only");
    assert_eq!(value["native_reason"], "x11_property_fallback_partial");
    assert_eq!(value["execution_certainty"], "acknowledged");
    assert_eq!(value["input_authorized"], false);
    assert_eq!(value["display_only"], true);
    assert!(value.get("snapshot_id").is_none());
    assert!(value["elements"][0].get("element_token").is_none());
    assert!(value["elements"][0].get("actions").is_none());
    assert_eq!(value["elements"][0]["read_only"], true);
    assert_eq!(value["elements"][0]["role"], "window");
}
#[test]
fn partial_tree_has_descriptions_and_never_native_or_host_action_references() {
    let mut native = acquired();
    let value = native.structured_content.as_mut().unwrap();
    value["element_count"] = json!(3);
    value["total_element_count"] = json!(3);
    value["truncated"] = json!(true);
    value["elements_complete"] = json!(false);
    let output = project_descriptive_read(&native, 42, 1234, false)
        .unwrap()
        .unwrap();
    let value = output.structured_content.unwrap();
    assert_eq!(value["elements"].as_array().unwrap().len(), 2);
    assert_eq!(value["elements"][0]["label"], "Record fixture-nonce");
    assert_eq!(value["native_reason"], "truncated_accessibility_tree");
    assert!(value.get("invalidated_snapshot_ids").is_none());
    for row in value["elements"].as_array().unwrap() {
        assert!(row.get("element_token").is_none());
        assert_eq!(row["read_only"], true);
    }
}
#[test]
fn descriptive_read_preserves_exact_window_and_protocol_boundaries() {
    let original = native_linux_chrome_metadata();
    for (pid, window) in [(41, 1234), (42, 1235), (0, 1234)] {
        assert!(project_descriptive_read(&original, pid, window, false).is_err());
    }
    for (key, value) in [
        ("returned_element_count", json!(2)),
        ("total_element_count", json!(0)),
        ("truncated", json!("false")),
        ("degraded", json!("yes")),
        ("tree_format", json!("markdown")),
    ] {
        let mut bad = original.clone();
        bad.structured_content.as_mut().unwrap()[key] = value;
        assert!(
            project_descriptive_read(&bad, 42, 1234, false).is_err(),
            "{key}"
        );
    }
    let mut bad = original.clone();
    bad.is_error = Some(true);
    assert!(project_descriptive_read(&bad, 42, 1234, false).is_err());
    let mut bad = original;
    bad.structured_content.as_mut().unwrap()["elements"][0]["role"] = json!(null);
    assert!(project_descriptive_read(&bad, 42, 1234, false).is_err());
}
#[test]
fn complete_tree_still_uses_original_actionable_parser() {
    assert!(
        project_descriptive_read(&acquired(), 42, 1234, false)
            .unwrap()
            .is_none()
    );
    let mut windows = acquired();
    windows.structured_content.as_mut().unwrap()["elements_complete"] = json!(false);
    assert!(
        project_descriptive_read(&windows, 42, 1234, false)
            .unwrap()
            .is_none()
    );
    assert!(parse_acquired(&windows, 42, 1234).is_ok());
}
