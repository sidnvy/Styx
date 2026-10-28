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
    assert_eq!(parsed.response_sha256, bounded_digest(&original).unwrap());
    let rewritten = parsed.rewrite_result(&original, "s000000b2").unwrap();
    let raw = serde_json::to_string(&rewritten).unwrap();
    assert!(!raw.contains("s000000a1"));
    assert!(!raw.contains("s00000099"));
    let structured = rewritten.structured_content.as_ref().unwrap();
    assert_eq!(structured["snapshot_id"], "s000000b2");
    assert_eq!(structured["elements"][0]["element_index"], 7);
    assert_eq!(structured["elements"][0]["element_token"], "s000000b2:7");
    assert_eq!(structured["elements"][1]["element_token"], "s000000b2:2");
    assert_eq!(structured["elements"][1]["value"], "fixture-nonce");
    assert!(parsed.rewrite_result(&original, "s000000a1").is_err());
    assert!(parsed.rewrite_result(&original, "s00000000").is_err());
    let mut changed = original.clone();
    changed.structured_content.as_mut().unwrap()["pid"] = json!(43);
    assert!(parsed.rewrite_result(&changed, "s000000b2").is_err());
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
    // Deliberate fail-closed limitation for token-shaped user prose, not an
    // excuse to leak native cache correlation into a public alias response.
    assert!(matches!(
        parsed.rewrite_result(&prose, "s000000b2"),
        Err(CuaError::ProtocolMismatch)
    ));
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
    let elements:Vec<Value>=(0..=MAX_REFS).map(|i|json!({"element_index":i,"element_token":format!("s000000a1:{i}"),"role":"entry","depth":1})).collect();
    let value = excessive.structured_content.as_mut().unwrap();
    for field in [
        "element_count",
        "total_element_count",
        "returned_element_count",
    ] {
        value[field] = json!(elements.len());
    }
    value["elements"] = json!(elements);
    assert!(matches!(
        parse_acquired(&excessive, 42, 1234),
        Err(CuaError::Busy)
    ));
}
