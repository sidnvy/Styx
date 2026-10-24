//! Source-shaped protocol controls only, not native capture/pixel acceptance.
use super::*;
const PNG: &str =
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jVZkAAAAASUVORK5CYII=";
fn arguments() -> Map<String, Value> {
    json!({"pid":42,"window_id":1234,"include_screenshot":true,"include_accessibility_tree":false,"max_image_dimension":1024,"timeout_ms":2000}).as_object().unwrap().clone()
}
fn request() -> WindowCaptureRequest {
    WindowCaptureRequest::classify("get_window_state", &arguments())
        .unwrap()
        .unwrap()
}
fn acquired() -> CallToolResult {
    let mut result = CallToolResult::structured(
        json!({"pid":42,"window_id":1234,"coordinate_frame":"window","screenshot_frame_valid":true,"screenshot_width":1,"screenshot_height":1,"screenshot_mime_type":"image/png","snapshot_id":"s000000a1","invalidated_snapshot_ids":["s00000099"],"capture_id":"native-private-correlation","screenshot_refreshed_snapshot":true}),
    );
    result.content = vec![
        ContentBlock::text("native token s000000a1:7 debug"),
        ContentBlock::image(PNG, "image/png"),
    ];
    result
}
#[test]
fn request_is_explicit_bounded_window_capture_with_no_other_branch() {
    let args = arguments();
    assert!(
        WindowCaptureRequest::classify("get_window_state", &args)
            .unwrap()
            .is_some()
    );
    for key in ["pid", "window_id", "max_image_dimension", "timeout_ms"] {
        let mut bad = args.clone();
        bad.remove(key);
        assert!(WindowCaptureRequest::classify("get_window_state", &bad).is_err());
    }
    for (key, value) in [
        ("session", json!("foreign")),
        ("query", json!("query")),
        ("since", json!("latest")),
        ("full_output", json!(true)),
        ("screenshot_out_file", json!("/tmp/no")),
        ("max_image_dimension", json!(1025)),
        ("max_image_dimension", json!(0)),
        ("timeout_ms", json!(2001)),
        ("timeout_ms", json!(99)),
        ("pid", json!(0)),
    ] {
        let mut bad = args.clone();
        bad.insert(key.into(), value);
        assert!(WindowCaptureRequest::classify("get_window_state", &bad).is_err());
    }
    let mut ax = args.clone();
    ax.insert("include_accessibility_tree".into(), json!(true));
    assert!(
        WindowCaptureRequest::classify("get_window_state", &ax)
            .unwrap()
            .is_none()
    );
    assert!(
        WindowCaptureRequest::classify("get_desktop_state", &args)
            .unwrap()
            .is_none()
    );
}
#[test]
fn projection_keeps_exact_image_bytes_and_discards_all_native_refs() {
    let result = project_acquired(&acquired(), &request()).unwrap();
    assert!(
        matches!(&result.content[1],ContentBlock::Image(image) if image.data==PNG && image.mime_type=="image/png")
    );
    let serialized = serde_json::to_string(&result).unwrap();
    for native in [
        "s000000a1",
        "s00000099",
        "native-private-correlation",
        "snapshot_id",
        "capture_id",
        "element_token",
    ] {
        assert!(!serialized.contains(native));
    }
    assert_eq!(
        result.structured_content.as_ref().unwrap()["input_authorized"],
        json!(false)
    );
    assert_eq!(
        STANDARD.decode(PNG).unwrap(),
        match &result.content[1] {
            ContentBlock::Image(image) => STANDARD.decode(&image.data).unwrap(),
            _ => panic!("single original image"),
        }
    );
}
#[test]
fn conflicting_target_ambiguous_content_and_malformed_or_oversized_images_refuse() {
    for (key, value) in [
        ("pid", json!(43)),
        ("window_id", json!(1235)),
        ("coordinate_frame", json!("desktop")),
        ("screenshot_frame_valid", json!(false)),
        ("screenshot_mime_type", json!("image/jpeg")),
        ("screenshot_width", json!(2)),
        ("screenshot_height", json!(2)),
        ("screenshot_error", json!({})),
        ("degraded", json!(true)),
        ("screenshot_composited", json!(true)),
        ("popup", json!(true)),
        ("dialogs", json!([{}])),
        ("popups", json!([{}])),
        ("overlays", json!([{}])),
        ("follow_up", json!("different target")),
    ] {
        let mut bad = acquired();
        bad.structured_content.as_mut().unwrap()[key] = value;
        assert!(project_acquired(&bad, &request()).is_err());
    }
    let mut bad = acquired();
    bad.is_error = Some(true);
    assert!(project_acquired(&bad, &request()).is_err());
    let mut bad = acquired();
    bad.content.push(ContentBlock::image(PNG, "image/png"));
    assert!(project_acquired(&bad, &request()).is_err());
    for (data, mime) in [
        ("not-base64", "image/png"),
        (PNG, "image/jpeg"),
        ("AA==", "image/png"),
    ] {
        let mut bad = acquired();
        bad.content = vec![ContentBlock::image(data, mime)];
        assert!(project_acquired(&bad, &request()).is_err());
    }
    let mut bytes = STANDARD.decode(PNG).unwrap();
    bytes[16..20].copy_from_slice(&1025u32.to_be_bytes());
    let mut bad = acquired();
    bad.content = vec![ContentBlock::image(STANDARD.encode(bytes), "image/png")];
    bad.structured_content.as_mut().unwrap()["screenshot_width"] = json!(1025);
    assert!(project_acquired(&bad, &request()).is_err());
    let mut bad = acquired();
    bad.content
        .push(ContentBlock::text("x".repeat(FRAME_BYTES)));
    assert!(matches!(
        project_acquired(&bad, &request()),
        Err(CuaError::Busy)
    ));
}
