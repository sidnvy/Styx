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
        json!({"pid":42,"window_id":1234,"coordinate_frame":"window","screenshot_frame_valid":true,"screenshot_width":1,"screenshot_height":1,"screenshot_mime_type":"image/png","window_bounds":{"x":-2,"y":0,"width":1,"height":1},"snapshot_id":"s000000a1","invalidated_snapshot_ids":["s00000099"],"capture_id":"native-private-correlation","screenshot_refreshed_snapshot":true}),
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
fn public_action_preserves_capture_only_and_default_accessibility_routes() {
    use super::super::{CuaAction, DesktopReadRequest};
    let capture = CuaAction::new("get_window_state".into(), arguments()).unwrap();
    assert!(matches!(
        capture.desktop_read_request().unwrap(),
        Some(DesktopReadRequest::WindowCapture(_))
    ));
    let tree = CuaAction::new(
        "get_window_state".into(),
        json!({"pid":42,"window_id":1234,"include_screenshot":false,
            "include_accessibility_tree":true,"max_elements":64,"max_depth":8,"timeout_ms":2000})
        .as_object()
        .unwrap()
        .clone(),
    )
    .unwrap();
    assert!(matches!(
        tree.desktop_read_request().unwrap(),
        Some(DesktopReadRequest::Accessibility(_))
    ));
    let mut extra = arguments();
    extra.insert("full_output".into(), json!(true));
    assert!(
        CuaAction::new("get_window_state".into(), extra)
            .unwrap()
            .desktop_read_request()
            .is_err()
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

#[test]
fn pinned_windows_capture_only_shape_is_observation_only_and_still_target_bound() {
    // Shape from the actual 2026-11-03 Windows worker response (pinned source
    // b88afe57... tools/impl_.rs); native PNG/readback acceptance is separate.
    let mut native = acquired();
    let object = native
        .structured_content
        .as_mut()
        .unwrap()
        .as_object_mut()
        .unwrap();
    object.remove("coordinate_frame");
    object.remove("screenshot_frame_valid");
    assert!(project_native_capture(&native, &request(), CaptureShape::Framed).is_err());
    let projected = project_native_capture(&native, &request(), CaptureShape::Windows).unwrap();
    let value = projected.structured_content.as_ref().unwrap();
    assert_eq!(value["input_authorized"], json!(false));
    assert_eq!(value["capture_observation_only"], json!(true));
    assert!(
        !serde_json::to_string(&projected)
            .unwrap()
            .contains("capture_id")
    );
    assert!(matches!(&projected.content[1],ContentBlock::Image(image) if image.data==PNG));
    for (key, value) in [
        ("coordinate_frame", json!("desktop")),
        ("screenshot_frame_valid", json!(false)),
        ("pid", json!(43)),
        ("window_id", json!(1235)),
        ("screenshot_width", json!(2)),
        ("window_bounds", json!({"x":0,"y":0,"width":0,"height":1})),
        ("window_bounds", json!({"x":0,"width":1,"height":1})),
        ("window_bounds", json!({"x":0,"y":0,"width":1.5,"height":1})),
        ("window_bounds", json!({"x":0,"y":0,"width":1,"height":0})),
        ("window_bounds", Value::Null),
        ("screenshot_error", json!("unavailable")),
        ("screenshot_composited", json!(true)),
        ("elements", json!([])),
    ] {
        let mut bad = native.clone();
        bad.structured_content.as_mut().unwrap()[key] = value;
        assert!(
            project_native_capture(&bad, &request(), CaptureShape::Windows).is_err(),
            "{key}"
        );
    }
}

#[test]
fn minimal_explicit_read_modalities_get_bounded_public_defaults() {
    use super::super::{CuaAction, DesktopReadRequest};
    let capture = CuaAction::new(
        "get_window_state".into(),
        json!({"pid":42,"window_id":1234,"include_accessibility_tree":false})
            .as_object()
            .unwrap()
            .clone(),
    )
    .unwrap();
    let Some(DesktopReadRequest::WindowCapture(request)) = capture.desktop_read_request().unwrap()
    else {
        panic!("capture default was not classified")
    };
    assert_eq!(request.max_image_dimension, 1024);
    assert_eq!(request.timeout_ms, 1000);
    let payload: Value = serde_json::from_slice(&capture.to_operation_payload().unwrap()).unwrap();
    assert!(payload["arguments"].get("tree_format").is_none());
    let tree = CuaAction::new(
        "get_window_state".into(),
        json!({"pid":42,"window_id":1234,"include_screenshot":false})
            .as_object()
            .unwrap()
            .clone(),
    )
    .unwrap();
    assert!(matches!(
        tree.desktop_read_request().unwrap(),
        Some(DesktopReadRequest::Accessibility(_))
    ));
    for (key, value) in [
        ("max_image_dimension", json!(0)),
        ("timeout_ms", json!(2001)),
    ] {
        let mut args = json!({"pid":42,"window_id":1234,"include_accessibility_tree":false})
            .as_object()
            .unwrap()
            .clone();
        args.insert(key.into(), value);
        let action = CuaAction::new("get_window_state".into(), args).unwrap();
        assert!(
            action.desktop_read_request().is_err(),
            "explicit invalid {key} must never become a default"
        );
    }
}

#[test]
fn pinned_macos_capture_only_shape_preserves_png_without_input_refs() {
    // Shape and field meanings from the original owned Mac response captured
    // 2026-11-05. Real PNG rendering and Gateway acceptance remain separate.
    let mut png_bytes = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut png_bytes, 40, 40);
        encoder.set_color(png::ColorType::Rgb);
        encoder.set_depth(png::BitDepth::Eight);
        encoder
            .write_header()
            .unwrap()
            .write_image_data(&[0; 40 * 40 * 3])
            .unwrap();
    }
    let mac_png = STANDARD.encode(&png_bytes);
    let mut native = acquired();
    native.content = vec![ContentBlock::image(mac_png.clone(), "image/png")];
    let object = native
        .structured_content
        .as_mut()
        .unwrap()
        .as_object_mut()
        .unwrap();
    object.remove("coordinate_frame");
    object.insert(
        "window_bounds".into(),
        json!({"x":-2.5,"y":0.0,"width":20.0,"height":20.0}),
    );
    object.insert("screenshot_width".into(), json!(40));
    object.insert("screenshot_height".into(), json!(40));
    object.insert("screenshot_scale".into(), json!(2.0));
    object.insert("tree_format".into(), json!("markdown"));
    object.insert("tree_markdown".into(), json!(""));
    object.insert("elements_complete".into(), json!(false));
    for key in [
        "element_count",
        "returned_element_count",
        "total_element_count",
    ] {
        object.insert(key.into(), json!(0));
    }
    assert!(project_native_capture(&native, &request(), CaptureShape::Framed).is_err());
    assert!(project_native_capture(&native, &request(), CaptureShape::Windows).is_err());
    let projected = project_native_capture(&native, &request(), CaptureShape::Macos).unwrap();
    assert!(matches!(&projected.content[1], ContentBlock::Image(value) if value.data == mac_png));
    let text = serde_json::to_string(&projected).unwrap();
    for field in [
        "tree_markdown",
        "snapshot_id",
        "capture_id",
        "element_token",
    ] {
        assert!(!text.contains(field));
    }
    assert_eq!(
        projected.structured_content.as_ref().unwrap()["input_authorized"],
        json!(false)
    );
    for (key, value) in [
        ("pid", json!(43)),
        ("window_id", json!(1235)),
        ("coordinate_frame", json!("desktop")),
        ("screenshot_frame_valid", json!(false)),
        ("tree_markdown", json!("unproven tree")),
        ("tree_format", json!("elements")),
        ("elements_complete", json!(true)),
        ("element_count", json!(1)),
        ("returned_element_count", json!(1)),
        ("total_element_count", json!(1)),
        ("elements", json!([])),
        ("screenshot_scale", json!(0)),
        ("screenshot_scale", json!(-1)),
        ("screenshot_scale", Value::Null),
        ("window_bounds", json!({"x":0,"y":0,"width":0,"height":1})),
        ("window_bounds", json!({"x":0,"y":0,"width":80,"height":40})),
        ("window_bounds", json!({"x":0,"y":0,"width":1,"height":1})),
        ("window_bounds", json!({"width":1,"height":1})),
    ] {
        let mut bad = native.clone();
        bad.structured_content.as_mut().unwrap()[key] = value;
        assert!(
            project_native_capture(&bad, &request(), CaptureShape::Macos).is_err(),
            "{key}"
        );
    }
    let mut bad = native;
    bad.structured_content
        .as_mut()
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove("screenshot_frame_valid");
    assert!(project_native_capture(&bad, &request(), CaptureShape::Macos).is_err());
}

#[test]
#[ignore = "requires original owned Mac native capture and Gateway request evidence file"]
fn original_owned_macos_capture_projection_reference() {
    let path = std::env::var_os("STYX_TEST_MAC_CAPTURE_REFERENCE")
        .expect("explicit original capture evidence");
    assert!(std::fs::metadata(&path).unwrap().len() <= FRAME_BYTES as u64);
    let evidence: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let request = WindowCaptureRequest::classify(
        "get_window_state",
        evidence["request"].as_object().unwrap(),
    )
    .unwrap()
    .unwrap();
    let native: CallToolResult =
        serde_json::from_value(evidence["native_response"]["result"].clone()).unwrap();
    let projected = project_native_capture(&native, &request, CaptureShape::Macos).unwrap();
    let image = projected
        .content
        .iter()
        .find_map(|part| match part {
            ContentBlock::Image(image) => Some(image),
            _ => None,
        })
        .unwrap();
    let png = STANDARD.decode(&image.data).unwrap();
    assert_eq!(
        styx_contracts::identity::Sha256Digest::of_bytes(&png).to_hex(),
        evidence["expected_png_sha256"].as_str().unwrap()
    );
    assert_eq!(
        projected.structured_content.as_ref().unwrap()["input_authorized"],
        json!(false)
    );
}
