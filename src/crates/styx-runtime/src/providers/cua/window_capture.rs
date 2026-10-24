//! Fixed window-capture request classification and ACK-result projection.
//! No permission, pixel correctness, owner, process or input authority is minted.
//! The caller must hold the original target/source pins and prove actual ACK.
use super::CuaError;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rmcp::model::{CallToolResult, ContentBlock};
use serde::Serialize;
use serde_json::{Map, Value, json};
use std::io::Write;

type Result<T> = std::result::Result<T, CuaError>;
const FRAME_BYTES: usize = 1024 * 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WindowCaptureRequest {
    pub(crate) pid: u32,
    pub(crate) window_id: u64,
    pub(crate) max_image_dimension: u32,
    pub(crate) timeout_ms: u64,
}
impl WindowCaptureRequest {
    pub(super) fn classify(name: &str, args: &Map<String, Value>) -> Result<Option<Self>> {
        if name != "get_window_state"
            || args.get("include_screenshot") != Some(&Value::Bool(true))
            || args.get("include_accessibility_tree") != Some(&Value::Bool(false))
        {
            return Ok(None);
        }
        const KEYS: &[&str] = &[
            "pid",
            "window_id",
            "include_screenshot",
            "include_accessibility_tree",
            "max_image_dimension",
            "timeout_ms",
        ];
        if args.keys().any(|key| !KEYS.contains(&key.as_str())) {
            return Err(CuaError::Unsupported);
        }
        let value = Self {
            pid: args
                .get("pid")
                .and_then(Value::as_u64)
                .and_then(|n| n.try_into().ok())
                .ok_or(CuaError::InvalidRequest)?,
            window_id: args
                .get("window_id")
                .and_then(Value::as_u64)
                .ok_or(CuaError::InvalidRequest)?,
            max_image_dimension: args
                .get("max_image_dimension")
                .and_then(Value::as_u64)
                .and_then(|n| n.try_into().ok())
                .ok_or(CuaError::InvalidRequest)?,
            timeout_ms: args
                .get("timeout_ms")
                .and_then(Value::as_u64)
                .ok_or(CuaError::InvalidRequest)?,
        };
        value.validate()?;
        Ok(Some(value))
    }
    fn validate(&self) -> Result<()> {
        if self.pid == 0
            || self.window_id == 0
            || !(1..=1024).contains(&self.max_image_dimension)
            || !(100..=2000).contains(&self.timeout_ms)
        {
            return Err(CuaError::InvalidRequest);
        }
        Ok(())
    }
}

/// Only an actual acknowledged response can be passed by the caller. An error
/// here means inadequate read evidence, never proof the native read was not sent.
pub(crate) fn project_acquired(
    result: &CallToolResult,
    request: &WindowCaptureRequest,
) -> Result<CallToolResult> {
    request.validate()?;
    bounded(result)?;
    if result.is_error == Some(true) {
        return Err(CuaError::Unsupported);
    }
    let object = result
        .structured_content
        .as_ref()
        .and_then(Value::as_object)
        .ok_or(CuaError::ProtocolMismatch)?;
    if object.get("pid").and_then(Value::as_u64) != Some(u64::from(request.pid))
        || object.get("window_id").and_then(Value::as_u64) != Some(request.window_id)
        || object.get("coordinate_frame").and_then(Value::as_str) != Some("window")
        || object
            .get("screenshot_frame_valid")
            .and_then(Value::as_bool)
            != Some(true)
        || object.get("screenshot_mime_type").and_then(Value::as_str) != Some("image/png")
    {
        return Err(CuaError::ProtocolMismatch);
    }
    for key in [
        "screenshot_error",
        "degraded_reason",
        "screenshot_file_path",
        "follow_up",
        "elements",
        "tree_markdown",
    ] {
        if object.contains_key(key) {
            return Err(CuaError::Unsupported);
        }
    }
    for key in ["degraded", "screenshot_composited", "popup", "display_only"] {
        if object.get(key).is_some_and(|v| v.as_bool() != Some(false)) {
            return Err(CuaError::Unsupported);
        }
    }
    for key in ["dialogs", "popups", "overlays"] {
        if object
            .get(key)
            .is_some_and(|v| !v.as_array().is_some_and(Vec::is_empty))
        {
            return Err(CuaError::Unsupported);
        }
    }
    let mut image = None;
    for part in &result.content {
        match part {
            ContentBlock::Text(_) => {} // Original native text/debug never survives.
            ContentBlock::Image(value) if image.is_none() => image = Some(value),
            _ => return Err(CuaError::Unsupported),
        }
    }
    let image = image.ok_or(CuaError::Unsupported)?;
    if image.mime_type != "image/png" {
        return Err(CuaError::ProtocolMismatch);
    }
    // The entire original response was bounded before this allocation. The
    // mature decoder rejects malformed alphabet/padding; no image is reencoded.
    let png = STANDARD
        .decode(&image.data)
        .map_err(|_| CuaError::ProtocolMismatch)?;
    let (width, height) = png_header_dimensions(&png)?;
    if width > request.max_image_dimension
        || height > request.max_image_dimension
        || object.get("screenshot_width").and_then(Value::as_u64) != Some(u64::from(width))
        || object.get("screenshot_height").and_then(Value::as_u64) != Some(u64::from(height))
    {
        return Err(CuaError::ProtocolMismatch);
    }
    // Whitelist instead of preserving native cache/capture IDs, metadata, old
    // text, annotations or arbitrary extension fields. This is not an input ref.
    let mut projected = CallToolResult::structured(json!({
        "pid": request.pid, "window_id": request.window_id,
        "coordinate_frame":"window", "screenshot_frame_valid":true,
        "screenshot_width":width, "screenshot_height":height,
        "screenshot_mime_type":"image/png", "input_authorized":false,
        "capture_observation_only":true
    }));
    projected
        .content
        .push(ContentBlock::image(image.data.clone(), "image/png"));
    bounded(&projected)?;
    Ok(projected)
}

/// Validate only the fixed PNG signature and first IHDR shape/dimensions.
/// No CRC/IDAT/pixel decoder is implemented here; native pixel acceptance and
/// image rendering remain separate from this bounded transport projection.
fn png_header_dimensions(bytes: &[u8]) -> Result<(u32, u32)> {
    if bytes.len() < 33
        || &bytes[..8] != b"\x89PNG\r\n\x1a\n"
        || bytes[8..12] != 13u32.to_be_bytes()
        || &bytes[12..16] != b"IHDR"
    {
        return Err(CuaError::ProtocolMismatch);
    }
    let width = u32::from_be_bytes(
        bytes[16..20]
            .try_into()
            .map_err(|_| CuaError::ProtocolMismatch)?,
    );
    let height = u32::from_be_bytes(
        bytes[20..24]
            .try_into()
            .map_err(|_| CuaError::ProtocolMismatch)?,
    );
    let depth = bytes[24];
    let color = bytes[25];
    let valid_depth = match color {
        0 => matches!(depth, 1 | 2 | 4 | 8 | 16),
        2 | 4 | 6 => matches!(depth, 8 | 16),
        3 => matches!(depth, 1 | 2 | 4 | 8),
        _ => false,
    };
    if width == 0
        || height == 0
        || !valid_depth
        || bytes[26] != 0
        || bytes[27] != 0
        || bytes[28] > 1
    {
        return Err(CuaError::ProtocolMismatch);
    }
    Ok((width, height))
}
fn bounded(value: &impl Serialize) -> Result<()> {
    struct Bound(usize);
    impl Write for Bound {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .filter(|v| *v <= FRAME_BYTES)
                .ok_or_else(|| std::io::Error::other("window capture response bound"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(Bound(0), value).map_err(|_| CuaError::Busy)
}
#[cfg(test)]
#[path = "window_capture_tests.rs"]
mod tests;
