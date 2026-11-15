//! File argument decoding and reference lifecycle around shared validation.
use super::*;
pub(super) use crate::providers::browser_contract::tool;
use serde_json::{Map, Value};

/// Decode file arguments; filesystem access and overwrite behavior belong to
/// the OS and Playwright. Relative output names retain the configured output base.
pub(super) fn check_files(
    args: &mut Map<String, Value>,
    _workspace: &Path,
    output: &Path,
) -> Result<()> {
    if let Some(paths) = args.get("paths") {
        let paths = paths.as_array().ok_or(BrowserError::InvalidRequest)?;
        if paths.iter().any(|path| !path.is_string()) {
            return Err(BrowserError::InvalidRequest);
        }
    }
    if let Some(filename) = args.get("filename") {
        let filename = filename.as_str().ok_or(BrowserError::InvalidRequest)?;
        let given = Path::new(filename);
        if !given.is_absolute() {
            let destination = output.join(given);
            args.insert(
                "filename".into(),
                Value::String(
                    destination
                        .to_str()
                        .ok_or(BrowserError::InvalidRequest)?
                        .to_owned(),
                ),
            );
        }
    }
    Ok(())
}
pub(super) fn snapshot(name: &str, args: &Map<String, Value>) -> bool {
    matches!(name, "browser_snapshot" | "browser_find") && !args.contains_key("filename")
}
pub(super) fn invalidates(name: &str, args: &Map<String, Value>) -> bool {
    !(matches!(
        name,
        "browser_console_messages"
            | "browser_network_requests"
            | "browser_network_request"
            | "browser_take_screenshot"
    ) || name == "browser_tabs" && args.get("action").and_then(Value::as_str) == Some("list"))
}
