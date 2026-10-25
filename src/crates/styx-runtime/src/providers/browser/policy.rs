//! Host-only file confinement and reference lifecycle around shared validation.
use super::*;
pub(super) use crate::providers::browser_contract::tool;
use serde_json::{Map, Value};

/// Run again under the resource mutex immediately before native I/O. This is
/// controlled-root validation, not a sandbox against malicious same-UID swaps.
pub(super) fn check_files(
    args: &mut Map<String, Value>,
    workspace: &Path,
    output: &Path,
) -> Result<()> {
    if super::canonical_path(workspace)? != workspace || super::canonical_path(output)? != output {
        return Err(BrowserError::PermissionDenied);
    }
    if let Some(paths) = args.get("paths").and_then(Value::as_array) {
        if paths.len() > 64 {
            return Err(BrowserError::Busy);
        }
        for path in paths {
            let path = Path::new(path.as_str().ok_or(BrowserError::InvalidRequest)?);
            if !path.is_absolute() || path.as_os_str().len() > 4096 {
                return Err(BrowserError::InvalidRequest);
            }
            let canonical = super::canonical_path(path)?;
            if canonical != path
                || !(path.starts_with(workspace) || path.starts_with(output))
                || !std::fs::symlink_metadata(path)
                    .map_err(|_| BrowserError::InvalidRequest)?
                    .is_file()
            {
                return Err(BrowserError::PermissionDenied);
            }
        }
    }
    if let Some(filename) = args.get("filename").and_then(Value::as_str) {
        let given = Path::new(filename);
        let destination = if given.is_absolute() {
            given.to_path_buf()
        } else {
            output.join(given)
        };
        let parent = destination.parent().ok_or(BrowserError::InvalidRequest)?;
        if filename.is_empty()
            || filename.len() > 4096
            || !destination.starts_with(output)
            || super::canonical_path(parent)? != parent
            || !parent.starts_with(output)
        {
            return Err(BrowserError::PermissionDenied);
        }
        // Existing symlinks, files and directories are refused: never overwrite
        // another action's artifact. Native SDK still opens the final filename.
        match std::fs::symlink_metadata(&destination) {
            Ok(_) => return Err(BrowserError::PermissionDenied),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(BrowserError::PermissionDenied),
        }
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
