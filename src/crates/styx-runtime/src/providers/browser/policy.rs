//! Frozen upstream schema plus local policy; no second catalog or schema dialect.
use super::*;
use serde_json::{Map, Value};
use std::sync::OnceLock;
const CONTRACT: &str =
    include_str!("../../../../../packages/styx-browser-provider/playwright-contract-0.0.83.json");
static SCHEMAS: OnceLock<Result<BTreeMap<String, jsonschema::Validator>>> = OnceLock::new();
fn schemas() -> Result<&'static BTreeMap<String, jsonschema::Validator>> {
    SCHEMAS
        .get_or_init(|| {
            let contract: Value =
                serde_json::from_str(CONTRACT).map_err(|_| BrowserError::ProtocolMismatch)?;
            let mut out = BTreeMap::new();
            for tool in contract["tools"]
                .as_array()
                .ok_or(BrowserError::ProtocolMismatch)?
            {
                let name = tool["name"]
                    .as_str()
                    .ok_or(BrowserError::ProtocolMismatch)?;
                let validator = jsonschema::validator_for(&tool["inputSchema"])
                    .map_err(|_| BrowserError::ProtocolMismatch)?;
                if out.insert(name.to_owned(), validator).is_some() {
                    return Err(BrowserError::ProtocolMismatch);
                }
            }
            if out.len() != 24 {
                return Err(BrowserError::ProtocolMismatch);
            }
            Ok(out)
        })
        .as_ref()
        .map_err(|e| *e)
}
pub(super) fn tool(action: &BrowserAction) -> (String, Map<String, Value>) {
    match action {
        BrowserAction::Tool { name, arguments } => (name.clone(), arguments.clone()),
        BrowserAction::Navigate { url } => (
            "browser_navigate".into(),
            Map::from_iter([("url".into(), Value::String(url.clone()))]),
        ),
        BrowserAction::Evaluate { function } => (
            "browser_evaluate".into(),
            Map::from_iter([("function".into(), Value::String(function.clone()))]),
        ),
        BrowserAction::Close => ("browser_close".into(), Map::new()),
    }
}
fn reserved(value: &Value) -> bool {
    match value {
        Value::Object(map) => map
            .iter()
            .any(|(k, v)| matches!(k.as_str(), "_meta" | "environment_id") || reserved(v)),
        Value::Array(values) => values.iter().any(reserved),
        _ => false,
    }
}
fn safe_url(value: &str) -> Result<()> {
    let url = url::Url::parse(value).map_err(|_| BrowserError::InvalidRequest)?;
    if value.len() > 8192
        || !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(BrowserError::Unsupported);
    }
    Ok(())
}
pub(super) fn validate(name: &str, args: &Map<String, Value>) -> Result<()> {
    struct Budget(usize);
    impl std::io::Write for Budget {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .filter(|n| *n <= 128 * 1024)
                .ok_or_else(|| std::io::Error::other("bounded browser arguments"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(&mut Budget(0), args).map_err(|_| BrowserError::InvalidRequest)?;
    let value = Value::Object(args.clone());
    if name.len() > 128 || reserved(&value) {
        return Err(BrowserError::InvalidRequest);
    }
    if !schemas()?
        .get(name)
        .ok_or(BrowserError::Unsupported)?
        .is_valid(&value)
    {
        return Err(BrowserError::InvalidRequest);
    }
    if let Some(url) = args.get("url").and_then(Value::as_str) {
        safe_url(url)?;
    }
    if let Some(function) = args.get("function").and_then(Value::as_str)
        && (function.is_empty() || function.len() > 65536)
    {
        return Err(BrowserError::InvalidRequest);
    }
    if name == "browser_wait_for"
        && args
            .get("time")
            .and_then(Value::as_f64)
            .is_some_and(|v| !(0.0..=30.0).contains(&v))
    {
        return Err(BrowserError::InvalidRequest);
    }
    if name == "browser_find" && args.contains_key("text") == args.contains_key("regex") {
        return Err(BrowserError::InvalidRequest);
    }
    validate_targets(&value)?;
    Ok(())
}
fn validate_targets(value: &Value) -> Result<()> {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if matches!(key.as_str(), "target" | "startTarget" | "endTarget") {
                    let target = value.as_str().ok_or(BrowserError::InvalidRequest)?;
                    if target.is_empty()
                        || target.len() > 8192
                        || target.to_ascii_lowercase().contains("aria-ref")
                    {
                        return Err(BrowserError::StaleObservation);
                    }
                    if super::references::native_ref(target) {
                        return Err(BrowserError::StaleObservation);
                    }
                }
                validate_targets(value)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                validate_targets(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}
/// Run again under the resource mutex immediately before native I/O. This is
/// controlled-root validation, not a sandbox against malicious same-UID swaps.
pub(super) fn check_files(
    args: &mut Map<String, Value>,
    workspace: &Path,
    output: &Path,
) -> Result<()> {
    if std::fs::canonicalize(workspace).map_err(|_| BrowserError::InvalidRequest)? != workspace
        || std::fs::canonicalize(output).map_err(|_| BrowserError::InvalidRequest)? != output
    {
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
            let canonical =
                std::fs::canonicalize(path).map_err(|_| BrowserError::InvalidRequest)?;
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
            || std::fs::canonicalize(parent).map_err(|_| BrowserError::PermissionDenied)? != parent
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
