//! Browser wire actions and pinned request validation shared by Gateway and Host.
//! No process, filesystem, desktop or provider availability is inferred here.
//! Actual file confinement and execution remain the selected Host worker's job.
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{collections::BTreeMap, sync::OnceLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum BrowserError {
    #[error("browser_busy")]
    Busy,
    #[error("browser_invalid_request")]
    InvalidRequest,
    #[error("browser_permission_denied")]
    PermissionDenied,
    #[error("browser_unsupported")]
    Unsupported,
    #[error("browser_spawn_failed")]
    SpawnFailed,
    #[error("browser_protocol_mismatch")]
    ProtocolMismatch,
    #[error("browser_outcome_unknown")]
    Unknown,
    #[error("browser_already_dispatched")]
    AlreadyDispatched,
    #[error("browser_cleanup_unconfirmed")]
    CleanupUnconfirmed,
    #[error("browser_stale_observation")]
    StaleObservation,
}
type Result<T> = std::result::Result<T, BrowserError>;
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BrowserAction {
    Navigate {
        url: String,
    },
    Evaluate {
        function: String,
    },
    Close,
    Tool {
        name: String,
        arguments: serde_json::Map<String, serde_json::Value>,
    },
}
impl BrowserAction {
    pub fn to_operation_payload(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| BrowserError::InvalidRequest)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        match self {
            Self::Tool { name, arguments } => validate(name, arguments),
            Self::Navigate { url } if url.len() > 8192 => Err(BrowserError::InvalidRequest),
            Self::Evaluate { function } if function.len() > 65536 => {
                Err(BrowserError::InvalidRequest)
            }
            _ => {
                let (name, args) = tool(self);
                validate(&name, &args)
            }
        }
    }
    pub fn is_close(&self) -> bool {
        matches!(self, Self::Close) || matches!(self,Self::Tool{name,..} if name=="browser_close")
    }
}
const CONTRACT: &str =
    include_str!("../../../../packages/styx-browser-provider/playwright-contract-0.0.83.json");
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
pub(crate) fn tool(action: &BrowserAction) -> (String, Map<String, Value>) {
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
fn validate(name: &str, args: &Map<String, Value>) -> Result<()> {
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
                    if native_ref(target) {
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
pub(crate) fn native_ref(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut at = 0;
    if bytes.first() == Some(&b'f') {
        at = 1;
        let start = at;
        while bytes.get(at).is_some_and(u8::is_ascii_digit) {
            at += 1;
        }
        if at == start {
            return false;
        }
    }
    if bytes.get(at) != Some(&b'e') {
        return false;
    }
    at += 1;
    at < bytes.len() && bytes[at..].iter().all(u8::is_ascii_digit)
}
