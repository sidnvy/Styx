//! Snapshot-local opaque references; native metadata is fact, not authorization.
use super::*;
use rmcp::model::ContentBlock;
use serde_json::Value;
pub(super) const META: &str = "app.styx/browser-native";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NativeFact {
    schema: u8,
    pub before: u64,
    pub after: u64,
    pub dispatched: bool,
    pub reason: Option<String>,
}
pub(super) fn fact(result: &CallToolResult) -> Result<NativeFact> {
    let value = result
        .meta
        .as_ref()
        .and_then(|v| v.0.get(META))
        .ok_or(BrowserError::ProtocolMismatch)?;
    let fact: NativeFact =
        serde_json::from_value(value.clone()).map_err(|_| BrowserError::ProtocolMismatch)?;
    if fact.schema != 1
        || fact.before == 0
        || fact.after < fact.before
        || fact.before > 9_007_199_254_740_991
        || fact.after > 9_007_199_254_740_991
        || fact
            .reason
            .as_deref()
            .is_some_and(|r| !matches!(r, "stale" | "invalid"))
    {
        return Err(BrowserError::ProtocolMismatch);
    }
    Ok(fact)
}
use crate::providers::browser_contract::native_ref;
/// Resolve only target fields, recursively including form fields. Arbitrary
/// page text, function bodies and typed input text are never target selectors.
pub(super) fn resolve_targets(
    value: &mut Value,
    scope: &styx_core::browser::BrowserReferenceScope,
    owner: &OwnerLease,
    target: &styx_contracts::operation::ResourceTarget,
    epoch: u64,
) -> Result<bool> {
    let mut has_reference = false;
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if matches!(key.as_str(), "target" | "startTarget" | "endTarget") {
                    let text = value.as_str().ok_or(BrowserError::InvalidRequest)?;
                    if native_ref(text) || text.to_ascii_lowercase().contains("aria-ref") {
                        return Err(BrowserError::StaleObservation);
                    }
                    if text.starts_with("styx-") {
                        let native = scope
                            .resolve(owner, target, text, epoch)
                            .map_err(|_| BrowserError::StaleObservation)?;
                        *value = Value::String(native);
                        has_reference = true;
                    }
                } else {
                    has_reference |= resolve_targets(value, scope, owner, target, epoch)?;
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                has_reference |= resolve_targets(value, scope, owner, target, epoch)?;
            }
        }
        _ => {}
    }
    Ok(has_reference)
}
fn markers(text: &str, out: &mut Vec<String>) -> Result<()> {
    let mut rest = text;
    while let Some(at) = rest.find("[ref=") {
        rest = &rest[at + 5..];
        let Some(end) = rest.find(']') else {
            break;
        };
        let native = &rest[..end];
        if native.len() <= 64 && native_ref(native) && !out.iter().any(|s| s == native) {
            if out.len() >= styx_core::browser::MAX_NATIVE_REFS {
                return Err(BrowserError::Busy);
            }
            out.push(native.to_owned());
        }
        rest = &rest[end + 1..];
    }
    Ok(())
}
fn strings(value: &Value, out: &mut Vec<String>) -> Result<()> {
    match value {
        Value::String(s) => markers(s, out)?,
        Value::Object(m) => {
            for v in m.values() {
                strings(v, out)?;
            }
        }
        Value::Array(a) => {
            for v in a {
                strings(v, out)?;
            }
        }
        _ => {}
    }
    Ok(())
}
fn rewrite(text: &str, map: &BTreeMap<String, String>) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("[ref=") {
        out.push_str(&rest[..at]);
        rest = &rest[at + 5..];
        let Some(end) = rest.find(']') else {
            out.push_str("[ref=");
            out.push_str(rest);
            return out;
        };
        let native = &rest[..end];
        if native_ref(native) {
            out.push_str("[ref=");
            out.push_str(map.get(native).map(String::as_str).unwrap_or("unavailable"));
            out.push(']');
        } else {
            out.push_str("[ref=");
            out.push_str(native);
            out.push(']');
        }
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    out
}
fn rewrite_value(value: &mut Value, map: &BTreeMap<String, String>) {
    match value {
        Value::String(s) => *s = rewrite(s, map),
        Value::Object(m) => {
            for v in m.values_mut() {
                rewrite_value(v, map);
            }
        }
        Value::Array(a) => {
            for v in a {
                rewrite_value(v, map);
            }
        }
        _ => {}
    }
}
pub(super) fn result_refs(
    result: &mut CallToolResult,
    scope: &mut styx_core::browser::BrowserReferenceScope,
    mint: bool,
    native: &NativeFact,
) -> Result<()> {
    let mut mapping = BTreeMap::new();
    if mint {
        scope.invalidate();
        if !native.dispatched || native.before != native.after {
            return Err(BrowserError::StaleObservation);
        }
        let mut refs = Vec::new();
        for content in &result.content {
            if let ContentBlock::Text(text) = content {
                markers(&text.text, &mut refs)?;
            }
        }
        if let Some(value) = &result.structured_content {
            strings(value, &mut refs)?;
        }
        mapping = scope
            .replace_snapshot(native.after, &refs)
            .map_err(|_| BrowserError::Busy)?;
    }
    for content in &mut result.content {
        if let ContentBlock::Text(text) = content {
            text.text = rewrite(&text.text, &mapping);
        }
    }
    if let Some(value) = &mut result.structured_content {
        rewrite_value(value, &mapping);
    }
    if let Some(meta) = &mut result.meta {
        meta.0.remove(META);
    }
    Ok(())
}
