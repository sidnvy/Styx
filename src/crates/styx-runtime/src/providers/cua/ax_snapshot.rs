//! Pure validation/projection of an already acquired fixed-Cua AX read.
//! No owner issuance, permission evidence, Core observation or token authority
//! is created here. Host must bind and install this only under its own gates.
use super::CuaError;
use rmcp::model::CallToolResult;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Write};
use styx_contracts::identity::Sha256Digest;

const RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_REFS: usize = 2048;
const RETAINED_BYTES: usize = 256 * 1024;
const ENTRY_OVERHEAD: usize = 96;
// These fixed upstream fields contain native cache/debug correlation, not
// caller-visible authority. Old invalidation IDs cannot be passed through.
const REMOVE_NATIVE_FIELDS: &[&str] = &[
    "invalidated_snapshot_ids",
    "screenshot_refreshed_snapshot",
    "_note",
    "tree_markdown",
];

pub(crate) struct ParsedAxSnapshot {
    native_snapshot_id: String,
    tokens: BTreeMap<u64, String>,
    response_sha256: Sha256Digest,
}
impl ParsedAxSnapshot {
    pub(crate) fn native_snapshot_id(&self) -> &str {
        &self.native_snapshot_id
    }

    /// Resolve only the exact Host presentation alias in this retained map.
    /// Native cache tokens are never accepted as remotely supplied authority.
    pub(crate) fn native_token_for(
        &self,
        host_alias: &str,
        full_host_token: &str,
    ) -> Result<&str, CuaError> {
        if !snapshot_id_valid(host_alias) || host_alias == self.native_snapshot_id {
            return Err(CuaError::StaleObservation);
        }
        let row = full_host_token
            .strip_prefix(&format!("{host_alias}:"))
            .and_then(|row| row.parse::<u64>().ok())
            .filter(|row| full_host_token == format!("{host_alias}:{row}"))
            .ok_or(CuaError::StaleObservation)?;
        self.tokens
            .get(&row)
            .map(String::as_str)
            .ok_or(CuaError::StaleObservation)
    }
    /// Only the Core-private translated payload is checked through this port.
    pub(crate) fn contains_native_token(&self, token: &str) -> bool {
        self.tokens.values().any(|value| value == token)
    }

    /// The caller supplies an alias from its own nonreused Host scope. This
    /// does not mint/validate that scope or authorize any subsequent action.
    /// Original text is discarded, including Markdown/native token hints.
    pub(crate) fn rewrite_result(
        &self,
        original: &CallToolResult,
        host_snapshot_id: &str,
    ) -> Result<CallToolResult, CuaError> {
        if !snapshot_id_valid(host_snapshot_id) || host_snapshot_id == self.native_snapshot_id {
            return Err(CuaError::InvalidRequest);
        }
        if bounded_digest(original)? != self.response_sha256 {
            return Err(CuaError::ProtocolMismatch);
        }
        let mut structured = original
            .structured_content
            .clone()
            .ok_or(CuaError::ProtocolMismatch)?;
        let object = structured
            .as_object_mut()
            .ok_or(CuaError::ProtocolMismatch)?;
        for key in REMOVE_NATIVE_FIELDS {
            object.remove(*key);
        }
        object.insert("snapshot_id".into(), Value::String(host_snapshot_id.into()));
        let elements = object
            .get_mut("elements")
            .and_then(Value::as_array_mut)
            .ok_or(CuaError::ProtocolMismatch)?;
        for element in elements {
            let element = element.as_object_mut().ok_or(CuaError::ProtocolMismatch)?;
            let index = element
                .get("element_index")
                .and_then(Value::as_u64)
                .ok_or(CuaError::ProtocolMismatch)?;
            if !self.tokens.contains_key(&index) {
                return Err(CuaError::ProtocolMismatch);
            }
            element.insert(
                "element_token".into(),
                Value::String(format!("{host_snapshot_id}:{index}")),
            );
        }
        // Fail closed rather than guessing whether a native snapshot prefix in
        // an arbitrary label/value/extra field is harmless user prose. Such a
        // label may be refused; its text is not retained in ParsedAxSnapshot.
        if contains_native_prefix(&structured, &self.native_snapshot_id) {
            return Err(CuaError::ProtocolMismatch);
        }
        bounded_digest(&structured)?;
        // Mature constructor deliberately regenerates a single text JSON view
        // from the same sanitized structured value. No image/old text survives.
        let output = CallToolResult::structured(structured);
        bounded_digest(&output)?;
        Ok(output)
    }
}

pub(crate) fn parse_acquired(
    result: &CallToolResult,
    pid: u32,
    window_id: u64,
) -> Result<ParsedAxSnapshot, CuaError> {
    if pid == 0 || window_id == 0 {
        return Err(CuaError::InvalidRequest);
    }
    let response_sha256 = bounded_digest(result)?;
    if result.is_error == Some(true) {
        return Err(CuaError::Unsupported);
    }
    // Only this narrow tree-only result is supported. Images/resources/audio
    // and future result content are not silently stripped into a fake read.
    let content = serde_json::to_value(&result.content).map_err(|_| CuaError::ProtocolMismatch)?;
    let content = content.as_array().ok_or(CuaError::ProtocolMismatch)?;
    if content.is_empty()
        || content.iter().any(|part| {
            part.get("type").and_then(Value::as_str) != Some("text")
                || !part.get("text").is_some_and(Value::is_string)
        })
    {
        return Err(CuaError::Unsupported);
    }
    let object = result
        .structured_content
        .as_ref()
        .and_then(Value::as_object)
        .ok_or(CuaError::ProtocolMismatch)?;
    if object.get("pid").and_then(Value::as_u64) != Some(u64::from(pid))
        || object.get("window_id").and_then(Value::as_u64) != Some(window_id)
        || object.get("tree_format").and_then(Value::as_str) != Some("elements")
    {
        return Err(CuaError::ProtocolMismatch);
    }
    if object.get("elements_complete").and_then(Value::as_bool) != Some(true)
        || object.get("truncated").and_then(Value::as_bool) != Some(false)
        || object
            .get("degraded")
            .is_some_and(|value| value.as_bool() != Some(false))
        || object
            .get("display_only")
            .is_some_and(|value| value.as_bool() != Some(false))
    {
        return Err(CuaError::Unsupported);
    }
    // A delta/Markdown/capture-only view cannot serve as a complete token map.
    if [
        "since_status",
        "since",
        "tree_markdown",
        "screenshot_error",
        "capture_id",
    ]
    .iter()
    .any(|key| object.contains_key(*key))
    {
        return Err(CuaError::Unsupported);
    }
    let native = object
        .get("snapshot_id")
        .and_then(Value::as_str)
        .ok_or(CuaError::ProtocolMismatch)?;
    if !snapshot_id_valid(native) {
        return Err(CuaError::ProtocolMismatch);
    }
    let elements = object
        .get("elements")
        .and_then(Value::as_array)
        .ok_or(CuaError::ProtocolMismatch)?;
    if elements.is_empty() {
        return Err(CuaError::Unsupported);
    }
    if elements.len() > MAX_REFS {
        return Err(CuaError::Busy);
    }
    for field in [
        "element_count",
        "total_element_count",
        "returned_element_count",
    ] {
        if object.get(field).and_then(Value::as_u64) != Some(elements.len() as u64) {
            return Err(CuaError::ProtocolMismatch);
        }
    }
    let mut tokens = BTreeMap::new();
    let mut retained = 128 + native.len();
    for element in elements {
        let element = element.as_object().ok_or(CuaError::ProtocolMismatch)?;
        let index = element
            .get("element_index")
            .and_then(Value::as_u64)
            .ok_or(CuaError::ProtocolMismatch)?;
        let token = element
            .get("element_token")
            .and_then(Value::as_str)
            .ok_or(CuaError::ProtocolMismatch)?;
        if token != format!("{native}:{index}")
            || !element
                .get("role")
                .and_then(Value::as_str)
                .is_some_and(|role| !role.is_empty() && role.len() <= 256)
            || element.get("depth").and_then(Value::as_u64).is_none()
        {
            return Err(CuaError::ProtocolMismatch);
        }
        retained = retained
            .checked_add(token.len() + ENTRY_OVERHEAD)
            .filter(|bytes| *bytes <= RETAINED_BYTES)
            .ok_or(CuaError::Busy)?;
        if tokens.insert(index, token.into()).is_some() {
            return Err(CuaError::ProtocolMismatch);
        }
    }
    Ok(ParsedAxSnapshot {
        native_snapshot_id: native.into(),
        tokens,
        response_sha256,
    })
}
fn snapshot_id_valid(value: &str) -> bool {
    value.len() == 9
        && value.starts_with('s')
        && value.as_bytes()[1..]
            .iter()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(v))
        && value != "s00000000"
}
fn contains_native_prefix(value: &Value, native: &str) -> bool {
    match value {
        Value::String(text) => text.contains(native),
        Value::Array(values) => values.iter().any(|v| contains_native_prefix(v, native)),
        Value::Object(values) => values
            .iter()
            .any(|(key, v)| key.contains(native) || contains_native_prefix(v, native)),
        _ => false,
    }
}
fn bounded_digest(value: &impl Serialize) -> Result<Sha256Digest, CuaError> {
    struct Bound {
        count: usize,
        hasher: Sha256,
    }
    impl Write for Bound {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.count = self
                .count
                .checked_add(bytes.len())
                .filter(|n| *n <= RESPONSE_BYTES)
                .ok_or_else(|| std::io::Error::other("AX response bound"))?;
            self.hasher.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = Bound {
        count: 0,
        hasher: Sha256::new(),
    };
    serde_json::to_writer(&mut writer, value).map_err(|_| CuaError::Busy)?;
    Ok(Sha256Digest::from_bytes(writer.hasher.finalize().into()))
}
#[cfg(test)]
#[path = "ax_snapshot_tests.rs"]
mod tests;

#[cfg(test)]
mod host_alias_tests {
    use super::*;
    #[test]
    fn exact_host_alias_resolves_only_its_retained_row_and_never_native_input() {
        let parsed = ParsedAxSnapshot {
            native_snapshot_id: "s00000001".into(),
            tokens: BTreeMap::from([(2, "s00000001:2".into())]),
            response_sha256: bounded_digest(&Value::Null).unwrap(),
        };
        assert_eq!(
            parsed.native_token_for("s00000002", "s00000002:2").unwrap(),
            "s00000001:2"
        );
        for (alias, token) in [
            ("s00000001", "s00000001:2"),
            ("s00000002", "s00000001:2"),
            ("s00000003", "s00000002:2"),
            ("s00000002", "s00000002:02"),
            ("s00000002", "s00000002:3"),
            ("s00000000", "s00000000:2"),
        ] {
            assert!(parsed.native_token_for(alias, token).is_err());
        }
        assert!(parsed.contains_native_token("s00000001:2"));
        assert!(!parsed.contains_native_token("s00000002:2"));
    }
}
