//! Pure validation/projection of an already acquired fixed-Cua AX read.
//! No owner issuance, permission evidence, Core observation or token authority
//! is created here. Host must bind and install this only under its own gates.
use super::CuaError;
use rmcp::model::CallToolResult;
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
};

const RESPONSE_BYTES: usize = 1024 * 1024;
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
    // Owned validated data: callers cannot substitute a different native result.
    result: CallToolResult,
    images_allowed: bool,
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
        host_snapshot_id: &str,
    ) -> Result<CallToolResult, CuaError> {
        if !snapshot_id_valid(host_snapshot_id) || host_snapshot_id == self.native_snapshot_id {
            return Err(CuaError::InvalidRequest);
        }
        let mut structured = self
            .result
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
            // Read-only rows never acquire either a native or a Host input ref.
            if element.get("read_only") == Some(&Value::Bool(true)) {
                if element.contains_key("element_token") || self.tokens.contains_key(&index) {
                    return Err(CuaError::ProtocolMismatch);
                }
                continue;
            }
            if !self.tokens.contains_key(&index) {
                return Err(CuaError::ProtocolMismatch);
            }
            element.insert(
                "element_token".into(),
                Value::String(format!("{host_snapshot_id}:{index}")),
            );
        }
        // References are typed fields, not substrings of user-visible labels.
        // Native-looking text in a page does not gain input authority.
        // Mature constructor deliberately regenerates a single text JSON view
        // from the same sanitized structured value. Ordinary authorized reads
        // retain their image content; acquisition never accepts images.
        let mut output = CallToolResult::structured(structured);
        if self.images_allowed {
            output.content.extend(
                self.result
                    .content
                    .iter()
                    .filter(|part| matches!(part, rmcp::model::ContentBlock::Image(_)))
                    .cloned(),
            );
        }
        check_size(&output)?;
        Ok(output)
    }
}

fn validate_read_frame(
    result: &CallToolResult,
    pid: u32,
    window_id: u64,
    observed: bool,
) -> Result<&serde_json::Map<String, Value>, CuaError> {
    if pid == 0 || window_id == 0 {
        return Err(CuaError::InvalidRequest);
    }
    check_size(result)?;
    if result.is_error == Some(true) {
        return Err(CuaError::Unsupported);
    }
    // Acquisition accepts only text. An ordinary authorized combined read
    // may retain images; resources/audio never become an actionable tree.
    let content = serde_json::to_value(&result.content).map_err(|_| CuaError::ProtocolMismatch)?;
    let content = content.as_array().ok_or(CuaError::ProtocolMismatch)?;
    if content.is_empty()
        || content.iter().any(|part| {
            if observed && part.get("type").and_then(Value::as_str) == Some("image") {
                return false;
            }
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
        || (!observed && object.get("tree_format").and_then(Value::as_str) != Some("elements"))
    {
        return Err(CuaError::ProtocolMismatch);
    }
    Ok(object)
}
fn flag(object: &serde_json::Map<String, Value>, name: &str) -> Result<bool, CuaError> {
    match object.get(name) {
        None => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(CuaError::ProtocolMismatch),
    }
}

/// Descriptive native results are useful even without a complete target map.
/// Never create a Host observation, alias, or writable reference for this branch.
pub(crate) fn project_descriptive_read(
    result: &CallToolResult,
    pid: u32,
    window_id: u64,
    observed: bool,
) -> Result<Option<CallToolResult>, CuaError> {
    let Some(object) = result
        .structured_content
        .as_ref()
        .and_then(Value::as_object)
    else {
        return Ok(None); // The ordinary parser supplies the protocol error.
    };
    let Some(elements) = object.get("elements").and_then(Value::as_array) else {
        return Ok(None);
    };
    let partial = flag(object, "degraded")?
        || flag(object, "display_only")?
        || flag(object, "truncated")?
        || elements.is_empty()
        || (!observed
            && object
                .get("total_element_count")
                .and_then(Value::as_u64)
                .is_some_and(|total| total > elements.len() as u64));
    if !partial {
        return Ok(None);
    }
    let object = validate_read_frame(result, pid, window_id, observed)?;
    let returned = object.get("returned_element_count").and_then(Value::as_u64);
    let total = object.get("total_element_count").and_then(Value::as_u64);
    if returned != Some(elements.len() as u64)
        || total != object.get("element_count").and_then(Value::as_u64)
        || total.is_none_or(|count| count < elements.len() as u64)
        || !object.get("truncated").is_some_and(Value::is_boolean)
    {
        return Err(CuaError::ProtocolMismatch);
    }
    let mut indices = BTreeSet::new();
    for element in elements {
        validate_row(element, &mut indices)?;
    }
    let mut output = Value::Object(object.clone());
    let output_object = output.as_object_mut().expect("validated native AX object");
    for name in REMOVE_NATIVE_FIELDS
        .iter()
        .copied()
        .chain(["snapshot_id", "capture_id"])
    {
        output_object.remove(name);
    }
    let reason = native_reason(result).unwrap_or_else(|| {
        if elements.is_empty() {
            "empty_accessibility_tree".into()
        } else if object.get("truncated") == Some(&Value::Bool(true)) {
            "truncated_accessibility_tree".into()
        } else {
            "partial_accessibility_tree".into()
        }
    });
    output_object.insert("native_reason".into(), Value::String(reason.clone()));
    output_object.insert(
        "read_status".into(),
        Value::String(
            if reason == "x11_property_fallback_partial" {
                "window_metadata_only"
            } else {
                "partial_accessibility_tree"
            }
            .into(),
        ),
    );
    output_object.insert("display_only".into(), Value::Bool(true));
    output_object.insert("read_only".into(), Value::Bool(true));
    output_object.insert("elements_complete".into(), Value::Bool(false));
    output_object.insert("input_authorized".into(), Value::Bool(false));
    output_object.insert(
        "execution_certainty".into(),
        Value::String("acknowledged".into()),
    );
    for row in output_object
        .get_mut("elements")
        .unwrap()
        .as_array_mut()
        .unwrap()
    {
        let row = row.as_object_mut().expect("validated native AX row");
        row.remove("element_token");
        row.remove("actions");
        row.insert("read_only".into(), Value::Bool(true));
    }
    let output = CallToolResult::structured(output);
    check_size(&output)?;
    Ok(Some(output))
}

/// Only a short driver diagnostic code is projected, never arbitrary error text.
pub(crate) fn native_reason(result: &CallToolResult) -> Option<String> {
    let value = result
        .structured_content
        .as_ref()?
        .get("degraded_reason")?
        .as_str()?;
    let code = value.split(':').next()?;
    (code.len() <= 96
        && !code.is_empty()
        && code.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
    .then(|| code.to_owned())
}
fn validate_row(element: &Value, indices: &mut BTreeSet<u64>) -> Result<u64, CuaError> {
    let row = element.as_object().ok_or(CuaError::ProtocolMismatch)?;
    let index = row
        .get("element_index")
        .and_then(Value::as_u64)
        .ok_or(CuaError::ProtocolMismatch)?;
    if !indices.insert(index)
        || !row
            .get("role")
            .and_then(Value::as_str)
            .is_some_and(|role| !role.is_empty() && role.len() <= 256)
        || row.get("depth").and_then(Value::as_u64).is_none()
    {
        return Err(CuaError::ProtocolMismatch);
    }
    Ok(index)
}

pub(crate) fn parse_acquired(
    result: &CallToolResult,
    pid: u32,
    window_id: u64,
) -> Result<ParsedAxSnapshot, CuaError> {
    parse_snapshot(result, pid, window_id, false)
}
pub(crate) fn parse_observed(
    result: &CallToolResult,
    pid: u32,
    window_id: u64,
) -> Result<ParsedAxSnapshot, CuaError> {
    parse_snapshot(result, pid, window_id, true)
}
fn parse_snapshot(
    result: &CallToolResult,
    pid: u32,
    window_id: u64,
    observed: bool,
) -> Result<ParsedAxSnapshot, CuaError> {
    let object = validate_read_frame(result, pid, window_id, observed)?;
    // Counts below already prove that the returned projection is complete.
    // Windows may report elements_complete:false even with matching counts;
    // do not impose a second, contradictory completeness test.
    if object.get("truncated").and_then(Value::as_bool) != Some(false)
        || flag(object, "degraded")?
        || flag(object, "display_only")?
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
    .any(|key| object.contains_key(*key) && (!observed || matches!(*key, "since_status" | "since")))
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

    let returned = object.get("returned_element_count").and_then(Value::as_u64);
    let total = object.get("total_element_count").and_then(Value::as_u64);
    let count = object.get("element_count").and_then(Value::as_u64);
    if returned != Some(elements.len() as u64)
        || total != count
        || total.is_none_or(|total| {
            if observed {
                total < elements.len() as u64
            } else {
                total != elements.len() as u64
            }
        })
    {
        return Err(CuaError::ProtocolMismatch);
    }
    let mut tokens = BTreeMap::new();
    let mut indices = BTreeSet::new();
    let mut retained = 128 + native.len();
    for element in elements {
        let index = validate_row(element, &mut indices)?;
        let element = element.as_object().expect("validated AX row");
        let read_only = match element.get("read_only") {
            None | Some(Value::Bool(false)) => false,
            Some(Value::Bool(true)) => true,
            Some(_) => return Err(CuaError::ProtocolMismatch),
        };
        if read_only {
            // Unsupported per-object native invalidation permits descriptive
            // reads only. A token on such a row is contradictory and refused.
            if element.contains_key("element_token") {
                return Err(CuaError::ProtocolMismatch);
            }
            continue;
        }
        let token = element
            .get("element_token")
            .and_then(Value::as_str)
            .ok_or(CuaError::ProtocolMismatch)?;
        if token != format!("{native}:{index}") {
            return Err(CuaError::ProtocolMismatch);
        }
        retained = retained
            .checked_add(token.len() + ENTRY_OVERHEAD)
            .filter(|bytes| *bytes <= RETAINED_BYTES)
            .ok_or(CuaError::Busy)?;
        tokens.insert(index, token.into());
    }
    Ok(ParsedAxSnapshot {
        native_snapshot_id: native.into(),
        tokens,
        result: result.clone(),
        images_allowed: observed,
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
fn check_size(value: &impl Serialize) -> Result<(), CuaError> {
    struct Bound {
        count: usize,
    }
    impl Write for Bound {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.count = self
                .count
                .checked_add(bytes.len())
                .filter(|n| *n <= RESPONSE_BYTES)
                .ok_or_else(|| std::io::Error::other("AX response bound"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = Bound { count: 0 };
    serde_json::to_writer(&mut writer, value).map_err(|_| CuaError::Busy)?;
    Ok(())
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
            result: CallToolResult::structured(Value::Null),
            images_allowed: false,
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
