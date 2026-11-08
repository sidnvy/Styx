//! Styx's supported public surface, separate from the pinned upstream catalog.
//! Static shape checks are not permission, target freshness or dispatch authority.
use super::{CuaAction, CuaError, Result};
use serde_json::{Map, Value};
use std::{collections::BTreeMap, sync::OnceLock};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PublicComputerRoute {
    Metadata,
    WindowRead,
    DesktopRead,
    ElementClick,
    ElementValue,
    VerifyRead,
}

pub(crate) fn route(name: &str) -> Option<PublicComputerRoute> {
    Some(match name {
        "list_apps" | "list_windows" => PublicComputerRoute::Metadata,
        "get_window_state" => PublicComputerRoute::WindowRead,
        "get_desktop_state" => PublicComputerRoute::DesktopRead,
        "click" => PublicComputerRoute::ElementClick,
        "set_value" => PublicComputerRoute::ElementValue,
        "verify_state" => PublicComputerRoute::VerifyRead,
        // The Host currently has no retained observation adapter for these
        // input forms. Upstream advertising them is not a Styx route.
        _ => return None,
    })
}

fn schemas() -> Result<&'static BTreeMap<String, jsonschema::Validator>> {
    static VALUE: OnceLock<Result<BTreeMap<String, jsonschema::Validator>>> = OnceLock::new();
    VALUE
        .get_or_init(|| {
            let public: Value = serde_json::from_str(include_str!(
                "../../../../../docs/rust-core-rewrite/PUBLIC-MCP-V1.json"
            ))
            .map_err(|_| CuaError::ProtocolMismatch)?;
            let mut schemas = BTreeMap::new();
            for tool in public["tools"]
                .as_array()
                .ok_or(CuaError::ProtocolMismatch)?
            {
                let name = tool["name"].as_str().ok_or(CuaError::ProtocolMismatch)?;
                if route(name).is_none() {
                    continue;
                }
                let schema = jsonschema::validator_for(&tool["inputSchema"])
                    .map_err(|_| CuaError::ProtocolMismatch)?;
                if schemas.insert(name.into(), schema).is_some() {
                    return Err(CuaError::ProtocolMismatch);
                }
            }
            if schemas.len() != 7 {
                return Err(CuaError::ProtocolMismatch);
            }
            Ok(schemas)
        })
        .as_ref()
        .map_err(|error| *error)
}

/// Call after the Gateway has extracted its environment selector. Validation
/// uses exactly the published Styx schema, then the independent pinned native
/// schema and request classifiers. The SDK catalog is never rewritten here.
pub(crate) fn decode(name: &str, arguments: Map<String, Value>) -> Result<CuaAction> {
    let selected = route(name).ok_or(CuaError::Unsupported)?;
    let schema = schemas()?.get(name).ok_or(CuaError::Unsupported)?;
    if !schema.is_valid(&Value::Object(arguments.clone())) {
        return Err(CuaError::InvalidRequest);
    }
    let action = CuaAction::new(name.into(), arguments)?;
    match selected {
        PublicComputerRoute::WindowRead => {
            // No SDK-valid shape may miss both supported acquisition branches.
            action
                .desktop_read_request()?
                .ok_or(CuaError::Unsupported)?;
        }
        PublicComputerRoute::ElementValue => {
            // In particular, JSON Schema character length cannot express the
            // 16KiB UTF-8 byte bound enforced by this exact request parser.
            action
                .accessibility_write_request()?
                .ok_or(CuaError::Unsupported)?;
        }
        PublicComputerRoute::ElementClick => {
            // Platform-specific gesture admission belongs to the selected
            // Host, not the platform on which the Gateway happens to run.
            let token = action.arguments["element_token"]
                .as_str()
                .ok_or(CuaError::InvalidRequest)?;
            super::ax_write::validate_token(token)?;
        }
        _ => {
            action.required_capabilities()?;
        }
    }
    Ok(action)
}

/// Canonical representation shared by the public decoder and native operation
/// construction. This does not widen the published schema: decode validates the
/// caller's raw shape first. Legacy internal SDK forms remain independently
/// subject to the pinned native schema and Host's target admission.
pub(super) fn canonicalize(name: &str, arguments: &mut Map<String, Value>) {
    if name == "get_window_state"
        && arguments.get("include_accessibility_tree") != Some(&Value::Bool(false))
        && matches!(
            arguments.get("tree_format").and_then(Value::as_str),
            None | Some("markdown")
        )
    {
        arguments.insert("tree_format".into(), Value::String("elements".into()));
    }
    if name == "get_window_state" {
        if arguments.get("include_accessibility_tree") == Some(&Value::Bool(false))
            && arguments.get("include_screenshot") != Some(&Value::Bool(false))
        {
            arguments
                .entry("include_screenshot")
                .or_insert(Value::Bool(true));
            for (key, default) in [("max_image_dimension", 1024), ("timeout_ms", 1000)] {
                arguments.entry(key).or_insert(Value::from(default));
            }
        } else if arguments.get("include_screenshot") == Some(&Value::Bool(false))
            && arguments.get("include_accessibility_tree") != Some(&Value::Bool(false))
        {
            arguments
                .entry("include_accessibility_tree")
                .or_insert(Value::Bool(true));
            for (key, default) in [
                ("max_elements", 250),
                ("max_depth", 25),
                ("timeout_ms", 1000),
            ] {
                arguments.entry(key).or_insert(Value::from(default));
            }
        }
    }
    if name == "click" && arguments.contains_key("element_token") {
        for (key, default) in [("button", "left"), ("delivery_mode", "background")] {
            if arguments.get(key).and_then(Value::as_str) == Some(default) {
                arguments.remove(key);
            }
        }
    }
}

#[cfg(test)]
#[path = "public_contract_tests.rs"]
mod tests;
