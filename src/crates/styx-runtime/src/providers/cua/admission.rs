//! Private native Linux/Wayland route classification, not authorization.
//! Call only after the frozen public schema check. Host must check every returned
//! capability under its original admission mutex and bind the same immutable
//! action/owner/session/observation before committing one dispatch permit.
//! Fixed Cua0.36 Linux impl_.rs: observations1207-1344, click6653-7188,
//! typing7454+, key8531+, set_value9321-9377, scroll9956-10235.
use super::CuaError;
use serde_json::{Map, Value};
use styx_contracts::capability::CapabilityId;

type Result<T> = std::result::Result<T, CuaError>;

pub(super) struct Requirements {
    pub(super) capabilities: Vec<CapabilityId>,
    pub(super) side_effecting: bool,
    /// Native input must bind an existing exact owner/session observation.
    /// A target object/element token supplied by JSON is never that authority.
    pub(super) requires_observed_target: bool,
}

fn unsupported<T>() -> Result<T> {
    Err(CuaError::Unsupported)
}
fn flag(args: &Map<String, Value>, name: &str, default: bool) -> Result<bool> {
    match args.get(name) {
        None => Ok(default),
        Some(Value::Bool(value)) => Ok(*value),
        _ => unsupported(),
    }
}
fn add(caps: &mut Vec<CapabilityId>, cap: CapabilityId) {
    if !caps.contains(&cap) {
        caps.push(cap);
    }
}
fn foreground(args: &Map<String, Value>) -> Result<bool> {
    match args.get("delivery_mode") {
        None => Ok(false),
        Some(Value::String(v)) if v == "background" => Ok(false),
        Some(Value::String(v)) if v == "foreground" => Ok(true),
        _ => unsupported(),
    }
}
fn token(args: &Map<String, Value>) -> Result<bool> {
    match args.get("element_token") {
        None => Ok(false),
        Some(Value::String(v)) if !v.is_empty() => Ok(true),
        _ => unsupported(),
    }
}
fn pixel(args: &Map<String, Value>) -> Result<bool> {
    match (args.get("x"), args.get("y")) {
        (None, None) => Ok(false),
        (Some(Value::Number(x)), Some(Value::Number(y)))
            if x.as_f64().is_some_and(f64::is_finite) && y.as_f64().is_some_and(f64::is_finite) =>
        {
            Ok(true)
        }
        _ => unsupported(),
    }
}
fn modifier(args: &Map<String, Value>, key: &str, array: bool) -> Result<bool> {
    match args.get(key) {
        None => Ok(false),
        Some(Value::Array(v)) if array && v.iter().all(Value::is_string) => Ok(!v.is_empty()),
        Some(Value::String(v)) if !array && !v.is_empty() => Ok(true),
        _ => unsupported(),
    }
}
/// Reject contradictory target selectors instead of guessing which native alias
/// wins. The native driver still performs all actual target resolution.
fn target_shape(args: &Map<String, Value>, has_token: bool, has_pixel: bool) -> Result<()> {
    if has_token && has_pixel {
        return unsupported();
    }
    if let Some(Value::Object(target)) = args.get("target") {
        let kind = target
            .get("kind")
            .and_then(Value::as_str)
            .ok_or(CuaError::Unsupported)?;
        let desktop = match kind {
            "window" => false,
            "desktop" => true,
            _ => return unsupported(),
        };
        if args
            .get("scope")
            .and_then(Value::as_str)
            .is_some_and(|scope| (scope == "desktop") != desktop)
        {
            return unsupported();
        }
        if desktop && (args.contains_key("pid") || args.contains_key("window_id") || has_token) {
            return unsupported();
        }
        if !desktop {
            for key in ["pid", "window_id"] {
                if let Some(outer) = args.get(key) {
                    if target.get(key) != Some(outer) {
                        return unsupported();
                    }
                }
            }
        }
    } else if args.contains_key("target") {
        return unsupported();
    }
    Ok(())
}

pub(super) fn required(name: &str, args: &Map<String, Value>) -> Result<Vec<CapabilityId>> {
    Ok(classify(name, args)?.capabilities)
}

pub(super) fn classify(name: &str, args: &Map<String, Value>) -> Result<Requirements> {
    use CapabilityId::*;
    // Native fs::write is not scoped to owned output by this adapter. Keep the
    // public schema frozen, but refuse the optional route before any native I/O.
    if args.contains_key("screenshot_out_file") {
        return unsupported();
    }
    let mut capabilities = Vec::new();
    let side_effecting = matches!(
        name,
        "click" | "set_value" | "type_text" | "press_key" | "scroll"
    );
    match name {
        "list_apps" | "list_windows" => add(&mut capabilities, DesktopWindowsRead),
        "get_window_state" => {
            // capture_mode is deprecated/ignored by native Linux: only actual
            // include_* switches choose the branches, both default true.
            let screenshot = flag(args, "include_screenshot", true)?;
            let tree = flag(args, "include_accessibility_tree", true)?;
            if !screenshot && !tree {
                return unsupported();
            }
            if screenshot {
                add(&mut capabilities, DesktopCapture);
            }
            if tree {
                add(&mut capabilities, DesktopAccessibility);
            }
        }
        "get_desktop_state" => add(&mut capabilities, DesktopCapture),
        "verify_state" => {
            add(&mut capabilities, DesktopAccessibility);
            if flag(args, "include_screenshot", false)? {
                add(&mut capabilities, DesktopCapture);
            }
        }
        "set_value" => {
            // This classification is ONLY native Wayland: after AT-SPI failure
            // fixed0.36 refuses the X11 pointer/keyboard fallback. Do not reuse
            // this table for X11 or a different upstream implementation.
            if !token(args)? {
                return unsupported();
            }
            add(&mut capabilities, DesktopAccessibility);
        }
        "click" | "scroll" | "type_text" | "press_key" => {
            let element = token(args)?;
            let xy = pixel(args)?;
            target_shape(args, element, xy)?;
            let fg = foreground(args)?;
            let keyboard = matches!(name, "type_text" | "press_key");
            add(
                &mut capabilities,
                if keyboard {
                    DesktopKeyboard
                } else {
                    DesktopPointer
                },
            );
            if element {
                add(&mut capabilities, DesktopAccessibility);
            }
            if keyboard && xy {
                add(&mut capabilities, DesktopPointer);
            }
            // type_text may use AT-SPI insertion even without an explicit token.
            // A bare desktop/focused typing route instead uses native keys.
            let desktop = args.get("scope").and_then(Value::as_str) == Some("desktop")
                && !args.contains_key("pid")
                || args
                    .get("target")
                    .and_then(Value::as_object)
                    .and_then(|t| t.get("kind"))
                    .and_then(Value::as_str)
                    == Some("desktop");
            if name == "type_text" && !desktop && !xy {
                add(&mut capabilities, DesktopAccessibility);
            }
            if name == "click" && modifier(args, "modifier", false)? {
                add(&mut capabilities, DesktopKeyboard);
            }
            if fg {
                add(&mut capabilities, DesktopWindowsControl);
            }
            // Native element click surrounds AT-SPI doAction with a focus
            // guard that may restore activation, even for background delivery.
            if name == "click" && element {
                add(&mut capabilities, DesktopWindowsControl);
            }
        }
        _ => return unsupported(),
    }
    Ok(Requirements {
        capabilities,
        side_effecting,
        requires_observed_target: side_effecting,
    })
}

#[cfg(test)]
#[path = "admission_tests.rs"]
mod tests;
