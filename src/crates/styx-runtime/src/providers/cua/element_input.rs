//! Element-bound input through the existing Cua executor. Linux typing requires
//! explicit foreground delivery; no pixel, clipboard or implicit-target API.
use super::*;
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ElementInputKind {
    Primary,
    WindowsContextMenu,
    ForegroundText(String),
}
pub(crate) struct ElementInputRequest {
    pub(crate) pid: Option<u32>,
    pub(crate) window_id: Option<u64>,
    pub(crate) element_token: String,
    pub(crate) gesture: ElementInputKind,
}
impl ElementInputRequest {
    pub(crate) fn with_native_token(&self, token: &str) -> Result<CuaAction> {
        let mut arguments = serde_json::json!({
            "pid":self.pid,"window_id":self.window_id,"element_token":token
        })
        .as_object()
        .expect("literal object")
        .clone();
        if self.gesture == ElementInputKind::WindowsContextMenu {
            arguments.insert("button".into(), Value::String("right".into()));
            arguments.insert("delivery_mode".into(), Value::String("foreground".into()));
        }
        if let ElementInputKind::ForegroundText(text) = &self.gesture {
            arguments.insert("text".into(), Value::String(text.clone()));
            arguments.insert("delivery_mode".into(), Value::String("foreground".into()));
            return CuaAction::new("type_text".into(), arguments);
        }
        CuaAction::new("click".into(), arguments)
    }
}
impl CuaAction {
    pub(crate) fn element_input_request(&self) -> Result<Option<ElementInputRequest>> {
        if !matches!(self.name.as_str(), "click" | "type_text") {
            return Ok(None);
        }
        if self.name == "type_text" {
            self.validate()?;
            // Explicit OS-foreground typing, reusing Cua's compositor target
            // and focus checks. Other platform routes have not been accepted.
            if !cfg!(target_os = "linux") {
                return Err(CuaError::Unsupported);
            }
            const FIELDS: &[&str] = &["pid", "window_id", "element_token", "text", "delivery_mode"];
            if self.arguments.len() != FIELDS.len()
                || self.arguments.keys().any(|k| !FIELDS.contains(&k.as_str()))
                || self.arguments.get("delivery_mode").and_then(Value::as_str) != Some("foreground")
            {
                return Err(CuaError::InvalidRequest);
            }
            let pid = self
                .arguments
                .get("pid")
                .and_then(Value::as_u64)
                .and_then(|v| u32::try_from(v).ok())
                .filter(|v| *v > 0 && *v <= i32::MAX as u32)
                .ok_or(CuaError::InvalidRequest)?;
            let window = self
                .arguments
                .get("window_id")
                .and_then(Value::as_u64)
                .filter(|v| *v > 0)
                .ok_or(CuaError::InvalidRequest)?;
            let token = self
                .arguments
                .get("element_token")
                .and_then(Value::as_str)
                .ok_or(CuaError::InvalidRequest)?;
            super::ax_write::validate_token(token)?;
            let text = self
                .arguments
                .get("text")
                .and_then(Value::as_str)
                .filter(|v| !v.is_empty() && v.len() <= 16 * 1024)
                .ok_or(CuaError::InvalidRequest)?;
            return Ok(Some(ElementInputRequest {
                pid: Some(pid),
                window_id: Some(window),
                element_token: token.to_owned(),
                gesture: ElementInputKind::ForegroundText(text.to_owned()),
            }));
        }
        self.validate()?;
        const KEYS: &[&str] = &[
            "pid",
            "window_id",
            "element_token",
            "button",
            "delivery_mode",
        ];
        if !self.arguments.contains_key("element_token")
            || self
                .arguments
                .keys()
                .any(|key| !KEYS.contains(&key.as_str()))
        {
            return Err(CuaError::Unsupported);
        }
        // WinUI tray icons have no background right-click analogue. Preserve
        // the public explicit posture; never silently front or turn it into Invoke.
        let gesture = match (
            self.arguments.get("button").and_then(Value::as_str),
            self.arguments.get("delivery_mode").and_then(Value::as_str),
        ) {
            (None, None) => ElementInputKind::Primary,
            (Some("right"), Some("foreground")) if cfg!(target_os = "windows") => {
                ElementInputKind::WindowsContextMenu
            }
            _ => return Err(CuaError::Unsupported),
        };
        let pid = self
            .arguments
            .get("pid")
            .map(|value| {
                value
                    .as_u64()
                    .and_then(|v| u32::try_from(v).ok())
                    .filter(|p| *p > 0 && *p <= i32::MAX as u32)
                    .ok_or(CuaError::InvalidRequest)
            })
            .transpose()?;
        let window_id = self
            .arguments
            .get("window_id")
            .map(|value| {
                value
                    .as_u64()
                    .filter(|w| *w > 0)
                    .ok_or(CuaError::InvalidRequest)
            })
            .transpose()?;
        let element_token = self
            .arguments
            .get("element_token")
            .and_then(Value::as_str)
            .ok_or(CuaError::InvalidRequest)?
            .to_owned();
        Ok(Some(ElementInputRequest {
            pid,
            window_id,
            element_token,
            gesture,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cua_click_context_menu_preserves_explicit_posture_and_native_token() {
        let args = serde_json::json!({"pid":42,"window_id":43,"element_token":"s00000002:1","button":"right","delivery_mode":"foreground"});
        let action = CuaAction::new("click".into(), args.as_object().unwrap().clone()).unwrap();
        let request = action.element_input_request();
        if cfg!(target_os = "windows") {
            let request = request.unwrap().unwrap();
            assert_eq!(request.gesture, ElementInputKind::WindowsContextMenu);
            let native = request.with_native_token("s00000001:1").unwrap();
            assert_eq!(native.arguments["element_token"], "s00000001:1");
            assert_eq!(native.arguments["button"], "right");
            assert_eq!(native.arguments["delivery_mode"], "foreground");
            assert_eq!(
                native.element_input_request().unwrap().unwrap().gesture,
                request.gesture
            );
            assert!(
                native
                    .required_capabilities()
                    .unwrap()
                    .contains(&CapabilityId::DesktopWindowsControl)
            );
        } else {
            assert!(matches!(request, Err(CuaError::Unsupported)));
        }
    }
    #[test]
    fn cua_click_context_menu_rejects_implicit_and_unbound_routes() {
        for extra in [
            serde_json::json!({"button":"right"}),
            serde_json::json!({"button":"right","delivery_mode":"background"}),
            serde_json::json!({"button":"middle","delivery_mode":"foreground"}),
            serde_json::json!({"delivery_mode":"foreground"}),
            serde_json::json!({"button":"right","delivery_mode":"foreground","x":1,"y":2}),
        ] {
            let mut args =
                serde_json::json!({"pid":42,"window_id":43,"element_token":"s00000002:1"})
                    .as_object()
                    .unwrap()
                    .clone();
            args.extend(extra.as_object().unwrap().clone());
            let action = CuaAction::new("click".into(), args).unwrap();
            assert!(matches!(
                action.element_input_request(),
                Err(CuaError::Unsupported)
            ));
        }
    }
}
