//! Exact element clicks only. Windows context menus use an explicit foreground
//! right click on the same retained AX target. No pixel or implicit-target route.
use super::*;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClickGesture {
    Primary,
    WindowsContextMenu,
}
pub(crate) struct ClickRequest {
    pub(crate) pid: Option<u32>,
    pub(crate) window_id: Option<u64>,
    pub(crate) element_token: String,
    pub(crate) gesture: ClickGesture,
}
impl ClickRequest {
    pub(crate) fn with_native_token(&self, token: &str) -> Result<CuaAction> {
        let mut arguments = serde_json::json!({
            "pid":self.pid,"window_id":self.window_id,"element_token":token
        })
        .as_object()
        .expect("literal object")
        .clone();
        if self.gesture == ClickGesture::WindowsContextMenu {
            arguments.insert("button".into(), Value::String("right".into()));
            arguments.insert("delivery_mode".into(), Value::String("foreground".into()));
        }
        CuaAction::new("click".into(), arguments)
    }
}
impl CuaAction {
    pub(crate) fn click_request(&self) -> Result<Option<ClickRequest>> {
        if self.name != "click" {
            return Ok(None);
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
            (None, None) => ClickGesture::Primary,
            (Some("right"), Some("foreground")) if cfg!(target_os = "windows") => {
                ClickGesture::WindowsContextMenu
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
        Ok(Some(ClickRequest {
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
        let request = action.click_request();
        if cfg!(target_os = "windows") {
            let request = request.unwrap().unwrap();
            assert_eq!(request.gesture, ClickGesture::WindowsContextMenu);
            let native = request.with_native_token("s00000001:1").unwrap();
            assert_eq!(native.arguments["element_token"], "s00000001:1");
            assert_eq!(native.arguments["button"], "right");
            assert_eq!(native.arguments["delivery_mode"], "foreground");
            assert_eq!(
                native.click_request().unwrap().unwrap().gesture,
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
            assert!(matches!(action.click_request(), Err(CuaError::Unsupported)));
        }
    }
}
