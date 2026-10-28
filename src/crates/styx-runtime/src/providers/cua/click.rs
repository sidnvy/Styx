//! Exact element clicks only. No pixel, implicit window, session override or multi-click route.
use super::*;
pub(crate) struct ClickRequest {
    pub(crate) pid: Option<u32>,
    pub(crate) window_id: Option<u64>,
    pub(crate) element_token: String,
}
impl ClickRequest {
    pub(crate) fn with_native_token(&self, token: &str) -> Result<CuaAction> {
        CuaAction::new(
            "click".into(),
            serde_json::json!({
                "pid":self.pid,"window_id":self.window_id,"element_token":token
            })
            .as_object()
            .expect("literal object")
            .clone(),
        )
    }
}
impl CuaAction {
    pub(crate) fn click_request(&self) -> Result<Option<ClickRequest>> {
        if self.name != "click" {
            return Ok(None);
        }
        self.validate()?;
        const KEYS: &[&str] = &["pid", "window_id", "element_token"];
        if !self.arguments.contains_key("element_token")
            || self
                .arguments
                .keys()
                .any(|key| !KEYS.contains(&key.as_str()))
        {
            return Err(CuaError::Unsupported);
        }
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
        }))
    }
}
