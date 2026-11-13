//! One standard Cua set_value call with its strict text-only native route.
//! Core retains operation ownership, the late write gate and no-unknown-replay.
use super::*;

/// Created only by the original Host coordinator, not deserializable tool input.
pub(crate) type AxWriteGate = Box<
    dyn FnOnce() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>> + Send,
>;

pub(crate) struct AxWriteRequest {
    pub(crate) pid: u32,
    pub(crate) window_id: u64,
    pub(crate) element_token: String,
    pub(crate) value: String,
}
impl AxWriteRequest {
    pub(crate) fn with_native_token(&self, token: &str) -> Result<CuaAction> {
        validate_token(token)?;
        CuaAction::new(
            "set_value".into(),
            serde_json::json!({
                "pid":self.pid,"window_id":self.window_id,"element_token":token,"value":self.value
            })
            .as_object()
            .ok_or(CuaError::InvalidRequest)?
            .clone(),
        )
    }
}
pub(super) fn validate_token(token: &str) -> Result<()> {
    let (snapshot, row) = token.split_once(':').ok_or(CuaError::InvalidRequest)?;
    if snapshot.len() != 9
        || !snapshot.starts_with('s')
        || !snapshot[1..]
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        || snapshot == "s00000000"
        || row
            .parse::<u64>()
            .ok()
            .filter(|i| *i < 2048)
            .is_none_or(|i| i.to_string() != row)
    {
        return Err(CuaError::InvalidRequest);
    }
    Ok(())
}
impl CuaAction {
    pub(crate) fn accessibility_write_request(&self) -> Result<Option<AxWriteRequest>> {
        self.validate()?;
        if self.name != "set_value" {
            return Ok(None);
        }
        const KEYS: &[&str] = &["pid", "window_id", "element_token", "value"];
        if self.arguments.len() != KEYS.len()
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
            .and_then(Value::as_u64)
            .and_then(|v| u32::try_from(v).ok())
            .filter(|p| *p > 0 && *p <= i32::MAX as u32)
            .ok_or(CuaError::InvalidRequest)?;
        let window_id = self
            .arguments
            .get("window_id")
            .and_then(Value::as_u64)
            .filter(|w| *w > 0)
            .ok_or(CuaError::InvalidRequest)?;
        let element_token = self
            .arguments
            .get("element_token")
            .and_then(Value::as_str)
            .ok_or(CuaError::InvalidRequest)?;
        validate_token(element_token)?;
        let value = self
            .arguments
            .get("value")
            .and_then(Value::as_str)
            .filter(|v| v.len() <= 16 * 1024)
            .ok_or(CuaError::InvalidRequest)?;
        Ok(Some(AxWriteRequest {
            pid,
            window_id,
            element_token: element_token.into(),
            value: value.into(),
        }))
    }
}

/// Diagnostic labels only; values, target handles and raw errors never enter logs.
pub(super) fn diagnostic(stage: &'static str, code: &str) {
    if std::env::var_os("STYX_CUA_DIAGNOSTICS").as_deref() != Some(std::ffi::OsStr::new("1")) {
        return;
    }
    use std::io::Write as _;
    let _ = writeln!(
        std::io::stderr().lock(),
        "{}",
        serde_json::json!({"event":"styx_cua_refusal", "stage":stage, "code":code})
    );
}

fn pre_send_code(code: &str) -> bool {
    matches!(
        code,
        "invalid_request"
            | "stale_observation"
            | "editable_unavailable"
            | "window_unavailable"
            | "process_unavailable"
            | "strict_text_unavailable"
            | "permission_denied"
    )
}

// Official Cua 0.47 publishes successful set_value calls as ActionResult.
// Only this strict call's accessibility/unverifiable projection is an ACK;
// descriptions and next-call suggestions confer no execution or effect proof.
fn valid_recovery_fields(data: &Map<String, Value>) -> bool {
    if data.get("hint").is_some_and(|value| !value.is_string()) {
        return false;
    }
    if let Some(value) = data.get("next_call") {
        let Some(call) = value.as_object() else {
            return false;
        };
        if call.len() != 2
            || !call.get("tool").is_some_and(Value::is_string)
            || !call.get("arguments").is_some_and(Value::is_object)
        {
            return false;
        }
    }
    true
}

fn published_ack(data: &Map<String, Value>) -> bool {
    if data.get("effect").and_then(Value::as_str) != Some("unverifiable")
        || data.get("route").and_then(Value::as_str) != Some("accessibility")
        || data.keys().any(|key| {
            !matches!(
                key.as_str(),
                "effect" | "route" | "delivery" | "summary" | "hint" | "next_call"
            )
        })
    {
        return false;
    }
    if data.get("summary").is_some_and(|value| !value.is_string()) || !valid_recovery_fields(data) {
        return false;
    }
    if let Some(value) = data.get("delivery") {
        let Some(delivery) = value.as_object() else {
            return false;
        };
        if delivery
            .keys()
            .any(|key| !matches!(key.as_str(), "mode" | "delivered_count"))
            || !matches!(
                delivery.get("mode").and_then(Value::as_str),
                Some("unknown" | "background" | "not_applicable")
            )
            || delivery.get("delivered_count").is_some_and(|count| {
                count
                    .as_u64()
                    .is_none_or(|count| count > u64::from(u32::MAX))
            })
        {
            return false;
        }
    }
    true
}

fn write_evidence(value: &CallToolResult) -> CuaEvidence {
    if bounded_bytes(value, FRAME_BYTES).is_err() {
        return CuaEvidence::Unknown;
    }
    let Some(data) = value.structured_content.as_ref().and_then(Value::as_object) else {
        return CuaEvidence::Unknown;
    };
    if value.is_error != Some(true) && published_ack(data) {
        return CuaEvidence::Acknowledged;
    }
    if data.get("schema").and_then(Value::as_u64) != Some(1)
        || data.get("effect").and_then(Value::as_str) != Some("unverified")
    {
        return CuaEvidence::Unknown;
    }
    match data.get("outcome").and_then(Value::as_str) {
        Some("acknowledged") if data.len() == 3 && value.is_error != Some(true) => {
            CuaEvidence::Acknowledged
        }
        Some("refused")
            if data.keys().all(|key| {
                matches!(
                    key.as_str(),
                    "schema" | "outcome" | "effect" | "code" | "hint" | "next_call"
                )
            }) && valid_recovery_fields(data)
                && value.is_error == Some(true)
                && data
                    .get("code")
                    .and_then(Value::as_str)
                    .is_some_and(pre_send_code) =>
        {
            CuaEvidence::NotDispatched
        }
        _ => CuaEvidence::Unknown,
    }
}

pub(super) async fn invoke(
    stop: &CancellationToken,
    uncertain: &mut bool,
    peer: &rmcp::service::Peer<RoleClient>,
    request: AxWriteRequest,
    until: Instant,
    gate: AxWriteGate,
    session: Option<&str>,
) -> (CuaEvidence, Option<CallToolResult>, Option<CuaError>) {
    // No acquisition RPC or native cache exists here. A refused/expired Core
    // gate therefore has sent no native request at all.
    if stop.is_cancelled() || Instant::now() >= until {
        return (CuaEvidence::NotDispatched, None, Some(CuaError::Unknown));
    }
    let authorized = tokio::select! {
        biased;
        _ = stop.cancelled() => None,
        _ = tokio::time::sleep_until(until) => None,
        result = gate() => Some(result),
    };
    match authorized {
        Some(Ok(())) if !stop.is_cancelled() && Instant::now() < until => {}
        Some(Err(cause)) => {
            diagnostic("late_write_gate", cause.code());
            return (CuaEvidence::NotDispatched, None, Some(cause));
        }
        _ => return (CuaEvidence::NotDispatched, None, Some(CuaError::Unknown)),
    }
    let mut arguments = serde_json::json!({
        "pid":request.pid,"window_id":request.window_id,
        "element_token":request.element_token,"value":request.value,
        "styx_strict_text":true
    })
    .as_object()
    .expect("literal object")
    .clone();
    if let Some(session) = session {
        arguments.insert("session".into(), Value::String(session.into()));
    }
    let write = CallToolRequestParams::new("set_value").with_arguments(arguments);
    // Only this Host-generated request contains the internal strict flag. One
    // poll of one official RPC; any failed/lost/malformed post-send reply is
    // terminal Unknown, never permission to try another setter or transport.
    let response = tokio::select! {
        biased;
        _ = stop.cancelled() => None,
        _ = tokio::time::sleep_until(until) => None,
        result = peer.call_tool_once(write) => Some(result),
    };
    let result = match response {
        Some(Ok(CallToolResponse::Complete(value))) => match write_evidence(&value) {
            CuaEvidence::Acknowledged => (
                CuaEvidence::Acknowledged,
                Some(CallToolResult::structured(serde_json::json!({
                    "schema":1,"outcome":"acknowledged","effect":"unverified"
                }))),
                None,
            ),
            CuaEvidence::NotDispatched => (
                CuaEvidence::NotDispatched,
                None,
                Some(CuaError::PermissionDenied),
            ),
            CuaEvidence::Unknown => (CuaEvidence::Unknown, None, Some(CuaError::Unknown)),
        },
        _ => (CuaEvidence::Unknown, None, Some(CuaError::Unknown)),
    };
    if result.0 == CuaEvidence::Unknown {
        *uncertain = true;
        stop.cancel();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    // Captured from the actual Session-1 Windows fixture, not a synthesized
    // envelope. The producer's words and follow-up hint are never authority.
    #[test]
    fn real_windows_04724_wire_is_an_unverified_ack_without_text_inference() {
        let wire: Value = serde_json::from_str(include_str!(
            "../../../../../docs/evidence/cua-windows-strict-0.47.24-wire.json"
        ))
        .unwrap();
        let mut reply: CallToolResult = serde_json::from_value(wire["result"].clone()).unwrap();
        assert_eq!(write_evidence(&reply), CuaEvidence::Acknowledged);
        reply.content.clear();
        reply.structured_content.as_mut().unwrap()["summary"] =
            Value::String("arbitrary diagnostic words".into());
        assert_eq!(write_evidence(&reply), CuaEvidence::Acknowledged);
        reply.is_error = Some(true);
        assert_eq!(write_evidence(&reply), CuaEvidence::Unknown);
        reply.is_error = Some(false);
        reply.structured_content.as_mut().unwrap()["route"] = Value::String("keyboard".into());
        assert_eq!(write_evidence(&reply), CuaEvidence::Unknown);
    }
    #[test]
    fn strict_write_accepts_only_full_public_target_without_internal_flags() {
        let args =
            serde_json::json!({"pid":42,"window_id":7,"element_token":"s00000001:2","value":""});
        let action = CuaAction::new("set_value".into(), args.as_object().unwrap().clone()).unwrap();
        assert!(action.accessibility_write_request().unwrap().is_some());
        for (key, value) in [
            ("delivery_mode", Value::String("foreground".into())),
            ("session", Value::String("foreign".into())),
            ("styx_strict_text", Value::Bool(true)),
        ] {
            let mut bad = args.as_object().unwrap().clone();
            bad.insert(key.into(), value);
            assert!(
                CuaAction::new("set_value".into(), bad)
                    .and_then(|action| action.accessibility_write_request())
                    .is_err()
            );
        }
        assert!(validate_token("s00000001:02").is_err());
        assert!(validate_token("s00000000:2").is_err());
    }
    #[test]
    fn strict_native_outcomes_never_infer_no_input_from_generic_failure() {
        let ack = CallToolResult::structured(
            serde_json::json!({"schema":1,"outcome":"acknowledged","effect":"unverified"}),
        );
        assert_eq!(write_evidence(&ack), CuaEvidence::Acknowledged);
        let mut refusal = CallToolResult::structured(
            serde_json::json!({"schema":1,"outcome":"refused","effect":"unverified","code":"editable_unavailable"}),
        );
        refusal.is_error = Some(true);
        assert_eq!(write_evidence(&refusal), CuaEvidence::NotDispatched);
        refusal.structured_content.as_mut().unwrap()["hint"] =
            Value::String("official read-again advice".into());
        refusal.structured_content.as_mut().unwrap()["next_call"] =
            serde_json::json!({"tool":"get_window_state","arguments":{"pid":42,"window_id":7}});
        assert_eq!(write_evidence(&refusal), CuaEvidence::NotDispatched);
        refusal.structured_content.as_mut().unwrap()["hint"] = Value::Bool(true);
        assert_eq!(write_evidence(&refusal), CuaEvidence::Unknown);
        refusal
            .structured_content
            .as_mut()
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove("hint");
        let mut failure = CallToolResult::structured(
            serde_json::json!({"schema":1,"outcome":"unknown","effect":"unverified","code":"native_write_unknown"}),
        );
        failure.is_error = Some(true);
        assert_eq!(write_evidence(&failure), CuaEvidence::Unknown);
        refusal.structured_content.as_mut().unwrap()["code"] =
            Value::String("arbitrary_failure".into());
        assert_eq!(write_evidence(&refusal), CuaEvidence::Unknown);
        let mut error_ack = ack;
        error_ack.is_error = Some(true);
        assert_eq!(write_evidence(&error_ack), CuaEvidence::Unknown);
    }
    #[test]
    fn official_strict_action_result_is_only_acknowledged_without_effect_proof() {
        let reply = serde_json::json!({
            "route":"accessibility","effect":"unverifiable","delivery":{"mode":"unknown"},
            "summary":"wording never decides execution","hint":"read the element",
            "next_call":{"tool":"get_window_state","arguments":{"pid":42,"window_id":7}}
        });
        assert_eq!(
            write_evidence(&CallToolResult::structured(reply.clone())),
            CuaEvidence::Acknowledged
        );
        for (key, replacement) in [
            ("effect", Value::String("confirmed".into())),
            ("route", Value::String("global_input".into())),
            ("summary", Value::Bool(true)),
            ("delivery", serde_json::json!({"mode":"foreground"})),
            ("unexpected", Value::Bool(true)),
        ] {
            let mut malformed = reply.clone();
            malformed[key] = replacement;
            assert_eq!(
                write_evidence(&CallToolResult::structured(malformed)),
                CuaEvidence::Unknown
            );
        }
        let mut error = CallToolResult::structured(reply);
        error.is_error = Some(true);
        assert_eq!(write_evidence(&error), CuaEvidence::Unknown);
    }
}

#[cfg(test)]
#[path = "ax_write_transport_tests.rs"]
mod transport_tests;
