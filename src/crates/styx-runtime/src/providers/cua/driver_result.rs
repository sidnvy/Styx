//! Only fixed structured pre-dispatch refusals prove that no input was sent.
use super::*;

pub(super) fn outcome(
    value: CallToolResult,
) -> (CuaEvidence, Option<CallToolResult>, Option<CuaError>) {
    if bounded_bytes(&value, FRAME_BYTES).is_err() {
        return (CuaEvidence::Unknown, None, Some(CuaError::Unknown));
    }
    if std::env::var_os("STYX_CUA_DIAGNOSTICS").as_deref() == Some(std::ffi::OsStr::new("1")) {
        use std::io::Write as _;
        let _ = writeln!(
            std::io::stderr().lock(),
            "{}",
            serde_json::json!({
                "event":"styx_cua_native_action_reply", "is_error":value.is_error,
                "structured":value.structured_content.is_some(),
                "native_code":value.structured_content.as_ref().and_then(|v|v.get("code")).and_then(Value::as_str).filter(|s|s.len()<=64 && s.bytes().all(|b|b.is_ascii_lowercase()||b==b'_'||b.is_ascii_digit())),
                "effect_unknown":value.structured_content.as_ref().and_then(|v| v.get("effect")).and_then(Value::as_str)==Some("unknown")
            })
        );
    }
    let data = value.structured_content.as_ref();
    let effect = data.and_then(|v| v.get("effect")).and_then(Value::as_str);
    if effect == Some("unknown") {
        return (CuaEvidence::Unknown, Some(value), Some(CuaError::Unknown));
    }
    if value.is_error == Some(true) {
        let direct = data.and_then(|v| v.get("code")).and_then(Value::as_str);
        let refusal = data
            .and_then(|v| v.get("refusal"))
            .and_then(|v| v.get("code"))
            .and_then(Value::as_str);
        // SnapshotStore's structured refusal is issued before resolving an
        // action. Other native code must explicitly report effect:none.
        // The pinned bridge issues this exact refusal before pointer dispatch
        // when the retained element has no usable native geometry. Do not infer
        // no-input from arbitrary text or from other effect:refused errors.
        let geometry_refusal = data.is_some_and(|d| {
            d.as_object().is_some_and(|d| d.len() == 4)
                && d.get("refusal")
                    .and_then(Value::as_object)
                    .is_some_and(|r| r.len() == 2 && r.get("message").is_some_and(Value::is_string))
                && d.get("status").and_then(Value::as_str) == Some("refused")
                && effect == Some("refused")
                && direct == Some("element_not_visible")
                && refusal == Some("element_not_visible")
        });
        let before_dispatch = geometry_refusal
            || effect == Some("none")
            || (effect.is_none()
                && matches!(
                    refusal,
                    Some(
                        "invalid_element_token"
                            | "stale_element_token"
                            | "element_outside_target_window"
                    )
                ));
        let cause = match direct.or(refusal) {
            Some("invalid_element_token" | "bad_element_token" | "input_invalid_args") => {
                Some(CuaError::InvalidRequest)
            }
            Some(
                "stale_element_token"
                | "input_stale_observation"
                | "stale_snapshot"
                | "element_outside_target_window"
                | "window_not_found"
                | "window_gone"
                | "element_not_visible",
            ) => Some(CuaError::StaleObservation),
            Some("permission_denied" | "permission_required") => Some(CuaError::PermissionDenied),
            Some("keyboard_unavailable" | "foreground_unavailable") => Some(CuaError::Unsupported),
            _ => None,
        };
        if let Some(cause) = cause.filter(|_| before_dispatch) {
            return (CuaEvidence::NotDispatched, Some(value), Some(cause));
        }
        return (CuaEvidence::Unknown, Some(value), Some(CuaError::Unknown));
    }
    (CuaEvidence::Acknowledged, Some(value), None)
}
pub(super) async fn invoke(
    peer: &rmcp::Peer<RoleClient>,
    params: CallToolRequestParams,
    stop: &CancellationToken,
    until: Option<Instant>,
) -> (CuaEvidence, Option<CallToolResult>, Option<CuaError>) {
    // One poll of one driver call. Unknown is terminal; there is no retry.
    let response = tokio::select! {
        _ = stop.cancelled() => None,
        result = within(until, peer.call_tool_once(params)) => Some(result),
    };
    match response {
        Some(Ok(Ok(CallToolResponse::Complete(value)))) => outcome(value),
        _ => (CuaEvidence::Unknown, None, Some(CuaError::Unknown)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn typed_input_refusals_require_explicit_no_dispatch() {
        for (code, cause) in [
            ("keyboard_unavailable", CuaError::Unsupported),
            ("foreground_unavailable", CuaError::Unsupported),
            ("input_invalid_args", CuaError::InvalidRequest),
            ("input_stale_observation", CuaError::StaleObservation),
        ] {
            let mut reply =
                CallToolResult::structured(serde_json::json!({"code":code,"effect":"none"}));
            reply.is_error = Some(true);
            let result = outcome(reply.clone());
            assert_eq!(result.0, CuaEvidence::NotDispatched, "{code}");
            assert_eq!(result.2, Some(cause), "{code}");
            for effect in ["unknown", "refused"] {
                reply.structured_content.as_mut().unwrap()["effect"] = Value::String(effect.into());
                assert_eq!(
                    outcome(reply.clone()).0,
                    CuaEvidence::Unknown,
                    "{code}/{effect}"
                );
            }
            reply
                .structured_content
                .as_mut()
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove("effect");
            assert_eq!(outcome(reply).0, CuaEvidence::Unknown, "{code}/missing");
        }
    }
    #[tokio::test]
    async fn complete_unknown_click_does_not_prevent_independent_read_on_same_transport() {
        let driver = super::super::fake_driver::FakeDriver::start(
            serde_json::json!({}),
            CallToolResult::structured(serde_json::json!({"effect":"unknown"})),
        )
        .await;
        let click = CuaAction {
            name: "click".into(),
            arguments: serde_json::Map::new(),
        };
        let original = driver.call(&click).await;
        assert_eq!(original.0, CuaEvidence::Unknown);
        assert!(original.1.is_some()); // complete response, not a dirty transport
        let read = CuaAction {
            name: "list_windows".into(),
            arguments: serde_json::Map::new(),
        };
        let fresh = driver.call(&read).await;
        assert!(fresh.1.is_some());
        let calls = driver.calls.lock().unwrap().clone();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0]["name"], "click");
        assert_eq!(calls[1]["name"], "list_windows");
        assert_eq!(original.0, CuaEvidence::Unknown);
        driver.close().await;
    }
    fn error(value: Value) -> CallToolResult {
        let mut result = CallToolResult::structured(value);
        result.is_error = Some(true);
        result
    }
    #[tokio::test]
    async fn cua_driver_refusals_are_typed_but_post_dispatch_errors_are_unknown() {
        let action = CuaAction::new(
            "click".into(),
            serde_json::json!({"pid":42,"window_id":123,"element_token":"s00000001:0"})
                .as_object()
                .unwrap()
                .clone(),
        )
        .unwrap();
        for (data, expected, certainty) in [
            (
                serde_json::json!({"refusal":{"code":"invalid_element_token"}}),
                CuaError::InvalidRequest,
                CuaEvidence::NotDispatched,
            ),
            (
                serde_json::json!({"refusal":{"code":"stale_element_token"}}),
                CuaError::StaleObservation,
                CuaEvidence::NotDispatched,
            ),
            (
                serde_json::json!({"code":"window_gone","effect":"none"}),
                CuaError::StaleObservation,
                CuaEvidence::NotDispatched,
            ),
            (
                serde_json::json!({"code":"permission_denied","effect":"none"}),
                CuaError::PermissionDenied,
                CuaEvidence::NotDispatched,
            ),
            (
                serde_json::json!({"code":"stale_element_token","effect":"unknown"}),
                CuaError::Unknown,
                CuaEvidence::Unknown,
            ),
            (
                serde_json::json!({"code":"permission_denied"}),
                CuaError::Unknown,
                CuaEvidence::Unknown,
            ),
            (
                serde_json::json!({"status":"refused","code":"element_not_visible","effect":"refused","refusal":{"code":"element_not_visible","message":"native geometry unavailable"}}),
                CuaError::StaleObservation,
                CuaEvidence::NotDispatched,
            ),
            (
                serde_json::json!({"code":"element_not_visible","effect":"unknown"}),
                CuaError::Unknown,
                CuaEvidence::Unknown,
            ),
            (
                serde_json::json!({"status":"refused","code":"element_not_visible","effect":"refused","refusal":{"code":"element_not_visible","message":"native geometry unavailable"},"execution_state":"unknown"}),
                CuaError::Unknown,
                CuaEvidence::Unknown,
            ),
            (
                serde_json::json!({"code":"element_not_visible","effect":"refused"}),
                CuaError::Unknown,
                CuaEvidence::Unknown,
            ),
            (
                serde_json::json!({"code":"ax_timeout","effect":"unknown"}),
                CuaError::Unknown,
                CuaEvidence::Unknown,
            ),
        ] {
            let driver = fake_driver::FakeDriver::start(Value::Null, error(data.clone())).await;
            let (evidence, result, cause) = driver.call(&action).await;
            assert_eq!(evidence, certainty);
            assert_eq!(cause, Some(expected));
            assert_eq!(result.unwrap().structured_content, Some(data));
            assert_eq!(driver.calls.lock().unwrap().len(), 1);
            driver.close().await;
        }
    }
}
