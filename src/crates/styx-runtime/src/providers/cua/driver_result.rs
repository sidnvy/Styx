//! Only fixed structured pre-dispatch refusals prove that no input was sent.
use super::*;

/// Constructed only from a validated private read and its Core operation purpose.
/// This is local call context, never a field accepted from the native reply.
pub(super) struct AxReadReplyContext(());
impl AxReadReplyContext {
    pub(super) fn for_action(action: &CuaAction, purpose: OperationPurpose) -> Option<Self> {
        (purpose == OperationPurpose::DesktopAccessibilityReadAcquisition
            && matches!(
                action.desktop_read_request(),
                Ok(Some(DesktopReadRequest::Accessibility(_)))
            ))
        .then_some(Self(()))
    }
}

fn incomplete_ax_read(value: &CallToolResult) -> Option<CuaError> {
    if value.is_error != Some(true) || value.meta.is_some() || value.content.len() != 1 {
        return None;
    }
    let data = value.structured_content.as_ref()?.as_object()?;
    if data.len() != 6
        || data.get("schema").and_then(Value::as_u64) != Some(1)
        || data.get("execution_certainty").and_then(Value::as_str) != Some("not_dispatched")
        || data.get("uncertain") != Some(&Value::Bool(false))
        || data.get("elements_complete") != Some(&Value::Bool(false))
        || data.get("degraded") != Some(&Value::Bool(true))
    {
        return None;
    }
    let code = data.get("code")?.as_str()?;
    let text = value.content[0].as_text()?;
    if text.text != code || text.meta.is_some() || text.annotations.is_some() {
        return None;
    }
    // Closed errors emitted by the pinned private complete-snapshot read. A
    // timeout (including validation_timeout), unknown code or partial reply is
    // deliberately not evidence of a completed, known refusal.
    Some(match code {
        "invalid_request" => CuaError::InvalidRequest,
        "editable_unavailable" => CuaError::PermissionDenied,
        "notification_unsupported" => CuaError::Unsupported,
        "window_unavailable"
        | "window_changed"
        | "process_unavailable"
        | "unproven_object_owner"
        | "object_unavailable"
        | "target_invalidated"
        | "target_expired"
        | "stale_observation"
        | "target_cache_unavailable"
        | "lifecycle_unavailable" => CuaError::StaleObservation,
        _ => return None,
    })
}

pub(super) fn outcome(
    value: CallToolResult,
) -> (CuaEvidence, Option<CallToolResult>, Option<CuaError>) {
    outcome_with_context(value, None)
}
fn outcome_with_context(
    value: CallToolResult,
    read: Option<&AxReadReplyContext>,
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
    // A malformed private incomplete reply cannot borrow the generic refusal
    // path. Replies without these private markers retain the existing rules.
    if read.is_some()
        && data.is_some_and(|data| {
            data.get("execution_certainty").is_some()
                || data.get("degraded").is_some()
                || data.get("elements_complete") == Some(&Value::Bool(false))
                || (value.is_error == Some(true) && data.get("elements_complete").is_some())
        })
    {
        if let Some(cause) = incomplete_ax_read(&value) {
            return (CuaEvidence::NotDispatched, Some(value), Some(cause));
        }
        return (CuaEvidence::Unknown, Some(value), Some(CuaError::Unknown));
    }
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
            Some("invalid_element_token" | "bad_element_token") => Some(CuaError::InvalidRequest),
            Some(
                "stale_element_token"
                | "stale_snapshot"
                | "element_outside_target_window"
                | "window_not_found"
                | "window_gone"
                | "element_not_visible",
            ) => Some(CuaError::StaleObservation),
            Some("permission_denied" | "permission_required") => Some(CuaError::PermissionDenied),
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
    until: Instant,
) -> (CuaEvidence, Option<CallToolResult>, Option<CuaError>) {
    invoke_with_context(peer, params, stop, until, None).await
}
pub(super) async fn invoke_ax_read(
    peer: &rmcp::Peer<RoleClient>,
    params: CallToolRequestParams,
    stop: &CancellationToken,
    until: Instant,
    read: AxReadReplyContext,
) -> (CuaEvidence, Option<CallToolResult>, Option<CuaError>) {
    invoke_with_context(peer, params, stop, until, Some(read)).await
}
async fn invoke_with_context(
    peer: &rmcp::Peer<RoleClient>,
    params: CallToolRequestParams,
    stop: &CancellationToken,
    until: Instant,
    read: Option<AxReadReplyContext>,
) -> (CuaEvidence, Option<CallToolResult>, Option<CuaError>) {
    // One poll of one driver call. Unknown is terminal; there is no retry.
    let response = tokio::select! {
        _ = stop.cancelled() => None,
        result = timeout_at(until, peer.call_tool_once(params)) => Some(result),
    };
    match response {
        Some(Ok(Ok(CallToolResponse::Complete(value)))) => match read.as_ref() {
            Some(read) => outcome_with_context(value, Some(read)),
            None => outcome(value),
        },
        _ => (CuaEvidence::Unknown, None, Some(CuaError::Unknown)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn error(value: Value) -> CallToolResult {
        let mut result = CallToolResult::structured(value);
        result.is_error = Some(true);
        result
    }
    fn private_read() -> CuaAction {
        CuaAction::new(
            "get_window_state".into(),
            serde_json::json!({
                "pid":42,"window_id":123,"include_screenshot":false,
                "include_accessibility_tree":true,"tree_format":"elements",
                "max_elements":256,"max_depth":20,"timeout_ms":1000
            })
            .as_object()
            .unwrap()
            .clone(),
        )
        .unwrap()
    }
    fn incomplete(code: &str) -> CallToolResult {
        let mut result = CallToolResult::error(vec![rmcp::model::ContentBlock::text(code)]);
        result.structured_content = Some(serde_json::json!({
            "schema":1,"code":code,"execution_certainty":"not_dispatched",
            "uncertain":false,"elements_complete":false,"degraded":true
        }));
        result
    }
    #[test]
    fn private_incomplete_read_requires_purpose_and_exact_native_refusal() {
        let action = private_read();
        let context = AxReadReplyContext::for_action(
            &action,
            OperationPurpose::DesktopAccessibilityReadAcquisition,
        )
        .unwrap();
        for (code, expected) in [
            ("window_unavailable", CuaError::StaleObservation),
            ("window_changed", CuaError::StaleObservation),
            ("process_unavailable", CuaError::StaleObservation),
            ("unproven_object_owner", CuaError::StaleObservation),
            ("object_unavailable", CuaError::StaleObservation),
            ("target_invalidated", CuaError::StaleObservation),
            ("target_expired", CuaError::StaleObservation),
            ("stale_observation", CuaError::StaleObservation),
            ("target_cache_unavailable", CuaError::StaleObservation),
            ("lifecycle_unavailable", CuaError::StaleObservation),
            ("invalid_request", CuaError::InvalidRequest),
            ("editable_unavailable", CuaError::PermissionDenied),
            ("notification_unsupported", CuaError::Unsupported),
        ] {
            let reply = incomplete(code);
            let (evidence, returned, cause) = outcome_with_context(reply.clone(), Some(&context));
            assert_eq!(evidence, CuaEvidence::NotDispatched, "{code}");
            assert_eq!(cause, Some(expected));
            assert_eq!(
                returned.unwrap().structured_content,
                reply.structured_content
            );
            // The identical reply has no new authority in the generic action path.
            assert_eq!(outcome(reply).0, CuaEvidence::Unknown, "{code}");
        }
        for purpose in [
            OperationPurpose::Execute,
            OperationPurpose::DesktopAccessibilityWriteAttempt,
            OperationPurpose::DesktopWindowCaptureReadAcquisition,
        ] {
            assert!(AxReadReplyContext::for_action(&action, purpose).is_none());
        }
        for (reply, expected) in [
            (
                error(serde_json::json!({"code":"permission_denied","effect":"none"})),
                CuaError::PermissionDenied,
            ),
            (
                error(serde_json::json!({"refusal":{"code":"stale_element_token"}})),
                CuaError::StaleObservation,
            ),
        ] {
            let (evidence, _, cause) = outcome_with_context(reply, Some(&context));
            assert_eq!(evidence, CuaEvidence::NotDispatched);
            assert_eq!(cause, Some(expected));
        }
        for action in [
            CuaAction::new(
                "click".into(),
                serde_json::json!({"pid":42,"window_id":123,"element_token":"s00000001:0"})
                    .as_object().unwrap().clone(),
            ).unwrap(),
            CuaAction::new(
                "set_value".into(),
                serde_json::json!({"pid":42,"window_id":123,"element_token":"s00000001:0","value":"x"})
                    .as_object().unwrap().clone(),
            ).unwrap(),
        ] {
            assert!(AxReadReplyContext::for_action(
                &action, OperationPurpose::DesktopAccessibilityReadAcquisition
            ).is_none());
        }

        let mut malformed = Vec::new();
        for field in [
            "schema",
            "code",
            "execution_certainty",
            "uncertain",
            "elements_complete",
            "degraded",
        ] {
            let mut reply = incomplete("window_unavailable");
            reply
                .structured_content
                .as_mut()
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(field);
            malformed.push(reply);
        }
        for (field, value) in [
            ("schema", serde_json::json!(2)),
            ("schema", serde_json::json!(1.0)),
            ("execution_certainty", serde_json::json!("unknown")),
            ("uncertain", serde_json::json!(true)),
            ("elements_complete", serde_json::json!(true)),
            ("degraded", serde_json::json!(false)),
            ("extra", serde_json::json!(true)),
            ("effect", serde_json::json!("none")),
        ] {
            let mut reply = incomplete("window_unavailable");
            reply.structured_content.as_mut().unwrap()[field] = value;
            malformed.push(reply);
        }
        for code in [
            "validation_timeout",
            "ax_timeout",
            "unrecognized_native_code",
        ] {
            malformed.push(incomplete(code));
        }
        let mut reply = incomplete("permission_denied");
        reply.structured_content.as_mut().unwrap()["effect"] = serde_json::json!("none");
        malformed.push(reply);
        let mut reply = incomplete("window_unavailable");
        reply.content.clear();
        malformed.push(reply);
        let mut reply = incomplete("window_unavailable");
        reply.content.push(rmcp::model::ContentBlock::text("extra"));
        malformed.push(reply);
        let mut reply = incomplete("window_unavailable");
        reply.content = vec![rmcp::model::ContentBlock::text("window_changed")];
        malformed.push(reply);
        let mut reply = incomplete("window_unavailable");
        reply.meta = Some(serde_json::from_value(serde_json::json!({"extra":true})).unwrap());
        malformed.push(reply);
        for is_error in [None, Some(false)] {
            let mut reply = incomplete("window_unavailable");
            reply.is_error = is_error;
            malformed.push(reply);
        }
        for reply in malformed {
            let (evidence, _, cause) = outcome_with_context(reply, Some(&context));
            assert_eq!(evidence, CuaEvidence::Unknown);
            assert_eq!(cause, Some(CuaError::Unknown));
        }
    }
    // Mac permission facts use the separate original native FD. This admitted
    // worker RPC is deliberately available only on Linux/Windows.
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[tokio::test]
    async fn private_read_refusal_settles_once_without_replacing_transport() {
        let action = private_read();
        let context = AxReadReplyContext::for_action(
            &action,
            OperationPurpose::DesktopAccessibilityReadAcquisition,
        )
        .unwrap();
        let driver = fake_driver::FakeDriver::start(
            serde_json::json!({"independent_read":"alive"}),
            incomplete("window_unavailable"),
        )
        .await;
        let (evidence, _, cause) = invoke_ax_read(
            &driver.peer,
            CallToolRequestParams::new(action.name).with_arguments(action.arguments),
            &CancellationToken::new(),
            Instant::now() + Duration::from_secs(2),
            context,
        )
        .await;
        assert_eq!(evidence, CuaEvidence::NotDispatched);
        assert_eq!(cause, Some(CuaError::StaleObservation));
        let (evidence, result, _) = invoke(
            &driver.peer,
            CallToolRequestParams::new("check_permissions").with_arguments(
                serde_json::json!({"prompt":false})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
            &CancellationToken::new(),
            Instant::now() + Duration::from_secs(2),
        )
        .await;
        assert_eq!(evidence, CuaEvidence::Acknowledged);
        assert_eq!(
            result.unwrap().structured_content.unwrap()["independent_read"],
            "alive"
        );
        let names = driver
            .calls
            .lock()
            .unwrap()
            .iter()
            .map(|call| call["name"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(names, ["get_window_state", "check_permissions"]);
        driver.close().await;
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
