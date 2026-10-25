//! Narrow owned-child EditableText adapter. This is not a second permission or
//! operation authority. Only Core's dedicated observed write-attempt permits
//! can reach these two private native tools; standard set_value is never called.
use super::*;

/// Created only by the original Host coordinator, not deserializable tool input.
pub(crate) type AxWriteGate = Box<
    dyn FnOnce() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>> + Send,
>;

pub(super) const ACQUIRE: &str = "styx_private_ax_acquire_editable_v1";
pub(super) const WRITE: &str = "styx_private_ax_set_text_once_v1";

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
fn validate_token(token: &str) -> Result<()> {
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

pub(super) fn private_name(name: &str) -> bool {
    matches!(name, ACQUIRE | WRITE)
}

/// Exact private schema comparison is additional to the original 64-tool
/// catalog. This does not add either name to Styx's public tool catalog.
pub(super) fn private_schemas() -> Map<String, Value> {
    let mut schemas = Map::new();
    schemas.insert(ACQUIRE.into(), serde_json::json!({
        "type":"object","required":["pid","window_id","element_token"],
        "properties":{"pid":{"type":"integer","minimum":1,"maximum":4294967295u64},
        "window_id":{"type":"integer","minimum":1},"element_token":{"type":"string","maxLength":64}},
        "additionalProperties":false
    }));
    schemas.insert(
        WRITE.into(),
        serde_json::json!({
            "type":"object","required":["editable_target","value"],"properties":{
            "editable_target":{"type":"string","minLength":64,"maxLength":64},
            "value":{"type":"string","maxLength":16384}},"additionalProperties":false
        }),
    );
    // Fixed Cua's advertised_runtime_input_schema adds this field to every
    // closed native schema. It is catalog compatibility, never a remote owner.
    let session = serde_json::json!({"type":"string","description":"For multi-call work, prefer a short public session label and repeat it on every call that accepts it. Omit it to use the authenticated transport's implicit lifecycle session."});
    for schema in schemas.values_mut() {
        schema["properties"]
            .as_object_mut()
            .expect("literal object")
            .insert("session".into(), session.clone());
    }
    schemas
}

fn acquired_target(value: &CallToolResult, request: &AxWriteRequest) -> Result<String> {
    if value.is_error == Some(true) || bounded_bytes(value, FRAME_BYTES).is_err() {
        return Err(CuaError::Unsupported);
    }
    let data = value
        .structured_content
        .as_ref()
        .and_then(Value::as_object)
        .ok_or(CuaError::ProtocolMismatch)?;
    let (snapshot, row) = request
        .element_token
        .split_once(':')
        .ok_or(CuaError::InvalidRequest)?;
    if data.len() != 6
        || data.get("schema").and_then(Value::as_u64) != Some(1)
        || data.get("pid").and_then(Value::as_u64) != Some(u64::from(request.pid))
        || data.get("window_id").and_then(Value::as_u64) != Some(request.window_id)
        || data.get("snapshot_id").and_then(Value::as_str) != Some(snapshot)
        || data.get("element_index").and_then(Value::as_u64) != row.parse().ok()
    {
        return Err(CuaError::ProtocolMismatch);
    }
    let target = data
        .get("target")
        .and_then(Value::as_str)
        .filter(|t| {
            t.len() == 64
                && t.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        .ok_or(CuaError::ProtocolMismatch)?;
    Ok(target.into())
}
fn pre_send_code(code: &str) -> bool {
    matches!(
        code,
        "transport_required"
            | "lifecycle_unavailable"
            | "invalid_request"
            | "target_cache_unavailable"
            | "target_cache_exhausted"
            | "stale_observation"
            | "value_too_large"
            | "target_expired"
            | "bus_unavailable"
            | "process_unavailable"
            | "unproven_object_owner"
            | "object_owner_gone"
            | "target_identity_changed"
            | "window_unavailable"
            | "window_changed"
            | "frame_unavailable"
            | "frame_window_mismatch"
            | "object_frame_mismatch"
            | "object_unavailable"
            | "object_defunct"
            | "editable_unavailable"
            | "validation_timeout"
            | "target_invalidated"
    )
}
fn write_evidence(value: &CallToolResult) -> CuaEvidence {
    if bounded_bytes(value, FRAME_BYTES).is_err() {
        return CuaEvidence::Unknown;
    }
    let Some(data) = value.structured_content.as_ref().and_then(Value::as_object) else {
        return CuaEvidence::Unknown;
    };
    if value.is_error == Some(true) {
        if data.len() == 4
            && data.get("schema").and_then(Value::as_u64) == Some(1)
            && data.get("execution_certainty").and_then(Value::as_str) == Some("not_dispatched")
            && data.get("uncertain").and_then(Value::as_bool) == Some(false)
            && data
                .get("code")
                .and_then(Value::as_str)
                .is_some_and(pre_send_code)
        {
            return CuaEvidence::NotDispatched;
        }
        return CuaEvidence::Unknown;
    }
    if data.len() == 4
        && data.get("schema").and_then(Value::as_u64) == Some(1)
        && data.get("target_consumed").and_then(Value::as_bool) == Some(true)
        && data.get("outcome").and_then(Value::as_str) == Some("acknowledged")
        && data.get("effect").and_then(Value::as_str) == Some("unverified")
    {
        CuaEvidence::Acknowledged
    } else {
        CuaEvidence::Unknown
    }
}

pub(super) async fn invoke(
    stop: &CancellationToken,
    uncertain: &mut bool,
    peer: &rmcp::service::Peer<RoleClient>,
    request: AxWriteRequest,
    until: Instant,
    gate: AxWriteGate,
) -> (CuaEvidence, Option<CallToolResult>, Option<CuaError>) {
    let acquire = CallToolRequestParams::new(ACQUIRE).with_arguments(
        serde_json::json!({
            "pid":request.pid,"window_id":request.window_id,"element_token":request.element_token
        })
        .as_object()
        .expect("literal object")
        .clone(),
    );
    let response = tokio::select! {
        _=stop.cancelled()=>None,
        v=timeout_at(until,peer.call_tool_once(acquire))=>Some(v)
    };
    let target = match response {
        Some(Ok(Ok(CallToolResponse::Complete(value)))) => {
            match acquired_target(&value, &request) {
                Ok(target) => target,
                Err(cause) => return (CuaEvidence::NotDispatched, None, Some(cause)),
            }
        }
        _ => {
            // Only read acquisition was polled. Input is not dispatched, but
            // native I/O/lifecycle may remain live and must stay fenced/owned.
            *uncertain = true;
            stop.cancel();
            return (CuaEvidence::NotDispatched, None, Some(CuaError::Unknown));
        }
    };
    if stop.is_cancelled() || Instant::now() >= until {
        return (CuaEvidence::NotDispatched, None, Some(CuaError::Unknown));
    }
    let authorized = tokio::select! {
        _=stop.cancelled()=>None,
        result=timeout_at(until,gate())=>Some(result)
    };
    match authorized {
        Some(Ok(Ok(()))) if !stop.is_cancelled() && Instant::now() < until => {}
        Some(Ok(Err(cause))) => return (CuaEvidence::NotDispatched, None, Some(cause)),
        _ => return (CuaEvidence::NotDispatched, None, Some(CuaError::Unknown)),
    }
    // Cua reserves `target` for its public typed desktop selector. This private
    // handle must pass through the same dispatcher without entering that path.
    let write = CallToolRequestParams::new(WRITE).with_arguments(
        serde_json::json!({
            "editable_target":target,"value":request.value
        })
        .as_object()
        .expect("literal object")
        .clone(),
    );
    // The only side-effecting send. Never retry after first poll, even if the
    // remote error says failure or cancellation was requested locally.
    let response = tokio::select! {
        _=stop.cancelled()=>None,
        v=timeout_at(until,peer.call_tool_once(write))=>Some(v)
    };
    match response {
        Some(Ok(Ok(CallToolResponse::Complete(value)))) => match write_evidence(&value) {
            CuaEvidence::Acknowledged => (
                CuaEvidence::Acknowledged,
                Some(CallToolResult::structured(serde_json::json!({
                    "schema":1,"target_consumed":true,"outcome":"acknowledged","effect":"unverified"
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn extended_catalog_is_exact_and_old_catalog_never_enables_private_input() {
        let old: Map<String, Value> =
            serde_json::from_str(selected_native_catalog().unwrap().schemas_json).unwrap();
        let tools = |schemas: Map<String, Value>| {
            schemas
                .into_iter()
                .map(|(name, input)| {
                    serde_json::from_value::<rmcp::model::Tool>(
                        serde_json::json!({"name":name,"inputSchema":input}),
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>()
        };
        assert!(!validate_catalog(&tools(old.clone())).unwrap());
        let mut extended = old.clone();
        extended.extend(private_schemas());
        assert!(validate_catalog(&tools(extended.clone())).unwrap());
        extended.get_mut(WRITE).unwrap()["properties"]
            .as_object_mut()
            .unwrap()
            .remove("session");
        assert_eq!(
            validate_catalog(&tools(extended)),
            Err(CuaError::Unsupported)
        );
    }
    #[test]
    fn private_write_accepts_only_explicit_full_target_and_never_error_as_ack() {
        let args =
            serde_json::json!({"pid":42,"window_id":7,"element_token":"s00000001:2","value":""});
        let action = CuaAction::new("set_value".into(), args.as_object().unwrap().clone()).unwrap();
        assert!(action.accessibility_write_request().unwrap().is_some());
        for (key, value) in [
            ("delivery_mode", Value::String("foreground".into())),
            ("session", Value::String("foreign".into())),
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
        let ack = CallToolResult::structured(
            serde_json::json!({"schema":1,"target_consumed":true,"outcome":"acknowledged","effect":"unverified"}),
        );
        assert_eq!(write_evidence(&ack), CuaEvidence::Acknowledged);
        let failure = CallToolResult::structured(
            serde_json::json!({"schema":1,"code":"native_write_unknown","execution_certainty":"unknown","uncertain":true}),
        );
        assert_eq!(write_evidence(&failure), CuaEvidence::Unknown);
        let mut not_sent =
            CallToolResult::error(vec![rmcp::model::ContentBlock::text("stale_observation")]);
        not_sent.structured_content = Some(
            serde_json::json!({"schema":1,"code":"stale_observation","execution_certainty":"not_dispatched","uncertain":false}),
        );
        assert_eq!(write_evidence(&not_sent), CuaEvidence::NotDispatched);
    }
}

#[cfg(test)]
#[path = "ax_write_transport_tests.rs"]
mod transport_tests;
