//! Real in-memory MCP adapter contracts, not native OS/GUI acceptance.
use super::{AxWriteGate, AxWriteRequest, invoke};
use crate::providers::cua::{CuaError, CuaEvidence};
use rmcp::{
    ErrorData, RoleServer, ServerHandler, ServiceExt,
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ServerCapabilities,
        ServerConfig,
    },
    service::RequestContext,
};
use serde_json::{Map, Value, json};
use std::sync::{Arc, Mutex};
use tokio::time::{Duration, Instant, timeout};
use tokio_util::sync::CancellationToken;

#[derive(Default)]
struct Trace {
    calls: Vec<(String, Map<String, Value>)>,
    gates: usize,
    effects: usize,
    write_observed_gate: Option<usize>,
}
#[derive(Clone, Copy)]
enum Reply {
    Ack,
    ForegroundAck,
    ReadbackAck,
    Refused(&'static str, CuaError, &'static str),
    PostEffectError,
    Late,
}
struct RpcFixture {
    trace: Arc<Mutex<Trace>>,
    reply: Reply,
}
impl ServerHandler for RpcFixture {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let name = request.name.to_string();
        {
            let mut trace = self.trace.lock().expect("fixture trace");
            trace
                .calls
                .push((name.clone(), request.arguments.unwrap_or_default()));
            if name == "list_windows" {
                return Ok(CallToolResponse::Complete(CallToolResult::structured(
                    json!({"windows":[]}),
                )));
            }
            if name != "set_value" {
                return Err(ErrorData::invalid_request("unexpected_fixture_tool", None));
            }
            trace.write_observed_gate = Some(trace.gates);
            if !matches!(self.reply, Reply::Refused(..)) {
                trace.effects += 1;
            }
        }
        if matches!(self.reply, Reply::Late) {
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        let result = match self.reply {
            Reply::Ack | Reply::Late => CallToolResult::structured(
                json!({"route":"accessibility","effect":"unverifiable","delivery":{"mode":"unknown"},"summary":"official action result fixture"}),
            ),
            Reply::ForegroundAck => CallToolResult::structured(json!({
                "route":"global_input", "effect":"unverifiable",
                "delivery":{"mode":"foreground"}, "summary":"native foreground result"
            })),
            Reply::ReadbackAck => CallToolResult::structured(json!({
                "route":"accessibility", "effect":"confirmed",
                "delivery":{"mode":"background"},
                "evidence":[{"kind":"value_readback","detail":"owned fixture readback"}]
            })),
            Reply::Refused(code, _, _) => {
                let mut value = CallToolResult::structured(
                    json!({"schema":1,"outcome":"refused","effect":"unverified","code":code,"hint":"official read-again hint","next_call":{"tool":"get_window_state","arguments":{"pid":42,"window_id":7}}}),
                );
                value.is_error = Some(true);
                value
            }
            Reply::PostEffectError => CallToolResult::error(vec![ContentBlock::text(
                "owned_fixture_post_effect_failure",
            )]),
        };
        Ok(CallToolResponse::Complete(result))
    }
}

#[tokio::test]
async fn set_value_runs_gate_before_one_platform_call_and_never_replays() {
    for (deny_gate, reply) in [
        (true, Reply::Ack),
        (false, Reply::Ack),
        (false, Reply::ForegroundAck),
        (false, Reply::ReadbackAck),
        (
            false,
            Reply::Refused(
                "editable_unavailable",
                CuaError::Unsupported,
                "CAPABILITY_UNSUPPORTED",
            ),
        ),
        (
            false,
            Reply::Refused(
                "strict_text_unavailable",
                CuaError::Unsupported,
                "CAPABILITY_UNSUPPORTED",
            ),
        ),
        (
            false,
            Reply::Refused(
                "stale_observation",
                CuaError::StaleObservation,
                "STALE_OBSERVATION",
            ),
        ),
        (
            false,
            Reply::Refused(
                "window_unavailable",
                CuaError::StaleObservation,
                "STALE_OBSERVATION",
            ),
        ),
        (
            false,
            Reply::Refused(
                "process_unavailable",
                CuaError::StaleObservation,
                "STALE_OBSERVATION",
            ),
        ),
        (
            false,
            Reply::Refused(
                "invalid_request",
                CuaError::InvalidRequest,
                "INVALID_REQUEST",
            ),
        ),
        (
            false,
            Reply::Refused(
                "permission_denied",
                CuaError::PermissionDenied,
                "PERMISSION_DENIED",
            ),
        ),
        (false, Reply::PostEffectError),
        (false, Reply::Late),
    ] {
        let trace = Arc::new(Mutex::new(Trace::default()));
        let fixture = RpcFixture {
            trace: trace.clone(),
            reply,
        };
        let (server_io, client_io) = tokio::io::duplex(65536);
        let (server, client) = timeout(Duration::from_secs(5), async {
            tokio::join!(fixture.serve(server_io), ().serve(client_io))
        })
        .await
        .expect("bounded SDK handshake");
        let mut server = server.expect("real MCP fixture server");
        let mut client = client.expect("real MCP fixture client");
        let gate_trace = trace.clone();
        let gate: AxWriteGate = Box::new(move || {
            Box::pin(async move {
                gate_trace.lock().expect("fixture gate trace").gates += 1;
                if deny_gate {
                    Err(CuaError::PermissionDenied)
                } else {
                    Ok(())
                }
            })
        });
        let request = AxWriteRequest {
            pid: 42,
            window_id: 7,
            element_token: "s00000001:2".into(),
            value: "owned-fixture-replacement".into(),
        };
        let stop = CancellationToken::new();
        let mut uncertain = false;
        let budget = if matches!(reply, Reply::Late) {
            Duration::from_millis(50)
        } else {
            Duration::from_secs(5)
        };
        let result = invoke(
            &stop,
            &mut uncertain,
            client.peer(),
            request,
            Some(Instant::now() + budget),
            gate,
            None,
        )
        .await;
        if matches!(reply, Reply::PostEffectError) && !deny_gate {
            // The first operation remains Unknown. A new correlated read uses
            // the SAME connection, with no replay of the write.
            assert!(!uncertain);
            assert!(!stop.is_cancelled());
            let read = client
                .peer()
                .call_tool_once(CallToolRequestParams::new("list_windows"))
                .await
                .unwrap();
            assert!(matches!(read, CallToolResponse::Complete(_)));
            let trace = trace.lock().unwrap();
            assert_eq!(
                trace
                    .calls
                    .iter()
                    .filter(|(name, _)| name == "set_value")
                    .count(),
                1
            );
            assert_eq!(
                trace
                    .calls
                    .iter()
                    .filter(|(name, _)| name == "list_windows")
                    .count(),
                1
            );
            assert_eq!(result.0, CuaEvidence::Unknown);
        }
        let (client_closed, server_closed) = timeout(Duration::from_secs(5), async {
            tokio::join!(client.close(), server.close())
        })
        .await
        .expect("bounded actual SDK task joins");
        assert!(client_closed.is_ok());
        assert!(server_closed.is_ok());
        let trace = trace.lock().unwrap();
        assert_eq!(trace.gates, 1);
        if deny_gate {
            assert_eq!(result.0, CuaEvidence::NotDispatched);
            assert_eq!(result.2, Some(CuaError::PermissionDenied));
            assert!(trace.calls.is_empty());
            assert_eq!(trace.effects, 0);
            assert_eq!(trace.write_observed_gate, None);
            assert!(!uncertain);
            continue;
        }
        let mut expected_args = json!({
            "pid":42,"window_id":7,"element_token":"s00000001:2",
            "value":"owned-fixture-replacement"
        })
        .as_object()
        .unwrap()
        .clone();
        if cfg!(target_os = "linux") {
            expected_args.insert("delivery_mode".into(), json!("foreground"));
        } else {
            expected_args.insert("styx_strict_text".into(), json!(true));
        }
        assert_eq!(
            trace
                .calls
                .iter()
                .filter(|(name, _)| name == "set_value")
                .cloned()
                .collect::<Vec<_>>(),
            vec![("set_value".into(), expected_args)]
        );
        assert_eq!(trace.write_observed_gate, Some(1));
        match reply {
            Reply::Ack => {
                assert_eq!(result.0, CuaEvidence::Acknowledged);
                assert!(result.1.is_some());
                if cfg!(target_os = "linux") {
                    let native = result
                        .1
                        .as_ref()
                        .unwrap()
                        .structured_content
                        .as_ref()
                        .unwrap();
                    assert_eq!(native["route"], "accessibility");
                    assert_eq!(native["summary"], "official action result fixture");
                }
                assert!(!uncertain);
                assert_eq!(trace.effects, 1);
            }
            Reply::ForegroundAck | Reply::ReadbackAck => {
                assert_eq!(
                    result.0,
                    if cfg!(target_os = "linux") {
                        CuaEvidence::Acknowledged
                    } else {
                        CuaEvidence::Unknown
                    }
                );
                let native = result
                    .1
                    .as_ref()
                    .unwrap()
                    .structured_content
                    .as_ref()
                    .unwrap();
                if matches!(reply, Reply::ForegroundAck) {
                    assert_eq!(native["route"], "global_input");
                    assert_eq!(native["effect"], "unverifiable");
                    assert_eq!(native["delivery"]["mode"], "foreground");
                } else {
                    assert_eq!(native["effect"], "confirmed");
                    assert_eq!(native["evidence"][0]["detail"], "owned fixture readback");
                }
                assert!(!uncertain);
                assert_eq!(trace.effects, 1);
            }
            Reply::Refused(..) if cfg!(target_os = "linux") => {
                // Linux no longer interprets the private strict-setter envelope.
                // The shared native handler preserves this complete error as Unknown.
                assert_eq!(result.0, CuaEvidence::Unknown);
                assert_eq!(result.2, Some(CuaError::Unknown));
                assert_eq!(result.1.as_ref().unwrap().is_error, Some(true));
                assert!(!uncertain);
                assert_eq!(trace.effects, 0);
            }
            Reply::Refused(code, cause, category) => {
                assert_eq!(result.0, CuaEvidence::NotDispatched);
                assert_eq!(result.2, Some(cause));
                let refusal = result.1.as_ref().expect("typed native refusal");
                assert_eq!(refusal.is_error, Some(true));
                assert_eq!(
                    refusal.structured_content.as_ref().unwrap(),
                    &json!({
                        "category":category,"error":code,"native_reason":code,
                        "execution_certainty":"not_dispatched","input_authorized":false,
                        "uncertain":false
                    })
                );
                assert!(!uncertain);
                assert!(!stop.is_cancelled());
                assert_eq!(trace.effects, 0);
            }
            Reply::PostEffectError => {
                assert_eq!(result.0, CuaEvidence::Unknown);
                assert!(result.1.is_some());
                assert!(!uncertain);
                assert!(!stop.is_cancelled());
                assert_eq!(trace.effects, 1);
            }
            Reply::Late => {
                assert_eq!(result.0, CuaEvidence::Unknown);
                assert!(result.1.is_none());
                assert!(uncertain);
                assert!(stop.is_cancelled());
                assert_eq!(trace.effects, 1);
            }
        }
    }
}

#[tokio::test]
async fn strict_write_expired_or_cancelled_before_gate_sends_no_request() {
    for cancelled in [false, true] {
        let trace = Arc::new(Mutex::new(Trace::default()));
        let fixture = RpcFixture {
            trace: trace.clone(),
            reply: Reply::Ack,
        };
        let (server_io, client_io) = tokio::io::duplex(65536);
        let (server, client) = tokio::join!(fixture.serve(server_io), ().serve(client_io));
        let mut server = server.unwrap();
        let mut client = client.unwrap();
        let stop = CancellationToken::new();
        if cancelled {
            stop.cancel();
        }
        let gate: AxWriteGate =
            Box::new(|| Box::pin(async { panic!("pre-expired gate must not run") }));
        let request = AxWriteRequest {
            pid: 42,
            window_id: 7,
            element_token: "s00000001:2".into(),
            value: "never sent".into(),
        };
        let until = if cancelled {
            Instant::now() + Duration::from_secs(5)
        } else {
            Instant::now()
        };
        let mut uncertain = false;
        let result = invoke(
            &stop,
            &mut uncertain,
            client.peer(),
            request,
            Some(until),
            gate,
            None,
        )
        .await;
        let (a, b) = tokio::join!(client.close(), server.close());
        assert!(a.is_ok() && b.is_ok());
        assert_eq!(result.0, CuaEvidence::NotDispatched);
        assert!(!uncertain);
        assert!(trace.lock().unwrap().calls.is_empty());
    }
}
