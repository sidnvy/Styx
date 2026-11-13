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
    Refused,
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
            if name != "set_value" {
                return Err(ErrorData::invalid_request("unexpected_fixture_tool", None));
            }
            trace.write_observed_gate = Some(trace.gates);
            if !matches!(self.reply, Reply::Refused) {
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
            Reply::Refused => {
                let mut value = CallToolResult::structured(
                    json!({"schema":1,"outcome":"refused","effect":"unverified","code":"stale_observation","hint":"official read-again hint","next_call":{"tool":"get_window_state","arguments":{"pid":42,"window_id":7}}}),
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
async fn standard_set_value_runs_gate_before_one_strict_call_and_never_replays() {
    for (deny_gate, reply) in [
        (true, Reply::Ack),
        (false, Reply::Ack),
        (false, Reply::Refused),
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
            Instant::now() + budget,
            gate,
            None,
        )
        .await;
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
        assert_eq!(trace.calls,vec![("set_value".into(),json!({"pid":42,"window_id":7,"element_token":"s00000001:2","value":"owned-fixture-replacement","styx_strict_text":true}).as_object().unwrap().clone())]);
        assert_eq!(trace.write_observed_gate, Some(1));
        match reply {
            Reply::Ack => {
                assert_eq!(result.0, CuaEvidence::Acknowledged);
                assert!(result.1.is_some());
                assert!(!uncertain);
                assert_eq!(trace.effects, 1);
            }
            Reply::Refused => {
                assert_eq!(result.0, CuaEvidence::NotDispatched);
                assert!(result.1.is_none());
                assert!(!uncertain);
                assert_eq!(trace.effects, 0);
            }
            Reply::PostEffectError | Reply::Late => {
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
            until,
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
