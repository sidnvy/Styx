//! Real in-memory MCP adapter contracts, not native OS/GUI acceptance.
use super::{ACQUIRE, AxWriteGate, AxWriteRequest, WRITE, invoke};
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
    // Recorded only when the official server actually receives tools/call.
    calls: Vec<(String, Map<String, Value>)>,
    gates: usize,
    effects: usize,
    write_observed_gate: Option<usize>,
}
struct RpcFixture {
    trace: Arc<Mutex<Trace>>,
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
        let mut trace = self.trace.lock().expect("fixture trace");
        trace
            .calls
            .push((name.clone(), request.arguments.unwrap_or_default()));
        match name.as_str() {
            ACQUIRE => Ok(CallToolResponse::Complete(CallToolResult::structured(
                json!({
                    "schema":1,"pid":42,"window_id":7,"snapshot_id":"s00000001",
                    "element_index":2,"target":"ab".repeat(32)
                }),
            ))),
            WRITE => {
                // The side effect really happens in the receiving RPC fixture,
                // before the error is serialized. isError cannot prove no effect.
                trace.write_observed_gate = Some(trace.gates);
                trace.effects += 1;
                Ok(CallToolResponse::Complete(CallToolResult::error(vec![
                    ContentBlock::text("owned_fixture_post_effect_failure"),
                ])))
            }
            _ => Err(ErrorData::invalid_request("unexpected_fixture_tool", None)),
        }
    }
}

#[tokio::test]
async fn private_acquire_gate_refusal_and_post_effect_error_never_replay_write() {
    // Each branch has a fresh real SDK connection and independent RPC trace.
    for deny_gate in [true, false] {
        let trace = Arc::new(Mutex::new(Trace::default()));
        let fixture = RpcFixture {
            trace: trace.clone(),
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
        let result = invoke(
            &stop,
            &mut uncertain,
            client.peer(),
            request,
            Instant::now() + Duration::from_secs(5),
            gate,
        )
        .await;
        // Actual SDK tasks are closed/joined before assertions, including the
        // branch whose reply is an error after a real counted effect.
        let (client_closed, server_closed) = timeout(Duration::from_secs(5), async {
            tokio::join!(client.close(), server.close())
        })
        .await
        .expect("bounded actual SDK task joins");
        assert!(client_closed.is_ok());
        assert!(server_closed.is_ok());
        let trace = trace.lock().unwrap();
        assert_eq!(trace.gates, 1);
        assert_eq!(
            trace.calls[0],
            (
                ACQUIRE.into(),
                json!({
                    "pid":42,"window_id":7,"element_token":"s00000001:2"
                })
                .as_object()
                .unwrap()
                .clone()
            )
        );
        assert!(
            result.1.is_none(),
            "neither refusal nor failed write is an ACK"
        );
        if deny_gate {
            assert_eq!(result.0, CuaEvidence::NotDispatched);
            assert_eq!(result.2, Some(CuaError::PermissionDenied));
            assert_eq!(trace.calls.len(), 1);
            assert_eq!(trace.effects, 0);
            assert_eq!(trace.write_observed_gate, None);
        } else {
            assert_eq!(result.0, CuaEvidence::Unknown);
            assert_eq!(result.2, Some(CuaError::Unknown));
            assert_eq!(
                trace.calls,
                vec![
                    (
                        ACQUIRE.into(),
                        json!({"pid":42,"window_id":7,"element_token":"s00000001:2"})
                            .as_object()
                            .unwrap()
                            .clone()
                    ),
                    (
                        WRITE.into(),
                        json!({"target":"ab".repeat(32),"value":"owned-fixture-replacement"})
                            .as_object()
                            .unwrap()
                            .clone()
                    ),
                ]
            );
            assert_eq!(trace.effects, 1);
            assert_eq!(trace.write_observed_gate, Some(1));
        }
    }
}
