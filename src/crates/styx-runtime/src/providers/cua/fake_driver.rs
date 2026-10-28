//! Hermetic driver replies over the production admitted transport and rmcp codec.
use super::*;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

pub(crate) struct FakeDriver {
    pub(crate) peer: rmcp::Peer<RoleClient>,
    pub(crate) calls: Arc<Mutex<Vec<Value>>>,
    client: RunningService<RoleClient, CuaClient>,
    job: JoinHandle<()>,
}
impl FakeDriver {
    pub(crate) async fn start(facts: Value, click_reply: CallToolResult) -> Self {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let seen = calls.clone();
        let (local, remote) = tokio::io::duplex(65536);
        let (read, mut write) = tokio::io::split(remote);
        let job = tokio::spawn(async move {
            let mut lines = tokio::io::BufReader::new(read).lines();
            while let Some(line) = lines.next_line().await.unwrap() {
                let request: Value = serde_json::from_str(&line).unwrap();
                let Some(id) = request.get("id") else {
                    continue;
                };
                let result = match request["method"].as_str().unwrap() {
                    "initialize" => {
                        serde_json::json!({"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"cua-driver","version":"0.36.0"}})
                    }
                    "tools/list" => serde_json::json!({"tools":[]}),
                    "tools/call" => {
                        seen.lock().unwrap().push(request["params"].clone());
                        serde_json::to_value(if request["params"]["name"] == "check_permissions" {
                            CallToolResult::structured(facts.clone())
                        } else {
                            click_reply.clone()
                        })
                        .unwrap()
                    }
                    _ => panic!("unexpected fake driver request"),
                };
                let response = serde_json::json!({"jsonrpc":"2.0","id":id,"result":result});
                if write
                    .write_all(format!("{response}\n").as_bytes())
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        let allocator = Arc::new(Semaphore::new(IO_BYTES));
        let budget = CuaIoBudget::from_reserved(
            allocator.acquire_many_owned(IO_BYTES as u32).await.unwrap(),
        )
        .unwrap();
        let (read, write) = tokio::io::split(local);
        let transport = transport::AdmittedTransport::from_io(
            read,
            write,
            CancellationToken::new(),
            budget.clone(),
        );
        let client = CuaClient { _budget: budget }
            .serve(transport)
            .await
            .unwrap();
        let peer = client.peer().clone();
        peer.list_tools(None).await.unwrap();
        Self {
            peer,
            calls,
            client,
            job,
        }
    }
    pub(crate) async fn call(
        &self,
        action: &CuaAction,
    ) -> (CuaEvidence, Option<CallToolResult>, Option<CuaError>) {
        driver_result::invoke(
            &self.peer,
            CallToolRequestParams::new(action.name.clone())
                .with_arguments(action.arguments.clone()),
            &CancellationToken::new(),
            Instant::now() + Duration::from_secs(2),
        )
        .await
    }
    pub(crate) async fn close(mut self) {
        drop(self.peer);
        self.client.close().await.unwrap();
        self.job.await.unwrap();
    }
}
