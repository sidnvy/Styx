//! Real official-SDK TCP boundary; the independent file resource is a fixture,
//! not native Exec, an OS bridge, TLS or ChatGPT-account acceptance.
use super::*;
use std::io::Write;

struct ResourceBackend {
    resource: Mutex<Option<(String, std::fs::File)>>,
    file: std::path::PathBuf,
    attempts: AtomicUsize,
    fenced: Mutex<BTreeSet<String>>,
    entered: Semaphore,
    release: Semaphore,
    completed: AtomicUsize,
}
impl GatewayToolBackend for ResourceBackend {
    async fn list_tools(
        &self,
        _: &VerifiedGatewayOwner,
        _: Option<PaginatedRequestParams>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult {
            tools: serde_json::from_value(surface()["tools"].clone()).unwrap(),
            ..Default::default()
        })
    }
    async fn call_tool(
        &self,
        owner: &VerifiedGatewayOwner,
        request: CallToolRequestParams,
    ) -> Result<CallToolResult, ErrorData> {
        self.attempts.fetch_add(1, Ordering::AcqRel);
        if request.name == "write_stdin"
            && request
                .arguments
                .as_ref()
                .and_then(|a| a.get("chars"))
                .and_then(serde_json::Value::as_str)
                == Some("hold-owned-call")
        {
            assert!(self.owner_has_live_work(owner));
            self.entered.add_permits(1);
            self.release.acquire().await.unwrap().forget();
            self.completed.fetch_add(1, Ordering::AcqRel);
            return Ok(CallToolResult::success(vec![ContentBlock::text(
                "original held call completed",
            )]));
        }
        let mut resource = self.resource.lock().unwrap();
        if request.name == "exec_command" {
            assert!(resource.is_none(), "fixture start must never be replayed");
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&self.file)
                .unwrap();
            file.write_all(b"one-owned-resource-effect\n").unwrap();
            *resource = Some((owner.owner_id().as_str().to_owned(), file));
            return Ok(CallToolResult::success(vec![ContentBlock::text(
                "session_id=1",
            )]));
        }
        if request.name == "write_stdin"
            && resource
                .as_ref()
                .is_some_and(|(actual, _)| actual == owner.owner_id().as_str())
        {
            return Ok(CallToolResult::success(vec![ContentBlock::text(
                std::fs::read_to_string(&self.file).unwrap(),
            )]));
        }
        Ok(CallToolResult::error(vec![ContentBlock::text(
            "unknown_session; not_dispatched",
        )]))
    }
}
impl GatewayOwnerLifecycle for ResourceBackend {
    fn owner_has_live_work(&self, owner: &VerifiedGatewayOwner) -> bool {
        self.resource
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|(actual, _)| actual == owner.owner_id().as_str())
    }
    fn fence_owner(&self, owner: &VerifiedGatewayOwner) -> Result<(), OwnerFenceError> {
        self.fenced
            .lock()
            .unwrap()
            .insert(owner.owner_id().as_str().to_owned());
        let mut resource = self.resource.lock().unwrap();
        if resource
            .as_ref()
            .is_some_and(|(actual, _)| actual == owner.owner_id().as_str())
        {
            resource.take();
        }
        Ok(())
    }
    async fn cleanup_owner(&self, owner: &VerifiedGatewayOwner, _: Duration) -> OwnerCleanup {
        assert!(!self.owner_has_live_work(owner));
        OwnerCleanup::Complete
    }
}
async fn sdk(
    uri: &str,
    token: &str,
) -> rmcp::service::RunningService<rmcp::RoleClient, ClientConfig> {
    let mut config = StreamableHttpClientTransportConfig::with_uri(uri.to_owned())
        .auth_header(token.to_owned())
        .reinit_on_expired_session(false)
        .max_concurrent_requests(1);
    config.allow_stateless = false;
    config.custom_headers = HashMap::from([(
        http::HeaderName::from_static(VERSION),
        "2025-11-25".parse().unwrap(),
    )]);
    ClientConfig::new(
        ClientCapabilities::default(),
        Implementation::new("owned-conversation-fixture", "1"),
    )
    .with_protocol_version(ProtocolVersion::V_2025_11_25)
    .serve_with_lifecycle(
        StreamableHttpClientTransport::with_client(reqwest::Client::new(), config),
        ClientLifecycleMode::Initialize,
    )
    .await
    .unwrap()
}
fn request(tool: &str, meta: serde_json::Value) -> CallToolRequestParams {
    serde_json::from_value(serde_json::json!({"name":tool,"arguments":if tool=="exec_command" {serde_json::json!({"cmd":"start-independent-fixture-once"})} else {serde_json::json!({"session_id":1,"chars":""})},"_meta":meta})).unwrap()
}

#[tokio::test]
#[ignore = "requires STYX_TEST_HTTP_ROOT; actual official-SDK separate TCP sessions and owned file-resource boundary, not native/account acceptance"]
async fn authenticated_tunnel_context_across_transports_and_isolation() {
    tokio::time::timeout(Duration::from_secs(40), async {
        let root = std::path::PathBuf::from(std::env::var("STYX_TEST_HTTP_ROOT").unwrap()).join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir_all(&root).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap(); let uri = format!("http://{address}/mcp");
        let ordinary = "ordinary-owned-fixture-credential-aaaaaaaa";
        let forwarding = "separate-owned-forwarder-credential-bbbbb";
        let policy = Arc::new(GatewayBearerPolicy::new(ordinary.as_bytes(), vec![address.to_string()], vec![]).unwrap().with_tunnel_ingress(forwarding.as_bytes()).unwrap());
        let backend = Arc::new(ResourceBackend {resource: Mutex::new(None), file: root.join("independent-effect.txt"), attempts: AtomicUsize::new(0), fenced: Mutex::new(BTreeSet::new()), entered: Semaphore::new(0), release: Semaphore::new(0), completed: AtomicUsize::new(0)});
        let partition = Arc::new(Semaphore::new(GATEWAY_HTTP_BYTES));
        let budget = HttpBudget::from_reserved_partition(partition.clone().try_acquire_many_owned(GATEWAY_HTTP_BYTES as u32).unwrap()).unwrap();
        let app = GatewayHttp::new(policy, backend.clone(), budget.clone());
        let server = app.clone().serve_owned(listener).await.unwrap();
        let meta = serde_json::json!({"openai/organization":"owned-org","openai/subject":"owned-subject","openai/session":"owned-chat"});
        let first = sdk(&uri, forwarding).await;
        assert_ne!(first.call_tool(request("exec_command", meta.clone())).await.unwrap().is_error, Some(true));
        let first_sid = app.sessions.lock().unwrap().values().find_map(|s| s.manager.id.lock().unwrap().as_ref().map(ToString::to_string)).unwrap();
        let original_owner = backend.resource.lock().unwrap().as_ref().unwrap().0.clone();
        let second = sdk(&uri, forwarding).await;
        assert_eq!(app.sessions.lock().unwrap().len(), 2, "distinct actual SDK transport sessions");
        let result = second.call_tool(request("write_stdin", meta.clone())).await.unwrap();
        assert_ne!(result.is_error, Some(true));
        assert!(serde_json::to_string(&result).unwrap().contains("one-owned-resource-effect"));
        first.cancel().await.unwrap();
        assert!(!backend.fenced.lock().unwrap().contains(&original_owner), "transport DELETE must not fence the logical resource");
        assert_ne!(second.call_tool(request("write_stdin", meta.clone())).await.unwrap().is_error, Some(true));
        for field in ["openai/organization", "openai/subject", "openai/session"] {
            let mut other = meta.clone(); other[field] = serde_json::json!("different-scope");
            assert_eq!(second.call_tool(request("write_stdin", other)).await.unwrap().is_error, Some(true));
        }
        let direct = sdk(&uri, ordinary).await;
        assert_eq!(direct.call_tool(request("write_stdin", meta.clone())).await.unwrap().is_error, Some(true), "ordinary bearer cannot forge forwarding context");
        let direct_again = sdk(&uri, ordinary).await;
        assert_eq!(direct_again.call_tool(request("write_stdin", meta.clone())).await.unwrap().is_error, Some(true));
        let raw = reqwest::Client::new();
        assert_eq!(raw.delete(&uri).bearer_auth(ordinary).header(SID, &first_sid).header(VERSION, "2025-11-25").send().await.unwrap().status(), StatusCode::NOT_FOUND);
        assert_eq!(raw.post(&uri).bearer_auth(ordinary).header("x-styx-tunnel-context", "forged").send().await.unwrap().status(), StatusCode::FORBIDDEN);
        let before = backend.attempts.load(Ordering::Acquire);
        for invalid in [serde_json::json!({}), serde_json::json!({"openai/organization":"owned-org","openai/subject":"owned-subject","openai/session":"bad\nchat"}), serde_json::json!({"openai/organization":"owned-org","openai/subject":"owned-subject","openai/session":"x".repeat(513)})] {
            assert!(second.call_tool(request("write_stdin", invalid)).await.is_err());
        }
        assert_eq!(backend.attempts.load(Ordering::Acquire), before, "invalid contexts refused before backend dispatch");
        // Drop a real HTTP response waiter after backend admission. The single
        // logical call reservation and actual work must outlive that waiter.
        let second_sid = app.sessions.lock().unwrap().values().find_map(|s| {
            let id = s.manager.id.lock().unwrap().as_ref().map(ToString::to_string);
            id.filter(|id| id != &first_sid && s.life.owner.is_tunnel())
        }).unwrap();
        let pending_http = raw.post(&uri).bearer_auth(forwarding).header(SID, &second_sid).header(VERSION, "2025-11-25").header("accept", "application/json, text/event-stream").json(&serde_json::json!({"jsonrpc":"2.0","id":9001,"method":"tools/call","params":{"name":"write_stdin","arguments":{"session_id":1,"chars":"hold-owned-call"},"_meta":meta}}));
        let waiter = tokio::spawn(async move { pending_http.send().await });
        tokio::time::timeout(Duration::from_secs(2), backend.entered.acquire()).await.unwrap().unwrap().forget();
        waiter.abort(); let _ = waiter.await;
        app.expire_conversations(Duration::ZERO);
        assert!(!backend.fenced.lock().unwrap().contains(&original_owner));
        assert_eq!(backend.completed.load(Ordering::Acquire), 0);
        assert!(app.conversations.lock().unwrap().values().any(|c| c.life.owner.owner_id().as_str()==original_owner && c.calls.available_permits()==0 && c.life.activity.lock().unwrap().users>0));
        backend.release.add_permits(1);
        let until = tokio::time::Instant::now() + Duration::from_secs(2);
        while backend.completed.load(Ordering::Acquire)==0 {
            assert!(tokio::time::Instant::now()<until);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(backend.completed.load(Ordering::Acquire), 1);
        app.expire_conversations(Duration::ZERO);
        assert!(!backend.fenced.lock().unwrap().contains(&original_owner), "live logical work cannot expire");
        assert_ne!(second.call_tool(request("write_stdin", meta)).await.unwrap().is_error, Some(true));
        assert_eq!(std::fs::read_to_string(&backend.file).unwrap(), "one-owned-resource-effect\n", "one independent effect, no replay");
        for client in [second, direct, direct_again] { let _ = client.cancel().await; }
        let stopped = server.shutdown(Duration::from_secs(5)).await;
        assert!(stopped.connections_joined && stopped.lifecycle_jobs_joined && stopped.session_transports_joined);
        assert_eq!(stopped.unconfirmed_owner_cleanups, 0);
        assert_eq!(stopped.unresolved_sessions, 0);
        assert!(backend.resource.lock().unwrap().is_none());
        assert!(backend.fenced.lock().unwrap().contains(&original_owner));
        drop(server); drop(app); drop(budget);
        assert_eq!(partition.available_permits(), GATEWAY_HTTP_BYTES);
        println!("PASS actual SDK distinct transports, same scoped resource, DELETE survival, cross-chat/subject/org and ordinary forgery refusal, invalid-context no-dispatch, dropped HTTP waiter retained original work/capacity, live-owner retention, one file effect and joined cleanup; not native/account acceptance; fixture={}", root.display());
    }).await.unwrap();
}

/// Pure lifecycle/capacity control: no socket/native/account acceptance claim.
#[tokio::test]
async fn logical_capacity_and_unknown_cleanup_never_reassign_an_owner() {
    let backend = Arc::new(UnconfirmedRemoteBackend {
        cleanup_attempts: AtomicUsize::new(0),
        cleanup_arrived: Semaphore::new(0),
        release_cleanup: Semaphore::new(0),
    });
    let ordinary = b"ordinary-capacity-fixture-aaaaaaaaaaaa";
    let forwarding = "separate-capacity-fixture-bbbbbbbbbbbb";
    let policy = Arc::new(
        GatewayBearerPolicy::new(ordinary, vec!["localhost".into()], vec![])
            .unwrap()
            .with_tunnel_ingress(forwarding.as_bytes())
            .unwrap(),
    );
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, "localhost".parse().unwrap());
    headers.insert(
        http::header::AUTHORIZATION,
        format!("Bearer {forwarding}").parse().unwrap(),
    );
    let principal = policy.authorize(&headers).unwrap();
    let partition = Arc::new(Semaphore::new(GATEWAY_HTTP_BYTES));
    let budget = HttpBudget::from_reserved_partition(
        partition
            .clone()
            .try_acquire_many_owned(GATEWAY_HTTP_BYTES as u32)
            .unwrap(),
    )
    .unwrap();
    let app = GatewayHttp::new(policy, backend.clone(), budget.clone());
    let meta = |i: usize| {
        serde_json::from_value::<RequestMetaObject>(serde_json::json!({"openai/organization":"capacity-org", "openai/subject":"capacity-subject", "openai/session":format!("capacity-chat-{i}")})).unwrap()
    };
    for i in 0..budget.capacity {
        drop(app.conversation_call(&principal, &meta(i)).unwrap());
    }
    assert_eq!(app.retained_sessions(), budget.capacity);
    assert!(matches!(
        app.conversation_call(&principal, &meta(budget.capacity)),
        Err(StatusCode::TOO_MANY_REQUESTS)
    ));
    let admitted = app.conversation_call(&principal, &meta(0)).unwrap();
    let original = admitted.conversation.life.clone();
    drop(admitted);
    original.close().unwrap();
    backend.cleanup_arrived.acquire().await.unwrap().forget();
    backend.release_cleanup.add_permits(1);
    let until = tokio::time::Instant::now() + Duration::from_secs(1);
    while original.facts.lock().unwrap().cleanup.is_none() {
        assert!(tokio::time::Instant::now() < until);
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert_eq!(
        original.facts.lock().unwrap().cleanup,
        Some(OwnerCleanup::Unknown)
    );
    app.expire_conversations(Duration::ZERO);
    assert!(!original.is_complete());
    assert_eq!(app.retained_sessions(), budget.capacity);
    assert!(
        matches!(
            app.conversation_call(&principal, &meta(0)),
            Err(StatusCode::NOT_FOUND)
        ),
        "closed context cannot mint another owner"
    );
    assert!(
        matches!(
            app.conversation_call(&principal, &meta(budget.capacity)),
            Err(StatusCode::TOO_MANY_REQUESTS)
        ),
        "unknown cleanup cannot free a reservation"
    );
    backend.release_cleanup.add_permits(budget.capacity);
    let server = HttpServer {
        app: app.clone(),
        listener_task: Mutex::new(None),
        shutdown_lock: tokio::sync::Mutex::new(()),
    };
    let stopped = server.shutdown(Duration::from_secs(2)).await;
    assert!(
        stopped.connections_joined
            && stopped.lifecycle_jobs_joined
            && stopped.session_transports_joined
    );
    assert_eq!(stopped.unconfirmed_owner_cleanups, budget.capacity);
    assert_eq!(stopped.unresolved_sessions, budget.capacity);
    assert_eq!(
        backend.cleanup_attempts.load(Ordering::Acquire),
        budget.capacity
    );
    let repeated = server.shutdown(Duration::from_secs(1)).await;
    assert_eq!(repeated.unconfirmed_owner_cleanups, budget.capacity);
    assert_eq!(
        backend.cleanup_attempts.load(Ordering::Acquire),
        budget.capacity,
        "shutdown observation never retries unknown cleanup"
    );
    drop(original);
    drop(server);
    drop(app);
    drop(budget);
    assert_eq!(partition.available_permits(), GATEWAY_HTTP_BYTES);
}
