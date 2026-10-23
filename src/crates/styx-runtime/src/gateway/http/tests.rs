//! Actual SDK/HTTP fixture, never native execution or account identity evidence.
use super::*;
use lifecycle::{OwnerCleanup, OwnerFenceError};
use rmcp::{
    ClientServiceExt, ErrorData,
    model::*,
    service::ClientLifecycleMode,
    transport::{
        StreamableHttpClientTransport, streamable_http_client::StreamableHttpClientTransportConfig,
    },
};
use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
struct CounterBackend {
    tools: Vec<Tool>,
    fenced: Mutex<BTreeSet<String>>,
    calls: Mutex<Vec<(String, String)>>,
    pending: AtomicUsize,
    attempts: AtomicUsize,
    fail_fence_once: std::sync::atomic::AtomicBool,
    arrived: tokio::sync::Notify,
    pending_owners: Mutex<BTreeMap<String, Arc<tokio::sync::Notify>>>,
    path: std::path::PathBuf,
}
impl GatewayToolBackend for CounterBackend {
    async fn list_tools(
        &self,
        _owner: &VerifiedGatewayOwner,
        _request: Option<PaginatedRequestParams>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult {
            tools: self.tools.clone(),
            ..Default::default()
        })
    }
    async fn call_tool(
        &self,
        owner: &VerifiedGatewayOwner,
        request: CallToolRequestParams,
    ) -> Result<CallToolResult, ErrorData> {
        self.attempts.fetch_add(1, Ordering::AcqRel);
        if self
            .fenced
            .lock()
            .unwrap()
            .contains(owner.owner_id().as_str())
        {
            return Err(ErrorData::invalid_request("owner fenced", None));
        }
        if request.name != "exec_command" {
            return Err(ErrorData::method_not_found::<CallToolRequestMethod>());
        }
        let command = request
            .arguments
            .as_ref()
            .and_then(|a| a.get("cmd"))
            .and_then(|x| x.as_str())
            .unwrap_or("invalid")
            .to_owned();
        {
            let mut calls = self.calls.lock().unwrap();
            assert!(calls.len() < 32);
            calls.push((owner.owner_id().as_str().to_owned(), command.clone()));
        }
        if command == "pending-counter-effect" {
            use std::io::Write;
            let release = Arc::new(tokio::sync::Notify::new());
            let owner_key = owner.owner_id().as_str().to_owned();
            self.pending_owners
                .lock()
                .unwrap()
                .insert(owner_key.clone(), release.clone());
            self.pending.fetch_add(1, Ordering::AcqRel);
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
                .unwrap()
                .write_all(b"fixture-nonce-effect\n")
                .unwrap();
            self.arrived.notify_one();
            release.notified().await;
            self.pending_owners.lock().unwrap().remove(&owner_key);
            self.pending.fetch_sub(1, Ordering::AcqRel);
        }
        Ok(CallToolResult::success(vec![ContentBlock::text(
            "typed counter backend only; no native executor",
        )]))
    }
}
impl GatewayOwnerLifecycle for CounterBackend {
    fn fence_owner(&self, owner: &VerifiedGatewayOwner) -> Result<(), OwnerFenceError> {
        if self.fail_fence_once.swap(false, Ordering::AcqRel) {
            return Err(OwnerFenceError);
        }
        self.fenced
            .lock()
            .unwrap()
            .insert(owner.owner_id().as_str().to_owned());
        if let Some(release) = self
            .pending_owners
            .lock()
            .unwrap()
            .get(owner.owner_id().as_str())
        {
            release.notify_one();
        }
        Ok(())
    }
    async fn cleanup_owner(&self, owner: &VerifiedGatewayOwner, budget: Duration) -> OwnerCleanup {
        let until = tokio::time::Instant::now() + budget;
        while self
            .pending_owners
            .lock()
            .unwrap()
            .contains_key(owner.owner_id().as_str())
        {
            if tokio::time::Instant::now() >= until {
                return OwnerCleanup::Unknown;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        OwnerCleanup::Complete
    }
}
fn surface() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../../../docs/rust-core-rewrite/PUBLIC-MCP-V1.json"
    ))
    .unwrap()
}
fn active_sid(app: &GatewayHttp<CounterBackend>) -> String {
    app.sessions
        .lock()
        .unwrap()
        .values()
        .find_map(|s| {
            if s.life.is_active() {
                s.manager
                    .id
                    .lock()
                    .unwrap()
                    .as_ref()
                    .map(|id| id.to_string())
            } else {
                None
            }
        })
        .unwrap()
}
async fn collected(app: &GatewayHttp<CounterBackend>) {
    for _ in 0..100 {
        if app.retained_sessions() == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let facts: Vec<_> = app
        .sessions
        .lock()
        .unwrap()
        .values()
        .map(|s| {
            let f = s.life.facts.lock().unwrap();
            (f.closing, f.fenced, f.cleanup, f.transport_joined)
        })
        .collect();
    panic!("session not proven closed: {facts:?}");
}
#[test]
fn outbound_limit_precedes_sdk_cache_and_partition_cannot_be_empty() {
    assert!(session::bounded_message(&"small"));
    assert!(!session::bounded_message(&"x".repeat(MESSAGE_BYTES)));
    let root = Arc::new(Semaphore::new(1));
    assert!(HttpBudget::from_reserved_partition(root.try_acquire_owned().unwrap()).is_err());
}
#[tokio::test]
#[ignore = "requires STYX_TEST_HTTP_ROOT; owned loopback official SDK counter-backend development scenario"]
async fn official_sdk_tcp_auth_sessions_limits_and_pending_close() {
    tokio::time::timeout(Duration::from_secs(40),async {
        let root=std::path::PathBuf::from(std::env::var("STYX_TEST_HTTP_ROOT").unwrap()).join(uuid::Uuid::new_v4().to_string());std::fs::create_dir_all(&root).unwrap();
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let address=listener.local_addr().unwrap();let uri=format!("http://{address}/mcp");
        let token="owned-development-fixture-token-aaaaaaaaaaaa".to_owned();
        let policy=Arc::new(GatewayBearerPolicy::new(token.as_bytes(),vec![address.to_string()],vec!["https://approved.example".into()]).unwrap());
        let backend=Arc::new(CounterBackend{tools:serde_json::from_value(surface()["tools"].clone()).unwrap(),fenced:Mutex::new(BTreeSet::new()),calls:Mutex::new(vec![]),pending:AtomicUsize::new(0),attempts:AtomicUsize::new(0),fail_fence_once:std::sync::atomic::AtomicBool::new(false),arrived:tokio::sync::Notify::new(),pending_owners:Mutex::new(BTreeMap::new()),path:root.join("counter-effects.txt")});
        let shared=Arc::new(Semaphore::new(styx_contracts::HOST_QUEUED_BYTES));
        let budget=HttpBudget::from_reserved_partition(shared.clone().try_acquire_many_owned((32*1024*1024)as u32).unwrap()).unwrap();
        let app=GatewayHttp::new(policy,backend.clone(),budget.clone());let server=app.clone().serve_owned(listener).await.unwrap();
        let raw=reqwest::Client::new();
        let versions=["2024-10-07","2024-11-05","2025-03-26","2025-06-18","2025-11-25"];
        for (index,version) in versions.iter().enumerate() {
            let mut config=StreamableHttpClientTransportConfig::with_uri(uri.clone()).auth_header(token.clone()).reinit_on_expired_session(false).max_sse_event_size(MESSAGE_BYTES).max_concurrent_requests(1);
            config.allow_stateless=false;config.custom_headers=HashMap::from([(http::HeaderName::from_static(VERSION),version.parse().unwrap())]);
            let transport=StreamableHttpClientTransport::with_client(raw.clone(),config);
            let client=ClientConfig::new(ClientCapabilities::default(),Implementation::new("owned-http-sdk-fixture","1")).with_protocol_version(serde_json::from_value(serde_json::json!(version)).unwrap()).serve_with_lifecycle(transport,ClientLifecycleMode::Initialize).await.unwrap();
            assert_eq!(client.peer_info().unwrap().protocol_version.as_str(),*version);
            assert_eq!(client.peer_info().unwrap().instructions.as_deref(),surface()["instructions"].as_str());
            assert_eq!(serde_json::to_value(client.list_tools(None).await.unwrap().tools).unwrap(),surface()["tools"]);
            let request:CallToolRequestParams=serde_json::from_value(serde_json::json!({"name":"exec_command","arguments":{"cmd":format!("counter-{index}")},"_meta":{"owner":"forged-other-owner"}})).unwrap();
            client.call_tool(request).await.unwrap();
            let sid=active_sid(&app);
            // Auth is rerun for all three verbs, even for an existing valid SDK ID.
            for method in [reqwest::Method::POST,reqwest::Method::GET,reqwest::Method::DELETE] {
                assert_eq!(raw.request(method.clone(),&uri).header(SID,&sid).send().await.unwrap().status(),StatusCode::UNAUTHORIZED);
                assert_eq!(raw.request(method,&uri).bearer_auth(&token).header(SID,&sid).header(http::header::ORIGIN,"https://wrong.example").send().await.unwrap().status(),StatusCode::FORBIDDEN);
            }
            // Wrong version cannot invoke SDK or end the valid session.
            if *version!="2024-10-07" {
                assert_eq!(raw.delete(&uri).bearer_auth(&token).header(SID,&sid).header(VERSION,OLDEST).send().await.unwrap().status(),StatusCode::BAD_REQUEST);
                assert!(app.find_session(&sid).unwrap().life.is_active());
            }
            if index==4 {
                let before=backend.calls.lock().unwrap().len();
                let unknown=raw.post(&uri).bearer_auth(&token).header(SID,&sid).header(VERSION,*version).header(http::header::ACCEPT,"application/json, text/event-stream").json(&serde_json::json!({"jsonrpc":"2.0","id":77,"method":"resources/list"})).send().await.unwrap();
                assert_eq!(unknown.status(),StatusCode::BAD_REQUEST);assert_eq!(backend.calls.lock().unwrap().len(),before);
                let too_large=raw.post(&uri).bearer_auth(&token).header(SID,&sid).body("x".repeat(MESSAGE_BYTES+1)).send().await.unwrap();assert_eq!(too_large.status(),StatusCode::PAYLOAD_TOO_LARGE);
                let peer=client.peer().clone();let pending=tokio::spawn(async move {peer.call_tool(serde_json::from_value(serde_json::json!({"name":"exec_command","arguments":{"cmd":"pending-counter-effect"}})).unwrap()).await});
                tokio::time::timeout(Duration::from_secs(3),backend.arrived.notified()).await.unwrap();
                assert_eq!(std::fs::read_to_string(&backend.path).unwrap(),"fixture-nonce-effect\n");
                assert_eq!(raw.delete(&uri).bearer_auth(&token).header(SID,&sid).header(VERSION,*version).send().await.unwrap().status(),StatusCode::ACCEPTED);
                let _pending_delivery=pending.await.unwrap(); // may close without a response; never replay
                assert!(backend.fenced.lock().unwrap().len()>=5);
            }
            let _=client.cancel().await;
            collected(&app).await;
        }
        assert_eq!(app.oldest_methods.load(Ordering::Acquire)&7,7,"actual official client oldest POST/GET/DELETE shim journey");
        let owners:BTreeSet<_>=backend.calls.lock().unwrap().iter().map(|x|x.0.clone()).collect();assert_eq!(owners.len(),5);
        assert_eq!(backend.calls.lock().unwrap().len(),6);assert_eq!(std::fs::read_to_string(&backend.path).unwrap().lines().count(),1);
        let report=server.shutdown(Duration::from_secs(5)).await;assert!(report.connections_joined&&report.lifecycle_jobs_joined);assert_eq!(report.unresolved_sessions,0);
        drop(server);drop(app);drop(budget);assert_eq!(shared.available_permits(),styx_contracts::HOST_QUEUED_BYTES);
        println!("HTTP owned development fixture={} PASS: real official SDK all5, frozen tools, auth each verb, isolated opaque owners, oldest header shim all3verbs, unknown/oversize refused, one pending nonce effect then real fence+observed SDK transport close+cleanup; not native/account/TLS",root.display());
    }).await.unwrap();
}

/// Deterministic supervisor boundary control, not an HTTP/OS fault or SDK join proof.
#[tokio::test]
async fn close_fences_late_admission_retries_fence_and_double_shutdown_keeps_ownership() {
    let backend = Arc::new(CounterBackend {
        tools: vec![],
        fenced: Mutex::new(BTreeSet::new()),
        calls: Mutex::new(vec![]),
        pending: AtomicUsize::new(0),
        attempts: AtomicUsize::new(0),
        fail_fence_once: std::sync::atomic::AtomicBool::new(true),
        arrived: tokio::sync::Notify::new(),
        pending_owners: Mutex::new(BTreeMap::new()),
        path: std::env::temp_dir().join(format!("styx-never-executed-{}", uuid::Uuid::new_v4())),
    });
    let token = "a".repeat(32);
    let policy = Arc::new(
        GatewayBearerPolicy::new(token.as_bytes(), vec!["localhost".into()], vec![]).unwrap(),
    );
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, "localhost".parse().unwrap());
    headers.insert(
        http::header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    );
    let principal = policy.authorize(&headers).unwrap();
    let shared = Arc::new(Semaphore::new(styx_contracts::HOST_QUEUED_BYTES));
    let budget = HttpBudget::from_reserved_partition(
        shared
            .clone()
            .try_acquire_many_owned((32 * 1024 * 1024) as u32)
            .unwrap(),
    )
    .unwrap();
    let app = GatewayHttp::new(policy, backend.clone(), budget.clone());
    let session = app
        .create_session(principal.new_mcp_session_owner())
        .unwrap();
    // This pure control fixture never constructed an SDK worker. It must not be
    // reported as a real SDK close/join observation from the TCP scenario.
    assert!(session.manager.id.lock().unwrap().is_none());
    session.life.facts.lock().unwrap().transport_joined = true;
    let arrived = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let bridge = Arc::new(BackendBridge {
        backend: backend.clone(),
        life: session.life.clone(),
        calls: Arc::new(Semaphore::new(1)),
        before_register: Mutex::new(Some((arrived.clone(), release.clone()))),
    });
    let waiting_bridge = bridge.clone();
    let owner = session.life.owner.clone();
    let waiter = tokio::spawn(async move {
        waiting_bridge.call_tool(&owner,serde_json::from_value(serde_json::json!({"name":"exec_command","arguments":{"cmd":"must-not-delegate"}})).unwrap()).await
    });
    arrived.notified().await;
    assert!(session.life.close().is_err());
    {
        let f = session.life.facts.lock().unwrap();
        assert!(f.closing && !f.fenced && !f.cleanup_started);
    }
    release.notify_one();
    assert!(waiter.await.unwrap().is_err());
    assert_eq!(
        backend.attempts.load(Ordering::Acquire),
        0,
        "late request cannot even enter backend after fence boundary"
    );
    session.life.close().unwrap(); // explicit idempotent fence reconciliation
    assert!(session.life.facts.lock().unwrap().fenced);
    let server = HttpServer {
        app: app.clone(),
        listener_task: Mutex::new(None),
        shutdown_lock: tokio::sync::Mutex::new(()),
    };
    let first = server.shutdown(Duration::from_secs(1)).await;
    assert!(
        first.unresolved_sessions > 0,
        "test-owned Arc<Life> must retain actual capacity"
    );
    drop(bridge);
    drop(session);
    let (a, b) = tokio::join!(
        server.shutdown(Duration::from_secs(1)),
        server.shutdown(Duration::from_secs(1))
    );
    assert!(
        a.connections_joined
            && a.lifecycle_jobs_joined
            && b.connections_joined
            && b.lifecycle_jobs_joined
    );
    assert_eq!(a.unresolved_sessions, 0);
    assert_eq!(b.unresolved_sessions, 0);
    assert!(
        app.create_session(principal.new_mcp_session_owner())
            .is_err()
    );
    assert_eq!(backend.attempts.load(Ordering::Acquire), 0);
    drop(server);
    drop(app);
    drop(budget);
    assert_eq!(
        shared.available_permits(),
        styx_contracts::HOST_QUEUED_BYTES
    );
}
