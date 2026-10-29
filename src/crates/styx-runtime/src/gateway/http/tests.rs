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
    fn owner_has_live_work(&self, owner: &VerifiedGatewayOwner) -> bool {
        self.pending_owners
            .lock()
            .unwrap()
            .contains_key(owner.owner_id().as_str())
    }
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
    let maximum = HttpBudget::from_reserved_partition(
        Arc::new(Semaphore::new(MAX_HTTP_BYTES))
            .try_acquire_many_owned(MAX_HTTP_BYTES as u32)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(maximum.capacity, 80);
    assert_eq!(maximum._partition.num_permits(), 128 * 1024 * 1024);
    let over = MAX_HTTP_BYTES + SESSION_BYTES;
    assert!(
        HttpBudget::from_reserved_partition(
            Arc::new(Semaphore::new(over))
                .try_acquire_many_owned(over as u32)
                .unwrap()
        )
        .is_err()
    );
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
        let shared=Arc::new(Semaphore::new(GATEWAY_HTTP_BYTES));
        let budget=HttpBudget::from_reserved_partition(shared.clone().try_acquire_many_owned(GATEWAY_HTTP_BYTES as u32).unwrap()).unwrap();
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
        drop(server);drop(app);drop(budget);assert_eq!(shared.available_permits(),GATEWAY_HTTP_BYTES);
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
    let shared = Arc::new(Semaphore::new(GATEWAY_HTTP_BYTES));
    let budget = HttpBudget::from_reserved_partition(
        shared
            .clone()
            .try_acquire_many_owned(GATEWAY_HTTP_BYTES as u32)
            .unwrap(),
    )
    .unwrap();
    let app = GatewayHttp::new(policy, backend.clone(), budget.clone());
    let session = app
        .create_session(principal.new_mcp_session_owner().unwrap())
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
        app.create_session(principal.new_mcp_session_owner().unwrap())
            .is_err()
    );
    assert_eq!(backend.attempts.load(Ordering::Acquire), 0);
    drop(server);
    drop(app);
    drop(budget);
    assert_eq!(shared.available_permits(), GATEWAY_HTTP_BYTES);
}

/// Actual HTTP transport pressure. The barrier only holds already-admitted
/// controls; it does not bypass policy, manufacture SDK replies or execute tools.
#[tokio::test]
#[ignore = "requires STYX_TEST_HTTP_ROOT; owned actual TCP admission-pressure fixture"]
async fn actual_tcp_slow_post_readers_do_not_starve_bodyless_control() {
    use tokio::io::AsyncWriteExt;
    tokio::time::timeout(Duration::from_secs(20), async {
        let root = std::path::PathBuf::from(std::env::var("STYX_TEST_HTTP_ROOT").unwrap())
            .join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir_all(&root).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let uri = format!("http://{address}/mcp");
        let token = "owned-admission-pressure-token-aaaaaaaaaaaa";
        let policy = Arc::new(GatewayBearerPolicy::new(token.as_bytes(), vec![address.to_string()], vec![]).unwrap());
        let backend = Arc::new(CounterBackend {
            tools: vec![], fenced: Mutex::new(BTreeSet::new()), calls: Mutex::new(vec![]),
            pending: AtomicUsize::new(0), attempts: AtomicUsize::new(0),
            fail_fence_once: std::sync::atomic::AtomicBool::new(false),
            arrived: tokio::sync::Notify::new(), pending_owners: Mutex::new(BTreeMap::new()),
            path: root.join("unused-effects.txt"),
        });
        let shared = Arc::new(Semaphore::new(GATEWAY_HTTP_BYTES));
        let budget = HttpBudget::from_reserved_partition(shared.clone().try_acquire_many_owned(GATEWAY_HTTP_BYTES as u32).unwrap()).unwrap();
        let app = GatewayHttp::new(policy, backend.clone(), budget.clone());
        let server = app.clone().serve_owned(listener).await.unwrap();
        let client = reqwest::Client::new();
        let mut ids = vec![];
        // Official SDK model serialization over real HTTP; no background client
        // GET is opened, so the dedicated GET slot is not accidentally occupied.
        for id in 0..4 {
            let initialize: ClientJsonRpcMessage = serde_json::from_value(serde_json::json!({
                "jsonrpc":"2.0", "id":id, "method":"initialize", "params":{
                    "protocolVersion":"2025-11-25", "capabilities":{},
                    "clientInfo":{"name":"owned-pressure-fixture","version":"1"}
                }
            })).unwrap();
            let response = client.post(&uri).bearer_auth(token)
                .header(http::header::ACCEPT, "application/json, text/event-stream")
                .json(&initialize).send().await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let sid = response.headers()[SID].to_str().unwrap().to_owned();
            assert!(!response.bytes().await.unwrap().is_empty());
            let initialized: ClientJsonRpcMessage = serde_json::from_value(serde_json::json!({
                "jsonrpc":"2.0", "method":"notifications/initialized"
            })).unwrap();
            assert_eq!(client.post(&uri).bearer_auth(token).header(SID, &sid)
                .header(VERSION, "2025-11-25")
                .header(http::header::ACCEPT, "application/json, text/event-stream")
                .json(&initialized).send().await.unwrap().status(), StatusCode::ACCEPTED);
            ids.push(sid);
        }
        let probe = Arc::new(AdmissionProbe {
            body_entered: Semaphore::new(0), control_entered: Semaphore::new(0),
            release_controls: Semaphore::new(0),
        });
        *app.admission_probe.lock().unwrap() = Some(probe.clone());
        let mut slow = vec![];
        for _ in 0..16 {
            let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
            let headers = format!("POST /mcp HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {token}\r\nMcp-Session-Id: {}\r\nContent-Length: {MESSAGE_BYTES}\r\nContent-Type: application/json\r\n\r\nx", ids[0]);
            socket.write_all(headers.as_bytes()).await.unwrap();
            slow.push(socket);
        }
        tokio::time::timeout(Duration::from_secs(2), probe.body_entered.acquire_many(16)).await.unwrap().unwrap().forget();
        assert_eq!(app.body_readers.available_permits(), 0);
        let get = client.get(&uri).bearer_auth(token).header(SID, &ids[0])
            .header(VERSION, "2025-11-25").header(http::header::ACCEPT, "text/event-stream")
            .send().await.unwrap();
        assert_eq!(get.status(), StatusCode::OK, "GET must enter while all slow bodies remain held");
        drop(get);
        let mut controls = vec![];
        for sid in [&ids[1], &ids[2]] {
            let request = client.delete(&uri).bearer_auth(token).header(SID, sid)
                .header(VERSION, "2025-11-25");
            controls.push(tokio::spawn(async move { request.send().await.unwrap() }));
        }
        tokio::time::timeout(Duration::from_secs(2), probe.control_entered.acquire_many(2)).await.unwrap().unwrap().forget();
        assert_eq!(app.control.available_permits(), 0);
        assert_eq!(app.body_readers.available_permits(), 0);
        assert_eq!(client.delete(&uri).bearer_auth(token).header(SID, &ids[3])
            .header(VERSION, "2025-11-25").send().await.unwrap().status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(backend.fenced.lock().unwrap().is_empty(), "barrier is before the SDK close effect");
        probe.release_controls.add_permits(2);
        for task in controls {
            let response = task.await.unwrap();
            assert_eq!(response.status(), StatusCode::ACCEPTED);
            response.bytes().await.unwrap();
        }
        assert_eq!(backend.fenced.lock().unwrap().len(), 2);
        assert!(backend.calls.lock().unwrap().is_empty());
        assert_eq!(app.body_readers.available_permits(), 0, "success must precede pressure release");
        *app.admission_probe.lock().unwrap() = None;
        // Nonempty/uncertain framing is rejected promptly, never read on the
        // POST queue. Connection-close prevents reusing an unread request body.
        for method in [reqwest::Method::GET, reqwest::Method::DELETE] {
            let response = client.request(method, &uri).bearer_auth(token).header(SID, &ids[0])
                .header(VERSION, "2025-11-25").body("x").send().await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(response.headers()[http::header::CONNECTION], "close");
        }
        drop(slow);
        for sid in [&ids[0], &ids[3]] {
            assert_eq!(client.delete(&uri).bearer_auth(token).header(SID, sid)
                .header(VERSION, "2025-11-25").send().await.unwrap().status(), StatusCode::ACCEPTED);
        }
        collected(&app).await;
        let report = server.shutdown(Duration::from_secs(5)).await;
        assert!(report.connections_joined && report.lifecycle_jobs_joined);
        assert_eq!(report.unresolved_sessions, 0);
        assert_eq!(report.sdk_detached_tasks_joined, None);
        assert_eq!(app.body_readers.available_permits(), 16);
        assert_eq!(app.control.available_permits(), 2);
        assert_eq!(app.requests.available_permits(), 16);
        assert_eq!(app.connections.available_permits(), 128);
        assert_eq!(backend.fenced.lock().unwrap().len(), 4);
        assert_eq!(backend.attempts.load(Ordering::Acquire), 0);
        drop(server); drop(app); drop(budget);
        assert_eq!(shared.available_permits(), GATEWAY_HTTP_BYTES);
        println!("actual TCP pressure PASS fixture={}: 16 observed slow POST readers held; GET entered; two independent DELETE controls simultaneously admitted before SDK effect; third429; two202 and exact fences before pressure release; all owned admissions/connections/partition returned. No native/TLS/account evidence. POST cancel still shares body capacity; SDK detached joins unknown", root.display());
    }).await.unwrap();
}

/// Controlled remote-unavailable lifecycle, with the actual official SDK local
/// worker. This is not native Host cleanup/TLS/account acceptance evidence.
struct UnconfirmedRemoteBackend {
    cleanup_attempts: AtomicUsize,
    cleanup_arrived: Semaphore,
    release_cleanup: Semaphore,
}
impl GatewayToolBackend for UnconfirmedRemoteBackend {
    async fn list_tools(
        &self,
        _owner: &VerifiedGatewayOwner,
        _request: Option<PaginatedRequestParams>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult::default())
    }
    async fn call_tool(
        &self,
        _owner: &VerifiedGatewayOwner,
        _request: CallToolRequestParams,
    ) -> Result<CallToolResult, ErrorData> {
        Err(ErrorData::invalid_request(
            "no native executor in lifecycle fixture",
            None,
        ))
    }
}
impl GatewayOwnerLifecycle for UnconfirmedRemoteBackend {
    fn fence_owner(&self, _owner: &VerifiedGatewayOwner) -> Result<(), OwnerFenceError> {
        Ok(()) // Local admission fence only, never a remote termination proof.
    }
    async fn cleanup_owner(
        &self,
        _owner: &VerifiedGatewayOwner,
        _budget: Duration,
    ) -> OwnerCleanup {
        self.cleanup_attempts.fetch_add(1, Ordering::AcqRel);
        self.cleanup_arrived.add_permits(1);
        self.release_cleanup.acquire().await.unwrap().forget();
        OwnerCleanup::Unknown
    }
}

#[tokio::test]
async fn process_quit_joins_local_sdk_workers_without_forging_remote_owner_cleanup() {
    use rmcp::transport::{Transport, streamable_http_server::SessionManager};
    let backend = Arc::new(UnconfirmedRemoteBackend {
        cleanup_attempts: AtomicUsize::new(0),
        cleanup_arrived: Semaphore::new(0),
        release_cleanup: Semaphore::new(0),
    });
    let token = "u".repeat(32);
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
    let partition = Arc::new(Semaphore::new(GATEWAY_HTTP_BYTES));
    let budget = HttpBudget::from_reserved_partition(
        partition
            .clone()
            .try_acquire_many_owned(GATEWAY_HTTP_BYTES as u32)
            .unwrap(),
    )
    .unwrap();
    let app = GatewayHttp::new(policy, backend.clone(), budget.clone());
    let attempted = app
        .create_session(principal.new_mcp_session_owner().unwrap())
        .unwrap();
    let untouched = app
        .create_session(principal.new_mcp_session_owner().unwrap())
        .unwrap();
    assert!(
        untouched.manager.local_transport_quiescent(),
        "never attempted, not a fabricated worker join"
    );
    let (_id, mut transport) = attempted.manager.create_session().await.unwrap();
    assert!(
        !attempted.manager.local_transport_quiescent(),
        "a real attempted worker must be joined"
    );
    tokio::time::timeout(Duration::from_secs(5), transport.close())
        .await
        .unwrap()
        .unwrap();
    assert!(
        attempted.life.facts.lock().unwrap().transport_joined,
        "official WorkerTransport.close actually awaited its worker"
    );
    untouched.life.close().unwrap();
    tokio::time::timeout(
        Duration::from_secs(1),
        backend.cleanup_arrived.acquire_many(2),
    )
    .await
    .unwrap()
    .unwrap()
    .forget();
    let server = HttpServer {
        app: app.clone(),
        listener_task: Mutex::new(None),
        shutdown_lock: tokio::sync::Mutex::new(()),
    };
    let blocked = server.shutdown(Duration::from_millis(20)).await;
    assert!(blocked.session_transports_joined);
    assert!(
        !blocked.lifecycle_jobs_joined,
        "a still-held local cleanup future is not joined"
    );
    assert_eq!(blocked.unconfirmed_owner_cleanups, 2);
    assert_eq!(backend.cleanup_attempts.load(Ordering::Acquire), 2);
    assert!(
        app.retained_sessions() >= 2,
        "normal Closing capacity remains retained"
    );
    assert!(
        untouched.manager.create_session().await.is_err(),
        "no late creation after the same close gate"
    );
    backend.release_cleanup.add_permits(2);
    let stopped = server.shutdown(Duration::from_secs(1)).await;
    assert!(
        stopped.connections_joined
            && stopped.lifecycle_jobs_joined
            && stopped.session_transports_joined
    );
    assert_eq!(
        stopped.unconfirmed_owner_cleanups, 2,
        "remote Unknown does not become Complete"
    );
    assert_eq!(stopped.sdk_detached_tasks_joined, None);
    assert!(!attempted.life.is_complete());
    assert_eq!(
        attempted.life.facts.lock().unwrap().cleanup,
        Some(OwnerCleanup::Unknown)
    );
    assert!(
        stopped.unresolved_sessions >= 2,
        "process-level stop does not collect unknown sessions as successful"
    );
    let repeated = server.shutdown(Duration::from_secs(1)).await;
    assert!(repeated.lifecycle_jobs_joined && repeated.session_transports_joined);
    assert_eq!(repeated.unconfirmed_owner_cleanups, 2);
    assert_eq!(
        backend.cleanup_attempts.load(Ordering::Acquire),
        2,
        "observing stop must not replay cleanup/actions"
    );

    // A task that actually panicked is terminated, with a separate sticky
    // failure. It must not leave an eternal 'still running' shutdown condition.
    app.supervisor
        .jobs
        .lock()
        .unwrap()
        .spawn(async { panic!("owned lifecycle negative control") });
    let failed = server.shutdown(Duration::from_secs(1)).await;
    assert!(failed.lifecycle_jobs_joined);
    assert!(failed.worker_failure_observed);
    assert!(
        server
            .shutdown(Duration::from_secs(1))
            .await
            .worker_failure_observed
    );
    drop(transport);
    drop(attempted);
    drop(untouched);
    drop(server);
    drop(app);
    drop(budget);
    assert_eq!(partition.available_permits(), GATEWAY_HTTP_BYTES);
}

#[path = "capacity_tests.rs"]
mod capacity;
