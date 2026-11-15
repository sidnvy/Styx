//! Official HTTP service/SDK workers, without socket admission. Socket/native
//! pairing coverage lives in the separately registered paired journey scenario.
use super::*;
use serde_json::{Value, json};
struct QuietBackend {
    live: Mutex<BTreeSet<String>>,
    started: Semaphore,
    release: Semaphore,
}
impl GatewayToolBackend for QuietBackend {
    async fn list_tools(
        &self,
        _: &VerifiedGatewayOwner,
        _: Option<PaginatedRequestParams>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult::default())
    }
    async fn call_tool(
        &self,
        owner: &VerifiedGatewayOwner,
        request: CallToolRequestParams,
    ) -> Result<CallToolResult, ErrorData> {
        if owner.is_fenced() {
            return Err(ErrorData::invalid_request("fenced", None));
        }
        if request
            .arguments
            .as_ref()
            .and_then(|a| a.get("cmd"))
            .and_then(Value::as_str)
            == Some("block")
        {
            self.live
                .lock()
                .unwrap()
                .insert(owner.owner_id().as_str().to_owned());
            self.started.add_permits(1);
            self.release.acquire().await.unwrap().forget();
            self.live.lock().unwrap().remove(owner.owner_id().as_str());
        }
        Ok(CallToolResult::success(vec![ContentBlock::text(
            "x".repeat(MESSAGE_BYTES - 1024),
        )]))
    }
}
impl GatewayOwnerLifecycle for QuietBackend {
    fn owner_has_live_work(&self, owner: &VerifiedGatewayOwner) -> bool {
        self.live
            .lock()
            .unwrap()
            .contains(owner.owner_id().as_str())
    }
    fn fence_owner(&self, owner: &VerifiedGatewayOwner) -> Result<(), OwnerFenceError> {
        owner.fence();
        Ok(())
    }
    async fn cleanup_owner(&self, _: &VerifiedGatewayOwner, _: Duration) -> OwnerCleanup {
        OwnerCleanup::Complete
    }
}
fn fixture() -> Arc<GatewayHttp<QuietBackend>> {
    GatewayHttp::new(
        Arc::new(
            GatewayBearerPolicy::new(
                b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                vec!["localhost".into()],
                vec![],
            )
            .unwrap(),
        ),
        Arc::new(QuietBackend {
            live: Mutex::new(BTreeSet::new()),
            started: Semaphore::new(0),
            release: Semaphore::new(0),
        }),
        HttpBudget::from_reserved_partition(
            Arc::new(Semaphore::new(GATEWAY_HTTP_BYTES))
                .try_acquire_many_owned(GATEWAY_HTTP_BYTES as u32)
                .unwrap(),
        )
        .unwrap(),
    )
}
async fn request<B: GatewayToolBackend + GatewayOwnerLifecycle>(
    app: &GatewayHttp<B>,
    method: Method,
    sid: Option<&str>,
    message: Value,
) -> Response<HeldBody> {
    let bytes = if method == Method::POST {
        serde_json::to_vec(&message).unwrap()
    } else {
        vec![]
    };
    let mut r = http::Request::builder()
        .method(method)
        .uri("/mcp")
        .header("host", "localhost")
        .header("authorization", "Bearer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream");
    if let Some(sid) = sid {
        r = r.header(SID, sid).header(VERSION, "2025-11-25");
    }
    app.handle_inner(r.body(Full::new(Bytes::from(bytes))).unwrap())
        .await
}
async fn initialize<B: GatewayToolBackend + GatewayOwnerLifecycle>(
    app: &GatewayHttp<B>,
) -> Result<String, StatusCode> {
    let r=request(app,Method::POST,None,json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"capacity-oracle","version":"1"}}})).await;
    if r.status() != StatusCode::OK {
        return Err(r.status());
    }
    let sid = r.headers()[SID].to_str().unwrap().to_owned();
    r.into_body().collect().await.unwrap();
    let r = request(
        app,
        Method::POST,
        Some(&sid),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    )
    .await;
    assert_eq!(r.status(), StatusCode::ACCEPTED);
    r.into_body().collect().await.unwrap();
    Ok(sid)
}
fn age<B: GatewayToolBackend + GatewayOwnerLifecycle>(app: &GatewayHttp<B>, duration: Duration) {
    for s in app.sessions.lock().unwrap().values() {
        let mut a = s.life.activity.lock().unwrap();
        if a.users == 0 {
            a.last -= duration;
        }
    }
}
async fn stop<B: GatewayToolBackend + GatewayOwnerLifecycle>(app: &Arc<GatewayHttp<B>>) {
    let report = app
        .paired_shutdown_handle()
        .shutdown(Duration::from_secs(5))
        .await;
    assert!(report.lifecycle_jobs_joined && report.session_transports_joined);
    assert_eq!(report.unresolved_sessions, 0);
}
#[tokio::test]
async fn thousand_sessions_have_no_quota_and_deleted_ids_stay_404() {
    let app = fixture();
    const {
        assert!(GATEWAY_HTTP_BYTES <= 128 * 1024 * 1024);
    }
    let mut stale = None;
    for _ in 0..1050 {
        let sid = initialize(&app).await.unwrap();
        if stale.is_none() {
            stale = Some((
                sid.clone(),
                app.find_session(&sid).unwrap().life.owner.clone(),
            ));
        }
        let r = request(&app, Method::DELETE, Some(&sid), Value::Null).await;
        assert_eq!(r.status(), StatusCode::ACCEPTED);
        r.into_body().collect().await.unwrap();
        for _ in 0..100 {
            if app.retained_sessions() == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(app.retained_sessions(), 0);
    }
    for i in 0..1050 {
        initialize(&app).await.unwrap();
        assert_eq!(app.retained_sessions(), i + 1);
    }
    assert_eq!(app.retained_sessions(), 1050);
    let (sid, owner) = stale.unwrap();
    assert!(owner.is_fenced());
    assert!(
        app.backend
            .call_tool(
                &owner,
                serde_json::from_value(json!({"name":"exec_command"})).unwrap()
            )
            .await
            .is_err()
    );
    assert_eq!(
        request(
            &app,
            Method::POST,
            Some(&sid),
            json!({"jsonrpc":"2.0","id":8,"method":"tools/list"})
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
    age(&app, Duration::from_secs(86400));
    app.collect_closed();
    assert_eq!(
        app.retained_sessions(),
        1050,
        "idle sessions remain available"
    );
    initialize(&app).await.unwrap(); // Client's fresh initialization after 404.
    stop(&app).await;
}
#[tokio::test]
async fn live_work_and_active_streams_survive_additional_sessions() {
    let app = fixture();
    let first = initialize(&app).await.unwrap();
    let stream = request(&app, Method::GET, Some(&first), Value::Null).await;
    assert_eq!(stream.status(), StatusCode::OK);
    age(&app, Duration::from_secs(86400));
    app.collect_closed();
    assert!(app.find_session(&first).unwrap().life.is_active());
    drop(stream);
    let mut ids = vec![first];
    for _ in 1..64 {
        ids.push(initialize(&app).await.unwrap());
    }
    for id in &ids {
        app.backend.live.lock().unwrap().insert(
            app.find_session(id)
                .unwrap()
                .life
                .owner
                .owner_id()
                .as_str()
                .to_owned(),
        );
    }
    age(&app, Duration::from_secs(86400));
    app.collect_closed();
    initialize(&app).await.unwrap();
    assert_eq!(app.retained_sessions(), 65);
    for id in &ids {
        assert!(app.find_session(id).unwrap().life.is_active());
    }
    app.backend.live.lock().unwrap().clear();
    let oldest = ids[0].clone();
    app.find_session(&oldest)
        .unwrap()
        .life
        .activity
        .lock()
        .unwrap()
        .last -= Duration::from_secs(86400);
    initialize(&app).await.unwrap();
    assert!(
        app.find_session(&oldest)
            .is_some_and(|s| s.life.is_active()),
        "new sessions must not evict existing owners"
    );
    stop(&app).await;
}
#[tokio::test]
async fn second_post_proceeds_while_first_original_call_is_running() {
    let app = fixture();
    let sid = initialize(&app).await.unwrap();
    let body = json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"exec_command","arguments":{"cmd":"block"}}});
    let response = request(&app, Method::POST, Some(&sid), body).await;
    assert_eq!(response.status(), StatusCode::OK);
    app.backend.started.acquire().await.unwrap().forget();
    let second = request(
        &app,
        Method::POST,
        Some(&sid),
        json!({"jsonrpc":"2.0","id":3,"method":"tools/list"}),
    );
    let r = tokio::time::timeout(Duration::from_secs(1), second)
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    r.into_body().collect().await.unwrap();
    app.backend.release.add_permits(1);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    assert!(bytes.len() <= MESSAGE_BYTES + 1024);
    assert!(bytes.len() > MESSAGE_BYTES - 2048);
    println!(
        "second concurrent POST=200 before first call completes; near-ceiling SSE bytes={}",
        bytes.len()
    );
    stop(&app).await;
}

/// Run alone with --test-threads=1 for RSS measurements; parallel tests
/// share this process and are deliberately not used as a memory verdict.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[tokio::test]
async fn session_memory_measurement() {
    #[allow(unsafe_code)] // glibc's pointer-free, read-only allocator statistics ABI.
    fn allocated() -> usize {
        let info = unsafe { libc::mallinfo2() };
        info.uordblks + info.hblkhd
    }
    let app = fixture();
    // Warm lazy SDK caches and allocator arenas before sampling steady state.
    let warm = initialize(&app).await.unwrap();
    request(&app, Method::DELETE, Some(&warm), Value::Null)
        .await
        .into_body()
        .collect()
        .await
        .unwrap();
    tokio::task::yield_now().await;
    let baseline = allocated();
    let mut ids = vec![];
    for _ in 0..64 {
        ids.push(initialize(&app).await.unwrap());
    }
    let idle = allocated().saturating_sub(baseline);
    let before_stream = allocated();
    let response=request(&app,Method::POST,Some(&ids[0]),json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"exec_command","arguments":{"cmd":"block"}}})).await;
    app.backend.started.acquire().await.unwrap().forget();
    app.backend.release.add_permits(1);
    // Poll exactly one frame; retain it together with the SDK body to include
    // typed-message, serialized SSE and HTTP body overlap, then measure.
    let mut body = response.into_body();
    let frame = body.frame().await.unwrap().unwrap();
    let streaming = allocated().saturating_sub(before_stream);
    println!(
        "SESSION_MEMORY idle_total_64={idle} idle_per_session={} stream_increment={streaming} first_frame={} reservation_per_session={SESSION_BYTES}",
        idle / 64,
        frame.data_ref().map_or(0, Bytes::len)
    );
    drop(frame);
    drop(body);
    stop(&app).await;
}

#[tokio::test]
async fn idle_session_remains_usable_without_reinitialization() {
    let app = fixture();
    let sid = initialize(&app).await.unwrap();
    age(&app, Duration::from_secs(24 * 60 * 60));
    app.collect_closed();
    let r = request(
        &app,
        Method::POST,
        Some(&sid),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK);
    let body = r.into_body().collect().await.unwrap().to_bytes();
    assert!(!String::from_utf8_lossy(&body).contains("Session terminated"));
    assert_eq!(app.status()["expired"], 0);
    stop(&app).await;
}
