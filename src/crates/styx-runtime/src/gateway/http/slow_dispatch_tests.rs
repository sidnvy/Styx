//! Real SDK HTTP/SSE regression: a slow executor must not lose its response
//! merely because the response body has existed for thirty seconds.
use super::lifecycle::{OwnerCleanup, OwnerFenceError};
use super::*;
use rmcp::{
    ErrorData,
    model::{
        CallToolRequestParams, CallToolResult, ContentBlock, ListToolsResult,
        PaginatedRequestParams,
    },
};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicUsize, Ordering};

struct SlowBackend {
    calls: AtomicUsize,
    entered: Semaphore,
    release: Semaphore,
}
impl GatewayToolBackend for SlowBackend {
    async fn list_tools(
        &self,
        _: &VerifiedGatewayOwner,
        _: Option<PaginatedRequestParams>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult::default())
    }
    async fn call_tool(
        &self,
        _: &VerifiedGatewayOwner,
        _: CallToolRequestParams,
    ) -> Result<CallToolResult, ErrorData> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.entered.add_permits(1);
        self.release.acquire().await.unwrap().forget();
        Ok(CallToolResult::success(vec![ContentBlock::text(
            "slow-original-result",
        )]))
    }
}
impl GatewayOwnerLifecycle for SlowBackend {
    fn owner_has_live_work(&self, _: &VerifiedGatewayOwner) -> bool {
        false
    }
    fn fence_owner(&self, owner: &VerifiedGatewayOwner) -> Result<(), OwnerFenceError> {
        owner.fence();
        Ok(())
    }
    async fn cleanup_owner(&self, _: &VerifiedGatewayOwner, _: Duration) -> OwnerCleanup {
        OwnerCleanup::Complete
    }
}
fn fixture() -> Arc<GatewayHttp<SlowBackend>> {
    GatewayHttp::new(
        Arc::new(
            GatewayBearerPolicy::new(
                b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                vec!["localhost".into()],
                vec![],
            )
            .unwrap(),
        ),
        Arc::new(SlowBackend {
            calls: AtomicUsize::new(0),
            entered: Semaphore::new(0),
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
async fn request(
    app: &GatewayHttp<SlowBackend>,
    sid: Option<&str>,
    message: Value,
) -> Response<HeldBody> {
    let mut req = Request::builder()
        .method(Method::POST)
        .uri("/mcp")
        .header("host", "localhost")
        .header("authorization", "Bearer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream");
    if let Some(sid) = sid {
        req = req.header(SID, sid).header(VERSION, "2025-11-25");
    }
    app.handle_inner(
        req.body(Full::new(Bytes::from(
            serde_json::to_vec(&message).unwrap(),
        )))
        .unwrap(),
    )
    .await
}
#[tokio::test(start_paused = true)]
async fn slow_http_result_survives_thirty_seconds_and_same_session_continues() {
    let app = fixture();
    let init = request(&app, None, json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"slow-http","version":"1"}
    }})).await;
    assert_eq!(init.status(), StatusCode::OK);
    let sid = init.headers()[SID].to_str().unwrap().to_owned();
    init.into_body().collect().await.unwrap();
    let initialized = request(
        &app,
        Some(&sid),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    )
    .await;
    assert_eq!(initialized.status(), StatusCode::ACCEPTED);
    initialized.into_body().collect().await.unwrap();

    let response = request(
        &app,
        Some(&sid),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
            "name":"exec_command","arguments":{"cmd":"slow-owned-fixture"}
        }}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    app.backend.entered.acquire().await.unwrap().forget();
    let mut body = response.into_body();
    tokio::time::advance(Duration::from_secs(31)).await;
    // Actually poll the production body while work is still pending. The old
    // absolute timer returns clean EOF here, before the result can exist.
    let observed = {
        let next = body.frame();
        tokio::pin!(next);
        futures_util::poll!(next)
    };
    assert!(
        !matches!(observed, std::task::Poll::Ready(None)),
        "HTTP body silently ended before the original tool finished"
    );
    if let std::task::Poll::Ready(Some(frame)) = observed {
        frame.unwrap(); // An SDK keep-alive is allowed; an error is not.
    }
    app.backend.release.add_permits(1);
    let result = body.collect().await.unwrap().to_bytes();
    assert!(String::from_utf8_lossy(&result).contains("slow-original-result"));
    let next = request(
        &app,
        Some(&sid),
        json!({"jsonrpc":"2.0","id":3,"method":"tools/list"}),
    )
    .await;
    assert_eq!(next.status(), StatusCode::OK);
    next.into_body().collect().await.unwrap();
    assert!(app.find_session(&sid).unwrap().life.is_active());
    let stopped = app
        .paired_shutdown_handle()
        .shutdown(Duration::from_secs(5))
        .await;
    assert!(stopped.lifecycle_jobs_joined && stopped.session_transports_joined);
}

#[tokio::test(start_paused = true)]
async fn dropped_sse_resumes_original_result_without_second_tool_dispatch() {
    let app = fixture();
    let init = request(&app, None, json!({"jsonrpc":"2.0","id":10,"method":"initialize","params":{
        "protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"resume-http","version":"1"}
    }})).await;
    assert_eq!(init.status(), StatusCode::OK);
    let sid = init.headers()[SID].to_str().unwrap().to_owned();
    init.into_body().collect().await.unwrap();
    let initialized = request(
        &app,
        Some(&sid),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    )
    .await;
    assert_eq!(initialized.status(), StatusCode::ACCEPTED);
    initialized.into_body().collect().await.unwrap();
    let response = request(
        &app,
        Some(&sid),
        json!({"jsonrpc":"2.0","id":11,"method":"tools/call","params":{
            "name":"exec_command","arguments":{"cmd":"resume-owned-fixture"}
        }}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    app.backend.entered.acquire().await.unwrap().forget();
    let mut body = response.into_body();
    // Use the SDK's real priming event, never manufacture a cursor or reissue
    // tools/call. Losing this HTTP body must leave the original work alive.
    let first = body.frame().await.expect("SDK SSE priming event").unwrap();
    let first = first.into_data().expect("SSE data frame");
    let first = String::from_utf8(first.to_vec()).unwrap();
    let cursor = first
        .lines()
        .find_map(|line| line.strip_prefix("id:").map(str::trim))
        .expect("SDK priming event supplies a resumable Last-Event-ID")
        .to_owned();
    drop(body);
    let resumed = app
        .handle_inner(
            Request::builder()
                .method(Method::GET)
                .uri("/mcp")
                .header("host", "localhost")
                .header("authorization", "Bearer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .header("accept", "text/event-stream")
                .header(SID, &sid)
                .header(VERSION, "2025-11-25")
                .header("last-event-id", cursor)
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await;
    assert_eq!(
        resumed.status(),
        StatusCode::OK,
        "resume must use the SDK's retained stream"
    );
    app.backend.release.add_permits(1);
    let result = resumed.into_body().collect().await.unwrap().to_bytes();
    assert!(String::from_utf8_lossy(&result).contains("slow-original-result"));
    assert_eq!(app.backend.calls.load(Ordering::SeqCst), 1);
    assert!(app.find_session(&sid).unwrap().life.is_active());
    let stopped = app
        .paired_shutdown_handle()
        .shutdown(Duration::from_secs(5))
        .await;
    assert!(stopped.lifecycle_jobs_joined && stopped.session_transports_joined);
}
