//! Real admitted transport and rmcp calls exercise the production invocation path.
use super::fake_driver::FakeDriver;
use super::*;

async fn driver(delay: Duration) -> FakeDriver {
    FakeDriver::start_delayed(
        serde_json::json!({}),
        CallToolResult::structured(serde_json::json!({"effect":"acknowledged"})),
        delay,
    )
    .await
}

#[tokio::test]
async fn no_deadline_allows_one_native_reply_beyond_the_old_ten_second_budget() {
    let driver = driver(Duration::from_millis(10_200)).await;
    let started = Instant::now();
    let (evidence, reply, error) = driver_result::invoke(
        &driver.peer,
        CallToolRequestParams::new("click"),
        &CancellationToken::new(),
        None,
    )
    .await;
    assert!(started.elapsed() >= Duration::from_secs(10));
    assert_eq!(evidence, CuaEvidence::Acknowledged);
    assert!(reply.is_some());
    assert!(error.is_none());
    assert_eq!(driver.calls.lock().unwrap().len(), 1);
    driver.close().await;
}

#[tokio::test]
async fn explicit_deadline_expires_without_replaying_the_native_call() {
    let driver = driver(Duration::from_millis(200)).await;
    let (evidence, reply, error) = driver_result::invoke(
        &driver.peer,
        CallToolRequestParams::new("click"),
        &CancellationToken::new(),
        Some(Instant::now() + Duration::from_millis(50)),
    )
    .await;
    assert_eq!(evidence, CuaEvidence::Unknown);
    assert!(reply.is_none());
    assert!(matches!(error, Some(CuaError::Unknown)));
    assert_eq!(driver.calls.lock().unwrap().len(), 1);
    driver.close().await;
}

#[tokio::test]
async fn cancellation_ends_an_unbounded_inflight_call_and_owner_still_closes() {
    let driver = driver(Duration::from_millis(200)).await;
    let stop = CancellationToken::new();
    let cancel = async {
        while driver.calls.lock().unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
        stop.cancel();
    };
    let invoke = driver_result::invoke(
        &driver.peer,
        CallToolRequestParams::new("click"),
        &stop,
        None,
    );
    let ((evidence, reply, error), ()) = tokio::join!(invoke, cancel);
    assert_eq!(evidence, CuaEvidence::Unknown);
    assert!(reply.is_none());
    assert!(matches!(error, Some(CuaError::Unknown)));
    assert_eq!(driver.calls.lock().unwrap().len(), 1);
    driver.close().await;
}

#[tokio::test]
async fn native_read_options_arrive_unchanged_without_styx_defaults_or_caps() {
    let driver = driver(Duration::ZERO).await;
    for supplied in [
        serde_json::json!({}),
        serde_json::json!({"timeout_ms":5000,"max_elements":4096,"max_depth":128}),
    ] {
        let mut args = serde_json::json!({"pid":42,"window_id":43,"include_screenshot":false})
            .as_object()
            .unwrap()
            .clone();
        args.extend(supplied.as_object().unwrap().clone());
        let action = public_contract::decode("get_window_state", args).unwrap();
        assert!(matches!(
            action.desktop_read_request().unwrap(),
            Some(ax_target::DesktopReadRequest::Accessibility(_))
        ));
        let payload = action.to_operation_payload().unwrap();
        let action: CuaAction = serde_json::from_slice(&payload).unwrap();
        let (evidence, _, _) = driver.call(&action).await;
        assert_eq!(evidence, CuaEvidence::Acknowledged);
        let calls = driver.calls.lock().unwrap();
        let actual = &calls.last().unwrap()["arguments"];
        for key in ["timeout_ms", "max_elements", "max_depth"] {
            assert_eq!(actual.get(key), supplied.get(key), "{key}");
        }
    }
    assert_eq!(driver.calls.lock().unwrap().len(), 2);
    driver.close().await;
}
