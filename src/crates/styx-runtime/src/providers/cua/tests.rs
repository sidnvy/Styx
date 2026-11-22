//! Real Core permits, native MCP action boundaries; NO Cua/GUI spawned.
use super::*;
use styx_contracts::{
    capability::*, error::Recovery, identity::*, operation::*, session::SessionState,
};
use styx_core::{
    operations::{DispatchDisposition, ExecutorFact, OperationLedger},
    policy::AdmissionFacts,
};
fn session(generation: &str) -> SessionBinding {
    SessionBinding {
        id: SessionId::try_from("owned-login").unwrap(),
        generation: SessionGeneration::try_from(generation).unwrap(),
    }
}
fn authority() -> (
    OperationLedger,
    OwnerLease,
    OwnerLease,
    AdmissionFacts,
    PreparedContext,
) {
    let mut ledger = OperationLedger::new(HostGeneration::try_from("cua-contract-host").unwrap());
    let owner = ledger
        .register_verified_owner("owner-a".try_into().unwrap(), "epoch-a".try_into().unwrap())
        .unwrap();
    let other = ledger
        .register_verified_owner("owner-b".try_into().unwrap(), "epoch-b".try_into().unwrap())
        .unwrap();
    let context = PreparedContext {
        device_id: "device-a".try_into().unwrap(),
        grant_revision: 1,
        session: Some(session("generation-a")),
        observation: None,
        capability: CapabilityId::DesktopWindowsRead,
        deadline: Some(MonotonicMillis(1000)),
        disconnect_policy: DisconnectPolicy::RetainForOwner,
    };
    let facts = AdmissionFacts {
        device_id: context.device_id.clone(),
        grant_revision: 1,
        local_policy_allowed: true,
        descriptor: CapabilityDescriptor {
            contract_version: 1,
            capability_id: context.capability,
            scope: Scope::Session,
            provider_id: "cua-contract".try_into().unwrap(),
            configured: true,
            remote_grant: true,
            availability: Availability::Available,
            authorization: Authorization::Granted,
            target_session: context.session.clone(),
            reason: None,
            observed_at: 0,
            observation_generation: 1,
            recovery: Recovery::None,
        },
        session_state: Some(SessionState::Ready),
        current_observation: None,
    };
    (ledger, owner, other, facts, context)
}

#[test]
fn native_cua_action_forwards_arbitrary_native_tools_and_bounds_invalid_inputs() {
    assert!(CuaAction::list_tools(None).is_ok());
    assert!(CuaAction::list_tools(Some(vec!["click".into(), "run_steps".into()])).is_ok());
    assert!(CuaAction::list_tools(Some(vec!["".into()])).is_err());

    for name in [
        "list_apps",
        "list_windows",
        "get_window_state",
        "click",
        "set_value",
        "type_text",
        "press_key",
        "scroll",
        "run_steps",
        "run_script",
        "get_guide",
        "browser_click",
    ] {
        let action = CuaAction::call_tool(name.into(), Map::new()).unwrap();
        assert_eq!(
            action.capability().unwrap(),
            CapabilityId::DesktopWindowsRead
        );
        let payload = action.to_operation_payload().unwrap();
        let roundtrip: CuaAction = serde_json::from_slice(&payload).unwrap();
        assert_eq!(roundtrip, action);
    }
    assert!(CuaAction::call_tool("".into(), Map::new()).is_err());
    assert!(CuaAction::call_tool("bad\nname".into(), Map::new()).is_err());
    assert_eq!(FRAME_BYTES, styx_contracts::DESKTOP_BROWSER_FRAME_BYTES);
}

#[tokio::test]
async fn exact_core_target_owner_and_session_are_required_without_exclusive_io_credit() {
    let (mut ledger, owner, other, facts, context) = authority();
    let open = ledger
        .prepare_desktop_agent(
            &owner,
            context.clone(),
            b"synthetic-open".to_vec(),
            MonotonicMillis(1),
        )
        .unwrap();
    let DispatchDisposition::ExecuteOnce(open_permit) = ledger
        .dispatch(
            &owner,
            &open.id,
            open.payload_digest,
            &facts,
            MonotonicMillis(2),
        )
        .unwrap()
    else {
        panic!("new open")
    };
    drop(open_permit);
    ledger
        .record_executor_fact(&open.id, ExecutorFact::Running, MonotonicMillis(3))
        .unwrap();
    let target = ResourceTarget {
        operation_id: open.id,
        payload_digest: open.payload_digest,
    };
    let action = CuaAction::call_tool("list_apps".into(), Map::new()).unwrap();
    let pending = ledger
        .prepare_targeted(
            &owner,
            target.clone(),
            context.clone(),
            action.to_operation_payload().unwrap(),
            MonotonicMillis(4),
        )
        .unwrap();
    let DispatchDisposition::ExecuteOnce(permit) = ledger
        .dispatch(
            &owner,
            &pending.id,
            pending.payload_digest,
            &facts,
            MonotonicMillis(5),
        )
        .unwrap()
    else {
        panic!("new action")
    };
    assert!(
        permit_binding(
            &permit,
            &owner,
            &target,
            &session("generation-a"),
            CapabilityId::DesktopWindowsRead
        )
        .is_ok()
    );
    assert!(
        permit_binding(
            &permit,
            &other,
            &target,
            &session("generation-a"),
            CapabilityId::DesktopWindowsRead
        )
        .is_err()
    );
    assert!(
        permit_binding(
            &permit,
            &owner,
            &target,
            &session("generation-b"),
            CapabilityId::DesktopWindowsRead
        )
        .is_err()
    );
    let wrong = ResourceTarget {
        operation_id: target.operation_id.clone(),
        payload_digest: Sha256Digest::of_bytes(b"other"),
    };
    assert!(
        permit_binding(
            &permit,
            &owner,
            &wrong,
            &session("generation-a"),
            CapabilityId::DesktopWindowsRead
        )
        .is_err()
    );
    assert!(
        permit_binding(
            &permit,
            &owner,
            &target,
            &session("generation-a"),
            CapabilityId::DesktopPointer
        )
        .is_err()
    );
    drop(permit);
    let worker = CuaWorker::new();
    let first = worker.try_reserve_open().unwrap();
    let second = worker
        .try_reserve_open()
        .expect("independent Computer sessions must coexist");
    drop(first);
    drop(second);
    assert!(worker.try_reserve_open().is_ok());
}

#[tokio::test]
async fn caller_deadline_is_optional_and_never_replaced_by_provider_budget() {
    let wait = within(None, std::future::pending::<()>());
    tokio::pin!(wait);
    assert!(futures_util::poll!(&mut wait).is_pending());
    let until = Instant::now();
    assert!(
        within(Some(until), std::future::pending::<()>())
            .await
            .is_err()
    );
    let stop = CancellationToken::new();
    stop.cancel();
    tokio::select! {
        _ = stop.cancelled() => {},
        _ = within(None, std::future::pending::<()>()) => panic!("unbounded wait completed"),
    }
}

#[tokio::test]
async fn list_tools_and_large_multimodal_result_over_old_1mib_limit_pass_through_verbatim() {
    use super::fake_driver::FakeDriver;
    let large_payload = "A".repeat(1_500_000);
    let reply =
        CallToolResult::success(vec![rmcp::model::ContentBlock::text(large_payload.clone())]);
    let driver = FakeDriver::start_delayed(
        serde_json::json!({"click": {"type": "object", "properties": {"pid": {"type": "integer"}}}}),
        reply,
        Duration::ZERO,
    )
    .await;

    // 1. Compact list_tools
    let (ev, res, err) = driver.call(&CuaAction::list_tools(None).unwrap()).await;
    assert_eq!(ev, CuaEvidence::Acknowledged);
    assert!(err.is_none());
    let structured = res.unwrap().structured_content.unwrap();
    assert!(structured["tool_count"].as_u64().unwrap() >= 1);

    // 2. Named list_tools returns full verbatim schema + unavailable_tools
    let (ev, res, err) = driver
        .call(
            &CuaAction::list_tools(Some(vec!["click".into(), "nonexistent_tool".into()])).unwrap(),
        )
        .await;
    assert_eq!(ev, CuaEvidence::Acknowledged);
    assert!(err.is_none());
    let structured = res.unwrap().structured_content.unwrap();
    assert_eq!(
        structured["unavailable_tools"],
        serde_json::json!(["nonexistent_tool"])
    );

    // 3. >1 MiB native tool result passes cleanly through AdmittedTransport (8 MiB ceiling)
    let (ev, res, err) = driver
        .call(&CuaAction::call_tool("get_window_state".into(), Map::new()).unwrap())
        .await;
    assert_eq!(ev, CuaEvidence::Acknowledged);
    assert!(err.is_none());
    let text = res.unwrap().content[0].as_text().unwrap().text.clone();
    assert_eq!(text.len(), 1_500_000);
    driver.close().await;
}
