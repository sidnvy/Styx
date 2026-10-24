//! Real Core permits, static schema/certainty boundaries; NO Cua/GUI spawned.
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
        deadline: MonotonicMillis(1000),
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
fn fixed_public_tools_and_native_inventory_cannot_become_arbitrary_rpc() {
    let native: Value = serde_json::from_str(NATIVE_CATALOG).unwrap();
    assert_eq!(native.as_object().unwrap().len(), 64);
    assert!(native.get("run_script").is_some());
    assert!(native.get("run_steps").is_some());
    let schemas = public_schemas().unwrap();
    assert_eq!(schemas.len(), 10);
    for name in schemas.keys() {
        assert!(capability(name).is_ok());
        assert!(native.get(name).is_some());
    }
    for name in [
        "run_script",
        "run_steps",
        "launch_app",
        "kill_app",
        "start_session",
        "future_tool",
    ] {
        assert!(matches!(
            CuaAction::new(name.into(), Map::new()),
            Err(CuaError::Unsupported)
        ));
    }
    assert!(CuaAction::new("list_apps".into(), Map::new()).is_ok());
    for args in [
        serde_json::json!({"_meta":{}}),
        serde_json::json!({"environment_id":"forged"}),
        serde_json::json!({"owner":"forged"}),
        serde_json::json!({"session":"x".repeat(REQUEST_BYTES)}),
    ] {
        assert!(CuaAction::new("list_apps".into(), args.as_object().unwrap().clone()).is_err());
    }
    // A capture grant is not an arbitrary current-user file overwrite grant.
    for name in ["get_window_state", "get_desktop_state"] {
        let args = serde_json::json!({"pid":123,"screenshot_out_file":"/tmp/unowned-output.png"});
        assert!(matches!(
            CuaAction::new(name.into(), args.as_object().unwrap().clone()),
            Err(CuaError::InvalidRequest)
        ));
    }
    assert!(bounded_bytes(&"x".repeat(FRAME_BYTES), FRAME_BYTES).is_err());
}
#[tokio::test]
async fn exact_core_target_owner_and_session_are_required_and_io_credit_is_exclusive() {
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
    let action = CuaAction::new("list_apps".into(), Map::new()).unwrap();
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
    let allocator = Arc::new(Semaphore::new(IO_BYTES));
    let partition = allocator
        .clone()
        .acquire_many_owned(IO_BYTES as u32)
        .await
        .unwrap();
    let budget = CuaIoBudget::from_reserved(partition).unwrap();
    let worker = CuaWorker::new(budget);
    let first = worker.try_reserve_open().unwrap();
    assert!(matches!(worker.try_reserve_open(), Err(CuaError::Busy)));
    drop(first);
    assert!(worker.try_reserve_open().is_ok());
    assert_eq!(allocator.available_permits(), 0);
}
