//! Slot handoff fixtures, not native desktop acceptance. Fake CUA uses the
//! production MCP transport; a real child wait models the slow process reap.
use super::*;
use crate::providers::cua::fake_driver::FakeDriver;
use rmcp::model::CallToolResult;
use serde_json::json;
use styx_contracts::{error::Recovery, session::SessionIdentity};
use styx_core::session::RegistrationFacts;

async fn fixture() -> (HostCoordinator, HostAuthority, OwnerLease, OwnerLease) {
    let facts = AdmissionFacts {
        device_id: "handoff-device".try_into().unwrap(),
        grant_revision: 1,
        local_policy_allowed: true,
        descriptor: CapabilityDescriptor {
            contract_version: 1,
            capability_id: CapabilityId::ExecRun,
            scope: Scope::Host,
            provider_id: "fixture".try_into().unwrap(),
            configured: true,
            remote_grant: true,
            availability: Availability::Available,
            authorization: Authorization::Granted,
            target_session: None,
            reason: None,
            observed_at: 0,
            observation_generation: 1,
            recovery: Recovery::None,
        },
        session_state: None,
        current_observation: None,
    };
    let (host, authority) = HostCoordinator::new_without_executor(
        OperationLedger::new("handoff-generation".try_into().unwrap()),
        facts,
        2,
    )
    .unwrap();
    let a = authority
        .register_verified_owner("owner-a".try_into().unwrap(), "epoch-a".try_into().unwrap())
        .unwrap();
    let b = authority
        .register_verified_owner("owner-b".try_into().unwrap(), "epoch-b".try_into().unwrap())
        .unwrap();
    let allocator = Arc::new(tokio::sync::Semaphore::new(8 * 1024 * 1024));
    let budget =
        CuaIoBudget::from_reserved(allocator.acquire_many_owned(8 * 1024 * 1024).await.unwrap())
            .unwrap();
    {
        let mut state = host.inner.state.lock().unwrap();
        let registration = state
            .sessions
            .attest(RegistrationFacts {
                id: "handoff-session".try_into().unwrap(),
                identity: SessionIdentity::Linux {
                    uid: nix::unistd::Uid::current().as_raw(),
                    login_instance: "fixture-login".into(),
                    seat: None,
                    compositor_instance: "fixture-compositor".into(),
                    display_identity: "fixture-display".into(),
                },
                agent_instance: "fixture-agent".try_into().unwrap(),
                protocol_version: 1,
                provenance: "synthetic source".into(),
            })
            .unwrap();
        let binding = state.sessions.register(registration).unwrap();
        let binding = state
            .sessions
            .set_state(&binding, styx_contracts::session::SessionState::Connecting)
            .unwrap();
        state
            .sessions
            .provider(
                &binding,
                ProviderEvidence {
                    capability: CapabilityId::DesktopWindowsRead,
                    provider: "fixture".try_into().unwrap(),
                    availability: Availability::Available,
                    authorization: Authorization::Granted,
                    provenance: "fake CUA; not OS evidence".into(),
                    reason: None,
                    recovery: Recovery::None,
                },
                Duration::from_secs(60),
            )
            .unwrap();
        state.desktop = Some(test_lane(binding, budget));
    }
    (host, authority, a, b)
}
fn prepare(host: &HostCoordinator, owner: &OwnerLease, budget: Duration) -> OperationSnapshot {
    let mut state = host.inner.state.lock().unwrap();
    let context = PreparedContext {
        device_id: state.facts.device_id.clone(),
        grant_revision: 1,
        session: Some(desktop(&state).unwrap().binding.clone()),
        observation: None,
        capability: CapabilityId::DesktopWindowsRead,
        deadline: MonotonicMillis(host.now().0 + budget.as_millis() as u64),
        disconnect_policy: DisconnectPolicy::RetainForOwner,
    };
    state
        .ledger
        .prepare_desktop_agent(owner, context, b"fixture-open".to_vec(), host.now())
        .unwrap()
}
fn running(host: &HostCoordinator, owner: &OwnerLease, open: &OperationSnapshot) {
    let mut state = host.inner.state.lock().unwrap();
    let admission = facts(&state, CapabilityId::DesktopWindowsRead).unwrap();
    assert!(matches!(
        state
            .ledger
            .dispatch(owner, &open.id, open.payload_digest, &admission, host.now())
            .unwrap(),
        DispatchDisposition::ExecuteOnce(_)
    ));
    state
        .ledger
        .record_executor_fact(&open.id, ExecutorFact::Running, host.now())
        .unwrap();
}
async fn action(driver: &FakeDriver) {
    let action = CuaAction::new("list_windows".into(), Default::default()).unwrap();
    assert_eq!(driver.call(&action).await.0, CuaEvidence::Acknowledged);
    assert_eq!(driver.calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn desktop_open_waits_for_closing_owner_reap_but_refuses_live_owner() {
    let (host, authority, a, b) = fixture().await;
    let open_a = prepare(&host, &a, Duration::from_secs(10));
    let DesktopOpenAdmission {
        execution: execution_a,
        slot: slot_a,
        ..
    } = host
        .reserve_desktop_open(&a, &open_a.id, open_a.payload_digest)
        .await
        .unwrap();
    let slot_a = slot_a.unwrap();
    running(&host, &a, &open_a);
    drop(execution_a);
    let driver_a =
        FakeDriver::start(json!({}), CallToolResult::structured(json!({"windows":[]}))).await;
    action(&driver_a).await;
    let open_b = prepare(&host, &b, Duration::from_secs(10));
    let DesktopOpenAdmission { slot: refused, .. } = tokio::time::timeout(
        Duration::from_millis(250),
        host.reserve_desktop_open(&b, &open_b.id, open_b.payload_digest),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        matches!(refused, Err(CuaError::Busy)),
        "a live owner's context must refuse admission"
    );
    authority.fence_owner_for_cleanup(&a).unwrap();
    let teardown_host = host.clone();
    let teardown = tokio::spawn(async move {
        // The original worker slot remains owned until actual child reap and
        // the original MCP transport join, even if an open waiter is dropped.
        let mut child = tokio::process::Command::new("/bin/sleep")
            .arg("1.5")
            .spawn()
            .unwrap();
        driver_a.close().await;
        assert!(child.wait().await.unwrap().success());
        let mut state = teardown_host.inner.state.lock().unwrap();
        state
            .ledger
            .record_executor_fact(
                &open_a.id,
                ExecutorFact::Exited { successful: true },
                teardown_host.now(),
            )
            .unwrap();
        state
            .ledger
            .record_executor_fact(&open_a.id, ExecutorFact::OutputDrained, teardown_host.now())
            .unwrap();
        drop(slot_a);
    });
    let started = Instant::now();
    let DesktopOpenAdmission {
        execution: execution_b,
        slot: slot_b,
        ..
    } = host
        .reserve_desktop_open(&b, &open_b.id, open_b.payload_digest)
        .await
        .unwrap();
    let slot_b = slot_b.expect("closing owner's slot must be awaited instead of refused");
    assert!(started.elapsed() >= Duration::from_millis(1400));
    teardown.await.unwrap();
    running(&host, &b, &open_b);
    drop(execution_b);
    let driver_b =
        FakeDriver::start(json!({}), CallToolResult::structured(json!({"windows":[]}))).await;
    action(&driver_b).await;
    driver_b.close().await;
    drop(slot_b);
}

#[tokio::test]
async fn desktop_open_teardown_wait_obeys_deadline_and_preserves_original_slot() {
    let (host, authority, a, b) = fixture().await;
    let open_a = prepare(&host, &a, Duration::from_secs(10));
    let DesktopOpenAdmission {
        execution, slot, ..
    } = host
        .reserve_desktop_open(&a, &open_a.id, open_a.payload_digest)
        .await
        .unwrap();
    let slot = slot.unwrap();
    running(&host, &a, &open_a);
    drop(execution);
    authority.fence_owner_for_cleanup(&a).unwrap();
    let abandoned = prepare(&host, &b, Duration::from_secs(10));
    {
        let waiting = host.reserve_desktop_open(&b, &abandoned.id, abandoned.payload_digest);
        tokio::pin!(waiting);
        assert!(futures_util::poll!(&mut waiting).is_pending());
    }
    assert_eq!(
        host.inspect_desktop(&b, &abandoned.id, abandoned.payload_digest, false)
            .unwrap()
            .state,
        OperationState::Reserved
    );
    let open_b = prepare(&host, &b, Duration::from_millis(100));
    let started = Instant::now();
    let result = host
        .reserve_desktop_open(&b, &open_b.id, open_b.payload_digest)
        .await;
    assert!(matches!(result, Err(CoordinatorError::Busy)));
    assert!(started.elapsed() >= Duration::from_millis(90));
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(
        host.inspect_desktop(&b, &open_b.id, open_b.payload_digest, false)
            .unwrap()
            .state,
        OperationState::Reserved
    );
    assert!(matches!(
        desktop(&host.inner.state.lock().unwrap())
            .unwrap()
            .worker
            .try_reserve_open(),
        Err(CuaError::Busy)
    ));
    drop(slot);
}

#[tokio::test]
async fn desktop_open_waits_for_cleanup_gate_without_holding_worker_or_job_slots() {
    let (host, _, _, b) = fixture().await;
    let open = prepare(&host, &b, Duration::from_secs(10));
    let writer = host.inner.execution_gate.clone().write_owned().await;
    let waiting = host.reserve_desktop_open(&b, &open.id, open.payload_digest);
    tokio::pin!(waiting);
    assert!(futures_util::poll!(&mut waiting).is_pending());
    assert_eq!(host.inner.slots.available_permits(), 2);
    let worker_slot = desktop(&host.inner.state.lock().unwrap())
        .unwrap()
        .worker
        .try_reserve_open()
        .unwrap();
    drop(worker_slot);
    drop(writer);
    let admission = waiting.await.unwrap();
    assert!(
        admission.waited,
        "source facts must refresh after cleanup's write gate"
    );
    assert!(admission.slot.is_ok());
}
