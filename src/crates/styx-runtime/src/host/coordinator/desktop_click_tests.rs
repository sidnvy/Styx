//! Synthetic session authority and real proc identity, with an owned duplex driver.
//! These verify dispatch boundaries, not native desktop effects.
use super::*;
use crate::providers::cua::{
    CuaEvidence, CuaIoBudget, ax_snapshot::parse_observed, fake_driver::FakeDriver,
};
use rmcp::model::CallToolResult;
use serde_json::{Value, json};
use styx_contracts::{
    error::Recovery,
    session::{SessionIdentity, SessionState},
};

fn context() -> PreparedContext {
    PreparedContext {
        device_id: "desktop-fixture".try_into().unwrap(),
        grant_revision: 1,
        session: None,
        observation: None,
        capability: CapabilityId::DesktopWindowsRead,
        deadline: MonotonicMillis(10000),
        disconnect_policy: DisconnectPolicy::RetainForOwner,
    }
}
fn evidence(capability: CapabilityId) -> crate::session::ProviderEvidence {
    crate::session::ProviderEvidence {
        capability,
        provider: "cua-native".try_into().unwrap(),
        availability: Availability::Available,
        authorization: Authorization::Granted,
        provenance: "fake driver facts; not OS acceptance".into(),
        reason: None,
        recovery: Recovery::None,
    }
}
async fn fixture() -> (State, OwnerLease, ResourceTarget) {
    let facts = AdmissionFacts {
        device_id: context().device_id,
        grant_revision: 1,
        local_policy_allowed: true,
        descriptor: CapabilityDescriptor {
            contract_version: styx_contracts::CONTRACT_VERSION,
            capability_id: CapabilityId::ExecRun,
            scope: Scope::Host,
            provider_id: "codex".try_into().unwrap(),
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
    let mut state = State::new(
        OperationLedger::new("desktop-generation".try_into().unwrap()),
        facts,
        Instant::now(),
    );
    let owner = state
        .ledger
        .register_verified_owner(
            "desktop-owner".try_into().unwrap(),
            "desktop-epoch".try_into().unwrap(),
        )
        .unwrap();
    let registration = state
        .sessions
        .attest(styx_core::session::RegistrationFacts {
            id: "desktop-session".try_into().unwrap(),
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
        .set_state(&binding, SessionState::Connecting)
        .unwrap();
    for cap in [
        CapabilityId::DesktopWindowsRead,
        CapabilityId::DesktopAccessibility,
        CapabilityId::DesktopCapture,
        CapabilityId::DesktopPointer,
        CapabilityId::DesktopWindowsControl,
    ] {
        state
            .sessions
            .provider(&binding, evidence(cap), Duration::from_secs(60))
            .unwrap();
    }
    let allocator = Arc::new(tokio::sync::Semaphore::new(8 * 1024 * 1024));
    let budget =
        CuaIoBudget::from_reserved(allocator.acquire_many_owned(8 * 1024 * 1024).await.unwrap())
            .unwrap();
    state.desktop = Some(super::super::desktop::test_lane(binding.clone(), budget));
    let mut context = context();
    context.session = Some(binding);
    let open = state
        .ledger
        .prepare_desktop_agent(
            &owner,
            context,
            b"synthetic-open".to_vec(),
            MonotonicMillis(0),
        )
        .unwrap();
    let facts = super::super::desktop::facts(&state, CapabilityId::DesktopWindowsRead).unwrap();
    assert!(matches!(
        state
            .ledger
            .dispatch(
                &owner,
                &open.id,
                open.payload_digest,
                &facts,
                MonotonicMillis(0)
            )
            .unwrap(),
        DispatchDisposition::ExecuteOnce(_)
    ));
    state
        .ledger
        .record_executor_fact(&open.id, ExecutorFact::Running, MonotonicMillis(0))
        .unwrap();
    let resource = ResourceTarget {
        operation_id: open.id,
        payload_digest: open.payload_digest,
    };
    let pid = std::process::id();
    // Query projection has fewer returned elements than the complete walk.
    let read = CallToolResult::structured(
        json!({"pid":pid,"window_id":42,"elements_complete":true,"truncated":false,"element_count":2,"total_element_count":2,"returned_element_count":1,"snapshot_id":"s00000001","tree_markdown":"native text","elements":[{"element_index":1,"element_token":"s00000001:1","role":"button","depth":0,"name":"Confirm"}]}),
    );
    let parsed = parse_observed(&read, pid, 42).unwrap();
    let request = CuaAction::new(
        "get_window_state".into(),
        json!({"pid":pid,"window_id":42,"include_screenshot":false})
            .as_object()
            .unwrap()
            .clone(),
    )
    .unwrap()
    .snapshot_request()
    .unwrap()
    .unwrap();
    let target = DesktopReadTarget::acquire(request).unwrap();
    install(
        &mut state,
        &owner,
        &resource,
        AcquiredAxObservation {
            target,
            parsed,
            alias: "s00000002".into(),
            source_epoch: 1,
            read_capabilities: vec![
                CapabilityId::DesktopAccessibility,
                CapabilityId::DesktopCapture,
            ],
        },
    )
    .unwrap();
    (state, owner, resource)
}
fn click(token: &str) -> CuaAction {
    CuaAction::new(
        "click".into(),
        json!({"element_token":token}).as_object().unwrap().clone(),
    )
    .unwrap()
}
fn prepare(
    state: &State,
    owner: &OwnerLease,
    resource: &ResourceTarget,
    action: &CuaAction,
) -> Result<(CuaAction, PreparedContext), CoordinatorError> {
    let (action, observation) =
        prepare_click(state, owner, resource, &action.click_request()?.unwrap())?;
    let mut context = context();
    context.capability = CapabilityId::DesktopPointer;
    context.session = Some(desktop(state)?.binding.clone());
    context.observation = Some(observation);
    Ok((action, context))
}
#[tokio::test]
async fn desktop_click_fresh_token_dispatches_once_and_unknown_is_never_replayed() {
    for unknown in [false, true] {
        let (mut state, owner, resource) = fixture().await;
        let (action, context) = prepare(&state, &owner, &resource, &click("s00000002:1")).unwrap();
        assert_eq!(
            action.click_request().unwrap().unwrap().element_token,
            "s00000001:1"
        );
        assert_eq!(action.click_request().unwrap().unwrap().window_id, Some(42));
        // A permissions refresh replaces registry observations, not the retained tree.
        for cap in [
            CapabilityId::DesktopAccessibility,
            CapabilityId::DesktopPointer,
            CapabilityId::DesktopWindowsControl,
        ] {
            state
                .sessions
                .provider(
                    &desktop(&state).unwrap().binding.clone(),
                    evidence(cap),
                    Duration::from_secs(60),
                )
                .unwrap();
        }
        let facts = validate_click_dispatch(
            &state,
            &owner,
            &resource,
            &context,
            &action.click_request().unwrap().unwrap(),
            MonotonicMillis(1),
        )
        .unwrap();
        let reserved = state
            .ledger
            .prepare_targeted(
                &owner,
                resource.clone(),
                context.clone(),
                action.to_operation_payload().unwrap(),
                MonotonicMillis(1),
            )
            .unwrap();
        let DispatchDisposition::ExecuteOnce(permit) = state
            .ledger
            .dispatch(
                &owner,
                &reserved.id,
                reserved.payload_digest,
                &facts,
                MonotonicMillis(1),
            )
            .unwrap()
        else {
            panic!("expected one permit");
        };
        let retained = state
            .desktop
            .as_mut()
            .unwrap()
            .ax_observation
            .take()
            .unwrap();
        retained
            .recheck_click(
                &state,
                &owner,
                &reserved.id,
                reserved.payload_digest,
                MonotonicMillis(1),
            )
            .unwrap();
        let mut reply = CallToolResult::structured(if unknown {
            json!({"code":"ax_timeout","effect":"unknown"})
        } else {
            json!({"path":"ax","effect":"unverifiable"})
        });
        reply.is_error = Some(unknown);
        let driver = FakeDriver::start(Value::Null, reply).await;
        let actual: CuaAction = serde_json::from_slice(permit.payload()).unwrap();
        let (evidence, _, _) = driver.call(&actual).await;
        assert_eq!(
            evidence,
            if unknown {
                CuaEvidence::Unknown
            } else {
                CuaEvidence::Acknowledged
            }
        );
        state
            .ledger
            .record_action_result(
                &reserved.id,
                if unknown {
                    ActionResult::Unknown
                } else {
                    ActionResult::Acknowledged
                },
                MonotonicMillis(2),
            )
            .unwrap();
        assert!(matches!(
            state
                .ledger
                .dispatch(
                    &owner,
                    &reserved.id,
                    reserved.payload_digest,
                    &facts,
                    MonotonicMillis(2)
                )
                .unwrap(),
            DispatchDisposition::Existing(_)
        ));
        assert!(prepare(&state, &owner, &resource, &click("s00000002:1")).is_err());
        assert_eq!(driver.calls.lock().unwrap().len(), 1);
        driver.close().await;
    }
}
#[tokio::test]
async fn desktop_click_wrong_stale_expired_and_ungranted_targets_never_dispatch() {
    let (mut state, owner, resource) = fixture().await;
    let driver = FakeDriver::start(Value::Null, CallToolResult::structured(Value::Null)).await;
    for token in ["s00000001:1", "s00000003:1", "s00000002:0"] {
        assert!(prepare(&state, &owner, &resource, &click(token)).is_err());
    }
    let other = CuaAction::new(
        "click".into(),
        json!({"window_id":43,"element_token":"s00000002:1"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .unwrap();
    assert!(prepare(&state, &owner, &resource, &other).is_err());
    let (action, context) = prepare(&state, &owner, &resource, &click("s00000002:1")).unwrap();
    for cap in [
        CapabilityId::DesktopPointer,
        CapabilityId::DesktopAccessibility,
        CapabilityId::DesktopWindowsControl,
        CapabilityId::DesktopCapture,
    ] {
        state
            .desktop
            .as_mut()
            .unwrap()
            .grants
            .get_mut(&cap)
            .unwrap()
            .remote_grant = false;
        assert!(
            validate_click_dispatch(
                &state,
                &owner,
                &resource,
                &context,
                &action.click_request().unwrap().unwrap(),
                MonotonicMillis(1)
            )
            .is_err()
        );
        state
            .desktop
            .as_mut()
            .unwrap()
            .grants
            .get_mut(&cap)
            .unwrap()
            .remote_grant = true;
    }
    state
        .desktop
        .as_mut()
        .unwrap()
        .ax_observation
        .as_mut()
        .unwrap()
        .observed_at -= Duration::from_secs(30);
    assert!(prepare(&state, &owner, &resource, &click("s00000002:1")).is_err());
    assert!(
        validate_click_dispatch(
            &state,
            &owner,
            &resource,
            &context,
            &action.click_request().unwrap().unwrap(),
            MonotonicMillis(1)
        )
        .is_err()
    );
    assert_eq!(driver.calls.lock().unwrap().len(), 0);
    driver.close().await;
}

#[tokio::test]
async fn desktop_click_requires_current_os_evidence_and_latest_owned_window_read() {
    let (mut state, owner, resource) = fixture().await;
    let (action, context) = prepare(&state, &owner, &resource, &click("s00000002:1")).unwrap();
    let binding = desktop(&state).unwrap().binding.clone();
    for cap in [
        CapabilityId::DesktopPointer,
        CapabilityId::DesktopAccessibility,
        CapabilityId::DesktopWindowsControl,
        CapabilityId::DesktopCapture,
    ] {
        for authorization in [
            Authorization::Unknown,
            Authorization::Required,
            Authorization::Denied,
            Authorization::Revoked,
        ] {
            let mut refused = evidence(cap);
            refused.authorization = authorization;
            state
                .sessions
                .provider(&binding, refused, Duration::from_secs(60))
                .unwrap();
            assert!(
                validate_click_dispatch(
                    &state,
                    &owner,
                    &resource,
                    &context,
                    &action.click_request().unwrap().unwrap(),
                    MonotonicMillis(1)
                )
                .is_err()
            );
        }
        let mut unavailable = evidence(cap);
        unavailable.availability = Availability::Unavailable;
        state
            .sessions
            .provider(&binding, unavailable, Duration::from_secs(60))
            .unwrap();
        assert!(
            validate_click_dispatch(
                &state,
                &owner,
                &resource,
                &context,
                &action.click_request().unwrap().unwrap(),
                MonotonicMillis(1)
            )
            .is_err()
        );
        state
            .sessions
            .provider(&binding, evidence(cap), Duration::from_secs(60))
            .unwrap();
    }
    let other = state
        .ledger
        .register_verified_owner(
            "other-owner".try_into().unwrap(),
            "other-epoch".try_into().unwrap(),
        )
        .unwrap();
    assert!(prepare(&state, &other, &resource, &click("s00000002:1")).is_err());
    let wrong_pid = CuaAction::new(
        "click".into(),
        json!({"pid":std::process::id()+1,"element_token":"s00000002:1"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .unwrap();
    assert!(prepare(&state, &owner, &resource, &wrong_pid).is_err());
    state
        .desktop
        .as_mut()
        .unwrap()
        .ax_observation
        .as_mut()
        .unwrap()
        .alias = "s00000003".into();
    assert!(prepare(&state, &owner, &resource, &click("s00000002:1")).is_err());
    assert!(prepare(&state, &owner, &resource, &click("s00000003:1")).is_ok());
    let pixel = CuaAction::new(
        "click".into(),
        json!({"pid":std::process::id(),"window_id":42,"x":1,"y":1})
            .as_object()
            .unwrap()
            .clone(),
    )
    .unwrap();
    assert!(pixel.click_request().is_err());
}

#[tokio::test]
async fn desktop_set_value_retains_its_read_binding_across_permission_refresh() {
    let (mut state, owner, resource) = fixture().await;
    let binding = desktop(&state).unwrap().binding.clone();
    state
        .sessions
        .provider(
            &binding,
            evidence(CapabilityId::DesktopAccessibility),
            Duration::from_secs(60),
        )
        .unwrap();
    let action = CuaAction::new("set_value".into(), json!({"pid":std::process::id(),"window_id":42,"element_token":"s00000002:1","value":"fixture"}).as_object().unwrap().clone()).unwrap();
    let (translated, observation) = super::prepare(
        &state,
        &owner,
        &resource,
        &action.accessibility_write_request().unwrap().unwrap(),
    )
    .unwrap();
    let mut context = context();
    context.capability = CapabilityId::DesktopAccessibility;
    context.session = Some(binding);
    context.observation = Some(observation);
    validate_dispatch(
        &state,
        &owner,
        &resource,
        &context,
        &translated.accessibility_write_request().unwrap().unwrap(),
        MonotonicMillis(1),
    )
    .unwrap();
}
