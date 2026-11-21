//! Synthetic session authority and real proc identity, with an owned duplex driver.
//! These verify dispatch boundaries, not native desktop effects.
use super::*;
use crate::providers::cua::{CuaEvidence, ax_snapshot::parse_observed, fake_driver::FakeDriver};
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
        deadline: Some(MonotonicMillis(10000)),
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
async fn fixture_for_pid(pid: u32) -> (State, OwnerLease, ResourceTarget, FakeDriver) {
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
        CapabilityId::DesktopKeyboard,
        CapabilityId::DesktopWindowsControl,
    ] {
        state
            .sessions
            .provider(&binding, evidence(cap), Duration::from_secs(60))
            .unwrap();
    }
    state.desktop = Some(super::super::desktop::test_lane(binding.clone()));
    let (resource, driver) = open_fixture_resource(&mut state, &owner).await;
    install_fixture_read(&mut state, &owner, &resource, pid, "s00000002");
    (state, owner, resource, driver)
}
async fn open_fixture_resource(
    state: &mut State,
    owner: &OwnerLease,
) -> (ResourceTarget, FakeDriver) {
    let mut context = context();
    context.session = Some(desktop(state).unwrap().binding.clone());
    let open = state
        .ledger
        .prepare_desktop_agent(
            owner,
            context,
            b"synthetic-open".to_vec(),
            MonotonicMillis(0),
        )
        .unwrap();
    let facts = super::super::desktop::facts(state, CapabilityId::DesktopWindowsRead).unwrap();
    assert!(matches!(
        state
            .ledger
            .dispatch(
                owner,
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
    let mut driver = FakeDriver::start(
        Value::Null,
        CallToolResult::structured(json!({"effect":"unverifiable"})),
    )
    .await;
    let lane = state.desktop.as_mut().unwrap();
    let handle = driver.bind_resource(
        &lane.worker,
        owner.clone(),
        resource.clone(),
        lane.binding.clone(),
    );
    lane.handles.insert(
        resource.operation_id.clone(),
        super::super::desktop::DesktopResource {
            handle,
            ax_observation: None,
        },
    );
    (resource, driver)
}
fn fixture_ax_read(pid: u32) -> CallToolResult {
    // Query projection has fewer returned elements than the complete walk.
    CallToolResult::structured(
        json!({"pid":pid,"window_id":42,"elements_complete":true,"truncated":false,"element_count":2,"total_element_count":2,"returned_element_count":1,"snapshot_id":"s00000001","tree_markdown":"native text","elements":[{"element_index":1,"element_token":"s00000001:1","role":"button","depth":0,"name":"Confirm"}]}),
    )
}
fn install_fixture_read(
    state: &mut State,
    owner: &OwnerLease,
    resource: &ResourceTarget,
    pid: u32,
    alias: &str,
) {
    let read = fixture_ax_read(pid);
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
        state,
        owner,
        resource,
        AcquiredAxObservation {
            target,
            parsed,
            alias: alias.into(),
            source_epoch: 1,
            read_capabilities: vec![
                CapabilityId::DesktopAccessibility,
                CapabilityId::DesktopCapture,
            ],
        },
    )
    .unwrap();
}
async fn fixture() -> (State, OwnerLease, ResourceTarget, FakeDriver) {
    fixture_for_pid(std::process::id()).await
}

#[tokio::test]
async fn known_read_refusal_is_delivered_without_read_data_or_replaying_the_action() {
    use super::super::desktop_read::{acquisition_facts, authorize_result};
    use crate::providers::cua::{CuaError, CuaReceipt};
    let (mut state, owner, resource, _resource_driver) = fixture().await;
    let action = CuaAction::new(
        "get_window_state".into(),
        json!({"pid":std::process::id(),"window_id":42,"include_screenshot":false})
            .as_object()
            .unwrap()
            .clone(),
    )
    .unwrap();
    let mut context = context();
    context.session = Some(desktop(&state).unwrap().binding.clone());
    context.capability = CapabilityId::DesktopAccessibility;
    let facts = acquisition_facts(&state, context.capability).unwrap();
    let prepared = state
        .ledger
        .prepare_desktop_read_acquisition(
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
            &prepared.id,
            prepared.payload_digest,
            &facts,
            MonotonicMillis(2),
        )
        .unwrap()
    else {
        panic!("fresh_read")
    };
    drop(permit);
    // This is the real Core settlement produced by the native NotDispatched
    // receipt. The separate opt-in Mac reference supplies actual native proof.
    let failed = state
        .ledger
        .record_action_result(
            &prepared.id,
            ActionResult::NotDispatched,
            MonotonicMillis(3),
        )
        .unwrap();
    assert_eq!(failed.state, OperationState::Failed);
    invalidate(state.desktop.as_mut(), None);
    let mut receipt = CuaReceipt {
        operation: prepared.id.clone(),
        evidence: CuaEvidence::NotDispatched,
        result: Some(CallToolResult::error(vec![
            rmcp::model::ContentBlock::text("window_unavailable"),
        ])),
        cause: Some(CuaError::StaleObservation),
    };
    // No refused native payload becomes read data or an input observation.
    authorize_result(
        &state.ledger,
        &owner,
        &prepared.id,
        prepared.payload_digest,
        &facts,
        MonotonicMillis(4),
        &mut receipt,
    )
    .unwrap();
    assert!(receipt.result.is_none());
    assert!(
        desktop(&state)
            .unwrap()
            .handles
            .get(&resource.operation_id)
            .unwrap()
            .ax_observation
            .is_none()
    );
    assert!(prepare(&state, &owner, &resource, &click("s00000002:1")).is_err());
    assert!(matches!(
        state
            .ledger
            .dispatch(
                &owner,
                &prepared.id,
                prepared.payload_digest,
                &facts,
                MonotonicMillis(4)
            )
            .unwrap(),
        DispatchDisposition::Existing(_)
    ));
    assert!(
        authorize_result(
            &state.ledger,
            &owner,
            &prepared.id,
            Sha256Digest::of_bytes(b"wrong"),
            &facts,
            MonotonicMillis(4),
            &mut receipt
        )
        .is_err()
    );
    let other = state
        .ledger
        .register_verified_owner(
            "other-read-owner".try_into().unwrap(),
            "other-read-epoch".try_into().unwrap(),
        )
        .unwrap();
    assert!(
        authorize_result(
            &state.ledger,
            &other,
            &prepared.id,
            prepared.payload_digest,
            &facts,
            MonotonicMillis(4),
            &mut receipt
        )
        .is_err()
    );

    // A DISTINCT known acquisition on the original resource can still settle;
    // no earlier failure or its stale target is revived.
    let next = state
        .ledger
        .prepare_desktop_read_acquisition(
            &owner,
            resource.clone(),
            context.clone(),
            action.to_operation_payload().unwrap(),
            MonotonicMillis(5),
        )
        .unwrap();
    let DispatchDisposition::ExecuteOnce(permit) = state
        .ledger
        .dispatch(
            &owner,
            &next.id,
            next.payload_digest,
            &facts,
            MonotonicMillis(6),
        )
        .unwrap()
    else {
        panic!("distinct_read")
    };
    drop(permit);
    state
        .ledger
        .record_action_result(&next.id, ActionResult::Acknowledged, MonotonicMillis(7))
        .unwrap();
    let mut acknowledged = CuaReceipt {
        operation: next.id.clone(),
        evidence: CuaEvidence::Acknowledged,
        result: Some(CallToolResult::structured(json!({"read":"new"}))),
        cause: None,
    };
    authorize_result(
        &state.ledger,
        &owner,
        &next.id,
        next.payload_digest,
        &facts,
        MonotonicMillis(8),
        &mut acknowledged,
    )
    .unwrap();
    assert!(acknowledged.result.is_some());

    let unknown = state
        .ledger
        .prepare_desktop_read_acquisition(
            &owner,
            resource,
            context,
            action.to_operation_payload().unwrap(),
            MonotonicMillis(9),
        )
        .unwrap();
    let DispatchDisposition::ExecuteOnce(permit) = state
        .ledger
        .dispatch(
            &owner,
            &unknown.id,
            unknown.payload_digest,
            &facts,
            MonotonicMillis(10),
        )
        .unwrap()
    else {
        panic!("distinct_unknown_read")
    };
    drop(permit);
    state
        .ledger
        .record_action_result(&unknown.id, ActionResult::Unknown, MonotonicMillis(11))
        .unwrap();
    let mut uncertain = CuaReceipt {
        operation: unknown.id.clone(),
        evidence: CuaEvidence::Unknown,
        result: None,
        cause: Some(CuaError::Unknown),
    };
    assert!(
        authorize_result(
            &state.ledger,
            &owner,
            &unknown.id,
            unknown.payload_digest,
            &facts,
            MonotonicMillis(12),
            &mut uncertain
        )
        .is_err()
    );
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
    let (action, observation) = prepare_element_input(
        state,
        owner,
        resource,
        &action.element_input_request()?.unwrap(),
    )?;
    let mut context = context();
    context.capability = action.capability()?;
    context.session = Some(desktop(state)?.binding.clone());
    context.observation = Some(observation);
    Ok((action, context))
}
#[tokio::test]
async fn desktop_click_fresh_token_dispatches_once_and_unknown_is_never_replayed() {
    for (unknown, defaults) in [
        (false, json!({})),
        (true, json!({})),
        (false, json!({"button":"left"})),
        (true, json!({"button":"left"})),
        (false, json!({"delivery_mode":"background"})),
        (true, json!({"delivery_mode":"background"})),
        (false, json!({"button":"left","delivery_mode":"background"})),
        (true, json!({"button":"left","delivery_mode":"background"})),
        (
            false,
            json!({"pid":std::process::id(),"window_id":42,"text":"Chrome 原生输入","delivery_mode":"foreground"}),
        ),
        (
            true,
            json!({"pid":std::process::id(),"window_id":42,"text":"Chrome 原生输入","delivery_mode":"foreground"}),
        ),
    ] {
        let (mut state, owner, resource, _resource_driver) = fixture().await;
        let mut arguments = json!({"element_token":"s00000002:1"})
            .as_object()
            .unwrap()
            .clone();
        arguments.extend(defaults.as_object().unwrap().clone());
        let keyboard = arguments.contains_key("text");
        let request = CuaAction::new(
            if keyboard { "type_text" } else { "click" }.into(),
            arguments,
        )
        .unwrap();
        if !keyboard {
            assert_eq!(
                request.to_operation_payload().unwrap(),
                click("s00000002:1").to_operation_payload().unwrap()
            );
        }
        let (action, context) = prepare(&state, &owner, &resource, &request).unwrap();
        assert_eq!(
            action
                .element_input_request()
                .unwrap()
                .unwrap()
                .element_token,
            "s00000001:1"
        );
        assert_eq!(
            action.element_input_request().unwrap().unwrap().window_id,
            Some(42)
        );
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
        let facts = validate_element_input_dispatch(
            &state,
            &owner,
            &resource,
            &context,
            &action.element_input_request().unwrap().unwrap(),
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
        let retained = take(state.desktop.as_mut(), &resource).unwrap();
        retained
            .recheck_element_input(
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
    let (mut state, owner, resource, _resource_driver) = fixture().await;
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
            validate_element_input_dispatch(
                &state,
                &owner,
                &resource,
                &context,
                &action.element_input_request().unwrap().unwrap(),
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
        .handles
        .get_mut(&resource.operation_id)
        .unwrap()
        .ax_observation
        .as_mut()
        .unwrap()
        .observed_at -= Duration::from_secs(30);
    assert!(prepare(&state, &owner, &resource, &click("s00000002:1")).is_err());
    assert!(
        validate_element_input_dispatch(
            &state,
            &owner,
            &resource,
            &context,
            &action.element_input_request().unwrap().unwrap(),
            MonotonicMillis(1)
        )
        .is_err()
    );
    assert_eq!(driver.calls.lock().unwrap().len(), 0);
    driver.close().await;
}

#[tokio::test]
async fn desktop_click_requires_current_os_evidence_and_latest_owned_window_read() {
    let (mut state, owner, resource, _resource_driver) = fixture().await;
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
                validate_element_input_dispatch(
                    &state,
                    &owner,
                    &resource,
                    &context,
                    &action.element_input_request().unwrap().unwrap(),
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
            validate_element_input_dispatch(
                &state,
                &owner,
                &resource,
                &context,
                &action.element_input_request().unwrap().unwrap(),
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
        .handles
        .get_mut(&resource.operation_id)
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
    assert!(pixel.element_input_request().is_err());
    for unsupported in [
        json!({"button":"right"}),
        json!({"button":"middle"}),
        json!({"delivery_mode":"foreground"}),
    ] {
        let mut arguments = json!({"element_token":"s00000003:1"})
            .as_object()
            .unwrap()
            .clone();
        arguments.extend(unsupported.as_object().unwrap().clone());
        let request = CuaAction::new("click".into(), arguments).unwrap();
        assert!(request.element_input_request().is_err());
        assert!(prepare(&state, &owner, &resource, &request).is_err());
    }
}

#[tokio::test]
async fn desktop_set_value_retains_its_read_binding_across_permission_refresh() {
    let (mut state, owner, resource, _resource_driver) = fixture().await;
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
    let facts = validate_dispatch(
        &state,
        &owner,
        &resource,
        &context,
        &translated.accessibility_write_request().unwrap().unwrap(),
        MonotonicMillis(1),
    )
    .unwrap();
    let action = state
        .ledger
        .prepare_desktop_accessibility_write_attempt(
            &owner,
            resource.clone(),
            context.clone(),
            translated.to_operation_payload().unwrap(),
            MonotonicMillis(1),
        )
        .unwrap();
    let DispatchDisposition::ExecuteOnce(_permit) = state
        .ledger
        .dispatch(
            &owner,
            &action.id,
            action.payload_digest,
            &facts,
            MonotonicMillis(1),
        )
        .unwrap()
    else {
        panic!("expected one write permit");
    };
    let retained = take(state.desktop.as_mut(), &resource).unwrap();
    // The native write ACK is a synthetic result here; test the real result
    // authorization path after a fresh permission observation, not OS effects.
    state
        .ledger
        .record_action_result(&action.id, ActionResult::Acknowledged, MonotonicMillis(2))
        .unwrap();
    let binding = desktop(&state).unwrap().binding.clone();
    state
        .sessions
        .provider(
            &binding,
            evidence(CapabilityId::DesktopAccessibility),
            Duration::from_secs(60),
        )
        .unwrap();
    let refreshed =
        super::super::desktop_read::acquisition_facts(&state, CapabilityId::DesktopAccessibility)
            .unwrap();
    assert_ne!(refreshed.current_observation, context.observation);
    assert!(
        state
            .ledger
            .authorize_desktop_accessibility_write_result(
                &owner,
                &action.id,
                action.payload_digest,
                &refreshed,
                MonotonicMillis(2),
            )
            .is_err()
    );
    let delivery = retained.write_result_facts(&state).unwrap();
    state
        .ledger
        .authorize_desktop_accessibility_write_result(
            &owner,
            &action.id,
            action.payload_digest,
            &delivery,
            MonotonicMillis(2),
        )
        .unwrap();
    let mut denied = evidence(CapabilityId::DesktopAccessibility);
    denied.authorization = Authorization::Denied;
    state
        .sessions
        .provider(&binding, denied, Duration::from_secs(60))
        .unwrap();
    let delivery = retained.write_result_facts(&state).unwrap();
    assert!(
        state
            .ledger
            .authorize_desktop_accessibility_write_result(
                &owner,
                &action.id,
                action.payload_digest,
                &delivery,
                MonotonicMillis(2),
            )
            .is_err()
    );
}

#[tokio::test]
async fn desktop_click_receipt_survives_original_target_exit_but_cannot_authorize_input() {
    let mut child = std::process::Command::new("/bin/sleep")
        .arg("60")
        .spawn()
        .unwrap();
    let (mut state, owner, resource, _resource_driver) = fixture_for_pid(child.id()).await;
    let (action, context) = prepare(&state, &owner, &resource, &click("s00000002:1")).unwrap();
    let request = action.element_input_request().unwrap().unwrap();
    let retained = take(state.desktop.as_mut(), &resource).unwrap();
    retained
        .element_input_facts(
            &state,
            &owner,
            &resource,
            &context,
            &request,
            MonotonicMillis(1),
        )
        .unwrap();
    // Exact owned process exits. A result has no reason to inspect a replacement PID.
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(
        retained
            .element_input_facts(
                &state,
                &owner,
                &resource,
                &context,
                &request,
                MonotonicMillis(2)
            )
            .is_err()
    );
    retained
        .element_input_result_facts(
            &state,
            &owner,
            &resource,
            &context,
            &request,
            MonotonicMillis(2),
        )
        .unwrap();
    let mut wrong = action.element_input_request().unwrap().unwrap();
    wrong.window_id = Some(43);
    assert!(
        retained
            .element_input_result_facts(
                &state,
                &owner,
                &resource,
                &context,
                &wrong,
                MonotonicMillis(2)
            )
            .is_err()
    );
    state.facts.grant_revision += 1;
    assert!(
        retained
            .element_input_result_facts(
                &state,
                &owner,
                &resource,
                &context,
                &request,
                MonotonicMillis(2)
            )
            .is_err()
    );
    assert!(prepare(&state, &owner, &resource, &click("s00000002:1")).is_err());
}

#[tokio::test]
async fn explicit_element_typing_preserves_window_owner_keyboard_and_focus_permissions() {
    let (mut state, owner, resource, _resource_driver) = fixture().await;
    let input = |pid: u32, window: u64, token: &str| {
        CuaAction::new("type_text".into(),
        json!({"pid":pid,"window_id":window,"element_token":token,"text":"fixture text","delivery_mode":"foreground"})
            .as_object().unwrap().clone()).unwrap()
    };
    let pid = std::process::id();
    for action in [
        input(pid, 43, "s00000002:1"),
        input(pid, 42, "s00000001:1"),
        input(pid, 42, "s00000002:0"),
    ] {
        assert!(prepare(&state, &owner, &resource, &action).is_err());
    }
    let (action, context) =
        prepare(&state, &owner, &resource, &input(pid, 42, "s00000002:1")).unwrap();
    assert_eq!(context.capability, CapabilityId::DesktopKeyboard);
    assert_eq!(
        serde_json::to_value(&action).unwrap()["arguments"]["text"],
        "fixture text"
    );
    assert_eq!(
        serde_json::to_value(&action).unwrap()["arguments"]["delivery_mode"],
        "foreground"
    );
    let request = action.element_input_request().unwrap().unwrap();
    for capability in [
        CapabilityId::DesktopKeyboard,
        CapabilityId::DesktopWindowsControl,
    ] {
        let lane = state.desktop.as_mut().unwrap();
        lane.grants.get_mut(&capability).unwrap().remote_grant = false;
        assert!(
            validate_element_input_dispatch(
                &state,
                &owner,
                &resource,
                &context,
                &request,
                MonotonicMillis(1)
            )
            .is_err()
        );
        state
            .desktop
            .as_mut()
            .unwrap()
            .grants
            .get_mut(&capability)
            .unwrap()
            .remote_grant = true;
    }
    let stranger = state
        .ledger
        .register_verified_owner(
            "different-text-owner".try_into().unwrap(),
            "different-text-epoch".try_into().unwrap(),
        )
        .unwrap();
    assert!(prepare(&state, &stranger, &resource, &input(pid, 42, "s00000002:1")).is_err());
}

fn set_value(token: &str) -> CuaAction {
    CuaAction::new(
        "set_value".into(),
        json!({
            "pid":std::process::id(), "window_id":42,
            "element_token":token, "value":"owner fixture"
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .unwrap()
}
async fn dispatch_fixture_set_value(
    shared: &Arc<std::sync::Mutex<State>>,
    owner: &OwnerLease,
    resource: &ResourceTarget,
    token: &str,
) {
    let (slot, permit, retained, prepared, facts) = {
        let mut state = shared.lock().unwrap();
        let request = set_value(token)
            .accessibility_write_request()
            .unwrap()
            .unwrap();
        let (translated, observation) = super::prepare(&state, owner, resource, &request)
            .expect("another owner's completed read must preserve this owner's write target");
        let mut context = context();
        context.session = Some(desktop(&state).unwrap().binding.clone());
        context.capability = CapabilityId::DesktopAccessibility;
        context.observation = Some(observation);
        let facts = validate_dispatch(
            &state,
            owner,
            resource,
            &context,
            &translated.accessibility_write_request().unwrap().unwrap(),
            MonotonicMillis(1),
        )
        .unwrap();
        let prepared = state
            .ledger
            .prepare_desktop_accessibility_write_attempt(
                owner,
                resource.clone(),
                context,
                translated.to_operation_payload().unwrap(),
                MonotonicMillis(1),
            )
            .unwrap();
        let lane = desktop(&state).unwrap();
        let bound = super::super::desktop::handle(lane, owner, resource).unwrap();
        let slot = lane.worker.try_reserve_action(&bound).unwrap();
        let DispatchDisposition::ExecuteOnce(permit) = state
            .ledger
            .dispatch(
                owner,
                &prepared.id,
                prepared.payload_digest,
                &facts,
                MonotonicMillis(1),
            )
            .unwrap()
        else {
            panic!("expected one permit");
        };
        let retained = Arc::new(take(state.desktop.as_mut(), resource).unwrap());
        (slot, permit, retained, prepared, facts)
    };
    let gate_state = shared.clone();
    let gate_owner = owner.clone();
    let gate_operation = prepared.id.clone();
    let gate_digest = prepared.payload_digest;
    let gate_observation = retained.clone();
    let gate: crate::providers::cua::AxWriteGate = Box::new(move || {
        Box::pin(async move {
            let state = gate_state.lock().unwrap();
            gate_observation
                .recheck_write(
                    &state,
                    &gate_owner,
                    &gate_operation,
                    gate_digest,
                    MonotonicMillis(1),
                )
                .map_err(|_| crate::providers::cua::CuaError::StaleObservation)
        })
    });
    let receipt = slot
        .call_once_until_with_write_gate(
            permit,
            Some(tokio::time::Instant::now() + Duration::from_secs(2)),
            gate,
        )
        .await;
    assert_eq!(receipt.evidence, CuaEvidence::Acknowledged);
    let mut state = shared.lock().unwrap();
    state
        .ledger
        .record_action_result(&prepared.id, ActionResult::Acknowledged, MonotonicMillis(2))
        .unwrap();
    let delivery = retained.write_result_facts(&state).unwrap();
    state
        .ledger
        .authorize_desktop_accessibility_write_result(
            owner,
            &prepared.id,
            prepared.payload_digest,
            &delivery,
            MonotonicMillis(2),
        )
        .unwrap();
    assert!(matches!(
        state
            .ledger
            .dispatch(
                owner,
                &prepared.id,
                prepared.payload_digest,
                &facts,
                MonotonicMillis(2)
            )
            .unwrap(),
        DispatchDisposition::Existing(_)
    ));
}
#[tokio::test]
async fn desktop_set_value_keeps_each_owners_read() {
    let (mut state, owner_a, resource_a, driver_a) = fixture().await;
    let owner_b = state
        .ledger
        .register_verified_owner(
            "desktop-owner-b".try_into().unwrap(),
            "desktop-epoch-b".try_into().unwrap(),
        )
        .unwrap();
    let (resource_b, driver_b) = open_fixture_resource(&mut state, &owner_b).await;
    install_fixture_read(
        &mut state,
        &owner_b,
        &resource_b,
        std::process::id(),
        "s00000003",
    );
    // Independent workers can be in flight together. Each late gate uses its
    // retained owner/resource snapshot even after the other dispatch consumes its own.
    let shared = Arc::new(std::sync::Mutex::new(state));
    tokio::join!(
        dispatch_fixture_set_value(&shared, &owner_a, &resource_a, "s00000002:1"),
        dispatch_fixture_set_value(&shared, &owner_b, &resource_b, "s00000003:1"),
    );
    assert_eq!(driver_a.calls.lock().unwrap().len(), 1);
    assert_eq!(driver_b.calls.lock().unwrap().len(), 1);
    driver_a.close().await;
    driver_b.close().await;
}
#[tokio::test]
async fn desktop_observation_owner_cleanup_preserves_other_owner() {
    let (mut state, owner_a, resource_a, driver_a) = fixture().await;
    let owner_b = state
        .ledger
        .register_verified_owner(
            "desktop-owner-b".try_into().unwrap(),
            "desktop-epoch-b".try_into().unwrap(),
        )
        .unwrap();
    let (resource_b, driver_b) = open_fixture_resource(&mut state, &owner_b).await;
    install_fixture_read(
        &mut state,
        &owner_b,
        &resource_b,
        std::process::id(),
        "s00000003",
    );
    for (wrong_owner, resource, token) in [
        (&owner_b, &resource_a, "s00000002:1"),
        (&owner_a, &resource_b, "s00000003:1"),
    ] {
        let request = set_value(token)
            .accessibility_write_request()
            .unwrap()
            .unwrap();
        assert!(matches!(
            super::prepare(&state, wrong_owner, resource, &request),
            Err(CoordinatorError::Admission(ErrorCategory::Unauthorized))
        ));
        assert!(matches!(
            super::super::desktop::handle(desktop(&state).unwrap(), wrong_owner, resource),
            Err(CoordinatorError::Admission(ErrorCategory::Unauthorized))
        ));
    }
    // Follow the owner-close fence/invalidation order. B cannot keep an input
    // target alive; A remains usable while B's resource is retained for cleanup.
    state
        .ledger
        .fence_owner_for_cleanup(&owner_b, MonotonicMillis(1))
        .unwrap();
    invalidate(state.desktop.as_mut(), Some(&owner_b));
    assert!(take(state.desktop.as_mut(), &resource_b).is_none());
    assert_eq!(driver_b.calls.lock().unwrap().len(), 0);
    driver_b.close().await;
    let shared = Arc::new(std::sync::Mutex::new(state));
    dispatch_fixture_set_value(&shared, &owner_a, &resource_a, "s00000002:1").await;
    {
        let mut state = shared.lock().unwrap();
        state
            .desktop
            .as_mut()
            .unwrap()
            .handles
            .remove(&resource_b.operation_id);
        install_fixture_read(
            &mut state,
            &owner_a,
            &resource_a,
            std::process::id(),
            "s00000004",
        );
    }
    dispatch_fixture_set_value(&shared, &owner_a, &resource_a, "s00000004:1").await;
    assert_eq!(driver_a.calls.lock().unwrap().len(), 2);
    driver_a.close().await;
}
#[tokio::test]
async fn desktop_observations_are_scoped_to_resource_and_source_fence() {
    let (mut state, owner, first, driver_a) = fixture().await;
    let (second, driver_b) = open_fixture_resource(&mut state, &owner).await;
    install_fixture_read(&mut state, &owner, &second, std::process::id(), "s00000003");
    let first_request = set_value("s00000002:1")
        .accessibility_write_request()
        .unwrap()
        .unwrap();
    let second_request = set_value("s00000003:1")
        .accessibility_write_request()
        .unwrap()
        .unwrap();
    assert!(super::prepare(&state, &owner, &first, &first_request).is_ok());
    assert!(matches!(
        super::prepare(&state, &owner, &second, &first_request),
        Err(CoordinatorError::Admission(ErrorCategory::StaleObservation))
    ));
    // The same per-resource take is used before read acquisition or a native
    // action: neither an in-flight read nor an unknown write erases another worker.
    assert!(take(state.desktop.as_mut(), &second).is_some());
    assert!(super::prepare(&state, &owner, &first, &first_request).is_ok());
    assert!(matches!(
        super::prepare(&state, &owner, &second, &second_request),
        Err(CoordinatorError::Admission(ErrorCategory::StaleObservation))
    ));
    install_fixture_read(&mut state, &owner, &second, std::process::id(), "s00000004");
    assert!(super::prepare(&state, &owner, &first, &first_request).is_ok());
    // Source/session invalidation must still revoke all retained worker maps.
    invalidate(state.desktop.as_mut(), None);
    assert!(matches!(
        super::prepare(&state, &owner, &first, &first_request),
        Err(CoordinatorError::Admission(ErrorCategory::StaleObservation))
    ));
    assert!(take(state.desktop.as_mut(), &second).is_none());
    driver_a.close().await;
    driver_b.close().await;
}

// Synthetic source authority and real process custody, with the original Core
// and Cua slot/transport/settlement path. Full source-supervisor/Host admission
// is covered separately by the real public-MCP Chrome acceptance.
async fn dispatch_fixture_read(
    shared: &Arc<std::sync::Mutex<State>>,
    owner: &OwnerLease,
    resource: &ResourceTarget,
    action: &CuaAction,
) {
    let (slot, permit, prepared, context, acquisition, acquired_target, read_capabilities) = {
        let mut state = shared.lock().unwrap();
        let mut context = context();
        context.session = Some(desktop(&state).unwrap().binding.clone());
        context.capability = action.capability().unwrap();
        let acquisition = action.desktop_read_request().unwrap();
        let snapshot = action.snapshot_request().unwrap();
        let acquired_target = acquisition
            .or(snapshot)
            .map(DesktopReadTarget::acquire)
            .transpose()
            .unwrap();
        let read_capabilities = action.required_capabilities().unwrap();
        let facts = if acquisition.is_some() {
            super::super::desktop_read::acquisition_facts(&state, context.capability).unwrap()
        } else {
            super::super::desktop::facts(&state, context.capability).unwrap()
        };
        let prepared = match acquisition {
            Some(DesktopReadRequest::Accessibility(_)) => {
                state.ledger.prepare_desktop_read_acquisition(
                    owner,
                    resource.clone(),
                    context.clone(),
                    action.to_operation_payload().unwrap(),
                    MonotonicMillis(1),
                )
            }
            Some(DesktopReadRequest::WindowCapture(_)) => {
                state.ledger.prepare_desktop_window_capture_acquisition(
                    owner,
                    resource.clone(),
                    context.clone(),
                    action.to_operation_payload().unwrap(),
                    MonotonicMillis(1),
                )
            }
            None => state.ledger.prepare_targeted(
                owner,
                resource.clone(),
                context.clone(),
                action.to_operation_payload().unwrap(),
                MonotonicMillis(1),
            ),
        }
        .unwrap();
        let lane = desktop(&state).unwrap();
        let bound = super::super::desktop::handle(lane, owner, resource).unwrap();
        let slot = lane.worker.try_reserve_action(&bound).unwrap();
        let DispatchDisposition::ExecuteOnce(permit) = state
            .ledger
            .dispatch(
                owner,
                &prepared.id,
                prepared.payload_digest,
                &facts,
                MonotonicMillis(1),
            )
            .unwrap()
        else {
            panic!("expected one read permit");
        };
        assert!(
            after_dispatch(
                state.desktop.as_mut(),
                resource,
                action.mutates() || snapshot.is_some(),
                false
            )
            .is_none()
        );
        (
            slot,
            permit,
            prepared,
            context,
            acquisition,
            acquired_target,
            read_capabilities,
        )
    };
    let mut receipt = slot
        .call_once_until(
            permit,
            Some(tokio::time::Instant::now() + Duration::from_secs(2)),
        )
        .await;
    assert_eq!(receipt.evidence, CuaEvidence::Acknowledged);
    let mut state = shared.lock().unwrap();
    state
        .ledger
        .record_action_result(&prepared.id, ActionResult::Acknowledged, MonotonicMillis(2))
        .unwrap();
    if acquisition.is_some() {
        let facts =
            super::super::desktop_read::acquisition_facts(&state, context.capability).unwrap();
        super::super::desktop_read::authorize_result(
            &state.ledger,
            owner,
            &prepared.id,
            prepared.payload_digest,
            &facts,
            MonotonicMillis(2),
            &mut receipt,
        )
        .unwrap();
    } else {
        let facts = super::super::desktop::facts(&state, context.capability).unwrap();
        state
            .ledger
            .authorize_resource_access(
                owner,
                &resource.operation_id,
                resource.payload_digest,
                &context,
                &facts,
                MonotonicMillis(2),
            )
            .unwrap();
    }
    if let Some(target) = acquired_target {
        let lane = state.desktop.as_mut().unwrap();
        let acquired = super::super::desktop_read::settle_acquired_read(
            lane,
            &target,
            &mut receipt,
            acquisition.is_some(),
        );
        assert_ne!(receipt.result.as_ref().unwrap().is_error, Some(true));
        if let Some((parsed, alias)) = acquired {
            install(
                &mut state,
                owner,
                resource,
                AcquiredAxObservation {
                    target,
                    parsed,
                    alias,
                    source_epoch: 1,
                    read_capabilities,
                },
            )
            .unwrap();
        }
    }
}
fn assert_all_input_gates(
    state: &State,
    owner: &OwnerLease,
    resource: &ResourceTarget,
    token: &str,
) {
    let request = set_value(token)
        .accessibility_write_request()
        .unwrap()
        .unwrap();
    let (translated, observation) = super::prepare(state, owner, resource, &request).unwrap();
    let mut write_context = context();
    write_context.session = Some(desktop(state).unwrap().binding.clone());
    write_context.capability = CapabilityId::DesktopAccessibility;
    write_context.observation = Some(observation);
    validate_dispatch(
        state,
        owner,
        resource,
        &write_context,
        &translated.accessibility_write_request().unwrap().unwrap(),
        MonotonicMillis(3),
    )
    .unwrap();
    for action in [
        click(token),
        CuaAction::new(
            "type_text".into(),
            json!({
                "pid":std::process::id(), "window_id":42, "element_token":token,
                "text":"fixture", "delivery_mode":"foreground"
            })
            .as_object()
            .unwrap()
            .clone(),
        )
        .unwrap(),
    ] {
        let (translated, context) = prepare(state, owner, resource, &action).unwrap();
        validate_element_input_dispatch(
            state,
            owner,
            resource,
            &context,
            &translated.element_input_request().unwrap().unwrap(),
            MonotonicMillis(3),
        )
        .unwrap();
    }
}
#[tokio::test]
async fn descriptive_reads_preserve_the_complete_tree_for_all_input_gates() {
    // Same one-pixel PNG as the established window_capture_tests fixture.
    const PNG: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jVZkAAAAASUVORK5CYII=";
    let pid = std::process::id();
    let mut capture = CallToolResult::structured(json!({"pid":pid,"window_id":42,
        "coordinate_frame":"window","screenshot_frame_valid":true,"screenshot_width":1,
        "screenshot_height":1,"screenshot_mime_type":"image/png",
        "window_bounds":{"x":0,"y":0,"width":1,"height":1},"snapshot_id":"s00000001"}));
    capture.content = vec![rmcp::model::ContentBlock::image(PNG, "image/png")];
    for (name, arguments, reply) in [
        (
            "list_apps",
            json!({}),
            CallToolResult::structured(json!({"apps":[]})),
        ),
        (
            "list_windows",
            json!({}),
            CallToolResult::structured(json!({"windows":[]})),
        ),
        (
            "get_desktop_state",
            json!({}),
            CallToolResult::structured(json!({"fixture":"desktop pixels"})),
        ),
        (
            "verify_state",
            json!({"pid":pid,"window_id":42,"expect":[{"window":{"exists":true}}]}),
            CallToolResult::structured(json!({"satisfied":true})),
        ),
        (
            "get_window_state",
            json!({"pid":pid,"window_id":42,"include_accessibility_tree":false}),
            capture,
        ),
    ] {
        let (state, owner, resource, driver) = fixture().await;
        let before = desktop(&state)
            .unwrap()
            .handles
            .get(&resource.operation_id)
            .unwrap()
            .ax_observation
            .as_ref()
            .map(|observation| (observation.observation.clone(), observation.observed_at))
            .unwrap();
        let action = CuaAction::new(name.into(), arguments.as_object().unwrap().clone()).unwrap();
        assert!(!action.mutates());
        assert!(action.snapshot_request().unwrap().is_none());
        *driver.reply.lock().unwrap() = reply;
        let shared = Arc::new(std::sync::Mutex::new(state));
        dispatch_fixture_read(&shared, &owner, &resource, &action).await;
        {
            let state = shared.lock().unwrap();
            assert_all_input_gates(&state, &owner, &resource, "s00000002:1");
            let retained = desktop(&state)
                .unwrap()
                .handles
                .get(&resource.operation_id)
                .unwrap()
                .ax_observation
                .as_ref()
                .unwrap();
            assert_eq!(
                (&retained.observation, retained.observed_at),
                (&before.0, before.1),
                "read-only calls preserve the binding without renewing its age"
            );
        }
        assert_eq!(driver.calls.lock().unwrap().len(), 1);
        *driver.reply.lock().unwrap() =
            CallToolResult::structured(json!({"effect":"unverifiable"}));
        dispatch_fixture_set_value(&shared, &owner, &resource, "s00000002:1").await;
        let calls = driver.calls.lock().unwrap().clone();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0]["name"], name);
        assert_eq!(calls[1]["name"], "set_value");
        driver.close().await;
    }
}
#[tokio::test]
async fn a_new_complete_tree_still_supersedes_the_previous_binding() {
    let (state, owner, resource, driver) = fixture().await;
    let mut complete = fixture_ax_read(std::process::id())
        .structured_content
        .unwrap();
    let object = complete.as_object_mut().unwrap();
    object.remove("tree_markdown");
    object.insert("tree_format".into(), json!("elements"));
    object.insert("element_count".into(), json!(1));
    object.insert("total_element_count".into(), json!(1));
    *driver.reply.lock().unwrap() = CallToolResult::structured(complete);
    let action = CuaAction::new(
        "get_window_state".into(),
        json!({
            "pid":std::process::id(),"window_id":42,"include_screenshot":false
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .unwrap();
    assert!(action.snapshot_request().unwrap().is_some());
    let shared = Arc::new(std::sync::Mutex::new(state));
    dispatch_fixture_read(&shared, &owner, &resource, &action).await;
    {
        let state = shared.lock().unwrap();
        assert!(prepare(&state, &owner, &resource, &click("s00000002:1")).is_err());
        assert_all_input_gates(&state, &owner, &resource, "s00000003:1");
    }
    assert_eq!(driver.calls.lock().unwrap().len(), 1);
    driver.close().await;
    let unknown: CuaAction =
        serde_json::from_value(json!({"name":"unknown_read","arguments":{}})).unwrap();
    assert!(
        unknown.mutates(),
        "an unclassified action must not preserve input authority"
    );
}

#[tokio::test]
async fn acknowledged_input_receipts_survive_observation_age() {
    let mut outcomes = Vec::new();
    for name in ["click", "type_text", "set_value"] {
        let (mut state, owner, resource, driver) = fixture().await;
        let action = match name {
            "click" => click("s00000002:1"),
            "type_text" => CuaAction::new(
                "type_text".into(),
                json!({
                    "pid":std::process::id(), "window_id":42,
                    "element_token":"s00000002:1", "text":"fixture", "delivery_mode":"foreground"
                })
                .as_object()
                .unwrap()
                .clone(),
            )
            .unwrap(),
            _ => set_value("s00000002:1"),
        };
        let is_write = name == "set_value";
        let (translated, mut context) = if is_write {
            let (translated, observation) = super::prepare(
                &state,
                &owner,
                &resource,
                &action.accessibility_write_request().unwrap().unwrap(),
            )
            .unwrap();
            let mut context = context();
            context.session = Some(desktop(&state).unwrap().binding.clone());
            context.capability = CapabilityId::DesktopAccessibility;
            context.observation = Some(observation);
            (translated, context)
        } else {
            prepare(&state, &owner, &resource, &action).unwrap()
        };
        // A public Computer call may legitimately omit a caller deadline. This
        // regression advances only retained snapshot age, not OS permission or
        // source identity, and must not confuse the two independent lifetimes.
        context.deadline = None;
        let facts = if is_write {
            validate_dispatch(
                &state,
                &owner,
                &resource,
                &context,
                &translated.accessibility_write_request().unwrap().unwrap(),
                MonotonicMillis(1),
            )
            .unwrap()
        } else {
            validate_element_input_dispatch(
                &state,
                &owner,
                &resource,
                &context,
                &translated.element_input_request().unwrap().unwrap(),
                MonotonicMillis(1),
            )
            .unwrap()
        };
        let prepared = if is_write {
            state.ledger.prepare_desktop_accessibility_write_attempt(
                &owner,
                resource.clone(),
                context.clone(),
                translated.to_operation_payload().unwrap(),
                MonotonicMillis(1),
            )
        } else {
            state.ledger.prepare_targeted(
                &owner,
                resource.clone(),
                context.clone(),
                translated.to_operation_payload().unwrap(),
                MonotonicMillis(1),
            )
        }
        .unwrap();
        let lane = desktop(&state).unwrap();
        let bound = super::super::desktop::handle(lane, &owner, &resource).unwrap();
        let slot = lane.worker.try_reserve_action(&bound).unwrap();
        let DispatchDisposition::ExecuteOnce(permit) = state
            .ledger
            .dispatch(
                &owner,
                &prepared.id,
                prepared.payload_digest,
                &facts,
                MonotonicMillis(1),
            )
            .unwrap()
        else {
            panic!("expected one input permit");
        };
        let mut retained =
            Arc::new(after_dispatch(state.desktop.as_mut(), &resource, true, true).unwrap());
        assert!(retained.observed_at.elapsed() < Duration::from_secs(30));
        let shared = Arc::new(std::sync::Mutex::new(state));
        let gate_state = shared.clone();
        let gate_owner = owner.clone();
        let gate_operation = prepared.id.clone();
        let gate_digest = prepared.payload_digest;
        let gate_observation = retained.clone();
        let gate: crate::providers::cua::AxWriteGate = Box::new(move || {
            Box::pin(async move {
                let state = gate_state.lock().unwrap();
                let result = if is_write {
                    gate_observation.recheck_write(
                        &state,
                        &gate_owner,
                        &gate_operation,
                        gate_digest,
                        MonotonicMillis(1),
                    )
                } else {
                    gate_observation.recheck_element_input(
                        &state,
                        &gate_owner,
                        &gate_operation,
                        gate_digest,
                        MonotonicMillis(1),
                    )
                };
                result.map_err(|_| crate::providers::cua::CuaError::StaleObservation)
            })
        });
        let receipt = slot
            .call_once_until_with_write_gate(
                permit,
                Some(tokio::time::Instant::now() + Duration::from_secs(2)),
                gate,
            )
            .await;
        assert_eq!(receipt.evidence, CuaEvidence::Acknowledged);
        assert_eq!(driver.calls.lock().unwrap().len(), 1);
        // Model a native call which was admitted while fresh and ACKed after
        // 31 seconds, without waiting or performing any real desktop input.
        Arc::get_mut(&mut retained).unwrap().observed_at -= Duration::from_secs(31);
        assert!(retained.observed_at.elapsed() >= Duration::from_secs(30));
        let deliver = |state: &State, caller: &OwnerLease, observation: &OwnedAxObservation| {
            if is_write {
                observation.write_result_facts(state).and_then(|facts| {
                    state
                        .ledger
                        .authorize_desktop_accessibility_write_result(
                            caller,
                            &prepared.id,
                            prepared.payload_digest,
                            &facts,
                            MonotonicMillis(31_001),
                        )
                        .map(|_| ())
                        .map_err(CoordinatorError::from)
                })
            } else {
                let request = translated.element_input_request().unwrap().unwrap();
                observation
                    .element_input_result_facts(
                        state,
                        caller,
                        &resource,
                        &context,
                        &request,
                        MonotonicMillis(31_001),
                    )
                    .and_then(|facts| {
                        state
                            .ledger
                            .authorize_resource_access(
                                caller,
                                &resource.operation_id,
                                resource.payload_digest,
                                &context,
                                &facts,
                                MonotonicMillis(31_001),
                            )
                            .map(|_| ())
                            .map_err(CoordinatorError::from)
                    })
            }
        };
        let delivery = {
            let mut state = shared.lock().unwrap();
            let snapshot = state
                .ledger
                .record_action_result(
                    &prepared.id,
                    ActionResult::Acknowledged,
                    MonotonicMillis(31_001),
                )
                .unwrap();
            assert_eq!(snapshot.state, OperationState::Succeeded);
            let stale_input = if is_write {
                retained.write_facts(
                    &state,
                    &owner,
                    &resource,
                    &context,
                    &translated.accessibility_write_request().unwrap().unwrap(),
                    MonotonicMillis(31_001),
                )
            } else {
                retained.element_input_facts(
                    &state,
                    &owner,
                    &resource,
                    &context,
                    &translated.element_input_request().unwrap().unwrap(),
                    MonotonicMillis(31_001),
                )
            };
            assert!(matches!(
                stale_input,
                Err(CoordinatorError::Admission(ErrorCategory::StaleObservation))
            ));
            let delivery = deliver(&state, &owner, &retained);
            // The receipt relaxes only pre-dispatch freshness, never its caller,
            // source binding or current capability authority.
            let foreign = state
                .ledger
                .register_verified_owner(
                    "receipt-foreign".try_into().unwrap(),
                    "receipt-foreign-epoch".try_into().unwrap(),
                )
                .unwrap();
            assert!(matches!(
                deliver(&state, &foreign, &retained),
                Err(CoordinatorError::Admission(ErrorCategory::Unauthorized))
            ));
            Arc::get_mut(&mut retained).unwrap().source_epoch += 1;
            assert!(deliver(&state, &owner, &retained).is_err());
            Arc::get_mut(&mut retained).unwrap().source_epoch -= 1;
            let binding = desktop(&state).unwrap().binding.clone();
            let mut denied = evidence(context.capability);
            denied.authorization = Authorization::Denied;
            state
                .sessions
                .provider(&binding, denied, Duration::from_secs(60))
                .unwrap();
            assert!(deliver(&state, &owner, &retained).is_err());
            state
                .sessions
                .provider(
                    &binding,
                    evidence(context.capability),
                    Duration::from_secs(60),
                )
                .unwrap();
            assert_eq!(deliver(&state, &owner, &retained).is_ok(), delivery.is_ok());
            // Delivery cannot downgrade known execution or mint another permit.
            assert!(matches!(state.ledger.dispatch(&owner, &prepared.id,
                prepared.payload_digest, &facts, MonotonicMillis(31_001)).unwrap(),
                DispatchDisposition::Existing(snapshot) if snapshot.state == OperationState::Succeeded));
            delivery
        };
        println!("receipt-age {name}: native=acknowledged ledger=Succeeded delivery={delivery:?}");
        outcomes.push((name, delivery.is_ok()));
        driver.close().await;
    }
    assert!(
        outcomes.iter().all(|(_, delivered)| *delivered),
        "an acknowledged input must not lose its original receipt solely because its pre-dispatch snapshot aged: {outcomes:?}"
    );
}
