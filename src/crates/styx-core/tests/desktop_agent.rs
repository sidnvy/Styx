//! Domain contracts only. The effect sink consumes real Core permits; no native
//! permission, session attestation, Cua process or GUI acceptance is claimed.
use styx_contracts::{capability::*, error::*, operation::*, session::*};
use styx_core::{operations::*, policy::AdmissionFacts};
fn binding() -> SessionBinding {
    SessionBinding {
        id: "desktop".try_into().unwrap(),
        generation: "session-1".try_into().unwrap(),
    }
}
fn context(capability: CapabilityId) -> PreparedContext {
    PreparedContext {
        device_id: "device".try_into().unwrap(),
        grant_revision: 1,
        session: Some(binding()),
        observation: (capability != CapabilityId::DesktopWindowsRead)
            .then(|| "observation".try_into().unwrap()),
        capability,
        deadline: MonotonicMillis(1000),
        disconnect_policy: DisconnectPolicy::RetainForOwner,
    }
}
fn facts(c: &PreparedContext) -> AdmissionFacts {
    AdmissionFacts {
        device_id: c.device_id.clone(),
        grant_revision: 1,
        local_policy_allowed: true,
        descriptor: CapabilityDescriptor {
            contract_version: 1,
            capability_id: c.capability,
            scope: Scope::Session,
            provider_id: "native-fixture".try_into().unwrap(),
            configured: true,
            remote_grant: true,
            availability: Availability::Available,
            authorization: Authorization::Granted,
            target_session: c.session.clone(),
            reason: None,
            observed_at: 1,
            observation_generation: 1,
            recovery: Recovery::None,
        },
        session_state: Some(SessionState::Ready),
        current_observation: c.observation.clone(),
    }
}
fn target(r: &OperationSnapshot) -> ResourceTarget {
    ResourceTarget {
        operation_id: r.id.clone(),
        payload_digest: r.payload_digest,
    }
}
fn setup(explicit: bool) -> (OperationLedger, OwnerLease, OperationSnapshot) {
    let mut ledger = OperationLedger::with_budget("host".try_into().unwrap(), 1_000_000, 10);
    let owner = ledger
        .register_verified_owner("owner".try_into().unwrap(), "epoch".try_into().unwrap())
        .unwrap();
    let c = context(CapabilityId::DesktopWindowsRead);
    let resource = if explicit {
        ledger.prepare_desktop_agent(&owner, c.clone(), b"agent".to_vec(), MonotonicMillis(0))
    } else {
        ledger.prepare(&owner, c.clone(), b"ordinary".to_vec(), MonotonicMillis(0))
    }
    .unwrap();
    let DispatchDisposition::ExecuteOnce(p) = ledger
        .dispatch(
            &owner,
            &resource.id,
            resource.payload_digest,
            &facts(&c),
            MonotonicMillis(1),
        )
        .unwrap()
    else {
        panic!("first dispatch")
    };
    assert_eq!(
        p.resource_domain(),
        if explicit {
            ResourceDomain::DesktopAgent
        } else {
            ResourceDomain::Capability
        }
    );
    ledger
        .record_executor_fact(&resource.id, ExecutorFact::Running, MonotonicMillis(1))
        .unwrap();
    (ledger, owner, resource)
}
#[test]
fn explicit_agent_cross_capability_dispatch_stays_once_and_exact_session() {
    let (mut ledger, owner, resource) = setup(true);
    let mut effects = Vec::new();
    for cap in [
        CapabilityId::DesktopWindowsRead,
        CapabilityId::DesktopWindowsControl,
        CapabilityId::DesktopCapture,
        CapabilityId::DesktopPointer,
        CapabilityId::DesktopKeyboard,
        CapabilityId::DesktopAccessibility,
    ] {
        let c = context(cap);
        let payload = format!("one-{cap:?}").into_bytes();
        let action = ledger
            .prepare_targeted(
                &owner,
                target(&resource),
                c.clone(),
                payload.clone(),
                MonotonicMillis(2),
            )
            .unwrap();
        let DispatchDisposition::ExecuteOnce(p) = ledger
            .dispatch(
                &owner,
                &action.id,
                action.payload_digest,
                &facts(&c),
                MonotonicMillis(3),
            )
            .unwrap()
        else {
            panic!("first action")
        };
        assert_eq!(p.resource_domain(), ResourceDomain::DesktopAgent);
        assert_eq!(p.context(), &c);
        assert_eq!(p.target(), Some(&target(&resource)));
        effects.push((p.context().capability, p.payload().to_vec()));
        ledger
            .record_action_result(&action.id, ActionResult::Unknown, MonotonicMillis(4))
            .unwrap();
        assert!(
            matches!(ledger.dispatch(&owner, &action.id, action.payload_digest, &facts(&c), MonotonicMillis(5)).unwrap(), DispatchDisposition::Existing(s) if s.state == OperationState::Unknown)
        );
        assert_eq!(effects.last(), Some(&(cap, payload)));
        ledger
            .authorize_resource_access(
                &owner,
                &resource.id,
                resource.payload_digest,
                &c,
                &facts(&c),
                MonotonicMillis(6),
            )
            .unwrap();
    }
    assert_eq!(effects.len(), 6);
}
#[test]
fn affinity_never_replaces_fresh_authorization_and_session_facts() {
    let (mut ledger, owner, resource) = setup(true);
    let c = context(CapabilityId::DesktopPointer);
    let action = ledger
        .prepare_targeted(
            &owner,
            target(&resource),
            c.clone(),
            b"input-once".to_vec(),
            MonotonicMillis(2),
        )
        .unwrap();
    let mut denied = facts(&c);
    denied.descriptor.remote_grant = false;
    let mut required = facts(&c);
    required.descriptor.authorization = Authorization::Required;
    let mut revoked = facts(&c);
    revoked.descriptor.authorization = Authorization::Revoked;
    let mut locked = facts(&c);
    locked.session_state = Some(SessionState::Locked);
    let mut generation = facts(&c);
    generation
        .descriptor
        .target_session
        .as_mut()
        .unwrap()
        .generation = "session-2".try_into().unwrap();
    let mut grant = facts(&c);
    grant.grant_revision = 2;
    let mut stale = facts(&c);
    stale.current_observation = Some("new-observation".try_into().unwrap());
    for (f, error) in [
        (denied, ErrorCategory::PermissionDenied),
        (required, ErrorCategory::PermissionRequired),
        (revoked, ErrorCategory::PermissionDenied),
        (locked, ErrorCategory::SessionLocked),
        (generation, ErrorCategory::SessionDisconnected),
        (grant, ErrorCategory::StateConflict),
        (stale, ErrorCategory::StaleObservation),
    ] {
        assert_eq!(
            ledger
                .dispatch(
                    &owner,
                    &action.id,
                    action.payload_digest,
                    &f,
                    MonotonicMillis(3)
                )
                .unwrap_err(),
            error
        );
        assert_eq!(
            ledger
                .authorize_resource_access(
                    &owner,
                    &resource.id,
                    resource.payload_digest,
                    &c,
                    &f,
                    MonotonicMillis(3)
                )
                .unwrap_err(),
            error
        );
        assert_eq!(
            ledger
                .inspect(&owner, &action.id, action.payload_digest)
                .unwrap()
                .state,
            OperationState::Reserved
        );
    }
    let mut no_snapshot = c.clone();
    no_snapshot.observation = None;
    let unobserved = ledger
        .prepare_targeted(
            &owner,
            target(&resource),
            no_snapshot.clone(),
            vec![],
            MonotonicMillis(3),
        )
        .unwrap();
    assert_eq!(
        ledger
            .dispatch(
                &owner,
                &unobserved.id,
                unobserved.payload_digest,
                &facts(&no_snapshot),
                MonotonicMillis(4)
            )
            .unwrap_err(),
        ErrorCategory::StaleObservation
    );
    let DispatchDisposition::ExecuteOnce(_) = ledger
        .dispatch(
            &owner,
            &action.id,
            action.payload_digest,
            &facts(&c),
            MonotonicMillis(4),
        )
        .unwrap()
    else {
        panic!("refusals must not dispatch")
    };
    ledger.revoke_owner(&owner).unwrap();
    assert_eq!(
        ledger
            .authorize_resource_access(
                &owner,
                &resource.id,
                resource.payload_digest,
                &c,
                &facts(&c),
                MonotonicMillis(5)
            )
            .unwrap_err(),
        ErrorCategory::Unauthorized
    );
}
#[test]
fn ordinary_resources_and_other_owner_or_session_cannot_become_desktop_agents() {
    let (mut ledger, owner, ordinary) = setup(false);
    let pointer = context(CapabilityId::DesktopPointer);
    assert_eq!(
        ledger
            .prepare_targeted(
                &owner,
                target(&ordinary),
                pointer.clone(),
                vec![],
                MonotonicMillis(2)
            )
            .unwrap_err(),
        ErrorCategory::StateConflict
    );
    assert_eq!(
        ledger
            .authorize_resource_access(
                &owner,
                &ordinary.id,
                ordinary.payload_digest,
                &pointer,
                &facts(&pointer),
                MonotonicMillis(2)
            )
            .unwrap_err(),
        ErrorCategory::StateConflict
    );
    let (mut ledger, owner, resource) = setup(true);
    let foreign = ledger
        .register_verified_owner(
            "foreign".try_into().unwrap(),
            "foreign-epoch".try_into().unwrap(),
        )
        .unwrap();
    assert_eq!(
        ledger
            .prepare_targeted(
                &foreign,
                target(&resource),
                pointer.clone(),
                vec![],
                MonotonicMillis(2)
            )
            .unwrap_err(),
        ErrorCategory::Unauthorized
    );
    let mut other_generation = pointer.clone();
    other_generation.session.as_mut().unwrap().generation =
        "different-generation".try_into().unwrap();
    let mut other_session = pointer.clone();
    other_session.session.as_mut().unwrap().id = "other-desktop".try_into().unwrap();
    for c in [
        other_generation,
        other_session,
        context(CapabilityId::BrowserHeaded),
    ] {
        assert_eq!(
            ledger
                .prepare_targeted(&owner, target(&resource), c, vec![], MonotonicMillis(2))
                .unwrap_err(),
            ErrorCategory::StateConflict
        );
    }
    let mut wrong_device = pointer.clone();
    wrong_device.device_id = "other-device".try_into().unwrap();
    assert_eq!(
        ledger
            .prepare_targeted(
                &owner,
                target(&resource),
                wrong_device,
                vec![],
                MonotonicMillis(2)
            )
            .unwrap_err(),
        ErrorCategory::StateConflict
    );
    for c in [context(CapabilityId::ExecRun), pointer] {
        assert_eq!(
            ledger
                .prepare_desktop_agent(&owner, c, vec![], MonotonicMillis(2))
                .unwrap_err(),
            ErrorCategory::StateConflict
        );
    }
    let mut absent = context(CapabilityId::DesktopWindowsRead);
    absent.session = None;
    assert_eq!(
        ledger
            .prepare_desktop_agent(&owner, absent, vec![], MonotonicMillis(2))
            .unwrap_err(),
        ErrorCategory::StateConflict
    );
    ledger
        .record_executor_fact(
            &resource.id,
            ExecutorFact::Exited { successful: true },
            MonotonicMillis(3),
        )
        .unwrap();
    ledger
        .record_executor_fact(
            &resource.id,
            ExecutorFact::OutputDrained,
            MonotonicMillis(3),
        )
        .unwrap();
    assert_eq!(
        ledger
            .prepare_targeted(
                &owner,
                target(&resource),
                context(CapabilityId::DesktopPointer),
                vec![],
                MonotonicMillis(4)
            )
            .unwrap_err(),
        ErrorCategory::StateConflict
    );
}
