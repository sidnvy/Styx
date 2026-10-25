//! Pure Core contracts. These consume genuine Core permits but perform no AX,
//! GUI, OS permission or native executor work; actual acceptance remains separate.
use styx_contracts::{capability::*, error::*, operation::*, session::*};
use styx_core::{
    operations::*,
    policy::{AdmissionFacts, check_admission, check_desktop_read_acquisition},
};
fn context(capability: CapabilityId) -> PreparedContext {
    PreparedContext {
        device_id: "device".try_into().unwrap(),
        grant_revision: 3,
        session: Some(SessionBinding {
            id: "desktop".try_into().unwrap(),
            generation: "session-1".try_into().unwrap(),
        }),
        observation: None,
        capability,
        deadline: MonotonicMillis(1000),
        disconnect_policy: DisconnectPolicy::RetainForOwner,
    }
}
fn facts(c: &PreparedContext) -> AdmissionFacts {
    AdmissionFacts {
        device_id: c.device_id.clone(),
        grant_revision: 3,
        local_policy_allowed: true,
        descriptor: CapabilityDescriptor {
            contract_version: 1,
            capability_id: c.capability,
            scope: Scope::Session,
            provider_id: "native-fixture".try_into().unwrap(),
            configured: true,
            remote_grant: true,
            availability: Availability::Unavailable,
            authorization: Authorization::Unknown,
            target_session: c.session.clone(),
            reason: Some(ErrorCategory::PermissionRequired),
            observed_at: 1,
            observation_generation: 1,
            recovery: Recovery::Reobserve,
        },
        session_state: Some(SessionState::Degraded),
        current_observation: None,
    }
}
fn target(r: &OperationSnapshot) -> ResourceTarget {
    ResourceTarget {
        operation_id: r.id.clone(),
        payload_digest: r.payload_digest,
    }
}
fn setup() -> (
    OperationLedger,
    OwnerLease,
    OperationSnapshot,
    PreparedContext,
    AdmissionFacts,
) {
    let mut ledger = OperationLedger::new("host".try_into().unwrap());
    let owner = ledger
        .register_verified_owner("owner".try_into().unwrap(), "epoch".try_into().unwrap())
        .unwrap();
    let c = context(CapabilityId::DesktopWindowsRead);
    let resource = ledger
        .prepare_desktop_agent(&owner, c.clone(), b"agent".to_vec(), MonotonicMillis(0))
        .unwrap();
    let mut f = facts(&c);
    f.descriptor.availability = Availability::Available;
    f.descriptor.authorization = Authorization::Granted;
    assert!(matches!(
        ledger
            .dispatch(
                &owner,
                &resource.id,
                resource.payload_digest,
                &f,
                MonotonicMillis(1)
            )
            .unwrap(),
        DispatchDisposition::ExecuteOnce(_)
    ));
    ledger
        .record_executor_fact(&resource.id, ExecutorFact::Running, MonotonicMillis(2))
        .unwrap();
    let c = context(CapabilityId::DesktopAccessibility);
    let f = facts(&c);
    (ledger, owner, resource, c, f)
}
fn prepare(
    ledger: &mut OperationLedger,
    owner: &OwnerLease,
    resource: &OperationSnapshot,
    c: PreparedContext,
) -> OperationSnapshot {
    ledger
        .prepare_desktop_read_acquisition(
            owner,
            target(resource),
            c,
            b"fixed-read-payload".to_vec(),
            MonotonicMillis(3),
        )
        .unwrap()
}
fn acknowledge(
    ledger: &mut OperationLedger,
    owner: &OwnerLease,
    action: &OperationSnapshot,
    f: &AdmissionFacts,
) {
    let DispatchDisposition::ExecuteOnce(permit) = ledger
        .dispatch(
            owner,
            &action.id,
            action.payload_digest,
            f,
            MonotonicMillis(4),
        )
        .unwrap()
    else {
        panic!("first dispatch")
    };
    assert_eq!(
        permit.purpose(),
        OperationPurpose::DesktopAccessibilityReadAcquisition
    );
    assert_eq!(permit.payload(), b"fixed-read-payload");
    ledger
        .record_action_result(&action.id, ActionResult::Acknowledged, MonotonicMillis(5))
        .unwrap();
}
#[test]
fn acquisition_is_once_scoped_read_and_never_a_provider_grant() {
    let (mut ledger, owner, resource, c, f) = setup();
    assert_eq!(
        check_admission(&c, &f, MonotonicMillis(3)),
        Err(ErrorCategory::PermissionRequired)
    );
    let ordinary = ledger
        .prepare_targeted(
            &owner,
            target(&resource),
            c.clone(),
            b"ordinary".to_vec(),
            MonotonicMillis(3),
        )
        .unwrap();
    assert!(
        ledger
            .dispatch(
                &owner,
                &ordinary.id,
                ordinary.payload_digest,
                &f,
                MonotonicMillis(4)
            )
            .is_err()
    );
    let action = prepare(&mut ledger, &owner, &resource, c.clone());
    acknowledge(&mut ledger, &owner, &action, &f);
    assert!(
        ledger
            .authorize_desktop_read_result(
                &owner,
                &action.id,
                action.payload_digest,
                &f,
                MonotonicMillis(6)
            )
            .is_ok()
    );
    assert!(
        matches!(ledger.dispatch(&owner,&action.id,action.payload_digest,&f,MonotonicMillis(6)).unwrap(),DispatchDisposition::Existing(s) if s.state==OperationState::Succeeded)
    );
    assert!(
        ledger
            .authorize_desktop_read_result(
                &owner,
                &ordinary.id,
                ordinary.payload_digest,
                &f,
                MonotonicMillis(6)
            )
            .is_err()
    );
    assert!(
        ledger
            .authorize_resource_access(
                &owner,
                &resource.id,
                resource.payload_digest,
                &c,
                &f,
                MonotonicMillis(6)
            )
            .is_err()
    );
    assert_eq!(f.descriptor.authorization, Authorization::Unknown);
    assert_eq!(f.descriptor.availability, Availability::Unavailable);
    assert!(f.current_observation.is_none());
    let mut required = f.clone();
    required.descriptor.authorization = Authorization::Required;
    assert!(check_desktop_read_acquisition(&c, &required, MonotonicMillis(6)).is_ok());
}
#[test]
fn acquisition_preserves_every_non_permission_admission_fence() {
    let (mut ledger, owner, resource, c, f) = setup();
    let action = prepare(&mut ledger, &owner, &resource, c.clone());
    let mut variants = Vec::new();
    for authorization in [Authorization::Denied, Authorization::Revoked] {
        let mut v = f.clone();
        v.descriptor.authorization = authorization;
        variants.push(v);
    }
    for state in [
        SessionState::Locked,
        SessionState::AuthorizationRequired,
        SessionState::Disconnected,
    ] {
        let mut v = f.clone();
        v.session_state = Some(state);
        variants.push(v);
    }
    let mut v = f.clone();
    v.descriptor.configured = false;
    variants.push(v);
    let mut v = f.clone();
    v.descriptor.remote_grant = false;
    variants.push(v);
    let mut v = f.clone();
    v.local_policy_allowed = false;
    variants.push(v);
    let mut v = f.clone();
    v.grant_revision += 1;
    variants.push(v);
    let mut v = f.clone();
    v.descriptor.capability_id = CapabilityId::DesktopCapture;
    variants.push(v);
    let mut v = f.clone();
    v.descriptor.scope = Scope::Host;
    variants.push(v);
    let mut v = f.clone();
    v.descriptor.target_session.as_mut().unwrap().generation = "session-2".try_into().unwrap();
    variants.push(v);
    for invalid in variants {
        assert!(
            ledger
                .dispatch(
                    &owner,
                    &action.id,
                    action.payload_digest,
                    &invalid,
                    MonotonicMillis(4)
                )
                .is_err()
        );
    }
    assert!(
        ledger
            .dispatch(
                &owner,
                &action.id,
                action.payload_digest,
                &f,
                MonotonicMillis(1000)
            )
            .is_err()
    );
    assert_eq!(
        ledger
            .inspect(&owner, &action.id, action.payload_digest)
            .unwrap()
            .state,
        OperationState::Reserved
    );
    acknowledge(&mut ledger, &owner, &action, &f);
}
#[test]
fn delivery_requires_original_owner_live_parent_and_fresh_authority() {
    let (mut ledger, owner, resource, c, f) = setup();
    let action = prepare(&mut ledger, &owner, &resource, c);
    assert!(
        ledger
            .authorize_desktop_read_result(
                &owner,
                &action.id,
                action.payload_digest,
                &f,
                MonotonicMillis(4)
            )
            .is_err()
    );
    acknowledge(&mut ledger, &owner, &action, &f);
    let foreign = ledger
        .register_verified_owner(
            "foreign".try_into().unwrap(),
            "foreign-epoch".try_into().unwrap(),
        )
        .unwrap();
    assert!(
        ledger
            .authorize_desktop_read_result(
                &foreign,
                &action.id,
                action.payload_digest,
                &f,
                MonotonicMillis(6)
            )
            .is_err()
    );
    let mut denied = f.clone();
    denied.descriptor.authorization = Authorization::Revoked;
    assert!(
        ledger
            .authorize_desktop_read_result(
                &owner,
                &action.id,
                action.payload_digest,
                &denied,
                MonotonicMillis(6)
            )
            .is_err()
    );
    let mut stale = f.clone();
    stale.descriptor.target_session.as_mut().unwrap().generation = "session-2".try_into().unwrap();
    assert!(
        ledger
            .authorize_desktop_read_result(
                &owner,
                &action.id,
                action.payload_digest,
                &stale,
                MonotonicMillis(6)
            )
            .is_err()
    );
    assert!(
        ledger
            .authorize_desktop_read_result(
                &owner,
                &action.id,
                action.payload_digest,
                &f,
                MonotonicMillis(1000)
            )
            .is_err()
    );
    ledger
        .record_executor_fact(
            &resource.id,
            ExecutorFact::Exited { successful: true },
            MonotonicMillis(7),
        )
        .unwrap();
    assert!(
        ledger
            .authorize_desktop_read_result(
                &owner,
                &action.id,
                action.payload_digest,
                &f,
                MonotonicMillis(8)
            )
            .is_err()
    );
}
#[test]
fn unknown_never_replays_or_delivers_and_other_domains_cannot_acquire() {
    let (mut ledger, owner, resource, c, f) = setup();
    let mut invalid = c.clone();
    invalid.capability = CapabilityId::DesktopPointer;
    assert!(
        ledger
            .prepare_desktop_read_acquisition(
                &owner,
                target(&resource),
                invalid,
                b"not-read".to_vec(),
                MonotonicMillis(3)
            )
            .is_err()
    );
    let mut invalid = c.clone();
    invalid.observation = Some("not-authority".try_into().unwrap());
    assert!(
        ledger
            .prepare_desktop_read_acquisition(
                &owner,
                target(&resource),
                invalid,
                b"not-read".to_vec(),
                MonotonicMillis(3)
            )
            .is_err()
    );
    let action = prepare(&mut ledger, &owner, &resource, c.clone());
    let DispatchDisposition::ExecuteOnce(_) = ledger
        .dispatch(
            &owner,
            &action.id,
            action.payload_digest,
            &f,
            MonotonicMillis(4),
        )
        .unwrap()
    else {
        panic!("first dispatch")
    };
    ledger
        .record_action_result(&action.id, ActionResult::Unknown, MonotonicMillis(5))
        .unwrap();
    ledger
        .record_action_result(&action.id, ActionResult::Acknowledged, MonotonicMillis(6))
        .unwrap();
    assert!(
        matches!(ledger.dispatch(&owner,&action.id,action.payload_digest,&f,MonotonicMillis(7)).unwrap(),DispatchDisposition::Existing(s) if s.state==OperationState::Unknown)
    );
    assert!(
        ledger
            .authorize_desktop_read_result(
                &owner,
                &action.id,
                action.payload_digest,
                &f,
                MonotonicMillis(7)
            )
            .is_err()
    );
    let c = context(CapabilityId::DesktopWindowsRead);
    let ordinary = ledger
        .prepare(
            &owner,
            c.clone(),
            b"ordinary-resource".to_vec(),
            MonotonicMillis(8),
        )
        .unwrap();
    let mut wf = facts(&c);
    wf.descriptor.authorization = Authorization::Granted;
    wf.descriptor.availability = Availability::Available;
    ledger
        .dispatch(
            &owner,
            &ordinary.id,
            ordinary.payload_digest,
            &wf,
            MonotonicMillis(9),
        )
        .unwrap();
    ledger
        .record_executor_fact(&ordinary.id, ExecutorFact::Running, MonotonicMillis(10))
        .unwrap();
    assert!(
        ledger
            .prepare_desktop_read_acquisition(
                &owner,
                target(&ordinary),
                context(CapabilityId::DesktopAccessibility),
                b"read".to_vec(),
                MonotonicMillis(11)
            )
            .is_err()
    );
}

#[test]
fn window_capture_purpose_cannot_be_used_for_ax_or_native_input() {
    let (mut ledger, owner, parent, _, _) = setup();
    let c = context(CapabilityId::DesktopCapture);
    let f = facts(&c);
    assert_eq!(
        check_admission(&c, &f, MonotonicMillis(3)),
        Err(ErrorCategory::PermissionRequired)
    );
    let action = ledger
        .prepare_desktop_window_capture_acquisition(
            &owner,
            target(&parent),
            c.clone(),
            b"fixed-window-capture".to_vec(),
            MonotonicMillis(3),
        )
        .unwrap();
    let DispatchDisposition::ExecuteOnce(permit) = ledger
        .dispatch(
            &owner,
            &action.id,
            action.payload_digest,
            &f,
            MonotonicMillis(4),
        )
        .unwrap()
    else {
        panic!("first dispatch missing");
    };
    assert_eq!(
        permit.purpose(),
        OperationPurpose::DesktopWindowCaptureReadAcquisition
    );
    ledger
        .record_action_result(&action.id, ActionResult::Acknowledged, MonotonicMillis(5))
        .unwrap();
    ledger
        .authorize_desktop_read_result(
            &owner,
            &action.id,
            action.payload_digest,
            &f,
            MonotonicMillis(6),
        )
        .unwrap();
    assert!(matches!(
        ledger
            .dispatch(
                &owner,
                &action.id,
                action.payload_digest,
                &f,
                MonotonicMillis(6)
            )
            .unwrap(),
        DispatchDisposition::Existing(_)
    ));
    for capability in [
        CapabilityId::DesktopAccessibility,
        CapabilityId::DesktopPointer,
        CapabilityId::DesktopKeyboard,
    ] {
        assert!(
            ledger
                .prepare_desktop_window_capture_acquisition(
                    &owner,
                    target(&parent),
                    context(capability),
                    b"bad-purpose".to_vec(),
                    MonotonicMillis(7)
                )
                .is_err()
        );
    }
    let mut revoked = f.clone();
    revoked.descriptor.authorization = Authorization::Revoked;
    assert_eq!(
        ledger.authorize_desktop_read_result(
            &owner,
            &action.id,
            action.payload_digest,
            &revoked,
            MonotonicMillis(8)
        ),
        Err(ErrorCategory::PermissionDenied)
    );
}

#[test]
fn exact_ax_write_attempt_is_separate_once_purpose_and_never_an_os_grant() {
    let (mut ledger, owner, resource, mut c, mut f) = setup();
    c.observation = Some("owned-ax-observation".try_into().unwrap());
    f.current_observation = c.observation.clone();
    f.descriptor.availability = Availability::Available;
    f.descriptor.reason = None;
    assert_eq!(
        check_admission(&c, &f, MonotonicMillis(3)),
        Err(ErrorCategory::PermissionRequired)
    );
    let action = ledger
        .prepare_desktop_accessibility_write_attempt(
            &owner,
            target(&resource),
            c.clone(),
            b"owned-once-ax-write".to_vec(),
            MonotonicMillis(3),
        )
        .unwrap();
    // The only relaxed fact is Unknown OS authorization at this exact port.
    let mut refusals = Vec::new();
    for (authorization, error) in [
        (Authorization::Required, ErrorCategory::PermissionRequired),
        (Authorization::Denied, ErrorCategory::PermissionDenied),
        (Authorization::Revoked, ErrorCategory::PermissionDenied),
    ] {
        let mut bad = f.clone();
        bad.descriptor.authorization = authorization;
        refusals.push((bad, error));
    }
    let mut bad = f.clone();
    bad.current_observation = None;
    refusals.push((bad, ErrorCategory::StaleObservation));
    let mut bad = f.clone();
    bad.descriptor.remote_grant = false;
    refusals.push((bad, ErrorCategory::PermissionDenied));
    let mut bad = f.clone();
    bad.local_policy_allowed = false;
    refusals.push((bad, ErrorCategory::PermissionDenied));
    let mut bad = f.clone();
    bad.session_state = Some(SessionState::Locked);
    refusals.push((bad, ErrorCategory::SessionLocked));
    let mut bad = f.clone();
    bad.grant_revision += 1;
    refusals.push((bad, ErrorCategory::StateConflict));
    for (bad, expected) in refusals {
        assert_eq!(
            ledger
                .dispatch(
                    &owner,
                    &action.id,
                    action.payload_digest,
                    &bad,
                    MonotonicMillis(4)
                )
                .err(),
            Some(expected)
        );
    }
    let DispatchDisposition::ExecuteOnce(permit) = ledger
        .dispatch(
            &owner,
            &action.id,
            action.payload_digest,
            &f,
            MonotonicMillis(4),
        )
        .unwrap()
    else {
        panic!("first write attempt");
    };
    assert_eq!(
        permit.purpose(),
        OperationPurpose::DesktopAccessibilityWriteAttempt
    );
    assert_eq!(permit.payload(), b"owned-once-ax-write");
    ledger
        .authorize_desktop_accessibility_write_dispatch(
            &owner,
            &action.id,
            action.payload_digest,
            &f,
            MonotonicMillis(4),
        )
        .unwrap();
    let mut current_revoked = f.clone();
    current_revoked.descriptor.authorization = Authorization::Revoked;
    assert_eq!(
        ledger.authorize_desktop_accessibility_write_dispatch(
            &owner,
            &action.id,
            action.payload_digest,
            &current_revoked,
            MonotonicMillis(4)
        ),
        Err(ErrorCategory::PermissionDenied)
    );
    assert_eq!(
        ledger.authorize_desktop_accessibility_write_dispatch(
            &owner,
            &action.id,
            action.payload_digest,
            &f,
            MonotonicMillis(1000)
        ),
        Err(ErrorCategory::OperationTimeout)
    );
    ledger
        .record_action_result(&action.id, ActionResult::Acknowledged, MonotonicMillis(5))
        .unwrap();
    ledger
        .authorize_desktop_accessibility_write_result(
            &owner,
            &action.id,
            action.payload_digest,
            &f,
            MonotonicMillis(6),
        )
        .unwrap();
    assert_eq!(
        ledger.authorize_desktop_read_result(
            &owner,
            &action.id,
            action.payload_digest,
            &f,
            MonotonicMillis(6)
        ),
        Err(ErrorCategory::StateConflict)
    );
    let mut revoked = f.clone();
    revoked.descriptor.authorization = Authorization::Revoked;
    assert_eq!(
        ledger.authorize_desktop_accessibility_write_result(
            &owner,
            &action.id,
            action.payload_digest,
            &revoked,
            MonotonicMillis(6)
        ),
        Err(ErrorCategory::PermissionDenied)
    );
    // Delivery refusal does not turn the recorded ACK into cancellation/retry.
    assert!(
        matches!(ledger.dispatch(&owner, &action.id, action.payload_digest, &f, MonotonicMillis(7)).unwrap(), DispatchDisposition::Existing(s) if s.state == OperationState::Succeeded)
    );
    assert_eq!(f.descriptor.authorization, Authorization::Unknown);
    let unknown = ledger
        .prepare_desktop_accessibility_write_attempt(
            &owner,
            target(&resource),
            c,
            b"another-once-ax-write".to_vec(),
            MonotonicMillis(8),
        )
        .unwrap();
    assert!(matches!(
        ledger
            .dispatch(
                &owner,
                &unknown.id,
                unknown.payload_digest,
                &f,
                MonotonicMillis(9)
            )
            .unwrap(),
        DispatchDisposition::ExecuteOnce(_)
    ));
    ledger
        .record_action_result(&unknown.id, ActionResult::Unknown, MonotonicMillis(10))
        .unwrap();
    assert!(
        matches!(ledger.dispatch(&owner, &unknown.id, unknown.payload_digest, &f, MonotonicMillis(11)).unwrap(), DispatchDisposition::Existing(s) if s.state == OperationState::Unknown)
    );
    assert_eq!(
        ledger.authorize_desktop_accessibility_write_result(
            &owner,
            &unknown.id,
            unknown.payload_digest,
            &f,
            MonotonicMillis(11)
        ),
        Err(ErrorCategory::StateConflict)
    );
}
