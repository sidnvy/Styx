//! Actual Host State composition, real UID/OS entropy/Instant; no native executor
//! is started. A consumed Core permit is not a native execution receipt.
use super::*;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use crate::session::ProviderEvidence;
use crate::session::{HostSessionError, SessionSupport};
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use styx_contracts::session::*;
use styx_contracts::{capability::*, error::Recovery};
fn exec_facts() -> AdmissionFacts {
    AdmissionFacts {
        device_id: DeviceId::try_from("session-test-host").unwrap(),
        grant_revision: 5,
        local_policy_allowed: true,
        descriptor: CapabilityDescriptor {
            contract_version: styx_contracts::CONTRACT_VERSION,
            capability_id: CapabilityId::ExecRun,
            scope: Scope::Host,
            provider_id: ProviderId::try_from("codex").unwrap(),
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
    }
}
fn state() -> State {
    State::new(
        OperationLedger::new(HostGeneration::try_from("same-test-host-generation").unwrap()),
        exec_facts(),
        Instant::now(),
    )
}
fn context() -> PreparedContext {
    PreparedContext {
        device_id: exec_facts().device_id,
        grant_revision: 5,
        session: None,
        observation: None,
        capability: CapabilityId::ExecRun,
        deadline: MonotonicMillis(10000),
        disconnect_policy: DisconnectPolicy::RetainForOwner,
    }
}
fn owner(state: &mut State) -> OwnerLease {
    state
        .ledger
        .register_verified_owner(
            OwnerId::try_from("test-owner").unwrap(),
            OwnerEpoch::try_from("test-owner-epoch").unwrap(),
        )
        .unwrap()
}
fn reserve_dispatch(state: &mut State, owner: &OwnerLease) {
    let reservation = state
        .reserve_exec(
            owner,
            context(),
            b"prepared-exec-payload".to_vec(),
            None,
            MonotonicMillis(0),
        )
        .unwrap();
    assert_eq!(reservation.state, OperationState::Reserved);
    let DispatchDisposition::ExecuteOnce(permit) = state
        .dispatch_exec(
            owner,
            &reservation.id,
            reservation.payload_digest,
            MonotonicMillis(1),
        )
        .unwrap()
    else {
        panic!("new reservation must issue exactly one permit")
    };
    assert_eq!(permit.context().capability, CapabilityId::ExecRun);
    assert!(permit.context().session.is_none());
    assert!(permit.context().observation.is_none());
    assert!(matches!(
        state
            .dispatch_exec(
                owner,
                &reservation.id,
                reservation.payload_digest,
                MonotonicMillis(1)
            )
            .unwrap(),
        DispatchDisposition::Existing(_)
    ));
    // No fake Started/Exited result: this fixture consumes no executor I/O.
    assert_eq!(
        state
            .ledger
            .inspect(owner, &reservation.id, reservation.payload_digest)
            .unwrap()
            .state,
        OperationState::Dispatched
    );
}
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn registration() -> RegistrationFacts {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let uid = nix::unistd::Uid::current().as_raw();
    #[cfg(target_os = "linux")]
    let identity = SessionIdentity::Linux {
        uid,
        login_instance: "synthetic-login".into(),
        seat: Some("synthetic-seat".into()),
        compositor_instance: "synthetic-compositor".into(),
        display_identity: "synthetic-display".into(),
    };
    #[cfg(target_os = "macos")]
    let identity = SessionIdentity::Macos {
        uid,
        audit_session: 1,
        console_instance: "synthetic-console".into(),
        window_server_instance: Some("synthetic-window-server".into()),
    };
    #[cfg(target_os = "windows")]
    let identity = {
        let crate::store::ProcessIdentity::Windows { owner_sid, .. } =
            crate::store::ProcessIdentity::current().unwrap()
        else {
            panic!("expected the current Windows process token");
        };
        SessionIdentity::Windows {
            sid: owner_sid,
            authentication_luid: 1,
            session_id: 1,
            window_station: "synthetic-station".into(),
            desktop: "synthetic-desktop".into(),
            integrity_level: 0x2000,
        }
    };
    RegistrationFacts {
        id: SessionId::try_from("test-session").unwrap(),
        identity,
        agent_instance: AgentInstanceId::try_from("synthetic-agent").unwrap(),
        protocol_version: 1,
        provenance: "trusted fixture only; no native session proof".into(),
    }
}
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn evidence(capability: CapabilityId) -> ProviderEvidence {
    ProviderEvidence {
        capability,
        provider: ProviderId::try_from("synthetic-provider").unwrap(),
        availability: Availability::Available,
        authorization: Authorization::Granted,
        provenance: "synthetic actual-adapter-port fixture".into(),
        reason: None,
        recovery: Recovery::Reobserve,
    }
}
#[test]
fn actual_host_state_session_composition_and_exec_guards() {
    let mut first = state();
    let owner = owner(&mut first);
    // No desktop discovery or GUI is necessary for existing Exec admission.
    assert_eq!(first.sessions.status().sessions, 0);
    reserve_dispatch(&mut first, &owner);
    let mut invalid = context();
    invalid.capability = CapabilityId::DesktopPointer;
    assert!(matches!(
        first.reserve_exec(&owner, invalid, b"x".to_vec(), None, MonotonicMillis(0)),
        Err(CoordinatorError::Admission(ErrorCategory::ProtocolMismatch))
    ));
    let mut invalid = context();
    invalid.observation = Some(ObservationId::try_from("network-observation").unwrap());
    assert!(matches!(
        first.reserve_exec(&owner, invalid, b"x".to_vec(), None, MonotonicMillis(0)),
        Err(CoordinatorError::Admission(ErrorCategory::StateConflict))
    ));
    let reserved = first
        .reserve_exec(
            &owner,
            context(),
            b"pending".to_vec(),
            None,
            MonotonicMillis(0),
        )
        .unwrap();
    let original = first.facts.clone();
    first.facts.descriptor.capability_id = CapabilityId::DesktopCapture;
    assert!(matches!(
        first.dispatch_exec(
            &owner,
            &reserved.id,
            reserved.payload_digest,
            MonotonicMillis(1)
        ),
        Err(ErrorCategory::ProtocolMismatch)
    ));
    assert_eq!(
        first
            .ledger
            .inspect(&owner, &reserved.id, reserved.payload_digest)
            .unwrap()
            .state,
        OperationState::Reserved
    );
    assert!(matches!(
        first.authorize_exec_read(
            &owner,
            &reserved.id,
            reserved.payload_digest,
            &context(),
            MonotonicMillis(1)
        ),
        Err(ErrorCategory::ProtocolMismatch)
    ));
    for contamination in 0..4 {
        first.facts = original.clone();
        match contamination {
            0 => first.facts.descriptor.scope = Scope::Session,
            1 => first.facts.session_state = Some(styx_contracts::session::SessionState::Locked),
            2 => {
                first.facts.current_observation =
                    Some(ObservationId::try_from("miswired-observation").unwrap())
            }
            _ => {
                first.facts.descriptor.target_session =
                    Some(styx_contracts::session::SessionBinding {
                        id: SessionId::try_from("miswired-session").unwrap(),
                        generation: SessionGeneration::try_from("miswired-generation").unwrap(),
                    })
            }
        }
        assert!(matches!(
            first.dispatch_exec(
                &owner,
                &reserved.id,
                reserved.payload_digest,
                MonotonicMillis(1)
            ),
            Err(ErrorCategory::StateConflict)
        ));
        assert_eq!(
            first
                .ledger
                .inspect(&owner, &reserved.id, reserved.payload_digest)
                .unwrap()
                .state,
            OperationState::Reserved
        );
    }
    first.facts = original;
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    {
        assert_eq!(first.sessions.status().support, SessionSupport::Enabled);
        // Owning an OS principal does not attest an arbitrary remote user or
        // create a desktop. Exercise this on the same real Host registry used
        // by the registration/locking/Exec isolation scenario below.
        let mut foreign = registration();
        match &mut foreign.identity {
            SessionIdentity::Linux { uid, .. } | SessionIdentity::Macos { uid, .. } => {
                *uid = uid.wrapping_add(1);
            }
            SessionIdentity::Windows { sid, .. } => sid.push_str("-1"),
        }
        assert!(
            first
                .with_sessions(|sessions| sessions.attest(foreign))
                .is_err()
        );
        assert_eq!(first.sessions.status().sessions, 0);
        let mut second = state();
        let mut third = state();
        let transferred = first
            .with_sessions(|sessions| sessions.attest(registration()))
            .unwrap();
        assert_eq!(
            second.with_sessions(|sessions| sessions.register(transferred)),
            Err(HostSessionError::Core(SessionError::Authority))
        );
        assert_eq!(second.sessions.status().sessions, 0);
        let first_registration = first
            .with_sessions(|sessions| sessions.attest(registration()))
            .unwrap();
        let second_registration = second
            .with_sessions(|sessions| sessions.attest(registration()))
            .unwrap();
        let a = first
            .with_sessions(|sessions| sessions.register(first_registration))
            .unwrap();
        let b = second
            .with_sessions(|sessions| sessions.register(second_registration))
            .unwrap();
        // Real OS entropy is used by both bootstraps, not injected counters.
        assert_ne!(a.generation, b.generation);
        assert_eq!(
            second.sessions.inspect(&a),
            Err(HostSessionError::Core(SessionError::StaleBinding))
        );
        assert_eq!(
            first.sessions.inspect(&a).unwrap().descriptor.state,
            SessionState::Discovered
        );
        first
            .with_sessions(|sessions| {
                sessions.provider(
                    &a,
                    evidence(CapabilityId::DesktopPointer),
                    Duration::from_secs(60),
                )
            })
            .unwrap();
        second
            .with_sessions(|sessions| {
                sessions.provider(
                    &b,
                    evidence(CapabilityId::DesktopPointer),
                    Duration::from_secs(60),
                )
            })
            .unwrap();
        let oa = first
            .with_sessions(|sessions| sessions.observe(&a, CapabilityId::DesktopPointer))
            .unwrap();
        let ob = second
            .with_sessions(|sessions| sessions.observe(&b, CapabilityId::DesktopPointer))
            .unwrap();
        assert_ne!(oa, ob);
        let before = first.sessions.status();
        assert_eq!(
            first.with_sessions(|sessions| sessions.provider(
                &a,
                evidence(CapabilityId::DesktopPointer),
                Duration::from_secs(61)
            )),
            Err(HostSessionError::InvalidEvidence)
        );
        assert_eq!(first.sessions.status(), before);
        assert_eq!(
            first.with_sessions(|sessions| sessions.provider(
                &a,
                evidence(CapabilityId::ExecRun),
                Duration::from_secs(1)
            )),
            Err(HostSessionError::Core(SessionError::Invalid))
        );
        // Session mutation never replaces grant, local policy or Exec descriptor.
        assert_eq!(first.facts.descriptor, exec_facts().descriptor);
        assert_eq!(first.facts.grant_revision, 5);
        assert!(first.facts.local_policy_allowed);
        let approved = first
            .with_sessions(|sessions| sessions.select(Selection::Unbound, true))
            .unwrap();
        assert_eq!(
            second
                .with_sessions(|sessions| sessions.select(Selection::Approved(&approved), true))
                .err(),
            Some(HostSessionError::Core(SessionError::Authority))
        );
        let locked = first
            .with_sessions(|sessions| sessions.set_state(&a, SessionState::Locked))
            .unwrap();
        assert_eq!(
            first.sessions.inspect(&locked).unwrap().descriptor.state,
            SessionState::Locked
        );
        reserve_dispatch(&mut first, &owner);
        let stopped_registration = third
            .with_sessions(|sessions| sessions.attest(registration()))
            .unwrap();
        third.shutting_down = true;
        assert_eq!(
            third.with_sessions(|sessions| sessions.register(stopped_registration)),
            Err(HostSessionError::Stopping)
        );
        assert_eq!(third.sessions.status().sessions, 0);
        assert!(first.sessions.events(0).unwrap().len() >= 4);
        let mut invalid = context();
        invalid.session = Some(locked);
        assert!(matches!(
            first.reserve_exec(&owner, invalid, b"x".to_vec(), None, MonotonicMillis(0)),
            Err(CoordinatorError::Admission(ErrorCategory::StateConflict))
        ));
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        assert_eq!(
            first.sessions.status().support,
            SessionSupport::UnsupportedPlatform
        );
        assert_eq!(
            first.sessions.list(),
            Err(HostSessionError::UnsupportedPlatform)
        );
        reserve_dispatch(&mut first, &owner);
    }
}
