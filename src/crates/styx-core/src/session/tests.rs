//! Pure Core state/contract journeys. No native desktop or kernel verification.
use super::*;
use crate::policy::{AdmissionFacts, check_admission};
use styx_contracts::{error::Recovery, operation::*};

fn registry(limits: SessionLimits) -> (SessionRegistry, SessionControl) {
    SessionRegistry::new_owned(
        HostGeneration::try_from("host-one").unwrap(),
        RegistryIncarnation::from_fresh_entropy([1; 32]).unwrap(),
        NativePrincipal::LinuxUid(1000),
        limits,
    )
    .unwrap()
}
fn registration(id: &str) -> RegistrationFacts {
    RegistrationFacts {
        id: SessionId::try_from(id).unwrap(),
        identity: SessionIdentity::Linux {
            uid: 1000,
            login_instance: format!("login-{id}"),
            seat: Some("seat0".into()),
            compositor_instance: format!("compositor-{id}"),
            display_identity: format!("display-{id}"),
        },
        agent_instance: AgentInstanceId::try_from("agent-one").unwrap(),
        protocol_version: 1,
        provenance: "trusted-test-adapter; synthetic association".into(),
    }
}
fn register(registry: &mut SessionRegistry, control: &SessionControl, id: &str) -> SessionBinding {
    registry
        .register(
            control,
            control.attest_registration(registration(id)).unwrap(),
        )
        .unwrap()
}
fn provider(capability: CapabilityId) -> ProviderFacts {
    ProviderFacts {
        capability,
        provider: ProviderId::try_from("native-test-provider").unwrap(),
        availability: Availability::Available,
        authorization: Authorization::Granted,
        observed_at: 10,
        valid_until: 100,
        provenance: "synthetic capability facts, not OS permission evidence".into(),
        reason: None,
        recovery: Recovery::Reobserve,
    }
}
fn ready(registry: &mut SessionRegistry, control: &SessionControl, binding: &SessionBinding) {
    registry
        .update_provider(control, binding, provider(CapabilityId::DesktopWindowsRead))
        .unwrap();
}
#[test]
fn selection_never_falls_back_or_turns_dto_into_authority() {
    let (mut directory, control) = registry(SessionLimits::default());
    let authority = control.selection_authority(true);
    assert_eq!(
        directory.select(&authority, Selection::Unbound, 30).err(),
        Some(SessionError::NoGraphicalSession)
    );
    let a = register(&mut directory, &control, "a");
    assert_eq!(
        directory.select(&authority, Selection::Unbound, 30).err(),
        Some(SessionError::SessionDisconnected)
    );
    ready(&mut directory, &control, &a);
    let approved = directory
        .select(&authority, Selection::Unbound, 30)
        .unwrap();
    assert_eq!(approved.binding(), &a);
    let b = register(&mut directory, &control, "b");
    let locked_b = directory
        .set_state(&control, &b, SessionState::Locked)
        .unwrap();
    assert_eq!(
        directory.select(&authority, Selection::Unbound, 30).err(),
        Some(SessionError::SessionAmbiguous)
    );
    assert_eq!(
        directory
            .select(&authority, Selection::Explicit(&locked_b), 30)
            .err(),
        Some(SessionError::SessionLocked)
    );
    let unknown = SessionBinding {
        id: SessionId::try_from("missing").unwrap(),
        generation: a.generation.clone(),
    };
    assert_eq!(
        directory
            .select(&authority, Selection::Explicit(&unknown), 30)
            .err(),
        Some(SessionError::NotFound)
    );
    let new_a = directory
        .set_state(&control, &a, SessionState::Disconnected)
        .unwrap();
    assert_eq!(
        directory
            .select(&authority, Selection::Approved(&approved), 30)
            .err(),
        Some(SessionError::StaleBinding)
    );
    assert_eq!(
        directory
            .select(&authority, Selection::Explicit(&new_a), 30)
            .err(),
        Some(SessionError::SessionDisconnected)
    );
    let (mut other, other_control) = registry(SessionLimits::default());
    let other_a = register(&mut other, &other_control, "a");
    ready(&mut other, &other_control, &other_a);
    let other_authority = other_control.selection_authority(true);
    let other_approved = other
        .select(&other_authority, Selection::Unbound, 30)
        .unwrap();
    assert_eq!(
        directory
            .select(&other_authority, Selection::Unbound, 30)
            .err(),
        Some(SessionError::Authority)
    );
    assert_eq!(
        directory
            .select(&authority, Selection::Approved(&other_approved), 30)
            .err(),
        Some(SessionError::Authority)
    );
    let before = (
        directory.list(30),
        directory.cursor(),
        directory.metadata_bytes(),
    );
    assert_eq!(
        directory.register(
            &control,
            other_control
                .attest_registration(registration("c"))
                .unwrap()
        ),
        Err(SessionError::Authority)
    );
    assert_eq!(
        directory.set_state(&other_control, &new_a, SessionState::Locked),
        Err(SessionError::Authority)
    );
    assert_eq!(
        (
            directory.list(30),
            directory.cursor(),
            directory.metadata_bytes()
        ),
        before
    );
    let mut wrong_user = registration("wrong-user");
    if let SessionIdentity::Linux { uid, .. } = &mut wrong_user.identity {
        *uid = 1001;
    }
    assert_eq!(
        control.attest_registration(wrong_user).err(),
        Some(SessionError::Invalid)
    );
    let deny = other_control.selection_authority(false);
    assert_eq!(
        other.select(&deny, Selection::Unbound, 30).err(),
        Some(SessionError::PermissionDenied)
    );
}

#[test]
fn identity_lifecycle_and_terminal_reuse_never_revive_old_generation() {
    let (mut directory, control) = registry(SessionLimits::default());
    let authority = control.selection_authority(true);
    let a = register(&mut directory, &control, "a");
    ready(&mut directory, &control, &a);
    let approved = directory
        .select(&authority, Selection::Unbound, 30)
        .unwrap();
    let pointer = CapabilityId::DesktopPointer;
    directory
        .update_provider(&control, &a, provider(pointer))
        .unwrap();
    let old_observation = directory
        .record_observation(&control, &a, pointer, 20)
        .unwrap();
    let locked = directory
        .set_state(&control, &a, SessionState::Locked)
        .unwrap();
    assert_ne!(locked.generation, a.generation);
    assert_eq!(
        directory.project(&a, pointer, 21),
        Err(SessionError::StaleBinding)
    );
    assert_eq!(
        directory
            .select(&authority, Selection::Approved(&approved), 30)
            .err(),
        Some(SessionError::StaleBinding)
    );
    assert_eq!(
        directory.project(&locked, pointer, 21),
        Err(SessionError::SessionLocked)
    );
    let unlocked = directory
        .set_state(&control, &locked, SessionState::Connecting)
        .unwrap();
    assert_ne!(unlocked.generation, locked.generation);
    assert!(
        directory
            .inspect(&unlocked, 30)
            .unwrap()
            .providers
            .is_empty()
    );
    directory
        .update_provider(&control, &unlocked, provider(pointer))
        .unwrap();
    let fresh = directory
        .record_observation(&control, &unlocked, pointer, 22)
        .unwrap();
    assert_ne!(old_observation, fresh);
    let mut current = unlocked;
    for mutate in [0, 1, 2] {
        let mut facts = registration("a");
        // Derive current trusted identity before changing only one fact.
        let view = directory.inspect(&current, 30).unwrap();
        facts.identity = view.descriptor.identity;
        facts.agent_instance = view.descriptor.agent_instance;
        facts.protocol_version = view.descriptor.protocol_version;
        match mutate {
            0 => {
                if let SessionIdentity::Linux {
                    compositor_instance,
                    ..
                } = &mut facts.identity
                {
                    *compositor_instance = "replacement-compositor".into();
                }
            }
            1 => facts.agent_instance = AgentInstanceId::try_from("replacement-agent").unwrap(),
            _ => facts.protocol_version += 1,
        }
        let next = directory
            .register(&control, control.attest_registration(facts).unwrap())
            .unwrap();
        assert_ne!(next.generation, current.generation);
        assert_eq!(
            directory.inspect(&current, 30),
            Err(SessionError::StaleBinding)
        );
        assert_eq!(
            directory.inspect(&next, 30).unwrap().descriptor.state,
            SessionState::Discovered
        );
        assert!(directory.inspect(&next, 30).unwrap().providers.is_empty());
        current = next;
    }
    let disconnected = directory
        .set_state(&control, &current, SessionState::Disconnected)
        .unwrap();
    let recovered = directory
        .register(
            &control,
            control.attest_registration(registration("a")).unwrap(),
        )
        .unwrap();
    assert_ne!(disconnected.generation, recovered.generation);
    let terminated = directory
        .set_state(&control, &recovered, SessionState::Terminated)
        .unwrap();
    directory.forget(&control, &terminated).unwrap();
    let recreated = register(&mut directory, &control, "a");
    assert_ne!(recreated.generation, a.generation);
    assert_ne!(recreated.generation, terminated.generation);
    assert_eq!(
        directory.inspect(&terminated, 30),
        Err(SessionError::StaleBinding)
    );
}

fn policy_facts(projection: &SessionProjection) -> AdmissionFacts {
    AdmissionFacts {
        device_id: DeviceId::try_from("test-device").unwrap(),
        grant_revision: 7,
        local_policy_allowed: true,
        descriptor: CapabilityDescriptor {
            contract_version: styx_contracts::CONTRACT_VERSION,
            capability_id: projection.provider.facts.capability,
            scope: Scope::Session,
            provider_id: projection.provider.facts.provider.clone(),
            configured: true,
            remote_grant: true,
            availability: projection.provider.facts.availability,
            authorization: projection.provider.facts.authorization,
            target_session: Some(projection.binding.clone()),
            reason: None,
            observed_at: projection.provider.facts.observed_at,
            observation_generation: projection.provider.revision,
            recovery: Recovery::Reobserve,
        },
        session_state: Some(projection.state),
        current_observation: projection.provider.observation.clone(),
    }
}
#[test]
fn provider_loss_is_local_and_fresh_projection_reuses_existing_policy() {
    let (mut directory, control) = registry(SessionLimits::default());
    let a = register(&mut directory, &control, "a");
    for capability in [
        CapabilityId::DesktopPointer,
        CapabilityId::DesktopCapture,
        CapabilityId::DesktopWindowsRead,
    ] {
        directory
            .update_provider(&control, &a, provider(capability))
            .unwrap();
    }
    let pointer = directory
        .record_observation(&control, &a, CapabilityId::DesktopPointer, 20)
        .unwrap();
    let capture = directory
        .record_observation(&control, &a, CapabilityId::DesktopCapture, 20)
        .unwrap();
    let projection = directory
        .project(&a, CapabilityId::DesktopPointer, 20)
        .unwrap();
    let context = PreparedContext {
        device_id: DeviceId::try_from("test-device").unwrap(),
        grant_revision: 7,
        session: Some(a.clone()),
        observation: Some(pointer.clone()),
        capability: CapabilityId::DesktopPointer,
        deadline: MonotonicMillis(90),
        disconnect_policy: DisconnectPolicy::RetainForOwner,
    };
    assert_eq!(
        check_admission(&context, &policy_facts(&projection), MonotonicMillis(21)),
        Ok(())
    );
    let mut denied = provider(CapabilityId::DesktopCapture);
    denied.authorization = Authorization::Revoked;
    denied.observed_at = 22;
    directory.update_provider(&control, &a, denied).unwrap();
    let view = directory.inspect(&a, 30).unwrap();
    assert_eq!(view.descriptor.state, SessionState::Degraded);
    assert_eq!(
        directory.project(&a, CapabilityId::DesktopCapture, 23),
        Err(SessionError::PermissionDenied)
    );
    let pointer_projection = directory
        .project(&a, CapabilityId::DesktopPointer, 23)
        .unwrap();
    assert_eq!(
        pointer_projection.provider.observation,
        Some(pointer.clone())
    );
    assert_eq!(
        check_admission(
            &context,
            &policy_facts(&pointer_projection),
            MonotonicMillis(23)
        ),
        Ok(())
    );
    assert!(
        directory
            .project(&a, CapabilityId::DesktopWindowsRead, 23)
            .is_ok()
    );
    let mut unavailable = provider(CapabilityId::DesktopCapture);
    unavailable.availability = Availability::Unavailable;
    unavailable.reason = Some(ErrorCategory::CompositorRestarted);
    unavailable.recovery = Recovery::Rediscover;
    unavailable.observed_at = 23;
    directory
        .update_provider(&control, &a, unavailable)
        .unwrap();
    assert_eq!(
        directory.project(&a, CapabilityId::DesktopCapture, 24),
        Err(SessionError::Provider(ErrorCategory::CompositorRestarted))
    );
    assert_eq!(
        directory
            .inspect(&a, 30)
            .unwrap()
            .providers
            .iter()
            .find(|p| p.facts.capability == CapabilityId::DesktopCapture)
            .unwrap()
            .facts
            .recovery,
        Recovery::Rediscover
    );
    let mut restored = provider(CapabilityId::DesktopCapture);
    restored.observed_at = 24;
    directory.update_provider(&control, &a, restored).unwrap();
    assert_eq!(
        directory
            .project(&a, CapabilityId::DesktopCapture, 25)
            .unwrap()
            .provider
            .observation,
        None
    );
    let new_capture = directory
        .record_observation(&control, &a, CapabilityId::DesktopCapture, 25)
        .unwrap();
    assert_ne!(capture, new_capture);
    let mut refreshed = provider(CapabilityId::DesktopPointer);
    refreshed.observed_at = 26;
    directory.update_provider(&control, &a, refreshed).unwrap();
    let new_projection = directory
        .project(&a, CapabilityId::DesktopPointer, 27)
        .unwrap();
    assert_eq!(
        check_admission(
            &context,
            &policy_facts(&new_projection),
            MonotonicMillis(27)
        ),
        Err(ErrorCategory::StaleObservation)
    );
    assert_eq!(
        directory.project(&a, CapabilityId::DesktopPointer, 100),
        Err(SessionError::StaleObservation)
    );
    assert_eq!(
        directory.project(&a, CapabilityId::DesktopPointer, 25),
        Err(SessionError::StaleObservation)
    );
    // Projection carries no Gateway grant. The trusted Host independently
    // intersects real grant/configuration/local policy with these facts.
    let mut facts = policy_facts(&new_projection);
    facts.descriptor.remote_grant = false;
    assert_eq!(
        check_admission(&context, &facts, MonotonicMillis(27)),
        Err(ErrorCategory::PermissionDenied)
    );
    for capability in [
        CapabilityId::ExecRun,
        CapabilityId::BrowserHeadless,
        CapabilityId::BrowserAttach,
    ] {
        let before = (
            directory.list(30),
            directory.cursor(),
            directory.metadata_bytes(),
        );
        assert_eq!(
            directory.update_provider(&control, &a, provider(capability)),
            Err(SessionError::Invalid)
        );
        assert_eq!(
            directory.project(&a, capability, 27),
            Err(SessionError::CapabilityUnsupported)
        );
        assert_eq!(
            (
                directory.list(30),
                directory.cursor(),
                directory.metadata_bytes()
            ),
            before
        );
    }
    // This is Core policy independence, not an actual native/headless run.
    for capability in [CapabilityId::ExecRun, CapabilityId::BrowserHeadless] {
        let mut context = context.clone();
        context.capability = capability;
        context.session = None;
        context.observation = None;
        let mut facts = policy_facts(&new_projection);
        facts.descriptor.capability_id = capability;
        facts.descriptor.target_session = None;
        facts.session_state = None;
        facts.current_observation = None;
        assert_eq!(
            check_admission(&context, &facts, MonotonicMillis(27)),
            Ok(())
        );
    }
}

#[test]
fn metadata_entry_limits_and_event_gaps_are_atomic_and_explicit() {
    let limits = SessionLimits {
        sessions: 1,
        providers_per_session: 1,
        events: 2,
        ..SessionLimits::default()
    };
    let (mut directory, control) = registry(limits);
    let a = register(&mut directory, &control, "a");
    ready(&mut directory, &control, &a);
    let before = (
        directory.list(30),
        directory.cursor(),
        directory.metadata_bytes(),
        directory.issuer,
    );
    assert_eq!(
        directory.register(
            &control,
            control.attest_registration(registration("b")).unwrap()
        ),
        Err(SessionError::Capacity)
    );
    assert_eq!(
        directory.update_provider(&control, &a, provider(CapabilityId::DesktopPointer)),
        Err(SessionError::Capacity)
    );
    assert_eq!(directory.forget(&control, &a), Err(SessionError::Invalid));
    assert_eq!(
        (
            directory.list(30),
            directory.cursor(),
            directory.metadata_bytes(),
            directory.issuer
        ),
        before
    );
    assert_eq!(directory.events_since(0).unwrap().len(), 2);
    directory
        .record_observation(&control, &a, CapabilityId::DesktopWindowsRead, 20)
        .unwrap();
    assert_eq!(
        directory.events_since(0),
        Err(SessionError::ResnapshotRequired)
    );
    assert_eq!(directory.events_since(1).unwrap().len(), 2);
    assert!(
        directory
            .events_since(directory.cursor())
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        directory.events_since(directory.cursor() + 1),
        Err(SessionError::Invalid)
    );
    let t = directory
        .set_state(&control, &a, SessionState::Terminated)
        .unwrap();
    directory.forget(&control, &t).unwrap();
    assert!(directory.list(30).is_empty());
    register(&mut directory, &control, "b");
    let (mut small, control) = registry(SessionLimits {
        metadata_bytes: 3500,
        ..SessionLimits::default()
    });
    let before = (
        small.list(30),
        small.cursor(),
        small.metadata_bytes(),
        small.issuer,
    );
    assert_eq!(
        small.register(
            &control,
            control.attest_registration(registration("a")).unwrap()
        ),
        Err(SessionError::Capacity)
    );
    assert_eq!(
        (
            small.list(30),
            small.cursor(),
            small.metadata_bytes(),
            small.issuer
        ),
        before
    );
    assert!(
        SessionRegistry::new_owned(
            HostGeneration::try_from("host").unwrap(),
            RegistryIncarnation::from_fresh_entropy([1; 32]).unwrap(),
            NativePrincipal::LinuxUid(1),
            SessionLimits {
                sessions: 33,
                ..SessionLimits::default()
            }
        )
        .is_err()
    );
}

#[test]
fn invalid_facts_and_counter_exhaustion_do_not_partially_mutate() {
    let (mut directory, control) = registry(SessionLimits::default());
    let mut too_long = registration("a");
    too_long.provenance = "x".repeat(257);
    assert_eq!(
        control.attest_registration(too_long).err(),
        Some(SessionError::Invalid)
    );
    let mut wrong_platform = registration("a");
    wrong_platform.identity = SessionIdentity::Macos {
        uid: 1000,
        audit_session: 1,
        console_instance: "console".into(),
        window_server_instance: None,
    };
    assert_eq!(
        control.attest_registration(wrong_platform).err(),
        Some(SessionError::Invalid)
    );
    let a = register(&mut directory, &control, "a");
    ready(&mut directory, &control, &a);
    let before = (
        directory.list(30),
        directory.cursor(),
        directory.metadata_bytes(),
        directory.issuer,
    );
    let mut facts = provider(CapabilityId::DesktopWindowsRead);
    facts.valid_until = facts.observed_at;
    assert_eq!(
        directory.update_provider(&control, &a, facts),
        Err(SessionError::Invalid)
    );
    let mut backwards = provider(CapabilityId::DesktopWindowsRead);
    backwards.observed_at = 9;
    assert_eq!(
        directory.update_provider(&control, &a, backwards),
        Err(SessionError::Invalid)
    );
    assert_eq!(
        directory.set_state(&control, &a, SessionState::Ready),
        Err(SessionError::Invalid)
    );
    assert_eq!(
        (
            directory.list(30),
            directory.cursor(),
            directory.metadata_bytes(),
            directory.issuer
        ),
        before
    );
    directory.issuer = u64::MAX;
    let before = (
        directory.list(30),
        directory.cursor(),
        directory.metadata_bytes(),
        directory.issuer,
    );
    assert_eq!(
        directory.set_state(&control, &a, SessionState::Locked),
        Err(SessionError::Exhausted)
    );
    assert_eq!(
        directory.record_observation(&control, &a, CapabilityId::DesktopWindowsRead, 20),
        Err(SessionError::Exhausted)
    );
    assert_eq!(
        (
            directory.list(30),
            directory.cursor(),
            directory.metadata_bytes(),
            directory.issuer
        ),
        before
    );
    directory.issuer = 5;
    directory.cursor = u64::MAX;
    let before = (
        directory.list(30),
        directory.cursor(),
        directory.metadata_bytes(),
        directory.issuer,
    );
    assert_eq!(
        directory.update_provider(&control, &a, provider(CapabilityId::DesktopWindowsRead)),
        Err(SessionError::Exhausted)
    );
    assert_eq!(
        (
            directory.list(30),
            directory.cursor(),
            directory.metadata_bytes(),
            directory.issuer
        ),
        before
    );
}

#[test]
fn safety_review_regressions_revocation_incarnation_and_freshness() {
    // Revocation is a retained bounded tombstone, not an auto-rediscovery hint.
    let (mut directory, control) = registry(SessionLimits {
        sessions: 2,
        ..SessionLimits::default()
    });
    let a = register(&mut directory, &control, "a");
    ready(&mut directory, &control, &a);
    let mut alias = registration("a");
    alias.id = SessionId::try_from("alias-before-revoke").unwrap();
    assert_eq!(
        directory.register(&control, control.attest_registration(alias).unwrap()),
        Err(SessionError::Invalid)
    );
    let revoked = directory
        .set_state(&control, &a, SessionState::Revoked)
        .unwrap();
    let before = (
        directory.list(30),
        directory.cursor(),
        directory.metadata_bytes(),
        directory.issuer,
    );
    assert_eq!(
        directory.register(
            &control,
            control.attest_registration(registration("a")).unwrap()
        ),
        Err(SessionError::PermissionDenied)
    );
    let mut alias = registration("a");
    alias.id = SessionId::try_from("alias-after-revoke").unwrap();
    assert_eq!(
        directory.register(&control, control.attest_registration(alias).unwrap()),
        Err(SessionError::PermissionDenied)
    );
    let mut replacement_same_id = registration("a");
    if let SessionIdentity::Linux {
        compositor_instance,
        ..
    } = &mut replacement_same_id.identity
    {
        *compositor_instance = "new-instance".into();
    }
    assert_eq!(
        directory.register(
            &control,
            control.attest_registration(replacement_same_id).unwrap()
        ),
        Err(SessionError::PermissionDenied)
    );
    assert_eq!(
        directory.forget(&control, &revoked),
        Err(SessionError::Invalid)
    );
    assert_eq!(
        directory.set_state(&control, &revoked, SessionState::Terminated),
        Err(SessionError::SessionDisconnected)
    );
    assert_eq!(
        directory.update_provider(
            &control,
            &revoked,
            provider(CapabilityId::DesktopWindowsRead)
        ),
        Err(SessionError::SessionDisconnected)
    );
    assert_eq!(
        (
            directory.list(30),
            directory.cursor(),
            directory.metadata_bytes(),
            directory.issuer
        ),
        before
    );
    let native_new = register(&mut directory, &control, "actual-new-native-instance");
    ready(&mut directory, &control, &native_new);
    assert_eq!(
        directory.register(
            &control,
            control
                .attest_registration(registration("third-native-instance"))
                .unwrap()
        ),
        Err(SessionError::Capacity)
    );
    assert_eq!(
        directory
            .list(30)
            .iter()
            .filter(|v| v.descriptor.state == SessionState::Revoked)
            .count(),
        1
    );

    // Same HostGeneration, SessionId and issuer order; a new trusted runtime
    // incarnation prevents raw DTOs/PreparedContext from reviving old targets.
    assert_eq!(
        RegistryIncarnation::from_fresh_entropy([0; 32]).err(),
        Some(SessionError::Invalid)
    );
    fn incarnated(byte: u8) -> (SessionRegistry, SessionControl) {
        SessionRegistry::new_owned(
            HostGeneration::try_from("host-one").unwrap(),
            RegistryIncarnation::from_fresh_entropy([byte; 32]).unwrap(),
            NativePrincipal::LinuxUid(1000),
            SessionLimits::default(),
        )
        .unwrap()
    }
    let (mut first, first_control) = incarnated(7);
    let first_binding = register(&mut first, &first_control, "same-id");
    first
        .update_provider(
            &first_control,
            &first_binding,
            provider(CapabilityId::DesktopPointer),
        )
        .unwrap();
    let old_observation = first
        .record_observation(
            &first_control,
            &first_binding,
            CapabilityId::DesktopPointer,
            20,
        )
        .unwrap();
    let old_context = PreparedContext {
        device_id: DeviceId::try_from("test-device").unwrap(),
        grant_revision: 7,
        session: Some(first_binding.clone()),
        observation: Some(old_observation.clone()),
        capability: CapabilityId::DesktopPointer,
        deadline: MonotonicMillis(90),
        disconnect_policy: DisconnectPolicy::RetainForOwner,
    };
    assert!(
        check_admission(
            &old_context,
            &policy_facts(
                &first
                    .project(&first_binding, CapabilityId::DesktopPointer, 20)
                    .unwrap()
            ),
            MonotonicMillis(20)
        )
        .is_ok()
    );
    for incarnation in [8, 9] {
        let (mut replacement, replacement_control) = incarnated(incarnation);
        let mut facts = registration("same-id");
        if incarnation == 9 {
            facts.agent_instance = AgentInstanceId::try_from("new-native-agent").unwrap();
            if let SessionIdentity::Linux {
                login_instance,
                compositor_instance,
                ..
            } = &mut facts.identity
            {
                *login_instance = "new-login".into();
                *compositor_instance = "new-compositor".into();
            }
        }
        let binding = replacement
            .register(
                &replacement_control,
                replacement_control.attest_registration(facts).unwrap(),
            )
            .unwrap();
        replacement
            .update_provider(
                &replacement_control,
                &binding,
                provider(CapabilityId::DesktopPointer),
            )
            .unwrap();
        let observation = replacement
            .record_observation(
                &replacement_control,
                &binding,
                CapabilityId::DesktopPointer,
                20,
            )
            .unwrap();
        assert_eq!(replacement.issuer, first.issuer);
        assert_ne!(binding.generation, first_binding.generation);
        assert_ne!(observation, old_observation);
        assert_eq!(
            replacement.project(&first_binding, CapabilityId::DesktopPointer, 20),
            Err(SessionError::StaleBinding)
        );
        let projection = replacement
            .project(&binding, CapabilityId::DesktopPointer, 20)
            .unwrap();
        assert_eq!(
            check_admission(
                &old_context,
                &policy_facts(&projection),
                MonotonicMillis(20)
            ),
            Err(ErrorCategory::SessionDisconnected)
        );
        let mut reanchored_context = old_context.clone();
        reanchored_context.session = Some(binding);
        assert_eq!(
            check_admission(
                &reanchored_context,
                &policy_facts(&projection),
                MonotonicMillis(20)
            ),
            Err(ErrorCategory::StaleObservation)
        );
    }

    // Expiry is projected per capability and does not mutate/republish stale
    // observations, mint approval, or silently choose another ready session.
    let (mut current, current_control) = incarnated(10);
    let a = register(&mut current, &current_control, "a");
    current
        .update_provider(&current_control, &a, provider(CapabilityId::DesktopCapture))
        .unwrap();
    let capture = current
        .record_observation(&current_control, &a, CapabilityId::DesktopCapture, 20)
        .unwrap();
    let mut pointer = provider(CapabilityId::DesktopPointer);
    pointer.valid_until = 200;
    current
        .update_provider(&current_control, &a, pointer)
        .unwrap();
    let pointer_observation = current
        .record_observation(&current_control, &a, CapabilityId::DesktopPointer, 20)
        .unwrap();
    let authority = current_control.selection_authority(true);
    let approved = current.select(&authority, Selection::Unbound, 30).unwrap();
    assert_eq!(
        current.inspect(&a, 30).unwrap().descriptor.state,
        SessionState::Ready
    );
    let projected = current.inspect(&a, 100).unwrap();
    assert_eq!(projected.descriptor.state, SessionState::Degraded);
    let expired = projected
        .providers
        .iter()
        .find(|p| p.facts.capability == CapabilityId::DesktopCapture)
        .unwrap();
    assert_eq!(expired.facts.availability, Availability::Unavailable);
    assert_eq!(expired.facts.reason, Some(ErrorCategory::StaleObservation));
    assert_eq!(expired.facts.recovery, Recovery::Reobserve);
    assert_eq!(expired.observation, None);
    assert_ne!(expired.observation, Some(capture));
    assert_eq!(
        current
            .project(&a, CapabilityId::DesktopPointer, 100)
            .unwrap()
            .provider
            .observation,
        Some(pointer_observation)
    );
    assert!(
        current
            .select(&authority, Selection::Approved(&approved), 100)
            .is_ok()
    );
    assert_eq!(
        current
            .select(&authority, Selection::Approved(&approved), 200)
            .err(),
        Some(SessionError::StaleObservation)
    );
    assert_eq!(
        current
            .select(&authority, Selection::Explicit(&a), 200)
            .err(),
        Some(SessionError::StaleObservation)
    );
    assert_eq!(
        current.select(&authority, Selection::Unbound, 200).err(),
        Some(SessionError::StaleObservation)
    );
    assert_eq!(
        current.list(200)[0].descriptor.state,
        SessionState::Degraded
    );
    assert!(
        current.list(200)[0]
            .providers
            .iter()
            .all(|p| p.observation.is_none())
    );
    let b = register(&mut current, &current_control, "b");
    let mut healthy = provider(CapabilityId::DesktopWindowsRead);
    healthy.valid_until = 300;
    current
        .update_provider(&current_control, &b, healthy)
        .unwrap();
    assert_eq!(
        current.select(&authority, Selection::Unbound, 200).err(),
        Some(SessionError::SessionAmbiguous)
    );
    assert_eq!(
        current
            .select(&authority, Selection::Explicit(&a), 200)
            .err(),
        Some(SessionError::StaleObservation)
    );
    assert_eq!(
        current
            .select(&authority, Selection::Approved(&approved), 200)
            .err(),
        Some(SessionError::StaleObservation)
    );
    assert!(
        current
            .select(&authority, Selection::Explicit(&b), 200)
            .is_ok()
    );
    let (mut denied, denied_control) = incarnated(11);
    let target = register(&mut denied, &denied_control, "denied");
    let mut required = provider(CapabilityId::DesktopCapture);
    required.authorization = Authorization::Required;
    denied
        .update_provider(&denied_control, &target, required)
        .unwrap();
    let authority = denied_control.selection_authority(true);
    assert_eq!(
        denied.select(&authority, Selection::Unbound, 100).err(),
        Some(SessionError::StaleObservation)
    );
    assert_eq!(
        denied.inspect(&target, 100).unwrap().descriptor.state,
        SessionState::Degraded
    );
}

#[test]
fn acquired_ax_observation_preserves_unknown_and_expires_with_provider() {
    let (mut directory, control) = registry(SessionLimits::default());
    let binding = register(&mut directory, &control, "ax");
    ready(&mut directory, &control, &binding);
    let mut evidence = provider(CapabilityId::DesktopAccessibility);
    evidence.authorization = Authorization::Unknown;
    directory
        .update_provider(&control, &binding, evidence.clone())
        .unwrap();
    let observation = directory
        .record_accessibility_read_observation(&control, &binding, 20)
        .unwrap();
    let view = directory.inspect(&binding, 20).unwrap();
    let ax = view
        .providers
        .iter()
        .find(|p| p.facts.capability == CapabilityId::DesktopAccessibility)
        .unwrap();
    assert_eq!(ax.facts.authorization, Authorization::Unknown);
    assert_eq!(ax.observation.as_ref(), Some(&observation));
    assert_eq!(
        directory
            .project(&binding, CapabilityId::DesktopAccessibility, 20)
            .err(),
        Some(SessionError::PermissionRequired)
    );
    assert_eq!(
        directory.record_accessibility_read_observation(&control, &binding, 100),
        Err(SessionError::StaleObservation)
    );
    evidence.authorization = Authorization::Revoked;
    directory
        .update_provider(&control, &binding, evidence)
        .unwrap();
    assert_eq!(
        directory.record_accessibility_read_observation(&control, &binding, 21),
        Err(SessionError::PermissionDenied)
    );
    let view = directory.inspect(&binding, 21).unwrap();
    assert!(
        view.providers
            .iter()
            .find(|p| p.facts.capability == CapabilityId::DesktopAccessibility)
            .unwrap()
            .observation
            .is_none()
    );
}
