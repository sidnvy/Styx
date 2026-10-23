//! Independently authored behavioral scenarios at the Core's executor seam.
//! EffectProbe consumes ONLY public ExecuteOnce instructions, never ledger internals.
//! It is a fake executor; these tests do not claim real Codex/Cua/Browser acceptance.
use styx_contracts::{capability::*, error::*, identity::*, operation::*, session::*};
use styx_core::{operations::*, policy::*};
mod support;

fn id<T: TryFrom<&'static str>>(value: &'static str) -> T
where
    T::Error: std::fmt::Debug,
{
    value.try_into().expect("valid fixture identity")
}
fn context() -> PreparedContext {
    PreparedContext {
        device_id: id("device-1"),
        grant_revision: 7,
        session: None,
        observation: None,
        capability: CapabilityId::ExecRun,
        deadline: MonotonicMillis(1000),
        disconnect_policy: DisconnectPolicy::RetainForOwner,
    }
}
fn facts() -> AdmissionFacts {
    AdmissionFacts {
        device_id: id("device-1"),
        grant_revision: 7,
        local_policy_allowed: true,
        descriptor: CapabilityDescriptor {
            contract_version: 1,
            capability_id: CapabilityId::ExecRun,
            scope: Scope::Host,
            provider_id: id("codex"),
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
fn ledger() -> (OperationLedger, OwnerLease) {
    let mut ledger = OperationLedger::with_budget(id("host-1"), 100_000, 10);
    let owner = ledger
        .register_verified_owner(id("owner-A"), id("epoch-A"))
        .unwrap();
    (ledger, owner)
}
#[derive(Default)]
struct EffectProbe(Vec<Vec<u8>>);
impl EffectProbe {
    fn deliver(&mut self, instruction: DispatchDisposition) {
        if let DispatchDisposition::ExecuteOnce(permit) = instruction {
            self.0.push(permit.payload().to_vec());
        }
    }
}

#[test]
fn revoked_lease_and_new_lease_cannot_adopt_old_reservation_even_with_same_epoch() {
    let (mut l, old) = ledger();
    let r = l
        .prepare(&old, context(), b"effect-one".to_vec(), MonotonicMillis(0))
        .unwrap();
    l.revoke_owner(&old).unwrap();
    let new = l
        .register_verified_owner(id("owner-A"), id("epoch-A"))
        .unwrap();
    for lease in [&old, &new] {
        assert_eq!(
            l.dispatch(lease, &r.id, r.payload_digest, &facts(), MonotonicMillis(1)),
            Err(ErrorCategory::Unauthorized)
        );
        assert_eq!(
            l.request_cancel(lease, &r.id, r.payload_digest, MonotonicMillis(1)),
            Err(ErrorCategory::Unauthorized)
        );
    }
    let fresh = l
        .prepare(&new, context(), b"fresh".to_vec(), MonotonicMillis(1))
        .unwrap();
    assert_ne!(r.id, fresh.id);
    let mut probe = EffectProbe::default();
    probe.deliver(
        l.dispatch(
            &new,
            &fresh.id,
            fresh.payload_digest,
            &facts(),
            MonotonicMillis(2),
        )
        .unwrap(),
    );
    assert_eq!(probe.0.as_slice(), [b"fresh".to_vec()]);
}

#[test]
fn unknown_payload_and_owner_retries_never_repeat_an_executor_instruction() {
    let (mut l, a) = ledger();
    let b = l
        .register_verified_owner(id("owner-B"), id("epoch-B"))
        .unwrap();
    let r = l
        .prepare(&a, context(), b"nonce-A".to_vec(), MonotonicMillis(0))
        .unwrap();
    let wrong = Sha256Digest::of_bytes(b"altered");
    assert_eq!(
        l.dispatch(&a, &r.id, wrong, &facts(), MonotonicMillis(1)),
        Err(ErrorCategory::IntegrityFailure)
    );
    assert_eq!(
        l.dispatch(&b, &r.id, r.payload_digest, &facts(), MonotonicMillis(1)),
        Err(ErrorCategory::Unauthorized)
    );
    assert_eq!(
        l.request_cancel(&b, &r.id, r.payload_digest, MonotonicMillis(1)),
        Err(ErrorCategory::Unauthorized)
    );
    let mut probe = EffectProbe::default();
    probe.deliver(
        l.dispatch(&a, &r.id, r.payload_digest, &facts(), MonotonicMillis(1))
            .unwrap(),
    );
    l.mark_result_unknown(&r.id).unwrap();
    for _ in 0..3 {
        probe.deliver(
            l.dispatch(&a, &r.id, r.payload_digest, &facts(), MonotonicMillis(2))
                .unwrap(),
        );
    }
    assert_eq!(probe.0.as_slice(), [b"nonce-A".to_vec()]);
    assert_eq!(
        l.inspect(&a, &r.id, r.payload_digest).unwrap().state,
        OperationState::Unknown
    );
    let mut fabricated = r.id.clone();
    fabricated.sequence += 100;
    assert_eq!(
        l.dispatch(
            &a,
            &fabricated,
            r.payload_digest,
            &facts(),
            MonotonicMillis(2)
        ),
        Err(ErrorCategory::StaleOperation)
    );
}

#[test]
fn cancellation_request_and_termination_fact_preserve_unknown_outcome() {
    let (mut l, a) = ledger();
    let r = l
        .prepare(
            &a,
            context(),
            b"already-effected".to_vec(),
            MonotonicMillis(0),
        )
        .unwrap();
    let mut probe = EffectProbe::default();
    probe.deliver(
        l.dispatch(&a, &r.id, r.payload_digest, &facts(), MonotonicMillis(1))
            .unwrap(),
    );
    l.record_executor_fact(&r.id, ExecutorFact::Running, MonotonicMillis(1))
        .unwrap();
    l.mark_result_unknown(&r.id).unwrap();
    let requested = l
        .request_cancel(&a, &r.id, r.payload_digest, MonotonicMillis(2))
        .unwrap();
    assert_eq!(requested.cancellation, Some(Cancellation::Requested));
    assert_eq!(requested.liveness, ExecutionLiveness::Unknown);
    assert_eq!(requested.state, OperationState::Unknown);
    let stopped = l
        .record_executor_fact(
            &r.id,
            ExecutorFact::TerminationConfirmed,
            MonotonicMillis(3),
        )
        .unwrap();
    assert_eq!(stopped.liveness, ExecutionLiveness::Exited);
    assert_eq!(stopped.state, OperationState::Unknown);
    probe.deliver(
        l.dispatch(&a, &r.id, r.payload_digest, &facts(), MonotonicMillis(4))
            .unwrap(),
    );
    assert_eq!(probe.0.len(), 1);
}

#[test]
fn live_unknown_is_not_evicted_and_ended_unknown_can_expire_without_replay() {
    let (mut l, a) = ledger();
    let r = l
        .prepare(&a, context(), vec![1; 1024], MonotonicMillis(0))
        .unwrap();
    l.dispatch(&a, &r.id, r.payload_digest, &facts(), MonotonicMillis(1))
        .unwrap();
    l.mark_result_unknown(&r.id).unwrap();
    loop {
        match l.prepare(&a, context(), vec![2; 1024], MonotonicMillis(2)) {
            Ok(_) => {}
            Err(ErrorCategory::Busy) => break,
            other => panic!("unexpected {other:?}"),
        }
    }
    let before = l.retained_bytes();
    assert_eq!(l.reap(MonotonicMillis(50)), 0);
    assert_eq!(l.retained_bytes(), before);
    assert_eq!(
        l.inspect(&a, &r.id, r.payload_digest).unwrap().state,
        OperationState::Unknown
    );
    l.record_executor_fact(
        &r.id,
        ExecutorFact::Exited { successful: true },
        MonotonicMillis(51),
    )
    .unwrap();
    assert_eq!(
        l.inspect(&a, &r.id, r.payload_digest).unwrap().state,
        OperationState::Unknown
    );
    assert_eq!(l.reap(MonotonicMillis(61)), 0); // exit alone cannot discard retained output
    l.record_executor_fact(&r.id, ExecutorFact::OutputDrained, MonotonicMillis(61))
        .unwrap();
    support::release_resource(&mut l, &r, &[]);
    assert_eq!(l.reap(MonotonicMillis(61)), 1);
    assert_eq!(
        l.dispatch(&a, &r.id, r.payload_digest, &facts(), MonotonicMillis(62)),
        Err(ErrorCategory::StaleOperation)
    );
}

#[test]
fn changed_device_grant_capability_and_unavailable_provider_refuse_without_poisoning_owner() {
    let (mut l, a) = ledger();
    let r = l
        .prepare(&a, context(), b"protected".to_vec(), MonotonicMillis(0))
        .unwrap();
    let mut variants = vec![];
    let mut f = facts();
    f.local_policy_allowed = false;
    variants.push(f);
    let mut f = facts();
    f.descriptor.authorization = Authorization::Unknown;
    variants.push(f);
    let mut f = facts();
    f.device_id = id("device-other");
    variants.push(f);
    let mut f = facts();
    f.grant_revision += 1;
    variants.push(f);
    let mut f = facts();
    f.descriptor.capability_id = CapabilityId::BrowserHeadless;
    variants.push(f);
    let mut f = facts();
    f.descriptor.availability = Availability::Unavailable;
    variants.push(f);
    let mut f = facts();
    f.descriptor.remote_grant = false;
    variants.push(f);
    let mut probe = EffectProbe::default();
    for f in variants {
        assert!(
            l.dispatch(&a, &r.id, r.payload_digest, &f, MonotonicMillis(1))
                .is_err()
        );
    }
    assert_eq!(
        l.inspect(&a, &r.id, r.payload_digest).unwrap().state,
        OperationState::Reserved
    );
    probe.deliver(
        l.dispatch(&a, &r.id, r.payload_digest, &facts(), MonotonicMillis(2))
            .unwrap(),
    );
    assert_eq!(probe.0.as_slice(), [b"protected".to_vec()]);
}

#[test]
fn cancelled_reserved_and_expired_records_cannot_turn_back_into_dispatchable_work() {
    let (mut l, a) = ledger();
    let r = l
        .prepare(
            &a,
            context(),
            b"never-effected".to_vec(),
            MonotonicMillis(0),
        )
        .unwrap();
    let cancelled = l
        .request_cancel(&a, &r.id, r.payload_digest, MonotonicMillis(1))
        .unwrap();
    assert_eq!(cancelled.cancellation, Some(Cancellation::NotDispatched));
    assert_eq!(cancelled.liveness, ExecutionLiveness::NotStarted);
    let mut probe = EffectProbe::default();
    probe.deliver(
        l.dispatch(&a, &r.id, r.payload_digest, &facts(), MonotonicMillis(2))
            .unwrap(),
    );
    assert!(probe.0.is_empty());
    assert_eq!(l.reap(MonotonicMillis(11)), 1);
    assert_eq!(
        l.dispatch(&a, &r.id, r.payload_digest, &facts(), MonotonicMillis(12)),
        Err(ErrorCategory::StaleOperation)
    );
}

#[test]
fn explicit_stale_desktop_binding_and_observation_never_fallback() {
    let binding = SessionBinding {
        id: id("session-A"),
        generation: id("generation-A"),
    };
    let mut c = context();
    c.capability = CapabilityId::DesktopPointer;
    c.session = Some(binding.clone());
    c.observation = Some(id("observation-A"));
    let mut f = facts();
    f.descriptor.capability_id = CapabilityId::DesktopPointer;
    f.descriptor.scope = Scope::Session;
    f.descriptor.target_session = Some(binding.clone());
    f.session_state = Some(SessionState::Ready);
    f.current_observation = Some(id("observation-A"));
    assert_eq!(check_admission(&c, &f, MonotonicMillis(1)), Ok(()));
    f.descriptor.target_session.as_mut().unwrap().generation = id("generation-B");
    assert_eq!(
        check_admission(&c, &f, MonotonicMillis(1)),
        Err(ErrorCategory::SessionDisconnected)
    );
    f.descriptor.target_session = Some(binding);
    f.current_observation = Some(id("observation-B"));
    assert_eq!(
        check_admission(&c, &f, MonotonicMillis(1)),
        Err(ErrorCategory::StaleObservation)
    );
    f.current_observation = Some(id("observation-A"));
    f.session_state = Some(SessionState::Locked);
    assert_eq!(
        check_admission(&c, &f, MonotonicMillis(1)),
        Err(ErrorCategory::SessionLocked)
    );
    f.session_state = Some(SessionState::Ready);
    c.observation = None;
    for capability in [
        CapabilityId::DesktopPointer,
        CapabilityId::DesktopKeyboard,
        CapabilityId::DesktopWindowsControl,
    ] {
        c.capability = capability;
        f.descriptor.capability_id = capability;
        assert_eq!(
            check_admission(&c, &f, MonotonicMillis(1)),
            Err(ErrorCategory::StaleObservation)
        );
    }
}

#[test]
fn output_drained_before_exit_is_never_process_termination_or_maintenance_settlement() {
    let (mut l, a) = ledger();
    let r = l
        .prepare(&a, context(), b"open-process".to_vec(), MonotonicMillis(0))
        .unwrap();
    l.dispatch(&a, &r.id, r.payload_digest, &facts(), MonotonicMillis(1))
        .unwrap();
    l.begin_maintenance();
    let drained = l
        .record_executor_fact(&r.id, ExecutorFact::OutputDrained, MonotonicMillis(2))
        .unwrap();
    assert_eq!(drained.output_drain, OutputDrain::Drained);
    assert_eq!(drained.liveness, ExecutionLiveness::Unknown);
    assert!(!l.maintenance_settled());
    l.mark_result_unknown(&r.id).unwrap();
    let exited = l
        .record_executor_fact(
            &r.id,
            ExecutorFact::Exited { successful: true },
            MonotonicMillis(3),
        )
        .unwrap();
    assert_eq!(exited.state, OperationState::Unknown);
    assert_eq!(exited.liveness, ExecutionLiveness::Exited);
    assert!(l.maintenance_settled());
}

#[test]
fn maintenance_fences_new_work_but_permits_cancellation_and_real_settlement() {
    let (mut l, a) = ledger();
    let running = l
        .prepare(&a, context(), b"first".to_vec(), MonotonicMillis(0))
        .unwrap();
    let queued = l
        .prepare(&a, context(), b"queued".to_vec(), MonotonicMillis(0))
        .unwrap();
    let mut probe = EffectProbe::default();
    probe.deliver(
        l.dispatch(
            &a,
            &running.id,
            running.payload_digest,
            &facts(),
            MonotonicMillis(1),
        )
        .unwrap(),
    );
    l.record_executor_fact(&running.id, ExecutorFact::Running, MonotonicMillis(1))
        .unwrap();
    l.begin_maintenance();
    assert!(!l.maintenance_settled());
    assert_eq!(
        l.prepare(&a, context(), b"forbidden".to_vec(), MonotonicMillis(2)),
        Err(ErrorCategory::Busy)
    );
    assert_eq!(
        l.dispatch(
            &a,
            &queued.id,
            queued.payload_digest,
            &facts(),
            MonotonicMillis(2)
        ),
        Err(ErrorCategory::Busy)
    );
    let requested = l
        .request_cancel(&a, &running.id, running.payload_digest, MonotonicMillis(2))
        .unwrap();
    assert_eq!(requested.cancellation, Some(Cancellation::Requested));
    assert_eq!(requested.liveness, ExecutionLiveness::Running);
    assert!(!l.maintenance_settled());
    let never_started = l
        .request_cancel(&a, &queued.id, queued.payload_digest, MonotonicMillis(2))
        .unwrap();
    assert_eq!(
        never_started.cancellation,
        Some(Cancellation::NotDispatched)
    );
    l.mark_result_unknown(&running.id).unwrap();
    let terminated = l
        .record_executor_fact(
            &running.id,
            ExecutorFact::TerminationConfirmed,
            MonotonicMillis(3),
        )
        .unwrap();
    assert_eq!(terminated.state, OperationState::Unknown);
    assert_eq!(terminated.liveness, ExecutionLiveness::Exited);
    assert!(!l.maintenance_settled()); // retained output is still unknown
    let complete = l
        .record_executor_fact(&running.id, ExecutorFact::OutputDrained, MonotonicMillis(4))
        .unwrap();
    assert_eq!(complete.state, OperationState::Unknown);
    assert!(l.maintenance_settled());
    probe.deliver(
        l.dispatch(
            &a,
            &running.id,
            running.payload_digest,
            &facts(),
            MonotonicMillis(4),
        )
        .unwrap(),
    );
    assert_eq!(probe.0.as_slice(), [b"first".to_vec()]);
    l.end_maintenance();
    assert!(!l.maintenance_settled()); // explicit fence state matters
    assert!(
        l.prepare(&a, context(), b"resumed".to_vec(), MonotonicMillis(5))
            .is_ok()
    );
}

#[test]
fn proven_pre_dispatch_refusal_settles_without_permitting_replay_or_rewriting_running_work() {
    let (mut l, a) = ledger();
    let refused = l
        .prepare(
            &a,
            context(),
            b"refused-before-send".to_vec(),
            MonotonicMillis(0),
        )
        .unwrap();
    let permit = l
        .dispatch(
            &a,
            &refused.id,
            refused.payload_digest,
            &facts(),
            MonotonicMillis(1),
        )
        .unwrap();
    // Independent fake backend deliberately emits no action bytes. Its pre-send
    // refusal is distinct from a remote error or a lost acknowledgement.
    assert!(matches!(permit, DispatchDisposition::ExecuteOnce(_)));
    drop(permit);
    let settled = l
        .record_executor_fact(&refused.id, ExecutorFact::NotDispatched, MonotonicMillis(2))
        .unwrap();
    assert_eq!(settled.state, OperationState::Failed);
    assert_eq!(settled.liveness, ExecutionLiveness::NotStarted);
    assert_eq!(settled.output_drain, OutputDrain::NotOpened);
    let mut probe = EffectProbe::default();
    probe.deliver(
        l.dispatch(
            &a,
            &refused.id,
            refused.payload_digest,
            &facts(),
            MonotonicMillis(3),
        )
        .unwrap(),
    );
    assert!(probe.0.is_empty());
    l.begin_maintenance();
    assert!(l.maintenance_settled());
    l.end_maintenance();
    support::release_resource(&mut l, &refused, &[]);
    assert_eq!(l.reap(MonotonicMillis(12)), 1);
    assert_eq!(
        l.dispatch(
            &a,
            &refused.id,
            refused.payload_digest,
            &facts(),
            MonotonicMillis(13)
        ),
        Err(ErrorCategory::StaleOperation)
    );
    for already_unknown in [false, true] {
        let active = l
            .prepare(&a, context(), b"already-sent".to_vec(), MonotonicMillis(14))
            .unwrap();
        probe.deliver(
            l.dispatch(
                &a,
                &active.id,
                active.payload_digest,
                &facts(),
                MonotonicMillis(15),
            )
            .unwrap(),
        );
        if already_unknown {
            l.mark_result_unknown(&active.id).unwrap();
        } else {
            l.record_executor_fact(&active.id, ExecutorFact::Running, MonotonicMillis(15))
                .unwrap();
        }
        assert_eq!(
            l.record_executor_fact(&active.id, ExecutorFact::NotDispatched, MonotonicMillis(16)),
            Err(ErrorCategory::StateConflict)
        );
        assert_ne!(
            l.inspect(&a, &active.id, active.payload_digest)
                .unwrap()
                .liveness,
            ExecutionLiveness::NotStarted
        );
    }
    assert_eq!(
        probe.0,
        [b"already-sent".to_vec(), b"already-sent".to_vec()]
    );
}

#[test]
fn degraded_session_admits_available_capture_but_not_unsupported_input_or_stale_binding() {
    let binding = SessionBinding {
        id: id("desktop-1"),
        generation: id("generation-1"),
    };
    let mut capture = context();
    capture.capability = CapabilityId::DesktopCapture;
    capture.session = Some(binding.clone());
    let mut live = facts();
    live.session_state = Some(SessionState::Degraded);
    live.descriptor.capability_id = CapabilityId::DesktopCapture;
    live.descriptor.scope = Scope::Session;
    live.descriptor.target_session = Some(binding);
    assert_eq!(check_admission(&capture, &live, MonotonicMillis(1)), Ok(()));

    // Aggregate degradation never supplies a missing permission or provider.
    let mut input = capture.clone();
    input.capability = CapabilityId::DesktopPointer;
    input.observation = Some(id("snapshot-1"));
    let mut unavailable = live.clone();
    unavailable.descriptor.capability_id = CapabilityId::DesktopPointer;
    unavailable.descriptor.availability = Availability::Unavailable;
    unavailable.descriptor.reason = Some(ErrorCategory::CapabilityUnsupported);
    unavailable.current_observation = input.observation.clone();
    assert_eq!(
        check_admission(&input, &unavailable, MonotonicMillis(1)),
        Err(ErrorCategory::CapabilityUnsupported)
    );

    live.descriptor.authorization = Authorization::Revoked;
    assert_eq!(
        check_admission(&capture, &live, MonotonicMillis(1)),
        Err(ErrorCategory::PermissionDenied)
    );
    live.descriptor.authorization = Authorization::Granted;
    live.descriptor.target_session.as_mut().unwrap().generation = id("generation-2");
    assert_eq!(
        check_admission(&capture, &live, MonotonicMillis(1)),
        Err(ErrorCategory::SessionDisconnected)
    );
    live.descriptor.target_session = capture.session.clone();
    live.session_state = Some(SessionState::Locked);
    assert_eq!(
        check_admission(&capture, &live, MonotonicMillis(1)),
        Err(ErrorCategory::SessionLocked)
    );
    // Host-level work remains independent of a degraded or absent desktop.
    assert_eq!(
        check_admission(&context(), &facts(), MonotonicMillis(1)),
        Ok(())
    );
}

#[test]
fn resource_access_uses_fresh_policy_without_rebinding_or_reusing_start_deadline() {
    let (mut l, a) = ledger();
    let other = l
        .register_verified_owner(id("owner-B"), id("epoch-B"))
        .unwrap();
    let start = l
        .prepare(&a, context(), b"resource".to_vec(), MonotonicMillis(0))
        .unwrap();
    let mut fresh = context();
    fresh.deadline = MonotonicMillis(3000);
    assert_eq!(
        l.authorize_resource_access(
            &a,
            &start.id,
            start.payload_digest,
            &fresh,
            &facts(),
            MonotonicMillis(1)
        ),
        Err(ErrorCategory::StateConflict)
    );
    assert!(matches!(
        l.dispatch(
            &a,
            &start.id,
            start.payload_digest,
            &facts(),
            MonotonicMillis(1)
        )
        .unwrap(),
        DispatchDisposition::ExecuteOnce(_)
    ));
    l.record_executor_fact(&start.id, ExecutorFact::Running, MonotonicMillis(2))
        .unwrap();
    // Start admission expired at1000; a new read at2000 remains possible.
    assert!(
        l.authorize_resource_access(
            &a,
            &start.id,
            start.payload_digest,
            &fresh,
            &facts(),
            MonotonicMillis(2000)
        )
        .is_ok()
    );
    assert_eq!(
        l.authorize_resource_access(
            &other,
            &start.id,
            start.payload_digest,
            &fresh,
            &facts(),
            MonotonicMillis(2000)
        ),
        Err(ErrorCategory::Unauthorized)
    );
    let mut denied = facts();
    denied.local_policy_allowed = false;
    assert_eq!(
        l.authorize_resource_access(
            &a,
            &start.id,
            start.payload_digest,
            &fresh,
            &denied,
            MonotonicMillis(2000)
        ),
        Err(ErrorCategory::PermissionDenied)
    );
    let mut changed = fresh.clone();
    changed.capability = CapabilityId::BrowserHeadless;
    let mut browser = facts();
    browser.descriptor.capability_id = CapabilityId::BrowserHeadless;
    assert_eq!(
        l.authorize_resource_access(
            &a,
            &start.id,
            start.payload_digest,
            &changed,
            &browser,
            MonotonicMillis(2000)
        ),
        Err(ErrorCategory::StateConflict)
    );
    let mut revised = facts();
    revised.grant_revision = 8;
    fresh.grant_revision = 8;
    assert!(
        l.authorize_resource_access(
            &a,
            &start.id,
            start.payload_digest,
            &fresh,
            &revised,
            MonotonicMillis(2000)
        )
        .is_ok()
    );
    l.begin_maintenance();
    assert!(
        l.authorize_resource_access(
            &a,
            &start.id,
            start.payload_digest,
            &fresh,
            &revised,
            MonotonicMillis(2000)
        )
        .is_ok()
    );
    l.revoke_owner(&a).unwrap();
    assert_eq!(
        l.authorize_resource_access(
            &a,
            &start.id,
            start.payload_digest,
            &fresh,
            &revised,
            MonotonicMillis(2000)
        ),
        Err(ErrorCategory::Unauthorized)
    );
}

#[test]
fn repeated_exit_observations_cannot_keep_ended_unknown_resources_forever() {
    for terminated in [false, true] {
        let (mut l, a) = ledger();
        let r = l
            .prepare(
                &a,
                context(),
                b"unknown-effect".to_vec(),
                MonotonicMillis(0),
            )
            .unwrap();
        let _permit = l
            .dispatch(&a, &r.id, r.payload_digest, &facts(), MonotonicMillis(1))
            .unwrap();
        l.mark_result_unknown(&r.id).unwrap();
        if terminated {
            l.request_cancel(&a, &r.id, r.payload_digest, MonotonicMillis(2))
                .unwrap();
            l.record_executor_fact(
                &r.id,
                ExecutorFact::TerminationConfirmed,
                MonotonicMillis(3),
            )
            .unwrap();
        } else {
            l.record_executor_fact(
                &r.id,
                ExecutorFact::Exited { successful: true },
                MonotonicMillis(3),
            )
            .unwrap();
        }
        l.record_executor_fact(&r.id, ExecutorFact::OutputDrained, MonotonicMillis(4))
            .unwrap();
        // Polling the same native exit is an observation, not a new terminal event.
        let again = l
            .record_executor_fact(
                &r.id,
                ExecutorFact::Exited { successful: false },
                MonotonicMillis(14),
            )
            .unwrap();
        assert_eq!(again.state, OperationState::Unknown);
        support::release_resource(&mut l, &r, &[]);
        assert_eq!(l.reap(MonotonicMillis(15)), 1);
        assert_eq!(
            l.inspect(&a, &r.id, r.payload_digest),
            Err(ErrorCategory::StaleOperation)
        );
    }
}
