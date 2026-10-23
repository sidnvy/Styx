//! Core contract fixtures only: permits drive an independent effect collector.
//! No native process/GUI/device acceptance is claimed by these scenarios.
use styx_contracts::{capability::*, error::*, identity::*, operation::*, session::*};
use styx_core::{operations::*, policy::*};

fn id<T: TryFrom<&'static str>>(s: &'static str) -> T
where
    T::Error: std::fmt::Debug,
{
    T::try_from(s).unwrap()
}
fn context() -> PreparedContext {
    PreparedContext {
        device_id: id("device"),
        grant_revision: 1,
        session: None,
        observation: None,
        capability: CapabilityId::ExecRun,
        deadline: MonotonicMillis(1000),
        disconnect_policy: DisconnectPolicy::RetainForOwner,
    }
}
fn facts() -> AdmissionFacts {
    AdmissionFacts {
        device_id: id("device"),
        grant_revision: 1,
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
            observed_at: 1,
            observation_generation: 1,
            recovery: Recovery::None,
        },
        session_state: None,
        current_observation: None,
    }
}
fn setup() -> (OperationLedger, OwnerLease, OperationSnapshot) {
    let mut ledger = OperationLedger::with_budget(id("host"), 1000000, 10);
    let owner = ledger
        .register_verified_owner(id("owner"), id("epoch"))
        .unwrap();
    let resource = ledger
        .prepare(&owner, context(), b"start".to_vec(), MonotonicMillis(0))
        .unwrap();
    let permit = take(&mut ledger, &owner, &resource, &facts(), 1);
    assert_eq!(permit.target(), None);
    ledger
        .record_executor_fact(&resource.id, ExecutorFact::Running, MonotonicMillis(1))
        .unwrap();
    (ledger, owner, resource)
}
fn target(r: &OperationSnapshot) -> ResourceTarget {
    ResourceTarget {
        operation_id: r.id.clone(),
        payload_digest: r.payload_digest,
    }
}
fn prepare(l: &mut OperationLedger, o: &OwnerLease, r: &OperationSnapshot) -> OperationSnapshot {
    l.prepare_targeted(
        o,
        target(r),
        context(),
        b"exact stdin bytes".to_vec(),
        MonotonicMillis(2),
    )
    .unwrap()
}
fn take(
    l: &mut OperationLedger,
    o: &OwnerLease,
    r: &OperationSnapshot,
    f: &AdmissionFacts,
    now: u64,
) -> DispatchPermit {
    match l
        .dispatch(o, &r.id, r.payload_digest, f, MonotonicMillis(now))
        .unwrap()
    {
        DispatchDisposition::ExecuteOnce(p) => p,
        _ => panic!("fresh operation must emit one permit"),
    }
}
#[derive(Default)]
struct EffectCollector(Vec<(ResourceTarget, Vec<u8>)>);
impl EffectCollector {
    fn consume(&mut self, p: DispatchPermit) {
        self.0
            .push((p.target().unwrap().clone(), p.payload().to_vec()));
    }
}
#[test]
fn exact_target_payload_and_action_token_are_independent_and_dispatch_only_once() {
    let (mut l, o, r) = setup();
    let a = prepare(&mut l, &o, &r);
    assert_ne!(a.id, r.id);
    assert_eq!(a.target, Some(target(&r)));
    assert_eq!(a.liveness, ExecutionLiveness::NotApplicable);
    let b = l
        .prepare(
            &o,
            context(),
            b"another resource".to_vec(),
            MonotonicMillis(2),
        )
        .unwrap();
    take(&mut l, &o, &b, &facts(), 2);
    let mut untrusted_snapshot = a.clone();
    untrusted_snapshot.target = Some(target(&b));
    assert_ne!(untrusted_snapshot.target, a.target);
    let mut effect = EffectCollector::default();
    // Dispatch uses the ledger's immutable target, never the altered DTO.
    effect.consume(take(&mut l, &o, &untrusted_snapshot, &facts(), 3));
    assert_eq!(effect.0, vec![(target(&r), b"exact stdin bytes".to_vec())]);
    assert!(matches!(
        l.dispatch(&o, &a.id, a.payload_digest, &facts(), MonotonicMillis(4))
            .unwrap(),
        DispatchDisposition::Existing(_)
    ));
    assert_eq!(effect.0.len(), 1);
    assert_eq!(
        l.dispatch(
            &o,
            &a.id,
            Sha256Digest::of_bytes(b"changed"),
            &facts(),
            MonotonicMillis(4)
        ),
        Err(ErrorCategory::IntegrityFailure)
    );
    assert_eq!(
        l.prepare_targeted(&o, target(&a), context(), vec![], MonotonicMillis(4)),
        Err(ErrorCategory::StateConflict)
    );
    assert_eq!(
        l.authorize_resource_access(
            &o,
            &a.id,
            a.payload_digest,
            &context(),
            &facts(),
            MonotonicMillis(4)
        ),
        Err(ErrorCategory::StateConflict)
    );
    for f in [
        ExecutorFact::Running,
        ExecutorFact::OutputDrained,
        ExecutorFact::Exited { successful: true },
        ExecutorFact::TerminationConfirmed,
        ExecutorFact::NotDispatched,
    ] {
        assert_eq!(
            l.record_executor_fact(&a.id, f, MonotonicMillis(4)),
            Err(ErrorCategory::StateConflict)
        );
    }
    assert_eq!(
        l.mark_result_unknown(&a.id),
        Err(ErrorCategory::StateConflict)
    );
}
#[test]
fn owner_incarnation_host_digest_and_resource_binding_cannot_be_substituted() {
    let (mut l, o, r) = setup();
    let foreign = l
        .register_verified_owner(id("foreign"), id("other-epoch"))
        .unwrap();
    assert_eq!(
        l.prepare_targeted(&foreign, target(&r), context(), vec![], MonotonicMillis(2)),
        Err(ErrorCategory::Unauthorized)
    );
    let mut wrong = target(&r);
    wrong.payload_digest = Sha256Digest::of_bytes(b"not start");
    assert_eq!(
        l.prepare_targeted(&o, wrong, context(), vec![], MonotonicMillis(2)),
        Err(ErrorCategory::IntegrityFailure)
    );
    let mut wrong = target(&r);
    wrong.operation_id.host_generation = id("another-host");
    assert_eq!(
        l.prepare_targeted(&o, wrong, context(), vec![], MonotonicMillis(2)),
        Err(ErrorCategory::StaleOperation)
    );
    for n in 0..3 {
        let mut c = context();
        match n {
            0 => c.device_id = id("other-device"),
            1 => c.capability = CapabilityId::BrowserHeadless,
            _ => {
                c.session = Some(SessionBinding {
                    id: id("s"),
                    generation: id("g"),
                })
            }
        }
        assert_eq!(
            l.prepare_targeted(&o, target(&r), c, vec![], MonotonicMillis(2)),
            Err(ErrorCategory::StateConflict)
        );
    }
    let a = prepare(&mut l, &o, &r);
    l.revoke_owner(&o).unwrap();
    let new = l.register_verified_owner(id("owner"), id("epoch")).unwrap();
    for lease in [&o, &new] {
        assert_eq!(
            l.prepare_targeted(lease, target(&r), context(), vec![], MonotonicMillis(3)),
            Err(ErrorCategory::Unauthorized)
        );
        assert_eq!(
            l.dispatch(lease, &a.id, a.payload_digest, &facts(), MonotonicMillis(3)),
            Err(ErrorCategory::Unauthorized)
        );
    }
}
#[test]
fn first_dispatch_rechecks_live_grant_deadline_target_exit_and_session() {
    let (mut l, o, r) = setup();
    let a = prepare(&mut l, &o, &r);
    let mut denied = facts();
    denied.descriptor.authorization = Authorization::Revoked;
    assert_eq!(
        l.dispatch(&o, &a.id, a.payload_digest, &denied, MonotonicMillis(3)),
        Err(ErrorCategory::PermissionDenied)
    );
    denied = facts();
    denied.grant_revision = 2;
    assert_eq!(
        l.dispatch(&o, &a.id, a.payload_digest, &denied, MonotonicMillis(3)),
        Err(ErrorCategory::StateConflict)
    );
    assert_eq!(
        l.dispatch(&o, &a.id, a.payload_digest, &facts(), MonotonicMillis(1000)),
        Err(ErrorCategory::OperationTimeout)
    );
    l.record_executor_fact(
        &r.id,
        ExecutorFact::Exited { successful: true },
        MonotonicMillis(4),
    )
    .unwrap();
    assert_eq!(
        l.dispatch(&o, &a.id, a.payload_digest, &facts(), MonotonicMillis(5)),
        Err(ErrorCategory::StateConflict)
    );
    assert_eq!(
        l.prepare_targeted(&o, target(&r), context(), vec![], MonotonicMillis(5)),
        Err(ErrorCategory::StateConflict)
    );

    let mut l = OperationLedger::new(id("desktop-host"));
    let o = l.register_verified_owner(id("owner"), id("epoch")).unwrap();
    let binding = SessionBinding {
        id: id("desktop"),
        generation: id("generation-1"),
    };
    let mut c = context();
    c.capability = CapabilityId::DesktopPointer;
    c.session = Some(binding.clone());
    c.observation = Some(id("fresh"));
    let mut f = facts();
    f.descriptor.capability_id = c.capability;
    f.descriptor.scope = Scope::Session;
    f.descriptor.target_session = Some(binding);
    f.session_state = Some(SessionState::Ready);
    f.current_observation = c.observation.clone();
    let r = l
        .prepare(&o, c.clone(), vec![], MonotonicMillis(0))
        .unwrap();
    take(&mut l, &o, &r, &f, 1);
    let a = l
        .prepare_targeted(&o, target(&r), c.clone(), vec![], MonotonicMillis(2))
        .unwrap();
    f.descriptor.target_session.as_mut().unwrap().generation = id("generation-2");
    assert_eq!(
        l.dispatch(&o, &a.id, a.payload_digest, &f, MonotonicMillis(3)),
        Err(ErrorCategory::SessionDisconnected)
    );
    f.descriptor.target_session = c.session.clone();
    f.session_state = Some(SessionState::Locked);
    assert_eq!(
        l.dispatch(&o, &a.id, a.payload_digest, &f, MonotonicMillis(3)),
        Err(ErrorCategory::SessionLocked)
    );
    let mut changed = c;
    changed.session.as_mut().unwrap().generation = id("generation-2");
    assert_eq!(
        l.prepare_targeted(&o, target(&r), changed, vec![], MonotonicMillis(3)),
        Err(ErrorCategory::StateConflict)
    );
}
#[test]
fn ack_and_pre_io_refusal_settle_only_the_request_not_the_running_process() {
    let (mut l, o, r) = setup();
    let before = l.inspect(&o, &r.id, r.payload_digest).unwrap();
    let a = prepare(&mut l, &o, &r);
    take(&mut l, &o, &a, &facts(), 3);
    let ack = l
        .record_action_result(&a.id, ActionResult::Acknowledged, MonotonicMillis(4))
        .unwrap();
    assert_eq!(ack.state, OperationState::Succeeded);
    assert_eq!(ack.liveness, ExecutionLiveness::NotApplicable);
    assert_eq!(ack.output_drain, OutputDrain::NotOpened);
    assert_eq!(l.inspect(&o, &r.id, r.payload_digest).unwrap(), before);
    let refused = prepare(&mut l, &o, &r);
    take(&mut l, &o, &refused, &facts(), 5);
    assert_eq!(
        l.record_action_result(&refused.id, ActionResult::NotDispatched, MonotonicMillis(6))
            .unwrap()
            .state,
        OperationState::Failed
    );
    assert_eq!(l.inspect(&o, &r.id, r.payload_digest).unwrap(), before);
    assert_eq!(
        l.record_action_result(&r.id, ActionResult::Acknowledged, MonotonicMillis(7)),
        Err(ErrorCategory::StateConflict)
    );
    assert_eq!(
        l.record_action_result(&a.id, ActionResult::Unknown, MonotonicMillis(7)),
        Err(ErrorCategory::StateConflict)
    );
    l.begin_maintenance();
    assert!(!l.maintenance_settled());
    assert_eq!(l.reap(MonotonicMillis(16)), 2); // known action results, not target
    assert_eq!(l.inspect(&o, &r.id, r.payload_digest).unwrap(), before);
}
#[test]
fn unknown_is_retained_until_both_target_exit_and_drain_plus_full_retention() {
    let (mut l, o, r) = setup();
    let a = prepare(&mut l, &o, &r);
    take(&mut l, &o, &a, &facts(), 3);
    let unknown = l
        .record_action_result(&a.id, ActionResult::Unknown, MonotonicMillis(4))
        .unwrap();
    assert_eq!(unknown.liveness, ExecutionLiveness::NotApplicable);
    assert_eq!(
        l.record_action_result(&a.id, ActionResult::NotDispatched, MonotonicMillis(5)),
        Err(ErrorCategory::StateConflict)
    );
    assert_eq!(
        l.record_action_result(&a.id, ActionResult::Acknowledged, MonotonicMillis(6))
            .unwrap(),
        unknown
    );
    l.begin_maintenance();
    assert!(!l.maintenance_settled());
    assert_eq!(l.reap(MonotonicMillis(1000)), 0);
    l.record_executor_fact(
        &r.id,
        ExecutorFact::Exited { successful: true },
        MonotonicMillis(1001),
    )
    .unwrap();
    assert!(!l.maintenance_settled());
    assert_eq!(l.reap(MonotonicMillis(1500)), 0);
    l.record_executor_fact(&r.id, ExecutorFact::OutputDrained, MonotonicMillis(2000))
        .unwrap();
    assert!(l.maintenance_settled());
    // Neither a repeated Unknown nor repeat drain restarts or shortens retention.
    assert_eq!(
        l.record_action_result(&a.id, ActionResult::Unknown, MonotonicMillis(2001))
            .unwrap(),
        unknown
    );
    l.record_executor_fact(&r.id, ExecutorFact::OutputDrained, MonotonicMillis(2002))
        .unwrap();
    assert_eq!(l.reap(MonotonicMillis(2009)), 0);
    assert!(l.inspect(&o, &r.id, r.payload_digest).is_ok());
    assert_eq!(l.inspect(&o, &a.id, a.payload_digest).unwrap(), unknown);
    assert_eq!(l.reap(MonotonicMillis(2010)), 2);
    assert_eq!(
        l.inspect(&o, &a.id, a.payload_digest),
        Err(ErrorCategory::StaleOperation)
    );
    assert_eq!(
        l.dispatch(&o, &a.id, a.payload_digest, &facts(), MonotonicMillis(2011)),
        Err(ErrorCategory::StaleOperation)
    );
}
#[test]
fn late_unknown_starts_its_own_retention_and_pending_actions_pin_ended_parent() {
    let (mut l, o, r) = setup();
    let a = prepare(&mut l, &o, &r);
    take(&mut l, &o, &a, &facts(), 3);
    l.record_executor_fact(&r.id, ExecutorFact::OutputDrained, MonotonicMillis(4))
        .unwrap();
    l.record_executor_fact(
        &r.id,
        ExecutorFact::Exited { successful: true },
        MonotonicMillis(5),
    )
    .unwrap();
    l.begin_maintenance();
    assert!(!l.maintenance_settled());
    assert_eq!(l.reap(MonotonicMillis(100)), 0); // dispatched action not silently settled
    l.record_action_result(&a.id, ActionResult::Unknown, MonotonicMillis(101))
        .unwrap();
    assert!(l.maintenance_settled());
    assert_eq!(l.reap(MonotonicMillis(110)), 0);
    assert_eq!(l.reap(MonotonicMillis(111)), 2);
}
#[test]
fn unstarted_refused_cancelled_and_expired_action_reservations_are_never_resources() {
    let (mut l, o, r) = setup();
    let reserved = l
        .prepare(&o, context(), vec![], MonotonicMillis(2))
        .unwrap();
    assert_eq!(
        l.prepare_targeted(&o, target(&reserved), context(), vec![], MonotonicMillis(2)),
        Err(ErrorCategory::StateConflict)
    );
    take(&mut l, &o, &reserved, &facts(), 3);
    l.record_executor_fact(
        &reserved.id,
        ExecutorFact::NotDispatched,
        MonotonicMillis(4),
    )
    .unwrap();
    assert_eq!(
        l.prepare_targeted(&o, target(&reserved), context(), vec![], MonotonicMillis(4)),
        Err(ErrorCategory::StateConflict)
    );
    let a = prepare(&mut l, &o, &r);
    l.request_cancel(&o, &a.id, a.payload_digest, MonotonicMillis(4))
        .unwrap();
    assert!(matches!(
        l.dispatch(&o, &a.id, a.payload_digest, &facts(), MonotonicMillis(5))
            .unwrap(),
        DispatchDisposition::Existing(_)
    ));
    assert_eq!(
        l.record_action_result(&a.id, ActionResult::Acknowledged, MonotonicMillis(5)),
        Err(ErrorCategory::StateConflict)
    );
    let expired = prepare(&mut l, &o, &r);
    assert_eq!(l.reap(MonotonicMillis(1000)), 2); // earlier refused + cancelled action
    assert_eq!(
        l.inspect(&o, &expired.id, expired.payload_digest)
            .unwrap()
            .state,
        OperationState::Cancelled
    );
    assert!(matches!(
        l.dispatch(
            &o,
            &expired.id,
            expired.payload_digest,
            &facts(),
            MonotonicMillis(1001)
        )
        .unwrap(),
        DispatchDisposition::Existing(_)
    ));
    assert_eq!(l.reap(MonotonicMillis(1010)), 1);
    l.begin_maintenance();
    assert_eq!(
        l.prepare_targeted(&o, target(&r), context(), vec![], MonotonicMillis(5)),
        Err(ErrorCategory::Busy)
    );
}
