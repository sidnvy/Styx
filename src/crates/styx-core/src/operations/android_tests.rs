use super::*;
use styx_contracts::capability::{Authorization, Availability, CapabilityDescriptor, Scope};
use styx_contracts::error::Recovery;

#[test]
fn android_requests_require_permission_and_never_replay_unknown_results() {
    let mut ledger = OperationLedger::new("android-host".try_into().unwrap());
    let owner = ledger
        .register_verified_owner(
            "owner-a".try_into().unwrap(),
            "owner-epoch".try_into().unwrap(),
        )
        .unwrap();
    let device: DeviceId = "android-device".try_into().unwrap();
    let now = MonotonicMillis(1);
    let context = PreparedContext {
        device_id: device.clone(),
        grant_revision: 1,
        session: None,
        observation: None,
        capability: CapabilityId::AndroidAct,
        deadline: None,
        disconnect_policy: DisconnectPolicy::RetainForOwner,
    };
    let mut facts = AdmissionFacts {
        device_id: device,
        grant_revision: 1,
        local_policy_allowed: true,
        descriptor: CapabilityDescriptor {
            contract_version: styx_contracts::CONTRACT_VERSION,
            capability_id: CapabilityId::AndroidAct,
            scope: Scope::Host,
            provider_id: "android".try_into().unwrap(),
            configured: true,
            remote_grant: true,
            availability: Availability::Available,
            authorization: Authorization::Required,
            target_session: None,
            reason: None,
            observed_at: 1,
            observation_generation: 1,
            recovery: Recovery::ExplicitAuthorization,
        },
        session_state: None,
        current_observation: None,
    };
    let request = ledger
        .prepare_android_request(&owner, context, b"observed node click".to_vec(), now)
        .unwrap();
    assert_eq!(
        ledger
            .dispatch(&owner, &request.id, request.payload_digest, &facts, now)
            .unwrap_err(),
        ErrorCategory::PermissionRequired
    );
    facts.descriptor.authorization = Authorization::Granted;
    let DispatchDisposition::ExecuteOnce(permit) = ledger
        .dispatch(&owner, &request.id, request.payload_digest, &facts, now)
        .unwrap()
    else {
        panic!("first dispatch");
    };
    assert_eq!(permit.payload(), b"observed node click");
    assert_eq!(permit.purpose(), OperationPurpose::AndroidRequest);
    let completed = ledger
        .record_android_result(permit.id(), RequestResult::Unknown, MonotonicMillis(2))
        .unwrap();
    assert_eq!(completed.state, OperationState::Unknown);
    assert_eq!(completed.liveness, ExecutionLiveness::NotApplicable);
    let DispatchDisposition::Existing(existing) = ledger
        .dispatch(
            &owner,
            &request.id,
            request.payload_digest,
            &facts,
            MonotonicMillis(3),
        )
        .unwrap()
    else {
        panic!("must not reissue native permit");
    };
    assert_eq!(existing.state, OperationState::Unknown);
    assert_eq!(
        ledger
            .record_android_result(&request.id, RequestResult::Succeeded, MonotonicMillis(4))
            .unwrap()
            .state,
        OperationState::Unknown
    );
    assert_eq!(ledger.unreleased_provider_records(), 0);
    ledger.revoke_owner(&owner).unwrap();
    assert_eq!(
        ledger
            .dispatch(
                &owner,
                &request.id,
                request.payload_digest,
                &facts,
                MonotonicMillis(5)
            )
            .unwrap_err(),
        ErrorCategory::Unauthorized
    );
}
