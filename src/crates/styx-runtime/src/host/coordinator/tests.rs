use super::*;
use crate::providers::codex::OwnedExecutorConfig;
use std::collections::BTreeMap;
use styx_contracts::{capability::*, error::Recovery};

fn facts() -> AdmissionFacts {
    AdmissionFacts {
        device_id: DeviceId::try_from("styx-owned-coordinator").unwrap(),
        grant_revision: 1,
        local_policy_allowed: true,
        descriptor: CapabilityDescriptor {
            contract_version: 1,
            capability_id: CapabilityId::ExecRun,
            scope: Scope::Host,
            provider_id: ProviderId::try_from("codex").unwrap(),
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
fn context(host: &HostCoordinator, revision: u64) -> PreparedContext {
    PreparedContext {
        device_id: facts().device_id,
        grant_revision: revision,
        session: None,
        observation: None,
        capability: CapabilityId::ExecRun,
        deadline: MonotonicMillis(host.now().0 + 10000),
        disconnect_policy: DisconnectPolicy::RetainForOwner,
    }
}
fn spec(root: &std::path::Path, file: &str, nonce: &str) -> StartProcess {
    StartProcess {
        argv: vec![
            "/bin/sh".into(),
            "-c".into(),
            format!("printf '%s\\n' '{nonce}' >> '{file}'; printf 'owned-output'; sleep 0.1"),
        ],
        cwd_file_uri: url::Url::from_directory_path(root).unwrap().to_string(),
        environment: BTreeMap::from([("PATH".into(), "/usr/bin:/bin".into())]),
        tty: false,
    }
}
fn submitted(
    host: &HostCoordinator,
    owner: &OwnerLease,
    reservation: &OperationSnapshot,
) -> StartTicket {
    match host
        .dispatch_start(owner, &reservation.id, reservation.payload_digest)
        .unwrap()
    {
        StartSubmission::Submitted(ticket) => ticket,
        StartSubmission::Existing(_) => panic!("new reservation must submit"),
    }
}
async fn drain(
    host: &HostCoordinator,
    owner: &OwnerLease,
    reservation: &OperationSnapshot,
    revision: u64,
) {
    for _ in 0..100 {
        let output = host
            .read(
                owner,
                &reservation.id,
                reservation.payload_digest,
                &context(host, revision),
                65536,
                Duration::from_millis(100),
            )
            .await
            .unwrap();
        if output.drain == OutputDrain::Drained {
            assert_eq!(output.liveness, ExecutionLiveness::Exited);
            assert_eq!(output.exit_code, Some(0));
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("bounded owned drain failed");
}
/// The executor and OS effects are real; explicit Core Unknown injection below is
/// a labelled hard-fault control, not a claim of an observed transport ACK loss.
#[tokio::test]
#[ignore = "requires STYX_TEST_CODEX and STYX_TEST_EXEC_ROOT; isolated Host coordinator native scenario"]
async fn real_owned_start_read_and_dropped_response_scenario() {
    let root = std::path::PathBuf::from(std::env::var("STYX_TEST_EXEC_ROOT").unwrap())
        .join(uuid::Uuid::new_v4().to_string());
    std::fs::create_dir_all(root.join("codex-home")).unwrap();
    let adapter = CodexStdio::spawn_owned(OwnedExecutorConfig {
        binary: std::env::var("STYX_TEST_CODEX").unwrap().into(),
        cwd: root.clone(),
        environment: BTreeMap::from([
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("HOME".into(), root.display().to_string()),
            (
                "CODEX_HOME".into(),
                root.join("codex-home").display().to_string(),
            ),
        ]),
        rpc_timeout: Duration::from_secs(2),
        retained_process_limit: 8,
    })
    .await
    .unwrap();
    let (host, authority) = HostCoordinator::new_owned(
        adapter,
        OperationLedger::new(HostGeneration::try_from("owned-coordinator-generation").unwrap()),
        facts(),
        2,
    )
    .unwrap();
    let owner = authority
        .register_verified_owner(
            OwnerId::try_from("owned:a").unwrap(),
            OwnerEpoch::try_from("epoch-a").unwrap(),
        )
        .unwrap();
    let foreign = authority
        .register_verified_owner(
            OwnerId::try_from("owned:b").unwrap(),
            OwnerEpoch::try_from("epoch-b").unwrap(),
        )
        .unwrap();
    let nonce = uuid::Uuid::new_v4().to_string();
    let mut short = context(&host, 1);
    short.deadline = MonotonicMillis(host.now().0 + 1000);
    let first = host
        .prepare_start(&owner, short, &spec(&root, "normal.txt", &nonce))
        .unwrap();
    assert!(
        !root.join("normal.txt").exists(),
        "prepare has no native effect"
    );
    let completion = submitted(&host, &owner, &first).wait().await.unwrap();
    assert_eq!(completion.dispatch, DispatchEvidence::Started);
    assert!(matches!(
        host.dispatch_start(&owner, &first.id, first.payload_digest)
            .unwrap(),
        StartSubmission::Existing(_)
    ));
    assert!(
        host.dispatch_start(&owner, &first.id, Sha256Digest::of_bytes(b"altered"))
            .is_err()
    );
    assert!(
        host.read(
            &foreign,
            &first.id,
            first.payload_digest,
            &context(&host, 1),
            65536,
            Duration::ZERO
        )
        .await
        .is_err()
    );
    let denied_start = host
        .prepare_start(
            &owner,
            context(&host, 1),
            &spec(&root, "negative-never-started.txt", &nonce),
        )
        .unwrap();
    let mut denied = facts();
    denied.local_policy_allowed = false;
    authority.replace_trusted_facts(denied);
    assert!(matches!(
        host.dispatch_start(&owner, &denied_start.id, denied_start.payload_digest),
        Err(CoordinatorError::Admission(ErrorCategory::PermissionDenied))
    ));
    assert!(matches!(
        host.read(
            &owner,
            &first.id,
            first.payload_digest,
            &context(&host, 1),
            65536,
            Duration::ZERO
        )
        .await,
        Err(CoordinatorError::Admission(ErrorCategory::PermissionDenied))
    ));
    let mut other_device = context(&host, 1);
    other_device.device_id = DeviceId::try_from("styx-another-device").unwrap();
    assert!(
        host.read(
            &owner,
            &first.id,
            first.payload_digest,
            &other_device,
            65536,
            Duration::ZERO
        )
        .await
        .is_err()
    );
    let mut revised = facts();
    revised.grant_revision = 2;
    authority.replace_trusted_facts(revised);
    assert!(
        host.read(
            &owner,
            &first.id,
            first.payload_digest,
            &context(&host, 1),
            65536,
            Duration::ZERO
        )
        .await
        .is_err()
    );
    tokio::time::sleep(Duration::from_millis(1050)).await;
    // New access deadline/current grant allows output after original start deadline.
    drain(&host, &owner, &first, 2).await;
    assert_eq!(
        std::fs::read_to_string(root.join("normal.txt")).unwrap(),
        format!("{nonce}\n")
    );
    let dropped = host
        .prepare_start(
            &owner,
            context(&host, 2),
            &spec(&root, "dropped.txt", &nonce),
        )
        .unwrap();
    drop(submitted(&host, &owner, &dropped)); // no response consumer, but owned job survives
    for _ in 0..100 {
        if host
            .inspect_start(&owner, &dropped.id, dropped.payload_digest)
            .unwrap()
            .state
            != OperationState::Dispatched
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(matches!(
        host.dispatch_start(&owner, &dropped.id, dropped.payload_digest)
            .unwrap(),
        StartSubmission::Existing(_)
    ));
    drain(&host, &owner, &dropped, 2).await;
    assert_eq!(
        std::fs::read_to_string(root.join("dropped.txt")).unwrap(),
        format!("{nonce}\n")
    );
    let uncertain = host
        .prepare_start(
            &owner,
            context(&host, 2),
            &spec(&root, "unknown-control.txt", &nonce),
        )
        .unwrap();
    submitted(&host, &owner, &uncertain).wait().await.unwrap();
    host.inner
        .state
        .lock()
        .unwrap()
        .ledger
        .mark_result_unknown(&uncertain.id)
        .unwrap();
    drain(&host, &owner, &uncertain, 2).await;
    let final_unknown = host
        .inspect_start(&owner, &uncertain.id, uncertain.payload_digest)
        .unwrap();
    assert_eq!(final_unknown.state, OperationState::Unknown);
    assert_eq!(final_unknown.liveness, ExecutionLiveness::Exited);
    assert_eq!(final_unknown.output_drain, OutputDrain::Drained);
    let delivery = host
        .prepare_start(
            &owner,
            context(&host, 2),
            &spec(&root, "delivery-sensitive.txt", &nonce),
        )
        .unwrap();
    submitted(&host, &owner, &delivery).wait().await.unwrap();
    let arrived = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    *host.inner.delivery_gate.lock().unwrap() = Some((arrived.clone(), release.clone()));
    let reader_host = host.clone();
    let reader_owner = owner.clone();
    let reader = tokio::spawn(async move {
        reader_host
            .read(
                &reader_owner,
                &delivery.id,
                delivery.payload_digest,
                &context(&reader_host, 2),
                65536,
                Duration::from_millis(100),
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(3), arrived.notified())
        .await
        .unwrap();
    // Only scheduling is injected: native output already arrived, current Core
    // owner revocation is real. This is not an OS permission or network test.
    assert_eq!(
        std::fs::read_to_string(root.join("delivery-sensitive.txt")).unwrap(),
        format!("{nonce}\n")
    );
    authority.revoke_owner(&owner).unwrap();
    release.notify_one();
    assert!(matches!(
        reader.await.unwrap(),
        Err(CoordinatorError::OutputDeliveryDenied(
            ErrorCategory::Unauthorized
        ))
    ));
    assert!(
        host.read(
            &owner,
            &first.id,
            first.payload_digest,
            &context(&host, 2),
            65536,
            Duration::ZERO
        )
        .await
        .is_err()
    );
    let replacement = authority
        .register_verified_owner(
            OwnerId::try_from("owned:a").unwrap(),
            OwnerEpoch::try_from("epoch-a").unwrap(),
        )
        .unwrap();
    assert!(
        host.read(
            &replacement,
            &first.id,
            first.payload_digest,
            &context(&host, 2),
            65536,
            Duration::ZERO
        )
        .await
        .is_err()
    );
    assert!(!root.join("negative-never-started.txt").exists());
    let cleanup = authority
        .shutdown_owned(Duration::from_secs(5))
        .await
        .unwrap();
    assert!(cleanup.supervised_jobs_joined);
    assert!(
        cleanup.native.executor_exited
            && cleanup.native.reader_task_reaped
            && cleanup.native.stderr_task_reaped
    );
    println!(
        "owned coordinator fixture={} PASS: actual nonce once, prepare zero effect, duplicate/altered/foreign/revoked denied, fresh grant/deadline, dropped response survives without replay, labelled injected-Unknown retains history after native exit/drain, deterministic post-native Core revoke refuses sensitive delivery, joined cleanup",
        root.display()
    );
}

fn submitted_action(
    host: &HostCoordinator,
    owner: &OwnerLease,
    action: &OperationSnapshot,
) -> ActionTicket {
    match host
        .dispatch_action(owner, &action.id, action.payload_digest)
        .unwrap()
    {
        ActionSubmission::Submitted(ticket) => ticket,
        ActionSubmission::Existing(_) => panic!("fresh action must submit once"),
    }
}
fn resource_target(resource: &OperationSnapshot) -> ResourceTarget {
    ResourceTarget {
        operation_id: resource.id.clone(),
        payload_digest: resource.payload_digest,
    }
}
/// Real executor/effects; dropping a local response receiver is deliberately not
/// described as native ACK loss. The provider's earlier hard queue case is not repeated.
#[tokio::test]
#[ignore = "requires STYX_TEST_CODEX/STYX_TEST_EXEC_ROOT; focused Host continuation native scenario"]
async fn real_host_action_nonce_drop_ticket_and_terminate_scenario() {
    use crate::providers::codex::ActionAcknowledgment;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let root = std::path::PathBuf::from(std::env::var("STYX_TEST_EXEC_ROOT").unwrap())
        .join(uuid::Uuid::new_v4().to_string());
    std::fs::create_dir_all(root.join("codex-home")).unwrap();
    let adapter = CodexStdio::spawn_owned(OwnedExecutorConfig {
        binary: std::env::var("STYX_TEST_CODEX").unwrap().into(),
        cwd: root.clone(),
        environment: BTreeMap::from([
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("HOME".into(), root.display().to_string()),
            (
                "CODEX_HOME".into(),
                root.join("codex-home").display().to_string(),
            ),
        ]),
        rpc_timeout: Duration::from_secs(2),
        retained_process_limit: 4,
    })
    .await
    .unwrap();
    let (host, authority) = HostCoordinator::new_owned(
        adapter,
        OperationLedger::new(HostGeneration::try_from("host-action-fixture-generation").unwrap()),
        facts(),
        1,
    )
    .unwrap();
    let authority = Arc::new(authority);
    let worker_authority = authority.clone();
    let worker_host = host.clone();
    let fixture_root = root.clone();
    let worker = tokio::spawn(async move {
        let authority = worker_authority;
        let host = worker_host;
        let root = fixture_root;
        assert!(host.shares_authority(&authority));
        assert_eq!(
            host.bootstrap_identity().1.as_str(),
            "host-action-fixture-generation"
        );
        let owner = authority
            .register_verified_owner(
                OwnerId::try_from("host-action:a").unwrap(),
                OwnerEpoch::try_from("epoch-a").unwrap(),
            )
            .unwrap();
        let foreign = authority
            .register_verified_owner(
                OwnerId::try_from("host-action:b").unwrap(),
                OwnerEpoch::try_from("epoch-b").unwrap(),
            )
            .unwrap();
        let mut process = spec(&root, "unused", "unused");
        process.argv=vec!["/bin/sh".into(),"-c".into(),"read -r line; printf '%s\\n' \"$line\" >> host-action-effect; printf FIRST_ACK; read -r hold".into()];
        let mut short = context(&host, 1);
        short.deadline = MonotonicMillis(host.now().0 + 500);
        let start_deadline = short.deadline;
        let resource = host.prepare_start(&owner, short, &process).unwrap();
        assert_eq!(
            submitted(&host, &owner, &resource)
                .wait()
                .await
                .unwrap()
                .dispatch,
            DispatchEvidence::Started
        );
        assert!(matches!(
            host.dispatch_action(&owner, &resource.id, resource.payload_digest),
            Err(CoordinatorError::Admission(ErrorCategory::StateConflict))
        ));
        tokio::time::sleep(Duration::from_millis(
            start_deadline
                .0
                .saturating_add(5)
                .saturating_sub(host.now().0),
        ))
        .await;
        assert!(host.now() >= start_deadline);
        let nonce = uuid::Uuid::new_v4().to_string();
        let input = ProcessAction::WriteStdin {
            input_base64: STANDARD.encode(format!("{nonce}\n")),
        };
        let write = host
            .prepare_action(
                &owner,
                resource_target(&resource),
                context(&host, 1),
                &input,
            )
            .unwrap();
        assert_ne!(write.id, resource.id);
        assert!(!root.join("host-action-effect").exists());
        let no_send = ProcessAction::WriteStdin {
            input_base64: STANDARD.encode(b"NO_SEND\n"),
        };
        let pending = host
            .prepare_action(
                &owner,
                resource_target(&resource),
                context(&host, 1),
                &no_send,
            )
            .unwrap();
        let ticket = submitted_action(&host, &owner, &write);
        // This current-thread test has not yielded since spawn. The complete
        // guard must be owned by the job, not dropped in dispatch_action.
        assert_eq!(
            host.inspect_action(&owner, &write.id, write.payload_digest)
                .unwrap()
                .state,
            OperationState::Dispatched
        );
        assert!(
            host.lookup_action(&owner, &write.id, write.payload_digest)
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            host.dispatch_action(&owner, &pending.id, pending.payload_digest),
            Err(CoordinatorError::Busy)
        ));
        assert_eq!(
            host.inspect_action(&owner, &pending.id, pending.payload_digest)
                .unwrap()
                .state,
            OperationState::Reserved
        );
        assert!(matches!(
            host.dispatch_start(&owner, &write.id, write.payload_digest),
            Err(CoordinatorError::Admission(ErrorCategory::StateConflict))
        ));
        drop(ticket); // only the receiver is lost; the supervised native job continues
        tokio::time::timeout(Duration::from_secs(3), async {
            while host
                .inspect_action(&owner, &write.id, write.payload_digest)
                .unwrap()
                .state
                != OperationState::Succeeded
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let acknowledged = host
            .lookup_action(&owner, &write.id, write.payload_digest)
            .unwrap()
            .unwrap();
        assert_eq!(acknowledged.evidence, ActionEvidence::Acknowledged);
        assert_eq!(
            acknowledged.acknowledgment,
            Some(ActionAcknowledgment::WriteAccepted)
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            while std::fs::read_to_string(root.join("host-action-effect")).ok()
                != Some(format!("{nonce}\n"))
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(matches!(
            host.dispatch_action(&owner, &write.id, write.payload_digest)
                .unwrap(),
            ActionSubmission::Existing(_)
        ));
        assert!(matches!(
            host.dispatch_action(&owner, &write.id, Sha256Digest::of_bytes(b"changed")),
            Err(CoordinatorError::Admission(ErrorCategory::IntegrityFailure))
        ));
        assert!(matches!(
            host.dispatch_action(&foreign, &write.id, write.payload_digest),
            Err(CoordinatorError::Admission(ErrorCategory::Unauthorized))
        ));
        assert!(matches!(
            host.lookup_action(&foreign, &write.id, write.payload_digest),
            Err(CoordinatorError::Admission(ErrorCategory::Unauthorized))
        ));
        assert!(matches!(
            host.prepare_action(
                &foreign,
                resource_target(&resource),
                context(&host, 1),
                &no_send
            ),
            Err(CoordinatorError::Admission(ErrorCategory::Unauthorized))
        ));
        let mut tampered = resource_target(&resource);
        tampered.payload_digest = Sha256Digest::of_bytes(b"other-target");
        assert!(matches!(
            host.prepare_action(&owner, tampered, context(&host, 1), &no_send),
            Err(CoordinatorError::Admission(ErrorCategory::IntegrityFailure))
        ));
        let denied = host
            .prepare_action(
                &owner,
                resource_target(&resource),
                context(&host, 1),
                &no_send,
            )
            .unwrap();
        let mut changed_grant = facts();
        changed_grant.grant_revision = 2;
        authority.replace_trusted_facts(changed_grant);
        assert!(matches!(
            host.dispatch_action(&owner, &denied.id, denied.payload_digest),
            Err(CoordinatorError::Admission(ErrorCategory::StateConflict))
        ));
        assert_eq!(
            host.inspect_action(&owner, &denied.id, denied.payload_digest)
                .unwrap()
                .state,
            OperationState::Reserved
        );
        authority.replace_trusted_facts(facts());
        let mut expired = context(&host, 1);
        expired.deadline = MonotonicMillis(host.now().0 + 1);
        let expired = host
            .prepare_action(&owner, resource_target(&resource), expired, &no_send)
            .unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(matches!(
            host.dispatch_action(&owner, &expired.id, expired.payload_digest),
            Err(CoordinatorError::Admission(ErrorCategory::OperationTimeout))
        ));
        let output = host
            .read(
                &owner,
                &resource.id,
                resource.payload_digest,
                &context(&host, 1),
                65536,
                Duration::from_millis(100),
            )
            .await
            .unwrap();
        assert_eq!(output.liveness, ExecutionLiveness::Running);
        assert_eq!(output.exit_code, None);
        assert_eq!(
            output
                .chunks
                .iter()
                .map(|c| c.text.as_str())
                .collect::<String>(),
            "FIRST_ACK"
        );
        let before = host
            .inspect_start(&owner, &resource.id, resource.payload_digest)
            .unwrap();
        let terminate = host
            .prepare_action(
                &owner,
                resource_target(&resource),
                context(&host, 1),
                &ProcessAction::Terminate {},
            )
            .unwrap();
        let result = submitted_action(&host, &owner, &terminate)
            .wait()
            .await
            .unwrap();
        assert_eq!(result.snapshot.state, OperationState::Succeeded);
        assert_eq!(result.snapshot.liveness, ExecutionLiveness::NotApplicable);
        assert_eq!(result.receipt.evidence, ActionEvidence::Acknowledged);
        assert!(matches!(
            result.receipt.acknowledgment,
            Some(ActionAcknowledgment::TerminateRequested { .. })
        ));
        assert_eq!(
            host.inspect_start(&owner, &resource.id, resource.payload_digest)
                .unwrap(),
            before,
            "terminate ACK does not change parent process state"
        );
        let mut exit = None;
        for _ in 0..60 {
            let page = host
                .read(
                    &owner,
                    &resource.id,
                    resource.payload_digest,
                    &context(&host, 1),
                    65536,
                    Duration::from_millis(20),
                )
                .await
                .unwrap();
            if page.drain == OutputDrain::Drained {
                assert_eq!(page.liveness, ExecutionLiveness::Exited);
                exit = page.exit_code;
                break;
            }
        }
        assert!(exit.is_some());
        assert_eq!(
            host.inspect_start(&owner, &resource.id, resource.payload_digest)
                .unwrap()
                .liveness,
            ExecutionLiveness::Exited
        );
        assert_eq!(
            host.inspect_action(&owner, &terminate.id, terminate.payload_digest)
                .unwrap()
                .state,
            OperationState::Succeeded
        );
        assert_eq!(
            std::fs::read_to_string(root.join("host-action-effect")).unwrap(),
            format!("{nonce}\n")
        );
        authority.revoke_owner(&owner).unwrap();
        assert!(matches!(
            host.inspect_action(&owner, &write.id, write.payload_digest),
            Err(CoordinatorError::Admission(ErrorCategory::Unauthorized))
        ));
        assert!(matches!(
            host.lookup_action(&owner, &write.id, write.payload_digest),
            Err(CoordinatorError::Admission(ErrorCategory::Unauthorized))
        ));
        assert!(
            host.prepare_action(
                &owner,
                resource_target(&resource),
                context(&host, 1),
                &no_send
            )
            .is_err()
        );
        println!(
            "HOST_ACTION_OBSERVATION {}",
            serde_json::json!({"root":root,"nonce":nonce,"effectCount":1,"startDeadlineExpiredBeforeFreshAction":true,
            "droppedLocalTicketJobCompleted":true,"nativeAckLossInjected":false,"writeAction":write.id,"writeId":acknowledged.write_id,
            "slotRefusalPreservedReservation":true,"changedGrantTargetDigestOwnerDenied":true,"terminateAction":terminate.id,"nativeExitAfterIndependentRead":exit,
            "terminateAckDidNotAlterParent":true,"ownerRevocationFencedQueriesAndActions":true})
        );
    });
    let outcome = worker.await;
    let cleanup = authority
        .shutdown_owned(Duration::from_secs(5))
        .await
        .unwrap();
    println!("HOST_ACTION_CLEANUP {:?}", cleanup);
    assert!(
        cleanup.supervised_jobs_joined
            && cleanup.native.executor_exited
            && cleanup.native.reader_task_reaped
            && cleanup.native.stderr_task_reaped
    );
    outcome.unwrap();
}
