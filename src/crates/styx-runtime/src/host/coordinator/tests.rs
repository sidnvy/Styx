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
