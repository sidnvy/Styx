//! Real Core permit + adapter admission boundary; no Node/browser is spawned.
use super::*;
use styx_contracts::{capability::*, error::Recovery, identity::*, operation::*};
use styx_core::{
    operations::{DispatchDisposition, ExecutorFact, OperationLedger},
    policy::AdmissionFacts,
};
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt;
        let root =
            std::env::temp_dir().join(format!("styx-browser-admission-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["workspace", "profile", "output"] {
            let path = root.join(name);
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(root)
    }
    fn config(&self) -> OwnedBrowserConfig {
        let never_started = std::fs::canonicalize("/usr/bin/true").unwrap();
        OwnedBrowserConfig {
            node_binary: never_started.clone(),
            worker_entry: never_started.clone(),
            browser_binary: never_started,
            workspace_dir: self.0.join("workspace"),
            profile_dir: self.0.join("profile"),
            output_dir: self.0.join("output"),
            rpc_timeout: Duration::from_secs(1),
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
fn permit(
    payload: Vec<u8>,
    capability: CapabilityId,
) -> (
    OperationLedger,
    OwnerLease,
    DispatchPermit,
    AdmissionFacts,
    PreparedContext,
) {
    let mut ledger =
        OperationLedger::new(HostGeneration::try_from("browser-admission-fixture").unwrap());
    let owner = ledger
        .register_verified_owner(
            OwnerId::try_from("owner-a").unwrap(),
            OwnerEpoch::try_from("epoch-a").unwrap(),
        )
        .unwrap();
    let context = PreparedContext {
        device_id: DeviceId::try_from("device-a").unwrap(),
        grant_revision: 1,
        session: None,
        observation: None,
        capability,
        deadline: MonotonicMillis(1000),
        disconnect_policy: DisconnectPolicy::RetainForOwner,
    };
    let facts = AdmissionFacts {
        device_id: context.device_id.clone(),
        grant_revision: 1,
        local_policy_allowed: true,
        descriptor: CapabilityDescriptor {
            contract_version: styx_contracts::CONTRACT_VERSION,
            capability_id: capability,
            scope: if capability == CapabilityId::ExecRun {
                Scope::Host
            } else {
                Scope::Browser
            },
            provider_id: ProviderId::try_from("browser-fixture").unwrap(),
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
    let prepared = ledger
        .prepare(&owner, context.clone(), payload, MonotonicMillis(0))
        .unwrap();
    let DispatchDisposition::ExecuteOnce(permit) = ledger
        .dispatch(
            &owner,
            &prepared.id,
            prepared.payload_digest,
            &facts,
            MonotonicMillis(0),
        )
        .unwrap()
    else {
        panic!("new permit expected")
    };
    (ledger, owner, permit, facts, context)
}
#[tokio::test]
async fn core_permit_pre_io_and_exclusive_lane_admission_batch() {
    let fixture = Fixture::new();
    let source = Arc::new(Semaphore::new(IO_BYTES));
    let budget = BrowserIoBudget::from_reserved(
        source
            .clone()
            .acquire_many_owned(IO_BYTES as u32)
            .await
            .unwrap(),
    )
    .unwrap();
    let worker = BrowserWorker::new(budget);
    let slot = worker.try_reserve_open().unwrap();
    assert!(matches!(worker.try_reserve_open(), Err(BrowserError::Busy)));
    drop(slot);
    let config = fixture.config();
    let payload = BrowserOpenSpec::for_config(&config)
        .unwrap()
        .to_operation_payload()
        .unwrap();
    let (_, _, wrong_capability, _, _) = permit(payload.clone(), CapabilityId::ExecRun);
    let failed = worker
        .try_reserve_open()
        .unwrap()
        .spawn_owned(wrong_capability, config.clone())
        .await
        .unwrap_err();
    assert_eq!(failed.evidence, BrowserActionEvidence::NotDispatched);
    assert!(failed.handle.is_none());
    assert_eq!(failed.cause, BrowserError::PermissionDenied);
    assert!(worker.resources().unwrap().is_empty());

    let (_, _, old_config, _, _) = permit(payload.clone(), CapabilityId::BrowserHeadless);
    let mut changed = config.clone();
    changed.rpc_timeout = Duration::from_secs(2);
    let failed = worker
        .try_reserve_open()
        .unwrap()
        .spawn_owned(old_config, changed)
        .await
        .unwrap_err();
    assert_eq!(failed.evidence, BrowserActionEvidence::NotDispatched);
    assert!(failed.handle.is_none());
    assert_eq!(failed.cause, BrowserError::InvalidRequest);

    let (mut ledger, owner, parent, facts, context) =
        permit(payload, CapabilityId::BrowserHeadless);
    let target = ResourceTarget {
        operation_id: parent.id().clone(),
        payload_digest: Sha256Digest::of_bytes(parent.payload()),
    };
    // Synthetic Core execution fact solely to create a genuine targeted permit;
    // the native resource is deliberately never launched in this fixture.
    ledger
        .record_executor_fact(parent.id(), ExecutorFact::Running, MonotonicMillis(1))
        .unwrap();
    let action = ledger
        .prepare_targeted(
            &owner,
            target,
            context,
            BrowserAction::Close.to_operation_payload().unwrap(),
            MonotonicMillis(1),
        )
        .unwrap();
    let DispatchDisposition::ExecuteOnce(targeted) = ledger
        .dispatch(
            &owner,
            &action.id,
            action.payload_digest,
            &facts,
            MonotonicMillis(1),
        )
        .unwrap()
    else {
        panic!("new targeted permit expected")
    };
    let failed = worker
        .try_reserve_open()
        .unwrap()
        .spawn_owned(targeted, config)
        .await
        .unwrap_err();
    assert_eq!(failed.evidence, BrowserActionEvidence::NotDispatched);
    assert!(failed.handle.is_none());
    assert_eq!(failed.cause, BrowserError::PermissionDenied);
    assert!(worker.resources().unwrap().is_empty());
    assert_eq!(
        std::fs::read_dir(fixture.0.join("output")).unwrap().count(),
        0,
        "all rejections precede even writing worker config"
    );
    println!(
        "Core/Browser admission boundary PASS: actual move-only permits; exclusive pre-reservation; wrong capability, mutated immutable config, targeted permit cannot open; all NotDispatched with no handle/config/worker; synthetic Core fact is not native Browser evidence"
    );
}

/// Synthetic provider state exercises the retention contract, not OS cleanup.
#[tokio::test]
async fn missing_unknown_requires_exact_ended_bundle_and_audit() {
    use styx_core::operations::ActionResult;
    for (audit_case, missing_cleanup, failed) in [
        (1, false, false),
        (0, true, false),
        (0, false, false),
        (0, false, true),
        (4, false, true),
        (1, false, true),
        (2, false, true),
        (3, false, true),
    ] {
        let (mut ledger, owner, parent, facts, context) =
            permit(vec![1], CapabilityId::BrowserHeadless);
        let target = ResourceTarget {
            operation_id: parent.id().clone(),
            payload_digest: Sha256Digest::of_bytes(parent.payload()),
        };
        ledger
            .record_executor_fact(parent.id(), ExecutorFact::Running, MonotonicMillis(1))
            .unwrap();
        let prepared = ledger
            .prepare_targeted(&owner, target.clone(), context, vec![2], MonotonicMillis(1))
            .unwrap();
        let DispatchDisposition::ExecuteOnce(action) = ledger
            .dispatch(
                &owner,
                &prepared.id,
                prepared.payload_digest,
                &facts,
                MonotonicMillis(1),
            )
            .unwrap()
        else {
            panic!("permit")
        };
        drop(action); // Models the owned dispatch guard losing its adapter result.
        ledger
            .record_action_result(
                &prepared.id,
                if failed {
                    ActionResult::NotDispatched
                } else {
                    ActionResult::Unknown
                },
                MonotonicMillis(2),
            )
            .unwrap();
        assert!(
            ledger.begin_action_release(&prepared.id).is_err(),
            "Unknown or missing audit cannot independently release"
        );
        let pool = Arc::new(Semaphore::new(IO_BYTES));
        let budget =
            BrowserIoBudget::from_reserved(pool.acquire_many_owned(IO_BYTES as u32).await.unwrap())
                .unwrap();
        let worker = BrowserWorker::new(budget.clone());
        let resource = Arc::new(Resource {
            metadata_record: Mutex::new(Some(
                worker.inner.metadata.clone().try_acquire_owned().unwrap(),
            )),
            metadata: worker.inner.metadata.clone(),
            stop: CancellationToken::new(),
            cleanup_job: Mutex::new(None),
            operation: parent.id().clone(),
            digest: target.payload_digest,
            owner: owner.clone(),
            _budget: budget,
            state: Arc::new(tokio::sync::Mutex::new(Live {
                child: None,
                client: None,
                stderr: None,
                client_close: None,
                io_join_failed: false,
                retired: false,
                slot: None,
                pins: vec![],
                uncertain: true,
                context_closed: false,
                timeout: Duration::from_secs(1),
                actions: BTreeMap::new(),
                config_file: PathBuf::new(),
                scope: None,
                cleanup: (!missing_cleanup).then_some(BrowserCleanup {
                    worker_exited: true,
                    worker_exit_success: Some(true),
                    stdio_joined: true,
                    context_closed: true,
                    descendants: BrowserDescendants::Confirmed,
                }),
            })),
        });
        worker
            .inner
            .resources
            .lock()
            .unwrap()
            .insert(parent.id().clone(), resource.clone());
        let key = ledger
            .retained_provider_records()
            .into_iter()
            .find(|k| k.snapshot().id == prepared.id)
            .unwrap();
        let receipt = if failed {
            assert!(
                worker.action_receipt(&key).await.is_err(),
                "missing Failed is not reconstructed as NotSent"
            );
            BrowserActionReceipt {
                operation: prepared.id.clone(),
                evidence: BrowserActionEvidence::NotDispatched,
                cause: if audit_case == 4 {
                    None
                } else {
                    Some(BrowserError::PermissionDenied)
                },
                result: None,
            }
        } else {
            let receipt = worker.action_receipt(&key).await.unwrap();
            assert_eq!(receipt.evidence, BrowserActionEvidence::Unknown);
            receipt
        };
        let audit = match audit_case {
            1 => b"{\"wrong\":true}".to_vec(),
            2 => worker
                .action_audit(&BrowserActionReceipt {
                    operation: prepared.id.clone(),
                    evidence: BrowserActionEvidence::Acknowledged,
                    cause: None,
                    result: None,
                })
                .unwrap(),
            3 => worker
                .action_audit(&BrowserActionReceipt {
                    operation: prepared.id.clone(),
                    evidence: BrowserActionEvidence::Unknown,
                    cause: Some(BrowserError::Unknown),
                    result: None,
                })
                .unwrap(),
            _ => worker.action_audit(&receipt).unwrap(),
        };
        ledger.record_provider_audit(&prepared.id, audit).unwrap();
        ledger
            .record_executor_fact(
                parent.id(),
                ExecutorFact::Exited { successful: true },
                MonotonicMillis(3),
            )
            .unwrap();
        ledger
            .record_executor_fact(parent.id(), ExecutorFact::OutputDrained, MonotonicMillis(3))
            .unwrap();
        let release = ledger.begin_resource_release(&target).unwrap();
        let result = worker.release_resource(release).await;
        if (1..=3).contains(&audit_case) || missing_cleanup {
            assert!(result.is_err());
            assert!(!resource.state.lock().await.retired);
            assert_eq!(worker.resources().unwrap().len(), 1);
        } else {
            ledger.record_provider_release(result.unwrap()).unwrap();
            assert!(worker.resources().unwrap().is_empty());
            assert!(resource.state.lock().await.retired);
            assert_eq!(worker.inner.metadata.available_permits(), MAX_RECORDS);
            let handle = BrowserHandle {
                resource,
                host: worker.inner.clone(),
            };
            assert!(
                worker.try_reserve_action(&handle).is_err(),
                "ancient handle remains fenced"
            );
        }
    }
    println!(
        "synthetic Core/provider bundle: missing Unknown retains Unknown; missing Failed accepts only canonical NotDispatched; ACK/Unknown/arbitrary audit and no physical cleanup refused; exact ended/drained bundle releases metadata; no native OS proof claimed"
    );
}
