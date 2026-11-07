//! Opt-in diagnostic against NEW disposable targets, never an Unknown account target.
//! The signed installed daemon, production proxy/admission and official MCP codec
//! are reused. This does not restart or repair an installed account context.
use super::*;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use styx_contracts::{
    capability::*, error::Recovery, identity::*, operation::*, session::SessionState,
};
use styx_core::{
    operations::{ActionResult, DispatchDisposition, ExecutorFact, OperationLedger},
    policy::AdmissionFacts,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    schema: u32,
    disposable_ax_refusal_reference: bool,
    pid: u32,
    process_start_seconds: u64,
    process_start_microseconds: u64,
    valid_window_id: u64,
    sheet_window_id: u64,
}

fn read_action(pid: u32, window: u64) -> CuaAction {
    CuaAction::new(
        "get_window_state".into(),
        serde_json::json!({"pid":pid,"window_id":window,"include_screenshot":false})
            .as_object()
            .unwrap()
            .clone(),
    )
    .unwrap()
}

struct ReadAuthority {
    ledger: OperationLedger,
    owner: OwnerLease,
    target: ResourceTarget,
    context: PreparedContext,
    facts: AdmissionFacts,
    at: u64,
}

// Use the production permit dispatch, native classifier AND Host read-delivery
// gate. Unknown ends the reference; no replacement context is opened.
async fn sample(
    worker: &CuaWorker,
    handle: &CuaHandle,
    authority: &mut ReadAuthority,
    action: CuaAction,
) -> (CuaEvidence, Value) {
    authority.at += 1;
    let at = MonotonicMillis(authority.at);
    let prepared = authority
        .ledger
        .prepare_desktop_read_acquisition(
            &authority.owner,
            authority.target.clone(),
            authority.context.clone(),
            action.to_operation_payload().unwrap(),
            at,
        )
        .unwrap();
    let DispatchDisposition::ExecuteOnce(permit) = authority
        .ledger
        .dispatch(
            &authority.owner,
            &prepared.id,
            prepared.payload_digest,
            &authority.facts,
            at,
        )
        .unwrap()
    else {
        panic!("fresh_reference_read")
    };
    let slot = worker.try_reserve_action(handle).unwrap();
    let mut receipt = slot.call_once(permit).await;
    let wire = serde_json::to_value(&receipt.result).unwrap();
    let evidence = receipt.evidence;
    let cause = receipt.cause.map(CuaError::code);
    let fact = match evidence {
        CuaEvidence::Acknowledged => ActionResult::Acknowledged,
        CuaEvidence::NotDispatched => ActionResult::NotDispatched,
        CuaEvidence::Unknown => ActionResult::Unknown,
    };
    authority
        .ledger
        .record_action_result(&prepared.id, fact, at)
        .unwrap();
    authority
        .ledger
        .record_provider_audit(&prepared.id, worker.action_audit(&receipt).unwrap())
        .unwrap();
    let delivered =
        crate::host::coordinator::HostCoordinator::authorize_native_reference_read_result(
            &authority.ledger,
            &authority.owner,
            &prepared.id,
            prepared.payload_digest,
            &authority.facts,
            at,
            &mut receipt,
        );
    let report = serde_json::json!({"complete":wire,"evidence":evidence,"cause":cause,"host_delivery":format!("{delivered:?}"),"payload_after_delivery":receipt.result.is_some()});
    (
        if delivered.is_ok() {
            evidence
        } else {
            CuaEvidence::Unknown
        },
        report,
    )
}

#[tokio::test]
#[ignore = "requires explicit installed-source read-only consent and NEW disposable Mac fixture"]
async fn installed_ax_refusal_wire_read_only() {
    assert_eq!(
        std::env::var("STYX_TEST_INSTALLED_MAC_SOURCE").as_deref(),
        Ok("read-only")
    );
    let fixture_path = PathBuf::from(std::env::var_os("STYX_TEST_MAC_AX_FIXTURE").unwrap());
    let fixture: Fixture = serde_json::from_slice(&std::fs::read(&fixture_path).unwrap()).unwrap();
    assert_eq!(fixture.schema, 1);
    assert!(fixture.disposable_ax_refusal_reference);
    assert!(fixture.pid > 1 && fixture.valid_window_id > 0 && fixture.sheet_window_id > 0);
    assert_ne!(fixture.valid_window_id, fixture.sheet_window_id);
    let target = ProcessIdentity::observe(fixture.pid).unwrap();
    assert!(matches!(
        &target,
        ProcessIdentity::Macos { start_seconds, start_microseconds, uid, .. }
            if *start_seconds == fixture.process_start_seconds
                && *start_microseconds == fixture.process_start_microseconds
                && *uid == nix::unistd::Uid::current().as_raw()
    ));
    let root = fixture_path
        .parent()
        .unwrap()
        .join(format!("wire-reference-{}", uuid::Uuid::new_v4()));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .unwrap();
    let workspace = root.join("workspace");
    let home = root.join("home");
    for path in [&workspace, &home] {
        std::fs::DirBuilder::new().mode(0o700).create(path).unwrap();
    }
    let source = MacProxySource::discover(Instant::now() + Duration::from_secs(15))
        .await
        .expect("original_installed_source");
    let session = SessionBinding {
        id: SessionId::try_from("disposable-ax-wire-reference").unwrap(),
        generation: SessionGeneration::try_from(uuid::Uuid::new_v4().to_string()).unwrap(),
    };
    let config = OwnedCuaConfig {
        launch: TrustedCuaLaunch::bind(
            session.clone(),
            source.clone(),
            workspace.clone(),
            home.clone(),
        )
        .unwrap(),
        rpc_timeout: Duration::from_secs(10),
        workspace,
        home,
    };
    let mut ledger = OperationLedger::new("disposable-ax-wire-reference".try_into().unwrap());
    let owner = ledger
        .register_verified_owner(
            "reference".try_into().unwrap(),
            "reference-epoch".try_into().unwrap(),
        )
        .unwrap();
    let context = PreparedContext {
        device_id: "reference-device".try_into().unwrap(),
        grant_revision: 1,
        session: Some(session.clone()),
        observation: None,
        capability: CapabilityId::DesktopWindowsRead,
        deadline: MonotonicMillis(30000),
        disconnect_policy: DisconnectPolicy::RetainForOwner,
    };
    let facts = AdmissionFacts {
        device_id: context.device_id.clone(),
        grant_revision: 1,
        local_policy_allowed: true,
        descriptor: CapabilityDescriptor {
            contract_version: styx_contracts::CONTRACT_VERSION,
            capability_id: context.capability,
            scope: Scope::Session,
            provider_id: "native-reference".try_into().unwrap(),
            configured: true,
            remote_grant: true,
            availability: Availability::Available,
            authorization: Authorization::Granted,
            target_session: Some(session),
            reason: None,
            observed_at: 0,
            observation_generation: 1,
            recovery: Recovery::None,
        },
        session_state: Some(SessionState::Ready),
        current_observation: None,
    };
    let payload = CuaOpenSpec::for_config(&config)
        .unwrap()
        .to_operation_payload()
        .unwrap();
    let open = ledger
        .prepare_desktop_agent(&owner, context.clone(), payload, MonotonicMillis(1))
        .unwrap();
    let DispatchDisposition::ExecuteOnce(permit) = ledger
        .dispatch(
            &owner,
            &open.id,
            open.payload_digest,
            &facts,
            MonotonicMillis(2),
        )
        .unwrap()
    else {
        panic!("fresh_reference_open")
    };
    let allocator = Arc::new(Semaphore::new(IO_BYTES));
    let budget =
        CuaIoBudget::from_reserved(allocator.acquire_many_owned(IO_BYTES as u32).await.unwrap())
            .unwrap();
    let worker = CuaWorker::new(budget);
    let opened = worker
        .try_reserve_open()
        .unwrap()
        .spawn_owned(permit, config)
        .await;
    let mut report = serde_json::json!({"fixture_pid":fixture.pid,"original_account_context_untouched":true,"native_calls":[],"input_calls":0});
    let mut passed = false;
    let handle = match opened {
        Ok(opened) => {
            ledger
                .record_executor_fact(&open.id, ExecutorFact::Running, MonotonicMillis(3))
                .unwrap();
            let mut read_context = context;
            read_context.capability = CapabilityId::DesktopAccessibility;
            let mut read_facts = facts;
            read_facts.descriptor.capability_id = CapabilityId::DesktopAccessibility;
            let mut authority = ReadAuthority {
                ledger,
                owner,
                target: ResourceTarget {
                    operation_id: open.id,
                    payload_digest: open.payload_digest,
                },
                context: read_context,
                facts: read_facts,
                at: 3,
            };
            let (peer, identity) = {
                let live = opened.handle.resource.live.lock().await;
                (
                    live.client.as_ref().unwrap().peer().clone(),
                    live.identity.clone(),
                )
            };
            report["worker_identity"] = serde_json::to_value(&identity).unwrap();
            report["peer_info"] = serde_json::to_value(peer.peer_info()).unwrap();
            let mut stages = Vec::new();
            let (before, value) = sample(
                &worker,
                &opened.handle,
                &mut authority,
                read_action(fixture.pid, fixture.valid_window_id),
            )
            .await;
            stages.push(serde_json::json!({"stage":"valid_before","result":value}));
            if before == CuaEvidence::Acknowledged && target.still_current().unwrap_or(false) {
                let (refusal, value) = sample(
                    &worker,
                    &opened.handle,
                    &mut authority,
                    read_action(fixture.pid, fixture.sheet_window_id),
                )
                .await;
                stages
                    .push(serde_json::json!({"stage":"distinct_disposable_sheet","result":value}));
                // Follow production fencing: a new read is allowed only after a
                // fully settled known refusal. Never work around Unknown here.
                if refusal == CuaEvidence::NotDispatched && target.still_current().unwrap_or(false)
                {
                    let (after, value) = sample(
                        &worker,
                        &opened.handle,
                        &mut authority,
                        read_action(fixture.pid, fixture.valid_window_id),
                    )
                    .await;
                    stages.push(serde_json::json!({"stage":"valid_after","result":value}));
                    passed = after == CuaEvidence::Acknowledged
                        && identity
                            .as_ref()
                            .is_some_and(|id| id.still_current().unwrap_or(false));
                }
            }
            report["native_calls"] = serde_json::to_value(stages).unwrap();
            drop(peer);
            Some(opened.handle)
        }
        Err(failure) => {
            report["open_failure"] =
                serde_json::json!({"evidence":failure.evidence,"cause":failure.cause.code()});
            failure.handle
        }
    };
    // Close/join ONLY this reference's original proxy and authenticated native
    // transport, even when the acquisition/classification failed.
    let settled = if let Some(handle) = handle {
        let cleanup = worker.cleanup_owned(&handle, Duration::from_secs(20)).await;
        report["cleanup"] = serde_json::json!(format!("{cleanup:?}"));
        cleanup.is_ok_and(|facts| facts.complete())
    } else {
        true
    };
    let probe = source.drain_source_probe(std::time::Instant::now() + Duration::from_secs(10));
    report["source_probe_drain"] = serde_json::json!(format!("{probe:?}"));
    report["pass"] = serde_json::json!(passed && settled && probe == Ok(true));
    let path = root.join("RESULT.json");
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    serde_json::to_writer_pretty(&mut out, &report).unwrap();
    eprintln!("MAC_AX_WIRE_REFERENCE result={}", path.display());
    assert!(settled, "reference_original_transport_cleanup_unconfirmed");
    assert_eq!(probe, Ok(true), "reference_original_probe_drain");
    assert!(
        passed,
        "native_refusal_or_same_worker_continuation_failed; inspect private RESULT.json"
    );
}
