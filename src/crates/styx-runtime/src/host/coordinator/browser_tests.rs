use super::*;

#[test]
fn context_ack_is_not_physical_cleanup_and_unknown_exit_status_is_not_success() {
    let mut cleanup = BrowserCleanup {
        worker_exited: false,
        worker_exit_success: None,
        stdio_joined: false,
        context_closed: true,
        descendants: BrowserDescendants::Unknown,
    };
    assert!(!physical_complete(&cleanup));
    cleanup.worker_exited = true;
    cleanup.stdio_joined = true;
    assert!(!physical_complete(&cleanup));
    cleanup.descendants = BrowserDescendants::Confirmed;
    assert!(physical_complete(&cleanup));
    // Physical settlement and the outcome's success proof are independent.
    assert_eq!(cleanup.worker_exit_success, None);
}

#[test]
fn browser_context_cannot_be_replaced_with_exec_or_desktop_context() {
    let mut context = PreparedContext {
        device_id: DeviceId::try_from("browser-fixture").unwrap(),
        grant_revision: 1,
        session: None,
        observation: None,
        capability: CapabilityId::BrowserHeadless,
        deadline: MonotonicMillis(100),
        disconnect_policy: DisconnectPolicy::RetainForOwner,
    };
    assert!(validate_context(&context).is_ok());
    context.capability = CapabilityId::ExecRun;
    assert!(matches!(
        validate_context(&context),
        Err(CoordinatorError::Admission(ErrorCategory::StateConflict))
    ));
    context.capability = CapabilityId::BrowserHeaded;
    assert!(validate_context(&context).is_err());
}

#[test]
fn profile_workspaces_cannot_expose_other_owner_private_directories() {
    let make = |profile: &str, output: &str, workspace: &str| OwnedBrowserConfig {
        node_binary: "/unused/node".into(),
        worker_entry: "/unused/worker".into(),
        browser_binary: "/unused/browser".into(),
        profile_dir: profile.into(),
        output_dir: output.into(),
        workspace_dir: workspace.into(),
        rpc_timeout: Duration::from_secs(1),
    };
    let a = make("/owned/a-profile", "/owned/a-output", "/owned/shared");
    let b = make(
        "/owned/shared/b-profile",
        "/owned/b-output",
        "/owned/project-b",
    );
    assert!(!profiles_disjoint(&a, &b));
    assert!(!profiles_disjoint(&b, &a));
    let b = make(
        "/owned/b-profile",
        "/owned/shared/b-output",
        "/owned/project-b",
    );
    assert!(!profiles_disjoint(&a, &b));
    let b = make("/owned/b-profile", "/owned/b-output", "/owned/shared");
    assert!(profiles_disjoint(&a, &b));
}

#[test]
fn repeated_physical_settlement_is_idempotent_and_contradictory_exit_is_refused() {
    let mut ledger =
        OperationLedger::new(HostGeneration::try_from("browser-settlement-fixture").unwrap());
    let owner = ledger
        .register_verified_owner(
            OwnerId::try_from("fixture-owner").unwrap(),
            OwnerEpoch::try_from("fixture-epoch").unwrap(),
        )
        .unwrap();
    let facts = fixture_facts(CapabilityId::BrowserHeadless);
    let context = PreparedContext {
        device_id: facts.device_id.clone(),
        grant_revision: 7,
        session: None,
        observation: None,
        capability: CapabilityId::BrowserHeadless,
        deadline: MonotonicMillis(1000),
        disconnect_policy: DisconnectPolicy::RetainForOwner,
    };
    let open = ledger
        .prepare(
            &owner,
            context,
            b"opaque-browser-open-fixture".to_vec(),
            MonotonicMillis(0),
        )
        .unwrap();
    let _permit = ledger
        .dispatch(
            &owner,
            &open.id,
            open.payload_digest,
            &facts,
            MonotonicMillis(1),
        )
        .unwrap();
    ledger
        .record_executor_fact(&open.id, ExecutorFact::Running, MonotonicMillis(2))
        .unwrap();
    let mut proof = BrowserCleanup {
        worker_exited: true,
        worker_exit_success: Some(true),
        stdio_joined: true,
        context_closed: true,
        descendants: BrowserDescendants::Confirmed,
    };
    settle_physical(&mut ledger, &open.id, &proof, MonotonicMillis(3)).unwrap();
    let before = ledger
        .inspect(&owner, &open.id, open.payload_digest)
        .unwrap();
    settle_physical(&mut ledger, &open.id, &proof, MonotonicMillis(900)).unwrap();
    assert_eq!(
        ledger
            .inspect(&owner, &open.id, open.payload_digest)
            .unwrap(),
        before
    );
    proof.worker_exit_success = Some(false);
    assert_eq!(
        settle_physical(&mut ledger, &open.id, &proof, MonotonicMillis(901)),
        Err(ErrorCategory::IntegrityFailure)
    );
    assert_eq!(
        ledger
            .inspect(&owner, &open.id, open.payload_digest)
            .unwrap(),
        before
    );
}

fn fixture_facts(capability: CapabilityId) -> AdmissionFacts {
    AdmissionFacts {
        device_id: DeviceId::try_from("browser-fixture").unwrap(),
        grant_revision: 7,
        local_policy_allowed: true,
        descriptor: styx_contracts::capability::CapabilityDescriptor {
            contract_version: 1,
            capability_id: capability,
            scope: if capability == CapabilityId::ExecRun {
                Scope::Host
            } else {
                Scope::Browser
            },
            provider_id: ProviderId::try_from("owned-browser-fixture").unwrap(),
            configured: true,
            remote_grant: true,
            availability: styx_contracts::capability::Availability::Available,
            authorization: styx_contracts::capability::Authorization::Granted,
            target_session: None,
            reason: None,
            observed_at: 1,
            observation_generation: 1,
            recovery: styx_contracts::error::Recovery::None,
        },
        session_state: None,
        current_observation: None,
    }
}
fn browser_context(host: &HostCoordinator) -> PreparedContext {
    PreparedContext {
        device_id: fixture_facts(CapabilityId::BrowserHeadless).device_id,
        grant_revision: 7,
        session: None,
        observation: None,
        capability: CapabilityId::BrowserHeadless,
        deadline: MonotonicMillis(host.now().0 + 30000),
        disconnect_policy: DisconnectPolicy::RetainForOwner,
    }
}
async fn opened(host: &HostCoordinator, owner: &OwnerLease) -> OperationSnapshot {
    let reserved = host
        .prepare_browser_open(owner, browser_context(host))
        .unwrap();
    let completion = match host
        .dispatch_browser_open(owner, &reserved.id, reserved.payload_digest)
        .unwrap()
    {
        BrowserOpenSubmission::Submitted(t) => t.wait().await.unwrap(),
        BrowserOpenSubmission::Existing(_) => panic!("new open was not dispatched"),
    };
    assert_eq!(completion.evidence, BrowserActionEvidence::Acknowledged);
    assert_eq!(completion.snapshot.liveness, ExecutionLiveness::Running);
    completion.snapshot
}
fn target(open: &OperationSnapshot) -> ResourceTarget {
    ResourceTarget {
        operation_id: open.id.clone(),
        payload_digest: open.payload_digest,
    }
}
async fn acted(
    host: &HostCoordinator,
    owner: &OwnerLease,
    open: &OperationSnapshot,
    action: BrowserAction,
) -> BrowserActionCompletion {
    let reservation = host
        .prepare_browser_action(owner, target(open), browser_context(host), &action)
        .unwrap();
    let result = match host
        .dispatch_browser_action(owner, &reservation.id, reservation.payload_digest)
        .unwrap()
    {
        BrowserActionSubmission::Submitted(t) => t.wait().await.unwrap(),
        BrowserActionSubmission::Existing(_) => panic!("new action was not dispatched"),
    };
    if result.receipt.evidence != BrowserActionEvidence::Acknowledged {
        // This helper is used only by the fresh owned HTTP/profile fixture.
        // Keep the official backend error available without changing verdicts
        // or adding product logging. UTF-8 boundary keeps the whole line <8KiB.
        let diagnostic = serde_json::to_string(&serde_json::json!({
            "cause": result.receipt.cause,
            "result": &result.receipt.result,
        }))
        .expect("owned fixture diagnostic serialization");
        let mut end = diagnostic.len().min(8128);
        while !diagnostic.is_char_boundary(end) {
            end -= 1;
        }
        eprintln!("owned_browser_action_diagnostic {}", &diagnostic[..end]);
    }
    assert_eq!(result.receipt.evidence, BrowserActionEvidence::Acknowledged);
    result
}

/// Actual Codex-backed Host + sandboxed headless Browser + independent HTTP
/// effects. Synthetic facts are trusted fixture bootstrap, not paired/network
/// authorization evidence. No user browser profile, GUI or external site.
#[tokio::test]
#[ignore = "requires explicit STYX_TEST_BROWSER_ROOT/NODE/WORKER/EXECUTABLE and STYX_TEST_CODEX; owned Linux headless Host scenario"]
async fn actual_owned_browser_host_nonce_policy_drop_and_cleanup() {
    use bytes::Bytes;
    use futures_util::FutureExt;
    use http_body_util::{BodyExt, Full, Limited};
    use hyper::{Request, Response, body::Incoming, service::service_fn};
    use hyper_util::rt::TokioIo;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio_util::sync::CancellationToken;
    let root = std::path::PathBuf::from(std::env::var_os("STYX_TEST_BROWSER_ROOT").unwrap())
        .join(uuid::Uuid::new_v4().to_string());
    std::fs::create_dir(&root).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    for dir in [
        "codex-home",
        "a-profile",
        "a-output",
        "a-work",
        "b-profile",
        "b-output",
        "b-work",
    ] {
        let p = root.join(dir);
        std::fs::create_dir(&p).unwrap();
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let adapter = crate::providers::codex::CodexStdio::spawn_owned(
        crate::providers::codex::OwnedExecutorConfig {
            binary: std::env::var_os("STYX_TEST_CODEX").unwrap().into(),
            cwd: root.clone(),
            environment: BTreeMap::from([
                ("PATH".into(), "/usr/bin:/bin".into()),
                ("HOME".into(), root.display().to_string()),
                (
                    "CODEX_HOME".into(),
                    root.join("codex-home").display().to_string(),
                ),
            ]),
            rpc_timeout: Duration::from_secs(3),
            retained_process_limit: 8,
        },
    )
    .await
    .unwrap();
    let (host, authority) = HostCoordinator::new_owned(
        adapter,
        OperationLedger::new(HostGeneration::try_from("browser-host-owned-generation").unwrap()),
        fixture_facts(CapabilityId::ExecRun),
        4,
    )
    .unwrap();
    let budget = Arc::new(Semaphore::new(16 * 1024 * 1024))
        .acquire_many_owned(16 * 1024 * 1024)
        .await
        .unwrap();
    authority
        .configure_browser(
            fixture_facts(CapabilityId::BrowserHeadless),
            BrowserIoBudget::from_reserved(budget).unwrap(),
        )
        .unwrap();
    let owner = authority
        .register_verified_owner(
            OwnerId::try_from("browser-owner:a").unwrap(),
            OwnerEpoch::try_from("browser-epoch-a").unwrap(),
        )
        .unwrap();
    let other = authority
        .register_verified_owner(
            OwnerId::try_from("browser-owner:b").unwrap(),
            OwnerEpoch::try_from("browser-epoch-b").unwrap(),
        )
        .unwrap();
    let config = |prefix: &str| OwnedBrowserConfig {
        node_binary: std::env::var_os("STYX_TEST_BROWSER_NODE").unwrap().into(),
        worker_entry: std::env::var_os("STYX_TEST_BROWSER_WORKER").unwrap().into(),
        browser_binary: std::env::var_os("STYX_TEST_BROWSER_EXECUTABLE")
            .unwrap()
            .into(),
        workspace_dir: root.join(format!("{prefix}-work")),
        profile_dir: root.join(format!("{prefix}-profile")),
        output_dir: root.join(format!("{prefix}-output")),
        rpc_timeout: Duration::from_secs(8),
    };
    authority
        .register_browser_profile(&owner, config("a"))
        .unwrap();
    assert!(
        authority
            .register_browser_profile(&other, config("a"))
            .is_err()
    );
    let penetration = root.join("a-work/foreign-profile");
    std::fs::create_dir(&penetration).unwrap();
    std::fs::set_permissions(&penetration, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut rejected = config("b");
    rejected.profile_dir = penetration;
    assert!(
        authority
            .register_browser_profile(&other, rejected)
            .is_err()
    );
    authority
        .register_browser_profile(&other, config("b"))
        .unwrap();
    let navigations = Arc::new(AtomicUsize::new(0));
    let effects = Arc::new(Mutex::new(Vec::<String>::new()));
    let cookie_observations = Arc::new(Mutex::new(Vec::<bool>::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let stop = CancellationToken::new();
    let stop_server = stop.clone();
    let nav = navigations.clone();
    let writes = effects.clone();
    let cookies = cookie_observations.clone();
    let server = tokio::spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            let stream = tokio::select! {_ =stop_server.cancelled()=>break,result=listener.accept()=>result.unwrap().0};
            let nav = nav.clone();
            let writes = writes.clone();
            let cookies = cookies.clone();
            connections.spawn(async move {
                let service=service_fn(move |request:Request<Incoming>|{
                    let nav=nav.clone();let writes=writes.clone();let cookies=cookies.clone();
                    async move {
                        let uri=request.uri().path().to_owned();
                        let response=if let Some(nonce)=uri.strip_prefix("/probe/") {
                            nav.fetch_add(1,Ordering::SeqCst);cookies.lock().unwrap().push(request.headers().contains_key("cookie"));
                            Response::builder().header("content-type","text/html").header("set-cookie",format!("styx_owned={nonce}; Path=/; HttpOnly; SameSite=Lax")).body(Full::new(Bytes::from(format!("<!doctype html><title>owned Browser fixture</title><p id=nonce>{nonce}</p>")))).unwrap()
                        } else if uri=="/effect" {
                            assert!(request.headers().contains_key("cookie"));
                            let body=Limited::new(request.into_body(),4096).collect().await.unwrap().to_bytes();writes.lock().unwrap().push(String::from_utf8(body.to_vec()).unwrap());
                            Response::new(Full::new(Bytes::from_static(b"owned-effect-recorded")))
                        } else {Response::builder().status(204).body(Full::new(Bytes::new())).unwrap()};
                        Ok::<_,std::convert::Infallible>(response)
                    }
                });
                let _=hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream),service).await;
            });
        }
        while connections.join_next().await.is_some() {}
    });
    let nonce = uuid::Uuid::new_v4().to_string();
    let expected = nonce.clone();
    let unknown_nonce = uuid::Uuid::new_v4().to_string();
    let mut stage = "initial";
    let mut observations = serde_json::json!({});
    let scenario=std::panic::AssertUnwindSafe(async {
        stage = "open_a";
        assert_eq!(navigations.load(Ordering::SeqCst),0);assert!(effects.lock().unwrap().is_empty());
        let open=opened(&host,&owner).await;
        assert!(host.prepare_browser_action(&other,target(&open),browser_context(&host),&BrowserAction::Close).is_err());
        stage = "navigate_a";
        let nav=acted(&host,&owner,&open,BrowserAction::Navigate{url:format!("http://{address}/probe/{nonce}")}).await;
        assert_eq!(nav.snapshot.state,OperationState::Succeeded);assert_eq!(navigations.load(Ordering::SeqCst),1);
        stage = "drop_waiter_effect_a";
        let expression=format!("async()=>{{await fetch('/effect',{{method:'POST',body:{}}});return document.querySelector('#nonce').textContent}}",serde_json::to_string(&nonce).unwrap());
        let operation=host.prepare_browser_action(&owner,target(&open),browser_context(&host),&BrowserAction::Evaluate{function:expression}).unwrap();
        match host.dispatch_browser_action(&owner,&operation.id,operation.payload_digest).unwrap(){BrowserActionSubmission::Submitted(ticket)=>drop(ticket),_=>panic!("expected new action")}
        tokio::time::timeout(Duration::from_secs(20),async {loop {if effects.lock().unwrap().len()==1 {break;}tokio::time::sleep(Duration::from_millis(10)).await;}}).await.unwrap();
        assert_eq!(*effects.lock().unwrap(),vec![nonce.clone()]);
        tokio::time::timeout(Duration::from_secs(20),async {
            loop {
                let snapshot=host.inner.state.lock().unwrap().ledger.inspect(&owner,&operation.id,operation.payload_digest).unwrap();
                if snapshot.state==OperationState::Succeeded {break;}
                assert_ne!(snapshot.state,OperationState::Unknown,"unexpected actual action acknowledgement loss; preserve rather than replay");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.unwrap();
        assert!(matches!(host.dispatch_browser_action(&owner,&operation.id,operation.payload_digest).unwrap(),BrowserActionSubmission::Existing(_)));
        stage = "policy_denial";
        let mut denied=fixture_facts(CapabilityId::BrowserHeadless);denied.local_policy_allowed=false;authority.replace_browser_facts(denied).unwrap();
        let forbidden=host.prepare_browser_action(&owner,target(&open),browser_context(&host),&BrowserAction::Navigate{url:format!("http://{address}/probe/forbidden")}).unwrap();
        assert!(matches!(host.dispatch_browser_action(&owner,&forbidden.id,forbidden.payload_digest),Err(CoordinatorError::Admission(ErrorCategory::PermissionDenied))));
        assert_eq!(navigations.load(Ordering::SeqCst),1);assert_eq!(effects.lock().unwrap().len(),1);
        authority.replace_browser_facts(fixture_facts(CapabilityId::BrowserHeadless)).unwrap();
        stage = "close_and_retire_a";
        let closed=acted(&host,&owner,&open,BrowserAction::Close).await;assert!(closed.cleanup.as_ref().is_some_and(physical_complete));
        let retired_a=authority.collect_provider_retention(Duration::from_secs(10)).await.unwrap();
        observations["a_retention"]=serde_json::json!({"actions_released":retired_a.actions_released,"resources_released":retired_a.resources_released,"unreleased":retired_a.unreleased_records,"blocked":retired_a.blocked.len(),"deadline":retired_a.deadline_exhausted});
        assert!(retired_a.blocked.is_empty());assert!(!retired_a.deadline_exhausted);assert_eq!(retired_a.resources_released,1);assert_eq!(retired_a.unreleased_records,0);
        assert!(host.prepare_browser_action(&owner,target(&open),browser_context(&host),&BrowserAction::Close).is_err());
        stage = "open_and_navigate_b";
        let b=opened(&host,&other).await;
        acted(&host,&other,&b,BrowserAction::Navigate{url:format!("http://{address}/probe/{}",uuid::Uuid::new_v4())}).await;
        assert_eq!(*cookie_observations.lock().unwrap(),vec![false,false]);
        stage = "real_effect_then_response_timeout_b";
        let expression=format!("async()=>{{await fetch('/effect',{{method:'POST',body:{}}});await new Promise(()=>{{}})}}",serde_json::to_string(&unknown_nonce).unwrap());
        let uncertain=host.prepare_browser_action(&other,target(&b),browser_context(&host),&BrowserAction::Evaluate{function:expression}).unwrap();
        let unknown=match host.dispatch_browser_action(&other,&uncertain.id,uncertain.payload_digest).unwrap(){BrowserActionSubmission::Submitted(t)=>t.wait().await.unwrap(),_=>panic!("new timeout action required")};
        observations["unknown_after_timeout"]=serde_json::json!({"state":unknown.snapshot.state,"evidence":unknown.receipt.evidence,"effect_count":effects.lock().unwrap().iter().filter(|n|*n==&unknown_nonce).count()});
        assert_eq!(unknown.snapshot.state,OperationState::Unknown);assert_eq!(unknown.receipt.evidence,BrowserActionEvidence::Unknown);
        assert_eq!(effects.lock().unwrap().iter().filter(|n|*n==&unknown_nonce).count(),1);
        stage = "unknown_duplicate_no_replay";
        let duplicate=host.dispatch_browser_action(&other,&uncertain.id,uncertain.payload_digest).unwrap();
        assert!(matches!(duplicate,BrowserActionSubmission::Existing(ref s) if s.state==OperationState::Unknown));
        assert_eq!(effects.lock().unwrap().iter().filter(|n|*n==&unknown_nonce).count(),1);
        observations["unknown_duplicate_existing_no_replay"]=serde_json::json!(true);
        stage = "close_b_after_unknown";
        // A stuck evaluate may also prevent the upstream Close ACK. Only actual
        // scope exit+stdio join+descendant proof establishes physical cleanup.
        let close=host.prepare_browser_action(&other,target(&b),browser_context(&host),&BrowserAction::Close).unwrap();
        let closed_b=match host.dispatch_browser_action(&other,&close.id,close.payload_digest).unwrap(){BrowserActionSubmission::Submitted(t)=>t.wait().await.unwrap(),_=>panic!("new close required")};
        assert!(closed_b.cleanup.as_ref().is_some_and(physical_complete));
        observations["b_close"]=serde_json::json!({"action_state":closed_b.snapshot.state,"context_ack":closed_b.cleanup.as_ref().unwrap().context_closed,"worker_exited":closed_b.cleanup.as_ref().unwrap().worker_exited,"stdio_joined":closed_b.cleanup.as_ref().unwrap().stdio_joined,"descendants_confirmed":closed_b.cleanup.as_ref().unwrap().descendants==BrowserDescendants::Confirmed});
        stage = "retire_b_unknown_bundle";
        let retired_b=authority.collect_provider_retention(Duration::from_secs(10)).await.unwrap();
        observations["b_retention"]=serde_json::json!({"actions_released":retired_b.actions_released,"resources_released":retired_b.resources_released,"unreleased":retired_b.unreleased_records,"blocked":retired_b.blocked.len(),"deadline":retired_b.deadline_exhausted});
        assert!(retired_b.blocked.is_empty());assert!(!retired_b.deadline_exhausted);assert_eq!(retired_b.resources_released,1);assert_eq!(retired_b.unreleased_records,0);
        let history=host.inner.state.lock().unwrap().ledger.inspect(&other,&uncertain.id,uncertain.payload_digest).unwrap();
        assert_eq!(history.state,OperationState::Unknown);
        observations["unknown_history_after_physical_release"]=serde_json::json!(history.state);
        assert_eq!(*effects.lock().unwrap(),vec![nonce.clone(),unknown_nonce.clone()]);
        stage = "owner_cleanup_and_profile_metadata_release";
        for current in [&owner,&other] {
            let cleanup=authority.fence_owner_for_cleanup(current).unwrap();
            let result=authority.cleanup_owner(&cleanup,Duration::from_secs(5)).unwrap().wait().await.unwrap();
            assert!(result.physical_complete);assert!(result.quiescent);assert_eq!(result.unreleased_records,0);assert!(result.blocked.is_empty());
        }
        assert!(host.inner.state.lock().unwrap().browser.as_ref().unwrap().profiles.is_empty());
        assert!(root.join("a-profile").is_dir());assert!(root.join("b-profile").is_dir());
        observations["owners_physically_complete_unreleased_zero"]=serde_json::json!(true);
        observations["profile_metadata_released_bytes_preserved"]=serde_json::json!(true);
        stage = "scenario_complete";
    }).catch_unwind().await;
    let cleanup = authority.shutdown_owned(Duration::from_secs(25)).await;
    stop.cancel();
    let server_join = tokio::time::timeout(Duration::from_secs(5), server).await;
    let server_complete = matches!(&server_join, Ok(Ok(())));
    let completed = cleanup.as_ref().ok().is_some_and(|facts| {
        facts.supervised_jobs_joined
            && facts.native.executor_exited
            && facts.native.reader_task_reaped
            && facts.native.stderr_task_reaped
            && facts
                .browser
                .as_ref()
                .is_some_and(|browser| browser.complete)
    });
    let receipt = serde_json::json!({"schema":1,"status":if scenario.is_ok()&&completed&&server_complete{"PASS"}else{"FAIL"},"scope":"actual owned Host single-ledger headless Browser with independent HTTP nonce/cookie effects; trusted bootstrap facts, not paired-network/account/GUI/release acceptance","nonce":expected,"unknown_nonce":unknown_nonce,"last_stage":stage,"observations":observations,"http_navigations":navigations.load(Ordering::SeqCst),"http_effects":effects.lock().unwrap().clone(),"cross_profile_cookie_received":cookie_observations.lock().unwrap().clone(),"host_browser_cleanup_complete":completed,"http_server_joined":server_complete,"browser_worker_source":std::env::var_os("STYX_TEST_BROWSER_WORKER"),"source_sha256":{"browser.rs":hex::encode(<sha2::Sha256 as sha2::Digest>::digest(include_bytes!("browser.rs"))),"browser_tests.rs":hex::encode(<sha2::Sha256 as sha2::Digest>::digest(include_bytes!("browser_tests.rs")))}});
    std::fs::write(
        root.join("receipt.json"),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();
    assert!(
        completed,
        "actual Browser cleanup must be physically confirmed"
    );
    assert!(server_complete);
    if let Err(panic) = scenario {
        std::panic::resume_unwind(panic);
    }
}

#[path = "browser_reference_tests.rs"]
mod references;
