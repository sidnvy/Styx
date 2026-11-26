use super::operations::BrowserBootstrap;
use super::*;
use crate::host::{
    browser_extension::{BROWSER_SESSION_ID, CdpSessionScope},
    coordinator::HostCoordinator,
};
use crate::providers::browser::OwnedBrowserConfig;
use std::{
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
use styx_contracts::{capability::*, error::Recovery};
use styx_core::{operations::OperationLedger, policy::AdmissionFacts};

struct Bootstrap {
    root: PathBuf,
    prepared: AtomicUsize,
}
impl operations::BrowserBootstrap for Bootstrap {
    fn release_profile(&self, _: &OwnerLease) {}
    fn prepare_profile(
        &self,
        _: &OwnerLease,
        _: CdpSessionScope,
    ) -> Result<OwnedBrowserConfig, ErrorCategory> {
        if self.prepared.fetch_add(1, Ordering::SeqCst) != 0 {
            return Err(ErrorCategory::CapabilityUnsupported);
        }
        let unused = std::fs::canonicalize("/usr/bin/true").unwrap();
        Ok(OwnedBrowserConfig {
            node_binary: unused.clone(),
            worker_entry: unused,
            cdp_endpoint: "ws://127.0.0.1:9222/devtools/browser/fixture".to_owned(),
            workspace_dir: self.root.join("workspace"),
            output_dir: self.root.join("output"),
            // Expire the actual read-only preflight before it starts a command.
            // No worker is started; its registered empty resource is cleaned normally.
            rpc_timeout: Duration::from_nanos(1),
        })
    }
    fn validate_before_spawn(&self) -> Result<(), ErrorCategory> {
        Ok(())
    }
    fn validate_control(&self) -> Result<(), ErrorCategory> {
        Ok(())
    }
}
impl Drop for Bootstrap {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root).unwrap();
    }
}

struct UnsupportedBootstrap;
impl operations::BrowserBootstrap for UnsupportedBootstrap {
    fn release_profile(&self, _: &OwnerLease) {}
    fn prepare_profile(
        &self,
        _: &OwnerLease,
        _: CdpSessionScope,
    ) -> Result<OwnedBrowserConfig, ErrorCategory> {
        Err(ErrorCategory::CapabilityUnsupported)
    }
    fn validate_before_spawn(&self) -> Result<(), ErrorCategory> {
        Ok(())
    }
    fn validate_control(&self) -> Result<(), ErrorCategory> {
        Ok(())
    }
}

fn facts(capability: CapabilityId) -> AdmissionFacts {
    AdmissionFacts {
        device_id: "browser-session-preflight".try_into().unwrap(),
        grant_revision: 1,
        local_policy_allowed: true,
        descriptor: CapabilityDescriptor {
            contract_version: 1,
            capability_id: capability,
            scope: if capability == CapabilityId::Browser {
                Scope::Browser
            } else {
                Scope::Host
            },
            provider_id: "browser-fixture".try_into().unwrap(),
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
fn register_caller(
    host: &HostCoordinator,
    authority: &crate::host::coordinator::HostAuthority,
    owner: &OwnerRef,
) {
    let lease = authority
        .register_verified_owner(owner.owner_id.clone(), owner.owner_epoch.clone())
        .unwrap();
    host.remote_access().lock().unwrap().owners.insert(
        caller(owner),
        crate::host::callers::OwnerRecord {
            lease: Some(lease),
            revision: host.grant_revision(),
            cleanup: None,
        },
    );
}
fn named_caller(name: &str) -> OwnerRef {
    OwnerRef {
        owner_id: name.try_into().unwrap(),
        owner_epoch: format!("{name}-epoch").try_into().unwrap(),
    }
}
fn error(result: &CallToolResult) -> Value {
    assert_eq!(result.is_error, Some(true));
    let value = serde_json::to_value(result).unwrap();
    serde_json::from_str(value["content"][0]["text"].as_str().unwrap()).unwrap()
}
fn tabs(session_id: Option<String>) -> BrowserSessionCommand {
    BrowserSessionCommand::Action {
        session_id,
        name: "browser_tabs".into(),
        arguments: serde_json::from_value(json!({"action":"list"})).unwrap(),
    }
}

#[tokio::test]
async fn known_preflight_refusal_releases_the_resource_and_allows_a_new_request() {
    let root = std::env::temp_dir().join(format!("styx-browser-session-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    for name in ["workspace", "output"] {
        let dir = root.join(name);
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let source = Arc::new(Bootstrap {
        root,
        prepared: AtomicUsize::new(0),
    });
    let (host, authority) = HostCoordinator::new_without_executor(
        OperationLedger::new("browser-session-generation".try_into().unwrap()),
        facts(CapabilityId::ExecRun),
    )
    .unwrap();
    authority
        .configure_browser(facts(CapabilityId::Browser))
        .unwrap();
    let inputs = host.browser_sessions().inputs(source.clone());
    let engine = Engine {
        port: BrowserPort {
            coordinator: &host,
            authority: &authority,
            inputs: &inputs,
        },
    };
    let owner = OwnerRef {
        owner_id: "caller".try_into().unwrap(),
        owner_epoch: "epoch".try_into().unwrap(),
    };

    register_caller(&host, &authority, &owner);
    let first = engine.handle(owner.clone(), tabs(None)).await;
    let refusal = error(&first);
    assert_eq!(refusal["uncertain"], false);
    assert_ne!(refusal["error"], "outcome_unknown");
    let id = first.structured_content.as_ref().unwrap()["browser_session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        id.starts_with("bg-"),
        "expected background session ID, got {id}"
    );
    let cell = engine.state().registry.lock().unwrap().sessions[&id].clone();
    {
        let session = cell.lock().await;
        assert!(session.phase == Phase::Saved);
        assert!(session.target.is_none());
    }
    let retained = authority
        .collect_provider_retention(Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(retained.resources_released, 0);
    assert_eq!(retained.unreleased_records, 0);
    assert!(retained.blocked.is_empty());
    assert_eq!(
        std::fs::read_dir(source.root.join("output"))
            .unwrap()
            .count(),
        0
    );
    assert_eq!(
        source.prepared.load(Ordering::SeqCst),
        1,
        "the failed request was not replayed"
    );

    let second = engine.handle(owner.clone(), tabs(Some(id.clone()))).await;
    assert_eq!(error(&second)["error"], "capability_unsupported");
    assert_eq!(error(&second)["uncertain"], false);
    assert_eq!(source.prepared.load(Ordering::SeqCst), 2);
    let closed = engine
        .handle(
            owner,
            BrowserSessionCommand::Action {
                session_id: Some(id),
                name: "browser_close".into(),
                arguments: Default::default(),
            },
        )
        .await;
    assert_ne!(closed.is_error, Some(true));
}

#[tokio::test]
async fn extension_bridge_session_is_default_transferable_and_rejects_unknown_ids() {
    let (host, authority) = HostCoordinator::new_without_executor(
        OperationLedger::new(uuid::Uuid::new_v4().to_string().try_into().unwrap()),
        facts(CapabilityId::ExecRun),
    )
    .unwrap();
    authority
        .configure_browser(facts(CapabilityId::Browser))
        .unwrap();
    let inputs = host
        .browser_sessions()
        .inputs(Arc::new(UnsupportedBootstrap));
    let engine = Engine {
        port: BrowserPort {
            coordinator: &host,
            authority: &authority,
            inputs: &inputs,
        },
    };
    let a = named_caller("ext-a");
    let b = named_caller("ext-b");
    register_caller(&host, &authority, &a);
    register_caller(&host, &authority, &b);

    let listed = engine.handle(a.clone(), BrowserSessionCommand::List).await;
    let sessions = listed.structured_content.as_ref().unwrap()["sessions"]
        .as_array()
        .unwrap();
    assert_eq!(sessions.len(), 1);
    let entry = &sessions[0];
    assert_eq!(entry["browser_session_id"], BROWSER_SESSION_ID);
    assert_eq!(entry["mode"], "extension_existing");
    assert_eq!(entry["attached_existing_browser"], true);
    assert_eq!(entry["profile_persistent"], false);
    assert_eq!(entry["available"], true);
    assert_eq!(entry["current_operator"], false);

    // Unknown explicit IDs are rejected cleanly.
    for unknown_id in ["other-session", "missing-id"] {
        let refused = engine
            .handle(a.clone(), tabs(Some(unknown_id.to_owned())))
            .await;
        assert_eq!(error(&refused)["error"], "browser_session_not_found");
        let rejected_takeover = engine
            .handle(
                a.clone(),
                BrowserSessionCommand::TakeOver {
                    session_id: unknown_id.to_owned(),
                },
            )
            .await;
        assert_eq!(
            error(&rejected_takeover)["error"],
            "browser_session_not_found"
        );
    }

    // `new` is never valid for takeover.
    let new_takeover = engine
        .handle(
            a.clone(),
            BrowserSessionCommand::TakeOver {
                session_id: "new".to_owned(),
            },
        )
        .await;
    assert_eq!(error(&new_takeover)["error"], "browser_session_not_found");

    // Omitting `browser_session_id` gives each independent caller its own parallel Tab Group session.
    let a_call = engine.handle(a.clone(), tabs(None)).await;
    let a_bg_id = a_call.structured_content.as_ref().unwrap()["browser_session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(a_bg_id.starts_with("bg-"));
    assert_eq!(error(&a_call)["error"], "capability_unsupported");

    let b_call = engine.handle(b.clone(), tabs(None)).await;
    let b_bg_id = b_call.structured_content.as_ref().unwrap()["browser_session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(b_bg_id.starts_with("bg-"));
    assert_ne!(a_bg_id, b_bg_id);

    let listed_parallel = engine.handle(a.clone(), BrowserSessionCommand::List).await;
    let parallel_sessions = listed_parallel.structured_content.as_ref().unwrap()["sessions"]
        .as_array()
        .unwrap();
    assert_eq!(parallel_sessions.len(), 3);
    assert!(parallel_sessions.iter().any(|s| {
        s["browser_session_id"] == a_bg_id
            && s["mode"] == "extension_tab_group"
            && s["tab_group_title"] == "Styx · 1"
    }));
    assert!(parallel_sessions.iter().any(|s| {
        s["browser_session_id"] == b_bg_id
            && s["mode"] == "extension_tab_group"
            && s["tab_group_title"] == "Styx · 2"
    }));

    // Explicit `existing-browser` remains single-operator with explicit takeover.
    let a_shared = engine
        .handle(a.clone(), tabs(Some(BROWSER_SESSION_ID.to_owned())))
        .await;
    assert_eq!(error(&a_shared)["error"], "capability_unsupported");

    let b_blocked = engine
        .handle(b.clone(), tabs(Some(BROWSER_SESSION_ID.to_owned())))
        .await;
    assert_eq!(error(&b_blocked)["error"], "browser_session_transferred");

    let taken = engine
        .handle(
            b.clone(),
            BrowserSessionCommand::TakeOver {
                session_id: BROWSER_SESSION_ID.to_owned(),
            },
        )
        .await;
    let taken_body = taken.structured_content.as_ref().unwrap();
    assert_eq!(taken_body["browser_session_id"], BROWSER_SESSION_ID);
    assert_eq!(taken_body["mode"], "extension_existing");
    assert_eq!(taken_body["attached_existing_browser"], true);
    assert_eq!(taken_body["profile_persistent"], false);
    assert_eq!(taken_body["current_operator"], true);

    let a_blocked = engine
        .handle(a.clone(), tabs(Some(BROWSER_SESSION_ID.to_owned())))
        .await;
    assert_eq!(error(&a_blocked)["error"], "browser_session_transferred");

    // Closing `existing-browser` releases operator ownership and resets to saved without disturbing `bg-...`.
    let closed = engine
        .handle(
            b.clone(),
            BrowserSessionCommand::Action {
                session_id: Some(BROWSER_SESSION_ID.to_owned()),
                name: "browser_close".into(),
                arguments: serde_json::from_value(json!({})).unwrap(),
            },
        )
        .await;
    let closed_body = closed.structured_content.as_ref().unwrap();
    assert_eq!(closed_body["closed"], true);
    assert_eq!(closed_body["detached"], true);
    assert_eq!(closed_body["profile_persistent"], false);

    // Caller A can close its `bg-...` session independently while `existing-browser` stays available.
    let closed_a_bg = engine
        .handle(
            a.clone(),
            BrowserSessionCommand::Action {
                session_id: Some(a_bg_id.clone()),
                name: "browser_close".into(),
                arguments: serde_json::from_value(json!({})).unwrap(),
            },
        )
        .await;
    assert_ne!(closed_a_bg.is_error, Some(true));

    let listed_after = engine.handle(a, BrowserSessionCommand::List).await;
    let after_arr = listed_after.structured_content.as_ref().unwrap()["sessions"]
        .as_array()
        .unwrap();
    assert!(!after_arr.iter().any(|s| s["browser_session_id"] == a_bg_id));
    assert!(after_arr.iter().any(|s| s["browser_session_id"] == b_bg_id));
    assert!(
        after_arr
            .iter()
            .find(|s| s["browser_session_id"] == BROWSER_SESSION_ID)
            .unwrap()["available"]
            == true
    );
}

#[tokio::test]
async fn caller_cleanup_releases_extension_session_operator_on_next_list() {
    let (host, authority) = HostCoordinator::new_without_executor(
        OperationLedger::new(uuid::Uuid::new_v4().to_string().try_into().unwrap()),
        facts(CapabilityId::ExecRun),
    )
    .unwrap();
    authority
        .configure_browser(facts(CapabilityId::Browser))
        .unwrap();
    let inputs = host
        .browser_sessions()
        .inputs(Arc::new(UnsupportedBootstrap));
    let engine = Engine {
        port: BrowserPort {
            coordinator: &host,
            authority: &authority,
            inputs: &inputs,
        },
    };
    let a = named_caller("cleanup-a");
    let b = named_caller("cleanup-b");
    register_caller(&host, &authority, &a);
    register_caller(&host, &authority, &b);

    let (_, cell) = engine
        .resolve(&a, Some(BROWSER_SESSION_ID.to_owned()))
        .unwrap();
    {
        let mut session = cell.lock().await;
        session.operator = Some(a.clone());
    }
    let in_flight = cell.lock().await;
    host.remote_access()
        .lock()
        .unwrap()
        .owners
        .remove(&caller(&a));
    host.browser_sessions().forget_caller(&a);
    drop(in_flight);

    let listed = engine.handle(b, BrowserSessionCommand::List).await;
    assert_eq!(
        listed.structured_content.as_ref().unwrap()["sessions"][0]["available"],
        true
    );
}

#[tokio::test]
async fn closed_or_exited_browser_context_recovers_to_saved_on_next_request() {
    let root = std::env::temp_dir().join(format!("styx-browser-recover-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    for name in ["workspace", "output"] {
        let dir = root.join(name);
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let source = Arc::new(Bootstrap {
        root,
        prepared: AtomicUsize::new(0),
    });
    let (host, authority) = HostCoordinator::new_without_executor(
        OperationLedger::new("browser-recover-generation".try_into().unwrap()),
        facts(CapabilityId::ExecRun),
    )
    .unwrap();
    authority
        .configure_browser(facts(CapabilityId::Browser))
        .unwrap();
    let inputs = host.browser_sessions().inputs(source.clone());
    let engine = Engine {
        port: BrowserPort {
            coordinator: &host,
            authority: &authority,
            inputs: &inputs,
        },
    };
    let a = named_caller("recover-after-exit");
    register_caller(&host, &authority, &a);

    let (resolved_id, cell) = engine
        .resolve(&a, Some(BROWSER_SESSION_ID.to_owned()))
        .unwrap();
    assert_eq!(resolved_id, BROWSER_SESSION_ID);

    let old_lease = {
        let mut session = cell.lock().await;
        session.operator = Some(a.clone());
        let lease = session.lease.clone();
        let config = source
            .prepare_profile(&lease, CdpSessionScope::SharedExisting)
            .unwrap();
        authority.register_browser_profile(&lease, config).unwrap();
        let context = PreparedContext {
            device_id: host.bootstrap_identity().0.clone(),
            grant_revision: host.grant_revision(),
            session: None,
            observation: None,
            capability: CapabilityId::Browser,
            deadline: Some(MonotonicMillis(host.now().0 + 5_000)),
            disconnect_policy: DisconnectPolicy::RetainForOwner,
        };
        let snapshot = host.prepare_browser_open(&lease, context).unwrap();
        let target = ResourceTarget {
            operation_id: snapshot.id.clone(),
            payload_digest: snapshot.payload_digest,
        };
        match host
            .dispatch_browser_open(&lease, &target.operation_id, target.payload_digest)
            .await
            .unwrap()
        {
            crate::host::coordinator::BrowserOpenSubmission::Submitted(ticket) => {
                let _ = ticket.wait().await.unwrap();
            }
            _ => panic!("expected submission"),
        }
        assert!(!host.browser_session_exited(&lease, &target));
        host.mark_browser_context_closed_for_test(&lease, &target);
        assert!(host.browser_session_exited(&lease, &target));
        session.target = Some(target);
        session.phase = Phase::Ready;
        lease
    };

    let outcome = engine.handle(a.clone(), tabs(Some(resolved_id))).await;
    assert_eq!(error(&outcome)["error"], "capability_unsupported");
    assert_eq!(error(&outcome)["uncertain"], false);

    let session = cell.lock().await;
    assert!(session.operator.as_ref() == Some(&a));
    assert!(session.target.is_none());
    assert!(session.cleanup.is_none());
    assert_ne!(session.lease, old_lease);
}

#[test]
fn attach_session_id_to_content_surfaces_id_without_mutating_errors_or_existing_json() {
    let mut page_result = CallToolResult::success(vec![ContentBlock::text(
        "### Page\n- Page URL: https://news.ycombinator.com/",
    )]);
    attach_session_id_to_content(&mut page_result, "sess-123");
    let text = &page_result.content[0].as_text().unwrap().text;
    assert!(text.starts_with("### Browser Session\n- browser_session_id: sess-123\n\n### Page"));

    let mut prose_mention_result = CallToolResult::success(vec![ContentBlock::text(
        "### Page\n- mentions browser_session_id in body",
    )]);
    attach_session_id_to_content(&mut prose_mention_result, "sess-123");
    let prose_text = &prose_mention_result.content[0].as_text().unwrap().text;
    assert!(
        prose_text.starts_with("### Browser Session\n- browser_session_id: sess-123\n\n### Page")
    );

    let mut json_result = CallToolResult::success(vec![ContentBlock::text(
        r#"{"browser_session_id":"sess-123"}"#,
    )]);
    attach_session_id_to_content(&mut json_result, "sess-123");
    assert_eq!(
        json_result.content[0].as_text().unwrap().text,
        r#"{"browser_session_id":"sess-123"}"#
    );

    let mut error_result = failure("browser_session_not_found", false);
    attach_session_id_to_content(&mut error_result, "sess-123");
    assert!(
        !error_result.content[0]
            .as_text()
            .unwrap()
            .text
            .contains("Browser Session")
    );
}

#[test]
fn action_timeout_uses_extended_prepare_timeout_and_result_accepts_large_snapshots() {
    assert_eq!(
        action_timeout("browser_tabs"),
        BROWSER_WAIT_PREPARE_TIMEOUT_MS
    );
    assert_eq!(
        action_timeout("browser_snapshot"),
        BROWSER_WAIT_PREPARE_TIMEOUT_MS
    );

    // Regression: >128 KB snapshots (such as Telegram Web) must be accepted up to 8 MB.
    let large_text = "x".repeat(300 * 1024);
    let ok = result(json!({
        "isError": false,
        "content": [{"type": "text", "text": large_text}]
    }))
    .unwrap();
    assert_ne!(ok.is_error, Some(true));

    let oversized = "y".repeat(MAX_BROWSER_RESULT_BYTES + 1024);
    assert_eq!(
        result(json!({
            "isError": false,
            "content": [{"type": "text", "text": oversized}]
        }))
        .unwrap_err(),
        "outcome_unknown"
    );
}

#[tokio::test]
async fn not_dispatched_cleans_up_unattached_worker_and_preserves_retryable_session() {
    let root = std::env::temp_dir().join(format!(
        "styx-browser-not-dispatched-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    for name in ["workspace", "output"] {
        let dir = root.join(name);
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let source = Arc::new(Bootstrap {
        root,
        prepared: AtomicUsize::new(0),
    });
    let (host, authority) = HostCoordinator::new_without_executor(
        OperationLedger::new("browser-not-dispatched".try_into().unwrap()),
        facts(CapabilityId::ExecRun),
    )
    .unwrap();
    authority
        .configure_browser(facts(CapabilityId::Browser))
        .unwrap();
    let inputs = host.browser_sessions().inputs(source.clone());
    let engine = Engine {
        port: BrowserPort {
            coordinator: &host,
            authority: &authority,
            inputs: &inputs,
        },
    };
    let a = named_caller("ext-retry");
    register_caller(&host, &authority, &a);

    let mut session = engine
        .new_session(
            BROWSER_SESSION_ID.to_owned(),
            CdpSessionScope::SharedExisting,
            Some(a.clone()),
            Phase::Saved,
        )
        .unwrap();
    let old_lease = session.lease.clone();
    let config = source
        .prepare_profile(&old_lease, CdpSessionScope::SharedExisting)
        .unwrap();
    authority
        .register_browser_profile(&old_lease, config)
        .unwrap();
    let context = PreparedContext {
        device_id: host.bootstrap_identity().0.clone(),
        grant_revision: host.grant_revision(),
        session: None,
        observation: None,
        capability: CapabilityId::Browser,
        deadline: Some(MonotonicMillis(host.now().0 + 5_000)),
        disconnect_policy: DisconnectPolicy::RetainForOwner,
    };
    let open_snap = host.prepare_browser_open(&old_lease, context).unwrap();
    let target = ResourceTarget {
        operation_id: open_snap.id.clone(),
        payload_digest: open_snap.payload_digest,
    };
    match host
        .dispatch_browser_open(&old_lease, &target.operation_id, target.payload_digest)
        .await
        .unwrap()
    {
        crate::host::coordinator::BrowserOpenSubmission::Submitted(ticket) => {
            let _ = ticket.wait().await.unwrap();
        }
        _ => panic!("expected submission"),
    }
    session.target = Some(target.clone());
    session.phase = Phase::Unknown;

    let op_id = OperationId {
        host_generation: "browser-not-dispatched".try_into().unwrap(),
        owner_epoch: "ext-retry-epoch".try_into().unwrap(),
        sequence: 1,
    };
    let digest = Sha256Digest::of_bytes(b"ext-tabs-list");
    let cell = Arc::new(AsyncMutex::new(session));
    {
        let mut registry = engine.state().registry.lock().unwrap();
        registry
            .sessions
            .insert(BROWSER_SESSION_ID.to_owned(), cell.clone());
    }

    let res = {
        let mut guard = cell.lock().await;
        engine
            .finish_action(
                BROWSER_SESSION_ID,
                &mut guard,
                &op_id,
                digest,
                &target,
                BrowserReply::Action {
                    snapshot: Snapshot {
                        operation_id: op_id.clone(),
                        payload_digest: digest,
                        target: Some(target.clone()),
                        state: OperationState::Failed,
                        liveness: ExecutionLiveness::Running,
                        output_drain: OutputDrain::Open,
                    },
                    dispatch: "not_dispatched".into(),
                    result: None,
                    cause: Some(ErrorCategory::CapabilityUnsupported),
                    cleanup_complete: Some(false),
                },
            )
            .await
    };
    assert_eq!(error(&res)["error"], "capability_unsupported");
    assert_eq!(error(&res)["uncertain"], false);

    let guard = cell.lock().await;
    assert!(guard.phase == Phase::Saved);
    assert!(guard.target.is_none());
    assert!(guard.cleanup.is_none());
    assert_ne!(guard.lease, old_lease);
    assert!(guard.operator.as_ref() == Some(&a));
}

#[tokio::test]
async fn acknowledged_stale_snapshot_and_clean_tool_error_do_not_poison_session() {
    let (host, authority) = HostCoordinator::new_without_executor(
        OperationLedger::new(uuid::Uuid::new_v4().to_string().try_into().unwrap()),
        facts(CapabilityId::ExecRun),
    )
    .unwrap();
    authority
        .configure_browser(facts(CapabilityId::Browser))
        .unwrap();
    let inputs = host
        .browser_sessions()
        .inputs(Arc::new(UnsupportedBootstrap));
    let engine = Engine {
        port: BrowserPort {
            coordinator: &host,
            authority: &authority,
            inputs: &inputs,
        },
    };
    let a = named_caller("stale-snapshot");
    register_caller(&host, &authority, &a);

    let mut session = engine
        .new_session(
            BROWSER_SESSION_ID.to_owned(),
            CdpSessionScope::SharedExisting,
            Some(a),
            Phase::Unknown,
        )
        .unwrap();
    let target = ResourceTarget {
        operation_id: OperationId {
            host_generation: "stale-snap-gen".try_into().unwrap(),
            owner_epoch: "stale-snapshot-epoch".try_into().unwrap(),
            sequence: 1,
        },
        payload_digest: Sha256Digest::of_bytes(b"open"),
    };
    session.target = Some(target.clone());
    let op_id = OperationId {
        host_generation: "stale-snap-gen".try_into().unwrap(),
        owner_epoch: "stale-snapshot-epoch".try_into().unwrap(),
        sequence: 2,
    };
    let digest = Sha256Digest::of_bytes(b"snapshot");

    let res = engine
        .finish_action(
            BROWSER_SESSION_ID,
            &mut session,
            &op_id,
            digest,
            &target,
            BrowserReply::Action {
                snapshot: Snapshot {
                    operation_id: op_id.clone(),
                    payload_digest: digest,
                    target: Some(target.clone()),
                    state: OperationState::Succeeded,
                    liveness: ExecutionLiveness::Running,
                    output_drain: OutputDrain::Open,
                },
                dispatch: "acknowledged".into(),
                result: Some(json!({
                    "isError": false,
                    "content": [{"type": "text", "text": "- button [ref=unavailable]"}]
                })),
                cause: Some(ErrorCategory::StaleObservation),
                cleanup_complete: None,
            },
        )
        .await;
    assert_ne!(res.is_error, Some(true));
    assert!(
        res.content[0]
            .as_text()
            .unwrap()
            .text
            .contains("[ref=unavailable]")
    );
    assert!(session.phase == Phase::Ready);

    // Clean Playwright MCP tool error (`isError: true`, acknowledged) returns the
    // upstream tool error and keeps session Ready instead of wedging to Phase::Unknown.
    let err_res = engine
        .finish_action(
            BROWSER_SESSION_ID,
            &mut session,
            &op_id,
            digest,
            &target,
            BrowserReply::Action {
                snapshot: Snapshot {
                    operation_id: op_id.clone(),
                    payload_digest: digest,
                    target: Some(target.clone()),
                    state: OperationState::Succeeded,
                    liveness: ExecutionLiveness::Running,
                    output_drain: OutputDrain::Open,
                },
                dispatch: "acknowledged".into(),
                result: Some(json!({
                    "isError": true,
                    "content": [{"type": "text", "text": "Tab 99 not found"}]
                })),
                cause: None,
                cleanup_complete: None,
            },
        )
        .await;
    assert_eq!(err_res.is_error, Some(true));
    assert_eq!(
        err_res.content[0].as_text().unwrap().text,
        "Tab 99 not found"
    );
    assert!(session.phase == Phase::Ready);
}

#[tokio::test]
async fn idle_auto_park_parks_ready_sessions_preserving_operator_and_skips_active_or_busy() {
    struct CountingBootstrap {
        root: PathBuf,
        released: Arc<AtomicUsize>,
        next_profile: AtomicUsize,
    }
    impl operations::BrowserBootstrap for CountingBootstrap {
        fn release_profile(&self, _: &OwnerLease) {
            self.released.fetch_add(1, Ordering::SeqCst);
        }
        fn prepare_profile(
            &self,
            _: &OwnerLease,
            _: CdpSessionScope,
        ) -> Result<OwnedBrowserConfig, ErrorCategory> {
            let n = self.next_profile.fetch_add(1, Ordering::SeqCst);
            let output_dir = self.root.join(format!("output-{n}"));
            std::fs::create_dir(&output_dir).unwrap();
            std::fs::set_permissions(&output_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            let unused = std::fs::canonicalize("/usr/bin/true").unwrap();
            Ok(OwnedBrowserConfig {
                node_binary: unused.clone(),
                worker_entry: unused,
                cdp_endpoint: format!("ws://127.0.0.1:9222/devtools/browser/fixture-{n}"),
                workspace_dir: self.root.join("workspace"),
                output_dir,
                rpc_timeout: Duration::from_nanos(1),
            })
        }
        fn validate_before_spawn(&self) -> Result<(), ErrorCategory> {
            Ok(())
        }
        fn validate_control(&self) -> Result<(), ErrorCategory> {
            Ok(())
        }
    }
    impl Drop for CountingBootstrap {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    let root = std::env::temp_dir().join(format!("styx-browser-park-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let workspace = root.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    std::fs::set_permissions(&workspace, std::fs::Permissions::from_mode(0o700)).unwrap();
    let released = Arc::new(AtomicUsize::new(0));
    let source = Arc::new(CountingBootstrap {
        root,
        released: released.clone(),
        next_profile: AtomicUsize::new(0),
    });
    let (host, authority) = HostCoordinator::new_without_executor(
        OperationLedger::new("browser-idle-park-gen".try_into().unwrap()),
        facts(CapabilityId::ExecRun),
    )
    .unwrap();
    authority
        .configure_browser(facts(CapabilityId::Browser))
        .unwrap();
    let inputs = host.browser_sessions().inputs(source.clone());
    let engine = Engine {
        port: BrowserPort {
            coordinator: &host,
            authority: &authority,
            inputs: &inputs,
        },
    };
    let a = named_caller("park-a");
    let b = named_caller("park-b");
    let gone = named_caller("park-gone");
    register_caller(&host, &authority, &a);
    register_caller(&host, &authority, &b);
    register_caller(&host, &authority, &gone);

    async fn insert_ready_session(
        engine: &Engine<'_>,
        source: &CountingBootstrap,
        id: &str,
        scope: CdpSessionScope,
        operator: Option<OwnerRef>,
        idle_for: Duration,
    ) -> (Cell, OwnerLease) {
        let host = engine.port.coordinator;
        let authority = engine.port.authority;
        let mut session = engine
            .new_session(id.to_owned(), scope.clone(), operator, Phase::Saved)
            .unwrap();
        let lease = session.lease.clone();
        let config = source.prepare_profile(&lease, scope).unwrap();
        authority.register_browser_profile(&lease, config).unwrap();
        let context = PreparedContext {
            device_id: host.bootstrap_identity().0.clone(),
            grant_revision: host.grant_revision(),
            session: None,
            observation: None,
            capability: CapabilityId::Browser,
            deadline: Some(MonotonicMillis(host.now().0 + 5_000)),
            disconnect_policy: DisconnectPolicy::RetainForOwner,
        };
        let open_snap = host.prepare_browser_open(&lease, context).unwrap();
        let target = ResourceTarget {
            operation_id: open_snap.id.clone(),
            payload_digest: open_snap.payload_digest,
        };
        match host
            .dispatch_browser_open(&lease, &target.operation_id, target.payload_digest)
            .await
            .unwrap()
        {
            crate::host::coordinator::BrowserOpenSubmission::Submitted(ticket) => {
                let _ = ticket.wait().await.unwrap();
            }
            _ => panic!("expected submission"),
        }
        session.target = Some(target);
        session.phase = Phase::Ready;
        session.last_activity = std::time::Instant::now() - idle_for;
        let cell = Arc::new(AsyncMutex::new(session));
        engine
            .state()
            .registry
            .lock()
            .unwrap()
            .sessions
            .insert(id.to_owned(), cell.clone());
        (cell, lease)
    }

    let (shared_cell, shared_lease) = insert_ready_session(
        &engine,
        &source,
        BROWSER_SESSION_ID,
        CdpSessionScope::SharedExisting,
        Some(a.clone()),
        Duration::from_secs(300),
    )
    .await;
    let (idle_bg_cell, idle_bg_lease) = insert_ready_session(
        &engine,
        &source,
        "bg-idle",
        CdpSessionScope::TabGroup {
            title: "Styx · 1".into(),
            color: "blue".into(),
            session_key: Some("bg-idle".into()),
        },
        Some(a.clone()),
        Duration::from_secs(300),
    )
    .await;
    let (fresh_bg_cell, _) = insert_ready_session(
        &engine,
        &source,
        "bg-fresh",
        CdpSessionScope::TabGroup {
            title: "Styx · 2".into(),
            color: "cyan".into(),
            session_key: Some("bg-fresh".into()),
        },
        Some(a.clone()),
        Duration::from_secs(10),
    )
    .await;
    let (busy_bg_cell, _) = insert_ready_session(
        &engine,
        &source,
        "bg-busy",
        CdpSessionScope::TabGroup {
            title: "Styx · 3".into(),
            color: "purple".into(),
            session_key: Some("bg-busy".into()),
        },
        Some(a.clone()),
        Duration::from_secs(300),
    )
    .await;
    let (takeover_bg_cell, _) = insert_ready_session(
        &engine,
        &source,
        "bg-takeover",
        CdpSessionScope::TabGroup {
            title: "Styx · 4".into(),
            color: "green".into(),
            session_key: Some("bg-takeover".into()),
        },
        Some(a.clone()),
        Duration::from_secs(300),
    )
    .await;
    let (gone_bg_cell, gone_bg_lease) = insert_ready_session(
        &engine,
        &source,
        "bg-gone",
        CdpSessionScope::TabGroup {
            title: "Styx · 5".into(),
            color: "orange".into(),
            session_key: Some("bg-gone".into()),
        },
        Some(gone.clone()),
        Duration::from_secs(300),
    )
    .await;

    engine
        .state()
        .registry
        .lock()
        .unwrap()
        .owner_default
        .insert(caller(&a), "bg-idle".into());
    host.remote_access()
        .lock()
        .unwrap()
        .owners
        .remove(&caller(&gone));

    // Listing does not park or refresh idle timestamps.
    let listed = engine.handle(b.clone(), BrowserSessionCommand::List).await;
    assert_ne!(listed.is_error, Some(true));
    assert!(shared_cell.lock().await.phase == Phase::Ready);

    // TakeOver refreshes last_activity so the session stays warm past the check.
    let takeover = engine
        .handle(
            b.clone(),
            BrowserSessionCommand::TakeOver {
                session_id: "bg-takeover".into(),
            },
        )
        .await;
    assert_ne!(takeover.is_error, Some(true));

    // Hold a lock on bg-busy to simulate an in-flight action.
    let busy_guard = busy_bg_cell.lock().await;
    let parked = engine.park_idle_sessions(Duration::from_secs(240)).await;
    assert_eq!(parked, 3);
    drop(busy_guard);

    assert_eq!(released.load(Ordering::SeqCst), 3);

    {
        let shared = shared_cell.lock().await;
        assert!(shared.phase == Phase::Saved);
        assert!(shared.target.is_none());
        assert!(shared.cleanup.is_none());
        assert_ne!(shared.lease, shared_lease);
        assert!(shared.operator.as_ref() == Some(&a));
    }
    {
        let idle_bg = idle_bg_cell.lock().await;
        assert!(idle_bg.phase == Phase::Saved);
        assert!(idle_bg.target.is_none());
        assert!(idle_bg.cleanup.is_none());
        assert_ne!(idle_bg.lease, idle_bg_lease);
        assert!(idle_bg.operator.as_ref() == Some(&a));
    }
    {
        let gone_bg = gone_bg_cell.lock().await;
        assert!(gone_bg.phase == Phase::Saved);
        assert!(gone_bg.target.is_none());
        assert_ne!(gone_bg.lease, gone_bg_lease);
        assert!(gone_bg.operator.is_none());
    }
    assert!(fresh_bg_cell.lock().await.phase == Phase::Ready);
    assert!(takeover_bg_cell.lock().await.phase == Phase::Ready);
    assert!(busy_bg_cell.lock().await.phase == Phase::Ready);

    let registry = engine.state().registry.lock().unwrap();
    assert!(registry.sessions.contains_key("bg-idle"));
    assert_eq!(
        registry.owner_default.get(&caller(&a)).map(String::as_str),
        Some("bg-idle")
    );
}
