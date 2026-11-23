use super::operations::BrowserBootstrap;
use super::*;
use crate::host::coordinator::HostCoordinator;
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
    fn saved_profiles(&self) -> Result<Vec<String>, styx_contracts::error::ErrorCategory> {
        Ok(Vec::new())
    }

    fn release_profile(&self, _: &OwnerLease) {}
    fn prepare_profile(&self, _: &OwnerLease) -> Result<OwnedBrowserConfig, ErrorCategory> {
        if self.prepared.fetch_add(1, Ordering::SeqCst) != 0 {
            return Err(ErrorCategory::CapabilityUnsupported);
        }
        let unused = std::fs::canonicalize("/usr/bin/true").unwrap();
        Ok(OwnedBrowserConfig {
            node_binary: unused.clone(),
            worker_entry: unused.clone(),
            browser_binary: unused,
            workspace_dir: self.root.join("workspace"),
            profile_dir: self.root.join("profile"),
            output_dir: self.root.join("output"),
            // Expire the actual read-only preflight before it starts a command.
            // No browser is started; its registered empty resource is cleaned normally.
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
    for name in ["workspace", "profile", "output"] {
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
    let cell = engine.state().registry.lock().unwrap().sessions[&id].clone();
    {
        let session = cell.lock().await;
        assert!(session.phase == Phase::New);
        assert!(session.target.is_none());
    }
    // The first public refusal already released the registered, never-spawned resource.
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

    // Only this explicit new public request re-enters preparation. Its chosen
    // bootstrap refusal keeps the test independent of any installed browser.
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

struct SavedBootstrap(Vec<String>);
impl operations::BrowserBootstrap for SavedBootstrap {
    fn saved_profiles(&self) -> Result<Vec<String>, ErrorCategory> {
        Ok(self.0.clone())
    }
    fn release_profile(&self, _: &OwnerLease) {}
    fn prepare_profile(&self, _: &OwnerLease) -> Result<OwnedBrowserConfig, ErrorCategory> {
        Err(ErrorCategory::CapabilityUnsupported)
    }
    fn validate_before_spawn(&self) -> Result<(), ErrorCategory> {
        Ok(())
    }
    fn validate_control(&self) -> Result<(), ErrorCategory> {
        Ok(())
    }
}

fn saved_host(
    ids: Vec<String>,
) -> (
    HostCoordinator,
    crate::host::coordinator::HostAuthority,
    Arc<operations::BrowserInputs>,
) {
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
        .inputs(Arc::new(SavedBootstrap(ids)));
    (host, authority, inputs)
}

fn named_caller(name: &str) -> OwnerRef {
    OwnerRef {
        owner_id: name.try_into().unwrap(),
        owner_epoch: format!("{name}-epoch").try_into().unwrap(),
    }
}

#[tokio::test]
async fn saved_profile_resumes_without_restoring_caller_access_or_execution() {
    let id = uuid::Uuid::new_v4().simple().to_string();
    let (host, authority, inputs) = saved_host(vec![id.clone()]);
    let engine = Engine {
        port: BrowserPort {
            coordinator: &host,
            authority: &authority,
            inputs: &inputs,
        },
    };
    let a = named_caller("a");
    let b = named_caller("b");
    register_caller(&host, &authority, &a);
    register_caller(&host, &authority, &b);
    let listed = engine.handle(a.clone(), BrowserSessionCommand::List).await;
    let saved = &listed.structured_content.as_ref().unwrap()["sessions"][0];
    assert_eq!(saved["browser_session_id"], id);
    assert_eq!(saved["status"], "saved");
    assert_eq!(saved["current_operator"], false);
    assert_eq!(saved["available"], true);
    let old_lease = engine
        .resolve(&a, None, true)
        .unwrap()
        .1
        .lock()
        .await
        .lease
        .clone();
    let (parallel_id, _) = engine.resolve(&b, None, true).unwrap();
    assert_ne!(
        parallel_id, id,
        "claim is atomic before the first action obtains its session lock"
    );
    let transfer = engine
        .handle(
            a.clone(),
            BrowserSessionCommand::TakeOver {
                session_id: id.clone(),
            },
        )
        .await;
    assert_ne!(transfer.is_error, Some(true));
    assert_eq!(
        transfer.structured_content.as_ref().unwrap()["status"],
        "saved"
    );

    // A different conversation cannot use a selected active profile implicitly.
    assert_eq!(
        error(&engine.handle(b.clone(), tabs(Some(id.clone()))).await)["error"],
        "browser_session_transferred"
    );
    let (independent, _) = engine.resolve(&b, None, true).unwrap();
    assert_ne!(
        independent, id,
        "parallel independent Browser sessions remain available"
    );

    // Explicit conversation cleanup makes the existing profile available again.
    let (_, busy_cell) = engine.resolve(&a, Some(id.clone()), false).unwrap();
    let in_flight = busy_cell.lock().await;
    host.remote_access()
        .lock()
        .unwrap()
        .owners
        .remove(&caller(&a));
    host.browser_sessions().forget_caller(&a);
    drop(in_flight);
    let c = named_caller("c");
    register_caller(&host, &authority, &c);
    let listed = engine.handle(c.clone(), BrowserSessionCommand::List).await;
    let released = listed.structured_content.as_ref().unwrap()["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["browser_session_id"] == id)
        .unwrap();
    assert_eq!(
        released["available"], true,
        "in-flight caller cleanup is observed after its action ends"
    );
    assert_eq!(engine.resolve(&c, None, true).unwrap().0, id);
    let resumed = engine
        .handle(
            c.clone(),
            BrowserSessionCommand::TakeOver {
                session_id: id.clone(),
            },
        )
        .await;
    assert_eq!(
        resumed.structured_content.as_ref().unwrap()["current_operator"],
        true
    );

    let closed = engine
        .handle(
            c,
            BrowserSessionCommand::Action {
                session_id: Some(id.clone()),
                name: "browser_close".into(),
                arguments: Default::default(),
            },
        )
        .await;
    assert_eq!(
        closed.structured_content.as_ref().unwrap()["profile_preserved"],
        true
    );
    assert!(
        engine
            .state()
            .registry
            .lock()
            .unwrap()
            .sessions
            .contains_key(&id)
    );

    let listed = engine.handle(b.clone(), BrowserSessionCommand::List).await;
    let retained = listed.structured_content.as_ref().unwrap()["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["browser_session_id"] == id)
        .unwrap();
    assert_eq!(
        retained["available"], true,
        "closing a saved profile releases its operator"
    );

    // A new Host discovers only the stable profile ID. It has no old operator,
    // old action, resource, cleanup handle, or restored lease.
    let (next_host, next_authority, next_inputs) = saved_host(vec![id.clone()]);
    let next = Engine {
        port: BrowserPort {
            coordinator: &next_host,
            authority: &next_authority,
            inputs: &next_inputs,
        },
    };
    register_caller(&next_host, &next_authority, &b);
    let listed = next.handle(b.clone(), BrowserSessionCommand::List).await;
    assert_eq!(
        listed.structured_content.as_ref().unwrap()["sessions"][0]["current_operator"],
        false
    );
    let (selected, cell) = next.resolve(&b, None, true).unwrap();
    assert_eq!(selected, id);
    let session = cell.lock().await;
    assert!(session.operator.as_ref() == Some(&b));
    assert!(session.target.is_none());
    assert!(session.cleanup.is_none());
    assert!(session.phase == Phase::Saved);
    assert_ne!(session.lease, old_lease);
}

#[tokio::test]
async fn several_saved_profiles_require_selection_instead_of_an_empty_replacement() {
    let ids = vec![
        uuid::Uuid::new_v4().simple().to_string(),
        uuid::Uuid::new_v4().simple().to_string(),
    ];
    let (host, authority, inputs) = saved_host(ids.clone());
    let engine = Engine {
        port: BrowserPort {
            coordinator: &host,
            authority: &authority,
            inputs: &inputs,
        },
    };
    let a = named_caller("a");
    register_caller(&host, &authority, &a);
    let result = engine.handle(a.clone(), tabs(None)).await;
    assert_eq!(
        error(&result)["error"],
        "browser_session_selection_required"
    );
    assert_eq!(engine.state().registry.lock().unwrap().sessions.len(), 2);
    let selected = engine
        .handle(
            a,
            BrowserSessionCommand::TakeOver {
                session_id: ids[1].clone(),
            },
        )
        .await;
    assert_eq!(
        selected.structured_content.as_ref().unwrap()["browser_session_id"],
        ids[1]
    );
}

struct PausedProfiles {
    id: String,
    started: tokio::sync::Notify,
    resume: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
}
impl operations::BrowserBootstrap for PausedProfiles {
    fn saved_profiles(&self) -> Result<Vec<String>, ErrorCategory> {
        self.started.notify_one();
        self.resume
            .lock()
            .unwrap()
            .take()
            .unwrap()
            .blocking_recv()
            .unwrap();
        Ok(vec![self.id.clone()])
    }
    fn release_profile(&self, _: &OwnerLease) {}
    fn prepare_profile(&self, _: &OwnerLease) -> Result<OwnedBrowserConfig, ErrorCategory> {
        panic!("a caller closed during discovery must not launch Browser")
    }
    fn validate_before_spawn(&self) -> Result<(), ErrorCategory> {
        Ok(())
    }
    fn validate_control(&self) -> Result<(), ErrorCategory> {
        Ok(())
    }
}

#[tokio::test]
async fn caller_closed_during_profile_discovery_cannot_reclaim_a_saved_profile() {
    let id = uuid::Uuid::new_v4().simple().to_string();
    let (host, authority) = HostCoordinator::new_without_executor(
        OperationLedger::new(uuid::Uuid::new_v4().to_string().try_into().unwrap()),
        facts(CapabilityId::ExecRun),
    )
    .unwrap();
    authority
        .configure_browser(facts(CapabilityId::Browser))
        .unwrap();
    let (resume, resumed) = tokio::sync::oneshot::channel();
    let source = Arc::new(PausedProfiles {
        id: id.clone(),
        started: tokio::sync::Notify::new(),
        resume: Mutex::new(Some(resumed)),
    });
    let inputs = host.browser_sessions().inputs(source.clone());
    let engine = Engine {
        port: BrowserPort {
            coordinator: &host,
            authority: &authority,
            inputs: &inputs,
        },
    };
    let a = named_caller("closed-during-discovery");
    register_caller(&host, &authority, &a);
    let request = engine.handle(a.clone(), tabs(None));
    tokio::pin!(request);
    tokio::select! {
        _ = source.started.notified() => {},
        result = &mut request => panic!("discovery unexpectedly completed: {result:?}"),
    }
    host.remote_access()
        .lock()
        .unwrap()
        .owners
        .remove(&caller(&a));
    host.browser_sessions().forget_caller(&a);
    resume.send(()).unwrap();
    assert_eq!(error(&request.await)["error"], "unauthorized");
    assert!(
        !engine
            .state()
            .registry
            .lock()
            .unwrap()
            .defaults
            .contains_key(&caller(&a))
    );
    let b = named_caller("next-conversation");
    register_caller(&host, &authority, &b);
    let listed = engine.handle(b.clone(), BrowserSessionCommand::List).await;
    assert_eq!(
        listed.structured_content.as_ref().unwrap()["sessions"][0]["available"],
        true
    );
    assert_eq!(engine.resolve(&b, None, true).unwrap().0, id);
}

#[tokio::test]
async fn closed_or_exited_browser_context_recovers_to_saved_profile_on_next_request() {
    let root = std::env::temp_dir().join(format!("styx-browser-recover-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    for name in ["workspace", "profile", "output"] {
        let dir = root.join(name);
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let id = uuid::Uuid::new_v4().simple().to_string();
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

    let (resolved_id, cell) = engine.resolve(&a, None, true).unwrap();
    assert_ne!(resolved_id, id);

    // Prepare an open operation on the session's lease, then simulate an open
    // resource whose worker has exited before the next action is dispatched.
    let old_lease = {
        let mut session = cell.lock().await;
        let lease = session.lease.clone();
        let config = source.prepare_profile(&lease).unwrap();
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
        // The fixture refuses browser startup without launching a browser.
        // Then simulate the provider's explicit context-closed observation,
        // so the session recovery path can be exercised independently of GUI.
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

    let outcome = engine
        .handle(a.clone(), tabs(Some(resolved_id.clone())))
        .await;
    assert_eq!(error(&outcome)["error"], "capability_unsupported");
    assert_eq!(error(&outcome)["uncertain"], false);

    let session = cell.lock().await;
    assert!(session.operator.as_ref() == Some(&a));
    assert!(session.target.is_none());
    assert!(session.cleanup.is_none());
    assert_ne!(session.lease, old_lease);
}
