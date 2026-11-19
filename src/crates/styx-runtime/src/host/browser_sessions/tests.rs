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
        std::fs::read_dir(source.root.join("output")).unwrap().count(),
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
