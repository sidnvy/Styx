//! Direct production adapter regression using an already-owned native Browser.
//! Owner registry installation is test-only trusted setup, not network auth.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

struct FailingBootstrap(AtomicUsize);
impl BrowserBootstrap for FailingBootstrap {
    fn prepare_profile(&self, _: &OwnerLease) -> Result<OwnedBrowserConfig, ErrorCategory> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(ErrorCategory::IntegrityFailure)
    }
    fn validate_before_spawn(&self) -> Result<(), ErrorCategory> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(ErrorCategory::IntegrityFailure)
    }
    fn validate_control(&self) -> Result<(), ErrorCategory> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(ErrorCategory::IntegrityFailure)
    }
}
fn same_snapshot(actual: &Snapshot, expected: &OperationSnapshot) {
    assert_eq!(actual.operation_id, expected.id);
    assert_eq!(actual.payload_digest, expected.payload_digest);
    assert_eq!(actual.target, expected.target);
    assert_eq!(actual.state, expected.state);
    assert_eq!(actual.liveness, expected.liveness);
    assert_eq!(actual.output_drain, expected.output_drain);
}
pub(crate) async fn verify_original_dispatch_history(
    host: &HostCoordinator,
    authority: &HostAuthority,
    owner: &OwnerLease,
    opened: &OperationSnapshot,
    action: &OperationSnapshot,
) {
    assert_eq!(opened.state, OperationState::Running);
    assert_eq!(action.state, OperationState::Unknown);
    let (device, generation) = host.bootstrap_identity();
    let source = Arc::new(FailingBootstrap(AtomicUsize::new(0)));
    let protocol = HostProtocol::new_paired(
        PairedTrustedProfile {
            endpoint: "wss://localhost/styx/host/v3/history-fixture/exec".into(),
            gateway_namespace: "history-regression".try_into().unwrap(),
            device_id: device.clone(),
            host_generation: generation.clone(),
        },
        host.clone(),
        authority,
    )
    .unwrap()
    .with_browser_profiles(source.clone())
    .unwrap();
    let reference = OwnerRef {
        owner_id: owner.owner_id().clone(),
        owner_epoch: action.id.owner_epoch.clone(),
    };
    protocol.owners.lock().unwrap().owners.insert(
        (reference.owner_id.clone(), reference.owner_epoch.clone()),
        OwnerRecord {
            lease: Some(owner.clone()),
            revision: host.grant_revision(),
            cleanup: None,
        },
    );
    let reply = protocol
        .handle_browser(
            reference.clone(),
            host.grant_revision(),
            1_000,
            BrowserCommand::DispatchOpen {
                target: ResourceTarget {
                    operation_id: opened.id.clone(),
                    payload_digest: opened.payload_digest,
                },
            },
        )
        .await;
    match reply {
        Reply::Start { snapshot, dispatch } => {
            assert_eq!(dispatch, "existing_no_replay");
            same_snapshot(&snapshot, opened);
        }
        _ => panic!("original Running open must remain existing history"),
    }
    let reply = protocol
        .handle_browser(
            reference,
            host.grant_revision(),
            1_000,
            BrowserCommand::DispatchAction {
                action: ActionRef {
                    operation_id: action.id.clone(),
                    payload_digest: action.payload_digest,
                },
            },
        )
        .await;
    match reply {
        Reply::BrowserAction {
            snapshot,
            dispatch,
            result,
            cause,
            cleanup_complete,
        } => {
            assert_eq!(dispatch, "existing_no_replay");
            same_snapshot(&snapshot, action);
            assert!(result.is_none());
            assert!(cause.is_none());
            assert!(cleanup_complete.is_none());
        }
        _ => panic!("original Unknown action must remain existing history"),
    }
    protocol.drain_browser_inputs().await;
    assert_eq!(source.0.load(Ordering::SeqCst), 0);
}
