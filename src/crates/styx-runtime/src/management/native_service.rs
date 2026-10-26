//! Explicit native Linux user-service management. Canonical desired state is
//! committed by the original Core journal; OS observations never mint that state.
use super::*;
use crate::platform::linux::native_service::{Definition, ServiceRole};
use styx_contracts::native_management::{NativeAutostartDesired, NativeStateTransaction};
use tokio::sync::{Semaphore, oneshot};
static OPERATIONS: Semaphore = Semaphore::const_new(1);
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ServiceAction {
    Install,
    Status,
    Enable,
    Disable,
    Start,
    Stop,
    Uninstall,
}
impl ServiceAction {
    fn name(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Status => "status",
            Self::Enable => "enable",
            Self::Disable => "disable",
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Uninstall => "uninstall",
        }
    }
}
#[derive(Serialize)]
pub struct ServiceReport {
    pub schema: u16,
    pub operation: &'static str,
    pub configuration_only: bool,
    pub transaction_id: Option<TransactionId>,
    pub revision: u64,
    pub desired: NativeDesired,
    pub os: serde_json::Value,
    pub operations_replayed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_observation: Option<serde_json::Value>,
}
fn role(component: NativeComponent) -> ServiceRole {
    match component {
        NativeComponent::Host => ServiceRole::Host,
        NativeComponent::Gateway => ServiceRole::Gateway,
    }
}
fn os(error: crate::platform::linux::native_service::ServiceError) -> NativeManagementError {
    use crate::platform::linux::manager::ManagerError;
    NativeManagementError::new(match error {
        ManagerError::Invalid => ErrorKind::Invalid,
        ManagerError::Conflict => ErrorKind::Conflict,
        ManagerError::Busy => ErrorKind::Busy,
        ManagerError::Unavailable => ErrorKind::Unavailable,
        ManagerError::Unknown => ErrorKind::Unknown,
    })
}
/// No mutation retry. A lost caller detaches the ONE owned operation. Unknown
/// retains its original scope/utility custody and budget until process teardown.
pub async fn manage(
    state_dir: &Path,
    action: ServiceAction,
    component: NativeComponent,
    transaction_id: Option<TransactionId>,
    expected_revision: Option<u64>,
) -> Result<ServiceReport> {
    if action == ServiceAction::Status {
        if expected_revision.is_some() {
            return Err(NativeManagementError::new(ErrorKind::Invalid));
        }
    } else if transaction_id.is_none() || expected_revision.is_none() {
        return Err(NativeManagementError::new(ErrorKind::Invalid));
    }
    let permit = OPERATIONS
        .try_acquire()
        .map_err(|_| NativeManagementError::new(ErrorKind::Busy))?;
    let path = state_dir.to_owned();
    let (send, receive) = oneshot::channel();
    let job = tokio::spawn(async move {
        let _permit = permit;
        let mut definition = None;
        let mut retained_transactions = None;
        let mut effects_started = false;
        let mut execution_lease = None;
        let mut operation_lease = None;
        let result = async {
            if action != ServiceAction::Status {
                let lease_path = path.clone();
                operation_lease = Some(
                    tokio::task::spawn_blocking(move || {
                        crate::store::PrivateRoot::open(lease_path)
                            .and_then(|root| root.try_service_operation_lease())
                    })
                    .await
                    .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?
                    .map_err(|e| {
                        NativeManagementError::new(match e {
                            crate::store::StoreError::Busy(_) => ErrorKind::Busy,
                            _ => ErrorKind::Unavailable,
                        })
                    })?,
                );
            }
            let path_read = path.clone();
            let service_role = role(component);
            // Only install may create the fixed user-unit directory. Status and
            // every other operation preserve missing/private-root failures.
            let prepared = tokio::task::spawn_blocking(move || {
                Definition::prepare(&path_read, service_role, action == ServiceAction::Install)
            })
            .await
            .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?
            .map_err(os)?;
            definition = Some(prepared);
            let current = definition
                .as_ref()
                .expect("prepared definition")
                .state()
                .map_err(os)?;
            let before = definition
                .as_ref()
                .expect("prepared definition")
                .inspect()
                .await
                .map_err(os)?;
            if action == ServiceAction::Status {
                let transaction_observation = if let Some(id) = transaction_id.as_ref() {
                    let gateway_path = path.clone();
                    let live_gateway = if current
                        .desired
                        .gateway
                        .is_some_and(|d| d.manager == NativeManager::PersistentService)
                    {
                        let gateway = tokio::task::spawn_blocking(move || {
                            Definition::prepare(&gateway_path, ServiceRole::Gateway, false)
                        })
                        .await
                        .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?
                        .map_err(os)?;
                        gateway.inspect().await.map_err(os)?.main_pid != 0
                    } else {
                        false
                    };
                    let observation = if live_gateway {
                        match crate::management::service_control::query(&path, id.clone()).await {
                            Ok(report) => serde_json::to_value(report),
                            Err(error) => Ok(serde_json::json!({
                                "transaction_id": id,
                                "status": "unknown",
                                "error": error.code(),
                                "operations_replayed": false,
                            })),
                        }
                    } else {
                        // Offline inspection uses the existing original-journal reader.
                        // It does not reconcile, replay, or start a service.
                        serde_json::to_value(super::inspect(&path, Some(id.as_str())).await?)
                    }
                    .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
                    Some(observation)
                } else {
                    None
                };
                let current = definition
                    .as_ref()
                    .expect("prepared definition")
                    .state()
                    .map_err(os)?;
                return Ok(ServiceReport {
                    schema: 1,
                    operation: action.name(),
                    configuration_only: false,
                    transaction_id,
                    revision: current.revision,
                    desired: current.desired,
                    os: serde_json::to_value(before)
                        .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?,
                    operations_replayed: false,
                    transaction_observation,
                });
            }
            let id = transaction_id
                .clone()
                .ok_or_else(|| NativeManagementError::new(ErrorKind::Invalid))?;
            let expected =
                expected_revision.ok_or_else(|| NativeManagementError::new(ErrorKind::Invalid))?;
            if current.revision != expected {
                return Err(NativeManagementError::new(ErrorKind::Conflict));
            }
            let original = service_role
                .desired(&current)
                .ok_or_else(|| NativeManagementError::new(ErrorKind::Invalid))?;
            if original.manager == NativeManager::AppManaged {
                return Err(NativeManagementError::new(ErrorKind::Conflict));
            }
            if action == ServiceAction::Install {
                if original.run != NativeRunDesired::Stopped || before.installed {
                    return Err(NativeManagementError::new(ErrorKind::Conflict));
                }
            } else if original.manager != NativeManager::PersistentService || !before.installed {
                return Err(NativeManagementError::new(ErrorKind::Conflict));
            }
            if action == ServiceAction::Start
                && (original.run != NativeRunDesired::Stopped || before.active != "inactive")
            {
                return Err(NativeManagementError::new(ErrorKind::Conflict));
            }
            if action == ServiceAction::Uninstall
                && (original.run != NativeRunDesired::Stopped
                    || before.active != "inactive"
                    || before.enabled != Some(false))
            {
                return Err(NativeManagementError::new(ErrorKind::Conflict));
            }
            if matches!(
                action,
                ServiceAction::Install | ServiceAction::Uninstall | ServiceAction::Start
            ) {
                let lease_path = path.clone();
                let lease_state = current.clone();
                execution_lease = Some(
                    tokio::task::spawn_blocking(move || {
                        inactive_execution_lease(&lease_path, service_role, &lease_state)
                    })
                    .await
                    .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))??,
                );
            }
            if action == ServiceAction::Stop {
                definition
                    .as_mut()
                    .expect("original definition")
                    .prepare_stop()
                    .await
                    .map_err(os)?;
            }
            operation_lease
                .as_ref()
                .expect("mutating service lease")
                .validate()
                .map_err(|_| NativeManagementError::new(ErrorKind::Conflict))?;
            let mut used_live_writer = false;
            let mut gateway_stop_requested = false;
            // The Gateway retains the actual single writer. It must commit live
            // autostart through that owner; this caller must not open another.
            if matches!(
                action,
                ServiceAction::Enable
                    | ServiceAction::Disable
                    | ServiceAction::Stop
                    | ServiceAction::Start
            ) && current.desired.gateway.is_some()
            {
                let gateway_path = path.clone();
                let gateway = tokio::task::spawn_blocking(move || {
                    Definition::prepare(&gateway_path, ServiceRole::Gateway, false)
                })
                .await
                .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?
                .map_err(os)?;
                let gateway_status = gateway.inspect().await.map_err(os)?;
                if gateway_status.main_pid != 0 {
                    if current
                        .desired
                        .gateway
                        .is_none_or(|d| d.manager != NativeManager::PersistentService)
                    {
                        return Err(NativeManagementError::new(ErrorKind::Conflict));
                    }
                    effects_started = true;
                    if matches!(action, ServiceAction::Stop | ServiceAction::Start) {
                        crate::management::service_control::set_run(
                            &path,
                            component,
                            if action == ServiceAction::Stop {
                                NativeRunDesired::Stopped
                            } else {
                                NativeRunDesired::Running
                            },
                            expected,
                            id.clone(),
                        )
                        .await
                        .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
                        gateway_stop_requested = action == ServiceAction::Stop
                            && matches!(component, NativeComponent::Gateway);
                    } else {
                        crate::management::service_control::set_autostart(
                            &path,
                            component,
                            action == ServiceAction::Enable,
                            expected,
                            id.clone(),
                        )
                        .await
                        .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
                    }
                    used_live_writer = true;
                }
            }
            if !used_live_writer {
                let opened_path = path.clone();
                let opened =
                    tokio::task::spawn_blocking(move || platform::service_open(&opened_path))
                        .await
                        .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))??;
                retained_transactions = Some(opened);
                let transactions = retained_transactions.as_mut().expect("original writer");
                let validated = transactions
                    .readstate()
                    .map_err(NativeManagementError::transaction)?;
                let mut target = validated.state().clone();
                if target.revision != expected {
                    return Err(NativeManagementError::new(ErrorKind::Conflict));
                }
                let desired = match component {
                    NativeComponent::Host => target.desired.host.as_mut(),
                    NativeComponent::Gateway => target.desired.gateway.as_mut(),
                }
                .ok_or_else(|| NativeManagementError::new(ErrorKind::Invalid))?;
                if desired.manager == NativeManager::AppManaged {
                    return Err(NativeManagementError::new(ErrorKind::Conflict));
                }
                match action {
                    ServiceAction::Install => {
                        desired.manager = NativeManager::PersistentService;
                        desired.run = NativeRunDesired::Stopped;
                        desired.autostart = NativeAutostartDesired::Disabled;
                    }
                    ServiceAction::Enable => desired.autostart = NativeAutostartDesired::Enabled,
                    ServiceAction::Disable => desired.autostart = NativeAutostartDesired::Disabled,
                    ServiceAction::Start => desired.run = NativeRunDesired::Running,
                    ServiceAction::Stop => desired.run = NativeRunDesired::Stopped,
                    ServiceAction::Uninstall => {
                        desired.manager = NativeManager::ForegroundCli;
                        desired.autostart = NativeAutostartDesired::Disabled;
                    }
                    ServiceAction::Status => unreachable!(),
                }
                let sequence = target
                    .last_transaction
                    .as_ref()
                    .map(|t| t.sequence)
                    .unwrap_or(0)
                    .checked_add(1)
                    .ok_or_else(|| NativeManagementError::new(ErrorKind::Invalid))?;
                target.revision = target
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| NativeManagementError::new(ErrorKind::Invalid))?;
                target.last_transaction = Some(NativeStateTransaction {
                    transaction_id: id.clone(),
                    sequence,
                });
                let raw = serde_json::to_vec(&target)
                    .map_err(|_| NativeManagementError::new(ErrorKind::Invalid))?;
                transactions
                    .validate_target(&raw)
                    .map_err(NativeManagementError::transaction)?;
                effects_started = true;
                transactions
                    .apply_target(&raw)
                    .map_err(NativeManagementError::transaction)?;
            }
            if action == ServiceAction::Start {
                // The new service must acquire the original configuration writer
                // itself. Release only after the exact Running tx is committed.
                drop(retained_transactions.take());
                drop(execution_lease.take());
            }
            operation_lease
                .as_ref()
                .expect("mutating service lease")
                .validate()
                .map_err(|_| NativeManagementError::new(ErrorKind::Conflict))?;
            let definition = definition.as_mut().expect("original definition");
            let observed = match action {
                ServiceAction::Install => definition.install().await,
                ServiceAction::Enable => definition.set_enabled(true).await,
                ServiceAction::Disable => definition.set_enabled(false).await,
                ServiceAction::Start => definition.start().await,
                ServiceAction::Stop => definition.stop(!gateway_stop_requested).await,
                ServiceAction::Uninstall => definition.uninstall().await,
                ServiceAction::Status => unreachable!(),
            }
            .map_err(os)?;
            let final_state = definition.state().map_err(os)?;
            if final_state
                .last_transaction
                .as_ref()
                .is_none_or(|t| t.transaction_id != id)
            {
                return Err(NativeManagementError::new(ErrorKind::Conflict));
            }
            Ok(ServiceReport {
                schema: 1,
                operation: action.name(),
                configuration_only: false,
                transaction_id: Some(id),
                revision: final_state.revision,
                desired: final_state.desired,
                os: serde_json::to_value(observed)
                    .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?,
                operations_replayed: false,
                transaction_observation: None,
            })
        }
        .await;
        match result {
            Ok(report) => {
                drop(retained_transactions);
                drop(definition);
                let _ = send.send(Ok(report));
            }
            Err(error) if effects_started => {
                let _ = send.send(Err((error.kind, true)));
                // Unknown has no implicit retry/rollback. Keep the actual original
                // roots, writer, utility context and budget even on waiter loss.
                std::future::pending::<()>().await;
                drop((
                    error,
                    retained_transactions,
                    definition,
                    execution_lease,
                    operation_lease,
                ));
            }
            Err(error) => {
                let kind = error.kind;
                drop(error);
                drop(retained_transactions);
                drop(definition);
                let _ = send.send(Err((kind, false)));
            }
        }
    });
    match receive.await {
        Ok(Ok(report)) => {
            job.await
                .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
            Ok(report)
        }
        Ok(Err((kind, true))) => {
            let mut error = NativeManagementError::new(kind);
            error._retained = Some(Retained::Service { _job: job });
            Err(error)
        }
        Ok(Err((kind, false))) => {
            job.await
                .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
            Err(NativeManagementError::new(kind))
        }
        Err(_) => {
            let mut error = NativeManagementError::new(ErrorKind::Unknown);
            error._retained = Some(Retained::Service { _job: job });
            Err(error)
        }
    }
}

fn inactive_execution_lease(
    path: &Path,
    role: ServiceRole,
    state: &NativeState,
) -> Result<crate::store::ExecutionLeaseGuard> {
    let root = crate::store::PrivateRoot::open(path)
        .map_err(|_| NativeManagementError::new(ErrorKind::Unavailable))?;
    let execution_path = if state.has_migration_binding() {
        match role {
            ServiceRole::Gateway => path.join("gateway"),
            ServiceRole::Host => {
                let raw = root
                    .read_raw("deployment.json", 1024 * 1024)
                    .map_err(|_| NativeManagementError::new(ErrorKind::Unavailable))?;
                if Sha256Digest::of_bytes(raw.bytes()) != state.deployment_raw_sha256 {
                    return Err(NativeManagementError::new(ErrorKind::Conflict));
                }
                #[derive(serde::Deserialize)]
                struct Deployment {
                    host: Host,
                }
                #[derive(serde::Deserialize)]
                struct Host {
                    #[serde(rename = "baseDir")]
                    base_dir: PathBuf,
                }
                serde_json::from_slice::<Deployment>(raw.bytes())
                    .map_err(|_| NativeManagementError::new(ErrorKind::Invalid))?
                    .host
                    .base_dir
            }
        }
    } else {
        path.to_owned()
    };
    let execution = crate::store::PrivateRoot::open(execution_path)
        .map_err(|_| NativeManagementError::new(ErrorKind::Unavailable))?;
    execution
        .try_execution_lease()
        .map_err(|_| NativeManagementError::new(ErrorKind::Busy))
}
/// Fixed background entry. Calling it from a shell or forging systemd-like
/// environment variables fails actual unit/MainPID/birth authentication.
pub async fn run(
    state_dir: &Path,
    component: NativeComponent,
    cancel: tokio_util::sync::CancellationToken,
    events: tokio::sync::mpsc::Sender<crate::foreground::ForegroundEvent>,
) -> Result<serde_json::Value> {
    let scope = crate::platform::linux::native_service::ServiceScope::authenticate(
        state_dir,
        role(component),
    )
    .await
    .map_err(os)?;
    match component {
        NativeComponent::Host => {
            let outcome = crate::foreground::host_run_for_service(scope, cancel, events)
                .await
                .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
            if !outcome.is_complete() {
                return Err(NativeManagementError::new(ErrorKind::Unknown));
            }
            serde_json::to_value(outcome)
                .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))
        }
        NativeComponent::Gateway => {
            let outcome = crate::foreground::gateway_run_for_service(scope, cancel, events)
                .await
                .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
            if !outcome.is_complete() {
                return Err(NativeManagementError::new(ErrorKind::Unknown));
            }
            serde_json::to_value(outcome)
                .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))
        }
    }
}
