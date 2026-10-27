//! Existing-UID launchd intent preparation, authenticated service entry, and
//! single-role preparation and Stop through the original C07 writer.
//! Preparation changes C07 only;
//! administrator registration is performed by the separately reviewed package.
use super::*;
use crate::platform::macos_service::{
    Definition, ServiceError, ServiceRole, ServiceScope, blocking_read, report_failure,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ServiceAction {
    Definition,
    Status,
    Stop,
    Start,
    Enable,
    Disable,
    /// Prepare removal of only the OS registration. The original C07 remains
    /// PersistentService/Stopped/Disabled; this is not a manager transfer.
    Uninstall,
    PrepareInstall,
    PrepareFirstStart,
    /// Commit Stopped/Disabled intent for a proven failed inactive registration.
    /// This neither stops an OS job nor claims that it is repaired.
    PrepareRecovery,
    /// Uses prepare_runtime_repair with an explicit signed selection input.
    PrepareRuntimeRepair,
    /// Recover only the original journal-bound runtime repair.
    RecoverRuntimeRepair,
}
#[derive(Serialize)]
pub struct ServiceReport {
    pub schema: u16,
    pub operation: &'static str,
    pub configuration_only: bool,
    pub revision: u64,
    pub desired: NativeDesired,
    pub definition_path: PathBuf,
    pub definition_plist: String,
    pub uid: u32,
    pub label: String,
    pub requires_initial_disabled: bool,
    pub runtime_selection: NativeRuntimeSelection,
    pub os: Option<serde_json::Value>,
    pub operations_replayed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_observation: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installation_request_v1: Option<serde_json::Value>,
}
fn role(component: NativeComponent) -> ServiceRole {
    match component {
        NativeComponent::Host => ServiceRole::Host,
        NativeComponent::Gateway => ServiceRole::Gateway,
    }
}
fn os(error: ServiceError) -> NativeManagementError {
    NativeManagementError::new(match error {
        ServiceError::Invalid => ErrorKind::Invalid,
        ServiceError::Conflict => ErrorKind::Conflict,
        ServiceError::Unavailable => ErrorKind::Unavailable,
        ServiceError::Busy => ErrorKind::Busy,
        ServiceError::Unknown => ErrorKind::Unknown,
    })
}
// Owned report DATA only; borrowed protected installation material never
// escapes the original blocking read.
struct ReportMaterial {
    path: PathBuf,
    plist: String,
    uid: u32,
    label: String,
    requires_initial_disabled: bool,
    selection: NativeRuntimeSelection,
}
async fn read_report_material(definition: Arc<Definition>) -> Result<ReportMaterial> {
    blocking_read(move || {
        let material = definition.installation_material()?;
        Ok(ReportMaterial {
            path: material.path,
            plist: std::str::from_utf8(material.bytes)
                .map_err(|_| ServiceError::Unknown)?
                .to_owned(),
            uid: material.uid,
            label: material.label.to_owned(),
            requires_initial_disabled: material.requires_initial_disabled,
            selection: definition.runtime_selection()?.clone(),
        })
    })
    .await
    .map_err(os)
}
async fn validate_operation(lease: Arc<crate::store::ServiceOperationGuard>) -> Result<()> {
    blocking_read(move || lease.validate().map_err(|_| ServiceError::Conflict))
        .await
        .map_err(os)
}

/// Definition/Status remain readonly. Stop delegates exactly once to the
/// original running Gateway's writer or the fresh Host-only original C07;
/// no action invokes mutating launchctl.
/// Missing/unknown registration is never reported as inactive.
pub async fn manage(
    state_dir: &Path,
    action: ServiceAction,
    component: NativeComponent,
    transaction_id: Option<TransactionId>,
    expected_revision: Option<u64>,
) -> Result<ServiceReport> {
    manage_scoped(
        state_dir,
        action,
        component,
        transaction_id,
        expected_revision,
        None,
    )
    .await
}

/// Retain the original App parent binding in the actual operation owner. It
/// grants no public CLI or alternate configuration-writer authority.
pub(crate) async fn manage_for_app(
    scope: Arc<crate::app::HostScope>,
    action: ServiceAction,
    component: NativeComponent,
    transaction_id: Option<TransactionId>,
    expected_revision: Option<u64>,
) -> Result<ServiceReport> {
    if !matches!(component, NativeComponent::Host)
        || matches!(
            action,
            ServiceAction::PrepareInstall
                | ServiceAction::PrepareRecovery
                | ServiceAction::PrepareRuntimeRepair
                | ServiceAction::RecoverRuntimeRepair
        )
    {
        return Err(NativeManagementError::new(ErrorKind::Unsupported));
    }
    let path = scope.state_dir().to_owned();
    manage_scoped(
        &path,
        action,
        component,
        transaction_id,
        expected_revision,
        Some(scope),
    )
    .await
}
fn validate_app_owner(
    scope: Option<&Arc<crate::app::HostScope>>,
    definition: &Definition,
    transactions: Option<&NativeTransactions>,
) -> Result<()> {
    if let Some(scope) = scope {
        scope
            .validate()
            .map_err(|_| NativeManagementError::new(ErrorKind::Conflict))?;
        let root = crate::store::PrivateRoot::open(scope.state_dir())
            .map_err(|_| NativeManagementError::new(ErrorKind::Conflict))?;
        definition
            .validate_root_identity(&root.identity())
            .map_err(os)?;
        if transactions.is_some_and(|transactions| {
            transactions.configuration_root().identity().ok().as_ref() != Some(&root.identity())
        }) {
            return Err(NativeManagementError::new(ErrorKind::Conflict));
        }
        scope
            .validate()
            .map_err(|_| NativeManagementError::new(ErrorKind::Conflict))?;
    }
    Ok(())
}
async fn manage_scoped(
    state_dir: &Path,
    action: ServiceAction,
    component: NativeComponent,
    transaction_id: Option<TransactionId>,
    expected_revision: Option<u64>,
    app_scope: Option<Arc<crate::app::HostScope>>,
) -> Result<ServiceReport> {
    if matches!(
        action,
        ServiceAction::PrepareRuntimeRepair | ServiceAction::RecoverRuntimeRepair
    ) {
        return Err(NativeManagementError::new(ErrorKind::Invalid));
    }
    if matches!(
        action,
        ServiceAction::PrepareInstall
            | ServiceAction::PrepareFirstStart
            | ServiceAction::PrepareRecovery
    ) {
        if action == ServiceAction::PrepareRecovery
            && !matches!(component, NativeComponent::Gateway)
        {
            return Err(NativeManagementError::new(ErrorKind::Unsupported));
        }
        return prepare_intent(
            state_dir,
            action,
            component,
            transaction_id.ok_or_else(|| NativeManagementError::new(ErrorKind::Invalid))?,
            expected_revision.ok_or_else(|| NativeManagementError::new(ErrorKind::Invalid))?,
            app_scope,
        )
        .await;
    }
    if action == ServiceAction::Stop {
        let id = transaction_id.ok_or_else(|| NativeManagementError::new(ErrorKind::Invalid))?;
        let revision =
            expected_revision.ok_or_else(|| NativeManagementError::new(ErrorKind::Invalid))?;
        return stop_component(state_dir, component, id, revision, app_scope).await;
    }
    if matches!(
        action,
        ServiceAction::Start
            | ServiceAction::Enable
            | ServiceAction::Disable
            | ServiceAction::Uninstall
    ) {
        return registered_intent(
            state_dir,
            action,
            component,
            transaction_id.ok_or_else(|| NativeManagementError::new(ErrorKind::Invalid))?,
            expected_revision.ok_or_else(|| NativeManagementError::new(ErrorKind::Invalid))?,
            app_scope,
        )
        .await;
    }
    if transaction_id.is_some() || expected_revision.is_some() {
        return Err(NativeManagementError::new(ErrorKind::Invalid));
    }
    let path = state_dir.to_owned();
    let definition = Arc::new(
        blocking_read(move || Definition::prepare(&path, role(component)))
            .await
            .map_err(os)?,
    );
    let checked = definition.clone();
    let retained = app_scope.clone();
    let before = blocking_read(move || {
        Ok((|| -> Result<_> {
            validate_app_owner(retained.as_ref(), &checked, None)?;
            checked.state().map_err(os)
        })())
    })
    .await
    .map_err(os)??;
    let before_bytes =
        serde_json::to_vec(&before).map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
    let observation = if action == ServiceAction::Status {
        Some(definition.registration_status().await.map_err(os)?)
    } else {
        None
    };
    let material = read_report_material(definition.clone()).await?;
    let report = ServiceReport {
        schema: 1,
        operation: match action {
            ServiceAction::Definition => "definition",
            ServiceAction::Status => "status",
            ServiceAction::Stop
            | ServiceAction::Start
            | ServiceAction::Enable
            | ServiceAction::Disable
            | ServiceAction::Uninstall
            | ServiceAction::PrepareInstall
            | ServiceAction::PrepareFirstStart
            | ServiceAction::PrepareRecovery
            | ServiceAction::PrepareRuntimeRepair
            | ServiceAction::RecoverRuntimeRepair => {
                unreachable!("mutation uses its owned operation")
            }
        },
        configuration_only: action == ServiceAction::Definition,
        revision: before.revision,
        desired: before.desired.clone(),
        definition_path: material.path,
        definition_plist: material.plist,
        uid: material.uid,
        label: material.label.to_owned(),
        requires_initial_disabled: material.requires_initial_disabled,
        runtime_selection: material.selection,
        os: observation,
        operations_replayed: false,
        transaction_observation: None,
        installation_request_v1: None,
    };
    let checked = definition.clone();
    let after = blocking_read(move || {
        Ok((|| -> Result<_> {
            validate_app_owner(app_scope.as_ref(), &checked, None)?;
            checked.state().map_err(os)
        })())
    })
    .await
    .map_err(os)??;
    if serde_json::to_vec(&after).map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?
        != before_bytes
    {
        return Err(NativeManagementError::new(ErrorKind::Conflict));
    }
    Ok(report)
}
static OPERATIONS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);

fn registered_target(
    before: &NativeState,
    action: ServiceAction,
    component: NativeComponent,
    id: &TransactionId,
    revision: u64,
) -> Result<NativeState> {
    if before.revision != revision
        || !crate::platform::macos_service::fresh_single_role(before, role(component))
    {
        return Err(NativeManagementError::new(ErrorKind::Conflict));
    }
    let mut target = before.clone();
    let desired = match component {
        NativeComponent::Host => target.desired.host.as_mut(),
        NativeComponent::Gateway => target.desired.gateway.as_mut(),
    }
    .ok_or_else(|| NativeManagementError::new(ErrorKind::Conflict))?;
    if desired.manager != NativeManager::PersistentService {
        return Err(NativeManagementError::new(ErrorKind::Conflict));
    }
    match action {
        ServiceAction::Start if desired.run == NativeRunDesired::Stopped => {
            desired.run = NativeRunDesired::Running
        }
        ServiceAction::Enable if desired.autostart == NativeAutostartDesired::Disabled => {
            desired.autostart = NativeAutostartDesired::Enabled
        }
        ServiceAction::Disable if desired.autostart == NativeAutostartDesired::Enabled => {
            desired.autostart = NativeAutostartDesired::Disabled
        }
        ServiceAction::Uninstall
            if desired.run == NativeRunDesired::Stopped
                && desired.autostart == NativeAutostartDesired::Disabled => {}
        _ => return Err(NativeManagementError::new(ErrorKind::Conflict)),
    }
    target.revision = revision
        .checked_add(1)
        .ok_or_else(|| NativeManagementError::new(ErrorKind::Invalid))?;
    target.last_transaction = Some(NativeStateTransaction {
        transaction_id: id.clone(),
        sequence: before
            .last_transaction
            .as_ref()
            .map_or(0, |tx| tx.sequence)
            .checked_add(1)
            .ok_or_else(|| NativeManagementError::new(ErrorKind::Invalid))?,
    });
    Ok(target)
}
fn registered_action_name(action: ServiceAction) -> &'static str {
    match action {
        ServiceAction::Start => "start",
        ServiceAction::Enable => "enable",
        ServiceAction::Disable => "disable",
        ServiceAction::Uninstall => "uninstall",
        _ => unreachable!("registered lifecycle action"),
    }
}
/// Prepare one administrator operation against the original installed job.
/// C07 intent is committed here; no privileged launchctl command is dispatched.
/// An uninstall retains the persistent manager and never admits CLI takeover.
async fn registered_intent(
    path: &Path,
    action: ServiceAction,
    component: NativeComponent,
    id: TransactionId,
    revision: u64,
    app_scope: Option<Arc<crate::app::HostScope>>,
) -> Result<ServiceReport> {
    let permit = OPERATIONS
        .try_acquire()
        .map_err(|_| NativeManagementError::new(ErrorKind::Busy))?;
    let path = path.to_owned();
    let (send, receive) = tokio::sync::oneshot::channel();
    let job = tokio::spawn(async move {
        let _permit = permit;
        let mut operation = None;
        let mut definition = None;
        let mut proof = None;
        let mut transactions: Option<Arc<std::sync::Mutex<NativeTransactions>>> = None;
        let mut execution = None;
        let attempted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let result: Result<ServiceReport> = async {
            let open_path = path.clone();
            operation = Some(Arc::new(
                blocking_read(move || {
                    crate::store::PrivateRoot::open(open_path)
                        .and_then(|root| root.try_service_operation_lease())
                        .map_err(|error| match error {
                            crate::store::StoreError::Busy(_) => ServiceError::Busy,
                            _ => ServiceError::Unavailable,
                        })
                })
                .await
                .map_err(os)?,
            ));
            let open_path = path.clone();
            definition = Some(Arc::new(
                blocking_read(move || Definition::prepare(&open_path, role(component)))
                    .await
                    .map_err(os)?,
            ));
            let original = definition.as_ref().expect("original definition").clone();
            let checked = original.clone();
            let checked_scope = app_scope.clone();
            let before = blocking_read(move || {
                Ok((|| -> Result<_> {
                    validate_app_owner(checked_scope.as_ref(), &checked, None)?;
                    let before = checked.state().map_err(os)?;
                    registered_target(&before, action, component, &id, revision)?;
                    Ok((before, id))
                })())
            })
            .await
            .map_err(os)??;
            let (before, id) = before;
            let original_desired = role(component)
                .desired(&before)
                .ok_or_else(|| NativeManagementError::new(ErrorKind::Conflict))?;
            proof = Some(original.capture_registered_lifecycle().await.map_err(os)?);
            let binding = proof.as_ref().expect("original registration").clone();
            if binding.enabled() != (original_desired.autostart == NativeAutostartDesired::Enabled)
                || binding.observation().pid.is_some()
                    != (original_desired.run == NativeRunDesired::Running)
            {
                return Err(NativeManagementError::new(ErrorKind::Conflict));
            }
            let live_gateway = matches!(component, NativeComponent::Gateway)
                && binding.observation().pid.is_some();
            if binding.observation().pid.is_none() {
                let open_path = path.clone();
                execution = Some(Arc::new(
                    blocking_read(move || {
                        crate::store::PrivateRoot::open(open_path)
                            .and_then(|root| root.try_execution_lease())
                            .map_err(|_| ServiceError::Busy)
                    })
                    .await
                    .map_err(os)?,
                ));
            }
            if !live_gateway {
                let open_path = path.clone();
                transactions = Some(Arc::new(std::sync::Mutex::new(
                    blocking_read(move || Ok(platform::service_open(&open_path)))
                        .await
                        .map_err(os)??,
                )));
            }
            binding.revalidate().await.map_err(os)?;
            validate_operation(operation.as_ref().expect("operation lease").clone()).await?;
            // Set custody before either original-writer dispatch. Lost ACK is
            // Unknown with the exact proof/leases retained, never a new attempt.
            let (commit, receipt) = if live_gateway {
                attempted.store(true, std::sync::atomic::Ordering::Release);
                let committed = crate::management::service_control::set_autostart(
                    &path,
                    component,
                    action == ServiceAction::Enable,
                    revision,
                    id.clone(),
                )
                .await
                .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
                let receipt = serde_json::to_value(&committed)
                    .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
                (committed, receipt)
            } else {
                let owner = transactions.as_ref().expect("original writer").clone();
                let checked = original.clone();
                let checked_scope = app_scope.clone();
                let checked_binding = binding.clone();
                let expected = before.clone();
                let transaction = id.clone();
                let checked_execution = execution.clone();
                let checked_operation = operation.as_ref().expect("operation lease").clone();
                let attempted_commit = attempted.clone();
                blocking_read(move || {
                    Ok((|| -> Result<_> {
                        let mut owner = owner
                            .lock()
                            .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
                        validate_app_owner(checked_scope.as_ref(), &checked, Some(&owner))?;
                        checked_binding
                            .validate_owner(&owner.configuration_root())
                            .map_err(os)?;
                        let current = owner
                            .readstate()
                            .map_err(NativeManagementError::transaction)?;
                        if current.raw_bytes() != checked_binding.initial_state().bytes()
                            || serde_json::to_vec(current.state()).ok()
                                != serde_json::to_vec(&expected).ok()
                        {
                            return Err(NativeManagementError::new(ErrorKind::Conflict));
                        }
                        let target = registered_target(
                            current.state(),
                            action,
                            component,
                            &transaction,
                            revision,
                        )?;
                        let bytes = serde_json::to_vec(&target)
                            .map_err(|_| NativeManagementError::new(ErrorKind::Invalid))?;
                        owner
                            .validate_target(&bytes)
                            .map_err(NativeManagementError::transaction)?;
                        checked_operation
                            .validate()
                            .map_err(|_| NativeManagementError::new(ErrorKind::Conflict))?;
                        if let Some(execution) = checked_execution {
                            execution
                                .validate()
                                .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
                        }
                        attempted_commit.store(true, std::sync::atomic::Ordering::Release);
                        let committed = owner
                            .apply_target(&bytes)
                            .map_err(NativeManagementError::transaction)?;
                        let current = owner
                            .readstate()
                            .map_err(NativeManagementError::transaction)?;
                        if current.raw_bytes() != bytes
                            || committed.transaction_id != transaction
                            || committed.canonical_raw_sha256 != Sha256Digest::of_bytes(&bytes)
                        {
                            return Err(NativeManagementError::new(ErrorKind::Unknown));
                        }
                        let receipt = serde_json::to_value(committed.committed)
                            .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
                        Ok((
                            crate::management::service_control::ServiceControlReport {
                                schema: 1,
                                transaction_id: transaction,
                                revision: target.revision,
                                canonical_raw_sha256: committed.canonical_raw_sha256,
                                status: "configuration_committed".into(),
                                state_scope: "committed_target".into(),
                            },
                            receipt,
                        ))
                    })())
                })
                .await
                .map_err(os)??
            };
            let checked = original.clone();
            let checked_scope = app_scope.clone();
            let (after, canonical) = blocking_read(move || {
                Ok((|| -> Result<_> {
                    validate_app_owner(checked_scope.as_ref(), &checked, None)?;
                    checked.state_observation().map_err(os)
                })())
            })
            .await
            .map_err(os)??;
            let mut expected = registered_target(&before, action, component, &id, revision)?;
            let next = after
                .last_transaction
                .as_ref()
                .ok_or_else(|| NativeManagementError::new(ErrorKind::Unknown))?;
            if next.sequence <= before.last_transaction.as_ref().map_or(0, |tx| tx.sequence) {
                return Err(NativeManagementError::new(ErrorKind::Unknown));
            }
            expected
                .last_transaction
                .as_mut()
                .expect("target transaction")
                .sequence = next.sequence;
            if serde_json::to_vec(&after).ok() != serde_json::to_vec(&expected).ok()
                || commit.transaction_id != id
                || commit.revision != after.revision
                || commit.state_scope != "committed_target"
                || commit.canonical_raw_sha256 != canonical
            {
                return Err(NativeManagementError::new(ErrorKind::Unknown));
            }
            binding.revalidate().await.map_err(os)?;
            let checked = binding.clone();
            let checked_id = id.clone();
            let checked_canonical = canonical.clone();
            let request = blocking_read(move || {
                checked.lifecycle_request(
                    registered_action_name(action),
                    original_desired,
                    &checked_id,
                    after.revision,
                    &checked_canonical,
                )
            })
            .await
            .map_err(os)?;
            let material = read_report_material(original).await?;
            validate_operation(operation.as_ref().expect("operation lease").clone()).await?;
            Ok(ServiceReport {
                schema: 1,
                operation: registered_action_name(action),
                configuration_only: true,
                revision: after.revision,
                desired: after.desired,
                definition_path: material.path,
                definition_plist: material.plist,
                uid: material.uid,
                label: material.label,
                requires_initial_disabled: material.requires_initial_disabled,
                runtime_selection: material.selection,
                os: Some(
                    serde_json::to_value(binding.observation())
                        .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?,
                ),
                operations_replayed: false,
                transaction_observation: Some(serde_json::json!({"status":"committed",
                    "state_scope":"committed_target","transaction_id":id,"revision":after.revision,
                    "canonical_raw_sha256":canonical,"receipt":receipt})),
                installation_request_v1: Some(request),
            })
        }
        .await;
        match result {
            Ok(report) => {
                let _ = send.send(Ok(report));
            }
            Err(error)
                if attempted.load(std::sync::atomic::Ordering::Acquire)
                    || error._retained.is_some()
                    || matches!(error.kind, ErrorKind::Unknown) =>
            {
                let _ = send.send(Err((ErrorKind::Unknown, true)));
                std::future::pending::<()>().await;
                drop(error);
            }
            Err(error) => {
                let _ = send.send(Err((error.kind, false)));
            }
        }
        drop((
            transactions,
            execution,
            proof,
            definition,
            operation,
            app_scope,
        ));
    });
    match receive.await {
        Ok(Ok(report)) => {
            job.await
                .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
            Ok(report)
        }
        Ok(Err((kind, false))) => {
            job.await
                .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
            Err(NativeManagementError::new(kind))
        }
        Ok(Err((kind, true))) => {
            let mut error = NativeManagementError::new(kind);
            error._retained = Some(Retained::Service { _job: job });
            Err(error)
        }
        Err(_) => {
            let mut error = NativeManagementError::new(ErrorKind::Unknown);
            error._retained = Some(Retained::Service { _job: job });
            Err(error)
        }
    }
}

struct PreparationOwner {
    transactions: NativeTransactions,
    _execution: Option<crate::store::ExecutionLeaseGuard>,
    definition: Arc<Definition>,
    inactive: Option<Arc<crate::platform::macos_service::RegisteredInactiveProof>>,
}
/// Explicit same-root failed-service selection repair. The administrator
/// request is DATA; this actor does not alter launchd or replay an OS action.
pub async fn prepare_runtime_repair(
    state_dir: &Path,
    selection_file: &Path,
    id: TransactionId,
    revision: u64,
) -> Result<ServiceReport> {
    let permit = OPERATIONS
        .try_acquire()
        .map_err(|_| NativeManagementError::new(ErrorKind::Busy))?;
    let path = state_dir.to_owned();
    let selection_path = selection_file.to_owned();
    let (send, receive) = tokio::sync::oneshot::channel();
    let job = tokio::spawn(async move {
        let _permit = permit;
        let mut operation = None;
        let mut owner = None;
        let attempted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let result: Result<ServiceReport> = async {
            let lease_path = path.clone();
            operation = Some(Arc::new(blocking_read(move || {
                crate::store::PrivateRoot::open(lease_path)
                    .and_then(|root| root.try_service_operation_lease())
                    .map_err(|error| match error { crate::store::StoreError::Busy(_) => ServiceError::Busy,
                        _ => ServiceError::Unavailable })
            }).await.map_err(os)?));
            let open_path = path.clone();
            owner = Some(Arc::new(std::sync::Mutex::new(blocking_read(move || Ok((|| -> Result<PreparationOwner> {
                let transactions = platform::service_open(&open_path)?;
                let checked = (|| -> Result<_> {
                    let state = transactions.readstate().map_err(NativeManagementError::transaction)?;
                    require_repair_before(state.state(), revision)?;
                    let execution = crate::store::PrivateRoot::open(&open_path)
                        .and_then(|root| root.try_execution_lease())
                        .map_err(|_| NativeManagementError::new(ErrorKind::Busy))?;
                    let definition = Definition::prepare(&open_path, ServiceRole::Gateway).map_err(os)?;
                    Ok((execution, definition))
                })();
                match checked {
                    Ok((execution, definition)) => Ok(PreparationOwner {
                        transactions, _execution:Some(execution), definition:Arc::new(definition), inactive:None,
                    }),
                    Err(error) if error.exit_code() == 4 => Err(error.keep(transactions)),
                    Err(error) => Err(error),
                }
            })())).await.map_err(os)??)));
            let checked = owner.as_ref().expect("repair owner").clone();
            let definition = blocking_read(move || Ok(checked.lock().map_err(|_| ServiceError::Unknown)?.definition.clone()))
                .await.map_err(os)?;
            let proof = definition.capture_registered_inactive().await.map_err(os)?;
            proof.revalidate().await.map_err(os)?;
            let checked = owner.as_ref().expect("repair owner").clone();
            let binding = proof.clone();
            let operation = operation.as_ref().expect("repair operation").clone();
            let attempted_commit = attempted.clone();
            let report = blocking_read(move || Ok((|| -> Result<ServiceReport> {
                operation.validate().map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
                let mut owner = checked.lock().map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
                let owner = &mut *owner;
                binding.validate_owner(&owner.transactions.configuration_root()).map_err(os)?;
                let before = owner.transactions.readstate().map_err(NativeManagementError::transaction)?;
                require_repair_before(before.state(), revision)?;
                let original_root = crate::store::PrivateRoot::open(owner.definition.state_dir())
                    .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
                if original_root.identity() != owner.transactions.configuration_root().identity()
                    .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))? {
                    return Err(NativeManagementError::new(ErrorKind::Unknown));
                }
                let original_raw = original_root.read_raw("state.json", NATIVE_STATE_BYTES)
                    .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
                if !Arc::ptr_eq(binding.original_definition(), &owner.definition)
                    || original_raw.observation() != binding.initial_state().observation()
                    || original_raw.bytes() != binding.initial_state().bytes()
                    || before.raw_bytes() != original_raw.bytes() {
                    return Err(NativeManagementError::new(ErrorKind::Unknown));
                }
                owner.inactive = Some(binding.clone());
                let raw = platform::private_file(&selection_path, NATIVE_STATE_BYTES)?;
                let selected: NativeRuntimeSelection = serde_json::from_slice(raw.bytes())
                    .map_err(|_| NativeManagementError::new(ErrorKind::Invalid))?;
                let previous = before.state().runtime_selection()
                    .map_err(|_| NativeManagementError::new(ErrorKind::Invalid))?
                    .ok_or_else(|| NativeManagementError::new(ErrorKind::Invalid))?;
                if previous.publisher_spki_sha256 != selected.publisher_spki_sha256 {
                    return Err(NativeManagementError::new(ErrorKind::Conflict));
                }
                let old_release = crate::release::verify_selected(&previous)
                    .map_err(|_| NativeManagementError::new(ErrorKind::Invalid))?;
                let candidate = crate::release::verify_selected(&selected)
                    .map_err(|_| NativeManagementError::new(ErrorKind::Invalid))?;
                let sequence = owner.transactions.runtime_update_high_water()
                    .map_err(NativeManagementError::transaction)?.checked_add(1)
                    .ok_or_else(|| NativeManagementError::new(ErrorKind::Invalid))?;
                if previous == selected || candidate.manifest().target != old_release.manifest().target
                    || !candidate.supports_state_reader(
                    styx_contracts::management::ReaderContract::NativeServiceRuntimeSelectedStateV1,
                ).map_err(|_| NativeManagementError::new(ErrorKind::Invalid))? {
                    return Err(NativeManagementError::new(ErrorKind::Invalid));
                }
                attempted_commit.store(true, std::sync::atomic::Ordering::Release);
                let committed = owner.transactions.update_runtime_for_failed_service(
                    old_release, candidate, id.clone(), sequence, binding, &mut owner._execution,
                ).map_err(NativeManagementError::transaction)?;
                let current = owner.transactions.readstate().map_err(NativeManagementError::transaction)?;
                if current.state().revision != revision.checked_add(1).ok_or_else(|| NativeManagementError::new(ErrorKind::Invalid))?
                    || current.raw_sha256() != committed.canonical_raw_sha256 {
                    return Err(NativeManagementError::new(ErrorKind::Unknown));
                }
                let request = owner.transactions.failed_service_repair_request(
                    &id, current.state().revision, &committed.canonical_raw_sha256,
                ).map_err(NativeManagementError::transaction)?;
                let report = runtime_repair_report(request, &current, &committed, selected,
                    owner.inactive.as_ref().expect("original proof"), false)?;
                operation.validate().map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
                Ok(report)
            })())).await.map_err(os)??;
            proof.revalidate().await.map_err(os)?;
            Ok(report)
        }.await;
        match result {
            Ok(report) => {
                let _ = send.send(Ok(report));
            }
            Err(error)
                if attempted.load(std::sync::atomic::Ordering::Acquire)
                    || error._retained.is_some()
                    || matches!(error.kind, ErrorKind::Unknown) =>
            {
                let _ = send.send(Err((ErrorKind::Unknown, true)));
                std::future::pending::<()>().await;
                drop(error);
            }
            Err(error) => {
                let _ = send.send(Err((error.kind, false)));
            }
        }
        drop((owner, operation));
    });
    match receive.await {
        Ok(Ok(report)) => {
            job.await
                .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
            Ok(report)
        }
        Ok(Err((kind, false))) => {
            job.await
                .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
            Err(NativeManagementError::new(kind))
        }
        Ok(Err((_, true))) | Err(_) => {
            let mut error = NativeManagementError::new(ErrorKind::Unknown);
            error._retained = Some(Retained::Service { _job: job });
            Err(error)
        }
    }
}
// Recovery keeps the original coordinator even while native registration is
// asynchronously observed. It never claims a second journal or selection input.
struct RuntimeRepairRecoveryOwner {
    transactions: NativeTransactions,
    execution: Option<crate::store::ExecutionLeaseGuard>,
}
fn runtime_repair_report(
    request: serde_json::Value,
    current: &crate::store::native_state::ValidatedNativeState,
    committed: &crate::store::native_transaction::NativeCommitResult,
    selected: NativeRuntimeSelection,
    proof: &crate::platform::macos_service::RegisteredInactiveProof,
    initially_committed: bool,
) -> Result<ServiceReport> {
    let text = |key: &str| -> Result<String> {
        request
            .get(key)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| NativeManagementError::new(ErrorKind::Unknown))
    };
    let mut observation = serde_json::json!({"status":"committed","state_scope":"committed_target",
        "transaction_id":committed.transaction_id,"revision":current.state().revision,
        "canonical_raw_sha256":committed.canonical_raw_sha256,"receipt":committed.committed});
    if initially_committed {
        observation["configuration_recovered"] = serde_json::json!(committed.recovered);
        observation["administrator_action_outcome"] =
            serde_json::json!("unknown_no_request_reissued");
    }
    Ok(ServiceReport {
        schema: 1,
        operation: if initially_committed {
            "recover_runtime_repair"
        } else {
            "prepare_runtime_repair"
        },
        configuration_only: true,
        revision: current.state().revision,
        desired: current.state().desired.clone(),
        definition_path: PathBuf::from(text("definition_path")?),
        definition_plist: text("definition_plist")?,
        uid: request
            .get("uid")
            .and_then(serde_json::Value::as_u64)
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| NativeManagementError::new(ErrorKind::Unknown))?,
        label: text("label")?,
        requires_initial_disabled: true,
        runtime_selection: selected,
        os: Some(
            serde_json::to_value(proof.observation())
                .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?,
        ),
        operations_replayed: false,
        transaction_observation: Some(observation),
        installation_request_v1: if initially_committed {
            None
        } else {
            Some(request)
        },
    })
}
/// Cold recovery of one exact original C07 repair; never selects a new target
/// or repeats an administrator operation whose delivery may already have occurred.
pub async fn recover_runtime_repair(
    state_dir: &Path,
    id: TransactionId,
    revision: u64,
) -> Result<ServiceReport> {
    let permit = OPERATIONS
        .try_acquire()
        .map_err(|_| NativeManagementError::new(ErrorKind::Busy))?;
    let path = state_dir.to_owned();
    let (send, receive) = tokio::sync::oneshot::channel();
    let job = tokio::spawn(async move {
        let _permit = permit;
        let mut operation = None;
        let mut owner = None;
        let attempted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let result: Result<ServiceReport> = async {
            let lease_path = path.clone();
            operation = Some(Arc::new(
                blocking_read(move || {
                    crate::store::PrivateRoot::open(lease_path)
                        .and_then(|root| root.try_service_operation_lease())
                        .map_err(|error| match error {
                            crate::store::StoreError::Busy(_) => ServiceError::Busy,
                            _ => ServiceError::Unavailable,
                        })
                })
                .await
                .map_err(os)?,
            ));
            let open_path = path.clone();
            owner = Some(Arc::new(std::sync::Mutex::new(
                blocking_read(move || {
                    Ok((|| -> Result<_> {
                        let transactions = platform::open(&open_path)?;
                        Ok(RuntimeRepairRecoveryOwner {
                            transactions,
                            execution: None,
                        })
                    })())
                })
                .await
                .map_err(os)??,
            )));
            let checked = owner.as_ref().expect("recovery owner").clone();
            let original_id = id.clone();
            let execution_path = path.clone();
            let original = blocking_read(move || {
                Ok((|| -> Result<_> {
                    let mut owner = checked
                        .lock()
                        .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
                    let original = owner
                        .transactions
                        .original_service_runtime_repair(&original_id)
                        .map_err(NativeManagementError::transaction)?;
                    if original.target().revision != revision {
                        return Err(NativeManagementError::new(ErrorKind::Conflict));
                    }
                    owner.execution = Some(
                        crate::store::PrivateRoot::open(execution_path)
                            .and_then(|root| root.try_execution_lease())
                            .map_err(|_| NativeManagementError::new(ErrorKind::Busy))?,
                    );
                    Ok(Arc::new(original))
                })())
            })
            .await
            .map_err(os)??;
            let checked = owner.as_ref().expect("recovery owner").clone();
            let authority = blocking_read(move || {
                Ok(checked
                    .lock()
                    .map_err(|_| ServiceError::Unknown)?
                    .transactions
                    .configuration_root())
            })
            .await
            .map_err(os)?;
            let proof =
                crate::platform::macos_service::RegisteredInactiveProof::reopen_from_original(
                    path.clone(),
                    original.clone(),
                    authority,
                )
                .await
                .map_err(os)?;
            proof.revalidate().await.map_err(os)?;
            let checked = owner.as_ref().expect("recovery owner").clone();
            let binding = proof.clone();
            let operation = operation.as_ref().expect("recovery operation").clone();
            let attempted_commit = attempted.clone();
            let report = blocking_read(move || {
                Ok((|| -> Result<_> {
                    operation
                        .validate()
                        .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
                    let mut owner = checked
                        .lock()
                        .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
                    let owner = &mut *owner;
                    original
                        .validate_owner(&owner.transactions.configuration_root())
                        .map_err(NativeManagementError::transaction)?;
                    let previous = original
                        .before()
                        .runtime_selection()
                        .map_err(|_| NativeManagementError::new(ErrorKind::Invalid))?
                        .ok_or_else(|| NativeManagementError::new(ErrorKind::Invalid))?;
                    let selected = original
                        .target()
                        .runtime_selection()
                        .map_err(|_| NativeManagementError::new(ErrorKind::Invalid))?
                        .ok_or_else(|| NativeManagementError::new(ErrorKind::Invalid))?;
                    let old_release = crate::release::verify_selected(&previous)
                        .map_err(|_| NativeManagementError::new(ErrorKind::Invalid))?;
                    let candidate = crate::release::verify_selected(&selected)
                        .map_err(|_| NativeManagementError::new(ErrorKind::Invalid))?;
                    let initially_committed = original.initially_committed();
                    attempted_commit.store(true, std::sync::atomic::Ordering::Release);
                    let committed = owner
                        .transactions
                        .recover_runtime_for_failed_service(
                            old_release,
                            candidate,
                            original.clone(),
                            binding.clone(),
                            &mut owner.execution,
                        )
                        .map_err(NativeManagementError::transaction)?;
                    let current = owner
                        .transactions
                        .readstate()
                        .map_err(NativeManagementError::transaction)?;
                    if current.raw_bytes() != original.target_bytes()
                        || current.state().revision != revision
                        || current.raw_sha256() != committed.canonical_raw_sha256
                    {
                        return Err(NativeManagementError::new(ErrorKind::Unknown));
                    }
                    let request = owner
                        .transactions
                        .failed_service_repair_request(
                            &id,
                            revision,
                            &committed.canonical_raw_sha256,
                        )
                        .map_err(NativeManagementError::transaction)?;
                    let report = runtime_repair_report(
                        request,
                        &current,
                        &committed,
                        selected,
                        &binding,
                        initially_committed,
                    )?;
                    operation
                        .validate()
                        .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
                    Ok(report)
                })())
            })
            .await
            .map_err(os)??;
            proof.revalidate().await.map_err(os)?;
            Ok(report)
        }
        .await;
        match result {
            Ok(report) => {
                let _ = send.send(Ok(report));
            }
            Err(error)
                if attempted.load(std::sync::atomic::Ordering::Acquire)
                    || error._retained.is_some()
                    || matches!(error.kind, ErrorKind::Unknown) =>
            {
                let _ = send.send(Err((ErrorKind::Unknown, true)));
                std::future::pending::<()>().await;
                drop(error);
            }
            Err(error) => {
                let _ = send.send(Err((error.kind, false)));
            }
        }
        drop((owner, operation));
    });
    match receive.await {
        Ok(Ok(report)) => {
            job.await
                .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
            Ok(report)
        }
        Ok(Err((kind, false))) => {
            job.await
                .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
            Err(NativeManagementError::new(kind))
        }
        Ok(Err((_, true))) | Err(_) => {
            let mut error = NativeManagementError::new(ErrorKind::Unknown);
            error._retained = Some(Retained::Service { _job: job });
            Err(error)
        }
    }
}
fn require_repair_before(before: &NativeState, revision: u64) -> Result<()> {
    if before.revision != revision
        || before.mode != NativeDeploymentMode::CreateLocal
        || before.has_migration_binding()
        || before.desired.host.is_some()
        || before.desired.gateway
            != Some(NativeComponentDesired {
                manager: NativeManager::PersistentService,
                run: NativeRunDesired::Stopped,
                autostart: NativeAutostartDesired::Disabled,
            })
    {
        return Err(NativeManagementError::new(ErrorKind::Conflict));
    }
    Ok(())
}
fn prepare_target(
    before: &NativeState,
    action: ServiceAction,
    component: NativeComponent,
    id: &TransactionId,
    revision: u64,
) -> Result<NativeState> {
    if before.revision != revision
        || !crate::platform::macos_service::fresh_single_role(before, role(component))
        || action == ServiceAction::PrepareRecovery
            && !matches!(component, NativeComponent::Gateway)
    {
        return Err(NativeManagementError::new(ErrorKind::Conflict));
    }
    let mut target = before.clone();
    let desired = match component {
        NativeComponent::Host => target.desired.host.as_mut(),
        NativeComponent::Gateway => target.desired.gateway.as_mut(),
    }
    .ok_or_else(|| NativeManagementError::new(ErrorKind::Conflict))?;
    let expected = match action {
        ServiceAction::PrepareInstall => NativeComponentDesired {
            manager: NativeManager::ForegroundCli,
            run: NativeRunDesired::Stopped,
            autostart: NativeAutostartDesired::Disabled,
        },
        ServiceAction::PrepareFirstStart => NativeComponentDesired {
            manager: NativeManager::PersistentService,
            run: NativeRunDesired::Stopped,
            autostart: NativeAutostartDesired::Disabled,
        },
        ServiceAction::PrepareRecovery => NativeComponentDesired {
            manager: NativeManager::PersistentService,
            run: NativeRunDesired::Running,
            autostart: NativeAutostartDesired::Enabled,
        },
        _ => return Err(NativeManagementError::new(ErrorKind::Invalid)),
    };
    if *desired != expected {
        return Err(NativeManagementError::new(ErrorKind::Conflict));
    }
    desired.manager = NativeManager::PersistentService;
    if action == ServiceAction::PrepareFirstStart {
        desired.run = NativeRunDesired::Running;
        desired.autostart = NativeAutostartDesired::Enabled;
    } else if action == ServiceAction::PrepareRecovery {
        desired.run = NativeRunDesired::Stopped;
        desired.autostart = NativeAutostartDesired::Disabled;
    }
    target.revision = revision
        .checked_add(1)
        .ok_or_else(|| NativeManagementError::new(ErrorKind::Invalid))?;
    target.last_transaction = Some(NativeStateTransaction {
        transaction_id: id.clone(),
        sequence: before
            .last_transaction
            .as_ref()
            .map_or(0, |tx| tx.sequence)
            .checked_add(1)
            .ok_or_else(|| NativeManagementError::new(ErrorKind::Invalid))?,
    });
    Ok(target)
}
async fn prepare_intent(
    path: &Path,
    action: ServiceAction,
    component: NativeComponent,
    id: TransactionId,
    revision: u64,
    app_scope: Option<Arc<crate::app::HostScope>>,
) -> Result<ServiceReport> {
    let permit = OPERATIONS
        .try_acquire()
        .map_err(|_| NativeManagementError::new(ErrorKind::Busy))?;
    let path = path.to_owned();
    let (send, receive) = tokio::sync::oneshot::channel();
    let job = tokio::spawn(async move {
        let _permit = permit;
        let mut operation = None;
        let mut owner = None;
        let attempted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let result: Result<ServiceReport> = async {
            let lease_path = path.clone();
            operation = Some(Arc::new(blocking_read(move || {
                crate::store::PrivateRoot::open(lease_path).and_then(|root| root.try_service_operation_lease())
                    .map_err(|error| match error { crate::store::StoreError::Busy(_) => ServiceError::Busy,
                        _=>ServiceError::Unavailable })
            }).await.map_err(os)?));
            let open_path = path.clone();
            let open_id = id.clone();
            let open_scope = app_scope.clone();
            // Nested Result preserves any original retained transaction-open
            // failure; converting it to ServiceError would discard custody.
            owner = Some(Arc::new(std::sync::Mutex::new(blocking_read(move || Ok((|| -> Result<PreparationOwner> {
                let transactions = platform::service_open(&open_path)?;
                let prepared = (|| -> Result<_> {
                    let before = transactions.readstate().map_err(NativeManagementError::transaction)?;
                    prepare_target(before.state(), action, component, &open_id, revision)?;
                    let execution = crate::store::PrivateRoot::open(&open_path)
                        .and_then(|root| root.try_execution_lease())
                        .map_err(|_| NativeManagementError::new(ErrorKind::Busy))?;
                    let definition = if action == ServiceAction::PrepareInstall {
                        Definition::prepare_install(&open_path, role(component))
                    } else { Definition::prepare(&open_path, role(component)) }.map_err(os)?;
                    validate_app_owner(open_scope.as_ref(), &definition, Some(&transactions))?;
                    if action != ServiceAction::PrepareRecovery {
                        definition.require_pending_registration().map_err(os)?;
                    }
                    Ok((execution, definition))
                })();
                match prepared {
                    Ok((execution, definition)) => Ok(PreparationOwner {
                        transactions, _execution:Some(execution), definition:Arc::new(definition), inactive:None }),
                    Err(error) if error.exit_code() == 4 => Err(error.keep(transactions)),
                    Err(error) => Err(error),
                }
            })())).await.map_err(os)??)));
            if action == ServiceAction::PrepareRecovery {
                let checked = owner.as_ref().expect("original preparation owner").clone();
                let definition = blocking_read(move || {
                    Ok(checked.lock().map_err(|_| ServiceError::Unknown)?.definition.clone())
                }).await.map_err(os)?;
                let proof = definition.capture_registered_inactive().await.map_err(os)?;
                let checked = owner.as_ref().expect("original preparation owner").clone();
                blocking_read(move || {
                    let mut held = checked.lock().map_err(|_| ServiceError::Unknown)?;
                    proof.validate_owner(&held.transactions.configuration_root())?;
                    held.inactive = Some(proof);
                    Ok(())
                }).await.map_err(os)?;
            }
            if action == ServiceAction::PrepareFirstStart {
                let checked = owner.as_ref().expect("original preparation owner").clone();
                let definition = blocking_read(move || Ok(checked.lock().map_err(|_| ServiceError::Unknown)?.definition.clone()))
                    .await.map_err(os)?;
                definition.require_unregistered().await.map_err(os)?;
            }
            let checked = owner.as_ref().expect("original preparation owner").clone();
            let attempted_commit = attempted.clone();
            let operation = operation.as_ref().expect("original operation lease").clone();
            let checked_scope = app_scope.clone();
            let report = blocking_read(move || Ok((|| -> Result<ServiceReport> {
                operation.validate().map_err(|_| NativeManagementError::new(ErrorKind::Conflict))?;
                let mut owner = checked.lock().map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
                let before = owner.transactions.readstate().map_err(NativeManagementError::transaction)?;
                let target = prepare_target(before.state(), action, component, &id, revision)?;
                validate_app_owner(checked_scope.as_ref(), &owner.definition, Some(&owner.transactions))?;
                owner.definition.validate().map_err(os)?;
                if let Some(proof) = &owner.inactive {
                    proof.validate_owner(&owner.transactions.configuration_root()).map_err(os)?;
                    let root = crate::store::PrivateRoot::open(owner.definition.state_dir())
                        .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
                    if root.identity() != owner.transactions.configuration_root().identity()
                        .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))? {
                        return Err(NativeManagementError::new(ErrorKind::Unknown));
                    }
                    let raw = root.read_raw("state.json", 1024 * 1024)
                        .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
                    if !Arc::ptr_eq(proof.original_definition(), &owner.definition)
                        || raw.observation() != proof.initial_state().observation()
                        || raw.bytes() != proof.initial_state().bytes()
                        || before.raw_bytes() != raw.bytes() {
                        return Err(NativeManagementError::new(ErrorKind::Unknown));
                    }
                }
                owner._execution.as_ref().ok_or_else(|| NativeManagementError::new(ErrorKind::Conflict))?.validate().map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
                let bytes = serde_json::to_vec(&target).map_err(|_| NativeManagementError::new(ErrorKind::Invalid))?;
                owner.transactions.validate_target(&bytes).map_err(NativeManagementError::transaction)?;
                attempted_commit.store(true, std::sync::atomic::Ordering::Release);
                let commit = owner.transactions.apply_target(&bytes).map_err(NativeManagementError::transaction)?;
                let current = owner.transactions.readstate().map_err(NativeManagementError::transaction)?;
                if current.raw_bytes() != bytes || commit.transaction_id != id
                    || commit.canonical_raw_sha256 != Sha256Digest::of_bytes(&bytes) {
                    return Err(NativeManagementError::new(ErrorKind::Unknown));
                }
                // Recovery retains the exact already-installed definition pin.
                // The absent-registration reopen belongs only to fresh install.
                let next = if owner.inactive.is_some() {
                    owner.definition.clone()
                } else {
                    Arc::new(owner.definition.reopen_after_preparation().map_err(os)?)
                };
                let (observed, raw_hash) = next.state_observation().map_err(os)?;
                if raw_hash != commit.canonical_raw_sha256 || serde_json::to_vec(&observed).ok() != Some(bytes) {
                    return Err(NativeManagementError::new(ErrorKind::Unknown));
                }
                let request = if action == ServiceAction::PrepareFirstStart {
                    Some(next.first_start_request(&id, target.revision, &raw_hash).map_err(os)?)
                } else { None };
                let material = next.installation_material().map_err(os)?;
                let report = ServiceReport { schema:1,
                    operation:match action {
                        ServiceAction::PrepareInstall => "prepare_install",
                        ServiceAction::PrepareFirstStart => "prepare_first_start",
                        ServiceAction::PrepareRecovery => "prepare_recovery",
                        _ => unreachable!("preparation action was checked"),
                    },
                    configuration_only:true, revision:target.revision, desired:target.desired,
                    definition_path:material.path, definition_plist:std::str::from_utf8(material.bytes)
                        .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?.to_owned(),
                    uid:material.uid,label:material.label.to_owned(),requires_initial_disabled:material.requires_initial_disabled,
                    runtime_selection:next.runtime_selection().map_err(os)?.clone(),
                    os:owner.inactive.as_ref().map(|proof| serde_json::to_value(proof.observation())
                        .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))).transpose()?,
                    operations_replayed:false,
                    transaction_observation:Some(serde_json::json!({"status":"committed","state_scope":"committed_target",
                        "transaction_id":commit.transaction_id,"revision":target.revision,
                        "canonical_raw_sha256":raw_hash,"receipt":commit.committed})),
                    installation_request_v1:request };
                operation.validate().map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
                owner.definition = next;
                Ok(report)
            })())).await.map_err(os)??;
            let checked = owner.as_ref().expect("original preparation owner").clone();
            let proof = blocking_read(move || {
                Ok(checked.lock().map_err(|_| ServiceError::Unknown)?.inactive.clone())
            }).await.map_err(os)?;
            if let Some(proof) = proof {
                // launchd and C07 are separate authorities. Any changed job
                // generation after publication is Unknown, never a stop receipt.
                proof.revalidate().await.map_err(os)?;
            }
            Ok(report)
        }.await;
        match result {
            Ok(report) => {
                let _ = send.send(Ok(report));
            }
            Err(error)
                if attempted.load(std::sync::atomic::Ordering::Acquire)
                    || error._retained.is_some()
                    || matches!(error.kind, ErrorKind::Unknown) =>
            {
                let _ = send.send(Err((ErrorKind::Unknown, true)));
                std::future::pending::<()>().await;
                drop(error);
            }
            Err(error) => {
                let _ = send.send(Err((error.kind, false)));
            }
        }
        drop((owner, operation, app_scope));
    });
    match receive.await {
        Ok(Ok(report)) => {
            job.await
                .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
            Ok(report)
        }
        Ok(Err((kind, false))) => {
            job.await
                .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
            Err(NativeManagementError::new(kind))
        }
        Ok(Err((kind, true))) => {
            let mut error = NativeManagementError::new(kind);
            error._retained = Some(Retained::Service { _job: job });
            Err(error)
        }
        Err(_) => {
            let mut error = NativeManagementError::new(ErrorKind::Unknown);
            error._retained = Some(Retained::Service { _job: job });
            Err(error)
        }
    }
}

/// Validate the exact reply's target, not an arbitrary newer current revision.
/// Other role intent, selection, opaque fields and identity must be unchanged.
fn validate_stop_target(
    before: &NativeState,
    after: &NativeState,
    raw_sha256: &styx_contracts::identity::Sha256Digest,
    report: &crate::management::service_control::ServiceControlReport,
    id: &TransactionId,
    component: NativeComponent,
) -> Result<()> {
    use styx_contracts::native_management::NativeStateTransaction;
    let mut expected = before.clone();
    let desired = match component {
        NativeComponent::Host => expected.desired.host.as_mut(),
        NativeComponent::Gateway => expected.desired.gateway.as_mut(),
    }
    .ok_or_else(|| NativeManagementError::new(ErrorKind::Conflict))?;
    if desired.manager != NativeManager::PersistentService
        || desired.run != NativeRunDesired::Running
    {
        return Err(NativeManagementError::new(ErrorKind::Conflict));
    }
    desired.run = NativeRunDesired::Stopped;
    expected.revision = expected
        .revision
        .checked_add(1)
        .ok_or_else(|| NativeManagementError::new(ErrorKind::Conflict))?;
    // Journal high-water can exceed the last committed state's sequence.
    // The complete chain reader validates the exact sequence; never equate it
    // to revision or require last committed + 1 here.
    let transaction = after
        .last_transaction
        .as_ref()
        .filter(|tx| {
            &tx.transaction_id == id
                && tx.sequence
                    > before
                        .last_transaction
                        .as_ref()
                        .map_or(0, |old| old.sequence)
        })
        .ok_or_else(|| NativeManagementError::new(ErrorKind::Unknown))?;
    expected.last_transaction = Some(NativeStateTransaction {
        transaction_id: id.clone(),
        sequence: transaction.sequence,
    });
    let expected_bytes = serde_json::to_vec(&expected)
        .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
    let after_bytes =
        serde_json::to_vec(after).map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
    if report.schema != 1
        || &report.transaction_id != id
        || report.status != "configuration_committed_stop_pending"
        || report.state_scope != "committed_target"
        || report.revision != expected.revision
        || &report.canonical_raw_sha256 != raw_sha256
        || expected_bytes != after_bytes
    {
        return Err(NativeManagementError::new(ErrorKind::Unknown));
    }
    Ok(())
}

/// Fresh Host-only metadata Stop through the caller's retained original C07
/// writer. This report is a committed target, never an actual-exit claim.
fn commit_host_stop(
    transactions: &mut NativeTransactions,
    before: &NativeState,
    id: &TransactionId,
    revision: u64,
) -> Result<crate::management::service_control::ServiceControlReport> {
    if before.revision != revision
        || !crate::platform::macos_service::fresh_single_role(before, ServiceRole::Host)
        || before.desired.host.is_none_or(|desired| {
            desired.manager != NativeManager::PersistentService
                || desired.run != NativeRunDesired::Running
        })
    {
        return Err(NativeManagementError::new(ErrorKind::Conflict));
    }
    let current = transactions
        .readstate()
        .map_err(NativeManagementError::transaction)?;
    if serde_json::to_vec(current.state())
        .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?
        != serde_json::to_vec(before).map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?
    {
        return Err(NativeManagementError::new(ErrorKind::Conflict));
    }
    let authority = transactions.configuration_root();
    // Existing typed C07 operation chooses journal high-water + 1 itself.
    let (commit, target_revision) = transactions
        .set_service_stopped(&authority, NativeComponent::Host, revision, id.clone())
        .map_err(NativeManagementError::transaction)?;
    let report = crate::management::service_control::ServiceControlReport {
        schema: 1,
        transaction_id: id.clone(),
        revision: target_revision,
        canonical_raw_sha256: commit.canonical_raw_sha256,
        status: "configuration_committed_stop_pending".into(),
        state_scope: "committed_target".into(),
    };
    let after = transactions
        .readstate()
        .map_err(NativeManagementError::transaction)?;
    let raw_hash = Sha256Digest::of_bytes(after.raw_bytes());
    validate_stop_target(
        before,
        after.state(),
        &raw_hash,
        &report,
        id,
        NativeComponent::Host,
    )?;
    Ok(report)
}

/// Caller loss never cancels or resends the original mutation. Any uncertainty
/// after dispatch retains operation lease, definition, original instance and
/// transaction identity until whole-process teardown, as on Linux.
async fn stop_component(
    path: &Path,
    component: NativeComponent,
    id: TransactionId,
    revision: u64,
    app_scope: Option<Arc<crate::app::HostScope>>,
) -> Result<ServiceReport> {
    let permit = OPERATIONS
        .try_acquire()
        .map_err(|_| NativeManagementError::new(ErrorKind::Busy))?;
    let path = path.to_owned();
    let (send, receive) = tokio::sync::oneshot::channel();
    let job = tokio::spawn(async move {
        let _permit = permit;
        let mut operation_lease = None;
        let mut definition = None;
        let mut instance = None;
        let mut host_transactions = None;
        let mut dispatched = false;
        let result = async {
            let lease_path = path.clone();
            operation_lease = Some(Arc::new(
                blocking_read(move || {
                    crate::store::PrivateRoot::open(lease_path)
                        .and_then(|root| root.try_service_operation_lease())
                        .map_err(|error| match error {
                            crate::store::StoreError::Busy(_) => ServiceError::Busy,
                            _ => ServiceError::Unavailable,
                        })
                })
                .await
                .map_err(os)?,
            ));
            let prepared_path = path.clone();
            definition = Some(Arc::new(
                blocking_read(move || Definition::prepare(&prepared_path, role(component)))
                    .await
                    .map_err(os)?,
            ));
            let definition = definition.as_ref().expect("original definition");
            let checked = definition.clone();
            let before = blocking_read(move || checked.state()).await.map_err(os)?;
            if before.revision != revision
                || role(component).desired(&before).is_none_or(|desired| {
                    desired.manager != NativeManager::PersistentService
                        || desired.run != NativeRunDesired::Running
                })
                || matches!(component, NativeComponent::Host)
                    && !crate::platform::macos_service::fresh_single_role(
                        &before,
                        ServiceRole::Host,
                    )
            {
                return Err(NativeManagementError::new(ErrorKind::Conflict));
            }
            // Pins exact root-owned installed plist + registered process UID,
            // kernel birth and original signed executable before C07 dispatch.
            instance = Some(Arc::new(definition.prepare_stop().await.map_err(os)?));
            if matches!(component, NativeComponent::Host) {
                // The Host runner owns an execution/read scope, not the C07
                // writer. This existing opener refuses all AppManaged roots.
                let opened_path = path.clone();
                host_transactions = Some(Arc::new(std::sync::Mutex::new(
                    blocking_read(move || Ok(platform::service_open(&opened_path)))
                        .await
                        .map_err(os)??,
                )));
            }
            let checked = definition.clone();
            let checked_scope = app_scope.clone();
            let checked_owner = host_transactions.clone();
            blocking_read(move || {
                Ok((|| -> Result<()> {
                    if let Some(owner) = checked_owner {
                        let owner = owner
                            .lock()
                            .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
                        validate_app_owner(checked_scope.as_ref(), &checked, Some(&owner))
                    } else {
                        validate_app_owner(checked_scope.as_ref(), &checked, None)
                    }
                })())
            })
            .await
            .map_err(os)??;
            validate_operation(operation_lease.as_ref().expect("operation lease").clone()).await?;
            dispatched = true;
            let committed = if let Some(transactions) = &host_transactions {
                let owner = transactions.clone();
                let original = instance.as_ref().expect("original Host instance").clone();
                let expected = before.clone();
                let transaction = id.clone();
                let checked_scope = app_scope.clone();
                let checked_definition = definition.clone();
                blocking_read(move || {
                    original.validate()?;
                    Ok((|| -> Result<_> {
                        let mut transactions = owner
                            .lock()
                            .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
                        validate_app_owner(
                            checked_scope.as_ref(),
                            &checked_definition,
                            Some(&transactions),
                        )?;
                        commit_host_stop(&mut transactions, &expected, &transaction, revision)
                    })())
                })
                .await
                .map_err(os)??
            } else {
                crate::management::service_control::set_run(
                    &path,
                    NativeComponent::Gateway,
                    NativeRunDesired::Stopped,
                    revision,
                    id.clone(),
                )
                .await
                .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?
            };
            // The same original service now cancels/drains itself. Never send
            // launchctl kill or retry Stop, even if ACK or actual exit is lost.
            let stopped = definition.wait_original_stop().await.map_err(os)?;
            let checked = definition.clone();
            let (after, raw_sha256) = blocking_read(move || checked.state_observation())
                .await
                .map_err(os)?;
            validate_stop_target(&before, &after, &raw_sha256, &committed, &id, component)?;
            validate_operation(operation_lease.as_ref().expect("operation lease").clone())
                .await
                .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
            let material = read_report_material(definition.clone()).await?;
            Ok(ServiceReport {
                schema: 1,
                operation: "stop",
                configuration_only: false,
                revision: after.revision,
                desired: after.desired,
                definition_path: material.path,
                definition_plist: material.plist,
                uid: material.uid,
                label: material.label.to_owned(),
                requires_initial_disabled: material.requires_initial_disabled,
                runtime_selection: material.selection,
                // Original signed __service-run exits zero only after its
                // role outcome is complete. OS absence alone is insufficient;
                // this does not claim independent per-worker waitpid observation.
                os: Some(serde_json::json!({"stop":stopped,
                    "product_settlement_basis":"original_signed_service_clean_exit",
                    "independent_worker_wait":"not_observed"})),
                operations_replayed: false,
                transaction_observation: Some(
                    serde_json::to_value(committed)
                        .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?,
                ),
                installation_request_v1: None,
            })
        }
        .await;
        match result {
            Ok(report) => {
                let _ = send.send(Ok(report));
            }
            Err(error) if dispatched || error._retained.is_some() => {
                let _ = send.send(Err((ErrorKind::Unknown, true)));
                std::future::pending::<()>().await;
                drop(error);
            }
            Err(error) => {
                let _ = send.send(Err((error.kind, false)));
            }
        }
        drop((
            host_transactions,
            instance,
            definition,
            operation_lease,
            id,
            app_scope,
        ));
    });
    match receive.await {
        Ok(Ok(report)) => {
            job.await
                .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
            Ok(report)
        }
        Ok(Err((kind, false))) => {
            job.await
                .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
            Err(NativeManagementError::new(kind))
        }
        Ok(Err((kind, true))) => {
            let mut error = NativeManagementError::new(kind);
            error._retained = Some(Retained::Service { _job: job });
            Err(error)
        }
        Err(_) => {
            let mut error = NativeManagementError::new(ErrorKind::Unknown);
            error._retained = Some(Retained::Service { _job: job });
            Err(error)
        }
    }
}

/// Only the exact launchd-registered PID/birth/code identity can obtain this
/// scope. Shell invocation and lookalike environment variables grant nothing.
pub async fn run(
    state_dir: &Path,
    component: NativeComponent,
    cancel: tokio_util::sync::CancellationToken,
    events: tokio::sync::mpsc::Sender<crate::foreground::ForegroundEvent>,
) -> Result<serde_json::Value> {
    let scope = ServiceScope::authenticate(state_dir, role(component))
        .await
        .map_err(os)?;
    match component {
        NativeComponent::Host => {
            let outcome = crate::foreground::host_run_for_service(scope, cancel, events)
                .await
                .map_err(|error| {
                    // ForegroundError codes are static labels, not OS Display text.
                    report_failure("host_foreground", error.code());
                    NativeManagementError::new(ErrorKind::Unknown)
                })?;
            if !outcome.is_complete() {
                report_failure("host_settlement", "service_outcome_incomplete");
                return Err(NativeManagementError::new(ErrorKind::Unknown));
            }
            serde_json::to_value(outcome).map_err(|_| {
                report_failure("host_report", "service_report_serialization_failed");
                NativeManagementError::new(ErrorKind::Unknown)
            })
        }
        NativeComponent::Gateway => {
            let outcome = crate::foreground::gateway_run_for_service(scope, cancel, events)
                .await
                .map_err(|error| {
                    // ForegroundError codes are static labels, not OS Display text.
                    report_failure("gateway_foreground", error.code());
                    NativeManagementError::new(ErrorKind::Unknown)
                })?;
            if !outcome.is_complete() {
                report_failure("gateway_settlement", "service_outcome_incomplete");
                return Err(NativeManagementError::new(ErrorKind::Unknown));
            }
            serde_json::to_value(outcome).map_err(|_| {
                report_failure("gateway_report", "service_report_serialization_failed");
                NativeManagementError::new(ErrorKind::Unknown)
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::management::service_control::ServiceControlReport;

    #[test]
    #[ignore = "requires fresh STYX_TEST_MACOS_HOST_MANAGEMENT_ROOT; real C07 filesystem only, no service registration"]
    fn fresh_host_prepare_first_start_stop_preserves_original_c07_and_refuses_app_adoption() {
        use crate::store::{
            PrivateRoot,
            native_root::{create_fresh, reopen_native},
        };
        use std::{collections::BTreeMap, ffi::OsStr, fs, os::unix::fs::PermissionsExt};
        let base = PathBuf::from(std::env::var("STYX_TEST_MACOS_HOST_MANAGEMENT_ROOT").unwrap());
        assert!(base.is_absolute());
        fs::create_dir(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        let parent = PrivateRoot::open(&base).unwrap();
        let fresh = create_fresh(&parent, OsStr::new("native"))
            .unwrap_or_else(|error| panic!("fresh: {:?}", error.error()));
        let deployment = b"{\"synthetic_host_c07_only\":true,\"opaque\":900719925474099312345}\n";
        let state = NativeState {
            schema: 2,
            kind: NativeStateKind::StyxDesiredState,
            runtime_format: NativeRuntimeFormat::NativeRustV1,
            reader_contract: styx_contracts::management::ReaderContract::NativeManagementStateV1,
            scope_generation: fresh.marker().scope_generation,
            deployment_raw_sha256: Sha256Digest::of_bytes(deployment),
            mode: NativeDeploymentMode::JoinExisting,
            revision: 0,
            last_transaction: None,
            desired: NativeDesired {
                gateway: None,
                host: Some(NativeComponentDesired {
                    manager: NativeManager::ForegroundCli,
                    run: NativeRunDesired::Stopped,
                    autostart: NativeAutostartDesired::Disabled,
                }),
            },
            migration: None,
            extensions: BTreeMap::from([(
                "host_service_opaque".into(),
                serde_json::value::RawValue::from_string(
                    "{\"integer\":900719925474099312345,\"decimal\":1e99999}".into(),
                )
                .unwrap(),
            )]),
        };
        let binding = fresh
            .initialize(deployment, &state)
            .unwrap_or_else(|error| panic!("genesis: {:?}", error.error()));
        let mut transactions = NativeTransactions::open(binding)
            .unwrap_or_else(|error| panic!("transactions: {:?}", error.error()));
        let root_path = base.join("native");
        let marker = fs::read(root_path.join(".styx-native-root-v1.json")).unwrap();
        for (action, name) in [
            (ServiceAction::PrepareInstall, "host-service-prepare"),
            (ServiceAction::PrepareFirstStart, "host-service-first-start"),
        ] {
            let before = transactions.readstate().unwrap().state().clone();
            let id = TransactionId::try_from(name).unwrap();
            let target =
                prepare_target(&before, action, NativeComponent::Host, &id, before.revision)
                    .unwrap();
            transactions
                .apply_target(&serde_json::to_vec(&target).unwrap())
                .unwrap();
            assert!(before.extensions_preserved_in(&target));
            assert_eq!(
                transactions.readstate().unwrap().raw_bytes(),
                serde_json::to_vec(&target).unwrap()
            );
            // A previously valid request cannot be replayed after its revision.
            assert!(
                prepare_target(&target, action, NativeComponent::Host, &id, before.revision)
                    .is_err()
            );
        }
        let before = transactions.readstate().unwrap().state().clone();
        let id = TransactionId::try_from("host-service-stop").unwrap();
        let report = commit_host_stop(&mut transactions, &before, &id, before.revision).unwrap();
        let mut stopped = transactions.readstate().unwrap().state().clone();
        assert_eq!(report.state_scope, "committed_target");
        assert_eq!(
            stopped.desired.host,
            Some(NativeComponentDesired {
                manager: NativeManager::PersistentService,
                run: NativeRunDesired::Stopped,
                autostart: NativeAutostartDesired::Enabled,
            })
        );
        assert!(before.extensions_preserved_in(&stopped));
        assert_eq!(
            fs::read(root_path.join("deployment.json")).unwrap(),
            deployment
        );
        assert_eq!(
            fs::read(root_path.join(".styx-native-root-v1.json")).unwrap(),
            marker
        );
        assert!(commit_host_stop(&mut transactions, &before, &id, before.revision).is_err());
        // Real C07 transactions for registered lifecycle intent only. This
        // fixture intentionally does not manufacture a launchd proof or invoke
        // administrator commands; native registration acceptance is separate.
        for (action, name) in [
            (ServiceAction::Disable, "host-service-disable"),
            (ServiceAction::Enable, "host-service-enable"),
            (ServiceAction::Disable, "host-service-disable-again"),
            (ServiceAction::Uninstall, "host-service-uninstall"),
            (ServiceAction::Start, "host-service-start"),
        ] {
            let before = transactions.readstate().unwrap().state().clone();
            let id = TransactionId::try_from(name).unwrap();
            let target =
                registered_target(&before, action, NativeComponent::Host, &id, before.revision)
                    .unwrap();
            transactions
                .apply_target(&serde_json::to_vec(&target).unwrap())
                .unwrap();
            assert!(before.extensions_preserved_in(&target));
            assert_eq!(
                fs::read(root_path.join("deployment.json")).unwrap(),
                deployment
            );
            assert_eq!(
                fs::read(root_path.join(".styx-native-root-v1.json")).unwrap(),
                marker
            );
            assert!(
                registered_target(&target, action, NativeComponent::Host, &id, before.revision)
                    .is_err()
            );
            if action == ServiceAction::Uninstall {
                assert_eq!(
                    target.desired.host,
                    Some(NativeComponentDesired {
                        manager: NativeManager::PersistentService,
                        run: NativeRunDesired::Stopped,
                        autostart: NativeAutostartDesired::Disabled
                    })
                );
                assert!(
                    prepare_target(
                        &target,
                        ServiceAction::PrepareFirstStart,
                        NativeComponent::Host,
                        &TransactionId::try_from("explicit-reinstall-intent").unwrap(),
                        target.revision
                    )
                    .is_ok()
                );
            }
            stopped = target;
        }
        let id = TransactionId::try_from("host-service-stop-after-start").unwrap();
        commit_host_stop(&mut transactions, &stopped, &id, stopped.revision).unwrap();
        stopped = transactions.readstate().unwrap().state().clone();
        for action in [
            ServiceAction::Start,
            ServiceAction::Enable,
            ServiceAction::Disable,
            ServiceAction::Uninstall,
        ] {
            let mut refused = stopped.clone();
            refused.desired.host.as_mut().unwrap().manager = NativeManager::AppManaged;
            let original = transactions.readstate().unwrap().raw_bytes().to_vec();
            assert!(
                registered_target(
                    &refused,
                    action,
                    NativeComponent::Host,
                    &TransactionId::try_from("refuse-app-registered-lifecycle").unwrap(),
                    refused.revision
                )
                .is_err()
            );
            assert_eq!(transactions.readstate().unwrap().raw_bytes(), original);
        }
        for component in [NativeComponent::Host, NativeComponent::Gateway] {
            let mut refused = state.clone();
            refused.desired.host.as_mut().unwrap().manager = NativeManager::AppManaged;
            let bytes_before = transactions.readstate().unwrap().raw_bytes().to_vec();
            assert!(
                prepare_target(
                    &refused,
                    ServiceAction::PrepareInstall,
                    component,
                    &TransactionId::try_from("refuse-app-manager-adoption").unwrap(),
                    refused.revision
                )
                .is_err()
            );
            assert_eq!(transactions.readstate().unwrap().raw_bytes(), bytes_before);
        }
        assert!(
            prepare_target(
                &stopped,
                ServiceAction::PrepareRecovery,
                NativeComponent::Host,
                &TransactionId::try_from("refuse-host-recovery").unwrap(),
                stopped.revision
            )
            .is_err()
        );
        drop(transactions);
        let root = PrivateRoot::open(&root_path).unwrap();
        let writer = root.try_existing_configuration_writer().unwrap();
        let binding = reopen_native(root, writer)
            .unwrap_or_else(|error| panic!("reopen: {:?}", error.error()));
        let reopened = NativeTransactions::open(binding)
            .unwrap_or_else(|error| panic!("coordinator: {:?}", error.error()));
        assert_eq!(
            reopened.readstate().unwrap().raw_bytes(),
            serde_json::to_vec(&stopped).unwrap()
        );
        drop(reopened);
        // Real public CLI opener must still refuse an App-managed root. Give
        // that separate root its own original C07 namespace before observing
        // refusal; do not substitute a DTO-only manager check for this port.
        let app = create_fresh(&parent, OsStr::new("app"))
            .unwrap_or_else(|error| panic!("app fresh: {:?}", error.error()));
        let mut app_state = state.clone();
        app_state.scope_generation = app.marker().scope_generation;
        app_state.desired.host.as_mut().unwrap().manager = NativeManager::AppManaged;
        let binding = app
            .initialize(deployment, &app_state)
            .unwrap_or_else(|error| panic!("app genesis: {:?}", error.error()));
        let app_transactions = NativeTransactions::open(binding)
            .unwrap_or_else(|error| panic!("app coordinator: {:?}", error.error()));
        let app_before = app_transactions.readstate().unwrap().raw_bytes().to_vec();
        drop(app_transactions);
        assert!(platform::service_open(&base.join("app")).is_err());
        assert_eq!(fs::read(base.join("app/state.json")).unwrap(), app_before);
        assert_eq!(
            fs::read(base.join("app/deployment.json")).unwrap(),
            deployment
        );
        drop(parent);
        fs::remove_dir_all(base).unwrap();
    }

    // Pure consumer contract only: no launchd, service registration, or native
    // process/settlement claim is made by this fixture.
    fn fixture() -> (
        NativeState,
        NativeState,
        ServiceControlReport,
        TransactionId,
    ) {
        let id: TransactionId = "mac-gateway-stop-contract".try_into().unwrap();
        let digest = Sha256Digest::of_bytes(b"consumer-contract");
        let desired = NativeComponentDesired {
            manager: NativeManager::PersistentService,
            run: NativeRunDesired::Running,
            autostart: NativeAutostartDesired::Enabled,
        };
        let before = NativeState {
            schema: 2,
            kind: NativeStateKind::StyxDesiredState,
            runtime_format: NativeRuntimeFormat::NativeRustV1,
            reader_contract: styx_contracts::management::ReaderContract::NativeManagementStateV1,
            scope_generation: digest.clone(),
            deployment_raw_sha256: digest,
            mode: NativeDeploymentMode::CreateLocal,
            revision: 4,
            last_transaction: Some(NativeStateTransaction {
                transaction_id: "previous-stop-contract".try_into().unwrap(),
                sequence: 9,
            }),
            desired: NativeDesired {
                gateway: Some(desired),
                host: Some(desired),
            },
            migration: None,
            extensions: Default::default(),
        };
        let mut after = before.clone();
        after.revision = 5;
        // Deliberate journal sequence gap, independent of revision.
        after.last_transaction = Some(NativeStateTransaction {
            transaction_id: id.clone(),
            sequence: 12,
        });
        after.desired.gateway.as_mut().unwrap().run = NativeRunDesired::Stopped;
        let hash = Sha256Digest::of_bytes(&serde_json::to_vec(&after).unwrap());
        let report = ServiceControlReport {
            schema: 1,
            transaction_id: id.clone(),
            revision: 5,
            canonical_raw_sha256: hash,
            status: "configuration_committed_stop_pending".into(),
            state_scope: "committed_target".into(),
        };
        (before, after, report, id)
    }
    #[test]
    fn mac_gateway_stop_target_binds_original_role_transaction_and_raw_canonical() {
        let (before, after, report, id) = fixture();
        let hash = report.canonical_raw_sha256.clone();
        assert!(
            validate_stop_target(
                &before,
                &after,
                &hash,
                &report,
                &id,
                NativeComponent::Gateway
            )
            .is_ok()
        );
        let mut changed = after.clone();
        changed.desired.host.as_mut().unwrap().run = NativeRunDesired::Stopped;
        assert!(
            validate_stop_target(
                &before,
                &changed,
                &hash,
                &report,
                &id,
                NativeComponent::Gateway
            )
            .is_err()
        );
        changed = after.clone();
        changed.desired.gateway.as_mut().unwrap().autostart = NativeAutostartDesired::Disabled;
        assert!(
            validate_stop_target(
                &before,
                &changed,
                &hash,
                &report,
                &id,
                NativeComponent::Gateway
            )
            .is_err()
        );
        changed = after.clone();
        changed.scope_generation = Sha256Digest::of_bytes(b"replacement-root");
        assert!(
            validate_stop_target(
                &before,
                &changed,
                &hash,
                &report,
                &id,
                NativeComponent::Gateway
            )
            .is_err()
        );
        assert!(
            validate_stop_target(
                &before,
                &after,
                &Sha256Digest::of_bytes(b"wrong-raw"),
                &report,
                &id,
                NativeComponent::Gateway
            )
            .is_err()
        );
        let mut wrong_reply = report;
        wrong_reply.status = "committed".into();
        assert!(
            validate_stop_target(
                &before,
                &after,
                &hash,
                &wrong_reply,
                &id,
                NativeComponent::Gateway
            )
            .is_err()
        );
    }
    #[test]
    fn mac_prepare_intent_refuses_manager_adoption_running_and_extra_roles() {
        let (mut before, _, _, id) = fixture();
        before.desired.host = None;
        let gateway = before.desired.gateway.as_mut().unwrap();
        gateway.manager = NativeManager::ForegroundCli;
        gateway.run = NativeRunDesired::Stopped;
        gateway.autostart = NativeAutostartDesired::Disabled;
        assert!(
            prepare_target(
                &before,
                ServiceAction::PrepareInstall,
                NativeComponent::Gateway,
                &id,
                before.revision
            )
            .is_ok()
        );
        let mut refused = before.clone();
        refused.desired.gateway.as_mut().unwrap().manager = NativeManager::AppManaged;
        assert!(
            prepare_target(
                &refused,
                ServiceAction::PrepareInstall,
                NativeComponent::Gateway,
                &id,
                before.revision
            )
            .is_err()
        );
        refused = before.clone();
        refused.desired.gateway.as_mut().unwrap().run = NativeRunDesired::Running;
        assert!(
            prepare_target(
                &refused,
                ServiceAction::PrepareInstall,
                NativeComponent::Gateway,
                &id,
                before.revision
            )
            .is_err()
        );
        refused = before.clone();
        refused.desired.host = refused.desired.gateway;
        assert!(
            prepare_target(
                &refused,
                ServiceAction::PrepareInstall,
                NativeComponent::Gateway,
                &id,
                before.revision
            )
            .is_err()
        );
        assert!(
            prepare_target(
                &before,
                ServiceAction::PrepareFirstStart,
                NativeComponent::Gateway,
                &id,
                before.revision
            )
            .is_err()
        );
        assert!(
            prepare_target(
                &before,
                ServiceAction::PrepareInstall,
                NativeComponent::Gateway,
                &id,
                before.revision + 1
            )
            .is_err()
        );
    }
    #[test]
    fn mac_failed_service_recovery_intent_preserves_identity_and_refuses_adoption() {
        let (mut before, _, _, id) = fixture();
        before.desired.host = None;
        // The parser/policy target is not failed-generation authority: only
        // manage's retained native proof plus leases can publish this target.
        let target = prepare_target(
            &before,
            ServiceAction::PrepareRecovery,
            NativeComponent::Gateway,
            &id,
            before.revision,
        )
        .unwrap();
        let mut expected = before.clone();
        let gateway = expected.desired.gateway.as_mut().unwrap();
        gateway.run = NativeRunDesired::Stopped;
        gateway.autostart = NativeAutostartDesired::Disabled;
        expected.revision += 1;
        expected.last_transaction = Some(NativeStateTransaction {
            transaction_id: id.clone(),
            sequence: 10,
        });
        assert_eq!(
            serde_json::to_vec(&target).unwrap(),
            serde_json::to_vec(&expected).unwrap()
        );
        assert!(
            prepare_target(
                &target,
                ServiceAction::PrepareRecovery,
                NativeComponent::Gateway,
                &id,
                target.revision
            )
            .is_err()
        );
        assert!(
            prepare_target(
                &before,
                ServiceAction::PrepareRecovery,
                NativeComponent::Gateway,
                &id,
                before.revision + 1
            )
            .is_err()
        );
        for mutate in [
            |s: &mut NativeState| s.desired.host = s.desired.gateway,
            |s: &mut NativeState| {
                s.desired.gateway.as_mut().unwrap().manager = NativeManager::AppManaged
            },
            |s: &mut NativeState| {
                s.desired.gateway.as_mut().unwrap().manager = NativeManager::ForegroundCli
            },
            |s: &mut NativeState| {
                s.desired.gateway.as_mut().unwrap().autostart = NativeAutostartDesired::Disabled
            },
            |s: &mut NativeState| s.mode = NativeDeploymentMode::JoinExisting,
        ] {
            let mut changed = before.clone();
            mutate(&mut changed);
            assert!(
                prepare_target(
                    &changed,
                    ServiceAction::PrepareRecovery,
                    NativeComponent::Gateway,
                    &id,
                    changed.revision
                )
                .is_err()
            );
        }
    }
    #[test]
    fn mac_gateway_stop_never_accepts_replayed_or_app_owned_transition() {
        let (mut before, mut after, mut report, id) = fixture();
        after.last_transaction.as_mut().unwrap().sequence = 9;
        assert!(
            validate_stop_target(
                &before,
                &after,
                &report.canonical_raw_sha256,
                &report,
                &id,
                NativeComponent::Gateway
            )
            .is_err()
        );
        after.last_transaction.as_mut().unwrap().sequence = 12;
        report.transaction_id = "foreign-stop-contract".try_into().unwrap();
        assert!(
            validate_stop_target(
                &before,
                &after,
                &report.canonical_raw_sha256,
                &report,
                &id,
                NativeComponent::Gateway
            )
            .is_err()
        );
        before.desired.gateway.as_mut().unwrap().manager = NativeManager::AppManaged;
        assert!(
            validate_stop_target(
                &before,
                &after,
                &report.canonical_raw_sha256,
                &report,
                &id,
                NativeComponent::Gateway
            )
            .is_err()
        );
    }
}
