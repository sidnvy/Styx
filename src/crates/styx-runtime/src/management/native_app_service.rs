//! Original App-scope service composition. Returned reports are read-only DATA;
//! only the retained HostScope may request the closed typed C07 transfer.
use super::*;

#[derive(Serialize)]
pub(crate) struct AppServiceClientReport {
    pub configuration: NativeManagementReport,
    pub runtime_selection: NativeRuntimeSelection,
    pub registration: &'static str,
    pub os: Option<serde_json::Value>,
    pub error: Option<&'static str>,
}

#[cfg(target_os = "macos")]
fn read_client(scope: &Arc<crate::app::HostScope>) -> Result<Option<AppServiceClientReport>> {
    use crate::{
        platform::macos_service::{Definition, ServiceRole},
        store::{PrivateRoot, native_state},
    };
    use styx_contracts::management::ReaderContract;
    scope
        .validate()
        .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
    // This is only a discriminator. Older App migration/update inputs may be
    // incomplete and must reach their original recovery parser. No fallback
    // from a positively identified service-transfer reader is permitted.
    let root = match PrivateRoot::open(scope.state_dir()) {
        Ok(root) => root,
        Err(_) => return Ok(None),
    };
    let raw = match root.read_raw("state.json", NATIVE_STATE_BYTES) {
        Ok(raw) => raw,
        Err(_) => return Ok(None),
    };
    #[derive(serde::Deserialize)]
    struct ReaderHint {
        reader_contract: ReaderContract,
    }
    let reader = serde_json::from_slice::<ReaderHint>(raw.bytes())
        .ok()
        .map(|hint| hint.reader_contract);
    if reader != Some(ReaderContract::NativeAppServiceTransferredStateV1) {
        return Ok(None);
    }
    let marker = root
        .read_raw(".styx-native-root-v1.json", NATIVE_MARKER_BYTES)
        .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
    let marker = native_state::decode_marker(marker.bytes())
        .map_err(|_| NativeManagementError::new(ErrorKind::Invalid))?;
    let parsed = native_state::decode_state(raw.bytes(), &marker)
        .map_err(|_| NativeManagementError::new(ErrorKind::Invalid))?;
    let state = parsed.state();
    if !state
        .desired
        .host
        .iter()
        .chain(state.desired.gateway.iter())
        .any(|role| role.manager == NativeManager::PersistentService)
    {
        return Ok(None);
    }
    // A pathname below an App container is not an adoption capability. Only the
    // complete original transfer reader is admitted to this client composition.
    if state.reader_contract != ReaderContract::NativeAppServiceTransferredStateV1
        || state.mode != NativeDeploymentMode::JoinExisting
        || state.has_migration_binding()
        || state.desired.gateway.is_some()
        || state.desired.host.is_none()
    {
        return Err(NativeManagementError::new(ErrorKind::Unsupported));
    }
    crate::store::native_host_snapshot::NativeHostSnapshot::inspect_gateway_binding_for_app_service(
        scope.state_dir(), scope.clone(),
    ).map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
    let definition =
        Definition::prepare(scope.state_dir(), ServiceRole::Host).map_err(service_error)?;
    let (_, canonical) = definition.state_observation().map_err(service_error)?;
    if canonical != parsed.raw_sha256() {
        return Err(NativeManagementError::new(ErrorKind::Conflict));
    }
    let selected = definition
        .runtime_selection()
        .map_err(service_error)?
        .clone();
    let stable = scope
        .state_dir()
        .parent()
        .ok_or_else(|| NativeManagementError::new(ErrorKind::Invalid))?
        .join("runtime-versions");
    if !Path::new(&selected.payload_path).starts_with(&stable)
        || Path::new(&selected.payload_path) == stable
    {
        return Err(NativeManagementError::new(ErrorKind::Conflict));
    }
    let registration = if definition.require_pending_registration().is_ok() {
        "not_registered"
    } else {
        "registered_unverified"
    };
    scope
        .validate()
        .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
    Ok(Some(AppServiceClientReport {
        configuration: NativeManagementReport {
            schema: 1,
            configuration_only: true,
            operation: "app_service_client",
            runtime_health: "not_observed",
            revision: state.revision,
            canonical_state_sha256: canonical,
            desired: state.desired.clone(),
            admission_fenced: false,
            transaction: None,
        },
        runtime_selection: selected,
        registration,
        os: None,
        error: None,
    }))
}
#[cfg(target_os = "macos")]
fn service_error(error: crate::platform::macos_service::ServiceError) -> NativeManagementError {
    use crate::platform::macos_service::ServiceError;
    NativeManagementError::new(match error {
        ServiceError::Invalid => ErrorKind::Invalid,
        ServiceError::Conflict => ErrorKind::Conflict,
        ServiceError::Unavailable => ErrorKind::Unavailable,
        ServiceError::Busy => ErrorKind::Busy,
        ServiceError::Unknown => ErrorKind::Unknown,
    })
}
/// This must run before App runtime-history or enrollment writer opening. A
/// registered Gateway may already retain its writer; client reads never claim it.
pub(crate) async fn inspect_for_app(
    scope: Arc<crate::app::HostScope>,
) -> Result<Option<AppServiceClientReport>> {
    #[cfg(target_os = "macos")]
    return app_blocking(scope, read_client).await;
    #[cfg(not(target_os = "macos"))]
    {
        let _ = scope;
        Ok(None)
    }
}
/// The selected stable runtime must already have been assigned by the existing
/// App staging/update operation. This function never stages or replays updates.
pub(crate) async fn transfer_for_app(
    scope: Arc<crate::app::HostScope>,
    id: TransactionId,
) -> Result<AppServiceClientReport> {
    #[cfg(target_os = "macos")]
    return app_blocking(scope, move |scope| {
        platform::require_scope(scope.state_dir(), Some(scope))?;
        let mut transactions = platform::open(scope.state_dir())?;
        let mut committed = false;
        let result = (|| {
            let state = transactions
                .readstate()
                .map_err(NativeManagementError::transaction)?;
            platform::require_state(state.state(), true)?;
            if state.state().mode != NativeDeploymentMode::JoinExisting
                || state.state().has_migration_binding()
                || state.state().desired.gateway.is_some()
                || state.state().desired.host.is_none()
            {
                return Err(NativeManagementError::new(ErrorKind::Unsupported));
            }
            crate::store::native_host_snapshot::NativeHostSnapshot::inspect_gateway_binding_for_app(
                scope.state_dir(), scope.clone(),
            ).map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
            let selected = state
                .state()
                .runtime_selection()
                .map_err(|_| NativeManagementError::new(ErrorKind::Invalid))?
                .ok_or_else(|| NativeManagementError::new(ErrorKind::Invalid))?;
            let release = crate::release::verify_selected(&selected)
                .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
            let sequence = transactions
                .runtime_update_high_water()
                .map_err(NativeManagementError::transaction)?
                .checked_add(1)
                .ok_or_else(|| NativeManagementError::new(ErrorKind::Invalid))?;
            transactions
                .transfer_app_to_service(scope.clone(), release, id, sequence)
                .map_err(NativeManagementError::transaction)?;
            committed = true;
            read_client(scope)?.ok_or_else(|| NativeManagementError::new(ErrorKind::Unknown))
        })();
        match result {
            Ok(report) => Ok(report),
            Err(_error) if committed || transactions.has_app_service_custody() => {
                // Even a curated precondition code after custody acquisition is
                // unresolved original ownership, never permission to retry.
                Err(NativeManagementError::new(ErrorKind::Unknown).keep(transactions))
            }
            Err(error) => Err(error.keep(transactions)),
        }
    })
    .await;
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (scope, id);
        Err(NativeManagementError::new(ErrorKind::Unsupported))
    }
}

pub(crate) async fn refresh_for_app(
    scope: Arc<crate::app::HostScope>,
) -> Result<AppServiceClientReport> {
    let report = inspect_for_app(scope.clone())
        .await?
        .ok_or_else(|| NativeManagementError::new(ErrorKind::Conflict))?;
    #[cfg(target_os = "macos")]
    let mut report = report;
    #[cfg(target_os = "macos")]
    if report.registration != "not_registered" {
        match service::manage_for_app(
            scope,
            service::ServiceAction::Status,
            NativeComponent::Host,
            None,
            None,
        )
        .await
        {
            Ok(status)
                if status.revision == report.configuration.revision
                    && status.runtime_selection == report.runtime_selection =>
            {
                report.registration = "observed";
                report.os = status.os;
            }
            Ok(_) => {
                report.registration = "unknown";
                report.error = Some("app_service_state_changed");
            }
            Err(error) => {
                report.registration = "unknown";
                report.error = Some(error.code());
            }
        }
    }
    Ok(report)
}

#[derive(Clone, Copy)]
pub(crate) enum AppServiceAction {
    PrepareFirstStart,
    Stop,
}
pub(crate) async fn manage_for_app(
    scope: Arc<crate::app::HostScope>,
    action: AppServiceAction,
    id: TransactionId,
    revision: u64,
) -> Result<serde_json::Value> {
    #[cfg(target_os = "macos")]
    {
        let action = match action {
            AppServiceAction::PrepareFirstStart => service::ServiceAction::PrepareFirstStart,
            AppServiceAction::Stop => service::ServiceAction::Stop,
        };
        let report = service::manage_for_app(
            scope,
            action,
            NativeComponent::Host,
            Some(id),
            Some(revision),
        )
        .await?;
        serde_json::to_value(report).map_err(|_| NativeManagementError::new(ErrorKind::Unknown))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (scope, action, id, revision);
        Err(NativeManagementError::new(ErrorKind::Unsupported))
    }
}
