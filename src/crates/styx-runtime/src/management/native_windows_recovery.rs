//! Windows migration routing. The original task owns all native effects and
//! reports a retained later-boot checkpoint separately from Unknown or Committed.
use super::*;
use crate::store::native_transaction::{
    WindowsMigrationPreparationFailure, WindowsMigrationRecovery,
};
use tokio::runtime::Handle;

pub(super) fn migration_error(
    owner: Box<WindowsMigrationPreparationFailure>,
) -> NativeManagementError {
    let kind = if owner.waiting_for_later_boot() {
        ErrorKind::WaitingForRestart
    } else {
        match owner.error() {
            NativeTransactionError::InvalidInput => ErrorKind::Invalid,
            NativeTransactionError::Conflict => ErrorKind::Conflict,
            NativeTransactionError::Unsupported => ErrorKind::Unsupported,
            NativeTransactionError::UnknownInspect => ErrorKind::Unknown,
        }
    };
    NativeManagementError {
        kind,
        _retained: Some(Retained::WindowsMigrationPreparation { _owner: owner }),
        _app_scope: None,
        runtime_update_transaction: None,
    }
}
async fn finish(
    task: WindowsMigrationRecovery,
    operation: &'static str,
    scope: Option<Arc<crate::app::HostScope>>,
) -> Result<NativeManagementReport> {
    let (transactions, committed, permit) = task.finish().await.map_err(migration_error)?;
    let recovered = committed.recovered;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        completed_migration(transactions, committed, operation, scope.as_ref()).map(|mut report| {
            report.configuration_only = false;
            report.runtime_health = if recovered {
                "recorded_validation_rechecked_runtime_not_observed"
            } else {
                "validation_workers_joined_runtime_not_observed"
            };
            report
        })
    })
    .await
    .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?
}
pub(super) async fn migrate(
    path: PathBuf,
    selection_path: PathBuf,
    id: TransactionId,
    run: NativeRunDesired,
    scope: Option<Arc<crate::app::HostScope>>,
    approved: Sha256Digest,
) -> Result<NativeManagementReport> {
    let permit = WORKERS
        .try_acquire()
        .map_err(|_| NativeManagementError::new(ErrorKind::Busy))?;
    let runtime = Handle::current();
    let reporting_scope = scope.clone();
    let task = tokio::task::spawn_blocking(move || {
        platform::require_scope(&path, scope.as_ref())?;
        let raw = platform::private_file(&selection_path, NATIVE_STATE_BYTES)?;
        let selection: NativeRuntimeSelection = serde_json::from_slice(raw.bytes())
            .map_err(|_| NativeManagementError::new(ErrorKind::Invalid))?;
        let candidate = Arc::new(
            crate::release::verify_selected(&selection)
                .map_err(|_| NativeManagementError::new(ErrorKind::Invalid))?,
        );
        crate::store::native_transaction::begin_windows_host_migration(
            path,
            id,
            candidate,
            run,
            scope.clone(),
            runtime,
            permit,
            approved,
        )
        .map_err(migration_error)
        .map_err(|error| match scope {
            Some(scope) => error.with_app_scope(scope),
            None => error,
        })
    })
    .await
    .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))??;
    finish(task, "migrate", reporting_scope).await
}
pub(super) async fn recover(
    path: PathBuf,
    id: TransactionId,
    scope: Option<Arc<crate::app::HostScope>>,
) -> Result<NativeManagementReport> {
    let permit = WORKERS
        .try_acquire()
        .map_err(|_| NativeManagementError::new(ErrorKind::Busy))?;
    let runtime = Handle::current();
    let reporting_scope = scope.clone();
    enum Prepared {
        Report(NativeManagementReport),
        Running(WindowsMigrationRecovery),
    }
    let prepared = tokio::task::spawn_blocking(move || {
        platform::require_scope(&path, scope.as_ref())?;
        let root = crate::store::PrivateRoot::open(&path)
            .map_err(|_| NativeManagementError::new(ErrorKind::Unavailable))?;
        if root
            .ensure_absent(crate::store::native_root::NATIVE_MARKER_FILE)
            .is_ok()
        {
            return crate::store::native_transaction::begin_windows_legacy_recovery(
                path,
                id,
                scope.clone(),
                runtime,
                permit,
            )
            .map(Prepared::Running)
            .map_err(migration_error)
            .map_err(|error| match scope {
                Some(scope) => error.with_app_scope(scope),
                None => error,
            });
        }
        // Native format is opened once under its original writer. Both
        // migration and ordinary recovery retain this exact coordinator.
        let transactions = platform::open(&path)?;
        let selected = (|| -> Result<bool> {
            let state = transactions
                .readstate()
                .map_err(NativeManagementError::transaction)?;
            platform::require_state(state.state(), scope.is_some())?;
            let migration = state
                .state()
                .migration_v2()
                .map_err(|_| NativeManagementError::new(ErrorKind::Invalid))?;
            Ok(migration.is_some_and(|binding| binding.transaction_id == id))
        })();
        let selected = match selected {
            Ok(selected) => selected,
            Err(error) => return Err(error.keep(transactions)),
        };
        if !selected {
            if scope.is_some() {
                return Err(NativeManagementError::new(ErrorKind::Conflict).keep(transactions));
            }
            return platform::recover_owned(transactions, &path, &id).map(Prepared::Report);
        }
        transactions
            .begin_windows_migration_recovery(path, id, scope.clone(), runtime, permit)
            .map(Prepared::Running)
            .map_err(migration_error)
            .map_err(|error| match scope {
                Some(scope) => error.with_app_scope(scope),
                None => error,
            })
    })
    .await
    .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))??;
    match prepared {
        Prepared::Report(report) => Ok(report),
        Prepared::Running(task) => finish(task, "recover_migration", reporting_scope).await,
    }
}
