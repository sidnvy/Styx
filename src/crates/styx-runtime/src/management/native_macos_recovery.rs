//! Existing `recover` command routing under one acquired configuration owner.
//! Selection is read under that owner, never from an unlocked fallback probe.
use super::*;
use crate::store::native_transaction::{MacMigrationRecovery, MacMigrationRecoveryStart};
use tokio::{runtime::Handle, sync::SemaphorePermit};

enum Prepared {
    Complete(NativeManagementReport),
    Running(MacMigrationRecovery),
}
fn migration_error(
    error: Box<crate::store::native_transaction::MacMigrationRecoveryFailure>,
) -> NativeManagementError {
    let mut report = NativeManagementError::transaction(error.error());
    report._retained = Some(Retained::MacMigration { _owner: error });
    report
}
fn prepare(
    path: PathBuf,
    id: TransactionId,
    runtime: Handle,
    permit: SemaphorePermit<'static>,
    scope: Option<Arc<crate::app::HostScope>>,
) -> Result<Prepared> {
    platform::require_scope(&path, scope.as_ref())?;
    // Read-only format routing, before acquiring ANY configuration writer.
    // A race is refused by the selected route under its one original writer.
    let root = crate::store::PrivateRoot::open(&path)
        .map_err(|_| NativeManagementError::new(ErrorKind::Unavailable))?;
    if root
        .ensure_absent(crate::store::native_root::NATIVE_MARKER_FILE)
        .is_ok()
    {
        return crate::store::native_transaction::begin_mac_legacy_recovery(
            path, id, scope, runtime, permit,
        )
        .map(Prepared::Running)
        .map_err(migration_error);
    }
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
        // Ordinary desired-state recovery keeps THIS coordinator and permit.
        return platform::recover_owned(transactions, &path, &id).map(Prepared::Complete);
    }
    match transactions
        .begin_mac_migration_recovery(path, id, scope.clone(), runtime, permit)
        .map_err(migration_error)?
    {
        MacMigrationRecoveryStart::Complete(transactions, result) => {
            completed_migration(transactions, result, "recover_migration", scope.as_ref())
                .map(Prepared::Complete)
        }
        MacMigrationRecoveryStart::Running(task) => Ok(Prepared::Running(task)),
    }
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
    // Once started, dropping this JoinHandle never aborts acquisition/recovery.
    // The permit moves into the actual recovery job, including its Unknown path.
    let reporting_scope = scope.clone();
    let prepared = tokio::task::spawn_blocking(move || {
        let retained = scope.clone();
        prepare(path, id, runtime, permit, scope).map_err(|error| match retained {
            Some(scope) => error.with_app_scope(scope),
            None => error,
        })
    })
    .await
    .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))??;
    match prepared {
        Prepared::Complete(report) => Ok(report),
        Prepared::Running(task) => finish(task, "recover_migration", reporting_scope).await,
    }
}
async fn finish(
    task: MacMigrationRecovery,
    operation: &'static str,
    scope: Option<Arc<crate::app::HostScope>>,
) -> Result<NativeManagementReport> {
    let (transactions, result, permit) = task.finish().await.map_err(migration_error)?;
    let recovered = result.recovered;
    // Retain the original budget through reporting after the real task joins.
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        completed_migration(transactions, result, operation, scope.as_ref()).map(|mut report| {
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
        crate::store::native_transaction::begin_mac_host_migration(
            path,
            id,
            candidate,
            run,
            scope.clone(),
            runtime,
            permit,
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
