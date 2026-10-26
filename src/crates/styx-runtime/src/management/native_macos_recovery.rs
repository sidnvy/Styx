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
fn completed(
    transactions: NativeTransactions,
    committed: crate::store::native_transaction::NativeCommitResult,
    operation: &'static str,
) -> Result<NativeManagementReport> {
    let transaction = NativeTransactionReport {
        transaction_id: committed.transaction_id,
        sequence: committed.committed.sequence,
        observed_stage: Some(DurableStage::Committed),
        receipt: Some(committed.committed),
        recovered: committed.recovered,
    };
    // Reopening an earlier Committed transaction proves historical validation,
    // not whether an ordinary Host is running now.
    let result = platform::report(&transactions, operation, Some(transaction));
    result.map_err(|error| error.keep(transactions))
}
fn prepare(
    path: PathBuf,
    id: TransactionId,
    runtime: Handle,
    permit: SemaphorePermit<'static>,
) -> Result<Prepared> {
    // Read-only format routing, before acquiring ANY configuration writer.
    // A race is refused by the selected route under its one original writer.
    let root = crate::store::PrivateRoot::open(&path)
        .map_err(|_| NativeManagementError::new(ErrorKind::Unavailable))?;
    if root
        .ensure_absent(crate::store::native_root::NATIVE_MARKER_FILE)
        .is_ok()
    {
        return crate::store::native_transaction::begin_mac_legacy_recovery(
            path, id, None, runtime, permit,
        )
        .map(Prepared::Running)
        .map_err(migration_error);
    }
    let transactions = platform::open(&path)?;
    let selected = (|| -> Result<bool> {
        let state = transactions
            .readstate()
            .map_err(NativeManagementError::transaction)?;
        platform::require_state(state.state(), false)?;
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
        // Ordinary desired-state recovery keeps THIS coordinator and permit.
        return platform::recover_owned(transactions, &path, &id).map(Prepared::Complete);
    }
    match transactions
        .begin_mac_migration_recovery(path, id, None, runtime, permit)
        .map_err(migration_error)?
    {
        MacMigrationRecoveryStart::Complete(transactions, result) => {
            completed(transactions, result, "recover_migration").map(Prepared::Complete)
        }
        MacMigrationRecoveryStart::Running(task) => Ok(Prepared::Running(task)),
    }
}
pub(super) async fn recover(path: PathBuf, id: TransactionId) -> Result<NativeManagementReport> {
    let permit = WORKERS
        .try_acquire()
        .map_err(|_| NativeManagementError::new(ErrorKind::Busy))?;
    let runtime = Handle::current();
    // Once started, dropping this JoinHandle never aborts acquisition/recovery.
    // The permit moves into the actual recovery job, including its Unknown path.
    let prepared = tokio::task::spawn_blocking(move || prepare(path, id, runtime, permit))
        .await
        .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))??;
    match prepared {
        Prepared::Complete(report) => Ok(report),
        Prepared::Running(task) => finish(task, "recover_migration").await,
    }
}
async fn finish(
    task: MacMigrationRecovery,
    operation: &'static str,
) -> Result<NativeManagementReport> {
    let (transactions, result, permit) = task.finish().await.map_err(migration_error)?;
    // Retain the original budget through reporting after the real task joins.
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        completed(transactions, result, operation).map(|mut report| {
            report.configuration_only = false;
            report.runtime_health = "validation_workers_joined_runtime_not_observed";
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
) -> Result<NativeManagementReport> {
    let permit = WORKERS
        .try_acquire()
        .map_err(|_| NativeManagementError::new(ErrorKind::Busy))?;
    let runtime = Handle::current();
    let task = tokio::task::spawn_blocking(move || {
        let raw = platform::private_file(&selection_path, NATIVE_STATE_BYTES)?;
        let selection: NativeRuntimeSelection = serde_json::from_slice(raw.bytes())
            .map_err(|_| NativeManagementError::new(ErrorKind::Invalid))?;
        let candidate = Arc::new(
            crate::release::verify_selected(&selection)
                .map_err(|_| NativeManagementError::new(ErrorKind::Invalid))?,
        );
        crate::store::native_transaction::begin_mac_host_migration(
            path, id, candidate, run, None, runtime, permit,
        )
        .map_err(migration_error)
    })
    .await
    .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))??;
    finish(task, "migrate").await
}
