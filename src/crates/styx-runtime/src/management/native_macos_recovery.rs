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
) -> Result<NativeManagementReport> {
    let transaction = NativeTransactionReport {
        transaction_id: committed.transaction_id,
        sequence: committed.committed.sequence,
        observed_stage: Some(DurableStage::Committed),
        receipt: Some(committed.committed),
        recovered: committed.recovered,
    };
    let result = platform::report(&transactions, "recover_migration", Some(transaction));
    result.map_err(|error| error.keep(transactions))
}
fn prepare(
    path: PathBuf,
    id: TransactionId,
    runtime: Handle,
    permit: SemaphorePermit<'static>,
) -> Result<Prepared> {
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
            completed(transactions, result).map(Prepared::Complete)
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
        Prepared::Running(task) => {
            let (transactions, result, permit) = task.finish().await.map_err(migration_error)?;
            // The original budget stays held through final report generation;
            // a new request cannot turn an already committed result into Busy.
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                completed(transactions, result)
            })
            .await
            .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?
        }
    }
}
