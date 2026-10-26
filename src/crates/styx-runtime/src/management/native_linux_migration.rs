//! Explicit original create-local migration. The entry owns all effects; this
//! boundary validates the immutable candidate and reads the committed outcome.
use super::*;
use crate::migration::{legacy_entry, legacy_service::TransitionError};

fn error_kind(error: TransitionError) -> ErrorKind {
    match error {
        TransitionError::Conflict => ErrorKind::Conflict,
        TransitionError::Unavailable => ErrorKind::Unavailable,
        TransitionError::Busy => ErrorKind::Busy,
        TransitionError::Unsupported => ErrorKind::Unsupported,
        TransitionError::Unknown => ErrorKind::Unknown,
    }
}
pub(super) async fn migrate(
    path: PathBuf,
    selection_path: PathBuf,
    id: TransactionId,
    run: NativeRunDesired,
) -> Result<NativeManagementReport> {
    // Running services require their own explicit lifecycle owner. This entry
    // migrates to Stopped and never derives new run intent from old service steps.
    if run != NativeRunDesired::Stopped {
        return Err(NativeManagementError::new(ErrorKind::Unsupported));
    }
    let role = NativeComponentDesired {
        manager: NativeManager::ForegroundCli,
        run,
        autostart: NativeAutostartDesired::Disabled,
    };
    let desired = NativeDesired {
        host: Some(role),
        gateway: Some(role),
    };
    let expected_desired = desired.clone();
    let expected_id = id.clone();
    let report_path = path.clone();
    let (candidate, selection) = blocking(move || {
        platform::require_scope(&path, None)?;
        let raw = platform::private_file(&selection_path, NATIVE_STATE_BYTES)?;
        let selection: NativeRuntimeSelection = serde_json::from_slice(raw.bytes())
            .map_err(|_| NativeManagementError::new(ErrorKind::Invalid))?;
        let candidate = crate::release::verify_selected(&selection)
            .map_err(|_| NativeManagementError::new(ErrorKind::Invalid))?;
        Ok((candidate, selection))
    })
    .await?;
    let task = legacy_entry::start(report_path.clone(), candidate, id, desired)
        .map_err(|error| NativeManagementError::new(error_kind(error)))?;
    let completed = task.finish().await.map_err(|owner| NativeManagementError {
        kind: error_kind(owner.code()),
        _retained: Some(Retained::LinuxMigration {
            _owner: Box::new(owner),
        }),
        _app_scope: None,
        runtime_update_transaction: None,
    })?;
    // No metadata flag alone grants success. Read the same formal committed
    // migration and its preserved materials after the actual owner task joined.
    blocking(move || {
        let snapshot =
            crate::store::committed_runtime::CommittedRuntimeSnapshot::open(&report_path)
                .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
        snapshot
            .revalidate()
            .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
        let state = snapshot.state();
        let receipt = snapshot
            .committed_receipt()
            .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?
            .clone();
        let digest = Sha256Digest::of_bytes(snapshot.canonical());
        if completed.transaction_id != expected_id
            || completed.canonical_raw_sha256 != digest
            || receipt.transaction_id != expected_id
            || state.desired != expected_desired
            || snapshot.selection() != &selection
            || !completed.report.migration_committed
        {
            return Err(NativeManagementError::new(ErrorKind::Unknown));
        }
        // Reacquire the actual original writer and reconcile the same committed
        // journal. A read-only snapshot alone cannot report open admission.
        let root = crate::store::PrivateRoot::open(&report_path)
            .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
        let writer = root
            .try_configuration_writer()
            .map_err(|_| NativeManagementError::new(ErrorKind::Busy))?;
        let owner = crate::store::OwnedConfigurationRoot::open_existing(root, writer)
            .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
        let snapshot = std::sync::Arc::new(snapshot);
        let recovered = crate::store::committed_runtime::RecoveredCommittedRuntime::reopen(
            owner.clone(),
            snapshot.clone(),
        )
        .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
        recovered
            .validate_owner(&owner)
            .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
        let state = snapshot.state();
        Ok(NativeManagementReport {
            schema: 1,
            configuration_only: false,
            operation: "migrate",
            runtime_health: "validation_workers_joined_migrated_stopped",
            revision: state.revision,
            canonical_state_sha256: digest,
            desired: state.desired.clone(),
            admission_fenced: false,
            transaction: Some(NativeTransactionReport {
                transaction_id: expected_id,
                sequence: receipt.sequence,
                observed_stage: Some(DurableStage::Committed),
                receipt: Some(receipt),
                recovered: false,
            }),
        })
    })
    .await
}
