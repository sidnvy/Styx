//! Same original migration task and joined validation/commit tail on native OSes.
//! OS custody stays inside the original blocking worker; observing or dropping
//! a waiter cannot fabricate cancellation or transfer an unsettled writer.
use super::{ConfigurationMaintenance, NativeCanonicalCutover, OwnedConfigurationRoot};
use crate::{
    foreground::profile::load_applied_native_maintenance_profile,
    migration::{
        mac_exec_validation::MacCandidateExecProbe, mac_pair_validation::MacPairReadinessProbe,
    },
    release::VerifiedNativeRelease,
    store::{
        management::OwnedManagementJournal,
        secure_journal::{JournalError, JournalResult},
    },
};
use std::sync::Arc;
use styx_contracts::identity::TransactionId;
use tokio::{runtime::Handle, sync::oneshot, task::JoinHandle};

/// One-shot observation data, optionally transferring original owned resources.
/// A dropped observer does not abort the original blocking job or release scope.
pub(in crate::store) struct NativeMigrationObservation {
    pub(in crate::store) transaction_id: TransactionId,
    pub(in crate::store) stage: &'static str,
    pub(in crate::store) local_exec_report: Option<Vec<u8>>,
    pub(in crate::store) pair_admission_report: Option<Vec<u8>>,
    pub(in crate::store) rejected_scope: Option<Box<NativeMigrationRejectedScope>>,
    pub(in crate::store) committed_scope: Option<Box<NativeMigrationCommittedScope>>,
}
/// Retained original capabilities after a strictly ZERO-effect rejection.
/// No Clone/Serde and no fence-clear method; caller gets its original scope back.
pub(in crate::store) struct NativeMigrationRejectedScope {
    pub(in crate::store) permit: Arc<tokio::sync::SemaphorePermit<'static>>,
    pub(in crate::store) app_scope: Option<Arc<crate::app::HostScope>>,
    pub(in crate::store) owner: OwnedConfigurationRoot,
    pub(in crate::store) maintenance: Arc<ConfigurationMaintenance>,
    pub(in crate::store) journal: OwnedManagementJournal,
    pub(in crate::store) candidate: Arc<VerifiedNativeRelease>,
}
/// Final commit returned the SAME configuration writer and domain journal.
/// Only the actual joined owner task returns this scope to an ordinary caller.
pub(in crate::store) struct NativeMigrationCommittedScope {
    pub(in crate::store) recovery_permit: Option<Arc<tokio::sync::SemaphorePermit<'static>>>,
    pub(in crate::store) app_scope: Option<Arc<crate::app::HostScope>>,
    pub(in crate::store) owner: OwnedConfigurationRoot,
    pub(in crate::store) journal: OwnedManagementJournal,
    pub(in crate::store) candidate: Arc<VerifiedNativeRelease>,
}
#[must_use = "retain the original non-aborted job and its observation"]
pub(in crate::store) struct NativeMigrationOwnerTask {
    observation: oneshot::Receiver<NativeMigrationObservation>,
    observed: bool,
    rejected_observed: bool,
    committed_scope: Option<Box<NativeMigrationCommittedScope>>,
    worker_joined: bool,
    worker_failed: bool,
    _job: JoinHandle<()>,
}
impl NativeMigrationOwnerTask {
    pub(in crate::store) fn from_job(
        observation: oneshot::Receiver<NativeMigrationObservation>,
        job: JoinHandle<()>,
    ) -> Self {
        Self {
            observation,
            observed: false,
            rejected_observed: false,
            committed_scope: None,
            worker_joined: false,
            worker_failed: false,
            _job: job,
        }
    }

    /// Cancelling this WAIT leaves the original receiver and job in self.
    pub(in crate::store) async fn observe(&mut self) -> JournalResult<NativeMigrationObservation> {
        if self.observed {
            return Err(JournalError::Conflict);
        }
        let mut result = (&mut self.observation)
            .await
            .map_err(|_| JournalError::Unknown);
        self.observed = true;
        if let Ok(observation) = &mut result {
            self.rejected_observed = observation.rejected_scope.is_some();
            self.committed_scope = observation.committed_scope.take();
        }
        result
    }
    /// Return the original scope only AFTER the actual worker join. Cancelling
    /// this wait retains both its handle and the scope in this task object.
    pub(in crate::store) async fn join_committed(
        &mut self,
    ) -> JournalResult<Box<NativeMigrationCommittedScope>> {
        if self.committed_scope.is_none() {
            return Err(JournalError::Conflict);
        }
        self.join_worker().await?;
        self.committed_scope.take().ok_or(JournalError::Conflict)
    }
    async fn join_worker(&mut self) -> JournalResult<()> {
        if self.worker_failed {
            return Err(JournalError::Unknown);
        }
        if !self.worker_joined {
            if (&mut self._job).await.is_err() {
                self.worker_failed = true;
                return Err(JournalError::Unknown);
            }
            self.worker_joined = true;
        }
        Ok(())
    }
    /// A zero-effect rejection actually returns from the worker. This is its
    /// real join; Unknown cannot use this port to discard scope.
    pub(in crate::store) async fn join_rejected(&mut self) -> JournalResult<()> {
        if !self.rejected_observed {
            return Err(JournalError::Conflict);
        }
        self.join_worker().await
    }
}
pub(in crate::store) async fn retain_scope<T>(
    held: T,
    sender: &mut Option<oneshot::Sender<NativeMigrationObservation>>,
    observation: NativeMigrationObservation,
) -> ! {
    if let Some(sender) = sender.take() {
        let _ = sender.send(observation);
    }
    // An Unknown effect retains every ORIGINAL value in this frame until an
    // explicit recovery consumer can reconcile it. The successful path returns.
    // There is intentionally no caller boolean that drops/clears this fence.
    loop {
        std::future::pending::<()>().await;
        std::hint::black_box(&held);
    }
}
/// Finish one already-applied original migration using actual joined probes.
/// The caller must await this inside the same non-abortable owner job: `applied`
/// borrows its original materials/C/held/token, keeping that caller frame alive.
/// No probe retry or historical-report substitution is performed here.
pub(in crate::store) async fn finish_applied_migration(
    runtime: Handle,
    owner: OwnedConfigurationRoot,
    maintenance: &ConfigurationMaintenance,
    mut journal: OwnedManagementJournal,
    candidate: Arc<VerifiedNativeRelease>,
    app_scope: Option<Arc<crate::app::HostScope>>,
    applied: NativeCanonicalCutover<'_, '_>,
    mut sender: Option<oneshot::Sender<NativeMigrationObservation>>,
    recovery_permit: Option<Arc<tokio::sync::SemaphorePermit<'static>>>,
) {
    let transaction = maintenance.transaction_id().clone();
    macro_rules! keep {
        ($result:expr, $stage:literal $(, $held:expr)* $(,)?) => {
            match $result {
                Ok(value) => value,
                Err(_) => retain_scope(
                    (&owner, &maintenance, &journal, &candidate, &app_scope,
                        &recovery_permit, &applied, $($held,)*),
                    &mut sender,
                    NativeMigrationObservation {
                        transaction_id: transaction.clone(),
                        stage: $stage,
                        local_exec_report: None,
                        pair_admission_report: None,
                        rejected_scope: None,
                        committed_scope: None,
                    },
                ).await,
            }
        };
    }
    let profile = keep!(
        load_applied_native_maintenance_profile(&applied),
        "unknown_maintenance_profile",
        &applied
    );
    let mut probe = keep!(
        MacCandidateExecProbe::prepare(&profile),
        "unknown_probe_prepare",
        &applied,
        &profile
    );
    let report_raw = keep!(
        probe.run_joined(&runtime).and_then(|report| {
            serde_json::to_vec(report)
                .map_err(|_| crate::migration::mac_exec_validation::MacExecValidationError::Unknown)
        }),
        "unknown_exec_cleanup_or_report",
        &applied,
        &profile,
        &probe
    );
    keep!(
        probe.revalidate_success(),
        "unknown_after_local_probe",
        &applied,
        &profile,
        &probe
    );
    keep!(
        applied.validate_applied(),
        "unknown_after_local_applied",
        &applied,
        &profile,
        &probe
    );
    let mut pair_probe = keep!(
        MacPairReadinessProbe::prepare(&profile),
        "unknown_pair_probe_prepare",
        &profile,
        &probe,
        &applied,
    );
    let pair_report_raw = keep!(
        pair_probe.run_joined(&runtime).and_then(|report| {
            serde_json::to_vec(report)
                .map_err(|_| crate::migration::mac_pair_validation::MacPairValidationError::Unknown)
        }),
        "unknown_original_pair_readiness_or_cleanup",
        &profile,
        &probe,
        &pair_probe,
        &applied,
    );
    keep!(
        pair_probe.revalidate_success(),
        "unknown_pair_revalidation",
        &profile,
        &probe,
        &pair_probe,
        &applied,
    );
    keep!(
        probe.revalidate_success(),
        "unknown_local_effect_after_pair_validation",
        &profile,
        &probe,
        &pair_probe,
        &applied,
    );
    keep!(
        app_scope.as_ref().map_or(Ok(()), |scope| {
            scope.validate().map_err(|_| JournalError::Unknown)
        }),
        "unknown_app_scope_before_commit",
        &profile,
        &probe,
        &pair_probe,
        &applied,
    );
    let committed = keep!(
        applied.commit_validated(&mut journal, &mut probe, &mut pair_probe),
        "unknown_final_validation_or_commit",
        &profile,
        &probe,
        &pair_probe,
        &applied,
    );
    keep!(
        committed.release_admission(&journal, &mut probe, &mut pair_probe, app_scope.as_deref()),
        "unknown_committed_admission_release",
        &profile,
        &probe,
        &pair_probe,
        &applied,
    );
    // Both workers are already settled. Drop the local execution lease BEFORE
    // transferring the same owner; it must not obstruct ordinary runtime start.
    drop(pair_probe);
    drop(probe);
    if let Some(sender) = sender.take() {
        let _ = sender.send(NativeMigrationObservation {
            transaction_id: transaction,
            stage: "committed_admission_released",
            local_exec_report: Some(report_raw),
            pair_admission_report: Some(pair_report_raw),
            rejected_scope: None,
            committed_scope: Some(Box::new(NativeMigrationCommittedScope {
                recovery_permit,
                app_scope,
                owner: owner.clone(),
                journal,
                candidate: candidate.clone(),
            })),
        });
    }
}
