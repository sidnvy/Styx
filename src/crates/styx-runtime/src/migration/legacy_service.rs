//! One existing writer/maintenance, original service scope and retained native
//! candidate. No new journal, credential writer, activation or ordinary dispatch.
use crate::store::legacy_handoff::LegacyFenceError;
use crate::{
    platform::linux::manager::legacy,
    release::VerifiedNativeRelease,
    store::{
        ConfigurationMaintenance, OwnedConfigurationRoot,
        legacy_handoff::{LegacyFenceFailure, LegacyMaterialInput, LegacyWriterFence},
    },
};
use std::{path::Path, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TransitionError {
    #[error("legacy_service_conflict")]
    Conflict,
    #[error("legacy_service_unavailable")]
    Unavailable,
    #[error("legacy_service_busy")]
    Busy,
    #[error("legacy_service_unsupported")]
    Unsupported,
    #[error("legacy_service_unknown")]
    Unknown,
}
fn classify(error: legacy::LegacyError) -> TransitionError {
    match error {
        legacy::LegacyError::Invalid | legacy::LegacyError::Conflict => TransitionError::Conflict,
        legacy::LegacyError::Unavailable => TransitionError::Unavailable,
        legacy::LegacyError::Unsupported => TransitionError::Unsupported,
        legacy::LegacyError::Busy => TransitionError::Busy,
        legacy::LegacyError::Unknown => TransitionError::Unknown,
    }
}
enum RetainedFailure {
    Initial {
        owner: OwnedConfigurationRoot,
        _maintenance: ConfigurationMaintenance,
    },
    Fence(LegacyFenceFailure),
    Capture(legacy::LegacyCaptureFailure),
}
#[must_use = "retain the original failure authority; it is not a successful handoff"]
pub struct PreparationFailure {
    code: TransitionError,
    retained: RetainedFailure,
}
impl PreparationFailure {
    pub fn code(&self) -> TransitionError {
        self.code
    }
    pub fn configuration_root(&self) -> &OwnedConfigurationRoot {
        match &self.retained {
            RetainedFailure::Initial { owner, .. } => owner,
            RetainedFailure::Fence(failure) => failure.configuration_root(),
            RetainedFailure::Capture(failure) => failure.fence().configuration_root(),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureStatus {
    Pending,
    Ready,
    Failed(TransitionError),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettlementStatus {
    Registered,
    Stopping,
    Unknown,
    Confirmed,
    Consumed,
}
#[derive(Clone, Copy, Debug)]
pub struct SettlementObservation {
    pub status: SettlementStatus,
    pub term_attempted: bool,
    pub signal_accepted: bool,
    pub original_main_exited: bool,
    pub original_cgroup_empty: bool,
    pub manager_reported_success: bool,
    pub worker_joined: bool,
}
fn observe(value: legacy::LegacySettlementObservation) -> SettlementObservation {
    SettlementObservation {
        status: match value.phase {
            legacy::SettlementPhase::Registered => SettlementStatus::Registered,
            legacy::SettlementPhase::Stopping => SettlementStatus::Stopping,
            legacy::SettlementPhase::Unknown => SettlementStatus::Unknown,
            legacy::SettlementPhase::Confirmed => SettlementStatus::Confirmed,
            legacy::SettlementPhase::Consumed => SettlementStatus::Consumed,
        },
        term_attempted: value.term_attempted,
        signal_accepted: value.signal_accepted,
        original_main_exited: value.original_main_exited,
        original_cgroup_empty: value.original_cgroup_empty,
        manager_reported_success: value.manager_reported_success,
        worker_joined: value.worker_joined,
    }
}
/// Trusted in-process migration resource. Dropping a waiter never declares the
/// old scope stopped; the manager retains any unresolved original fence/job.
/// Caller-selected materials are NOT a complete C07 preservation manifest.
#[must_use]
pub struct LegacyServiceTransition {
    target: Arc<VerifiedNativeRelease>,
    capture: legacy::LegacyCaptureTicket,
    scope: Option<Arc<legacy::LegacyManagedScope>>,
    failure: Option<legacy::LegacyCaptureFailure>,
}
impl LegacyServiceTransition {
    pub async fn prepare(
        state_dir: &Path,
        owner: OwnedConfigurationRoot,
        maintenance: ConfigurationMaintenance,
        materials: &[LegacyMaterialInput],
        target: VerifiedNativeRelease,
    ) -> Result<Self, PreparationFailure> {
        let target = Arc::new(target);
        let initial = |code, owner, maintenance| PreparationFailure {
            code,
            retained: RetainedFailure::Initial {
                owner,
                _maintenance: maintenance,
            },
        };
        // The ownership-changing filesystem section cannot be abandoned in the
        // middle of a write/fsync. Refuse unsupported executors before mutation.
        if !matches!(
            tokio::runtime::Handle::try_current().map(|h| h.runtime_flavor()),
            Ok(tokio::runtime::RuntimeFlavor::MultiThread)
        ) {
            return Err(initial(TransitionError::Unsupported, owner, maintenance));
        }
        let inputs = match legacy::load_inputs(state_dir).await {
            Ok(inputs) => inputs,
            Err(error) => return Err(initial(classify(error), owner, maintenance)),
        };
        if let Err(error) = legacy::verify_candidate(inputs.clone(), target.clone()).await {
            return Err(initial(classify(error), owner, maintenance));
        }
        let permit = match legacy::preparation_permit() {
            Ok(permit) => permit,
            Err(error) => return Err(initial(classify(error), owner, maintenance)),
        };
        // No await separates fence creation from synchronous owned capture-job
        // registration. block_in_place hands unrelated tasks to other workers;
        // this same stack retains every original handle until the section ends.
        let fence = tokio::task::block_in_place(|| {
            let _permit = permit;
            let host = match inputs.open_host_root() {
                Ok(host) if host.identity() == inputs.host_root_identity() => host,
                _ => return Err(initial(TransitionError::Conflict, owner, maintenance)),
            };
            LegacyWriterFence::acquire_with_service_descriptor(
                owner,
                maintenance,
                host,
                materials,
                inputs.service_descriptor(),
            )
            .map_err(|failure| PreparationFailure {
                code: match failure.error() {
                    LegacyFenceError::Unknown => TransitionError::Unknown,
                    LegacyFenceError::InvalidMaterials | LegacyFenceError::BusyOrUnresolved => {
                        TransitionError::Conflict
                    }
                },
                retained: RetainedFailure::Fence(failure),
            })
        })?;
        let capture = legacy::capture(inputs, fence).map_err(|failure| PreparationFailure {
            code: classify(failure.cause),
            retained: RetainedFailure::Capture(failure),
        })?;
        Ok(Self {
            target,
            capture,
            scope: None,
            failure: None,
        })
    }
    pub fn capture_status(&self) -> CaptureStatus {
        match self.capture.query() {
            legacy::CaptureState::Pending => CaptureStatus::Pending,
            legacy::CaptureState::Ready => CaptureStatus::Ready,
            legacy::CaptureState::Failed(error) => CaptureStatus::Failed(classify(error)),
        }
    }
    /// Cancellation only drops this borrow. The original ticket stays owned.
    pub async fn capture_changed(&mut self) -> CaptureStatus {
        self.capture.changed().await;
        self.capture_status()
    }
    pub fn complete_capture(&mut self) -> Result<(), TransitionError> {
        if self.scope.is_some() || self.failure.is_some() {
            return Err(TransitionError::Conflict);
        }
        match self.capture.try_complete() {
            Ok(scope) => {
                self.scope = Some(scope);
                Ok(())
            }
            Err(failure) => {
                let error = classify(failure.cause);
                if error != TransitionError::Busy {
                    self.failure = Some(failure);
                }
                Err(error)
            }
        }
    }
    pub fn begin_settlement(
        &self,
        budget: Duration,
        cancel: CancellationToken,
    ) -> Result<(), TransitionError> {
        self.scope
            .as_ref()
            .ok_or(TransitionError::Busy)?
            .begin_settlement(budget, cancel)
            .map_err(classify)
    }
    pub fn settlement_observation(&self) -> Result<Option<SettlementObservation>, TransitionError> {
        self.scope
            .as_ref()
            .ok_or(TransitionError::Busy)?
            .query_settlement()
            .map(|v| v.map(observe))
            .map_err(classify)
    }
    /// This consumes only an actually joined physical-settlement result. It
    /// does not clear maintenance, release the writer or activate native code.
    pub fn consume_settlement(&self) -> Result<SettledLegacyService, TransitionError> {
        let proof = self
            .scope
            .as_ref()
            .ok_or(TransitionError::Busy)?
            .consume_settlement()
            .map_err(classify)?;
        Ok(SettledLegacyService {
            target: self.target.clone(),
            proof,
        })
    }
}
#[must_use = "physical settlement is not legacy launch retirement or migration commit"]
pub struct SettledLegacyService {
    target: Arc<VerifiedNativeRelease>,
    proof: legacy::LegacySettlementProof,
}
impl SettledLegacyService {
    pub fn observation(&self) -> SettlementObservation {
        observe(self.proof.observation())
    }
    pub fn configuration_root(&self) -> &OwnedConfigurationRoot {
        self.proof.fence().configuration_root()
    }
    pub fn target(&self) -> &VerifiedNativeRelease {
        &self.target
    }
    pub fn descriptor_sha256(&self) -> styx_contracts::identity::Sha256Digest {
        self.proof.service_descriptor().raw_sha256()
    }
}

#[cfg(test)]
#[path = "legacy_service_tests.rs"]
mod tests;

/// The same stopped-service proof, writer and signed candidate after the original
/// credential locator was retired. This is NOT owner handoff or native admission.
#[must_use = "retirement remains pending under original maintenance; no activation"]
pub struct RetiredLegacyCredential {
    original: SettledLegacyService,
}
#[must_use = "retain original writer/fence/FDs after an uncertain retirement"]
pub struct CredentialRetirementFailure {
    code: TransitionError,
    retained: Box<SettledLegacyService>,
}
impl CredentialRetirementFailure {
    pub fn code(&self) -> TransitionError {
        self.code
    }
    pub fn configuration_root(&self) -> &OwnedConfigurationRoot {
        self.retained.configuration_root()
    }
}
pub struct CredentialRetirementObservation {
    pub transaction_id: styx_contracts::identity::TransactionId,
    pub retired_relative_path: std::path::PathBuf,
    pub original_inode_preserved: bool,
    pub original_bytes_preserved: bool,
    pub original_locator_absent: bool,
    pub retired_receipt_sha256: styx_contracts::identity::Sha256Digest,
}
impl SettledLegacyService {
    /// A synchronous owned filesystem transition: no cancellation point can
    /// abandon the original writer between Prepared, rename/fsync and receipt.
    /// Multi-thread block_in_place yields unrelated tasks; DBus sampling uses the
    /// SAME retained connection. No ordinary dispatch or execution lease opens.
    pub fn retire_legacy_credential(
        self,
    ) -> Result<RetiredLegacyCredential, CredentialRetirementFailure> {
        let handle = match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                handle
            }
            _ => {
                return Err(CredentialRetirementFailure {
                    code: TransitionError::Unsupported,
                    retained: Box::new(self),
                });
            }
        };
        let result = tokio::task::block_in_place(|| {
            handle
                .block_on(self.proof.verify_original_still_settled())
                .map_err(classify)?;
            self.proof
                .retire_credential_locator(&self.target)
                .map_err(classify)?;
            if handle
                .block_on(self.proof.verify_original_still_settled())
                .is_err()
            {
                self.proof.invalidate_credential_retirement();
                return Err(TransitionError::Unknown);
            }
            Ok(())
        });
        match result {
            Ok(()) => Ok(RetiredLegacyCredential { original: self }),
            Err(code) => Err(CredentialRetirementFailure {
                code,
                retained: Box::new(self),
            }),
        }
    }
}
impl RetiredLegacyCredential {
    pub fn configuration_root(&self) -> &OwnedConfigurationRoot {
        self.original.configuration_root()
    }
    pub fn target(&self) -> &VerifiedNativeRelease {
        self.original.target()
    }
    /// Fresh preserved-material observation, never an admission/commit port.
    pub fn observation(&self) -> Result<CredentialRetirementObservation, TransitionError> {
        let value = self
            .original
            .proof
            .credential_retirement_observation()
            .map_err(classify)?;
        Ok(CredentialRetirementObservation {
            transaction_id: value.transaction_id,
            retired_relative_path: value.retired_relative_path,
            original_inode_preserved: value.original_inode_preserved,
            original_bytes_preserved: value.original_bytes_preserved,
            original_locator_absent: value.original_locator_absent,
            retired_receipt_sha256: value.retired_receipt_sha256,
        })
    }
}

/// Non-transferable provenance for maintenance validation only. Arc shares the
/// SAME original writer/proof/candidate; serialized material cannot recreate it.
/// It grants neither ordinary dispatch nor a new configuration/execution owner.
pub(crate) struct RetiredCredentialReadBinding {
    original: Arc<RetiredLegacyCredential>,
}
impl RetiredLegacyCredential {
    /// Read original protected identity/trust materials for controlled candidate
    /// validation while keeping original service settlement and maintenance.
    /// The result cannot enter ordinary Host startup or release this fence.
    pub fn validation_profile(
        self: &Arc<Self>,
        state_dir: &Path,
    ) -> Result<
        crate::foreground::profile::LoadedMaintenanceProfile,
        crate::foreground::profile::ProfileError,
    > {
        crate::foreground::profile::load_for_migration_validation(state_dir, self.reader_binding())
    }
    pub(crate) fn reader_binding(self: &Arc<Self>) -> Arc<RetiredCredentialReadBinding> {
        Arc::new(RetiredCredentialReadBinding {
            original: self.clone(),
        })
    }
}
impl RetiredCredentialReadBinding {
    fn with_original<T>(
        &self,
        read: impl FnOnce() -> Result<T, TransitionError>,
    ) -> Result<T, TransitionError> {
        let handle = match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                handle
            }
            _ => return Err(TransitionError::Unsupported),
        };
        tokio::task::block_in_place(|| {
            let proof = &self.original.original.proof;
            if handle
                .block_on(proof.verify_original_still_settled())
                .is_err()
            {
                proof.invalidate_credential_retirement();
                return Err(TransitionError::Unknown);
            }
            self.original.observation()?;
            let result = read();
            if handle
                .block_on(proof.verify_original_still_settled())
                .is_err()
            {
                proof.invalidate_credential_retirement();
                return Err(TransitionError::Unknown);
            }
            self.original.observation()?;
            result
        })
    }
    pub(crate) fn read_token(
        &self,
        configuration: &crate::store::PrivateRoot,
        host: &crate::store::PrivateRoot,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, TransitionError> {
        self.with_original(|| {
            self.original
                .original
                .proof
                .fence()
                .read_retired_credential(configuration, host)
                .map_err(|error| match error {
                    LegacyFenceError::InvalidMaterials => TransitionError::Conflict,
                    _ => TransitionError::Unknown,
                })
        })
    }
    pub(crate) fn revalidate(&self) -> Result<(), TransitionError> {
        self.with_original(|| Ok(()))
    }
    pub(crate) fn candidate(&self) -> Arc<VerifiedNativeRelease> {
        self.original.original.target.clone()
    }
}

#[path = "legacy_gateway.rs"]
mod gateway;
pub use gateway::{LegacyGatewayTransition, SettledLegacyRuntime};
