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
