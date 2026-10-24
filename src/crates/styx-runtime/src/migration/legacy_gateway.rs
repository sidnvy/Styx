//! Gateway-specific original service proof composed with the continuously held
//! Host retirement authority. No new writer, service activation or C07 commit.
use super::*;
use crate::store::PrivateRoot;

#[must_use = "retain the original Host retirement and registered Gateway capture"]
pub struct LegacyGatewayTransition {
    original: Arc<RetiredLegacyCredential>,
    capture: legacy::LegacyCaptureTicket,
    scope: Option<Arc<legacy::LegacyManagedScope>>,
    failure: Option<legacy::LegacyCaptureFailure>,
}
impl RetiredLegacyCredential {
    /// Only the original retired Host proof can register the associated Gateway
    /// scope. Read-only verification can fail without releasing that authority.
    /// Duplicate registration is refused by the SAME original scope's slot.
    pub async fn prepare_gateway(
        self: &Arc<Self>,
    ) -> Result<LegacyGatewayTransition, TransitionError> {
        self.observation()?;
        let proof = &self.original.proof;
        let inputs = proof
            .load_gateway_inputs(self.original.target.clone())
            .await
            .map_err(classify)?;
        let capture = proof
            .capture_gateway(inputs)
            .map_err(|error| classify(error.cause))?;
        Ok(LegacyGatewayTransition {
            original: self.clone(),
            capture,
            scope: None,
            failure: None,
        })
    }
}
impl LegacyGatewayTransition {
    pub fn capture_status(&self) -> CaptureStatus {
        match self.capture.query() {
            legacy::CaptureState::Pending => CaptureStatus::Pending,
            legacy::CaptureState::Ready => CaptureStatus::Ready,
            legacy::CaptureState::Failed(error) => CaptureStatus::Failed(classify(error)),
        }
    }
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
            .map(|value| value.map(observe))
            .map_err(classify)
    }
    /// Requires actual capture and settlement worker joins. This combined proof
    /// remains a maintenance resource, never ordinary admission or activation.
    pub fn consume_settlement(&self) -> Result<SettledLegacyRuntime, TransitionError> {
        let scope = self.scope.as_ref().ok_or(TransitionError::Busy)?;
        if !scope.is_gateway_of(&self.original.original.proof) {
            return Err(TransitionError::Conflict);
        }
        let proof = scope.consume_settlement().map_err(classify)?;
        Ok(SettledLegacyRuntime {
            original: self.original.clone(),
            gateway: proof,
        })
    }
}
#[must_use = "dual physical settlement is not launch retirement or migration commit"]
pub struct SettledLegacyRuntime {
    original: Arc<RetiredLegacyCredential>,
    gateway: legacy::LegacySettlementProof,
}
impl SettledLegacyRuntime {
    pub fn configuration_root(&self) -> &OwnedConfigurationRoot {
        self.original.configuration_root()
    }
    pub(crate) fn maintenance_profile(
        self: &Arc<Self>,
        state_dir: &Path,
    ) -> Result<
        crate::foreground::profile::LoadedMaintenanceProfile,
        crate::foreground::profile::ProfileError,
    > {
        self.original.validation_profile(state_dir)
    }
    pub(crate) fn maintenance_transaction(&self) -> styx_contracts::identity::TransactionId {
        self.original
            .original
            .proof
            .fence()
            .maintenance()
            .transaction_id()
            .clone()
    }
    pub(crate) fn original_fence(&self) -> &crate::store::legacy_handoff::LegacyWriterFence {
        self.original.original.proof.fence()
    }
    pub(crate) fn original_retirement(
        &self,
    ) -> Result<CredentialRetirementObservation, TransitionError> {
        self.original.observation()
    }
    pub(crate) fn scope_bindings(&self) -> Result<Vec<u8>, TransitionError> {
        serde_json::to_vec(&serde_json::json!({"schema":1,
            "host":self.original.original.proof.original_scope_binding(),
            "gateway":self.gateway.original_scope_binding(),
            "writer_exclusion":self.original_fence().writer_exclusion_bindings().map_err(|_| TransitionError::Unknown)?
        })).map_err(|_| TransitionError::Unknown)
    }
    pub fn target(&self) -> &VerifiedNativeRelease {
        self.original.target()
    }
    pub fn host_observation(&self) -> SettlementObservation {
        self.original.original.observation()
    }
    pub fn gateway_observation(&self) -> SettlementObservation {
        observe(self.gateway.observation())
    }
    /// Execute a synchronous history step while retaining the SAME original
    /// state-root writer and maintenance fence. Both settled scopes are freshly
    /// checked before/after; this never opens ordinary startup or commits C07.
    /// No configuration mutex spans the external manager observations.
    pub fn with_original_history<T>(
        &self,
        state_dir: &Path,
        operation: impl FnOnce(
            &crate::migration::legacy_enrollment::LegacyEnrollmentSnapshot<'_>,
            &OwnedConfigurationRoot,
            &ConfigurationMaintenance,
        ) -> Result<T, TransitionError>,
    ) -> Result<T, TransitionError> {
        let handle = match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                handle
            }
            _ => return Err(TransitionError::Unsupported),
        };
        tokio::task::block_in_place(|| {
            handle.block_on(self.revalidate())?;
            let fence = self.original.original.proof.fence();
            let root =
                Arc::new(PrivateRoot::open(state_dir).map_err(|_| TransitionError::Conflict)?);
            let snapshot = crate::migration::legacy_enrollment::LegacyEnrollmentSnapshot::capture(
                state_dir,
                root,
                fence.maintenance(),
            )?;
            let result = operation(&snapshot, self.configuration_root(), fence.maintenance());
            // Even a failed write cannot hide changed source or resurrected
            // services. Retained unresolved records never authorize replay.
            let source = snapshot.revalidate();
            let scopes = handle.block_on(self.revalidate());
            scopes?;
            source?;
            result
        })
    }
    /// Fresh original invocation/cgroup/manager facts for BOTH scopes. Changed
    /// sources or a restarted/replaced scope invalidate the maintenance reader;
    /// no credential restoration, automatic retry or native publication occurs.
    pub async fn revalidate(&self) -> Result<(), TransitionError> {
        let result = async {
            self.original
                .original
                .proof
                .verify_original_still_settled()
                .await
                .map_err(classify)?;
            self.original.observation()?;
            self.gateway
                .verify_original_still_settled()
                .await
                .map_err(classify)?;
            self.original
                .original
                .proof
                .verify_original_still_settled()
                .await
                .map_err(classify)?;
            self.original.observation()?;
            Ok(())
        }
        .await;
        if result.is_err() {
            self.original
                .original
                .proof
                .invalidate_credential_retirement();
        }
        result
    }
}

#[cfg(test)]
#[path = "legacy_gateway_tests.rs"]
mod tests;
