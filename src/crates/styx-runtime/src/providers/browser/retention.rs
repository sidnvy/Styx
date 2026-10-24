//! Input-free correlation transfer and Core-attested physical release.
use super::*;
use styx_contracts::operation::{ExecutionLiveness, OperationState, OutputDrain};
use styx_core::operations::{
    ProviderRecordKey, ProviderReleaseConfirmation, ProviderReleasePermit,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Audit {
    schema: u8,
    evidence: BrowserActionEvidence,
    cause: Option<BrowserError>,
}
fn encode(evidence: BrowserActionEvidence, cause: Option<BrowserError>) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(&Audit {
        schema: 1,
        evidence,
        cause,
    })
    .map_err(|_| BrowserError::ProtocolMismatch)?;
    if bytes.len() > 1024 {
        return Err(BrowserError::Busy);
    }
    Ok(bytes)
}
fn canonical_not_dispatched(digest: Option<Sha256Digest>) -> Result<bool> {
    let Some(digest) = digest else {
        return Ok(false);
    };
    // Finite, input-free encodings preserve the original curated cause while
    // rejecting ACK, Unknown, untyped bytes and absent audit metadata.
    for cause in [
        None,
        Some(BrowserError::Busy),
        Some(BrowserError::InvalidRequest),
        Some(BrowserError::PermissionDenied),
        Some(BrowserError::Unsupported),
        Some(BrowserError::SpawnFailed),
        Some(BrowserError::ProtocolMismatch),
        Some(BrowserError::Unknown),
        Some(BrowserError::AlreadyDispatched),
        Some(BrowserError::CleanupUnconfirmed),
    ] {
        if digest == Sha256Digest::of_bytes(&encode(BrowserActionEvidence::NotDispatched, cause)?) {
            return Ok(true);
        }
    }
    Ok(false)
}
impl BrowserWorker {
    /// No URL, function, page output, profile path or arbitrary MCP fields enter
    /// Core's historical audit. This is correlation, never execution authority.
    pub fn action_audit(&self, receipt: &BrowserActionReceipt) -> Result<Vec<u8>> {
        encode(receipt.evidence, receipt.cause)
    }
    pub fn action_from_audit(operation: OperationId, bytes: &[u8]) -> Result<BrowserActionReceipt> {
        if bytes.len() > 1024 {
            return Err(BrowserError::InvalidRequest);
        }
        let audit: Audit =
            serde_json::from_slice(bytes).map_err(|_| BrowserError::ProtocolMismatch)?;
        if audit.schema != 1 {
            return Err(BrowserError::ProtocolMismatch);
        }
        Ok(BrowserActionReceipt {
            operation,
            evidence: audit.evidence,
            cause: audit.cause,
            result: None,
        })
    }
    fn check_action(
        resource: &Resource,
        live: &Live,
        key: &ProviderRecordKey,
        ended: bool,
    ) -> Result<()> {
        let s = key.snapshot();
        let target = s.target.as_ref().ok_or(BrowserError::PermissionDenied)?;
        if key.capability() != CapabilityId::BrowserHeadless
            || key.owner() != &resource.owner
            || target.operation_id != resource.operation
            || target.payload_digest != resource.digest
            || s.state == OperationState::Unknown && !ended
        {
            return Err(BrowserError::PermissionDenied);
        }
        if let Some((digest, evidence, cause, _)) = live.actions.get(&s.id) {
            if *digest != s.payload_digest
                || !matches!(
                    (s.state, *evidence),
                    (
                        OperationState::Succeeded,
                        BrowserActionEvidence::Acknowledged
                    ) | (OperationState::Failed, BrowserActionEvidence::NotDispatched)
                        | (OperationState::Unknown, _)
                )
                || key.audit_digest() != Some(Sha256Digest::of_bytes(&encode(*evidence, *cause)?))
            {
                return Err(BrowserError::ProtocolMismatch);
            }
        } else {
            let strict_not_dispatched = s.state == OperationState::Failed
                && s.liveness == ExecutionLiveness::NotApplicable
                && s.output_drain == OutputDrain::NotOpened
                && canonical_not_dispatched(key.audit_digest())?;
            let ended_unknown = ended
                && s.state == OperationState::Unknown
                && key.audit_digest()
                    == Some(Sha256Digest::of_bytes(&encode(
                        BrowserActionEvidence::Unknown,
                        Some(BrowserError::Unknown),
                    )?));
            if !(strict_not_dispatched || ended_unknown) {
                // Missing Unknown requires an exact physically ended parent
                // bundle; missing Failed requires canonical no-dispatch audit.
                return Err(BrowserError::Unknown);
            }
        }
        Ok(())
    }
    /// Trusted historical recovery only. The Host must authorize inspection
    /// before using this port; a release key binds the original owner even when
    /// that owner has since been revoked. Missing receipt remains Unknown.
    pub async fn action_receipt(&self, key: &ProviderRecordKey) -> Result<BrowserActionReceipt> {
        let s = key.snapshot();
        let target = s.target.as_ref().ok_or(BrowserError::InvalidRequest)?;
        let resource = self
            .inner
            .resources
            .lock()
            .map_err(|_| BrowserError::Unknown)?
            .get(&target.operation_id)
            .cloned()
            .ok_or(BrowserError::Unknown)?;
        if key.capability() != CapabilityId::BrowserHeadless
            || key.owner() != &resource.owner
            || target.payload_digest != resource.digest
        {
            return Err(BrowserError::PermissionDenied);
        }
        let live = resource.state.lock().await;
        let Some((digest, evidence, cause, _)) = live.actions.get(&s.id) else {
            if !live.retired && s.state == OperationState::Unknown {
                return Ok(BrowserActionReceipt {
                    operation: s.id.clone(),
                    evidence: BrowserActionEvidence::Unknown,
                    cause: Some(BrowserError::Unknown),
                    result: None,
                });
            }
            return Err(BrowserError::Unknown);
        };
        if live.retired || *digest != s.payload_digest {
            return Err(BrowserError::PermissionDenied);
        }
        Ok(BrowserActionReceipt {
            operation: s.id.clone(),
            evidence: *evidence,
            cause: *cause,
            result: None,
        })
    }
    /// Host holds its execution-quiescence gate. The resource mutex additionally
    /// excludes any already admitted provider action; no I/O occurs here.
    pub async fn release_action(
        &self,
        permit: ProviderReleasePermit,
    ) -> Result<ProviderReleaseConfirmation> {
        if permit.resource().is_some() || permit.actions().len() != 1 {
            return Err(BrowserError::InvalidRequest);
        }
        let key = &permit.actions()[0];
        let target = key
            .snapshot()
            .target
            .as_ref()
            .ok_or(BrowserError::InvalidRequest)?;
        let resource = self
            .inner
            .resources
            .lock()
            .map_err(|_| BrowserError::Unknown)?
            .get(&target.operation_id)
            .cloned()
            .ok_or(BrowserError::Unknown)?;
        let mut live = resource.state.lock().await;
        if live.retired {
            return Err(BrowserError::Unknown);
        }
        Self::check_action(&resource, &live, key, false)?;
        live.actions.remove(&key.snapshot().id);
        Ok(permit.confirm_released())
    }
    /// Scope proof and all IO joins must already have completed. Unknown action
    /// records are removed only as part of this exact ended resource bundle.
    pub async fn release_resource(
        &self,
        permit: ProviderReleasePermit,
    ) -> Result<ProviderReleaseConfirmation> {
        let key = permit.resource().ok_or(BrowserError::InvalidRequest)?;
        let s = key.snapshot();
        if key.capability() != CapabilityId::BrowserHeadless || s.target.is_some() {
            return Err(BrowserError::PermissionDenied);
        }
        let resource = self
            .inner
            .resources
            .lock()
            .map_err(|_| BrowserError::Unknown)?
            .get(&s.id)
            .cloned();
        let Some(resource) = resource else {
            if s.state != OperationState::Failed
                || s.liveness != ExecutionLiveness::NotStarted
                || s.output_drain != OutputDrain::NotOpened
                || !permit.actions().is_empty()
            {
                return Err(BrowserError::CleanupUnconfirmed);
            }
            return Ok(permit.confirm_released());
        };
        if key.owner() != &resource.owner || s.payload_digest != resource.digest {
            return Err(BrowserError::PermissionDenied);
        }
        let mut live = resource.state.lock().await;
        let clean = live.cleanup.ok_or(BrowserError::CleanupUnconfirmed)?;
        if live.retired
            || !clean.worker_exited
            || !clean.stdio_joined
            || clean.descendants != BrowserDescendants::Confirmed
            || s.liveness != ExecutionLiveness::Exited
            || s.output_drain != OutputDrain::Drained
        {
            return Err(BrowserError::CleanupUnconfirmed);
        }
        for action in permit.actions() {
            Self::check_action(&resource, &live, action, true)?;
        }
        if live
            .actions
            .keys()
            .any(|id| !permit.actions().iter().any(|k| &k.snapshot().id == id))
        {
            return Err(BrowserError::Unknown);
        }
        // All validation precedes mutation. Ancient handles retain a retired
        // object and cannot acquire a new action even after map removal.
        live.retired = true;
        live.actions.clear();
        resource
            .metadata_record
            .lock()
            .map_err(|_| BrowserError::Unknown)?
            .take();
        self.inner
            .resources
            .lock()
            .map_err(|_| BrowserError::Unknown)?
            .remove(&s.id);
        Ok(permit.confirm_released())
    }
}
