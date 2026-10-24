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
    evidence: CuaEvidence,
    cause: Option<CuaError>,
}
fn encode(evidence: CuaEvidence, cause: Option<CuaError>) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(&Audit {
        schema: 1,
        evidence,
        cause,
    })
    .map_err(|_| CuaError::ProtocolMismatch)?;
    if bytes.len() > 1024 {
        return Err(CuaError::Busy);
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
        Some(CuaError::Busy),
        Some(CuaError::InvalidRequest),
        Some(CuaError::PermissionDenied),
        Some(CuaError::Unsupported),
        Some(CuaError::ProtocolMismatch),
        Some(CuaError::Unknown),
        Some(CuaError::CleanupUnconfirmed),
    ] {
        if digest == Sha256Digest::of_bytes(&encode(CuaEvidence::NotDispatched, cause)?) {
            return Ok(true);
        }
    }
    Ok(false)
}
fn desktop_capability(value: CapabilityId) -> bool {
    matches!(
        value,
        CapabilityId::DesktopWindowsRead
            | CapabilityId::DesktopCapture
            | CapabilityId::DesktopPointer
            | CapabilityId::DesktopKeyboard
            | CapabilityId::DesktopAccessibility
            | CapabilityId::DesktopWindowsControl
    )
}
impl CuaWorker {
    /// No URL, function, page output, profile path or arbitrary MCP fields enter
    /// Core's historical audit. This is correlation, never execution authority.
    pub fn action_audit(&self, receipt: &CuaReceipt) -> Result<Vec<u8>> {
        encode(receipt.evidence, receipt.cause)
    }
    pub fn action_from_audit(operation: OperationId, bytes: &[u8]) -> Result<CuaReceipt> {
        if bytes.len() > 1024 {
            return Err(CuaError::InvalidRequest);
        }
        let audit: Audit = serde_json::from_slice(bytes).map_err(|_| CuaError::ProtocolMismatch)?;
        if audit.schema != 1 {
            return Err(CuaError::ProtocolMismatch);
        }
        Ok(CuaReceipt {
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
        let target = s.target.as_ref().ok_or(CuaError::PermissionDenied)?;
        if key.resource_domain() != ResourceDomain::DesktopAgent
            || !desktop_capability(key.capability())
            || key.owner() != &resource.owner
            || target.operation_id != resource.target.operation_id
            || target.payload_digest != resource.target.payload_digest
            || s.state == OperationState::Unknown && !ended
        {
            return Err(CuaError::PermissionDenied);
        }
        if let Some((digest, evidence, cause, actual_capability)) = live.actions.get(&s.id) {
            if key.capability() != *actual_capability
                || *digest != s.payload_digest
                || !matches!(
                    (s.state, *evidence),
                    (OperationState::Succeeded, CuaEvidence::Acknowledged)
                        | (OperationState::Failed, CuaEvidence::NotDispatched)
                        | (OperationState::Unknown, _)
                )
                || key.audit_digest() != Some(Sha256Digest::of_bytes(&encode(*evidence, *cause)?))
            {
                return Err(CuaError::ProtocolMismatch);
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
                        CuaEvidence::Unknown,
                        Some(CuaError::Unknown),
                    )?));
            if !(strict_not_dispatched || ended_unknown) {
                // Missing Unknown requires an exact physically ended parent
                // bundle; missing Failed requires canonical no-dispatch audit.
                return Err(CuaError::Unknown);
            }
        }
        Ok(())
    }
    /// Trusted historical recovery only. The Host must authorize inspection
    /// before using this port; a release key binds the original owner even when
    /// that owner has since been revoked. Missing receipt remains Unknown.
    pub async fn action_receipt(&self, key: &ProviderRecordKey) -> Result<CuaReceipt> {
        let s = key.snapshot();
        let target = s.target.as_ref().ok_or(CuaError::InvalidRequest)?;
        let resource = self
            .inner
            .resources
            .lock()
            .map_err(|_| CuaError::Unknown)?
            .get(&target.operation_id)
            .cloned()
            .ok_or(CuaError::Unknown)?;
        if !desktop_capability(key.capability())
            || key.owner() != &resource.owner
            || target.payload_digest != resource.target.payload_digest
        {
            return Err(CuaError::PermissionDenied);
        }
        let live = resource.live.lock().await;
        let Some((digest, evidence, cause, actual_capability)) = live.actions.get(&s.id) else {
            if !live.retired && s.state == OperationState::Unknown {
                return Ok(CuaReceipt {
                    operation: s.id.clone(),
                    evidence: CuaEvidence::Unknown,
                    cause: Some(CuaError::Unknown),
                    result: None,
                });
            }
            return Err(CuaError::Unknown);
        };
        if live.retired || key.capability() != *actual_capability || *digest != s.payload_digest {
            return Err(CuaError::PermissionDenied);
        }
        Ok(CuaReceipt {
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
            return Err(CuaError::InvalidRequest);
        }
        let key = &permit.actions()[0];
        let target = key
            .snapshot()
            .target
            .as_ref()
            .ok_or(CuaError::InvalidRequest)?;
        let resource = self
            .inner
            .resources
            .lock()
            .map_err(|_| CuaError::Unknown)?
            .get(&target.operation_id)
            .cloned()
            .ok_or(CuaError::Unknown)?;
        let mut live = resource.live.lock().await;
        if live.retired {
            return Err(CuaError::Unknown);
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
        let key = permit.resource().ok_or(CuaError::InvalidRequest)?;
        let s = key.snapshot();
        if key.capability() != CapabilityId::DesktopWindowsRead || s.target.is_some() {
            return Err(CuaError::PermissionDenied);
        }
        let resource = self
            .inner
            .resources
            .lock()
            .map_err(|_| CuaError::Unknown)?
            .get(&s.id)
            .cloned();
        let Some(resource) = resource else {
            if s.state != OperationState::Failed
                || s.liveness != ExecutionLiveness::NotStarted
                || s.output_drain != OutputDrain::NotOpened
                || !permit.actions().is_empty()
            {
                return Err(CuaError::CleanupUnconfirmed);
            }
            return Ok(permit.confirm_released());
        };
        if key.owner() != &resource.owner || s.payload_digest != resource.target.payload_digest {
            return Err(CuaError::PermissionDenied);
        }
        let mut live = resource.live.lock().await;
        let clean = live.cleanup.ok_or(CuaError::CleanupUnconfirmed)?;
        if live.retired
            || !clean.worker_exited
            || !clean.io_joined
            || !clean.descendants_confirmed
            || s.liveness != ExecutionLiveness::Exited
            || s.output_drain != OutputDrain::Drained
        {
            return Err(CuaError::CleanupUnconfirmed);
        }
        for action in permit.actions() {
            Self::check_action(&resource, &live, action, true)?;
        }
        if live
            .actions
            .keys()
            .any(|id| !permit.actions().iter().any(|k| &k.snapshot().id == id))
        {
            return Err(CuaError::Unknown);
        }
        // All validation precedes mutation. Ancient handles retain a retired
        // object and cannot acquire a new action even after map removal.
        live.retired = true;
        live.actions.clear();
        self.inner
            .resources
            .lock()
            .map_err(|_| CuaError::Unknown)?
            .remove(&s.id);
        Ok(permit.confirm_released())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn audit_transfer_preserves_unknown_and_missing_record_requires_canonical_no_io() {
        for evidence in [CuaEvidence::Acknowledged, CuaEvidence::Unknown] {
            let encoded = encode(evidence, Some(CuaError::Unknown)).unwrap();
            assert!(!canonical_not_dispatched(Some(Sha256Digest::of_bytes(&encoded))).unwrap());
            let audit: Audit = serde_json::from_slice(&encoded).unwrap();
            assert_eq!(audit.evidence, evidence);
            assert_eq!(audit.cause, Some(CuaError::Unknown));
        }
        assert!(!canonical_not_dispatched(None).unwrap());
        assert!(!canonical_not_dispatched(Some(Sha256Digest::of_bytes(b"arbitrary"))).unwrap());
        assert!(
            canonical_not_dispatched(Some(Sha256Digest::of_bytes(
                &encode(CuaEvidence::NotDispatched, Some(CuaError::Busy)).unwrap()
            )))
            .unwrap()
        );
        assert!(serde_json::from_slice::<Audit>(br#"{"schema":1,"evidence":"Unknown","cause":"Unknown","input":"must-not-enter-audit"}"#).is_err());
    }
}
