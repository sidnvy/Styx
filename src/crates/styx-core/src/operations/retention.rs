//! Provider retention is distinct from historical operation outcome.
//! Only trusted adapters report physical release; network DTOs cannot mint these
//! linear tokens. An abandoned release remains fenced, never silently retried.
use super::*;

const PROVIDER_AUDIT_BYTES: usize = 1024;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) enum PhysicalRetention {
    #[default]
    NotOpened,
    Retained,
    ReleasePending,
    Released,
}
impl PhysicalRetention {
    pub(super) fn collectible(self) -> bool {
        matches!(self, Self::NotOpened | Self::Released)
    }
}

/// Exact historical binding, including a revoked owner's original incarnation.
/// This is cleanup authority, never authority to execute or read process output.
#[derive(Debug)]
pub struct ProviderRecordKey {
    owner: OwnerLease,
    snapshot: OperationSnapshot,
    audit_digest: Option<Sha256Digest>,
    capability: styx_contracts::capability::CapabilityId,
}
impl ProviderRecordKey {
    pub fn capability(&self) -> styx_contracts::capability::CapabilityId {
        self.capability
    }
    pub fn owner(&self) -> &OwnerLease {
        &self.owner
    }
    pub fn snapshot(&self) -> &OperationSnapshot {
        &self.snapshot
    }
    pub fn audit_digest(&self) -> Option<Sha256Digest> {
        self.audit_digest
    }
}

/// Core-attested physical release. No public field constructor, Clone or wire
/// representation. A known action may transfer its receipt into Core while the
/// resource lives; uncertain actions require independently ended/drained target.
///
/// ```compile_fail
/// fn duplicate(p: styx_core::operations::ProviderReleasePermit) { let _ = p.clone(); }
/// ```
#[derive(Debug)]
pub struct ProviderReleasePermit {
    resource: Option<ProviderRecordKey>,
    actions: Vec<ProviderRecordKey>,
}
impl ProviderReleasePermit {
    pub fn resource(&self) -> Option<&ProviderRecordKey> {
        self.resource.as_ref()
    }
    pub fn actions(&self) -> &[ProviderRecordKey] {
        &self.actions
    }
    /// Trusted adapter fact, analogous to ExecutorFact. Call only AFTER exact
    /// physical records/observers have been released. This is not an OS proof
    /// supplied by a client or a replacement for provider-side validation.
    pub fn confirm_released(self) -> ProviderReleaseConfirmation {
        ProviderReleaseConfirmation { permit: self }
    }
}
#[derive(Debug)]
pub struct ProviderReleaseConfirmation {
    permit: ProviderReleasePermit,
}

fn key(host: &HostGeneration, record: &Record) -> ProviderRecordKey {
    ProviderRecordKey {
        owner: OwnerLease {
            owner: record.owner.clone(),
            epoch: record.snapshot.id.owner_epoch.clone(),
            host: host.clone(),
            incarnation: record.owner_incarnation,
        },
        snapshot: record.snapshot.clone(),
        audit_digest: record.provider_audit.as_deref().map(Sha256Digest::of_bytes),
        capability: record.context.capability,
    }
}
impl OperationLedger {
    /// Bounded provider correlation evidence (no input/output bytes). The runtime
    /// owns its encoding. Core neither interprets it nor grants authority from it.
    /// A different second value is refused rather than rewriting history.
    pub fn record_provider_audit(
        &mut self,
        id: &OperationId,
        bytes: Vec<u8>,
    ) -> Result<(), ErrorCategory> {
        if bytes.is_empty() || bytes.len() > PROVIDER_AUDIT_BYTES {
            return Err(ErrorCategory::Busy);
        }
        let record = self
            .records
            .get_mut(id)
            .ok_or(ErrorCategory::StaleOperation)?;
        if record.snapshot.target.is_none()
            || matches!(
                record.snapshot.state,
                OperationState::Reserved | OperationState::Dispatched | OperationState::Running
            )
        {
            return Err(ErrorCategory::StateConflict);
        }
        match &record.provider_audit {
            Some(existing) if existing.as_ref() != bytes.as_slice() => {
                Err(ErrorCategory::IntegrityFailure)
            }
            Some(_) => Ok(()),
            None => {
                record.provider_audit = Some(bytes.into_boxed_slice());
                Ok(())
            }
        }
    }
    /// Trusted supervision/audit port. Request handlers must first inspect under
    /// the current authenticated owner, just as before provider receipt lookup.
    pub fn provider_audit(&self, id: &OperationId) -> Option<&[u8]> {
        self.records.get(id)?.provider_audit.as_deref()
    }
    /// Trusted cleanup inventory; owner revocation never fabricates termination
    /// or prevents cleanup of resources created under the old incarnation.
    pub fn retained_provider_records(&self) -> Vec<ProviderRecordKey> {
        self.records
            .values()
            .filter(|r| r.physical == PhysicalRetention::Retained)
            .map(|r| key(&self.host, r))
            .collect()
    }
    pub fn unreleased_provider_records(&self) -> usize {
        self.records
            .values()
            .filter(|r| {
                matches!(
                    r.physical,
                    PhysicalRetention::Retained | PhysicalRetention::ReleasePending
                )
            })
            .count()
    }
    /// Transfer known action evidence into Core without retaining a duplicate
    /// provider receipt for the entire resource lifetime. Core audit/metadata
    /// remain subject to their original retention interval.
    pub fn begin_action_release(
        &mut self,
        id: &OperationId,
    ) -> Result<ProviderReleasePermit, ErrorCategory> {
        let record = self.records.get(id).ok_or(ErrorCategory::StaleOperation)?;
        if record.snapshot.target.is_none()
            || record.physical != PhysicalRetention::Retained
            || record.provider_audit.is_none()
            || !matches!(
                record.snapshot.state,
                OperationState::Succeeded | OperationState::Failed | OperationState::Cancelled
            )
        {
            return Err(ErrorCategory::StateConflict);
        }
        let action = key(&self.host, record);
        self.records.get_mut(id).expect("checked action").physical =
            PhysicalRetention::ReleasePending;
        Ok(ProviderReleasePermit {
            resource: None,
            actions: vec![action],
        })
    }
    /// Caller must hold its actual execution-quiescence gate. End/drain facts
    /// alone do not prove an asynchronous action future has stopped using a record.
    pub fn begin_resource_release(
        &mut self,
        target: &ResourceTarget,
    ) -> Result<ProviderReleasePermit, ErrorCategory> {
        let resource = self
            .records
            .get(&target.operation_id)
            .ok_or(ErrorCategory::StaleOperation)?;
        if resource.snapshot.payload_digest != target.payload_digest {
            return Err(ErrorCategory::IntegrityFailure);
        }
        let ended = matches!(
            resource.snapshot.liveness,
            ExecutionLiveness::NotStarted | ExecutionLiveness::Exited
        ) && matches!(
            resource.snapshot.output_drain,
            OutputDrain::NotOpened | OutputDrain::Drained
        ) && resource.snapshot.state != OperationState::Reserved;
        if resource.snapshot.target.is_some()
            || resource.physical != PhysicalRetention::Retained
            || !ended
        {
            return Err(ErrorCategory::StateConflict);
        }
        let resource_key = key(&self.host, resource);
        let mut actions = Vec::new();
        for record in self.records.values() {
            let Some(parent) = &record.snapshot.target else {
                continue;
            };
            if parent.operation_id != target.operation_id {
                continue;
            }
            if parent.payload_digest != target.payload_digest {
                return Err(ErrorCategory::IntegrityFailure);
            }
            if matches!(
                record.snapshot.state,
                OperationState::Dispatched | OperationState::Running
            ) || record.physical == PhysicalRetention::ReleasePending
            {
                return Err(ErrorCategory::Busy);
            }
            if record.physical == PhysicalRetention::Retained {
                if record.provider_audit.is_none() {
                    return Err(ErrorCategory::StateConflict);
                }
                actions.push(key(&self.host, record));
            }
        }
        self.records
            .get_mut(&target.operation_id)
            .expect("checked resource")
            .physical = PhysicalRetention::ReleasePending;
        for action in &actions {
            self.records
                .get_mut(&action.snapshot.id)
                .expect("checked action")
                .physical = PhysicalRetention::ReleasePending;
        }
        Ok(ProviderReleasePermit {
            resource: Some(resource_key),
            actions,
        })
    }
    /// Physical release does not change Succeeded/Failed/Unknown, cancellation,
    /// exit or drain. It only allows later policy-based metadata collection.
    pub fn record_provider_release(
        &mut self,
        confirmation: ProviderReleaseConfirmation,
    ) -> Result<(), ErrorCategory> {
        let permit = confirmation.permit;
        for k in permit.resource.iter().chain(permit.actions.iter()) {
            let r = self
                .records
                .get(&k.snapshot.id)
                .ok_or(ErrorCategory::StaleOperation)?;
            if r.physical != PhysicalRetention::ReleasePending
                || r.owner != k.owner.owner
                || r.owner_incarnation != k.owner.incarnation
                || r.snapshot != k.snapshot
                || r.provider_audit.as_deref().map(Sha256Digest::of_bytes) != k.audit_digest
            {
                return Err(ErrorCategory::StateConflict);
            }
        }
        for k in permit.resource.iter().chain(permit.actions.iter()) {
            self.records
                .get_mut(&k.snapshot.id)
                .expect("validated release")
                .physical = PhysicalRetention::Released;
        }
        Ok(())
    }
}
