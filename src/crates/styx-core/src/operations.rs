//! A bounded reservation ledger. Only a recorded, current reservation may dispatch.
//! It owns immutable request bytes, not executor I/O. Outcome and liveness differ.
use crate::policy::{AdmissionFacts, check_admission};
use std::collections::BTreeMap;
use styx_contracts::{error::ErrorCategory, identity::*, operation::*};

mod retention;
use retention::PhysicalRetention;
pub use retention::{ProviderRecordKey, ProviderReleaseConfirmation, ProviderReleasePermit};

const RECORD_ACCOUNTING_OVERHEAD: usize = 4096;
const OWNER_ACCOUNTING_OVERHEAD: usize = 1024;

/// Never deserialize this authority from network input. The authenticated runtime
/// registers an owner after validating Gateway identity and owner namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerLease {
    owner: OwnerId,
    epoch: OwnerEpoch,
    host: HostGeneration,
    incarnation: u64,
}
impl OwnerLease {
    pub fn owner_id(&self) -> &OwnerId {
        &self.owner
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationSnapshot {
    pub id: OperationId,
    pub target: Option<ResourceTarget>,
    pub state: OperationState,
    pub liveness: ExecutionLiveness,
    pub output_drain: OutputDrain,
    pub cancellation: Option<Cancellation>,
    pub payload_digest: Sha256Digest,
}
struct Record {
    owner: OwnerId,
    owner_incarnation: u64,
    context: PreparedContext,
    payload: Box<[u8]>,
    snapshot: OperationSnapshot,
    terminal_at: Option<MonotonicMillis>,
    resource_settled_at: Option<MonotonicMillis>,
    accounting_bytes: usize,
    physical: PhysicalRetention,
    provider_audit: Option<Box<[u8]>>,
}
impl Record {
    fn note_resource_settled(&mut self, now: MonotonicMillis) {
        let exited_and_drained = self.snapshot.liveness == ExecutionLiveness::Exited
            && self.snapshot.output_drain == OutputDrain::Drained;
        let strictly_not_dispatched = self.snapshot.state == OperationState::Failed
            && self.snapshot.liveness == ExecutionLiveness::NotStarted
            && self.snapshot.output_drain == OutputDrain::NotOpened;
        if self.snapshot.target.is_none() && (exited_and_drained || strictly_not_dispatched) {
            self.resource_settled_at.get_or_insert(now);
        }
    }
}
/// One admission decision, consumed by an executor adapter. No public
/// constructor, Clone or Deserialize: an old ID cannot manufacture new authority.
///
/// ```compile_fail
/// fn duplicate(permit: styx_core::operations::DispatchPermit) {
///     let _another = permit.clone();
/// }
/// ```
/// ```compile_fail
/// fn requires_copy<T: Copy>() {}
/// requires_copy::<styx_core::operations::DispatchPermit>();
/// ```
#[derive(PartialEq, Eq)]
pub struct DispatchPermit {
    id: OperationId,
    owner: OwnerLease,
    context: PreparedContext,
    target: Option<ResourceTarget>,
    payload: Box<[u8]>,
}
impl DispatchPermit {
    pub fn id(&self) -> &OperationId {
        &self.id
    }
    pub fn target(&self) -> Option<&ResourceTarget> {
        self.target.as_ref()
    }
    pub fn owner(&self) -> &OwnerLease {
        &self.owner
    }
    pub fn context(&self) -> &PreparedContext {
        &self.context
    }
    /// Exact prepared bytes. Deliberately omitted from Debug/serialization.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}
impl std::fmt::Debug for DispatchPermit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DispatchPermit")
            .field("operation", &self.id)
            .field("capability", &self.context.capability)
            .field("payload", &"[REDACTED]")
            .finish()
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum DispatchDisposition {
    ExecuteOnce(DispatchPermit),
    Existing(OperationSnapshot),
}

pub struct OperationLedger {
    host: HostGeneration,
    owners: BTreeMap<OwnerId, (OwnerEpoch, u64)>,
    records: BTreeMap<OperationId, Record>,
    next_sequence: u64,
    next_owner_incarnation: u64,
    budget: usize,
    retained_bytes: usize,
    retention_ms: u64,
    maintenance_fenced: bool,
}
impl OperationLedger {
    /// Actual Host generation of this ledger, never a registry generation.
    pub fn host_generation(&self) -> &HostGeneration {
        &self.host
    }
    pub fn new(host: HostGeneration) -> Self {
        Self::with_budget(
            host,
            styx_contracts::OPERATION_METADATA_BYTES,
            styx_contracts::TERMINAL_OPERATION_RETENTION_MS,
        )
    }
    pub fn with_budget(host: HostGeneration, budget: usize, retention_ms: u64) -> Self {
        Self {
            host,
            owners: BTreeMap::new(),
            records: BTreeMap::new(),
            next_sequence: 0,
            next_owner_incarnation: 0,
            budget,
            retained_bytes: 0,
            retention_ms,
            maintenance_fenced: false,
        }
    }
    /// Caller is the authentication boundary, not a tool parameter handler.
    /// Existing owners cannot be silently replaced or have their epoch reused.
    pub fn register_verified_owner(
        &mut self,
        owner: OwnerId,
        epoch: OwnerEpoch,
    ) -> Result<OwnerLease, ErrorCategory> {
        if self.owners.contains_key(&owner) {
            return Err(ErrorCategory::StateConflict);
        }
        self.reserve_capacity(OWNER_ACCOUNTING_OVERHEAD)?;
        let incarnation = self.next_owner_incarnation;
        let next = incarnation
            .checked_add(1)
            .ok_or(ErrorCategory::StateConflict)?;
        self.owners
            .insert(owner.clone(), (epoch.clone(), incarnation));
        self.next_owner_incarnation = next;
        self.retained_bytes += OWNER_ACCOUNTING_OVERHEAD;
        Ok(OwnerLease {
            owner,
            epoch,
            host: self.host.clone(),
            incarnation,
        })
    }
    fn reserve_capacity(&self, bytes: usize) -> Result<(), ErrorCategory> {
        match self.retained_bytes.checked_add(bytes) {
            Some(total) if total <= self.budget => Ok(()),
            _ => Err(ErrorCategory::Busy),
        }
    }
    fn verify_owner(&self, owner: &OwnerLease) -> Result<(), ErrorCategory> {
        if owner.host != self.host
            || self.owners.get(&owner.owner) != Some(&(owner.epoch.clone(), owner.incarnation))
        {
            return Err(ErrorCategory::Unauthorized);
        }
        Ok(())
    }
    fn record_for(
        &self,
        owner: &OwnerLease,
        id: &OperationId,
        digest: Sha256Digest,
    ) -> Result<&Record, ErrorCategory> {
        self.verify_owner(owner)?;
        if id.host_generation != self.host {
            return Err(ErrorCategory::StaleOperation);
        }
        let record = self.records.get(id).ok_or(ErrorCategory::StaleOperation)?;
        if record.owner != owner.owner
            || id.owner_epoch != owner.epoch
            || record.owner_incarnation != owner.incarnation
        {
            return Err(ErrorCategory::Unauthorized);
        }
        if record.snapshot.payload_digest != digest {
            return Err(ErrorCategory::IntegrityFailure);
        }
        Ok(record)
    }
    pub fn prepare(
        &mut self,
        owner: &OwnerLease,
        context: PreparedContext,
        payload: Vec<u8>,
        now: MonotonicMillis,
    ) -> Result<OperationSnapshot, ErrorCategory> {
        self.prepare_record(owner, None, context, payload, now)
    }
    /// Reserve an independent request-level action on an exact existing
    /// resource. Core proves committed dispatch, not native start success.
    pub fn prepare_targeted(
        &mut self,
        owner: &OwnerLease,
        target: ResourceTarget,
        context: PreparedContext,
        payload: Vec<u8>,
        now: MonotonicMillis,
    ) -> Result<OperationSnapshot, ErrorCategory> {
        self.verify_target(owner, &target, &context)?;
        self.prepare_record(owner, Some(target), context, payload, now)
    }
    fn verify_target(
        &self,
        owner: &OwnerLease,
        target: &ResourceTarget,
        context: &PreparedContext,
    ) -> Result<(), ErrorCategory> {
        let record = self.record_for(owner, &target.operation_id, target.payload_digest)?;
        if record.snapshot.target.is_some()
            || matches!(
                record.physical,
                PhysicalRetention::ReleasePending | PhysicalRetention::Released
            )
            || !matches!(
                record.snapshot.liveness,
                ExecutionLiveness::Running | ExecutionLiveness::Unknown
            )
            || record.context.device_id != context.device_id
            || record.context.capability != context.capability
            || record.context.session != context.session
        {
            return Err(ErrorCategory::StateConflict);
        }
        Ok(())
    }
    fn prepare_record(
        &mut self,
        owner: &OwnerLease,
        target: Option<ResourceTarget>,
        context: PreparedContext,
        payload: Vec<u8>,
        now: MonotonicMillis,
    ) -> Result<OperationSnapshot, ErrorCategory> {
        self.verify_owner(owner)?;
        if self.maintenance_fenced {
            return Err(ErrorCategory::Busy);
        }
        if now >= context.deadline {
            return Err(ErrorCategory::OperationTimeout);
        }
        if payload.len() > styx_contracts::DESKTOP_BROWSER_FRAME_BYTES {
            return Err(ErrorCategory::Busy);
        }
        let accounting_bytes = payload
            .len()
            .checked_add(RECORD_ACCOUNTING_OVERHEAD)
            .ok_or(ErrorCategory::Busy)?;
        self.reserve_capacity(accounting_bytes)?;
        // No wrap, no implicit epoch reuse. Exhaustion fences new reservations
        // until the runtime explicitly establishes a fresh Host generation.
        let next = self
            .next_sequence
            .checked_add(1)
            .ok_or(ErrorCategory::StateConflict)?;
        let id = OperationId {
            host_generation: self.host.clone(),
            owner_epoch: owner.epoch.clone(),
            sequence: self.next_sequence,
        };
        let snapshot = OperationSnapshot {
            id: id.clone(),
            target: target.clone(),
            state: OperationState::Reserved,
            liveness: if target.is_some() {
                ExecutionLiveness::NotApplicable
            } else {
                ExecutionLiveness::NotStarted
            },
            output_drain: OutputDrain::NotOpened,
            cancellation: None,
            payload_digest: Sha256Digest::of_bytes(&payload),
        };
        self.records.insert(
            id,
            Record {
                owner: owner.owner.clone(),
                owner_incarnation: owner.incarnation,
                context,
                payload: payload.into_boxed_slice(),
                snapshot: snapshot.clone(),
                terminal_at: None,
                resource_settled_at: None,
                accounting_bytes,
                physical: PhysicalRetention::NotOpened,
                provider_audit: None,
            },
        );
        self.next_sequence = next;
        self.retained_bytes += accounting_bytes;
        Ok(snapshot)
    }
    /// Recheck live grants/session/deadline under the caller's admission lock.
    /// This changes to Dispatched BEFORE returning bytes; losing this reply must
    /// produce Unknown/reconciliation, never a second ExecuteOnce.
    pub fn dispatch(
        &mut self,
        owner: &OwnerLease,
        id: &OperationId,
        digest: Sha256Digest,
        facts: &AdmissionFacts,
        now: MonotonicMillis,
    ) -> Result<DispatchDisposition, ErrorCategory> {
        let record = self.record_for(owner, id, digest)?;
        if record.snapshot.state != OperationState::Reserved {
            return Ok(DispatchDisposition::Existing(record.snapshot.clone()));
        }
        if self.maintenance_fenced {
            return Err(ErrorCategory::Busy);
        }
        if let Some(target) = &record.snapshot.target {
            self.verify_target(owner, target, &record.context)?;
        }
        check_admission(&record.context, facts, now)?;
        let record = self
            .records
            .get_mut(id)
            .expect("record checked above with exclusive ledger access");
        record.snapshot.state = OperationState::Dispatched;
        record.physical = PhysicalRetention::Retained;
        if record.snapshot.target.is_none() {
            record.snapshot.liveness = ExecutionLiveness::Unknown;
            record.snapshot.output_drain = OutputDrain::Unknown;
        }
        Ok(DispatchDisposition::ExecuteOnce(DispatchPermit {
            id: id.clone(),
            owner: owner.clone(),
            payload: record.payload.clone(),
            context: record.context.clone(),
            target: record.snapshot.target.clone(),
        }))
    }
    pub fn inspect(
        &self,
        owner: &OwnerLease,
        id: &OperationId,
        digest: Sha256Digest,
    ) -> Result<OperationSnapshot, ErrorCategory> {
        Ok(self.record_for(owner, id, digest)?.snapshot.clone())
    }
    /// Authorize a fresh access to an existing resource under current policy.
    /// The start deadline is deliberately not reused for a long-lived process.
    /// Fresh policy can change, but device/capability/session binding cannot.
    /// A DTO target ID or a retained start permit is never access authority.
    pub fn authorize_resource_access(
        &self,
        owner: &OwnerLease,
        id: &OperationId,
        digest: Sha256Digest,
        fresh_context: &PreparedContext,
        facts: &AdmissionFacts,
        now: MonotonicMillis,
    ) -> Result<OperationSnapshot, ErrorCategory> {
        let record = self.record_for(owner, id, digest)?;
        if record.snapshot.target.is_some()
            || matches!(
                record.physical,
                PhysicalRetention::ReleasePending | PhysicalRetention::Released
            )
            || record.snapshot.liveness == ExecutionLiveness::NotStarted
        {
            return Err(ErrorCategory::StateConflict);
        }
        if fresh_context.device_id != record.context.device_id
            || fresh_context.capability != record.context.capability
            || fresh_context.session != record.context.session
        {
            return Err(ErrorCategory::StateConflict);
        }
        check_admission(fresh_context, facts, now)?;
        Ok(record.snapshot.clone())
    }
    pub fn request_cancel(
        &mut self,
        owner: &OwnerLease,
        id: &OperationId,
        digest: Sha256Digest,
        now: MonotonicMillis,
    ) -> Result<OperationSnapshot, ErrorCategory> {
        self.record_for(owner, id, digest)?;
        let record = self.records.get_mut(id).expect("checked record");
        if record.snapshot.state == OperationState::Reserved {
            record.snapshot.state = OperationState::Cancelled;
            record.snapshot.cancellation = Some(Cancellation::NotDispatched);
            record.terminal_at = Some(now);
        } else if !matches!(
            record.snapshot.state,
            OperationState::Succeeded | OperationState::Failed | OperationState::Cancelled
        ) {
            record.snapshot.cancellation = Some(Cancellation::Requested);
        }
        Ok(record.snapshot.clone())
    }
    /// Only executor adapters may supply these facts. An RPC timeout is not a
    /// completion or termination fact; call mark_result_unknown for that case.
    pub fn record_executor_fact(
        &mut self,
        id: &OperationId,
        fact: ExecutorFact,
        now: MonotonicMillis,
    ) -> Result<OperationSnapshot, ErrorCategory> {
        let record = self
            .records
            .get_mut(id)
            .ok_or(ErrorCategory::StaleOperation)?;
        if record.snapshot.target.is_some() || record.snapshot.state == OperationState::Reserved {
            return Err(ErrorCategory::StateConflict);
        }
        if matches!(fact, ExecutorFact::OutputDrained) {
            if record.snapshot.output_drain == OutputDrain::NotOpened {
                return Err(ErrorCategory::StateConflict);
            }
            record.snapshot.output_drain = OutputDrain::Drained;
            record.note_resource_settled(now);
            return Ok(record.snapshot.clone());
        }
        if matches!(
            record.snapshot.state,
            OperationState::Succeeded | OperationState::Failed | OperationState::Cancelled
        ) {
            return Err(ErrorCategory::StateConflict);
        }
        match fact {
            ExecutorFact::NotDispatched => {
                if record.snapshot.state != OperationState::Dispatched
                    || record.snapshot.liveness != ExecutionLiveness::Unknown
                    || record.snapshot.output_drain != OutputDrain::Unknown
                {
                    return Err(ErrorCategory::StateConflict);
                }
                record.snapshot.state = OperationState::Failed;
                record.snapshot.liveness = ExecutionLiveness::NotStarted;
                record.snapshot.output_drain = OutputDrain::NotOpened;
                record.terminal_at = Some(now);
            }
            ExecutorFact::OutputDrained => unreachable!("handled above"),
            ExecutorFact::Running => {
                if record.snapshot.liveness == ExecutionLiveness::Exited {
                    return Err(ErrorCategory::StateConflict);
                }
                record.snapshot.liveness = ExecutionLiveness::Running;
                if record.snapshot.output_drain != OutputDrain::Drained {
                    record.snapshot.output_drain = OutputDrain::Open;
                }
                if record.snapshot.state != OperationState::Unknown {
                    record.snapshot.state = OperationState::Running;
                }
            }
            ExecutorFact::Exited { successful } => {
                record.snapshot.liveness = ExecutionLiveness::Exited;
                // Exit proves liveness, not rollback or the result of an already unknown action.
                if record.snapshot.state != OperationState::Unknown {
                    record.snapshot.state = if successful {
                        OperationState::Succeeded
                    } else {
                        OperationState::Failed
                    };
                }
                record.terminal_at.get_or_insert(now);
            }
            ExecutorFact::TerminationConfirmed => {
                if record.snapshot.cancellation != Some(Cancellation::Requested) {
                    return Err(ErrorCategory::StateConflict);
                }
                record.snapshot.liveness = ExecutionLiveness::Exited;
                if record.snapshot.state != OperationState::Unknown {
                    record.snapshot.state = OperationState::Cancelled;
                }
                record.snapshot.cancellation = Some(Cancellation::TerminationConfirmed);
                record.terminal_at.get_or_insert(now);
            }
        }
        record.note_resource_settled(now);
        Ok(record.snapshot.clone())
    }
    pub fn mark_result_unknown(
        &mut self,
        id: &OperationId,
    ) -> Result<OperationSnapshot, ErrorCategory> {
        let record = self
            .records
            .get_mut(id)
            .ok_or(ErrorCategory::StaleOperation)?;
        if record.snapshot.target.is_some() {
            return Err(ErrorCategory::StateConflict);
        }
        if matches!(
            record.snapshot.state,
            OperationState::Reserved
                | OperationState::Succeeded
                | OperationState::Failed
                | OperationState::Cancelled
        ) {
            return Err(ErrorCategory::StateConflict);
        }
        record.snapshot.state = OperationState::Unknown;
        if record.snapshot.liveness != ExecutionLiveness::Exited {
            record.snapshot.liveness = ExecutionLiveness::Unknown;
        }
        Ok(record.snapshot.clone())
    }
    /// Trusted request-level facts only. These never settle the target process.
    pub fn record_action_result(
        &mut self,
        id: &OperationId,
        result: ActionResult,
        now: MonotonicMillis,
    ) -> Result<OperationSnapshot, ErrorCategory> {
        let record = self
            .records
            .get_mut(id)
            .ok_or(ErrorCategory::StaleOperation)?;
        if record.snapshot.target.is_none()
            || !matches!(
                record.snapshot.state,
                OperationState::Dispatched | OperationState::Unknown
            )
        {
            return Err(ErrorCategory::StateConflict);
        }
        match result {
            ActionResult::NotDispatched if record.snapshot.state == OperationState::Dispatched => {
                record.snapshot.state = OperationState::Failed;
                record.terminal_at = Some(now);
            }
            ActionResult::NotDispatched => return Err(ErrorCategory::StateConflict),
            ActionResult::Acknowledged if record.snapshot.state == OperationState::Dispatched => {
                record.snapshot.state = OperationState::Succeeded;
                record.terminal_at = Some(now);
            }
            ActionResult::Acknowledged => {} // Unknown history is never rewritten.
            ActionResult::Unknown => {
                record.snapshot.state = OperationState::Unknown;
                record.terminal_at.get_or_insert(now);
            }
        }
        Ok(record.snapshot.clone())
    }
    /// Revocation fences new dispatch. Execution cleanup remains the runtime's
    /// explicit job; removing an owner never fabricates termination evidence.
    pub fn revoke_owner(&mut self, owner: &OwnerLease) -> Result<(), ErrorCategory> {
        self.verify_owner(owner)?;
        self.owners.remove(&owner.owner);
        self.retained_bytes -= OWNER_ACCOUNTING_OVERHEAD;
        Ok(())
    }
    /// Only ended work is eligible. NotStarted reservations expire to Cancelled;
    /// no active or liveness-Unknown record is evicted to admit new work.
    pub fn reap(&mut self, now: MonotonicMillis) -> usize {
        for record in self.records.values_mut() {
            if record.snapshot.state == OperationState::Reserved && now >= record.context.deadline {
                record.snapshot.state = OperationState::Cancelled;
                record.snapshot.cancellation = Some(Cancellation::NotDispatched);
                record.terminal_at = Some(now);
            }
        }
        // Actions settle before their parent can be collected. Unknown needs
        // a full retention interval after BOTH ambiguity and proven resource
        // settlement, never merely after the original process exit timestamp.
        let action_candidates: Vec<_> = self
            .records
            .iter()
            .filter_map(|(id, record)| {
                if !record.physical.collectible() {
                    return None;
                }
                let target = record.snapshot.target.as_ref()?;
                let since = if record.snapshot.state == OperationState::Unknown {
                    let action_at = record.terminal_at?;
                    let parent_at = self
                        .records
                        .get(&target.operation_id)?
                        .resource_settled_at?;
                    Some(std::cmp::max(action_at, parent_at))
                } else if matches!(
                    record.snapshot.state,
                    OperationState::Succeeded | OperationState::Failed | OperationState::Cancelled
                ) {
                    record.terminal_at
                } else {
                    None
                };
                since
                    .filter(|at| now.0.saturating_sub(at.0) >= self.retention_ms)
                    .map(|_| id.clone())
            })
            .collect();
        let mut removed = 0;
        for id in action_candidates {
            if let Some(record) = self.records.remove(&id) {
                self.retained_bytes -= record.accounting_bytes;
                removed += 1;
            }
        }
        let parents: std::collections::BTreeSet<_> = self
            .records
            .values()
            .filter_map(|r| r.snapshot.target.as_ref().map(|t| t.operation_id.clone()))
            .collect();
        let mut removed_bytes = 0;
        self.records.retain(|id, record| {
            if record.snapshot.target.is_some() || parents.contains(id) {
                return true;
            }
            let ended = matches!(
                record.snapshot.liveness,
                ExecutionLiveness::NotStarted | ExecutionLiveness::Exited
            );
            let expired = record
                .terminal_at
                .is_some_and(|t| now.0.saturating_sub(t.0) >= self.retention_ms);
            let drained = matches!(
                record.snapshot.output_drain,
                OutputDrain::NotOpened | OutputDrain::Drained
            );
            if ended && drained && expired && record.physical.collectible() {
                removed_bytes += record.accounting_bytes;
                removed += 1;
                false
            } else {
                true
            }
        });
        self.retained_bytes -= removed_bytes;
        removed
    }
    /// Fences new side effects, while reads, cancellation and executor settlement continue.
    pub fn begin_maintenance(&mut self) {
        self.maintenance_fenced = true;
    }
    pub fn end_maintenance(&mut self) {
        self.maintenance_fenced = false;
    }
    pub fn maintenance_settled(&self) -> bool {
        self.maintenance_fenced
            && self.records.values().all(|r| {
                if let Some(target) = &r.snapshot.target {
                    return match r.snapshot.state {
                        OperationState::Reserved
                        | OperationState::Succeeded
                        | OperationState::Failed
                        | OperationState::Cancelled => true,
                        OperationState::Unknown => self
                            .records
                            .get(&target.operation_id)
                            .is_some_and(|parent| parent.resource_settled_at.is_some()),
                        _ => false,
                    };
                }
                matches!(
                    r.snapshot.liveness,
                    ExecutionLiveness::NotStarted | ExecutionLiveness::Exited
                ) && matches!(
                    r.snapshot.output_drain,
                    OutputDrain::NotOpened | OutputDrain::Drained
                )
            })
    }
    pub fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ExecutorFact {
    /// Adapter proves refusal before sending any start/action bytes; never infer
    /// this from an acknowledgement timeout or a generic remote error response.
    NotDispatched,
    OutputDrained,
    Running,
    Exited {
        successful: bool,
    },
    TerminationConfirmed,
}

/// Request-level evidence; never process completion or permission authority.
#[derive(Debug, Clone, Copy)]
pub enum ActionResult {
    Acknowledged,
    /// Trusted adapter proves no action bytes could have been emitted.
    NotDispatched,
    Unknown,
}
