//! One bounded, Host-owned AX read binding, never a second operation ledger.
use super::{
    desktop::{DesktopLane, desktop},
    *,
};
use crate::providers::cua::{
    AxWriteRequest, CuaAction, CuaError, DesktopReadRequest, DesktopReadTarget,
    ax_snapshot::ParsedAxSnapshot,
};
use styx_contracts::{capability::*, identity::ObservationId, session::SessionBinding};

/// Only one map is retained per lane (the Core provider also has one current
/// observation). ParsedAxSnapshot bounds native token metadata to 256KiB.
/// Original proc custody remains alive through a consumed native write.
pub(super) struct OwnedAxObservation {
    owner: OwnerLease,
    resource: ResourceTarget,
    binding: SessionBinding,
    source_epoch: u64,
    grant_revision: u64,
    provider_revision: u64,
    observation: ObservationId,
    alias: String,
    target: DesktopReadTarget,
    parsed: ParsedAxSnapshot,
}
impl OwnedAxObservation {
    fn check(
        &self,
        state: &State,
        owner: &OwnerLease,
        resource: &ResourceTarget,
        request: &AxWriteRequest,
    ) -> Result<AdmissionFacts, CoordinatorError> {
        let lane = desktop(state)?;
        if &self.owner != owner || &self.resource != resource {
            return Err(ErrorCategory::Unauthorized.into());
        }
        if lane.source.fenced()
            || lane.source.epoch() != self.source_epoch
            || lane.binding != self.binding
            || state.facts.grant_revision != self.grant_revision
        {
            return Err(ErrorCategory::StaleObservation.into());
        }
        let DesktopReadRequest::Accessibility(read) = self.target.request else {
            return Err(ErrorCategory::StaleObservation.into());
        };
        if request.pid != read.pid || request.window_id != read.window_id {
            return Err(ErrorCategory::StaleObservation.into());
        }
        self.target.validate()?;
        let facts =
            super::desktop_read::acquisition_facts(state, CapabilityId::DesktopAccessibility)?;
        if facts.descriptor.observation_generation != self.provider_revision
            || facts.current_observation.as_ref() != Some(&self.observation)
        {
            return Err(ErrorCategory::StaleObservation.into());
        }
        Ok(facts)
    }
    fn write_facts(
        &self,
        state: &State,
        owner: &OwnerLease,
        resource: &ResourceTarget,
        context: &PreparedContext,
        request: &AxWriteRequest,
        now: MonotonicMillis,
    ) -> Result<AdmissionFacts, CoordinatorError> {
        let facts = self.check(state, owner, resource, request)?;
        if context.observation.as_ref() != Some(&self.observation)
            || !self.parsed.contains_native_token(&request.element_token)
        {
            return Err(ErrorCategory::StaleObservation.into());
        }
        styx_core::policy::check_desktop_accessibility_write_attempt(context, &facts, now)?;
        Ok(facts)
    }
    /// Recheck after the private native acquire await, before the sole WRITE
    /// poll. The retained entry is consumed already, but Core remains current.
    pub(super) fn recheck_write(
        &self,
        state: &State,
        owner: &OwnerLease,
        operation: &OperationId,
        digest: Sha256Digest,
        now: MonotonicMillis,
    ) -> Result<(), CoordinatorError> {
        let context = state.ledger.inspect_context(owner, operation, digest)?;
        let record = state.ledger.inspect(owner, operation, digest)?;
        let resource = record.target.as_ref().ok_or(ErrorCategory::StateConflict)?;
        let action: CuaAction =
            serde_json::from_slice(state.ledger.inspect_payload(owner, operation, digest)?)
                .map_err(|_| CuaError::InvalidRequest)?;
        let request = action
            .accessibility_write_request()?
            .ok_or(ErrorCategory::StateConflict)?;
        let facts = self.write_facts(state, owner, resource, &context, &request, now)?;
        state
            .ledger
            .authorize_desktop_accessibility_write_dispatch(
                owner, operation, digest, &facts, now,
            )?;
        Ok(())
    }
    pub(super) fn validate_delivery(&self, state: &State) -> Result<(), CoordinatorError> {
        let lane = desktop(state)?;
        if lane.source.fenced()
            || lane.source.epoch() != self.source_epoch
            || lane.binding != self.binding
        {
            return Err(ErrorCategory::SessionDisconnected.into());
        }
        self.target.validate()?;
        Ok(())
    }
}
/// Called after a fully validated read and sanitized result, under State lock.
/// Availability is actual acquisition evidence; OS authorization is preserved.
pub(super) struct AcquiredAxObservation {
    pub(super) target: DesktopReadTarget,
    pub(super) parsed: ParsedAxSnapshot,
    pub(super) alias: String,
    pub(super) source_epoch: u64,
}
pub(super) fn install(
    state: &mut State,
    owner: &OwnerLease,
    resource: &ResourceTarget,
    acquired: AcquiredAxObservation,
) -> Result<(), CoordinatorError> {
    let AcquiredAxObservation {
        target,
        parsed,
        alias,
        source_epoch,
    } = acquired;
    target.validate()?;
    if state.shutting_down {
        return Err(CoordinatorError::Busy);
    }
    state.ledger.validate_owner(owner)?;
    let lane = desktop(state)?;
    if lane.source.fenced() || lane.source.epoch() != source_epoch {
        return Err(ErrorCategory::SessionDisconnected.into());
    }
    let binding = lane.binding.clone();
    let before = super::desktop_read::acquisition_facts(state, CapabilityId::DesktopAccessibility)?;
    // Required/Denied/Revoked are not erased by a successful read. The public
    // read may still be returned, but it never acquires this write-attempt map.
    if !matches!(
        before.descriptor.authorization,
        Authorization::Unknown | Authorization::Granted
    ) {
        return Ok(());
    }
    if !before.descriptor.configured
        || !before.descriptor.remote_grant
        || !before.local_policy_allowed
    {
        return Err(ErrorCategory::PermissionDenied.into());
    }
    state
        .sessions
        .provider(
            &binding,
            crate::session::ProviderEvidence {
                capability: CapabilityId::DesktopAccessibility,
                provider: before.descriptor.provider_id,
                availability: Availability::Available,
                authorization: before.descriptor.authorization,
                provenance:
                    "original owned child exact AX read acquired; OS write authorization unchanged"
                        .into(),
                reason: None,
                recovery: styx_contracts::error::Recovery::Reobserve,
            },
            Duration::from_secs(60),
        )
        .map_err(|_| CuaError::PermissionDenied)?;
    let observation = state
        .sessions
        .observe_accessibility_read(&binding)
        .map_err(|_| CuaError::PermissionDenied)?;
    let after = super::desktop_read::acquisition_facts(state, CapabilityId::DesktopAccessibility)?;
    let entry = OwnedAxObservation {
        owner: owner.clone(),
        resource: resource.clone(),
        binding,
        source_epoch,
        grant_revision: state.facts.grant_revision,
        provider_revision: after.descriptor.observation_generation,
        observation,
        alias,
        target,
        parsed,
    };
    state
        .desktop
        .as_mut()
        .ok_or(CuaError::Unsupported)?
        .ax_observation = Some(entry);
    Ok(())
}
pub(super) fn prepare(
    state: &State,
    owner: &OwnerLease,
    resource: &ResourceTarget,
    request: &AxWriteRequest,
) -> Result<(CuaAction, ObservationId), CoordinatorError> {
    let entry = desktop(state)?
        .ax_observation
        .as_ref()
        .ok_or(ErrorCategory::StaleObservation)?;
    entry.check(state, owner, resource, request)?;
    let native = entry
        .parsed
        .native_token_for(&entry.alias, &request.element_token)?;
    Ok((
        request.with_native_token(native)?,
        entry.observation.clone(),
    ))
}
pub(super) fn validate_dispatch(
    state: &State,
    owner: &OwnerLease,
    resource: &ResourceTarget,
    context: &PreparedContext,
    request: &AxWriteRequest,
    now: MonotonicMillis,
) -> Result<AdmissionFacts, CoordinatorError> {
    let entry = desktop(state)?
        .ax_observation
        .as_ref()
        .ok_or(ErrorCategory::StaleObservation)?;
    entry.write_facts(state, owner, resource, context, request, now)
}
/// Root cleanup calls this before native cancellation; a later read completion
/// must additionally pass fresh authority/resource checks before installing.
pub(super) fn invalidate(lane: Option<&mut DesktopLane>, owner: Option<&OwnerLease>) {
    if let Some(lane) = lane
        && lane
            .ax_observation
            .as_ref()
            .is_some_and(|value| owner.is_none_or(|owner| &value.owner == owner))
    {
        lane.ax_observation = None;
    }
}
