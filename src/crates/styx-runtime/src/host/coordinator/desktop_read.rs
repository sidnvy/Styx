//! Read acquisition remains a Core action. Its presentation alias is not input authority.
use super::desktop::{DesktopLane, desktop};
use super::*;
use crate::providers::cua::{
    CuaError, CuaEvidence, CuaReceipt, DesktopReadRequest, DesktopReadTarget,
    ax_snapshot::parse_acquired,
};
use rmcp::model::{CallToolResult, ContentBlock};
use styx_contracts::capability::*;

pub(super) fn acquisition_facts(
    state: &State,
    cap: CapabilityId,
) -> Result<AdmissionFacts, CoordinatorError> {
    let lane = desktop(state)?;
    if lane.source.fenced() {
        return Err(ErrorCategory::SessionDisconnected.into());
    }
    if !matches!(
        cap,
        CapabilityId::DesktopAccessibility | CapabilityId::DesktopCapture
    ) {
        return Err(ErrorCategory::StateConflict.into());
    }
    let grant = lane
        .grants
        .get(&cap)
        .ok_or(ErrorCategory::PermissionDenied)?;
    // inspect preserves Denied/Revoked even after evidence expiry. No projection
    // to Granted and no fabricated availability is needed to attempt a read.
    let view = state
        .sessions
        .inspect(&lane.binding)
        .map_err(|_| ErrorCategory::SessionDisconnected)?;
    let provider = view
        .providers
        .into_iter()
        .find(|p| p.facts.capability == cap)
        .ok_or(ErrorCategory::CapabilityUnsupported)?;
    Ok(AdmissionFacts {
        device_id: state.facts.device_id.clone(),
        grant_revision: state.facts.grant_revision,
        local_policy_allowed: grant.local_policy_allowed,
        descriptor: CapabilityDescriptor {
            contract_version: styx_contracts::CONTRACT_VERSION,
            capability_id: cap,
            scope: Scope::Session,
            provider_id: provider.facts.provider,
            configured: grant.configured,
            remote_grant: grant.remote_grant,
            availability: provider.facts.availability,
            authorization: provider.facts.authorization,
            target_session: Some(lane.binding.clone()),
            reason: provider.facts.reason,
            observed_at: provider.facts.observed_at,
            observation_generation: provider.revision,
            recovery: provider.facts.recovery,
        },
        session_state: Some(view.descriptor.state),
        current_observation: None,
    })
}
fn insufficient_read() -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(
        serde_json::json!({
            "category":"PERMISSION_REQUIRED", "error":"desktop_read_not_proven",
            "execution_certainty":"acknowledged", "uncertain":false,
            "input_authorized":false
        })
        .to_string(),
    )])
}
pub(super) fn settle_acquired_read(
    lane: &mut DesktopLane,
    target: &DesktopReadTarget,
    receipt: &mut CuaReceipt,
) {
    if receipt.evidence != CuaEvidence::Acknowledged {
        return;
    }
    let rewritten = (|| {
        target.validate()?;
        let original = receipt.result.as_ref().ok_or(CuaError::Unknown)?;
        match target.request {
            DesktopReadRequest::Accessibility(request) => {
                let parsed = parse_acquired(original, request.pid, request.window_id)?;
                let mut next = lane.next_read_alias.checked_add(1).ok_or(CuaError::Busy)?;
                if format!("s{next:08x}") == parsed.native_snapshot_id() {
                    next = next.checked_add(1).ok_or(CuaError::Busy)?;
                }
                lane.next_read_alias = next;
                parsed.rewrite_result(original, &format!("s{next:08x}"))
            }
            DesktopReadRequest::WindowCapture(request) => {
                crate::providers::cua::window_capture::project_acquired(original, &request)
            }
        }
    })();
    // Preserve the original native ACK even when the returned read is not
    // adequate evidence. Neither read creates input authority.
    receipt.result = Some(rewritten.unwrap_or_else(|_| insufficient_read()));
}
