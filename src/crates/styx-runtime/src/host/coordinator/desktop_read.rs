//! Read acquisition remains a Core action. Its presentation alias is not input authority.
use super::desktop::{DesktopLane, desktop};
use super::*;
use crate::providers::cua::{
    CuaError, CuaEvidence, CuaReceipt, DesktopReadRequest, DesktopReadTarget,
    ax_snapshot::{ParsedAxSnapshot, parse_acquired},
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
        current_observation: provider.observation,
    })
}
fn insufficient_read(error: CuaError, original: Option<&CallToolResult>) -> CallToolResult {
    let unresolved = original
        .and_then(|result| result.structured_content.as_ref())
        .is_some_and(|value| {
            value.get("degraded").and_then(serde_json::Value::as_bool) == Some(true)
                && value
                    .get("degraded_reason")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|reason| reason.starts_with("ax_window_unresolved:"))
        });
    let (category, code, reason) = if unresolved {
        (
            ErrorCategory::StaleObservation,
            "desktop_window_unresolved",
            "The window exists, but its accessibility surface is unavailable. Read it again after the window is visible and the app has settled.",
        )
    } else {
        let category = match error {
            CuaError::PermissionDenied => ErrorCategory::PermissionDenied,
            CuaError::InvalidRequest => ErrorCategory::InvalidRequest,
            CuaError::ProtocolMismatch => ErrorCategory::ProtocolMismatch,
            CuaError::StaleObservation => ErrorCategory::StaleObservation,
            CuaError::Unsupported => ErrorCategory::CapabilityUnsupported,
            CuaError::Busy => ErrorCategory::Busy,
            CuaError::Unknown | CuaError::CleanupUnconfirmed => ErrorCategory::ResultUnknown,
        };
        (
            category,
            "desktop_read_not_proven",
            "The native response did not contain a usable window observation.",
        )
    };
    CallToolResult::error(vec![ContentBlock::text(
        serde_json::json!({
            "category":category, "error":code, "reason":reason,
            "native_reason":if unresolved { Some("ax_window_unresolved") } else { None },
            "execution_certainty":"acknowledged", "uncertain":false,
            "input_authorized":false
        })
        .to_string(),
    )])
}
pub(super) fn authorize_result(
    ledger: &styx_core::operations::OperationLedger,
    owner: &styx_core::operations::OwnerLease,
    operation: &styx_contracts::operation::OperationId,
    digest: styx_contracts::identity::Sha256Digest,
    facts: &AdmissionFacts,
    now: MonotonicMillis,
    receipt: &mut CuaReceipt,
) -> Result<(), CoordinatorError> {
    if receipt.evidence == CuaEvidence::NotDispatched {
        // A known refusal carries no acquired data. Core correctly records it
        // as Failed, so it must not enter the Succeeded-only read-data gate.
        // Keep the original owner/digest/purpose binding and return only the
        // trusted typed refusal; no native payload or observation is delivered.
        let snapshot = ledger.inspect(owner, operation, digest)?;
        if receipt.operation != *operation
            || snapshot.state != OperationState::Failed
            || snapshot.target.is_none()
            || !matches!(
                ledger.inspect_purpose(owner, operation, digest)?,
                styx_core::operations::OperationPurpose::DesktopAccessibilityReadAcquisition
                    | styx_core::operations::OperationPurpose::DesktopWindowCaptureReadAcquisition
            )
        {
            return Err(ErrorCategory::StateConflict.into());
        }
        receipt.result = None;
        return Ok(());
    }
    ledger
        .authorize_desktop_read_result(owner, operation, digest, facts, now)
        .map(|_| ())
        .map_err(CoordinatorError::from)
}
pub(super) fn settle_acquired_read(
    lane: &mut DesktopLane,
    target: &DesktopReadTarget,
    receipt: &mut CuaReceipt,
    acquisition: bool,
) -> Option<(ParsedAxSnapshot, String)> {
    if receipt.evidence != CuaEvidence::Acknowledged {
        return None;
    }
    let rewritten = (|| {
        target.validate()?;
        let original = receipt.result.as_ref().ok_or(CuaError::Unknown)?;
        match target.request {
            DesktopReadRequest::Accessibility(request) => {
                let parsed = if acquisition {
                    parse_acquired(original, request.pid, request.window_id)?
                } else {
                    crate::providers::cua::ax_snapshot::parse_observed(
                        original,
                        request.pid,
                        request.window_id,
                    )?
                };
                let mut next = lane.next_read_alias.checked_add(1).ok_or(CuaError::Busy)?;
                if format!("s{next:08x}") == parsed.native_snapshot_id() {
                    next = next.checked_add(1).ok_or(CuaError::Busy)?;
                }
                lane.next_read_alias = next;
                let alias = format!("s{next:08x}");
                let result = parsed.rewrite_result(original, &alias)?;
                Ok((result, Some((parsed, alias))))
            }
            DesktopReadRequest::WindowCapture(request) => {
                crate::providers::cua::window_capture::project_acquired(original, &request)
                    .map(|result| (result, None))
            }
        }
    })();
    // The original ACK is preserved even when the read is inadequate. Only the
    // caller's fresh Core/owner/resource settlement can install the returned map.
    match rewritten {
        Ok((result, observation)) => {
            receipt.result = Some(result);
            observation
        }
        Err(error) => {
            receipt.result = Some(insufficient_read(error, receipt.result.as_ref()));
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    #[test]
    fn unresolved_native_window_is_not_a_permission_failure_or_input_target() {
        // Minimal fields from the real Mac reply: a CG window existed but no
        // AXWindow matched it. Never substitute menu-bar/sibling-window rows.
        let native = CallToolResult::structured(json!({
            "pid":42, "window_id":7, "tree_format":"elements",
            "degraded":true,
            "degraded_reason":"ax_window_unresolved: no AXWindow reports this CGWindowID",
            "elements":[], "elements_complete":false, "truncated":false,
            "element_count":0, "returned_element_count":0, "total_element_count":0
        }));
        let error = match parse_acquired(&native, 42, 7) {
            Err(error) => error,
            Ok(_) => panic!("unresolved window must not acquire input tokens"),
        };
        let output = insufficient_read(error, Some(&native));
        let value: Value =
            serde_json::from_str(&output.content[0].as_text().unwrap().text).unwrap();
        assert_eq!(value["category"], "STALE_OBSERVATION");
        assert_eq!(value["native_reason"], "ax_window_unresolved");
        assert_eq!(value["input_authorized"], false);
        assert_eq!(value["uncertain"], false);
        assert!(value.get("elements").is_none());
        assert!(value.get("snapshot_id").is_none());
    }

    #[test]
    fn malformed_read_is_not_reported_as_missing_os_permission() {
        let output = insufficient_read(CuaError::ProtocolMismatch, None);
        let value: Value =
            serde_json::from_str(&output.content[0].as_text().unwrap().text).unwrap();
        assert_eq!(value["category"], "PROTOCOL_MISMATCH");
        assert_eq!(value["input_authorized"], false);
    }
}
