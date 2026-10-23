//! Admission uses facts supplied by authenticated adapters, never tool JSON.
use styx_contracts::{capability::*, error::ErrorCategory, identity::*, operation::*, session::*};

/// Fresh facts must be read under the same coordinator as dispatch and revocation.
/// Constructing this value does not authenticate a remote caller or desktop agent.
#[derive(Debug, Clone)]
pub struct AdmissionFacts {
    pub device_id: DeviceId,
    pub grant_revision: u64,
    pub local_policy_allowed: bool,
    pub descriptor: CapabilityDescriptor,
    pub session_state: Option<SessionState>,
    pub current_observation: Option<ObservationId>,
}

pub fn check_admission(
    context: &PreparedContext,
    facts: &AdmissionFacts,
    now: MonotonicMillis,
) -> Result<(), ErrorCategory> {
    let d = &facts.descriptor;
    if now >= context.deadline {
        return Err(ErrorCategory::OperationTimeout);
    }
    if context.device_id != facts.device_id || context.grant_revision != facts.grant_revision {
        return Err(ErrorCategory::StateConflict);
    }
    if d.contract_version != styx_contracts::CONTRACT_VERSION
        || d.capability_id != context.capability
    {
        return Err(ErrorCategory::ProtocolMismatch);
    }
    if context.capability == CapabilityId::BrowserAttach {
        return Err(ErrorCategory::CapabilityUnsupported);
    }
    if !d.configured || !d.remote_grant || !facts.local_policy_allowed {
        return Err(ErrorCategory::PermissionDenied);
    }
    match d.authorization {
        Authorization::Granted => {}
        Authorization::Required => return Err(ErrorCategory::PermissionRequired),
        Authorization::Denied | Authorization::Revoked => {
            return Err(ErrorCategory::PermissionDenied);
        }
        Authorization::Unknown => return Err(ErrorCategory::PermissionRequired),
    }
    if d.availability != Availability::Available {
        return Err(d.reason.unwrap_or(ErrorCategory::CapabilityUnsupported));
    }
    if context.capability.requires_session() {
        let session = context
            .session
            .as_ref()
            .ok_or(ErrorCategory::NoGraphicalSession)?;
        if d.target_session.as_ref() != Some(session) {
            return Err(ErrorCategory::SessionDisconnected);
        }
        match facts.session_state {
            Some(SessionState::Ready) => {}
            Some(SessionState::Locked) => return Err(ErrorCategory::SessionLocked),
            Some(SessionState::AuthorizationRequired) => {
                return Err(ErrorCategory::PermissionRequired);
            }
            _ => return Err(ErrorCategory::SessionDisconnected),
        }
        if matches!(
            context.capability,
            CapabilityId::DesktopPointer
                | CapabilityId::DesktopKeyboard
                | CapabilityId::DesktopWindowsControl
        ) && context.observation.is_none()
        {
            return Err(ErrorCategory::StaleObservation);
        }
        if let Some(observation) = &context.observation
            && facts.current_observation.as_ref() != Some(observation)
        {
            return Err(ErrorCategory::StaleObservation);
        }
    } else if context.session.is_some() {
        // Headless work never silently acquires a desktop binding.
        return Err(ErrorCategory::StateConflict);
    }
    Ok(())
}
