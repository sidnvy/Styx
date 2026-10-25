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
    check_admission_inner(context, facts, now, AdmissionMode::Ordinary)
}

/// A single explicitly prepared AX read may obtain evidence while OS permission
/// is still unknown. This never authorizes AX mutation, capture or native input,
/// and never changes any descriptor to Granted. Runtime must additionally prove
/// the immutable payload is the fixed, screenshot-free native AX read route.
pub fn check_desktop_read_acquisition(
    context: &PreparedContext,
    facts: &AdmissionFacts,
    now: MonotonicMillis,
) -> Result<(), ErrorCategory> {
    if context.capability != CapabilityId::DesktopAccessibility
        || context.session.is_none()
        || context.observation.is_some()
        || facts.descriptor.scope != Scope::Session
    {
        return Err(ErrorCategory::StateConflict);
    }
    check_admission_inner(context, facts, now, AdmissionMode::ReadAcquisition)
}

/// A fixed exact-window screenshot attempt has the same acquisition boundary
/// as AX reading, but never grants AX, pointer or keyboard authorization.
pub fn check_desktop_window_capture_acquisition(
    context: &PreparedContext,
    facts: &AdmissionFacts,
    now: MonotonicMillis,
) -> Result<(), ErrorCategory> {
    if context.capability != CapabilityId::DesktopCapture
        || context.session.is_none()
        || context.observation.is_some()
        || facts.descriptor.scope != Scope::Session
    {
        return Err(ErrorCategory::StateConflict);
    }
    check_admission_inner(context, facts, now, AdmissionMode::ReadAcquisition)
}

/// Only the dedicated target-bound EditableText write-attempt port may use
/// this policy. Unknown OS permission remains Unknown: the protected OS call
/// performs final authorization, and a lost/negative write reply is not replayed.
/// Runtime must prove the original owner/resource/native snapshot/object and
/// select only the signed once-write provider; ordinary input remains closed.
pub fn check_desktop_accessibility_write_attempt(
    context: &PreparedContext,
    facts: &AdmissionFacts,
    now: MonotonicMillis,
) -> Result<(), ErrorCategory> {
    if context.capability != CapabilityId::DesktopAccessibility
        || context.session.is_none()
        || context.observation.is_none()
        || facts.current_observation != context.observation
        || facts.descriptor.scope != Scope::Session
    {
        return Err(ErrorCategory::StaleObservation);
    }
    check_admission_inner(context, facts, now, AdmissionMode::TargetBoundWriteAttempt)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AdmissionMode {
    Ordinary,
    ReadAcquisition,
    TargetBoundWriteAttempt,
}

fn check_admission_inner(
    context: &PreparedContext,
    facts: &AdmissionFacts,
    now: MonotonicMillis,
    mode: AdmissionMode,
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
        Authorization::Required | Authorization::Unknown
            if mode == AdmissionMode::ReadAcquisition => {}
        Authorization::Unknown if mode == AdmissionMode::TargetBoundWriteAttempt => {}
        Authorization::Required => return Err(ErrorCategory::PermissionRequired),
        Authorization::Denied | Authorization::Revoked => {
            return Err(ErrorCategory::PermissionDenied);
        }
        Authorization::Unknown => return Err(ErrorCategory::PermissionRequired),
    }
    if d.availability != Availability::Available
        && !(mode == AdmissionMode::ReadAcquisition && d.availability == Availability::Unavailable)
    {
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
            // Degraded is an aggregate session state: another provider may be
            // unavailable while this exact descriptor is Available + Granted.
            Some(SessionState::Ready | SessionState::Degraded) => {}
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
