//! Host-local desktop facts, composed under the existing admission mutex.
//!
//! Bootstrap reads the current native user and fresh OS entropy. Request APIs
//! take neither a principal override, incarnation, nor a clock value. The future
//! native adapter must prove login/compositor/Agent association before using the
//! HostAuthority registration port: discovery hints or Unknown candidates are
//! not registrations. This module does not implement that OS proof, Cua, GUI,
//! persistence of revocation, or a desktop execution provider.
//!
//! Projection contains no Gateway grant. A future desktop dispatch must combine
//! it with real configured/grant/local-policy facts under the same Host mutex.
//! Session metadata's 1MiB bound is distinct from the Host's queued-I/O budget.
use std::time::{Duration, Instant};
use styx_contracts::{
    capability::*,
    error::{ErrorCategory, Recovery},
    identity::*,
    session::*,
};
pub use styx_core::session::{
    ApprovedBinding, NativePrincipal, RegistrationFacts, Selection, SessionError, SessionEvent,
    SessionProjection, SessionView,
};
use styx_core::session::{
    RegistryIncarnation, SessionControl, SessionLimits, SessionRegistry, VerifiedRegistration,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionSupport {
    Enabled,
    UnsupportedPlatform,
    EntropyUnavailable,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostSessionError {
    UnsupportedPlatform,
    EntropyUnavailable,
    Stopping,
    InvalidEvidence,
    Core(SessionError),
}
impl From<SessionError> for HostSessionError {
    fn from(error: SessionError) -> Self {
        Self::Core(error)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionStatus {
    pub support: SessionSupport,
    pub sessions: usize,
    pub metadata_bytes: usize,
    pub event_cursor: u64,
}
/// No network or ordinary owner can construct this branded registration.
/// Cross-Host delivery is checked again by the Core registry on consumption.
pub struct SessionRegistration(VerifiedRegistration);
/// Timeless trusted adapter evidence. The Host stamps its own monotonic clock
/// and applies the bounded lifetime; a network client cannot supply `now`.
pub struct ProviderEvidence {
    pub capability: CapabilityId,
    pub provider: ProviderId,
    pub availability: Availability,
    pub authorization: Authorization,
    pub provenance: String,
    pub reason: Option<ErrorCategory>,
    pub recovery: Recovery,
}
struct EnabledSessions {
    registry: SessionRegistry,
    control: SessionControl,
}
enum Storage {
    Enabled(Box<EnabledSessions>),
    Unavailable(SessionSupport),
}
pub(crate) struct HostSessions {
    origin: Instant,
    storage: Storage,
}
impl HostSessions {
    pub(crate) fn bootstrap(generation: HostGeneration, origin: Instant) -> Self {
        let storage = match native_principal() {
            None => Storage::Unavailable(SessionSupport::UnsupportedPlatform),
            Some(principal) => {
                let mut entropy = [0u8; 32];
                if getrandom::fill(&mut entropy).is_err() {
                    Storage::Unavailable(SessionSupport::EntropyUnavailable)
                } else {
                    let registry =
                        RegistryIncarnation::from_fresh_entropy(entropy).and_then(|incarnation| {
                            SessionRegistry::new_owned(
                                generation,
                                incarnation,
                                principal,
                                SessionLimits::default(),
                            )
                        });
                    match registry {
                        Ok((registry, control)) => {
                            Storage::Enabled(Box::new(EnabledSessions { registry, control }))
                        }
                        // The fixed defaults are valid; invalid all-zero entropy
                        // cannot produce a ready registry or fake fresh identity.
                        Err(_) => Storage::Unavailable(SessionSupport::EntropyUnavailable),
                    }
                }
            }
        };
        Self { origin, storage }
    }
    fn now(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
    fn enabled(&self) -> Result<&EnabledSessions, HostSessionError> {
        match &self.storage {
            Storage::Enabled(value) => Ok(value),
            Storage::Unavailable(SessionSupport::UnsupportedPlatform) => {
                Err(HostSessionError::UnsupportedPlatform)
            }
            Storage::Unavailable(_) => Err(HostSessionError::EntropyUnavailable),
        }
    }
    fn enabled_mut(&mut self) -> Result<&mut EnabledSessions, HostSessionError> {
        match &mut self.storage {
            Storage::Enabled(value) => Ok(value),
            Storage::Unavailable(SessionSupport::UnsupportedPlatform) => {
                Err(HostSessionError::UnsupportedPlatform)
            }
            Storage::Unavailable(_) => Err(HostSessionError::EntropyUnavailable),
        }
    }
    pub(crate) fn status(&self) -> SessionStatus {
        match &self.storage {
            Storage::Enabled(value) => SessionStatus {
                support: SessionSupport::Enabled,
                sessions: value.registry.list(self.now()).len(),
                metadata_bytes: value.registry.metadata_bytes(),
                event_cursor: value.registry.cursor(),
            },
            Storage::Unavailable(support) => SessionStatus {
                support: *support,
                sessions: 0,
                metadata_bytes: 0,
                event_cursor: 0,
            },
        }
    }
    pub(crate) fn attest(
        &self,
        facts: RegistrationFacts,
    ) -> Result<SessionRegistration, HostSessionError> {
        let value = self.enabled()?;
        Ok(SessionRegistration(
            value.control.attest_registration(facts)?,
        ))
    }
    pub(crate) fn register(
        &mut self,
        registration: SessionRegistration,
    ) -> Result<SessionBinding, HostSessionError> {
        let value = self.enabled_mut()?;
        Ok(value.registry.register(&value.control, registration.0)?)
    }
    pub(crate) fn set_state(
        &mut self,
        binding: &SessionBinding,
        state: SessionState,
    ) -> Result<SessionBinding, HostSessionError> {
        let value = self.enabled_mut()?;
        Ok(value.registry.set_state(&value.control, binding, state)?)
    }
    pub(crate) fn provider(
        &mut self,
        binding: &SessionBinding,
        evidence: ProviderEvidence,
        valid_for: Duration,
    ) -> Result<(), HostSessionError> {
        if valid_for.is_zero() || valid_for > Duration::from_secs(60) {
            return Err(HostSessionError::InvalidEvidence);
        }
        let observed_at = self.now();
        let millis =
            u64::try_from(valid_for.as_millis()).map_err(|_| HostSessionError::InvalidEvidence)?;
        if millis == 0 {
            return Err(HostSessionError::InvalidEvidence);
        }
        let valid_until = observed_at
            .checked_add(millis)
            .ok_or(HostSessionError::InvalidEvidence)?;
        let value = self.enabled_mut()?;
        Ok(value.registry.update_provider(
            &value.control,
            binding,
            styx_core::session::ProviderFacts {
                capability: evidence.capability,
                provider: evidence.provider,
                availability: evidence.availability,
                authorization: evidence.authorization,
                observed_at,
                valid_until,
                provenance: evidence.provenance,
                reason: evidence.reason,
                recovery: evidence.recovery,
            },
        )?)
    }
    pub(crate) fn observe(
        &mut self,
        binding: &SessionBinding,
        capability: CapabilityId,
    ) -> Result<ObservationId, HostSessionError> {
        let now = self.now();
        let value = self.enabled_mut()?;
        Ok(value
            .registry
            .record_observation(&value.control, binding, capability, now)?)
    }
    pub(crate) fn select(
        &self,
        selection: Selection<'_>,
        allow_unbound: bool,
    ) -> Result<ApprovedBinding, HostSessionError> {
        let value = self.enabled()?;
        Ok(value.registry.select(
            &value.control.selection_authority(allow_unbound),
            selection,
            self.now(),
        )?)
    }
    pub(crate) fn project(
        &self,
        binding: &SessionBinding,
        capability: CapabilityId,
    ) -> Result<SessionProjection, HostSessionError> {
        Ok(self
            .enabled()?
            .registry
            .project(binding, capability, self.now())?)
    }
    pub(crate) fn list(&self) -> Result<Vec<SessionView>, HostSessionError> {
        Ok(self.enabled()?.registry.list(self.now()))
    }
    pub(crate) fn inspect(
        &self,
        binding: &SessionBinding,
    ) -> Result<SessionView, HostSessionError> {
        Ok(self.enabled()?.registry.inspect(binding, self.now())?)
    }
    pub(crate) fn events(&self, after: u64) -> Result<Vec<SessionEvent>, HostSessionError> {
        Ok(self.enabled()?.registry.events_since(after)?)
    }
    pub(crate) fn forget(&mut self, binding: &SessionBinding) -> Result<(), HostSessionError> {
        let value = self.enabled_mut()?;
        Ok(value.registry.forget(&value.control, binding)?)
    }
}
#[cfg(target_os = "linux")]
fn native_principal() -> Option<NativePrincipal> {
    Some(NativePrincipal::LinuxUid(
        nix::unistd::Uid::current().as_raw(),
    ))
}
#[cfg(target_os = "macos")]
fn native_principal() -> Option<NativePrincipal> {
    Some(NativePrincipal::MacUid(
        nix::unistd::Uid::current().as_raw(),
    ))
}
// Windows SID/token observation has not been implemented. Never derive it from
// USERNAME, a session DTO, or a fabricated cross-platform UID.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn native_principal() -> Option<NativePrincipal> {
    None
}
