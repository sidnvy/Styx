//! The only mutation facade is HostAuthority. Every call uses the same State
//! mutex as operation prepare/dispatch and never replaces Exec AdmissionFacts.
use super::*;
use crate::session::*;
use styx_contracts::{
    capability::CapabilityId,
    session::{SessionBinding, SessionState},
};
impl HostCoordinator {
    pub fn sessions_status(&self) -> SessionStatus {
        self.inner
            .state
            .lock()
            .expect("Host state mutex")
            .sessions
            .status()
    }
    pub fn list_sessions(&self) -> Result<Vec<SessionView>, HostSessionError> {
        self.inner
            .state
            .lock()
            .expect("Host state mutex")
            .sessions
            .list()
    }
    pub fn inspect_session(
        &self,
        binding: &SessionBinding,
    ) -> Result<SessionView, HostSessionError> {
        self.inner
            .state
            .lock()
            .expect("Host state mutex")
            .sessions
            .inspect(binding)
    }
    pub fn session_events_since(&self, cursor: u64) -> Result<Vec<SessionEvent>, HostSessionError> {
        self.inner
            .state
            .lock()
            .expect("Host state mutex")
            .sessions
            .events(cursor)
    }
}
impl HostAuthority {
    fn with_sessions<T>(
        &self,
        f: impl FnOnce(&mut HostSessions) -> Result<T, HostSessionError>,
    ) -> Result<T, HostSessionError> {
        let mut state = self.inner.state.lock().expect("Host state mutex");
        state.with_sessions(f)
    }
    /// Privileged future adapter port. Caller must have verified kernel/login/
    /// display/Agent association; a Linux Unknown candidate is not such proof.
    pub fn attest_session_registration(
        &self,
        facts: RegistrationFacts,
    ) -> Result<SessionRegistration, HostSessionError> {
        self.with_sessions(|sessions| sessions.attest(facts))
    }
    pub fn register_session(
        &self,
        registration: SessionRegistration,
    ) -> Result<SessionBinding, HostSessionError> {
        self.with_sessions(|sessions| sessions.register(registration))
    }
    pub fn set_session_state(
        &self,
        binding: &SessionBinding,
        state: SessionState,
    ) -> Result<SessionBinding, HostSessionError> {
        self.with_sessions(|sessions| sessions.set_state(binding, state))
    }
    pub fn update_session_provider(
        &self,
        binding: &SessionBinding,
        evidence: ProviderEvidence,
        valid_for: Duration,
    ) -> Result<(), HostSessionError> {
        self.with_sessions(|sessions| sessions.provider(binding, evidence, valid_for))
    }
    pub fn record_session_observation(
        &self,
        binding: &SessionBinding,
        capability: CapabilityId,
    ) -> Result<ObservationId, HostSessionError> {
        self.with_sessions(|sessions| sessions.observe(binding, capability))
    }
    /// Approved binding is not an execution permit or Gateway capability grant.
    pub fn select_session(
        &self,
        selection: Selection<'_>,
        allow_unbound: bool,
    ) -> Result<ApprovedBinding, HostSessionError> {
        self.with_sessions(|sessions| sessions.select(selection, allow_unbound))
    }
    /// Trusted facts only. Future desktop dispatch must compose actual grants
    /// under this same mutex, not cache this projection across an await.
    pub fn project_session(
        &self,
        binding: &SessionBinding,
        capability: CapabilityId,
    ) -> Result<SessionProjection, HostSessionError> {
        self.with_sessions(|sessions| sessions.project(binding, capability))
    }
    pub fn forget_terminated_session(
        &self,
        binding: &SessionBinding,
    ) -> Result<(), HostSessionError> {
        self.with_sessions(|sessions| sessions.forget(binding))
    }
}
#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
