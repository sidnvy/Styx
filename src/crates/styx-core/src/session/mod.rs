//! Bounded, process-local desktop facts. Registration is a trusted runtime port,
//! not a network DTO, OS verifier, grant authority, or second operation ledger.
use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
};
use styx_contracts::{
    capability::*,
    error::{ErrorCategory, Recovery},
    identity::*,
    session::*,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativePrincipal {
    LinuxUid(u32),
    MacUid(u32),
    WindowsSid(String),
}
/// Move-only bootstrap input. The runtime must obtain fresh OS entropy on every
/// construction, even under the same HostGeneration. This is not a stored key.
/// Core neither generates entropy nor promises revocation survives restart.
pub struct RegistryIncarnation([u8; 32]);
impl RegistryIncarnation {
    pub fn from_fresh_entropy(bytes: [u8; 32]) -> Result<Self> {
        if bytes == [0; 32] {
            return Err(SessionError::Invalid);
        }
        Ok(Self(bytes))
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    Authority,
    Invalid,
    Capacity,
    Exhausted,
    NotFound,
    StaleBinding,
    SessionAmbiguous,
    NoGraphicalSession,
    SessionLocked,
    SessionDisconnected,
    PermissionRequired,
    PermissionDenied,
    CapabilityUnsupported,
    StaleObservation,
    ResnapshotRequired,
    Provider(ErrorCategory),
}
type Result<T> = std::result::Result<T, SessionError>;
#[derive(Debug, Clone, Copy)]
pub struct SessionLimits {
    pub sessions: usize,
    pub providers_per_session: usize,
    pub events: usize,
    pub metadata_bytes: usize,
}
impl Default for SessionLimits {
    fn default() -> Self {
        Self {
            sessions: 32,
            providers_per_session: 16,
            events: 256,
            metadata_bytes: 1024 * 1024,
        }
    }
}
impl SessionLimits {
    fn valid(self) -> bool {
        self.sessions > 0
            && self.sessions <= 32
            && self.providers_per_session > 0
            && self.providers_per_session <= 16
            && self.events > 0
            && self.events <= 256
            && self.metadata_bytes > 0
            && self.metadata_bytes <= 1024 * 1024
    }
}
/// Only trusted bootstrap retains this handle. Its holder must prove kernel
/// peer, user/login/compositor/Agent association before attesting any facts.
pub struct SessionControl {
    brand: Arc<()>,
    principal: NativePrincipal,
}
pub struct VerifiedRegistration {
    brand: Arc<()>,
    facts: RegistrationFacts,
}
pub struct SelectionAuthority {
    brand: Arc<()>,
    auto_bind_allowed: bool,
}
#[derive(Clone)]
pub struct ApprovedBinding {
    brand: Arc<()>,
    binding: SessionBinding,
}
impl ApprovedBinding {
    pub fn binding(&self) -> &SessionBinding {
        &self.binding
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationFacts {
    pub id: SessionId,
    pub identity: SessionIdentity,
    pub agent_instance: AgentInstanceId,
    pub protocol_version: u16,
    pub provenance: String,
}
impl SessionControl {
    /// Association proof lives in the authenticated runtime; no JSON boolean
    /// or environment hint is accepted as proof by this API.
    pub fn attest_registration(&self, facts: RegistrationFacts) -> Result<VerifiedRegistration> {
        validate_registration(&self.principal, &facts)?;
        Ok(VerifiedRegistration {
            brand: self.brand.clone(),
            facts,
        })
    }
    pub fn selection_authority(&self, auto_bind_allowed: bool) -> SelectionAuthority {
        SelectionAuthority {
            brand: self.brand.clone(),
            auto_bind_allowed,
        }
    }
}
pub enum Selection<'a> {
    Explicit(&'a SessionBinding),
    Approved(&'a ApprovedBinding),
    Unbound,
}
/// Provider evidence is independent of Gateway grant/configuration/local policy.
/// Monotonic times are supplied by the trusted Host clock, not remote requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderFacts {
    pub capability: CapabilityId,
    pub provider: ProviderId,
    pub availability: Availability,
    pub authorization: Authorization,
    pub observed_at: u64,
    pub valid_until: u64,
    pub provenance: String,
    pub reason: Option<ErrorCategory>,
    pub recovery: Recovery,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderView {
    pub facts: ProviderFacts,
    pub observation: Option<ObservationId>,
    pub revision: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionView {
    pub descriptor: SessionDescriptor,
    pub provenance: String,
    pub providers: Vec<ProviderView>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionProjection {
    pub binding: SessionBinding,
    pub state: SessionState,
    pub provider: ProviderView,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Registered,
    IdentityChanged,
    StateChanged,
    ProviderChanged,
    Observed,
    Forgotten,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionEvent {
    pub cursor: u64,
    pub binding: SessionBinding,
    pub kind: EventKind,
    pub capability: Option<CapabilityId>,
}
#[derive(Clone)]
struct Record {
    facts: RegistrationFacts,
    binding: SessionBinding,
    state: SessionState,
    providers: BTreeMap<CapabilityId, ProviderView>,
}
pub struct SessionRegistry {
    brand: Arc<()>,
    host: HostGeneration,
    incarnation: RegistryIncarnation,
    principal: NativePrincipal,
    limits: SessionLimits,
    issuer: u64,
    cursor: u64,
    records: BTreeMap<SessionId, Record>,
    events: VecDeque<SessionEvent>,
}
impl SessionRegistry {
    pub fn new_owned(
        host: HostGeneration,
        incarnation: RegistryIncarnation,
        principal: NativePrincipal,
        limits: SessionLimits,
    ) -> Result<(Self, SessionControl)> {
        if !limits.valid() || matches!(&principal, NativePrincipal::WindowsSid(s) if !bounded(s)) {
            return Err(SessionError::Invalid);
        }
        let brand = Arc::new(());
        let control = SessionControl {
            brand: brand.clone(),
            principal: principal.clone(),
        };
        let registry = Self {
            brand,
            host,
            incarnation,
            principal,
            limits,
            issuer: 0,
            cursor: 0,
            records: BTreeMap::new(),
            events: VecDeque::new(),
        };
        if registry.metadata_bytes() > limits.metadata_bytes {
            return Err(SessionError::Capacity);
        }
        Ok((registry, control))
    }
    fn authority(&self, brand: &Arc<()>) -> Result<()> {
        if Arc::ptr_eq(&self.brand, brand) {
            Ok(())
        } else {
            Err(SessionError::Authority)
        }
    }
    fn issued(&self, domain: &[u8]) -> Result<(u64, String)> {
        let sequence = self.issuer.checked_add(1).ok_or(SessionError::Exhausted)?;
        // Fixed domain, length-delimited HostGeneration, fixed-width counter.
        // This is an internal opaque identity derivation, not JSON signing.
        let mut bytes = Vec::with_capacity(256);
        bytes.extend_from_slice(domain);
        bytes.extend_from_slice(&self.incarnation.0);
        bytes.extend_from_slice(&(self.host.as_str().len() as u64).to_be_bytes());
        bytes.extend_from_slice(self.host.as_str().as_bytes());
        bytes.extend_from_slice(&sequence.to_be_bytes());
        Ok((sequence, Sha256Digest::of_bytes(&bytes).to_hex()))
    }
    fn binding(&self, id: SessionId) -> Result<(u64, SessionBinding)> {
        let (sequence, value) = self.issued(b"styx.session.generation.v1\0")?;
        let generation = SessionGeneration::try_from(value).map_err(|_| SessionError::Invalid)?;
        Ok((sequence, SessionBinding { id, generation }))
    }
    fn current(&self, binding: &SessionBinding) -> Result<&Record> {
        let record = self
            .records
            .get(&binding.id)
            .ok_or(SessionError::NotFound)?;
        if &record.binding != binding {
            return Err(SessionError::StaleBinding);
        }
        Ok(record)
    }
    fn record_bytes(record: &Record) -> usize {
        2048 + identity_bytes(&record.facts.identity)
            + record.facts.provenance.len()
            + record
                .providers
                .values()
                .map(|p| 1024 + p.facts.provenance.len())
                .sum::<usize>()
    }
    /// Conservative logical metadata accounting; not the Host queued-I/O metric.
    pub fn metadata_bytes(&self) -> usize {
        1024 + self.records.values().map(Self::record_bytes).sum::<usize>()
            + self.events.len() * 1024
    }
    fn install(
        &mut self,
        record: Record,
        kind: EventKind,
        capability: Option<CapabilityId>,
        issuer: Option<u64>,
    ) -> Result<SessionBinding> {
        let cursor = self.cursor.checked_add(1).ok_or(SessionError::Exhausted)?;
        let previous = self.records.get(&record.binding.id);
        if previous.is_none() && self.records.len() >= self.limits.sessions {
            return Err(SessionError::Capacity);
        }
        let event_count = (self.events.len() + 1).min(self.limits.events);
        let bytes = self.metadata_bytes()
            - self.events.len() * 1024
            - previous.map_or(0, Self::record_bytes)
            + Self::record_bytes(&record)
            + event_count * 1024;
        if bytes > self.limits.metadata_bytes {
            return Err(SessionError::Capacity);
        }
        let binding = record.binding.clone();
        self.records.insert(binding.id.clone(), record);
        self.commit_event(SessionEvent {
            cursor,
            binding: binding.clone(),
            kind,
            capability,
        });
        if let Some(issuer) = issuer {
            self.issuer = issuer;
        }
        Ok(binding)
    }
    fn commit_event(&mut self, event: SessionEvent) {
        self.cursor = event.cursor;
        if self.events.len() == self.limits.events {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }
    pub fn register(
        &mut self,
        control: &SessionControl,
        registration: VerifiedRegistration,
    ) -> Result<SessionBinding> {
        self.authority(&control.brand)?;
        self.authority(&registration.brand)?;
        validate_registration(&self.principal, &registration.facts)?;
        // A retained revoked identity is a tombstone, not a rediscovery hint.
        // Reject aliases even before revocation so a second ID cannot retain
        // access to an identity whose first ID was subsequently revoked.
        for record in self.records.values() {
            if record.binding.id == registration.facts.id && record.state == SessionState::Revoked {
                return Err(SessionError::PermissionDenied);
            }
            if record.binding.id != registration.facts.id
                && record.facts.identity == registration.facts.identity
            {
                return Err(if record.state == SessionState::Revoked {
                    SessionError::PermissionDenied
                } else {
                    SessionError::Invalid
                });
            }
        }
        let kind = if let Some(old) = self.records.get(&registration.facts.id) {
            if old.facts == registration.facts
                && !matches!(
                    old.state,
                    SessionState::Disconnected | SessionState::Revoked | SessionState::Terminated
                )
            {
                return Ok(old.binding.clone());
            }
            EventKind::IdentityChanged
        } else {
            EventKind::Registered
        };
        let (issuer, binding) = self.binding(registration.facts.id.clone())?;
        self.install(
            Record {
                facts: registration.facts,
                binding,
                state: SessionState::Discovered,
                providers: BTreeMap::new(),
            },
            kind,
            None,
            Some(issuer),
        )
    }
    /// Lifecycle facts never fabricate Ready. Recovery, lock/unlock and other
    /// lifecycle transitions allocate a new generation and discard old evidence.
    pub fn set_state(
        &mut self,
        control: &SessionControl,
        binding: &SessionBinding,
        state: SessionState,
    ) -> Result<SessionBinding> {
        self.authority(&control.brand)?;
        if matches!(
            state,
            SessionState::Ready | SessionState::Degraded | SessionState::AuthorizationRequired
        ) {
            return Err(SessionError::Invalid);
        }
        let old = self.current(binding)?;
        if old.state == state {
            return Ok(binding.clone());
        }
        if matches!(old.state, SessionState::Revoked | SessionState::Terminated) {
            return Err(SessionError::SessionDisconnected);
        }
        let mut next = old.clone();
        let (issuer, new_binding) = self.binding(binding.id.clone())?;
        next.binding = new_binding;
        next.state = state;
        next.providers.clear();
        self.install(next, EventKind::StateChanged, None, Some(issuer))
    }
    pub fn update_provider(
        &mut self,
        control: &SessionControl,
        binding: &SessionBinding,
        facts: ProviderFacts,
    ) -> Result<()> {
        self.authority(&control.brand)?;
        validate_provider(&facts)?;
        let old = self.current(binding)?;
        if !matches!(
            old.state,
            SessionState::Discovered
                | SessionState::Connecting
                | SessionState::Ready
                | SessionState::Degraded
                | SessionState::AuthorizationRequired
        ) {
            return Err(SessionError::SessionDisconnected);
        }
        if !old.providers.contains_key(&facts.capability)
            && old.providers.len() >= self.limits.providers_per_session
        {
            return Err(SessionError::Capacity);
        }
        if old
            .providers
            .get(&facts.capability)
            .is_some_and(|p| facts.observed_at < p.facts.observed_at)
        {
            return Err(SessionError::Invalid);
        }
        let revision = old
            .providers
            .get(&facts.capability)
            .map_or(Some(1), |p| p.revision.checked_add(1))
            .ok_or(SessionError::Exhausted)?;
        let capability = facts.capability;
        let mut next = old.clone();
        next.providers.insert(
            capability,
            ProviderView {
                facts,
                revision,
                observation: None,
            },
        );
        next.state = aggregate(&next.providers);
        self.install(next, EventKind::ProviderChanged, Some(capability), None)?;
        Ok(())
    }
    pub fn record_observation(
        &mut self,
        control: &SessionControl,
        binding: &SessionBinding,
        capability: CapabilityId,
        now: u64,
    ) -> Result<ObservationId> {
        self.authority(&control.brand)?;
        self.project(binding, capability, now)?;
        let (issuer, value) = self.issued(b"styx.session.observation.v1\0")?;
        let observation = ObservationId::try_from(value).map_err(|_| SessionError::Invalid)?;
        let mut next = self.current(binding)?.clone();
        let provider = next
            .providers
            .get_mut(&capability)
            .ok_or(SessionError::CapabilityUnsupported)?;
        provider.observation = Some(observation.clone());
        self.install(next, EventKind::Observed, Some(capability), Some(issuer))?;
        Ok(observation)
    }
    /// Trusted runtime reports an actual acquired AX snapshot, never an input
    /// grant. Unlike generic observation this preserves Unknown authorization;
    /// only the separately prepared exact-object write-attempt policy may use it.
    pub fn record_accessibility_read_observation(
        &mut self,
        control: &SessionControl,
        binding: &SessionBinding,
        now: u64,
    ) -> Result<ObservationId> {
        self.authority(&control.brand)?;
        let current = self.current(binding)?;
        usable_state(current.state)?;
        let provider = current
            .providers
            .get(&CapabilityId::DesktopAccessibility)
            .ok_or(SessionError::CapabilityUnsupported)?;
        if now < provider.facts.observed_at || now >= provider.facts.valid_until {
            return Err(SessionError::StaleObservation);
        }
        match provider.facts.authorization {
            Authorization::Denied | Authorization::Revoked => {
                return Err(SessionError::PermissionDenied);
            }
            Authorization::Required => return Err(SessionError::PermissionRequired),
            Authorization::Granted | Authorization::Unknown => {}
        }
        if provider.facts.availability != Availability::Available {
            return Err(SessionError::CapabilityUnsupported);
        }
        let (issuer, value) = self.issued(b"styx.session.observation.v1\0")?;
        let observation = ObservationId::try_from(value).map_err(|_| SessionError::Invalid)?;
        let mut next = self.current(binding)?.clone();
        next.providers
            .get_mut(&CapabilityId::DesktopAccessibility)
            .ok_or(SessionError::CapabilityUnsupported)?
            .observation = Some(observation.clone());
        self.install(
            next,
            EventKind::Observed,
            Some(CapabilityId::DesktopAccessibility),
            Some(issuer),
        )?;
        Ok(observation)
    }
    pub fn select(
        &self,
        authority: &SelectionAuthority,
        selection: Selection<'_>,
        now: u64,
    ) -> Result<ApprovedBinding> {
        self.authority(&authority.brand)?;
        let binding = match selection {
            Selection::Explicit(binding) => {
                self.current(binding)?;
                binding.clone()
            }
            Selection::Approved(approved) => {
                self.authority(&approved.brand)?;
                self.current(&approved.binding)?;
                approved.binding.clone()
            }
            Selection::Unbound => {
                if !authority.auto_bind_allowed {
                    return Err(SessionError::PermissionDenied);
                }
                // Locked/disconnected sessions remain candidates: availability
                // cannot silently choose another user's GUI on their behalf.
                let mut candidates = self.records.values().filter(|r| {
                    !matches!(r.state, SessionState::Revoked | SessionState::Terminated)
                });
                let candidate = candidates.next().ok_or(SessionError::NoGraphicalSession)?;
                if candidates.next().is_some() {
                    return Err(SessionError::SessionAmbiguous);
                }
                candidate.binding.clone()
            }
        };
        let current = view(self.current(&binding)?, now);
        if !matches!(
            current.descriptor.state,
            SessionState::Ready | SessionState::Degraded | SessionState::AuthorizationRequired
        ) {
            usable_state(current.descriptor.state)?;
        }
        if !current.providers.iter().any(provider_usable) {
            if current
                .providers
                .iter()
                .any(|p| p.facts.reason == Some(ErrorCategory::StaleObservation))
            {
                return Err(SessionError::StaleObservation);
            }
            if current.providers.iter().any(|p| {
                matches!(
                    p.facts.authorization,
                    Authorization::Denied | Authorization::Revoked
                )
            }) {
                return Err(SessionError::PermissionDenied);
            }
            if current.providers.iter().any(|p| {
                p.facts.reason != Some(ErrorCategory::StaleObservation)
                    && p.facts.authorization != Authorization::Granted
            }) {
                return Err(SessionError::PermissionRequired);
            }
            return Err(SessionError::Provider(
                current
                    .providers
                    .iter()
                    .find_map(|p| p.facts.reason)
                    .unwrap_or(ErrorCategory::CapabilityUnsupported),
            ));
        }
        Ok(ApprovedBinding {
            brand: self.brand.clone(),
            binding,
        })
    }
    pub fn project(
        &self,
        binding: &SessionBinding,
        capability: CapabilityId,
        now: u64,
    ) -> Result<SessionProjection> {
        if !session_capability(capability) {
            return Err(SessionError::CapabilityUnsupported);
        }
        let record = self.current(binding)?;
        if record.state != SessionState::AuthorizationRequired {
            usable_state(record.state)?;
        }
        let provider = record
            .providers
            .get(&capability)
            .ok_or(SessionError::CapabilityUnsupported)?;
        if now < provider.facts.observed_at || now >= provider.facts.valid_until {
            return Err(SessionError::StaleObservation);
        }
        match provider.facts.authorization {
            Authorization::Granted => {}
            Authorization::Denied | Authorization::Revoked => {
                return Err(SessionError::PermissionDenied);
            }
            Authorization::Required | Authorization::Unknown => {
                return Err(SessionError::PermissionRequired);
            }
        }
        if provider.facts.availability != Availability::Available {
            return Err(SessionError::Provider(
                provider
                    .facts
                    .reason
                    .unwrap_or(ErrorCategory::CapabilityUnsupported),
            ));
        }
        Ok(SessionProjection {
            binding: binding.clone(),
            state: view(record, now).descriptor.state,
            provider: provider.clone(),
        })
    }
    pub fn inspect(&self, binding: &SessionBinding, now: u64) -> Result<SessionView> {
        Ok(view(self.current(binding)?, now))
    }
    pub fn list(&self, now: u64) -> Vec<SessionView> {
        self.records
            .values()
            .map(|record| view(record, now))
            .collect()
    }
    pub fn cursor(&self) -> u64 {
        self.cursor
    }
    pub fn events_since(&self, cursor: u64) -> Result<Vec<SessionEvent>> {
        if cursor > self.cursor {
            return Err(SessionError::Invalid);
        }
        if self.events.front().is_some_and(|e| cursor < e.cursor - 1) {
            return Err(SessionError::ResnapshotRequired);
        }
        Ok(self
            .events
            .iter()
            .filter(|event| event.cursor > cursor)
            .cloned()
            .collect())
    }
    /// No live eviction. Old references remain invalid after explicit terminal
    /// removal and re-registration because the issuer highwater is retained.
    /// Revoked tombstones cannot be forgotten by ordinary discovery. They are
    /// process-local: durable revocation/re-authorization is not implemented.
    pub fn forget(&mut self, control: &SessionControl, binding: &SessionBinding) -> Result<()> {
        self.authority(&control.brand)?;
        let record = self.current(binding)?;
        if record.state != SessionState::Terminated {
            return Err(SessionError::Invalid);
        }
        let cursor = self.cursor.checked_add(1).ok_or(SessionError::Exhausted)?;
        let count = (self.events.len() + 1).min(self.limits.events);
        if self.metadata_bytes() - Self::record_bytes(record) - self.events.len() * 1024
            + count * 1024
            > self.limits.metadata_bytes
        {
            return Err(SessionError::Capacity);
        }
        self.records.remove(&binding.id);
        self.commit_event(SessionEvent {
            cursor,
            binding: binding.clone(),
            kind: EventKind::Forgotten,
            capability: None,
        });
        Ok(())
    }
}
fn bounded(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}
fn identity_bytes(identity: &SessionIdentity) -> usize {
    match identity {
        SessionIdentity::Linux {
            login_instance,
            seat,
            compositor_instance,
            display_identity,
            ..
        } => {
            login_instance.len()
                + seat.as_ref().map_or(0, String::len)
                + compositor_instance.len()
                + display_identity.len()
        }
        SessionIdentity::Macos {
            console_instance,
            window_server_instance,
            ..
        } => console_instance.len() + window_server_instance.as_ref().map_or(0, String::len),
        SessionIdentity::Windows {
            sid,
            window_station,
            desktop,
            ..
        } => sid.len() + window_station.len() + desktop.len(),
    }
}
fn validate_registration(principal: &NativePrincipal, facts: &RegistrationFacts) -> Result<()> {
    let valid = match (&facts.identity, principal) {
        (
            SessionIdentity::Linux {
                uid,
                login_instance,
                seat,
                compositor_instance,
                display_identity,
            },
            NativePrincipal::LinuxUid(expected),
        ) => {
            uid == expected
                && bounded(login_instance)
                && seat.as_ref().is_none_or(|s| bounded(s))
                && bounded(compositor_instance)
                && bounded(display_identity)
        }
        (
            SessionIdentity::Macos {
                uid,
                console_instance,
                window_server_instance,
                ..
            },
            NativePrincipal::MacUid(expected),
        ) => {
            uid == expected
                && bounded(console_instance)
                && window_server_instance.as_ref().is_none_or(|s| bounded(s))
        }
        (
            SessionIdentity::Windows {
                sid,
                window_station,
                desktop,
                ..
            },
            NativePrincipal::WindowsSid(expected),
        ) => sid == expected && bounded(sid) && bounded(window_station) && bounded(desktop),
        _ => false,
    };
    if !valid || facts.protocol_version == 0 || !bounded(&facts.provenance) {
        return Err(SessionError::Invalid);
    }
    Ok(())
}
fn session_capability(capability: CapabilityId) -> bool {
    capability.requires_session() && capability != CapabilityId::BrowserAttach
}
fn validate_provider(facts: &ProviderFacts) -> Result<()> {
    if !session_capability(facts.capability)
        || !bounded(&facts.provenance)
        || facts.observed_at >= facts.valid_until
    {
        return Err(SessionError::Invalid);
    }
    Ok(())
}
fn aggregate(providers: &BTreeMap<CapabilityId, ProviderView>) -> SessionState {
    let ready = providers
        .values()
        .filter(|p| {
            p.facts.availability == Availability::Available
                && p.facts.authorization == Authorization::Granted
        })
        .count();
    if ready == providers.len() && ready > 0 {
        SessionState::Ready
    } else if ready > 0 {
        SessionState::Degraded
    } else if providers.values().any(|p| {
        p.facts.reason != Some(ErrorCategory::StaleObservation)
            && p.facts.authorization != Authorization::Granted
    }) {
        SessionState::AuthorizationRequired
    } else {
        SessionState::Degraded
    }
}
fn usable_state(state: SessionState) -> Result<()> {
    match state {
        SessionState::Ready | SessionState::Degraded => Ok(()),
        SessionState::Locked => Err(SessionError::SessionLocked),
        SessionState::AuthorizationRequired => Err(SessionError::PermissionRequired),
        _ => Err(SessionError::SessionDisconnected),
    }
}
fn provider_usable(provider: &ProviderView) -> bool {
    provider.facts.availability == Availability::Available
        && provider.facts.authorization == Authorization::Granted
}
fn fresh_provider(provider: &ProviderView, now: u64) -> ProviderView {
    let mut fresh = provider.clone();
    if now < fresh.facts.observed_at || now >= fresh.facts.valid_until {
        fresh.facts.availability = Availability::Unavailable;
        fresh.facts.reason = Some(ErrorCategory::StaleObservation);
        fresh.facts.recovery = Recovery::Reobserve;
        fresh.observation = None;
    }
    fresh
}
fn view(record: &Record, now: u64) -> SessionView {
    let providers: BTreeMap<_, _> = record
        .providers
        .iter()
        .map(|(capability, provider)| (*capability, fresh_provider(provider, now)))
        .collect();
    let state = if matches!(
        record.state,
        SessionState::Ready | SessionState::Degraded | SessionState::AuthorizationRequired
    ) {
        aggregate(&providers)
    } else {
        record.state
    };
    SessionView {
        descriptor: SessionDescriptor {
            binding: record.binding.clone(),
            identity: record.facts.identity.clone(),
            agent_instance: record.facts.agent_instance.clone(),
            state,
            capabilities: record.providers.keys().copied().collect(),
            protocol_version: record.facts.protocol_version,
        },
        provenance: record.facts.provenance.clone(),
        providers: providers.into_values().collect(),
    }
}
/// Mapping only; no automatic retries, actions, or authority creation.
impl From<SessionError> for ErrorCategory {
    fn from(error: SessionError) -> Self {
        match error {
            SessionError::SessionAmbiguous => Self::SessionAmbiguous,
            SessionError::NoGraphicalSession => Self::NoGraphicalSession,
            SessionError::SessionLocked => Self::SessionLocked,
            SessionError::SessionDisconnected
            | SessionError::NotFound
            | SessionError::StaleBinding => Self::SessionDisconnected,
            SessionError::PermissionRequired => Self::PermissionRequired,
            SessionError::PermissionDenied | SessionError::Authority => Self::PermissionDenied,
            SessionError::CapabilityUnsupported => Self::CapabilityUnsupported,
            SessionError::StaleObservation => Self::StaleObservation,
            SessionError::Capacity => Self::Busy,
            SessionError::ResnapshotRequired => Self::StaleObservation,
            SessionError::Provider(reason) => reason,
            SessionError::Invalid => Self::InvalidRequest,
            SessionError::Exhausted => Self::StateConflict,
        }
    }
}
#[cfg(test)]
mod tests;
