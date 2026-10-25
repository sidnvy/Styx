use super::GatewayExecProfile;
#[path = "drain.rs"]
mod drain;
use crate::{
    enrollment::shared::SharedEnrollment,
    gateway::auth::VerifiedGatewayOwner,
    host::protocol::wire::{BrowserCommand, Call, ComputerCommand, OwnerRef, Reply},
};
pub(crate) use drain::{EntryDrain, cleanup_control};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use styx_contracts::{identity::*, operation::OperationId};
use styx_core::enrollment::{ConnectionLease, Lane};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio_util::sync::CancellationToken;
#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum RelayError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("offline")]
    Offline,
    #[error("busy")]
    Busy,
    #[error("invalid request")]
    Invalid,
    #[error("outcome unknown; do not replay")]
    Unknown,
    #[error("unsupported")]
    Unsupported,
}
impl RelayError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::Offline => "offline",
            Self::Busy => "busy",
            Self::Invalid => "invalid",
            Self::Unknown => "outcome_unknown",
            Self::Unsupported => "unsupported",
        }
    }
}
#[derive(Clone, Debug)]
pub struct DeviceStatus {
    pub device_id: DeviceId,
    pub online: bool,
    pub browser_online: bool,
    pub computer_online: bool,
    pub capability_generation: String,
    pub host_generation: Option<HostGeneration>,
    pub grant_revision: Option<u64>,
}
pub(crate) struct Command {
    pub call: Call,
    pub result: oneshot::Sender<Result<Reply, RelayError>>,
    pub gate: Option<Arc<Mutex<bool>>>,
}
pub(crate) struct Entry {
    pub device: DeviceId,
    pub transport_generation: ConnectionGeneration,
    pub host_connection: ConnectionGeneration,
    pub host_generation: HostGeneration,
    pub grant_revision: u64,
    pub profile: GatewayExecProfile,
    pub tx: mpsc::Sender<Command>,
    pub stop: CancellationToken,
    pub live: AtomicBool,
    pub admission: Mutex<bool>,
    pub drain: Mutex<Option<EntryDrain>>,
    pub drain_enabled: bool,
    pub lease: tokio::sync::Mutex<Option<ConnectionLease>>,
    // Initial authenticated transport admission only. If its lane was not
    // negotiated, retain it solely for control until the physical WS ends.
    pub bootstrap_lane: Lane,
    pub bootstrap_lease: tokio::sync::Mutex<Option<ConnectionLease>>,
    pub exec_feature: bool,
    pub browser_feature: bool,
    pub computer_feature: bool,
    pub browser_lease: tokio::sync::Mutex<Option<ConnectionLease>>,
    pub computer_lease: tokio::sync::Mutex<Option<ConnectionLease>>,
}
impl Entry {
    pub(crate) async fn control_lease_for(
        &self,
        lane: Lane,
    ) -> tokio::sync::MutexGuard<'_, Option<ConnectionLease>> {
        let business = self.lease_for(lane).await;
        if business.is_some() || lane != self.bootstrap_lane {
            return business;
        }
        drop(business);
        self.bootstrap_lease.lock().await
    }
    pub(crate) async fn lease_for(
        &self,
        lane: Lane,
    ) -> tokio::sync::MutexGuard<'_, Option<ConnectionLease>> {
        match lane {
            Lane::Exec => self.lease.lock().await,
            Lane::Browser => self.browser_lease.lock().await,
            Lane::Computer => self.computer_lease.lock().await,
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum TargetKind {
    ExecResource,
    ExecAction,
    BrowserResource,
    BrowserAction,
    ComputerResource,
    ComputerAction,
}
struct Binding {
    owner: VerifiedGatewayOwner,
    reference: OwnerRef,
    // Immutable original Host/capability identity; never adopted from a new peer.
    entry: Arc<Entry>,
    route: Mutex<Arc<Entry>>,
    rebind: tokio::sync::Mutex<()>,
    targets: Mutex<BTreeMap<OperationId, (Sha256Digest, TargetKind)>>,
    revoked: Arc<Mutex<bool>>,
    ready: AtomicBool,
    admitted_records: AtomicUsize,
    cleanup: Mutex<drain::BindingCleanup>,
    cleanup_changed: tokio::sync::Notify,
}
#[derive(Clone)]
pub struct BoundOwner {
    inner: Arc<Binding>,
}
impl BoundOwner {
    pub(crate) fn physically_settled(&self) -> bool {
        self.inner
            .cleanup
            .lock()
            .is_ok_and(|s| s.result == Some(true))
    }
    pub(crate) fn closed(&self) -> bool {
        self.inner.revoked.lock().map_or(true, |r| *r)
    }
    pub fn device(&self) -> &DeviceId {
        &self.inner.entry.device
    }
    pub fn owner_ref(&self) -> OwnerRef {
        self.inner.reference.clone()
    }
    pub fn grant_revision(&self) -> u64 {
        self.inner.entry.grant_revision
    }
    pub fn host_generation(&self) -> &HostGeneration {
        &self.inner.entry.host_generation
    }
    pub fn capability_generation(&self) -> &str {
        &self.inner.entry.profile.capability_generation
    }
    /// Original transport anchor, not a current-route claim after rebind.
    pub fn transport_generation(&self) -> &ConnectionGeneration {
        &self.inner.entry.transport_generation
    }
    /// Original transport anchor, not a current-route claim after rebind.
    pub fn host_connection_generation(&self) -> &ConnectionGeneration {
        &self.inner.entry.host_connection
    }
    pub fn defaults(&self) -> &GatewayExecProfile {
        &self.inner.entry.profile
    }
}
pub(crate) struct State {
    pub entries: BTreeMap<DeviceId, Arc<Entry>>,
    pub closing: bool,
    pub tasks: Vec<(CancellationToken, tokio::task::JoinHandle<()>)>,
}
pub(crate) struct Inner {
    pub shared: SharedEnrollment,
    pub gateway: GatewayId,
    pub epoch: GatewayEpoch,
    pub state: Mutex<State>,
    pub slots: Arc<Semaphore>,
    pub _budget: OwnedSemaphorePermit,
    bindings: Mutex<Vec<Arc<Binding>>>,
    shutdown_lock: tokio::sync::Mutex<()>,
    shutdown_failed: AtomicBool,
    unconfirmed_drains: AtomicUsize,
    fenced: Mutex<Vec<(OwnerId, Sha256Digest)>>,
}
#[derive(Clone)]
pub struct RelayHandle {
    pub(crate) inner: Arc<Inner>,
}
impl RelayHandle {
    pub fn new(
        shared: SharedEnrollment,
        gateway: GatewayId,
        epoch: GatewayEpoch,
        budget: OwnedSemaphorePermit,
    ) -> Result<Self, RelayError> {
        let bytes = budget.num_permits();
        if !(16 * 1024 * 1024..=64 * 1024 * 1024).contains(&bytes)
            || !bytes.is_multiple_of(16 * 1024 * 1024)
        {
            return Err(RelayError::Invalid);
        }
        Ok(Self {
            inner: Arc::new(Inner {
                shared,
                gateway,
                epoch,
                state: Mutex::new(State {
                    entries: BTreeMap::new(),
                    closing: false,
                    tasks: vec![],
                }),
                slots: Arc::new(Semaphore::new(bytes / (16 * 1024 * 1024))),
                _budget: budget,
                bindings: Mutex::new(vec![]),
                shutdown_lock: tokio::sync::Mutex::new(()),
                shutdown_failed: AtomicBool::new(false),
                unconfirmed_drains: AtomicUsize::new(0),
                fenced: Mutex::new(vec![]),
            }),
        })
    }
    pub(crate) async fn authorize(&self, e: &Entry) -> Result<(), RelayError> {
        self.authorize_for(e, Lane::Exec).await
    }
    pub(crate) async fn authorize_for(&self, e: &Entry, lane: Lane) -> Result<(), RelayError> {
        if !e.live.load(Ordering::Acquire) || e.stop.is_cancelled() {
            return Err(RelayError::Offline);
        }
        if (lane == Lane::Exec && !e.exec_feature)
            || (lane == Lane::Browser && !e.browser_feature)
            || (lane == Lane::Computer && !e.computer_feature)
        {
            return Err(RelayError::Unsupported);
        }
        let held = e.lease_for(lane).await;
        let lease = held.as_ref().ok_or(if lane == Lane::Exec {
            RelayError::Offline
        } else {
            RelayError::Unauthorized
        })?;
        self.inner
            .shared
            .with(|s| s.authorize_host_frame(lease))
            .await
            .map_err(|_| RelayError::Unknown)?
            .map_err(|_| RelayError::Unauthorized)
    }
    /// Control messages have no execution capability. They may use either
    /// currently authorized connection lane; business calls never fall through
    /// from a denied Browser grant to an Exec grant.
    pub(crate) async fn authorization_lane(
        &self,
        e: &Entry,
        call: &Call,
    ) -> Result<Lane, RelayError> {
        if !drain::cleanup_control(call) && *e.admission.lock().map_err(|_| RelayError::Unknown)? {
            return Err(RelayError::Unauthorized);
        }
        if matches!(
            call,
            Call::OwnerOpen { .. }
                | Call::OwnerRevoke { .. }
                | Call::OwnerCleanup { .. }
                | Call::EnableTransportDrain
                | Call::TransportDrainResult { .. }
        ) {
            self.control_lane(e).await
        } else {
            let lane = if call.is_computer() {
                Lane::Computer
            } else if call.is_browser() {
                Lane::Browser
            } else {
                Lane::Exec
            };
            self.authorize_for(e, lane).await?;
            Ok(lane)
        }
    }
    pub(crate) async fn control_lane(&self, e: &Entry) -> Result<Lane, RelayError> {
        if !e.live.load(Ordering::Acquire) || e.stop.is_cancelled() {
            return Err(RelayError::Offline);
        }
        for lane in [Lane::Exec, Lane::Browser, Lane::Computer] {
            let held = e.control_lease_for(lane).await;
            let Some(lease) = held.as_ref() else {
                continue;
            };
            if self
                .inner
                .shared
                .with(|s| s.authorize_host_frame(lease))
                .await
                .map_err(|_| RelayError::Unknown)?
                .is_ok()
            {
                return Ok(lane);
            }
        }
        Err(RelayError::Unauthorized)
    }
    pub async fn devices(&self) -> Result<Vec<DeviceStatus>, RelayError> {
        let profiles = self
            .inner
            .shared
            .profiles()
            .await
            .map_err(|_| RelayError::Unknown)?;
        let entries = self
            .inner
            .state
            .lock()
            .map_err(|_| RelayError::Unknown)?
            .entries
            .clone();
        let mut devices = Vec::with_capacity(profiles.len());
        for p in profiles {
            let e = entries.get(&p.device_id).filter(|e| {
                e.live.load(Ordering::Acquire)
                    && e.profile.capability_generation == p.capability_generation
            });
            let online = match e {
                Some(e) => self.authorize(e).await.is_ok(),
                None => false,
            };
            let browser_online = match e {
                Some(e) if p.browser_approved => self.authorize_for(e, Lane::Browser).await.is_ok(),
                _ => false,
            };
            let computer_online = match e {
                Some(e) if p.computer_approved => {
                    self.authorize_for(e, Lane::Computer).await.is_ok()
                }
                _ => false,
            };
            devices.push(DeviceStatus {
                device_id: p.device_id,
                online,
                browser_online,
                computer_online,
                capability_generation: p.capability_generation,
                host_generation: e.map(|e| e.host_generation.clone()),
                grant_revision: e.map(|e| e.grant_revision),
            });
        }
        Ok(devices)
    }
    async fn exchange(
        &self,
        e: &Arc<Entry>,
        call: Call,
        gate: Option<Arc<Mutex<bool>>>,
    ) -> Result<Reply, RelayError> {
        self.authorization_lane(e, &call).await?;
        let response_budget = call.response_budget();
        let (tx, rx) = oneshot::channel();
        e.tx.try_send(Command {
            call,
            result: tx,
            gate,
        })
        .map_err(|_| RelayError::Busy)?;
        match tokio::time::timeout(response_budget, rx).await {
            Ok(Ok(r)) => r,
            _ => Err(RelayError::Unknown),
        }
    }
    fn current_binding_entry(
        &self,
        binding: &Binding,
        cleanup: bool,
    ) -> Result<Arc<Entry>, RelayError> {
        let current = {
            let state = self.inner.state.lock().map_err(|_| RelayError::Unknown)?;
            if state.closing && !cleanup {
                return Err(RelayError::Offline);
            }
            state
                .entries
                .get(&binding.entry.device)
                .cloned()
                .ok_or(RelayError::Offline)?
        };
        let original_draining = if cleanup {
            false
        } else {
            *binding
                .entry
                .admission
                .lock()
                .map_err(|_| RelayError::Unknown)?
        };
        let current_draining = if cleanup {
            false
        } else {
            *current.admission.lock().map_err(|_| RelayError::Unknown)?
        };
        if original_draining || current_draining {
            return Err(RelayError::Unauthorized);
        }
        let old = &binding.entry;
        // Same Relay instance fixes Gateway ID/epoch. Metadata is not a grant:
        // authorize_for/control_lane still prove the current Core connection.
        if current.device != old.device
            || current.host_generation != old.host_generation
            || current.grant_revision != old.grant_revision
            || current.profile.capability_generation != old.profile.capability_generation
            || current.profile.device_id != old.profile.device_id
            || current.profile.browser_approved != old.profile.browser_approved
            || current.profile.computer_approved != old.profile.computer_approved
            || current.profile.platform != old.profile.platform
            || current.profile.cwd != old.profile.cwd
            || current.profile.shell != old.profile.shell
            || current.profile.allowed_shells != old.profile.allowed_shells
            || current.profile.environment != old.profile.environment
        {
            return Err(RelayError::Unauthorized);
        }
        Ok(current)
    }
    fn active_binding(&self, binding: &Binding) -> Result<(), RelayError> {
        if self.is_fenced(&binding.owner)?
            || *binding.revoked.lock().map_err(|_| RelayError::Unknown)?
            || !binding.ready.load(Ordering::Acquire)
        {
            return Err(RelayError::Unauthorized);
        }
        Ok(())
    }
    async fn route_binding(
        &self,
        binding: &Arc<Binding>,
        lane: Lane,
    ) -> Result<Arc<Entry>, RelayError> {
        self.active_binding(binding)?;
        let current = self.current_binding_entry(binding, false)?;
        if *current.admission.lock().map_err(|_| RelayError::Unknown)? {
            return Err(RelayError::Unauthorized);
        }
        self.authorize_for(&current, lane).await?;
        let already_confirmed = {
            let route = binding.route.lock().map_err(|_| RelayError::Unknown)?;
            Arc::ptr_eq(&route, &current)
        };
        if already_confirmed {
            return Ok(current);
        }
        // Synchronous try-lock prevents an unbounded per-owner rebind queue.
        // This is a Tokio guard; no std::MutexGuard is held across await.
        let _admission = binding.rebind.try_lock().map_err(|_| RelayError::Busy)?;
        self.active_binding(binding)?;
        let current = self.current_binding_entry(binding, false)?;
        self.authorize_for(&current, lane).await?;
        let already_confirmed = {
            let route = binding.route.lock().map_err(|_| RelayError::Unknown)?;
            Arc::ptr_eq(&route, &current)
        };
        if !already_confirmed {
            // Exact previously acknowledged owner only. Never mint a new epoch,
            // resource or operation; this Host control is idempotent, not I/O replay.
            let reply = self
                .exchange(
                    &current,
                    Call::OwnerOpen {
                        owner: binding.reference.clone(),
                        grant_revision: current.grant_revision,
                    },
                    Some(binding.revoked.clone()),
                )
                .await?;
            if !matches!(reply, Reply::OwnerOpened { owner: ref got, grant_revision }
                if got == &binding.reference && grant_revision == current.grant_revision)
            {
                return Err(RelayError::Unauthorized);
            }
            self.active_binding(binding)?;
            self.authorize_for(&current, lane).await?;
            if !Arc::ptr_eq(&self.current_binding_entry(binding, false)?, &current) {
                return Err(RelayError::Offline);
            }
            *binding.route.lock().map_err(|_| RelayError::Unknown)? = current.clone();
        }
        Ok(current)
    }
    async fn cleanup_binding_entry(&self, binding: &Binding) -> Result<Arc<Entry>, RelayError> {
        // Cleanup follows an already fenced owner; do not call OwnerOpen and
        // accidentally recreate authority. Same Host incarnation is mandatory.
        if !binding.ready.load(Ordering::Acquire) {
            return Err(RelayError::Unknown);
        }
        let current = self.current_binding_entry(binding, true)?;
        self.control_lane(&current).await?;
        Ok(current)
    }
    pub async fn bind(
        &self,
        owner: &VerifiedGatewayOwner,
        device: &DeviceId,
    ) -> Result<BoundOwner, RelayError> {
        self.bind_for(owner, device, Lane::Exec).await
    }
    pub async fn bind_browser(
        &self,
        owner: &VerifiedGatewayOwner,
        device: &DeviceId,
    ) -> Result<BoundOwner, RelayError> {
        self.bind_for(owner, device, Lane::Browser).await
    }
    pub async fn bind_computer(
        &self,
        owner: &VerifiedGatewayOwner,
        device: &DeviceId,
    ) -> Result<BoundOwner, RelayError> {
        self.bind_for(owner, device, Lane::Computer).await
    }
    async fn bind_for(
        &self,
        owner: &VerifiedGatewayOwner,
        device: &DeviceId,
        lane: Lane,
    ) -> Result<BoundOwner, RelayError> {
        if self.is_fenced(owner)? {
            return Err(RelayError::Unauthorized);
        }
        let entry = self
            .inner
            .state
            .lock()
            .map_err(|_| RelayError::Unknown)?
            .entries
            .get(device)
            .cloned()
            .ok_or(RelayError::Offline)?;
        self.authorize_for(&entry, lane).await?;
        let existing = {
            let bindings = self
                .inner
                .bindings
                .lock()
                .map_err(|_| RelayError::Unknown)?;
            if let Some(binding) = bindings.iter().find(|binding| {
                binding.owner.owner_id() == owner.owner_id()
                    && binding.owner.principal_fingerprint() == owner.principal_fingerprint()
                    && binding.entry.device == *device
            }) {
                Some(binding.clone())
            } else {
                if bindings.len() >= 128 {
                    return Err(RelayError::Busy);
                }
                None
            }
        };
        if let Some(binding) = existing {
            if !binding.ready.load(Ordering::Acquire) {
                return Err(RelayError::Busy);
            }
            self.route_binding(&binding, lane).await?;
            return Ok(BoundOwner { inner: binding });
        }
        let reference = OwnerRef {
            owner_id: owner.owner_id().clone(),
            owner_epoch: format!("paired-owner-{}", uuid::Uuid::new_v4())
                .try_into()
                .map_err(|_| RelayError::Invalid)?,
        };
        let binding = Arc::new(Binding {
            owner: owner.clone(),
            reference: reference.clone(),
            entry: entry.clone(),
            route: Mutex::new(entry.clone()),
            rebind: tokio::sync::Mutex::new(()),
            targets: Mutex::new(BTreeMap::new()),
            revoked: Arc::new(Mutex::new(false)),
            ready: AtomicBool::new(false),
            admitted_records: AtomicUsize::new(0),
            cleanup: Mutex::new(drain::BindingCleanup::default()),
            cleanup_changed: tokio::sync::Notify::new(),
        });
        // Reserve before await; cancelled bind never creates an untracked Host owner.
        {
            let admission = entry.admission.lock().map_err(|_| RelayError::Unknown)?;
            if *admission {
                return Err(RelayError::Unauthorized);
            }
            let fenced = self.inner.fenced.lock().map_err(|_| RelayError::Unknown)?;
            if fenced
                .iter()
                .any(|(id, p)| id == owner.owner_id() && *p == owner.principal_fingerprint())
            {
                return Err(RelayError::Unauthorized);
            }
            let mut b = self
                .inner
                .bindings
                .lock()
                .map_err(|_| RelayError::Unknown)?;
            if b.len() >= 128
                || b.iter().any(|existing| {
                    existing.owner.owner_id() == owner.owner_id()
                        && existing.owner.principal_fingerprint() == owner.principal_fingerprint()
                        && existing.entry.device == *device
                })
            {
                return Err(RelayError::Busy);
            }
            b.push(binding.clone());
        }
        match self
            .exchange(
                &entry,
                Call::OwnerOpen {
                    owner: reference.clone(),
                    grant_revision: entry.grant_revision,
                },
                Some(binding.revoked.clone()),
            )
            .await?
        {
            Reply::OwnerOpened {
                owner: got,
                grant_revision,
            } if got == reference && grant_revision == entry.grant_revision => {
                if self.is_fenced(owner)? {
                    *binding.revoked.lock().map_err(|_| RelayError::Unknown)? = true;
                    return Err(RelayError::Unauthorized);
                }
                let admission = entry.admission.lock().map_err(|_| RelayError::Unknown)?;
                if *admission || *binding.revoked.lock().map_err(|_| RelayError::Unknown)? {
                    return Err(RelayError::Unauthorized);
                }
                binding.ready.store(true, Ordering::Release);
                Ok(BoundOwner { inner: binding })
            }
            _ => {
                *binding.revoked.lock().map_err(|_| RelayError::Unknown)? = true;
                Err(RelayError::Unauthorized)
            }
        }
    }
    pub async fn call(&self, b: &BoundOwner, call: Call) -> Result<Reply, RelayError> {
        if self.is_fenced(&b.inner.owner)?
            || *b.inner.revoked.lock().map_err(|_| RelayError::Unknown)?
            || !b.inner.ready.load(Ordering::Acquire)
        {
            return Err(RelayError::Unauthorized);
        }
        {
            let bindings = self
                .inner
                .bindings
                .lock()
                .map_err(|_| RelayError::Unknown)?;
            if !bindings.iter().any(|x| Arc::ptr_eq(x, &b.inner)) {
                return Err(RelayError::Unauthorized);
            }
        }
        let lane = if call.is_computer() {
            Lane::Computer
        } else if call.is_browser() {
            Lane::Browser
        } else {
            Lane::Exec
        };
        // A denied lane cannot consume the shared routing-record allowance.
        // exchange/actual-send/delivery still repeat the current authorization.
        let entry = self.route_binding(&b.inner, lane).await?;
        let (owner, target, revision, new_record, record_kind) = match &call {
            Call::PrepareStart {
                owner,
                grant_revision,
                ..
            } => (
                owner,
                None,
                Some(*grant_revision),
                true,
                TargetKind::ExecResource,
            ),
            Call::DispatchStart { owner, target } | Call::InspectStart { owner, target } => (
                owner,
                Some((
                    target.operation_id.clone(),
                    target.payload_digest,
                    TargetKind::ExecResource,
                )),
                None,
                false,
                TargetKind::ExecResource,
            ),
            Call::Read {
                owner,
                target,
                grant_revision,
                ..
            } => (
                owner,
                Some((
                    target.operation_id.clone(),
                    target.payload_digest,
                    TargetKind::ExecResource,
                )),
                Some(*grant_revision),
                false,
                TargetKind::ExecResource,
            ),
            Call::PrepareAction {
                owner,
                target,
                grant_revision,
                ..
            } => (
                owner,
                Some((
                    target.operation_id.clone(),
                    target.payload_digest,
                    TargetKind::ExecResource,
                )),
                Some(*grant_revision),
                true,
                TargetKind::ExecAction,
            ),
            Call::DispatchAction { owner, action } | Call::InspectAction { owner, action } => (
                owner,
                Some((
                    action.operation_id.clone(),
                    action.payload_digest,
                    TargetKind::ExecAction,
                )),
                None,
                false,
                TargetKind::ExecAction,
            ),
            Call::Browser {
                owner,
                grant_revision,
                command,
                ..
            } => match command {
                BrowserCommand::PrepareOpen => (
                    owner,
                    None,
                    Some(*grant_revision),
                    true,
                    TargetKind::BrowserResource,
                ),
                BrowserCommand::DispatchOpen { target }
                | BrowserCommand::InspectOpen { target } => (
                    owner,
                    Some((
                        target.operation_id.clone(),
                        target.payload_digest,
                        TargetKind::BrowserResource,
                    )),
                    Some(*grant_revision),
                    false,
                    TargetKind::BrowserResource,
                ),
                BrowserCommand::PrepareAction { target, .. } => (
                    owner,
                    Some((
                        target.operation_id.clone(),
                        target.payload_digest,
                        TargetKind::BrowserResource,
                    )),
                    Some(*grant_revision),
                    true,
                    TargetKind::BrowserAction,
                ),
                BrowserCommand::DispatchAction { action }
                | BrowserCommand::InspectAction { action } => (
                    owner,
                    Some((
                        action.operation_id.clone(),
                        action.payload_digest,
                        TargetKind::BrowserAction,
                    )),
                    Some(*grant_revision),
                    false,
                    TargetKind::BrowserAction,
                ),
            },
            Call::Computer {
                owner,
                grant_revision,
                command,
                ..
            } => match command {
                ComputerCommand::PrepareOpen => (
                    owner,
                    None,
                    Some(*grant_revision),
                    true,
                    TargetKind::ComputerResource,
                ),
                ComputerCommand::DispatchOpen { target }
                | ComputerCommand::InspectOpen { target } => (
                    owner,
                    Some((
                        target.operation_id.clone(),
                        target.payload_digest,
                        TargetKind::ComputerResource,
                    )),
                    Some(*grant_revision),
                    false,
                    TargetKind::ComputerResource,
                ),
                ComputerCommand::PrepareAction { target, .. } => (
                    owner,
                    Some((
                        target.operation_id.clone(),
                        target.payload_digest,
                        TargetKind::ComputerResource,
                    )),
                    Some(*grant_revision),
                    true,
                    TargetKind::ComputerAction,
                ),
                ComputerCommand::DispatchAction { action }
                | ComputerCommand::InspectAction { action } => (
                    owner,
                    Some((
                        action.operation_id.clone(),
                        action.payload_digest,
                        TargetKind::ComputerAction,
                    )),
                    Some(*grant_revision),
                    false,
                    TargetKind::ComputerAction,
                ),
            },
            _ => return Err(RelayError::Unsupported),
        };
        if owner != &b.inner.reference || revision.is_some_and(|r| r != b.grant_revision()) {
            return Err(RelayError::Unauthorized);
        }
        {
            let targets = b.inner.targets.lock().map_err(|_| RelayError::Unknown)?;
            if target
                .as_ref()
                .is_some_and(|(id, d, kind)| targets.get(id) != Some(&(*d, *kind)))
            {
                return Err(RelayError::Unauthorized);
            }
            if new_record && targets.len() >= 256 {
                return Err(RelayError::Busy);
            }
        }
        if new_record
            && b.inner
                .admitted_records
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                    (n < 256).then_some(n + 1)
                })
                .is_err()
        {
            return Err(RelayError::Busy);
        }
        let reply = self
            .exchange(&entry, call, Some(b.inner.revoked.clone()))
            .await?;
        if self.is_fenced(&b.inner.owner)?
            || *b.inner.revoked.lock().map_err(|_| RelayError::Unknown)?
            || !b.inner.ready.load(Ordering::Acquire)
        {
            return Err(RelayError::Unauthorized);
        }
        self.authorize_for(&entry, lane).await?;
        if let Reply::Prepared { snapshot }
        | Reply::ComputerPrepared { snapshot, .. }
        | Reply::Start { snapshot, .. }
        | Reply::Inspected { snapshot }
        | Reply::Action { snapshot, .. }
        | Reply::BrowserAction { snapshot, .. }
        | Reply::ComputerAction { snapshot, .. } = &reply
        {
            let mut targets = b.inner.targets.lock().map_err(|_| RelayError::Unknown)?;
            if let Some(existing) = targets.get(&snapshot.operation_id) {
                if existing != &(snapshot.payload_digest, record_kind) {
                    return Err(RelayError::Unknown);
                }
            } else {
                if targets.len() >= 256 {
                    return Err(RelayError::Unknown);
                }
                targets.insert(
                    snapshot.operation_id.clone(),
                    (snapshot.payload_digest, record_kind),
                );
            }
        }
        Ok(reply)
    }
    fn is_fenced(&self, owner: &VerifiedGatewayOwner) -> Result<bool, RelayError> {
        Ok(self
            .inner
            .fenced
            .lock()
            .map_err(|_| RelayError::Unknown)?
            .iter()
            .any(|(id, p)| id == owner.owner_id() && *p == owner.principal_fingerprint()))
    }
    pub fn fence_owner(&self, owner: &VerifiedGatewayOwner) -> Result<(), RelayError> {
        let mut fenced = self.inner.fenced.lock().map_err(|_| RelayError::Unknown)?;
        if !fenced
            .iter()
            .any(|(id, p)| id == owner.owner_id() && *p == owner.principal_fingerprint())
        {
            if fenced.len() >= 128 {
                return Err(RelayError::Busy);
            }
            fenced.push((owner.owner_id().clone(), owner.principal_fingerprint()));
        }
        for b in self
            .inner
            .bindings
            .lock()
            .map_err(|_| RelayError::Unknown)?
            .iter()
        {
            if b.owner.owner_id() == owner.owner_id()
                && b.owner.principal_fingerprint() == owner.principal_fingerprint()
            {
                *b.revoked.lock().map_err(|_| RelayError::Unknown)? = true
            }
        }
        Ok(())
    }
    pub async fn revoke(&self, owner: &VerifiedGatewayOwner) -> Result<(), RelayError> {
        self.fence_owner(owner)?;
        let bindings: Vec<_> = self
            .inner
            .bindings
            .lock()
            .map_err(|_| RelayError::Unknown)?
            .iter()
            .filter(|b| {
                b.owner.owner_id() == owner.owner_id()
                    && b.owner.principal_fingerprint() == owner.principal_fingerprint()
            })
            .cloned()
            .collect();
        for b in bindings {
            *b.revoked.lock().map_err(|_| RelayError::Unknown)? = true;
            let entry = self.cleanup_binding_entry(&b).await?;
            let _ = self
                .exchange(
                    &entry,
                    Call::OwnerRevoke {
                        owner: b.reference.clone(),
                    },
                    None,
                )
                .await?;
        }
        Err(RelayError::Unknown)
    }
    pub async fn cleanup_owner(
        &self,
        owner: &VerifiedGatewayOwner,
        budget: Duration,
    ) -> Result<bool, RelayError> {
        self.fence_owner(owner)?;
        let until = tokio::time::Instant::now() + budget.min(Duration::from_secs(5));
        let bindings: Vec<_> = self
            .inner
            .bindings
            .lock()
            .map_err(|_| RelayError::Unknown)?
            .iter()
            .filter(|b| {
                b.owner.owner_id() == owner.owner_id()
                    && b.owner.principal_fingerprint() == owner.principal_fingerprint()
            })
            .cloned()
            .collect();
        for b in bindings {
            if !self.settle_binding(&b, until, None).await {
                return Ok(false);
            }
        }
        Ok(true)
    }
    pub fn fence_transport(&self) {
        if let Ok(mut s) = self.inner.state.lock() {
            s.closing = true;
            for (stop, _) in &s.tasks {
                stop.cancel()
            }
            for e in s.entries.values() {
                e.live.store(false, Ordering::Release);
                e.stop.cancel()
            }
        }
    }
    pub async fn shutdown(&self) -> Result<(), RelayError> {
        let _join = self.inner.shutdown_lock.lock().await;
        let jobs = {
            let mut s = self.inner.state.lock().map_err(|_| RelayError::Unknown)?;
            s.closing = true;
            for e in s.entries.values() {
                e.stop.cancel()
            }
            for (stop, _) in &s.tasks {
                stop.cancel();
            }
            std::mem::take(&mut s.tasks)
        };
        let mut joined = !self.inner.shutdown_failed.load(Ordering::Acquire);
        for (stop, job) in jobs {
            stop.cancel();
            joined &= job.await.is_ok();
        }
        let bindings = self
            .inner
            .bindings
            .lock()
            .map_err(|_| RelayError::Unknown)?
            .clone();
        for binding in bindings {
            let job = binding
                .cleanup
                .lock()
                .map_err(|_| RelayError::Unknown)?
                .job
                .take();
            if let Some(job) = job {
                joined &= job.await.is_ok();
            }
        }
        if joined {
            Ok(())
        } else {
            self.inner.shutdown_failed.store(true, Ordering::Release);
            Err(RelayError::Unknown)
        }
    }
}
