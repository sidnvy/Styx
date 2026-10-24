use super::GatewayExecProfile;
use crate::{
    enrollment::shared::SharedEnrollment,
    gateway::auth::VerifiedGatewayOwner,
    host::protocol::wire::{BrowserCommand, Call, OwnerRef, Reply},
};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use styx_contracts::{identity::*, operation::OperationId};
use styx_core::enrollment::ConnectionLease;
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
    pub lease: tokio::sync::Mutex<Option<ConnectionLease>>,
    pub browser_feature: bool,
    pub browser_lease: tokio::sync::Mutex<Option<ConnectionLease>>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum TargetKind {
    ExecResource,
    ExecAction,
    BrowserResource,
    BrowserAction,
}
struct Binding {
    owner: VerifiedGatewayOwner,
    reference: OwnerRef,
    entry: Arc<Entry>,
    targets: Mutex<BTreeMap<OperationId, (Sha256Digest, TargetKind)>>,
    revoked: Arc<Mutex<bool>>,
    ready: AtomicBool,
    admitted_records: AtomicUsize,
}
#[derive(Clone)]
pub struct BoundOwner {
    inner: Arc<Binding>,
}
impl BoundOwner {
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
    pub fn transport_generation(&self) -> &ConnectionGeneration {
        &self.inner.entry.transport_generation
    }
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
                fenced: Mutex::new(vec![]),
            }),
        })
    }
    pub(crate) async fn authorize(&self, e: &Entry) -> Result<(), RelayError> {
        self.authorize_for(e, false).await
    }
    pub(crate) async fn authorize_for(&self, e: &Entry, browser: bool) -> Result<(), RelayError> {
        if !e.live.load(Ordering::Acquire) || e.stop.is_cancelled() {
            return Err(RelayError::Offline);
        }
        if browser && !e.browser_feature {
            return Err(RelayError::Unsupported);
        }
        let lease = if browser {
            e.browser_lease.lock().await
        } else {
            e.lease.lock().await
        };
        let lease = lease.as_ref().ok_or(if browser {
            RelayError::Unauthorized
        } else {
            RelayError::Offline
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
    ) -> Result<bool, RelayError> {
        if matches!(
            call,
            Call::OwnerOpen { .. } | Call::OwnerRevoke { .. } | Call::OwnerCleanup { .. }
        ) {
            self.control_lane(e).await
        } else {
            let browser = call.is_browser();
            self.authorize_for(e, browser).await?;
            Ok(browser)
        }
    }
    pub(crate) async fn control_lane(&self, e: &Entry) -> Result<bool, RelayError> {
        if self.authorize(e).await.is_ok() {
            return Ok(false);
        }
        self.authorize_for(e, true).await?;
        Ok(true)
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
                Some(e) if p.browser_approved => self.authorize_for(e, true).await.is_ok(),
                _ => false,
            };
            devices.push(DeviceStatus {
                device_id: p.device_id,
                online,
                browser_online,
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
        let (tx, rx) = oneshot::channel();
        e.tx.try_send(Command {
            call,
            result: tx,
            gate,
        })
        .map_err(|_| RelayError::Busy)?;
        match tokio::time::timeout(Duration::from_secs(35), rx).await {
            Ok(Ok(r)) => r,
            _ => Err(RelayError::Unknown),
        }
    }
    pub async fn bind(
        &self,
        owner: &VerifiedGatewayOwner,
        device: &DeviceId,
    ) -> Result<BoundOwner, RelayError> {
        self.bind_for(owner, device, false).await
    }
    pub async fn bind_browser(
        &self,
        owner: &VerifiedGatewayOwner,
        device: &DeviceId,
    ) -> Result<BoundOwner, RelayError> {
        self.bind_for(owner, device, true).await
    }
    async fn bind_for(
        &self,
        owner: &VerifiedGatewayOwner,
        device: &DeviceId,
        browser: bool,
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
        self.authorize_for(&entry, browser).await?;
        {
            let bindings = self
                .inner
                .bindings
                .lock()
                .map_err(|_| RelayError::Unknown)?;
            if let Some(b) = bindings.iter().find(|b| {
                b.owner.owner_id() == owner.owner_id()
                    && b.owner.principal_fingerprint() == owner.principal_fingerprint()
                    && Arc::ptr_eq(&b.entry, &entry)
                    && b.revoked.lock().is_ok_and(|g| !*g)
            }) {
                return if b.ready.load(Ordering::Acquire) {
                    Ok(BoundOwner { inner: b.clone() })
                } else {
                    Err(RelayError::Busy)
                };
            }
            if bindings.len() >= 128 {
                return Err(RelayError::Busy);
            }
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
            targets: Mutex::new(BTreeMap::new()),
            revoked: Arc::new(Mutex::new(false)),
            ready: AtomicBool::new(false),
            admitted_records: AtomicUsize::new(0),
        });
        // Reserve before await; cancelled bind never creates an untracked Host owner.
        {
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
            if b.len() >= 128 {
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
        let browser = call.is_browser();
        // A denied lane cannot consume the shared routing-record allowance.
        // exchange/actual-send/delivery still repeat the current authorization.
        self.authorize_for(&b.inner.entry, browser).await?;
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
            .exchange(&b.inner.entry, call, Some(b.inner.revoked.clone()))
            .await?;
        if self.is_fenced(&b.inner.owner)?
            || *b.inner.revoked.lock().map_err(|_| RelayError::Unknown)?
            || !b.inner.ready.load(Ordering::Acquire)
        {
            return Err(RelayError::Unauthorized);
        }
        self.authorize_for(&b.inner.entry, browser).await?;
        if let Reply::Prepared { snapshot }
        | Reply::Start { snapshot, .. }
        | Reply::Inspected { snapshot }
        | Reply::Action { snapshot, .. }
        | Reply::BrowserAction { snapshot, .. } = &reply
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
            let _ = self
                .exchange(
                    &b.entry,
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
            // An unconfirmed open remains tracked and cannot be called already cleaned.
            if !b.ready.load(Ordering::Acquire) {
                return Err(RelayError::Unknown);
            }
            let revoked = tokio::time::timeout_at(
                until,
                self.exchange(
                    &b.entry,
                    Call::OwnerRevoke {
                        owner: b.reference.clone(),
                    },
                    None,
                ),
            )
            .await
            .map_err(|_| RelayError::Unknown)??;
            if !matches!(revoked,Reply::OwnerRevoked{owner:ref got,fenced:true,..} if got==&b.reference)
            {
                return Err(RelayError::Unknown);
            }
            let remaining = until
                .saturating_duration_since(tokio::time::Instant::now())
                .as_millis()
                .min(5000) as u32;
            if remaining == 0 {
                return Err(RelayError::Unknown);
            }
            let result = tokio::time::timeout_at(
                until,
                self.exchange(
                    &b.entry,
                    Call::OwnerCleanup {
                        owner: b.reference.clone(),
                        timeout_ms: remaining,
                    },
                    None,
                ),
            )
            .await
            .map_err(|_| RelayError::Unknown)??;
            if !matches!(result,Reply::OwnerCleanup{owner:ref got,complete:true} if got==&b.reference)
            {
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
        if joined {
            Ok(())
        } else {
            self.inner.shutdown_failed.store(true, Ordering::Release);
            Err(RelayError::Unknown)
        }
    }
}
