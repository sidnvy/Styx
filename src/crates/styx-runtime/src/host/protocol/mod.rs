//! Private, explicitly negotiated Host protocol slice. Not public MCP and not
//! complete public protocol: v2 uses bootstrap owners; v3 accepts owner control
//! only from the fixed authenticated paired Gateway. Reads are not resumable. Every mutation uses separate Host prepare/dispatch.
//! Connection loss never shuts down the coordinator/executor or replays reads.
use super::replies::{coordinator_error, invalid, rejection};
use super::{
    coordinator::{HostAuthority, HostCoordinator},
    link::{HostWssLink, LinkEndpoint},
};
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
pub(crate) mod browser;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) mod computer;
use super::callers::{OwnerRecord, order as owner_order};
#[cfg(not(target_os = "android"))]
use super::exec_tasks::{self as tasks, operations::ExecPort};
pub mod wire;
#[cfg(test)]
use super::coordinator::CoordinatorError;
use futures_util::{FutureExt, StreamExt, stream::FuturesUnordered};
pub(crate) use owner_order::epoch_key as paired_owner_epoch;
use std::{collections::BTreeMap, io::Write, time::Duration};
use styx_contracts::{
    capability::CapabilityId,
    error::{ErrorCategory, ExecutionCertainty},
    identity::*,
    operation::*,
};
use styx_core::operations::{OperationSnapshot, OwnerLease};
use tokio_util::sync::CancellationToken;
use wire::*;

const FRAME_LIMIT: usize = 256 * 1024;
const SPEC_LIMIT: usize = 128 * 1024;
const RESPONSE_LIMIT: usize = 128 * 1024;

/// All fields come from protected bootstrap configuration, never wire hello.
/// Epoch is scoped to this fixed Gateway namespace and Host generation.
pub struct TrustedProfile {
    pub endpoint: String,
    pub gateway_namespace: GatewayId,
    pub gateway_epoch: GatewayEpoch,
    pub device_id: DeviceId,
    pub host_generation: HostGeneration,
}
/// Protected pairing bootstrap: the authenticated fixed Gateway endpoint is
/// trusted to announce its process epoch, never an ordinary MCP client.
pub struct PairedTrustedProfile {
    pub endpoint: String,
    pub gateway_namespace: GatewayId,
    pub device_id: DeviceId,
    pub host_generation: HostGeneration,
}
struct ProfileBinding {
    endpoint: String,
    gateway_namespace: GatewayId,
    gateway_epoch: Option<GatewayEpoch>,
    device_id: DeviceId,
    host_generation: HostGeneration,
}
impl From<TrustedProfile> for ProfileBinding {
    fn from(p: TrustedProfile) -> Self {
        Self {
            endpoint: p.endpoint,
            gateway_namespace: p.gateway_namespace,
            gateway_epoch: Some(p.gateway_epoch),
            device_id: p.device_id,
            host_generation: p.host_generation,
        }
    }
}
impl From<PairedTrustedProfile> for ProfileBinding {
    fn from(p: PairedTrustedProfile) -> Self {
        Self {
            endpoint: p.endpoint,
            gateway_namespace: p.gateway_namespace,
            gateway_epoch: None,
            device_id: p.device_id,
            host_generation: p.host_generation,
        }
    }
}
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
struct BrowserLinkReferences<'a>(&'a HostCoordinator);
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
impl Drop for BrowserLinkReferences<'_> {
    fn drop(&mut self) {
        self.0.invalidate_browser_link_references();
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProtocolError {
    #[error("paired Gateway explicitly revoked this device")]
    PairingRevoked,
    #[error("trusted bootstrap binding does not match Host or link")]
    BootstrapMismatch,
    #[error("invalid bounded Host protocol frame")]
    InvalidFrame,
    #[error("explicit Host protocol negotiation required or rejected")]
    NegotiationRejected,
    #[error("connection handler capacity exhausted")]
    Busy,
    #[error("connection response lost; operation/read must not be replayed")]
    ResponseLost,
    #[error("verified bootstrap owner registration rejected")]
    OwnerRegistrationRejected,
}
impl From<OperationSnapshot> for Snapshot {
    fn from(value: OperationSnapshot) -> Self {
        Self {
            operation_id: value.id,
            payload_digest: value.payload_digest,
            target: value.target,
            state: value.state,
            liveness: value.liveness,
            output_drain: value.output_drain,
        }
    }
}
/// v2 authority comes only from bootstrap; v3 owner-control DTOs are admitted
/// only after fixed-endpoint TLS and explicit Gateway namespace negotiation.
pub struct HostProtocol<'a> {
    android: Option<std::sync::Arc<dyn super::android::AndroidPlatform>>,
    settings: Option<std::sync::Arc<crate::host::settings::HostSettings>>,
    profile: ProfileBinding,
    coordinator: HostCoordinator,
    authority: &'a HostAuthority,
    paired: bool,
    command_environment: BTreeMap<String, String>,
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    browser: Option<std::sync::Arc<browser::BrowserInputs>>,
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    computer: Option<computer::ComputerInputs>,
}
impl<'a> HostProtocol<'a> {
    #[cfg(not(target_os = "android"))]
    fn exec_port(&self) -> ExecPort<'_> {
        ExecPort {
            coordinator: &self.coordinator,
            authority: self.authority,
            command_environment: &self.command_environment,
        }
    }
    pub fn new(
        profile: TrustedProfile,
        coordinator: HostCoordinator,
        authority: &'a HostAuthority,
    ) -> Result<Self, ProtocolError> {
        Self::build(profile.into(), coordinator, authority, false)
    }
    pub fn new_paired(
        profile: PairedTrustedProfile,
        coordinator: HostCoordinator,
        authority: &'a HostAuthority,
    ) -> Result<Self, ProtocolError> {
        Self::build(profile.into(), coordinator, authority, true)
    }
    fn build(
        profile: ProfileBinding,
        coordinator: HostCoordinator,
        authority: &'a HostAuthority,
        paired: bool,
    ) -> Result<Self, ProtocolError> {
        let (device, generation) = coordinator.bootstrap_identity();
        if &profile.device_id != device
            || &profile.host_generation != generation
            || !coordinator.shares_authority(authority)
        {
            return Err(ProtocolError::BootstrapMismatch);
        }
        let endpoint =
            LinkEndpoint::parse(&profile.endpoint).map_err(|_| ProtocolError::BootstrapMismatch)?;
        // Require one canonical endpoint, not aliases supplied by a wire peer.
        let canonical = url::Url::parse(&profile.endpoint)
            .map_err(|_| ProtocolError::BootstrapMismatch)?
            .to_string();
        drop(endpoint);
        if canonical != profile.endpoint {
            return Err(ProtocolError::BootstrapMismatch);
        }
        Ok(Self {
            android: None,
            settings: None,
            profile,
            coordinator,
            authority,
            paired,
            command_environment: BTreeMap::new(),
            #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
            browser: None,
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            computer: None,
        })
    }
    /// Trusted local OS defaults are resolved BEFORE Core preparation, so
    /// the operation digest and retained payload include every effective value.
    /// This is bootstrap data, never a post-permit provider environment fallback.
    pub(crate) fn with_command_environment(
        mut self,
        environment: BTreeMap<String, String>,
    ) -> Self {
        self.command_environment = environment;
        self
    }
    pub fn register_bootstrap_verified_owner(
        &mut self,
        owner: OwnerId,
        epoch: OwnerEpoch,
    ) -> Result<(), ProtocolError> {
        if self.paired {
            return Err(ProtocolError::OwnerRegistrationRejected);
        }
        let mut registry = self
            .coordinator
            .remote_access()
            .lock()
            .expect("owner registry");
        let key = (owner.clone(), epoch.clone());
        if registry.owners.contains_key(&key) {
            return Ok(());
        }

        let lease = self
            .authority
            .register_verified_owner(owner, epoch)
            .map_err(|_| ProtocolError::OwnerRegistrationRejected)?;
        registry.owners.insert(
            key,
            OwnerRecord {
                lease: Some(lease),
                revision: self.coordinator.grant_revision(),
                cleanup: None,
            },
        );
        Ok(())
    }
    fn owner(&self, reference: &OwnerRef) -> Result<OwnerLease, ErrorCategory> {
        let registry = self
            .coordinator
            .remote_access()
            .lock()
            .expect("owner registry");
        if registry.stopping {
            return Err(ErrorCategory::Unauthorized);
        }
        registry
            .owners
            .get(&(reference.owner_id.clone(), reference.owner_epoch.clone()))
            .and_then(|entry| entry.lease.clone())
            .ok_or(ErrorCategory::Unauthorized)
    }
    /// Existing pending handlers only. Withdrawing new admission is not owner
    /// revocation: their original result may still leave this same connection.
    fn receipt_owner(&self, reference: &OwnerRef) -> Result<OwnerLease, ErrorCategory> {
        let registry = self
            .coordinator
            .remote_access()
            .lock()
            .expect("owner registry");
        registry
            .owners
            .get(&(reference.owner_id.clone(), reference.owner_epoch.clone()))
            .and_then(|entry| entry.lease.clone())
            .ok_or(ErrorCategory::Unauthorized)
    }
    fn fence_transport_stop(&self) -> Result<(), ProtocolError> {
        if let Some(platform) = &self.android {
            let _ = platform.execute("clear", serde_json::json!({}));
        }
        let mut registry = self
            .coordinator
            .remote_access()
            .lock()
            .expect("owner registry");
        registry.stopping = true;
        for entry in registry.owners.values_mut() {
            if let Some(lease) = &entry.lease {
                let cleanup = self
                    .authority
                    .fence_owner_for_cleanup(lease)
                    .map_err(|_| ProtocolError::OwnerRegistrationRejected)?;
                entry.cleanup = Some(cleanup);
                entry.lease = None;
            }
        }
        Ok(())
    }
    fn accept_epoch(&self, epoch: &GatewayEpoch) -> Result<(), ProtocolError> {
        if !self.paired {
            return if self.profile.gateway_epoch.as_ref() == Some(epoch) {
                Ok(())
            } else {
                Err(ProtocolError::NegotiationRejected)
            };
        }
        let mut registry = self
            .coordinator
            .remote_access()
            .lock()
            .expect("owner registry");
        if registry.active_epoch.as_ref() == Some(epoch) {
            return Ok(());
        }
        if registry.retired_epochs.contains(epoch) {
            return Err(ProtocolError::NegotiationRejected);
        }
        if let Some(platform) = &self.android {
            let _ = platform.execute("clear", serde_json::json!({}));
        }
        // Fence all old scope leases before accepting a new authenticated server epoch.
        for entry in registry.owners.values_mut() {
            if let Some(lease) = entry.lease.as_ref() {
                let cleanup = self
                    .authority
                    .fence_owner_for_cleanup(lease)
                    .map_err(|_| ProtocolError::OwnerRegistrationRejected)?;
                entry.cleanup = Some(cleanup);
                entry.lease = None;
            }
        }
        if let Some(old) = registry.active_epoch.replace(epoch.clone()) {
            registry.retired_epochs.insert(old);
        }
        Ok(())
    }
    fn control(&self, call: &Call) -> Option<Reply> {
        let (owner, revision) = match call {
            Call::OwnerOpen {
                owner,
                grant_revision,
            } => (owner, Some(*grant_revision)),
            Call::OwnerRevoke { owner } => (owner, None),
            _ => return None,
        };
        if !self.paired {
            return Some(Reply::Unsupported {
                feature: "gateway_owner_control".into(),
            });
        }
        let mut registry = self
            .coordinator
            .remote_access()
            .lock()
            .expect("owner registry");
        let key = (owner.owner_id.clone(), owner.owner_epoch.clone());
        let Some(epoch) = registry.active_epoch.clone() else {
            return Some(rejection(ErrorCategory::Unauthorized));
        };
        if let Some(revision) = revision {
            if registry.stopping {
                return Some(rejection(ErrorCategory::Unauthorized));
            }
            if revision != self.coordinator.grant_revision() {
                return Some(rejection(ErrorCategory::StateConflict));
            }
            if let Some(entry) = registry.owners.get(&key) {
                return Some(if entry.lease.is_some() && entry.revision == revision {
                    Reply::OwnerOpened {
                        owner: owner.clone(),
                        grant_revision: revision,
                    }
                } else {
                    rejection(ErrorCategory::Unauthorized)
                });
            }

            if let Err(error) = registry.order.admit(&epoch, owner) {
                return Some(rejection(error));
            }
            match self
                .authority
                .register_verified_owner(owner.owner_id.clone(), owner.owner_epoch.clone())
            {
                Ok(lease) => {
                    registry.owners.insert(
                        key,
                        OwnerRecord {
                            lease: Some(lease),
                            revision,
                            cleanup: None,
                        },
                    );
                }
                Err(e) => return Some(coordinator_error(e, false)),
            }
            Some(Reply::OwnerOpened {
                owner: owner.clone(),
                grant_revision: revision,
            })
        } else {
            if let Some(entry) = registry.owners.get_mut(&key) {
                if let Some(lease) = entry.lease.as_ref() {
                    match self.authority.fence_owner_for_cleanup(lease) {
                        Ok(cleanup) => entry.cleanup = Some(cleanup),
                        Err(e) => return Some(coordinator_error(e, false)),
                    }
                    entry.lease = None;
                    if let Some(platform) = &self.android {
                        let _ = platform.execute(
                            "release_caller",
                            serde_json::json!({"__caller_id": super::android::caller_key(owner)}),
                        );
                    }
                }
            } else if let Err(error) = registry.order.fence_unseen(&epoch, owner) {
                return Some(rejection(error));
            }
            Some(Reply::OwnerRevoked {
                owner: owner.clone(),
                fenced: true,
                cleanup: "unknown".into(),
            })
        }
    }
    pub fn with_android(
        mut self,
        platform: std::sync::Arc<dyn super::android::AndroidPlatform>,
    ) -> Self {
        self.android = Some(platform);
        self
    }
    fn report(&self) -> Option<crate::host::settings::SettingsReport> {
        self.settings.as_ref().map(|settings| {
            let mut report = settings.report();
            report.android_status = self
                .android
                .as_ref()
                .and_then(|platform| platform.execute("status", serde_json::json!({})).ok())
                .and_then(|status| serde_json::from_value(status).ok());
            report
        })
    }
    pub fn with_settings(
        mut self,
        settings: std::sync::Arc<crate::host::settings::HostSettings>,
    ) -> Self {
        self.settings = Some(settings);
        self
    }
    async fn handle(&self, call: Call) -> Reply {
        match &call {
            Call::GetCapabilities => {
                return self.report().map_or_else(
                    || rejection(ErrorCategory::CapabilityUnsupported),
                    |report| Reply::Capabilities { report },
                );
            }
            Call::SetCapabilities { patch } => {
                if self.android.is_some()
                    && [patch.exec, patch.browser, patch.computer].contains(&Some(true))
                {
                    return rejection(ErrorCategory::CapabilityUnsupported);
                }
                if patch.android == Some(false)
                    && let Some(platform) = &self.android
                {
                    // Cancel the remaining batch before the settings writer waits for
                    // the original dispatched step to settle under its read gate.
                    let _ = platform.execute("clear", serde_json::json!({}));
                }
                return match &self.settings {
                    Some(settings) => match settings.update(*patch).await {
                        Ok(report) => Reply::Capabilities { report },
                        Err(error) => Reply::Error {
                            category: error,
                            certainty: if error == ErrorCategory::ResultUnknown {
                                ExecutionCertainty::Unknown
                            } else {
                                ExecutionCertainty::NotDispatched
                            },
                            cursor_may_be_consumed: false,
                        },
                    },
                    None => rejection(ErrorCategory::CapabilityUnsupported),
                };
            }
            _ => (),
        }
        let _admission = if call_owner(&call).is_some() {
            match &self.settings {
                Some(settings) => match settings
                    .admit(|caps| {
                        if call.is_android() {
                            caps.android
                        } else if call.is_browser() {
                            caps.browser
                        } else if call.is_computer() {
                            caps.computer
                        } else {
                            caps.exec
                        }
                    })
                    .await
                {
                    Ok(guard) => Some(guard),
                    Err(error) => return rejection(error),
                },
                None => None,
            }
        } else {
            None
        };
        match call {
            Call::Android {
                owner,
                grant_revision,
                command,
            } => {
                let lease = match self.owner(&owner) {
                    Ok(lease) if self.paired => lease,
                    _ => return rejection(ErrorCategory::Unauthorized),
                };
                if grant_revision != self.coordinator.grant_revision() {
                    return rejection(ErrorCategory::StateConflict);
                }
                let Some(platform) = &self.android else {
                    return rejection(ErrorCategory::CapabilityUnsupported);
                };
                match self
                    .coordinator
                    .run_android(lease, owner, command, platform.clone())
                    .await
                {
                    Ok(result) => Reply::Android { result },
                    Err(error) => coordinator_error(error, false),
                }
            }
            #[cfg(not(target_os = "android"))]
            Call::BrowserSession {
                owner,
                grant_revision,
                command,
            } => {
                if !self.paired || self.owner(&owner).is_err() {
                    return rejection(ErrorCategory::Unauthorized);
                }
                if grant_revision != self.coordinator.grant_revision() {
                    return rejection(ErrorCategory::StateConflict);
                }
                match self.browser_port() {
                    Some(port) => Reply::BrowserSession {
                        result: crate::host::browser_sessions::Engine { port }
                            .handle(owner, command)
                            .await,
                    },
                    None => rejection(ErrorCategory::CapabilityUnsupported),
                }
            }
            Call::DesktopSession {
                owner,
                grant_revision,
                timeout_ms,
                action,
            } => {
                #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
                {
                    self.handle_desktop_session(owner, grant_revision, timeout_ms, action)
                        .await
                }
                #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
                {
                    let _ = (owner, grant_revision, timeout_ms, action);
                    Reply::Unsupported {
                        feature: COMPUTER_V3.into(),
                    }
                }
            }
            Call::OwnerCleanup { owner, timeout_ms } => {
                if !self.paired || timeout_ms == 0 || timeout_ms > 5000 {
                    return invalid();
                }
                let cleanup = self
                    .coordinator
                    .remote_access()
                    .lock()
                    .expect("owner registry")
                    .owners
                    .get(&(owner.owner_id.clone(), owner.owner_epoch.clone()))
                    .and_then(|entry| entry.cleanup.clone());
                let Some(cleanup) = cleanup else {
                    let registry = self
                        .coordinator
                        .remote_access()
                        .lock()
                        .expect("owner registry");
                    return if !registry
                        .owners
                        .contains_key(&(owner.owner_id.clone(), owner.owner_epoch.clone()))
                        && registry
                            .active_epoch
                            .as_ref()
                            .is_some_and(|epoch| registry.order.fenced(epoch, &owner))
                    {
                        Reply::OwnerCleanup {
                            owner,
                            complete: true,
                        }
                    } else {
                        rejection(ErrorCategory::Unauthorized)
                    };
                };
                let until =
                    tokio::time::Instant::now() + Duration::from_millis(u64::from(timeout_ms));
                let mut complete = match self
                    .authority
                    .cleanup_owner(&cleanup, Duration::from_millis(u64::from(timeout_ms)))
                {
                    Ok(ticket) => ticket
                        .wait()
                        .await
                        .is_ok_and(|facts| facts.physical_complete),
                    Err(_) => false,
                };
                if complete {
                    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
                    {
                        let released = tokio::time::timeout_at(until, async {
                            self.release_browser_profile(cleanup.owner().clone())
                                .await?;
                            self.release_computer_profile(cleanup.owner().clone()).await
                        })
                        .await;
                        complete = matches!(released, Ok(Ok(())));
                    }
                }
                if complete {
                    #[cfg(not(target_os = "android"))]
                    self.coordinator.browser_sessions().forget_caller(&owner);
                    if let Some(platform) = &self.android {
                        let _ = platform.execute(
                            "release_caller",
                            serde_json::json!({"__caller_id": super::android::caller_key(&owner)}),
                        );
                    }
                    let mut registry = self
                        .coordinator
                        .remote_access()
                        .lock()
                        .expect("owner registry");
                    registry
                        .owners
                        .remove(&(owner.owner_id.clone(), owner.owner_epoch.clone()));
                }
                Reply::OwnerCleanup { owner, complete }
            }
            #[cfg(not(target_os = "android"))]
            call @ (Call::PrepareStart { .. }
            | Call::DispatchStart { .. }
            | Call::InspectStart { .. }
            | Call::Read { .. }
            | Call::PrepareAction { .. }
            | Call::DispatchAction { .. }
            | Call::InspectAction { .. }) => {
                let owner = match self.owner(call_owner(&call).expect("exec caller")) {
                    Ok(owner) => owner,
                    Err(error) => return rejection(error),
                };
                self.exec_port().exec_operation(&owner, call).await
            }
            #[cfg(not(target_os = "android"))]
            Call::ExecTask {
                owner,
                grant_revision,
                command,
            } => {
                if self.owner(&owner).is_err()
                    || grant_revision != self.coordinator.grant_revision()
                {
                    return rejection(ErrorCategory::Unauthorized);
                }
                Reply::ExecTask {
                    result: tasks::Engine {
                        port: self.exec_port(),
                    }
                    .handle(command)
                    .await,
                }
            }
            #[cfg(target_os = "android")]
            Call::BrowserSession { .. }
            | Call::ExecTask { .. }
            | Call::PrepareStart { .. }
            | Call::DispatchStart { .. }
            | Call::InspectStart { .. }
            | Call::Read { .. }
            | Call::PrepareAction { .. }
            | Call::DispatchAction { .. }
            | Call::InspectAction { .. } => rejection(ErrorCategory::CapabilityUnsupported),
            Call::Write {} => Reply::Unsupported {
                feature: "write".into(),
            },
            Call::Terminate {} => Reply::Unsupported {
                feature: "terminate".into(),
            },
            Call::GetCapabilities
            | Call::SetCapabilities { .. }
            | Call::Negotiate { .. }
            | Call::OwnerOpen { .. }
            | Call::OwnerRevoke { .. }
            | Call::EnableTransportDrain
            | Call::TransportDrainResult { .. } => invalid(),
        }
    }
    fn features(&self) -> Vec<String> {
        let mut features: Vec<String> = if self.android.is_none()
            && cfg!(not(target_os = "android"))
            && (self.coordinator.exec_configured() || self.settings.is_some())
        {
            [
                "prepare_start",
                "dispatch_start",
                "inspect_start",
                "read",
                "prepare_action",
                "dispatch_action",
                "inspect_action",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect()
        } else {
            Vec::new()
        };
        if self.paired {
            #[cfg(not(target_os = "android"))]
            if self.android.is_none() {
                features.push(wire::HOST_EXEC_TASKS_V1.into());
            }
            features.extend(
                [
                    "owner_open",
                    "owner_revoke",
                    "owner_cleanup",
                    TRANSPORT_DRAIN_V1,
                ]
                .into_iter()
                .map(str::to_owned),
            );
        }
        #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
        if self.paired && self.browser.is_some() {
            features.push(HOST_BROWSER_SESSIONS_V1.into());
        }
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        if self.paired && self.computer.is_some() {
            features.push(COMPUTER_V3.into());
        }
        if self.paired && self.android.is_some() {
            features.push(ANDROID_V1.into());
        }
        if self.settings.is_some() {
            features.push(crate::host::settings::FEATURE.into());
        }
        features
    }
    /// Scoped business waiters never own the native executor. Control admission
    /// remains live while business handlers await upstream work.
    pub async fn run_connection(&self, link: &mut HostWssLink) -> Result<(), ProtocolError> {
        self.run_connection_with_stop(link, &CancellationToken::new())
            .await
            .map(|_| ())
    }
    /// Normal local stop keeps this exact negotiated connection future alive for
    /// original Core owner cleanup. EOF is never terminal-quiescence evidence.
    pub(crate) async fn run_connection_with_stop(
        &self,
        link: &mut HostWssLink,
        stop: &CancellationToken,
    ) -> Result<Option<TransportDrainOutcome>, ProtocolError> {
        self.run_connection_with_readiness(link, stop, None).await
    }
    /// Connection-local observation only: notify after the negotiated drain
    /// enable reply has actually left the original writer. Opening WSS or merely
    /// parsing Negotiate cannot establish a ready paired Host.
    pub(crate) async fn run_connection_with_readiness(
        &self,
        link: &mut HostWssLink,
        stop: &CancellationToken,
        mut ready: Option<tokio::sync::oneshot::Sender<()>>,
    ) -> Result<Option<TransportDrainOutcome>, ProtocolError> {
        let _slot = self
            .coordinator
            .connection_slot()
            .try_acquire()
            .map_err(|_| ProtocolError::Busy)?;
        if link.endpoint() != self.profile.endpoint {
            return Err(ProtocolError::BootstrapMismatch);
        }
        #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
        let _browser_references = if self.paired {
            self.coordinator.invalidate_browser_link_references();
            Some(BrowserLinkReferences(&self.coordinator))
        } else {
            None
        };
        let generation = link.generation().clone();
        let sender = link.sender();
        let mut negotiated = false;
        let mut drain_enabled = false;
        let mut stop_requested = false;
        let mut outstanding_drain: Option<RequestId> = None;
        let mut drain_deadline: Option<tokio::time::Instant> = None;
        let mut result_deadline: Option<tokio::time::Instant> = None;
        let mut completed_drain = None;
        let mut pending: FuturesUnordered<
            futures_util::future::BoxFuture<'_, (RequestId, Option<OwnerRef>, Reply)>,
        > = FuturesUnordered::new();
        loop {
            // Finish already admitted result delivery before sending the existing
            // drain control, which revokes these exact bindings on the Gateway.
            // A fixed grace bounds this wait; it never re-polls an input action.
            if stop_requested
                && outstanding_drain.is_none()
                && (pending.is_empty()
                    || result_deadline.is_some_and(|d| tokio::time::Instant::now() >= d))
            {
                self.fence_transport_stop()?;
                result_deadline = None;
                let id: RequestId = format!("host-drain-{}", uuid::Uuid::new_v4())
                    .try_into()
                    .map_err(|_| ProtocolError::InvalidFrame)?;
                drain_deadline = Some(
                    tokio::time::Instant::now()
                        + Duration::from_millis(u64::from(TRANSPORT_DRAIN_TIMEOUT_MS)),
                );
                let frame = HostControl::TransportDrainV1 {
                    drain_id: id.clone(),
                    connection_generation: generation.clone(),
                    host_generation: self.profile.host_generation.clone(),
                    timeout_ms: TRANSPORT_DRAIN_TIMEOUT_MS,
                };
                outstanding_drain = Some(id);
                let text =
                    serde_json::to_string(&frame).map_err(|_| ProtocolError::ResponseLost)?;
                sender
                    .send_text(text, Duration::from_secs(5))
                    .await
                    .map_err(|_| ProtocolError::ResponseLost)?;
            }
            let (request_id, reply) = tokio::select! {
                biased;
                _ = stop.cancelled(), if !stop_requested => {
                    stop_requested = true;
                    if !self.paired || !negotiated || !drain_enabled {
                        self.fence_transport_stop()?;
                        return Ok(Some(TransportDrainOutcome::Unsupported));
                    }
                    self.coordinator.remote_access().lock().expect("owner registry").stopping = true;
                    result_deadline = Some(tokio::time::Instant::now() + Duration::from_secs(5));
                    continue;
                }
                _ = tokio::time::sleep_until(result_deadline.unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_secs(86400))), if result_deadline.is_some() => {
                    // Re-enter the single original fencing/drain path above.
                    continue;
                }
                _ = tokio::time::sleep_until(drain_deadline.unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_secs(86400))), if drain_deadline.is_some() => {
                    return Ok(Some(TransportDrainOutcome::Unknown));
                }
                finished = pending.next(), if !pending.is_empty() => {
                    let Some((id, owner, mut reply)) = finished else { continue; };
                    // A revoked owner may not receive an in-flight result.
                    if owner.as_ref().is_some_and(|owner| self.receipt_owner(owner).is_err()) {
                        reply = Reply::Error { category: ErrorCategory::Unauthorized, certainty: ExecutionCertainty::Unknown, cursor_may_be_consumed: true };
                    }
                    (id, reply)
                }
                frame = link.recv() => {
                    if self.paired && negotiated && link.close_frame().is_some_and(|f| u16::from(f.code) == PAIRING_REVOKED_CLOSE_CODE && f.reason == PAIRING_REVOKED_CLOSE_REASON) {
                        self.fence_transport_stop()?;
                        return Err(ProtocolError::PairingRevoked);
                    }
                    let Some(frame) = frame else {
                        if !pending.is_empty() { return Err(ProtocolError::ResponseLost); }
                        break;
                    };
                    if frame.generation != generation || frame.as_str().len() > FRAME_LIMIT { return Err(ProtocolError::InvalidFrame); }
                    let request: Request = serde_json::from_str(frame.as_str()).map_err(|_| ProtocolError::InvalidFrame)?;
                    if (!negotiated && request.connection_generation.is_some()) ||
                       (negotiated && request.connection_generation.as_ref() != Some(&generation)) {
                        return Err(ProtocolError::NegotiationRejected);
                    }
                    let request_id = request.request_id.clone();
                    let reply = if !negotiated {
                        match request.call {
                            Call::Negotiate { version, challenge, gateway_namespace, gateway_epoch }
                                if version == (if self.paired { 3 } else { 2 })
                                && gateway_namespace == self.profile.gateway_namespace
                                && (16..=128).contains(&challenge.len())
                                && challenge.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)) => {
                                self.accept_epoch(&gateway_epoch)?;
                                negotiated = true;
                                Reply::Negotiated {
                                    version, challenge, device_id: self.profile.device_id.clone(),
                                    host_generation: self.profile.host_generation.clone(), connection_generation: generation.clone(),
                                    features: self.features(),
                                    write: self.android.is_none() && cfg!(not(target_os = "android")) && (self.coordinator.exec_configured() || self.settings.is_some()), terminate: self.android.is_none() && cfg!(not(target_os = "android")) && (self.coordinator.exec_configured() || self.settings.is_some()), read_resume: false,
                                    owner_issuance: if self.paired { "gateway_authenticated" } else { "bootstrap_preverified_only" }.into(),
                                    grant_revision: self.paired.then(|| self.coordinator.grant_revision()),
                                }
                            }
                            _ => return Err(ProtocolError::NegotiationRejected),
                        }
                    } else if matches!(&request.call, Call::EnableTransportDrain) {
                        if !self.paired || stop_requested { invalid() } else {
                            drain_enabled = true;
                            Reply::TransportDrainEnabled
                        }
                    } else if let Call::TransportDrainResult { drain_id, host_generation, complete } = &request.call {
                        if !stop_requested || !drain_enabled || outstanding_drain.as_ref() != Some(drain_id)
                            || host_generation != &self.profile.host_generation
                            || drain_deadline.is_none_or(|deadline| tokio::time::Instant::now() >= deadline) {
                            return Err(ProtocolError::NegotiationRejected);
                        }
                        completed_drain = Some(if *complete { TransportDrainOutcome::Complete } else { TransportDrainOutcome::Unknown });
                        Reply::TransportDrainResultAccepted { drain_id: drain_id.clone() }
                    } else if let Some(reply) = self.control(&request.call) { reply }
                    else if stop_requested && !matches!(&request.call, Call::OwnerCleanup { .. }) {
                        rejection(ErrorCategory::Unauthorized)
                    }
                    else {
                        let owner = call_owner(&request.call).cloned();
                        // Poll once at admission: dispatch/cleanup synchronously
                        // register Host-owned work before waiting for its result.
                        // A concurrently ready EOF may abandon only the waiter,
                        // not an unpolled, already parsed dispatch request.
                        let mut handler: futures_util::future::BoxFuture<'_, (RequestId, Option<OwnerRef>, Reply)> = Box::pin(async move { (request.request_id, owner, self.handle(request.call).await) });
                        match handler.as_mut().now_or_never() {
                            Some((_, _, reply)) => reply,
                            None => { pending.push(handler); continue; }
                        }
                    };
                    (request_id, reply)
                }
            };
            let response = Response {
                request_id,
                connection_generation: generation.clone(),
                reply,
            };
            let limit = if matches!(
                &response.reply,
                Reply::Android { .. } | Reply::DesktopSession { .. }
            ) {
                super::link::MAX_MESSAGE
            } else {
                RESPONSE_LIMIT
            };
            let mut bytes = BoundedJson(Vec::new(), limit);
            serde_json::to_writer(&mut bytes, &response)
                .map_err(|_| ProtocolError::ResponseLost)?;
            let text = String::from_utf8(bytes.0).map_err(|_| ProtocolError::ResponseLost)?;
            let send_budget = drain_deadline.map_or(Duration::from_secs(5), |deadline| {
                deadline
                    .saturating_duration_since(tokio::time::Instant::now())
                    .min(Duration::from_secs(5))
            });
            if send_budget.is_zero() {
                return Ok(Some(TransportDrainOutcome::Unknown));
            }
            sender
                .send_text(text, send_budget)
                .await
                .map_err(|_| ProtocolError::ResponseLost)?;
            if matches!(&response.reply, Reply::TransportDrainEnabled)
                && let Some(ready) = ready.take()
            {
                // An absent observer never changes protocol/owner admission.
                let _ = ready.send(());
            }
            if let Some(outcome) = completed_drain {
                return Ok(Some(outcome));
            }
        }
        // Dropping scoped waiters does not cancel supervised Host work or replay it.
        Ok(stop_requested.then_some(TransportDrainOutcome::Unknown))
    }
}
fn call_owner(call: &Call) -> Option<&OwnerRef> {
    match call {
        Call::Android { owner, .. }
        | Call::ExecTask { owner, .. }
        | Call::BrowserSession { owner, .. }
        | Call::PrepareStart { owner, .. }
        | Call::DispatchStart { owner, .. }
        | Call::InspectStart { owner, .. }
        | Call::Read { owner, .. }
        | Call::PrepareAction { owner, .. }
        | Call::DispatchAction { owner, .. }
        | Call::InspectAction { owner, .. }
        | Call::DesktopSession { owner, .. } => Some(owner),
        _ => None,
    }
}

struct BoundedJson(Vec<u8>, usize);
impl Write for BoundedJson {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.1.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("bounded response exceeded"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
#[cfg(test)]
mod tests;

#[cfg(test)]
mod paired_tests;

#[cfg(test)]
mod exec_capacity_tests;
