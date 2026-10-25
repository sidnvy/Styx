//! Protected foreground execution, not a migration/service manager. All ownership
//! refusals are conservative observations; the Rust lease cannot lock old JS.
use super::{ForegroundError, ForegroundEvent, ForegroundOutcome, HostWireMode, profile};
use crate::{
    host::{
        bootstrap::OwnedExecHost,
        legacy::{LegacyExecSession, TrustedLegacyGateway},
        link::{HostLinkBudget, HostWssLink, LinkAuthentication, LinkError},
        protocol::{HostProtocol, PairedTrustedProfile},
    },
    providers::codex::TerminationEvidence,
    store::{ExecutionLeaseGuard, PrivateRoot},
};
use std::{collections::BTreeMap, path::Path, sync::Arc, time::Duration};
use styx_contracts::{
    capability::{Authorization, Availability, CapabilityDescriptor, CapabilityId, Scope},
    error::Recovery,
    identity::{ConnectionGeneration, DeviceId, HostGeneration, Sha256Digest},
};
use styx_core::policy::AdmissionFacts;
use tokio::{net::TcpStream, sync::mpsc};
use tokio_util::sync::CancellationToken;

const STATE_OWNERS: &[&str] = &[
    "foreground.lock",
    "foreground-recovery.lock",
    "background.lock",
    "advance.lock",
    "capabilities.lock",
];
const HEALTH_OWNERS: &[&str] = &[
    "install/.health-update-lock",
    "install/.health-operation-lock",
    "install/.health-recovery-guard",
];
struct Admitted {
    profile: Arc<profile::LoadedLegacyProfile>,
    state: PrivateRoot,
    base: PrivateRoot,
    lease: ExecutionLeaseGuard,
}
impl Admitted {
    fn validate_ownership(&self) -> Result<(), ForegroundError> {
        if self
            .profile
            .validate_committed_ownership(&self.state, &self.base)?
        {
            self.lease
                .validate()
                .map_err(|_| ForegroundError("execution_lease_changed"))?;
            return Ok(());
        }
        for name in STATE_OWNERS {
            self.state
                .ensure_absent(name)
                .map_err(|_| ForegroundError("legacy_owner_reconciliation_required"))?;
        }
        // No OS service observer is available in this slice. Even a reportedly
        // stopped service configuration therefore requires explicit reconciliation.
        self.base
            .ensure_absent("service.json")
            .map_err(|_| ForegroundError("legacy_service_observation_required"))?;
        for name in HEALTH_OWNERS {
            self.base
                .ensure_absent(name)
                .map_err(|_| ForegroundError("legacy_update_reconciliation_required"))?;
        }
        self.lease
            .validate()
            .map_err(|_| ForegroundError("execution_lease_changed"))?;
        Ok(())
    }
    fn validate(&self) -> Result<(), ForegroundError> {
        self.validate_ownership()?;
        self.profile.revalidate()?;
        Ok(())
    }
}
#[cfg(target_os = "linux")]
struct ForegroundBrowser {
    admitted: Arc<Admitted>,
    source: Arc<dyn crate::host::protocol::browser::BrowserBootstrap>,
}
#[cfg(target_os = "linux")]
impl crate::host::protocol::browser::BrowserBootstrap for ForegroundBrowser {
    fn prepare_profile(
        &self,
        owner: &styx_core::operations::OwnerLease,
    ) -> Result<crate::providers::browser::OwnedBrowserConfig, styx_contracts::error::ErrorCategory>
    {
        self.source.prepare_profile(owner)
    }
    fn validate_before_spawn(&self) -> Result<(), styx_contracts::error::ErrorCategory> {
        self.admitted
            .validate_ownership()
            .map_err(|_| styx_contracts::error::ErrorCategory::StateConflict)?;
        self.source.validate_before_spawn()
    }
    fn validate_control(&self) -> Result<(), styx_contracts::error::ErrorCategory> {
        self.admitted
            .validate_ownership()
            .map_err(|_| styx_contracts::error::ErrorCategory::StateConflict)?;
        self.source.validate_control()
    }
}
#[cfg(target_os = "linux")]
struct ForegroundComputer {
    admitted: Arc<Admitted>,
    source: Arc<dyn crate::host::protocol::computer::ComputerBootstrap>,
}
#[cfg(target_os = "linux")]
impl crate::host::protocol::computer::ComputerBootstrap for ForegroundComputer {
    fn prepare_profile(
        &self,
        owner: &styx_core::operations::OwnerLease,
    ) -> Result<crate::providers::cua::OwnedCuaConfig, styx_contracts::error::ErrorCategory> {
        self.admitted
            .validate_ownership()
            .map_err(|_| styx_contracts::error::ErrorCategory::StateConflict)?;
        self.source.prepare_profile(owner)
    }
    fn validate_before_spawn(&self) -> Result<(), styx_contracts::error::ErrorCategory> {
        self.admitted
            .validate_ownership()
            .map_err(|_| styx_contracts::error::ErrorCategory::StateConflict)?;
        self.source.validate_before_spawn()
    }
    fn validate_control(&self) -> Result<(), styx_contracts::error::ErrorCategory> {
        self.admitted
            .validate_ownership()
            .map_err(|_| styx_contracts::error::ErrorCategory::StateConflict)?;
        self.source.validate_control()
    }
}
#[cfg(target_os = "linux")]
async fn prepare_computer(
    admitted: &Arc<Admitted>,
    host: &OwnedExecHost,
) -> Result<Option<Arc<dyn crate::host::protocol::computer::ComputerBootstrap>>, ForegroundError> {
    let retained = admitted.clone();
    let enabled =
        tokio::task::spawn_blocking(move || retained.profile.pin_cua_driver().map(|p| p.is_some()))
            .await
            .map_err(|_| ForegroundError("profile_reader_failed"))??;
    if !enabled {
        return Ok(None);
    }
    // Zero candidates is normal on a headless Host; multiple candidates are
    // ambiguous. Never pick the first desktop or inherit stale SSH/tmux env.
    let snapshot = super::discover_desktop_candidates().await?;
    if snapshot.candidates.len() != 1 {
        return Err(ForegroundError("desktop_selection_required"));
    }
    let source = crate::host::coordinator::DesktopSource::start(
        snapshot.candidates.into_iter().next().expect("exactly one"),
    )
    .await
    .map_err(|e| ForegroundError(e.code()))?;
    let budget = match host.reserve_computer_io() {
        Ok(v) => v,
        Err(_) => {
            let _ = source.stop().await;
            return Err(ForegroundError("computer_capacity"));
        }
    };
    let mut grants = BTreeMap::new();
    for cap in [
        CapabilityId::DesktopWindowsRead,
        CapabilityId::DesktopWindowsControl,
        CapabilityId::DesktopCapture,
        CapabilityId::DesktopPointer,
        CapabilityId::DesktopKeyboard,
        CapabilityId::DesktopAccessibility,
    ] {
        grants.insert(
            cap,
            crate::host::coordinator::DesktopGrant {
                configured: true,
                remote_grant: true,
                local_policy_allowed: true,
            },
        );
    }
    let binding = match host
        .authority()
        .configure_desktop(source.clone(), budget, grants)
        .await
    {
        Ok(v) => v,
        Err(_) => {
            let _ = source.stop().await;
            return Err(ForegroundError("computer_session_refused"));
        }
    };
    let retained = admitted.clone();
    let prepared = tokio::task::spawn_blocking(move || {
        super::computer::prepare_computer_bootstrap(retained.profile.clone(), source, binding)
    })
    .await
    .map_err(|_| ForegroundError("computer_bootstrap_failed"))??;
    Ok(prepared.map(|source| {
        Arc::new(ForegroundComputer {
            admitted: admitted.clone(),
            source,
        }) as Arc<dyn crate::host::protocol::computer::ComputerBootstrap>
    }))
}
fn event(
    events: &mpsc::Sender<ForegroundEvent>,
    cancel: &CancellationToken,
    name: &'static str,
    device: &DeviceId,
    generation: Option<&ConnectionGeneration>,
) {
    event_with_reason(events, cancel, name, device, generation, None);
}
fn event_with_reason(
    events: &mpsc::Sender<ForegroundEvent>,
    cancel: &CancellationToken,
    name: &'static str,
    device: &DeviceId,
    generation: Option<&ConnectionGeneration>,
    reason: Option<&'static str>,
) {
    if events
        .try_send(ForegroundEvent {
            schema: 1,
            event: name,
            reason,
            device_id: Some(device.clone()),
            connection_generation: generation.cloned(),
        })
        .is_err()
    {
        // Output loss cannot block cleanup or silently detach an owned executor.
        cancel.cancel();
    }
}
async fn validate(admitted: &Arc<Admitted>) -> Result<(), ForegroundError> {
    let retained = admitted.clone();
    tokio::task::spawn_blocking(move || retained.validate())
        .await
        .map_err(|_| ForegroundError("profile_reader_failed"))?
}
async fn connect(
    profile: &profile::LoadedLegacyProfile,
    generation: ConnectionGeneration,
    budget: Arc<HostLinkBudget>,
) -> Result<HostWssLink, ForegroundError> {
    let endpoint = profile.endpoint();
    let url = url::Url::parse(endpoint.as_str())
        .map_err(|_| ForegroundError("invalid_gateway_endpoint"))?;
    let hostname = match url
        .host()
        .ok_or(ForegroundError("invalid_gateway_endpoint"))?
    {
        url::Host::Domain(v) => v.to_owned(),
        url::Host::Ipv4(v) => v.to_string(),
        url::Host::Ipv6(v) => v.to_string(),
    };
    let port = url
        .port_or_known_default()
        .ok_or(ForegroundError("invalid_gateway_endpoint"))?;
    let tcp = tokio::time::timeout(
        Duration::from_secs(5),
        TcpStream::connect((hostname.as_str(), port)),
    )
    .await
    .map_err(|_| ForegroundError("gateway_connect_timeout"))?
    .map_err(|_| ForegroundError("gateway_connect_failed"))?;
    HostWssLink::connect(
        endpoint,
        profile.tls(),
        tcp,
        LinkAuthentication::Bearer(profile.bearer()),
        generation,
        budget,
    )
    .await
    .map_err(|error| match error {
        LinkError::Tls(crate::tls::TlsError::CertificateRejected(cause)) => {
            ForegroundError(cause.code())
        }
        LinkError::Tls(crate::tls::TlsError::HandshakeTimeout) => {
            ForegroundError("gateway_tls_timeout")
        }
        LinkError::Tls(_) => ForegroundError("gateway_tls_handshake_rejected"),
        LinkError::HandshakeRejected => ForegroundError("gateway_wss_upgrade_rejected"),
        LinkError::Deadline => ForegroundError("gateway_transport_deadline"),
        _ => ForegroundError("gateway_transport_refused"),
    })
}
fn facts(device: &DeviceId) -> AdmissionFacts {
    // These are bootstrap-local facts after the original credential's strict
    // WSS admission, not v3 per-chat grants or client-supplied tool authority.
    AdmissionFacts {
        device_id: device.clone(),
        grant_revision: 1,
        local_policy_allowed: true,
        descriptor: CapabilityDescriptor {
            contract_version: styx_contracts::CONTRACT_VERSION,
            capability_id: CapabilityId::ExecRun,
            scope: Scope::Host,
            provider_id: "codex".try_into().expect("static provider identity"),
            configured: true,
            remote_grant: true,
            availability: Availability::Available,
            authorization: Authorization::Granted,
            target_session: None,
            reason: None,
            observed_at: 0,
            observation_generation: 1,
            recovery: Recovery::None,
        },
        session_state: None,
        current_observation: None,
    }
}
fn empty_outcome() -> ForegroundOutcome {
    ForegroundOutcome {
        schema: 1,
        executor_started: false,
        executor_exited: false,
        processes_exited: true,
        io_tasks_joined: true,
        supervised_jobs_joined: true,
    }
}
pub async fn host_run(
    state_dir: &Path,
    mode: HostWireMode,
    cancel: CancellationToken,
    events: mpsc::Sender<ForegroundEvent>,
) -> Result<ForegroundOutcome, ForegroundError> {
    let state = state_dir.to_path_buf();
    let stop = cancel.child_token();
    // A caller timeout/aborted waiter signals the owned worker instead of dropping
    // its lease, pinned payload or native supervisor. Tokio detaches the worker
    // JoinHandle on waiter drop; the running runtime must remain alive for cleanup.
    let _cancel_on_waiter_drop = stop.clone().drop_guard();
    tokio::spawn(async move { run_owned(&state, mode, stop, events).await })
        .await
        .map_err(|_| ForegroundError("foreground_worker_failed"))?
}
async fn run_owned(
    state_dir: &Path,
    mode: HostWireMode,
    cancel: CancellationToken,
    events: mpsc::Sender<ForegroundEvent>,
) -> Result<ForegroundOutcome, ForegroundError> {
    let path = state_dir.to_path_buf();
    // Never abandon a blocking reader/lease acquisition on signal. Join it,
    // then observe cancellation before any native executable is started.
    let admitted = tokio::task::spawn_blocking(move || {
        let profile = match mode {
            HostWireMode::LegacyExplicit => profile::load_legacy(&path)?,
            HostWireMode::PairedV3 => profile::load_paired(&path)?,
        };
        let state = PrivateRoot::open(&path).map_err(|_| ForegroundError("state_root_refused"))?;
        let base = PrivateRoot::open(profile.host_base_dir())
            .map_err(|_| ForegroundError("host_root_refused"))?;
        let lease = base
            .try_execution_lease()
            .map_err(|_| ForegroundError("execution_lease_busy"))?;
        let admitted = Arc::new(Admitted {
            profile: Arc::new(profile),
            state,
            base,
            lease,
        });
        admitted.validate()?;
        // Runtime scratch is created only after original ownership/leases were
        // admitted, never by the read-only profile inspection API.
        #[cfg(target_os = "windows")]
        admitted.profile.prepare_runtime_temp(&admitted.base)?;
        Ok::<_, ForegroundError>(admitted)
    })
    .await
    .map_err(|_| ForegroundError("profile_reader_failed"))??;
    let device = admitted.profile.device_id().clone();
    if cancel.is_cancelled() {
        return Ok(empty_outcome());
    }
    let generation: HostGeneration = uuid::Uuid::new_v4()
        .to_string()
        .try_into()
        .expect("UUID identity");
    let reservation = OwnedExecHost::reserve(generation.clone(), facts(&device), 16)
        .map_err(|_| ForegroundError("host_reservation_refused"))?;
    let connection: ConnectionGeneration = uuid::Uuid::new_v4()
        .to_string()
        .try_into()
        .expect("UUID identity");
    event(&events, &cancel, "connecting", &device, Some(&connection));
    let mut link = tokio::select! {
        _=cancel.cancelled()=>return Ok(empty_outcome()),
        result=connect(&admitted.profile,connection,reservation.link_budget())=>result?,
    };
    // Run blocking filesystem work on the blocking pool. executor_config itself
    // revalidates the entire signed inventory/raw profile at this spawn boundary;
    // avoid repeating the same full walk immediately before it on an I/O thread.
    let retained = admitted.clone();
    let prepared = tokio::task::spawn_blocking(move || {
        retained.validate_ownership()?;
        if retained.profile.executor_enabled() {
            retained
                .profile
                .executor_config()
                .map(Some)
                .map_err(ForegroundError::from)
        } else {
            retained
                .profile
                .revalidate()
                .map_err(ForegroundError::from)?;
            Ok(None)
        }
    })
    .await;
    let config = match prepared {
        Ok(Ok(v)) => v,
        result => {
            let _ = link.shutdown(Duration::from_secs(3)).await;
            return Err(match result {
                Ok(Err(error)) => error,
                _ => ForegroundError("profile_reader_failed"),
            });
        }
    };
    if cancel.is_cancelled() {
        link.shutdown(Duration::from_secs(3))
            .await
            .map_err(|_| ForegroundError("link_cleanup_unknown"))?;
        return Ok(empty_outcome());
    }
    // Spawn is joined even on signal; cancelling initialization cannot orphan a
    // partially started child. The bounded provider owns its startup cleanup.
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    let started = reservation
        .spawn_optional_pinned(config, admitted.profile.executor_image())
        .await;
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let started = reservation.spawn_optional(config).await;
    let host = match started {
        Ok(v) => v,
        Err(_) => {
            let _ = link.shutdown(Duration::from_secs(3)).await;
            return Err(ForegroundError("executor_start_failed"));
        }
    };
    // Browser is an independent optional local capability. Unsupported or
    // unavailable Browser inputs cannot take down an already admitted Exec Host.
    #[cfg(target_os = "linux")]
    let browser: Option<Arc<dyn crate::host::protocol::browser::BrowserBootstrap>> =
        if mode == HostWireMode::PairedV3 {
            let retained = admitted.clone();
            let source = tokio::task::spawn_blocking(move || {
                retained
                    .validate_ownership()
                    .map_err(|_| styx_contracts::error::ErrorCategory::StateConflict)?;
                super::browser::prepare_browser_bootstrap(retained.profile.clone())
            })
            .await;
            match source {
                Ok(Ok(Some(source))) => {
                    let mut browser_facts = facts(&device);
                    browser_facts.descriptor.capability_id = CapabilityId::BrowserHeadless;
                    browser_facts.descriptor.scope = Scope::Browser;
                    browser_facts.descriptor.provider_id =
                        "playwright".try_into().expect("static provider identity");
                    match host.reserve_browser_io().and_then(|budget| {
                        host.authority()
                            .configure_browser(browser_facts, budget)
                            .map_err(Into::into)
                    }) {
                        Ok(()) => Some(Arc::new(ForegroundBrowser {
                            admitted: admitted.clone(),
                            source,
                        })),
                        Err(_) => {
                            event(&events, &cancel, "browser_unavailable", &device, None);
                            None
                        }
                    }
                }
                Ok(Ok(None)) => None,
                _ => {
                    event(&events, &cancel, "browser_unavailable", &device, None);
                    None
                }
            }
        } else {
            None
        };
    #[cfg(target_os = "linux")]
    let computer = if mode == HostWireMode::PairedV3 {
        match prepare_computer(&admitted, &host).await {
            Ok(source) => source,
            Err(error) => {
                event_with_reason(
                    &events,
                    &cancel,
                    "computer_unavailable",
                    &device,
                    None,
                    Some(error.code()),
                );
                None
            }
        }
    } else {
        None
    };
    // Keep this SAME protocol and executor across transport reconnects. In v3,
    // per-chat owner admission comes only from the authenticated fixed Gateway;
    // loading a device credential does not register a bootstrap MCP owner.
    let session = match mode {
        HostWireMode::LegacyExplicit => {
            let namespace = format!(
                "legacy.{}",
                Sha256Digest::of_bytes(admitted.profile.endpoint().as_str().as_bytes()).to_hex()
            );
            host.legacy_session(TrustedLegacyGateway {
                endpoint: admitted.profile.endpoint().as_str().to_owned(),
                gateway_namespace: namespace.try_into().expect("bounded namespace"),
            })
            .map(ConnectionSession::Legacy)
            .map_err(|_| ForegroundError("legacy_bootstrap_refused"))
        }
        HostWireMode::PairedV3 => host
            .paired_protocol(PairedTrustedProfile {
                endpoint: admitted.profile.endpoint().as_str().to_owned(),
                gateway_namespace: admitted.profile.paired_gateway_namespace(),
                device_id: device.clone(),
                host_generation: generation,
            })
            .and_then(|protocol| {
                #[cfg(target_os = "windows")]
                let protocol = protocol
                    .with_windows_command_environment(admitted.profile.command_environment());
                #[cfg(target_os = "linux")]
                let protocol = if let Some(source) = &browser {
                    protocol.with_browser_profiles(source.clone())?
                } else {
                    protocol
                };
                #[cfg(target_os = "linux")]
                let protocol = if let Some(source) = &computer {
                    protocol.with_computer_profiles(source.clone())?
                } else {
                    protocol
                };
                Ok(protocol)
            })
            .map(ConnectionSession::Paired)
            .map_err(|_| ForegroundError("paired_bootstrap_refused")),
    };
    let mut failure = None;
    match session {
        Ok(session) => {
            event(
                &events,
                &cancel,
                "connected",
                &device,
                Some(link.generation()),
            );
            loop {
                // This trusted collector runs alongside the SAME pinned connection
                // future; a timer must not drop an in-flight request and invent EOF.
                let housekeeping = async {
                    loop {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        let _ = host
                            .authority()
                            .collect_provider_retention(Duration::from_secs(1))
                            .await;
                    }
                };
                let disconnected = tokio::select! {
                    _=cancel.cancelled()=>false,
                    _=housekeeping=>unreachable!("collector loop does not return"),
                    result=session.run_connection(&mut link)=>{
                        event(&events,&cancel,if result.is_ok(){"disconnected"}else{"connection_result_unknown"},&device,Some(link.generation()));
                        true
                    },
                };
                // The executor and supervised operations are NOT stopped by EOF.
                // shutdown joins all I/O tasks even when graceful-close times out;
                // Deadline is not evidence of a still-detached transport task.
                if link.shutdown(Duration::from_secs(3)).await.is_err() {
                    event(&events, &cancel, "link_close_deadline", &device, None);
                }
                if !disconnected || cancel.is_cancelled() {
                    break;
                }
                let mut next = None;
                loop {
                    tokio::select! {
                        _=cancel.cancelled()=>break,
                        _=tokio::time::sleep(Duration::from_secs(2))=>{},
                    }
                    if cancel.is_cancelled() {
                        break;
                    }
                    if let Err(error) = validate(&admitted).await {
                        failure = Some(error);
                        break;
                    }
                    let generation: ConnectionGeneration = uuid::Uuid::new_v4()
                        .to_string()
                        .try_into()
                        .expect("UUID identity");
                    event(&events, &cancel, "reconnecting", &device, Some(&generation));
                    let attempt = tokio::select! {
                        _=cancel.cancelled()=>break,
                        result=connect(&admitted.profile,generation,host.link_budget())=>result,
                    };
                    match attempt {
                        Ok(v) => {
                            next = Some(v);
                            break;
                        }
                        Err(_) => event(&events, &cancel, "disconnected", &device, None),
                    }
                }
                let Some(connected) = next else {
                    break;
                };
                link = connected;
                event(
                    &events,
                    &cancel,
                    "connected",
                    &device,
                    Some(link.generation()),
                );
            }
            // EOF abandons only a response waiter. Explicit shutdown joins all
            // retained blocking input jobs before releasing original owner pins.
            #[cfg(target_os = "linux")]
            session.drain_browser_inputs().await;
        }
        Err(error) => {
            let _ = link.shutdown(Duration::from_secs(3)).await;
            failure = Some(error);
        }
    }
    event(&events, &cancel, "stopping", &device, None);
    let mut outcome = ForegroundOutcome {
        schema: 1,
        executor_started: host.coordinator().exec_configured(),
        executor_exited: false,
        processes_exited: false,
        io_tasks_joined: false,
        supervised_jobs_joined: false,
    };
    let mut process_exits = BTreeMap::new();
    // Unknown cleanup retains the SAME owner, pin and supervisor. Never release
    // the lease on a timer while the native child might still execute signed code.
    loop {
        if let Ok(cleanup) = host.shutdown_owned(Duration::from_secs(10)).await {
            if let Some(native) = &cleanup.native {
                for (process, evidence) in &native.processes {
                    record_process_exit(&mut process_exits, process.operation().clone(), *evidence);
                }
            }
            outcome.processes_exited = process_exits.values().all(|exited| *exited)
                && cleanup.ancillary_providers_settled();
            if let Some(native) = &cleanup.native {
                outcome.executor_exited |= native.executor_exited;
            }
            outcome.io_tasks_joined = cleanup
                .native
                .as_ref()
                .is_none_or(|native| native.reader_task_reaped && native.stderr_task_reaped)
                && cleanup.ancillary_providers_settled();
            outcome.supervised_jobs_joined = cleanup.supervised_jobs_joined;
        }
        if outcome.is_complete() {
            break;
        }
        event(&events, &cancel, "cleanup_unknown", &device, None);
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    event(&events, &cancel, "stopped", &device, None);
    // Explicit drop order: observed signed files / lease outlive native cleanup.
    drop(host);
    #[cfg(target_os = "linux")]
    drop(browser);
    #[cfg(target_os = "linux")]
    drop(computer);
    drop(admitted);
    if let Some(error) = failure {
        Err(error)
    } else {
        Ok(outcome)
    }
}

/// A local composition choice, not a wire fallback. Protocol negotiation never
/// silently switches to legacy mode if authenticated paired admission fails.
enum ConnectionSession<'a> {
    Legacy(LegacyExecSession<'a>),
    Paired(HostProtocol<'a>),
}
impl ConnectionSession<'_> {
    #[cfg(target_os = "linux")]
    async fn drain_browser_inputs(&self) {
        if let Self::Paired(protocol) = self {
            protocol.drain_browser_inputs().await;
            protocol.drain_computer_inputs().await;
        }
    }
    async fn run_connection(&self, link: &mut HostWssLink) -> Result<(), ()> {
        match self {
            Self::Legacy(session) => session.run_connection(link).await.map_err(|_| ()),
            Self::Paired(protocol) => protocol.run_connection(link).await.map_err(|_| ()),
        }
    }
}

/// Keep original resource identities even if a later cleanup inventory is empty.
/// Server exit and joined I/O are independent from each command's real exit.
fn record_process_exit(
    records: &mut BTreeMap<styx_contracts::operation::OperationId, bool>,
    operation: styx_contracts::operation::OperationId,
    evidence: TerminationEvidence,
) {
    let previous = records.entry(operation).or_insert(false);
    *previous |= matches!(evidence, TerminationEvidence::ProcessExited(_));
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cleanup_unknown_original_resource_cannot_be_erased_by_server_exit_or_empty_inventory() {
        let operation = styx_contracts::operation::OperationId {
            host_generation: "test-host".try_into().unwrap(),
            owner_epoch: "test-owner".try_into().unwrap(),
            sequence: 1,
        };
        let mut records = BTreeMap::new();
        record_process_exit(
            &mut records,
            operation.clone(),
            TerminationEvidence::Unknown,
        );
        let mut outcome = empty_outcome();
        outcome.processes_exited = records.values().all(|exited| *exited);
        assert!(
            !outcome.is_complete(),
            "joined server/I/O/jobs cannot stand in for original command exit"
        );
        // A second empty inventory does not remove the original Unknown identity.
        assert!(!records.values().all(|exited| *exited));
        record_process_exit(
            &mut records,
            operation.clone(),
            TerminationEvidence::ProcessExited(137),
        );
        record_process_exit(&mut records, operation, TerminationEvidence::Unknown);
        outcome.processes_exited = records.values().all(|exited| *exited);
        assert!(
            outcome.is_complete(),
            "independently known exit is monotonic, not operation success"
        );
    }
}
