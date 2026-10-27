//! Protected foreground execution, not a migration/service manager. All ownership
//! refusals are conservative observations; the Rust lease cannot lock old JS.
use super::{ForegroundError, ForegroundEvent, ForegroundOutcome, HostWireMode, profile};
use crate::{
    host::{
        bootstrap::OwnedExecHost,
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
    identity::{ConnectionGeneration, DeviceId, HostGeneration},
};
use styx_core::policy::AdmissionFacts;
use tokio::{net::TcpStream, sync::mpsc};
use tokio_util::sync::CancellationToken;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[path = "computer_startup.rs"]
mod computer_startup;

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
enum RunOwner {
    Cli,
    App(
        Arc<crate::app::HostScope>,
        Option<Arc<crate::release::VerifiedNativeRelease>>,
    ),
    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "macos",
        target_os = "windows"
    ))]
    Service(Arc<crate::platform::native_service::ServiceScope>),
}
struct Admitted {
    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "macos",
        target_os = "windows"
    ))]
    service_scope: Option<Arc<crate::platform::native_service::ServiceScope>>,
    profile: Arc<profile::LoadedLegacyProfile>,
    state: PrivateRoot,
    base: PrivateRoot,
    lease: ExecutionLeaseGuard,
}
#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "macos",
    target_os = "windows"
))]
struct ServiceExecAdmission {
    admitted: Arc<Admitted>,
}
#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "macos",
    target_os = "windows"
))]
impl crate::host::coordinator::ExecAdmission for ServiceExecAdmission {
    fn check(&self) -> Result<(), crate::host::coordinator::CoordinatorError> {
        use crate::host::coordinator::CoordinatorError;
        let checked = self.admitted.validate_ownership().and_then(|()| {
            self.admitted
                .profile
                .revalidate_control()
                .map_err(ForegroundError::from)
        });
        checked.map_err(|error| match error.code() {
            "native_service_configuration_pending" => CoordinatorError::Busy,
            "native_service_stop_requested" => {
                CoordinatorError::Admission(styx_contracts::error::ErrorCategory::StateConflict)
            }
            _ => {
                CoordinatorError::Admission(styx_contracts::error::ErrorCategory::IntegrityFailure)
            }
        })
    }
}
impl Admitted {
    fn validate_ownership(&self) -> Result<(), ForegroundError> {
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "macos",
            target_os = "windows"
        ))]
        if let Some(scope) = &self.service_scope {
            // OS identity is stable across a desired-state commit. The profile
            // immediately below owns the full typed C07 admission decision.
            scope
                .validate_identity()
                .map_err(|_| ForegroundError("native_service_scope_changed"))?;
        }
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
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
struct ForegroundBrowser {
    admitted: Arc<Admitted>,
    source: Arc<dyn crate::host::protocol::browser::BrowserBootstrap>,
}
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
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
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
struct ForegroundComputer {
    admitted: Arc<Admitted>,
    source: Arc<dyn crate::host::protocol::computer::ComputerBootstrap>,
}
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
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
#[cfg(any(target_os = "linux", target_os = "windows"))]
async fn prepare_computer(
    admitted: &Arc<Admitted>,
    host: &OwnedExecHost,
    custody: &computer_startup::DeferredComputer,
) -> Result<Option<Arc<dyn crate::host::protocol::computer::ComputerBootstrap>>, ForegroundError> {
    let retained = admitted.clone();
    let enabled =
        tokio::task::spawn_blocking(move || retained.profile.pin_cua_driver().map(|p| p.is_some()))
            .await
            .map_err(|_| ForegroundError("profile_reader_failed"))??;
    if !enabled {
        return Ok(None);
    }
    #[cfg(target_os = "linux")]
    let source = {
        // Zero candidates is normal on a headless Host; multiple candidates are
        // ambiguous. Never pick the first desktop or inherit stale SSH/tmux env.
        let snapshot = super::discover_desktop_candidates().await?;
        if snapshot.candidates.len() != 1 {
            return Err(ForegroundError("desktop_selection_required"));
        }
        crate::host::coordinator::DesktopSource::start(
            snapshot.candidates.into_iter().next().expect("exactly one"),
        )
        .await
        .map_err(|e| ForegroundError(e.code()))?
    };
    #[cfg(target_os = "windows")]
    let source = crate::host::coordinator::DesktopSource::start()
        .await
        .map_err(|_| ForegroundError("computer_native_session_unavailable"))?;
    custody.retain_source(source.clone());
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
#[cfg(target_os = "macos")]
async fn prepare_computer(
    admitted: &Arc<Admitted>,
    host: &OwnedExecHost,
    custody: &computer_startup::DeferredComputer,
) -> Result<Option<Arc<dyn crate::host::protocol::computer::ComputerBootstrap>>, ForegroundError> {
    let retained = admitted.clone();
    let enabled = tokio::task::spawn_blocking(move || retained.profile.computer_enabled())
        .await
        .map_err(|_| ForegroundError("profile_reader_failed"))??;
    if !enabled {
        return Ok(None);
    }
    let source = crate::host::coordinator::DesktopSource::start()
        .await
        .map_err(|e| ForegroundError(e.code()))?;
    custody.retain_source(source.clone());
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
    // The original source is now retained in the Host lane. A lost read-probe
    // reply remains owned Unknown through the common Host cleanup, even if
    // profile construction below fails or the Computer lane stays unavailable.
    host.coordinator()
        .refresh_desktop_source()
        .await
        .map_err(|_| ForegroundError("computer_source_probe_failed"))?;
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
        LinkError::UpgradeStatus(400) => ForegroundError("gateway_wss_request_rejected"),
        LinkError::UpgradeStatus(403) => ForegroundError("gateway_wss_admission_refused"),
        LinkError::UpgradeStatus(429) => ForegroundError("gateway_wss_capacity_exhausted"),
        LinkError::UpgradeStatus(503) => ForegroundError("gateway_wss_unavailable"),
        LinkError::UpgradeStatus(_) | LinkError::HandshakeRejected => {
            ForegroundError("gateway_wss_upgrade_rejected")
        }
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
        remote_transport_drain: None,
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
    tokio::spawn(async move { run_owned(&state, mode, stop, events, RunOwner::Cli).await })
        .await
        .map_err(|_| ForegroundError("foreground_worker_failed"))?
}
#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "windows",
    target_os = "macos"
))]
pub(crate) async fn host_run_for_app(
    scope: Arc<crate::app::HostScope>,
    cancel: CancellationToken,
    events: mpsc::Sender<ForegroundEvent>,
    verified_runtime: Option<Arc<crate::release::VerifiedNativeRelease>>,
) -> Result<ForegroundOutcome, ForegroundError> {
    let state = scope.state_dir().to_owned();
    let stop = cancel.child_token();
    let _cancel_on_waiter_drop = stop.clone().drop_guard();
    tokio::spawn(async move {
        run_owned(
            &state,
            HostWireMode::PairedV3,
            stop,
            events,
            RunOwner::App(scope, verified_runtime),
        )
        .await
    })
    .await
    .map_err(|_| ForegroundError("foreground_worker_failed"))?
}
#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "macos",
    target_os = "windows"
))]
pub(crate) async fn host_run_for_service(
    scope: Arc<crate::platform::native_service::ServiceScope>,
    cancel: CancellationToken,
    events: mpsc::Sender<ForegroundEvent>,
) -> Result<ForegroundOutcome, ForegroundError> {
    use crate::platform::native_service::ServiceRole;
    if scope.role() != ServiceRole::Host {
        return Err(ForegroundError("native_service_role_invalid"));
    }
    scope
        .validate()
        .map_err(|_| ForegroundError("native_service_scope_changed"))?;
    let path = scope.state_dir().to_owned();
    let stop = cancel.child_token();
    let _waiter = stop.clone().drop_guard();
    tokio::spawn(async move {
        run_owned(
            &path,
            HostWireMode::PairedV3,
            stop,
            events,
            RunOwner::Service(scope),
        )
        .await
    })
    .await
    .map_err(|_| ForegroundError("foreground_worker_failed"))?
}
async fn run_owned(
    state_dir: &Path,
    mode: HostWireMode,
    cancel: CancellationToken,
    events: mpsc::Sender<ForegroundEvent>,
    owner: RunOwner,
) -> Result<ForegroundOutcome, ForegroundError> {
    // Independent foreground-run clock. Opt-in closed labels carry no profile,
    // path or credential data and never participate in admission decisions.
    let diagnostic = crate::app::startup_diagnostic::StartupDiagnostic::from_env();
    if let Some(d) = &diagnostic {
        d.report("host_run_begin");
    }
    let profile_diagnostic = diagnostic.clone();
    let path = state_dir.to_path_buf();
    // Never abandon a blocking reader/lease acquisition on signal. Join it,
    // then observe cancellation before any native executable is started.
    let admitted = tokio::task::spawn_blocking(move || {
        if let Some(d) = &profile_diagnostic {
            d.report("host_profile_load_begin");
        }
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "macos",
            target_os = "windows"
        ))]
        let service_scope = match &owner {
            RunOwner::Service(scope) => Some(scope.clone()),
            _ => None,
        };
        let profile = match owner {
            RunOwner::App(scope, Some(runtime)) => profile::load_for_app_retained(scope, runtime)?,
            RunOwner::App(scope, None) => profile::load_for_app(scope)?,
            RunOwner::Cli => match mode {
                HostWireMode::PairedV3 => profile::load_paired(&path)?,
            },
            #[cfg(any(
                all(target_os = "linux", target_env = "gnu"),
                target_os = "macos",
                target_os = "windows"
            ))]
            RunOwner::Service(scope) => profile::load_for_service(scope)?,
        };
        if let Some(d) = &profile_diagnostic {
            d.report("host_profile_load_returned");
        }
        let state = PrivateRoot::open(&path).map_err(|_| ForegroundError("state_root_refused"))?;
        let base = PrivateRoot::open(profile.host_base_dir())
            .map_err(|_| ForegroundError("host_root_refused"))?;
        let lease = base
            .try_execution_lease()
            .map_err(|_| ForegroundError("execution_lease_busy"))?;
        let admitted = Arc::new(Admitted {
            #[cfg(any(
                all(target_os = "linux", target_env = "gnu"),
                target_os = "macos",
                target_os = "windows"
            ))]
            service_scope,
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
    if let Some(d) = &diagnostic {
        d.report("host_profile_admission_returned");
    }
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
    // Run blocking filesystem work on the blocking pool. executor_config itself
    // revalidates the entire signed inventory/raw profile at this spawn boundary;
    // avoid repeating the same full walk immediately before it on an I/O thread.
    let retained = admitted.clone();
    if let Some(d) = &diagnostic {
        d.report("host_executor_config_begin");
    }
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
    if let Some(d) = &diagnostic {
        d.report("host_executor_config_returned");
    }
    let config = match prepared {
        Ok(Ok(v)) => v,
        result => {
            return Err(match result {
                Ok(Err(error)) => error,
                _ => ForegroundError("profile_reader_failed"),
            });
        }
    };
    if cancel.is_cancelled() {
        return Ok(empty_outcome());
    }
    if let Some(d) = &diagnostic {
        d.report("host_executor_spawn_begin");
    }
    // Spawn is joined even on signal; cancelling initialization cannot orphan a
    // partially started child. The bounded provider owns its startup cleanup.
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    let started = reservation
        .spawn_optional_pinned(config, admitted.profile.executor_image())
        .await;
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let started = reservation.spawn_optional(config).await;
    if let Some(d) = &diagnostic {
        d.report("host_executor_spawn_returned");
    }
    let host = match started {
        Ok(v) => Arc::new(v),
        Err(_) => return Err(ForegroundError("executor_start_failed")),
    };
    // Install before exposing any paired connection. A failed installation
    // follows the same owned Host cleanup below; never early-drop the executor.
    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "macos",
        target_os = "windows"
    ))]
    let exec_admission_ready = if admitted.service_scope.is_some() {
        host.authority()
            .configure_exec_admission(Arc::new(ServiceExecAdmission {
                admitted: admitted.clone(),
            }))
            .is_ok()
    } else {
        true
    };
    #[cfg(not(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "macos",
        target_os = "windows"
    )))]
    let exec_admission_ready = true;
    // Browser is an independent optional local capability. Unsupported or
    // unavailable Browser inputs cannot take down an already admitted Exec Host.
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    let browser: Option<Arc<dyn crate::host::protocol::browser::BrowserBootstrap>> =
        if mode == HostWireMode::PairedV3 {
            let retained = admitted.clone();
            let source = tokio::task::spawn_blocking(move || {
                retained.validate_ownership().map_err(|_| {
                    super::browser::BrowserPreparationError::new(
                        "ownership",
                        styx_contracts::error::ErrorCategory::StateConflict,
                    )
                })?;
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
                            event_with_reason(
                                &events,
                                &cancel,
                                "browser_unavailable",
                                &device,
                                None,
                                Some("configure_lane"),
                            );
                            None
                        }
                    }
                }
                Ok(Ok(None)) => None,
                Ok(Err(error)) => {
                    // Static stage plus typed category; never format an upstream
                    // native error or protected path into this event/log.
                    eprintln!(
                        "styx_browser_prepare_failed stage={} category={:?}",
                        error.stage, error.category
                    );
                    event_with_reason(
                        &events,
                        &cancel,
                        "browser_unavailable",
                        &device,
                        None,
                        Some(error.stage),
                    );
                    None
                }
                Err(_) => {
                    event_with_reason(
                        &events,
                        &cancel,
                        "browser_unavailable",
                        &device,
                        None,
                        Some("prepare_task_join"),
                    );
                    None
                }
            }
        } else {
            None
        };
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    let mut computer = (mode == HostWireMode::PairedV3).then(|| {
        computer_startup::ComputerStartup::start(
            admitted.clone(),
            host.clone(),
            events.clone(),
            device.clone(),
            cancel.clone(),
        )
    });
    // Keep this SAME protocol and executor across transport reconnects. In v3,
    // per-chat owner admission comes only from the authenticated fixed Gateway;
    // loading a device credential does not register a bootstrap MCP owner.
    let session = if !exec_admission_ready {
        Err(ForegroundError(
            "native_service_admission_configuration_failed",
        ))
    } else {
        match mode {
            HostWireMode::PairedV3 => {
                let protocol = host.paired_protocol(PairedTrustedProfile {
                    endpoint: admitted.profile.endpoint().as_str().to_owned(),
                    gateway_namespace: admitted.profile.paired_gateway_namespace(),
                    device_id: device.clone(),
                    host_generation: generation,
                });
                let protocol = protocol.map(|protocol| {
                    protocol.with_command_environment(admitted.profile.command_environment())
                });
                #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
                let protocol = protocol.and_then(|protocol| {
                    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
                    let protocol = if let Some(source) = &browser {
                        protocol.with_browser_profiles(source.clone())?
                    } else {
                        protocol
                    };
                    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
                    let protocol = if let Some(source) = &computer {
                        protocol.with_computer_profiles(source.factory())?
                    } else {
                        protocol
                    };
                    Ok(protocol)
                });
                protocol
                    .map(ConnectionSession::Paired)
                    .map_err(|_| ForegroundError("paired_bootstrap_refused"))
            }
        }
    };
    let mut failure = None;
    // No remote transport exists until after the local signed inputs, executor
    // and optional providers are ready. Local failure still settles this host.
    let mut remote_transport_drain = None;
    match session {
        Ok(session) => {
            let connection: ConnectionGeneration = uuid::Uuid::new_v4()
                .to_string()
                .try_into()
                .expect("UUID identity");
            let initial = if cancel.is_cancelled() {
                Ok(None)
            } else {
                event(&events, &cancel, "connecting", &device, Some(&connection));
                tokio::select! {
                    _=cancel.cancelled()=>Ok(None),
                    result=connect(&admitted.profile,connection,host.link_budget())=>result.map(Some),
                }
            };
            match initial {
                Ok(Some(mut link)) => {
                    if mode == HostWireMode::PairedV3 {
                        remote_transport_drain =
                            Some(crate::host::protocol::wire::TransportDrainOutcome::Unknown);
                    }
                    loop {
                        // Readiness cannot drop or replace this connection future.
                        // The paired protocol sends it only after the drain-enable
                        // response has actually been sent on this exact link.
                        let connection_generation = link.generation().clone();
                        let (ready, mut readiness) = tokio::sync::oneshot::channel();
                        let result = {
                            let maintenance_stop = CancellationToken::new();
                            let housekeeping = async {
                                loop {
                                    tokio::select! {
                                        _=maintenance_stop.cancelled()=>return None::<ForegroundError>,
                                        _=tokio::time::sleep(Duration::from_secs(5))=>{},
                                    }
                                    #[cfg(any(
                                        all(target_os = "linux", target_env = "gnu"),
                                        target_os = "macos",
                                        target_os = "windows"
                                    ))]
                                    if admitted.service_scope.is_some()
                                        && let Err(error) = validate(&admitted).await
                                    {
                                        match error.code() {
                                            "native_service_configuration_pending" => {}
                                            "native_service_stop_requested" => {
                                                cancel.cancel();
                                                return None;
                                            }
                                            _ => {
                                                cancel.cancel();
                                                return Some(error);
                                            }
                                        }
                                    }
                                    let _ = host
                                        .authority()
                                        .collect_provider_retention(Duration::from_secs(1))
                                        .await;
                                }
                            };
                            let running = session.run_connection_with_readiness(
                                &mut link,
                                &cancel,
                                Some(ready),
                            );
                            tokio::pin!(housekeeping);
                            tokio::pin!(running);
                            let mut awaiting_ready = true;
                            loop {
                                tokio::select! {
                                    biased;
                                    // A known terminal link wins over a queued
                                    // readiness observation for that same link.
                                    result=&mut running=>{
                                        maintenance_stop.cancel();
                                        // A blocking read already admitted by this
                                        // original housekeeping future must join.
                                        if let Some(error)=housekeeping.await { failure=Some(error); }
                                        break result;
                                    },
                                    ready=&mut readiness, if awaiting_ready=>{
                                        awaiting_ready = false;
                                        if ready.is_ok() && !cancel.is_cancelled() {
                                            event(&events,&cancel,"connected",&device,Some(&connection_generation));
                                        }
                                    },
                                    error=&mut housekeeping=>{
                                        if let Some(error)=error { failure=Some(error); }
                                        // Stop/failure requests drain the SAME
                                        // live protocol future, never drop it.
                                        break running.await;
                                    },
                                }
                            }
                        };
                        let disconnected = if cancel.is_cancelled() {
                            if mode == HostWireMode::PairedV3 {
                                remote_transport_drain = Some(result.ok().flatten().unwrap_or(
                                    crate::host::protocol::wire::TransportDrainOutcome::Unknown,
                                ));
                            }
                            false
                        } else {
                            event(
                                &events,
                                &cancel,
                                if result.is_ok() {
                                    "disconnected"
                                } else {
                                    "connection_result_unknown"
                                },
                                &device,
                                Some(&connection_generation),
                            );
                            true
                        };
                        // EOF does not stop the executor. Always join the same
                        // physical link before reconnecting or native cleanup.
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
                                if error.code() == "native_service_configuration_pending" {
                                    event(&events, &cancel, "configuration_pending", &device, None);
                                    continue;
                                }
                                if error.code() == "native_service_stop_requested" {
                                    cancel.cancel();
                                    break;
                                }
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
                        if mode == HostWireMode::PairedV3 {
                            remote_transport_drain =
                                Some(crate::host::protocol::wire::TransportDrainOutcome::Unknown);
                        }
                    }
                }
                Ok(None) => {}
                Err(error) => failure = Some(error),
            }
            // Same original input jobs remain owned through every link failure.
            #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
            session.drain_browser_inputs().await;
        }
        Err(error) => failure = Some(error),
    }
    event(&events, &cancel, "stopping", &device, None);
    let mut outcome = ForegroundOutcome {
        schema: 1,
        executor_started: host.coordinator().exec_configured(),
        executor_exited: false,
        processes_exited: false,
        io_tasks_joined: false,
        supervised_jobs_joined: false,
        remote_transport_drain,
    };
    let mut process_exits = BTreeMap::new();
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    if let Some(computer) = &computer {
        computer.close_admission();
    }

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
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        if let Some(computer) = &mut computer {
            // Exec shutdown happens independently, while desktop initialization
            // and its original source stay retained until real join/stop facts.
            let complete = computer
                .settle(tokio::time::Instant::now() + Duration::from_secs(1))
                .await;
            outcome.supervised_jobs_joined &= complete;
            outcome.processes_exited &= complete;
            outcome.io_tasks_joined &= complete;
        }
        if outcome.local_stop_complete() {
            break;
        }
        event(&events, &cancel, "cleanup_unknown", &device, None);
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    event(&events, &cancel, "stopped", &device, None);
    // Explicit drop order: observed signed files / lease outlive native cleanup.
    drop(host);
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    drop(browser);
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
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
    Paired(HostProtocol<'a>),
}
impl ConnectionSession<'_> {
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    async fn drain_browser_inputs(&self) {
        let Self::Paired(protocol) = self;
        protocol.drain_browser_inputs().await;
        protocol.drain_computer_inputs().await;
    }
    async fn run_connection_with_readiness(
        &self,
        link: &mut HostWssLink,
        stop: &CancellationToken,
        ready: Option<tokio::sync::oneshot::Sender<()>>,
    ) -> Result<Option<crate::host::protocol::wire::TransportDrainOutcome>, ()> {
        match self {
            Self::Paired(protocol) => protocol
                .run_connection_with_readiness(link, stop, ready)
                .await
                .map_err(|_| ()),
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
