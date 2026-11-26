//! Native foreground execution shared by CLI, App and persistent services.
use super::{ForegroundError, ForegroundEvent, ForegroundOutcome, profile};
use crate::{
    host::{
        bootstrap::OwnedExecHost,
        link::{HostWssLink, LinkAuthentication, LinkError},
        protocol::PairedTrustedProfile,
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

struct LocalCapabilityRuntime {
    admitted: Arc<Admitted>,
    host: Arc<OwnedExecHost>,
}
impl crate::host::settings::CapabilityRuntime for LocalCapabilityRuntime {
    fn apply(
        &self,
        _before: crate::host::settings::Capabilities,
        after: crate::host::settings::Capabilities,
    ) -> futures_util::future::BoxFuture<'_, Result<(), styx_contracts::error::ErrorCategory>> {
        Box::pin(async move {
            use styx_contracts::error::ErrorCategory;
            self.admitted
                .validate_ownership()
                .map_err(|_| ErrorCategory::IntegrityFailure)?;
            self.host
                .authority()
                .stop_disabled_capabilities(after)
                .await?;
            if after.exec && !self.host.coordinator().exec_configured() {
                let profile = self.admitted.profile.clone();
                let config = tokio::task::spawn_blocking(move || profile.executor_config())
                    .await
                    .map_err(|_| ErrorCategory::IntegrityFailure)?
                    .map_err(|_| ErrorCategory::CapabilityUnsupported)?;
                self.host
                    .enable_executor(
                        config,
                        facts(self.admitted.profile.device_id()),
                        #[cfg(any(target_os = "macos", target_os = "windows"))]
                        self.admitted
                            .profile
                            .executor_image()
                            .ok_or(ErrorCategory::CapabilityUnsupported)?,
                    )
                    .await
                    .map_err(|_| ErrorCategory::CapabilityUnsupported)?;
            }
            Ok(())
        })
    }
}
enum RunOwner {
    Cli,
    App(
        Arc<crate::app::HostScope>,
        Option<Arc<crate::release::VerifiedNativeRelease>>,
    ),
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    Service(Arc<crate::platform::native_service::ServiceScope>),
}
struct Admitted {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    service_scope: Option<Arc<crate::platform::native_service::ServiceScope>>,
    profile: Arc<profile::LoadedProfile>,
    state: PrivateRoot,
    base: PrivateRoot,
    lease: ExecutionLeaseGuard,
}
#[cfg(all(target_os = "linux", target_env = "gnu"))]
struct ServiceExecAdmission {
    admitted: Arc<Admitted>,
}
#[cfg(all(target_os = "linux", target_env = "gnu"))]
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
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        if let Some(scope) = &self.service_scope {
            // OS identity is stable across a desired-state commit. The profile
            // immediately below owns the full typed C07 admission decision.
            scope
                .validate_identity()
                .map_err(|_| ForegroundError("native_service_scope_changed"))?;
        }
        self.profile.validate_ownership(&self.state, &self.base)?;
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
    fn release_profile(&self, owner: &styx_core::operations::OwnerLease) {
        self.source.release_profile(owner);
    }

    fn prepare_profile(
        &self,
        owner: &styx_core::operations::OwnerLease,
        scope: crate::host::browser_extension::CdpSessionScope,
    ) -> Result<crate::providers::browser::OwnedBrowserConfig, styx_contracts::error::ErrorCategory>
    {
        self.source.prepare_profile(owner, scope)
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
    let enabled = custody
        .read_before_source(Duration::from_secs(30), || {
            let retained = admitted.clone();
            async move {
                tokio::task::spawn_blocking(move || {
                    retained.profile.pin_cua_driver().map(|p| p.is_some())
                })
                .await
                .map_err(|_| ForegroundError("profile_reader_failed"))?
                .map_err(ForegroundError::from)
            }
        })
        .await?;
    if !enabled {
        return Ok(None);
    }
    #[cfg(target_os = "linux")]
    let source = {
        // A login service may precede the graphical session. Wait only for an
        // empty candidate set, before acquiring the sole original source.
        // Ambiguity and discovery errors never select or retry another desktop.
        let candidate = custody
            .desktop_candidate(Duration::from_secs(30), super::discover_desktop_candidates)
            .await?;
        crate::host::coordinator::DesktopSource::start(candidate)
            .await
            .map_err(|e| ForegroundError(e.code()))?
    };
    #[cfg(target_os = "windows")]
    let source = crate::host::coordinator::DesktopSource::start()
        .await
        .map_err(|_| ForegroundError("computer_native_session_unavailable"))?;
    custody.retain_source(source.clone());
    let mut grants = BTreeMap::new();
    grants.insert(
        CapabilityId::DesktopWindowsRead,
        crate::host::coordinator::DesktopGrant {
            configured: true,
            remote_grant: true,
            local_policy_allowed: true,
        },
    );
    let binding = match host
        .authority()
        .configure_desktop(source.clone(), grants)
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
    runtime_fault: Option<
        tokio::sync::watch::Sender<
            Option<(
                crate::providers::cua::probe_diagnostic::ProbeStage,
                crate::providers::cua::probe_diagnostic::ProbeCause,
            )>,
        >,
    >,
) -> Result<Option<Arc<dyn crate::host::protocol::computer::ComputerBootstrap>>, ForegroundError> {
    let enabled = custody
        .read_before_source(Duration::from_secs(30), || {
            let retained = admitted.clone();
            async move {
                tokio::task::spawn_blocking(move || retained.profile.computer_enabled())
                    .await
                    .map_err(|_| ForegroundError("profile_reader_failed"))?
                    .map_err(ForegroundError::from)
            }
        })
        .await?;
    if !enabled {
        return Ok(None);
    }
    // The App needs this Core's configured intent before publishing its Cua
    // descriptor. Wait only for absent publication, before retaining any source.
    // Invalid hints, dead owners, signature/peer failures and an acquired source
    // are never retried or replaced. Exec and lifecycle remain independently live.
    custody
        .read_before_source(Duration::from_secs(30), || async {
            use crate::providers::cua::macos_source::{BindingError, MacSourceCandidate};
            tokio::task::spawn_blocking(MacSourceCandidate::check_discovery_presence)
                .await
                .map_err(|_| ForegroundError("computer_bootstrap_failed"))?
                .map_err(|error| {
                    ForegroundError(match error {
                        BindingError::NotPublished => "desktop_session_not_ready",
                        _ => "desktop_source_unavailable",
                    })
                })
        })
        .await?;
    let source = crate::host::coordinator::DesktopSource::start_with_runtime_fault(runtime_fault)
        .await
        .map_err(|e| ForegroundError(e.code()))?;
    custody.retain_source(source.clone());
    let mut grants = BTreeMap::new();
    grants.insert(
        CapabilityId::DesktopWindowsRead,
        crate::host::coordinator::DesktopGrant {
            configured: true,
            remote_grant: true,
            local_policy_allowed: true,
        },
    );
    let binding = match host
        .authority()
        .configure_desktop(source.clone(), grants)
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
    #[cfg(target_os = "macos")]
    let refresh_started = std::time::Instant::now();
    host.coordinator()
        .refresh_desktop_source()
        .await
        .map_err(|_| {
            #[cfg(target_os = "macos")]
            source.remember_startup_coordinator_refusal(refresh_started);
            ForegroundError("computer_source_probe_failed")
        })?;
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
    _cancel: &CancellationToken,
    name: &'static str,
    device: &DeviceId,
    generation: Option<&ConnectionGeneration>,
) {
    event_with_reason(events, _cancel, name, device, generation, None);
}
fn event_with_reason(
    events: &mpsc::Sender<ForegroundEvent>,
    _cancel: &CancellationToken,
    name: &'static str,
    device: &DeviceId,
    generation: Option<&ConnectionGeneration>,
    reason: Option<&'static str>,
) {
    // These events are best-effort status observations, not execution authority.
    // A slow/closed event consumer must not terminate a healthy Host or its tasks.
    let _ = events.try_send(ForegroundEvent {
        schema: 1,
        event: name,
        reason,
        #[cfg(target_os = "macos")]
        computer_probe: None,
        device_id: Some(device.clone()),
        connection_generation: generation.cloned(),
    });
}
async fn validate(admitted: &Arc<Admitted>) -> Result<(), ForegroundError> {
    let retained = admitted.clone();
    tokio::task::spawn_blocking(move || retained.validate())
        .await
        .map_err(|_| ForegroundError("profile_reader_failed"))?
}
async fn connect(
    profile: &profile::LoadedProfile,
    generation: ConnectionGeneration,
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
        LinkError::UpgradeStatus(409 | 503) => ForegroundError("gateway_wss_unavailable"),
        LinkError::UpgradeStatus(_) | LinkError::HandshakeRejected => {
            ForegroundError("gateway_wss_upgrade_rejected")
        }
        LinkError::Deadline => ForegroundError("gateway_transport_deadline"),
        _ => ForegroundError("gateway_transport_refused"),
    })
}
fn retain_transport_outcome(
    previous: Option<crate::host::protocol::wire::TransportDrainOutcome>,
    current: crate::host::protocol::wire::TransportDrainOutcome,
) -> crate::host::protocol::wire::TransportDrainOutcome {
    use crate::host::protocol::wire::TransportDrainOutcome::{Complete, Unknown, Unsupported};
    match (previous, current) {
        (Some(Unknown), _) | (_, Unknown) => Unknown,
        (Some(Unsupported), _) | (_, Unsupported) => Unsupported,
        _ => Complete,
    }
}

#[cfg(test)]
mod connection_recovery_tests {
    use super::*;
    use crate::host::protocol::wire::TransportDrainOutcome::{Complete, Unknown, Unsupported};
    #[test]
    fn service_exit_after_reconnection_keeps_remote_unknown_but_accepts_local_cleanup() {
        let mut outcome = empty_outcome();
        outcome.remote_transport_drain = Some(retain_transport_outcome(Some(Unknown), Complete));
        assert!(outcome.local_stop_succeeded());
        assert!(!outcome.is_complete());
        let report = serde_json::to_value(&outcome).unwrap();
        assert_eq!(report["remote_transport_drain"], "unknown");
        // Each actual local cleanup fact is still required, independently of
        // the remote report and of a later successful connection.
        for missing in 0..4 {
            let mut incomplete = empty_outcome();
            incomplete.executor_started = true;
            incomplete.executor_exited = true;
            match missing {
                0 => incomplete.executor_exited = false,
                1 => incomplete.processes_exited = false,
                2 => incomplete.io_tasks_joined = false,
                _ => incomplete.supervised_jobs_joined = false,
            }
            assert!(!incomplete.local_stop_succeeded());
            assert_eq!(
                incomplete.local_runtime_joined(),
                missing == 1,
                "only missing command receipts can be left for the native service owner"
            );
        }
        outcome.stop_reason = Some("gateway_pairing_revoked");
        assert!(
            !outcome.local_stop_succeeded(),
            "actual runtime fault still fails"
        );
    }

    #[test]
    fn successful_new_link_cannot_clear_an_old_missing_receipt() {
        assert_eq!(retain_transport_outcome(Some(Unknown), Complete), Unknown);
        assert_eq!(retain_transport_outcome(Some(Complete), Unknown), Unknown);
        assert_eq!(
            retain_transport_outcome(Some(Unsupported), Complete),
            Unsupported
        );
        assert_eq!(retain_transport_outcome(None, Complete), Complete);
        assert_eq!(retain_transport_outcome(Some(Complete), Complete), Complete);
    }
    #[test]
    fn temporary_network_wait_is_not_authorization_to_retry_rejected_credentials_or_tls() {
        for code in [
            "gateway_connect_failed",
            "gateway_connect_timeout",
            "gateway_wss_unavailable",
        ] {
            assert!(retryable_connect_error(code));
        }
        for code in [
            "gateway_wss_admission_refused",
            "gateway_tls_handshake_rejected",
            "gateway_wss_request_rejected",
            "gateway_leaf_pin_mismatch",
        ] {
            assert!(!retryable_connect_error(code));
        }
    }
}

fn retryable_connect_error(code: &str) -> bool {
    matches!(
        code,
        "gateway_connect_timeout"
            | "gateway_connect_failed"
            | "gateway_tls_timeout"
            | "gateway_transport_deadline"
            | "gateway_wss_unavailable"
    )
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
        stop_reason: None,
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
    cancel: CancellationToken,
    events: mpsc::Sender<ForegroundEvent>,
) -> Result<ForegroundOutcome, ForegroundError> {
    let state = state_dir.to_path_buf();
    let stop = cancel.child_token();
    // A caller timeout/aborted waiter signals the owned worker instead of dropping
    // its lease, pinned payload or native supervisor. Tokio detaches the worker
    // JoinHandle on waiter drop; the running runtime must remain alive for cleanup.
    let _cancel_on_waiter_drop = stop.clone().drop_guard();
    tokio::spawn(async move {
        run_owned(
            &state,
            stop,
            events,
            RunOwner::Cli,
            #[cfg(target_os = "macos")]
            None,
        )
        .await
    })
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
    #[cfg(target_os = "macos")] runtime_fault: tokio::sync::watch::Sender<
        Option<(
            crate::providers::cua::probe_diagnostic::ProbeStage,
            crate::providers::cua::probe_diagnostic::ProbeCause,
        )>,
    >,
) -> Result<ForegroundOutcome, ForegroundError> {
    let state = scope.state_dir().to_owned();
    let stop = cancel.child_token();
    let _cancel_on_waiter_drop = stop.clone().drop_guard();
    tokio::spawn(async move {
        run_owned(
            &state,
            stop,
            events,
            RunOwner::App(scope, verified_runtime),
            #[cfg(target_os = "macos")]
            Some(runtime_fault),
        )
        .await
    })
    .await
    .map_err(|_| ForegroundError("foreground_worker_failed"))?
}
#[cfg(all(target_os = "linux", target_env = "gnu"))]
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
    tokio::spawn(async move { run_owned(&path, stop, events, RunOwner::Service(scope)).await })
        .await
        .map_err(|_| ForegroundError("foreground_worker_failed"))?
}
async fn run_owned(
    state_dir: &Path,
    cancel: CancellationToken,
    events: mpsc::Sender<ForegroundEvent>,
    owner: RunOwner,
    #[cfg(target_os = "macos")] runtime_fault: Option<
        tokio::sync::watch::Sender<
            Option<(
                crate::providers::cua::probe_diagnostic::ProbeStage,
                crate::providers::cua::probe_diagnostic::ProbeCause,
            )>,
        >,
    >,
) -> Result<ForegroundOutcome, ForegroundError> {
    // Independent foreground-run clock. Opt-in closed labels carry no profile,
    // path or credential data and never participate in admission decisions.
    let settings_scope = match &owner {
        RunOwner::App(scope, _) => Some(scope.clone()),
        _ => None,
    };
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
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        let service_scope = match &owner {
            RunOwner::Service(scope) => Some(scope.clone()),
            _ => None,
        };
        let profile = match owner {
            RunOwner::App(scope, Some(runtime)) => profile::load_for_app_retained(scope, runtime)?,
            RunOwner::App(scope, None) => profile::load_for_app(scope)?,
            RunOwner::Cli => profile::load_paired(&path)?,
            #[cfg(all(target_os = "linux", target_env = "gnu"))]
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
            #[cfg(all(target_os = "linux", target_env = "gnu"))]
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
    let reservation = OwnedExecHost::reserve(generation.clone(), facts(&device))
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
        if retained.profile.exec_selected() {
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
        .spawn_optional_pinned(
            config,
            admitted
                .profile
                .executor_image()
                .filter(|_| admitted.profile.exec_selected()),
        )
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
    let settings = admitted.profile.settings();
    if let Some(settings) = &settings {
        settings
            .attach(Arc::new(LocalCapabilityRuntime {
                admitted: admitted.clone(),
                host: host.clone(),
            }))
            .map_err(|_| ForegroundError("host_settings_configuration_failed"))?;
        if let Some(scope) = &settings_scope {
            scope.publish_settings(settings);
        }
    }
    #[cfg(not(target_os = "android"))]
    let browser_extension = match crate::host::browser_extension::BrowserExtensionBridge::start(
        admitted.profile.host_base_dir(),
    )
    .await
    {
        Ok(bridge) => {
            if let Some(scope) = &settings_scope {
                scope.publish_browser_extension(&bridge);
            }
            Some(bridge)
        }
        Err(_) => None,
    };
    // Install before exposing any paired connection. A failed installation
    // follows the same owned Host cleanup below; never early-drop the executor.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    let exec_admission_ready = if admitted.service_scope.is_some() {
        host.authority()
            .configure_exec_admission(Arc::new(ServiceExecAdmission {
                admitted: admitted.clone(),
            }))
            .is_ok()
    } else {
        true
    };
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    let exec_admission_ready = true;
    // Browser is an independent optional local capability. Unsupported or
    // unavailable Browser inputs cannot take down an already admitted Exec Host.
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    let browser: Option<Arc<dyn crate::host::protocol::browser::BrowserBootstrap>> = {
        let retained = admitted.clone();
        let ext = browser_extension.clone();
        let source = tokio::task::spawn_blocking(move || {
            retained.validate_ownership().map_err(|_| {
                super::browser::BrowserPreparationError::new(
                    "ownership",
                    styx_contracts::error::ErrorCategory::StateConflict,
                )
            })?;
            super::browser::prepare_browser_bootstrap(retained.profile.clone(), ext)
        })
        .await;
        match source {
            Ok(Ok(Some(source))) => {
                let mut browser_facts = facts(&device);
                browser_facts.descriptor.capability_id = CapabilityId::Browser;
                browser_facts.descriptor.scope = Scope::Browser;
                browser_facts.descriptor.provider_id =
                    "playwright".try_into().expect("static provider identity");
                match host.authority().configure_browser(browser_facts) {
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
    };
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    let mut computer = computer_startup::ComputerStartup::start(
        admitted.clone(),
        host.clone(),
        events.clone(),
        device.clone(),
        cancel.clone(),
        #[cfg(target_os = "macos")]
        runtime_fault,
    );
    // Keep this SAME protocol and executor across transport reconnects. In v3,
    // per-chat owner admission comes only from the authenticated fixed Gateway;
    // loading a device credential does not register a bootstrap MCP owner.
    let session = if !exec_admission_ready {
        Err(ForegroundError(
            "native_service_admission_configuration_failed",
        ))
    } else {
        let protocol = host.paired_protocol(PairedTrustedProfile {
            endpoint: admitted.profile.endpoint().as_str().to_owned(),
            gateway_namespace: admitted.profile.paired_gateway_namespace(),
            device_id: device.clone(),
            host_generation: generation,
        });
        let protocol = protocol.map(|protocol| {
            let protocol =
                protocol.with_command_environment(admitted.profile.command_environment());
            if let Some(settings) = &settings {
                protocol.with_settings(settings.clone())
            } else {
                protocol
            }
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
            let protocol = protocol.with_computer_profiles(computer.factory())?;
            Ok(protocol)
        });
        protocol.map_err(|_| ForegroundError("paired_bootstrap_refused"))
    };
    let mut failure = None;
    // No remote transport exists until after the local signed inputs, executor
    // and optional providers are ready. Local failure still settles this host.
    let mut remote_transport_drain = None;
    let mut settled_transports = None;
    match session {
        Ok(session) => {
            let initial = loop {
                if cancel.is_cancelled() {
                    break Ok(None);
                }
                let connection: ConnectionGeneration = uuid::Uuid::new_v4()
                    .to_string()
                    .try_into()
                    .expect("UUID identity");
                event(&events, &cancel, "connecting", &device, Some(&connection));
                let attempt = tokio::select! {
                    _=cancel.cancelled()=>break Ok(None),
                    result=connect(&admitted.profile,connection)=>result,
                };
                match attempt {
                    Ok(link) => break Ok(Some(link)),
                    Err(error) if retryable_connect_error(error.code()) => {
                        // No protocol/business request has been dispatched. Reuse
                        // this original Host; each authenticated link has a fresh
                        // generation. Never retry a native action or weaken TLS.
                        event_with_reason(
                            &events,
                            &cancel,
                            "disconnected",
                            &device,
                            None,
                            Some(error.code()),
                        );
                        tokio::select! {
                            _=cancel.cancelled()=>break Ok(None),
                            _=tokio::time::sleep(Duration::from_secs(2))=>{},
                        }
                        if let Err(error) = validate(&admitted).await {
                            match error.code() {
                                "native_service_configuration_pending" => continue,
                                "native_service_stop_requested" => break Ok(None),
                                _ => break Err(error),
                            }
                        }
                    }
                    Err(error) => break Err(error),
                }
            };
            match initial {
                Ok(Some(mut link)) => {
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
                                    #[cfg(all(target_os = "linux", target_env = "gnu"))]
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
                                    #[cfg(any(
                                        target_os = "linux",
                                        target_os = "windows",
                                        target_os = "macos"
                                    ))]
                                    let _ = session.park_idle_browser_sessions().await;
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

                        let observed =
                            result.as_ref().ok().copied().flatten().unwrap_or(
                                crate::host::protocol::wire::TransportDrainOutcome::Unknown,
                            );
                        let retained = retain_transport_outcome(settled_transports, observed);
                        settled_transports = Some(retained);
                        remote_transport_drain = Some(retained);

                        if matches!(
                            &result,
                            Err(crate::host::protocol::ProtocolError::PairingRevoked)
                        ) {
                            failure = Some(ForegroundError("gateway_pairing_revoked"));
                            cancel.cancel();
                        }
                        let disconnected = if cancel.is_cancelled() {
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
                            #[cfg(any(
                                target_os = "linux",
                                target_os = "windows",
                                target_os = "macos"
                            ))]
                            let _ = session.park_idle_browser_sessions().await;
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
                                result=connect(&admitted.profile,generation)=>result,
                            };
                            match attempt {
                                Ok(v) => {
                                    next = Some(v);
                                    break;
                                }
                                Err(error) if !retryable_connect_error(error.code()) => {
                                    failure = Some(error);
                                    break;
                                }
                                Err(error) => event_with_reason(
                                    &events,
                                    &cancel,
                                    "disconnected",
                                    &device,
                                    None,
                                    Some(error.code()),
                                ),
                            }
                        }
                        let Some(connected) = next else {
                            break;
                        };
                        link = connected;
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    event_with_reason(
                        &events,
                        &cancel,
                        "disconnected",
                        &device,
                        None,
                        Some(error.code()),
                    );
                    failure = Some(error);
                }
            }
            // Same original input jobs remain owned through every link failure.
            #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
            {
                session.drain_browser_inputs().await;
                session.drain_computer_inputs().await;
            }
        }
        Err(error) => failure = Some(error),
    }
    if let Some(settings) = &settings {
        settings.close().await;
    }
    #[cfg(not(target_os = "android"))]
    if let Some(ext) = &browser_extension {
        ext.shutdown().await;
    }
    event(&events, &cancel, "stopping", &device, None);
    let mut outcome = ForegroundOutcome {
        schema: 1,
        stop_reason: failure.as_ref().map(ForegroundError::code),
        executor_started: host.coordinator().exec_configured(),
        executor_exited: false,
        processes_exited: false,
        io_tasks_joined: false,
        supervised_jobs_joined: false,
        remote_transport_drain,
    };
    let mut process_exits = BTreeMap::new();
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    computer.close_admission();

    // Retain the original owner until its executor, I/O and local jobs end.
    // A Linux service can then return missing command receipts unchanged:
    // systemd owns final descendant cleanup and the external stop observes it.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    let service_shutdown_deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut last_cleanup_reason = "cleanup_incomplete";
    loop {
        let mut desktop_cleanup_complete = true;
        let mut browser_cleanup_complete = true;
        let mut exec_io_joined = true;
        match host.shutdown_owned(Duration::from_secs(10)).await {
            Ok(cleanup) => {
                if let Some(native) = &cleanup.native {
                    for (process, evidence) in &native.processes {
                        record_process_exit(
                            &mut process_exits,
                            process.operation().clone(),
                            *evidence,
                        );
                    }
                    outcome.executor_exited |= native.executor_exited;
                    exec_io_joined = native.reader_task_reaped && native.stderr_task_reaped;
                }
                #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
                {
                    browser_cleanup_complete =
                        cleanup.browser.as_ref().is_none_or(|facts| facts.complete);
                    desktop_cleanup_complete =
                        cleanup.desktop.as_ref().is_none_or(|facts| facts.complete);
                }
                outcome.processes_exited = process_exits.values().all(|exited| *exited)
                    && cleanup.ancillary_providers_settled();
                outcome.io_tasks_joined = exec_io_joined && cleanup.ancillary_providers_settled();
                outcome.supervised_jobs_joined = cleanup.supervised_jobs_joined;
            }
            Err(_) => {
                last_cleanup_reason = "shutdown_lock_busy";
            }
        }
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        let computer_settle_complete = {
            // Exec shutdown happens independently, while desktop initialization
            // and its original source stay retained until real join/stop facts.
            let complete = computer
                .settle(tokio::time::Instant::now() + Duration::from_secs(1))
                .await;
            outcome.supervised_jobs_joined &= complete;
            outcome.processes_exited &= complete;
            outcome.io_tasks_joined &= complete;
            complete
        };
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        let computer_settle_complete = true;
        if outcome.local_stop_complete() {
            break;
        }
        let reason = cleanup_unknown_reason(
            &outcome,
            exec_io_joined,
            browser_cleanup_complete,
            desktop_cleanup_complete,
            computer_settle_complete,
            last_cleanup_reason,
        );
        event_with_reason(
            &events,
            &cancel,
            "cleanup_unknown",
            &device,
            None,
            Some(reason),
        );
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        if service_shutdown_should_break(
            admitted.service_scope.is_some(),
            &outcome,
            tokio::time::Instant::now() >= service_shutdown_deadline,
        ) {
            // RPC is already closed. Waiting again cannot recover a lost task
            // exit receipt or unrecoverable join failure, and keeps systemd from
            // finishing the same cgroup under TimeoutStopSec=infinity.
            break;
        }
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
    // Preserve the actual local cleanup even when admission or transport ended
    // the runtime. Callers report stop_reason separately from cleanup evidence.
    Ok(outcome)
}

#[cfg(any(all(target_os = "linux", target_env = "gnu"), test))]
fn service_shutdown_should_break(
    has_service_scope: bool,
    outcome: &ForegroundOutcome,
    deadline_reached: bool,
) -> bool {
    has_service_scope && (outcome.local_runtime_joined() || deadline_reached)
}

/// Classify the unsettled cleanup cause as a fixed category without dynamic details.
fn cleanup_unknown_reason(
    outcome: &ForegroundOutcome,
    exec_io_joined: bool,
    browser_cleanup_complete: bool,
    desktop_cleanup_complete: bool,
    computer_settle_complete: bool,
    fallback: &'static str,
) -> &'static str {
    if outcome.executor_started && !outcome.executor_exited {
        "executor_running"
    } else if !exec_io_joined {
        "exec_io_unjoined"
    } else if !browser_cleanup_complete {
        "browser_cleanup_incomplete"
    } else if !desktop_cleanup_complete {
        "desktop_cleanup_incomplete"
    } else if !computer_settle_complete {
        "computer_startup_incomplete"
    } else if !outcome.supervised_jobs_joined {
        "supervised_jobs_running"
    } else if !outcome.io_tasks_joined {
        "io_tasks_unjoined"
    } else if !outcome.processes_exited {
        "processes_remaining"
    } else {
        fallback
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
    fn full_or_closed_status_channel_does_not_cancel_host_work() {
        let (events, receiver) = mpsc::channel(1);
        let stop = CancellationToken::new();
        let device: DeviceId = "telemetry-test-device".to_owned().try_into().unwrap();
        event(&events, &stop, "connected", &device, None);
        event(&events, &stop, "reconnecting", &device, None);
        assert!(
            !stop.is_cancelled(),
            "a full status channel is not a Host stop"
        );
        drop(receiver);
        event(&events, &stop, "disconnected", &device, None);
        assert!(
            !stop.is_cancelled(),
            "a closed status channel is not a Host stop"
        );
    }
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
        assert!(outcome.local_runtime_joined());
        assert!(!outcome.local_stop_complete());
        assert!(!outcome.local_stop_succeeded());
        assert_eq!(
            serde_json::to_value(&outcome).unwrap()["processes_exited"],
            false
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
    #[test]
    fn cleanup_unknown_reason_classifies_unsettled_lanes_and_bounds_service_shutdown() {
        let mut outcome = empty_outcome();
        outcome.executor_started = true;
        assert_eq!(
            cleanup_unknown_reason(&outcome, true, true, true, true, "fallback"),
            "executor_running"
        );
        assert!(!service_shutdown_should_break(true, &outcome, false));
        assert!(service_shutdown_should_break(true, &outcome, true));
        assert!(!service_shutdown_should_break(false, &outcome, true));

        outcome.executor_exited = true;
        assert_eq!(
            cleanup_unknown_reason(&outcome, false, true, true, true, "fallback"),
            "exec_io_unjoined"
        );
        assert_eq!(
            cleanup_unknown_reason(&outcome, true, false, true, true, "fallback"),
            "browser_cleanup_incomplete"
        );
        assert_eq!(
            cleanup_unknown_reason(&outcome, true, true, false, true, "fallback"),
            "desktop_cleanup_incomplete"
        );
        assert_eq!(
            cleanup_unknown_reason(&outcome, true, true, true, false, "fallback"),
            "computer_startup_incomplete"
        );
        outcome.io_tasks_joined = false;
        assert!(service_shutdown_should_break(true, &outcome, true));
        assert!(!outcome.local_runtime_joined());
    }
}

#[cfg(target_os = "macos")]
fn computer_unavailable_with_probe(
    events: &mpsc::Sender<ForegroundEvent>,
    _cancel: &CancellationToken,
    device: &DeviceId,
    reason: &'static str,
    computer_probe: Option<crate::providers::cua::probe_diagnostic::ProbeDiagnostic>,
) {
    // Missing diagnostic delivery is never a reason to cancel Exec/Browser.
    let _ = events.try_send(ForegroundEvent {
        schema: 1,
        event: "computer_unavailable",
        reason: Some(reason),
        computer_probe,
        device_id: Some(device.clone()),
        connection_generation: None,
    });
}
