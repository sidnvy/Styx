//! Existing-only, current-user Gateway foreground composition. Configuration
//! evidence is not a migration grant; legacy ownership is conservatively refused.
use super::{ForegroundError, ForegroundEvent};
use serde::Serialize;
use std::path::Path;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

#[derive(Serialize)]
pub struct GatewayForegroundOutcome {
    pub schema: u32,
    pub connections_joined: bool,
    pub blocking_jobs_joined: bool,
    pub mcp_lifecycle_jobs_joined: bool,
    pub mcp_session_transports_joined: bool,
    pub unconfirmed_owner_cleanups: usize,
    pub unconfirmed_transport_drains: usize,
    pub sdk_detached_tasks_joined: Option<bool>,
    pub worker_failure_observed: bool,
    pub listener_error_observed: bool,
}
impl GatewayForegroundOutcome {
    /// Tracked Styx work only. The SDK's unavailable detached-task join remains
    /// explicitly None, never a claim that all SDK internals were joined.
    pub fn local_stop_complete(&self) -> bool {
        self.connections_joined
            && self.blocking_jobs_joined
            && self.mcp_lifecycle_jobs_joined
            && self.mcp_session_transports_joined
    }
    pub fn is_complete(&self) -> bool {
        self.local_stop_complete()
            && self.unconfirmed_owner_cleanups == 0
            && self.unconfirmed_transport_drains == 0
            && !self.worker_failure_observed
            && !self.listener_error_observed
    }
}

pub async fn gateway_run(
    state_dir: &Path,
    cancel: CancellationToken,
    events: mpsc::Sender<ForegroundEvent>,
) -> Result<GatewayForegroundOutcome, ForegroundError> {
    #[cfg(any(
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
        all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"),
        all(
            target_os = "macos",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    {
        let path = state_dir.to_path_buf();
        let stop = cancel.child_token();
        // Dropped response waiters request stop, not release of the owned task's
        // execution/configuration leases. The runtime must remain alive to join.
        let _waiter = stop.clone().drop_guard();
        tokio::spawn(async move {
            platform::run(
                path,
                stop,
                events,
                None,
                None,
                (None, None),
                #[cfg(any(
                    all(target_os = "linux", target_env = "gnu"),
                    target_os = "macos",
                    target_os = "windows"
                ))]
                None,
            )
            .await
        })
        .await
        .map_err(|_| ForegroundError("gateway_foreground_worker_failed"))?
    }
    #[cfg(not(any(
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
        all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"),
        all(
            target_os = "macos",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )))]
    {
        let _ = (state_dir, cancel, events);
        Err(ForegroundError("gateway_foreground_platform_unsupported"))
    }
}

/// Service admission comes only from the authenticated original OS unit.
#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "macos",
    target_os = "windows"
))]
pub(crate) async fn gateway_run_for_service(
    scope: std::sync::Arc<crate::platform::native_service::ServiceScope>,
    cancel: CancellationToken,
    events: mpsc::Sender<ForegroundEvent>,
) -> Result<GatewayForegroundOutcome, ForegroundError> {
    scope
        .validate()
        .map_err(|_| ForegroundError("service_scope_changed"))?;
    let path = scope.state_dir().to_owned();
    let stop = cancel.child_token();
    let _waiter = stop.clone().drop_guard();
    tokio::spawn(async move {
        platform::run(path, stop, events, None, None, (None, None), Some(scope)).await
    })
    .await
    .map_err(|_| ForegroundError("gateway_foreground_worker_failed"))?
}

/// An App startup failure owns any unsettled bootstrap writer and its original
/// App scope. The App must retain this value until its teardown; reporting the
/// static code alone is not settlement evidence.
#[must_use]
pub(crate) struct AppGatewayError {
    foreground: ForegroundError,
    _retained: Option<AppStartupOwner>,
}
enum AppStartupOwner {
    Fresh(crate::management::native_gateway::BootstrapError),
}
impl AppStartupOwner {
    fn code(&self) -> &'static str {
        match self {
            Self::Fresh(error) => error.code(),
        }
    }
}
impl AppGatewayError {
    pub(crate) fn code(&self) -> &'static str {
        self.foreground.code()
    }
}
impl std::fmt::Debug for AppGatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("AppGatewayError")
            .field(&self.code())
            .finish()
    }
}
impl std::fmt::Display for AppGatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for AppGatewayError {}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
    all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"),
    all(
        target_os = "macos",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
// One startup loader and one error slot per original run, with no backpointer
// from HostScope. This transports ownership, not new domain/recovery state.
type AppStartupFailure = std::sync::Arc<std::sync::Mutex<Option<AppStartupOwner>>>;

/// Owned native App role. Scope cannot be constructed from RPC data. The worker
/// retains it through original blocking work and Gateway settlement.
pub(crate) async fn gateway_run_for_app(
    scope: std::sync::Arc<crate::app::HostScope>,
    cancel: CancellationToken,
    events: mpsc::Sender<ForegroundEvent>,
    diagnostic: Option<crate::management::native_gateway::StartupDiagnostic>,
    retained_candidate: Option<std::sync::Arc<crate::release::VerifiedNativeRelease>>,
) -> Result<GatewayForegroundOutcome, AppGatewayError> {
    #[cfg(any(
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
        all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"),
        all(
            target_os = "macos",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    {
        let path = scope.state_dir().to_owned();
        let stop = cancel.child_token();
        let _waiter = stop.clone().drop_guard();
        let failure: AppStartupFailure = Default::default();
        let loader_failure = failure.clone();
        let terminal_diagnostic = diagnostic.clone();
        let result = tokio::spawn(async move {
            platform::run(
                path,
                stop,
                events,
                Some(scope),
                Some(loader_failure),
                (diagnostic, retained_candidate),
                #[cfg(any(
                    all(target_os = "linux", target_env = "gnu"),
                    target_os = "macos",
                    target_os = "windows"
                ))]
                None,
            )
            .await
        })
        .await
        .unwrap_or(Err(ForegroundError("gateway_foreground_worker_failed")));
        // run awaits its original blocking loader. Only after that run has
        // actually joined may ownership pass from the slot to the App result.
        if let Some(d) = terminal_diagnostic {
            d.report(if result.is_ok() {
                "worker_complete"
            } else {
                "worker_failed"
            });
        }
        let retained = failure.lock().unwrap_or_else(|e| e.into_inner()).take();
        match (result, retained) {
            (Ok(outcome), None) => Ok(outcome),
            (Err(foreground), retained) => Err(AppGatewayError {
                foreground,
                _retained: retained,
            }),
            (Ok(_), Some(retained)) => Err(AppGatewayError {
                foreground: ForegroundError(retained.code()),
                _retained: Some(retained),
            }),
        }
    }
    #[cfg(not(any(
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
        all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"),
        all(
            target_os = "macos",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )))]
    {
        let _ = (scope, cancel, events, diagnostic, retained_candidate);
        Err(AppGatewayError {
            foreground: ForegroundError("gateway_foreground_platform_unsupported"),
            _retained: None,
        })
    }
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
    all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"),
    all(
        target_os = "macos",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
pub(crate) use platform::StartupTransportClosure;

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
    all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"),
    all(
        target_os = "macos",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod platform {
    use super::*;
    use crate::{
        enrollment::{http::EnrollmentHttp, service::EnrollmentService, shared::SharedEnrollment},
        gateway::{
            auth::GatewayBearerPolicy,
            http::{GatewayHttp, HttpBudget},
            paired::{PairedGatewayBackend, RelayHandle},
        },
        store::{
            ExecutionLeaseGuard, OwnedConfigurationRoot, PrivateRoot,
            enrollment::{JournalBudget, OwnedEnrollmentJournal},
        },
        tls::GatewayServerTls,
    };
    use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
    use styx_contracts::identity::{GatewayEpoch, GatewayId, Sha256Digest};
    use styx_core::enrollment::Limits;
    use tokio::{net::TcpListener, sync::Semaphore};

    static LOADERS: Semaphore = Semaphore::const_new(2);
    struct Admitted {
        lease: ExecutionLeaseGuard,
        // Retains the SAME writer even if service boot fails after uncertain I/O.
        _configuration: OwnedConfigurationRoot,
        address: SocketAddr,
        fresh: Option<crate::management::native_gateway::FreshGatewayRuntime>,
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "macos",
            target_os = "windows"
        ))]
        control_gate: std::sync::Mutex<()>,
    }
    /// One-shot bootstrap evidence for this exact cooperating Rust foreground
    /// scope. Not proof that a legacy writer stopped or a remote process exited.
    /// The private borrow cannot outlive the actual execution/configuration owner.
    pub(crate) struct StartupTransportClosure<'a> {
        admitted: &'a Admitted,
    }
    impl StartupTransportClosure<'_> {
        pub(crate) fn validate_for(
            &self,
            owner: &OwnedConfigurationRoot,
        ) -> Result<(), ForegroundError> {
            if !self.admitted._configuration.same_authority(owner) {
                return Err(error("gateway_startup_authority_mismatch"));
            }
            self.admitted.validate()?;
            owner
                .ensure_admission()
                .map_err(|_| error("gateway_startup_admission_unproven"))
        }
    }
    impl Admitted {
        fn validate(&self) -> Result<(), ForegroundError> {
            #[cfg(any(
                all(target_os = "linux", target_env = "gnu"),
                target_os = "macos",
                target_os = "windows"
            ))]
            let _gate = self
                .control_gate
                .lock()
                .map_err(|_| error("service_control_unknown"))?;
            self.validate_inner()
        }
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "macos",
            target_os = "windows"
        ))]
        fn service_tip_status(&self) -> Result<(), crate::store::native_live_tip::LiveTipError> {
            if let Some(fresh) = &self.fresh {
                fresh.service_tip_status()
            } else {
                Ok(())
            }
        }
        fn validate_inner(&self) -> Result<(), ForegroundError> {
            if let Some(fresh) = &self.fresh {
                fresh.validate().map_err(|e| error(e.code()))?;
                if !fresh
                    .configuration_root()
                    .same_authority(&self._configuration)
                {
                    return Err(error("fresh_gateway_configuration_changed"));
                }
            } else {
                return Err(error("fresh_native_gateway_required"));
            }
            self.lease
                .validate()
                .map_err(|_| error("execution_lease_changed"))?;
            Ok(())
        }
    }
    fn error(code: &'static str) -> ForegroundError {
        ForegroundError(code)
    }
    struct Loaded {
        admitted: Arc<Admitted>,
        service: EnrollmentService,
        tls: Arc<GatewayServerTls>,
        policy: Arc<GatewayBearerPolicy>,
        host: String,
        gateway_id: GatewayId,
    }
    fn load(path: &Path) -> Result<Loaded, ForegroundError> {
        if !path.is_absolute() {
            return Err(error("absolute_state_directory_required"));
        }
        let state = Arc::new(PrivateRoot::open(path).map_err(|_| error("gateway_protected_read"))?);
        // Select the explicit native reader before touching legacy layout.
        // Any malformed/present ready material stays on the fresh reader path;
        // failure must never fall back to the legacy or migrated authority.
        let native = state.ensure_absent(".styx-native-root-v1.json").is_err();
        if native && state.ensure_absent("gateway-ready-v1.json").is_err() {
            return load_fresh(
                path,
                None,
                None,
                None,
                None,
                #[cfg(any(
                    all(target_os = "linux", target_env = "gnu"),
                    target_os = "macos",
                    target_os = "windows"
                ))]
                None,
            );
        }
        Err(error("fresh_native_gateway_required"))
    }
    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "macos",
        target_os = "windows"
    ))]
    fn load_service(
        path: &Path,
        scope: Arc<crate::platform::native_service::ServiceScope>,
    ) -> Result<Loaded, ForegroundError> {
        scope
            .validate()
            .map_err(|_| error("service_scope_changed"))?;
        if scope.state_dir() != path
            || scope.role() != crate::platform::native_service::ServiceRole::Gateway
        {
            return Err(error("service_scope_changed"));
        }
        let state = Arc::new(PrivateRoot::open(path).map_err(|_| error("gateway_protected_read"))?);
        if state.ensure_absent("gateway-ready-v1.json").is_err() {
            return load_fresh(path, None, None, None, None, Some(scope));
        }
        Err(error("service_native_gateway_required"))
    }
    fn load_app(
        path: &Path,
        scope: Arc<crate::app::HostScope>,
        failure: Option<AppStartupFailure>,
        diagnostic: Option<&crate::management::native_gateway::StartupDiagnostic>,
        retained_candidate: Option<Arc<crate::release::VerifiedNativeRelease>>,
    ) -> Result<Loaded, ForegroundError> {
        if scope.state_dir() != path {
            return Err(error("app_scope_changed"));
        }
        scope.validate().map_err(|_| error("app_scope_changed"))?;
        load_fresh(
            path,
            Some(scope),
            failure,
            diagnostic,
            retained_candidate,
            #[cfg(any(
                all(target_os = "linux", target_env = "gnu"),
                target_os = "macos",
                target_os = "windows"
            ))]
            None,
        )
    }
    /// Fresh native startup retains the existing ready binding and the same
    /// configuration owner. No legacy-layout or migration proof is invented.
    fn load_fresh(
        path: &Path,
        app_scope: Option<Arc<crate::app::HostScope>>,
        app_failure: Option<AppStartupFailure>,
        diagnostic: Option<&crate::management::native_gateway::StartupDiagnostic>,
        retained_candidate: Option<Arc<crate::release::VerifiedNativeRelease>>,
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "macos",
            target_os = "windows"
        ))]
        service_scope: Option<Arc<crate::platform::native_service::ServiceScope>>,
    ) -> Result<Loaded, ForegroundError> {
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "macos",
            target_os = "windows"
        ))]
        let service_runtime =
            service_scope.map(crate::management::native_gateway::open_existing_for_service);
        #[cfg(not(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "macos",
            target_os = "windows"
        )))]
        let service_runtime: Option<
            Result<
                crate::management::native_gateway::FreshGatewayRuntime,
                crate::management::native_gateway::BootstrapError,
            >,
        > = None;
        let runtime = match service_runtime {
            Some(result) => result,
            None => match app_scope {
                Some(scope) => {
                    if scope.state_dir() != path {
                        return Err(error("app_scope_changed"));
                    }
                    crate::management::native_gateway::open_existing_for_app_diagnostic(
                        scope,
                        diagnostic,
                        retained_candidate,
                    )
                }
                None => crate::management::native_gateway::open_existing(path),
            },
        }
        .map_err(|e| {
            let foreground = error(e.code());
            if let Some(failure) = app_failure {
                // Exactly one open attempt in this run, so no prior failure can
                // be overwritten. Keep the original error, writer and scope.
                *failure.lock().unwrap_or_else(|e| e.into_inner()) =
                    Some(AppStartupOwner::Fresh(e));
            }
            foreground
        })?;
        let configuration = runtime.configuration_root();
        let authority = runtime
            .origin
            .strip_prefix("https://")
            .ok_or(error("gateway_origin_invalid"))?
            .to_owned();
        let policy = Arc::new(
            GatewayBearerPolicy::new(
                &runtime.model_token,
                vec![authority.clone()],
                vec![runtime.origin.clone()],
            )
            .map_err(|_| error("gateway_model_authority_invalid"))?,
        );
        let journal = OwnedEnrollmentJournal::from_configuration(
            configuration.clone(),
            JournalBudget::default(),
        )
        .map_err(|_| error("existing_native_enrollment_required"))?;
        let service = EnrollmentService::recover_existing(
            journal,
            &runtime.admin_token,
            Sha256Digest::of_bytes(&runtime.model_token),
            vec![authority.clone()],
            Limits::default(),
        )
        .map_err(|e| error(e.code()))?;
        let lease = runtime
            .root
            .try_execution_lease()
            .map_err(|_| error("gateway_execution_busy"))?;
        let gateway_id = format!(
            "paired.{}",
            Sha256Digest::of_bytes(runtime.origin.as_bytes()).to_hex()
        )
        .try_into()
        .map_err(|_| error("gateway_namespace_invalid"))?;
        let tls = runtime.tls.clone();
        let admitted = Arc::new(Admitted {
            lease,
            _configuration: configuration,
            #[cfg(any(
                all(target_os = "linux", target_env = "gnu"),
                target_os = "macos",
                target_os = "windows"
            ))]
            control_gate: std::sync::Mutex::new(()),
            address: runtime.address,
            fresh: Some(runtime),
        });
        admitted.validate()?;
        Ok(Loaded {
            admitted,
            service,
            tls,
            policy,
            host: authority,
            gateway_id,
        })
    }
    fn emit(events: &mpsc::Sender<ForegroundEvent>, stop: &CancellationToken, name: &'static str) {
        if events
            .try_send(ForegroundEvent {
                schema: 1,
                event: name,
                reason: None,
                device_id: None,
                connection_generation: None,
            })
            .is_err()
        {
            stop.cancel();
        }
    }
    enum Validation {
        Ready,
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "macos",
            target_os = "windows"
        ))]
        Pending,
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "macos",
            target_os = "windows"
        ))]
        StopRequested,
    }
    async fn validate_for_poll(admitted: Arc<Admitted>) -> Result<Validation, ForegroundError> {
        let permit = LOADERS
            .try_acquire()
            .map_err(|_| error("gateway_reader_busy"))?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            #[cfg(any(
                all(target_os = "linux", target_env = "gnu"),
                target_os = "macos",
                target_os = "windows"
            ))]
            {
                use crate::store::native_live_tip::LiveTipError;
                let _gate = admitted
                    .control_gate
                    .lock()
                    .map_err(|_| error("service_control_unknown"))?;
                match admitted.service_tip_status() {
                    Err(LiveTipError::Pending) => return Ok(Validation::Pending),
                    Err(LiveTipError::StopRequested) => return Ok(Validation::StopRequested),
                    Err(LiveTipError::Changed) => {
                        return Err(error("gateway_protected_input_changed"));
                    }
                    Ok(()) => (),
                }
                admitted.validate_inner()?;
            }
            #[cfg(not(any(
                all(target_os = "linux", target_env = "gnu"),
                target_os = "macos",
                target_os = "windows"
            )))]
            admitted.validate()?;
            Ok(Validation::Ready)
        })
        .await
        .map_err(|_| error("gateway_reader_failed"))?
    }
    async fn validate(admitted: Arc<Admitted>) -> Result<(), ForegroundError> {
        match validate_for_poll(admitted).await? {
            Validation::Ready => Ok(()),
            #[cfg(any(
                all(target_os = "linux", target_env = "gnu"),
                target_os = "macos",
                target_os = "windows"
            ))]
            Validation::Pending => Err(error("gateway_configuration_pending")),
            #[cfg(any(
                all(target_os = "linux", target_env = "gnu"),
                target_os = "macos",
                target_os = "windows"
            ))]
            Validation::StopRequested => Err(error("gateway_stop_requested")),
        }
    }
    pub(super) async fn run(
        path: PathBuf,
        stop: CancellationToken,
        events: mpsc::Sender<ForegroundEvent>,
        app_scope: Option<Arc<crate::app::HostScope>>,
        app_failure: Option<AppStartupFailure>,
        startup: (
            Option<crate::management::native_gateway::StartupDiagnostic>,
            Option<Arc<crate::release::VerifiedNativeRelease>>,
        ),
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "macos",
            target_os = "windows"
        ))]
        service_scope: Option<Arc<crate::platform::native_service::ServiceScope>>,
    ) -> Result<GatewayForegroundOutcome, ForegroundError> {
        let (diagnostic, retained_candidate) = startup;
        if retained_candidate.is_some() && app_scope.is_none() {
            return Err(error("app_scope_required_for_retained_gateway_runtime"));
        }
        let permit = LOADERS
            .try_acquire()
            .map_err(|_| error("gateway_reader_busy"))?;
        emit(&events, &stop, "gateway_loading");
        let Loaded {
            admitted,
            service,
            tls,
            policy,
            host,
            gateway_id,
        } = {
            #[cfg(any(
                all(target_os = "linux", target_env = "gnu"),
                target_os = "macos",
                target_os = "windows"
            ))]
            let loader_service = service_scope.clone();
            let loader_diagnostic = diagnostic.clone();
            if let Some(d) = &diagnostic {
                d.mark("load");
            }
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                #[cfg(any(
                    all(target_os = "linux", target_env = "gnu"),
                    target_os = "macos",
                    target_os = "windows"
                ))]
                if let Some(scope) = loader_service {
                    return load_service(&path, scope);
                }
                match app_scope {
                    Some(scope) => load_app(
                        &path,
                        scope,
                        app_failure,
                        loader_diagnostic.as_ref(),
                        retained_candidate,
                    ),
                    None => load(&path),
                }
            })
            .await
            .map_err(|_| error("gateway_reader_failed"))??
        };
        if stop.is_cancelled() {
            return Err(error("gateway_start_cancelled"));
        }
        if let Some(d) = &diagnostic {
            d.mark("load_done");
        }
        // Before any new transport authority exists, reconcile only startup
        // RecoveredUnknown lanes under the exact held owner. All protected reads
        // stay on a bounded blocking worker, with its permit held until exit.
        let checked = admitted.clone();
        let permit = LOADERS
            .try_acquire()
            .map_err(|_| error("gateway_reader_busy"))?;
        if let Some(d) = &diagnostic {
            d.mark("reconcile");
        }
        let service = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut service = service;
            service
                .reconcile_recovered_foreground_transports(StartupTransportClosure {
                    admitted: &checked,
                })
                .map_err(|e| error(e.code()))?;
            Ok::<_, ForegroundError>(service)
        })
        .await
        .map_err(|_| error("gateway_reader_failed"))??;
        if stop.is_cancelled() {
            return Err(error("gateway_start_cancelled"));
        }
        if let Some(d) = &diagnostic {
            d.mark("reconcile_done");
        }
        let shared = SharedEnrollment::new(service);
        let partition = Arc::new(Semaphore::new(styx_contracts::HOST_QUEUED_BYTES));
        // Preserve the MCP32MiB allocation and use the previously unreserved
        //16MiB for a second Host link. Both partitions still share the original
        //64MiB queue budget; no per-link limit or authentication is relaxed.
        let relay = RelayHandle::new(
            shared.clone(),
            gateway_id,
            GatewayEpoch::try_from(format!("gateway-{}", uuid::Uuid::new_v4()))
                .map_err(|_| error("gateway_epoch_invalid"))?,
            partition
                .clone()
                .try_acquire_many_owned(32 * 1024 * 1024)
                .map_err(|_| error("gateway_partition_unavailable"))?,
        )
        .map_err(|_| error("gateway_relay_invalid"))?;
        let backend = Arc::new(PairedGatewayBackend::new(relay.clone(), None));
        let budget = HttpBudget::from_reserved_partition(
            partition
                .clone()
                .try_acquire_many_owned(32 * 1024 * 1024)
                .map_err(|_| error("gateway_partition_unavailable"))?,
        )
        .map_err(|_| error("gateway_partition_invalid"))?;
        let mcp = GatewayHttp::new(policy, backend, budget);
        let mcp_stop = mcp.paired_shutdown_handle();
        let app = EnrollmentHttp::new_paired(tls, shared.clone(), relay.clone(), mcp, vec![host])
            .map_err(|_| error("gateway_listener_configuration_invalid"))?;
        if let Some(d) = &diagnostic {
            d.mark("bind");
        }
        let listener = TcpListener::bind(admitted.address)
            .await
            .map_err(|_| error("gateway_listen_failed"))?;
        if let Some(d) = &diagnostic {
            d.mark("prelisten_validate");
        }
        validate(admitted.clone()).await?;
        if let Some(d) = &diagnostic {
            d.mark("prelisten_validate_done");
        }
        if stop.is_cancelled() {
            return Err(error("gateway_start_cancelled"));
        }
        let control_failed = CancellationToken::new();
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "macos",
            target_os = "windows"
        ))]
        let control = if let Some(scope) = service_scope {
            use crate::management::service_control::{
                ControlServer, Handler, ServiceControlError, ServiceControlReport, ServiceRequest,
            };
            use futures_util::FutureExt;
            if let Some(fresh) = &admitted.fresh {
                fresh
                    .enable_service_control(scope.clone())
                    .map_err(|e| error(e.code()))?;
            }
            let transactions = admitted
                .fresh
                .as_ref()
                .ok_or_else(|| error("service_native_required"))?
                .service_transactions();
            let checked = admitted.clone();
            let authority = shared.clone();
            let original_scope = scope.clone();
            let original_stop = stop.clone();
            let handler: Handler = Arc::new(move |request| {
                let checked = checked.clone();
                let authority = authority.clone();
                let transactions = transactions.clone();
                let scope = original_scope.clone();
                let stop = original_stop.clone();
                async move {
                    authority.service_control(move |service| {
                        let _gate=checked.control_gate.lock().map_err(|_| ServiceControlError::new("service_control_unknown"))?;
                        scope.validate().map_err(|_| ServiceControlError::new("service_scope_changed"))?;
                        let owner=service.service_control_owner();
                        if !owner.same_authority(&checked._configuration) { return Err(ServiceControlError::new("service_control_owner_changed")); }
                        if matches!(&request, ServiceRequest::SetAutostart {..} | ServiceRequest::SetStopped {..} | ServiceRequest::SetRunning {..}) {
                            checked.validate_inner().map_err(|_| ServiceControlError::new("service_control_inputs_changed"))?;
                        }
                        let mut tx=transactions.lock().map_err(|_| ServiceControlError::new("service_control_unknown"))?;
                        match request {
                            ServiceRequest::SetAutostart {component,enabled,expected_revision,transaction_id,..} => {
                                let (commit,revision)=tx.set_service_autostart(&owner,component.into(),enabled,expected_revision,transaction_id)
                                    .map_err(|_| ServiceControlError::new("service_control_unknown_inspect_transaction"))?;
                                // validate_inner may read this same coordinator; release its lock first.
                                drop(tx);
                                checked.validate_inner().map_err(|_| ServiceControlError::new("service_control_unknown_inspect_transaction"))?;
                                Ok(ServiceControlReport {schema:1,transaction_id:commit.transaction_id,revision,canonical_raw_sha256:commit.canonical_raw_sha256,status:"committed".into(),state_scope:"committed_target".into()})
                            }
                            ServiceRequest::SetStopped {component,expected_revision,transaction_id,..} => {
                                let gateway = matches!(component, crate::management::service_control::Component::Gateway);
                                let result=tx.set_service_stopped(&owner,component.into(),expected_revision,transaction_id);
                                // Even failure after canonical attempt withdraws ordinary work; no replay.
                                if gateway && !matches!(&result, Err(crate::store::native_transaction::NativeTransactionError::Conflict | crate::store::native_transaction::NativeTransactionError::InvalidInput | crate::store::native_transaction::NativeTransactionError::Unsupported)) { stop.cancel(); }
                                let (commit,revision)=result.map_err(|_| ServiceControlError::new("service_control_unknown_inspect_transaction"))?;
                                Ok(ServiceControlReport {schema:1,transaction_id:commit.transaction_id,revision,canonical_raw_sha256:commit.canonical_raw_sha256,status:"configuration_committed_stop_pending".into(),state_scope:"committed_target".into()})
                            }
                            ServiceRequest::SetRunning {expected_revision,transaction_id,..} => {
                                let (commit,revision)=tx.set_service_host_running(&owner,expected_revision,transaction_id)
                                    .map_err(|_| ServiceControlError::new("service_control_unknown_inspect_transaction"))?;
                                drop(tx);
                                checked.validate_inner().map_err(|_| ServiceControlError::new("service_control_unknown_inspect_transaction"))?;
                                Ok(ServiceControlReport {schema:1,transaction_id:commit.transaction_id,revision,canonical_raw_sha256:commit.canonical_raw_sha256,status:"configuration_committed_start_pending".into(),state_scope:"committed_target".into()})
                            }
                            ServiceRequest::Query {transaction_id,..} => {
                                let observed=tx.query(&transaction_id).map_err(|_| ServiceControlError::new("service_control_unknown_inspect_transaction"))?
                                    .ok_or_else(|| ServiceControlError::new("service_control_transaction_absent"))?;
                                let revision=tx.service_transaction_target_revision(&transaction_id).map_err(|_| ServiceControlError::new("service_control_unknown_inspect_transaction"))?;
                                let complete=observed.phase_receipts.last().is_some_and(|p| p.stage==styx_core::management::transaction::DurableStage::Committed);
                                Ok(ServiceControlReport {schema:1,transaction_id,revision,canonical_raw_sha256:observed.intent.target_state_sha256,status:if complete {"committed"} else {"pending"}.into(),state_scope:"transaction_target".into()})
                            }
                        }
                    }).await.map_err(|_| ServiceControlError::new("service_control_core_unavailable"))?
                }.boxed()
            });
            let control = ControlServer::bind_owned(scope, handler)
                .await
                .map_err(|e| error(e.code()))?;
            let cancelled = stop.child_token();
            let failure = control_failed.clone();
            Some(tokio::spawn(async move {
                let result = control.run(cancelled).await;
                if result.is_err() {
                    failure.cancel();
                }
                result
            }))
        } else {
            None
        };
        let server_app = app.clone();
        let server_stop = stop.clone();
        let keep = admitted.clone();
        let mut server = tokio::spawn(async move {
            let _keep = keep;
            server_app.run(listener, server_stop).await
        });
        if let Some(d) = &diagnostic {
            d.mark("listening");
        }
        emit(&events, &stop, "gateway_listening");
        let mut invalidated = false;
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let facts = loop {
            tokio::select! {
                result = &mut server => {
                    break result.map_err(|_| error("gateway_listener_worker_failed"))
                        .and_then(|result| result.map_err(|_| error("gateway_listener_failed")));
                }
                _ = control_failed.cancelled(), if !stop.is_cancelled() => { invalidated=true;stop.cancel(); }
                _ = interval.tick(), if !stop.is_cancelled() => {
                    match validate_for_poll(admitted.clone()).await {
                        Ok(Validation::Ready)=> {
                            #[cfg(any(all(target_os = "linux", target_env = "gnu"), target_os = "macos", target_os = "windows"))]
                            if shared.with(|s| s.set_service_tip_pending(false)).await.is_err() {invalidated=true;stop.cancel();}
                        }
                        #[cfg(any(all(target_os = "linux", target_env = "gnu"), target_os = "macos", target_os = "windows"))]
                        Ok(Validation::Pending)=> {
                            #[cfg(any(all(target_os = "linux", target_env = "gnu"), target_os = "macos", target_os = "windows"))]
                            if shared.with(|s| s.set_service_tip_pending(true)).await.is_err() {invalidated=true;stop.cancel();}
                        }
                        #[cfg(any(all(target_os = "linux", target_env = "gnu"), target_os = "macos", target_os = "windows"))]
                        Ok(Validation::StopRequested)=>stop.cancel(),
                        Err(error)=> {
                            if let Some(d) = &diagnostic { d.report(error.code()); }
                            invalidated=true;emit(&events,&stop,"gateway_inputs_changed");stop.cancel();
                        }
                    }
                }
            }
        };
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "macos",
            target_os = "windows"
        ))]
        let control_joined = {
            stop.cancel();
            match control {
                Some(task) => task.await.is_ok_and(|r| r.is_ok()),
                None => true,
            }
        };
        let facts = facts?;
        // A timeout is not release. Keep the exact original input pins, writer
        // and execution lease while real blocking/read tasks finish.
        let mut joined = facts.blocking_jobs_joined;
        let mut worker_failure = facts.worker_failure_observed;
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "macos",
            target_os = "windows"
        ))]
        {
            worker_failure |= !control_joined;
        }
        while !joined {
            emit(&events, &stop, "gateway_waiting_for_owned_jobs");
            let next = app.wait_for_blocking(Duration::from_secs(30)).await;
            joined = next.blocking_jobs_joined;
            worker_failure |= next.worker_failure_observed;
        }
        let mut lifecycle = mcp_stop.shutdown(Duration::from_secs(5)).await;
        while !lifecycle.connections_joined
            || !lifecycle.lifecycle_jobs_joined
            || !lifecycle.session_transports_joined
        {
            emit(&events, &stop, "gateway_waiting_for_owned_lifecycle");
            tokio::time::sleep(Duration::from_secs(1)).await;
            lifecycle = mcp_stop.shutdown(Duration::from_secs(5)).await;
        }
        let outcome = GatewayForegroundOutcome {
            schema: 1,
            connections_joined: facts.connections_joined && lifecycle.connections_joined,
            blocking_jobs_joined: joined,
            mcp_lifecycle_jobs_joined: lifecycle.lifecycle_jobs_joined,
            mcp_session_transports_joined: lifecycle.session_transports_joined,
            unconfirmed_owner_cleanups: lifecycle.unconfirmed_owner_cleanups,
            // Enrollment listener shutdown actually joined original relay jobs.
            unconfirmed_transport_drains: relay.unconfirmed_transport_drains(),
            sdk_detached_tasks_joined: lifecycle.sdk_detached_tasks_joined,
            worker_failure_observed: worker_failure || lifecycle.worker_failure_observed,
            listener_error_observed: facts.listener_error_observed,
        };
        if outcome.unconfirmed_owner_cleanups != 0 {
            emit(&events, &stop, "remote_owner_cleanup_unconfirmed");
        }
        if outcome.unconfirmed_transport_drains != 0 {
            emit(&events, &stop, "remote_transport_drain_unconfirmed");
        }
        emit(&events, &stop, "gateway_stopped");
        // This explicit command-scope teardown follows actual owned-job waits.
        // None above is not silently promoted to an SDK join claim.
        if invalidated {
            Err(error("gateway_protected_input_changed"))
        } else {
            Ok(outcome)
        }
    }
}
