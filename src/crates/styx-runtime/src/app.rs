//! Private owned-child App composition. Local UI is an entry point, not an OS
//! privilege or a second policy/configuration authority. No network listener,
//! arbitrary call-supplied paths, legacy adoption or mutation replay lives here.
#[cfg(all(test, target_os = "linux", target_env = "gnu"))]
mod control_binding_tests;
mod local_gateway;
mod login;
mod maintenance;
#[cfg(all(test, target_os = "linux", target_env = "gnu"))]
mod maintenance_integration_tests;
pub(crate) mod pairing_link;
mod role_retire;
mod runtime_update;
mod service;
pub(crate) mod startup_diagnostic;

use crate::{
    foreground::{self, ForegroundError, ForegroundOutcome},
    management::{native, native_join},
    store::{ConfigurationWriterGuard, ExecutionLeaseGuard, PrivateRoot},
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    path::{Component, Path, PathBuf},
    sync::{Arc, OnceLock},
    time::Duration,
};
use styx_contracts::native_management::{NativeAutostartDesired, NativeManager, NativeRunDesired};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, watch},
    task::JoinHandle,
};
use tokio_util::{
    codec::{FramedRead, FramedWrite, LinesCodec},
    sync::CancellationToken,
};

const FRAME_BYTES: usize = 2 * 1024 * 1024;
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct AppError(&'static str);
impl AppError {
    pub fn code(&self) -> &'static str {
        self.0
    }
}

/// Retained original App container and its one instance lease. The child root's
/// configuration writer remains separate and is acquired ONLY by existing C07
/// operations. Arc retains this owner; wire DATA cannot construct/replace it.
/// This protects cooperative same-user lifecycle ownership, not against a
/// malicious process already able to execute as the same OS account.
struct AppContainer {
    parent_path: PathBuf,
    parent: PrivateRoot,
    instance: ExecutionLeaseGuard,
}
pub(crate) struct HostScope {
    container: Arc<AppContainer>,
    state_dir: PathBuf,
    root: OnceLock<PrivateRoot>,
}
impl HostScope {
    #[cfg(test)]
    pub(crate) fn open_for_test(state_dir: &Path) -> Result<Self, AppError> {
        Self::open(state_dir)
    }
    fn open(state_dir: &Path) -> Result<Self, AppError> {
        if !state_dir.is_absolute()
            || state_dir.components().any(|p| {
                !matches!(
                    p,
                    Component::Normal(_) | Component::RootDir | Component::Prefix(_)
                )
            })
        {
            return Err(AppError("app_scope_invalid"));
        }
        let parent_path = state_dir
            .parent()
            .ok_or(AppError("app_scope_invalid"))?
            .to_owned();
        let parent = PrivateRoot::open(&parent_path).map_err(|_| AppError("app_scope_refused"))?;
        // The container is never itself an active native configuration root.
        parent
            .ensure_absent(".styx-native-root-v1.json")
            .map_err(|_| AppError("app_container_is_configuration"))?;
        for name in ["state.json", "deployment.json"] {
            parent
                .ensure_absent(name)
                .map_err(|_| AppError("app_container_is_configuration"))?;
        }
        let instance = parent
            .try_execution_lease()
            .map_err(|_| AppError("app_instance_busy"))?;
        let container = Arc::new(AppContainer {
            parent_path,
            parent,
            instance,
        });
        Self::in_container(container, state_dir.to_owned())
    }
    fn in_container(container: Arc<AppContainer>, state_dir: PathBuf) -> Result<Self, AppError> {
        if state_dir.parent() != Some(container.parent_path.as_path()) {
            return Err(AppError("app_scope_invalid"));
        }
        let name = state_dir.file_name().ok_or(AppError("app_scope_invalid"))?;
        let root = OnceLock::new();
        if container.parent.ensure_absent(Path::new(name)).is_err() {
            let original =
                PrivateRoot::open(&state_dir).map_err(|_| AppError("app_scope_refused"))?;
            root.set(original)
                .map_err(|_| AppError("app_scope_changed"))?;
        }
        let result = Self {
            container,
            state_dir,
            root,
        };
        result.validate()?;
        Ok(result)
    }
    /// A fixed sibling under the SAME original App instance lease. Neither the
    /// wire caller nor a second App process can choose or acquire another owner.
    fn gateway_sibling(&self) -> Result<Self, AppError> {
        self.validate()?;
        let state_dir = self.container.parent_path.join("gateway");
        if state_dir == self.state_dir {
            return Err(AppError("app_role_scope_conflict"));
        }
        Self::in_container(self.container.clone(), state_dir)
    }
    pub(crate) fn state_dir(&self) -> &Path {
        &self.state_dir
    }
    pub(crate) fn validate(&self) -> Result<(), AppError> {
        self.container
            .instance
            .validate()
            .map_err(|_| AppError("app_instance_changed"))?;
        let parent = PrivateRoot::open(&self.container.parent_path)
            .map_err(|_| AppError("app_scope_changed"))?;
        if parent.identity() != self.container.parent.identity() {
            return Err(AppError("app_scope_changed"));
        }
        for name in [".styx-native-root-v1.json", "state.json", "deployment.json"] {
            parent
                .ensure_absent(name)
                .map_err(|_| AppError("app_scope_changed"))?;
        }
        match self.root.get() {
            Some(original) => {
                let current = PrivateRoot::open(&self.state_dir)
                    .map_err(|_| AppError("app_scope_changed"))?;
                if current.identity() != original.identity() {
                    return Err(AppError("app_scope_changed"));
                }
            }
            None => self
                .container
                .parent
                .ensure_absent(Path::new(
                    self.state_dir
                        .file_name()
                        .ok_or(AppError("app_scope_invalid"))?,
                ))
                .map_err(|_| AppError("app_scope_changed"))?,
        }
        Ok(())
    }
    pub(crate) fn bind(&self) -> Result<(), AppError> {
        if self.root.get().is_none() {
            let root =
                PrivateRoot::open(&self.state_dir).map_err(|_| AppError("app_scope_changed"))?;
            self.root
                .set(root)
                .map_err(|_| AppError("app_scope_changed"))?;
        }
        self.validate()
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyInput {}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum Operation {
    StartupStatus,
    Status,
    CreateLocal,
    ResumeLocal,
    RequestJoin,
    InspectJoin,
    Join,
    ClaimJoin,
    InspectHost,
    Connect,
    Disconnect,
    QuitAdmission,
    RetireRole,
    PrepareAppMaintenance,
    AppMaintenanceStatus,
    CancelAppMaintenance,
    AppLifecycle,
    AppLogin,
    AppLoginResult,
    StageRuntime,
    UpdateRuntime,
    RuntimeUpdateStatus,
    RecoverRuntimeUpdate,
    TransferToService,
    ServiceStatus,
    PrepareServiceFirstStart,
    StopService,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: u16,
    id: u32,
    operation: Operation,
    input: Box<serde_json::value::RawValue>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InspectJoinInput {
    #[serde(deserialize_with = "secret_string")]
    link: zeroize::Zeroizing<String>,
}
fn secret_string<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<zeroize::Zeroizing<String>, D::Error> {
    String::deserialize(d).map(zeroize::Zeroizing::new)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct JoinInput {
    approved_gateway_origin: String,
    approved_ca_sha256: Option<String>,
    label: String,
    computer: bool,
    browser: bool,
    browser_channel: Option<String>,
    persist_login: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct LocalInput {
    label: String,
    computer: bool,
    browser: bool,
    browser_channel: Option<String>,
    persist_login: bool,
    #[serde(default = "local_port")]
    port: u16,
    #[serde(default)]
    lan_address: Option<String>,
}
fn local_port() -> u16 {
    22022
}
fn validate_choice(choice: &JoinInput) -> Result<(), AppError> {
    if choice.label.trim().is_empty()
        || choice.label.len() > 128
        || choice.label.chars().any(char::is_control)
        || choice
            .browser_channel
            .as_deref()
            .is_some_and(|v| !matches!(v, "chrome" | "msedge" | "chromium"))
    {
        return Err(AppError("app_input_invalid"));
    }
    Ok(())
}
fn now_ms() -> Result<u64, AppError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .ok_or(AppError("app_clock_unavailable"))
}
fn decode_input<T: serde::de::DeserializeOwned>(
    value: &serde_json::value::RawValue,
) -> Result<T, AppError> {
    serde_json::from_str(value.get()).map_err(|_| AppError("app_input_invalid"))
}
#[derive(Clone, Serialize)]
struct ConnectionStatus {
    status: &'static str,
    #[serde(rename = "execConnection")]
    exec_connection: &'static str,
}
impl ConnectionStatus {
    fn stopped() -> Self {
        Self {
            status: "stopped",
            exec_connection: "disconnected",
        }
    }
    fn unknown() -> Self {
        Self {
            status: "unknown",
            exec_connection: "unknown",
        }
    }
}
struct RunningHost {
    // Same protected enrollment/configuration snapshot for this original role.
    // App component intent is not an OS permission or a remote operation grant.
    desktop_intent: Option<Arc<crate::store::native_host_snapshot::NativeHostSnapshot>>,
    cancel: CancellationToken,
    worker: JoinHandle<Result<ForegroundOutcome, ForegroundError>>,
    events: JoinHandle<()>,
    // Dropping a waiter can signal cleanup, but can never issue a joined receipt.
    _cancel_on_drop: tokio_util::sync::DropGuard,
}
enum RetainedFailure {
    Join(native_join::JoinError),
    Management(native::NativeManagementError),
    Bootstrap(crate::management::native_gateway::BootstrapError),
}
impl RetainedFailure {
    fn code(&self) -> &'static str {
        match self {
            Self::Join(e) => e.code(),
            Self::Management(e) => e.code(),
            Self::Bootstrap(e) => e.code(),
        }
    }
}
struct HostApp {
    retire_failure: Option<crate::management::role_retire::RetireError>,
    runtime_update: Option<runtime_update::State>,
    service: Option<service::State>,
    local_gateway: Option<local_gateway::LocalGateway>,
    resume_local_available: bool,
    deployment_file: PathBuf,
    configuration: Option<native::NativeManagementReport>,
    runtime_selection_file: Option<PathBuf>,
    inspected_join: Option<pairing_link::InspectedLink>,
    enrollment: Option<Value>,
    // A verified false may disable optional desktop work; it cannot authorize Exec.
    native_computer_requested: Option<bool>,
    // Original signed object retained across adjacent enrollment/start boundaries.
    native_runtime: Option<Arc<crate::release::VerifiedNativeRelease>>,
    // Retain the exact input writer after any partial publication, too.
    input_writer: Option<ConfigurationWriterGuard>,
    running: Option<RunningHost>,
    observed: watch::Receiver<ConnectionStatus>,
    status: watch::Sender<ConnectionStatus>,
    cleanup: Option<ForegroundOutcome>,
    retained: Option<RetainedFailure>,
    unknown: bool,
    quit_ticket: Option<String>,
    login: login::Login,
    maintenance: Option<maintenance::State>,
    startup_diagnostic: Option<startup_diagnostic::StartupDiagnostic>,
    // Last owner drops only after role workers, retained failures and writers.
    scope: Arc<HostScope>,
}
impl HostApp {
    async fn open(state_dir: &Path, deployment_file: &Path) -> Result<Self, AppError> {
        Self::open_with_selection(state_dir, deployment_file, None).await
    }
    async fn open_with_selection(
        state_dir: &Path,
        deployment_file: &Path,
        selection: Option<PathBuf>,
    ) -> Result<Self, AppError> {
        if !deployment_file.is_absolute() {
            return Err(AppError("app_deployment_invalid"));
        }
        let scope = Arc::new(HostScope::open(state_dir)?);
        let (status, observed) = watch::channel(ConnectionStatus::stopped());
        let mut app = Self {
            retire_failure: None,
            runtime_update: None,
            service: None,
            local_gateway: None,
            resume_local_available: false,
            scope,
            deployment_file: deployment_file.to_owned(),
            configuration: None,
            runtime_selection_file: selection,
            inspected_join: None,
            enrollment: None,
            native_computer_requested: None,
            native_runtime: None,
            input_writer: None,
            running: None,
            observed,
            status,
            cleanup: None,
            retained: None,
            unknown: false,
            quit_ticket: None,
            login: login::Login::default(),
            maintenance: None,
            startup_diagnostic: None,
        };
        if app.scope.root.get().is_some() {
            if app.observe_service_client().await? {
                return Ok(app);
            }
            if app.observe_runtime_update()? {
                return Ok(app);
            }
            if let Err(error) = app.read_configuration().await {
                if app.retained.is_none() {
                    return Err(error);
                }
                app.unknown = true;
                app.enrollment = Some(json!({"status":"incomplete","error":error.code()}));
                return Ok(app);
            }
            {
                match native_join::inspect_for_app(app.scope.clone()).await {
                    Ok(report) => {
                        app.native_computer_requested = Some(report.computer_requested);
                        app.native_runtime = Some(report.verified_runtime.clone());
                        app.enrollment = Some(
                            serde_json::to_value(report)
                                .map_err(|_| AppError("app_response_invalid"))?,
                        )
                    }
                    Err(error) => {
                        let code = app.join_error(error).code();
                        app.unknown = true;
                        app.enrollment = Some(json!({"status":"incomplete","error":code}));
                    }
                }
            }
        }
        Ok(app)
    }
    async fn open_native(state_dir: &Path, selection: &Path) -> Result<Self, AppError> {
        if !selection.is_absolute() {
            return Err(AppError("app_runtime_selection_invalid"));
        }
        let deployment = state_dir
            .parent()
            .ok_or(AppError("app_scope_invalid"))?
            .join("app-join-input-v1.json");
        let mut app =
            Self::open_with_selection(state_dir, &deployment, Some(selection.to_owned())).await?;
        // A committed original Host-only root is not a fresh split App setup.
        // Its original remote Gateway and pairing are never reconstructed.
        if app.service_client_or_unknown() || app.runtime_update_fenced() {
            return Ok(app);
        }
        let gateway_scope = Arc::new(app.scope.gateway_sibling()?);
        if gateway_scope.root.get().is_some() {
            let gateway = match app.load_local_gateway(gateway_scope).await {
                Ok(gateway) => gateway,
                Err(error) => {
                    app.unknown = true;
                    app.enrollment = Some(json!({"status":"incomplete","error":error.code()}));
                    return Ok(app);
                }
            };
            // Existing local setup must retain the original Host enrollment.
            // Missing/partial phases remain inspectable but never auto-paired.
            // Association inspection is not runtime admission: an originally
            // paired, Stopped Host must remain reopenable and normally quitable.
            // No credentials or execution-capable Stopped snapshot escape.
            let host_scope = app.scope.clone();
            let binding = tokio::task::spawn_blocking(move || {
                crate::store::native_host_snapshot::NativeHostSnapshot::inspect_gateway_binding_for_app(
                    host_scope.state_dir(),
                    host_scope.clone(),
                )
            })
            .await
            .map_err(|_| AppError("app_host_binding_reader_failed"))?;
            if let Ok(binding) = binding {
                if binding.gateway_origin() != gateway.origin
                    || binding.anchor_sha256().to_hex() != gateway.ca_sha
                {
                    app.unknown = true;
                }
            } else {
                app.unknown = true;
                match app.check_pre_invite_local().await {
                    Ok(()) => {
                        app.resume_local_available = true;
                        app.enrollment = Some(
                            json!({"status":"local_setup_pre_invite","can_resume_local":true}),
                        );
                    }
                    Err(error) => {
                        app.enrollment = Some(
                            json!({"status":"incomplete","error":error.code(),"can_resume_local":false}),
                        );
                    }
                }
            }
            app.local_gateway = Some(gateway);
        } else if app
            .scope
            .container
            .parent
            .ensure_absent("app-local-gateway-input-v1.json")
            .is_err()
        {
            app.unknown = true;
        }
        Ok(app)
    }
    fn prepare_join_input(&mut self, choice: JoinInput) -> Result<(), AppError> {
        self.available()?;
        if self.scope.root.get().is_some() || self.input_writer.is_some() {
            return Err(AppError("app_join_already_exists"));
        }
        validate_choice(&choice)?;
        let inspected = self
            .inspected_join
            .take()
            .ok_or(AppError("app_join_not_inspected"))?;
        let ca_sha = inspected
            .preview()
            .ca_sha256
            .clone()
            .ok_or(AppError("app_system_trust_not_supported"))?;
        let accepted = inspected
            .approve(
                &choice.approved_gateway_origin,
                choice.approved_ca_sha256.as_deref(),
                now_ms()?,
            )
            .map_err(|e| AppError(e.code()))?;
        let (origin, invitation, ca, _) = accepted.into_parts();
        let ca = ca.ok_or(AppError("app_system_trust_not_supported"))?;
        self.write_join_input(choice, origin, ca_sha, invitation, ca)
    }
    fn write_join_input(
        &mut self,
        choice: JoinInput,
        origin: String,
        ca_sha: String,
        invitation: zeroize::Zeroizing<String>,
        ca: String,
    ) -> Result<(), AppError> {
        validate_choice(&choice)?;
        let selection = self
            .runtime_selection_file
            .as_ref()
            .ok_or(AppError("app_join_input_unavailable"))?;
        // OS/user launch context only. RPC cannot choose arbitrary executables,
        // working directories, runtime payloads or trust files.
        #[cfg(windows)]
        let (home, shell) = (
            std::env::var_os("USERPROFILE").map(PathBuf::from),
            std::env::var_os("SystemRoot")
                // Match the existing enrollment shell policy on every Gateway OS.
                .map(|p| {
                    PathBuf::from(p)
                        .join("System32")
                        .join("WindowsPowerShell")
                        .join("v1.0")
                        .join("powershell.exe")
                }),
        );
        #[cfg(not(windows))]
        let (home, shell) = (
            std::env::var_os("HOME").map(PathBuf::from),
            Some(PathBuf::from("/bin/sh")),
        );
        let home = home
            .filter(|p| p.is_absolute() && p.is_dir())
            .ok_or(AppError("app_home_unavailable"))?;
        let shell = shell
            .filter(|p| p.is_absolute() && p.is_file())
            .ok_or(AppError("app_shell_unavailable"))?;
        let parent = &self.scope.container.parent_path;
        let mut browser =
            json!({"enabled":choice.browser,"headless":true,"persistLogin":choice.persist_login});
        if let Some(channel) = choice.browser_channel {
            browser["channel"] = json!(channel);
        }
        let deployment = serde_json::to_vec(&json!({
            "schema":1,"mode":"join-existing",
            "gateway":{"url":origin,"caFile":parent.join("app-join-ca-v1.pem"),"expectedCaSha256":ca_sha},
            "host":{"label":choice.label,"cwd":home,"shell":shell,"computer":choice.computer,"browser":browser},
            "runtimeSelectionFile":selection,"invitationFile":parent.join("app-join-invitation-v1")
        })).map_err(|_| AppError("app_input_invalid"))?;
        self.scope.validate()?;
        if self.input_writer.is_none() {
            self.input_writer = Some(
                self.scope
                    .container
                    .parent
                    .try_configuration_writer()
                    .map_err(|_| AppError("app_input_writer_busy"))?,
            );
        }
        let result = self.scope.container.parent.create_app_join_inputs(
            self.input_writer
                .as_ref()
                .ok_or(AppError("app_input_writer_busy"))?,
            &deployment,
            invitation.as_bytes(),
            ca.as_bytes(),
        );
        if result.is_err() || self.scope.validate().is_err() {
            self.unknown = true;
            return Err(AppError("app_join_input_unknown"));
        }
        Ok(())
    }
    fn available(&self) -> Result<(), AppError> {
        self.scope.validate()?;
        if self.service_fenced() {
            return Err(AppError("app_service_original_operation_unknown"));
        }
        if self.runtime_update_fenced() {
            return Err(AppError("app_runtime_update_pending"));
        }
        if let Some(error) = &self.retained {
            return Err(AppError(error.code()));
        }
        if self.unknown {
            return Err(AppError("app_cleanup_unknown"));
        }
        if self
            .local_gateway
            .as_ref()
            .is_some_and(|gateway| gateway.is_fenced())
        {
            return Err(AppError("app_gateway_fenced"));
        }
        if self.quit_ticket.is_some() {
            return Err(AppError("app_quit_admitted"));
        }
        Ok(())
    }
    fn management_error(&mut self, e: native::NativeManagementError) -> AppError {
        let code = e.code();
        if e.exit_code() == 4 {
            self.retained = Some(RetainedFailure::Management(e));
        }
        AppError(code)
    }
    fn join_error(&mut self, e: native_join::JoinError) -> AppError {
        let code = e.code();
        if e.exit_code() == 4 {
            self.retained = Some(RetainedFailure::Join(e));
        }
        AppError(code)
    }
    async fn read_configuration(&mut self) -> Result<(), AppError> {
        self.scope.validate()?;
        // Never call a path-only writer while our original role is still live.
        if self.running.is_some() {
            return Err(AppError("app_role_busy"));
        }
        let report = native::inspect_for_app(self.scope.clone())
            .await
            .map_err(|e| self.management_error(e))?;
        if report.desired.gateway.is_some()
            || !report.desired.host.is_some_and(|d| {
                d.manager == NativeManager::AppManaged
                    && d.autostart == NativeAutostartDesired::Disabled
            })
            || report.desired.gateway.is_some_and(|d| {
                d.manager != NativeManager::AppManaged
                    || d.autostart != NativeAutostartDesired::Disabled
            })
        {
            return Err(AppError("app_manager_refused"));
        }
        if report.admission_fenced {
            return Err(AppError("app_transaction_fenced"));
        }
        self.configuration = Some(report);
        Ok(())
    }
    async fn resume_desired_running(&mut self) -> Result<(), AppError> {
        if self.running.is_some() || self.unknown {
            return Ok(());
        }
        self.read_configuration().await?;
        let wanted = self
            .configuration
            .as_ref()
            .and_then(|report| report.desired.host)
            .is_some_and(|host| host.run == NativeRunDesired::Running);
        if !wanted {
            return Ok(());
        }
        if let Some(gateway) = &mut self.local_gateway {
            gateway.start().await?;
        }
        self.connect_host().await
    }
    async fn connect_host(&mut self) -> Result<(), AppError> {
        if self.running.is_none() {
            let diagnostic = self.startup_diagnostic.clone();
            if let Some(d) = &diagnostic {
                d.report("app_connect_host");
            }
            self.set_desired(NativeRunDesired::Running).await?;
            if let Some(d) = &diagnostic {
                d.report("app_host_desired_ready");
            }
            let desktop_intent = if self.native_computer_requested == Some(false) {
                // The original native seed explicitly declined Computer. Starting
                // Exec still loads and verifies its own complete Host profile below.
                None
            } else {
                let intent_scope = self.scope.clone();
                tokio::task::spawn_blocking(move || {
                    crate::store::native_host_snapshot::NativeHostSnapshot::open_for_app(
                        intent_scope.state_dir(),
                        intent_scope.clone(),
                    )
                    .ok()
                    .map(Arc::new)
                })
                .await
                .ok()
                .flatten()
            };
            if let Some(d) = &diagnostic {
                d.report("app_desktop_intent_ready");
            }
            // Missing desktop facts disable that optional component;
            // they cannot prevent the independent Exec Host starting.
            let cancel = CancellationToken::new();
            let worker_cancel = cancel.clone();
            let scope = self.scope.clone();
            let (events, mut received) = mpsc::channel::<foreground::ForegroundEvent>(16);
            let status = self.status.clone();
            let event_task = tokio::spawn(async move {
                while let Some(event) = received.recv().await {
                    let status_value = match event.event {
                        "connected" => ConnectionStatus {
                            status: "connected",
                            exec_connection: "connected",
                        },
                        "connecting" | "reconnecting" => ConnectionStatus {
                            status: "started",
                            exec_connection: "connecting",
                        },
                        "disconnected" => ConnectionStatus {
                            status: "started",
                            exec_connection: "disconnected",
                        },
                        _ => continue,
                    };
                    status.send_replace(status_value);
                }
            });
            self.status.send_replace(ConnectionStatus {
                status: "started",
                exec_connection: "connecting",
            });
            let verified_runtime = self.native_runtime.clone();
            if let Some(d) = &diagnostic {
                d.report("app_host_worker_scheduled");
            }
            let worker = tokio::spawn(async move {
                if let Some(d) = &diagnostic {
                    d.report("app_host_worker_started");
                }
                foreground::host_run_for_app(scope, worker_cancel, events, verified_runtime).await
            });
            let cancel_on_drop = cancel.clone().drop_guard();
            self.running = Some(RunningHost {
                desktop_intent,
                cancel,
                worker,
                events: event_task,
                _cancel_on_drop: cancel_on_drop,
            });
        }
        Ok(())
    }
    async fn settle_all(&mut self) -> Result<(), AppError> {
        self.reap_runtime_update(true).await;
        let host = self.settle().await;
        let gateway = match &mut self.local_gateway {
            Some(gateway) => gateway.settle().await,
            None => Ok(()),
        };
        if gateway.is_err() {
            self.unknown = true;
        }
        host.and(gateway)?;
        if self.runtime_update_fenced() {
            return Err(AppError("app_runtime_update_pending"));
        }
        Ok(())
    }
    async fn set_desired(&mut self, run: NativeRunDesired) -> Result<(), AppError> {
        self.available()?;
        self.read_configuration().await?;
        let report = self
            .configuration
            .as_ref()
            .ok_or(AppError("app_not_configured"))?;
        if report.desired.host.is_some_and(|h| h.run == run) {
            return Ok(());
        }
        let change = native::NativeDesiredChange {
            component: native::NativeComponent::Host,
            run,
            transaction_id: uuid::Uuid::new_v4()
                .to_string()
                .try_into()
                .expect("UUID identity"),
            sequence: report
                .revision
                .checked_add(1)
                .ok_or(AppError("app_revision_exhausted"))?,
        };
        let plan = native::plan_for_app(self.scope.clone(), change)
            .await
            .map_err(|e| self.management_error(e))?;
        self.scope.validate()?;
        let report = native::apply_for_app(self.scope.clone(), &plan.plan_file)
            .await
            .map_err(|e| self.management_error(e))?;
        if report.admission_fenced {
            self.unknown = true;
            return Err(AppError("app_transaction_fenced"));
        }
        self.configuration = Some(report);
        Ok(())
    }
    async fn settle(&mut self) -> Result<(), AppError> {
        if let Some(role) = self.running.take() {
            role.cancel.cancel();
            let outcome = role.worker.await;
            let events = role.events.await;
            match outcome {
                Ok(Ok(outcome)) => {
                    let complete = outcome.is_complete() && events.is_ok();
                    let locally_joined = outcome.local_stop_complete() && events.is_ok();
                    self.cleanup = Some(outcome);
                    if complete {
                        self.status.send_replace(ConnectionStatus::stopped());
                    } else {
                        self.unknown = true;
                        self.status.send_replace(ConnectionStatus::unknown());
                        let cause = if locally_joined {
                            "remote_transport_drain_unconfirmed"
                        } else {
                            "foreground_cleanup_incomplete"
                        };
                        eprintln!(
                            "{}",
                            json!({"schema":1,"event":"app_role_failed","cause":cause,"events_joined":events.is_ok()})
                        );
                        return Err(AppError("app_cleanup_unknown"));
                    }
                }
                failed => {
                    // Preserve a fixed diagnostic cause; never print native
                    // output, credentials, paths or an arbitrary error display.
                    let cause = match &failed {
                        Ok(Err(error)) => error.code(),
                        Ok(Ok(_)) => "foreground_cleanup_incomplete",
                        Err(_) => "foreground_worker_failed",
                    };
                    eprintln!(
                        "{}",
                        json!({"schema":1,"event":"app_role_failed","cause":cause,"events_joined":events.is_ok()})
                    );
                    self.unknown = true;
                    self.status.send_replace(ConnectionStatus::unknown());
                    return Err(AppError("app_cleanup_unknown"));
                }
            }
        }
        if self.unknown {
            return Err(AppError("app_cleanup_unknown"));
        }
        Ok(())
    }
    async fn reap(&mut self) -> Result<(), AppError> {
        if self
            .running
            .as_ref()
            .is_some_and(|r| r.worker.is_finished())
        {
            self.settle().await?;
        }
        Ok(())
    }
    fn admission_fenced(&self) -> bool {
        self.service_fenced()
            || self.runtime_update_fenced()
            || self.unknown
            || self.retained.is_some()
            || self.quit_ticket.is_some()
            || self
                .local_gateway
                .as_ref()
                .is_some_and(|gateway| gateway.is_fenced())
    }
    async fn desktop_component_requested(&self) -> bool {
        if self.admission_fenced() {
            return false;
        }
        let Some(role) = &self.running else {
            return false;
        };
        if role.cancel.is_cancelled() || role.worker.is_finished() {
            return false;
        }
        let Some(original) = role.desktop_intent.clone() else {
            return false;
        };
        // Never acquire a replacement profile on a status request. Original
        // private file/namespace identities and bytes must still match; only
        // the successful pairing self-response supplies computer_approved.
        let requested = tokio::task::spawn_blocking(move || {
            original.seed().computer_requested
                && original.ready().computer_approved
                && original.revalidate().is_ok()
        })
        .await
        .unwrap_or(false);
        requested && !role.cancel.is_cancelled() && !role.worker.is_finished()
    }
    async fn snapshot(&self) -> Value {
        let computer_requested = self.desktop_component_requested().await;
        let configuration = self.service_configuration().or(self.configuration.as_ref());
        let mut supported = vec![
            "appLifecycle",
            "appLogin",
            "appLoginResult",
            "startupStatus",
            "status",
            "quitAdmission",
            "prepareAppMaintenance",
            "cancelAppMaintenance",
            "appMaintenanceStatus",
        ];
        if !self.service_client_or_unknown() {
            supported.extend([
                "createLocal",
                "resumeLocal",
                "inspectJoin",
                "join",
                "requestJoin",
                "claimJoin",
                "inspectHost",
                "connect",
                "disconnect",
                "retireRole",
                "stageRuntime",
                "updateRuntime",
                "runtimeUpdateStatus",
                "recoverRuntimeUpdate",
            ]);
            // Advertise only the supported fresh single-Host composition.
            // The mutation still revalidates original scope, Ready and C07.
            if cfg!(target_os = "macos")
                && !self.admission_fenced()
                && self.local_gateway.is_none()
                && self.configuration.as_ref().is_some_and(|report| {
                    report.desired.gateway.is_none()
                        && report.desired.host.is_some_and(|host| {
                            host.manager == NativeManager::AppManaged
                                && host.autostart == NativeAutostartDesired::Disabled
                        })
                })
                && self.enrollment.as_ref().is_some_and(|report| {
                    matches!(
                        report.get("status").and_then(Value::as_str),
                        Some("ready_to_connect" | "already_ready")
                    )
                })
            {
                supported.push("transferToService");
            }
        } else if cfg!(target_os = "macos") {
            supported.extend(["serviceStatus", "prepareServiceFirstStart", "stopService"]);
        }
        json!({"schema":1,"maintenance":self.maintenance_status()["maintenance"],"runtimeUpdate":self.runtime_update,"service":self.service,"configuration":configuration,"foreground":*self.observed.borrow(),"admission_fenced":self.admission_fenced(),"desktop_intent":{"schema":1,"computer_requested":computer_requested,"source":"approved_host_configuration"},"cleanup":self.cleanup,"gateway":self.local_gateway.as_ref().map(|g| g.status()),"enrollment":self.enrollment,"mode":"rust_host","supportedOperations":supported})
    }
    async fn dispatch(
        &mut self,
        operation: Operation,
        input: Box<serde_json::value::RawValue>,
    ) -> Result<Value, AppError> {
        match operation {
            Operation::PrepareAppMaintenance => {
                return self.prepare_maintenance(decode_input(&input)?).await;
            }
            Operation::CancelAppMaintenance => {
                return self.cancel_maintenance(decode_input(&input)?).await;
            }
            Operation::AppMaintenanceStatus => {
                let _: EmptyInput = decode_input(&input)?;
                return Ok(self.maintenance_status());
            }
            _ => (),
        }
        let quitting = matches!(operation, Operation::QuitAdmission);
        if quitting && !self.maintenance_quit_allowed() {
            return Err(AppError("app_maintenance_original_operation_required"));
        }
        if self.maintenance_fenced()
            && !matches!(
                operation,
                Operation::QuitAdmission
                    | Operation::Status
                    | Operation::StartupStatus
                    | Operation::AppLifecycle
                    | Operation::RuntimeUpdateStatus
                    | Operation::ServiceStatus
            )
        {
            return Err(AppError("app_maintenance_original_operation_required"));
        }
        let result = self.dispatch_inner(operation, input).await;
        if quitting {
            self.maintenance_quit_result(result).await
        } else {
            result
        }
    }
    async fn dispatch_inner(
        &mut self,
        operation: Operation,
        input: Box<serde_json::value::RawValue>,
    ) -> Result<Value, AppError> {
        if !matches!(
            operation,
            Operation::RetireRole
                | Operation::InspectJoin
                | Operation::Join
                | Operation::CreateLocal
                | Operation::ResumeLocal
                | Operation::StageRuntime
                | Operation::UpdateRuntime
                | Operation::RecoverRuntimeUpdate
                | Operation::AppLifecycle
                | Operation::AppLogin
                | Operation::AppLoginResult
                | Operation::TransferToService
                | Operation::PrepareServiceFirstStart
                | Operation::StopService
        ) {
            let _: EmptyInput = decode_input(&input)?;
        }
        self.reap_runtime_update(false).await;
        self.reap().await?;
        match operation {
            Operation::AppLifecycle => return self.login_read(input),
            Operation::AppLogin => return self.login_authorize(input),
            Operation::AppLoginResult => return self.login_complete(input),
            Operation::QuitAdmission if self.login.pending() => {
                return Err(AppError("app_login_in_progress"));
            }
            _ => (),
        }
        if matches!(operation, Operation::QuitAdmission) && self.service_client_or_unknown() {
            return self.service_quit_admission().await;
        }
        if matches!(operation, Operation::TransferToService) {
            self.transfer_to_service(decode_input(&input)?).await?;
            return Ok(self.snapshot().await);
        }
        if matches!(
            operation,
            Operation::PrepareServiceFirstStart | Operation::StopService
        ) {
            self.manage_service(
                decode_input(&input)?,
                matches!(operation, Operation::PrepareServiceFirstStart),
            )
            .await?;
            return Ok(self.snapshot().await);
        }
        if matches!(operation, Operation::ServiceStatus) {
            self.refresh_service_client().await?;
            return Ok(self.snapshot().await);
        }
        if matches!(operation, Operation::Status | Operation::StartupStatus) {
            self.scope.validate()?;
            if self.service_client_or_unknown() && !self.service_fenced() {
                // A failed observation is represented in service.error; this
                // read never opens/reconciles a service configuration writer.
                let _ = self.refresh_service_client().await;
            } else if matches!(operation, Operation::StartupStatus) {
                // Reopen reconnects a role the user left running, without
                // re-pairing. Pause (Disconnect) records Stopped and is kept.
                // A failure is visible in the snapshot; it is not this read's error.
                let _ = self.resume_desired_running().await;
            }
            return Ok(self.snapshot().await);
        }
        if self.service_client_or_unknown() {
            return Err(AppError("app_role_managed_by_service"));
        }
        if matches!(operation, Operation::RetireRole) {
            return self.retire_role(decode_input(&input)?).await;
        }
        if matches!(operation, Operation::RuntimeUpdateStatus) {
            self.scope.validate()?;
            return Ok(self.snapshot().await);
        }
        if matches!(operation, Operation::StageRuntime) {
            self.stage_runtime(decode_input(&input)?).await?;
            return Ok(self.snapshot().await);
        }
        if matches!(
            operation,
            Operation::UpdateRuntime | Operation::RecoverRuntimeUpdate
        ) {
            self.update_runtime(
                decode_input(&input)?,
                matches!(operation, Operation::RecoverRuntimeUpdate),
            )
            .await?;
            return Ok(self.snapshot().await);
        }
        if matches!(operation, Operation::ResumeLocal) {
            self.resume_local(decode_input(&input)?).await?;
            self.connect_host().await?;
            return Ok(self.snapshot().await);
        }
        if matches!(operation, Operation::QuitAdmission) && self.resume_local_available {
            // This is a positively revalidated never-dispatched checkpoint,
            // not permission to clear an arbitrary failed pairing/role outcome.
            self.check_pre_invite_local().await?;
            // Only the positively checked never-dispatched setup is known;
            // settle itself must not inherit that incomplete-setup sentinel.
            self.unknown = false;
            if let Err(error) = self.settle_all().await.and_then(|()| self.scope.validate()) {
                self.unknown = true;
                return Err(error);
            }
            let ticket = uuid::Uuid::new_v4().simple().to_string();
            self.quit_ticket = Some(ticket.clone());
            self.resume_local_available = false;
            self.unknown = false;
            return Ok(
                json!({"quit":{"status":"ready_to_quit","ticketId":ticket},"cleanup":self.cleanup,"gateway":self.local_gateway.as_ref().map(|g| g.status())}),
            );
        }
        // A queued runtime update owns its original writer. A UI Quit must
        // return promptly and must never abort it or pretend it has settled.
        if matches!(operation, Operation::QuitAdmission) && self.runtime_update_running() {
            return Err(AppError("app_runtime_update_in_progress"));
        }
        // Stopping our own captured role remains safe even if scope validation
        // has failed. Never leave it running because a configuration write was refused.
        if matches!(operation, Operation::QuitAdmission) {
            self.settle_all().await?;
        } else if matches!(operation, Operation::Disconnect) {
            self.settle().await?;
        }
        self.available()?;
        match operation {
            Operation::ResumeLocal => Err(AppError("app_local_checkpoint_refused")),
            Operation::CreateLocal => {
                let choice: LocalInput = decode_input(&input)?;
                self.create_local(choice).await?;
                self.connect_host().await?;
                Ok(self.snapshot().await)
            }
            Operation::InspectJoin => {
                if self.scope.root.get().is_some() || self.input_writer.is_some() {
                    return Err(AppError("app_join_already_exists"));
                }
                // Clear the previous secret even when replacement input is invalid.
                self.inspected_join = None;
                let input: InspectJoinInput = decode_input(&input)?;
                let inspected = pairing_link::inspect(&input.link, now_ms()?)
                    .map_err(|e| AppError(e.code()))?;
                let preview = inspected.preview();
                self.inspected_join = Some(inspected);
                Ok(json!({"inspectionId":uuid::Uuid::new_v4().to_string(),"preview":preview}))
            }
            Operation::RequestJoin | Operation::Join => {
                if matches!(operation, Operation::RequestJoin)
                    && self.runtime_selection_file.is_some()
                {
                    return Err(AppError("app_join_inspection_required"));
                }
                if matches!(operation, Operation::Join) {
                    self.prepare_join_input(decode_input(&input)?)?;
                }
                if self.running.is_some() || self.scope.root.get().is_some() {
                    return Err(AppError("app_join_already_exists"));
                }
                let report =
                    native_join::request_for_app(self.scope.clone(), &self.deployment_file)
                        .await
                        .map_err(|e| self.join_error(e))?;
                self.read_configuration().await?;
                self.native_computer_requested = Some(report.computer_requested);
                self.native_runtime = Some(report.verified_runtime.clone());
                let value =
                    serde_json::to_value(report).map_err(|_| AppError("app_response_invalid"))?;
                self.enrollment = Some(value.clone());
                Ok(value)
            }
            Operation::ClaimJoin => {
                if self.running.is_some() {
                    return Err(AppError("app_role_busy"));
                }
                // Enrollment must not bypass an unresolved C07 operation.
                self.read_configuration().await?;
                let report =
                    native_join::claim_for_app(self.scope.clone(), self.native_runtime.clone())
                        .await
                        .map_err(|e| self.join_error(e))?;
                self.read_configuration().await?;
                self.native_computer_requested = Some(report.computer_requested);
                self.native_runtime = Some(report.verified_runtime.clone());
                let value =
                    serde_json::to_value(report).map_err(|_| AppError("app_response_invalid"))?;
                self.enrollment = Some(value.clone());
                // A confirmed join connects at once; the claim itself already
                // succeeded, so a connect failure shows in status, not here.
                if value["status"] == "ready_to_connect" {
                    let _ = self.connect_host().await;
                }
                Ok(value)
            }
            Operation::InspectHost => {
                if self.running.is_some() {
                    return Err(AppError("app_role_busy"));
                }
                self.read_configuration().await?;
                let report = foreground::inspect_for_app(self.scope.clone())
                    .await
                    .map_err(|e| AppError(e.code()))?;
                serde_json::to_value(report).map_err(|_| AppError("app_response_invalid"))
            }
            Operation::Connect => {
                if let Some(gateway) = &mut self.local_gateway {
                    gateway.start().await?;
                }
                self.connect_host().await?;
                Ok(self.snapshot().await)
            }
            Operation::Disconnect => {
                self.settle().await?;
                self.set_desired(NativeRunDesired::Stopped).await?;
                Ok(self.snapshot().await)
            }
            Operation::QuitAdmission => {
                // This ticket is only admission. Here admission is deliberately
                // issued after actual owned-role settlement, never after kill.
                self.settle_all().await?;
                let ticket = uuid::Uuid::new_v4().simple().to_string();
                self.quit_ticket = Some(ticket.clone());
                Ok(
                    json!({"quit":{"status":"ready_to_quit","ticketId":ticket},"cleanup":self.cleanup,"gateway":self.local_gateway.as_ref().map(|g|g.status())}),
                )
            }
            Operation::RetireRole
            | Operation::PrepareAppMaintenance
            | Operation::AppMaintenanceStatus
            | Operation::CancelAppMaintenance
            | Operation::AppLifecycle
            | Operation::AppLogin
            | Operation::AppLoginResult
            | Operation::StartupStatus
            | Operation::Status
            | Operation::StageRuntime
            | Operation::UpdateRuntime
            | Operation::RuntimeUpdateStatus
            | Operation::RecoverRuntimeUpdate
            | Operation::TransferToService
            | Operation::ServiceStatus
            | Operation::PrepareServiceFirstStart
            | Operation::StopService => unreachable!(),
        }
    }
}

/// Closed bounded request/response protocol over the actual owned child's pipe.
/// It is distinct from the Linux read-only socket and is not exposed remotely.
/// EOF/output loss stops and joins only this App's role, leaving durable desired
/// state and independent CLI/services unchanged. No request is automatically retried.
pub async fn serve<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    state_dir: &Path,
    deployment_file: &Path,
    read: R,
    write: W,
    cancel: CancellationToken,
) -> Result<(), AppError> {
    serve_app(
        HostApp::open(state_dir, deployment_file).await?,
        read,
        write,
        cancel,
    )
    .await
}

/// Native UI bootstrap: selection is a protected, fixed launcher input, never RPC data.
pub async fn serve_native<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    state_dir: &Path,
    runtime_selection_file: &Path,
    read: R,
    write: W,
    cancel: CancellationToken,
) -> Result<(), AppError> {
    serve_app(
        HostApp::open_native(state_dir, runtime_selection_file).await?,
        read,
        write,
        cancel,
    )
    .await
}

async fn serve_app<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut app: HostApp,
    read: R,
    write: W,
    cancel: CancellationToken,
) -> Result<(), AppError> {
    let mut input = FramedRead::new(read, LinesCodec::new_with_max_length(FRAME_BYTES));
    let mut output = FramedWrite::new(write, LinesCodec::new_with_max_length(FRAME_BYTES));
    let mut previous_id = 0;
    let mut transport_error = None;
    loop {
        let line = tokio::select! {_=cancel.cancelled()=>break, line=input.next()=>line};
        let Some(Ok(line)) = line else {
            if line.is_some() {
                transport_error = Some(AppError("app_frame_invalid"));
            }
            break;
        };
        let line = zeroize::Zeroizing::new(line);
        let request: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(_) => {
                transport_error = Some(AppError("app_frame_invalid"));
                break;
            }
        };
        if request.schema != 1
            || request.id == 0
            || request.id <= previous_id
            || request.id > i32::MAX as u32
        {
            transport_error = Some(AppError("app_correlation_invalid"));
            break;
        }
        previous_id = request.id;
        // Do not select/drop this future on disconnect or cancellation: an
        // already dispatched enrollment/configuration operation must settle.
        let result = app.dispatch(request.operation, request.input).await;
        let response = match result {
            Ok(result) => json!({"id":request.id,"ok":true,"result":result}),
            Err(error) => {
                json!({"id":request.id,"ok":false,"error":error.code(),"runtimeUpdate":app.runtime_update,"retirement":app.retire_failure.as_ref().map(|error| &error.report)})
            }
        };
        let encoded =
            serde_json::to_string(&response).map_err(|_| AppError("app_response_invalid"));
        let written = match encoded {
            Ok(value) => tokio::time::timeout(Duration::from_secs(10), output.send(value))
                .await
                .is_ok_and(|r| r.is_ok()),
            Err(_) => false,
        };
        if !written {
            transport_error = Some(AppError("app_output_unavailable"));
            break;
        }
    }
    app.settle_all().await?;
    if app.retained.is_some() {
        return Err(AppError("app_operation_unknown"));
    }
    if let Some(error) = transport_error {
        return Err(error);
    }
    Ok(())
}
