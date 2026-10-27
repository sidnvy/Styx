//! Private owned-child App composition. Local UI is an entry point, not an OS
//! privilege or a second policy/configuration authority. No network listener,
//! arbitrary call-supplied paths, legacy adoption or mutation replay lives here.
mod local_gateway;
mod migrated;
mod migration;
mod pairing_link;
mod runtime_update;

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
    ReviewMigration,
    StartMigration,
    RecoverMigration,
    StageRuntime,
    UpdateRuntime,
    RuntimeUpdateStatus,
    RecoverRuntimeUpdate,
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
    desktop_intent: Option<migrated::DesktopIntent>,
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
    migration: Option<migration::State>,
    runtime_update: Option<runtime_update::State>,
    local_gateway: Option<local_gateway::LocalGateway>,
    resume_local_available: bool,
    committed_migration: bool,
    migrated_shared: bool,
    deployment_file: PathBuf,
    configuration: Option<native::NativeManagementReport>,
    runtime_selection_file: Option<PathBuf>,
    inspected_join: Option<pairing_link::InspectedLink>,
    enrollment: Option<Value>,
    // Retain the exact input writer after any partial publication, too.
    input_writer: Option<ConfigurationWriterGuard>,
    running: Option<RunningHost>,
    observed: watch::Receiver<ConnectionStatus>,
    status: watch::Sender<ConnectionStatus>,
    cleanup: Option<ForegroundOutcome>,
    retained: Option<RetainedFailure>,
    unknown: bool,
    quit_ticket: Option<String>,
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
            migration: None,
            runtime_update: None,
            local_gateway: None,
            resume_local_available: false,
            committed_migration: false,
            migrated_shared: false,
            scope,
            deployment_file: deployment_file.to_owned(),
            configuration: None,
            runtime_selection_file: selection,
            inspected_join: None,
            enrollment: None,
            input_writer: None,
            running: None,
            observed,
            status,
            cleanup: None,
            retained: None,
            unknown: false,
            quit_ticket: None,
        };
        if app.scope.root.get().is_some() {
            if app.runtime_selection_file.is_some() {
                app.observe_migration().await;
                if app.migration.is_some() {
                    return Ok(app);
                }
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
            if !app.committed_migration {
                match native_join::inspect_for_app(app.scope.clone()).await {
                    Ok(report) => {
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
            if app.migrated_shared {
                let gateway = local_gateway::LocalGateway::open_migrated(app.scope.clone()).await?;
                app.local_gateway = Some(gateway);
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
        if app.committed_migration || app.migration.is_some() || app.runtime_update_fenced() {
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
        if self.runtime_update_fenced() {
            return Err(AppError("app_runtime_update_pending"));
        }
        if self.migration_fenced() {
            return Err(AppError("app_migration_pending"));
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
        if self.running.is_some()
            || (self.migrated_shared && self.local_gateway.as_ref().is_some_and(|g| g.is_running()))
        {
            return Err(AppError("app_role_busy"));
        }
        let report = native::inspect_for_app(self.scope.clone())
            .await
            .map_err(|e| self.management_error(e))?;
        let scope = self.scope.clone();
        let inspection = tokio::task::spawn_blocking(move || migrated::inspect(scope))
            .await
            .map_err(|_| AppError("app_migrated_reader_failed"))??;
        let shared = inspection
            .as_ref()
            .is_some_and(|i| i.topology == migrated::Topology::SharedLocal);
        if (report.desired.gateway.is_some() && !shared)
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
        if let Some(inspection) = inspection {
            self.committed_migration = true;
            self.migrated_shared = shared;
            self.enrollment = Some(inspection.enrollment);
        } else if self.committed_migration {
            return Err(AppError("app_migrated_input_changed"));
        }
        if report.admission_fenced {
            return Err(AppError("app_transaction_fenced"));
        }
        self.configuration = Some(report);
        Ok(())
    }
    async fn connect_host(&mut self) -> Result<(), AppError> {
        if self.running.is_none() {
            if !self.migrated_shared {
                self.set_desired(NativeRunDesired::Running).await?;
            }
            let intent_scope = self.scope.clone();
            let migrated_source = self.committed_migration;
            let desktop_intent = tokio::task::spawn_blocking(move || {
                migrated::DesktopIntent::open(intent_scope, migrated_source).ok()
            })
            .await
            .ok()
            .flatten();
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
            let worker = tokio::spawn(async move {
                foreground::host_run_for_app(scope, worker_cancel, events).await
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
        // EOF waits for the original dispatched migration. Dropping the pipe
        // is never cancellation, a new writer, or a successful cleanup receipt.
        self.reap_migration(true).await;
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
    /// Both actual roles have joined before the one original-root C07 update.
    /// Gateway desired remains Running on Pause, preserving its existing role.
    async fn set_shared_desired(&mut self, run: NativeRunDesired) -> Result<(), AppError> {
        self.available()?;
        if !self.migrated_shared
            || self.running.is_some()
            || self.local_gateway.as_ref().is_some_and(|g| g.is_running())
        {
            return Err(AppError("app_role_busy"));
        }
        self.read_configuration().await?;
        let report = self
            .configuration
            .as_ref()
            .ok_or(AppError("app_not_configured"))?;
        if report.desired.host.is_some_and(|h| h.run == run)
            && report
                .desired
                .gateway
                .is_some_and(|g| g.run == NativeRunDesired::Running)
        {
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
        let plan = native::plan_shared_roles_for_app(
            self.scope.clone(),
            change,
            NativeRunDesired::Running,
        )
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
        // The previous read-only snapshot correctly pins the previous canonical
        // tip. Reopen only after both roles joined and this exact C07 committed;
        // the original scope/root and immutable migration bindings are retained.
        let gateway = match local_gateway::LocalGateway::open_migrated(self.scope.clone()).await {
            Ok(gateway) => gateway,
            Err(error) => {
                self.unknown = true;
                return Err(error);
            }
        };
        self.local_gateway = Some(gateway);
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
        self.migration_fenced()
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
        let requested = tokio::task::spawn_blocking(move || original.requested())
            .await
            .unwrap_or(false);
        requested && !role.cancel.is_cancelled() && !role.worker.is_finished()
    }
    async fn snapshot(&self) -> Value {
        let computer_requested = self.desktop_component_requested().await;
        json!({"schema":1,"migration":self.migration,"runtimeUpdate":self.runtime_update,"configuration":self.configuration,"foreground":*self.observed.borrow(),"admission_fenced":self.admission_fenced(),"desktop_intent":{"schema":1,"computer_requested":computer_requested,"source":if self.committed_migration {"committed_original_local_intent"} else {"approved_host_configuration"}},"cleanup":self.cleanup,"gateway":self.local_gateway.as_ref().map(|g| g.status()),"enrollment":self.enrollment,"mode":"rust_host","supportedOperations":["startupStatus","status","createLocal","resumeLocal","inspectJoin","join","requestJoin","claimJoin","inspectHost","connect","disconnect","quitAdmission","reviewMigration","startMigration","recoverMigration","stageRuntime","updateRuntime","runtimeUpdateStatus","recoverRuntimeUpdate"]})
    }
    async fn dispatch(
        &mut self,
        operation: Operation,
        input: Box<serde_json::value::RawValue>,
    ) -> Result<Value, AppError> {
        if !matches!(
            operation,
            Operation::InspectJoin
                | Operation::Join
                | Operation::CreateLocal
                | Operation::ResumeLocal
                | Operation::ReviewMigration
                | Operation::StartMigration
                | Operation::RecoverMigration
                | Operation::StageRuntime
                | Operation::UpdateRuntime
                | Operation::RecoverRuntimeUpdate
        ) {
            let _: EmptyInput = decode_input(&input)?;
        }
        self.reap_runtime_update(false).await;
        self.reap_migration(false).await;
        self.reap().await?;
        if matches!(operation, Operation::Status | Operation::StartupStatus) {
            self.scope.validate()?;
            return Ok(self.snapshot().await);
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
        if matches!(operation, Operation::ReviewMigration) {
            return self.review_migration(decode_input(&input)?).await;
        }
        if matches!(
            operation,
            Operation::StartMigration | Operation::RecoverMigration
        ) {
            self.start_migration(
                decode_input(&input)?,
                matches!(operation, Operation::RecoverMigration),
            )?;
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
        // A queued native migration owns its original writer. A UI Quit must
        // return promptly and must never abort it or pretend it has settled.
        if matches!(operation, Operation::QuitAdmission) && self.runtime_update_running() {
            return Err(AppError("app_runtime_update_in_progress"));
        }
        if matches!(operation, Operation::QuitAdmission) && self.migration_running() {
            return Err(AppError("app_migration_in_progress"));
        }
        // Stopping our own captured role remains safe even if scope validation
        // has failed. Never leave it running because a configuration write was refused.
        if matches!(operation, Operation::QuitAdmission) {
            self.settle_all().await?;
        } else if matches!(operation, Operation::Disconnect) {
            self.settle().await?;
        }
        if matches!(operation, Operation::QuitAdmission)
            && self.migration_fenced()
            && !self.unknown
            && self.retained.is_none()
        {
            self.scope.validate()?;
            let ticket = uuid::Uuid::new_v4().simple().to_string();
            self.quit_ticket = Some(ticket.clone());
            return Ok(
                json!({"quit":{"status":"ready_to_quit","ticketId":ticket},"migration":self.migration}),
            );
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
                let value =
                    serde_json::to_value(report).map_err(|_| AppError("app_response_invalid"))?;
                self.enrollment = Some(value.clone());
                Ok(value)
            }
            Operation::ClaimJoin => {
                if self.committed_migration {
                    return Err(AppError("app_migrated_pairing_already_committed"));
                }
                if self.running.is_some() {
                    return Err(AppError("app_role_busy"));
                }
                // Enrollment must not bypass an unresolved C07 operation.
                self.read_configuration().await?;
                let report = native_join::claim_for_app(self.scope.clone())
                    .await
                    .map_err(|e| self.join_error(e))?;
                self.read_configuration().await?;
                let value =
                    serde_json::to_value(report).map_err(|_| AppError("app_response_invalid"))?;
                self.enrollment = Some(value.clone());
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
                if self.migrated_shared && self.running.is_none() {
                    if let Some(gateway) = &mut self.local_gateway {
                        gateway.settle().await?;
                    }
                    self.set_shared_desired(NativeRunDesired::Running).await?;
                }
                if let Some(gateway) = &mut self.local_gateway {
                    gateway.start().await?;
                }
                self.connect_host().await?;
                Ok(self.snapshot().await)
            }
            Operation::Disconnect => {
                if self.migrated_shared {
                    self.settle_all().await?;
                    self.set_shared_desired(NativeRunDesired::Stopped).await?;
                    if let Some(gateway) = &mut self.local_gateway {
                        gateway.start().await?;
                    }
                } else {
                    self.settle().await?;
                    self.set_desired(NativeRunDesired::Stopped).await?;
                }
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
            Operation::StartupStatus
            | Operation::Status
            | Operation::ReviewMigration
            | Operation::StartMigration
            | Operation::RecoverMigration
            | Operation::StageRuntime
            | Operation::UpdateRuntime
            | Operation::RuntimeUpdateStatus
            | Operation::RecoverRuntimeUpdate => unreachable!(),
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
                json!({"id":request.id,"ok":false,"error":error.code(),"migration":app.migration,"runtimeUpdate":app.runtime_update})
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
