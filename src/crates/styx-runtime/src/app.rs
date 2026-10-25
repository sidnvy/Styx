//! Private owned-child App composition. Local UI is an entry point, not an OS
//! privilege or a second policy/configuration authority. No network listener,
//! arbitrary call-supplied paths, legacy adoption or mutation replay lives here.
use crate::{
    foreground::{self, ForegroundError, ForegroundOutcome},
    management::{native, native_join},
    store::{ExecutionLeaseGuard, PrivateRoot},
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
pub(crate) struct HostScope {
    parent_path: PathBuf,
    parent: PrivateRoot,
    instance: ExecutionLeaseGuard,
    state_dir: PathBuf,
    root: OnceLock<PrivateRoot>,
}
impl HostScope {
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
        let name = state_dir.file_name().ok_or(AppError("app_scope_invalid"))?;
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
        let root = OnceLock::new();
        if parent.ensure_absent(Path::new(name)).is_err() {
            let original =
                PrivateRoot::open(state_dir).map_err(|_| AppError("app_scope_refused"))?;
            root.set(original)
                .map_err(|_| AppError("app_scope_changed"))?;
        }
        let result = Self {
            parent_path,
            parent,
            instance,
            state_dir: state_dir.to_owned(),
            root,
        };
        result.validate()?;
        Ok(result)
    }
    pub(crate) fn state_dir(&self) -> &Path {
        &self.state_dir
    }
    pub(crate) fn validate(&self) -> Result<(), AppError> {
        self.instance
            .validate()
            .map_err(|_| AppError("app_instance_changed"))?;
        let parent =
            PrivateRoot::open(&self.parent_path).map_err(|_| AppError("app_scope_changed"))?;
        if parent.identity() != self.parent.identity() {
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
    RequestJoin,
    ClaimJoin,
    InspectHost,
    Connect,
    Disconnect,
    QuitAdmission,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: u16,
    id: u32,
    operation: Operation,
    input: EmptyInput,
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
    cancel: CancellationToken,
    worker: JoinHandle<Result<ForegroundOutcome, ForegroundError>>,
    events: JoinHandle<()>,
    // Dropping a waiter can signal cleanup, but can never issue a joined receipt.
    _cancel_on_drop: tokio_util::sync::DropGuard,
}
enum RetainedFailure {
    Join(native_join::JoinError),
    Management(native::NativeManagementError),
}
impl RetainedFailure {
    fn code(&self) -> &'static str {
        match self {
            Self::Join(e) => e.code(),
            Self::Management(e) => e.code(),
        }
    }
}
struct HostApp {
    scope: Arc<HostScope>,
    deployment_file: PathBuf,
    configuration: Option<native::NativeManagementReport>,
    running: Option<RunningHost>,
    observed: watch::Receiver<ConnectionStatus>,
    status: watch::Sender<ConnectionStatus>,
    cleanup: Option<ForegroundOutcome>,
    retained: Option<RetainedFailure>,
    unknown: bool,
    quit_ticket: Option<String>,
}
impl HostApp {
    async fn open(state_dir: &Path, deployment_file: &Path) -> Result<Self, AppError> {
        if !deployment_file.is_absolute() {
            return Err(AppError("app_deployment_invalid"));
        }
        let scope = Arc::new(HostScope::open(state_dir)?);
        let (status, observed) = watch::channel(ConnectionStatus::stopped());
        let mut app = Self {
            scope,
            deployment_file: deployment_file.to_owned(),
            configuration: None,
            running: None,
            observed,
            status,
            cleanup: None,
            retained: None,
            unknown: false,
            quit_ticket: None,
        };
        if app.scope.root.get().is_some() {
            app.read_configuration().await?;
        }
        Ok(app)
    }
    fn available(&self) -> Result<(), AppError> {
        self.scope.validate()?;
        if let Some(error) = &self.retained {
            return Err(AppError(error.code()));
        }
        if self.unknown {
            return Err(AppError("app_cleanup_unknown"));
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
        {
            return Err(AppError("app_manager_refused"));
        }
        if report.admission_fenced {
            return Err(AppError("app_transaction_fenced"));
        }
        self.configuration = Some(report);
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
        let plan = native::plan(self.scope.state_dir(), change)
            .await
            .map_err(|e| self.management_error(e))?;
        self.scope.validate()?;
        let report = native::apply(self.scope.state_dir(), &plan.plan_file)
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
                Ok(Ok(outcome)) if outcome.is_complete() && events.is_ok() => {
                    self.cleanup = Some(outcome);
                    self.status.send_replace(ConnectionStatus::stopped());
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
    fn snapshot(&self) -> Value {
        json!({"schema":1,"configuration":self.configuration,"foreground":*self.observed.borrow(),"admission_fenced":self.unknown||self.retained.is_some()||self.quit_ticket.is_some(),"cleanup":self.cleanup})
    }
    async fn dispatch(&mut self, operation: Operation) -> Result<Value, AppError> {
        self.reap().await?;
        if matches!(operation, Operation::Status | Operation::StartupStatus) {
            self.scope.validate()?;
            return Ok(self.snapshot());
        }
        // Stopping our own captured role remains safe even if scope validation
        // has failed. Never leave it running because a configuration write was refused.
        if matches!(operation, Operation::Disconnect | Operation::QuitAdmission) {
            self.settle().await?;
        }
        self.available()?;
        match operation {
            Operation::RequestJoin => {
                if self.running.is_some() || self.scope.root.get().is_some() {
                    return Err(AppError("app_join_already_exists"));
                }
                let report =
                    native_join::request_for_app(self.scope.clone(), &self.deployment_file)
                        .await
                        .map_err(|e| self.join_error(e))?;
                self.read_configuration().await?;
                serde_json::to_value(report).map_err(|_| AppError("app_response_invalid"))
            }
            Operation::ClaimJoin => {
                if self.running.is_some() {
                    return Err(AppError("app_role_busy"));
                }
                // Enrollment must not bypass an unresolved C07 operation.
                self.read_configuration().await?;
                let report = native_join::claim_for_app(self.scope.clone())
                    .await
                    .map_err(|e| self.join_error(e))?;
                self.read_configuration().await?;
                serde_json::to_value(report).map_err(|_| AppError("app_response_invalid"))
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
                if self.running.is_none() {
                    self.set_desired(NativeRunDesired::Running).await?;
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
                        cancel,
                        worker,
                        events: event_task,
                        _cancel_on_drop: cancel_on_drop,
                    });
                }
                Ok(self.snapshot())
            }
            Operation::Disconnect => {
                self.settle().await?;
                self.set_desired(NativeRunDesired::Stopped).await?;
                Ok(self.snapshot())
            }
            Operation::QuitAdmission => {
                // This ticket is only admission. Here admission is deliberately
                // issued after actual owned-role settlement, never after kill.
                self.settle().await?;
                let ticket = uuid::Uuid::new_v4().simple().to_string();
                self.quit_ticket = Some(ticket.clone());
                Ok(
                    json!({"quit":{"status":"ready_to_quit","ticketId":ticket},"cleanup":self.cleanup}),
                )
            }
            Operation::StartupStatus | Operation::Status => unreachable!(),
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
    let mut app = HostApp::open(state_dir, deployment_file).await?;
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
        let _input = request.input;
        // Do not select/drop this future on disconnect or cancellation: an
        // already dispatched enrollment/configuration operation must settle.
        let result = app.dispatch(request.operation).await;
        let response = match result {
            Ok(result) => json!({"id":request.id,"ok":true,"result":result}),
            Err(error) => json!({"id":request.id,"ok":false,"error":error.code()}),
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
    app.settle().await?;
    if app.retained.is_some() {
        return Err(AppError("app_operation_unknown"));
    }
    if let Some(error) = transport_error {
        return Err(error);
    }
    Ok(())
}
