//! Process entry adapter. Runtime owns trusted profile admission and cleanup;
//! command arguments never supply credentials, executor binaries or authority.
use clap::{Parser, Subcommand, ValueEnum};
use std::{
    ffi::OsString,
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
};
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(
    name = "styx",
    version,
    about = "Styx Rust runtime (development build)"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "macos",
        target_os = "windows"
    ))]
    #[command(name = "__service-run", hide = true)]
    ServiceRun {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long, value_enum)]
        role: NativeComponentArg,
    },
    /// Explicit native user-service lifecycle; never enables linger or sudo.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    Service {
        #[arg(value_enum)]
        action: ServiceActionArg,
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long, value_enum)]
        component: NativeComponentArg,
        #[arg(long)]
        transaction_id: Option<String>,
        #[arg(long)]
        expected_revision: Option<u64>,
        #[arg(long)]
        authorize: bool,
        #[arg(long)]
        json: bool,
    },
    /// Review/observe a fixed launchd definition, or stop its original Gateway.
    /// Does not install, enable, start, or adopt an App-managed profile.
    #[cfg(target_os = "macos")]
    #[command(name = "service")]
    MacService {
        #[arg(value_enum)]
        action: MacServiceActionArg,
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long, value_enum)]
        component: NativeComponentArg,
        #[arg(long)]
        transaction_id: Option<String>,
        #[arg(long)]
        expected_revision: Option<u64>,
        /// Original-publisher signed candidate, only for prepare-runtime-repair.
        #[arg(long)]
        runtime_selection_file: Option<PathBuf>,
        #[arg(long)]
        authorize: bool,
        #[arg(long)]
        json: bool,
    },
    /// Private native App owned-child transport, never a network endpoint.
    #[command(name = "__app-core", hide = true)]
    AppCore {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(
            long,
            required_unless_present = "runtime_selection_file",
            conflicts_with = "runtime_selection_file"
        )]
        deployment_file: Option<PathBuf>,
        #[arg(long)]
        runtime_selection_file: Option<PathBuf>,
    },
    // Fixed read-only worker mode; there are no target/credential/path options.
    #[command(name = "__linux-desktop-probe", hide = true)]
    LinuxDesktopProbe,
    #[command(name = "__linux-desktop-watch", hide = true)]
    LinuxDesktopWatch,
    #[command(name = "__linux-desktop-association", hide = true)]
    LinuxDesktopAssociation {
        #[arg(long)]
        candidate: String,
    },
    #[command(name = "__linux-desktop-association-check", hide = true)]
    LinuxDesktopAssociationCheck {
        #[arg(long)]
        candidate: String,
    },
    /// Print build and contract identity; never claims a running service.
    BuildInfo {
        #[arg(long)]
        json: bool,
    },
    /// Run the explicitly configured native Host in this foreground process.
    Host {
        #[command(subcommand)]
        command: HostCommand,
    },
    /// Run the protected paired Gateway in this foreground process.
    Gateway {
        #[command(subcommand)]
        command: GatewayCommand,
    },
    /// Verify an offline release using an externally trusted public publisher pin.
    Release {
        #[command(subcommand)]
        command: ReleaseCommand,
    },
    /// Initialize a fresh native configuration root; never adopts legacy state.
    Init {
        #[arg(long)]
        parent_dir: PathBuf,
        #[arg(long)]
        name: OsString,
        #[arg(long)]
        deployment_file: PathBuf,
        #[arg(long, value_enum)]
        mode: NativeModeArg,
        #[arg(long, value_enum)]
        manager: NativeManagerArg,
        #[arg(long)]
        host: bool,
        #[arg(long)]
        gateway: bool,
        #[arg(long)]
        json: bool,
    },
    /// Apply an exact reviewed native plan; no services are started here.
    Apply {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        plan_file: PathBuf,
        #[arg(long, required = true)]
        authorize: bool,
        #[arg(long)]
        json: bool,
    },
    /// Review Windows migration; may initialize its private journal, without retiring the owner.
    MigrateReview {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        runtime_selection_file: PathBuf,
        #[arg(long)]
        transaction_id: String,
        #[arg(long, value_enum)]
        run: NativeRunArg,
        #[arg(long)]
        json: bool,
    },
    /// Migrate the original paired foreground Host using an explicit candidate.
    Migrate {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        runtime_selection_file: PathBuf,
        #[arg(long)]
        transaction_id: String,
        #[arg(long, value_enum)]
        run: NativeRunArg,
        #[arg(long, required = true)]
        authorize: bool,
        /// Exact digest returned by Windows migrate-review.
        #[arg(long)]
        plan_sha256: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Reconcile the original native transaction; never mint a replacement ID.
    Recover {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        transaction_id: String,
        #[arg(long, required = true)]
        authorize: bool,
        #[arg(long)]
        json: bool,
    },
    /// Inspect a native transaction without applying or recovering it.
    Transaction {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        transaction_id: String,
        #[arg(long)]
        json: bool,
    },
    /// Review configuration intent and unresolved legacy steps without executing them.
    Plan {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        json: bool,
        #[arg(long,requires_all=["component","run","transaction_id","sequence"])]
        native: bool,
        #[arg(long, value_enum, requires = "native")]
        component: Option<NativeComponentArg>,
        #[arg(long, value_enum, requires = "native")]
        run: Option<NativeRunArg>,
        #[arg(long, requires = "native")]
        transaction_id: Option<String>,
        #[arg(long,requires="native",value_parser=clap::value_parser!(u64).range(1..))]
        sequence: Option<u64>,
    },
    /// Inspect the existing deployment without connecting or starting services.
    Status {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        native: bool,
    },
    /// Validate a profile, or inspect OS desktop candidates without granting access.
    Doctor {
        #[arg(
            long,
            required_unless_present = "desktop_sessions",
            conflicts_with = "desktop_sessions"
        )]
        state_dir: Option<PathBuf>,
        /// Linux OS candidates only; does not attach or authorize a desktop.
        #[arg(long)]
        desktop_sessions: bool,
        /// Stream unverified Linux OS candidates; cancellation fences the source.
        #[arg(long, requires = "desktop_sessions")]
        watch: bool,
        #[arg(long)]
        json: bool,
    },
}
#[derive(Clone, Copy, ValueEnum)]
enum NativeModeArg {
    CreateLocal,
    JoinExisting,
}
#[derive(Clone, Copy, ValueEnum)]
enum NativeManagerArg {
    ForegroundCli,
    AppManaged,
    PersistentService,
}
#[derive(Clone, Copy, ValueEnum)]
enum NativeComponentArg {
    Host,
    Gateway,
}
#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ServiceActionArg {
    Install,
    Status,
    Enable,
    Disable,
    Start,
    Stop,
    Uninstall,
}
#[cfg(all(target_os = "linux", target_env = "gnu"))]
impl ServiceActionArg {
    fn native(self) -> styx_runtime::management::native::service::ServiceAction {
        use styx_runtime::management::native::service::ServiceAction;
        match self {
            Self::Install => ServiceAction::Install,
            Self::Status => ServiceAction::Status,
            Self::Enable => ServiceAction::Enable,
            Self::Disable => ServiceAction::Disable,
            Self::Start => ServiceAction::Start,
            Self::Stop => ServiceAction::Stop,
            Self::Uninstall => ServiceAction::Uninstall,
        }
    }
}
#[cfg(target_os = "macos")]
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum MacServiceActionArg {
    Definition,
    Status,
    PrepareInstall,
    PrepareFirstStart,
    /// Prepare same-identity recovery of a registered but failed inactive Gateway.
    PrepareRecovery,
    PrepareRuntimeRepair,
    /// Recover the exact original target; never reissue an uncertain admin request.
    RecoverRuntimeRepair,
    Stop,
    Start,
    Enable,
    Disable,
    Uninstall,
}
#[cfg(target_os = "macos")]
impl MacServiceActionArg {
    fn native(self) -> styx_runtime::management::native::service::ServiceAction {
        use styx_runtime::management::native::service::ServiceAction;
        match self {
            Self::Definition => ServiceAction::Definition,
            Self::Status => ServiceAction::Status,
            Self::PrepareInstall => ServiceAction::PrepareInstall,
            Self::PrepareFirstStart => ServiceAction::PrepareFirstStart,
            Self::PrepareRecovery => ServiceAction::PrepareRecovery,
            Self::PrepareRuntimeRepair => ServiceAction::PrepareRuntimeRepair,
            Self::RecoverRuntimeRepair => ServiceAction::RecoverRuntimeRepair,
            Self::Stop => ServiceAction::Stop,
            Self::Start => ServiceAction::Start,
            Self::Enable => ServiceAction::Enable,
            Self::Disable => ServiceAction::Disable,
            Self::Uninstall => ServiceAction::Uninstall,
        }
    }
}
#[derive(Clone, Copy, ValueEnum)]
enum NativeRunArg {
    Running,
    Stopped,
}
impl Cli {
    /// SCM must attach on the original process main thread before Tokio exists.
    #[cfg(target_os = "windows")]
    pub(crate) fn dispatch_windows_service(&self) -> Option<ExitCode> {
        let Command::ServiceRun { state_dir, role } = &self.command else {
            return None;
        };
        Some(native_recovery_result(
            styx_runtime::management::native::service::dispatch(state_dir, role.native()),
            true,
            "Original Windows service dispatcher and drain observations:",
        ))
    }
    pub(crate) fn is_desktop_probe_worker(&self) -> bool {
        matches!(
            self.command,
            Command::LinuxDesktopProbe
                | Command::LinuxDesktopWatch
                | Command::LinuxDesktopAssociation { .. }
        )
    }
}
#[derive(Subcommand)]
enum HostCommand {
    /// Explicit native enrollment; does not start or install a Host.
    Join {
        #[command(subcommand)]
        command: HostJoinCommand,
    },
    /// Explicit current-user transient action; no autostart or installation.
    Start {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long, required = true)]
        transient: bool,
        #[arg(long)]
        json: bool,
    },
    /// Observe scoped user units; never starts or adopts one.
    Status {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long, required = true)]
        transient: bool,
        #[arg(long)]
        owner_file: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    Run {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        legacy_gateway: bool,
    },
    Stop {
        #[arg(long)]
        state_dir: Option<PathBuf>,
        #[arg(long, requires_all = ["state_dir", "owner_file", "expected_invocation"])]
        transient: bool,
        #[arg(long, requires = "transient")]
        owner_file: Option<PathBuf>,
        #[arg(long, requires = "transient")]
        expected_invocation: Option<String>,
        #[arg(long)]
        json: bool,
    },
    Pause {
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    Resume {
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
}
#[derive(Subcommand)]
enum HostJoinCommand {
    /// Create a fresh private Host identity and request Gateway approval once.
    Request {
        #[arg(long)]
        parent_dir: PathBuf,
        #[arg(long)]
        name: OsString,
        #[arg(long)]
        deployment_file: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Claim an approved credential and verify current authenticated self state.
    Claim {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum GatewayCommand {
    /// Create one invitation and publish its secret only to a new private file.
    Invite {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        invitation_file: PathBuf,
        #[arg(long, default_value_t = 600, value_parser = clap::value_parser!(u64).range(60..=600))]
        ttl_seconds: u64,
        #[arg(long, required = true)]
        authorize: bool,
        #[arg(long)]
        json: bool,
    },
    /// Observe authoritative pending identities; never approves or claims them.
    Pending {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Approve exactly one explicitly compared pending identity.
    Approve {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        request_id: String,
        #[arg(long)]
        device_id: String,
        #[arg(long)]
        fingerprint: String,
        #[arg(long)]
        comparison_code: String,
        #[arg(long)]
        enable_computer: bool,
        #[arg(long)]
        enable_browser: bool,
        #[arg(long, required = true)]
        authorize: bool,
        #[arg(long)]
        json: bool,
    },
    /// Initialize fresh Gateway-only foreground configuration; no service launch or legacy adoption.
    Bootstrap {
        #[arg(long)]
        parent_dir: PathBuf,
        #[arg(long)]
        name: OsString,
        #[arg(long)]
        deployment_file: PathBuf,
        #[arg(long)]
        runtime_selection_file: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Run {
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ReleaseCommand {
    /// Commit a verified runtime selection for a stopped fresh foreground profile.
    Select {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        runtime_selection_file: PathBuf,
        #[arg(long)]
        transaction_id: String,
        #[arg(long)]
        sequence: u64,
        #[arg(long, required = true)]
        authorize: bool,
        #[arg(long)]
        json: bool,
    },
    /// Copy a verified runtime to a new private version directory; never activates it.
    Stage {
        #[arg(long)]
        payload_dir: PathBuf,
        #[arg(long)]
        publisher_file: PathBuf,
        #[arg(long)]
        expected_publisher: String,
        #[arg(long)]
        parent_dir: PathBuf,
        #[arg(long)]
        name: OsString,
        #[arg(long, required = true)]
        authorize: bool,
        #[arg(long)]
        json: bool,
    },
    /// Read-only signature and payload verification; never installs or runs it.
    Verify {
        #[arg(long)]
        payload_dir: PathBuf,
        #[arg(long)]
        publisher_file: PathBuf,
        /// Public SHA256 pin from trusted external policy, not from the payload.
        #[arg(long)]
        expected_publisher: String,
        #[arg(long)]
        json: bool,
        /// Emit verified runtime selection data for the native App bootstrap.
        #[arg(long)]
        runtime_selection: bool,
    },
}

fn error(code: &str) -> ExitCode {
    // Curated codes only; runtime errors may contain private paths or inputs.
    eprintln!("{}", serde_json::json!({"schema":1,"error":code}));
    ExitCode::from(2)
}
fn write_json(value: &impl serde::Serialize) -> io::Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, value)?;
    output.write_all(b"\n")?;
    output.flush()
}
fn native_error_output(
    value: &styx_runtime::management::native::NativeManagementError,
) -> serde_json::Value {
    let mut output = serde_json::json!({"schema":1,"error":value.code()});
    if let Some(diagnostic) = value.migration_diagnostic() {
        output["migration"] = diagnostic;
    }
    output
}
/// An unresolved owned migration/recovery job must survive until explicit
/// whole-process teardown. Dropping its result would leave runtime shutdown
/// waiting for the original blocking custody job.
fn native_recovery_result<T: serde::Serialize>(
    result: Result<T, styx_runtime::management::native::NativeManagementError>,
    json: bool,
    summary: &'static str,
) -> ExitCode {
    #[cfg(any(
        target_os = "macos",
        target_os = "windows",
        all(target_os = "linux", target_env = "gnu")
    ))]
    if let Err(value) = &result
        && value.requires_process_teardown()
    {
        let mut output = native_error_output(value);
        output["outcome"] = serde_json::json!(if value.code()
            == "native_migration_waiting_for_later_boot"
        {
            "pending"
        } else {
            "unknown"
        });
        output["operations_replayed"] = serde_json::json!(false);
        output["cleanup_confirmed"] = serde_json::json!(false);
        output["process_exit"] = serde_json::json!("explicit_scope_teardown");
        eprintln!("{output}");
        let _ = io::stdout().flush();
        let _ = io::stderr().flush();
        // Keep the entire original result alive; this is not successful cleanup.
        std::process::exit(i32::from(value.exit_code()));
    }
    native_result(result, json, summary)
}
fn native_result<T: serde::Serialize>(
    result: Result<T, styx_runtime::management::native::NativeManagementError>,
    json: bool,
    summary: &'static str,
) -> ExitCode {
    match result {
        Ok(value) => {
            if !json {
                eprintln!("{summary}");
            }
            if write_json(&value).is_err() {
                error("output_unavailable")
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(value) => {
            eprintln!("{}", native_error_output(&value));
            ExitCode::from(value.exit_code())
        }
    }
}
fn gateway_admin_result(
    result: Result<
        styx_runtime::management::native_gateway_admin::AdminReport,
        styx_runtime::management::native_gateway_admin::AdminError,
    >,
    json: bool,
) -> ExitCode {
    match result {
        Ok(report) => {
            if !json {
                eprintln!("Native Gateway admin observation; invitation secrets are file-only:");
            }
            if write_json(&report).is_ok() {
                ExitCode::SUCCESS
            } else if matches!(report.operation, "gateway_invite" | "gateway_approve") {
                eprintln!(
                    "{}",
                    serde_json::json!({"schema":1,"error":"native_gateway_admin_response_unknown","outcome":"unknown","operations_replayed":false})
                );
                ExitCode::from(4)
            } else {
                error("output_unavailable")
            }
        }
        Err(value) => {
            eprintln!(
                "{}",
                serde_json::json!({"schema":1,"error":value.code(),"outcome":value.outcome(),"operations_replayed":false})
            );
            ExitCode::from(value.exit_code())
        }
    }
}
fn join_result(
    result: Result<
        styx_runtime::management::native_join::JoinReport,
        styx_runtime::management::native_join::JoinError,
    >,
    json: bool,
) -> ExitCode {
    match result {
        Ok(value) => {
            if !json {
                eprintln!("Native Host enrollment observed; runtime not started:");
            }
            if write_json(&value).is_err() {
                error("output_unavailable")
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(value) => {
            eprintln!("{}", serde_json::json!({"schema":1,"error":value.code()}));
            ExitCode::from(value.exit_code())
        }
    }
}
impl NativeModeArg {
    fn native(self) -> styx_contracts::native_management::NativeDeploymentMode {
        use styx_contracts::native_management::NativeDeploymentMode;
        match self {
            Self::CreateLocal => NativeDeploymentMode::CreateLocal,
            Self::JoinExisting => NativeDeploymentMode::JoinExisting,
        }
    }
}
impl NativeManagerArg {
    fn native(self) -> styx_contracts::native_management::NativeManager {
        use styx_contracts::native_management::NativeManager;
        match self {
            Self::ForegroundCli => NativeManager::ForegroundCli,
            Self::AppManaged => NativeManager::AppManaged,
            Self::PersistentService => NativeManager::PersistentService,
        }
    }
}
impl NativeComponentArg {
    fn native(self) -> styx_runtime::management::native::NativeComponent {
        use styx_runtime::management::native::NativeComponent;
        match self {
            Self::Host => NativeComponent::Host,
            Self::Gateway => NativeComponent::Gateway,
        }
    }
}
impl NativeRunArg {
    fn native(self) -> styx_contracts::native_management::NativeRunDesired {
        use styx_contracts::native_management::NativeRunDesired;
        match self {
            Self::Running => NativeRunDesired::Running,
            Self::Stopped => NativeRunDesired::Stopped,
        }
    }
}
async fn desktop_association_check(candidate: &str) -> ExitCode {
    #[cfg(target_os = "linux")]
    {
        match styx_runtime::session_probe::association::inspect_candidate_association(candidate)
            .await
        {
            Ok(output) => match write_json(&output) {
                Ok(()) => ExitCode::SUCCESS,
                Err(_) => error("output_unavailable"),
            },
            Err(refusal) => error(refusal.code()),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = candidate;
        error("desktop_association_unsupported")
    }
}

async fn desktop_association_worker(candidate: &str) -> ExitCode {
    #[cfg(target_os = "linux")]
    {
        match styx_runtime::session_probe::association::worker_association(candidate).await {
            Ok(output) => match write_json(&output) {
                Ok(()) => ExitCode::SUCCESS,
                Err(_) => error("output_unavailable"),
            },
            Err(refusal) => match write_json(&refusal) {
                Ok(()) => ExitCode::from(2),
                Err(_) => error("output_unavailable"),
            },
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = candidate;
        error("desktop_association_unsupported")
    }
}

async fn desktop_probe_worker() -> ExitCode {
    #[cfg(target_os = "linux")]
    {
        match styx_runtime::session_probe::worker_snapshot().await {
            Ok(snapshot) => match write_json(&snapshot) {
                Ok(()) => ExitCode::SUCCESS,
                Err(_) => error("output_unavailable"),
            },
            Err(styx_runtime::session_probe::ProbeError::Discovery(value)) => {
                let refusal = styx_runtime::session_probe::WorkerRefusal::from_error(value);
                if write_json(&refusal).is_err() {
                    error("output_unavailable")
                } else {
                    ExitCode::from(2)
                }
            }
            Err(value) => error(value.code()),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        error("desktop_discovery_unsupported")
    }
}

#[cfg(target_os = "linux")]
async fn watch_write<T: serde::Serialize>(
    output: &mut crate::watch_output::WatchOutput,
    value: &T,
) -> io::Result<()> {
    tokio::time::timeout(
        std::time::Duration::from_millis(250),
        output.write_json(value),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "watch output unavailable"))?
}

async fn desktop_watch_worker() -> ExitCode {
    #[cfg(target_os = "linux")]
    {
        use styx_runtime::session_probe::watch::{self, Wire};
        let mut output = match crate::watch_output::WatchOutput::open() {
            Ok(value) => value,
            Err(_) => return error("output_unavailable"),
        };
        let cancel = CancellationToken::new();
        let (events, mut rx) = tokio::sync::mpsc::channel(8);
        let watching = watch::worker_watch(events, cancel.clone());
        tokio::pin!(watching);
        let signal = stop_signal();
        tokio::pin!(signal);
        let mut output_ok = true;
        let mut signal_ok = true;
        let stopped = loop {
            tokio::select! {
                biased;
                _=output.disconnected()=>{output_ok=false;cancel.cancel();break watching.await;},
                result=&mut signal=>{signal_ok=result.is_ok();cancel.cancel();break watching.await;},
                result=&mut watching=>break result,
                event=rx.recv()=>if let Some(event)=event && watch_write(&mut output,&Wire::Event(event)).await.is_err(){output_ok=false;cancel.cancel();break watching.await;},
            }
        };
        while let Ok(event) = rx.try_recv() {
            if output_ok && watch_write(&mut output, &Wire::Event(event)).await.is_err() {
                output_ok = false;
            }
        }
        if output_ok
            && watch_write(&mut output, &Wire::Shutdown(stopped))
                .await
                .is_err()
        {
            output_ok = false;
        }
        let finished = output.finish().await.is_ok();
        if !output_ok || !finished {
            return error("output_unavailable");
        }
        if signal_ok && stopped.connection_closed {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(2)
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        error("desktop_discovery_unsupported")
    }
}
async fn desktop_watch_diagnostics(json: bool) -> ExitCode {
    #[cfg(target_os = "linux")]
    {
        use styx_runtime::session_probe::watch::{self, ParentStop};
        if !json {
            eprintln!("Unverified OS candidates; this stream grants no Desktop access:");
        }
        let mut output = match crate::watch_output::WatchOutput::open() {
            Ok(value) => value,
            Err(_) => return error("output_unavailable"),
        };
        let cancel = CancellationToken::new();
        let (events, mut rx) = tokio::sync::mpsc::channel(8);
        let watching = watch::watch_current_user(events, cancel.clone());
        tokio::pin!(watching);
        let signal = stop_signal();
        tokio::pin!(signal);
        let mut output_ok = true;
        let mut signal_ok = true;
        let report = loop {
            tokio::select! {
                biased;
                _=output.disconnected()=>{output_ok=false;cancel.cancel();break watching.await;},
                result=&mut signal=>{signal_ok=result.is_ok();cancel.cancel();break watching.await;},
                result=&mut watching=>break result,
                event=rx.recv()=>if let Some(event)=event && watch_write(&mut output,&event).await.is_err(){output_ok=false;cancel.cancel();break watching.await;},
            }
        };
        while let Ok(event) = rx.try_recv() {
            if output_ok && watch_write(&mut output, &event).await.is_err() {
                output_ok = false;
            }
        }
        if output_ok
            && watch_write(
                &mut output,
                &serde_json::json!({"schema":1,"watch_shutdown":report}),
            )
            .await
            .is_err()
        {
            output_ok = false;
        }
        let finished = output.finish().await.is_ok();
        if !output_ok || !finished {
            return error("output_unavailable");
        }
        if signal_ok
            && report.child_reaped
            && report.stdout_joined
            && report.reason == ParentStop::Cancelled
        {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(2)
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = json;
        error("desktop_discovery_unsupported")
    }
}

async fn desktop_diagnostics(json: bool) -> ExitCode {
    #[cfg(target_os = "linux")]
    {
        match styx_runtime::foreground::discover_desktop_candidates().await {
            Ok(snapshot) => {
                if !json {
                    eprintln!(
                        "OS desktop candidates; agent association and desktop authorization are unproven:"
                    );
                }
                if write_json(&snapshot).is_err() {
                    error("output_unavailable")
                } else {
                    ExitCode::SUCCESS
                }
            }
            Err(value) => error(value.code()),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = json;
        error("desktop_discovery_unsupported")
    }
}
#[cfg(unix)]
async fn stop_signal() -> io::Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! { r=tokio::signal::ctrl_c()=>r, _=terminate.recv()=>Ok(()) }
}
#[cfg(windows)]
async fn stop_signal() -> io::Result<()> {
    let mut interrupt = tokio::signal::windows::ctrl_c()?;
    let mut terminate = tokio::signal::windows::ctrl_break()?;
    tokio::select! {
        event = interrupt.recv() => event.ok_or_else(|| io::Error::other("console_signal_closed")),
        event = terminate.recv() => event.ok_or_else(|| io::Error::other("console_signal_closed")),
    }
}
#[cfg(not(any(unix, windows)))]
async fn stop_signal() -> io::Result<()> {
    tokio::signal::ctrl_c().await
}

pub(crate) async fn run(cli: Cli) -> ExitCode {
    use styx_runtime::foreground::{self, HostWireMode};
    match cli.command {
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        Command::Service {
            action,
            state_dir,
            component,
            transaction_id,
            expected_revision,
            authorize,
            json,
        } => {
            if action != ServiceActionArg::Status && !authorize {
                return error("explicit_service_authorization_required");
            }
            let transaction_id = match transaction_id
                .map(styx_contracts::identity::TransactionId::try_from)
                .transpose()
            {
                Ok(v) => v,
                Err(_) => return error("native_management_invalid_input"),
            };
            native_recovery_result(
                styx_runtime::management::native::service::manage(
                    &state_dir,
                    action.native(),
                    component.native(),
                    transaction_id,
                    expected_revision,
                )
                .await,
                json,
                "Native service observations; inspect canonical intent and actual OS state:",
            )
        }
        #[cfg(target_os = "macos")]
        Command::MacService {
            action,
            state_dir,
            component,
            transaction_id,
            expected_revision,
            runtime_selection_file,
            authorize,
            json,
        } => {
            if matches!(
                action,
                MacServiceActionArg::PrepareInstall
                    | MacServiceActionArg::PrepareFirstStart
                    | MacServiceActionArg::PrepareRecovery
                    | MacServiceActionArg::PrepareRuntimeRepair
                    | MacServiceActionArg::RecoverRuntimeRepair
                    | MacServiceActionArg::Stop
                    | MacServiceActionArg::Start
                    | MacServiceActionArg::Enable
                    | MacServiceActionArg::Disable
                    | MacServiceActionArg::Uninstall
            ) {
                if !authorize {
                    return error("explicit_service_authorization_required");
                }
                if matches!(
                    action,
                    MacServiceActionArg::PrepareRecovery
                        | MacServiceActionArg::PrepareRuntimeRepair
                        | MacServiceActionArg::RecoverRuntimeRepair
                ) && !matches!(component, NativeComponentArg::Gateway)
                {
                    return error("native_service_gateway_only");
                }
            }
            let transaction_id = match transaction_id
                .map(styx_contracts::identity::TransactionId::try_from)
                .transpose()
            {
                Ok(value) => value,
                Err(_) => return error("native_management_invalid_input"),
            };
            let result = if action == MacServiceActionArg::PrepareRuntimeRepair {
                let (Some(selection), Some(id), Some(revision)) = (
                    runtime_selection_file.as_deref(),
                    transaction_id,
                    expected_revision,
                ) else {
                    return error("explicit_service_repair_inputs_required");
                };
                styx_runtime::management::native::service::prepare_runtime_repair(
                    &state_dir, selection, id, revision,
                )
                .await
            } else if action == MacServiceActionArg::RecoverRuntimeRepair {
                if runtime_selection_file.is_some() {
                    return error("runtime_selection_only_for_service_repair");
                }
                let (Some(id), Some(revision)) = (transaction_id, expected_revision) else {
                    return error("explicit_service_repair_inputs_required");
                };
                styx_runtime::management::native::service::recover_runtime_repair(
                    &state_dir, id, revision,
                )
                .await
            } else {
                if runtime_selection_file.is_some() {
                    return error("runtime_selection_only_for_service_repair");
                }
                styx_runtime::management::native::service::manage(
                    &state_dir,
                    action.native(),
                    component.native(),
                    transaction_id,
                    expected_revision,
                )
                .await
            };
            native_recovery_result(
                result,
                json,
                "Native launchd intent and observations; prepared installation does not prove registration or readiness:",
            )
        }
        #[cfg(any(all(target_os = "linux", target_env = "gnu"), target_os = "macos"))]
        Command::ServiceRun { state_dir, role } => {
            let cancel = CancellationToken::new();
            let (events, mut received) = tokio::sync::mpsc::channel(16);
            let output_cancel = cancel.clone();
            let output = tokio::spawn(async move {
                let mut healthy = true;
                while let Some(event) = received.recv().await {
                    if healthy && write_json(&event).is_err() {
                        healthy = false;
                        output_cancel.cancel();
                    }
                }
                healthy
            });
            let running = styx_runtime::management::native::service::run(
                &state_dir,
                role.native(),
                cancel.clone(),
                events,
            );
            tokio::pin!(running);
            let result = tokio::select! {result=&mut running=>result,signal=stop_signal()=>{if signal.is_err(){cancel.cancel();let _=running.await;return error("signal_listener_failed");}cancel.cancel();running.await}};
            if !output.await.unwrap_or(false) {
                return error("output_unavailable");
            }
            native_recovery_result(
                result,
                true,
                "Native service stopped with physical cleanup observations:",
            )
        }
        #[cfg(target_os = "windows")]
        Command::ServiceRun { .. } => {
            error("windows_service_requires_original_pre_runtime_dispatch")
        }
        Command::AppCore {
            state_dir,
            deployment_file,
            runtime_selection_file,
        } => {
            let cancel = CancellationToken::new();
            let signal_cancel = cancel.clone();
            let signal = tokio::spawn(async move {
                let result = stop_signal().await;
                signal_cancel.cancel();
                result
            });
            let result = match (deployment_file, runtime_selection_file) {
                (Some(deployment), None) => {
                    styx_runtime::app::serve(
                        &state_dir,
                        &deployment,
                        tokio::io::stdin(),
                        tokio::io::stdout(),
                        cancel,
                    )
                    .await
                }
                (None, Some(selection)) => {
                    styx_runtime::app::serve_native(
                        &state_dir,
                        &selection,
                        tokio::io::stdin(),
                        tokio::io::stdout(),
                        cancel,
                    )
                    .await
                }
                _ => return error("app_startup_invalid"),
            };
            let signal_failed = if signal.is_finished() {
                !matches!(signal.await, Ok(Ok(())))
            } else {
                signal.abort();
                let _ = signal.await;
                false
            };
            if signal_failed {
                return error("signal_listener_failed");
            }
            match result {
                Ok(()) => ExitCode::SUCCESS,
                Err(value) => error(value.code()),
            }
        }
        Command::LinuxDesktopProbe => desktop_probe_worker().await,
        Command::LinuxDesktopWatch => desktop_watch_worker().await,
        Command::LinuxDesktopAssociation { candidate } => {
            desktop_association_worker(&candidate).await
        }
        Command::LinuxDesktopAssociationCheck { candidate } => {
            desktop_association_check(&candidate).await
        }
        Command::Init {
            parent_dir,
            name,
            deployment_file,
            mode,
            manager,
            host,
            gateway,
            json,
        } => {
            let options = styx_runtime::management::native::NativeCreateOptions {
                mode: mode.native(),
                manager: manager.native(),
                host,
                gateway,
            };
            native_result(
                styx_runtime::management::native::initialize(
                    &parent_dir,
                    &name,
                    &deployment_file,
                    options,
                )
                .await,
                json,
                "Native configuration initialized with stopped/disabled intent; no service started:",
            )
        }
        Command::Plan {
            native: true,
            state_dir,
            json,
            component,
            run,
            transaction_id,
            sequence,
        } => {
            let (Some(component), Some(run), Some(transaction_id), Some(sequence)) =
                (component, run, transaction_id, sequence)
            else {
                return error("native_plan_arguments_required");
            };
            let Ok(transaction_id) =
                styx_contracts::identity::TransactionId::try_from(transaction_id)
            else {
                return error("invalid_transaction_id");
            };
            let change = styx_runtime::management::native::NativeDesiredChange {
                component: component.native(),
                run: run.native(),
                transaction_id,
                sequence,
            };
            native_result(
                styx_runtime::management::native::plan(&state_dir, change).await,
                json,
                "Native desired-state plan prepared for review; no service changed:",
            )
        }
        Command::Apply {
            state_dir,
            plan_file,
            authorize,
            json,
        } => {
            if !authorize {
                return error("authorization_required");
            }
            native_result(
                styx_runtime::management::native::apply(&state_dir, &plan_file).await,
                json,
                "Native desired-state transaction; inspect report for completion:",
            )
        }
        Command::MigrateReview {
            state_dir,
            runtime_selection_file,
            transaction_id,
            run,
            json,
        } => native_result(
            styx_runtime::management::native::review_migration(
                &state_dir,
                &runtime_selection_file,
                &transaction_id,
                run.native(),
            )
            .await,
            json,
            "Review the exact migration request before authorizing Startup exclusion:",
        ),
        Command::Migrate {
            state_dir,
            runtime_selection_file,
            transaction_id,
            run,
            authorize,
            plan_sha256,
            json,
        } => {
            if !authorize {
                return error("authorization_required");
            }
            native_recovery_result(
                styx_runtime::management::native::migrate_with_approval(
                    &state_dir,
                    &runtime_selection_file,
                    &transaction_id,
                    run.native(),
                    plan_sha256.as_deref(),
                )
                .await,
                json,
                "Original paired Host migration; inspect the report for completion:",
            )
        }
        Command::Recover {
            state_dir,
            transaction_id,
            authorize,
            json,
        } => {
            if !authorize {
                return error("authorization_required");
            }
            let result =
                styx_runtime::management::native::recover(&state_dir, &transaction_id).await;
            native_recovery_result(
                result,
                json,
                "Original native transaction reconciliation; no automatic service start:",
            )
        }
        Command::Transaction {
            state_dir,
            transaction_id,
            json,
        } => native_result(
            styx_runtime::management::native::inspect(&state_dir, Some(&transaction_id)).await,
            json,
            "Read-only native transaction report:",
        ),
        Command::Status {
            native: true,
            state_dir,
            json,
        } => native_result(
            styx_runtime::management::native::inspect(&state_dir, None).await,
            json,
            "Read-only native configuration report:",
        ),
        Command::Plan {
            native: false,
            state_dir,
            json,
            ..
        } => match styx_runtime::management::inspect_deployment(&state_dir).await {
            Ok(plan) => {
                if !json {
                    eprintln!(
                        "Configuration intent; runtime health and management ownership are unobserved:"
                    );
                }
                if write_json(&plan).is_err() {
                    error("output_unavailable")
                } else {
                    ExitCode::SUCCESS
                }
            }
            Err(value) => error(value.code()),
        },
        Command::Release {
            command:
                ReleaseCommand::Select {
                    state_dir,
                    runtime_selection_file,
                    transaction_id,
                    sequence,
                    authorize,
                    json,
                },
        } => {
            if !authorize {
                return error("native_management_authorization_required");
            }
            match styx_runtime::management::native::update::select_runtime(
                &state_dir,
                &runtime_selection_file,
                &transaction_id,
                sequence,
            )
            .await
            {
                Ok(report) => {
                    if !json {
                        eprintln!(
                            "Stopped profile runtime selection committed; start the role explicitly."
                        );
                    }
                    if write_json(&report).is_ok() {
                        ExitCode::SUCCESS
                    } else {
                        eprintln!(
                            "{}",
                            serde_json::json!({"schema":1,"error":"output_unavailable","outcome":"unknown","operations_replayed":false})
                        );
                        ExitCode::from(4)
                    }
                }
                Err(value) => {
                    eprintln!("{}", native_error_output(&value));
                    ExitCode::from(value.exit_code())
                }
            }
        }
        Command::Release {
            command:
                ReleaseCommand::Stage {
                    payload_dir,
                    publisher_file,
                    expected_publisher,
                    parent_dir,
                    name,
                    authorize,
                    json,
                },
        } => {
            if !authorize {
                return error("native_release_authorization_required");
            }
            match styx_runtime::release::stage(
                &payload_dir,
                &publisher_file,
                &expected_publisher,
                &parent_dir,
                &name,
            )
            .await
            {
                Ok(selection) => {
                    if !json {
                        eprintln!(
                            "Verified runtime staged; no configuration or running component changed."
                        );
                    }
                    if write_json(&serde_json::json!({
                        "schema": 1, "operation": "release_stage", "staged": true,
                        "installed": false, "runtime_launched": false, "operations_replayed": false,
                        "runtime_selection": selection,
                    }))
                    .is_ok()
                    {
                        ExitCode::SUCCESS
                    } else {
                        eprintln!(
                            "{}",
                            serde_json::json!({"schema":1,"error":"output_unavailable","outcome":"unknown","operations_replayed":false})
                        );
                        ExitCode::from(4)
                    }
                }
                Err(value) => {
                    eprintln!(
                        "{}",
                        serde_json::json!({"schema":1,"error":value.code(),"operations_replayed":false})
                    );
                    ExitCode::from(value.exit_code())
                }
            }
        }
        Command::Release {
            command:
                ReleaseCommand::Verify {
                    payload_dir,
                    publisher_file,
                    expected_publisher,
                    json,
                    runtime_selection,
                },
        } => {
            if runtime_selection {
                return match styx_runtime::release::inspect_selection(
                    &payload_dir,
                    &publisher_file,
                    &expected_publisher,
                )
                .await
                {
                    Ok(selection) => {
                        if write_json(&selection).is_ok() {
                            ExitCode::SUCCESS
                        } else {
                            error("output_unavailable")
                        }
                    }
                    Err(value) => error(value.code()),
                };
            }
            match styx_runtime::release::inspect(&payload_dir, &publisher_file, &expected_publisher)
                .await
            {
                Ok(report) => {
                    if !json {
                        eprintln!(
                            "Offline release verification; no installation or runtime activation:"
                        );
                    }
                    if write_json(&report).is_err() {
                        error("output_unavailable")
                    } else {
                        ExitCode::SUCCESS
                    }
                }
                Err(value) => {
                    eprintln!("{}", serde_json::json!({"schema":1,"error":value.code()}));
                    ExitCode::from(value.exit_code())
                }
            }
        }
        Command::BuildInfo { json } => {
            if json {
                return if write_json(&native_build_info()).is_ok() {
                    ExitCode::SUCCESS
                } else {
                    error("output_unavailable")
                };
            }
            println!(
                "styx {} contract={} stage={}",
                env!("CARGO_PKG_VERSION"),
                styx_contracts::CONTRACT_VERSION,
                styx_runtime::IMPLEMENTATION_STAGE
            );
            ExitCode::SUCCESS
        }
        Command::Host {
            command: HostCommand::Join { command },
        } => match command {
            HostJoinCommand::Request {
                parent_dir,
                name,
                deployment_file,
                json,
            } => join_result(
                styx_runtime::management::native_join::request(
                    &parent_dir,
                    &name,
                    &deployment_file,
                )
                .await,
                json,
            ),
            HostJoinCommand::Claim { state_dir, json } => join_result(
                styx_runtime::management::native_join::claim(&state_dir).await,
                json,
            ),
        },
        Command::Host {
            command: HostCommand::Start {
                state_dir, json, ..
            },
        } => transient_manager::start(state_dir, json).await,
        Command::Host {
            command:
                HostCommand::Status {
                    state_dir,
                    owner_file,
                    json,
                    ..
                },
        } => transient_manager::query(state_dir, owner_file, json).await,
        Command::Host {
            command:
                HostCommand::Stop {
                    state_dir: Some(state_dir),
                    transient: true,
                    owner_file: Some(owner_file),
                    expected_invocation: Some(expected),
                    json,
                },
        } => transient_manager::stop(state_dir, owner_file, expected, json).await,
        Command::Gateway {
            command:
                GatewayCommand::Invite {
                    state_dir,
                    invitation_file,
                    ttl_seconds,
                    json,
                    ..
                },
        } => gateway_admin_result(
            styx_runtime::management::native_gateway_admin::invite(
                &state_dir,
                &invitation_file,
                ttl_seconds,
            )
            .await,
            json,
        ),
        Command::Gateway {
            command: GatewayCommand::Pending { state_dir, json },
        } => gateway_admin_result(
            styx_runtime::management::native_gateway_admin::pending(&state_dir).await,
            json,
        ),
        Command::Gateway {
            command:
                GatewayCommand::Approve {
                    state_dir,
                    request_id,
                    device_id,
                    fingerprint,
                    comparison_code,
                    enable_computer,
                    enable_browser,
                    json,
                    ..
                },
        } => {
            let Ok(device_id) = styx_contracts::identity::DeviceId::try_from(device_id) else {
                return error("native_gateway_admin_input");
            };
            let Ok(fingerprint) = styx_contracts::identity::Sha256Digest::try_from(fingerprint)
            else {
                return error("native_gateway_admin_input");
            };
            let selected = styx_runtime::management::native_gateway_admin::ApprovalSelection {
                request_id,
                device_id,
                fingerprint,
                comparison_code,
                enable_computer,
                enable_browser,
            };
            gateway_admin_result(
                styx_runtime::management::native_gateway_admin::approve(&state_dir, selected).await,
                json,
            )
        }
        Command::Gateway {
            command:
                GatewayCommand::Bootstrap {
                    parent_dir,
                    name,
                    deployment_file,
                    runtime_selection_file,
                    json,
                },
        } => {
            match styx_runtime::management::native_gateway::bootstrap(
                &parent_dir,
                &name,
                &deployment_file,
                &runtime_selection_file,
            )
            .await
            {
                Ok(value) => {
                    if !json {
                        eprintln!(
                            "Fresh Gateway-only foreground configuration initialized; Gateway not started:"
                        );
                    }
                    if write_json(&value).is_err() {
                        error("output_unavailable")
                    } else {
                        ExitCode::SUCCESS
                    }
                }
                Err(value) => {
                    // Retain the owned error through output, as for native_result.
                    eprintln!("{}", serde_json::json!({"schema":1,"error":value.code()}));
                    ExitCode::from(value.exit_code())
                }
            }
        }
        Command::Gateway {
            command: GatewayCommand::Run {
                state_dir: Some(state_dir),
            },
        } => {
            let cancel = CancellationToken::new();
            let (events, mut received) = tokio::sync::mpsc::channel(16);
            let event_cancel = cancel.clone();
            let output = tokio::spawn(async move {
                let mut healthy = true;
                while let Some(event) = received.recv().await {
                    if healthy && write_json(&event).is_err() {
                        healthy = false;
                        event_cancel.cancel();
                    }
                }
                healthy
            });
            let mut signal_failed = false;
            let outcome = {
                let running = foreground::gateway_run(&state_dir, cancel.clone(), events);
                tokio::pin!(running);
                tokio::select! {
                    result = &mut running => result,
                    signal = stop_signal() => {
                        signal_failed = signal.is_err();
                        cancel.cancel();
                        // The original owned future retains its leases until
                        // tracked connections, native owners and workers settle.
                        running.await
                    },
                }
            };
            let output_healthy = output.await.unwrap_or(false);
            if signal_failed {
                return error("signal_listener_failed");
            }
            if !output_healthy {
                return error("output_unavailable");
            }
            match outcome {
                Ok(outcome) => {
                    if write_json(&outcome).is_err() {
                        return error("output_unavailable");
                    }
                    if outcome.is_complete() {
                        ExitCode::SUCCESS
                    } else if outcome.local_stop_complete()
                        && (outcome.unconfirmed_owner_cleanups > 0
                            || outcome.unconfirmed_transport_drains > 0)
                        && !outcome.worker_failure_observed
                        && !outcome.listener_error_observed
                    {
                        // A stopped local Gateway is not proof of remote native
                        // cleanup. Keep that uncertainty visible and nonzero.
                        eprintln!(
                            "{}",
                            serde_json::json!({"schema":1,"error":if outcome.unconfirmed_owner_cleanups > 0 {
                                "remote_owner_cleanup_unconfirmed"
                            } else {
                                "remote_transport_drain_unconfirmed"
                            }})
                        );
                        ExitCode::from(4)
                    } else {
                        error("gateway_shutdown_unknown")
                    }
                }
                Err(error_value) => error(error_value.code()),
            }
        }
        Command::Gateway {
            command: GatewayCommand::Run { state_dir: None },
        } => error("gateway_input_required"),
        Command::Host {
            command:
                HostCommand::Stop { .. } | HostCommand::Pause { .. } | HostCommand::Resume { .. },
        } => error("unsupported"),
        Command::Doctor {
            desktop_sessions: true,
            watch: true,
            json,
            ..
        } => desktop_watch_diagnostics(json).await,
        Command::Doctor {
            desktop_sessions: true,
            json,
            ..
        } => desktop_diagnostics(json).await,
        Command::Status {
            native: false,
            state_dir,
            json,
        }
        | Command::Doctor {
            state_dir: Some(state_dir),
            json,
            ..
        } => {
            match foreground::inspect(&state_dir).await {
                Ok(diagnostics) => {
                    // The same redacted diagnostics are used in both modes;
                    // --json commits to one JSON line for machine consumers.
                    if !json {
                        eprintln!("Read-only deployment diagnostics:");
                    }
                    if write_json(&diagnostics).is_err() {
                        return error("output_unavailable");
                    }
                    ExitCode::SUCCESS
                }
                Err(error_value) => error(error_value.code()),
            }
        }
        Command::Doctor {
            state_dir: None, ..
        } => error("doctor_input_required"),
        Command::Host {
            command:
                HostCommand::Run {
                    state_dir,
                    legacy_gateway,
                },
        } => {
            let cancel = CancellationToken::new();
            let (events, mut received) = tokio::sync::mpsc::channel(16);
            let event_cancel = cancel.clone();
            let output = tokio::spawn(async move {
                let mut healthy = true;
                while let Some(event) = received.recv().await {
                    if healthy && write_json(&event).is_err() {
                        healthy = false;
                        event_cancel.cancel();
                    }
                }
                healthy
            });
            let mut signal_failed = false;
            let outcome = {
                let running = foreground::host_run(
                    &state_dir,
                    if legacy_gateway {
                        HostWireMode::LegacyExplicit
                    } else {
                        HostWireMode::PairedV3
                    },
                    cancel.clone(),
                    events,
                );
                tokio::pin!(running);
                tokio::select! {
                    result=&mut running=>result,
                    signal=stop_signal()=>{
                        signal_failed = signal.is_err();
                        cancel.cancel();
                        // Keep the SAME foreground future alive for real bounded
                        // cleanup. Dropping it or exiting here would fake stop.
                        running.await
                    },
                }
            };
            let output_healthy = output.await.unwrap_or(false);
            if signal_failed {
                return error("signal_listener_failed");
            }
            if !output_healthy {
                return error("output_unavailable");
            }
            match outcome {
                Ok(outcome) => {
                    if write_json(&outcome).is_err() {
                        return error("output_unavailable");
                    }
                    if outcome.is_complete() {
                        ExitCode::SUCCESS
                    } else {
                        error("host_shutdown_unknown")
                    }
                }
                Err(error_value) => error(error_value.code()),
            }
        }
    }
}
#[path = "cli_manager.rs"]
mod transient_manager;

#[cfg(test)]
#[path = "cli_tests.rs"]
mod tests;

/// This binary's closed reader declaration, consumed only with build/source/hash
/// evidence. It does not claim installed state, readiness or platform acceptance.
fn native_build_info() -> serde_json::Value {
    let target = if cfg!(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu"
    )) {
        "x86_64-unknown-linux-gnu"
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        "aarch64-apple-darwin"
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        "x86_64-apple-darwin"
    } else if cfg!(all(
        target_os = "windows",
        target_arch = "x86_64",
        target_env = "msvc"
    )) {
        "x86_64-pc-windows-msvc"
    } else {
        "unsupported"
    };
    serde_json::json!({
        "schema": 1, "target": target,
        "minimum_release_reader": styx_contracts::native_release::NativeReleaseReader::NativeAppServiceTransferredV1,
        "supported_state_readers": [
            styx_contracts::management::ReaderContract::NativeManagementStateV1,
            styx_contracts::management::ReaderContract::NativeMigratedStateV1,
            styx_contracts::management::ReaderContract::NativeMigratedStateV2,
            styx_contracts::management::ReaderContract::NativeRuntimeSelectedStateV1,
            styx_contracts::management::ReaderContract::NativeAppRuntimeSelectedStateV1,
            styx_contracts::management::ReaderContract::NativeServiceRuntimeSelectedStateV1,
            styx_contracts::management::ReaderContract::NativeAppServiceTransferredStateV1
        ]
    })
}
