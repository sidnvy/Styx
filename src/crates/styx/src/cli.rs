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
    // Fixed read-only worker mode; there are no target/credential/path options.
    #[command(name = "__linux-desktop-probe", hide = true)]
    LinuxDesktopProbe,
    #[command(name = "__linux-desktop-watch", hide = true)]
    LinuxDesktopWatch,
    /// Print build and contract identity; never claims a running service.
    BuildInfo,
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
#[derive(Clone, Copy, ValueEnum)]
enum NativeRunArg {
    Running,
    Stopped,
}
impl Cli {
    pub(crate) fn is_desktop_probe_worker(&self) -> bool {
        matches!(
            self.command,
            Command::LinuxDesktopProbe | Command::LinuxDesktopWatch
        )
    }
}
#[derive(Subcommand)]
enum HostCommand {
    Run {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        legacy_gateway: bool,
    },
    Stop {
        #[arg(long)]
        state_dir: Option<PathBuf>,
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
enum GatewayCommand {
    Run {
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ReleaseCommand {
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
#[cfg(not(unix))]
async fn stop_signal() -> io::Result<()> {
    tokio::signal::ctrl_c().await
}

pub(crate) async fn run(cli: Cli) -> ExitCode {
    use styx_runtime::foreground::{self, HostWireMode};
    match cli.command {
        Command::LinuxDesktopProbe => desktop_probe_worker().await,
        Command::LinuxDesktopWatch => desktop_watch_worker().await,
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
        Command::Recover {
            state_dir,
            transaction_id,
            authorize,
            json,
        } => {
            if !authorize {
                return error("authorization_required");
            }
            native_result(
                styx_runtime::management::native::recover(&state_dir, &transaction_id).await,
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
                ReleaseCommand::Verify {
                    payload_dir,
                    publisher_file,
                    expected_publisher,
                    json,
                },
        } => {
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
        Command::BuildInfo => {
            println!(
                "styx {} contract={} stage={}",
                env!("CARGO_PKG_VERSION"),
                styx_contracts::CONTRACT_VERSION,
                styx_runtime::IMPLEMENTATION_STAGE
            );
            ExitCode::SUCCESS
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
#[cfg(test)]
#[path = "cli_tests.rs"]
mod tests;
