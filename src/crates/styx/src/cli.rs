//! Process entry adapter. Runtime owns trusted profile admission and cleanup;
//! command arguments never supply credentials, executor binaries or authority.
use clap::{Parser, Subcommand};
use std::{
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
    /// Print build and contract identity; never claims a running service.
    BuildInfo,
    /// Run the explicitly configured native Host in this foreground process.
    Host {
        #[command(subcommand)]
        command: HostCommand,
    },
    /// Gateway foreground composition is not implemented by this CLI slice.
    Gateway {
        #[command(subcommand)]
        command: GatewayCommand,
    },
    /// Inspect the existing deployment without connecting or starting services.
    Status {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Validate existing profile/release inputs without mutation or execution.
    Doctor {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        json: bool,
    },
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
        Command::BuildInfo => {
            println!(
                "styx {} contract={} stage={}",
                env!("CARGO_PKG_VERSION"),
                styx_contracts::CONTRACT_VERSION,
                styx_runtime::IMPLEMENTATION_STAGE
            );
            ExitCode::SUCCESS
        }
        Command::Gateway { .. }
        | Command::Host {
            command:
                HostCommand::Stop { .. } | HostCommand::Pause { .. } | HostCommand::Resume { .. },
        } => error("unsupported"),
        Command::Status { state_dir, json } | Command::Doctor { state_dir, json } => {
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
