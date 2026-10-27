mod cli;
#[cfg(target_os = "linux")]
mod watch_output;
use clap::Parser;
use std::process::ExitCode;

fn main() -> ExitCode {
    let arguments = cli::Cli::parse();
    #[cfg(target_os = "windows")]
    if let Some(result) = arguments.dispatch_windows_service() {
        return result;
    }
    let worker = arguments.is_desktop_probe_worker();
    // A worker must be constrained before any Tokio threads/buffers exist.
    // Limits apply only to this child process, never a normal Host or CLI.
    #[cfg(target_os = "linux")]
    if worker && styx_runtime::session_probe::prepare_worker_limits().is_err() {
        eprintln!(r#"{{"schema":1,"error":"desktop_worker_limits_refused"}}"#);
        return ExitCode::from(2);
    }
    let mut builder = if worker {
        tokio::runtime::Builder::new_current_thread()
    } else {
        tokio::runtime::Builder::new_multi_thread()
    };
    match builder.enable_all().build() {
        Ok(runtime) => runtime.block_on(cli::run(arguments)),
        Err(_) => {
            eprintln!(r#"{{"schema":1,"error":"runtime_unavailable"}}"#);
            ExitCode::from(2)
        }
    }
}
