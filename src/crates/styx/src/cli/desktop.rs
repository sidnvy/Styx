use super::{error, stop_signal, write_json};
#[cfg(target_os = "linux")]
use std::io;
use std::process::ExitCode;
#[cfg(target_os = "linux")]
use tokio_util::sync::CancellationToken;

pub(super) async fn desktop_association_check(candidate: &str) -> ExitCode {
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

pub(super) async fn desktop_association_worker(candidate: &str) -> ExitCode {
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

pub(super) async fn desktop_probe_worker() -> ExitCode {
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

pub(super) async fn desktop_watch_worker() -> ExitCode {
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
pub(super) async fn desktop_watch_diagnostics(json: bool) -> ExitCode {
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

pub(super) async fn desktop_diagnostics(json: bool) -> ExitCode {
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
