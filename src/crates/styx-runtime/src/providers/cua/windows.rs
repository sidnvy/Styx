//! Windows Cua process adapter: Host-owned shared `serve --socket <pipe>` plus
//! per-caller `mcp --socket <pipe>` proxy, each in a non-breakaway Job Object.
use super::*;
use crate::platform::windows_spawn;
use tokio::net::windows::named_pipe::ClientOptions;

pub(super) struct SharedWindowsDaemon {
    child: windows_spawn::RunningChild,
    socket: String,
    pid_file: PathBuf,
    stderr: Option<JoinHandle<std::io::Result<u64>>>,
}

pub(super) async fn ensure_daemon(
    slot: &tokio::sync::Mutex<Option<SharedWindowsDaemon>>,
    stop: &CancellationToken,
    config: &OwnedCuaConfig,
    until: Option<Instant>,
) -> Result<String> {
    let mut guard = slot.lock().await;
    if let Some(daemon) = guard.as_mut() {
        let alive = daemon.child.observed_exit().ok().flatten().is_none();
        if alive && ClientOptions::new().open(&daemon.socket).is_ok() {
            return Ok(daemon.socket.clone());
        }
        if let Some(mut dead) = guard.take() {
            let _ =
                tokio::time::timeout(Duration::from_secs(2), dead.child.terminate_and_wait()).await;
            if let Some(stderr) = dead.stderr.take() {
                let _ = tokio::time::timeout(Duration::from_secs(1), stderr).await;
            }
            let _ = std::fs::remove_file(&dead.pid_file);
        }
    }
    config
        .launch
        .source
        .fresh()
        .await
        .map_err(|_| CuaError::PermissionDenied)?;
    let socket = format!(r"\\.\pipe\styx-cua-{}", uuid::Uuid::new_v4().simple());
    let pid_file = config.workspace.join("cua-serve.pid");
    let config_clone = config.clone();
    let socket_clone = socket.clone();
    let pid_clone = pid_file.clone();
    let mut child = tokio::task::spawn_blocking(move || -> Result<windows_spawn::RunningChild> {
        config_clone.validate()?;
        if config_clone.launch.source.fenced() {
            return Err(CuaError::StaleObservation);
        }
        let environment = config_clone
            .environment
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        let suspended = windows_spawn::spawn_cua_serve_suspended(
            config_clone.driver,
            config_clone.workspace,
            environment,
            socket_clone,
            pid_clone,
        )
        .map_err(|_| CuaError::Unknown)?;
        if config_clone.launch.source.fenced() {
            let _ = suspended.cancel_unresumed();
            return Err(CuaError::StaleObservation);
        }
        suspended.verify_and_resume().map_err(|error| {
            let mut owned = error.into_owned_child();
            if let Some(child) = owned.as_mut() {
                let _ = child.start_kill();
            }
            CuaError::Unknown
        })
    })
    .await
    .map_err(|_| CuaError::Unknown)??;
    let stderr = child.take_stderr().map(|mut stderr| {
        tokio::spawn(async move { tokio::io::copy(&mut stderr, &mut tokio::io::sink()).await })
    });
    let ready_deadline = until.unwrap_or_else(|| Instant::now() + Duration::from_secs(10));
    loop {
        if stop.is_cancelled() {
            let _ = tokio::time::timeout(Duration::from_secs(2), child.terminate_and_wait()).await;
            return Err(CuaError::Unknown);
        }
        if ClientOptions::new().open(&socket).is_ok() {
            break;
        }
        if child.observed_exit().ok().flatten().is_some() || Instant::now() >= ready_deadline {
            let _ = tokio::time::timeout(Duration::from_secs(2), child.terminate_and_wait()).await;
            return Err(CuaError::Unknown);
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    *guard = Some(SharedWindowsDaemon {
        child,
        socket: socket.clone(),
        pid_file,
        stderr,
    });
    Ok(socket)
}

pub(super) async fn stop_daemon(
    slot: &tokio::sync::Mutex<Option<SharedWindowsDaemon>>,
    budget: Duration,
) {
    let mut guard = slot.lock().await;
    if let Some(mut daemon) = guard.take() {
        let _ = tokio::time::timeout(budget, daemon.child.terminate_and_wait()).await;
        if let Some(stderr) = daemon.stderr.take() {
            let _ = tokio::time::timeout(Duration::from_secs(1), stderr).await;
        }
        let _ = std::fs::remove_file(&daemon.pid_file);
    }
}

pub(super) async fn start(live: &mut Live, config: &OwnedCuaConfig, socket: String) -> Result<()> {
    config
        .launch
        .source
        .fresh()
        .await
        .map_err(|_| CuaError::PermissionDenied)?;
    let config = config.clone();
    // Owned open task awaits the actual blocking job even when public observer
    // disconnects. Native suspension/image checks never run on Host's mutex.
    let started = tokio::task::spawn_blocking(move || -> Result<_> {
        config.validate()?;
        if config.launch.source.fenced() {
            return Err(CuaError::StaleObservation);
        }
        let environment = config
            .environment
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        let child = windows_spawn::spawn_cua_proxy_suspended(
            config.driver,
            config.workspace,
            environment,
            socket,
        );
        Ok(match child {
            Ok(child) => {
                let identity = Some(child.identity().clone());
                if config.launch.source.fenced() {
                    (Ok(child.cancel_unresumed()), identity, true)
                } else {
                    (child.verify_and_resume(), identity, false)
                }
            }
            Err(error) => (Err(error), None, false),
        })
    })
    .await
    .map_err(|_| CuaError::Unknown)??;
    let (child, identity, cancelled_before_resume) = started;
    live.identity = identity;
    match child {
        Ok(child) => live.child = Some(child),
        Err(error) => {
            live.child = error.into_owned_child();
            return Err(CuaError::Unknown);
        }
    }
    if cancelled_before_resume {
        return Err(CuaError::StaleObservation);
    }
    // A post-spawn failure retains the original child in Live and can never be
    // relabelled NotDispatched or retried through a replacement worker.
    config_source_fresh(live).await
}
async fn config_source_fresh(live: &Live) -> Result<()> {
    live.config
        .launch
        .source
        .fresh()
        .await
        .map_err(|_| CuaError::StaleObservation)
}
pub(super) async fn stop(live: &mut Live, until: Instant) {
    if let Some(child) = live.child.as_mut() {
        child.take_stdin();
        child.take_stdout();
        child.take_stderr();
        // cleanup() already owns client.close(), which sends MCP EOF. Wait
        // for that same proxy to drain; terminating its Job here raced the
        // normal close and turned a successful session into exit code 1.
        // A deadline leaves the original child retained and cleanup unproven.
        if let Ok(Ok(status)) = timeout_at(until, child.wait()).await {
            // wait() requires root_waited AND original Job ActiveProcesses0
            // AND actual original supervisor join; never an EOF acknowledgement.
            live.exit_success = Some(status.success());
            live.scope_confirmed = true;
        }
    } else if live.identity.is_none() {
        live.scope_confirmed = true; // Strict local pre-spawn failure only.
    }
}
