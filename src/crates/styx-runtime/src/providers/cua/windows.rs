//! Windows Cua process adapter. Fixed mcp --direct; original Job owns every
//! descendant. MCP close/cancel acknowledgement never proves physical cleanup.
use super::*;
use crate::platform::windows_spawn;

pub(super) async fn start(live: &mut Live, config: &OwnedCuaConfig) -> Result<()> {
    config
        .launch
        .source
        .fresh()
        .await
        .map_err(|_| CuaError::PermissionDenied)?;
    let partition = live.slot.as_ref().ok_or(CuaError::Unknown)?.clone();
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
        let child = windows_spawn::spawn_cua_suspended(
            config.driver,
            partition,
            config.workspace,
            environment,
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
        if child.start_kill().is_ok() {
            if let Ok(Ok(status)) = timeout_at(until, child.wait()).await {
                // wait() requires root_waited AND original Job ActiveProcesses0
                // AND actual original supervisor join; never termination ACK.
                live.exit_success = Some(status.success());
                live.scope_confirmed = true;
            }
        }
    } else if live.identity.is_none() {
        live.scope_confirmed = true; // Strict local pre-spawn failure only.
    }
}
