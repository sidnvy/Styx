//! Darwin Browser startup over the existing signed-image suspension barrier.
//! No App/TCC ownership or publisher authority is inferred from a pathname.
use super::*;
use crate::platform::{macos_process_tree::ProcessTree, macos_spawn};
use std::{ffi::OsString, fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OriginalBrowserProcess {
    pub schema: u8,
    pub pid: u32,
    pub original_child_closed: bool,
}

enum Started {
    Running(macos_spawn::RunningChild),
    Refused(Option<macos_spawn::SuspendedChild>),
}

pub(super) async fn start(live: &mut Live, config: &OwnedBrowserConfig) -> Result<()> {
    live.launch_unconfirmed = true;
    let config = config.clone();
    let (started, path, pins) = tokio::task::spawn_blocking(move || -> Result<_> {
        config.validate()?;
        config
            .node_pin
            .revalidate()
            .map_err(|_| BrowserError::PermissionDenied)?;
        let node = config
            .node_pin
            .source_path_for_suspended_spawn()
            .map_err(|_| BrowserError::PermissionDenied)?;
        if node != config.node_binary {
            return Err(BrowserError::PermissionDenied);
        }
        let path = config
            .output_dir
            .join(format!("worker-{}.json", uuid::Uuid::new_v4().simple()));
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|_| BrowserError::SpawnFailed)?;
        let bytes = serde_json::to_vec(&serde_json::json!({
            "schema":1,"profile_dir":config.profile_dir,"output_dir":config.output_dir,
            "workspace_dir":config.workspace_dir,"browser_executable":config.browser_binary
        }))
        .map_err(|_| BrowserError::InvalidRequest)?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| BrowserError::SpawnFailed)?;
        // Both original adapter members and the runtime configuration remain
        // pinned in the same Live state until actual cleanup or retained failure.
        let worker = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&config.worker_entry)
            .map_err(|_| BrowserError::PermissionDenied)?;
        let environment = config
            .environment
            .into_iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)))
            .collect();
        let args = vec![
            config.worker_entry.into_os_string(),
            OsString::from("--config"),
            path.clone().into_os_string(),
        ];
        let result =
            macos_spawn::spawn_suspended(config.node_pin, args, config.workspace_dir, environment)
                .and_then(|child| child.verify_and_resume());
        let started = match result {
            Ok(child) => Started::Running(child),
            Err(error) => Started::Refused(error.into_owned_child()),
        };
        Ok((started, path, vec![file, worker]))
    })
    .await
    .map_err(|_| BrowserError::Unknown)??;
    live.config_file = path;
    live.pins.extend(pins);
    live.launch_unconfirmed = false;
    match started {
        Started::Running(child) => {
            live.process_tree = Some(ProcessTree::new(child.id()));
            live.child = Some(child);
            Ok(())
        }
        Started::Refused(child) => {
            live.suspended = child;
            Err(BrowserError::SpawnFailed)
        }
    }
}

pub(super) async fn stop(
    child: &mut macos_spawn::RunningChild,
    mut tree: Option<&mut ProcessTree>,
    until: Instant,
) -> (bool, Option<bool>, BrowserDescendants) {
    // EOF normally closes the persistent context. Reserve part of this same
    // budget for TERM, KILL and actual descendant exit observations.
    let remaining = until.saturating_duration_since(Instant::now());
    let terminate_at = Instant::now() + remaining / 2;
    let kill_at = terminate_at + remaining / 4;
    let mut terminated = false;
    let mut killed = false;
    let mut exit_success = None;
    loop {
        if let Some(tree) = tree.as_deref_mut() {
            tree.snapshot();
        }
        // wait() joins the original reaper as well as observing Node's exit.
        let next = until.min(Instant::now() + Duration::from_millis(100));
        match timeout_at(next, child.wait()).await {
            Ok(Ok(exit)) => {
                exit_success = Some(exit.success());
                break;
            }
            Ok(Err(_)) => break,
            Err(_) => {}
        }
        let now = Instant::now();
        if now >= terminate_at && !terminated {
            let _ = child.request_terminate();
            terminated = true;
        }
        if now >= kill_at && !killed {
            let _ = child.start_kill();
            killed = true;
        }
        if now >= until {
            break;
        }
    }

    let worker_exited = exit_success.is_some();
    if worker_exited && let Some(tree) = tree {
        // Chrome's detached Crashpad handler is outside ppid custody: it runs
        // only the signed system-browser image and exits with its client.
        let kill_at = Instant::now() + until.saturating_duration_since(Instant::now()) / 2;
        let mut killed = false;
        loop {
            if tree.confirmed_gone() {
                return (true, exit_success, BrowserDescendants::Confirmed);
            }
            let now = Instant::now();
            if now >= kill_at && !killed {
                tree.kill_remaining();
                killed = true;
            }
            if now >= until {
                break;
            }
            tokio::time::sleep_until(until.min(now + Duration::from_millis(100))).await;
        }
    }
    (worker_exited, exit_success, BrowserDescendants::Unknown)
}
