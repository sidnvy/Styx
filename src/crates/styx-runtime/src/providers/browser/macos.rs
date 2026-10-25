//! Darwin Browser startup over the existing signed-image suspension barrier.
//! No App/TCC ownership or publisher authority is inferred from a pathname.
use super::*;
use crate::platform::macos_spawn;
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
            live.child = Some(child);
            Ok(())
        }
        Started::Refused(child) => {
            live.suspended = child;
            Err(BrowserError::SpawnFailed)
        }
    }
}
