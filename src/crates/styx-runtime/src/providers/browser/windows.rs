//! Windows native Browser startup; Core still owns every operation and owner.
use super::*;
use crate::{platform::windows_spawn, store::PrivateRoot};

pub(super) async fn start(
    live: &mut Live,
    config: &OwnedBrowserConfig,
    partition: Arc<OwnedSemaphorePermit>,
) -> Result<()> {
    let config = config.clone();
    // Protected file I/O, PE hashing and native suspension are bounded blocking
    // work. The outer provider task owns this await even if its observer leaves.
    let startup = tokio::task::spawn_blocking(move || -> Result<_> {
        config.validate()?;
        let node_path = config
            .node_pin
            .source_path_for_suspended_spawn()
            .map_err(|_| BrowserError::PermissionDenied)?;
        if node_path != config.node_binary {
            return Err(BrowserError::PermissionDenied);
        }
        let root =
            PrivateRoot::open(&config.output_dir).map_err(|_| BrowserError::PermissionDenied)?;
        let name = format!("worker-{}.json", uuid::Uuid::new_v4().simple());
        let bytes = serde_json::to_vec(&serde_json::json!({
            "schema":1,"profile_dir":config.profile_dir,"output_dir":config.output_dir,
            "workspace_dir":config.workspace_dir,"browser_executable":config.browser_binary
        }))
        .map_err(|_| BrowserError::InvalidRequest)?;
        let (_observed, pin) = root
            .create_runtime_asset(&name, &bytes)
            .map_err(|_| BrowserError::SpawnFailed)?;
        let path = config.output_dir.join(name);
        let env = config
            .environment
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        let child = windows_spawn::spawn_browser_suspended(
            config.node_pin,
            partition,
            config.workspace_dir,
            env,
            config.worker_entry,
            path.clone(),
        )
        .and_then(|child| child.verify_and_resume());
        Ok((child, path, pin))
    })
    .await
    .map_err(|_| BrowserError::Unknown)??;
    let (child, config_file, pin) = startup;
    live.config_file = config_file;
    live.pins.push(pin);
    match child {
        Ok(child) => {
            live.child = Some(child);
            Ok(())
        }
        Err(error) => {
            live.child = error.into_owned_child();
            Err(BrowserError::SpawnFailed)
        }
    }
}
