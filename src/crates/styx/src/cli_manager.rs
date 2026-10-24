//! Explicit transient-manager CLI transport. Owner data is an observation;
//! runtime revalidates the actual manager/scope/invocation on every mutation.
use super::error;
#[cfg(target_os = "linux")]
use super::write_json;
use std::{path::PathBuf, process::ExitCode};
#[cfg(target_os = "linux")]
use styx_runtime::platform::linux::manager;
#[cfg(target_os = "linux")]
use tokio_util::sync::CancellationToken;

#[cfg(target_os = "linux")]
fn result<T: serde::Serialize>(value: Result<T, manager::ManagerError>, json: bool) -> ExitCode {
    match value {
        Ok(value) => {
            if !json {
                eprintln!(
                    "Transient user-manager observation; no autostart or Host readiness claim."
                );
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

#[cfg(target_os = "linux")]
async fn owner_file(path: PathBuf) -> Result<manager::UnitRefDto, &'static str> {
    tokio::task::spawn_blocking(move || {
        if !path.is_absolute() {
            return Err("private_owner_file_required");
        }
        let root = styx_runtime::store::PrivateRoot::open(
            path.parent().ok_or("private_owner_file_required")?,
        )
        .map_err(|_| "private_owner_file_required")?;
        let raw = root
            .read_raw(
                std::path::Path::new(path.file_name().ok_or("private_owner_file_required")?),
                16 * 1024,
            )
            .map_err(|_| "private_owner_file_required")?;
        serde_json::from_slice(raw.bytes()).map_err(|_| "invalid_unit_owner_observation")
    })
    .await
    .map_err(|_| "owner_file_reader_failed")?
}

pub(super) async fn start(state_dir: PathBuf, json: bool) -> ExitCode {
    #[cfg(target_os = "linux")]
    {
        let cancel = CancellationToken::new();
        let mut signal_failed = false;
        let outcome = {
            let running = manager::start(&state_dir, cancel.clone());
            tokio::pin!(running);
            tokio::select! {
                result = &mut running => result,
                signal = super::stop_signal() => {
                    signal_failed = signal.is_err();
                    cancel.cancel();
                    running.await
                },
            }
        };
        if signal_failed {
            return error("signal_listener_failed");
        }
        // Explicit success hands lifetime to the native user-manager. Dropping
        // caller observation data never stops a successfully handed-off service.
        match outcome {
            Ok(owned) => result(Ok(owned.observation()), json),
            Err(value) => result::<manager::UnitRefDto>(Err(value), json),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (state_dir, json);
        error("transient_user_manager_platform_unsupported")
    }
}

pub(super) async fn query(state_dir: PathBuf, owner: Option<PathBuf>, json: bool) -> ExitCode {
    #[cfg(target_os = "linux")]
    {
        if let Some(path) = owner {
            let owner = match owner_file(path).await {
                Ok(value) => value,
                Err(code) => return error(code),
            };
            result(manager::query(&state_dir, &owner).await, json)
        } else {
            result(manager::list_scoped(&state_dir).await, json)
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (state_dir, owner, json);
        error("transient_user_manager_platform_unsupported")
    }
}

pub(super) async fn stop(
    state_dir: PathBuf,
    owner: PathBuf,
    expected: String,
    json: bool,
) -> ExitCode {
    #[cfg(target_os = "linux")]
    {
        let owner = match owner_file(owner).await {
            Ok(value) => value,
            Err(code) => return error(code),
        };
        result(manager::stop(&state_dir, &owner, &expected).await, json)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (state_dir, owner, expected, json);
        error("transient_user_manager_platform_unsupported")
    }
}
