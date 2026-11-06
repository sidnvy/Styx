//! Current-user local App control. The original GUI owner performs Quit;
//! this client never edits configuration, adopts a role or signals a process.
#[cfg(target_os = "windows")]
use serde::Deserialize;
use serde::Serialize;
use std::path::Path;

#[derive(Clone, Copy)]
pub enum Operation {
    Status,
    Quit,
}
impl Operation {
    #[cfg(target_os = "windows")]
    fn name(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Quit => "quit",
        }
    }
}
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ControlError(pub &'static str);
#[derive(Debug, Serialize)]
pub struct Report {
    pub schema: u16,
    pub operation: &'static str,
    pub scope: &'static str,
    pub status: String,
    pub code: Option<String>,
    pub app_pid: Option<u32>,
    pub core_pid: Option<u32>,
    pub app_exited: Option<bool>,
    pub core_exited: Option<bool>,
    pub core_exit_observed_by: Option<&'static str>,
    pub starting: Option<bool>,
    pub busy: Option<bool>,
    pub app_exit_code: Option<u32>,
    pub core_exit_code: Option<i32>,
    pub operations_replayed: bool,
}
impl Report {
    #[cfg(target_os = "windows")]
    fn initial(operation: Operation) -> Self {
        Self {
            schema: 1,
            operation: operation.name(),
            scope: "local_app_owner",
            status: "unknown".into(),
            code: Some("app_control_response_unconfirmed".into()),
            app_pid: None,
            core_pid: None,
            app_exited: None,
            core_exited: None,
            core_exit_observed_by: None,
            starting: None,
            busy: None,
            app_exit_code: None,
            core_exit_code: None,
            operations_replayed: false,
        }
    }
    pub fn exit_code(&self) -> u8 {
        match self.status.as_str() {
            "exited" | "running" | "stopping" | "ready_to_exit" => 0,
            "busy" | "unavailable" => 3,
            _ => 4,
        }
    }
}
#[cfg(target_os = "windows")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Process {
    pid: u32,
    creation_file_time: String,
}
#[cfg(target_os = "windows")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Hello {
    schema: u16,
    kind: String,
    pid: u32,
    creation_file_time: String,
    owner_sid: String,
    state_directory: String,
    core: Option<Process>,
}
#[cfg(target_os = "windows")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CoreExit {
    pid: u32,
    creation_file_time: String,
    exit_code: i32,
    stdin_eof: bool,
    io_joined: bool,
}
#[cfg(target_os = "windows")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Outcome {
    status: String,
    code: Option<String>,
    core_exit: Option<CoreExit>,
    starting: Option<bool>,
    busy: Option<bool>,
}
#[cfg(target_os = "windows")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    schema: u16,
    id: String,
    result: Outcome,
}
pub async fn request(state_dir: &Path, operation: Operation) -> Result<Report, ControlError> {
    #[cfg(target_os = "windows")]
    {
        windows::request(state_dir, operation).await
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (state_dir, operation);
        Err(ControlError("local_app_control_windows_only"))
    }
}
#[cfg(target_os = "windows")]
mod windows;
