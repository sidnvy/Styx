use super::AppError;
use crate::management::{native, native_join};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EmptyInput {}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) enum Operation {
    Computers,
    InviteComputer,
    PendingComputers,
    ApproveComputer,
    RejectComputer,
    RevokeComputer,
    TunnelStatus,
    TunnelSave,
    PluginRead,
    PluginSave,
    PluginExport,
    StartupStatus,
    Status,
    NetworkInterfaces,
    CreateLocal,
    ResumeLocal,
    RequestJoin,
    InspectJoin,
    Join,
    ClaimJoin,
    InspectHost,
    Connect,
    Disconnect,
    QuitAdmission,
    RetireRole,
    PrepareAppMaintenance,
    AppMaintenanceStatus,
    CancelAppMaintenance,
    AppLifecycle,
    AppLogin,
    AppLoginResult,
    StageRuntime,
    UpdateRuntime,
    RuntimeUpdateStatus,
    RecoverRuntimeUpdate,
    TransferToService,
    ServiceStatus,
    PrepareServiceFirstStart,
    StopService,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub(super) schema: u16,
    pub(super) id: u32,
    pub(super) operation: Operation,
    pub(super) input: Box<serde_json::value::RawValue>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InspectJoinInput {
    #[serde(deserialize_with = "secret_string")]
    pub(super) link: zeroize::Zeroizing<String>,
}

fn secret_string<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<zeroize::Zeroizing<String>, D::Error> {
    String::deserialize(d).map(zeroize::Zeroizing::new)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct JoinInput {
    pub(super) approved_gateway_origin: String,
    pub(super) approved_ca_sha256: Option<String>,
    pub(super) label: String,
    pub(super) computer: bool,
    pub(super) browser: bool,
    pub(super) browser_channel: Option<String>,
    pub(super) persist_login: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct LocalInput {
    pub(super) label: String,
    pub(super) computer: bool,
    pub(super) browser: bool,
    pub(super) browser_channel: Option<String>,
    pub(super) persist_login: bool,
    #[serde(default = "local_port")]
    pub(super) port: u16,
    #[serde(default)]
    pub(super) lan_address: Option<String>,
    #[serde(default)]
    pub(super) allow_remote_hosts: bool,
}

fn local_port() -> u16 {
    22022
}

pub(super) fn validate_choice(choice: &JoinInput) -> Result<(), AppError> {
    if choice.label.trim().is_empty()
        || choice.label.len() > 128
        || choice.label.chars().any(char::is_control)
        || choice
            .browser_channel
            .as_deref()
            .is_some_and(|v| !matches!(v, "chrome" | "msedge" | "chromium"))
    {
        return Err(AppError("app_input_invalid"));
    }
    Ok(())
}

pub(super) fn now_ms() -> Result<u64, AppError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .ok_or(AppError("app_clock_unavailable"))
}

pub(super) fn decode_input<T: serde::de::DeserializeOwned>(
    value: &serde_json::value::RawValue,
) -> Result<T, AppError> {
    serde_json::from_str(value.get()).map_err(|_| AppError("app_input_invalid"))
}

#[derive(Clone, Serialize)]
pub(super) struct ConnectionStatus {
    pub(super) status: &'static str,
    #[serde(rename = "execConnection")]
    pub(super) exec_connection: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) error: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) hint: Option<&'static str>,
    #[serde(
        rename = "computerStartupError",
        skip_serializing_if = "Option::is_none"
    )]
    pub(super) computer_error: Option<&'static str>,
    #[cfg(target_os = "macos")]
    #[serde(
        rename = "computerStartupProbe",
        skip_serializing_if = "Option::is_none"
    )]
    pub(super) computer_probe: Option<crate::providers::cua::probe_diagnostic::ProbeDiagnostic>,
    #[cfg(target_os = "macos")]
    #[serde(
        rename = "computerInitialEpochAdvanced",
        skip_serializing_if = "Option::is_none"
    )]
    pub(super) computer_initial_epoch_advanced: Option<bool>,
}

impl ConnectionStatus {
    pub(super) fn pairing_refused() -> Self {
        Self {
            status: "stopped",
            exec_connection: "disconnected",
            error: Some("gateway_wss_admission_refused"),
            computer_error: None,
            #[cfg(target_os = "macos")]
            computer_probe: None,
            #[cfg(target_os = "macos")]
            computer_initial_epoch_advanced: None,
            hint: Some(
                "The Gateway refused this identity. Change this computer's role and pair again.",
            ),
        }
    }
    pub(super) fn hub_full() -> Self {
        Self {
            status: "hub_full",
            // Existing native views display this field as text. Keep the
            // actionable message visible without requiring a native UI change.
            exec_connection: crate::gateway::paired::CAPACITY_HINT,
            error: Some(crate::gateway::paired::CAPACITY_ERROR_CODE),
            computer_error: None,
            #[cfg(target_os = "macos")]
            computer_probe: None,
            #[cfg(target_os = "macos")]
            computer_initial_epoch_advanced: None,
            hint: Some(crate::gateway::paired::CAPACITY_HINT),
        }
    }
    pub(super) fn stopped() -> Self {
        Self {
            status: "stopped",
            exec_connection: "disconnected",
            error: None,
            hint: None,
            computer_error: None,
            #[cfg(target_os = "macos")]
            computer_probe: None,
            #[cfg(target_os = "macos")]
            computer_initial_epoch_advanced: None,
        }
    }
    pub(super) fn unknown() -> Self {
        Self {
            status: "unknown",
            exec_connection: "unknown",
            error: None,
            hint: None,
            computer_error: None,
            #[cfg(target_os = "macos")]
            computer_probe: None,
            #[cfg(target_os = "macos")]
            computer_initial_epoch_advanced: None,
        }
    }
}

pub(super) enum RetainedFailure {
    Join(native_join::JoinError),
    Management(native::NativeManagementError),
    Bootstrap(crate::management::native_gateway::BootstrapError),
}

impl RetainedFailure {
    pub(super) fn code(&self) -> &'static str {
        match self {
            Self::Join(e) => e.code(),
            Self::Management(e) => e.code(),
            Self::Bootstrap(e) => e.code(),
        }
    }
}

#[derive(Serialize)]
#[serde(untagged)]
pub(crate) enum AppEnrollment {
    Report(native_join::JoinReport),
    Incomplete {
        status: &'static str,
        error: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        can_resume_local: Option<bool>,
    },
    LocalCheckpoint {
        status: &'static str,
        can_resume_local: bool,
    },
    RuntimeUpdatePending {
        status: &'static str,
    },
    #[cfg(test)]
    StatusOnly {
        status: native_join::JoinStatus,
    },
}

impl AppEnrollment {
    pub(crate) const fn incomplete(error: &'static str) -> Self {
        Self::Incomplete {
            status: "incomplete",
            error,
            can_resume_local: None,
        }
    }
    pub(crate) const fn incomplete_local(error: &'static str) -> Self {
        Self::Incomplete {
            status: "incomplete",
            error,
            can_resume_local: Some(false),
        }
    }
    pub(crate) const fn local_pre_invite() -> Self {
        Self::LocalCheckpoint {
            status: "local_setup_pre_invite",
            can_resume_local: true,
        }
    }
    pub(crate) const fn local_continuation_dispatched() -> Self {
        Self::LocalCheckpoint {
            status: "local_setup_continuation_dispatched",
            can_resume_local: false,
        }
    }
    pub(crate) const fn runtime_update_pending() -> Self {
        Self::RuntimeUpdatePending {
            status: "runtime_update_pending",
        }
    }
    #[cfg(test)]
    pub(crate) const fn ready_for_test() -> Self {
        Self::StatusOnly {
            status: native_join::JoinStatus::ReadyToConnect,
        }
    }
    #[cfg(test)]
    pub(crate) const fn status(&self) -> &'static str {
        match self {
            Self::Report(report) => report.status.as_str(),
            Self::StatusOnly { status } => status.as_str(),
            Self::Incomplete { status, .. }
            | Self::LocalCheckpoint { status, .. }
            | Self::RuntimeUpdatePending { status } => status,
        }
    }
    pub(crate) const fn is_ready(&self) -> bool {
        match self {
            Self::Report(report) => report.status.is_ready(),
            #[cfg(test)]
            Self::StatusOnly { status } => status.is_ready(),
            _ => false,
        }
    }
    pub(crate) fn device_id(&self) -> Option<&str> {
        match self {
            Self::Report(report) => Some(report.device_id.as_str()),
            _ => None,
        }
    }
}
