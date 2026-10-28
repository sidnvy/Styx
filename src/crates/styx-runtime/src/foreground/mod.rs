//! Foreground composition; CLI and later native UI share these authority ports.
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
mod browser;
#[cfg(any(target_os = "linux", target_os = "windows"))]
mod computer;
#[cfg(target_os = "macos")]
#[path = "computer_macos.rs"]
mod computer;
pub mod profile;
#[cfg(target_os = "windows")]
mod windows_env;
pub use profile::ProfileDiagnostics;
use serde::Serialize;
use std::path::Path;
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HostWireMode {
    PairedV3,
}
#[derive(Serialize)]
pub struct ForegroundEvent {
    pub schema: u32,
    pub event: &'static str,
    /// Fixed category only; never profile contents, native output or credentials.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    pub device_id: Option<styx_contracts::identity::DeviceId>,
    pub connection_generation: Option<styx_contracts::identity::ConnectionGeneration>,
}
#[derive(Serialize)]
pub struct ForegroundOutcome {
    pub schema: u32,
    /// False means no executor was configured/started, never an inferred wait.
    pub executor_started: bool,
    pub executor_exited: bool,
    pub processes_exited: bool,
    pub io_tasks_joined: bool,
    pub supervised_jobs_joined: bool,
    /// Only negotiated paired transport settlement; legacy has no such proof.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_transport_drain: Option<crate::host::protocol::wire::TransportDrainOutcome>,
}
impl ForegroundOutcome {
    pub fn local_stop_complete(&self) -> bool {
        (!self.executor_started || self.executor_exited)
            && self.processes_exited
            && self.io_tasks_joined
            && self.supervised_jobs_joined
    }
    pub fn is_complete(&self) -> bool {
        self.local_stop_complete()
            && self.remote_transport_drain.is_none_or(|outcome| {
                outcome == crate::host::protocol::wire::TransportDrainOutcome::Complete
            })
    }
}
#[derive(Debug, thiserror::Error)]
#[error("foreground admission or cleanup refused")]
pub struct ForegroundError(&'static str);
impl ForegroundError {
    pub fn code(&self) -> &'static str {
        self.0
    }
}
impl From<profile::ProfileError> for ForegroundError {
    fn from(e: profile::ProfileError) -> Self {
        Self(e.code())
    }
}
pub async fn inspect(state_dir: &Path) -> Result<ProfileDiagnostics, ForegroundError> {
    let path = state_dir.to_path_buf();
    tokio::task::spawn_blocking(move || {
        profile::load_legacy(&path).and_then(|p| p.revalidate().map(|()| p.into_diagnostics()))
    })
    .await
    .map_err(|_| ForegroundError("profile_reader_failed"))?
    .map_err(Into::into)
}
mod run;
#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "macos",
    target_os = "windows"
))]
pub(crate) use gateway::gateway_run_for_service;
pub use run::host_run;
#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "windows",
    target_os = "macos"
))]
pub(crate) use run::host_run_for_app;
#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "macos",
    target_os = "windows"
))]
pub(crate) use run::host_run_for_service;
mod gateway;
pub mod tunnel;
#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
    all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"),
    all(
        target_os = "macos",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
pub(crate) use gateway::StartupTransportClosure;
pub(crate) use gateway::{AppGatewayError, gateway_run_for_app};
pub use gateway::{GatewayForegroundOutcome, gateway_run};

/// Read OS candidates for the actual invoking user. No state/profile, environment
/// display hint, remote UID, registration authority or native executor is used.
#[cfg(target_os = "linux")]
pub async fn discover_desktop_candidates()
-> Result<crate::platform::linux::LinuxDiscoverySnapshot, ForegroundError> {
    crate::session_probe::probe_current_user()
        .await
        .map_err(|error| ForegroundError(error.code()))
}

/// Owned-App read-only Host admission diagnostics. Does not start a connector,
/// acquire an execution lease, install a service or authorize a remote tool.
#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "windows",
    target_os = "macos"
))]
pub(crate) async fn inspect_for_app(
    scope: std::sync::Arc<crate::app::HostScope>,
) -> Result<ProfileDiagnostics, ForegroundError> {
    tokio::task::spawn_blocking(move || {
        let profile = profile::load_for_app(scope)?;
        profile.revalidate()?;
        Ok(profile.into_diagnostics())
    })
    .await
    .map_err(|_| ForegroundError("profile_reader_failed"))?
}
