//! Foreground composition; CLI and later native UI share these authority ports.
pub mod profile;
pub use profile::ProfileDiagnostics;
use serde::Serialize;
use std::path::Path;
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HostWireMode {
    LegacyExplicit,
    PairedV3,
}
#[derive(Serialize)]
pub struct ForegroundEvent {
    pub schema: u32,
    pub event: &'static str,
    pub device_id: Option<styx_contracts::identity::DeviceId>,
    pub connection_generation: Option<styx_contracts::identity::ConnectionGeneration>,
}
#[derive(Serialize)]
pub struct ForegroundOutcome {
    pub schema: u32,
    pub executor_exited: bool,
    pub processes_exited: bool,
    pub io_tasks_joined: bool,
    pub supervised_jobs_joined: bool,
}
impl ForegroundOutcome {
    pub fn is_complete(&self) -> bool {
        self.executor_exited
            && self.processes_exited
            && self.io_tasks_joined
            && self.supervised_jobs_joined
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
pub use run::host_run;
mod gateway;
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
pub(crate) use gateway::StartupTransportClosure;
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
