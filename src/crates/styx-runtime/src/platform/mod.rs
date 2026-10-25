//! Platform adapters expose observed OS facts without granting authority.

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub(crate) mod macos_spawn;

#[cfg(target_os = "windows")]
pub(crate) mod windows_spawn;

#[cfg(target_os = "windows")]
pub(crate) mod windows_desktop;

#[cfg(target_os = "windows")]
pub(crate) mod windows_legacy_observation;
#[cfg(target_os = "windows")]
pub(crate) mod windows_restart_observation;
