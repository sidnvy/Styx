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

#[cfg(target_os = "macos")]
pub(crate) mod macos_service;

#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub(crate) use linux::native_service;
#[cfg(target_os = "macos")]
pub(crate) use macos_service as native_service;
