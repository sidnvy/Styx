//! OS and transport adapters; composition belongs in the styx binary.
/// This describes the implementation stage, never runtime readiness.
pub const IMPLEMENTATION_STAGE: &str = "native-runtime";

pub mod crypto;
pub mod enrollment;
#[cfg(not(target_os = "android"))]
pub mod foreground;
#[cfg(not(target_os = "android"))]
pub mod gateway;
pub mod host;
#[cfg(not(target_os = "android"))]
pub mod ipc;
#[cfg(not(target_os = "android"))]
pub mod management;
#[cfg(not(target_os = "android"))]
pub mod platform;
#[cfg(not(target_os = "android"))]
pub mod providers;
#[cfg(not(target_os = "android"))]
pub mod session;
#[cfg(target_os = "linux")]
pub mod session_probe;
#[cfg(not(target_os = "android"))]
pub mod store;
pub mod tls;

#[cfg(not(target_os = "android"))]
pub mod release;

#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "windows",
    target_os = "macos"
))]
pub mod app;

#[cfg(not(target_os = "android"))]
pub mod app_control;

pub mod android;
