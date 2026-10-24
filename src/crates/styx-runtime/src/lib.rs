//! OS and transport adapters; composition belongs in the styx binary.
/// This describes the implementation stage, never runtime readiness.
pub const IMPLEMENTATION_STAGE: &str = "foundation; not a deployed Host or Gateway";

pub mod crypto;
pub mod enrollment;
pub mod foreground;
pub mod gateway;
pub mod host;
pub mod ipc;
pub mod management;
pub mod migration;
pub mod platform;
pub mod providers;
pub mod session;
#[cfg(target_os = "linux")]
pub mod session_probe;
pub mod store;
pub mod tls;

pub mod release;
