//! Native configuration, onboarding, pairing and role management.
pub mod native;
pub mod native_gateway;
pub mod native_gateway_admin;
pub mod native_join;
#[cfg(any(
    all(target_os = "windows", target_arch = "x86_64"),
    all(
        target_os = "macos",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")
))]
pub(crate) use crate::enrollment::client_http as native_join_http;
#[cfg(any(
    all(target_os = "windows", target_arch = "x86_64"),
    all(
        target_os = "macos",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")
))]
use crate::enrollment::client_protocol as native_join_protocol;
pub mod plugin_package;
pub mod plugin_presentation;
pub mod public_mcp;
pub mod role_retire;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub(crate) mod service_control;
pub mod setup;

#[cfg(test)]
pub(crate) mod setup_pending_restart_reference_tests;
