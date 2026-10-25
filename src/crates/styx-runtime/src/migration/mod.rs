//! Original-identity migration composition. Service settlement is a prerequisite,
//! never a final handoff, activation, committed migration or rollback receipt.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub mod legacy_service;

#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub mod legacy_enrollment;

#[cfg(target_os = "macos")]
pub(crate) mod mac_exec_validation;
