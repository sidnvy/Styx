//! Original-identity migration composition. Service settlement is a prerequisite,
//! never a final handoff, activation, committed migration or rollback receipt.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub mod legacy_service;

#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub mod legacy_enrollment;

#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(crate) mod mac_exec_validation;

#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(crate) mod mac_pair_validation;
