//! Platform adapters expose observed OS facts without granting authority.

#[cfg(target_os = "linux")]
pub mod linux;
