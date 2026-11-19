//! Protected enrollment bootstrap. This is not a network listener or an
//! administrator factory. Recovery of file/Core facts does not prove profile
//! crypto semantics, original transport quiescence or OS/native readiness.
#[cfg(not(target_os = "android"))]
pub mod http;
pub(crate) mod pairing_link;
mod profile;
#[cfg(not(target_os = "android"))]
mod recovery;
#[cfg(not(target_os = "android"))]
pub(crate) mod retirement;
#[cfg(not(target_os = "android"))]
pub mod service;
#[cfg(not(target_os = "android"))]
pub mod shared;
pub(crate) mod short_code;

#[cfg(not(target_os = "android"))]
mod bootstrap;
pub mod client;
pub(crate) mod client_http;
pub(crate) mod client_protocol;
#[cfg(not(target_os = "android"))]
pub use bootstrap::*;

/// Reuses the server's bounded canonical admission checks without granting or
/// approving a local device. Client-side validation is not Gateway authority.
pub(crate) fn validate_local_join(
    payload: &styx_contracts::legacy::JoinPayload,
    signature: &str,
) -> Result<(), &'static str> {
    profile::verify_join(payload, signature)
        .map(|_| ())
        .map_err(|_| "native_join_profile_invalid")
}
