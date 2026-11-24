//! Host supervision is independent of remote transport lifetime.
#[cfg(not(target_os = "android"))]
pub mod bootstrap;
#[cfg(not(target_os = "android"))]
pub mod browser_cdp;
#[cfg(not(target_os = "android"))]
pub(crate) mod browser_sessions;
pub(crate) mod callers;
pub mod coordinator;
#[cfg(not(target_os = "android"))]
pub(crate) mod exec_tasks;
pub mod link;
pub mod protocol;
mod replies;
pub mod settings;

pub mod android;
