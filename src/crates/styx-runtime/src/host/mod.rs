//! Host supervision is independent of remote transport lifetime.
pub mod bootstrap;
pub(crate) mod callers;
pub mod coordinator;
pub(crate) mod exec_tasks;
pub mod link;
pub mod protocol;
mod replies;
pub mod settings;
