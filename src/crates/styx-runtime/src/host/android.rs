//! The Android native executor boundary. Rust retains identity and operation authority.
use super::protocol::wire::OwnerRef;
use serde_json::Value;
use styx_contracts::error::ErrorCategory;
pub trait AndroidPlatform: Send + Sync {
    /// Called on a blocking worker. No JNI object or UI permission is inferred from JSON.
    fn execute(&self, method: &str, arguments: Value) -> Result<Value, ErrorCategory>;
}
pub(crate) fn caller_key(owner: &OwnerRef) -> String {
    serde_json::to_string(owner).expect("owner identity is serializable")
}
