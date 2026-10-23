use crate::{
    error::{ErrorCategory, Recovery},
    identity::ProviderId,
    session::SessionBinding,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CapabilityId {
    #[serde(rename = "exec.run")]
    ExecRun,
    #[serde(rename = "browser.headless")]
    BrowserHeadless,
    #[serde(rename = "browser.headed")]
    BrowserHeaded,
    #[serde(rename = "browser.attach")]
    BrowserAttach,
    #[serde(rename = "desktop.windows.read")]
    DesktopWindowsRead,
    #[serde(rename = "desktop.windows.control")]
    DesktopWindowsControl,
    #[serde(rename = "desktop.capture")]
    DesktopCapture,
    #[serde(rename = "desktop.pointer")]
    DesktopPointer,
    #[serde(rename = "desktop.keyboard")]
    DesktopKeyboard,
    #[serde(rename = "desktop.accessibility")]
    DesktopAccessibility,
}
impl CapabilityId {
    pub fn requires_session(self) -> bool {
        !matches!(self, Self::ExecRun | Self::BrowserHeadless)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Host,
    Session,
    Browser,
    Target,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    Available,
    Unavailable,
    Degraded,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Authorization {
    Granted,
    Required,
    Denied,
    Revoked,
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityDescriptor {
    pub contract_version: u16,
    pub capability_id: CapabilityId,
    pub scope: Scope,
    pub provider_id: ProviderId,
    pub configured: bool,
    pub remote_grant: bool,
    pub availability: Availability,
    pub authorization: Authorization,
    pub target_session: Option<SessionBinding>,
    pub reason: Option<ErrorCategory>,
    pub observed_at: u64,
    pub observation_generation: u64,
    pub recovery: Recovery,
}
