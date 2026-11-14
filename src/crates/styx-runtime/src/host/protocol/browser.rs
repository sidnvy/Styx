//! Protocol adapter; Browser resources and operation ownership live in Host.
use super::*;
use crate::host::browser_sessions::operations::BrowserPort;
pub(crate) use crate::host::browser_sessions::operations::{BrowserBootstrap, BrowserInputs};
impl HostProtocol<'_> {
    pub(crate) fn with_browser_profiles(
        mut self,
        source: std::sync::Arc<dyn BrowserBootstrap>,
    ) -> Result<Self, ProtocolError> {
        if !self.paired || !self.coordinator.browser_configured() || self.browser.is_some() {
            return Err(ProtocolError::BootstrapMismatch);
        }
        self.browser = Some(self.coordinator.browser_sessions().inputs(source));
        Ok(self)
    }
    pub(crate) fn browser_port(&self) -> Option<BrowserPort<'_>> {
        self.browser.as_ref().map(|inputs| BrowserPort {
            coordinator: &self.coordinator,
            authority: self.authority,
            inputs,
        })
    }
    pub(super) async fn release_browser_profile(
        &self,
        owner: OwnerLease,
    ) -> Result<(), ErrorCategory> {
        if let Some(port) = self.browser_port() {
            port.release_browser_profile(owner).await
        } else {
            Ok(())
        }
    }
    pub(crate) async fn drain_browser_inputs(&self) {
        if let Some(port) = self.browser_port() {
            port.drain_browser_inputs().await;
        }
    }
    pub(super) async fn handle_browser(
        &self,
        reference: OwnerRef,
        revision: u64,
        timeout: u32,
        command: BrowserCommand,
    ) -> Reply {
        let owner = match self.owner(&reference) {
            Ok(o) => o,
            Err(e) => return rejection(e),
        };
        match self.browser_port() {
            Some(port) => port.handle_browser(owner, revision, timeout, command).await,
            None => rejection(ErrorCategory::CapabilityUnsupported),
        }
    }
}
#[cfg(all(test, target_os = "linux"))]
#[path = "browser_history_tests.rs"]
pub(crate) mod history_tests;
