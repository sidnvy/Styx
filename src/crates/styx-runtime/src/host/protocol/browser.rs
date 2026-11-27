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
    pub(crate) async fn park_idle_browser_sessions(&self) -> usize {
        if let Some(port) = self.browser_port() {
            let engine = crate::host::browser_sessions::Engine { port };
            let parked = engine
                .park_idle_sessions(crate::host::browser_sessions::DEFAULT_IDLE_PARK_TIMEOUT)
                .await;
            let reaped = engine
                .reap_parked_tab_groups(
                    crate::host::browser_sessions::DEFAULT_PARKED_TAB_GROUP_TTL,
                    crate::host::browser_sessions::MAX_PARKED_TAB_GROUPS,
                )
                .await;
            parked + reaped
        } else {
            0
        }
    }
}
#[cfg(all(test, target_os = "linux"))]
#[path = "browser_history_tests.rs"]
pub(crate) mod history_tests;
