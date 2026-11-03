//! Local App lifetime is independent of a missing remote settlement receipt.
//! Control/update paths retain strict remote checks. No result becomes Complete.
use super::*;

impl HostApp {
    pub(super) fn remote_cleanup_unconfirmed(&self) -> bool {
        self.cleanup
            .as_ref()
            .is_some_and(|c| c.local_stop_complete() && !c.is_complete())
    }
    pub(super) async fn settle_for_quit(&mut self) -> Result<(), AppError> {
        // Installation handoff continues to need the original full admission.
        if self.maintenance_fenced() {
            return self.settle_all().await;
        }
        self.reap_runtime_update(true).await;
        let host = self.settle_host(true).await;
        let gateway = match &mut self.local_gateway {
            Some(gateway) => gateway.settle_for(true).await,
            None => Ok(()),
        };
        host.and(gateway)?;
        if self.runtime_update_fenced() {
            return Err(AppError("app_runtime_update_pending"));
        }
        Ok(())
    }
    pub(super) async fn record_exit_uncertainty(&self, ticket: &str) -> Result<(), AppError> {
        self.record_stop_uncertainty(ticket, false).await
    }
    pub(super) async fn record_pause_uncertainty(&self, ticket: &str) -> Result<(), AppError> {
        self.record_stop_uncertainty(ticket, true).await
    }
    async fn record_stop_uncertainty(&self, ticket: &str, pause: bool) -> Result<(), AppError> {
        let remote = self.remote_cleanup_unconfirmed()
            || !pause
                && self
                    .local_gateway
                    .as_ref()
                    .and_then(|g| g.cleanup.as_ref())
                    .is_some_and(|c| !c.is_complete());
        if !remote {
            return Ok(());
        }
        let kind = if pause {
            "app_host_pause"
        } else {
            "app_local_exit"
        };
        let bytes = serde_json::to_vec(&json!({"schema":1,"kind":kind,
            "ticket_id":ticket,"local_cleanup_complete":true,"remote_cleanup_confirmed":false,
            "host_cleanup":self.cleanup,"gateway_cleanup":self.local_gateway.as_ref().and_then(|g| g.cleanup.as_ref()),
            "operations_replayed":false})).map_err(|_| AppError("app_exit_receipt_invalid"))?;
        let reason = if pause { "pause" } else { "exit" };
        let name = format!("app-local-{reason}-{ticket}.json");
        let scope = self.scope.clone();
        tokio::task::spawn_blocking(move || {
            scope.validate()?;
            // Existing exclusive private writer; observation only, no C07,
            // new journal, identity change, adoption or replacement of evidence.
            scope
                .container
                .parent
                .create_setup_export(std::ffi::OsStr::new(&name), &bytes)
                .map_err(|_| AppError("app_exit_receipt_unconfirmed"))?;
            scope.validate()
        })
        .await
        .map_err(|_| AppError("app_exit_receipt_unconfirmed"))?
    }
}

#[cfg(all(test, target_os = "linux", target_env = "gnu"))]
#[path = "exit_tests.rs"]
mod tests;
