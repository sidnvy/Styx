//! Local App lifetime is independent of a missing remote settlement receipt.
//! Control paths retain strict remote checks. No result becomes Complete.
use super::*;

impl HostApp {
    pub(super) async fn admit_quit(&mut self) -> Result<Value, AppError> {
        // Preserve the result of a Host that already exited, even when the
        // caller must wait for a login change or update before it can quit.
        if self
            .running
            .as_ref()
            .is_some_and(|role| role.worker.is_finished())
        {
            self.settle_host(true).await?;
        }
        if self.login.pending() {
            return Err(AppError("app_login_in_progress"));
        }
        if self.service_client_or_unknown() {
            return self.service_quit_admission().await;
        }
        if self.resume_local_available {
            // This is a positively revalidated never-dispatched checkpoint,
            // not permission to clear an arbitrary failed pairing/role outcome.
            self.check_pre_invite_local().await?;
            // Only the positively checked never-dispatched setup is known;
            // settle itself must not inherit that incomplete-setup sentinel.
            self.unknown = false;
            if let Err(error) = self.settle_all().await.and_then(|()| self.scope.validate()) {
                self.unknown = true;
                return Err(error);
            }
            let ticket = uuid::Uuid::new_v4().simple().to_string();
            self.quit_ticket = Some(ticket.clone());
            self.resume_local_available = false;
            self.unknown = false;
            return Ok(
                json!({"quit":{"status":"ready_to_quit","ticketId":ticket},"cleanup":self.cleanup,"gateway":self.local_gateway.as_ref().map(|g| g.status())}),
            );
        }
        if let Some(ticket) = &self.quit_ticket {
            // A role change may be refused after stopping. Reuse the completed
            // local stop, including its original evidence, without another write.
            self.scope.validate()?;
            return Ok(self.local_quit_reply(ticket));
        }
        self.settle_for_quit().await?;
        self.available_for(true)?;
        let ticket = uuid::Uuid::new_v4().simple().to_string();
        self.record_exit_uncertainty(&ticket).await?;
        self.quit_ticket = Some(ticket.clone());
        Ok(self.local_quit_reply(&ticket))
    }

    fn local_quit_reply(&self, ticket: &str) -> Value {
        json!({"quit":{"status":"ready_to_quit","scope":"local_app","ticketId":ticket},
            "cleanup":self.cleanup,"gateway":self.local_gateway.as_ref().map(|g|g.status())})
    }

    pub(super) fn remote_cleanup_unconfirmed(&self) -> bool {
        self.cleanup
            .as_ref()
            .is_some_and(|c| c.local_stop_complete() && !c.is_complete())
    }
    pub(super) async fn settle_for_quit(&mut self) -> Result<(), AppError> {
        let host = self.settle_host(true).await;
        let gateway = match &mut self.local_gateway {
            Some(gateway) => gateway.settle_for(true).await,
            None => Ok(()),
        };
        host.and(gateway)?;
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
