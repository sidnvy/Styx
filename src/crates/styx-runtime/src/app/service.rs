//! The native App becomes a service client only from the original committed
//! C07 manager transfer. No App preference records service ownership.
use super::*;
use crate::management::native::app_service::{
    self as backend, AppServiceAction, AppServiceClientReport,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Authorization {
    authorize: bool,
}
#[derive(Serialize)]
pub(super) struct State {
    status: &'static str,
    client: Option<AppServiceClientReport>,
    last_action: Option<Value>,
    // Exact Rust serialization for native export; Swift numeric DTOs use Double.
    last_action_report_json: Option<String>,
    error: Option<&'static str>,
    // Original typed C07 writer/release/execution custody on Unknown. This is
    // intentionally retained until process teardown; no status read clears it.
    #[serde(skip)]
    retained: Option<native::NativeManagementError>,
    #[serde(skip)]
    retain_until_exit: bool,
}
impl Drop for State {
    fn drop(&mut self) {
        // Only an unresolved typed error is retained until process exit. Normal
        // reports/results drop normally; this is not a successful cleanup or
        // service-transfer receipt. A later App in this process remains busy.
        if self.retain_until_exit
            && let Some(error) = self.retained.take()
        {
            std::mem::forget(error);
        }
    }
}
impl State {
    fn client(report: AppServiceClientReport) -> Self {
        Self {
            status: "service_client",
            client: Some(report),
            last_action: None,
            last_action_report_json: None,
            error: None,
            retained: None,
            retain_until_exit: false,
        }
    }
    fn fenced(&self) -> bool {
        self.retained.is_some() || self.status == "unknown"
    }
}
impl HostApp {
    pub(super) fn service_client_or_unknown(&self) -> bool {
        self.service
            .as_ref()
            .is_some_and(|state| state.client.is_some() || state.fenced())
    }
    pub(super) fn service_fenced(&self) -> bool {
        self.service.as_ref().is_some_and(State::fenced)
    }
    pub(super) fn service_configuration(&self) -> Option<&native::NativeManagementReport> {
        self.service
            .as_ref()
            .and_then(|state| state.client.as_ref())
            .map(|client| &client.configuration)
    }
    /// Must precede runtime-input scanning, App-managed inspection and joining;
    /// all of those old paths can otherwise acquire the live service writer.
    pub(super) async fn observe_service_client(&mut self) -> Result<bool, AppError> {
        match backend::inspect_for_app(self.scope.clone()).await {
            Ok(Some(report)) => {
                self.service = Some(State::client(report));
                self.configuration = None;
                Ok(true)
            }
            Ok(None) => Ok(false),
            Err(error) => {
                let code = error.code();
                self.service = Some(State {
                    status: "unknown",
                    client: None,
                    last_action: None,
                    last_action_report_json: None,
                    error: Some(code),
                    retained: Some(error),
                    retain_until_exit: false,
                });
                // Keep the original App available as an inspectable client. No
                // enrollment, old App writer or worker is started on this path.
                Ok(true)
            }
        }
    }
    pub(super) async fn refresh_service_client(&mut self) -> Result<(), AppError> {
        self.scope.validate()?;
        if self.service_fenced() {
            return Err(AppError("app_service_original_operation_unknown"));
        }
        if !self.service_client_or_unknown() {
            return Err(AppError("app_service_client_required"));
        }
        match backend::refresh_for_app(self.scope.clone()).await {
            Ok(report) => {
                if let Some(state) = &mut self.service {
                    state.client = Some(report);
                }
                Ok(())
            }
            Err(error) => Err(self.service_error(error, false)),
        }
    }
    fn service_error(&mut self, error: native::NativeManagementError, mutation: bool) -> AppError {
        let code = error.code();
        if let Some(state) = &mut self.service {
            state.error = Some(code);
            if error.exit_code() == 4 {
                state.status = "unknown";
                state.retain_until_exit |= mutation;
                state.retained = Some(error);
            }
        }
        AppError(code)
    }
    pub(super) async fn transfer_to_service(
        &mut self,
        input: Authorization,
    ) -> Result<(), AppError> {
        if !input.authorize {
            return Err(AppError("app_service_authorization_required"));
        }
        self.available()?;
        if self.login.pending() {
            return Err(AppError("app_login_in_progress"));
        }
        if self.service_client_or_unknown() {
            return Err(AppError("app_service_already_transferred"));
        }
        // This first vertical is the original fresh single Host. Split sibling
        // transfer has no cross-root atomic receipt and remains explicit work.
        if self.committed_migration || self.local_gateway.is_some() || self.configuration.is_none()
        {
            return Err(AppError("app_service_profile_unsupported"));
        }
        self.settle_all().await?;
        self.set_desired(NativeRunDesired::Stopped).await?;
        self.service = Some(State {
            status: "transferring",
            client: None,
            last_action: None,
            last_action_report_json: None,
            error: None,
            retained: None,
            retain_until_exit: false,
        });
        let id = uuid::Uuid::new_v4()
            .to_string()
            .try_into()
            .map_err(|_| AppError("app_service_transaction_invalid"))?;
        match backend::transfer_for_app(self.scope.clone(), id).await {
            Ok(report) => {
                // The original writer/execution custody was released only after
                // committed exact readback. No old App worker can restart now.
                self.configuration = None;
                self.service = Some(State::client(report));
                Ok(())
            }
            Err(error) => {
                if error.exit_code() != 4 {
                    self.service = None;
                    return Err(AppError(error.code()));
                }
                Err(self.service_error(error, true))
            }
        }
    }
    pub(super) async fn manage_service(
        &mut self,
        input: Authorization,
        first_start: bool,
    ) -> Result<(), AppError> {
        if !input.authorize {
            return Err(AppError("app_service_authorization_required"));
        }
        self.available()?;
        if self.login.pending() {
            return Err(AppError("app_login_in_progress"));
        }
        self.refresh_service_client().await?;
        let revision = self
            .service_configuration()
            .ok_or(AppError("app_service_client_required"))?
            .revision;
        let id = uuid::Uuid::new_v4()
            .to_string()
            .try_into()
            .map_err(|_| AppError("app_service_transaction_invalid"))?;
        let action = if first_start {
            AppServiceAction::PrepareFirstStart
        } else {
            AppServiceAction::Stop
        };
        let report = backend::manage_for_app(self.scope.clone(), action, id, revision)
            .await
            .map_err(|error| self.service_error(error, true))?;
        if let Some(state) = &mut self.service {
            state.last_action_report_json = serde_json::to_string(&report).ok();
            state.last_action = Some(report);
            state.error = None;
        }
        self.refresh_service_client().await
    }
    /// Normal App Quit settles only original App-owned work. A service and an
    /// already-ended Unknown configuration operation are never signal targets.
    pub(super) async fn service_quit_admission(&mut self) -> Result<Value, AppError> {
        self.settle_all().await?;
        self.scope.validate()?;
        if self.running.is_some()
            || self
                .local_gateway
                .as_ref()
                .is_some_and(|gateway| gateway.is_running())
        {
            return Err(AppError("app_role_busy"));
        }
        let ticket = uuid::Uuid::new_v4().simple().to_string();
        self.quit_ticket = Some(ticket.clone());
        Ok(json!({"quit":{"status":"ready_to_quit","ticketId":ticket},
            "cleanup":self.cleanup,"service":self.service,"service_action":"none"}))
    }
}
