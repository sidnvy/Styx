use super::{AppError, ConnectionStatus, HostApp, RunningHost};
use crate::{
    foreground::{self, ForegroundOutcome},
    management::native,
};
use serde_json::json;
use std::sync::Arc;
use styx_contracts::native_management::{NativeAutostartDesired, NativeManager, NativeRunDesired};
use tokio::sync::mpsc;
#[cfg(target_os = "macos")]
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

impl HostApp {
    pub(super) async fn read_configuration(&mut self) -> Result<(), AppError> {
        self.scope.validate()?;
        // Never call a path-only writer while our original role is still live.
        if self.running.is_some() {
            return Err(AppError("app_role_busy"));
        }
        let report = native::inspect_for_app(self.scope.clone())
            .await
            .map_err(|e| self.management_error(e))?;
        if report.desired.gateway.is_some()
            || !report.desired.host.is_some_and(|d| {
                d.manager == NativeManager::AppManaged
                    && d.autostart == NativeAutostartDesired::Disabled
            })
            || report.desired.gateway.is_some_and(|d| {
                d.manager != NativeManager::AppManaged
                    || d.autostart != NativeAutostartDesired::Disabled
            })
        {
            return Err(AppError("app_manager_refused"));
        }
        if report.admission_fenced {
            return Err(AppError("app_transaction_fenced"));
        }
        self.configuration = Some(report);
        Ok(())
    }

    pub(super) async fn resume_desired_running(&mut self) -> Result<(), AppError> {
        if self.running.is_some() || self.unknown {
            return Ok(());
        }
        if let Some(profile) = self.startup_profile.clone() {
            if tokio::task::spawn_blocking(move || profile.revalidate())
                .await
                .map_err(|_| AppError("app_startup_observation_failed"))?
                .is_err()
            {
                self.unknown = true;
                return Err(AppError("app_startup_observation_changed"));
            }
        } else {
            self.read_configuration().await?;
        }
        // Each role retains its own durable intent. Gateway resume must not
        // promote a stopped Gateway or depend on the local Host being enabled.
        if let Some(gateway) = &mut self.local_gateway {
            gateway.resume_if_desired_running().await?;
        }
        if self.observed.borrow().error == Some("gateway_wss_admission_refused") {
            return Ok(());
        }
        let wanted = self
            .configuration
            .as_ref()
            .and_then(|report| report.desired.host)
            .is_some_and(|host| host.run == NativeRunDesired::Running);
        if !wanted {
            return Ok(());
        }
        // Resume observes Running; it must never overwrite a newer Stopped
        // intent. Original Host admission rechecks canonical Running itself.
        self.start_host().await
    }

    pub(super) async fn connect_host(&mut self) -> Result<(), AppError> {
        if self.observed.borrow().error == Some("gateway_wss_admission_refused") {
            return Err(AppError("app_gateway_access_refused"));
        }
        if self.running.is_none() {
            self.set_desired(NativeRunDesired::Running).await?;
            self.start_host().await?;
        }
        Ok(())
    }

    pub(super) async fn start_host(&mut self) -> Result<(), AppError> {
        if self.running.is_none() {
            let diagnostic = self.startup_diagnostic.clone();
            if let Some(d) = &diagnostic {
                d.report("app_connect_host");
            }
            if let Some(d) = &diagnostic {
                d.report("app_host_desired_ready");
            }
            let startup_profile = self.startup_profile.take();
            let desktop_intent = if self.native_computer_requested == Some(false) {
                // The original native seed explicitly declined Computer. Starting
                // Exec still loads and verifies its own complete Host profile below.
                None
            } else if startup_profile.is_some() {
                // Metadata only. Actual Host execution still loads and validates
                // canonical Running through its existing independent port.
                startup_profile
            } else {
                let intent_scope = self.scope.clone();
                let runtime = self.native_runtime.clone();
                tokio::task::spawn_blocking(move || {
                    use crate::store::native_host_snapshot::NativeHostSnapshot;
                    // Reuse the original formal release, with its existing full
                    // selection/member revalidation; never a receipt/path cache.
                    let snapshot = match runtime {
                        Some(runtime) => NativeHostSnapshot::open_for_app_retained(
                            intent_scope.state_dir(),
                            intent_scope.clone(),
                            runtime,
                        ),
                        None => NativeHostSnapshot::open_for_app(
                            intent_scope.state_dir(),
                            intent_scope.clone(),
                        ),
                    };
                    snapshot.ok().map(Arc::new)
                })
                .await
                .ok()
                .flatten()
            };
            if let Some(d) = &diagnostic {
                d.report("app_desktop_intent_ready");
            }
            // Missing desktop facts disable that optional component;
            // they cannot prevent the independent Exec Host starting.
            let cancel = CancellationToken::new();
            let worker_cancel = cancel.clone();
            let scope = self.scope.clone();
            let (events, mut received) = mpsc::channel::<foreground::ForegroundEvent>(16);
            let status = self.status.clone();
            let event_task = tokio::spawn(async move {
                use crate::foreground::ForegroundEventKind;
                while let Some(event) = received.recv().await {
                    // Computer initialization is independent of Exec transport.
                    // Retain its fixed failure code for this original Host; later
                    // connection events must not erase that optional-lane failure.
                    // A closed diagnostic fact, never readiness or permission.
                    #[cfg(target_os = "macos")]
                    if event.event == ForegroundEventKind::ComputerInitialProbe {
                        status.send_modify(|value| {
                            value.computer_initial_epoch_advanced =
                                crate::foreground::InitialConsoleEpoch::parse_advanced(
                                    event.reason,
                                );
                        });
                        continue;
                    }
                    if event.event == ForegroundEventKind::ComputerUnavailable {
                        status.send_modify(|value| {
                            value.computer_error =
                                Some(event.reason.unwrap_or("computer_bootstrap_failed"));
                            #[cfg(target_os = "macos")]
                            {
                                value.computer_probe = event.computer_probe;
                            }
                        });
                        continue;
                    }
                    let computer_error = status.borrow().computer_error;
                    #[cfg(target_os = "macos")]
                    let computer_probe = status.borrow().computer_probe;
                    #[cfg(target_os = "macos")]
                    let computer_initial_epoch_advanced =
                        status.borrow().computer_initial_epoch_advanced;
                    if event.reason == Some(crate::gateway::paired::CAPACITY_ERROR_CODE) {
                        let mut value = ConnectionStatus::hub_full();
                        value.computer_error = computer_error;
                        #[cfg(target_os = "macos")]
                        {
                            value.computer_probe = computer_probe;
                            value.computer_initial_epoch_advanced = computer_initial_epoch_advanced;
                        }
                        status.send_replace(value);
                        continue;
                    }
                    if status.borrow().error == Some(crate::gateway::paired::CAPACITY_ERROR_CODE)
                        && matches!(
                            event.event,
                            ForegroundEventKind::Connecting
                                | ForegroundEventKind::Reconnecting
                                | ForegroundEventKind::Disconnected
                        )
                    {
                        continue;
                    }
                    let status_value = match event.event {
                        ForegroundEventKind::Connected => ConnectionStatus {
                            status: "connected",
                            exec_connection: "connected",
                            error: None,
                            hint: None,
                            computer_error,
                            #[cfg(target_os = "macos")]
                            computer_probe,
                            #[cfg(target_os = "macos")]
                            computer_initial_epoch_advanced,
                        },
                        ForegroundEventKind::Connecting | ForegroundEventKind::Reconnecting => {
                            ConnectionStatus {
                                status: "started",
                                exec_connection: "connecting",
                                error: None,
                                hint: None,
                                computer_error,
                                #[cfg(target_os = "macos")]
                                computer_probe,
                                #[cfg(target_os = "macos")]
                                computer_initial_epoch_advanced,
                            }
                        }
                        ForegroundEventKind::Disconnected => ConnectionStatus {
                            status: "started",
                            exec_connection: "disconnected",
                            error: None,
                            hint: None,
                            computer_error,
                            #[cfg(target_os = "macos")]
                            computer_probe,
                            #[cfg(target_os = "macos")]
                            computer_initial_epoch_advanced,
                        },
                        _ => continue,
                    };
                    status.send_replace(status_value);
                }
            });
            self.status.send_replace(ConnectionStatus {
                status: "started",
                exec_connection: "connecting",
                error: None,
                hint: None,
                computer_error: None,
                #[cfg(target_os = "macos")]
                computer_probe: None,
                #[cfg(target_os = "macos")]
                computer_initial_epoch_advanced: None,
            });
            let verified_runtime = self.native_runtime.clone();
            #[cfg(target_os = "macos")]
            let (computer_runtime_fault_tx, computer_runtime_fault) = watch::channel(None);
            if let Some(d) = &diagnostic {
                d.report("app_host_worker_scheduled");
            }
            let worker = tokio::spawn(async move {
                if let Some(d) = &diagnostic {
                    d.report("app_host_worker_started");
                }
                foreground::host_run_for_app(
                    scope,
                    worker_cancel,
                    events,
                    verified_runtime,
                    #[cfg(target_os = "macos")]
                    computer_runtime_fault_tx,
                )
                .await
            });
            let cancel_on_drop = cancel.clone().drop_guard();
            self.running = Some(RunningHost {
                desktop_intent,
                cancel,
                worker,
                events: event_task,
                #[cfg(target_os = "macos")]
                computer_runtime_fault,
                _cancel_on_drop: cancel_on_drop,
            });
        }
        Ok(())
    }

    pub(super) async fn settle_all(&mut self) -> Result<(), AppError> {
        self.reap_runtime_update(true).await;
        let host = self.settle().await;
        let gateway = match &mut self.local_gateway {
            Some(gateway) => gateway.settle().await,
            None => Ok(()),
        };
        if gateway.is_err()
            && self
                .local_gateway
                .as_ref()
                .is_some_and(|g| g.local_exit_fenced())
        {
            self.unknown = true;
        }
        host.and(gateway)?;
        if self.runtime_update_fenced() {
            return Err(AppError("app_runtime_update_pending"));
        }
        Ok(())
    }

    pub(super) async fn set_desired(&mut self, run: NativeRunDesired) -> Result<(), AppError> {
        self.set_desired_for(run, false).await
    }

    pub(super) async fn set_desired_for(
        &mut self,
        run: NativeRunDesired,
        local_stop: bool,
    ) -> Result<(), AppError> {
        if local_stop
            && (run != NativeRunDesired::Stopped
                || self
                    .cleanup
                    .as_ref()
                    .is_some_and(|c| !c.local_stop_complete()))
        {
            return Err(AppError("app_cleanup_unknown"));
        }
        self.available_for(local_stop)?;
        self.read_configuration().await?;
        let report = self
            .configuration
            .as_ref()
            .ok_or(AppError("app_not_configured"))?;
        if report.desired.host.is_some_and(|h| h.run == run) {
            return Ok(());
        }
        let change = native::NativeDesiredChange {
            component: native::NativeComponent::Host,
            run,
            transaction_id: uuid::Uuid::new_v4()
                .to_string()
                .try_into()
                .expect("UUID identity"),
            sequence: report
                .revision
                .checked_add(1)
                .ok_or(AppError("app_revision_exhausted"))?,
        };
        let plan = native::plan_for_app(self.scope.clone(), change)
            .await
            .map_err(|e| self.management_error(e))?;
        self.scope.validate()?;
        let report = native::apply_for_app(self.scope.clone(), &plan.plan_file)
            .await
            .map_err(|e| self.management_error(e))?;
        if report.admission_fenced {
            self.unknown = true;
            return Err(AppError("app_transaction_fenced"));
        }
        self.configuration = Some(report);
        Ok(())
    }

    pub(super) async fn settle(&mut self) -> Result<(), AppError> {
        self.settle_host(false).await
    }

    pub(super) async fn settle_host(&mut self, local_exit: bool) -> Result<(), AppError> {
        if let Some(role) = self.running.take() {
            role.cancel.cancel();
            let outcome = role.worker.await;
            let events = role.events.await;
            match outcome {
                Ok(Ok(outcome)) => {
                    let complete = outcome.is_complete() && events.is_ok();
                    let locally_joined = outcome.local_stop_complete() && events.is_ok();
                    self.cleanup = Some(outcome);
                    if complete || (local_exit && locally_joined) {
                        self.status.send_replace(ConnectionStatus::stopped());
                    } else {
                        self.unknown |= !locally_joined;
                        self.status.send_replace(ConnectionStatus::unknown());
                        let cause = if locally_joined {
                            "remote_transport_drain_unconfirmed"
                        } else {
                            "foreground_cleanup_incomplete"
                        };
                        eprintln!(
                            "{}",
                            json!({"schema":1,"event":"app_role_failed","cause":cause,"events_joined":events.is_ok()})
                        );
                        return Err(AppError("app_cleanup_unknown"));
                    }
                }
                failed => {
                    // Preserve a fixed diagnostic cause; never print native
                    // output, credentials, paths or an arbitrary error display.
                    let cause = match &failed {
                        Ok(Err(error)) => error.code(),
                        Ok(Ok(_)) => "foreground_cleanup_incomplete",
                        Err(_) => "foreground_worker_failed",
                    };
                    eprintln!(
                        "{}",
                        json!({"schema":1,"event":"app_role_failed","cause":cause,"events_joined":events.is_ok()})
                    );
                    if cause == crate::gateway::paired::CAPACITY_ERROR_CODE && events.is_ok() {
                        // host_run returns this admission error only after its
                        // owned local executor and input jobs have settled.
                        self.status.send_replace(ConnectionStatus::hub_full());
                        return Ok(());
                    }
                    if cause == "gateway_wss_admission_refused"
                        && events.is_ok()
                        && !self.unknown
                        && self
                            .cleanup
                            .as_ref()
                            .is_none_or(ForegroundOutcome::is_complete)
                    {
                        // This fixed error comes from the initial WSS 403,
                        // before any transport grants this Host an owner. The
                        // original host_run returns only after its executor,
                        // inputs and providers have physically joined. Keep
                        // the denial visible without inventing a remote drain
                        // receipt or clearing any prior Unknown outcome.
                        self.status
                            .send_replace(ConnectionStatus::pairing_refused());
                        return Ok(());
                    }
                    self.unknown = true;
                    self.status.send_replace(ConnectionStatus::unknown());
                    return Err(AppError("app_cleanup_unknown"));
                }
            }
        }
        if self.unknown || (!local_exit && self.remote_cleanup_unconfirmed()) {
            return Err(AppError("app_cleanup_unknown"));
        }
        Ok(())
    }

    pub(super) async fn reap(&mut self) -> Result<(), AppError> {
        if self
            .running
            .as_ref()
            .is_some_and(|r| r.worker.is_finished())
        {
            self.settle().await?;
        }
        Ok(())
    }

    pub(super) fn admission_fenced(&self) -> bool {
        self.service_fenced()
            || self.runtime_update_fenced()
            || self.unknown
            || self.remote_cleanup_unconfirmed()
            || self.retained.is_some()
            || self.quit_ticket.is_some()
            || self
                .local_gateway
                .as_ref()
                .is_some_and(|gateway| gateway.is_fenced())
    }

    pub(super) async fn desktop_component_requested(&self) -> bool {
        if self.admission_fenced() {
            return false;
        }
        let Some(role) = &self.running else {
            return false;
        };
        if role.cancel.is_cancelled() || role.worker.is_finished() {
            return false;
        }
        let Some(original) = role.desktop_intent.clone() else {
            return false;
        };
        // Never acquire a replacement profile on a status request. Original
        // private file/namespace identities and bytes must still match; only
        // the successful pairing self-response supplies computer_approved.
        let requested = tokio::task::spawn_blocking(move || {
            original.seed().computer_requested
                && original.ready().computer_approved
                && original.revalidate().is_ok()
        })
        .await
        .unwrap_or(false);
        requested && !role.cancel.is_cancelled() && !role.worker.is_finished()
    }
}
