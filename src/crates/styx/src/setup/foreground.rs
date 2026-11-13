use super::{Failure, Result, Session, admin, native, now_ms, prompt};
use serde_json::Value;
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use styx_contracts::native_management::{NativeManager, NativeRunDesired};
use tokio_util::sync::CancellationToken;

pub(super) async fn desired_running(
    session: &Session,
    path: &Path,
    component: native::NativeComponent,
    step: &str,
) -> Result<()> {
    session.require_known(step)?;
    let status = native::inspect_completed(path)
        .await
        .map_err(Failure::native)?;
    if status.admission_fenced {
        return Err(Failure::unknown("setup_native_admission_fenced"));
    }
    let desired = match component {
        native::NativeComponent::Host => status.desired.host,
        native::NativeComponent::Gateway => status.desired.gateway,
    }
    .ok_or_else(|| Failure::new("setup_role_missing"))?;
    if desired.manager != NativeManager::ForegroundCli {
        return Err("setup_foreground_requires_foreground_owned_root".into());
    }
    if desired.run == NativeRunDesired::Running {
        return Ok(());
    }
    session.begin(step)?;
    let tx = format!("setup-{step}-{}", now_ms()?)
        .try_into()
        .map_err(|_| Failure::new("setup_transaction_id_invalid"))?;
    // A fresh foreground root has no prior transaction. On resume the stored
    // original step is fenced; we never mint a replacement after dispatch.
    let plan = native::plan(
        path,
        native::NativeDesiredChange {
            component,
            run: NativeRunDesired::Running,
            transaction_id: tx,
            sequence: 1,
        },
    )
    .await
    .map_err(Failure::native)?;
    native::apply(path, &plan.plan_file)
        .await
        .map_err(Failure::native)?;
    session.done(step)
}

pub(super) struct Foreground {
    cancel: CancellationToken,
    stops: Vec<CancellationToken>,
    tasks: Vec<tokio::task::JoinHandle<Result<()>>>,
    events: tokio::task::JoinHandle<()>,
    send: tokio::sync::mpsc::Sender<styx_runtime::foreground::ForegroundEvent>,
}
pub(super) fn runtime_event_line(event: &styx_runtime::foreground::ForegroundEvent) -> String {
    let prefix = if event.device_id.is_some() {
        "This computer"
    } else {
        "Runtime"
    };
    match event.reason {
        Some(reason) => format!("{prefix}: {} ({reason})", event.event),
        None => format!("{prefix}: {}", event.event),
    }
}
impl Foreground {
    pub(super) fn new() -> Self {
        let (send, mut receive) =
            tokio::sync::mpsc::channel::<styx_runtime::foreground::ForegroundEvent>(32);
        let events = tokio::spawn(async move {
            use styx_runtime::foreground::ForegroundEventKind;
            while let Some(event) = receive.recv().await {
                if prompt::enhanced() {
                    match event.event {
                        ForegroundEventKind::GatewayLoading => prompt::info("Starting Gateway…"),
                        ForegroundEventKind::GatewayListening => {
                            prompt::success("Gateway is listening")
                        }
                        ForegroundEventKind::GatewayStopped => prompt::info("Gateway stopped"),
                        ForegroundEventKind::Connected => {
                            prompt::success("This computer is connected")
                        }
                        _ => prompt::info(&runtime_event_line(&event)),
                    }
                } else {
                    println!("{}", runtime_event_line(&event));
                }
            }
        });
        Self {
            cancel: CancellationToken::new(),
            stops: Vec::new(),
            tasks: Vec::new(),
            events,
            send,
        }
    }
    pub(super) fn gateway(&mut self, path: PathBuf) {
        let cancel = self.cancel.child_token();
        self.stops.push(cancel.clone());
        let events = self.send.clone();
        self.tasks.push(tokio::spawn(async move {
            let outcome = styx_runtime::foreground::gateway_run(&path, cancel, events)
                .await
                .map_err(|e| Failure::new(e.code()))?;
            if outcome.is_complete() {
                Ok(())
            } else {
                Err(Failure::unknown("setup_gateway_cleanup_unconfirmed"))
            }
        }));
    }
    pub(super) fn host(&mut self, path: PathBuf) {
        let cancel = self.cancel.child_token();
        self.stops.push(cancel.clone());
        let events = self.send.clone();
        self.tasks.push(tokio::spawn(async move {
            let outcome = styx_runtime::foreground::host_run(
                &path,
                styx_runtime::foreground::HostWireMode::PairedV3,
                cancel,
                events,
            )
            .await
            .map_err(|e| Failure::new(e.code()))?;
            if outcome.is_complete() {
                Ok(())
            } else {
                Err(Failure::unknown("setup_host_cleanup_unconfirmed"))
            }
        }));
    }
    pub(super) async fn stop(self) -> Result<()> {
        let mut failure = None;
        for (task, stop) in self.tasks.into_iter().zip(self.stops).rev() {
            stop.cancel();
            match task.await {
                Ok(Ok(())) => (),
                Ok(Err(e)) => {
                    failure.get_or_insert(e);
                }
                Err(_) => {
                    failure.get_or_insert_with(|| Failure::unknown("setup_foreground_join_failed"));
                }
            }
        }
        self.cancel.cancel();
        drop(self.send);
        self.events
            .await
            .map_err(|_| Failure::unknown("setup_event_join_failed"))?;
        if let Some(error) = failure {
            Err(error)
        } else {
            Ok(())
        }
    }
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub(super) fn service_steps() -> [(&'static str, native::service::ServiceAction); 3] {
    use native::service::ServiceAction;
    [
        ("install", ServiceAction::Install),
        ("enable", ServiceAction::Enable),
        ("start", ServiceAction::Start),
    ]
}
#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub(super) async fn service(
    session: &Session,
    path: &Path,
    role: native::NativeComponent,
    step: &str,
) -> Result<()> {
    use native::service::{ServiceAction, manage};
    let observed = manage(path, ServiceAction::Status, role, None, None)
        .await
        .map_err(Failure::native)?;
    if observed.os["installed"] == true
        && observed.os["active"] == "active"
        && observed.os["enabled"] == true
    {
        session.skip(step);
        return Ok(());
    }
    session.consent(step, "Install, start and enable this role as your systemd --user service. It starts at user login; Styx never uses sudo or enables linger.")?;
    // Enable while stopped: starting a service only proves systemd admission,
    // not readiness of the Gateway's original live configuration writer.
    // Enabling immediately after start can race its private control endpoint.
    for (name, action) in service_steps() {
        let before = manage(path, ServiceAction::Status, role, None, None)
            .await
            .map_err(Failure::native)?;
        let done = match action {
            ServiceAction::Install => before.os["installed"] == true,
            ServiceAction::Start => before.os["active"] == "active",
            ServiceAction::Enable => before.os["enabled"] == true,
            _ => false,
        };
        let action_name = format!("{step}-{name}-r{}", before.revision);
        if done {
            session.skip(&action_name);
            continue;
        }
        session.begin(&action_name)?;
        let tx = format!("setup-{step}-{name}-{}", now_ms()?)
            .try_into()
            .map_err(|_| Failure::new("setup_transaction_id_invalid"))?;
        manage(path, action, role, Some(tx), Some(before.revision))
            .await
            .map_err(Failure::native)?;
        session.done(&action_name)?;
    }
    Ok(())
}
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
pub(super) async fn service(
    _: &Session,
    _: &Path,
    _: native::NativeComponent,
    _: &str,
) -> Result<()> {
    Err("setup_user_services_unsupported".into())
}

pub(in crate::cli) async fn wait_gateway(path: &Path) -> Result<Value> {
    let waiting = prompt::waiting("Checking the Gateway connection…");
    let until = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        match admin::observe(path).await {
            Ok(v) => {
                waiting.finish("Gateway authenticated and ready");
                return Ok(v);
            }
            Err(e) => {
                if tokio::time::Instant::now() >= until {
                    return Err(Failure::admin(e));
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
pub(in crate::cli) async fn wait_computer(
    gateway: &Path,
    device: Option<&str>,
    browser: bool,
) -> Result<()> {
    let until = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let observed = admin::observe(gateway).await.map_err(Failure::admin)?;
        if observed["environments"].as_array().is_some_and(|envs| {
            envs.iter().any(|env| {
                device.is_none_or(|id| env["environment_id"] == id)
                    && env["exec"]["connection"] == "connected"
                    && (!browser || env["browser"]["connection"] == "connected")
            })
        }) {
            println!("This computer connected (confirmed by the hub).");
            break;
        }
        if tokio::time::Instant::now() >= until {
            return Err("setup_computer_connection_timeout_check_status".into());
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    Ok(())
}
