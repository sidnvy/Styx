//! Process entry adapter. Runtime owns trusted profile admission and cleanup;
//! command arguments never supply credentials, executor binaries or authority.
#[cfg(test)]
use clap::Parser;
use std::{io, path::PathBuf, process::ExitCode};
use tokio_util::sync::CancellationToken;

mod args;
#[path = "computers.rs"]
mod computers;
mod desktop;
#[path = "install.rs"]
mod install;
mod output;
#[path = "plugin_command.rs"]
mod plugin_command;
#[path = "plugin_package.rs"]
mod plugin_package;
#[path = "setup.rs"]
mod setup;
#[path = "setup_prompt.rs"]
mod setup_prompt;
#[path = "status_view.rs"]
mod status_view;
#[path = "upgrade.rs"]
mod upgrade;

pub(crate) use args::Cli;
use args::*;
use desktop::*;
use output::*;

#[cfg(unix)]
async fn stop_signal() -> io::Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! { r=tokio::signal::ctrl_c()=>r, _=terminate.recv()=>Ok(()) }
}
#[cfg(windows)]
async fn stop_signal() -> io::Result<()> {
    let mut interrupt = tokio::signal::windows::ctrl_c()?;
    let mut terminate = tokio::signal::windows::ctrl_break()?;
    tokio::select! {
        event = interrupt.recv() => event.ok_or_else(|| io::Error::other("console_signal_closed")),
        event = terminate.recv() => event.ok_or_else(|| io::Error::other("console_signal_closed")),
    }
}
#[cfg(not(any(unix, windows)))]
async fn stop_signal() -> io::Result<()> {
    tokio::signal::ctrl_c().await
}

async fn local_app(
    state_dir: Option<PathBuf>,
    operation: styx_runtime::app_control::Operation,
    json: bool,
) -> ExitCode {
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (state_dir, operation, json);
        error("local_app_control_windows_only")
    }
    #[cfg(target_os = "windows")]
    {
        let path = match state_dir.or_else(|| {
            std::env::var_os("LOCALAPPDATA")
                .map(|p| PathBuf::from(p).join("StyxPreview/WindowsFirst"))
        }) {
            Some(path) => path,
            None => return error("app_control_state_dir_required"),
        };
        match styx_runtime::app_control::request(&path, operation).await {
            Ok(report) => {
                let code = report.exit_code();
                if json {
                    if write_json(&report).is_err() {
                        return error("output_unavailable");
                    }
                } else {
                    eprintln!(
                        "Styx App: {}{}",
                        report.status,
                        report
                            .code
                            .as_ref()
                            .map(|s| format!(" ({s})"))
                            .unwrap_or_default()
                    );
                }
                ExitCode::from(code)
            }
            Err(err) => error(err.0),
        }
    }
}

pub(crate) async fn run(cli: Cli) -> ExitCode {
    use styx_runtime::foreground::{self, HostWireMode};
    match cli.command {
        Command::Quit { state_dir, json } => {
            local_app(state_dir, styx_runtime::app_control::Operation::Quit, json).await
        }
        Command::App {
            command: LocalAppCommand::Status { state_dir, json },
        } => {
            local_app(
                state_dir,
                styx_runtime::app_control::Operation::Status,
                json,
            )
            .await
        }
        Command::Install {
            payload_dir,
            publisher_file,
            expected_publisher,
            bin_dir,
            authorize,
        } => setup_result(
            install::run(
                payload_dir,
                publisher_file,
                expected_publisher,
                bin_dir,
                authorize,
            )
            .await,
        ),
        Command::Plugin {
            root,
            gateway_state_dir,
            command,
        } => setup_result(plugin_command::run(root, gateway_state_dir, command).await),
        Command::Setup {
            root,
            answers,
            foreground,
            exit_when_connected,
        } => setup_result(setup::run(root, answers, foreground, exit_when_connected).await),
        Command::Invite { root } => setup_result(setup::invite(root).await),
        Command::Computers { root, all, command } => {
            setup_result(computers::run(root, all, command).await)
        }
        Command::Upgrade {
            payload,
            publisher_file,
            expected_publisher,
            root,
            yes,
        } => {
            setup_result(upgrade::run(payload, publisher_file, expected_publisher, root, yes).await)
        }
        Command::Uninstall { root, yes } => setup_result(setup::uninstall(root, yes).await),
        Command::Status {
            state_dir: None,
            root,
            json,
            ..
        } => setup_result(status_view::run(root, json).await),
        Command::Role {
            command:
                RoleCommand::Retire {
                    state_dir,
                    setup_root,
                    gateway_state_dir,
                    allow_other_devices,
                    authorize,
                    json,
                },
        } => {
            if !authorize {
                return error("role_retire_authorization_required");
            }
            if setup_root.is_some() && (gateway_state_dir.is_some() || allow_other_devices) {
                return error("role_retire_invalid_options");
            }
            let result = tokio::task::spawn_blocking(move || {
                if let Some(root) = setup_root {
                    return styx_runtime::management::role_retire::retire_setup_host(
                        &root, &state_dir,
                    );
                }
                styx_runtime::management::role_retire::retire_role(
                    &state_dir,
                    gateway_state_dir.as_deref(),
                    styx_runtime::management::role_retire::RetireOptions {
                        allow_other_devices,
                    },
                )
            })
            .await;
            match result {
                Ok(Ok(report)) => {
                    if json {
                        if write_json(&report).is_err() {
                            return error("output_unavailable");
                        }
                    } else {
                        println!(
                            "Role retired; use --json for backup paths, then set up or join again."
                        );
                    }
                    ExitCode::SUCCESS
                }
                Ok(Err(failure)) => {
                    if json {
                        let body =
                            serde_json::json!({"error":failure.code,"retirement":failure.report});
                        if write_json(&body).is_err() {
                            return error("output_unavailable");
                        }
                    } else {
                        eprintln!("{}", failure.code);
                    }
                    ExitCode::from(failure.exit_code())
                }
                Err(_) => error("role_retire_worker_unknown"),
            }
        }

        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        Command::Service {
            action,
            state_dir,
            component,
            transaction_id,
            expected_revision,
            authorize,
            json,
        } => {
            if action != ServiceActionArg::Status && !authorize {
                return error("explicit_service_authorization_required");
            }
            let transaction_id = match transaction_id
                .map(styx_contracts::identity::TransactionId::try_from)
                .transpose()
            {
                Ok(v) => v,
                Err(_) => return error("native_management_invalid_input"),
            };
            native_recovery_result(
                styx_runtime::management::native::service::manage(
                    &state_dir,
                    action.native(),
                    component.native(),
                    transaction_id,
                    expected_revision,
                )
                .await,
                json,
                "Native service observations; inspect canonical intent and actual OS state:",
            )
        }
        #[cfg(target_os = "macos")]
        Command::MacService {
            action,
            state_dir,
            component,
            transaction_id,
            expected_revision,
            runtime_selection_file,
            authorize,
            json,
        } => {
            if matches!(
                action,
                MacServiceActionArg::PrepareInstall
                    | MacServiceActionArg::PrepareFirstStart
                    | MacServiceActionArg::PrepareRecovery
                    | MacServiceActionArg::PrepareRuntimeRepair
                    | MacServiceActionArg::RecoverRuntimeRepair
                    | MacServiceActionArg::Stop
                    | MacServiceActionArg::Start
                    | MacServiceActionArg::Enable
                    | MacServiceActionArg::Disable
                    | MacServiceActionArg::Uninstall
            ) {
                if !authorize {
                    return error("explicit_service_authorization_required");
                }
                if matches!(
                    action,
                    MacServiceActionArg::PrepareRecovery
                        | MacServiceActionArg::PrepareRuntimeRepair
                        | MacServiceActionArg::RecoverRuntimeRepair
                ) && !matches!(component, NativeComponentArg::Gateway)
                {
                    return error("native_service_gateway_only");
                }
            }
            let transaction_id = match transaction_id
                .map(styx_contracts::identity::TransactionId::try_from)
                .transpose()
            {
                Ok(value) => value,
                Err(_) => return error("native_management_invalid_input"),
            };
            let result = if action == MacServiceActionArg::PrepareRuntimeRepair {
                let (Some(selection), Some(id), Some(revision)) = (
                    runtime_selection_file.as_deref(),
                    transaction_id,
                    expected_revision,
                ) else {
                    return error("explicit_service_repair_inputs_required");
                };
                styx_runtime::management::native::service::prepare_runtime_repair(
                    &state_dir, selection, id, revision,
                )
                .await
            } else if action == MacServiceActionArg::RecoverRuntimeRepair {
                if runtime_selection_file.is_some() {
                    return error("runtime_selection_only_for_service_repair");
                }
                let (Some(id), Some(revision)) = (transaction_id, expected_revision) else {
                    return error("explicit_service_repair_inputs_required");
                };
                styx_runtime::management::native::service::recover_runtime_repair(
                    &state_dir, id, revision,
                )
                .await
            } else {
                if runtime_selection_file.is_some() {
                    return error("runtime_selection_only_for_service_repair");
                }
                styx_runtime::management::native::service::manage(
                    &state_dir,
                    action.native(),
                    component.native(),
                    transaction_id,
                    expected_revision,
                )
                .await
            };
            native_recovery_result(
                result,
                json,
                "Native launchd intent and observations; prepared installation does not prove registration or readiness:",
            )
        }
        #[cfg(any(all(target_os = "linux", target_env = "gnu"), target_os = "macos"))]
        Command::ServiceRun { state_dir, role } => {
            let cancel = CancellationToken::new();
            let (events, mut received) = tokio::sync::mpsc::channel(16);
            let output_cancel = cancel.clone();
            let output = tokio::spawn(async move {
                let mut healthy = true;
                while let Some(event) = received.recv().await {
                    if healthy && write_json(&event).is_err() {
                        healthy = false;
                        output_cancel.cancel();
                    }
                }
                healthy
            });
            let running = styx_runtime::management::native::service::run(
                &state_dir,
                role.native(),
                cancel.clone(),
                events,
            );
            tokio::pin!(running);
            let result = tokio::select! {result=&mut running=>result,signal=stop_signal()=>{if signal.is_err(){cancel.cancel();let _=running.await;return error("signal_listener_failed");}cancel.cancel();running.await}};
            if !output.await.unwrap_or(false) {
                return error("output_unavailable");
            }
            native_recovery_result(
                result,
                true,
                "Native service stopped with physical cleanup observations:",
            )
        }
        #[cfg(target_os = "windows")]
        Command::ServiceRun { .. } => {
            error("windows_service_requires_original_pre_runtime_dispatch")
        }
        Command::AppCore {
            state_dir,
            deployment_file,
            runtime_selection_file,
        } => {
            let cancel = CancellationToken::new();
            let signal_cancel = cancel.clone();
            let signal = tokio::spawn(async move {
                let result = stop_signal().await;
                signal_cancel.cancel();
                result
            });
            let result = match (deployment_file, runtime_selection_file) {
                (Some(deployment), None) => {
                    styx_runtime::app::serve(
                        &state_dir,
                        &deployment,
                        tokio::io::stdin(),
                        tokio::io::stdout(),
                        cancel,
                    )
                    .await
                }
                (None, Some(selection)) => {
                    styx_runtime::app::serve_native(
                        &state_dir,
                        &selection,
                        tokio::io::stdin(),
                        tokio::io::stdout(),
                        cancel,
                    )
                    .await
                }
                _ => return error("app_startup_invalid"),
            };
            let signal_failed = if signal.is_finished() {
                !matches!(signal.await, Ok(Ok(())))
            } else {
                signal.abort();
                let _ = signal.await;
                false
            };
            if signal_failed {
                return error("signal_listener_failed");
            }
            match result {
                Ok(()) => ExitCode::SUCCESS,
                Err(value) => error(value.code()),
            }
        }
        Command::LinuxDesktopProbe => desktop_probe_worker().await,
        Command::LinuxDesktopWatch => desktop_watch_worker().await,
        Command::LinuxDesktopAssociation { candidate } => {
            desktop_association_worker(&candidate).await
        }
        Command::LinuxDesktopAssociationCheck { candidate } => {
            desktop_association_check(&candidate).await
        }
        Command::Init {
            parent_dir,
            name,
            deployment_file,
            mode,
            manager,
            host,
            gateway,
            json,
        } => {
            let options = styx_runtime::management::native::NativeCreateOptions {
                mode: mode.native(),
                manager: manager.native(),
                host,
                gateway,
            };
            native_result(
                styx_runtime::management::native::initialize(
                    &parent_dir,
                    &name,
                    &deployment_file,
                    options,
                )
                .await,
                json,
                "Native configuration initialized with stopped/disabled intent; no service started:",
            )
        }
        Command::Plan {
            native: true,
            state_dir,
            json,
            component,
            run,
            transaction_id,
            sequence,
        } => {
            let (Some(component), Some(run), Some(transaction_id), Some(sequence)) =
                (component, run, transaction_id, sequence)
            else {
                return error("native_plan_arguments_required");
            };
            let Ok(transaction_id) =
                styx_contracts::identity::TransactionId::try_from(transaction_id)
            else {
                return error("invalid_transaction_id");
            };
            let change = styx_runtime::management::native::NativeDesiredChange {
                component: component.native(),
                run: run.native(),
                transaction_id,
                sequence,
            };
            native_result(
                styx_runtime::management::native::plan(&state_dir, change).await,
                json,
                "Native desired-state plan prepared for review; no service changed:",
            )
        }
        Command::Apply {
            state_dir,
            plan_file,
            authorize,
            json,
        } => {
            if !authorize {
                return error("authorization_required");
            }
            native_result(
                styx_runtime::management::native::apply(&state_dir, &plan_file).await,
                json,
                "Native desired-state transaction; inspect report for completion:",
            )
        }
        Command::Recover {
            state_dir,
            transaction_id,
            authorize,
            json,
        } => {
            if !authorize {
                return error("authorization_required");
            }
            let result =
                styx_runtime::management::native::recover(&state_dir, &transaction_id).await;
            native_recovery_result(
                result,
                json,
                "Original native transaction reconciliation; no automatic service start:",
            )
        }
        Command::Transaction {
            state_dir,
            transaction_id,
            json,
        } => native_result(
            styx_runtime::management::native::inspect(&state_dir, Some(&transaction_id)).await,
            json,
            "Read-only native transaction report:",
        ),
        Command::Status {
            native: true,
            state_dir: Some(state_dir),
            json,
            ..
        } => native_result(
            styx_runtime::management::native::inspect(&state_dir, None).await,
            json,
            "Read-only native configuration report:",
        ),
        Command::Plan {
            native: false,
            state_dir,
            json,
            ..
        } => match styx_runtime::management::inspect_deployment(&state_dir).await {
            Ok(plan) => {
                if !json {
                    eprintln!(
                        "Configuration intent; runtime health and management ownership are unobserved:"
                    );
                }
                if write_json(&plan).is_err() {
                    error("output_unavailable")
                } else {
                    ExitCode::SUCCESS
                }
            }
            Err(value) => error(value.code()),
        },
        Command::Release {
            command:
                ReleaseCommand::Select {
                    state_dir,
                    runtime_selection_file,
                    transaction_id,
                    sequence,
                    authorize,
                    json,
                },
        } => {
            if !authorize {
                return error("native_management_authorization_required");
            }
            match styx_runtime::management::native::update::select_runtime(
                &state_dir,
                &runtime_selection_file,
                &transaction_id,
                sequence,
            )
            .await
            {
                Ok(report) => {
                    if !json {
                        eprintln!(
                            "Stopped profile runtime selection committed; start the role explicitly."
                        );
                    }
                    if write_json(&report).is_ok() {
                        ExitCode::SUCCESS
                    } else {
                        eprintln!(
                            "{}",
                            serde_json::json!({"schema":1,"error":"output_unavailable","outcome":"unknown","operations_replayed":false})
                        );
                        ExitCode::from(4)
                    }
                }
                Err(value) => {
                    eprintln!("{}", native_error_output(&value));
                    ExitCode::from(value.exit_code())
                }
            }
        }
        Command::Release {
            command:
                ReleaseCommand::Stage {
                    payload_dir,
                    publisher_file,
                    expected_publisher,
                    parent_dir,
                    name,
                    authorize,
                    json,
                },
        } => {
            if !authorize {
                return error("native_release_authorization_required");
            }
            match styx_runtime::release::stage(
                &payload_dir,
                &publisher_file,
                &expected_publisher,
                &parent_dir,
                &name,
            )
            .await
            {
                Ok(selection) => {
                    if !json {
                        eprintln!(
                            "Verified runtime staged; no configuration or running component changed."
                        );
                    }
                    if write_json(&serde_json::json!({
                        "schema": 1, "operation": "release_stage", "staged": true,
                        "installed": false, "runtime_launched": false, "operations_replayed": false,
                        "runtime_selection": selection,
                    }))
                    .is_ok()
                    {
                        ExitCode::SUCCESS
                    } else {
                        eprintln!(
                            "{}",
                            serde_json::json!({"schema":1,"error":"output_unavailable","outcome":"unknown","operations_replayed":false})
                        );
                        ExitCode::from(4)
                    }
                }
                Err(value) => {
                    eprintln!(
                        "{}",
                        serde_json::json!({"schema":1,"error":value.code(),"operations_replayed":false})
                    );
                    ExitCode::from(value.exit_code())
                }
            }
        }
        Command::Release {
            command:
                ReleaseCommand::InstalledSelection {
                    payload_dir,
                    publisher_file,
                    expected_publisher,
                },
        } => {
            match styx_runtime::release::installed_selection(
                &payload_dir,
                &publisher_file,
                &expected_publisher,
            )
            .await
            {
                Ok(selection) => {
                    if write_json(&selection).is_ok() {
                        ExitCode::SUCCESS
                    } else {
                        error("output_unavailable")
                    }
                }
                Err(value) => error(value.code()),
            }
        }
        Command::Release {
            command:
                ReleaseCommand::Verify {
                    payload_dir,
                    publisher_file,
                    expected_publisher,
                    json,
                    runtime_selection,
                },
        } => {
            if runtime_selection {
                return match styx_runtime::release::inspect_selection(
                    &payload_dir,
                    &publisher_file,
                    &expected_publisher,
                )
                .await
                {
                    Ok(selection) => {
                        if write_json(&selection).is_ok() {
                            ExitCode::SUCCESS
                        } else {
                            error("output_unavailable")
                        }
                    }
                    Err(value) => error(value.code()),
                };
            }
            match styx_runtime::release::inspect(&payload_dir, &publisher_file, &expected_publisher)
                .await
            {
                Ok(report) => {
                    if !json {
                        eprintln!(
                            "Offline release verification; no installation or runtime activation:"
                        );
                    }
                    if write_json(&report).is_err() {
                        error("output_unavailable")
                    } else {
                        ExitCode::SUCCESS
                    }
                }
                Err(value) => {
                    eprintln!("{}", serde_json::json!({"schema":1,"error":value.code()}));
                    ExitCode::from(value.exit_code())
                }
            }
        }
        Command::BuildInfo { json } => {
            if json {
                return if write_json(&native_build_info()).is_ok() {
                    ExitCode::SUCCESS
                } else {
                    error("output_unavailable")
                };
            }
            println!(
                "styx {} contract={} stage={}",
                env!("CARGO_PKG_VERSION"),
                styx_contracts::CONTRACT_VERSION,
                styx_runtime::IMPLEMENTATION_STAGE
            );
            ExitCode::SUCCESS
        }
        Command::Host {
            command: HostCommand::Join { command },
        } => match command {
            HostJoinCommand::Request {
                parent_dir,
                name,
                deployment_file,
                json,
            } => join_result(
                styx_runtime::management::native_join::request(
                    &parent_dir,
                    &name,
                    &deployment_file,
                )
                .await,
                json,
            ),
            HostJoinCommand::Claim { state_dir, json } => join_result(
                styx_runtime::management::native_join::claim(&state_dir).await,
                json,
            ),
        },
        Command::Host {
            command: HostCommand::Start {
                state_dir, json, ..
            },
        } => transient_manager::start(state_dir, json).await,
        Command::Host {
            command:
                HostCommand::Status {
                    state_dir,
                    owner_file,
                    json,
                    ..
                },
        } => transient_manager::query(state_dir, owner_file, json).await,
        Command::Host {
            command:
                HostCommand::Stop {
                    state_dir: Some(state_dir),
                    transient: true,
                    owner_file: Some(owner_file),
                    expected_invocation: Some(expected),
                    json,
                },
        } => transient_manager::stop(state_dir, owner_file, expected, json).await,
        Command::Gateway {
            command: GatewayCommand::Tunnel { command },
        } => {
            use foreground::tunnel;
            let (result, json) = match command {
                GatewayTunnelCommand::Configure {
                    state_dir,
                    tunnel_id,
                    api_key_file,
                    auto_start,
                    authorize,
                    json,
                } => {
                    let result = tokio::task::spawn_blocking(move || {
                        tunnel::configure(
                            &state_dir,
                            &tunnel_id,
                            &api_key_file,
                            auto_start,
                            authorize,
                        )
                    })
                    .await;
                    (result.unwrap_or_else(|_| Err(tunnel::worker_error())), json)
                }
                GatewayTunnelCommand::Status { state_dir, json } => {
                    (tunnel::status(&state_dir).await, json)
                }
                GatewayTunnelCommand::Remove {
                    state_dir,
                    authorize,
                    json,
                } => {
                    let result =
                        tokio::task::spawn_blocking(move || tunnel::remove(&state_dir, authorize))
                            .await;
                    (result.unwrap_or_else(|_| Err(tunnel::worker_error())), json)
                }
            };
            match result {
                Ok(report) => {
                    if json {
                        if write_json(&report).is_err() {
                            return error("output_unavailable");
                        }
                    } else {
                        println!("Gateway tunnel configuration observed; use --json for details.");
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => error(e.code()),
            }
        }
        Command::Gateway {
            command:
                GatewayCommand::Invite {
                    state_dir,
                    invitation_file,
                    ttl_seconds,
                    origin,
                    origin_address,
                    app_link_file,
                    json,
                    ..
                },
        } => {
            use styx_runtime::management::native_gateway_admin::{self, InvitationOrigin};
            let origin = origin_address.map(InvitationOrigin::Address).or_else(|| {
                origin.map(|origin| match origin {
                    GatewayInviteOrigin::Loopback => InvitationOrigin::Loopback,
                    GatewayInviteOrigin::Lan => InvitationOrigin::Lan,
                })
            });
            gateway_admin_result(
                native_gateway_admin::invite_with_options(
                    &state_dir,
                    &invitation_file,
                    ttl_seconds,
                    origin,
                    app_link_file.as_deref(),
                )
                .await,
                json,
            )
        }
        Command::Gateway {
            command: GatewayCommand::Pending { state_dir, json },
        } => gateway_admin_result(
            styx_runtime::management::native_gateway_admin::pending(&state_dir).await,
            json,
        ),
        Command::Gateway {
            command:
                GatewayCommand::Approve {
                    state_dir,
                    request_id,
                    device_id,
                    fingerprint,
                    comparison_code,
                    enable_computer,
                    enable_browser,
                    json,
                    ..
                },
        } => {
            let Ok(device_id) = styx_contracts::identity::DeviceId::try_from(device_id) else {
                return error("native_gateway_admin_input");
            };
            let Ok(fingerprint) = styx_contracts::identity::Sha256Digest::try_from(fingerprint)
            else {
                return error("native_gateway_admin_input");
            };
            let selected = styx_runtime::management::native_gateway_admin::ApprovalSelection {
                request_id,
                device_id,
                fingerprint,
                comparison_code,
                enable_computer,
                enable_browser,
            };
            gateway_admin_result(
                styx_runtime::management::native_gateway_admin::approve(&state_dir, selected).await,
                json,
            )
        }
        Command::Gateway {
            command:
                GatewayCommand::Reject {
                    state_dir,
                    request_id,
                    device_id,
                    fingerprint,
                    comparison_code,
                    json,
                    ..
                },
        } => {
            let Ok(device_id) = styx_contracts::identity::DeviceId::try_from(device_id) else {
                return error("native_gateway_admin_input");
            };
            let Ok(fingerprint) = styx_contracts::identity::Sha256Digest::try_from(fingerprint)
            else {
                return error("native_gateway_admin_input");
            };
            let selected = styx_runtime::management::native_gateway_admin::RejectionSelection {
                request_id,
                device_id,
                fingerprint,
                comparison_code,
            };
            gateway_admin_result(
                styx_runtime::management::native_gateway_admin::reject(&state_dir, selected).await,
                json,
            )
        }
        Command::Gateway {
            command:
                GatewayCommand::Bootstrap {
                    parent_dir,
                    name,
                    deployment_file,
                    runtime_selection_file,
                    json,
                },
        } => {
            match styx_runtime::management::native_gateway::bootstrap(
                &parent_dir,
                &name,
                &deployment_file,
                &runtime_selection_file,
            )
            .await
            {
                Ok(value) => {
                    if !json {
                        eprintln!(
                            "Fresh Gateway-only foreground configuration initialized; Gateway not started:"
                        );
                    }
                    if write_json(&value).is_err() {
                        error("output_unavailable")
                    } else {
                        ExitCode::SUCCESS
                    }
                }
                Err(value) => {
                    // Retain the owned error through output, as for native_result.
                    eprintln!("{}", serde_json::json!({"schema":1,"error":value.code()}));
                    ExitCode::from(value.exit_code())
                }
            }
        }
        Command::Gateway {
            command: GatewayCommand::Run {
                state_dir: Some(state_dir),
            },
        } => {
            let cancel = CancellationToken::new();
            let (events, mut received) = tokio::sync::mpsc::channel(16);
            let event_cancel = cancel.clone();
            let output = tokio::spawn(async move {
                let mut healthy = true;
                while let Some(event) = received.recv().await {
                    if healthy && write_json(&event).is_err() {
                        healthy = false;
                        event_cancel.cancel();
                    }
                }
                healthy
            });
            let mut signal_failed = false;
            let outcome = {
                let running = foreground::gateway_run(&state_dir, cancel.clone(), events);
                tokio::pin!(running);
                tokio::select! {
                    result = &mut running => result,
                    signal = stop_signal() => {
                        signal_failed = signal.is_err();
                        cancel.cancel();
                        // The original owned future retains its leases until
                        // tracked connections, native owners and workers settle.
                        running.await
                    },
                }
            };
            let output_healthy = output.await.unwrap_or(false);
            if signal_failed {
                return error("signal_listener_failed");
            }
            if !output_healthy {
                return error("output_unavailable");
            }
            match outcome {
                Ok(outcome) => {
                    if write_json(&outcome).is_err() {
                        return error("output_unavailable");
                    }
                    if outcome.is_complete() {
                        ExitCode::SUCCESS
                    } else if outcome.local_stop_complete()
                        && (outcome.unconfirmed_owner_cleanups > 0
                            || outcome.unconfirmed_transport_drains > 0)
                        && !outcome.worker_failure_observed
                        && !outcome.listener_error_observed
                    {
                        // A stopped local Gateway is not proof of remote native
                        // cleanup. Keep that uncertainty visible and nonzero.
                        eprintln!(
                            "{}",
                            serde_json::json!({"schema":1,"error":if outcome.unconfirmed_owner_cleanups > 0 {
                                "remote_owner_cleanup_unconfirmed"
                            } else {
                                "remote_transport_drain_unconfirmed"
                            }})
                        );
                        ExitCode::from(4)
                    } else {
                        error("gateway_shutdown_unknown")
                    }
                }
                Err(error_value) => error(error_value.code()),
            }
        }
        Command::Gateway {
            command: GatewayCommand::Run { state_dir: None },
        } => error("gateway_input_required"),
        Command::Host {
            command:
                HostCommand::Stop { .. } | HostCommand::Pause { .. } | HostCommand::Resume { .. },
        } => error("unsupported"),
        Command::Doctor {
            desktop_sessions: true,
            watch: true,
            json,
            ..
        } => desktop_watch_diagnostics(json).await,
        Command::Doctor {
            desktop_sessions: true,
            json,
            ..
        } => desktop_diagnostics(json).await,
        Command::Status {
            native: false,
            state_dir: Some(state_dir),
            json,
            ..
        }
        | Command::Doctor {
            state_dir: Some(state_dir),
            json,
            ..
        } => {
            match foreground::inspect(&state_dir).await {
                Ok(diagnostics) => {
                    // The same redacted diagnostics are used in both modes;
                    // --json commits to one JSON line for machine consumers.
                    if !json {
                        eprintln!("Read-only deployment diagnostics:");
                    }
                    if write_json(&diagnostics).is_err() {
                        return error("output_unavailable");
                    }
                    ExitCode::SUCCESS
                }
                Err(error_value) => error(error_value.code()),
            }
        }
        Command::Doctor {
            state_dir: None, ..
        } => error("doctor_input_required"),
        Command::Host {
            command: HostCommand::Run { state_dir },
        } => {
            let cancel = CancellationToken::new();
            let (events, mut received) = tokio::sync::mpsc::channel(16);
            let event_cancel = cancel.clone();
            let output = tokio::spawn(async move {
                let mut healthy = true;
                while let Some(event) = received.recv().await {
                    if healthy && write_json(&event).is_err() {
                        healthy = false;
                        event_cancel.cancel();
                    }
                }
                healthy
            });
            let mut signal_failed = false;
            let outcome = {
                let running = foreground::host_run(
                    &state_dir,
                    HostWireMode::PairedV3,
                    cancel.clone(),
                    events,
                );
                tokio::pin!(running);
                tokio::select! {
                    result=&mut running=>result,
                    signal=stop_signal()=>{
                        signal_failed = signal.is_err();
                        cancel.cancel();
                        // Keep the SAME foreground future alive for real bounded
                        // cleanup. Dropping it or exiting here would fake stop.
                        running.await
                    },
                }
            };
            let output_healthy = output.await.unwrap_or(false);
            if signal_failed {
                return error("signal_listener_failed");
            }
            if !output_healthy {
                return error("output_unavailable");
            }
            match outcome {
                Ok(outcome) => {
                    if write_json(&outcome).is_err() {
                        return error("output_unavailable");
                    }
                    if outcome.is_complete() {
                        ExitCode::SUCCESS
                    } else {
                        error("host_shutdown_unknown")
                    }
                }
                Err(error_value) => error(error_value.code()),
            }
        }
    }
}
#[path = "cli_manager.rs"]
mod transient_manager;

#[cfg(test)]
#[path = "cli_tests.rs"]
mod tests;
