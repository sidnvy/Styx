use super::Result;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
use super::{Answers, Failure, now_ms, prompt, root_default};
#[cfg(all(target_os = "linux", target_env = "gnu"))]
use std::path::Path;
use std::path::PathBuf;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
use std::time::Duration;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
use styx_runtime::management::native;

/// Shared stop/disable/uninstall ordering and process-exit observation. The
/// caller owns dispatch receipts and confirmation of uncertain replies.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub(in crate::cli) async fn uninstall_role(
    path: &Path,
    dir: &str,
    component: native::NativeComponent,
    mut step: impl AsyncFnMut(
        native::service::ServiceAction,
        native::service::ServiceReport,
    ) -> Result<()>,
) -> Result<()> {
    use native::service::{ServiceAction, manage};
    for _ in 0..4 {
        let before = manage(path, ServiceAction::Status, component, None, None)
            .await
            .map_err(Failure::native)?;
        let os = &before.os;
        let desired = serde_json::to_value(&before.desired)
            .map_err(|_| Failure::new("uninstall_state_invalid"))?;
        let running = desired[dir]["run"] == "running"
            || !matches!(os["active"].as_str(), Some("inactive" | "failed") | None);
        let action = if os["installed"] != true {
            break;
        } else if running {
            ServiceAction::Stop
        } else if os["enabled"] == true {
            ServiceAction::Disable
        } else {
            ServiceAction::Uninstall
        };
        let stopping = action == ServiceAction::Stop;
        step(action, before).await?;
        if stopping {
            // The stopping service still reads its records while it exits;
            // the next step must not overlap that exit.
            let until = std::time::Instant::now() + Duration::from_secs(15);
            while !running_roles(path).is_empty() {
                if std::time::Instant::now() >= until {
                    return Err(Failure::unknown("uninstall_role_did_not_exit"));
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
    let after = manage(path, ServiceAction::Status, component, None, None)
        .await
        .map_err(Failure::native)?;
    if after.os["installed"] == true {
        return Err(Failure::unknown("uninstall_service_still_installed"));
    }
    Ok(())
}
#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub(in crate::cli) fn service_action_name(action: native::service::ServiceAction) -> &'static str {
    use native::service::ServiceAction;
    match action {
        ServiceAction::Install => "install",
        ServiceAction::Start => "start",
        ServiceAction::Enable => "enable",
        ServiceAction::Stop => "stop",
        ServiceAction::Disable => "disable",
        ServiceAction::Uninstall => "uninstall",
        ServiceAction::Status => "status",
    }
}

/// Stop and remove this computer's Styx login services (Linux). Data folders
/// stay in place. Each step reads the current state first; an "unknown" reply
/// is accepted only when Styx's own records show that step committed.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub(in crate::cli) async fn uninstall(root: Option<PathBuf>, yes: bool) -> Result<()> {
    use native::service::{ServiceAction, manage};
    let root = root.map(Ok).unwrap_or_else(root_default)?;
    let roles: Vec<_> = [
        ("This computer", "host", native::NativeComponent::Host),
        (
            "Hub (Styx Gateway)",
            "gateway",
            native::NativeComponent::Gateway,
        ),
    ]
    .into_iter()
    .filter(|(_, dir, _)| root.join(dir).is_dir())
    .collect();
    if roles.is_empty() {
        return Err("uninstall_nothing_set_up".into());
    }
    println!(
        "Styx will stop and remove its login services for {}.",
        root.display()
    );
    println!("Your settings, pairing and workspace stay on disk; nothing is deleted.");
    if !yes {
        if !prompt::terminal() {
            return Err("uninstall_confirmation_required_use_yes".into());
        }
        if !prompt::confirm("Uninstall Styx services now?")? {
            return Err("setup_cancelled".into());
        }
    }
    for (label, dir, component) in &roles {
        let path = root.join(dir);
        uninstall_role(&path, dir, *component, async |action, before| {
            let name = service_action_name(action);
            let tx = format!("uninstall-{dir}-{name}-{}", now_ms()?)
                .try_into()
                .map_err(|_| Failure::new("setup_transaction_id_invalid"))?;
            match manage(&path, action, *component, Some(tx), Some(before.revision)).await {
                Ok(_) => println!("{label}: {name} done."),
                Err(error) => {
                    let mut after = None;
                    for _ in 0..25 {
                        if let Ok(report) =
                            manage(&path, ServiceAction::Status, *component, None, None).await
                        {
                            after = Some(report);
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                    let after = after.ok_or_else(|| Failure::native(error))?;
                    if after.revision <= before.revision {
                        return Err(Failure::unknown("uninstall_step_outcome_unknown"));
                    }
                    println!("{label}: {name} done (confirmed from Styx's records).");
                }
            }
            Ok(())
        })
        .await?;
    }
    let remaining = running_roles(&root);
    if !remaining.is_empty() {
        println!("Still running for this setup (process ids): {remaining:?}");
        return Err(Failure::unknown("uninstall_processes_remain"));
    }
    println!("Styx services are removed and no Styx process is running for this setup.");
    println!(
        "Kept on disk: {} (settings and pairing). Delete it yourself only if you will not reuse this setup.",
        root.display()
    );
    if let Ok(answers) = Answers::load(&root.join("inputs/setup-intent.json")) {
        println!("Also kept: workspace {}", answers.workspace.display());
        println!(
            "          installed files {}",
            answers.payload.payload_dir.display()
        );
        if let Some(plugin) = answers.plugin {
            println!(
                "          ChatGPT plugin export {}",
                plugin.output.display()
            );
        }
    }
    Ok(())
}
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
pub(in crate::cli) async fn uninstall(_: Option<PathBuf>, _: bool) -> Result<()> {
    println!("On macOS and Windows, quit Styx from its menu and uninstall the App.");
    Err("uninstall_use_the_app".into())
}
/// Service processes started for this root (`__service-run --state-dir <root>/...`).
#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn running_roles(root: &Path) -> Vec<u32> {
    let prefix = root.as_os_str().as_encoded_bytes();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse::<u32>().ok())
        .filter(|pid| {
            std::fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|raw| {
                let args: Vec<&[u8]> = raw.split(|b| *b == 0).collect();
                args.iter().any(|a| *a == b"__service-run")
                    && args
                        .windows(2)
                        .any(|w| w[0] == b"--state-dir" && w[1].starts_with(prefix))
            })
        })
        .collect()
}
