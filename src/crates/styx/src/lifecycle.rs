//! User-facing lifecycle commands over the existing native service owner.
//! No second journal or retry loop: an uncertain mutation retains its owner.
use super::setup::Failure;
use std::path::PathBuf;

#[cfg(all(target_os = "linux", target_env = "gnu"))]
use styx_contracts::native_management::{NativeManager, NativeRunDesired};
#[cfg(all(target_os = "linux", target_env = "gnu"))]
use styx_runtime::management::native::{
    NativeComponent,
    service::{ServiceAction, ServiceReport, manage},
};

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn reached(report: &ServiceReport, component: NativeComponent, start: bool) -> bool {
    let desired = match component {
        NativeComponent::Host => report.desired.host,
        NativeComponent::Gateway => report.desired.gateway,
    };
    let Some(desired) = desired else {
        return false;
    };
    if desired.manager != NativeManager::PersistentService || report.os["installed"] != true {
        return false;
    }
    if start {
        desired.run == NativeRunDesired::Running
            && report.os["active"] == "active"
            && report.os["main_pid"].as_u64().is_some_and(|pid| pid != 0)
    } else {
        desired.run == NativeRunDesired::Stopped
            && report.os["main_pid"] == 0
            && (report.os["active"] == "inactive"
                || (report.os["active"] == "failed" && report.os["cgroup"] == ""))
    }
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
async fn wait_for_exit(path: &std::path::Path) -> Result<(), Failure> {
    let until = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
    while !super::setup::running_roles(path).is_empty() {
        if tokio::time::Instant::now() >= until {
            return Err(Failure::unknown("quit_process_exit_unconfirmed"));
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    Ok(())
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub(super) async fn run(root: Option<PathBuf>, start: bool) -> Result<(), Failure> {
    let root = root.map(Ok).unwrap_or_else(super::setup::root_default)?;
    let roles = if start {
        [
            ("Gateway", "gateway", NativeComponent::Gateway),
            ("This computer", "host", NativeComponent::Host),
        ]
    } else {
        [
            ("This computer", "host", NativeComponent::Host),
            ("Gateway", "gateway", NativeComponent::Gateway),
        ]
    };
    let mut found = false;
    for (label, directory, component) in roles {
        let path = root.join(directory);
        if !path.is_dir() {
            continue;
        }
        found = true;
        let before = manage(&path, ServiceAction::Status, component, None, None)
            .await
            .map_err(Failure::native)?;
        if reached(&before, component, start) {
            if !start {
                wait_for_exit(&path).await?;
            }
            println!(
                "{label}: already {}.",
                if start { "running" } else { "stopped" }
            );
            continue;
        }
        if before.os["installed"] != true {
            println!("{label}: run styx setup to install its service first.");
            return Err(Failure::new("lifecycle_service_not_installed"));
        }
        let action = if start {
            ServiceAction::Start
        } else {
            ServiceAction::Stop
        };
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Failure::new("lifecycle_clock_unavailable"))?
            .as_nanos();
        let transaction = format!(
            "cli-{}-{directory}-{}-{}-{timestamp}",
            if start { "start" } else { "quit" },
            std::process::id(),
            before.revision,
        )
        .try_into()
        .map_err(|_| Failure::new("lifecycle_transaction_id_invalid"))?;
        // One dispatch against the fresh original revision. In particular, an
        // Unknown error is returned with its native owner, never retried with a
        // fresh transaction or translated into success from a newer revision.
        manage(
            &path,
            action,
            component,
            Some(transaction),
            Some(before.revision),
        )
        .await
        .map_err(Failure::native)?;
        if !start {
            wait_for_exit(&path).await?;
        }
        let after = manage(&path, ServiceAction::Status, component, None, None)
            .await
            .map_err(Failure::native)?;
        if !reached(&after, component, start) {
            return Err(Failure::unknown("lifecycle_result_unconfirmed"));
        }
        println!("{label}: {}.", if start { "started" } else { "stopped" });
    }
    if !found {
        println!("Styx is not set up here. Run styx setup first.");
        return Err(Failure::new("lifecycle_nothing_set_up"));
    }
    if start {
        println!("Styx is running. Use styx status to check connections.");
    } else {
        wait_for_exit(&root).await?;
        println!("Styx has quit. Settings and pairing are retained. Use styx start to reopen it.");
    }
    Ok(())
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
pub(super) async fn run(_: Option<PathBuf>, _: bool) -> Result<(), Failure> {
    println!("Open or quit Styx using the desktop App.");
    Err(Failure::new("lifecycle_use_the_app"))
}

#[cfg(all(test, target_os = "linux", target_env = "gnu"))]
mod tests {
    use super::*;
    use serde_json::json;
    use styx_contracts::native_management::{
        NativeAutostartDesired, NativeComponentDesired, NativeDesired,
    };

    fn report(run: NativeRunDesired, active: &str, pid: u32) -> ServiceReport {
        ServiceReport {
            schema: 1,
            operation: "status",
            configuration_only: false,
            transaction_id: None,
            revision: 4,
            desired: NativeDesired {
                gateway: Some(NativeComponentDesired {
                    manager: NativeManager::PersistentService,
                    run,
                    autostart: NativeAutostartDesired::Enabled,
                }),
                host: None,
            },
            os: json!({"installed":true,"active":active,"main_pid":pid,"cgroup":""}),
            operations_replayed: false,
            transaction_observation: None,
        }
    }

    #[test]
    fn running_requires_both_desired_state_and_actual_process() {
        let running = report(NativeRunDesired::Running, "active", 42);
        assert!(reached(&running, NativeComponent::Gateway, true));
        assert!(!reached(&running, NativeComponent::Host, true));
        assert!(!reached(
            &report(NativeRunDesired::Stopped, "active", 42),
            NativeComponent::Gateway,
            true
        ));
        assert!(!reached(
            &report(NativeRunDesired::Running, "active", 0),
            NativeComponent::Gateway,
            true
        ));
        assert!(!reached(
            &report(NativeRunDesired::Running, "failed", 0),
            NativeComponent::Gateway,
            true
        ));
    }

    #[test]
    fn stopping_is_not_inferred_from_desired_state_or_failed_unit_alone() {
        assert!(reached(
            &report(NativeRunDesired::Stopped, "inactive", 0),
            NativeComponent::Gateway,
            false
        ));
        assert!(!reached(
            &report(NativeRunDesired::Running, "inactive", 0),
            NativeComponent::Gateway,
            false
        ));
        assert!(!reached(
            &report(NativeRunDesired::Stopped, "deactivating", 42),
            NativeComponent::Gateway,
            false
        ));
        let mut failed = report(NativeRunDesired::Stopped, "failed", 0);
        assert!(reached(&failed, NativeComponent::Gateway, false));
        failed.os["cgroup"] = json!("/user.slice/still-owned");
        assert!(!reached(&failed, NativeComponent::Gateway, false));
        failed.os["cgroup"] = json!("");
        failed.os["installed"] = json!(false);
        assert!(!reached(&failed, NativeComponent::Gateway, false));
    }
}
