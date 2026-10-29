use super::setup::{self, Answers, Failure, Role};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use styx_runtime::management::{native, native_gateway_admin as admin, setup as inputs};

pub(super) async fn observe(root: &Path) -> Result<Value, Failure> {
    let answers = Answers::load(&root.join("inputs/setup-intent.json"))?;
    let payload = if root.join("inputs/runtime-selection.json").exists() {
        let selection: styx_contracts::native_management::NativeRuntimeSelection =
            serde_json::from_slice(
                &inputs::read_private(&root.join("inputs/runtime-selection.json"), 1024 * 1024)
                    .map_err(|_| Failure::new("status_runtime_selection_unavailable"))?,
            )
            .map_err(|_| Failure::new("status_runtime_selection_invalid"))?;
        let candidate = styx_runtime::release::verify_selected(&selection)
            .map_err(|e| Failure::new(e.code()))?;
        json!({"version":candidate.report().version,"manifest_sha256":selection.manifest_sha256})
    } else {
        json!({"version":"not selected"})
    };
    let mut services = json!({});
    for (name, component) in [
        ("gateway", native::NativeComponent::Gateway),
        ("host", native::NativeComponent::Host),
    ] {
        let path = root.join(name);
        if !path.exists() {
            services[name] = json!({"state":"not_configured"});
            continue;
        }
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        {
            services[name] = match native::service::manage(
                &path,
                native::service::ServiceAction::Status,
                component,
                None,
                None,
            )
            .await
            {
                Ok(report) => json!({"state":"observed","desired":report.desired,"os":report.os}),
                Err(error) => json!({"state":"unavailable","error":error.code()}),
            };
        }
        #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
        {
            let _ = component;
            services[name] = json!({"state":"foreground_only","run_command":format!("styx {name} run --state-dir {}", path.display())});
        }
    }
    let gateway = root.join("gateway");
    let mut report = json!({"schema":1,"role":answers.role,"label":answers.label,"payload_version":payload["version"],"payload_manifest_sha256":payload["manifest_sha256"],"networks":answers.networks,"services":services,"operations_replayed":false});
    if let Ok(raw) = inputs::read_private(&root.join("inputs/host-public-identity.json"), 16384)
        && let Ok(identity) = serde_json::from_slice::<Value>(&raw)
        && let Some(device) = identity["device_id"].as_str()
    {
        report["this_computer"] =
            json!({"device_id":device,"browser":answers.browser,"computer":answers.computer});
    }
    if answers.role == Role::Hub && gateway.exists() {
        report["gateway"] = match admin::observe(&gateway).await {
            Ok(observed) => observed,
            Err(error) => json!({"state":"unavailable","error":error.code()}),
        };
        report["tunnel"] = match styx_runtime::foreground::tunnel::status(&gateway).await {
            Ok(status) => serde_json::to_value(status)
                .map_err(|_| Failure::new("status_serialization_failed"))?,
            Err(error) => json!({"status":"unavailable","error":error.code()}),
        };
        report["chatgpt"] = styx_runtime::foreground::tunnel::request_observation(&gateway)
            .map_err(|e| Failure::new(e.code()))?;
    } else if root.join("inputs/host-deployment.json").exists() {
        let raw = inputs::read_private(&root.join("inputs/host-deployment.json"), 1024 * 1024)
            .map_err(|_| Failure::new("status_host_deployment_unavailable"))?;
        let deployment: Value = serde_json::from_slice(&raw)
            .map_err(|_| Failure::new("status_host_deployment_invalid"))?;
        report["gateway"] = json!({"origin":deployment["gateway"]["url"],"state":"remote_hub"});
        report["chatgpt"] = json!({"status":"observed_on_hub"});
    } else {
        report["gateway"] = json!({"state":"not_configured"});
    }
    Ok(report)
}
pub(super) async fn run(root: Option<PathBuf>, json_output: bool) -> Result<(), Failure> {
    let root = root.map(Ok).unwrap_or_else(setup::root_default)?;
    if !root.join("inputs/setup-intent.json").exists() {
        if json_output {
            println!(
                "{}",
                json!({"schema":1,"role":"not_configured","next_command":"styx setup","operations_replayed":false})
            );
        } else {
            println!("Styx is not set up. Run styx setup.");
        }
        return Ok(());
    }
    let v = observe(&root).await?;
    if json_output {
        println!("{v}");
        return Ok(());
    }
    println!(
        "{}",
        render(
            &v,
            &root,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX)
        )
    );
    Ok(())
}
fn capability_state<'a>(report: &'a Value, environment: &'a Value, name: &str) -> &'a str {
    let capability = &environment[name];
    if capability["connection"] == "connected" {
        return "connected";
    }
    let local_off = report["this_computer"]["device_id"]
        .as_str()
        .is_some_and(|id| {
            environment["environment_id"] == id && report["this_computer"][name] == false
        });
    if capability["configured"] == false || local_off {
        "off"
    } else {
        capability["connection"].as_str().unwrap_or("unknown")
    }
}
fn last_seen(timestamp: Option<u64>, now_ms: u64) -> String {
    let Some(timestamp) = timestamp else {
        return "not observed".into();
    };
    let Some(local) = inputs::local_datetime(timestamp) else {
        return "date unavailable".into();
    };
    let minutes = now_ms.saturating_sub(timestamp) / 60_000;
    format!(
        "{local} ({minutes} {} ago)",
        if minutes == 1 { "minute" } else { "minutes" }
    )
}
fn render(v: &Value, root: &Path, now_ms: u64) -> String {
    let mut lines = vec![format!(
        "Styx — {} ({})\nPayload: {}",
        v["label"].as_str().unwrap_or("computer"),
        v["role"].as_str().unwrap_or("unknown"),
        v["payload_version"].as_str().unwrap_or("unknown")
    )];
    if let Some(origins) = v["gateway"]["origins"].as_array() {
        for origin in origins {
            lines.push(format!(
                "Hub (Styx Gateway): {}",
                origin.as_str().unwrap_or("unknown")
            ));
        }
    } else {
        lines.push(format!(
            "Hub (Styx Gateway): {}",
            v["gateway"]["origin"]
                .as_str()
                .or_else(|| v["gateway"]["state"].as_str())
                .unwrap_or("unavailable")
        ));
    }
    if let (Some(connected), Some(capacity)) = (
        v["gateway"]["computers"]["connected"].as_u64(),
        v["gateway"]["computers"]["capacity"].as_u64(),
    ) {
        lines.push(format!("Connected computers: {connected}/{capacity}"));
    }
    if let Some(capacity) = v["gateway"]["mcp_sessions"]["capacity"].as_u64() {
        let sessions = &v["gateway"]["mcp_sessions"];
        lines.push(format!(
            "MCP sessions: {}/{} open; {} expired; {} evicted",
            sessions["open"], capacity, sessions["expired"], sessions["evicted"]
        ));
    }
    let tunnel = v["tunnel"]["status"].as_str();
    lines.push(
        if tunnel == Some("not_configured") || (v["role"] == "hub" && tunnel.is_none()) {
            format!(
                "Tunnel: not set up — run styx setup --root {} to connect ChatGPT",
                root.display()
            )
        } else {
            format!(
                "Tunnel: {} / {}",
                tunnel.unwrap_or("on hub"),
                v["tunnel"]["transport"].as_str().unwrap_or("not observed")
            )
        },
    );
    for (name, label) in [("gateway", "Hub"), ("host", "This computer")] {
        let s = &v["services"][name];
        lines.push(format!(
            "{label} service: {}, enabled {}",
            s["os"]["active"]
                .as_str()
                .or_else(|| s["state"].as_str())
                .unwrap_or("unknown"),
            s["os"]["enabled"]
                .as_bool()
                .map(|b| if b { "yes" } else { "no" })
                .unwrap_or("unknown")
        ));
    }
    if let Some(environments) = v["gateway"]["environments"].as_array() {
        for e in environments {
            lines.push(format!(
                "Computer {}: Commands {}, Browser {}, Computer Use {}",
                e["environment_id"].as_str().unwrap_or("unknown"),
                capability_state(v, e, "exec"),
                capability_state(v, e, "browser"),
                capability_state(v, e, "computer")
            ));
        }
    }
    lines.push(format!(
        "ChatGPT last seen: {}",
        if v["chatgpt"]["status"] == "observed_on_hub" {
            "check on the hub".into()
        } else {
            last_seen(v["chatgpt"]["last_seen_unix_ms"].as_u64(), now_ms)
        }
    ));
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn status_shows_connected_computers_and_hub_capacity() {
        let report = json!({"gateway":{"computers":{"connected":32,"capacity":32}}});
        assert!(
            render(&report, Path::new("/owned/styx"), 0).contains("Connected computers: 32/32")
        );
        assert!(!render(&json!({}), Path::new("/owned/styx"), 0).contains("Connected computers:"));
    }
    #[test]
    fn status_shows_session_capacity_and_close_counters() {
        let value =
            json!({"gateway":{"mcp_sessions":{"open":17,"capacity":64,"expired":11,"evicted":29}}});
        assert!(
            render(&value, Path::new("/owned"), 0)
                .contains("MCP sessions: 17/64 open; 11 expired; 29 evicted")
        );
    }
    #[test]
    fn status_distinguishes_off_from_disconnected_without_guessing_remote_settings() {
        let report =
            json!({"this_computer":{"device_id":"local","browser":false,"computer":false}});
        let mut environment = json!({"environment_id":"local","exec":{"connection":"connected"},"browser":{"connection":"disconnected","configured":"unknown"},"computer":{"connection":"disconnected","configured":"unknown"}});
        assert_eq!(capability_state(&report, &environment, "browser"), "off");
        assert_eq!(capability_state(&report, &environment, "computer"), "off");
        assert_eq!(capability_state(&report, &environment, "exec"), "connected");
        environment["environment_id"] = json!("remote");
        assert_eq!(
            capability_state(&report, &environment, "browser"),
            "disconnected"
        );
        environment["browser"]["configured"] = json!(false);
        assert_eq!(capability_state(&report, &environment, "browser"), "off");
    }
    #[test]
    fn status_shows_local_dates_relative_time_and_chatgpt_setup_command() {
        let report = json!({"role":"hub","tunnel":{"status":"not_configured"},"chatgpt":{"last_seen_unix_ms":1_700_000_000_000u64}});
        let output = render(&report, Path::new("/private/profile"), 1_700_000_120_000);
        let date = inputs::local_datetime(1_700_000_000_000).unwrap();
        assert!(output.contains(&format!("ChatGPT last seen: {date} (2 minutes ago)")));
        assert!(output.contains(
            "Tunnel: not set up — run styx setup --root /private/profile to connect ChatGPT"
        ));
        assert!(!output.contains("Unix ms"));
        assert_eq!(last_seen(None, 0), "not observed");
    }
}
