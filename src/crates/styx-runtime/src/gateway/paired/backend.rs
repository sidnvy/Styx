//! Frozen public tools over authenticated paired Host operations.
//! Public session IDs are presentation handles, never dispatch authority.
use crate::gateway::{auth::VerifiedGatewayOwner, mcp::GatewayToolBackend};
use rmcp::{ErrorData, model::*};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::{collections::BTreeMap, sync::LazyLock};
use styx_contracts::identity::DeviceId;

#[path = "backend_android.rs"]
mod android;
#[path = "backend_browser.rs"]
mod browser;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[path = "backend_computer.rs"]
mod computer;

/// Human-facing metadata only. Unknown stored text is never echoed as an OS.
pub(crate) fn display_platform(stored: &str) -> &'static str {
    match stored {
        "linux" => "linux",
        "darwin" => "macos",
        "win32" => "windows",
        "android" => "android",
        _ => "unknown",
    }
}
/// Enrollment currently bounds labels to 72 Unicode characters. Keep the same
/// output bound even if a future internal metadata source has a looser reader.
fn display_label(stored: &str) -> String {
    stored.chars().take(72).collect()
}

fn environment_summary(d: &super::DeviceStatus) -> Value {
    json!({"environment_id":d.device_id.as_str(),"label":display_label(&d.label),"platform":display_platform(&d.platform),"kind":"paired","connection":if d.online || d.browser_online || d.computer_online || d.android_online {"connected"} else {"disconnected"}})
}

static PUBLIC: LazyLock<Vec<Tool>> = LazyLock::new(|| {
    let value: Value = serde_json::from_str(include_str!(
        "../../../../../docs/rust-core-rewrite/PUBLIC-MCP-V1.json"
    ))
    .expect("frozen public contract");
    serde_json::from_value(value["tools"].clone()).expect("frozen tool schemas")
});

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecArgs {
    cmd: String,
    workdir: Option<String>,
    shell: Option<String>,
    login: Option<bool>,
    tty: Option<bool>,
    yield_time_ms: Option<u32>,
    max_output_tokens: Option<usize>,
    environment_id: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WriteArgs {
    environment_id: Option<String>,
    session_id: u64,
    chars: Option<String>,
    yield_time_ms: Option<u32>,
    max_output_tokens: Option<usize>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusArgs {
    environment_id: String,
}

fn decode<T: serde::de::DeserializeOwned>(
    args: Option<Map<String, Value>>,
) -> Result<T, &'static str> {
    let mut args = args.ok_or("invalid_arguments")?;
    for (key, value) in &mut args {
        if matches!(
            key.as_str(),
            "session_id" | "yield_time_ms" | "max_output_tokens"
        ) && let Some(f) = value.as_f64()
        {
            if !f.is_finite() || f.fract() != 0.0 || !(0.0..=9_007_199_254_740_991.0).contains(&f) {
                return Err("invalid_arguments");
            }
            *value = json!(f as u64);
        }
    }
    // Explicit null is not an omitted optional field in the frozen JS contract.
    if args
        .values()
        .any(|v| v.is_null() || v.as_str().is_some_and(|s| s.contains('\0')))
    {
        return Err("invalid_arguments");
    }
    serde_json::from_value(Value::Object(args)).map_err(|_| "invalid_arguments")
}
fn bounds(wait: Option<u32>, tokens: Option<usize>) -> Result<(), &'static str> {
    if wait.is_some_and(|n| n > 30_000) || tokens.is_some_and(|n| !(1..=10_000).contains(&n)) {
        return Err("invalid_arguments");
    }
    Ok(())
}
impl ExecArgs {
    fn parse(args: Option<Map<String, Value>>) -> Result<Self, &'static str> {
        let a: Self = decode(args)?;
        bounds(a.yield_time_ms, a.max_output_tokens)?;
        if a.cmd.is_empty()
            || a.cmd.len() > 65_536
            || a.environment_id.as_ref().is_some_and(|s| s.is_empty())
        {
            return Err("invalid_arguments");
        }
        Ok(a)
    }
}
impl WriteArgs {
    fn parse(args: Option<Map<String, Value>>) -> Result<Self, &'static str> {
        let a: Self = decode(args)?;
        bounds(a.yield_time_ms, a.max_output_tokens)?;
        if !(1..(1_u64 << 48)).contains(&a.session_id)
            || a.chars.as_ref().is_some_and(|s| s.len() > 65_536)
            || a.environment_id.as_ref().is_some_and(|s| s.is_empty())
        {
            return Err("invalid_arguments");
        }
        Ok(a)
    }
}

/// Bootstrap input from the explicitly selected Host's trusted profile, not the
/// Gateway's environment or a tool argument. Missing defaults refuse execution.
#[derive(Clone)]
struct NativeExecDefaults {
    platform: String,
    cwd_file_uri: String,
    shell: String,
    allowed_shells: Vec<String>,
    environment: BTreeMap<String, String>,
}
impl NativeExecDefaults {
    fn spec(&self, a: &ExecArgs) -> Result<crate::providers::codex::StartProcess, &'static str> {
        let windows = match self.platform.as_str() {
            "win32" => true,
            "linux" | "darwin" => false,
            _ => return Err("unsupported_platform"),
        };
        let shell = a.shell.as_ref().unwrap_or(&self.shell);
        if !self.allowed_shells.contains(shell) || shell.contains('\0') {
            return Err("unsupported_shell");
        }
        let name = shell
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        let argv = if windows {
            if !matches!(name.as_str(), "powershell.exe" | "pwsh.exe" | "pwsh") {
                return Err("unsupported_shell");
            }
            let mut v = vec![shell.clone(), "-NoLogo".into()];
            if a.login != Some(true) {
                v.push("-NoProfile".into());
            }
            v.extend(["-NonInteractive".into(), "-Command".into(), a.cmd.clone()]);
            v
        } else {
            if !shell.starts_with('/') || !matches!(name.as_str(), "sh" | "bash" | "zsh") {
                return Err("unsupported_shell");
            }
            vec![
                shell.clone(),
                if a.login == Some(false) { "-c" } else { "-lc" }.into(),
                a.cmd.clone(),
            ]
        };
        let cwd_file_uri = match &a.workdir {
            None => self.cwd_file_uri.clone(),
            Some(path) => resolve_native_cwd(&self.cwd_file_uri, path, windows)?,
        };
        let uri = url::Url::parse(&cwd_file_uri).map_err(|_| "invalid_workdir")?;
        if uri.scheme() != "file"
            || uri.host_str().is_some_and(|h| !h.is_empty())
            || uri.query().is_some()
            || uri.fragment().is_some()
        {
            return Err("invalid_workdir");
        }
        let allowed: &[&str] = if windows {
            &[
                "Path",
                "PATHEXT",
                "SystemRoot",
                "WinDir",
                "ComSpec",
                "USERNAME",
                "USERPROFILE",
                "HOMEDRIVE",
                "HOMEPATH",
                "APPDATA",
                "LOCALAPPDATA",
                "TEMP",
                "TMP",
                "PSModulePath",
                "LANG",
            ]
        } else {
            &[
                "PATH", "HOME", "SHELL", "USER", "LOGNAME", "TMPDIR", "TMP", "TEMP", "LANG",
                "LC_ALL", "LC_CTYPE", "TZ",
            ]
        };
        let environment = self
            .environment
            .iter()
            .filter(|(k, v)| allowed.contains(&k.as_str()) && !v.contains('\0'))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        Ok(crate::providers::codex::StartProcess {
            argv,
            cwd_file_uri,
            environment,
            tty: a.tty.unwrap_or(false),
        })
    }
}
fn native_file_uri(path: &str, windows: bool) -> Result<String, &'static str> {
    if path.contains('\0') {
        return Err("invalid_workdir");
    }
    let normalized = if windows {
        let b = path.as_bytes();
        if b.len() < 3
            || !b[0].is_ascii_alphabetic()
            || b[1] != b':'
            || !matches!(b[2], b'\\' | b'/')
        {
            return Err("invalid_workdir");
        }
        format!("/{}", path.replace('\\', "/"))
    } else {
        if !path.starts_with('/') {
            return Err("invalid_workdir");
        }
        path.to_owned()
    };
    let mut uri = url::Url::parse("file:///").expect("fixed file URI");
    {
        let mut parts = uri.path_segments_mut().map_err(|_| "invalid_workdir")?;
        parts.clear();
        let mut depth = 0_usize;
        for segment in normalized.split('/') {
            match segment {
                "" | "." => {}
                ".." if depth > usize::from(windows) => {
                    parts.pop();
                    depth -= 1;
                }
                ".." => {}
                value => {
                    parts.push(value);
                    depth += 1;
                }
            }
        }
    }
    Ok(uri.into())
}
fn resolve_native_cwd(base: &str, path: &str, windows: bool) -> Result<String, &'static str> {
    if path.contains('\0') {
        return Err("invalid_workdir");
    }
    if path.starts_with('/') || (windows && path.as_bytes().get(1) == Some(&b':')) {
        return native_file_uri(path, windows);
    }
    if windows && path.starts_with('\\') {
        return Err("invalid_workdir");
    }
    let relative = if windows {
        path.replace('\\', "/")
    } else {
        path.to_owned()
    };
    let mut clean = url::Url::parse(base).map_err(|_| "invalid_workdir")?;
    {
        let mut depth = clean
            .path_segments()
            .ok_or("invalid_workdir")?
            .filter(|s| !s.is_empty())
            .count();
        let mut segments = clean.path_segments_mut().map_err(|_| "invalid_workdir")?;
        segments.pop_if_empty();
        for part in relative.split('/') {
            match part {
                "" | "." => {}
                ".." if depth > usize::from(windows) => {
                    segments.pop();
                    depth -= 1;
                }
                ".." => {}
                p => {
                    segments.push(p);
                    depth += 1;
                }
            }
        }
    }
    Ok(clean.into())
}
fn failure(code: &str, session: Option<u64>, uncertain: bool) -> CallToolResult {
    let busy = !uncertain && matches!(code, "busy" | "capacity" | "capacity_busy");
    let mut value = json!({"error":if busy {"capacity_busy"} else {code}, "uncertain": uncertain});
    if busy {
        value["retryable"] = json!(true);
    }
    if let Some(id) = session {
        value["session_id"] = json!(id);
    }
    CallToolResult::error(vec![ContentBlock::text(value.to_string())])
}
fn success(value: Value) -> CallToolResult {
    CallToolResult::structured(value)
}

use super::{BoundOwner, RelayHandle};
use crate::gateway::http::lifecycle::{GatewayOwnerLifecycle, OwnerCleanup, OwnerFenceError};
use crate::host::protocol::wire::{Call, ExecTaskCommand, Reply};
use std::{sync::Mutex, time::Duration};
use styx_contracts::identity::{OwnerId, Sha256Digest};

struct OwnerState {
    principal: Sha256Digest,
    closing: bool,
}
struct State {
    capability_generations: BTreeMap<DeviceId, [u64; 4]>,
    owners: BTreeMap<OwnerId, OwnerState>,
}
/// No raw executor or network authority is exposed to the public tool adapter.
pub struct PairedGatewayBackend {
    #[cfg(test)]
    physical_cleanups_completed: std::sync::atomic::AtomicUsize,
    relay: RelayHandle,
    state: Mutex<State>,
}
impl PairedGatewayBackend {
    pub fn new(relay: RelayHandle) -> Self {
        Self {
            #[cfg(test)]
            physical_cleanups_completed: std::sync::atomic::AtomicUsize::new(0),
            relay,
            state: Mutex::new(State {
                capability_generations: BTreeMap::new(),
                owners: BTreeMap::new(),
            }),
        }
    }
    /// Read-only typed settlement observation for independent integration
    /// fixtures; it never requests cleanup or changes a native operation.
    #[cfg(all(test, target_os = "linux", target_env = "gnu"))]
    pub(crate) fn observed_physical_cleanups(&self) -> usize {
        self.physical_cleanups_completed
            .load(std::sync::atomic::Ordering::Acquire)
    }
    /// Explicit targets retain their identity when offline. An omitted target
    /// resolves only when the deployment contains exactly one paired Host.
    async fn resolve_device(&self, requested: Option<&str>) -> Result<DeviceId, &'static str> {
        if let Some(id) = requested {
            return DeviceId::try_from(id).map_err(|_| "invalid_arguments");
        }
        let devices = self.relay.devices().await.map_err(|error| error.code())?;
        match devices.as_slice() {
            [device] => Ok(device.device_id.clone()),
            [] => Err("environment_unavailable"),
            _ => Err("environment_required"),
        }
    }
    async fn refresh_host_capabilities(&self, device: &DeviceId) -> Result<(), &'static str> {
        let report = match self.relay.host_capabilities(device, None).await {
            Ok(report) => report,
            Err(super::RelayError::Unsupported) => return Ok(()),
            Err(error) => return Err(error.code()),
        };
        let mut state = self.state.lock().map_err(|_| "state_unavailable")?;
        state
            .capability_generations
            .insert(device.clone(), report.generations);
        Ok(())
    }
    fn active(&self, owner: &VerifiedGatewayOwner) -> bool {
        !owner.is_fenced()
            && self
                .state
                .lock()
                .expect("paired state")
                .owners
                .get(owner.owner_id())
                .is_none_or(|o| o.principal == owner.principal_fingerprint() && !o.closing)
    }
    async fn execute(&self, owner: &VerifiedGatewayOwner, args: ExecArgs) -> CallToolResult {
        let device = match self.resolve_device(args.environment_id.as_deref()).await {
            Ok(device) => device,
            Err(error) => return failure(error, None, false),
        };
        let binding =
            match tokio::time::timeout(Duration::from_secs(5), self.relay.bind(owner, &device))
                .await
            {
                Ok(Ok(b)) => b,
                Ok(Err(e)) => return failure(e.code(), None, false),
                Err(_) => return failure("outcome_unknown", None, true),
            };
        let profile = binding.defaults();
        let defaults = NativeExecDefaults {
            platform: profile.platform.clone(),
            cwd_file_uri: match native_file_uri(&profile.cwd, profile.platform == "win32") {
                Ok(p) => p,
                Err(e) => return failure(e, None, false),
            },
            shell: profile.shell.clone(),
            allowed_shells: profile.allowed_shells.clone(),
            environment: profile.environment.clone(),
        };
        let spec = match defaults
            .spec(&args)
            .and_then(|s| serde_json::value::to_raw_value(&s).map_err(|_| "invalid_arguments"))
        {
            Ok(s) if s.get().len() <= 128 * 1024 => s,
            _ => return failure("invalid_arguments", None, false),
        };
        self.task_call(
            &binding,
            ExecTaskCommand::Run {
                spec,
                max_output_tokens: args.max_output_tokens.unwrap_or(10_000),
                yield_time_ms: args.yield_time_ms.unwrap_or(1_000),
            },
        )
        .await
    }
    async fn task_call(&self, binding: &BoundOwner, command: ExecTaskCommand) -> CallToolResult {
        // No task handles or output cursors live in Gateway. A current chat
        // authorizes access; the selected Host resolves its own task IDs.
        let call = Call::ExecTask {
            owner: binding.owner_ref(),
            grant_revision: binding.grant_revision(),
            command,
        };
        match self.relay.call(binding, call).await {
            Ok(Reply::ExecTask { mut result }) => {
                result.value["environment_id"] = json!(binding.device());
                if result.is_error { CallToolResult::error(vec![ContentBlock::text(result.value.to_string())]) }
                else { success(result.value) }
            }
            Ok(Reply::Error { category, certainty, cursor_may_be_consumed }) => CallToolResult::error(vec![ContentBlock::text(json!({
                "error":serde_json::to_value(category).expect("error category").as_str().expect("category name").to_ascii_lowercase(),
                "execution_certainty":certainty,"cursor_may_be_consumed":cursor_may_be_consumed,
                "uncertain":certainty == styx_contracts::error::ExecutionCertainty::Unknown || cursor_may_be_consumed,
                "environment_id":binding.device(),
            }).to_string())]),
            Err(e) => failure(e.code(), None, !matches!(e, super::RelayError::Busy | super::RelayError::NotSent)),
            _ => failure("outcome_unknown", None, true),
        }
    }
    async fn route_task(
        &self,
        owner: &VerifiedGatewayOwner,
        environment: Option<&str>,
        command: ExecTaskCommand,
    ) -> CallToolResult {
        let device = match self.resolve_device(environment).await {
            Ok(d) => d,
            Err(e) => return failure(e, None, false),
        };
        match self.relay.bind(owner, &device).await {
            Ok(binding) => self.task_call(&binding, command).await,
            Err(e) => failure(e.code(), None, matches!(e, super::RelayError::Unknown)),
        }
    }
    async fn write(&self, owner: &VerifiedGatewayOwner, args: WriteArgs) -> CallToolResult {
        let chars = args.chars.unwrap_or_default();
        let wait = args
            .yield_time_ms
            .unwrap_or(if chars.is_empty() { 5_000 } else { 250 });
        self.route_task(
            owner,
            args.environment_id.as_deref(),
            ExecTaskCommand::Poll {
                session_id: args.session_id,
                chars,
                max_output_tokens: args.max_output_tokens.unwrap_or(10_000),
                yield_time_ms: wait,
            },
        )
        .await
    }
}
impl GatewayToolBackend for PairedGatewayBackend {
    async fn list_tools(
        &self,
        owner: &VerifiedGatewayOwner,
        request: Option<PaginatedRequestParams>,
    ) -> Result<ListToolsResult, ErrorData> {
        if !self.active(owner) {
            return Err(ErrorData::invalid_request("owner closed", None));
        }
        if request.is_some_and(|r| r.cursor.is_some()) {
            return Err(ErrorData::invalid_params("unsupported cursor", None));
        }
        Ok(ListToolsResult {
            tools: PUBLIC.clone(),
            ..Default::default()
        })
    }
    async fn call_tool(
        &self,
        owner: &VerifiedGatewayOwner,
        request: CallToolRequestParams,
    ) -> Result<CallToolResult, ErrorData> {
        if !self.active(owner) {
            return Ok(failure("permission_denied", None, false));
        }
        if !PUBLIC.iter().any(|t| t.name == request.name) {
            return Err(ErrorData::invalid_params("unknown tool", None));
        }
        Ok(match request.name.as_ref() {
            name if android::is_public_android_tool(name) => {
                self.android_call(owner, request.name.as_ref(), request.arguments)
                    .await
            }
            "exec_command" => match ExecArgs::parse(request.arguments) {
                Ok(a) => self.execute(owner, a).await,
                Err(e) => failure(e, None, false),
            },
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            name if computer::is_public_computer_tool(name) => {
                self.computer_call(owner, request.name.as_ref(), request.arguments)
                    .await
            }
            name if browser::is_public_browser_tool(name)
                || matches!(name, "list_browser_sessions" | "take_over_browser_session") =>
            {
                self.browser_call(owner, request.name.as_ref(), request.arguments)
                    .await
            }
            "write_stdin" => match WriteArgs::parse(request.arguments) {
                Ok(a) => self.write(owner, a).await,
                Err(e) => failure(e, None, false),
            },
            "list_execution_tasks" | "stop_execution_task" => {
                let mut args = request.arguments.unwrap_or_default();
                let environment = match args.remove("environment_id") {
                    None => None,
                    Some(Value::String(v)) if !v.is_empty() => Some(v),
                    _ => return Ok(failure("invalid_arguments", None, false)),
                };
                let command = if request.name == "list_execution_tasks" && args.is_empty() {
                    ExecTaskCommand::List
                } else if request.name == "stop_execution_task" {
                    #[derive(Deserialize)]
                    #[serde(deny_unknown_fields)]
                    struct Stop {
                        session_id: u64,
                    }
                    match decode::<Stop>(Some(args)) {
                        Ok(a) if (1..(1u64 << 48)).contains(&a.session_id) => {
                            ExecTaskCommand::Stop {
                                session_id: a.session_id,
                            }
                        }
                        _ => return Ok(failure("invalid_arguments", None, false)),
                    }
                } else {
                    return Ok(failure("invalid_arguments", None, false));
                };
                self.route_task(owner, environment.as_deref(), command)
                    .await
            }
            "set_execution_environment_capabilities" => {
                let mut args = request.arguments.unwrap_or_default();
                let target = match args.remove("environment_id") {
                    None => None,
                    Some(Value::String(id)) if !id.is_empty() => Some(id),
                    _ => return Ok(failure("invalid_arguments", None, false)),
                };
                let patch: crate::host::settings::CapabilityPatch =
                    match decode::<crate::host::settings::CapabilityPatch>(Some(args)) {
                        Ok(patch) if !patch.is_empty() => patch,
                        _ => return Ok(failure("invalid_arguments", None, false)),
                    };
                let device = match self.resolve_device(target.as_deref()).await {
                    Ok(device) => device,
                    Err(e) => return Ok(failure(e, None, false)),
                };
                match self.relay.host_capabilities(&device, Some(patch)).await {
                    Ok(report) if report.applied => success(json!({"environment_id":device,"capabilities":report})),
                    Ok(report) => CallToolResult::error(vec![ContentBlock::text(json!({"error":"host_settings_incomplete","environment_id":device,"capabilities":report,"uncertain":true}).to_string())]),
                    Err(e) => failure(e.code(), None, matches!(e, super::RelayError::Unknown)),
                }
            }
            "list_execution_environments" => {
                if request.arguments.as_ref().is_some_and(|a| !a.is_empty()) {
                    return Ok(failure("invalid_arguments", None, false));
                }
                match self.relay.devices().await {
                    Ok(devices) => success(
                        json!({"environments":devices.iter().map(environment_summary).collect::<Vec<_>>()}),
                    ),
                    Err(e) => failure(e.code(), None, false),
                }
            }
            "get_execution_environment_status" => {
                let a: StatusArgs = match decode(request.arguments) {
                    Ok(a) => a,
                    Err(e) => return Ok(failure(e, None, false)),
                };
                if a.environment_id.is_empty() {
                    return Ok(failure("invalid_arguments", None, false));
                }
                match self.relay.devices().await {
                    Ok(devices) => match devices
                        .iter()
                        .find(|d| d.device_id.as_str() == a.environment_id)
                    {
                        Some(d) => {
                            let ver = d.host_version.as_deref().unwrap_or("unknown");
                            let mut status = json!({"environment_id":a.environment_id,"label":display_label(&d.label),"platform":display_platform(&d.platform),"kind":"paired","access":"allowed","exec":{"configured":"unknown","connection":if d.online {"connected"} else {"disconnected"},"readiness":"unknown","version":if d.online {ver} else {"unknown"}},"browser":{"configured":"unknown","connection":if d.browser_online {"connected"} else {"disconnected"},"readiness":"unknown","version":if d.browser_online {ver} else {"unknown"}},"computer":{"configured":"unknown","connection":if d.computer_online {"connected"} else {"disconnected"},"permission":"unknown","readiness":"unknown","version":if d.computer_online {ver} else {"unknown"}},"android":{"configured":"unknown","connection":if d.android_online {"connected"} else {"disconnected"},"permission":"unknown","readiness":"unknown","version":if d.android_online {ver} else {"unknown"}}});
                            if d.host_settings {
                                match self.relay.host_capabilities(&d.device_id, None).await {
                                    Ok(report) => {
                                        for (name, enabled) in [
                                            ("exec", report.configured.exec),
                                            ("browser", report.configured.browser),
                                            ("computer", report.configured.computer),
                                            ("android", report.configured.android),
                                        ] {
                                            status[name]["configured"] = json!(enabled);
                                            if !enabled {
                                                status[name]["readiness"] = json!("disabled");
                                            }
                                        }
                                        if let Some(android) = &report.android_status {
                                            status["android"]["permission"] =
                                                json!(if android.accessibility {
                                                    "granted"
                                                } else {
                                                    "required"
                                                });
                                            status["android"]["device_locked"] =
                                                json!(android.device_locked);
                                            status["android"]["readiness"] =
                                                json!(if !report.configured.android {
                                                    "disabled"
                                                } else if !android.accessibility {
                                                    "permission_required"
                                                } else if android.device_locked {
                                                    "locked"
                                                } else {
                                                    "ready"
                                                });
                                        }
                                        status["capabilities"] = json!(report);
                                    }
                                    Err(e) => {
                                        status["capabilities_error"] = json!(e.code());
                                    }
                                }
                            }
                            success(status)
                        }
                        None => failure("environment_unavailable", None, false),
                    },
                    Err(e) => failure(e.code(), None, false),
                }
            }
            _ => failure("unsupported", None, false),
        })
    }
}
impl GatewayOwnerLifecycle for PairedGatewayBackend {
    fn fence_owner(&self, owner: &VerifiedGatewayOwner) -> Result<(), OwnerFenceError> {
        owner.fence();
        let mut state = self.state.lock().expect("paired state");
        if let Some(entry) = state.owners.get_mut(owner.owner_id()) {
            if entry.principal != owner.principal_fingerprint() {
                return Err(OwnerFenceError);
            }
            entry.closing = true;
        }
        drop(state);
        self.relay.fence_owner(owner).map_err(|_| OwnerFenceError)
    }
    async fn cleanup_owner(&self, owner: &VerifiedGatewayOwner, budget: Duration) -> OwnerCleanup {
        if self.fence_owner(owner).is_err() {
            return OwnerCleanup::Unknown;
        }
        // Only exact per-owner Host settlement releases local resource slots.
        // The shared sequence ledger preserves fencing after map compaction.
        match tokio::time::timeout(budget, self.relay.cleanup_owner(owner, budget)).await {
            Ok(Ok(true)) => {
                #[cfg(test)]
                self.physical_cleanups_completed
                    .fetch_add(1, std::sync::atomic::Ordering::Release);
                let mut state = self.state.lock().expect("paired state");
                state.owners.remove(owner.owner_id());
                owner.cleanup_complete();
                OwnerCleanup::Complete
            }
            _ => OwnerCleanup::Unknown,
        }
    }
}
#[cfg(test)]
#[path = "backend_tests.rs"]
mod tests;
