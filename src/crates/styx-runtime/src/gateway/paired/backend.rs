//! Frozen public tools over authenticated paired Host operations.
//! Public session IDs are presentation handles, never dispatch authority.
use crate::gateway::{auth::VerifiedGatewayOwner, mcp::GatewayToolBackend};
use rmcp::{ErrorData, model::*};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::{collections::BTreeMap, sync::LazyLock};
use styx_contracts::identity::DeviceId;

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
    let mut value = json!({"error": code, "uncertain": uncertain});
    if let Some(id) = session {
        value["session_id"] = json!(id);
    }
    CallToolResult::error(vec![ContentBlock::text(value.to_string())])
}
/// Facts from an explicit authenticated Host reply. Never constructed from a
/// generic Relay error, missing reply, timeout, ACK, or public arguments.
#[derive(Clone, Copy)]
struct HostFailure {
    category: styx_contracts::error::ErrorCategory,
    certainty: styx_contracts::error::ExecutionCertainty,
    cursor_may_be_consumed: bool,
}
impl HostFailure {
    fn from_exchange(reply: &Result<Reply, super::RelayError>) -> Option<Self> {
        match reply {
            Ok(Reply::Error {
                category,
                certainty,
                cursor_may_be_consumed,
            }) => Some(Self {
                category: *category,
                certainty: *certainty,
                cursor_may_be_consumed: *cursor_may_be_consumed,
            }),
            _ => None,
        }
    }
    fn result(self, session: u64) -> CallToolResult {
        let category = serde_json::to_value(self.category).expect("fixed error enum");
        let code = category
            .as_str()
            .expect("fixed error name")
            .to_ascii_lowercase();
        CallToolResult::error(vec![ContentBlock::text(json!({
            "error":code,"category":category,"execution_certainty":self.certainty,
            "cursor_may_be_consumed":self.cursor_may_be_consumed,
            "uncertain":self.certainty == styx_contracts::error::ExecutionCertainty::Unknown || self.cursor_may_be_consumed,
            "session_id":session,
        }).to_string())])
    }
    fn mutation_result(self, uncertain: &mut bool, session: u64) -> CallToolResult {
        // Only this explicit Host proof clears action ambiguity. In particular,
        // Completed without a WriteAccepted/resource snapshot is not synthesized
        // into a successful action or a usable process resource.
        if self.certainty == styx_contracts::error::ExecutionCertainty::NotDispatched {
            *uncertain = false;
        }
        self.result(session)
    }
    fn read_result(self, cursor_unknown: &mut bool, session: u64) -> CallToolResult {
        // The caller checked the cursor was known, then poisoned it before I/O.
        // A typed proof that this read did not consume it safely clears only
        // that temporary poison. Missing/generic replies never enter here.
        *cursor_unknown = self.cursor_may_be_consumed;
        self.result(session)
    }
}

fn success(value: Value) -> CallToolResult {
    CallToolResult::structured(value)
}

use super::{BoundOwner, RelayHandle};
use crate::gateway::http::lifecycle::{GatewayOwnerLifecycle, OwnerCleanup, OwnerFenceError};
use crate::host::protocol::wire::{ActionAcknowledgmentDto, ActionRef, Call, Reply};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use styx_contracts::{
    identity::{OwnerId, Sha256Digest},
    operation::{ExecutionLiveness, OperationState, OutputDrain, ResourceTarget},
};
use tokio::sync::Mutex as AsyncMutex;

const MAX_RESOURCES: usize = 64;
const MAX_OWNERS: usize = 128;
struct Resource {
    binding: BoundOwner,
    target: Option<ResourceTarget>,
    start_unknown: bool,
    input_unknown: bool,
    cursor_unknown: bool,
    pending_action: Option<ActionRef>,
    start_refusal: Option<HostFailure>,
}
struct Entry {
    owner: OwnerId,
    principal: Sha256Digest,
    resource: Arc<AsyncMutex<Resource>>,
}
struct OwnerState {
    principal: Sha256Digest,
    closing: bool,
}
struct State {
    next_session: u64,
    owners: BTreeMap<OwnerId, OwnerState>,
    sessions: BTreeMap<u64, Entry>,
}
/// No raw executor or network authority is exposed to the public tool adapter.
pub struct PairedGatewayBackend {
    #[cfg(test)]
    physical_cleanups_completed: std::sync::atomic::AtomicUsize,
    relay: RelayHandle,
    default_device: Option<DeviceId>,
    state: Mutex<State>,
}
impl PairedGatewayBackend {
    pub fn new(relay: RelayHandle, default_device: Option<DeviceId>) -> Self {
        Self {
            #[cfg(test)]
            physical_cleanups_completed: std::sync::atomic::AtomicUsize::new(0),
            relay,
            default_device,
            state: Mutex::new(State {
                next_session: 1,
                owners: BTreeMap::new(),
                sessions: BTreeMap::new(),
            }),
        }
    }
    /// Read-only typed settlement observation for independent integration
    /// fixtures; it never requests cleanup or changes a native operation.
    #[cfg(test)]
    pub(crate) fn observed_physical_cleanups(&self) -> usize {
        self.physical_cleanups_completed
            .load(std::sync::atomic::Ordering::Acquire)
    }
    async fn exchange(&self, binding: &BoundOwner, call: Call) -> Result<Reply, super::RelayError> {
        tokio::time::timeout(Duration::from_secs(5), self.relay.call(binding, call))
            .await
            .unwrap_or(Err(super::RelayError::Unknown))
    }
    fn active(&self, owner: &VerifiedGatewayOwner) -> bool {
        self.state
            .lock()
            .expect("paired state")
            .owners
            .get(owner.owner_id())
            .is_none_or(|o| o.principal == owner.principal_fingerprint() && !o.closing)
    }
    fn reserve(
        &self,
        owner: &VerifiedGatewayOwner,
        binding: BoundOwner,
    ) -> Result<(u64, Arc<AsyncMutex<Resource>>), &'static str> {
        let mut state = self.state.lock().expect("paired state");
        if state
            .owners
            .get(owner.owner_id())
            .is_some_and(|o| o.closing || o.principal != owner.principal_fingerprint())
        {
            return Err("permission_denied");
        }
        if state.sessions.len() >= MAX_RESOURCES
            || (!state.owners.contains_key(owner.owner_id()) && state.owners.len() >= MAX_OWNERS)
            || state.next_session >= (1_u64 << 48)
        {
            return Err("capacity");
        }
        state
            .owners
            .entry(owner.owner_id().clone())
            .or_insert(OwnerState {
                principal: owner.principal_fingerprint(),
                closing: false,
            });
        let id = state.next_session;
        state.next_session += 1;
        let resource = Arc::new(AsyncMutex::new(Resource {
            binding,
            target: None,
            start_unknown: true,
            input_unknown: false,
            cursor_unknown: false,
            pending_action: None,
            start_refusal: None,
        }));
        state.sessions.insert(
            id,
            Entry {
                owner: owner.owner_id().clone(),
                principal: owner.principal_fingerprint(),
                resource: resource.clone(),
            },
        );
        Ok((id, resource))
    }
    fn lookup(
        &self,
        owner: &VerifiedGatewayOwner,
        id: u64,
    ) -> Result<Arc<AsyncMutex<Resource>>, &'static str> {
        let state = self.state.lock().expect("paired state");
        if state
            .owners
            .get(owner.owner_id())
            .is_some_and(|o| o.closing || o.principal != owner.principal_fingerprint())
        {
            return Err("unknown_session");
        }
        state
            .sessions
            .get(&id)
            .filter(|r| {
                r.owner == *owner.owner_id() && r.principal == owner.principal_fingerprint()
            })
            .map(|r| r.resource.clone())
            .ok_or("unknown_session")
    }
    async fn execute(&self, owner: &VerifiedGatewayOwner, args: ExecArgs) -> CallToolResult {
        let began = Instant::now();
        let device = match args
            .environment_id
            .as_ref()
            .map(|s| DeviceId::try_from(s.as_str()))
            .transpose()
        {
            Ok(Some(d)) => d,
            Ok(None) => match &self.default_device {
                Some(d) => d.clone(),
                None => return failure("environment_required", None, false),
            },
            Err(_) => return failure("invalid_arguments", None, false),
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
        let (id, cell) = match self.reserve(owner, binding) {
            Ok(r) => r,
            Err(e) => return failure(e, None, false),
        };
        let mut r = match tokio::time::timeout(Duration::from_secs(5), cell.lock()).await {
            Ok(r) => r,
            Err(_) => return failure("busy", None, false),
        };
        if !self.active(owner) {
            return failure("permission_denied", Some(id), false);
        }
        let call = Call::PrepareStart {
            owner: r.binding.owner_ref(),
            grant_revision: r.binding.grant_revision(),
            timeout_ms: 5_000,
            spec,
        };
        let snapshot = match self.exchange(&r.binding, call).await {
            Ok(Reply::Prepared { snapshot }) => snapshot,
            Ok(Reply::Error {
                category,
                certainty,
                cursor_may_be_consumed,
            }) => {
                let error = HostFailure {
                    category,
                    certainty,
                    cursor_may_be_consumed,
                };
                if certainty == styx_contracts::error::ExecutionCertainty::NotDispatched {
                    r.start_refusal = Some(error);
                }
                return error.mutation_result(&mut r.start_unknown, id);
            }
            _ => return failure("outcome_unknown", Some(id), true),
        };
        if snapshot.target.is_some()
            || snapshot.operation_id.host_generation != *r.binding.host_generation()
        {
            return failure("outcome_unknown", Some(id), true);
        }
        let target = ResourceTarget {
            operation_id: snapshot.operation_id,
            payload_digest: snapshot.payload_digest,
        };
        r.target = Some(target.clone());
        if !self.active(owner) {
            return failure("permission_denied", Some(id), false);
        }
        match self
            .exchange(
                &r.binding,
                Call::DispatchStart {
                    owner: r.binding.owner_ref(),
                    target,
                },
            )
            .await
        {
            Ok(Reply::Start { snapshot, .. })
                if r.target.as_ref().is_some_and(|t| {
                    t.operation_id == snapshot.operation_id
                        && t.payload_digest == snapshot.payload_digest
                }) && snapshot.target.is_none()
                    && snapshot.state != OperationState::Unknown
                    && snapshot.liveness != ExecutionLiveness::NotStarted =>
            {
                r.start_unknown = false
            }
            Ok(Reply::Error {
                category,
                certainty,
                cursor_may_be_consumed,
            }) => {
                let error = HostFailure {
                    category,
                    certainty,
                    cursor_may_be_consumed,
                };
                if certainty == styx_contracts::error::ExecutionCertainty::NotDispatched {
                    r.start_refusal = Some(error);
                }
                return error.mutation_result(&mut r.start_unknown, id);
            }
            _ => return failure("outcome_unknown", Some(id), true),
        }
        self.read(
            owner,
            id,
            &mut r,
            args.max_output_tokens.unwrap_or(10_000),
            args.yield_time_ms.unwrap_or(10_000),
            began,
        )
        .await
    }
    async fn write(&self, owner: &VerifiedGatewayOwner, args: WriteArgs) -> CallToolResult {
        let began = Instant::now();
        let cell = match self.lookup(owner, args.session_id) {
            Ok(r) => r,
            Err(e) => return failure(e, None, false),
        };
        let mut r = match tokio::time::timeout(Duration::from_secs(5), cell.lock()).await {
            Ok(r) => r,
            Err(_) => return failure("busy", None, false),
        };
        if !self.active(owner) {
            return failure("unknown_session", None, false);
        }
        if let Some(error) = r.start_refusal {
            return error.result(args.session_id);
        }
        let Some(target) = r.target.clone() else {
            return failure("outcome_unknown", Some(args.session_id), true);
        };
        let chars = args.chars.unwrap_or_default();
        if !chars.is_empty() {
            if r.start_unknown || r.input_unknown || r.cursor_unknown {
                return failure("outcome_unknown", Some(args.session_id), true);
            }
            let action = match serde_json::value::to_raw_value(
                &crate::providers::codex::ProcessAction::WriteStdin {
                    input_base64: STANDARD.encode(chars.as_bytes()),
                },
            ) {
                Ok(a) => a,
                Err(_) => return failure("invalid_arguments", Some(args.session_id), false),
            };
            // Set before any await that can lose an action response. Never send
            // the same input again after ambiguity.
            r.input_unknown = true;
            let prepared = self
                .exchange(
                    &r.binding,
                    Call::PrepareAction {
                        owner: r.binding.owner_ref(),
                        target,
                        grant_revision: r.binding.grant_revision(),
                        timeout_ms: 5_000,
                        action,
                    },
                )
                .await;
            let action = match prepared {
                Ok(Reply::Prepared { snapshot }) if snapshot.target == r.target => ActionRef {
                    operation_id: snapshot.operation_id,
                    payload_digest: snapshot.payload_digest,
                },
                Ok(Reply::Error {
                    category,
                    certainty,
                    cursor_may_be_consumed,
                }) => {
                    return HostFailure {
                        category,
                        certainty,
                        cursor_may_be_consumed,
                    }
                    .mutation_result(&mut r.input_unknown, args.session_id);
                }
                _ => return failure("outcome_unknown", Some(args.session_id), true),
            };
            r.pending_action = Some(ActionRef {
                operation_id: action.operation_id.clone(),
                payload_digest: action.payload_digest,
            });
            if !self.active(owner) {
                return failure("permission_denied", Some(args.session_id), true);
            }
            match self
                .exchange(
                    &r.binding,
                    Call::DispatchAction {
                        owner: r.binding.owner_ref(),
                        action,
                    },
                )
                .await
            {
                Ok(Reply::Action {
                    acknowledgment: Some(ActionAcknowledgmentDto::WriteAccepted),
                    snapshot,
                    ..
                }) if snapshot.state == OperationState::Succeeded
                    && snapshot.target == r.target
                    && r.pending_action.as_ref().is_some_and(|a| {
                        a.operation_id == snapshot.operation_id
                            && a.payload_digest == snapshot.payload_digest
                    }) =>
                {
                    r.input_unknown = false;
                    r.pending_action = None;
                }
                Ok(Reply::Error {
                    category,
                    certainty,
                    cursor_may_be_consumed,
                }) => {
                    return HostFailure {
                        category,
                        certainty,
                        cursor_may_be_consumed,
                    }
                    .mutation_result(&mut r.input_unknown, args.session_id);
                }
                _ => return failure("outcome_unknown", Some(args.session_id), true),
            }
        } else if r.start_unknown {
            // Inspection is not a second dispatch. Unknown history stays sticky.
            let inspected = self
                .exchange(
                    &r.binding,
                    Call::InspectStart {
                        owner: r.binding.owner_ref(),
                        target: target.clone(),
                    },
                )
                .await;
            if let Some(error) = HostFailure::from_exchange(&inspected) {
                return error.result(args.session_id);
            }
            if let Ok(Reply::Inspected { snapshot }) = inspected
                && snapshot.operation_id == target.operation_id
                && snapshot.payload_digest == target.payload_digest
                && snapshot.state != OperationState::Unknown
                && matches!(
                    snapshot.liveness,
                    ExecutionLiveness::Running | ExecutionLiveness::Exited
                )
            {
                r.start_unknown = false;
            }
        }
        if chars.is_empty()
            && r.input_unknown
            && let Some(original) = r.pending_action.as_ref()
        {
            let action = ActionRef {
                operation_id: original.operation_id.clone(),
                payload_digest: original.payload_digest,
            };
            let inspected = self
                .exchange(
                    &r.binding,
                    Call::InspectAction {
                        owner: r.binding.owner_ref(),
                        action,
                    },
                )
                .await;
            if let Some(error) = HostFailure::from_exchange(&inspected) {
                return error.result(args.session_id);
            }
            if let Ok(Reply::Action {
                snapshot,
                acknowledgment: Some(ActionAcknowledgmentDto::WriteAccepted),
                ..
            }) = inspected
                && snapshot.state == OperationState::Succeeded
                && snapshot.target == r.target
                && r.pending_action.as_ref().is_some_and(|a| {
                    a.operation_id == snapshot.operation_id
                        && a.payload_digest == snapshot.payload_digest
                })
            {
                r.input_unknown = false;
                r.pending_action = None;
            }
        }

        self.read(
            owner,
            args.session_id,
            &mut r,
            args.max_output_tokens.unwrap_or(10_000),
            args.yield_time_ms
                .unwrap_or(if chars.is_empty() { 5_000 } else { 250 }),
            began,
        )
        .await
    }
    async fn read(
        &self,
        owner: &VerifiedGatewayOwner,
        id: u64,
        r: &mut Resource,
        max_bytes: usize,
        wait_ms: u32,
        began: Instant,
    ) -> CallToolResult {
        if r.cursor_unknown {
            return failure("read_cursor_unknown", Some(id), true);
        }
        if !self.active(owner) {
            return failure("permission_denied", Some(id), false);
        }
        let Some(target) = r.target.clone() else {
            return failure("outcome_unknown", Some(id), true);
        };
        // Current decoded cursor cannot resume. Conservatively poison before
        // await; only a complete typed read clears the delivery uncertainty.
        r.cursor_unknown = true;
        let reply = self
            .exchange(
                &r.binding,
                Call::Read {
                    owner: r.binding.owner_ref(),
                    target,
                    grant_revision: r.binding.grant_revision(),
                    timeout_ms: 5_000,
                    max_bytes: max_bytes as u32,
                    wait_ms: wait_ms.min(100),
                },
            )
            .await;
        let (chunks, liveness, drain, exit) = match reply {
            Ok(Reply::Read {
                chunks,
                liveness,
                output_drain,
                exit_code,
                ..
            }) => (chunks, liveness, output_drain, exit_code),
            Ok(Reply::Error {
                category,
                certainty,
                cursor_may_be_consumed,
            }) => {
                return HostFailure {
                    category,
                    certainty,
                    cursor_may_be_consumed,
                }
                .read_result(&mut r.cursor_unknown, id);
            }
            _ => return failure("read_cursor_unknown", Some(id), true),
        };
        if !self.active(owner) {
            return failure("permission_denied", Some(id), true);
        }
        let output: String = chunks.into_iter().map(|c| c.text).collect();
        if output.len() > max_bytes.saturating_mul(4).saturating_add(4) {
            return failure("read_cursor_unknown", Some(id), true);
        }
        r.cursor_unknown = false;
        if r.start_unknown
            || r.input_unknown
            || liveness == ExecutionLiveness::Unknown
            || (drain == OutputDrain::Drained && liveness != ExecutionLiveness::Exited)
        {
            let mut result =
                json!({"error":"outcome_unknown","uncertain":true,"session_id":id,"output":output});
            if let Some(code) = exit {
                result["observed_exit_code"] = json!(code);
            }
            return CallToolResult::error(vec![ContentBlock::text(result.to_string())]);
        }
        let mut result = json!({"wall_time_seconds":began.elapsed().as_secs_f64(),"output":output});
        if liveness == ExecutionLiveness::Exited && drain == OutputDrain::Drained {
            let Some(code) = exit else {
                return failure("outcome_unknown", Some(id), true);
            };
            result["exit_code"] = json!(code);
            self.state
                .lock()
                .expect("paired state")
                .sessions
                .remove(&id);
        } else {
            result["session_id"] = json!(id);
        }
        success(result)
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
            "exec_command" => match ExecArgs::parse(request.arguments) {
                Ok(a) => self.execute(owner, a).await,
                Err(e) => failure(e, None, false),
            },
            "write_stdin" => match WriteArgs::parse(request.arguments) {
                Ok(a) => self.write(owner, a).await,
                Err(e) => failure(e, None, false),
            },
            "list_execution_environments" => {
                if request.arguments.as_ref().is_some_and(|a| !a.is_empty()) {
                    return Ok(failure("invalid_arguments", None, false));
                }
                match self.relay.devices().await {
                    Ok(devices) => success(
                        json!({"environments":devices.iter().map(|d| json!({"environment_id":d.device_id.as_str(),"kind":"paired","connection":if d.online {"connected"} else {"disconnected"}})).collect::<Vec<_>>()}),
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
                        Some(d) => success(
                            json!({"environment_id":a.environment_id,"kind":"paired","access":"allowed","exec":{"configured":true,"connection":if d.online {"connected"} else {"disconnected"},"readiness":"unknown","version":"unknown"},"browser":{"configured":"unknown","connection":"unknown","readiness":"unknown","version":"unknown"},"computer":{"configured":"unknown","connection":"unknown","permission":"unknown","readiness":"unknown","version":"unknown"}}),
                        ),
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
        let mut state = self.state.lock().expect("paired state");
        if !state.owners.contains_key(owner.owner_id()) && state.owners.len() >= MAX_OWNERS {
            return Err(OwnerFenceError);
        }
        let entry = state
            .owners
            .entry(owner.owner_id().clone())
            .or_insert(OwnerState {
                principal: owner.principal_fingerprint(),
                closing: true,
            });
        if entry.principal != owner.principal_fingerprint() {
            return Err(OwnerFenceError);
        }
        entry.closing = true;
        drop(state);
        self.relay.fence_owner(owner).map_err(|_| OwnerFenceError)
    }
    async fn cleanup_owner(&self, owner: &VerifiedGatewayOwner, budget: Duration) -> OwnerCleanup {
        if self.fence_owner(owner).is_err() {
            return OwnerCleanup::Unknown;
        }
        // Only exact per-owner Host settlement releases local resource slots.
        // The fence tombstone remains: a stale HTTP owner cannot bind again.
        match tokio::time::timeout(budget, self.relay.cleanup_owner(owner, budget)).await {
            Ok(Ok(true)) => {
                #[cfg(test)]
                self.physical_cleanups_completed
                    .fetch_add(1, std::sync::atomic::Ordering::Release);
                self.state
                    .lock()
                    .expect("paired state")
                    .sessions
                    .retain(|_, entry| {
                        entry.owner != *owner.owner_id()
                            || entry.principal != owner.principal_fingerprint()
                    });
                OwnerCleanup::Complete
            }
            _ => OwnerCleanup::Unknown,
        }
    }
}
#[cfg(test)]
#[path = "backend_tests.rs"]
mod tests;
