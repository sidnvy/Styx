//! Host-owned Browser contexts; a conversation holds only the current operator slot.
//! Transfers reuse the existing worker, profile, tabs and Core resource identity.
pub(crate) mod operations;
use crate::host::{coordinator::OwnerCleanupHandle, protocol::wire::*};
use crate::providers::browser_contract::BrowserAction;
use operations::{BrowserCommand, BrowserPort, BrowserReply};
use rmcp::model::{CallToolResult, ContentBlock};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use styx_contracts::{
    error::{ErrorCategory, ExecutionCertainty},
    identity::*,
    operation::*,
};
use styx_core::operations::OwnerLease;
use tokio::sync::Mutex as AsyncMutex;

const MAX_BROWSER_RESULT_BYTES: usize = 128 * 1024;
const NEW_SESSION_ID: &str = "new";

fn is_public_mcp_subject(owner: &OwnerRef) -> bool {
    owner.owner_id.as_str().starts_with("public-mcp-subject:")
}

type Caller = (OwnerId, OwnerEpoch);
type Cell = Arc<AsyncMutex<Session>>;
#[derive(Default)]
pub(crate) struct State {
    registry: Mutex<Registry>,
    restored: tokio::sync::OnceCell<()>,
    cdp_sync: AsyncMutex<()>,
    inputs: std::sync::OnceLock<Arc<operations::BrowserInputs>>,
}
impl State {
    pub(crate) fn inputs(
        &self,
        source: Arc<dyn operations::BrowserBootstrap>,
    ) -> Arc<operations::BrowserInputs> {
        self.inputs
            .get_or_init(|| Arc::new(operations::BrowserInputs::new(source)))
            .clone()
    }
    pub(crate) fn forget_caller(&self, owner: &OwnerRef) {
        let mut registry = self.registry.lock().expect("Browser sessions");
        registry.defaults.remove(&caller(owner));
        for cell in registry.sessions.values() {
            if let Ok(mut session) = cell.try_lock()
                && session.operator.as_ref() == Some(owner)
            {
                session.operator = None;
            }
        }
    }
}
#[derive(Default)]
struct Registry {
    sessions: BTreeMap<String, Cell>,
    defaults: BTreeMap<Caller, String>,
    cdp_endpoint: Option<Option<String>>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SessionMode {
    Managed,
    Cdp,
}
struct Session {
    mode: SessionMode,
    cdp_endpoint_key: Option<Option<String>>,
    operator: Option<OwnerRef>,
    lease: OwnerLease,
    target: Option<ResourceTarget>,
    phase: Phase,
    cleanup: Option<OwnerCleanupHandle>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Saved,
    New,
    Ready,
    Unknown,
}
pub(crate) struct Engine<'a> {
    pub(crate) port: BrowserPort<'a>,
}
fn caller(owner: &OwnerRef) -> Caller {
    (owner.owner_id.clone(), owner.owner_epoch.clone())
}
fn failure(code: &str, unknown: bool) -> CallToolResult {
    let busy = matches!(code, "busy" | "capacity_busy") && !unknown;
    CallToolResult::error(vec![ContentBlock::text(
        json!({"error":if busy {"capacity_busy"} else {code},"uncertain":unknown,"retryable":busy})
            .to_string(),
    )])
}
fn success(value: Value) -> CallToolResult {
    CallToolResult::structured(value)
}
fn refusal(reply: &BrowserReply) -> CallToolResult {
    match reply {
        BrowserReply::Error {
            category,
            certainty,
        } => {
            let code = serde_json::to_value(category).expect("fixed category");
            failure(
                &code
                    .as_str()
                    .unwrap_or("RESULT_UNKNOWN")
                    .to_ascii_lowercase(),
                *certainty != ExecutionCertainty::NotDispatched,
            )
        }
        _ => failure("outcome_unknown", true),
    }
}
fn not_dispatched(reply: &BrowserReply) -> bool {
    matches!(
        reply,
        BrowserReply::Error {
            certainty: ExecutionCertainty::NotDispatched,
            ..
        }
    )
}
fn action_timeout(name: &str, mode: SessionMode) -> u32 {
    if mode == SessionMode::Cdp
        || matches!(
            name,
            "browser_navigate" | "browser_navigate_back" | "browser_wait_for"
        )
    {
        BROWSER_WAIT_PREPARE_TIMEOUT_MS
    } else {
        5_000
    }
}
fn result(value: Value) -> Result<CallToolResult, &'static str> {
    struct Bound(usize);
    impl std::io::Write for Bound {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .filter(|n| *n <= MAX_BROWSER_RESULT_BYTES)
                .ok_or_else(|| std::io::Error::other("browser result bound"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(&mut Bound(0), &value).map_err(|_| "outcome_unknown")?;
    serde_json::from_value(value).map_err(|_| "outcome_unknown")
}

fn attach_session_id_to_content(result: &mut CallToolResult, id: &str) {
    if result.is_error == Some(true) {
        return;
    }
    let header = format!("### Browser Session\n- browser_session_id: {id}");
    if result.content.iter().any(|block| {
        block.as_text().is_some_and(|text| {
            text.text.starts_with(&header)
                || serde_json::from_str::<Value>(&text.text)
                    .ok()
                    .and_then(|value| value.get("browser_session_id").cloned())
                    .is_some()
        })
    }) {
        return;
    }
    match result.content.first_mut() {
        Some(ContentBlock::Text(text)) => {
            text.text = format!("{header}\n\n{}", text.text);
        }
        _ => {
            result.content.insert(0, ContentBlock::text(header));
        }
    }
}

impl Engine<'_> {
    fn state(&self) -> &State {
        self.port.coordinator.browser_sessions()
    }
    fn active_caller(
        &self,
        owner: &OwnerRef,
    ) -> Result<std::sync::MutexGuard<'_, crate::host::callers::OwnerRegistry>, &'static str> {
        let registry = self
            .port
            .coordinator
            .remote_access()
            .lock()
            .expect("owner registry");
        if registry.stopping
            || !registry
                .owners
                .get(&caller(owner))
                .is_some_and(|record| record.lease.is_some())
        {
            return Err("unauthorized");
        }
        Ok(registry)
    }
    fn new_session(
        &self,
        id: &str,
        mode: SessionMode,
        cdp_endpoint_key: Option<Option<String>>,
        operator: Option<OwnerRef>,
        phase: Phase,
    ) -> Result<Session, &'static str> {
        // The profile ID survives restart; caller access and execution identity do not.
        let incarnation = uuid::Uuid::new_v4().simple().to_string();
        let owner_id = match mode {
            SessionMode::Managed => format!("host-browser-{id}-{incarnation}"),
            SessionMode::Cdp => {
                format!(
                    "{}{incarnation}",
                    crate::host::browser_cdp::CDP_OWNER_PREFIX
                )
            }
        };
        let lease = self
            .port
            .authority
            .register_verified_owner(
                owner_id.try_into().expect("local Browser owner"),
                uuid::Uuid::new_v4()
                    .to_string()
                    .try_into()
                    .expect("UUID epoch"),
            )
            .map_err(|_| "capacity_busy")?;
        Ok(Session {
            mode,
            cdp_endpoint_key,
            operator,
            lease,
            target: None,
            phase,
            cleanup: None,
        })
    }
    async fn restore_profiles(&self) -> Result<(), &'static str> {
        self.state()
            .restored
            .get_or_try_init(|| async {
                let profiles = self
                    .port
                    .saved_profiles()
                    .await
                    .map_err(|_| "browser_profile_unavailable")?;
                let mut registry = self.state().registry.lock().expect("Browser sessions");
                for id in profiles {
                    if let std::collections::btree_map::Entry::Vacant(entry) =
                        registry.sessions.entry(id.clone())
                    {
                        let session =
                            self.new_session(&id, SessionMode::Managed, None, None, Phase::Saved)?;
                        entry.insert(Arc::new(AsyncMutex::new(session)));
                    }
                }
                Ok(())
            })
            .await
            .map(|_| ())
    }
    async fn sync_cdp_session(&self) -> Result<(), &'static str> {
        use crate::host::browser_cdp::CDP_SESSION_ID;
        let _sync_guard = self.state().cdp_sync.lock().await;
        let cfg = self
            .port
            .cdp_config()
            .await
            .map_err(|_| "browser_profile_unavailable")?;
        if !cfg.enabled {
            let removed = {
                let mut registry = self.state().registry.lock().expect("Browser sessions");
                if registry.cdp_endpoint.is_none()
                    && !registry.sessions.contains_key(CDP_SESSION_ID)
                {
                    return Ok(());
                }
                registry.cdp_endpoint = None;
                registry.defaults.retain(|_, v| v != CDP_SESSION_ID);
                registry.sessions.remove(CDP_SESSION_ID)
            };
            if let Some(cell) = removed {
                let mut session = cell.lock().await;
                session.operator = None;
                let _ = self.cleanup_session_resources(&mut session).await;
                session.phase = Phase::Unknown;
            }
            return Ok(());
        }

        let desired = cfg.endpoint;
        let existing = {
            let mut registry = self.state().registry.lock().expect("Browser sessions");
            if registry.cdp_endpoint.as_ref() == Some(&desired)
                && registry.sessions.contains_key(CDP_SESSION_ID)
            {
                return Ok(());
            }
            if let Some(cell) = registry.sessions.get(CDP_SESSION_ID).cloned() {
                registry.defaults.retain(|_, v| v != CDP_SESSION_ID);
                Some(cell)
            } else {
                let session = self.new_session(
                    CDP_SESSION_ID,
                    SessionMode::Cdp,
                    Some(desired.clone()),
                    None,
                    Phase::Saved,
                )?;
                registry.sessions.insert(
                    CDP_SESSION_ID.to_owned(),
                    Arc::new(AsyncMutex::new(session)),
                );
                registry.cdp_endpoint = Some(desired.clone());
                None
            }
        };
        if let Some(cell) = existing {
            let mut session = cell.lock().await;
            self.cleanup_session_resources(&mut session).await?;
            *session = self.new_session(
                CDP_SESSION_ID,
                SessionMode::Cdp,
                Some(desired.clone()),
                None,
                Phase::Saved,
            )?;
            self.state()
                .registry
                .lock()
                .expect("Browser sessions")
                .cdp_endpoint = Some(desired);
        }
        Ok(())
    }
    fn has_open_default(state: &Registry, owner: &OwnerRef) -> bool {
        let Some(default_id) = state.defaults.get(&caller(owner)) else {
            return false;
        };
        let Some(cell) = state.sessions.get(default_id) else {
            return false;
        };
        match cell.try_lock() {
            Err(_) => true,
            Ok(session) => session.mode == SessionMode::Managed && session.phase != Phase::Saved,
        }
    }
    fn claim_or_create_managed(
        &self,
        state: &mut Registry,
        owner: &OwnerRef,
        preserve_open_default: bool,
    ) -> Result<(String, Cell), &'static str> {
        // Reuse an available signed-in profile instead of silently creating an
        // empty one after a conversation ends or the Host restarts. An active
        // operator is never displaced; independent concurrent conversations
        // claim distinct idle profiles or create a new isolated profile.
        let claimed = state.sessions.iter().find_map(|(id, cell)| {
            let session = cell.try_lock().ok()?;
            (session.mode == SessionMode::Managed
                && session.operator.is_none()
                && session.phase != Phase::Unknown
                && session.cleanup.is_none())
            .then(|| (id.clone(), cell.clone()))
        });
        if let Some((id, cell)) = claimed {
            let mut session = cell.try_lock().map_err(|_| "busy")?;
            if session.operator.is_some() {
                return Err("busy");
            }
            if let Some(target) = &session.target {
                self.port
                    .coordinator
                    .invalidate_browser_session_references(&session.lease, target)
                    .map_err(|_| "busy")?;
            }
            session.operator = Some(owner.clone());
            drop(session);
            if !(preserve_open_default && Self::has_open_default(state, owner)) {
                state.defaults.insert(caller(owner), id.clone());
            }
            return Ok((id, cell));
        }
        let id = uuid::Uuid::new_v4().simple().to_string();
        let cell = Arc::new(AsyncMutex::new(self.new_session(
            &id,
            SessionMode::Managed,
            None,
            Some(owner.clone()),
            Phase::New,
        )?));
        let update_default = !(preserve_open_default && Self::has_open_default(state, owner));
        state.sessions.insert(id.clone(), cell.clone());
        if update_default {
            state.defaults.insert(caller(owner), id.clone());
        }
        Ok((id, cell))
    }
    fn resolve(
        &self,
        owner: &OwnerRef,
        id: Option<String>,
        create: bool,
        action_name: Option<&str>,
    ) -> Result<(String, Cell), &'static str> {
        // Serialize claiming with the existing caller fence, without retaining
        // caller access over async work or persisting a second lifecycle record.
        let _caller = self.active_caller(owner)?;
        let mut state = self.state().registry.lock().expect("Browser sessions");
        if id.as_deref() == Some(NEW_SESSION_ID) {
            if !create {
                return Err("browser_session_not_found");
            }
            return self.claim_or_create_managed(&mut state, owner, true);
        }
        if let Some(explicit_id) = id {
            return state
                .sessions
                .get(&explicit_id)
                .cloned()
                .map(|cell| (explicit_id, cell))
                .ok_or("browser_session_not_found");
        }
        if let Some(default_id) = state.defaults.get(&caller(owner)).cloned() {
            let cell = state
                .sessions
                .get(&default_id)
                .cloned()
                .ok_or("browser_session_not_found")?;
            if is_public_mcp_subject(owner) && create && action_name == Some("browser_navigate") {
                let should_isolate = match cell.try_lock() {
                    Err(_) => true,
                    Ok(session) => session.phase != Phase::Saved,
                };
                if should_isolate {
                    return self.claim_or_create_managed(&mut state, owner, true);
                }
            }
            return Ok((default_id, cell));
        }
        if !create {
            return Err("browser_not_open");
        }
        self.claim_or_create_managed(&mut state, owner, true)
    }
    async fn cleanup_session_resources(&self, session: &mut Session) -> Result<(), &'static str> {
        if session.phase == Phase::Saved && session.target.is_none() && session.cleanup.is_none() {
            return Ok(());
        }
        if session.cleanup.is_none() {
            match self.port.authority.fence_owner_for_cleanup(&session.lease) {
                Ok(handle) => session.cleanup = Some(handle),
                Err(_) => return Err("outcome_unknown"),
            }
        }
        session.phase = Phase::Unknown;
        let clean = match self.port.authority.cleanup_owner(
            session.cleanup.as_ref().expect("original cleanup"),
            Duration::from_secs(5),
        ) {
            Ok(ticket) => ticket.wait().await.is_ok_and(|r| r.physical_complete),
            Err(_) => false,
        };
        if !clean
            || self
                .port
                .release_browser_profile(session.lease.clone())
                .await
                .is_err()
        {
            return Err("outcome_unknown");
        }
        Ok(())
    }
    fn close_payload(id: &str, is_cdp: bool) -> Value {
        if is_cdp {
            json!({
                "browser_session_id": id,
                "closed": true,
                "detached": true,
                "profile_persistent": false,
                "profile_preserved": false,
            })
        } else {
            json!({"browser_session_id": id, "closed": true, "profile_preserved": true})
        }
    }
    async fn close(&self, id: &str, session: &mut Session) -> CallToolResult {
        let is_cdp = session.mode == SessionMode::Cdp;
        let endpoint_key = session.cdp_endpoint_key.clone();
        if session.phase == Phase::Saved && session.target.is_none() {
            session.operator = None;
            return success(Self::close_payload(id, is_cdp));
        }
        if self.cleanup_session_resources(session).await.is_err() {
            return failure("outcome_unknown", true);
        }
        if is_cdp
            && !self
                .state()
                .registry
                .lock()
                .expect("Browser sessions")
                .sessions
                .contains_key(id)
        {
            session.operator = None;
            session.phase = Phase::Unknown;
            return success(Self::close_payload(id, true));
        }
        *session = match self.new_session(id, session.mode, endpoint_key, None, Phase::Saved) {
            Ok(saved) => saved,
            Err(code) => return failure(code, false),
        };
        success(Self::close_payload(id, is_cdp))
    }
    /// Capability shutdown already proved physical exit. Reclaim that context's
    /// local owner/profile on the next request, without starting a browser.
    async fn collect_closed(&self) {
        let entries: Vec<_> = self
            .state()
            .registry
            .lock()
            .expect("Browser sessions")
            .sessions
            .iter()
            .map(|(id, c)| (id.clone(), c.clone()))
            .collect();
        for (id, cell) in entries {
            let Ok(mut s) = cell.try_lock() else { continue };
            // A caller can finish while profile discovery or an action is
            // pending. Its existing fenced/removed owner record is authoritative.
            if s.operator
                .as_ref()
                .is_some_and(|operator| self.active_caller(operator).is_err())
            {
                s.operator = None;
            }
            if s.cleanup.is_none()
                && s.target.as_ref().is_some_and(|target| {
                    self.port
                        .coordinator
                        .browser_session_exited(&s.lease, target)
                        || self
                            .port
                            .coordinator
                            .inspect_browser(
                                &s.lease,
                                &target.operation_id,
                                target.payload_digest,
                                false,
                            )
                            .is_ok_and(|snap| {
                                snap.liveness == ExecutionLiveness::Exited
                                    && snap.output_drain == OutputDrain::Drained
                            })
                })
            {
                let operator = s.operator.clone();
                let _ = self.close(&id, &mut s).await;
                if s.phase == Phase::Saved
                    && operator
                        .as_ref()
                        .is_some_and(|op| self.active_caller(op).is_ok())
                {
                    s.operator = operator;
                }
            }
        }
    }
    pub(crate) async fn handle(
        &self,
        owner: OwnerRef,
        command: BrowserSessionCommand,
    ) -> CallToolResult {
        if let Err(code) = self.restore_profiles().await {
            return failure(code, false);
        }
        if let Err(code) = self.sync_cdp_session().await {
            return failure(code, false);
        }
        self.collect_closed().await;
        if self.active_caller(&owner).is_err() {
            return failure("unauthorized", false);
        }
        match command {
            BrowserSessionCommand::List => {
                let entries: Vec<_> = self
                    .state()
                    .registry
                    .lock()
                    .expect("Browser sessions")
                    .sessions
                    .iter()
                    .map(|(id, c)| (id.clone(), c.clone()))
                    .collect();
                let mut sessions = Vec::new();
                for (id, cell) in entries {
                    sessions.push(match cell.try_lock() {
                        Ok(session) => {
                            let is_cdp = session.mode == SessionMode::Cdp;
                            json!({
                                "browser_session_id": id,
                                "mode": if is_cdp { "cdp" } else { "managed" },
                                "attached_existing_browser": is_cdp,
                                "current_operator": session.operator.as_ref() == Some(&owner),
                                "profile_persistent": !is_cdp,
                                "available": session.operator.is_none() && session.phase != Phase::Unknown && session.cleanup.is_none(),
                                "status": match session.phase {
                                    Phase::Saved => "saved",
                                    Phase::New => "not_opened",
                                    Phase::Ready => "open",
                                    Phase::Unknown => "outcome_unknown",
                                },
                            })
                        }
                        Err(_) => json!({"browser_session_id": id, "status": "busy"}),
                    });
                }
                success(json!({"sessions":sessions}))
            }
            BrowserSessionCommand::TakeOver { session_id } => {
                let (id, cell) = match self.resolve(&owner, Some(session_id), false, None) {
                    Ok(v) => v,
                    Err(e) => return failure(e, false),
                };
                let Ok(mut s) = cell.try_lock() else {
                    return failure("busy", false);
                };
                let _caller = match self.active_caller(&owner) {
                    Ok(guard) => guard,
                    Err(code) => return failure(code, false),
                };
                if s.mode == SessionMode::Cdp
                    && self
                        .state()
                        .registry
                        .lock()
                        .expect("Browser sessions")
                        .sessions
                        .get(&id)
                        .is_none_or(|current| !Arc::ptr_eq(current, &cell))
                {
                    return failure("browser_session_not_found", false);
                }
                if s.cleanup.is_some() {
                    return failure("outcome_unknown", true);
                }
                if s.operator.as_ref() != Some(&owner) {
                    if let Some(target) = &s.target
                        && self
                            .port
                            .coordinator
                            .invalidate_browser_session_references(&s.lease, target)
                            .is_err()
                    {
                        return failure("busy", false);
                    }
                    s.operator = Some(owner.clone());
                }
                // An old operator's default remains bound to this ID and is
                // refused; an implicit action must never take the context back.
                // Never make `existing-browser` the caller's implicit default.
                if s.mode == SessionMode::Managed {
                    self.state()
                        .registry
                        .lock()
                        .expect("Browser sessions")
                        .defaults
                        .insert(caller(&owner), id.clone());
                }
                let is_cdp = s.mode == SessionMode::Cdp;
                success(
                    json!({"browser_session_id":id,"mode":if is_cdp {"cdp"} else {"managed"},"attached_existing_browser":is_cdp,"current_operator":true,"profile_persistent":!is_cdp,"status":match s.phase {Phase::Saved=>"saved",Phase::New=>"not_opened",Phase::Ready=>"open",Phase::Unknown=>"outcome_unknown"},"refresh_snapshot":true}),
                )
            }
            BrowserSessionCommand::Action {
                session_id,
                name,
                arguments,
            } => {
                let action = BrowserAction::Tool {
                    name: name.clone(),
                    arguments,
                };
                if action.to_operation_payload().is_err() {
                    return failure("invalid_arguments", false);
                }
                let close = action.is_close();
                let (id, cell) = match self.resolve(&owner, session_id, !close, Some(name.as_str()))
                {
                    Ok(v) => v,
                    Err(e) => return failure(e, false),
                };
                let mut session = cell.lock().await;
                let session_mode = session.mode;
                {
                    let _caller = match self.active_caller(&owner) {
                        Ok(guard) => guard,
                        Err(code) => return failure(code, false),
                    };
                    if session_mode == SessionMode::Cdp
                        && self
                            .state()
                            .registry
                            .lock()
                            .expect("Browser sessions")
                            .sessions
                            .get(&id)
                            .is_none_or(|current| !Arc::ptr_eq(current, &cell))
                    {
                        return failure("browser_session_not_found", false);
                    }
                    if session.operator.is_none() {
                        if let Some(target) = &session.target
                            && self
                                .port
                                .coordinator
                                .invalidate_browser_session_references(&session.lease, target)
                                .is_err()
                        {
                            return failure("busy", false);
                        }
                        session.operator = Some(owner.clone());
                        if session_mode == SessionMode::Managed {
                            let mut state = self.state().registry.lock().expect("Browser sessions");
                            if !Self::has_open_default(&state, &owner) {
                                state.defaults.insert(caller(&owner), id.clone());
                            }
                        }
                    } else if session.operator.as_ref() != Some(&owner) {
                        return failure("browser_session_transferred", false);
                    }
                }
                let mut result = if close {
                    self.close(&id, &mut session).await
                } else {
                    if session.cleanup.is_none()
                        && session.target.as_ref().is_some_and(|target| {
                            self.port
                                .coordinator
                                .browser_session_exited(&session.lease, target)
                        })
                    {
                        let operator = session.operator.clone();
                        let _ = self.close(&id, &mut session).await;
                        if session.phase == Phase::Saved
                            && operator
                                .as_ref()
                                .is_some_and(|op| self.active_caller(op).is_ok())
                        {
                            session.operator = operator;
                        }
                    }
                    self.execute(&id, &mut session, action, &name).await
                };
                if !close
                    && session.cleanup.is_none()
                    && session.target.as_ref().is_some_and(|target| {
                        self.port
                            .coordinator
                            .browser_session_exited(&session.lease, target)
                    })
                {
                    let operator = session.operator.clone();
                    let _ = self.close(&id, &mut session).await;
                    if session.phase == Phase::Saved
                        && operator
                            .as_ref()
                            .is_some_and(|op| self.active_caller(op).is_ok())
                    {
                        // Keep the first outcome. An action may have taken effect
                        // before its worker exited; repeating it is not safe.
                        session.operator = operator;
                    }
                }
                let metadata = result.structured_content.get_or_insert_with(|| json!({}));
                if metadata.is_object() {
                    metadata["browser_session_id"] = json!(id);
                }
                if !close {
                    attach_session_id_to_content(&mut result, &id);
                }
                result
            }
        }
    }
    async fn exchange(&self, s: &Session, command: BrowserCommand, timeout: u32) -> BrowserReply {
        self.port
            .handle_browser(
                s.lease.clone(),
                self.port.coordinator.grant_revision(),
                timeout,
                command,
            )
            .await
    }
    async fn execute(
        &self,
        id: &str,
        s: &mut Session,
        action: BrowserAction,
        name: &str,
    ) -> CallToolResult {
        if s.phase == Phase::Unknown {
            return failure("outcome_unknown", true);
        }
        if matches!(s.phase, Phase::New | Phase::Saved) {
            s.phase = Phase::Unknown; // Dropped waiters never cause automatic replay.
            let reply = self
                .exchange(
                    s,
                    BrowserCommand::PrepareOpen,
                    BROWSER_WAIT_PREPARE_TIMEOUT_MS,
                )
                .await;
            let target = match reply {
                BrowserReply::Prepared { snapshot }
                    if snapshot.state == OperationState::Reserved && snapshot.target.is_none() =>
                {
                    ResourceTarget {
                        operation_id: snapshot.operation_id,
                        payload_digest: snapshot.payload_digest,
                    }
                }
                other => {
                    if not_dispatched(&other) {
                        s.phase = Phase::New;
                    }
                    return refusal(&other);
                }
            };
            s.target = Some(target.clone());
            match self
                .exchange(
                    s,
                    BrowserCommand::DispatchOpen {
                        target: target.clone(),
                    },
                    BROWSER_WAIT_PREPARE_TIMEOUT_MS,
                )
                .await
            {
                BrowserReply::Start { snapshot, dispatch }
                    if dispatch == "started"
                        && snapshot.state == OperationState::Running
                        && snapshot.operation_id == target.operation_id
                        && snapshot.payload_digest == target.payload_digest =>
                {
                    s.phase = Phase::Ready
                }
                other => {
                    if not_dispatched(&other) {
                        s.target = None;
                        s.phase = Phase::New;
                    }
                    return refusal(&other);
                }
            }
        }
        let target = s.target.clone().expect("opened resource");
        let payload = action.to_operation_payload().expect("validated action");
        let digest = Sha256Digest::of_bytes(&payload);
        let raw =
            serde_json::value::RawValue::from_string(String::from_utf8(payload).expect("JSON"))
                .expect("JSON action");
        s.phase = Phase::Unknown;
        let reply = self
            .exchange(
                s,
                BrowserCommand::PrepareAction {
                    target: target.clone(),
                    action: raw,
                },
                action_timeout(name, s.mode),
            )
            .await;
        let action = match reply {
            BrowserReply::Prepared { snapshot }
                if snapshot.state == OperationState::Reserved
                    && snapshot.target.as_ref() == Some(&target)
                    && snapshot.payload_digest == digest =>
            {
                ActionRef {
                    operation_id: snapshot.operation_id,
                    payload_digest: snapshot.payload_digest,
                }
            }
            other => {
                if not_dispatched(&other) {
                    s.phase = Phase::Ready;
                }
                return refusal(&other);
            }
        };
        let operation_id = action.operation_id.clone();
        let reply = self
            .exchange(
                s,
                BrowserCommand::DispatchAction { action },
                action_timeout(name, s.mode),
            )
            .await;
        self.finish_action(id, s, &operation_id, digest, &target, reply)
            .await
    }
    async fn finish_action(
        &self,
        id: &str,
        s: &mut Session,
        operation_id: &OperationId,
        digest: Sha256Digest,
        target: &ResourceTarget,
        reply: BrowserReply,
    ) -> CallToolResult {
        match reply {
            BrowserReply::Action {
                snapshot,
                dispatch,
                result: Some(value),
                cause: None | Some(ErrorCategory::StaleObservation),
                ..
            } if dispatch == "acknowledged"
                && matches!(
                    snapshot.state,
                    OperationState::Succeeded | OperationState::Failed
                )
                && snapshot.operation_id == *operation_id
                && snapshot.payload_digest == digest
                && snapshot.target.as_ref() == Some(target) =>
            {
                match result(value) {
                    Ok(result) => {
                        s.phase = Phase::Ready;
                        result
                    }
                    Err(_) => failure("outcome_unknown", true),
                }
            }
            BrowserReply::Action {
                snapshot,
                dispatch,
                cause,
                ..
            } if dispatch == "not_dispatched"
                && snapshot.state == OperationState::Failed
                && snapshot.operation_id == *operation_id
                && snapshot.payload_digest == digest
                && snapshot.target.as_ref() == Some(target) =>
            {
                if s.mode == SessionMode::Cdp && cause == Some(ErrorCategory::CapabilityUnsupported)
                {
                    let operator = s.operator.clone();
                    let _ = self.close(id, s).await;
                    if s.phase == Phase::Saved
                        && operator
                            .as_ref()
                            .is_some_and(|op| self.active_caller(op).is_ok())
                    {
                        s.operator = operator;
                    }
                } else {
                    s.phase = Phase::Ready;
                }
                refusal(&BrowserReply::Error {
                    category: cause.unwrap_or(ErrorCategory::CapabilityUnsupported),
                    certainty: ExecutionCertainty::NotDispatched,
                })
            }
            other => {
                if not_dispatched(&other) {
                    s.phase = Phase::Ready;
                }
                refusal(&other)
            }
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
