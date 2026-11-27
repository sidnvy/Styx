//! Host-owned Browser sessions backed by the Chrome Extension Bridge (`existing-browser`
//! for shared user tabs and parallel `bg-...` Tab Group sessions for background work).
//! Transfers reuse a session's Core resource identity.
pub(crate) mod operations;
use crate::host::{
    browser_extension::{
        BROWSER_OWNER_PREFIX, BROWSER_SESSION_ID, CdpSessionScope, TabGroupCloseOutcome,
    },
    coordinator::OwnerCleanupHandle,
    protocol::wire::*,
};
use crate::providers::browser_contract::BrowserAction;
use operations::{BrowserCommand, BrowserPort, BrowserReply};
use rmcp::model::{CallToolResult, ContentBlock};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap},
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

const MAX_BROWSER_RESULT_BYTES: usize = styx_contracts::DESKTOP_BROWSER_FRAME_BYTES;
const MAX_TAB_GROUP_SESSIONS: usize = 16;
const TAB_GROUP_COLORS: &[&str] = &["blue", "cyan", "purple", "green", "orange", "pink"];
pub(crate) const DEFAULT_IDLE_PARK_TIMEOUT: Duration = Duration::from_secs(240);
pub(crate) const DEFAULT_PARKED_TAB_GROUP_TTL: Duration = Duration::from_secs(2 * 60 * 60);
pub(crate) const MAX_PARKED_TAB_GROUPS: usize = 3;

type Caller = (OwnerId, OwnerEpoch);
type Cell = Arc<AsyncMutex<Session>>;
#[derive(Default)]
pub(crate) struct State {
    registry: Mutex<Registry>,
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
        registry.owner_default.remove(&caller(owner));
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
    owner_default: HashMap<Caller, String>,
    next_group_seq: u64,
}
struct Session {
    id: String,
    scope: CdpSessionScope,
    operator: Option<OwnerRef>,
    lease: OwnerLease,
    target: Option<ResourceTarget>,
    phase: Phase,
    cleanup: Option<OwnerCleanupHandle>,
    last_activity: std::time::Instant,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Saved,
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
fn action_timeout(_name: &str) -> u32 {
    BROWSER_WAIT_PREPARE_TIMEOUT_MS
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
        id: String,
        scope: CdpSessionScope,
        operator: Option<OwnerRef>,
        phase: Phase,
    ) -> Result<Session, &'static str> {
        // Each Host Extension Bridge session owns an independent Core lease/incarnation.
        let incarnation = uuid::Uuid::new_v4().simple().to_string();
        let owner_id = format!("{BROWSER_OWNER_PREFIX}{incarnation}");
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
            id,
            scope,
            operator,
            lease,
            target: None,
            phase,
            cleanup: None,
            last_activity: std::time::Instant::now(),
        })
    }
    fn ensure_shared_existing_in(&self, registry: &mut Registry) -> Result<Cell, &'static str> {
        if let Some(cell) = registry.sessions.get(BROWSER_SESSION_ID).cloned() {
            return Ok(cell);
        }
        let cell = Arc::new(AsyncMutex::new(self.new_session(
            BROWSER_SESSION_ID.to_owned(),
            CdpSessionScope::SharedExisting,
            None,
            Phase::Saved,
        )?));
        registry
            .sessions
            .insert(BROWSER_SESSION_ID.to_owned(), cell.clone());
        Ok(cell)
    }
    fn create_tab_group_session_in(
        &self,
        registry: &mut Registry,
        owner: &OwnerRef,
    ) -> Result<(String, Cell), &'static str> {
        let bg_count = registry
            .sessions
            .keys()
            .filter(|id| id.as_str() != BROWSER_SESSION_ID)
            .count();
        if bg_count >= MAX_TAB_GROUP_SESSIONS {
            return Err("capacity_busy");
        }
        let seq = registry.next_group_seq + 1;
        let title = format!("Styx · {seq}");
        let color = TAB_GROUP_COLORS[((seq - 1) as usize) % TAB_GROUP_COLORS.len()].to_owned();
        let id = format!("bg-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
        let session = self.new_session(
            id.clone(),
            CdpSessionScope::TabGroup {
                title,
                color,
                session_key: Some(id.clone()),
            },
            Some(owner.clone()),
            Phase::Saved,
        )?;
        registry.next_group_seq = seq;
        let cell = Arc::new(AsyncMutex::new(session));
        registry.sessions.insert(id.clone(), cell.clone());
        registry.owner_default.insert(caller(owner), id.clone());
        Ok((id, cell))
    }
    fn resolve(
        &self,
        owner: &OwnerRef,
        id: Option<String>,
    ) -> Result<(String, Cell), &'static str> {
        let _caller = self.active_caller(owner)?;
        let mut registry = self.state().registry.lock().expect("Browser sessions");
        match id.as_deref() {
            Some(BROWSER_SESSION_ID) => {
                let cell = self.ensure_shared_existing_in(&mut registry)?;
                Ok((BROWSER_SESSION_ID.to_owned(), cell))
            }
            Some("new") => self.create_tab_group_session_in(&mut registry, owner),
            Some(explicit_id) => {
                let cell = registry
                    .sessions
                    .get(explicit_id)
                    .cloned()
                    .ok_or("browser_session_not_found")?;
                Ok((explicit_id.to_owned(), cell))
            }
            None => {
                if let Some(default_id) = registry.owner_default.get(&caller(owner)).cloned()
                    && let Some(cell) = registry.sessions.get(&default_id).cloned()
                {
                    return Ok((default_id, cell));
                }
                self.create_tab_group_session_in(&mut registry, owner)
            }
        }
    }
    fn resolve_for_takeover(
        &self,
        owner: &OwnerRef,
        session_id: String,
    ) -> Result<(String, Cell), &'static str> {
        let _caller = self.active_caller(owner)?;
        let mut registry = self.state().registry.lock().expect("Browser sessions");
        if session_id == BROWSER_SESSION_ID {
            let cell = self.ensure_shared_existing_in(&mut registry)?;
            return Ok((BROWSER_SESSION_ID.to_owned(), cell));
        }
        let cell = registry
            .sessions
            .get(&session_id)
            .cloned()
            .ok_or("browser_session_not_found")?;
        Ok((session_id, cell))
    }
    fn remove_session_entry(&self, id: &str) {
        if id == BROWSER_SESSION_ID {
            return;
        }
        let mut registry = self.state().registry.lock().expect("Browser sessions");
        registry.sessions.remove(id);
        registry.owner_default.retain(|_, v| v != id);
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
    fn close_payload(id: &str) -> Value {
        json!({
            "browser_session_id": id,
            "closed": true,
            "detached": true,
            "profile_persistent": false,
            "profile_preserved": false,
        })
    }
    async fn close(&self, id: &str, session: &mut Session) -> CallToolResult {
        if session.phase == Phase::Saved && session.target.is_none() {
            session.operator = None;
            return success(Self::close_payload(id));
        }
        if self.cleanup_session_resources(session).await.is_err() {
            return failure("outcome_unknown", true);
        }
        *session = match self.new_session(
            session.id.clone(),
            session.scope.clone(),
            None,
            Phase::Saved,
        ) {
            Ok(saved) => saved,
            Err(code) => return failure(code, false),
        };
        success(Self::close_payload(id))
    }
    /// Parks active `Phase::Ready` sessions that have been idle for at least
    /// `idle_timeout`, closing their Playwright worker and CDP WebSocket (which
    /// detaches `chrome.debugger` without closing tabs) while preserving the logical
    /// session record, `owner_default`, and operator so the next turn re-attaches.
    pub(crate) async fn park_idle_sessions(&self, idle_timeout: Duration) -> usize {
        self.collect_closed().await;
        let entries: Vec<(String, Cell)> = {
            let registry = self.state().registry.lock().expect("Browser sessions");
            registry
                .sessions
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        };
        let mut parked = 0;
        for (id, cell) in entries {
            let Ok(mut session) = cell.try_lock() else {
                continue;
            };
            if session.phase != Phase::Ready
                || session.cleanup.is_some()
                || session.last_activity.elapsed() < idle_timeout
            {
                continue;
            }
            let preserved_operator = session.operator.clone();
            let preserved_scope = session.scope.clone();
            if self.cleanup_session_resources(&mut session).await.is_err() {
                continue;
            }
            let preserved_operator = preserved_operator.filter(|op| self.active_caller(op).is_ok());
            let park_tab_group_key = match &preserved_scope {
                CdpSessionScope::TabGroup { session_key, .. } => session_key.clone(),
                CdpSessionScope::SharedExisting => None,
            };
            let Ok(saved) = self.new_session(id, preserved_scope, preserved_operator, Phase::Saved)
            else {
                continue;
            };
            *session = saved;
            drop(session);
            if let (Some(key), Some(bridge)) =
                (park_tab_group_key, self.port.inputs.extension_bridge())
            {
                let _ = bridge.park_tab_group(&key).await;
            }
            parked += 1;
        }
        parked
    }
    /// Reaps parked `bg-...` Tab Group sessions that exceed `max_parked_groups`
    /// (oldest-first) or have stayed parked longer than `parked_ttl`. Never touches
    /// `existing-browser` or any group containing an actively viewed Chrome tab.
    pub(crate) async fn reap_parked_tab_groups(
        &self,
        parked_ttl: Duration,
        max_parked_groups: usize,
    ) -> usize {
        let entries: Vec<(String, Cell)> = {
            let registry = self.state().registry.lock().expect("Browser sessions");
            registry
                .sessions
                .iter()
                .filter(|(k, _)| k.as_str() != BROWSER_SESSION_ID)
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        };
        let mut candidates = Vec::new();
        for (id, cell) in entries {
            let Ok(session) = cell.try_lock() else {
                continue;
            };
            if session.phase != Phase::Saved || session.cleanup.is_some() {
                continue;
            }
            let session_key = match &session.scope {
                CdpSessionScope::TabGroup { session_key, .. } => session_key.clone(),
                CdpSessionScope::SharedExisting => continue,
            };
            candidates.push((id, cell.clone(), session.last_activity, session_key));
        }
        candidates.sort_by_key(|(_, _, last_activity, _)| *last_activity);
        let excess = candidates.len().saturating_sub(max_parked_groups);
        let mut reaped = 0;
        for (idx, (id, cell, last_activity, session_key)) in candidates.into_iter().enumerate() {
            if idx >= excess && last_activity.elapsed() < parked_ttl {
                continue;
            }
            let Ok(mut session) = cell.try_lock() else {
                continue;
            };
            if session.phase != Phase::Saved || session.cleanup.is_some() {
                continue;
            }
            if let (Some(key), Some(bridge)) =
                (session_key.as_deref(), self.port.inputs.extension_bridge())
                && bridge.close_tab_group(key, true).await == TabGroupCloseOutcome::SkippedActive
            {
                session.last_activity = std::time::Instant::now();
                continue;
            }
            drop(session);
            self.remove_session_entry(&id);
            reaped += 1;
        }
        reaped
    }
    /// Capability shutdown already proved physical exit. Reclaim exited local
    /// owners/sessions on the next request without disturbing active parallel sessions.
    async fn collect_closed(&self) {
        let entries: Vec<(String, Cell)> = {
            let registry = self.state().registry.lock().expect("Browser sessions");
            registry
                .sessions
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        };
        let mut remove_ids = Vec::new();
        for (id, cell) in entries {
            let Ok(mut s) = cell.try_lock() else {
                continue;
            };
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
                let res = self.close(&id, &mut s).await;
                if res.is_error != Some(true) && id != BROWSER_SESSION_ID {
                    remove_ids.push(id);
                } else if s.phase == Phase::Saved
                    && operator
                        .as_ref()
                        .is_some_and(|op| self.active_caller(op).is_ok())
                {
                    s.operator = operator;
                }
            }
        }
        for id in remove_ids {
            self.remove_session_entry(&id);
        }
    }
    pub(crate) async fn handle(
        &self,
        owner: OwnerRef,
        command: BrowserSessionCommand,
    ) -> CallToolResult {
        self.collect_closed().await;
        if self.active_caller(&owner).is_err() {
            return failure("unauthorized", false);
        }
        match command {
            BrowserSessionCommand::List => {
                let entries: Vec<(String, Cell)> = {
                    let mut registry = self.state().registry.lock().expect("Browser sessions");
                    if let Err(code) = self.ensure_shared_existing_in(&mut registry) {
                        return failure(code, false);
                    }
                    registry
                        .sessions
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect()
                };
                let mut list = Vec::with_capacity(entries.len());
                for (id, cell) in entries {
                    let item = match cell.try_lock() {
                        Ok(session) => {
                            let (mode, title, color) = match &session.scope {
                                CdpSessionScope::SharedExisting => {
                                    ("extension_existing", None, None)
                                }
                                CdpSessionScope::TabGroup { title, color, .. } => (
                                    "extension_tab_group",
                                    Some(title.as_str()),
                                    Some(color.as_str()),
                                ),
                            };
                            let mut obj = json!({
                                "browser_session_id": id,
                                "mode": mode,
                                "attached_existing_browser": true,
                                "current_operator": session.operator.as_ref() == Some(&owner),
                                "profile_persistent": false,
                                "available": session.operator.is_none() && session.phase != Phase::Unknown && session.cleanup.is_none(),
                                "status": match session.phase {
                                    Phase::Saved => "saved",
                                    Phase::Ready => "open",
                                    Phase::Unknown => "outcome_unknown",
                                },
                            });
                            if let (Some(t), Some(c)) = (title, color) {
                                obj["tab_group_title"] = json!(t);
                                obj["tab_group_color"] = json!(c);
                            }
                            obj
                        }
                        Err(_) => {
                            let mode = if id == BROWSER_SESSION_ID {
                                "extension_existing"
                            } else {
                                "extension_tab_group"
                            };
                            json!({
                                "browser_session_id": id,
                                "mode": mode,
                                "attached_existing_browser": true,
                                "status": "busy",
                            })
                        }
                    };
                    list.push(item);
                }
                success(json!({ "sessions": list }))
            }
            BrowserSessionCommand::TakeOver { session_id } => {
                let (id, cell) = match self.resolve_for_takeover(&owner, session_id) {
                    Ok(v) => v,
                    Err(e) => return failure(e, false),
                };
                let (mode, title, color, status) = {
                    let Ok(mut s) = cell.try_lock() else {
                        return failure("busy", false);
                    };
                    let _caller = match self.active_caller(&owner) {
                        Ok(guard) => guard,
                        Err(code) => return failure(code, false),
                    };
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
                    s.last_activity = std::time::Instant::now();
                    let (mode, title, color) = match &s.scope {
                        CdpSessionScope::SharedExisting => ("extension_existing", None, None),
                        CdpSessionScope::TabGroup { title, color, .. } => (
                            "extension_tab_group",
                            Some(title.clone()),
                            Some(color.clone()),
                        ),
                    };
                    let status = match s.phase {
                        Phase::Saved => "saved",
                        Phase::Ready => "open",
                        Phase::Unknown => "outcome_unknown",
                    };
                    (mode, title, color, status)
                };
                {
                    let mut registry = self.state().registry.lock().expect("Browser sessions");
                    if registry.sessions.contains_key(&id) {
                        registry.owner_default.insert(caller(&owner), id.clone());
                    }
                }
                let mut payload = json!({
                    "browser_session_id": id,
                    "mode": mode,
                    "attached_existing_browser": true,
                    "current_operator": true,
                    "profile_persistent": false,
                    "status": status,
                    "refresh_snapshot": true,
                });
                if let (Some(t), Some(c)) = (title, color) {
                    payload["tab_group_title"] = json!(t);
                    payload["tab_group_color"] = json!(c);
                }
                success(payload)
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
                let (id, cell) = match self.resolve(&owner, session_id) {
                    Ok(v) => v,
                    Err(e) => return failure(e, false),
                };
                let mut session = cell.lock().await;
                {
                    let _caller = match self.active_caller(&owner) {
                        Ok(guard) => guard,
                        Err(code) => return failure(code, false),
                    };
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
                    } else if session.operator.as_ref() != Some(&owner) {
                        return failure("browser_session_transferred", false);
                    }
                    session.last_activity = std::time::Instant::now();
                }
                let mut result = if close {
                    let close_tab_group_key = match &session.scope {
                        CdpSessionScope::TabGroup { session_key, .. } => session_key.clone(),
                        CdpSessionScope::SharedExisting => None,
                    };
                    let closed = self.close(&id, &mut session).await;
                    drop(session);
                    if closed.is_error != Some(true) && id != BROWSER_SESSION_ID {
                        self.remove_session_entry(&id);
                        if let (Some(key), Some(bridge)) =
                            (close_tab_group_key, self.port.inputs.extension_bridge())
                        {
                            let _ = bridge.close_tab_group(&key, false).await;
                        }
                    }
                    closed
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
                    let res = self.execute(&id, &mut session, action, &name).await;
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
                    if !close {
                        session.last_activity = std::time::Instant::now();
                    }
                    drop(session);
                    res
                };
                if !close {
                    let mut registry = self.state().registry.lock().expect("Browser sessions");
                    if registry.sessions.contains_key(&id) {
                        registry.owner_default.insert(caller(&owner), id.clone());
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
        if s.phase == Phase::Saved {
            s.phase = Phase::Unknown; // Dropped waiters never cause automatic replay.
            let reply = self
                .exchange(
                    s,
                    BrowserCommand::PrepareOpen {
                        scope: s.scope.clone(),
                    },
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
                        s.phase = Phase::Saved;
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
                        s.phase = Phase::Saved;
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
                action_timeout(name),
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
                action_timeout(name),
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
                if cause == Some(ErrorCategory::CapabilityUnsupported) {
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
