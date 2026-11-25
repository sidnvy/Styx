//! Host-owned authenticated bridge + loopback CDP WebSocket relay translating
//! Playwright `connectOverCDP` commands into Chrome Extension `chrome.debugger` RPCs.
use super::bridge_file_path;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use styx_contracts::error::ErrorCategory;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::{Mutex, mpsc, oneshot},
    task::JoinHandle,
};
use tokio_tungstenite::{
    accept_hdr_async,
    tungstenite::{
        Message,
        handshake::server::{ErrorResponse, Request, Response},
    },
};
use tokio_util::sync::CancellationToken;

const RPC_TIMEOUT: Duration = Duration::from_secs(30);
const AUTH_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CdpSessionScope {
    SharedExisting,
    TabGroup { title: String, color: String },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct TabDescriptor {
    id: i64,
    #[serde(default)]
    url: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    active: bool,
    #[serde(rename = "windowId", default)]
    window_id: Option<i64>,
    #[serde(rename = "groupId", default = "default_group_id")]
    group_id: i64,
    #[serde(rename = "openerTabId", default)]
    opener_tab_id: Option<i64>,
    #[serde(default)]
    isolated: bool,
}

fn default_group_id() -> i64 {
    -1
}

struct ExtensionPeer {
    browser_label: String,
    user_agent: String,
    outbound: mpsc::Sender<String>,
    next_id: AtomicU64,
    next_relay_id: AtomicU64,
    pending: StdMutex<HashMap<u64, oneshot::Sender<Result<Value, String>>>>,
    event_subscribers: StdMutex<HashMap<u64, mpsc::UnboundedSender<(String, Value)>>>,
    initial_tabs: StdMutex<Vec<TabDescriptor>>,
    isolated_tabs: StdMutex<HashMap<i64, u64>>,
    tab_owners: StdMutex<HashMap<i64, u64>>,
    shutdown: CancellationToken,
}

impl ExtensionPeer {
    async fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();
        {
            let mut guard = self
                .pending
                .lock()
                .map_err(|_| "extension_peer_mutex_poisoned".to_owned())?;
            guard.insert(id, tx);
        }
        let msg = json!({ "id": id, "method": method, "params": params }).to_string();
        if self.outbound.send(msg).await.is_err() {
            if let Ok(mut guard) = self.pending.lock() {
                guard.remove(&id);
            }
            return Err("extension_disconnected".to_owned());
        }
        match tokio::time::timeout(RPC_TIMEOUT, rx).await {
            Ok(Ok(res)) => res,
            Ok(Err(_)) => Err("extension_disconnected".to_owned()),
            Err(_) => {
                if let Ok(mut guard) = self.pending.lock() {
                    guard.remove(&id);
                }
                Err(format!("extension_rpc_timeout: {method}"))
            }
        }
    }

    fn resolve_rpc(&self, id: u64, result: Option<Value>, error: Option<Value>) {
        let tx = self.pending.lock().ok().and_then(|mut map| map.remove(&id));
        let Some(tx) = tx else {
            return;
        };
        if let Some(err) = error {
            let msg = err
                .as_str()
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| err.to_string());
            let _ = tx.send(Err(msg));
        } else {
            let _ = tx.send(Ok(result.unwrap_or_else(|| json!({}))));
        }
    }

    fn subscribe_events(&self) -> (u64, mpsc::UnboundedReceiver<(String, Value)>) {
        let relay_id = self.next_relay_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = mpsc::unbounded_channel();
        if let Ok(mut guard) = self.event_subscribers.lock() {
            guard.insert(relay_id, tx);
        }
        (relay_id, rx)
    }

    fn unsubscribe_events(&self, relay_id: u64) {
        if let Ok(mut guard) = self.event_subscribers.lock() {
            guard.remove(&relay_id);
        }
    }

    fn emit_event(&self, event: String, params: Value) {
        if let Ok(mut guard) = self.event_subscribers.lock() {
            guard.retain(|_, tx| tx.send((event.clone(), params.clone())).is_ok());
        }
    }

    fn snapshot_initial_tabs(&self) -> Vec<TabDescriptor> {
        self.initial_tabs
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    fn claim_tab(&self, tab_id: i64, relay_id: u64, isolated: bool) -> bool {
        if isolated && let Ok(mut iso) = self.isolated_tabs.lock() {
            match iso.get(&tab_id) {
                Some(&owner) if owner != relay_id => return false,
                _ => {
                    iso.insert(tab_id, relay_id);
                }
            }
        } else if !isolated
            && self
                .isolated_tabs
                .lock()
                .is_ok_and(|iso| iso.get(&tab_id).is_some_and(|&owner| owner != relay_id))
        {
            return false;
        }
        if let Ok(mut owners) = self.tab_owners.lock() {
            match owners.get(&tab_id) {
                Some(&owner) if owner != relay_id => return false,
                _ => {
                    owners.insert(tab_id, relay_id);
                    return true;
                }
            }
        }
        false
    }

    fn is_tab_available_for_shared(&self, tab_id: i64, relay_id: u64) -> bool {
        let isolated = self
            .isolated_tabs
            .lock()
            .is_ok_and(|iso| iso.contains_key(&tab_id));
        if isolated {
            return false;
        }
        self.tab_owners
            .lock()
            .is_ok_and(|owners| !owners.get(&tab_id).is_some_and(|&owner| owner != relay_id))
    }

    fn release_relay_tabs(&self, relay_id: u64, tab_ids: &[i64]) {
        if let Ok(mut owners) = self.tab_owners.lock() {
            for tab_id in tab_ids {
                if owners.get(tab_id) == Some(&relay_id) {
                    owners.remove(tab_id);
                }
            }
            owners.retain(|_, &mut owner| owner != relay_id);
        }
        if let Ok(mut iso) = self.isolated_tabs.lock() {
            for tab_id in tab_ids {
                if iso.get(tab_id) == Some(&relay_id) {
                    iso.remove(tab_id);
                }
            }
            iso.retain(|_, &mut owner| owner != relay_id);
        }
    }

    fn clear_pending(&self) {
        if let Ok(mut guard) = self.pending.lock() {
            for (_, tx) in guard.drain() {
                let _ = tx.send(Err("extension_disconnected".to_owned()));
            }
        }
    }
}

/// Host-owned listener for the Chrome Extension Native Messaging bridge and
/// single-use loopback CDP WebSocket sessions.
pub struct BrowserExtensionBridge {
    state_dir: PathBuf,
    ipc_port: u16,
    ws_port: u16,
    token: String,
    cancel: CancellationToken,
    peer: Mutex<Option<Arc<ExtensionPeer>>>,
    peer_info: StdMutex<Option<(String, String)>>,
    pending_ws_tokens: StdMutex<HashMap<String, CdpSessionScope>>,
    tasks: StdMutex<Vec<JoinHandle<()>>>,
}

impl BrowserExtensionBridge {
    pub async fn start(state_dir: &Path) -> Result<Arc<Self>, ErrorCategory> {
        let mut raw = [0_u8; 32];
        getrandom::fill(&mut raw).map_err(|_| ErrorCategory::IntegrityFailure)?;
        let token = hex::encode(raw);

        let ipc_listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .map_err(|_| ErrorCategory::CapabilityUnsupported)?;
        let ipc_port = ipc_listener
            .local_addr()
            .map_err(|_| ErrorCategory::CapabilityUnsupported)?
            .port();

        let ws_listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .map_err(|_| ErrorCategory::CapabilityUnsupported)?;
        let ws_port = ws_listener
            .local_addr()
            .map_err(|_| ErrorCategory::CapabilityUnsupported)?
            .port();

        let endpoint_bytes = serde_json::to_vec(&json!({
            "schema": 1,
            "port": ipc_port,
            "token": token,
        }))
        .map_err(|_| ErrorCategory::IntegrityFailure)?;
        super::atomic_write(
            state_dir,
            &bridge_file_path(state_dir),
            &endpoint_bytes,
            false,
        )?;

        let cancel = CancellationToken::new();
        let bridge = Arc::new(Self {
            state_dir: state_dir.to_owned(),
            ipc_port,
            ws_port,
            token,
            cancel: cancel.clone(),
            peer: Mutex::new(None),
            peer_info: StdMutex::new(None),
            pending_ws_tokens: StdMutex::new(HashMap::new()),
            tasks: StdMutex::new(Vec::new()),
        });

        let ipc_bridge = bridge.clone();
        let ipc_handle = tokio::spawn(async move {
            ipc_bridge.accept_ipc_loop(ipc_listener).await;
        });

        let ws_bridge = bridge.clone();
        let ws_handle = tokio::spawn(async move {
            ws_bridge.accept_ws_loop(ws_listener).await;
        });

        if let Ok(mut tasks) = bridge.tasks.lock() {
            tasks.push(ipc_handle);
            tasks.push(ws_handle);
        }

        Ok(bridge)
    }

    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    pub fn ipc_port(&self) -> u16 {
        self.ipc_port
    }

    pub fn ws_port(&self) -> u16 {
        self.ws_port
    }

    pub fn is_connected(&self) -> bool {
        self.peer_info
            .lock()
            .ok()
            .is_some_and(|info| info.is_some())
    }

    pub fn browser_label(&self) -> Option<String> {
        self.peer_info
            .lock()
            .ok()
            .and_then(|info| info.as_ref().map(|(label, _)| label.clone()))
    }

    /// Mints a single-use loopback CDP WebSocket endpoint for `worker.mjs`.
    pub fn open_cdp_session(&self) -> Result<String, ErrorCategory> {
        self.open_cdp_session_with_scope(CdpSessionScope::SharedExisting)
    }

    /// Mints a single-use loopback CDP WebSocket endpoint bound to a specific tab scope.
    pub fn open_cdp_session_with_scope(
        &self,
        scope: CdpSessionScope,
    ) -> Result<String, ErrorCategory> {
        if !self.is_connected() {
            return Err(ErrorCategory::CapabilityUnsupported);
        }
        let id = uuid::Uuid::new_v4().to_string();
        let path = format!("/devtools/browser/{id}");
        self.pending_ws_tokens
            .lock()
            .map_err(|_| ErrorCategory::ResultUnknown)?
            .insert(path.clone(), scope);
        Ok(format!("ws://127.0.0.1:{}{}", self.ws_port, path))
    }

    pub async fn shutdown(&self) {
        self.cancel.cancel();
        let _ = std::fs::remove_file(bridge_file_path(&self.state_dir));
        if let Some(peer) = self.peer.lock().await.take() {
            peer.shutdown.cancel();
            peer.clear_pending();
        }
        if let Ok(mut info) = self.peer_info.lock() {
            *info = None;
        }
        let handles: Vec<JoinHandle<()>> = self
            .tasks
            .lock()
            .ok()
            .map(|mut guard| std::mem::take(&mut *guard))
            .unwrap_or_default();
        for handle in handles {
            let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
        }
    }

    async fn accept_ipc_loop(self: Arc<Self>, listener: TcpListener) {
        loop {
            tokio::select! {
                () = self.cancel.cancelled() => break,
                accepted = listener.accept() => {
                    let Ok((stream, _addr)) = accepted else {
                        break;
                    };
                    let this = self.clone();
                    tokio::spawn(async move {
                        this.handle_ipc_client(stream).await;
                    });
                }
            }
        }
    }

    async fn handle_ipc_client(self: Arc<Self>, stream: TcpStream) {
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);
        let mut auth_line = String::new();
        let Ok(Ok(n)) = tokio::time::timeout(AUTH_TIMEOUT, reader.read_line(&mut auth_line)).await
        else {
            return;
        };
        if n == 0 {
            return;
        }
        let Ok(auth) = serde_json::from_str::<Value>(&auth_line) else {
            return;
        };
        let valid = auth.get("type").and_then(Value::as_str) == Some("auth")
            && auth.get("token").and_then(Value::as_str) == Some(self.token.as_str());
        if !valid {
            return;
        }
        if write_half
            .write_all(b"{\"type\":\"auth_ok\"}\n")
            .await
            .is_err()
        {
            return;
        }

        let (out_tx, mut out_rx) = mpsc::channel::<String>(256);
        let peer_cancel = self.cancel.child_token();
        let writer_cancel = peer_cancel.clone();
        let writer_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = writer_cancel.cancelled() => break,
                    msg = out_rx.recv() => {
                        let Some(msg) = msg else { break };
                        let line = format!("{msg}\n");
                        if write_half.write_all(line.as_bytes()).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        let mut active_peer: Option<Arc<ExtensionPeer>> = None;
        let mut line = String::new();
        loop {
            line.clear();
            tokio::select! {
                () = peer_cancel.cancelled() => break,
                read = reader.read_line(&mut line) => {
                    let Ok(bytes) = read else { break };
                    if bytes == 0 {
                        break;
                    }
                    let Ok(msg) = serde_json::from_str::<Value>(line.trim()) else {
                        continue;
                    };
                    if let Some(id) = msg.get("id").and_then(Value::as_u64) {
                        if let Some(peer) = &active_peer {
                            peer.resolve_rpc(
                                id,
                                msg.get("result").cloned(),
                                msg.get("error").cloned(),
                            );
                        }
                        continue;
                    }
                    let Some(event) = msg.get("event").and_then(Value::as_str) else {
                        continue;
                    };
                    let params = msg.get("params").cloned().unwrap_or_else(|| json!({}));
                    if event == "extension.hello" {
                        let browser_label = params
                            .get("browser")
                            .and_then(Value::as_str)
                            .unwrap_or("Chrome/Extension-Bridge")
                            .to_owned();
                        let user_agent = params
                            .get("userAgent")
                            .and_then(Value::as_str)
                            .unwrap_or("Mozilla/5.0 Chrome/130.0.0.0")
                            .to_owned();
                        let hello_tabs = serde_json::from_value::<Vec<TabDescriptor>>(
                            params.get("tabs").cloned().unwrap_or_else(|| json!([])),
                        )
                        .unwrap_or_default();
                        if active_peer.is_none() {
                            let new_peer = Arc::new(ExtensionPeer {
                                browser_label: browser_label.clone(),
                                user_agent,
                                outbound: out_tx.clone(),
                                next_id: AtomicU64::new(1),
                                next_relay_id: AtomicU64::new(1),
                                pending: StdMutex::new(HashMap::new()),
                                event_subscribers: StdMutex::new(HashMap::new()),
                                initial_tabs: StdMutex::new(hello_tabs),
                                isolated_tabs: StdMutex::new(HashMap::new()),
                                tab_owners: StdMutex::new(HashMap::new()),
                                shutdown: peer_cancel.clone(),
                            });
                            let previous = self.peer.lock().await.replace(new_peer.clone());
                            if let Some(prev) = previous {
                                prev.shutdown.cancel();
                                prev.clear_pending();
                            }
                            if let Ok(mut info) = self.peer_info.lock() {
                                *info = Some((browser_label, new_peer.user_agent.clone()));
                            }
                            active_peer = Some(new_peer);
                        } else if let Some(peer) = &active_peer
                            && let Ok(mut initial) = peer.initial_tabs.lock()
                        {
                            *initial = hello_tabs;
                        }
                    } else if let Some(peer) = &active_peer {
                        peer.emit_event(event.to_owned(), params);
                    }
                }
            }
        }

        peer_cancel.cancel();
        let _ = writer_task.await;
        if let Some(peer) = active_peer {
            peer.clear_pending();
            let mut current = self.peer.lock().await;
            if current.as_ref().is_some_and(|p| Arc::ptr_eq(p, &peer)) {
                *current = None;
                if let Ok(mut info) = self.peer_info.lock() {
                    *info = None;
                }
            }
        }
    }

    async fn accept_ws_loop(self: Arc<Self>, listener: TcpListener) {
        loop {
            tokio::select! {
                () = self.cancel.cancelled() => break,
                accepted = listener.accept() => {
                    let Ok((stream, _addr)) = accepted else {
                        break;
                    };
                    let this = self.clone();
                    tokio::spawn(async move {
                        this.handle_ws_connection(stream).await;
                    });
                }
            }
        }
    }

    #[allow(clippy::result_large_err)]
    async fn handle_ws_connection(self: Arc<Self>, stream: TcpStream) {
        let selected_scope: Arc<StdMutex<Option<CdpSessionScope>>> = Arc::new(StdMutex::new(None));
        let selected_for_cb = selected_scope.clone();
        let ws = accept_hdr_async(
            stream,
            |req: &Request, res: Response| -> Result<Response, ErrorResponse> {
                let path = req.uri().path();
                let scope = self
                    .pending_ws_tokens
                    .lock()
                    .ok()
                    .and_then(|mut map| map.remove(path));
                if let Some(scope) = scope {
                    if let Ok(mut slot) = selected_for_cb.lock() {
                        *slot = Some(scope);
                    }
                    Ok(res)
                } else {
                    Err(http::Response::builder()
                        .status(http::StatusCode::NOT_FOUND)
                        .body(Some("not_found".to_owned()))
                        .expect("404 response"))
                }
            },
        )
        .await;
        let Ok(ws) = ws else {
            return;
        };
        let Some(scope) = selected_scope.lock().ok().and_then(|mut s| s.take()) else {
            return;
        };

        let Some(peer) = self.peer.lock().await.clone() else {
            return;
        };
        run_cdp_relay_session(ws, peer, self.cancel.clone(), scope).await;
    }
}

struct TabSession {
    session_id: String,
    target_info: Value,
    child_sessions: HashSet<String>,
}

type AttachWaiter = oneshot::Sender<Result<(String, Value), String>>;

struct RelayState {
    relay_id: u64,
    scope: CdpSessionScope,
    group_id: Option<i64>,
    owned_tabs: HashSet<i64>,
    peer: Arc<ExtensionPeer>,
    cdp_out: mpsc::UnboundedSender<String>,
    known_tabs: BTreeMap<i64, TabDescriptor>,
    tab_sessions: HashMap<i64, TabSession>,
    attaching: HashMap<i64, Vec<AttachWaiter>>,
    auto_attach: bool,
    next_session_seq: u64,
    temp_screencast_tabs: HashSet<i64>,
}

impl RelayState {
    fn emit_cdp(&self, msg: Value) {
        let _ = self.cdp_out.send(msg.to_string());
    }

    fn find_tab_by_session(&self, session_id: &str) -> Option<(i64, Option<String>)> {
        for (tab_id, ts) in &self.tab_sessions {
            if ts.session_id == session_id {
                return Some((*tab_id, None));
            }
            if ts.child_sessions.contains(session_id) {
                return Some((*tab_id, Some(session_id.to_owned())));
            }
        }
        None
    }

    fn find_tab_by_target(&self, target_id: &str) -> Option<i64> {
        for (tab_id, ts) in &self.tab_sessions {
            if ts.target_info.get("targetId").and_then(Value::as_str) == Some(target_id) {
                return Some(*tab_id);
            }
        }
        None
    }

    fn detach_tab(&mut self, tab_id: i64) -> bool {
        self.temp_screencast_tabs.remove(&tab_id);
        if let Some(ts) = self.tab_sessions.remove(&tab_id) {
            for child in ts.child_sessions {
                self.emit_cdp(json!({
                    "method": "Target.detachedFromTarget",
                    "params": { "sessionId": child }
                }));
            }
            self.emit_cdp(json!({
                "method": "Target.detachedFromTarget",
                "params": {
                    "sessionId": ts.session_id,
                    "targetId": ts.target_info.get("targetId").cloned().unwrap_or(Value::Null),
                }
            }));
            true
        } else {
            false
        }
    }
}

async fn attach_tab(
    state: &Arc<Mutex<RelayState>>,
    tab_id: i64,
) -> Result<(String, Value), String> {
    let (peer, relay_id, isolated, existing_waiter) = {
        let mut guard = state.lock().await;
        if let Some(existing) = guard.tab_sessions.get(&tab_id) {
            return Ok((existing.session_id.clone(), existing.target_info.clone()));
        }
        let isolated = matches!(guard.scope, CdpSessionScope::TabGroup { .. });
        if let Some(waiters) = guard.attaching.get_mut(&tab_id) {
            let (tx, rx) = oneshot::channel();
            waiters.push(tx);
            (guard.peer.clone(), guard.relay_id, isolated, Some(rx))
        } else {
            if !guard.peer.claim_tab(tab_id, guard.relay_id, isolated) {
                return Err("tab_owned_by_another_session".to_owned());
            }
            guard.attaching.insert(tab_id, Vec::new());
            (guard.peer.clone(), guard.relay_id, isolated, None)
        }
    };

    if let Some(rx) = existing_waiter {
        return rx.await.map_err(|_| "tab_attach_cancelled".to_owned())?;
    }

    let attach_res = async {
        peer.call("debugger.attach", json!({ "tabId": tab_id }))
            .await?;
        let info = peer
            .call(
                "debugger.sendCommand",
                json!({ "tabId": tab_id, "method": "Target.getTargetInfo" }),
            )
            .await?;
        let target_info = info.get("targetInfo").cloned().unwrap_or_else(|| json!({}));
        // Emulate focus on the attached tab so `active: false` background tabs
        // maintain an active visibilityState and requestAnimationFrame loop for
        // interactive Playwright actions without stealing Chrome OS window focus.
        let _ = peer
            .call(
                "debugger.sendCommand",
                json!({
                    "tabId": tab_id,
                    "method": "Emulation.setFocusEmulationEnabled",
                    "params": { "enabled": true }
                }),
            )
            .await;
        Ok::<Value, String>(target_info)
    }
    .await;

    let mut guard = state.lock().await;
    let waiters = guard.attaching.remove(&tab_id).unwrap_or_default();
    let outcome = match attach_res {
        Ok(target_info) => {
            if let Some(existing) = guard.tab_sessions.get(&tab_id) {
                Ok((existing.session_id.clone(), existing.target_info.clone()))
            } else {
                guard.owned_tabs.insert(tab_id);
                guard.next_session_seq += 1;
                let session_id = format!("pw-tab-{}-{}", guard.relay_id, guard.next_session_seq);
                let mut emitted_info = target_info.clone();
                if let Some(obj) = emitted_info.as_object_mut() {
                    obj.insert("attached".to_owned(), Value::Bool(true));
                }
                guard.tab_sessions.insert(
                    tab_id,
                    TabSession {
                        session_id: session_id.clone(),
                        target_info: target_info.clone(),
                        child_sessions: HashSet::new(),
                    },
                );
                guard.emit_cdp(json!({
                    "method": "Target.attachedToTarget",
                    "params": {
                        "sessionId": session_id,
                        "targetInfo": emitted_info,
                        "waitingForDebugger": false,
                    }
                }));
                Ok((session_id, target_info))
            }
        }
        Err(err) => {
            if !isolated || !guard.owned_tabs.contains(&tab_id) {
                peer.release_relay_tabs(relay_id, &[tab_id]);
            }
            Err(err)
        }
    };
    drop(guard);
    for waiter in waiters {
        let _ = waiter.send(outcome.clone());
    }
    outcome
}

async fn handle_cdp_request(
    state: &Arc<Mutex<RelayState>>,
    method: &str,
    params: Value,
    session_id: Option<&str>,
) -> Result<Value, String> {
    if session_id.is_none() {
        match method {
            "Browser.getVersion" => {
                let peer = state.lock().await.peer.clone();
                return Ok(json!({
                    "protocolVersion": "1.3",
                    "product": peer.browser_label,
                    "revision": "0",
                    "userAgent": peer.user_agent,
                    "jsVersion": "V8",
                }));
            }
            "Browser.setDownloadBehavior"
            | "Target.setDiscoverTargets"
            | "Target.activateTarget"
            | "Page.bringToFront" => {
                return Ok(json!({}));
            }
            "Target.getTargetInfo" => {
                return Ok(json!({}));
            }
            "Target.setAutoAttach" => {
                let (peer, relay_id, scope, existing_owned, fallback_ids) = {
                    let mut guard = state.lock().await;
                    guard.auto_attach = true;
                    (
                        guard.peer.clone(),
                        guard.relay_id,
                        guard.scope.clone(),
                        guard.owned_tabs.iter().copied().collect::<Vec<_>>(),
                        guard.known_tabs.keys().copied().collect::<Vec<_>>(),
                    )
                };
                match scope {
                    CdpSessionScope::TabGroup { title, color } => {
                        let tab_ids = if existing_owned.is_empty() {
                            let created = peer
                                .call(
                                    "tabs.create",
                                    json!({
                                        "url": "about:blank",
                                        "active": false,
                                        "isolated": true,
                                        "groupTitle": title,
                                        "groupColor": color,
                                    }),
                                )
                                .await?;
                            let tab: TabDescriptor = serde_json::from_value(
                                created.get("tab").cloned().unwrap_or_else(|| json!({})),
                            )
                            .map_err(|_| "tabs.create invalid response".to_owned())?;
                            let returned_gid = created
                                .get("groupId")
                                .and_then(Value::as_i64)
                                .unwrap_or(tab.group_id);
                            let mut guard = state.lock().await;
                            if guard.group_id.is_none() && returned_gid >= 0 {
                                guard.group_id = Some(returned_gid);
                            }
                            guard.owned_tabs.insert(tab.id);
                            guard.known_tabs.insert(tab.id, tab.clone());
                            guard.peer.claim_tab(tab.id, relay_id, true);
                            vec![tab.id]
                        } else {
                            existing_owned
                        };
                        for tab_id in tab_ids {
                            let _ = attach_tab(state, tab_id).await;
                        }
                    }
                    CdpSessionScope::SharedExisting => {
                        if let Ok(listed) = peer
                            .call("tabs.list", json!({ "excludeIsolated": true }))
                            .await
                            && let Ok(tabs) = serde_json::from_value::<Vec<TabDescriptor>>(
                                listed.get("tabs").cloned().unwrap_or_else(|| json!([])),
                            )
                        {
                            let mut guard = state.lock().await;
                            guard.known_tabs.clear();
                            for tab in tabs {
                                if !tab.isolated
                                    && peer.is_tab_available_for_shared(tab.id, relay_id)
                                {
                                    guard.known_tabs.insert(tab.id, tab);
                                }
                            }
                        }
                        let tab_ids: Vec<i64> = {
                            let guard = state.lock().await;
                            let ids: Vec<i64> = guard
                                .known_tabs
                                .keys()
                                .copied()
                                .filter(|id| peer.is_tab_available_for_shared(*id, relay_id))
                                .collect();
                            if ids.is_empty() {
                                fallback_ids
                                    .into_iter()
                                    .filter(|id| peer.is_tab_available_for_shared(*id, relay_id))
                                    .collect()
                            } else {
                                ids
                            }
                        };
                        for tab_id in tab_ids {
                            let _ = attach_tab(state, tab_id).await;
                        }
                    }
                }
                return Ok(json!({}));
            }
            "Target.createTarget" => {
                let url = params
                    .get("url")
                    .and_then(Value::as_str)
                    .filter(|u| !u.is_empty())
                    .unwrap_or("about:blank");
                let (peer, relay_id, scope, existing_group_id) = {
                    let guard = state.lock().await;
                    (
                        guard.peer.clone(),
                        guard.relay_id,
                        guard.scope.clone(),
                        guard.group_id,
                    )
                };
                let (is_isolated, create_params) = match scope {
                    CdpSessionScope::TabGroup { title, color } => {
                        let mut p = json!({
                            "url": url,
                            "active": false,
                            "isolated": true,
                        });
                        if let Some(gid) = existing_group_id.filter(|g| *g >= 0) {
                            p["groupId"] = json!(gid);
                        } else {
                            p["groupTitle"] = json!(title);
                            p["groupColor"] = json!(color);
                        }
                        (true, p)
                    }
                    CdpSessionScope::SharedExisting => {
                        let mut p = json!({
                            "url": url,
                            "active": false,
                            "isolated": false,
                        });
                        if let Some(gid) = existing_group_id.filter(|g| *g >= 0) {
                            p["groupId"] = json!(gid);
                        } else {
                            p["groupTitle"] = json!("Styx");
                            p["groupColor"] = json!("blue");
                        }
                        (false, p)
                    }
                };
                let created = peer.call("tabs.create", create_params).await?;
                let tab: TabDescriptor = serde_json::from_value(
                    created.get("tab").cloned().unwrap_or_else(|| json!({})),
                )
                .map_err(|_| "tabs.create invalid response".to_owned())?;
                let returned_gid = created
                    .get("groupId")
                    .and_then(Value::as_i64)
                    .unwrap_or(tab.group_id);
                {
                    let mut guard = state.lock().await;
                    if guard.group_id.is_none() && returned_gid >= 0 {
                        guard.group_id = Some(returned_gid);
                    }
                    guard.owned_tabs.insert(tab.id);
                    guard.known_tabs.insert(tab.id, tab.clone());
                    guard.peer.claim_tab(tab.id, relay_id, is_isolated);
                }
                let (_sid, target_info) = attach_tab(state, tab.id).await?;
                return Ok(json!({
                    "targetId": target_info.get("targetId").cloned().unwrap_or(Value::Null),
                }));
            }
            "Target.closeTarget" => {
                let target_id = params.get("targetId").and_then(Value::as_str);
                let (peer, relay_id, tab_id) = {
                    let guard = state.lock().await;
                    let found = target_id.and_then(|id| guard.find_tab_by_target(id));
                    (guard.peer.clone(), guard.relay_id, found)
                };
                let Some(tab_id) = tab_id else {
                    return Ok(json!({ "success": false }));
                };
                peer.call("tabs.remove", json!({ "tabId": tab_id })).await?;
                let mut guard = state.lock().await;
                guard.known_tabs.remove(&tab_id);
                guard.owned_tabs.remove(&tab_id);
                guard.detach_tab(tab_id);
                peer.release_relay_tabs(relay_id, &[tab_id]);
                return Ok(json!({ "success": true }));
            }
            "Target.getTargets" => {
                let guard = state.lock().await;
                let infos: Vec<Value> = guard
                    .tab_sessions
                    .values()
                    .map(|ts| {
                        let mut info = ts.target_info.clone();
                        if let Some(obj) = info.as_object_mut() {
                            obj.insert("attached".to_owned(), Value::Bool(true));
                        }
                        info
                    })
                    .collect();
                return Ok(json!({ "targetInfos": infos }));
            }
            _ => {
                let (peer, first_tab) = {
                    let guard = state.lock().await;
                    let first = guard.tab_sessions.keys().next().copied();
                    (guard.peer.clone(), first)
                };
                let Some(tab_id) = first_tab else {
                    return Err(format!(
                        "No attached tab to forward browser-level command: {method}"
                    ));
                };
                return peer
                    .call(
                        "debugger.sendCommand",
                        json!({ "tabId": tab_id, "method": method, "params": params }),
                    )
                    .await;
            }
        }
    }

    if method == "Page.bringToFront" {
        return Ok(json!({}));
    }

    let sid = session_id.expect("checked above");
    if method == "Target.getTargetInfo" {
        let guard = state.lock().await;
        for ts in guard.tab_sessions.values() {
            if ts.session_id == sid {
                return Ok(json!({ "targetInfo": ts.target_info }));
            }
        }
    }
    let (peer, target) = {
        let guard = state.lock().await;
        (guard.peer.clone(), guard.find_tab_by_session(sid))
    };
    let Some((tab_id, child_sid)) = target else {
        return Err(format!("No tab found for sessionId: {sid}"));
    };
    let is_top_level_screenshot = method == "Page.captureScreenshot" && child_sid.is_none();
    let mut rpc = json!({ "tabId": tab_id, "method": method, "params": params });
    if let Some(child) = child_sid
        && let Some(obj) = rpc.as_object_mut()
    {
        obj.insert("sessionId".to_owned(), Value::String(child));
    }
    if is_top_level_screenshot {
        // On `active: false` background tabs, Chromium pauses Viz surface readback
        // unless the WebContents has an active capturer. Briefly starting a minimal
        // screencast around the capture increments the capturer count (~250ms capture)
        // with zero ongoing overhead and without stealing tab or OS window focus.
        let started_screencast = peer
            .call(
                "debugger.sendCommand",
                json!({
                    "tabId": tab_id,
                    "method": "Page.startScreencast",
                    "params": {
                        "format": "jpeg",
                        "quality": 1,
                        "maxWidth": 16,
                        "maxHeight": 16,
                        "everyNthFrame": 100
                    }
                }),
            )
            .await
            .is_ok();
        if started_screencast {
            state.lock().await.temp_screencast_tabs.insert(tab_id);
        }
        let res = peer.call("debugger.sendCommand", rpc).await;
        if started_screencast {
            let _ = tokio::time::timeout(
                Duration::from_secs(1),
                peer.call(
                    "debugger.sendCommand",
                    json!({
                        "tabId": tab_id,
                        "method": "Page.stopScreencast",
                        "params": {}
                    }),
                ),
            )
            .await;
            state.lock().await.temp_screencast_tabs.remove(&tab_id);
        }
        return res;
    }
    peer.call("debugger.sendCommand", rpc).await
}

async fn handle_extension_event(
    state: &Arc<Mutex<RelayState>>,
    event: &str,
    params: Value,
    cancel: &CancellationToken,
) {
    match event {
        "chrome.debugger.onEvent" => {
            let Some(arr) = params.as_array() else { return };
            if arr.len() < 2 {
                return;
            }
            let source = &arr[0];
            let Some(cdp_method) = arr[1].as_str() else {
                return;
            };
            let cdp_params = arr.get(2).cloned().unwrap_or_else(|| json!({}));
            let Some(tab_id) = source.get("tabId").and_then(Value::as_i64) else {
                return;
            };
            let source_child = source.get("sessionId").and_then(Value::as_str);
            let mut guard = state.lock().await;
            if cdp_method == "Page.screencastFrame"
                && source_child.is_none()
                && guard.temp_screencast_tabs.contains(&tab_id)
            {
                return;
            }
            let Some(ts) = guard.tab_sessions.get_mut(&tab_id) else {
                return;
            };
            if cdp_method == "Target.attachedToTarget"
                && let Some(child) = cdp_params.get("sessionId").and_then(Value::as_str)
            {
                ts.child_sessions.insert(child.to_owned());
            } else if cdp_method == "Target.detachedFromTarget"
                && let Some(child) = cdp_params.get("sessionId").and_then(Value::as_str)
            {
                ts.child_sessions.remove(child);
            }
            let emit_sid = source_child.unwrap_or(ts.session_id.as_str()).to_owned();
            guard.emit_cdp(json!({
                "sessionId": emit_sid,
                "method": cdp_method,
                "params": cdp_params,
            }));
        }
        "chrome.debugger.onDetach" => {
            let Some(arr) = params.as_array() else { return };
            let source = arr.first();
            let reason = arr.get(1).and_then(Value::as_str);
            if let Some(tab_id) = source.and_then(|s| s.get("tabId")).and_then(Value::as_i64) {
                let mut guard = state.lock().await;
                let removed = guard.detach_tab(tab_id);
                let relay_id = guard.relay_id;
                let peer = guard.peer.clone();
                if removed {
                    guard.owned_tabs.remove(&tab_id);
                    peer.release_relay_tabs(relay_id, &[tab_id]);
                }
                drop(guard);
                if removed && reason == Some("canceled_by_user") {
                    cancel.cancel();
                }
            }
        }
        "chrome.tabs.onCreated" | "chrome.tabs.onUpdated" => {
            let Some(arr) = params.as_array() else { return };
            let Some(tab_val) = arr.first() else { return };
            let Ok(tab) = serde_json::from_value::<TabDescriptor>(tab_val.clone()) else {
                return;
            };
            let (should_attach, group_params) = {
                let mut guard = state.lock().await;
                let id = tab.id;
                let relay_id = guard.relay_id;
                let peer = guard.peer.clone();
                let scope = guard.scope.clone();
                match scope {
                    CdpSessionScope::TabGroup { title, color } => {
                        let by_owner = guard.owned_tabs.contains(&id);
                        let by_opener = tab
                            .opener_tab_id
                            .is_some_and(|op| guard.owned_tabs.contains(&op));
                        let by_group = guard.group_id.is_some_and(|g| g >= 0 && tab.group_id == g);
                        if !(by_owner || by_opener || by_group)
                            || !peer.claim_tab(id, relay_id, true)
                        {
                            (false, None)
                        } else {
                            guard.owned_tabs.insert(id);
                            let target_gid = guard.group_id;
                            let needs_grouping = (by_opener || by_owner)
                                && target_gid.is_some_and(|gid| gid >= 0 && tab.group_id != gid);
                            let group_cfg = needs_grouping.then(|| {
                                (
                                    peer,
                                    json!({
                                        "tabId": id,
                                        "groupId": target_gid,
                                        "groupTitle": title,
                                        "groupColor": color,
                                        "isolated": true,
                                    }),
                                )
                            });
                            guard.known_tabs.insert(id, tab);
                            let attach = guard.auto_attach
                                && !guard.tab_sessions.contains_key(&id)
                                && !guard.attaching.contains_key(&id);
                            (attach, group_cfg)
                        }
                    }
                    CdpSessionScope::SharedExisting => {
                        if tab.isolated || !peer.is_tab_available_for_shared(id, relay_id) {
                            (false, None)
                        } else {
                            guard.known_tabs.insert(id, tab);
                            let attach = guard.auto_attach
                                && !guard.tab_sessions.contains_key(&id)
                                && !guard.attaching.contains_key(&id);
                            (attach, None)
                        }
                    }
                }
            };
            if let Some((peer, rpc_params)) = group_params {
                tokio::spawn(async move {
                    let _ = peer.call("tabs.group", rpc_params).await;
                });
            }
            if should_attach {
                let cloned = state.clone();
                let id = tab_val
                    .get("id")
                    .and_then(Value::as_i64)
                    .unwrap_or_default();
                tokio::spawn(async move {
                    let _ = attach_tab(&cloned, id).await;
                });
            }
        }
        "chrome.tabs.onRemoved" => {
            let Some(arr) = params.as_array() else { return };
            if let Some(tab_id) = arr.first().and_then(Value::as_i64) {
                let mut guard = state.lock().await;
                guard.known_tabs.remove(&tab_id);
                let had_session = guard.detach_tab(tab_id);
                let had_owned = guard.owned_tabs.remove(&tab_id);
                if had_session || had_owned {
                    let relay_id = guard.relay_id;
                    guard.peer.release_relay_tabs(relay_id, &[tab_id]);
                }
            }
        }
        _ => {}
    }
}

async fn run_cdp_relay_session(
    ws: tokio_tungstenite::WebSocketStream<TcpStream>,
    peer: Arc<ExtensionPeer>,
    bridge_cancel: CancellationToken,
    scope: CdpSessionScope,
) {
    let (mut ws_sink, mut ws_stream) = ws.split();
    let (cdp_tx, mut cdp_rx) = mpsc::unbounded_channel::<String>();
    let (relay_id, mut ev_rx) = peer.subscribe_events();
    let session_cancel = bridge_cancel.child_token();

    let mut initial_known = BTreeMap::new();
    if scope == CdpSessionScope::SharedExisting {
        for tab in peer.snapshot_initial_tabs() {
            if !tab.isolated && peer.is_tab_available_for_shared(tab.id, relay_id) {
                initial_known.insert(tab.id, tab);
            }
        }
    }

    let state = Arc::new(Mutex::new(RelayState {
        relay_id,
        scope,
        group_id: None,
        owned_tabs: HashSet::new(),
        peer: peer.clone(),
        cdp_out: cdp_tx.clone(),
        known_tabs: initial_known,
        tab_sessions: HashMap::new(),
        attaching: HashMap::new(),
        auto_attach: false,
        next_session_seq: 0,
        temp_screencast_tabs: HashSet::new(),
    }));

    let writer_cancel = session_cancel.clone();
    let ws_writer = tokio::spawn(async move {
        loop {
            tokio::select! {
                () = writer_cancel.cancelled() => break,
                msg = cdp_rx.recv() => {
                    let Some(text) = msg else { break };
                    if ws_sink.send(Message::Text(text.into())).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = ws_sink.close().await;
    });

    let event_state = state.clone();
    let event_cancel = session_cancel.clone();
    let event_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                () = event_cancel.cancelled() => break,
                ev = ev_rx.recv() => {
                    let Some((event, params)) = ev else { break };
                    handle_extension_event(&event_state, &event, params, &event_cancel).await;
                }
            }
        }
    });

    loop {
        tokio::select! {
            () = session_cancel.cancelled() => break,
            () = peer.shutdown.cancelled() => break,
            frame = ws_stream.next() => {
                match frame {
                    Some(Ok(Message::Text(text))) => {
                        let Ok(req) = serde_json::from_str::<Value>(&text) else {
                            continue;
                        };
                        let id = req.get("id").cloned();
                        let Some(method) = req.get("method").and_then(Value::as_str).map(ToOwned::to_owned) else {
                            continue;
                        };
                        let params = req.get("params").cloned().unwrap_or_else(|| json!({}));
                        let session_id = req.get("sessionId").and_then(Value::as_str).map(ToOwned::to_owned);
                        let req_state = state.clone();
                        let req_out = cdp_tx.clone();
                        tokio::spawn(async move {
                            let res = handle_cdp_request(&req_state, &method, params, session_id.as_deref()).await;
                            let mut reply = match res {
                                Ok(result) => json!({ "id": id, "result": result }),
                                Err(message) => json!({ "id": id, "error": { "message": message } }),
                            };
                            if let Some(sid) = session_id
                                && let Some(obj) = reply.as_object_mut()
                            {
                                obj.insert("sessionId".to_owned(), Value::String(sid));
                            }
                            let _ = req_out.send(reply.to_string());
                        });
                    }
                    Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => {}
                    _ => break,
                }
            }
        }
    }

    session_cancel.cancel();
    peer.unsubscribe_events(relay_id);
    let (attached_tabs, release_tabs) = {
        let mut guard = state.lock().await;
        let attached: Vec<i64> = guard.tab_sessions.keys().copied().collect();
        let mut release = attached.clone();
        for id in guard.owned_tabs.drain() {
            if !release.contains(&id) {
                release.push(id);
            }
        }
        guard.tab_sessions.clear();
        (attached, release)
    };
    peer.release_relay_tabs(relay_id, &release_tabs);
    for tab_id in attached_tabs {
        let _ = tokio::time::timeout(
            Duration::from_secs(1),
            peer.call(
                "debugger.sendCommand",
                json!({
                    "tabId": tab_id,
                    "method": "Emulation.setFocusEmulationEnabled",
                    "params": { "enabled": false }
                }),
            ),
        )
        .await;
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            peer.call("debugger.detach", json!({ "tabId": tab_id })),
        )
        .await;
    }
    let _ = ws_writer.await;
    let _ = event_task.await;
}
