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
const DEFAULT_INDICATOR_IDLE_TIMEOUT_MS: u64 = 3_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CdpSessionScope {
    SharedExisting,
    TabGroup {
        title: String,
        color: String,
        session_key: Option<String>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TabGroupParkOutcome {
    Collapsed,
    Removed,
    Missing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TabGroupCloseOutcome {
    Closed,
    SkippedActive,
    NotFound,
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
    tab_group_ids: StdMutex<HashMap<String, i64>>,
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
        }
        if let Ok(mut iso) = self.isolated_tabs.lock() {
            for tab_id in tab_ids {
                if iso.get(tab_id) == Some(&relay_id) {
                    iso.remove(tab_id);
                }
            }
        }
    }

    fn release_all_for_relay(&self, relay_id: u64) {
        if let Ok(mut owners) = self.tab_owners.lock() {
            owners.retain(|_, &mut owner| owner != relay_id);
        }
        if let Ok(mut iso) = self.isolated_tabs.lock() {
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

    fn remembered_tab_group_id(&self, key: &str) -> Option<i64> {
        self.tab_group_ids
            .lock()
            .ok()
            .and_then(|guard| guard.get(key).copied())
            .filter(|gid| *gid >= 0)
    }

    fn remember_tab_group_id(&self, key: &str, group_id: i64) {
        if group_id < 0 {
            return;
        }
        if let Ok(mut guard) = self.tab_group_ids.lock() {
            guard.insert(key.to_owned(), group_id);
        }
    }

    fn forget_tab_group_id(&self, key: &str) {
        if let Ok(mut guard) = self.tab_group_ids.lock() {
            guard.remove(key);
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
    next_external_group_seq: AtomicU64,
    indicator_idle_ms: AtomicU64,
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
            next_external_group_seq: AtomicU64::new(1),
            indicator_idle_ms: AtomicU64::new(DEFAULT_INDICATOR_IDLE_TIMEOUT_MS),
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
        self.open_cdp_session_with_details(scope)
            .map(|(ws_endpoint, _)| ws_endpoint)
    }

    /// Mints a single-use loopback CDP WebSocket endpoint and matching HTTP `/cdp/<id>`
    /// discovery base URL bound to a specific tab scope.
    pub fn open_cdp_session_with_details(
        &self,
        scope: CdpSessionScope,
    ) -> Result<(String, String), ErrorCategory> {
        if !self.is_connected() {
            return Err(ErrorCategory::CapabilityUnsupported);
        }
        let id = uuid::Uuid::new_v4().to_string();
        let path = format!("/devtools/browser/{id}");
        self.pending_ws_tokens
            .lock()
            .map_err(|_| ErrorCategory::ResultUnknown)?
            .insert(path.clone(), scope);
        Ok((
            format!("ws://127.0.0.1:{}{}", self.ws_port, path),
            format!("http://127.0.0.1:{}/cdp/{id}", self.ws_port),
        ))
    }

    fn next_auto_tab_group_scope(
        &self,
        title: Option<String>,
        color: Option<String>,
        session_key: Option<String>,
    ) -> CdpSessionScope {
        const PALETTE: [&str; 6] = ["cyan", "purple", "green", "orange", "pink", "blue"];
        let seq = self.next_external_group_seq.fetch_add(1, Ordering::Relaxed);
        let chosen_color = color
            .as_deref()
            .map(str::trim)
            .and_then(|c| {
                let lower = c.to_ascii_lowercase();
                PALETTE
                    .iter()
                    .find(|&&allowed| allowed == lower)
                    .copied()
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| PALETTE[((seq - 1) as usize) % PALETTE.len()].to_owned());
        let chosen_title = title
            .as_deref()
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(|t| t.chars().take(48).collect::<String>())
            .unwrap_or_else(|| format!("Styx · {seq}"));
        CdpSessionScope::TabGroup {
            title: chosen_title,
            color: chosen_color,
            session_key,
        }
    }

    pub async fn park_tab_group(&self, session_key: &str) -> TabGroupParkOutcome {
        let Some(peer) = self.peer.lock().await.clone() else {
            return TabGroupParkOutcome::Missing;
        };
        let Some(gid) = peer.remembered_tab_group_id(session_key) else {
            return TabGroupParkOutcome::Missing;
        };
        let Ok(Ok(listed)) = tokio::time::timeout(
            Duration::from_secs(3),
            peer.call("tabs.list", json!({ "excludeIsolated": false })),
        )
        .await
        else {
            return TabGroupParkOutcome::Missing;
        };
        let Ok(tabs) = serde_json::from_value::<Vec<TabDescriptor>>(
            listed.get("tabs").cloned().unwrap_or_else(|| json!([])),
        ) else {
            return TabGroupParkOutcome::Missing;
        };
        let group_tabs: Vec<TabDescriptor> =
            tabs.into_iter().filter(|t| t.group_id == gid).collect();
        if group_tabs.is_empty() {
            peer.forget_tab_group_id(session_key);
            return TabGroupParkOutcome::Removed;
        }
        let any_active = group_tabs.iter().any(|t| t.active);
        let all_blank = group_tabs
            .iter()
            .all(|t| t.url.is_empty() || t.url == "about:blank");
        if all_blank && !any_active {
            for tab in group_tabs {
                let _ = tokio::time::timeout(
                    Duration::from_secs(3),
                    peer.call("tabs.remove", json!({ "tabId": tab.id })),
                )
                .await;
            }
            peer.forget_tab_group_id(session_key);
            return TabGroupParkOutcome::Removed;
        }
        if !any_active {
            let _ = tokio::time::timeout(
                Duration::from_secs(3),
                peer.call(
                    "tabGroups.collapse",
                    json!({ "groupId": gid, "collapsed": true }),
                ),
            )
            .await;
        }
        TabGroupParkOutcome::Collapsed
    }

    pub async fn close_tab_group(
        &self,
        session_key: &str,
        skip_if_active: bool,
    ) -> TabGroupCloseOutcome {
        let Some(peer) = self.peer.lock().await.clone() else {
            return TabGroupCloseOutcome::NotFound;
        };
        let Some(gid) = peer.remembered_tab_group_id(session_key) else {
            return TabGroupCloseOutcome::NotFound;
        };
        let Ok(Ok(listed)) = tokio::time::timeout(
            Duration::from_secs(3),
            peer.call("tabs.list", json!({ "excludeIsolated": false })),
        )
        .await
        else {
            return TabGroupCloseOutcome::NotFound;
        };
        let Ok(tabs) = serde_json::from_value::<Vec<TabDescriptor>>(
            listed.get("tabs").cloned().unwrap_or_else(|| json!([])),
        ) else {
            return TabGroupCloseOutcome::NotFound;
        };
        let group_tabs: Vec<TabDescriptor> =
            tabs.into_iter().filter(|t| t.group_id == gid).collect();
        if group_tabs.is_empty() {
            peer.forget_tab_group_id(session_key);
            return TabGroupCloseOutcome::NotFound;
        }
        if skip_if_active && group_tabs.iter().any(|t| t.active) {
            return TabGroupCloseOutcome::SkippedActive;
        }
        for tab in group_tabs {
            let _ = tokio::time::timeout(
                Duration::from_secs(3),
                peer.call("tabs.remove", json!({ "tabId": tab.id })),
            )
            .await;
        }
        peer.forget_tab_group_id(session_key);
        TabGroupCloseOutcome::Closed
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
        if auth.get("token").and_then(Value::as_str) != Some(self.token.as_str()) {
            return;
        }
        match auth.get("type").and_then(Value::as_str) {
            Some("auth") => {}
            Some("open_cdp_session") => {
                let mode = auth
                    .get("mode")
                    .and_then(Value::as_str)
                    .unwrap_or("tab_group");
                let scope = if mode == "shared_existing" {
                    CdpSessionScope::SharedExisting
                } else {
                    let title = auth
                        .get("groupTitle")
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                    let color = auth
                        .get("groupColor")
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                    let session_key = auth
                        .get("sessionKey")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(|s| s.chars().take(64).collect::<String>());
                    self.next_auto_tab_group_scope(title, color, session_key)
                };
                let reply = match self.open_cdp_session_with_details(scope) {
                    Ok((ws_endpoint, http_base_url)) => json!({
                        "type": "cdp_session_ok",
                        "wsEndpoint": ws_endpoint,
                        "httpBaseUrl": http_base_url,
                        "browser": self.browser_label(),
                    }),
                    Err(_) => json!({
                        "type": "cdp_session_error",
                        "error": "extension_not_connected",
                    }),
                };
                let line = format!("{reply}\n");
                let _ = write_half.write_all(line.as_bytes()).await;
                let _ = write_half.flush().await;
                return;
            }
            _ => return,
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
                                tab_group_ids: StdMutex::new(HashMap::new()),
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

    async fn handle_http_discovery(self: Arc<Self>, mut stream: TcpStream) {
        use tokio::io::AsyncReadExt;

        let mut req_buf = Vec::with_capacity(1024);
        let mut chunk = [0_u8; 1024];
        loop {
            let Ok(Ok(n)) =
                tokio::time::timeout(Duration::from_secs(3), stream.read(&mut chunk)).await
            else {
                return;
            };
            if n == 0 {
                break;
            }
            req_buf.extend_from_slice(&chunk[..n]);
            if req_buf.windows(4).any(|w| w == b"\r\n\r\n") || req_buf.len() >= 8192 {
                break;
            }
        }
        let req_text = String::from_utf8_lossy(&req_buf);
        let mut parts = req_text
            .lines()
            .next()
            .unwrap_or_default()
            .split_whitespace();
        let method = parts.next().unwrap_or_default();
        let raw_target = parts.next().unwrap_or_default();
        let path = raw_target.split('?').next().unwrap_or_default();

        let write_json_response = |status: &str, body: &str| -> Vec<u8> {
            format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .into_bytes()
        };

        if method != "GET" {
            let resp = write_json_response(
                "405 Method Not Allowed",
                r#"{"error":"method_not_allowed"}"#,
            );
            let _ = stream.write_all(&resp).await;
            let _ = stream.flush().await;
            return;
        }

        let matched = path.strip_prefix("/cdp/").and_then(|rest| {
            if let Some(id) = rest.strip_suffix("/json/version") {
                Some((id, true))
            } else if let Some(id) = rest.strip_suffix("/json/list") {
                Some((id, false))
            } else {
                rest.strip_suffix("/json").map(|id| (id, false))
            }
        });

        let Some((id, is_version)) = matched.filter(|(id, _)| {
            !id.is_empty()
                && id != &"."
                && id != &".."
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        }) else {
            let resp = write_json_response("404 Not Found", r#"{"error":"not_found"}"#);
            let _ = stream.write_all(&resp).await;
            let _ = stream.flush().await;
            return;
        };

        let ws_path = format!("/devtools/browser/{id}");
        let token_exists = self
            .pending_ws_tokens
            .lock()
            .ok()
            .is_some_and(|map| map.contains_key(&ws_path));
        if !token_exists {
            let resp = write_json_response("404 Not Found", r#"{"error":"not_found"}"#);
            let _ = stream.write_all(&resp).await;
            let _ = stream.flush().await;
            return;
        }

        let peer_info = self.peer_info.lock().ok().and_then(|info| info.clone());
        let Some((browser_label, user_agent)) = peer_info else {
            let resp = write_json_response(
                "503 Service Unavailable",
                r#"{"error":"extension_not_connected"}"#,
            );
            let _ = stream.write_all(&resp).await;
            let _ = stream.flush().await;
            return;
        };

        let body = if is_version {
            json!({
                "Browser": browser_label,
                "Protocol-Version": "1.3",
                "User-Agent": user_agent,
                "V8-Version": "V8",
                "WebKit-Version": "537.36",
                "webSocketDebuggerUrl": format!("ws://127.0.0.1:{}{}", self.ws_port, ws_path),
            })
            .to_string()
        } else {
            "[]".to_owned()
        };
        let resp = write_json_response("200 OK", &body);
        let _ = stream.write_all(&resp).await;
        let _ = stream.flush().await;
    }

    #[allow(clippy::result_large_err)]
    async fn handle_ws_connection(self: Arc<Self>, stream: TcpStream) {
        let mut peek_buf = [0_u8; 4096];
        let Ok(Ok(peek_len)) =
            tokio::time::timeout(Duration::from_secs(3), stream.peek(&mut peek_buf)).await
        else {
            return;
        };
        if peek_len == 0 {
            return;
        }
        let preview = String::from_utf8_lossy(&peek_buf[..peek_len]);
        let is_ws_upgrade = preview.lines().any(|line| {
            line.split_once(':').is_some_and(|(name, val)| {
                name.trim().eq_ignore_ascii_case("upgrade")
                    && val.to_ascii_lowercase().contains("websocket")
            })
        });
        if !is_ws_upgrade {
            self.handle_http_discovery(stream).await;
            return;
        }

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
        let idle_timeout = Duration::from_millis(self.indicator_idle_ms.load(Ordering::Relaxed));
        run_cdp_relay_session(ws, peer, self.cancel.clone(), scope, idle_timeout).await;
    }

    #[cfg(test)]
    pub(crate) fn set_indicator_idle_timeout_for_test(&self, duration: Duration) {
        self.indicator_idle_ms
            .store(duration.as_millis() as u64, Ordering::Relaxed);
    }
}

const FAVICON_WORLD_NAME: &str = "styx_favicon_indicator";

pub(crate) fn favicon_accent_hex(scope: &CdpSessionScope) -> &'static str {
    match scope {
        CdpSessionScope::TabGroup { color, .. } => match color.as_str() {
            "cyan" => "#0097A7",
            "purple" => "#9334E6",
            "green" => "#188038",
            "orange" => "#E37400",
            "pink" => "#D01884",
            _ => "#1A73E8",
        },
        CdpSessionScope::SharedExisting => "#1A73E8",
    }
}

pub(crate) fn favicon_install_script(accent_hex: &str) -> String {
    let color_json = serde_json::to_string(accent_hex).unwrap_or_else(|_| "\"#1A73E8\"".to_owned());
    format!(
        r##"(() => {{
  const COLOR = {color_json};
  const CLEANUP_KEY = '__styxFaviconCleanup';
  const ACTIVE_KEY = '__styxIndicatorSetActive';
  const MOVE_KEY = '__styxCursorMove';
  const HIDDEN_KEY = '__styxCursorSetHidden';
  if (typeof globalThis[CLEANUP_KEY] === 'function') {{
    try {{ globalThis[CLEANUP_KEY](); }} catch {{}}
  }}

  const faviconSvg = 'data:image/svg+xml,' + encodeURIComponent(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">' +
    '<defs><radialGradient id="g" cx="52%" cy="52%" r="48%">' +
    '<stop offset="0%" stop-color="' + COLOR + '" stop-opacity="0.92"/>' +
    '<stop offset="55%" stop-color="' + COLOR + '" stop-opacity="0.45"/>' +
    '<stop offset="100%" stop-color="' + COLOR + '" stop-opacity="0"/>' +
    '</radialGradient></defs>' +
    '<circle cx="34" cy="34" r="30" fill="url(#g)"/>' +
    '<path d="M12 8 L54 25 L35 34 L25 54 Z" fill="#0B0F19" stroke="#FFFFFF" stroke-width="5" stroke-linejoin="round"/>' +
    '</svg>'
  );

  let active = false;
  let observer = null;
  let applying = false;
  let readyListener = null;
  let cursorHost = null;
  let cursorWrap = null;
  let cursorRing = null;

  function ensureStyxLink(head) {{
    let badge = head.querySelector('link[data-styx-favicon="1"]');
    if (!badge) {{
      badge = document.createElement('link');
      badge.setAttribute('data-styx-favicon', '1');
      head.appendChild(badge);
    }}
    badge.setAttribute('rel', 'icon');
    badge.setAttribute('type', 'image/svg+xml');
    badge.setAttribute('href', faviconSvg);
  }}

  function restoreHeadIcons() {{
    const head = document.head;
    if (!head) return;
    applying = true;
    try {{
      for (const el of head.querySelectorAll('link[data-styx-favicon="1"]')) el.remove();
      for (const el of head.querySelectorAll('link[data-styx-orig-rel]')) {{
        const origRel = el.getAttribute('data-styx-orig-rel');
        if (origRel) el.setAttribute('rel', origRel);
        el.removeAttribute('data-styx-orig-rel');
      }}
    }} finally {{
      applying = false;
    }}
  }}

  function applyFavicon() {{
    if (!active) return;
    const head = document.head;
    if (!head || applying) return;
    applying = true;
    try {{
      const origLinks = Array.from(head.querySelectorAll('link[rel]')).filter(el => {{
        if (el.dataset && el.dataset.styxFavicon === '1') return false;
        const rel = (el.getAttribute('rel') || '').toLowerCase().split(/\s+/);
        return rel.includes('icon');
      }});
      for (const el of origLinks) {{
        const curRel = el.getAttribute('rel');
        if (curRel && !el.hasAttribute('data-styx-orig-rel')) {{
          el.setAttribute('data-styx-orig-rel', curRel);
        }}
        el.removeAttribute('rel');
      }}
      ensureStyxLink(head);
    }} finally {{
      applying = false;
    }}
    if (!observer && typeof MutationObserver === 'function') {{
      observer = new MutationObserver(() => {{
        if (active && !applying) applyFavicon();
      }});
      observer.observe(head, {{ childList: true, attributes: true, attributeFilter: ['href', 'rel'] }});
    }}
  }}

  function ensureCursor() {{
    if (cursorHost && cursorHost.isConnected) return cursorWrap;
    const root = document.documentElement;
    if (!root) return null;
    for (const stale of root.querySelectorAll('[data-styx-cursor="1"]')) {{
      if (stale !== cursorHost) stale.remove();
    }}
    cursorHost = document.createElement('div');
    cursorHost.setAttribute('data-styx-cursor', '1');
    cursorHost.setAttribute('aria-hidden', 'true');
    cursorHost.style.cssText =
      'position:fixed;inset:0;width:0;height:0;overflow:visible;pointer-events:none;z-index:2147483647;display:block;';
    const shadow = cursorHost.attachShadow({{ mode: 'closed' }});
    const style = document.createElement('style');
    style.textContent =
      ':host {{ all: initial; }}' +
      '.c {{ position:fixed;left:0;top:0;width:0;height:0;pointer-events:none;opacity:0;' +
      'transform:translate3d(-120px,-120px,0);' +
      'transition:transform 110ms cubic-bezier(0.22,1,0.36,1),opacity 160ms ease;' +
      'will-change:transform,opacity; }}' +
      '.c.v {{ opacity:1; }}' +
      '.c.h {{ opacity:0 !important;transition:none !important; }}' +
      '.glow {{ position:absolute;left:-27px;top:-27px;width:54px;height:54px;border-radius:50%;' +
      'background:radial-gradient(circle,' + COLOR + '77 0%,' + COLOR + '22 45%,transparent 72%); }}' +
      '.ring {{ position:absolute;left:-14px;top:-14px;width:28px;height:28px;border-radius:50%;' +
      'border:2px solid ' + COLOR + ';opacity:0;transform:scale(0.35); }}' +
      '.ring.pop {{ animation:styx-ring 340ms cubic-bezier(0.22,1,0.36,1) forwards; }}' +
      '@keyframes styx-ring {{ 0% {{ opacity:0.95;transform:scale(0.35); }} 100% {{ opacity:0;transform:scale(1.55); }} }}' +
      '.a {{ position:relative;margin-left:-4.875px;margin-top:-3.25px;width:26px;height:26px;' +
      'transition:transform 80ms ease;transform-origin:4.875px 3.25px; }}' +
      '.c.d .a {{ transform:scale(0.86); }}' +
      'svg {{ display:block;width:26px;height:26px;overflow:visible;' +
      'filter:drop-shadow(0 0 7px ' + COLOR + ') drop-shadow(0 2px 5px rgba(0,0,0,0.55)); }}';
    cursorWrap = document.createElement('div');
    cursorWrap.className = 'c';
    const glow = document.createElement('div');
    glow.className = 'glow';
    cursorRing = document.createElement('div');
    cursorRing.className = 'ring';
    const arrow = document.createElement('div');
    arrow.className = 'a';
    arrow.innerHTML =
      '<svg xmlns="http://www.w3.org/2000/svg" width="26" height="26" viewBox="0 0 64 64">' +
      '<path d="M12 8 L54 25 L35 34 L25 54 Z" fill="#0B0F19" stroke="#FFFFFF" stroke-width="4.5" stroke-linejoin="round"/>' +
      '</svg>';
    cursorWrap.append(glow, cursorRing, arrow);
    shadow.append(style, cursorWrap);
    root.appendChild(cursorHost);
    return cursorWrap;
  }}

  function setActive(nextActive) {{
    active = Boolean(nextActive);
    if (active) {{
      if (document.head) {{
        applyFavicon();
      }} else if (!readyListener) {{
        readyListener = () => {{
          readyListener = null;
          if (active) applyFavicon();
        }};
        document.addEventListener('DOMContentLoaded', readyListener, {{ once: true }});
      }}
      if (document.documentElement) ensureCursor();
    }} else {{
      if (readyListener) {{
        document.removeEventListener('DOMContentLoaded', readyListener);
        readyListener = null;
      }}
      if (observer) {{
        observer.disconnect();
        observer = null;
      }}
      restoreHeadIcons();
      if (cursorWrap) {{
        cursorWrap.classList.remove('v');
        cursorWrap.classList.remove('d');
      }}
    }}
  }}

  globalThis[ACTIVE_KEY] = setActive;

  globalThis[MOVE_KEY] = (x, y, state) => {{
    if (!active) setActive(true);
    const wrap = ensureCursor();
    if (!wrap) return;
    if (typeof x === 'number' && typeof y === 'number' && Number.isFinite(x) && Number.isFinite(y)) {{
      wrap.style.transform = 'translate3d(' + x + 'px,' + y + 'px,0)';
    }}
    wrap.classList.add('v');
    if (state === 'down') {{
      wrap.classList.add('d');
      if (cursorRing) {{
        cursorRing.classList.remove('pop');
        void cursorRing.offsetWidth;
        cursorRing.classList.add('pop');
      }}
    }} else if (state === 'up') {{
      wrap.classList.remove('d');
    }}
  }};

  globalThis[HIDDEN_KEY] = (hidden) => {{
    const wrap = cursorWrap;
    if (!wrap) return;
    if (hidden) wrap.classList.add('h');
    else wrap.classList.remove('h');
  }};

  function cleanup() {{
    setActive(false);
    if (cursorHost) {{
      cursorHost.remove();
      cursorHost = null;
      cursorWrap = null;
      cursorRing = null;
    }}
    const root = document.documentElement;
    if (root) {{
      for (const el of root.querySelectorAll('[data-styx-cursor="1"]')) el.remove();
    }}
    if (globalThis[CLEANUP_KEY] === cleanup) delete globalThis[CLEANUP_KEY];
    delete globalThis[ACTIVE_KEY];
    delete globalThis[MOVE_KEY];
    delete globalThis[HIDDEN_KEY];
  }}

  globalThis[CLEANUP_KEY] = cleanup;
}})()"##
    )
}

const FAVICON_RESTORE_SCRIPT: &str = r#"(() => {
  const fn = globalThis.__styxFaviconCleanup;
  if (typeof fn === 'function') {
    try { fn(); } catch {}
  }
  const head = document.head;
  if (head) {
    for (const el of head.querySelectorAll('link[data-styx-favicon="1"]')) el.remove();
    for (const el of head.querySelectorAll('link[data-styx-orig-rel]')) {
      const origRel = el.getAttribute('data-styx-orig-rel');
      if (origRel) el.setAttribute('rel', origRel);
      el.removeAttribute('data-styx-orig-rel');
    }
  }
  const root = document.documentElement;
  if (root) {
    for (const el of root.querySelectorAll('[data-styx-cursor="1"]')) el.remove();
  }
  delete globalThis.__styxIndicatorSetActive;
  delete globalThis.__styxCursorMove;
  delete globalThis.__styxCursorSetHidden;
})()"#;

async fn eval_in_favicon_world(
    peer: &Arc<ExtensionPeer>,
    tab_id: i64,
    cached_context_id: Option<i64>,
    fallback_frame_id: Option<&str>,
    script: &str,
) -> Option<i64> {
    if let Some(cid) = cached_context_id
        && let Ok(Ok(res)) = tokio::time::timeout(
            Duration::from_secs(1),
            peer.call(
                "debugger.sendCommand",
                json!({
                    "tabId": tab_id,
                    "method": "Runtime.evaluate",
                    "params": {
                        "expression": script,
                        "contextId": cid,
                        "silent": true,
                    }
                }),
            ),
        )
        .await
        && res.get("exceptionDetails").is_none()
    {
        return Some(cid);
    }

    let frame_id = match tokio::time::timeout(
        Duration::from_secs(1),
        peer.call(
            "debugger.sendCommand",
            json!({ "tabId": tab_id, "method": "Page.getFrameTree", "params": {} }),
        ),
    )
    .await
    {
        Ok(Ok(tree)) => tree
            .pointer("/frameTree/frame/id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| fallback_frame_id.map(str::to_owned)),
        _ => fallback_frame_id.map(str::to_owned),
    };
    let frame_id = frame_id?;
    let Ok(Ok(world)) = tokio::time::timeout(
        Duration::from_secs(1),
        peer.call(
            "debugger.sendCommand",
            json!({
                "tabId": tab_id,
                "method": "Page.createIsolatedWorld",
                "params": {
                    "frameId": frame_id,
                    "worldName": FAVICON_WORLD_NAME,
                }
            }),
        ),
    )
    .await
    else {
        return None;
    };
    let context_id = world.get("executionContextId").and_then(Value::as_i64)?;
    let _ = tokio::time::timeout(
        Duration::from_secs(1),
        peer.call(
            "debugger.sendCommand",
            json!({
                "tabId": tab_id,
                "method": "Runtime.evaluate",
                "params": {
                    "expression": script,
                    "contextId": context_id,
                    "silent": true,
                }
            }),
        ),
    )
    .await;
    Some(context_id)
}

async fn install_favicon_indicator(
    peer: &Arc<ExtensionPeer>,
    tab_id: i64,
    target_info: &Value,
    accent_hex: &str,
) -> (Option<String>, Option<i64>) {
    let install_js = favicon_install_script(accent_hex);
    let script_id = tokio::time::timeout(
        Duration::from_secs(1),
        peer.call(
            "debugger.sendCommand",
            json!({
                "tabId": tab_id,
                "method": "Page.addScriptToEvaluateOnNewDocument",
                "params": {
                    "source": &install_js,
                    "worldName": FAVICON_WORLD_NAME,
                }
            }),
        ),
    )
    .await
    .ok()
    .and_then(Result::ok)
    .and_then(|res| {
        res.get("identifier")
            .and_then(Value::as_str)
            .map(str::to_owned)
    });
    let fallback_frame_id = target_info.get("targetId").and_then(Value::as_str);
    let context_id =
        eval_in_favicon_world(peer, tab_id, None, fallback_frame_id, &install_js).await;
    (script_id, context_id)
}

async fn restore_favicon_indicator(
    peer: &Arc<ExtensionPeer>,
    tab_id: i64,
    script_id: Option<&str>,
    cached_context_id: Option<i64>,
    fallback_frame_id: Option<&str>,
) {
    if let Some(identifier) = script_id {
        let _ = tokio::time::timeout(
            Duration::from_secs(1),
            peer.call(
                "debugger.sendCommand",
                json!({
                    "tabId": tab_id,
                    "method": "Page.removeScriptToEvaluateOnNewDocument",
                    "params": { "identifier": identifier }
                }),
            ),
        )
        .await;
    }
    let _ = eval_in_favicon_world(
        peer,
        tab_id,
        cached_context_id,
        fallback_frame_id,
        FAVICON_RESTORE_SCRIPT,
    )
    .await;
}

async fn detach_and_cleanup_tab(
    peer: &Arc<ExtensionPeer>,
    tab_id: i64,
    favicon_script_id: Option<&str>,
    cached_context_id: Option<i64>,
    target_id: Option<&str>,
    indicator_installed: bool,
    focus_emulated: bool,
) {
    if indicator_installed || favicon_script_id.is_some() || cached_context_id.is_some() {
        restore_favicon_indicator(
            peer,
            tab_id,
            favicon_script_id,
            cached_context_id,
            target_id,
        )
        .await;
    }
    if focus_emulated {
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
    }
    let _ = tokio::time::timeout(
        Duration::from_secs(2),
        peer.call("debugger.detach", json!({ "tabId": tab_id })),
    )
    .await;
}

async fn eval_tab_indicator(state: &Arc<Mutex<RelayState>>, tab_id: i64, script: &str) {
    let (peer, cached_ctx, fallback_frame_id) = {
        let guard = state.lock().await;
        let Some(ts) = guard.tab_sessions.get(&tab_id) else {
            return;
        };
        (
            guard.peer.clone(),
            ts.indicator_context_id,
            ts.target_info
                .get("targetId")
                .and_then(Value::as_str)
                .map(str::to_owned),
        )
    };
    let new_ctx = eval_in_favicon_world(
        &peer,
        tab_id,
        cached_ctx,
        fallback_frame_id.as_deref(),
        script,
    )
    .await;
    if let Some(cid) = new_ctx
        && cached_ctx != Some(cid)
        && let Some(ts) = state.lock().await.tab_sessions.get_mut(&tab_id)
    {
        ts.indicator_context_id = Some(cid);
    }
}

fn is_active_control_cdp_method(method: &str) -> bool {
    method.starts_with("Input.")
        || matches!(
            method,
            "Page.navigate"
                | "Page.reload"
                | "Page.navigateToHistoryEntry"
                | "Page.captureScreenshot"
                | "Page.printToPDF"
                | "Page.handleJavaScriptDialog"
                | "Runtime.evaluate"
                | "Runtime.callFunctionOn"
                | "Runtime.awaitPromise"
                | "Accessibility.getFullAXTree"
                | "Accessibility.getPartialAXTree"
                | "Accessibility.queryAXTree"
                | "Emulation.setDeviceMetricsOverride"
        )
        || (method.starts_with("DOM.") && !matches!(method, "DOM.enable" | "DOM.disable"))
}

async fn begin_tab_indicator_activity(state: &Arc<Mutex<RelayState>>, tab_id: i64) {
    let (deactivated_tabs, need_focus, need_install, need_activate, peer, target_info, accent_hex) = {
        let mut guard = state.lock().await;
        let accent_hex = favicon_accent_hex(&guard.scope);
        let peer = guard.peer.clone();
        let mut to_deactivate = Vec::new();
        for (&other_id, other) in &mut guard.tab_sessions {
            if other_id != tab_id && other.indicator_active && other.indicator_in_flight == 0 {
                other.indicator_active = false;
                other.indicator_release_gen += 1;
                to_deactivate.push(other_id);
            }
        }
        let (need_focus, need_install, need_activate, target_info) =
            if let Some(ts) = guard.tab_sessions.get_mut(&tab_id) {
                ts.indicator_in_flight += 1;
                ts.indicator_release_gen += 1;
                let need_focus = !ts.focus_emulated;
                ts.focus_emulated = true;
                let need_install = !ts.indicator_installed;
                ts.indicator_installed = true;
                let activate = !ts.indicator_active;
                ts.indicator_active = true;
                (
                    need_focus,
                    need_install,
                    activate,
                    Some(ts.target_info.clone()),
                )
            } else {
                (false, false, false, None)
            };
        (
            to_deactivate,
            need_focus,
            need_install,
            need_activate,
            peer,
            target_info,
            accent_hex,
        )
    };
    for other_id in deactivated_tabs {
        let cloned = state.clone();
        tokio::spawn(async move {
            eval_tab_indicator(
                &cloned,
                other_id,
                "globalThis.__styxIndicatorSetActive?.(false)",
            )
            .await;
        });
    }
    if need_focus {
        let _ = tokio::time::timeout(
            Duration::from_secs(1),
            peer.call(
                "debugger.sendCommand",
                json!({
                    "tabId": tab_id,
                    "method": "Emulation.setFocusEmulationEnabled",
                    "params": { "enabled": true }
                }),
            ),
        )
        .await;
    }
    if need_install && let Some(target_info) = target_info.as_ref() {
        let (script_id, ctx_id) =
            install_favicon_indicator(&peer, tab_id, target_info, accent_hex).await;
        if let Some(ts) = state.lock().await.tab_sessions.get_mut(&tab_id) {
            if ts.favicon_script_id.is_none() {
                ts.favicon_script_id = script_id;
            }
            if ts.indicator_context_id.is_none() {
                ts.indicator_context_id = ctx_id;
            }
        }
    }
    if need_activate {
        let _ = tokio::time::timeout(
            Duration::from_millis(400),
            eval_tab_indicator(state, tab_id, "globalThis.__styxIndicatorSetActive?.(true)"),
        )
        .await;
    }
}

async fn end_tab_indicator_activity(state: &Arc<Mutex<RelayState>>, tab_id: i64) {
    let schedule = {
        let mut guard = state.lock().await;
        let delay = guard.indicator_idle_timeout;
        guard.tab_sessions.get_mut(&tab_id).and_then(|ts| {
            ts.indicator_in_flight = ts.indicator_in_flight.saturating_sub(1);
            if ts.indicator_in_flight == 0 {
                ts.indicator_release_gen += 1;
                Some((ts.indicator_release_gen, delay))
            } else {
                None
            }
        })
    };
    if let Some((release_gen, delay)) = schedule {
        let cloned = state.clone();
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let should_deactivate = {
                let mut guard = cloned.lock().await;
                if let Some(ts) = guard.tab_sessions.get_mut(&tab_id)
                    && ts.indicator_active
                    && ts.indicator_in_flight == 0
                    && ts.indicator_release_gen == release_gen
                {
                    ts.indicator_active = false;
                    true
                } else {
                    false
                }
            };
            if should_deactivate {
                eval_tab_indicator(
                    &cloned,
                    tab_id,
                    "globalThis.__styxIndicatorSetActive?.(false)",
                )
                .await;
            }
        });
    }
}

struct TabSession {
    session_id: String,
    target_info: Value,
    child_sessions: HashSet<String>,
    favicon_script_id: Option<String>,
    indicator_context_id: Option<i64>,
    indicator_installed: bool,
    focus_emulated: bool,
    indicator_active: bool,
    indicator_in_flight: usize,
    indicator_release_gen: u64,
}

type AttachWaiter = oneshot::Sender<Result<(String, Value), String>>;

struct RelayState {
    relay_id: u64,
    session_cancel: CancellationToken,
    scope: CdpSessionScope,
    group_id: Option<i64>,
    owned_tabs: HashSet<i64>,
    peer: Arc<ExtensionPeer>,
    cdp_out: mpsc::UnboundedSender<String>,
    known_tabs: BTreeMap<i64, TabDescriptor>,
    tab_sessions: HashMap<i64, TabSession>,
    attaching: HashMap<i64, Vec<AttachWaiter>>,
    init_lock: Arc<Mutex<()>>,
    discover_targets: bool,
    auto_attach: bool,
    announced_targets: HashSet<String>,
    attached_emitted: HashSet<String>,
    next_session_seq: u64,
    temp_screencast_tabs: HashSet<i64>,
    indicator_idle_timeout: Duration,
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
            self.attached_emitted.remove(&ts.session_id);
            for child in ts.child_sessions {
                self.attached_emitted.remove(&child);
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
    let (peer, relay_id, session_cancel, isolated, existing_waiter) = {
        let mut guard = state.lock().await;
        if guard.session_cancel.is_cancelled() {
            return Err("session_closed".to_owned());
        }
        if let Some(existing) = guard.tab_sessions.get(&tab_id) {
            return Ok((existing.session_id.clone(), existing.target_info.clone()));
        }
        let isolated = matches!(guard.scope, CdpSessionScope::TabGroup { .. });
        if let Some(waiters) = guard.attaching.get_mut(&tab_id) {
            let (tx, rx) = oneshot::channel();
            waiters.push(tx);
            (
                guard.peer.clone(),
                guard.relay_id,
                guard.session_cancel.clone(),
                isolated,
                Some(rx),
            )
        } else {
            if !guard.peer.claim_tab(tab_id, guard.relay_id, isolated) {
                return Err("tab_owned_by_another_session".to_owned());
            }
            guard.attaching.insert(tab_id, Vec::new());
            (
                guard.peer.clone(),
                guard.relay_id,
                guard.session_cancel.clone(),
                isolated,
                None,
            )
        }
    };

    if let Some(rx) = existing_waiter {
        return tokio::select! {
            () = session_cancel.cancelled() => Err("session_closed".to_owned()),
            res = rx => res.map_err(|_| "tab_attach_cancelled".to_owned())?,
        };
    }

    let mut debugger_attached = false;
    let attach_res = tokio::select! {
        () = session_cancel.cancelled() => Err("session_closed".to_owned()),
        res = async {
            tokio::time::timeout(
                Duration::from_secs(3),
                peer.call("debugger.attach", json!({ "tabId": tab_id })),
            )
            .await
            .map_err(|_| "debugger_attach_timeout".to_owned())??;
            debugger_attached = true;
            let info = tokio::time::timeout(
                Duration::from_secs(3),
                peer.call(
                    "debugger.sendCommand",
                    json!({ "tabId": tab_id, "method": "Target.getTargetInfo" }),
                ),
            )
            .await
            .map_err(|_| "target_info_timeout".to_owned())??;
            let mut target_info = info.get("targetInfo").cloned().unwrap_or_else(|| json!({}));
            // Normalize `targetId` to the page's current main frame ID so COOP/RenderFrameHost
            // swaps (`Page.getFrameTree().frameTree.frame.id`) match `targetInfo.targetId`.
            if let Ok(Ok(ft)) = tokio::time::timeout(
                Duration::from_secs(2),
                peer.call(
                    "debugger.sendCommand",
                    json!({ "tabId": tab_id, "method": "Page.getFrameTree", "params": {} }),
                ),
            )
            .await
                && let Some(main_frame_id) = ft
                    .pointer("/frameTree/frame/id")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                && let Some(obj) = target_info.as_object_mut()
            {
                obj.insert("targetId".to_owned(), Value::String(main_frame_id.to_owned()));
            }
            // For isolated Tab Group tabs, emulate focus immediately so `active: false`
            // background tabs run rAF/visibilityState normally without stealing focus.
            // SharedExisting attaches lazily without side effects until a tab is operated.
            let focus_emulated = if isolated {
                let _ = tokio::time::timeout(
                    Duration::from_secs(1),
                    peer.call(
                        "debugger.sendCommand",
                        json!({
                            "tabId": tab_id,
                            "method": "Emulation.setFocusEmulationEnabled",
                            "params": { "enabled": true }
                        }),
                    ),
                )
                .await;
                true
            } else {
                false
            };
            Ok::<(Value, bool), String>((target_info, focus_emulated))
        } => res,
    };

    let mut guard = state.lock().await;
    let waiters = guard.attaching.remove(&tab_id).unwrap_or_default();
    if guard.session_cancel.is_cancelled() {
        guard.owned_tabs.remove(&tab_id);
        drop(guard);
        match attach_res {
            Ok((target_info, focus_emulated)) => {
                detach_and_cleanup_tab(
                    &peer,
                    tab_id,
                    None,
                    None,
                    target_info.get("targetId").and_then(Value::as_str),
                    false,
                    focus_emulated,
                )
                .await;
            }
            Err(_) if debugger_attached => {
                let _ = tokio::time::timeout(
                    Duration::from_secs(2),
                    peer.call("debugger.detach", json!({ "tabId": tab_id })),
                )
                .await;
            }
            Err(_) => {}
        }
        peer.release_relay_tabs(relay_id, &[tab_id]);
        let cancelled: Result<(String, Value), String> = Err("session_closed".to_owned());
        for waiter in waiters {
            let _ = waiter.send(cancelled.clone());
        }
        return cancelled;
    }

    let mut cleanup_partial_attach = false;
    let outcome = match attach_res {
        Ok((target_info, focus_emulated)) => {
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
                        favicon_script_id: None,
                        indicator_context_id: None,
                        indicator_installed: false,
                        focus_emulated,
                        indicator_active: false,
                        indicator_in_flight: 0,
                        indicator_release_gen: 0,
                    },
                );
                if guard.discover_targets
                    && let Some(target_id) = target_info
                        .get("targetId")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                    && guard.announced_targets.insert(target_id)
                {
                    guard.emit_cdp(json!({
                        "method": "Target.targetCreated",
                        "params": { "targetInfo": emitted_info.clone() }
                    }));
                }
                if guard.auto_attach && guard.attached_emitted.insert(session_id.clone()) {
                    guard.emit_cdp(json!({
                        "method": "Target.attachedToTarget",
                        "params": {
                            "sessionId": session_id,
                            "targetInfo": emitted_info,
                            "waitingForDebugger": false,
                        }
                    }));
                }
                Ok((session_id, target_info))
            }
        }
        Err(err) => {
            cleanup_partial_attach = debugger_attached;
            if !isolated || !guard.owned_tabs.contains(&tab_id) {
                peer.release_relay_tabs(relay_id, &[tab_id]);
            }
            Err(err)
        }
    };
    drop(guard);
    if cleanup_partial_attach {
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            peer.call("debugger.detach", json!({ "tabId": tab_id })),
        )
        .await;
    }
    for waiter in waiters {
        let _ = waiter.send(outcome.clone());
    }
    outcome
}

async fn ensure_scope_tabs_ready(state: &Arc<Mutex<RelayState>>) -> Result<(), String> {
    const MAX_CONCURRENT_SHARED_ATTACHES: usize = 6;

    let init_lock = state.lock().await.init_lock.clone();
    let _init_guard = init_lock.lock().await;
    let (peer, relay_id, session_cancel, scope, existing_owned, fallback_ids) = {
        let guard = state.lock().await;
        if guard.session_cancel.is_cancelled() {
            return Err("session_closed".to_owned());
        }
        (
            guard.peer.clone(),
            guard.relay_id,
            guard.session_cancel.clone(),
            guard.scope.clone(),
            guard.owned_tabs.iter().copied().collect::<Vec<_>>(),
            guard.known_tabs.keys().copied().collect::<Vec<_>>(),
        )
    };
    match scope {
        CdpSessionScope::TabGroup {
            title,
            color,
            session_key,
        } => {
            let tab_ids = if existing_owned.is_empty() {
                let mut reattached_ids = Vec::new();
                if let Some(ref key) = session_key
                    && let Some(gid) = peer.remembered_tab_group_id(key)
                {
                    let listed_res = tokio::select! {
                        () = session_cancel.cancelled() => return Err("session_closed".to_owned()),
                        res = peer.call("tabs.list", json!({ "excludeIsolated": false })) => res,
                    };
                    if let Ok(listed) = listed_res
                        && let Ok(tabs) = serde_json::from_value::<Vec<TabDescriptor>>(
                            listed.get("tabs").cloned().unwrap_or_else(|| json!([])),
                        )
                    {
                        let mut matched = Vec::new();
                        for tab in tabs {
                            if tab.group_id == gid && peer.claim_tab(tab.id, relay_id, true) {
                                matched.push(tab);
                            }
                        }
                        if !matched.is_empty() {
                            {
                                let mut guard = state.lock().await;
                                guard.group_id = Some(gid);
                                for tab in matched {
                                    reattached_ids.push(tab.id);
                                    guard.owned_tabs.insert(tab.id);
                                    guard.known_tabs.insert(tab.id, tab);
                                }
                            }
                            let _ = tokio::time::timeout(
                                Duration::from_secs(2),
                                peer.call(
                                    "tabGroups.collapse",
                                    json!({ "groupId": gid, "collapsed": false }),
                                ),
                            )
                            .await;
                        } else {
                            peer.forget_tab_group_id(key);
                        }
                    } else {
                        peer.forget_tab_group_id(key);
                    }
                }
                if !reattached_ids.is_empty() {
                    reattached_ids
                } else {
                    let created = tokio::select! {
                        () = session_cancel.cancelled() => return Err("session_closed".to_owned()),
                        res = peer.call(
                            "tabs.create",
                            json!({
                                "url": "about:blank",
                                "active": false,
                                "isolated": true,
                                "groupTitle": title,
                                "groupColor": color,
                            }),
                        ) => res?,
                    };
                    if session_cancel.is_cancelled() {
                        if let Some(tab_id) = created.pointer("/tab/id").and_then(Value::as_i64) {
                            let _ = peer.call("tabs.remove", json!({ "tabId": tab_id })).await;
                        }
                        return Err("session_closed".to_owned());
                    }
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
                        if let Some(ref key) = session_key {
                            guard.peer.remember_tab_group_id(key, returned_gid);
                        }
                    }
                    guard.owned_tabs.insert(tab.id);
                    guard.known_tabs.insert(tab.id, tab.clone());
                    guard.peer.claim_tab(tab.id, relay_id, true);
                    vec![tab.id]
                }
            } else {
                existing_owned
            };
            for tab_id in tab_ids {
                if session_cancel.is_cancelled() {
                    return Err("session_closed".to_owned());
                }
                let _ = attach_tab(state, tab_id).await;
            }
        }
        CdpSessionScope::SharedExisting => {
            let listed_res = tokio::select! {
                () = session_cancel.cancelled() => return Err("session_closed".to_owned()),
                res = peer.call("tabs.list", json!({ "excludeIsolated": true })) => res,
            };
            if let Ok(listed) = listed_res
                && let Ok(tabs) = serde_json::from_value::<Vec<TabDescriptor>>(
                    listed.get("tabs").cloned().unwrap_or_else(|| json!([])),
                )
            {
                let mut guard = state.lock().await;
                guard.known_tabs.clear();
                for tab in tabs {
                    if !tab.isolated && peer.is_tab_available_for_shared(tab.id, relay_id) {
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
            let sem = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SHARED_ATTACHES));
            let mut join_set = tokio::task::JoinSet::new();
            for tab_id in tab_ids {
                let state_cloned = state.clone();
                let sem_cloned = sem.clone();
                join_set.spawn(async move {
                    let Ok(_permit) = sem_cloned.acquire_owned().await else {
                        return;
                    };
                    let _ = attach_tab(&state_cloned, tab_id).await;
                });
            }
            loop {
                tokio::select! {
                    () = session_cancel.cancelled() => {
                        join_set.abort_all();
                        return Err("session_closed".to_owned());
                    }
                    next = join_set.join_next() => {
                        if next.is_none() {
                            break;
                        }
                    }
                }
            }
        }
    }
    Ok(())
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
            "Target.getBrowserContexts" => {
                return Ok(json!({ "browserContextIds": [] }));
            }
            "Browser.setDownloadBehavior"
            | "Target.disposeBrowserContext"
            | "Browser.close"
            | "Target.activateTarget"
            | "Page.bringToFront" => {
                return Ok(json!({}));
            }
            "Target.getTargetInfo" => {
                if let Some(target_id) = params.get("targetId").and_then(Value::as_str) {
                    let guard = state.lock().await;
                    if let Some(tab_id) = guard.find_tab_by_target(target_id)
                        && let Some(ts) = guard.tab_sessions.get(&tab_id)
                    {
                        return Ok(json!({ "targetInfo": ts.target_info }));
                    }
                }
                return Ok(json!({}));
            }
            "Target.setDiscoverTargets" => {
                let discover = params
                    .get("discover")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                {
                    state.lock().await.discover_targets = discover;
                }
                if discover {
                    ensure_scope_tabs_ready(state).await?;
                    let mut guard = state.lock().await;
                    let mut items: Vec<(i64, Value)> = guard
                        .tab_sessions
                        .iter()
                        .map(|(id, ts)| (*id, ts.target_info.clone()))
                        .collect();
                    items.sort_by_key(|(id, _)| *id);
                    for (_, target_info) in items {
                        if let Some(target_id) = target_info
                            .get("targetId")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                            && guard.announced_targets.insert(target_id)
                        {
                            let mut info = target_info;
                            if let Some(obj) = info.as_object_mut() {
                                obj.insert("attached".to_owned(), Value::Bool(true));
                            }
                            guard.emit_cdp(json!({
                                "method": "Target.targetCreated",
                                "params": { "targetInfo": info }
                            }));
                        }
                    }
                }
                return Ok(json!({}));
            }
            "Target.setAutoAttach" => {
                let auto_attach = params
                    .get("autoAttach")
                    .and_then(Value::as_bool)
                    .unwrap_or(true);
                {
                    state.lock().await.auto_attach = auto_attach;
                }
                if auto_attach {
                    ensure_scope_tabs_ready(state).await?;
                    let mut guard = state.lock().await;
                    let mut items: Vec<(i64, String, Value)> = guard
                        .tab_sessions
                        .iter()
                        .map(|(id, ts)| (*id, ts.session_id.clone(), ts.target_info.clone()))
                        .collect();
                    items.sort_by_key(|(id, _, _)| *id);
                    for (_, sid, target_info) in items {
                        if guard.attached_emitted.insert(sid.clone()) {
                            let mut emitted_info = target_info;
                            if let Some(obj) = emitted_info.as_object_mut() {
                                obj.insert("attached".to_owned(), Value::Bool(true));
                            }
                            guard.emit_cdp(json!({
                                "method": "Target.attachedToTarget",
                                "params": {
                                    "sessionId": sid,
                                    "targetInfo": emitted_info,
                                    "waitingForDebugger": false,
                                }
                            }));
                        }
                    }
                }
                return Ok(json!({}));
            }
            "Target.attachToTarget" => {
                let target_id = params.get("targetId").and_then(Value::as_str);
                let tab_id = {
                    let guard = state.lock().await;
                    target_id.and_then(|id| guard.find_tab_by_target(id))
                };
                let Some(tab_id) = tab_id else {
                    return Err("target_not_found".to_owned());
                };
                let (sid, info) = attach_tab(state, tab_id).await?;
                let mut guard = state.lock().await;
                if guard.attached_emitted.insert(sid.clone()) {
                    let mut emitted_info = info;
                    if let Some(obj) = emitted_info.as_object_mut() {
                        obj.insert("attached".to_owned(), Value::Bool(true));
                    }
                    guard.emit_cdp(json!({
                        "method": "Target.attachedToTarget",
                        "params": {
                            "sessionId": sid,
                            "targetInfo": emitted_info,
                            "waitingForDebugger": false,
                        }
                    }));
                }
                return Ok(json!({ "sessionId": sid }));
            }
            "Target.detachFromTarget" => {
                let target_sid = params
                    .get("sessionId")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                let Some(target_sid) = target_sid else {
                    return Ok(json!({}));
                };
                let found = {
                    let guard = state.lock().await;
                    guard.find_tab_by_session(&target_sid)
                };
                match found {
                    Some((tab_id, None)) => {
                        let (peer, relay_id, detached_info) = {
                            let mut guard = state.lock().await;
                            let info = guard.tab_sessions.get(&tab_id).map(|ts| {
                                (
                                    ts.favicon_script_id.clone(),
                                    ts.indicator_context_id,
                                    ts.target_info
                                        .get("targetId")
                                        .and_then(Value::as_str)
                                        .map(str::to_owned),
                                    ts.indicator_installed,
                                    ts.focus_emulated,
                                )
                            });
                            guard.detach_tab(tab_id);
                            guard.owned_tabs.remove(&tab_id);
                            (guard.peer.clone(), guard.relay_id, info)
                        };
                        if let Some((
                            script_id,
                            ctx_id,
                            target_id,
                            indicator_installed,
                            focus_emulated,
                        )) = detached_info
                        {
                            detach_and_cleanup_tab(
                                &peer,
                                tab_id,
                                script_id.as_deref(),
                                ctx_id,
                                target_id.as_deref(),
                                indicator_installed,
                                focus_emulated,
                            )
                            .await;
                        }
                        peer.release_relay_tabs(relay_id, &[tab_id]);
                        return Ok(json!({}));
                    }
                    Some((tab_id, Some(child))) => {
                        let peer = state.lock().await.peer.clone();
                        return peer
                            .call(
                                "debugger.sendCommand",
                                json!({
                                    "tabId": tab_id,
                                    "method": "Target.detachFromTarget",
                                    "params": { "sessionId": child }
                                }),
                            )
                            .await;
                    }
                    None => return Ok(json!({})),
                }
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
                    CdpSessionScope::TabGroup { title, color, .. } => {
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
                        if let CdpSessionScope::TabGroup {
                            session_key: Some(ref key),
                            ..
                        } = guard.scope
                        {
                            guard.peer.remember_tab_group_id(key, returned_gid);
                        }
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
                if guard.discover_targets
                    && let Some(tid) = target_id
                    && guard.announced_targets.remove(tid)
                {
                    guard.emit_cdp(json!({
                        "method": "Target.targetDestroyed",
                        "params": { "targetId": tid }
                    }));
                }
                peer.release_relay_tabs(relay_id, &[tab_id]);
                return Ok(json!({ "success": true }));
            }
            "Target.getTargets" => {
                let _ = ensure_scope_tabs_ready(state).await;
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
    let track_activity = child_sid.is_none() && is_active_control_cdp_method(method);
    if track_activity {
        begin_tab_indicator_activity(state, tab_id).await;
    }
    if method == "Input.dispatchMouseEvent"
        && child_sid.is_none()
        && let (Some(x), Some(y)) = (
            params
                .get("x")
                .and_then(Value::as_f64)
                .filter(|v| v.is_finite()),
            params
                .get("y")
                .and_then(Value::as_f64)
                .filter(|v| v.is_finite()),
        )
    {
        let cursor_state = match params.get("type").and_then(Value::as_str) {
            Some("mouseMoved") => Some("move"),
            Some("mousePressed") => Some("down"),
            Some("mouseReleased") => Some("up"),
            Some("mouseWheel") => Some("wheel"),
            _ => None,
        };
        if let Some(cursor_state) = cursor_state {
            let script = format!("globalThis.__styxCursorMove?.({x},{y},\"{cursor_state}\")");
            let cloned_state = state.clone();
            tokio::spawn(async move {
                eval_tab_indicator(&cloned_state, tab_id, &script).await;
            });
        }
    }
    let is_top_level_screenshot = method == "Page.captureScreenshot" && child_sid.is_none();
    let mut rpc = json!({ "tabId": tab_id, "method": method, "params": params });
    if let Some(child) = child_sid
        && let Some(obj) = rpc.as_object_mut()
    {
        obj.insert("sessionId".to_owned(), Value::String(child));
    }
    let res = if is_top_level_screenshot {
        let _ = tokio::time::timeout(
            Duration::from_millis(400),
            eval_tab_indicator(state, tab_id, "globalThis.__styxCursorSetHidden?.(true)"),
        )
        .await;
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
        let shot_res = peer.call("debugger.sendCommand", rpc).await;
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
        let _ = tokio::time::timeout(
            Duration::from_millis(400),
            eval_tab_indicator(state, tab_id, "globalThis.__styxCursorSetHidden?.(false)"),
        )
        .await;
        shot_res
    } else {
        peer.call("debugger.sendCommand", rpc).await
    };
    if track_activity {
        end_tab_indicator_activity(state, tab_id).await;
    }
    res
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
            let mut reactivate_tab = false;
            if source_child.is_none() {
                let is_main_frame_nav = cdp_method == "Page.frameNavigated"
                    && cdp_params.pointer("/frame/parentId").is_none();
                if is_main_frame_nav || cdp_method == "Runtime.executionContextsCleared" {
                    ts.indicator_context_id = None;
                }
                if is_main_frame_nav && ts.indicator_active {
                    reactivate_tab = true;
                }
            }
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
            drop(guard);
            if reactivate_tab {
                let cloned = state.clone();
                tokio::spawn(async move {
                    eval_tab_indicator(
                        &cloned,
                        tab_id,
                        "globalThis.__styxIndicatorSetActive?.(true)",
                    )
                    .await;
                });
            }
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
                    CdpSessionScope::TabGroup { title, color, .. } => {
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
                            let attach = (guard.auto_attach || guard.discover_targets)
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
                            let attach = (guard.auto_attach || guard.discover_targets)
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
                let target_id = guard
                    .tab_sessions
                    .get(&tab_id)
                    .and_then(|ts| ts.target_info.get("targetId"))
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                guard.known_tabs.remove(&tab_id);
                let had_session = guard.detach_tab(tab_id);
                let had_owned = guard.owned_tabs.remove(&tab_id);
                if guard.discover_targets
                    && let Some(tid) = target_id
                    && guard.announced_targets.remove(&tid)
                {
                    guard.emit_cdp(json!({
                        "method": "Target.targetDestroyed",
                        "params": { "targetId": tid }
                    }));
                }
                if had_session || had_owned {
                    let relay_id = guard.relay_id;
                    guard.peer.release_relay_tabs(relay_id, &[tab_id]);
                }
            }
        }
        _ => {}
    }
}

struct QueuedCdpRequest {
    id: Option<Value>,
    method: String,
    params: Value,
    session_id: Option<String>,
}

fn spawn_cdp_session_worker(
    state: Arc<Mutex<RelayState>>,
    cdp_tx: mpsc::UnboundedSender<String>,
    cancel: CancellationToken,
    handles: &mut Vec<JoinHandle<()>>,
) -> mpsc::UnboundedSender<QueuedCdpRequest> {
    let (tx, mut rx) = mpsc::unbounded_channel::<QueuedCdpRequest>();
    let handle = tokio::spawn(async move {
        loop {
            let req = tokio::select! {
                () = cancel.cancelled() => break,
                maybe_req = rx.recv() => match maybe_req {
                    Some(req) => req,
                    None => break,
                }
            };
            let res = tokio::select! {
                () = cancel.cancelled() => break,
                out = handle_cdp_request(&state, &req.method, req.params, req.session_id.as_deref()) => out,
            };
            let mut reply = match res {
                Ok(result) => json!({ "id": req.id, "result": result }),
                Err(message) => json!({ "id": req.id, "error": { "message": message } }),
            };
            if let Some(sid) = req.session_id
                && let Some(obj) = reply.as_object_mut()
            {
                obj.insert("sessionId".to_owned(), Value::String(sid));
            }
            if cdp_tx.send(reply.to_string()).is_err() {
                break;
            }
        }
    });
    handles.push(handle);
    tx
}

async fn run_cdp_relay_session(
    ws: tokio_tungstenite::WebSocketStream<TcpStream>,
    peer: Arc<ExtensionPeer>,
    bridge_cancel: CancellationToken,
    scope: CdpSessionScope,
    indicator_idle_timeout: Duration,
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
        session_cancel: session_cancel.clone(),
        scope,
        group_id: None,
        owned_tabs: HashSet::new(),
        peer: peer.clone(),
        cdp_out: cdp_tx.clone(),
        known_tabs: initial_known,
        tab_sessions: HashMap::new(),
        attaching: HashMap::new(),
        init_lock: Arc::new(Mutex::new(())),
        discover_targets: false,
        auto_attach: false,
        announced_targets: HashSet::new(),
        attached_emitted: HashSet::new(),
        next_session_seq: 0,
        temp_screencast_tabs: HashSet::new(),
        indicator_idle_timeout,
    }));

    let (pong_flush_tx, mut pong_flush_rx) = mpsc::unbounded_channel::<()>();
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
                flush_req = pong_flush_rx.recv() => {
                    let Some(()) = flush_req else { break };
                    if ws_sink.flush().await.is_err() {
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

    // Enforce strict FIFO execution per CDP sessionId (matching real Chromium DevTools)
    // while keeping different tabs independent.
    let mut session_queues: HashMap<Option<String>, mpsc::UnboundedSender<QueuedCdpRequest>> =
        HashMap::new();
    let mut worker_handles: Vec<JoinHandle<()>> = Vec::new();

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
                        let queued = QueuedCdpRequest {
                            id,
                            method,
                            params,
                            session_id: session_id.clone(),
                        };
                        let queue_tx = session_queues
                            .entry(session_id.clone())
                            .or_insert_with(|| {
                                spawn_cdp_session_worker(
                                    state.clone(),
                                    cdp_tx.clone(),
                                    session_cancel.clone(),
                                    &mut worker_handles,
                                )
                            });
                        if let Err(err) = queue_tx.send(queued) {
                            let rebuilt = spawn_cdp_session_worker(
                                state.clone(),
                                cdp_tx.clone(),
                                session_cancel.clone(),
                                &mut worker_handles,
                            );
                            let _ = rebuilt.send(err.0);
                            session_queues.insert(session_id, rebuilt);
                        }
                    }
                    Some(Ok(Message::Ping(_))) => {
                        // tungstenite queues the Pong automatically; trigger ws_sink.flush().
                        let _ = pong_flush_tx.send(());
                    }
                    Some(Ok(Message::Pong(_))) => {}
                    _ => break,
                }
            }
        }
    }

    session_cancel.cancel();
    drop(session_queues);
    let _ = tokio::time::timeout(
        Duration::from_secs(3),
        futures_util::future::join_all(worker_handles),
    )
    .await;
    peer.unsubscribe_events(relay_id);

    struct AttachedTabCleanup {
        tab_id: i64,
        favicon_script_id: Option<String>,
        cached_ctx: Option<i64>,
        target_id: Option<String>,
        indicator_installed: bool,
        focus_emulated: bool,
    }
    let attached_tabs: Vec<AttachedTabCleanup> = {
        let mut guard = state.lock().await;
        let attached = guard
            .tab_sessions
            .iter()
            .map(|(tab_id, ts)| AttachedTabCleanup {
                tab_id: *tab_id,
                favicon_script_id: ts.favicon_script_id.clone(),
                cached_ctx: ts.indicator_context_id,
                target_id: ts
                    .target_info
                    .get("targetId")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                indicator_installed: ts.indicator_installed,
                focus_emulated: ts.focus_emulated,
            })
            .collect();
        guard.owned_tabs.clear();
        guard.tab_sessions.clear();
        attached
    };
    let cleanup_futs = attached_tabs.into_iter().map(|entry| {
        let peer = peer.clone();
        async move {
            detach_and_cleanup_tab(
                &peer,
                entry.tab_id,
                entry.favicon_script_id.as_deref(),
                entry.cached_ctx,
                entry.target_id.as_deref(),
                entry.indicator_installed,
                entry.focus_emulated,
            )
            .await;
        }
    });
    let _ = tokio::time::timeout(
        Duration::from_secs(3),
        futures_util::future::join_all(cleanup_futs),
    )
    .await;
    peer.release_all_for_relay(relay_id);
    let _ = ws_writer.await;
    let _ = event_task.await;
}
