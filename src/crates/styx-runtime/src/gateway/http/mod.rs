//! Gateway HTTP/MCP adapter. The official SDK owns MCP sessions and SSE.
//! This adapter binds authenticated owners and supervises their lifecycle.
mod backend;
pub(crate) mod body;
mod conversation;
pub mod lifecycle;
mod session;
use crate::gateway::{
    auth::{
        AuthenticatedGatewayPrincipal, GatewayAuthError, GatewayBearerPolicy, VerifiedGatewayOwner,
        public_mcp::RESOURCE_METADATA_PATH,
    },
    mcp::{GatewayMcp, GatewayToolBackend},
};
use backend::BackendBridge;
use body::HeldBody;
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body::Body;
use http_body_util::{BodyExt, Full, Limited};
use lifecycle::{CloseFacts, GatewayOwnerLifecycle, Life, Supervisor};
use rmcp::{
    model::{ClientJsonRpcMessage, ClientNotification, ClientRequest},
    transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService},
};
use session::McpSessionManager;
use std::{
    collections::BTreeMap,
    convert::Infallible,
    sync::{Arc, Mutex},
    time::Duration,
};
#[cfg(test)]
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

pub(crate) const MCP_PATH: &str = "/mcp";
pub const MESSAGE_BYTES: usize = 256 * 1024;
const OLDEST: &str = "2024-10-07";
const SID: &str = "mcp-session-id";
const VERSION: &str = "mcp-protocol-version";
/// Original oldest protocol header retained after the narrowly approved SDK shim.
#[derive(Clone, Debug)]
pub struct OriginalOldestProtocolHeader;
impl OriginalOldestProtocolHeader {
    pub fn as_str(&self) -> &'static str {
        OLDEST
    }
}
#[derive(Debug, thiserror::Error)]
#[error("HTTP configuration or session lifetime refused")]
pub struct HttpError;
struct Session<B: GatewayToolBackend + GatewayOwnerLifecycle> {
    sdk: StreamableHttpService<GatewayMcp<BackendBridge<B>>, McpSessionManager<B>>,
    manager: Arc<McpSessionManager<B>>,
    life: Arc<Life<B>>,
}
pub struct GatewayHttp<B: GatewayToolBackend + GatewayOwnerLifecycle> {
    tunnel_observation: Mutex<Option<Arc<crate::foreground::tunnel::RequestObservation>>>,
    policy: Arc<GatewayBearerPolicy>,
    backend: Arc<B>,
    sessions: Mutex<BTreeMap<uuid::Uuid, Arc<Session<B>>>>,
    conversations: Mutex<BTreeMap<[u8; 32], Arc<conversation::Conversation<B>>>>,
    supervisor: Arc<Supervisor>,
    stop: CancellationToken,
    collection_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    #[cfg(test)]
    oldest_methods: std::sync::atomic::AtomicU8,
    #[cfg(test)]
    admission_probe: Mutex<Option<Arc<AdmissionProbe>>>,
}
#[cfg(test)]
struct AdmissionProbe {
    body_entered: Semaphore,
    control_entered: Semaphore,
    release_controls: Semaphore,
}
#[derive(Debug)]
pub struct HttpShutdown {
    pub connections_joined: bool,
    /// Actual supervised task termination, independent of a remote result.
    pub lifecycle_jobs_joined: bool,
    /// Official LocalSessionWorker close was actually joined (or never attempted).
    pub session_transports_joined: bool,
    /// Remote owner settlement is not a local task-liveness fact.
    pub unconfirmed_owner_cleanups: usize,
    pub worker_failure_observed: bool,
    pub unresolved_sessions: usize,
    /// Official SDK does not expose joins for its outer/handler tasks. None is
    /// deliberately distinct from the observed LocalSessionWorker join.
    pub sdk_detached_tasks_joined: Option<bool>,
}
impl<B: GatewayToolBackend + GatewayOwnerLifecycle> GatewayHttp<B> {
    pub fn new(policy: Arc<GatewayBearerPolicy>, backend: Arc<B>) -> Arc<Self> {
        let app = Arc::new(Self {
            tunnel_observation: Mutex::new(None),
            policy,
            backend,
            sessions: Mutex::new(BTreeMap::new()),
            conversations: Mutex::new(BTreeMap::new()),
            supervisor: Arc::new(Supervisor {
                jobs: Mutex::new(JoinSet::new()),
                parked: Mutex::new(vec![]),
                worker_failure_observed: std::sync::atomic::AtomicBool::new(false),
                accepting_cleanup_jobs: std::sync::atomic::AtomicBool::new(true),
            }),
            stop: CancellationToken::new(),
            collection_task: Mutex::new(None),
            #[cfg(test)]
            oldest_methods: std::sync::atomic::AtomicU8::new(0),
            #[cfg(test)]
            admission_probe: Mutex::new(None),
        });
        let weak = Arc::downgrade(&app);
        let stop = app.stop.clone();
        *app.collection_task.lock().expect("session collector") = Some(tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(15));
            loop {
                tokio::select! {
                    _ = stop.cancelled() => break,
                    _ = tick.tick() => {
                        let Some(app) = weak.upgrade() else { break; };
                        app.collect_closed();
                        app.collect_closed_conversations();
                    }
                }
            }
        }));
        app
    }
    pub(crate) fn observe_tunnel(
        &self,
        observation: Option<Arc<crate::foreground::tunnel::RequestObservation>>,
    ) {
        *self.tunnel_observation.lock().expect("tunnel observation") = observation;
    }
    fn collect_closed(&self) {
        self.sessions
            .lock()
            .expect("HTTP sessions")
            .retain(|_, session| !session.life.is_complete());
        self.conversations
            .lock()
            .expect("Tunnel conversations")
            .retain(|_, conversation| !conversation.life.is_complete());
    }
    fn new_life(&self, owner: VerifiedGatewayOwner, boundary: lifecycle::Boundary) -> Arc<Life<B>> {
        Arc::new(Life {
            boundary,
            owner,
            lifecycle: self.backend.clone(),
            facts: Mutex::new(CloseFacts::default()),
            changed: tokio::sync::Notify::new(),
            cancellation: Mutex::new(None),
            supervisor: Arc::downgrade(&self.supervisor),
        })
    }
    fn create_session(&self, owner: VerifiedGatewayOwner) -> Result<Arc<Session<B>>, HttpError> {
        self.collect_closed();
        let mut registry = self.sessions.lock().expect("HTTP sessions");
        if self.stop.is_cancelled() {
            owner.cleanup_complete();
            return Err(HttpError);
        }
        let life = self.new_life(owner.clone(), lifecycle::Boundary::McpTransport);
        let manager = Arc::new(McpSessionManager::new(life.clone()));
        let bridge = Arc::new(BackendBridge {
            backend: self.backend.clone(),
            life: life.clone(),
            #[cfg(test)]
            before_register: Mutex::new(None),
        });
        let mut config =
            StreamableHttpServerConfig::default().with_allowed_hosts(self.policy.mcp_authorities());
        config.max_request_body_bytes = MESSAGE_BYTES;
        config.sse_keep_alive = Some(Duration::from_secs(10));
        config.session_store = None;
        // The SDK and outer policy use the same configured Host authorities.
        // The outer policy applies exact Host and ingress-specific Origin checks.
        let sdk = StreamableHttpService::new(
            move || {
                Ok(GatewayMcp::new(
                    bridge.clone(),
                    owner.clone(),
                    crate::gateway::INSTRUCTIONS.clone(),
                ))
            },
            manager.clone(),
            config,
        );
        let session = Arc::new(Session { sdk, manager, life });
        registry.insert(uuid::Uuid::new_v4(), session.clone());
        Ok(session)
    }
    pub fn status(&self) -> serde_json::Value {
        serde_json::json!({"open": self.retained_sessions()})
    }
    fn admit_session(
        &self,
        principal: &crate::gateway::auth::AuthenticatedGatewayPrincipal,
    ) -> Result<Arc<Session<B>>, HttpError> {
        self.create_session(principal.new_mcp_session_owner().map_err(|_| HttpError)?)
    }
    fn status_headers(&self, response: &mut Response<HeldBody>) {
        response.headers_mut().insert(
            "x-styx-sessions-open",
            self.retained_sessions()
                .to_string()
                .parse()
                .expect("counter header"),
        );
    }
    #[cfg(all(test, target_os = "linux", target_env = "gnu"))]
    pub(crate) async fn collect_closed_sessions_for_test(&self) {
        self.collect_closed();
    }
    fn find_session(&self, id: &str) -> Option<Arc<Session<B>>> {
        self.sessions
            .lock()
            .expect("HTTP sessions")
            .values()
            .find(|s| {
                s.manager
                    .id
                    .lock()
                    .expect("SDK session id")
                    .as_ref()
                    .is_some_and(|x| x.as_ref() == id)
            })
            .cloned()
    }
    pub fn retained_sessions(&self) -> usize {
        self.collect_closed();
        self.sessions
            .lock()
            .expect("HTTP sessions")
            .values()
            .filter(|s| !s.life.is_complete())
            .count()
            + self
                .conversations
                .lock()
                .expect("Tunnel conversations")
                .values()
                .filter(|c| !c.life.is_complete())
                .count()
    }
    fn session_shutdown_facts(&self) -> (bool, usize) {
        let sessions = self.sessions.lock().expect("HTTP sessions");
        let mut transports_joined = true;
        let mut unconfirmed = 0;
        for session in sessions.values() {
            transports_joined &= session.manager.local_transport_quiescent();
            if session.life.facts.lock().expect("session lifetime").cleanup
                != Some(lifecycle::OwnerCleanup::Complete)
            {
                unconfirmed += 1;
            }
        }
        unconfirmed += self
            .conversations
            .lock()
            .expect("Tunnel conversations")
            .values()
            .filter(|c| {
                c.life.facts.lock().expect("conversation lifetime").cleanup
                    != Some(lifecycle::OwnerCleanup::Complete)
            })
            .count();
        (transports_joined, unconfirmed)
    }
    pub(crate) async fn handle(
        self: Arc<Self>,
        request: Request<hyper::body::Incoming>,
    ) -> Result<Response<HeldBody>, Infallible> {
        let response = self.handle_inner(request).await;
        crate::foreground::tunnel::record_gateway_http_status(response.status());
        Ok(response)
    }

    async fn handle_inner<I: Body<Data = Bytes>>(&self, request: Request<I>) -> Response<HeldBody>
    where
        I::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        use http::header::{CACHE_CONTROL, CONTENT_TYPE, WWW_AUTHENTICATE};

        let origin_form = request.uri().query().is_none()
            && request.uri().scheme().is_none()
            && request.uri().authority().is_none();
        let mut response = if request.uri().path() == RESOURCE_METADATA_PATH && origin_form {
            match self
                .policy
                .public_mcp(request.headers())
                .and_then(|public| public.oauth())
            {
                None => plain(StatusCode::NOT_FOUND),
                Some(_) if self.policy.admit_ingress(request.headers()).is_err() => {
                    plain(StatusCode::FORBIDDEN)
                }
                Some(_) if request.method() != Method::GET => plain(StatusCode::METHOD_NOT_ALLOWED),
                Some(oauth) => {
                    let mut response = Response::new(HeldBody::new(
                        Full::new(Bytes::copy_from_slice(&oauth.metadata)).boxed(),
                        None,
                    ));
                    response
                        .headers_mut()
                        .insert(CONTENT_TYPE, "application/json".parse().unwrap());
                    response
                }
            }
        } else if request.uri().path() != MCP_PATH {
            plain(StatusCode::NOT_FOUND)
        } else {
            match self.policy.authorize_mcp(request.headers()).await {
                Ok(principal) => {
                    let mut response = if origin_form {
                        self.handle_authenticated(request, principal).await
                    } else {
                        plain(StatusCode::NOT_FOUND)
                    };
                    self.status_headers(&mut response);
                    response
                }
                Err(GatewayAuthError::Unauthenticated) => {
                    let mut response = plain(StatusCode::UNAUTHORIZED);
                    let challenge = self
                        .policy
                        .public_mcp(request.headers())
                        .and_then(|public| public.oauth())
                        .map_or_else(
                            || http::HeaderValue::from_static("Bearer"),
                            |oauth| oauth.challenge.clone(),
                        );
                    response.headers_mut().insert(WWW_AUTHENTICATE, challenge);
                    response
                }
                Err(GatewayAuthError::AuthorizationUnavailable) => {
                    plain(StatusCode::SERVICE_UNAVAILABLE)
                }
                Err(_) => plain(StatusCode::FORBIDDEN),
            }
        };
        response
            .headers_mut()
            .insert(CACHE_CONTROL, http::HeaderValue::from_static("no-store"));
        response
    }

    async fn handle_authenticated<I: Body<Data = Bytes>>(
        &self,
        request: Request<I>,
        principal: AuthenticatedGatewayPrincipal,
    ) -> Response<HeldBody>
    where
        I::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        if self.stop.is_cancelled() {
            return plain(StatusCode::SERVICE_UNAVAILABLE);
        }
        if !matches!(
            *request.method(),
            Method::GET | Method::POST | Method::DELETE
        ) {
            return plain(StatusCode::METHOD_NOT_ALLOWED);
        }
        let (mut parts, body) = request.into_parts();
        if parts.headers.get_all(SID).iter().count() > 1
            || parts.headers.get_all(VERSION).iter().count() > 1
        {
            return plain(StatusCode::BAD_REQUEST);
        }
        let sid = match parts.headers.get(SID) {
            Some(v) => match v.to_str() {
                Ok(s) if !s.is_empty() && s.len() <= 128 => Some(s.to_owned()),
                _ => return plain(StatusCode::BAD_REQUEST),
            },
            None => None,
        };
        let mut session = match &sid {
            Some(id) => match self.find_session(id) {
                Some(s) if principal.matches_owner(&s.life.owner) && s.life.is_active() => Some(s),
                _ => return plain(StatusCode::NOT_FOUND),
            },
            None => None,
        };
        let header_version = match parts.headers.get(VERSION) {
            Some(v) => match v.to_str() {
                Ok(s) if s.len() <= 32 => Some(s.to_owned()),
                _ => return plain(StatusCode::BAD_REQUEST),
            },
            None => None,
        };
        // Bodyless verbs never queue behind a POST sender. Hyper owns framing;
        // uncertain/positive framing is refused rather than drained indefinitely.
        let bytes = if parts.method != Method::POST {
            let empty_length = parts
                .headers
                .get_all(http::header::CONTENT_LENGTH)
                .iter()
                .all(|v| v == "0");
            if parts.headers.contains_key(http::header::TRANSFER_ENCODING)
                || !empty_length
                || body.size_hint().exact() != Some(0)
                || !body.is_end_stream()
            {
                let mut response = plain(StatusCode::BAD_REQUEST);
                response.headers_mut().insert(
                    http::header::CONNECTION,
                    http::HeaderValue::from_static("close"),
                );
                return response;
            }
            Bytes::new()
        } else {
            #[cfg(test)]
            if let Some(probe) = self
                .admission_probe
                .lock()
                .expect("admission probe")
                .clone()
            {
                probe.body_entered.add_permits(1);
            }
            match tokio::time::timeout(
                Duration::from_secs(5),
                Limited::new(body, MESSAGE_BYTES).collect(),
            )
            .await
            {
                Ok(Ok(b)) => b.to_bytes(),
                Ok(Err(_)) => return plain(StatusCode::PAYLOAD_TOO_LARGE),
                Err(_) => return plain(StatusCode::REQUEST_TIMEOUT),
            }
        };
        let mut conversation_context = None;
        let mut initialize_version = None;
        let mut cancel = false;
        if parts.method == Method::POST {
            let message: ClientJsonRpcMessage = match serde_json::from_slice(&bytes) {
                Ok(m) => m,
                Err(_) => return plain(StatusCode::BAD_REQUEST),
            };
            match &message {
                ClientJsonRpcMessage::Request(r) => match &r.request {
                    ClientRequest::InitializeRequest(r) => {
                        initialize_version = Some(r.params.protocol_version.as_str().to_owned())
                    }
                    ClientRequest::CallToolRequest(_) => {
                        if principal.is_tunnel() {
                            conversation_context =
                                Some(rmcp::model::GetMeta::get_meta(&r.request).clone());
                        }
                        // Only a tool call shows ChatGPT used Styx: the tunnel
                        // client's own startup probe sends initialize/tools/list
                        // with the same forwarding headers. Recorded after bearer
                        // admission; the marker grants no authority.
                        if principal.is_tunnel()
                            && let Some(marker) = parts.headers.get("x-styx-tunnel-observation")
                            && let Some(observation) = self
                                .tunnel_observation
                                .lock()
                                .expect("tunnel observation")
                                .as_ref()
                        {
                            observation.record(marker.as_bytes(), sid.as_deref(), &r.request);
                        }
                    }
                    ClientRequest::PingRequest(_) | ClientRequest::ListToolsRequest(_) => {}
                    _ => return plain(StatusCode::BAD_REQUEST),
                },
                ClientJsonRpcMessage::Notification(n) => match &n.notification {
                    ClientNotification::InitializedNotification(_) => {}
                    ClientNotification::CancelledNotification(_) => cancel = true,
                    _ => return plain(StatusCode::BAD_REQUEST),
                },
                _ => return plain(StatusCode::BAD_REQUEST),
            }
            if sid.is_none() && initialize_version.is_none()
                || sid.is_some() && initialize_version.is_some()
            {
                return plain(StatusCode::BAD_REQUEST);
            }
        } else if sid.is_none() || !bytes.is_empty() {
            return plain(StatusCode::BAD_REQUEST);
        }
        let is_control = parts.method == Method::DELETE || cancel;
        if sid.is_none() {
            session = match self.admit_session(&principal) {
                Ok(s) => Some(s),
                Err(_) => return plain(StatusCode::SERVICE_UNAVAILABLE),
            };
        }
        let Some(session) = session else {
            return plain(StatusCode::BAD_REQUEST);
        };
        if !session.life.is_active() {
            return plain(StatusCode::NOT_FOUND);
        }
        // Exact header shim only after original auth and body/session version binding.
        if header_version.as_deref() == Some(OLDEST) {
            let expected = initialize_version.clone().or_else(|| {
                session
                    .manager
                    .negotiated
                    .lock()
                    .expect("negotiated version")
                    .clone()
            });
            if expected.as_deref() != Some(OLDEST) {
                if sid.is_none() {
                    session
                        .life
                        .facts
                        .lock()
                        .expect("session lifetime")
                        .transport_joined = true;
                    let _ = session.life.close();
                }
                return plain(StatusCode::BAD_REQUEST);
            }
            #[cfg(test)]
            self.oldest_methods.fetch_or(
                match parts.method {
                    Method::POST => 1,
                    Method::GET => 2,
                    Method::DELETE => 4,
                    _ => 0,
                },
                std::sync::atomic::Ordering::AcqRel,
            );
            parts.headers.remove(VERSION);
            parts.extensions.insert(OriginalOldestProtocolHeader);
        } else if let (Some(header), Some(negotiated)) = (
            &header_version,
            session
                .manager
                .negotiated
                .lock()
                .expect("negotiated version")
                .as_ref(),
        ) && header != negotiated
        {
            return plain(StatusCode::BAD_REQUEST);
        }

        if !is_control && !session.life.is_active() {
            return plain(StatusCode::NOT_FOUND);
        }
        #[cfg(test)]
        if is_control {
            let probe = self
                .admission_probe
                .lock()
                .expect("admission probe")
                .clone();
            if let Some(probe) = probe {
                probe.control_entered.add_permits(1);
                probe
                    .release_controls
                    .acquire()
                    .await
                    .expect("probe release")
                    .forget();
            }
        }
        let mut logical_delivery = None;
        if let Some(meta) = conversation_context {
            let call = match self.conversation_call(&principal, &meta) {
                Ok(call) => call,
                Err(status) => return plain(status),
            };
            logical_delivery = Some(call.conversation.life.clone());
            parts.extensions.insert(call);
        }
        let delete = parts.method == Method::DELETE;
        let new_session = sid.is_none();
        // SDK queueing is not evidence that the MCP session has ended.
        // Keep transport lifetime independent from an HTTP response's latency.
        let response = session
            .sdk
            .handle(Request::from_parts(parts, Full::new(bytes)))
            .await;
        if new_session
            && (!response.status().is_success()
                || session
                    .manager
                    .negotiated
                    .lock()
                    .expect("negotiated version")
                    .is_none())
        {
            // Official service returned without ever constructing a worker. This
            // is actual NotCreated evidence, not an invented worker join.
            if session.manager.id.lock().expect("SDK session id").is_none() {
                session
                    .life
                    .facts
                    .lock()
                    .expect("session lifetime")
                    .transport_joined = true;
            }
            let _ = session.life.close();
        }
        let (parts, body) = response.into_parts();
        let mut held = HeldBody::new(body, Some(session.clone()));
        if !delete {
            let life = session.life.clone();
            held.delivery_allowed = Some(Arc::new(move || {
                life.is_active()
                    && logical_delivery
                        .as_ref()
                        .is_none_or(|logical| logical.is_active())
            }));
        }
        Response::from_parts(parts, held)
    }
    /// Lifecycle shutdown for the external strict-TLS listener. This handle
    /// owns no socket; its connections_joined field is not transport evidence.
    pub(crate) fn paired_shutdown_handle(self: &Arc<Self>) -> Arc<HttpServer<B>> {
        Arc::new(HttpServer {
            app: self.clone(),
            listener_task: Mutex::new(None),
            shutdown_lock: tokio::sync::Mutex::new(()),
        })
    }
    /// Only loopback cleartext is supported by this development listener. TLS
    /// profile/listener composition is separate and never silently downgraded.
    pub async fn serve_owned(
        self: Arc<Self>,
        listener: tokio::net::TcpListener,
    ) -> Result<HttpServer<B>, HttpError> {
        if !listener
            .local_addr()
            .map_err(|_| HttpError)?
            .ip()
            .is_loopback()
        {
            return Err(HttpError);
        }
        let this = self.clone();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                while connections.try_join_next().is_some() {}
                let accepted = tokio::select! {_=this.stop.cancelled()=>break,accepted=listener.accept()=>accepted};
                let Ok((stream, _)) = accepted else {
                    break;
                };
                let app = this.clone();
                let stop = this.stop.clone();
                connections.spawn(async move {
                    let service=hyper::service::service_fn(move|request|app.clone().handle(request));
                    let mut builder=hyper::server::conn::http1::Builder::new();
                    builder.max_headers(64).max_buf_size(16*1024).header_read_timeout(Duration::from_secs(5)).timer(hyper_util::rt::TokioTimer::new());
                    let connection=builder.serve_connection(hyper_util::rt::TokioIo::new(stream),service);
                    tokio::pin!(connection);
                    tokio::select!{_=stop.cancelled()=>{connection.as_mut().graceful_shutdown();let _=tokio::time::timeout(Duration::from_secs(1),connection).await;},_= &mut connection=>{}}
                });
            }
            while connections.join_next().await.is_some() {}
        });
        Ok(HttpServer {
            app: self,
            listener_task: Mutex::new(Some(task)),
            shutdown_lock: tokio::sync::Mutex::new(()),
        })
    }
}
pub struct HttpServer<B: GatewayToolBackend + GatewayOwnerLifecycle> {
    app: Arc<GatewayHttp<B>>,
    listener_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    shutdown_lock: tokio::sync::Mutex<()>,
}
impl<B: GatewayToolBackend + GatewayOwnerLifecycle> HttpServer<B> {
    pub async fn shutdown(&self, budget: Duration) -> HttpShutdown {
        let until = tokio::time::Instant::now() + budget.min(Duration::from_secs(30));
        let Ok(_shutdown) = tokio::time::timeout_at(until, self.shutdown_lock.lock()).await else {
            return HttpShutdown {
                connections_joined: false,
                lifecycle_jobs_joined: false,
                session_transports_joined: self.app.session_shutdown_facts().0,
                unconfirmed_owner_cleanups: self.app.session_shutdown_facts().1,
                worker_failure_observed: self
                    .app
                    .supervisor
                    .worker_failure_observed
                    .load(std::sync::atomic::Ordering::Acquire),
                unresolved_sessions: self.app.retained_sessions(),
                sdk_detached_tasks_joined: None,
            };
        };
        self.app.stop.cancel();
        let idle = self
            .app
            .collection_task
            .lock()
            .expect("session collector")
            .take();
        let mut idle_joined = true;
        if let Some(mut idle) = idle {
            match tokio::time::timeout_at(until, &mut idle).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => {
                    self.app
                        .supervisor
                        .worker_failure_observed
                        .store(true, std::sync::atomic::Ordering::Release);
                }
                Err(_) => {
                    idle_joined = false;
                    *self.app.collection_task.lock().expect("session collector") = Some(idle);
                }
            }
        }
        for session in self.app.sessions.lock().expect("HTTP sessions").values() {
            let _ = session.life.close();
        }
        self.app.close_conversations();
        // Cancellation wakes SDK workers, whose actual close joins run on the
        // SDK task. Observe those joins before the final shutdown snapshot.
        loop {
            let quiet = {
                let sessions = self.app.sessions.lock().expect("HTTP sessions");
                for s in sessions.values() {
                    if s.manager.local_transport_quiescent()
                        && s.manager.id.lock().expect("SDK session id").is_none()
                    {
                        s.life
                            .facts
                            .lock()
                            .expect("session lifetime")
                            .transport_joined = true;
                    }
                }
                sessions
                    .values()
                    .all(|s| s.manager.local_transport_quiescent())
            };
            if quiet || tokio::time::Instant::now() >= until {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        {
            // All initial closes above registered under facts -> jobs. Prevent
            // a late SDK close retry from spawning after the final join sample.
            let _jobs = self.app.supervisor.jobs.lock().expect("HTTP cleanup jobs");
            self.app
                .supervisor
                .accepting_cleanup_jobs
                .store(false, std::sync::atomic::Ordering::Release);
        }
        let task = self
            .listener_task
            .lock()
            .expect("HTTP listener task")
            .take();
        let mut joined = true;
        if let Some(mut task) = task {
            match tokio::time::timeout_at(until, &mut task).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => {
                    // A panicked task terminated; its failure is not a live job.
                    self.app
                        .supervisor
                        .worker_failure_observed
                        .store(true, std::sync::atomic::Ordering::Release);
                }
                Err(_) => {
                    joined = false;
                    *self.listener_task.lock().expect("HTTP listener task") = Some(task);
                }
            }
        }
        let mut sets = std::mem::take(
            &mut *self
                .app
                .supervisor
                .parked
                .lock()
                .expect("parked cleanup jobs"),
        );
        sets.push(std::mem::replace(
            &mut *self.app.supervisor.jobs.lock().expect("HTTP cleanup jobs"),
            JoinSet::new(),
        ));
        let mut jobs_joined = idle_joined;
        let mut parked = vec![];
        for mut jobs in sets {
            while !jobs.is_empty() {
                match tokio::time::timeout_at(until, jobs.join_next()).await {
                    Ok(Some(Ok(()))) => {}
                    Ok(Some(Err(_))) => {
                        self.app
                            .supervisor
                            .worker_failure_observed
                            .store(true, std::sync::atomic::Ordering::Release);
                    }
                    Ok(None) => break,
                    _ => {
                        jobs_joined = false;
                        break;
                    }
                }
            }
            if !jobs.is_empty() {
                parked.push(jobs);
            }
        }
        self.app
            .supervisor
            .parked
            .lock()
            .expect("parked cleanup jobs")
            .extend(parked);
        // Late SDK close/reconciliation may register cleanup in the new set.
        // Never overwrite/drop it with the old drained set.
        {
            let mut fresh = self.app.supervisor.jobs.lock().expect("HTTP cleanup jobs");
            while let Some(result) = fresh.try_join_next() {
                if result.is_err() {
                    self.app
                        .supervisor
                        .worker_failure_observed
                        .store(true, std::sync::atomic::Ordering::Release);
                }
            }
            if !fresh.is_empty() {
                jobs_joined = false;
            }
        }
        let (session_transports_joined, unconfirmed_owner_cleanups) =
            self.app.session_shutdown_facts();
        // SDK handler Arcs can outlive their observed worker join by a few
        // scheduler turns. Collect completed sessions without claiming SDK
        // detached-task joins or dropping Unknown cleanup ownership.
        if jobs_joined && session_transports_joined && unconfirmed_owner_cleanups == 0 {
            while self.app.retained_sessions() != 0 && tokio::time::Instant::now() < until {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
        let unresolved = self.app.retained_sessions();
        HttpShutdown {
            connections_joined: joined,
            lifecycle_jobs_joined: jobs_joined,
            session_transports_joined,
            unconfirmed_owner_cleanups,
            worker_failure_observed: self
                .app
                .supervisor
                .worker_failure_observed
                .load(std::sync::atomic::Ordering::Acquire),
            unresolved_sessions: unresolved,
            sdk_detached_tasks_joined: None,
        }
    }
}
impl<B: GatewayToolBackend + GatewayOwnerLifecycle> Drop for HttpServer<B> {
    fn drop(&mut self) {
        self.app.stop.cancel();
        for s in self.app.sessions.lock().expect("HTTP sessions").values() {
            let _ = s.life.close();
        }
        self.app.close_conversations();
    }
}
fn plain(status: StatusCode) -> Response<HeldBody> {
    let mut r = Response::new(HeldBody::new(Full::new(Bytes::new()).boxed(), None));
    *r.status_mut() = status;
    r
}

#[cfg(test)]
mod tests;

#[cfg(all(test, target_os = "linux", target_env = "gnu"))]
mod lan_tests;

#[cfg(test)]
mod slow_dispatch_tests;
