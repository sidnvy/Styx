//! Bounded development HTTP/MCP slice. Official SDK owns HTTP MCP and SSE.
//! No native tools, real-account identity or production TLS acceptance is implied.
mod backend;
pub(crate) mod body;
pub mod lifecycle;
mod session;
use crate::gateway::{
    auth::{GatewayBearerPolicy, VerifiedGatewayOwner},
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
use session::BoundedManager;
use std::{
    collections::BTreeMap,
    convert::Infallible,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

pub const MESSAGE_BYTES: usize = 256 * 1024;
const SESSION_BYTES: usize = 1536 * 1024;
/// HTTP queue reservation, independent of Host and relay allocations.
pub const GATEWAY_HTTP_BYTES: usize = FIXED_BYTES + 64 * SESSION_BYTES;
const MAX_HTTP_BYTES: usize = 128 * 1024 * 1024;
const SESSION_IDLE: Duration = Duration::from_secs(600);
const SESSION_EVICT_MIN_IDLE: Duration = Duration::from_secs(60);
const FIXED_BYTES: usize = 8 * 1024 * 1024;
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
#[error("HTTP configuration or capacity refused")]
pub struct HttpError;
/// Must originate in the bootstrap's shared process allocator. This is a logical
/// wire/queue reservation, not an allocator/RSS ceiling.
pub struct HttpBudget {
    _partition: OwnedSemaphorePermit,
    sessions: Arc<Semaphore>,
    capacity: usize,
}
impl HttpBudget {
    pub fn from_reserved_partition(
        partition: OwnedSemaphorePermit,
    ) -> Result<Arc<Self>, HttpError> {
        let bytes = partition.num_permits();
        if !(FIXED_BYTES + SESSION_BYTES..=MAX_HTTP_BYTES).contains(&bytes)
            || !(bytes - FIXED_BYTES).is_multiple_of(SESSION_BYTES)
        {
            return Err(HttpError);
        }
        Ok(Arc::new(Self {
            _partition: partition,
            sessions: Arc::new(Semaphore::new((bytes - FIXED_BYTES) / SESSION_BYTES)),
            capacity: (bytes - FIXED_BYTES) / SESSION_BYTES,
        }))
    }
}
struct Session<B: GatewayToolBackend + GatewayOwnerLifecycle> {
    sdk: StreamableHttpService<GatewayMcp<BackendBridge<B>>, BoundedManager<B>>,
    manager: Arc<BoundedManager<B>>,
    life: Arc<Life<B>>,
    post: Arc<Semaphore>,
    get: Arc<Semaphore>,
    calls: Arc<Semaphore>,
}
pub struct GatewayHttp<B: GatewayToolBackend + GatewayOwnerLifecycle> {
    tunnel_observation: Mutex<Option<Arc<crate::foreground::tunnel::RequestObservation>>>,
    policy: Arc<GatewayBearerPolicy>,
    backend: Arc<B>,
    budget: Arc<HttpBudget>,
    sessions: Mutex<BTreeMap<uuid::Uuid, Arc<Session<B>>>>,
    requests: Arc<Semaphore>,
    body_readers: Arc<Semaphore>,
    control: Arc<Semaphore>,
    connections: Arc<Semaphore>,
    supervisor: Arc<Supervisor>,
    stop: CancellationToken,
    idle_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    expired: std::sync::atomic::AtomicU64,
    evicted: std::sync::atomic::AtomicU64,
    admission: tokio::sync::Mutex<()>,
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
    pub fn new(
        policy: Arc<GatewayBearerPolicy>,
        backend: Arc<B>,
        budget: Arc<HttpBudget>,
    ) -> Arc<Self> {
        let app = Arc::new(Self {
            tunnel_observation: Mutex::new(None),
            policy,
            backend,
            budget,
            sessions: Mutex::new(BTreeMap::new()),
            requests: Arc::new(Semaphore::new(16)),
            body_readers: Arc::new(Semaphore::new(16)),
            control: Arc::new(Semaphore::new(2)),
            connections: Arc::new(Semaphore::new(128)),
            supervisor: Arc::new(Supervisor {
                jobs: Mutex::new(JoinSet::new()),
                parked: Mutex::new(vec![]),
                worker_failure_observed: std::sync::atomic::AtomicBool::new(false),
                accepting_cleanup_jobs: std::sync::atomic::AtomicBool::new(true),
            }),
            stop: CancellationToken::new(),
            idle_task: Mutex::new(None),
            expired: std::sync::atomic::AtomicU64::new(0),
            evicted: std::sync::atomic::AtomicU64::new(0),
            admission: tokio::sync::Mutex::new(()),
            #[cfg(test)]
            oldest_methods: std::sync::atomic::AtomicU8::new(0),
            #[cfg(test)]
            admission_probe: Mutex::new(None),
        });
        let weak = Arc::downgrade(&app);
        let stop = app.stop.clone();
        *app.idle_task.lock().expect("idle supervisor") = Some(tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(15));
            loop {
                tokio::select! {
                    _ = stop.cancelled() => break,
                    _ = tick.tick() => {
                        let Some(app) = weak.upgrade() else { break; };
                        tokio::select! {
                            _ = stop.cancelled() => break,
                            _ = app.expire_idle(SESSION_IDLE) => {}
                        }
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
    }
    fn create_session(&self, owner: VerifiedGatewayOwner) -> Result<Arc<Session<B>>, HttpError> {
        self.collect_closed();
        let mut registry = self.sessions.lock().expect("HTTP sessions");
        if self.stop.is_cancelled() {
            owner.cleanup_complete();
            return Err(HttpError);
        }
        let slot = match self.budget.sessions.clone().try_acquire_owned() {
            Ok(slot) => slot,
            Err(_) => {
                owner.cleanup_complete();
                return Err(HttpError);
            }
        };
        let life = Arc::new(Life {
            activity: Mutex::new(lifecycle::Activity {
                last: tokio::time::Instant::now(),
                users: 0,
            }),
            owner: owner.clone(),
            lifecycle: self.backend.clone(),
            facts: Mutex::new(CloseFacts::default()),
            changed: tokio::sync::Notify::new(),
            cancellation: Mutex::new(None),
            supervisor: Arc::downgrade(&self.supervisor),
            _session_slot: slot,
            _budget: self.budget.clone(),
        });
        let manager = Arc::new(BoundedManager::new(life.clone()));
        let calls = Arc::new(Semaphore::new(1));
        let bridge = Arc::new(BackendBridge {
            backend: self.backend.clone(),
            life: life.clone(),
            calls: calls.clone(),
            #[cfg(test)]
            before_register: Mutex::new(None),
        });
        let mut config = StreamableHttpServerConfig::default();
        config.max_request_body_bytes = MESSAGE_BYTES;
        config.sse_retry = None;
        config.sse_keep_alive = Some(Duration::from_secs(10));
        config.session_store = None;
        // Outer original-header GatewayBearerPolicy is authoritative and stricter.
        // SDK retains its default loopback guard in this loopback-only development slice.
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
        let session = Arc::new(Session {
            sdk,
            manager,
            life,
            post: Arc::new(Semaphore::new(1)),
            get: Arc::new(Semaphore::new(1)),
            calls,
        });
        registry.insert(uuid::Uuid::new_v4(), session.clone());
        Ok(session)
    }
    pub fn status(&self) -> serde_json::Value {
        serde_json::json!({"open":self.retained_sessions(),"capacity":self.budget.capacity,
            "expired":self.expired.load(std::sync::atomic::Ordering::Relaxed),
            "evicted":self.evicted.load(std::sync::atomic::Ordering::Relaxed),
            "reservation_bytes":self.budget._partition.num_permits()})
    }
    fn idle_candidate(&self, minimum: Duration) -> Option<Arc<Session<B>>> {
        self.collect_closed();
        self.sessions
            .lock()
            .expect("HTTP sessions")
            .values()
            .filter_map(|s| {
                let a = s.life.activity.lock().expect("session activity");
                (a.users == 0
                    && a.last.elapsed() >= minimum
                    && s.life.is_active()
                    && s.calls.available_permits() == 1)
                    .then(|| (a.last, s.clone()))
            })
            .filter(|(_, s)| !self.backend.owner_has_live_work(&s.life.owner))
            .min_by_key(|(last, _)| *last)
            .map(|(_, s)| s)
    }
    async fn close_idle(&self, session: Arc<Session<B>>, minimum: Duration, expired: bool) -> bool {
        {
            let a = session.life.activity.lock().expect("session activity");
            if a.users != 0
                || session.calls.available_permits() != 1
                || a.last.elapsed() < minimum
                || !session.life.is_active()
                || self.backend.owner_has_live_work(&session.life.owner)
            {
                return false;
            }
            if session.life.close().is_err() {
                return false;
            }
            (if expired {
                &self.expired
            } else {
                &self.evicted
            })
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        session.manager.close_idle().await.is_ok()
    }
    async fn expire_idle(&self, minimum: Duration) {
        while let Some(session) = self.idle_candidate(minimum) {
            self.close_idle(session, minimum, true).await;
            if self.stop.is_cancelled() {
                break;
            }
        }
        self.collect_closed();
    }
    async fn admit_session(
        &self,
        principal: &crate::gateway::auth::AuthenticatedGatewayPrincipal,
    ) -> Result<Arc<Session<B>>, HttpError> {
        let until = tokio::time::Instant::now() + Duration::from_secs(5);
        let _gate = tokio::time::timeout_at(until, self.admission.lock())
            .await
            .map_err(|_| HttpError)?;
        self.collect_closed();
        if self.budget.sessions.available_permits() == 0 {
            let candidate = self
                .idle_candidate(SESSION_EVICT_MIN_IDLE)
                .ok_or(HttpError)?;
            tokio::time::timeout_at(
                until,
                self.close_idle(candidate, SESSION_EVICT_MIN_IDLE, false),
            )
            .await
            .map_err(|_| HttpError)?;
            loop {
                self.collect_closed();
                if self.budget.sessions.available_permits() > 0 {
                    break;
                }
                if tokio::time::Instant::now() >= until {
                    return Err(HttpError);
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
        self.create_session(principal.new_mcp_session_owner().map_err(|_| HttpError)?)
    }
    fn status_headers(&self, response: &mut Response<HeldBody>) {
        for (key, value) in [
            ("x-styx-sessions-open", self.retained_sessions() as u64),
            ("x-styx-sessions-capacity", self.budget.capacity as u64),
            (
                "x-styx-sessions-expired",
                self.expired.load(std::sync::atomic::Ordering::Relaxed),
            ),
            (
                "x-styx-sessions-evicted",
                self.evicted.load(std::sync::atomic::Ordering::Relaxed),
            ),
        ] {
            response
                .headers_mut()
                .insert(key, value.to_string().parse().expect("counter header"));
        }
    }
    #[cfg(all(test, target_os = "linux", target_env = "gnu"))]
    pub(crate) fn age_idle_sessions_for_test(&self, duration: Duration) {
        for s in self.sessions.lock().expect("HTTP sessions").values() {
            let mut a = s.life.activity.lock().expect("session activity");
            if a.users == 0 {
                a.last -= duration;
            }
        }
    }
    #[cfg(all(test, target_os = "linux", target_env = "gnu"))]
    pub(crate) async fn expire_idle_for_test(&self) {
        self.expire_idle(SESSION_IDLE).await;
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
        // Registry removal is not proof detached SDK handlers ended. Their
        // Arc<Life> retains the real reservation until the last owner drops.
        self.budget.capacity - self.budget.sessions.available_permits()
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
        (transports_joined, unconfirmed)
    }
    pub(crate) async fn handle(
        self: Arc<Self>,
        request: Request<hyper::body::Incoming>,
    ) -> Result<Response<HeldBody>, Infallible> {
        let authorized = self.policy.authorize(request.headers()).is_ok();
        let mut response = self.handle_inner(request).await;
        if authorized {
            self.status_headers(&mut response);
        }
        Ok(response)
    }
    async fn handle_inner<I: Body<Data = Bytes>>(&self, request: Request<I>) -> Response<HeldBody>
    where
        I::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let principal = match self.policy.authorize(request.headers()) {
            Ok(p) => p,
            Err(crate::gateway::auth::GatewayAuthError::Unauthenticated) => {
                return plain(StatusCode::UNAUTHORIZED);
            }
            Err(_) => return plain(StatusCode::FORBIDDEN),
        };
        if self.stop.is_cancelled() {
            return plain(StatusCode::SERVICE_UNAVAILABLE);
        }
        if request.uri().path() != "/mcp" || request.uri().query().is_some() {
            return plain(StatusCode::NOT_FOUND);
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
        let mut activity = match &session {
            Some(s) => match s.life.activity() {
                Some(a) => Some(a),
                None => return plain(StatusCode::NOT_FOUND),
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
            let _body_permit = match self.body_readers.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => return plain(StatusCode::TOO_MANY_REQUESTS),
            };
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
                        // Only a tool call shows ChatGPT used Styx: the tunnel
                        // client's own startup probe sends initialize/tools/list
                        // with the same forwarding headers. Recorded after bearer
                        // admission; the marker grants no authority.
                        if let Some(marker) = parts.headers.get("x-styx-tunnel-observation")
                            && let Some(observation) = self
                                .tunnel_observation
                                .lock()
                                .expect("tunnel observation")
                                .as_ref()
                        {
                            observation.record(marker.as_bytes());
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
        // Two global control reservations. GET is bounded separately by
        // one stream per retained session and does not consume POST capacity.
        let request_permit = if parts.method == Method::GET {
            None
        } else {
            let semaphore = if is_control {
                self.control.clone()
            } else {
                self.requests.clone()
            };
            match semaphore.try_acquire_owned() {
                Ok(p) => Some(p),
                Err(_) => return plain(StatusCode::TOO_MANY_REQUESTS),
            }
        };
        if sid.is_none() {
            session = match self.admit_session(&principal).await {
                Ok(s) => Some(s),
                Err(_) => return plain(StatusCode::TOO_MANY_REQUESTS),
            };
        }
        let Some(session) = session else {
            return plain(StatusCode::BAD_REQUEST);
        };
        if activity.is_none() {
            activity = session.life.activity();
        }
        let request_until = tokio::time::Instant::now() + Duration::from_secs(5);
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
        let session_permit = if parts.method == Method::GET {
            match session.get.clone().try_acquire_owned() {
                Ok(p) => Some(p),
                Err(_) => return plain(StatusCode::TOO_MANY_REQUESTS),
            }
        } else if !is_control {
            match tokio::time::timeout_at(request_until, session.post.clone().acquire_owned()).await
            {
                Ok(Ok(p)) => Some(p),
                _ => return plain(StatusCode::REQUEST_TIMEOUT),
            }
        } else {
            None
        };
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
        let delete = parts.method == Method::DELETE;
        let new_session = sid.is_none();
        let response = match tokio::time::timeout_at(
            request_until,
            session
                .sdk
                .handle(Request::from_parts(parts, Full::new(bytes))),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => {
                if session.manager.id.lock().expect("SDK session id").is_none() {
                    session
                        .life
                        .facts
                        .lock()
                        .expect("session lifetime")
                        .transport_joined = true;
                }
                let _ = session.life.close();
                return plain(StatusCode::GATEWAY_TIMEOUT);
            }
        };
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
        let mut held = HeldBody::new(
            body,
            request_permit.into_iter().chain(session_permit).collect(),
            Some(Arc::new((session.clone(), activity))),
        );
        if !delete {
            let life = session.life.clone();
            held.delivery_allowed = Some(Arc::new(move || life.is_active()));
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
                let Ok(slot) = this.connections.clone().try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                let app = this.clone();
                let stop = this.stop.clone();
                connections.spawn(async move {
                    let _slot=slot;
                    let service=hyper::service::service_fn(move|request|app.clone().handle(request));
                    let mut builder=hyper::server::conn::http1::Builder::new();
                    builder.max_headers(64).max_buf_size(16*1024).header_read_timeout(Duration::from_secs(5)).timer(hyper_util::rt::TokioTimer::new());
                    let connection=builder.serve_connection(hyper_util::rt::TokioIo::new(stream),service);
                    tokio::pin!(connection);
                    tokio::select!{_=stop.cancelled()=>{connection.as_mut().graceful_shutdown();let _=tokio::time::timeout(Duration::from_secs(1),connection).await;},_= &mut connection=>{},_=tokio::time::sleep(Duration::from_secs(120))=>{connection.as_mut().graceful_shutdown();let _=tokio::time::timeout(Duration::from_secs(1),connection).await;}}
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
        let idle = self.app.idle_task.lock().expect("idle supervisor").take();
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
                    *self.app.idle_task.lock().expect("idle supervisor") = Some(idle);
                }
            }
        }
        for session in self.app.sessions.lock().expect("HTTP sessions").values() {
            let _ = session.life.close();
        }
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
        // scheduler turns. Observe reservation release, without claiming SDK
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
    }
}
fn plain(status: StatusCode) -> Response<HeldBody> {
    let mut r = Response::new(HeldBody::new(Full::new(Bytes::new()).boxed(), vec![], None));
    *r.status_mut() = status;
    r
}

#[cfg(test)]
mod tests;

#[cfg(all(test, target_os = "linux", target_env = "gnu"))]
mod lan_tests;
