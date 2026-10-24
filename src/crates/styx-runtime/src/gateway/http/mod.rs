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
const SESSION_BYTES: usize = 4 * 1024 * 1024;
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
        if !(FIXED_BYTES + SESSION_BYTES..=styx_contracts::HOST_QUEUED_BYTES).contains(&bytes)
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
}
pub struct GatewayHttp<B: GatewayToolBackend + GatewayOwnerLifecycle> {
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
        Arc::new(Self {
            policy,
            backend,
            budget,
            sessions: Mutex::new(BTreeMap::new()),
            requests: Arc::new(Semaphore::new(16)),
            body_readers: Arc::new(Semaphore::new(16)),
            control: Arc::new(Semaphore::new(2)),
            connections: Arc::new(Semaphore::new(32)),
            supervisor: Arc::new(Supervisor {
                jobs: Mutex::new(JoinSet::new()),
                parked: Mutex::new(vec![]),
                worker_failure_observed: std::sync::atomic::AtomicBool::new(false),
                accepting_cleanup_jobs: std::sync::atomic::AtomicBool::new(true),
            }),
            stop: CancellationToken::new(),
            #[cfg(test)]
            oldest_methods: std::sync::atomic::AtomicU8::new(0),
            #[cfg(test)]
            admission_probe: Mutex::new(None),
        })
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
            return Err(HttpError);
        }
        let slot = self
            .budget
            .sessions
            .clone()
            .try_acquire_owned()
            .map_err(|_| HttpError)?;
        let life = Arc::new(Life {
            owner: owner.clone(),
            lifecycle: self.backend.clone(),
            facts: Mutex::new(CloseFacts::default()),
            cancellation: Mutex::new(None),
            supervisor: Arc::downgrade(&self.supervisor),
            _session_slot: slot,
            _budget: self.budget.clone(),
        });
        let manager = Arc::new(BoundedManager::new(life.clone()));
        let bridge = Arc::new(BackendBridge {
            backend: self.backend.clone(),
            life: life.clone(),
            calls: Arc::new(Semaphore::new(1)),
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
        });
        registry.insert(uuid::Uuid::new_v4(), session.clone());
        Ok(session)
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
        Ok(self.handle_inner(request).await)
    }
    async fn handle_inner(&self, request: Request<hyper::body::Incoming>) -> Response<HeldBody> {
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
                    ClientRequest::PingRequest(_)
                    | ClientRequest::ListToolsRequest(_)
                    | ClientRequest::CallToolRequest(_) => {}
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
        // Exactly one global control reservation. GET is bounded separately by
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
            session = match self.create_session(principal.new_mcp_session_owner()) {
                Ok(s) => Some(s),
                Err(_) => return plain(StatusCode::TOO_MANY_REQUESTS),
            };
        }
        let Some(session) = session else {
            return plain(StatusCode::BAD_REQUEST);
        };
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
            Some(session.get.clone().try_acquire_owned())
        } else if !is_control {
            Some(session.post.clone().try_acquire_owned())
        } else {
            None
        };
        let session_permit = match session_permit {
            Some(Ok(p)) => Some(p),
            Some(Err(_)) => return plain(StatusCode::TOO_MANY_REQUESTS),
            None => None,
        };
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
        let response = match tokio::time::timeout(
            Duration::from_secs(5),
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
            Some(session.clone()),
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
        for session in self.app.sessions.lock().expect("HTTP sessions").values() {
            let _ = session.life.close();
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
        let mut jobs_joined = true;
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
