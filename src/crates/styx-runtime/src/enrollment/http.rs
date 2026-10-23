//! Strict TLS enrollment transport. Service owns all role/domain authorization.
//! Counts bound this listener's work, not native RSS or a shared Host partition.
use super::service::EnrollmentService;
use crate::tls::GatewayServerTls;
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body::Body;
use http_body_util::{BodyExt, Full, Limited};
use std::{
    collections::BTreeSet,
    convert::Infallible,
    io::Write,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use styx_contracts::{
    enrollment::PairingContext,
    identity::{PairingIngressGeneration, Sha256Digest},
};
use tokio::{
    net::TcpListener,
    sync::{OwnedSemaphorePermit, Semaphore, oneshot},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

const CONNECTIONS: usize = 16;
const REQUESTS: usize = 8;
const BODY_BYTES: usize = 16 * 1024;
const RESPONSE_BYTES: usize = 1024 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const WORK_WAIT: Duration = Duration::from_secs(30);
type HttpResponse = Response<Full<Bytes>>;
type PublicFailure = (u16, &'static str);

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("enrollment listener configuration refused")]
    Configuration,
    #[error("enrollment listener was already run")]
    AlreadyRun,
}
#[derive(Debug)]
pub struct ShutdownFacts {
    pub connections_joined: bool,
    pub blocking_jobs_joined: bool,
    pub blocking_slots_in_use: usize,
    pub worker_failure_observed: bool,
    pub listener_error_observed: bool,
}
pub struct EnrollmentHttp {
    tls: Arc<GatewayServerTls>,
    service: Arc<Mutex<EnrollmentService>>,
    allowed_hosts: BTreeSet<String>,
    leaf: Sha256Digest,
    ingress: PairingIngressGeneration,
    connections: Arc<Semaphore>,
    requests: Arc<Semaphore>,
    // Dropping a JoinHandle detaches rather than cancelling a blocking job.
    // Each closure also retains this owner until its actual work is complete.
    workers: Mutex<Vec<JoinHandle<()>>>,
    worker_failure: AtomicBool,
    listener_failure: AtomicBool,
    join_lock: tokio::sync::Mutex<()>,
    run_once: AtomicBool,
    transport_quiescent: AtomicBool,
}
impl EnrollmentHttp {
    pub fn new(
        tls: Arc<GatewayServerTls>,
        service: EnrollmentService,
        allowed_hosts: Vec<String>,
    ) -> Result<Arc<Self>, HttpError> {
        if allowed_hosts.is_empty()
            || allowed_hosts.len() > 16
            || allowed_hosts.iter().any(|host| !valid_host(host))
        {
            return Err(HttpError::Configuration);
        }
        let leaf = Sha256Digest::try_from(tls.certificate_pin().as_hex())
            .map_err(|_| HttpError::Configuration)?;
        let ingress = PairingIngressGeneration::try_from(format!(
            "enrollment-listener-{}",
            uuid::Uuid::new_v4()
        ))
        .map_err(|_| HttpError::Configuration)?;
        Ok(Arc::new(Self {
            tls,
            service: Arc::new(Mutex::new(service)),
            allowed_hosts: allowed_hosts.into_iter().collect(),
            leaf,
            ingress,
            connections: Arc::new(Semaphore::new(CONNECTIONS)),
            requests: Arc::new(Semaphore::new(REQUESTS)),
            workers: Mutex::new(vec![]),
            worker_failure: AtomicBool::new(false),
            listener_failure: AtomicBool::new(false),
            join_lock: tokio::sync::Mutex::new(()),
            run_once: AtomicBool::new(false),
            transport_quiescent: AtomicBool::new(false),
        }))
    }
    /// Test-only same-state observation/admission seam; never an HTTP route.
    #[cfg(test)]
    pub(super) fn with_service<T>(&self, operation: impl FnOnce(&mut EnrollmentService) -> T) -> T {
        operation(&mut self.service.lock().expect("test-only enrollment service"))
    }
    fn spawn_work(self: &Arc<Self>, work: impl FnOnce() + Send + 'static) {
        use futures_util::FutureExt;
        let mut workers = self.workers.lock().expect("enrollment worker registry");
        let mut active = Vec::with_capacity(REQUESTS);
        for handle in workers.drain(..) {
            if handle.is_finished() {
                if !matches!(handle.now_or_never(), Some(Ok(()))) {
                    self.worker_failure.store(true, Ordering::Release);
                }
            } else {
                active.push(handle);
            }
        }
        active.push(tokio::task::spawn_blocking(work));
        *workers = active;
    }
    async fn handle(self: Arc<Self>, request: Request<hyper::body::Incoming>) -> HttpResponse {
        let (parts, body) = request.into_parts();
        if parts.uri.query().is_some()
            || parts.uri.scheme().is_some()
            || parts.uri.authority().is_some()
        {
            return failure(404, "not_found", true);
        }
        let path = parts.uri.path().to_owned();
        match expected_method(&path) {
            None => return failure(404, "not_found", true),
            Some(method)
                if method != parts.method
                    && !(parts.method == Method::POST
                        && path.starts_with("/styx/enroll/self/")) =>
            {
                return failure(405, "method_not_allowed", true);
            }
            _ => {}
        }
        if parts.headers.contains_key(http::header::ORIGIN)
            || parts.headers.get_all(http::header::HOST).iter().count() != 1
        {
            return failure(403, "host_or_origin_not_allowed", true);
        }
        let host = match parts
            .headers
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
        {
            Some(host) if self.allowed_hosts.contains(host) => host.to_owned(),
            _ => return failure(403, "host_or_origin_not_allowed", true),
        };
        let pairing = PairingContext {
            origin: format!("https://{host}"),
            leaf: self.leaf,
            ingress_generation: self.ingress.clone(),
            window: None,
        };
        let permit = match self.requests.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => return failure(429, "enrollment_capacity", true),
        };
        let (method, headers) = (parts.method, parts.headers);
        // This is only an early rejection. request() rechecks complete headers,
        // original device authority and Core state after the full body is read.
        let (send, receive) = oneshot::channel();
        let app = self.clone();
        let (pre_method, pre_path, pre_headers, pre_pairing) = (
            method.clone(),
            path.clone(),
            headers.clone(),
            pairing.clone(),
        );
        self.spawn_work(move || {
            let result = match app.service.lock() {
                Ok(service) => service
                    .preflight(&pre_method, &pre_path, &pre_headers, &pre_pairing)
                    .map_err(|e| (e.status(), e.code())),
                Err(_) => Err((503, "enrollment_outcome_unknown")),
            };
            let _ = send.send((permit, result));
        });
        let permit = match tokio::time::timeout(IO_TIMEOUT, receive).await {
            Ok(Ok((permit, Ok(())))) => permit,
            Ok(Ok((_, Err((status, code))))) => return failure(status, code, true),
            _ => return failure(503, "enrollment_outcome_unknown", true),
        };
        let bytes = if method == Method::GET {
            if headers.contains_key(http::header::TRANSFER_ENCODING)
                || headers
                    .get_all(http::header::CONTENT_LENGTH)
                    .iter()
                    .any(|v| v != "0")
                || body.size_hint().exact() != Some(0)
                || !body.is_end_stream()
            {
                return failure(400, "bodyless_request_required", true);
            }
            Bytes::new()
        } else {
            if headers.get_all(http::header::CONTENT_TYPE).iter().count() != 1
                || headers
                    .get(http::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.split(';').next())
                    .is_none_or(|s| !s.trim().eq_ignore_ascii_case("application/json"))
            {
                return failure(415, "json_content_type_required", true);
            }
            match tokio::time::timeout(IO_TIMEOUT, Limited::new(body, BODY_BYTES).collect()).await {
                Ok(Ok(bytes)) => bytes.to_bytes(),
                Ok(Err(_)) => return failure(413, "body_too_large", true),
                Err(_) => return failure(408, "request_timeout", true),
            }
        };
        let (send, receive) = oneshot::channel();
        let app = self.clone();
        self.spawn_work(move || {
            // Permit remains with actual work even if its HTTP waiter vanishes.
            let _permit: OwnedSemaphorePermit = permit;
            let result: Result<(u16, serde_json::Value), PublicFailure> = match app.service.lock() {
                Ok(mut service) => service
                    .request(&method, &path, &headers, &bytes, &pairing)
                    .map_err(|e| (e.status(), e.code())),
                Err(_) => Err((503, "enrollment_outcome_unknown")),
            };
            let response = match result {
                Ok((status, value)) => match encode_response(&value) {
                    Ok(bytes) => response(status, bytes, false),
                    Err(()) => failure(503, "enrollment_outcome_unknown", true),
                },
                Err((status, code)) => failure(status, code, false),
            };
            let _ = send.send(response);
        });
        match tokio::time::timeout(WORK_WAIT, receive).await {
            Ok(Ok(response)) => response,
            _ => failure(503, "enrollment_outcome_unknown", true),
        }
    }
    /// Single listener lifetime; no plaintext path and no transparent restart.
    pub async fn run(
        self: Arc<Self>,
        listener: TcpListener,
        cancel: CancellationToken,
    ) -> Result<ShutdownFacts, HttpError> {
        if self.run_once.swap(true, Ordering::AcqRel) {
            return Err(HttpError::AlreadyRun);
        }
        let mut connections = tokio::task::JoinSet::new();
        loop {
            while let Some(result) = connections.try_join_next() {
                if result.is_err() {
                    self.worker_failure.store(true, Ordering::Release);
                }
            }
            let accepted = tokio::select! { _ = cancel.cancelled() => break, accepted = listener.accept() => accepted };
            let (tcp, _) = match accepted {
                Ok(value) => value,
                Err(_) => {
                    self.listener_failure.store(true, Ordering::Release);
                    cancel.cancel();
                    break;
                }
            };
            let Ok(slot) = self.connections.clone().try_acquire_owned() else {
                drop(tcp);
                continue;
            };
            let app = self.clone();
            let stop = cancel.clone();
            connections.spawn(async move {
                let _slot = slot;
                let tls = tokio::select! { _ = stop.cancelled() => return, result = app.tls.accept(tcp, IO_TIMEOUT) => match result { Ok(tls) => tls, Err(_) => return } };
                let service = hyper::service::service_fn(move |request| { let app=app.clone(); async move { Ok::<_, Infallible>(app.handle(request).await) } });
                let mut builder = hyper::server::conn::http1::Builder::new();
                builder.max_headers(64).max_buf_size(16*1024).header_read_timeout(IO_TIMEOUT).timer(hyper_util::rt::TokioTimer::new());
                let connection = builder.serve_connection(hyper_util::rt::TokioIo::new(tls), service);
                tokio::pin!(connection);
                tokio::select! {
                    _ = stop.cancelled() => { connection.as_mut().graceful_shutdown(); let _=tokio::time::timeout(Duration::from_secs(2), &mut connection).await; },
                    _ = tokio::time::sleep(Duration::from_secs(120)) => { connection.as_mut().graceful_shutdown(); let _=tokio::time::timeout(Duration::from_secs(2), &mut connection).await; },
                    _ = &mut connection => {}
                }
            });
        }
        drop(listener);
        let mut joined = true;
        while let Some(result) = connections.join_next().await {
            joined &= result.is_ok();
        }
        // No new worker can register only AFTER every connection future ended.
        // Cancellation alone is not quiescence; the one-shot run cannot reopen.
        self.transport_quiescent.store(true, Ordering::Release);
        let mut facts = self.wait_for_blocking(Duration::from_secs(10)).await;
        facts.connections_joined = joined;
        Ok(facts)
    }
    /// Explicit reconciliation may be called again after bounded shutdown. It
    /// never cancels a blocking mutation and never equates timeout with joined.
    pub async fn wait_for_blocking(&self, budget: Duration) -> ShutdownFacts {
        if !self.transport_quiescent.load(Ordering::Acquire) {
            return self.shutdown_facts(false);
        }
        let until = tokio::time::Instant::now() + budget.min(Duration::from_secs(30));
        let Ok(_join) = tokio::time::timeout_at(until, self.join_lock.lock()).await else {
            return self.shutdown_facts(false);
        };
        let handles = std::mem::take(&mut *self.workers.lock().expect("enrollment workers"));
        let mut retained = vec![];
        let mut joined = true;
        for mut handle in handles {
            match tokio::time::timeout_at(until, &mut handle).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => {
                    self.worker_failure.store(true, Ordering::Release);
                }
                Err(_) => {
                    retained.push(handle);
                    joined = false;
                }
            }
        }
        let mut workers = self.workers.lock().expect("enrollment workers");
        workers.extend(retained);
        joined &= workers.is_empty();
        drop(workers);
        self.shutdown_facts(joined)
    }
    fn shutdown_facts(&self, joined: bool) -> ShutdownFacts {
        ShutdownFacts {
            connections_joined: false,
            blocking_jobs_joined: joined,
            blocking_slots_in_use: REQUESTS - self.requests.available_permits(),
            worker_failure_observed: self.worker_failure.load(Ordering::Acquire),
            listener_error_observed: self.listener_failure.load(Ordering::Acquire),
        }
    }
}
fn valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 512 || host.contains('@') {
        return false;
    }
    let Ok(authority) = host.parse::<http::uri::Authority>() else {
        return false;
    };
    !authority.host().is_empty()
        && authority
            .port()
            .is_none_or(|port| port.as_str().parse::<u16>().is_ok())
}
fn expected_method(path: &str) -> Option<Method> {
    if let Some(device) = path
        .strip_prefix("/styx/enroll/self/")
        .and_then(|s| s.strip_suffix("/capabilities"))
    {
        if device.len() == 29
            && device.starts_with("styx-")
            && device[5..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            // Self supports both verbs; handler separately selects this marker.
            return Some(Method::GET);
        }
        return None;
    }
    match path {
        "/styx/enroll/pending" | "/styx/enroll/devices" => Some(Method::GET),
        "/styx/enroll/invitations"
        | "/styx/enroll/invitations/close"
        | "/styx/enroll/approve"
        | "/styx/enroll/revoke"
        | "/styx/enroll/recover"
        | "/styx/enroll/capabilities"
        | "/styx/enroll/set-default"
        | "/styx/enroll/join"
        | "/styx/enroll/claim"
        | "/styx/enroll/confirm" => Some(Method::POST),
        _ => None,
    }
}
struct BoundedResponse(Vec<u8>);
impl Write for BoundedResponse {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self
            .0
            .len()
            .checked_add(bytes.len())
            .is_none_or(|n| n > RESPONSE_BYTES)
        {
            return Err(std::io::Error::other("response limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn encode_response(value: &serde_json::Value) -> Result<Bytes, ()> {
    let mut writer = BoundedResponse(Vec::new());
    serde_json::to_writer(&mut writer, value).map_err(|_| ())?;
    Ok(Bytes::from(writer.0))
}
fn response(status: u16, bytes: Bytes, close: bool) -> HttpResponse {
    let mut response = Response::new(Full::new(bytes));
    *response.status_mut() =
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let headers = response.headers_mut();
    headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/json; charset=utf-8"),
    );
    headers.insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );
    headers.insert(
        http::header::X_CONTENT_TYPE_OPTIONS,
        http::HeaderValue::from_static("nosniff"),
    );
    if close {
        headers.insert(
            http::header::CONNECTION,
            http::HeaderValue::from_static("close"),
        );
    }
    response
}
fn failure(status: u16, code: &'static str, close: bool) -> HttpResponse {
    let bytes = encode_response(&serde_json::json!({"error":code}))
        .unwrap_or_else(|_| Bytes::from_static(b"{\"error\":\"enrollment_outcome_unknown\"}"));
    response(status, bytes, close)
}

#[cfg(test)]
#[path = "http_tests.rs"]
mod tests;
