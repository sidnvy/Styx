//! One owned, once-only enrollment HTTP exchange. No identity, persistence,
//! approval, retry, redirect, proxy, or publication authority lives here.
use crate::tls::{GatewayClientTls, GatewayLeafPin, TlsError};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::{Request, header};
use hyper_util::rt::TokioIo;
use std::{fmt, time::Duration};
use tokio::{net::TcpStream, time::Instant};
use zeroize::Zeroizing;

const REQUEST_BYTES: usize = 16 * 1024;
const RESPONSE_BYTES: usize = 32 * 1024;
const HEADER_BYTES: usize = 16 * 1024;
const MAX_HEADERS: usize = 32;
const MAX_TIMEOUT: Duration = Duration::from_secs(30);

/// Contains a credential response; deliberately no Debug/Clone/Serde.
pub(crate) struct JoinHttpResponse {
    pub(crate) status: u16,
    pub(crate) body: Zeroizing<Vec<u8>>,
    /// The actual verified endpoint certificate, never a configured CA pin.
    pub(crate) leaf_pin: GatewayLeafPin,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum JoinHttpCertainty {
    NotDispatched,
    ResultUnknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum JoinHttpErrorKind {
    InvalidInput,
    InvalidTimeout,
    Connect,
    Tls(TlsError),
    Http,
    ResponseTooLarge,
    RedirectRefused,
    Deadline,
}
/// Only typed/static facts. Never retains URLs, headers, bodies or upstream
/// Display strings. Even a backend error response may follow an actual effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct JoinHttpError {
    pub(crate) kind: JoinHttpErrorKind,
    pub(crate) certainty: JoinHttpCertainty,
}
impl JoinHttpError {
    pub(crate) fn code(self) -> &'static str {
        match self.kind {
            JoinHttpErrorKind::InvalidInput => "join_http_invalid_input",
            JoinHttpErrorKind::InvalidTimeout => "join_http_invalid_timeout",
            JoinHttpErrorKind::Connect => "join_http_connect_failed",
            JoinHttpErrorKind::Tls(TlsError::CertificateRejected(value)) => value.code(),
            JoinHttpErrorKind::Tls(TlsError::PinMismatch) => "join_http_leaf_pin_mismatch",
            JoinHttpErrorKind::Tls(_) => "join_http_tls_rejected",
            JoinHttpErrorKind::Http => "join_http_exchange_failed",
            JoinHttpErrorKind::ResponseTooLarge => "join_http_response_too_large",
            JoinHttpErrorKind::RedirectRefused => "join_http_redirect_refused",
            JoinHttpErrorKind::Deadline => "join_http_deadline",
        }
    }
}
impl fmt::Display for JoinHttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for JoinHttpError {}
fn refusal(kind: JoinHttpErrorKind) -> JoinHttpError {
    JoinHttpError {
        kind,
        certainty: JoinHttpCertainty::NotDispatched,
    }
}
fn unknown(kind: JoinHttpErrorKind) -> JoinHttpError {
    JoinHttpError {
        kind,
        certainty: JoinHttpCertainty::ResultUnknown,
    }
}

// Observations only: no upstream text or input/response data is retained.
#[derive(Clone, Copy, Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum HttpFailureStage {
    Handshake,
    Send,
    Body,
    #[cfg(test)]
    Connection,
}
#[derive(Default, Debug, serde::Serialize)]
pub(crate) struct HyperClassification {
    present: bool,
    incomplete_message: bool,
    closed: bool,
    timeout: bool,
    parse: bool,
    canceled: bool,
    user: bool,
    body_write_aborted: bool,
}
/// Pure fixed predicates for an original Hyper error. No upstream text.
pub(crate) fn http_error_diagnostic(error: &hyper::Error) -> HyperClassification {
    HyperClassification {
        present: true,
        incomplete_message: error.is_incomplete_message(),
        closed: error.is_closed(),
        timeout: error.is_timeout(),
        parse: error.is_parse(),
        canceled: error.is_canceled(),
        user: error.is_user(),
        body_write_aborted: error.is_body_write_aborted(),
    }
}
#[derive(Debug, serde::Serialize)]
struct HttpFailureObservation {
    schema: u8,
    event: &'static str,
    code: &'static str,
    certainty: &'static str,
    stage: HttpFailureStage,
    response_received: bool,
    body_complete: bool,
    hyper: HyperClassification,
    io_kind: Option<&'static str>,
}
impl HttpFailureObservation {
    fn capture(
        error: JoinHttpError,
        stage: HttpFailureStage,
        cause: &(dyn std::error::Error + 'static),
        response_received: bool,
        body_complete: bool,
    ) -> Self {
        let mut hyper = HyperClassification::default();
        let mut io_kind = None;
        let mut current = Some(cause);
        // The original error source chain need not be acyclic or bounded.
        // Only typed predicates are inspected; never upstream Display/Debug.
        for _ in 0..8 {
            let Some(cause) = current else { break };
            if let Some(value) = cause.downcast_ref::<hyper::Error>() {
                let facts = http_error_diagnostic(value);
                hyper.present |= facts.present;
                hyper.incomplete_message |= facts.incomplete_message;
                hyper.closed |= facts.closed;
                hyper.timeout |= facts.timeout;
                hyper.parse |= facts.parse;
                hyper.canceled |= facts.canceled;
                hyper.user |= facts.user;
                hyper.body_write_aborted |= facts.body_write_aborted;
            }
            if io_kind.is_none()
                && let Some(value) = cause.downcast_ref::<std::io::Error>()
            {
                io_kind = Some(match value.kind() {
                    std::io::ErrorKind::ConnectionReset => "connection_reset",
                    std::io::ErrorKind::ConnectionAborted => "connection_aborted",
                    std::io::ErrorKind::BrokenPipe => "broken_pipe",
                    std::io::ErrorKind::UnexpectedEof => "unexpected_eof",
                    std::io::ErrorKind::TimedOut => "timed_out",
                    std::io::ErrorKind::NotConnected => "not_connected",
                    std::io::ErrorKind::WouldBlock => "would_block",
                    std::io::ErrorKind::Interrupted => "interrupted",
                    _ => "other",
                });
            }
            current = cause.source();
        }
        Self {
            schema: 1,
            event: "styx_join_http_failure",
            code: error.code(),
            certainty: match error.certainty {
                JoinHttpCertainty::NotDispatched => "not_dispatched",
                JoinHttpCertainty::ResultUnknown => "result_unknown",
            },
            stage,
            response_received,
            body_complete,
            hyper,
            io_kind,
        }
    }
}
fn observe_http_failure(
    error: JoinHttpError,
    stage: HttpFailureStage,
    cause: &(dyn std::error::Error + 'static),
    response_received: bool,
    body_complete: bool,
) -> JoinHttpError {
    if std::env::var("STYX_GATEWAY_STARTUP_DIAGNOSTICS").as_deref() == Ok("1") {
        let facts =
            HttpFailureObservation::capture(error, stage, cause, response_received, body_complete);
        use std::io::Write as _;
        // A lost diagnostic sink must not replace the original HTTP error.
        let _ = writeln!(std::io::stderr().lock(), "{}", serde_json::json!(facts));
    }
    // Logging cannot grant a successful response or change dispatch certainty.
    error
}

// Bytes retains this zeroizing owner until the official HTTP body releases its
// last reference. This does not promise zeroization of TLS/Hyper internal copies.
struct RequestBytes(Zeroizing<Vec<u8>>);
impl AsRef<[u8]> for RequestBytes {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

pub(crate) async fn exchange(
    origin: &url::Url,
    tls: &GatewayClientTls,
    path: &'static str,
    body: &[u8],
    bearer: Option<&[u8]>,
    timeout: Duration,
) -> Result<JoinHttpResponse, JoinHttpError> {
    if !post_path(path) {
        return Err(refusal(JoinHttpErrorKind::InvalidInput));
    }
    exchange_once(
        origin,
        tls,
        hyper::Method::POST,
        path,
        body,
        bearer,
        timeout,
    )
    .await
}

/// Fixed authenticated self route only. A response status is not a ready grant;
/// the caller must validate actual device/fingerprint/generation and status200.
pub(crate) async fn exchange_self(
    origin: &url::Url,
    tls: &GatewayClientTls,
    device: &styx_contracts::identity::DeviceId,
    bearer: &[u8],
    timeout: Duration,
) -> Result<JoinHttpResponse, JoinHttpError> {
    if !device_path_component(device.as_str()) {
        return Err(refusal(JoinHttpErrorKind::InvalidInput));
    }
    let path = format!("/styx/enroll/self/{}/capabilities", device.as_str());
    exchange_once(
        origin,
        tls,
        hyper::Method::GET,
        &path,
        &[],
        Some(bearer),
        timeout,
    )
    .await
}
/// Owner-local setup uses the existing once-only exchange and original Gateway
/// admin credential. No generic admin route, redirect or retry is introduced.
pub(crate) async fn exchange_local_admin(
    origin: &url::Url,
    tls: &GatewayClientTls,
    approve: bool,
    body: &[u8],
    bearer: &[u8],
) -> Result<JoinHttpResponse, JoinHttpError> {
    let path = if approve {
        "/styx/enroll/approve"
    } else {
        "/styx/enroll/invitations"
    };
    exchange_once(
        origin,
        tls,
        hyper::Method::POST,
        path,
        body,
        Some(bearer),
        MAX_TIMEOUT,
    )
    .await
}
/// Fixed read-only admin discovery; never retries a failed mutation.
pub(crate) async fn exchange_local_pending(
    origin: &url::Url,
    tls: &GatewayClientTls,
    bearer: &[u8],
) -> Result<JoinHttpResponse, JoinHttpError> {
    exchange_once(
        origin,
        tls,
        hyper::Method::GET,
        "/styx/enroll/pending",
        &[],
        Some(bearer),
        MAX_TIMEOUT,
    )
    .await
}
fn post_path(path: &str) -> bool {
    matches!(
        path,
        "/styx/enroll/join" | "/styx/enroll/claim" | "/styx/enroll/confirm"
    )
}
fn device_path_component(device: &str) -> bool {
    device.len() == 29
        && device.starts_with("styx-")
        && device.as_bytes()[5..]
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}
async fn exchange_once(
    origin: &url::Url,
    tls: &GatewayClientTls,
    method: hyper::Method,
    path: &str,
    body: &[u8],
    bearer: Option<&[u8]>,
    timeout: Duration,
) -> Result<JoinHttpResponse, JoinHttpError> {
    if timeout.is_zero() || timeout > MAX_TIMEOUT {
        return Err(refusal(JoinHttpErrorKind::InvalidTimeout));
    }
    let allowed = (method == hyper::Method::POST
        && (post_path(path)
            || (bearer.is_some()
                && matches!(path, "/styx/enroll/invitations" | "/styx/enroll/approve"))))
        || (method == hyper::Method::GET
            && body.is_empty()
            && bearer.is_some()
            && (path == "/styx/enroll/pending"
                || path
                    .strip_prefix("/styx/enroll/self/")
                    .and_then(|p| p.strip_suffix("/capabilities"))
                    .is_some_and(device_path_component)));
    if !allowed
        || body.len() > REQUEST_BYTES
        || origin.as_str().len() > 2048
        || origin.scheme() != "https"
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
        || origin.as_str() != format!("{}/", origin.origin().ascii_serialization())
    {
        return Err(refusal(JoinHttpErrorKind::InvalidInput));
    }
    let host = origin
        .host_str()
        .ok_or_else(|| refusal(JoinHttpErrorKind::InvalidInput))?;
    // Url::host_str includes brackets on IPv6; the TLS API requires an
    // unbracketed literal. Authority retains the URI's required brackets.
    let server_name = host.trim_matches(['[', ']']);
    let port = origin
        .port_or_known_default()
        .filter(|p| *p != 0)
        .ok_or_else(|| refusal(JoinHttpErrorKind::InvalidInput))?;
    let authority = if server_name.contains(':') {
        format!("[{server_name}]:{port}")
    } else {
        format!("{server_name}:{port}")
    };
    // Conservative complete HTTP/1 request bound: mature Hyper performs the
    // encoding; reserve more than all fixed names, framing and length digits.
    let wire_bound = body
        .len()
        .checked_add(path.len())
        .and_then(|n| n.checked_add(authority.len()))
        .and_then(|n| n.checked_add(bearer.map_or(0, <[u8]>::len)))
        .and_then(|n| n.checked_add(512));
    if server_name.len() > 253 || wire_bound.is_none_or(|n| n > REQUEST_BYTES) {
        return Err(refusal(JoinHttpErrorKind::InvalidInput));
    }
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, authority)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json")
        .header(header::CONNECTION, "close");
    if let Some(bearer) = bearer {
        if !(32..=4096).contains(&bearer.len())
            || !bearer
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || matches!(*b, b'_' | b'-'))
        {
            return Err(refusal(JoinHttpErrorKind::InvalidInput));
        }
        let mut value = Zeroizing::new(Vec::with_capacity(7 + bearer.len()));
        value.extend_from_slice(b"Bearer ");
        value.extend_from_slice(bearer);
        let mut value = hyper::header::HeaderValue::from_bytes(&value)
            .map_err(|_| refusal(JoinHttpErrorKind::InvalidInput))?;
        value.set_sensitive(true);
        request = request.header(header::AUTHORIZATION, value);
    }
    let request = request
        .body(Full::new(Bytes::from_owner(RequestBytes(Zeroizing::new(
            body.to_vec(),
        )))))
        .map_err(|_| refusal(JoinHttpErrorKind::InvalidInput))?;
    let until = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| refusal(JoinHttpErrorKind::InvalidTimeout))?;
    let mut dispatched = false;
    let result = tokio::time::timeout_at(until, async {
        // One standard Tokio DNS lookup and one TCP connect. Do not add
        // address failover, proxy handling or an automatic request retry layer.
        let address = tokio::net::lookup_host((server_name, port))
            .await
            .map_err(|_| refusal(JoinHttpErrorKind::Connect))?
            .next()
            .ok_or_else(|| refusal(JoinHttpErrorKind::Connect))?;
        let tcp = TcpStream::connect(address)
            .await
            .map_err(|_| refusal(JoinHttpErrorKind::Connect))?;
        let remaining = until.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(refusal(JoinHttpErrorKind::Deadline));
        }
        let stream = tls
            .connect(server_name, tcp, remaining)
            .await
            .map_err(|e| refusal(JoinHttpErrorKind::Tls(e)))?;
        let leaf = stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|chain| chain.first())
            .ok_or_else(|| refusal(JoinHttpErrorKind::Tls(TlsError::MissingPeerCertificate)))?;
        let leaf_pin = GatewayLeafPin::from_certificate_der(leaf);
        let mut builder = hyper::client::conn::http1::Builder::new();
        builder.max_headers(MAX_HEADERS).max_buf_size(HEADER_BYTES);
        let (mut sender, connection) = builder
            .handshake::<_, Full<Bytes>>(TokioIo::new(stream))
            .await
            .map_err(|cause| {
                observe_http_failure(
                    refusal(JoinHttpErrorKind::Http),
                    HttpFailureStage::Handshake,
                    &cause,
                    false,
                    false,
                )
            })?;
        let started = &mut dispatched;
        let request_once = async move {
            // Conservative dispatch boundary: never infer NotDispatched from
            // a send/response error. There is exactly one send_request call.
            *started = true;
            let response = sender.send_request(request).await.map_err(|cause| {
                observe_http_failure(
                    unknown(JoinHttpErrorKind::Http),
                    HttpFailureStage::Send,
                    &cause,
                    false,
                    false,
                )
            })?;
            let status = response.status();
            if status.is_redirection() {
                return Err(unknown(JoinHttpErrorKind::RedirectRefused));
            }
            let body = Limited::new(response.into_body(), RESPONSE_BYTES)
                .collect()
                .await
                .map_err(|e| {
                    let error = unknown(if e.is::<LengthLimitError>() {
                        JoinHttpErrorKind::ResponseTooLarge
                    } else {
                        JoinHttpErrorKind::Http
                    });
                    observe_http_failure(error, HttpFailureStage::Body, e.as_ref(), true, false)
                })?
                .to_bytes();
            Ok(JoinHttpResponse {
                status: status.as_u16(),
                body: Zeroizing::new(body.to_vec()),
                leaf_pin,
            })
        };
        finish_response_owned(request_once, connection).await
    })
    .await;
    match result {
        Ok(result) => result,
        Err(_) => Err(if dispatched {
            unknown(JoinHttpErrorKind::Deadline)
        } else {
            refusal(JoinHttpErrorKind::Deadline)
        }),
    }
    // Timeout/caller cancellation drops the inline connection and its TLS/TCP
    // handle. No spawned connection task or sender survives this future. This
    // is local transport closure, not proof that the server rolled back effects.
}

// The full bounded response, not the later TLS/TCP close, settles this one HTTP
// exchange. Poll both inline: no detached connection survives cancellation or
// completion. Dropping Hyper's Connection closes its underlying IO resource.
// If IO ends first, the original send/body future still validates the whole
// response; a partial body, parse error or reset remains an unknown result.
async fn finish_response_owned<R>(
    response: impl std::future::Future<Output = Result<R, JoinHttpError>>,
    connection: impl std::future::Future<Output = Result<(), hyper::Error>>,
) -> Result<R, JoinHttpError> {
    tokio::pin!(response, connection);
    tokio::select! {
        biased;
        response = &mut response => response,
        _closed = &mut connection => response.await,
    }
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;
    use std::error::Error;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // A real backend cause may have sensitive Display/Debug text. Diagnostics
    // must use only the underlying typed classification, not copy that text.
    #[derive(Debug)]
    struct PrivateContext(hyper::Error);
    impl fmt::Display for PrivateContext {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("https://private.example/credential Bearer SYNTHETIC_SECRET")
        }
    }
    impl Error for PrivateContext {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            Some(&self.0)
        }
    }
    async fn failure_from_wire(raw: &'static [u8]) -> HttpFailureObservation {
        let (client, mut peer) = tokio::io::duplex(8192);
        let server = tokio::spawn(async move {
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            while !request.windows(4).any(|part| part == b"\r\n\r\n") {
                let read = peer.read(&mut chunk).await.unwrap();
                assert!(read > 0 && request.len() + read <= 4096);
                request.extend_from_slice(&chunk[..read]);
            }
            peer.write_all(raw).await.unwrap();
            peer.shutdown().await.unwrap();
        });
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake::<_, Full<Bytes>>(TokioIo::new(client))
                .await
                .unwrap();
        let request = Request::builder()
            .uri("/credential")
            .header(header::HOST, "private.example")
            .header(header::CONNECTION, "close")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let read_response = async move {
            let error = unknown(JoinHttpErrorKind::Http);
            match sender.send_request(request).await {
                Err(cause) => HttpFailureObservation::capture(
                    error,
                    HttpFailureStage::Send,
                    &PrivateContext(cause),
                    false,
                    false,
                ),
                Ok(response) => {
                    let cause = response.into_body().collect().await.unwrap_err();
                    HttpFailureObservation::capture(
                        error,
                        HttpFailureStage::Body,
                        &PrivateContext(cause),
                        true,
                        false,
                    )
                }
            }
        };
        let (observation, _connection_result) = tokio::join!(read_response, connection);
        server.await.unwrap();
        observation
    }
    fn assert_private_safe(observation: &HttpFailureObservation) -> serde_json::Value {
        let raw = serde_json::to_string(observation).unwrap();
        for secret in [
            "private.example",
            "/credential",
            "Bearer",
            "SYNTHETIC_SECRET",
            "HEADER_SECRET",
            "BODY_SECRET",
        ] {
            assert!(
                !raw.contains(secret),
                "upstream text escaped fixed diagnostics"
            );
        }
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(value["code"], "join_http_exchange_failed");
        assert_eq!(value["certainty"], "result_unknown");
        assert_eq!(value["hyper"]["present"], true);
        value
    }
    #[tokio::test]
    async fn malformed_response_keeps_actual_parse_classification_private() {
        let observation = failure_from_wire(
            b"HTTP/1.1 INVALID SYNTHETIC_SECRET\r\nX-Private: HEADER_SECRET\r\n\r\n",
        )
        .await;
        let value = assert_private_safe(&observation);
        assert_eq!(value["stage"], "send");
        assert_eq!(value["hyper"]["parse"], true);
        assert_eq!(value["response_received"], false);
        assert_eq!(value["body_complete"], false);
    }
    #[tokio::test]
    async fn truncated_headers_keep_actual_incomplete_message_classification() {
        let observation = failure_from_wire(b"HTTP/1.1 200 OK\r\nContent-Length: 10").await;
        let value = assert_private_safe(&observation);
        assert_eq!(value["stage"], "send");
        assert_eq!(value["hyper"]["incomplete_message"], true);
        assert_eq!(value["response_received"], false);
        assert_eq!(value["body_complete"], false);
    }
    #[tokio::test]
    async fn truncated_response_keeps_incomplete_body_distinct_from_complete() {
        let observation = failure_from_wire(
            b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nX-Private: HEADER_SECRET\r\n\r\nBODY_SECRET",
        ).await;
        let value = assert_private_safe(&observation);
        assert_eq!(value["stage"], "body");
        // Hyper wraps this body framing failure around an actual I/O EOF;
        // do not relabel it as its distinct incomplete-head error variant.
        assert_eq!(value["io_kind"], "unexpected_eof");
        assert_eq!(value["response_received"], true);
        assert_eq!(value["body_complete"], false);
    }
}

#[cfg(test)]
#[path = "native_join_http_transport_tests.rs"]
mod transport_tests;
