//! Native Public MCP loopback ingress with OIDC / Cloudflare Access JWKS RS256
//! JWT verification. Authenticates incoming requests in-process and dispatches
//! straight into `GatewayHttp` with `TunnelConversation` isolation — no external
//! Python proxy or static tool allowlist required.
use crate::{
    gateway::{
        http::{GatewayHttp, MESSAGE_BYTES, body::HeldBody, lifecycle::GatewayOwnerLifecycle},
        mcp::GatewayToolBackend,
    },
    store::PrivateRoot,
};
use aws_lc_rs::signature::{RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use http::{
    HeaderMap, HeaderValue, Method, Request, Response, StatusCode,
    header::{CACHE_CONTROL, CONTENT_TYPE, HeaderName, ORIGIN},
};
use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    convert::Infallible,
    fs,
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{net::TcpListener, sync::RwLock, task::JoinSet};
use tokio_util::sync::CancellationToken;

const CONFIG_FILE: &str = "public-mcp.json";
const MAX_CONFIG_BYTES: usize = 16 * 1024;
const MAX_JWT_BYTES: usize = 12_000;
const MAX_JWKS_BYTES: usize = 256 * 1024;
const JWKS_CACHE_TTL: Duration = Duration::from_secs(300);
const JWKS_MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(10);
const JWT_CLOCK_LEEWAY_SECS: u64 = 15;
const DEFAULT_PORT: u16 = 22128;

fn default_jwt_header() -> String {
    "cf-access-jwt-assertion".into()
}
fn default_allowed_origins() -> Vec<String> {
    vec![
        "https://chatgpt.com".into(),
        "https://gemini.google.com".into(),
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicMcpError(&'static str);
impl PublicMcpError {
    pub const fn new(code: &'static str) -> Self {
        Self(code)
    }
    pub const fn code(self) -> &'static str {
        self.0
    }
}
impl std::fmt::Display for PublicMcpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for PublicMcpError {}
type Result<T> = std::result::Result<T, PublicMcpError>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicMcpConfig {
    pub schema: u32,
    pub enabled: bool,
    pub listen_port: u16,
    pub issuer: String,
    pub audience: String,
    pub jwks_url: String,
    #[serde(default = "default_jwt_header")]
    pub jwt_header: String,
    #[serde(default = "default_allowed_origins")]
    pub allowed_origins: Vec<String>,
}

impl PublicMcpConfig {
    pub fn validate(&self) -> Result<()> {
        if self.schema != 1 || self.listen_port == 0 {
            return Err(PublicMcpError("invalid_public_mcp_configuration"));
        }
        if !valid_https_url(&self.issuer)
            || !valid_https_url(&self.jwks_url)
            || self.audience.is_empty()
            || self.audience.len() > 512
            || self.audience.bytes().any(|b| b <= 0x20 || b >= 0x7f)
        {
            return Err(PublicMcpError("invalid_public_mcp_configuration"));
        }
        if self.jwt_header.is_empty()
            || self.jwt_header.len() > 128
            || HeaderName::from_bytes(self.jwt_header.as_bytes()).is_err()
        {
            return Err(PublicMcpError("invalid_public_mcp_configuration"));
        }
        if self.allowed_origins.len() > 8
            || self.allowed_origins.iter().any(|o| !valid_https_url(o))
        {
            return Err(PublicMcpError("invalid_public_mcp_configuration"));
        }
        Ok(())
    }

    pub fn loopback_addr(&self) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, self.listen_port))
    }
}

fn valid_https_url(value: &str) -> bool {
    if value.len() > 512 || value.bytes().any(|b| b <= 0x20 || b >= 0x7f) {
        return false;
    }
    let Ok(parsed) = url::Url::parse(value) else {
        return false;
    };
    parsed.scheme() == "https" && parsed.host_str().is_some() && parsed.username().is_empty()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicMcpStatus {
    pub schema: u32,
    pub status: &'static str,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwt_header: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_origins: Option<Vec<String>>,
}

fn projection(config: Option<PublicMcpConfig>) -> PublicMcpStatus {
    match config {
        Some(c) => PublicMcpStatus {
            schema: 1,
            status: if c.enabled { "enabled" } else { "disabled" },
            enabled: c.enabled,
            listen_port: Some(c.listen_port),
            issuer: Some(c.issuer),
            audience: Some(c.audience),
            jwks_url: Some(c.jwks_url),
            jwt_header: Some(c.jwt_header),
            allowed_origins: Some(c.allowed_origins),
        },
        None => PublicMcpStatus {
            schema: 1,
            status: "not_configured",
            enabled: false,
            listen_port: None,
            issuer: None,
            audience: None,
            jwks_url: None,
            jwt_header: None,
            allowed_origins: None,
        },
    }
}

pub fn load_config(state_dir: &Path) -> Result<Option<PublicMcpConfig>> {
    let root =
        PrivateRoot::open(state_dir).map_err(|_| PublicMcpError("public_mcp_protected_read"))?;
    if root.ensure_absent(CONFIG_FILE).is_ok() {
        return Ok(None);
    }
    let raw = root
        .read_raw(CONFIG_FILE, MAX_CONFIG_BYTES)
        .map_err(|_| PublicMcpError("public_mcp_protected_read"))?;
    let config: PublicMcpConfig = serde_json::from_slice(raw.bytes())
        .map_err(|_| PublicMcpError("invalid_public_mcp_configuration"))?;
    config.validate()?;
    Ok(Some(config))
}

fn atomic_write(state_dir: &Path, root: &PrivateRoot, bytes: &[u8]) -> Result<()> {
    let temporary = format!("tmp-public-mcp-{}", uuid::Uuid::new_v4().simple());
    root.create_pairing_invitation(std::ffi::OsStr::new(&temporary), bytes)
        .map_err(|_| PublicMcpError("public_mcp_protected_write"))?;
    let result = fs::rename(state_dir.join(&temporary), state_dir.join(CONFIG_FILE))
        .map_err(|_| PublicMcpError("public_mcp_protected_write"));
    if result.is_err() {
        let _ = fs::remove_file(state_dir.join(&temporary));
    }
    result?;
    #[cfg(unix)]
    fs::File::open(state_dir)
        .and_then(|f| f.sync_all())
        .map_err(|_| PublicMcpError("public_mcp_protected_write"))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn configure(
    state_dir: &Path,
    issuer: &str,
    audience: &str,
    jwks_url: &str,
    listen_port: Option<u16>,
    jwt_header: Option<&str>,
    allowed_origins: Option<Vec<String>>,
    enabled: bool,
    authorize: bool,
) -> Result<PublicMcpStatus> {
    if !authorize {
        return Err(PublicMcpError("public_mcp_authorization_required"));
    }
    let root =
        PrivateRoot::open(state_dir).map_err(|_| PublicMcpError("public_mcp_protected_read"))?;
    let config = PublicMcpConfig {
        schema: 1,
        enabled,
        listen_port: listen_port.unwrap_or(DEFAULT_PORT),
        issuer: issuer.trim().to_owned(),
        audience: audience.trim().to_owned(),
        jwks_url: jwks_url.trim().to_owned(),
        jwt_header: jwt_header
            .map(|h| h.trim().to_ascii_lowercase())
            .unwrap_or_else(default_jwt_header),
        allowed_origins: allowed_origins.unwrap_or_else(default_allowed_origins),
    };
    config.validate()?;
    let bytes = serde_json::to_vec_pretty(&config)
        .map_err(|_| PublicMcpError("public_mcp_protected_write"))?;
    atomic_write(state_dir, &root, &bytes)?;
    Ok(projection(Some(config)))
}

pub fn status(state_dir: &Path) -> Result<PublicMcpStatus> {
    Ok(projection(load_config(state_dir)?))
}

pub fn disable(state_dir: &Path, authorize: bool) -> Result<PublicMcpStatus> {
    if !authorize {
        return Err(PublicMcpError("public_mcp_authorization_required"));
    }
    let root =
        PrivateRoot::open(state_dir).map_err(|_| PublicMcpError("public_mcp_protected_read"))?;
    let Some(mut config) = load_config(state_dir)? else {
        return Ok(projection(None));
    };
    config.enabled = false;
    let bytes = serde_json::to_vec_pretty(&config)
        .map_err(|_| PublicMcpError("public_mcp_protected_write"))?;
    atomic_write(state_dir, &root, &bytes)?;
    Ok(projection(Some(config)))
}

#[derive(Clone)]
pub struct RsaJwk {
    pub n: Vec<u8>,
    pub e: Vec<u8>,
}

struct CachedJwks {
    keys: BTreeMap<String, RsaJwk>,
    fetched_at: Option<Instant>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedClaim {
    pub subject: String,
}

pub struct JwksVerifier {
    config: PublicMcpConfig,
    header_name: HeaderName,
    client: Option<reqwest::Client>,
    cache: RwLock<CachedJwks>,
}

impl JwksVerifier {
    pub fn new(config: PublicMcpConfig) -> Result<Self> {
        config.validate()?;
        let header_name = HeaderName::from_bytes(config.jwt_header.as_bytes())
            .map_err(|_| PublicMcpError("invalid_public_mcp_configuration"))?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| PublicMcpError("public_mcp_http_client_failed"))?;
        Ok(Self {
            config,
            header_name,
            client: Some(client),
            cache: RwLock::new(CachedJwks {
                keys: BTreeMap::new(),
                fetched_at: None,
            }),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_static_keys(
        config: PublicMcpConfig,
        keys: BTreeMap<String, RsaJwk>,
    ) -> Result<Self> {
        config.validate()?;
        let header_name = HeaderName::from_bytes(config.jwt_header.as_bytes())
            .map_err(|_| PublicMcpError("invalid_public_mcp_configuration"))?;
        Ok(Self {
            config,
            header_name,
            client: None,
            cache: RwLock::new(CachedJwks {
                keys,
                fetched_at: Some(Instant::now()),
            }),
        })
    }

    pub fn config(&self) -> &PublicMcpConfig {
        &self.config
    }

    pub fn origin_allowed(&self, headers: &HeaderMap) -> bool {
        if headers.get_all(ORIGIN).iter().count() > 1 {
            return false;
        }
        match headers.get(ORIGIN) {
            None => true,
            Some(value) => value
                .to_str()
                .ok()
                .is_some_and(|origin| self.config.allowed_origins.iter().any(|a| a == origin)),
        }
    }

    fn extract_token<'a>(&self, headers: &'a HeaderMap) -> Option<&'a str> {
        if headers.get_all(&self.header_name).iter().count() != 1 {
            return None;
        }
        let raw = headers.get(&self.header_name)?.to_str().ok()?.trim();
        let token = if self.header_name == http::header::AUTHORIZATION {
            raw.strip_prefix("Bearer ")?.trim()
        } else {
            raw
        };
        if token.is_empty() || token.len() > MAX_JWT_BYTES {
            return None;
        }
        Some(token)
    }

    async fn get_key(&self, kid: &str) -> Option<RsaJwk> {
        let now = Instant::now();
        {
            let guard = self.cache.read().await;
            let fresh = guard
                .fetched_at
                .is_some_and(|t| now.saturating_duration_since(t) < JWKS_CACHE_TTL);
            if fresh && let Some(key) = guard.keys.get(kid) {
                return Some(key.clone());
            }
        }
        self.refresh_jwks(kid).await
    }

    async fn refresh_jwks(&self, kid: &str) -> Option<RsaJwk> {
        let Some(client) = self.client.as_ref() else {
            return self.cache.read().await.keys.get(kid).cloned();
        };
        let mut guard = self.cache.write().await;
        let now = Instant::now();
        if let Some(fetched) = guard.fetched_at {
            if now.saturating_duration_since(fetched) < JWKS_CACHE_TTL
                && let Some(key) = guard.keys.get(kid)
            {
                return Some(key.clone());
            }
            if now.saturating_duration_since(fetched) < JWKS_MIN_REFRESH_INTERVAL {
                return guard.keys.get(kid).cloned();
            }
        }
        let response = client.get(&self.config.jwks_url).send().await.ok()?;
        if !response.status().is_success() {
            return None;
        }
        let body = response.bytes().await.ok()?;
        if body.len() > MAX_JWKS_BYTES {
            return None;
        }
        let parsed = parse_jwks(&body)?;
        guard.keys = parsed;
        guard.fetched_at = Some(Instant::now());
        guard.keys.get(kid).cloned()
    }

    pub async fn verify_headers(&self, headers: &HeaderMap) -> Option<VerifiedClaim> {
        let token = self.extract_token(headers)?;
        let now_unix = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        self.verify_jwt(token, now_unix).await
    }

    pub async fn verify_jwt(&self, token: &str, now_unix: u64) -> Option<VerifiedClaim> {
        if token.is_empty() || token.len() > MAX_JWT_BYTES {
            return None;
        }
        let mut parts = token.split('.');
        let header_b64 = parts.next()?;
        let payload_b64 = parts.next()?;
        let sig_b64 = parts.next()?;
        if parts.next().is_some() {
            return None;
        }
        let header_bytes = URL_SAFE_NO_PAD.decode(header_b64).ok()?;
        let header: Value = serde_json::from_slice(&header_bytes).ok()?;
        if header.get("alg")?.as_str()? != "RS256" {
            return None;
        }
        let kid = header.get("kid")?.as_str()?;
        if kid.is_empty() || kid.len() > 256 {
            return None;
        }
        let key = self.get_key(kid).await?;
        let signature = URL_SAFE_NO_PAD.decode(sig_b64).ok()?;
        let signing_input_len = header_b64.len() + 1 + payload_b64.len();
        let mut signing_input = Vec::with_capacity(signing_input_len);
        signing_input.extend_from_slice(header_b64.as_bytes());
        signing_input.push(b'.');
        signing_input.extend_from_slice(payload_b64.as_bytes());
        let public = RsaPublicKeyComponents {
            n: key.n.as_slice(),
            e: key.e.as_slice(),
        };
        public
            .verify(&RSA_PKCS1_2048_8192_SHA256, &signing_input, &signature)
            .ok()?;

        let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
        let claims: Value = serde_json::from_slice(&payload_bytes).ok()?;
        if claims.get("iss")?.as_str()? != self.config.issuer {
            return None;
        }
        let aud_ok = match claims.get("aud")? {
            Value::String(s) => s == &self.config.audience,
            Value::Array(items) => items
                .iter()
                .any(|item| item.as_str() == Some(self.config.audience.as_str())),
            _ => false,
        };
        if !aud_ok {
            return None;
        }
        let exp = claims.get("exp")?.as_u64()?;
        let iat = claims.get("iat")?.as_u64()?;
        if now_unix > exp.saturating_add(JWT_CLOCK_LEEWAY_SECS) {
            return None;
        }
        if iat > now_unix.saturating_add(JWT_CLOCK_LEEWAY_SECS) {
            return None;
        }
        if let Some(nbf) = claims.get("nbf").and_then(Value::as_u64)
            && nbf > now_unix.saturating_add(JWT_CLOCK_LEEWAY_SECS)
        {
            return None;
        }
        let sub = claims.get("sub")?.as_str()?;
        if sub.is_empty() || sub.len() > 256 || sub.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return None;
        }
        Some(VerifiedClaim {
            subject: sub.to_owned(),
        })
    }
}

fn parse_jwks(bytes: &[u8]) -> Option<BTreeMap<String, RsaJwk>> {
    #[derive(Deserialize)]
    struct JwksDoc {
        keys: Vec<JwkEntry>,
    }
    #[derive(Deserialize)]
    struct JwkEntry {
        kty: Option<String>,
        kid: Option<String>,
        n: Option<String>,
        e: Option<String>,
    }
    let doc: JwksDoc = serde_json::from_slice(bytes).ok()?;
    let mut keys = BTreeMap::new();
    for entry in doc.keys {
        if entry.kty.as_deref() != Some("RSA") {
            continue;
        }
        let (Some(kid), Some(n_b64), Some(e_b64)) = (entry.kid, entry.n, entry.e) else {
            continue;
        };
        let (Ok(n), Ok(e)) = (URL_SAFE_NO_PAD.decode(n_b64), URL_SAFE_NO_PAD.decode(e_b64)) else {
            continue;
        };
        if !n.is_empty() && !e.is_empty() {
            keys.insert(kid, RsaJwk { n, e });
        }
    }
    Some(keys)
}

fn plain_response(status: StatusCode) -> Response<HeldBody> {
    Response::builder()
        .status(status)
        .header(CACHE_CONTROL, "no-store")
        .header("x-content-type-options", "nosniff")
        .body(HeldBody::new(Full::new(Bytes::new()).boxed(), None))
        .expect("static response")
}

fn json_response(status: StatusCode, body: Bytes) -> Response<HeldBody> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .header(CACHE_CONTROL, "no-store")
        .header("x-content-type-options", "nosniff")
        .body(HeldBody::new(Full::new(body).boxed(), None))
        .expect("json response")
}

fn inject_oauth_scheme(event: &mut Value) -> bool {
    let Some(tools) = event
        .get_mut("result")
        .and_then(|r| r.get_mut("tools"))
        .and_then(Value::as_array_mut)
    else {
        return false;
    };
    let scheme = json!([{"type": "oauth2", "scopes": []}]);
    for tool in tools {
        if let Some(obj) = tool.as_object_mut() {
            obj.insert("securitySchemes".into(), scheme.clone());
        }
    }
    true
}

pub(crate) fn annotate_oauth_tools_body(content_type: &str, bytes: Bytes) -> Bytes {
    if content_type.contains("text/event-stream") {
        let Ok(text) = std::str::from_utf8(&bytes) else {
            return bytes;
        };
        let mut out = String::with_capacity(text.len() + 512);
        let mut changed = false;
        for segment in text.split_inclusive('\n') {
            if let Some(rest) = segment.strip_prefix("data:") {
                let trimmed = rest.trim();
                if !trimmed.is_empty()
                    && let Ok(mut event) = serde_json::from_str::<Value>(trimmed)
                    && inject_oauth_scheme(&mut event)
                    && let Ok(serialized) = serde_json::to_string(&event)
                {
                    out.push_str("data: ");
                    out.push_str(&serialized);
                    out.push('\n');
                    changed = true;
                    continue;
                }
            }
            out.push_str(segment);
        }
        if changed {
            return Bytes::from(out);
        }
        return bytes;
    }
    if let Ok(mut event) = serde_json::from_slice::<Value>(&bytes)
        && inject_oauth_scheme(&mut event)
        && let Ok(serialized) = serde_json::to_vec(&event)
    {
        return Bytes::from(serialized);
    }
    bytes
}

fn extract_sse_json_payload(bytes: &[u8]) -> Option<Bytes> {
    let text = std::str::from_utf8(bytes).ok()?;
    let normalized = if text.contains('\r') {
        std::borrow::Cow::Owned(text.replace("\r\n", "\n"))
    } else {
        std::borrow::Cow::Borrowed(text)
    };
    for block in normalized.split("\n\n") {
        let mut data_lines = Vec::new();
        for line in block.lines() {
            if let Some(rest) = line.strip_prefix("data:") {
                data_lines.push(rest.strip_prefix(' ').unwrap_or(rest));
            }
        }
        if data_lines.is_empty() {
            continue;
        }
        let payload = data_lines.join("\n");
        let trimmed = payload.trim();
        if trimmed.is_empty() {
            continue;
        }
        if serde_json::from_str::<Value>(trimmed).is_ok() {
            return Some(Bytes::copy_from_slice(trimmed.as_bytes()));
        }
    }
    None
}

fn find_sse_event_end(buf: &[u8]) -> Option<usize> {
    let lf = buf.windows(2).position(|w| w == b"\n\n").map(|i| i + 2);
    let crlf = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4);
    match (lf, crlf) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn sanitize_sse_event(event: Bytes) -> Option<Bytes> {
    let Ok(text) = std::str::from_utf8(&event) else {
        return Some(event);
    };
    let mut has_data = false;
    let mut has_non_empty_data = false;
    let mut has_event = false;
    for line in text.lines() {
        if line.starts_with("event:") {
            has_event = true;
        } else if let Some(rest) = line.strip_prefix("data:") {
            has_data = true;
            if !rest.trim().is_empty() {
                has_non_empty_data = true;
            }
        }
    }
    if !has_data {
        return Some(event);
    }
    if !has_non_empty_data {
        return None;
    }
    if has_event {
        return Some(event);
    }
    let prefix = if text.contains("\r\n") {
        "event: message\r\n"
    } else {
        "event: message\n"
    };
    let mut out = String::with_capacity(prefix.len() + text.len());
    out.push_str(prefix);
    out.push_str(text);
    Some(Bytes::from(out))
}

struct SanitizedSseBody {
    inner: HeldBody,
    buf: Vec<u8>,
    eof: bool,
}

impl SanitizedSseBody {
    fn new(inner: HeldBody) -> Self {
        Self {
            inner,
            buf: Vec::new(),
            eof: false,
        }
    }
}

impl Body for SanitizedSseBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        loop {
            if let Some(end) = find_sse_event_end(&self.buf) {
                let tail = self.buf.split_off(end);
                let event = Bytes::from(std::mem::replace(&mut self.buf, tail));
                if let Some(out) = sanitize_sse_event(event) {
                    return Poll::Ready(Some(Ok(Frame::data(out))));
                }
                continue;
            }
            if self.eof {
                if self.buf.is_empty() {
                    return Poll::Ready(None);
                }
                let event = Bytes::from(std::mem::take(&mut self.buf));
                if let Some(out) = sanitize_sse_event(event) {
                    return Poll::Ready(Some(Ok(Frame::data(out))));
                }
                return Poll::Ready(None);
            }
            match Pin::new(&mut self.inner).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    self.eof = true;
                }
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(chunk) => {
                        self.buf.extend_from_slice(&chunk);
                    }
                    Err(other) => {
                        if !self.buf.is_empty() {
                            let event = Bytes::from(std::mem::take(&mut self.buf));
                            if let Some(out) = sanitize_sse_event(event) {
                                // Only reachable if a non-data frame (trailers) arrives after data;
                                // we don't drop trailers either way, just emit buffered data first.
                                return Poll::Ready(Some(Ok(Frame::data(out))));
                            }
                        }
                        return Poll::Ready(Some(Ok(other)));
                    }
                },
                Poll::Ready(Some(Err(err))) => match err {},
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.eof && self.buf.is_empty()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

async fn handle_request<B: GatewayToolBackend + GatewayOwnerLifecycle>(
    verifier: Arc<JwksVerifier>,
    mcp: Arc<GatewayHttp<B>>,
    request: Request<hyper::body::Incoming>,
) -> std::result::Result<Response<HeldBody>, Infallible> {
    if request.uri().path() != "/mcp" || request.uri().query().is_some() {
        return Ok(plain_response(StatusCode::NOT_FOUND));
    }
    if !verifier.origin_allowed(request.headers()) {
        return Ok(plain_response(StatusCode::FORBIDDEN));
    }
    let Some(claim) = verifier.verify_headers(request.headers()).await else {
        return Ok(plain_response(StatusCode::UNAUTHORIZED));
    };
    if *request.method() == Method::GET {
        return Ok(plain_response(StatusCode::METHOD_NOT_ALLOWED));
    }
    if !matches!(*request.method(), Method::POST | Method::DELETE) {
        return Ok(plain_response(StatusCode::METHOD_NOT_ALLOWED));
    }
    let principal = mcp
        .policy()
        .authorize_public_mcp_subject(&verifier.config().issuer, &claim.subject);
    let (mut parts, body) = request.into_parts();
    // Normalize Host/Origin after outer Public MCP policy verified them so
    // the official SDK's internal loopback guard admits the in-process call.
    parts
        .headers
        .insert(http::header::HOST, HeaderValue::from_static("127.0.0.1"));
    parts.headers.remove(ORIGIN);
    parts.headers.remove("x-styx-tunnel-context");
    let client_accepts_sse = parts
        .headers
        .get(http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|a| a.contains("text/event-stream"));
    if parts.method == Method::POST {
        let has_both = parts
            .headers
            .get(http::header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|a| a.contains("application/json") && a.contains("text/event-stream"));
        if !has_both {
            parts.headers.insert(
                http::header::ACCEPT,
                HeaderValue::from_static("application/json, text/event-stream"),
            );
        }
    }

    let mut is_tools_list = false;
    let mut method: Option<String> = None;
    let body_bytes = if parts.method == Method::POST {
        match tokio::time::timeout(
            Duration::from_secs(5),
            http_body_util::Limited::new(body, MESSAGE_BYTES).collect(),
        )
        .await
        {
            Ok(Ok(collected)) => collected.to_bytes(),
            Ok(Err(_)) => return Ok(plain_response(StatusCode::PAYLOAD_TOO_LARGE)),
            Err(_) => return Ok(plain_response(StatusCode::REQUEST_TIMEOUT)),
        }
    } else {
        Bytes::new()
    };

    if parts.method == Method::POST
        && let Ok(parsed) = serde_json::from_slice::<Value>(&body_bytes)
    {
        method = parsed
            .get("method")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        if method.as_deref() == Some("server/discover") {
            let err = json!({
                "jsonrpc": "2.0",
                "id": parsed.get("id").cloned().unwrap_or(Value::Null),
                "error": {"code": -32601, "message": "Method not found"}
            });
            return Ok(json_response(
                StatusCode::NOT_FOUND,
                Bytes::from(err.to_string()),
            ));
        }
        is_tools_list = method.as_deref() == Some("tools/list");
    }
    let prefer_json_response = matches!(
        method.as_deref(),
        Some(
            "initialize"
                | "tools/list"
                | "ping"
                | "prompts/list"
                | "resources/list"
                | "resources/templates/list"
        )
    ) || !client_accepts_sse;

    let forwarded = Request::from_parts(parts, Full::new(body_bytes));
    let mut response = mcp.handle_authorized(principal, forwarded).await;
    crate::foreground::tunnel::record_gateway_http_status(response.status());
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );

    if response.status() == StatusCode::OK {
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/json")
            .to_owned();
        if content_type.contains("text/event-stream") {
            let (mut resp_parts, resp_body) = response.into_parts();
            resp_parts.headers.remove(http::header::CONTENT_LENGTH);
            if prefer_json_response {
                let Ok(collected) = resp_body.collect().await;
                let raw_bytes = collected.to_bytes();
                if let Some(json_payload) = extract_sse_json_payload(&raw_bytes) {
                    let final_bytes = if is_tools_list {
                        annotate_oauth_tools_body("application/json", json_payload)
                    } else {
                        json_payload
                    };
                    resp_parts
                        .headers
                        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
                    resp_parts
                        .headers
                        .remove(HeaderName::from_static("x-accel-buffering"));
                    response = Response::from_parts(
                        resp_parts,
                        HeldBody::new(Full::new(final_bytes).boxed(), None),
                    );
                } else {
                    let fallback = if is_tools_list {
                        annotate_oauth_tools_body(&content_type, raw_bytes)
                    } else {
                        raw_bytes
                    };
                    response = Response::from_parts(
                        resp_parts,
                        HeldBody::new(Full::new(fallback).boxed(), None),
                    );
                }
            } else {
                response = Response::from_parts(
                    resp_parts,
                    HeldBody::new(SanitizedSseBody::new(resp_body).boxed(), None),
                );
            }
        } else if is_tools_list {
            let (mut resp_parts, resp_body) = response.into_parts();
            let Ok(collected) = resp_body.collect().await;
            let rewritten = annotate_oauth_tools_body(&content_type, collected.to_bytes());
            resp_parts.headers.remove(http::header::CONTENT_LENGTH);
            response = Response::from_parts(
                resp_parts,
                HeldBody::new(Full::new(rewritten).boxed(), None),
            );
        }
    }
    Ok(response)
}

pub async fn serve<B: GatewayToolBackend + GatewayOwnerLifecycle>(
    listener: TcpListener,
    verifier: Arc<JwksVerifier>,
    mcp: Arc<GatewayHttp<B>>,
    stop: CancellationToken,
) -> std::io::Result<()> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = stop.cancelled() => break,
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let verifier = verifier.clone();
                let mcp = mcp.clone();
                let conn_stop = stop.child_token();
                connections.spawn(async move {
                    let io = TokioIo::new(stream);
                    let service = service_fn(move |req| {
                        handle_request(verifier.clone(), mcp.clone(), req)
                    });
                    let conn = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service);
                    tokio::pin!(conn);
                    tokio::select! {
                        _ = conn.as_mut() => {}
                        _ = conn_stop.cancelled() => {
                            conn.as_mut().graceful_shutdown();
                            let _ = tokio::time::timeout(Duration::from_secs(2), conn).await;
                        }
                    }
                });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
    while connections.join_next().await.is_some() {}
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::{
        rand::SystemRandom,
        rsa::{KeyPair, KeySize},
        signature::{KeyPair as _, RSA_PKCS1_SHA256},
    };

    fn test_rsa_keypair() -> (KeyPair, RsaJwk) {
        let keypair = KeyPair::generate(KeySize::Rsa2048).expect("rsa2048");
        let pub_der = keypair.public_key().as_ref();
        // Extract modulus (n) and public exponent (e) from PKCS#1 RSAPublicKey DER.
        let (_, seq) = x509_parser::der_parser::parse_der(pub_der).expect("der");
        let items = seq.as_sequence().expect("seq");
        let n = items[0].as_slice().expect("n");
        let e = items[1].as_slice().expect("e");
        let n = n.strip_prefix(&[0]).unwrap_or(n).to_vec();
        let e = e.strip_prefix(&[0]).unwrap_or(e).to_vec();
        (keypair, RsaJwk { n, e })
    }

    fn sign_jwt(keypair: &KeyPair, header: &Value, claims: &Value) -> String {
        let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).unwrap());
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
        let input = format!("{h}.{p}");
        let mut sig = vec![0u8; keypair.public_modulus_len()];
        keypair
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                input.as_bytes(),
                &mut sig,
            )
            .expect("sign");
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig))
    }

    fn sample_config() -> PublicMcpConfig {
        PublicMcpConfig {
            schema: 1,
            enabled: true,
            listen_port: 22128,
            issuer: "https://team.cloudflareaccess.com".into(),
            audience: "aud-123456".into(),
            jwks_url: "https://team.cloudflareaccess.com/cdn-cgi/access/certs".into(),
            jwt_header: default_jwt_header(),
            allowed_origins: default_allowed_origins(),
        }
    }

    #[tokio::test]
    async fn rs256_jwt_verification_enforces_signature_claims_and_origins() {
        let (kp, jwk) = test_rsa_keypair();
        let (other_kp, _) = test_rsa_keypair();
        let mut keys = BTreeMap::new();
        keys.insert("kid-1".into(), jwk);
        let verifier = JwksVerifier::with_static_keys(sample_config(), keys).unwrap();
        let now = 1_750_000_000u64;

        let header = json!({"alg": "RS256", "kid": "kid-1", "typ": "JWT"});
        let valid_claims = json!({
            "iss": "https://team.cloudflareaccess.com",
            "aud": ["aud-123456"],
            "sub": "user-abc",
            "iat": now - 10,
            "exp": now + 300
        });
        let good = sign_jwt(&kp, &header, &valid_claims);
        assert_eq!(
            verifier.verify_jwt(&good, now).await,
            Some(VerifiedClaim {
                subject: "user-abc".into()
            })
        );

        // String audience also accepted.
        let mut str_aud = valid_claims.clone();
        str_aud["aud"] = json!("aud-123456");
        let good_str_aud = sign_jwt(&kp, &header, &str_aud);
        assert!(verifier.verify_jwt(&good_str_aud, now).await.is_some());

        // Wrong signing key rejected.
        let forged = sign_jwt(&other_kp, &header, &valid_claims);
        assert!(verifier.verify_jwt(&forged, now).await.is_none());

        // Expired token rejected beyond leeway.
        let mut expired = valid_claims.clone();
        expired["exp"] = json!(now - 30);
        assert!(
            verifier
                .verify_jwt(&sign_jwt(&kp, &header, &expired), now)
                .await
                .is_none()
        );

        // Wrong issuer / audience / missing sub rejected.
        let mut bad_iss = valid_claims.clone();
        bad_iss["iss"] = json!("https://evil.example");
        assert!(
            verifier
                .verify_jwt(&sign_jwt(&kp, &header, &bad_iss), now)
                .await
                .is_none()
        );

        let mut bad_aud = valid_claims.clone();
        bad_aud["aud"] = json!(["wrong"]);
        assert!(
            verifier
                .verify_jwt(&sign_jwt(&kp, &header, &bad_aud), now)
                .await
                .is_none()
        );

        let mut bad_sub = valid_claims.clone();
        bad_sub["sub"] = json!("");
        assert!(
            verifier
                .verify_jwt(&sign_jwt(&kp, &header, &bad_sub), now)
                .await
                .is_none()
        );

        // Non-RS256 alg rejected.
        let bad_alg = json!({"alg": "none", "kid": "kid-1"});
        assert!(
            verifier
                .verify_jwt(&sign_jwt(&kp, &bad_alg, &valid_claims), now)
                .await
                .is_none()
        );

        // Origin checks.
        let mut headers = HeaderMap::new();
        assert!(verifier.origin_allowed(&headers));
        headers.insert(ORIGIN, HeaderValue::from_static("https://chatgpt.com"));
        assert!(verifier.origin_allowed(&headers));
        headers.insert(
            ORIGIN,
            HeaderValue::from_static("https://gemini.google.com"),
        );
        assert!(verifier.origin_allowed(&headers));
        headers.insert(ORIGIN, HeaderValue::from_static("https://evil.example"));
        assert!(!verifier.origin_allowed(&headers));
    }

    #[test]
    fn annotate_oauth_tools_handles_json_and_sse() {
        let raw_json = Bytes::from(
            json!({"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"desktop_list_tools"}]}})
                .to_string(),
        );
        let out_json: Value =
            serde_json::from_slice(&annotate_oauth_tools_body("application/json", raw_json))
                .unwrap();
        assert_eq!(
            out_json["result"]["tools"][0]["securitySchemes"],
            json!([{"type":"oauth2","scopes":[]}])
        );

        let raw_sse = Bytes::from(
            "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"android_list_displays\"}]}}\n\n",
        );
        let out_sse =
            String::from_utf8(annotate_oauth_tools_body("text/event-stream", raw_sse).to_vec())
                .unwrap();
        assert!(
            out_sse.contains("\"securitySchemes\":[{\"scopes\":[],\"type\":\"oauth2\"}]")
                || out_sse.contains("\"securitySchemes\":[{\"type\":\"oauth2\",\"scopes\":[]}]")
        );
    }

    #[cfg(unix)]
    #[test]
    fn configure_status_and_disable_round_trip_privately() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(status(dir.path()).unwrap().status, "not_configured");
        assert!(
            configure(
                dir.path(),
                "https://team.cloudflareaccess.com",
                "aud-1",
                "https://team.cloudflareaccess.com/cdn-cgi/access/certs",
                Some(22128),
                None,
                None,
                true,
                false,
            )
            .is_err()
        );
        let saved = configure(
            dir.path(),
            "https://team.cloudflareaccess.com",
            "aud-1",
            "https://team.cloudflareaccess.com/cdn-cgi/access/certs",
            Some(22128),
            None,
            None,
            true,
            true,
        )
        .unwrap();
        assert_eq!(saved.status, "enabled");
        assert_eq!(saved.listen_port, Some(22128));
        assert_eq!(
            fs::metadata(dir.path().join(CONFIG_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let disabled = disable(dir.path(), true).unwrap();
        assert_eq!(disabled.status, "disabled");
        assert!(!disabled.enabled);
    }

    struct StubBackend;
    impl GatewayToolBackend for StubBackend {
        async fn list_tools(
            &self,
            _: &crate::gateway::auth::VerifiedGatewayOwner,
            _: Option<rmcp::model::PaginatedRequestParams>,
        ) -> std::result::Result<rmcp::model::ListToolsResult, rmcp::ErrorData> {
            let tool: rmcp::model::Tool = serde_json::from_value(json!({
                "name": "desktop_list_tools",
                "description": "List native desktop tools",
                "inputSchema": {"type": "object", "properties": {}}
            }))
            .unwrap();
            Ok(rmcp::model::ListToolsResult {
                tools: vec![tool],
                ..Default::default()
            })
        }
        async fn call_tool(
            &self,
            _: &crate::gateway::auth::VerifiedGatewayOwner,
            _: rmcp::model::CallToolRequestParams,
        ) -> std::result::Result<rmcp::model::CallToolResult, rmcp::ErrorData> {
            Ok(rmcp::model::CallToolResult::success(vec![
                rmcp::model::ContentBlock::text("ok"),
            ]))
        }
    }
    impl GatewayOwnerLifecycle for StubBackend {
        fn fence_owner(
            &self,
            _: &crate::gateway::auth::VerifiedGatewayOwner,
        ) -> std::result::Result<(), crate::gateway::http::lifecycle::OwnerFenceError> {
            Ok(())
        }
        async fn cleanup_owner(
            &self,
            _: &crate::gateway::auth::VerifiedGatewayOwner,
            _: Duration,
        ) -> crate::gateway::http::lifecycle::OwnerCleanup {
            crate::gateway::http::lifecycle::OwnerCleanup::Complete
        }
    }

    #[tokio::test]
    async fn serve_enforces_jwt_origin_discover_and_oauth_tools_over_real_tcp() {
        let (kp, jwk) = test_rsa_keypair();
        let mut keys = BTreeMap::new();
        keys.insert("kid-live".into(), jwk);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut cfg = sample_config();
        cfg.listen_port = addr.port();
        let verifier = Arc::new(JwksVerifier::with_static_keys(cfg, keys).unwrap());
        let policy = Arc::new(
            crate::gateway::auth::GatewayBearerPolicy::new(
                b"ordinary_bearer_token_for_fixture_0123456789",
                vec!["127.0.0.1".into()],
                vec![],
            )
            .unwrap(),
        );
        let mcp = GatewayHttp::new(policy, Arc::new(StubBackend));
        let stop = CancellationToken::new();
        let server = tokio::spawn(serve(listener, verifier, mcp.clone(), stop.clone()));

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let jwt = sign_jwt(
            &kp,
            &json!({"alg": "RS256", "kid": "kid-live", "typ": "JWT"}),
            &json!({
                "iss": "https://team.cloudflareaccess.com",
                "aud": ["aud-123456"],
                "sub": "owner@example.com",
                "iat": now - 5,
                "exp": now + 300
            }),
        );
        let url = format!("http://{addr}/mcp");
        let client = reqwest::Client::new();

        // 1. Unauthenticated GET & POST -> 401
        assert_eq!(client.get(&url).send().await.unwrap().status(), 401);
        assert_eq!(
            client
                .post(&url)
                .header(CONTENT_TYPE, "application/json")
                .body("{}")
                .send()
                .await
                .unwrap()
                .status(),
            401
        );
        // 2. Bad Origin -> 403
        assert_eq!(
            client
                .post(&url)
                .header("Cf-Access-Jwt-Assertion", &jwt)
                .header(ORIGIN, "https://evil.example")
                .header(CONTENT_TYPE, "application/json")
                .body("{}")
                .send()
                .await
                .unwrap()
                .status(),
            403
        );
        // 3. Authenticated GET -> 405
        assert_eq!(
            client
                .get(&url)
                .header("Cf-Access-Jwt-Assertion", &jwt)
                .send()
                .await
                .unwrap()
                .status(),
            405
        );
        // 4. server/discover -> 404 JSON-RPC -32601
        let disc = client
            .post(&url)
            .header("Cf-Access-Jwt-Assertion", &jwt)
            .header(CONTENT_TYPE, "application/json")
            .body(json!({"jsonrpc":"2.0","id":7,"method":"server/discover"}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(disc.status(), 404);
        let disc_json: Value = disc.json().await.unwrap();
        assert_eq!(disc_json["error"]["code"], -32601);

        // 5. Real initialize -> 200 with Mcp-Session-Id (including external Host header!)
        let init = client
            .post(&url)
            .header("Host", "styx.example.test")
            .header("Cf-Access-Jwt-Assertion", &jwt)
            .header(CONTENT_TYPE, "application/json")
            .header("Accept", "application/json, text/event-stream")
            .body(
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {},
                        "clientInfo": {"name": "chatgpt-test", "version": "1"}
                    }
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(init.status(), 200);
        let sid = init
            .headers()
            .get("mcp-session-id")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();

        // 6. Real tools/list -> 200 JSON with desktop_list_tools AND oauth2 securitySchemes!
        let list = client
            .post(&url)
            .header("Host", "styx.example.test")
            .header("Cf-Access-Jwt-Assertion", &jwt)
            .header("Mcp-Session-Id", &sid)
            .header(CONTENT_TYPE, "application/json")
            .header("Accept", "application/json, text/event-stream")
            .body(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(list.status(), 200);
        assert_eq!(list.headers()[CONTENT_TYPE], "application/json");
        let list_json: Value = list.json().await.unwrap();
        assert_eq!(
            list_json["result"]["tools"][0]["name"],
            "desktop_list_tools"
        );
        assert_eq!(
            list_json["result"]["tools"][0]["securitySchemes"],
            json!([{"type":"oauth2","scopes":[]}])
        );

        stop.cancel();
        server.await.unwrap().unwrap();
        let shutdown = mcp
            .paired_shutdown_handle()
            .shutdown(Duration::from_secs(5))
            .await;
        assert!(shutdown.connections_joined);
    }

    #[test]
    fn extract_and_sanitize_sse_drop_priming_and_preserve_keepalive() {
        let sse = b"data: \nid: 0\nretry: 3000\n\n: keep-alive\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":\"a724de6b-0\",\"result\":{\"protocolVersion\":\"2025-11-25\"}}\n\n";
        let extracted = extract_sse_json_payload(sse).expect("json payload extracted");
        let parsed: Value = serde_json::from_slice(&extracted).unwrap();
        assert_eq!(parsed["id"], "a724de6b-0");
        assert_eq!(parsed["result"]["protocolVersion"], "2025-11-25");

        assert!(extract_sse_json_payload(b"data: \nid: 0\nretry: 3000\n\n").is_none());

        assert!(
            sanitize_sse_event(Bytes::from_static(b"data: \nid: 0\nretry: 3000\n\n")).is_none()
        );
        assert_eq!(
            sanitize_sse_event(Bytes::from_static(b":\n\n")),
            Some(Bytes::from_static(b":\n\n"))
        );
        let bare =
            Bytes::from_static(b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\nid: 0/0\n\n");
        let sanitized = sanitize_sse_event(bare).expect("sanitized data event");
        assert!(sanitized.starts_with(b"event: message\ndata: "));
        let with_event = Bytes::from_static(b"event: message\ndata: {\"ok\":true}\n\n");
        assert_eq!(sanitize_sse_event(with_event.clone()), Some(with_event));
    }

    struct ChunkedTestBody(std::collections::VecDeque<Bytes>);

    impl Body for ChunkedTestBody {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Ready(self.0.pop_front().map(|chunk| Ok(Frame::data(chunk))))
        }
    }

    #[tokio::test]
    async fn sanitized_sse_body_frames_coalesced_split_utf8_and_crlf_events() {
        async fn run(chunks: Vec<&[u8]>) -> String {
            let queue = chunks
                .into_iter()
                .map(Bytes::copy_from_slice)
                .collect::<std::collections::VecDeque<_>>();
            let held = HeldBody::new(ChunkedTestBody(queue).boxed(), None);
            let collected = SanitizedSseBody::new(held).collect().await.unwrap();
            String::from_utf8(collected.to_bytes().to_vec()).expect("valid utf8")
        }

        // 1. Coalesced priming + data event in a single chunk.
        let coalesced = run(vec![
            b"data: \nid: 0\nretry: 3000\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\nid: 1/0\n\n",
        ])
        .await;
        assert_eq!(
            coalesced,
            "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\nid: 1/0\n\n"
        );

        // 2. Single event split mid-UTF-8 multibyte character across chunks.
        let full = "data: {\"text\":\"中文结果\"}\nid: 2/0\n\n".as_bytes();
        let split_pos = full
            .windows(2)
            .position(|w| w == &"中".as_bytes()[..2])
            .unwrap()
            + 1;
        let split = run(vec![&full[..split_pos], &full[split_pos..]]).await;
        assert_eq!(
            split,
            "event: message\ndata: {\"text\":\"中文结果\"}\nid: 2/0\n\n"
        );

        // 3. CRLF-delimited priming + real event.
        let crlf = run(vec![
            b"data: \r\nid: 0\r\nretry: 3000\r\n\r\ndata: {\"ok\":true}\r\n\r\n",
        ])
        .await;
        assert_eq!(crlf, "event: message\r\ndata: {\"ok\":true}\r\n\r\n");
    }

    #[tokio::test]
    async fn serve_prefers_json_for_handshake_and_sanitizes_sse_calls_over_tcp() {
        let (kp, jwk) = test_rsa_keypair();
        let mut keys = BTreeMap::new();
        keys.insert("kid-google".into(), jwk);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut cfg = sample_config();
        cfg.listen_port = addr.port();
        let verifier = Arc::new(JwksVerifier::with_static_keys(cfg, keys).unwrap());
        let policy = Arc::new(
            crate::gateway::auth::GatewayBearerPolicy::new(
                b"ordinary_bearer_token_for_fixture_0123456789",
                vec!["127.0.0.1".into()],
                vec![],
            )
            .unwrap(),
        );
        let mcp = GatewayHttp::new(policy, Arc::new(StubBackend));
        let stop = CancellationToken::new();
        let server = tokio::spawn(serve(listener, verifier, mcp.clone(), stop.clone()));

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let jwt = sign_jwt(
            &kp,
            &json!({"alg": "RS256", "kid": "kid-google", "typ": "JWT"}),
            &json!({
                "iss": "https://team.cloudflareaccess.com",
                "aud": ["aud-123456"],
                "sub": "sidnvy@gmail.com",
                "iat": now - 5,
                "exp": now + 300
            }),
        );
        let url = format!("http://{addr}/mcp");
        let client = reqwest::Client::new();

        // 1. Google-style initialize (2025-11-25, charset utf-8, string uuid id) -> JSON directly.
        let init = client
            .post(&url)
            .header("Host", "styx.example.test")
            .header("Cf-Access-Jwt-Assertion", &jwt)
            .header(CONTENT_TYPE, "application/json; charset=utf-8")
            .header("Accept", "application/json, text/event-stream")
            .header("Mcp-Protocol-Version", "2025-11-25")
            .body(
                json!({
                    "jsonrpc": "2.0",
                    "method": "initialize",
                    "id": "a724de6b-0",
                    "params": {
                        "protocolVersion": "2025-11-25",
                        "capabilities": {"roots": {"listChanged": true}, "sampling": {}},
                        "clientInfo": {"name": "mcp", "version": "0.1.0"}
                    }
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(init.status(), 200);
        assert_eq!(init.headers()[CONTENT_TYPE], "application/json");
        let sid = init.headers()["mcp-session-id"]
            .to_str()
            .unwrap()
            .to_owned();
        let init_json: Value = init.json().await.unwrap();
        assert_eq!(init_json["id"], "a724de6b-0");
        assert_eq!(init_json["result"]["protocolVersion"], "2025-11-25");

        // 2. notifications/initialized -> 202 Accepted
        let initialized = client
            .post(&url)
            .header("Cf-Access-Jwt-Assertion", &jwt)
            .header("Mcp-Session-Id", &sid)
            .header("Mcp-Protocol-Version", "2025-11-25")
            .header(CONTENT_TYPE, "application/json; charset=utf-8")
            .header("Accept", "application/json, text/event-stream")
            .body(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(initialized.status(), 202);

        // 3. tools/list -> direct JSON with securitySchemes
        let list = client
            .post(&url)
            .header("Cf-Access-Jwt-Assertion", &jwt)
            .header("Mcp-Session-Id", &sid)
            .header("Mcp-Protocol-Version", "2025-11-25")
            .header(CONTENT_TYPE, "application/json; charset=utf-8")
            .header("Accept", "application/json, text/event-stream")
            .body(
                json!({"jsonrpc": "2.0", "id": "list-1", "method": "tools/list", "params": {}})
                    .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(list.status(), 200);
        assert_eq!(list.headers()[CONTENT_TYPE], "application/json");
        let list_json: Value = list.json().await.unwrap();
        assert_eq!(list_json["id"], "list-1");
        assert_eq!(
            list_json["result"]["tools"][0]["securitySchemes"],
            json!([{"type":"oauth2","scopes":[]}])
        );

        // 4. prompts/list -> direct JSON JSON-RPC -32601
        let prompts = client
            .post(&url)
            .header("Cf-Access-Jwt-Assertion", &jwt)
            .header("Mcp-Session-Id", &sid)
            .header("Mcp-Protocol-Version", "2025-11-25")
            .header(CONTENT_TYPE, "application/json")
            .header("Accept", "application/json, text/event-stream")
            .body(
                json!({"jsonrpc": "2.0", "id": "prompts-1", "method": "prompts/list"}).to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(prompts.status(), 200);
        assert_eq!(prompts.headers()[CONTENT_TYPE], "application/json");
        let prompts_json: Value = prompts.json().await.unwrap();
        assert_eq!(prompts_json["error"]["code"], -32601);

        // 5. tools/call with Accept: application/json, text/event-stream -> sanitized SSE (no priming, has event: message)
        let call_sse = client
            .post(&url)
            .header("Cf-Access-Jwt-Assertion", &jwt)
            .header("Mcp-Session-Id", &sid)
            .header("Mcp-Protocol-Version", "2025-11-25")
            .header(CONTENT_TYPE, "application/json")
            .header("Accept", "application/json, text/event-stream")
            .body(
                json!({
                    "jsonrpc": "2.0",
                    "id": "call-sse",
                    "method": "tools/call",
                    "params": {"name": "desktop_list_tools", "arguments": {}}
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(call_sse.status(), 200);
        assert!(
            call_sse.headers()[CONTENT_TYPE]
                .to_str()
                .unwrap()
                .contains("text/event-stream")
        );
        let sse_text = call_sse.text().await.unwrap();
        assert!(!sse_text.contains("data: \n"), "{sse_text}");
        assert!(!sse_text.contains("retry:"), "{sse_text}");
        assert!(sse_text.contains("event: message\ndata: "), "{sse_text}");
        assert!(sse_text.contains("\"ok\""), "{sse_text}");

        // 6. tools/call with Accept: application/json only -> direct JSON
        let call_json_resp = client
            .post(&url)
            .header("Cf-Access-Jwt-Assertion", &jwt)
            .header("Mcp-Session-Id", &sid)
            .header("Mcp-Protocol-Version", "2025-11-25")
            .header(CONTENT_TYPE, "application/json")
            .header("Accept", "application/json")
            .body(
                json!({
                    "jsonrpc": "2.0",
                    "id": "call-json",
                    "method": "tools/call",
                    "params": {"name": "desktop_list_tools", "arguments": {}}
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(call_json_resp.status(), 200);
        assert_eq!(call_json_resp.headers()[CONTENT_TYPE], "application/json");
        let call_json: Value = call_json_resp.json().await.unwrap();
        assert_eq!(call_json["id"], "call-json");
        assert_eq!(call_json["result"]["content"][0]["text"], "ok");

        // 7. tools/call WITH complete OpenAI _meta -> 200 OK (preserves TunnelConversation isolation)
        let call_openai_resp = client
            .post(&url)
            .header("Cf-Access-Jwt-Assertion", &jwt)
            .header("Mcp-Session-Id", &sid)
            .header("Mcp-Protocol-Version", "2025-11-25")
            .header(CONTENT_TYPE, "application/json")
            .header("Accept", "application/json")
            .body(
                json!({
                    "jsonrpc": "2.0",
                    "id": "call-openai",
                    "method": "tools/call",
                    "params": {
                        "name": "desktop_list_tools",
                        "arguments": {},
                        "_meta": {
                            "openai/organization": "org-1",
                            "openai/subject": "sub-1",
                            "openai/session": "chat-1"
                        }
                    }
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(call_openai_resp.status(), 200);
        let call_openai_json: Value = call_openai_resp.json().await.unwrap();
        assert_eq!(call_openai_json["id"], "call-openai");
        assert_eq!(call_openai_json["result"]["content"][0]["text"], "ok");

        // 8. tools/call WITH partial OpenAI _meta -> 400 Bad Request before dispatch
        let call_partial_resp = client
            .post(&url)
            .header("Cf-Access-Jwt-Assertion", &jwt)
            .header("Mcp-Session-Id", &sid)
            .header("Mcp-Protocol-Version", "2025-11-25")
            .header(CONTENT_TYPE, "application/json")
            .header("Accept", "application/json")
            .body(
                json!({
                    "jsonrpc": "2.0",
                    "id": "call-partial",
                    "method": "tools/call",
                    "params": {
                        "name": "desktop_list_tools",
                        "arguments": {},
                        "_meta": {"openai/session": "chat-1"}
                    }
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(call_partial_resp.status(), 400);

        stop.cancel();
        server.await.unwrap().unwrap();
        let shutdown = mcp
            .paired_shutdown_handle()
            .shutdown(Duration::from_secs(5))
            .await;
        assert!(shutdown.connections_joined);
    }
}
