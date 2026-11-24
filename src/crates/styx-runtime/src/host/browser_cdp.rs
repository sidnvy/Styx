//! Local-only opt-in Chrome DevTools Protocol (CDP) attachment configuration.
//! Disabled by default; never modifiable by remote MCP callers or Gateway relays.
use crate::store::{PrivateRoot, StoreError};
use futures_util::future::BoxFuture;
use serde::{Deserialize, Deserializer, Serialize};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use styx_contracts::error::ErrorCategory;
use url::{Host, Url};

pub const CDP_SESSION_ID: &str = "existing-browser";
pub const CDP_OWNER_PREFIX: &str = "host-browser-cdp-";
const FILE: &str = "browser-cdp.json";
const MAX_CONFIG_BYTES: usize = 4096;
const MAX_ENDPOINT_LEN: usize = 512;
const MAX_DEVTOOLS_PORT_FILE_BYTES: usize = 1024;
const PROBE_TIMEOUT: Duration = Duration::from_millis(150);

pub type DisconnectHook = Arc<dyn Fn() -> BoxFuture<'static, bool> + Send + Sync>;

/// Persisted local opt-in CDP configuration for attaching to an existing browser.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserCdpConfig {
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

/// Read-only status snapshot exposed to CLI and native desktop GUIs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserCdpStatus {
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(rename = "detectedEndpoint", skip_serializing_if = "Option::is_none")]
    pub detected_endpoint: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Persisted {
    schema: u16,
    cdp: BrowserCdpConfig,
}

#[derive(Serialize)]
struct PersistedRef<'a> {
    schema: u16,
    cdp: &'a BrowserCdpConfig,
}

/// Local UI / CLI patch for opt-in CDP settings.
/// Omitted `endpoint` preserves the current endpoint; `null` or `""` clears it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserCdpPatch {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_patch_endpoint")]
    pub endpoint: Option<Option<String>>,
}

fn deserialize_patch_endpoint<'de, D>(deserializer: D) -> Result<Option<Option<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = Option::<String>::deserialize(deserializer)?;
    Ok(Some(raw.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_owned())
        }
    })))
}

/// Validates and canonicalizes a loopback-only Chrome DevTools Protocol URL.
pub fn validate_cdp_endpoint(raw: &str) -> Result<String, ErrorCategory> {
    if raw.chars().any(char::is_control) {
        return Err(ErrorCategory::InvalidRequest);
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_ENDPOINT_LEN {
        return Err(ErrorCategory::InvalidRequest);
    }
    let parsed = Url::parse(trimmed).map_err(|_| ErrorCategory::InvalidRequest)?;
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(ErrorCategory::InvalidRequest);
    }
    let port = parsed
        .port()
        .filter(|port| *port > 0)
        .ok_or(ErrorCategory::InvalidRequest)?;
    let host = match parsed.host() {
        Some(Host::Ipv4(ip)) if ip == Ipv4Addr::LOCALHOST => "127.0.0.1",
        Some(Host::Ipv6(ip)) if ip == Ipv6Addr::LOCALHOST => "[::1]",
        Some(Host::Domain(domain)) if domain.eq_ignore_ascii_case("localhost") => "localhost",
        _ => return Err(ErrorCategory::InvalidRequest),
    };
    match parsed.scheme() {
        "http" => {
            if parsed.path() != "/" && !parsed.path().is_empty() {
                return Err(ErrorCategory::InvalidRequest);
            }
            Ok(format!("http://{host}:{port}"))
        }
        "ws" => {
            let path = parsed.path();
            if !valid_devtools_ws_path(path) {
                return Err(ErrorCategory::InvalidRequest);
            }
            Ok(format!("ws://{host}:{port}{path}"))
        }
        _ => Err(ErrorCategory::InvalidRequest),
    }
}

fn valid_devtools_ws_path(path: &str) -> bool {
    if path == "/devtools/browser" {
        return true;
    }
    let Some(suffix) = path.strip_prefix("/devtools/browser/") else {
        return false;
    };
    !suffix.is_empty()
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// Parses Chrome/Edge/Chromium's `DevToolsActivePort` contents into a loopback WebSocket URL.
pub fn parse_devtools_active_port(bytes: &[u8]) -> Result<String, ErrorCategory> {
    parse_devtools_active_port_for_host(bytes, "127.0.0.1")
}

fn parse_devtools_active_port_for_host(bytes: &[u8], host: &str) -> Result<String, ErrorCategory> {
    if bytes.is_empty() || bytes.len() > MAX_DEVTOOLS_PORT_FILE_BYTES {
        return Err(ErrorCategory::CapabilityUnsupported);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ErrorCategory::CapabilityUnsupported)?;
    let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
    let port_text = lines.next().ok_or(ErrorCategory::CapabilityUnsupported)?;
    let port: u16 = port_text
        .parse()
        .ok()
        .filter(|port| *port > 0)
        .ok_or(ErrorCategory::CapabilityUnsupported)?;
    let path = lines.next().unwrap_or("/devtools/browser");
    if lines.next().is_some() {
        return Err(ErrorCategory::CapabilityUnsupported);
    }
    validate_cdp_endpoint(&format!("ws://{host}:{port}{path}"))
        .map_err(|_| ErrorCategory::CapabilityUnsupported)
}

fn default_browser_data_dirs(channel: Option<&str>) -> Vec<PathBuf> {
    let channel = channel.unwrap_or("auto");
    let order: &[&str] = match channel {
        "chrome" => &["chrome"],
        "msedge" => &["msedge"],
        "chromium" => &["chromium"],
        "auto" => &["chrome", "msedge", "chromium"],
        _ => &["chrome", "msedge", "chromium"],
    };
    let mut dirs = Vec::new();
    #[cfg(target_os = "linux")]
    {
        let config_home = std::env::var_os("XDG_CONFIG_HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME")
                    .filter(|v| !v.is_empty())
                    .map(|home| PathBuf::from(home).join(".config"))
            });
        if let Some(base) = config_home {
            for item in order {
                let rel = match *item {
                    "chrome" => "google-chrome",
                    "msedge" => "microsoft-edge",
                    "chromium" => "chromium",
                    _ => continue,
                };
                dirs.push(base.join(rel));
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
            let base = PathBuf::from(home)
                .join("Library")
                .join("Application Support");
            for item in order {
                let rel = match *item {
                    "chrome" => "Google/Chrome",
                    "msedge" => "Microsoft Edge",
                    "chromium" => "Chromium",
                    _ => continue,
                };
                dirs.push(base.join(rel));
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        let local_app_data = std::env::var_os("LOCALAPPDATA")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("USERPROFILE")
                    .filter(|v| !v.is_empty())
                    .map(|home| PathBuf::from(home).join("AppData").join("Local"))
            });
        if let Some(base) = local_app_data {
            for item in order {
                let rel = match *item {
                    "chrome" => r"Google\Chrome\User Data",
                    "msedge" => r"Microsoft\Edge\User Data",
                    "chromium" => r"Chromium\User Data",
                    _ => continue,
                };
                dirs.push(base.join(rel));
            }
        }
    }
    dirs
}

fn read_bounded_regular_file(path: &Path, max_bytes: usize) -> Option<Vec<u8>> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_file() || meta.len() > max_bytes as u64 {
        return None;
    }
    let mut file = OpenOptions::new().read(true).open(path).ok()?;
    let opened = file.metadata().ok()?;
    if !opened.is_file() || opened.len() > max_bytes as u64 {
        return None;
    }
    let mut buf = Vec::with_capacity(opened.len() as usize);
    std::io::Read::by_ref(&mut file)
        .take((max_bytes + 1) as u64)
        .read_to_end(&mut buf)
        .ok()?;
    if buf.len() > max_bytes {
        return None;
    }
    Some(buf)
}

fn probe_loopback_host(port: u16) -> Option<&'static str> {
    let v4 = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    if TcpStream::connect_timeout(&v4, PROBE_TIMEOUT).is_ok() {
        return Some("127.0.0.1");
    }
    let v6 = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
    if TcpStream::connect_timeout(&v6, PROBE_TIMEOUT).is_ok() {
        return Some("[::1]");
    }
    None
}

/// Detects an active Chrome 144+ / Edge / Chromium `DevToolsActivePort` endpoint on loopback.
pub fn detect_devtools_active_port(channel: Option<&str>) -> Option<String> {
    detect_devtools_active_port_in(&default_browser_data_dirs(channel))
}

fn detect_devtools_active_port_in(data_dirs: &[PathBuf]) -> Option<String> {
    for dir in data_dirs {
        let port_file = dir.join("DevToolsActivePort");
        let Some(bytes) = read_bounded_regular_file(&port_file, MAX_DEVTOOLS_PORT_FILE_BYTES)
        else {
            continue;
        };
        let Ok(candidate) = parse_devtools_active_port(&bytes) else {
            continue;
        };
        let Ok(url) = Url::parse(&candidate) else {
            continue;
        };
        let Some(port) = url.port() else {
            continue;
        };
        if let Some(live_host) = probe_loopback_host(port) {
            return parse_devtools_active_port_for_host(&bytes, live_host).ok();
        }
    }
    None
}

/// Resolves the effective loopback CDP endpoint from explicit config or `DevToolsActivePort`.
pub fn resolve_cdp_endpoint(
    configured: Option<&str>,
    channel: Option<&str>,
) -> Result<String, ErrorCategory> {
    if let Some(endpoint) = configured {
        return validate_cdp_endpoint(endpoint);
    }
    detect_devtools_active_port(channel).ok_or(ErrorCategory::CapabilityUnsupported)
}

/// Host-local store for `browser-cdp.json` inside the Host's `PrivateRoot`.
pub struct BrowserCdpStore {
    path: PathBuf,
    root: PrivateRoot,
    gate: Arc<tokio::sync::Mutex<()>>,
    disconnect_hook: Mutex<Option<DisconnectHook>>,
}

impl BrowserCdpStore {
    /// Opens the store under the Host's private state directory (read-only until updated).
    pub fn open(path: &Path) -> Result<Arc<Self>, ErrorCategory> {
        let root = PrivateRoot::open(path).map_err(|_| ErrorCategory::IntegrityFailure)?;
        let store = Arc::new(Self {
            path: path.to_owned(),
            root,
            gate: Arc::new(tokio::sync::Mutex::new(())),
            disconnect_hook: Mutex::new(None),
        });
        let _ = store.read_validated()?;
        Ok(store)
    }

    pub fn attach_disconnect_hook(&self, hook: DisconnectHook) {
        *self
            .disconnect_hook
            .lock()
            .expect("BrowserCdpStore disconnect hook mutex") = Some(hook);
    }

    pub fn clear_disconnect_hook(&self) {
        *self
            .disconnect_hook
            .lock()
            .expect("BrowserCdpStore disconnect hook mutex") = None;
    }

    pub fn current(&self) -> Result<BrowserCdpConfig, ErrorCategory> {
        self.read_validated()
    }

    pub fn status(&self, channel: Option<&str>) -> Result<BrowserCdpStatus, ErrorCategory> {
        let cfg = self.current()?;
        let detected_endpoint = if cfg.enabled {
            detect_devtools_active_port(channel)
        } else {
            None
        };
        Ok(BrowserCdpStatus {
            enabled: cfg.enabled,
            endpoint: cfg.endpoint,
            detected_endpoint,
        })
    }

    /// Reads and returns the status synchronously if `browser-cdp.json` exists, or default OFF.
    pub fn read_status_readonly(
        path: &Path,
        channel: Option<&str>,
    ) -> Result<BrowserCdpStatus, ErrorCategory> {
        let store = Self::open(path)?;
        store.status(channel)
    }

    pub async fn update(
        self: &Arc<Self>,
        patch: BrowserCdpPatch,
    ) -> Result<(BrowserCdpConfig, bool), ErrorCategory> {
        let _guard = self.gate.lock().await;
        let this = self.clone();
        let (before, after) = tokio::task::spawn_blocking(move || this.update_sync(patch))
            .await
            .map_err(|_| ErrorCategory::ResultUnknown)??;
        let needs_disconnect = (before.enabled && !after.enabled)
            || (after.enabled && before.endpoint != after.endpoint);
        let hook = if needs_disconnect {
            self.disconnect_hook
                .lock()
                .expect("BrowserCdpStore disconnect hook mutex")
                .clone()
        } else {
            None
        };
        let mut applied = true;
        if let Some(hook) = hook {
            applied = hook().await;
        }
        Ok((after, applied))
    }

    pub fn update_sync(
        &self,
        patch: BrowserCdpPatch,
    ) -> Result<(BrowserCdpConfig, BrowserCdpConfig), ErrorCategory> {
        let before = self.read_validated()?;
        let enabled = patch.enabled.unwrap_or(before.enabled);
        let endpoint = match patch.endpoint {
            Some(Some(raw)) => Some(validate_cdp_endpoint(&raw)?),
            Some(None) => None,
            None => before.endpoint.clone(),
        };
        let after = BrowserCdpConfig { enabled, endpoint };
        if after != before {
            self.persist(&after)?;
        }
        Ok((before, after))
    }

    fn read_validated(&self) -> Result<BrowserCdpConfig, ErrorCategory> {
        let current = PrivateRoot::open(&self.path).map_err(|_| ErrorCategory::IntegrityFailure)?;
        if current.identity() != self.root.identity() {
            return Err(ErrorCategory::IntegrityFailure);
        }
        let raw = match self.root.read_raw(FILE, MAX_CONFIG_BYTES) {
            Ok(raw) => raw,
            Err(StoreError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(BrowserCdpConfig::default());
            }
            Err(_) => return Err(ErrorCategory::IntegrityFailure),
        };
        let persisted: Persisted =
            serde_json::from_slice(raw.bytes()).map_err(|_| ErrorCategory::IntegrityFailure)?;
        if persisted.schema != 1 {
            return Err(ErrorCategory::IntegrityFailure);
        }
        let endpoint = persisted
            .cdp
            .endpoint
            .as_deref()
            .map(validate_cdp_endpoint)
            .transpose()
            .map_err(|_| ErrorCategory::IntegrityFailure)?;
        Ok(BrowserCdpConfig {
            enabled: persisted.cdp.enabled,
            endpoint,
        })
    }

    fn persist(&self, config: &BrowserCdpConfig) -> Result<(), ErrorCategory> {
        if PrivateRoot::open(&self.path)
            .map_err(|_| ErrorCategory::IntegrityFailure)?
            .identity()
            != self.root.identity()
        {
            return Err(ErrorCategory::IntegrityFailure);
        }
        let bytes = serde_json::to_vec(&PersistedRef {
            schema: 1,
            cdp: config,
        })
        .map_err(|_| ErrorCategory::IntegrityFailure)?;
        let mut file = tempfile::NamedTempFile::new_in(&self.path)
            .map_err(|_| ErrorCategory::IntegrityFailure)?;
        file.write_all(&bytes)
            .and_then(|()| file.as_file().sync_all())
            .map_err(|_| ErrorCategory::IntegrityFailure)?;
        file.persist(self.path.join(FILE))
            .map_err(|_| ErrorCategory::IntegrityFailure)?;
        #[cfg(unix)]
        if std::fs::File::open(&self.path)
            .and_then(|f| f.sync_all())
            .is_err()
        {
            return Err(ErrorCategory::ResultUnknown);
        }
        match self.root.read_raw(FILE, MAX_CONFIG_BYTES) {
            Ok(raw) if raw.bytes() == bytes => Ok(()),
            _ => Err(ErrorCategory::ResultUnknown),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn private_root() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        dir
    }

    #[test]
    fn validate_cdp_endpoint_accepts_strict_loopback_and_rejects_remote_or_unsafe() {
        assert_eq!(
            validate_cdp_endpoint("http://127.0.0.1:9222").unwrap(),
            "http://127.0.0.1:9222"
        );
        assert_eq!(
            validate_cdp_endpoint("  http://LOCALHOST:9222/  ").unwrap(),
            "http://localhost:9222"
        );
        assert_eq!(
            validate_cdp_endpoint("ws://[::1]:9333/devtools/browser/abc-123_4.5").unwrap(),
            "ws://[::1]:9333/devtools/browser/abc-123_4.5"
        );
        assert_eq!(
            validate_cdp_endpoint("ws://127.0.0.1:9222/devtools/browser").unwrap(),
            "ws://127.0.0.1:9222/devtools/browser"
        );

        for invalid in [
            "",
            "   ",
            "https://127.0.0.1:9222",
            "wss://127.0.0.1:9222/devtools/browser",
            "http://192.168.1.10:9222",
            "http://0.0.0.0:9222",
            "http://[::]:9222",
            "http://example.com:9222",
            "http://127.0.0.1",
            "http://user@127.0.0.1:9222",
            "http://127.0.0.1:9222?token=1",
            "http://127.0.0.1:9222#frag",
            "http://127.0.0.1:9222/json/version",
            "ws://127.0.0.1:9222/other",
            "ws://127.0.0.1:9222/devtools/browser/../secret",
            "http://127.0.0.1:9222\n",
        ] {
            assert_eq!(
                validate_cdp_endpoint(invalid),
                Err(ErrorCategory::InvalidRequest),
                "expected invalid endpoint refusal for {invalid:?}"
            );
        }
    }

    #[test]
    fn parse_and_detect_devtools_active_port() {
        assert_eq!(
            parse_devtools_active_port(b"9222\n/devtools/browser/uuid-1\n").unwrap(),
            "ws://127.0.0.1:9222/devtools/browser/uuid-1"
        );
        assert_eq!(
            parse_devtools_active_port(b"9333\r\n").unwrap(),
            "ws://127.0.0.1:9333/devtools/browser"
        );
        assert_eq!(
            parse_devtools_active_port(b"0\n/devtools/browser\n"),
            Err(ErrorCategory::CapabilityUnsupported)
        );
        assert_eq!(
            parse_devtools_active_port(b"9222\n/other/path\n"),
            Err(ErrorCategory::CapabilityUnsupported)
        );
        assert_eq!(
            parse_devtools_active_port(b"9222\n/devtools/browser\nextra\n"),
            Err(ErrorCategory::CapabilityUnsupported)
        );

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let dir = tempfile::tempdir().unwrap();
        let stale = dir.path().join("stale");
        let live = dir.path().join("live");
        std::fs::create_dir(&stale).unwrap();
        std::fs::create_dir(&live).unwrap();
        // Unused high port vs live listening port
        std::fs::write(
            stale.join("DevToolsActivePort"),
            b"1\n/devtools/browser/stale\n",
        )
        .unwrap();
        std::fs::write(
            live.join("DevToolsActivePort"),
            format!("{port}\n/devtools/browser/live-1\n"),
        )
        .unwrap();
        let detected = detect_devtools_active_port_in(&[stale, live]);
        assert_eq!(
            detected.as_deref(),
            Some(format!("ws://127.0.0.1:{port}/devtools/browser/live-1").as_str())
        );
    }

    #[tokio::test]
    async fn cdp_store_defaults_off_persists_validates_and_runs_disconnect_hook() {
        let root = private_root();
        let store = BrowserCdpStore::open(root.path()).unwrap();
        assert_eq!(
            store.current().unwrap(),
            BrowserCdpConfig {
                enabled: false,
                endpoint: None
            }
        );

        let disconnected = Arc::new(AtomicBool::new(false));
        let hook_flag = disconnected.clone();
        store.attach_disconnect_hook(Arc::new(move || {
            hook_flag.store(true, Ordering::SeqCst);
            Box::pin(async { true })
        }));

        // Enabling without previous state does not need disconnect.
        let (cfg, applied) = store
            .update(serde_json::from_value(serde_json::json!({ "enabled": true })).unwrap())
            .await
            .unwrap();
        assert!(applied);
        assert!(cfg.enabled && cfg.endpoint.is_none());
        assert!(!disconnected.load(Ordering::SeqCst));

        // Remote endpoint is refused without altering saved state.
        let err = store
            .update(
                serde_json::from_value(serde_json::json!({ "endpoint": "http://10.0.0.5:9222" }))
                    .unwrap(),
            )
            .await
            .unwrap_err();
        assert_eq!(err, ErrorCategory::InvalidRequest);
        assert_eq!(store.current().unwrap(), cfg);

        // Changing endpoint while enabled disconnects old worker.
        let (cfg, applied) = store
            .update(
                serde_json::from_value(serde_json::json!({ "endpoint": "http://localhost:9222/" }))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(applied);
        assert_eq!(
            cfg,
            BrowserCdpConfig {
                enabled: true,
                endpoint: Some("http://localhost:9222".to_owned()),
            }
        );
        assert!(disconnected.swap(false, Ordering::SeqCst));

        // Reopen proves persistence; empty string clears endpoint; disabling disconnects.
        let reopened = BrowserCdpStore::open(root.path()).unwrap();
        assert_eq!(reopened.current().unwrap(), cfg);

        let (cfg, applied) = store
            .update(
                serde_json::from_value(serde_json::json!({ "enabled": false, "endpoint": "" }))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(applied);
        assert_eq!(
            cfg,
            BrowserCdpConfig {
                enabled: false,
                endpoint: None
            }
        );
        assert!(disconnected.load(Ordering::SeqCst));
    }
}
