//! Stable loopback CDP discovery proxy for long-lived clients such as
//! `chrome-devtools-mcp` and Antigravity. Reads the active Host's
//! `browser-extension-bridge.json` on each `/json/version` request and mints a
//! fresh single-use CDP WebSocket endpoint so clients survive Host restarts.
use super::CdpSessionScope;
use serde_json::json;
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use styx_contracts::error::ErrorCategory;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug)]
pub struct LocalCdpProxyConfig {
    pub state_dir: PathBuf,
    pub scope: Option<CdpSessionScope>,
    pub group_title: Option<String>,
    pub group_color: Option<String>,
    pub bind_port: u16,
}

/// Long-lived local HTTP `/json/version` + `/json/list` discovery server that
/// mints a fresh CDP WebSocket endpoint from whichever Styx Host is active.
pub struct LocalCdpProxy {
    port: u16,
    cancel: CancellationToken,
    accept_task: JoinHandle<()>,
}

impl LocalCdpProxy {
    pub async fn start(config: LocalCdpProxyConfig) -> Result<Self, ErrorCategory> {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], config.bind_port)))
            .await
            .map_err(|_| ErrorCategory::CapabilityUnsupported)?;
        let port = listener
            .local_addr()
            .map_err(|_| ErrorCategory::CapabilityUnsupported)?
            .port();
        let cancel = CancellationToken::new();
        let shared = Arc::new(config);
        let loop_cancel = cancel.clone();
        let accept_task = tokio::spawn(async move {
            accept_loop(listener, shared, loop_cancel).await;
        });
        Ok(Self {
            port,
            cancel,
            accept_task,
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn browser_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub async fn shutdown(self) {
        self.cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), self.accept_task).await;
    }
}

async fn accept_loop(
    listener: TcpListener,
    config: Arc<LocalCdpProxyConfig>,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            () = cancel.cancelled() => break,
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else {
                    break;
                };
                let cfg = config.clone();
                tokio::spawn(async move {
                    handle_http_client(stream, cfg).await;
                });
            }
        }
    }
}

async fn handle_http_client(mut stream: TcpStream, config: Arc<LocalCdpProxyConfig>) {
    let mut req_buf = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 1024];
    loop {
        let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut chunk)).await
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
    if req_buf.is_empty() {
        return;
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

    let (status, body) = if method != "GET" {
        (
            "405 Method Not Allowed",
            r#"{"error":"method_not_allowed"}"#.to_owned(),
        )
    } else if matches!(path, "/json/version" | "/json/version/") {
        let resolved_scope = match config.scope.clone() {
            Some(scope) => Some(scope),
            None => {
                let title = config
                    .group_title
                    .clone()
                    .unwrap_or_else(|| "Antigravity".to_owned());
                let color = config
                    .group_color
                    .clone()
                    .unwrap_or_else(|| "cyan".to_owned());
                let session_key = Some(format!("cdp-proxy:{title}"));
                Some(CdpSessionScope::TabGroup {
                    title,
                    color,
                    session_key,
                })
            }
        };
        match super::request_local_cdp_session(
            &config.state_dir,
            resolved_scope,
            config.group_title.clone(),
            config.group_color.clone(),
        )
        .await
        {
            Ok(session) => {
                let payload = json!({
                    "Browser": session.browser.unwrap_or_else(|| "Chrome/Extension-Bridge".to_owned()),
                    "Protocol-Version": "1.3",
                    "User-Agent": "Mozilla/5.0 Chrome/130.0.0.0",
                    "V8-Version": "V8",
                    "WebKit-Version": "537.36",
                    "webSocketDebuggerUrl": session.ws_endpoint,
                })
                .to_string();
                ("200 OK", payload)
            }
            Err(_) => (
                "503 Service Unavailable",
                r#"{"error":"styx_browser_extension_unavailable"}"#.to_owned(),
            ),
        }
    } else if matches!(path, "/json" | "/json/" | "/json/list" | "/json/list/") {
        ("200 OK", "[]".to_owned())
    } else {
        ("404 Not Found", r#"{"error":"not_found"}"#.to_owned())
    };

    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;
}
