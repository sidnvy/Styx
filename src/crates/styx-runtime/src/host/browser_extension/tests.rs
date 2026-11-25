use super::*;
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::{
    io::Cursor,
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};
use tokio_tungstenite::{client_async, tungstenite::Message};

async fn ws_connect(
    url_str: &str,
) -> Result<tokio_tungstenite::WebSocketStream<TcpStream>, Box<dyn std::error::Error>> {
    let parsed = url::Url::parse(url_str)?;
    let host = parsed.host_str().unwrap_or("127.0.0.1");
    let port = parsed.port().ok_or("missing port")?;
    let tcp = TcpStream::connect((host, port)).await?;
    let (ws, _) = client_async(url_str, tcp).await?;
    Ok(ws)
}

fn private_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    dir
}

#[test]
fn native_messaging_framing_roundtrips_and_enforces_limits() {
    let mut buf = Vec::new();
    let msg = r#"{"event":"extension.hello"}"#;
    native_host::write_native_message(&mut buf, msg).unwrap();
    let mut cursor = Cursor::new(buf);
    assert_eq!(
        native_host::read_native_message(&mut cursor)
            .unwrap()
            .as_deref(),
        Some(msg)
    );
    assert_eq!(native_host::read_native_message(&mut cursor).unwrap(), None);

    let mut zero = Cursor::new(0_u32.to_le_bytes().to_vec());
    assert!(native_host::read_native_message(&mut zero).is_err());

    let mut out = Vec::new();
    let huge = "a".repeat(1024 * 1024 + 1);
    assert!(native_host::write_native_message(&mut out, &huge).is_err());
}

#[test]
fn extension_install_extracts_assets_writes_manifest_and_uninstalls() {
    let state_dir = private_dir();
    let manifest_root = private_dir();
    let chrome_nm = manifest_root
        .path()
        .join("google-chrome/NativeMessagingHosts");
    let fake_bin = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();

    let dirs = vec![(chrome_nm.clone(), true)];
    install_with_manifest_dirs(state_dir.path(), &fake_bin, &dirs).unwrap();

    let st = status_with_manifest_dirs(state_dir.path(), &dirs, None).unwrap();
    assert!(st.installed);
    assert!(!st.connected);
    assert_eq!(st.extension_id, EXTENSION_ID);
    assert!(
        extension_dir(state_dir.path())
            .join("manifest.json")
            .is_file()
    );
    assert!(
        extension_dir(state_dir.path())
            .join("icons/icon128.png")
            .is_file()
    );

    let manifest_bytes = std::fs::read(chrome_nm.join(format!("{NATIVE_HOST_NAME}.json"))).unwrap();
    let manifest: Value = serde_json::from_slice(&manifest_bytes).unwrap();
    assert_eq!(manifest["name"], NATIVE_HOST_NAME);
    assert_eq!(manifest["type"], "stdio");
    assert_eq!(
        manifest["allowed_origins"],
        json!([format!("chrome-extension://{EXTENSION_ID}/")])
    );

    uninstall_with_manifest_dirs(state_dir.path(), &dirs).unwrap();
    let st_after = status_with_manifest_dirs(state_dir.path(), &dirs, None).unwrap();
    assert!(!st_after.installed);
    assert!(!chrome_nm.join(format!("{NATIVE_HOST_NAME}.json")).exists());
}

#[tokio::test]
async fn cdp_relay_authenticates_translates_targets_and_detaches_on_ws_close() {
    let state_dir = private_dir();
    let bridge = BrowserExtensionBridge::start(state_dir.path())
        .await
        .unwrap();
    assert!(!bridge.is_connected());
    assert!(bridge.open_cdp_session().is_err());

    let (port, token) = read_bridge_endpoint(state_dir.path()).unwrap();

    // Bad auth token is disconnected immediately without becoming connected peer.
    let bad = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let (bad_r, mut bad_w) = bad.into_split();
    bad_w
        .write_all(b"{\"type\":\"auth\",\"token\":\"wrong\"}\n")
        .await
        .unwrap();
    let mut bad_reader = BufReader::new(bad_r);
    let mut bad_ack = String::new();
    assert_eq!(bad_reader.read_line(&mut bad_ack).await.unwrap(), 0);
    assert!(!bridge.is_connected());

    // Valid authenticated extension peer connects and announces itself.
    let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let (read_half, mut write_half) = stream.into_split();
    write_half
        .write_all(format!("{}\n", json!({ "type": "auth", "token": token })).as_bytes())
        .await
        .unwrap();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&line).unwrap()["type"],
        "auth_ok"
    );

    write_half
        .write_all(
            format!(
                "{}\n",
                json!({
                    "event": "extension.hello",
                    "params": {
                        "extensionId": EXTENSION_ID,
                        "browser": "Chrome/158.0.0.0",
                        "userAgent": "Mozilla/5.0 Chrome/158.0.0.0",
                        "tabs": []
                    }
                })
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    for _ in 0..40 {
        if bridge.is_connected() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(bridge.is_connected());
    assert_eq!(bridge.browser_label().as_deref(), Some("Chrome/158.0.0.0"));

    // Mint single-use WS URL and verify unknown/reused path fails.
    let ws_url = bridge.open_cdp_session().unwrap();
    let bad_ws = format!(
        "ws://127.0.0.1:{}/devtools/browser/invalid",
        bridge.ws_port()
    );
    assert!(ws_connect(&bad_ws).await.is_err());

    let recorded_calls = Arc::new(StdMutex::new(Vec::<(String, Value)>::new()));
    let recorded_clone = recorded_calls.clone();
    let detach_seen = Arc::new(tokio::sync::Notify::new());
    let detach_notify = detach_seen.clone();

    let mock_ext = tokio::spawn(async move {
        let mut buf = String::new();
        while reader.read_line(&mut buf).await.unwrap_or(0) > 0 {
            let msg: Value = serde_json::from_str(buf.trim()).unwrap();
            buf.clear();
            let id = msg["id"].as_u64().unwrap();
            let method = msg["method"].as_str().unwrap().to_owned();
            let params = msg["params"].clone();
            recorded_clone
                .lock()
                .unwrap()
                .push((method.clone(), params.clone()));
            let reply = match method.as_str() {
                "tabs.list" => json!({ "id": id, "result": { "tabs": [
                    { "id": 101, "url": "https://dash.cloudflare.com/", "title": "Cloudflare", "active": true }
                ]}}),
                "tabs.create" => json!({ "id": id, "result": { "tab": {
                    "id": 102, "url": params["url"], "title": "New Tab", "active": true
                }}}),
                "debugger.attach" => json!({ "id": id, "result": { "ok": true } }),
                "debugger.sendCommand" => {
                    let cdp_method = params["method"].as_str().unwrap();
                    if cdp_method == "Target.getTargetInfo" {
                        let tab_id = params["tabId"].as_i64().unwrap();
                        json!({ "id": id, "result": { "targetInfo": {
                            "targetId": format!("target-{tab_id}"),
                            "type": "page",
                            "url": "https://dash.cloudflare.com/"
                        }}})
                    } else {
                        json!({ "id": id, "result": { "frameId": "f1", "cdpMethod": cdp_method } })
                    }
                }
                "debugger.detachAll" => {
                    detach_notify.notify_one();
                    json!({ "id": id, "result": { "detached": 2 } })
                }
                _ => json!({ "id": id, "result": {} }),
            };
            if write_half
                .write_all(format!("{reply}\n").as_bytes())
                .await
                .is_err()
            {
                break;
            }
        }
    });

    let mut ws = ws_connect(&ws_url).await.unwrap();
    // Single-use WS path cannot be dialed a second time.
    assert!(ws_connect(&ws_url).await.is_err());

    // 1. Browser.getVersion returns non-headless userAgent from extension.hello.
    ws.send(Message::Text(
        json!({"id": 1, "method": "Browser.getVersion"})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let v_reply: Value =
        serde_json::from_str(&ws.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
    assert_eq!(v_reply["id"], 1);
    assert!(
        !v_reply["result"]["userAgent"]
            .as_str()
            .unwrap()
            .contains("Headless")
    );

    // 2. Target.setAutoAttach emits Target.attachedToTarget BEFORE resolving.
    ws.send(Message::Text(
        json!({"id": 2, "method": "Target.setAutoAttach", "params": {"autoAttach": true, "flatten": true}})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let ev: Value =
        serde_json::from_str(&ws.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
    assert_eq!(ev["method"], "Target.attachedToTarget");
    let tab_session_id = ev["params"]["sessionId"].as_str().unwrap().to_owned();
    let aa_reply: Value =
        serde_json::from_str(&ws.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
    assert_eq!(aa_reply["id"], 2);

    // 3. Target.createTarget emits Target.attachedToTarget BEFORE returning targetId.
    ws.send(Message::Text(
        json!({"id": 3, "method": "Target.createTarget", "params": {"url": "https://example.com"}})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let ev2: Value =
        serde_json::from_str(&ws.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
    assert_eq!(ev2["method"], "Target.attachedToTarget");
    let create_reply: Value =
        serde_json::from_str(&ws.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
    assert_eq!(create_reply["id"], 3);
    assert_eq!(create_reply["result"]["targetId"], "target-102");

    // 4. Tab CDP command routes through debugger.sendCommand with tabId=101.
    ws.send(Message::Text(
        json!({"id": 4, "sessionId": tab_session_id, "method": "Page.navigate", "params": {"url": "https://example.org"}})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let nav_reply: Value =
        serde_json::from_str(&ws.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
    assert_eq!(nav_reply["id"], 4);
    assert_eq!(nav_reply["result"]["cdpMethod"], "Page.navigate");

    // 5. Closing WS triggers debugger.detachAll without closing Chrome.
    ws.close(None).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), detach_seen.notified())
        .await
        .unwrap();

    bridge.shutdown().await;
    assert!(!bridge_file_path(state_dir.path()).exists());
    let _ = tokio::time::timeout(Duration::from_secs(1), mock_ext).await;
}

#[ignore = "requires local Chromium, compiled styx binary, and Node 22 + Playwright assets"]
#[tokio::test]
async fn real_chromium_extension_bridge_e2e_with_playwright_worker() {
    use tokio::io::AsyncReadExt;
    use tokio_util::sync::CancellationToken;

    let styx_bin = PathBuf::from(std::env::var_os("STYX_TEST_BIN").expect("STYX_TEST_BIN"));
    let chrome_bin = PathBuf::from(std::env::var_os("STYX_TEST_CHROME").expect("STYX_TEST_CHROME"));
    let node22_bin = PathBuf::from(std::env::var_os("STYX_TEST_NODE22").expect("STYX_TEST_NODE22"));
    let node_modules =
        PathBuf::from(std::env::var_os("STYX_TEST_NODE_MODULES").expect("STYX_TEST_NODE_MODULES"));

    let root = private_dir();
    let state_dir = root.path().join("host-state");
    let xdg_dir = root.path().join("xdg");
    let user_data_dir = root.path().join("chrome-profile");
    let worker_stage = root.path().join("worker-stage");
    let output_dir = root.path().join("output");
    let workspace_dir = root.path().join("workspace");
    for d in [
        &state_dir,
        &xdg_dir,
        &user_data_dir,
        &worker_stage,
        &output_dir,
        &workspace_dir,
    ] {
        ensure_private_dir(d).unwrap();
    }

    // Extract extension + write Native Messaging manifests into XDG and user-data-dir.
    let nm_dirs = vec![
        (user_data_dir.join("NativeMessagingHosts"), true),
        (xdg_dir.join("chromium/NativeMessagingHosts"), true),
        (xdg_dir.join("google-chrome/NativeMessagingHosts"), true),
    ];
    install_with_manifest_dirs(&state_dir, &styx_bin, &nm_dirs).unwrap();

    // Start local HTTP fixture server with HttpOnly cookie + clickable button.
    let nonce = uuid::Uuid::new_v4().to_string();
    let http_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_port = http_listener.local_addr().unwrap().port();
    let probe_cookie_seen = Arc::new(StdMutex::new(Option::<String>::None));
    let probe_clone = probe_cookie_seen.clone();
    let http_nonce = nonce.clone();
    let http_stop = CancellationToken::new();
    let http_cancel = http_stop.clone();
    let http_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                () = http_cancel.cancelled() => break,
                accepted = http_listener.accept() => {
                    let Ok((mut sock, _)) = accepted else { break };
                    let probe = probe_clone.clone();
                    let expected = http_nonce.clone();
                    tokio::spawn(async move {
                        let mut buf = [0_u8; 8192];
                        let n = sock.read(&mut buf).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        let req = String::from_utf8_lossy(&buf[..n]);
                        let first_line = req.lines().next().unwrap_or("");
                        let path = first_line.split_whitespace().nth(1).unwrap_or("/");
                        let cookie_hdr = req
                            .lines()
                            .find(|l| l.to_ascii_lowercase().starts_with("cookie:"))
                            .map(|l| l.split_once(':').map_or("", |x| x.1).trim().to_owned())
                            .unwrap_or_default();
                        let (status, headers, body) = if path == "/initial" {
                            (
                                "200 OK",
                                format!("Content-Type: text/html\r\nSet-Cookie: styx_ext_cookie={expected}; Path=/; HttpOnly; SameSite=Lax\r\nCache-Control: no-store"),
                                format!(
                                    "<!doctype html><html><head><title>Ext Initial {expected}</title></head><body><h1>Styx Ext Fixture</h1><p id=\"marker\">Marker {expected}</p><button id=\"btn\" onclick=\"document.getElementById('status').textContent='Clicked OK'\">Click Me</button><p id=\"status\">Pending</p></body></html>"
                                ),
                            )
                        } else if path == "/probe" {
                            *probe.lock().unwrap() = Some(cookie_hdr.clone());
                            let ok = cookie_hdr.contains(&format!("styx_ext_cookie={expected}"));
                            (
                                "200 OK",
                                "Content-Type: text/html\r\nCache-Control: no-store".to_owned(),
                                format!(
                                    "<!doctype html><html><head><title>Ext Probe {expected}</title></head><body><p id=\"probe\">{}</p></body></html>",
                                    if ok { "Probe Cookie Verified" } else { "Probe Cookie Missing" }
                                ),
                            )
                        } else {
                            ("204 No Content", "Cache-Control: no-store".to_owned(), String::new())
                        };
                        let resp = format!(
                            "HTTP/1.1 {status}\r\n{headers}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = sock.write_all(resp.as_bytes()).await;
                    });
                }
            }
        }
    });

    // Start Host-owned BrowserExtensionBridge BEFORE spawning Chromium.
    let bridge = BrowserExtensionBridge::start(&state_dir).await.unwrap();

    struct ChromeGuard(Option<std::process::Child>);
    impl Drop for ChromeGuard {
        fn drop(&mut self) {
            if let Some(mut child) = self.0.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    let ext_dir_str = extension_dir(&state_dir).to_string_lossy().into_owned();
    let initial_url = format!("http://127.0.0.1:{http_port}/initial");
    let mut chrome_cmd = std::process::Command::new(&chrome_bin);
    chrome_cmd
        .env("XDG_CONFIG_HOME", &xdg_dir)
        .arg(format!("--user-data-dir={}", user_data_dir.display()))
        .arg(format!("--load-extension={ext_dir_str}"))
        .arg(format!("--disable-extensions-except={ext_dir_str}"))
        .arg("--no-first-run")
        .arg("--no-default-browser-check")
        .arg(&initial_url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let mut chrome_guard = ChromeGuard(Some(chrome_cmd.spawn().expect("spawn chromium")));

    for _ in 0..200 {
        if bridge.is_connected() {
            break;
        }
        assert!(
            chrome_guard
                .0
                .as_mut()
                .unwrap()
                .try_wait()
                .unwrap()
                .is_none(),
            "Chromium exited prematurely before extension connected"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        bridge.is_connected(),
        "Chromium extension did not connect via Native Messaging within 20s"
    );
    eprintln!(
        "E2E: Extension connected from browser={:?}",
        bridge.browser_label()
    );

    let ws_url = bridge.open_cdp_session().unwrap();
    eprintln!("E2E: Minted single-use extension CDP endpoint {ws_url}");

    // Stage worker.mjs, config.mjs, and node_modules symlink for real Node 22 worker test.
    let repo_worker_dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../providers/browser-worker");
    std::fs::copy(
        repo_worker_dir.join("worker.mjs"),
        worker_stage.join("worker.mjs"),
    )
    .unwrap();
    std::fs::copy(
        repo_worker_dir.join("config.mjs"),
        worker_stage.join("config.mjs"),
    )
    .unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&node_modules, worker_stage.join("node_modules")).unwrap();

    let worker_cfg = worker_stage.join("cdp-worker.json");
    let worker_cfg_bytes = serde_json::to_vec(&json!({
        "schema": 1,
        "output_dir": output_dir,
        "workspace_dir": workspace_dir,
        "cdp_endpoint": ws_url,
    }))
    .unwrap();
    atomic_write(&worker_stage, &worker_cfg, &worker_cfg_bytes, false).unwrap();

    let driver_script = worker_stage.join("e2e-driver.mjs");
    std::fs::write(
        &driver_script,
        r#"
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const stageDir = path.dirname(fileURLToPath(import.meta.url));
const workerEntry = path.join(stageDir, 'worker.mjs');
const configPath = path.join(stageDir, 'cdp-worker.json');
const baseUrl = process.env.STYX_E2E_BASE_URL;
const nonce = process.env.STYX_E2E_NONCE;

const transport = new StdioClientTransport({
  command: process.execPath,
  args: [workerEntry, '--config', configPath],
  stderr: 'pipe',
});
let workerStderr = '';
transport.stderr.on('data', chunk => { workerStderr += chunk.toString(); });

let closedResolve;
const workerClosed = new Promise(r => { closedResolve = r; });
const client = new Client({ name: 'styx-ext-e2e', version: '1.0.0' });
client.onclose = closedResolve;
try {
  await client.connect(transport);
} catch (err) {
  throw new Error(`connect failed: ${err?.message || err}\nworkerStderr=${workerStderr}`);
}

const textOf = res => (res.content || []).filter(c => c.type === 'text').map(c => c.text).join('\n');
async function call(name, args = {}) {
  const res = await client.callTool({ name, arguments: args }, undefined, { timeout: 30000 });
  assert.notEqual(res.isError, true, `${name} failed: ${textOf(res)}\nstderr=${workerStderr}`);
  return res;
}

const tabs = textOf(await call('browser_tabs', { action: 'list' }));
assert.match(tabs, new RegExp(`Ext Initial ${nonce}`), `missing initial tab in: ${tabs}`);

const snap1 = textOf(await call('browser_snapshot', {}));
assert.match(snap1, /Click Me/, `missing Click Me button in snapshot: ${snap1}`);
const refMatch = snap1.match(/button "Click Me" \[ref=([^\]]+)\]/);
assert.ok(refMatch, `could not extract button ref from snapshot: ${snap1}`);

await call('browser_click', { target: refMatch[1], element: 'Click Me' });
const snap2 = textOf(await call('browser_snapshot', {}));
assert.match(snap2, /Clicked OK/, `click did not update DOM in snapshot: ${snap2}`);

await call('browser_tabs', { action: 'new' });
await call('browser_navigate', { url: `${baseUrl}/probe` });
const snap3 = textOf(await call('browser_snapshot', {}));
assert.match(snap3, /Probe Cookie Verified/, `probe cookie missing in snapshot: ${snap3}`);

const shot = await call('browser_take_screenshot', { scale: 'css' });
assert.ok(shot.content.length > 0, 'screenshot returned empty content');

const closeRes = await call('browser_close', {});
assert.equal(closeRes.structuredContent?.styx_context_closed, true);
await workerClosed;
console.log('NODE_E2E_SUCCESS');
"#,
    )
    .unwrap();

    let mut driver = tokio::process::Command::new(&node22_bin);
    driver
        .arg(&driver_script)
        .env("STYX_E2E_BASE_URL", format!("http://127.0.0.1:{http_port}"))
        .env("STYX_E2E_NONCE", &nonce)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let output = tokio::time::timeout(Duration::from_secs(60), driver.output())
        .await
        .expect("Node E2E driver timed out")
        .expect("run Node E2E driver");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() && stdout.contains("NODE_E2E_SUCCESS"),
        "E2E driver failed (status={:?}):\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status
    );

    assert!(
        probe_cookie_seen
            .lock()
            .unwrap()
            .as_deref()
            .is_some_and(|c| c.contains(&format!("styx_ext_cookie={nonce}"))),
        "probe request did not carry HttpOnly cookie"
    );

    // Chromium must still be running after browser_close detaches!
    assert!(
        chrome_guard
            .0
            .as_mut()
            .unwrap()
            .try_wait()
            .unwrap()
            .is_none(),
        "Chromium exited on browser_close instead of staying open"
    );

    drop(chrome_guard);
    http_stop.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), http_task).await;
    bridge.shutdown().await;
}
