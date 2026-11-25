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
                "debugger.detach" => {
                    detach_notify.notify_one();
                    json!({ "id": id, "result": { "ok": true } })
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

    // 5. Focus-stealing CDP calls are suppressed cleanly before touching extension.
    ws.send(Message::Text(
        json!({"id": 5, "sessionId": tab_session_id, "method": "Page.bringToFront", "params": {}})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let btf_reply: Value =
        serde_json::from_str(&ws.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
    assert_eq!(btf_reply["id"], 5);
    assert!(
        !recorded_calls
            .lock()
            .unwrap()
            .iter()
            .any(|(m, p)| m == "tabs.activate" || p["method"] == "Page.bringToFront")
    );

    // 6. Closing WS detaches only this relay's tabs without calling debugger.detachAll.
    ws.close(None).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), detach_seen.notified())
        .await
        .unwrap();
    assert!(
        recorded_calls
            .lock()
            .unwrap()
            .iter()
            .any(|(m, _)| m == "debugger.detach")
    );

    bridge.shutdown().await;
    assert!(!bridge_file_path(state_dir.path()).exists());
    let _ = tokio::time::timeout(Duration::from_secs(1), mock_ext).await;
}

#[tokio::test]
async fn parallel_tab_group_relays_isolate_tabs_and_close_independently() {
    let state_dir = private_dir();
    let bridge = BrowserExtensionBridge::start(state_dir.path())
        .await
        .unwrap();
    let cfg: Value =
        serde_json::from_slice(&std::fs::read(bridge_file_path(state_dir.path())).unwrap())
            .unwrap();

    let stream = TcpStream::connect(("127.0.0.1", cfg["port"].as_u64().unwrap() as u16))
        .await
        .unwrap();
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    write_half
        .write_all(format!("{}\n", json!({ "type": "auth", "token": cfg["token"] })).as_bytes())
        .await
        .unwrap();
    let mut ack = String::new();
    reader.read_line(&mut ack).await.unwrap();
    write_half
        .write_all(
            format!(
                "{}\n",
                json!({
                    "event": "extension.hello",
                    "params": {
                        "browser": "Chrome/158.0.0.0",
                        "userAgent": "Mozilla/5.0 Chrome/158.0.0.0",
                        "tabs": [{ "id": 101, "url": "https://user.example/", "title": "User", "active": true }]
                    }
                })
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(40)).await;

    let calls = Arc::new(StdMutex::new(Vec::<(String, Value)>::new()));
    let calls_ref = calls.clone();
    let next_tab = Arc::new(std::sync::atomic::AtomicI64::new(201));
    let next_group = Arc::new(std::sync::atomic::AtomicI64::new(700));
    let detached_tabs = Arc::new(StdMutex::new(Vec::<i64>::new()));
    let detached_ref = detached_tabs.clone();
    let detached_notify = Arc::new(tokio::sync::Notify::new());
    let notify_ref = detached_notify.clone();

    let mock_ext = tokio::spawn(async move {
        let mut buf = String::new();
        while reader.read_line(&mut buf).await.unwrap_or(0) > 0 {
            let msg: Value = serde_json::from_str(buf.trim()).unwrap();
            buf.clear();
            let id = msg["id"].as_u64().unwrap();
            let method = msg["method"].as_str().unwrap().to_owned();
            let params = msg["params"].clone();
            calls_ref
                .lock()
                .unwrap()
                .push((method.clone(), params.clone()));
            let reply = match method.as_str() {
                "tabs.create" => {
                    let tab_id = next_tab.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let group_id = params
                        .get("groupId")
                        .and_then(Value::as_i64)
                        .unwrap_or_else(|| {
                            next_group.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                        });
                    json!({ "id": id, "result": {
                        "tab": {
                            "id": tab_id,
                            "url": params["url"],
                            "title": "Bg",
                            "active": false,
                            "groupId": group_id,
                            "isolated": params["isolated"]
                        },
                        "groupId": group_id
                    }})
                }
                "debugger.attach" => json!({ "id": id, "result": { "ok": true } }),
                "debugger.sendCommand" => {
                    let cdp_method = params["method"].as_str().unwrap();
                    let tab_id = params["tabId"].as_i64().unwrap();
                    if cdp_method == "Target.getTargetInfo" {
                        json!({ "id": id, "result": { "targetInfo": {
                            "targetId": format!("target-{tab_id}"),
                            "type": "page",
                            "url": "about:blank"
                        }}})
                    } else {
                        json!({ "id": id, "result": { "tabId": tab_id, "cdpMethod": cdp_method } })
                    }
                }
                "debugger.detach" => {
                    detached_ref
                        .lock()
                        .unwrap()
                        .push(params["tabId"].as_i64().unwrap());
                    notify_ref.notify_one();
                    json!({ "id": id, "result": { "ok": true } })
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

    let ws1_url = bridge
        .open_cdp_session_with_scope(CdpSessionScope::TabGroup {
            title: "Styx · 1".into(),
            color: "blue".into(),
        })
        .unwrap();
    let ws2_url = bridge
        .open_cdp_session_with_scope(CdpSessionScope::TabGroup {
            title: "Styx · 2".into(),
            color: "cyan".into(),
        })
        .unwrap();
    let mut ws1 = ws_connect(&ws1_url).await.unwrap();
    let mut ws2 = ws_connect(&ws2_url).await.unwrap();

    for (ws, cid) in [(&mut ws1, 1), (&mut ws2, 2)] {
        ws.send(Message::Text(
            json!({"id": cid, "method": "Target.setAutoAttach", "params": {"autoAttach": true, "flatten": true}})
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    }
    let ev1: Value =
        serde_json::from_str(&ws1.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
    let _rep1: Value =
        serde_json::from_str(&ws1.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
    let ev2: Value =
        serde_json::from_str(&ws2.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
    let _rep2: Value =
        serde_json::from_str(&ws2.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();

    let sid1 = ev1["params"]["sessionId"].as_str().unwrap().to_owned();
    let sid2 = ev2["params"]["sessionId"].as_str().unwrap().to_owned();
    assert_eq!(ev1["params"]["targetInfo"]["targetId"], "target-201");
    assert_eq!(ev2["params"]["targetInfo"]["targetId"], "target-202");

    // Closing relay 1 detaches ONLY tab 201; relay 2 continues operating tab 202.
    ws1.close(None).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), detached_notify.notified())
        .await
        .unwrap();
    assert_eq!(*detached_tabs.lock().unwrap(), vec![201]);

    ws2.send(Message::Text(
        json!({"id": 9, "sessionId": sid2, "method": "Page.reload", "params": {}})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let reload_rep: Value =
        serde_json::from_str(&ws2.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
    assert_eq!(reload_rep["id"], 9);
    assert_eq!(reload_rep["result"]["tabId"], 202);
    assert_ne!(sid1, sid2);
    assert!(
        !calls
            .lock()
            .unwrap()
            .iter()
            .any(|(m, p)| m == "debugger.attach" && p["tabId"] == 101)
    );

    ws2.close(None).await.unwrap();
    bridge.shutdown().await;
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

    // Start local HTTP fixture server with HttpOnly cookie + clickable button + form submit.
    let nonce = uuid::Uuid::new_v4().to_string();
    let http_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_port = http_listener.local_addr().unwrap().port();
    let probe_cookie_seen = Arc::new(StdMutex::new(Option::<String>::None));
    let submitted_payload = Arc::new(StdMutex::new(Option::<String>::None));
    let probe_clone = probe_cookie_seen.clone();
    let submit_clone = submitted_payload.clone();
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
                    let submit = submit_clone.clone();
                    let expected = http_nonce.clone();
                    tokio::spawn(async move {
                        let mut buf = Vec::with_capacity(8192);
                        let mut tmp = [0_u8; 4096];
                        let header_end = loop {
                            let n = sock.read(&mut tmp).await.unwrap_or(0);
                            if n == 0 {
                                break None;
                            }
                            buf.extend_from_slice(&tmp[..n]);
                            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                break Some(pos + 4);
                            }
                            if buf.len() > 64 * 1024 {
                                break None;
                            }
                        };
                        let Some(header_end) = header_end else {
                            return;
                        };
                        let headers_str = String::from_utf8_lossy(&buf[..header_end]).into_owned();
                        let content_len = headers_str
                            .lines()
                            .find_map(|l| {
                                l.split_once(':').and_then(|(k, v)| {
                                    k.eq_ignore_ascii_case("content-length")
                                        .then(|| v.trim().parse::<usize>().ok())
                                        .flatten()
                                })
                            })
                            .unwrap_or(0)
                            .min(64 * 1024);
                        while buf.len() < header_end + content_len {
                            let n = sock.read(&mut tmp).await.unwrap_or(0);
                            if n == 0 {
                                break;
                            }
                            buf.extend_from_slice(&tmp[..n]);
                        }
                        let req_body = String::from_utf8_lossy(
                            &buf[header_end..buf.len().min(header_end + content_len)],
                        )
                        .into_owned();
                        let first_line = headers_str.lines().next().unwrap_or("");
                        let mut parts = first_line.split_whitespace();
                        let req_method = parts.next().unwrap_or("GET");
                        let path = parts.next().unwrap_or("/");
                        let cookie_hdr = headers_str
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
                        } else if path == "/form" {
                            (
                                "200 OK",
                                "Content-Type: text/html\r\nCache-Control: no-store".to_owned(),
                                "<!doctype html><html><head><title>Ext Daily Form</title></head><body>\
                                <h1>Daily Browser Operations Form</h1>\
                                <label>Username <input id=\"username\" aria-label=\"Username\" type=\"text\" /></label>\
                                <label>Note <input id=\"note\" aria-label=\"Note\" type=\"text\" /></label>\
                                <label><input id=\"agree\" aria-label=\"Agree\" type=\"checkbox\" /> Agree</label>\
                                <label>Role <select id=\"role\" aria-label=\"Role\"><option value=\"viewer\">Viewer</option><option value=\"editor\">Editor</option><option value=\"admin\">Admin</option></select></label>\
                                <button id=\"submit-btn\" type=\"button\">Submit Form</button>\
                                <button id=\"async-btn\" type=\"button\">Start Async</button>\
                                <p id=\"result\">Unsubmitted</p>\
                                <p id=\"key-out\">No Key</p>\
                                <p id=\"async-out\">Waiting</p>\
                                <script>\
                                document.getElementById('submit-btn').addEventListener('click', async () => {\
                                  const payload = {\
                                    username: document.getElementById('username').value,\
                                    note: document.getElementById('note').value,\
                                    agree: document.getElementById('agree').checked,\
                                    role: document.getElementById('role').value,\
                                  };\
                                  const res = await fetch('/submit', {\
                                    method: 'POST',\
                                    headers: { 'Content-Type': 'application/json' },\
                                    body: JSON.stringify(payload),\
                                  });\
                                  if (res.ok) {\
                                    document.getElementById('result').textContent =\
                                      'Submitted OK: ' + payload.username + '|' + payload.note + '|' + payload.agree + '|' + payload.role;\
                                  }\
                                });\
                                document.getElementById('async-btn').addEventListener('click', () => {\
                                  setTimeout(() => {\
                                    document.getElementById('async-out').textContent = 'Async Ready';\
                                  }, 250);\
                                });\
                                window.addEventListener('keydown', (e) => {\
                                  if (e.key === 'F8') {\
                                    document.getElementById('key-out').textContent = 'Key F8 Observed';\
                                  }\
                                });\
                                </script></body></html>"
                                    .to_owned(),
                            )
                        } else if req_method == "POST" && path == "/submit" {
                            if cookie_hdr.contains(&format!("styx_ext_cookie={expected}")) {
                                *submit.lock().unwrap() = Some(req_body);
                                (
                                    "200 OK",
                                    "Content-Type: application/json\r\nCache-Control: no-store".to_owned(),
                                    r#"{"ok":true}"#.to_owned(),
                                )
                            } else {
                                (
                                    "403 Forbidden",
                                    "Content-Type: application/json\r\nCache-Control: no-store".to_owned(),
                                    r#"{"error":"missing_cookie"}"#.to_owned(),
                                )
                            }
                        } else if path == "/large" {
                            use std::fmt::Write as _;
                            let mut body = String::from(
                                "<!doctype html><html><head><title>Ext Large</title></head><body><h1>Large Snapshot Fixture</h1>",
                            );
                            for idx in 0..4500 {
                                let _ = write!(
                                    body,
                                    "<p>Large snapshot paragraph entry number {idx} with deterministic payload {expected}</p>"
                                );
                            }
                            body.push_str("<p id=\"tail\">Large End Verified</p></body></html>");
                            (
                                "200 OK",
                                "Content-Type: text/html\r\nCache-Control: no-store".to_owned(),
                                body,
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

await call('browser_navigate', { url: `${baseUrl}/large` });
const largeSnap = textOf(await call('browser_snapshot', {}));
assert.ok(Buffer.byteLength(largeSnap) > 200 * 1024, `expected >200KB snapshot, got ${Buffer.byteLength(largeSnap)}`);
assert.match(largeSnap, /Large End Verified/);

const badTab = await client.callTool({ name: 'browser_tabs', arguments: { action: 'select', index: 99 } }, undefined, { timeout: 30000 });
assert.equal(badTab.isError, true, 'out-of-range tab index should fail cleanly');
assert.notEqual(textOf(badTab), 'browser_native_result_unconfirmed');
assert.equal(badTab._meta?.['app.styx/browser-native']?.dispatched, true);
assert.equal(badTab._meta?.['app.styx/browser-native']?.reason, undefined);

const afterErrSnap = textOf(await call('browser_snapshot', {}));
assert.match(afterErrSnap, /Large End Verified/, 'session should still snapshot cleanly after tool error');

// Close the extra non-isolated tab opened in Phase 1 so Phase 2 starts with only the user's initial tab.
await call('browser_tabs', { action: 'close' });

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

    // Phase 2: Full Rust Host stack (`browser_sessions::Engine` -> `HostCoordinator`
    // -> `providers::browser::BrowserWorker` + `LinuxOwnedScope` -> `worker.mjs`
    // -> `BrowserExtensionBridge` -> real Chromium).
    #[cfg(target_os = "linux")]
    {
        use crate::host::{
            browser_sessions::{Engine, operations::BrowserBootstrap, operations::BrowserPort},
            callers::OwnerRecord,
            coordinator::HostCoordinator,
            protocol::wire::{BrowserSessionCommand, OwnerRef},
        };
        use crate::providers::browser::OwnedBrowserConfig;
        use styx_contracts::{
            capability::{Authorization, Availability, CapabilityDescriptor, CapabilityId, Scope},
            error::{ErrorCategory, Recovery},
            identity::OwnerId,
        };
        use styx_core::{operations::OperationLedger, policy::AdmissionFacts};

        struct LiveBridgeBootstrap {
            bridge: Arc<BrowserExtensionBridge>,
            node_binary: PathBuf,
            worker_entry: PathBuf,
            workspace_dir: PathBuf,
            output_dir: PathBuf,
        }
        impl BrowserBootstrap for LiveBridgeBootstrap {
            fn release_profile(&self, _: &styx_core::operations::OwnerLease) {}
            fn prepare_profile(
                &self,
                _: &styx_core::operations::OwnerLease,
                scope: CdpSessionScope,
            ) -> Result<OwnedBrowserConfig, ErrorCategory> {
                let cdp_endpoint = self
                    .bridge
                    .open_cdp_session_with_scope(scope)
                    .map_err(|_| ErrorCategory::CapabilityUnsupported)?;
                let output_dir = self
                    .output_dir
                    .join(format!("s-{}", uuid::Uuid::new_v4().simple()));
                ensure_private_dir(&output_dir).map_err(|_| ErrorCategory::IntegrityFailure)?;
                let output_dir = std::fs::canonicalize(&output_dir)
                    .map_err(|_| ErrorCategory::IntegrityFailure)?;
                Ok(OwnedBrowserConfig {
                    node_binary: self.node_binary.clone(),
                    worker_entry: self.worker_entry.clone(),
                    cdp_endpoint,
                    workspace_dir: self.workspace_dir.clone(),
                    output_dir,
                    rpc_timeout: Duration::from_secs(30),
                })
            }
            fn validate_before_spawn(&self) -> Result<(), ErrorCategory> {
                Ok(())
            }
            fn validate_control(&self) -> Result<(), ErrorCategory> {
                Ok(())
            }
        }

        let host_workspace = root.path().join("host-workspace");
        let host_output = root.path().join("host-output");
        ensure_private_dir(&host_workspace).unwrap();
        ensure_private_dir(&host_output).unwrap();

        let cap_facts = |capability: CapabilityId| AdmissionFacts {
            device_id: "e2e-linux-host".try_into().unwrap(),
            grant_revision: 1,
            local_policy_allowed: true,
            descriptor: CapabilityDescriptor {
                contract_version: 1,
                capability_id: capability,
                scope: if capability == CapabilityId::Browser {
                    Scope::Browser
                } else {
                    Scope::Host
                },
                provider_id: "browser-e2e".try_into().unwrap(),
                configured: true,
                remote_grant: true,
                availability: Availability::Available,
                authorization: Authorization::Granted,
                target_session: None,
                reason: None,
                observed_at: 1,
                observation_generation: 1,
                recovery: Recovery::None,
            },
            session_state: None,
            current_observation: None,
        };

        let (host, authority) = HostCoordinator::new_without_executor(
            OperationLedger::new("ext-e2e-host".try_into().unwrap()),
            cap_facts(CapabilityId::ExecRun),
        )
        .unwrap();
        authority
            .configure_browser(cap_facts(CapabilityId::Browser))
            .unwrap();

        let bootstrap = Arc::new(LiveBridgeBootstrap {
            bridge: bridge.clone(),
            node_binary: std::fs::canonicalize(&node22_bin).unwrap(),
            worker_entry: std::fs::canonicalize(worker_stage.join("worker.mjs")).unwrap(),
            workspace_dir: std::fs::canonicalize(&host_workspace).unwrap(),
            output_dir: std::fs::canonicalize(&host_output).unwrap(),
        });
        let inputs = host.browser_sessions().inputs(bootstrap);
        let engine = Engine {
            port: BrowserPort {
                coordinator: &host,
                authority: &authority,
                inputs: &inputs,
            },
        };

        let register = |name: &str| {
            let owner = OwnerRef {
                owner_id: OwnerId::try_from(name.to_owned()).unwrap(),
                owner_epoch: format!("{name}-epoch").try_into().unwrap(),
            };
            let lease = authority
                .register_verified_owner(owner.owner_id.clone(), owner.owner_epoch.clone())
                .unwrap();
            host.remote_access().lock().unwrap().owners.insert(
                (owner.owner_id.clone(), owner.owner_epoch.clone()),
                OwnerRecord {
                    lease: Some(lease),
                    revision: host.grant_revision(),
                    cleanup: None,
                },
            );
            owner
        };
        let caller_a = register("e2e-caller-a");
        let caller_b = register("e2e-caller-b");

        let all_text = |res: &rmcp::model::CallToolResult| -> String {
            res.content
                .iter()
                .filter_map(|c| c.as_text().map(|t| t.text.as_str()))
                .collect::<Vec<_>>()
                .join("\n")
        };

        // 2a. List initially returns `existing-browser` (`extension_existing`, `saved`).
        let list_a = engine
            .handle(caller_a.clone(), BrowserSessionCommand::List)
            .await;
        assert_ne!(
            list_a.is_error,
            Some(true),
            "list failed: {}",
            all_text(&list_a)
        );
        let list_json = list_a.structured_content.as_ref().unwrap();
        assert_eq!(
            list_json["sessions"][0]["browser_session_id"],
            BROWSER_SESSION_ID
        );
        assert_eq!(list_json["sessions"][0]["mode"], "extension_existing");
        assert_eq!(list_json["sessions"][0]["attached_existing_browser"], true);
        assert_eq!(list_json["sessions"][0]["status"], "saved");

        // 2b-parallel. Two callers omitting `session_id` run concurrently in separate
        // non-focusing Chrome Tab Groups (`Styx · 1` and `Styx · 2`) without conflicts!
        let caller_a_future = async {
            let new_tab_res = engine
                .handle(
                    caller_a.clone(),
                    BrowserSessionCommand::Action {
                        session_id: None,
                        name: "browser_tabs".into(),
                        arguments: serde_json::from_value(json!({
                            "action": "new",
                            "url": format!("http://127.0.0.1:{http_port}/form"),
                        }))
                        .unwrap(),
                    },
                )
                .await;
            assert_ne!(
                new_tab_res.is_error,
                Some(true),
                "open /form tab failed: {}",
                all_text(&new_tab_res)
            );
            let bg_a = new_tab_res.structured_content.as_ref().unwrap()["browser_session_id"]
                .as_str()
                .unwrap()
                .to_owned();
            assert!(
                bg_a.starts_with("bg-"),
                "expected bg- session for caller_a, got {bg_a}"
            );

            let extract_ref = |snap: &str, needle: &str| -> String {
                let line = snap
                    .lines()
                    .find(|l| l.contains(needle) && l.contains("[ref="))
                    .unwrap_or_else(|| panic!("missing {needle} with [ref= in snapshot:\n{snap}"));
                let (_, after) = line
                    .split_once("[ref=")
                    .unwrap_or_else(|| panic!("missing [ref= on line: {line}"));
                let (id, _) = after
                    .split_once(']')
                    .unwrap_or_else(|| panic!("unterminated [ref= on line: {line}"));
                assert!(
                    id.starts_with("styx-"),
                    "expected opaque styx- ref, got {id:?}"
                );
                id.to_owned()
            };
            let snap_page = || async {
                let res = engine
                    .handle(
                        caller_a.clone(),
                        BrowserSessionCommand::Action {
                            session_id: None,
                            name: "browser_snapshot".into(),
                            arguments: Default::default(),
                        },
                    )
                    .await;
                assert_ne!(
                    res.is_error,
                    Some(true),
                    "form snapshot failed: {}",
                    all_text(&res)
                );
                all_text(&res)
            };

            let form_snap_text = snap_page().await;
            let username_ref = extract_ref(&form_snap_text, "textbox \"Username\"");
            let type_res = engine
                .handle(
                    caller_a.clone(),
                    BrowserSessionCommand::Action {
                        session_id: None,
                        name: "browser_type".into(),
                        arguments: serde_json::from_value(json!({
                            "target": username_ref,
                            "element": "Username",
                            "text": "alice-daily",
                            "submit": false,
                        }))
                        .unwrap(),
                    },
                )
                .await;
            assert_ne!(
                type_res.is_error,
                Some(true),
                "browser_type failed: {}",
                all_text(&type_res)
            );

            let snap_after_type = snap_page().await;
            let note_ref = extract_ref(&snap_after_type, "textbox \"Note\"");
            let agree_ref = extract_ref(&snap_after_type, "checkbox \"Agree\"");
            let role_ref = extract_ref(&snap_after_type, "combobox \"Role\"");
            let fill_res = engine
                .handle(
                    caller_a.clone(),
                    BrowserSessionCommand::Action {
                        session_id: None,
                        name: "browser_fill_form".into(),
                        arguments: serde_json::from_value(json!({
                            "fields": [
                                { "name": "Note", "type": "textbox", "target": note_ref, "value": "hello from styx" },
                                { "name": "Agree", "type": "checkbox", "target": agree_ref, "value": "true" },
                                { "name": "Role", "type": "combobox", "target": role_ref, "value": "Editor" },
                            ],
                        }))
                        .unwrap(),
                    },
                )
                .await;
            assert_ne!(
                fill_res.is_error,
                Some(true),
                "browser_fill_form failed: {}",
                all_text(&fill_res)
            );

            let snap_after_fill = snap_page().await;
            let role_ref_2 = extract_ref(&snap_after_fill, "combobox \"Role\"");
            let select_res = engine
                .handle(
                    caller_a.clone(),
                    BrowserSessionCommand::Action {
                        session_id: None,
                        name: "browser_select_option".into(),
                        arguments: serde_json::from_value(json!({
                            "target": role_ref_2,
                            "element": "Role",
                            "values": ["admin"],
                        }))
                        .unwrap(),
                    },
                )
                .await;
            assert_ne!(
                select_res.is_error,
                Some(true),
                "browser_select_option failed: {}",
                all_text(&select_res)
            );

            let key_res = engine
                .handle(
                    caller_a.clone(),
                    BrowserSessionCommand::Action {
                        session_id: None,
                        name: "browser_press_key".into(),
                        arguments: serde_json::from_value(json!({ "key": "F8" })).unwrap(),
                    },
                )
                .await;
            assert_ne!(
                key_res.is_error,
                Some(true),
                "browser_press_key failed: {}",
                all_text(&key_res)
            );

            let snap_before_submit = snap_page().await;
            let submit_ref = extract_ref(&snap_before_submit, "button \"Submit Form\"");
            let click_submit = engine
                .handle(
                    caller_a.clone(),
                    BrowserSessionCommand::Action {
                        session_id: None,
                        name: "browser_click".into(),
                        arguments: serde_json::from_value(json!({
                            "target": submit_ref,
                            "element": "Submit Form",
                        }))
                        .unwrap(),
                    },
                )
                .await;
            assert_ne!(
                click_submit.is_error,
                Some(true),
                "click submit failed: {}",
                all_text(&click_submit)
            );

            let wait_submit = engine
                .handle(
                    caller_a.clone(),
                    BrowserSessionCommand::Action {
                        session_id: None,
                        name: "browser_wait_for".into(),
                        arguments: serde_json::from_value(json!({
                            "text": "Submitted OK: alice-daily|hello from styx|true|admin",
                        }))
                        .unwrap(),
                    },
                )
                .await;
            assert_ne!(
                wait_submit.is_error,
                Some(true),
                "wait submit failed: {}",
                all_text(&wait_submit)
            );
            let posted = submitted_payload
                .lock()
                .unwrap()
                .clone()
                .expect("POST /submit payload captured");
            let posted_json: Value = serde_json::from_str(&posted).unwrap();
            assert_eq!(posted_json["username"], "alice-daily");
            assert_eq!(posted_json["note"], "hello from styx");
            assert_eq!(posted_json["agree"], true);
            assert_eq!(posted_json["role"], "admin");

            let snap_before_async = snap_page().await;
            let async_ref = extract_ref(&snap_before_async, "button \"Start Async\"");
            let click_async = engine
                .handle(
                    caller_a.clone(),
                    BrowserSessionCommand::Action {
                        session_id: None,
                        name: "browser_click".into(),
                        arguments: serde_json::from_value(json!({
                            "target": async_ref,
                            "element": "Start Async",
                        }))
                        .unwrap(),
                    },
                )
                .await;
            assert_ne!(
                click_async.is_error,
                Some(true),
                "click async failed: {}",
                all_text(&click_async)
            );

            let wait_async = engine
                .handle(
                    caller_a.clone(),
                    BrowserSessionCommand::Action {
                        session_id: None,
                        name: "browser_wait_for".into(),
                        arguments: serde_json::from_value(json!({ "text": "Async Ready" }))
                            .unwrap(),
                    },
                )
                .await;
            assert_ne!(
                wait_async.is_error,
                Some(true),
                "wait async failed: {}",
                all_text(&wait_async)
            );

            let eval_res = engine
                .handle(
                    caller_a.clone(),
                    BrowserSessionCommand::Action {
                        session_id: None,
                        name: "browser_evaluate".into(),
                        arguments: serde_json::from_value(json!({
                            "function": "() => ({ title: document.title, result: document.getElementById('result').textContent, key: document.getElementById('key-out').textContent, asyncOut: document.getElementById('async-out').textContent })",
                        }))
                        .unwrap(),
                    },
                )
                .await;
            assert_ne!(
                eval_res.is_error,
                Some(true),
                "browser_evaluate failed: {}",
                all_text(&eval_res)
            );
            let eval_text = all_text(&eval_res);
            assert!(
                eval_text.contains("Submitted OK: alice-daily|hello from styx|true|admin"),
                "{eval_text}"
            );
            assert!(eval_text.contains("Key F8 Observed"), "{eval_text}");
            assert!(eval_text.contains("Async Ready"), "{eval_text}");

            let shot_res = engine
                .handle(
                    caller_a.clone(),
                    BrowserSessionCommand::Action {
                        session_id: None,
                        name: "browser_take_screenshot".into(),
                        arguments: serde_json::from_value(json!({ "scale": "css" })).unwrap(),
                    },
                )
                .await;
            assert_ne!(
                shot_res.is_error,
                Some(true),
                "browser_take_screenshot failed: {}",
                all_text(&shot_res)
            );
            assert!(
                !shot_res.content.is_empty(),
                "screenshot returned no content blocks"
            );

            let nav_initial = engine
                .handle(
                    caller_a.clone(),
                    BrowserSessionCommand::Action {
                        session_id: None,
                        name: "browser_navigate".into(),
                        arguments: serde_json::from_value(json!({
                            "url": format!("http://127.0.0.1:{http_port}/initial"),
                        }))
                        .unwrap(),
                    },
                )
                .await;
            assert_ne!(
                nav_initial.is_error,
                Some(true),
                "navigate /initial failed: {}",
                all_text(&nav_initial)
            );

            let back_res = engine
                .handle(
                    caller_a.clone(),
                    BrowserSessionCommand::Action {
                        session_id: None,
                        name: "browser_navigate_back".into(),
                        arguments: Default::default(),
                    },
                )
                .await;
            assert_ne!(
                back_res.is_error,
                Some(true),
                "browser_navigate_back failed: {}",
                all_text(&back_res)
            );
            let back_snap = snap_page().await;
            assert!(
                back_snap.contains("Submit Form"),
                "expected /form after back: {back_snap}"
            );

            eprintln!(
                "E2E: Phase 2a parallel write/interactive operations verified (POST payload={posted})"
            );
            bg_a
        };

        let caller_b_future = async {
            let nav_large = engine
                .handle(
                    caller_b.clone(),
                    BrowserSessionCommand::Action {
                        session_id: None,
                        name: "browser_navigate".into(),
                        arguments: serde_json::from_value(
                            json!({ "url": format!("http://127.0.0.1:{http_port}/large") }),
                        )
                        .unwrap(),
                    },
                )
                .await;
            assert_ne!(
                nav_large.is_error,
                Some(true),
                "navigate /large failed: {}",
                all_text(&nav_large)
            );
            let bg_b = nav_large.structured_content.as_ref().unwrap()["browser_session_id"]
                .as_str()
                .unwrap()
                .to_owned();
            assert!(
                bg_b.starts_with("bg-"),
                "expected bg- session for caller_b, got {bg_b}"
            );

            let large_res = engine
                .handle(
                    caller_b.clone(),
                    BrowserSessionCommand::Action {
                        session_id: None,
                        name: "browser_snapshot".into(),
                        arguments: Default::default(),
                    },
                )
                .await;
            assert_ne!(
                large_res.is_error,
                Some(true),
                "large snap failed: {}",
                all_text(&large_res)
            );
            let large_text = all_text(&large_res);
            assert!(
                large_text.len() > 200 * 1024,
                "expected >200KB snap, got {}",
                large_text.len()
            );
            assert!(large_text.contains("Large End Verified"));

            let bad_tab = engine
                .handle(
                    caller_b.clone(),
                    BrowserSessionCommand::Action {
                        session_id: None,
                        name: "browser_tabs".into(),
                        arguments: serde_json::from_value(
                            json!({ "action": "select", "index": 99 }),
                        )
                        .unwrap(),
                    },
                )
                .await;
            assert_eq!(bad_tab.is_error, Some(true));
            assert!(
                !all_text(&bad_tab).contains("outcome_unknown"),
                "tool error poisoned session: {}",
                all_text(&bad_tab)
            );

            let recovered_snap = engine
                .handle(
                    caller_b.clone(),
                    BrowserSessionCommand::Action {
                        session_id: None,
                        name: "browser_snapshot".into(),
                        arguments: Default::default(),
                    },
                )
                .await;
            assert_ne!(
                recovered_snap.is_error,
                Some(true),
                "post-error snap failed: {}",
                all_text(&recovered_snap)
            );
            assert!(all_text(&recovered_snap).contains("Large End Verified"));

            eprintln!("E2E: Phase 2b parallel >200KB snapshot + error recovery verified");
            bg_b
        };

        let (bg_a, bg_b) = tokio::join!(caller_a_future, caller_b_future);
        assert_ne!(bg_a, bg_b);

        // Verify both parallel Tab Group sessions appear cleanly in list_browser_sessions.
        let list_parallel = engine
            .handle(caller_a.clone(), BrowserSessionCommand::List)
            .await;
        let parallel_arr = list_parallel.structured_content.as_ref().unwrap()["sessions"]
            .as_array()
            .unwrap();
        assert!(
            parallel_arr
                .iter()
                .any(|s| s["browser_session_id"] == bg_a && s["mode"] == "extension_tab_group")
        );
        assert!(
            parallel_arr
                .iter()
                .any(|s| s["browser_session_id"] == bg_b && s["mode"] == "extension_tab_group")
        );

        // Close caller_a's Tab Group session independently and prove caller_b still works.
        let close_bg_a = engine
            .handle(
                caller_a.clone(),
                BrowserSessionCommand::Action {
                    session_id: Some(bg_a.clone()),
                    name: "browser_close".into(),
                    arguments: Default::default(),
                },
            )
            .await;
        assert_ne!(
            close_bg_a.is_error,
            Some(true),
            "close bg_a failed: {}",
            all_text(&close_bg_a)
        );

        let snap_b_after_a_close = engine
            .handle(
                caller_b.clone(),
                BrowserSessionCommand::Action {
                    session_id: Some(bg_b.clone()),
                    name: "browser_snapshot".into(),
                    arguments: Default::default(),
                },
            )
            .await;
        assert_ne!(
            snap_b_after_a_close.is_error,
            Some(true),
            "caller_b failed after bg_a close: {}",
            all_text(&snap_b_after_a_close)
        );
        assert!(all_text(&snap_b_after_a_close).contains("Large End Verified"));

        // Close caller_b's Tab Group session too.
        let close_bg_b = engine
            .handle(
                caller_b.clone(),
                BrowserSessionCommand::Action {
                    session_id: Some(bg_b.clone()),
                    name: "browser_close".into(),
                    arguments: Default::default(),
                },
            )
            .await;
        assert_ne!(
            close_bg_b.is_error,
            Some(true),
            "close bg_b failed: {}",
            all_text(&close_bg_b)
        );

        // 2c. Unknown explicit ID is rejected cleanly.
        let unknown_id = engine
            .handle(
                caller_a.clone(),
                BrowserSessionCommand::Action {
                    session_id: Some("missing-session".into()),
                    name: "browser_tabs".into(),
                    arguments: serde_json::from_value(json!({ "action": "list" })).unwrap(),
                },
            )
            .await;
        assert_eq!(unknown_id.is_error, Some(true));
        assert!(all_text(&unknown_id).contains("browser_session_not_found"));

        // 2d. Explicit `existing-browser` sees the user's open tabs (not isolated Tab Group tabs)
        // and proves zero focus stealing kept an original user tab active!
        let existing_tabs = engine
            .handle(
                caller_a.clone(),
                BrowserSessionCommand::Action {
                    session_id: Some(BROWSER_SESSION_ID.into()),
                    name: "browser_tabs".into(),
                    arguments: serde_json::from_value(json!({ "action": "list" })).unwrap(),
                },
            )
            .await;
        assert_ne!(
            existing_tabs.is_error,
            Some(true),
            "existing-browser tabs failed: {}",
            all_text(&existing_tabs)
        );
        let existing_tabs_text = all_text(&existing_tabs);
        assert!(
            existing_tabs_text.contains(&format!("Ext Initial {nonce}")),
            "missing initial tab: {existing_tabs_text}"
        );
        assert!(
            !existing_tabs_text.contains("Ext Daily Form"),
            "existing-browser leaked isolated /form tab: {existing_tabs_text}"
        );
        assert!(
            !existing_tabs_text.contains("Ext Large"),
            "existing-browser leaked isolated /large tab: {existing_tabs_text}"
        );

        // Second conversation hits transfer fence on `existing-browser` until explicit takeover.
        let conflict = engine
            .handle(
                caller_b.clone(),
                BrowserSessionCommand::Action {
                    session_id: Some(BROWSER_SESSION_ID.into()),
                    name: "browser_tabs".into(),
                    arguments: serde_json::from_value(json!({ "action": "list" })).unwrap(),
                },
            )
            .await;
        assert_eq!(conflict.is_error, Some(true));
        assert!(all_text(&conflict).contains("browser_session_transferred"));

        let takeover = engine
            .handle(
                caller_b.clone(),
                BrowserSessionCommand::TakeOver {
                    session_id: BROWSER_SESSION_ID.into(),
                },
            )
            .await;
        assert_ne!(
            takeover.is_error,
            Some(true),
            "takeover failed: {}",
            all_text(&takeover)
        );
        assert_eq!(
            takeover.structured_content.as_ref().unwrap()["current_operator"],
            true
        );
        assert_eq!(
            takeover.structured_content.as_ref().unwrap()["refresh_snapshot"],
            true
        );

        let snap_b = engine
            .handle(
                caller_b.clone(),
                BrowserSessionCommand::Action {
                    session_id: Some(BROWSER_SESSION_ID.into()),
                    name: "browser_tabs".into(),
                    arguments: serde_json::from_value(json!({ "action": "list" })).unwrap(),
                },
            )
            .await;
        assert_ne!(
            snap_b.is_error,
            Some(true),
            "caller_b existing tabs failed: {}",
            all_text(&snap_b)
        );
        assert!(all_text(&snap_b).contains(&format!("Ext Initial {nonce}")));

        // `browser_close` detaches cleanly and leaves Chrome open and `existing-browser` reusable (`saved`).
        let close_b = engine
            .handle(
                caller_b.clone(),
                BrowserSessionCommand::Action {
                    session_id: Some(BROWSER_SESSION_ID.into()),
                    name: "browser_close".into(),
                    arguments: Default::default(),
                },
            )
            .await;
        assert_ne!(
            close_b.is_error,
            Some(true),
            "close failed: {}",
            all_text(&close_b)
        );
        let close_json = close_b.structured_content.as_ref().unwrap();
        assert_eq!(close_json["closed"], true);
        assert_eq!(close_json["detached"], true);
        assert!(
            chrome_guard
                .0
                .as_mut()
                .unwrap()
                .try_wait()
                .unwrap()
                .is_none(),
            "Chromium exited during Host browser_close instead of staying open"
        );

        let list_after = engine.handle(caller_b, BrowserSessionCommand::List).await;
        let after_sessions = list_after.structured_content.as_ref().unwrap()["sessions"]
            .as_array()
            .unwrap();
        assert_eq!(after_sessions.len(), 1);
        assert_eq!(after_sessions[0]["browser_session_id"], BROWSER_SESSION_ID);
        assert_eq!(after_sessions[0]["status"], "saved");

        eprintln!(
            "E2E: Phase 2 full parallel Tab Group + existing-browser stack verified against real Chrome"
        );
    }

    drop(chrome_guard);
    http_stop.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), http_task).await;
    bridge.shutdown().await;
}

#[test]
fn strip_windows_verbatim_prefix_handles_drive_unc_and_plain_paths() {
    assert_eq!(
        strip_windows_verbatim_prefix(r"\\?\C:\Users\Sid\AppData\Local\Styx\styx.exe"),
        r"C:\Users\Sid\AppData\Local\Styx\styx.exe"
    );
    assert_eq!(
        strip_windows_verbatim_prefix(r"\\?\UNC\server\share\Styx\styx.exe"),
        r"\\server\share\Styx\styx.exe"
    );
    assert_eq!(
        strip_windows_verbatim_prefix(r"C:\Users\Sid\Styx"),
        r"C:\Users\Sid\Styx"
    );
    assert_eq!(
        strip_windows_verbatim_prefix("/home/sid/styx"),
        "/home/sid/styx"
    );
}

#[test]
fn validate_loopback_ws_endpoint_accepts_canonical_ws_and_rejects_http_or_remote() {
    assert_eq!(
        validate_loopback_ws_endpoint("  ws://LOCALHOST:9222/devtools/browser/abc-123_4.5 ")
            .unwrap(),
        "ws://localhost:9222/devtools/browser/abc-123_4.5"
    );
    assert_eq!(
        validate_loopback_ws_endpoint("ws://[::1]:9333/devtools/browser").unwrap(),
        "ws://[::1]:9333/devtools/browser"
    );
    assert_eq!(
        validate_loopback_ws_endpoint("ws://127.0.0.1:9222/devtools/browser/uuid-1").unwrap(),
        "ws://127.0.0.1:9222/devtools/browser/uuid-1"
    );

    for invalid in [
        "",
        "   ",
        "http://127.0.0.1:9222",
        "wss://127.0.0.1:9222/devtools/browser",
        "ws://192.168.1.10:9222/devtools/browser",
        "ws://0.0.0.0:9222/devtools/browser",
        "ws://example.com:9222/devtools/browser",
        "ws://127.0.0.1/devtools/browser",
        "ws://user@127.0.0.1:9222/devtools/browser",
        "ws://127.0.0.1:9222/devtools/browser?token=1",
        "ws://127.0.0.1:9222/devtools/browser#frag",
        "ws://127.0.0.1:9222/other",
        "ws://127.0.0.1:9222/devtools/browser/.",
        "ws://127.0.0.1:9222/devtools/browser/..",
        "ws://127.0.0.1:9222/devtools/browser/../secret",
        "ws://127.0.0.1:9222/devtools/browser\n",
    ] {
        assert_eq!(
            validate_loopback_ws_endpoint(invalid),
            Err(ErrorCategory::InvalidRequest),
            "expected invalid endpoint refusal for {invalid:?}"
        );
    }
}
