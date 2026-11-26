use super::*;
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::{
    collections::HashSet,
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
    let detach_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

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
                    match cdp_method {
                        "Target.getTargetInfo" => {
                            let tab_id = params["tabId"].as_i64().unwrap();
                            json!({ "id": id, "result": { "targetInfo": {
                                "targetId": format!("target-{tab_id}"),
                                "type": "page",
                                "url": "https://dash.cloudflare.com/"
                            }}})
                        }
                        "Page.addScriptToEvaluateOnNewDocument" => {
                            json!({ "id": id, "result": { "identifier": "favicon-script-1" } })
                        }
                        "Page.getFrameTree" => {
                            let tab_id = params["tabId"].as_i64().unwrap();
                            json!({ "id": id, "result": { "frameTree": { "frame": { "id": format!("target-{tab_id}") } } } })
                        }
                        "Page.createIsolatedWorld" => {
                            json!({ "id": id, "result": { "executionContextId": 42 } })
                        }
                        _ => {
                            json!({ "id": id, "result": { "frameId": "f1", "cdpMethod": cdp_method } })
                        }
                    }
                }
                "debugger.detach" => {
                    if detach_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1 >= 2 {
                        detach_notify.notify_one();
                    }
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

    // 6. Closing WS detaches only this relay's tabs and restores favicon indicator cleanly.
    ws.close(None).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), detach_seen.notified())
        .await
        .unwrap();
    {
        let calls = recorded_calls.lock().unwrap();
        assert!(calls.iter().any(|(m, _)| m == "debugger.detach"));
        assert!(calls.iter().any(|(m, p)| {
            m == "debugger.sendCommand"
                && p["method"] == "Page.addScriptToEvaluateOnNewDocument"
                && p["params"]["worldName"] == "styx_favicon_indicator"
        }));
        assert!(calls.iter().any(|(m, p)| {
            m == "debugger.sendCommand"
                && p["method"] == "Page.removeScriptToEvaluateOnNewDocument"
                && p["params"]["identifier"] == "favicon-script-1"
        }));
        assert!(calls.iter().any(|(m, p)| {
            m == "debugger.sendCommand"
                && p["method"] == "Runtime.evaluate"
                && p["params"]["contextId"] == 42
                && p["params"]["expression"]
                    .as_str()
                    .is_some_and(|s| s.contains("__styxFaviconCleanup"))
        }));
    }

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
            session_key: None,
        })
        .unwrap();
    let ws2_url = bridge
        .open_cdp_session_with_scope(CdpSessionScope::TabGroup {
            title: "Styx · 2".into(),
            color: "cyan".into(),
            session_key: None,
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
                                "<!doctype html><html><head><title>Ext Daily Form</title>\
                                <link id=\"site-icon\" rel=\"icon\" href=\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'%3E%3Crect width='16' height='16' fill='%23222'/%3E%3C/svg%3E\" />\
                                </head><body>\
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
                        } else if path == "/frame-inner" {
                            (
                                "200 OK",
                                "Content-Type: text/html\r\nCache-Control: no-store".to_owned(),
                                "<!doctype html><html><head><title>Ext Inner Frame</title></head><body><p>Inner Frame Body</p></body></html>".to_owned(),
                            )
                        } else if path == "/multi-frame" {
                            (
                                "200 OK",
                                "Content-Type: text/html\r\nCache-Control: no-store".to_owned(),
                                format!(
                                    "<!doctype html><html><head><title>Ext MultiFrame {expected}</title></head><body><h1>MultiFrame Host</h1><iframe src=\"/frame-inner\"></iframe></body></html>"
                                ),
                            )
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
    let multi_frame_url = format!("http://127.0.0.1:{http_port}/multi-frame");
    let inner_frame_url = format!("http://127.0.0.1:{http_port}/frame-inner");
    let mut chrome_cmd = std::process::Command::new(&chrome_bin);
    chrome_cmd
        .env("XDG_CONFIG_HOME", &xdg_dir)
        .arg(format!("--user-data-dir={}", user_data_dir.display()))
        .arg(format!("--load-extension={ext_dir_str}"))
        .arg(format!("--disable-extensions-except={ext_dir_str}"))
        .arg("--no-first-run")
        .arg("--no-default-browser-check")
        .arg(&initial_url)
        .arg(&multi_frame_url)
        .arg(&inner_frame_url)
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
                            "function": "() => ({ title: document.title, result: document.getElementById('result').textContent, key: document.getElementById('key-out').textContent, asyncOut: document.getElementById('async-out').textContent, styxFaviconHref: document.querySelector('link[data-styx-favicon=\"1\"]')?.getAttribute('href') || null, origIconRel: document.getElementById('site-icon')?.getAttribute('rel') ?? null, origIconSaved: document.getElementById('site-icon')?.getAttribute('data-styx-orig-rel') ?? null, mainWorldClean: typeof window.__styxFaviconCleanup === 'undefined' })",
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
            assert!(
                eval_text.contains("\"styxFaviconHref\": \"data:image/"),
                "missing tab favicon indicator: {eval_text}"
            );
            assert!(
                eval_text.contains("\"origIconRel\": null")
                    && eval_text.contains("\"origIconSaved\": \"icon\""),
                "original icon link should be preserved for restore: {eval_text}"
            );
            assert!(
                eval_text.contains("\"mainWorldClean\": true"),
                "favicon helper leaked into page main world: {eval_text}"
            );

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
            existing_tabs_text.contains(&format!("Ext MultiFrame {nonce}")),
            "missing multi-frame tab: {existing_tabs_text}"
        );
        assert!(
            existing_tabs_text.contains("Ext Inner Frame"),
            "missing inner-frame tab: {existing_tabs_text}"
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

        let existing_favicon = engine
            .handle(
                caller_b.clone(),
                BrowserSessionCommand::Action {
                    session_id: Some(BROWSER_SESSION_ID.into()),
                    name: "browser_evaluate".into(),
                    arguments: serde_json::from_value(json!({
                        "function": "() => ({ href: document.querySelector('link[data-styx-favicon=\"1\"]')?.getAttribute('href') || null, hasCursor: Boolean(document.querySelector('[data-styx-cursor=\"1\"]')) })",
                    }))
                    .unwrap(),
                },
            )
            .await;
        assert_ne!(
            existing_favicon.is_error,
            Some(true),
            "existing-browser favicon eval failed: {}",
            all_text(&existing_favicon)
        );
        assert!(
            all_text(&existing_favicon).contains("\"href\": \"data:image/svg+xml"),
            "existing-browser missing Codex SVG tab favicon indicator: {}",
            all_text(&existing_favicon)
        );
        assert!(
            all_text(&existing_favicon).contains("\"hasCursor\": true"),
            "existing-browser missing virtual cursor host: {}",
            all_text(&existing_favicon)
        );

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

#[ignore = "requires local Chromium, compiled styx binary, Node 22 + MCP SDK, and chrome-devtools-mcp"]
#[tokio::test]
async fn real_chromium_extension_bridge_e2e_with_chrome_devtools_mcp() {
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
    let driver_stage = root.path().join("driver-stage");
    for d in [&state_dir, &xdg_dir, &user_data_dir, &driver_stage] {
        ensure_private_dir(d).unwrap();
    }

    let nm_dirs = vec![
        (user_data_dir.join("NativeMessagingHosts"), true),
        (xdg_dir.join("chromium/NativeMessagingHosts"), true),
        (xdg_dir.join("google-chrome/NativeMessagingHosts"), true),
    ];
    install_with_manifest_dirs(&state_dir, &styx_bin, &nm_dirs).unwrap();

    let http_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_port = http_listener.local_addr().unwrap().port();
    let http_stop = CancellationToken::new();
    let http_cancel = http_stop.clone();
    let http_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                () = http_cancel.cancelled() => break,
                accepted = http_listener.accept() => {
                    let Ok((mut sock, _)) = accepted else { break };
                    tokio::spawn(async move {
                        let mut buf = [0_u8; 4096];
                        let n = sock.read(&mut buf).await.unwrap_or(0);
                        let req_text = String::from_utf8_lossy(&buf[..n]);
                        let path = req_text
                            .lines()
                            .next()
                            .and_then(|l| l.split_whitespace().nth(1))
                            .unwrap_or("/");
                        let body = if path == "/target" {
                            "<!doctype html><html><head><title>DevTools MCP Target</title></head><body><h1>Antigravity DevTools MCP Test</h1><button id=\"btn\" onclick=\"document.getElementById('status').textContent='Clicked OK'\">Click Me</button><p id=\"status\">Pending</p></body></html>"
                        } else {
                            "<!doctype html><html><head><title>Initial User Tab</title></head><body><h1>User Open Tab</h1></body></html>"
                        };
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = sock.write_all(resp.as_bytes()).await;
                    });
                }
            }
        }
    });

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
    let mut chrome_cmd = std::process::Command::new(&chrome_bin);
    chrome_cmd
        .env("XDG_CONFIG_HOME", &xdg_dir)
        .arg(format!("--user-data-dir={}", user_data_dir.display()))
        .arg(format!("--load-extension={ext_dir_str}"))
        .arg(format!("--disable-extensions-except={ext_dir_str}"))
        .arg("--no-first-run")
        .arg("--no-default-browser-check")
        .arg(format!("http://127.0.0.1:{http_port}/"))
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
            "Chromium exited prematurely"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(bridge.is_connected(), "extension did not connect");

    // Verify `styx host browser-extension cdp-url` CLI still mints single-use local wsEndpoint.
    let cdp_out = tokio::process::Command::new(&styx_bin)
        .args([
            "host",
            "browser-extension",
            "cdp-url",
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--group-title",
            "Antigravity",
            "--group-color",
            "cyan",
        ])
        .output()
        .await
        .expect("run styx cdp-url");
    assert!(
        cdp_out.status.success(),
        "styx cdp-url failed: stderr={}",
        String::from_utf8_lossy(&cdp_out.stderr)
    );
    let ws_url = String::from_utf8(cdp_out.stdout).unwrap().trim().to_owned();
    assert!(
        ws_url.starts_with("ws://127.0.0.1:"),
        "unexpected cdp-url output: {ws_url:?}"
    );
    eprintln!("E2E: Minted Antigravity CLI cdp-url={ws_url}");

    #[cfg(unix)]
    std::os::unix::fs::symlink(&node_modules, driver_stage.join("node_modules")).unwrap();
    let driver_script = driver_stage.join("devtools-mcp-driver.mjs");
    let phase1_done = driver_stage.join("phase1.done");
    let phase2_ready = driver_stage.join("phase2.ready");
    std::fs::write(
        &driver_script,
        r#"
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const styxBin = process.env.STYX_TEST_BIN;
const stateDir = process.env.STYX_STATE_DIR;
const stageDir = process.env.STYX_STAGE_DIR;
const baseUrl = process.env.STYX_E2E_BASE_URL;

const transport = new StdioClientTransport({
  command: styxBin,
  args: [
    'host', 'browser-extension', 'cdp-proxy',
    '--state-dir', stateDir,
    '--group-title', 'Antigravity',
    '--group-color', 'cyan',
    '--',
    'npx', '-y', 'chrome-devtools-mcp@latest',
  ],
  stderr: 'pipe',
});
let stderrLog = '';
transport.stderr.on('data', chunk => { stderrLog += chunk.toString(); });

const client = new Client({ name: 'styx-devtools-e2e', version: '1.0.0' });
await client.connect(transport);

const textOf = res => (res.content || []).filter(c => c.type === 'text').map(c => c.text).join('\n');
const toolsRes = await client.listTools();
const toolSchemas = new Map(toolsRes.tools.map(t => [t.name, t.inputSchema?.properties || {}]));

async function call(name, args = {}) {
  const res = await client.callTool({ name, arguments: args }, undefined, { timeout: 30000 });
  assert.notEqual(res.isError, true, `${name} failed: ${textOf(res)}\nstderr=${stderrLog}`);
  return res;
}

const listed = textOf(await call('list_pages', {}));
assert.ok(listed.length > 0, `list_pages returned empty: ${listed}`);
const pageIdMatch = listed.match(/(?:^|\n)\s*(\d+)\s*:/);
const pageId = pageIdMatch ? Number(pageIdMatch[1]) : 1;
const withPageId = (name, args) =>
  toolSchemas.get(name)?.pageId ? { pageId, ...args } : args;

await call('navigate_page', withPageId('navigate_page', { type: 'url', url: `${baseUrl}/target` }));
const snap1 = textOf(await call('take_snapshot', withPageId('take_snapshot', {})));
assert.match(snap1, /Click Me/, `missing Click Me in snapshot:\n${snap1}`);

const uidMatch = snap1.match(/uid=([^\s]+)[^\n]*button[^\n]*Click Me/i)
  || snap1.match(/uid="([^"]+)"[^\n]*Click Me/i);
assert.ok(uidMatch, `could not extract uid from chrome-devtools-mcp snapshot:\n${snap1}`);

await call('click', withPageId('click', { uid: uidMatch[1] }));
const snap2 = textOf(await call('take_snapshot', withPageId('take_snapshot', {})));
assert.match(snap2, /Clicked OK/, `click did not update DOM in snapshot:\n${snap2}`);

if (toolSchemas.has('evaluate_script')) {
  const evalOut = textOf(await call('evaluate_script', withPageId('evaluate_script', {
    function: '() => ({ favicon: document.querySelector("link[data-styx-favicon]")?.getAttribute("href") || null, hasCursor: Boolean(document.querySelector("[data-styx-cursor]")) })',
  })));
  assert.match(evalOut, /data:image\/svg\+xml/, `missing Codex SVG favicon: ${evalOut}`);
  assert.match(evalOut, /"hasCursor":\s*true/, `missing virtual cursor host: ${evalOut}`);
}

const shot = await call('take_screenshot', withPageId('take_screenshot', {}));
assert.ok((shot.content || []).some(c => c.type === 'image'), `screenshot missing image: ${JSON.stringify(shot)}`);

// Phase 2: Wait for Host bridge restart on a new port and keep reusing the same MCP server.
fs.writeFileSync(path.join(stageDir, 'phase1.done'), 'ok');
const readyPath = path.join(stageDir, 'phase2.ready');
for (let i = 0; i < 300; i++) {
  if (fs.existsSync(readyPath)) break;
  await delay(100);
}
assert.ok(fs.existsSync(readyPath), 'timed out waiting for Host bridge restart signal');
await delay(150);

const listedAfter = textOf(await call('list_pages', {}));
assert.ok(listedAfter.length > 0, `list_pages after bridge restart returned empty: ${listedAfter}`);
const pageIdAfterMatch = listedAfter.match(/(?:^|\n)\s*(\d+)\s*:/);
const pageIdAfter = pageIdAfterMatch ? Number(pageIdAfterMatch[1]) : 1;
const withPageIdAfter = (name, args) =>
  toolSchemas.get(name)?.pageId ? { pageId: pageIdAfter, ...args } : args;

await call('navigate_page', withPageIdAfter('navigate_page', { type: 'url', url: `${baseUrl}/target` }));
const snap3 = textOf(await call('take_snapshot', withPageIdAfter('take_snapshot', {})));
assert.match(snap3, /Click Me/, `missing Click Me after bridge restart:\n${snap3}`);
const uidAfterMatch = snap3.match(/uid=([^\s]+)[^\n]*button[^\n]*Click Me/i)
  || snap3.match(/uid="([^"]+)"[^\n]*Click Me/i);
assert.ok(uidAfterMatch, `could not extract uid after bridge restart:\n${snap3}`);
await call('click', withPageIdAfter('click', { uid: uidAfterMatch[1] }));
const snap4 = textOf(await call('take_snapshot', withPageIdAfter('take_snapshot', {})));
assert.match(snap4, /Clicked OK/, `click after bridge restart did not update DOM:\n${snap4}`);

await transport.close();
console.log('DEVTOOLS_MCP_E2E_SUCCESS');
"#,
    )
    .unwrap();

    let mut driver = tokio::process::Command::new(&node22_bin);
    driver
        .arg(&driver_script)
        .env("STYX_TEST_BIN", &styx_bin)
        .env("STYX_STATE_DIR", &state_dir)
        .env("STYX_STAGE_DIR", &driver_stage)
        .env("STYX_E2E_BASE_URL", format!("http://127.0.0.1:{http_port}"))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = driver.spawn().expect("spawn devtools-mcp driver");

    for _ in 0..450 {
        if phase1_done.exists() {
            break;
        }
        if let Some(status) = child.try_wait().unwrap() {
            let out = child.wait_with_output().await.unwrap();
            panic!(
                "devtools-mcp driver exited before phase1.done (status={status}):\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        phase1_done.exists(),
        "devtools-mcp phase1 did not finish in time"
    );

    // Simulate Host restart: tear down bridge #1 and start bridge #2 on new ephemeral ports.
    let old_ws_port = bridge.ws_port();
    bridge.shutdown().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let bridge2 = BrowserExtensionBridge::start(&state_dir)
        .await
        .expect("start second extension bridge");
    assert_ne!(bridge2.ws_port(), old_ws_port);
    for _ in 0..200 {
        if bridge2.is_connected() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        bridge2.is_connected(),
        "real Chrome extension did not auto-reconnect to bridge2"
    );
    eprintln!(
        "E2E: Restarted Host bridge ws_port {} -> {}, extension reconnected",
        old_ws_port,
        bridge2.ws_port()
    );
    std::fs::write(&phase2_ready, b"ok").unwrap();

    let output = tokio::time::timeout(Duration::from_secs(60), child.wait_with_output())
        .await
        .expect("devtools-mcp driver phase2 timed out")
        .expect("wait devtools-mcp driver");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() && stdout.contains("DEVTOOLS_MCP_E2E_SUCCESS"),
        "chrome-devtools-mcp E2E failed (status={:?}):\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status
    );

    drop(chrome_guard);
    http_stop.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), http_task).await;
    bridge2.shutdown().await;
}

#[test]
fn favicon_indicator_colors_and_script_generation() {
    use cdp_relay::{CdpSessionScope, favicon_accent_hex, favicon_install_script};

    assert_eq!(
        favicon_accent_hex(&CdpSessionScope::SharedExisting),
        "#1A73E8"
    );
    assert_eq!(
        favicon_accent_hex(&CdpSessionScope::TabGroup {
            title: "Styx · 1".into(),
            color: "blue".into(),
            session_key: None,
        }),
        "#1A73E8"
    );
    assert_eq!(
        favicon_accent_hex(&CdpSessionScope::TabGroup {
            title: "Styx · 2".into(),
            color: "cyan".into(),
            session_key: None,
        }),
        "#0097A7"
    );
    assert_eq!(
        favicon_accent_hex(&CdpSessionScope::TabGroup {
            title: "Styx · 3".into(),
            color: "purple".into(),
            session_key: None,
        }),
        "#9334E6"
    );
    assert_eq!(
        favicon_accent_hex(&CdpSessionScope::TabGroup {
            title: "Styx · 4".into(),
            color: "green".into(),
            session_key: None,
        }),
        "#188038"
    );
    assert_eq!(
        favicon_accent_hex(&CdpSessionScope::TabGroup {
            title: "Styx · 5".into(),
            color: "orange".into(),
            session_key: None,
        }),
        "#E37400"
    );
    assert_eq!(
        favicon_accent_hex(&CdpSessionScope::TabGroup {
            title: "Styx · 6".into(),
            color: "pink".into(),
            session_key: None,
        }),
        "#D01884"
    );

    let js = favicon_install_script("#9334E6");
    assert!(js.contains("\"#9334E6\""));
    assert!(js.contains("M12 8 L54 25 L35 34 L25 54 Z"));
    assert!(js.contains("#0B0F19"));
    assert!(js.contains("#FFFFFF"));
    assert!(js.contains("radialGradient"));
    assert!(js.contains("data-styx-favicon"));
    assert!(js.contains("data-styx-orig-rel"));
    assert!(js.contains("data-styx-cursor"));
    assert!(js.contains("attachShadow"));
    assert!(js.contains("__styxIndicatorSetActive"));
    assert!(js.contains("__styxCursorMove"));
    assert!(js.contains("__styxCursorSetHidden"));
    assert!(js.contains("__styxFaviconCleanup"));
}

#[tokio::test]
async fn indicator_activates_on_control_and_releases_after_idle() {
    let state_dir = private_dir();
    let bridge = BrowserExtensionBridge::start(state_dir.path())
        .await
        .unwrap();
    bridge.set_indicator_idle_timeout_for_test(Duration::from_millis(120));
    let (port, token) = read_bridge_endpoint(state_dir.path()).unwrap();

    let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    write_half
        .write_all(format!("{}\n", json!({ "type": "auth", "token": token })).as_bytes())
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
                        "extensionId": EXTENSION_ID,
                        "browser": "Chrome/158.0.0.0",
                        "userAgent": "Mozilla/5.0 Chrome/158.0.0.0",
                        "tabs": [
                            { "id": 101, "url": "https://a.example/", "title": "A", "active": true },
                            { "id": 102, "url": "https://b.example/", "title": "B", "active": false }
                        ]
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

    // Track (tab_id, cdp_method, expression) per debugger.sendCommand.
    let cdp_events = Arc::new(StdMutex::new(Vec::<(i64, String, Option<String>)>::new()));
    let ev_ref = cdp_events.clone();
    let mock_ext = tokio::spawn(async move {
        let mut buf = String::new();
        while reader.read_line(&mut buf).await.unwrap_or(0) > 0 {
            let msg: Value = serde_json::from_str(buf.trim()).unwrap();
            buf.clear();
            let id = msg["id"].as_u64().unwrap();
            let method = msg["method"].as_str().unwrap().to_owned();
            let params = msg["params"].clone();
            let reply = match method.as_str() {
                "tabs.list" => json!({ "id": id, "result": { "tabs": [
                    { "id": 101, "url": "https://a.example/", "title": "A", "active": true },
                    { "id": 102, "url": "https://b.example/", "title": "B", "active": false }
                ]}}),
                "debugger.attach" | "debugger.detach" => {
                    json!({ "id": id, "result": { "ok": true } })
                }
                "debugger.sendCommand" => {
                    let tab_id = params["tabId"].as_i64().unwrap();
                    let cdp_method = params["method"].as_str().unwrap().to_owned();
                    let expr = params["params"]
                        .get("expression")
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                    ev_ref
                        .lock()
                        .unwrap()
                        .push((tab_id, cdp_method.clone(), expr));
                    match cdp_method.as_str() {
                        "Target.getTargetInfo" => json!({ "id": id, "result": { "targetInfo": {
                            "targetId": format!("target-{tab_id}"),
                            "type": "page",
                            "url": "https://a.example/"
                        }}}),
                        "Page.addScriptToEvaluateOnNewDocument" => {
                            json!({ "id": id, "result": { "identifier": format!("fav-{tab_id}") } })
                        }
                        "Page.getFrameTree" => {
                            json!({ "id": id, "result": { "frameTree": { "frame": { "id": format!("target-{tab_id}") } } } })
                        }
                        "Page.createIsolatedWorld" => {
                            json!({ "id": id, "result": { "executionContextId": tab_id + 1000 } })
                        }
                        _ => json!({ "id": id, "result": {} }),
                    }
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

    let ws_url = bridge.open_cdp_session().unwrap();
    let mut ws = ws_connect(&ws_url).await.unwrap();
    ws.send(Message::Text(
        json!({"id": 1, "method": "Target.setAutoAttach", "params": {"autoAttach": true, "flatten": true}})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let ev_a: Value =
        serde_json::from_str(&ws.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
    let ev_b: Value =
        serde_json::from_str(&ws.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
    let _aa: Value =
        serde_json::from_str(&ws.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
    let sid_101 = if ev_a["params"]["targetInfo"]["targetId"] == "target-101" {
        ev_a["params"]["sessionId"].as_str().unwrap().to_owned()
    } else {
        ev_b["params"]["sessionId"].as_str().unwrap().to_owned()
    };
    let sid_102 = if sid_101 == ev_a["params"]["sessionId"].as_str().unwrap() {
        ev_b["params"]["sessionId"].as_str().unwrap().to_owned()
    } else {
        ev_a["params"]["sessionId"].as_str().unwrap().to_owned()
    };

    // Passive attach + Page.enable MUST NOT activate indicator.
    ws.send(Message::Text(
        json!({"id": 2, "sessionId": sid_101, "method": "Page.enable", "params": {}})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let _: Value =
        serde_json::from_str(&ws.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
    assert!(!cdp_events.lock().unwrap().iter().any(|(_, m, e)| {
        m == "Runtime.evaluate"
            && e.as_deref()
                .is_some_and(|s| s.contains("__styxIndicatorSetActive?.(true)"))
    }));

    // Active control (Runtime.evaluate) MUST activate tab 101, then auto-release after 120ms idle.
    cdp_events.lock().unwrap().clear();
    ws.send(Message::Text(
        json!({"id": 3, "sessionId": sid_101, "method": "Runtime.evaluate", "params": {"expression": "1+1"}})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let _: Value =
        serde_json::from_str(&ws.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
    assert!(cdp_events.lock().unwrap().iter().any(|(tid, m, e)| {
        *tid == 101
            && m == "Runtime.evaluate"
            && e.as_deref()
                .is_some_and(|s| s.contains("__styxIndicatorSetActive?.(true)"))
    }));

    tokio::time::sleep(Duration::from_millis(240)).await;
    assert!(cdp_events.lock().unwrap().iter().any(|(tid, m, e)| {
        *tid == 101
            && m == "Runtime.evaluate"
            && e.as_deref()
                .is_some_and(|s| s.contains("__styxIndicatorSetActive?.(false)"))
    }));

    // Operating tab 102 while tab 101 is still active MUST immediately deactivate tab 101.
    cdp_events.lock().unwrap().clear();
    ws.send(Message::Text(
        json!({"id": 4, "sessionId": sid_101, "method": "Runtime.evaluate", "params": {"expression": "2+2"}})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let _: Value =
        serde_json::from_str(&ws.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
    ws.send(Message::Text(
        json!({"id": 5, "sessionId": sid_102, "method": "Runtime.evaluate", "params": {"expression": "3+3"}})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let _: Value =
        serde_json::from_str(&ws.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
    tokio::time::sleep(Duration::from_millis(40)).await;
    {
        let recorded = cdp_events.lock().unwrap();
        assert!(recorded.iter().any(|(tid, m, e)| {
            *tid == 101
                && m == "Runtime.evaluate"
                && e.as_deref()
                    .is_some_and(|s| s.contains("__styxIndicatorSetActive?.(false)"))
        }));
        assert!(recorded.iter().any(|(tid, m, e)| {
            *tid == 102
                && m == "Runtime.evaluate"
                && e.as_deref()
                    .is_some_and(|s| s.contains("__styxIndicatorSetActive?.(true)"))
        }));
    }

    ws.close(None).await.unwrap();
    bridge.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), mock_ext).await;
}

#[tokio::test]
async fn cursor_tracks_mouse_events_and_hides_during_screenshot() {
    let state_dir = private_dir();
    let bridge = BrowserExtensionBridge::start(state_dir.path())
        .await
        .unwrap();
    let (port, token) = read_bridge_endpoint(state_dir.path()).unwrap();

    let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    write_half
        .write_all(format!("{}\n", json!({ "type": "auth", "token": token })).as_bytes())
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
                        "extensionId": EXTENSION_ID,
                        "browser": "Chrome/158.0.0.0",
                        "userAgent": "Mozilla/5.0 Chrome/158.0.0.0",
                        "tabs": [{ "id": 101, "url": "https://example.com/", "title": "Ex", "active": true }]
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

    let cdp_sequence = Arc::new(StdMutex::new(Vec::<(String, Value)>::new()));
    let seq_ref = cdp_sequence.clone();
    let mock_ext = tokio::spawn(async move {
        let mut buf = String::new();
        while reader.read_line(&mut buf).await.unwrap_or(0) > 0 {
            let msg: Value = serde_json::from_str(buf.trim()).unwrap();
            buf.clear();
            let id = msg["id"].as_u64().unwrap();
            let method = msg["method"].as_str().unwrap().to_owned();
            let params = msg["params"].clone();
            let reply = match method.as_str() {
                "tabs.list" => json!({ "id": id, "result": { "tabs": [
                    { "id": 101, "url": "https://example.com/", "title": "Ex", "active": true }
                ]}}),
                "debugger.attach" | "debugger.detach" => {
                    json!({ "id": id, "result": { "ok": true } })
                }
                "debugger.sendCommand" => {
                    let cdp_method = params["method"].as_str().unwrap().to_owned();
                    let cdp_params = params["params"].clone();
                    seq_ref
                        .lock()
                        .unwrap()
                        .push((cdp_method.clone(), cdp_params));
                    match cdp_method.as_str() {
                        "Target.getTargetInfo" => json!({ "id": id, "result": { "targetInfo": {
                            "targetId": "target-101", "type": "page", "url": "https://example.com/"
                        }}}),
                        "Page.addScriptToEvaluateOnNewDocument" => {
                            json!({ "id": id, "result": { "identifier": "fav-1" } })
                        }
                        "Page.getFrameTree" => {
                            let tab_id = params["tabId"].as_i64().unwrap();
                            json!({ "id": id, "result": { "frameTree": { "frame": { "id": format!("target-{tab_id}") } } } })
                        }
                        "Page.createIsolatedWorld" => {
                            json!({ "id": id, "result": { "executionContextId": 42 } })
                        }
                        "Page.captureScreenshot" => {
                            json!({ "id": id, "result": { "data": "AA==" } })
                        }
                        _ => json!({ "id": id, "result": {} }),
                    }
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

    let ws_url = bridge.open_cdp_session().unwrap();
    let mut ws = ws_connect(&ws_url).await.unwrap();
    ws.send(Message::Text(
        json!({"id": 1, "method": "Target.setAutoAttach", "params": {"autoAttach": true, "flatten": true}})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let attached: Value =
        serde_json::from_str(&ws.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
    let _aa: Value =
        serde_json::from_str(&ws.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
    let sid = attached["params"]["sessionId"].as_str().unwrap().to_owned();

    ws.send(Message::Text(
        json!({"id": 2, "sessionId": sid, "method": "Input.dispatchMouseEvent", "params": {"type": "mouseMoved", "x": 120, "y": 240}})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let _: Value =
        serde_json::from_str(&ws.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();

    ws.send(Message::Text(
        json!({"id": 3, "sessionId": sid, "method": "Input.dispatchMouseEvent", "params": {"type": "mousePressed", "x": 120, "y": 240, "button": "left"}})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let _: Value =
        serde_json::from_str(&ws.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();

    // Give spawned cursor eval tasks a moment before taking screenshot.
    tokio::time::sleep(Duration::from_millis(40)).await;

    ws.send(Message::Text(
        json!({"id": 4, "sessionId": sid, "method": "Page.captureScreenshot", "params": {}})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let shot_reply: Value =
        serde_json::from_str(&ws.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
    assert_eq!(shot_reply["result"]["data"], "AA==");

    let recorded = cdp_sequence.lock().unwrap().clone();
    assert!(recorded.iter().any(|(m, p)| {
        m == "Runtime.evaluate"
            && p["contextId"] == 42
            && p["expression"]
                .as_str()
                .is_some_and(|e| e.contains("__styxCursorMove?.(120,240,\"move\")"))
    }));
    assert!(recorded.iter().any(|(m, p)| {
        m == "Runtime.evaluate"
            && p["contextId"] == 42
            && p["expression"]
                .as_str()
                .is_some_and(|e| e.contains("__styxCursorMove?.(120,240,\"down\")"))
    }));

    let hide_idx = recorded
        .iter()
        .position(|(m, p)| {
            m == "Runtime.evaluate"
                && p["expression"]
                    .as_str()
                    .is_some_and(|e| e.contains("__styxCursorSetHidden?.(true)"))
        })
        .expect("missing pre-screenshot cursor hide");
    let shot_idx = recorded
        .iter()
        .position(|(m, _)| m == "Page.captureScreenshot")
        .expect("missing screenshot");
    let unhide_idx = recorded
        .iter()
        .rposition(|(m, p)| {
            m == "Runtime.evaluate"
                && p["expression"]
                    .as_str()
                    .is_some_and(|e| e.contains("__styxCursorSetHidden?.(false)"))
        })
        .expect("missing post-screenshot cursor unhide");
    assert!(hide_idx < shot_idx && shot_idx < unhide_idx);

    ws.close(None).await.unwrap();
    bridge.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), mock_ext).await;
}

#[tokio::test]
async fn local_cdp_session_ipc_http_discovery_and_puppeteer_handshake() {
    use tokio::io::AsyncReadExt;

    let state_dir = private_dir();
    let bridge = BrowserExtensionBridge::start(state_dir.path())
        .await
        .unwrap();

    // Disconnected bridge refuses local CDP session minting cleanly.
    assert!(
        request_local_cdp_session(state_dir.path(), None, Some("Antigravity".into()), None)
            .await
            .is_err()
    );

    let (port, token) = read_bridge_endpoint(state_dir.path()).unwrap();
    let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    write_half
        .write_all(format!("{}\n", json!({ "type": "auth", "token": token })).as_bytes())
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

    let rpc_calls = Arc::new(StdMutex::new(Vec::<(String, Value)>::new()));
    let calls_ref = rpc_calls.clone();
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
                "tabs.create" => json!({ "id": id, "result": {
                    "tab": { "id": 301, "url": params["url"], "title": "", "active": false, "groupId": 900, "isolated": true },
                    "groupId": 900
                }}),
                "debugger.attach" | "debugger.detach" => {
                    json!({ "id": id, "result": { "ok": true } })
                }
                "debugger.sendCommand" => {
                    let cdp_method = params["method"].as_str().unwrap();
                    match cdp_method {
                        "Target.getTargetInfo" => json!({ "id": id, "result": { "targetInfo": {
                            "targetId": "target-301", "type": "page", "url": "about:blank"
                        }}}),
                        _ => json!({ "id": id, "result": {} }),
                    }
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

    let session = request_local_cdp_session(
        state_dir.path(),
        None,
        Some("Antigravity".to_owned()),
        Some("cyan".to_owned()),
    )
    .await
    .unwrap();
    assert!(session.ws_endpoint.starts_with("ws://127.0.0.1:"));
    assert!(session.http_base_url.starts_with("http://127.0.0.1:"));
    assert_eq!(session.browser.as_deref(), Some("Chrome/158.0.0.0"));

    let http_get = |path: String| {
        let ws_port = bridge.ws_port();
        async move {
            let mut tcp = TcpStream::connect(("127.0.0.1", ws_port)).await.unwrap();
            let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{ws_port}\r\n\r\n");
            tcp.write_all(req.as_bytes()).await.unwrap();
            let mut out = Vec::new();
            tcp.read_to_end(&mut out).await.unwrap();
            String::from_utf8(out).unwrap()
        }
    };

    // Unauthenticated /json/version MUST be rejected.
    let unauth = http_get("/json/version".to_owned()).await;
    assert!(unauth.starts_with("HTTP/1.1 404 "));

    // Scoped /cdp/<id>/json/version and /json/list succeed without consuming the WS token.
    let session_id_slug = session.ws_endpoint.rsplit('/').next().unwrap().to_owned();
    let ver_resp = http_get(format!("/cdp/{session_id_slug}/json/version")).await;
    assert!(ver_resp.starts_with("HTTP/1.1 200 OK"));
    let (_, ver_body) = ver_resp.split_once("\r\n\r\n").unwrap();
    let ver_json: Value = serde_json::from_str(ver_body).unwrap();
    assert_eq!(ver_json["webSocketDebuggerUrl"], session.ws_endpoint);

    let list_resp = http_get(format!("/cdp/{session_id_slug}/json/list")).await;
    assert!(list_resp.starts_with("HTTP/1.1 200 OK"));
    let (_, list_body) = list_resp.split_once("\r\n\r\n").unwrap();
    assert_eq!(serde_json::from_str::<Value>(list_body).unwrap(), json!([]));

    // Now Puppeteer / chrome-devtools-mcp connects via WebSocket and uses the minted token.
    let mut ws = ws_connect(&session.ws_endpoint).await.unwrap();
    // Token is single-use: second WS attempt and subsequent /json/version return 404.
    assert!(ws_connect(&session.ws_endpoint).await.is_err());
    let spent_ver = http_get(format!("/cdp/{session_id_slug}/json/version")).await;
    assert!(spent_ver.starts_with("HTTP/1.1 404 "));

    ws.send(Message::Text(
        json!({"id": 1, "method": "Target.getBrowserContexts", "params": {}})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let ctx_rep: Value =
        serde_json::from_str(&ws.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
    assert_eq!(ctx_rep["result"]["browserContextIds"], json!([]));

    // Puppeteer issues setDiscoverTargets + setAutoAttach back-to-back.
    ws.send(Message::Text(
        json!({"id": 2, "method": "Target.setDiscoverTargets", "params": {"discover": true}})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    ws.send(Message::Text(
        json!({"id": 3, "method": "Target.setAutoAttach", "params": {"autoAttach": true, "waitForDebuggerOnStart": false, "flatten": true}})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();

    let mut msgs = Vec::new();
    for _ in 0..4 {
        let txt = ws.next().await.unwrap().unwrap().into_text().unwrap();
        msgs.push(serde_json::from_str::<Value>(&txt).unwrap());
    }
    assert!(msgs.iter().any(|m| m["method"] == "Target.targetCreated"));
    let attached_ev = msgs
        .iter()
        .find(|m| m["method"] == "Target.attachedToTarget")
        .expect("missing Target.attachedToTarget");
    let attached_sid = attached_ev["params"]["sessionId"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(msgs.iter().any(|m| m["id"] == 2));
    assert!(msgs.iter().any(|m| m["id"] == 3));

    // Only ONE tabs.create should have occurred, with groupTitle=Antigravity and groupColor=cyan.
    let create_calls: Vec<_> = rpc_calls
        .lock()
        .unwrap()
        .iter()
        .filter(|(m, _)| m == "tabs.create")
        .cloned()
        .collect();
    assert_eq!(create_calls.len(), 1);
    assert_eq!(create_calls[0].1["groupTitle"], "Antigravity");
    assert_eq!(create_calls[0].1["groupColor"], "cyan");

    // Target.detachFromTarget + Browser.close succeed cleanly.
    ws.send(Message::Text(
        json!({"id": 4, "method": "Target.detachFromTarget", "params": {"sessionId": attached_sid}})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let mut detach_msgs = Vec::new();
    for _ in 0..2 {
        let txt = ws.next().await.unwrap().unwrap().into_text().unwrap();
        detach_msgs.push(serde_json::from_str::<Value>(&txt).unwrap());
    }
    assert!(
        detach_msgs
            .iter()
            .any(|m| m["method"] == "Target.detachedFromTarget")
    );
    assert!(detach_msgs.iter().any(|m| m["id"] == 4));

    ws.send(Message::Text(
        json!({"id": 5, "method": "Browser.close", "params": {}})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let close_rep: Value =
        serde_json::from_str(&ws.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
    assert_eq!(close_rep["id"], 5);

    ws.close(None).await.unwrap();
    bridge.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), mock_ext).await;
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

async fn http_get_local(port: u16, path: &str) -> (u16, String) {
    use tokio::io::AsyncReadExt;

    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8(raw).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    let status = head
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse::<u16>()
        .unwrap();
    (status, body.to_owned())
}

async fn spawn_mock_extension_peer(bridge: &BrowserExtensionBridge) -> tokio::task::JoinHandle<()> {
    let (ipc_port, token) = read_bridge_endpoint(bridge.state_dir()).unwrap();
    let stream = TcpStream::connect(("127.0.0.1", ipc_port)).await.unwrap();
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
    tokio::spawn(async move {
        let mut buf = String::new();
        while reader.read_line(&mut buf).await.unwrap_or(0) > 0 {
            let msg: Value = serde_json::from_str(buf.trim()).unwrap();
            buf.clear();
            let id = msg["id"].as_u64().unwrap();
            let reply = match msg["method"].as_str().unwrap() {
                "tabs.list" => json!({ "id": id, "result": { "tabs": [] } }),
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
    })
}

#[tokio::test]
async fn local_cdp_proxy_reconnects_across_host_bridge_restarts_and_handles_unavailable() {
    let state_dir = private_dir();
    let proxy = LocalCdpProxy::start(LocalCdpProxyConfig {
        state_dir: state_dir.path().to_path_buf(),
        scope: None,
        group_title: Some("Antigravity".to_owned()),
        group_color: Some("cyan".to_owned()),
        bind_port: 0,
    })
    .await
    .unwrap();
    let proxy_port = proxy.port();
    assert_eq!(
        proxy.browser_url(),
        format!("http://127.0.0.1:{proxy_port}")
    );

    // Before any Host bridge is started, /json/version returns 503 and /json/list returns [].
    let (status_down, _) = http_get_local(proxy_port, "/json/version").await;
    assert_eq!(status_down, 503);
    let (list_status, list_body) = http_get_local(proxy_port, "/json/list").await;
    assert_eq!(list_status, 200);
    assert_eq!(list_body, "[]");

    // Start Host bridge #1 and connect through the proxy + verify Ping->Pong and CDP RPC.
    let bridge1 = BrowserExtensionBridge::start(state_dir.path())
        .await
        .unwrap();
    let peer1 = spawn_mock_extension_peer(&bridge1).await;
    let (status1, body1) = http_get_local(proxy_port, "/json/version").await;
    assert_eq!(status1, 200);
    let v1: Value = serde_json::from_str(&body1).unwrap();
    let ws_url1 = v1["webSocketDebuggerUrl"].as_str().unwrap();
    assert!(
        ws_url1.starts_with(&format!(
            "ws://127.0.0.1:{}/devtools/browser/",
            bridge1.ws_port()
        )),
        "unexpected ws_url1: {ws_url1}"
    );

    let mut ws1 = ws_connect(ws_url1).await.unwrap();
    ws1.send(Message::Ping(vec![9, 8, 7].into())).await.unwrap();
    let pong = tokio::time::timeout(Duration::from_secs(3), ws1.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(pong, Message::Pong(vec![9, 8, 7].into()));

    ws1.send(Message::Text(
        json!({ "id": 1, "method": "Browser.getVersion" })
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let ver1: Value =
        serde_json::from_str(&ws1.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
    assert_eq!(ver1["id"], 1);
    assert_eq!(ver1["result"]["product"], "Chrome/158.0.0.0");

    // Shut down bridge #1: existing WS closes cleanly and /json/version reports 503.
    let port1 = bridge1.ws_port();
    bridge1.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), peer1).await;
    let closed_frame = tokio::time::timeout(Duration::from_secs(3), ws1.next())
        .await
        .unwrap();
    assert!(
        matches!(
            closed_frame,
            None | Some(Ok(Message::Close(_))) | Some(Err(_))
        ),
        "expected clean close on bridge1 shutdown, got {closed_frame:?}"
    );
    let (status_between, _) = http_get_local(proxy_port, "/json/version").await;
    assert_eq!(status_between, 503);

    // Start Host bridge #2 on a new ephemeral port; same proxy seamlessly mints bridge2 URL.
    let bridge2 = BrowserExtensionBridge::start(state_dir.path())
        .await
        .unwrap();
    let peer2 = spawn_mock_extension_peer(&bridge2).await;
    let (status2, body2) = http_get_local(proxy_port, "/json/version").await;
    assert_eq!(status2, 200);
    let v2: Value = serde_json::from_str(&body2).unwrap();
    let ws_url2 = v2["webSocketDebuggerUrl"].as_str().unwrap();
    assert_ne!(bridge2.ws_port(), port1);
    assert!(
        ws_url2.starts_with(&format!(
            "ws://127.0.0.1:{}/devtools/browser/",
            bridge2.ws_port()
        )),
        "unexpected ws_url2: {ws_url2}"
    );

    let mut ws2 = ws_connect(ws_url2).await.unwrap();
    ws2.send(Message::Text(
        json!({ "id": 2, "method": "Browser.getVersion" })
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let ver2: Value =
        serde_json::from_str(&ws2.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
    assert_eq!(ver2["id"], 2);
    assert_eq!(ver2["result"]["product"], "Chrome/158.0.0.0");

    drop(ws2);
    bridge2.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), peer2).await;
    proxy.shutdown().await;
}

#[tokio::test]
async fn cdp_relay_enforces_per_session_fifo_ordering() {
    let state_dir = private_dir();
    let bridge = BrowserExtensionBridge::start(state_dir.path())
        .await
        .unwrap();
    let (port, token) = read_bridge_endpoint(state_dir.path()).unwrap();

    let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    write_half
        .write_all(format!("{}\n", json!({ "type": "auth", "token": token })).as_bytes())
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
                        "extensionId": EXTENSION_ID,
                        "browser": "Chrome/158.0.0.0",
                        "userAgent": "Mozilla/5.0 Chrome/158.0.0.0",
                        "tabs": [{ "id": 101, "url": "https://example.com/", "title": "Ex", "active": true }]
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

    let mock_ext = tokio::spawn(async move {
        let mut buf = String::new();
        while reader.read_line(&mut buf).await.unwrap_or(0) > 0 {
            let msg: Value = serde_json::from_str(buf.trim()).unwrap();
            buf.clear();
            let id = msg["id"].as_u64().unwrap();
            let method = msg["method"].as_str().unwrap().to_owned();
            let params = msg["params"].clone();
            let reply = match method.as_str() {
                "tabs.list" => json!({ "id": id, "result": { "tabs": [
                    { "id": 101, "url": "https://example.com/", "title": "Ex", "active": true }
                ]}}),
                "debugger.attach" | "debugger.detach" => {
                    json!({ "id": id, "result": { "ok": true } })
                }
                "debugger.sendCommand" => {
                    let cdp_method = params["method"].as_str().unwrap();
                    match cdp_method {
                        "Target.getTargetInfo" => json!({ "id": id, "result": { "targetInfo": {
                            "targetId": "target-101", "type": "page", "url": "https://example.com/"
                        }}}),
                        "Page.getFrameTree" => {
                            // Slow response that previously allowed pipelined Runtime.enable to overtake it.
                            tokio::time::sleep(Duration::from_millis(80)).await;
                            json!({ "id": id, "result": { "frameTree": { "frame": { "id": "f1" } } } })
                        }
                        "Runtime.enable" => {
                            let ev = json!({
                                "event": "chrome.debugger.onEvent",
                                "params": [
                                    { "tabId": 101 },
                                    "Runtime.executionContextCreated",
                                    { "context": { "id": 1, "origin": "https://example.com", "name": "" } }
                                ]
                            });
                            if write_half
                                .write_all(format!("{ev}\n").as_bytes())
                                .await
                                .is_err()
                            {
                                break;
                            }
                            json!({ "id": id, "result": {} })
                        }
                        _ => json!({ "id": id, "result": {} }),
                    }
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

    let ws_url = bridge.open_cdp_session().unwrap();
    let mut ws = ws_connect(&ws_url).await.unwrap();
    ws.send(Message::Text(
        json!({"id": 1, "method": "Target.setAutoAttach", "params": {"autoAttach": true, "flatten": true}})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let ev: Value =
        serde_json::from_str(&ws.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
    assert_eq!(ev["method"], "Target.attachedToTarget");
    let sid = ev["params"]["sessionId"].as_str().unwrap().to_owned();
    let aa_reply: Value =
        serde_json::from_str(&ws.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
    assert_eq!(aa_reply["id"], 1);

    // Pipeline Page.enable, slow Page.getFrameTree, and fast Runtime.enable in a single burst.
    for (id, method) in [
        (2, "Page.enable"),
        (3, "Page.getFrameTree"),
        (4, "Runtime.enable"),
    ] {
        ws.send(Message::Text(
            json!({ "id": id, "sessionId": sid, "method": method, "params": {} })
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    }

    let mut trace = Vec::new();
    for _ in 0..4 {
        let msg: Value = serde_json::from_str(
            &tokio::time::timeout(Duration::from_secs(3), ws.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap()
                .into_text()
                .unwrap(),
        )
        .unwrap();
        if let Some(id) = msg.get("id").and_then(Value::as_u64) {
            trace.push(format!("reply:{id}"));
        } else if let Some(m) = msg.get("method").and_then(Value::as_str) {
            trace.push(format!("event:{m}"));
        }
    }
    assert_eq!(
        trace,
        vec![
            "reply:2",
            "reply:3",
            "event:Runtime.executionContextCreated",
            "reply:4",
        ],
        "CDP replies/events broke per-session FIFO ordering: {trace:?}"
    );

    ws.close(None).await.unwrap();
    bridge.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), mock_ext).await;
}

#[tokio::test]
async fn cdp_relay_disconnect_mid_attach_never_leaks_tab_owners_or_debugger() {
    let state_dir = private_dir();
    let bridge = BrowserExtensionBridge::start(state_dir.path())
        .await
        .unwrap();
    let (port, token) = read_bridge_endpoint(state_dir.path()).unwrap();

    let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    write_half
        .write_all(format!("{}\n", json!({ "type": "auth", "token": token })).as_bytes())
        .await
        .unwrap();
    let mut ack = String::new();
    reader.read_line(&mut ack).await.unwrap();

    let tabs_json: Vec<Value> = (101..=106)
        .map(|id| json!({ "id": id, "url": format!("https://example.com/{id}"), "title": format!("Tab {id}"), "active": id == 101 }))
        .collect();
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
                        "tabs": tabs_json
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

    let attached_tabs = Arc::new(StdMutex::new(HashSet::<i64>::new()));
    let attached_ref = attached_tabs.clone();
    let out_tx = {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        tokio::spawn(async move {
            while let Some(line) = rx.recv().await {
                if write_half
                    .write_all(format!("{line}\n").as_bytes())
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        tx
    };
    let mock_ext = tokio::spawn(async move {
        let mut buf = String::new();
        while reader.read_line(&mut buf).await.unwrap_or(0) > 0 {
            let msg: Value = serde_json::from_str(buf.trim()).unwrap();
            buf.clear();
            let id = msg["id"].as_u64().unwrap();
            let method = msg["method"].as_str().unwrap().to_owned();
            let params = msg["params"].clone();
            let tx = out_tx.clone();
            let attached_clone = attached_ref.clone();
            tokio::spawn(async move {
                let reply = match method.as_str() {
                    "tabs.list" => {
                        let list: Vec<Value> = (101..=106)
                            .map(|tid| json!({ "id": tid, "url": format!("https://example.com/{tid}"), "title": format!("Tab {tid}"), "active": tid == 101 }))
                            .collect();
                        json!({ "id": id, "result": { "tabs": list } })
                    }
                    "debugger.attach" => {
                        let tid = params["tabId"].as_i64().unwrap();
                        tokio::time::sleep(Duration::from_millis(60)).await;
                        attached_clone.lock().unwrap().insert(tid);
                        json!({ "id": id, "result": { "ok": true } })
                    }
                    "debugger.detach" => {
                        let tid = params["tabId"].as_i64().unwrap();
                        attached_clone.lock().unwrap().remove(&tid);
                        json!({ "id": id, "result": { "ok": true } })
                    }
                    "debugger.sendCommand" => {
                        let tid = params["tabId"].as_i64().unwrap();
                        match params["method"].as_str().unwrap() {
                            "Target.getTargetInfo" => json!({ "id": id, "result": { "targetInfo": {
                                "targetId": format!("target-{tid}"), "type": "page", "url": format!("https://example.com/{tid}")
                            }}}),
                            _ => json!({ "id": id, "result": {} }),
                        }
                    }
                    _ => json!({ "id": id, "result": {} }),
                };
                let _ = tx.send(reply.to_string());
            });
        }
    });

    // Session #1 starts Target.setAutoAttach and drops abruptly mid-attach!
    let ws_url1 = bridge.open_cdp_session().unwrap();
    let mut ws1 = ws_connect(&ws_url1).await.unwrap();
    ws1.send(Message::Text(
        json!({"id": 1, "method": "Target.setAutoAttach", "params": {"autoAttach": true, "flatten": true}})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    drop(ws1);

    for _ in 0..40 {
        if attached_tabs.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        attached_tabs.lock().unwrap().is_empty(),
        "mid-attach disconnect leaked debugger attachments: {:?}",
        *attached_tabs.lock().unwrap()
    );

    // Session #2 immediately acquires ALL 6 tabs with zero leaked tab_owners!
    let ws_url2 = bridge.open_cdp_session().unwrap();
    let mut ws2 = ws_connect(&ws_url2).await.unwrap();
    ws2.send(Message::Text(
        json!({"id": 2, "method": "Target.setAutoAttach", "params": {"autoAttach": true, "flatten": true}})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let mut seen_targets = HashSet::new();
    loop {
        let msg: Value = serde_json::from_str(
            &tokio::time::timeout(Duration::from_secs(3), ws2.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap()
                .into_text()
                .unwrap(),
        )
        .unwrap();
        if msg["method"] == "Target.attachedToTarget" {
            seen_targets.insert(
                msg["params"]["targetInfo"]["targetId"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            );
        } else if msg["id"] == 2 {
            break;
        }
    }
    assert_eq!(
        seen_targets.len(),
        6,
        "expected all 6 tabs cleanly re-acquired, got {seen_targets:?}"
    );

    ws2.close(None).await.unwrap();
    for _ in 0..40 {
        if attached_tabs.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(attached_tabs.lock().unwrap().is_empty());

    bridge.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), mock_ext).await;
}

#[tokio::test]
async fn cdp_relay_lazy_indicator_does_not_inject_on_passive_attach() {
    let state_dir = private_dir();
    let bridge = BrowserExtensionBridge::start(state_dir.path())
        .await
        .unwrap();
    let (port, token) = read_bridge_endpoint(state_dir.path()).unwrap();

    let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    write_half
        .write_all(format!("{}\n", json!({ "type": "auth", "token": token })).as_bytes())
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
                        "extensionId": EXTENSION_ID,
                        "browser": "Chrome/158.0.0.0",
                        "userAgent": "Mozilla/5.0 Chrome/158.0.0.0",
                        "tabs": [
                            { "id": 101, "url": "https://example.com/1", "title": "One", "active": true },
                            { "id": 102, "url": "https://example.com/2", "title": "Two", "active": false }
                        ]
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

    let recorded = Arc::new(StdMutex::new(Vec::<(i64, String, Option<String>)>::new()));
    let recorded_ref = recorded.clone();
    let mock_ext = tokio::spawn(async move {
        let mut buf = String::new();
        while reader.read_line(&mut buf).await.unwrap_or(0) > 0 {
            let msg: Value = serde_json::from_str(buf.trim()).unwrap();
            buf.clear();
            let id = msg["id"].as_u64().unwrap();
            let method = msg["method"].as_str().unwrap().to_owned();
            let params = msg["params"].clone();
            let reply = match method.as_str() {
                "tabs.list" => json!({ "id": id, "result": { "tabs": [
                    { "id": 101, "url": "https://example.com/1", "title": "One", "active": true },
                    { "id": 102, "url": "https://example.com/2", "title": "Two", "active": false }
                ]}}),
                "debugger.attach" | "debugger.detach" => {
                    json!({ "id": id, "result": { "ok": true } })
                }
                "debugger.sendCommand" => {
                    let tid = params["tabId"].as_i64().unwrap();
                    let cdp_method = params["method"].as_str().unwrap().to_owned();
                    let expr = params
                        .pointer("/params/expression")
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                    recorded_ref
                        .lock()
                        .unwrap()
                        .push((tid, cdp_method.clone(), expr));
                    match cdp_method.as_str() {
                        "Target.getTargetInfo" => json!({ "id": id, "result": { "targetInfo": {
                            "targetId": format!("target-{tid}"), "type": "page", "url": format!("https://example.com/{tid}")
                        }}}),
                        "Page.addScriptToEvaluateOnNewDocument" => {
                            json!({ "id": id, "result": { "identifier": format!("fav-{tid}") } })
                        }
                        "Page.getFrameTree" => {
                            json!({ "id": id, "result": { "frameTree": { "frame": { "id": format!("target-{tid}") } } } })
                        }
                        "Page.createIsolatedWorld" => {
                            json!({ "id": id, "result": { "executionContextId": tid } })
                        }
                        _ => json!({ "id": id, "result": {} }),
                    }
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

    let ws_url = bridge.open_cdp_session().unwrap();
    let mut ws = ws_connect(&ws_url).await.unwrap();
    ws.send(Message::Text(
        json!({"id": 1, "method": "Target.setAutoAttach", "params": {"autoAttach": true, "flatten": true}})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let mut sid_101 = None;
    loop {
        let msg: Value =
            serde_json::from_str(&ws.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
        if msg["method"] == "Target.attachedToTarget"
            && msg["params"]["targetInfo"]["targetId"] == "target-101"
        {
            sid_101 = msg["params"]["sessionId"].as_str().map(str::to_owned);
        } else if msg["id"] == 1 {
            break;
        }
    }
    let sid_101 = sid_101.unwrap();

    // Passive Page.enable on tab 101 must NOT trigger focus emulation or favicon/world injection.
    ws.send(Message::Text(
        json!({"id": 2, "sessionId": sid_101, "method": "Page.enable", "params": {}})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let _: Value =
        serde_json::from_str(&ws.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
    {
        let ops = recorded.lock().unwrap();
        assert!(
            !ops.iter().any(|(_, m, _)| {
                matches!(
                    m.as_str(),
                    "Emulation.setFocusEmulationEnabled"
                        | "Page.addScriptToEvaluateOnNewDocument"
                        | "Page.createIsolatedWorld"
                )
            }),
            "passive attach/Page.enable must not inject indicator or focus emulation: {ops:?}"
        );
    }

    // Active command on tab 101 lazily installs + activates ONLY on tab 101; tab 102 stays untouched.
    ws.send(Message::Text(
        json!({"id": 3, "sessionId": sid_101, "method": "Runtime.evaluate", "params": {"expression": "1+1"}})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let _: Value =
        serde_json::from_str(&ws.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
    {
        let ops = recorded.lock().unwrap();
        assert!(
            ops.iter()
                .any(|(tid, m, _)| *tid == 101 && m == "Emulation.setFocusEmulationEnabled")
        );
        assert!(
            ops.iter()
                .any(|(tid, m, _)| *tid == 101 && m == "Page.addScriptToEvaluateOnNewDocument")
        );
        assert!(ops.iter().any(|(tid, m, e)| {
            *tid == 101
                && m == "Runtime.evaluate"
                && e.as_deref()
                    .is_some_and(|s| s.contains("__styxIndicatorSetActive?.(true)"))
        }));
        assert!(!ops.iter().any(|(tid, m, _)| *tid == 102
            && m != "Target.getTargetInfo"
            && m != "Page.getFrameTree"));
    }

    ws.close(None).await.unwrap();
    bridge.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), mock_ext).await;
}

#[tokio::test]
async fn cdp_relay_normalizes_target_id_to_main_frame_id() {
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
                        "extensionId": "cncjpfhbbnibdjkcheeimdfklfiknibl",
                        "userAgent": "Mozilla/5.0 Chrome/157.0.0.0",
                        "browser": "Chrome/157.0.0.0",
                        "tabs": [
                            { "id": 101, "url": "https://ipcheck.ing/", "title": "IPCheck", "active": true }
                        ]
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

    let recorded = Arc::new(StdMutex::new(Vec::<(String, Value)>::new()));
    let recorded_ref = recorded.clone();
    let mock_ext = tokio::spawn(async move {
        let mut buf = String::new();
        while reader.read_line(&mut buf).await.unwrap_or(0) > 0 {
            let msg: Value = serde_json::from_str(buf.trim()).unwrap();
            buf.clear();
            let id = msg["id"].as_u64().unwrap();
            let method = msg["method"].as_str().unwrap().to_owned();
            let params = msg["params"].clone();
            recorded_ref
                .lock()
                .unwrap()
                .push((method.clone(), params.clone()));
            let reply = match method.as_str() {
                "tabs.list" => json!({ "id": id, "result": { "tabs": [
                    { "id": 101, "url": "https://ipcheck.ing/", "title": "IPCheck", "active": true }
                ]}}),
                "debugger.attach" | "debugger.detach" | "tabs.remove" => {
                    json!({ "id": id, "result": { "ok": true } })
                }
                "debugger.sendCommand" => {
                    let cdp_method = params["method"].as_str().unwrap();
                    match cdp_method {
                        "Target.getTargetInfo" => json!({ "id": id, "result": { "targetInfo": {
                            "targetId": "stale-webcontents-target-101",
                            "type": "page",
                            "url": "https://ipcheck.ing/"
                        }}}),
                        "Page.getFrameTree" => json!({ "id": id, "result": { "frameTree": {
                            "frame": { "id": "swapped-main-frame-101" }
                        }}}),
                        _ => json!({ "id": id, "result": {} }),
                    }
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

    let ws_url = bridge.open_cdp_session().unwrap();
    let mut ws = ws_connect(&ws_url).await.unwrap();
    ws.send(Message::Text(
        json!({"id": 1, "method": "Target.setAutoAttach", "params": {"autoAttach": true, "flatten": true}})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();

    let mut attached_target_id = None;
    let mut session_id = None;
    loop {
        let msg: Value =
            serde_json::from_str(&ws.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
        if msg["method"] == "Target.attachedToTarget" {
            attached_target_id = msg["params"]["targetInfo"]["targetId"]
                .as_str()
                .map(str::to_owned);
            session_id = msg["params"]["sessionId"].as_str().map(str::to_owned);
        } else if msg["id"] == 1 {
            break;
        }
    }
    assert_eq!(
        attached_target_id.as_deref(),
        Some("swapped-main-frame-101")
    );
    let session_id = session_id.unwrap();

    // Target.getTargets reports normalized main frame targetId.
    ws.send(Message::Text(
        json!({"id": 2, "method": "Target.getTargets", "params": {}})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let targets_reply: Value =
        serde_json::from_str(&ws.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
    assert_eq!(targets_reply["id"], 2);
    assert_eq!(
        targets_reply["result"]["targetInfos"][0]["targetId"],
        "swapped-main-frame-101"
    );

    // Target.getTargetInfo (by normalized targetId and by sessionId) resolves cleanly.
    ws.send(Message::Text(
        json!({"id": 3, "method": "Target.getTargetInfo", "params": {"targetId": "swapped-main-frame-101"}})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let info_reply: Value =
        serde_json::from_str(&ws.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
    assert_eq!(info_reply["id"], 3);
    assert_eq!(
        info_reply["result"]["targetInfo"]["targetId"],
        "swapped-main-frame-101"
    );

    ws.send(Message::Text(
        json!({"id": 4, "sessionId": session_id, "method": "Target.getTargetInfo", "params": {}})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let session_info_reply: Value =
        serde_json::from_str(&ws.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
    assert_eq!(session_info_reply["id"], 4);
    assert_eq!(
        session_info_reply["result"]["targetInfo"]["targetId"],
        "swapped-main-frame-101"
    );

    // Target.closeTarget matches the normalized targetId and removes tab 101.
    ws.send(Message::Text(
        json!({"id": 5, "method": "Target.closeTarget", "params": {"targetId": "swapped-main-frame-101"}})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let close_reply: Value = loop {
        let msg: Value =
            serde_json::from_str(&ws.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
        if msg["id"] == 5 {
            break msg;
        }
    };
    assert_eq!(close_reply["id"], 5);
    assert_eq!(close_reply["result"]["success"], true);
    {
        let calls = recorded.lock().unwrap();
        assert!(
            calls
                .iter()
                .any(|(m, p)| m == "tabs.remove" && p["tabId"] == 101),
            "expected tabs.remove for normalized targetId: {calls:?}"
        );
    }

    ws.close(None).await.unwrap();
    bridge.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), mock_ext).await;
}

#[tokio::test]
async fn cdp_relay_tab_group_reattaches_existing_group_after_disconnect_and_falls_back_when_closed()
{
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
                        "extensionId": "cncjpfhbbnibdjkcheeimdfklfiknibl",
                        "userAgent": "Mozilla/5.0 Chrome/157.0.0.0",
                        "browser": "Chrome/157.0.0.0",
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

    let mock_tabs = Arc::new(StdMutex::new(Vec::<Value>::new()));
    let next_tab_num = Arc::new(std::sync::atomic::AtomicI64::new(201));
    let next_group_num = Arc::new(std::sync::atomic::AtomicI64::new(77));
    let recorded = Arc::new(StdMutex::new(Vec::<(String, Value)>::new()));
    let mock_tabs_ref = mock_tabs.clone();
    let recorded_ref = recorded.clone();
    let mock_ext = tokio::spawn(async move {
        let mut buf = String::new();
        while reader.read_line(&mut buf).await.unwrap_or(0) > 0 {
            let msg: Value = serde_json::from_str(buf.trim()).unwrap();
            buf.clear();
            let id = msg["id"].as_u64().unwrap();
            let method = msg["method"].as_str().unwrap().to_owned();
            let params = msg["params"].clone();
            recorded_ref
                .lock()
                .unwrap()
                .push((method.clone(), params.clone()));
            let reply = match method.as_str() {
                "tabs.create" => {
                    let tab_id = next_tab_num.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let group_id = next_group_num.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let tab = json!({
                        "id": tab_id,
                        "url": params.get("url").and_then(Value::as_str).unwrap_or("about:blank"),
                        "title": "",
                        "active": false,
                        "groupId": group_id,
                        "isolated": params.get("isolated").and_then(Value::as_bool).unwrap_or(false),
                    });
                    mock_tabs_ref.lock().unwrap().push(tab.clone());
                    json!({ "id": id, "result": { "tab": tab, "groupId": group_id } })
                }
                "tabs.list" => {
                    let tabs = mock_tabs_ref.lock().unwrap().clone();
                    json!({ "id": id, "result": { "tabs": tabs } })
                }
                "debugger.attach" | "debugger.detach" | "tabs.remove" => {
                    json!({ "id": id, "result": { "ok": true } })
                }
                "debugger.sendCommand" => {
                    let tab_id = params["tabId"].as_i64().unwrap();
                    let target_id = format!("target-{tab_id}");
                    match params["method"].as_str().unwrap() {
                        "Target.getTargetInfo" => json!({ "id": id, "result": { "targetInfo": {
                            "targetId": target_id,
                            "type": "page",
                            "url": "about:blank"
                        }}}),
                        "Page.getFrameTree" => json!({ "id": id, "result": { "frameTree": {
                            "frame": { "id": format!("target-{tab_id}") }
                        }}}),
                        _ => json!({ "id": id, "result": {} }),
                    }
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

    let scope = CdpSessionScope::TabGroup {
        title: "Styx · 1".into(),
        color: "blue".into(),
        session_key: Some("bg-reattach".into()),
    };

    // Session 1: creates tab 201 in group 77, then closes WS -> detaches debugger without closing tab.
    let ws1_url = bridge.open_cdp_session_with_scope(scope.clone()).unwrap();
    let mut ws1 = ws_connect(&ws1_url).await.unwrap();
    ws1.send(Message::Text(
        json!({"id": 1, "method": "Target.setAutoAttach", "params": {"autoAttach": true, "flatten": true}})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let mut attached1 = None;
    loop {
        let msg: Value =
            serde_json::from_str(&ws1.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
        if msg["method"] == "Target.attachedToTarget" {
            attached1 = msg["params"]["targetInfo"]["targetId"]
                .as_str()
                .map(str::to_owned);
        } else if msg["id"] == 1 {
            break;
        }
    }
    assert_eq!(attached1.as_deref(), Some("target-201"));
    ws1.close(None).await.unwrap();
    drop(ws1);

    for _ in 0..50 {
        if recorded
            .lock()
            .unwrap()
            .iter()
            .any(|(m, p)| m == "debugger.detach" && p["tabId"] == 201)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    {
        let calls = recorded.lock().unwrap();
        assert!(
            calls
                .iter()
                .any(|(m, p)| m == "debugger.detach" && p["tabId"] == 201),
            "expected debugger.detach after ws1 close: {calls:?}"
        );
        assert!(
            !calls.iter().any(|(m, _)| m == "tabs.remove"),
            "idle park/disconnect must not close tabs: {calls:?}"
        );
    }

    // Session 2 (after idle park): re-attaches directly to tab 201 in group 77 via tabs.list without tabs.create.
    let offset2 = recorded.lock().unwrap().len();
    let ws2_url = bridge.open_cdp_session_with_scope(scope.clone()).unwrap();
    let mut ws2 = ws_connect(&ws2_url).await.unwrap();
    ws2.send(Message::Text(
        json!({"id": 1, "method": "Target.setAutoAttach", "params": {"autoAttach": true, "flatten": true}})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let mut attached2 = None;
    loop {
        let msg: Value =
            serde_json::from_str(&ws2.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
        if msg["method"] == "Target.attachedToTarget" {
            attached2 = msg["params"]["targetInfo"]["targetId"]
                .as_str()
                .map(str::to_owned);
        } else if msg["id"] == 1 {
            break;
        }
    }
    assert_eq!(attached2.as_deref(), Some("target-201"));
    {
        let calls = recorded.lock().unwrap();
        let slice = &calls[offset2..];
        assert!(
            slice
                .iter()
                .any(|(m, p)| m == "tabs.list" && p["excludeIsolated"] == false),
            "expected tabs.list with excludeIsolated=false on re-attach: {slice:?}"
        );
        assert!(
            !slice.iter().any(|(m, _)| m == "tabs.create"),
            "must not open a duplicate Tab Group when group 77 still exists: {slice:?}"
        );
    }
    ws2.close(None).await.unwrap();
    drop(ws2);
    for _ in 0..50 {
        let detach_count = recorded
            .lock()
            .unwrap()
            .iter()
            .filter(|(m, p)| m == "debugger.detach" && p["tabId"] == 201)
            .count();
        if detach_count >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Session 3: simulate user closing the Tab Group while parked -> falls back to tabs.create (tab 202).
    mock_tabs.lock().unwrap().clear();
    let offset3 = recorded.lock().unwrap().len();
    let ws3_url = bridge.open_cdp_session_with_scope(scope).unwrap();
    let mut ws3 = ws_connect(&ws3_url).await.unwrap();
    ws3.send(Message::Text(
        json!({"id": 1, "method": "Target.setAutoAttach", "params": {"autoAttach": true, "flatten": true}})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let mut attached3 = None;
    loop {
        let msg: Value =
            serde_json::from_str(&ws3.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
        if msg["method"] == "Target.attachedToTarget" {
            attached3 = msg["params"]["targetInfo"]["targetId"]
                .as_str()
                .map(str::to_owned);
        } else if msg["id"] == 1 {
            break;
        }
    }
    assert_eq!(attached3.as_deref(), Some("target-202"));
    {
        let calls = recorded.lock().unwrap();
        let slice = &calls[offset3..];
        assert!(
            slice.iter().any(|(m, _)| m == "tabs.create"),
            "expected fallback tabs.create when remembered Tab Group is gone: {slice:?}"
        );
    }

    ws3.close(None).await.unwrap();
    bridge.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), mock_ext).await;
}
