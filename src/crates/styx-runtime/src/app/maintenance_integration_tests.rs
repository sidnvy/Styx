//! Real signed C08 + completed strict-TLS local enrollment and original C07.
//! No installed root, publisher private key or canonical edit. The revoked
//! guest scenario also starts the original signed Host executor.
use super::*;
use std::{
    fs,
    io::Write as _,
    os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _},
};
use styx_contracts::{identity::Sha256Digest, native_management::NativeRuntimeSelection};

fn raw(value: Value) -> Box<serde_json::value::RawValue> {
    serde_json::value::to_raw_value(&value).unwrap()
}
fn directory(path: &Path) {
    fs::DirBuilder::new().mode(0o700).create(path).unwrap();
}
fn write_new(path: &Path, bytes: &[u8]) {
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires STYX_TEST_APP_CONTROL_SELECTION and STYX_TEST_APP_LAN_ADDRESS; real TLS revoked identity and signed Host executor"]
async fn revoked_guest_startup_refusal_allows_fresh_role_without_replay() {
    let selection_file = PathBuf::from(std::env::var("STYX_TEST_APP_CONTROL_SELECTION").unwrap());
    let selection: NativeRuntimeSelection =
        serde_json::from_slice(&fs::read(selection_file).unwrap()).unwrap();
    let lan = std::env::var("STYX_TEST_APP_LAN_ADDRESS").unwrap();
    let top = std::env::temp_dir().join(format!("styx-revoked-repair-{}", uuid::Uuid::new_v4()));
    directory(&top);
    let (mut hub, candidate) = enroll_on(&top.join("hub"), &selection, Some(lan)).await;
    hub.local_gateway.as_mut().unwrap().start().await.unwrap();
    let invite = hub
        .dispatch(Operation::InviteComputer, raw(json!({"authorize":true})))
        .await
        .unwrap();
    let guest_dir = top.join("guest");
    directory(&guest_dir);
    let profile = guest_dir.join("profile");
    let mut guest = HostApp::open_native(&profile, &candidate).await.unwrap();
    let inspected = guest
        .dispatch(Operation::InspectJoin, raw(json!({"link":invite["link"]})))
        .await
        .unwrap();
    let joined = guest.dispatch(Operation::Join, raw(json!({"label":"Revoked recovery guest","computer":false,"browser":false,"persistLogin":false,
        "approvedGatewayOrigin":inspected["preview"]["origin"],"approvedCaSha256":inspected["preview"]["caSha256"]}))).await.unwrap();
    assert_eq!(joined["status"], "ready_to_connect");
    guest.settle_all().await.unwrap();
    guest.set_desired(NativeRunDesired::Running).await.unwrap();
    drop(guest);
    hub.dispatch(
        Operation::RevokeComputer,
        raw(json!({"authorize":true,"deviceId":joined["device_id"]})),
    )
    .await
    .unwrap();
    let inventory = hub
        .dispatch(Operation::Computers, raw(json!({})))
        .await
        .unwrap();
    assert_eq!(inventory["devices"].as_array().unwrap().len(), 1);
    let mut guest = HostApp::open_native(&profile, &candidate).await.unwrap();
    guest
        .dispatch(Operation::StartupStatus, raw(json!({})))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        while !guest
            .running
            .as_ref()
            .is_some_and(|role| role.worker.is_finished())
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("original revoked admission must terminate");
    let observed = guest.dispatch(Operation::Status, raw(json!({}))).await;
    assert!(
        observed.is_ok(),
        "actual revoked startup result: {:?}",
        observed.as_ref().err().map(AppError::code)
    );
    let observed = observed.unwrap();
    assert_eq!(
        observed["foreground"]["error"],
        "gateway_wss_admission_refused"
    );
    assert_eq!(observed["admission_fenced"], false);
    assert!(guest.running.is_none());
    // Repeated observation must not retry the rejected credential. Explicit
    // reconfiguration preserves the old identity as a backup instead.
    guest
        .dispatch(Operation::StartupStatus, raw(json!({})))
        .await
        .unwrap();
    assert!(guest.running.is_none());
    assert_eq!(
        guest
            .dispatch(Operation::Connect, raw(json!({})))
            .await
            .unwrap_err()
            .code(),
        "app_gateway_access_refused"
    );
    assert!(guest.running.is_none());
    let quitting = guest
        .dispatch(Operation::QuitAdmission, raw(json!({})))
        .await
        .unwrap();
    assert_eq!(quitting["quit"]["status"], "ready_to_quit");
    let retired = guest
        .dispatch(
            Operation::RetireRole,
            raw(json!({"allowOtherDevices":false})),
        )
        .await
        .unwrap();
    assert_eq!(retired["retirement"]["outcome"], "retired");
    assert!(!profile.exists());
    for path in retired["retirement"]["retired"].as_array().unwrap() {
        assert!(!Path::new(path["oldPath"].as_str().unwrap()).exists());
        assert!(Path::new(path["newPath"].as_str().unwrap()).exists());
    }
    assert!(guest.enrollment.is_none() && guest.configuration.is_none());
    assert!(!guest.admission_fenced());
    hub.settle_all().await.unwrap();
    drop(guest);
    drop(hub);
    fs::remove_dir_all(top).unwrap();
}
// Hashes avoid exposing private enrollment material if an assertion fails.
async fn enroll(container: &Path, selection: &NativeRuntimeSelection) -> (HostApp, PathBuf) {
    enroll_on(container, selection, None).await
}
async fn enroll_on(
    container: &Path,
    selection: &NativeRuntimeSelection,
    lan_address: Option<String>,
) -> (HostApp, PathBuf) {
    directory(container);
    let candidates = container.join("migration-candidates");
    directory(&candidates);
    let bytes = serde_json::to_vec(selection).unwrap();
    let candidate = candidates.join(format!("{}.json", Sha256Digest::of_bytes(&bytes).to_hex()));
    write_new(&candidate, &bytes);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let mut app = HostApp::open_native(&container.join("profile"), &candidate)
        .await
        .unwrap();
    // Direct existing enrollment entry avoids the UI dispatch's later Connect.
    // Only the original local Gateway executes, over strict pinned TLS.
    app.create_local(LocalInput {
        exec: true,
        tunnel: None,
        label: "App maintenance fixture".into(),
        computer: false,
        browser: false,
        browser_channel: None,
        persist_login: false,
        port,
        lan_address,
        allow_remote_hosts: false,
    })
    .await
    .unwrap();
    assert_eq!(
        app.enrollment.as_ref().unwrap()["status"],
        "ready_to_connect"
    );
    assert!(app.running.is_none());
    app.settle_all().await.unwrap();
    app.set_desired(NativeRunDesired::Stopped).await.unwrap();
    assert!(app.running.is_none());
    assert!(!app.local_gateway.as_ref().unwrap().is_running());
    (app, candidate)
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires STYX_TEST_APP_CONTROL_SELECTION and STYX_TEST_APP_LAN_ADDRESS; disposable real TLS Gateway and two App profiles"]
async fn native_gui_computer_management_keeps_binding_and_local_identity() {
    let selection_file = PathBuf::from(std::env::var("STYX_TEST_APP_CONTROL_SELECTION").unwrap());
    let selection: NativeRuntimeSelection =
        serde_json::from_slice(&fs::read(selection_file).unwrap()).unwrap();
    let lan = std::env::var("STYX_TEST_APP_LAN_ADDRESS").unwrap();
    let top = std::env::temp_dir().join(format!("styx-gui-admin-{}", uuid::Uuid::new_v4()));
    directory(&top);
    let (mut hub, candidate) = enroll_on(&top.join("hub"), &selection, Some(lan)).await;
    hub.local_gateway.as_mut().unwrap().start().await.unwrap();
    assert_eq!(
        crate::management::native_gateway_admin::computers(
            &hub.local_gateway.as_ref().unwrap().scope.state_dir
        )
        .await
        .unwrap_err()
        .code(),
        "native_gateway_admin_fresh_gateway_required"
    );
    let before = hub
        .dispatch(Operation::Computers, raw(json!({})))
        .await
        .unwrap();
    assert_eq!(before["devices"].as_array().unwrap().len(), 1);
    assert_eq!(before["devices"][0]["is_local"], true);
    assert_eq!(
        hub.dispatch(
            Operation::RevokeComputer,
            raw(json!({"authorize":true,"deviceId":before["devices"][0]["device_id"]}))
        )
        .await
        .unwrap_err()
        .code(),
        "app_cannot_revoke_this_computer"
    );
    assert_eq!(
        hub.dispatch(Operation::InviteComputer, raw(json!({"authorize":false})))
            .await
            .unwrap_err()
            .code(),
        "app_confirmation_required"
    );
    let invite = hub
        .dispatch(Operation::InviteComputer, raw(json!({"authorize":true})))
        .await
        .unwrap();
    let guest_dir = top.join("guest");
    directory(&guest_dir);
    let mut guest = HostApp::open_native(&guest_dir.join("profile"), &candidate)
        .await
        .unwrap();
    let inspected = guest
        .dispatch(Operation::InspectJoin, raw(json!({"link":invite["link"]})))
        .await
        .unwrap();
    let request = guest.dispatch(Operation::Join, raw(json!({"label":"GUI guest","computer":false,"browser":false,"persistLogin":false,
        "approvedGatewayOrigin":inspected["preview"]["origin"],"approvedCaSha256":inspected["preview"]["caSha256"]}))).await.unwrap();
    assert_eq!(request["status"], "ready_to_connect");
    let pending = hub
        .dispatch(Operation::PendingComputers, raw(json!({})))
        .await
        .unwrap();
    assert!(pending["pending"].as_array().unwrap().is_empty());
    let listed = hub
        .dispatch(Operation::Computers, raw(json!({})))
        .await
        .unwrap();
    assert_eq!(listed["devices"].as_array().unwrap().len(), 2);
    hub.dispatch(
        Operation::RevokeComputer,
        raw(json!({"authorize":true,"deviceId":request["device_id"]})),
    )
    .await
    .unwrap();
    assert_eq!(
        hub.dispatch(Operation::Computers, raw(json!({})))
            .await
            .unwrap()["devices"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let saved = hub
        .dispatch(
            Operation::TunnelSave,
            raw(json!({"authorize":true,"tunnelId":"bad","apiKey":"not-a-key"})),
        )
        .await
        .unwrap_err();
    assert_eq!(saved.code(), "invalid_tunnel_id");
    assert!(hub.local_gateway.as_ref().unwrap().is_running());
    let presentation = hub
        .dispatch(Operation::PluginRead, raw(json!({})))
        .await
        .unwrap();
    assert_eq!(
        presentation["plugin"]["presentation"]["displayName"],
        "Styx"
    );
    guest.settle_all().await.unwrap();
    hub.settle_all().await.unwrap();
    drop(guest);
    drop(hub);
    let mut reopened = HostApp::open_native(&top.join("hub/profile"), &candidate)
        .await
        .unwrap();
    reopened
        .local_gateway
        .as_mut()
        .unwrap()
        .start()
        .await
        .unwrap();
    let observed = reopened
        .dispatch(Operation::Computers, raw(json!({})))
        .await
        .unwrap();
    assert_eq!(observed["devices"].as_array().unwrap().len(), 1);
    assert_eq!(observed["devices"][0]["is_local"], true);
    reopened.settle_all().await.unwrap();
    drop(reopened);
    fs::remove_dir_all(top).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires STYX_TEST_APP_CONTROL_SELECTION and STYX_TEST_APP_SETTLE_ROOT; real signed Exec worker, local strict TLS App and independent process/file effects"]
async fn strict_settlement_with_live_exec_keeps_host_available_for_owner_cleanup() {
    use rmcp::{
        ClientServiceExt,
        model::*,
        service::ClientLifecycleMode,
        transport::{
            StreamableHttpClientTransport,
            streamable_http_client::StreamableHttpClientTransportConfig,
        },
    };
    let selection: NativeRuntimeSelection = serde_json::from_slice(
        &fs::read(std::env::var("STYX_TEST_APP_CONTROL_SELECTION").unwrap()).unwrap(),
    )
    .unwrap();
    let parent = PathBuf::from(std::env::var("STYX_TEST_APP_SETTLE_ROOT").unwrap());
    let top = parent.join(uuid::Uuid::new_v4().to_string());
    directory(&top);
    let (mut app, _) = enroll(&top.join("app"), &selection).await;
    app.local_gateway.as_mut().unwrap().start().await.unwrap();
    app.connect_host().await.unwrap();
    let gateway = app.local_gateway.as_ref().unwrap();
    let raw_client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(gateway.ca.as_bytes()).unwrap())
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let token = zeroize::Zeroizing::new(
        String::from_utf8(
            gateway
                .scope
                .root
                .get()
                .unwrap()
                .read_raw("gateway-model.token", 4096)
                .unwrap()
                .bytes()
                .to_vec(),
        )
        .unwrap(),
    );
    let config = StreamableHttpClientTransportConfig::with_uri(format!("{}/mcp", gateway.origin))
        .auth_header(token.trim().to_owned())
        .reinit_on_expired_session(false)
        .max_concurrent_requests(1);
    let client = ClientConfig::new(
        ClientCapabilities::default(),
        Implementation::new("owned-app-settlement-oracle", "1"),
    )
    .with_protocol_version(ProtocolVersion::V_2025_11_25)
    .serve_with_lifecycle(
        StreamableHttpClientTransport::with_client(raw_client, config),
        ClientLifecycleMode::Initialize,
    )
    .await
    .unwrap();
    let devices = app
        .dispatch(Operation::Computers, raw(json!({})))
        .await
        .unwrap();
    let device = devices["devices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["is_local"] == true)
        .unwrap()["device_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let call = |name: &str, arguments: Value| {
        serde_json::from_value::<CallToolRequestParams>(json!({"name":name,"arguments":arguments}))
            .unwrap()
    };
    let until = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let status = client
            .call_tool(call(
                "get_execution_environment_status",
                json!({"environment_id":device}),
            ))
            .await
            .unwrap();
        if status
            .structured_content
            .is_some_and(|v| v["exec"]["connection"] == "connected")
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < until,
            "real local Host connection deadline"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let cwd = top.join("effects");
    directory(&cwd);
    let nonce = uuid::Uuid::new_v4().to_string();
    let command = format!(
        "printf '%s\\n' '{nonce}' >> settle-once.txt; printf '%s' \"$$\" > settle.pid; printf ready; IFS= read -r never; printf forbidden > settle-escaped.txt"
    );
    let started = client
        .call_tool(call(
            "exec_command",
            json!({"cmd":command,"workdir":cwd,"login":false,"environment_id":device,"yield_time_ms":100}),
        ))
        .await
        .unwrap();
    assert_ne!(
        started.is_error,
        Some(true),
        "native Exec must actually start"
    );
    assert!(
        started.structured_content.unwrap()["session_id"]
            .as_u64()
            .is_some()
    );
    let until = tokio::time::Instant::now() + Duration::from_secs(5);
    while !cwd.join("settle.pid").is_file() {
        assert!(
            tokio::time::Instant::now() < until,
            "independent PID file deadline"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let pid: u32 = fs::read_to_string(cwd.join("settle.pid"))
        .unwrap()
        .parse()
        .unwrap();
    assert!(pid > 1);
    let process = PathBuf::from(format!("/proc/{pid}/stat"));
    let birth = |path: &Path| -> std::io::Result<u64> {
        let text = fs::read_to_string(path)?;
        text.rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().nth(19))
            .and_then(|value| value.parse().ok())
            .ok_or_else(|| std::io::Error::other("invalid process birth"))
    };
    let before = birth(&process).unwrap();
    assert_eq!(
        fs::read_to_string(cwd.join("settle-once.txt")).unwrap(),
        format!("{nonce}\n")
    );
    let settled = app.settle_all().await;
    let process_exited = match birth(&process) {
        Ok(actual) => actual != before,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(error) => panic!("kernel exit observation unknown: {error}"),
    };
    let observation = json!({"schema":1,"status":if settled.is_ok(){"PASS"}else{"FAIL"},"settle_error":settled.as_ref().err().map(AppError::code),"native_pid":pid,"original_process_exited":process_exited,"host_cleanup":app.cleanup,"gateway_cleanup":app.local_gateway.as_ref().unwrap().cleanup,"once_file":fs::read_to_string(cwd.join("settle-once.txt")).unwrap(),"escaped_input_effect":cwd.join("settle-escaped.txt").exists(),"scope":"disposable App/strict TLS/real Codex; not installed GUI or account acceptance"});
    fs::write(
        top.join("settlement-observation.json"),
        serde_json::to_vec_pretty(&observation).unwrap(),
    )
    .unwrap();
    let _ = client.cancel().await;
    assert!(
        settled.is_ok(),
        "strict settlement failed: {:?}; fixture={}",
        settled.err().map(|e| e.code()),
        top.display()
    );
    assert!(app.cleanup.as_ref().unwrap().is_complete());
    assert!(
        app.local_gateway
            .as_ref()
            .unwrap()
            .cleanup
            .as_ref()
            .unwrap()
            .is_complete()
    );
    assert_eq!(observation["original_process_exited"], true);
    assert!(!cwd.join("settle-escaped.txt").exists());
    println!(
        "PASS strict App settlement after actual Exec, independent one-time file/PID and exact Host/Gateway cleanup; fixture={}",
        top.display()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires STYX_TEST_APP_PREVIOUS_SELECTION, STYX_TEST_APP_CONTROL_SELECTION and fresh STYX_TEST_APP_BUNDLE_ROOT; removes only its disposable previous-runtime fixture"]
async fn reopened_app_gateway_uses_current_bundle_after_old_payload_is_removed() {
    use crate::management::{native_gateway, native_gateway_admin};
    let top = PathBuf::from(std::env::var("STYX_TEST_APP_BUNDLE_ROOT").unwrap());
    let previous: NativeRuntimeSelection = serde_json::from_slice(
        &fs::read(std::env::var("STYX_TEST_APP_PREVIOUS_SELECTION").unwrap()).unwrap(),
    )
    .unwrap();
    let current_file = PathBuf::from(std::env::var("STYX_TEST_APP_CONTROL_SELECTION").unwrap());
    let current: NativeRuntimeSelection =
        serde_json::from_slice(&fs::read(&current_file).unwrap()).unwrap();
    let previous_root = top.join("previous-runtime");
    assert!(top.is_absolute());
    assert_eq!(
        Path::new(&previous.payload_path),
        previous_root.join("payload")
    );
    assert_eq!(
        Path::new(&previous.publisher_file),
        previous_root.join("publisher.pem")
    );
    assert!(!Path::new(&current.payload_path).starts_with(&top));
    assert_ne!(previous.manifest_sha256, current.manifest_sha256);
    assert_eq!(
        previous.publisher_spki_sha256,
        current.publisher_spki_sha256
    );
    let bundle = Arc::new(crate::release::load_selected(&current).unwrap());
    let (mut app, _) = enroll(&top.join("hub"), &previous).await;
    app.local_gateway.as_mut().unwrap().start().await.unwrap();
    let before = app
        .dispatch(Operation::Computers, raw(json!({})))
        .await
        .unwrap();
    assert_eq!(before["devices"].as_array().unwrap().len(), 1);
    let host_identity = app.scope.root.get().unwrap().identity();
    let gateway_scope = app.local_gateway.as_ref().unwrap().scope.clone();
    let gateway_identity = gateway_scope.root.get().unwrap().identity();
    let ca_sha = app.local_gateway.as_ref().unwrap().ca_sha.clone();
    let host_seed = Sha256Digest::of_bytes(
        app.scope
            .root
            .get()
            .unwrap()
            .read_raw("host-join-seed-v1.json", 1024 * 1024)
            .unwrap()
            .bytes(),
    );
    app.settle_all().await.unwrap();
    drop(app.local_gateway.take());
    // Linux has no installed desktop bundle. Supply the same retained object
    // that open_with_selection obtains from the installed Mac/Windows App.
    app.native_runtime = Some(bundle.clone());
    app.runtime_selection_file = Some(current_file);
    fs::remove_dir_all(&previous_root).unwrap();
    assert!(!previous_root.exists());
    app.local_gateway = Some(app.load_local_gateway(gateway_scope.clone()).await.unwrap());
    {
        let runtime = native_gateway::open_existing_for_app_diagnostic(
            gateway_scope.clone(),
            None,
            Some(bundle.clone()),
        )
        .unwrap();
        assert_eq!(
            runtime.verified_release().runtime_selection().unwrap(),
            current
        );
        // The retained-runtime revalidation must not return to the old hash.
        runtime.validate().unwrap();
    }
    for _ in 0..2 {
        app.local_gateway.as_mut().unwrap().start().await.unwrap();
        let status = native_gateway_admin::observe_for_app(gateway_scope.clone())
            .await
            .unwrap();
        assert!(status["mcp_sessions"]["open"].as_u64().is_some());
        assert_eq!(status["computers"]["connected"], 0);
        assert!(status["mcp_sessions"].get("capacity").is_none());
        let after = app
            .dispatch(Operation::Computers, raw(json!({})))
            .await
            .unwrap();
        assert_eq!(after, before);
        assert!(
            native_gateway_admin::pairing_rejection_supported_for_app(gateway_scope.clone())
                .await
                .unwrap()
        );
        let invitation = app
            .local_gateway
            .as_mut()
            .unwrap()
            .admin_once(false, &json!({"ttl_seconds":600}))
            .await
            .unwrap();
        assert!(
            invitation["invitation"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        );
        app.settle_all().await.unwrap();
    }
    assert_eq!(app.scope.root.get().unwrap().identity(), host_identity);
    assert_eq!(
        gateway_scope.root.get().unwrap().identity(),
        gateway_identity
    );
    assert_eq!(app.local_gateway.as_ref().unwrap().ca_sha, ca_sha);
    assert_eq!(
        Sha256Digest::of_bytes(
            app.scope
                .root
                .get()
                .unwrap()
                .read_raw("host-join-seed-v1.json", 1024 * 1024)
                .unwrap()
                .bytes(),
        ),
        host_seed
    );
    assert_eq!(
        native_gateway_admin::committed_runtime_selection(gateway_scope.state_dir())
            .await
            .unwrap(),
        previous
    );
    drop(app);
    drop(gateway_scope);
    fs::remove_dir_all(top).unwrap();
}
