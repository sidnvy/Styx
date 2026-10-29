//! Real transport + private profile regressions. Synthetic signed payload is
//! verified but never executed; no installed device/profile is used.
use super::*;
use crate::{
    crypto::PublisherVerifyingKey,
    enrollment::{http::EnrollmentHttp, service::EnrollmentService},
    management::native_join_http,
    store::enrollment::{EnrollmentJournal, JournalBudget, OwnedEnrollmentJournal},
    tls::{GatewayClientTls, GatewayServerTls, generate_gateway_ca, issue_server_leaf},
};
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey, pkcs8::EncodePublicKey as _};
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
};
use styx_contracts::identity::Sha256Digest;
use tokio::{io::AsyncReadExt, net::TcpListener};

fn directory(path: &Path) {
    fs::DirBuilder::new().mode(0o700).create(path).unwrap();
}
fn write(path: &Path, bytes: &[u8], executable: bool) {
    use std::io::Write as _;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(if executable { 0o700 } else { 0o600 })
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
fn selection(root: &Path) -> PathBuf {
    let payload = root.join("payload");
    directory(&payload);
    directory(&payload.join("bin"));
    let sources = [
        ("LICENSE", b"synthetic fixture license".as_slice(), false),
        (
            "bin/styx",
            b"\x7fELF synthetic, never executed".as_slice(),
            true,
        ),
        ("source-inputs.json", b"{}".as_slice(), false),
    ];
    let files: Vec<_> = sources.iter().map(|(path, bytes, executable)| {
        write(&payload.join(path), bytes, *executable);
        json!({"path":path,"size":bytes.len(),"sha256":Sha256Digest::of_bytes(bytes),"executable":executable})
    }).collect();
    let key = SigningKey::from_bytes(&[37; 32]);
    let der = key.verifying_key().to_public_key_der().unwrap();
    let pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        base64::engine::general_purpose::STANDARD.encode(der.as_bytes())
    );
    let publisher = root.join("publisher.pem");
    write(&publisher, pem.as_bytes(), false);
    let pin = PublisherVerifyingKey::from_spki_pem(pem.as_bytes())
        .unwrap()
        .fingerprint()
        .unwrap();
    let manifest = json!({"schema":2,"runtime_format":"native_rust_v1","component":"styx",
        "scope":"runtime_candidate","minimum_reader":"native_runtime_migrated_v3","target":"x86_64-unknown-linux-gnu",
        "version":"0.4.0-test.1","entrypoint":"bin/styx","source":{"revision":"1".repeat(40),
        "inputs_sha256":Sha256Digest::of_bytes(b"{}")},"contracts":{"control":1,"management_state":2},
        "files":files,"external_workers":[]});
    let raw = serde_json::to_vec(&manifest).unwrap();
    write(&payload.join("manifest.json"), &raw, false);
    write(
        &payload.join("manifest.sig"),
        &key.sign(&raw).to_bytes(),
        false,
    );
    let selected = crate::release::verify(&payload, &publisher, &pin)
        .unwrap()
        .runtime_selection()
        .unwrap();
    let path = root.join("selection.json");
    write(&path, &serde_json::to_vec(&selected).unwrap(), false);
    path
}
fn raw(value: Value) -> Box<serde_json::value::RawValue> {
    serde_json::value::to_raw_value(&value).unwrap()
}
fn deployment(
    root: &Path,
    selection: &Path,
    origin: &str,
    ca: &str,
    pin: &str,
    invitation: &str,
) -> PathBuf {
    write(&root.join("ca.pem"), ca.as_bytes(), false);
    write(&root.join("invitation"), invitation.as_bytes(), false);
    let path = root.join("deployment.json");
    write(
        &path,
        &serde_json::to_vec(&json!({"schema":1,"mode":"join-existing",
        "gateway":{"url":origin,"caFile":root.join("ca.pem"),"expectedCaSha256":pin},
        "host":{"label":"Join retry fixture","cwd":root,"shell":"/bin/sh","computer":false},
        "runtimeSelectionFile":selection,"invitationFile":root.join("invitation")}))
        .unwrap(),
        false,
    );
    path
}
fn backups(root: &Path, prefix: &str) -> Vec<PathBuf> {
    fs::read_dir(root)
        .unwrap()
        .map(Result::unwrap)
        .filter(|e| e.file_name().to_string_lossy().starts_with(prefix))
        .map(|e| e.path())
        .collect()
}
async fn invite(origin: &url::Url, client: &GatewayClientTls) -> Value {
    let response = native_join_http::exchange_local_admin(
        origin,
        client,
        false,
        br#"{"ttl_seconds":600}"#,
        "a".repeat(43).as_bytes(),
    )
    .await
    .unwrap();
    assert_eq!(response.status, 200);
    serde_json::from_slice(&response.body).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires loopback sockets; synthetic signed payload and disposable real enrollment server"]
async fn unsent_cli_and_app_join_retry_but_dispatched_join_stays_fenced_requires_sockets() {
    let root = std::env::temp_dir().join(format!("styx-join-retry-{}", uuid::Uuid::new_v4()));
    directory(&root);
    let selection = selection(&root);
    let now = now_ms().unwrap();
    let ca = generate_gateway_ca(now / 1000, now / 1000 - 60, now / 1000 + 86400).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let origin = url::Url::parse(&format!("https://{address}/")).unwrap();
    let leaf = issue_server_leaf(
        &ca.certificate_pem,
        &ca.private_key,
        &ca.anchor_pin,
        origin.as_str(),
        now / 1000,
    )
    .unwrap();
    let server_tls = Arc::new(
        GatewayServerTls::from_pem(
            &leaf.certificate_chain_pem,
            &leaf.private_key,
            leaf.leaf_pin,
        )
        .unwrap(),
    );
    let client =
        GatewayClientTls::from_pinned_ca_pem(&ca.certificate_pem, ca.anchor_pin.clone(), None)
            .unwrap();
    let store_path = root.join("server");
    directory(&store_path);
    let private = PrivateRoot::open(&store_path).unwrap();
    let mut writer = private.try_configuration_writer().unwrap();
    EnrollmentJournal::open(&private, &mut writer, JournalBudget::default())
        .unwrap()
        .record_time_floor(now)
        .unwrap();
    let journal =
        OwnedEnrollmentJournal::open_existing(private, writer, JournalBudget::default()).unwrap();
    let service = EnrollmentService::recover_existing(
        journal,
        "a".repeat(43).as_bytes(),
        Sha256Digest::of_bytes(b"model"),
        vec![address.to_string()],
        styx_core::enrollment::Limits::default(),
    )
    .unwrap();
    let http = EnrollmentHttp::new(server_tls.clone(), service, vec![address.to_string()]).unwrap();
    let stop = CancellationToken::new();
    let server = tokio::spawn(http.run(listener, stop.clone()));
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unreachable = format!("https://{}", closed.local_addr().unwrap());
    drop(closed);
    let pin = &ca.anchor_pin.as_hex();
    let ca_pem = std::str::from_utf8(&ca.certificate_pem).unwrap();
    let invitation = invite(&origin, &client).await;
    let token = invitation["invitation"].as_str().unwrap();

    let cli = root.join("cli");
    directory(&cli);
    let bad = cli.join("bad");
    directory(&bad);
    let input = deployment(&bad, &selection, &unreachable, ca_pem, pin, token);
    let error = native_join::request(&cli, std::ffi::OsStr::new("host"), &input)
        .await
        .err()
        .unwrap();
    assert_eq!(error.code(), "join_http_connect_failed");
    assert!(error.retryable() && !error.uncertain() && error.hint().is_some());
    assert!(!cli.join("host").exists());
    let saved = backups(&cli, "host.join-not-sent-");
    assert_eq!(saved.len(), 1);
    assert_eq!(
        fs::metadata(&saved[0]).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert!(saved[0].join("host-join-dispatched-v1.json").is_file());
    assert!(!saved[0].join("host-join-reply-v1.json").exists());
    // No request reached the hub: the same one-use invitation still works.
    let good = cli.join("good");
    directory(&good);
    let input = deployment(
        &good,
        &selection,
        &origin.origin().ascii_serialization(),
        ca_pem,
        pin,
        token,
    );
    let joined = native_join::request(&cli, std::ffi::OsStr::new("host"), &input)
        .await
        .unwrap();
    assert_eq!(joined.status, "awaiting_approval");
    assert_eq!(
        native_join::inspect(&cli.join("host"))
            .await
            .unwrap()
            .request_id,
        joined.request_id
    );

    // Exercise the actual App inspectJoin + join operations in the SAME owner.
    let container = root.join("app");
    directory(&container);
    let mut app = HostApp::open_native(&container.join("host"), &selection)
        .await
        .unwrap();
    for origin_text in [&unreachable, &origin.origin().ascii_serialization()] {
        let invitation = invite(&origin, &client).await;
        let link = pairing_link::build(
            origin_text,
            invitation["invitation"].as_str().unwrap(),
            invitation["expires_at"].as_u64().unwrap(),
            ca_pem,
            now_ms().unwrap(),
        )
        .unwrap();
        app.dispatch(Operation::InspectJoin, raw(json!({"link":link.as_str()})))
            .await
            .unwrap();
        let result = app.dispatch(Operation::Join, raw(json!({"label":"Retry App","computer":false,"browser":false,"persistLogin":false,"approvedGatewayOrigin":origin_text,"approvedCaSha256":pin}))).await;
        if origin_text == &unreachable {
            assert_eq!(result.unwrap_err().code(), "join_http_connect_failed");
            let status = app
                .dispatch(Operation::Status, raw(json!({})))
                .await
                .unwrap();
            assert!(status["configuration"].is_null() && status["enrollment"].is_null());
            assert_eq!(status["admission_fenced"], false);
            assert!(app.join_retry.is_some() && app.input_writer.is_none());
            for name in [
                "app-join-input-v1.json",
                "app-join-ca-v1.pem",
                "app-join-invitation-v1",
            ] {
                assert!(!container.join(name).exists());
                assert_eq!(
                    backups(&container, &format!("{name}.join-not-sent-")).len(),
                    1
                );
            }
        } else {
            assert_eq!(result.unwrap()["status"], "awaiting_approval");
        }
    }
    drop(app);

    // Negative control: peer observes the WHOLE request, then closes without a
    // reply. Its remote effect cannot be inferred, so never archive or retry.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unknown_origin = format!("https://{}", listener.local_addr().unwrap());
    let peer = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = server_tls
            .accept(tcp, Duration::from_secs(5))
            .await
            .unwrap();
        let mut request = Vec::new();
        let mut buf = [0; 1024];
        loop {
            let n = tls.read(&mut buf).await.unwrap();
            assert!(n > 0 && request.len() + n <= 16384);
            request.extend_from_slice(&buf[..n]);
            if let Some(i) = request.windows(4).position(|b| b == b"\r\n\r\n") {
                let headers = std::str::from_utf8(&request[..i])
                    .unwrap()
                    .to_ascii_lowercase();
                let length: usize = headers
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .unwrap()
                    .trim()
                    .parse()
                    .unwrap();
                if request.len() == i + 4 + length {
                    break;
                }
            }
        }
        request.len()
    });
    let unknown = root.join("unknown");
    directory(&unknown);
    let input = deployment(&unknown, &selection, &unknown_origin, ca_pem, pin, token);
    let error = native_join::request(&unknown, std::ffi::OsStr::new("host"), &input)
        .await
        .err()
        .unwrap();
    assert!(peer.await.unwrap() > 1024);
    assert_eq!(error.code(), "join_http_exchange_failed");
    assert!(!error.retryable() && error.uncertain());
    assert!(unknown.join("host").is_dir());
    assert!(backups(&unknown, "host.join-not-sent-").is_empty());
    drop(error); // Whole owner teardown releases the retained writer.
    let error = native_join::inspect(&unknown.join("host"))
        .await
        .err()
        .unwrap();
    assert_eq!(error.code(), "native_join_dispatch_unknown_no_retry");
    drop(error);
    stop.cancel();
    let facts = server.await.unwrap().unwrap();
    assert!(facts.connections_joined && facts.blocking_jobs_joined);
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn presend_refusal_archives_cli_and_app_inputs_and_allows_new_inspection() {
    let root = std::env::temp_dir().join(format!("styx-presend-retry-{}", uuid::Uuid::new_v4()));
    directory(&root);
    let selection = selection(&root);
    let now = now_ms().unwrap();
    let ca = generate_gateway_ca(now / 1000, now / 1000 - 60, now / 1000 + 86400).unwrap();
    let pem = std::str::from_utf8(&ca.certificate_pem).unwrap();
    let pin = ca.anchor_pin.as_hex();
    // Port zero is rejected by exchange_once before any DNS/socket operation.
    // This tests the real NotDispatched recovery without a transport mock.
    let origin = "https://127.0.0.1:0";
    let cli = root.join("cli");
    directory(&cli);
    let input = deployment(&cli, &selection, origin, pem, &pin, &"a".repeat(43));
    let error = native_join::request(&cli, std::ffi::OsStr::new("host"), &input)
        .await
        .err()
        .unwrap();
    assert_eq!(error.code(), "join_http_invalid_input");
    assert!(error.retryable() && !error.uncertain());
    assert!(!cli.join("host").exists());
    assert_eq!(backups(&cli, "host.join-not-sent-").len(), 1);
    let container = root.join("app");
    directory(&container);
    let mut app = HostApp::open_native(&container.join("host"), &selection)
        .await
        .unwrap();
    let expected =
        [2u8, 3].map(|byte| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([byte; 32]));
    for secret in &expected {
        let link = pairing_link::build(
            origin,
            secret,
            now_ms().unwrap() + 300_000,
            pem,
            now_ms().unwrap(),
        )
        .unwrap();
        app.dispatch(Operation::InspectJoin, raw(json!({"link":link.as_str()})))
            .await
            .unwrap();
        let error = app.dispatch(Operation::Join, raw(json!({"label":"Retry App","computer":false,"browser":false,"persistLogin":false,"approvedGatewayOrigin":origin,"approvedCaSha256":pin}))).await.unwrap_err();
        assert_eq!(error.code(), "join_http_invalid_input");
        let status = app
            .dispatch(Operation::Status, raw(json!({})))
            .await
            .unwrap();
        assert!(status["configuration"].is_null() && status["enrollment"].is_null());
        assert_eq!(status["admission_fenced"], false);
        assert!(app.scope.root.get().is_none() && app.input_writer.is_none());
        assert!(!container.join("host").exists());
    }
    assert_eq!(backups(&container, "host.join-not-sent-").len(), 2);
    let saved = backups(&container, "app-join-invitation-v1.join-not-sent-");
    let mut secrets: Vec<_> = saved
        .iter()
        .map(|p| fs::read_to_string(p).unwrap())
        .collect();
    secrets.sort();
    let mut expected = expected.to_vec();
    expected.sort();
    assert_eq!(secrets, expected);
    for name in [
        "app-join-input-v1.json",
        "app-join-ca-v1.pem",
        "app-join-invitation-v1",
    ] {
        assert!(!container.join(name).exists());
        assert_eq!(
            backups(&container, &format!("{name}.join-not-sent-")).len(),
            2
        );
    }
    drop(app);
    let mut reopened = HostApp::open_native(&container.join("host"), &selection)
        .await
        .unwrap();
    assert_eq!(reopened.snapshot().await["admission_fenced"], false);
    let link = pairing_link::build(
        origin,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([4u8; 32]),
        now_ms().unwrap() + 300_000,
        pem,
        now_ms().unwrap(),
    )
    .unwrap();
    reopened
        .dispatch(Operation::InspectJoin, raw(json!({"link":link.as_str()})))
        .await
        .unwrap();
    drop(reopened);
    fs::remove_dir_all(root).unwrap();
}
