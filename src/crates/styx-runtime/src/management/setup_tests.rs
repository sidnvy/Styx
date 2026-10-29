//! Private-filesystem checks and an opt-in real signed-payload foreground journey.
//! The live journey never installs services or adopts an existing profile.
use super::*;
use serde_json::{Value, json};
use std::{fs, path::PathBuf};

fn directory(name: &str) -> PathBuf {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    let root = repo
        .join("target")
        .join(format!("{name}-{}", uuid::Uuid::new_v4().simple()));
    private_directory(&root).unwrap();
    root
}
#[test]
fn setup_pinned_tls_configuration_is_accepted_by_http_client() {
    let now = 1900000000;
    let ca = crate::tls::generate_gateway_ca(now, now - 60, now + 86400 * 365)
        .unwrap_or_else(|_| panic!("test CA"));
    let tls =
        crate::tls::GatewayClientTls::from_pinned_ca_pem(&ca.certificate_pem, ca.anchor_pin, None)
            .unwrap();
    // reqwest accepts ClientConfig, not Arc<ClientConfig>; a type-check alone
    // cannot catch a mismatched Any-based preconfigured TLS backend.
    reqwest::Client::builder()
        .no_proxy()
        .tls_backend_preconfigured(tls.http_client_config())
        .build()
        .unwrap();
}
#[test]
fn setup_hidden_key_never_enters_public_status_or_error_strings() {
    let root = directory("setup-secret");
    let gateway = root.join("gateway");
    private_directory(&gateway).unwrap();
    let key = root.join("source-key");
    let sentinel = "sk-SETUP_SECRET_SENTINEL_0123456789abcdef";
    write_new(&key, sentinel.as_bytes()).unwrap();
    let status = crate::foreground::tunnel::configure(
        &gateway,
        &format!("tunnel_{}", "a".repeat(32)),
        &key,
        true,
        true,
    )
    .unwrap();
    let output = serde_json::to_string(&status).unwrap();
    assert!(!output.contains(sentinel));
    assert!(!output.contains("SETUP_SECRET_SENTINEL"));
    let refused = crate::foreground::tunnel::configure(&gateway, "invalid", &key, true, true)
        .err()
        .unwrap();
    assert!(!format!("{refused:?} {refused}").contains(sentinel));
    assert_eq!(read_private(&key, 4096).unwrap(), sentinel.as_bytes());
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn setup_tunnel_observation_ignores_foreign_markers_and_contains_only_metadata() {
    let root = directory("setup-observation");
    let gateway = root.join("gateway");
    private_directory(&gateway).unwrap();
    let key = root.join("source-key");
    write_new(&key, b"sk-SETUP_SECRET_SENTINEL_0123456789abcdef").unwrap();
    crate::foreground::tunnel::configure(
        &gateway,
        &format!("tunnel_{}", "a".repeat(32)),
        &key,
        true,
        true,
    )
    .unwrap();
    let observer = crate::foreground::tunnel::observe_requests(&gateway)
        .unwrap()
        .unwrap();
    observer.record(b"forged-marker");
    assert_eq!(
        crate::foreground::tunnel::request_observation(&gateway).unwrap()["requests"],
        0
    );
    let marker = read_private(&gateway.join("tunnel/request-marker"), 128).unwrap();
    observer.record(&marker);
    let value = crate::foreground::tunnel::request_observation(&gateway).unwrap();
    assert_eq!(value["requests"], 1);
    assert!(value["last_seen_unix_ms"].as_u64().unwrap() > 0);
    assert_eq!(value.as_object().unwrap().len(), 3);
    assert!(
        !value
            .to_string()
            .contains(std::str::from_utf8(&marker).unwrap())
    );
    drop(observer);
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
#[ignore = "requires sockets, a built CLI, and STYX_SETUP_TEST_PAYLOAD/PUBLISHER/PIN; no systemd"]
async fn setup_hub_answers_foreground_connects_and_resumes_without_pairing_requires_sockets() {
    let (Some(payload), Some(publisher), Some(pin)) = (
        std::env::var_os("STYX_SETUP_TEST_PAYLOAD"),
        std::env::var_os("STYX_SETUP_TEST_PUBLISHER"),
        std::env::var_os("STYX_SETUP_TEST_PIN"),
    ) else {
        eprintln!(
            "SKIP setup foreground journey: set STYX_SETUP_TEST_PAYLOAD, STYX_SETUP_TEST_PUBLISHER and STYX_SETUP_TEST_PIN to a real signed Linux payload and its trusted public publisher inputs."
        );
        return;
    };
    let payload = PathBuf::from(payload);
    let publisher = PathBuf::from(publisher);
    let pin = pin
        .into_string()
        .expect("publisher fingerprint must be text");
    assert!(payload.is_absolute() && publisher.is_absolute());
    // Short roots are required by the real Host's Unix-domain sockets. Claim
    // this fresh private directory exclusively; preserve it for result review.
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let root = PathBuf::from(format!("/tmp/sx-{}", &suffix[..8]));
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    println!("setup evidence: {}", root.display());
    fn save(path: &Path, bytes: &[u8]) {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    let cli = std::env::var_os("STYX_SETUP_TEST_CLI")
        .map(PathBuf::from)
        .unwrap_or_else(|| repo.join("target/debug/styx"));
    assert!(cli.is_file(), "build the CLI first: cargo build -p styx");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let answers = json!({"schema":1,"role":"hub","payload":{"payload_dir":payload,"publisher_file":publisher,"expected_publisher":pin},"label":"setup-fixture","workspace":root.join("work"),"shell":"/bin/bash","port":port,"approve":["inputs","payload","workspace","gateway","gateway-run","invite","trust","request","approve","claim","host-run"]});
    let file = root.join("answers.json");
    write_new(&file, &serde_json::to_vec_pretty(&answers).unwrap()).unwrap();
    let state = root.join("state");
    async fn invoke(cli: &Path, file: &Path, state: &Path) -> std::process::Output {
        tokio::time::timeout(
            std::time::Duration::from_secs(90),
            tokio::process::Command::new(cli)
                .args(["setup", "--answers"])
                .arg(file)
                .arg("--root")
                .arg(state)
                .args(["--foreground", "--exit-when-connected"])
                .kill_on_drop(true)
                .output(),
        )
        .await
        .expect("setup deadline")
        .unwrap()
    }
    let first = invoke(&cli, &file, &state).await;
    save(&root.join("first.stdout.txt"), &first.stdout);
    save(&root.join("first.stderr.txt"), &first.stderr);
    assert!(
        first.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(
        String::from_utf8_lossy(&first.stdout)
            .contains("This computer connected (confirmed by the hub).")
    );
    let seed = read_private(&state.join("host/host-join-seed-v1.json"), 1024 * 1024).unwrap();
    // Capture all enrollment material using existing fixed names from the store.
    let ready = read_private(&state.join("host/host-ready-v1.json"), 1024 * 1024).unwrap();
    let gateway_ready =
        read_private(&state.join("gateway/gateway-ready-v1.json"), 1024 * 1024).unwrap();
    let second = invoke(&cli, &file, &state).await;
    save(&root.join("resume.stdout.txt"), &second.stdout);
    save(&root.join("resume.stderr.txt"), &second.stderr);
    assert!(
        second.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr)
    );
    let resumed = String::from_utf8_lossy(&second.stdout);
    assert!(resumed.contains("Computer pairing: already complete"));
    assert!(resumed.contains("This computer connected (confirmed by the hub)."));
    assert!(!resumed.contains("Create a one-use local invitation"));
    assert!(!resumed.contains("ask the confirmed hub to pair it"));
    assert_eq!(
        gateway_ready,
        read_private(&state.join("gateway/gateway-ready-v1.json"), 1024 * 1024).unwrap()
    );
    assert_eq!(
        ready,
        read_private(&state.join("host/host-ready-v1.json"), 1024 * 1024).unwrap()
    );
    assert_eq!(
        seed,
        read_private(&state.join("host/host-join-seed-v1.json"), 1024 * 1024).unwrap()
    );
    let status = tokio::process::Command::new(&cli)
        .arg("status")
        .arg("--root")
        .arg(&state)
        .arg("--json")
        .output()
        .await
        .unwrap();
    assert!(status.status.success());
    let status: Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status["role"], "hub");
    assert!(
        status["gateway"].get("error").is_some(),
        "stopped foreground Gateway must not be reported connected"
    );
}
