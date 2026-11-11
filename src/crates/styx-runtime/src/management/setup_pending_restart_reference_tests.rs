//! Opt-in reference: real CLI, signed payload, fresh Gateway CA and strict TLS.
//! This captures the C28 refusal boundary, not successful resume acceptance.
#![cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
use super::*;
use serde_json::{Value, json};
use std::io::Write;
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

fn save(path: &Path, data: &[u8]) {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(data).unwrap();
    file.sync_all().unwrap();
}

// The durable enrollment mutation records must not change. The separately
// maintained clock floor may advance while the Gateway is read/restarted.
fn journal(path: &Path) -> BTreeMap<String, Vec<u8>> {
    fs::read_dir(path)
        .unwrap()
        .map(|e| e.unwrap())
        .filter_map(|entry| {
            let name = entry.file_name().into_string().unwrap();
            if name == "clock.floor" {
                return None;
            }
            let ty = entry.file_type().unwrap();
            assert!(ty.is_file(), "unexpected journal entry: {name}");
            Some((name, fs::read(entry.path()).unwrap()))
        })
        .collect()
}

#[tokio::test]
#[ignore = "requires loopback, built CLI and explicit signed STYX_SETUP_TEST_PAYLOAD/PUBLISHER/PIN"]
async fn hub_pending_across_foreground_restart_is_refused_without_approval_or_claim() {
    let payload = PathBuf::from(
        std::env::var_os("STYX_SETUP_TEST_PAYLOAD").expect("signed payload required"),
    );
    let publisher =
        PathBuf::from(std::env::var_os("STYX_SETUP_TEST_PUBLISHER").expect("publisher required"));
    let pin = std::env::var("STYX_SETUP_TEST_PIN").expect("publisher pin required");
    let cli = PathBuf::from(std::env::var_os("STYX_SETUP_TEST_CLI").expect("built CLI required"));
    assert!(payload.is_absolute() && publisher.is_absolute() && cli.is_absolute() && cli.is_file());
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let root = PathBuf::from(format!("/tmp/sx-{}", &suffix[..8]));
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    println!("private synthetic setup evidence: {}", root.display());
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    drop(socket);
    let answers = json!({"schema":1,"role":"hub","payload":{"payload_dir":payload,"publisher_file":publisher,"expected_publisher":pin},"label":"restart-reference","workspace":root.join("work"),"shell":"/bin/bash","port":port,"approve":["inputs","payload","workspace","gateway","gateway-run","invite","trust","request"]});
    let first_answers = root.join("first-answers.json");
    save(
        &first_answers,
        &serde_json::to_vec_pretty(&answers).unwrap(),
    );
    let state = root.join("state");
    let invoke = |answers: PathBuf| {
        let mut command = tokio::process::Command::new(&cli);
        command
            .args(["setup", "--answers"])
            .arg(answers)
            .arg("--root")
            .arg(&state)
            .args(["--foreground", "--exit-when-connected"])
            .kill_on_drop(true);
        command
    };
    let first = tokio::time::timeout(Duration::from_secs(120), invoke(first_answers).output())
        .await
        .expect("first setup deadline")
        .unwrap();
    save(&root.join("first.stdout"), &first.stdout);
    save(&root.join("first.stderr"), &first.stderr);
    let first_text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );
    assert_eq!(
        first.status.code(),
        Some(2),
        "first setup must stop at consent: {first_text}"
    );
    assert!(first_text.contains("setup_step_not_authorized"));
    assert!(!first_text.contains("setup_gateway_cleanup_unconfirmed"));
    let before = native_join::inspect(&state.join("host"))
        .await
        .expect("original durable Host");
    assert_eq!(before.status, "awaiting_approval");
    let identity = serde_json::to_value(&before).unwrap();
    let reply_path = state.join("host/host-join-reply-v1.json");
    let reply_bytes = fs::read(&reply_path).unwrap();
    let reply: Value = serde_json::from_slice(&reply_bytes).unwrap();
    let old_leaf = reply["peer_leaf_sha256"].as_str().unwrap();
    assert_eq!(reply["body"]["ingress"]["certificate_sha256"], old_leaf);
    let records = journal(&state.join("gateway/.styx-enrollment-journal-v1"));
    assert!(!records.is_empty());
    for path in [
        "inputs/approve.started",
        "inputs/claim-0.started",
        "host/host-credential.token",
        "host/host-confirm-dispatched-v1.json",
        "host/host-ready-v1.json",
    ] {
        assert!(!state.join(path).exists(), "unexpected mutation: {path}");
    }
    // Independently verify that the previous foreground owner stopped listening.
    assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_err());
    let mut resumed_answers = answers;
    resumed_answers["approve"].as_array_mut().unwrap().extend([
        json!("approve"),
        json!("claim"),
        json!("host-run"),
    ]);
    let resume_file = root.join("resume-answers.json");
    save(
        &resume_file,
        &serde_json::to_vec_pretty(&resumed_answers).unwrap(),
    );

    // Read the new process's actual TLS peer and pending row with the synthetic
    // Gateway's local admin credential. Never print the credential or response.
    // This concurrent observation is deliberately required: failing to catch the
    // short-lived process makes the reference fail rather than fabricate proof.
    let ca = fs::read(state.join("gateway/gateway-ca.pem")).unwrap();
    let der = rustls_pemfile::certs(&mut std::io::Cursor::new(&ca))
        .next()
        .unwrap()
        .unwrap();
    let tls = crate::tls::GatewayClientTls::from_pinned_ca_pem(
        &ca,
        crate::tls::TrustAnchorPin::from_certificate_der(&der),
        None,
    )
    .unwrap();
    let bearer = fs::read(state.join("gateway/gateway-admin.token")).unwrap();
    let origin = url::Url::parse(&format!("https://127.0.0.1:{port}/")).unwrap();
    let output = invoke(resume_file).output();
    let observation = async {
        loop {
            if let Ok(response) =
                native_join_http::exchange_local_pending(&origin, &tls, &bearer).await
                && response.status == 200
            {
                return (
                    response.leaf_pin.as_hex(),
                    serde_json::from_slice::<Value>(&response.body).unwrap(),
                );
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    let (second, observed) = tokio::time::timeout(Duration::from_secs(120), async {
        tokio::join!(
            output,
            tokio::time::timeout(Duration::from_secs(30), observation)
        )
    })
    .await
    .expect("resume deadline");
    let second = second.unwrap();
    save(&root.join("resume.stdout"), &second.stdout);
    save(&root.join("resume.stderr"), &second.stderr);
    let second_text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(
        second.status.code(),
        Some(2),
        "resume must refuse: {second_text}"
    );
    assert!(second_text.contains("native_gateway_pending_binding_mismatch"));
    let (new_leaf, rows) = observed.expect("did not independently observe resumed TLS peer");
    assert_ne!(new_leaf, old_leaf);
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 1);
    for (wire, host) in [
        ("request_id", "request_id"),
        ("device_id", "device_id"),
        ("fingerprint", "fingerprint"),
        ("comparison_code", "comparison_code"),
    ] {
        assert_eq!(rows[0][wire], identity[host]);
    }
    assert_eq!(rows[0]["ingress"]["certificate_sha256"], old_leaf);
    let after = native_join::inspect(&state.join("host"))
        .await
        .expect("same durable Host");
    let after = serde_json::to_value(after).unwrap();
    for name in ["request_id", "device_id", "fingerprint", "comparison_code"] {
        assert_eq!(identity[name], after[name]);
    }
    assert_eq!(fs::read(reply_path).unwrap(), reply_bytes);
    assert_eq!(
        journal(&state.join("gateway/.styx-enrollment-journal-v1")),
        records
    );
    for path in [
        "inputs/approve.started",
        "inputs/claim-0.started",
        "host/host-credential.token",
        "host/host-confirm-dispatched-v1.json",
        "host/host-ready-v1.json",
    ] {
        assert!(!state.join(path).exists(), "unexpected mutation: {path}");
    }
    assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_err());
}

/// Fresh signed-reader7 Hub with one real pending request and a joined,
/// stopped foreground Gateway. Private synthetic evidence is retained.
pub(crate) struct PendingFixture {
    pub(crate) root: PathBuf,
    pub(crate) state: PathBuf,
    pub(crate) cli: PathBuf,
    pub(crate) answers: Value,
    pub(crate) port: u16,
}
impl PendingFixture {
    pub(crate) fn setup_command(&self, answers: &Path) -> tokio::process::Command {
        let mut cmd = tokio::process::Command::new(&self.cli);
        cmd.args(["setup", "--answers"])
            .arg(answers)
            .arg("--root")
            .arg(&self.state)
            .args(["--foreground", "--exit-when-connected"])
            .kill_on_drop(true);
        cmd
    }
}
pub(crate) async fn fresh_signed_pending_fixture() -> PendingFixture {
    let payload = PathBuf::from(
        std::env::var_os("STYX_SETUP_TEST_PAYLOAD").expect("signed payload required"),
    );
    let publisher =
        PathBuf::from(std::env::var_os("STYX_SETUP_TEST_PUBLISHER").expect("publisher required"));
    let pin = std::env::var("STYX_SETUP_TEST_PIN").expect("publisher pin required");
    let cli =
        PathBuf::from(std::env::var_os("STYX_SETUP_TEST_CLI").expect("new built CLI required"));
    assert!(payload.is_absolute() && publisher.is_absolute() && cli.is_absolute() && cli.is_file());
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let root = PathBuf::from(format!("/tmp/sx-{}", &suffix[..8]));
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    println!("private synthetic setup evidence: {}", root.display());
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let answers = json!({"schema":1,"role":"hub","payload":{"payload_dir":payload,"publisher_file":publisher,"expected_publisher":pin},"label":"retirement-reference","workspace":root.join("work"),"shell":"/bin/bash","port":port,"approve":["inputs","payload","workspace","gateway","gateway-run","invite","trust","request"]});
    let fixture = PendingFixture {
        state: root.join("state"),
        root,
        cli,
        answers,
        port,
    };
    let file = fixture.root.join("first-answers.json");
    save(&file, &serde_json::to_vec_pretty(&fixture.answers).unwrap());
    let output = tokio::time::timeout(
        Duration::from_secs(120),
        fixture.setup_command(&file).output(),
    )
    .await
    .expect("setup deadline")
    .unwrap();
    save(&fixture.root.join("first.stdout"), &output.stdout);
    save(&fixture.root.join("first.stderr"), &output.stderr);
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(2), "{text}");
    assert!(text.contains("setup_step_not_authorized"));
    assert!(!text.contains("setup_gateway_cleanup_unconfirmed"));
    assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_err());
    assert_eq!(
        native_join::inspect(&fixture.state.join("host"))
            .await
            .expect("durable pending")
            .status,
        "awaiting_approval"
    );
    fixture
}

#[tokio::test]
#[ignore = "requires loopback and NEW CLI plus signed reader7 payload/publisher/pin"]
async fn hub_explicit_retire_preserves_gateway_then_pairs_new_identity_in_same_root() {
    let f = fresh_signed_pending_fixture().await;
    let old = native_join::inspect(&f.state.join("host")).await.unwrap();
    let old_request = old.request_id.clone().unwrap();
    let old_device = old.device_id.clone();
    let immutable_names = [
        "gateway/gateway-ca.pem",
        "gateway/gateway-ready-v1.json",
        "gateway/state.json",
        "gateway/deployment.json",
        "inputs/runtime-selection.json",
    ];
    let immutable: Vec<_> = immutable_names
        .iter()
        .map(|name| fs::read(f.state.join(name)).unwrap())
        .collect();
    let journal_before = journal(&f.state.join("gateway/.styx-enrollment-journal-v1"));
    let output = tokio::time::timeout(
        Duration::from_secs(120),
        tokio::process::Command::new(&f.cli)
            .args(["role", "retire", "--state-dir"])
            .arg(f.state.join("host"))
            .arg("--setup-root")
            .arg(&f.state)
            .args(["--authorize", "--json"])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("retire deadline")
    .unwrap();
    save(&f.root.join("retire.stdout"), &output.stdout);
    save(&f.root.join("retire.stderr"), &output.stderr);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["outcome"], "retired");
    assert_eq!(report["pairingOutcome"], "rejected");
    assert_eq!(report["operationsReplayed"], false);
    let paths = report["retired"].as_array().unwrap();
    let old_host = f.state.join("host");
    let archived = paths
        .iter()
        .find(|p| p["oldPath"].as_str() == old_host.to_str())
        .unwrap();
    let archived_host = PathBuf::from(archived["newPath"].as_str().unwrap());
    assert!(!old_host.exists() && archived_host.is_dir());
    assert!(!archived_host.join("host-credential.token").exists());
    assert!(!archived_host.join("host-ready-v1.json").exists());
    for (name, before) in immutable_names.iter().zip(&immutable) {
        assert_eq!(&fs::read(f.state.join(name)).unwrap(), before);
    }
    let journal_after = journal(&f.state.join("gateway/.styx-enrollment-journal-v1"));
    for (name, bytes) in &journal_before {
        assert_eq!(journal_after.get(name), Some(bytes));
    }
    let rejected: Vec<_> = journal_after
        .iter()
        .filter_map(|(name, bytes)| {
            if !name.ends_with(".intent") {
                return None;
            }
            let value: Value = serde_json::from_slice(bytes).ok()?;
            (value["mutation"]["kind"] == "reject"
                && value["mutation"]["target"]["request"] == old_request)
                .then_some(name)
        })
        .collect();
    assert_eq!(rejected.len(), 1);
    let stem = rejected[0].strip_suffix(".intent").unwrap();
    assert!(
        journal_after.contains_key(&format!("{stem}.prepared"))
            && journal_after.contains_key(&format!("{stem}.committed"))
    );
    let mut answers = f.answers.clone();
    answers["approve"].as_array_mut().unwrap().extend([
        json!("approve"),
        json!("claim"),
        json!("host-run"),
    ]);
    let file = f.root.join("fresh-answers.json");
    save(&file, &serde_json::to_vec_pretty(&answers).unwrap());
    let next = tokio::time::timeout(Duration::from_secs(120), f.setup_command(&file).output())
        .await
        .expect("fresh pairing deadline")
        .unwrap();
    save(&f.root.join("fresh.stdout"), &next.stdout);
    save(&f.root.join("fresh.stderr"), &next.stderr);
    assert!(
        next.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&next.stdout),
        String::from_utf8_lossy(&next.stderr)
    );
    assert!(
        String::from_utf8_lossy(&next.stdout)
            .contains("This computer connected (confirmed by the hub).")
    );
    let new = native_join::inspect(&f.state.join("host")).await.unwrap();
    assert_eq!(new.status, "ready_to_connect");
    assert_ne!(new.device_id, old_device);
    assert_ne!(new.request_id.as_deref(), Some(old_request.as_str()));
    assert!(std::net::TcpStream::connect(("127.0.0.1", f.port)).is_err());
}
