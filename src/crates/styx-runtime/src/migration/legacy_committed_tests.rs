//! Real post-exit startup through ordinary Gateway/Host composition. No
//! maintenance profile, preserved live writer, mocked provider or fresh pairing.
use super::*;
use crate::foreground::{HostWireMode, gateway_run, host_run};
use crate::store::committed_runtime::CommittedRuntimeSnapshot;
use styx_contracts::identity::Sha256Digest;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a physically observed finalized original migration fixture; real ordinary network/executor scene"]
async fn committed_runtime_reopens_ordinary_gateway_and_host() {
    let root = PathBuf::from(std::env::var_os("STYX_TEST_LEGACY_GATEWAY_FIXTURE").unwrap());
    let fixture_root = PrivateRoot::open(&root).unwrap();
    let fixture: Fixture = serde_json::from_slice(
        fixture_root
            .read_raw("fixture.json", 32 * 1024)
            .unwrap()
            .bytes(),
    )
    .unwrap();
    let prior: Value = serde_json::from_slice(
        fixture_root
            .read_raw("native-result.json", 32 * 1024)
            .unwrap()
            .bytes(),
    )
    .unwrap();
    assert_eq!(
        prior["status"],
        "PASS_ORIGINAL_CUTOVER_COMMITTED_SAME_SERVICE_PROMOTED"
    );
    let snapshot = CommittedRuntimeSnapshot::open(&fixture.state_dir).unwrap();
    assert_eq!(
        snapshot.root_identity(),
        PrivateRoot::open(&fixture.state_dir).unwrap().identity()
    );
    let profile = crate::foreground::profile::load_paired(&fixture.state_dir).unwrap();
    let device = profile.device_id().clone();
    let host = PrivateRoot::open(&fixture.host_base).unwrap();
    let retired_token = snapshot.read_retired_token(&host).unwrap();
    let token = std::str::from_utf8(&retired_token).unwrap().trim();
    let ca = host.read_raw("gateway-ca.pem", 128 * 1024).unwrap();
    let mut anchors = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut std::io::Cursor::new(ca.bytes())) {
        anchors.add(cert.unwrap()).unwrap();
    }
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
    .unwrap()
    .with_root_certificates(anchors)
    .with_no_client_auth();
    let client = reqwest::Client::builder()
        .tls_backend_preconfigured(tls)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap();
    let gateway_root = PrivateRoot::open(fixture.state_dir.join("gateway")).unwrap();
    let model_raw = gateway_root.read_raw("model.token", 8192).unwrap();
    let model_token = std::str::from_utf8(model_raw.bytes()).unwrap().trim();
    let admin_raw = gateway_root.read_raw("admin.token", 8192).unwrap();
    let admin_token = std::str::from_utf8(admin_raw.bytes()).unwrap().trim();
    let endpoint: styx_contracts::native_management::NativeGatewayEndpointBinding =
        serde_json::from_slice(snapshot.endpoint_binding().unwrap()).unwrap();
    let nonce_name = format!("styx_ordinary_{}", uuid::Uuid::new_v4().simple());
    let nonce = format!("styx_ordinary_{}", uuid::Uuid::new_v4().simple());
    host.ensure_absent(&nonce_name).unwrap();
    let gateway_stop = CancellationToken::new();
    let host_stop = CancellationToken::new();
    let (gateway_events, mut gateway_events_rx) = tokio::sync::mpsc::channel(128);
    let (host_events, mut host_events_rx) = tokio::sync::mpsc::channel(128);
    let state = fixture.state_dir.clone();
    let stop = gateway_stop.clone();
    let mut gateway_job =
        tokio::spawn(async move { gateway_run(&state, stop, gateway_events).await });
    let mut host_job = None;
    let journey = async {
        timeout(Duration::from_secs(30), async {
            loop {
                let event = gateway_events_rx
                    .recv()
                    .await
                    .ok_or(TransitionError::Unknown)?;
                if event.event == "gateway_listening" {
                    return Ok::<(), TransitionError>(());
                }
            }
        })
        .await
        .map_err(|_| TransitionError::Unknown)??;
        // A normal authenticated self read must work with the original device
        // token. The model token cannot substitute for that device identity.
        let self_url = format!(
            "{}/styx/enroll/self/{}/capabilities",
            endpoint.origin,
            device.as_str()
        );
        let good = client
            .get(&self_url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|_| TransitionError::Unknown)?;
        if good.status() != reqwest::StatusCode::OK {
            return Err(TransitionError::Unknown);
        }
        let self_state: Value = good.json().await.map_err(|_| TransitionError::Unknown)?;
        if self_state["device_id"] != device.as_str() || self_state["status"] != "approved" {
            return Err(TransitionError::Unknown);
        }
        let wrong = client
            .get(&self_url)
            .bearer_auth(model_token)
            .send()
            .await
            .map_err(|_| TransitionError::Unknown)?;
        if wrong.status() != reqwest::StatusCode::FORBIDDEN {
            return Err(TransitionError::Unknown);
        }
        let devices = client
            .get(format!("{}/styx/enroll/devices", endpoint.origin))
            .bearer_auth(admin_token)
            .send()
            .await
            .map_err(|_| TransitionError::Unknown)?;
        if devices.status() != reqwest::StatusCode::OK {
            return Err(TransitionError::Unknown);
        }
        let path = fixture.state_dir.clone();
        let stop = host_stop.clone();
        host_job = Some(tokio::spawn(async move {
            host_run(&path, HostWireMode::PairedV3, stop, host_events).await
        }));
        timeout(Duration::from_secs(30), async {
            loop {
                let event = host_events_rx
                    .recv()
                    .await
                    .ok_or(TransitionError::Unknown)?;
                if event.event == "connected" {
                    return Ok::<(), TransitionError>(());
                }
            }
        })
        .await
        .map_err(|_| TransitionError::Unknown)??;
        let observation = super::super::super::network_client::exercise(
            client.clone(),
            &endpoint.origin,
            model_token,
            &device,
            fixture.host_base.to_str().ok_or(TransitionError::Unknown)?,
            &nonce_name,
            &nonce,
        )
        .await?;
        let effect = host
            .read_raw(&nonce_name, 128)
            .map_err(|_| TransitionError::Unknown)?;
        if effect.bytes() != nonce.as_bytes() || !observation.drained || observation.exit_code != 0
        {
            return Err(TransitionError::Unknown);
        }
        Ok::<_, TransitionError>((observation, self_state))
    }
    .await;
    // Gateway owns remote owner/transport cleanup. Keep the real Host alive
    // until Gateway cleanup returns, then stop and join the Host executor.
    gateway_stop.cancel();
    let gateway_outcome = timeout(Duration::from_secs(30), &mut gateway_job)
        .await
        .expect("Gateway cleanup still owned, no forced replay/stop")
        .unwrap();
    host_stop.cancel();
    let host_outcome = match host_job {
        Some(mut job) => Some(
            timeout(Duration::from_secs(20), &mut job)
                .await
                .expect("Host cleanup still owned, no inferred completion")
                .unwrap(),
        ),
        None => None,
    };
    let (observation, self_state) = journey.unwrap();
    let gateway_outcome = gateway_outcome.unwrap();
    let host_outcome = host_outcome.unwrap().unwrap();
    assert!(gateway_outcome.is_complete() && host_outcome.is_complete());
    snapshot.revalidate().unwrap();
    let effect = host.read_raw(&nonce_name, 128).unwrap();
    save(
        &root,
        "committed-reopen.json",
        &json!({
            "schema":1,"status":"PASS_COMMITTED_ORDINARY_GATEWAY_HOST_EXEC_AND_CLEANUP",
            "canonical_target_sha256":Sha256Digest::of_bytes(snapshot.canonical()),
            "candidate_manifest_sha256":snapshot.selection().manifest_sha256,
            "configuration_root":snapshot.root_identity(),"same_original_identity":true,
            "ordinary_profile":true,"ordinary_gateway":true,"ordinary_host":true,
            "self_device_status":200,"self_wrong_token_status":403,"admin_devices_status":200,
            "device_id":device,"self_state":self_state,"client":observation,
            "nonce_path":fixture.host_base.join(&nonce_name),"nonce_sha256":Sha256Digest::of_bytes(effect.bytes()),
            "nonce_bytes":effect.bytes().len(),"nonce_observation":effect.observation(),
            "gateway_cleanup":gateway_outcome,"host_cleanup":host_outcome,
            "original_enrollment_writer_created":false,"original_enrollment_namespace_created":false,
            "deployed":false,"account_login_tested":false
        }),
    );
    let original_enrollment =
        PrivateRoot::open(fixture.state_dir.join("gateway/enrollment")).unwrap();
    original_enrollment
        .ensure_absent(".styx-configuration-writer.lock")
        .unwrap();
    original_enrollment
        .ensure_absent(".styx-enrollment-journal-v1")
        .unwrap();
}
