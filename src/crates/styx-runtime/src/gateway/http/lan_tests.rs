//! Real TLS/enrollment/WebSocket on loopback plus an assigned private interface.
//! Synthetic identities; no executor, package, device installation or account.
use super::*;
use crate::{
    crypto::{ClaimCapability, DevicePrivateKey, DeviceProofBytes, EnrollmentRequestId},
    enrollment::{http::EnrollmentHttp, service::EnrollmentService, shared::SharedEnrollment},
    gateway::paired::{PairedGatewayBackend, RelayHandle},
    host::{
        link::{HostLinkBudget, HostWssLink, LinkAuthentication, LinkEndpoint, SecretBearer},
        protocol::wire,
    },
    store::{
        PrivateRoot,
        enrollment::{EnrollmentJournal, JournalBudget, OwnedEnrollmentJournal},
    },
    tls::{
        GatewayClientTls, GatewayLeafPin, GatewayServerTls, generate_gateway_ca,
        issue_server_leaf_with_lan,
    },
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    os::unix::fs::PermissionsExt,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use styx_contracts::{
    identity::*,
    legacy::{JoinPayload, PairingComparison},
};
use styx_core::enrollment::Limits;
use tokio::net::{TcpListener, TcpStream};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap()
}
fn fresh_store(path: &Path) -> OwnedEnrollmentJournal {
    std::fs::create_dir(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = PrivateRoot::open(path).unwrap();
    let mut writer = root.try_configuration_writer().unwrap();
    EnrollmentJournal::open(&root, &mut writer, JournalBudget::default())
        .unwrap()
        .record_time_floor(now_ms())
        .unwrap();
    OwnedEnrollmentJournal::open_existing(root, writer, JournalBudget::default()).unwrap()
}
async fn request(
    tls: &GatewayClientTls,
    address: SocketAddr,
    host: &str,
    method: Method,
    path: &str,
    bearer: Option<&str>,
    body: Value,
) -> (u16, Value, GatewayLeafPin) {
    let tcp = TcpStream::connect(address).await.unwrap();
    let stream = tls
        .connect(&address.ip().to_string(), tcp, Duration::from_secs(5))
        .await
        .unwrap();
    let leaf =
        GatewayLeafPin::from_certificate_der(&stream.get_ref().1.peer_certificates().unwrap()[0]);
    let (mut sender, connection) = hyper::client::conn::http1::handshake::<_, Full<Bytes>>(
        hyper_util::rt::TokioIo::new(stream),
    )
    .await
    .unwrap();
    let driver = tokio::spawn(connection);
    let bytes = if method == Method::GET {
        vec![]
    } else {
        serde_json::to_vec(&body).unwrap()
    };
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("host", host)
        .header("connection", "close")
        .header("content-type", "application/json");
    if let Some(token) = bearer {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let response = sender
        .send_request(builder.body(Full::new(Bytes::from(bytes))).unwrap())
        .await
        .unwrap();
    let status = response.status().as_u16();
    let raw = Limited::new(response.into_body(), 32 * 1024)
        .collect()
        .await
        .unwrap()
        .to_bytes();
    drop(sender);
    driver.await.unwrap().unwrap();
    let value = if raw.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&raw).unwrap()
    };
    (status, value, leaf)
}
fn lan_ip() -> Ipv4Addr {
    if let Ok(address) = std::env::var("STYX_TEST_LAN_ADDRESS") {
        return crate::gateway::auth::lan_address(true, Some(&address))
            .expect("private IPv4 required")
            .unwrap();
    }
    // Route selection only; connect on a UDP socket sends no packets.
    let route = std::net::UdpSocket::bind("0.0.0.0:0").expect("requires sockets");
    route
        .connect("10.255.255.255:9")
        .expect("set STYX_TEST_LAN_ADDRESS to an assigned private IPv4");
    let ip = route.local_addr().unwrap().ip();
    crate::gateway::auth::lan_address(true, Some(&ip.to_string()))
        .expect("requires an assigned private IPv4; set STYX_TEST_LAN_ADDRESS")
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires sockets and assigned private IPv4; optionally set STYX_TEST_LAN_ADDRESS"]
async fn gateway_two_listeners_lan_join_and_host_link_requires_sockets() {
    let ip = lan_ip();
    let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local = local_listener.local_addr().unwrap();
    let lan = SocketAddr::new(IpAddr::V4(ip), local.port());
    let lan_listener = TcpListener::bind(lan)
        .await
        .expect("LAN address must be assigned locally");
    let local_host = local.to_string();
    let lan_host = lan.to_string();
    let local_origin = format!("https://{local}");
    let lan_origin = format!("https://{lan}");
    let clock = now_ms() / 1000;
    let (ca, leaf, identity) = tokio::task::spawn_blocking(move || {
        let ca = generate_gateway_ca(clock, clock - 60, clock + 86400).unwrap();
        let leaf = issue_server_leaf_with_lan(
            &ca.certificate_pem,
            &ca.private_key,
            &ca.anchor_pin,
            &local_origin,
            Some(ip.into()),
            clock,
        )
        .unwrap();
        (ca, leaf, DevicePrivateKey::generate_rsa3072().unwrap())
    })
    .await
    .unwrap();
    let tls = GatewayClientTls::from_pinned_ca_pem(
        &ca.certificate_pem,
        ca.anchor_pin,
        Some(leaf.leaf_pin.clone()),
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
    let root = std::env::current_dir()
        .unwrap()
        .join("target")
        .join(format!("gateway-lan-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let admin = "a".repeat(43);
    let model = "m".repeat(43);
    let mut service = EnrollmentService::recover_existing(
        fresh_store(&root.join("store")),
        admin.as_bytes(),
        Sha256Digest::of_bytes(model.as_bytes()),
        vec![local_host.clone()],
        Limits::default(),
    )
    .unwrap();
    service.allow_remote_host(lan_host.clone()).unwrap();
    let shared = SharedEnrollment::new(service);
    let partition = Arc::new(Semaphore::new(styx_contracts::HOST_QUEUED_BYTES));
    let relay = RelayHandle::new(
        shared.clone(),
        GatewayId::try_from("lan-test-gateway").unwrap(),
        GatewayEpoch::try_from("lan-test-epoch").unwrap(),
        partition
            .clone()
            .try_acquire_many_owned(16 * 1024 * 1024)
            .unwrap(),
    )
    .unwrap();
    let backend = Arc::new(PairedGatewayBackend::new(relay.clone(), None));
    let policy = Arc::new(
        GatewayBearerPolicy::new(model.as_bytes(), vec![local_host.clone()], vec![]).unwrap(),
    );
    let mcp = GatewayHttp::new(
        policy,
        backend,
        HttpBudget::from_reserved_partition(
            partition.try_acquire_many_owned(32 * 1024 * 1024).unwrap(),
        )
        .unwrap(),
    );
    let app = EnrollmentHttp::new_paired(
        server_tls,
        shared,
        relay.clone(),
        mcp,
        vec![local_host.clone()],
    )
    .unwrap();
    let stop = CancellationToken::new();
    let server_app = app.clone();
    let server_stop = stop.clone();
    let server = tokio::spawn(async move {
        server_app
            .run_with_lan(local_listener, Some((lan_listener, lan_host)), server_stop)
            .await
    });
    let host = lan.to_string();
    // Even genuine administrator/model credentials cannot reach LAN control.
    for path in [
        "/mcp",
        "/styx/enroll/invitations",
        "/styx/enroll/approve",
        "/styx/enroll/revoke",
        "/styx/enroll/pending",
        "/control",
    ] {
        for bearer in [&admin, &model] {
            assert_eq!(
                request(
                    &tls,
                    lan,
                    &host,
                    Method::POST,
                    path,
                    Some(bearer),
                    json!({})
                )
                .await
                .0,
                404,
                "{path}"
            );
        }
    }
    assert_eq!(
        request(
            &tls,
            local,
            &local_host,
            Method::GET,
            "/mcp",
            None,
            Value::Null
        )
        .await
        .0,
        401
    );
    assert_eq!(
        request(
            &tls,
            local,
            &host,
            Method::POST,
            "/styx/enroll/join",
            None,
            json!({})
        )
        .await
        .0,
        403
    );
    assert_eq!(
        request(
            &tls,
            lan,
            &local_host,
            Method::POST,
            "/styx/enroll/join",
            None,
            json!({})
        )
        .await
        .0,
        403
    );
    let (status, invitation, _) = request(
        &tls,
        local,
        &local_host,
        Method::POST,
        "/styx/enroll/invitations",
        Some(&admin),
        json!({"ttl_seconds":600}),
    )
    .await;
    assert_eq!(status, 200);
    let device = DeviceId::try_from("styx-0123456789abcdef01234567").unwrap();
    let payload = JoinPayload {
        invitation: invitation["invitation"].as_str().unwrap().into(),
        device_id: device.clone(),
        label: "LAN Host".into(),
        platform: "linux".into(),
        cwd: root.to_str().unwrap().into(),
        shell: "/bin/sh".into(),
        computer_requested: false,
        browser_requested: Some(false),
        public_key_pem: identity.public_key_pem().into(),
    };
    let signature = URL_SAFE_NO_PAD.encode(
        identity
            .private_key()
            .sign(DeviceProofBytes::from_canonical_bytes(
                &payload.signing_bytes().unwrap(),
            ))
            .unwrap(),
    );
    let mut join = serde_json::to_value(payload).unwrap();
    join["signature"] = json!(signature);
    let (status, joined, observed_leaf) = request(
        &tls,
        lan,
        &host,
        Method::POST,
        "/styx/enroll/join",
        None,
        join,
    )
    .await;
    assert_eq!(status, 202);
    assert_eq!(joined["ingress"]["origin"], lan_origin);
    let comparison = PairingComparison {
        gateway_origin: lan_origin,
        certificate_sha256: Sha256Digest::try_from(observed_leaf.as_hex()).unwrap(),
        request_id: joined["request_id"].as_str().unwrap().into(),
        device_fingerprint: serde_json::from_value(joined["fingerprint"].clone()).unwrap(),
    }
    .comparison_code()
    .unwrap();
    assert_eq!(joined["comparison_code"], comparison);
    let pending = request(
        &tls,
        local,
        &local_host,
        Method::GET,
        "/styx/enroll/pending",
        Some(&admin),
        Value::Null,
    )
    .await;
    assert_eq!(pending.0, 200);
    assert_eq!(pending.1[0]["comparison_code"], comparison);
    let approved = request(&tls, local, &local_host, Method::POST, "/styx/enroll/approve", Some(&admin), json!({"request_id":joined["request_id"],"fingerprint":joined["fingerprint"],"enable_computer":false,"enable_browser":false})).await;
    assert_eq!(approved.0, 200);
    let claim_body =
        json!({"request_id":joined["request_id"],"claim_secret":joined["claim_secret"]});
    let claimed = request(
        &tls,
        lan,
        &host,
        Method::POST,
        "/styx/enroll/claim",
        None,
        claim_body.clone(),
    )
    .await;
    assert_eq!(claimed.0, 200);
    let credential = identity
        .private_key()
        .unwrap_credential(
            &URL_SAFE_NO_PAD
                .decode(claimed.1["encrypted_credential"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
    let confirmation = ClaimCapability::from_legacy_token_bytes(&credential)
        .unwrap()
        .confirm(&EnrollmentRequestId::parse(joined["request_id"].as_str().unwrap()).unwrap())
        .to_hex();
    let mut confirm = claim_body;
    confirm["confirmation"] = json!(confirmation);
    assert_eq!(
        request(
            &tls,
            lan,
            &host,
            Method::POST,
            "/styx/enroll/confirm",
            None,
            confirm
        )
        .await
        .0,
        200
    );
    assert_eq!(
        request(
            &tls,
            lan,
            &host,
            Method::GET,
            &format!("/styx/enroll/self/{}/capabilities", device.as_str()),
            Some(std::str::from_utf8(&credential).unwrap()),
            Value::Null
        )
        .await
        .0,
        200
    );
    let endpoint = LinkEndpoint::parse(&format!(
        "wss://{host}/styx/host/v3/{}/exec",
        device.as_str()
    ))
    .unwrap();
    let link_budget = HostLinkBudget::from_reserved_partition(
        Arc::new(Semaphore::new(16 * 1024 * 1024))
            .try_acquire_many_owned(16 * 1024 * 1024)
            .unwrap(),
    )
    .unwrap();
    let wrong = SecretBearer::from_protected_reader("w".repeat(43)).unwrap();
    let attempt = HostWssLink::connect(
        &endpoint,
        &tls,
        TcpStream::connect(lan).await.unwrap(),
        LinkAuthentication::Bearer(&wrong),
        ConnectionGeneration::try_from("wrong-credential").unwrap(),
        link_budget.clone(),
    )
    .await;
    assert!(matches!(
        attempt,
        Err(crate::host::link::LinkError::UpgradeStatus(403))
    ));
    let bearer =
        SecretBearer::from_protected_reader(std::str::from_utf8(&credential).unwrap().into())
            .unwrap();
    // Recover by reconnecting with the same credential after an observed close.
    for attempt in 0..2 {
        let generation =
            ConnectionGeneration::try_from(format!("lan-host-connection-{attempt}")).unwrap();
        let mut link = HostWssLink::connect(
            &endpoint,
            &tls,
            TcpStream::connect(lan).await.unwrap(),
            LinkAuthentication::Bearer(&bearer),
            generation.clone(),
            link_budget.clone(),
        )
        .await
        .unwrap();
        let incoming = tokio::time::timeout(Duration::from_secs(5), link.recv())
            .await
            .unwrap()
            .unwrap();
        let negotiate: wire::Request = serde_json::from_str(incoming.as_str()).unwrap();
        let wire::Call::Negotiate { challenge, .. } = negotiate.call else {
            panic!("negotiate required")
        };
        let response = wire::Response {
            request_id: negotiate.request_id,
            connection_generation: generation.clone(),
            reply: wire::Reply::Negotiated {
                version: 3,
                challenge,
                device_id: device.clone(),
                host_generation: HostGeneration::try_from("lan-host-generation").unwrap(),
                connection_generation: generation,
                features: [
                    "owner_open",
                    "owner_revoke",
                    "owner_cleanup",
                    "prepare_start",
                    "dispatch_start",
                    "inspect_start",
                    "read",
                    "prepare_action",
                    "dispatch_action",
                    "inspect_action",
                ]
                .into_iter()
                .map(str::to_owned)
                .collect(),
                write: true,
                terminate: true,
                read_resume: false,
                owner_issuance: "gateway_authenticated".into(),
                grant_revision: Some(1),
            },
        };
        link.send_text(
            serde_json::to_string(&response).unwrap(),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        let until = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if relay
                .devices()
                .await
                .unwrap()
                .iter()
                .any(|device| device.online)
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < until,
                "independent Gateway registry must observe connected Host"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        link.shutdown(Duration::from_secs(5)).await.unwrap();
        let until = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if relay
                .devices()
                .await
                .unwrap()
                .iter()
                .all(|device| !device.online)
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < until,
                "closed Host must leave the live registry before reconnect"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    stop.cancel();
    let facts = tokio::time::timeout(Duration::from_secs(20), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(facts.connections_joined && facts.blocking_jobs_joined);
    assert!(!facts.worker_failure_observed && !facts.listener_error_observed);
    drop(app);
    drop(relay);
    std::fs::remove_dir_all(root).unwrap();
}
