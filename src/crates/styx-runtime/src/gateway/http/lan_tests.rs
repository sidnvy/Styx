//! Real TLS/enrollment/WebSocket on loopback plus an assigned private interface.
//! Synthetic identities; optional isolated executor, no installed device or account.
use super::*;
use crate::{
    crypto::{ClaimCapability, DevicePrivateKey, DeviceProofBytes, EnrollmentRequestId},
    enrollment::{http::EnrollmentHttp, service::EnrollmentService, shared::SharedEnrollment},
    gateway::paired::{PairedGatewayBackend, RelayHandle},
    host::{
        bootstrap::OwnedExecHost,
        link::{HostLinkBudget, HostWssLink, LinkAuthentication, LinkEndpoint, SecretBearer},
        protocol::{PairedTrustedProfile, wire},
    },
    store::{
        PrivateRoot,
        enrollment::{EnrollmentJournal, JournalBudget, OwnedEnrollmentJournal},
    },
    tls::{
        GatewayClientTls, GatewayLeafPin, GatewayServerTls, generate_gateway_ca,
        issue_server_leaf_with_lan_addresses,
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
    capability::{Authorization, Availability, CapabilityDescriptor, CapabilityId, Scope},
    error::Recovery,
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
#[ignore = "requires sockets, assigned private IPv4 and STYX_TEST_CODEX; isolated owned executor"]
async fn gateway_two_listeners_lan_join_and_host_link_requires_sockets() {
    gateway_lan_scenario(vec![lan_ip()], true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires sockets and two assigned private IPv4s in STYX_TEST_LAN_ADDRESSES"]
async fn gateway_three_listeners_two_lan_addresses_join_and_host_link_requires_sockets() {
    let addresses: Vec<_> = std::env::var("STYX_TEST_LAN_ADDRESSES")
        .expect("set STYX_TEST_LAN_ADDRESSES to two assigned private IPv4s separated by a comma")
        .split(',')
        .map(str::to_owned)
        .collect();
    let ips = crate::gateway::auth::lan_addresses(true, None, Some(&addresses)).unwrap();
    assert_eq!(ips.len(), 2);
    gateway_lan_scenario(ips, false).await;
}

async fn gateway_lan_scenario(ips: Vec<Ipv4Addr>, owner_reopen: bool) {
    gateway_lan_scenario_inner(ips, owner_reopen, false).await;
}

async fn gateway_lan_scenario_inner(
    ips: Vec<Ipv4Addr>,
    owner_reopen: bool,
    computer_refusal: bool,
) {
    let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local = local_listener.local_addr().unwrap();
    let mut lan_listeners = Vec::new();
    let mut addresses = Vec::new();
    for ip in &ips {
        let address = SocketAddr::new(IpAddr::V4(*ip), local.port());
        let listener = TcpListener::bind(address)
            .await
            .expect("LAN address must be assigned locally");
        lan_listeners.push((listener, address.to_string()));
        addresses.push(address);
    }
    let lan = addresses[0];
    let local_host = local.to_string();
    let local_origin = format!("https://{local}");
    let lan_origin = format!("https://{lan}");
    let clock = now_ms() / 1000;
    let (ca, leaf, identity) = tokio::task::spawn_blocking(move || {
        let ca = generate_gateway_ca(clock, clock - 60, clock + 86400).unwrap();
        let leaf = issue_server_leaf_with_lan_addresses(
            &ca.certificate_pem,
            &ca.private_key,
            &ca.anchor_pin,
            &local_origin,
            &ips.into_iter().map(IpAddr::V4).collect::<Vec<_>>(),
            clock,
        )
        .unwrap();
        (ca, leaf, DevicePrivateKey::generate_rsa3072().unwrap())
    })
    .await
    .unwrap();
    let gateway_namespace = crate::tls::paired_gateway_namespace(&ca.anchor_pin);
    let ca_hash = Sha256Digest::try_from(ca.anchor_pin.as_hex()).unwrap();
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
    let root = std::env::temp_dir().join(format!("gateway-lan-{}", uuid::Uuid::new_v4()));
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
    for address in &addresses {
        service.allow_remote_host(address.to_string()).unwrap();
    }
    let shared = SharedEnrollment::new(service);
    let partition = Arc::new(Semaphore::new(styx_contracts::HOST_QUEUED_BYTES));
    let relay = RelayHandle::new(
        shared.clone(),
        gateway_namespace.clone(),
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
    let mut owner_headers = http::HeaderMap::new();
    owner_headers.insert(http::header::HOST, local_host.parse().unwrap());
    owner_headers.insert(
        http::header::AUTHORIZATION,
        format!("Bearer {model}").parse().unwrap(),
    );
    let principal = policy.authorize(&owner_headers).unwrap();
    let owner = principal.new_mcp_session_owner().unwrap();
    let unknown_owner = principal.new_mcp_session_owner().unwrap();
    let mcp = GatewayHttp::new(
        policy,
        backend.clone(),
        HttpBudget::from_reserved_partition(
            Arc::new(Semaphore::new(crate::gateway::http::GATEWAY_HTTP_BYTES))
                .try_acquire_many_owned(crate::gateway::http::GATEWAY_HTTP_BYTES as u32)
                .unwrap(),
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
            .run_with_lan_addresses(local_listener, lan_listeners, server_stop)
            .await
    });
    let host = lan.to_string();
    // Even genuine administrator/model credentials cannot reach LAN control.
    for address in &addresses {
        let host = address.to_string();
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
                        *address,
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
        computer_requested: computer_refusal,
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
    let approved = request(&tls, local, &local_host, Method::POST, "/styx/enroll/approve", Some(&admin), json!({"request_id":joined["request_id"],"fingerprint":joined["fingerprint"],"enable_computer":computer_refusal,"enable_browser":false})).await;
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
    for address in &addresses {
        let host = address.to_string();
        assert_eq!(
            request(
                &tls,
                *address,
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
    }
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
    let mut original_binding = None;
    let mut unknown_binding = None;
    for (attempt, lan) in addresses
        .iter()
        .cycle()
        .take(if computer_refusal {
            1
        } else if owner_reopen {
            3
        } else {
            2.max(addresses.len())
        })
        .enumerate()
    {
        let configured_origin = format!("https://{lan}");
        let (endpoint, namespace, profile_tls) =
            crate::foreground::profile::fresh_connection_profile(
                &configured_origin,
                &device,
                ca_hash,
                &ca.certificate_pem,
            )
            .unwrap();
        assert_eq!(namespace, gateway_namespace);
        // First reproduce the old origin-hash mismatch, then recover with the
        // real profile namespace. HTTP 101 alone must never imply connected.
        for old_origin_namespace in [true, false] {
            let host_generation =
                HostGeneration::try_from(format!("lan-host-generation-{attempt}")).unwrap();
            let reservation = OwnedExecHost::reserve(
                host_generation.clone(),
                styx_core::policy::AdmissionFacts {
                    device_id: device.clone(),
                    grant_revision: 1,
                    local_policy_allowed: true,
                    descriptor: CapabilityDescriptor {
                        contract_version: 1,
                        capability_id: CapabilityId::ExecRun,
                        scope: Scope::Host,
                        provider_id: "codex".try_into().unwrap(),
                        configured: owner_reopen && !old_origin_namespace,
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
                },
                2,
            )
            .unwrap();
            let host = if owner_reopen && !old_origin_namespace {
                let home = root.join(format!("codex-home-{attempt}"));
                std::fs::create_dir(&home).unwrap();
                reservation
                    .spawn(crate::providers::codex::OwnedExecutorConfig {
                        binary: std::env::var_os("STYX_TEST_CODEX")
                            .expect("set STYX_TEST_CODEX to an isolated Codex executor")
                            .into(),
                        cwd: root.clone(),
                        environment: BTreeMap::from([
                            ("PATH".into(), "/usr/bin:/bin".into()),
                            ("HOME".into(), root.display().to_string()),
                            ("CODEX_HOME".into(), home.display().to_string()),
                        ]),
                        rpc_timeout: Duration::from_secs(5),
                        retained_process_limit: 4,
                    })
                    .await
                    .unwrap()
            } else {
                reservation.without_executor().unwrap()
            };
            let host = Arc::new(host);
            #[cfg(target_os = "linux")]
            let computer_fixture = if computer_refusal && !old_origin_namespace {
                Some(computer_refusal_reference::Factory::new(host.coordinator(), &root).await)
            } else {
                None
            };
            #[cfg(target_os = "linux")]
            let protocol_computer = computer_fixture.clone();
            let namespace = if old_origin_namespace {
                format!(
                    "paired.{}",
                    Sha256Digest::of_bytes(configured_origin.as_bytes()).to_hex()
                )
                .try_into()
                .unwrap()
            } else {
                namespace.clone()
            };
            let protocol_host = host.clone();
            let profile = PairedTrustedProfile {
                endpoint: endpoint.as_str().to_owned(),
                gateway_namespace: namespace,
                device_id: device.clone(),
                host_generation: host_generation.clone(),
            };
            let mut link = HostWssLink::connect(
                &endpoint,
                &profile_tls,
                TcpStream::connect(lan).await.unwrap(),
                LinkAuthentication::Bearer(&bearer),
                ConnectionGeneration::try_from(format!(
                    "lan-host-{attempt}-{old_origin_namespace}"
                ))
                .unwrap(),
                host.link_budget(),
            )
            .await
            .unwrap();
            let host_stop = CancellationToken::new();
            let protocol_stop = host_stop.clone();
            let (ready, mut readiness) = tokio::sync::oneshot::channel();
            let mut protocol_job = tokio::spawn(async move {
                let protocol = protocol_host.paired_protocol(profile).unwrap();
                #[cfg(target_os = "linux")]
                let protocol = if let Some(factory) = protocol_computer {
                    protocol.with_computer_profiles(factory).unwrap()
                } else {
                    protocol
                };
                let result = protocol
                    .run_connection_with_readiness(&mut link, &protocol_stop, Some(ready))
                    .await;
                let shutdown = link.shutdown(Duration::from_secs(5)).await;
                (result, shutdown)
            });
            if old_origin_namespace {
                let (result, _) = tokio::time::timeout(Duration::from_secs(5), protocol_job)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    result,
                    Err(crate::host::protocol::ProtocolError::NegotiationRejected)
                );
                assert!(
                    readiness.try_recv().is_err(),
                    "rejected namespace cannot announce connected"
                );
            } else {
                tokio::select! {
                    result = tokio::time::timeout(Duration::from_secs(5), &mut readiness) => {
                        result.expect("bounded real Host connected readiness").expect("real negotiation and drain enable must succeed");
                    }
                    result = &mut protocol_job => panic!("Host ended before connected: {result:?}"),
                }
                let until = tokio::time::Instant::now() + Duration::from_secs(5);
                loop {
                    if relay.devices().await.unwrap().iter().any(|entry| {
                        entry.device_id == device
                            && entry.host_generation.as_ref() == Some(&host_generation)
                            && entry.grant_revision == Some(1)
                    }) {
                        break;
                    }
                    assert!(
                        tokio::time::Instant::now() < until,
                        "Gateway must independently observe negotiated Host"
                    );
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                #[cfg(target_os = "linux")]
                if let Some(factory) = computer_fixture {
                    computer_refusal_reference::exercise(
                        backend.clone(),
                        host.coordinator(),
                        factory,
                        &principal,
                        &owner,
                        &device,
                    )
                    .await;
                }
                if owner_reopen {
                    match attempt {
                        0 => {
                            original_binding = Some(relay.bind(&owner, &device).await.unwrap());
                        }
                        1 => {
                            let old = original_binding.as_ref().unwrap();
                            assert!(
                                old.physically_settled(),
                                "original cleanup must be proven before replacement"
                            );
                            let replacement = relay.bind(&owner, &device).await.expect(
                                "same owner can open a fresh binding after complete old drain",
                            );
                            assert!(replacement.owner_ref() != old.owner_ref());
                            assert_ne!(replacement.host_generation(), old.host_generation());
                            let old_frame = || wire::Call::PrepareStart {
                                owner: old.owner_ref(),
                                grant_revision: old.grant_revision(),
                                timeout_ms: 5000,
                                spec: serde_json::value::RawValue::from_string("{}".into())
                                    .unwrap(),
                            };
                            assert!(matches!(
                                relay.call(old, old_frame()).await,
                                Err(crate::gateway::paired::RelayError::Unauthorized)
                            ));
                            assert!(matches!(
                                relay.call(&replacement, old_frame()).await,
                                Err(crate::gateway::paired::RelayError::Unauthorized)
                            ));
                            unknown_binding =
                                Some(relay.bind(&unknown_owner, &device).await.unwrap());
                        }
                        2 => {
                            assert!(!unknown_binding.as_ref().unwrap().physically_settled());
                            assert!(
                                relay.bind(&unknown_owner, &device).await.is_err(),
                                "unknown old cleanup must not be replaced"
                            );
                        }
                        _ => unreachable!(),
                    }
                }
                if owner_reopen && attempt == 1 {
                    // Abrupt loss deliberately leaves both original owner cleanups unknown.
                    protocol_job.abort();
                    assert!(protocol_job.await.unwrap_err().is_cancelled());
                } else {
                    host_stop.cancel();
                    let (result, shutdown) =
                        tokio::time::timeout(Duration::from_secs(10), protocol_job)
                            .await
                            .unwrap()
                            .unwrap();
                    assert_eq!(result.unwrap(), Some(wire::TransportDrainOutcome::Complete));
                    shutdown.unwrap();
                }
            }
            host.shutdown_owned(Duration::from_secs(5)).await.unwrap();
        }
        let until = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if relay
                .devices()
                .await
                .unwrap()
                .iter()
                .all(|device| device.host_generation.is_none())
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

#[cfg(target_os = "linux")]
#[path = "computer_refusal_reference.rs"]
mod computer_refusal_reference;
