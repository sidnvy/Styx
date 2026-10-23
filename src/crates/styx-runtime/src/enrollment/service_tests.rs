//! Actual TLS/HTTP/Core/private journal + independent Node crypto. Synthetic
//! owned identities only; Core transport leases are NOT a Host WSS/Exec proof.
#![cfg(all(target_os = "linux", target_env = "gnu"))]
use super::*;
use crate::{
    enrollment::http::{EnrollmentHttp, ShutdownFacts},
    store::{
        PrivateRoot,
        enrollment::{EnrollmentJournal, JournalBudget},
    },
    tls::{GatewayClientTls, GatewayLeafPin, GatewayServerTls, PrivateKeyPem, TrustAnchorPin},
};
use bytes::Bytes;
use futures_util::StreamExt;
use http::{
    Request,
    header::{CONNECTION, CONTENT_TYPE},
};
use http_body_util::{BodyExt, Full, Limited};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    process::{Child, ChildStdin, ChildStdout},
    sync::Mutex,
    task::JoinHandle,
};
use tokio_util::{
    codec::{FramedRead, LinesCodec},
    sync::CancellationToken,
};

pub(super) struct SecretText(Zeroizing<String>);
impl SecretText {
    pub(super) fn expose(&self) -> &str {
        &self.0
    }
}
impl std::fmt::Debug for SecretText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretText([redacted])")
    }
}
impl<'de> Deserialize<'de> for SecretText {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(|s| Self(Zeroizing::new(s)))
    }
}
#[derive(Deserialize)]
pub(super) struct NodeHello {
    pub node: String,
    pub public_a: String,
    pub public_b: String,
    pub fingerprint_a: Sha256Digest,
    pub fingerprint_b: Sha256Digest,
}
#[derive(Deserialize)]
struct Envelope<T> {
    ok: bool,
    data: Option<T>,
}
#[derive(Deserialize)]
struct Signature {
    signature: String,
}
#[derive(Deserialize)]
struct Comparison {
    code: String,
}
#[derive(Deserialize)]
pub(super) struct Unwrapped {
    pub credential: SecretText,
    pub confirmation: String,
}
#[derive(Deserialize)]
struct Stopped {
    stopped: bool,
}
pub(super) struct NodeClient {
    child: Child,
    input: ChildStdin,
    output: FramedRead<BufReader<ChildStdout>, LinesCodec>,
    pub hello: NodeHello,
}
impl NodeClient {
    pub(super) async fn start() -> Self {
        let path = std::env::var("STYX_TEST_NODE22").expect("fixed Node22 required");
        let protocol =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../shared/enrollment-protocol.mjs");
        let mut child = tokio::process::Command::new(path)
            .args([
                "--input-type=module",
                "-e",
                include_str!("service_node.mjs"),
            ])
            .env("STYX_TEST_SERVICE_PROTOCOL", protocol)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut output = FramedRead::new(
            BufReader::new(stdout),
            LinesCodec::new_with_max_length(128 * 1024),
        );
        let line = Zeroizing::new(
            tokio::time::timeout(Duration::from_secs(30), output.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
        );
        let envelope: Envelope<NodeHello> =
            serde_json::from_str(&line).expect("public Node hello schema");
        assert!(envelope.ok);
        let hello = envelope.data.expect("Node hello");
        assert!(hello.node.starts_with("v22."));
        Self {
            child,
            input,
            output,
            hello,
        }
    }
    async fn call<T: Serialize, R: DeserializeOwned>(
        &mut self,
        request: &T,
    ) -> Result<R, &'static str> {
        let mut bytes =
            Zeroizing::new(serde_json::to_vec(request).map_err(|_| "request encoding")?);
        bytes.push(b'\n');
        tokio::time::timeout(Duration::from_secs(5), self.input.write_all(&bytes))
            .await
            .map_err(|_| "write deadline")?
            .map_err(|_| "write")?;
        let line = Zeroizing::new(
            tokio::time::timeout(Duration::from_secs(10), self.output.next())
                .await
                .map_err(|_| "reply deadline")?
                .ok_or("child EOF")?
                .map_err(|_| "bounded child frame")?,
        );
        let envelope: Envelope<R> = serde_json::from_str(&line).map_err(|_| "reply schema")?;
        if !envelope.ok {
            return Err("child proof operation refused");
        }
        envelope.data.ok_or("missing reply")
    }
    pub(super) async fn sign_join(&mut self, key: &str, payload: &JoinPayload) -> String {
        #[derive(Serialize)]
        struct Command<'a> {
            op: &'static str,
            key: &'a str,
            payload: &'a JoinPayload,
        }
        self.call::<_, Signature>(&Command {
            op: "sign_join",
            key,
            payload,
        })
        .await
        .unwrap()
        .signature
    }
    pub(super) async fn sign_capability(&mut self, key: &str, payload: &CapChange<'_>) -> String {
        #[derive(Serialize)]
        struct Command<'a, 'b> {
            op: &'static str,
            key: &'a str,
            payload: &'a CapChange<'b>,
        }
        self.call::<_, Signature>(&Command {
            op: "sign_capability",
            key,
            payload,
        })
        .await
        .unwrap()
        .signature
    }
    pub(super) async fn unwrap(
        &mut self,
        key: &str,
        ciphertext: &str,
        request_id: &str,
    ) -> Result<Unwrapped, &'static str> {
        #[derive(Serialize)]
        struct Command<'a> {
            op: &'static str,
            key: &'a str,
            ciphertext: &'a str,
            request_id: &'a str,
        }
        self.call(&Command {
            op: "unwrap",
            key,
            ciphertext,
            request_id,
        })
        .await
    }
    pub(super) async fn comparison(
        &mut self,
        origin: &str,
        leaf: Sha256Digest,
        request_id: &str,
        fingerprint: Sha256Digest,
    ) -> String {
        #[derive(Serialize)]
        struct Command<'a> {
            op: &'static str,
            origin: &'a str,
            certificate_sha256: Sha256Digest,
            request_id: &'a str,
            device_fingerprint: Sha256Digest,
        }
        self.call::<_, Comparison>(&Command {
            op: "comparison",
            origin,
            certificate_sha256: leaf,
            request_id,
            device_fingerprint: fingerprint,
        })
        .await
        .unwrap()
        .code
    }
    pub(super) async fn stop(&mut self) {
        #[derive(Serialize)]
        struct Command {
            op: &'static str,
        }
        let graceful =
            matches!(self.call::<_,Stopped>(&Command {op:"stop"}).await,Ok(reply) if reply.stopped);
        if graceful {
            let _ = self.input.shutdown().await;
        } else {
            let _ = self.child.start_kill();
        }
        let status = tokio::time::timeout(Duration::from_secs(5), self.child.wait())
            .await
            .unwrap()
            .unwrap();
        if graceful {
            assert!(status.success());
        }
        println!("ENROLLMENT_NODE_CLEANUP graceful={graceful} reaped=true");
    }
}
#[derive(Serialize)]
pub(super) struct CapChange<'a> {
    pub device_id: &'a DeviceId,
    pub fingerprint: Sha256Digest,
    pub generation: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_computer: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_browser: Option<bool>,
}
#[derive(Serialize)]
struct SignedJoin<'a> {
    #[serde(flatten)]
    payload: &'a JoinPayload,
    signature: &'a str,
}
#[derive(Serialize)]
struct SignedCap<'a, 'b> {
    #[serde(flatten)]
    payload: &'a CapChange<'b>,
    public_key_pem: &'a str,
    signature: &'a str,
}
#[derive(Serialize)]
struct ClaimRequest<'a> {
    request_id: &'a str,
    claim_secret: &'a str,
}
#[derive(Serialize)]
struct ConfirmRequest<'a> {
    request_id: &'a str,
    claim_secret: &'a str,
    confirmation: &'a str,
}
#[derive(Deserialize)]
struct InvitationReply {
    invitation: SecretText,
}
#[derive(Deserialize)]
struct Joined {
    request_id: String,
    claim_secret: SecretText,
    fingerprint: Sha256Digest,
    comparison_code: String,
}
#[derive(Deserialize)]
struct Claimed {
    encrypted_credential: String,
}
#[derive(Deserialize)]
struct PendingSummary {
    request_id: String,
    fingerprint: Sha256Digest,
    comparison_code: String,
}
#[derive(Deserialize)]
struct Connections {
    exec: String,
    computer: String,
    browser: String,
}
#[derive(Deserialize)]
struct SelfReply {
    device_id: DeviceId,
    fingerprint: Sha256Digest,
    generation: String,
    connections: Connections,
}
#[derive(Deserialize)]
struct CasReply {
    generation: String,
}
fn encoded<T: Serialize>(v: &T) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(serde_json::to_vec(v).unwrap())
}
struct HttpReply {
    status: u16,
    body: Zeroizing<Vec<u8>>,
    leaf: Sha256Digest,
}
impl HttpReply {
    fn decode<T: DeserializeOwned>(&self) -> T {
        serde_json::from_slice(&self.body).expect("bounded expected response schema")
    }
}
#[derive(Clone)]
struct Client {
    tls: Arc<GatewayClientTls>,
    address: SocketAddr,
    host: String,
}
impl Client {
    async fn request(
        &self,
        method: Method,
        path: &str,
        bearer: Option<&str>,
        body: &[u8],
    ) -> HttpReply {
        let tcp = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(self.address))
            .await
            .unwrap()
            .unwrap();
        let tls = self
            .tls
            .connect("localhost", tcp, Duration::from_secs(5))
            .await
            .unwrap();
        let peer = tls
            .get_ref()
            .1
            .peer_certificates()
            .unwrap()
            .first()
            .unwrap();
        let leaf = Sha256Digest::of_bytes(peer.as_ref());
        let (mut sender, connection) = hyper::client::conn::http1::handshake::<_, Full<Bytes>>(
            hyper_util::rt::TokioIo::new(tls),
        )
        .await
        .unwrap();
        let driver = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(connection));
        let mut request = Request::builder()
            .method(method.clone())
            .uri(path)
            .header(HOST, &self.host)
            .header(CONNECTION, "close");
        if method == Method::POST {
            request = request.header(CONTENT_TYPE, "application/json");
        }
        if let Some(token) = bearer {
            request = request.header(AUTHORIZATION, format!("Bearer {token}"));
        }
        let response = tokio::time::timeout(
            Duration::from_secs(30),
            sender.send_request(
                request
                    .body(Full::new(Bytes::copy_from_slice(body)))
                    .unwrap(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        let status = response.status().as_u16();
        let bytes = tokio::time::timeout(
            Duration::from_secs(5),
            Limited::new(response.into_body(), 1024 * 1024).collect(),
        )
        .await
        .unwrap()
        .unwrap()
        .to_bytes();
        drop(sender);
        tokio::time::timeout(Duration::from_secs(5), driver)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        HttpReply {
            status,
            body: Zeroizing::new(bytes.to_vec()),
            leaf,
        }
    }
}
struct Running {
    _app: Arc<EnrollmentHttp>,
    cancel: CancellationToken,
    job: JoinHandle<Result<ShutdownFacts, crate::enrollment::http::HttpError>>,
}
type ServerOwner = Arc<Mutex<Option<Running>>>;
async fn stop_server(owner: &ServerOwner) -> Option<ShutdownFacts> {
    let mut guard = owner.lock().await;
    let active = guard.as_mut()?;
    active.cancel.cancel();
    let facts = tokio::time::timeout(Duration::from_secs(15), &mut active.job)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let removed = guard.take();
    drop(removed);
    Some(facts)
}
fn assert_joined(facts: &ShutdownFacts) {
    assert!(
        facts.connections_joined && facts.blocking_jobs_joined && !facts.worker_failure_observed
    );
    assert_eq!(facts.blocking_slots_in_use, 0);
}
fn now() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}
pub(super) fn fresh_store(path: &Path) -> OwnedEnrollmentJournal {
    assert!(!path.exists(), "fresh test root must not preexist");
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = PrivateRoot::open(path).unwrap();
    let mut writer = root.try_configuration_writer().unwrap();
    {
        let mut journal =
            EnrollmentJournal::open(&root, &mut writer, JournalBudget::default()).unwrap();
        journal.record_time_floor(now()).unwrap();
    }
    OwnedEnrollmentJournal::open_existing(root, writer, JournalBudget::default()).unwrap()
}
fn reopen_store(path: &Path) -> OwnedEnrollmentJournal {
    let root = PrivateRoot::open(path).unwrap();
    let writer = root.try_configuration_writer().unwrap();
    OwnedEnrollmentJournal::open_existing(root, writer, JournalBudget::default()).unwrap()
}
async fn start_server(
    owner: &ServerOwner,
    store: OwnedEnrollmentJournal,
    tls: Arc<GatewayServerTls>,
    client_tls: Arc<GatewayClientTls>,
    admin: &[u8],
    mcp: Sha256Digest,
) -> (Client, Arc<EnrollmentHttp>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let host = format!("localhost:{}", address.port());
    let service = EnrollmentService::recover_existing(
        store,
        admin,
        mcp,
        vec![host.clone()],
        Limits::default(),
    )
    .unwrap();
    let app = EnrollmentHttp::new(tls, service, vec![host.clone()]).unwrap();
    let cancel = CancellationToken::new();
    let server = app.clone();
    let stop = cancel.clone();
    let job = tokio::spawn(async move { server.run(listener, stop).await });
    *owner.lock().await = Some(Running {
        _app: app.clone(),
        cancel,
        job,
    });
    (
        Client {
            tls: client_tls,
            address,
            host,
        },
        app,
    )
}
fn committed(app: &EnrollmentHttp) -> usize {
    app.with_service(|service| {
        service.store.with_journal(|journal| {
            Ok(journal
                .scan()?
                .files
                .iter()
                .filter(|f| f.name.ends_with(".committed"))
                .count())
        })
    })
    .unwrap()
}
fn random_token() -> Zeroizing<String> {
    let mut raw = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *raw).unwrap();
    Zeroizing::new(URL_SAFE_NO_PAD.encode(raw.as_slice()))
}

/// New complete enrollment authority scene only. No old crypto/profile batch
/// is repeated, and no Host WSS/Codex/native package claim is manufactured.
#[tokio::test]
#[ignore = "requires STYX_TEST_ENROLLMENT_SERVICE_ROOT, STYX_TEST_TLS_FIXTURES and STYX_TEST_NODE22; actual owned TLS enrollment journey"]
async fn actual_strict_tls_enrollment_service_full_journey() {
    use zeroize::Zeroize;
    let parent = PathBuf::from(
        std::env::var("STYX_TEST_ENROLLMENT_SERVICE_ROOT").expect("owned service fixture root"),
    );
    std::fs::create_dir_all(&parent).unwrap();
    let path = parent.join(uuid::Uuid::new_v4().to_string());
    let fixture = PathBuf::from(
        std::env::var("STYX_TEST_TLS_FIXTURES").expect("owned TLS fixture directory"),
    );
    let cert = std::fs::read(fixture.join("cert-a.pem")).unwrap();
    let ca = std::fs::read(fixture.join("ca-a.pem")).unwrap();
    let leaf_der = rustls_pemfile::certs(&mut std::io::Cursor::new(&cert))
        .next()
        .unwrap()
        .unwrap();
    let ca_der = rustls_pemfile::certs(&mut std::io::Cursor::new(&ca))
        .next()
        .unwrap()
        .unwrap();
    let leaf = GatewayLeafPin::from_certificate_der(leaf_der.as_ref());
    let anchor = TrustAnchorPin::from_certificate_der(ca_der.as_ref());
    let key = PrivateKeyPem::from_protected_reader_bytes(
        std::fs::read(fixture.join("key-a.pem")).unwrap(),
    )
    .unwrap();
    let tls = Arc::new(GatewayServerTls::from_pem(&cert, &key, leaf.clone()).unwrap());
    drop(key);
    let client_tls =
        Arc::new(GatewayClientTls::from_pinned_ca_pem(&ca, anchor, Some(leaf)).unwrap());
    let node = Arc::new(Mutex::new(NodeClient::start().await));
    let owner: ServerOwner = Arc::new(Mutex::new(None));
    let worker_node = node.clone();
    let worker_owner = owner.clone();
    let worker = tokio::spawn(async move {
        let admin = random_token();
        let mcp = random_token();
        let mcp_digest = Sha256Digest::of_bytes(mcp.as_bytes());
        let (client, app) = start_server(
            &worker_owner,
            fresh_store(&path),
            tls.clone(),
            client_tls.clone(),
            admin.as_bytes(),
            mcp_digest,
        )
        .await;
        let invitations = "/styx/enroll/invitations";
        assert_eq!(
            client
                .request(Method::POST, invitations, Some(&mcp), b"{}")
                .await
                .status,
            401,
            "ordinary MCP bearer cannot administer enrollment"
        );
        assert_eq!(
            client
                .request(Method::POST, "/styx/enroll/join", Some(&admin), b"{}")
                .await
                .status,
            401,
            "public proof route rejects unexpected Authorization"
        );
        let wrong = random_token();
        assert_eq!(
            client
                .request(Method::GET, "/styx/enroll/pending", Some(&wrong), b"")
                .await
                .status,
            401
        );
        let invitation_reply = client
            .request(Method::POST, invitations, Some(&admin), b"{}")
            .await;
        assert_eq!(invitation_reply.status, 200);
        let invitation: InvitationReply = invitation_reply.decode();
        let (public_a, public_b, fingerprint_a, fingerprint_b) = {
            let node = worker_node.lock().await;
            (
                node.hello.public_a.clone(),
                node.hello.public_b.clone(),
                node.hello.fingerprint_a,
                node.hello.fingerprint_b,
            )
        };
        assert!(public_a != public_b, "independent child device keys differ");
        let device = DeviceId::try_from("styx-0123456789abcdef01234567").unwrap();
        let mut payload = JoinPayload {
            invitation: invitation.invitation.expose().to_owned(),
            device_id: device.clone(),
            label: "Owned headless enrollment".into(),
            platform: "linux".into(),
            cwd: "/tmp".into(),
            shell: "/bin/sh".into(),
            computer_requested: true,
            browser_requested: Some(true),
            public_key_pem: public_a.clone(),
        };
        let signature = worker_node.lock().await.sign_join("a", &payload).await;
        let wire = encoded(&SignedJoin {
            payload: &payload,
            signature: &signature,
        });
        let joined_reply = client
            .request(Method::POST, "/styx/enroll/join", None, &wire)
            .await;
        assert_eq!(joined_reply.status, 202);
        payload.invitation.zeroize();
        drop(wire);
        let joined: Joined = joined_reply.decode();
        assert_eq!(joined.fingerprint, fingerprint_a);
        let comparison = worker_node
            .lock()
            .await
            .comparison(
                &format!("https://{}", client.host),
                joined_reply.leaf,
                &joined.request_id,
                fingerprint_a,
            )
            .await;
        assert_eq!(
            comparison, joined.comparison_code,
            "independent client code uses observed TLS leaf, not CA pin"
        );
        let claim = ClaimRequest {
            request_id: &joined.request_id,
            claim_secret: joined.claim_secret.expose(),
        };
        assert_eq!(
            client
                .request(Method::POST, "/styx/enroll/claim", None, &encoded(&claim))
                .await
                .status,
            202
        );
        let pending_reply = client
            .request(Method::GET, "/styx/enroll/pending", Some(&admin), b"")
            .await;
        assert_eq!(pending_reply.status, 200);
        let pending: Vec<PendingSummary> = pending_reply.decode();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].request_id, joined.request_id);
        assert_eq!(pending[0].fingerprint, fingerprint_a);
        assert_eq!(pending[0].comparison_code, comparison);
        let wrong_approval = encoded(
            &json!({"request_id":joined.request_id,"fingerprint":fingerprint_b,"enable_computer":true,"enable_browser":true}),
        );
        assert_eq!(
            client
                .request(
                    Method::POST,
                    "/styx/enroll/approve",
                    Some(&admin),
                    &wrong_approval
                )
                .await
                .status,
            403,
            "wrong original key cannot be approved"
        );
        let approval = encoded(
            &json!({"request_id":joined.request_id,"fingerprint":fingerprint_a,"enable_computer":true,"enable_browser":true}),
        );
        assert_eq!(
            client
                .request(Method::POST, "/styx/enroll/approve", Some(&mcp), &approval)
                .await
                .status,
            401
        );
        assert_eq!(
            client
                .request(
                    Method::POST,
                    "/styx/enroll/approve",
                    Some(&admin),
                    &approval
                )
                .await
                .status,
            200
        );
        let first = client
            .request(Method::POST, "/styx/enroll/claim", None, &encoded(&claim))
            .await;
        assert_eq!(first.status, 200);
        let first: Claimed = first.decode();
        let second = client
            .request(Method::POST, "/styx/enroll/claim", None, &encoded(&claim))
            .await;
        assert_eq!(second.status, 200);
        let second: Claimed = second.decode();
        assert!(
            first.encrypted_credential == second.encrypted_credential,
            "claim retry preserves exact original sealed credential"
        );
        assert!(
            worker_node
                .lock()
                .await
                .unwrap("b", &first.encrypted_credential, &joined.request_id)
                .await
                .is_err(),
            "wrong device key cannot unwrap the actual credential"
        );
        let credential = worker_node
            .lock()
            .await
            .unwrap("a", &first.encrypted_credential, &joined.request_id)
            .await
            .unwrap();
        let credential_hash = Sha256Digest::of_bytes(credential.credential.expose().as_bytes());
        let wrong_confirmation = "0".repeat(64);
        let bad = ConfirmRequest {
            request_id: &joined.request_id,
            claim_secret: joined.claim_secret.expose(),
            confirmation: &wrong_confirmation,
        };
        assert_eq!(
            client
                .request(Method::POST, "/styx/enroll/confirm", None, &encoded(&bad))
                .await
                .status,
            403
        );
        let confirm = ConfirmRequest {
            request_id: &joined.request_id,
            claim_secret: joined.claim_secret.expose(),
            confirmation: &credential.confirmation,
        };
        assert_eq!(
            client
                .request(
                    Method::POST,
                    "/styx/enroll/confirm",
                    None,
                    &encoded(&confirm)
                )
                .await
                .status,
            200
        );
        let after_confirm = committed(&app);
        assert_eq!(
            client
                .request(
                    Method::POST,
                    "/styx/enroll/confirm",
                    None,
                    &encoded(&confirm)
                )
                .await
                .status,
            200
        );
        assert_eq!(
            committed(&app),
            after_confirm,
            "lost confirm ACK retry does not create another transaction/credential"
        );
        let self_path = format!("/styx/enroll/self/{}/capabilities", device.as_str());
        assert_eq!(
            client
                .request(Method::GET, &self_path, Some(&wrong), b"")
                .await
                .status,
            403
        );
        assert_eq!(
            client
                .request(
                    Method::GET,
                    "/styx/enroll/self/styx-1123456789abcdef01234567/capabilities",
                    Some(credential.credential.expose()),
                    b""
                )
                .await
                .status,
            403
        );
        let own = client
            .request(
                Method::GET,
                &self_path,
                Some(credential.credential.expose()),
                b"",
            )
            .await;
        assert_eq!(own.status, 200);
        let own: SelfReply = own.decode();
        assert_eq!(own.device_id, device);
        assert_eq!(own.fingerprint, fingerprint_a);
        let stale = CapChange {
            device_id: &device,
            fingerprint: fingerprint_a,
            generation: "stale-generation",
            enable_computer: Some(false),
            enable_browser: None,
        };
        let stale_sig = worker_node.lock().await.sign_capability("a", &stale).await;
        assert_eq!(
            client
                .request(
                    Method::POST,
                    &self_path,
                    Some(credential.credential.expose()),
                    &encoded(&SignedCap {
                        payload: &stale,
                        public_key_pem: &public_a,
                        signature: &stale_sig
                    })
                )
                .await
                .status,
            409
        );
        let computer = CapChange {
            device_id: &device,
            fingerprint: fingerprint_a,
            generation: &own.generation,
            enable_computer: Some(false),
            enable_browser: None,
        };
        let wrong_sig = worker_node
            .lock()
            .await
            .sign_capability("b", &computer)
            .await;
        assert_eq!(
            client
                .request(
                    Method::POST,
                    &self_path,
                    Some(credential.credential.expose()),
                    &encoded(&SignedCap {
                        payload: &computer,
                        public_key_pem: &public_a,
                        signature: &wrong_sig
                    })
                )
                .await
                .status,
            403
        );
        // Real service/Core connection admission, explicitly NOT Host WSS.
        let lease = app
            .with_service(|service| {
                service.admit_host(
                    &device,
                    credential.credential.expose().as_bytes(),
                    Lane::Exec,
                    ConnectionGeneration::try_from("owned-core-transport-lease").unwrap(),
                )
            })
            .unwrap();
        assert!(
            app.with_service(|service| service.authorize_host_frame(&lease))
                .is_ok()
        );
        let connected_browser = CapChange {
            device_id: &device,
            fingerprint: fingerprint_a,
            generation: &own.generation,
            enable_computer: None,
            enable_browser: Some(false),
        };
        let connected_sig = worker_node
            .lock()
            .await
            .sign_capability("a", &connected_browser)
            .await;
        assert_eq!(
            client
                .request(
                    Method::POST,
                    &self_path,
                    Some(credential.credential.expose()),
                    &encoded(&SignedCap {
                        payload: &connected_browser,
                        public_key_pem: &public_a,
                        signature: &connected_sig
                    })
                )
                .await
                .status,
            409
        );
        let computer_sig = worker_node
            .lock()
            .await
            .sign_capability("a", &computer)
            .await;
        let changed = client
            .request(
                Method::POST,
                &self_path,
                Some(credential.credential.expose()),
                &encoded(&SignedCap {
                    payload: &computer,
                    public_key_pem: &public_a,
                    signature: &computer_sig,
                }),
            )
            .await;
        assert_eq!(changed.status, 200);
        let changed: CasReply = changed.decode();
        assert_ne!(changed.generation, own.generation);
        assert!(
            app.with_service(|service| service.authorize_host_frame(&lease))
                .is_err(),
            "committed CAS fences old Core lease before async disconnect"
        );
        app.with_service(|service| service.host_connection_ended(lease, true))
            .unwrap();
        let browser = CapChange {
            device_id: &device,
            fingerprint: fingerprint_a,
            generation: &changed.generation,
            enable_computer: None,
            enable_browser: Some(false),
        };
        let browser_sig = worker_node
            .lock()
            .await
            .sign_capability("a", &browser)
            .await;
        let changed = client
            .request(
                Method::POST,
                &self_path,
                Some(credential.credential.expose()),
                &encoded(&SignedCap {
                    payload: &browser,
                    public_key_pem: &public_a,
                    signature: &browser_sig,
                }),
            )
            .await;
        assert_eq!(changed.status, 200);
        let changed: CasReply = changed.decode();
        let active = app.wait_for_blocking(Duration::from_millis(50)).await;
        assert!(
            !active.blocking_jobs_joined,
            "active transport is not a worker join proof"
        );
        drop(app);
        let first_shutdown = stop_server(&worker_owner).await.unwrap();
        assert_joined(&first_shutdown);
        // Reopening the actual same writer is an independent exclusion oracle.
        let reopened = reopen_store(&path);
        let (client, app) = start_server(
            &worker_owner,
            reopened,
            tls,
            client_tls,
            admin.as_bytes(),
            mcp_digest,
        )
        .await;
        assert_eq!(
            client
                .request(
                    Method::POST,
                    "/styx/enroll/confirm",
                    None,
                    &encoded(&confirm)
                )
                .await
                .status,
            200
        );
        let restored = client
            .request(
                Method::GET,
                &self_path,
                Some(credential.credential.expose()),
                b"",
            )
            .await;
        assert_eq!(restored.status, 200);
        let restored: SelfReply = restored.decode();
        assert_eq!(restored.generation, changed.generation);
        assert_eq!(restored.connections.exec, "unknown");
        assert_eq!(restored.connections.computer, "unknown");
        assert_eq!(restored.connections.browser, "unknown");
        let token_hash = app
            .with_service(|service| {
                service
                    .ledger
                    .authentication_target(&service.control, &device)
            })
            .unwrap()
            .credential_hash;
        assert_eq!(
            token_hash, credential_hash,
            "restart preserved original token bytes without re-pairing"
        );
        let after_restart_confirm = committed(&app);
        assert_eq!(
            client
                .request(
                    Method::POST,
                    "/styx/enroll/confirm",
                    None,
                    &encoded(&confirm)
                )
                .await
                .status,
            200
        );
        assert_eq!(committed(&app), after_restart_confirm);
        let unknown_browser = CapChange {
            device_id: &device,
            fingerprint: fingerprint_a,
            generation: &restored.generation,
            enable_computer: None,
            enable_browser: Some(true),
        };
        let unknown_sig = worker_node
            .lock()
            .await
            .sign_capability("a", &unknown_browser)
            .await;
        assert_eq!(
            client
                .request(
                    Method::POST,
                    &self_path,
                    Some(credential.credential.expose()),
                    &encoded(&SignedCap {
                        payload: &unknown_browser,
                        public_key_pem: &public_a,
                        signature: &unknown_sig
                    })
                )
                .await
                .status,
            409,
            "recovery does not fabricate Offline lanes to approve browser change"
        );
        assert_eq!(
            client
                .request(
                    Method::POST,
                    "/styx/enroll/revoke",
                    Some(&admin),
                    &encoded(&json!({"device_id":device}))
                )
                .await
                .status,
            200
        );
        assert_eq!(
            client
                .request(
                    Method::GET,
                    &self_path,
                    Some(credential.credential.expose()),
                    b""
                )
                .await
                .status,
            403
        );
        assert!(
            app.with_service(|service| service.admit_host(
                &device,
                credential.credential.expose().as_bytes(),
                Lane::Exec,
                ConnectionGeneration::try_from("revoked-resume").unwrap()
            ))
            .is_err()
        );
        println!(
            "ENROLLMENT_SERVICE_OBSERVATION {}",
            json!({"root":path,"device":device,"fingerprint":fingerprint_a,"request":joined.request_id,"strictTLS":true,"independentActualLeafComparison":true,"sameSealedCredentialOnClaimRetry":true,"wrongDeviceKeyUnwrapRejected":true,"lostConfirmReplyRetryNoNewTransaction":true,"sameTokenAfterRealStoreRestart":true,"oldCoreLeaseFenced":true,"restartLanesUnknown":true,"revocationDeniedOldCredential":true,"hostWss":"NOT_RUN","realExecNonce":"NOT_RUN","nativePackage":"NOT_RUN","A05Complete":false})
        );
    });
    let outcome = worker.await;
    if let Some(facts) = stop_server(&owner).await {
        println!("ENROLLMENT_HTTP_CLEANUP {facts:?}");
        assert_joined(&facts);
    }
    node.lock().await.stop().await;
    outcome.unwrap();
}
