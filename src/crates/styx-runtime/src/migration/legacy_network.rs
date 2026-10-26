//! Fixed original-pair maintenance journey through the real TLS/MCP/WSS
//! adapters. No new pairing, ordinary activation, replay, or final commit.
use super::*;
use crate::{
    enrollment::{http::EnrollmentHttp, shared::SharedEnrollment},
    foreground::profile::LoadedMaintenanceProfile,
    gateway::{
        http::{GatewayHttp, HttpBudget},
        paired::{PairedGatewayBackend, RelayHandle},
    },
    host::{
        bootstrap::OwnedExecHost,
        link::{HostWssLink, LinkAuthentication, LinkEndpoint, SecretBearer},
        protocol::{PairedTrustedProfile, wire::TransportDrainOutcome},
    },
    providers::codex::TerminationEvidence,
    store::{
        ExecutionLeaseGuard, FileObservation, PrivateRoot,
        legacy_handoff::{AppliedNativeCutover, PreparedNativeCutover},
    },
};
use serde::Serialize;
use std::{io::Cursor, path::PathBuf, sync::Mutex};
use styx_contracts::{
    identity::{
        ConnectionGeneration, DeviceId, GatewayEpoch, HostGeneration, Sha256Digest, TransactionId,
    },
    native_management::NativeGatewayEndpointBinding,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Semaphore, oneshot},
};

/// Redacted observations only. This handle cannot authorize an operation.
#[derive(Clone, Serialize)]
pub(crate) struct NetworkValidationObservation {
    stage: &'static str,
    elapsed_millis: u64,
    failure_stage: Option<&'static str>,
    failure_kind: Option<&'static str>,
    negative_http: [Option<(u16, &'static str)>; 4],
    negative_wss: [Option<&'static str>; 4],
    cleanup: Option<NetworkCleanupObservation>,
}
#[derive(Clone, Serialize)]
struct NetworkCleanupObservation {
    mcp_connections_joined: bool,
    mcp_lifecycle_jobs_joined: bool,
    mcp_session_transports_joined: bool,
    unconfirmed_owner_cleanups: usize,
    unresolved_sessions: usize,
    protocol_joined: bool,
    link_closed: bool,
    remote_transport_drain: Option<TransportDrainOutcome>,
    server_joined: bool,
    server_connections_joined: bool,
    server_blocking_jobs_joined: bool,
    native_settled: bool,
    unconfirmed_transport_drains: usize,
}
#[derive(Clone)]
pub(crate) struct NetworkValidationObserver {
    state: Arc<Mutex<NetworkValidationObservation>>,
    started: std::time::Instant,
}
impl NetworkValidationObserver {
    pub(crate) fn new() -> Self {
        Self {
            started: std::time::Instant::now(),
            state: Arc::new(Mutex::new(NetworkValidationObservation {
                stage: "plan_binding",
                elapsed_millis: 0,
                failure_stage: None,
                failure_kind: None,
                negative_http: [None; 4],
                negative_wss: [None; 4],
                cleanup: None,
            })),
        }
    }
    pub(crate) fn snapshot(&self) -> Option<NetworkValidationObservation> {
        self.state.lock().ok().map(|state| state.clone())
    }
    fn update(&self, operation: impl FnOnce(&mut NetworkValidationObservation)) {
        if let Ok(mut state) = self.state.lock() {
            state.elapsed_millis =
                u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
            operation(&mut state);
        }
    }
    pub(super) fn stage(&self, stage: &'static str) {
        self.update(|state| state.stage = stage);
    }
    pub(super) fn failure(&self, kind: &'static str) {
        self.update(|state| {
            if state.failure_stage.is_none() {
                state.failure_stage = Some(state.stage);
                state.failure_kind = Some(kind);
            }
        });
    }
}

#[derive(Serialize)]
pub struct PairedGatewayValidationReport {
    pub schema: u8,
    pub status: &'static str,
    pub transaction_id: TransactionId,
    pub candidate_manifest_sha256: Sha256Digest,
    pub target_sha256: Sha256Digest,
    pub endpoint: NativeGatewayEndpointBinding,
    pub device_id: DeviceId,
    pub nonce_relative_path: PathBuf,
    pub nonce_sha256: Sha256Digest,
    pub nonce_bytes: usize,
    pub stdout_bytes: usize,
    pub exit_code: i32,
    pub drained: bool,
    pub strict_negative_controls: usize,
    pub connections_joined: bool,
    pub blocking_jobs_joined: bool,
    pub mcp_lifecycle_jobs_joined: bool,
    pub mcp_session_transports_joined: bool,
    pub unconfirmed_owner_cleanups: usize,
    pub remote_transport_drain: Option<TransportDrainOutcome>,
    pub unconfirmed_transport_drains: usize,
    pub sdk_service_joined: bool,
    pub sdk_detached_tasks_joined: Option<bool>,
    pub host_protocol_joined: bool,
    pub host_link_io_joined: bool,
    pub executor_exited: bool,
    pub processes_exited: bool,
    pub reader_task_reaped: bool,
    pub stderr_task_reaped: bool,
    pub supervised_jobs_joined: bool,
    pub validation_task_joined: bool,
    pub migration_committed: bool,
    pub ordinary_admission_open: bool,
}
struct Effect {
    observation: FileObservation,
    digest: Sha256Digest,
    bytes: usize,
}
struct Custody {
    state_path: PathBuf,
    original: Arc<SettledLegacyRuntime>,
    prepared: Arc<PreparedNativeCutover>,
    preservation: Arc<OriginalPreservation>,
    profile: Arc<LoadedMaintenanceProfile>,
    gateway: PrivateRoot,
    gateway_lease: ExecutionLeaseGuard,
    local: Arc<MigrationValidationProbe>,
    base: PrivateRoot,
    _shared: SharedEnrollment,
    nonce_name: String,
    effect: Mutex<Option<Effect>>,
}
impl Custody {
    fn validate_fixed(&self) -> Result<(), TransitionError> {
        self.gateway_lease
            .validate()
            .map_err(|_| TransitionError::Unknown)?;
        self.local.validate_host_lease()?;
        self.original
            .original_fence()
            .validate_prepared_cutover(&self.prepared)
            .map_err(|_| TransitionError::Unknown)?;
        self.preservation.revalidate_except_canonical()?;
        self.profile
            .revalidate_worker_closures()
            .map_err(|_| TransitionError::Unknown)?;
        let gateway = PrivateRoot::open(self.state_path.join("gateway"))
            .map_err(|_| TransitionError::Unknown)?;
        if gateway.identity() != self.gateway.identity() {
            return Err(TransitionError::Unknown);
        }
        let base = PrivateRoot::open(self.profile.host_base_dir())
            .map_err(|_| TransitionError::Unknown)?;
        if base.identity() != self.base.identity()
            || self
                .original
                .configuration_root()
                .ensure_admission()
                .is_ok()
        {
            return Err(TransitionError::Unknown);
        }
        Ok(())
    }
    fn record_effect(&self, nonce: &str) -> Result<(), TransitionError> {
        let mut effect = self.effect.lock().map_err(|_| TransitionError::Unknown)?;
        if effect.is_some() {
            return Err(TransitionError::Conflict);
        }
        let first = self
            .base
            .read_raw(&self.nonce_name, 256)
            .map_err(|_| TransitionError::Unknown)?;
        let second = self
            .base
            .read_raw(&self.nonce_name, 256)
            .map_err(|_| TransitionError::Unknown)?;
        if first.bytes() != nonce.as_bytes()
            || second.bytes() != first.bytes()
            || first.observation() != second.observation()
        {
            return Err(TransitionError::Unknown);
        }
        *effect = Some(Effect {
            observation: first.observation().clone(),
            digest: Sha256Digest::of_bytes(first.bytes()),
            bytes: first.bytes().len(),
        });
        Ok(())
    }
    fn validate_effect(&self) -> Result<(), TransitionError> {
        let effect = self.effect.lock().map_err(|_| TransitionError::Unknown)?;
        let expected = effect.as_ref().ok_or(TransitionError::Unknown)?;
        let now = self
            .base
            .read_raw(&self.nonce_name, 256)
            .map_err(|_| TransitionError::Unknown)?;
        if now.observation() != &expected.observation
            || Sha256Digest::of_bytes(now.bytes()) != expected.digest
            || now.bytes().len() != expected.bytes
        {
            return Err(TransitionError::Unknown);
        }
        Ok(())
    }
}

/// Sealed result retains the original Host/Gateway leases and the one recovered
/// enrollment authority after actual network/executor cleanup. Data is not proof.
#[must_use]
pub struct PairedGatewayValidation {
    custody: Arc<Custody>,
    report: PairedGatewayValidationReport,
}
impl PairedGatewayValidation {
    pub fn report(&self) -> &PairedGatewayValidationReport {
        &self.report
    }
    pub(super) async fn promote_committed(
        &self,
        proof: Arc<crate::store::legacy_handoff::CommittedNativeCutover>,
    ) -> Result<SharedEnrollment, TransitionError> {
        self.custody
            ._shared
            .promote_committed_migration(proof)
            .await
            .map_err(|_| TransitionError::Unknown)
    }
    pub(super) fn local_probe(&self) -> Arc<MigrationValidationProbe> {
        self.custody.local.clone()
    }
    pub(super) fn matches(
        &self,
        original: &Arc<SettledLegacyRuntime>,
        prepared: &Arc<PreparedNativeCutover>,
    ) -> bool {
        Arc::ptr_eq(original, &self.custody.original)
            && Arc::ptr_eq(prepared, &self.custody.prepared)
    }
    pub(super) async fn revalidate(
        &self,
        applied: Option<&AppliedNativeCutover>,
    ) -> Result<(), TransitionError> {
        if let Some(applied) = applied {
            self.custody
                .local
                .revalidate_after_canonical(applied)
                .await?;
        } else {
            self.custody.local.revalidate().await?;
        }
        self.custody.original.revalidate().await?;
        let custody = self.custody.clone();
        tokio::task::spawn_blocking(move || {
            custody.validate_fixed()?;
            custody.validate_effect()
        })
        .await
        .map_err(|_| TransitionError::Unknown)??;
        self.custody.original.revalidate().await
    }
}
fn http_client(plan: &PreparedGatewayValidation) -> Result<reqwest::Client, TransitionError> {
    let chain = plan
        .prepared
        .endpoint_chain()
        .ok_or(TransitionError::Conflict)?;
    let certificates = rustls_pemfile::certs(&mut Cursor::new(chain))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| TransitionError::Conflict)?;
    if certificates.len() != 2
        || Sha256Digest::of_bytes(&certificates[1]) != plan.endpoint.anchor_sha256
        || Sha256Digest::of_bytes(&certificates[0]) != plan.endpoint.leaf_sha256
    {
        return Err(TransitionError::Conflict);
    }
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(certificates[1].clone())
        .map_err(|_| TransitionError::Conflict)?;
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
    .map_err(|_| TransitionError::Conflict)?
    .with_root_certificates(roots)
    .with_no_client_auth();
    reqwest::Client::builder()
        .tls_backend_preconfigured(tls)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(25))
        .build()
        .map_err(|_| TransitionError::Conflict)
}
impl PreparedGatewayValidation {
    /// Starts ONE fixed journey; cancellation of this response waiter does not
    /// abandon the owned driver's cleanup or free a live executor's lease.
    pub async fn validate(
        self,
        probe: MigrationValidationProbe,
    ) -> Result<PairedGatewayValidation, TransitionError> {
        self.validate_observed(probe, NetworkValidationObserver::new())
            .await
    }
    pub(crate) async fn validate_observed(
        self,
        probe: MigrationValidationProbe,
        observer: NetworkValidationObserver,
    ) -> Result<PairedGatewayValidation, TransitionError> {
        if !Arc::ptr_eq(probe.original_runtime(), &self.original)
            || !probe.report().probe_task_joined
        {
            return Err(TransitionError::Conflict);
        }
        let (send, receive) = oneshot::channel();
        let job = tokio::spawn(run_owned(self, Arc::new(probe), send, observer.clone()));
        let mut proof = receive.await.map_err(|_| {
            observer.failure("validation_response_lost");
            TransitionError::Unknown
        })??;
        job.await.map_err(|_| {
            observer.failure("validation_job_join_failed");
            TransitionError::Unknown
        })?;
        proof.report.validation_task_joined = true;
        Ok(proof)
    }
}
async fn run_owned(
    plan: PreparedGatewayValidation,
    local: Arc<MigrationValidationProbe>,
    sender: oneshot::Sender<Result<PairedGatewayValidation, TransitionError>>,
    observer: NetworkValidationObserver,
) {
    observer.stage("http_client_prepare");
    let client = match http_client(&plan) {
        Ok(c) => c,
        Err(e) => {
            observer.failure("stage_rejected");
            let _ = sender.send(Err(e));
            return;
        }
    };
    observer.stage("protected_host_root");
    let origin = plan.endpoint.origin.clone();
    let endpoint = plan.endpoint.clone();
    let address = plan.address;
    let host_header = plan.host_header.clone();
    let host_generation: HostGeneration = uuid::Uuid::new_v4()
        .to_string()
        .try_into()
        .expect("fixed UUID syntax");
    let shared = SharedEnrollment::new(plan.service);
    let base = match PrivateRoot::open(plan.profile.host_base_dir()) {
        Ok(b) => b,
        Err(_) => {
            observer.failure("stage_unknown");
            let _ = sender.send(Err(TransitionError::Unknown));
            return;
        }
    };
    let nonce_name = format!("styx_migration_paired_{}", uuid::Uuid::new_v4().simple());
    let nonce = format!("styx_paired_{}", uuid::Uuid::new_v4().simple());
    let custody = Arc::new(Custody {
        state_path: plan.state_path,
        original: plan.original,
        prepared: plan.prepared,
        preservation: plan.preservation,
        profile: plan.profile,
        gateway: plan.gateway,
        gateway_lease: plan.lease,
        local,
        base,
        _shared: shared.clone(),
        nonce_name,
        effect: Mutex::new(None),
    });
    observer.stage("protected_inputs_and_executor_config");
    let before = custody.clone();
    let prepared = tokio::task::spawn_blocking(move || {
        before.validate_fixed()?;
        before
            .base
            .ensure_absent(&before.nonce_name)
            .map_err(|_| TransitionError::Conflict)?;
        let mut config = before
            .profile
            .executor_config()
            .map_err(|_| TransitionError::Unknown)?;
        config.rpc_timeout = config.rpc_timeout.min(Duration::from_secs(5));
        config.retained_process_limit = 2;
        Ok::<_, TransitionError>(config)
    })
    .await;
    let config = match prepared {
        Ok(Ok(c)) => c,
        _ => {
            observer.failure("stage_unknown");
            let _ = sender.send(Err(TransitionError::Unknown));
            return;
        }
    };
    observer.stage("original_scopes_revalidate");
    if let Err(e) = custody.original.revalidate().await {
        observer.failure("stage_rejected");
        let _ = sender.send(Err(e));
        return;
    }
    observer.stage("gateway_setup");
    let partition = Arc::new(Semaphore::new(styx_contracts::HOST_QUEUED_BYTES));
    let setup = (|| {
        let relay = RelayHandle::new(
            shared.clone(),
            custody.profile.paired_gateway_namespace(),
            GatewayEpoch::try_from(format!("migration-{}", uuid::Uuid::new_v4()))
                .map_err(|_| TransitionError::Conflict)?,
            partition
                .clone()
                .try_acquire_many_owned(16 * 1024 * 1024)
                .map_err(|_| TransitionError::Busy)?,
        )
        .map_err(|_| TransitionError::Conflict)?;
        let backend = Arc::new(PairedGatewayBackend::new(relay.clone(), None));
        let budget = HttpBudget::from_reserved_partition(
            partition
                .try_acquire_many_owned(32 * 1024 * 1024)
                .map_err(|_| TransitionError::Busy)?,
        )
        .map_err(|_| TransitionError::Conflict)?;
        let mcp = GatewayHttp::new(plan.policy, backend, budget);
        let mcp_stop = mcp.paired_shutdown_handle();
        let app =
            EnrollmentHttp::new_paired(plan.tls, shared, relay.clone(), mcp, vec![host_header])
                .map_err(|_| TransitionError::Conflict)?;
        Ok::<_, TransitionError>((app, mcp_stop, relay))
    })();
    let (app, mcp_stop, relay) = match setup {
        Ok(v) => v,
        Err(e) => {
            observer.failure("stage_rejected");
            let _ = sender.send(Err(e));
            return;
        }
    };
    observer.stage("listener_bind");
    let listener = match TcpListener::bind(address).await {
        Ok(l) => l,
        Err(_) => {
            observer.failure("stage_busy");
            let _ = sender.send(Err(TransitionError::Busy));
            return;
        }
    };
    let stop = CancellationToken::new();
    let server_app = app.clone();
    let server_stop = stop.clone();
    let mut server = tokio::spawn(async move { server_app.run(listener, server_stop).await });
    let protocol_stop = CancellationToken::new();
    let mut protocol_job = None;
    let mut host: Option<Arc<OwnedExecHost>> = None;
    let mut bootstrap_unknown = false;
    let execution = async {
        observer.stage("executor_reservation");
        let reservation = OwnedExecHost::reserve(
            host_generation.clone(),
            super::probe::facts(custody.profile.device_id().clone()),
            2,
        )
        .map_err(|_| TransitionError::Conflict)?;
        // Typed HTTP maintenance gate must reject real requests, regardless of
        // the caller presenting the original Gateway's model credential.
        for (index, (method, path)) in [
            (reqwest::Method::GET, "/styx/enroll/devices".to_owned()),
            (reqwest::Method::POST, "/styx/enroll/invitations".to_owned()),
            (
                reqwest::Method::POST,
                "/styx/enroll/capabilities".to_owned(),
            ),
            (
                reqwest::Method::GET,
                format!(
                    "/styx/enroll/self/{}/capabilities",
                    custody.profile.device_id().as_str()
                ),
            ),
        ]
        .into_iter()
        .enumerate()
        {
            observer.stage(match index {
                0 => "negative_http_devices",
                1 => "negative_http_invitation",
                2 => "negative_http_capabilities",
                _ => "negative_http_self",
            });
            let response = client
                .request(method, format!("{origin}{path}"))
                .bearer_auth(plan.model_token.as_str())
                .header("content-type", "application/json")
                .body("{}")
                .send()
                .await
                .map_err(|error| {
                    observer.failure(if error.is_timeout() {
                        "http_timeout"
                    } else if error.is_connect() {
                        "http_connect"
                    } else {
                        "http_transport"
                    });
                    TransitionError::Unknown
                })?;
            let status = response.status();
            observer.update(|state| {
                state.negative_http[index] = Some((status.as_u16(), "body_not_read"))
            });
            if status != reqwest::StatusCode::SERVICE_UNAVAILABLE {
                observer.failure("unexpected_http_status");
                return Err(TransitionError::Unknown);
            }
            let body: serde_json::Value = response.json().await.map_err(|_| {
                observer.failure("http_body_rejected");
                TransitionError::Unknown
            })?;
            let expected = body["error"] == "migration_commit_required";
            observer.update(|state| {
                state.negative_http[index] = Some((
                    status.as_u16(),
                    if expected {
                        "migration_commit_required"
                    } else {
                        "unexpected_error"
                    },
                ))
            });
            if !expected {
                observer.failure("unexpected_http_error");
                return Err(TransitionError::Unknown);
            }
        }
        observer.stage("negative_wss_prepare");
        let original_endpoint = custody.profile.endpoint().as_str().to_owned();
        let mut wrong =
            url::Url::parse(&original_endpoint).map_err(|_| TransitionError::Conflict)?;
        let other = format!("styx-{}", &uuid::Uuid::new_v4().simple().to_string()[..24]);
        wrong.set_path(&format!("/styx/host/v3/{other}/exec"));
        let bad = SecretBearer::from_protected_reader(uuid::Uuid::new_v4().to_string())
            .map_err(|_| TransitionError::Conflict)?;
        for (index, (text, bearer)) in [
            (wrong.to_string(), custody.profile.bearer()),
            (
                original_endpoint.replace("/exec", "/browser"),
                custody.profile.bearer(),
            ),
            (
                original_endpoint.replace("/exec", "/computer"),
                custody.profile.bearer(),
            ),
            (original_endpoint.clone(), &bad),
        ]
        .into_iter()
        .enumerate()
        {
            observer.stage(match index {
                0 => "negative_wss_device",
                1 => "negative_wss_browser",
                2 => "negative_wss_computer",
                _ => "negative_wss_bearer",
            });
            let endpoint = LinkEndpoint::parse(&text).map_err(|_| TransitionError::Conflict)?;
            let tcp = TcpStream::connect(address)
                .await
                .map_err(|_| TransitionError::Unknown)?;
            let attempt = HostWssLink::connect(
                &endpoint,
                custody.profile.tls(),
                tcp,
                LinkAuthentication::Bearer(bearer),
                ConnectionGeneration::try_from(uuid::Uuid::new_v4().to_string())
                    .map_err(|_| TransitionError::Conflict)?,
                reservation.link_budget(),
            )
            .await;
            match attempt {
                Err(crate::host::link::LinkError::HandshakeRejected) => {
                    observer.update(|state| state.negative_wss[index] = Some("handshake_rejected"))
                }
                Ok(link) => {
                    observer
                        .update(|state| state.negative_wss[index] = Some("unexpected_acceptance"));
                    observer.failure("negative_wss_accepted");
                    let _ = link.shutdown(Duration::from_secs(5)).await;
                    return Err(TransitionError::Unknown);
                }
                Err(error) => {
                    observer.update(|state| {
                        state.negative_wss[index] = Some(match error {
                            crate::host::link::LinkError::Deadline => "deadline",
                            crate::host::link::LinkError::UpgradeStatus(_) => "upgrade_status",
                            _ => "other",
                        })
                    });
                    observer.failure("negative_wss_unexpected_error");
                    return Err(TransitionError::Unknown);
                }
            }
        }
        observer.stage("positive_wss_connect");
        let tcp = TcpStream::connect(address)
            .await
            .map_err(|_| TransitionError::Unknown)?;
        let mut link = HostWssLink::connect(
            custody.profile.endpoint(),
            custody.profile.tls(),
            tcp,
            LinkAuthentication::Bearer(custody.profile.bearer()),
            ConnectionGeneration::try_from(uuid::Uuid::new_v4().to_string())
                .map_err(|_| TransitionError::Conflict)?,
            reservation.link_budget(),
        )
        .await
        .map_err(|_| TransitionError::Unknown)?;
        // Original credential/TLS admission precedes actual native bootstrap.
        observer.stage("native_bootstrap");
        let candidate = match reservation.spawn(config).await {
            Ok(h) => Arc::new(h),
            Err(_) => {
                bootstrap_unknown = true;
                let _ = link.shutdown(Duration::from_secs(5)).await;
                return Err(TransitionError::Unknown);
            }
        };
        host = Some(candidate.clone());
        let device = custody.profile.device_id().clone();
        let namespace = custody.profile.paired_gateway_namespace();
        let cancel = protocol_stop.clone();
        protocol_job = Some(tokio::spawn(async move {
            let protocol = candidate.paired_protocol(PairedTrustedProfile {
                endpoint: original_endpoint,
                gateway_namespace: namespace,
                device_id: device,
                host_generation,
            });
            let result = match protocol {
                Ok(protocol) => protocol
                    .run_connection_with_stop(&mut link, &cancel)
                    .await
                    .map_err(|_| TransitionError::Unknown),
                Err(_) => Err(TransitionError::Conflict),
            };
            let cleanup = link.shutdown(Duration::from_secs(5)).await;
            (result, cleanup.is_ok())
        }));
        observer.stage("sdk_journey");
        super::network_client::exercise_observed(
            client,
            &origin,
            plan.model_token.as_str(),
            custody.profile.device_id(),
            custody
                .profile
                .host_base_dir()
                .to_str()
                .ok_or(TransitionError::Unsupported)?,
            (&custody.nonce_name, &nonce),
            observer.clone(),
        )
        .await
    }
    .await;
    if execution.is_err() {
        observer.failure("execution_rejected_or_unknown");
    }
    // Original MCP owners settle while the Host is online. The Host then drains
    // over that same live Gateway control connection; EOF is not a drain ACK.
    observer.stage("mcp_cleanup");
    let mcp_cleanup = mcp_stop.shutdown(Duration::from_secs(10)).await;
    observer.stage("host_transport_drain");
    protocol_stop.cancel();
    let protocol_join = if let Some(job) = protocol_job.as_mut() {
        Some(tokio::time::timeout(Duration::from_secs(10), job).await)
    } else {
        None
    };
    let remote_transport_drain = match &protocol_join {
        Some(Ok(Ok((Ok(outcome), _)))) => *outcome,
        _ => None,
    };
    observer.stage("server_cleanup");
    stop.cancel();
    let server_join = tokio::time::timeout(Duration::from_secs(25), &mut server).await;
    observer.stage("native_cleanup");
    let native_cleanup = if let Some(host) = &host {
        Some(host.shutdown_owned(Duration::from_secs(30)).await)
    } else {
        None
    };
    let server_facts = match &server_join {
        Ok(Ok(Ok(f))) => Some(f),
        _ => None,
    };
    let protocol_closed = matches!(&protocol_join, Some(Ok(Ok((_, true)))))
        || (protocol_job.is_none() && host.is_none() && !bootstrap_unknown);
    let native = native_cleanup.as_ref().and_then(|r| r.as_ref().ok());
    let unconfirmed_transport_drains = relay.unconfirmed_transport_drains();
    observer.update(|state| {
        state.cleanup = Some(NetworkCleanupObservation {
            mcp_connections_joined: mcp_cleanup.connections_joined,
            mcp_lifecycle_jobs_joined: mcp_cleanup.lifecycle_jobs_joined,
            mcp_session_transports_joined: mcp_cleanup.session_transports_joined,
            unconfirmed_owner_cleanups: mcp_cleanup.unconfirmed_owner_cleanups,
            unresolved_sessions: mcp_cleanup.unresolved_sessions,
            protocol_joined: matches!(&protocol_join, Some(Ok(Ok(_)))),
            link_closed: protocol_closed,
            remote_transport_drain,
            server_joined: matches!(&server_join, Ok(Ok(Ok(_)))),
            server_connections_joined: server_facts.is_some_and(|facts| facts.connections_joined),
            server_blocking_jobs_joined: server_facts
                .is_some_and(|facts| facts.blocking_jobs_joined),
            native_settled: native.is_some_and(|facts| {
                facts.supervised_jobs_joined
                    && facts.ancillary_providers_settled()
                    && facts.native.as_ref().is_some_and(|native| {
                        native.executor_exited
                            && native.reader_task_reaped
                            && native.stderr_task_reaped
                            && native
                                .processes
                                .iter()
                                .all(|(_, e)| matches!(e, TerminationEvidence::ProcessExited(_)))
                    })
            }),
            unconfirmed_transport_drains,
        })
    });
    let clean = !bootstrap_unknown
        && (host.is_none() || remote_transport_drain == Some(TransportDrainOutcome::Complete))
        && unconfirmed_transport_drains == 0
        && mcp_cleanup.unresolved_sessions == 0
        && server_facts.is_some_and(|f| {
            f.connections_joined
                && f.blocking_jobs_joined
                && f.blocking_slots_in_use == 0
                && f.profile_jobs_in_use == 0
                && !f.worker_failure_observed
                && !f.listener_error_observed
                && f.mcp_lifecycle_jobs_joined == Some(true)
        })
        && mcp_cleanup.connections_joined
        && mcp_cleanup.lifecycle_jobs_joined
        && mcp_cleanup.session_transports_joined
        && mcp_cleanup.unconfirmed_owner_cleanups == 0
        && !mcp_cleanup.worker_failure_observed
        && (host.is_none()
            || native.is_some_and(|f| {
                f.supervised_jobs_joined
                    && f.ancillary_providers_settled()
                    && f.native.as_ref().is_some_and(|n| {
                        n.executor_exited
                            && n.reader_task_reaped
                            && n.stderr_task_reaped
                            && n.processes
                                .iter()
                                .all(|(_, e)| matches!(e, TerminationEvidence::ProcessExited(_)))
                    })
            }))
        && protocol_closed;
    if !clean {
        observer.failure("physical_cleanup_unconfirmed");
        observer.failure("stage_unknown");
        let _ = sender.send(Err(TransitionError::Unknown));
        // Explicit incomplete recovery: retain every original lease plus actual
        // native/transport handle on Unknown. No restart, replay or fake join.
        std::future::pending::<()>().await;
        drop((custody, host, server, protocol_job, app, mcp_stop));
        return;
    }
    let observed = match execution {
        Ok(o) => o,
        Err(e) => {
            observer.failure("stage_rejected");
            let _ = sender.send(Err(e));
            return;
        }
    };
    observer.stage("nonce_effect_revalidate");
    let checked = custody.clone();
    let expected = nonce.clone();
    if !matches!(
        tokio::task::spawn_blocking(move || {
            checked.validate_fixed()?;
            checked.record_effect(&expected)
        })
        .await,
        Ok(Ok(()))
    ) {
        observer.failure("stage_unknown");
        let _ = sender.send(Err(TransitionError::Unknown));
        return;
    }
    let native = native
        .expect("clean native facts")
        .native
        .as_ref()
        .expect("configured executor");
    let proof = PairedGatewayValidation {
        report: PairedGatewayValidationReport {
            schema: 1,
            status: "PASS_ORIGINAL_PAIR_NETWORK_NONCE_AND_PHYSICAL_CLEANUP_ONLY",
            transaction_id: custody.prepared.transaction_id().clone(),
            candidate_manifest_sha256: endpoint.candidate_manifest_sha256,
            target_sha256: custody.prepared.target_sha256(),
            endpoint,
            device_id: custody.profile.device_id().clone(),
            nonce_relative_path: PathBuf::from(&custody.nonce_name),
            nonce_sha256: Sha256Digest::of_bytes(nonce.as_bytes()),
            nonce_bytes: nonce.len(),
            stdout_bytes: observed.stdout_bytes,
            exit_code: observed.exit_code,
            drained: observed.drained,
            strict_negative_controls: 8,
            connections_joined: true,
            blocking_jobs_joined: true,
            mcp_lifecycle_jobs_joined: true,
            mcp_session_transports_joined: true,
            unconfirmed_owner_cleanups: 0,
            remote_transport_drain,
            unconfirmed_transport_drains,
            sdk_service_joined: observed.sdk_service_joined,
            sdk_detached_tasks_joined: mcp_cleanup.sdk_detached_tasks_joined,
            host_protocol_joined: true,
            host_link_io_joined: protocol_closed,
            executor_exited: native.executor_exited,
            processes_exited: true,
            reader_task_reaped: native.reader_task_reaped,
            stderr_task_reaped: native.stderr_task_reaped,
            supervised_jobs_joined: true,
            validation_task_joined: false,
            migration_committed: false,
            ordinary_admission_open: false,
        },
        custody,
    };
    observer.stage("final_proof_revalidate");
    if let Err(e) = proof.revalidate(None).await {
        observer.failure("final_proof_rejected");
        observer.failure("stage_rejected");
        let _ = sender.send(Err(e));
        return;
    }
    let _ = sender.send(Ok(proof));
}
