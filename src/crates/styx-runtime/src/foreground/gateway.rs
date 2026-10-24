//! Existing-only, current-user Gateway foreground composition. Configuration
//! evidence is not a migration grant; legacy ownership is conservatively refused.
use super::{ForegroundError, ForegroundEvent};
use serde::Serialize;
use std::path::Path;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

#[derive(Serialize)]
pub struct GatewayForegroundOutcome {
    pub schema: u32,
    pub connections_joined: bool,
    pub blocking_jobs_joined: bool,
    pub mcp_lifecycle_jobs_joined: bool,
    pub mcp_session_transports_joined: bool,
    pub unconfirmed_owner_cleanups: usize,
    pub sdk_detached_tasks_joined: Option<bool>,
    pub worker_failure_observed: bool,
    pub listener_error_observed: bool,
}
impl GatewayForegroundOutcome {
    /// Tracked Styx work only. The SDK's unavailable detached-task join remains
    /// explicitly None, never a claim that all SDK internals were joined.
    pub fn local_stop_complete(&self) -> bool {
        self.connections_joined
            && self.blocking_jobs_joined
            && self.mcp_lifecycle_jobs_joined
            && self.mcp_session_transports_joined
    }
    pub fn is_complete(&self) -> bool {
        self.local_stop_complete()
            && self.unconfirmed_owner_cleanups == 0
            && !self.worker_failure_observed
            && !self.listener_error_observed
    }
}

pub async fn gateway_run(
    state_dir: &Path,
    cancel: CancellationToken,
    events: mpsc::Sender<ForegroundEvent>,
) -> Result<GatewayForegroundOutcome, ForegroundError> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    {
        let path = state_dir.to_path_buf();
        let stop = cancel.child_token();
        // Dropped response waiters request stop, not release of the owned task's
        // execution/configuration leases. The runtime must remain alive to join.
        let _waiter = stop.clone().drop_guard();
        tokio::spawn(async move { platform::run(path, stop, events).await })
            .await
            .map_err(|_| ForegroundError("gateway_foreground_worker_failed"))?
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
    {
        let _ = (state_dir, cancel, events);
        Err(ForegroundError("gateway_foreground_platform_unsupported"))
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
pub(crate) use platform::StartupTransportClosure;

#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
mod platform {
    use super::*;
    use crate::{
        enrollment::{http::EnrollmentHttp, service::EnrollmentService, shared::SharedEnrollment},
        gateway::{
            auth::GatewayBearerPolicy,
            http::{GatewayHttp, HttpBudget},
            paired::{PairedGatewayBackend, RelayHandle},
        },
        store::{
            ExecutionLeaseGuard, OwnedConfigurationRoot, PrivateRoot, RawFile,
            enrollment::{JournalBudget, OwnedEnrollmentJournal},
        },
        tls::{GatewayLeafPin, GatewayServerTls, PrivateKeyPem},
    };
    use serde::Deserialize;
    use std::{
        io::Cursor,
        net::{IpAddr, SocketAddr},
        path::PathBuf,
        sync::Arc,
        time::Duration,
    };
    use styx_contracts::identity::{GatewayEpoch, GatewayId, Sha256Digest};
    use styx_core::enrollment::Limits;
    use tokio::{net::TcpListener, sync::Semaphore};

    const LIMIT: usize = 1024 * 1024;
    static LOADERS: Semaphore = Semaphore::const_new(2);
    const OWNERS: &[&str] = &[
        "foreground.lock",
        "foreground-recovery.lock",
        "background.lock",
        "advance.lock",
        "capabilities.lock",
        "gateway-runtime-recovery.lock",
        "host-payload-migration-recovery.lock",
        "host-update-recovery.lock",
        "account-acceptance.lock",
        "onboarding-plugin.lock",
        "tunnel/owner.lock",
    ];
    const GATEWAY_OWNERS: &[&str] = &[
        "service.json",
        "runtime-change.json",
        "foreground.lock",
        "background.lock",
        "install/.health-update-lock",
        "install/.health-operation-lock",
        "install/.health-recovery-guard",
    ];
    #[derive(Deserialize)]
    struct Deployment {
        schema: u32,
        mode: String,
        gateway: Gateway,
    }
    #[derive(Deserialize)]
    struct Gateway {
        url: String,
        #[serde(rename = "listenHost")]
        listen_host: Option<String>,
        runtime: Option<RuntimeLocator>,
        #[serde(rename = "deviceIngress")]
        device_ingress: Option<Ingress>,
    }
    #[derive(Deserialize)]
    struct RuntimeLocator {
        #[serde(rename = "baseDir")]
        base_dir: PathBuf,
    }
    #[derive(Deserialize)]
    struct Ingress {
        enabled: bool,
    }
    #[derive(Deserialize)]
    struct DeploymentState {
        schema: u32,
        mode: String,
        #[serde(rename = "configSha256")]
        config_sha256: String,
        steps: Vec<Step>,
        #[serde(default)]
        uncertain: bool,
        #[serde(rename = "activeStep")]
        active_step: Option<serde_json::Value>,
        #[serde(rename = "hostServiceMaintenance")]
        host_maintenance: Option<Maintenance>,
        #[serde(rename = "gatewayServiceMaintenance")]
        gateway_maintenance: Option<Maintenance>,
        #[serde(rename = "gatewayMaintenance", default)]
        gateway_operations: Vec<Step>,
        #[serde(default)]
        maintenance: Vec<Step>,
    }
    #[derive(Deserialize)]
    struct Maintenance {
        #[serde(rename = "hasUncertainMutation", default)]
        has_uncertain_mutation: bool,
    }
    #[derive(Deserialize)]
    struct Step {
        id: Option<String>,
        status: String,
        evidence: Option<EvidenceSet>,
    }
    #[derive(Deserialize)]
    struct EvidenceSet {
        runtime: Option<Evidence>,
        certificate: Option<Evidence>,
        #[serde(rename = "ownerConfiguration")]
        owner: Option<Evidence>,
    }
    #[derive(Deserialize)]
    struct Evidence {
        path: PathBuf,
        sha256: String,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Runtime {
        schema: u32,
        url: String,
        #[serde(rename = "listenHost")]
        listen_host: String,
        #[serde(rename = "tlsCertificateFile")]
        certificate: PathBuf,
        #[serde(rename = "tlsPrivateKeyFile")]
        key: PathBuf,
        #[serde(rename = "modelTokenFile")]
        model_token: PathBuf,
        #[serde(rename = "adminTokenFile")]
        admin_token: PathBuf,
        #[serde(rename = "enrollmentDir")]
        enrollment: PathBuf,
        #[serde(rename = "catalogFile")]
        catalog: PathBuf,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Catalog {
        version: u32,
        targets: Vec<Box<serde_json::value::RawValue>>,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LegacyEnrollment {
        version: u32,
        invitations: Vec<Box<serde_json::value::RawValue>>,
        pending: Vec<Box<serde_json::value::RawValue>>,
        devices: Vec<Box<serde_json::value::RawValue>>,
    }
    #[derive(Deserialize)]
    struct Owner {
        gateway_url: String,
        gateway_ca_file: PathBuf,
        admin_token_file: PathBuf,
    }
    struct Input {
        root: Arc<PrivateRoot>,
        raw: RawFile,
    }
    struct Admitted {
        state: Arc<PrivateRoot>,
        gateway: Arc<PrivateRoot>,
        runtime_root: Option<PrivateRoot>,
        inputs: Vec<Input>,
        absent_inputs: Vec<(Arc<PrivateRoot>, &'static str)>,
        lease: ExecutionLeaseGuard,
        // Retains the SAME writer even if service boot fails after uncertain I/O.
        _configuration: OwnedConfigurationRoot,
        address: SocketAddr,
    }
    /// One-shot bootstrap evidence for this exact cooperating Rust foreground
    /// scope. Not proof that a legacy writer stopped or a remote process exited.
    /// The private borrow cannot outlive the actual execution/configuration owner.
    pub(crate) struct StartupTransportClosure<'a> {
        admitted: &'a Admitted,
    }
    impl StartupTransportClosure<'_> {
        pub(crate) fn validate_for(
            &self,
            owner: &OwnedConfigurationRoot,
        ) -> Result<(), ForegroundError> {
            if !self.admitted._configuration.same_authority(owner) {
                return Err(error("gateway_startup_authority_mismatch"));
            }
            self.admitted.validate()?;
            owner
                .ensure_admission()
                .map_err(|_| error("gateway_startup_admission_unproven"))
        }
    }
    impl Admitted {
        fn validate(&self) -> Result<(), ForegroundError> {
            ownership(&self.state, &self.gateway, self.runtime_root.as_ref())?;
            self.lease
                .validate()
                .map_err(|_| error("execution_lease_changed"))?;
            for (root, name) in &self.absent_inputs {
                root.ensure_absent(name)
                    .map_err(|_| error("legacy_enrollment_appeared"))?;
            }
            for input in &self.inputs {
                let current = input
                    .root
                    .read_raw(input.raw.relative_path(), LIMIT)
                    .map_err(|_| error("protected_input_changed"))?;
                if current.bytes() != input.raw.bytes()
                    || current.observation() != input.raw.observation()
                {
                    return Err(error("protected_input_changed"));
                }
            }
            Ok(())
        }
    }
    fn error(code: &'static str) -> ForegroundError {
        ForegroundError(code)
    }
    fn ownership(
        state: &PrivateRoot,
        gateway: &PrivateRoot,
        runtime: Option<&PrivateRoot>,
    ) -> Result<(), ForegroundError> {
        for name in OWNERS {
            state
                .ensure_absent(name)
                .map_err(|_| error("legacy_gateway_owner_reconciliation_required"))?;
        }
        // Without an OS service observer, a service config never proves stopped.
        for root in std::iter::once(gateway).chain(runtime) {
            for name in GATEWAY_OWNERS {
                root.ensure_absent(name)
                    .map_err(|_| error("legacy_gateway_service_reconciliation_required"))?;
            }
        }
        // Conservatively refuse existing Host payload transactions, including
        // historical completed journals, rather than infer a cutover grant.
        state
            .ensure_absent("host-payload-migration.json")
            .map_err(|_| error("legacy_gateway_migration_reconciliation_required"))?;
        Ok(())
    }
    fn read(
        root: &Arc<PrivateRoot>,
        path: &str,
        inputs: &mut Vec<Input>,
    ) -> Result<usize, ForegroundError> {
        let raw = root
            .read_raw(path, LIMIT)
            .map_err(|_| error("gateway_protected_read"))?;
        inputs.push(Input {
            root: root.clone(),
            raw,
        });
        Ok(inputs.len() - 1)
    }
    fn decode<T: serde::de::DeserializeOwned>(input: &Input) -> Result<T, ForegroundError> {
        serde_json::from_slice(input.raw.bytes())
            .map_err(|_| error("gateway_configuration_invalid"))
    }
    fn evidence(
        expected: &Option<Evidence>,
        path: &Path,
        input: &Input,
    ) -> Result<(), ForegroundError> {
        let e = expected
            .as_ref()
            .ok_or(error("gateway_prepare_evidence_required"))?;
        if e.path != path || e.sha256 != input.raw.sha256() {
            return Err(error("gateway_prepare_evidence_changed"));
        }
        Ok(())
    }
    fn token(input: &Input) -> Result<&[u8], ForegroundError> {
        // Original Gateway readers trim token-file whitespace. Keep/pin the
        // original file bytes; normalize only the admission input in memory.
        let value = std::str::from_utf8(input.raw.bytes())
            .map_err(|_| error("gateway_token_invalid"))?
            .trim();
        if !(32..=4096).contains(&value.len())
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        {
            return Err(error("gateway_token_invalid"));
        }
        Ok(value.as_bytes())
    }
    struct Loaded {
        admitted: Arc<Admitted>,
        service: EnrollmentService,
        tls: Arc<GatewayServerTls>,
        policy: Arc<GatewayBearerPolicy>,
        host: String,
        gateway_id: GatewayId,
    }
    fn load(path: &Path) -> Result<Loaded, ForegroundError> {
        if !path.is_absolute() {
            return Err(error("absolute_state_directory_required"));
        }
        let state = Arc::new(PrivateRoot::open(path).map_err(|_| error("gateway_protected_read"))?);
        let gateway_path = path.join("gateway");
        let gateway = Arc::new(
            PrivateRoot::open(&gateway_path).map_err(|_| error("gateway_protected_read"))?,
        );
        let mut inputs = Vec::new();
        let deployment_i = read(&state, "deployment.json", &mut inputs)?;
        let state_i = read(&state, "state.json", &mut inputs)?;
        let config: Deployment = decode(&inputs[deployment_i])?;
        let completed: DeploymentState = decode(&inputs[state_i])?;
        if config.schema != 1
            || config.mode != "create-local"
            || completed.schema != 1
            || completed.mode != config.mode
            || completed.config_sha256 != inputs[deployment_i].raw.sha256()
            || completed.uncertain
            || completed.active_step.is_some()
            || completed
                .host_maintenance
                .as_ref()
                .is_some_and(|m| m.has_uncertain_mutation)
            || completed
                .gateway_maintenance
                .as_ref()
                .is_some_and(|m| m.has_uncertain_mutation)
            || completed
                .steps
                .iter()
                .chain(&completed.gateway_operations)
                .chain(&completed.maintenance)
                .any(|s| matches!(s.status.as_str(), "running" | "uncertain"))
            || config
                .gateway
                .device_ingress
                .as_ref()
                .is_some_and(|i| i.enabled)
        {
            return Err(error("gateway_deployment_state_invalid_or_unsupported"));
        }
        let step = completed
            .steps
            .iter()
            .find(|s| s.id.as_deref() == Some("gateway.prepare") && s.status == "succeeded")
            .ok_or(error("gateway_prepare_required"))?;
        if config.gateway.runtime.is_some()
            && !completed.steps.iter().any(|s| {
                s.id.as_deref() == Some("gateway.runtime.prepare") && s.status == "succeeded"
            })
        {
            return Err(error("gateway_runtime_prepare_required"));
        }
        let prepared = step
            .evidence
            .as_ref()
            .ok_or(error("gateway_prepare_evidence_required"))?;
        let url =
            url::Url::parse(&config.gateway.url).map_err(|_| error("gateway_origin_invalid"))?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
        {
            return Err(error("gateway_origin_invalid"));
        }
        let ip: IpAddr = url
            .host_str()
            .ok_or(error("gateway_loopback_required"))?
            .trim_matches(['[', ']'])
            .parse()
            .map_err(|_| error("gateway_loopback_required"))?;
        let listen: IpAddr = config
            .gateway
            .listen_host
            .as_deref()
            .unwrap_or("127.0.0.1")
            .parse()
            .map_err(|_| error("gateway_loopback_required"))?;
        if !ip.is_loopback() || !ip.is_ipv4() || ip != listen || url.port().is_none_or(|p| p < 1024)
        {
            return Err(error("gateway_loopback_required"));
        }
        let address = SocketAddr::new(
            ip,
            url.port_or_known_default()
                .ok_or(error("gateway_origin_invalid"))?,
        );
        let origin = url.origin().ascii_serialization();
        let host = origin
            .strip_prefix("https://")
            .ok_or(error("gateway_origin_invalid"))?
            .to_owned();
        let gateway_id = format!(
            "paired.{}",
            Sha256Digest::of_bytes(origin.as_bytes()).to_hex()
        )
        .try_into()
        .map_err(|_| error("gateway_namespace_invalid"))?;
        let runtime_i = read(&gateway, "runtime.json", &mut inputs)?;
        let cert_i = read(&gateway, "certificate.pem", &mut inputs)?;
        let owner_i = read(&gateway, "owner.json", &mut inputs)?;
        evidence(
            &prepared.runtime,
            &gateway_path.join("runtime.json"),
            &inputs[runtime_i],
        )?;
        evidence(
            &prepared.certificate,
            &gateway_path.join("certificate.pem"),
            &inputs[cert_i],
        )?;
        evidence(
            &prepared.owner,
            &gateway_path.join("owner.json"),
            &inputs[owner_i],
        )?;
        let runtime: Runtime = decode(&inputs[runtime_i])?;
        let owner: Owner = decode(&inputs[owner_i])?;
        if runtime.schema != 1
            || runtime.url != config.gateway.url
            || runtime.listen_host != config.gateway.listen_host.as_deref().unwrap_or("127.0.0.1")
            || runtime.certificate != gateway_path.join("certificate.pem")
            || runtime.key != gateway_path.join("private-key.pem")
            || runtime.model_token != gateway_path.join("model.token")
            || runtime.admin_token != gateway_path.join("admin.token")
            || runtime.enrollment != gateway_path.join("enrollment")
            || runtime.catalog != gateway_path.join("targets.json")
            || owner.gateway_url != config.gateway.url
            || owner.gateway_ca_file != runtime.certificate
            || owner.admin_token_file != runtime.admin_token
        {
            return Err(error("gateway_runtime_identity_binding_changed"));
        }
        let key_i = read(&gateway, "private-key.pem", &mut inputs)?;
        let model_i = read(&gateway, "model.token", &mut inputs)?;
        let admin_i = read(&gateway, "admin.token", &mut inputs)?;
        let catalog_i = read(&gateway, "targets.json", &mut inputs)?;
        let catalog: Catalog = decode(&inputs[catalog_i])?;
        if catalog.version != 1 || !catalog.targets.is_empty() {
            return Err(error("legacy_gateway_catalog_migration_required"));
        }
        let runtime_root = config
            .gateway
            .runtime
            .as_ref()
            .map(|r| PrivateRoot::open(&r.base_dir).map_err(|_| error("gateway_protected_read")))
            .transpose()?;
        ownership(&state, &gateway, runtime_root.as_ref())?;
        // Existing-only: neither the journal namespace nor its writer file may
        // be initialized/adopted as a side effect of this foreground command.
        let legacy_enrollment = Arc::new(
            PrivateRoot::open(&runtime.enrollment)
                .map_err(|_| error("existing_native_enrollment_required"))?,
        );
        let mut absent_inputs = Vec::new();
        if legacy_enrollment.ensure_absent("state.json").is_ok() {
            absent_inputs.push((legacy_enrollment.clone(), "state.json"));
        } else {
            let legacy_i = read(&legacy_enrollment, "state.json", &mut inputs)?;
            let legacy: LegacyEnrollment = decode(&inputs[legacy_i])?;
            if legacy.version != 1
                || !legacy.invitations.is_empty()
                || !legacy.pending.is_empty()
                || !legacy.devices.is_empty()
            {
                return Err(error("legacy_gateway_enrollment_migration_required"));
            }
        }
        let enrollment = PrivateRoot::open(&runtime.enrollment)
            .map_err(|_| error("existing_native_enrollment_required"))?;
        if enrollment.identity() != legacy_enrollment.identity() {
            return Err(error("gateway_protected_input_changed"));
        }
        let writer = enrollment
            .try_existing_configuration_writer()
            .map_err(|_| error("existing_native_enrollment_writer_required"))?;
        let configuration = OwnedConfigurationRoot::open_existing(enrollment, writer)
            .map_err(|_| error("existing_native_enrollment_required"))?;
        let journal = OwnedEnrollmentJournal::from_configuration(
            configuration.clone(),
            JournalBudget::default(),
        )
        .map_err(|_| error("existing_native_enrollment_required"))?;
        let lease = gateway
            .try_execution_lease()
            .map_err(|_| error("gateway_execution_busy"))?;
        let policy = Arc::new(
            GatewayBearerPolicy::new(token(&inputs[model_i])?, vec![host.clone()], vec![origin])
                .map_err(|_| error("gateway_model_authority_invalid"))?,
        );
        let leaf = rustls_pemfile::certs(&mut Cursor::new(inputs[cert_i].raw.bytes()))
            .next()
            .ok_or(error("gateway_certificate_invalid"))?
            .map_err(|_| error("gateway_certificate_invalid"))?;
        let tls = Arc::new(
            GatewayServerTls::from_pem(
                inputs[cert_i].raw.bytes(),
                &PrivateKeyPem::from_protected_reader_bytes(inputs[key_i].raw.bytes().to_vec())
                    .map_err(|_| error("gateway_key_invalid"))?,
                GatewayLeafPin::from_certificate_der(leaf.as_ref()),
            )
            .map_err(|_| error("gateway_tls_identity_invalid"))?,
        );
        let service = EnrollmentService::recover_existing(
            journal,
            token(&inputs[admin_i])?,
            Sha256Digest::of_bytes(token(&inputs[model_i])?),
            vec![host.clone()],
            Limits::default(),
        )
        .map_err(|e| error(e.code()))?;
        let admitted = Arc::new(Admitted {
            state,
            gateway,
            runtime_root,
            inputs,
            absent_inputs,
            lease,
            _configuration: configuration,
            address,
        });
        admitted.validate()?;
        Ok(Loaded {
            admitted,
            service,
            tls,
            policy,
            host,
            gateway_id,
        })
    }
    fn emit(events: &mpsc::Sender<ForegroundEvent>, stop: &CancellationToken, name: &'static str) {
        if events
            .try_send(ForegroundEvent {
                schema: 1,
                event: name,
                reason: None,
                device_id: None,
                connection_generation: None,
            })
            .is_err()
        {
            stop.cancel();
        }
    }
    async fn validate(admitted: Arc<Admitted>) -> Result<(), ForegroundError> {
        let permit = LOADERS
            .try_acquire()
            .map_err(|_| error("gateway_reader_busy"))?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            admitted.validate()
        })
        .await
        .map_err(|_| error("gateway_reader_failed"))?
    }
    pub(super) async fn run(
        path: PathBuf,
        stop: CancellationToken,
        events: mpsc::Sender<ForegroundEvent>,
    ) -> Result<GatewayForegroundOutcome, ForegroundError> {
        let permit = LOADERS
            .try_acquire()
            .map_err(|_| error("gateway_reader_busy"))?;
        emit(&events, &stop, "gateway_loading");
        let Loaded {
            admitted,
            service,
            tls,
            policy,
            host,
            gateway_id,
        } = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            load(&path)
        })
        .await
        .map_err(|_| error("gateway_reader_failed"))??;
        if stop.is_cancelled() {
            return Err(error("gateway_start_cancelled"));
        }
        // Before any new transport authority exists, reconcile only startup
        // RecoveredUnknown lanes under the exact held owner. All protected reads
        // stay on a bounded blocking worker, with its permit held until exit.
        let checked = admitted.clone();
        let permit = LOADERS
            .try_acquire()
            .map_err(|_| error("gateway_reader_busy"))?;
        let service = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut service = service;
            service
                .reconcile_recovered_foreground_transports(StartupTransportClosure {
                    admitted: &checked,
                })
                .map_err(|e| error(e.code()))?;
            Ok::<_, ForegroundError>(service)
        })
        .await
        .map_err(|_| error("gateway_reader_failed"))??;
        if stop.is_cancelled() {
            return Err(error("gateway_start_cancelled"));
        }
        let shared = SharedEnrollment::new(service);
        let partition = Arc::new(Semaphore::new(styx_contracts::HOST_QUEUED_BYTES));
        let relay = RelayHandle::new(
            shared.clone(),
            gateway_id,
            GatewayEpoch::try_from(format!("gateway-{}", uuid::Uuid::new_v4()))
                .map_err(|_| error("gateway_epoch_invalid"))?,
            partition
                .clone()
                .try_acquire_many_owned(16 * 1024 * 1024)
                .map_err(|_| error("gateway_partition_unavailable"))?,
        )
        .map_err(|_| error("gateway_relay_invalid"))?;
        let backend = Arc::new(PairedGatewayBackend::new(relay.clone(), None));
        let budget = HttpBudget::from_reserved_partition(
            partition
                .clone()
                .try_acquire_many_owned(32 * 1024 * 1024)
                .map_err(|_| error("gateway_partition_unavailable"))?,
        )
        .map_err(|_| error("gateway_partition_invalid"))?;
        let mcp = GatewayHttp::new(policy, backend, budget);
        let mcp_stop = mcp.paired_shutdown_handle();
        let app = EnrollmentHttp::new_paired(tls, shared, relay, mcp, vec![host])
            .map_err(|_| error("gateway_listener_configuration_invalid"))?;
        let listener = TcpListener::bind(admitted.address)
            .await
            .map_err(|_| error("gateway_listen_failed"))?;
        validate(admitted.clone()).await?;
        if stop.is_cancelled() {
            return Err(error("gateway_start_cancelled"));
        }
        let server_app = app.clone();
        let server_stop = stop.clone();
        let keep = admitted.clone();
        let mut server = tokio::spawn(async move {
            let _keep = keep;
            server_app.run(listener, server_stop).await
        });
        emit(&events, &stop, "gateway_listening");
        let mut invalidated = false;
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let facts = loop {
            tokio::select! {
                result = &mut server => {
                    break result.map_err(|_| error("gateway_listener_worker_failed"))?
                        .map_err(|_| error("gateway_listener_failed"))?;
                }
                _ = interval.tick(), if !stop.is_cancelled() => {
                    let validated = validate(admitted.clone()).await;
                    if validated.is_err() {
                        invalidated = true;
                        emit(&events, &stop, "gateway_inputs_changed");
                        stop.cancel();
                    }
                }
            }
        };
        // A timeout is not release. Keep the exact original input pins, writer
        // and execution lease while real blocking/read tasks finish.
        let mut joined = facts.blocking_jobs_joined;
        let mut worker_failure = facts.worker_failure_observed;
        while !joined {
            emit(&events, &stop, "gateway_waiting_for_owned_jobs");
            let next = app.wait_for_blocking(Duration::from_secs(30)).await;
            joined = next.blocking_jobs_joined;
            worker_failure |= next.worker_failure_observed;
        }
        let mut lifecycle = mcp_stop.shutdown(Duration::from_secs(5)).await;
        while !lifecycle.connections_joined
            || !lifecycle.lifecycle_jobs_joined
            || !lifecycle.session_transports_joined
        {
            emit(&events, &stop, "gateway_waiting_for_owned_lifecycle");
            tokio::time::sleep(Duration::from_secs(1)).await;
            lifecycle = mcp_stop.shutdown(Duration::from_secs(5)).await;
        }
        let outcome = GatewayForegroundOutcome {
            schema: 1,
            connections_joined: facts.connections_joined && lifecycle.connections_joined,
            blocking_jobs_joined: joined,
            mcp_lifecycle_jobs_joined: lifecycle.lifecycle_jobs_joined,
            mcp_session_transports_joined: lifecycle.session_transports_joined,
            unconfirmed_owner_cleanups: lifecycle.unconfirmed_owner_cleanups,
            sdk_detached_tasks_joined: lifecycle.sdk_detached_tasks_joined,
            worker_failure_observed: worker_failure || lifecycle.worker_failure_observed,
            listener_error_observed: facts.listener_error_observed,
        };
        if outcome.unconfirmed_owner_cleanups != 0 {
            emit(&events, &stop, "remote_owner_cleanup_unconfirmed");
        }
        emit(&events, &stop, "gateway_stopped");
        // This explicit command-scope teardown follows actual owned-job waits.
        // None above is not silently promoted to an SDK join claim.
        if invalidated {
            Err(error("gateway_protected_input_changed"))
        } else {
            Ok(outcome)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{fs, os::unix::fs::PermissionsExt};

        #[test]
        fn startup_closure_binds_actual_writer_lease_and_original_input() {
            // Preserve this private fixture on assertion failure for inspection.
            let path =
                std::env::temp_dir().join(format!("styx-startup-closure-{}", uuid::Uuid::new_v4()));
            fn directory(path: &Path) {
                fs::create_dir(path).unwrap();
                fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
            }
            fn configuration(path: &Path) -> OwnedConfigurationRoot {
                directory(path);
                let root = PrivateRoot::open(path).unwrap();
                let writer = root.try_configuration_writer().unwrap();
                OwnedConfigurationRoot::open_existing(root, writer).unwrap()
            }
            directory(&path);
            let state_path = path.join("state");
            directory(&state_path);
            let gateway_path = state_path.join("gateway");
            directory(&gateway_path);
            let input = state_path.join("binding.json");
            fs::write(&input, b"original").unwrap();
            fs::set_permissions(&input, fs::Permissions::from_mode(0o600)).unwrap();
            let state = Arc::new(PrivateRoot::open(&state_path).unwrap());
            let gateway = Arc::new(PrivateRoot::open(&gateway_path).unwrap());
            let owner = configuration(&path.join("enrollment"));
            let foreign = configuration(&path.join("foreign-enrollment"));
            let mut inputs = vec![];
            read(&state, "binding.json", &mut inputs).unwrap();
            let admitted = Admitted {
                state,
                gateway: gateway.clone(),
                runtime_root: None,
                inputs,
                absent_inputs: vec![],
                lease: gateway.try_execution_lease().unwrap(),
                _configuration: owner.clone(),
                address: "127.0.0.1:32651".parse().unwrap(),
            };
            let closure = StartupTransportClosure {
                admitted: &admitted,
            };
            closure.validate_for(&owner).unwrap();
            assert!(
                closure.validate_for(&foreign).is_err(),
                "an unrelated writer/root cannot authorize startup reconciliation"
            );
            assert!(
                gateway.try_execution_lease().is_err(),
                "validation retains the actual original execution lease"
            );
            fs::write(&input, b"changed").unwrap();
            assert!(
                closure.validate_for(&owner).is_err(),
                "held locks cannot substitute for unchanged original protected input"
            );
            assert!(
                gateway.try_execution_lease().is_err(),
                "failed observation must not silently release ownership"
            );
            drop(admitted);
            gateway.try_execution_lease().unwrap().validate().unwrap();
            drop((owner, foreign, gateway));
            fs::remove_dir_all(path).unwrap();
        }
    }
}
