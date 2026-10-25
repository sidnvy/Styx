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
    pub unconfirmed_transport_drains: usize,
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
            && self.unconfirmed_transport_drains == 0
            && !self.worker_failure_observed
            && !self.listener_error_observed
    }
}

pub async fn gateway_run(
    state_dir: &Path,
    cancel: CancellationToken,
    events: mpsc::Sender<ForegroundEvent>,
) -> Result<GatewayForegroundOutcome, ForegroundError> {
    #[cfg(any(
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
        all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"),
        all(
            target_os = "macos",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    {
        let path = state_dir.to_path_buf();
        let stop = cancel.child_token();
        // Dropped response waiters request stop, not release of the owned task's
        // execution/configuration leases. The runtime must remain alive to join.
        let _waiter = stop.clone().drop_guard();
        tokio::spawn(async move { platform::run(path, stop, events, None, None).await })
            .await
            .map_err(|_| ForegroundError("gateway_foreground_worker_failed"))?
    }
    #[cfg(not(any(
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
        all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"),
        all(
            target_os = "macos",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )))]
    {
        let _ = (state_dir, cancel, events);
        Err(ForegroundError("gateway_foreground_platform_unsupported"))
    }
}

/// An App startup failure owns any unsettled bootstrap writer and its original
/// App scope. The App must retain this value until its teardown; reporting the
/// static code alone is not settlement evidence.
#[must_use]
pub(crate) struct AppGatewayError {
    foreground: ForegroundError,
    _retained: Option<crate::management::native_gateway::BootstrapError>,
}
impl AppGatewayError {
    pub(crate) fn code(&self) -> &'static str {
        self.foreground.code()
    }
}
impl std::fmt::Debug for AppGatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("AppGatewayError")
            .field(&self.code())
            .finish()
    }
}
impl std::fmt::Display for AppGatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for AppGatewayError {}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
    all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"),
    all(
        target_os = "macos",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
// One startup loader and one error slot per original run, with no backpointer
// from HostScope. This transports ownership, not new domain/recovery state.
type AppStartupFailure =
    std::sync::Arc<std::sync::Mutex<Option<crate::management::native_gateway::BootstrapError>>>;

/// Owned native App role. Scope cannot be constructed from RPC data. The worker
/// retains it through original blocking work and Gateway settlement.
pub(crate) async fn gateway_run_for_app(
    scope: std::sync::Arc<crate::app::HostScope>,
    cancel: CancellationToken,
    events: mpsc::Sender<ForegroundEvent>,
) -> Result<GatewayForegroundOutcome, AppGatewayError> {
    #[cfg(any(
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
        all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"),
        all(
            target_os = "macos",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    {
        let path = scope.state_dir().to_owned();
        let stop = cancel.child_token();
        let _waiter = stop.clone().drop_guard();
        let failure: AppStartupFailure = Default::default();
        let loader_failure = failure.clone();
        let result = tokio::spawn(async move {
            platform::run(path, stop, events, Some(scope), Some(loader_failure)).await
        })
        .await
        .unwrap_or(Err(ForegroundError("gateway_foreground_worker_failed")));
        // run awaits its original blocking loader. Only after that run has
        // actually joined may ownership pass from the slot to the App result.
        let retained = failure.lock().unwrap_or_else(|e| e.into_inner()).take();
        match (result, retained) {
            (Ok(outcome), None) => Ok(outcome),
            (Err(foreground), retained) => Err(AppGatewayError {
                foreground,
                _retained: retained,
            }),
            (Ok(_), Some(retained)) => Err(AppGatewayError {
                foreground: ForegroundError(retained.code()),
                _retained: Some(retained),
            }),
        }
    }
    #[cfg(not(any(
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
        all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"),
        all(
            target_os = "macos",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )))]
    {
        let _ = (scope, cancel, events);
        Err(AppGatewayError {
            foreground: ForegroundError("gateway_foreground_platform_unsupported"),
            _retained: None,
        })
    }
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
    all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"),
    all(
        target_os = "macos",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
pub(crate) use platform::StartupTransportClosure;

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
    all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"),
    all(
        target_os = "macos",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
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
            ExecutionLeaseGuard, OwnedConfigurationRoot, PrivateRoot,
            enrollment::{JournalBudget, OwnedEnrollmentJournal},
        },
        tls::GatewayServerTls,
    };
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    use crate::{
        store::RawFile,
        tls::{GatewayLeafPin, PrivateKeyPem},
    };
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    use serde::Deserialize;
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    use std::{io::Cursor, net::IpAddr};
    use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
    use styx_contracts::identity::{GatewayEpoch, GatewayId, Sha256Digest};
    use styx_core::enrollment::Limits;
    use tokio::{net::TcpListener, sync::Semaphore};

    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    const LIMIT: usize = 1024 * 1024;
    static LOADERS: Semaphore = Semaphore::const_new(2);
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
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
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
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
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    struct Deployment {
        schema: u32,
        mode: String,
        gateway: Gateway,
    }
    #[derive(Deserialize)]
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    struct Gateway {
        url: String,
        #[serde(rename = "listenHost")]
        listen_host: Option<String>,
        runtime: Option<RuntimeLocator>,
        #[serde(rename = "deviceIngress")]
        device_ingress: Option<Ingress>,
    }
    #[derive(Deserialize)]
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    struct RuntimeLocator {
        #[serde(rename = "baseDir")]
        base_dir: PathBuf,
    }
    #[derive(Deserialize)]
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    struct Ingress {
        enabled: bool,
    }
    #[derive(Deserialize)]
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
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
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    struct Maintenance {
        #[serde(rename = "hasUncertainMutation", default)]
        has_uncertain_mutation: bool,
    }
    #[derive(Deserialize)]
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    struct Step {
        id: Option<String>,
        status: String,
        evidence: Option<EvidenceSet>,
    }
    #[derive(Deserialize)]
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    struct EvidenceSet {
        runtime: Option<Evidence>,
        certificate: Option<Evidence>,
        #[serde(rename = "ownerConfiguration")]
        owner: Option<Evidence>,
    }
    #[derive(Deserialize)]
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    struct Evidence {
        path: PathBuf,
        sha256: String,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
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
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    struct Catalog {
        version: u32,
        targets: Vec<Box<serde_json::value::RawValue>>,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    struct LegacyEnrollment {
        version: u32,
        invitations: Vec<Box<serde_json::value::RawValue>>,
        pending: Vec<Box<serde_json::value::RawValue>>,
        devices: Vec<Box<serde_json::value::RawValue>>,
    }
    #[derive(Deserialize)]
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    struct Owner {
        gateway_url: String,
        gateway_ca_file: PathBuf,
        admin_token_file: PathBuf,
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    struct Input {
        root: Arc<PrivateRoot>,
        raw: RawFile,
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    struct NativeCommittedAdmission {
        snapshot: Arc<crate::store::committed_runtime::CommittedRuntimeSnapshot>,
        host: PrivateRoot,
        candidate: crate::release::VerifiedNativeRelease,
        proof: crate::store::committed_runtime::RecoveredCommittedRuntime,
    }
    struct Admitted {
        #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        state: Arc<PrivateRoot>,
        #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        gateway: Arc<PrivateRoot>,
        #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        runtime_root: Option<PrivateRoot>,
        #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        inputs: Vec<Input>,
        #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        absent_inputs: Vec<(Arc<PrivateRoot>, &'static str)>,
        lease: ExecutionLeaseGuard,
        // Retains the SAME writer even if service boot fails after uncertain I/O.
        _configuration: OwnedConfigurationRoot,
        address: SocketAddr,
        #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        native: Option<NativeCommittedAdmission>,
        fresh: Option<crate::management::native_gateway::FreshGatewayRuntime>,
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
            if let Some(fresh) = &self.fresh {
                fresh.validate().map_err(|e| error(e.code()))?;
                if !fresh
                    .configuration_root()
                    .same_authority(&self._configuration)
                {
                    return Err(error("fresh_gateway_configuration_changed"));
                }
            } else {
                #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                self.validate_legacy()?;
                #[cfg(not(all(
                    target_os = "linux",
                    target_arch = "x86_64",
                    target_env = "gnu"
                )))]
                return Err(error("fresh_gateway_required"));
            }
            self.lease
                .validate()
                .map_err(|_| error("execution_lease_changed"))?;
            Ok(())
        }
        #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        fn validate_legacy(&self) -> Result<(), ForegroundError> {
            if let Some(native) = &self.native {
                native
                    .snapshot
                    .validate_legacy_owners(&self.state, &native.host)
                    .map_err(|_| error("committed_owner_binding_changed"))?;
                native
                    .candidate
                    .revalidate()
                    .map_err(|_| error("committed_candidate_changed"))?;
                native
                    .proof
                    .validate_owner(&self._configuration)
                    .map_err(|_| error("committed_configuration_changed"))?;
            } else {
                ownership(&self.state, &self.gateway, self.runtime_root.as_ref())?;
            }
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
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
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
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
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
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    fn decode<T: serde::de::DeserializeOwned>(input: &Input) -> Result<T, ForegroundError> {
        serde_json::from_slice(input.raw.bytes())
            .map_err(|_| error("gateway_configuration_invalid"))
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
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
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
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
        // Select the explicit native reader before touching legacy layout.
        // Any malformed/present ready material stays on the fresh reader path;
        // failure must never fall back to the legacy or migrated authority.
        let native = state.ensure_absent(".styx-native-root-v1.json").is_err();
        if native && state.ensure_absent("gateway-ready-v1.json").is_err() {
            return load_fresh(path, None, None);
        }
        #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        {
            load_legacy(path, state, native)
        }
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
        {
            Err(error("fresh_native_gateway_required"))
        }
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    fn load_legacy(
        path: &Path,
        state: Arc<PrivateRoot>,
        native: bool,
    ) -> Result<Loaded, ForegroundError> {
        let gateway_path = path.join("gateway");
        let gateway = Arc::new(
            PrivateRoot::open(&gateway_path).map_err(|_| error("gateway_protected_read"))?,
        );
        if native {
            return load_committed(path, state, gateway);
        }
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
            native: None,
            fresh: None,
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
    /// Fresh native startup retains the existing ready binding and the same
    /// configuration owner. No legacy-layout or migration proof is invented.
    fn load_fresh(
        path: &Path,
        app_scope: Option<Arc<crate::app::HostScope>>,
        app_failure: Option<AppStartupFailure>,
    ) -> Result<Loaded, ForegroundError> {
        let runtime = match app_scope {
            Some(scope) => {
                if scope.state_dir() != path {
                    return Err(error("app_scope_changed"));
                }
                crate::management::native_gateway::open_existing_for_app(scope)
            }
            None => crate::management::native_gateway::open_existing(path),
        }
        .map_err(|e| {
            let foreground = error(e.code());
            if let Some(failure) = app_failure {
                // Exactly one open attempt in this run, so no prior failure can
                // be overwritten. Keep the original error, writer and scope.
                *failure.lock().unwrap_or_else(|e| e.into_inner()) = Some(e);
            }
            foreground
        })?;
        let configuration = runtime.configuration_root();
        let authority = runtime
            .origin
            .strip_prefix("https://")
            .ok_or(error("gateway_origin_invalid"))?
            .to_owned();
        let policy = Arc::new(
            GatewayBearerPolicy::new(
                &runtime.model_token,
                vec![authority.clone()],
                vec![runtime.origin.clone()],
            )
            .map_err(|_| error("gateway_model_authority_invalid"))?,
        );
        let journal = OwnedEnrollmentJournal::from_configuration(
            configuration.clone(),
            JournalBudget::default(),
        )
        .map_err(|_| error("existing_native_enrollment_required"))?;
        let service = EnrollmentService::recover_existing(
            journal,
            &runtime.admin_token,
            Sha256Digest::of_bytes(&runtime.model_token),
            vec![authority.clone()],
            Limits::default(),
        )
        .map_err(|e| error(e.code()))?;
        let lease = runtime
            .root
            .try_execution_lease()
            .map_err(|_| error("gateway_execution_busy"))?;
        let gateway_id = format!(
            "paired.{}",
            Sha256Digest::of_bytes(runtime.origin.as_bytes()).to_hex()
        )
        .try_into()
        .map_err(|_| error("gateway_namespace_invalid"))?;
        let tls = runtime.tls.clone();
        let admitted = Arc::new(Admitted {
            #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            state: runtime.root.clone(),
            #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            gateway: runtime.root.clone(),
            #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            runtime_root: None,
            #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            inputs: vec![],
            #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            absent_inputs: vec![],
            lease,
            _configuration: configuration,
            address: runtime.address,
            #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            native: None,
            fresh: Some(runtime),
        });
        admitted.validate()?;
        Ok(Loaded {
            admitted,
            service,
            tls,
            policy,
            host: authority,
            gateway_id,
        })
    }
    /// Ordinary native startup consumes a fresh complete committed chain. The
    /// state-root writer remains the ONLY configuration writer; imported device
    /// history is read there, never from the old child enrollment runtime.
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    fn load_committed(
        path: &Path,
        state: Arc<PrivateRoot>,
        gateway: Arc<PrivateRoot>,
    ) -> Result<Loaded, ForegroundError> {
        use crate::store::committed_runtime::{
            CommittedRuntimeSnapshot, RecoveredCommittedRuntime,
        };
        use styx_contracts::native_management::{NativeGatewayEndpointBinding, NativeRunDesired};
        let snapshot = Arc::new(
            CommittedRuntimeSnapshot::open(path)
                .map_err(|_| error("committed_configuration_required"))?,
        );
        if !snapshot
            .state()
            .desired
            .gateway
            .as_ref()
            .is_some_and(|desired| desired.run == NativeRunDesired::Running)
        {
            return Err(error("gateway_not_desired_running"));
        }
        let mut inputs = Vec::new();
        let deployment_i = read(&state, "deployment.json", &mut inputs)?;
        let config: Deployment = decode(&inputs[deployment_i])?;
        if config.schema != 1
            || config.mode != "create-local"
            || config
                .gateway
                .device_ingress
                .as_ref()
                .is_some_and(|i| i.enabled)
        {
            return Err(error("gateway_deployment_state_invalid_or_unsupported"));
        }
        #[derive(Deserialize)]
        struct HostBase {
            #[serde(rename = "baseDir")]
            base: PathBuf,
        }
        #[derive(Deserialize)]
        struct WithHost {
            host: HostBase,
        }
        let host_config: WithHost = decode(&inputs[deployment_i])?;
        let host_root = PrivateRoot::open(&host_config.host.base)
            .map_err(|_| error("gateway_protected_read"))?;
        snapshot
            .validate_legacy_owners(&state, &host_root)
            .map_err(|_| error("committed_owner_binding_changed"))?;
        let candidate = crate::release::verify_selected(snapshot.selection())
            .map_err(|_| error("committed_candidate_untrusted"))?;
        let endpoint: NativeGatewayEndpointBinding = serde_json::from_slice(
            snapshot
                .endpoint_binding()
                .ok_or(error("committed_gateway_endpoint_required"))?,
        )
        .map_err(|_| error("committed_gateway_endpoint_invalid"))?;
        let origin =
            url::Url::parse(&endpoint.origin).map_err(|_| error("gateway_origin_invalid"))?;
        let original =
            url::Url::parse(&config.gateway.url).map_err(|_| error("gateway_origin_invalid"))?;
        let ip: IpAddr = origin
            .host_str()
            .ok_or(error("gateway_loopback_required"))?
            .parse()
            .map_err(|_| error("gateway_loopback_required"))?;
        let listen: IpAddr = config
            .gateway
            .listen_host
            .as_deref()
            .unwrap_or("127.0.0.1")
            .parse()
            .map_err(|_| error("gateway_loopback_required"))?;
        let port = origin.port().ok_or(error("gateway_loopback_required"))?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_secs()).ok())
            .ok_or(error("gateway_clock_unproven"))?;
        let migration = snapshot
            .state()
            .migration
            .as_ref()
            .ok_or(error("committed_migration_binding_required"))?;
        if endpoint.schema != 1
            || endpoint.transaction_id != migration.transaction_id
            || endpoint.candidate_manifest_sha256 != snapshot.selection().manifest_sha256
            || endpoint.root_identity
                != match snapshot.root_identity() {
                    crate::store::RootIdentity::Linux { device, inode, uid } => {
                        styx_contracts::native_management::NativeRootIdentity::Linux {
                            device,
                            inode,
                            uid,
                        }
                    }
                }
            || endpoint.origin != original.origin().ascii_serialization()
            || origin.scheme() != "https"
            || original.scheme() != "https"
            || origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || !ip.is_ipv4()
            || !ip.is_loopback()
            || ip != listen
            || port < 1024
            || now < endpoint.not_before_unix
            || now >= endpoint.not_after_unix
        {
            return Err(error("committed_gateway_endpoint_invalid"));
        }
        let chain = snapshot
            .endpoint_chain()
            .ok_or(error("committed_gateway_endpoint_invalid"))?;
        let certs = rustls_pemfile::certs(&mut Cursor::new(chain))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| error("gateway_certificate_invalid"))?;
        let cert_i = read(&gateway, "certificate.pem", &mut inputs)?;
        let anchors = rustls_pemfile::certs(&mut Cursor::new(inputs[cert_i].raw.bytes()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| error("gateway_certificate_invalid"))?;
        if certs.len() != 2
            || anchors.len() != 1
            || endpoint.chain_sha256 != Sha256Digest::of_bytes(chain)
            || endpoint.leaf_sha256 != Sha256Digest::of_bytes(&certs[0])
            || endpoint.anchor_sha256 != Sha256Digest::of_bytes(&certs[1])
            || certs[1] != anchors[0]
        {
            return Err(error("gateway_tls_identity_invalid"));
        }
        let tls = Arc::new(
            GatewayServerTls::from_pem(
                chain,
                &PrivateKeyPem::from_protected_reader_bytes(
                    snapshot
                        .endpoint_key()
                        .ok_or(error("gateway_key_invalid"))?
                        .to_vec(),
                )
                .map_err(|_| error("gateway_key_invalid"))?,
                GatewayLeafPin::from_certificate_der(&certs[0]),
            )
            .map_err(|_| error("gateway_tls_identity_invalid"))?,
        );
        let model_i = read(&gateway, "model.token", &mut inputs)?;
        let admin_i = read(&gateway, "admin.token", &mut inputs)?;
        let authority = format!("{ip}:{port}");
        let policy = Arc::new(
            GatewayBearerPolicy::new(
                token(&inputs[model_i])?,
                vec![authority.clone()],
                vec![endpoint.origin.clone()],
            )
            .map_err(|_| error("gateway_model_authority_invalid"))?,
        );
        let owned_root = PrivateRoot::open(path).map_err(|_| error("gateway_protected_read"))?;
        if owned_root.identity() != snapshot.root_identity() {
            return Err(error("gateway_protected_input_changed"));
        }
        let writer = owned_root
            .try_existing_configuration_writer()
            .map_err(|_| error("existing_native_configuration_writer_required"))?;
        let configuration = OwnedConfigurationRoot::open_existing(owned_root, writer)
            .map_err(|_| error("existing_native_configuration_required"))?;
        let proof = RecoveredCommittedRuntime::reopen(configuration.clone(), snapshot.clone())
            .map_err(|_| error("committed_configuration_reopen_failed"))?;
        let journal = OwnedEnrollmentJournal::from_configuration(
            configuration.clone(),
            JournalBudget::default(),
        )
        .map_err(|_| error("existing_native_enrollment_required"))?;
        let mut service = EnrollmentService::recover_existing(
            journal,
            token(&inputs[admin_i])?,
            Sha256Digest::of_bytes(token(&inputs[model_i])?),
            vec![authority.clone()],
            Limits::default(),
        )
        .map_err(|e| error(e.code()))?;
        service
            .accept_committed_recovery(&proof)
            .map_err(|e| error(e.code()))?;
        let lease = gateway
            .try_execution_lease()
            .map_err(|_| error("gateway_execution_busy"))?;
        let gateway_id = format!(
            "paired.{}",
            Sha256Digest::of_bytes(endpoint.origin.as_bytes()).to_hex()
        )
        .try_into()
        .map_err(|_| error("gateway_namespace_invalid"))?;
        let admitted = Arc::new(Admitted {
            state,
            gateway,
            runtime_root: None,
            inputs,
            absent_inputs: vec![],
            lease,
            _configuration: configuration,
            address: SocketAddr::new(ip, port),
            native: Some(NativeCommittedAdmission {
                snapshot,
                host: host_root,
                candidate,
                proof,
            }),
            fresh: None,
        });
        admitted.validate()?;
        Ok(Loaded {
            admitted,
            service,
            tls,
            policy,
            host: authority,
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
        app_scope: Option<Arc<crate::app::HostScope>>,
        app_failure: Option<AppStartupFailure>,
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
            match app_scope {
                Some(scope) => load_fresh(&path, Some(scope), app_failure),
                None => load(&path),
            }
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
        // Preserve the MCP32MiB allocation and use the previously unreserved
        //16MiB for a second Host link. Both partitions still share the original
        //64MiB queue budget; no per-link limit or authentication is relaxed.
        let relay = RelayHandle::new(
            shared.clone(),
            gateway_id,
            GatewayEpoch::try_from(format!("gateway-{}", uuid::Uuid::new_v4()))
                .map_err(|_| error("gateway_epoch_invalid"))?,
            partition
                .clone()
                .try_acquire_many_owned(32 * 1024 * 1024)
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
        let app = EnrollmentHttp::new_paired(tls, shared, relay.clone(), mcp, vec![host])
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
            // Enrollment listener shutdown actually joined original relay jobs.
            unconfirmed_transport_drains: relay.unconfirmed_transport_drains(),
            sdk_detached_tasks_joined: lifecycle.sdk_detached_tasks_joined,
            worker_failure_observed: worker_failure || lifecycle.worker_failure_observed,
            listener_error_observed: facts.listener_error_observed,
        };
        if outcome.unconfirmed_owner_cleanups != 0 {
            emit(&events, &stop, "remote_owner_cleanup_unconfirmed");
        }
        if outcome.unconfirmed_transport_drains != 0 {
            emit(&events, &stop, "remote_transport_drain_unconfirmed");
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

    #[cfg(all(test, target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
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
                native: None,
                fresh: None,
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
