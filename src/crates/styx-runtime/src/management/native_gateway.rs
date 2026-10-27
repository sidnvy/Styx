//! Explicit fresh Gateway bootstrap. Migration proofs and old identities are
//! never fabricated. The final ready binding is published under the original
//! newly-created configuration writer, after private material and clock floor.
use serde::Serialize;
use std::{
    ffi::OsStr,
    fmt,
    path::{Path, PathBuf},
    sync::Arc,
};
use styx_contracts::identity::Sha256Digest;

/// Diagnostic observations only: never consulted for admission or settlement.
#[derive(Clone)]
pub(crate) struct StartupDiagnostic {
    started: std::time::Instant,
    stage: Arc<std::sync::Mutex<(&'static str, std::time::Instant)>>,
}
impl StartupDiagnostic {
    pub(crate) fn from_env() -> Option<Self> {
        (std::env::var_os("STYX_GATEWAY_STARTUP_DIAGNOSTICS").as_deref() == Some(OsStr::new("1")))
            .then(|| Self {
                started: std::time::Instant::now(),
                stage: Arc::new(std::sync::Mutex::new((
                    "scheduled",
                    std::time::Instant::now(),
                ))),
            })
    }
    pub(crate) fn mark(&self, stage: &'static str) {
        let (previous, elapsed) = {
            let mut current = self.stage.lock().unwrap_or_else(|e| e.into_inner());
            let previous = current.0;
            let elapsed = current.1.elapsed().as_millis();
            *current = (stage, std::time::Instant::now());
            (previous, elapsed)
        };
        self.emit(stage, previous, elapsed);
    }
    pub(crate) fn report(&self, event: &'static str) {
        let (stage, elapsed) = {
            let current = self.stage.lock().unwrap_or_else(|e| e.into_inner());
            (current.0, current.1.elapsed().as_millis())
        };
        self.emit(event, stage, elapsed);
    }
    fn emit(&self, event: &'static str, stage: &'static str, elapsed: u128) {
        // All labels are compile-time constants; no paths, tokens or error text.
        use std::io::Write as _;
        // Logging failure must not replace the original startup outcome.
        let _ = writeln!(
            std::io::stderr().lock(),
            "{}",
            serde_json::json!({"event":"styx_gateway_startup", "stage":event,
            "previous_stage":stage, "stage_elapsed_ms":elapsed,
            "elapsed_ms":self.started.elapsed().as_millis()})
        );
    }
}

#[derive(Serialize)]
pub struct BootstrapReport {
    pub schema: u16,
    pub operation: &'static str,
    pub state_dir: PathBuf,
    pub origin: String,
    pub candidate_manifest_sha256: Sha256Digest,
    pub certificate_pin: String,
    pub endpoint_not_after_unix: i64,
    pub service_started: bool,
    pub runtime_health: &'static str,
}
/// Retains uncertain bootstrap resources until the caller explicitly tears down
/// this entire scope. Formatting is static and never contains key material.
#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
    all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"),
    all(
        target_os = "macos",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
enum Retained {
    Root {
        _failure: crate::store::native_root::NativeRootFailure,
    },
    Fresh {
        _root: Box<crate::store::native_root::FreshNativeRoot>,
    },
    Binding {
        _binding: crate::store::native_root::NativeRootBinding,
    },
    TransactionOpen {
        _failure: crate::store::native_transaction::NativeTransactionOpenFailure,
    },
    Transactions {
        _transactions: Arc<std::sync::Mutex<crate::store::native_transaction::NativeTransactions>>,
    },
}
#[must_use]
pub struct BootstrapError {
    code: &'static str,
    exit: u8,
    #[cfg(any(
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
        all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"),
        all(
            target_os = "macos",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    _retained: Option<Box<Retained>>,
    // Declared last so original writer/resources drop before the App lease.
    _app_scope: Option<Arc<crate::app::HostScope>>,
}
impl BootstrapError {
    fn with_app_scope(mut self, scope: Option<Arc<crate::app::HostScope>>) -> Self {
        self._app_scope = scope;
        self
    }
    pub fn code(&self) -> &'static str {
        self.code
    }
    pub fn exit_code(&self) -> u8 {
        self.exit
    }
    fn new(code: &'static str, exit: u8) -> Self {
        Self {
            code,
            exit,
            _app_scope: None,
            #[cfg(any(
                all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
                all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"),
                all(
                    target_os = "macos",
                    any(target_arch = "x86_64", target_arch = "aarch64")
                )
            ))]
            _retained: None,
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
    fn retaining(mut self, retained: Retained) -> Self {
        self._retained = Some(Box::new(retained));
        self
    }
    #[cfg(any(
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
        all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"),
        all(
            target_os = "macos",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    fn root(failure: crate::store::native_root::NativeRootFailure) -> Self {
        use crate::store::native_root::NativeRootError;
        let (code, exit) = match failure.error() {
            NativeRootError::AlreadyExists => ("fresh_gateway_already_exists", 2),
            NativeRootError::InvalidInput => ("fresh_gateway_input_invalid", 2),
            NativeRootError::Unsupported => ("fresh_gateway_platform_unsupported", 3),
            NativeRootError::Unknown => ("fresh_gateway_persistence_unknown", 4),
        };
        Self {
            code,
            exit,
            _app_scope: None,
            _retained: Some(Box::new(Retained::Root { _failure: failure })),
        }
    }
}
impl fmt::Debug for BootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code)
    }
}
impl fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code)
    }
}
impl std::error::Error for BootstrapError {}

pub async fn bootstrap(
    parent: &Path,
    name: &OsStr,
    deployment_file: &Path,
    runtime_selection_file: &Path,
) -> Result<BootstrapReport, BootstrapError> {
    bootstrap_owned(parent, name, deployment_file, runtime_selection_file, None)
        .await
        .map(|(report, _candidate)| report)
}

/// The App supplies its retained scope, never a wire-selected role or manager.
pub(crate) async fn bootstrap_for_app(
    scope: Arc<crate::app::HostScope>,
    deployment_file: &Path,
    runtime_selection_file: &Path,
) -> Result<(BootstrapReport, Arc<crate::release::VerifiedNativeRelease>), BootstrapError> {
    let path = scope.state_dir().to_owned();
    let parent = path.parent().ok_or_else(|| {
        BootstrapError::new("fresh_gateway_input_invalid", 2).with_app_scope(Some(scope.clone()))
    })?;
    let name = path.file_name().ok_or_else(|| {
        BootstrapError::new("fresh_gateway_input_invalid", 2).with_app_scope(Some(scope.clone()))
    })?;
    bootstrap_owned(
        parent,
        name,
        deployment_file,
        runtime_selection_file,
        Some(scope),
    )
    .await
}

async fn bootstrap_owned(
    parent: &Path,
    name: &OsStr,
    deployment_file: &Path,
    runtime_selection_file: &Path,
    app_scope: Option<Arc<crate::app::HostScope>>,
) -> Result<(BootstrapReport, Arc<crate::release::VerifiedNativeRelease>), BootstrapError> {
    #[cfg(any(
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
        all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"),
        all(
            target_os = "macos",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    {
        static JOBS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
        let permit = JOBS.try_acquire().map_err(|_| {
            BootstrapError::new("fresh_gateway_busy", 3).with_app_scope(app_scope.clone())
        })?;
        let (parent, name, deployment, selection) = (
            parent.to_path_buf(),
            name.to_owned(),
            deployment_file.to_path_buf(),
            runtime_selection_file.to_path_buf(),
        );
        // The spawned job owns the permit until real completion even if its
        // response waiter is dropped. No second writer or entropy retry.
        let retained = app_scope.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            platform::bootstrap(&parent, &name, &deployment, &selection, app_scope.clone())
                .map_err(|error| error.with_app_scope(app_scope))
        })
        .await
        .map_err(|_| {
            BootstrapError::new("fresh_gateway_worker_failed", 4).with_app_scope(retained)
        })?
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
        let _ = (parent, name, deployment_file, runtime_selection_file);
        Err(BootstrapError::new("fresh_gateway_platform_unsupported", 3).with_app_scope(app_scope))
    }
}

#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "macos",
    target_os = "windows"
))]
pub(crate) use platform::open_existing_for_service;
#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
    all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"),
    all(
        target_os = "macos",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
pub(crate) use platform::{
    FreshGatewayRuntime, inspect_pre_invite_for_app, open_existing,
    open_existing_for_app_diagnostic,
};
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
        release::{self, VerifiedNativeRelease},
        store::{
            OwnedConfigurationRoot, PrivateRoot, RawFile, RootIdentity,
            native_root::{self, FreshGatewayFiles},
            native_transaction::NativeTransactions,
        },
        tls::{self, GatewayLeafPin, GatewayServerTls},
    };
    use serde::{Deserialize, Serialize};
    use std::{
        collections::BTreeMap,
        io::Cursor,
        net::{IpAddr, SocketAddr},
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };
    use styx_contracts::{management::ReaderContract, native_management::*};
    use styx_core::management::transaction::DurableStage;
    use zeroize::Zeroizing;
    const LIMIT: usize = 1024 * 1024;
    const READY: &str = "gateway-ready-v1.json";
    const NAMES: [&str; 6] = [
        "gateway-ca.pem",
        "gateway-ca-key.pem",
        "gateway-chain.pem",
        "gateway-key.pem",
        "gateway-admin.token",
        "gateway-model.token",
    ];
    fn bad() -> BootstrapError {
        BootstrapError::new("fresh_gateway_input_invalid", 2)
    }
    fn changed() -> BootstrapError {
        BootstrapError::new("fresh_gateway_binding_changed", 4)
    }
    // Map only the identity observed by the retained PrivateRoot. Ready JSON
    // cannot choose a foreign OS root or alias another platform's identity.
    fn native_identity(root: &PrivateRoot) -> NativeRootIdentity {
        match root.identity() {
            RootIdentity::Linux { device, inode, uid } => {
                NativeRootIdentity::Linux { device, inode, uid }
            }
            #[cfg(target_os = "macos")]
            RootIdentity::Macos { device, inode, uid } => {
                NativeRootIdentity::Macos { device, inode, uid }
            }
            #[cfg(target_os = "windows")]
            RootIdentity::Windows {
                volume_serial,
                file_id,
                owner_sid,
            } => NativeRootIdentity::Windows {
                volume_serial,
                file_id,
                owner_sid,
            },
        }
    }
    fn now() -> Result<u64, BootstrapError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|_| BootstrapError::new("fresh_gateway_clock_unproven", 3))
    }
    fn private_input(path: &Path) -> Result<(PrivateRoot, RawFile), BootstrapError> {
        if !path.is_absolute() {
            return Err(bad());
        }
        let root = PrivateRoot::open(path.parent().ok_or_else(bad)?).map_err(|_| bad())?;
        let raw = root
            .read_raw(path.file_name().ok_or_else(bad)?, LIMIT)
            .map_err(|_| bad())?;
        Ok((root, raw))
    }
    fn reobserve(root: &PrivateRoot, raw: &RawFile) -> Result<(), BootstrapError> {
        let after = root
            .read_raw(raw.relative_path(), LIMIT)
            .map_err(|_| changed())?;
        if after.observation() != raw.observation() || after.bytes() != raw.bytes() {
            return Err(changed());
        }
        Ok(())
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Deployment {
        schema: u16,
        mode: String,
        gateway: Gateway,
        #[serde(default)]
        host: Option<Box<serde_json::value::RawValue>>,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "camelCase")]
    struct Gateway {
        url: String,
        listen_host: Option<String>,
        #[serde(default)]
        allow_remote_hosts: bool,
    }
    fn endpoint(deployment: &[u8]) -> Result<(String, SocketAddr), BootstrapError> {
        let d: Deployment = serde_json::from_slice(deployment).map_err(|_| bad())?;
        let url = url::Url::parse(&d.gateway.url).map_err(|_| bad())?;
        let ip: IpAddr = url.host_str().ok_or_else(bad)?.parse().map_err(|_| bad())?;
        let listen: IpAddr = d
            .gateway
            .listen_host
            .as_deref()
            .unwrap_or("127.0.0.1")
            .parse()
            .map_err(|_| bad())?;
        let port = url.port().ok_or_else(bad)?;
        if d.schema != 1
            || d.mode != "create-local"
            || d.host.is_some()
            || d.gateway.allow_remote_hosts
            || url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
            || !ip.is_ipv4()
            || !ip.is_loopback()
            || ip != listen
            || port < 1024
        {
            return Err(bad());
        }
        Ok((
            url.origin().ascii_serialization(),
            SocketAddr::new(ip, port),
        ))
    }
    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct ReadyBinding {
        schema: u16,
        root_identity: NativeRootIdentity,
        scope_generation: Sha256Digest,
        deployment_raw_sha256: Sha256Digest,
        runtime: NativeRuntimeSelection,
        origin: String,
        not_before_unix: i64,
        not_after_unix: i64,
        files: BTreeMap<String, Sha256Digest>,
    }
    fn secret() -> Result<Zeroizing<Vec<u8>>, BootstrapError> {
        let mut raw = Zeroizing::new([0u8; 32]);
        getrandom::fill(raw.as_mut())
            .map_err(|_| BootstrapError::new("fresh_gateway_entropy_unavailable", 3))?;
        Ok(Zeroizing::new(hex::encode(*raw).into_bytes()))
    }
    pub(super) fn bootstrap(
        parent: &Path,
        name: &OsStr,
        deployment_file: &Path,
        selection_file: &Path,
        app_scope: Option<Arc<crate::app::HostScope>>,
    ) -> Result<(BootstrapReport, Arc<VerifiedNativeRelease>), BootstrapError> {
        if let Some(scope) = &app_scope {
            if scope.state_dir() != parent.join(name) {
                return Err(bad());
            }
            scope.validate().map_err(|_| changed())?;
        }
        let (deployment_root, deployment) = private_input(deployment_file)?;
        let (selection_root, selection_raw) = private_input(selection_file)?;
        let (origin, _) = endpoint(deployment.bytes())?;
        let selection: NativeRuntimeSelection =
            serde_json::from_slice(selection_raw.bytes()).map_err(|_| bad())?;
        let candidate = Arc::new(
            release::verify_selected(&selection)
                .map_err(|_| BootstrapError::new("fresh_gateway_candidate_untrusted", 2))?,
        );
        // Match the original selection directly. The publication getter would
        // repeat this complete inventory walk twice at the same boundary.
        candidate
            .revalidate_matches_selection(&selection)
            .map_err(|_| bad())?;
        // All validation/crypto precedes root creation. This never rotates or
        // repairs an existing CA; an interrupted bootstrap must remain closed.
        let clock = now()?;
        let ca = tls::generate_gateway_ca(
            clock,
            clock.saturating_sub(60),
            clock.checked_add(3650 * 86400).ok_or_else(bad)?,
        )
        .map_err(|_| BootstrapError::new("fresh_gateway_ca_generation_failed", 3))?;
        let leaf = tls::issue_server_leaf(
            &ca.certificate_pem,
            &ca.private_key,
            &ca.anchor_pin,
            &origin,
            clock,
        )
        .map_err(|_| BootstrapError::new("fresh_gateway_leaf_issuance_failed", 3))?;
        if leaf.not_before_unix < ca.not_before_unix || leaf.not_after_unix > ca.not_after_unix {
            return Err(BootstrapError::new("fresh_gateway_validity_invalid", 3));
        }
        let admin = secret()?;
        let model = secret()?;
        if *admin == *model {
            return Err(BootstrapError::new("fresh_gateway_entropy_collision", 3));
        }
        let parent_root = PrivateRoot::open(parent).map_err(|_| bad())?;
        reobserve(&deployment_root, &deployment)?;
        reobserve(&selection_root, &selection_raw)?;
        candidate.revalidate().map_err(|_| changed())?;
        if let Some(scope) = &app_scope {
            scope.validate().map_err(|_| changed())?;
        }
        let fresh = native_root::create_fresh(&parent_root, name).map_err(BootstrapError::root)?;
        if let Some(scope) = &app_scope
            && scope.bind().is_err()
        {
            return Err(changed().retaining(Retained::Fresh {
                _root: Box::new(fresh),
            }));
        }
        let public = [
            ca.certificate_pem.as_slice(),
            ca.private_key.as_protected_bytes(),
            leaf.certificate_chain_pem.as_slice(),
            leaf.private_key.as_protected_bytes(),
            admin.as_slice(),
            model.as_slice(),
        ];
        // Even an encoding failure after fresh-root creation retains its
        // original writer; it is never reported as a clean rejected input.
        let metadata = (|| {
            let ready = ReadyBinding {
                schema: 1,
                root_identity: fresh.marker().root_identity.clone(),
                scope_generation: fresh.marker().scope_generation,
                deployment_raw_sha256: Sha256Digest::of_bytes(deployment.bytes()),
                runtime: selection.clone(),
                origin: origin.clone(),
                not_before_unix: leaf.not_before_unix,
                not_after_unix: leaf.not_after_unix,
                files: NAMES
                    .iter()
                    .zip(public)
                    .map(|(n, b)| (n.to_string(), Sha256Digest::of_bytes(b)))
                    .collect(),
            };
            let ready_bytes = serde_json::to_vec(&ready).map_err(|_| bad())?;
            let mut extensions = BTreeMap::new();
            extensions.insert(
                "fresh_gateway_binding_v1".into(),
                serde_json::value::to_raw_value(&Sha256Digest::of_bytes(&ready_bytes))
                    .map_err(|_| bad())?,
            );
            extensions.insert(
                "runtime_selection_v1".into(),
                serde_json::value::to_raw_value(&selection).map_err(|_| bad())?,
            );
            let state = NativeState {
                schema: NATIVE_STATE_SCHEMA,
                kind: NativeStateKind::StyxDesiredState,
                runtime_format: NativeRuntimeFormat::NativeRustV1,
                reader_contract: ReaderContract::NativeManagementStateV1,
                scope_generation: fresh.marker().scope_generation,
                deployment_raw_sha256: ready.deployment_raw_sha256,
                mode: NativeDeploymentMode::CreateLocal,
                revision: 0,
                last_transaction: None,
                desired: NativeDesired {
                    gateway: Some(NativeComponentDesired {
                        manager: if app_scope.is_some() {
                            NativeManager::AppManaged
                        } else {
                            NativeManager::ForegroundCli
                        },
                        run: NativeRunDesired::Stopped,
                        autostart: NativeAutostartDesired::Disabled,
                    }),
                    host: None,
                },
                migration: None,
                extensions,
            };
            Ok::<_, BootstrapError>((ready_bytes, state))
        })();
        let (ready_bytes, state) = match metadata {
            Ok(value) => value,
            Err(error) => {
                return Err(error.retaining(Retained::Fresh {
                    _root: Box::new(fresh),
                }));
            }
        };
        let material = FreshGatewayFiles {
            certificate_pem: &ca.certificate_pem,
            ca_private_key_pem: ca.private_key.as_protected_bytes(),
            endpoint_chain_pem: &leaf.certificate_chain_pem,
            endpoint_private_key_pem: leaf.private_key.as_protected_bytes(),
            admin_token: &admin,
            model_token: &model,
            ready_binding: &ready_bytes,
        };
        let binding = fresh
            .initialize_gateway(deployment.bytes(), &state, material, clock)
            .map_err(BootstrapError::root)?;
        // No daemon launched, no runtime-health claim. Reading the formal state
        // is complete before deliberately releasing this successful writer.
        if let Some(scope) = &app_scope
            && scope.validate().is_err()
        {
            return Err(changed().retaining(Retained::Binding { _binding: binding }));
        }
        let _ = binding;
        Ok((
            BootstrapReport {
                schema: 1,
                operation: "fresh_gateway_bootstrap",
                state_dir: parent.join(name),
                origin,
                candidate_manifest_sha256: selection.manifest_sha256,
                certificate_pin: ca.anchor_pin.as_hex(),
                endpoint_not_after_unix: leaf.not_after_unix,
                service_started: false,
                runtime_health: "not_started",
            },
            candidate,
        ))
    }

    pub(crate) struct FreshGatewayRuntime {
        pub(crate) root: Arc<PrivateRoot>,
        pub(crate) tls: Arc<GatewayServerTls>,
        pub(crate) address: SocketAddr,
        pub(crate) origin: String,
        pub(crate) admin_token: Zeroizing<Vec<u8>>,
        pub(crate) model_token: Zeroizing<Vec<u8>>,
        transactions: Arc<std::sync::Mutex<NativeTransactions>>,
        candidate: Arc<VerifiedNativeRelease>,
        inputs: Vec<RawFile>,
        state_raw: Vec<u8>,
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "macos",
            target_os = "windows"
        ))]
        service_tip: std::sync::OnceLock<crate::store::native_live_tip::ServiceTip>,
        app_scope: Option<Arc<crate::app::HostScope>>,
    }
    impl FreshGatewayRuntime {
        pub(crate) fn configuration_root(&self) -> OwnedConfigurationRoot {
            self.transactions
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .configuration_root()
        }
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "macos",
            target_os = "windows"
        ))]
        pub(crate) fn service_transactions(&self) -> Arc<std::sync::Mutex<NativeTransactions>> {
            self.transactions.clone()
        }
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "macos",
            target_os = "windows"
        ))]
        pub(crate) fn enable_service_control(
            &self,
            scope: Arc<crate::platform::native_service::ServiceScope>,
        ) -> Result<(), BootstrapError> {
            if crate::store::PrivateRoot::open(scope.state_dir())
                .map_err(|_| changed())?
                .identity()
                != self.root.identity()
            {
                return Err(changed());
            }
            self.validate()?;
            let tip =
                crate::store::native_live_tip::ServiceTip::open(scope).map_err(|_| changed())?;
            self.service_tip.set(tip).map_err(|_| changed())
        }
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "macos",
            target_os = "windows"
        ))]
        pub(crate) fn service_tip_status(
            &self,
        ) -> Result<(), crate::store::native_live_tip::LiveTipError> {
            self.service_tip
                .get()
                .map_or(Ok(()), |tip| tip.revalidate())
        }
        pub(crate) fn validate(&self) -> Result<(), BootstrapError> {
            if let Some(scope) = &self.app_scope {
                scope.validate().map_err(|_| changed())?;
            }
            self.configuration_root()
                .ensure_admission()
                .map_err(|_| changed())?;
            #[cfg(any(
                all(target_os = "linux", target_env = "gnu"),
                target_os = "macos",
                target_os = "windows"
            ))]
            if let Some(tip) = self.service_tip.get() {
                tip.revalidate().map_err(|_| changed())?;
                self.candidate.revalidate().map_err(|_| changed())?;
            } else {
                self.validate_original_state()?;
            }
            #[cfg(not(any(
                all(target_os = "linux", target_env = "gnu"),
                target_os = "macos",
                target_os = "windows"
            )))]
            self.validate_original_state()?;
            for raw in &self.inputs {
                reobserve(&self.root, raw)?;
            }
            Ok(())
        }
        fn validate_original_state(&self) -> Result<(), BootstrapError> {
            let transactions = self.transactions.lock().unwrap_or_else(|e| e.into_inner());
            let state = transactions.readstate().map_err(|_| changed())?;
            if state.raw_bytes() != self.state_raw {
                return Err(changed());
            }
            let current = crate::store::native_host_snapshot::validated_runtime_selection(
                &self.root,
                &state,
                transactions.marker(),
            )
            .map_err(|_| changed())?;
            self.candidate
                .revalidate_matches_selection(&current)
                .map_err(|_| changed())
        }
    }
    pub(crate) fn open_existing(path: &Path) -> Result<FreshGatewayRuntime, BootstrapError> {
        open_existing_owned(
            path,
            None,
            None,
            None,
            #[cfg(any(
                all(target_os = "linux", target_env = "gnu"),
                target_os = "macos",
                target_os = "windows"
            ))]
            None,
        )
    }
    pub(crate) fn open_existing_for_app(
        scope: Arc<crate::app::HostScope>,
    ) -> Result<FreshGatewayRuntime, BootstrapError> {
        open_existing_for_app_diagnostic(scope, None, None)
    }
    pub(crate) fn open_existing_for_app_diagnostic(
        scope: Arc<crate::app::HostScope>,
        diagnostic: Option<&super::StartupDiagnostic>,
        retained_candidate: Option<Arc<VerifiedNativeRelease>>,
    ) -> Result<FreshGatewayRuntime, BootstrapError> {
        let path = scope.state_dir().to_owned();
        open_existing_owned(
            &path,
            Some(scope.clone()),
            diagnostic,
            retained_candidate,
            #[cfg(any(
                all(target_os = "linux", target_env = "gnu"),
                target_os = "macos",
                target_os = "windows"
            ))]
            None,
        )
        .map_err(|error| error.with_app_scope(Some(scope)))
    }
    /// Original ready/canonical/TLS/C08 checks and enrollment inspection share
    /// this one existing coordinator. No bootstrap, namespace claim or pairing.
    pub(crate) fn inspect_pre_invite_for_app(
        scope: Arc<crate::app::HostScope>,
        selection_file: &Path,
    ) -> Result<(), BootstrapError> {
        let runtime = open_existing_for_app(scope.clone())?;
        let checked = (|| {
            runtime.validate()?;
            let (selection_root, raw) = private_input(selection_file)?;
            let supplied: NativeRuntimeSelection =
                serde_json::from_slice(raw.bytes()).map_err(|_| bad())?;
            if runtime
                .candidate
                .runtime_selection()
                .map_err(|_| changed())?
                != supplied
            {
                return Err(BootstrapError::new(
                    "original_runtime_selection_required",
                    2,
                ));
            }
            runtime
                .configuration_root()
                .require_pre_invite_enrollment(now()?.checked_mul(1000).ok_or_else(bad)?)
                .map_err(|_| BootstrapError::new("app_local_checkpoint_refused", 3))?;
            reobserve(&selection_root, &raw)?;
            runtime.validate()?;
            Ok(())
        })();
        checked.map_err(|error| {
            error
                .retaining(Retained::Transactions {
                    _transactions: runtime.transactions,
                })
                .with_app_scope(Some(scope))
        })
    }
    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "macos",
        target_os = "windows"
    ))]
    pub(crate) fn open_existing_for_service(
        scope: Arc<crate::platform::native_service::ServiceScope>,
    ) -> Result<FreshGatewayRuntime, BootstrapError> {
        scope.validate().map_err(|_| changed())?;
        let path = scope.state_dir().to_owned();
        open_existing_owned(&path, None, None, None, Some(scope))
    }
    fn open_existing_owned(
        path: &Path,
        app_scope: Option<Arc<crate::app::HostScope>>,
        diagnostic: Option<&super::StartupDiagnostic>,
        retained_candidate: Option<Arc<VerifiedNativeRelease>>,
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "macos",
            target_os = "windows"
        ))]
        service_scope: Option<Arc<crate::platform::native_service::ServiceScope>>,
    ) -> Result<FreshGatewayRuntime, BootstrapError> {
        // Retained verification is an App-owned startup input, never a CLI or
        // service bypass. It cannot replace this original scope/coordinator.
        if retained_candidate.is_some() && app_scope.is_none() {
            return Err(bad());
        }
        if let Some(scope) = &app_scope {
            if scope.state_dir() != path {
                return Err(bad());
            }
            scope.validate().map_err(|_| changed())?;
        }
        if !path.is_absolute() {
            return Err(bad());
        }
        let root = Arc::new(PrivateRoot::open(path).map_err(|_| bad())?);
        let ready_raw = root
            .read_raw(READY, LIMIT)
            .map_err(|_| BootstrapError::new("fresh_gateway_bootstrap_incomplete", 3))?;
        let ready: ReadyBinding = serde_json::from_slice(ready_raw.bytes()).map_err(|_| bad())?;
        let deployment = root.read_raw("deployment.json", LIMIT).map_err(|_| bad())?;
        let (origin, address) = endpoint(deployment.bytes())?;
        let clock = i64::try_from(now()?).map_err(|_| bad())?;
        if ready.schema != 1
            || ready.root_identity != native_identity(&root)
            || ready.origin != origin
            || ready.deployment_raw_sha256 != Sha256Digest::of_bytes(deployment.bytes())
            || clock < ready.not_before_unix
            || clock >= ready.not_after_unix
            || ready.files.len() != NAMES.len()
            || NAMES.iter().any(|n| !ready.files.contains_key(*n))
        {
            return Err(bad());
        }
        let writer = root
            .try_existing_configuration_writer()
            .map_err(|_| BootstrapError::new("fresh_gateway_configuration_busy", 3))?;
        let owned = PrivateRoot::open(path).map_err(|_| changed())?;
        if owned.identity() != root.identity() {
            return Err(changed());
        }
        let binding = native_root::reopen_native(owned, writer).map_err(BootstrapError::root)?;
        if binding.marker().scope_generation != ready.scope_generation {
            return Err(changed().retaining(Retained::Binding { _binding: binding }));
        }
        let mut transactions = match NativeTransactions::open(binding) {
            Ok(transactions) => transactions,
            Err(failure) => {
                return Err(changed().retaining(Retained::TransactionOpen { _failure: failure }));
            }
        };
        // Every failure from this point keeps the exact coordinator, including
        // any maintenance retained by failed durable completed-tip recovery.
        let loaded: Result<_, BootstrapError> = (|| {
            let state = transactions.readstate().map_err(|_| changed())?;
            let state_value = state.state();
            let expected_binding: Sha256Digest = serde_json::from_str(
                state_value
                    .extensions
                    .get("fresh_gateway_binding_v1")
                    .ok_or_else(bad)?
                    .get(),
            )
            .map_err(|_| bad())?;
            let selected = crate::store::native_host_snapshot::validated_runtime_selection(
                &root,
                &state,
                transactions.marker(),
            )
            .map_err(|_| changed())?;
            let bootstrap = state_value
                .runtime_update()
                .map_err(|_| bad())?
                .map_or_else(|| selected.clone(), |update| update.bootstrap_runtime);
            let retained = retained_candidate.is_some();
            if let Some(d) = diagnostic {
                d.mark(if retained {
                    "retained_candidate"
                } else {
                    "verify_selected"
                });
            }
            let candidate = match retained_candidate {
                Some(candidate) => {
                    // Same formal C08 object from this App's successful bootstrap.
                    // A mismatch is a closed failure, never a cold-load fallback.
                    candidate
                        .revalidate_matches_selection(&selected)
                        .map_err(|_| changed())?;
                    candidate
                }
                None => Arc::new(
                    release::verify_selected(&selected)
                        .map_err(|_| BootstrapError::new("fresh_gateway_candidate_untrusted", 2))?,
                ),
            };
            if let Some(d) = diagnostic {
                d.mark(if retained {
                    "retained_candidate_done"
                } else {
                    "verify_selected_done"
                });
            }
            // Formal verification or exact-selection revalidation authenticated
            // this same retained manifest.
            // Reader support is immutable signed metadata; load/reconcile still
            // perform their complete release validation before admission.
            if !candidate
                .manifest()
                .minimum_reader
                .supports_state_reader(state_value.reader_contract)
            {
                return Err(bad());
            }
            let manager = if app_scope.is_some() {
                NativeManager::AppManaged
            } else {
                NativeManager::ForegroundCli
            };
            #[cfg(any(
                all(target_os = "linux", target_env = "gnu"),
                target_os = "macos",
                target_os = "windows"
            ))]
            let service_owned = if let Some(scope) = &service_scope {
                if app_scope.is_some()
                    || scope.state_dir() != path
                    || scope.role() != crate::platform::native_service::ServiceRole::Gateway
                {
                    return Err(bad());
                }
                scope.validate().map_err(|_| changed())?;
                true
            } else {
                false
            };
            #[cfg(not(any(
                all(target_os = "linux", target_env = "gnu"),
                target_os = "macos",
                target_os = "windows"
            )))]
            let service_owned = false;
            let manager = if service_owned {
                NativeManager::PersistentService
            } else {
                manager
            };
            if state_value.has_migration_binding()
                || state_value.mode != NativeDeploymentMode::CreateLocal
                || state_value.desired.host.is_some()
                || state_value.desired.gateway.as_ref().is_none_or(|d| {
                    d.manager != manager
                        || d.run != NativeRunDesired::Running
                        || (!service_owned && d.autostart != NativeAutostartDesired::Disabled)
                })
                || expected_binding != Sha256Digest::of_bytes(ready_raw.bytes())
                || bootstrap != ready.runtime
            {
                return Err(bad());
            }
            // Existing C07 journal bytes can fence startup. Reconcile only the exact
            // already COMMITTED pure configuration tip, never pending native work.
            if transactions
                .configuration_root()
                .ensure_admission()
                .is_err()
            {
                let last = state_value.last_transaction.as_ref().ok_or_else(changed)?;
                let tx = transactions
                    .query(&last.transaction_id)
                    .map_err(|_| changed())?
                    .ok_or_else(changed)?;
                if tx
                    .phase_receipts
                    .last()
                    .is_none_or(|r| r.stage != DurableStage::Committed)
                {
                    return Err(changed());
                }
                transactions
                    .recover_original(&last.transaction_id)
                    .map_err(|_| changed())?;
            }
            transactions
                .configuration_root()
                .ensure_admission()
                .map_err(|_| changed())?;
            let mut inputs = vec![ready_raw, deployment];
            for name in NAMES {
                let raw = root.read_raw(name, LIMIT).map_err(|_| changed())?;
                if Sha256Digest::of_bytes(raw.bytes()) != ready.files[name] {
                    return Err(changed());
                }
                inputs.push(raw);
            }
            let chain = &inputs[4];
            let certs = rustls_pemfile::certs(&mut Cursor::new(chain.bytes()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| bad())?;
            let anchors = rustls_pemfile::certs(&mut Cursor::new(inputs[2].bytes()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| bad())?;
            if certs.len() != 2 || anchors.len() != 1 || certs[1] != anchors[0] {
                return Err(bad());
            }
            let key = tls::PrivateKeyPem::from_protected_reader_bytes(inputs[5].bytes().to_vec())
                .map_err(|_| bad())?;
            let tls = Arc::new(
                GatewayServerTls::from_pem(
                    chain.bytes(),
                    &key,
                    GatewayLeafPin::from_certificate_der(&certs[0]),
                )
                .map_err(|_| bad())?,
            );
            let admin_token = Zeroizing::new(inputs[6].bytes().to_vec());
            let model_token = Zeroizing::new(inputs[7].bytes().to_vec());
            Ok((
                tls,
                admin_token,
                model_token,
                inputs,
                state.raw_bytes().to_vec(),
                candidate,
            ))
        })();
        let (tls, admin_token, model_token, inputs, state_raw, candidate) = match loaded {
            Ok(value) => value,
            Err(error) => {
                return Err(error.retaining(Retained::Transactions {
                    _transactions: Arc::new(std::sync::Mutex::new(transactions)),
                }));
            }
        };
        let runtime = FreshGatewayRuntime {
            root,
            tls,
            address,
            origin,
            admin_token,
            model_token,
            transactions: Arc::new(std::sync::Mutex::new(transactions)),
            candidate,
            inputs,
            state_raw,
            #[cfg(any(
                all(target_os = "linux", target_env = "gnu"),
                target_os = "macos",
                target_os = "windows"
            ))]
            service_tip: std::sync::OnceLock::new(),
            app_scope,
        };
        if let Some(d) = diagnostic {
            d.mark("fresh_validate");
        }
        if let Err(error) = runtime.validate() {
            return Err(error.retaining(Retained::Transactions {
                _transactions: runtime.transactions,
            }));
        }
        if let Some(d) = diagnostic {
            d.mark("fresh_validate_done");
        }
        Ok(runtime)
    }
}
