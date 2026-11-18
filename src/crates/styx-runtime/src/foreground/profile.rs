//! Native foreground profile. Signed payload authority is distinct
//! from private mutable configuration; no credential, identity or pointer writes.
use crate::{
    crypto::{DevicePrivateKey, DevicePublicKey, PublisherFingerprint},
    host::link::{LinkEndpoint, SecretBearer},
    providers::codex::OwnedExecutorConfig,
    store::{PinnedExecutable, PrivateRoot},
    tls::{GatewayClientTls, TrustAnchorPin},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::Cursor,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use styx_contracts::{
    identity::{DeviceId, GatewayId, Sha256Digest},
    native_release::NativeExternalWorker,
};
#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "windows",
    target_os = "macos"
))]
#[path = "profile_fresh.rs"]
mod fresh;
#[cfg(all(test, target_os = "linux", target_env = "gnu"))]
pub(crate) use fresh::connection_profile as fresh_connection_profile;
#[path = "profile_release.rs"]
mod release;
const JSON_LIMIT: usize = 1024 * 1024;
#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum ProfileError {
    #[error("native profile unsupported on this platform or authentication mode")]
    Unsupported,
    #[error("executor environment is unsupported")]
    UnsupportedExecutorEnvironment,
    #[error("protected native configuration could not be read")]
    ProtectedRead,
    #[error("native configuration or binding invalid")]
    Invalid,
    #[error("publisher signature or active release provenance invalid")]
    UntrustedRelease,
    #[error("protected native input changed")]
    Changed,
    #[error("persistent service configuration transaction is pending")]
    ManagementBusy,
    #[error("persistent service has a committed stop request")]
    StopRequested,
}
impl ProfileError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unsupported => "native_profile_unsupported",
            Self::UnsupportedExecutorEnvironment => "unsupported_executor_environment",
            Self::ProtectedRead => "native_profile_protected_read",
            Self::Invalid => "native_profile_invalid",
            Self::UntrustedRelease => "native_release_untrusted",
            Self::Changed => "native_profile_changed",
            Self::ManagementBusy => "native_service_configuration_pending",
            Self::StopRequested => "native_service_stop_requested",
        }
    }
}
#[derive(Clone, Serialize)]
pub struct PreservationEntry {
    pub path: PathBuf,
    pub sha256: Sha256Digest,
    pub bytes: u64,
}
struct Observed {
    root: PathBuf,
    relative: PathBuf,
    digest: Sha256Digest,
    max: usize,
}
#[derive(Serialize)]
pub struct ProfileDiagnostics {
    pub schema: u32,
    pub device_id: DeviceId,
    pub endpoint: String,
    pub runtime_format: &'static str,
    pub wire_mode: &'static str,
    pub version: String,
    pub publisher_sha256: String,
    pub manifest_sha256: Sha256Digest,
    pub preservation: Vec<PreservationEntry>,
    pub tool_health: &'static str,
    pub account_acceptance: &'static str,
}
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
pub(super) struct BrowserSource<'a> {
    pub deployment: Option<&'a serde_json::Value>,
    pub host: Option<&'a serde_json::Value>,
    pub release: &'a Path,
    #[cfg(target_os = "linux")]
    pub workspace: &'a Path,
    pub node_version: Option<&'a str>,
}
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ComputerSelection {
    enabled: bool,
    // Configuration is never an executable-path authority.
    #[serde(rename = "binary")]
    _binary: Option<serde_json::Value>,
    connections: Option<u32>,
    socket: Option<serde_json::Value>,
    env: Option<BTreeMap<String, String>>,
}
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn computer_selected(
    deployment: Option<&serde_json::Value>,
    host: Option<&serde_json::Value>,
) -> Result<bool, ProfileError> {
    use serde_json::Value;
    // Either explicit local disable or absence closes this lane. It must not
    // invalidate the independent Exec loader or let the other side enable it.
    if deployment.is_none()
        || host.is_none()
        || deployment == Some(&Value::Bool(false))
        || host == Some(&Value::Bool(false))
        || host.and_then(|v| v.get("enabled")).and_then(Value::as_bool) == Some(false)
    {
        return Ok(false);
    }
    if deployment != Some(&Value::Bool(true)) {
        return Err(ProfileError::Unsupported);
    }
    let selected: ComputerSelection =
        serde_json::from_value(host.cloned().ok_or(ProfileError::Unsupported)?)
            .map_err(|_| ProfileError::Unsupported)?;
    if !selected.enabled {
        return Ok(false);
    }
    // This slice owns one fresh fixed stdio worker. No arbitrary socket attach,
    // parallel old connectors or caller environment is silently adopted.
    if selected.connections.is_some_and(|v| v != 1)
        || selected.socket.is_some()
        || selected.env.as_ref().is_some_and(|env| {
            env.iter().any(|(key, value)| {
                !cfg!(target_os = "linux") || key != "CUA_DRIVER_RS_ENABLE_WAYLAND" || value != "1"
            })
        })
    {
        return Err(ProfileError::Unsupported);
    }
    Ok(true)
}
pub struct LoadedProfile {
    settings: Option<Arc<crate::host::settings::HostSettings>>,
    host_base_dir: PathBuf,
    device: DeviceId,
    endpoint: LinkEndpoint,
    paired_namespace: GatewayId,
    tls: GatewayClientTls,
    bearer: SecretBearer,
    executor: Option<Arc<PinnedExecutable>>,
    inventory: release::ProfileRelease,
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    release_root: PathBuf,
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    browser_node_version: Option<String>,
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    cua_version: Option<String>,
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    deployment_computer: Option<serde_json::Value>,
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    host_computer: Option<serde_json::Value>,
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    deployment_browser: Option<serde_json::Value>,
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    host_browser: Option<serde_json::Value>,
    cwd: PathBuf,
    environment: BTreeMap<String, String>,
    #[cfg(target_os = "windows")]
    runtime_temp: std::sync::OnceLock<PrivateRoot>,
    rpc_timeout: Duration,
    observed: Vec<Observed>,
    diagnostics: ProfileDiagnostics,
    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "windows",
        target_os = "macos"
    ))]
    snapshot: Arc<crate::store::native_host_snapshot::NativeHostSnapshot>,
}
impl std::fmt::Debug for LoadedProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedProfile")
            .field("device", &self.device)
            .field("version", &self.diagnostics.version)
            .finish_non_exhaustive()
    }
}
impl LoadedProfile {
    pub(crate) fn settings(&self) -> Option<Arc<crate::host::settings::HostSettings>> {
        self.settings.clone()
    }
    pub(crate) fn exec_selected(&self) -> bool {
        self.settings.as_ref().is_none_or(|s| s.current().exec) && self.executor_enabled()
    }
    pub fn host_base_dir(&self) -> &Path {
        &self.host_base_dir
    }
    pub fn device_id(&self) -> &DeviceId {
        &self.device
    }
    pub fn endpoint(&self) -> &LinkEndpoint {
        &self.endpoint
    }
    /// Namespace derived from the protected Gateway CA certificate, never a
    /// remote wire value or the address used to reach this Gateway.
    pub fn paired_gateway_namespace(&self) -> GatewayId {
        self.paired_namespace.clone()
    }
    pub fn tls(&self) -> &GatewayClientTls {
        &self.tls
    }
    pub fn bearer(&self) -> &SecretBearer {
        &self.bearer
    }
    pub fn diagnostics(&self) -> &ProfileDiagnostics {
        &self.diagnostics
    }
    pub fn into_diagnostics(self) -> ProfileDiagnostics {
        self.diagnostics
    }
    /// Browser selections remain private mutable input, never an execution grant.
    /// Unsupported/malformed Browser options must not invalidate the Exec profile.
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    pub(super) fn browser_source(&self) -> BrowserSource<'_> {
        BrowserSource {
            deployment: self.deployment_browser.as_ref(),
            host: self.host_browser.as_ref(),
            release: &self.release_root,
            #[cfg(target_os = "linux")]
            workspace: &self.cwd,
            node_version: self.browser_node_version.as_deref(),
        }
    }
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    pub(super) fn pin_browser_node(&self) -> Result<PinnedExecutable, ProfileError> {
        self.inventory
            .pin_worker(NativeExternalWorker::BrowserNode22)
            .map_err(|_| ProfileError::UntrustedRelease)
    }
    #[cfg(target_os = "macos")]
    pub(crate) fn computer_enabled(&self) -> Result<bool, ProfileError> {
        self.revalidate_control()?;
        computer_selected(
            self.deployment_computer.as_ref(),
            self.host_computer.as_ref(),
        )
    }
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    pub(crate) fn pin_cua_driver(&self) -> Result<Option<PinnedExecutable>, ProfileError> {
        self.revalidate_control()?;
        if !computer_selected(
            self.deployment_computer.as_ref(),
            self.host_computer.as_ref(),
        )? {
            return Ok(None);
        }
        if self.cua_version.as_deref() != Some("cua-driver 0.47.24")
            || !self.inventory.has_worker(NativeExternalWorker::CuaNative)
        {
            return Err(ProfileError::UntrustedRelease);
        }
        self.revalidate()?;
        let pinned = self
            .inventory
            .pin_worker(NativeExternalWorker::CuaNative)
            .map_err(|_| ProfileError::UntrustedRelease)?;
        pinned.revalidate().map_err(|_| ProfileError::Changed)?;
        self.revalidate_control()?;
        Ok(Some(pinned))
    }
    pub fn executor_enabled(&self) -> bool {
        self.executor.is_some()
    }
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    pub(crate) fn executor_image(&self) -> Option<Arc<PinnedExecutable>> {
        self.executor.clone()
    }
    pub(crate) fn command_environment(&self) -> BTreeMap<String, String> {
        // CODEX_HOME belongs to the supervised executor, not business commands.
        self.environment
            .iter()
            .filter(|(key, _)| key.as_str() != "CODEX_HOME")
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect()
    }
    /// Browser receives the OS-derived baseline only, without Exec-specific
    /// configuration. Its private scratch must already belong to this Host.
    #[cfg(target_os = "windows")]
    pub(super) fn browser_environment(&self) -> Result<BTreeMap<String, String>, ProfileError> {
        self.revalidate_control()?;
        self.runtime_temp
            .get()
            .ok_or(ProfileError::ProtectedRead)?
            .revalidate_runtime_directory()
            .map_err(|_| ProfileError::Changed)?;
        super::windows_env::executor_environment(&BTreeMap::new(), &self.host_base_dir)
    }
    #[cfg(target_os = "windows")]
    pub(super) fn prepare_runtime_temp(&self, base: &PrivateRoot) -> Result<(), ProfileError> {
        let browser_requested = self
            .deployment_browser
            .as_ref()
            .and_then(|value| value.get("enabled"))
            .and_then(serde_json::Value::as_bool)
            == Some(true);
        if self.executor_enabled()
            || browser_requested
            || computer_selected(
                self.deployment_computer.as_ref(),
                self.host_computer.as_ref(),
            )?
        {
            let expected =
                PrivateRoot::open(&self.host_base_dir).map_err(|_| ProfileError::ProtectedRead)?;
            if base.identity() != expected.identity() {
                return Err(ProfileError::Changed);
            }
            let temp = base
                .open_or_create_private_child(".styx-runtime-tmp")
                .map_err(|_| ProfileError::ProtectedRead)?;
            self.runtime_temp
                .set(temp)
                .map_err(|_| ProfileError::Changed)?;
        }
        Ok(())
    }
    pub fn executor_config(&self) -> Result<OwnedExecutorConfig, ProfileError> {
        self.revalidate()?;
        #[cfg(target_os = "windows")]
        self.runtime_temp
            .get()
            .ok_or(ProfileError::ProtectedRead)?
            .revalidate_runtime_directory()
            .map_err(|_| ProfileError::Changed)?;
        let image = self.executor.as_ref().ok_or(ProfileError::Unsupported)?;
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        let binary = image
            .source_path_for_suspended_spawn()
            .map_err(|_| ProfileError::Changed)?;
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        let binary = image.launch_path().map_err(|_| ProfileError::Changed)?;
        Ok(OwnedExecutorConfig {
            binary,
            cwd: self.cwd.clone(),
            environment: self.environment.clone(),
            rpc_timeout: self.rpc_timeout,
        })
    }
    pub(super) fn validate_ownership(
        &self,
        state: &PrivateRoot,
        host: &PrivateRoot,
    ) -> Result<(), ProfileError> {
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "windows",
            target_os = "macos"
        ))]
        {
            let binding = &self.snapshot;
            binding.revalidate().map_err(journal_profile_error)?;
            if state.identity() != binding.root_identity()
                || host.identity() != binding.root_identity()
                || self.host_base_dir != binding.state_dir()
            {
                return Err(ProfileError::Changed);
            }
            Ok(())
        }
        #[cfg(not(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "windows",
            target_os = "macos"
        )))]
        {
            let _ = (state, host);
            Err(ProfileError::Unsupported)
        }
    }
    pub fn revalidate(&self) -> Result<(), ProfileError> {
        self.inventory
            .revalidate()
            .map_err(|_| ProfileError::Changed)?;
        self.revalidate_control()
    }
    /// Existing control does not load a new release/configuration snapshot.
    /// Original private observations and executable pin remain mandatory.
    pub(super) fn revalidate_control(&self) -> Result<(), ProfileError> {
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "windows",
            target_os = "macos"
        ))]
        self.snapshot.revalidate().map_err(journal_profile_error)?;
        #[cfg(target_os = "windows")]
        if let Some(temp) = self.runtime_temp.get() {
            temp.revalidate_runtime_directory()
                .map_err(|_| ProfileError::Changed)?;
        }

        if let Some(executor) = &self.executor {
            executor.revalidate().map_err(|_| ProfileError::Changed)?;
        }
        for o in &self.observed {
            let root = PrivateRoot::open(&o.root).map_err(|_| ProfileError::Changed)?;
            let raw = root
                .read_raw(&o.relative, o.max)
                .map_err(|_| ProfileError::Changed)?;
            if raw.sha256() != o.digest.to_hex()
                && !(o.relative == Path::new("state.json")
                    && self.service_canonical_matches(&root, &raw)?)
            {
                return Err(ProfileError::Changed);
            }
        }
        Ok(())
    }
}
struct Capture {
    observed: Vec<Observed>,
    public: Vec<PreservationEntry>,
}
impl Capture {
    fn read(
        &mut self,
        root: &Path,
        relative: impl AsRef<Path>,
        limit: usize,
    ) -> Result<Vec<u8>, ProfileError> {
        let relative = relative.as_ref();
        let private = PrivateRoot::open(root).map_err(|_| ProfileError::ProtectedRead)?;
        let raw = private
            .read_raw(relative, limit)
            .map_err(|_| ProfileError::ProtectedRead)?;
        let digest = Sha256Digest::of_bytes(raw.bytes());
        self.observed.push(Observed {
            root: root.to_path_buf(),
            relative: relative.to_path_buf(),
            digest,
            max: limit,
        });
        self.public.push(PreservationEntry {
            path: root.join(relative),
            sha256: digest,
            bytes: raw.bytes().len() as u64,
        });
        Ok(raw.bytes().to_vec())
    }
}
fn decode<T: serde::de::DeserializeOwned>(raw: &[u8]) -> Result<T, ProfileError> {
    serde_json::from_slice(raw).map_err(|_| ProfileError::Invalid)
}
fn absolute(path: &Path) -> Result<(), ProfileError> {
    #[cfg(target_os = "windows")]
    {
        super::windows_env::local_absolute(path)
    }
    #[cfg(not(target_os = "windows"))]
    {
        use std::path::Component;
        if !path.is_absolute()
            || path.components().any(|p| {
                matches!(
                    p,
                    Component::ParentDir | Component::CurDir | Component::Prefix(_)
                )
            })
        {
            return Err(ProfileError::Invalid);
        }
        Ok(())
    }
}
fn origin(raw: &str, scheme: &str) -> Result<url::Url, ProfileError> {
    let u = url::Url::parse(raw).map_err(|_| ProfileError::Invalid)?;
    if u.scheme() != scheme {
        return Err(ProfileError::Unsupported);
    }
    if u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
        || u.path() != "/"
    {
        return Err(ProfileError::Invalid);
    }
    Ok(u)
}
impl LoadedProfile {
    fn service_canonical_matches(
        &self,
        root: &PrivateRoot,
        raw: &crate::store::RawFile,
    ) -> Result<bool, ProfileError> {
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "macos",
            target_os = "windows"
        ))]
        {
            self.snapshot
                .service_canonical_matches(root, raw)
                .map(|matched| matched == Some(true))
                .map_err(service_tip_error)
        }
        #[cfg(not(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "macos",
            target_os = "windows"
        )))]
        {
            let _ = (root, raw);
            Err(ProfileError::Unsupported)
        }
    }
}
fn journal_profile_error(error: crate::store::enrollment::JournalError) -> ProfileError {
    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "macos",
        target_os = "windows"
    ))]
    match error {
        crate::store::enrollment::JournalError::ConfigurationPending => {
            return ProfileError::ManagementBusy;
        }
        crate::store::enrollment::JournalError::ServiceStopRequested => {
            return ProfileError::StopRequested;
        }
        _ => (),
    }
    let _ = error;
    ProfileError::Changed
}
#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "macos",
    target_os = "windows"
))]
fn service_tip_error(error: crate::store::native_live_tip::LiveTipError) -> ProfileError {
    use crate::store::native_live_tip::LiveTipError;
    match error {
        LiveTipError::Pending => ProfileError::ManagementBusy,
        LiveTipError::StopRequested => ProfileError::StopRequested,
        LiveTipError::Changed => ProfileError::Changed,
    }
}

/// The App loads its existing native profile through its retained owner scope.
#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "windows",
    target_os = "macos"
))]
pub(crate) fn load_for_app(
    scope: Arc<crate::app::HostScope>,
) -> Result<LoadedProfile, ProfileError> {
    scope.validate().map_err(|_| ProfileError::Changed)?;
    fresh::load_for_app(scope)
}
/// Same original fresh App owner and formal runtime. The fresh snapshot still
/// enforces its entire C07/Ready/manager chain and exact signed selection.
#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "windows",
    target_os = "macos"
))]
pub(crate) fn load_for_app_retained(
    scope: Arc<crate::app::HostScope>,
    runtime: Arc<crate::release::VerifiedNativeRelease>,
) -> Result<LoadedProfile, ProfileError> {
    fresh::load_for_app_retained(scope, runtime)
}
/// Only the native OS manager can supply this opaque scope. A CLI argument or
/// environment variable cannot adopt the service's profile or execution lease.
#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "macos",
    target_os = "windows"
))]
pub(crate) fn load_for_service(
    scope: Arc<crate::platform::native_service::ServiceScope>,
) -> Result<LoadedProfile, ProfileError> {
    use crate::platform::native_service::ServiceRole;
    use styx_contracts::management::ReaderContract;
    scope.validate().map_err(|_| ProfileError::Changed)?;
    if scope.role() != ServiceRole::Host {
        return Err(ProfileError::Invalid);
    }
    let root = PrivateRoot::open(scope.state_dir()).map_err(|_| ProfileError::ProtectedRead)?;
    let raw = root
        .read_raw(".styx-native-root-v1.json", 4096)
        .map_err(|_| ProfileError::Changed)?;
    let marker = crate::store::native_state::decode_marker(raw.bytes())
        .map_err(|_| ProfileError::Changed)?;
    if marker.reader_floor != ReaderContract::NativeManagementStateV1 {
        return Err(ProfileError::Invalid);
    }
    fresh::load_for_service(scope)
}
/// Load the native Host profile used by the CLI. Old JavaScript deployment
/// files do not become runtime state through a fallback reader.
pub fn load_paired(state_dir: &Path) -> Result<LoadedProfile, ProfileError> {
    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "windows",
        target_os = "macos"
    ))]
    {
        fresh::load(state_dir)
    }
    #[cfg(not(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "windows",
        target_os = "macos"
    )))]
    {
        let _ = state_dir;
        Err(ProfileError::Unsupported)
    }
}

#[cfg(test)]
#[path = "profile_tests.rs"]
mod tests;
