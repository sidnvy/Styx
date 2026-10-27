//! Read-only legacy foreground bootstrap. Signed payload authority is distinct
//! from private mutable configuration; no credential, identity or pointer writes.
use crate::{
    crypto::{DevicePrivateKey, DevicePublicKey, PublisherFingerprint, PublisherVerifyingKey},
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
#[path = "profile_release.rs"]
mod release;
const JSON_LIMIT: usize = 1024 * 1024;
#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum ProfileError {
    #[error("legacy profile unsupported on this platform or authentication mode")]
    Unsupported,
    #[error("legacy executor environment is unsupported")]
    UnsupportedExecutorEnvironment,
    #[error("protected legacy configuration could not be read")]
    ProtectedRead,
    #[error("legacy configuration or binding invalid")]
    Invalid,
    #[error("publisher signature or active release provenance invalid")]
    UntrustedRelease,
    #[error("protected legacy input changed")]
    Changed,
    #[error("persistent service configuration transaction is pending")]
    ManagementBusy,
    #[error("persistent service has a committed stop request")]
    StopRequested,
}
impl ProfileError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unsupported => "legacy_profile_unsupported",
            Self::UnsupportedExecutorEnvironment => "unsupported_executor_environment",
            Self::ProtectedRead => "legacy_profile_protected_read",
            Self::Invalid => "legacy_profile_invalid",
            Self::UntrustedRelease => "legacy_release_untrusted",
            Self::Changed => "legacy_profile_changed",
            Self::ManagementBusy => "native_service_configuration_pending",
            Self::StopRequested => "native_service_stop_requested",
        }
    }
}
#[derive(Deserialize)]
struct Deployment {
    schema: u32,
    mode: String,
    host: HostLocator,
    gateway: GatewayLocator,
}
#[derive(Deserialize)]
struct HostLocator {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    computer: Option<serde_json::Value>,
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    browser: Option<serde_json::Value>,
    #[serde(rename = "baseDir")]
    base_dir: PathBuf,
    #[serde(rename = "publisherSha256")]
    publisher: String,
}
#[derive(Deserialize)]
struct GatewayLocator {
    url: String,
    #[serde(rename = "caFile")]
    ca_file: Option<PathBuf>,
}
#[derive(Deserialize)]
struct LegacyState {
    schema: u32,
    mode: String,
    #[serde(default)]
    uncertain: bool,
    #[serde(rename = "configSha256")]
    config_sha256: Sha256Digest,
    steps: Vec<LegacyStep>,
    #[serde(rename = "activeStep")]
    active_step: Option<serde_json::Value>,
    #[serde(rename = "hostServiceMaintenance")]
    host_maintenance: Option<Maintenance>,
    #[serde(rename = "gatewayServiceMaintenance")]
    gateway_maintenance: Option<Maintenance>,
    #[serde(rename = "gatewayMaintenance", default)]
    gateway_operations: Vec<LegacyStep>,
}
#[derive(Deserialize)]
struct LegacyStep {
    id: Option<String>,
    status: String,
}
#[derive(Deserialize)]
struct Maintenance {
    #[serde(rename = "hasUncertainMutation", default)]
    has_uncertain_mutation: bool,
}
#[derive(Deserialize)]
struct Identity {
    version: u32,
    device_id: DeviceId,
    platform: String,
    fingerprint: String,
    public_key_pem: String,
}
#[derive(Deserialize)]
struct HostProfile {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    computer: Option<serde_json::Value>,
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    browser: Option<serde_json::Value>,
    host_id: DeviceId,
    gateway_ws_url: String,
    token_file: PathBuf,
    gateway_ca_file: Option<PathBuf>,
    client_cert_file: Option<serde_json::Value>,
    client_key_file: Option<serde_json::Value>,
    exec: Option<ExecutorProfile>,
}
#[derive(Deserialize)]
struct ExecutorProfile {
    #[serde(default = "default_exec_enabled")]
    enabled: bool,
    #[serde(default)]
    binary: serde_json::Value,
    #[serde(default)]
    cwd: PathBuf,
    #[serde(default)]
    env: BTreeMap<String, String>,
    timeout_ms: Option<u64>,
}
fn default_exec_enabled() -> bool {
    true
}
#[derive(Deserialize)]
struct Active {
    schema: u32,
    version: String,
    manifest_sha256: Sha256Digest,
    previous: Option<String>,
    runtime_format: Option<String>,
}
impl Active {
    fn parse(raw: &[u8]) -> Result<(Self, &'static str), ProfileError> {
        let active: Self = decode(raw)?;
        let format = match (active.schema, active.runtime_format.as_deref()) {
            (1, None | Some("legacy_js_v1")) => "legacy_js_v1",
            (2, Some("native_rust_v1")) => "native_rust_v1",
            _ => return Err(ProfileError::Invalid),
        };
        if !version(&active.version) || active.previous.as_ref().is_some_and(|v| !version(v)) {
            return Err(ProfileError::Invalid);
        }
        Ok((active, format))
    }
}
#[derive(Deserialize)]
struct Manifest {
    #[cfg(target_os = "linux")]
    upstream: Option<serde_json::Value>,
    schema: u32,
    version: String,
    platform: String,
    arch: String,
    files: Vec<Member>,
    runtime_format: Option<String>,
}
#[derive(Deserialize)]
struct Member {
    path: String,
    sha256: Sha256Digest,
    size: u64,
    executable: bool,
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
    // Mutable legacy spelling is never an executable-path authority.
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
pub struct LoadedLegacyProfile {
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
    source: ProfileSource,
}
impl std::fmt::Debug for LoadedLegacyProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedLegacyProfile")
            .field("device", &self.device)
            .field("version", &self.diagnostics.version)
            .finish_non_exhaustive()
    }
}
impl LoadedLegacyProfile {
    pub fn host_base_dir(&self) -> &Path {
        &self.host_base_dir
    }
    pub fn device_id(&self) -> &DeviceId {
        &self.device
    }
    pub fn endpoint(&self) -> &LinkEndpoint {
        &self.endpoint
    }
    /// Configured normalized HTTPS origin, never a remote wire namespace.
    /// This is a routing binding only, not a new publisher or device authority.
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
        if self.cua_version.as_deref() != Some("cua-driver 0.36.0")
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
    #[cfg(target_os = "windows")]
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
            retained_process_limit: 128,
        })
    }
    pub(super) fn validate_committed_ownership(
        &self,
        state: &PrivateRoot,
        host: &PrivateRoot,
    ) -> Result<bool, ProfileError> {
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "windows",
            target_os = "macos"
        ))]
        if let ProfileSource::Fresh(binding) = &self.source {
            binding.revalidate().map_err(journal_profile_error)?;
            if state.identity() != binding.root_identity()
                || host.identity() != binding.root_identity()
                || self.host_base_dir != binding.state_dir()
            {
                return Err(ProfileError::Changed);
            }
            return Ok(true);
        }
        let _ = (state, host);
        Ok(false)
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
        self.source.revalidate()?;
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
                    && self.source.service_canonical_matches(&root, &raw)?)
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
    fn absolute(&mut self, file: &Path, limit: usize) -> Result<Vec<u8>, ProfileError> {
        absolute(file)?;
        self.read(
            file.parent().ok_or(ProfileError::Invalid)?,
            Path::new(file.file_name().ok_or(ProfileError::Invalid)?),
            limit,
        )
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
fn version(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 64
        && v.bytes()
            .enumerate()
            .all(|(i, b)| b.is_ascii_alphanumeric() || (i > 0 && b"._-".contains(&b)))
}
fn relative(p: &str) -> bool {
    !p.is_empty()
        && p.len() < 240
        && !p.starts_with('/')
        && !p.starts_with('\\')
        && p.split('/')
            .all(|s| !s.is_empty() && s != "." && s != ".." && !s.contains(['\\', ':']))
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
#[derive(Clone, Copy)]
enum GatewayWireMode {
    Legacy,
    PairedV3,
}
// The maintenance variant is never obtainable through ordinary load entry
// points. Its profile remains private inside a non-convertible wrapper.
enum ProfileSource {
    Ordinary,
    // Only the private material loader can choose this mode. Its result has no
    // ordinary-profile conversion or execution/credential accessor.
    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "windows",
        target_os = "macos"
    ))]
    Fresh(Arc<crate::store::native_host_snapshot::NativeHostSnapshot>),
}
impl ProfileSource {
    fn revalidate(&self) -> Result<(), ProfileError> {
        match self {
            Self::Ordinary => Ok(()),
            #[cfg(any(
                all(target_os = "linux", target_env = "gnu"),
                target_os = "windows",
                target_os = "macos"
            ))]
            Self::Fresh(binding) => binding.revalidate().map_err(journal_profile_error),
        }
    }
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
            let result = match self {
                Self::Fresh(binding) => binding.service_canonical_matches(root, raw),
                _ => Ok(None),
            };
            result
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
            Ok(false)
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

/// Reads the original deployment authority; does not initialize a new profile.
pub fn load_legacy(state_dir: &Path) -> Result<LoadedLegacyProfile, ProfileError> {
    load(state_dir, GatewayWireMode::Legacy)
}
/// Sealed App composition accepts fresh or completed native migration state;
/// it never adopts an ordinary legacy or CLI-managed profile.
#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "windows",
    target_os = "macos"
))]
pub(crate) fn load_for_app(
    scope: Arc<crate::app::HostScope>,
) -> Result<LoadedLegacyProfile, ProfileError> {
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
) -> Result<LoadedLegacyProfile, ProfileError> {
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
) -> Result<LoadedLegacyProfile, ProfileError> {
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
/// Explicit paired-v3 bridge using the SAME protected original profile and
/// signed legacy executor closure. No identity, pairing or native-format rewrite.
pub fn load_paired(state_dir: &Path) -> Result<LoadedLegacyProfile, ProfileError> {
    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "windows",
        target_os = "macos"
    ))]
    {
        let root = PrivateRoot::open(state_dir).map_err(|_| ProfileError::ProtectedRead)?;
        let native_present = root.ensure_absent(".styx-native-root-v1.json").is_err();
        // A present/unreadable native seed selects this exact reader, never an
        // old active pointer or synthetic legacy succeeded-step fallback.
        if root.ensure_absent("host-join-seed-v1.json").is_err() {
            if !native_present {
                return Err(ProfileError::Changed);
            }
            return fresh::load(state_dir);
        }
        if native_present {
            return Err(ProfileError::Changed);
        }
    }
    load(state_dir, GatewayWireMode::PairedV3)
}
fn load(state_dir: &Path, mode: GatewayWireMode) -> Result<LoadedLegacyProfile, ProfileError> {
    load_source(state_dir, mode, ProfileSource::Ordinary)
}
fn load_source(
    state_dir: &Path,
    mode: GatewayWireMode,
    source: ProfileSource,
) -> Result<LoadedLegacyProfile, ProfileError> {
    load_source_inner(state_dir, mode, source)
}
// The borrowed retirement port is accepted only by the private original-material
// reader. It is never stored in or exposed through an ordinary runtime profile.
fn load_source_inner(
    state_dir: &Path,
    mode: GatewayWireMode,
    source: ProfileSource,
) -> Result<LoadedLegacyProfile, ProfileError> {
    source.revalidate()?;
    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "windows",
        target_os = "macos"
    ))]
    if matches!(&source, ProfileSource::Fresh(_)) {
        return Err(ProfileError::Invalid);
    }
    if !cfg!(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows"
    )) || (cfg!(any(target_os = "macos", target_os = "windows"))
        && !matches!(mode, GatewayWireMode::PairedV3))
    {
        return Err(ProfileError::Unsupported);
    }
    // Preserve the original Node platform spelling in identity and signed
    // worker metadata; neither may impersonate a different native platform.
    let legacy_platform = match std::env::consts::OS {
        "linux" => "linux",
        "macos" => "darwin",
        "windows" => "win32",
        _ => return Err(ProfileError::Unsupported),
    };
    absolute(state_dir)?;
    let mut capture = Capture {
        observed: vec![],
        public: vec![],
    };
    let deployment_raw = capture.read(state_dir, "deployment.json", JSON_LIMIT)?;
    let deployment: Deployment = decode(&deployment_raw)?;
    if deployment.schema != 1
        || !["create-local", "join-existing"].contains(&deployment.mode.as_str())
    {
        return Err(ProfileError::Invalid);
    }
    let canonical = capture.read(state_dir, "state.json", JSON_LIMIT)?;
    let legacy_source = canonical.as_slice();
    let state: LegacyState = decode(legacy_source)?;
    let original_history_only = false;
    if state.schema != 1
        || state.mode != deployment.mode
        || state.config_sha256 != Sha256Digest::of_bytes(&deployment_raw)
    {
        return Err(ProfileError::Invalid);
    }
    // A fenced material read has no runtime conversion. A NativeCommitted
    // snapshot separately validates the complete committed conversion, current
    // native tip and original ownership/identity inputs before supplying before.
    // Its legacy before is historical DATA, not current native operation state.
    // Preserve it unchanged; neither path replays the old unknown operation.
    if !original_history_only
        && (state.uncertain
            || state.active_step.is_some()
            || state
                .host_maintenance
                .as_ref()
                .is_some_and(|m| m.has_uncertain_mutation)
            || state
                .gateway_maintenance
                .as_ref()
                .is_some_and(|m| m.has_uncertain_mutation)
            || state
                .steps
                .iter()
                .chain(&state.gateway_operations)
                .any(|s| matches!(s.status.as_str(), "running" | "uncertain")))
    {
        return Err(ProfileError::Invalid);
    }
    let succeeded = |id: &str| {
        state
            .steps
            .iter()
            .any(|s| s.id.as_deref() == Some(id) && s.status == "succeeded")
    };
    if !succeeded("host.prepare")
        || !succeeded("host.doctor")
        || !(succeeded("host.pair") || succeeded("host.claim"))
    {
        return Err(ProfileError::Invalid);
    }
    absolute(&deployment.host.base_dir)?;
    let base = &deployment.host.base_dir;
    let publisher_pem = capture.read(base, "publisher.pem", 4096)?;
    let publisher = PublisherVerifyingKey::from_spki_pem(&publisher_pem)
        .map_err(|_| ProfileError::UntrustedRelease)?;
    let expected = PublisherFingerprint::parse(&deployment.host.publisher)
        .map_err(|_| ProfileError::UntrustedRelease)?;
    if publisher
        .fingerprint()
        .map_err(|_| ProfileError::UntrustedRelease)?
        != expected
    {
        return Err(ProfileError::UntrustedRelease);
    }
    let identity: Identity = decode(&capture.read(base, "device/identity.json", JSON_LIMIT)?)?;
    let host: HostProfile = decode(&capture.read(base, "device/host.json", JSON_LIMIT)?)?;
    if identity.version != 1
        || identity.platform != legacy_platform
        || identity.device_id != host.host_id
    {
        return Err(ProfileError::Invalid);
    }
    if host.client_cert_file.is_some() || host.client_key_file.is_some() {
        return Err(ProfileError::Unsupported);
    }
    let private_bytes =
        zeroize::Zeroizing::new(capture.read(base, "device/identity.pem", 16 * 1024)?);
    let private =
        DevicePrivateKey::from_pkcs8_pem(&private_bytes).map_err(|_| ProfileError::Invalid)?;
    let public = DevicePublicKey::from_spki_pem(identity.public_key_pem.as_bytes())
        .map_err(|_| ProfileError::Invalid)?;
    if private.public_key().fingerprint().as_hex() != identity.fingerprint
        || public.fingerprint().as_hex() != identity.fingerprint
    {
        return Err(ProfileError::Invalid);
    }
    if host.token_file != base.join("device/host.token") {
        return Err(ProfileError::Invalid);
    }
    let raw_token = match &source {
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "windows",
            target_os = "macos"
        ))]
        ProfileSource::Fresh(_) => return Err(ProfileError::Invalid),
        ProfileSource::Ordinary => {
            zeroize::Zeroizing::new(capture.read(base, "device/host.token", 4096)?)
        }
    };
    let token = std::str::from_utf8(&raw_token)
        .map_err(|_| ProfileError::Invalid)?
        .trim();
    if !(32..=4096).contains(&token.len())
        || !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
    {
        return Err(ProfileError::Invalid);
    }
    let bearer =
        SecretBearer::from_protected_reader(token.to_owned()).map_err(|_| ProfileError::Invalid)?;
    let gateway = origin(&deployment.gateway.url, "https")?;
    let mut endpoint = origin(&host.gateway_ws_url, "wss")?;
    let mut expected_ws = gateway.clone();
    expected_ws
        .set_scheme("wss")
        .map_err(|_| ProfileError::Invalid)?;
    if endpoint != expected_ws {
        return Err(ProfileError::Invalid);
    }
    let normalized_origin = gateway.origin().ascii_serialization();
    let paired_namespace = GatewayId::try_from(format!(
        "paired.{}",
        Sha256Digest::of_bytes(normalized_origin.as_bytes()).to_hex()
    ))
    .map_err(|_| ProfileError::Invalid)?;
    let endpoint_path = match mode {
        GatewayWireMode::Legacy => format!("/styx/hosts/{}/exec", identity.device_id.as_str()),
        GatewayWireMode::PairedV3 => format!("/styx/host/v3/{}/exec", identity.device_id.as_str()),
    };
    endpoint.set_path(&endpoint_path);
    let endpoint_text = endpoint.to_string();
    let endpoint = LinkEndpoint::parse(endpoint.as_str()).map_err(|_| ProfileError::Invalid)?;
    let ca_file = host
        .gateway_ca_file
        .as_ref()
        .ok_or(ProfileError::Unsupported)?;
    let ca = capture.absolute(ca_file, 128 * 1024)?;
    if let Some(original) = deployment.gateway.ca_file
        && capture.absolute(&original, 128 * 1024)? != ca
    {
        return Err(ProfileError::Invalid);
    }
    let certs = rustls_pemfile::certs(&mut Cursor::new(&ca))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ProfileError::Invalid)?;
    if certs.is_empty() || certs.len() > 8 {
        return Err(ProfileError::Invalid);
    }
    let pins: Vec<_> = certs
        .iter()
        .map(|c| TrustAnchorPin::from_certificate_der(c))
        .collect();
    let tls = GatewayClientTls::from_pinned_ca_bundle(&ca, &pins, None)
        .map_err(|_| ProfileError::Invalid)?;
    let (active, expected_format) =
        Active::parse(&capture.read(base, "install/active.json", JSON_LIMIT)?)?;
    let root = base.join("install/releases").join(&active.version);
    // The preserved active pointer remains an observed original input. After
    // migration it never selects workers; only the committed canonical selection
    // and a fresh C08 verification may do that.
    let inventory = {
        let inventory = release::load(&mut capture, &root, &active, base, &publisher, &expected)?;
        if inventory.runtime_format() != expected_format {
            return Err(ProfileError::UntrustedRelease);
        }
        inventory
    };
    let exec_enabled = host.exec.as_ref().is_some_and(|exec| exec.enabled);
    if matches!(mode, GatewayWireMode::Legacy) && !exec_enabled {
        return Err(ProfileError::Unsupported);
    }
    if exec_enabled && !inventory.has_worker(NativeExternalWorker::CodexExec) {
        return Err(ProfileError::UntrustedRelease);
    }
    let executor = if exec_enabled {
        Some(Arc::new(
            inventory.pin_worker(NativeExternalWorker::CodexExec)?,
        ))
    } else {
        None
    };
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    let release_root = inventory.browser_release_root();
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    let browser_node_version = inventory.browser_node_version();
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    let cua_version = inventory.cua_version();
    let runtime_format = match (inventory.runtime_format(), exec_enabled) {
        ("legacy_js_v1", true) => "legacy_js_v1_executor_only",
        ("legacy_js_v1", false) => "legacy_js_v1_signed_worker_closure",
        ("native_rust_v1", true) => "native_rust_v1_executor_only",
        ("native_rust_v1", false) => "native_rust_v1_signed_worker_closure",
        _ => return Err(ProfileError::Unsupported),
    };
    let diagnostic_manifest = match &source {
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "windows",
            target_os = "macos"
        ))]
        ProfileSource::Fresh(_) => return Err(ProfileError::Invalid),
        ProfileSource::Ordinary => active.manifest_sha256,
    };
    let signed_version = inventory.version().to_owned();
    // An absent Exec profile supplies no Browser workspace authority.
    let exec = host.exec.unwrap_or(ExecutorProfile {
        enabled: false,
        binary: serde_json::Value::Null,
        cwd: PathBuf::new(),
        env: BTreeMap::new(),
        timeout_ms: None,
    });
    if exec_enabled || !exec.cwd.as_os_str().is_empty() {
        absolute(&exec.cwd)?;
    }
    let _ignored_mutable_binary = exec.binary;
    if exec_enabled {
        if exec.env.keys().any(|k| k != "CODEX_HOME") {
            return Err(ProfileError::UnsupportedExecutorEnvironment);
        }
        if let Some(home) = exec.env.get("CODEX_HOME") {
            let path = Path::new(home);
            absolute(path)?;
            if home.len() > 4096
                || home.contains('\0')
                || path.components().collect::<PathBuf>().as_os_str() != path.as_os_str()
            {
                return Err(ProfileError::UnsupportedExecutorEnvironment);
            }
        }
        if exec.env.len() > 64
            || exec.env.iter().any(|(k, v)| {
                k.is_empty()
                    || k.len() > 128
                    || k.contains(['=', '\0'])
                    || v.len() > 16384
                    || v.contains('\0')
            })
        {
            return Err(ProfileError::Invalid);
        }
    }
    let timeout = if exec_enabled {
        exec.timeout_ms.unwrap_or(35000)
    } else {
        35000
    };
    if !(1..=60000).contains(&timeout) {
        return Err(ProfileError::Invalid);
    }
    #[cfg(target_os = "windows")]
    let runtime_environment = if exec_enabled {
        super::windows_env::executor_environment(&exec.env, base)?
    } else {
        BTreeMap::new()
    };
    #[cfg(not(target_os = "windows"))]
    let runtime_environment = if exec_enabled {
        exec.env
    } else {
        BTreeMap::new()
    };
    let loaded = LoadedLegacyProfile {
        host_base_dir: base.clone(),
        device: identity.device_id.clone(),
        endpoint,
        paired_namespace,
        tls,
        bearer,
        executor,
        inventory,
        #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
        release_root,
        #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
        browser_node_version,
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        cua_version,
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        deployment_computer: deployment.host.computer,
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        host_computer: host.computer,
        #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
        deployment_browser: deployment.host.browser,
        #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
        host_browser: host.browser,
        cwd: exec.cwd,
        environment: runtime_environment,
        #[cfg(target_os = "windows")]
        runtime_temp: std::sync::OnceLock::new(),
        rpc_timeout: Duration::from_millis(timeout),
        observed: capture.observed,
        diagnostics: ProfileDiagnostics {
            schema: 1,
            device_id: identity.device_id,
            endpoint: endpoint_text,
            runtime_format,
            wire_mode: match mode {
                GatewayWireMode::Legacy => "explicit_legacy_gateway",
                GatewayWireMode::PairedV3 => "paired_v3",
            },
            version: signed_version,
            publisher_sha256: deployment.host.publisher,
            manifest_sha256: diagnostic_manifest,
            preservation: capture.public,
            tool_health: "NOT RUN",
            account_acceptance: "NOT RUN",
        },
        source,
    };
    loaded.revalidate()?;
    Ok(loaded)
}
#[cfg(test)]
#[path = "profile_tests.rs"]
mod tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "profile_cua_tests.rs"]
mod cua_tests;
