//! Read-only legacy foreground bootstrap. Signed payload authority is distinct
//! from private mutable configuration; no credential, identity or pointer writes.
use crate::{
    crypto::{
        DevicePrivateKey, DevicePublicKey, PublisherFingerprint, PublisherVerifyingKey,
        RawReleaseManifest,
    },
    host::link::{LinkEndpoint, SecretBearer},
    providers::codex::OwnedExecutorConfig,
    store::{PayloadInventory, PayloadLimits, PinnedExecutable, PrivateRoot},
    tls::{GatewayClientTls, TrustAnchorPin},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Cursor,
    path::{Component, Path, PathBuf},
    time::Duration,
};
use styx_contracts::identity::{DeviceId, GatewayId, Sha256Digest};
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
    #[cfg(target_os = "linux")]
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
    #[cfg(target_os = "linux")]
    browser: Option<serde_json::Value>,
    host_id: DeviceId,
    gateway_ws_url: String,
    token_file: PathBuf,
    gateway_ca_file: Option<PathBuf>,
    client_cert_file: Option<serde_json::Value>,
    client_key_file: Option<serde_json::Value>,
    exec: ExecutorProfile,
}
#[derive(Deserialize)]
struct ExecutorProfile {
    binary: serde_json::Value,
    cwd: PathBuf,
    #[serde(default)]
    env: BTreeMap<String, String>,
    timeout_ms: Option<u64>,
}
#[derive(Deserialize)]
struct Active {
    schema: u32,
    version: String,
    manifest_sha256: Sha256Digest,
    previous: Option<String>,
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
#[cfg(target_os = "linux")]
pub(super) struct BrowserSource<'a> {
    pub deployment: Option<&'a serde_json::Value>,
    pub host: Option<&'a serde_json::Value>,
    pub release: &'a Path,
    pub workspace: &'a Path,
    pub node_version: Option<&'a str>,
}
pub struct LoadedLegacyProfile {
    host_base_dir: PathBuf,
    device: DeviceId,
    endpoint: LinkEndpoint,
    paired_namespace: GatewayId,
    tls: GatewayClientTls,
    bearer: SecretBearer,
    executor: PinnedExecutable,
    inventory: PayloadInventory,
    #[cfg(target_os = "linux")]
    release_root: PathBuf,
    #[cfg(target_os = "linux")]
    browser_node_version: Option<String>,
    #[cfg(target_os = "linux")]
    deployment_browser: Option<serde_json::Value>,
    #[cfg(target_os = "linux")]
    host_browser: Option<serde_json::Value>,
    cwd: PathBuf,
    environment: BTreeMap<String, String>,
    rpc_timeout: Duration,
    observed: Vec<Observed>,
    diagnostics: ProfileDiagnostics,
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
    #[cfg(target_os = "linux")]
    pub(super) fn browser_source(&self) -> BrowserSource<'_> {
        BrowserSource {
            deployment: self.deployment_browser.as_ref(),
            host: self.host_browser.as_ref(),
            release: &self.release_root,
            workspace: &self.cwd,
            node_version: self.browser_node_version.as_deref(),
        }
    }
    #[cfg(target_os = "linux")]
    pub(super) fn pin_browser_node(&self) -> Result<PinnedExecutable, ProfileError> {
        self.inventory
            .pin_executable("bin/node")
            .map_err(|_| ProfileError::UntrustedRelease)
    }
    pub fn executor_config(&self) -> Result<OwnedExecutorConfig, ProfileError> {
        self.revalidate()?;
        Ok(OwnedExecutorConfig {
            binary: self
                .executor
                .launch_path()
                .map_err(|_| ProfileError::Changed)?,
            cwd: self.cwd.clone(),
            environment: self.environment.clone(),
            rpc_timeout: self.rpc_timeout,
            retained_process_limit: 128,
        })
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
        self.executor
            .revalidate()
            .map_err(|_| ProfileError::Changed)?;
        for o in &self.observed {
            let root = PrivateRoot::open(&o.root).map_err(|_| ProfileError::Changed)?;
            let raw = root
                .read_raw(&o.relative, o.max)
                .map_err(|_| ProfileError::Changed)?;
            if raw.sha256() != o.digest.to_hex() {
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
/// Reads the original deployment authority; does not initialize a new profile.
pub fn load_legacy(state_dir: &Path) -> Result<LoadedLegacyProfile, ProfileError> {
    load(state_dir, GatewayWireMode::Legacy)
}
/// Explicit paired-v3 bridge using the SAME protected original profile and
/// signed legacy executor closure. No identity, pairing or native-format rewrite.
pub fn load_paired(state_dir: &Path) -> Result<LoadedLegacyProfile, ProfileError> {
    load(state_dir, GatewayWireMode::PairedV3)
}
fn load(state_dir: &Path, mode: GatewayWireMode) -> Result<LoadedLegacyProfile, ProfileError> {
    if !cfg!(target_os = "linux") {
        return Err(ProfileError::Unsupported);
    }
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
    let state: LegacyState = decode(&capture.read(state_dir, "state.json", JSON_LIMIT)?)?;
    if state.schema != 1
        || state.uncertain
        || state.mode != deployment.mode
        || state.config_sha256 != Sha256Digest::of_bytes(&deployment_raw)
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
            .any(|s| matches!(s.status.as_str(), "running" | "uncertain"))
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
    if identity.version != 1 || identity.platform != "linux" || identity.device_id != host.host_id {
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
    let raw_token = zeroize::Zeroizing::new(capture.read(base, "device/host.token", 4096)?);
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
    let active: Active = decode(&capture.read(base, "install/active.json", JSON_LIMIT)?)?;
    if active.schema != 1
        || !version(&active.version)
        || active.previous.as_ref().is_some_and(|v| !version(v))
    {
        return Err(ProfileError::Invalid);
    }
    let release = base.join("install/releases").join(&active.version);
    let manifest_raw = capture.read(&release, "manifest.json", JSON_LIMIT)?;
    let signature = capture.read(&release, "manifest.sig", 256)?;
    let signature = std::str::from_utf8(&signature)
        .map_err(|_| ProfileError::UntrustedRelease)?
        .trim();
    if signature.len() != 86
        || !signature
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
    {
        return Err(ProfileError::UntrustedRelease);
    }
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| ProfileError::UntrustedRelease)?;
    publisher
        .verify_manifest(
            &expected,
            RawReleaseManifest::from_original_bytes(&manifest_raw),
            &signature,
        )
        .map_err(|_| ProfileError::UntrustedRelease)?;
    if Sha256Digest::of_bytes(&manifest_raw) != active.manifest_sha256 {
        return Err(ProfileError::UntrustedRelease);
    }
    let manifest: Manifest = decode(&manifest_raw)?;
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        _ => return Err(ProfileError::Unsupported),
    };
    if manifest.schema != 1
        || manifest.version != active.version
        || manifest.platform != "linux"
        || manifest.arch != arch
        || manifest.files.is_empty()
        || manifest.files.len() > 4096
    {
        return Err(ProfileError::UntrustedRelease);
    }
    if manifest
        .runtime_format
        .as_ref()
        .is_some_and(|f| f != "legacy_js_v1")
    {
        return Err(ProfileError::Unsupported);
    }
    let private_release = PrivateRoot::open(&release).map_err(|_| ProfileError::ProtectedRead)?;
    let inventory = private_release
        .payload_inventory(PayloadLimits::default())
        .map_err(|_| ProfileError::UntrustedRelease)?;
    let mut expected_members = BTreeMap::new();
    for m in manifest.files {
        if !relative(&m.path)
            || m.path == "manifest.json"
            || m.path == "manifest.sig"
            || expected_members
                .insert(PathBuf::from(&m.path), (m.size, m.sha256, m.executable))
                .is_some()
        {
            return Err(ProfileError::UntrustedRelease);
        }
    }
    expected_members.insert(
        PathBuf::from("manifest.json"),
        (
            manifest_raw.len() as u64,
            Sha256Digest::of_bytes(&manifest_raw),
            false,
        ),
    );
    let signature_raw = capture.read(&release, "manifest.sig", 256)?;
    expected_members.insert(
        PathBuf::from("manifest.sig"),
        (
            signature_raw.len() as u64,
            Sha256Digest::of_bytes(&signature_raw),
            false,
        ),
    );
    let mut actual = BTreeSet::new();
    for member in inventory.members() {
        let Some((size, sha, executable)) = expected_members.get(&member.path) else {
            return Err(ProfileError::UntrustedRelease);
        };
        if member.bytes != *size || member.sha256 != *sha || member.executable != *executable {
            return Err(ProfileError::UntrustedRelease);
        }
        actual.insert(member.path.clone());
    }
    if actual.len() != expected_members.len()
        || !expected_members
            .get(Path::new("bin/codex"))
            .is_some_and(|(_, _, x)| *x)
    {
        return Err(ProfileError::UntrustedRelease);
    }
    let executor = inventory
        .pin_executable(Path::new("bin/codex"))
        .map_err(|_| ProfileError::UntrustedRelease)?;
    absolute(&host.exec.cwd)?;
    let _ignored_mutable_binary = host.exec.binary;
    if host.exec.env.keys().any(|k| k != "CODEX_HOME") {
        return Err(ProfileError::UnsupportedExecutorEnvironment);
    }
    if let Some(home) = host.exec.env.get("CODEX_HOME") {
        let path = Path::new(home);
        absolute(path)?;
        if home.len() > 4096
            || home.contains('\0')
            || path.components().collect::<PathBuf>().as_os_str() != path.as_os_str()
        {
            return Err(ProfileError::UnsupportedExecutorEnvironment);
        }
    }
    if host.exec.env.len() > 64
        || host.exec.env.iter().any(|(k, v)| {
            k.is_empty()
                || k.len() > 128
                || k.contains(['=', '\0'])
                || v.len() > 16384
                || v.contains('\0')
        })
    {
        return Err(ProfileError::Invalid);
    }
    let timeout = host.exec.timeout_ms.unwrap_or(35000);
    if !(1..=60000).contains(&timeout) {
        return Err(ProfileError::Invalid);
    }
    let loaded = LoadedLegacyProfile {
        host_base_dir: base.clone(),
        device: identity.device_id.clone(),
        endpoint,
        paired_namespace,
        tls,
        bearer,
        executor,
        inventory,
        #[cfg(target_os = "linux")]
        release_root: release,
        #[cfg(target_os = "linux")]
        browser_node_version: manifest
            .upstream
            .as_ref()
            .and_then(|v| v.get("node"))
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        #[cfg(target_os = "linux")]
        deployment_browser: deployment.host.browser,
        #[cfg(target_os = "linux")]
        host_browser: host.browser,
        cwd: host.exec.cwd,
        environment: host.exec.env,
        rpc_timeout: Duration::from_millis(timeout),
        observed: capture.observed,
        diagnostics: ProfileDiagnostics {
            schema: 1,
            device_id: identity.device_id,
            endpoint: endpoint_text,
            runtime_format: "legacy_js_v1_executor_only",
            wire_mode: match mode {
                GatewayWireMode::Legacy => "explicit_legacy_gateway",
                GatewayWireMode::PairedV3 => "paired_v3",
            },
            version: active.version,
            publisher_sha256: deployment.host.publisher,
            manifest_sha256: active.manifest_sha256,
            preservation: capture.public,
            tool_health: "NOT RUN",
            account_acceptance: "NOT RUN",
        },
    };
    loaded.revalidate()?;
    Ok(loaded)
}
#[cfg(test)]
#[path = "profile_tests.rs"]
mod tests;
