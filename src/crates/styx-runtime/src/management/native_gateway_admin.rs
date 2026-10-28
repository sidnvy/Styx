//! Protected local admin client, never a second Gateway writer or ledger.
//! Every mutation is one HTTP exchange. Invitation bytes leave only via a
//! fresh private file; reports and errors contain public observations only.
use super::native_join_http::{self as http, JoinHttpCertainty, JoinHttpError};
use crate::{
    release::{self, VerifiedNativeRelease},
    store::{PrivateRoot, RawFile, RootIdentity, native_state},
    tls::{GatewayClientTls, GatewayLeafPin, TrustAnchorPin},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::Cursor,
    path::{Path, PathBuf},
    sync::{Arc, LazyLock},
    time::{SystemTime, UNIX_EPOCH},
};
use styx_contracts::{
    identity::{DeviceId, Sha256Digest},
    legacy::PairingComparison,
    management::ReaderContract,
    native_management::{
        NativeDeploymentMode, NativeManager, NativeRootIdentity, NativeRunDesired,
        NativeRuntimeSelection,
    },
};
use tokio::sync::{Semaphore, oneshot};
use zeroize::Zeroizing;

const LIMIT: usize = 1024 * 1024;
static OPERATIONS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(1)));

pub struct AdminError {
    code: &'static str,
    exit: u8,
    outcome: &'static str,
}
impl AdminError {
    pub fn code(&self) -> &'static str {
        self.code
    }
    pub fn exit_code(&self) -> u8 {
        self.exit
    }
    pub fn outcome(&self) -> &'static str {
        self.outcome
    }
}
impl fmt::Debug for AdminError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code)
    }
}
impl fmt::Display for AdminError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code)
    }
}
impl std::error::Error for AdminError {}
type Result<T> = std::result::Result<T, AdminError>;
fn refused(code: &'static str) -> AdminError {
    AdminError {
        code,
        exit: 2,
        outcome: "not_dispatched",
    }
}
fn unknown() -> AdminError {
    AdminError {
        code: "native_gateway_admin_result_unknown",
        exit: 4,
        outcome: "unknown",
    }
}
fn http_error(error: JoinHttpError) -> AdminError {
    match error.certainty {
        JoinHttpCertainty::NotDispatched => AdminError {
            code: error.code(),
            exit: 3,
            outcome: "not_dispatched",
        },
        JoinHttpCertainty::ResultUnknown => unknown(),
    }
}
#[derive(Serialize)]
pub struct PendingDevice {
    pub request_id: String,
    pub device_id: DeviceId,
    pub fingerprint: Sha256Digest,
    pub comparison_code: String,
    pub expires_at: u64,
    pub computer_requested: bool,
    pub browser_requested: bool,
    pub gateway_origin: String,
}
pub struct ApprovalSelection {
    pub request_id: String,
    pub device_id: DeviceId,
    pub fingerprint: Sha256Digest,
    pub comparison_code: String,
    pub enable_computer: bool,
    pub enable_browser: bool,
}
#[derive(Serialize)]
pub struct AdminReport {
    pub schema: u16,
    pub operation: &'static str,
    pub state_dir: PathBuf,
    pub operations_replayed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origins: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invitation_file: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_link_file: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub one_use: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending: Option<Vec<PendingDevice>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<Sha256Digest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comparison_code: Option<String>,
}
impl AdminReport {
    fn new(operation: &'static str, state_dir: PathBuf) -> Self {
        Self {
            schema: 1,
            operation,
            state_dir,
            operations_replayed: false,
            origin: None,
            origins: None,
            invitation_file: None,
            app_link_file: None,
            expires_at: None,
            one_use: None,
            pending: None,
            status: None,
            request_id: None,
            device_id: None,
            fingerprint: None,
            comparison_code: None,
        }
    }
}
enum Action {
    Invite(
        PathBuf,
        PathBuf,
        u64,
        Option<InvitationOrigin>,
        Option<PathBuf>,
    ),
    Pending(PathBuf),
    Approve(PathBuf, ApprovalSelection),
}
#[derive(Clone, Copy)]
pub enum InvitationOrigin {
    Loopback,
    Lan,
    Address(std::net::Ipv4Addr),
}
pub async fn invite(
    state_dir: &Path,
    invitation_file: &Path,
    ttl_seconds: u64,
) -> Result<AdminReport> {
    invite_with_origin(state_dir, invitation_file, ttl_seconds, None).await
}
pub async fn invite_with_origin(
    state_dir: &Path,
    invitation_file: &Path,
    ttl_seconds: u64,
    origin: Option<InvitationOrigin>,
) -> Result<AdminReport> {
    invite_with_options(state_dir, invitation_file, ttl_seconds, origin, None).await
}
/// Optionally export an App link containing the selected origin and public CA.
pub async fn invite_with_options(
    state_dir: &Path,
    invitation_file: &Path,
    ttl_seconds: u64,
    origin: Option<InvitationOrigin>,
    app_link_file: Option<&Path>,
) -> Result<AdminReport> {
    owned(Action::Invite(
        state_dir.into(),
        invitation_file.into(),
        ttl_seconds,
        origin,
        app_link_file.map(Path::to_path_buf),
    ))
    .await
}
pub async fn pending(state_dir: &Path) -> Result<AdminReport> {
    owned(Action::Pending(state_dir.into())).await
}
pub async fn approve(state_dir: &Path, selection: ApprovalSelection) -> Result<AdminReport> {
    owned(Action::Approve(state_dir.into(), selection)).await
}
async fn owned(action: Action) -> Result<AdminReport> {
    let permit = OPERATIONS
        .clone()
        .try_acquire_owned()
        .map_err(|_| AdminError {
            code: "native_gateway_admin_busy",
            exit: 3,
            outcome: "not_dispatched",
        })?;
    let (send, receive) = oneshot::channel();
    // A disappearing CLI waiter never cancels/replays the dispatched operation.
    // The original bounded worker retains its permit and read-only material.
    let job = tokio::spawn(async move {
        let _permit = permit;
        let result = perform(action).await;
        let _ = send.send(result);
    });
    let result = receive.await.map_err(|_| unknown())?;
    job.await.map_err(|_| unknown())?;
    result
}
async fn blocking<T: Send + 'static>(
    job: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    tokio::task::spawn_blocking(job)
        .await
        .map_err(|_| unknown())?
}
fn clock_ms() -> Result<u64> {
    let value = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| refused("native_gateway_admin_clock"))?
        .as_millis();
    u64::try_from(value)
        .ok()
        .filter(|v| *v != 0)
        .ok_or_else(|| refused("native_gateway_admin_clock"))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ready {
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
struct Material {
    path: PathBuf,
    root: PrivateRoot,
    files: Vec<RawFile>,
    candidate: VerifiedNativeRelease,
    tls: GatewayClientTls,
    origin: url::Url,
    origins: Vec<String>,
    leaf: GatewayLeafPin,
    token: Zeroizing<Vec<u8>>,
}
fn root_identity(root: &PrivateRoot) -> NativeRootIdentity {
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
fn token(raw: &[u8]) -> bool {
    (32..=4096).contains(&raw.len())
        && raw
            .iter()
            .all(|v| v.is_ascii_alphanumeric() || matches!(*v, b'_' | b'-'))
}
fn one_certificate(raw: &[u8]) -> Result<Vec<u8>> {
    let certs = rustls_pemfile::certs(&mut Cursor::new(raw))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| refused("native_gateway_admin_tls_material"))?;
    if certs.len() != 1 {
        return Err(refused("native_gateway_admin_tls_material"));
    }
    Ok(certs[0].as_ref().to_vec())
}
impl Material {
    fn open(path: PathBuf) -> Result<Self> {
        if !path.is_absolute() {
            return Err(refused("native_gateway_admin_input"));
        }
        let root =
            PrivateRoot::open(&path).map_err(|_| refused("native_gateway_admin_private_root"))?;
        let mut files = Vec::new();
        for name in [
            ".styx-native-root-v1.json",
            "state.json",
            "deployment.json",
            "gateway-ready-v1.json",
            "gateway-ca.pem",
            "gateway-chain.pem",
            "gateway-admin.token",
        ] {
            files.push(
                root.read_raw(name, LIMIT)
                    .map_err(|_| refused("native_gateway_admin_material"))?,
            );
        }
        let marker = native_state::decode_marker(files[0].bytes())
            .map_err(|_| refused("native_gateway_admin_material"))?;
        let state = native_state::decode_state(files[1].bytes(), &marker)
            .map_err(|_| refused("native_gateway_admin_material"))?;
        let selection =
            crate::store::native_host_snapshot::validated_runtime_selection(&root, &state, &marker)
                .map_err(|_| refused("native_gateway_admin_material"))?;
        let state = state.state();
        if marker.root_identity != root_identity(&root)
            || marker.reader_floor != ReaderContract::NativeManagementStateV1
            || state.migration.is_some()
            || state.mode != NativeDeploymentMode::CreateLocal
            || state.desired.host.is_some()
            || state.desired.gateway.is_none_or(|d| {
                d.manager == NativeManager::AppManaged || d.run != NativeRunDesired::Running
            })
            || state.deployment_raw_sha256 != Sha256Digest::of_bytes(files[2].bytes())
        {
            return Err(refused("native_gateway_admin_fresh_gateway_required"));
        }
        let ready: Ready = serde_json::from_slice(files[3].bytes())
            .map_err(|_| refused("native_gateway_admin_material"))?;
        let binding: Sha256Digest = serde_json::from_str(
            state
                .extensions
                .get("fresh_gateway_binding_v1")
                .ok_or_else(|| refused("native_gateway_admin_material"))?
                .get(),
        )
        .map_err(|_| refused("native_gateway_admin_material"))?;
        let bootstrap = state
            .runtime_update()
            .map_err(|_| refused("native_gateway_admin_material"))?
            .map_or_else(|| selection.clone(), |update| update.bootstrap_runtime);
        if binding != Sha256Digest::of_bytes(files[3].bytes())
            || ready.schema != 1
            || ready.root_identity != marker.root_identity
            || ready.scope_generation != marker.scope_generation
            || ready.deployment_raw_sha256 != state.deployment_raw_sha256
            || ready.runtime != bootstrap
        {
            return Err(refused("native_gateway_admin_material"));
        }
        let candidate = release::verify_selected(&selection)
            .map_err(|_| refused("native_gateway_admin_candidate"))?;
        if !candidate
            .supports_state_reader(state.reader_contract)
            .map_err(|_| refused("native_gateway_admin_candidate"))?
        {
            return Err(refused("native_gateway_admin_candidate"));
        }
        if candidate
            .runtime_selection()
            .map_err(|_| refused("native_gateway_admin_candidate"))?
            != selection
        {
            return Err(refused("native_gateway_admin_candidate"));
        }
        let names = [
            "gateway-ca.pem",
            "gateway-ca-key.pem",
            "gateway-chain.pem",
            "gateway-key.pem",
            "gateway-admin.token",
            "gateway-model.token",
        ];
        if ready.files.len() != names.len() || names.iter().any(|n| !ready.files.contains_key(*n)) {
            return Err(refused("native_gateway_admin_material"));
        }
        for (name, index) in [
            ("gateway-ca.pem", 4),
            ("gateway-chain.pem", 5),
            ("gateway-admin.token", 6),
        ] {
            if ready.files.get(name) != Some(&Sha256Digest::of_bytes(files[index].bytes())) {
                return Err(refused("native_gateway_admin_material"));
            }
        }
        let origin = url::Url::parse(&format!("{}/", ready.origin))
            .map_err(|_| refused("native_gateway_admin_origin"))?;
        if origin.scheme() != "https"
            || origin.origin().ascii_serialization() != ready.origin
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.query().is_some()
            || origin.fragment().is_some()
        {
            return Err(refused("native_gateway_admin_origin"));
        }
        let endpoints = super::native_gateway::endpoints(files[2].bytes())
            .map_err(|_| refused("native_gateway_admin_origin"))?;
        if endpoints.origin != ready.origin {
            return Err(refused("native_gateway_admin_origin"));
        }
        let mut origins = vec![endpoints.origin.clone()];
        origins.extend(endpoints.lan_origins());
        let now = clock_ms()? / 1000;
        if ready.not_before_unix < 0
            || ready.not_after_unix <= ready.not_before_unix
            || now < ready.not_before_unix as u64
            || now >= ready.not_after_unix as u64
        {
            return Err(refused("native_gateway_admin_certificate_expired"));
        }
        let ca = one_certificate(files[4].bytes())?;
        let chain = rustls_pemfile::certs(&mut Cursor::new(files[5].bytes()))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| refused("native_gateway_admin_tls_material"))?;
        if chain.is_empty() || chain.len() > 8 {
            return Err(refused("native_gateway_admin_tls_material"));
        }
        let leaf = GatewayLeafPin::from_certificate_der(&chain[0]);
        let tls = GatewayClientTls::from_pinned_ca_pem(
            files[4].bytes(),
            TrustAnchorPin::from_certificate_der(&ca),
            Some(leaf.clone()),
        )
        .map_err(|_| refused("native_gateway_admin_tls_material"))?;
        if !token(files[6].bytes()) {
            return Err(refused("native_gateway_admin_material"));
        }
        let bearer = Zeroizing::new(files[6].bytes().to_vec());
        let result = Self {
            path,
            root,
            files,
            candidate,
            tls,
            origin,
            origins,
            leaf,
            token: bearer,
        };
        result.validate()?;
        Ok(result)
    }
    fn validate(&self) -> Result<()> {
        if PrivateRoot::open(&self.path)
            .map_err(|_| refused("native_gateway_admin_material_changed"))?
            .identity()
            != self.root.identity()
        {
            return Err(refused("native_gateway_admin_material_changed"));
        }
        self.candidate
            .revalidate()
            .map_err(|_| refused("native_gateway_admin_material_changed"))?;
        let marker = native_state::decode_marker(self.files[0].bytes())
            .map_err(|_| refused("native_gateway_admin_material_changed"))?;
        let state = native_state::decode_state(self.files[1].bytes(), &marker)
            .map_err(|_| refused("native_gateway_admin_material_changed"))?;
        let current = crate::store::native_host_snapshot::validated_runtime_selection(
            &self.root, &state, &marker,
        )
        .map_err(|_| refused("native_gateway_admin_material_changed"))?;
        if self
            .candidate
            .runtime_selection()
            .map_err(|_| refused("native_gateway_admin_material_changed"))?
            != current
        {
            return Err(refused("native_gateway_admin_material_changed"));
        }
        for old in &self.files {
            let now = self
                .root
                .read_raw(old.relative_path(), LIMIT)
                .map_err(|_| refused("native_gateway_admin_material_changed"))?;
            if now.observation() != old.observation() || now.bytes() != old.bytes() {
                return Err(refused("native_gateway_admin_material_changed"));
            }
        }
        Ok(())
    }
}
async fn checked(material: Material) -> Result<Material> {
    blocking(move || {
        material.validate()?;
        Ok(material)
    })
    .await
}
struct Output {
    root: PrivateRoot,
    path: PathBuf,
    name: std::ffi::OsString,
}
impl Output {
    fn preflight(path: PathBuf, material: &Material) -> Result<Self> {
        let parent = path
            .parent()
            .filter(|_| path.is_absolute())
            .ok_or_else(|| refused("native_gateway_invitation_output"))?;
        let name = path
            .file_name()
            .ok_or_else(|| refused("native_gateway_invitation_output"))?
            .to_owned();
        let root =
            PrivateRoot::open(parent).map_err(|_| refused("native_gateway_invitation_output"))?;
        let canonical_parent = std::fs::canonicalize(parent)
            .map_err(|_| refused("native_gateway_invitation_output"))?;
        let canonical_state = std::fs::canonicalize(&material.path)
            .map_err(|_| refused("native_gateway_invitation_output"))?;
        let canonical_payload = std::fs::canonicalize(
            &material
                .candidate
                .runtime_selection()
                .map_err(|_| refused("native_gateway_admin_candidate"))?
                .payload_path,
        )
        .map_err(|_| refused("native_gateway_invitation_output"))?;
        if root.identity() == material.root.identity()
            || canonical_parent.starts_with(canonical_state)
            || canonical_parent.starts_with(canonical_payload)
        {
            return Err(refused(
                "native_gateway_invitation_output_inside_state_or_payload",
            ));
        }
        root.ensure_absent(Path::new(&name))
            .map_err(|_| refused("native_gateway_invitation_output_exists"))?;
        Ok(Self { root, path, name })
    }
    fn publish(self, secret: &[u8]) -> Result<PathBuf> {
        let current =
            PrivateRoot::open(self.path.parent().ok_or_else(unknown)?).map_err(|_| unknown())?;
        if current.identity() != self.root.identity() {
            return Err(unknown());
        }
        let raw = self
            .root
            .create_pairing_invitation(&self.name, secret)
            .map_err(|_| unknown())?;
        if raw.bytes() != secret {
            return Err(unknown());
        }
        if PrivateRoot::open(self.path.parent().ok_or_else(unknown)?)
            .map_err(|_| unknown())?
            .identity()
            != self.root.identity()
        {
            return Err(unknown());
        }
        Ok(self.path)
    }
}
#[derive(Deserialize)]
struct Ingress {
    origin: String,
    certificate_sha256: Sha256Digest,
}
#[derive(Deserialize)]
struct PendingWire {
    request_id: String,
    device_id: DeviceId,
    fingerprint: Sha256Digest,
    comparison_code: String,
    expires_at: u64,
    computer_requested: bool,
    browser_requested: bool,
    ingress: Ingress,
}
fn pending_body(
    raw: &[u8],
    origins: &[String],
    leaf: &GatewayLeafPin,
    now: u64,
) -> Result<Vec<PendingDevice>> {
    if raw.is_empty() || raw.len() > 32 * 1024 || now == 0 {
        return Err(refused("native_gateway_pending_invalid"));
    }
    let rows: Vec<PendingWire> =
        serde_json::from_slice(raw).map_err(|_| refused("native_gateway_pending_invalid"))?;
    if rows.len() > 256 {
        return Err(refused("native_gateway_pending_invalid"));
    }
    let certificate = Sha256Digest::try_from(leaf.as_hex())
        .map_err(|_| refused("native_gateway_pending_invalid"))?;
    let mut ids = BTreeSet::new();
    let mut result = Vec::with_capacity(rows.len());
    for row in rows {
        let comparison = PairingComparison {
            gateway_origin: row.ingress.origin.clone(),
            certificate_sha256: certificate,
            request_id: row.request_id.clone(),
            device_fingerprint: row.fingerprint,
        }
        .comparison_code()
        .map_err(|_| refused("native_gateway_pending_invalid"))?;
        if !ids.insert(row.request_id.clone())
            || row.expires_at <= now
            || !origins.contains(&row.ingress.origin)
            || row.ingress.certificate_sha256 != certificate
            || row.comparison_code != comparison
        {
            return Err(refused("native_gateway_pending_binding_mismatch"));
        }
        result.push(PendingDevice {
            request_id: row.request_id,
            device_id: row.device_id,
            fingerprint: row.fingerprint,
            comparison_code: row.comparison_code,
            expires_at: row.expires_at,
            computer_requested: row.computer_requested,
            browser_requested: row.browser_requested,
            gateway_origin: row.ingress.origin,
        });
    }
    Ok(result)
}
fn approval_body(
    rows: &[PendingDevice],
    selected: &ApprovalSelection,
) -> Result<Zeroizing<Vec<u8>>> {
    let row = rows
        .iter()
        .find(|row| row.request_id == selected.request_id)
        .ok_or_else(|| refused("native_gateway_approval_binding_mismatch"))?;
    if row.device_id != selected.device_id
        || row.fingerprint != selected.fingerprint
        || row.comparison_code != selected.comparison_code
        || selected.enable_computer && !row.computer_requested
        || selected.enable_browser && !row.browser_requested
    {
        return Err(refused("native_gateway_approval_binding_mismatch"));
    }
    Ok(Zeroizing::new(serde_json::to_vec(&serde_json::json!({"request_id":selected.request_id,"fingerprint":selected.fingerprint,"enable_computer":selected.enable_computer,"enable_browser":selected.enable_browser})).map_err(|_| refused("native_gateway_admin_input"))?))
}
async fn read_pending(material: &Material) -> Result<Vec<PendingDevice>> {
    let response = http::exchange_local_pending(&material.origin, &material.tls, &material.token)
        .await
        .map_err(http_error)?;
    accepted_status(response.status)?;
    if response.leaf_pin != material.leaf {
        return Err(refused("native_gateway_pending_binding_mismatch"));
    }
    pending_body(
        &response.body,
        &material.origins,
        &response.leaf_pin,
        clock_ms()?,
    )
}
fn accepted_status(status: u16) -> Result<()> {
    match status {
        200 => Ok(()),
        400 | 401 | 403 | 404 | 409 | 429 => Err(AdminError {
            code: "native_gateway_admin_rejected",
            exit: 2,
            outcome: "rejected",
        }),
        _ => Err(unknown()),
    }
}
fn secret<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Zeroizing<String>, D::Error> {
    String::deserialize(d).map(Zeroizing::new)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Invitation {
    #[serde(deserialize_with = "secret")]
    invitation: Zeroizing<String>,
    expires_at: u64,
    one_use: bool,
}
#[derive(Deserialize)]
struct Capabilities {
    exec: bool,
    computer: bool,
    browser: bool,
}
#[derive(Deserialize)]
struct Approved {
    status: String,
    device_id: DeviceId,
    fingerprint: Sha256Digest,
    approved_capabilities: Capabilities,
}
fn invitation_app_link(
    invite: &Invitation,
    origin: &str,
    ca: &[u8],
    now: u64,
) -> Result<Zeroizing<String>> {
    let ca = std::str::from_utf8(ca).map_err(|_| unknown())?;
    crate::app::pairing_link::build(origin, &invite.invitation, invite.expires_at, ca, now)
        .map_err(|_| unknown())
}
async fn perform(action: Action) -> Result<AdminReport> {
    let state_dir = match &action {
        Action::Invite(p, _, _, _, _) | Action::Pending(p) | Action::Approve(p, _) => p.clone(),
    };
    let material = blocking(move || Material::open(state_dir)).await?;
    match action {
        Action::Pending(path) => {
            let rows = read_pending(&material).await?;
            let _material = checked(material).await?;
            let mut report = AdminReport::new("gateway_pending", path);
            report.pending = Some(rows);
            Ok(report)
        }
        Action::Invite(path, output, ttl, selection, app_output) => {
            if !(60..=600).contains(&ttl) {
                return Err(refused("native_gateway_invitation_ttl"));
            }
            let origin = invitation_origin(&material.origins, selection)?;
            let origins = material.origins.clone();
            let (material, output, app_output) = blocking(move || {
                material.validate()?;
                let output = Output::preflight(output, &material)?;
                let app_output = app_output
                    .map(|path| Output::preflight(path, &material))
                    .transpose()?;
                if app_output.as_ref().is_some_and(|app| {
                    app.root.identity() == output.root.identity() && app.name == output.name
                }) {
                    return Err(refused("native_gateway_invitation_outputs_conflict"));
                }
                Ok((material, output, app_output))
            })
            .await?;
            let body = serde_json::to_vec(&serde_json::json!({"ttl_seconds":ttl}))
                .map_err(|_| refused("native_gateway_admin_input"))?;
            let response = http::exchange_local_admin(
                &material.origin,
                &material.tls,
                false,
                &body,
                &material.token,
            )
            .await
            .map_err(http_error)?;
            accepted_status(response.status)?;
            let invite: Invitation =
                serde_json::from_slice(&response.body).map_err(|_| unknown())?;
            if !token(invite.invitation.as_bytes())
                || !invite.one_use
                || invite.expires_at <= clock_ms().map_err(|_| unknown())?
            {
                return Err(unknown());
            }
            let material = checked(material).await.map_err(|_| unknown())?;
            let expires = invite.expires_at;
            let link = if app_output.is_some() {
                Some(invitation_app_link(
                    &invite,
                    &origin,
                    material.files[4].bytes(),
                    clock_ms().map_err(|_| unknown())?,
                )?)
            } else {
                None
            };
            let (destination, app_destination) = blocking(move || {
                let destination = output.publish(invite.invitation.as_bytes())?;
                let app_destination = match (app_output, link) {
                    (Some(output), Some(link)) => Some(output.publish(link.as_bytes())?),
                    (None, None) => None,
                    _ => return Err(unknown()),
                };
                Ok((destination, app_destination))
            })
            .await
            .map_err(|_| unknown())?;
            let mut report = AdminReport::new("gateway_invite", path);
            report.invitation_file = Some(destination);
            report.app_link_file = app_destination;
            report.expires_at = Some(expires);
            report.one_use = Some(true);
            report.origin = Some(origin);
            report.origins = Some(origins);
            Ok(report)
        }
        Action::Approve(path, selected) => {
            let rows = read_pending(&material).await?;
            let body = approval_body(&rows, &selected)?; // Binding refusal is BEFORE the unique approval POST.
            let material = checked(material).await?;
            let response = http::exchange_local_admin(
                &material.origin,
                &material.tls,
                true,
                &body,
                &material.token,
            )
            .await
            .map_err(http_error)?;
            accepted_status(response.status)?;
            let approved: Approved =
                serde_json::from_slice(&response.body).map_err(|_| unknown())?;
            if approved.status != "approved"
                || approved.device_id != selected.device_id
                || approved.fingerprint != selected.fingerprint
                || !approved.approved_capabilities.exec
                || approved.approved_capabilities.computer != selected.enable_computer
                || approved.approved_capabilities.browser != selected.enable_browser
            {
                return Err(unknown());
            }
            let _material = checked(material).await.map_err(|_| unknown())?;
            let mut report = AdminReport::new("gateway_approve", path);
            report.status = Some("approved");
            report.request_id = Some(selected.request_id);
            report.device_id = Some(selected.device_id);
            report.fingerprint = Some(selected.fingerprint);
            report.comparison_code = Some(selected.comparison_code);
            Ok(report)
        }
    }
}
fn invitation_origin(origins: &[String], selected: Option<InvitationOrigin>) -> Result<String> {
    if let Some(InvitationOrigin::Address(address)) = selected {
        return origins
            .iter()
            .skip(1)
            .find(|origin| {
                url::Url::parse(origin)
                    .ok()
                    .and_then(|url| url.host_str()?.parse::<std::net::Ipv4Addr>().ok())
                    == Some(address)
            })
            .cloned()
            .ok_or_else(|| refused("native_gateway_origin_address_not_configured"));
    }
    let index = match selected {
        Some(InvitationOrigin::Loopback) => 0,
        Some(InvitationOrigin::Lan) => 1,
        Some(InvitationOrigin::Address(_)) => unreachable!("handled above"),
        None => usize::from(origins.len() > 1),
    };
    origins
        .get(index)
        .cloned()
        .ok_or_else(|| refused("native_gateway_lan_not_enabled"))
}
#[cfg(test)]
#[path = "native_gateway_admin_tests.rs"]
mod tests;
