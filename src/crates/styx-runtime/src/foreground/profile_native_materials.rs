//! Read-only original Pair materials under a borrowed live configuration fence.
//! No runtime, settlement, execution, grant or credential access is exposed.
use super::*;
use crate::store::{ConfigurationMaintenance, FileObservation, RootIdentity};
use styx_contracts::native_management::{NativePreservedHostPair, NativeRootIdentity};

struct InputPin {
    root: PrivateRoot,
    path: PathBuf,
    relative: PathBuf,
    observation: FileObservation,
    sha256: Sha256Digest,
    max: usize,
}
impl InputPin {
    fn revalidate(&self) -> Result<(), ProfileError> {
        let raw = self
            .root
            .read_raw(&self.relative, self.max)
            .map_err(|_| ProfileError::Changed)?;
        if raw.observation() != &self.observation
            || Sha256Digest::of_bytes(raw.bytes()) != self.sha256
        {
            return Err(ProfileError::Changed);
        }
        Ok(())
    }
}
/// No Clone, Debug, Serialize, Deref, into_inner or ordinary-profile getter.
/// The borrowed fence cannot be dropped while these original observations live.
pub(crate) struct OriginalNativePairMaterials<'a> {
    maintenance: &'a ConfigurationMaintenance,
    #[cfg(target_os = "macos")]
    retired_materials: Option<&'a crate::store::MacRetiredMaterialSource<'a>>,
    state_dir: PathBuf,
    config_root: NativeRootIdentity,
    host_root: NativeRootIdentity,
    original: LoadedLegacyProfile,
    pins: Vec<InputPin>,
    fingerprint: Sha256Digest,
    gateway_origin: String,
    ca_path: PathBuf,
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    publisher: Sha256Digest,
}
fn native_root(root: RootIdentity) -> NativeRootIdentity {
    match root {
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
pub(crate) fn read_original_pair_materials<'a>(
    state_dir: &Path,
    maintenance: &'a ConfigurationMaintenance,
) -> Result<OriginalNativePairMaterials<'a>, ProfileError> {
    read_pair_materials_inner(
        state_dir,
        maintenance,
        #[cfg(target_os = "macos")]
        None,
    )
}
/// Only the original retained OS retirement and same-journal plan can provide
/// this source. No caller path, credential bytes or JSON boolean substitutes it.
#[cfg(target_os = "macos")]
pub(crate) fn read_recovered_pair_materials<'a>(
    state_dir: &Path,
    maintenance: &'a ConfigurationMaintenance,
    source: &'a crate::store::MacRetiredMaterialSource<'a>,
) -> Result<OriginalNativePairMaterials<'a>, ProfileError> {
    source.validate().map_err(|_| ProfileError::Changed)?;
    if source.state_dir() != state_dir
        || &source.original_pair().transaction_id != maintenance.transaction_id()
    {
        return Err(ProfileError::Invalid);
    }
    read_pair_materials_inner(state_dir, maintenance, Some(source))
}
fn read_pair_materials_inner<'a>(
    state_dir: &Path,
    maintenance: &'a ConfigurationMaintenance,
    #[cfg(target_os = "macos")] retired_materials: Option<
        &'a crate::store::MacRetiredMaterialSource<'a>,
    >,
) -> Result<OriginalNativePairMaterials<'a>, ProfileError> {
    absolute(state_dir)?;
    let active_root = maintenance
        .validate_active()
        .map_err(|_| ProfileError::Changed)?;
    let root = PrivateRoot::open(state_dir).map_err(|_| ProfileError::ProtectedRead)?;
    if root.identity() != active_root {
        return Err(ProfileError::Changed);
    }
    let original = load_source_inner(
        state_dir,
        GatewayWireMode::PairedV3,
        ProfileSource::OriginalMaterials,
        #[cfg(target_os = "macos")]
        retired_materials,
    )?;
    let mut pins = Vec::with_capacity(original.observed.len());
    for observed in &original.observed {
        let root = PrivateRoot::open(&observed.root).map_err(|_| ProfileError::Changed)?;
        let raw = root
            .read_raw(&observed.relative, observed.max)
            .map_err(|_| ProfileError::Changed)?;
        let sha256 = Sha256Digest::of_bytes(raw.bytes());
        if sha256 != observed.digest {
            return Err(ProfileError::Changed);
        }
        pins.push(InputPin {
            path: observed.root.join(&observed.relative),
            root,
            relative: observed.relative.clone(),
            observation: raw.observation().clone(),
            sha256,
            max: observed.max,
        });
    }
    let host = PrivateRoot::open(&original.host_base_dir).map_err(|_| ProfileError::Changed)?;
    let identity: Identity = decode(
        host.read_raw("device/identity.json", JSON_LIMIT)
            .map_err(|_| ProfileError::Changed)?
            .bytes(),
    )?;
    let host_profile: HostProfile = decode(
        host.read_raw("device/host.json", JSON_LIMIT)
            .map_err(|_| ProfileError::Changed)?
            .bytes(),
    )?;
    let deployment: Deployment = decode(
        root.read_raw("deployment.json", JSON_LIMIT)
            .map_err(|_| ProfileError::Changed)?
            .bytes(),
    )?;
    let gateway_origin = origin(&deployment.gateway.url, "https")?
        .origin()
        .ascii_serialization();
    let _publisher = Sha256Digest::try_from(original.diagnostics.publisher_sha256.clone())
        .map_err(|_| ProfileError::Invalid)?;
    let result = OriginalNativePairMaterials {
        maintenance,
        #[cfg(target_os = "macos")]
        retired_materials,
        state_dir: state_dir.to_owned(),
        config_root: native_root(active_root),
        host_root: native_root(host.identity()),
        original,
        pins,
        fingerprint: Sha256Digest::try_from(identity.fingerprint)
            .map_err(|_| ProfileError::Invalid)?,
        gateway_origin,
        ca_path: host_profile.gateway_ca_file.ok_or(ProfileError::Invalid)?,
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        publisher: _publisher,
    };
    #[cfg(target_os = "macos")]
    let result = if let Some(source) = retired_materials {
        let mut result = result;
        result.restore_preserved_rows(source)?;
        result
    } else {
        result
    };
    result.revalidate()?;
    Ok(result)
}
impl OriginalNativePairMaterials<'_> {
    #[cfg(target_os = "macos")]
    fn restore_preserved_rows(
        &mut self,
        source: &crate::store::MacRetiredMaterialSource<'_>,
    ) -> Result<(), ProfileError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Row {
            path: PathBuf,
            sha256: Sha256Digest,
            bytes: u64,
            observation: serde_json::Value,
        }
        source.validate().map_err(|_| ProfileError::Changed)?;
        let pair = source.original_pair();
        if self.config_root != pair.config_root
            || &self.host_root != source.host_root_identity()
            || self.host_root != pair.host_root
            || Sha256Digest::of_bytes(source.preservation_raw()) != pair.preservation_sha256
        {
            return Err(ProfileError::Changed);
        }
        let rows: Vec<Row> = decode(source.preservation_raw())?;
        if rows.is_empty() || rows.len() > 128 {
            return Err(ProfileError::Invalid);
        }
        // The common loader includes publisher, active selector, its ORIGINAL
        // manifest/signature and both configured CA paths. Require equality of
        // the WHOLE deduplicated path set, not just the rows we happen to use.
        let current: BTreeMap<_, _> = self
            .pins
            .iter()
            .map(|pin| (pin.path.clone(), pin))
            .collect();
        let token_path = self.original.host_base_dir.join("device/host.token");
        if current.contains_key(&token_path) || rows.len() != current.len() + 1 {
            return Err(ProfileError::Changed);
        }
        let host = PrivateRoot::open(&self.original.host_base_dir)
            .map_err(|_| ProfileError::ProtectedRead)?;
        let token = source
            .read_retired_token(&host)
            .map_err(|_| ProfileError::Changed)?;
        if Sha256Digest::of_bytes(&token) != pair.credential_sha256 {
            return Err(ProfileError::Changed);
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut entries = Vec::with_capacity(rows.len());
        for row in rows {
            absolute(&row.path)?;
            if !seen.insert(row.path.clone()) || row.bytes == 0 || row.bytes > JSON_LIMIT as u64 {
                return Err(ProfileError::Invalid);
            }
            if row.path == token_path {
                // Source construction binds this historical row's FULL original
                // observation to the actual token's pre-stamp. A post-rename
                // descriptor is not represented as a pin at the absent source.
                if row.sha256 != pair.credential_sha256 || row.bytes != token.len() as u64 {
                    return Err(ProfileError::Changed);
                }
            } else {
                let pin = current.get(&row.path).ok_or(ProfileError::Changed)?;
                if pin.sha256 != row.sha256
                    || pin.observation.byte_len != row.bytes
                    || serde_json::to_value(&pin.observation).map_err(|_| ProfileError::Invalid)?
                        != row.observation
                {
                    return Err(ProfileError::Changed);
                }
                pin.revalidate()?;
            }
            entries.push(PreservationEntry {
                path: row.path,
                sha256: row.sha256,
                bytes: row.bytes,
            });
        }
        if !seen.contains(&token_path) || current.keys().any(|path| !seen.contains(path)) {
            return Err(ProfileError::Changed);
        }
        // Keep the original historical source row for pair/preservation DATA;
        // all live pins remain at their actual current paths.
        self.original.diagnostics.preservation = entries;
        if self.pair_binding(pair.preservation_sha256)? != *pair {
            return Err(ProfileError::Changed);
        }
        source.validate().map_err(|_| ProfileError::Changed)
    }
    #[cfg(target_os = "macos")]
    pub(crate) fn preservation_entries(&self) -> &[PreservationEntry] {
        &self.original.diagnostics.preservation
    }
    #[cfg(target_os = "macos")]
    pub(crate) fn executor_configured(&self) -> bool {
        self.original.executor_enabled()
    }
    fn validate_fence_and_roots(&self) -> Result<(), ProfileError> {
        if native_root(
            self.maintenance
                .validate_active()
                .map_err(|_| ProfileError::Changed)?,
        ) != self.config_root
            || native_root(
                PrivateRoot::open(&self.state_dir)
                    .map_err(|_| ProfileError::Changed)?
                    .identity(),
            ) != self.config_root
            || native_root(
                PrivateRoot::open(&self.original.host_base_dir)
                    .map_err(|_| ProfileError::Changed)?
                    .identity(),
            ) != self.host_root
        {
            return Err(ProfileError::Changed);
        }
        Ok(())
    }
    pub(crate) fn revalidate(&self) -> Result<(), ProfileError> {
        #[cfg(target_os = "macos")]
        if let Some(source) = self.retired_materials {
            source.validate().map_err(|_| ProfileError::Changed)?;
        }
        self.validate_fence_and_roots()?;
        self.original.revalidate()?;
        for pin in &self.pins {
            pin.revalidate()?;
        }
        #[cfg(target_os = "macos")]
        if let Some(source) = self.retired_materials {
            source.validate().map_err(|_| ProfileError::Changed)?;
        }
        self.validate_fence_and_roots()
    }
    /// Observation of the immutable subset ONLY. Does not attest either token
    /// retirement or canonical replacement; their actual native effect owners
    /// must supply those proofs separately. No caller-selected skip list exists.
    pub(crate) fn revalidate_preserved_materials(&self) -> Result<(), ProfileError> {
        self.validate_fence_and_roots()?;
        self.original
            .inventory
            .revalidate()
            .map_err(|_| ProfileError::Changed)?;
        if let Some(executor) = &self.original.executor {
            executor.revalidate().map_err(|_| ProfileError::Changed)?;
        }
        let canonical = self.state_dir.join("state.json");
        let token = self.original.host_base_dir.join("device/host.token");
        for pin in &self.pins {
            if pin.path != canonical && pin.path != token {
                pin.revalidate()?;
            }
        }
        self.validate_fence_and_roots()
    }
    fn digest(&self, path: &Path) -> Result<Sha256Digest, ProfileError> {
        #[cfg(target_os = "macos")]
        if let Some(source) = self.retired_materials
            && path == self.original.host_base_dir.join("device/host.token")
        {
            // Historical source digest, authenticated by the actual retirement
            // port; never a fabricated pin at the now-absent source pathname.
            return Ok(source.original_pair().credential_sha256);
        }
        self.pins
            .iter()
            .find(|pin| pin.path == path)
            .map(|pin| pin.sha256)
            .ok_or(ProfileError::Invalid)
    }
    pub(crate) fn before_sha256(&self) -> Result<Sha256Digest, ProfileError> {
        self.revalidate()?;
        self.digest(&self.state_dir.join("state.json"))
    }
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    pub(crate) fn publisher_sha256(&self) -> Result<Sha256Digest, ProfileError> {
        self.revalidate()?;
        Ok(self.publisher)
    }
    pub(crate) fn pair_binding(
        &self,
        preservation_sha256: Sha256Digest,
    ) -> Result<NativePreservedHostPair, ProfileError> {
        self.revalidate()?;
        let base = &self.original.host_base_dir;
        Ok(NativePreservedHostPair {
            schema: 1,
            transaction_id: self.maintenance.transaction_id().clone(),
            config_root: self.config_root.clone(),
            host_root: self.host_root.clone(),
            deployment_raw_sha256: self.digest(&self.state_dir.join("deployment.json"))?,
            device_id: self.original.device.clone(),
            fingerprint: self.fingerprint,
            gateway_origin: self.gateway_origin.clone(),
            gateway_ca_pem_sha256: self.digest(&self.ca_path)?,
            identity_json_sha256: self.digest(&base.join("device/identity.json"))?,
            identity_private_pem_sha256: self.digest(&base.join("device/identity.pem"))?,
            host_profile_sha256: self.digest(&base.join("device/host.json"))?,
            credential_sha256: self.digest(&base.join("device/host.token"))?,
            preservation_sha256,
        })
    }
}

/// Maintenance-only borrowed composition. No Clone, Deref, ordinary-profile
/// conversion or constructor accepting standalone read-only material data.
/// The owning migration task must retain the entire original native scope while
/// this value (and every Host/protocol/cleanup operation borrowing it) exists.
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(crate) struct AppliedNativeMaintenanceProfile<'borrow, 'effects, 'materials> {
    guard: &'borrow crate::store::NativeCanonicalCutover<'effects, 'materials>,
    host: PrivateRoot,
    executor: Arc<PinnedExecutable>,
    bearer: SecretBearer,
    selection: styx_contracts::native_management::NativeRuntimeSelection,
}

/// This is the ONLY construction path: the original applied physical guard,
/// not a read-only Pair snapshot, receipt, caller locator or serialized report.
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(crate) fn load_applied_native_maintenance_profile<'borrow, 'effects, 'materials>(
    guard: &'borrow crate::store::NativeCanonicalCutover<'effects, 'materials>,
) -> Result<AppliedNativeMaintenanceProfile<'borrow, 'effects, 'materials>, ProfileError> {
    use styx_contracts::{management::ReaderContract, native_release::NativeReleaseScope};
    guard
        .validate_applied()
        .map_err(|_| ProfileError::Changed)?;
    let original = &guard.original_materials().original;
    let pair = guard.original_pair();
    if pair.config_root != *guard.config_root()
        || pair.host_root != *guard.host_root()
        || pair.transaction_id != *guard.transaction_id()
        || pair.device_id != *original.device_id()
        || pair.fingerprint != guard.original_materials().fingerprint
        || pair.gateway_origin != guard.original_materials().gateway_origin
        || !original.executor_enabled()
    {
        return Err(ProfileError::Invalid);
    }
    let host =
        PrivateRoot::open(original.host_base_dir()).map_err(|_| ProfileError::ProtectedRead)?;
    if native_root(host.identity()) != pair.host_root {
        return Err(ProfileError::Changed);
    }
    let candidate = guard.candidate();
    let report = candidate.report();
    let selection = candidate
        .runtime_selection()
        .map_err(|_| ProfileError::UntrustedRelease)?;
    #[cfg(target_os = "macos")]
    let expected_target = match std::env::consts::ARCH {
        "x86_64" => "x86_64-apple-darwin",
        "aarch64" => "aarch64-apple-darwin",
        _ => return Err(ProfileError::Unsupported),
    };
    #[cfg(target_os = "windows")]
    let expected_target = match std::env::consts::ARCH {
        "x86_64" => "x86_64-pc-windows-msvc",
        _ => return Err(ProfileError::Unsupported),
    };
    #[cfg(target_os = "macos")]
    let native_payload = matches!(selection.payload_root, NativeRootIdentity::Macos { .. });
    #[cfg(target_os = "windows")]
    let native_payload = matches!(selection.payload_root, NativeRootIdentity::Windows { .. });
    if candidate.manifest().scope != NativeReleaseScope::RuntimeCandidate
        || report.target != expected_target
        || selection.schema != 1
        || !native_payload
        || selection.manifest_sha256 != report.manifest_sha256
        || selection.publisher_spki_sha256.to_hex() != report.publisher_spki_sha256
        || selection.publisher_spki_sha256 != guard.original_materials().publisher
        || !candidate
            .manifest()
            .minimum_reader
            .supports_state_reader(ReaderContract::NativeMigratedStateV2)
    {
        return Err(ProfileError::UntrustedRelease);
    }
    let executor = Arc::new(
        candidate
            .pin_worker(NativeExternalWorker::CodexExec)
            .map_err(|_| ProfileError::UntrustedRelease)?,
    );
    executor.revalidate().map_err(|_| ProfileError::Changed)?;
    let token = guard
        .read_retired_token(&host)
        .map_err(|_| ProfileError::Changed)?;
    if Sha256Digest::of_bytes(&token) != pair.credential_sha256 {
        return Err(ProfileError::Changed);
    }
    // Preserve the raw credential digest above; the existing on-disk format
    // permits a trailing newline and uses the narrower paired-token alphabet.
    let text = std::str::from_utf8(&token)
        .map_err(|_| ProfileError::Invalid)?
        .trim();
    if !(32..=4096).contains(&text.len())
        || !text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
    {
        return Err(ProfileError::Invalid);
    }
    let bearer =
        SecretBearer::from_protected_reader(text.to_owned()).map_err(|_| ProfileError::Invalid)?;
    let profile = AppliedNativeMaintenanceProfile {
        guard,
        host,
        executor,
        bearer,
        selection,
    };
    profile.revalidate()?;
    Ok(profile)
}
#[cfg(any(target_os = "macos", target_os = "windows"))]
impl AppliedNativeMaintenanceProfile<'_, '_, '_> {
    /// Exact retained physical cutover instance, not equality of public IDs.
    pub(crate) fn matches_cutover(
        &self,
        guard: &crate::store::NativeCanonicalCutover<'_, '_>,
    ) -> bool {
        std::ptr::eq(self.guard, guard)
    }
    pub(crate) fn original_pair(&self) -> &NativePreservedHostPair {
        self.guard.original_pair()
    }
    pub(crate) fn target_sha256(&self) -> Sha256Digest {
        self.guard.target_sha256()
    }

    pub(crate) fn transaction_id(&self) -> &styx_contracts::identity::TransactionId {
        self.guard.transaction_id()
    }
    fn original(&self) -> &LoadedLegacyProfile {
        &self.guard.original_materials().original
    }
    pub(crate) fn host_base_dir(&self) -> &Path {
        self.original().host_base_dir()
    }
    pub(crate) fn device_id(&self) -> &DeviceId {
        self.original().device_id()
    }
    pub(crate) fn endpoint(&self) -> &LinkEndpoint {
        self.original().endpoint()
    }
    pub(crate) fn paired_gateway_namespace(&self) -> GatewayId {
        self.original().paired_gateway_namespace()
    }
    pub(crate) fn tls(&self) -> &GatewayClientTls {
        self.original().tls()
    }
    /// This is the fixed retired-token FD result, never original.cached bearer.
    pub(crate) fn bearer(&self) -> &SecretBearer {
        &self.bearer
    }
    pub(crate) fn runtime_selection(
        &self,
    ) -> &styx_contracts::native_management::NativeRuntimeSelection {
        &self.selection
    }
    pub(crate) fn executor_image(&self) -> Result<Arc<PinnedExecutable>, ProfileError> {
        self.revalidate()?;
        Ok(self.executor.clone())
    }
    /// Scratch is created only after the probe holds the actual execution lease.
    /// The original profile retains the same protected directory as ordinary Host.
    #[cfg(target_os = "windows")]
    pub(crate) fn prepare_execution_runtime(
        &self,
        base: &PrivateRoot,
        lease: &crate::store::ExecutionLeaseGuard,
    ) -> Result<(), ProfileError> {
        self.revalidate()?;
        lease.validate().map_err(|_| ProfileError::Changed)?;
        if native_root(base.identity()) != *self.guard.host_root() {
            return Err(ProfileError::Changed);
        }
        self.original().prepare_runtime_temp(base)?;
        lease.validate().map_err(|_| ProfileError::Changed)?;
        self.revalidate()
    }
    pub(crate) fn executor_config(&self) -> Result<OwnedExecutorConfig, ProfileError> {
        self.revalidate()?;
        #[cfg(target_os = "windows")]
        self.original()
            .runtime_temp
            .get()
            .ok_or(ProfileError::ProtectedRead)?
            .revalidate_runtime_directory()
            .map_err(|_| ProfileError::Changed)?;
        let binary = self
            .executor
            .source_path_for_suspended_spawn()
            .map_err(|_| ProfileError::Changed)?;
        let original = self.original();
        let config = OwnedExecutorConfig {
            binary,
            cwd: original.cwd.clone(),
            environment: original.environment.clone(),
            rpc_timeout: original.rpc_timeout,
            retained_process_limit: 128,
        };
        self.revalidate()?;
        Ok(config)
    }
    pub(crate) fn revalidate(&self) -> Result<(), ProfileError> {
        #[cfg(target_os = "windows")]
        if let Some(temp) = self.original().runtime_temp.get() {
            temp.revalidate_runtime_directory()
                .map_err(|_| ProfileError::Changed)?;
        }
        self.guard
            .validate_applied()
            .map_err(|_| ProfileError::Changed)?;
        self.executor
            .revalidate()
            .map_err(|_| ProfileError::Changed)?;
        if native_root(self.host.identity()) != *self.guard.host_root() {
            return Err(ProfileError::Changed);
        }
        self.guard
            .validate_applied()
            .map_err(|_| ProfileError::Changed)
    }
}
