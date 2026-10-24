//! Read-only C08 native release verification. No installation, migration,
//! activation, service mutation or child execution. Publisher approval and a
//! verified closure do not establish runtime health or final release acceptance.
#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
    all(
        target_os = "macos",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
use crate::store::PayloadLimits;
use crate::{
    crypto::{PublisherFingerprint, PublisherVerifyingKey, RawReleaseManifest},
    store::{PayloadInventory, PinnedExecutable, PrivateRoot, RawFile, StoreError},
};
use serde::Serialize;
#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
    all(
        target_os = "macos",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
    all(
        target_os = "macos",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
use styx_contracts::native_release::NativeReleaseTarget;
use styx_contracts::{
    identity::Sha256Digest,
    native_release::{
        NATIVE_RELEASE_MANIFEST_BYTES, NativeExternalWorker, NativeReleaseManifest,
        NativeReleaseScope,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReleaseError {
    #[error("native_release_platform_unsupported")]
    Unsupported,
    #[error("native_release_input_invalid")]
    Invalid,
    #[error("native_release_publisher_untrusted")]
    Untrusted,
    #[error("native_release_payload_integrity")]
    Integrity,
    #[error("native_release_observation_changed")]
    Changed,
    #[error("native_release_input_unavailable")]
    Unavailable,
    #[error("native_release_capacity")]
    Capacity,
    #[error("native_release_busy")]
    Busy,
    #[error("native_release_observation_unknown")]
    Unknown,
}
impl ReleaseError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Unsupported => "native_release_platform_unsupported",
            Self::Invalid => "native_release_input_invalid",
            Self::Untrusted => "native_release_publisher_untrusted",
            Self::Integrity => "native_release_payload_integrity",
            Self::Changed => "native_release_observation_changed",
            Self::Unavailable => "native_release_input_unavailable",
            Self::Capacity => "native_release_capacity",
            Self::Busy => "native_release_busy",
            Self::Unknown => "native_release_observation_unknown",
        }
    }
    pub fn exit_code(self) -> u8 {
        match self {
            Self::Invalid | Self::Untrusted | Self::Integrity | Self::Capacity => 2,
            Self::Unsupported | Self::Unavailable | Self::Busy => 3,
            Self::Changed | Self::Unknown => 4,
        }
    }
}
impl From<StoreError> for ReleaseError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::Unsupported => Self::Unsupported,
            StoreError::Changed | StoreError::ProcessIdentityUnavailable => Self::Changed,
            StoreError::TooLarge => Self::Capacity,
            StoreError::Busy(_) => Self::Busy,
            StoreError::InvalidRoot | StoreError::InvalidRelativePath => Self::Invalid,
            StoreError::Io(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                ) =>
            {
                Self::Unavailable
            }
            StoreError::NotPrivate | StoreError::NotRegularFile => Self::Integrity,
            _ => Self::Unknown,
        }
    }
}
type Result<T> = std::result::Result<T, ReleaseError>;

/// Public metadata only. No raw manifest, filenames other than the fixed entry,
/// publisher-file locator, PEM, signature, private profile or credentials.
#[derive(Debug, Clone, Serialize)]
pub struct ReleaseReport {
    pub schema: u16,
    pub scope: &'static str,
    pub runtime_format: &'static str,
    pub component: &'static str,
    pub version: String,
    pub target: &'static str,
    pub entrypoint: &'static str,
    pub source_revision: String,
    pub source_inputs_sha256: Sha256Digest,
    pub manifest_sha256: Sha256Digest,
    pub publisher_spki_sha256: String,
    pub member_count: usize,
    pub payload_bytes: u64,
    pub external_worker_count: usize,
    pub installed: bool,
    pub runtime_launched: bool,
}
/// Not Clone/Deserialize: this retains the original directory and native image
/// descriptions. A plain manifest DTO or launch pathname cannot reconstruct it.
/// A caller launching this image must keep this object until real child reaping.
pub struct VerifiedNativeRelease {
    root: PrivateRoot,
    manifest_file: RawFile,
    signature_file: RawFile,
    publisher_root: PrivateRoot,
    publisher_file: RawFile,
    expected: PublisherFingerprint,
    manifest: NativeReleaseManifest,
    inventory: PayloadInventory,
    executable: PinnedExecutable,
    workers: Vec<(NativeExternalWorker, PinnedExecutable)>,
    report: ReleaseReport,
}
impl VerifiedNativeRelease {
    pub fn report(&self) -> ReleaseReport {
        self.report.clone()
    }
    /// Verified data only, not a replacement for this object's pinned ownership.
    pub fn manifest(&self) -> &NativeReleaseManifest {
        &self.manifest
    }
    pub fn revalidate(&self) -> Result<()> {
        reobserve(
            &self.root,
            &self.manifest_file,
            NATIVE_RELEASE_MANIFEST_BYTES,
        )?;
        reobserve(&self.root, &self.signature_file, 64)?;
        reobserve(&self.publisher_root, &self.publisher_file, 4096)?;
        // Verify again from original exact bytes and the externally supplied pin;
        // a same-content metadata replacement was already refused above.
        let publisher = PublisherVerifyingKey::from_spki_pem(self.publisher_file.bytes())
            .map_err(|_| ReleaseError::Untrusted)?;
        publisher
            .verify_manifest(
                &self.expected,
                RawReleaseManifest::from_original_bytes(self.manifest_file.bytes()),
                self.signature_file.bytes(),
            )
            .map_err(|_| ReleaseError::Untrusted)?;
        self.inventory.revalidate().map_err(ReleaseError::from)?;
        self.executable.revalidate().map_err(ReleaseError::from)?;
        for (_, worker) in &self.workers {
            worker.revalidate().map_err(ReleaseError::from)?;
        }
        // No observations while streaming/revalidating may hide a moved name.
        reobserve(
            &self.root,
            &self.manifest_file,
            NATIVE_RELEASE_MANIFEST_BYTES,
        )?;
        reobserve(&self.root, &self.signature_file, 64)?;
        reobserve(&self.publisher_root, &self.publisher_file, 4096)?;
        Ok(())
    }
    /// The fixed worker's image was admitted by the SAME approved publisher and
    /// complete package inventory. This is neither a Core execution grant nor an
    /// OS permission. Retain this release through actual child cleanup; Darwin
    /// callers must use the verified suspended-spawn adapter, never a raw path.
    pub fn worker_image(&self, kind: NativeExternalWorker) -> Result<&PinnedExecutable> {
        self.revalidate()?;
        self.workers
            .iter()
            .find(|(candidate, _)| *candidate == kind)
            .map(|(_, image)| image)
            .ok_or(ReleaseError::Unsupported)
    }
    /// Trusted profile bootstrap only. This creates another original image pin
    /// from the same retained, approved inventory, never from a network path or
    /// a worker descriptor supplied separately from the verified release.
    pub(crate) fn pin_worker(&self, kind: NativeExternalWorker) -> Result<PinnedExecutable> {
        self.revalidate()?;
        let entry = &self
            .manifest
            .worker_closures
            .iter()
            .find(|worker| worker.kind == kind)
            .ok_or(ReleaseError::Unsupported)?
            .entrypoint;
        let pinned = self.inventory.pin_executable(entry)?;
        self.revalidate()?;
        Ok(pinned)
    }
    /// Returns only the fixed, retained native image's kernel FD path. This
    /// function does not spawn, install, activate or authorize arbitrary commands.
    pub fn launch_path(&self) -> Result<PathBuf> {
        self.revalidate()?;
        self.executable.launch_path().map_err(ReleaseError::from)
    }
}
fn reobserve(root: &PrivateRoot, original: &RawFile, limit: usize) -> Result<()> {
    let current = root
        .read_raw(original.relative_path(), limit)
        .map_err(ReleaseError::from)?;
    if current.bytes() != original.bytes()
        || current.observation() != original.observation()
        || current.sha256() != original.sha256()
    {
        return Err(ReleaseError::Changed);
    }
    Ok(())
}
#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
    all(
        target_os = "macos",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
static INSPECTORS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);

/// Async read-only client port. The actual blocking worker owns its permit;
/// dropping its waiter never admits an extra concurrent verifier.
pub async fn inspect(
    payload: &Path,
    publisher_file: &Path,
    expected_pin: &str,
) -> Result<ReleaseReport> {
    #[cfg(any(
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
        all(
            target_os = "macos",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    {
        let expected =
            PublisherFingerprint::parse(expected_pin).map_err(|_| ReleaseError::Invalid)?;
        let permit = INSPECTORS.try_acquire().map_err(|_| ReleaseError::Busy)?;
        let payload = payload.to_owned();
        let publisher_file = publisher_file.to_owned();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let verified = verify(&payload, &publisher_file, &expected)?;
            verified.revalidate()?;
            Ok(verified.report())
        })
        .await
        .map_err(|_| ReleaseError::Unknown)?
    }
    #[cfg(not(any(
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
        all(
            target_os = "macos",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )))]
    {
        let _ = (payload, publisher_file, expected_pin);
        Err(ReleaseError::Unsupported)
    }
}

/// The external public key must already have an independently approved pin.
/// Bundling a new publisher.pem beside a package never supplies that trust.
pub fn verify(
    payload: &Path,
    publisher_file: &Path,
    expected: &PublisherFingerprint,
) -> Result<VerifiedNativeRelease> {
    #[cfg(any(
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
        all(
            target_os = "macos",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    {
        verify_native(payload, publisher_file, expected)
    }
    #[cfg(not(any(
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
        all(
            target_os = "macos",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )))]
    {
        let _ = (payload, publisher_file, expected);
        Err(ReleaseError::Unsupported)
    }
}
#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
    all(
        target_os = "macos",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn verify_native(
    payload: &Path,
    publisher_path: &Path,
    expected: &PublisherFingerprint,
) -> Result<VerifiedNativeRelease> {
    if !publisher_path.is_absolute() {
        return Err(ReleaseError::Invalid);
    }
    let parent = publisher_path.parent().ok_or(ReleaseError::Invalid)?;
    let name = publisher_path.file_name().ok_or(ReleaseError::Invalid)?;
    let publisher_root = PrivateRoot::open(parent)?;
    let publisher_file = publisher_root.read_raw(Path::new(name), 4096)?;
    let root = PrivateRoot::open(payload)?;
    let manifest_file = root.read_raw("manifest.json", NATIVE_RELEASE_MANIFEST_BYTES)?;
    let signature_file = root.read_raw("manifest.sig", 64)?;
    if signature_file.bytes().len() != 64 {
        return Err(ReleaseError::Invalid);
    }
    let publisher = PublisherVerifyingKey::from_spki_pem(publisher_file.bytes())
        .map_err(|_| ReleaseError::Untrusted)?;
    publisher
        .verify_manifest(
            expected,
            RawReleaseManifest::from_original_bytes(manifest_file.bytes()),
            signature_file.bytes(),
        )
        .map_err(|_| ReleaseError::Untrusted)?;
    let manifest: NativeReleaseManifest =
        serde_json::from_slice(manifest_file.bytes()).map_err(|_| ReleaseError::Invalid)?;
    manifest.validate().map_err(|_| ReleaseError::Invalid)?;
    let target = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => NativeReleaseTarget::LinuxX86_64Gnu,
        ("macos", "x86_64") => NativeReleaseTarget::MacosX86_64,
        ("macos", "aarch64") => NativeReleaseTarget::MacosAarch64,
        _ => return Err(ReleaseError::Unsupported),
    };
    if manifest.target != target {
        return Err(ReleaseError::Unsupported);
    }
    // Signed worker provenance cannot silently introduce another publisher.
    // Upstream source membership is attested by the build publisher; local
    // admission still verifies every actual packaged byte and native image.
    if manifest
        .worker_closures
        .iter()
        .any(|worker| worker.source_publisher_spki_sha256.to_hex() != expected.as_hex())
    {
        return Err(ReleaseError::Untrusted);
    }
    let mut expected_members = BTreeMap::new();
    for member in &manifest.files {
        if expected_members
            .insert(
                PathBuf::from(&member.path),
                (member.size, member.sha256, member.executable),
            )
            .is_some()
        {
            return Err(ReleaseError::Invalid);
        }
    }
    for (path, file) in [
        ("manifest.json", &manifest_file),
        ("manifest.sig", &signature_file),
    ] {
        if expected_members
            .insert(
                PathBuf::from(path),
                (
                    file.bytes().len() as u64,
                    Sha256Digest::of_bytes(file.bytes()),
                    false,
                ),
            )
            .is_some()
        {
            return Err(ReleaseError::Invalid);
        }
    }
    let inventory = root.payload_inventory(PayloadLimits::default())?;
    if inventory.members().len() != expected_members.len() {
        return Err(ReleaseError::Integrity);
    }
    let mut payload_bytes = 0u64;
    for member in inventory.members() {
        let Some((size, digest, executable)) = expected_members.get(&member.path) else {
            return Err(ReleaseError::Integrity);
        };
        if member.bytes != *size || member.sha256 != *digest || member.executable != *executable {
            return Err(ReleaseError::Integrity);
        }
        payload_bytes = payload_bytes
            .checked_add(member.bytes)
            .ok_or(ReleaseError::Capacity)?;
    }
    let executable = inventory.pin_executable(Path::new(&manifest.entrypoint))?;
    let mut workers = Vec::with_capacity(manifest.worker_closures.len());
    for worker in &manifest.worker_closures {
        workers.push((worker.kind, inventory.pin_executable(&worker.entrypoint)?));
    }
    let report = ReleaseReport {
        schema: 1,
        scope: match manifest.scope {
            NativeReleaseScope::ConfigurationPreview => "configuration_preview",
            NativeReleaseScope::RuntimeCandidate => "runtime_candidate",
        },
        runtime_format: "native_rust_v1",
        component: "styx",
        version: manifest.version.clone(),
        target: match target {
            NativeReleaseTarget::LinuxX86_64Gnu => "x86_64-unknown-linux-gnu",
            NativeReleaseTarget::MacosX86_64 => "x86_64-apple-darwin",
            NativeReleaseTarget::MacosAarch64 => "aarch64-apple-darwin",
            NativeReleaseTarget::WindowsX86_64Msvc => return Err(ReleaseError::Unsupported),
        },
        entrypoint: target.entrypoint(),
        source_revision: manifest.source.revision.clone(),
        source_inputs_sha256: manifest.source.inputs_sha256,
        manifest_sha256: Sha256Digest::of_bytes(manifest_file.bytes()),
        publisher_spki_sha256: expected.as_hex().to_owned(),
        member_count: inventory.members().len(),
        payload_bytes,
        external_worker_count: manifest.external_workers.len(),
        installed: false,
        runtime_launched: false,
    };
    let verified = VerifiedNativeRelease {
        root,
        manifest_file,
        signature_file,
        publisher_root,
        publisher_file,
        expected: expected.clone(),
        manifest,
        inventory,
        executable,
        workers,
        report,
    };
    verified.revalidate()?;
    Ok(verified)
}
