//! Read-only legacy observations and distinct, fail-closed ownership resources.
//!
//! Raw bytes are authoritative: this module never normalizes or rewrites legacy
//! JSON. A preservation manifest is a per-file observation, not a transactional
//! snapshot or permission to migrate. Linux implements writable stores; macOS
//! adds private raw reads and independent leases only. Other platform operations
//! remain explicitly Unsupported; read/lease support is not migration authority.
//! Secrets are not included in Debug output or preservation manifests.

mod configuration;
pub mod enrollment;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub mod legacy_handoff;
pub mod management;
pub mod native_root;
pub mod native_state;
pub mod native_transaction;
mod secure_journal;
pub use configuration::{ConfigurationMaintenance, OwnedConfigurationRoot};
mod payload;
pub use payload::{PayloadInventory, PayloadLimits, PayloadMember, PinnedExecutable};

use serde::{
    Serialize,
    de::{self, IgnoredAny, MapAccess, Visitor},
};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    path::{Component, Path, PathBuf},
};
use thiserror::Error;

#[cfg(target_os = "linux")]
#[path = "linux.rs"]
mod platform;
#[cfg(target_os = "macos")]
#[path = "macos.rs"]
mod platform;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[path = "unsupported.rs"]
mod platform;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("secure store operation unsupported on this platform")]
    Unsupported,
    #[error("absolute private root required")]
    InvalidRoot,
    #[error("relative, nonempty path without traversal required")]
    InvalidRelativePath,
    #[error("private current-user ownership/permissions required")]
    NotPrivate,
    #[error("regular unaliased file required")]
    NotRegularFile,
    #[error("file exceeds explicit read budget")]
    TooLarge,
    #[error("filesystem identity changed during observation")]
    Changed,
    #[error("ownership resource is busy: {0:?}")]
    Busy(LockResource),
    #[error("explicit supported JSON version required")]
    UnsupportedJsonVersion,
    #[error("invalid versioned JSON")]
    InvalidJson { line: usize, column: usize },
    #[error("duplicate preservation path")]
    DuplicatePath,
    #[error("operating-system entropy unavailable")]
    EntropyUnavailable,
    #[error("kernel process identity unavailable")]
    ProcessIdentityUnavailable,
    #[error("secure store I/O failed")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, StoreError>;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "platform", rename_all = "snake_case")]
pub enum RootIdentity {
    Linux {
        device: u64,
        inode: u64,
        uid: u32,
    },
    #[cfg(target_os = "macos")]
    Macos {
        device: u64,
        inode: u64,
        uid: u32,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "platform", rename_all = "snake_case")]
pub enum ProcessIdentity {
    Linux {
        boot_id: String,
        pid: u32,
        start_ticks: u64,
    },
    #[cfg(target_os = "macos")]
    Macos {
        boot_session_id: String,
        pid: u32,
        start_seconds: u64,
        start_microseconds: u64,
        uid: u32,
    },
}

impl ProcessIdentity {
    /// Observe kernel birth identity; callers must still bind it to an authenticated OS peer.
    pub fn observe(pid: u32) -> Result<Self> {
        platform::process_identity(pid)
    }
    pub fn current() -> Result<Self> {
        platform::process_identity(std::process::id())
    }
    /// PID existence alone is never evidence of the same owner.
    pub fn still_current(&self) -> Result<bool> {
        platform::process_matches(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LockResource {
    ConfigurationWriter,
    Execution,
}

impl LockResource {
    fn filename(self) -> &'static str {
        match self {
            Self::ConfigurationWriter => ".styx-configuration-writer.lock",
            Self::Execution => ".styx-execution-lease.lock",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LeaseIdentity {
    pub resource: LockResource,
    pub root: RootIdentity,
    pub process: ProcessIdentity,
    pub owner_generation: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FileObservation {
    pub device: u64,
    pub inode: u64,
    pub byte_len: u64,
    pub modified_seconds: i64,
    pub modified_nanoseconds: i64,
    pub changed_seconds: i64,
    pub changed_nanoseconds: i64,
}

pub struct RawFile {
    relative_path: PathBuf,
    bytes: Vec<u8>,
    sha256: String,
    observation: FileObservation,
}
impl RawFile {
    pub fn relative_path(&self) -> &Path {
        &self.relative_path
    }
    /// Private material: callers must not log or serialize these bytes by default.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    pub fn observation(&self) -> &FileObservation {
        &self.observation
    }
}
impl fmt::Debug for RawFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawFile")
            .field("relative_path", &self.relative_path)
            .field("bytes", &"<redacted>")
            .field("byte_len", &self.bytes.len())
            .field("sha256", &self.sha256)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionField {
    Schema,
    Version,
}
impl VersionField {
    fn name(self) -> &'static str {
        match self {
            Self::Schema => "schema",
            Self::Version => "version",
        }
    }
}

#[derive(Clone, Debug)]
pub struct JsonVersionPolicy {
    pub field: VersionField,
    pub supported_versions: Vec<u64>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JsonVersion {
    pub field: VersionField,
    pub value: u64,
}
#[derive(Debug)]
pub struct VersionedJson {
    pub raw: RawFile,
    pub version: JsonVersion,
}

/// Parse only the explicitly selected version field, skip all other values without
/// converting their numbers, and retain the exact original JSON as authority.
fn json_error(error: serde_json::Error) -> StoreError {
    // serde error strings can echo private field contents; retain only positions.
    StoreError::InvalidJson {
        line: error.line(),
        column: error.column(),
    }
}

fn json_version(bytes: &[u8], policy: &JsonVersionPolicy) -> Result<JsonVersion> {
    struct VersionVisitor<'a>(&'a JsonVersionPolicy);
    impl<'de> Visitor<'de> for VersionVisitor<'_> {
        type Value = u64;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("versioned JSON object")
        }
        fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> std::result::Result<u64, M::Error> {
            let mut version = None;
            while let Some(key) = map.next_key::<String>()? {
                if key == self.0.field.name() {
                    if version.is_some() {
                        return Err(de::Error::custom("duplicate version field"));
                    }
                    version = Some(map.next_value::<u64>()?);
                } else {
                    map.next_value::<IgnoredAny>()?;
                }
            }
            version.ok_or_else(|| de::Error::custom("missing explicit version"))
        }
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value = de::Deserializer::deserialize_map(&mut decoder, VersionVisitor(policy))
        .map_err(json_error)?;
    decoder.end().map_err(json_error)?;
    if !policy.supported_versions.contains(&value) {
        return Err(StoreError::UnsupportedJsonVersion);
    }
    Ok(JsonVersion {
        field: policy.field,
        value,
    })
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreservationRole {
    DeviceIdentity,
    DevicePrivateKey,
    PairingCredential,
    GatewayCa,
    PublisherTrust,
    DeploymentConfiguration,
    BrowserState,
    NativePermissionResponsibility,
}
#[derive(Clone, Debug)]
pub struct PreservationInput {
    pub relative_path: PathBuf,
    pub role: PreservationRole,
    pub json_version: Option<JsonVersionPolicy>,
}
#[derive(Clone, Debug, Serialize)]
pub struct PreservedFile {
    pub relative_path: PathBuf,
    pub role: PreservationRole,
    pub sha256: String,
    pub observation: FileObservation,
    pub json_version: Option<JsonVersion>,
}
#[derive(Clone, Debug, Serialize)]
pub struct PreservationManifest {
    pub schema: u32,
    pub root: RootIdentity,
    /// Never an atomic multi-file snapshot; migration must obtain coordination.
    pub consistency: &'static str,
    pub entries: Vec<PreservedFile>,
}

pub struct PrivateRoot {
    inner: platform::Root,
}
impl PrivateRoot {
    /// Opens an existing root without creating or changing it. Linux rejects
    /// symlinks in the root path, even if they resolve inside the same directory.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            inner: platform::Root::open(path.as_ref())?,
        })
    }
    pub fn identity(&self) -> RootIdentity {
        self.inner.identity()
    }
    /// Read-only, descriptor-relative absence check. An existing file, directory,
    /// symlink or special node refuses admission; only ENOENT proves absence.
    /// This is an observation, never a lock against an uncoordinated legacy writer.
    pub fn ensure_absent(&self, relative: impl AsRef<Path>) -> Result<()> {
        self.inner
            .ensure_absent(&checked_relative(relative.as_ref())?)
    }
    pub fn read_raw(&self, relative: impl AsRef<Path>, max_bytes: usize) -> Result<RawFile> {
        let path = checked_relative(relative.as_ref())?;
        self.inner.read_raw(&path, max_bytes)
    }
    pub fn read_json(
        &self,
        relative: impl AsRef<Path>,
        max_bytes: usize,
        policy: &JsonVersionPolicy,
    ) -> Result<VersionedJson> {
        let raw = self.read_raw(relative, max_bytes)?;
        let version = json_version(raw.bytes(), policy)?;
        Ok(VersionedJson { raw, version })
    }
    /// Observes specified files twice to detect changes across the capture. This
    /// cannot prove a cross-file transaction against an uncoordinated writer.
    /// No files, including lock files, are created by this read-only method.
    pub fn preservation_manifest(
        &self,
        inputs: &[PreservationInput],
        max_bytes_per_file: usize,
    ) -> Result<PreservationManifest> {
        let mut seen = std::collections::BTreeSet::new();
        let mut entries = Vec::with_capacity(inputs.len());
        for input in inputs {
            let relative_path = checked_relative(&input.relative_path)?;
            if !seen.insert(relative_path.clone()) {
                return Err(StoreError::DuplicatePath);
            }
            let raw = self.read_raw(&relative_path, max_bytes_per_file)?;
            let version = input
                .json_version
                .as_ref()
                .map(|policy| json_version(raw.bytes(), policy))
                .transpose()?;
            entries.push(PreservedFile {
                relative_path,
                role: input.role.clone(),
                sha256: raw.sha256,
                observation: raw.observation,
                json_version: version,
            });
        }
        for entry in &entries {
            let observed = self.read_raw(&entry.relative_path, max_bytes_per_file)?;
            if observed.sha256 != entry.sha256 || observed.observation != entry.observation {
                return Err(StoreError::Changed);
            }
        }
        Ok(PreservationManifest {
            schema: 1,
            root: self.identity(),
            consistency: "per_file_stable_not_transactional",
            entries,
        })
    }
    /// Explicit mutation of the ownership namespace only: creates a dedicated
    /// 0600 lock file if absent. The lock file is never unlinked on release.
    pub fn try_configuration_writer(&self) -> Result<ConfigurationWriterGuard> {
        Ok(ConfigurationWriterGuard(
            self.inner.try_lock(LockResource::ConfigurationWriter)?,
        ))
    }
    /// Existing native ownership namespace only: never recreate a missing lock
    /// as a side effect of inspection/reopen. Fresh bootstrap uses the explicit
    /// creating acquisition above. Same validation/flock implementation.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn try_existing_configuration_writer(&self) -> Result<ConfigurationWriterGuard> {
        Ok(ConfigurationWriterGuard(
            self.inner
                .try_existing_lock(LockResource::ConfigurationWriter)?,
        ))
    }
    /// Separate resource and type from configuration writer ownership. Neither
    /// lock grants authority over unknown legacy owners/journals or live jobs.
    pub fn try_execution_lease(&self) -> Result<ExecutionLeaseGuard> {
        Ok(ExecutionLeaseGuard(
            self.inner.try_lock(LockResource::Execution)?,
        ))
    }
}

pub struct ConfigurationWriterGuard(platform::Lock);
pub struct ExecutionLeaseGuard(platform::Lock);
impl ConfigurationWriterGuard {
    pub fn identity(&self) -> &LeaseIdentity {
        self.0.identity()
    }
    pub fn validate(&self) -> Result<()> {
        self.0.validate()
    }
}
impl ExecutionLeaseGuard {
    pub fn identity(&self) -> &LeaseIdentity {
        self.0.identity()
    }
    pub fn validate(&self) -> Result<()> {
        self.0.validate()
    }
}

fn checked_relative(path: &Path) -> Result<PathBuf> {
    if path.as_os_str().is_empty() || path.to_str().is_none() {
        return Err(StoreError::InvalidRelativePath);
    }
    if !path.components().all(|c| matches!(c, Component::Normal(_))) {
        return Err(StoreError::InvalidRelativePath);
    }
    Ok(path.to_path_buf())
}
fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests;
