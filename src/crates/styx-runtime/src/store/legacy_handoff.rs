//! Linux cooperative legacy-writer exclusion, not handoff/quiescence authority.
//! No schema replacement, runtime activation or unlink-on-Drop exists here.
//! Standalone host/connect.mjs does not honor these state-directory locks: real
//! execution settlement and platform manager proof remain a separate dependency.
#![cfg(all(target_os = "linux", target_env = "gnu"))]
use super::secure_journal::{JournalError, JournalResult};
use super::{
    ConfigurationMaintenance, FileObservation, OwnedConfigurationRoot, PreservationInput,
    PreservationRole, PrivateRoot, ProcessIdentity, RawFile, RootIdentity,
};
use nix::{
    errno::Errno,
    fcntl::{OFlag, openat},
    sys::stat::Mode,
    unistd::geteuid,
};
use serde::Serialize;
use std::{
    fs::File,
    io::Write,
    os::unix::fs::{FileExt, MetadataExt},
    path::PathBuf,
    sync::Arc,
};
use zeroize::Zeroizing;

/// Advance blocks core; foreground closes the old scope()->claim() race.
/// Background/capabilities also exclude independently entered legacy writers.
const LOCKS: &[&str] = &[
    "advance.lock",
    "foreground.lock",
    "background.lock",
    "capabilities.lock",
];
const MAX_FILES: usize = 32;
const MAX_FILE_BYTES: usize = 1024 * 1024;
const MAX_MATERIAL_BYTES: usize = 2 * 1024 * 1024;
const MAX_SERVICE_DESCRIPTOR_BYTES: usize = 64 * 1024;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyFenceError {
    InvalidMaterials,
    BusyOrUnresolved,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LegacyMaterialRoot {
    Configuration,
    Host,
}
/// Trusted runtime selection, never a deserializable remote path/authority.
/// A selection is NOT a complete signed-profile or quiescence proof.
pub struct LegacyMaterialInput {
    pub root: LegacyMaterialRoot,
    pub input: PreservationInput,
    pub max_bytes: usize,
}
/// Facts only. The borrowed binding cannot reconstruct a fence or writer.
pub struct LegacyMaterialBinding {
    pub root: LegacyMaterialRoot,
    pub relative_path: PathBuf,
    pub role: PreservationRole,
    pub observation: FileObservation,
}
struct FrozenFile {
    binding: LegacyMaterialBinding,
    sha256: String,
    bytes: Zeroizing<Vec<u8>>,
    limit: usize,
}
struct PinnedLegacyLock {
    name: &'static str,
    file: File,
    raw: Vec<u8>,
    stamp: Option<FileObservation>,
}
/// Protected material selection only. This is NOT a signed service proof,
/// execution authority, unit selection or evidence that any runtime has stopped.
/// The platform manager must separately authenticate the original publisher,
/// bootstrap closure, unit, manager, invocation and live process before control.
/// No caller-supplied DTO or boolean can reconstruct this original observation.
pub struct LegacyServiceDescriptor {
    host: RootIdentity,
    raw: RawFile,
}
impl LegacyServiceDescriptor {
    pub fn capture(host: &PrivateRoot) -> Result<Self, LegacyFenceError> {
        let raw = host
            .read_raw("service.json", MAX_SERVICE_DESCRIPTOR_BYTES)
            .map_err(|_| LegacyFenceError::InvalidMaterials)?;
        Ok(Self {
            host: host.identity(),
            raw,
        })
    }
    pub fn host_root_identity(&self) -> RootIdentity {
        self.host.clone()
    }
    /// Private configuration material: do not log these bytes by default.
    pub fn raw_bytes(&self) -> &[u8] {
        self.raw.bytes()
    }
    pub fn raw_sha256(&self) -> styx_contracts::identity::Sha256Digest {
        styx_contracts::identity::Sha256Digest::of_bytes(self.raw.bytes())
    }
    fn revalidate(&self, host: &PrivateRoot) -> Result<(), LegacyFenceError> {
        if self.host != host.identity() {
            return Err(LegacyFenceError::InvalidMaterials);
        }
        let now = host
            .read_raw("service.json", MAX_SERVICE_DESCRIPTOR_BYTES)
            .map_err(|_| LegacyFenceError::BusyOrUnresolved)?;
        if now.observation() != self.raw.observation() || now.bytes() != self.raw.bytes() {
            return Err(LegacyFenceError::BusyOrUnresolved);
        }
        Ok(())
    }
}
/// Never Clone/Deserialize. Dropping leaves every created guard name intact;
/// absent/dead process or file absence is never interpreted as quiescence.
pub struct LegacyWriterFence {
    owner: OwnedConfigurationRoot,
    maintenance: ConfigurationMaintenance,
    host: PrivateRoot,
    host_identity: RootIdentity,
    locks: Vec<PinnedLegacyLock>,
    frozen: Vec<FrozenFile>,
    service: Option<Arc<LegacyServiceDescriptor>>,
}
impl std::fmt::Debug for LegacyWriterFence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LegacyWriterFence")
            .field("owned_lock_count", &self.locks.len())
            .field("material_count", &self.frozen.len())
            .finish_non_exhaustive()
    }
}
/// Retains the SAME writer/maintenance and all partially created original FDs.
/// It has no retry/adopt/unlink/ready conversion; original-ID recovery is future work.
#[must_use]
pub struct LegacyFenceFailure {
    error: LegacyFenceError,
    retained: Box<LegacyWriterFence>,
}
impl std::fmt::Debug for LegacyFenceFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LegacyFenceFailure")
            .field("error", &self.error)
            .field("retained", &self.retained)
            .finish()
    }
}
impl LegacyFenceFailure {
    pub fn error(&self) -> LegacyFenceError {
        self.error
    }
    pub fn retained_lock_count(&self) -> usize {
        self.retained.locks.len()
    }
    pub fn configuration_root(&self) -> &OwnedConfigurationRoot {
        &self.retained.owner
    }
}
#[derive(Serialize)]
struct LockRecord<'a> {
    schema: u16,
    kind: &'static str,
    transaction_id: &'a styx_contracts::identity::TransactionId,
    root: RootIdentity,
    process: ProcessIdentity,
    owner_generation: String,
}
impl LegacyWriterFence {
    pub fn acquire(
        owner: OwnedConfigurationRoot,
        maintenance: ConfigurationMaintenance,
        host: PrivateRoot,
        inputs: &[LegacyMaterialInput],
    ) -> Result<Self, LegacyFenceFailure> {
        Self::acquire_selected(owner, maintenance, host, inputs, None)
    }
    /// Explicit protected service-material branch, never a stopped-service or
    /// handoff grant. The default acquire path still requires service absence.
    pub fn acquire_with_service_descriptor(
        owner: OwnedConfigurationRoot,
        maintenance: ConfigurationMaintenance,
        host: PrivateRoot,
        inputs: &[LegacyMaterialInput],
        descriptor: Arc<LegacyServiceDescriptor>,
    ) -> Result<Self, LegacyFenceFailure> {
        Self::acquire_selected(owner, maintenance, host, inputs, Some(descriptor))
    }
    fn acquire_selected(
        owner: OwnedConfigurationRoot,
        maintenance: ConfigurationMaintenance,
        host: PrivateRoot,
        inputs: &[LegacyMaterialInput],
        service: Option<Arc<LegacyServiceDescriptor>>,
    ) -> Result<Self, LegacyFenceFailure> {
        let mut fence = Self {
            host_identity: host.identity(),
            owner,
            maintenance,
            host,
            locks: Vec::with_capacity(LOCKS.len()),
            frozen: Vec::new(),
            service,
        };
        let outcome = fence.acquire_inner(inputs);
        match outcome {
            Ok(()) => Ok(fence),
            Err(error) => Err(LegacyFenceFailure {
                error,
                retained: Box::new(fence),
            }),
        }
    }
    fn acquire_inner(&mut self, inputs: &[LegacyMaterialInput]) -> Result<(), LegacyFenceError> {
        if inputs.is_empty()
            || inputs.len() + usize::from(self.service.is_some()) > MAX_FILES
            || inputs
                .iter()
                .any(|i| i.max_bytes == 0 || i.max_bytes > MAX_FILE_BYTES)
        {
            return Err(LegacyFenceError::InvalidMaterials);
        }
        if inputs.iter().any(|i| !allowed_material(i)) {
            return Err(LegacyFenceError::InvalidMaterials);
        }
        let mut unique = std::collections::BTreeSet::new();
        if inputs
            .iter()
            .any(|i| !unique.insert((i.root, i.input.relative_path.clone())))
        {
            return Err(LegacyFenceError::InvalidMaterials);
        }
        // Selection only: neither branch proves service quiescence.
        self.validate_service_selection()?;
        let mut entropy = [0u8; 32];
        getrandom::fill(&mut entropy).map_err(|_| LegacyFenceError::Unknown)?;
        let root = self
            .owner
            .identity()
            .map_err(|_| LegacyFenceError::Unknown)?;
        let raw = serde_json::to_vec(&LockRecord {
            schema: 1,
            kind: "styx-rust-legacy-writer-fence-v1",
            transaction_id: self.maintenance.transaction_id(),
            root,
            process: ProcessIdentity::current().map_err(|_| LegacyFenceError::Unknown)?,
            owner_generation: hex::encode(entropy),
        })
        .map_err(|_| LegacyFenceError::Unknown)?;
        let locks = &mut self.locks;
        self.owner
            .with_maintenance(&self.maintenance, |state| {
                state
                    .root
                    .ensure_absent("foreground-recovery.lock")
                    .map_err(|_| JournalError::Conflict)?;
                state
                    .root
                    .inner
                    .with_configuration_writer_directory(&state.writer, |directory| {
                        Ok((|| {
                            for name in LOCKS {
                                let descriptor = openat(
                                    directory,
                                    *name,
                                    OFlag::O_RDWR
                                        | OFlag::O_CREAT
                                        | OFlag::O_EXCL
                                        | OFlag::O_NONBLOCK
                                        | OFlag::O_NOFOLLOW
                                        | OFlag::O_CLOEXEC,
                                    Mode::S_IRUSR | Mode::S_IWUSR,
                                )
                                .map_err(|e| {
                                    if e == Errno::EEXIST {
                                        JournalError::Conflict
                                    } else {
                                        JournalError::Unknown
                                    }
                                })?;
                                // Retain before first write/fsync. A partial failure never forgets its name.
                                locks.push(PinnedLegacyLock {
                                    name,
                                    file: File::from(descriptor),
                                    raw: raw.clone(),
                                    stamp: None,
                                });
                                let lock = locks.last_mut().ok_or(JournalError::Unknown)?;
                                private_stamp(&lock.file)?;
                                lock.file
                                    .write_all(&lock.raw)
                                    .map_err(|_| JournalError::Unknown)?;
                                lock.file.sync_all().map_err(|_| JournalError::Unknown)?;
                                directory.sync_all().map_err(|_| JournalError::Unknown)?;
                                lock.stamp = Some(private_stamp(&lock.file)?);
                            }
                            validate_locks(directory, locks)
                        })())
                    })
                    .map_err(|_| JournalError::Unknown)?
            })
            .map_err(classify)?;
        let mut total = self
            .service
            .as_ref()
            .map_or(0, |service| service.raw.bytes().len());
        for input in inputs {
            let raw = self
                .owner
                .with_maintenance(&self.maintenance, |state| {
                    let root = match input.root {
                        LegacyMaterialRoot::Configuration => &state.root,
                        LegacyMaterialRoot::Host => &self.host,
                    };
                    root.read_raw(&input.input.relative_path, input.max_bytes)
                        .map_err(|_| JournalError::Unknown)
                })
                .map_err(classify)?;
            let RawFile {
                relative_path,
                bytes,
                sha256,
                observation,
            } = raw;
            let bytes = Zeroizing::new(bytes);
            total = total
                .checked_add(bytes.len())
                .filter(|n| *n <= MAX_MATERIAL_BYTES)
                .ok_or(LegacyFenceError::InvalidMaterials)?;
            if let Some(policy) = &input.input.json_version {
                super::json_version(&bytes, policy)
                    .map_err(|_| LegacyFenceError::InvalidMaterials)?;
            }
            self.frozen.push(FrozenFile {
                binding: LegacyMaterialBinding {
                    root: input.root,
                    relative_path,
                    role: input.input.role.clone(),
                    observation,
                },
                sha256,
                bytes,
                limit: input.max_bytes,
            });
        }
        self.validate()
    }
    /// Rechecks original names/FDs/raw bytes and materials under the same writer.
    /// Success means writer exclusion/preservation only, NEVER stopped/ready.
    pub fn validate(&self) -> Result<(), LegacyFenceError> {
        if self.locks.len() != LOCKS.len() || self.host.identity() != self.host_identity {
            return Err(LegacyFenceError::Unknown);
        }
        self.owner
            .with_maintenance(&self.maintenance, |state| {
                self.validate_service_selection()
                    .map_err(|_| JournalError::Conflict)?;
                state
                    .root
                    .ensure_absent("foreground-recovery.lock")
                    .map_err(|_| JournalError::Conflict)?;
                state
                    .root
                    .inner
                    .with_configuration_writer_directory(&state.writer, |directory| {
                        Ok(validate_locks(directory, &self.locks))
                    })
                    .map_err(|_| JournalError::Unknown)??;
                for old in &self.frozen {
                    let root = match old.binding.root {
                        LegacyMaterialRoot::Configuration => &state.root,
                        LegacyMaterialRoot::Host => &self.host,
                    };
                    let current = root
                        .read_raw(&old.binding.relative_path, old.limit)
                        .map_err(|_| JournalError::Unknown)?;
                    if current.observation() != &old.binding.observation
                        || current.sha256() != old.sha256
                        || current.bytes() != old.bytes.as_slice()
                    {
                        return Err(JournalError::Conflict);
                    }
                }
                Ok(())
            })
            .map_err(classify)
    }
    fn validate_service_selection(&self) -> Result<(), LegacyFenceError> {
        match &self.service {
            Some(descriptor) => descriptor.revalidate(&self.host),
            None => self
                .host
                .ensure_absent("service.json")
                .map_err(|_| LegacyFenceError::BusyOrUnresolved),
        }
    }
    /// The SAME continuously validated configuration writer and original Host
    /// material must match the manager's independently verified service inputs.
    /// This does not promote descriptor bytes to service control authority.
    pub fn verify_service_descriptor(
        &self,
        descriptor: &LegacyServiceDescriptor,
    ) -> Result<(), LegacyFenceError> {
        self.validate()?;
        let held = self
            .service
            .as_ref()
            .ok_or(LegacyFenceError::InvalidMaterials)?;
        if held.host != descriptor.host
            || held.raw.observation() != descriptor.raw.observation()
            || held.raw.bytes() != descriptor.raw.bytes()
        {
            return Err(LegacyFenceError::InvalidMaterials);
        }
        descriptor.revalidate(&self.host)
    }
    pub fn configuration_root(&self) -> &OwnedConfigurationRoot {
        &self.owner
    }
    pub fn material_bindings(&self) -> impl Iterator<Item = &LegacyMaterialBinding> {
        self.frozen.iter().map(|v| &v.binding)
    }
}
// Closed first-slice material vocabulary, not an arbitrary path reader. External
// CA roots, signed release closure, Browser state and native permission proof
// need their own already-validated profile binding before any future handoff.
fn allowed_material(input: &LegacyMaterialInput) -> bool {
    use LegacyMaterialRoot::{Configuration, Host};
    use PreservationRole::{
        DeploymentConfiguration, DeviceIdentity, DevicePrivateKey, GatewayCa, PairingCredential,
        PublisherTrust,
    };
    matches!(
        (
            input.root,
            &input.input.role,
            input.input.relative_path.to_str()
        ),
        (
            Configuration,
            DeploymentConfiguration,
            Some("deployment.json" | "state.json")
        ) | (Host, DeviceIdentity, Some("device/identity.json"))
            | (Host, DevicePrivateKey, Some("device/identity.pem"))
            | (
                Host,
                PairingCredential,
                Some("device/host.json" | "device/host.token")
            )
            | (Host, GatewayCa, Some("gateway-ca.pem"))
            | (
                Host,
                PublisherTrust,
                Some("publisher.pem" | "install/active.json")
            )
    )
}
fn classify(error: JournalError) -> LegacyFenceError {
    match error {
        JournalError::Conflict => LegacyFenceError::BusyOrUnresolved,
        JournalError::InvalidInput | JournalError::BudgetExceeded => {
            LegacyFenceError::InvalidMaterials
        }
        _ => LegacyFenceError::Unknown,
    }
}
fn private_stamp(file: &File) -> JournalResult<FileObservation> {
    let m = file.metadata().map_err(|_| JournalError::Unknown)?;
    if !m.is_file() || m.uid() != geteuid().as_raw() || m.mode() & 0o7777 != 0o600 || m.nlink() != 1
    {
        return Err(JournalError::Unknown);
    }
    Ok(FileObservation {
        device: m.dev(),
        inode: m.ino(),
        byte_len: m.len(),
        modified_seconds: m.mtime(),
        modified_nanoseconds: m.mtime_nsec(),
        changed_seconds: m.ctime(),
        changed_nanoseconds: m.ctime_nsec(),
    })
}
fn exact_read(file: &File, length: usize) -> JournalResult<Vec<u8>> {
    if length > 4096 {
        return Err(JournalError::Unknown);
    }
    let mut bytes = vec![0u8; length];
    file.read_exact_at(&mut bytes, 0)
        .map_err(|_| JournalError::Unknown)?;
    Ok(bytes)
}
fn validate_locks(directory: &File, locks: &[PinnedLegacyLock]) -> JournalResult<()> {
    for old in locks {
        let expected = old.stamp.as_ref().ok_or(JournalError::Unknown)?;
        let named = File::from(
            openat(
                directory,
                old.name,
                OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| JournalError::Unknown)?,
        );
        if &private_stamp(&old.file)? != expected
            || &private_stamp(&named)? != expected
            || exact_read(&old.file, old.raw.len())? != old.raw
            || exact_read(&named, old.raw.len())? != old.raw
            || &private_stamp(&old.file)? != expected
            || &private_stamp(&named)? != expected
        {
            return Err(JournalError::Conflict);
        }
    }
    Ok(())
}
#[cfg(test)]
#[path = "legacy_handoff_tests.rs"]
mod tests;
