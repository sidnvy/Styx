//! Bounded read-only payload observations. Publisher authority belongs to the
//! caller verifying the original signed manifest, not to filesystem metadata.
use super::*;
use styx_contracts::identity::Sha256Digest;

#[derive(Clone, Copy, Debug)]
pub struct PayloadLimits {
    pub max_files: usize,
    pub max_directories: usize,
    pub max_depth: usize,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
}
impl Default for PayloadLimits {
    fn default() -> Self {
        Self {
            max_files: 4098,
            max_directories: 4096,
            max_depth: 32,
            max_file_bytes: 1024 * 1024 * 1024,
            max_total_bytes: 4 * 1024 * 1024 * 1024,
        }
    }
}
impl PayloadLimits {
    pub(super) fn validate(self) -> Result<()> {
        let cap = Self::default();
        if self.max_files == 0
            || self.max_files > cap.max_files
            || self.max_directories == 0
            || self.max_directories > cap.max_directories
            || self.max_depth == 0
            || self.max_depth > cap.max_depth
            || self.max_file_bytes == 0
            || self.max_file_bytes > cap.max_file_bytes
            || self.max_total_bytes == 0
            || self.max_total_bytes > cap.max_total_bytes
        {
            return Err(StoreError::TooLarge);
        }
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub struct PayloadMember {
    pub path: PathBuf,
    pub bytes: u64,
    pub sha256: Sha256Digest,
    pub executable: bool,
    pub observation: FileObservation,
}
/// Digests from an earlier full read, keyed by member path. A digest is reused
/// only while the file's device, inode, size, mtime and ctime are unchanged;
/// any other file is read and hashed again.
pub type KnownDigests = std::collections::BTreeMap<PathBuf, (FileObservation, Sha256Digest)>;
pub(super) fn known_digest(
    known: &KnownDigests,
    path: &Path,
    facts: &FileObservation,
) -> Option<Sha256Digest> {
    known
        .get(path)
        .filter(|(seen, _)| seen == facts)
        .map(|(_, digest)| *digest)
}
/// Holds the original directory descriptor; revalidation never adopts a replaced
/// tree. This is a detected-change observation, not an atomic filesystem snapshot.
pub struct PayloadInventory {
    pub(super) members: Vec<PayloadMember>,
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    pub(super) inner: platform::PayloadSnapshot,
}
impl PayloadInventory {
    pub fn members(&self) -> &[PayloadMember] {
        &self.members
    }
    pub fn revalidate(&self) -> Result<()> {
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        {
            self.inner.revalidate()
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            Err(StoreError::Unsupported)
        }
    }
    /// Windows native release closure only: CLI plus at most three fixed
    /// workers. This mints image pins, never publisher or execution authority.
    #[cfg(target_os = "windows")]
    pub(crate) fn pin_executables(&self, relative: &[&Path]) -> Result<Vec<PinnedExecutable>> {
        if relative.is_empty() || relative.len() > 5 {
            return Err(StoreError::TooLarge);
        }
        // Reject the entire request before any filesystem observation. Windows
        // aliases differing only by case must not mint duplicate image slots.
        let paths = relative
            .iter()
            .map(|path| checked_relative(path))
            .collect::<Result<Vec<_>>>()?;
        let mut unique = std::collections::BTreeSet::new();
        for path in &paths {
            if !unique.insert(path.to_string_lossy().to_lowercase()) {
                return Err(StoreError::InvalidRelativePath);
            }
        }
        self.inner.pin_executables(&paths).map(|images| {
            images
                .into_iter()
                .map(|inner| PinnedExecutable { inner })
                .collect()
        })
    }
    pub fn pin_executable(&self, relative: impl AsRef<Path>) -> Result<PinnedExecutable> {
        let relative = checked_relative(relative.as_ref())?;
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        {
            self.inner
                .pin_executable(&relative)
                .map(|inner| PinnedExecutable { inner })
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            let _ = relative;
            Err(StoreError::Unsupported)
        }
    }
}
/// A pinned observed native image, not a signature or execution grant. The owning
/// bootstrap must retain this object until its child has actually been reaped.
pub struct PinnedExecutable {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    inner: platform::PinnedImage,
}
impl PinnedExecutable {
    pub fn revalidate(&self) -> Result<()> {
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        {
            self.inner.revalidate()
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            Err(StoreError::Unsupported)
        }
    }
    /// Linux resolves this retained parent FD, never a freshly substituted path.
    /// Darwin remains Unsupported here: it requires the verified suspended-spawn port.
    /// Script interpreters are deliberately unsupported by this native-image port.
    pub fn launch_path(&self) -> Result<PathBuf> {
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        {
            self.inner.launch_path()
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            Err(StoreError::Unsupported)
        }
    }
}
#[cfg(any(target_os = "macos", target_os = "windows"))]
impl PinnedExecutable {
    /// Only the suspended native-child adapter may use this source locator.
    /// Ordinary launch_path stays unsupported until loaded-image attestation.
    pub(crate) fn source_path_for_suspended_spawn(&self) -> Result<PathBuf> {
        self.inner.source_path_for_suspended_spawn()
    }
    #[cfg(target_os = "macos")]
    pub(crate) fn expected_cdhash(&self) -> Result<Vec<u8>> {
        self.inner.expected_cdhash()
    }
    pub(crate) fn expected_sha256(&self) -> Result<Sha256Digest> {
        self.inner.expected_sha256()
    }
    pub(crate) fn retained_file(&self) -> Result<&std::fs::File> {
        self.inner.retained_file()
    }
}

impl PrivateRoot {
    /// Retain only the fixed native images of an installed signed manifest.
    /// Installation/update owns payload hashing; launch does not walk the tree.
    #[cfg(not(target_os = "windows"))]
    pub(crate) fn installed_images(
        &self,
        images: &[(PathBuf, u64, Sha256Digest)],
    ) -> Result<PayloadInventory> {
        validate_images(images)?;
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        {
            self.inner.installed_images(images)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            Err(StoreError::Unsupported)
        }
    }
    pub fn payload_inventory(&self, limits: PayloadLimits) -> Result<PayloadInventory> {
        self.payload_inventory_with_known(limits, &KnownDigests::new())
    }
    pub fn payload_inventory_with_known(
        &self,
        limits: PayloadLimits,
        known: &KnownDigests,
    ) -> Result<PayloadInventory> {
        limits.validate()?;
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        {
            self.inner.payload_inventory(limits, known)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            let _ = known;
            Err(StoreError::Unsupported)
        }
    }
}

pub(super) fn validate_images(images: &[(PathBuf, u64, Sha256Digest)]) -> Result<()> {
    if images.is_empty() || images.len() > 5 {
        return Err(StoreError::TooLarge);
    }
    let mut paths = std::collections::BTreeSet::new();
    for (path, bytes, _) in images {
        checked_relative(path)?;
        if *bytes > PayloadLimits::default().max_file_bytes
            || !paths.insert(path.to_string_lossy().to_lowercase())
        {
            return Err(StoreError::InvalidRelativePath);
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "payload_tests.rs"]
mod tests;
