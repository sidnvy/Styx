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
}
/// Holds the original directory descriptor; revalidation never adopts a replaced
/// tree. This is a detected-change observation, not an atomic filesystem snapshot.
pub struct PayloadInventory {
    pub(super) members: Vec<PayloadMember>,
    #[cfg(target_os = "linux")]
    pub(super) inner: platform::PayloadSnapshot,
}
impl PayloadInventory {
    pub fn members(&self) -> &[PayloadMember] {
        &self.members
    }
    pub fn revalidate(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.inner.revalidate()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(StoreError::Unsupported)
        }
    }
    pub fn pin_executable(&self, relative: impl AsRef<Path>) -> Result<PinnedExecutable> {
        let relative = checked_relative(relative.as_ref())?;
        #[cfg(target_os = "linux")]
        {
            self.inner
                .pin_executable(&relative)
                .map(|inner| PinnedExecutable { inner })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = relative;
            Err(StoreError::Unsupported)
        }
    }
}
/// A pinned observed ELF image, not a signature or execution grant. The owning
/// bootstrap must retain this object until its child has actually been reaped.
pub struct PinnedExecutable {
    #[cfg(target_os = "linux")]
    inner: platform::PinnedImage,
}
impl PinnedExecutable {
    pub fn revalidate(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.inner.revalidate()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(StoreError::Unsupported)
        }
    }
    /// Linux resolves this retained parent FD, never a freshly substituted path.
    /// Script interpreters are deliberately unsupported by this native-image port.
    pub fn launch_path(&self) -> Result<PathBuf> {
        #[cfg(target_os = "linux")]
        {
            self.inner.launch_path()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(StoreError::Unsupported)
        }
    }
}
impl PrivateRoot {
    pub fn payload_inventory(&self, limits: PayloadLimits) -> Result<PayloadInventory> {
        limits.validate()?;
        #[cfg(target_os = "linux")]
        {
            self.inner.payload_inventory(limits)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(StoreError::Unsupported)
        }
    }
}

#[cfg(test)]
#[path = "payload_tests.rs"]
mod tests;
