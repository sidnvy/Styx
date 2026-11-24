//! The native release retained by the Host profile.
use super::ProfileError;
use crate::{
    crypto::PublisherFingerprint,
    release::{ReleaseError, VerifiedNativeRelease},
    store::PinnedExecutable,
};
use std::{path::PathBuf, sync::Arc};
use styx_contracts::native_release::NativeExternalWorker;

pub(super) struct ProfileRelease {
    verified: Arc<VerifiedNativeRelease>,
    root: PathBuf,
    version: String,
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    node_version: Option<String>,
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    cua_version: Option<String>,
}
fn load_error(error: ReleaseError) -> ProfileError {
    match error {
        ReleaseError::Unsupported => ProfileError::Unsupported,
        ReleaseError::Unavailable => ProfileError::ProtectedRead,
        ReleaseError::Changed | ReleaseError::Unknown => ProfileError::Changed,
        _ => ProfileError::UntrustedRelease,
    }
}
impl ProfileRelease {
    /// Reuse only the exact formal release retained by the fresh Host snapshot.
    /// Full original inventory, publisher and selection identities are checked
    /// again at this boundary; a report or selected pathname cannot supply it.
    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "windows",
        target_os = "macos"
    ))]
    pub(super) fn from_retained_native(
        selection: &styx_contracts::native_management::NativeRuntimeSelection,
        expected: &PublisherFingerprint,
        verified: Arc<VerifiedNativeRelease>,
    ) -> Result<Self, ProfileError> {
        if selection.publisher_spki_sha256.to_hex() != expected.as_hex() {
            return Err(ProfileError::UntrustedRelease);
        }
        verified
            .revalidate_matches_selection(selection)
            .map_err(load_error)?;
        Self::from_verified_native(verified)
    }
    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "windows",
        target_os = "macos"
    ))]
    fn from_verified_native(verified: Arc<VerifiedNativeRelease>) -> Result<Self, ProfileError> {
        let manifest = verified.manifest();
        #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
        let node_version = manifest
            .worker_closures
            .iter()
            .find(|w| w.kind == NativeExternalWorker::BrowserNode22)
            .map(|w| w.version.clone());
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        let cua_version = manifest
            .worker_closures
            .iter()
            .find(|w| w.kind == NativeExternalWorker::CuaNative)
            .map(|w| {
                format!(
                    "cua-driver {}",
                    w.version.strip_prefix("cua-driver ").unwrap_or(&w.version)
                )
            });
        let version = manifest.version.clone();
        let root = verified.runtime_root().map_err(load_error)?;
        Ok(Self {
            verified,
            root,
            version,
            #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
            node_version,
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            cua_version,
        })
    }
    pub(super) fn revalidate(&self) -> Result<(), ProfileError> {
        self.verified.revalidate().map_err(load_error)
    }
    pub(super) fn pin_worker(
        &self,
        kind: NativeExternalWorker,
    ) -> Result<PinnedExecutable, ProfileError> {
        self.verified.pin_worker(kind).map_err(load_error)
    }
    /// Signed package membership, never a Core grant, live health or readiness.
    pub(super) fn has_worker(&self, kind: NativeExternalWorker) -> bool {
        self.verified
            .manifest()
            .worker_closures
            .iter()
            .any(|worker| worker.kind == kind)
    }
    /// Locator only. The caller still requires Browser membership and its pin,
    /// and retains/revalidates this WHOLE release through physical Host cleanup.
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    pub(super) fn browser_release_root(&self) -> PathBuf {
        self.root.join("workers/browser-node22")
    }
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    pub(super) fn browser_node_version(&self) -> Option<String> {
        self.node_version.clone()
    }
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    pub(super) fn cua_version(&self) -> Option<String> {
        self.cua_version.clone()
    }
    pub(super) fn version(&self) -> &str {
        &self.version
    }
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[path = "profile_release_tests.rs"]
mod tests;
