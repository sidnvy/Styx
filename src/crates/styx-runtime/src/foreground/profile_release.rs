//! One retained, read-only release authority for the foreground profile.
//! A native DTO or pathname cannot substitute for the verified package object.
use super::{Active, Capture, Manifest, ProfileError, decode, relative, version};
use crate::{
    crypto::{PublisherFingerprint, PublisherVerifyingKey, RawReleaseManifest},
    release::{ReleaseError, VerifiedNativeRelease},
    store::{PayloadInventory, PayloadLimits, PinnedExecutable, PrivateRoot},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::Arc,
};
use styx_contracts::{
    identity::Sha256Digest,
    native_release::{NativeExternalWorker, NativeReleaseScope},
};

const MANIFEST_LIMIT: usize = 1024 * 1024;
#[derive(Deserialize)]
struct Header {
    schema: u32,
}
enum RetainedRelease {
    Legacy {
        inventory: PayloadInventory,
    },
    Native {
        verified: Arc<VerifiedNativeRelease>,
    },
}
pub(super) struct ProfileRelease {
    retained: RetainedRelease,
    root: PathBuf,
    version: String,
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    node_version: Option<String>,
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    cua_version: Option<String>,
}
fn fixed_legacy_worker(kind: NativeExternalWorker) -> &'static str {
    match (kind, cfg!(target_os = "windows")) {
        (NativeExternalWorker::CodexExec, true) => "bin/codex.exe",
        (NativeExternalWorker::BrowserNode22, true) => "bin/node.exe",
        (NativeExternalWorker::CuaNative, true) => "bin/cua-driver.exe",
        (NativeExternalWorker::CodexExec, false) => "bin/codex",
        (NativeExternalWorker::BrowserNode22, false) => "bin/node",
        (NativeExternalWorker::CuaNative, false) => "bin/cua-driver",
    }
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
            retained: RetainedRelease::Native { verified },
            root,
            version,
            #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
            node_version,
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            cua_version,
        })
    }
    pub(super) fn revalidate(&self) -> Result<(), ProfileError> {
        match &self.retained {
            RetainedRelease::Legacy { inventory } => {
                inventory.revalidate().map_err(|_| ProfileError::Changed)
            }
            RetainedRelease::Native { verified } => {
                verified.revalidate().map_err(|_| ProfileError::Changed)
            }
        }
    }
    pub(super) fn pin_worker(
        &self,
        kind: NativeExternalWorker,
    ) -> Result<PinnedExecutable, ProfileError> {
        match &self.retained {
            RetainedRelease::Legacy { inventory } => inventory
                .pin_executable(fixed_legacy_worker(kind))
                .map_err(|_| ProfileError::UntrustedRelease),
            // This original retained inventory is the only native pin factory.
            RetainedRelease::Native { verified } => verified.pin_worker(kind).map_err(load_error),
        }
    }
    /// Signed package membership, never a Core grant, live health or readiness.
    pub(super) fn has_worker(&self, kind: NativeExternalWorker) -> bool {
        match &self.retained {
            RetainedRelease::Legacy { inventory } => inventory.members().iter().any(|member| {
                member.path == Path::new(fixed_legacy_worker(kind))
                    && member.executable
                    && member.bytes > 0
            }),
            RetainedRelease::Native { verified } => verified
                .manifest()
                .worker_closures
                .iter()
                .any(|worker| worker.kind == kind),
        }
    }
    /// Locator only. The caller still requires Browser membership and its pin,
    /// and retains/revalidates this WHOLE release through physical Host cleanup.
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    pub(super) fn browser_release_root(&self) -> PathBuf {
        match &self.retained {
            RetainedRelease::Legacy { .. } => self.root.clone(),
            RetainedRelease::Native { .. } => self.root.join("workers/browser-node22"),
        }
    }
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    pub(super) fn browser_node_version(&self) -> Option<String> {
        self.node_version.clone()
    }
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    pub(super) fn cua_version(&self) -> Option<String> {
        self.cua_version.clone()
    }
    pub(super) fn runtime_format(&self) -> &'static str {
        match &self.retained {
            RetainedRelease::Legacy { .. } => "legacy_js_v1",
            RetainedRelease::Native { .. } => "native_rust_v1",
        }
    }
    pub(super) fn version(&self) -> &str {
        &self.version
    }
}

pub(super) fn load(
    capture: &mut Capture,
    release: &Path,
    active: &Active,
    publisher_base: &Path,
    publisher: &PublisherVerifyingKey,
    expected: &PublisherFingerprint,
) -> Result<ProfileRelease, ProfileError> {
    let active_version = active.version.as_str();
    let active_manifest = active.manifest_sha256;
    if !version(active_version) {
        return Err(ProfileError::Invalid);
    }
    let manifest_raw = capture.read(release, "manifest.json", MANIFEST_LIMIT)?;
    let signature_raw = capture.read(release, "manifest.sig", 256)?;
    if Sha256Digest::of_bytes(&manifest_raw) != active_manifest {
        return Err(ProfileError::UntrustedRelease);
    }
    // Only a structural version header chooses a codec. Neither signature
    // decoding nor another reader is retried after failure in the selected one.
    let header: Header = decode(&manifest_raw).map_err(|_| ProfileError::UntrustedRelease)?;
    match header.schema {
        1 => load_legacy(
            release,
            active_version,
            &manifest_raw,
            &signature_raw,
            publisher,
            expected,
        ),
        2 => {
            if signature_raw.len() != 64 {
                return Err(ProfileError::UntrustedRelease);
            }
            let verified =
                crate::release::verify(release, &publisher_base.join("publisher.pem"), expected)
                    .map_err(load_error)?;
            let manifest = verified.manifest();
            if manifest.scope != NativeReleaseScope::RuntimeCandidate
                || manifest.version != active_version
                || verified.report().manifest_sha256 != active_manifest
            {
                return Err(ProfileError::UntrustedRelease);
            }
            #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
            let node_version = manifest
                .worker_closures
                .iter()
                .find(|worker| worker.kind == NativeExternalWorker::BrowserNode22)
                .map(|worker| worker.version.clone());
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            let cua_version = manifest
                .worker_closures
                .iter()
                .find(|worker| worker.kind == NativeExternalWorker::CuaNative)
                .map(|worker| {
                    format!(
                        "cua-driver {}",
                        worker
                            .version
                            .strip_prefix("cua-driver ")
                            .unwrap_or(&worker.version)
                    )
                });
            let signed_version = manifest.version.clone();
            Ok(ProfileRelease {
                retained: RetainedRelease::Native {
                    verified: Arc::new(verified),
                },
                root: release.to_path_buf(),
                version: signed_version,
                #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
                node_version,
                #[cfg(any(target_os = "linux", target_os = "windows"))]
                cua_version,
            })
        }
        _ => Err(ProfileError::Unsupported),
    }
}
fn load_legacy(
    release: &Path,
    active_version: &str,
    manifest_raw: &[u8],
    signature_raw: &[u8],
    publisher: &PublisherVerifyingKey,
    expected: &PublisherFingerprint,
) -> Result<ProfileRelease, ProfileError> {
    let signature = std::str::from_utf8(signature_raw)
        .map_err(|_| ProfileError::UntrustedRelease)?
        .trim();
    if signature.len() != 86
        || !signature
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
    {
        return Err(ProfileError::UntrustedRelease);
    }
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| ProfileError::UntrustedRelease)?;
    publisher
        .verify_manifest(
            expected,
            RawReleaseManifest::from_original_bytes(manifest_raw),
            &signature,
        )
        .map_err(|_| ProfileError::UntrustedRelease)?;
    let manifest: Manifest = decode(manifest_raw)?;
    let platform = match std::env::consts::OS {
        "linux" => "linux",
        "macos" => "darwin",
        "windows" => "win32",
        _ => return Err(ProfileError::Unsupported),
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        _ => return Err(ProfileError::Unsupported),
    };
    if manifest.schema != 1
        || manifest.version != active_version
        || manifest.platform != platform
        || manifest.arch != arch
        || manifest.files.is_empty()
        || manifest.files.len() > 4096
    {
        return Err(ProfileError::UntrustedRelease);
    }
    if manifest
        .runtime_format
        .as_ref()
        .is_some_and(|format| format != "legacy_js_v1")
    {
        return Err(ProfileError::Unsupported);
    }
    // Known Manifest fields retain their original serde validation. Optional
    // upstream/extra metadata stays compatible on both platforms: a non-string
    // value supplies no version and does not become an executable authority.
    #[cfg(target_os = "linux")]
    let (node_version, cua_version) = {
        let upstream = manifest.upstream.as_ref();
        (
            upstream
                .and_then(|value| value.get("node"))
                .and_then(|value| value.as_str())
                .map(str::to_owned),
            upstream
                .and_then(|value| value.get("cua"))
                .and_then(|value| value.as_str())
                .map(str::to_owned),
        )
    };
    #[cfg(target_os = "windows")]
    let cua_version = {
        let metadata: serde_json::Value = decode(manifest_raw)?;
        metadata
            .get("upstream")
            .and_then(|v| v.get("cua"))
            .and_then(|v| v.as_str())
            .map(str::to_owned)
    };
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    let node_version = {
        let metadata: serde_json::Value = decode(manifest_raw)?;
        metadata
            .get("upstream")
            .and_then(|value| value.get("node"))
            .and_then(|value| value.as_str())
            .map(str::to_owned)
    };
    let private_release = PrivateRoot::open(release).map_err(|_| ProfileError::ProtectedRead)?;
    let inventory = private_release
        .payload_inventory(PayloadLimits::default())
        .map_err(|_| ProfileError::UntrustedRelease)?;
    let mut expected_members = BTreeMap::new();
    for member in manifest.files {
        if !relative(&member.path)
            || member.path == "manifest.json"
            || member.path == "manifest.sig"
            || expected_members
                .insert(
                    PathBuf::from(&member.path),
                    (member.size, member.sha256, member.executable),
                )
                .is_some()
        {
            return Err(ProfileError::UntrustedRelease);
        }
    }
    expected_members.insert(
        PathBuf::from("manifest.json"),
        (
            manifest_raw.len() as u64,
            Sha256Digest::of_bytes(manifest_raw),
            false,
        ),
    );
    expected_members.insert(
        PathBuf::from("manifest.sig"),
        (
            signature_raw.len() as u64,
            Sha256Digest::of_bytes(signature_raw),
            false,
        ),
    );
    let mut actual = BTreeSet::new();
    for member in inventory.members() {
        let Some((size, digest, executable)) = expected_members.get(&member.path) else {
            return Err(ProfileError::UntrustedRelease);
        };
        if member.bytes != *size || member.sha256 != *digest || member.executable != *executable {
            return Err(ProfileError::UntrustedRelease);
        }
        actual.insert(member.path.clone());
    }
    if actual.len() != expected_members.len() {
        return Err(ProfileError::UntrustedRelease);
    }
    Ok(ProfileRelease {
        retained: RetainedRelease::Legacy { inventory },
        root: release.to_path_buf(),
        version: manifest.version,
        #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
        node_version,
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        cua_version,
    })
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[path = "profile_release_tests.rs"]
mod tests;
