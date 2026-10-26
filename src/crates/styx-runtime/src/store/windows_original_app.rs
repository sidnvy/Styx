//! Source evidence for the legacy UNSIGNED Windows App and its original Node
//! bridge. Package hashes establish retained-byte consistency, not an App
//! publisher signature. The signed Host root is independently authenticated by
//! OriginalNativePairMaterials and bound by its exact raw manifest digest.
use super::*;
use crate::crypto::{PublisherFingerprint, PublisherVerifyingKey, RawReleaseManifest};
use crate::{
    foreground::profile::OriginalNativePairMaterials,
    platform::windows_legacy_observation::RetainedLegacyAppCore,
    store::{
        management::handoff::{WindowsRestartProcess, WindowsStartupCheckpoint},
        secure_journal::{JournalError, JournalResult},
    },
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use std::{collections::BTreeMap, os::windows::fs::FileExt};
use styx_contracts::identity::Sha256Digest;
fn failed<T>(_: T) -> JournalError {
    JournalError::Unknown
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Member {
    path: String,
    size: u64,
    sha256: Sha256Digest,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Package {
    schema: u16,
    kind: String,
    arch: String,
    compiled: bool,
    host_bundle: bool,
    authenticity: String,
    files: Vec<Member>,
}
#[derive(Deserialize)]
struct FixedMember {
    path: String,
    sha256: Sha256Digest,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Runtime {
    schema: u16,
    node: FixedMember,
    desktop_app: FixedMember,
    desktop_probe: FixedMember,
    artifacts: Artifacts,
    #[serde(default)]
    native_runtime: Option<serde_json::Value>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Artifacts {
    bundle: String,
    publisher_key_file: String,
    publisher_sha256: Sha256Digest,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Installed {
    schema: u16,
    kind: String,
    target: PathBuf,
    package_sha256: Sha256Digest,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManagedInstall {
    schema: u16,
    kind: String,
    root: PathBuf,
    launcher_sha256: Sha256Digest,
    current: String,
    releases: Vec<ManagedRelease>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManagedRelease {
    id: String,
    package_sha256: Sha256Digest,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetupOwner {
    schema: u16,
    kind: String,
    root: PathBuf,
    launcher_sha256: Sha256Digest,
}

struct SourceFile {
    path: PathBuf,
    file: File,
    facts: ffi::Facts,
    digest: Sha256Digest,
    parents: Vec<(File, ffi::Facts, PathBuf)>,
}
impl SourceFile {
    fn open(path: PathBuf, max: u64) -> JournalResult<Self> {
        let (_, ancestors) =
            absolute_pins(path.parent().ok_or(JournalError::Conflict)?).map_err(failed)?;
        let mut parents = Vec::new();
        for (index, parent) in ancestors.into_iter().enumerate() {
            if index != 0 {
                ffi::local_executable_acl(&parent).map_err(failed)?;
            }
            let facts = ffi::facts(&parent).map_err(failed)?;
            let actual = ffi::final_path(&parent).map_err(failed)?;
            parents.push((parent, facts, actual));
        }
        let file = ffi::open(&path, false, false, false).map_err(failed)?;
        ffi::require_no_streams(&path).map_err(failed)?;
        let facts = ffi::facts(&file).map_err(failed)?;
        if facts.directory
            || facts.links != 1
            || facts.observation.byte_len == 0
            || facts.observation.byte_len > max
            || ffi::final_path(&file).map_err(failed)? != path
        {
            return Err(JournalError::Conflict);
        }
        ffi::local_executable_acl(&file).map_err(failed)?;
        let digest = payload_backend::stream_hash(&file, max).map_err(failed)?;
        let this = Self {
            path,
            file,
            facts,
            digest,
            parents,
        };
        this.revalidate()?;
        Ok(this)
    }
    fn revalidate(&self) -> JournalResult<()> {
        if ffi::facts(&self.file).map_err(failed)? != self.facts
            || ffi::final_path(&self.file).map_err(failed)? != self.path
            || payload_backend::stream_hash(&self.file, self.facts.observation.byte_len)
                .map_err(failed)?
                != self.digest
        {
            return Err(JournalError::Conflict);
        }
        ffi::local_executable_acl(&self.file).map_err(failed)?;
        for (index, (parent, facts, path)) in self.parents.iter().enumerate() {
            if ffi::facts(parent).map_err(failed)? != *facts
                || ffi::final_path(parent).map_err(failed)? != *path
            {
                return Err(JournalError::Conflict);
            }
            if index != 0 {
                ffi::local_executable_acl(parent).map_err(failed)?;
            }
        }
        // Open the fixed name as well: the held old file alone cannot prove the
        // current installed slot still names that exact object.
        let now = ffi::open(&self.path, false, false, false).map_err(failed)?;
        if ffi::facts(&now).map_err(failed)? != self.facts {
            return Err(JournalError::Conflict);
        }
        Ok(())
    }
    fn bytes(&self, max: usize) -> JournalResult<Vec<u8>> {
        if self.facts.observation.byte_len > max as u64 {
            return Err(JournalError::Unsupported);
        }
        self.revalidate()?;
        let mut raw = vec![0u8; self.facts.observation.byte_len as usize];
        let mut offset = 0;
        while offset < raw.len() {
            let n = self
                .file
                .seek_read(&mut raw[offset..], offset as u64)
                .map_err(failed)?;
            if n == 0 {
                return Err(JournalError::Unknown);
            }
            offset += n;
        }
        if Sha256Digest::of_bytes(&raw) != self.digest {
            return Err(JournalError::Conflict);
        }
        self.revalidate()?;
        Ok(raw)
    }
}

/// Held fixed source files + original process objects. No Clone/Serialize or
/// boolean constructor. In particular this is NOT a settled-tree capability.
pub(in crate::store) struct WindowsOriginalApp {
    parents: Vec<(File, ffi::Facts, PathBuf)>,
    files: Vec<SourceFile>,
    processes: RetainedLegacyAppCore,
    checkpoint: WindowsStartupCheckpoint,
    release_manifest: Sha256Digest,
}
impl WindowsOriginalApp {
    pub(in crate::store) fn capture(
        startup: &crate::store::platform::restart::StartupLinkRead,
        state_dir: &Path,
        materials: &OriginalNativePairMaterials<'_>,
    ) -> JournalResult<Self> {
        materials.revalidate().map_err(failed)?;
        let target = normalized_root(Path::new(&startup.fields.target)).map_err(failed)?;
        let root = normalized_root(Path::new(&startup.fields.working_directory)).map_err(failed)?;
        let state_parent = state_dir.parent().ok_or(JournalError::Conflict)?;
        let expected_args = format!(
            "--startup --state-dir \"{}\"",
            state_parent.to_str().ok_or(JournalError::Conflict)?
        );
        if target != root.join("StyxPreview.exe") || startup.fields.arguments != expected_args {
            return Err(JournalError::Conflict);
        }
        let (_, held_parents) = absolute_pins(&root).map_err(failed)?;
        let mut parents = Vec::new();
        for (index, file) in held_parents.into_iter().enumerate() {
            let path = ffi::final_path(&file).map_err(failed)?;
            let facts = ffi::facts(&file).map_err(failed)?;
            if index != 0 {
                ffi::local_executable_acl(&file).map_err(failed)?;
            }
            parents.push((file, facts, path));
        }
        let manifest = SourceFile::open(root.join("windows-package.json"), 8 * 1024 * 1024)?;
        let package: Package =
            serde_json::from_slice(&manifest.bytes(8 * 1024 * 1024)?).map_err(failed)?;
        if package.schema != 1
            || package.kind != "styx-windows-unsigned-preview"
            || package.arch != "x64"
            || !package.compiled
            || !package.host_bundle
            || package.authenticity != "not_verified_unsigned_preview"
            || package.files.is_empty()
            || package.files.len() >= 20000
        {
            return Err(JournalError::Conflict);
        }
        let mut members = BTreeMap::new();
        for member in package.files {
            if member.path.contains(['\\', ':'])
                || member
                    .path
                    .split('/')
                    .any(|p| p.is_empty() || p == "." || p == "..")
                || member.size > 2 * 1024 * 1024 * 1024
                || members.insert(member.path.clone(), member).is_some()
            {
                return Err(JournalError::Conflict);
            }
        }
        let package_sha256 = manifest.digest;
        let mut files = vec![manifest];
        let runtime_file = pin_member(&root, &members, "windows-runtime.json", 1024 * 1024)?;
        let runtime: Runtime =
            serde_json::from_slice(&runtime_file.bytes(1024 * 1024)?).map_err(failed)?;
        let publisher = materials.publisher_sha256().map_err(failed)?;
        let release_manifest = materials
            .original_release_manifest_sha256()
            .map_err(failed)?;
        if runtime.schema != 1
            || runtime.native_runtime.is_some()
            || runtime.node.path != "runtime/node.exe"
            || runtime.desktop_app.path != "StyxPreview.exe"
            || runtime.desktop_probe.path != "StyxSessionProbe.exe"
            || runtime.artifacts.bundle != "host-bundle"
            || runtime.artifacts.publisher_key_file != "publisher.pem"
            || runtime.artifacts.publisher_sha256 != publisher
        {
            return Err(JournalError::Conflict);
        }
        files.push(runtime_file);
        let fixed = [
            ("StyxPreview.exe", 64 * 1024 * 1024),
            ("runtime/node.exe", 256 * 1024 * 1024),
            ("StyxSessionProbe.exe", 64 * 1024 * 1024),
            ("vnext/host/windows/core-bridge.mjs", 8 * 1024 * 1024),
            (
                "vnext/host/windows/native-app-authority.mjs",
                8 * 1024 * 1024,
            ),
            ("vnext/onboarding/core.mjs", 8 * 1024 * 1024),
            ("host-bundle/manifest.json", 8 * 1024 * 1024),
            ("host-bundle/manifest.sig", 256),
            ("publisher.pem", 32768),
        ];
        let mut observed = BTreeMap::new();
        for (name, max) in fixed {
            let pin = pin_member(&root, &members, name, max)?;
            observed.insert(name, pin.digest);
            files.push(pin);
        }
        if observed["StyxPreview.exe"] != runtime.desktop_app.sha256
            || observed["runtime/node.exe"] != runtime.node.sha256
            || observed["StyxSessionProbe.exe"] != runtime.desktop_probe.sha256
            || observed["host-bundle/manifest.json"] != release_manifest
        {
            return Err(JournalError::Conflict);
        }
        // Authenticate the package's public key and exact original Host
        // manifest too. A self-reported artifacts.publisherSha256 is not proof
        // that the fixed publisher.pem / manifest.sig actually contain them.
        // Complete signed worker membership remains the original materials
        // reader's retained authority, not this unsigned outer package parser.
        let public = files
            .iter()
            .find(|p| p.path == root.join("publisher.pem"))
            .ok_or(JournalError::Conflict)?
            .bytes(32768)?;
        let manifest_raw = files
            .iter()
            .find(|p| p.path == root.join("host-bundle/manifest.json"))
            .ok_or(JournalError::Conflict)?
            .bytes(8 * 1024 * 1024)?;
        let signature_raw = files
            .iter()
            .find(|p| p.path == root.join("host-bundle/manifest.sig"))
            .ok_or(JournalError::Conflict)?
            .bytes(256)?;
        let signature = std::str::from_utf8(&signature_raw).map_err(failed)?.trim();
        if signature.len() != 86
            || !signature
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        {
            return Err(JournalError::Conflict);
        }
        let signature = URL_SAFE_NO_PAD.decode(signature).map_err(failed)?;
        let key = PublisherVerifyingKey::from_spki_pem(&public).map_err(failed)?;
        let expected = PublisherFingerprint::parse(&publisher.to_hex()).map_err(failed)?;
        key.verify_manifest(
            &expected,
            RawReleaseManifest::from_original_bytes(&manifest_raw),
            &signature,
        )
        .map_err(failed)?;
        // If this is an installed-preview copy, validate its original receipt.
        // Direct original packages remain anchored by the actual Startup link.
        let receipt = root.join(".styx-preview-install.json");
        match SourceFile::open(receipt.clone(), 32768) {
            Ok(pin) => {
                let installed: Installed =
                    serde_json::from_slice(&pin.bytes(32768)?).map_err(failed)?;
                if installed.schema != 1
                    || installed.kind != "styx-owned-fresh-preview-install"
                    || installed.target != root
                    || installed.package_sha256 != package_sha256
                {
                    return Err(JournalError::Conflict);
                }
                files.push(pin);
            }
            Err(error) => match ffi::open(&receipt, false, false, false) {
                Err(StoreError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => (),
                _ => return Err(error),
            },
        }
        // Side-by-side installs have a real selected-release descriptor. Pin
        // that selector and launcher too; never infer current from a UUID path.
        if root.parent().and_then(Path::file_name) == Some(OsStr::new("releases")) {
            let install_root = root
                .parent()
                .and_then(Path::parent)
                .ok_or(JournalError::Conflict)?;
            let descriptor_pin =
                SourceFile::open(install_root.join("installation.json"), 1024 * 1024)?;
            let descriptor: ManagedInstall =
                serde_json::from_slice(&descriptor_pin.bytes(1024 * 1024)?).map_err(failed)?;
            let selected = root
                .file_name()
                .and_then(OsStr::to_str)
                .ok_or(JournalError::Conflict)?;
            if descriptor.schema != 1
                || descriptor.kind != "styx-windows-user-install"
                || descriptor.root != install_root
                || descriptor.current != selected
                || uuid::Uuid::parse_str(selected).is_err()
                || descriptor.releases.len() > 4096
            {
                return Err(JournalError::Conflict);
            }
            let mut ids = std::collections::BTreeSet::new();
            let mut selected_hash = None;
            for release in &descriptor.releases {
                if uuid::Uuid::parse_str(&release.id).is_err() || !ids.insert(&release.id) {
                    return Err(JournalError::Conflict);
                }
                if release.id == selected {
                    selected_hash = Some(release.package_sha256);
                }
            }
            if selected_hash != Some(package_sha256) {
                return Err(JournalError::Conflict);
            }
            let launcher = SourceFile::open(install_root.join("Styx.exe"), 64 * 1024 * 1024)?;
            let setup_pin = SourceFile::open(install_root.join(".setup-owner.json"), 32768)?;
            let setup: SetupOwner =
                serde_json::from_slice(&setup_pin.bytes(32768)?).map_err(failed)?;
            if setup.schema != 1
                || setup.kind != descriptor.kind
                || setup.root != install_root
                || setup.launcher_sha256 != descriptor.launcher_sha256
                || launcher.digest != descriptor.launcher_sha256
            {
                return Err(JournalError::Conflict);
            }
            files.extend([descriptor_pin, launcher, setup_pin]);
        }
        let processes = RetainedLegacyAppCore::capture(
            &target,
            &root.join("runtime/node.exe"),
            &ffi::current_sid().map_err(failed)?,
        )
        .map_err(failed)?;
        let (app_pid, app_birth) = processes.app();
        let (core_pid, core_birth) = processes.core();
        let checkpoint = WindowsStartupCheckpoint {
            original_link: startup.original.clone(),
            startup_directory: startup
                .directory
                .to_str()
                .ok_or(JournalError::Conflict)?
                .into(),
            target: startup.fields.target.clone(),
            arguments: startup.fields.arguments.clone(),
            working_directory: startup.fields.working_directory.clone(),
            desired_enabled: true,
            app: WindowsRestartProcess {
                pid: app_pid,
                birth_filetime: app_birth,
            },
            core: WindowsRestartProcess {
                pid: core_pid,
                birth_filetime: core_birth,
            },
            original_package_sha256: package_sha256,
            original_app_sha256: observed["StyxPreview.exe"],
            original_publisher_spki_sha256: publisher,
        };
        let this = Self {
            parents,
            files,
            processes,
            checkpoint,
            release_manifest,
        };
        this.revalidate(materials)?;
        Ok(this)
    }
    pub(in crate::store) fn revalidate(
        &self,
        materials: &OriginalNativePairMaterials<'_>,
    ) -> JournalResult<()> {
        materials.revalidate().map_err(failed)?;
        if materials.publisher_sha256().map_err(failed)?
            != self.checkpoint.original_publisher_spki_sha256
            || materials
                .original_release_manifest_sha256()
                .map_err(failed)?
                != self.release_manifest
        {
            return Err(JournalError::Conflict);
        }
        for (index, (file, facts, path)) in self.parents.iter().enumerate() {
            if ffi::facts(file).map_err(failed)? != *facts
                || ffi::final_path(file).map_err(failed)? != *path
            {
                return Err(JournalError::Conflict);
            }
            if index != 0 {
                ffi::local_executable_acl(file).map_err(failed)?;
            }
        }
        for file in &self.files {
            file.revalidate()?;
        }
        self.processes.revalidate().map_err(failed)?;
        materials.revalidate().map_err(failed)
    }
    pub(in crate::store) fn checkpoint(&self) -> &WindowsStartupCheckpoint {
        &self.checkpoint
    }
}
fn pin_member(
    root: &Path,
    members: &BTreeMap<String, Member>,
    name: &str,
    max: u64,
) -> JournalResult<SourceFile> {
    let declared = members.get(name).ok_or(JournalError::Conflict)?;
    // SourceFile retains every intermediate directory without delete sharing.
    let pin = SourceFile::open(root.join(name.replace('/', "\\")), max)?;
    if pin.facts.observation.byte_len != declared.size || pin.digest != declared.sha256 {
        return Err(JournalError::Conflict);
    }
    Ok(pin)
}
