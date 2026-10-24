//! Explicit transition-profile Browser bootstrap. No pairing, publisher, login
//! state or installed release is rewritten. The original verified release is
//! kept alive together with this Rust image's fixed worker until Host cleanup.
//! All methods perform synchronous protected I/O: call only on bounded blocking
//! workers. This directory binding is not an owner/admission/operation ledger.
use super::profile::LoadedLegacyProfile;
use crate::{
    host::protocol::browser::BrowserBootstrap,
    providers::browser::{
        OwnedBrowserConfig,
        assets::{self, PreparedBrowserAssets, PrivateDirectory},
    },
    store::{PinnedExecutable, PrivateRoot},
};
use serde::Deserialize;
use std::{
    fs::{File, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use styx_contracts::{error::ErrorCategory, identity::Sha256Digest};
use styx_core::operations::OwnerLease;

const MAX_OWNERS: usize = 16;
const MAX_BROWSER_BYTES: u64 = 512 * 1024 * 1024;
type Result<T> = std::result::Result<T, ErrorCategory>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    enabled: bool,
    headless: Option<bool>,
    #[serde(rename = "persistLogin")]
    persist_login: Option<bool>,
    #[serde(rename = "executablePath")]
    executable: Option<PathBuf>,
    channel: Option<String>,
    #[serde(rename = "profileRoot")]
    profile_root: Option<PathBuf>,
}
struct OwnerProfile {
    owner: OwnerLease,
    profile: PrivateDirectory,
    output: PrivateDirectory,
    config: OwnedBrowserConfig,
}
struct LocalBrowser {
    profile: Arc<LoadedLegacyProfile>,
    node: PinnedExecutable,
    node_path: PathBuf,
    browser: LocalExecutable,
    runtime: PrivateDirectory,
    assets: PreparedBrowserAssets,
    workspace: PathBuf,
    owners: Mutex<Vec<OwnerProfile>>,
}

/// Executable explicitly selected by protected local configuration. This pin
/// establishes exact local bytes/identity, NOT a publisher signature for Chrome.
/// The caller's ordinary same-UID administrative trust boundary is unchanged.
struct LocalExecutable {
    path: PathBuf,
    file: File,
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
    bytes: u64,
    digest: Sha256Digest,
}
impl LocalExecutable {
    fn open(path: &Path) -> Result<Self> {
        canonical(path)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| ErrorCategory::PermissionDenied)?;
        let m = file
            .metadata()
            .map_err(|_| ErrorCategory::IntegrityFailure)?;
        let uid = nix::unistd::Uid::current().as_raw();
        if !m.is_file()
            || m.nlink() != 1
            || ![0, uid].contains(&m.uid())
            || m.mode() & 0o022 != 0
            || m.mode() & 0o111 == 0
            || m.len() == 0
            || m.len() > MAX_BROWSER_BYTES
        {
            return Err(ErrorCategory::PermissionDenied);
        }
        let mut pinned = Self {
            path: path.into(),
            digest: Sha256Digest::of_bytes(&[]),
            device: m.dev(),
            inode: m.ino(),
            uid: m.uid(),
            mode: m.mode(),
            bytes: m.len(),
            file,
        };
        pinned.digest = hash_file(&pinned.file, pinned.bytes)?;
        pinned.revalidate()?;
        Ok(pinned)
    }
    fn revalidate(&self) -> Result<()> {
        canonical(&self.path)?;
        let current = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.path)
            .map_err(|_| ErrorCategory::IntegrityFailure)?;
        for f in [&current, &self.file] {
            let m = f.metadata().map_err(|_| ErrorCategory::IntegrityFailure)?;
            if !m.is_file()
                || m.nlink() != 1
                || (m.dev(), m.ino(), m.uid(), m.mode(), m.len())
                    != (self.device, self.inode, self.uid, self.mode, self.bytes)
                || hash_file(f, self.bytes)? != self.digest
            {
                return Err(ErrorCategory::IntegrityFailure);
            }
        }
        Ok(())
    }
}
fn hash_file(file: &File, expected: u64) -> Result<Sha256Digest> {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::FileExt;
    let mut hasher = Sha256::new();
    let mut offset = 0;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let n = file
            .read_at(&mut buffer, offset)
            .map_err(|_| ErrorCategory::IntegrityFailure)?;
        if n == 0 {
            break;
        }
        offset += n as u64;
        if offset > expected {
            return Err(ErrorCategory::IntegrityFailure);
        }
        hasher.update(&buffer[..n]);
    }
    if offset != expected {
        return Err(ErrorCategory::IntegrityFailure);
    }
    Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
}
fn canonical(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path.as_os_str().len() > 4096
        || std::fs::canonicalize(path).map_err(|_| ErrorCategory::PermissionDenied)? != path
    {
        return Err(ErrorCategory::PermissionDenied);
    }
    Ok(())
}
fn selected(profile: &LoadedLegacyProfile) -> Result<Option<PathBuf>> {
    let source = profile.browser_source();
    let (deployment, host) = (source.deployment, source.host);
    // Missing or explicit disabled selection does not enable a Browser lane.
    if deployment
        .and_then(|v| v.get("enabled"))
        .and_then(|v| v.as_bool())
        != Some(true)
    {
        return Ok(None);
    }
    let d: Selection = serde_json::from_value(deployment.unwrap().clone())
        .map_err(|_| ErrorCategory::CapabilityUnsupported)?;
    let h: Selection =
        serde_json::from_value(host.ok_or(ErrorCategory::CapabilityUnsupported)?.clone())
            .map_err(|_| ErrorCategory::CapabilityUnsupported)?;
    if !h.enabled
        || d.headless != Some(true)
        || h.headless != Some(true)
        || d.persist_login != Some(false)
        || h.persist_login != Some(false)
        || d.profile_root.is_some()
        || h.profile_root.as_deref() != Some(profile.host_base_dir().join("browser").as_path())
        || d.channel != h.channel
        || d.executable != h.executable
        || d.channel
            .as_deref()
            .is_some_and(|v| !["auto", "chrome", "msedge"].contains(&v))
    {
        return Err(ErrorCategory::CapabilityUnsupported);
    }
    // No implicit system browser selection/channel inference in this slice.
    Ok(Some(
        d.executable.ok_or(ErrorCategory::CapabilityUnsupported)?,
    ))
}

/// Only a bootstrap already holding the original private profile and verified
/// publisher inventory may call this. No fixture path or network input can mint
/// this object. No browser is executed by preparation or validation.
pub(crate) fn prepare_browser_bootstrap(
    profile: Arc<LoadedLegacyProfile>,
) -> Result<Option<Arc<dyn BrowserBootstrap>>> {
    let Some(browser_path) = selected(&profile)? else {
        return Ok(None);
    };
    profile
        .revalidate()
        .map_err(|_| ErrorCategory::IntegrityFailure)?;
    let source = profile.browser_source();
    let (release, workspace) = (source.release, source.workspace);
    if !source.node_version.is_some_and(|v| v.starts_with("22.")) {
        return Err(ErrorCategory::CapabilityUnsupported);
    }
    check_dependency_versions(release)?;
    canonical(workspace)?;
    // MCP roots must not encompass the private stage, other owners or original
    // credential/release trees. An unsupported workspace disables Browser only.
    if profile.host_base_dir().starts_with(workspace)
        || workspace.starts_with(profile.host_base_dir())
    {
        return Err(ErrorCategory::PermissionDenied);
    }
    let node = profile
        .pin_browser_node()
        .map_err(|_| ErrorCategory::IntegrityFailure)?;
    let node_path = release.join("bin/node");
    canonical(&node_path)?;
    let browser = LocalExecutable::open(&browser_path)?;
    let runtime = assets::fresh_private_directory(profile.host_base_dir()).map_err(map_error)?;
    let staged = assets::prepare(
        runtime.path(),
        &release.join("packages/styx-browser-provider/node_modules"),
    )
    .map_err(map_error)?;
    let factory = LocalBrowser {
        workspace: workspace.into(),
        node_path,
        node,
        browser,
        runtime,
        assets: staged,
        profile,
        owners: Mutex::new(Vec::new()),
    };
    factory.validate_before_spawn()?;
    Ok(Some(Arc::new(factory)))
}
impl LocalBrowser {
    fn validate_inputs(&self, full_release: bool) -> Result<()> {
        if full_release {
            self.profile.revalidate()
        } else {
            self.profile.revalidate_control()
        }
        .map_err(|_| ErrorCategory::IntegrityFailure)?;
        self.node
            .revalidate()
            .map_err(|_| ErrorCategory::IntegrityFailure)?;
        self.browser.revalidate()?;
        self.runtime.revalidate().map_err(map_error)?;
        self.assets.revalidate().map_err(map_error)?;
        canonical(&self.workspace)?;
        let owners = self
            .owners
            .lock()
            .map_err(|_| ErrorCategory::ResultUnknown)?;
        for p in owners.iter() {
            p.profile.revalidate().map_err(map_error)?;
            p.output.revalidate().map_err(map_error)?;
        }
        Ok(())
    }
}
impl BrowserBootstrap for LocalBrowser {
    fn prepare_profile(&self, owner: &OwnerLease) -> Result<OwnedBrowserConfig> {
        self.validate_inputs(true)?;
        let mut owners = self
            .owners
            .lock()
            .map_err(|_| ErrorCategory::ResultUnknown)?;
        if let Some(p) = owners.iter().find(|p| &p.owner == owner) {
            return Ok(p.config.clone());
        }
        // An OwnerId reused with a different epoch/incarnation never adopts an
        // old profile. Core remains the sole authority deciding valid owners.
        if owners
            .iter()
            .any(|p| p.owner.owner_id() == owner.owner_id())
        {
            return Err(ErrorCategory::Unauthorized);
        }
        if owners.len() >= MAX_OWNERS {
            return Err(ErrorCategory::Busy);
        }
        let private = assets::fresh_private_directory(self.runtime.path()).map_err(map_error)?;
        let output = assets::fresh_private_directory(self.runtime.path()).map_err(map_error)?;
        let config = OwnedBrowserConfig {
            node_binary: self.node_path.clone(),
            worker_entry: self.assets.entry_path().into(),
            browser_binary: self.browser.path.clone(),
            workspace_dir: self.workspace.clone(),
            profile_dir: private.path().into(),
            output_dir: output.path().into(),
            rpc_timeout: Duration::from_millis(u64::from(
                crate::host::protocol::wire::BROWSER_WAIT_PREPARE_TIMEOUT_MS,
            )),
        };
        private.revalidate().map_err(map_error)?;
        output.revalidate().map_err(map_error)?;
        owners.push(OwnerProfile {
            owner: owner.clone(),
            profile: private,
            output,
            config: config.clone(),
        });
        Ok(config)
    }
    fn validate_before_spawn(&self) -> Result<()> {
        self.validate_inputs(true)
    }
    fn validate_control(&self) -> Result<()> {
        self.validate_inputs(false)
    }
}
fn map_error(error: crate::providers::browser::BrowserError) -> ErrorCategory {
    use crate::providers::browser::BrowserError;
    match error {
        BrowserError::Busy => ErrorCategory::Busy,
        BrowserError::Unsupported => ErrorCategory::CapabilityUnsupported,
        BrowserError::InvalidRequest => ErrorCategory::InvalidRequest,
        BrowserError::PermissionDenied => ErrorCategory::PermissionDenied,
        _ => ErrorCategory::IntegrityFailure,
    }
}

/// These exact upstream APIs are the previously verified signed worker closure;
/// an arbitrary signed but incompatible package is not silently substituted.
fn check_dependency_versions(release: &Path) -> Result<()> {
    let root = PrivateRoot::open(release).map_err(|_| ErrorCategory::IntegrityFailure)?;
    for (name, version) in [
        ("@playwright/mcp", "0.0.83"),
        ("playwright", "1.64.0-alpha-1790635538000"),
        ("playwright-core", "1.64.0-alpha-1790635538000"),
        ("@modelcontextprotocol/sdk", "1.32.1"),
    ] {
        let path = format!("packages/styx-browser-provider/node_modules/{name}/package.json");
        let raw = root
            .read_raw(path, 64 * 1024)
            .map_err(|_| ErrorCategory::IntegrityFailure)?;
        let json: serde_json::Value = serde_json::from_slice(raw.bytes())
            .map_err(|_| ErrorCategory::CapabilityUnsupported)?;
        if json.get("version").and_then(|v| v.as_str()) != Some(version) {
            return Err(ErrorCategory::CapabilityUnsupported);
        }
    }
    Ok(())
}
