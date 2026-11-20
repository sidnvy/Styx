//! Explicit transition-profile Browser bootstrap. No pairing, publisher, login
//! state or installed release is rewritten. The original verified release is
//! kept alive together with this Rust image's fixed worker until Host cleanup.
//! All methods perform synchronous protected I/O: call only on bounded blocking
//! workers. This directory binding is not an owner/admission/operation ledger.
use super::profile::LoadedProfile;
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
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use styx_contracts::error::ErrorCategory;
use styx_core::operations::OwnerLease;
#[cfg(target_os = "windows")]
#[path = "browser_windows.rs"]
mod windows;

type Result<T> = std::result::Result<T, ErrorCategory>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    enabled: bool,
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
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    workspace: PrivateDirectory,
    config: OwnedBrowserConfig,
}
struct LocalBrowser {
    profile: Arc<LoadedProfile>,
    node: Arc<PinnedExecutable>,
    node_path: PathBuf,
    browser: PathBuf,
    runtime: PrivateDirectory,
    profiles: PrivateDirectory,
    assets: PreparedBrowserAssets,
    #[cfg(target_os = "linux")]
    workspace: PathBuf,
    owners: Mutex<Vec<OwnerProfile>>,
}

fn canonical(path: &Path) -> Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        if !path.is_absolute()
            || path.as_os_str().len() > 4096
            || std::fs::canonicalize(path).map_err(|_| ErrorCategory::PermissionDenied)? != path
        {
            return Err(ErrorCategory::PermissionDenied);
        }
    }
    #[cfg(target_os = "windows")]
    assets::canonical_path(path).map_err(map_error)?;
    Ok(())
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn resolve_browser(path: &Path) -> Result<PathBuf> {
    std::fs::canonicalize(path).map_err(|_| ErrorCategory::PermissionDenied)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn first_browser(paths: &[&str]) -> Result<PathBuf> {
    paths
        .iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .ok_or(ErrorCategory::CapabilityUnsupported)
}

fn selected(profile: &LoadedProfile) -> Result<Option<PathBuf>> {
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
    #[cfg(target_os = "linux")]
    {
        let path = match d.executable {
            Some(path) => path,
            None => {
                let paths: &[&str] = match d.channel.as_deref().unwrap_or("auto") {
                    "chrome" => &["/opt/google/chrome/chrome"],
                    "msedge" => &["/opt/microsoft/msedge/msedge"],
                    "auto" => &[
                        "/opt/google/chrome/chrome",
                        "/opt/microsoft/msedge/msedge",
                        "/usr/lib/chromium/chromium",
                    ],
                    _ => return Err(ErrorCategory::CapabilityUnsupported),
                };
                first_browser(paths)?
            }
        };
        Ok(Some(resolve_browser(&path)?))
    }
    #[cfg(target_os = "windows")]
    {
        Ok(Some(match d.executable {
            Some(path) => path,
            None => windows::selected_channel(d.channel.as_deref().unwrap_or("auto"))?,
        }))
    }
    #[cfg(target_os = "macos")]
    {
        let path = match d.executable {
            Some(path) => path,
            None => {
                let paths: &[&str] = match d.channel.as_deref().unwrap_or("auto") {
                    "chrome" => &["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"],
                    "msedge" => &["/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"],
                    "auto" => &[
                        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
                    ],
                    _ => return Err(ErrorCategory::CapabilityUnsupported),
                };
                first_browser(paths)?
            }
        };
        Ok(Some(resolve_browser(&path)?))
    }
}

/// Fixed local bootstrap stage and existing typed category only. No native
/// error text, protected path, configuration or credentials enter diagnostics.
pub(crate) struct BrowserPreparationError {
    pub(crate) stage: &'static str,
    pub(crate) category: ErrorCategory,
}
impl BrowserPreparationError {
    pub(crate) fn new(stage: &'static str, category: ErrorCategory) -> Self {
        Self { stage, category }
    }
}

/// Only a bootstrap already holding the original private profile and verified
/// publisher inventory may call this. No fixture path or network input can mint
/// this object. No browser is executed by preparation or validation.
pub(crate) fn prepare_browser_bootstrap(
    profile: Arc<LoadedProfile>,
) -> std::result::Result<Option<Arc<dyn BrowserBootstrap>>, BrowserPreparationError> {
    let at = BrowserPreparationError::new;
    let Some(browser_path) = selected(&profile).map_err(|e| at("selection", e))? else {
        return Ok(None);
    };
    profile
        .revalidate()
        .map_err(|_| at("profile", ErrorCategory::IntegrityFailure))?;
    let source = profile.browser_source();
    let release = source.release;
    #[cfg(target_os = "linux")]
    let workspace = source.workspace;
    if !source.node_version.is_some_and(|v| v.starts_with("22.")) {
        return Err(at("node_version", ErrorCategory::CapabilityUnsupported));
    }
    check_dependency_versions(release).map_err(|e| at("dependency_versions", e))?;
    #[cfg(target_os = "linux")]
    canonical(workspace).map_err(|e| at("workspace", e))?;
    // MCP roots must not encompass the private stage, other owners or original
    // credential/release trees. An unsupported workspace disables Browser only.
    #[cfg(target_os = "linux")]
    if profile.host_base_dir().starts_with(workspace)
        || workspace.starts_with(profile.host_base_dir())
    {
        return Err(at("workspace", ErrorCategory::PermissionDenied));
    }
    let node = Arc::new(
        profile
            .pin_browser_node()
            .map_err(|_| at("node_pin", ErrorCategory::IntegrityFailure))?,
    );
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let node_path = release.join("bin/node");
    #[cfg(target_os = "windows")]
    let node_path = release.join("bin/node.exe");
    canonical(&node_path).map_err(|e| at("node_path", e))?;
    let browser = browser_path;
    let browser_root = assets::open_or_create_private_directory(profile.host_base_dir(), "browser")
        .map_err(|e| at("private_profiles", map_error(e)))?;
    let profiles = assets::open_or_create_private_directory(browser_root.path(), "profiles")
        .map_err(|e| at("private_profiles", map_error(e)))?;
    let runtime = assets::fresh_private_directory(profile.host_base_dir())
        .map_err(|e| at("private_runtime", map_error(e)))?;
    let staged = assets::prepare(
        runtime.path(),
        &release.join("packages/styx-browser-provider/node_modules"),
    )
    .map_err(|e| at("worker_assets", map_error(e)))?;
    let factory = LocalBrowser {
        #[cfg(target_os = "linux")]
        workspace: workspace.into(),
        node_path,
        node,
        browser,
        runtime,
        profiles,
        assets: staged,
        profile,
        owners: Mutex::new(Vec::new()),
    };
    factory
        .validate_before_spawn()
        .map_err(|e| at("prepared_inputs", e))?;
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
        self.runtime.revalidate().map_err(map_error)?;
        self.profiles.revalidate().map_err(map_error)?;
        self.assets.revalidate().map_err(map_error)?;
        #[cfg(target_os = "linux")]
        canonical(&self.workspace)?;
        let owners = self
            .owners
            .lock()
            .map_err(|_| ErrorCategory::ResultUnknown)?;
        for p in owners.iter() {
            p.profile.revalidate().map_err(map_error)?;
            p.output.revalidate().map_err(map_error)?;
            #[cfg(any(target_os = "windows", target_os = "macos"))]
            p.workspace.revalidate().map_err(map_error)?;
        }
        Ok(())
    }
}
impl BrowserBootstrap for LocalBrowser {
    fn saved_profiles(&self) -> Result<Vec<String>> {
        saved_profile_ids(&self.profiles)
    }

    fn release_profile(&self, owner: &OwnerLease) {
        if let Ok(mut owners) = self.owners.lock() {
            owners.retain(|entry| &entry.owner != owner);
        }
    }

    fn prepare_profile(&self, owner: &OwnerLease) -> Result<OwnedBrowserConfig> {
        self.validate_inputs(true)?;
        let mut owners = self
            .owners
            .lock()
            .map_err(|_| ErrorCategory::ResultUnknown)?;
        if let Some(p) = owners.iter().find(|p| &p.owner == owner) {
            return Ok(p.config.clone());
        }
        // Old runtime owners are never restored. The Host's stable profile ID
        // selects only browser data; Core still decides valid operator leases.
        if owners
            .iter()
            .any(|p| p.owner.owner_id() == owner.owner_id())
        {
            return Err(ErrorCategory::Unauthorized);
        }
        let private = profile_directory(&self.runtime, &self.profiles, owner.owner_id().as_str())?;
        let output = assets::fresh_private_directory(self.runtime.path()).map_err(map_error)?;
        #[cfg(any(target_os = "windows", target_os = "macos"))]
        let workspace = assets::fresh_private_directory(self.runtime.path()).map_err(map_error)?;
        let config = OwnedBrowserConfig {
            node_binary: self.node_path.clone(),
            worker_entry: self.assets.entry_path().into(),
            browser_binary: self.browser.clone(),
            #[cfg(target_os = "linux")]
            workspace_dir: self.workspace.clone(),
            #[cfg(any(target_os = "windows", target_os = "macos"))]
            workspace_dir: workspace.path().into(),
            profile_dir: private.path().into(),
            output_dir: output.path().into(),
            #[cfg(any(target_os = "windows", target_os = "macos"))]
            node_pin: self.node.clone(),
            #[cfg(target_os = "windows")]
            environment: self
                .profile
                .browser_environment()
                .map_err(|_| ErrorCategory::PermissionDenied)?,
            #[cfg(target_os = "macos")]
            environment: std::collections::BTreeMap::new(),
            rpc_timeout: Duration::from_millis(u64::from(
                crate::host::protocol::wire::BROWSER_WAIT_PREPARE_TIMEOUT_MS,
            )),
        };
        private.revalidate().map_err(map_error)?;
        output.revalidate().map_err(map_error)?;
        #[cfg(target_os = "macos")]
        let config = OwnedBrowserConfig {
            environment: std::collections::BTreeMap::from([
                ("HOME".into(), output.path().to_string_lossy().into_owned()),
                (
                    "TMPDIR".into(),
                    output.path().to_string_lossy().into_owned(),
                ),
                ("PATH".into(), "/usr/bin:/bin".into()),
                ("LANG".into(), "C.UTF-8".into()),
                // Bind crash data to this original protected owner directory.
                // HOME alone does not select Chrome's native crash database.
                (
                    "BREAKPAD_DUMP_LOCATION".into(),
                    output.path().to_string_lossy().into_owned(),
                ),
            ]),
            ..config
        };
        owners.push(OwnerProfile {
            owner: owner.clone(),
            profile: private,
            output,
            #[cfg(any(target_os = "windows", target_os = "macos"))]
            workspace,
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
fn profile_id_name(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn persistent_profile_id(owner_id: &str) -> Option<&str> {
    let (profile, incarnation) = owner_id.strip_prefix("host-browser-")?.split_once('-')?;
    (profile_id_name(profile) && profile_id_name(incarnation)).then_some(profile)
}

pub(crate) fn profile_directory(
    runtime: &PrivateDirectory,
    profiles: &PrivateDirectory,
    owner_id: &str,
) -> Result<PrivateDirectory> {
    match persistent_profile_id(owner_id) {
        Some(profile) => {
            profiles.revalidate().map_err(map_error)?;
            assets::open_or_create_private_directory(profiles.path(), profile).map_err(map_error)
        }
        // Retain the private protocol/fixture behavior outside Host sessions.
        None => assets::fresh_private_directory(runtime.path()).map_err(map_error),
    }
}

fn saved_profile_ids(profiles: &PrivateDirectory) -> Result<Vec<String>> {
    profiles.revalidate().map_err(map_error)?;
    let mut ids = Vec::new();
    for entry in std::fs::read_dir(profiles.path()).map_err(|_| ErrorCategory::PermissionDenied)? {
        let entry = entry.map_err(|_| ErrorCategory::PermissionDenied)?;
        let name = entry.file_name();
        let Some(name) = name.to_str().filter(|name| profile_id_name(name)) else {
            continue;
        };
        if entry
            .file_type()
            .map_err(|_| ErrorCategory::PermissionDenied)?
            .is_dir()
        {
            ids.push(name.to_owned());
        }
    }
    ids.sort();
    Ok(ids)
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

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod selection_tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn installed_browser_aliases_and_multiple_candidates_follow_os_paths() {
        let directory = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("styx-browser-selection-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let chrome = directory.join("chrome");
        let edge = directory.join("edge");
        for path in [&chrome, &edge] {
            std::fs::write(path, b"installed browser fixture").unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o775)).unwrap();
        }
        let alias = directory.join("chrome-alias");
        let hard_link = directory.join("chrome-hard-link");
        symlink(&chrome, &alias).unwrap();
        std::fs::hard_link(&chrome, &hard_link).unwrap();
        assert_eq!(resolve_browser(&alias).unwrap(), chrome);
        assert_eq!(resolve_browser(&hard_link).unwrap(), hard_link);
        assert_eq!(
            first_browser(&[chrome.to_str().unwrap(), edge.to_str().unwrap()]).unwrap(),
            chrome
        );
        std::fs::rename(&chrome, directory.join("chrome-before-update")).unwrap();
        std::fs::write(&chrome, b"updated browser fixture").unwrap();
        assert_eq!(resolve_browser(&alias).unwrap(), chrome);
        assert_eq!(
            first_browser(&[chrome.to_str().unwrap(), edge.to_str().unwrap()]).unwrap(),
            chrome
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    struct PrivateFixture(PathBuf);
    impl PrivateFixture {
        fn new() -> Self {
            let path = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("styx-browser-profiles-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }
    impl Drop for PrivateFixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn persistent_profiles_keep_login_bytes_across_runtime_and_incarnation_changes() {
        let fixture = PrivateFixture::new();
        let profiles = assets::open_or_create_private_directory(&fixture.0, "profiles").unwrap();
        let profile_id = "a".repeat(32);
        let first_owner = format!("host-browser-{profile_id}-{}", "1".repeat(32));
        let (profile_path, runtime_path) = {
            let runtime = assets::fresh_private_directory(&fixture.0).unwrap();
            let profile = profile_directory(&runtime, &profiles, &first_owner).unwrap();
            std::fs::write(profile.path().join("Cookies"), b"persistent login fixture").unwrap();
            (profile.path().to_path_buf(), runtime.path().to_path_buf())
        };
        let profiles = assets::open_or_create_private_directory(&fixture.0, "profiles").unwrap();
        let runtime = assets::fresh_private_directory(&fixture.0).unwrap();
        let next_owner = format!("host-browser-{profile_id}-{}", "2".repeat(32));
        let reopened = profile_directory(&runtime, &profiles, &next_owner).unwrap();
        assert_ne!(runtime.path(), runtime_path);
        assert_eq!(reopened.path(), profile_path);
        assert_eq!(
            std::fs::read(reopened.path().join("Cookies")).unwrap(),
            b"persistent login fixture"
        );
        let other_owner = format!("host-browser-{}-{}", "b".repeat(32), "3".repeat(32));
        let other = profile_directory(&runtime, &profiles, &other_owner).unwrap();
        assert_ne!(other.path(), reopened.path());
        assert!(!other.path().join("Cookies").exists());
        let legacy = profile_directory(&runtime, &profiles, "browser-fixture-owner").unwrap();
        assert!(legacy.path().starts_with(runtime.path()));
        assert!(!legacy.path().starts_with(profiles.path()));
    }

    #[test]
    fn saved_profiles_list_only_stable_profile_directory_names() {
        let fixture = PrivateFixture::new();
        let profiles = assets::open_or_create_private_directory(&fixture.0, "profiles").unwrap();
        for name in ["b".repeat(32), "a".repeat(32), "not-a-profile".to_owned()] {
            assets::open_or_create_private_directory(profiles.path(), &name).unwrap();
        }
        std::fs::write(profiles.path().join("c".repeat(32)), b"not a directory").unwrap();
        symlink(
            profiles.path().join("a".repeat(32)),
            profiles.path().join("d".repeat(32)),
        )
        .unwrap();
        assert_eq!(
            saved_profile_ids(&profiles).unwrap(),
            vec!["a".repeat(32), "b".repeat(32)]
        );
        assert_eq!(
            persistent_profile_id(&format!(
                "host-browser-{}-{}",
                "a".repeat(32),
                "1".repeat(32)
            )),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        assert_eq!(
            persistent_profile_id(&format!(
                "host-browser-{}-{}",
                "A".repeat(32),
                "1".repeat(32)
            )),
            None
        );
        assert_eq!(persistent_profile_id("host-browser-old-incarnation"), None);
    }
}
