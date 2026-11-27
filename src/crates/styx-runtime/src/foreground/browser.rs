//! Extension-Bridge-only Browser bootstrap. No pairing, publisher, login
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

type Result<T> = std::result::Result<T, ErrorCategory>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    enabled: bool,
    #[serde(rename = "executablePath", default)]
    _executable: Option<PathBuf>,
    #[serde(rename = "channel", default)]
    _channel: Option<String>,
    #[serde(rename = "profileRoot", default)]
    _profile_root: Option<PathBuf>,
}
struct OwnerProfile {
    owner: OwnerLease,
    output: PrivateDirectory,
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    workspace: PrivateDirectory,
    config: OwnedBrowserConfig,
}
struct LocalBrowser {
    profile: Arc<LoadedProfile>,
    extension: Option<Arc<crate::host::browser_extension::BrowserExtensionBridge>>,
    node: Arc<PinnedExecutable>,
    node_path: PathBuf,
    runtime: PrivateDirectory,
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

fn selected(profile: &LoadedProfile) -> Result<bool> {
    let source = profile.browser_source();
    let (deployment, host) = (source.deployment, source.host);
    if deployment
        .and_then(|v| v.get("enabled"))
        .and_then(|v| v.as_bool())
        != Some(true)
    {
        return Ok(false);
    }
    let d: Selection = serde_json::from_value(deployment.unwrap().clone())
        .map_err(|_| ErrorCategory::CapabilityUnsupported)?;
    let h: Selection =
        serde_json::from_value(host.ok_or(ErrorCategory::CapabilityUnsupported)?.clone())
            .map_err(|_| ErrorCategory::CapabilityUnsupported)?;
    if !d.enabled || !h.enabled {
        return Err(ErrorCategory::CapabilityUnsupported);
    }
    Ok(true)
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
    extension: Option<Arc<crate::host::browser_extension::BrowserExtensionBridge>>,
) -> std::result::Result<Option<Arc<dyn BrowserBootstrap>>, BrowserPreparationError> {
    let at = BrowserPreparationError::new;
    if !selected(&profile).map_err(|e| at("selection", e))? {
        return Ok(None);
    }
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
        extension,
        runtime,
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
        self.assets.revalidate().map_err(map_error)?;
        #[cfg(target_os = "linux")]
        canonical(&self.workspace)?;
        let owners = self
            .owners
            .lock()
            .map_err(|_| ErrorCategory::ResultUnknown)?;
        for p in owners.iter() {
            p.output.revalidate().map_err(map_error)?;
            #[cfg(any(target_os = "windows", target_os = "macos"))]
            p.workspace.revalidate().map_err(map_error)?;
        }
        Ok(())
    }
}
impl BrowserBootstrap for LocalBrowser {
    fn release_profile(&self, owner: &OwnerLease) {
        if let Ok(mut owners) = self.owners.lock() {
            owners.retain(|entry| &entry.owner != owner);
        }
    }

    fn prepare_profile(
        &self,
        owner: &OwnerLease,
        scope: crate::host::browser_extension::CdpSessionScope,
    ) -> Result<OwnedBrowserConfig> {
        self.validate_inputs(true)?;
        let mut owners = self
            .owners
            .lock()
            .map_err(|_| ErrorCategory::ResultUnknown)?;
        if let Some(p) = owners.iter().find(|p| &p.owner == owner) {
            return Ok(p.config.clone());
        }
        if owners
            .iter()
            .any(|p| p.owner.owner_id() == owner.owner_id())
        {
            return Err(ErrorCategory::Unauthorized);
        }
        let bridge = self
            .extension
            .as_ref()
            .ok_or(ErrorCategory::CapabilityUnsupported)?;
        let cdp_endpoint = bridge.open_cdp_session_with_scope(scope)?;
        let output = assets::fresh_private_directory(self.runtime.path()).map_err(map_error)?;
        #[cfg(any(target_os = "windows", target_os = "macos"))]
        let workspace = assets::fresh_private_directory(self.runtime.path()).map_err(map_error)?;
        let config = OwnedBrowserConfig {
            node_binary: self.node_path.clone(),
            worker_entry: self.assets.entry_path().into(),
            cdp_endpoint,
            #[cfg(target_os = "linux")]
            workspace_dir: self.workspace.clone(),
            #[cfg(any(target_os = "windows", target_os = "macos"))]
            workspace_dir: workspace.path().into(),
            output_dir: output.path().into(),
            #[cfg(any(target_os = "windows", target_os = "macos"))]
            node_pin: self.node.clone(),
            #[cfg(target_os = "windows")]
            environment: self
                .profile
                .browser_environment()
                .map_err(|_| ErrorCategory::PermissionDenied)?,
            #[cfg(target_os = "macos")]
            environment: std::collections::BTreeMap::from([
                ("HOME".into(), output.path().to_string_lossy().into_owned()),
                (
                    "TMPDIR".into(),
                    output.path().to_string_lossy().into_owned(),
                ),
                ("PATH".into(), "/usr/bin:/bin".into()),
                ("LANG".into(), "C.UTF-8".into()),
                (
                    "BREAKPAD_DUMP_LOCATION".into(),
                    output.path().to_string_lossy().into_owned(),
                ),
            ]),
            rpc_timeout: Duration::from_millis(u64::from(
                crate::host::protocol::wire::BROWSER_WAIT_PREPARE_TIMEOUT_MS,
            )),
        };
        output.revalidate().map_err(map_error)?;
        owners.push(OwnerProfile {
            owner: owner.clone(),
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
    fn extension_bridge(
        &self,
    ) -> Option<Arc<crate::host::browser_extension::BrowserExtensionBridge>> {
        self.extension.clone()
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

#[cfg(test)]
mod selection_tests {
    use super::*;

    #[test]
    fn selection_accepts_enabled_flags_with_or_without_legacy_fields() {
        let legacy: Selection = serde_json::from_value(serde_json::json!({
            "enabled": true,
            "channel": "chrome",
            "profileRoot": "/home/sid/.local/state/styx/host/browser"
        }))
        .unwrap();
        assert!(legacy.enabled);

        let minimal: Selection =
            serde_json::from_value(serde_json::json!({ "enabled": true })).unwrap();
        assert!(minimal.enabled);
    }
}
