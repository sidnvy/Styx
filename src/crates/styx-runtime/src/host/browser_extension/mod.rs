//! Host-owned Chrome Extension (MV3) + Native Messaging bridge for zero-prompt
//! attachment to the user's everyday signed-in Chrome/Edge/Chromium profile.
pub mod cdp_relay;
pub mod native_host;
#[cfg(test)]
mod tests;

pub use cdp_relay::BrowserExtensionBridge;

use crate::store::PrivateRoot;
use serde::{Deserialize, Serialize};
use std::{
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
};
use styx_contracts::error::ErrorCategory;

pub const NATIVE_HOST_NAME: &str = "com.styx.browser_bridge";
pub const EXTENSION_ID: &str = "cncjpfhbbnibdjkcheeimdfklfiknibl";
const EXTENSION_DIR: &str = "browser-extension";
const BRIDGE_FILE: &str = "browser-extension-bridge.json";

#[cfg(unix)]
const LAUNCHER_NAME: &str = "browser-extension-host.sh";
#[cfg(windows)]
const LAUNCHER_NAME: &str = "browser-extension-host.cmd";
#[cfg(windows)]
const WINDOWS_MANIFEST_NAME: &str = "com.styx.browser_bridge.json";

struct EmbeddedAsset {
    relative: &'static str,
    bytes: &'static [u8],
}

const EXTENSION_ASSETS: &[EmbeddedAsset] = &[
    EmbeddedAsset {
        relative: "manifest.json",
        bytes: include_bytes!("../../../../../providers/browser-extension/manifest.json"),
    },
    EmbeddedAsset {
        relative: "background.js",
        bytes: include_bytes!("../../../../../providers/browser-extension/background.js"),
    },
    EmbeddedAsset {
        relative: "popup.html",
        bytes: include_bytes!("../../../../../providers/browser-extension/popup.html"),
    },
    EmbeddedAsset {
        relative: "popup.js",
        bytes: include_bytes!("../../../../../providers/browser-extension/popup.js"),
    },
    EmbeddedAsset {
        relative: "icons/icon16.png",
        bytes: include_bytes!("../../../../../providers/browser-extension/icons/icon16.png"),
    },
    EmbeddedAsset {
        relative: "icons/icon48.png",
        bytes: include_bytes!("../../../../../providers/browser-extension/icons/icon48.png"),
    },
    EmbeddedAsset {
        relative: "icons/icon128.png",
        bytes: include_bytes!("../../../../../providers/browser-extension/icons/icon128.png"),
    },
];

/// Read-only status snapshot of the local Chrome Extension bridge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserExtensionStatus {
    pub installed: bool,
    pub connected: bool,
    #[serde(rename = "extensionId")]
    pub extension_id: String,
    #[serde(rename = "extensionPath", skip_serializing_if = "Option::is_none")]
    pub extension_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser: Option<String>,
}

pub fn extension_dir(state_dir: &Path) -> PathBuf {
    state_dir.join(EXTENSION_DIR)
}

pub(crate) fn bridge_file_path(state_dir: &Path) -> PathBuf {
    state_dir.join(BRIDGE_FILE)
}

fn launcher_path(state_dir: &Path) -> PathBuf {
    state_dir.join(LAUNCHER_NAME)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BridgeEndpoint {
    schema: u16,
    port: u16,
    token: String,
}

fn native_manifest_json(launcher: &Path) -> Result<Vec<u8>, ErrorCategory> {
    let manifest = serde_json::json!({
        "name": NATIVE_HOST_NAME,
        "description": "Styx Browser Bridge",
        "path": launcher.to_string_lossy(),
        "type": "stdio",
        "allowed_origins": [format!("chrome-extension://{EXTENSION_ID}/")],
    });
    serde_json::to_vec_pretty(&manifest).map_err(|_| ErrorCategory::IntegrityFailure)
}

fn atomic_write(
    dir: &Path,
    path: &Path,
    bytes: &[u8],
    executable: bool,
) -> Result<(), ErrorCategory> {
    let mut temp =
        tempfile::NamedTempFile::new_in(dir).map_err(|_| ErrorCategory::IntegrityFailure)?;
    temp.write_all(bytes)
        .and_then(|()| temp.as_file().sync_all())
        .map_err(|_| ErrorCategory::IntegrityFailure)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if executable { 0o700 } else { 0o600 };
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(mode))
            .map_err(|_| ErrorCategory::IntegrityFailure)?;
    }
    #[cfg(not(unix))]
    let _ = executable;
    temp.persist(path)
        .map_err(|_| ErrorCategory::IntegrityFailure)?;
    Ok(())
}

fn ensure_private_dir(path: &Path) -> Result<(), ErrorCategory> {
    if !path.exists() {
        std::fs::create_dir_all(path).map_err(|_| ErrorCategory::IntegrityFailure)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                .map_err(|_| ErrorCategory::IntegrityFailure)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn shell_quote(raw: &str) -> String {
    let escaped = raw.replace('\'', "'\"'\"'");
    format!("'{escaped}'")
}

fn launcher_script_bytes(styx_binary: &Path, state_dir: &Path) -> Result<Vec<u8>, ErrorCategory> {
    let bin_str = styx_binary.to_str().ok_or(ErrorCategory::InvalidRequest)?;
    let state_str = state_dir.to_str().ok_or(ErrorCategory::InvalidRequest)?;
    #[cfg(unix)]
    {
        Ok(format!(
            "#!/bin/sh\nexec {} __browser-extension-bridge --state-dir {}\n",
            shell_quote(bin_str),
            shell_quote(state_str)
        )
        .into_bytes())
    }
    #[cfg(windows)]
    {
        Ok(format!(
            "@echo off\r\n\"{bin_str}\" __browser-extension-bridge --state-dir \"{state_str}\"\r\n"
        )
        .into_bytes())
    }
}

#[cfg(target_os = "linux")]
fn unix_manifest_dirs() -> Vec<(PathBuf, bool)> {
    let config_home = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|v| !v.is_empty())
                .map(|home| PathBuf::from(home).join(".config"))
        });
    let Some(base) = config_home else {
        return Vec::new();
    };
    vec![
        (base.join("google-chrome/NativeMessagingHosts"), true),
        (base.join("chromium/NativeMessagingHosts"), false),
        (base.join("microsoft-edge/NativeMessagingHosts"), false),
        (
            base.join("BraveSoftware/Brave-Browser/NativeMessagingHosts"),
            false,
        ),
    ]
}

#[cfg(target_os = "macos")]
fn unix_manifest_dirs() -> Vec<(PathBuf, bool)> {
    let Some(home) = std::env::var_os("HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
    else {
        return Vec::new();
    };
    let base = home.join("Library/Application Support");
    vec![
        (base.join("Google/Chrome/NativeMessagingHosts"), true),
        (base.join("Chromium/NativeMessagingHosts"), false),
        (base.join("Microsoft Edge/NativeMessagingHosts"), false),
        (
            base.join("BraveSoftware/Brave-Browser/NativeMessagingHosts"),
            false,
        ),
    ]
}

#[cfg(target_os = "windows")]
const WINDOWS_REG_KEYS: &[&str] = &[
    r"HKCU\Software\Google\Chrome\NativeMessagingHosts\com.styx.browser_bridge",
    r"HKCU\Software\Microsoft\Edge\NativeMessagingHosts\com.styx.browser_bridge",
    r"HKCU\Software\Chromium\NativeMessagingHosts\com.styx.browser_bridge",
];

#[cfg(target_os = "windows")]
fn write_windows_registry_key(key: &str, value: &Path) -> Result<(), ErrorCategory> {
    let status = std::process::Command::new("reg.exe")
        .args([
            "add",
            key,
            "/ve",
            "/t",
            "REG_SZ",
            "/d",
            value.to_str().ok_or(ErrorCategory::InvalidRequest)?,
            "/f",
        ])
        .status()
        .map_err(|_| ErrorCategory::IntegrityFailure)?;
    if status.success() {
        Ok(())
    } else {
        Err(ErrorCategory::IntegrityFailure)
    }
}

#[cfg(target_os = "windows")]
fn delete_windows_registry_key(key: &str) {
    let _ = std::process::Command::new("reg.exe")
        .args(["delete", key, "/f"])
        .status();
}

#[cfg(target_os = "windows")]
fn windows_registry_key_exists(key: &str) -> bool {
    std::process::Command::new("reg.exe")
        .args(["query", key, "/ve"])
        .output()
        .is_ok_and(|out| out.status.success())
}

/// Installs the embedded MV3 extension assets, Native Messaging host launcher, and
/// browser-specific Native Messaging host manifests for this Host `state_dir`.
pub fn install(
    state_dir: &Path,
    styx_binary: &Path,
) -> Result<BrowserExtensionStatus, ErrorCategory> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let dirs = unix_manifest_dirs();
        install_with_manifest_dirs(state_dir, styx_binary, &dirs)?;
    }
    #[cfg(target_os = "windows")]
    {
        let root = PrivateRoot::open(state_dir).map_err(|_| ErrorCategory::IntegrityFailure)?;
        install_extension_files(state_dir, &root, styx_binary)?;
        let manifest_path = state_dir.join(WINDOWS_MANIFEST_NAME);
        let manifest_bytes = native_manifest_json(&launcher_path(state_dir))?;
        atomic_write(state_dir, &manifest_path, &manifest_bytes, false)?;
        write_windows_registry_key(WINDOWS_REG_KEYS[0], &manifest_path)?;
        for extra in &WINDOWS_REG_KEYS[1..] {
            let _ = write_windows_registry_key(extra, &manifest_path);
        }
    }
    status(state_dir, None)
}

fn install_extension_files(
    state_dir: &Path,
    _root: &PrivateRoot,
    styx_binary: &Path,
) -> Result<PathBuf, ErrorCategory> {
    let canonical_bin =
        std::fs::canonicalize(styx_binary).map_err(|_| ErrorCategory::InvalidRequest)?;
    if !canonical_bin.is_file() {
        return Err(ErrorCategory::InvalidRequest);
    }
    let ext_dir = extension_dir(state_dir);
    ensure_private_dir(&ext_dir)?;
    ensure_private_dir(&ext_dir.join("icons"))?;
    for asset in EXTENSION_ASSETS {
        let dest = ext_dir.join(asset.relative);
        let parent = dest.parent().ok_or(ErrorCategory::IntegrityFailure)?;
        atomic_write(parent, &dest, asset.bytes, false)?;
    }
    let launcher = launcher_path(state_dir);
    let script = launcher_script_bytes(&canonical_bin, state_dir)?;
    atomic_write(state_dir, &launcher, &script, true)?;
    Ok(launcher)
}

pub(crate) fn install_with_manifest_dirs(
    state_dir: &Path,
    styx_binary: &Path,
    manifest_dirs: &[(PathBuf, bool)],
) -> Result<(), ErrorCategory> {
    let root = PrivateRoot::open(state_dir).map_err(|_| ErrorCategory::IntegrityFailure)?;
    let launcher = install_extension_files(state_dir, &root, styx_binary)?;
    let manifest_bytes = native_manifest_json(&launcher)?;
    let mut wrote_any = false;
    for (dir, always_create) in manifest_dirs {
        let browser_root_exists = dir.parent().is_some_and(|p| p.exists());
        if !*always_create && !browser_root_exists {
            continue;
        }
        std::fs::create_dir_all(dir).map_err(|_| ErrorCategory::IntegrityFailure)?;
        let target = dir.join(format!("{NATIVE_HOST_NAME}.json"));
        atomic_write(dir, &target, &manifest_bytes, false)?;
        wrote_any = true;
    }
    if !wrote_any && !manifest_dirs.is_empty() {
        return Err(ErrorCategory::IntegrityFailure);
    }
    Ok(())
}

/// Removes the Native Messaging manifests, Windows registry entries, and launcher script.
pub fn uninstall(state_dir: &Path) -> Result<BrowserExtensionStatus, ErrorCategory> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        uninstall_with_manifest_dirs(state_dir, &unix_manifest_dirs())?;
    }
    #[cfg(target_os = "windows")]
    {
        for key in WINDOWS_REG_KEYS {
            delete_windows_registry_key(key);
        }
        let _ = std::fs::remove_file(state_dir.join(WINDOWS_MANIFEST_NAME));
        let _ = std::fs::remove_file(launcher_path(state_dir));
    }
    status(state_dir, None)
}

pub(crate) fn uninstall_with_manifest_dirs(
    state_dir: &Path,
    manifest_dirs: &[(PathBuf, bool)],
) -> Result<(), ErrorCategory> {
    let _root = PrivateRoot::open(state_dir).map_err(|_| ErrorCategory::IntegrityFailure)?;
    for (dir, _) in manifest_dirs {
        let path = dir.join(format!("{NATIVE_HOST_NAME}.json"));
        if path.exists() {
            let _ = std::fs::remove_file(path);
        }
    }
    let launcher = launcher_path(state_dir);
    if launcher.exists() {
        let _ = std::fs::remove_file(launcher);
    }
    Ok(())
}

fn manifest_installed(manifest_dirs: &[(PathBuf, bool)]) -> bool {
    manifest_dirs
        .iter()
        .any(|(dir, _)| dir.join(format!("{NATIVE_HOST_NAME}.json")).is_file())
}

pub(crate) fn status_with_manifest_dirs(
    state_dir: &Path,
    manifest_dirs: &[(PathBuf, bool)],
    bridge: Option<&BrowserExtensionBridge>,
) -> Result<BrowserExtensionStatus, ErrorCategory> {
    let _root = PrivateRoot::open(state_dir).map_err(|_| ErrorCategory::IntegrityFailure)?;
    let ext_dir = extension_dir(state_dir);
    let assets_ok = ext_dir.join("manifest.json").is_file() && launcher_path(state_dir).is_file();
    let host_ok = manifest_installed(manifest_dirs);
    let installed = assets_ok && host_ok;
    let connected = bridge.is_some_and(BrowserExtensionBridge::is_connected);
    let browser = bridge.and_then(BrowserExtensionBridge::browser_label);
    Ok(BrowserExtensionStatus {
        installed,
        connected,
        extension_id: EXTENSION_ID.to_owned(),
        extension_path: assets_ok.then(|| ext_dir.to_string_lossy().into_owned()),
        browser,
    })
}

pub fn status(
    state_dir: &Path,
    bridge: Option<&BrowserExtensionBridge>,
) -> Result<BrowserExtensionStatus, ErrorCategory> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        status_with_manifest_dirs(state_dir, &unix_manifest_dirs(), bridge)
    }
    #[cfg(target_os = "windows")]
    {
        let _root = PrivateRoot::open(state_dir).map_err(|_| ErrorCategory::IntegrityFailure)?;
        let ext_dir = extension_dir(state_dir);
        let assets_ok = ext_dir.join("manifest.json").is_file()
            && launcher_path(state_dir).is_file()
            && state_dir.join(WINDOWS_MANIFEST_NAME).is_file();
        let reg_ok = WINDOWS_REG_KEYS
            .iter()
            .any(|k| windows_registry_key_exists(k));
        let installed = assets_ok && reg_ok;
        let connected = bridge.is_some_and(BrowserExtensionBridge::is_connected);
        let browser = bridge.and_then(BrowserExtensionBridge::browser_label);
        Ok(BrowserExtensionStatus {
            installed,
            connected,
            extension_id: EXTENSION_ID.to_owned(),
            extension_path: assets_ok.then(|| ext_dir.to_string_lossy().into_owned()),
            browser,
        })
    }
}

pub(crate) fn read_bridge_endpoint(state_dir: &Path) -> Option<(u16, String)> {
    let path = bridge_file_path(state_dir);
    let meta = std::fs::symlink_metadata(&path).ok()?;
    if !meta.file_type().is_file() || meta.len() > 4096 {
        return None;
    }
    let mut file = OpenOptions::new().read(true).open(&path).ok()?;
    let mut raw = String::new();
    std::io::Read::read_to_string(&mut file, &mut raw).ok()?;
    let parsed: BridgeEndpoint = serde_json::from_str(&raw).ok()?;
    if parsed.schema != 1 || parsed.port == 0 || parsed.token.is_empty() {
        return None;
    }
    Some((parsed.port, parsed.token))
}
