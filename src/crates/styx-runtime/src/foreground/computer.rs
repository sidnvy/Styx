//! Trusted transition-profile Cua bootstrap. The original signed release and
//! protected local selection remain authoritative; no executable/profile path,
//! session identity or environment is supplied by MCP. Synchronous filesystem
//! methods run only on the existing bounded bootstrap blocking workers.
use super::{ForegroundError, profile::LoadedLegacyProfile};
use crate::{
    host::{coordinator::DesktopSource, protocol::computer::ComputerBootstrap},
    providers::{
        browser::assets::{self, PrivateDirectory},
        cua::{OwnedCuaConfig, TrustedCuaLaunch},
    },
    store::PinnedExecutable,
};
#[cfg(target_os = "linux")]
use std::path::PathBuf;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use styx_contracts::{error::ErrorCategory, session::SessionBinding};
use styx_core::operations::OwnerLease;

const MAX_OWNERS: usize = 64;
const RPC_TIMEOUT: Duration = Duration::from_secs(10);
type Result<T> = std::result::Result<T, ErrorCategory>;
struct OwnerDirectories {
    owner: OwnerLease,
    root: PrivateDirectory,
    workspace: PrivateDirectory,
    home: PrivateDirectory,
    #[cfg(target_os = "windows")]
    temporary: PrivateDirectory,
}
struct LocalComputer {
    // These original authorities outlive configs/jobs and remain revalidated.
    // A cloned pin is not a new publisher or OS/session permission authority.
    profile: Arc<LoadedLegacyProfile>,
    driver: Arc<PinnedExecutable>,
    source: DesktopSource,
    source_epoch: u64,
    binding: SessionBinding,
    #[cfg(target_os = "linux")]
    uid: u32,
    #[cfg(target_os = "linux")]
    runtime_dir: PathBuf,
    #[cfg(target_os = "linux")]
    wayland_display: String,
    #[cfg(target_os = "linux")]
    hyprland_instance: String,
    runtime: PrivateDirectory,
    #[cfg(target_os = "windows")]
    environment: std::collections::BTreeMap<String, String>,
    owners: Mutex<Vec<OwnerDirectories>>,
}
/// Called after root has explicitly selected/registered the source and exact
/// Core binding. Does not start/probe/register an Agent or infer permission.
/// None means the protected Computer lane is locally disabled, not unavailable
/// Exec. Creation never adopts an existing home or any original user profile.
pub(crate) fn prepare_computer_bootstrap(
    profile: Arc<LoadedLegacyProfile>,
    source: DesktopSource,
    binding: SessionBinding,
) -> std::result::Result<Option<Arc<dyn ComputerBootstrap>>, ForegroundError> {
    let Some(driver) = profile.pin_cua_driver()? else {
        return Ok(None);
    };
    let epoch = source.epoch();
    #[cfg(target_os = "linux")]
    let fields = source
        .launch_fields()
        .map_err(|error| ForegroundError(error.code()))?;
    #[cfg(target_os = "linux")]
    let uid = nix::unistd::Uid::current().as_raw();
    #[cfg(target_os = "linux")]
    if fields.runtime_dir != std::path::Path::new(&format!("/run/user/{uid}")) {
        return Err(ForegroundError("desktop_source_fenced"));
    }
    if source.fenced() || source.epoch() != epoch {
        return Err(ForegroundError("desktop_source_fenced"));
    }
    let runtime = assets::fresh_private_directory(profile.host_base_dir())
        .map_err(|_| ForegroundError("computer_private_root_failed"))?;
    #[cfg(target_os = "windows")]
    let environment = profile.browser_environment()?;
    let factory = LocalComputer {
        profile,
        driver: Arc::new(driver),
        source,
        source_epoch: epoch,
        binding,
        #[cfg(target_os = "linux")]
        uid,
        #[cfg(target_os = "linux")]
        runtime_dir: fields.runtime_dir,
        #[cfg(target_os = "linux")]
        wayland_display: fields.wayland_display,
        #[cfg(target_os = "linux")]
        hyprland_instance: fields.hyprland_instance,
        runtime,
        #[cfg(target_os = "windows")]
        environment,
        owners: Mutex::new(Vec::new()),
    };
    factory
        .validate_before_spawn()
        .map_err(|_| ForegroundError("computer_bootstrap_changed"))?;
    Ok(Some(Arc::new(factory)))
}
impl LocalComputer {
    fn validate_source(&self) -> Result<()> {
        if self.source.fenced() || self.source.epoch() != self.source_epoch {
            return Err(ErrorCategory::SessionDisconnected);
        }
        #[cfg(target_os = "linux")]
        {
            let fields = self
                .source
                .launch_fields()
                .map_err(|_| ErrorCategory::SessionDisconnected)?;
            if fields.runtime_dir != self.runtime_dir
                || fields.wayland_display != self.wayland_display
                || fields.hyprland_instance != self.hyprland_instance
                || self.source.fenced()
                || self.source.epoch() != self.source_epoch
            {
                return Err(ErrorCategory::SessionDisconnected);
            }
        }
        Ok(())
    }
    fn validate_inputs(&self, full_release: bool) -> Result<()> {
        self.validate_source()?;
        if full_release {
            self.profile.revalidate()
        } else {
            self.profile.revalidate_control()
        }
        .map_err(|_| ErrorCategory::IntegrityFailure)?;
        self.driver
            .revalidate()
            .map_err(|_| ErrorCategory::IntegrityFailure)?;
        self.runtime.revalidate().map_err(map_directory)?;
        {
            let owners = self
                .owners
                .lock()
                .map_err(|_| ErrorCategory::ResultUnknown)?;
            for owner in owners.iter() {
                owner.root.revalidate().map_err(map_directory)?;
                owner.workspace.revalidate().map_err(map_directory)?;
                owner.home.revalidate().map_err(map_directory)?;
                #[cfg(target_os = "windows")]
                owner.temporary.revalidate().map_err(map_directory)?;
            }
        }
        // A fence concurrent with protected I/O invalidates the completed result too.
        self.validate_source()
    }
    #[cfg(target_os = "linux")]
    fn config(&self, owner: &OwnerDirectories) -> Result<OwnedCuaConfig> {
        Ok(OwnedCuaConfig {
            driver: self.driver.clone(),
            launch: TrustedCuaLaunch {
                session: self.binding.clone(),
                uid: self.uid,
                runtime_dir: self.runtime_dir.clone(),
                wayland_display: self.wayland_display.clone(),
                hyprland_instance: self.hyprland_instance.clone(),
                compositor_peer: self
                    .source
                    .window_read_evidence()
                    .map_err(|_| ErrorCategory::SessionDisconnected)?
                    .source_peer(),
                session_bus: self.runtime_dir.join("bus"),
            },
            rpc_timeout: RPC_TIMEOUT,
            workspace: owner.workspace.path().into(),
            home: owner.home.path().into(),
        })
    }
    #[cfg(target_os = "windows")]
    fn config(&self, owner: &OwnerDirectories) -> Result<OwnedCuaConfig> {
        // Only the OS-derived baseline is reused. All Cua state and temporary
        // paths belong to this exact owner's retained private directories.
        let mut environment = std::collections::BTreeMap::new();
        for (source, target) in [
            ("SystemRoot", "SystemRoot"),
            ("WinDir", "WINDIR"),
            ("ComSpec", "COMSPEC"),
            ("Path", "PATH"),
            ("PATHEXT", "PATHEXT"),
        ] {
            let value = self
                .environment
                .get(source)
                .ok_or(ErrorCategory::IntegrityFailure)?;
            environment.insert(target.to_owned(), value.clone());
        }
        let home = owner
            .home
            .path()
            .to_str()
            .ok_or(ErrorCategory::IntegrityFailure)?;
        let temporary = owner
            .temporary
            .path()
            .to_str()
            .ok_or(ErrorCategory::IntegrityFailure)?;
        for key in ["HOME", "USERPROFILE", "CUA_DRIVER_RS_HOME"] {
            environment.insert(key.into(), home.into());
        }
        for key in ["TEMP", "TMP"] {
            environment.insert(key.into(), temporary.into());
        }
        environment.insert("CUA_DRIVER_RS_TELEMETRY_ENABLED".into(), "0".into());
        environment.insert("DO_NOT_TRACK".into(), "1".into());
        Ok(OwnedCuaConfig {
            driver: self.driver.clone(),
            launch: TrustedCuaLaunch {
                session: self.binding.clone(),
                source: self.source.clone(),
            },
            rpc_timeout: RPC_TIMEOUT,
            workspace: owner.workspace.path().into(),
            home: owner.home.path().into(),
            environment,
        })
    }
}
impl ComputerBootstrap for LocalComputer {
    fn release_profile(&self, owner: &OwnerLease) {
        if let Ok(mut owners) = self.owners.lock() {
            owners.retain(|entry| &entry.owner != owner);
        }
    }

    fn prepare_profile(&self, owner: &OwnerLease) -> Result<OwnedCuaConfig> {
        self.validate_inputs(true)?;
        let mut owners = self
            .owners
            .lock()
            .map_err(|_| ErrorCategory::ResultUnknown)?;
        if let Some(existing) = owners.iter().find(|existing| &existing.owner == owner) {
            let config = self.config(existing)?;
            self.validate_source()?;
            return Ok(config);
        }
        // A same display name/OwnerId with a different opaque epoch/incarnation does
        // not adopt a previous owner's runtime directories or native resource.
        if owners
            .iter()
            .any(|existing| existing.owner.owner_id() == owner.owner_id())
        {
            return Err(ErrorCategory::Unauthorized);
        }
        if owners.len() >= MAX_OWNERS {
            return Err(ErrorCategory::Busy);
        }
        let root = assets::fresh_private_directory(self.runtime.path()).map_err(map_directory)?;
        let workspace = assets::fresh_private_directory(root.path()).map_err(map_directory)?;
        let home = assets::fresh_private_directory(root.path()).map_err(map_directory)?;
        #[cfg(target_os = "windows")]
        let temporary = assets::fresh_private_directory(root.path()).map_err(map_directory)?;
        let owned = OwnerDirectories {
            owner: owner.clone(),
            root,
            workspace,
            home,
            #[cfg(target_os = "windows")]
            temporary,
        };
        owned.root.revalidate().map_err(map_directory)?;
        owned.workspace.revalidate().map_err(map_directory)?;
        owned.home.revalidate().map_err(map_directory)?;
        #[cfg(target_os = "windows")]
        owned.temporary.revalidate().map_err(map_directory)?;
        self.validate_source()?;
        let config = self.config(&owned)?;
        config
            .validate_metadata_bound()
            .map_err(|_| ErrorCategory::InvalidRequest)?;
        owners.push(owned);
        Ok(config)
    }
    fn validate_before_spawn(&self) -> Result<()> {
        self.validate_inputs(true)
    }
    fn validate_control(&self) -> Result<()> {
        self.validate_inputs(false)
    }
}
fn map_directory(error: crate::providers::browser::BrowserError) -> ErrorCategory {
    use crate::providers::browser::BrowserError;
    match error {
        BrowserError::Busy => ErrorCategory::Busy,
        BrowserError::PermissionDenied => ErrorCategory::PermissionDenied,
        BrowserError::Unsupported => ErrorCategory::CapabilityUnsupported,
        _ => ErrorCategory::IntegrityFailure,
    }
}
