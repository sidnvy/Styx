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
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use styx_contracts::{error::ErrorCategory, session::SessionBinding};
use styx_core::operations::OwnerLease;

const MAX_OWNERS: usize = 16;
const RPC_TIMEOUT: Duration = Duration::from_secs(10);
type Result<T> = std::result::Result<T, ErrorCategory>;
struct OwnerDirectories {
    owner: OwnerLease,
    root: PrivateDirectory,
    workspace: PrivateDirectory,
    home: PrivateDirectory,
}
struct LocalComputer {
    // These original authorities outlive configs/jobs and remain revalidated.
    // A cloned pin is not a new publisher or OS/session permission authority.
    profile: Arc<LoadedLegacyProfile>,
    driver: Arc<PinnedExecutable>,
    source: DesktopSource,
    source_epoch: u64,
    binding: SessionBinding,
    uid: u32,
    runtime_dir: PathBuf,
    wayland_display: String,
    hyprland_instance: String,
    runtime: PrivateDirectory,
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
    let fields = source
        .launch_fields()
        .map_err(|error| ForegroundError(error.code()))?;
    let uid = nix::unistd::Uid::current().as_raw();
    if source.fenced()
        || source.epoch() != epoch
        || fields.runtime_dir != std::path::Path::new(&format!("/run/user/{uid}"))
    {
        return Err(ForegroundError("desktop_source_fenced"));
    }
    let runtime = assets::fresh_private_directory(profile.host_base_dir())
        .map_err(|_| ForegroundError("computer_private_root_failed"))?;
    let factory = LocalComputer {
        profile,
        driver: Arc::new(driver),
        source,
        source_epoch: epoch,
        binding,
        uid,
        runtime_dir: fields.runtime_dir,
        wayland_display: fields.wayland_display,
        hyprland_instance: fields.hyprland_instance,
        runtime,
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
            }
        }
        // A fence concurrent with protected I/O invalidates the completed result too.
        self.validate_source()
    }
    fn config(&self, owner: &OwnerDirectories) -> OwnedCuaConfig {
        OwnedCuaConfig {
            driver: self.driver.clone(),
            launch: TrustedCuaLaunch {
                session: self.binding.clone(),
                uid: self.uid,
                runtime_dir: self.runtime_dir.clone(),
                wayland_display: self.wayland_display.clone(),
                hyprland_instance: self.hyprland_instance.clone(),
                session_bus: self.runtime_dir.join("bus"),
            },
            rpc_timeout: RPC_TIMEOUT,
            workspace: owner.workspace.path().into(),
            home: owner.home.path().into(),
        }
    }
}
impl ComputerBootstrap for LocalComputer {
    fn prepare_profile(&self, owner: &OwnerLease) -> Result<OwnedCuaConfig> {
        self.validate_inputs(true)?;
        let mut owners = self
            .owners
            .lock()
            .map_err(|_| ErrorCategory::ResultUnknown)?;
        if let Some(existing) = owners.iter().find(|existing| &existing.owner == owner) {
            let config = self.config(existing);
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
        let owned = OwnerDirectories {
            owner: owner.clone(),
            root,
            workspace,
            home,
        };
        owned.root.revalidate().map_err(map_directory)?;
        owned.workspace.revalidate().map_err(map_directory)?;
        owned.home.revalidate().map_err(map_directory)?;
        self.validate_source()?;
        let config = self.config(&owned);
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
