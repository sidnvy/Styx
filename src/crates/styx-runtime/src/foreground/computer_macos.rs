//! Fixed App-owned Mac Computer bootstrap; no C08 standalone Cua or browser authority.
use super::{ForegroundError, profile::LoadedLegacyProfile};
use crate::{
    host::{coordinator::DesktopSource, protocol::computer::ComputerBootstrap},
    providers::cua::{OwnedCuaConfig, TrustedCuaLaunch},
    store::PrivateRoot,
};
use std::{
    fs::{File, OpenOptions},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use styx_contracts::{error::ErrorCategory, session::SessionBinding};
use styx_core::operations::OwnerLease;
type Result<T> = std::result::Result<T, ErrorCategory>;
struct Directory {
    path: PathBuf,
    root: PrivateRoot,
    parent: PathBuf,
    parent_root: PrivateRoot,
    _parent_fd: File,
}
impl Directory {
    fn fresh(parent: &Path) -> Result<Self> {
        let parent_root = PrivateRoot::open(parent).map_err(|_| ErrorCategory::IntegrityFailure)?;
        let parent_fd = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(parent)
            .map_err(|_| ErrorCategory::IntegrityFailure)?;
        use std::os::unix::fs::MetadataExt;
        let md = parent_fd
            .metadata()
            .map_err(|_| ErrorCategory::IntegrityFailure)?;
        if parent_root.identity()
            != (crate::store::RootIdentity::Macos {
                device: md.dev(),
                inode: md.ino(),
                uid: md.uid(),
            })
        {
            return Err(ErrorCategory::IntegrityFailure);
        }
        let name = format!(".styx-computer-{}", uuid::Uuid::new_v4().simple());
        nix::sys::stat::mkdirat(
            &parent_fd,
            name.as_str(),
            nix::sys::stat::Mode::from_bits_truncate(0o700),
        )
        .map_err(|_| ErrorCategory::IntegrityFailure)?;
        let path = parent.join(name);
        let root = PrivateRoot::open(&path).map_err(|_| ErrorCategory::IntegrityFailure)?;
        let value = Self {
            path,
            root,
            parent: parent.to_owned(),
            parent_root,
            _parent_fd: parent_fd,
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<()> {
        if PrivateRoot::open(&self.path)
            .map_err(|_| ErrorCategory::IntegrityFailure)?
            .identity()
            != self.root.identity()
            || PrivateRoot::open(&self.parent)
                .map_err(|_| ErrorCategory::IntegrityFailure)?
                .identity()
                != self.parent_root.identity()
        {
            return Err(ErrorCategory::IntegrityFailure);
        }
        Ok(())
    }
}
struct OwnerDirectories {
    owner: OwnerLease,
    root: Directory,
    workspace: Directory,
    home: Directory,
}
struct LocalComputer {
    profile: Arc<LoadedLegacyProfile>,
    source: DesktopSource,
    epoch: u64,
    binding: SessionBinding,
    runtime: Directory,
    owners: Mutex<Vec<OwnerDirectories>>,
}
pub(crate) fn prepare_computer_bootstrap(
    profile: Arc<LoadedLegacyProfile>,
    source: DesktopSource,
    binding: SessionBinding,
) -> std::result::Result<Option<Arc<dyn ComputerBootstrap>>, ForegroundError> {
    if !profile.computer_enabled()? {
        return Ok(None);
    }
    let epoch = source.epoch();
    if source.fenced() {
        return Err(ForegroundError("desktop_source_fenced"));
    }
    let runtime = Directory::fresh(profile.host_base_dir())
        .map_err(|_| ForegroundError("computer_private_root_failed"))?;
    let factory = LocalComputer {
        profile,
        source,
        epoch,
        binding,
        runtime,
        owners: Mutex::new(Vec::new()),
    };
    factory
        .validate_before_spawn()
        .map_err(|_| ForegroundError("computer_bootstrap_changed"))?;
    Ok(Some(Arc::new(factory)))
}
impl LocalComputer {
    fn validate(&self, full: bool) -> Result<()> {
        if self.source.fenced() || self.source.epoch() != self.epoch {
            return Err(ErrorCategory::SessionDisconnected);
        }
        if full {
            self.profile.revalidate()
        } else {
            self.profile.revalidate_control()
        }
        .map_err(|_| ErrorCategory::IntegrityFailure)?;
        self.runtime.validate()?;
        for owner in self
            .owners
            .lock()
            .map_err(|_| ErrorCategory::ResultUnknown)?
            .iter()
        {
            owner.root.validate()?;
            owner.workspace.validate()?;
            owner.home.validate()?;
        }
        if self.source.fenced() || self.source.epoch() != self.epoch {
            return Err(ErrorCategory::SessionDisconnected);
        }
        Ok(())
    }
    fn config(&self, owner: &OwnerDirectories) -> Result<OwnedCuaConfig> {
        let source = self
            .source
            .proxy_source()
            .map_err(|_| ErrorCategory::SessionDisconnected)?;
        let launch = TrustedCuaLaunch::bind(
            self.binding.clone(),
            source,
            owner.workspace.path.clone(),
            owner.home.path.clone(),
        )
        .map_err(|_| ErrorCategory::IntegrityFailure)?;
        Ok(OwnedCuaConfig {
            launch,
            rpc_timeout: Duration::from_secs(10),
            workspace: owner.workspace.path.clone(),
            home: owner.home.path.clone(),
        })
    }
}
impl ComputerBootstrap for LocalComputer {
    fn prepare_profile(&self, owner: &OwnerLease) -> Result<OwnedCuaConfig> {
        self.validate(true)?;
        let mut owners = self
            .owners
            .lock()
            .map_err(|_| ErrorCategory::ResultUnknown)?;
        if let Some(old) = owners.iter().find(|old| &old.owner == owner) {
            return self.config(old);
        }
        if owners
            .iter()
            .any(|old| old.owner.owner_id() == owner.owner_id())
        {
            return Err(ErrorCategory::Unauthorized);
        }
        if owners.len() >= 16 {
            return Err(ErrorCategory::Busy);
        }
        let root = Directory::fresh(&self.runtime.path)?;
        let workspace = Directory::fresh(&root.path)?;
        let home = Directory::fresh(&root.path)?;
        let owned = OwnerDirectories {
            owner: owner.clone(),
            root,
            workspace,
            home,
        };
        let config = self.config(&owned)?;
        owners.push(owned);
        Ok(config)
    }
    fn validate_before_spawn(&self) -> Result<()> {
        self.validate(true)
    }
    fn validate_control(&self) -> Result<()> {
        self.validate(false)
    }
}
