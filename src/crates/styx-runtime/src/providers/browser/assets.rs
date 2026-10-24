//! Fixed assets of this Rust image, NOT members signed by the legacy publisher.
//! The trusted bootstrap must independently verify/pin the complete dependency
//! release and retain/revalidate it through actual Host/worker quiescence. This
//! adapter establishes staging identity only; a pathname never establishes trust.
use super::BrowserError;
use crate::store::{PrivateRoot, RawFile, RootIdentity};
use nix::{
    fcntl::{OFlag, openat, readlinkat},
    sys::stat::{Mode, mkdirat},
    unistd::symlinkat,
};
use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    io::Write,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};

type Result<T> = std::result::Result<T, BrowserError>;
const WORKER: &[u8] = include_bytes!("../../../../../providers/browser-worker/worker.mjs");
const CONFIG: &[u8] = include_bytes!("../../../../../providers/browser-worker/config.mjs");
const ASSET_LIMIT: usize = 1024 * 1024;

/// No Clone/Deserialize, no automatic deletion on Drop: the caller must keep
/// this guard AND the verified dependency release until native cleanup/reap.
/// Failed preparations leave their fresh private namespace for explicit diagnosis.
pub(crate) struct PreparedBrowserAssets {
    parent_path: PathBuf,
    parent_root: PrivateRoot,
    parent_directory: File,
    stage_path: PathBuf,
    stage_root: PrivateRoot,
    stage_directory: File,
    dependency_path: PathBuf,
    dependency_root: PrivateRoot,
    dependency_directory: File,
    worker: RawFile,
    config: RawFile,
    entry: PathBuf,
}
impl PreparedBrowserAssets {
    pub(crate) fn entry_path(&self) -> &Path {
        &self.entry
    }
    /// Also revalidate the caller's verified release inventory before dispatch;
    /// this method intentionally does not mint signature or closure authority.
    pub(crate) fn revalidate(&self) -> Result<()> {
        checked_root(&self.parent_path, &self.parent_root, &self.parent_directory)?;
        checked_root(&self.stage_path, &self.stage_root, &self.stage_directory)?;
        checked_root(
            &self.dependency_path,
            &self.dependency_root,
            &self.dependency_directory,
        )?;
        for (original, expected) in [(&self.worker, WORKER), (&self.config, CONFIG)] {
            let current = self
                .stage_root
                .read_raw(original.relative_path(), ASSET_LIMIT)
                .map_err(|_| BrowserError::PermissionDenied)?;
            if current.bytes() != expected || current.observation() != original.observation() {
                return Err(BrowserError::PermissionDenied);
            }
        }
        let link = readlinkat(&self.stage_directory, "node_modules")
            .map_err(|_| BrowserError::PermissionDenied)?;
        if Path::new(&link) != self.dependency_path {
            return Err(BrowserError::PermissionDenied);
        }
        // The one deliberate dependency link is not accepted as a manifest
        // member. Its exact target is an independently verified original tree.
        let pinned = PathBuf::from(format!(
            "/proc/self/fd/{}",
            self.stage_directory.as_raw_fd()
        ));
        let metadata = std::fs::symlink_metadata(pinned.join("node_modules"))
            .map_err(|_| BrowserError::PermissionDenied)?;
        if !metadata.file_type().is_symlink()
            || metadata.uid() != nix::unistd::Uid::current().as_raw()
            || metadata.nlink() != 1
        {
            return Err(BrowserError::PermissionDenied);
        }
        let mut entries = BTreeSet::new();
        for entry in std::fs::read_dir(&pinned).map_err(|_| BrowserError::PermissionDenied)? {
            if entries.len() >= 3 {
                return Err(BrowserError::PermissionDenied);
            }
            entries.insert(
                entry
                    .map_err(|_| BrowserError::PermissionDenied)?
                    .file_name(),
            );
        }
        let expected: BTreeSet<std::ffi::OsString> = BTreeSet::from([
            "worker.mjs".into(),
            "config.mjs".into(),
            "node_modules".into(),
        ]);
        if entries != expected {
            return Err(BrowserError::PermissionDenied);
        }
        checked_root(&self.stage_path, &self.stage_root, &self.stage_directory)?;
        checked_root(
            &self.dependency_path,
            &self.dependency_root,
            &self.dependency_directory,
        )
    }
}
fn checked_root(path: &Path, original: &PrivateRoot, directory: &File) -> Result<()> {
    let current = PrivateRoot::open(path).map_err(|_| BrowserError::PermissionDenied)?;
    let RootIdentity::Linux { device, inode, uid } = original.identity();
    let pinned = directory
        .metadata()
        .map_err(|_| BrowserError::PermissionDenied)?;
    if current.identity() != original.identity()
        || pinned.dev() != device
        || pinned.ino() != inode
        || pinned.uid() != uid
        || !pinned.is_dir()
        || pinned.mode() & 0o077 != 0
    {
        return Err(BrowserError::PermissionDenied);
    }
    Ok(())
}
fn directory(path: &Path) -> Result<(PrivateRoot, File)> {
    if !path.is_absolute()
        || path.as_os_str().len() > 4096
        || std::fs::canonicalize(path).map_err(|_| BrowserError::PermissionDenied)? != path
    {
        return Err(BrowserError::PermissionDenied);
    }
    let root = PrivateRoot::open(path).map_err(|_| BrowserError::PermissionDenied)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| BrowserError::PermissionDenied)?;
    checked_root(path, &root, &file)?;
    Ok((root, file))
}
fn create_asset(directory: &File, name: &str, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() > ASSET_LIMIT {
        return Err(BrowserError::InvalidRequest);
    }
    let fd = openat(
        directory,
        name,
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::S_IRUSR | Mode::S_IWUSR,
    )
    .map_err(|_| BrowserError::SpawnFailed)?;
    let mut file = File::from(fd);
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| BrowserError::SpawnFailed)
}
/// Synchronous filesystem work: call on the bounded bootstrap blocking worker.
/// `dependency_root` MUST come from the original verified inventory, never MCP,
/// environment, a fixture node_modules directory, or an unverified package path.
pub(crate) fn prepare(
    private_parent: &Path,
    dependency_root: &Path,
) -> Result<PreparedBrowserAssets> {
    let (parent_root, parent_directory) = directory(private_parent)?;
    let (dependency_root_guard, dependency_directory) = directory(dependency_root)?;
    let name = format!("styx-browser-assets-{}", uuid::Uuid::new_v4().simple());
    mkdirat(&parent_directory, name.as_str(), Mode::S_IRWXU)
        .map_err(|_| BrowserError::SpawnFailed)?;
    let stage_path = private_parent.join(&name);
    let fd = openat(
        &parent_directory,
        name.as_str(),
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| BrowserError::SpawnFailed)?;
    let stage_directory = File::from(fd);
    create_asset(&stage_directory, "worker.mjs", WORKER)?;
    create_asset(&stage_directory, "config.mjs", CONFIG)?;
    symlinkat(dependency_root, &stage_directory, "node_modules")
        .map_err(|_| BrowserError::SpawnFailed)?;
    stage_directory
        .sync_all()
        .and_then(|_| parent_directory.sync_all())
        .map_err(|_| BrowserError::SpawnFailed)?;
    let stage_root = PrivateRoot::open(&stage_path).map_err(|_| BrowserError::PermissionDenied)?;
    let worker = stage_root
        .read_raw("worker.mjs", ASSET_LIMIT)
        .map_err(|_| BrowserError::PermissionDenied)?;
    let config = stage_root
        .read_raw("config.mjs", ASSET_LIMIT)
        .map_err(|_| BrowserError::PermissionDenied)?;
    let prepared = PreparedBrowserAssets {
        parent_path: private_parent.into(),
        parent_root,
        parent_directory,
        stage_root,
        stage_directory,
        dependency_path: dependency_root.into(),
        dependency_root: dependency_root_guard,
        dependency_directory,
        worker,
        config,
        entry: stage_path.join("worker.mjs"),
        stage_path,
    };
    prepared.revalidate()?;
    Ok(prepared)
}

/// Fresh runtime-only directory. No adoption, recursive chmod, or deletion of
/// existing profiles. Its descriptor and original identity remain pinned.
pub(crate) struct PrivateDirectory {
    path: PathBuf,
    root: PrivateRoot,
    descriptor: File,
    parent_path: PathBuf,
    parent: PrivateRoot,
    parent_descriptor: File,
}
impl PrivateDirectory {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
    pub(crate) fn revalidate(&self) -> Result<()> {
        checked_root(&self.parent_path, &self.parent, &self.parent_descriptor)?;
        checked_root(&self.path, &self.root, &self.descriptor)
    }
}
/// Called only from the trusted blocking bootstrap; the caller supplies a
/// protected local parent, never a remote pathname. Failed new directories are
/// retained for explicit diagnosis rather than deleting possibly live assets.
pub(crate) fn fresh_private_directory(parent: &Path) -> Result<PrivateDirectory> {
    let (parent_root, parent_descriptor) = directory(parent)?;
    let name = format!("styx-browser-{}", uuid::Uuid::new_v4().simple());
    mkdirat(&parent_descriptor, name.as_str(), Mode::S_IRWXU)
        .map_err(|_| BrowserError::SpawnFailed)?;
    let path = parent.join(name);
    let (root, descriptor) = directory(&path)?;
    parent_descriptor
        .sync_all()
        .map_err(|_| BrowserError::Unknown)?;
    let owned = PrivateDirectory {
        path,
        root,
        descriptor,
        parent_path: parent.to_path_buf(),
        parent: parent_root,
        parent_descriptor,
    };
    owned.revalidate()?;
    Ok(owned)
}
