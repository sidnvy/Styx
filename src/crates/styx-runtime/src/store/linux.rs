//! Linux-only primitives composed from nix owned descriptors, standard-library
//! file locks and getrandom. No environment or PID-only ownership fallback.
use super::*;
use nix::{
    fcntl::{OFlag, openat},
    sys::stat::Mode,
    unistd::geteuid,
};
use std::{
    ffi::{OsStr, OsString},
    fs::{File, Metadata, TryLockError},
    io::Read,
    os::unix::fs::MetadataExt,
    sync::Arc,
};

#[derive(Clone)]
pub(super) struct Root {
    directory: Arc<File>,
    path: PathBuf,
    identity: RootIdentity,
}

fn open_at(parent: &File, name: &OsStr, flags: OFlag, mode: Mode) -> Result<File> {
    // nix owns the newly opened descriptor; File::from(OwnedFd) preserves it
    // without handwritten raw-descriptor lifetime or conversion code.
    openat(
        parent,
        name,
        flags | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        mode,
    )
    .map(File::from)
    .map_err(|error| StoreError::Io(std::io::Error::from_raw_os_error(error as i32)))
}
fn current_uid() -> u32 {
    geteuid().as_raw()
}
fn private(metadata: &Metadata) -> Result<()> {
    if metadata.uid() != current_uid() || metadata.mode() & 0o7077 != 0 {
        return Err(StoreError::NotPrivate);
    }
    Ok(())
}
fn private_file(file: &File) -> Result<Metadata> {
    let metadata = file.metadata()?;
    private(&metadata)?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(StoreError::NotRegularFile);
    }
    Ok(metadata)
}
fn observation(metadata: &Metadata) -> FileObservation {
    FileObservation {
        device: metadata.dev(),
        inode: metadata.ino(),
        byte_len: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}
fn root_identity(metadata: &Metadata) -> RootIdentity {
    RootIdentity::Linux {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
    }
}
fn open_root(path: &Path) -> Result<File> {
    if !path.is_absolute()
        || !path
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
    {
        return Err(StoreError::InvalidRoot);
    }
    // The filesystem root is the only trusted absolute anchor; all remaining
    // components, including ancestors of the private directory, reject symlinks.
    let mut directory = File::open("/")?;
    for component in path.components() {
        if let Component::Normal(name) = component {
            directory = open_at(
                &directory,
                name,
                OFlag::O_RDONLY | OFlag::O_DIRECTORY,
                Mode::empty(),
            )?;
        }
    }
    private(&directory.metadata()?)?;
    Ok(directory)
}

impl Root {
    pub(super) fn open(path: &Path) -> Result<Self> {
        let directory = open_root(path)?;
        let identity = root_identity(&directory.metadata()?);
        Ok(Self {
            directory: Arc::new(directory),
            path: path.to_path_buf(),
            identity,
        })
    }
    /// Store-internal mutation port. No descriptor or path is exposed through
    /// the public store API; configuration and execution ownership stay distinct.
    pub(super) fn with_configuration_writer_directory<T>(
        &self,
        guard: &ConfigurationWriterGuard,
        operation: impl FnOnce(&File) -> Result<T>,
    ) -> Result<T> {
        if guard.identity().resource != LockResource::ConfigurationWriter
            || guard.identity().root != self.identity()
            || guard.identity().process != ProcessIdentity::current()?
        {
            return Err(StoreError::Changed);
        }
        self.validate_root()?;
        guard.validate()?;
        let result = operation(&self.directory);
        // Validate even after an operation returned an error. A replaced root or
        // ownership resource cannot become a successful persistence receipt.
        self.validate_root()?;
        guard.validate()?;
        result
    }
    pub(super) fn identity(&self) -> RootIdentity {
        self.identity.clone()
    }
    fn validate_root(&self) -> Result<()> {
        let current = open_root(&self.path)?;
        if root_identity(&current.metadata()?) != self.identity {
            return Err(StoreError::Changed);
        }
        private(&self.directory.metadata()?)
    }
    fn parent(&self, relative: &Path) -> Result<(File, OsString)> {
        let relative = checked_relative(relative)?;
        let mut directory = self.directory.try_clone()?;
        let mut components = relative.components().peekable();
        while let Some(Component::Normal(name)) = components.next() {
            if components.peek().is_none() {
                return Ok((directory, name.to_os_string()));
            }
            directory = open_at(
                &directory,
                name,
                OFlag::O_RDONLY | OFlag::O_DIRECTORY,
                Mode::empty(),
            )?;
            private(&directory.metadata()?)?;
        }
        Err(StoreError::InvalidRelativePath)
    }
    pub(super) fn ensure_absent(&self, relative: &Path) -> Result<()> {
        self.validate_root()?;
        let absent = match self.parent(relative) {
            Ok((parent, name)) => match nix::sys::stat::fstatat(
                &parent,
                name.as_os_str(),
                nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
            ) {
                Err(nix::errno::Errno::ENOENT) => true,
                Ok(_) => false,
                Err(error) => {
                    return Err(StoreError::Io(std::io::Error::from_raw_os_error(
                        error as i32,
                    )));
                }
            },
            Err(StoreError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => true,
            Err(error) => return Err(error),
        };
        self.validate_root()?;
        if absent {
            Ok(())
        } else {
            Err(StoreError::Changed)
        }
    }
    pub(super) fn read_raw(&self, relative: &Path, max_bytes: usize) -> Result<RawFile> {
        self.read_raw_observing(relative, max_bytes, || Ok(()))
    }
    fn read_raw_observing<F: FnOnce() -> Result<()>>(
        &self,
        relative: &Path,
        max_bytes: usize,
        after_read: F,
    ) -> Result<RawFile> {
        self.validate_root()?;
        let (directory, name) = self.parent(relative)?;
        let mut file = open_at(
            &directory,
            name.as_os_str(),
            OFlag::O_RDONLY | OFlag::O_NONBLOCK,
            Mode::empty(),
        )?;
        let before = private_file(&file)?;
        if before.len() > max_bytes as u64 {
            return Err(StoreError::TooLarge);
        }
        let mut bytes = Vec::new();
        // Read max+1 even if a concurrent writer grows the file after fstat.
        (&mut file)
            .take((max_bytes as u64).saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() > max_bytes {
            return Err(StoreError::TooLarge);
        }
        after_read()?;
        let after = private_file(&file)?;
        let current = open_at(
            &directory,
            name.as_os_str(),
            OFlag::O_RDONLY | OFlag::O_NONBLOCK,
            Mode::empty(),
        )?;
        if observation(&before) != observation(&after)
            || observation(&after) != observation(&private_file(&current)?)
            || bytes.len() as u64 != after.len()
        {
            return Err(StoreError::Changed);
        }
        // Re-walk the root-relative name to detect an intermediate directory swap.
        let (rechecked_parent, rechecked_name) = self.parent(relative)?;
        let rechecked = open_at(
            &rechecked_parent,
            rechecked_name.as_os_str(),
            OFlag::O_RDONLY | OFlag::O_NONBLOCK,
            Mode::empty(),
        )?;
        if observation(&after) != observation(&private_file(&rechecked)?) {
            return Err(StoreError::Changed);
        }
        self.validate_root()?;
        Ok(RawFile {
            relative_path: relative.to_path_buf(),
            sha256: sha256(&bytes),
            bytes,
            observation: observation(&after),
        })
    }
    #[cfg(test)]
    pub(super) fn read_raw_after_read_for_test<F: FnOnce() -> Result<()>>(
        &self,
        relative: &Path,
        max_bytes: usize,
        after_read: F,
    ) -> Result<RawFile> {
        self.read_raw_observing(relative, max_bytes, after_read)
    }
    pub(super) fn try_lock(&self, resource: LockResource) -> Result<Lock> {
        self.validate_root()?;
        let file = open_at(
            &self.directory,
            OsStr::new(resource.filename()),
            OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_NONBLOCK,
            Mode::S_IRUSR | Mode::S_IWUSR,
        )?;
        private_file(&file)?;
        // Rust 1.94.1 uses nonblocking exclusive flock on Linux. Only this
        // owned handle is locked; it is never cloned or explicitly unlocked.
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(StoreError::Busy(resource)),
            Err(TryLockError::Error(error)) => return Err(error.into()),
        }
        let lock = Lock {
            file,
            root: self.clone(),
            identity: LeaseIdentity {
                resource,
                root: self.identity(),
                process: process_identity(std::process::id())?,
                owner_generation: random_generation()?,
            },
        };
        lock.validate()?;
        Ok(lock)
    }
}

pub(super) struct Lock {
    file: File,
    root: Root,
    identity: LeaseIdentity,
}
impl Lock {
    pub(super) fn identity(&self) -> &LeaseIdentity {
        &self.identity
    }
    pub(super) fn validate(&self) -> Result<()> {
        self.root.validate_root()?;
        if process_identity(std::process::id())? != self.identity.process
            || !process_matches(&self.identity.process)?
        {
            return Err(StoreError::Changed);
        }
        let held = private_file(&self.file)?;
        let current = open_at(
            &self.root.directory,
            OsStr::new(self.identity.resource.filename()),
            OFlag::O_RDONLY | OFlag::O_NONBLOCK,
            Mode::empty(),
        )?;
        let current = private_file(&current)?;
        if held.dev() != current.dev() || held.ino() != current.ino() {
            return Err(StoreError::Changed);
        }
        Ok(())
    }
}
// No unlink and no explicit LOCK_UN: closing this unique CLOEXEC file description
// releases the lock without creating a second lock namespace for other waiters.

fn random_generation() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| StoreError::EntropyUnavailable)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
fn boot_id() -> Result<String> {
    let text = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let value = text.trim();
    if value.len() != 36
        || !value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
    {
        return Err(StoreError::ProcessIdentityUnavailable);
    }
    Ok(value.to_string())
}
fn start_ticks(text: &str, pid: u32) -> Result<u64> {
    let (prefix, fields) = text
        .rsplit_once(')')
        .ok_or(StoreError::ProcessIdentityUnavailable)?;
    if prefix
        .split_whitespace()
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        != Some(pid)
    {
        return Err(StoreError::ProcessIdentityUnavailable);
    }
    fields
        .split_whitespace()
        .nth(19)
        .and_then(|v| v.parse().ok())
        .ok_or(StoreError::ProcessIdentityUnavailable)
}
pub(super) fn process_identity(pid: u32) -> Result<ProcessIdentity> {
    if pid == 0 {
        return Err(StoreError::ProcessIdentityUnavailable);
    }
    let boot = boot_id()?;
    let path = format!("/proc/{pid}/stat");
    let first = start_ticks(&std::fs::read_to_string(&path)?, pid)?;
    let second = start_ticks(&std::fs::read_to_string(&path)?, pid)?;
    if first != second || boot != boot_id()? {
        return Err(StoreError::Changed);
    }
    Ok(ProcessIdentity::Linux {
        boot_id: boot,
        pid,
        start_ticks: first,
    })
}
pub(super) fn process_matches(identity: &ProcessIdentity) -> Result<bool> {
    let ProcessIdentity::Linux { pid, .. } = identity;
    match process_identity(*pid) {
        Ok(current) => Ok(&current == identity),
        Err(StoreError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

#[path = "linux_payload.rs"]
mod payload;
pub(super) use payload::{PayloadSnapshot, PinnedImage};
