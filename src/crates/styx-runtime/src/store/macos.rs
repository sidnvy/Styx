//! macOS protected roots, fixed private writes and distinct ownership resources.
//! OS file operations do not grant enrollment/migration/commit authority.
//! Extended ACLs are conservatively refused; original ACLs are never rewritten.
#[path = "macos_ffi.rs"]
mod ffi;
#[path = "macos_payload.rs"]
mod payload_backend;
use super::*;
use nix::{
    fcntl::{OFlag, openat},
    sys::stat::Mode,
    unistd::geteuid,
};
pub(crate) use payload_backend::signed_app::{SignedAppMember, SignedAppMembers};
pub(in crate::store) use payload_backend::{PayloadSnapshot, PinnedImage};
use std::{
    ffi::{OsStr, OsString},
    fs::{File, Metadata, TryLockError},
    io::{Read, Write},
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
fn private_descriptor(file: &File) -> Result<Metadata> {
    let metadata = file.metadata()?;
    private(&metadata)?;
    ffi::require_empty_acl(file)?;
    Ok(metadata)
}
fn private_file(file: &File) -> Result<Metadata> {
    let metadata = private_descriptor(file)?;
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
    RootIdentity::Macos {
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
    private_descriptor(&directory)?;
    Ok(directory)
}

/// Post-mkdir failures preserve creation provenance and the original child
/// whenever it was opened. No deletion, adoption or retry is performed here.
pub(super) struct FreshChildError {
    pub(super) cause: StoreError,
    pub(super) created: bool,
    pub(super) root: Option<Root>,
}
fn single_component(name: &OsStr) -> Result<()> {
    let raw = name.as_encoded_bytes();
    if raw.is_empty() || raw.len() > 255 || raw.contains(&0) || raw.contains(&b'/') {
        return Err(StoreError::InvalidRelativePath);
    }
    let mut parts = Path::new(name).components();
    if !matches!(parts.next(), Some(Component::Normal(_))) || parts.next().is_some() {
        return Err(StoreError::InvalidRelativePath);
    }
    Ok(())
}
pub(in crate::store) fn journal_component(name: &str) -> Result<()> {
    single_component(OsStr::new(name))
}
pub(in crate::store) fn journal_private_file(file: &File) -> Result<Metadata> {
    let metadata = private_file(file)?;
    if metadata.mode() & 0o7777 != 0o600 {
        return Err(StoreError::NotPrivate);
    }
    Ok(metadata)
}
pub(in crate::store) fn journal_private_directory(file: &File) -> Result<Metadata> {
    let metadata = private_descriptor(file)?;
    if !metadata.is_dir() || metadata.mode() & 0o7777 != 0o700 {
        return Err(StoreError::NotPrivate);
    }
    Ok(metadata)
}
/// Darwin fsync followed by the existing mature nix F_FULLFSYNC wrapper. No
/// fallback on EINVAL/unsupported filesystems or a failed physical flush request.
/// Success is the OS result, not a simulated power-loss acceptance claim.
pub(in crate::store) fn sync_private_file(file: &File) -> Result<()> {
    journal_private_file(file)?;
    sync_descriptor(file)
}
pub(in crate::store) fn sync_private_directory(file: &File) -> Result<()> {
    journal_private_directory(file)?;
    sync_descriptor(file)
}
fn sync_descriptor(file: &File) -> Result<()> {
    file.sync_all()?;
    nix::fcntl::fcntl(file, nix::fcntl::FcntlArg::F_FULLFSYNC)
        .map_err(|e| StoreError::Io(std::io::Error::from_raw_os_error(e as i32)))?;
    Ok(())
}
pub(in crate::store) fn rename_exclusive(
    source: &File,
    source_name: &str,
    destination: &File,
    destination_name: &str,
) -> Result<()> {
    journal_component(source_name)?;
    journal_component(destination_name)?;
    ffi::rename_exclusive(source, source_name, destination, destination_name)
}
impl Root {
    pub(super) fn create_fresh_child(
        &self,
        name: &OsStr,
    ) -> std::result::Result<Self, FreshChildError> {
        let mut created = false;
        let mut retained = None;
        let result = (|| {
            single_component(name)?;
            self.validate_root()?;
            journal_private_directory(&self.directory)?;
            nix::sys::stat::mkdirat(&*self.directory, name, Mode::S_IRWXU)
                .map_err(|e| StoreError::Io(std::io::Error::from_raw_os_error(e as i32)))?;
            created = true;
            let directory = open_at(
                &self.directory,
                name,
                OFlag::O_RDONLY | OFlag::O_DIRECTORY,
                Mode::empty(),
            )?;
            let metadata = directory.metadata()?;
            let child = Self {
                directory: Arc::new(directory),
                path: self.path.join(name),
                identity: root_identity(&metadata),
            };
            retained = Some(child.clone());
            journal_private_directory(&child.directory)?;
            child.sync_directory()?;
            self.sync_directory()?;
            self.validate_root()?;
            child.validate_root()?;
            Ok(child)
        })();
        result.map_err(|cause| FreshChildError {
            cause,
            created,
            root: retained,
        })
    }
    pub(in crate::store) fn sync_directory(&self) -> Result<()> {
        self.validate_root()?;
        let before = journal_private_directory(&self.directory)?;
        let result = sync_private_directory(&self.directory);
        let after = journal_private_directory(&self.directory)?;
        if (before.dev(), before.ino()) != (after.dev(), after.ino()) {
            return Err(StoreError::Changed);
        }
        self.validate_root()?;
        result
    }
    pub(super) fn with_readonly_directory<T>(
        &self,
        operation: impl FnOnce(&File) -> Result<T>,
    ) -> Result<T> {
        self.validate_root()?;
        let result = operation(&self.directory);
        self.validate_root()?;
        result
    }
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
        journal_private_directory(&self.directory)?;
        let result = operation(&self.directory);
        self.validate_root()?;
        guard.validate()?;
        result
    }
    /// Same fixed CREATE_NEW failure model as Linux: partial final files remain
    /// unknown; they are not overwritten, adopted, deleted or automatically retried.
    pub(super) fn create_fixed(
        &self,
        guard: &ConfigurationWriterGuard,
        name: &str,
        bytes: &[u8],
        observer: &dyn Fn(&str),
    ) -> Result<()> {
        journal_component(name)?;
        if bytes.is_empty() || bytes.len() > 1024 * 1024 {
            return Err(StoreError::TooLarge);
        }
        self.with_configuration_writer_directory(guard, |directory| {
            let mut file = open_at(
                directory,
                OsStr::new(name),
                OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NONBLOCK,
                Mode::S_IRUSR | Mode::S_IWUSR,
            )?;
            let original = journal_private_file(&file)?;
            file.write_all(bytes)?;
            observer("write");
            sync_private_file(&file)?;
            observer("file_sync");
            sync_private_directory(directory)?;
            observer("directory_sync");
            let raw = self.read_raw(Path::new(name), bytes.len())?;
            if (raw.observation().device, raw.observation().inode)
                != (original.dev(), original.ino())
                || raw.bytes() != bytes
            {
                return Err(StoreError::Changed);
            }
            journal_private_file(&file)?;
            Ok(())
        })
    }
    pub(super) fn open(path: &Path) -> Result<Self> {
        let directory = open_root(path)?;
        let identity = root_identity(&directory.metadata()?);
        Ok(Self {
            directory: Arc::new(directory),
            path: path.to_path_buf(),
            identity,
        })
    }
    pub(super) fn identity(&self) -> RootIdentity {
        self.identity.clone()
    }
    pub(in crate::store) fn validate_root(&self) -> Result<()> {
        let current = open_root(&self.path)?;
        if root_identity(&current.metadata()?) != self.identity {
            return Err(StoreError::Changed);
        }
        private_descriptor(&self.directory).map(|_| ())
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
            private_descriptor(&directory)?;
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
        let changed = file.metadata()?;
        // An originally private file that is replaced/unlinked is a changed
        // observation, not a newly supplied invalid file. Detect this before
        // the regular-file nlink guard classifies the now-unlinked old fd.
        if changed.nlink() != before.nlink() || observation(&changed) != observation(&before) {
            return Err(StoreError::Changed);
        }
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
        self.lock(resource, true)
    }
    pub(super) fn try_existing_lock(&self, resource: LockResource) -> Result<Lock> {
        self.lock(resource, false)
    }
    fn lock(&self, resource: LockResource, create: bool) -> Result<Lock> {
        self.validate_root()?;
        let file = open_at(
            &self.directory,
            OsStr::new(resource.filename()),
            OFlag::O_RDWR
                | OFlag::O_NONBLOCK
                | if create {
                    OFlag::O_CREAT
                } else {
                    OFlag::empty()
                },
            Mode::S_IRUSR | Mode::S_IWUSR,
        )?;
        private_file(&file)?;
        // Rust File::try_lock provides the platform nonblocking exclusive lock. Only this
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
    Ok(hex::encode(bytes))
}
pub(super) fn process_identity(pid: u32) -> Result<ProcessIdentity> {
    ffi::process_identity(pid)
}
pub(super) fn process_matches(identity: &ProcessIdentity) -> Result<bool> {
    let ProcessIdentity::Macos {
        boot_session_id,
        pid,
        start_seconds,
        start_microseconds,
        uid,
    } = identity
    else {
        return Err(StoreError::ProcessIdentityUnavailable);
    };
    let Some(current) = ffi::process_identity_optional(*pid)? else {
        // This Option is produced only by actual proc_pidinfo ESRCH, never a
        // sysctl/permission/decoding failure or a PID-existence heuristic.
        return Ok(false);
    };
    let ProcessIdentity::Macos {
        boot_session_id: actual_boot,
        start_seconds: actual_seconds,
        start_microseconds: actual_microseconds,
        uid: actual_uid,
        ..
    } = current
    else {
        return Err(StoreError::ProcessIdentityUnavailable);
    };
    if actual_boot != *boot_session_id
        || actual_seconds != *start_seconds
        || actual_microseconds != *start_microseconds
    {
        return Ok(false);
    }
    if actual_uid != *uid {
        return Err(StoreError::Changed);
    }
    Ok(true)
}
#[cfg(test)]
#[path = "macos_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "macos_publication_tests.rs"]
mod publication_tests;

#[path = "macos_legacy.rs"]
mod legacy_effect;
pub(crate) use legacy_effect::MacRetiredMaterialSource;
pub(in crate::store) use legacy_effect::MacTokenRetirement;

#[path = "macos_previous_boot.rs"]
mod previous_boot;
pub(in crate::store) use previous_boot::{MacBootRecoveryEffects, MacPreviousBootInput};

#[path = "macos_legacy_restart.rs"]
mod legacy_restart;

#[path = "macos_native_cutover.rs"]
mod native_cutover;
pub(in crate::store) use native_cutover::MacCutoverPlan;
pub(crate) use native_cutover::{MacCanonicalCutover, NativeCommittedCutover};

#[path = "macos_migration_owner.rs"]
mod migration_owner;
pub(in crate::store) use migration_owner::{
    MacMigrationCommittedScope, MacMigrationObservation, MacMigrationOwnerTask,
    MacMigrationRejectedScope, MacResumedCutover, start_previous_boot_host_migration,
    start_resume_pre_cutover_host_migration, start_resume_validated_host_migration,
};
