//! Windows protected existing roots and distinct native file-lock resources.
//! Retained ancestor handles omit delete sharing; regular input handles also
//! omit write sharing. Fixed writes use local NTFS write-through/file flush;
//! directory flush uses a separately opened, identity-checked writable handle.
//! No ACL rewrite or path launch fallback.
#[path = "windows_original_app.rs"]
mod original_app;
pub(in crate::store) use original_app::WindowsOriginalApp;
#[path = "windows_migration.rs"]
mod migration;
#[path = "windows_native_cutover.rs"]
mod native_cutover;
pub(crate) use native_cutover::{NativeCommittedCutover, WindowsCanonicalCutover};
pub(in crate::store) use native_cutover::{WindowsCutoverCustody, WindowsCutoverPlan};
#[path = "windows_previous_boot.rs"]
mod previous_boot;
pub(in crate::store) use migration::{WindowsOriginalMaterials, WindowsTokenRetirement};
pub(in crate::store) use previous_boot::{
    WindowsBootRecoveryEffects, WindowsCheckpointResumeFailure, WindowsCheckpointRetainedScope,
    WindowsLegacyMaintenancePlan, WindowsMigrationCheckpointJob, WindowsMigrationCheckpointPlan,
    WindowsMigrationCheckpointResume, WindowsMigrationRecoveredGuards,
    WindowsMigrationWaitingForBoot, WindowsPreviousBootEvidence, WindowsRecoveryOpenFailure,
    WindowsRestartCheckpoint, WindowsRestartMigrationReview, WindowsResumedCutover,
    resume_recorded_windows_checkpoint, review_windows_restart_host_migration,
    start_resume_validated_windows_host_migration, start_resume_windows_restart_host_migration,
    start_windows_restart_host_migration,
};
#[path = "windows_ffi.rs"]
mod ffi;
#[path = "windows_payload.rs"]
mod payload_backend;
use super::*;
pub(in crate::store) use payload_backend::{PayloadSnapshot, PinnedImage};
use std::{
    ffi::OsStr,
    fs::{File, TryLockError},
    io::{Read, Write},
    os::windows::ffi::OsStrExt,
    path::Prefix,
    sync::Arc,
};

#[derive(Clone)]
pub(super) struct Root {
    directory: Arc<File>,
    // Includes every actual drive-root-to-private-root ancestor. No delete-share
    // means a renamed ancestor cannot redirect a retained ordinary pathname.
    ancestors: Arc<Vec<File>>,
    path: PathBuf,
    identity: RootIdentity,
}
fn component(name: &OsStr) -> Result<()> {
    let text = name.to_str().ok_or(StoreError::InvalidRelativePath)?;
    let stem = text.split('.').next().unwrap_or("").to_ascii_uppercase();
    if text.is_empty()
        || text.ends_with(['.', ' '])
        || text.contains(['<', '>', ':', '"', '/', '\\', '|', '?', '*', '\0'])
        || text == "."
        || text == ".."
        || matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ["COM", "LPT"].iter().any(|prefix| {
            stem.strip_prefix(prefix)
                .is_some_and(|n| n.len() == 1 && matches!(n.as_bytes()[0], b'1'..=b'9'))
        })
    {
        return Err(StoreError::InvalidRelativePath);
    }
    Ok(())
}
fn normalized_root(path: &Path) -> Result<PathBuf> {
    let text = path.to_str().ok_or(StoreError::InvalidRoot)?;
    if text
        .split(['\\', '/'])
        .any(|part| matches!(part, "." | ".."))
    {
        return Err(StoreError::InvalidRoot);
    }
    let mut parts = path.components();
    let drive = match parts.next() {
        Some(Component::Prefix(p)) => match p.kind() {
            Prefix::Disk(d) => d,
            _ => return Err(StoreError::InvalidRoot),
        },
        _ => return Err(StoreError::InvalidRoot),
    };
    if !matches!(parts.next(), Some(Component::RootDir)) {
        return Err(StoreError::InvalidRoot);
    }
    let mut result = PathBuf::from(format!("{}:\\", char::from(drive.to_ascii_uppercase())));
    for p in parts {
        let Component::Normal(name) = p else {
            return Err(StoreError::InvalidRoot);
        };
        component(name)?;
        result.push(name);
    }
    Ok(result)
}
fn absolute_pins(path: &Path) -> Result<(PathBuf, Vec<File>)> {
    let normalized = normalized_root(path)?;
    let mut current = PathBuf::new();
    let mut pins = Vec::new();
    for p in normalized.components() {
        current.push(p.as_os_str());
        if matches!(p, Component::Prefix(_)) {
            continue;
        }
        pins.push(ffi::open(&current, true, false, false)?);
    }
    if pins.is_empty() {
        return Err(StoreError::InvalidRoot);
    }
    Ok((normalized, pins))
}
fn private_facts(file: &File, directory: bool) -> Result<ffi::Facts> {
    let facts = ffi::facts(file)?;
    if facts.directory != directory {
        return Err(StoreError::NotRegularFile);
    }
    ffi::private(file)?;
    Ok(facts)
}
fn root_identity(file: &File) -> Result<RootIdentity> {
    let facts = private_facts(file, true)?;
    Ok(RootIdentity::Windows {
        volume_serial: facts.observation.device,
        file_id: facts.observation.inode,
        owner_sid: ffi::private(file)?,
    })
}
pub(crate) fn file_identity(file: &File) -> Result<(u64, u64)> {
    let facts = ffi::facts(file)?;
    Ok((facts.observation.device, facts.observation.inode))
}
struct Opened {
    file: File,
    _parents: Vec<File>,
    path: PathBuf,
    relative: PathBuf,
}
/// A post-mkdir failure keeps the original child when it was successfully
/// opened, and always preserves whether this call actually created the name.
pub(super) struct FreshChildError {
    pub(super) cause: StoreError,
    pub(super) created: bool,
    pub(super) root: Option<Root>,
}
impl Root {
    /// Convert only an original protected directory HANDLE into its revalidated
    /// local path/ancestor pin chain. The supplied handle remains borrowed, and
    /// its private identity must match the independently opened path both ways.
    pub(in crate::store) fn from_directory_handle(directory: &File) -> Result<Self> {
        let identity = root_identity(directory)?;
        let path = ffi::final_path(directory)?;
        let root = Self::open(&path)?;
        if root.identity() != identity
            || root_identity(directory)? != identity
            || ffi::final_path(directory)? != path
        {
            return Err(StoreError::Changed);
        }
        ffi::require_local_ntfs(&root.path, directory)?;
        root.validate_root()?;
        Ok(root)
    }
    pub(in crate::store) fn validate_journal_name(name: &str) -> Result<()> {
        component(OsStr::new(name))?;
        if name.encode_utf16().count() > 255 {
            return Err(StoreError::InvalidRelativePath);
        }
        Ok(())
    }
    pub(in crate::store) fn journal_path(&self) -> &Path {
        &self.path
    }
    pub(in crate::store) fn journal_directory(&self, name: &str) -> Result<File> {
        component(OsStr::new(name))?;
        self.with_readonly_directory(|_| {
            let opened = self.open_relative(Path::new(name), true, false, false)?;
            private_facts(&opened.file, true)?;
            Ok(opened.file)
        })
    }
    pub(in crate::store) fn create_journal_directory(
        &self,
        name: &str,
        strict: bool,
    ) -> Result<File> {
        component(OsStr::new(name))?;
        self.with_readonly_directory(|_| {
            ffi::require_local_ntfs(&self.path, &self.directory)?;
            match ffi::create_new_private_directory(&self.path.join(name)) {
                Ok(()) => {}
                Err(StoreError::Io(e))
                    if !strict && e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
            self.journal_directory(name)
        })
    }
    pub(in crate::store) fn journal_file_identity(file: &File) -> Result<(u64, u64)> {
        private_facts(file, false)?;
        file_identity(file)
    }
    pub(in crate::store) fn new_journal_file(&self, name: &str) -> Result<File> {
        component(OsStr::new(name))?;
        self.with_readonly_directory(|_| {
            let path = self.path.join(name);
            let file = ffi::create_new_journal_file(&path)?;
            ffi::require_no_streams(&path)?;
            Ok(file)
        })
    }
    pub(in crate::store) fn rename_journal_file(
        &self,
        file: &File,
        name: &str,
        replace: bool,
    ) -> Result<()> {
        self.with_readonly_directory(|directory| {
            private_facts(file, false)?;
            let source = ffi::final_path(file)?;
            if source.parent() != Some(self.path.as_path()) {
                return Err(StoreError::Changed);
            }
            ffi::require_no_streams(&source)?;
            ffi::rename_journal_file(file, directory, name, replace)?;
            ffi::flush_file(file)
        })
    }
    /// Publish the already journaled C07 target under the SAME writer. The
    /// source namespace, original file ID and exact bytes are pinned separately;
    /// the canonical before observation is checked immediately before rename.
    /// This is cooperating-writer replacement, never hostile-writer kernel CAS.
    pub(in crate::store) fn replace_native_state_from_journal(
        &self,
        guard: &ConfigurationWriterGuard,
        source: (&File, &str),
        expected: &RawFile,
        target: &[u8],
        observer: &dyn Fn(&str),
    ) -> Result<()> {
        let (directory, temporary) = source;
        Self::validate_journal_name(temporary)?;
        if expected.relative_path != Path::new("state.json")
            || target.is_empty()
            || target.len() > 1024 * 1024
        {
            return Err(StoreError::Changed);
        }
        let source_root = Self::from_directory_handle(directory)?;
        if source_root.path != self.path.join(".styx-management-journal-v1") {
            return Err(StoreError::Changed);
        }
        self.with_configuration_writer_directory(guard, |destination| {
            source_root.with_readonly_directory(|_| {
                let observed = source_root.read_raw(Path::new(temporary), target.len())?;
                if observed.bytes() != target {
                    return Err(StoreError::Changed);
                }
                let source_path = source_root.path.join(temporary);
                let file = ffi::open_journal_for_rename(&source_path)?;
                let facts = private_facts(&file, false)?;
                ffi::require_no_streams(&source_path)?;
                if facts.observation != *observed.observation() {
                    return Err(StoreError::Changed);
                }
                let mut bytes = Vec::new();
                file.try_clone()?
                    .take(target.len() as u64 + 1)
                    .read_to_end(&mut bytes)?;
                if bytes != target
                    || private_facts(&file, false)? != facts
                    || ffi::final_path(&file)? != source_path
                {
                    return Err(StoreError::Changed);
                }
                let canonical = self.read_raw(Path::new("state.json"), 1024 * 1024)?;
                if canonical.observation() != expected.observation()
                    || canonical.bytes() != expected.bytes()
                {
                    return Err(StoreError::Changed);
                }
                // Both Root owners retain all directory/ancestor pins without
                // delete sharing. Source selection uses this actual HANDLE only.
                ffi::rename_journal_file(&file, destination, "state.json", true)?;
                observer("rename");
                ffi::flush_file(&file)?;
                observer("file_sync_after_rename");
                if Self::journal_file_identity(&file)?
                    != (facts.observation.device, facts.observation.inode)
                {
                    return Err(StoreError::Changed);
                }
                drop(file); // close write/delete access before protected reads
                let after = self.read_raw(Path::new("state.json"), target.len())?;
                if (after.observation().device, after.observation().inode)
                    != (facts.observation.device, facts.observation.inode)
                    || after.bytes() != target
                {
                    return Err(StoreError::Changed);
                }
                source_root.ensure_absent(Path::new(temporary))?;
                self.sync_directory()?;
                source_root.sync_directory()?;
                let final_state = self.read_raw(Path::new("state.json"), target.len())?;
                if after.observation() != final_state.observation() || final_state.bytes() != target
                {
                    return Err(StoreError::Changed);
                }
                Ok(())
            })
        })
    }
    pub(in crate::store) fn flush_journal_file(&self, file: &File) -> Result<()> {
        self.with_readonly_directory(|_| {
            private_facts(file, false)?;
            ffi::flush_file(file)
        })
    }
    /// Flush the exact original directory through a separately opened writable
    /// directory HANDLE. This is the tested ordinary Win32/NTFS operation, not a
    /// volume flush, privilege escalation, ACL change or power-loss proof.
    pub(in crate::store) fn sync_directory(&self) -> Result<()> {
        self.validate_root()?;
        let result = (|| {
            let directory = ffi::open(&self.path, true, true, false)?;
            if root_identity(&directory)? != self.identity() {
                return Err(StoreError::Changed);
            }
            ffi::require_local_ntfs(&self.path, &directory)?;
            let flushed = ffi::flush_file(&directory);
            // Recheck the original writable object even if flushing failed.
            if root_identity(&directory)? != self.identity() {
                return Err(StoreError::Changed);
            }
            flushed
        })();
        self.validate_root()?;
        result
    }
    pub(in crate::store) fn sync_journal_file(&self, name: &str) -> Result<()> {
        component(OsStr::new(name))?;
        self.with_readonly_directory(|_| {
            let opened = self.open_relative(Path::new(name), false, true, false)?;
            private_facts(&opened.file, false)?;
            ffi::require_no_streams(&opened.path)?;
            ffi::flush_file(&opened.file)
        })
    }
    pub(super) fn create_fresh_child(
        &self,
        name: &OsStr,
    ) -> std::result::Result<Self, FreshChildError> {
        let mut created = false;
        let mut retained = None;
        let result = (|| {
            component(name)?;
            if name.encode_wide().count() > 255 {
                return Err(StoreError::InvalidRelativePath);
            }
            self.validate_root()?;
            ffi::require_local_ntfs(&self.path, &self.directory)?;
            let path = self.path.join(name);
            ffi::create_new_private_directory(&path)?;
            created = true;
            let child = Self::open(&path)?;
            retained = Some(child.clone());
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
    /// Store-internal observation only. Retains the original ancestor/directory
    /// handles and rechecks the original path/identity even when the closure errs.
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
        let result = operation(&self.directory);
        self.validate_root()?;
        guard.validate()?;
        result
    }
    /// Fixed single-file CREATE_NEW under the original writer, following the
    /// Linux fixed-write failure model: partial final files remain Unknown and
    /// are never overwritten/adopted/repaired. No extra temporary-name protocol.
    ///
    /// Requires a local fixed NTFS volume. WRITE_THROUGH plus FlushFileBuffers
    /// uses the documented NTFS data/metadata flush semantics, subject to the
    /// storage device honoring flushes. The original parent directory is also
    /// actually flushed. This is not an atomic transaction or power-loss test.
    pub(super) fn create_fixed(
        &self,
        guard: &ConfigurationWriterGuard,
        name: &str,
        bytes: &[u8],
        observer: &dyn Fn(&str),
    ) -> Result<()> {
        self.with_configuration_writer_directory(guard, |_| {
            self.create_private_export(name, bytes, observer)
        })
    }
    // The bounded invitation exporter is the only writer-free caller; App
    // immutable inputs retain their original container writer. CREATE_NEW and flush
    // semantics are identical; failed or partial files are never replaced.
    pub(super) fn create_private_export(
        &self,
        name: &str,
        bytes: &[u8],
        observer: &dyn Fn(&str),
    ) -> Result<()> {
        component(OsStr::new(name))?;
        if name.encode_utf16().count() > 255 || bytes.is_empty() || bytes.len() > 1024 * 1024 {
            return Err(StoreError::TooLarge);
        }
        self.with_readonly_directory(|_| {
            ffi::require_local_ntfs(&self.path, &self.directory)?;
            let path = self.path.join(name);
            let mut file = ffi::create_new_private_file(&path)?;
            let original = private_facts(&file, false)?;
            ffi::require_no_streams(&path)?;
            file.write_all(bytes)?;
            observer("write");
            ffi::flush_file(&file)?;
            observer("file_sync");
            let written = private_facts(&file, false)?;
            if original.observation.device != written.observation.device
                || original.observation.inode != written.observation.inode
                || written.observation.byte_len != bytes.len() as u64
            {
                return Err(StoreError::Changed);
            }
            // Readers deny write sharing. Actual writer close must precede
            // reopen; retain file-ID/length instead of pre-close timestamps,
            // which Windows may finalize at the last writable-handle close.
            drop(file);
            let published = self.read_raw(Path::new(name), bytes.len())?;
            if published.observation().device != written.observation.device
                || published.observation().inode != written.observation.inode
                || published.observation().byte_len != written.observation.byte_len
                || published.bytes() != bytes
            {
                return Err(StoreError::Changed);
            }
            self.sync_directory()?;
            observer("directory_sync");
            let after = self.read_raw(Path::new(name), bytes.len())?;
            if after.observation() != published.observation() || after.bytes() != bytes {
                return Err(StoreError::Changed);
            }
            observer("publication_observed");
            Ok(())
        })
    }
    pub(super) fn open(path: &Path) -> Result<Self> {
        let (path, mut ancestors) = absolute_pins(path)?;
        let directory = ancestors.pop().ok_or(StoreError::InvalidRoot)?;
        let identity = root_identity(&directory)?;
        Ok(Self {
            directory: Arc::new(directory),
            ancestors: Arc::new(ancestors),
            path,
            identity,
        })
    }
    /// Runtime scratch only. Creation supplies its own owner/private inheritable
    /// DACL instead of relying on an elevated token's default Administrators owner.
    /// Existing objects are inspected as-is and never repaired or adopted by chmod.
    pub(crate) fn open_or_create_private_child(&self, name: &str) -> Result<Self> {
        component(OsStr::new(name))?;
        if name.encode_utf16().count() > 255 {
            return Err(StoreError::InvalidRelativePath);
        }
        self.validate_root()?;
        let path = self.path.join(name);
        // Retained parent/ancestor handles deny delete sharing throughout. The
        // Win32 creator only handles a checked single child, never a new tree.
        ffi::create_private_directory(&path)?;
        let child = Self::open(&path)?;
        self.validate_root()?;
        child.validate_root()?;
        Ok(child)
    }
    pub(super) fn identity(&self) -> RootIdentity {
        self.identity.clone()
    }
    pub(super) fn validate_root(&self) -> Result<()> {
        let (_, pins) = absolute_pins(&self.path)?;
        let current = pins.last().ok_or(StoreError::InvalidRoot)?;
        if root_identity(current)? != self.identity
            || root_identity(&self.directory)? != self.identity
        {
            return Err(StoreError::Changed);
        }
        // Keep the original chain alive across the validation call too.
        if self.ancestors.iter().any(|f| ffi::facts(f).is_err()) {
            return Err(StoreError::Changed);
        }
        Ok(())
    }
    fn open_relative(
        &self,
        relative: &Path,
        directory: bool,
        write: bool,
        create: bool,
    ) -> Result<Opened> {
        let raw = relative.to_str().ok_or(StoreError::InvalidRelativePath)?;
        if raw.ends_with(['\\', '/'])
            || raw
                .split(['\\', '/'])
                .any(|part| matches!(part, "." | ".."))
        {
            return Err(StoreError::InvalidRelativePath);
        }
        let relative = checked_relative(relative)?;
        let mut parents = Vec::new();
        let mut path = self.path.clone();
        let mut parts = relative.components().peekable();
        while let Some(Component::Normal(name)) = parts.next() {
            component(name)?;
            path.push(name);
            if parts.peek().is_none() {
                let file = ffi::open(&path, directory, write, create)?;
                return Ok(Opened {
                    file,
                    _parents: parents,
                    path,
                    relative: relative.clone(),
                });
            }
            let file = ffi::open(&path, true, false, false)?;
            private_facts(&file, true)?;
            parents.push(file);
        }
        Err(StoreError::InvalidRelativePath)
    }
    pub(super) fn ensure_absent(&self, relative: &Path) -> Result<()> {
        self.validate_root()?;
        let result = match self.open_relative(relative, false, false, false) {
            Err(StoreError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
            Ok(_) => Err(StoreError::Changed),
        };
        self.validate_root()?;
        result
    }
    pub(super) fn read_raw(&self, relative: &Path, max_bytes: usize) -> Result<RawFile> {
        self.validate_root()?;
        let opened = self.open_relative(relative, false, false, false)?;
        let before = private_facts(&opened.file, false)?;
        ffi::require_no_streams(&opened.path)?;
        if before.observation.byte_len > max_bytes as u64 {
            return Err(StoreError::TooLarge);
        }
        let mut bytes = Vec::new();
        opened
            .file
            .try_clone()?
            .take((max_bytes as u64).saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() > max_bytes {
            return Err(StoreError::TooLarge);
        }
        let after = private_facts(&opened.file, false)?;
        let current = self.open_relative(relative, false, false, false)?;
        if before != after
            || after != private_facts(&current.file, false)?
            || bytes.len() as u64 != after.observation.byte_len
        {
            return Err(StoreError::Changed);
        }
        self.validate_root()?;
        Ok(RawFile {
            relative_path: relative.to_owned(),
            sha256: sha256(&bytes),
            bytes,
            observation: after.observation,
        })
    }
    pub(super) fn try_lock(&self, resource: LockResource) -> Result<Lock> {
        self.lock(resource, true)
    }
    pub(super) fn try_existing_lock(&self, resource: LockResource) -> Result<Lock> {
        self.lock(resource, false)
    }
    fn lock(&self, resource: LockResource, create: bool) -> Result<Lock> {
        self.validate_root()?;
        let opened = self.open_relative(Path::new(resource.filename()), false, true, create)?;
        private_facts(&opened.file, false)?;
        ffi::require_no_streams(&opened.path)?;
        match opened.file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(StoreError::Busy(resource)),
            Err(TryLockError::Error(e)) => return Err(e.into()),
        }
        let mut generation = [0u8; 16];
        getrandom::fill(&mut generation).map_err(|_| StoreError::EntropyUnavailable)?;
        let lock = Lock {
            opened,
            root: self.clone(),
            identity: LeaseIdentity {
                resource,
                root: self.identity(),
                process: process_identity(std::process::id())?,
                owner_generation: hex::encode(generation),
            },
        };
        lock.validate()?;
        Ok(lock)
    }
}
pub(super) struct Lock {
    opened: Opened,
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
        // A shared RW observation of the lock is required because its original
        // handle owns write access. No second lock, unlock or deletion occurs.
        let current = self.root.open_relative(
            Path::new(self.identity.resource.filename()),
            false,
            true,
            false,
        )?;
        if file_identity(&current.file)? != file_identity(&self.opened.file)? {
            return Err(StoreError::Changed);
        }
        private_facts(&current.file, false)?;
        private_facts(&self.opened.file, false)?;
        Ok(())
    }
}
pub(super) fn process_identity(pid: u32) -> Result<ProcessIdentity> {
    ffi::process_optional(pid)?.ok_or(StoreError::ProcessIdentityUnavailable)
}
pub(super) fn process_matches(expected: &ProcessIdentity) -> Result<bool> {
    let ProcessIdentity::Windows {
        pid,
        creation_time_100ns,
        owner_sid,
    } = expected
    else {
        return Err(StoreError::ProcessIdentityUnavailable);
    };
    let Some(current) = ffi::process_optional(*pid)? else {
        return Ok(false);
    };
    let ProcessIdentity::Windows {
        creation_time_100ns: created,
        owner_sid: actual,
        ..
    } = current
    else {
        return Err(StoreError::ProcessIdentityUnavailable);
    };
    if created != *creation_time_100ns {
        return Ok(false);
    }
    if actual != *owner_sid {
        return Err(StoreError::Changed);
    }
    Ok(true)
}
#[cfg(test)]
#[path = "windows_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "windows_publication_tests.rs"]
mod publication_tests;

#[path = "windows_browser.rs"]
mod browser;
pub(crate) use browser::LocalExecutable as WindowsLocalExecutable;

#[path = "windows_restart_effects.rs"]
mod restart;

#[path = "release_stage_windows.rs"]
mod release_staging;

#[path = "app_runtime_inputs.rs"]
mod app_runtime_inputs;
