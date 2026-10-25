//! Store-private secure journal file primitives, extracted from enrollment.
//! No enrollment/management policy, commit authority, new writer acquisition or
//! recovery decision lives here. Callers retain their original namespace pin;
//! creating a namespace never proves a fresh profile or a stopped legacy owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum JournalError {
    #[error("enrollment journal unsupported on this platform")]
    Unsupported,
    #[error("invalid or over-budget journal input")]
    InvalidInput,
    #[error("immutable journal binding conflicts")]
    Conflict,
    #[error("journal observation or persistence outcome unknown")]
    Unknown,
    #[error("journal scan budget exceeded")]
    BudgetExceeded,
}
pub type JournalResult<T> = Result<T, JournalError>;

#[derive(Clone, Copy, Debug)]
pub struct JournalBudget {
    pub max_files: usize,
    pub max_bytes: usize,
    pub max_file_bytes: usize,
}
impl Default for JournalBudget {
    fn default() -> Self {
        Self {
            max_files: 4096,
            max_bytes: 64 * 1024 * 1024,
            max_file_bytes: 1024 * 1024,
        }
    }
}
impl JournalBudget {
    pub(super) fn valid(self) -> bool {
        self.max_files > 0
            && self.max_files <= 4096
            && self.max_bytes > 0
            && self.max_bytes <= 64 * 1024 * 1024
            && self.max_file_bytes > 0
            && self.max_file_bytes <= 1024 * 1024
            && self.max_file_bytes <= self.max_bytes
    }
}
/// Raw content is intentionally neither Debug nor Serialize.
pub struct ObservedJournalFile {
    pub name: String,
    pub(super) bytes: Vec<u8>,
}
impl ObservedJournalFile {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
/// Presence alone is not durability. Reconcile syncs the exact verified files;
/// only a verified commit marker is authoritative. Orphans remain observable.
pub struct JournalObservation {
    pub files: Vec<ObservedJournalFile>,
    pub total_bytes: usize,
}

#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "windows",
    target_os = "macos"
))]
use super::{ConfigurationWriterGuard, PrivateRoot};
#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "windows",
    target_os = "macos"
))]
#[derive(Clone, Copy)]
pub(super) enum NamespaceName {
    EnrollmentV1,
    ManagementV1,
}
#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "windows",
    target_os = "macos"
))]
impl NamespaceName {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::EnrollmentV1 => ".styx-enrollment-journal-v1",
            Self::ManagementV1 => ".styx-management-journal-v1",
        }
    }
}
#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub(super) mod files {
    use super::*;
    use nix::{
        dir::Dir,
        errno::Errno,
        fcntl::{OFlag, RenameFlags, openat, renameat2},
        sys::stat::{Mode, mkdirat},
        unistd::geteuid,
    };
    use std::{
        fs::File,
        io::{Read, Write},
        os::unix::fs::MetadataExt,
    };
    fn unknown<T>(_: T) -> JournalError {
        JournalError::Unknown
    }
    pub(in crate::store) fn directory(parent: &File, name: &str) -> JournalResult<File> {
        let f = File::from(
            openat(
                parent,
                name,
                OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(unknown)?,
        );
        let m = f.metadata().map_err(unknown)?;
        if !m.is_dir() || m.uid() != geteuid().as_raw() || m.mode() & 0o7777 != 0o700 {
            return Err(JournalError::Unknown);
        }
        Ok(f)
    }
    fn regular(file: &File) -> JournalResult<std::fs::Metadata> {
        let m = file.metadata().map_err(unknown)?;
        if !m.is_file()
            || m.uid() != geteuid().as_raw()
            || m.mode() & 0o7777 != 0o600
            || m.nlink() != 1
        {
            return Err(JournalError::Unknown);
        }
        Ok(m)
    }
    pub(in crate::store) fn read(
        dir: &File,
        name: &str,
        max: usize,
    ) -> JournalResult<Option<Vec<u8>>> {
        let fd = match openat(
            dir,
            name,
            OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        ) {
            Ok(f) => f,
            Err(Errno::ENOENT) => return Ok(None),
            Err(e) => return Err(unknown(e)),
        };
        let mut f = File::from(fd);
        let before = regular(&f)?;
        if before.len() > max as u64 {
            return Err(JournalError::BudgetExceeded);
        }
        let mut bytes = Vec::new();
        (&mut f)
            .take(max as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(unknown)?;
        let after = regular(&f)?;
        let current = File::from(
            openat(
                dir,
                name,
                OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(unknown)?,
        );
        let current = regular(&current)?;
        let identity = |m: &std::fs::Metadata| {
            (
                m.dev(),
                m.ino(),
                m.len(),
                m.mtime(),
                m.mtime_nsec(),
                m.ctime(),
                m.ctime_nsec(),
            )
        };
        if identity(&before) != identity(&after)
            || identity(&after) != identity(&current)
            || bytes.len() as u64 != after.len()
        {
            return Err(JournalError::Unknown);
        }
        Ok(Some(bytes))
    }
    pub(in crate::store) fn sync_file(dir: &File, name: &str) -> JournalResult<()> {
        let f = File::from(
            openat(
                dir,
                name,
                OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(unknown)?,
        );
        regular(&f)?;
        f.sync_all().map_err(unknown)
    }
    pub(in crate::store) fn scan(
        dir: &File,
        budget: JournalBudget,
    ) -> JournalResult<JournalObservation> {
        // A fresh directory description avoids shared seek offsets across scans.
        let mut iterator = Dir::openat(
            dir,
            ".",
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(unknown)?;
        let mut files = vec![];
        let mut total_bytes = 0usize;
        for entry in iterator.iter() {
            let entry = entry.map_err(unknown)?;
            let raw = entry.file_name().to_bytes();
            if raw == b"." || raw == b".." {
                continue;
            }
            if files.len() >= budget.max_files {
                return Err(JournalError::BudgetExceeded);
            }
            let name = std::str::from_utf8(raw).map_err(unknown)?.to_owned();
            let remaining = budget
                .max_bytes
                .checked_sub(total_bytes)
                .ok_or(JournalError::BudgetExceeded)?;
            let bytes = read(dir, &name, budget.max_file_bytes.min(remaining))?
                .ok_or(JournalError::Unknown)?;
            total_bytes = total_bytes
                .checked_add(bytes.len())
                .ok_or(JournalError::BudgetExceeded)?;
            files.push(ObservedJournalFile { name, bytes });
        }
        files.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(JournalObservation { files, total_bytes })
    }
    pub(in crate::store) fn immutable(
        dir: &File,
        name: &str,
        bytes: &[u8],
        budget: JournalBudget,
        fault: &impl Fn(&str),
    ) -> JournalResult<()> {
        if bytes.is_empty() || bytes.len() > budget.max_file_bytes {
            return Err(JournalError::InvalidInput);
        }
        if let Some(existing) = read(dir, name, budget.max_file_bytes)? {
            if existing != bytes {
                return Err(JournalError::Conflict);
            }
            sync_file(dir, name)?;
            dir.sync_all().map_err(unknown)?;
            if read(dir, name, budget.max_file_bytes)?.as_deref() != Some(bytes) {
                return Err(JournalError::Unknown);
            }
            return Ok(());
        }
        let observed = scan(dir, budget)?;
        if observed.files.len() >= budget.max_files
            || observed
                .total_bytes
                .checked_add(bytes.len())
                .is_none_or(|n| n > budget.max_bytes)
        {
            return Err(JournalError::BudgetExceeded);
        }
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(unknown)?;
        let temporary = format!("orphan-{}.temporary", super::super::sha256(&nonce));
        let mut f = File::from(
            openat(
                dir,
                temporary.as_str(),
                OFlag::O_WRONLY
                    | OFlag::O_CREAT
                    | OFlag::O_EXCL
                    | OFlag::O_NOFOLLOW
                    | OFlag::O_CLOEXEC,
                Mode::S_IRUSR | Mode::S_IWUSR,
            )
            .map_err(unknown)?,
        );
        f.write_all(bytes).map_err(unknown)?;
        fault("write");
        f.sync_all().map_err(unknown)?;
        fault("file_sync");
        match renameat2(
            dir,
            temporary.as_str(),
            dir,
            name,
            RenameFlags::RENAME_NOREPLACE,
        ) {
            Ok(()) => (),
            Err(Errno::EEXIST) => {
                if read(dir, name, budget.max_file_bytes)?.as_deref() != Some(bytes) {
                    return Err(JournalError::Conflict);
                }
                sync_file(dir, name)?; // Unknown temporary is deliberately retained.
            }
            Err(e) => return Err(unknown(e)),
        }
        fault("rename");
        dir.sync_all().map_err(unknown)?;
        fault("directory_sync");
        if read(dir, name, budget.max_file_bytes)?.as_deref() != Some(bytes) {
            return Err(JournalError::Unknown);
        }
        Ok(())
    }
    pub(in crate::store) fn existing_namespace(
        root: &File,
        name: NamespaceName,
    ) -> JournalResult<(u64, u64)> {
        let dir = directory(root, name.as_str())?;
        let m = dir.metadata().map_err(unknown)?;
        Ok((m.dev(), m.ino()))
    }
    /// Original-owner migration bootstrap only. Unlike fresh setup's helper,
    /// an existing name is a conflict and is never adopted after an absence race.
    pub(in crate::store) fn create_new_namespace(
        root: &File,
        name: NamespaceName,
    ) -> JournalResult<(u64, u64)> {
        mkdirat(root, name.as_str(), Mode::S_IRWXU).map_err(|error| {
            if error == Errno::EEXIST {
                JournalError::Conflict
            } else {
                JournalError::Unknown
            }
        })?;
        let dir = directory(root, name.as_str())?;
        dir.sync_all().map_err(unknown)?;
        root.sync_all().map_err(unknown)?;
        let m = dir.metadata().map_err(unknown)?;
        Ok((m.dev(), m.ino()))
    }
    pub(in crate::store) fn create_namespace(
        root: &File,
        name: NamespaceName,
    ) -> JournalResult<(u64, u64)> {
        match mkdirat(root, name.as_str(), Mode::S_IRWXU) {
            Ok(()) => (),
            Err(Errno::EEXIST) => (),
            Err(e) => return Err(unknown(e)),
        }
        let dir = directory(root, name.as_str())?;
        dir.sync_all().map_err(unknown)?;
        root.sync_all().map_err(unknown)?;
        let m = dir.metadata().map_err(unknown)?;
        Ok((m.dev(), m.ino()))
    }
    pub(in crate::store) fn with_namespace<T>(
        root: &PrivateRoot,
        writer: &ConfigurationWriterGuard,
        name: NamespaceName,
        namespace: (u64, u64),
        operation: impl FnOnce(&File) -> JournalResult<T>,
    ) -> JournalResult<T> {
        root.inner
            .with_configuration_writer_directory(writer, |root| {
                Ok((|| {
                    let dir = directory(root, name.as_str())?;
                    let m = dir.metadata().map_err(unknown)?;
                    if (m.dev(), m.ino()) != namespace {
                        return Err(JournalError::Unknown);
                    }
                    let result = operation(&dir);
                    let current = directory(root, name.as_str())?;
                    let m = current.metadata().map_err(unknown)?;
                    if (m.dev(), m.ino()) != namespace {
                        return Err(JournalError::Unknown);
                    }
                    result
                })())
            })
            .map_err(unknown)?
    }
}

#[cfg(target_os = "windows")]
#[path = "windows_journal.rs"]
pub(super) mod files;

#[cfg(target_os = "macos")]
#[path = "macos_journal.rs"]
pub(super) mod files;
