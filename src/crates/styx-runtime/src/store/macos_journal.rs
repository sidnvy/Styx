//! Darwin implementation of the existing store-private file port. All names
//! are components relative to retained original FDs; no policy/writer/recovery
//! authority is minted. Full-sync failures are Unknown, never silently fsync-only.
use super::*;
use crate::store::{StoreError, platform};
use nix::{
    dir::Dir,
    errno::Errno,
    fcntl::{OFlag, openat, renameat},
    sys::stat::{Mode, mkdirat},
};
use std::{
    fs::{File, Metadata},
    io::{Read, Write},
    os::unix::fs::MetadataExt,
};
fn unknown<T>(_: T) -> JournalError {
    JournalError::Unknown
}
fn component(name: &str) -> JournalResult<()> {
    platform::journal_component(name).map_err(|_| JournalError::InvalidInput)
}
fn open(dir: &File, name: &str, flags: OFlag, mode: Mode) -> JournalResult<File> {
    component(name)?;
    openat(
        dir,
        name,
        flags | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        mode,
    )
    .map(File::from)
    .map_err(unknown)
}
fn directory_pin(dir: &File) -> JournalResult<(u64, u64)> {
    let m = platform::journal_private_directory(dir).map_err(unknown)?;
    Ok((m.dev(), m.ino()))
}
fn regular(file: &File) -> JournalResult<Metadata> {
    platform::journal_private_file(file).map_err(unknown)
}
fn observation(m: &Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
pub(in crate::store) fn directory(parent: &File, name: &str) -> JournalResult<File> {
    let original = directory_pin(parent)?;
    let child = open(
        parent,
        name,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY,
        Mode::empty(),
    )?;
    directory_pin(&child)?;
    if directory_pin(parent)? != original {
        return Err(JournalError::Unknown);
    }
    Ok(child)
}
fn read_observed(dir: &File, name: &str, max: usize) -> JournalResult<Option<(Vec<u8>, Metadata)>> {
    component(name)?;
    if max > 1024 * 1024 {
        return Err(JournalError::InvalidInput);
    }
    let original_directory = directory_pin(dir)?;
    let fd = match openat(
        dir,
        name,
        OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::ENOENT) => {
            return if directory_pin(dir)? == original_directory {
                Ok(None)
            } else {
                Err(JournalError::Unknown)
            };
        }
        Err(e) => return Err(unknown(e)),
    };
    let mut file = File::from(fd);
    let before = regular(&file)?;
    if before.len() > max as u64 {
        return Err(JournalError::BudgetExceeded);
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(unknown)?;
    if bytes.len() > max {
        return Err(JournalError::BudgetExceeded);
    }
    let after = regular(&file)?;
    let current = open(
        dir,
        name,
        OFlag::O_RDONLY | OFlag::O_NONBLOCK,
        Mode::empty(),
    )?;
    let current = regular(&current)?;
    if observation(&before) != observation(&after)
        || observation(&after) != observation(&current)
        || bytes.len() as u64 != after.len()
        || directory_pin(dir)? != original_directory
    {
        return Err(JournalError::Unknown);
    }
    Ok(Some((bytes, after)))
}
pub(in crate::store) fn read(dir: &File, name: &str, max: usize) -> JournalResult<Option<Vec<u8>>> {
    read_observed(dir, name, max).map(|v| v.map(|(bytes, _)| bytes))
}
pub(in crate::store) fn sync_file(dir: &File, name: &str) -> JournalResult<()> {
    let original_directory = directory_pin(dir)?;
    let original = read_observed(dir, name, 1024 * 1024)?.ok_or(JournalError::Unknown)?;
    // Probe-proven read/write rights, no create/truncate, same original inode.
    let file = open(dir, name, OFlag::O_RDWR | OFlag::O_NONBLOCK, Mode::empty())?;
    if observation(&regular(&file)?) != observation(&original.1) {
        return Err(JournalError::Unknown);
    }
    platform::sync_private_file(&file).map_err(unknown)?;
    let after = read_observed(dir, name, 1024 * 1024)?.ok_or(JournalError::Unknown)?;
    if original.0 != after.0
        || observation(&original.1) != observation(&after.1)
        || observation(&after.1) != observation(&regular(&file)?)
        || directory_pin(dir)? != original_directory
    {
        return Err(JournalError::Unknown);
    }
    Ok(())
}
pub(in crate::store) fn sync_directory(dir: &File) -> JournalResult<()> {
    let before = directory_pin(dir)?;
    let result = platform::sync_private_directory(dir).map_err(unknown);
    if directory_pin(dir)? != before {
        return Err(JournalError::Unknown);
    }
    result
}
pub(in crate::store) fn scan(
    dir: &File,
    budget: JournalBudget,
) -> JournalResult<JournalObservation> {
    if !budget.valid() {
        return Err(JournalError::InvalidInput);
    }
    let original = directory_pin(dir)?;
    // New description avoids sharing enumeration offsets with the owner.
    let mut entries = Dir::openat(
        dir,
        ".",
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(unknown)?;
    let mut files = Vec::new();
    let mut total_bytes = 0usize;
    for entry in entries.iter() {
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
        let bytes =
            read(dir, &name, budget.max_file_bytes.min(remaining))?.ok_or(JournalError::Unknown)?;
        total_bytes = total_bytes
            .checked_add(bytes.len())
            .ok_or(JournalError::BudgetExceeded)?;
        files.push(ObservedJournalFile { name, bytes });
    }
    if directory_pin(dir)? != original {
        return Err(JournalError::Unknown);
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
    component(name)?;
    if !budget.valid() || bytes.is_empty() || bytes.len() > budget.max_file_bytes {
        return Err(JournalError::InvalidInput);
    }
    if let Some(existing) = read(dir, name, budget.max_file_bytes)? {
        if existing != bytes {
            return Err(JournalError::Conflict);
        }
        return replace_observed(dir, name, Some(bytes), bytes, budget, fault);
    }
    replace_observed(dir, name, None, bytes, budget, fault)
}
/// Same original-writer cooperative expected-byte check as Linux, not a kernel
/// CAS against hostile same-UID writers. Existing/orphan material is never erased.
pub(in crate::store) fn replace_observed(
    dir: &File,
    name: &str,
    expected: Option<&[u8]>,
    bytes: &[u8],
    budget: JournalBudget,
    fault: &impl Fn(&str),
) -> JournalResult<()> {
    component(name)?;
    if !budget.valid() || bytes.is_empty() || bytes.len() > budget.max_file_bytes {
        return Err(JournalError::InvalidInput);
    }
    let original_directory = directory_pin(dir)?;
    let before = read_observed(dir, name, budget.max_file_bytes)?;
    if before.as_ref().map(|(b, _)| b.as_slice()) != expected {
        return Err(JournalError::Conflict);
    }
    if before.as_ref().is_some_and(|(b, _)| b == bytes) {
        sync_file(dir, name)?;
        sync_directory(dir)?;
        fault("directory_sync");
        let after =
            read_observed(dir, name, budget.max_file_bytes)?.ok_or(JournalError::Unknown)?;
        let before = before.ok_or(JournalError::Unknown)?;
        if after.0 != bytes || observation(&after.1) != observation(&before.1) {
            return Err(JournalError::Unknown);
        }
        return Ok(());
    }
    let inventory = scan(dir, budget)?;
    if inventory.files.len() >= budget.max_files
        || inventory
            .total_bytes
            .checked_add(bytes.len())
            .is_none_or(|n| n > budget.max_bytes)
    {
        return Err(JournalError::BudgetExceeded);
    }
    let mut entropy = [0u8; 16];
    getrandom::fill(&mut entropy).map_err(unknown)?;
    let temporary = format!("orphan-{}.temporary", crate::store::sha256(&entropy));
    let mut file = open(
        dir,
        &temporary,
        OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NONBLOCK,
        Mode::S_IRUSR | Mode::S_IWUSR,
    )?;
    let original = regular(&file)?;
    file.write_all(bytes).map_err(unknown)?;
    fault("write");
    platform::sync_private_file(&file).map_err(unknown)?;
    fault("file_sync");
    let current = read_observed(dir, name, budget.max_file_bytes)?;
    if current.as_ref().map(|(b, _)| b.as_slice()) != expected
        || current.as_ref().map(|(_, m)| observation(m))
            != before.as_ref().map(|(_, m)| observation(m))
    {
        return Err(JournalError::Unknown);
    }
    let staged =
        read_observed(dir, &temporary, budget.max_file_bytes)?.ok_or(JournalError::Unknown)?;
    if (staged.1.dev(), staged.1.ino()) != (original.dev(), original.ino()) || staged.0 != bytes {
        return Err(JournalError::Unknown);
    }
    if expected.is_some() {
        renameat(dir, temporary.as_str(), dir, name).map_err(unknown)?;
    } else {
        platform::rename_exclusive(dir, &temporary, dir, name).map_err(|error| {
            if matches!(error,StoreError::Io(ref e) if e.kind()==std::io::ErrorKind::AlreadyExists)
            {
                JournalError::Conflict
            } else {
                JournalError::Unknown
            }
        })?;
    }
    fault("rename");
    platform::sync_private_file(&file).map_err(unknown)?;
    sync_directory(dir)?;
    fault("directory_sync");
    let after = read_observed(dir, name, budget.max_file_bytes)?.ok_or(JournalError::Unknown)?;
    if (after.1.dev(), after.1.ino()) != (original.dev(), original.ino())
        || after.0 != bytes
        || read(dir, &temporary, budget.max_file_bytes)?.is_some()
        || directory_pin(dir)? != original_directory
    {
        return Err(JournalError::Unknown);
    }
    regular(&file)?;
    Ok(())
}
pub(in crate::store) fn existing_namespace(
    root: &File,
    name: NamespaceName,
) -> JournalResult<(u64, u64)> {
    directory_pin(&directory(root, name.as_str())?)
}
// Exclusive namespace creation is exercised by native filesystem publication tests.
#[cfg(test)]
pub(in crate::store) fn create_new_namespace(
    root: &File,
    name: NamespaceName,
) -> JournalResult<(u64, u64)> {
    create_namespace_with(root, name, true)
}
pub(in crate::store) fn create_namespace(
    root: &File,
    name: NamespaceName,
) -> JournalResult<(u64, u64)> {
    create_namespace_with(root, name, false)
}
fn create_namespace_with(
    root: &File,
    name: NamespaceName,
    strict: bool,
) -> JournalResult<(u64, u64)> {
    let original = directory_pin(root)?;
    match mkdirat(root, name.as_str(), Mode::S_IRWXU) {
        Ok(()) => {}
        Err(Errno::EEXIST) if !strict => {}
        Err(Errno::EEXIST) => return Err(JournalError::Conflict),
        Err(e) => return Err(unknown(e)),
    }
    let dir = directory(root, name.as_str())?;
    let pin = directory_pin(&dir)?;
    sync_directory(&dir)?;
    sync_directory(root)?;
    if existing_namespace(root, name)? != pin || directory_pin(root)? != original {
        return Err(JournalError::Unknown);
    }
    Ok(pin)
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
                if directory_pin(&dir)? != namespace {
                    return Err(JournalError::Unknown);
                }
                let result = operation(&dir);
                if existing_namespace(root, name)? != namespace {
                    return Err(JournalError::Unknown);
                }
                result
            })())
        })
        .map_err(unknown)?
}
