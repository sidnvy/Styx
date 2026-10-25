//! Local fixed-NTFS implementation of the store-private journal file port.
//! Original directory handles are converted only through OS final-path lookup,
//! protected ancestor pins and before/after file-ID checks. No new writer,
//! policy, transaction authority, repair, orphan deletion or directory-fsync
//! emulation lives here. File and directory flushes are actual Win32 calls on
//! identity-checked writable HANDLES, not a volume flush or power-loss test.
use super::*;
use crate::store::{StoreError, platform::Root};
use std::{fs::File, io::Write, path::Path};

fn unknown<T>(_: T) -> JournalError {
    JournalError::Unknown
}
fn protected(dir: &File) -> JournalResult<Root> {
    Root::from_directory_handle(dir).map_err(unknown)
}
fn pin(dir: &File) -> JournalResult<(u64, u64)> {
    let root = protected(dir)?;
    let crate::store::RootIdentity::Windows {
        volume_serial,
        file_id,
        ..
    } = root.identity()
    else {
        return Err(JournalError::Unknown);
    };
    Ok((volume_serial, file_id))
}
fn read_at(root: &Root, name: &str, max: usize) -> JournalResult<Option<Vec<u8>>> {
    match root.read_raw(Path::new(name), max) {
        Ok(raw) => Ok(Some(raw.bytes)),
        Err(StoreError::TooLarge) => Err(JournalError::BudgetExceeded),
        Err(StoreError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            root.ensure_absent(Path::new(name)).map_err(unknown)?;
            Ok(None)
        }
        Err(_) => Err(JournalError::Unknown),
    }
}
pub(in crate::store) fn directory(parent: &File, name: &str) -> JournalResult<File> {
    let root = protected(parent)?;
    let result = root.journal_directory(name).map_err(unknown);
    root.validate_root().map_err(unknown)?;
    result
}
pub(in crate::store) fn read(dir: &File, name: &str, max: usize) -> JournalResult<Option<Vec<u8>>> {
    if max > 1024 * 1024 {
        return Err(JournalError::InvalidInput);
    }
    let root = protected(dir)?;
    let result = read_at(&root, name, max);
    root.validate_root().map_err(unknown)?;
    result
}
pub(in crate::store) fn sync_directory(dir: &File) -> JournalResult<()> {
    protected(dir)?.sync_directory().map_err(unknown)
}
pub(in crate::store) fn sync_file(dir: &File, name: &str) -> JournalResult<()> {
    let root = protected(dir)?;
    let before = root
        .read_raw(Path::new(name), 1024 * 1024)
        .map_err(unknown)?;
    root.sync_journal_file(name).map_err(unknown)?;
    let after = root
        .read_raw(Path::new(name), 1024 * 1024)
        .map_err(unknown)?;
    if before.observation() != after.observation() || before.bytes() != after.bytes() {
        return Err(JournalError::Unknown);
    }
    root.validate_root().map_err(unknown)
}
pub(in crate::store) fn scan(
    dir: &File,
    budget: JournalBudget,
) -> JournalResult<JournalObservation> {
    if !budget.valid() {
        return Err(JournalError::InvalidInput);
    }
    let root = protected(dir)?;
    let mut files = Vec::new();
    let mut total_bytes = 0usize;
    // The original and independently reopened directory/ancestors deny delete
    // sharing. Enumeration is lazy and bounded, not an unbounded walk/collect.
    let iterator = std::fs::read_dir(root.journal_path()).map_err(unknown)?;
    for entry in iterator {
        let entry = entry.map_err(unknown)?;
        if files.len() >= budget.max_files {
            return Err(JournalError::BudgetExceeded);
        }
        let name = entry.file_name().into_string().map_err(unknown)?;
        let remaining = budget
            .max_bytes
            .checked_sub(total_bytes)
            .ok_or(JournalError::BudgetExceeded)?;
        let bytes = read_at(&root, &name, budget.max_file_bytes.min(remaining))?
            .ok_or(JournalError::Unknown)?;
        total_bytes = total_bytes
            .checked_add(bytes.len())
            .ok_or(JournalError::BudgetExceeded)?;
        files.push(ObservedJournalFile { name, bytes });
    }
    root.validate_root().map_err(unknown)?;
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
    if !budget.valid() || bytes.is_empty() || bytes.len() > budget.max_file_bytes {
        return Err(JournalError::InvalidInput);
    }
    Root::validate_journal_name(name).map_err(|_| JournalError::InvalidInput)?;
    let root = protected(dir)?;
    if let Some(existing) = read_at(&root, name, budget.max_file_bytes)? {
        if existing != bytes {
            return Err(JournalError::Conflict);
        }
        sync_file(dir, name)?;
        root.sync_directory().map_err(unknown)?;
        fault("directory_sync");
        if read_at(&root, name, budget.max_file_bytes)?.as_deref() != Some(bytes) {
            return Err(JournalError::Unknown);
        }
        return root.validate_root().map_err(unknown);
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
    let mut file = root.new_journal_file(&temporary).map_err(unknown)?;
    let original = Root::journal_file_identity(&file).map_err(unknown)?;
    file.write_all(bytes).map_err(unknown)?;
    fault("write");
    // Source handle is writable/write-through and retains DELETE access for
    // the following handle-bound rename. No path reopen can select a new source.
    root.flush_journal_file(&file).map_err(unknown)?;
    fault("file_sync");
    match root.rename_journal_file(&file, name, false) {
        Ok(()) => {}
        Err(StoreError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            // Unlike an initial known exact record, a racing destination is not
            // adopted, even if somebody wrote matching bytes. Keep the orphan.
            return Err(JournalError::Conflict);
        }
        Err(_) => return Err(JournalError::Unknown),
    }
    fault("rename");
    // rename_journal_file flushed the same actual source file after the rename.
    // Flush the independently identity-checked writable namespace below too.
    fault("file_sync_after_rename");
    if Root::journal_file_identity(&file).map_err(unknown)? != original {
        return Err(JournalError::Unknown);
    }
    drop(file); // write/delete sharing must end before the ordinary input reader
    let raw = root
        .read_raw(Path::new(name), budget.max_file_bytes)
        .map_err(unknown)?;
    if (raw.observation().device, raw.observation().inode) != original || raw.bytes() != bytes {
        return Err(JournalError::Unknown);
    }
    root.ensure_absent(Path::new(&temporary)).map_err(unknown)?;
    root.sync_directory().map_err(unknown)?;
    fault("directory_sync");
    let after = root
        .read_raw(Path::new(name), budget.max_file_bytes)
        .map_err(unknown)?;
    if after.observation() != raw.observation() || after.bytes() != bytes {
        return Err(JournalError::Unknown);
    }
    root.validate_root().map_err(unknown)
}
/// Original-writer cooperative conditional replacement, matching the Linux
/// clock-floor before-read + rename semantics. Expected bytes are NOT kernel
/// CAS authority. Domain code retains monotonic-clock policy and original writer.
pub(in crate::store) fn replace_observed(
    dir: &File,
    name: &str,
    expected: Option<&[u8]>,
    bytes: &[u8],
    budget: JournalBudget,
    fault: &impl Fn(&str),
) -> JournalResult<()> {
    if !budget.valid() || bytes.is_empty() || bytes.len() > budget.max_file_bytes {
        return Err(JournalError::InvalidInput);
    }
    Root::validate_journal_name(name).map_err(|_| JournalError::InvalidInput)?;
    let root = protected(dir)?;
    let current = read_at(&root, name, budget.max_file_bytes)?;
    if current.as_deref() != expected {
        return Err(JournalError::Conflict);
    }
    if current.as_deref() == Some(bytes) {
        // Even a same-value floor must actually be flushed and reobserved.
        sync_file(dir, name)?;
        root.sync_directory().map_err(unknown)?;
        fault("directory_sync");
        if read_at(&root, name, budget.max_file_bytes)?.as_deref() != Some(bytes) {
            return Err(JournalError::Unknown);
        }
        return root.validate_root().map_err(unknown);
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
    let mut file = root.new_journal_file(&temporary).map_err(unknown)?;
    let original = Root::journal_file_identity(&file).map_err(unknown)?;
    file.write_all(bytes).map_err(unknown)?;
    fault("write");
    root.flush_journal_file(&file).map_err(unknown)?;
    fault("file_sync");
    if read_at(&root, name, budget.max_file_bytes)?.as_deref() != expected {
        return Err(JournalError::Unknown); // retain the new orphan, never repair
    }
    root.rename_journal_file(&file, name, expected.is_some())
        .map_err(unknown)?;
    fault("rename");
    fault("file_sync_after_rename");
    if Root::journal_file_identity(&file).map_err(unknown)? != original {
        return Err(JournalError::Unknown);
    }
    drop(file);
    let raw = root
        .read_raw(Path::new(name), budget.max_file_bytes)
        .map_err(unknown)?;
    if (raw.observation().device, raw.observation().inode) != original || raw.bytes() != bytes {
        return Err(JournalError::Unknown);
    }
    root.ensure_absent(Path::new(&temporary)).map_err(unknown)?;
    root.sync_directory().map_err(unknown)?;
    fault("directory_sync");
    let after = root
        .read_raw(Path::new(name), budget.max_file_bytes)
        .map_err(unknown)?;
    if after.observation() != raw.observation() || after.bytes() != bytes {
        return Err(JournalError::Unknown);
    }
    root.validate_root().map_err(unknown)
}
pub(in crate::store) fn existing_namespace(
    root: &File,
    name: NamespaceName,
) -> JournalResult<(u64, u64)> {
    pin(&directory(root, name.as_str())?)
}
// Original-writer migration uses the same strict create-new namespace.
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
    dir: &File,
    name: NamespaceName,
    strict: bool,
) -> JournalResult<(u64, u64)> {
    let root = protected(dir)?;
    let directory = root.create_journal_directory(name.as_str(), strict).map_err(|error| {
        if matches!(error, StoreError::Io(ref e) if e.kind() == std::io::ErrorKind::AlreadyExists) {
            JournalError::Conflict
        } else { JournalError::Unknown }
    })?;
    let identity = pin(&directory)?;
    protected(&directory)?.sync_directory().map_err(unknown)?;
    root.sync_directory().map_err(unknown)?;
    if pin(&directory)? != identity || existing_namespace(dir, name)? != identity {
        return Err(JournalError::Unknown);
    }
    root.validate_root().map_err(unknown)?;
    Ok(identity)
}
pub(in crate::store) fn with_namespace<T>(
    root: &PrivateRoot,
    writer: &ConfigurationWriterGuard,
    name: NamespaceName,
    namespace: (u64, u64),
    operation: impl FnOnce(&File) -> JournalResult<T>,
) -> JournalResult<T> {
    root.inner
        .with_configuration_writer_directory(writer, |directory| {
            Ok((|| {
                let dir = self::directory(directory, name.as_str())?;
                if pin(&dir)? != namespace {
                    return Err(JournalError::Unknown);
                }
                let result = operation(&dir);
                if existing_namespace(directory, name)? != namespace {
                    return Err(JournalError::Unknown);
                }
                result
            })())
        })
        .map_err(unknown)?
}
