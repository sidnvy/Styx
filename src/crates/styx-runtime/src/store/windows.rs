//! Windows protected existing roots and distinct native file-lock resources.
//! Retained ancestor handles omit delete sharing; regular input handles also
//! omit write sharing. No journal writes, ACL rewrite or path launch fallback.
#[path = "windows_ffi.rs"]
mod ffi;
#[path = "windows_payload.rs"]
mod payload_backend;
use super::*;
pub(in crate::store) use payload_backend::{PayloadSnapshot, PinnedImage};
use std::{
    ffi::OsStr,
    fs::{File, TryLockError},
    io::Read,
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
impl Root {
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
    pub(super) fn identity(&self) -> RootIdentity {
        self.identity.clone()
    }
    fn validate_root(&self) -> Result<()> {
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
