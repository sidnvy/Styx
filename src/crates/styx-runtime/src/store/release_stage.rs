//! Exclusive release staging only; no configuration or activation authority.
use super::*;
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs::File,
    io::{Read, Write},
};
use styx_contracts::identity::Sha256Digest;

pub(crate) struct ReleaseCopyMember<'a> {
    pub source_relative: &'a Path,
    pub destination_relative: &'a Path,
    pub bytes: u64,
    pub sha256: Sha256Digest,
    pub executable: bool,
}
/// Only identities of directories this instance created are retained between
/// members. Reopening one never adopts an existing or concurrent directory.
pub(crate) struct ReleaseStage {
    root: PrivateRoot,
    path: PathBuf,
    directories: BTreeMap<PathBuf, RootIdentity>,
    copied_files: usize,
    copied_bytes: u64,
}
impl ReleaseStage {
    pub(crate) fn create(parent: &PrivateRoot, parent_path: &Path, name: &OsStr) -> Result<Self> {
        let inner = parent
            .inner
            .create_fresh_child(name)
            .map_err(|failure| failure.cause)?;
        let root = PrivateRoot { inner };
        let path = parent_path.join(name);
        let mut directories = BTreeMap::new();
        directories.insert(PathBuf::new(), root.identity());
        Ok(Self {
            root,
            path,
            directories,
            copied_files: 0,
            copied_bytes: 0,
        })
    }
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
    fn directory(&mut self, relative: &Path) -> Result<PrivateRoot> {
        self.root.inner.with_readonly_directory(|_| Ok(()))?;
        let mut current = PrivateRoot::open(&self.path)?;
        if current.identity() != self.root.identity() {
            return Err(StoreError::Changed);
        }
        let mut prefix = PathBuf::new();
        for part in relative.components() {
            let Component::Normal(name) = part else {
                return Err(StoreError::InvalidRelativePath);
            };
            prefix.push(name);
            current = if let Some(identity) = self.directories.get(&prefix) {
                let opened = PrivateRoot::open(self.path.join(&prefix))?;
                if &opened.identity() != identity {
                    return Err(StoreError::Changed);
                }
                opened
            } else {
                if self.directories.len() >= PayloadLimits::default().max_directories + 2 {
                    return Err(StoreError::TooLarge);
                }
                let inner = current
                    .inner
                    .create_fresh_child(name)
                    .map_err(|failure| failure.cause)?;
                let opened = PrivateRoot { inner };
                self.directories.insert(prefix.clone(), opened.identity());
                opened
            };
        }
        self.root.inner.with_readonly_directory(|_| Ok(()))?;
        Ok(current)
    }
    pub(crate) fn copy_member(
        &mut self,
        source: &PrivateRoot,
        member: ReleaseCopyMember<'_>,
    ) -> Result<()> {
        let source_relative = checked_relative(member.source_relative)?;
        let target = checked_relative(member.destination_relative)?;
        if member.bytes > PayloadLimits::default().max_file_bytes {
            return Err(StoreError::TooLarge);
        }
        let next_bytes = self
            .copied_bytes
            .checked_add(member.bytes)
            .ok_or(StoreError::TooLarge)?;
        // The source payload's bounded inventory plus one <=4KiB public PEM.
        if self.copied_files > PayloadLimits::default().max_files
            || next_bytes > PayloadLimits::default().max_total_bytes + 4096
        {
            return Err(StoreError::TooLarge);
        }
        self.copied_files += 1;
        self.copied_bytes = next_bytes;
        let directory = self.directory(target.parent().ok_or(StoreError::InvalidRelativePath)?)?;
        let name = target.file_name().ok_or(StoreError::InvalidRelativePath)?;
        let (mut input, before) = source.inner.release_open(&source_relative)?;
        if before.byte_len != member.bytes {
            return Err(StoreError::Changed);
        }
        let mut output = directory.inner.release_create(name)?;
        let original = directory.inner.release_observe(&output)?;
        let hash = copy_exact(&mut input, Some(&mut output), member.bytes)?;
        if hash != member.sha256 {
            return Err(StoreError::Changed);
        }
        if source.inner.release_observe(&input)? != before {
            return Err(StoreError::Changed);
        }
        let (_, source_after) = source.inner.release_open(&source_relative)?;
        if source_after != before {
            return Err(StoreError::Changed);
        }
        directory.inner.release_flush(&output, member.executable)?;
        let written = directory.inner.release_observe(&output)?;
        if written.device != original.device
            || written.inode != original.inode
            || written.byte_len != member.bytes
        {
            return Err(StoreError::Changed);
        }
        drop(output);
        let (mut published, observed) = directory.inner.release_open(Path::new(name))?;
        if observed.device != written.device
            || observed.inode != written.inode
            || observed.byte_len != member.bytes
            || copy_exact(&mut published, None, member.bytes)? != member.sha256
            || directory.inner.release_observe(&published)? != observed
        {
            return Err(StoreError::Changed);
        }
        let (_, after) = directory.inner.release_open(Path::new(name))?;
        if after != observed {
            return Err(StoreError::Changed);
        }
        source.inner.with_readonly_directory(|_| Ok(()))?;
        directory.inner.with_readonly_directory(|_| Ok(()))?;
        self.root.inner.with_readonly_directory(|_| Ok(()))?;
        Ok(())
    }
}
fn copy_exact(
    input: &mut File,
    mut output: Option<&mut File>,
    expected: u64,
) -> Result<Sha256Digest> {
    let mut hash = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        total = total.checked_add(n as u64).ok_or(StoreError::TooLarge)?;
        if total > expected {
            return Err(StoreError::TooLarge);
        }
        hash.update(&buffer[..n]);
        if let Some(writer) = output.as_mut() {
            writer.write_all(&buffer[..n])?;
        }
    }
    if total != expected {
        return Err(StoreError::Changed);
    }
    let encoded = hex::encode(hash.finalize());
    encoded.try_into().map_err(|_| StoreError::Changed)
}
