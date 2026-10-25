//! Bounded protected Windows payload closure. No mutable pathname execution.
use super::*;
use crate::store::payload::{PayloadInventory, PayloadLimits, PayloadMember};
use std::{
    collections::{BTreeMap, BTreeSet},
    os::windows::fs::FileExt,
};
use styx_contracts::identity::Sha256Digest;
#[derive(Clone, PartialEq, Eq)]
struct Observed {
    facts: ffi::Facts,
    sha256: Option<Sha256Digest>,
    executable: bool,
}
pub(in crate::store) struct PayloadSnapshot {
    root: Root,
    observed: BTreeMap<PathBuf, Observed>,
    limits: PayloadLimits,
}
pub(in crate::store) struct PinnedImage {
    root: Root,
    relative: PathBuf,
    opened: Opened,
    observed: Observed,
    creator: ProcessIdentity,
}
fn stream_hash(file: &File, max: u64) -> Result<Sha256Digest> {
    let mut hash = Sha256::new();
    let mut bytes = [0u8; 65536];
    let mut offset = 0u64;
    loop {
        let n = file.seek_read(&mut bytes, offset)?;
        if n == 0 {
            break;
        }
        offset = offset.checked_add(n as u64).ok_or(StoreError::TooLarge)?;
        if offset > max {
            return Err(StoreError::TooLarge);
        }
        hash.update(&bytes[..n]);
    }
    Sha256Digest::try_from(hex::encode(hash.finalize())).map_err(|_| StoreError::Changed)
}
fn executable(path: &Path) -> bool {
    // Preserve the original signed legacy rule, independent of Windows ACLs.
    // Native runtime bundles additionally allocate only these fixed workers.
    let parts: Vec<_> = path.components().map(|p| p.as_os_str()).collect();
    parts.first().is_some_and(|p| *p == OsStr::new("bin"))
        || [
            "workers/codex-exec/bin/codex.exe",
            "workers/browser-node22/bin/node.exe",
            "workers/cua-native/bin/cua-driver.exe",
        ]
        .iter()
        .any(|expected| path == Path::new(expected))
}
fn directory_names(path: &Path, max: usize) -> Result<BTreeSet<std::ffi::OsString>> {
    let mut names = BTreeSet::new();
    let mut folded = BTreeSet::new();
    for entry in std::fs::read_dir(path)? {
        let name = entry?.file_name();
        component(&name)?;
        if !folded.insert(name.to_string_lossy().to_lowercase()) || !names.insert(name) {
            return Err(StoreError::Changed);
        }
        if names.len() > max {
            return Err(StoreError::TooLarge);
        }
    }
    Ok(names)
}
fn observe(opened: &Opened, directory: bool) -> Result<Observed> {
    let facts = private_facts(&opened.file, directory)?;
    if !directory {
        ffi::require_no_streams(&opened.path)?;
    }
    Ok(Observed {
        facts,
        sha256: None,
        executable: !directory && executable(&opened.relative),
    })
}
fn same(a: &Observed, b: &Observed) -> bool {
    a.facts == b.facts && a.executable == b.executable
}
impl Root {
    fn payload_directory(&self, path: &Path) -> Result<Opened> {
        if path.as_os_str().is_empty() {
            return Ok(Opened {
                file: self.directory.try_clone()?,
                _parents: Vec::new(),
                path: self.path.clone(),
                relative: PathBuf::new(),
            });
        }
        self.open_relative(path, true, false, false)
    }
    fn collect_payload(
        &self,
        limits: PayloadLimits,
    ) -> Result<(BTreeMap<PathBuf, Observed>, Vec<PayloadMember>)> {
        self.validate_root()?;
        limits.validate()?;
        let mut observed = BTreeMap::new();
        let mut members = Vec::new();
        let mut total = 0;
        let mut directories = 0;
        self.walk_payload(
            Path::new(""),
            0,
            limits,
            &mut observed,
            &mut members,
            &mut total,
            &mut directories,
        )?;
        members.sort_by(|a, b| a.path.cmp(&b.path));
        self.validate_root()?;
        Ok((observed, members))
    }
    pub(in crate::store) fn payload_inventory(
        &self,
        limits: PayloadLimits,
    ) -> Result<PayloadInventory> {
        let (observed, members) = self.collect_payload(limits)?;
        let inner = PayloadSnapshot {
            root: self.clone(),
            observed,
            limits,
        };
        inner.revalidate()?;
        Ok(PayloadInventory { members, inner })
    }
    #[allow(clippy::too_many_arguments)]
    fn walk_payload(
        &self,
        relative: &Path,
        depth: usize,
        limits: PayloadLimits,
        observed: &mut BTreeMap<PathBuf, Observed>,
        members: &mut Vec<PayloadMember>,
        total: &mut u64,
        directories: &mut usize,
    ) -> Result<()> {
        if depth > limits.max_depth || *directories >= limits.max_directories {
            return Err(StoreError::TooLarge);
        }
        let directory = self.payload_directory(relative)?;
        let before = observe(&directory, true)?;
        *directories += 1;
        let names = directory_names(&directory.path, limits.max_files + limits.max_directories)?;
        for name in &names {
            let path = relative.join(name);
            let listing = directory.path.join(name);
            let kind = std::fs::symlink_metadata(&listing)?;
            let opened = self.open_relative(&path, kind.is_dir(), false, false)?;
            if kind.is_dir() {
                // The opened directory remains held while recursing through its
                // ordinary path, so neither it nor an ancestor can be renamed.
                private_facts(&opened.file, true)?;
                self.walk_payload(
                    &path,
                    depth + 1,
                    limits,
                    observed,
                    members,
                    total,
                    directories,
                )?;
            } else {
                if members.len() >= limits.max_files {
                    return Err(StoreError::TooLarge);
                }
                let mut facts = observe(&opened, false)?;
                let size = facts.facts.observation.byte_len;
                if size > limits.max_file_bytes {
                    return Err(StoreError::TooLarge);
                }
                *total = total.checked_add(size).ok_or(StoreError::TooLarge)?;
                if *total > limits.max_total_bytes {
                    return Err(StoreError::TooLarge);
                }
                let digest = stream_hash(&opened.file, size)?;
                let current = self.open_relative(&path, false, false, false)?;
                if !same(&facts, &observe(&opened, false)?)
                    || !same(&facts, &observe(&current, false)?)
                {
                    return Err(StoreError::Changed);
                }
                facts.sha256 = Some(digest);
                members.push(PayloadMember {
                    path: path.clone(),
                    bytes: size,
                    sha256: digest,
                    executable: facts.executable,
                });
                observed.insert(path, facts);
            }
        }
        let after_names =
            directory_names(&directory.path, limits.max_files + limits.max_directories)?;
        if after_names != names
            || !same(&before, &observe(&directory, true)?)
            || !same(&before, &observe(&self.payload_directory(relative)?, true)?)
        {
            return Err(StoreError::Changed);
        }
        observed.insert(relative.to_owned(), before);
        Ok(())
    }
}
impl PayloadSnapshot {
    pub(in crate::store) fn revalidate(&self) -> Result<()> {
        let (actual, _) = self.root.collect_payload(self.limits)?;
        if actual != self.observed {
            return Err(StoreError::Changed);
        }
        Ok(())
    }
    pub(in crate::store) fn pin_executable(&self, path: &Path) -> Result<PinnedImage> {
        self.revalidate()?;
        let observed = self
            .observed
            .get(path)
            .filter(|o| o.executable && !o.facts.directory)
            .ok_or(StoreError::NotRegularFile)?
            .clone();
        let opened = self.root.open_relative(path, false, false, false)?;
        if !same(&observed, &observe(&opened, false)?) {
            return Err(StoreError::Changed);
        }
        check_pe64(&opened.file, observed.facts.observation.byte_len)?;
        let image = PinnedImage {
            root: self.root.clone(),
            relative: path.to_owned(),
            opened,
            observed,
            creator: ProcessIdentity::current()?,
        };
        image.revalidate()?;
        Ok(image)
    }
}
fn read_exact_at(file: &File, mut buffer: &mut [u8], mut offset: u64) -> Result<()> {
    while !buffer.is_empty() {
        let n = file.seek_read(buffer, offset)?;
        if n == 0 {
            return Err(StoreError::Unsupported);
        }
        offset = offset.checked_add(n as u64).ok_or(StoreError::TooLarge)?;
        buffer = &mut buffer[n..];
    }
    Ok(())
}
fn check_pe64(file: &File, len: u64) -> Result<()> {
    // Bounded format/machine guard only; the Windows loader validates the image.
    if !cfg!(target_arch = "x86_64") || len < 64 {
        return Err(StoreError::Unsupported);
    }
    let mut dos = [0u8; 64];
    read_exact_at(file, &mut dos, 0)?;
    let offset = u64::from(u32::from_le_bytes(
        dos[60..64].try_into().expect("fixed field"),
    ));
    if &dos[..2] != b"MZ"
        || offset < 64
        || offset > 1024 * 1024
        || offset.checked_add(26).is_none_or(|n| n > len)
    {
        return Err(StoreError::Unsupported);
    }
    let mut pe = [0u8; 26];
    read_exact_at(file, &mut pe, offset)?;
    let flags = u16::from_le_bytes(pe[22..24].try_into().expect("fixed field"));
    if &pe[..4] != b"PE\0\0"
        || u16::from_le_bytes(pe[4..6].try_into().expect("fixed field")) != 0x8664
        || u16::from_le_bytes(pe[24..26].try_into().expect("fixed field")) != 0x20b
        || flags & 0x0002 == 0
        || flags & 0x2000 != 0
    {
        return Err(StoreError::Unsupported);
    }
    Ok(())
}
impl PinnedImage {
    pub(in crate::store) fn revalidate(&self) -> Result<()> {
        if !self.creator.still_current()? {
            return Err(StoreError::ProcessIdentityUnavailable);
        }
        self.root.validate_root()?;
        let current = self
            .root
            .open_relative(&self.relative, false, false, false)?;
        if !same(&self.observed, &observe(&self.opened, false)?)
            || !same(&self.observed, &observe(&current, false)?)
            || Some(stream_hash(
                &self.opened.file,
                self.observed.facts.observation.byte_len,
            )?) != self.observed.sha256
        {
            return Err(StoreError::Changed);
        }
        Ok(())
    }
    pub(in crate::store) fn launch_path(&self) -> Result<PathBuf> {
        self.revalidate()?;
        Err(StoreError::Unsupported)
    }
    pub(in crate::store) fn source_path_for_suspended_spawn(&self) -> Result<PathBuf> {
        self.revalidate()?;
        Ok(self.opened.path.clone())
    }
    pub(in crate::store) fn expected_sha256(&self) -> Result<Sha256Digest> {
        self.revalidate()?;
        self.observed.sha256.ok_or(StoreError::Changed)
    }
    pub(in crate::store) fn retained_file(&self) -> Result<&File> {
        self.revalidate()?;
        Ok(&self.opened.file)
    }
}
