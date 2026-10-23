//! Descriptor-relative inventory and streaming hashes using safe nix/std APIs.
use super::*;
use crate::store::payload::{PayloadInventory, PayloadLimits, PayloadMember};
use nix::dir::Dir;
use std::{
    collections::BTreeMap,
    os::{fd::AsRawFd, unix::ffi::OsStringExt},
};
use styx_contracts::identity::Sha256Digest;
#[derive(Clone)]
struct Observed {
    facts: FileObservation,
    executable: bool,
    directory: bool,
}
pub(in crate::store) struct PayloadSnapshot {
    root: Root,
    observed: BTreeMap<PathBuf, Observed>,
}
pub(in crate::store) struct PinnedImage {
    root: Root,
    relative: PathBuf,
    file: File,
    observed: Observed,
    creator: ProcessIdentity,
}
fn observe(file: &File, directory: bool) -> Result<Observed> {
    let metadata = file.metadata()?;
    private(&metadata)?;
    if directory {
        if !metadata.is_dir() {
            return Err(StoreError::NotRegularFile);
        }
    } else {
        private_file(file)?;
    }
    Ok(Observed {
        facts: observation(&metadata),
        executable: metadata.mode() & 0o100 != 0,
        directory,
    })
}
fn same(a: &Observed, b: &Observed) -> bool {
    a.facts == b.facts && a.executable == b.executable && a.directory == b.directory
}
fn child(root: &Root, relative: &Path, directory: bool) -> Result<File> {
    if relative.as_os_str().is_empty() {
        return root.directory.try_clone().map_err(StoreError::from);
    }
    let (parent, name) = root.parent(relative)?;
    open_at(
        &parent,
        &name,
        OFlag::O_RDONLY
            | OFlag::O_NONBLOCK
            | if directory {
                OFlag::O_DIRECTORY
            } else {
                OFlag::empty()
            },
        Mode::empty(),
    )
}
fn stream_hash(file: &File, max: u64) -> Result<Sha256Digest> {
    use std::io::{Seek, SeekFrom};
    let mut reader = file.try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    let mut reader = reader.take(max.saturating_add(1));
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut total = 0u64;
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        total = total.checked_add(n as u64).ok_or(StoreError::TooLarge)?;
        if total > max {
            return Err(StoreError::TooLarge);
        }
        hash.update(&buffer[..n]);
    }
    Sha256Digest::try_from(hex::encode(hash.finalize())).map_err(|_| StoreError::Changed)
}
impl Root {
    pub(in crate::store) fn payload_inventory(
        &self,
        limits: PayloadLimits,
    ) -> Result<PayloadInventory> {
        self.validate_root()?;
        let mut observed = BTreeMap::new();
        let mut members = Vec::new();
        let mut bytes = 0u64;
        let mut dirs = 0usize;
        self.walk_payload(
            Path::new(""),
            0,
            limits,
            &mut observed,
            &mut members,
            &mut bytes,
            &mut dirs,
        )?;
        members.sort_by(|a, b| a.path.cmp(&b.path));
        let inner = PayloadSnapshot {
            root: self.clone(),
            observed,
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
        bytes: &mut u64,
        dirs: &mut usize,
    ) -> Result<()> {
        if depth > limits.max_depth || *dirs >= limits.max_directories {
            return Err(StoreError::TooLarge);
        }
        let directory = child(self, relative, true)?;
        let before = observe(&directory, true)?;
        *dirs += 1;
        // Open a new file description: dup would share/reuse a directory offset.
        let listing = open_at(
            &directory,
            OsStr::new("."),
            OFlag::O_RDONLY | OFlag::O_DIRECTORY,
            Mode::empty(),
        )?;
        let mut listing = Dir::from_fd(listing.into())
            .map_err(|e| StoreError::Io(std::io::Error::from_raw_os_error(e as i32)))?;
        let mut names = Vec::new();
        for entry in listing.iter() {
            let entry =
                entry.map_err(|e| StoreError::Io(std::io::Error::from_raw_os_error(e as i32)))?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            if names.len() >= limits.max_files + limits.max_directories {
                return Err(StoreError::TooLarge);
            }
            names.push(OsString::from_vec(name.to_vec()));
        }
        for name in names {
            let path = relative.join(&name);
            checked_relative(&path)?;
            let file = open_at(
                &directory,
                &name,
                OFlag::O_RDONLY | OFlag::O_NONBLOCK,
                Mode::empty(),
            )?;
            if file.metadata()?.is_dir() {
                self.walk_payload(&path, depth + 1, limits, observed, members, bytes, dirs)?;
                continue;
            }
            if members.len() >= limits.max_files {
                return Err(StoreError::TooLarge);
            }
            let facts = observe(&file, false)?;
            if facts.facts.byte_len > limits.max_file_bytes {
                return Err(StoreError::TooLarge);
            }
            *bytes = bytes
                .checked_add(facts.facts.byte_len)
                .ok_or(StoreError::TooLarge)?;
            if *bytes > limits.max_total_bytes {
                return Err(StoreError::TooLarge);
            }
            let digest = stream_hash(&file, facts.facts.byte_len)?;
            if !same(&facts, &observe(&file, false)?)
                || !same(&facts, &observe(&child(self, &path, false)?, false)?)
            {
                return Err(StoreError::Changed);
            }
            members.push(PayloadMember {
                path: path.clone(),
                bytes: facts.facts.byte_len,
                sha256: digest,
                executable: facts.executable,
            });
            observed.insert(path, facts);
        }
        if !same(&before, &observe(&directory, true)?)
            || !same(&before, &observe(&child(self, relative, true)?, true)?)
        {
            return Err(StoreError::Changed);
        }
        observed.insert(relative.to_path_buf(), before);
        Ok(())
    }
}
impl PayloadSnapshot {
    pub(in crate::store) fn revalidate(&self) -> Result<()> {
        self.root.validate_root()?;
        for (path, before) in &self.observed {
            if !same(
                before,
                &observe(
                    &child(&self.root, path, before.directory)?,
                    before.directory,
                )?,
            ) {
                return Err(StoreError::Changed);
            }
        }
        self.root.validate_root()
    }
    pub(in crate::store) fn pin_executable(&self, path: &Path) -> Result<PinnedImage> {
        self.revalidate()?;
        let observed = self
            .observed
            .get(path)
            .filter(|o| !o.directory && o.executable)
            .ok_or(StoreError::NotRegularFile)?
            .clone();
        let file = child(&self.root, path, false)?;
        if !same(&observed, &observe(&file, false)?) {
            return Err(StoreError::Changed);
        }
        // This is a native executable pin; never leave a script reopening a path.
        use std::io::{Seek, SeekFrom};
        let mut reader = file.try_clone()?;
        reader.seek(SeekFrom::Start(0))?;
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if &magic != b"\x7fELF" {
            return Err(StoreError::NotRegularFile);
        }
        let image = PinnedImage {
            root: self.root.clone(),
            relative: path.to_path_buf(),
            file,
            observed,
            creator: ProcessIdentity::current()?,
        };
        image.revalidate()?;
        Ok(image)
    }
}
impl PinnedImage {
    pub(in crate::store) fn revalidate(&self) -> Result<()> {
        if !self.creator.still_current()? {
            return Err(StoreError::ProcessIdentityUnavailable);
        }
        self.root.validate_root()?;
        if !same(&self.observed, &observe(&self.file, false)?)
            || !same(
                &self.observed,
                &observe(&child(&self.root, &self.relative, false)?, false)?,
            )
        {
            return Err(StoreError::Changed);
        }
        Ok(())
    }
    pub(in crate::store) fn launch_path(&self) -> Result<PathBuf> {
        self.revalidate()?;
        Ok(PathBuf::from(format!(
            "/proc/{}/fd/{}",
            std::process::id(),
            self.file.as_raw_fd()
        )))
    }
}
