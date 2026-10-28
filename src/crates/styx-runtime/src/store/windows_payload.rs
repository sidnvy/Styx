//! Bounded protected Windows payload closure. No mutable pathname execution.
use super::*;
use crate::store::payload::{
    KnownDigests, PayloadInventory, PayloadLimits, PayloadMember, known_digest,
};
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
pub(super) fn stream_hash(file: &File, max: u64) -> Result<Sha256Digest> {
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
            "workers/tunnel-client/tunnel-client-runtime.exe",
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
    /// Bind this original byte observation before retaining the existing
    /// ordinary-reader HANDLE. In particular, equal bytes in a new file ID
    /// between read_raw and this open must not become the approved input.
    pub(in crate::store) fn retain_raw_file(&self, original: &RawFile) -> Result<File> {
        self.validate_root()?;
        let opened = self.open_relative(original.relative_path(), false, false, false)?;
        let observed = observe(&opened, false)?;
        if observed.facts.observation != *original.observation()
            || observed.facts.observation.byte_len != original.bytes().len() as u64
            || stream_hash(&opened.file, observed.facts.observation.byte_len)?
                != Sha256Digest::of_bytes(original.bytes())
        {
            return Err(StoreError::Changed);
        }
        let current = self.open_relative(original.relative_path(), false, false, false)?;
        if !same(&observed, &observe(&opened, false)?)
            || !same(&observed, &observe(&current, false)?)
        {
            return Err(StoreError::Changed);
        }
        self.validate_root()?;
        Ok(opened.file)
    }

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
        known: &KnownDigests,
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
            known,
        )?;
        members.sort_by(|a, b| a.path.cmp(&b.path));
        self.validate_root()?;
        Ok((observed, members))
    }
    pub(in crate::store) fn payload_inventory(
        &self,
        limits: PayloadLimits,
        known: &KnownDigests,
    ) -> Result<PayloadInventory> {
        let (observed, members) = self.collect_payload(limits, known)?;
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
        known: &KnownDigests,
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
                    known,
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
                let digest = match known_digest(known, &path, &facts.facts.observation) {
                    Some(digest) => digest,
                    None => stream_hash(&opened.file, size)?,
                };
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
                    observation: facts.facts.observation.clone(),
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
        // Unchanged file metadata reuses this snapshot's own digests; only a
        // changed file is read again. Any difference is still refused below.
        let known: KnownDigests = self
            .observed
            .iter()
            .filter_map(|(path, seen)| {
                seen.sha256
                    .map(|digest| (path.clone(), (seen.facts.observation.clone(), digest)))
            })
            .collect();
        let (actual, _) = self.root.collect_payload(self.limits, &known)?;
        if actual != self.observed {
            return Err(StoreError::Changed);
        }
        Ok(())
    }
    pub(in crate::store) fn pin_executable(&self, path: &Path) -> Result<PinnedImage> {
        self.revalidate()?;
        self.pin_original_image(path)
    }
    /// The caller checked every relative locator and the bounded batch before
    /// entering this port. Both full observations refer to this SAME snapshot.
    pub(in crate::store) fn pin_executables(&self, paths: &[PathBuf]) -> Result<Vec<PinnedImage>> {
        #[cfg(test)]
        {
            self.pin_executables_inner(paths, None)
        }
        #[cfg(not(test))]
        {
            self.pin_executables_inner(paths)
        }
    }
    fn pin_executables_inner(
        &self,
        paths: &[PathBuf],
        #[cfg(test)] before_final: Option<&mut dyn FnMut() -> Result<()>>,
    ) -> Result<Vec<PinnedImage>> {
        self.revalidate()?;
        let images = paths
            .iter()
            .map(|path| self.pin_original_image(path))
            .collect::<Result<Vec<_>>>()?;
        #[cfg(test)]
        if let Some(observe) = before_final {
            observe()?;
        }
        self.revalidate()?;
        Ok(images)
    }
    fn pin_original_image(&self, path: &Path) -> Result<PinnedImage> {
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
pub(super) fn check_pe64(file: &File, len: u64) -> Result<()> {
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
        || !(64..=1024 * 1024).contains(&offset)
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
        // The retained handle denies write sharing, so the bytes hashed when this
        // image was pinned cannot change while it is held; metadata suffices.
        if !same(&self.observed, &observe(&self.opened, false)?)
            || !same(&self.observed, &observe(&current, false)?)
            || self.observed.sha256.is_none()
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

#[cfg(test)]
mod batch_tests {
    use super::*;
    use std::io::Write;

    fn private_copy(source: &Path, destination: &Path) {
        let mut input = File::open(source).unwrap();
        let mut output = ffi::create_new_private_file(destination).unwrap();
        std::io::copy(&mut input, &mut output).unwrap();
        ffi::flush_file(&output).unwrap();
    }

    #[test]
    fn windows_raw_file_pin_refuses_same_bytes_replacement_before_handle_and_rename_after() {
        let container = std::env::temp_dir().join(format!(
            "styx-raw-file-pin-{}",
            uuid::Uuid::new_v4().simple()
        ));
        ffi::create_new_private_directory(&container).unwrap();
        {
            let parent = Root::open(&container).unwrap();
            let root = parent
                .create_fresh_child(OsStr::new("input"))
                .unwrap_or_else(|_| panic!("fresh private raw input"));
            let original_path = root.path.join("publisher.pem");
            {
                let mut file = ffi::create_new_private_file(&original_path).unwrap();
                file.write_all(b"same original public input").unwrap();
                ffi::flush_file(&file).unwrap();
            }
            let original = root.read_raw(Path::new("publisher.pem"), 4096).unwrap();
            let replacement = container.join("replacement.pem");
            private_copy(&original_path, &replacement);
            std::fs::rename(&replacement, &original_path).unwrap();
            assert_eq!(std::fs::read(&original_path).unwrap(), original.bytes());
            assert!(matches!(
                root.retain_raw_file(&original),
                Err(StoreError::Changed)
            ));
            let current = root.read_raw(Path::new("publisher.pem"), 4096).unwrap();
            let pin = root.retain_raw_file(&current).unwrap();
            assert!(std::fs::rename(&original_path, root.path.join("moved.pem")).is_err());
            let after = root.read_raw(Path::new("publisher.pem"), 4096).unwrap();
            assert_eq!(after.observation(), current.observation());
            assert_eq!(after.bytes(), current.bytes());
            drop(pin);
        }
        std::fs::remove_dir_all(&container).unwrap();
    }

    #[test]
    fn windows_batch_pins_refuse_original_nonentry_replacement_between_observations() {
        // Actual owned NTFS files and PE images; no package signer, process
        // launch, service, permission grant or external fixture is involved.
        let container = std::env::temp_dir().join(format!(
            "styx-payload-batch-{}",
            uuid::Uuid::new_v4().simple()
        ));
        ffi::create_new_private_directory(&container).unwrap();
        {
            let parent = Root::open(&container).unwrap();
            let root = parent
                .create_fresh_child(OsStr::new("payload"))
                .unwrap_or_else(|_| panic!("fresh private payload"));
            let bin = root
                .create_fresh_child(OsStr::new("bin"))
                .unwrap_or_else(|_| panic!("fresh private image directory"));
            let assets = root
                .create_fresh_child(OsStr::new("assets"))
                .unwrap_or_else(|_| panic!("fresh private asset directory"));
            let one = bin.path.join("one.exe");
            let two = bin.path.join("two.exe");
            private_copy(&std::env::current_exe().unwrap(), &one);
            private_copy(&std::env::current_exe().unwrap(), &two);
            let member = assets.path.join("member.txt");
            {
                let mut file = ffi::create_new_private_file(&member).unwrap();
                file.write_all(b"same approved member bytes").unwrap();
                ffi::flush_file(&file).unwrap();
            }
            let replacement = container.join("replacement.txt");
            private_copy(&member, &replacement);
            let inventory = root
                .payload_inventory(PayloadLimits::default(), &crate::store::KnownDigests::new())
                .unwrap();
            let paths = [Path::new("bin/one.exe"), Path::new("bin/two.exe")];
            let pins = inventory.pin_executables(&paths).unwrap();
            assert_eq!(pins[0].source_path_for_suspended_spawn().unwrap(), one);
            assert_eq!(pins[1].source_path_for_suspended_spawn().unwrap(), two);
            for pin in &pins {
                pin.revalidate().unwrap();
                assert!(matches!(pin.launch_path(), Err(StoreError::Unsupported)));
            }
            assert!(std::fs::rename(&one, bin.path.join("moved.exe")).is_err());
            assert!(std::fs::rename(&root.path, container.join("moved-root")).is_err());
            assert!(matches!(
                inventory.pin_executables(&[]),
                Err(StoreError::TooLarge)
            ));
            assert!(matches!(
                inventory.pin_executables(&[paths[0], Path::new("../escape")]),
                Err(StoreError::InvalidRelativePath)
            ));
            assert!(matches!(
                inventory.pin_executables(&[paths[0], Path::new("BIN/ONE.EXE")]),
                Err(StoreError::InvalidRelativePath)
            ));
            let mut replaced = false;
            let mut replace = || {
                // Same bytes, new actual file ID: individual image validation
                // cannot detect this unrelated signed member substitution.
                std::fs::rename(&replacement, &member)?;
                replaced = true;
                Ok(())
            };
            let relative = paths.iter().map(|p| p.to_path_buf()).collect::<Vec<_>>();
            assert!(matches!(
                inventory
                    .inner
                    .pin_executables_inner(&relative, Some(&mut replace)),
                Err(StoreError::Changed)
            ));
            assert!(replaced);
            assert_eq!(
                std::fs::read(&member).unwrap(),
                b"same approved member bytes"
            );
            assert!(matches!(inventory.revalidate(), Err(StoreError::Changed)));
            // The legacy public single-pin contract is still a full original
            // inventory observation, not merely this image's PE/hash check.
            assert!(matches!(
                inventory.pin_executable(paths[0]),
                Err(StoreError::Changed)
            ));
        }
        std::fs::remove_dir_all(&container).unwrap();
    }
}
