//! macOS descriptor-relative signed-payload observations. No path-launch fallback.
//! Uses existing MacRoot private/empty-ACL checks and safe nix/std ownership.
#[path = "macos_signed_app.rs"]
pub(in crate::store) mod signed_app;
use super::*;
use crate::store::payload::{
    KnownDigests, PayloadInventory, PayloadLimits, PayloadMember, known_digest,
};
use nix::dir::Dir;
use std::{collections::BTreeMap, os::unix::ffi::OsStringExt};
use styx_contracts::identity::Sha256Digest;
#[derive(Clone)]
struct Observed {
    facts: FileObservation,
    executable: bool,
    directory: bool,
    sha256: Option<Sha256Digest>,
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
    let metadata = private_descriptor(file)?;
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
        sha256: None,
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
        known: &KnownDigests,
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
            known,
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
        known: &KnownDigests,
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
                self.walk_payload(
                    &path,
                    depth + 1,
                    limits,
                    observed,
                    members,
                    bytes,
                    dirs,
                    known,
                )?;
                continue;
            }
            if members.len() >= limits.max_files {
                return Err(StoreError::TooLarge);
            }
            let mut facts = observe(&file, false)?;
            if facts.facts.byte_len > limits.max_file_bytes {
                return Err(StoreError::TooLarge);
            }
            *bytes = bytes
                .checked_add(facts.facts.byte_len)
                .ok_or(StoreError::TooLarge)?;
            if *bytes > limits.max_total_bytes {
                return Err(StoreError::TooLarge);
            }
            let digest = match known_digest(known, &path, &facts.facts) {
                Some(digest) => digest,
                None => stream_hash(&file, facts.facts.byte_len)?,
            };
            // The name is re-resolved in the held directory; that directory's
            // own path from the root is re-checked after its last entry below.
            if !same(&facts, &observe(&file, false)?)
                || !same(
                    &facts,
                    &observe(
                        &open_at(
                            &directory,
                            &name,
                            OFlag::O_RDONLY | OFlag::O_NONBLOCK,
                            Mode::empty(),
                        )?,
                        false,
                    )?,
                )
            {
                return Err(StoreError::Changed);
            }
            facts.sha256 = Some(digest);
            members.push(PayloadMember {
                path: path.clone(),
                bytes: facts.facts.byte_len,
                sha256: digest,
                executable: facts.executable,
                observation: facts.facts.clone(),
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
        // Sorted paths list each directory right before its contents, so every
        // entry is reopened once relative to its already re-observed parent
        // instead of walking from the root. Only the ancestor chain stays open.
        let mut parents: Vec<(&Path, File)> = Vec::new();
        for (path, before) in &self.observed {
            let parent = path.parent();
            while parents.last().is_some_and(|(p, _)| Some(*p) != parent) {
                parents.pop();
            }
            let file = match (parents.last(), path.file_name()) {
                (Some((_, directory)), Some(name)) => open_at(
                    directory,
                    name,
                    OFlag::O_RDONLY
                        | OFlag::O_NONBLOCK
                        | if before.directory {
                            OFlag::O_DIRECTORY
                        } else {
                            OFlag::empty()
                        },
                    Mode::empty(),
                )?,
                _ => child(&self.root, path, before.directory)?,
            };
            if !same(before, &observe(&file, before.directory)?) {
                return Err(StoreError::Changed);
            }
            if before.directory {
                parents.push((path, file));
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
        // Only modern thin native Mach-O executables. The OS loader remains
        // responsible for full Mach-O/signature validation; this is a bounded
        // type/architecture guard, never a handwritten executable loader.
        use std::io::{Seek, SeekFrom};
        let mut reader = file.try_clone()?;
        reader.seek(SeekFrom::Start(0))?;
        if observed.facts.byte_len < 32 {
            return Err(StoreError::Unsupported);
        }
        let mut header = [0u8; 32];
        reader.read_exact(&mut header)?;
        let cpu = match std::env::consts::ARCH {
            "x86_64" => 0x0100_0007_u32,
            "aarch64" => 0x0100_000c_u32,
            _ => return Err(StoreError::Unsupported),
        };
        if header[..4] != [0xcf, 0xfa, 0xed, 0xfe]
            || u32::from_le_bytes(header[4..8].try_into().expect("fixed header")) != cpu
            || u32::from_le_bytes(header[12..16].try_into().expect("fixed header")) != 2
        {
            return Err(StoreError::Unsupported);
        }
        if observed.sha256.is_none() {
            return Err(StoreError::Changed);
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
        // Darwin rejects held-FD /dev/fd exec in the actual owned spike.
        // A later START_SUSPENDED trusted-spawn port must attest the original
        // loaded image before resume. Do not silently return a mutable pathname.
        Err(StoreError::Unsupported)
    }
}

impl PinnedImage {
    /// Original locator for the suspended, image-attested spawn adapter only.
    /// This does not authorize ordinary path execution.
    pub(in crate::store) fn source_path_for_suspended_spawn(&self) -> Result<PathBuf> {
        self.revalidate()?;
        let expected = self.observed.sha256.ok_or(StoreError::Changed)?;
        if stream_hash(&self.file, self.observed.facts.byte_len)? != expected {
            return Err(StoreError::Changed);
        }
        let path = self.root.path.join(&self.relative);
        self.revalidate()?;
        Ok(path)
    }
    /// Static signing identity of the already publisher-verified original image.
    /// A CDHash is additional loaded-image evidence, never publisher authority.
    pub(in crate::store) fn expected_cdhash(&self) -> Result<Vec<u8>> {
        use core_foundation::url::CFURL;
        use security_framework::os::macos::code_signing::{Flags, SecRequirement, SecStaticCode};
        let path = self.source_path_for_suspended_spawn()?;
        let url = CFURL::from_path(&path, false).ok_or(StoreError::Unsupported)?;
        let code =
            SecStaticCode::from_path(&url, Flags::NONE).map_err(|_| StoreError::Unsupported)?;
        let hash = signing_information::cdhash(&code)?;
        let requirement: SecRequirement = format!("cdhash H\"{}\"", hex::encode(&hash))
            .parse()
            .map_err(|_| StoreError::Unsupported)?;
        code.check_validity(Flags::NO_NETWORK_ACCESS, &requirement)
            .map_err(|_| StoreError::Changed)?;
        self.source_path_for_suspended_spawn()?;
        Ok(hash)
    }
    pub(in crate::store) fn expected_sha256(&self) -> Result<Sha256Digest> {
        self.revalidate()?;
        self.observed.sha256.ok_or(StoreError::Changed)
    }
    pub(in crate::store) fn retained_file(&self) -> Result<&File> {
        self.revalidate()?;
        Ok(&self.file)
    }
}

#[cfg(test)]
#[path = "macos_payload_tests.rs"]
mod tests;

// SDK: Security.framework/Headers/SecCode.h, SecCodeCopySigningInformation
// and kSecCodeInfoUnique. Installed Xcode SDK declaration was read on pho.
// security-framework 3.7/sys 2.17 omit this narrow API. All CF ownership and
// runtime type checks remain in mature core-foundation wrappers.
#[allow(unsafe_code)]
mod signing_information {
    use super::*;
    use core_foundation::{
        base::{CFType, TCFType},
        data::CFData,
        dictionary::{CFDictionary, CFDictionaryRef},
        string::{CFString, CFStringRef},
    };
    use security_framework::os::macos::code_signing::SecStaticCode;
    use security_framework_sys::code_signing::SecStaticCodeRef;

    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        fn SecCodeCopySigningInformation(
            code: SecStaticCodeRef,
            flags: u32,
            information: *mut CFDictionaryRef,
        ) -> i32;
        static kSecCodeInfoUnique: CFStringRef;
    }
    pub(super) fn cdhash(code: &SecStaticCode) -> Result<Vec<u8>> {
        let mut raw = std::ptr::null();
        // SAFETY: code is a retained SecStaticCode. SDK declares an owned
        // CFDictionary (+1 Create rule) on success; null/error is never wrapped.
        let status =
            unsafe { SecCodeCopySigningInformation(code.as_concrete_TypeRef(), 1 << 1, &mut raw) };
        if status != 0 || raw.is_null() {
            return Err(StoreError::Unsupported);
        }
        // SAFETY: successful SDK output owns a dictionary. The documented keys
        // are CFString and values CFType; each value is dynamically downcast.
        let dictionary: CFDictionary<CFString, CFType> =
            unsafe { CFDictionary::wrap_under_create_rule(raw) };
        // SAFETY: SDK exports a process-lifetime non-null CFString constant;
        // Get rule retains it. No custom CF layout or unchecked data cast.
        let key = unsafe { CFString::wrap_under_get_rule(kSecCodeInfoUnique) };
        let value = dictionary.find(&key).ok_or(StoreError::Unsupported)?;
        let data = value.downcast::<CFData>().ok_or(StoreError::Unsupported)?;
        // Apple CDHash is normally truncated SHA-1/SHA-256 (20 bytes); accept
        // a full 32-byte digest only as a bounded typed algorithm representation.
        if !matches!(data.len(), 20 | 32) {
            return Err(StoreError::Unsupported);
        }
        Ok(data.bytes().to_vec())
    }
}
