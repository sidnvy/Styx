//! Runtime assets and explicitly selected local browser images. These are not
//! publisher grants or configuration transactions. Retained Windows handles
//! prevent replacement; existing ACLs are inspected, never rewritten.
use super::*;
use styx_contracts::identity::Sha256Digest;

impl Root {
    pub(in crate::store) fn create_runtime_asset(
        &self,
        name: &str,
        bytes: &[u8],
    ) -> Result<(RawFile, File)> {
        component(OsStr::new(name))?;
        if name.encode_utf16().count() > 255 || bytes.is_empty() || bytes.len() > 1024 * 1024 {
            return Err(StoreError::TooLarge);
        }
        self.with_readonly_directory(|_| {
            let path = self.path.join(name);
            let mut writer = ffi::create_new_private_file(&path)?;
            let initial = private_facts(&writer, false)?;
            writer.write_all(bytes)?;
            ffi::flush_file(&writer)?;
            let written = private_facts(&writer, false)?;
            if initial.observation.device != written.observation.device
                || initial.observation.inode != written.observation.inode
                || written.observation.byte_len != bytes.len() as u64
            {
                return Err(StoreError::Changed);
            }
            drop(writer);
            let held = self.open_relative(Path::new(name), false, false, false)?;
            let facts = private_facts(&held.file, false)?;
            let observed = self.read_raw(Path::new(name), bytes.len())?;
            if facts.observation.device != written.observation.device
                || facts.observation.inode != written.observation.inode
                || observed.observation() != &facts.observation
                || observed.bytes() != bytes
            {
                return Err(StoreError::Changed);
            }
            self.validate_root()?;
            Ok((observed, held.file))
        })
    }
}

/// Local PE bytes selected through protected configuration, not a signed worker.
/// Chrome's OS/vendor library closure remains in the same local-admin boundary.
pub(crate) struct LocalExecutable {
    path: PathBuf,
    file: File,
    parents: Vec<File>,
    facts: ffi::Facts,
    digest: Sha256Digest,
}
impl LocalExecutable {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        let path = normalized_root(path)?;
        let parent = path.parent().ok_or(StoreError::InvalidRoot)?;
        let (_, parents) = absolute_pins(parent)?;
        // Volume roots may legitimately permit creation of other directories;
        // their retained non-delete-shared handles still bind this exact chain.
        for dir in parents.iter().skip(1) {
            ffi::local_executable_acl(dir)?;
        }
        let file = ffi::open(&path, false, false, false)?;
        ffi::require_no_streams(&path)?;
        ffi::local_executable_acl(&file)?;
        let facts = ffi::facts(&file)?;
        if facts.observation.byte_len == 0 || facts.observation.byte_len > 512 * 1024 * 1024 {
            return Err(StoreError::TooLarge);
        }
        payload_backend::check_pe64(&file, facts.observation.byte_len)?;
        let digest = payload_backend::stream_hash(&file, facts.observation.byte_len)?;
        let image = Self {
            path,
            file,
            parents,
            facts,
            digest,
        };
        image.revalidate()?;
        Ok(image)
    }
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
    pub(crate) fn revalidate(&self) -> Result<()> {
        for dir in self.parents.iter().skip(1) {
            ffi::facts(dir)?;
            ffi::local_executable_acl(dir)?;
        }
        let current = ffi::open(&self.path, false, false, false)?;
        ffi::require_no_streams(&self.path)?;
        for file in [&self.file, &current] {
            ffi::local_executable_acl(file)?;
            if ffi::facts(file)? != self.facts
                || payload_backend::stream_hash(file, self.facts.observation.byte_len)?
                    != self.digest
            {
                return Err(StoreError::Changed);
            }
        }
        Ok(())
    }
}
