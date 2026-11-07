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

/// Read-only bytes in an existing local installation. Ordinary read grants are
/// permitted; modifying grants and the original namespace remain protected by
/// the same local-image ACL and retained HANDLE checks. Never a private store,
/// writer, publisher grant or executable launch authority.
pub(crate) struct LocalFile {
    path: PathBuf,
    file: File,
    parents: Vec<File>,
    facts: ffi::Facts,
    digest: Sha256Digest,
}
impl LocalFile {
    pub(crate) fn open(path: &Path, max_bytes: u64) -> Result<Self> {
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
        if facts.observation.byte_len == 0 || facts.observation.byte_len > max_bytes {
            return Err(StoreError::TooLarge);
        }
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
    pub(crate) fn digest(&self) -> Sha256Digest {
        self.digest
    }
    pub(crate) fn read_bytes(&self, max_bytes: usize) -> Result<Vec<u8>> {
        use std::os::windows::fs::FileExt;
        self.revalidate()?;
        let len =
            usize::try_from(self.facts.observation.byte_len).map_err(|_| StoreError::TooLarge)?;
        if len > max_bytes {
            return Err(StoreError::TooLarge);
        }
        let mut bytes = vec![0; len];
        let mut offset = 0;
        while offset < len {
            let read = self.file.seek_read(&mut bytes[offset..], offset as u64)?;
            if read == 0 {
                return Err(StoreError::Changed);
            }
            offset += read;
        }
        if Sha256Digest::of_bytes(&bytes) != self.digest {
            return Err(StoreError::Changed);
        }
        self.revalidate()?;
        Ok(bytes)
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

/// Local PE bytes selected through protected configuration, not a signed worker.
/// Chrome's OS/vendor library closure remains in the same local-admin boundary.
/// The PE64 restriction belongs to this launch boundary, not public data reads.
pub(crate) struct LocalExecutable {
    file: LocalFile,
}
impl LocalExecutable {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        let file = LocalFile::open(path, 512 * 1024 * 1024)?;
        payload_backend::check_pe64(&file.file, file.facts.observation.byte_len)?;
        Ok(Self { file })
    }
    pub(crate) fn path(&self) -> &Path {
        &self.file.path
    }
    pub(crate) fn revalidate(&self) -> Result<()> {
        self.file.revalidate()
    }
}

#[cfg(test)]
mod public_file_tests {
    use super::*;

    struct Fixture(PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn acl(path: &Path, arguments: &[&str]) {
        let tool =
            PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32/icacls.exe");
        let result = std::process::Command::new(tool)
            .arg(path)
            .args(arguments)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "owned ACL fixture operation failed"
        );
    }

    #[test]
    fn public_install_reads_keep_confidentiality_and_modification_boundaries_distinct() {
        // The shared build TEMP has writable ancestors. Allocate our fresh
        // protected fixture directly on its volume, without changing any
        // existing ancestor ACL or weakening the public-file guard.
        let temp = std::env::temp_dir();
        assert!(temp.is_absolute());
        let volume_root = temp.ancestors().last().unwrap();
        let path = volume_root.join(format!(
            "styx-public-install-read-{}",
            uuid::Uuid::new_v4().simple()
        ));
        ffi::create_new_private_directory(&path).unwrap();
        let _fixture = Fixture(path.clone());
        let metadata = path.join("windows-runtime.json");
        let bytes = br#"{"desktopApp":{"path":"StyxPreview.exe"}}"#;
        let mut writer = ffi::create_new_private_file(&metadata).unwrap();
        writer.write_all(bytes).unwrap();
        drop(writer);
        // Real effective read/execute ACEs on both the installation directory
        // and data file reproduce the installed-package compatibility issue.
        acl(&path, &["/grant", "*S-1-1-0:(OI)(CI)(RX)"]);
        acl(&metadata, &["/grant", "*S-1-1-0:(R)"]);
        assert!(matches!(Root::open(&path), Err(StoreError::NotPrivate)));
        let installation = crate::store::PublicInstallationRoot::open(&path).unwrap();
        let raw = installation
            .read_raw("windows-runtime.json", 16384)
            .unwrap();
        assert_eq!(raw.bytes(), bytes);
        let _raw_pin = installation.retain_raw_file(&raw).unwrap();
        let inventory = installation
            .payload_inventory_with_known(
                crate::store::PayloadLimits::default(),
                &crate::store::KnownDigests::new(),
            )
            .unwrap();
        assert_eq!(inventory.members().len(), 1);
        inventory.revalidate().unwrap();
        // A read-only installation cannot mint a writer through its backend.
        assert!(
            installation
                .inner
                .open_relative(Path::new("new"), false, true, true)
                .is_err()
        );
        let pinned = LocalFile::open(&metadata, 16384).unwrap();
        assert_eq!(pinned.read_bytes(16384).unwrap(), bytes);
        assert!(pinned.digest() == Sha256Digest::of_bytes(bytes));
        assert!(matches!(pinned.read_bytes(4), Err(StoreError::TooLarge)));
        assert!(
            LocalExecutable::open(&metadata).is_err(),
            "data is not a PE launch"
        );
        // Original handles independently prevent overwrite and replacement.
        assert!(
            std::fs::OpenOptions::new()
                .write(true)
                .open(&metadata)
                .is_err()
        );
        assert!(std::fs::remove_file(&metadata).is_err());
        acl(&path, &["/grant", "*S-1-1-0:(W)"]);
        assert!(matches!(pinned.revalidate(), Err(StoreError::NotPrivate)));
        assert!(LocalFile::open(&metadata, 16384).is_err());
        assert!(
            installation
                .read_raw("windows-runtime.json", 16384)
                .is_err()
        );
        assert!(inventory.revalidate().is_err());
        acl(&path, &["/remove:g", "*S-1-1-0"]);
        acl(&path, &["/grant", "*S-1-1-0:(OI)(CI)(RX)"]);
        pinned.revalidate().unwrap();
        assert_eq!(pinned.read_bytes(16384).unwrap(), bytes);
        assert_eq!(
            installation
                .read_raw("windows-runtime.json", 16384)
                .unwrap()
                .bytes(),
            bytes
        );
        acl(&metadata, &["/grant", "*S-1-1-0:(W)"]);
        assert!(matches!(pinned.revalidate(), Err(StoreError::NotPrivate)));
        assert!(LocalFile::open(&metadata, 16384).is_err());
        assert!(
            installation
                .read_raw("windows-runtime.json", 16384)
                .is_err()
        );
    }
}
