//! Existing private Windows CREATE_NEW, no-reparse/ADS and real flush policy.
use super::*;
impl Root {
    pub(in crate::store) fn release_open(
        &self,
        relative: &Path,
    ) -> Result<(File, FileObservation)> {
        self.validate_root()?;
        let opened = self.open_relative(relative, false, false, false)?;
        let facts = private_facts(&opened.file, false)?;
        ffi::require_no_streams(&opened.path)?;
        self.validate_root()?;
        Ok((opened.file, facts.observation))
    }
    pub(in crate::store) fn release_observe(&self, file: &File) -> Result<FileObservation> {
        self.validate_root()?;
        Ok(private_facts(file, false)?.observation)
    }
    pub(in crate::store) fn release_create(&self, name: &OsStr) -> Result<File> {
        component(name)?;
        self.validate_root()?;
        ffi::require_local_ntfs(&self.path, &self.directory)?;
        let path = self.path.join(name);
        let file = ffi::create_new_private_file(&path)?;
        private_facts(&file, false)?;
        ffi::require_no_streams(&path)?;
        self.validate_root()?;
        Ok(file)
    }
    pub(in crate::store) fn release_flush(&self, file: &File, _executable: bool) -> Result<()> {
        private_facts(file, false)?;
        ffi::flush_file(file)?;
        self.sync_directory()?;
        self.validate_root()?;
        Ok(())
    }
}
