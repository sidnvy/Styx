//! Shared Unix descriptor-relative release publication, using existing OS policy.
use super::*;
impl Root {
    pub(in crate::store) fn release_open(
        &self,
        relative: &Path,
    ) -> Result<(File, FileObservation)> {
        self.validate_root()?;
        let (directory, name) = self.parent(relative)?;
        let file = open_at(
            &directory,
            &name,
            OFlag::O_RDONLY | OFlag::O_NONBLOCK,
            Mode::empty(),
        )?;
        let facts = observation(&private_file(&file)?);
        self.validate_root()?;
        Ok((file, facts))
    }
    pub(in crate::store) fn release_observe(&self, file: &File) -> Result<FileObservation> {
        self.validate_root()?;
        Ok(observation(&private_file(file)?))
    }
    pub(in crate::store) fn release_create(&self, name: &OsStr) -> Result<File> {
        single_component(name)?;
        self.validate_root()?;
        let file = open_at(
            &self.directory,
            name,
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NONBLOCK,
            Mode::S_IRUSR | Mode::S_IWUSR,
        )?;
        private_file(&file)?;
        Ok(file)
    }
    pub(in crate::store) fn release_flush(&self, file: &File, executable: bool) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        private_file(file)?;
        file.set_permissions(std::fs::Permissions::from_mode(if executable {
            0o700
        } else {
            0o600
        }))?;
        #[cfg(target_os = "macos")]
        {
            sync_descriptor(file)?;
            sync_descriptor(&self.directory)?;
        }
        #[cfg(target_os = "linux")]
        {
            file.sync_all()?;
            self.directory.sync_all()?;
        }
        self.validate_root()?;
        Ok(())
    }
}
