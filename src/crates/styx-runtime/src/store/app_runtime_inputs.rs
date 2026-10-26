//! Fixed App input directories and exclusive immutable input publication.
//! The original container writer owns these inputs; C07 remains the only state ledger.
use super::*;

impl Root {
    pub(in crate::store) fn app_runtime_directory(
        &self,
        writer: &ConfigurationWriterGuard,
        name: &str,
    ) -> Result<Self> {
        if !matches!(name, "runtime-versions" | "runtime-updates") {
            return Err(StoreError::InvalidRelativePath);
        }
        self.with_configuration_writer_directory(writer, |_| {
            // Existing fixed containers are inspected as-is. Individual release
            // directories and input files are still exclusively created.
            let child = if self.ensure_absent(Path::new(name)).is_ok() {
                self.create_fresh_child(OsStr::new(name))
                    .map_err(|failure| failure.cause)?
            } else {
                Self::open(&self.path.join(name))?
            };
            child.validate_root()?;
            Ok(child)
        })
    }
    pub(in crate::store) fn app_runtime_file(
        &self,
        writer: &ConfigurationWriterGuard,
        directory: &Self,
        name: &str,
        bytes: &[u8],
    ) -> Result<RawFile> {
        if bytes.is_empty() || bytes.len() > 64 * 1024 {
            return Err(StoreError::TooLarge);
        }
        let stem = name
            .strip_suffix(".json")
            .ok_or(StoreError::InvalidRelativePath)?;
        let directory_name = directory.path.file_name().and_then(|name| name.to_str());
        let valid = match directory_name {
            Some("runtime-versions") => {
                stem.len() == 64
                    && stem
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            }
            Some("runtime-updates") => {
                styx_contracts::identity::TransactionId::try_from(stem).is_ok()
            }
            _ => false,
        };
        if !valid || directory.path.parent() != Some(self.path.as_path()) {
            return Err(StoreError::InvalidRelativePath);
        }
        self.with_configuration_writer_directory(writer, |_| {
            directory.validate_root()?;
            directory.ensure_absent(Path::new(name))?;
            directory.create_private_export(name, bytes, &|_| {})?;
            let original = directory.read_raw(Path::new(name), bytes.len())?;
            if original.bytes() != bytes {
                return Err(StoreError::Changed);
            }
            directory.validate_root()?;
            Ok(original)
        })
    }
}

#[cfg(all(test, target_os = "linux", target_env = "gnu"))]
mod tests {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, symlink};
    struct Fixture(PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn original_container_writer_bounds_immutable_app_inputs() {
        let path = std::env::temp_dir().join(format!("styx-app-inputs-{}", uuid::Uuid::new_v4()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        let fixture = Fixture(path);
        for name in ["owner", "foreign"] {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(fixture.0.join(name))
                .unwrap();
        }
        let owner = PrivateRoot::open(fixture.0.join("owner")).unwrap();
        let foreign = PrivateRoot::open(fixture.0.join("foreign")).unwrap();
        let writer = owner.try_configuration_writer().unwrap();
        let other_writer = foreign.try_configuration_writer().unwrap();
        assert!(
            owner
                .prepare_app_runtime_directory(&other_writer, "runtime-updates")
                .is_err()
        );
        assert!(!fixture.0.join("owner/runtime-updates").exists());
        assert!(
            owner
                .prepare_app_runtime_directory(&writer, "../foreign")
                .is_err()
        );
        let updates = owner
            .prepare_app_runtime_directory(&writer, "runtime-updates")
            .unwrap();
        let reopened = owner
            .prepare_app_runtime_directory(&writer, "runtime-updates")
            .unwrap();
        assert_eq!(updates.identity(), reopened.identity());
        let bytes = br#"{"schema":1,"original_input":true}"#;
        let raw = owner
            .publish_app_runtime_file(&writer, &updates, "update-one.json", bytes)
            .unwrap();
        assert_eq!(raw.bytes(), bytes);
        assert_eq!(
            std::fs::metadata(fixture.0.join("owner/runtime-updates/update-one.json"))
                .unwrap()
                .mode()
                & 0o7777,
            0o600
        );
        assert!(
            owner
                .publish_app_runtime_file(&writer, &updates, "update-one.json", b"replacement")
                .is_err()
        );
        assert_eq!(
            updates.read_raw("update-one.json", 1024).unwrap().bytes(),
            bytes
        );
        let outside = foreign
            .prepare_app_runtime_directory(&other_writer, "runtime-updates")
            .unwrap();
        assert!(
            owner
                .publish_app_runtime_file(&writer, &outside, "update-two.json", bytes)
                .is_err()
        );
        assert!(outside.ensure_absent("update-two.json").is_ok());
        assert!(
            owner
                .publish_app_runtime_file(&other_writer, &updates, "update-two.json", bytes)
                .is_err()
        );
        let versions = owner
            .prepare_app_runtime_directory(&writer, "runtime-versions")
            .unwrap();
        assert!(
            owner
                .publish_app_runtime_file(&writer, &versions, "not-a-digest.json", bytes)
                .is_err()
        );
        let name = format!("{}.json", "a".repeat(64));
        owner
            .publish_app_runtime_file(&writer, &versions, &name, bytes)
            .unwrap();
        assert!(
            owner
                .publish_app_runtime_file(
                    &writer,
                    &versions,
                    &format!("{}.json", "b".repeat(64)),
                    &vec![1; 64 * 1024 + 1]
                )
                .is_err()
        );
        symlink(
            fixture.0.join("foreign/runtime-updates"),
            fixture.0.join("foreign/runtime-versions"),
        )
        .unwrap();
        assert!(
            foreign
                .prepare_app_runtime_directory(&other_writer, "runtime-versions")
                .is_err()
        );
    }
}
