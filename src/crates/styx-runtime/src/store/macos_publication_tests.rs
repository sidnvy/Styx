//! Owned macOS filesystem operations, not native runtime or power-loss evidence.
use super::*;
use crate::store::secure_journal::{JournalBudget, JournalError, NamespaceName, files};
use std::{cell::RefCell, os::unix::fs::OpenOptionsExt};

#[test]
#[ignore = "STYX_TEST_NATIVE_STORE_ROOT; explicit private parent, real owned Mac filesystem only"]
fn macos_fresh_child_and_no_replace_publication_observations() {
    let path = PathBuf::from(
        std::env::var_os("STYX_TEST_NATIVE_STORE_ROOT").expect("explicit private parent"),
    );
    let parent = Root::open(&path).unwrap();
    let name = format!("publication-{}", uuid::Uuid::new_v4());
    let root = match parent.create_fresh_child(OsStr::new(&name)) {
        Ok(root) => root,
        Err(_) => panic!("fresh private directory creation failed"),
    };
    let failure = match parent.create_fresh_child(OsStr::new(&name)) {
        Ok(_) => panic!("existing directory adopted"),
        Err(failure) => failure,
    };
    assert!(!failure.created && failure.root.is_none());
    assert!(
        matches!(failure.cause, StoreError::Io(ref e) if e.kind() == std::io::ErrorKind::AlreadyExists)
    );
    let protected = PrivateRoot {
        inner: root.clone(),
    };
    let writer = protected.try_configuration_writer().unwrap();
    let phases = RefCell::new(Vec::new());
    let bytes = b"{\"opaque\":900719925474099312345,\"enabled\":false}\n";
    root.create_fixed(&writer, "material.json", bytes, &|phase| {
        phases.borrow_mut().push(phase.to_owned())
    })
    .unwrap();
    assert_eq!(
        phases.into_inner(),
        ["write", "file_sync", "directory_sync"]
    );
    let raw = root.read_raw(Path::new("material.json"), 1024).unwrap();
    assert_eq!(raw.bytes(), bytes);
    assert!(
        root.create_fixed(&writer, "material.json", b"replacement", &|_| {})
            .is_err()
    );
    let unchanged = root.read_raw(Path::new("material.json"), 1024).unwrap();
    assert_eq!(unchanged.observation(), raw.observation());
    assert_eq!(unchanged.bytes(), bytes);
    let other =
        match parent.create_fresh_child(OsStr::new(&format!("other-{}", uuid::Uuid::new_v4()))) {
            Ok(root) => root,
            Err(_) => panic!("second private directory creation failed"),
        };
    assert!(
        other
            .create_fixed(&writer, "foreign.json", b"forbidden", &|_| {})
            .is_err()
    );
    other.ensure_absent(Path::new("foreign.json")).unwrap();
    root.with_configuration_writer_directory(&writer, |directory| {
        Ok((|| {
            let identity = files::create_new_namespace(directory, NamespaceName::EnrollmentV1)?;
            assert_eq!(
                files::existing_namespace(directory, NamespaceName::EnrollmentV1)?,
                identity
            );
            assert!(matches!(
                files::create_new_namespace(directory, NamespaceName::EnrollmentV1),
                Err(JournalError::Conflict)
            ));
            let namespace = files::directory(directory, NamespaceName::EnrollmentV1.as_str())?;
            let budget = JournalBudget::default();
            files::immutable(
                &namespace,
                "record.json",
                b"original bytes",
                budget,
                &|_| {},
            )?;
            files::immutable(
                &namespace,
                "record.json",
                b"original bytes",
                budget,
                &|_| {},
            )?;
            assert!(matches!(
                files::immutable(&namespace, "record.json", b"different", budget, &|_| {}),
                Err(JournalError::Conflict)
            ));
            // Exercise the actual Darwin exclusive-rename refusal too. The
            // ordinary journal precheck alone cannot prove the kernel flag.
            let source_path = root
                .path
                .join(NamespaceName::EnrollmentV1.as_str())
                .join("exclusive-source.json");
            let mut source = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&source_path)
                .unwrap();
            source.write_all(b"retained exclusive source").unwrap();
            sync_private_file(&source).unwrap();
            let source_identity = observation(&source.metadata().unwrap());
            let target_before = root
                .read_raw(Path::new(".styx-enrollment-journal-v1/record.json"), 1024)
                .unwrap();
            assert!(
                matches!(rename_exclusive(&namespace, "exclusive-source.json",
                &namespace, "record.json"),
                Err(StoreError::Io(ref e)) if e.kind() == std::io::ErrorKind::AlreadyExists)
            );
            assert_eq!(observation(&source.metadata().unwrap()), source_identity);
            let target_after = root
                .read_raw(Path::new(".styx-enrollment-journal-v1/record.json"), 1024)
                .unwrap();
            assert_eq!(target_before.observation(), target_after.observation());
            assert_eq!(target_before.bytes(), target_after.bytes());
            assert_eq!(
                files::read(&namespace, "exclusive-source.json", 1024)?.as_deref(),
                Some(b"retained exclusive source".as_slice())
            );
            let limited = JournalBudget {
                max_files: 1,
                ..budget
            };
            assert!(matches!(
                files::immutable(&namespace, "extra.json", b"extra", limited, &|_| {}),
                Err(JournalError::BudgetExceeded)
            ));
            let old = 1000u64.to_be_bytes();
            let new = 2000u64.to_be_bytes();
            files::replace_observed(&namespace, "clock.floor", None, &old, budget, &|_| {})?;
            files::replace_observed(&namespace, "clock.floor", Some(&old), &new, budget, &|_| {})?;
            let synced = RefCell::new(Vec::new());
            files::replace_observed(
                &namespace,
                "clock.floor",
                Some(&new),
                &new,
                budget,
                &|phase| synced.borrow_mut().push(phase.to_owned()),
            )?;
            assert_eq!(synced.into_inner(), ["directory_sync"]);
            assert!(matches!(
                files::replace_observed(
                    &namespace,
                    "clock.floor",
                    Some(&old),
                    &new,
                    budget,
                    &|_| {}
                ),
                Err(JournalError::Conflict)
            ));
            assert_eq!(
                files::read(&namespace, "clock.floor", 8)?.as_deref(),
                Some(new.as_slice())
            );
            // A concurrent cooperative-contract violation must leave both the
            // independent target and our orphan; never overwrite or adopt it.
            let collision_path = root
                .path
                .join(NamespaceName::EnrollmentV1.as_str())
                .join("collision.json");
            let collision = files::immutable(
                &namespace,
                "collision.json",
                b"intended",
                budget,
                &|phase| {
                    if phase == "file_sync" {
                        let mut file = std::fs::OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .mode(0o600)
                            .open(&collision_path)
                            .unwrap();
                        file.write_all(b"independent original").unwrap();
                        file.sync_all().unwrap();
                    }
                },
            );
            assert!(collision.is_err());
            assert_eq!(
                files::read(&namespace, "collision.json", 1024)?.as_deref(),
                Some(b"independent original".as_slice())
            );
            assert_eq!(
                files::scan(&namespace, budget)?
                    .files
                    .iter()
                    .filter(|file| file.name.starts_with("orphan-"))
                    .count(),
                1
            );
            files::sync_file(&namespace, "record.json")?;
            files::sync_directory(&namespace)?;
            assert_eq!(
                files::existing_namespace(directory, NamespaceName::EnrollmentV1)?,
                identity
            );
            Ok::<_, JournalError>(())
        })())
    })
    .unwrap()
    .unwrap();
    writer.validate().unwrap();
    root.validate_root().unwrap();
    // Fixtures remain for independent observation; no cleanup hides a failure.
}
