//! Real owned Windows FS only: not native join, journal durability, or power loss.
use super::*;
use std::{
    cell::RefCell,
    panic::{AssertUnwindSafe, catch_unwind},
};

#[test]
#[ignore = "STYX_TEST_WINDOWS_STORE_ROOT; fresh private Windows FS publication observations only, no runtime/services or durable-commit claim"]
fn windows_fresh_child_and_no_replace_publication_observations() {
    let parent_path = PathBuf::from(
        std::env::var_os("STYX_TEST_WINDOWS_STORE_ROOT").expect("explicit owned private parent"),
    );
    let parent = Root::open(&parent_path).unwrap();
    let name = format!("publication-{}", uuid::Uuid::new_v4());
    let root = match parent.create_fresh_child(OsStr::new(&name)) {
        Ok(root) => root,
        Err(_) => panic!("fresh owned directory creation failed"),
    };
    let original_root = root.identity();
    let failure = match parent.create_fresh_child(OsStr::new(&name)) {
        Ok(_) => panic!("existing root adopted as fresh"),
        Err(failure) => failure,
    };
    assert!(!failure.created && failure.root.is_none());
    assert!(
        matches!(failure.cause, StoreError::Io(ref e) if e.kind() == std::io::ErrorKind::AlreadyExists)
    );
    assert_eq!(root.identity(), original_root);
    let protected = PrivateRoot {
        inner: root.clone(),
    };
    let guard = protected.try_configuration_writer().unwrap();
    let phases = RefCell::new(Vec::new());
    let bytes = b"{\"opaque\":900719925474099312345,\"enabled\":false}\n";
    root.create_fixed(&guard, "material.json", bytes, &|phase| {
        phases.borrow_mut().push(phase.to_owned());
    })
    .unwrap();
    let raw = root.read_raw(Path::new("material.json"), 1024).unwrap();
    assert_eq!(raw.bytes(), bytes);
    assert_eq!(
        phases.into_inner(),
        [
            "write",
            "file_sync",
            "directory_sync",
            "publication_observed"
        ]
    );
    assert!(
        root.create_fixed(&guard, "material.json", b"changed", &|_| {})
            .is_err()
    );
    let unchanged = root.read_raw(Path::new("material.json"), 1024).unwrap();
    assert_eq!(unchanged.observation(), raw.observation());
    assert_eq!(unchanged.bytes(), bytes);
    let other_name = format!("other-{}", uuid::Uuid::new_v4());
    let other = match parent.create_fresh_child(OsStr::new(&other_name)) {
        Ok(root) => root,
        Err(_) => panic!("second owned directory creation failed"),
    };
    assert!(
        other
            .create_fixed(&guard, "foreign.json", b"forbidden", &|_| {})
            .is_err()
    );
    other.ensure_absent(Path::new("foreign.json")).unwrap();
    // Stop inside the actual production fixed-write port after the write. The
    // final file remains, and another call must reject rather than repair or
    // overwrite it. This is a process-interruption boundary, not power-loss IO.
    let interrupted = catch_unwind(AssertUnwindSafe(|| {
        let _ = root.create_fixed(
            &guard,
            "interrupted.json",
            b"retained exact bytes",
            &|phase| {
                if phase == "write" {
                    panic!("owned fixed-write interruption");
                }
            },
        );
    }));
    assert!(interrupted.is_err());
    let interrupted_raw = root.read_raw(Path::new("interrupted.json"), 1024).unwrap();
    assert_eq!(interrupted_raw.bytes(), b"retained exact bytes");
    assert!(
        root.create_fixed(&guard, "interrupted.json", b"do not replace", &|_| {})
            .is_err()
    );
    let still_original = root.read_raw(Path::new("interrupted.json"), 1024).unwrap();
    assert_eq!(still_original.observation(), interrupted_raw.observation());
    assert_eq!(still_original.bytes(), interrupted_raw.bytes());
    // Same real held writer/namespace, through the production Windows files
    // module. No enrollment/Gateway grant or transaction receipt is fabricated.
    use crate::store::secure_journal::{JournalBudget, JournalError, NamespaceName, files};
    root.with_configuration_writer_directory(&guard, |directory| {
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
            files::sync_directory(&namespace)?;
            assert_eq!(
                files::existing_namespace(directory, NamespaceName::EnrollmentV1)?,
                identity
            );
            let budget = JournalBudget::default();
            files::immutable(
                &namespace,
                "record.json",
                b"original immutable bytes",
                budget,
                &|_| {},
            )?;
            files::immutable(
                &namespace,
                "record.json",
                b"original immutable bytes",
                budget,
                &|_| {},
            )?;
            assert!(matches!(
                files::immutable(
                    &namespace,
                    "record.json",
                    b"different bytes",
                    budget,
                    &|_| {}
                ),
                Err(JournalError::Conflict)
            ));
            assert_eq!(files::scan(&namespace, budget)?.files.len(), 1);
            let limited = JournalBudget {
                max_files: 1,
                ..budget
            };
            assert!(matches!(
                files::immutable(&namespace, "too-many.json", b"more", limited, &|_| {}),
                Err(JournalError::BudgetExceeded)
            ));
            let old = 1000u64.to_be_bytes();
            let new = 2000u64.to_be_bytes();
            files::replace_observed(&namespace, "clock.floor", None, &old, budget, &|_| {})?;
            files::replace_observed(&namespace, "clock.floor", Some(&old), &new, budget, &|_| {})?;
            files::replace_observed(&namespace, "clock.floor", Some(&new), &new, budget, &|_| {})?;
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
            // Retained ordinary input pins deny write/delete sharing. A real
            // replacement must fail and leave the prior file plus its new
            // orphan, rather than report success or delete an unknown remnant.
            let ns_root = Root::from_directory_handle(&namespace).unwrap();
            let held = ffi::open(
                &ns_root.journal_path().join("clock.floor"),
                false,
                false,
                false,
            )
            .unwrap();
            assert!(
                files::replace_observed(
                    &namespace,
                    "clock.floor",
                    Some(&new),
                    &3000u64.to_be_bytes(),
                    budget,
                    &|_| {}
                )
                .is_err()
            );
            drop(held);
            assert_eq!(
                files::read(&namespace, "clock.floor", 8)?.as_deref(),
                Some(new.as_slice())
            );
            let inventory = files::scan(&namespace, budget)?;
            assert_eq!(inventory.files.len(), 3);
            assert_eq!(
                inventory
                    .files
                    .iter()
                    .filter(|f| f.name.starts_with("orphan-"))
                    .count(),
                1
            );
            Ok::<_, JournalError>(())
        })())
    })
    .unwrap()
    .unwrap();
    guard.validate().unwrap();
    root.validate_root().unwrap();
    // Preserve all owned fixture files for the external observer; no delete.
}
