//! Actual files, owned roots only. No power-loss/crash injection or wall-clock
//! authority is established by this deterministic low-level store scenario.
#![cfg(all(target_os = "linux", target_env = "gnu"))]
use super::*;
use std::{
    fs,
    io::Read,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
};
fn owned_root(parent: &Path) -> PathBuf {
    let path = parent.join(uuid::Uuid::new_v4().to_string());
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}
fn raw_floor(root: &Path) -> Vec<u8> {
    fs::read(root.join(NAMESPACE).join(NAME)).unwrap()
}

#[test]
#[ignore = "requires STYX_TEST_ENROLLMENT_CLOCK_ROOT; owned real-file monotonic-floor scenario, not clock/powerloss acceptance"]
fn durable_floor_atomic_updates_reopen_and_shared_budget_refuse_unsafe_state() {
    let base = PathBuf::from(std::env::var("STYX_TEST_ENROLLMENT_CLOCK_ROOT").unwrap());
    fs::create_dir_all(&base).unwrap();
    let path = owned_root(&base);
    let root = PrivateRoot::open(&path).unwrap();
    let mut writer = root.try_configuration_writer().unwrap();
    let mut journal =
        EnrollmentJournal::open(&root, &mut writer, JournalBudget::default()).unwrap();
    assert_eq!(
        journal.read_time_floor().unwrap(),
        None,
        "absence must not become Some(0)"
    );
    // Independent wire-byte oracle: literal byte sequence, not encode/decode
    // roundtrip using the production helper under test.
    let first = 0x0102_0304_0506_0708;
    let next = 0x0102_0304_0506_0709;
    journal.record_time_floor(first).unwrap();
    assert_eq!(raw_floor(&path), vec![1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(journal.read_time_floor().unwrap(), Some(first));
    let floor = path.join(NAMESPACE).join(NAME);
    let inode = fs::metadata(&floor).unwrap().ino();
    let mut old_descriptor = fs::File::open(&floor).unwrap();
    journal.record_time_floor(first).unwrap();
    assert_eq!(
        fs::metadata(&floor).unwrap().ino(),
        inode,
        "equal floor re-sync must not allocate another record"
    );
    journal.record_time_floor(next).unwrap();
    assert_ne!(fs::metadata(&floor).unwrap().ino(), inode);
    let mut old_bytes = vec![];
    old_descriptor.read_to_end(&mut old_bytes).unwrap();
    assert_eq!(
        old_bytes,
        vec![1, 2, 3, 4, 5, 6, 7, 8],
        "old descriptor observes original complete inode"
    );
    assert_eq!(
        raw_floor(&path),
        vec![1, 2, 3, 4, 5, 6, 7, 9],
        "public pathname observes complete replacement"
    );
    assert_eq!(
        journal.record_time_floor(first),
        Err(JournalError::Conflict)
    );
    assert_eq!(raw_floor(&path), vec![1, 2, 3, 4, 5, 6, 7, 9]);
    assert_eq!(
        journal.scan().unwrap().files.len(),
        1,
        "normal floor advancement must not grow journal event count"
    );
    journal.record_time_floor(u64::MAX).unwrap();
    assert_eq!(raw_floor(&path), vec![255; 8]);
    assert_eq!(journal.record_time_floor(0), Err(JournalError::Conflict));
    assert_eq!(raw_floor(&path), vec![255; 8]);
    drop(writer);
    drop(root);
    // Re-open both root and kernel writer, not merely another borrowed reader.
    let root = PrivateRoot::open(&path).unwrap();
    let mut writer = root.try_configuration_writer().unwrap();
    let journal = EnrollmentJournal::open(&root, &mut writer, JournalBudget::default()).unwrap();
    assert_eq!(journal.read_time_floor().unwrap(), Some(u64::MAX));
    drop(writer);
    drop(root);

    // Missing floor in a nonempty inventory remains None. It is NOT evidence
    // that a service may initialize zero/reset time: boot recovery must refuse.
    let path = owned_root(&base);
    let root = PrivateRoot::open(&path).unwrap();
    let mut writer = root.try_configuration_writer().unwrap();
    let mut journal =
        EnrollmentJournal::open(&root, &mut writer, JournalBudget::default()).unwrap();
    journal
        .put_material(MaterialKind::Profile, b"synthetic profile only")
        .unwrap();
    assert_eq!(journal.read_time_floor().unwrap(), None);
    assert_eq!(journal.scan().unwrap().files.len(), 1);

    for attack in [
        "zero_length",
        "short",
        "long",
        "mode",
        "hardlink",
        "symlink",
        "directory",
    ] {
        let path = owned_root(&base);
        let root = PrivateRoot::open(&path).unwrap();
        let mut writer = root.try_configuration_writer().unwrap();
        let mut journal =
            EnrollmentJournal::open(&root, &mut writer, JournalBudget::default()).unwrap();
        journal.record_time_floor(100).unwrap();
        let floor = path.join(NAMESPACE).join(NAME);
        match attack {
            "zero_length" => fs::write(&floor, []).unwrap(),
            "short" => fs::write(&floor, [0; 7]).unwrap(),
            "long" => fs::write(&floor, [0; 9]).unwrap(),
            "mode" => fs::set_permissions(&floor, fs::Permissions::from_mode(0o644)).unwrap(),
            "hardlink" => fs::hard_link(&floor, path.join("floor-alias")).unwrap(),
            "symlink" => {
                fs::write(path.join("untrusted-target"), [0; 8]).unwrap();
                fs::remove_file(&floor).unwrap();
                symlink(path.join("untrusted-target"), &floor).unwrap();
            }
            _ => {
                fs::remove_file(&floor).unwrap();
                fs::create_dir(&floor).unwrap();
            }
        }
        let before = if fs::symlink_metadata(&floor).unwrap().is_file() {
            Some(fs::read(&floor).unwrap())
        } else {
            None
        };
        assert!(journal.read_time_floor().is_err(), "unsafe floor {attack}");
        assert!(
            journal.record_time_floor(101).is_err(),
            "must not repair unsafe floor {attack}"
        );
        if let Some(before) = before {
            assert_eq!(fs::read(&floor).unwrap(), before);
        }
    }
    // Clock and immutable material genuinely share the same file-count slots.
    let path = owned_root(&base);
    let root = PrivateRoot::open(&path).unwrap();
    let mut writer = root.try_configuration_writer().unwrap();
    let mut journal = EnrollmentJournal::open(
        &root,
        &mut writer,
        JournalBudget {
            max_files: 2,
            max_bytes: 1024,
            max_file_bytes: 1024,
        },
    )
    .unwrap();
    let material = journal
        .put_material(MaterialKind::Token, b"synthetic-token")
        .unwrap();
    journal.record_time_floor(100).unwrap();
    let before = raw_floor(&path);
    assert_eq!(
        journal.record_time_floor(101),
        Err(JournalError::BudgetExceeded)
    );
    assert_eq!(raw_floor(&path), before);
    assert_eq!(
        journal.put_material(MaterialKind::Sealed, b"another"),
        Err(JournalError::BudgetExceeded)
    );
    journal.record_time_floor(100).unwrap();
    assert_eq!(
        journal
            .put_material(MaterialKind::Token, b"synthetic-token")
            .unwrap(),
        material
    );
    assert_eq!(journal.scan().unwrap().files.len(), 2);
    // Updating the fixed 8-byte final file still reserves 8 temporary bytes.
    let path = owned_root(&base);
    let root = PrivateRoot::open(&path).unwrap();
    let mut writer = root.try_configuration_writer().unwrap();
    let mut journal = EnrollmentJournal::open(
        &root,
        &mut writer,
        JournalBudget {
            max_files: 3,
            max_bytes: 9,
            max_file_bytes: 8,
        },
    )
    .unwrap();
    journal.put_material(MaterialKind::Token, b"x").unwrap();
    journal.record_time_floor(100).unwrap();
    assert_eq!(
        journal.record_time_floor(101),
        Err(JournalError::BudgetExceeded)
    );
    assert_eq!(raw_floor(&path), vec![0, 0, 0, 0, 0, 0, 0, 100]);
    let path = owned_root(&base);
    let root = PrivateRoot::open(&path).unwrap();
    let mut writer = root.try_configuration_writer().unwrap();
    let mut journal = EnrollmentJournal::open(
        &root,
        &mut writer,
        JournalBudget {
            max_files: 1,
            max_bytes: 7,
            max_file_bytes: 7,
        },
    )
    .unwrap();
    assert_eq!(
        journal.record_time_floor(100),
        Err(JournalError::BudgetExceeded)
    );
    assert_eq!(journal.read_time_floor().unwrap(), None);
    assert!(journal.scan().unwrap().files.is_empty());
    println!(
        "Clock owned real-file fixture={}: literal 8-byte floor, old descriptor/new pathname atomic replacement, equal-floor fixed entry, backwards time refusal preserves bytes, root+writer reopen, malformed/unsafe alias/mode refusals, shared immutable file/byte budget verified; NOT powerloss/crash/wall-clock/boot-recovery acceptance",
        base.display()
    );
}
