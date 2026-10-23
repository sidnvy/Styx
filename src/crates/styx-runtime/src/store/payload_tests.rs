//! Actual descriptor/inode/exec negative controls in a caller-owned directory.
#![cfg(target_os = "linux")]
use super::*;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
};
#[test]
#[ignore = "requires fresh external STYX_TEST_PAYLOAD_ROOT; actual read-only payload and pinned ELF scenario"]
fn payload_inventory_stream_pin_and_replacement_alias_budget_negatives() {
    let parent = PathBuf::from(std::env::var("STYX_TEST_PAYLOAD_ROOT").unwrap());
    let path = parent.join(uuid::Uuid::new_v4().to_string());
    fs::create_dir_all(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let image = path.join("image");
    fs::copy("/usr/bin/true", &image).unwrap();
    fs::set_permissions(&image, fs::Permissions::from_mode(0o700)).unwrap();
    let root = PrivateRoot::open(&path).unwrap();
    root.ensure_absent("missing").unwrap();
    assert!(
        root.ensure_absent("image").is_err(),
        "existing legacy owner never counts as absent"
    );
    fs::create_dir(path.join("owner-dir")).unwrap();
    fs::set_permissions(path.join("owner-dir"), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(root.ensure_absent("owner-dir").is_err());
    fs::remove_dir(path.join("owner-dir")).unwrap();
    let inventory = root.payload_inventory(PayloadLimits::default()).unwrap();
    assert_eq!(inventory.members().len(), 1);
    assert_eq!(
        root.payload_inventory(PayloadLimits::default())
            .unwrap()
            .members()
            .len(),
        1,
        "directory offsets cannot silently lose members on repeated observation"
    );
    let pinned = inventory.pin_executable("image").unwrap();
    assert!(
        std::process::Command::new(pinned.launch_path().unwrap())
            .status()
            .unwrap()
            .success(),
        "an actual native ELF runs through the retained parent FD"
    );
    fs::rename(&image, path.join("saved-image")).unwrap();
    fs::copy(path.join("saved-image"), &image).unwrap();
    fs::set_permissions(&image, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        matches!(pinned.launch_path(), Err(StoreError::Changed)),
        "same-byte replacement inode must not be adopted"
    );
    assert!(
        inventory.revalidate().is_err(),
        "original inventory cannot silently include an added/replaced member"
    );
    fs::remove_file(path.join("saved-image")).unwrap();
    symlink("/etc/passwd", path.join("alias")).unwrap();
    assert!(
        root.payload_inventory(PayloadLimits::default()).is_err(),
        "no outside-tree symlink read"
    );
    assert!(root.ensure_absent("alias").is_err());
    assert!(
        root.ensure_absent("alias/child").is_err(),
        "no-follow parent check cannot infer absence through an alias"
    );
    fs::remove_file(path.join("alias")).unwrap();
    fs::hard_link(&image, path.join("alias")).unwrap();
    assert!(matches!(
        root.payload_inventory(PayloadLimits::default()),
        Err(StoreError::NotRegularFile)
    ));
    fs::remove_file(path.join("alias")).unwrap();
    nix::unistd::mkfifo(
        &path.join("pipe"),
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .unwrap();
    assert!(
        root.payload_inventory(PayloadLimits::default()).is_err(),
        "FIFO inventory must reject without blocking on open"
    );
    assert!(
        root.ensure_absent("pipe").is_err(),
        "special owner nodes reject without opening FIFO"
    );
    fs::remove_file(path.join("pipe")).unwrap();
    let sparse = fs::File::create(path.join("oversize")).unwrap();
    fs::set_permissions(path.join("oversize"), fs::Permissions::from_mode(0o600)).unwrap();
    sparse
        .set_len(PayloadLimits::default().max_file_bytes + 1)
        .unwrap();
    assert!(
        matches!(
            root.payload_inventory(PayloadLimits::default()),
            Err(StoreError::TooLarge)
        ),
        "oversize must be rejected from metadata before hashing/allocation"
    );
    drop(sparse);
    fs::remove_file(path.join("oversize")).unwrap();
    let final_inventory = root.payload_inventory(PayloadLimits::default()).unwrap();
    assert_eq!(final_inventory.members().len(), 1);
    final_inventory.revalidate().unwrap();
}
