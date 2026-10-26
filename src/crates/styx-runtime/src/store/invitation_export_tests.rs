//! Real-filesystem export boundaries. No Gateway or synthetic writer authority.
use super::*;
use std::{
    ffi::OsStr,
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
};

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("styx-invitation-export-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn invitation_export_is_private_exclusive_and_independent_of_configuration_writer() {
    let scratch = Scratch::new();
    let root = PrivateRoot::open(&scratch.0).unwrap();
    let writer = root.try_configuration_writer().unwrap();
    let first = root
        .create_pairing_invitation(OsStr::new("invite.json"), b"synthetic-invitation")
        .unwrap();
    let metadata = fs::symlink_metadata(scratch.0.join("invite.json")).unwrap();
    assert_eq!(metadata.mode() & 0o7777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(first.bytes(), b"synthetic-invitation");
    assert!(
        root.create_pairing_invitation(OsStr::new("invite.json"), b"replacement")
            .is_err()
    );
    let after = root.read_raw("invite.json", 32 * 1024).unwrap();
    assert_eq!(after.bytes(), first.bytes());
    assert_eq!(after.observation(), first.observation());
    writer.validate().unwrap();
    symlink("invite.json", scratch.0.join("alias.json")).unwrap();
    assert!(
        root.create_pairing_invitation(OsStr::new("alias.json"), b"replacement")
            .is_err()
    );
    assert_eq!(
        fs::read(scratch.0.join("invite.json")).unwrap(),
        first.bytes()
    );
}

#[test]
fn invitation_export_refuses_traversal_budget_and_changed_root_before_publication() {
    let scratch = Scratch::new();
    let root = PrivateRoot::open(&scratch.0).unwrap();
    for name in ["", ".", "../escape", "child/invite", "/absolute"] {
        assert!(
            root.create_pairing_invitation(OsStr::new(name), b"synthetic")
                .is_err()
        );
    }
    assert!(
        root.create_pairing_invitation(OsStr::new("empty"), b"")
            .is_err()
    );
    assert!(
        root.create_pairing_invitation(OsStr::new("oversized"), &vec![0; 32 * 1024 + 1])
            .is_err()
    );
    assert_eq!(fs::read_dir(&scratch.0).unwrap().count(), 0);
    fs::set_permissions(&scratch.0, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        root.create_pairing_invitation(OsStr::new("public-parent"), b"synthetic")
            .is_err()
    );
    fs::set_permissions(&scratch.0, fs::Permissions::from_mode(0o700)).unwrap();
    let old = scratch.0.with_extension("original");
    fs::rename(&scratch.0, &old).unwrap();
    fs::create_dir(&scratch.0).unwrap();
    fs::set_permissions(&scratch.0, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        root.create_pairing_invitation(OsStr::new("changed-parent"), b"synthetic")
            .is_err()
    );
    assert_eq!(fs::read_dir(&scratch.0).unwrap().count(), 0);
    assert_eq!(fs::read_dir(&old).unwrap().count(), 0);
    fs::remove_dir(old).unwrap();
}
