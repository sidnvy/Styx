//! Owned Mac filesystem aggregate; not publisher/native-runtime acceptance.
use super::*;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};

fn directory(path: &Path) {
    std::fs::DirBuilder::new().mode(0o700).create(path).unwrap();
}
fn file(path: &Path, bytes: &[u8], mode: u32) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
#[ignore = "requires explicit fresh owned Mac root and native Mach-O source"]
fn macos_payload_inventory_identity_acl_and_bounds_native() {
    let path = PathBuf::from(std::env::var_os("STYX_TEST_MACOS_PAYLOAD_ROOT").expect("fresh root"));
    let native = PathBuf::from(
        std::env::var_os("STYX_TEST_MACOS_PAYLOAD_EXECUTABLE").expect("native input"),
    );
    assert!(path.is_absolute() && !path.exists());
    assert_eq!(
        path.parent().unwrap().canonicalize().unwrap(),
        path.parent().unwrap()
    );
    assert!(native.is_absolute() && native.is_file());
    let source_before = native.metadata().unwrap();
    directory(&path);
    directory(&path.join("bin"));
    let image = path.join("bin/codex");
    std::fs::copy(&native, &image).unwrap();
    std::fs::set_permissions(&image, std::fs::Permissions::from_mode(0o700)).unwrap();
    file(&path.join("manifest.json"), b"{\"fixture\":true}\n", 0o600);
    let root = Root::open(&path).unwrap();
    let inventory = root
        .payload_inventory(PayloadLimits::default(), &crate::store::KnownDigests::new())
        .unwrap();
    assert_eq!(inventory.members.len(), 2);
    let wanted = inventory
        .members
        .iter()
        .find(|v| v.path == Path::new("bin/codex"))
        .unwrap()
        .sha256;
    let pin = inventory
        .inner
        .pin_executable(Path::new("bin/codex"))
        .unwrap();
    assert_eq!(pin.expected_sha256().unwrap(), wanted);
    assert_eq!(
        pin.retained_file().unwrap().metadata().unwrap().ino(),
        image.metadata().unwrap().ino()
    );
    assert!(matches!(pin.launch_path(), Err(StoreError::Unsupported)));
    assert_eq!(pin.source_path_for_suspended_spawn().unwrap(), image);
    assert!(matches!(pin.expected_cdhash().unwrap().len(), 20 | 32));
    let mut limits = PayloadLimits::default();
    limits.max_files = 1;
    assert!(matches!(
        root.payload_inventory(limits, &crate::store::KnownDigests::new()),
        Err(StoreError::TooLarge)
    ));
    let mut limits = PayloadLimits::default();
    limits.max_file_bytes = source_before.len() - 1;
    assert!(matches!(
        root.payload_inventory(limits, &crate::store::KnownDigests::new()),
        Err(StoreError::TooLarge)
    ));

    symlink("bin/codex", path.join("alias")).unwrap();
    assert!(
        root.payload_inventory(PayloadLimits::default(), &crate::store::KnownDigests::new())
            .is_err()
    );
    std::fs::remove_file(path.join("alias")).unwrap();
    std::fs::hard_link(&image, path.join("alias")).unwrap();
    assert!(matches!(
        root.payload_inventory(PayloadLimits::default(), &crate::store::KnownDigests::new()),
        Err(StoreError::NotRegularFile)
    ));
    std::fs::remove_file(path.join("alias")).unwrap();

    let user = nix::unistd::User::from_uid(nix::unistd::Uid::current())
        .expect("current user lookup")
        .expect("current user exists");
    let status = std::process::Command::new("/bin/chmod")
        .arg("+a")
        .arg(format!("user:{} allow read", user.name))
        .arg(&image)
        .status()
        .unwrap();
    assert!(status.success());
    assert!(matches!(
        root.payload_inventory(PayloadLimits::default(), &crate::store::KnownDigests::new()),
        Err(StoreError::NotPrivate)
    ));
    assert!(
        std::process::Command::new("/bin/chmod")
            .arg("-N")
            .arg(&image)
            .status()
            .unwrap()
            .success()
    );

    let fresh = root
        .payload_inventory(PayloadLimits::default(), &crate::store::KnownDigests::new())
        .unwrap();
    let held = fresh.inner.pin_executable(Path::new("bin/codex")).unwrap();
    std::fs::rename(&image, path.join("original-held")).unwrap();
    std::fs::copy(path.join("original-held"), &image).unwrap();
    std::fs::set_permissions(&image, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(held.revalidate(), Err(StoreError::Changed)));
    assert!(matches!(fresh.revalidate(), Err(StoreError::Changed)));
    std::fs::remove_file(&image).unwrap();
    std::fs::rename(path.join("original-held"), &image).unwrap();

    file(&path.join("bin/script"), b"#!/bin/sh\nexit 0\n", 0o700);
    let typed = root
        .payload_inventory(PayloadLimits::default(), &crate::store::KnownDigests::new())
        .unwrap();
    assert!(typed.inner.pin_executable(Path::new("bin/script")).is_err());
    std::fs::remove_file(path.join("bin/script")).unwrap();
    directory(&path.join("deeper"));
    directory(&path.join("deeper/child"));
    let mut limits = PayloadLimits::default();
    limits.max_depth = 1;
    assert!(matches!(
        root.payload_inventory(limits, &crate::store::KnownDigests::new()),
        Err(StoreError::TooLarge)
    ));
    let source_after = native.metadata().unwrap();
    assert_eq!(observation(&source_before), observation(&source_after));
    assert_eq!(source_before.nlink(), source_after.nlink());
    // Fixture retained for independent observation. No native image was run.
    println!(
        "{}",
        serde_json::json!({"schema":1,"status":"PASS_OWNED_MAC_PAYLOAD_FS_ONLY","members":2,"native_source_unchanged":true,"launch":"UNSUPPORTED_UNTIL_SUSPENDED_ATTESTED_SPAWN","native_runtime_executed":false})
    );
}

#[test]
#[ignore = "requires explicit fresh owned Mac root"]
fn macos_payload_revalidate_nested_changes_native() {
    let path = PathBuf::from(std::env::var_os("STYX_TEST_MACOS_PAYLOAD_ROOT").expect("fresh root"));
    assert!(path.is_absolute() && !path.exists());
    directory(&path);
    for dir in ["a", "a/b", "a/b/c", "a.d", "z"] {
        directory(&path.join(dir));
    }
    for name in [
        "a/one",
        "a/b/two",
        "a/b/c/three",
        "a.d/four",
        "z/five",
        "top",
    ] {
        file(&path.join(name), name.as_bytes(), 0o600);
    }
    let root = Root::open(&path).unwrap();
    let fresh = || {
        root.payload_inventory(PayloadLimits::default(), &crate::store::KnownDigests::new())
            .unwrap()
    };
    let inventory = fresh();
    assert_eq!(inventory.members.len(), 6);
    inventory.inner.revalidate().unwrap();
    inventory.inner.revalidate().unwrap();

    // Renamed away and back deep in the tree: its directory observation changes.
    let deep = path.join("a/b/c/three");
    std::fs::rename(&deep, path.join("a/b/c/moved")).unwrap();
    std::fs::rename(path.join("a/b/c/moved"), &deep).unwrap();
    assert!(matches!(
        inventory.inner.revalidate(),
        Err(StoreError::Changed)
    ));

    // An added entry changes its directory's observation.
    let inventory = fresh();
    file(&path.join("a/b/extra"), b"x", 0o600);
    assert!(matches!(
        inventory.inner.revalidate(),
        Err(StoreError::Changed)
    ));
    std::fs::remove_file(path.join("a/b/extra")).unwrap();

    // An ACL added to a nested member is refused, not skipped.
    let inventory = fresh();
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::current())
        .expect("current user lookup")
        .expect("current user exists");
    let target = path.join("a.d/four");
    assert!(
        std::process::Command::new("/bin/chmod")
            .arg("+a")
            .arg(format!("user:{} allow read", user.name))
            .arg(&target)
            .status()
            .unwrap()
            .success()
    );
    assert!(inventory.inner.revalidate().is_err());
    assert!(
        std::process::Command::new("/bin/chmod")
            .arg("-N")
            .arg(&target)
            .status()
            .unwrap()
            .success()
    );
    fresh().inner.revalidate().unwrap();
}
