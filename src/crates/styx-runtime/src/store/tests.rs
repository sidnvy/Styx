use super::*;

#[test]
fn version_probe_preserves_big_integers_without_value_conversion() {
    let bytes = b"{ \"schema\":1,\"n\":12345678901234567890123456789012345678901234567890,\"nested\":[1e999, {\"x\":true}] }\n";
    let result = json_version(
        bytes,
        &JsonVersionPolicy {
            field: VersionField::Schema,
            supported_versions: vec![1],
        },
    );
    assert_eq!(
        result.unwrap(),
        JsonVersion {
            field: VersionField::Schema,
            value: 1
        }
    );
}
#[test]
fn version_is_explicit_unambiguous_and_whole_document_validated() {
    let policy = JsonVersionPolicy {
        field: VersionField::Schema,
        supported_versions: vec![1],
    };
    for bytes in [
        b"{}".as_slice(),
        b"{\"schema\":1,\"schema\":1}",
        b"{\"schema\":\"1\"}",
        b"{\"schema\":1} true",
        b"{\"schema\":1,\"bad\":[}",
    ] {
        assert!(matches!(
            json_version(bytes, &policy),
            Err(StoreError::InvalidJson { .. })
        ));
    }
    assert!(matches!(
        json_version(b"{\"schema\":2}", &policy),
        Err(StoreError::UnsupportedJsonVersion)
    ));
    assert!(json_version(b"{\"version\":1}", &policy).is_err());
}
#[test]
fn invalid_json_diagnostics_do_not_echo_private_field_values() {
    let policy = JsonVersionPolicy {
        field: VersionField::Schema,
        supported_versions: vec![1],
    };
    let error = json_version(b"{\"schema\":\"SYNTHETIC-PRIVATE-VALUE\"}", &policy).unwrap_err();
    assert!(!format!("{error:?}").contains("SYNTHETIC-PRIVATE-VALUE"));
    assert!(!error.to_string().contains("SYNTHETIC-PRIVATE-VALUE"));
}

#[test]
fn traversal_absolute_and_empty_relative_paths_are_rejected() {
    for path in ["", "/etc/passwd", "../outside", "a/../../outside", "."] {
        assert!(checked_relative(Path::new(path)).is_err());
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        process::Command,
    };

    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "styx-store-{}-{}",
                std::process::id(),
                crate_generation()
            ));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            Self(root)
        }
        fn private_file(&self, name: &str, bytes: &[u8]) {
            fs::write(self.0.join(name), bytes).unwrap();
            fs::set_permissions(self.0.join(name), fs::Permissions::from_mode(0o600)).unwrap();
        }
        fn open(&self) -> PrivateRoot {
            PrivateRoot::open(&self.0).unwrap()
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn crate_generation() -> String {
        // Test-only uniqueness; production owner generation uses kernel getrandom.
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        format!(
            "{}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        )
    }

    #[test]
    fn raw_import_is_byte_exact_private_and_has_independent_digest() {
        let scratch = Scratch::new();
        let bytes = b"{ \"schema\":1,\"secret\":\"SYNTHETIC-NEVER-LOG\",\"big\":18446744073709551616000 }\r\n";
        scratch.private_file("state.json", bytes);
        let before = fs::metadata(scratch.0.join("state.json")).unwrap();
        let root = scratch.open();
        let raw = root
            .read_json(
                "state.json",
                4096,
                &JsonVersionPolicy {
                    field: VersionField::Schema,
                    supported_versions: vec![1],
                },
            )
            .unwrap();
        assert_eq!(raw.raw.bytes(), bytes);
        assert_eq!(raw.raw.sha256(), format!("{:x}", Sha256::digest(bytes)));
        assert!(!format!("{raw:?}").contains("SYNTHETIC-NEVER-LOG"));
        assert_eq!(fs::read(scratch.0.join("state.json")).unwrap(), bytes);
        assert_eq!(
            fs::metadata(scratch.0.join("state.json"))
                .unwrap()
                .modified()
                .unwrap(),
            before.modified().unwrap()
        );
        assert_eq!(
            fs::read_dir(&scratch.0).unwrap().count(),
            1,
            "read-only import must not create locks or receipts"
        );
    }
    #[test]
    fn manifest_contains_hashes_and_roles_but_never_private_bytes() {
        let scratch = Scratch::new();
        scratch.private_file("identity.pem", b"SYNTHETIC-PRIVATE-KEY");
        scratch.private_file(
            "deployment.json",
            b"{\"schema\":1,\"n\":999999999999999999999999999999999}",
        );
        let inputs = vec![
            PreservationInput {
                relative_path: "identity.pem".into(),
                role: PreservationRole::DevicePrivateKey,
                json_version: None,
            },
            PreservationInput {
                relative_path: "deployment.json".into(),
                role: PreservationRole::DeploymentConfiguration,
                json_version: Some(JsonVersionPolicy {
                    field: VersionField::Schema,
                    supported_versions: vec![1],
                }),
            },
        ];
        let root = scratch.open();
        let manifest = root.preservation_manifest(&inputs, 4096).unwrap();
        assert_eq!(manifest.entries.len(), 2);
        assert_eq!(
            manifest.entries[0].sha256,
            format!("{:x}", Sha256::digest(b"SYNTHETIC-PRIVATE-KEY"))
        );
        let encoded = serde_json::to_string(&manifest).unwrap();
        assert!(!encoded.contains("SYNTHETIC-PRIVATE-KEY"));
        assert_eq!(manifest.consistency, "per_file_stable_not_transactional");
        assert_eq!(fs::read_dir(&scratch.0).unwrap().count(), 2);
        assert!(matches!(
            root.preservation_manifest(&[inputs[0].clone(), inputs[0].clone()], 4096),
            Err(StoreError::DuplicatePath)
        ));
    }
    #[test]
    fn symlink_roots_ancestors_and_nested_files_never_resolve() {
        let scratch = Scratch::new();
        scratch.private_file("real", b"private");
        symlink(scratch.0.join("real"), scratch.0.join("link")).unwrap();
        let root = scratch.open();
        assert!(root.read_raw("link", 32).is_err());
        symlink(&scratch.0, scratch.0.join("root-link")).unwrap();
        assert!(PrivateRoot::open(scratch.0.join("root-link")).is_err());
        fs::create_dir(scratch.0.join("nested")).unwrap();
        fs::set_permissions(scratch.0.join("nested"), fs::Permissions::from_mode(0o700)).unwrap();
        symlink(scratch.0.join("nested"), scratch.0.join("parent-link")).unwrap();
        fs::create_dir(scratch.0.join("nested/child")).unwrap();
        fs::set_permissions(
            scratch.0.join("nested/child"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        scratch.private_file("nested/anything", b"existing target");
        assert!(PrivateRoot::open(scratch.0.join("nested/child")).is_ok());
        assert!(PrivateRoot::open(scratch.0.join("parent-link/child")).is_err());
        assert_eq!(
            root.read_raw("nested/anything", 32).unwrap().bytes(),
            b"existing target"
        );
        assert!(root.read_raw("parent-link/anything", 32).is_err());
    }
    #[test]
    fn hardlink_aliases_and_non_private_modes_fail_closed() {
        let scratch = Scratch::new();
        scratch.private_file("original", b"private");
        fs::hard_link(scratch.0.join("original"), scratch.0.join("alias")).unwrap();
        assert!(matches!(
            scratch.open().read_raw("original", 32),
            Err(StoreError::NotRegularFile)
        ));
        fs::remove_file(scratch.0.join("alias")).unwrap();
        fs::set_permissions(
            scratch.0.join("original"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(matches!(
            scratch.open().read_raw("original", 32),
            Err(StoreError::NotPrivate)
        ));
        fs::set_permissions(&scratch.0, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            PrivateRoot::open(&scratch.0),
            Err(StoreError::NotPrivate)
        ));
    }
    #[test]
    fn wrong_object_and_over_budget_reads_are_rejected() {
        let scratch = Scratch::new();
        scratch.private_file("large", b"12345");
        let root = scratch.open();
        assert!(matches!(
            root.read_raw("large", 4),
            Err(StoreError::TooLarge)
        ));
        assert_eq!(root.read_raw("large", 5).unwrap().bytes(), b"12345");
        fs::create_dir(scratch.0.join("directory")).unwrap();
        fs::set_permissions(
            scratch.0.join("directory"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        assert!(matches!(
            root.read_raw("directory", 4096),
            Err(StoreError::NotRegularFile)
        ));
    }
    #[test]
    fn replacing_private_root_invalidates_existing_reader_and_guard() {
        let scratch = Scratch::new();
        scratch.private_file("config", b"before");
        let root = scratch.open();
        let writer = root.try_configuration_writer().unwrap();
        let moved = scratch.0.with_extension("moved");
        fs::rename(&scratch.0, &moved).unwrap();
        fs::create_dir(&scratch.0).unwrap();
        fs::set_permissions(&scratch.0, fs::Permissions::from_mode(0o700)).unwrap();
        let read = root.read_raw("config", 32);
        let validation = writer.validate();
        drop(writer);
        fs::remove_dir(&scratch.0).unwrap();
        fs::rename(moved, &scratch.0).unwrap();
        assert!(matches!(read, Err(StoreError::Changed)));
        assert!(matches!(validation, Err(StoreError::Changed)));
    }
    #[test]
    fn lock_resources_are_distinct_exclusive_and_release_without_unlink() {
        let scratch = Scratch::new();
        let root = scratch.open();
        let writer = root.try_configuration_writer().unwrap();
        let execution = root.try_execution_lease().unwrap();
        assert_ne!(writer.identity().resource, execution.identity().resource);
        assert_ne!(
            writer.identity().owner_generation,
            execution.identity().owner_generation
        );
        assert!(matches!(
            root.try_configuration_writer(),
            Err(StoreError::Busy(LockResource::ConfigurationWriter))
        ));
        assert!(matches!(
            root.try_execution_lease(),
            Err(StoreError::Busy(LockResource::Execution))
        ));
        writer.validate().unwrap();
        execution.validate().unwrap();
        drop(writer);
        assert!(
            scratch
                .0
                .join(LockResource::ConfigurationWriter.filename())
                .exists()
        );
        let new_writer = root.try_configuration_writer().unwrap();
        new_writer.validate().unwrap();
        assert!(matches!(
            root.try_execution_lease(),
            Err(StoreError::Busy(LockResource::Execution))
        ));
        drop(execution);
        root.try_execution_lease().unwrap().validate().unwrap();
    }
    #[test]
    fn replaced_or_wrong_lock_file_is_never_accepted_as_the_held_lock() {
        let scratch = Scratch::new();
        let root = scratch.open();
        let writer = root.try_configuration_writer().unwrap();
        fs::rename(
            scratch.0.join(LockResource::ConfigurationWriter.filename()),
            scratch.0.join("displaced-lock"),
        )
        .unwrap();
        scratch.private_file(LockResource::ConfigurationWriter.filename(), b"other inode");
        assert!(matches!(writer.validate(), Err(StoreError::Changed)));
        drop(writer);
        fs::remove_file(scratch.0.join(LockResource::ConfigurationWriter.filename())).unwrap();
        fs::create_dir(scratch.0.join(LockResource::ConfigurationWriter.filename())).unwrap();
        assert!(root.try_configuration_writer().is_err());
    }
    #[test]
    fn concurrent_independent_writer_change_is_detected_after_read() {
        use std::io::Write;
        use std::process::Stdio;
        let scratch = Scratch::new();
        scratch.private_file("mutable", b"BEFORE");
        let root = scratch.open();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "store::tests::linux::raw_change_child_probe",
                "--ignored",
            ])
            .env("STYX_STORE_CHILD_ROOT", &scratch.0)
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        let result = root
            .inner
            .read_raw_after_read_for_test(Path::new("mutable"), 32, || {
                child.stdin.take().unwrap().write_all(b"G").unwrap();
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
                loop {
                    if let Some(status) = child.try_wait().unwrap() {
                        assert!(status.success());
                        break;
                    }
                    if std::time::Instant::now() >= deadline {
                        child.kill().unwrap();
                        child.wait().unwrap();
                        panic!("owned writer did not finish");
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Ok(())
            });
        assert!(matches!(result, Err(StoreError::Changed)));
        assert_eq!(fs::read(scratch.0.join("mutable")).unwrap(), b"AFTER!");
        assert_eq!(root.read_raw("mutable", 32).unwrap().bytes(), b"AFTER!");
        println!(
            "store_observation={}",
            serde_json::json!({"oracle":"concurrent_read","observed":"changed_rejected_then_fresh_read_ok","writer_pid":child.id(),"writer_exit":child.try_wait().unwrap().unwrap().code(),"after_sha256":format!("{:x}",Sha256::digest(b"AFTER!"))})
        );
    }
    #[test]
    #[ignore = "owned subprocess oracle for concurrent_independent_writer_change_is_detected_after_read"]
    fn raw_change_child_probe() {
        use std::io::Read;
        let root = std::env::var_os("STYX_STORE_CHILD_ROOT").expect("owned root required");
        let mut signal = [0u8; 1];
        std::io::stdin().read_exact(&mut signal).unwrap();
        assert_eq!(signal, *b"G");
        let file = PathBuf::from(root).join("mutable");
        fs::write(&file, b"AFTER!").unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(file)
            .unwrap()
            .sync_all()
            .unwrap();
    }
    #[test]
    fn birth_identity_rejects_reused_pid_and_wrong_boot() {
        let actual = ProcessIdentity::current().unwrap();
        assert!(actual.still_current().unwrap());
        let ProcessIdentity::Linux {
            boot_id,
            pid,
            start_ticks,
        } = actual;
        assert!(
            !ProcessIdentity::Linux {
                boot_id: boot_id.clone(),
                pid,
                start_ticks: start_ticks + 1
            }
            .still_current()
            .unwrap()
        );
        assert!(
            !ProcessIdentity::Linux {
                boot_id: "00000000-0000-0000-0000-000000000000".into(),
                pid,
                start_ticks
            }
            .still_current()
            .unwrap()
        );
    }
    #[test]
    fn independent_process_observes_kernel_writer_exclusion_then_release() {
        let scratch = Scratch::new();
        let root = scratch.open();
        let guard = root.try_configuration_writer().unwrap();
        let run_child = |expected: &str| {
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "store::tests::linux::lock_child_probe",
                    "--ignored",
                    "--nocapture",
                ])
                .env("STYX_STORE_CHILD_ROOT", &scratch.0)
                .env("STYX_STORE_CHILD_EXPECT", expected)
                .status()
                .unwrap()
        };
        assert!(run_child("busy").success());
        drop(guard);
        assert!(run_child("acquired").success());
    }
    #[test]
    #[ignore = "owned subprocess oracle for independent_process_observes_kernel_writer_exclusion_then_release"]
    fn lock_child_probe() {
        let path = std::env::var_os("STYX_STORE_CHILD_ROOT").expect("owned test root required");
        let expected = std::env::var("STYX_STORE_CHILD_EXPECT").unwrap();
        let root = PrivateRoot::open(path).unwrap();
        match (expected.as_str(), root.try_configuration_writer()) {
            ("busy", Err(StoreError::Busy(LockResource::ConfigurationWriter))) => {
                println!(
                    "store_observation={}",
                    serde_json::json!({"oracle":"independent_writer","observed":"busy","pid":std::process::id(),"process_identity":ProcessIdentity::current().unwrap()})
                );
            }
            ("acquired", Ok(guard)) => {
                guard.validate().unwrap();
                println!(
                    "store_observation={}",
                    serde_json::json!({"oracle":"independent_writer","observed":"acquired_after_release","pid":std::process::id(),"process_identity":ProcessIdentity::current().unwrap()})
                );
            }
            _ => panic!("independent kernel lock oracle mismatch"),
        }
        root.try_execution_lease().unwrap().validate().unwrap();
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn secure_store_and_birth_identity_are_explicitly_unsupported() {
    assert!(matches!(
        PrivateRoot::open("unused"),
        Err(StoreError::Unsupported)
    ));
    assert!(matches!(
        ProcessIdentity::current(),
        Err(StoreError::Unsupported)
    ));
}
