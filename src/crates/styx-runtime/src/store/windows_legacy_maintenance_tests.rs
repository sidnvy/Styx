//! Real private NTFS plan observations with deliberately old fixture mtimes.
//! Not proof that a production owner rebooted or that an App scope has exited.
use super::*;
use crate::store::management::handoff::RetirementKind;
struct Cleanup(PathBuf);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
#[test]
#[ignore = "requires STYX_TEST_WINDOWS_STORE_ROOT; private native NTFS plus WMI/TaskScheduler"]
fn missing_owner_plan_is_readonly_live_observer_and_changed_review_refuse() {
    let base = PathBuf::from(std::env::var_os("STYX_TEST_WINDOWS_STORE_ROOT").unwrap());
    let parent = Root::open(&base).unwrap();
    for active in [false, true] {
        let name = format!("r60-legacy-plan-{}", uuid::Uuid::new_v4().simple());
        let path = base.join(&name);
        let cleanup = Cleanup(path.clone());
        let root = parent
            .create_fresh_child(OsStr::new(&name))
            .unwrap_or_else(|_| panic!("private fixture child creation failed"));
        let host_root = root
            .create_fresh_child(OsStr::new("host"))
            .unwrap_or_else(|_| panic!("private fixture child creation failed"));
        let device_root = host_root
            .create_fresh_child(OsStr::new("device"))
            .unwrap_or_else(|_| panic!("private fixture child creation failed"));
        let host = PrivateRoot {
            inner: host_root.clone(),
        };
        let host_writer = host.try_configuration_writer().unwrap();
        let device_private = PrivateRoot {
            inner: device_root.clone(),
        };
        let device_writer = device_private.try_configuration_writer().unwrap();
        device_root
            .create_fixed(
                &device_writer,
                "identity.json",
                br#"{"device_id":"fixture-original-device"}"#,
                &|_| {},
            )
            .unwrap();
        drop(device_writer);
        drop(device_private);
        drop(device_root);
        let task_name = format!(
            "StyxPilot-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..20]
        );
        let service=serde_json::to_vec(&serde_json::json!({"task_name":task_name,"install_root":host_root.path,"host_config_file":host_root.path.join("host.json"),"publisher_key_file":host_root.path.join("publisher.pem"),"node_binary":host_root.path.join("node.exe")})).unwrap();
        host_root
            .create_fixed(&host_writer, "service.json", &service, &|_| {})
            .unwrap();
        drop(host_writer);
        let deployment =
            serde_json::to_vec(&serde_json::json!({"schema":1,"host":{"baseDir":host_root.path}}))
                .unwrap();
        let private = PrivateRoot {
            inner: root.clone(),
        };
        let writer = private.try_configuration_writer().unwrap();
        for (name, raw) in [
            ("deployment.json", deployment.as_slice()),
            ("state.json", b"{}".as_slice()),
            ("foreground.lock", b"original-legacy-lock".as_slice()),
        ] {
            root.create_fixed(&writer, name, raw, &|_| {}).unwrap();
        }
        let pid = if active { std::process::id() } else { u32::MAX };
        if !active {
            assert!(ffi::process_optional(pid).unwrap().is_none());
        }
        let observer=serde_json::to_vec(&serde_json::json!({"schema":1,"pid":pid,"configurationHash":styx_contracts::legacy_deployment::deployment_connection_hash(&deployment).unwrap(),"secret":"fixture-private-observer-secret","lock":{"ino":9007199254740992u64,"dev":0,"sha256":Sha256Digest::of_bytes(b"original-legacy-lock")}})).unwrap();
        root.create_fixed(&writer, "foreground-observer.json", &observer, &|_| {})
            .unwrap();
        let observation = WindowsLegacyObservation::capture_foreground_only(&task_name).unwrap();
        let boot = observation.checkpoint().unwrap();
        let old = std::time::UNIX_EPOCH
            + std::time::Duration::from_micros(boot.unix_micros.checked_sub(60_000_000).unwrap());
        for name in ["foreground.lock", "foreground-observer.json"] {
            let pin = ffi::open_retirement_token(&root.path.join(name)).unwrap();
            pin.set_modified(old).unwrap();
            ffi::flush_file(&pin).unwrap();
        }
        let original_lock = root.read_raw(Path::new("foreground.lock"), 4096).unwrap();
        let original_observer = root
            .read_raw(Path::new("foreground-observer.json"), 4096)
            .unwrap();
        let token_pin = ffi::open(&root.path.join("foreground.lock"), false, false, false).unwrap();
        let token_stamp = native_stamp(&token_pin, original_lock.bytes()).unwrap();
        drop(token_pin);
        let owner = OwnedConfigurationRoot::open_existing(private, writer).unwrap();
        let tx: TransactionId = "explicit-legacy-plan".try_into().unwrap();
        let maintenance = owner.begin_standalone_native(tx.clone(), false).unwrap();
        let hash = Sha256Digest::of_bytes(b"synthetic-candidate-not-admission");
        let successor = NativeRetirementIntent {
            schema: 3,
            kind: RetirementKind::LegacyCredentialRetirement,
            transaction_id: tx,
            sequence: 1,
            config_root: root_native(root.identity()).unwrap(),
            host_root: root_native(host.identity()).unwrap(),
            deployment_raw_sha256: Sha256Digest::of_bytes(&deployment),
            before_state_sha256: Sha256Digest::of_bytes(b"{}"),
            preservation_sha256: hash,
            service_descriptor_sha256: Sha256Digest::of_bytes(&service),
            candidate_manifest_sha256: hash,
            publisher_spki_sha256: hash,
            original_token: token_stamp,
        };
        let plan = WindowsLegacyMaintenancePlan::capture(
            &owner,
            &maintenance,
            &host,
            &observation,
            &successor,
        );
        if active {
            assert!(plan.is_err());
        } else {
            let plan = plan.unwrap();
            plan.revalidate_review(plan.plan_sha256(), &observation)
                .unwrap();
            assert!(
                plan.revalidate_review(Sha256Digest::of_bytes(b"changed-review"), &observation)
                    .is_err()
            );
            let json: serde_json::Value = serde_json::from_slice(plan.review_bytes()).unwrap();
            assert_eq!(json["previousWorkOutcome"], "unknown_not_replayed");
            assert!(json.get("previousBoot").is_none());
            assert!(json.get("ownerReceipt").is_none());
            assert!(
                !String::from_utf8_lossy(plan.review_bytes())
                    .contains("fixture-private-observer-secret")
            );
            assert_eq!(
                json["files"][0]["ino"],
                original_lock.observation().inode.to_string()
            );
            assert_eq!(
                Sha256Digest::of_bytes(plan.review_bytes()),
                plan.plan_sha256()
            );
            drop(plan);
        }
        assert_eq!(
            root.read_raw(Path::new("foreground.lock"), 4096)
                .unwrap()
                .observation(),
            original_lock.observation()
        );
        assert_eq!(
            root.read_raw(Path::new("foreground-observer.json"), 4096)
                .unwrap()
                .observation(),
            original_observer.observation()
        );
        for name in [
            "foreground-owner.json",
            "foreground-recovery.lock",
            "advance.lock",
            "background.lock",
            "capabilities.lock",
            "foreground-recovery",
            ".styx-management-journal-v1",
        ] {
            assert!(root.ensure_absent(Path::new(name)).is_ok());
        }
        drop(maintenance);
        drop(owner);
        drop(observation);
        drop(host);
        drop(host_root);
        drop(root);
        std::fs::remove_dir_all(&path).unwrap();
        drop(cleanup);
    }
}
