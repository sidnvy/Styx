//! Deterministic real private-journal publication windows; no service or OS scope
//! is manufactured and no physical service acceptance is implied.
use super::*;
use crate::store::{native_root::create_fresh, native_transaction::NativeTransactions};
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
};
use styx_contracts::{management::ReaderContract, native_management::*};

#[test]
fn native_service_partial_publication_preserves_original_pending_and_follows_tip() {
    let base = std::env::temp_dir().join(format!(
        "styx-service-publication-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    fs::create_dir(&base).unwrap();
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
    let parent = PrivateRoot::open(&base).unwrap();
    let fresh = create_fresh(&parent, OsStr::new("native"))
        .unwrap_or_else(|e| panic!("fresh: {:?}", e.error()));
    let deployment = b"{\"owned_journal_fixture\":true}\n";
    let state = NativeState {
        schema: 2,
        kind: NativeStateKind::StyxDesiredState,
        runtime_format: NativeRuntimeFormat::NativeRustV1,
        reader_contract: ReaderContract::NativeManagementStateV1,
        scope_generation: fresh.marker().scope_generation,
        deployment_raw_sha256: Sha256Digest::of_bytes(deployment),
        mode: NativeDeploymentMode::JoinExisting,
        revision: 0,
        last_transaction: None,
        desired: NativeDesired {
            gateway: None,
            host: Some(NativeComponentDesired {
                manager: NativeManager::ForegroundCli,
                run: NativeRunDesired::Stopped,
                autostart: NativeAutostartDesired::Disabled,
            }),
        },
        migration: None,
        extensions: BTreeMap::new(),
    };
    let binding = fresh
        .initialize(deployment, &state)
        .unwrap_or_else(|e| panic!("init: {:?}", e.error()));
    let mut tx =
        NativeTransactions::open(binding).unwrap_or_else(|e| panic!("open: {:?}", e.error()));
    let mut installed = tx.readstate().unwrap().state().clone();
    installed.revision = 1;
    installed.last_transaction = Some(NativeStateTransaction {
        transaction_id: "installed".try_into().unwrap(),
        sequence: 1,
    });
    installed.desired.host.as_mut().unwrap().manager = NativeManager::PersistentService;
    installed.desired.host.as_mut().unwrap().run = NativeRunDesired::Running;
    tx.apply_target(&serde_json::to_vec(&installed).unwrap())
        .unwrap();
    let root = PrivateRoot::open(base.join("native")).unwrap();
    let namespace = root
        .inner
        .with_readonly_directory(|d| Ok(files::directory(d, NS)))
        .unwrap()
        .unwrap();
    let scan = || files::scan(&namespace, JournalBudget::default()).unwrap();
    let read = || root.read_raw("state.json", MAX).unwrap().bytes().to_vec();
    let original_scan = scan();
    let original_raw = read();
    let tip = AutostartTip::capture(tx.marker(), &original_raw, &original_scan).unwrap();
    let mut next = installed;
    next.revision = 2;
    next.last_transaction = Some(NativeStateTransaction {
        transaction_id: "autostart-on".try_into().unwrap(),
        sequence: 2,
    });
    next.desired.host.as_mut().unwrap().autostart = NativeAutostartDesired::Enabled;
    let target = serde_json::to_vec(&next).unwrap();
    let intent = tx.validate_target(&target).unwrap();
    let owner = tx.configuration_root();
    let maintenance = owner
        .begin_standalone_native(intent.transaction_id.clone(), false)
        .unwrap();
    let saw_write = std::cell::Cell::new(false);
    let saw_rename = std::cell::Cell::new(false);
    tx.journal_for_test()
        .prepare_observing(
            &maintenance,
            &serde_json::to_vec(&intent).unwrap(),
            &original_raw,
            &target,
            &|_, phase| {
                if phase == "write" || phase == "rename" {
                    let actual = scan();
                    if phase == "write" {
                        assert!(actual.files.iter().any(|f| append_temporary(&f.name)));
                        saw_write.set(true);
                    } else {
                        saw_rename.set(true);
                    }
                    assert_eq!(tip.validate(&actual, &read()), Err(LiveTipError::Pending));
                }
            },
        )
        .unwrap();
    assert!(saw_write.get() && saw_rename.get());
    let original_error = tip.validate(&scan(), &read()).unwrap_err().journal();
    assert_eq!(original_error, JournalError::ConfigurationPending);
    drop(maintenance);
    drop(owner);
    // Same original tx recovery performs the actual canonical assignment and
    // phase appends. The reader never repairs, adopts, or ignores a temporary.
    drop(tx);
    let reopened = PrivateRoot::open(base.join("native")).unwrap();
    let writer = reopened.try_configuration_writer().unwrap();
    let binding = crate::store::native_root::reopen_native(reopened, writer)
        .unwrap_or_else(|e| panic!("reopen: {:?}", e.error()));
    let mut tx = NativeTransactions::open(binding)
        .unwrap_or_else(|e| panic!("reopen coordinator: {:?}", e.error()));
    tx.recover_original(&intent.transaction_id).unwrap();
    assert_eq!(tip.validate(&scan(), &read()), Ok(()));
    // Completion cannot retroactively upgrade a previously observed Pending.
    assert_eq!(LiveTipError::from(original_error), LiveTipError::Pending);
    let accepted = AutostartTip::capture(tx.marker(), &read(), &scan()).unwrap();
    assert_eq!(
        accepted.validate(&original_scan, &original_raw),
        Err(LiveTipError::Changed)
    );
    let mut foreign_file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(base.join("native").join(NS).join("foreign-entry"))
        .unwrap();
    foreign_file.write_all(b"not-a-c07-entry").unwrap();
    foreign_file.sync_all().unwrap();
    assert_eq!(
        accepted.validate(&scan(), &read()),
        Err(LiveTipError::Changed)
    );
    drop(foreign_file);
    drop(tx);
    drop(namespace);
    drop(root);
    drop(parent);
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn native_service_enumerated_publication_rename_is_pending_without_history_exception() {
    use nix::fcntl::{RenameFlags, renameat2};
    let base =
        std::env::temp_dir().join(format!("styx-service-read-race-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&base).unwrap();
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
    let root = PrivateRoot::open(&base).unwrap();
    root.inner
        .with_readonly_directory(|dir| {
            let name = format!("orphan-{}.temporary", "a".repeat(64));
            let path = base.join(&name);
            let mut file = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            file.write_all(b"original publication bytes").unwrap();
            file.sync_all().unwrap();
            let renamed = std::cell::Cell::new(false);
            let result = files::scan_observing(dir, JournalBudget::default(), &|entry| {
                if entry == name && !renamed.replace(true) {
                    renameat2(
                        dir,
                        name.as_str(),
                        dir,
                        "txn-actual.intent",
                        RenameFlags::RENAME_NOREPLACE,
                    )
                    .unwrap();
                }
            });
            assert!(renamed.get());
            assert!(matches!(result, Err(JournalError::ConfigurationPending)));
            assert_eq!(
                fs::read(base.join("txn-actual.intent")).unwrap(),
                b"original publication bytes"
            );
            // A missing ordinary/accepted journal name retains the old fatal class.
            let result = files::scan_observing(dir, JournalBudget::default(), &|entry| {
                if entry == "txn-actual.intent" {
                    renameat2(
                        dir,
                        entry,
                        dir,
                        "kept-original",
                        RenameFlags::RENAME_NOREPLACE,
                    )
                    .unwrap();
                }
            });
            assert!(matches!(result, Err(JournalError::Unknown)));
            Ok(())
        })
        .unwrap();
    drop(root);
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn fixed_service_state_reader_separates_publication_from_immutable_damage() {
    use crate::store::{StoreError, platform::ServiceStateReadError};
    fn write(path: &std::path::Path, raw: &[u8]) {
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(raw).unwrap();
        file.sync_all().unwrap();
    }
    let base = std::env::temp_dir().join(format!("styx-fixed-state-read-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&base).unwrap();
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
    for name in ["publication", "inplace", "permissions", "root", "ordinary"] {
        let path = base.join(name);
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        write(&path.join("state.json"), b"old");
        let root = PrivateRoot::open(&path).unwrap();
        if name == "ordinary" {
            write(&path.join("next"), b"new");
            let result = root.inner.read_raw_after_read_for_test(
                std::path::Path::new("state.json"),
                64,
                || {
                    fs::rename(path.join("next"), path.join("state.json"))?;
                    Ok(())
                },
            );
            assert!(matches!(
                result,
                Err(StoreError::Changed | StoreError::NotRegularFile)
            ));
            continue;
        }
        let result = root.inner.read_service_state_after_read_for_test(64, || {
            match name {
                "publication" => {
                    write(&path.join("next"), b"new");
                    fs::rename(path.join("next"), path.join("state.json"))?;
                }
                "inplace" => {
                    let mut file = fs::OpenOptions::new()
                        .write(true)
                        .truncate(true)
                        .open(path.join("state.json"))?;
                    file.write_all(b"changed-in-place")?;
                    file.sync_all()?;
                }
                "permissions" => {
                    fs::set_permissions(path.join("state.json"), fs::Permissions::from_mode(0o644))?
                }
                "root" => {
                    fs::rename(&path, base.join("original-root-retained"))?;
                    fs::create_dir(&path)?;
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
                    write(&path.join("state.json"), b"old");
                }
                _ => unreachable!(),
            }
            Ok(())
        });
        if name == "publication" {
            assert!(matches!(
                result,
                Err(ServiceStateReadError::PublicationChanged)
            ));
            assert_eq!(root.inner.read_service_state(64).unwrap().bytes(), b"new");
        } else if name == "permissions" {
            assert!(matches!(
                result,
                Err(ServiceStateReadError::Store(StoreError::NotPrivate))
            ));
        } else {
            assert!(matches!(
                result,
                Err(ServiceStateReadError::Store(StoreError::Changed))
            ));
        }
    }
    fs::remove_dir_all(base).unwrap();
}
