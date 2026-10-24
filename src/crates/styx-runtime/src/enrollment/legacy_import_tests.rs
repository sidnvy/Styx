//! Test-only fresh roots/public RSA fixtures. No legacy Gateway, fresh pair,
//! native enrollment ledger, admission, production identity or token is created.
use super::*;
use crate::{crypto::DevicePublicKey, store::OwnedConfigurationRoot};
use serde_json::json;
use std::{
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    process::Command,
};
const APPROVED: &str = "styx-111111111111111111111111";
const REVOKED: &str = "styx-222222222222222222222222";
const TOKEN: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv0123456789_-\n";
struct Fixture {
    path: PathBuf,
    root: Arc<PrivateRoot>,
    _owner: OwnedConfigurationRoot,
    maintenance: ConfigurationMaintenance,
    db: serde_json::Value,
}
fn dir(p: &Path) {
    fs::create_dir(p).unwrap();
    fs::set_permissions(p, fs::Permissions::from_mode(0o700)).unwrap();
}
fn write(p: &Path, b: &[u8]) {
    let mut f = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(p)
        .unwrap();
    f.write_all(b).unwrap();
    f.sync_all().unwrap();
}
fn keys() -> Vec<String> {
    let node =
        std::env::var("STYX_TEST_NODE22").expect("fixed owned Node22 fixture executable required");
    let output=Command::new(node).args(["--input-type=module","-e",r#"import{generateKeyPairSync}from'node:crypto';console.log(JSON.stringify([0,1].map(()=>generateKeyPairSync('rsa',{modulusLength:3072}).publicKey.export({type:'spki',format:'pem'}))));"#]).output().unwrap();
    assert!(output.status.success());
    assert!(output.stdout.len() < 8192);
    assert!(output.stderr.is_empty());
    serde_json::from_slice(&output.stdout).unwrap()
}
fn fixture(base: &Path, keys: &[String]) -> Fixture {
    let path = base.join(uuid::Uuid::new_v4().to_string());
    dir(&path);
    dir(&path.join("gateway"));
    dir(&path.join("gateway/enrollment"));
    dir(&path.join("gateway/enrollment/tokens"));
    let deployment=b"{\"schema\":1,\"mode\":\"create-local\",\"gateway\":{\"url\":\"https://127.0.0.1:8443/\"}}\n";
    write(&path.join("deployment.json"), deployment);
    write(&path.join("state.json"),&serde_json::to_vec(&json!({"schema":1,"mode":"create-local","configSha256":Sha256Digest::of_bytes(deployment),"uncertain":false,"activeStep":null})).unwrap());
    write(&path.join("gateway/runtime.json"),&serde_json::to_vec(&json!({"schema":1,"url":"https://127.0.0.1:8443/","enrollmentDir":path.join("gateway/enrollment"),"catalogFile":path.join("gateway/targets.json")})).unwrap());
    write(
        &path.join("gateway/targets.json"),
        b"{\"version\":1,\"targets\":[]}\n",
    );
    let mut pending = Vec::new();
    let mut devices = Vec::new();
    for (i, id) in [APPROVED, REVOKED].iter().enumerate() {
        let fingerprint = DevicePublicKey::from_spki_pem(keys[i].as_bytes())
            .unwrap()
            .fingerprint()
            .as_hex()
            .to_owned();
        let mut p = json!({"request_id":format!("{:032x}",i+1),"device_id":id,"label":format!("Owned {i}"),"platform":"linux","cwd":"/tmp/owned","shell":"/bin/sh","computer_requested":false,"browser_requested":false,"public_key_pem":keys[i],"fingerprint":fingerprint,"exp":1_000_000_000_000_u64,"approved_at":900_000_000_000_u64,"claim_expires_at":1_100_000_000_000_u64,"status":if i==0{"claimed"}else{"revoked"}});
        if i == 0 {
            p["claim_hash"] = json!(Sha256Digest::of_bytes(b"original claim"));
            p["claimed_at"] = json!(900_000_000_001_u64);
        }
        pending.push(p);
        // Old signed self-CAS can enable Browser after an initial false request.
        let generation = if i == 0 {
            "capability-0123456789abcdef"
        } else {
            "paired-fedcba9876543210"
        };
        let mut d = json!({"id":id,"label":format!("Owned {i}"),"fingerprint":fingerprint,"target":{"id":id,"kind":"host","platform":"linux","generation":generation,"allowed":true,"cwd":"/tmp/owned","shell":"/bin/sh","shells":["/bin/sh"],"exec":{"transport":"outbound","token_file":path.join(format!("gateway/enrollment/tokens/{id}.token"))},"computer":{"enabled":false},"browser":if i==0{json!({"enabled":true,"transport":"outbound"})}else{json!({"enabled":false})}},"status":if i==0{"approved"}else{"revoked"},"approved_at":900_000_000_000_u64});
        if i == 1 {
            d["revoked_at"] = json!(900_000_000_002_u64);
        }
        devices.push(d);
    }
    let db = json!({"version":1,"invitations":[],"pending":pending,"devices":devices,"default_environment_id":APPROVED});
    write(
        &path.join("gateway/enrollment/state.json"),
        &serde_json::to_vec(&db).unwrap(),
    );
    write(
        &path.join(format!("gateway/enrollment/tokens/{APPROVED}.token")),
        TOKEN,
    );
    let private = PrivateRoot::open(&path).unwrap();
    let writer = private.try_configuration_writer().unwrap();
    let owner = OwnedConfigurationRoot::open_existing(private, writer).unwrap();
    let maintenance = owner
        .begin_maintenance("legacy-import-owned".try_into().unwrap())
        .unwrap();
    let root = Arc::new(PrivateRoot::open(&path).unwrap());
    Fixture {
        path,
        root,
        _owner: owner,
        maintenance,
        db,
    }
}
fn replace_db(f: &Fixture, value: &serde_json::Value) {
    fs::write(
        f.path.join("gateway/enrollment/state.json"),
        serde_json::to_vec(value).unwrap(),
    )
    .unwrap();
}
fn cleanup(f: Fixture) {
    let path = f.path.clone();
    drop(f);
    fs::remove_dir_all(path).unwrap();
}

#[test]
#[ignore = "STYX_TEST_LEGACY_IMPORT_ROOT + STYX_TEST_NODE22; actual private snapshot/RSA association, not Core import/Gateway handoff"]
fn original_registry_revocation_credentials_and_source_change_batch() {
    let base = PathBuf::from(std::env::var("STYX_TEST_LEGACY_IMPORT_ROOT").unwrap());
    fs::create_dir_all(&base).unwrap();
    let keys = keys();
    let f = fixture(&base, &keys);
    let snapshot = capture(&f.path, f.root.clone(), &f.maintenance).unwrap();
    assert_eq!(snapshot.transaction_id(), f.maintenance.transaction_id());
    assert_eq!(snapshot.default_environment_id(), Some(APPROVED));
    assert_eq!(snapshot.devices.len(), 2);
    assert!(snapshot.blockers().is_empty());
    snapshot.validate_preparation().unwrap();
    assert_eq!(snapshot.summary().unwrap().devices, 2);
    let a = &snapshot.devices[0];
    let r = &snapshot.devices[1];
    assert_eq!(a.status, HistoricalDeviceStatus::Approved);
    assert!(a.effective_capabilities().browser);
    assert_eq!(r.status, HistoricalDeviceStatus::Revoked);
    assert!(!r.effective_capabilities().exec);
    assert!(r.token_material.is_none());
    assert!(!a.public_key_spki_der().is_empty());
    assert!(!a.raw_profile_bytes().is_empty());
    assert_eq!(a.pending_index, 0);
    let material = a.token_material.unwrap();
    assert_eq!(
        snapshot.credential_bytes(material).unwrap(),
        std::str::from_utf8(TOKEN).unwrap().trim().as_bytes()
    );
    assert_eq!(
        snapshot.credential_materials()[material].credential_sha256,
        Sha256Digest::of_bytes(snapshot.credential_bytes(material).unwrap())
    );
    assert_ne!(
        snapshot.credential_materials()[material].raw_sha256,
        snapshot.credential_materials()[material].credential_sha256
    );
    assert!(snapshot.raw_bindings().any(|(p, raw, _, _)| p
        == Path::new("gateway/enrollment/state.json")
        && raw == fs::read(f.path.join(p)).unwrap()));
    f.root.ensure_absent(".styx-enrollment-journal-v1").unwrap();
    assert!(f._owner.ensure_admission().is_err());
    // Same content under a new inode is not the original bound credential.
    let token = f
        .path
        .join(format!("gateway/enrollment/tokens/{APPROVED}.token"));
    let replacement = f.path.join("replacement-owned");
    write(&replacement, TOKEN);
    fs::rename(&replacement, &token).unwrap();
    assert!(matches!(
        snapshot.revalidate(),
        Err(LegacyImportError::Changed)
    ));
    drop(snapshot);
    cleanup(f);
    // Old revoke may have persisted before token unlink failed. Preserve that
    // byte material but never restore an effective grant for the tombstone.
    let f = fixture(&base, &keys);
    write(
        &f.path
            .join(format!("gateway/enrollment/tokens/{REVOKED}.token")),
        TOKEN,
    );
    let snapshot = capture(&f.path, f.root.clone(), &f.maintenance).unwrap();
    let r = &snapshot.devices[1];
    assert!(r.token_material.is_some());
    assert!(!r.effective_capabilities().exec);
    assert!(snapshot.validate_preparation().is_ok());
    drop(snapshot);
    cleanup(f);
}

#[test]
#[ignore = "STYX_TEST_LEGACY_IMPORT_ROOT + STYX_TEST_NODE22; actual protected refusal/blocker aggregate, not native grant or migration"]
fn original_unsettled_and_unsupported_sources_are_not_silently_imported_batch() {
    let base = PathBuf::from(std::env::var("STYX_TEST_LEGACY_IMPORT_ROOT").unwrap());
    fs::create_dir_all(&base).unwrap();
    let keys = keys();
    let f = fixture(&base, &keys);
    let mut db = f.db.clone();
    db["invitations"] = json!([{"id":"0123456789abcdef0123","hash":Sha256Digest::of_bytes(b"unused"),"exp":1,"used":false}]);
    replace_db(&f, &db);
    let snapshot = capture(&f.path, f.root.clone(), &f.maintenance).unwrap();
    assert!(
        snapshot
            .blockers()
            .contains(&PreparationBlocker::UnclosedInvitation)
    );
    assert!(matches!(
        snapshot.validate_preparation(),
        Err(LegacyImportError::Unsettled)
    ));
    drop(snapshot);
    // No clock-based silent pruning of expired-but-unused old invitations.
    replace_db(&f, &f.db);
    let mut db = f.db.clone();
    db["devices"][0]["target"]["exec"]["token_file"] = json!("/tmp/untrusted-other-token");
    replace_db(&f, &db);
    assert!(matches!(
        capture(&f.path, f.root.clone(), &f.maintenance),
        Err(LegacyImportError::Invalid)
    ));
    let mut db = f.db.clone();
    db["pending"].as_array_mut().unwrap().remove(0);
    replace_db(&f, &db);
    assert!(matches!(
        capture(&f.path, f.root.clone(), &f.maintenance),
        Err(LegacyImportError::Unsupported)
    ));
    replace_db(&f, &f.db);
    write(
        &f.path.join("gateway/enrollment/tokens/orphan.token"),
        TOKEN,
    );
    let snapshot = capture(&f.path, f.root.clone(), &f.maintenance).unwrap();
    assert!(
        snapshot
            .blockers()
            .contains(&PreparationBlocker::UnreferencedToken)
    );
    assert!(matches!(
        snapshot.validate_preparation(),
        Err(LegacyImportError::Unsettled)
    ));
    drop(snapshot);
    fs::remove_file(f.path.join("gateway/enrollment/tokens/orphan.token")).unwrap();
    let catalog = json!({"version":1,"targets":[{"id":"static-owned","kind":"environment","platform":"linux","generation":"original","allowed":false,"cwd":"/tmp","shell":"/bin/sh","shells":["/bin/sh"],"exec":{"transport":"websocket","url":"ws://127.0.0.1:1/"}}]});
    fs::write(
        f.path.join("gateway/targets.json"),
        serde_json::to_vec(&catalog).unwrap(),
    )
    .unwrap();
    let snapshot = capture(&f.path, f.root.clone(), &f.maintenance).unwrap();
    assert_eq!(snapshot.static_targets.len(), 1);
    assert!(
        snapshot
            .blockers()
            .contains(&PreparationBlocker::StaticCatalogTargets)
    );
    assert!(matches!(
        snapshot.validate_preparation(),
        Err(LegacyImportError::Unsettled)
    ));
    drop(snapshot);
    cleanup(f);
    let other = fixture(&base, &keys);
    let f = fixture(&base, &keys);
    assert!(matches!(
        capture(&f.path, f.root.clone(), &other.maintenance),
        Err(LegacyImportError::Maintenance)
    ));
    cleanup(other);
    cleanup(f);
}

#[test]
#[ignore = "STYX_TEST_LEGACY_IMPORT_ROOT + STYX_TEST_NODE22; protected original RSA history projection and real process reopen; not original Gateway settlement or C07 admission"]
fn original_history_persistence_and_process_reopen_remain_migration_fenced() {
    use crate::{
        migration::legacy_enrollment::LegacyEnrollmentSnapshot,
        store::enrollment::{JournalBudget, OwnedEnrollmentJournal},
    };
    let base = PathBuf::from(std::env::var("STYX_TEST_LEGACY_IMPORT_ROOT").unwrap());
    if let Some(path) = std::env::var_os("STYX_TEST_HISTORY_REOPEN_CHILD") {
        let path = PathBuf::from(path);
        assert!(path.starts_with(&base));
        let root = PrivateRoot::open(&path).unwrap();
        let writer = root.try_existing_configuration_writer().unwrap();
        let mut journal =
            OwnedEnrollmentJournal::open_existing(root, writer, JournalBudget::default()).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        journal
            .with_journal(|j| {
                let recovered = crate::enrollment::recovery::recover_journal(
                    j,
                    "actual-history-reopen".try_into().unwrap(),
                    styx_core::enrollment::Limits::default(),
                    now,
                )
                .unwrap();
                let active = recovered
                    .ledger
                    .devices_for_admin(&recovered.control.admin())
                    .unwrap();
                let revoked = recovered
                    .ledger
                    .historical_revoked_for_recovery(&recovered.control)
                    .unwrap();
                assert_eq!(active.len(), 1);
                assert_eq!(revoked.len(), 1);
                assert_eq!(active[0].id.as_str(), APPROVED);
                assert_eq!(revoked[0].id.as_str(), REVOKED);
                assert_eq!(active[0].generation, "capability-0123456789abcdef");
                assert!(active[0].grant.browser);
                assert_eq!(
                    recovered
                        .ledger
                        .default_device_for_admin(&recovered.control.admin())
                        .unwrap()
                        .as_ref()
                        .map(|s| s.as_str()),
                    Some(APPROVED)
                );
                assert!(
                    recovered
                        .ledger
                        .authentication_target(&recovered.control, &revoked[0].id)
                        .is_err()
                );
                let proof = recovered.control.attest_device(
                    active[0].id.clone(),
                    active[0].fingerprint,
                    active[0].credential_hash,
                );
                assert_eq!(
                    recovered.ledger.connection_observations(&proof).unwrap(),
                    [styx_core::enrollment::ConnectionObservation::Unknown; 3]
                );
                assert_eq!(recovered.facts.revision, 1);
                Ok(())
            })
            .unwrap();
        // This exercises real RSA/SPKI material validation, unlike the separate
        // synthetic recovery codec aggregate. No transport is published.
        let mut service = crate::enrollment::service::EnrollmentService::recover_existing(
            journal,
            b"actual-owned-history-admin-1234567890",
            Sha256Digest::of_bytes(b"different-owned-mcp"),
            vec!["127.0.0.1:8443".to_owned()],
            styx_core::enrollment::Limits::default(),
        )
        .unwrap();
        let error = match service.exec_profiles() {
            Ok(_) => panic!("pending migration must not publish exec profiles"),
            Err(error) => error,
        };
        assert_eq!(error.code(), "migration_commit_required");
        let report = PathBuf::from(std::env::var_os("STYX_TEST_HISTORY_REOPEN_REPORT").unwrap());
        assert!(report.starts_with(&base));
        write(&report,&serde_json::to_vec(&json!({"schema":1,"status":"PASS_ORIGINAL_HISTORY_REOPEN_ONLY","actual_rsa_spki_profiles_verified":true,"original_active_grant_generation_default_preserved":true,"tokenless_revoked_preserved_and_denied":true,"recovered_connections_unknown":true,"ordinary_execution_profiles_refused":"migration_commit_required","migration_committed":false,"network_published":false,"native_activated":false})).unwrap());
        return;
    }
    fs::create_dir_all(&base).unwrap();
    let keys = keys();
    let f = fixture(&base, &keys);
    let snapshot =
        LegacyEnrollmentSnapshot::capture(&f.path, f.root.clone(), &f.maintenance).unwrap();
    let source_files = [
        "deployment.json",
        "state.json",
        "gateway/runtime.json",
        "gateway/targets.json",
        "gateway/enrollment/state.json",
    ];
    let original: Vec<_> = source_files
        .iter()
        .map(|p| {
            (
                (*p).to_owned(),
                Sha256Digest::of_bytes(&fs::read(f.path.join(p)).unwrap()),
            )
        })
        .collect();
    let original_token = f
        .path
        .join(format!("gateway/enrollment/tokens/{APPROVED}.token"));
    let before = fs::metadata(&original_token).unwrap();
    let original_token_raw = zeroize::Zeroizing::new(fs::read(&original_token).unwrap());
    let path = f.path.join("gateway/enrollment");
    let root = PrivateRoot::open(&path).unwrap();
    let writer = root.try_configuration_writer().unwrap();
    let owner = OwnedConfigurationRoot::open_existing(root, writer).unwrap();
    let maintenance = owner
        .begin_maintenance(f.maintenance.transaction_id().clone())
        .unwrap();
    let mut journal = snapshot.claim_history_store(&owner, &maintenance).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let committed = snapshot
        .persist_candidate_history(
            &mut journal,
            &maintenance,
            "original-history-epoch".try_into().unwrap(),
            now,
        )
        .unwrap();
    assert!(owner.ensure_admission().is_err());
    assert!(journal.with_journal(|_| Ok(())).is_err());
    assert!(
        snapshot
            .persist_candidate_history(
                &mut journal,
                &maintenance,
                "original-history-epoch".try_into().unwrap(),
                now
            )
            .is_err()
    );
    let observation = journal
        .with_historical_journal(&maintenance, |j| j.resync_historical())
        .unwrap()
        .unwrap();
    assert_eq!(observation.committed, Some(committed));
    assert_eq!(observation.body.devices.len(), 1);
    assert_eq!(observation.body.revoked.len(), 1);
    assert_eq!(observation.body.token_bindings.len(), 1);
    let binding = &observation.body.token_bindings[0];
    assert_eq!(
        binding.raw_material.digest,
        Sha256Digest::of_bytes(&original_token_raw)
    );
    assert_ne!(
        binding.raw_material.digest,
        binding.normalized_material.digest
    );
    for (relative, digest) in &original {
        assert_eq!(
            Sha256Digest::of_bytes(&fs::read(f.path.join(relative)).unwrap()),
            *digest
        );
    }
    use std::os::unix::fs::MetadataExt;
    let after = fs::metadata(&original_token).unwrap();
    assert_eq!(
        (
            before.dev(),
            before.ino(),
            before.mode(),
            before.mtime(),
            before.ctime()
        ),
        (
            after.dev(),
            after.ino(),
            after.mode(),
            after.mtime(),
            after.ctime()
        )
    );
    assert!(!path.join(format!("tokens/{REVOKED}.token")).exists());
    // End this enrollment writer before starting a genuinely independent process.
    drop(journal);
    drop(maintenance);
    drop(owner);
    let report = f.path.join("history-reopened.json");
    let output=Command::new(std::env::current_exe().unwrap()).args(["--ignored","--exact","enrollment::legacy_import::tests::original_history_persistence_and_process_reopen_remain_migration_fenced","--nocapture"]).env("STYX_TEST_HISTORY_REOPEN_CHILD",&path).env("STYX_TEST_HISTORY_REOPEN_REPORT",&report).output().unwrap();
    assert!(
        output.status.success(),
        "owned history reopen child failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let reopened: serde_json::Value = serde_json::from_slice(&fs::read(&report).unwrap()).unwrap();
    assert_eq!(reopened["status"], "PASS_ORIGINAL_HISTORY_REOPEN_ONLY");
    snapshot.revalidate().unwrap();
    for (relative, digest) in &original {
        assert_eq!(
            Sha256Digest::of_bytes(&fs::read(f.path.join(relative)).unwrap()),
            *digest
        );
    }
    write(&base.join("original-history-effect-receipt.json"),&serde_json::to_vec(&json!({"schema":1,"status":"PASS_ORIGINAL_HISTORY_PERSISTENCE_AND_REOPEN_ONLY","fixture":f.path,"source_original_hashes":original,"original_token_raw_sha256":binding.raw_material.digest,"normalized_token_sha256":binding.normalized_material.digest,"original_token_inode":before.ino(),"original_token_device":before.dev(),"original_token_mode":before.mode(),"original_active_id":APPROVED,"original_revoked_id":REVOKED,"child_actual_wait_exit0":output.status.success(),"reopened":reopened,"scope":"protected legacy-file/RSA fixture and new process native recovery; no actual old Gateway settlement, first onboarding, C07 commit, remote authentication or activation"})).unwrap());
    // Retain this one positive fixture for an independent post-test file oracle.
    drop(snapshot);
    drop(f);
}
