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
