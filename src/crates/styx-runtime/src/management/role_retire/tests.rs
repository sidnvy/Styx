use super::*;
use crate::store::enrollment::{EnrollmentJournal, JournalBudget, MaterialKind};
use std::{
    fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
};
use styx_contracts::{enrollment::*, identity::*, legacy::JoinPayload};
use styx_core::enrollment::{
    ApprovalRequest, EnrollmentControl, EnrollmentLedger, Limits, PendingIntent,
};

pub(crate) struct Temp(pub PathBuf);
impl Temp {
    pub(crate) fn new() -> Self {
        let path = std::env::temp_dir().join(format!("styx-retire-{}", uuid::Uuid::new_v4()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    pub(crate) fn child(&self, name: &str) -> PathBuf {
        let path = self.0.join(name);
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        path
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
pub(crate) fn file(path: &Path, bytes: &[u8]) {
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}
fn hash(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::of_bytes(bytes)
}
fn commit(
    journal: &mut EnrollmentJournal<'_>,
    ledger: &mut EnrollmentLedger,
    control: &EnrollmentControl,
    intent: &PendingIntent,
    previous: &mut Option<Sha256Digest>,
) {
    let prepared = journal.prepare(intent.original_bytes(), *previous).unwrap();
    let committed = journal.commit(&prepared).unwrap().digest().unwrap();
    ledger
        .confirm_durable(control.attest_durable(intent, committed))
        .unwrap();
    *previous = Some(committed);
}
/// Real bounded journal/Core commits and real profile key. No network, executor,
/// synthetic approved-device list or mocked retirement I/O.
fn gateway_with_device(path: &Path, revoked: bool) -> (DeviceId, Sha256Digest) {
    let root = PrivateRoot::open(path).unwrap();
    let mut writer = root.try_configuration_writer().unwrap();
    let mut journal =
        EnrollmentJournal::open(&root, &mut writer, JournalBudget::default()).unwrap();
    journal.record_time_floor(1000).unwrap();
    let (mut ledger, control) =
        EnrollmentLedger::new_recovering("retire-fixture".try_into().unwrap(), Limits::default())
            .unwrap();
    ledger
        .finish_recovery(control.attest_recovery_closure(0, 0, None, None, 1000, 1000))
        .unwrap();
    let key = crate::crypto::DevicePrivateKey::generate_rsa3072().unwrap();
    let fingerprint: Sha256Digest = key
        .public_key()
        .fingerprint()
        .as_hex()
        .to_owned()
        .try_into()
        .unwrap();
    let device_id: DeviceId = "styx-other-computer".try_into().unwrap();
    let profile = serde_json::to_vec(&serde_json::json!({"schema":1,"device_id":device_id,"fingerprint":fingerprint,"label":"Other laptop","platform":"linux","cwd":"/tmp","shell":"/bin/sh","public_key_pem":key.public_key_pem()})).unwrap();
    let profile = journal
        .put_material(MaterialKind::Profile, &profile)
        .unwrap();
    let token = journal
        .put_material(
            MaterialKind::Token,
            b"owned-fixture-token-not-a-real-credential",
        )
        .unwrap();
    let sealed = journal
        .put_material(MaterialKind::Sealed, b"owned-fixture-sealed-bytes")
        .unwrap();
    let mut previous = None;
    let payload = JoinPayload {
        invitation: "owned-fixture-one-use-invitation".into(),
        device_id: device_id.clone(),
        label: "Other laptop".into(),
        platform: "linux".into(),
        cwd: "/tmp".into(),
        shell: "/bin/sh".into(),
        computer_requested: false,
        public_key_pem: key.public_key_pem().into(),
        browser_requested: Some(false),
    };
    let invite = ledger
        .invite(
            &control.admin(),
            hash(payload.invitation.as_bytes()),
            60,
            None,
            1001,
        )
        .unwrap();
    commit(&mut journal, &mut ledger, &control, &invite, &mut previous);
    let request: RequestId = "0123456789abcdef0123456789abcdef".try_into().unwrap();
    let proof = control
        .attest_join(
            &payload,
            fingerprint,
            request.clone(),
            hash(b"claim"),
            OpaqueProfileRef(profile.digest),
            PairingContext {
                origin: "https://127.0.0.1:22022".into(),
                leaf: hash(b"leaf"),
                ingress_generation: "retire-ingress".try_into().unwrap(),
                window: None,
            },
        )
        .unwrap();
    let join = ledger.join(proof, 1002).unwrap();
    commit(&mut journal, &mut ledger, &control, &join, &mut previous);
    let comparison = ledger.pending_for_admin(&control.admin(), 1002).unwrap()[0]
        .facts
        .comparison
        .clone();
    let credential = control
        .attest_prepared_credential(
            ledger.approval_target(&control.admin(), &request).unwrap(),
            CredentialRef(token.digest),
            token.digest,
            SealedCredentialRef(sealed.digest),
        )
        .unwrap();
    let approved = ledger
        .approve(
            &control.admin(),
            ApprovalRequest {
                request,
                fingerprint,
                comparison,
                grant: Grant {
                    computer: false,
                    browser: false,
                },
            },
            credential,
            1003,
        )
        .unwrap();
    commit(
        &mut journal,
        &mut ledger,
        &control,
        &approved,
        &mut previous,
    );
    if revoked {
        let revoke = ledger.revoke(&control.admin(), &device_id, 1004).unwrap();
        commit(&mut journal, &mut ledger, &control, &revoke, &mut previous);
    }
    journal.record_time_floor(1004).unwrap();
    (device_id, fingerprint)
}

#[test]
fn retire_refuses_held_execution_lease_without_moving_any_root() {
    let temp = Temp::new();
    let host = temp.child("host");
    let gateway = temp.child("gateway");
    let root = PrivateRoot::open(&gateway).unwrap();
    let lease = root.try_execution_lease().unwrap();
    let error = retire_role(&host, Some(&gateway), RetireOptions::default()).unwrap_err();
    assert_eq!(error.code, "role_retire_role_busy");
    assert!(host.is_dir() && gateway.is_dir());
    drop(lease);
    let root = PrivateRoot::open(&host).unwrap();
    let lease = root.try_execution_lease().unwrap();
    assert_eq!(
        retire_role(&host, None, RetireOptions::default())
            .unwrap_err()
            .code,
        "role_retire_role_busy"
    );
    drop(lease);
}
#[test]
fn retire_gateway_requires_other_device_confirmation_and_preserves_bytes_and_inodes() {
    let temp = Temp::new();
    let host = temp.child("host");
    let gateway = temp.child("gateway");
    file(&host.join("owned.txt"), b"preserve original bytes");
    let (device, _) = gateway_with_device(&gateway, false);
    let before = fs::metadata(host.join("owned.txt")).unwrap().ino();
    let journal_before = fs::read_dir(gateway.join(".styx-enrollment-journal-v1"))
        .unwrap()
        .count();
    let refusal = retire_role(&host, Some(&gateway), RetireOptions::default()).unwrap_err();
    assert_eq!(refusal.code, "role_retire_gateway_has_devices");
    assert_eq!(refusal.report.other_devices[0].device_id, device);
    assert_eq!(refusal.report.other_devices[0].label, "Other laptop");
    assert!(host.is_dir() && gateway.is_dir());
    let report = retire_role(
        &host,
        Some(&gateway),
        RetireOptions {
            allow_other_devices: true,
        },
    )
    .unwrap();
    assert_eq!(report.retired.len(), 2);
    assert!(!host.exists() && !gateway.exists());
    let host_backup = &report.retired[0].new_path;
    assert_eq!(
        fs::metadata(host_backup.join("owned.txt")).unwrap().ino(),
        before
    );
    assert_eq!(
        fs::read(host_backup.join("owned.txt")).unwrap(),
        b"preserve original bytes"
    );
    assert_eq!(
        fs::read_dir(
            report.retired[1]
                .new_path
                .join(".styx-enrollment-journal-v1")
        )
        .unwrap()
        .count(),
        journal_before
    );
    assert!(
        host_backup
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("host.retired-")
    );
    // The actual fresh native root publisher accepts both original names again.
    let parent = PrivateRoot::open(&temp.0).unwrap();
    let fresh_host = crate::store::native_root::create_fresh(&parent, std::ffi::OsStr::new("host"))
        .unwrap_or_else(|e| panic!("{:?}", e.error()));
    let fresh_gateway =
        crate::store::native_root::create_fresh(&parent, std::ffi::OsStr::new("gateway"))
            .unwrap_or_else(|e| panic!("{:?}", e.error()));
    drop((fresh_host, fresh_gateway));
    assert!(host_backup.is_dir());
}
#[test]
fn retire_never_overwrites_a_backup_created_after_preflight() {
    let temp = Temp::new();
    let host = temp.child("host");
    let prepared = prepare(Some(&host), None, RetireOptions::default()).unwrap();
    let backup = prepared.paths[0].new_path.clone();
    fs::create_dir(&backup).unwrap();
    file(&backup.join("keep"), b"original backup");
    let failure = prepared.retire().unwrap_err();
    assert_eq!(failure.report.outcome, "unknown");
    assert!(host.is_dir());
    assert_eq!(fs::read(backup.join("keep")).unwrap(), b"original backup");
}
#[test]
fn retire_refuses_nested_roots_and_unproven_gateway_enrollment() {
    let temp = Temp::new();
    let host = temp.child("host");
    let gateway = temp.child("gateway");
    assert_eq!(
        retire_role(&host, Some(&temp.0), RetireOptions::default())
            .unwrap_err()
            .code,
        "role_retire_invalid_roots"
    );
    assert_eq!(
        retire_role(
            &host,
            Some(&gateway),
            RetireOptions {
                allow_other_devices: true
            }
        )
        .unwrap_err()
        .code,
        "role_retire_enrollment_unproven"
    );
    assert!(host.is_dir() && gateway.is_dir());
}

#[test]
fn retire_excludes_only_the_matching_own_host_identity() {
    use styx_contracts::native_management::{NativeRootIdentity, NativeRuntimeSelection};
    let temp = Temp::new();
    let host = temp.child("host");
    let gateway = temp.child("gateway");
    let (device_id, fingerprint) = gateway_with_device(&gateway, false);
    let meta = fs::metadata(&host).unwrap();
    let identity = NativeRootIdentity::Linux {
        device: meta.dev(),
        inode: meta.ino(),
        uid: meta.uid(),
    };
    let mut seed = NativeHostJoinSeed {
        schema: 1,
        root_identity: identity.clone(),
        scope_generation: hash(b"scope"),
        deployment_raw_sha256: hash(b"deployment"),
        runtime: NativeRuntimeSelection {
            schema: 1,
            payload_path: temp.0.join("payload").display().to_string(),
            payload_root: identity,
            manifest_sha256: hash(b"manifest"),
            publisher_file: temp.0.join("publisher.pem").display().to_string(),
            publisher_spki_sha256: hash(b"publisher"),
        },
        gateway_origin: "https://127.0.0.1:22022".into(),
        anchor_sha256: hash(b"ca"),
        device_id,
        fingerprint: hash(b"wrong own fingerprint"),
        public_key_pem: "not used by retirement".into(),
        label: "This computer".into(),
        platform: "linux".into(),
        cwd: "/tmp".into(),
        shell: "/bin/sh".into(),
        computer_requested: false,
        browser_requested: false,
    };
    let seed_path = host.join("host-join-seed-v1.json");
    file(&seed_path, &serde_json::to_vec(&seed).unwrap());
    assert_eq!(
        retire_role(&host, Some(&gateway), RetireOptions::default())
            .unwrap_err()
            .code,
        "role_retire_gateway_has_devices"
    );
    seed.fingerprint = fingerprint;
    fs::write(&seed_path, serde_json::to_vec(&seed).unwrap()).unwrap();
    let report = retire_role(&host, Some(&gateway), RetireOptions::default()).unwrap();
    assert!(report.other_devices.is_empty());
    assert_eq!(report.retired.len(), 2);
}

#[test]
fn retire_revoked_devices_do_not_require_confirmation() {
    let temp = Temp::new();
    let host = temp.child("host");
    let gateway = temp.child("gateway");
    gateway_with_device(&gateway, true);
    let report = retire_role(&host, Some(&gateway), RetireOptions::default()).unwrap();
    assert!(report.other_devices.is_empty());
}
