//! Real private files and a synthetic signed C08; no executable is launched.
use super::*;
use ed25519_dalek::{Signer as _, SigningKey, pkcs8::EncodePublicKey as _};
use std::{
    fs,
    io::Write as _,
    os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _},
};

#[test]
fn fresh_profile_keeps_original_release_and_refuses_foreign_selection_or_replaced_member() {
    fn directory(path: &Path) {
        fs::DirBuilder::new().mode(0o700).create(path).unwrap();
    }
    fn write(path: &Path, bytes: &[u8], executable: bool) {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(if executable { 0o700 } else { 0o600 })
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }
    let root = std::env::temp_dir().join(format!("styx-profile-retained-{}", uuid::Uuid::new_v4()));
    directory(&root);
    let key = SigningKey::from_bytes(&[43u8; 32]);
    let der = key.verifying_key().to_public_key_der().unwrap();
    let pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        base64::engine::general_purpose::STANDARD.encode(der.as_bytes())
    );
    let publisher = root.join("publisher.pem");
    write(&publisher, pem.as_bytes(), false);
    let expected = PublisherVerifyingKey::from_spki_pem(pem.as_bytes())
        .unwrap()
        .fingerprint()
        .unwrap();
    let make = |name: &str| {
        let payload = root.join(name);
        directory(&payload);
        directory(&payload.join("bin"));
        let sources = [
            (
                "LICENSE",
                b"synthetic retained profile license".as_slice(),
                false,
            ),
            (
                "bin/styx",
                b"\x7fELF synthetic fixture, never executed".as_slice(),
                true,
            ),
            (
                "source-inputs.json",
                b"synthetic retained profile inputs".as_slice(),
                false,
            ),
        ];
        let files: Vec<_> = sources
            .iter()
            .map(|(name, bytes, executable)| {
                write(&payload.join(name), bytes, *executable);
                styx_contracts::native_release::NativeReleaseMember {
                    path: (*name).to_owned(),
                    size: bytes.len() as u64,
                    sha256: Sha256Digest::of_bytes(bytes),
                    executable: *executable,
                }
            })
            .collect();
        let manifest = serde_json::json!({"schema":2,"runtime_format":"native_rust_v1","component":"styx",
            "scope":"runtime_candidate","minimum_reader":"native_app_service_transferred_v1","target":"x86_64-unknown-linux-gnu",
            "version":"0.4.0-test.1","entrypoint":"bin/styx","source":{"revision":"1".repeat(40),
            "inputs_sha256":Sha256Digest::of_bytes(sources[2].1)},"contracts":{"control":1,"management_state":6},
            "files":files,"external_workers":[]});
        let raw = serde_json::to_vec(&manifest).unwrap();
        write(&payload.join("manifest.json"), &raw, false);
        write(
            &payload.join("manifest.sig"),
            &key.sign(&raw).to_bytes(),
            false,
        );
        let verified = crate::release::verify(&payload, &publisher, &expected).unwrap();
        let selection = verified.runtime_selection().unwrap();
        (Arc::new(verified), selection)
    };
    let (original, selection) = make("original");
    let profile =
        ProfileRelease::from_retained_native(&selection, &expected, original.clone()).unwrap();
    match &profile.retained {
        RetainedRelease::Native { verified } => assert!(Arc::ptr_eq(verified, &original)),
        _ => panic!("fresh profile must retain the original native release"),
    }
    profile.revalidate().unwrap();
    let mut wrong = selection.clone();
    wrong.manifest_sha256 = Sha256Digest::of_bytes(b"other manifest");
    assert!(ProfileRelease::from_retained_native(&wrong, &expected, original.clone()).is_err());
    let (_, foreign_selection) = make("foreign");
    assert!(
        ProfileRelease::from_retained_native(&foreign_selection, &expected, original.clone())
            .is_err()
    );
    let wrong_publisher =
        PublisherFingerprint::parse(&Sha256Digest::of_bytes(b"other publisher").to_hex()).unwrap();
    assert!(
        ProfileRelease::from_retained_native(&selection, &wrong_publisher, original.clone())
            .is_err()
    );
    // Same bytes at the same pathname cannot replace the originally verified inode.
    let member = root.join("original/source-inputs.json");
    fs::rename(&member, root.join("held-member-original")).unwrap();
    write(&member, b"synthetic retained profile inputs", false);
    assert!(ProfileRelease::from_retained_native(&selection, &expected, original.clone()).is_err());
    assert!(profile.revalidate().is_err());
    drop(profile);
    drop(original);
    fs::remove_dir_all(root).unwrap();
}
