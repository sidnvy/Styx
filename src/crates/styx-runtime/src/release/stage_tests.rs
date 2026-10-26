//! Real private-filesystem staging with a synthetic test publisher. No execution.
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[tokio::test]
async fn signed_stage_is_exact_exclusive_and_keeps_failed_publications() {
    use super::*;
    use base64::Engine as _;
    use ed25519_dalek::{Signer as _, SigningKey, pkcs8::EncodePublicKey as _};
    use std::{
        ffi::OsStr,
        fs,
        os::unix::fs::{DirBuilderExt, PermissionsExt},
    };
    fn directory(path: &Path) {
        fs::DirBuilder::new().mode(0o700).create(path).unwrap();
    }
    fn write(path: &Path, bytes: &[u8], executable: bool) {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(if executable { 0o700 } else { 0o600 })
            .open(path)
            .unwrap();
        f.write_all(bytes).unwrap();
        f.sync_all().unwrap();
    }
    let root = std::env::temp_dir().join(format!("styx-signed-stage-{}", uuid::Uuid::new_v4()));
    directory(&root);
    let payload = root.join("source");
    directory(&payload);
    directory(&payload.join("bin"));
    let sources = [
        (
            "LICENSE",
            b"synthetic staging fixture license".to_vec(),
            false,
        ),
        (
            "bin/styx",
            b"\x7fELF synthetic pin fixture, never executed".to_vec(),
            true,
        ),
        ("source-inputs.json", vec![b'x'; 3 * 64 * 1024 + 17], false),
    ];
    let files: Vec<_> = sources
        .iter()
        .map(|(path, bytes, executable)| {
            write(&payload.join(path), bytes, *executable);
            styx_contracts::native_release::NativeReleaseMember {
                path: (*path).to_owned(),
                size: bytes.len() as u64,
                sha256: Sha256Digest::of_bytes(bytes),
                executable: *executable,
            }
        })
        .collect();
    let key = SigningKey::from_bytes(&[37u8; 32]);
    let der = key.verifying_key().to_public_key_der().unwrap();
    let pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        base64::engine::general_purpose::STANDARD.encode(der.as_bytes())
    );
    let publisher = root.join("original-publisher.pem");
    write(&publisher, pem.as_bytes(), false);
    let expected = PublisherVerifyingKey::from_spki_pem(pem.as_bytes())
        .unwrap()
        .fingerprint()
        .unwrap();
    let manifest = serde_json::json!({"schema":2,"runtime_format":"native_rust_v1","component":"styx",
        "scope":"runtime_candidate","minimum_reader":"native_runtime_migrated_v3","target":"x86_64-unknown-linux-gnu",
        "version":"0.4.0-test.1","entrypoint":"bin/styx","source":{"revision":"1".repeat(40),
        "inputs_sha256":Sha256Digest::of_bytes(&sources[2].1)},"contracts":{"control":1,"management_state":2},
        "files":files,"external_workers":[]});
    let raw = serde_json::to_vec(&manifest).unwrap();
    write(&payload.join("manifest.json"), &raw, false);
    write(
        &payload.join("manifest.sig"),
        &key.sign(&raw).to_bytes(),
        false,
    );
    let source_before = verify(&payload, &publisher, &expected)
        .unwrap()
        .runtime_selection()
        .unwrap();
    let selected = stage(
        &payload,
        &publisher,
        expected.as_hex(),
        &root,
        OsStr::new("version-one"),
    )
    .await
    .unwrap();
    assert_ne!(selected.payload_root, source_before.payload_root);
    assert_eq!(selected.manifest_sha256, source_before.manifest_sha256);
    assert_eq!(
        selected.publisher_spki_sha256,
        source_before.publisher_spki_sha256
    );
    assert_eq!(
        Path::new(&selected.publisher_file),
        root.join("version-one/publisher.pem")
    );
    let staged = verify_selected(&selected).unwrap();
    assert_eq!(staged.manifest_file.bytes(), raw);
    assert_eq!(
        fs::metadata(root.join("version-one/payload/bin/styx"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert!(
        stage(
            &payload,
            &publisher,
            expected.as_hex(),
            &root,
            OsStr::new("version-one")
        )
        .await
        .is_err()
    );
    assert_eq!(
        verify_selected(&selected)
            .unwrap()
            .runtime_selection()
            .unwrap(),
        selected
    );
    assert!(
        stage(
            &payload,
            &publisher,
            &"0".repeat(64),
            &root,
            OsStr::new("wrong-key")
        )
        .await
        .is_err()
    );
    assert!(!root.join("wrong-key").exists());
    // Hash failure after CREATE_NEW retains a partial publication, and a new
    // instance cannot adopt that directory to retry the copy.
    let parent = PrivateRoot::open(&root).unwrap();
    let source = PrivateRoot::open(&payload).unwrap();
    let mut partial =
        crate::store::ReleaseStage::create(&parent, &root, OsStr::new("partial")).unwrap();
    assert!(
        partial
            .copy_member(
                &source,
                crate::store::ReleaseCopyMember {
                    source_relative: Path::new("source-inputs.json"),
                    destination_relative: Path::new("payload/source-inputs.json"),
                    bytes: sources[2].1.len() as u64,
                    sha256: Sha256Digest::of_bytes(b"wrong"),
                    executable: false,
                }
            )
            .is_err()
    );
    assert!(root.join("partial/payload/source-inputs.json").is_file());
    assert!(crate::store::ReleaseStage::create(&parent, &root, OsStr::new("partial")).is_err());
    let mut tampered = fs::read(payload.join("LICENSE")).unwrap();
    tampered[0] ^= 1;
    fs::write(payload.join("LICENSE"), tampered).unwrap();
    assert!(
        stage(
            &payload,
            &publisher,
            expected.as_hex(),
            &root,
            OsStr::new("tampered-source")
        )
        .await
        .is_err()
    );
    assert!(!root.join("tampered-source").exists());
    // Deliberately retain source, destination and failed partial fixtures.
}
