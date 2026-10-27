//! Actual signed-package fixture: no signer, executor, SDK or OS mutation.
//! The native batch prepares protected independent copies before invoking this
//! test. Tampered copies are not made by rewriting a retained verified image.
use super::*;
use crate::store::RootIdentity;

#[tokio::test]
#[ignore = "requires explicit protected Windows signed runtime package and refusal copies"]
async fn actual_signed_windows_runtime_closure_selection_and_refusals() {
    let path =
        PathBuf::from(std::env::var_os("STYX_TEST_WINDOWS_RELEASE_ROOT").expect("fixture root"));
    let fixture = PrivateRoot::open(&path).expect("protected existing fixture");
    let expected = PublisherFingerprint::parse(
        &std::env::var("STYX_TEST_WINDOWS_RELEASE_PUBLISHER_PIN")
            .expect("external test publisher pin"),
    )
    .expect("public pin");
    let publisher = path.join("publisher.pem");
    let payload = path.join("valid");
    let verified =
        verify(&payload, &publisher, &expected).expect("actual approved signed Windows closure");
    let report = verified.report();
    assert_eq!(report.target, "x86_64-pc-windows-msvc");
    assert_eq!(report.entrypoint, "bin/styx.exe");
    assert_eq!(report.scope, "runtime_candidate");
    assert!(!report.installed && !report.runtime_launched);
    assert!(
        verified
            .supports_state_reader(ReaderContract::NativeMigratedStateV1)
            .unwrap()
    );
    assert!(matches!(
        verified.launch_path(),
        Err(ReleaseError::Unsupported)
    ));
    for worker in &verified.manifest().worker_closures {
        assert!(worker.entrypoint.ends_with(".exe"));
        let image = verified
            .worker_image(worker.kind)
            .expect("same approved inventory PE pin");
        image.revalidate().expect("original worker kernel identity");
        assert!(matches!(image.launch_path(), Err(StoreError::Unsupported)));
    }
    // These original HANDLEs reject physical publisher/root replacement;
    // failure is not inferred from signature metadata or a serialized report.
    let moved_publisher = path.join(format!("publisher-moved-{}", uuid::Uuid::new_v4().simple()));
    let moved_root = path.join(format!("payload-moved-{}", uuid::Uuid::new_v4().simple()));
    assert!(std::fs::rename(&publisher, &moved_publisher).is_err());
    assert!(std::fs::rename(&payload, &moved_root).is_err());
    assert!(!moved_publisher.exists() && !moved_root.exists());
    verified
        .revalidate()
        .expect("original publisher/root still pinned");

    let selection = verified
        .runtime_selection()
        .expect("original observed Windows selection");
    let RootIdentity::Windows {
        volume_serial,
        file_id,
        owner_sid,
    } = PrivateRoot::open(&payload).unwrap().identity()
    else {
        panic!("actual protected root is not Windows");
    };
    assert_eq!(
        selection.payload_root,
        NativeRootIdentity::Windows {
            volume_serial,
            file_id,
            owner_sid
        }
    );
    let reopened =
        verify_selected(&selection).expect("fresh read-only selected release verification");
    assert_eq!(reopened.report().manifest_sha256, report.manifest_sha256);
    assert_eq!(reopened.runtime_selection().unwrap(), selection);
    let inspected = inspect(&payload, &publisher, expected.as_hex())
        .await
        .expect("bounded original-worker inspector");
    assert_eq!(inspected.manifest_sha256, report.manifest_sha256);

    // These retain exactly the original signed manifest/signature except the
    // explicit signature case. Public observations establish each real delta.
    let valid_root = PrivateRoot::open(&payload).unwrap();
    let manifest = valid_root
        .read_raw("manifest.json", NATIVE_RELEASE_MANIFEST_BYTES)
        .unwrap();
    let signature = valid_root.read_raw("manifest.sig", 64).unwrap();
    let member_root = PrivateRoot::open(path.join("member-tampered")).unwrap();
    assert_eq!(
        member_root
            .read_raw("manifest.json", NATIVE_RELEASE_MANIFEST_BYTES)
            .unwrap()
            .bytes(),
        manifest.bytes()
    );
    assert_eq!(
        member_root.read_raw("manifest.sig", 64).unwrap().bytes(),
        signature.bytes()
    );
    let altered = member_root
        .payload_inventory(PayloadLimits::default())
        .unwrap();
    assert!(altered.members().iter().any(|actual| {
        verified.inventory.members().iter().any(|original| {
            original.path == actual.path
                && (original.sha256 != actual.sha256 || original.bytes != actual.bytes)
        })
    }));
    assert!(matches!(
        verify(&path.join("member-tampered"), &publisher, &expected),
        Err(ReleaseError::Integrity)
    ));

    let signature_root = PrivateRoot::open(path.join("signature-tampered")).unwrap();
    assert_eq!(
        signature_root
            .read_raw("manifest.json", NATIVE_RELEASE_MANIFEST_BYTES)
            .unwrap()
            .bytes(),
        manifest.bytes()
    );
    assert_ne!(
        signature_root.read_raw("manifest.sig", 64).unwrap().bytes(),
        signature.bytes()
    );
    assert!(matches!(
        verify(&path.join("signature-tampered"), &publisher, &expected),
        Err(ReleaseError::Untrusted)
    ));

    let extra_root = PrivateRoot::open(path.join("extra-member")).unwrap();
    assert_eq!(
        extra_root
            .read_raw("manifest.json", NATIVE_RELEASE_MANIFEST_BYTES)
            .unwrap()
            .bytes(),
        manifest.bytes()
    );
    assert_eq!(
        extra_root.read_raw("manifest.sig", 64).unwrap().bytes(),
        signature.bytes()
    );
    let extra = extra_root
        .payload_inventory(PayloadLimits::default())
        .unwrap();
    assert!(extra.members().iter().any(|actual| {
        !verified
            .inventory
            .members()
            .iter()
            .any(|original| original.path == actual.path)
    }));
    assert!(matches!(
        verify(&path.join("extra-member"), &publisher, &expected),
        Err(ReleaseError::Integrity)
    ));

    let foreign = PrivateRoot::open(path.join("wrong-target")).unwrap();
    let foreign_raw = foreign
        .read_raw("manifest.json", NATIVE_RELEASE_MANIFEST_BYTES)
        .unwrap();
    let foreign_sig = foreign.read_raw("manifest.sig", 64).unwrap();
    let public = fixture.read_raw("publisher.pem", 4096).unwrap();
    PublisherVerifyingKey::from_spki_pem(public.bytes())
        .unwrap()
        .verify_manifest(
            &expected,
            RawReleaseManifest::from_original_bytes(foreign_raw.bytes()),
            foreign_sig.bytes(),
        )
        .expect("foreign target is genuinely signed, not a signature failure");
    let foreign_manifest: NativeReleaseManifest =
        serde_json::from_slice(foreign_raw.bytes()).unwrap();
    foreign_manifest.validate().unwrap();
    assert_ne!(
        foreign_manifest.target,
        NativeReleaseTarget::WindowsX86_64Msvc
    );
    assert!(matches!(
        verify(&path.join("wrong-target"), &publisher, &expected),
        Err(ReleaseError::Unsupported)
    ));

    let mut changed = selection.clone();
    let NativeRootIdentity::Windows { file_id, .. } = &mut changed.payload_root else {
        panic!("Windows root")
    };
    *file_id ^= 1;
    assert!(matches!(
        verify_selected(&changed),
        Err(ReleaseError::Changed)
    ));
    changed = selection.clone();
    changed.manifest_sha256 = Sha256Digest::of_bytes(b"not the approved manifest");
    assert!(matches!(
        verify_selected(&changed),
        Err(ReleaseError::Changed)
    ));
    changed = selection.clone();
    changed.payload_path.push_str(":hidden-stream");
    assert!(matches!(
        verify_selected(&changed),
        Err(ReleaseError::Invalid)
    ));
    changed = selection.clone();
    changed.payload_path = r"\\?\C:\not-opened-device-path".into();
    assert!(matches!(
        verify_selected(&changed),
        Err(ReleaseError::Invalid)
    ));
    verified
        .revalidate()
        .expect("all original approved bytes remain retained and unchanged");
    // Last refusal deliberately changes only a non-executable member in this
    // disposable signed-package fixture. Equal bytes cannot hide a new file ID
    // from the retained release or the original single-pin inventory contract.
    let member = verified
        .inventory
        .members()
        .iter()
        .find(|member| {
            !member.executable
                && member.bytes > 0
                && member.bytes <= 65536
                && member.path != Path::new("manifest.json")
                && member.path != Path::new("manifest.sig")
        })
        .expect("actual bounded non-executable signed member");
    let target = payload.join(&member.path);
    let bytes = valid_root
        .read_raw(&member.path, 65536)
        .unwrap()
        .bytes()
        .to_vec();
    let scratch_name = format!("batch-member-{}", uuid::Uuid::new_v4().simple());
    let scratch = fixture.create_runtime_child(&scratch_name).unwrap();
    let (replacement, held) = scratch.create_runtime_asset("replacement", &bytes).unwrap();
    drop(replacement);
    drop(held);
    std::fs::rename(path.join(&scratch_name).join("replacement"), &target).unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), bytes);
    assert!(matches!(verified.revalidate(), Err(ReleaseError::Changed)));
    assert!(matches!(
        verified
            .inventory
            .pin_executable(&verified.manifest.entrypoint),
        Err(StoreError::Changed)
    ));

    println!(
        "{}",
        serde_json::json!({"schema":1,"status":"PASS_SIGNED_WINDOWS_RELEASE_READ_ONLY", "manifest_sha256":report.manifest_sha256,"target":report.target,"external_worker_count":report.external_worker_count,"selection_reopened":true,"ordinary_launch_refused":true,"runtime_launched":false,"installed":false})
    );
}
