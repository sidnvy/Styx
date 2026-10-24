//! Explicit native fixture only: private copied thin Rust test image, ad-hoc signed only after copying, no installed profile.
use super::*;
use crate::store::{PayloadLimits, PrivateRoot};
use std::{
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::Path,
};

#[tokio::test]
#[ignore = "requires explicitly owned fresh Mac root; executes private signed native fixture"]
async fn actual_suspended_image_barrier_wrong_cdhash_and_original_wait() {
    let root =
        PathBuf::from(std::env::var_os("STYX_TEST_MACOS_SPAWN_ROOT").expect("explicit owned root"));
    assert!(root.is_absolute() && !root.exists());
    assert_eq!(
        root.parent().unwrap().canonicalize().unwrap(),
        root.parent().unwrap()
    );
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .unwrap();
    let payload = root.join("payload");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&payload)
        .unwrap();
    let original_image = std::env::current_exe().unwrap();
    let copied_image = payload.join("fixture-child");
    std::fs::copy(&original_image, &copied_image).unwrap();
    // Cargo's current-architecture test executable must be thin64. Never thin,
    // re-sign, or otherwise alter the original executable or an installed App.
    let magic = {
        use std::io::Read;
        let mut magic = [0; 4];
        std::fs::File::open(&copied_image)
            .unwrap()
            .read_exact(&mut magic)
            .unwrap();
        magic
    };
    assert!(magic == [0xcf, 0xfa, 0xed, 0xfe] || magic == [0xfe, 0xed, 0xfa, 0xcf]);
    let signed = std::process::Command::new("/usr/bin/codesign")
        .args(["--force", "--sign", "-", "--timestamp=none"])
        .arg(&copied_image)
        .status()
        .unwrap();
    assert!(signed.success(), "owned fixture ad-hoc signing failed");
    std::fs::set_permissions(
        payload.join("fixture-child"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let protected = PrivateRoot::open(&payload).unwrap();
    let inventory = protected
        .payload_inventory(PayloadLimits::default())
        .unwrap();
    let pin = Arc::new(
        inventory
            .pin_executable(Path::new("fixture-child"))
            .unwrap(),
    );
    let args = || {
        vec![
            OsString::from("--ignored"),
            OsString::from("--exact"),
            OsString::from("platform::macos_spawn::tests::suspended_fixture_child"),
            OsString::from("--nocapture"),
        ]
    };
    let environment = |filename: &str| {
        BTreeMap::from([(
            OsString::from("STYX_TEST_MACOS_SUSPENDED_EFFECT"),
            root.join(filename).into_os_string(),
        )])
    };

    let mut rejected =
        spawn_suspended(pin.clone(), args(), root.clone(), environment("forbidden")).unwrap();
    assert!(!root.join("forbidden").exists());
    // Deterministic verification-negative control, never an external hash authority.
    rejected.cdhash[0] ^= 1;
    let rejection = match rejected.verify_and_resume() {
        Ok(mut unexpected) => {
            let _ = unexpected.start_kill();
            let _ = unexpected.wait().await;
            panic!("wrong cdhash resumed");
        }
        Err(error) => error,
    };
    assert_eq!(rejection.code, "suspended_image_verification_failed");
    let mut rejected = rejection
        .into_owned_child()
        .expect("original child retained");
    let rejected_status = rejected.terminate_and_wait().await.unwrap();
    let rejected_receipt = rejected.receipt();
    assert!(!rejected_status.success());
    assert!(rejected_receipt.actual_wait && rejected_receipt.supervisor_joined);
    assert!(!root.join("forbidden").exists());

    let mut suspended = spawn_suspended(pin, args(), root.clone(), environment("effect")).unwrap();
    let original = suspended.receipt();
    assert!(original.birth.is_some());
    assert!(!root.join("effect").exists());
    // A cancelled public waiter does not consume the retained original JoinHandle.
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            suspended.child.as_mut().unwrap().wait()
        )
        .await
        .is_err()
    );
    assert!(!root.join("effect").exists());
    let mut running = match suspended.verify_and_resume() {
        Ok(child) => child,
        Err(failure) => {
            if let Some(mut child) = failure.into_owned_child() {
                let _ = child.terminate_and_wait().await;
            }
            panic!("trusted fixture failed image verification");
        }
    };
    let status = match tokio::time::timeout(Duration::from_secs(5), running.wait()).await {
        Ok(result) => result.unwrap(),
        Err(_) => {
            let _ = running.start_kill();
            let _ = running.wait().await;
            panic!("native fixture did not exit");
        }
    };
    let receipt = running.receipt();
    assert!(status.success());
    assert!(receipt.actual_wait && receipt.supervisor_joined);
    assert_eq!(receipt.birth, original.birth);
    assert_eq!(std::fs::read(root.join("effect")).unwrap(), b"owned-once\n");
    inventory.revalidate().unwrap();
    // Kernel absence is observed independently of the adapter's wait flags.
    assert!(
        matches!(ProcessIdentity::observe(receipt.pid), Err(_))
            || ProcessIdentity::observe(receipt.pid).ok() != original.birth
    );
    println!(
        "{}",
        serde_json::json!({"schema":1,"status":"PASS_OWNED_DARWIN_SUSPENDED_FIXTURE_ONLY","pid":receipt.pid,"birth":receipt.birth,"actual_wait":receipt.actual_wait,"supervisor_joined":receipt.supervisor_joined,"before_resume_effect_absent":true,"effect_count":1,"wrong_cdhash_effect_count":0,"wrong_cdhash_pid":rejected_receipt.pid,"wrong_cdhash_actual_wait":rejected_receipt.actual_wait,"cancelled_waiter_retained_original_child":true,"fixture_ad_hoc_signature_only":true,"original_app_modified":false,"publisher_acceptance":false,"host_gateway_acceptance":false})
    );
}

#[test]
#[ignore = "owned copied-image child helper; not an independent acceptance case"]
fn suspended_fixture_child() {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let target = PathBuf::from(
        std::env::var_os("STYX_TEST_MACOS_SUSPENDED_EFFECT").expect("explicit owned effect path"),
    );
    assert!(target.is_absolute() && !target.exists());
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(target)
        .unwrap();
    output.write_all(b"owned-once\n").unwrap();
    output.sync_all().unwrap();
}
