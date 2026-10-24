//! One explicitly opted-in native filesystem/process batch, not App, TCC,
//! executor, journal durability or installed-profile takeover acceptance.
use super::*;
use futures_util::StreamExt;
use std::{
    io::{BufRead, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt, symlink},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::AsyncWriteExt,
    process::{Child, Command},
    time::timeout,
};
use tokio_util::codec::{FramedRead, LinesCodec};
type TestResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const CHILD_TEST: &str = "store::platform::tests::macos_store_child";
fn directory(path: &Path) -> TestResult<()> {
    std::fs::DirBuilder::new().mode(0o700).create(path)?;
    Ok(())
}
fn write_private(path: &Path, bytes: &[u8]) -> TestResult<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    Ok(())
}
struct OwnedChild {
    child: Child,
    original: ProcessIdentity,
    frames: FramedRead<tokio::process::ChildStdout, LinesCodec>,
}
impl OwnedChild {
    async fn start(root: &Path, action: &str) -> TestResult<Self> {
        let mut child = Command::new(std::env::current_exe()?)
            .args(["--ignored", "--exact", CHILD_TEST, "--nocapture"])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("STYX_TEST_MACOS_STORE_ROOT", root)
            .env("STYX_TEST_MACOS_STORE_CHILD_ACTION", action)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let original = ProcessIdentity::observe(child.id().ok_or("missing owned child PID")?)?;
        let frames = FramedRead::new(
            child.stdout.take().ok_or("missing owned stdout")?,
            LinesCodec::new_with_max_length(2048),
        );
        Ok(Self {
            child,
            original,
            frames,
        })
    }
    async fn marker(&mut self) -> TestResult<String> {
        timeout(Duration::from_secs(10), async {
            while let Some(frame) = self.frames.next().await {
                let frame = frame?;
                if let Some(marker) = frame.strip_prefix("STYX_MAC_STORE_CHILD=") {
                    return Ok(marker.to_owned());
                }
            }
            Err("owned child ended before marker".into())
        })
        .await?
    }
    async fn finish(mut self, release: bool) -> TestResult<ProcessIdentity> {
        if release {
            let mut input = self.child.stdin.take().ok_or("missing owned stdin")?;
            input.write_all(b"release\n").await?;
            input.shutdown().await?;
        }
        let status = timeout(Duration::from_secs(10), self.child.wait()).await??;
        assert!(
            status.success(),
            "owned helper failed; no secret output included"
        );
        assert!(
            !self.original.still_current()?,
            "actual-wait original child still current"
        );
        Ok(self.original)
    }
}

#[test]
#[ignore = "private native helper; called only by the explicit macOS aggregate"]
fn macos_store_child() -> TestResult<()> {
    let path = PathBuf::from(
        std::env::var_os("STYX_TEST_MACOS_STORE_ROOT").ok_or("explicit owned root required")?,
    );
    let action = std::env::var("STYX_TEST_MACOS_STORE_CHILD_ACTION")?;
    let root = PrivateRoot::open(path)?;
    let resource = match action.as_str() {
        "hold_writer" | "probe_writer" => LockResource::ConfigurationWriter,
        "hold_execution" | "probe_execution" => LockResource::Execution,
        _ => return Err("unknown private helper action".into()),
    };
    let guard = match root.inner.try_lock(resource) {
        Ok(guard) => guard,
        Err(StoreError::Busy(observed)) if observed == resource && action.starts_with("probe_") => {
            println!("STYX_MAC_STORE_CHILD=busy");
            std::io::stdout().flush()?;
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    guard.validate()?;
    println!("STYX_MAC_STORE_CHILD=held");
    std::io::stdout().flush()?;
    if action.starts_with("hold_") {
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        if line != "release\n" {
            return Err("explicit owned release required".into());
        }
        guard.validate()?;
    }
    drop(guard);
    Ok(())
}

#[tokio::test]
#[ignore = "actual macOS raw-file/ACL/replacement/independent-lock/process aggregate; explicit fresh root required"]
async fn macos_raw_reads_and_distinct_leases_native() -> TestResult<()> {
    let requested = PathBuf::from(
        std::env::var_os("STYX_TEST_MACOS_STORE_ROOT").ok_or("explicit fresh root required")?,
    );
    if !requested.is_absolute() {
        return Err("absolute fresh owned root required".into());
    }
    // create is exclusive. Never adopt or remove a previous batch's directory.
    directory(&requested)?;
    let path = requested.canonicalize()?;
    let root = PrivateRoot::open(&path)?;
    let raw = br#"{"schema":1,"opaque":{"number":184467440737095516160000000000000001},"appLogin":false}"#;
    write_private(&path.join("profile.json"), raw)?;
    let observed = root.read_json(
        "profile.json",
        1024,
        &JsonVersionPolicy {
            field: VersionField::Schema,
            supported_versions: vec![1],
        },
    )?;
    assert!(observed.raw.bytes() == raw, "raw bytes were changed");
    assert!(matches!(
        root.read_raw("profile.json", 4),
        Err(StoreError::TooLarge)
    ));
    root.ensure_absent("absent")?;
    assert!(root.ensure_absent("profile.json").is_err());
    symlink(path.join("profile.json"), path.join("symlink"))?;
    assert!(root.read_raw("symlink", 1024).is_err());
    assert!(root.ensure_absent("symlink").is_err());
    symlink(path.join("missing"), path.join("dangling"))?;
    assert!(root.ensure_absent("dangling").is_err());
    std::fs::hard_link(path.join("profile.json"), path.join("hardlink"))?;
    assert!(matches!(
        root.read_raw("profile.json", 1024),
        Err(StoreError::NotRegularFile)
    ));
    std::fs::remove_file(path.join("hardlink"))?;
    std::fs::set_permissions(
        path.join("profile.json"),
        std::fs::Permissions::from_mode(0o640),
    )?;
    assert!(matches!(
        root.read_raw("profile.json", 1024),
        Err(StoreError::NotPrivate)
    ));
    std::fs::set_permissions(
        path.join("profile.json"),
        std::fs::Permissions::from_mode(0o600),
    )?;
    assert!(root.read_raw("../profile.json", 1024).is_err());

    // Deliberately add/remove ACL only on this newly created synthetic file.
    let status = timeout(
        Duration::from_secs(5),
        Command::new("/bin/chmod")
            .args(["+a", "everyone allow read"])
            .arg(path.join("profile.json"))
            .kill_on_drop(true)
            .status(),
    )
    .await??;
    assert!(status.success(), "owned ACL fixture setup failed");
    assert!(matches!(
        root.read_raw("profile.json", 1024),
        Err(StoreError::NotPrivate)
    ));
    let status = timeout(
        Duration::from_secs(5),
        Command::new("/bin/chmod")
            .arg("-N")
            .arg(path.join("profile.json"))
            .kill_on_drop(true)
            .status(),
    )
    .await??;
    assert!(status.success(), "owned ACL fixture removal failed");
    assert!(root.read_raw("profile.json", 1024)?.bytes() == raw);

    write_private(&path.join("replacement"), raw)?;
    let replaced = root
        .inner
        .read_raw_after_read_for_test(Path::new("profile.json"), 1024, || {
            std::fs::rename(path.join("replacement"), path.join("profile.json"))?;
            Ok(())
        });
    assert!(
        matches!(replaced, Err(StoreError::Changed)),
        "identical bytes must not hide inode replacement"
    );
    directory(&path.join("nested"))?;
    write_private(&path.join("nested/value"), raw)?;
    let moved = root
        .inner
        .read_raw_after_read_for_test(Path::new("nested/value"), 1024, || {
            std::fs::rename(path.join("nested"), path.join("nested-original"))?;
            std::fs::create_dir(path.join("nested"))?;
            std::fs::set_permissions(path.join("nested"), std::fs::Permissions::from_mode(0o700))?;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path.join("nested/value"))?;
            f.write_all(raw)?;
            Ok(())
        });
    assert!(matches!(moved, Err(StoreError::Changed)));

    for resource in [LockResource::ConfigurationWriter, LockResource::Execution] {
        assert!(root.inner.try_existing_lock(resource).is_err());
        assert!(
            !path.join(resource.filename()).exists(),
            "existing-only acquisition created a lock"
        );
    }
    let writer = root.try_configuration_writer()?;
    let execution = root.try_execution_lease()?;
    writer.validate()?;
    execution.validate()?;
    for action in ["probe_writer", "probe_execution"] {
        let mut child = OwnedChild::start(&path, action).await?;
        assert_eq!(child.marker().await?, "busy");
        child.finish(false).await?;
    }
    drop(execution);
    let mut independent = OwnedChild::start(&path, "probe_execution").await?;
    assert_eq!(independent.marker().await?, "held");
    independent.finish(false).await?;
    writer.validate()?;
    drop(writer);
    for (action, resource) in [
        ("hold_writer", LockResource::ConfigurationWriter),
        ("hold_execution", LockResource::Execution),
    ] {
        let mut child = OwnedChild::start(&path, action).await?;
        assert_eq!(child.marker().await?, "held");
        assert!(matches!(root.inner.try_lock(resource), Err(StoreError::Busy(r)) if r == resource));
        assert!(child.original.still_current()?);
        child.finish(true).await?;
        let guard = root.inner.try_existing_lock(resource)?;
        guard.validate()?;
        drop(guard);
    }
    let current = ProcessIdentity::current()?;
    assert!(current.still_current()?);
    let ProcessIdentity::Macos {
        boot_session_id,
        pid,
        start_seconds,
        start_microseconds,
        uid,
    } = current
    else {
        return Err("Darwin birth required".into());
    };
    assert_eq!(pid, std::process::id());
    assert_eq!(uid, current_uid());
    assert!(start_microseconds < 1_000_000);
    let wrong_birth = ProcessIdentity::Macos {
        boot_session_id: boot_session_id.clone(),
        pid,
        start_seconds: start_seconds.checked_add(1).ok_or("birth overflow")?,
        start_microseconds,
        uid,
    };
    assert!(!wrong_birth.still_current()?);
    let wrong_uid = ProcessIdentity::Macos {
        boot_session_id,
        pid,
        start_seconds,
        start_microseconds,
        uid: uid.checked_add(1).ok_or("UID overflow")?,
    };
    assert!(matches!(
        wrong_uid.still_current(),
        Err(StoreError::Changed)
    ));
    assert!(process_identity(0).is_err());

    let lease_dir = path.join("replaced-root");
    directory(&lease_dir)?;
    let old = PrivateRoot::open(&lease_dir)?;
    let held = old.try_execution_lease()?;
    std::fs::rename(&lease_dir, path.join("original-root"))?;
    directory(&lease_dir)?;
    assert!(held.validate().is_err());
    drop(held);
    let swap_dir = path.join("replaced-lock");
    directory(&swap_dir)?;
    let swap = PrivateRoot::open(&swap_dir)?;
    let held = swap.try_configuration_writer()?;
    std::fs::rename(
        swap_dir.join(LockResource::ConfigurationWriter.filename()),
        swap_dir.join("original.lock"),
    )?;
    write_private(
        &swap_dir.join(LockResource::ConfigurationWriter.filename()),
        b"",
    )?;
    assert!(held.validate().is_err());
    drop(held);
    println!(
        "STYX_MAC_STORE_NATIVE={{\"schema\":1,\"raw_preserved\":true,\"acl_negative\":true,\"independent_process_leases\":true,\"actual_children_waited\":true,\"app_executor_journal\":\"NOT_TESTED\"}}"
    );
    Ok(())
}
