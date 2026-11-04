//! Owned Windows filesystem/actual-child boundaries. No runtime/service/desktop.
use super::*;
use std::{
    io::{BufRead, BufReader, Read, Write},
    process::{Command, Stdio},
};

struct OwnedChild {
    child: std::process::Child,
    waited: bool,
}
impl std::ops::Deref for OwnedChild {
    type Target = std::process::Child;
    fn deref(&self) -> &Self::Target {
        &self.child
    }
}
impl std::ops::DerefMut for OwnedChild {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.child
    }
}
impl OwnedChild {
    fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        let status = self.child.wait()?;
        self.waited = true;
        Ok(status)
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !self.waited {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[test]
fn windows_components_refuse_ads_device_alias_and_normalized_traversal() {
    for name in [
        "data:stream",
        "NUL",
        "con.txt",
        "COM1.exe",
        "LPT9",
        "name.",
        "name ",
        "a\\b",
        ".",
        "..",
    ] {
        assert!(component(OsStr::new(name)).is_err());
    }
    for path in [
        "C:relative",
        "\\\\server\\share\\root",
        "\\\\.\\pipe\\anything",
        "C:\\root\\..\\other",
        "C:\\root\\.",
    ] {
        assert!(normalized_root(Path::new(path)).is_err());
    }
    assert!(normalized_root(Path::new("C:\\owned\\profile")).is_ok());
}

#[test]
#[ignore = "helper only: invoked by windows_owned_root_leases_acl_alias_and_pe_pin with its exact owned root; not standalone acceptance"]
fn windows_lock_holder_child() {
    let path =
        std::env::var_os("STYX_TEST_WINDOWS_STORE_CHILD_ROOT").expect("owned parent selector");
    let root = Root::open(Path::new(&path)).unwrap();
    let _writer = root.try_lock(LockResource::ConfigurationWriter).unwrap();
    println!("STYX_WINDOWS_LOCK_HELD");
    std::io::stdout().flush().unwrap();
    let mut byte = [0];
    std::io::stdin().read_exact(&mut byte).unwrap();
}

#[test]
#[ignore = "STYX_TEST_WINDOWS_STORE_ROOT; owned Windows FS, cross-process lock, ACL and PE-pin aggregate; not runtime/platform/TCC acceptance"]
fn windows_owned_root_leases_acl_alias_and_pe_pin() {
    let parent = PathBuf::from(
        std::env::var_os("STYX_TEST_WINDOWS_STORE_ROOT").expect("explicit owned private root"),
    );
    let _parent = Root::open(&parent).unwrap();
    let path = parent.join(uuid::Uuid::new_v4().to_string());
    std::fs::create_dir(&path).unwrap();
    let root = Root::open(&path).unwrap();
    assert_ne!(root.identity(), _parent.identity());
    let current = ProcessIdentity::current().unwrap();
    let ProcessIdentity::Windows {
        pid,
        creation_time_100ns,
        owner_sid,
    } = current
    else {
        panic!("Windows process fact")
    };
    assert!(
        !process_matches(&ProcessIdentity::Windows {
            pid,
            creation_time_100ns: creation_time_100ns + 1,
            owner_sid
        })
        .unwrap()
    );
    let data = path.join("data.json");
    std::fs::write(&data, b"private owned fixture").unwrap();
    assert_eq!(
        root.read_raw(Path::new("data.json"), 1024).unwrap().bytes(),
        b"private owned fixture"
    );
    assert!(root.read_raw(Path::new("data.json"), 1).is_err());
    assert!(
        root.ensure_absent(Path::new("not-created/owner.lock"))
            .is_ok()
    );
    let writer = root.try_lock(LockResource::ConfigurationWriter).unwrap();
    assert!(matches!(
        root.try_lock(LockResource::ConfigurationWriter),
        Err(StoreError::Busy(_))
    ));
    let execution = root.try_lock(LockResource::Execution).unwrap();
    writer.validate().unwrap();
    execution.validate().unwrap();
    drop(writer);
    drop(execution);
    // Actual independent test process, not another in-process handle.
    let mut child = OwnedChild {
        child: Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "store::platform::tests::windows_lock_holder_child",
                "--nocapture",
            ])
            .env("STYX_TEST_WINDOWS_STORE_CHILD_ROOT", &path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
        waited: false,
    };
    let original = ProcessIdentity::observe(child.id()).unwrap();
    let output = child.stdout.take().unwrap();
    let mut reader = BufReader::new(output);
    let mut ready = false;
    for _ in 0..16 {
        let mut line = String::new();
        (&mut reader).take(8193).read_line(&mut line).unwrap();
        assert!(line.len() <= 8192);
        if line.trim() == "STYX_WINDOWS_LOCK_HELD" {
            ready = true;
            break;
        }
        if line.is_empty() {
            break;
        }
    }
    assert!(ready, "actual helper must hold its independent lock");
    assert!(matches!(
        root.try_lock(LockResource::ConfigurationWriter),
        Err(StoreError::Busy(_))
    ));
    child.stdin.take().unwrap().write_all(b"x").unwrap();
    assert!(child.wait().unwrap().success());
    assert!(!original.still_current().unwrap());
    drop(reader);
    let writer = root
        .try_existing_lock(LockResource::ConfigurationWriter)
        .unwrap();
    writer.validate().unwrap();
    drop(writer);
    let ads = PathBuf::from(format!("{}:owned-hidden-stream", data.display()));
    std::fs::write(&ads, b"not-a-manifest-member").unwrap();
    assert!(root.read_raw(Path::new("data.json"), 1024).is_err());
    std::fs::remove_file(&ads).unwrap();
    let target = path.join("junction-target");
    std::fs::create_dir(&target).unwrap();
    let junction = path.join("junction-alias");
    let linked = Command::new("cmd.exe")
        .args(["/D", "/C", "mklink", "/J"])
        .arg(&junction)
        .arg(&target)
        .output()
        .unwrap();
    assert!(linked.status.success());
    assert!(Root::open(&junction).is_err());
    std::fs::remove_dir(&junction).unwrap();
    std::fs::remove_dir(&target).unwrap();
    let limits = PayloadLimits {
        max_files: 1,
        ..PayloadLimits::default()
    };
    assert!(matches!(
        root.payload_inventory(limits, &crate::store::KnownDigests::new()),
        Err(StoreError::TooLarge)
    ));
    let alias = path.join("alias.json");
    std::fs::hard_link(&data, &alias).unwrap();
    assert!(root.read_raw(Path::new("data.json"), 1024).is_err());
    std::fs::remove_file(&alias).unwrap();
    // Mature OS ACL utility on this private disposable file only; no original
    // profile ACL is changed. Do not infer denial merely from an empty read.
    let changed = Command::new("icacls.exe")
        .arg(&data)
        .args(["/grant", "*S-1-1-0:(R)"])
        .output()
        .unwrap();
    assert!(changed.status.success());
    assert!(matches!(
        root.read_raw(Path::new("data.json"), 1024),
        Err(StoreError::NotPrivate)
    ));
    std::fs::remove_file(&data).unwrap();
    std::fs::create_dir(path.join("bin")).unwrap();
    let image = path.join("bin/owned-fixture.exe");
    std::fs::copy(std::env::current_exe().unwrap(), &image).unwrap();
    let inventory = root
        .payload_inventory(PayloadLimits::default(), &crate::store::KnownDigests::new())
        .unwrap();
    let pin = inventory
        .pin_executable(Path::new("bin/owned-fixture.exe"))
        .unwrap();
    pin.revalidate().unwrap();
    assert!(matches!(pin.launch_path(), Err(StoreError::Unsupported)));
    assert_eq!(pin.source_path_for_suspended_spawn().unwrap(), image);
    assert!(
        std::fs::rename(&image, path.join("moved.exe")).is_err(),
        "retained image denies delete sharing"
    );
    let expected = pin.expected_sha256().unwrap();
    assert_eq!(
        expected,
        inventory
            .members()
            .iter()
            .find(|m| m.path == Path::new("bin/owned-fixture.exe"))
            .unwrap()
            .sha256
    );
    drop(pin);
    drop(inventory);
    drop(root);
    drop(_parent);
    std::fs::remove_dir_all(&path).unwrap();
}

#[test]
#[ignore = "requires STYX_TEST_WINDOWS_PRIVATE_CHILD_ROOT: fresh protected current-SID parent; actual Windows directory creation/ACL/reparse refusal, no runtime"]
fn windows_private_runtime_child_creation_and_existing_refusal() {
    let path = PathBuf::from(
        std::env::var_os("STYX_TEST_WINDOWS_PRIVATE_CHILD_ROOT").expect("explicit fresh parent"),
    );
    let parent = Root::open(&path).unwrap();
    assert!(std::fs::read_dir(&path).unwrap().next().is_none());
    let original_parent = parent.identity();
    for invalid in ["", ".", "..", "../escape", "a\\b", "temp:stream", "NUL"] {
        assert!(parent.open_or_create_private_child(invalid).is_err());
    }
    assert!(std::fs::read_dir(&path).unwrap().next().is_none());
    // This creator must set TokenUser ownership atomically, even when the
    // elevated token's default owner is Administrators. Root::open enforces it.
    let child = parent
        .open_or_create_private_child(".styx-runtime-tmp")
        .unwrap();
    let RootIdentity::Windows { owner_sid, .. } = child.identity() else {
        panic!("Windows root")
    };
    assert_eq!(owner_sid, ffi::current_sid().unwrap());
    let reopened = parent
        .open_or_create_private_child(".styx-runtime-tmp")
        .unwrap();
    assert_eq!(child.identity(), reopened.identity());
    assert_eq!(parent.identity(), original_parent);
    child.validate_root().unwrap();
    reopened.validate_root().unwrap();

    let unsafe_root = parent
        .open_or_create_private_child("preexisting-unsafe")
        .unwrap();
    let unsafe_path = path.join("preexisting-unsafe");
    let unsafe_identity = unsafe_root.identity();
    drop(unsafe_root);
    let changed = Command::new("icacls.exe")
        .arg(&unsafe_path)
        .args(["/grant", "*S-1-1-0:(OI)(CI)(F)"])
        .output()
        .unwrap();
    assert!(changed.status.success());
    let acl = |item: &Path| {
        let powershell = PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32/WindowsPowerShell/v1.0/powershell.exe");
        let result = Command::new(powershell)
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "[Console]::Write((Get-Acl -LiteralPath $env:STYX_OWNED_ACL_OBSERVATION).Sddl)",
            ])
            .env("STYX_OWNED_ACL_OBSERVATION", item)
            .output()
            .unwrap();
        assert!(result.status.success());
        assert!(!result.stdout.is_empty() && result.stdout.len() <= 65536);
        result.stdout
    };
    let before_acl = acl(&unsafe_path);
    assert!(matches!(
        parent.open_or_create_private_child("preexisting-unsafe"),
        Err(StoreError::NotPrivate)
    ));
    assert_eq!(
        before_acl,
        acl(&unsafe_path),
        "existing unsafe DACL was not repaired"
    );
    let retained = ffi::open(&unsafe_path, true, false, false).unwrap();
    let RootIdentity::Windows {
        volume_serial,
        file_id,
        ..
    } = unsafe_identity
    else {
        panic!("Windows root")
    };
    assert_eq!(file_identity(&retained).unwrap(), (volume_serial, file_id));

    let file_path = path.join("preexisting-file");
    std::fs::write(&file_path, b"unchanged owned negative fixture").unwrap();
    let file_before = std::fs::read(&file_path).unwrap();
    assert!(
        parent
            .open_or_create_private_child("preexisting-file")
            .is_err()
    );
    assert_eq!(std::fs::read(&file_path).unwrap(), file_before);

    let alias = path.join("preexisting-junction");
    let linked = Command::new("cmd.exe")
        .args(["/D", "/C", "mklink", "/J"])
        .arg(&alias)
        .arg(path.join(".styx-runtime-tmp"))
        .output()
        .unwrap();
    assert!(linked.status.success());
    let target_before = std::fs::read_link(&alias).unwrap();
    assert!(
        parent
            .open_or_create_private_child("preexisting-junction")
            .is_err()
    );
    assert_eq!(std::fs::read_link(&alias).unwrap(), target_before);
    // Preserve negatives for the external observer; no existing tree repair or
    // cleanup-by-name. All changes above belong to this explicitly fresh root.
    parent.validate_root().unwrap();
}

#[test]
#[ignore = "requires STYX_TEST_WINDOWS_PRIVATE_CHILD_ROOT; actual private asset publication, replacement refusal and retained handle sharing"]
fn windows_browser_runtime_assets_are_fresh_and_nonreplaceable() {
    let parent = PathBuf::from(
        std::env::var_os("STYX_TEST_WINDOWS_PRIVATE_CHILD_ROOT").expect("owned parent"),
    );
    let parent = PrivateRoot::open(parent).unwrap();
    let name = format!("browser-assets-{}", uuid::Uuid::new_v4().simple());
    let root = parent.create_runtime_child(&name).unwrap();
    assert!(parent.create_runtime_child(&name).is_err());
    let (observed, held) = root
        .create_runtime_asset("worker.mjs", b"// immutable asset")
        .unwrap();
    assert!(
        root.create_runtime_asset("worker.mjs", b"// replacement")
            .is_err()
    );
    let path = ffi::final_path(&held).unwrap();
    assert!(std::fs::OpenOptions::new().write(true).open(&path).is_err());
    assert!(std::fs::remove_file(&path).is_err());
    let current = root.read_raw("worker.mjs", 1024).unwrap();
    assert_eq!(current.observation(), observed.observation());
    assert_eq!(current.bytes(), b"// immutable asset");
    assert!(root.create_runtime_asset("../escape", b"x").is_err());
    assert!(
        root.create_runtime_asset("worker.mjs:stream", b"x")
            .is_err()
    );
    assert!(root.create_runtime_asset("empty", &[]).is_err());
    drop(held);
    std::fs::remove_file(path).unwrap();
}

#[test]
#[ignore = "STYX_TEST_WINDOWS_STORE_ROOT; owned NTFS journal read, bounds, hard-link/ADS/ACL negatives and late root ACL refusal only; no runtime/service/UI"]
fn windows_journal_read_batch_preserves_original_bytes_and_private_boundaries() {
    use crate::store::secure_journal::{JournalBudget, JournalError, files};
    let parent_path = PathBuf::from(
        std::env::var_os("STYX_TEST_WINDOWS_STORE_ROOT").expect("explicit owned private parent"),
    );
    let parent = Root::open(&parent_path).unwrap();
    let name = format!("journal-read-batch-{}", uuid::Uuid::new_v4());
    let root = parent.open_or_create_private_child(&name).unwrap();
    let path = parent_path.join(&name);
    let first = b"original first\n";
    let second = b"original second \xe4\xb8\xad\xe6\x96\x87\n";
    // An elevated Windows token may default a raw new file to Administrators.
    // The production private publisher sets current TokenUser ownership at
    // creation; the ordinary reader must keep refusing the raw default.
    root.create_private_export("a.json", first, &|_| {})
        .unwrap();
    root.create_private_export("b.json", second, &|_| {})
        .unwrap();
    let scan = files::scan(&root.directory, JournalBudget::default()).unwrap();
    assert_eq!(scan.total_bytes, first.len() + second.len());
    assert_eq!(scan.files.len(), 2);
    assert_eq!(scan.files[0].name, "a.json");
    assert_eq!(scan.files[0].bytes, first);
    assert_eq!(scan.files[1].name, "b.json");
    assert_eq!(scan.files[1].bytes, second);
    assert!(matches!(
        files::scan(
            &root.directory,
            JournalBudget {
                max_files: 1,
                ..JournalBudget::default()
            }
        ),
        Err(JournalError::BudgetExceeded)
    ));
    let refused = root.with_read_batch(|batch| {
        assert!(matches!(
            batch.read_raw(Path::new("a.json"), 1),
            Err(StoreError::TooLarge)
        ));
        assert!(batch.read_raw(Path::new("a.json:stream"), 1024).is_err());
        assert!(std::fs::rename(&path, parent_path.join("unexpected-root-move")).is_err());
    });
    refused.unwrap();
    let alias = path.join("alias.json");
    std::fs::hard_link(path.join("a.json"), &alias).unwrap();
    assert!(files::scan(&root.directory, JournalBudget::default()).is_err());
    std::fs::remove_file(&alias).unwrap();
    let acl = |target: &Path, grant: bool| {
        let mut command = Command::new("icacls.exe");
        command.arg(target);
        if grant {
            command.args(["/grant", "*S-1-1-0:(R)"]);
        } else {
            command.args(["/remove:g", "*S-1-1-0"]);
        }
        assert!(command.output().unwrap().status.success());
    };
    acl(&path.join("a.json"), true);
    assert!(files::scan(&root.directory, JournalBudget::default()).is_err());
    acl(&path.join("a.json"), false);
    // A member was read successfully, then the original directory becomes
    // non-private. The entire enclosing result must fail rather than publish
    // that earlier byte observation as a successfully validated scan.
    let late = root.with_read_batch(|batch| {
        let bytes = batch.read_raw(Path::new("a.json"), 1024).unwrap().bytes;
        acl(&path, true);
        bytes
    });
    assert!(matches!(late, Err(StoreError::NotPrivate)));
    acl(&path, false);
    let recovered = files::scan(&root.directory, JournalBudget::default()).unwrap();
    assert_eq!(recovered.files[0].bytes, first);
    assert_eq!(recovered.files[1].bytes, second);
    assert_eq!(root.identity(), Root::open(&path).unwrap().identity());
}

#[test]
#[ignore = "requires STYX_TEST_WINDOWS_READONLY_JOURNAL; owner-selected existing private namespace; read only, no lock creation/recovery/runtime/service/input"]
fn windows_existing_journal_read_batch_readonly_diagnostic() {
    use crate::store::secure_journal::{JournalBudget, files};
    let path = PathBuf::from(
        std::env::var_os("STYX_TEST_WINDOWS_READONLY_JOURNAL")
            .expect("explicit existing namespace"),
    );
    let root = Root::open(&path).unwrap();
    let budget = JournalBudget::default();
    let warm = files::scan(&root.directory, budget).unwrap();
    let before = std::time::Instant::now();
    let mut original = Vec::new();
    let mut total = 0usize;
    for entry in std::fs::read_dir(&path).unwrap() {
        assert!(original.len() < budget.max_files);
        let name = entry.unwrap().file_name().into_string().unwrap();
        let raw = root
            .read_raw(
                Path::new(&name),
                budget.max_file_bytes.min(budget.max_bytes - total),
            )
            .unwrap();
        total += raw.bytes.len();
        original.push((name, raw.bytes));
    }
    root.validate_root().unwrap();
    let repeated_ms = before.elapsed().as_secs_f64() * 1000.0;
    original.sort_by(|a, b| a.0.cmp(&b.0));
    let before = std::time::Instant::now();
    let batched = files::scan(&root.directory, budget).unwrap();
    let batched_ms = before.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(warm.total_bytes, total);
    assert_eq!(batched.total_bytes, total);
    assert_eq!(batched.files.len(), original.len());
    assert_eq!(warm.files.len(), original.len());
    for ((old, current), initial) in original.iter().zip(&batched.files).zip(&warm.files) {
        assert_eq!(old.0, current.name);
        assert_eq!(old.1, current.bytes);
        assert_eq!(initial.name, current.name);
        assert_eq!(initial.bytes, current.bytes);
    }
    println!(
        "{}",
        serde_json::json!({
            "scope":"same_existing_private_journal_readonly_no_runtime_or_startup_acceptance",
            "members":original.len(),"bytes":total,"identical_original_bytes":true,
            "repeated_full_directory_walk_ms":repeated_ms,"batched_original_directory_ms":batched_ms,
            "writes":false,"recovery_or_operations_replayed":false
        })
    );
}
