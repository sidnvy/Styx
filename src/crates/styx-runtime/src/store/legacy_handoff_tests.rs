//! Actual owned files and the existing legacy exclusive-file primitive. This is
//! NOT a running-profile settlement, legacy runtime shutdown or migration test.
use super::*;
use crate::store::{LockResource, StoreError};
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::{Child, Command},
    time::timeout,
};

const STATE: &[u8] = br#"{"schema":1,"desired":{"host":"stopped","appLogin":false},"opaque":{"integer":18446744073709551617000}}"#;
const IDENTITY: &[u8] = br#"{"schema":1,"device_id":"owned-fixture","opaque":"preserve-verbatim"}"#;
// The child runs the actual legacy wx primitive, not a Rust lookalike or an
// executable profile. Static protocol only; no credential or private error text.
const LEGACY_CHILD: &str = r#"
const fs=await import('node:fs');
const {pathToFileURL}=await import('node:url');
const {openPrivateFile}=await import(pathToFileURL(process.argv[1]).href);
let fd;
try { fd=openPrivateFile(process.argv[2]); }
catch(e) { process.stdout.write(e.code==='EEXIST'?'REFUSED\n':'ERROR\n'); process.exit(e.code==='EEXIST'?23:97); }
fs.writeFileSync(fd,'owned-old-writer');fs.fsyncSync(fd);
process.stdout.write('ACQUIRED\n');
if(process.argv[3]==='hold') {
 await new Promise(resolve=>{process.stdin.once('data',resolve);process.stdin.once('end',resolve);process.stdin.resume();});
}
fs.closeSync(fd);
"#;

fn directory(path: &Path) {
    fs::DirBuilder::new().mode(0o700).create(path).unwrap();
}
fn raw(path: &Path, bytes: &[u8]) {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
struct Fixture {
    configuration: PathBuf,
    host: PathBuf,
    owner: OwnedConfigurationRoot,
}
fn fixture(base: &Path) -> Fixture {
    let path = base.join(uuid::Uuid::new_v4().to_string());
    directory(&path);
    let configuration = path.join("configuration");
    let host = path.join("host");
    directory(&configuration);
    directory(&host);
    directory(&host.join("device"));
    raw(&configuration.join("state.json"), STATE);
    raw(&host.join("device/identity.json"), IDENTITY);
    // Explicit synthetic stopped/disabled input, no service configuration.
    let root = PrivateRoot::open(&configuration).unwrap();
    let writer = root.try_configuration_writer().unwrap();
    let owner = OwnedConfigurationRoot::open_existing(root, writer).unwrap();
    Fixture {
        configuration,
        host,
        owner,
    }
}
fn inputs() -> Vec<LegacyMaterialInput> {
    vec![
        LegacyMaterialInput {
            root: LegacyMaterialRoot::Configuration,
            input: PreservationInput {
                relative_path: "state.json".into(),
                role: PreservationRole::DeploymentConfiguration,
                json_version: None,
            },
            max_bytes: 4096,
        },
        LegacyMaterialInput {
            root: LegacyMaterialRoot::Host,
            input: PreservationInput {
                relative_path: "device/identity.json".into(),
                role: PreservationRole::DeviceIdentity,
                json_version: None,
            },
            max_bytes: 4096,
        },
    ]
}
fn acquire(f: &Fixture) -> Result<LegacyWriterFence, LegacyFenceFailure> {
    let maintenance = f
        .owner
        .begin_maintenance("legacy-owned-1".try_into().unwrap())
        .unwrap();
    LegacyWriterFence::acquire(
        f.owner.clone(),
        maintenance,
        PrivateRoot::open(&f.host).unwrap(),
        &inputs(),
    )
}
fn assert_busy(f: &Fixture) {
    assert!(matches!(
        PrivateRoot::open(&f.configuration)
            .unwrap()
            .try_configuration_writer(),
        Err(StoreError::Busy(LockResource::ConfigurationWriter))
    ));
}
struct OldWriter {
    child: Child,
    birth: ProcessIdentity,
    line: String,
}
impl OldWriter {
    async fn start(node: &Path, target: &Path, hold: bool) -> Self {
        let module = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("host/private-storage.mjs");
        assert!(module.is_file());
        let mut child = Command::new(node)
            .args(["--input-type=module", "-e", LEGACY_CHILD])
            .arg(module)
            .arg(target)
            .arg(if hold { "hold" } else { "try" })
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let birth = ProcessIdentity::observe(child.id().unwrap()).unwrap();
        let mut line = String::new();
        let stdout = child.stdout.take().unwrap();
        let mut reader = BufReader::new(stdout.take(64));
        match timeout(Duration::from_secs(5), reader.read_line(&mut line)).await {
            Ok(Ok(_)) => {}
            _ => {
                child.start_kill().unwrap();
                timeout(Duration::from_secs(2), child.wait())
                    .await
                    .unwrap()
                    .unwrap();
                panic!("owned legacy primitive handshake failed; child actually waited");
            }
        }
        Self { child, birth, line }
    }
    async fn finish(mut self, held: bool, expected: i32) {
        if held {
            self.child
                .stdin
                .take()
                .unwrap()
                .write_all(b"release\n")
                .await
                .unwrap();
        } else {
            self.child.stdin.take();
        }
        let status = match timeout(Duration::from_secs(5), self.child.wait()).await {
            Ok(Ok(status)) => status,
            _ => {
                self.child.start_kill().unwrap();
                timeout(Duration::from_secs(2), self.child.wait())
                    .await
                    .unwrap()
                    .unwrap();
                panic!("owned legacy primitive deadline expired; child actually waited");
            }
        };
        assert_eq!(status.code(), Some(expected));
        assert!(!self.birth.still_current().unwrap());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires STYX_TEST_LEGACY_HANDOFF_ROOT and STYX_TEST_NODE22; owned actual-FS legacy wx writer-fence aggregate, not migration/quiescence"]
async fn actual_legacy_writer_exclusion_and_original_material_batch() {
    let base = PathBuf::from(std::env::var("STYX_TEST_LEGACY_HANDOFF_ROOT").unwrap());
    // The runner supplies a fresh private parent; never repair another root.
    PrivateRoot::open(&base).unwrap();
    let node = PathBuf::from(std::env::var("STYX_TEST_NODE22").unwrap());

    // Actual old primitive wins advance first. New code must preserve it and
    // retain its Rust owner; a stale/unknown old name never gets unlinked.
    let f = fixture(&base);
    let old = OldWriter::start(&node, &f.configuration.join("advance.lock"), true).await;
    assert_eq!(old.line, "ACQUIRED\n");
    let before = fs::read(f.configuration.join("advance.lock")).unwrap();
    let before_inode = fs::metadata(f.configuration.join("advance.lock"))
        .unwrap()
        .ino();
    let failed = acquire(&f).unwrap_err();
    assert_eq!(failed.error(), LegacyFenceError::BusyOrUnresolved);
    assert_eq!(failed.retained_lock_count(), 0);
    assert_eq!(
        failed.configuration_root().identity().unwrap(),
        f.owner.identity().unwrap()
    );
    assert_busy(&f);
    assert_eq!(
        fs::read(f.configuration.join("advance.lock")).unwrap(),
        before
    );
    assert_eq!(
        fs::metadata(f.configuration.join("advance.lock"))
            .unwrap()
            .ino(),
        before_inode
    );
    old.finish(true, 0).await;
    drop(failed);
    assert!(f.configuration.join("advance.lock").exists());

    // All four fixed guard names are exclusive against the actual legacy
    // create primitive, including foreground's delayed claim after its scope.
    let f = fixture(&base);
    let fence = acquire(&f).unwrap();
    fence.validate().unwrap();
    assert_eq!(fence.material_bindings().count(), 2);
    assert!(fence.frozen[0].bytes.as_slice() == STATE);
    assert!(fence.frozen[1].bytes.as_slice() == IDENTITY);
    assert!(!format!("{fence:?}").contains("preserve-verbatim"));
    assert_eq!(
        fence.configuration_root().ensure_admission(),
        Err(JournalError::Conflict)
    );
    assert_busy(&f);
    for name in LOCKS {
        let old = OldWriter::start(&node, &f.configuration.join(name), false).await;
        assert_eq!(old.line, "REFUSED\n");
        old.finish(false, 23).await;
    }
    let originals: Vec<_> = LOCKS
        .iter()
        .map(|name| fs::read(f.configuration.join(name)).unwrap())
        .collect();
    drop(fence);
    assert_busy(&f);
    for (name, bytes) in LOCKS.iter().zip(&originals) {
        assert_eq!(fs::read(f.configuration.join(name)).unwrap(), *bytes);
    }

    // Foreign in-process authority must fail before touching any old guard.
    let a = fixture(&base);
    let b = fixture(&base);
    let foreign = b
        .owner
        .begin_maintenance("foreign".try_into().unwrap())
        .unwrap();
    let failure = LegacyWriterFence::acquire(
        a.owner.clone(),
        foreign,
        PrivateRoot::open(&a.host).unwrap(),
        &inputs(),
    )
    .unwrap_err();
    assert_eq!(failure.error(), LegacyFenceError::BusyOrUnresolved);
    assert_eq!(failure.retained_lock_count(), 0);
    for name in LOCKS {
        assert!(!a.configuration.join(name).exists());
    }

    // Exact raw contents AND original inode/time metadata are binding: identical
    // replacement bytes do not authorize adopting a replacement guard.
    let f = fixture(&base);
    let fence = acquire(&f).unwrap();
    let lock = f.configuration.join("foreground.lock");
    let bytes = fs::read(&lock).unwrap();
    raw(&f.configuration.join("replacement"), &bytes);
    fs::rename(f.configuration.join("replacement"), &lock).unwrap();
    assert!(fence.validate().is_err());
    assert_eq!(fs::read(&lock).unwrap(), bytes);
    assert!(f.configuration.join("advance.lock").exists());

    let f = fixture(&base);
    let fence = acquire(&f).unwrap();
    fs::write(
        f.configuration.join("state.json"),
        b"changed-owned-material",
    )
    .unwrap();
    assert!(fence.validate().is_err());
    assert!(fence.frozen[0].bytes.as_slice() == STATE);
    for name in LOCKS {
        assert!(f.configuration.join(name).exists());
    }

    // Existing unknown/symlink/hardlink/wrong-mode names remain untouched.
    for kind in ["opaque", "symlink", "hardlink", "mode"] {
        let f = fixture(&base);
        let name = f.configuration.join("foreground.lock");
        match kind {
            "symlink" => symlink("state.json", &name).unwrap(),
            "hardlink" => fs::hard_link(f.configuration.join("state.json"), &name).unwrap(),
            _ => {
                raw(&name, b"existing-unknown");
                if kind == "mode" {
                    fs::set_permissions(&name, fs::Permissions::from_mode(0o644)).unwrap();
                }
            }
        }
        let before = fs::symlink_metadata(&name).unwrap();
        let failure = acquire(&f).unwrap_err();
        assert_eq!(failure.error(), LegacyFenceError::BusyOrUnresolved);
        assert_eq!(failure.retained_lock_count(), 1); // advance retained, never deleted
        drop(failure);
        let after = fs::symlink_metadata(&name).unwrap();
        assert_eq!(
            (after.dev(), after.ino(), after.mode()),
            (before.dev(), before.ino(), before.mode())
        );
        assert!(f.configuration.join("advance.lock").exists());
    }

    // Missing service metadata is only a supported-selection restriction, not
    // quiescence evidence. An existing service file is never interpreted away.
    let f = fixture(&base);
    raw(&f.host.join("service.json"), b"{}");
    let failure = acquire(&f).unwrap_err();
    assert_eq!(failure.error(), LegacyFenceError::BusyOrUnresolved);
    assert_eq!(failure.retained_lock_count(), 0);
    assert_eq!(fs::read(f.host.join("service.json")).unwrap(), b"{}");

    // A service descriptor is only protected material. The platform manager
    // must still verify its signed bootstrap/unit/live process before control.
    // Two byte-identical descriptors in different Host roots cannot substitute.
    let a = fixture(&base);
    let b = fixture(&base);
    let service_bytes = br#"{"unitName":"styx-owned-material.service"}"#;
    raw(&a.host.join("service.json"), service_bytes);
    raw(&b.host.join("service.json"), service_bytes);
    let descriptor =
        Arc::new(LegacyServiceDescriptor::capture(&PrivateRoot::open(&a.host).unwrap()).unwrap());
    let foreign = LegacyWriterFence::acquire_with_service_descriptor(
        b.owner.clone(),
        b.owner
            .begin_maintenance("service-foreign".try_into().unwrap())
            .unwrap(),
        PrivateRoot::open(&b.host).unwrap(),
        &inputs(),
        descriptor.clone(),
    )
    .unwrap_err();
    assert_eq!(foreign.error(), LegacyFenceError::InvalidMaterials);
    assert_eq!(foreign.retained_lock_count(), 0);
    assert!(!b.configuration.join("advance.lock").exists());
    let fence = LegacyWriterFence::acquire_with_service_descriptor(
        a.owner.clone(),
        a.owner
            .begin_maintenance("service-original".try_into().unwrap())
            .unwrap(),
        PrivateRoot::open(&a.host).unwrap(),
        &inputs(),
        descriptor.clone(),
    )
    .unwrap();
    fence.verify_service_descriptor(&descriptor).unwrap();
    assert_eq!(descriptor.raw_bytes(), service_bytes);
    assert_eq!(
        descriptor.host_root_identity(),
        PrivateRoot::open(&a.host).unwrap().identity()
    );
    assert_busy(&a);
    let old = OldWriter::start(&node, &a.configuration.join("advance.lock"), false).await;
    assert_eq!(old.line, "REFUSED\n");
    old.finish(false, 23).await;
    // Same-content replacement is a different original file. Neither an intact
    // signature elsewhere nor a known pathname permits silently adopting it.
    raw(&a.host.join("service-replacement"), service_bytes);
    fs::rename(
        a.host.join("service-replacement"),
        a.host.join("service.json"),
    )
    .unwrap();
    assert_eq!(
        fs::read(a.host.join("service.json")).unwrap(),
        service_bytes
    );
    assert!(fence.validate().is_err());
    assert!(fence.verify_service_descriptor(&descriptor).is_err());
    assert_busy(&a);
    for name in LOCKS {
        assert!(a.configuration.join(name).exists());
    }

    // Closed path/role vocabulary rejects before any file is created.
    let f = fixture(&base);
    let maintenance = f
        .owner
        .begin_maintenance("bad-selection".try_into().unwrap())
        .unwrap();
    let mut bad = inputs();
    bad[0].input.relative_path = "opaque-unapproved.json".into();
    let failure = LegacyWriterFence::acquire(
        f.owner.clone(),
        maintenance,
        PrivateRoot::open(&f.host).unwrap(),
        &bad,
    )
    .unwrap_err();
    assert_eq!(failure.error(), LegacyFenceError::InvalidMaterials);
    assert_eq!(failure.retained_lock_count(), 0);
    for name in LOCKS {
        assert!(!f.configuration.join(name).exists());
    }
    // No names/materials are removed: every failed intermediate is retained as
    // evidence. Exact child waits above cover only owned old-primitives, NOT a
    // stopped real Host/Gateway or an OS service/descendant settlement claim.
}
