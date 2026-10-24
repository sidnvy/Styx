//! Real owned fixture processes; not native logind or Desktop acceptance.
use super::*;
use crate::store::ProcessIdentity;
use std::os::unix::process::ExitStatusExt;

struct Fixtures {
    root: PathBuf,
}
impl Fixtures {
    fn new() -> Self {
        let root =
            std::env::temp_dir().join(format!("styx-session-probe-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self { root }
    }
    fn image(&self, name: &str, mode: &str, payload: &str) -> (PinnedWorker, PathBuf) {
        let binary = File::open("/usr/bin/python3").unwrap();
        let launch = PathBuf::from(format!(
            "/proc/{}/fd/{}",
            std::process::id(),
            binary.as_raw_fd()
        ));
        let pid_file = self.root.join(name);
        let code = "import os,sys,time,json\npid=os.getpid()\nbirth=int(open('/proc/self/stat').read().rsplit(')',1)[1].split()[19])\nwith open(sys.argv[1],'w') as f: json.dump({'pid':pid,'birth':birth},f)\nmode=sys.argv[2]\nif mode=='large':\n sys.stdout.buffer.write(b'x'*65537);sys.stdout.buffer.flush();time.sleep(30)\nelif mode=='hang': time.sleep(30)\nelif mode=='refusal':\n sys.stdout.write(sys.argv[3]);sys.stdout.flush();sys.exit(2)\nelse:\n sys.stdout.write(sys.argv[3]);sys.stdout.flush()\n";
        (
            PinnedWorker {
                _image: binary,
                launch,
                args: vec![
                    "-I".into(),
                    "-c".into(),
                    code.into(),
                    pid_file.as_os_str().to_owned(),
                    mode.into(),
                    payload.into(),
                ],
                environment: Default::default(),
                observed_exit: None,
            },
            pid_file,
        )
    }
}
impl Drop for Fixtures {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root).unwrap();
    }
}
async fn pid_fact(path: &std::path::Path) -> (u32, u64) {
    let end = Instant::now() + Duration::from_secs(2);
    loop {
        if let Ok(bytes) = std::fs::read(path)
            && let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes)
            && let (Some(pid), Some(birth)) = (value["pid"].as_u64(), value["birth"].as_u64())
        {
            return (u32::try_from(pid).unwrap(), birth);
        }
        assert!(
            Instant::now() < end,
            "fixture did not write its own identity"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
fn assert_original_gone((pid, birth): (u32, u64)) {
    match ProcessIdentity::observe(pid) {
        Ok(ProcessIdentity::Linux { start_ticks, .. }) => assert_ne!(
            start_ticks, birth,
            "original fixture PID/birth still exists"
        ),
        Err(_) => assert!(
            !std::path::Path::new(&format!("/proc/{pid}")).exists(),
            "cannot infer exit from an observation error"
        ),
    }
    println!("owned_fixture_gone pid={pid} start_ticks={birth}");
}
async fn available() {
    let end = Instant::now() + Duration::from_secs(2);
    while SLOT.available_permits() != 1 {
        assert!(
            Instant::now() < end,
            "actual process cleanup did not return its permit"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
#[tokio::test]
async fn owned_worker_bounds_cancel_and_reap_batch() {
    let fixtures = Fixtures::new();
    let uid = nix::unistd::Uid::current().as_raw();
    let payload =
        r#"{"schema":1,"login_unique_owner":":1.42","candidates":[],"connection_closed":true}"#;
    let (image, pid) = fixtures.image("valid", "valid", payload);
    assert!(run(image, uid).await.unwrap().candidates.is_empty());
    assert_original_gone(pid_fact(&pid).await);
    available().await;

    let (image, pid) = fixtures.image("oversize", "large", "");
    assert_eq!(
        run(image, uid).await.err(),
        Some(ProbeError::OutputTooLarge)
    );
    assert_original_gone(pid_fact(&pid).await);
    available().await;

    let (image, pid) = fixtures.image("hang", "hang", "");
    let hung = tokio::spawn(run(image, uid));
    let identity = pid_fact(&pid).await;
    assert_eq!(SLOT.available_permits(), 0);
    assert_eq!(probe_current_user().await.err(), Some(ProbeError::Busy));
    assert_eq!(hung.await.unwrap().err(), Some(ProbeError::Deadline));
    assert_original_gone(identity);
    available().await;

    let (image, pid) = fixtures.image("caller-drop", "hang", "");
    let waiter = tokio::spawn(run(image, uid));
    let identity = pid_fact(&pid).await;
    assert_eq!(SLOT.available_permits(), 0);
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    available().await;
    assert_original_gone(identity);

    let (image, pid) = fixtures.image("invalid", "valid", "{}");
    assert_eq!(run(image, uid).await.err(), Some(ProbeError::InvalidFacts));
    assert_original_gone(pid_fact(&pid).await);
    available().await;
    let refusal =
        serde_json::to_string(&WorkerRefusal::from_error(DiscoveryError::OwnerChanged)).unwrap();
    let (image, pid) = fixtures.image("typed-refusal", "refusal", &refusal);
    let error = run(image, uid).await.unwrap_err();
    assert_eq!(error, ProbeError::Discovery(DiscoveryError::OwnerChanged));
    assert_eq!(error.code(), "login_owner_changed");
    assert_original_gone(pid_fact(&pid).await);
    available().await;
    // Unknown/extra fields cannot manufacture a recognized native cause.
    assert!(
        serde_json::from_str::<WorkerRefusal>(r#"{"schema":1,"error":"arbitrary_private_text"}"#)
            .is_err()
    );
    assert!(
        serde_json::from_str::<WorkerRefusal>(
            r#"{"schema":1,"error":"owner_changed","extra":"private"}"#
        )
        .is_err()
    );
    let image_file = File::open("/proc/self/exe").unwrap();
    let memory_pid = fixtures.root.join("memory-pid");
    let memory_stage = fixtures.root.join("memory-stage");
    let exit = Arc::new(std::sync::Mutex::new(None));
    let image = PinnedWorker {
        launch: PathBuf::from(format!(
            "/proc/{}/fd/{}",
            std::process::id(),
            image_file.as_raw_fd()
        )),
        _image: image_file,
        args: vec![
            "--exact".into(),
            "session_probe::tests::memory_limit_worker_fixture".into(),
            "--ignored".into(),
            "--nocapture".into(),
        ],
        environment: std::collections::BTreeMap::from([
            (
                "STYX_TEST_PROBE_MEMORY_PID".into(),
                memory_pid.to_str().unwrap().into(),
            ),
            (
                "STYX_TEST_PROBE_MEMORY_STAGE".into(),
                memory_stage.to_str().unwrap().into(),
            ),
        ]),
        observed_exit: Some(exit.clone()),
    };
    assert_eq!(run(image, uid).await.err(), Some(ProbeError::WorkerFailed));
    assert_eq!(
        std::fs::read_to_string(memory_stage).unwrap(),
        "limits_set;allocation_begin"
    );
    let status = exit.lock().unwrap().unwrap();
    println!(
        "memory_fixture_exit signal={:?} code={:?}",
        status.signal(),
        status.code()
    );
    assert_eq!(
        status.signal(),
        Some(nix::libc::SIGABRT),
        "must observe allocator failure, not malformed output or timeout"
    );
    assert_original_gone(pid_fact(&memory_pid).await);
    available().await;
    let (image, pid) = fixtures.image("after-memory", "valid", payload);
    assert!(run(image, uid).await.unwrap().candidates.is_empty());
    assert_original_gone(pid_fact(&pid).await);
    available().await;
    println!(
        "owned-process probe batch PASS: valid typed fixture, oversize>64KiB, timeout, caller future drop, Busy/no second worker, malformed facts; memory allocation SIGABRT isolated; recovery success; typed refusal preserved; all8 exact PID/birth identities gone after actualwait; slot returned after each; private fixture root removed on test completion; not logind/Desktop acceptance"
    );
}

/// Child-only fixture. It is invoked by the new parent batch; the deliberately
/// failed allocation must never run inside its parent process.
#[test]
#[ignore = "child-only resource isolation fixture; invoked by owned_worker_bounds_cancel_and_reap_batch"]
fn memory_limit_worker_fixture() {
    let pid_path =
        std::path::PathBuf::from(std::env::var_os("STYX_TEST_PROBE_MEMORY_PID").unwrap());
    let stage_path =
        std::path::PathBuf::from(std::env::var_os("STYX_TEST_PROBE_MEMORY_STAGE").unwrap());
    let ProcessIdentity::Linux {
        pid, start_ticks, ..
    } = ProcessIdentity::current().unwrap();
    std::fs::write(
        pid_path,
        serde_json::to_vec(&serde_json::json!({"pid":pid,"birth":start_ticks})).unwrap(),
    )
    .unwrap();
    prepare_worker_limits().unwrap();
    std::fs::write(&stage_path, "limits_set;allocation_begin").unwrap();
    let mut bytes = vec![0u8; 128 * 1024 * 1024];
    for (index, page) in bytes.chunks_mut(4096).enumerate() {
        page[0] = (index % 251) as u8;
    }
    std::hint::black_box(&bytes);
    assert_eq!(bytes[4096], 1);
    std::fs::write(stage_path, "allocation_survived").unwrap();
}
