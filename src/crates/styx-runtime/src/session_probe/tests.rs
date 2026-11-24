//! Real owned fixture processes; not native logind or Desktop acceptance.
use super::*;
use crate::store::ProcessIdentity;

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
async fn wait_original_gone(identity: (u32, u64)) {
    let end = Instant::now() + Duration::from_secs(2);
    while let Ok(ProcessIdentity::Linux { start_ticks, .. }) = ProcessIdentity::observe(identity.0)
    {
        if start_ticks != identity.1 {
            break;
        }
        assert!(
            Instant::now() < end,
            "original probe did not finish cleanup"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_original_gone(identity);
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

    let (image, pid) = fixtures.image("oversize", "large", "");
    assert_eq!(
        run(image, uid).await.err(),
        Some(ProbeError::OutputTooLarge)
    );
    assert_original_gone(pid_fact(&pid).await);

    let (image, pid) = fixtures.image("hang", "hang", "");
    let hung = tokio::spawn(run(image, uid));
    let identity = pid_fact(&pid).await;
    // A slow probe does not reserve discovery for the whole Host.
    let (parallel, parallel_pid) = fixtures.image("parallel", "valid", payload);
    assert!(run(parallel, uid).await.unwrap().candidates.is_empty());
    assert_original_gone(pid_fact(&parallel_pid).await);
    assert_eq!(hung.await.unwrap().err(), Some(ProbeError::Deadline));
    assert_original_gone(identity);

    let (image, pid) = fixtures.image("caller-drop", "hang", "");
    let waiter = tokio::spawn(run(image, uid));
    let identity = pid_fact(&pid).await;
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    wait_original_gone(identity).await;

    let (image, pid) = fixtures.image("invalid", "valid", "{}");
    assert_eq!(run(image, uid).await.err(), Some(ProbeError::InvalidFacts));
    assert_original_gone(pid_fact(&pid).await);
    let refusal =
        serde_json::to_string(&WorkerRefusal::from_error(DiscoveryError::OwnerChanged)).unwrap();
    let (image, pid) = fixtures.image("typed-refusal", "refusal", &refusal);
    let error = run(image, uid).await.unwrap_err();
    assert_eq!(error, ProbeError::Discovery(DiscoveryError::OwnerChanged));
    assert_eq!(error.code(), "login_owner_changed");
    assert_original_gone(pid_fact(&pid).await);
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
    println!(
        "owned-process probe batch PASS: valid typed fixture, oversize>64KiB, timeout, caller future drop, independent concurrent probe, malformed facts; typed refusal preserved; exact PID/birth identities gone after actual wait; not logind/Desktop acceptance"
    );
}

/// Real child regression for the long-lived watcher's former cumulative CPU cap.
/// The existing probe batch separately verifies deadline/drop cleanup ownership.
#[tokio::test]
async fn owned_worker_inherits_resources_and_outlives_old_cpu_quota() {
    use nix::sys::resource::{Resource, getrlimit};
    let fixtures = Fixtures::new();
    let evidence = fixtures.root.join("worker.json");
    let parent = ProcessIdentity::current().unwrap();
    let ProcessIdentity::Linux {
        pid, start_ticks, ..
    } = parent;
    let inherited: Vec<_> = [
        Resource::RLIMIT_CPU,
        Resource::RLIMIT_AS,
        Resource::RLIMIT_DATA,
        Resource::RLIMIT_STACK,
        Resource::RLIMIT_NOFILE,
    ]
    .into_iter()
    .map(|r| getrlimit(r).unwrap())
    .collect();
    // This regression needs a parent without the removed CPU quota; it does not
    // raise system limits or alter the parent in order to manufacture success.
    assert_eq!(
        inherited[0],
        (nix::libc::RLIM_INFINITY, nix::libc::RLIM_INFINITY)
    );
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "session_probe::tests::worker_resource_inheritance_fixture",
            "--ignored",
            "--nocapture",
        ])
        .env("STYX_INTERNAL_PROBE_PARENT_PID", pid.to_string())
        .env("STYX_INTERNAL_PROBE_PARENT_BIRTH", start_ticks.to_string())
        .env("STYX_TEST_PROBE_RESOURCE_EVIDENCE", &evidence)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let original = ProcessIdentity::observe(child.id().unwrap()).unwrap();
    let result = timeout_at(Instant::now() + Duration::from_secs(30), child.wait()).await;
    if result.is_err() {
        child.start_kill().unwrap();
        child.wait().await.unwrap();
        panic!("resource inheritance fixture did not complete");
    }
    assert!(
        result.unwrap().unwrap().success(),
        "worker died before independent completion evidence"
    );
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&evidence).unwrap()).unwrap();
    assert_eq!(value["inherited"], serde_json::to_value(inherited).unwrap());
    assert!(value["cpu_micros"].as_i64().unwrap() >= 3_250_000);
    assert_eq!(value["allocated_bytes"], 128 * 1024 * 1024);
    assert_eq!(value["open_files"], 64);
    assert_eq!(value["core_dump_disabled"], true);
    assert_eq!(value["parent_death_signal_preserved"], true);
    let ProcessIdentity::Linux {
        pid, start_ticks, ..
    } = original;
    assert_original_gone((pid, start_ticks));
}

/// Child-only fixture using the production worker preparation. Real CPU work
/// crosses both former CPU limits and still reaches a normal process exit.
#[test]
#[ignore = "child-only resource inheritance fixture; invoked by owned_worker_inherits_resources_and_outlives_old_cpu_quota"]
fn worker_resource_inheritance_fixture() {
    use nix::sys::{
        resource::{Resource, UsageWho, getrlimit, getrusage},
        time::TimeValLike,
    };
    let evidence = PathBuf::from(std::env::var_os("STYX_TEST_PROBE_RESOURCE_EVIDENCE").unwrap());
    prepare_owned_worker().unwrap();
    let inherited: Vec<_> = [
        Resource::RLIMIT_CPU,
        Resource::RLIMIT_AS,
        Resource::RLIMIT_DATA,
        Resource::RLIMIT_STACK,
        Resource::RLIMIT_NOFILE,
    ]
    .into_iter()
    .map(|r| getrlimit(r).unwrap())
    .collect();
    let files: Vec<_> = (0..64).map(|_| File::open("/dev/null").unwrap()).collect();
    let mut bytes = vec![0u8; 128 * 1024 * 1024];
    for (index, page) in bytes.chunks_mut(4096).enumerate() {
        page[0] = (index % 251) as u8;
    }
    let cpu_time = || {
        let usage = getrusage(UsageWho::RUSAGE_SELF).unwrap();
        usage.user_time().num_microseconds() + usage.system_time().num_microseconds()
    };
    let start = cpu_time();
    let mut value = 1u64;
    while cpu_time() - start < 3_250_000 {
        for _ in 0..100_000 {
            value = std::hint::black_box(value.wrapping_mul(6364136223846793005).wrapping_add(1));
        }
    }
    std::hint::black_box((&bytes, &files, value));
    let observed = serde_json::json!({"inherited":inherited, "cpu_micros":cpu_time()-start,
        "allocated_bytes":bytes.len(), "open_files":files.len(),
        "core_dump_disabled":getrlimit(Resource::RLIMIT_CORE).unwrap()==(0,0),
        "parent_death_signal_preserved":nix::sys::prctl::get_pdeathsig().unwrap()==Some(nix::sys::signal::Signal::SIGKILL)});
    std::fs::write(evidence, serde_json::to_vec(&observed).unwrap()).unwrap();
}
