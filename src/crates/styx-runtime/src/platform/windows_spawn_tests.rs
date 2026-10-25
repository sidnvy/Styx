use super::*;
#[test]
fn fixed_native_spawn_input_boundary() {
    // This is a pure input contract, not a JobObject or native lifecycle claim.
    let mut env = BTreeMap::new();
    assert_eq!(environment(&env).unwrap(), vec![0, 0]);
    env.insert(OsString::from("CODEX_HOME"), OsString::from("D:\\owned"));
    let block = environment(&env).unwrap();
    assert!(block.ends_with(&[0, 0]));
    env.insert(OsString::from("codex_home"), OsString::from("D:\\other"));
    assert!(environment(&env).is_err());
    env.clear();
    env.insert(OsString::from("BAD=KEY"), OsString::from("value"));
    assert!(environment(&env).is_err());
    assert!(wide(OsStr::new("")).is_err());
    assert!(wide(&OsString::from_wide(&[65, 0, 66])).is_err());
}

// Explicitly owned fixture of original Codex PE bytes. This test's filesystem
// pin is an OS-image observation, not a publisher/signature or remote Exec grant.
#[tokio::test]
#[ignore = "requires protected owned Windows fixture with original Codex PE copies; actual JobObject/native initialization"]
async fn actual_pinned_codex_suspended_job_cleanup_and_waiter_drop() {
    use crate::store::{PayloadLimits, PrivateRoot};
    use tokio::sync::Semaphore;
    let root =
        PathBuf::from(std::env::var_os("STYX_TEST_WINDOWS_SPAWN_ROOT").expect("explicit fixture"));
    assert!(root.is_absolute());
    PrivateRoot::open(&root).unwrap();
    let inventory = PrivateRoot::open(root.join("payload"))
        .unwrap()
        .payload_inventory(PayloadLimits::default())
        .unwrap();
    let original = Arc::new(inventory.pin_executable("bin/codex.exe").unwrap());
    let other_inventory = PrivateRoot::open(root.join("other"))
        .unwrap()
        .payload_inventory(PayloadLimits::default())
        .unwrap();
    let other = Arc::new(other_inventory.pin_executable("bin/codex.exe").unwrap());
    let work = root.join("work");
    PrivateRoot::open(&work).unwrap();
    PrivateRoot::open(root.join("home")).unwrap();
    let system_root = std::env::var_os("SystemRoot").expect("trusted OS fixture environment");
    let env = BTreeMap::from([
        (OsString::from("SystemRoot"), system_root.clone()),
        (
            OsString::from("CODEX_HOME"),
            root.join("home").into_os_string(),
        ),
    ]);
    let pool = Arc::new(Semaphore::new(16 * 1024 * 1024));
    // A real original image exists but has no native-user-code execution yet.
    let budget = Arc::new(
        pool.clone()
            .acquire_many_owned(16 * 1024 * 1024)
            .await
            .unwrap(),
    );
    let pin = original.clone();
    let dir = work.clone();
    let variables = env.clone();
    let mut suspended =
        tokio::task::spawn_blocking(move || spawn_suspended(pin, budget, dir, variables))
            .await
            .unwrap()
            .unwrap();
    {
        let guard = suspended.child.shared.native.lock().unwrap();
        let native = guard.as_ref().unwrap();
        assert_eq!(ffi::active(&native.job).unwrap(), 1);
        assert!(ffi::poll_exit(&native.process).unwrap().is_none());
        assert!(
            image_matches(&other, &native.process).is_err(),
            "same bytes at another file identity cannot substitute the pin"
        );
    }
    assert_eq!(
        ffi::available(suspended.child.stdout.as_ref().unwrap()).unwrap(),
        0
    );
    // Deliberately wrong birth/PID: production verification must refuse before
    // ResumeThread, preserving ownership of the actual original suspended child.
    suspended.birth = ProcessIdentity::current().unwrap();
    let failure = suspended
        .verify_and_resume()
        .err()
        .expect("wrong PID/birth refused");
    let mut rejected = failure.into_owned_child().expect("failed child retained");
    rejected.terminate_and_wait().await.unwrap();
    {
        let facts = rejected.shared.facts.lock().unwrap();
        assert!(facts.root_waited && facts.job_empty && facts.supervisor_finished);
        assert!(!facts.handles_closed_unconfirmed);
    }
    drop(rejected);
    assert_eq!(pool.available_permits(), 16 * 1024 * 1024);

    // Real query-failure injection on an actual Job. It must stop the original
    // scope and finish supervision boundedly, never turn close into wait proof.
    let budget = Arc::new(
        pool.clone()
            .acquire_many_owned(16 * 1024 * 1024)
            .await
            .unwrap(),
    );
    let pin = original.clone();
    let dir = work.clone();
    let variables = env.clone();
    let suspended =
        tokio::task::spawn_blocking(move || spawn_suspended(pin, budget, dir, variables))
            .await
            .unwrap()
            .unwrap();
    suspended
        .child
        .shared
        .inject_query_failure
        .store(true, Ordering::Release);
    let SuspendedChild {
        mut child,
        thread,
        birth,
    } = suspended;
    drop(thread);
    assert!(
        tokio::time::timeout(Duration::from_secs(8), child.wait())
            .await
            .unwrap()
            .is_err()
    );
    {
        let facts = child.shared.facts.lock().unwrap();
        assert!(facts.supervisor_finished && facts.unknown && facts.handles_closed_unconfirmed);
        assert!(!facts.root_waited && !facts.job_empty);
    }
    drop(child);
    assert_eq!(pool.available_permits(), 16 * 1024 * 1024);
    assert!(!birth.still_current().unwrap());

    // Positive initialization uses the existing native Codex adapter and RPC.
    let partition = pool
        .clone()
        .acquire_many_owned(16 * 1024 * 1024)
        .await
        .unwrap();
    let config = crate::providers::codex::OwnedExecutorConfig {
        binary: root.join("payload/bin/codex.exe"),
        cwd: work.clone(),
        environment: BTreeMap::from([
            (
                "SystemRoot".into(),
                system_root.to_string_lossy().into_owned(),
            ),
            (
                "CODEX_HOME".into(),
                root.join("home").to_str().unwrap().into(),
            ),
        ]),
        rpc_timeout: Duration::from_secs(10),
        retained_process_limit: 16,
    };
    let provider = crate::providers::codex::CodexStdio::spawn_pinned_with_reserved_budget(
        config,
        partition,
        original.clone(),
    )
    .await
    .unwrap();
    assert!(!provider.session_id().is_empty() && !provider.provider_id().is_empty());
    let cleanup = provider.shutdown_owned(Duration::from_secs(10)).await;
    assert!(cleanup.executor_exited && cleanup.reader_task_reaped && cleanup.stderr_task_reaped);
    drop(provider);
    assert_eq!(pool.available_permits(), 16 * 1024 * 1024);

    // Dropping only the waiter requests termination. The independent supervisor
    // owns the handles/pin/credit; completion credit is returned after it exits.
    let budget = Arc::new(
        pool.clone()
            .acquire_many_owned(16 * 1024 * 1024)
            .await
            .unwrap(),
    );
    let pin = original.clone();
    let dir = work;
    let variables = env;
    let suspended =
        tokio::task::spawn_blocking(move || spawn_suspended(pin, budget, dir, variables))
            .await
            .unwrap()
            .unwrap();
    let SuspendedChild {
        mut child,
        thread,
        birth,
    } = suspended;
    drop(thread);
    assert_eq!(pool.available_permits(), 0);
    let waiter = tokio::spawn(async move { child.wait().await });
    tokio::task::yield_now().await;
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    tokio::time::timeout(Duration::from_secs(8), async {
        while pool.available_permits() != 16 * 1024 * 1024 {
            tokio::time::sleep(Duration::from_millis(20)).await
        }
    })
    .await
    .unwrap();
    assert!(!birth.still_current().unwrap());
    // No new business operation/nonce or descendant-containment success is
    // inferred from this cancelled-waiter branch. Ordinary Host E2E is separate.
}

#[test]
#[allow(unsafe_code)]
fn browser_fixed_argv_roundtrips_through_windows_parser() {
    use windows_sys::Win32::{Foundation::LocalFree, UI::Shell::CommandLineToArgvW};
    let application = OsStr::new(r"D:\owned runtime\node.exe");
    let entry = Entry::Browser {
        worker: PathBuf::from(r"D:\owned space\worker.mjs"),
        config: PathBuf::from("D:\\config\\quoted\"value\\tail\\"),
    };
    let command = command_line(application, &entry).unwrap();
    let mut count = 0;
    // Independent OS parser: no child, shell, browser or fixture side effect.
    let parsed = unsafe { CommandLineToArgvW(command.as_ptr(), &mut count) };
    assert!(!parsed.is_null());
    let values: Vec<OsString> = (0..count as usize)
        .map(|i| {
            let start = unsafe { *parsed.add(i) };
            let mut length = 0;
            while unsafe { *start.add(length) } != 0 {
                length += 1;
            }
            OsString::from_wide(unsafe { std::slice::from_raw_parts(start, length) })
        })
        .collect();
    unsafe {
        LocalFree(parsed.cast());
    }
    let Entry::Browser { worker, config } = entry else {
        unreachable!()
    };
    assert_eq!(
        values,
        vec![
            application.to_os_string(),
            worker.into_os_string(),
            "--config".into(),
            config.into_os_string()
        ]
    );
    assert!(quote_argument(OsStr::new("bad\0arg"), &mut Vec::new()).is_err());
    assert!(quote_argument(OsStr::new(&"\\".repeat(32768)), &mut Vec::new()).is_err());
}
