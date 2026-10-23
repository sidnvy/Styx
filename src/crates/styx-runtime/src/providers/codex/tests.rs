use super::*;
use styx_contracts::identity::*;
use styx_contracts::{capability::*, error::Recovery, operation::*};
use styx_core::{
    operations::{DispatchDisposition, DispatchPermit, OperationLedger, OperationSnapshot},
    policy::AdmissionFacts,
};
struct Authority {
    ledger: OperationLedger,
    owner: OwnerLease,
    foreign: OwnerLease,
    facts: AdmissionFacts,
}
fn authority() -> Authority {
    let mut ledger = OperationLedger::new(HostGeneration::try_from("test-host").unwrap());
    let owner = ledger
        .register_verified_owner(
            OwnerId::try_from("test-owner:a").unwrap(),
            OwnerEpoch::try_from("epoch-a").unwrap(),
        )
        .unwrap();
    let foreign = ledger
        .register_verified_owner(
            OwnerId::try_from("test-owner:b").unwrap(),
            OwnerEpoch::try_from("epoch-b").unwrap(),
        )
        .unwrap();
    let facts = AdmissionFacts {
        device_id: DeviceId::try_from("styx-test").unwrap(),
        grant_revision: 1,
        local_policy_allowed: true,
        descriptor: CapabilityDescriptor {
            contract_version: 1,
            capability_id: CapabilityId::ExecRun,
            scope: Scope::Host,
            provider_id: ProviderId::try_from("codex").unwrap(),
            configured: true,
            remote_grant: true,
            availability: Availability::Available,
            authorization: Authorization::Granted,
            target_session: None,
            reason: None,
            observed_at: 1,
            observation_generation: 1,
            recovery: Recovery::None,
        },
        session_state: None,
        current_observation: None,
    };
    Authority {
        ledger,
        owner,
        foreign,
        facts,
    }
}
impl Authority {
    fn issue(&mut self, spec: StartProcess) -> (DispatchPermit, OperationId, Sha256Digest) {
        self.issue_payload(spec.to_operation_payload().unwrap())
    }
    fn issue_payload(&mut self, payload: Vec<u8>) -> (DispatchPermit, OperationId, Sha256Digest) {
        let context = PreparedContext {
            device_id: self.facts.device_id.clone(),
            grant_revision: 1,
            session: None,
            observation: None,
            capability: CapabilityId::ExecRun,
            deadline: MonotonicMillis(100000),
            disconnect_policy: DisconnectPolicy::RetainForOwner,
        };
        let snapshot = self
            .ledger
            .prepare(&self.owner, context, payload, MonotonicMillis(1))
            .unwrap();
        let permit = match self
            .ledger
            .dispatch(
                &self.owner,
                &snapshot.id,
                snapshot.payload_digest,
                &self.facts,
                MonotonicMillis(1),
            )
            .unwrap()
        {
            DispatchDisposition::ExecuteOnce(permit) => permit,
            _ => panic!("fresh reservation did not dispatch"),
        };
        (permit, snapshot.id, snapshot.payload_digest)
    }
    async fn run(&mut self, adapter: &CodexStdio, spec: StartProcess) -> StartReceipt {
        adapter.start(self.issue(spec).0).await.unwrap()
    }
}
#[test]
fn output_cursor_terminal_gaps_and_utf8_are_independent_facts() {
    let page:ReadPage=serde_json::from_value(json!({"chunks":[{"seq":1,"stream":"stdout","chunk":"5L0="}],"nextSeq":2,"exited":false,"exitCode":null,"closed":false,"failure":null})).unwrap();
    let mut decoder = OutputDecoder::default();
    let validated = output::validate(&page, None, 0, 100).unwrap();
    assert!(decoder.decode(validated.chunks, false).unwrap().is_empty());
    let second:ReadPage=serde_json::from_value(json!({"chunks":[{"seq":2,"stream":"stdout","chunk":"oA=="}],"nextSeq":5,"exited":true,"exitCode":7,"closed":true,"failure":null})).unwrap();
    let validated = output::validate(&second, Some(1), 0, 100).unwrap();
    assert_eq!(
        decoder.decode(validated.chunks, false).unwrap()[0].text,
        "你"
    );
    let duplicate:ReadPage=serde_json::from_value(json!({"chunks":[{"seq":1,"stream":"stdout","chunk":"YQ=="}],"nextSeq":2,"exited":false,"exitCode":null,"closed":false})).unwrap();
    assert!(output::validate(&duplicate, Some(1), 0, 100).is_err());
    let bad_gap: ReadPage = serde_json::from_value(
        json!({"chunks":[],"nextSeq":9,"exited":true,"exitCode":0,"closed":true}),
    )
    .unwrap();
    assert!(output::validate(&bad_gap, None, 0, 100).is_err());
    let eof: ReadPage = serde_json::from_value(
        json!({"chunks":[],"nextSeq":2,"exited":false,"exitCode":null,"closed":true}),
    )
    .unwrap();
    output::validate(&eof, None, 0, 100).unwrap();
    assert!(!eof.exited);
    assert_eq!(eof.exit_code, None);
}
fn spec(root: &std::path::Path, command: &str, tty: bool) -> StartProcess {
    StartProcess {
        argv: vec!["/bin/sh".into(), "-c".into(), command.into()],
        cwd_file_uri: url::Url::from_directory_path(root).unwrap().to_string(),
        environment: BTreeMap::from([("PATH".into(), "/usr/bin:/bin".into())]),
        tty,
    }
}
async fn drain(adapter: &CodexStdio, owner: &OwnerLease, handle: &ProcessHandle) -> (String, i32) {
    let mut text = String::new();
    for _ in 0..100 {
        let page = adapter
            .read(owner, handle, 65536, Duration::from_millis(100))
            .await
            .unwrap();
        for c in page.chunks {
            text.push_str(&c.text)
        }
        if page.drain == OutputDrain::Drained {
            assert_eq!(page.liveness, ExecutionLiveness::Exited);
            return (text, page.exit_code.unwrap());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("bounded drain did not finish")
}
#[tokio::test]
#[ignore = "requires STYX_TEST_CODEX and STYX_TEST_EXEC_ROOT; starts only its isolated owned executor"]
async fn real_codex_native_stdio_complete_scenario_batch() {
    let binary = PathBuf::from(std::env::var("STYX_TEST_CODEX").unwrap());
    let root = PathBuf::from(std::env::var("STYX_TEST_EXEC_ROOT").unwrap())
        .join(Uuid::new_v4().to_string());
    std::fs::create_dir_all(root.join("codex-home")).unwrap();
    let adapter = CodexStdio::spawn_owned(OwnedExecutorConfig {
        binary,
        cwd: root.clone(),
        environment: BTreeMap::from([
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("HOME".into(), root.display().to_string()),
            (
                "CODEX_HOME".into(),
                root.join("codex-home").display().to_string(),
            ),
        ]),
        rpc_timeout: Duration::from_millis(300),
        retained_process_limit: 2,
    })
    .await
    .unwrap();
    let mut auth = authority();
    let owner = auth.owner.clone();
    let nonce = Uuid::new_v4().to_string();
    let marker = root.join("independent-effect.txt");
    let mut start = spec(
        &root,
        "printf '%s' \"$1\" > \"$2\"; printf OUT; printf ERR >&2; exit 7",
        false,
    );
    start.argv.extend([
        "r09-fixture".into(),
        nonce.clone(),
        marker.display().to_string(),
    ]);
    let (permit, id, digest) = auth.issue(start);
    let first = adapter.start(permit).await.unwrap();
    assert_eq!(first.dispatch, DispatchEvidence::Started);
    assert_eq!(
        adapter
            .read(&auth.foreign, &first.handle, 10, Duration::ZERO)
            .await
            .unwrap_err(),
        ExecError::OwnerMismatch
    );
    let (out, code) = drain(&adapter, &owner, &first.handle).await;
    assert_eq!(code, 7);
    assert!(out.contains("OUT") && out.contains("ERR"));
    assert_eq!(std::fs::read_to_string(&marker).unwrap(), nonce);
    assert!(!root.join("negative-control.txt").exists());
    adapter.retire(&owner, &first.handle).await.unwrap();
    assert_eq!(
        adapter.lookup_operation(&owner, &id).await.unwrap_err(),
        ExecError::UnknownHandle
    );
    assert!(
        matches!(
            auth.ledger
                .dispatch(&owner, &id, digest, &auth.facts, MonotonicMillis(2))
                .unwrap(),
            DispatchDisposition::Existing(_)
        ),
        "retirement must not let old Core token produce another linear permit"
    );
    let interactive = auth
        .run(
            &adapter,
            spec(&root, "read line; printf '<%s>' \"$line\"", false),
        )
        .await;
    adapter
        .write_stdin(&owner, &interactive.handle, "你好\n".as_bytes())
        .await
        .unwrap();
    assert_eq!(
        drain(&adapter, &owner, &interactive.handle).await,
        ("<你好>".into(), 0)
    );
    adapter.retire(&owner, &interactive.handle).await.unwrap();
    let pty = auth
        .run(&adapter, spec(&root, "test -t 0 && printf PTY_OK", true))
        .await;
    assert_eq!(
        drain(&adapter, &owner, &pty.handle).await,
        ("PTY_OK".into(), 0)
    );
    adapter.retire(&owner, &pty.handle).await.unwrap();
    let utf8 = auth
        .run(
            &adapter,
            spec(
                &root,
                "printf '\\344\\275'; sleep 0.1; printf '\\240'",
                false,
            ),
        )
        .await;
    assert_eq!(
        drain(&adapter, &owner, &utf8.handle).await,
        ("你".into(), 0)
    );
    adapter.retire(&owner, &utf8.handle).await.unwrap();
    let late = auth
        .run(
            &adapter,
            spec(&root, "(sleep 0.15; printf LATE) & exit 0", false),
        )
        .await;
    assert_eq!(
        drain(&adapter, &owner, &late.handle).await,
        ("LATE".into(), 0)
    );
    adapter.retire(&owner, &late.handle).await.unwrap();
    let waiting = auth
        .run(&adapter, spec(&root, "printf WAIT_READY; read line", false))
        .await;
    let mut ready = String::new();
    for _ in 0..10 {
        let p = adapter
            .read(&owner, &waiting.handle, 100, Duration::from_millis(100))
            .await
            .unwrap();
        for c in p.chunks {
            ready.push_str(&c.text)
        }
        if ready.contains("WAIT_READY") {
            break;
        }
    }
    assert!(ready.contains("WAIT_READY"));
    // Native Codex serializes this long read's request dispatch. Launch the
    // independent process first, then verify its OS effect while its peer's
    // read reply times out. Do not invent concurrent RPC dispatch upstream.
    let survivor = auth
        .run(
            &adapter,
            spec(
                &root,
                "sleep 0.45; printf SURVIVED; printf exact > continued-effect.txt",
                false,
            ),
        )
        .await;
    assert_eq!(survivor.dispatch, DispatchEvidence::Started);
    assert_eq!(
        adapter
            .read(&owner, &waiting.handle, 100, Duration::from_secs(1))
            .await
            .unwrap_err(),
        ExecError::TimeoutUnknown
    );
    let effect_deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while !root.join("continued-effect.txt").exists()
        && tokio::time::Instant::now() < effect_deadline
    {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        std::fs::read_to_string(root.join("continued-effect.txt")).unwrap(),
        "exact"
    );
    // Give the original waitMs=1000 reply its bounded opportunity to arrive;
    // the timed-out waiter is gone, so the late response must be discarded.
    tokio::time::sleep(Duration::from_millis(650)).await;
    assert_eq!(
        drain(&adapter, &owner, &survivor.handle).await,
        ("SURVIVED".into(), 0)
    );
    adapter.retire(&owner, &survivor.handle).await.unwrap();
    // Preserve the original observed upstream queueing failure as a separate
    // measured scenario: start is sent once behind a long read, its ACK times
    // out, and its resource remains owner-bound for explicit reconciliation.
    assert_eq!(
        adapter
            .read(&owner, &waiting.handle, 100, Duration::from_secs(1))
            .await
            .unwrap_err(),
        ExecError::TimeoutUnknown
    );
    let queued_nonce = Uuid::new_v4().to_string();
    let mut queued_spec = spec(
        &root,
        "printf '%s' \"$1\" > queued-effect.txt; printf X >> queued-count.txt; printf QUEUED",
        false,
    );
    queued_spec
        .argv
        .extend(["r09-queued".into(), queued_nonce.clone()]);
    let (queued_permit, queued_id, queued_digest) = auth.issue(queued_spec);
    let queued = adapter.start(queued_permit).await.unwrap();
    let evidence_file = root.join("queued-start-unknown-reconciliation.json");
    let mut evidence = json!({"initialDispatch":format!("{:?}",queued.dispatch),"cause":format!("{:?}",queued.cause),"operation":queued_id,"processUuid":queued.handle.process_uuid(),"automaticReplay":false});
    std::fs::write(
        &evidence_file,
        serde_json::to_vec_pretty(&evidence).unwrap(),
    )
    .unwrap();
    assert_eq!(queued.dispatch, DispatchEvidence::Unknown);
    let queued_deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while !root.join("queued-effect.txt").exists() && tokio::time::Instant::now() < queued_deadline
    {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        std::fs::read_to_string(root.join("queued-effect.txt")).unwrap(),
        queued_nonce
    );
    assert_eq!(
        std::fs::read_to_string(root.join("queued-count.txt")).unwrap(),
        "X"
    );
    assert_eq!(
        adapter.lookup_operation(&owner, &queued_id).await.unwrap(),
        queued.handle
    );
    assert_eq!(
        drain(&adapter, &owner, &queued.handle).await,
        ("QUEUED".into(), 0)
    );
    adapter.retire(&owner, &queued.handle).await.unwrap();
    assert!(matches!(
        auth.ledger
            .dispatch(
                &owner,
                &queued_id,
                queued_digest,
                &auth.facts,
                MonotonicMillis(3)
            )
            .unwrap(),
        DispatchDisposition::Existing(_)
    ));
    evidence["nativeExitReadback"] = json!(0);
    evidence["independentNonce"] = json!(queued_nonce);
    evidence["appendCount"] = json!(1);
    evidence["retired"] = json!(true);
    evidence["oldCoreTokenRejected"] = json!(true);
    std::fs::write(
        &evidence_file,
        serde_json::to_vec_pretty(&evidence).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        adapter
            .cancel(&owner, &waiting.handle, Duration::from_secs(2))
            .await
            .unwrap(),
        TerminationEvidence::ProcessExited(_)
    ));
    let _ = drain(&adapter, &owner, &waiting.handle).await;
    adapter.retire(&owner, &waiting.handle).await.unwrap();
    let blocked = auth
        .run(&adapter, spec(&root, "printf '%s' $$; read line", false))
        .await;
    let mut pid = String::new();
    for _ in 0..10 {
        let p = adapter
            .read(&owner, &blocked.handle, 100, Duration::from_millis(100))
            .await
            .unwrap();
        for c in p.chunks {
            pid.push_str(&c.text)
        }
        if !pid.is_empty() {
            break;
        }
    }
    let native_pid = pid.trim().parse::<u32>().unwrap();
    assert!(matches!(
        adapter
            .cancel(&owner, &blocked.handle, Duration::from_secs(2))
            .await
            .unwrap(),
        TerminationEvidence::ProcessExited(_)
    ));
    let alive = std::process::Command::new("/bin/kill")
        .args(["-0", &native_pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(!alive.success());
    let cleanup = adapter.shutdown_owned(Duration::from_secs(5)).await;
    assert!(cleanup.executor_exited && cleanup.reader_task_reaped && cleanup.stderr_task_reaped);
    assert!(
        cleanup
            .processes
            .iter()
            .all(|(_, e)| matches!(e, TerminationEvidence::ProcessExited(_)))
    );
    println!(
        "Codex0.163 real native stdio complete batch PASS: nonce readback, owner denial, linear Core permit/no replay after retirement, low-capacity resource reuse, stdio exit7, PTY, write/read Unicode+split UTF8, delayed inherited output, local timeout with another process and file effect continuing, processExited+independent PID absent, executor and owned tasks reaped"
    );
}

fn fixture_adapter(
    owner: OwnerLease,
    operation: OperationId,
) -> (Arc<CodexStdio>, ProcessHandle, tokio::io::DuplexStream) {
    let (client, server) = tokio::io::duplex(65536);
    let (r, w) = tokio::io::split(client);
    let partition = Arc::new(
        Arc::new(tokio::sync::Semaphore::new(16 * 1024 * 1024))
            .try_acquire_many_owned(16 * 1024 * 1024)
            .unwrap(),
    );
    let rpc =
        Rpc::new_with_reserved_partition(w, r, Duration::from_millis(200), 4, partition.clone());
    let handle = ProcessHandle {
        process_id: Uuid::new_v4().to_string(),
        operation: operation.clone(),
    };
    rpc.register(&handle.process_id).unwrap();
    let resource = Arc::new(Resource {
        start_digest: Sha256Digest::of_bytes(b"fixture-start"),
        owner,
        handle: handle.clone(),
        state: Arc::new(tokio::sync::Mutex::new(Record {
            retired: false,
            read_mode: None,
            cursor: None,
            gaps: 0,
            decoder: OutputDecoder::default(),
            drained: false,
            input_unknown: None,
            last_exit: None,
        })),
    });
    let adapter = Arc::new(CodexStdio {
        _rpc_partition: partition,
        rpc,
        child: tokio::sync::Mutex::new(None),
        stderr_task: tokio::sync::Mutex::new(None),
        records: Mutex::new(HashMap::from([(handle.process_id.clone(), resource)])),
        actions: Mutex::new(BTreeMap::new()),
        operations: Mutex::new(BTreeMap::from([(operation, handle.clone())])),
        limit: 4,
        session_id: "fixture-session".into(),
        provider_id: "fixture-provider".into(),
        initialization: json!({"sessionId":"fixture-session","environmentInfo":{"providerId":"fixture-provider"}}),
    });
    (adapter, handle, server)
}
#[tokio::test]
async fn late_native_exit_updates_already_drained_output_without_replaying_read() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let mut auth = authority();
    let (_, id, _) = auth.issue(spec(&std::env::temp_dir(), "unused", false));
    let owner = auth.owner.clone();
    let (adapter, handle, server) = fixture_adapter(owner.clone(), id);
    let process = handle.process_id.clone();
    let worker = tokio::spawn(async move {
        let (r, mut w) = tokio::io::split(server);
        let mut lines = BufReader::new(r).lines();
        let q: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
        w.write_all(format!("{}\n",json!({"id":q["id"],"result":{"chunks":[],"nextSeq":2,"exited":false,"exitCode":null,"closed":true,"failure":null}})).as_bytes()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        w.write_all(format!("{}\n",json!({"method":"process/exited","params":{"processId":process,"seq":2,"exitCode":7}})).as_bytes()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;
    });
    let first = adapter
        .read(&owner, &handle, 100, Duration::ZERO)
        .await
        .unwrap();
    assert_eq!(first.drain, OutputDrain::Drained);
    assert_eq!(first.liveness, ExecutionLiveness::Unknown);
    assert_eq!(first.exit_code, None);
    tokio::time::sleep(Duration::from_millis(20)).await;
    let later = adapter
        .read(&owner, &handle, 100, Duration::ZERO)
        .await
        .unwrap();
    assert_eq!(later.liveness, ExecutionLiveness::Exited);
    assert_eq!(later.exit_code, Some(7));
    worker.await.unwrap();
}
#[tokio::test]
async fn dropped_stdin_call_keeps_unknown_and_cannot_dispatch_another_write() {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let mut auth = authority();
    let (_, id, _) = auth.issue(spec(&std::env::temp_dir(), "unused", false));
    let owner = auth.owner.clone();
    let (adapter, handle, server) = fixture_adapter(owner.clone(), id);
    let (seen, observed) = tokio::sync::oneshot::channel();
    let worker = tokio::spawn(async move {
        let (r, _w) = tokio::io::split(server);
        let mut lines = BufReader::new(r).lines();
        let q: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
        assert_eq!(q["method"], "process/write");
        let _ = seen.send(());
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(20), lines.next_line())
                .await
                .is_err(),
            "second write was emitted after unknown input"
        );
    });
    let (a, o, h) = (adapter.clone(), owner.clone(), handle.clone());
    let call = tokio::spawn(async move { a.write_stdin(&o, &h, b"one").await });
    observed.await.unwrap();
    call.abort();
    let _ = call.await;
    assert_eq!(
        adapter
            .write_stdin(&owner, &handle, b"two")
            .await
            .unwrap_err(),
        ExecError::InputUnknown
    );
    worker.await.unwrap();
}
#[tokio::test]
async fn cancelled_start_is_reconciled_by_owner_bound_operation_lookup() {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let mut auth = authority();
    let (_, id, _) = auth.issue(spec(&std::env::temp_dir(), "fixture-existing", false));
    let owner = auth.owner.clone();
    let (adapter, _handle, server) = fixture_adapter(owner.clone(), id);
    let (permit, start_id, _) = auth.issue(spec(&std::env::temp_dir(), "fixture-new", false));
    let (seen, observed) = tokio::sync::oneshot::channel();
    let worker = tokio::spawn(async move {
        let (r, _w) = tokio::io::split(server);
        let mut lines = BufReader::new(r).lines();
        let q: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
        assert_eq!(q["method"], "process/start");
        let _ = seen.send(q["params"]["processId"].as_str().unwrap().to_owned());
        tokio::time::sleep(Duration::from_millis(40)).await;
    });
    let a = adapter.clone();
    let call = tokio::spawn(async move { a.start(permit).await });
    let native_id = observed.await.unwrap();
    call.abort();
    let _ = call.await;
    assert_eq!(
        adapter
            .lookup_operation(&owner, &start_id)
            .await
            .unwrap()
            .process_uuid(),
        native_id
    );
    assert_eq!(
        adapter
            .lookup_operation(&auth.foreign, &start_id)
            .await
            .unwrap_err(),
        ExecError::OwnerMismatch
    );
    worker.await.unwrap();
}
#[tokio::test]
async fn cancellation_deadline_covers_resource_lock_and_known_exit_is_not_downgraded() {
    let mut auth = authority();
    let (_, id, _) = auth.issue(spec(&std::env::temp_dir(), "unused", false));
    let owner = auth.owner.clone();
    let (adapter, handle, _server) = fixture_adapter(owner.clone(), id);
    let mut lock = adapter.owned(&owner, &handle).await.unwrap();
    let began = tokio::time::Instant::now();
    assert_eq!(
        adapter
            .cancel(&owner, &handle, Duration::from_millis(25))
            .await
            .unwrap(),
        TerminationEvidence::Unknown
    );
    assert!(began.elapsed() < Duration::from_millis(150));
    lock.last_exit = Some(7);
    drop(lock);
    adapter.rpc.fail(ExecError::TransportLost);
    assert_eq!(
        adapter
            .cancel(&owner, &handle, Duration::from_millis(25))
            .await
            .unwrap(),
        TerminationEvidence::ProcessExited(7)
    );
}
#[tokio::test]
async fn shutdown_global_budget_does_not_wait_for_all_resource_locks_or_invent_reaped_tasks() {
    let mut auth = authority();
    let (_, id, _) = auth.issue(spec(&std::env::temp_dir(), "unused", false));
    let owner = auth.owner.clone();
    let (adapter, handle, server) = fixture_adapter(owner.clone(), id);
    let lock = adapter.owned(&owner, &handle).await.unwrap();
    let began = tokio::time::Instant::now();
    let cleanup = adapter.shutdown_owned(Duration::from_millis(25)).await;
    assert!(began.elapsed() < Duration::from_millis(150));
    assert_eq!(cleanup.processes[0].1, TerminationEvidence::Unknown);
    assert!(!cleanup.executor_exited);
    drop(lock);
    drop(server);
    let _ = adapter.shutdown_owned(Duration::from_millis(100)).await;
}

#[tokio::test]
async fn start_local_rejection_has_not_dispatched_proof_but_remote_error_remains_unknown() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let mut auth = authority();
    let (_, existing, _) = auth.issue(spec(&std::env::temp_dir(), "fixture", false));
    let (adapter, _handle, server) = fixture_adapter(auth.owner.clone(), existing);
    let (invalid, id, _) = auth.issue_payload(b"{}".to_vec());
    let failed = adapter.start(invalid).await.unwrap_err();
    assert_eq!(failed.evidence, DispatchEvidence::NotDispatched);
    assert_eq!(failed.error, ExecError::InvalidRequest);
    let settled = auth
        .ledger
        .record_executor_fact(
            &id,
            styx_core::operations::ExecutorFact::NotDispatched,
            MonotonicMillis(2),
        )
        .unwrap();
    assert_eq!(settled.liveness, ExecutionLiveness::NotStarted);
    let worker = tokio::spawn(async move {
        let (r, mut w) = tokio::io::split(server);
        let mut lines = BufReader::new(r).lines();
        let q: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
        assert_eq!(q["method"], "process/start");
        w.write_all(
            format!(
                "{}\n",
                json!({"id":q["id"],"error":{"code":-32600,"message":"executor generic error"}})
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
    });
    let (permit, id, _) = auth.issue(spec(&std::env::temp_dir(), "unused", false));
    let receipt = adapter.start(permit).await.unwrap();
    assert_eq!(receipt.dispatch, DispatchEvidence::Unknown);
    assert_eq!(receipt.cause, Some(ExecError::Rejected(-32600)));
    assert_eq!(
        adapter.lookup_operation(&auth.owner, &id).await.unwrap(),
        receipt.handle
    );
    worker.await.unwrap();
}

#[tokio::test]
#[ignore = "requires isolated STYX_TEST_CODEX and STYX_TEST_EXEC_ROOT; focused raw-page native scenario"]
async fn real_codex_raw_page_focused_scenario() {
    let binary = PathBuf::from(std::env::var("STYX_TEST_CODEX").unwrap());
    let root = PathBuf::from(std::env::var("STYX_TEST_EXEC_ROOT").unwrap())
        .join(Uuid::new_v4().to_string());
    std::fs::create_dir_all(root.join("codex-home")).unwrap();
    let adapter = Arc::new(
        CodexStdio::spawn_owned(OwnedExecutorConfig {
            binary,
            cwd: root.clone(),
            environment: BTreeMap::from([
                ("PATH".into(), "/usr/bin:/bin".into()),
                ("HOME".into(), root.display().to_string()),
                (
                    "CODEX_HOME".into(),
                    root.join("codex-home").display().to_string(),
                ),
            ]),
            rpc_timeout: Duration::from_secs(2),
            retained_process_limit: 2,
        })
        .await
        .unwrap(),
    );
    let worker_adapter = adapter.clone();
    // Panic isolation guarantees that the fixture still performs owned cleanup.
    let worker = tokio::spawn(async move {
        let adapter = worker_adapter;
        let mut auth = authority();
        let owner = auth.owner.clone();
        let started = auth.run(&adapter, spec(&root,
            "printf '\\344\\275'; read -r release; printf '\\240'; printf RAW_EFFECT > raw-effect; exit 7", false)).await;
        assert_eq!(started.dispatch, DispatchEvidence::Started);
        let handle = started.handle;
        assert_eq!(
            adapter
                .read_raw(&auth.foreign, &handle, None, 2, Duration::ZERO)
                .await
                .unwrap_err(),
            ExecError::OwnerMismatch
        );
        let mut first = None;
        for _ in 0..30 {
            let page = adapter
                .read_raw(&owner, &handle, None, 2, Duration::from_millis(20))
                .await
                .unwrap()
                .into_native();
            if !page["chunks"].as_array().unwrap().is_empty() {
                first = Some(page);
                break;
            }
        }
        let first = first.expect("initial native bytes must arrive while stdin is gated");
        assert_eq!(first["chunks"][0]["seq"], 1);
        assert_eq!(first["chunks"][0]["chunk"], "5L0=");
        assert!(!first["exited"].as_bool().unwrap());
        let repeat = adapter
            .read_raw(&owner, &handle, None, 2, Duration::ZERO)
            .await
            .unwrap()
            .into_native();
        assert_eq!(repeat, first, "same native readonly cursor before release");
        assert_eq!(
            adapter
                .read(&owner, &handle, 65536, Duration::ZERO)
                .await
                .unwrap_err(),
            ExecError::ReadModeMismatch
        );
        assert!(!root.join("raw-effect").exists());
        adapter
            .write_stdin(&owner, &handle, b"release\n")
            .await
            .unwrap();
        let mut pages = vec![first.clone(), repeat];
        let mut cursor = first["nextSeq"].as_u64().unwrap() - 1;
        let mut tail = vec![];
        let mut ended = false;
        for _ in 0..60 {
            let page = adapter
                .read_raw(
                    &owner,
                    &handle,
                    Some(cursor),
                    65536,
                    Duration::from_millis(20),
                )
                .await
                .unwrap()
                .into_native();
            for chunk in page["chunks"].as_array().unwrap() {
                tail.extend(STANDARD.decode(chunk["chunk"].as_str().unwrap()).unwrap());
            }
            cursor = page["nextSeq"].as_u64().unwrap() - 1;
            ended = page["closed"] == true
                && page["exited"] == true
                && page["chunks"].as_array().unwrap().is_empty();
            pages.push(page);
            if ended {
                break;
            }
        }
        assert!(ended, "native exit and empty closed page required");
        assert_eq!(tail, [0xa0]);
        assert_eq!(
            std::fs::read(root.join("raw-effect")).unwrap(),
            b"RAW_EFFECT"
        );
        assert_eq!(pages.last().unwrap()["exitCode"], 7);
        // Even after settled EOF, the raw API must return an actual earlier
        // native page, never the decoded API's synthesized empty drained page.
        let historical = adapter
            .read_raw(&owner, &handle, None, 65536, Duration::ZERO)
            .await
            .unwrap()
            .into_native();
        assert!(!historical["chunks"].as_array().unwrap().is_empty());
        assert_eq!(historical["chunks"][0]["chunk"], "5L0=");
        pages.push(historical);
        assert_eq!(
            adapter
                .read(&owner, &handle, 1, Duration::ZERO)
                .await
                .unwrap_err(),
            ExecError::ReadModeMismatch
        );
        adapter.retire(&owner, &handle).await.unwrap();
        let decoded = auth
            .run(&adapter, spec(&root, "printf DECODED; exit 0", false))
            .await;
        assert_eq!(
            drain(&adapter, &owner, &decoded.handle).await,
            ("DECODED".into(), 0)
        );
        assert_eq!(
            adapter
                .read_raw(&owner, &decoded.handle, None, 65536, Duration::ZERO)
                .await
                .unwrap_err(),
            ExecError::ReadModeMismatch
        );
        adapter.retire(&owner, &decoded.handle).await.unwrap();
        println!(
            "RAW_NATIVE_OBSERVATION {}",
            json!({"root":root,"pages":pages,"foreignOwnerDenied":true,"bothModeDirectionsDenied":true,"independentEffect":"RAW_EFFECT","nativeExit":7})
        );
    });
    let outcome = worker.await;
    let cleanup = adapter.shutdown_owned(Duration::from_secs(5)).await;
    println!("RAW_CLEANUP {:?}", cleanup);
    assert!(cleanup.executor_exited && cleanup.reader_task_reaped && cleanup.stderr_task_reaped);
    outcome.unwrap();
}

#[tokio::test]
async fn raw_pages_preserve_failure_extensions_and_cancelled_read_mode() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let mut auth = authority();
    let (_, id, _) = auth.issue(spec(&std::env::temp_dir(), "unused", false));
    let (adapter, handle, server) = fixture_adapter(auth.owner.clone(), id);
    let native = json!({"chunks":[],"nextSeq":1,"exited":false,"closed":false,"failure":{"code":"native_failure"},"extension":{"kept":true}});
    let expected = native.clone();
    let worker = tokio::spawn(async move {
        let (r, mut w) = tokio::io::split(server);
        let mut lines = BufReader::new(r).lines();
        let request: Value =
            serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
        assert_eq!(request["params"]["afterSeq"], 0);
        // The first read is cancelled without receiving a page. Its mode must
        // already be irrevocably selected, independent of response success.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let request: Value =
            serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
        assert_eq!(request["params"]["afterSeq"], 0);
        w.write_all(format!("{}\n", json!({"id":request["id"],"result":native})).as_bytes())
            .await
            .unwrap();
    });
    assert_eq!(
        adapter
            .read(&auth.owner, &handle, 0, Duration::ZERO)
            .await
            .unwrap_err(),
        ExecError::InvalidRequest
    );
    let pending = adapter.read_raw(&auth.owner, &handle, Some(0), 1, Duration::ZERO);
    assert!(
        tokio::time::timeout(Duration::from_millis(10), pending)
            .await
            .is_err()
    );
    assert_eq!(
        adapter
            .read(&auth.owner, &handle, 1, Duration::ZERO)
            .await
            .unwrap_err(),
        ExecError::ReadModeMismatch
    );
    assert_eq!(
        adapter
            .read_raw(&auth.owner, &handle, Some(0), 1, Duration::ZERO)
            .await
            .unwrap()
            .into_native(),
        expected
    );
    worker.await.unwrap();
}

#[tokio::test]
async fn targeted_action_permit_cannot_start_another_process_even_with_valid_start_bytes() {
    // Isolated protocol fixture, not a native process acceptance claim.
    let mut auth = authority();
    let start_spec = spec(std::path::Path::new("/tmp"), "printf forbidden", false);
    let (_original_permit, parent, digest) = auth.issue(start_spec.clone());
    let (adapter, _, mut native_peer) = fixture_adapter(auth.owner.clone(), parent.clone());
    let action = auth
        .ledger
        .prepare_targeted(
            &auth.owner,
            ResourceTarget {
                operation_id: parent,
                payload_digest: digest,
            },
            PreparedContext {
                device_id: auth.facts.device_id.clone(),
                grant_revision: 1,
                session: None,
                observation: None,
                capability: CapabilityId::ExecRun,
                deadline: MonotonicMillis(100000),
                disconnect_policy: DisconnectPolicy::RetainForOwner,
            },
            start_spec.to_operation_payload().unwrap(),
            MonotonicMillis(2),
        )
        .unwrap();
    let DispatchDisposition::ExecuteOnce(permit) = auth
        .ledger
        .dispatch(
            &auth.owner,
            &action.id,
            action.payload_digest,
            &auth.facts,
            MonotonicMillis(3),
        )
        .unwrap()
    else {
        panic!("new targeted permit required")
    };
    let refused = adapter.start(permit).await.unwrap_err();
    assert_eq!(refused.operation, action.id);
    assert_eq!(refused.evidence, DispatchEvidence::NotDispatched);
    assert_eq!(refused.error, ExecError::InvalidRequest);
    assert_eq!(
        adapter.lookup_operation(&auth.owner, &action.id).await,
        Err(ExecError::UnknownHandle)
    );
    use tokio::io::AsyncReadExt;
    assert!(
        tokio::time::timeout(Duration::from_millis(20), native_peer.read_u8())
            .await
            .is_err()
    );
    // Close the fixture's owned peer before requesting normal reader cleanup.
    // Keeping a silent fake peer open would spend the entire shutdown budget
    // waiting for its deliberately absent terminate response.
    drop(native_peer);
    let cleanup = adapter.shutdown_owned(Duration::from_secs(1)).await;
    assert!(cleanup.reader_task_reaped);
}

impl Authority {
    fn action(
        &mut self,
        handle: &ProcessHandle,
        digest: Sha256Digest,
        action: &ProcessAction,
    ) -> (DispatchPermit, OperationSnapshot) {
        let snapshot = self
            .ledger
            .prepare_targeted(
                &self.owner,
                ResourceTarget {
                    operation_id: handle.operation.clone(),
                    payload_digest: digest,
                },
                PreparedContext {
                    device_id: self.facts.device_id.clone(),
                    grant_revision: 1,
                    session: None,
                    observation: None,
                    capability: CapabilityId::ExecRun,
                    deadline: MonotonicMillis(100000),
                    disconnect_policy: DisconnectPolicy::RetainForOwner,
                },
                action.to_operation_payload().unwrap(),
                MonotonicMillis(2),
            )
            .unwrap();
        let DispatchDisposition::ExecuteOnce(permit) = self
            .ledger
            .dispatch(
                &self.owner,
                &snapshot.id,
                snapshot.payload_digest,
                &self.facts,
                MonotonicMillis(3),
            )
            .unwrap()
        else {
            panic!("fresh action permit")
        };
        (permit, snapshot)
    }
}
fn write_action(bytes: &[u8]) -> ProcessAction {
    ProcessAction::WriteStdin {
        input_base64: STANDARD.encode(bytes),
    }
}
fn bind_fixture_digest(adapter: &CodexStdio, handle: &ProcessHandle, digest: Sha256Digest) {
    let mut records = adapter.records.lock().unwrap();
    Arc::get_mut(records.get_mut(&handle.process_id).unwrap())
        .unwrap()
        .start_digest = digest;
}
#[tokio::test]
async fn continuation_target_owner_kind_and_digest_refuse_without_any_native_io() {
    use tokio::io::AsyncReadExt;
    let mut auth = authority();
    let (_, id, digest) = auth.issue(spec(&std::env::temp_dir(), "unused", false));
    let (adapter, handle, mut server) = fixture_adapter(auth.owner.clone(), id);
    bind_fixture_digest(&adapter, &handle, digest);
    let (permit, _) = auth.action(&handle, digest, &write_action(b"MUST_NOT_SEND"));
    let refused = adapter.terminate(permit, &handle).await;
    assert_eq!(refused.evidence, ActionEvidence::NotDispatched);
    assert_eq!(refused.cause, Some(ExecError::InvalidRequest));
    let (_, different, _) = auth.issue(spec(&std::env::temp_dir(), "different", false));
    let mut false_handle = handle.clone();
    false_handle.operation = different;
    let (permit, _) = auth.action(&handle, digest, &write_action(b"MUST_NOT_SEND"));
    assert_eq!(
        adapter.write(permit, &false_handle).await.cause,
        Some(ExecError::OwnerMismatch)
    );
    // Same opaque handle, mismatched original-start digest must also reject.
    bind_fixture_digest(&adapter, &handle, Sha256Digest::of_bytes(b"substituted"));
    let (permit, _) = auth.action(&handle, digest, &write_action(b"MUST_NOT_SEND"));
    assert_eq!(
        adapter.write(permit, &handle).await.cause,
        Some(ExecError::InvalidRequest)
    );
    bind_fixture_digest(&adapter, &handle, digest);
    let (permit, _) = auth.action(&handle, digest, &write_action(b"MUST_NOT_SEND"));
    {
        let mut records = adapter.records.lock().unwrap();
        Arc::get_mut(records.get_mut(&handle.process_id).unwrap())
            .unwrap()
            .owner = auth.foreign.clone();
    }
    assert_eq!(
        adapter.write(permit, &handle).await.cause,
        Some(ExecError::OwnerMismatch)
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(20), server.read_u8())
            .await
            .is_err()
    );
    assert_eq!(adapter.actions.lock().unwrap().len(), 0);
    let printed = format!("{:?}", write_action(b"PRIVATE_INPUT"));
    assert!(!printed.contains("PRIVATE_INPUT"));
    assert!(!printed.contains(&STANDARD.encode(b"PRIVATE_INPUT")));
}
#[tokio::test]
async fn continuation_dropped_write_retains_exact_action_write_id_and_never_replays() {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let mut auth = authority();
    let (_, id, digest) = auth.issue(spec(&std::env::temp_dir(), "unused", false));
    let owner = auth.owner.clone();
    let (adapter, handle, server) = fixture_adapter(owner.clone(), id);
    bind_fixture_digest(&adapter, &handle, digest);
    let (permit, snapshot) = auth.action(&handle, digest, &write_action(b"ONCE"));
    let (seen, observed) = tokio::sync::oneshot::channel();
    let worker = tokio::spawn(async move {
        let (r, _w) = tokio::io::split(server);
        let mut lines = BufReader::new(r).lines();
        let q: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
        assert_eq!(q["method"], "process/write");
        seen.send(q).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(80), lines.next_line())
                .await
                .is_err()
        );
    });
    let (a, h) = (adapter.clone(), handle.clone());
    let pending = tokio::spawn(async move { a.write(permit, &h).await });
    let frame = observed.await.unwrap();
    pending.abort();
    let _ = pending.await;
    let receipt = adapter.lookup_action(&owner, &snapshot.id).unwrap();
    assert_eq!(receipt.evidence, ActionEvidence::Unknown);
    assert_eq!(
        receipt.write_id.as_deref(),
        frame["params"]["writeId"].as_str()
    );
    assert_eq!(
        adapter.owned(&owner, &handle).await.unwrap().input_unknown,
        Some(snapshot.id.clone())
    );
    assert_eq!(
        adapter
            .lookup_action(&auth.foreign, &snapshot.id)
            .unwrap_err(),
        ExecError::OwnerMismatch
    );
    let (permit, _) = auth.action(&handle, digest, &write_action(b"MUST_NOT_SEND"));
    let refused = adapter.write(permit, &handle).await;
    assert_eq!(refused.evidence, ActionEvidence::NotDispatched);
    assert_eq!(refused.cause, Some(ExecError::InputUnknown));
    assert_eq!(
        adapter
            .lookup_action(&owner, &snapshot.id)
            .unwrap()
            .write_id,
        receipt.write_id
    );
    assert!(matches!(
        auth.ledger
            .dispatch(
                &owner,
                &snapshot.id,
                snapshot.payload_digest,
                &auth.facts,
                MonotonicMillis(4)
            )
            .unwrap(),
        DispatchDisposition::Existing(_)
    ));
    {
        let mut record = adapter.owned(&owner, &handle).await.unwrap();
        record.last_exit = Some(0);
        record.drained = true;
    }
    assert_eq!(
        adapter.retire(&owner, &handle).await.unwrap_err(),
        ExecError::ResourceUnsettled
    );
    worker.await.unwrap();
}
#[tokio::test]
async fn continuation_terminate_ack_is_not_process_exit_or_drain() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let mut auth = authority();
    let (_, id, digest) = auth.issue(spec(&std::env::temp_dir(), "unused", false));
    let (adapter, handle, server) = fixture_adapter(auth.owner.clone(), id);
    bind_fixture_digest(&adapter, &handle, digest);
    let (permit, action) = auth.action(&handle, digest, &ProcessAction::Terminate {});
    let worker = tokio::spawn(async move {
        let (r, mut w) = tokio::io::split(server);
        let mut lines = BufReader::new(r).lines();
        let q: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
        assert_eq!(q["method"], "process/terminate");
        w.write_all(format!("{}\n", json!({"id":q["id"],"result":{"running":true}})).as_bytes())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
    });
    let before = auth
        .ledger
        .inspect(&auth.owner, &handle.operation, digest)
        .unwrap();
    let receipt = adapter.terminate(permit, &handle).await;
    assert_eq!(receipt.evidence, ActionEvidence::Acknowledged);
    assert_eq!(
        receipt.acknowledgment,
        Some(ActionAcknowledgment::TerminateRequested { was_running: true })
    );
    auth.ledger
        .record_action_result(
            &action.id,
            styx_core::operations::ActionResult::Acknowledged,
            MonotonicMillis(4),
        )
        .unwrap();
    assert_eq!(
        auth.ledger
            .inspect(&auth.owner, &handle.operation, digest)
            .unwrap(),
        before
    );
    let state = adapter.owned(&auth.owner, &handle).await.unwrap();
    assert_eq!(state.last_exit, None);
    assert!(!state.drained);
    drop(state);
    assert_eq!(
        adapter.retire(&auth.owner, &handle).await.unwrap_err(),
        ExecError::ResourceUnsettled
    );
    worker.await.unwrap();
}
#[tokio::test]
async fn continuation_local_metadata_is_bounded_and_survives_resource_retirement() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let mut auth = authority();
    let (_, id, digest) = auth.issue(spec(&std::env::temp_dir(), "unused", false));
    let (adapter, handle, server) = fixture_adapter(auth.owner.clone(), id);
    bind_fixture_digest(&adapter, &handle, digest);
    let worker = tokio::spawn(async move {
        let (r, mut w) = tokio::io::split(server);
        let mut lines = BufReader::new(r).lines();
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..256 {
            let q: Value =
                serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
            assert_eq!(q["method"], "process/write");
            assert!(seen.insert(q["params"]["writeId"].as_str().unwrap().to_owned()));
            w.write_all(
                format!("{}\n", json!({"id":q["id"],"result":{"status":"accepted"}})).as_bytes(),
            )
            .await
            .unwrap();
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(20), lines.next_line())
                .await
                .is_err()
        );
    });
    let mut last = None;
    for _ in 0..256 {
        let (permit, a) = auth.action(&handle, digest, &write_action(b"x"));
        assert_eq!(
            adapter.write(permit, &handle).await.evidence,
            ActionEvidence::Acknowledged
        );
        last = Some(a.id);
    }
    let (permit, _) = auth.action(&handle, digest, &write_action(b"MUST_NOT_SEND"));
    let receipt = adapter.write(permit, &handle).await;
    assert_eq!(receipt.evidence, ActionEvidence::NotDispatched);
    assert_eq!(receipt.cause, Some(ExecError::Capacity));
    {
        let mut r = adapter.owned(&auth.owner, &handle).await.unwrap();
        r.last_exit = Some(0);
        r.drained = true;
    }
    adapter.retire(&auth.owner, &handle).await.unwrap();
    assert_eq!(adapter.actions.lock().unwrap().len(), 256);
    // Defensive producer-reconstruction control, not a claim that clients can
    // create a Core permit or that a real Host may reuse its generation.
    let mut reconstructed = authority();
    let (_, parent, old_digest) = reconstructed.issue(spec(&std::env::temp_dir(), "unused", false));
    assert_eq!(parent, handle.operation);
    let (duplicate, _) = reconstructed.action(&handle, old_digest, &write_action(b"x"));
    let refused = adapter.write(duplicate, &handle).await;
    assert_eq!(refused.cause, Some(ExecError::AlreadyDispatched));
    assert_eq!(refused.evidence, ActionEvidence::Acknowledged);
    assert_eq!(
        refused.acknowledgment,
        Some(ActionAcknowledgment::WriteAccepted)
    );
    assert_eq!(
        adapter
            .lookup_action(&auth.owner, &refused.operation)
            .unwrap()
            .write_id,
        refused.write_id
    );
    assert!(refused.write_id.is_some());
    assert_eq!(
        adapter
            .lookup_action(&auth.owner, &last.unwrap())
            .unwrap()
            .evidence,
        ActionEvidence::Acknowledged
    );
    worker.await.unwrap();
}
#[tokio::test]
async fn externally_reserved_rpc_partition_outlives_helper_and_reader_cleanup() {
    let budget = Arc::new(tokio::sync::Semaphore::new(16 * 1024 * 1024));
    let (client, server) = tokio::io::duplex(128);
    let (r, w) = tokio::io::split(client);
    let partition = Arc::new(
        budget
            .clone()
            .try_acquire_many_owned(16 * 1024 * 1024)
            .unwrap(),
    );
    let rpc =
        Rpc::new_with_reserved_partition(w, r, Duration::from_millis(100), 1, partition.clone());
    drop(partition);
    drop(rpc); // reader still waiting on its owned stdout
    assert_eq!(budget.available_permits(), 0);
    drop(server);
    tokio::time::timeout(Duration::from_secs(1), async {
        while budget.available_permits() != 16 * 1024 * 1024 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires isolated STYX_TEST_CODEX/STYX_TEST_EXEC_ROOT; focused permit stdin/terminate/unknown only"]
async fn real_codex_continuation_permit_focused_scenario() {
    let binary = PathBuf::from(std::env::var("STYX_TEST_CODEX").unwrap());
    let root = PathBuf::from(std::env::var("STYX_TEST_EXEC_ROOT").unwrap())
        .join(Uuid::new_v4().to_string());
    std::fs::create_dir_all(root.join("codex-home")).unwrap();
    let global = Arc::new(tokio::sync::Semaphore::new(64 * 1024 * 1024));
    let partition = global
        .clone()
        .try_acquire_many_owned(16 * 1024 * 1024)
        .unwrap();
    let adapter = Arc::new(
        CodexStdio::spawn_owned_with_reserved_budget(
            OwnedExecutorConfig {
                binary,
                cwd: root.clone(),
                environment: BTreeMap::from([
                    ("PATH".into(), "/usr/bin:/bin".into()),
                    ("HOME".into(), root.display().to_string()),
                    (
                        "CODEX_HOME".into(),
                        root.join("codex-home").display().to_string(),
                    ),
                ]),
                rpc_timeout: Duration::from_millis(300),
                retained_process_limit: 4,
            },
            partition,
        )
        .await
        .unwrap(),
    );
    assert_eq!(global.available_permits(), 48 * 1024 * 1024);
    let a = adapter.clone();
    let worker = tokio::spawn(async move {
        let adapter = a;
        let mut auth = authority();
        let owner = auth.owner.clone();
        let process_spec = spec(
            &root,
            "read -r line; printf '%s\\n' \"$line\" >> stdin-effect; printf ACK; read -r hold",
            false,
        );
        let digest = Sha256Digest::of_bytes(&process_spec.to_operation_payload().unwrap());
        let process = auth.run(&adapter, process_spec).await;
        assert_eq!(process.dispatch, DispatchEvidence::Started);
        let handle = process.handle;
        let nonce = Uuid::new_v4().to_string();
        let (permit, action) = auth.action(
            &handle,
            digest,
            &write_action(format!("{nonce}\n").as_bytes()),
        );
        let receipt = adapter.write(permit, &handle).await;
        assert_eq!(receipt.evidence, ActionEvidence::Acknowledged);
        assert_eq!(
            receipt.acknowledgment,
            Some(ActionAcknowledgment::WriteAccepted)
        );
        auth.ledger
            .record_action_result(
                &action.id,
                styx_core::operations::ActionResult::Acknowledged,
                MonotonicMillis(4),
            )
            .unwrap();
        assert!(matches!(
            auth.ledger
                .dispatch(
                    &owner,
                    &action.id,
                    action.payload_digest,
                    &auth.facts,
                    MonotonicMillis(5)
                )
                .unwrap(),
            DispatchDisposition::Existing(_)
        ));
        let page = adapter
            .read(&owner, &handle, 65536, Duration::from_millis(50))
            .await
            .unwrap();
        assert_eq!(page.liveness, ExecutionLiveness::Running);
        assert_eq!(page.exit_code, None);
        assert_eq!(
            page.chunks
                .iter()
                .map(|c| c.text.as_str())
                .collect::<String>(),
            "ACK"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("stdin-effect")).unwrap(),
            format!("{nonce}\n")
        );
        let original = auth
            .ledger
            .inspect(&owner, handle.operation(), digest)
            .unwrap();
        let (permit, terminate_action) = auth.action(&handle, digest, &ProcessAction::Terminate {});
        let termination_request = adapter.terminate(permit, &handle).await;
        println!("NATIVE_TERMINATE_REQUEST {:?}", termination_request);
        assert_eq!(termination_request.evidence, ActionEvidence::Acknowledged);
        auth.ledger
            .record_action_result(
                &terminate_action.id,
                styx_core::operations::ActionResult::Acknowledged,
                MonotonicMillis(6),
            )
            .unwrap();
        assert_eq!(
            auth.ledger
                .inspect(&owner, handle.operation(), digest)
                .unwrap(),
            original
        );
        assert_eq!(
            adapter.owned(&owner, &handle).await.unwrap().last_exit,
            None,
            "request ACK never sets exit"
        );
        let (_, exit) = drain(&adapter, &owner, &handle).await;
        adapter.retire(&owner, &handle).await.unwrap();
        assert_eq!(
            adapter.lookup_action(&owner, &action.id).unwrap().write_id,
            receipt.write_id
        );

        let process_spec = spec(
            &root,
            "read -r line; printf '%s\\n' \"$line\" >> uncertain-effect; printf LATE_ACK; read -r hold",
            false,
        );
        let digest = Sha256Digest::of_bytes(&process_spec.to_operation_payload().unwrap());
        let process = auth.run(&adapter, process_spec).await;
        assert_eq!(process.dispatch, DispatchEvidence::Started);
        let handle = process.handle;
        let (aa, oo, hh) = (adapter.clone(), owner.clone(), handle.clone());
        // Upstream stdio serializes this long native wait ahead of the write.
        let read = tokio::spawn(async move {
            aa.read_raw(&oo, &hh, None, 65536, Duration::from_secs(1))
                .await
        });
        tokio::time::sleep(Duration::from_millis(40)).await;
        let unknown_nonce = Uuid::new_v4().to_string();
        let (permit, unknown_action) = auth.action(
            &handle,
            digest,
            &write_action(format!("{unknown_nonce}\n").as_bytes()),
        );
        let unknown = adapter.write(permit, &handle).await;
        assert_eq!(unknown.evidence, ActionEvidence::Unknown);
        auth.ledger
            .record_action_result(
                &unknown_action.id,
                styx_core::operations::ActionResult::Unknown,
                MonotonicMillis(7),
            )
            .unwrap();
        assert_eq!(read.await.unwrap().unwrap_err(), ExecError::TimeoutUnknown);
        tokio::time::timeout(Duration::from_secs(3), async {
            while std::fs::read_to_string(root.join("uncertain-effect")).ok()
                != Some(format!("{unknown_nonce}\n"))
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(root.join("uncertain-effect")).unwrap(),
            format!("{unknown_nonce}\n")
        );
        let (permit, _) = auth.action(&handle, digest, &write_action(b"NO_REPLAY\n"));
        let blocked = adapter.write(permit, &handle).await;
        assert_eq!(blocked.evidence, ActionEvidence::NotDispatched);
        assert_eq!(blocked.cause, Some(ExecError::InputUnknown));
        assert_eq!(
            adapter
                .lookup_action(&owner, &unknown_action.id)
                .unwrap()
                .write_id,
            unknown.write_id
        );
        assert_eq!(
            adapter.owned(&owner, &handle).await.unwrap().input_unknown,
            Some(unknown_action.id.clone())
        );
        let (permit, _) = auth.action(&handle, digest, &ProcessAction::Terminate {});
        let terminated = adapter.terminate(permit, &handle).await;
        assert_eq!(terminated.evidence, ActionEvidence::Acknowledged);
        let mut cursor = None;
        let mut ended = false;
        for _ in 0..60 {
            let page = adapter
                .read_raw(&owner, &handle, cursor, 65536, Duration::from_millis(20))
                .await
                .unwrap()
                .into_native();
            cursor = page["nextSeq"].as_u64().map(|s| s - 1);
            ended = page["closed"] == true
                && page["exited"] == true
                && page["chunks"].as_array().unwrap().is_empty();
            if ended {
                break;
            }
        }
        assert!(ended);
        assert_eq!(
            adapter.retire(&owner, &handle).await.unwrap_err(),
            ExecError::ResourceUnsettled
        );
        assert_eq!(
            auth.ledger
                .inspect(&owner, &unknown_action.id, unknown_action.payload_digest)
                .unwrap()
                .state,
            OperationState::Unknown
        );
        assert_eq!(
            std::fs::read_to_string(root.join("uncertain-effect")).unwrap(),
            format!("{unknown_nonce}\n")
        );
        println!(
            "NATIVE_CONTINUATION_OBSERVATION {}",
            json!({"root":root,"stdinEffect":nonce,"stdinCount":1,"nativeExitAfterRead":exit,
            "ackWriteId":receipt.write_id,"unknownAction":unknown_action.id,"unknownWriteId":unknown.write_id,"unknownEffect":unknown_nonce,"unknownEffectCount":1,
            "unknownPreservedAfterTargetExitDrain":true,"forceArchiveUsed":false,"metadataSurvivedRetire":true})
        );
    });
    let outcome = worker.await;
    let cleanup = adapter.shutdown_owned(Duration::from_secs(5)).await;
    println!("NATIVE_CONTINUATION_CLEANUP {:?}", cleanup);
    assert!(cleanup.executor_exited && cleanup.reader_task_reaped && cleanup.stderr_task_reaped);
    drop(adapter);
    assert_eq!(
        global.available_permits(),
        64 * 1024 * 1024,
        "budget returns only after owned execution/reader/stderr/resource lifetime ends"
    );
    outcome.unwrap();
}

/// Mock stdio/control-boundary regression only; never a native Codex claim.
#[tokio::test]
async fn archival_strict_not_sent_related_unknown_uuid_and_negative_bundle_batch() {
    use styx_core::operations::{ActionResult, ExecutorFact};
    use tokio::io::AsyncReadExt;
    for case in 0..3 {
        let mut auth = authority();
        let (start_permit, start, digest) =
            auth.issue(spec(&std::env::temp_dir(), "never dispatched", false));
        let (adapter, placeholder, mut peer) = fixture_adapter(auth.owner.clone(), start.clone());
        adapter.discard_unstarted(&placeholder);
        // Mock-only transport backpressure occupies the private RPC writer.
        // It emits partial fixture-control bytes, never a process action frame.
        let barrier_method = "fixture_writer_barrier".repeat(4096);
        let mut writer_barrier = Box::pin(adapter.rpc.notify(&barrier_method));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut writer_barrier)
                .await
                .is_err()
        );
        let starter = adapter.clone();
        let starting = tokio::spawn(async move { starter.start(start_permit).await });
        let handle = tokio::time::timeout(Duration::from_millis(100), async {
            loop {
                if let Ok(handle) = adapter.lookup_operation(&auth.owner, &start).await {
                    break handle;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let resource_guard = adapter.owned(&auth.owner, &handle).await.unwrap();
        let (permit, action) = auth.action(&handle, digest, &write_action(b"MUST_NOT_SEND"));
        let (sender, owned_handle) = (adapter.clone(), handle.clone());
        let pending = tokio::spawn(async move { sender.write(permit, &owned_handle).await });
        let receipt = tokio::time::timeout(Duration::from_millis(100), async {
            loop {
                if let Ok(receipt) = adapter.lookup_action(&auth.owner, &action.id) {
                    break receipt;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        pending.abort();
        assert!(pending.await.unwrap_err().is_cancelled());
        assert_eq!(receipt.evidence, ActionEvidence::Unknown);
        assert!(receipt.write_id.is_some());
        assert!(resource_guard.input_unknown.is_none()); // Wait was before the first native write.
        drop(resource_guard);
        let unknown = auth
            .ledger
            .record_action_result(&action.id, ActionResult::Unknown, MonotonicMillis(4))
            .unwrap();
        let audit_before = adapter.action_audit(&receipt).unwrap();
        let parsed: Value = serde_json::from_slice(&audit_before).unwrap();
        assert_eq!(
            parsed["native_process_uuid"].as_str(),
            Some(handle.process_id.as_str())
        );
        assert_eq!(parsed["write_id"].as_str(), receipt.write_id.as_deref());
        adapter.rpc.fail(ExecError::TransportLost);
        drop(writer_barrier);
        let failure = starting.await.unwrap().unwrap_err();
        assert_eq!(failure.evidence, DispatchEvidence::NotDispatched);
        assert_eq!(failure.error, ExecError::NotSent);
        auth.ledger
            .record_executor_fact(&start, ExecutorFact::NotDispatched, MonotonicMillis(5))
            .unwrap();
        assert!(adapter.records.lock().unwrap().is_empty());
        assert!(adapter.operations.lock().unwrap().is_empty());
        assert_eq!(adapter.action_audit(&receipt).unwrap(), audit_before);
        let audit = if case == 2 {
            b"bad audit must not authorize deletion".to_vec()
        } else {
            audit_before.clone()
        };
        auth.ledger
            .record_provider_audit(&action.id, audit)
            .unwrap();
        if case == 1 {
            let mut extra = receipt.clone();
            extra.operation.sequence += 10000;
            adapter.actions.lock().unwrap().insert(
                extra.operation.clone(),
                continuation::StoredAction {
                    native_process_uuid: handle.process_id.clone(),
                    owner: auth.owner.clone(),
                    payload_digest: action.payload_digest,
                    receipt: extra,
                },
            );
        }
        let target = ResourceTarget {
            operation_id: start.clone(),
            payload_digest: digest,
        };
        let permit = auth.ledger.begin_resource_release(&target).unwrap();
        assert_eq!(permit.actions().len(), 1);
        assert_eq!(permit.actions()[0].snapshot(), &unknown);
        let result =
            tokio::time::timeout(Duration::from_millis(100), adapter.release_resource(permit))
                .await
                .unwrap();
        if case == 0 {
            auth.ledger
                .record_provider_release(result.unwrap())
                .unwrap();
            assert!(adapter.actions.lock().unwrap().is_empty());
            assert_eq!(auth.ledger.unreleased_provider_records(), 0);
            assert_eq!(
                auth.ledger.provider_audit(&action.id),
                Some(audit_before.as_slice())
            );
        } else {
            assert_eq!(
                result.unwrap_err(),
                if case == 1 {
                    ExecError::ResourceUnsettled
                } else {
                    ExecError::InvalidFrame
                }
            );
            assert_eq!(
                adapter.actions.lock().unwrap().len(),
                if case == 1 { 2 } else { 1 }
            );
            assert_eq!(auth.ledger.unreleased_provider_records(), 2);
            assert_eq!(auth.ledger.reap(MonotonicMillis(1_000_000)), 0);
        }
        assert_eq!(
            auth.ledger
                .inspect(&auth.owner, &action.id, action.payload_digest)
                .unwrap(),
            unknown
        );
        assert!(matches!(
            adapter.owned(&auth.owner, &handle).await,
            Err(ExecError::UnknownHandle)
        ));
        let mut wire = Vec::new();
        loop {
            let mut bytes = [0u8; 8192];
            match tokio::time::timeout(Duration::from_millis(10), peer.read(&mut bytes)).await {
                Ok(Ok(n)) if n > 0 => wire.extend_from_slice(&bytes[..n]),
                Err(_) => break,
                other => panic!("unexpected mock peer state: {other:?}"),
            }
        }
        assert!(!wire.is_empty());
        let wire = std::str::from_utf8(&wire).unwrap();
        assert!(wire.contains("fixture_writer_barrier"));
        assert!(!wire.contains("process/start"));
        assert!(!wire.contains("process/write"));
        drop(peer);
        let cleanup = adapter.shutdown_owned(Duration::from_secs(1)).await;
        assert!(cleanup.processes.is_empty());
        assert!(cleanup.reader_task_reaped);
        assert!(cleanup.stderr_task_reaped);
        assert!(adapter.rpc.observation(&handle.process_id).is_none());
    }
}
