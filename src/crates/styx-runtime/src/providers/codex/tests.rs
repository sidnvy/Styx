use super::*;
use styx_contracts::identity::*;
use styx_contracts::{capability::*, error::Recovery, operation::*};
use styx_core::{
    operations::{DispatchDisposition, DispatchPermit, OperationLedger},
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
    let rpc = Rpc::new(w, r, Duration::from_millis(200), 4);
    let handle = ProcessHandle {
        process_id: Uuid::new_v4().to_string(),
        operation: operation.clone(),
    };
    rpc.register(&handle.process_id).unwrap();
    let resource = Arc::new(Resource {
        owner,
        handle: handle.clone(),
        state: Arc::new(tokio::sync::Mutex::new(Record {
            cursor: None,
            gaps: 0,
            decoder: OutputDecoder::default(),
            drained: false,
            input_unknown: false,
            last_exit: None,
        })),
    });
    let adapter = Arc::new(CodexStdio {
        rpc,
        child: tokio::sync::Mutex::new(None),
        stderr_task: tokio::sync::Mutex::new(None),
        records: Mutex::new(HashMap::from([(handle.process_id.clone(), resource)])),
        operations: Mutex::new(BTreeMap::from([(operation, handle.clone())])),
        limit: 4,
        session_id: "fixture-session".into(),
        provider_id: "fixture-provider".into(),
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
