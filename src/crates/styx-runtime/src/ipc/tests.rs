#[cfg(target_os = "linux")]
use super::*;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use futures_util::StreamExt;
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::PathBuf,
        process::Stdio,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixStream,
        time::timeout,
    };
    use tokio_util::{
        codec::{FramedRead, LinesCodec},
        sync::CancellationToken,
    };

    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("styx-ipc-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
        fn endpoint(&self) -> EndpointRoot {
            EndpointRoot::open(&self.0).unwrap()
        }
        fn socket(&self) -> PathBuf {
            self.0.join(SOCKET_FILENAME)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn request(id: &str, call: ControlCall, ms: u32) -> ControlRequest {
        ControlRequest {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            client_instance: AgentInstanceId::try_from("uid-0-pid-1").unwrap(),
            request_id: RequestId::try_from(id).unwrap(),
            timeout_ms: ms,
            call,
        }
    }
    fn category(frame: ControlResponse) -> ErrorCategory {
        match frame.outcome {
            ControlOutcome::Error(e) => e.category,
            _ => panic!("expected a structured refusal"),
        }
    }
    async fn start(
        root: EndpointRoot,
    ) -> (
        ExpectedServer,
        CancellationToken,
        tokio::task::JoinHandle<Result<ServerReport>>,
        Arc<AtomicUsize>,
    ) {
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let server=ManagementServer::bind(root,move |peer:ReadPeer,request:ReadRequest| {
            count.fetch_add(1,Ordering::SeqCst);
            async move {match request.call {
                ReadCall::Snapshot=>ControlOutcome::Ok(serde_json::json!({"fixture":true,"kernel_pid":peer.pid(),"kernel_uid":peer.uid(),"scope":"management_read"})),
                ReadCall::Transaction {transaction_id} if transaction_id.as_str()=="slow"=>{tokio::time::sleep(Duration::from_millis(100)).await;unsupported_read()},
                ReadCall::Transaction {transaction_id} if transaction_id.as_str()=="large"=>ControlOutcome::Ok(serde_json::Value::String("x".repeat(CONTROL_FRAME_BYTES+1024))),
                ReadCall::Transaction {..}=>unsupported_read(),
            }}
        }).await.unwrap();
        let expected = server.expected_server().unwrap();
        let stop = CancellationToken::new();
        let shutdown = stop.clone();
        (expected, stop, tokio::spawn(server.run(shutdown)), calls)
    }
    async fn raw(root: &Scratch, value: serde_json::Value) -> ControlResponse {
        let mut stream = UnixStream::connect(root.socket()).await.unwrap();
        stream
            .write_all(&serde_json::to_vec(&value).unwrap())
            .await
            .unwrap();
        stream.write_all(b"\n").await.unwrap();
        let mut frames =
            FramedRead::new(stream, LinesCodec::new_with_max_length(CONTROL_FRAME_BYTES));
        let line = timeout(Duration::from_secs(2), frames.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        serde_json::from_str(&line).unwrap()
    }
    async fn rejected_frame(root: &Scratch, bytes: &[u8]) {
        let mut stream = UnixStream::connect(root.socket()).await.unwrap();
        let _ = stream.write_all(bytes).await;
        let mut byte = [0u8; 1];
        let result = timeout(Duration::from_secs(2), stream.read(&mut byte))
            .await
            .unwrap();
        assert!(
            matches!(result, Ok(0) | Err(_)),
            "unframed/untrusted request must not receive a success response"
        );
    }

    #[tokio::test]
    async fn read_only_journey_refuses_scope_bad_frames_timeout_and_stays_healthy() {
        let scratch = Scratch::new();
        let root = scratch.endpoint();
        let (expected, stop, task, calls) = start(root.clone()).await;
        let mode = fs::metadata(scratch.socket()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let mut client = ManagementClient::connect(&root, expected.clone())
            .await
            .unwrap();
        let healthy = client
            .call(
                &request("healthy", ControlCall::ReadSnapshot, 1000),
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        match healthy.outcome {
            ControlOutcome::Ok(value) => {
                assert_eq!(value["kernel_pid"], std::process::id());
                assert_eq!(value["scope"], "management_read");
            }
            _ => panic!("fixture read failed"),
        }
        assert_eq!(
            category(
                client
                    .call(
                        &request(
                            "tx",
                            ControlCall::ReadTransaction {
                                transaction_id: TransactionId::try_from("unimplemented").unwrap()
                            },
                            1000
                        ),
                        Duration::from_secs(2)
                    )
                    .await
                    .unwrap()
            ),
            ErrorCategory::CapabilityUnsupported
        );
        let before = calls.load(Ordering::SeqCst);
        for method in ["cancel_operation", "register_session"] {
            let frame=raw(&scratch,serde_json::json!({"protocol_version":1,"client_instance":"uid-0-pid-1","request_id":method,"timeout_ms":1000,"call":{"method":method,"params":{"claimed_uid":0,"claimed_pid":1}}})).await;
            assert_eq!(category(frame), ErrorCategory::Unauthorized);
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            before,
            "denied descriptors never reach the handler"
        );
        let spoof = serde_json::json!({"protocol_version":1,"client_instance":"claimed-root","request_id":"spoof","timeout_ms":1000,"peer_uid":0,"peer_pid":1,"call":{"method":"read_snapshot"}});
        let mut bytes = serde_json::to_vec(&spoof).unwrap();
        bytes.push(b'\n');
        rejected_frame(&scratch, &bytes).await;
        rejected_frame(&scratch, b"{not-json}\n").await;
        rejected_frame(&scratch, &vec![b'x'; CONTROL_FRAME_BYTES + 2]).await;
        let slow = request(
            "timeout",
            ControlCall::ReadTransaction {
                transaction_id: TransactionId::try_from("slow").unwrap(),
            },
            5,
        );
        let timed = client.call(&slow, Duration::from_secs(2)).await.unwrap();
        match timed.outcome {
            ControlOutcome::Error(error) => {
                assert_eq!(error.category, ErrorCategory::OperationTimeout);
                assert_eq!(error.execution_certainty, ExecutionCertainty::Unknown);
            }
            _ => panic!("timeout was hidden"),
        }
        assert_eq!(
            category(
                client
                    .call(
                        &request(
                            "large",
                            ControlCall::ReadTransaction {
                                transaction_id: TransactionId::try_from("large").unwrap()
                            },
                            1000
                        ),
                        Duration::from_secs(2)
                    )
                    .await
                    .unwrap()
            ),
            ErrorCategory::Busy
        );
        // Disconnect while a read is active; no provider is owned or killed here.
        let mut disconnect = UnixStream::connect(scratch.socket()).await.unwrap();
        let mut bytes = serde_json::to_vec(&request(
            "disconnect",
            ControlCall::ReadTransaction {
                transaction_id: TransactionId::try_from("slow").unwrap(),
            },
            200,
        ))
        .unwrap();
        bytes.push(b'\n');
        disconnect.write_all(&bytes).await.unwrap();
        drop(disconnect);
        assert!(matches!(
            client
                .call(
                    &request("after-errors", ControlCall::ReadSnapshot, 1000),
                    Duration::from_secs(2)
                )
                .await
                .unwrap()
                .outcome,
            ControlOutcome::Ok(_)
        ));
        let wrong = ExpectedServer::from_trusted_manager(
            nix::unistd::geteuid().as_raw(),
            ProcessIdentity::Linux {
                boot_id: "00000000-0000-0000-0000-000000000000".into(),
                pid: std::process::id(),
                start_ticks: 0,
            },
        );
        assert!(matches!(
            ManagementClient::connect(&root, wrong).await,
            Err(IpcError::PeerIdentity)
        ));
        // An existing live endpoint is never unlinked by a second bind.
        assert!(
            ManagementServer::bind(root.clone(), |_: ReadPeer, _: ReadRequest| async {
                unsupported_read()
            })
            .await
            .is_err()
        );
        assert!(matches!(
            client
                .call(
                    &request("still-live", ControlCall::ReadSnapshot, 1000),
                    Duration::from_secs(2)
                )
                .await
                .unwrap()
                .outcome,
            ControlOutcome::Ok(_)
        ));
        drop(client);
        stop.cancel();
        let report = task.await.unwrap().unwrap();
        assert!(report.socket_removed);
        assert!(!scratch.socket().exists());
        assert!(report.denied_scope >= 2);
        assert!(report.rejected_frame >= 3);
        assert!(report.wait_expired >= 1);
        println!(
            "ipc_observation={}",
            serde_json::to_string(&report).unwrap()
        );
    }

    #[tokio::test]
    async fn capacity_is_derived_and_cleanup_refuses_substituted_inode() {
        let scratch = Scratch::new();
        let root = scratch.endpoint();
        let (expected, stop, task, _) = start(root.clone()).await;
        let mut clients = Vec::new();
        for i in 0..MAX_CONNECTIONS {
            let mut client = ManagementClient::connect(&root, expected.clone())
                .await
                .unwrap();
            client
                .call(
                    &request(&format!("capacity-{i}"), ControlCall::ReadSnapshot, 1000),
                    Duration::from_secs(2),
                )
                .await
                .unwrap();
            clients.push(client);
        }
        rejected_frame(&scratch, b"{}\n").await;
        drop(clients);
        stop.cancel();
        let report = task.await.unwrap().unwrap();
        assert!(report.rejected_capacity >= 1);
        assert!(report.socket_removed);
        let (expected, stop, task, _) = start(root).await;
        let _ = expected;
        fs::rename(scratch.socket(), scratch.0.join("displaced.sock")).unwrap();
        fs::write(scratch.socket(), b"owned-negative-control").unwrap();
        stop.cancel();
        assert!(matches!(
            task.await.unwrap(),
            Err(IpcError::EndpointIdentity)
        ));
        assert_eq!(
            fs::read(scratch.socket()).unwrap(),
            b"owned-negative-control"
        );
        assert!(scratch.0.join("displaced.sock").exists());
        println!(
            "ipc_observation={}",
            serde_json::json!({"capacity":MAX_CONNECTIONS,"reservation_bytes":CONNECTION_WIRE_RESERVATION,"rejected_capacity":report.rejected_capacity,"replacement_preserved":true})
        );
    }

    #[tokio::test]
    async fn independent_process_peer_is_kernel_bound_not_client_instance_claim() {
        let scratch = Scratch::new();
        let root = scratch.endpoint();
        let (expected, stop, task, _) = start(root).await;
        let ProcessIdentity::Linux {
            boot_id,
            pid,
            start_ticks,
        } = expected.process;
        let mut child = tokio::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "ipc::tests::linux::client_child_probe",
                "--ignored",
                "--nocapture",
            ])
            .env("STYX_IPC_ROOT", &scratch.0)
            .env("STYX_IPC_SERVER_PID", pid.to_string())
            .env("STYX_IPC_SERVER_BOOT", boot_id)
            .env("STYX_IPC_SERVER_TICKS", start_ticks.to_string())
            .env("STYX_IPC_SERVER_UID", expected.uid.to_string())
            .spawn()
            .unwrap();
        let child_id = child.id().unwrap();
        let status = match timeout(Duration::from_secs(5), child.wait()).await {
            Ok(s) => s.unwrap(),
            Err(_) => {
                child.start_kill().unwrap();
                child.wait().await.unwrap();
                panic!("owned IPC child exceeded bound")
            }
        };
        assert!(status.success());
        stop.cancel();
        assert!(task.await.unwrap().unwrap().socket_removed);
        println!(
            "ipc_observation={}",
            serde_json::json!({"owned_child_pid":child_id,"exit_code":status.code(),"kernel_peer_verified":true})
        );
    }
    #[tokio::test]
    #[ignore = "owned independent-process oracle"]
    async fn client_child_probe() {
        let root = EndpointRoot::open(std::env::var_os("STYX_IPC_ROOT").unwrap()).unwrap();
        let expected = ExpectedServer::from_trusted_manager(
            std::env::var("STYX_IPC_SERVER_UID")
                .unwrap()
                .parse()
                .unwrap(),
            ProcessIdentity::Linux {
                boot_id: std::env::var("STYX_IPC_SERVER_BOOT").unwrap(),
                pid: std::env::var("STYX_IPC_SERVER_PID")
                    .unwrap()
                    .parse()
                    .unwrap(),
                start_ticks: std::env::var("STYX_IPC_SERVER_TICKS")
                    .unwrap()
                    .parse()
                    .unwrap(),
            },
        );
        let mut client = ManagementClient::connect(&root, expected).await.unwrap();
        let frame = client
            .call(
                &request("child-read", ControlCall::ReadSnapshot, 1000),
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        match frame.outcome {
            ControlOutcome::Ok(value) => {
                assert_eq!(value["kernel_pid"], std::process::id());
                assert_eq!(value["kernel_uid"], nix::unistd::geteuid().as_raw());
            }
            _ => panic!("child peer not observed"),
        }
    }

    #[tokio::test]
    async fn owned_stdio_timeout_keeps_child_and_resumes_same_response_without_replay() {
        let script = r#"import sys,json,time,os
count=0
for line in sys.stdin:
 r=json.loads(line);count+=1
 if r['call']['method']=='read_transaction':time.sleep(.1)
 print(json.dumps({'protocol_version':1,'request_id':r['request_id'],'outcome':{'status':'ok','value':{'fixture':True,'count':count,'pid':os.getpid()}}}),flush=True)
"#;
        let mut child = tokio::process::Command::new("/usr/bin/python3")
            .args(["-u", "-c", script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id().unwrap();
        let mut backend = BackendStdio::from_owned_child(&mut child).unwrap();
        let slow = request(
            "same-response",
            ControlCall::ReadTransaction {
                transaction_id: TransactionId::try_from("slow").unwrap(),
            },
            1000,
        );
        assert!(matches!(
            backend.call(&slow, Duration::from_millis(1)).await,
            Err(IpcError::WaitExpired)
        ));
        assert!(backend.has_pending_response());
        assert!(child.try_wait().unwrap().is_none());
        assert!(matches!(
            backend
                .call(
                    &request("no-replay", ControlCall::ReadSnapshot, 1000),
                    Duration::from_secs(1)
                )
                .await,
            Err(IpcError::PendingResponse)
        ));
        let first = backend.read_pending(Duration::from_secs(2)).await.unwrap();
        assert_eq!(first.request_id.as_str(), "same-response");
        match first.outcome {
            ControlOutcome::Ok(value) => {
                assert_eq!(value["count"], 1);
                assert_eq!(value["pid"], pid);
            }
            _ => panic!("missing original result"),
        }
        let second = backend
            .call(
                &request("next", ControlCall::ReadSnapshot, 1000),
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        match second.outcome {
            ControlOutcome::Ok(value) => assert_eq!(value["count"], 2),
            _ => panic!("read after timeout failed"),
        }
        drop(backend);
        let status = timeout(Duration::from_secs(2), child.wait())
            .await
            .unwrap()
            .unwrap();
        assert!(status.success());
        println!(
            "ipc_observation={}",
            serde_json::json!({"stdio_child_pid":pid,"original_response_count":1,"next_response_count":2,"normal_child_exit":status.code(),"replayed":false})
        );
    }
}
