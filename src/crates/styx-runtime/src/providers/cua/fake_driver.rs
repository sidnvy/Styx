//! Hermetic driver replies over the production admitted transport and rmcp codec.
use super::*;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

#[allow(dead_code)]
pub(crate) struct FakeDriver {
    pub(crate) peer: rmcp::Peer<RoleClient>,
    pub(crate) calls: Arc<Mutex<Vec<Value>>>,
    pub(crate) reply: Arc<Mutex<CallToolResult>>,
    client: Option<RunningService<RoleClient, CuaClient>>,
    #[cfg(target_os = "linux")]
    bound: Option<(CuaHandle, tempfile::TempDir)>,
    job: JoinHandle<()>,
}
impl FakeDriver {
    pub(crate) async fn start(facts: Value, click_reply: CallToolResult) -> Self {
        Self::start_delayed(facts, click_reply, Duration::ZERO).await
    }
    pub(crate) async fn start_delayed(
        facts: Value,
        click_reply: CallToolResult,
        delay: Duration,
    ) -> Self {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let seen = calls.clone();
        let reply = Arc::new(Mutex::new(click_reply));
        let response_reply = reply.clone();
        let (local, remote) = tokio::io::duplex(65536);
        let (read, mut write) = tokio::io::split(remote);
        let job = tokio::spawn(async move {
            let mut lines = tokio::io::BufReader::new(read).lines();
            while let Some(line) = lines.next_line().await.unwrap() {
                let request: Value = serde_json::from_str(&line).unwrap();
                let Some(id) = request.get("id") else {
                    continue;
                };
                let result = match request["method"].as_str().unwrap() {
                    "initialize" => {
                        serde_json::json!({"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"cua-driver","version":"0.47.24"}})
                    }
                    "tools/list" => serde_json::json!({
                        "tools": [{
                            "name": "click",
                            "description": "Click a native desktop element.",
                            "inputSchema": {
                                "type": "object",
                                "properties": { "pid": { "type": "integer" } },
                                "required": ["pid"]
                            }
                        }]
                    }),
                    "tools/call" => {
                        seen.lock().unwrap().push(request["params"].clone());
                        tokio::time::sleep(delay).await;
                        serde_json::to_value(if request["params"]["name"] == "check_permissions" {
                            CallToolResult::structured(facts.clone())
                        } else {
                            response_reply.lock().unwrap().clone()
                        })
                        .unwrap()
                    }
                    _ => panic!("unexpected fake driver request"),
                };
                let response = serde_json::json!({"jsonrpc":"2.0","id":id,"result":result});
                if write
                    .write_all(format!("{response}\n").as_bytes())
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        let (read, write) = tokio::io::split(local);
        let transport =
            transport::AdmittedTransport::from_io(read, write, CancellationToken::new());
        let client = CuaClient {}.serve(transport).await.unwrap();
        let peer = client.peer().clone();
        peer.list_tools(None).await.unwrap();
        Self {
            peer,
            calls,
            reply,
            client: Some(client),
            #[cfg(target_os = "linux")]
            bound: None,
            job,
        }
    }
    /// Bind the existing duplex client to a real provider resource for Host
    /// ownership tests. The pinned image is never executed; no GUI is touched.
    #[cfg(target_os = "linux")]
    #[allow(dead_code)]
    pub(crate) fn bind_resource(
        &mut self,
        worker: &CuaWorker,
        owner: OwnerLease,
        target: ResourceTarget,
        session: SessionBinding,
    ) -> CuaHandle {
        use std::os::unix::fs::PermissionsExt;
        assert!(self.bound.is_none());
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let image = root.path().join("never-executed-cua");
        std::fs::copy("/bin/true", &image).unwrap();
        std::fs::set_permissions(&image, std::fs::Permissions::from_mode(0o700)).unwrap();
        let driver = Arc::new(
            crate::store::PrivateRoot::open(root.path())
                .unwrap()
                .payload_inventory(Default::default())
                .unwrap()
                .pin_executable("never-executed-cua")
                .unwrap(),
        );
        let uid = nix::unistd::Uid::current().as_raw();
        let runtime_dir = PathBuf::from(format!("/run/user/{uid}"));
        let config = Arc::new(OwnedCuaConfig {
            driver,
            launch: TrustedCuaLaunch {
                session: session.clone(),
                uid,
                session_bus: runtime_dir.join("bus"),
                runtime_dir,
                wayland_display: "wayland-0".into(),
                hyprland_instance: "fixture-never-launched".into(),
                compositor_peer: (std::process::id(), 1),
            },
            workspace: root.path().to_path_buf(),
            home: root.path().to_path_buf(),
        });
        let resource = Arc::new(Resource {
            owner,
            target,
            session,
            stop: CancellationToken::new(),
            live: Arc::new(tokio::sync::Mutex::new(Live {
                scope: None,
                scope_confirmed: false,
                child: None,
                identity: None,
                client: self.client.take(),
                close_job: None,
                stderr: None,
                config,
                retired: false,
                cleanup: None,
                uncertain: false,
                io_failed: false,
                exit_success: None,
                actions: BTreeMap::new(),
            })),
            cleanup_job: Mutex::new(None),
        });
        worker
            .inner
            .resources
            .lock()
            .unwrap()
            .insert(resource.target.operation_id.clone(), resource.clone());
        let handle = CuaHandle {
            resource,
            worker: worker.inner.clone(),
        };
        self.bound = Some((handle.clone(), root));
        handle
    }
    pub(crate) async fn call(
        &self,
        action: &CuaAction,
    ) -> (CuaEvidence, Option<CallToolResult>, Option<CuaError>) {
        let until = Some(Instant::now() + Duration::from_secs(2));
        match action {
            CuaAction::ListTools { names } => {
                driver_result::invoke_list_tools(
                    &self.peer,
                    names.as_deref(),
                    &CancellationToken::new(),
                    until,
                )
                .await
            }
            CuaAction::CallTool { name, arguments } => {
                driver_result::invoke(
                    &self.peer,
                    CallToolRequestParams::new(name.clone()).with_arguments(arguments.clone()),
                    &CancellationToken::new(),
                    until,
                )
                .await
            }
        }
    }
    pub(crate) async fn close(mut self) {
        drop(self.peer);
        #[cfg(target_os = "linux")]
        if let Some((handle, _)) = self.bound.as_ref() {
            handle.resource.stop.cancel();
            self.client = handle.resource.live.lock().await.client.take();
        }
        if let Some(mut client) = self.client.take() {
            client.close().await.unwrap();
        }
        self.job.await.unwrap();
    }
}
