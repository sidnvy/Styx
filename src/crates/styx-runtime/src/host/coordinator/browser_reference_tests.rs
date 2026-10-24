//! One actual, serialized Host/Node/Chrome reference-boundary journey. Synthetic
//! bootstrap authority is not pairing/account/native desktop authorization.
use super::*;
use futures_util::FutureExt;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

fn tool(name: &str, arguments: Value) -> BrowserAction {
    BrowserAction::Tool {
        name: name.into(),
        arguments: arguments
            .as_object()
            .expect("fixture tool arguments")
            .clone(),
    }
}
async fn execute(
    host: &HostCoordinator,
    owner: &OwnerLease,
    resource: &OperationSnapshot,
    action: BrowserAction,
    observations: &mut Vec<Value>,
) -> BrowserActionCompletion {
    let reserved = host
        .prepare_browser_action(owner, target(resource), browser_context(host), &action)
        .unwrap();
    let completed = match host
        .dispatch_browser_action(owner, &reserved.id, reserved.payload_digest)
        .unwrap()
    {
        BrowserActionSubmission::Submitted(ticket) => ticket.wait().await.unwrap(),
        BrowserActionSubmission::Existing(_) => {
            panic!("fresh logical operation must not already exist")
        }
    };
    observations.push(json!({"operation":completed.snapshot.id,"state":completed.snapshot.state,"evidence":completed.receipt.evidence,"cause":completed.receipt.cause,"retention_error":completed.retention_error.as_ref().map(|_|"present")}));
    completed
}
fn acknowledged(completed: &BrowserActionCompletion) {
    if completed.receipt.evidence != BrowserActionEvidence::Acknowledged {
        let diagnostic =
            json!({"cause":completed.receipt.cause,"result":completed.receipt.result}).to_string();
        let mut end = diagnostic.len().min(8128);
        while !diagnostic.is_char_boundary(end) {
            end -= 1;
        }
        eprintln!("owned_reference_diagnostic {}", &diagnostic[..end]);
    }
    assert_eq!(
        completed.receipt.evidence,
        BrowserActionEvidence::Acknowledged,
        "unexpected Unknown is preserved, never internally retried"
    );
    assert!(completed.retention_error.is_none());
}
fn stale(completed: &BrowserActionCompletion) {
    assert_eq!(
        completed.receipt.evidence,
        BrowserActionEvidence::NotDispatched
    );
    assert_eq!(
        completed.receipt.cause,
        Some(BrowserError::StaleObservation)
    );
    assert_eq!(completed.snapshot.state, OperationState::Failed);
}
fn snapshot_ref(completed: &BrowserActionCompletion, label: &str) -> String {
    acknowledged(completed);
    let value = serde_json::to_value(completed.receipt.result.as_ref().unwrap()).unwrap();
    let texts = value["content"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c.get("text").and_then(Value::as_str));
    let mut tokens = Vec::new();
    for text in texts {
        for line in text.lines().filter(|line| line.contains(label)) {
            if let Some((_, rest)) = line.split_once("[ref=") {
                let token = rest.split_once(']').unwrap().0;
                if token.len() == 37
                    && token.starts_with("styx-")
                    && token[5..]
                        .bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                {
                    tokens.push(token.to_owned());
                }
            }
        }
    }
    assert_eq!(
        tokens.len(),
        1,
        "exact owned label must identify one opaque snapshot reference"
    );
    tokens.pop().unwrap()
}
async fn wait_count(values: &Arc<Mutex<Vec<String>>>, expected: usize) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let n = values.lock().unwrap().len();
            assert!(n <= expected, "unexpected extra HTTP effect");
            if n == expected {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires explicit owned STYX_TEST_BROWSER_ROOT/NODE/WORKER/EXECUTABLE and STYX_TEST_CODEX; actual serialized reference journey"]
async fn actual_snapshot_refs_navigation_tabs_owner_and_reopen_batch() {
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full, Limited};
    use hyper::{Request, Response, body::Incoming, service::service_fn};
    use hyper_util::rt::TokioIo;
    use std::os::unix::fs::PermissionsExt;
    let root = std::path::PathBuf::from(std::env::var_os("STYX_TEST_BROWSER_ROOT").unwrap())
        .join(uuid::Uuid::new_v4().to_string());
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    for name in ["codex-home", "profile", "output", "workspace"] {
        let path = root.join(name);
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let adapter = crate::providers::codex::CodexStdio::spawn_owned(
        crate::providers::codex::OwnedExecutorConfig {
            binary: std::env::var_os("STYX_TEST_CODEX").unwrap().into(),
            cwd: root.clone(),
            environment: BTreeMap::from([
                ("PATH".into(), "/usr/bin:/bin".into()),
                ("HOME".into(), root.display().to_string()),
                (
                    "CODEX_HOME".into(),
                    root.join("codex-home").display().to_string(),
                ),
            ]),
            rpc_timeout: Duration::from_secs(3),
            retained_process_limit: 8,
        },
    )
    .await
    .unwrap();
    let (host, authority) = HostCoordinator::new_owned(
        adapter,
        OperationLedger::new(HostGeneration::try_from("browser-reference-host").unwrap()),
        fixture_facts(CapabilityId::ExecRun),
        4,
    )
    .unwrap();
    let budget = Arc::new(Semaphore::new(16 * 1024 * 1024))
        .acquire_many_owned(16 * 1024 * 1024)
        .await
        .unwrap();
    authority
        .configure_browser(
            fixture_facts(CapabilityId::BrowserHeadless),
            BrowserIoBudget::from_reserved(budget).unwrap(),
        )
        .unwrap();
    let owner = authority
        .register_verified_owner(
            OwnerId::try_from("reference-owner").unwrap(),
            OwnerEpoch::try_from("reference-epoch").unwrap(),
        )
        .unwrap();
    let foreign = authority
        .register_verified_owner(
            OwnerId::try_from("reference-foreign").unwrap(),
            OwnerEpoch::try_from("reference-foreign-epoch").unwrap(),
        )
        .unwrap();
    authority
        .register_browser_profile(
            &owner,
            OwnedBrowserConfig {
                node_binary: std::env::var_os("STYX_TEST_BROWSER_NODE").unwrap().into(),
                worker_entry: std::env::var_os("STYX_TEST_BROWSER_WORKER").unwrap().into(),
                browser_binary: std::env::var_os("STYX_TEST_BROWSER_EXECUTABLE")
                    .unwrap()
                    .into(),
                workspace_dir: root.join("workspace"),
                profile_dir: root.join("profile"),
                output_dir: root.join("output"),
                rpc_timeout: Duration::from_secs(10),
            },
        )
        .unwrap();
    let effects = Arc::new(Mutex::new(Vec::<String>::new()));
    let ready = Arc::new(Mutex::new(Vec::<String>::new()));
    let link_probes = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let navigation_gate = CancellationToken::new();
    let server_navigation_gate = navigation_gate.clone();
    let stop = CancellationToken::new();
    let stop_server = stop.clone();
    let server_effects = effects.clone();
    let server_ready = ready.clone();
    let server_link_probes = link_probes.clone();
    let server = tokio::spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            let stream = tokio::select! {_=stop_server.cancelled()=>break,result=listener.accept()=>result.unwrap().0};
            let effects = server_effects.clone();
            let ready = server_ready.clone();
            let link_probes = server_link_probes.clone();
            let navigation_gate = server_navigation_gate.clone();
            connections.spawn(async move {
                let service=service_fn(move |request:Request<Incoming>|{let effects=effects.clone();let ready=ready.clone();let link_probes=link_probes.clone();let navigation_gate=navigation_gate.clone();async move {
                    let path=request.uri().path().to_owned();
                    let response=if let Some(page)=path.strip_prefix("/page/") {
                        assert!(["a","b","tab"].contains(&page));
                        let html=format!(r#"<!doctype html><title>owned ref {page}</title><label>Owned value<input id="value" aria-label="Owned value"></label><button id="commit" onclick="fetch('/effect',{{method:'POST',body:'{page}:'+document.querySelector('#value').value}})">Owned commit {page}</button><script>fetch('/ready/{page}')</script>"#);
                        Response::builder().header("content-type","text/html").body(Full::new(Bytes::from(html))).unwrap()
                    } else if path=="/navigation-gate" {
                        // Each poll completes immediately: official MCP's
                        // waitForCompletion must not wait on a held fetch.
                        let body=if navigation_gate.is_cancelled(){b"go".as_slice()}else{b"wait".as_slice()};
                        Response::new(Full::new(Bytes::copy_from_slice(body)))
                    } else if let Some(page)=path.strip_prefix("/ready/") {ready.lock().unwrap().push(page.to_owned());Response::new(Full::new(Bytes::new()))}
                    else if path=="/link-probe" {let cookie=request.headers().get("cookie").and_then(|v|v.to_str().ok()).unwrap_or("").to_owned();let body=Limited::new(request.into_body(),4096).collect().await.unwrap().to_bytes();link_probes.lock().unwrap().push((String::from_utf8(body.to_vec()).unwrap(),cookie));Response::new(Full::new(Bytes::from_static(b"recorded")))}
                    else if path=="/effect" {let body=Limited::new(request.into_body(),4096).collect().await.unwrap().to_bytes();effects.lock().unwrap().push(String::from_utf8(body.to_vec()).unwrap());Response::new(Full::new(Bytes::from_static(b"recorded")))}
                    else {Response::builder().status(204).body(Full::new(Bytes::new())).unwrap()};
                    Ok::<_,std::convert::Infallible>(response)
                }});
                let _=hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream),service).await;
            });
        }
        while connections.join_next().await.is_some() {}
    });
    let nonce = uuid::Uuid::new_v4().to_string();
    let mut stage = "open";
    let mut observations = Vec::new();
    let mut retirements = Vec::new();
    let scenario=std::panic::AssertUnwindSafe(async {
        let open=opened(&host,&owner).await;
        stage="first_snapshot_without_prior_navigation";
        // Real UX: lazy context creation is not worked around by first issuing
        // Navigate or retrying a failed snapshot. Preserve that initial result.
        acknowledged(&execute(&host,&owner,&open,tool("browser_snapshot",json!({})),&mut observations).await);
        stage="navigate_owned_page";
        acknowledged(&execute(&host,&owner,&open,BrowserAction::Navigate{url:format!("http://{address}/page/a")},&mut observations).await);
        stage="snapshot_opaque_and_foreign_raw_rejection";
        let snapshot=execute(&host,&owner,&open,tool("browser_snapshot",json!({})),&mut observations).await;
        let old=snapshot_ref(&snapshot,"Owned commit a");
        assert!(host.prepare_browser_action(&foreign,target(&open),browser_context(&host),&tool("browser_click",json!({"target":old}))).is_err());
        let raw=host.prepare_browser_action(&owner,target(&open),browser_context(&host),&tool("browser_click",json!({"target":"e1"})));
        assert!(matches!(raw,Err(CoordinatorError::Browser(BrowserError::StaleObservation))));
        observations.push(json!({"raw_native_reference":"prepare_rejected_stale_observation","dispatched":false}));
        assert!(effects.lock().unwrap().is_empty());
        stage="old_snapshot_rejection_then_input_click";
        let fresh=execute(&host,&owner,&open,tool("browser_snapshot",json!({})),&mut observations).await;
        let intermediate=snapshot_ref(&fresh,"Owned commit a");assert_ne!(intermediate,old);
        stale(&execute(&host,&owner,&open,tool("browser_click",json!({"target":old})),&mut observations).await);
        assert!(effects.lock().unwrap().is_empty());
        stage="trusted_link_boundary_preserves_context_rejects_refs";
        acknowledged(&execute(&host,&owner,&open,BrowserAction::Evaluate{function:format!("()=>{{window.__styx_link_guard={};document.cookie='styx_link_cookie='+window.__styx_link_guard+'; path=/';return true}}",serde_json::to_string(&nonce).unwrap())},&mut observations).await);
        let before_link=execute(&host,&owner,&open,tool("browser_snapshot",json!({})),&mut observations).await;
        let link_old=snapshot_ref(&before_link,"Owned commit a");
        // Exact trusted HostProtocol boundary port, not a simulated network
        // result and not evidence that a real WSS socket was disconnected.
        host.invalidate_browser_link_references();
        host.invalidate_browser_link_references();
        stale(&execute(&host,&owner,&open,tool("browser_click",json!({"target":link_old})),&mut observations).await);
        assert!(effects.lock().unwrap().is_empty());
        acknowledged(&execute(&host,&owner,&open,BrowserAction::Evaluate{function:"async()=>{await fetch('/link-probe',{method:'POST',body:String(window.__styx_link_guard)});return true}".into()},&mut observations).await);
        let probes=link_probes.lock().unwrap().clone();
        assert_eq!(probes.len(),1);assert_eq!(probes[0].0,nonce);
        assert!(probes[0].1.split(';').any(|v|v.trim()==format!("styx_link_cookie={nonce}")));
        observations.push(json!({"trusted_link_boundary":"end_and_begin","same_resource":open.id,"retained_window_nonce":true,"retained_http_cookie":true,"rejected_click_effects":0,"actual_wss_reconnect":"NOT_RUN"}));
        // The rejected stale request invalidates all refs. This is a new user
        // observation, not a retry of the failed click or its old reference.
        let fresh=execute(&host,&owner,&open,tool("browser_snapshot",json!({})),&mut observations).await;
        let input=snapshot_ref(&fresh,"textbox");
        acknowledged(&execute(&host,&owner,&open,tool("browser_type",json!({"target":input,"text":nonce})),&mut observations).await);
        // Successful mutation invalidates old refs: a fresh user snapshot is
        // required before the separate logical click, never an action retry.
        let after_type=execute(&host,&owner,&open,tool("browser_snapshot",json!({})),&mut observations).await;
        let button=snapshot_ref(&after_type,"Owned commit a");
        acknowledged(&execute(&host,&owner,&open,tool("browser_click",json!({"target":button})),&mut observations).await);
        wait_count(&effects,1).await;assert_eq!(*effects.lock().unwrap(),vec![format!("a:{nonce}")]);
        stage="autonomous_navigation_rejects_old_snapshot";
        acknowledged(&execute(&host,&owner,&open,BrowserAction::Evaluate{function:"()=>{let done=false;const timer=setInterval(()=>{void fetch('/navigation-gate').then(r=>r.text()).then(value=>{if(!done&&value==='go'){done=true;clearInterval(timer);location.assign('/page/b');}})},100);return 'scheduled'}".into()},&mut observations).await);
        // Evaluate already invalidated refs. The independent HTTP server holds
        // navigation until this new user snapshot has bound the still-live A.
        assert!(!ready.lock().unwrap().iter().any(|p|p=="b"),"navigation bypassed the independent server gate");
        let before_nav=execute(&host,&owner,&open,tool("browser_snapshot",json!({})),&mut observations).await;
        let autonav_old=snapshot_ref(&before_nav,"Owned commit a");
        assert!(!ready.lock().unwrap().iter().any(|p|p=="b"),"navigation crossed the closed independent gate");
        navigation_gate.cancel();
        observations.push(json!({"navigation_gate_released_after_snapshot":true,"snapshot_before_new_document":true}));
        tokio::time::timeout(Duration::from_secs(10),async {loop {if ready.lock().unwrap().iter().any(|p|p=="b"){break;}tokio::time::sleep(Duration::from_millis(10)).await;}}).await.unwrap();
        stale(&execute(&host,&owner,&open,tool("browser_click",json!({"target":autonav_old})),&mut observations).await);assert_eq!(effects.lock().unwrap().len(),1);
        let fresh=execute(&host,&owner,&open,tool("browser_snapshot",json!({})),&mut observations).await;
        let _before_type_b=snapshot_ref(&fresh,"Owned commit b");
        // A valid unique selector remains supported; raw native IDs are the
        // rejected bypass, not every nonopaque selector.
        acknowledged(&execute(&host,&owner,&open,tool("browser_type",json!({"target":"#value","text":nonce})),&mut observations).await);
        let after_type=execute(&host,&owner,&open,tool("browser_snapshot",json!({})),&mut observations).await;
        let bbutton=snapshot_ref(&after_type,"Owned commit b");
        acknowledged(&execute(&host,&owner,&open,tool("browser_click",json!({"target":bbutton})),&mut observations).await);
        wait_count(&effects,2).await;assert_eq!(*effects.lock().unwrap(),vec![format!("a:{nonce}"),format!("b:{nonce}")]);
        stage="tabs_new_select_no_cross_page_effect";
        // Click also invalidates refs. This token must be live immediately
        // before tabs/new, otherwise the rejection would not prove tab fencing.
        let before_tabs=execute(&host,&owner,&open,tool("browser_snapshot",json!({})),&mut observations).await;
        let before_new_tab=snapshot_ref(&before_tabs,"Owned commit b");
        acknowledged(&execute(&host,&owner,&open,tool("browser_tabs",json!({"action":"new","url":format!("http://{address}/page/tab")})),&mut observations).await);
        stale(&execute(&host,&owner,&open,tool("browser_click",json!({"target":before_new_tab})),&mut observations).await);
        let tab_snapshot=execute(&host,&owner,&open,tool("browser_snapshot",json!({})),&mut observations).await;let tabbutton=snapshot_ref(&tab_snapshot,"Owned commit tab");
        acknowledged(&execute(&host,&owner,&open,tool("browser_tabs",json!({"action":"select","index":0})),&mut observations).await);
        stale(&execute(&host,&owner,&open,tool("browser_click",json!({"target":tabbutton})),&mut observations).await);assert_eq!(effects.lock().unwrap().len(),2);
        stage="close_retire_then_same_owner_profile_reopen_aba";
        let before_close=execute(&host,&owner,&open,tool("browser_snapshot",json!({})),&mut observations).await;
        let resource_old=snapshot_ref(&before_close,"Owned commit b");
        let closed=execute(&host,&owner,&open,BrowserAction::Close,&mut observations).await;acknowledged(&closed);assert!(closed.cleanup.as_ref().is_some_and(physical_complete));
        let collected=authority.collect_provider_retention(Duration::from_secs(10)).await.unwrap();retirements.push(json!({"resources":collected.resources_released,"actions":collected.actions_released,"unreleased":collected.unreleased_records,"blocked":collected.blocked.len()}));assert!(collected.blocked.is_empty());assert_eq!(collected.unreleased_records,0);assert_eq!(collected.resources_released,1);
        let reopened=opened(&host,&owner).await;assert_ne!(reopened.id,open.id);
        acknowledged(&execute(&host,&owner,&reopened,BrowserAction::Navigate{url:format!("http://{address}/page/a")},&mut observations).await);
        let new_snapshot=execute(&host,&owner,&reopened,tool("browser_snapshot",json!({})),&mut observations).await;let new_token=snapshot_ref(&new_snapshot,"Owned commit a");assert_ne!(new_token,resource_old);
        stale(&execute(&host,&owner,&reopened,tool("browser_click",json!({"target":resource_old})),&mut observations).await);assert_eq!(effects.lock().unwrap().len(),2);
        let closed=execute(&host,&owner,&reopened,BrowserAction::Close,&mut observations).await;acknowledged(&closed);assert!(closed.cleanup.as_ref().is_some_and(physical_complete));
        let collected=authority.collect_provider_retention(Duration::from_secs(10)).await.unwrap();retirements.push(json!({"resources":collected.resources_released,"actions":collected.actions_released,"unreleased":collected.unreleased_records,"blocked":collected.blocked.len()}));assert!(collected.blocked.is_empty());assert_eq!(collected.unreleased_records,0);assert_eq!(collected.resources_released,1);
        let cleanup=authority.fence_owner_for_cleanup(&owner).unwrap();let facts=authority.cleanup_owner(&cleanup,Duration::from_secs(5)).unwrap().wait().await.unwrap();assert!(facts.physical_complete);assert_eq!(facts.unreleased_records,0);assert!(facts.blocked.is_empty());
        stage="complete";
    }).catch_unwind().await;
    // Release the independent gate on every exit path. Poll responses never
    // block; context shutdown cancels the page's outstanding poll interval.
    navigation_gate.cancel();
    let cleanup = authority.shutdown_owned(Duration::from_secs(25)).await;
    stop.cancel();
    let joined = tokio::time::timeout(Duration::from_secs(5), server).await;
    let http_server_joined = matches!(joined, Ok(Ok(())));
    let host_browser_cleanup_complete = cleanup.as_ref().ok().is_some_and(|f| {
        f.supervised_jobs_joined
            && f.native
                .as_ref()
                .expect("fixture configured Exec")
                .executor_exited
            && f.native
                .as_ref()
                .expect("fixture configured Exec")
                .reader_task_reaped
            && f.native
                .as_ref()
                .expect("fixture configured Exec")
                .stderr_task_reaped
            && f.browser.as_ref().is_some_and(|b| b.complete)
    });
    let receipt = json!({"schema":1,"status":if scenario.is_ok()&&host_browser_cleanup_complete&&http_server_joined{"PASS"}else{"FAIL"},"scope":"actual owned serial Rust Host/Node/Chrome references; synthetic bootstrap authority, not paired/account/GUI/file-transfer acceptance","last_stage":stage,"nonce":nonce,"http_effects":effects.lock().unwrap().clone(),"http_ready_pages":ready.lock().unwrap().clone(),"trusted_link_http_probes":link_probes.lock().unwrap().clone(),"actual_wss_reconnect":"NOT_RUN","core_observations":observations,"retirement":retirements,"host_browser_cleanup_complete":host_browser_cleanup_complete,"http_server_joined":http_server_joined,"internal_ref_retries":0,"unknown_policy":"unexpected Unknown fails and preserves history; no reset or replay","source_sha256":hex::encode(<sha2::Sha256 as sha2::Digest>::digest(include_bytes!("browser_reference_tests.rs")))});
    std::fs::write(
        root.join("receipt.json"),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();
    assert!(host_browser_cleanup_complete);
    assert!(http_server_joined);
    if let Err(panic) = scenario {
        std::panic::resume_unwind(panic);
    }
}
