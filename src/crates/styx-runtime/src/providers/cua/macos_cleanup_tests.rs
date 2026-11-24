use super::*;
use crate::providers::cua::CuaCleanup;
use rmcp::{
    ErrorData, RoleServer, ServerHandler, ServiceExt,
    model::{CallToolRequestParams, CallToolResponse, CallToolResult},
    service::RequestContext,
};
use serde_json::json;
use std::sync::{Arc, Mutex};

#[test]
fn observation_error_and_live_original_never_prove_daemon_exit() {
    assert_eq!(ended_from_observation::<()>(Ok(true)), Ok(false));
    assert_eq!(ended_from_observation::<()>(Ok(false)), Ok(true));
    assert_eq!(
        ended_from_observation(Err::<bool, _>("permission")),
        Err("permission")
    );
    assert_eq!(
        ended_from_observation(Err::<bool, _>("short_read")),
        Err("short_read")
    );
}

#[test]
fn original_birth_is_checked_without_adopting_replacement() {
    let original = ProcessIdentity::current().unwrap();
    assert!(!original_daemon_ended(&original).unwrap());
    let mut older_birth = original.clone();
    match &mut older_birth {
        ProcessIdentity::Linux { start_ticks, .. } => *start_ticks += 1,
        #[cfg(target_os = "macos")]
        ProcessIdentity::Macos { start_seconds, .. } => *start_seconds += 1,
        #[cfg(target_os = "windows")]
        ProcessIdentity::Windows {
            creation_time_100ns,
            ..
        } => *creation_time_100ns += 1,
    }
    // A different birth at the same PID proves only that the retained original
    // ended. The current process is neither adopted nor acted upon.
    assert!(original_daemon_ended(&older_birth).unwrap());
    assert!(!original_daemon_ended(&original).unwrap());
}

#[cfg(unix)]
#[test]
fn actual_owned_child_exit_is_observed_after_wait() {
    let mut child = std::process::Command::new("/bin/sh")
        .args(["-c", "read line"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let original = ProcessIdentity::observe(child.id()).unwrap();
    assert!(!original_daemon_ended(&original).unwrap());
    drop(child.stdin.take());
    let _ = child.wait().unwrap();
    assert!(original_daemon_ended(&original).unwrap());
}

#[test]
fn daemon_exit_is_not_session_ack_and_does_not_replace_proxy_or_io_join() {
    let facts = |worker_exited, io_joined, native_settlement| CuaCleanup {
        worker_exited,
        worker_exit_success: Some(false),
        io_joined,
        descendants_confirmed: false,
        native_settlement,
    };
    let settlement = proxy_native_settlement(true, false, true, true, Some(false));
    assert!(matches!(
        settlement,
        CuaNativeSettlement::MacOriginalDaemonExited
    ));
    assert!(!facts(false, true, settlement).complete());
    assert!(!facts(true, false, settlement).complete());
    assert!(facts(true, true, settlement).complete());

    // EOF or a failed end_session, even with a successful proxy exit, cannot
    // supply either kind of native settlement while the original daemon lives.
    let no_ack = proxy_native_settlement(true, false, false, true, Some(true));
    assert!(!facts(true, true, no_ack).complete());
    let ack = proxy_native_settlement(true, true, false, true, Some(true));
    assert!(facts(true, true, ack).complete());
    let proxy_failed = proxy_native_settlement(true, true, false, true, Some(false));
    assert!(!facts(true, true, proxy_failed).complete());
}

#[cfg(unix)]
#[tokio::test]
async fn actual_dead_daemon_still_waits_original_proxy_and_retained_io() {
    let spawn = || {
        let mut command = tokio::process::Command::new("/bin/sh");
        command
            .args(["-c", "read line; exit 7"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null());
        command.spawn().unwrap()
    };
    let mut daemon = spawn();
    let original = ProcessIdentity::observe(daemon.id().unwrap()).unwrap();
    let mut proxy = spawn();
    let mut stdout = proxy.stdout.take().unwrap();
    let (release, retained) = tokio::sync::oneshot::channel::<()>();
    let io = tokio::spawn(async move {
        tokio::io::copy(&mut stdout, &mut tokio::io::sink())
            .await
            .unwrap();
        // Keep actual supervisor-owned work alive after pipe EOF. Completion
        // must wait for this task, not infer it from child/PID disappearance.
        let _ = retained.await;
    });
    drop(daemon.stdin.take());
    let daemon_exit = daemon.wait().await.unwrap();
    assert!(!daemon_exit.success());
    assert!(original_daemon_ended(&original).unwrap());
    assert!(proxy.try_wait().unwrap().is_none());
    let facts = |exited, success, joined| CuaCleanup {
        worker_exited: exited,
        worker_exit_success: success,
        io_joined: joined,
        descendants_confirmed: false,
        native_settlement: proxy_native_settlement(true, false, true, exited, success),
    };
    assert!(!facts(false, None, io.is_finished()).complete());
    drop(proxy.stdin.take());
    let exit = tokio::time::timeout(std::time::Duration::from_secs(5), proxy.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(!exit.success());
    assert!(!facts(true, Some(false), io.is_finished()).complete());
    release.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), io)
        .await
        .unwrap()
        .unwrap();
    let complete = facts(true, Some(false), true);
    assert!(complete.complete());
    // Physical termination never fabricates a successful native result.
    assert_eq!(complete.worker_exit_success, Some(false));
    assert!(matches!(
        complete.native_settlement,
        CuaNativeSettlement::MacOriginalDaemonExited
    ));
}

struct EndFixture {
    replies: Arc<Mutex<std::collections::VecDeque<CallToolResult>>>,
    calls: Arc<Mutex<Vec<String>>>,
}
impl ServerHandler for EndFixture {
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        assert_eq!(request.name, "end_session");
        let session = request.arguments.unwrap()["session"]
            .as_str()
            .unwrap()
            .to_owned();
        self.calls.lock().unwrap().push(session);
        Ok(CallToolResponse::Complete(
            self.replies
                .lock()
                .unwrap()
                .pop_front()
                .expect("no extra RPC permitted"),
        ))
    }
}

fn pending_reply(code: &str, session: &str, in_progress: bool) -> CallToolResult {
    let mut reply = CallToolResult::structured(json!({
        "code":code,"session":session,"cleanup_complete":false,
        "cleanup_in_progress":in_progress,"failed_hooks":[],
    }));
    reply.is_error = Some(true);
    reply
}

#[tokio::test]
async fn actual_original_mcp_peer_continues_only_known_same_session_cleanup() {
    for known in [true, false] {
        let session = "styx-original-cleanup-fixture";
        let first = if known {
            pending_reply("session_cleanup_pending", session, true)
        } else {
            pending_reply("generic_failure", session, false)
        };
        let replies = if known {
            vec![
                first,
                pending_reply("session_cleanup_partial", session, false),
                CallToolResult::structured(json!({"session":session,"active":false})),
            ]
        } else {
            vec![first]
        };
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fixture = EndFixture {
            replies: Arc::new(Mutex::new(replies.into())),
            calls: calls.clone(),
        };
        let (server_io, client_io) = tokio::io::duplex(65536);
        let (server, client) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(fixture.serve(server_io), ().serve(client_io))
        })
        .await
        .unwrap();
        let mut server = server.unwrap();
        let mut client = client.unwrap();
        // Invoke the exact RPC/decoder function used by production cleanup.
        let mut result = end_session(client.peer().clone(), session.into()).await;
        if known {
            assert_eq!(result, EndSessionOutcome::RetryKnown);
            result = end_session(client.peer().clone(), session.into()).await;
            assert_eq!(result, EndSessionOutcome::RetryKnown);
            result = end_session(client.peer().clone(), session.into()).await;
            assert_eq!(result, EndSessionOutcome::Ended);
            assert_eq!(*calls.lock().unwrap(), vec![session; 3]);
        } else {
            assert_eq!(result, EndSessionOutcome::Unknown);
            tokio::task::yield_now().await;
            assert_eq!(*calls.lock().unwrap(), vec![session]);
        }
        client.close().await.unwrap();
        server.close().await.unwrap();
    }
}

#[test]
fn malformed_or_foreign_cleanup_errors_are_never_retry_admission() {
    let session = "styx-original-cleanup-fixture";
    for reply in [
        pending_reply("session_cleanup_pending", "styx-other-owner", true),
        pending_reply("session_cleanup_pending", session, false),
        pending_reply("session_cleanup_partial", session, true),
        CallToolResult::structured(json!({"session":session,"code":"session_cleanup_pending"})),
    ] {
        assert_eq!(
            end_session_outcome(session, &reply),
            EndSessionOutcome::Unknown
        );
    }
}
