//! Cheap production Host/Core/Codex-adapter fixture. Native replies travel over
//! framed owned pipes; the paired socket scenario remains the native oracle.
use super::*;
use crate::providers::codex::CodexStdio;
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use styx_contracts::{capability::*, error::Recovery};
use styx_core::{operations::OperationLedger, policy::AdmissionFacts};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
struct Peer {
    exited: AtomicBool,
    drained: AtomicBool,
    starts: AtomicUsize,
}
fn facts() -> AdmissionFacts {
    AdmissionFacts {
        device_id: "settled-exec-device".try_into().unwrap(),
        grant_revision: 1,
        local_policy_allowed: true,
        descriptor: CapabilityDescriptor {
            contract_version: 1,
            capability_id: CapabilityId::ExecRun,
            scope: Scope::Host,
            provider_id: "codex".try_into().unwrap(),
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
    }
}
fn fixture() -> (
    HostCoordinator,
    HostAuthority,
    Arc<Peer>,
    tokio::task::JoinHandle<()>,
) {
    let (adapter, io) = CodexStdio::fixture_io(16); // Exact limit in the failing paired fixture.
    let (host, authority) = HostCoordinator::new_owned(
        adapter,
        OperationLedger::new("settled-exec-host".try_into().unwrap()),
        facts(),
        4,
    )
    .unwrap();
    let peer = Arc::new(Peer {
        exited: AtomicBool::new(true),
        drained: AtomicBool::new(true),
        starts: AtomicUsize::new(0),
    });
    let worker = peer.clone();
    let driver = tokio::spawn(async move {
        let (reader, mut writer) = tokio::io::split(io);
        let mut lines = BufReader::new(reader).lines();
        while let Some(line) = lines.next_line().await.unwrap() {
            let q: Value = serde_json::from_str(&line).unwrap();
            let result = match q["method"].as_str().unwrap() {
                "process/start" => {
                    worker.starts.fetch_add(1, Ordering::Relaxed);
                    json!({"processId":q["params"]["processId"]})
                }
                "process/read" => {
                    json!({"chunks":[],"nextSeq":1,"exited":worker.exited.load(Ordering::Relaxed),"exitCode":if worker.exited.load(Ordering::Relaxed){json!(0)}else{Value::Null},"closed":worker.drained.load(Ordering::Relaxed),"failure":null})
                }
                method => panic!("unexpected native action {method}"),
            };
            writer
                .write_all(format!("{}\n", json!({"id":q["id"],"result":result})).as_bytes())
                .await
                .unwrap();
        }
    });
    (host, authority, peer, driver)
}
fn owner(n: u64) -> OwnerRef {
    OwnerRef {
        owner_id: format!("fixture:exec-{n}").try_into().unwrap(),
        owner_epoch: paired_owner_epoch(&"exec-capacity-epoch".try_into().unwrap(), n),
    }
}
fn protocol<'a>(host: &HostCoordinator, authority: &'a HostAuthority) -> HostProtocol<'a> {
    let p = HostProtocol::new_paired(
        PairedTrustedProfile {
            endpoint: "wss://localhost/settled-exec".into(),
            gateway_namespace: "exec-capacity-gateway".try_into().unwrap(),
            device_id: facts().device_id,
            host_generation: "settled-exec-host".try_into().unwrap(),
        },
        host.clone(),
        authority,
    )
    .unwrap();
    p.accept_epoch(&"exec-capacity-epoch".try_into().unwrap())
        .unwrap();
    p
}
async fn prepare(protocol: &HostProtocol<'_>, owner: &OwnerRef) -> ResourceTarget {
    assert!(matches!(
        protocol.control(&Call::OwnerOpen {
            owner: owner.clone(),
            grant_revision: 1
        }),
        Some(Reply::OwnerOpened { .. })
    ));
    let reply=protocol.handle(Call::PrepareStart {owner:owner.clone(),grant_revision:1,timeout_ms:5000,spec:serde_json::value::to_raw_value(&json!({"argv":["/bin/sh","-c","fixture-only"],"cwd_file_uri":"file:///owned","environment":{},"tty":false})).unwrap()}).await;
    match reply {
        Reply::Prepared { snapshot } => ResourceTarget {
            operation_id: snapshot.operation_id,
            payload_digest: snapshot.payload_digest,
        },
        _ => panic!("prepare refused"),
    }
}
async fn read(protocol: &HostProtocol<'_>, owner: &OwnerRef, target: &ResourceTarget) -> Reply {
    protocol
        .handle(Call::Read {
            owner: owner.clone(),
            target: target.clone(),
            grant_revision: 1,
            timeout_ms: 5000,
            max_bytes: 1024,
            wait_ms: 0,
        })
        .await
}
#[tokio::test]
async fn sixty_four_open_owners_with_settled_execs_do_not_exhaust_sixteen_process_slots() {
    let (host, authority, peer, driver) = fixture();
    let protocol = protocol(&host, &authority);
    let mut first = None;
    for n in 1..=64 {
        let owner = owner(n);
        let target = prepare(&protocol, &owner).await;
        if first.is_none() {
            first = Some(target.clone());
        }
        assert!(
            matches!(protocol.handle(Call::DispatchStart{owner:owner.clone(),target:target.clone()}).await,Reply::Start{dispatch,..} if dispatch=="started"),
            "start owner {n}"
        );
        assert!(matches!(
            read(&protocol, &owner, &target).await,
            Reply::Read {
                liveness: ExecutionLiveness::Exited,
                output_drain: OutputDrain::Drained,
                exit_code: Some(0),
                ..
            }
        ));
        assert_eq!(
            host.retained_exec_processes_for_test(),
            0,
            "settled owner {n} must release provider capacity before terminal success"
        );
        assert!(
            protocol.owner(&owner).is_ok(),
            "MCP/Host owner remains open; no DELETE or revocation"
        );
    }
    assert_eq!(peer.starts.load(Ordering::Relaxed), 64);
    assert_eq!(protocol.owners.lock().unwrap().owners.len(), 64);
    // Historical completion remains available, but must not dispatch a second start.
    let previous = owner(1);
    assert!(protocol.owner(&previous).is_ok());
    let target = first.unwrap();
    assert!(
        matches!(protocol.handle(Call::InspectStart {owner:previous.clone(),target:target.clone()}).await,Reply::Inspected {snapshot} if snapshot.liveness==ExecutionLiveness::Exited)
    );
    assert!(
        matches!(protocol.handle(Call::DispatchStart {owner:previous,target}).await,Reply::Start {dispatch,..} if dispatch=="existing_no_replay")
    );
    assert_eq!(
        peer.starts.load(Ordering::Relaxed),
        64,
        "retiring provider storage must not reopen Core dispatch"
    );
    host.close_exec_fixture_for_test().await;
    driver.await.unwrap();
}
#[tokio::test]
async fn sixteen_live_execs_refuse_the_next_start_without_native_io_or_uncertainty() {
    let (host, authority, peer, driver) = fixture();
    let protocol = protocol(&host, &authority);
    peer.exited.store(false, Ordering::Relaxed);
    peer.drained.store(false, Ordering::Relaxed);
    let mut targets = vec![];
    for n in 1..=16 {
        let o = owner(n);
        let t = prepare(&protocol, &o).await;
        assert!(
            matches!(protocol.handle(Call::DispatchStart{owner:o.clone(),target:t.clone()}).await,Reply::Start{dispatch,..} if dispatch=="started")
        );
        assert!(matches!(
            read(&protocol, &o, &t).await,
            Reply::Read {
                liveness: ExecutionLiveness::Running,
                ..
            }
        ));
        targets.push((o, t));
    }
    assert_eq!(host.retained_exec_processes_for_test(), 16);
    let rejected = owner(17);
    let target = prepare(&protocol, &rejected).await;
    assert!(matches!(
        protocol
            .handle(Call::DispatchStart {
                owner: rejected,
                target
            })
            .await,
        Reply::Error {
            category: ErrorCategory::Busy,
            certainty: ExecutionCertainty::NotDispatched,
            cursor_may_be_consumed: false
        }
    ));
    assert_eq!(
        peer.starts.load(Ordering::Relaxed),
        16,
        "capacity failure must send no process/start frame"
    );
    // Exit alone is insufficient: undrained output still owns a process slot.
    peer.exited.store(true, Ordering::Relaxed);
    assert!(matches!(
        read(&protocol, &targets[0].0, &targets[0].1).await,
        Reply::Read {
            liveness: ExecutionLiveness::Exited,
            output_drain: OutputDrain::Open,
            ..
        }
    ));
    assert_eq!(host.retained_exec_processes_for_test(), 16);
    peer.drained.store(true, Ordering::Relaxed);
    for (o, t) in targets {
        assert!(matches!(
            read(&protocol, &o, &t).await,
            Reply::Read {
                exit_code: Some(0),
                output_drain: OutputDrain::Drained,
                ..
            }
        ));
    }
    assert_eq!(host.retained_exec_processes_for_test(), 0);
    let fresh = owner(18);
    let target = prepare(&protocol, &fresh).await;
    assert!(
        matches!(protocol.handle(Call::DispatchStart{owner:fresh.clone(),target:target.clone()}).await,Reply::Start{dispatch,..} if dispatch=="started")
    );
    read(&protocol, &fresh, &target).await;
    assert_eq!(peer.starts.load(Ordering::Relaxed), 17);
    host.close_exec_fixture_for_test().await;
    driver.await.unwrap();
}
