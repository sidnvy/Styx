//! Owned duplex IO and the real official AsyncRw codec; no native/GUI process.
use super::*;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::io::{AsyncWriteExt, duplex, split};

fn initialize() -> TxJsonRpcMessage<RoleClient> {
    serde_json::from_value(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"owned-raw-credit-fixture","version":"1"}}})).unwrap()
}
fn initialized() -> TxJsonRpcMessage<RoleClient> {
    serde_json::from_value(json!({"jsonrpc":"2.0","method":"notifications/initialized"})).unwrap()
}
fn response() -> Vec<u8> {
    let mut bytes=serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"cua-driver","version":"0.47.24"}}})).unwrap();
    bytes.push(b'\n');
    bytes
}
async fn budget() -> Arc<CuaIoBudget> {
    let allocator = Arc::new(tokio::sync::Semaphore::new(super::super::IO_BYTES));
    CuaIoBudget::from_reserved(
        allocator
            .acquire_many_owned(super::super::IO_BYTES as u32)
            .await
            .unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn actual_codec_cannot_ack_after_oversize_or_ignored_bad_frame_credit_exhaustion() {
    for oversized in [true, false] {
        let (mut peer, local) = duplex(4096);
        let (read, write) = split(local);
        let stop = CancellationToken::new();
        let mut transport = AdmittedTransport::from_io(read, write, stop.clone(), budget().await);
        transport.send(initialize()).await.unwrap();
        let mut raw = if oversized {
            vec![b'x'; FRAME_BYTES + 256]
        } else {
            let mut out = Vec::new();
            for _ in 0..(FRAME_BYTES / 4096 + 1) {
                out.extend_from_slice(&vec![b'z'; 4095]);
                out.push(b'\n');
            }
            out
        };
        raw.push(b'\n');
        raw.extend_from_slice(&response());
        let writer = tokio::spawn(async move {
            let result = peer.write_all(&raw).await;
            drop(peer);
            result
        });
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), transport.receive())
            .await
            .expect("bounded raw input must settle");
        assert!(
            result.is_none(),
            "SDK must not see the later matching reply after exhausting original credit"
        );
        assert!(stop.is_cancelled());
        assert_eq!(transport.admission.state.lock().unwrap().raw_remaining, 0);
        transport.close().await.unwrap();
        assert_eq!(transport.admission.state.lock().unwrap().raw_remaining, 0);
        assert!(transport.send(initialized()).await.is_err());
        drop(transport);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), writer)
            .await
            .expect("owned writer joined")
            .expect("owned writer did not panic");
    }
}

#[tokio::test]
async fn normal_response_and_unpolled_send_cancel_preserve_original_credit_semantics() {
    let (mut peer, local) = duplex(4096);
    let (read, write) = split(local);
    let stop = CancellationToken::new();
    let mut transport = AdmittedTransport::from_io(read, write, stop.clone(), budget().await);
    transport.send(initialize()).await.unwrap();
    peer.write_all(&response()).await.unwrap();
    assert!(matches!(
        transport.receive().await,
        Some(JsonRpcMessage::Response(_))
    ));
    let remaining = transport.admission.state.lock().unwrap().raw_remaining;
    assert!(remaining > 0 && remaining < FRAME_BYTES);
    transport.send(initialized()).await.unwrap();
    assert_eq!(
        transport.admission.state.lock().unwrap().raw_remaining,
        remaining
    );
    transport.close().await.unwrap();
    assert!(stop.is_cancelled());
    assert_eq!(
        transport.admission.state.lock().unwrap().raw_remaining,
        remaining
    );
    drop(transport);
    drop(peer);
    // Reservation occurs synchronously before the send future's first poll.
    // Dropping that future must fence, not silently return/reset request credit.
    let (peer, local) = duplex(4096);
    let (read, write) = split(local);
    let stop = CancellationToken::new();
    let mut transport = AdmittedTransport::from_io(read, write, stop.clone(), budget().await);
    let send = transport.send(initialize());
    drop(send);
    assert!(stop.is_cancelled());
    {
        let state = transport.admission.state.lock().unwrap();
        assert_eq!(state.raw_remaining, FRAME_BYTES);
        assert!(state.pending.is_some());
    }
    assert!(transport.send(initialize()).await.is_err());
    assert_eq!(
        transport.admission.state.lock().unwrap().raw_remaining,
        FRAME_BYTES
    );
    drop(transport);
    drop(peer);
}

#[tokio::test]
async fn actual_codec_cleanup_survives_business_stop_only_with_production_split_tokens() {
    for legacy_shared_token in [true, false] {
        let (business, io_stop) = super::super::macos_cleanup::resource_stop_tokens();
        let transport_stop = if legacy_shared_token {
            business.clone()
        } else {
            io_stop
        };
        let (peer, local) = duplex(4096);
        let mut peer = BufReader::new(peer);
        let (read, write) = split(local);
        let mut transport =
            AdmittedTransport::from_io(read, write, transport_stop.clone(), budget().await);
        let mut line = String::new();
        transport.send(initialize()).await.unwrap();
        peer.read_line(&mut line).await.unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&line).unwrap()["method"],
            "initialize"
        );
        peer.get_mut().write_all(&response()).await.unwrap();
        assert!(transport.receive().await.is_some());
        transport.send(initialized()).await.unwrap();
        line.clear();
        peer.read_line(&mut line).await.unwrap();
        let list =
            serde_json::from_value(json!({"jsonrpc":"2.0","id":2,"method":"tools/list"})).unwrap();
        transport.send(list).await.unwrap();
        line.clear();
        peer.read_line(&mut line).await.unwrap();
        peer.get_mut()
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[]}}\n")
            .await
            .unwrap();
        assert!(transport.receive().await.is_some());

        // This is the SAME factory and supervisor cancellation function used
        // by Mac Resource, not a pair of unrelated ad hoc fixture tokens.
        let host = CancellationToken::new();
        let business_owner = business.clone();
        let io_owner = transport_stop.clone();
        let supervisor = tokio::spawn(async move {
            super::super::macos_cleanup::wait_cleanup_request(&host, &business_owner, &io_owner)
                .await;
        });
        business.cancel();
        supervisor.await.unwrap();
        let name = if cfg!(target_os = "macos") {
            "end_session"
        } else {
            "list_apps"
        };
        let arguments = if cfg!(target_os = "macos") {
            json!({"session":"styx-cleanup-fixture"})
        } else {
            json!({})
        };
        let call = serde_json::from_value(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":name,"arguments":arguments}})).unwrap();
        let sent = transport.send(call).await;
        if legacy_shared_token {
            assert!(
                sent.is_err(),
                "old resource.stop wiring prevents cleanup before any bytes are sent"
            );
            assert!(transport.receive().await.is_none());
            line.clear();
            assert!(
                tokio::time::timeout(
                    std::time::Duration::from_millis(20),
                    peer.read_line(&mut line)
                )
                .await
                .is_err()
            );
        } else {
            sent.unwrap();
            line.clear();
            peer.read_line(&mut line).await.unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&line).unwrap()["params"]["name"],
                name
            );
            peer.get_mut().write_all(b"{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"isError\":false,\"content\":[],\"structuredContent\":{\"session\":\"styx-cleanup-fixture\",\"active\":false}}}\n").await.unwrap();
            assert!(transport.receive().await.is_some());
            assert!(!transport_stop.is_cancelled());
        }
        assert!(
            business.is_cancelled(),
            "cleanup never restores business admission"
        );
        transport.close().await.unwrap();
        assert!(transport_stop.is_cancelled());
        assert!(transport.send(initialize()).await.is_err());
    }
}

#[tokio::test]
async fn actual_codec_eof_still_requests_resource_cleanup_with_split_tokens() {
    let (business, io_stop) = super::super::macos_cleanup::resource_stop_tokens();
    let host = CancellationToken::new();
    let business_owner = business.clone();
    let io_owner = io_stop.clone();
    let supervisor = tokio::spawn(async move {
        super::super::macos_cleanup::wait_cleanup_request(&host, &business_owner, &io_owner).await;
    });
    let (peer, local) = duplex(4096);
    let (read, write) = split(local);
    let mut transport = AdmittedTransport::from_io(read, write, io_stop.clone(), budget().await);
    transport.send(initialize()).await.unwrap();
    assert!(!business.is_cancelled());
    drop(peer);
    assert!(transport.receive().await.is_none());
    tokio::time::timeout(std::time::Duration::from_secs(5), supervisor)
        .await
        .unwrap()
        .unwrap();
    assert!(io_stop.is_cancelled() && business.is_cancelled());
    transport.close().await.unwrap();
}
