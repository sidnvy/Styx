//! Owned duplex IO and the real official AsyncRw codec; no native/GUI process.
use super::*;
use serde_json::json;
use tokio::io::{AsyncWriteExt, duplex, split};

fn initialize() -> TxJsonRpcMessage<RoleClient> {
    serde_json::from_value(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"owned-raw-credit-fixture","version":"1"}}})).unwrap()
}
fn initialized() -> TxJsonRpcMessage<RoleClient> {
    serde_json::from_value(json!({"jsonrpc":"2.0","method":"notifications/initialized"})).unwrap()
}
fn response() -> Vec<u8> {
    let mut bytes=serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"cua-driver","version":"0.36.0"}}})).unwrap();
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
