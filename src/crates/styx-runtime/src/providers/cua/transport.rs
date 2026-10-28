//! Admission around the official bounded AsyncRwTransport, not a codec.
//! Only the one original outbound request's response reaches rmcp. Native
//! requests never reach SDK handler spawning; logging/progress are deliberately
//! unused, silently discarded with finite credits, and never traced/persisted.
use super::{CuaIoBudget, FRAME_BYTES, REQUEST_BYTES, bounded_bytes, capability};
use rmcp::{
    RoleClient,
    model::{ClientNotification, ClientRequest, JsonRpcMessage, RequestId, ServerNotification},
    service::{RxJsonRpcMessage, TxJsonRpcMessage},
    transport::{Transport, async_rw::AsyncRwTransport},
};
use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

fn permission_query(name: &str, args: Option<&serde_json::Map<String, serde_json::Value>>) -> bool {
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        super::permissions::query_allowed(name, args)
    }
    #[cfg(target_os = "macos")]
    {
        let _ = (name, args);
        false
    }
}

const NOTIFICATIONS_PER_REQUEST: u16 = 64;
const TOTAL_DROPPED_NOTIFICATIONS: u32 = 4096;
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("cua_transport_refused")]
pub(super) struct TransportRefused;
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Fresh,
    AwaitingInitialize,
    InitializedNotification,
    Ready,
}
#[derive(Clone, Copy)]
enum Kind {
    Initialize,
    Catalog,
    Tool,
}
struct State {
    phase: Phase,
    pending: Option<(RequestId, Kind)>,
    catalog_seen: bool,
    notifications: u16,
    total_notifications: u32,
    fenced: bool,
    raw_remaining: usize,
}
struct Admission {
    state: Mutex<State>,
    stop: CancellationToken,
    _budget: Arc<CuaIoBudget>,
}
impl Admission {
    fn new(stop: CancellationToken, budget: Arc<CuaIoBudget>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                phase: Phase::Fresh,
                pending: None,
                catalog_seen: false,
                notifications: 0,
                total_notifications: 0,
                fenced: false,
                raw_remaining: 0,
            }),
            stop,
            _budget: budget,
        })
    }
    fn fence(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.fenced = true
        }
        self.stop.cancel();
    }
    fn admit_send(&self, item: &TxJsonRpcMessage<RoleClient>) -> Result<(), TransportRefused> {
        if bounded_bytes(item, REQUEST_BYTES).is_err() {
            self.fence();
            return Err(TransportRefused);
        }
        let result = (|| {
            let mut state = self.state.lock().map_err(|_| TransportRefused)?;
            if state.fenced || self.stop.is_cancelled() {
                return Err(TransportRefused);
            }
            match item {
                JsonRpcMessage::Request(request) => {
                    if state.pending.is_some() {
                        return Err(TransportRefused);
                    }
                    let kind = match &request.request {
                        ClientRequest::InitializeRequest(_) if state.phase == Phase::Fresh => {
                            state.phase = Phase::AwaitingInitialize;
                            Kind::Initialize
                        }
                        ClientRequest::ListToolsRequest(_)
                            if state.phase == Phase::Ready && !state.catalog_seen =>
                        {
                            Kind::Catalog
                        }
                        ClientRequest::CallToolRequest(value)
                            if state.phase == Phase::Ready
                                && state.catalog_seen
                                && (capability(value.params.name.as_ref()).is_ok()
                                    || permission_query(
                                        value.params.name.as_ref(),
                                        value.params.arguments.as_ref(),
                                    )
                                    || super::ax_write::private_name(
                                        value.params.name.as_ref(),
                                    )) =>
                        {
                            Kind::Tool
                        }
                        _ => return Err(TransportRefused),
                    };
                    state.notifications = 0;
                    // Reset only for a newly admitted original request, never
                    // on response, timeout, cancellation or close. Includes
                    // every raw byte, including SDK-ignored malformed lines.
                    state.raw_remaining = FRAME_BYTES;
                    state.pending = Some((request.id.clone(), kind));
                    Ok(())
                }
                JsonRpcMessage::Notification(notification) => match &notification.notification {
                    ClientNotification::InitializedNotification(_)
                        if state.phase == Phase::InitializedNotification
                            && state.pending.is_none() =>
                    {
                        state.phase = Phase::Ready;
                        Ok(())
                    }
                    // SDK timeout cancellation is only for the still-pending exact request.
                    // It is not an execution/rollback acknowledgement and cannot reopen it.
                    ClientNotification::CancelledNotification(value)
                        if value.params.request_id.as_ref().is_some_and(|id| {
                            state
                                .pending
                                .as_ref()
                                .is_some_and(|(pending, _)| id == pending)
                        }) =>
                    {
                        Ok(())
                    }
                    _ => Err(TransportRefused),
                },
                _ => Err(TransportRefused),
            }
        })();
        if result.is_err() {
            self.fence()
        }
        result
    }
    fn admit_receive(&self, item: &RxJsonRpcMessage<RoleClient>) -> Result<bool, TransportRefused> {
        let result = (|| {
            let mut state = self.state.lock().map_err(|_| TransportRefused)?;
            if state.fenced || self.stop.is_cancelled() {
                return Err(TransportRefused);
            }
            let response_id = match item {
                JsonRpcMessage::Response(value) => Some(&value.id),
                JsonRpcMessage::Error(value) => value.id.as_ref(),
                JsonRpcMessage::Notification(value) => {
                    if !matches!(
                        &value.notification,
                        ServerNotification::LoggingMessageNotification(_)
                            | ServerNotification::ProgressNotification(_)
                    ) {
                        return Err(TransportRefused);
                    }
                    if state.notifications >= NOTIFICATIONS_PER_REQUEST
                        || state.total_notifications >= TOTAL_DROPPED_NOTIFICATIONS
                    {
                        return Err(TransportRefused);
                    }
                    state.notifications += 1;
                    state.total_notifications += 1;
                    return Ok(false);
                }
                // No sampling, roots, elicitation or arbitrary native peer requests. These
                // must never enter rmcp's detached request/notification handler queues.
                _ => return Err(TransportRefused),
            };
            let (pending, kind) = state.pending.as_ref().ok_or(TransportRefused)?;
            if response_id != Some(pending) {
                return Err(TransportRefused);
            }
            let kind = *kind;
            state.pending = None;
            match kind {
                Kind::Initialize => state.phase = Phase::InitializedNotification,
                Kind::Catalog => state.catalog_seen = true,
                Kind::Tool => {}
            }
            Ok(true)
        })();
        if result.is_err() {
            self.fence()
        }
        result
    }
}

pub(super) struct AdmittedTransport<T> {
    inner: T,
    admission: Arc<Admission>,
}
// No line/JSON parsing here: the mature SDK remains the sole codec. Raw
// credit is deliberately aggregate per original request (including harmless
// logging), so ignored/oversized/empty input cannot bypass typed admission.
pub(super) struct RawCreditRead<R> {
    inner: R,
    admission: Arc<Admission>,
}
impl<R: AsyncRead + Unpin> AsyncRead for RawCreditRead<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let this = self.get_mut();
        let mut state = match this.admission.state.lock() {
            Ok(value) => value,
            Err(_) => {
                this.admission.stop.cancel();
                return Poll::Ready(Err(io::Error::other("cua_transport_fenced")));
            }
        };
        if state.fenced || this.admission.stop.is_cancelled() || state.raw_remaining == 0 {
            state.fenced = true;
            this.admission.stop.cancel();
            return Poll::Ready(Err(io::Error::other("cua_raw_credit_exhausted")));
        }
        let count = buf.remaining().min(state.raw_remaining);
        let (result, filled) = {
            let mut limited = ReadBuf::new(buf.initialize_unfilled_to(count));
            let result = Pin::new(&mut this.inner).poll_read(cx, &mut limited);
            (result, limited.filled().len())
        };
        match result {
            Poll::Ready(Ok(())) => {
                state.raw_remaining -= filled;
                drop(state);
                buf.advance(filled);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                state.fenced = true;
                this.admission.stop.cancel();
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
impl<R, W> AdmittedTransport<AsyncRwTransport<RoleClient, RawCreditRead<R>, W>>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    pub(super) fn from_io(
        read: R,
        write: W,
        stop: CancellationToken,
        budget: Arc<CuaIoBudget>,
    ) -> Self {
        let admission = Admission::new(stop, budget);
        let read = RawCreditRead {
            inner: read,
            admission: admission.clone(),
        };
        Self {
            inner: AsyncRwTransport::new(read, write).with_max_line_length(FRAME_BYTES),
            admission,
        }
    }
}
impl<T: Transport<RoleClient> + 'static> Transport<RoleClient> for AdmittedTransport<T> {
    type Error = TransportRefused;
    fn send(
        &mut self,
        item: TxJsonRpcMessage<RoleClient>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
        // Reserve the actual SDK request ID before invoking the underlying send. If
        // that future is dropped/failed, fence; never clear Unknown to admit a retry.
        let accepted = self.admission.admit_send(&item);
        let admission = self.admission.clone();
        let future = accepted.is_ok().then(|| self.inner.send(item));
        let guard = admission.stop.clone().drop_guard();
        async move {
            accepted?;
            let Some(future) = future else {
                return Err(TransportRefused);
            };
            match future.await {
                Ok(()) => {
                    guard.disarm();
                    Ok(())
                }
                Err(_) => {
                    admission.fence();
                    Err(TransportRefused)
                }
            }
        }
    }
    async fn receive(&mut self) -> Option<RxJsonRpcMessage<RoleClient>> {
        loop {
            if self.admission.stop.is_cancelled() {
                return None;
            }
            let value = match self.inner.receive().await {
                Some(value) => value,
                None => {
                    self.admission.fence();
                    return None;
                }
            };
            match self.admission.admit_receive(&value) {
                Ok(true) => return Some(value),
                Ok(false) => {}
                Err(_) => return None,
            }
        }
    }
    async fn close(&mut self) -> Result<(), Self::Error> {
        self.admission.fence();
        self.inner.close().await.map_err(|_| TransportRefused)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn client(value: serde_json::Value) -> TxJsonRpcMessage<RoleClient> {
        serde_json::from_value(value).unwrap()
    }
    fn server(value: serde_json::Value) -> RxJsonRpcMessage<RoleClient> {
        serde_json::from_value(value).unwrap()
    }
    async fn new_gate() -> Arc<Admission> {
        let allocator = Arc::new(tokio::sync::Semaphore::new(super::super::IO_BYTES));
        let permit = allocator
            .acquire_many_owned(super::super::IO_BYTES as u32)
            .await
            .unwrap();
        Admission::new(
            CancellationToken::new(),
            CuaIoBudget::from_reserved(permit).unwrap(),
        )
    }
    #[tokio::test]
    async fn typed_admission_rejects_foreign_duplicate_peer_requests_and_notification_flood() {
        let init = client(
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"owned-fixture","version":"1"}}}),
        );
        let init_response = server(
            json!({"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"cua-driver","version":"0.36.0"}}}),
        );
        let gate = new_gate().await;
        gate.admit_send(&init).unwrap();
        assert!(gate.admit_receive(&init_response).unwrap());
        gate.admit_send(&client(
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        ))
        .unwrap();
        let list = client(json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}));
        gate.admit_send(&list).unwrap();
        let list_response = server(json!({"jsonrpc":"2.0","id":2,"result":{"tools":[]}}));
        assert!(gate.admit_receive(&list_response).unwrap());
        assert!(gate.admit_receive(&list_response).is_err());
        assert!(gate.stop.is_cancelled());
        let wrong = new_gate().await;
        wrong.admit_send(&init).unwrap();
        let response = server(
            json!({"jsonrpc":"2.0","id":99,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"cua-driver","version":"0.36.0"}}}),
        );
        assert!(wrong.admit_receive(&response).is_err());
        let peer = new_gate().await;
        assert!(
            peer.admit_receive(&server(json!({"jsonrpc":"2.0","id":7,"method":"ping"})))
                .is_err()
        );
        let flood = new_gate().await;
        let progress = server(
            json!({"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"ignored","progress":1}}),
        );
        for _ in 0..NOTIFICATIONS_PER_REQUEST {
            assert!(!flood.admit_receive(&progress).unwrap());
        }
        assert!(flood.admit_receive(&progress).is_err());
    }
}

#[cfg(test)]
#[path = "transport_tests.rs"]
mod raw_credit_tests;
