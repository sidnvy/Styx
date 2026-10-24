use super::{
    MESSAGE_BYTES,
    lifecycle::{GatewayOwnerLifecycle, Life},
};
use futures_util::Stream;
use rmcp::{
    RoleServer,
    model::{ClientJsonRpcMessage, ServerJsonRpcMessage},
    transport::{
        Transport, WorkerTransport,
        streamable_http_server::{
            SessionId, SessionManager,
            session::local::{
                LocalSessionManager, LocalSessionManagerError, LocalSessionWorker,
                LocalSessionWorkerError,
            },
        },
    },
};
use std::{
    io::{self, Write},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

#[derive(Debug, thiserror::Error)]
pub(super) enum SessionError {
    #[error("SDK session rejected")]
    Local(#[from] LocalSessionManagerError),
    #[error("session capacity or lifetime refused")]
    Refused,
}
#[derive(Debug, thiserror::Error)]
pub(super) enum TransportError {
    #[error("official SDK transport rejected message")]
    Local,
    #[error("bounded message rejected after possible action; no replay")]
    TooLarge,
    #[error("owner fence refused; cleanup remains unresolved")]
    FenceRefused,
}
impl From<LocalSessionWorkerError> for TransportError {
    fn from(_: LocalSessionWorkerError) -> Self {
        Self::Local
    }
}
struct SizeWriter(usize);
impl Write for SizeWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("message limit"))?;
        if self.0 > MESSAGE_BYTES {
            return Err(io::Error::other("message limit"));
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
pub(super) fn bounded_message(value: &impl serde::Serialize) -> bool {
    serde_json::to_writer(SizeWriter(0), value).is_ok()
}
pub(super) struct BoundedManager<L: GatewayOwnerLifecycle> {
    inner: LocalSessionManager,
    created: AtomicBool,
    pub id: Mutex<Option<SessionId>>,
    pub life: Arc<Life<L>>,
    pub negotiated: Mutex<Option<String>>,
}
impl<L: GatewayOwnerLifecycle> BoundedManager<L> {
    /// Only a never-attempted transport is exempt from a join. Once creation
    /// starts, a failed/unknown SDK result is not fabricated into quiescence.
    pub(super) fn local_transport_quiescent(&self) -> bool {
        let facts = self.life.facts.lock().expect("session lifetime");
        !self.created.load(Ordering::Acquire) || facts.transport_joined
    }
    pub fn new(life: Arc<Life<L>>) -> Self {
        let mut inner = LocalSessionManager::default();
        inner.session_config.channel_capacity = 1;
        inner.session_config.init_timeout = Some(Duration::from_secs(5));
        inner.session_config.keep_alive = Some(Duration::from_secs(60));
        inner.session_config.sse_retry = None;
        inner.session_config.completed_cache_ttl = Duration::ZERO;
        Self {
            inner,
            created: AtomicBool::new(false),
            id: Mutex::new(None),
            life,
            negotiated: Mutex::new(None),
        }
    }
}
pub(super) struct ObservedTransport<L: GatewayOwnerLifecycle> {
    inner: WorkerTransport<LocalSessionWorker>,
    life: Arc<Life<L>>,
}
impl<L: GatewayOwnerLifecycle> Transport<RoleServer> for ObservedTransport<L> {
    type Error = TransportError;
    fn send(
        &mut self,
        message: ServerJsonRpcMessage,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
        // Typed value already exists; backend source allocation must also be bounded.
        // This check occurs before official session caches duplicate the message.
        let allowed = bounded_message(&message);
        let life = self.life.clone();
        let sent = allowed.then(|| self.inner.send(message));
        async move {
            match sent {
                Some(sent) => sent.await.map_err(TransportError::from),
                None => {
                    let _ = life.close();
                    Err(TransportError::TooLarge)
                }
            }
        }
    }
    async fn receive(&mut self) -> Option<ClientJsonRpcMessage> {
        self.inner.receive().await
    }
    async fn close(&mut self) -> Result<(), Self::Error> {
        // SDK idle/error termination also fences before any asynchronous join,
        // rather than relying on the later manager callback or HTTP DELETE.
        let fenced = self.life.close();
        let result = self.inner.close().await.map_err(TransportError::from);
        if result.is_ok() {
            self.life
                .facts
                .lock()
                .expect("session lifetime")
                .transport_joined = true;
        }
        if fenced.is_err() {
            return Err(TransportError::FenceRefused);
        }
        result
    }
}
impl<L: GatewayOwnerLifecycle> Drop for ObservedTransport<L> {
    fn drop(&mut self) {
        let _ = self.life.close();
    } // signal/fence only; never a join claim
}
impl<L: GatewayOwnerLifecycle> SessionManager for BoundedManager<L> {
    type Error = SessionError;
    type Transport = ObservedTransport<L>;
    async fn create_session(&self) -> Result<(SessionId, Self::Transport), Self::Error> {
        {
            // Register the attempt under the same synchronous close gate. A
            // late SDK creation cannot race a never-attempted shutdown sample.
            let facts = self.life.facts.lock().expect("session lifetime");
            if facts.closing || self.created.swap(true, Ordering::AcqRel) {
                return Err(SessionError::Refused);
            }
        }
        let (id, transport) = self.inner.create_session().await?;
        *self.life.cancellation.lock().expect("session cancellation") =
            Some(transport.cancel_token());
        *self.id.lock().expect("SDK session id") = Some(id.clone());
        Ok((
            id,
            ObservedTransport {
                inner: transport,
                life: self.life.clone(),
            },
        ))
    }
    async fn initialize_session(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<ServerJsonRpcMessage, Self::Error> {
        if !self.life.is_active() {
            return Err(SessionError::Refused);
        }
        let response = self.inner.initialize_session(id, message).await?;
        if let ServerJsonRpcMessage::Response(reply) = &response
            && let rmcp::model::ServerResult::InitializeResult(result) = &reply.result
        {
            *self.negotiated.lock().expect("negotiated version") =
                Some(result.protocol_version.as_str().to_owned());
        }
        Ok(response)
    }
    async fn has_session(&self, id: &SessionId) -> Result<bool, Self::Error> {
        Ok(self.life.is_active() && self.inner.has_session(id).await?)
    }
    async fn close_session(&self, id: &SessionId) -> Result<(), Self::Error> {
        self.life.close().map_err(|_| SessionError::Refused)?;
        // Cancellation token wakes the official worker even if a stream is backpressured.
        self.inner.close_session(id).await?;
        Ok(()) // means close accepted, not transport joined/owner cleanup completed
    }
    async fn create_stream(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<
        impl Stream<Item = rmcp::transport::common::server_side_http::ServerSseMessage>
        + Send
        + Sync
        + 'static,
        Self::Error,
    > {
        if !self.life.is_active() {
            return Err(SessionError::Refused);
        }
        Ok(self.inner.create_stream(id, message).await?)
    }
    async fn accept_message(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<(), Self::Error> {
        if !self.life.is_active() {
            return Err(SessionError::Refused);
        }
        Ok(self.inner.accept_message(id, message).await?)
    }
    async fn create_standalone_stream(
        &self,
        id: &SessionId,
    ) -> Result<
        impl Stream<Item = rmcp::transport::common::server_side_http::ServerSseMessage>
        + Send
        + Sync
        + 'static,
        Self::Error,
    > {
        if !self.life.is_active() {
            return Err(SessionError::Refused);
        }
        Ok(self.inner.create_standalone_stream(id).await?)
    }
    async fn resume(
        &self,
        _id: &SessionId,
        _last: String,
    ) -> Result<
        impl Stream<Item = rmcp::transport::common::server_side_http::ServerSseMessage>
        + Send
        + Sync
        + 'static,
        Self::Error,
    > {
        // No response-cache recovery guarantee in this first slice. Never rerun a tool.
        Err::<futures_util::stream::Empty<_>, _>(SessionError::Refused)
    }
}
