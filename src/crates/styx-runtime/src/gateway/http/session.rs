use super::lifecycle::{GatewayOwnerLifecycle, Life};
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
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

#[derive(Debug, thiserror::Error)]
pub(super) enum SessionError {
    #[error("SDK session rejected")]
    Local(#[from] LocalSessionManagerError),
    #[error("session lifetime refused")]
    Refused,
}
#[derive(Debug, thiserror::Error)]
pub(super) enum TransportError {
    #[error("official SDK transport rejected message")]
    Local,
    #[error("owner fence refused; cleanup remains unresolved")]
    FenceRefused,
}
impl From<LocalSessionWorkerError> for TransportError {
    fn from(_: LocalSessionWorkerError) -> Self {
        Self::Local
    }
}
pub(super) struct McpSessionManager<L: GatewayOwnerLifecycle> {
    inner: LocalSessionManager,
    created: AtomicBool,
    pub id: Mutex<Option<SessionId>>,
    pub life: Arc<Life<L>>,
    pub negotiated: Mutex<Option<String>>,
}
impl<L: GatewayOwnerLifecycle> McpSessionManager<L> {
    /// Only a never-attempted transport is exempt from a join. Once creation
    /// starts, a failed/unknown SDK result is not fabricated into quiescence.
    pub(super) fn local_transport_quiescent(&self) -> bool {
        let facts = self.life.facts.lock().expect("session lifetime");
        !self.created.load(Ordering::Acquire) || facts.transport_joined
    }
    pub fn new(life: Arc<Life<L>>) -> Self {
        let mut inner = LocalSessionManager::default();
        // Idle time alone does not close an admitted conversation.
        inner.session_config.keep_alive = None;
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
        // Outbound tool results (including screenshots) are passed to the SDK
        // without applying the inbound request-body bound to their response.
        let sent = self.inner.send(message);
        async move { sent.await.map_err(TransportError::from) }
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
            self.life.changed.notify_waiters();
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
impl<L: GatewayOwnerLifecycle> SessionManager for McpSessionManager<L> {
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
        // Successful DELETE is an ordered close boundary, not merely the SDK
        // close event being accepted. This awaits the SAME original Life job;
        // timeout/HTTP waiter loss leaves its supervisor and Closing slot owned.
        self.life
            .wait_complete()
            .await
            .map_err(|_| SessionError::Refused)
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
        id: &SessionId,
        last: String,
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
        // SDK event replay resumes the original stream; it never reruns a tool.
        Ok(self.inner.resume(id, last).await?)
    }
}
