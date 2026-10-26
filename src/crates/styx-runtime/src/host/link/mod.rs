//! Outbound WSS transport only: no owner authorization, RPC interpretation or
//! executor lifecycle. Every failure is local to this connection generation.
use crate::tls::{GatewayClientTls, TlsError};
use futures_util::{SinkExt, StreamExt};
use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};
use styx_contracts::identity::ConnectionGeneration;
use tokio::{
    net::TcpStream,
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot},
    task::JoinHandle,
};
use tokio_tungstenite::{
    client_async_with_config,
    tungstenite::{
        Utf8Bytes,
        client::IntoClientRequest,
        protocol::{Message, WebSocketConfig},
    },
};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

pub const MAX_MESSAGE: usize = 2 * 1024 * 1024;
pub const LINK_BYTES: usize = 16 * 1024 * 1024;
const MAX_LINKS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LinkError {
    #[error("invalid or insecure WSS endpoint")]
    InvalidEndpoint,
    #[error("invalid bearer credential")]
    InvalidBearer,
    #[error("mutual TLS profile is not supported by this transport slice")]
    UnsupportedMutualTls,
    #[error("transport capacity exhausted")]
    Capacity,
    #[error(transparent)]
    Tls(#[from] TlsError),
    #[error("WSS handshake rejected")]
    HandshakeRejected,
    #[error("WSS upgrade refused with HTTP status {0}")]
    UpgradeStatus(u16),
    #[error("transport deadline expired")]
    Deadline,
    #[error("connection generation closed")]
    Closed,
    #[error("message exceeds transport limit")]
    TooLarge,
}

pub struct SecretBearer(Zeroizing<String>);
impl SecretBearer {
    pub fn from_protected_reader(value: String) -> Result<Self, LinkError> {
        let value = Zeroizing::new(value);
        if value.is_empty()
            || value.len() > 4096
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~+/=".contains(&b))
        {
            return Err(LinkError::InvalidBearer);
        }
        Ok(Self(value))
    }
}
impl fmt::Debug for SecretBearer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBearer([REDACTED])")
    }
}
pub enum LinkAuthentication<'a> {
    Bearer(&'a SecretBearer),
    UnsupportedMutualTls,
}

#[derive(Debug)]
pub struct LinkEndpoint(url::Url);
impl LinkEndpoint {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
    pub fn parse(value: &str) -> Result<Self, LinkError> {
        if value.len() > 4096 {
            return Err(LinkError::InvalidEndpoint);
        }
        let url = url::Url::parse(value).map_err(|_| LinkError::InvalidEndpoint)?;
        if url.scheme() != "wss"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(LinkError::InvalidEndpoint);
        }
        Ok(Self(url))
    }
}

/// A partition already reserved from the caller's *same* Host byte budget.
/// The retained permit prevents a second, independent 64MiB allowance. This
/// partition is exclusive to this allocator until all links have released it.
pub struct HostLinkBudget {
    _partition: OwnedSemaphorePermit,
    slots: Arc<Semaphore>,
}
impl HostLinkBudget {
    pub fn from_reserved_partition(
        partition: OwnedSemaphorePermit,
    ) -> Result<Arc<Self>, LinkError> {
        let bytes = partition.num_permits();
        if !(LINK_BYTES..=styx_contracts::HOST_QUEUED_BYTES).contains(&bytes)
            || !bytes.is_multiple_of(LINK_BYTES)
        {
            return Err(LinkError::Capacity);
        }
        Ok(Arc::new(Self {
            _partition: partition,
            slots: Arc::new(Semaphore::new((bytes / LINK_BYTES).min(MAX_LINKS))),
        }))
    }
}

pub struct ReceivedText {
    pub generation: ConnectionGeneration,
    text: Utf8Bytes,
    _bytes: OwnedSemaphorePermit,
    _delivery: OwnedSemaphorePermit,
    _lease: Arc<(Arc<HostLinkBudget>, OwnedSemaphorePermit)>,
}
impl ReceivedText {
    pub fn as_str(&self) -> &str {
        self.text.as_str()
    }
}
impl fmt::Debug for ReceivedText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceivedText")
            .field("generation", &self.generation)
            .field("bytes", &self.text.len())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendFailure {
    NotSent(LinkError),
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameFlushed; // local websocket flush, never application/native acknowledgement
struct Outgoing {
    text: String,
    state: Arc<AtomicU8>,
    ack: oneshot::Sender<Result<FrameFlushed, SendFailure>>,
    _bytes: OwnedSemaphorePermit,
}
struct PendingSend(Arc<AtomicU8>);
impl Drop for PendingSend {
    fn drop(&mut self) {
        let _ = self
            .0
            .compare_exchange(0, 3, Ordering::AcqRel, Ordering::Acquire);
    }
}

pub struct HostWssLink {
    endpoint: String,
    generation: ConnectionGeneration,
    outgoing: mpsc::Sender<Outgoing>,
    incoming: mpsc::Receiver<ReceivedText>,
    out_bytes: Arc<Semaphore>,
    stop: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
    // Permit and partition remain held by both IO tasks, not merely this handle.
}
impl HostWssLink {
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
    pub fn generation(&self) -> &ConnectionGeneration {
        &self.generation
    }
    /// TCP destination selection remains caller responsibility; TLS identity and
    /// HTTP Host always derive from the same endpoint, and neither redirects nor
    /// Origin/subprotocol/application-v2 inference are allowed.
    pub async fn connect(
        endpoint: &LinkEndpoint,
        tls: &GatewayClientTls,
        tcp: TcpStream,
        authentication: LinkAuthentication<'_>,
        generation: ConnectionGeneration,
        budget: Arc<HostLinkBudget>,
    ) -> Result<Self, LinkError> {
        let bearer = match authentication {
            LinkAuthentication::Bearer(value) => value,
            LinkAuthentication::UnsupportedMutualTls => {
                return Err(LinkError::UnsupportedMutualTls);
            }
        };
        let slot = budget
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| LinkError::Capacity)?;
        let lease = Arc::new((budget, slot));
        let until = tokio::time::Instant::now() + Duration::from_secs(5);
        let host = match endpoint.0.host().ok_or(LinkError::InvalidEndpoint)? {
            url::Host::Domain(v) => v.to_owned(),
            url::Host::Ipv4(v) => v.to_string(),
            url::Host::Ipv6(v) => v.to_string(),
        };
        let stream =
            tokio::time::timeout_at(until, tls.connect(&host, tcp, Duration::from_secs(5)))
                .await
                .map_err(|_| LinkError::Deadline)?
                .map_err(LinkError::Tls)?;
        let mut request = endpoint
            .0
            .as_str()
            .into_client_request()
            .map_err(|_| LinkError::InvalidEndpoint)?;
        let mut authorization = http::HeaderValue::from_str(&format!("Bearer {}", *bearer.0))
            .map_err(|_| LinkError::InvalidBearer)?;
        authorization.set_sensitive(true);
        request
            .headers_mut()
            .insert(http::header::AUTHORIZATION, authorization);
        let config = WebSocketConfig::default()
            .read_buffer_size(16 * 1024)
            .write_buffer_size(16 * 1024)
            .max_write_buffer_size(MAX_MESSAGE + 64 * 1024)
            .max_message_size(Some(MAX_MESSAGE))
            .max_frame_size(Some(MAX_MESSAGE))
            .accept_unmasked_frames(false);
        let (socket, response) = tokio::time::timeout_at(
            until,
            client_async_with_config(request, stream, Some(config)),
        )
        .await
        .map_err(|_| LinkError::Deadline)?
        .map_err(|error| match error {
            tokio_tungstenite::tungstenite::Error::Http(response) => {
                LinkError::UpgradeStatus(response.status().as_u16())
            }
            _ => LinkError::HandshakeRejected,
        })?;
        if response
            .headers()
            .contains_key(http::header::SEC_WEBSOCKET_PROTOCOL)
        {
            return Err(LinkError::HandshakeRejected);
        }
        let (mut sink, mut source) = socket.split();
        let stop = CancellationToken::new();
        let (outgoing, mut outgoing_rx) = mpsc::channel::<Outgoing>(2);
        let (incoming_tx, incoming) = mpsc::channel(2);
        let (control_tx, mut control_rx) = mpsc::channel::<()>(4);
        let out_bytes = Arc::new(Semaphore::new(2));
        let inbound_bytes = Arc::new(Semaphore::new(3));
        let deliveries = Arc::new(Semaphore::new(2));
        let reader_stop = stop.clone();
        let reader_generation = generation.clone();
        let reader_lease = lease.clone();
        let reader = tokio::spawn(async move {
            let lease = reader_lease;
            loop {
                let Ok(bytes) = inbound_bytes.clone().try_acquire_owned() else {
                    break;
                };
                let next = tokio::select! { biased; _=reader_stop.cancelled()=>break, next=source.next()=>next };
                match next {
                    Some(Ok(Message::Text(text))) => {
                        let Ok(delivery) = deliveries.clone().try_acquire_owned() else {
                            break;
                        };
                        if incoming_tx
                            .try_send(ReceivedText {
                                generation: reader_generation.clone(),
                                text,
                                _bytes: bytes,
                                _delivery: delivery,
                                _lease: lease.clone(),
                            })
                            .is_err()
                        {
                            break;
                        }
                    }
                    // Tungstenite queues automatic pong on read. Sink flush
                    // shares Split BiLock and emits that queued control frame.
                    Some(Ok(Message::Ping(_))) => {
                        if control_tx.try_send(()).is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Close(_))) => {
                        let _ = control_tx.try_send(());
                        break;
                    }
                    _ => break,
                }
            }
            reader_stop.cancel();
        });
        let writer_stop = stop.clone();
        let writer = tokio::spawn(async move {
            let _lease = lease;
            loop {
                tokio::select! { biased;
                    _=writer_stop.cancelled()=>break,
                    control=control_rx.recv()=> { if control.is_none() || sink.flush().await.is_err() { break; } },
                    next=outgoing_rx.recv()=> {
                        let Some(next)=next else { break };
                        if next.state.compare_exchange(0,1,Ordering::AcqRel,Ordering::Acquire).is_err() { let _=next.ack.send(Err(SendFailure::NotSent(LinkError::Deadline))); continue; }
                        let result=tokio::select! { biased; _=writer_stop.cancelled()=>Err(SendFailure::Unknown), result=sink.send(Message::Text(next.text.into()))=>result.map(|_|FrameFlushed).map_err(|_|SendFailure::Unknown) };
                        next.state.store(2,Ordering::Release);
                        let failed=result.is_err();
                        let _=next.ack.send(result);
                        if failed { break; }
                    }
                }
            }
            writer_stop.cancel();
            // A close is best effort with a bound; no native operation is
            // considered cancelled/exited merely because this socket closes.
            let _ = tokio::time::timeout(Duration::from_millis(100), sink.close()).await;
        });
        Ok(Self {
            endpoint: endpoint.0.as_str().to_owned(),
            generation,
            outgoing,
            incoming,
            out_bytes,
            stop,
            tasks: vec![reader, writer],
        })
    }
    pub async fn recv(&mut self) -> Option<ReceivedText> {
        self.incoming.recv().await
    }
    pub fn sender(&self) -> LinkSender {
        LinkSender {
            generation: self.generation.clone(),
            outgoing: self.outgoing.clone(),
            out_bytes: self.out_bytes.clone(),
            stop: self.stop.clone(),
        }
    }
    pub async fn send_text(
        &self,
        text: String,
        timeout: Duration,
    ) -> Result<FrameFlushed, SendFailure> {
        self.sender().send_text(text, timeout).await
    }
    /// Cleanup has a single total budget. Timeout aborts and joins owned IO
    /// tasks; external native executors are neither stopped nor restarted.
    pub async fn shutdown(mut self, timeout: Duration) -> Result<(), LinkError> {
        self.stop.cancel();
        let until = tokio::time::Instant::now() + timeout.min(Duration::from_secs(5));
        let mut timed_out = false;
        let mut task_failed = false;
        for mut task in std::mem::take(&mut self.tasks) {
            match tokio::time::timeout_at(until, &mut task).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => task_failed = true,
                Err(_) => {
                    task.abort();
                    // Pure async IO cancellation drops socket halves. Still
                    // join every task; failure is not a successful cleanup.
                    let _ = task.await;
                    timed_out = true;
                }
            }
        }
        if timed_out {
            Err(LinkError::Deadline)
        } else if task_failed {
            Err(LinkError::Closed)
        } else {
            Ok(())
        }
    }
}
impl Drop for HostWssLink {
    fn drop(&mut self) {
        self.stop.cancel();
        for task in &self.tasks {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests;

/// Cloneable transport sender shares the same two outbound reservations. It
/// cannot create connections, revive generations or control native executors.
#[derive(Clone)]
pub struct LinkSender {
    generation: ConnectionGeneration,
    outgoing: mpsc::Sender<Outgoing>,
    out_bytes: Arc<Semaphore>,
    stop: CancellationToken,
}
impl LinkSender {
    pub fn generation(&self) -> &ConnectionGeneration {
        &self.generation
    }
    pub async fn send_text(
        &self,
        text: String,
        timeout: Duration,
    ) -> Result<FrameFlushed, SendFailure> {
        if self.stop.is_cancelled() {
            return Err(SendFailure::NotSent(LinkError::Closed));
        }
        if text.len() > MAX_MESSAGE {
            return Err(SendFailure::NotSent(LinkError::TooLarge));
        }
        if timeout.is_zero() || timeout > Duration::from_secs(30) {
            return Err(SendFailure::NotSent(LinkError::Deadline));
        }
        if self.stop.is_cancelled() {
            return Err(SendFailure::NotSent(LinkError::Closed));
        }
        let bytes = self
            .out_bytes
            .clone()
            .try_acquire_owned()
            .map_err(|_| SendFailure::NotSent(LinkError::Capacity))?;
        let state = Arc::new(AtomicU8::new(0));
        let _guard = PendingSend(state.clone());
        let (ack, reply) = oneshot::channel();
        self.outgoing
            .try_send(Outgoing {
                text,
                state: state.clone(),
                ack,
                _bytes: bytes,
            })
            .map_err(|_| SendFailure::NotSent(LinkError::Capacity))?;
        match tokio::time::timeout(timeout, reply).await {
            Ok(Ok(result)) => result,
            _ => {
                if state
                    .compare_exchange(0, 3, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    Err(SendFailure::NotSent(LinkError::Deadline))
                } else {
                    Err(SendFailure::Unknown)
                }
            }
        }
    }
}
