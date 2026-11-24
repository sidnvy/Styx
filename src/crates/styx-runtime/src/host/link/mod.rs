//! Outbound WSS transport only: no owner authorization, RPC interpretation or
//! executor lifecycle. Every failure is local to this connection generation.
use crate::tls::{GatewayClientTls, TlsError};
use futures_util::{SinkExt, StreamExt};
use std::{
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};
use styx_contracts::identity::ConnectionGeneration;
use tokio::{
    net::TcpStream,
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tokio_tungstenite::{
    client_async_with_config,
    tungstenite::{
        Utf8Bytes,
        client::IntoClientRequest,
        protocol::{CloseFrame, Message, WebSocketConfig},
    },
};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

pub const MAX_MESSAGE: usize = styx_contracts::DESKTOP_BROWSER_FRAME_BYTES + 64 * 1024;

/// Tungstenite has already queued an automatic pong when the ping is read.
/// One pending flush is sufficient for all queued pongs: a full notification
/// slot is not a connection failure. A closed writer still ends this link.
fn request_control_flush(tx: &mpsc::Sender<()>) -> bool {
    !matches!(tx.try_send(()), Err(mpsc::error::TrySendError::Closed(_)))
}

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

pub struct ReceivedText {
    pub generation: ConnectionGeneration,
    text: Utf8Bytes,
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
    close_frame: Arc<Mutex<Option<CloseFrame>>>,
    endpoint: String,
    generation: ConnectionGeneration,
    outgoing: mpsc::Sender<Outgoing>,
    incoming: mpsc::Receiver<ReceivedText>,
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
    ) -> Result<Self, LinkError> {
        let bearer = match authentication {
            LinkAuthentication::Bearer(value) => value,
            LinkAuthentication::UnsupportedMutualTls => {
                return Err(LinkError::UnsupportedMutualTls);
            }
        };
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
        let reader_stop = stop.clone();
        let reader_generation = generation.clone();
        let close_frame = Arc::new(Mutex::new(None));
        let received_close = close_frame.clone();
        let reader = tokio::spawn(async move {
            loop {
                let next = tokio::select! { biased; _=reader_stop.cancelled()=>break, next=source.next()=>next };
                match next {
                    Some(Ok(Message::Text(text))) => {
                        let message = ReceivedText {
                            generation: reader_generation.clone(),
                            text,
                        };
                        if tokio::select! {
                            _ = reader_stop.cancelled() => break,
                            sent = incoming_tx.send(message) => sent,
                        }
                        .is_err()
                        {
                            break;
                        }
                    }
                    // Tungstenite queues automatic pong on read. Sink flush
                    // shares Split BiLock and emits that queued control frame.
                    Some(Ok(Message::Ping(_))) => {
                        if !request_control_flush(&control_tx) {
                            break;
                        }
                    }
                    Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Close(frame))) => {
                        *received_close.lock().expect("link close frame") = frame;
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
            close_frame,
            endpoint: endpoint.0.as_str().to_owned(),
            generation,
            outgoing,
            incoming,
            stop,
            tasks: vec![reader, writer],
        })
    }
    pub(crate) fn close_frame(&self) -> Option<CloseFrame> {
        self.close_frame.lock().expect("link close frame").clone()
    }
    pub async fn recv(&mut self) -> Option<ReceivedText> {
        self.incoming.recv().await
    }
    pub fn sender(&self) -> LinkSender {
        LinkSender {
            generation: self.generation.clone(),
            outgoing: self.outgoing.clone(),
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
        let until = tokio::time::Instant::now() + timeout;
        let state = Arc::new(AtomicU8::new(0));
        let _guard = PendingSend(state.clone());
        let (ack, reply) = oneshot::channel();
        tokio::time::timeout_at(
            until,
            self.outgoing.send(Outgoing {
                text,
                state: state.clone(),
                ack,
            }),
        )
        .await
        .map_err(|_| SendFailure::NotSent(LinkError::Deadline))?
        .map_err(|_| SendFailure::NotSent(LinkError::Closed))?;
        match tokio::time::timeout_at(until, reply).await {
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
