use super::*;
use crate::store::{PrivateRoot, RootIdentity};
use futures_util::StreamExt;
use nix::{
    fcntl::{OFlag, open},
    sys::stat::{FchmodatFlags, Mode, fchmodat},
    unistd::geteuid,
};
use std::{
    fs::File,
    os::{
        fd::AsRawFd,
        unix::fs::{FileTypeExt, MetadataExt},
    },
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        UnixListener, UnixStream,
        unix::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::Semaphore,
    task::JoinSet,
    time::{Instant, timeout, timeout_at},
};
use tokio_util::{
    codec::{FramedRead, LinesCodec},
    sync::CancellationToken,
};

struct Directory {
    root: PrivateRoot,
    directory: File,
}
#[derive(Clone)]
pub struct EndpointRoot(Arc<Directory>);
impl EndpointRoot {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let root = PrivateRoot::open(path.as_ref())?;
        let fd = open(
            path.as_ref(),
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
        let directory = File::from(fd);
        let metadata = directory.metadata()?;
        if root.identity()
            != (RootIdentity::Linux {
                device: metadata.dev(),
                inode: metadata.ino(),
                uid: metadata.uid(),
            })
        {
            return Err(IpcError::EndpointIdentity);
        }
        Ok(Self(Arc::new(Directory { root, directory })))
    }
    fn path(&self) -> PathBuf {
        PathBuf::from(format!(
            "/proc/self/fd/{}/{}",
            self.0.directory.as_raw_fd(),
            SOCKET_FILENAME
        ))
    }
    fn socket_identity(&self) -> Result<SocketIdentity> {
        let metadata = std::fs::symlink_metadata(self.path())?;
        if metadata.mode() & 0o7077 != 0 {
            return Err(IpcError::EndpointIdentity);
        }
        self.owned_socket_identity()
    }
    fn owned_socket_identity(&self) -> Result<SocketIdentity> {
        let metadata = std::fs::symlink_metadata(self.path())?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != geteuid().as_raw()
            || metadata.nlink() != 1
        {
            return Err(IpcError::EndpointIdentity);
        }
        Ok(SocketIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    pub fn root_identity(&self) -> RootIdentity {
        self.0.root.identity()
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct SocketIdentity {
    device: u64,
    inode: u64,
}
struct OwnedSocket {
    root: EndpointRoot,
    identity: SocketIdentity,
    cleaned: bool,
}
impl OwnedSocket {
    fn cleanup(&mut self) -> Result<()> {
        if self.cleaned {
            return Ok(());
        }
        // Never remove an old, substituted, linked or permission-changed endpoint.
        if self.root.owned_socket_identity()? != self.identity {
            return Err(IpcError::EndpointIdentity);
        }
        std::fs::remove_file(self.root.path())?;
        self.cleaned = true;
        Ok(())
    }
}
impl Drop for OwnedSocket {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

#[derive(Default)]
struct Metrics {
    accepted: AtomicU64,
    rejected_capacity: AtomicU64,
    rejected_identity: AtomicU64,
    rejected_frame: AtomicU64,
    denied_scope: AtomicU64,
    wait_expired: AtomicU64,
}
fn peer(stream: &UnixStream) -> Result<ReadPeer> {
    let credentials = stream.peer_cred()?;
    if credentials.uid() != geteuid().as_raw() {
        return Err(IpcError::PeerIdentity);
    }
    let pid = credentials
        .pid()
        .and_then(|p| u32::try_from(p).ok())
        .filter(|p| *p > 0)
        .ok_or(IpcError::PeerIdentity)?;
    let process = ProcessIdentity::observe(pid)?;
    if !process.still_current()? {
        return Err(IpcError::PeerIdentity);
    }
    Ok(ReadPeer {
        uid: credentials.uid(),
        gid: credentials.gid(),
        pid,
        process,
    })
}
fn check_expected(peer: &ReadPeer, expected: &ExpectedServer) -> Result<()> {
    if peer.uid != expected.uid
        || peer.process != expected.process
        || !expected.process.still_current()?
    {
        return Err(IpcError::PeerIdentity);
    }
    Ok(())
}

pub struct ManagementServer<H: ReadHandler> {
    listener: UnixListener,
    socket: OwnedSocket,
    handler: Arc<H>,
    metrics: Arc<Metrics>,
}
impl<H: ReadHandler> ManagementServer<H> {
    pub async fn bind(root: EndpointRoot, handler: H) -> Result<Self> {
        // Bind never unlinks: an existing socket (live or stale) blocks startup.
        let listener = UnixListener::bind(root.path())?;
        // Parent 0700 closes the initial creation-mode window to other UIDs.
        // No fallback follows a symlink if this owned entry has been substituted.
        let metadata = std::fs::symlink_metadata(root.path())?;
        if !metadata.file_type().is_socket() || metadata.uid() != geteuid().as_raw() {
            return Err(IpcError::EndpointIdentity);
        }
        let identity = SocketIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        let mut socket = OwnedSocket {
            root,
            identity,
            cleaned: false,
        };
        if let Err(error) = fchmodat(
            &socket.root.0.directory,
            SOCKET_FILENAME,
            Mode::S_IRUSR | Mode::S_IWUSR,
            FchmodatFlags::NoFollowSymlink,
        ) {
            // Only our inode may be removed even when permission setup fails.
            let _ = socket.cleanup();
            return Err(std::io::Error::from_raw_os_error(error as i32).into());
        }
        if socket.root.socket_identity()? != identity {
            return Err(IpcError::EndpointIdentity);
        }
        Ok(Self {
            listener,
            socket,
            handler: Arc::new(handler),
            metrics: Arc::new(Metrics::default()),
        })
    }
    pub fn expected_server(&self) -> Result<ExpectedServer> {
        Ok(ExpectedServer::from_trusted_manager(
            geteuid().as_raw(),
            ProcessIdentity::current()?,
        ))
    }
    pub async fn run(self, shutdown: CancellationToken) -> Result<ServerReport> {
        let Self {
            listener,
            mut socket,
            handler,
            metrics,
        } = self;
        let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let mut tasks = JoinSet::new();
        loop {
            while tasks.try_join_next().is_some() {}
            tokio::select! {
                _ = shutdown.cancelled() => break,
                accepted = listener.accept() => {
                    let (stream, _) = accepted?;
                    let permit = match slots.clone().try_acquire_owned() { Ok(p) => p, Err(_) => { metrics.rejected_capacity.fetch_add(1,Ordering::Relaxed); continue; } };
                    let peer = match peer(&stream) { Ok(p) => p, Err(_) => { metrics.rejected_identity.fetch_add(1,Ordering::Relaxed); continue; } };
                    metrics.accepted.fetch_add(1,Ordering::Relaxed);
                    let handler = handler.clone(); let metrics = metrics.clone(); let stop = shutdown.clone();
                    tasks.spawn(async move { let _permit = permit; tokio::select! {
                        _ = stop.cancelled() => {},
                        _ = serve_peer(stream, peer, handler, metrics) => {},
                    }});
                }
            }
        }
        drop(listener);
        // Read handlers only: cancellation drops read waits, never provider owners.
        tasks.shutdown().await;
        socket.cleanup()?;
        Ok(ServerReport {
            accepted: metrics.accepted.load(Ordering::Relaxed),
            rejected_capacity: metrics.rejected_capacity.load(Ordering::Relaxed),
            rejected_identity: metrics.rejected_identity.load(Ordering::Relaxed),
            rejected_frame: metrics.rejected_frame.load(Ordering::Relaxed),
            denied_scope: metrics.denied_scope.load(Ordering::Relaxed),
            wait_expired: metrics.wait_expired.load(Ordering::Relaxed),
            socket_removed: socket.cleaned,
        })
    }
}

async fn send(writer: &mut OwnedWriteHalf, frame: &ControlResponse) -> Result<()> {
    let bytes = match encode(frame) {
        Ok(bytes) => bytes,
        Err(IpcError::FrameBudget) => encode(&response(
            frame.request_id.clone(),
            error_outcome(
                ErrorCategory::Busy,
                "response_budget",
                ExecutionCertainty::Completed,
                "Management response exceeds the wire budget.",
            ),
        ))?,
        Err(error) => return Err(error),
    };
    timeout(IO_DEADLINE, async {
        writer.write_all(&bytes).await?;
        writer.write_all(b"\n").await
    })
    .await
    .map_err(|_| IpcError::WaitExpired)??;
    Ok(())
}
async fn serve_peer<H: ReadHandler>(
    stream: UnixStream,
    peer: ReadPeer,
    handler: Arc<H>,
    metrics: Arc<Metrics>,
) -> Result<()> {
    let (read, mut write) = stream.into_split();
    // Take limits bytes consumed per frame; LinesCodec remains the sole decoder.
    // Reset after each parsed line, including any prefetched next-line remainder.
    let limited = read.take((CONTROL_FRAME_BYTES + 2) as u64);
    let mut frames = FramedRead::with_capacity(
        limited,
        LinesCodec::new_with_max_length(CONTROL_FRAME_BYTES),
        CONTROL_FRAME_BYTES + 2,
    );
    loop {
        let line = match timeout(IO_DEADLINE, frames.next()).await {
            Ok(Some(Ok(line))) => line,
            Ok(None) => return Ok(()),
            Ok(Some(Err(_))) => {
                metrics.rejected_frame.fetch_add(1, Ordering::Relaxed);
                return Err(IpcError::InvalidFrame);
            }
            Err(_) => return Err(IpcError::WaitExpired),
        };
        let received = Instant::now();
        // Remaining buffered bytes are part of the next frame's input budget.
        let remainder = frames.read_buffer().len();
        frames
            .get_mut()
            .set_limit((CONTROL_FRAME_BYTES + 2).saturating_sub(remainder) as u64);
        if !peer.process.still_current()? {
            return Err(IpcError::PeerIdentity);
        }
        let gate: GateRequest = match serde_json::from_str(&line) {
            Ok(g) => g,
            Err(_) => {
                metrics.rejected_frame.fetch_add(1, Ordering::Relaxed);
                return Err(IpcError::InvalidFrame);
            }
        };
        // Read these only as correlation claims. Never construct peer facts here.
        let _claim = (&gate.client_instance, &gate.call.params);
        let rejection = gate.validate().err().or(match gate.call.method.as_str() {
            "read_snapshot" | "read_transaction" => None,
            "cancel_operation" | "register_session" => Some(ErrorCategory::Unauthorized),
            _ => Some(ErrorCategory::InvalidRequest),
        });
        if let Some(category) = rejection {
            if category == ErrorCategory::Unauthorized {
                metrics.denied_scope.fetch_add(1, Ordering::Relaxed);
            }
            send(
                &mut write,
                &response(
                    gate.request_id,
                    error_outcome(
                        category,
                        "admission",
                        ExecutionCertainty::NotDispatched,
                        "This request is not admitted by the management-read endpoint.",
                    ),
                ),
            )
            .await?;
            continue;
        }
        let request: ControlRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(_) => {
                metrics.rejected_frame.fetch_add(1, Ordering::Relaxed);
                return Err(IpcError::InvalidFrame);
            }
        };
        let id = request.request_id.clone();
        let wait = Duration::from_millis(request.timeout_ms as u64);
        let read = ReadRequest {
            request_id: request.request_id,
            client_instance: request.client_instance,
            call: read_call(request.call)?,
        };
        let outcome = match timeout_at(received + wait, handler.read(peer.clone(), read)).await {
            Ok(outcome) => outcome,
            Err(_) => {
                metrics.wait_expired.fetch_add(1, Ordering::Relaxed);
                error_outcome(
                    ErrorCategory::OperationTimeout,
                    "read_wait",
                    ExecutionCertainty::Unknown,
                    "Read wait expired; no backend cancellation is implied.",
                )
            }
        };
        send(&mut write, &response(id, outcome)).await?;
    }
}

pub struct ManagementClient {
    frames: FramedRead<OwnedReadHalf, LinesCodec>,
    write: OwnedWriteHalf,
    expected: ExpectedServer,
    observed: ReadPeer,
    pending: Option<RequestId>,
    root: EndpointRoot,
    socket: SocketIdentity,
}
impl ManagementClient {
    pub async fn connect(root: &EndpointRoot, expected: ExpectedServer) -> Result<Self> {
        let socket = root.socket_identity()?;
        let stream = timeout(IO_DEADLINE, UnixStream::connect(root.path()))
            .await
            .map_err(|_| IpcError::WaitExpired)??;
        let observed = peer(&stream)?;
        check_expected(&observed, &expected)?;
        if root.socket_identity()? != socket {
            return Err(IpcError::EndpointIdentity);
        }
        let (read, write) = stream.into_split();
        Ok(Self {
            frames: FramedRead::new(read, LinesCodec::new_with_max_length(CONTROL_FRAME_BYTES)),
            write,
            expected,
            observed,
            pending: None,
            root: root.clone(),
            socket,
        })
    }
    pub async fn call(
        &mut self,
        request: &ControlRequest,
        wait: Duration,
    ) -> Result<ControlResponse> {
        wait_budget(wait)?;
        if self.pending.is_some() {
            return Err(IpcError::PendingResponse);
        }
        request.validate().map_err(|_| IpcError::InvalidFrame)?;
        if request.call.required_scope() != ControlScope::ManagementRead {
            return Err(IpcError::Unauthorized);
        }
        check_expected(&self.observed, &self.expected)?;
        if self.root.socket_identity()? != self.socket {
            return Err(IpcError::EndpointIdentity);
        }
        let bytes = encode(request)?;
        let deadline = Instant::now() + wait;
        self.pending = Some(request.request_id.clone()); // Set before any dispatch.
        timeout_at(deadline, async {
            self.write.write_all(&bytes).await?;
            self.write.write_all(b"\n").await
        })
        .await
        .map_err(|_| IpcError::WaitExpired)??;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(IpcError::WaitExpired);
        }
        self.read_pending(remaining).await
    }
    /// Continues only the existing read wait; never resends a request after timeout.
    pub async fn read_pending(&mut self, wait: Duration) -> Result<ControlResponse> {
        wait_budget(wait)?;
        check_expected(&self.observed, &self.expected)?;
        let expected = self.pending.as_ref().ok_or(IpcError::PendingResponse)?;
        let line = timeout(wait, self.frames.next())
            .await
            .map_err(|_| IpcError::WaitExpired)?
            .ok_or(IpcError::Disconnected)?
            .map_err(|_| IpcError::InvalidFrame)?;
        let frame: ControlResponse =
            serde_json::from_str(&line).map_err(|_| IpcError::InvalidFrame)?;
        if frame.protocol_version != CONTROL_PROTOCOL_VERSION || &frame.request_id != expected {
            return Err(IpcError::Correlation);
        }
        self.pending = None;
        Ok(frame)
    }
}
