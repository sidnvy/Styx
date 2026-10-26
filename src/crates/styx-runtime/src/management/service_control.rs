//! Private local control for the already authenticated service's original writer.
//! This socket is not MCP, and neither a request nor a transaction ID is authority.
use super::native::NativeComponent;
use crate::platform::native_service::{ServicePeer, ServiceRole, ServiceScope};
use futures_util::future::BoxFuture;
use serde::{Deserialize, Serialize};
use std::{
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use styx_contracts::identity::{Sha256Digest, TransactionId};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
};
use tokio_util::sync::CancellationToken;
const SOCKET: &str = crate::platform::native_service::CONTROL_SOCKET_NAME;
const FRAME: usize = 4096;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServiceControlReport {
    pub schema: u32,
    pub transaction_id: TransactionId,
    pub revision: u64,
    pub canonical_raw_sha256: Sha256Digest,
    pub status: String,
    /// This receipt describes the exact transaction target, never an unqualified current state.
    pub state_scope: String,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Component {
    Host,
    Gateway,
}
impl From<NativeComponent> for Component {
    fn from(value: NativeComponent) -> Self {
        match value {
            NativeComponent::Host => Self::Host,
            NativeComponent::Gateway => Self::Gateway,
        }
    }
}
impl From<Component> for NativeComponent {
    fn from(value: Component) -> Self {
        match value {
            Component::Host => Self::Host,
            Component::Gateway => Self::Gateway,
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ServiceRequest {
    SetAutostart {
        schema: u32,
        component: Component,
        enabled: bool,
        expected_revision: u64,
        transaction_id: TransactionId,
    },
    SetRunning {
        schema: u32,
        expected_revision: u64,
        transaction_id: TransactionId,
    },
    SetStopped {
        schema: u32,
        component: Component,
        expected_revision: u64,
        transaction_id: TransactionId,
    },
    Query {
        schema: u32,
        transaction_id: TransactionId,
    },
}
impl ServiceRequest {
    fn valid(&self) -> bool {
        match self {
            Self::SetAutostart { schema, .. }
            | Self::SetRunning { schema, .. }
            | Self::SetStopped { schema, .. }
            | Self::Query { schema, .. } => *schema == 1,
        }
    }
    pub(crate) fn transaction_id(&self) -> &TransactionId {
        match self {
            Self::SetAutostart { transaction_id, .. }
            | Self::SetRunning { transaction_id, .. }
            | Self::SetStopped { transaction_id, .. }
            | Self::Query { transaction_id, .. } => transaction_id,
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    schema: u32,
    ok: bool,
    report: Option<ServiceControlReport>,
    error: Option<String>,
}
#[derive(Debug)]
pub(crate) struct ServiceControlError {
    code: &'static str,
}
impl ServiceControlError {
    pub(crate) fn new(code: &'static str) -> Self {
        Self { code }
    }
    pub(crate) fn code(&self) -> &'static str {
        self.code
    }
}
type Result<T> = std::result::Result<T, ServiceControlError>;
pub(crate) type Handler =
    Arc<dyn Fn(ServiceRequest) -> BoxFuture<'static, Result<ServiceControlReport>> + Send + Sync>;
fn error() -> ServiceControlError {
    ServiceControlError::new("service_control_unknown_inspect_transaction")
}
// macOS service observations include complete signed-payload validation.
// Retain the original scope/peer and a bounded permit until the blocking job
// finishes, including when the async caller stops waiting.
#[cfg(target_os = "macos")]
async fn checked_io<T: Send + 'static>(
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    static READERS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);
    let permit = READERS.try_acquire().map_err(|_| error())?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work()
    })
    .await
    .map_err(|_| error())?
}
async fn validate_scope(scope: Arc<ServiceScope>) -> Result<()> {
    #[cfg(target_os = "macos")]
    return checked_io(move || scope.validate().map_err(|_| error())).await;
    #[cfg(not(target_os = "macos"))]
    scope.validate().map_err(|_| error())
}
async fn validate_peer(peer: Arc<ServicePeer>) -> Result<()> {
    #[cfg(target_os = "macos")]
    return checked_io(move || peer.validate().map_err(|_| error())).await;
    #[cfg(not(target_os = "macos"))]
    peer.validate().map_err(|_| error())
}
async fn frame(read: &mut BufReader<tokio::net::unix::OwnedReadHalf>) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let bytes = read.fill_buf().await.map_err(|_| error())?;
        if bytes.is_empty() {
            return Err(error());
        }
        let end = bytes.iter().position(|b| *b == b'\n');
        let count = end.map_or(bytes.len(), |n| n + 1);
        if out.len() + count > FRAME {
            return Err(error());
        }
        out.extend_from_slice(&bytes[..count]);
        read.consume(count);
        if end.is_some() {
            return Ok(out);
        }
    }
}
struct SocketPin {
    path: PathBuf,
    device: u64,
    inode: u64,
    root: crate::store::PrivateRoot,
}
impl SocketPin {
    fn validate(&self) -> Result<()> {
        self.root
            .read_raw(".styx-native-root-v1.json", 4096)
            .map_err(|_| error())?;
        let m = std::fs::symlink_metadata(&self.path).map_err(|_| error())?;
        if !m.file_type().is_socket()
            || m.dev() != self.device
            || m.ino() != self.inode
            || m.uid() != nix::unistd::Uid::current().as_raw()
            || m.mode() & 0o777 != 0o600
        {
            return Err(error());
        }
        Ok(())
    }
    fn remove(&self) -> Result<()> {
        self.validate()?;
        std::fs::remove_file(&self.path).map_err(|_| error())?;
        match std::fs::symlink_metadata(&self.path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            _ => Err(error()),
        }
    }
}
impl Drop for SocketPin {
    fn drop(&mut self) {
        // Never remove a replacement endpoint or a pathname under a replaced root.
        if self.validate().is_ok() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}
pub(crate) struct ControlServer {
    listener: UnixListener,
    pin: SocketPin,
    scope: Arc<ServiceScope>,
    handler: Handler,
}
impl ControlServer {
    pub(crate) async fn bind_owned(scope: Arc<ServiceScope>, handler: Handler) -> Result<Self> {
        #[cfg(target_os = "macos")]
        return checked_io(move || Self::bind(scope, handler)).await;
        #[cfg(not(target_os = "macos"))]
        Self::bind(scope, handler)
    }
    pub(crate) fn bind(scope: Arc<ServiceScope>, handler: Handler) -> Result<Self> {
        scope.validate().map_err(|_| error())?;
        if scope.role() != ServiceRole::Gateway {
            return Err(error());
        }
        let root = crate::store::PrivateRoot::open(scope.state_dir()).map_err(|_| error())?;
        let path = scope.state_dir().join(SOCKET);
        match std::fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            _ => {
                return Err(ServiceControlError::new(
                    "service_control_endpoint_exists_no_adoption",
                ));
            }
        }
        let listener = std::os::unix::net::UnixListener::bind(&path).map_err(|_| error())?;
        let before = std::fs::symlink_metadata(&path).map_err(|_| error())?;
        if !before.file_type().is_socket() || before.uid() != nix::unistd::Uid::current().as_raw() {
            return Err(error());
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| error())?;
        let pin = SocketPin {
            path,
            device: before.dev(),
            inode: before.ino(),
            root,
        };
        pin.validate()?;
        scope.validate().map_err(|_| error())?;
        listener.set_nonblocking(true).map_err(|_| error())?;
        let listener = UnixListener::from_std(listener).map_err(|_| error())?;
        Ok(Self {
            listener,
            pin,
            scope,
            handler,
        })
    }
    /// One serial connection/job. An accepted mutation is always awaited even
    /// after disconnect/cancellation; shutdown cannot drop its original custody.
    pub(crate) async fn run(self, stop: CancellationToken) -> Result<()> {
        loop {
            let (stream, _) = tokio::select! { _=stop.cancelled()=>return self.pin.remove(), v=self.listener.accept()=>v.map_err(|_| error())? };
            self.pin.validate()?;
            validate_scope(self.scope.clone()).await?;
            let peer = stream.peer_cred().map_err(|_| error())?;
            if peer.uid() != nix::unistd::Uid::current().as_raw() || peer.pid().is_none() {
                continue;
            }
            let (read, mut write) = stream.into_split();
            let mut read = BufReader::new(read);
            let bytes = tokio::select! { _=stop.cancelled()=>return self.pin.remove(), v=tokio::time::timeout(Duration::from_secs(2),frame(&mut read))=>match v {Ok(Ok(v))=>v,_=>continue} };
            let request: ServiceRequest = match serde_json::from_slice(&bytes) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if !request.valid() {
                continue;
            }
            self.pin.validate()?;
            validate_scope(self.scope.clone()).await?;
            // NO select/timeout/drop around the dispatched original owner job.
            let result = (self.handler)(request).await;
            let response = match result {
                Ok(report) => Response {
                    schema: 1,
                    ok: true,
                    report: Some(report),
                    error: None,
                },
                Err(e) => Response {
                    schema: 1,
                    ok: false,
                    report: None,
                    error: Some(e.code().into()),
                },
            };
            let mut bytes = serde_json::to_vec(&response).map_err(|_| error())?;
            bytes.push(b'\n');
            let _ = tokio::time::timeout(Duration::from_secs(2), write.write_all(&bytes)).await;
        }
    }
}
async fn exchange(path: &Path, request: ServiceRequest) -> Result<ServiceControlReport> {
    let peer = ServicePeer::observe(path, ServiceRole::Gateway)
        .await
        .map_err(|_| error())?;
    validate_peer(peer.clone()).await?;
    let stream = tokio::time::timeout(
        Duration::from_secs(2),
        UnixStream::connect(path.join(SOCKET)),
    )
    .await
    .map_err(|_| error())?
    .map_err(|_| error())?;
    let credentials = stream.peer_cred().map_err(|_| error())?;
    if credentials.uid() != peer.uid()
        || credentials.pid().and_then(|p| u32::try_from(p).ok()) != Some(peer.pid())
    {
        return Err(error());
    }
    validate_peer(peer.clone()).await?;
    let stopping = matches!(&request, ServiceRequest::SetStopped { .. });
    let id = request.transaction_id().clone();
    let (read, mut write) = stream.into_split();
    let mut bytes = serde_json::to_vec(&request).map_err(|_| error())?;
    bytes.push(b'\n');
    if bytes.len() > FRAME {
        return Err(error());
    }
    write.write_all(&bytes).await.map_err(|_| error())?;
    // Deadline loss is Unknown, never a reason to resend the mutation.
    let mut read = BufReader::new(read);
    let bytes = tokio::time::timeout(Duration::from_secs(30), frame(&mut read))
        .await
        .map_err(|_| error())??;
    let response: Response = serde_json::from_slice(&bytes).map_err(|_| error())?;
    // A verified same-socket Stop ACK remains a configuration receipt if its
    // original service already exited. Physical completion is checked by caller.
    if !stopping {
        validate_peer(peer.clone()).await?;
    }
    if response.schema != 1 || !response.ok {
        return Err(error());
    }
    let report = response.report.ok_or_else(error)?;
    if report.schema != 1 || report.transaction_id != id {
        return Err(error());
    }
    Ok(report)
}
pub(crate) async fn set_autostart(
    path: &Path,
    component: NativeComponent,
    enabled: bool,
    expected_revision: u64,
    transaction_id: TransactionId,
) -> Result<ServiceControlReport> {
    let report = exchange(
        path,
        ServiceRequest::SetAutostart {
            schema: 1,
            component: component.into(),
            enabled,
            expected_revision,
            transaction_id,
        },
    )
    .await?;
    if report.status != "committed" {
        return Err(error());
    }
    Ok(report)
}
pub(crate) async fn query(
    path: &Path,
    transaction_id: TransactionId,
) -> Result<ServiceControlReport> {
    exchange(
        path,
        ServiceRequest::Query {
            schema: 1,
            transaction_id,
        },
    )
    .await
}

pub(crate) async fn set_run(
    path: &Path,
    component: NativeComponent,
    run: styx_contracts::native_management::NativeRunDesired,
    expected_revision: u64,
    transaction_id: TransactionId,
) -> Result<ServiceControlReport> {
    use styx_contracts::native_management::NativeRunDesired;
    let (request, status) = match (run, component) {
        (NativeRunDesired::Stopped, component) => (
            ServiceRequest::SetStopped {
                schema: 1,
                component: component.into(),
                expected_revision,
                transaction_id,
            },
            "configuration_committed_stop_pending",
        ),
        (NativeRunDesired::Running, NativeComponent::Host) => (
            ServiceRequest::SetRunning {
                schema: 1,
                expected_revision,
                transaction_id,
            },
            "configuration_committed_start_pending",
        ),
        _ => {
            return Err(ServiceControlError::new(
                "service_control_live_start_host_only",
            ));
        }
    };
    let report = exchange(path, request).await?;
    if report.status != status || report.state_scope != "committed_target" {
        return Err(error());
    }
    Ok(report)
}
