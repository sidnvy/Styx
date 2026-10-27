use super::*;
use std::{
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::PathBuf,
    time::Duration,
};
use tokio::{
    io::AsyncWriteExt,
    net::{UnixListener, UnixStream},
};
use tokio_util::sync::CancellationToken;
const SOCKET: &str = crate::platform::native_service::CONTROL_SOCKET_NAME;
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
pub(super) async fn exchange(path: &Path, request: ServiceRequest) -> Result<ServiceControlReport> {
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
