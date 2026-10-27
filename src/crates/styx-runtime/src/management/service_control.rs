//! Private local control for the already authenticated service's original writer.
//! This socket is not MCP, and neither a request nor a transaction ID is authority.
use super::native::NativeComponent;
#[cfg(not(target_os = "windows"))]
use crate::platform::native_service::ServiceRole;
use crate::platform::native_service::{ServicePeer, ServiceScope};
use futures_util::future::BoxFuture;
use serde::{Deserialize, Serialize};
use std::{path::Path, sync::Arc};
use styx_contracts::identity::{Sha256Digest, TransactionId};
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
#[cfg(not(target_os = "windows"))]
mod unix;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(not(target_os = "windows"))]
pub(crate) use unix::ControlServer;
#[cfg(not(target_os = "windows"))]
use unix::exchange;
#[cfg(target_os = "windows")]
pub(crate) use windows::ControlServer;
#[cfg(target_os = "windows")]
use windows::exchange;
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
#[cfg(any(target_os = "macos", target_os = "windows"))]
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
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    return checked_io(move || scope.validate().map_err(|_| error())).await;
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    scope.validate().map_err(|_| error())
}
async fn validate_peer(peer: Arc<ServicePeer>) -> Result<()> {
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    return checked_io(move || peer.validate().map_err(|_| error())).await;
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    peer.validate().map_err(|_| error())
}
async fn frame<R: AsyncRead + Unpin>(read: &mut BufReader<R>) -> Result<Vec<u8>> {
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
