//! Typed, bounded framing for an already-owned child, not a launcher or trust
//! verifier. Composition must supply a child from its verified release inputs.
//! Timeout retains correlation state and does not kill the child or resend work.
use super::*;
use futures_util::StreamExt;
use tokio::{
    io::AsyncWriteExt,
    process::{Child, ChildStdin, ChildStdout},
    time::{Instant, timeout, timeout_at},
};
use tokio_util::codec::{FramedRead, LinesCodec};

pub struct BackendStdio {
    write: ChildStdin,
    frames: FramedRead<ChildStdout, LinesCodec>,
    process: ProcessIdentity,
    pending: Option<RequestId>,
}
impl BackendStdio {
    #[cfg(target_os = "linux")]
    pub fn from_owned_child(child: &mut Child) -> Result<Self> {
        let process = ProcessIdentity::observe(child.id().ok_or(IpcError::MissingStdio)?)?;
        // Validate both before taking either: failure does not close a lone pipe.
        if child.stdin.is_none() || child.stdout.is_none() {
            return Err(IpcError::MissingStdio);
        }
        let write = child.stdin.take().ok_or(IpcError::MissingStdio)?;
        let read = child.stdout.take().ok_or(IpcError::MissingStdio)?;
        Ok(Self {
            write,
            frames: FramedRead::new(read, LinesCodec::new_with_max_length(CONTROL_FRAME_BYTES)),
            process,
            pending: None,
        })
    }
    #[cfg(not(target_os = "linux"))]
    pub fn from_owned_child(_: &mut Child) -> Result<Self> {
        Err(IpcError::Unsupported)
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
        if !self.process.still_current()? {
            return Err(IpcError::PeerIdentity);
        }
        let bytes = encode(request)?;
        let deadline = Instant::now() + wait;
        self.pending = Some(request.request_id.clone());
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
    pub async fn read_pending(&mut self, wait: Duration) -> Result<ControlResponse> {
        wait_budget(wait)?;
        let expected = self.pending.as_ref().ok_or(IpcError::PendingResponse)?;
        let line = timeout(wait, self.frames.next())
            .await
            .map_err(|_| IpcError::WaitExpired)?
            .ok_or(IpcError::Disconnected)?
            .map_err(|_| IpcError::InvalidFrame)?;
        let result: ControlResponse =
            serde_json::from_str(&line).map_err(|_| IpcError::InvalidFrame)?;
        if result.protocol_version != CONTROL_PROTOCOL_VERSION || &result.request_id != expected {
            return Err(IpcError::Correlation);
        }
        self.pending = None;
        Ok(result)
    }
    pub fn has_pending_response(&self) -> bool {
        self.pending.is_some()
    }
}
