use crate::gateway::auth::VerifiedGatewayOwner;
use std::{
    future::Future,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerCleanup {
    Complete,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("owner fence refused; session remains Closing")]
pub struct OwnerFenceError;
/// Required real authority port. A dropped response/SDK request never proves
/// an action stopped. Cleanup implementations must retain action ownership if
/// their waiter is dropped, and must not report Complete from a cancel ACK.
pub trait GatewayOwnerLifecycle: Send + Sync + 'static {
    fn fence_owner(&self, owner: &VerifiedGatewayOwner) -> Result<(), OwnerFenceError>;
    fn cleanup_owner(
        &self,
        owner: &VerifiedGatewayOwner,
        budget: Duration,
    ) -> impl Future<Output = OwnerCleanup> + Send;
}
#[derive(Default)]
pub(super) struct CloseFacts {
    pub closing: bool,
    pub fenced: bool,
    pub cleanup: Option<OwnerCleanup>,
    pub transport_joined: bool,
    pub cleanup_started: bool,
}
pub(super) struct Supervisor {
    pub jobs: Mutex<JoinSet<()>>,
    pub parked: Mutex<Vec<JoinSet<()>>>,
}
pub(super) struct Life<L: GatewayOwnerLifecycle> {
    pub owner: VerifiedGatewayOwner,
    pub lifecycle: Arc<L>,
    pub facts: Mutex<CloseFacts>,
    pub cancellation: Mutex<Option<CancellationToken>>,
    pub supervisor: Weak<Supervisor>,
    // All SDK handler/transport and cleanup owners retain this same real lease.
    pub _session_slot: tokio::sync::OwnedSemaphorePermit,
    pub _budget: Arc<super::HttpBudget>,
}
impl<L: GatewayOwnerLifecycle> Life<L> {
    pub fn is_active(&self) -> bool {
        !self.facts.lock().expect("session lifetime").closing
    }
    pub fn is_complete(&self) -> bool {
        let f = self.facts.lock().expect("session lifetime");
        f.fenced && f.cleanup == Some(OwnerCleanup::Complete) && f.transport_joined
    }
    /// Sync fence precedes any async close, even when invoked from Drop.
    pub fn close(self: &Arc<Self>) -> Result<(), OwnerFenceError> {
        let mut f = self.facts.lock().expect("session lifetime");
        f.closing = true;
        if !f.fenced {
            // Explicit idempotent fence reconciliation is not business replay.
            self.lifecycle.fence_owner(&self.owner)?;
            f.fenced = true;
        }
        if !f.fenced {
            return Err(OwnerFenceError);
        }
        if let Some(ct) = self
            .cancellation
            .lock()
            .expect("session cancellation")
            .as_ref()
        {
            ct.cancel();
        }
        if !f.cleanup_started {
            let Some(supervisor) = self.supervisor.upgrade() else {
                return Err(OwnerFenceError);
            };
            if tokio::runtime::Handle::try_current().is_err() {
                return Err(OwnerFenceError);
            }
            f.cleanup_started = true;
            let this = self.clone();
            let mut jobs = supervisor.jobs.lock().expect("cleanup supervisor");
            while jobs.try_join_next().is_some() {}
            jobs.spawn(async move {
                let result = this
                    .lifecycle
                    .cleanup_owner(&this.owner, Duration::from_secs(5))
                    .await;
                this.facts.lock().expect("session lifetime").cleanup = Some(result);
            });
        }
        Ok(())
    }
}
