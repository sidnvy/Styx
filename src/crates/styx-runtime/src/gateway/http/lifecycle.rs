use crate::gateway::auth::VerifiedGatewayOwner;
use std::{
    future::Future,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};
use tokio::{sync::Notify, task::JoinSet};
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
    pub worker_failure_observed: std::sync::atomic::AtomicBool,
    pub accepting_cleanup_jobs: std::sync::atomic::AtomicBool,
}
pub(super) struct Life<L: GatewayOwnerLifecycle> {
    pub owner: VerifiedGatewayOwner,
    pub lifecycle: Arc<L>,
    pub facts: Mutex<CloseFacts>,
    pub changed: Notify,
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
    /// Wait only for this Life's original supervised cleanup and actual SDK
    /// transport close. Dropping this waiter cannot cancel or recreate either.
    /// The outer HTTP deadline remains independently bounded at five seconds.
    pub(super) async fn wait_complete(&self) -> Result<(), OwnerFenceError> {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let changed = self.changed.notified();
                tokio::pin!(changed);
                // Register before sampling facts: cleanup/transport completion
                // between the sample and await must not lose its notification.
                changed.as_mut().enable();
                {
                    let facts = self.facts.lock().expect("session lifetime");
                    if facts.cleanup == Some(OwnerCleanup::Unknown) {
                        return Err(OwnerFenceError);
                    }
                    if facts.fenced
                        && facts.cleanup == Some(OwnerCleanup::Complete)
                        && facts.transport_joined
                    {
                        return Ok(());
                    }
                }
                changed.await;
            }
        })
        .await
        .map_err(|_| OwnerFenceError)?
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
            let mut jobs = supervisor.jobs.lock().expect("cleanup supervisor");
            if !supervisor
                .accepting_cleanup_jobs
                .load(std::sync::atomic::Ordering::Acquire)
            {
                // Process-level shutdown has fenced registration. A late SDK
                // Drop cannot create a job after the final quiescence snapshot;
                // no remote completion is inferred from refusing registration.
                return Err(OwnerFenceError);
            }
            f.cleanup_started = true;
            let this = self.clone();
            while let Some(result) = jobs.try_join_next() {
                if result.is_err() {
                    supervisor
                        .worker_failure_observed
                        .store(true, std::sync::atomic::Ordering::Release);
                }
            }
            jobs.spawn(async move {
                let result = this
                    .lifecycle
                    .cleanup_owner(&this.owner, Duration::from_secs(5))
                    .await;
                this.facts.lock().expect("session lifetime").cleanup = Some(result);
                this.changed.notify_waiters();
            });
        }
        Ok(())
    }
}
