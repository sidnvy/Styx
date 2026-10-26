//! Single enrollment authority shared by HTTP and paired transport.
use super::service::EnrollmentService;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
#[derive(Clone)]
pub struct SharedEnrollment {
    inner: Arc<tokio::sync::Mutex<EnrollmentService>>,
    failed: Arc<AtomicBool>,
    jobs: Arc<tokio::sync::Semaphore>,
    readers_closing: Arc<AtomicBool>,
    active_generation: Arc<AtomicU64>,
    epoch: u64,
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    promotion: Arc<std::sync::Mutex<Option<Promotion>>>,
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    promotion_worker: Arc<tokio::sync::Semaphore>,
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
struct Promotion {
    from_epoch: u64,
    epoch: u64,
    proof: Arc<crate::store::legacy_handoff::CommittedNativeCutover>,
    jobs: Arc<tokio::sync::Semaphore>,
    readers_closing: Arc<AtomicBool>,
}
#[derive(Debug, thiserror::Error)]
#[error("enrollment authority is unavailable")]
pub struct SharedError;
impl SharedEnrollment {
    pub fn new(service: EnrollmentService) -> Self {
        Self {
            inner: Arc::new(tokio::sync::Mutex::new(service)),
            failed: Arc::new(AtomicBool::new(false)),
            jobs: Arc::new(tokio::sync::Semaphore::new(8)),
            readers_closing: Arc::new(AtomicBool::new(false)),
            active_generation: Arc::new(AtomicU64::new(1)),
            epoch: 1,
            #[cfg(all(target_os = "linux", target_env = "gnu"))]
            promotion: Arc::new(std::sync::Mutex::new(None)),
            #[cfg(all(target_os = "linux", target_env = "gnu"))]
            promotion_worker: Arc::new(tokio::sync::Semaphore::new(1)),
        }
    }
    fn require_current(&self) -> Result<(), SharedError> {
        if self.failed.load(Ordering::Acquire)
            || self.active_generation.load(Ordering::Acquire) != self.epoch
        {
            return Err(SharedError);
        }
        Ok(())
    }
    fn apply<T>(
        &self,
        service: &mut EnrollmentService,
        f: impl FnOnce(&mut EnrollmentService) -> T,
    ) -> Result<T, SharedError> {
        self.require_current()?;
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(service))) {
            Ok(v) => Ok(v),
            Err(_) => {
                self.failed.store(true, Ordering::Release);
                Err(SharedError)
            }
        }
    }
    pub(crate) async fn with<T>(
        &self,
        f: impl FnOnce(&mut EnrollmentService) -> T,
    ) -> Result<T, SharedError> {
        self.require_current()?;
        let mut s = self.inner.lock().await;
        self.apply(&mut s, f)
    }
    pub(crate) fn blocking<T>(
        &self,
        f: impl FnOnce(&mut EnrollmentService) -> T,
    ) -> Result<T, SharedError> {
        self.require_current()?;
        let mut s = self.inner.blocking_lock();
        self.apply(&mut s, f)
    }
    /// The service callback is executed under this SAME Core mutex. The owned
    /// blocking worker retains the slot, callback and all custody if a client leaves.
    #[cfg(any(all(target_os = "linux", target_env = "gnu"), target_os = "macos"))]
    pub(crate) async fn service_control<T: Send + 'static>(
        &self,
        work: impl FnOnce(&mut EnrollmentService) -> T + Send + 'static,
    ) -> Result<T, SharedError> {
        self.require_current()?;
        let permit = self
            .jobs
            .clone()
            .try_acquire_owned()
            .map_err(|_| SharedError)?;
        let shared = self.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            shared.blocking(work)
        })
        .await
        .map_err(|_| SharedError)?
    }
    /// Trusted local management port. Waits behind the complete existing
    /// enrollment round trip, then fences the very same configuration owner.
    /// The blocking job retains its bounded slot after caller cancellation;
    /// dropping its result leaves admission fenced, never resumes implicitly.
    pub async fn begin_configuration_maintenance(
        &self,
        transaction: styx_contracts::identity::TransactionId,
    ) -> Result<crate::store::ConfigurationMaintenance, SharedError> {
        self.require_current()?;
        let permit = self
            .jobs
            .clone()
            .try_acquire_owned()
            .map_err(|_| SharedError)?;
        let shared = self.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            shared
                .blocking(|service| service.begin_configuration_maintenance(transaction))
                .map_err(|_| SharedError)?
                .map_err(|_| SharedError)
        })
        .await
        .map_err(|_| SharedError)?
    }
    pub(crate) async fn profiles(
        &self,
    ) -> Result<Vec<super::service::GatewayExecProfile>, SharedError> {
        self.require_current()?;
        if self.readers_closing.load(Ordering::Acquire) {
            return Err(SharedError);
        }
        let permit = self
            .jobs
            .clone()
            .try_acquire_owned()
            .map_err(|_| SharedError)?;
        let shared = self.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            if shared.readers_closing.load(Ordering::Acquire) {
                return Err(SharedError);
            }
            shared
                .blocking(|s| s.exec_profiles())
                .map_err(|_| SharedError)?
                .map_err(|_| SharedError)
        })
        .await
        .map_err(|_| SharedError)?
    }
    pub(crate) fn close_readers(&self) {
        self.readers_closing.store(true, Ordering::Release);
    }
    pub(crate) fn reader_jobs_in_use(&self) -> usize {
        8 - self.jobs.available_permits()
    }
    pub(crate) fn same_authority(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
            && self.epoch == other.epoch
            && self.require_current().is_ok()
            && other.require_current().is_ok()
    }
    pub(crate) async fn wait_readers(&self, until: tokio::time::Instant) -> bool {
        tokio::time::timeout_at(until, self.jobs.clone().acquire_many_owned(8))
            .await
            .is_ok_and(|r| r.is_ok())
    }
    /// Retire the closed maintenance listener without replacing its Core/store.
    /// The owned blocking task survives waiter cancellation. One retained result
    /// allows the exact same proof to retrieve that task's already-published gate.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    pub(crate) async fn promote_committed_migration(
        &self,
        proof: Arc<crate::store::legacy_handoff::CommittedNativeCutover>,
    ) -> Result<Self, SharedError> {
        if !self.readers_closing.load(Ordering::Acquire) {
            return Err(SharedError);
        }
        let permit = self
            .promotion_worker
            .clone()
            .try_acquire_owned()
            .map_err(|_| SharedError)?;
        let shared = self.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            // Lock ordering: service -> promotion. No ordinary method acquires
            // promotion; this serializes duplicate callers and result retrieval.
            let mut service = shared.inner.blocking_lock();
            let mut result = shared.promotion.lock().map_err(|_| SharedError)?;
            if let Some(existing) = result.as_ref() {
                if existing.from_epoch != shared.epoch
                    || !Arc::ptr_eq(&existing.proof, &proof)
                    || shared.failed.load(Ordering::Acquire)
                    || shared.active_generation.load(Ordering::Acquire) != existing.epoch
                {
                    return Err(SharedError);
                }
                return Ok(shared.promoted(existing));
            }
            shared.require_current()?;
            // Holding every permit proves old reader/blocking jobs have really
            // completed; a dropped caller cannot release an executing job's slot.
            let _all_jobs = shared
                .jobs
                .clone()
                .try_acquire_many_owned(8)
                .map_err(|_| SharedError)?;
            let epoch = shared.epoch.checked_add(1).ok_or(SharedError)?;
            shared
                .apply(&mut service, |service| {
                    service.promote_committed_migration(&proof)
                })?
                .map_err(|_| SharedError)?;
            let completed = Promotion {
                from_epoch: shared.epoch,
                epoch,
                proof,
                jobs: Arc::new(tokio::sync::Semaphore::new(8)),
                readers_closing: Arc::new(AtomicBool::new(false)),
            };
            let next = shared.promoted(&completed);
            *result = Some(completed);
            shared.active_generation.store(epoch, Ordering::Release);
            Ok(next)
        })
        .await
        .map_err(|_| SharedError)?
    }

    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    fn promoted(&self, completed: &Promotion) -> Self {
        Self {
            inner: self.inner.clone(),
            failed: self.failed.clone(),
            jobs: completed.jobs.clone(),
            readers_closing: completed.readers_closing.clone(),
            active_generation: self.active_generation.clone(),
            epoch: completed.epoch,
            promotion: self.promotion.clone(),
            promotion_worker: self.promotion_worker.clone(),
        }
    }

    #[cfg(all(test, target_os = "linux", target_env = "gnu"))]
    pub(crate) fn test_with<T>(&self, f: impl FnOnce(&mut EnrollmentService) -> T) -> T {
        f(&mut self.inner.try_lock().expect("exclusive test service"))
    }
}

#[cfg(test)]
#[path = "maintenance_tests.rs"]
mod maintenance_tests;

#[cfg(test)]
#[path = "shared_migration_tests.rs"]
mod shared_migration_tests;
