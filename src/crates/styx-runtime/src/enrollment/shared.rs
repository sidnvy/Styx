//! Single enrollment authority shared by HTTP and paired transport.
use super::service::EnrollmentService;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
#[derive(Clone)]
pub struct SharedEnrollment {
    inner: Arc<tokio::sync::Mutex<EnrollmentService>>,
    failed: Arc<AtomicBool>,
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
        }
    }
    fn apply<T>(
        &self,
        service: &mut EnrollmentService,
        f: impl FnOnce(&mut EnrollmentService) -> T,
    ) -> Result<T, SharedError> {
        if self.failed.load(Ordering::Acquire) {
            return Err(SharedError);
        }
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
        let mut s = self.inner.lock().await;
        self.apply(&mut s, f)
    }
    pub(crate) fn blocking<T>(
        &self,
        f: impl FnOnce(&mut EnrollmentService) -> T,
    ) -> Result<T, SharedError> {
        let mut s = self.inner.blocking_lock();
        self.apply(&mut s, f)
    }
    /// Trusted local management port. Waits behind the complete existing
    /// enrollment round trip, then fences the very same configuration owner.
    /// The blocking job retains its bounded slot after caller cancellation;
    /// dropping its result leaves admission fenced, never resumes implicitly.
    pub async fn begin_configuration_maintenance(
        &self,
        transaction: styx_contracts::identity::TransactionId,
    ) -> Result<crate::store::ConfigurationMaintenance, SharedError> {
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
    }
    pub(crate) async fn wait_readers(&self, until: tokio::time::Instant) -> bool {
        tokio::time::timeout_at(until, self.jobs.clone().acquire_many_owned(8))
            .await
            .is_ok_and(|r| r.is_ok())
    }
    #[cfg(test)]
    pub(crate) fn test_with<T>(&self, f: impl FnOnce(&mut EnrollmentService) -> T) -> T {
        f(&mut self.inner.try_lock().expect("exclusive test service"))
    }
}

#[cfg(test)]
#[path = "maintenance_tests.rs"]
mod maintenance_tests;
