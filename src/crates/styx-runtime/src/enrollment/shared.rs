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
    jobs: tokio_util::task::TaskTracker,
    readers_closing: Arc<AtomicBool>,
    active_generation: Arc<AtomicU64>,
    epoch: u64,
}

#[derive(Debug, thiserror::Error)]
#[error("enrollment authority is unavailable")]
pub struct SharedError;
impl SharedEnrollment {
    pub fn new(service: EnrollmentService) -> Self {
        Self {
            inner: Arc::new(tokio::sync::Mutex::new(service)),
            failed: Arc::new(AtomicBool::new(false)),
            jobs: tokio_util::task::TaskTracker::new(),
            readers_closing: Arc::new(AtomicBool::new(false)),
            active_generation: Arc::new(AtomicU64::new(1)),
            epoch: 1,
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
    /// blocking worker retains its lifetime token, callback and all custody if a client leaves.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    pub(crate) async fn service_control<T: Send + 'static>(
        &self,
        work: impl FnOnce(&mut EnrollmentService) -> T + Send + 'static,
    ) -> Result<T, SharedError> {
        let token = self.jobs.token();
        self.require_current()?;
        if self.readers_closing.load(Ordering::Acquire) {
            return Err(SharedError);
        }
        let shared = self.clone();
        tokio::task::spawn_blocking(move || {
            let _token = token;
            shared.blocking(work)
        })
        .await
        .map_err(|_| SharedError)?
    }
    pub(crate) async fn profiles(
        &self,
    ) -> Result<Vec<super::service::GatewayExecProfile>, SharedError> {
        let token = self.jobs.token();
        self.require_current()?;
        if self.readers_closing.load(Ordering::Acquire) {
            return Err(SharedError);
        }
        let shared = self.clone();
        tokio::task::spawn_blocking(move || {
            let _token = token;
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
        self.jobs.close();
    }
    pub(crate) fn reader_jobs_in_use(&self) -> usize {
        self.jobs.len()
    }
    pub(crate) fn same_authority(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
            && self.epoch == other.epoch
            && self.require_current().is_ok()
            && other.require_current().is_ok()
    }
    pub(crate) async fn wait_readers(&self, until: tokio::time::Instant) -> bool {
        tokio::time::timeout_at(until, self.jobs.wait())
            .await
            .is_ok()
    }

    #[cfg(all(test, target_os = "linux", target_env = "gnu"))]
    pub(crate) fn test_with<T>(&self, f: impl FnOnce(&mut EnrollmentService) -> T) -> T {
        f(&mut self.inner.try_lock().expect("exclusive test service"))
    }
}
