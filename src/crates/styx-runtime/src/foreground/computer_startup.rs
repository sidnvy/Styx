//! One retained desktop initialization job, independent of the transport/Exec
//! ready barrier. This is a factory readiness adapter, never Core authority.
use super::*;
use crate::{
    host::{
        coordinator::{DesktopSource, source_stop_complete},
        protocol::computer::ComputerBootstrap,
    },
    providers::cua::OwnedCuaConfig,
};
use std::sync::Mutex;
use styx_contracts::error::ErrorCategory;
use styx_core::operations::OwnerLease;
use tokio::{
    task::JoinHandle,
    time::{Instant, timeout_at},
};

enum Readiness {
    Pending,
    Ready(Arc<dyn ComputerBootstrap>),
    Unavailable,
    Closed,
}
pub(super) struct DeferredComputer {
    readiness: Mutex<Readiness>,
    source: Mutex<Option<DesktopSource>>,
}
impl DeferredComputer {
    pub(super) fn retain_source(&self, source: DesktopSource) {
        let mut slot = self.source.lock().expect("desktop startup source mutex");
        assert!(slot.is_none(), "one original desktop source per startup");
        *slot = Some(source);
    }
    fn original_factory(&self) -> Result<Arc<dyn ComputerBootstrap>, ErrorCategory> {
        match &*self
            .readiness
            .lock()
            .map_err(|_| ErrorCategory::IntegrityFailure)?
        {
            Readiness::Pending | Readiness::Closed => Err(ErrorCategory::Busy),
            Readiness::Unavailable => Err(ErrorCategory::CapabilityUnsupported),
            Readiness::Ready(factory) => Ok(factory.clone()),
        }
    }
    fn publish(&self, factory: Option<Arc<dyn ComputerBootstrap>>) {
        let mut state = self
            .readiness
            .lock()
            .expect("desktop startup readiness mutex");
        if matches!(*state, Readiness::Pending) {
            *state = factory.map_or(Readiness::Unavailable, Readiness::Ready);
        }
    }
}
impl ComputerBootstrap for DeferredComputer {
    fn prepare_profile(&self, owner: &OwnerLease) -> Result<OwnedCuaConfig, ErrorCategory> {
        self.original_factory()?.prepare_profile(owner)
    }
    fn validate_before_spawn(&self) -> Result<(), ErrorCategory> {
        self.original_factory()?.validate_before_spawn()
    }
    fn validate_control(&self) -> Result<(), ErrorCategory> {
        self.original_factory()?.validate_control()
    }
}
/// Owns the actual initialization task and original source across every waiter
/// timeout. Shared by production and the hermetic lifecycle fault tests below.
struct InitializationJob {
    shared: Arc<DeferredComputer>,
    job: Option<JoinHandle<()>>,
    join_failed: bool,
}
impl InitializationJob {
    fn spawn<F, Fut>(work: F) -> Self
    where
        F: FnOnce(Arc<DeferredComputer>) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Option<Arc<dyn ComputerBootstrap>>> + Send + 'static,
    {
        let shared = Arc::new(DeferredComputer {
            readiness: Mutex::new(Readiness::Pending),
            source: Mutex::new(None),
        });
        let retained = shared.clone();
        let job = tokio::spawn(async move {
            let factory = work(retained.clone()).await;
            retained.publish(factory);
        });
        Self {
            shared,
            job: Some(job),
            join_failed: false,
        }
    }
    fn close_admission(&self) {
        *self
            .shared
            .readiness
            .lock()
            .expect("desktop startup readiness mutex") = Readiness::Closed;
    }
    /// Called after original Host shutdown has fenced late registration. Timeout
    /// retains the same handle and source; a JoinError is permanently Unknown.
    async fn settle(&mut self, until: Instant) -> bool {
        if let Some(job) = &mut self.job {
            match timeout_at(until, job).await {
                Ok(result) => {
                    self.join_failed |= result.is_err();
                    self.job.take();
                }
                Err(_) => return false,
            }
        }
        if self.join_failed {
            return false;
        }
        let source = self
            .shared
            .source
            .lock()
            .expect("desktop startup source mutex")
            .clone();
        match source {
            None => true,
            Some(source) => {
                matches!(timeout_at(until, source.stop()).await, Ok(Ok(report)) if source_stop_complete(&report))
            }
        }
    }
}
pub(super) struct ComputerStartup {
    initialization: InitializationJob,
    // Explicit lifetime custody: neither transport loss nor a pending native
    // query can release the original Host, profile, execution lease or budget.
    _host: Arc<OwnedExecHost>,
    _admitted: Arc<Admitted>,
}
impl ComputerStartup {
    pub(super) fn start(
        admitted: Arc<Admitted>,
        host: Arc<OwnedExecHost>,
        events: mpsc::Sender<ForegroundEvent>,
        device: DeviceId,
        cancel: CancellationToken,
    ) -> Self {
        let retained_host = host.clone();
        let retained_admitted = admitted.clone();
        let initialization = InitializationJob::spawn(move |retained| async move {
            match prepare_computer(&retained_admitted, &retained_host, &retained).await {
                Ok(factory) => factory,
                Err(error) => {
                    event_with_reason(
                        &events,
                        &cancel,
                        "computer_unavailable",
                        &device,
                        None,
                        Some(error.code()),
                    );
                    None
                }
            }
        });
        Self {
            initialization,
            _host: host,
            _admitted: admitted,
        }
    }
    pub(super) fn factory(&self) -> Arc<dyn ComputerBootstrap> {
        self.initialization.shared.clone()
    }
    pub(super) fn close_admission(&self) {
        self.initialization.close_admission();
    }
    pub(super) async fn settle(&mut self, until: Instant) -> bool {
        self.initialization.settle(until).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct ReadyFactory;
    impl ComputerBootstrap for ReadyFactory {
        fn prepare_profile(&self, _: &OwnerLease) -> Result<OwnedCuaConfig, ErrorCategory> {
            Err(ErrorCategory::CapabilityUnsupported)
        }
        fn validate_before_spawn(&self) -> Result<(), ErrorCategory> {
            Ok(())
        }
        fn validate_control(&self) -> Result<(), ErrorCategory> {
            Ok(())
        }
    }
    /// Actual Tokio task/waiter faults, not a desktop/native provider acceptance.
    #[tokio::test]
    async fn pending_startup_retains_original_job_and_fences_late_success() {
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let mut init = InitializationJob::spawn(move |_| async move {
            entered_tx.send(()).unwrap();
            release_rx.await.unwrap();
            Some(Arc::new(ReadyFactory) as Arc<dyn ComputerBootstrap>)
        });
        entered_rx.await.unwrap();
        let task_id = init.job.as_ref().unwrap().id();
        assert_eq!(init.shared.validate_control(), Err(ErrorCategory::Busy));
        crate::host::protocol::computer::assert_pending_factory_keeps_owner_control_live(
            init.shared.clone(),
        )
        .await;
        assert!(!init.job.as_ref().unwrap().is_finished());
        init.close_admission();
        assert!(!init.settle(Instant::now() + Duration::from_millis(5)).await);
        assert_eq!(init.job.as_ref().unwrap().id(), task_id);
        assert!(!init.job.as_ref().unwrap().is_finished());
        release_tx.send(()).unwrap();
        assert!(init.settle(Instant::now() + Duration::from_secs(1)).await);
        assert!(init.job.is_none());
        // Its real successful completion cannot reopen already closed admission.
        assert_eq!(init.shared.validate_control(), Err(ErrorCategory::Busy));
        let mut panicked = InitializationJob::spawn(|_| async {
            panic!("bounded startup fault fixture");
        });
        assert!(
            !panicked
                .settle(Instant::now() + Duration::from_secs(1))
                .await
        );
        assert!(panicked.job.is_none()); // actual JoinError was consumed
        assert!(panicked.join_failed);
        assert!(
            !panicked
                .settle(Instant::now() + Duration::from_secs(1))
                .await
        );
    }
}
