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
    // Retry only read-only startup prerequisites before any desktop source
    // exists. The same initialization job owns every check and is joined on
    // shutdown; no candidate, source or possibly dispatched action is replayed.
    pub(super) async fn read_before_source<T, F, Fut>(
        &self,
        budget: Duration,
        mut read: F,
    ) -> Result<T, ForegroundError>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T, ForegroundError>>,
    {
        let until = Instant::now() + budget;
        loop {
            if !matches!(
                *self
                    .readiness
                    .lock()
                    .expect("desktop startup readiness mutex"),
                Readiness::Pending
            ) || self
                .source
                .lock()
                .expect("desktop startup source mutex")
                .is_some()
            {
                return Err(ForegroundError("computer_startup_closed"));
            }
            let result = read().await;
            if !matches!(
                *self
                    .readiness
                    .lock()
                    .expect("desktop startup readiness mutex"),
                Readiness::Pending
            ) {
                return Err(ForegroundError("computer_startup_closed"));
            }
            match result {
                Err(error)
                    if matches!(
                        error.code(),
                        "native_service_configuration_pending" | "desktop_session_not_ready"
                    ) && Instant::now() < until =>
                {
                    tokio::time::sleep_until(until.min(Instant::now() + Duration::from_millis(50)))
                        .await;
                }
                other => return other,
            }
        }
    }
    #[cfg(target_os = "linux")]
    pub(super) async fn desktop_candidate<F, Fut>(
        &self,
        budget: Duration,
        mut discover: F,
    ) -> Result<crate::platform::linux::LinuxCandidate, ForegroundError>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<
                Output = Result<crate::platform::linux::LinuxDiscoverySnapshot, ForegroundError>,
            >,
    {
        self.read_before_source(budget, || {
            let snapshot = discover();
            async move {
                let mut candidates = snapshot.await?.candidates;
                match candidates.len() {
                    0 => Err(ForegroundError("desktop_session_not_ready")),
                    1 => Ok(candidates.pop().expect("exactly one")),
                    _ => Err(ForegroundError("desktop_selection_required")),
                }
            }
        })
        .await
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
    fn release_profile(&self, owner: &OwnerLease) {
        if let Ok(factory) = self.original_factory() {
            factory.release_profile(owner);
        }
    }
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
    #[cfg(target_os = "linux")]
    fn desktop_snapshot(count: usize) -> crate::platform::linux::LinuxDiscoverySnapshot {
        use crate::platform::linux::{Association, LinuxCandidate, LinuxDiscoverySnapshot};
        LinuxDiscoverySnapshot {
            schema: 1,
            login_unique_owner: ":1.9".into(),
            candidates: (0..count)
                .map(|i| LinuxCandidate {
                    session_id: format!("fixture-{i}"),
                    uid: 1000,
                    seat: Some("seat0".into()),
                    leader_pid: 20 + i as u32,
                    leader_birth: 10,
                    login_timestamp_monotonic: 9,
                    backend: "wayland".into(),
                    active: true,
                    state: "active".into(),
                    locked_hint: false,
                    compositor_association: Association::Unknown,
                    agent_association: Association::Unknown,
                })
                .collect(),
            connection_closed: true,
        }
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn initial_desktop_waits_for_unique_candidate_without_reselecting() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let ready = Arc::new(AtomicBool::new(false));
        let reads = Arc::new(AtomicUsize::new(0));
        let (entered, observed) = tokio::sync::oneshot::channel();
        let (state, count) = (ready.clone(), reads.clone());
        let mut init = InitializationJob::spawn(move |shared| async move {
            let mut entered = Some(entered);
            let selected = shared
                .desktop_candidate(Duration::from_secs(1), || {
                    count.fetch_add(1, Ordering::SeqCst);
                    if let Some(entered) = entered.take() {
                        let _ = entered.send(());
                    }
                    std::future::ready(Ok(desktop_snapshot(usize::from(
                        state.load(Ordering::SeqCst),
                    ))))
                })
                .await
                .unwrap();
            assert_eq!(selected.session_id, "fixture-0");
            assert!(shared.source.lock().unwrap().is_none());
            Some(Arc::new(ReadyFactory) as Arc<dyn ComputerBootstrap>)
        });
        observed.await.unwrap();
        let original = init.job.as_ref().unwrap().id();
        assert_eq!(init.shared.validate_control(), Err(ErrorCategory::Busy));
        assert!(!init.job.as_ref().unwrap().is_finished());
        ready.store(true, Ordering::SeqCst);
        assert_eq!(init.job.as_ref().unwrap().id(), original);
        assert!(init.settle(Instant::now() + Duration::from_secs(1)).await);
        assert!(reads.load(Ordering::SeqCst) >= 2);
        assert_eq!(init.shared.validate_control(), Ok(()));

        let shared = DeferredComputer {
            readiness: Mutex::new(Readiness::Pending),
            source: Mutex::new(None),
        };
        for (candidates, budget, expected) in [
            (2, Duration::from_secs(30), "desktop_selection_required"),
            (0, Duration::ZERO, "desktop_session_not_ready"),
        ] {
            let mut calls = 0;
            let error = shared
                .desktop_candidate(budget, || {
                    calls += 1;
                    std::future::ready(Ok(desktop_snapshot(candidates)))
                })
                .await
                .unwrap_err();
            assert_eq!(error.code(), expected);
            assert_eq!(calls, 1);
        }
        let mut calls = 0;
        let error = shared
            .desktop_candidate(Duration::from_secs(30), || {
                calls += 1;
                std::future::ready(Err(ForegroundError("login_owner_changed")))
            })
            .await
            .unwrap_err();
        assert_eq!(error.code(), "login_owner_changed");
        assert_eq!(calls, 1);
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn pending_desktop_shutdown_joins_original_discovery_without_opening_source() {
        let (entered, observed) = tokio::sync::oneshot::channel();
        let mut init = InitializationJob::spawn(move |shared| async move {
            let mut entered = Some(entered);
            let result = shared
                .desktop_candidate(Duration::from_secs(30), || {
                    if let Some(entered) = entered.take() {
                        let _ = entered.send(());
                    }
                    std::future::ready(Ok(desktop_snapshot(0)))
                })
                .await;
            assert_eq!(result.unwrap_err().code(), "computer_startup_closed");
            assert!(shared.source.lock().unwrap().is_none());
            None
        });
        observed.await.unwrap();
        init.close_admission();
        assert!(init.settle(Instant::now() + Duration::from_secs(1)).await);
        assert!(init.job.is_none());
        assert_eq!(init.shared.validate_control(), Err(ErrorCategory::Busy));
    }
    #[tokio::test]
    async fn service_transaction_pending_keeps_original_initialization_until_commit() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let ready = Arc::new(AtomicBool::new(false));
        let reads = Arc::new(AtomicUsize::new(0));
        let (entered, observed) = tokio::sync::oneshot::channel();
        let (state, count) = (ready.clone(), reads.clone());
        let mut init = InitializationJob::spawn(move |shared| async move {
            let mut entered = Some(entered);
            let result = shared
                .read_before_source(Duration::from_secs(1), || {
                    count.fetch_add(1, Ordering::SeqCst);
                    if let Some(entered) = entered.take() {
                        let _ = entered.send(());
                    }
                    std::future::ready(if state.load(Ordering::SeqCst) {
                        Ok(true)
                    } else {
                        Err(ForegroundError("native_service_configuration_pending"))
                    })
                })
                .await;
            result
                .ok()
                .map(|_| Arc::new(ReadyFactory) as Arc<dyn ComputerBootstrap>)
        });
        observed.await.unwrap();
        let original = init.job.as_ref().unwrap().id();
        assert_eq!(init.shared.validate_control(), Err(ErrorCategory::Busy));
        assert!(!init.job.as_ref().unwrap().is_finished());
        ready.store(true, Ordering::SeqCst);
        assert_eq!(init.job.as_ref().unwrap().id(), original);
        assert!(init.settle(Instant::now() + Duration::from_secs(1)).await);
        assert!(reads.load(Ordering::SeqCst) >= 2);
        assert_eq!(init.shared.validate_control(), Ok(()));
    }
    #[tokio::test]
    async fn pending_profile_shutdown_and_nontransient_errors_never_open_desktop() {
        let (entered, observed) = tokio::sync::oneshot::channel();
        let mut init = InitializationJob::spawn(move |shared| async move {
            let mut entered = Some(entered);
            let result = shared
                .read_before_source(Duration::from_secs(30), || {
                    if let Some(entered) = entered.take() {
                        let _ = entered.send(());
                    }
                    std::future::ready(Err::<bool, _>(ForegroundError(
                        "native_service_configuration_pending",
                    )))
                })
                .await;
            assert_eq!(result.unwrap_err().code(), "computer_startup_closed");
            None
        });
        observed.await.unwrap();
        init.close_admission();
        assert!(init.settle(Instant::now() + Duration::from_secs(1)).await);
        assert_eq!(init.shared.validate_control(), Err(ErrorCategory::Busy));
        let shared = DeferredComputer {
            readiness: Mutex::new(Readiness::Pending),
            source: Mutex::new(None),
        };
        let mut calls = 0;
        let error = shared
            .read_before_source(Duration::from_secs(30), || {
                calls += 1;
                std::future::ready(Err::<bool, _>(ForegroundError("legacy_profile_changed")))
            })
            .await
            .unwrap_err();
        assert_eq!(error.code(), "legacy_profile_changed");
        assert_eq!(calls, 1);
        let error = shared
            .read_before_source(Duration::ZERO, || {
                std::future::ready(Err::<bool, _>(ForegroundError(
                    "native_service_configuration_pending",
                )))
            })
            .await
            .unwrap_err();
        assert_eq!(error.code(), "native_service_configuration_pending");
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
