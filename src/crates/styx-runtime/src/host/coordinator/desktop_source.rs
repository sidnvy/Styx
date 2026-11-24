//! One selected native source, supervised through the original bounded workers.
//! This owns observations only; Core registration and capability policy remain
//! with the Host. No replacement candidate is ever adopted after a fence.
use crate::platform::linux::{
    LinuxCandidate,
    association::{LinuxAssociationLease, WindowReadEvidence},
};
use crate::session_probe::{
    association::probe_candidate,
    watch::{self, CandidateKey, WatchChange, WatchObservation, WatchReport},
};
use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
const FRESHNESS_WINDOW: Duration = Duration::from_secs(15);
use styx_contracts::identity::AgentInstanceId;
use styx_core::session::RegistrationFacts;
use tokio::{
    sync::{Mutex as AsyncMutex, mpsc, oneshot},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum DesktopSourceError {
    #[error("desktop source unavailable")]
    Unavailable,
    #[error("desktop source association acquisition refused")]
    Acquisition(crate::session_probe::association::AssociationProbeError),
    #[error("desktop source changed or ended")]
    Fenced,
    #[error("desktop source supervisor failed")]
    Supervisor,
}
impl DesktopSourceError {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::Unavailable => "desktop_source_unavailable",
            Self::Acquisition(error) => error.code(),
            Self::Fenced => "desktop_source_fenced",
            Self::Supervisor => "desktop_source_supervisor_failed",
        }
    }
}
type Result<T> = std::result::Result<T, DesktopSourceError>;
type Answer = oneshot::Sender<Result<()>>;

pub(crate) struct DesktopLaunchFields {
    pub(crate) runtime_dir: PathBuf,
    pub(crate) wayland_display: String,
    pub(crate) hyprland_instance: String,
}
struct State {
    fenced: AtomicBool,
    epoch: AtomicU64,
    lease: Mutex<Option<LinuxAssociationLease>>,
    verified_at: Mutex<Option<Instant>>,
}
impl State {
    fn fence(&self) {
        if !self.fenced.swap(true, Ordering::AcqRel) {
            // This source fences once and never restarts, so this cannot wrap.
            self.epoch.fetch_add(1, Ordering::AcqRel);
            if let Ok(mut verified) = self.verified_at.lock() {
                *verified = None;
            }
        }
    }
    fn has_fresh_lease(&self) -> bool {
        let before = self.epoch.load(Ordering::Acquire);
        if self.fenced.load(Ordering::Acquire) {
            return false;
        }
        let has_lease = self.lease.lock().is_ok_and(|held| held.is_some());
        let fresh = self
            .verified_at
            .lock()
            .is_ok_and(|at| at.is_some_and(|instant| instant.elapsed() < FRESHNESS_WINDOW));
        has_lease
            && fresh
            && !self.fenced.load(Ordering::Acquire)
            && before == self.epoch.load(Ordering::Acquire)
    }
    fn with_lease<T>(&self, f: impl FnOnce(&LinuxAssociationLease) -> Result<T>) -> Result<T> {
        let before = self.epoch.load(Ordering::Acquire);
        if self.fenced.load(Ordering::Acquire) {
            return Err(DesktopSourceError::Fenced);
        }
        let held = self
            .lease
            .lock()
            .map_err(|_| DesktopSourceError::Supervisor)?;
        let value = f(held.as_ref().ok_or(DesktopSourceError::Unavailable)?)?;
        if self.fenced.load(Ordering::Acquire) || before != self.epoch.load(Ordering::Acquire) {
            return Err(DesktopSourceError::Fenced);
        }
        Ok(value)
    }
}
struct Handle {
    state: Arc<State>,
    cancel: CancellationToken,
    requests: mpsc::Sender<Answer>,
    job: AsyncMutex<Option<JoinHandle<WatchReport>>>,
    terminal: Mutex<Option<Result<WatchReport>>>,
}
impl Drop for Handle {
    fn drop(&mut self) {
        self.state.fence();
        self.cancel.cancel();
        // Dropping JoinHandle detaches, never aborts: the original supervisor
        // still owns and waits its watch/probe children through cleanup.
    }
}
#[derive(Clone)]
pub(crate) struct DesktopSource {
    inner: Arc<Handle>,
}
struct StartGuard(Option<CancellationToken>);
impl Drop for StartGuard {
    fn drop(&mut self) {
        if let Some(cancel) = &self.0 {
            cancel.cancel();
        }
    }
}
impl DesktopSource {
    pub(crate) async fn start(selected: LinuxCandidate) -> Result<Self> {
        let state = Arc::new(State {
            fenced: AtomicBool::new(false),
            epoch: AtomicU64::new(1),
            lease: Mutex::new(None),
            verified_at: Mutex::new(None),
        });
        let cancel = CancellationToken::new();
        let mut guard = StartGuard(Some(cancel.clone()));
        let (requests, rx) = mpsc::channel(1);
        let (ready, ready_rx) = oneshot::channel();
        let job = tokio::spawn(supervise(
            selected,
            state.clone(),
            cancel.clone(),
            rx,
            ready,
        ));
        let source = Self {
            inner: Arc::new(Handle {
                state,
                cancel,
                requests,
                job: AsyncMutex::new(Some(job)),
                terminal: Mutex::new(None),
            }),
        };
        match ready_rx.await {
            Ok(Ok(())) => {
                guard.0 = None;
                Ok(source)
            }
            other => {
                source.inner.cancel.cancel();
                let _ = source.stop().await;
                Err(other
                    .ok()
                    .and_then(|r| r.err())
                    .unwrap_or(DesktopSourceError::Supervisor))
            }
        }
    }
    pub(crate) fn fenced(&self) -> bool {
        self.inner.state.fenced.load(Ordering::Acquire)
    }
    pub(crate) fn epoch(&self) -> u64 {
        self.inner.state.epoch.load(Ordering::Acquire)
    }
    pub(crate) async fn fresh(&self) -> Result<()> {
        if self.fenced() {
            return Err(DesktopSourceError::Fenced);
        }
        // The continuous logind watch worker fences immediately on session lock,
        // switch, or logout; avoid spawning a redundant association subprocess
        // on every Desktop call while the pinned lease is still within window.
        if self.inner.state.has_fresh_lease() {
            return Ok(());
        }
        let first = self.fresh_once().await;
        // A revalidation probe is read-only: retry it once if the original
        // pinned source is still live. Never replay any native Cua action.
        if matches!(first, Err(DesktopSourceError::Acquisition(error)) if recoverable_probe_failure(error, true))
            && !self.fenced()
        {
            return self.fresh_once().await;
        }
        first
    }
    async fn fresh_once(&self) -> Result<()> {
        if self.fenced() {
            return Err(DesktopSourceError::Fenced);
        }
        let (tx, rx) = oneshot::channel();
        // Use the original reader's normal channel backpressure. A concurrent
        // read is not a desktop-capacity refusal and creates no second probe.
        self.inner
            .requests
            .send(tx)
            .await
            .map_err(|_| DesktopSourceError::Fenced)?;
        rx.await.map_err(|_| DesktopSourceError::Supervisor)?
    }
    /// Caller invokes on its existing blocking boundary: registration_facts
    /// performs descriptor-relative native identity revalidation.
    pub(crate) fn initial_facts(&self, agent: AgentInstanceId) -> Result<RegistrationFacts> {
        let result = self.inner.state.with_lease(|lease| {
            lease
                .registration_facts(agent)
                .map_err(|_| DesktopSourceError::Fenced)
        });
        if result.is_err() {
            self.inner.state.fence();
            self.inner.cancel.cancel();
        }
        result
    }
    pub(crate) fn launch_fields(&self) -> Result<DesktopLaunchFields> {
        self.inner.state.with_lease(|lease| {
            Ok(DesktopLaunchFields {
                runtime_dir: lease.runtime_dir(),
                wayland_display: lease.wayland_display().into(),
                hyprland_instance: lease.hyprland_instance().into(),
            })
        })
    }
    pub(crate) fn window_read_evidence(&self) -> Result<WindowReadEvidence> {
        self.inner
            .state
            .with_lease(|lease| Ok(lease.window_read_evidence().clone()))
    }
    pub(crate) async fn stop(&self) -> Result<WatchReport> {
        self.inner.state.fence();
        self.inner.cancel.cancel();
        let mut slot = self.inner.job.lock().await;
        if let Some(job) = slot.as_mut() {
            // Await by mutable reference. Cancelling this public waiter leaves
            // the original JoinHandle in its slot for a subsequent real join.
            let result = job.await.map_err(|_| DesktopSourceError::Supervisor);
            // No await between consuming the completed JoinHandle and storing
            // its terminal result: cancelling stop cannot lose that fact.
            *slot = None;
            *self
                .inner
                .terminal
                .lock()
                .map_err(|_| DesktopSourceError::Supervisor)? = Some(result.clone());
            return result;
        }
        self.inner
            .terminal
            .lock()
            .map_err(|_| DesktopSourceError::Supervisor)?
            .clone()
            .ok_or(DesktopSourceError::Supervisor)?
    }
}
struct Pending {
    job: JoinHandle<
        std::result::Result<
            LinuxAssociationLease,
            crate::session_probe::association::AssociationProbeError,
        >,
    >,
    epoch: u64,
    answer: Answer,
}
fn begin_probe(selected: &LinuxCandidate, state: &State, answer: Answer) -> Pending {
    let selected = selected.clone();
    Pending {
        job: tokio::spawn(async move { probe_candidate(&selected).await }),
        epoch: state.epoch.load(Ordering::Acquire),
        answer,
    }
}
fn accept_event(
    selected: &LinuxCandidate,
    owner: &mut Option<String>,
    instance: &mut Option<AgentInstanceId>,
    event: &WatchObservation,
) -> Result<bool> {
    if instance
        .as_ref()
        .is_some_and(|v| v != &event.stream_instance)
    {
        return Err(DesktopSourceError::Fenced);
    }
    *instance = Some(event.stream_instance.clone());
    match &event.event.change {
        WatchChange::Snapshot {
            login_unique_owner,
            candidates,
        } => {
            if owner.as_ref().is_some_and(|v| v != login_unique_owner)
                || candidates.iter().filter(|c| *c == selected).count() != 1
            {
                return Err(DesktopSourceError::Fenced);
            }
            *owner = Some(login_unique_owner.clone());
            Ok(true)
        }
        WatchChange::Invalidations { items } => {
            if items.iter().any(|v| v.key == CandidateKey::from(selected)) {
                Err(DesktopSourceError::Fenced)
            } else {
                Ok(false)
            }
        }
    }
}
// A failed refresh does not prove a different desktop exists. Keep the original
// kernel-pinned association and revalidate it on the next read. A successful
// candidate must STILL match the original source exactly; an actual owner,
// process or socket identity replacement continues to fence this source.
fn recoverable_probe_failure(
    error: crate::session_probe::association::AssociationProbeError,
    initialized: bool,
) -> bool {
    use crate::platform::linux::association::AssociationError;
    use crate::session_probe::{ProbeError, association::AssociationProbeError};
    initialized
        && matches!(
            error,
            AssociationProbeError::Association(
                AssociationError::Unavailable
                    | AssociationError::Deadline
                    | AssociationError::Ambiguous
                    | AssociationError::Changed
                    | AssociationError::Capacity
                    | AssociationError::Inactive
            ) | AssociationProbeError::Probe(
                ProbeError::Spawn
                    | ProbeError::Deadline
                    | ProbeError::WorkerFailed
                    | ProbeError::Cancelled
            )
        )
}
fn source_probe_deferred(reason: &'static str) {
    eprintln!(
        "{}",
        serde_json::json!({"schema":1,"event":"desktop_source_probe_unavailable","reason":reason})
    );
}
fn source_fault(reason: &'static str) {
    // Diagnostic only; never consumed as authorization or native outcome proof.
    eprintln!(
        "{}",
        serde_json::json!({"schema":1,"event":"desktop_source_fenced","reason":reason})
    );
}
async fn supervise(
    selected: LinuxCandidate,
    state: Arc<State>,
    cancel: CancellationToken,
    mut requests: mpsc::Receiver<Answer>,
    ready: Answer,
) -> WatchReport {
    let (events, mut rx) = mpsc::channel(8);
    let watch_cancel = cancel.child_token();
    let producer_cancel = watch_cancel.clone();
    let mut producer =
        tokio::spawn(async move { watch::watch_current_user(events, producer_cancel).await });
    let mut owner = None;
    let mut instance = None;
    let mut ready = Some(ready);
    let mut pending: Option<Pending> = None;
    let startup = tokio::time::sleep(std::time::Duration::from_secs(5));
    tokio::pin!(startup);
    let mut initialized = false;
    let report = loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break None,
            _ = &mut startup, if !initialized => { state.fence(); break None; },
            event = rx.recv() => match event {
                Some(event) => match accept_event(&selected, &mut owner, &mut instance, &event) {
                    Ok(true) if ready.is_some() && pending.is_none() => pending = Some(begin_probe(&selected, &state, ready.take().expect("initial reply"))),
                    Ok(_) => {},
                    Err(_) => {
                        source_fault("watch_selected_source_invalidated");
                        state.fence(); break None;
                    }
                },
                None => { source_fault("watch_stream_ended"); state.fence(); break None; }
            },
            report = &mut producer => {
                // Only bounded typed reasons: no app titles, native content,
                // selectors, paths, user input or credentials enter diagnostics.
                if let Ok(value) = &report {
                    eprintln!("{}", serde_json::json!({"schema":1,"event":"desktop_source_fenced","watch_reason":value.reason}));
                } else {
                    source_fault("watch_supervisor_failed");
                }
                state.fence(); break Some(report);
            },
            result = async { (&mut pending.as_mut().expect("guarded pending").job).await }, if pending.is_some() => {
                let pending = pending.take().expect("completed probe");
                let result = match result {
                    Ok(Ok(fresh)) if !state.fenced.load(Ordering::Acquire) && pending.epoch == state.epoch.load(Ordering::Acquire) && owner.as_deref() == Some(fresh.login_unique_owner()) => {
                        match state.lease.lock() {
                            Ok(mut held) if held.as_ref().is_none_or(|original| original.same_source(&fresh)) => {
                                *held = Some(fresh);
                                if let Ok(mut verified) = state.verified_at.lock() {
                                    *verified = Some(Instant::now());
                                }
                                Ok(())
                            },
                            _ => { source_fault("association_source_identity_changed"); state.fence(); Err(DesktopSourceError::Fenced) }
                        }
                    },
                    Ok(Err(error)) if recoverable_probe_failure(error, initialized) => {
                        source_probe_deferred(error.code());
                        Err(DesktopSourceError::Acquisition(error))
                    },
                    Ok(Err(error)) => { source_fault(error.code()); state.fence(); Err(DesktopSourceError::Acquisition(error)) },
                    _ => { source_fault("association_epoch_owner_or_job_changed"); state.fence(); Err(DesktopSourceError::Fenced) }
                };
                let failed = result.is_err();
                if !failed { initialized = true; }
                let _ = pending.answer.send(result);
                if failed && state.fenced.load(Ordering::Acquire) { break None; }
            },
            request = requests.recv(), if ready.is_none() && pending.is_none() => match request {
                Some(answer) => pending = Some(begin_probe(&selected, &state, answer)),
                None => break None,
            }
        }
    };
    // Every terminal path fences before awaiting child cleanup. A dropped
    // public response cannot leave either owned worker without this supervisor.
    state.fence();
    watch_cancel.cancel();
    if let Some(pending) = pending {
        let _ = pending.job.await;
        let _ = pending.answer.send(Err(DesktopSourceError::Fenced));
    }
    if let Some(ready) = ready {
        let _ = ready.send(Err(DesktopSourceError::Fenced));
    }
    while let Ok(answer) = requests.try_recv() {
        let _ = answer.send(Err(DesktopSourceError::Fenced));
    }
    // Retain/drain the bounded consumer while producer emits its final fence.
    let result = match report {
        Some(report) => report,
        None => loop {
            tokio::select! {
                result = &mut producer => break result,
                event = rx.recv() => if event.is_none() { break producer.await; },
            }
        },
    };
    result.unwrap_or(WatchReport {
        stream_instance: instance,
        owned_worker_identity: None,
        fenced: true,
        reason: watch::ParentStop::CleanupUnconfirmed,
        child_reaped: false,
        worker_exit_success: None,
        stdout_eof: false,
        stdout_joined: false,
        worker_shutdown: None,
        final_invalidation_delivered: false,
    })
}

#[cfg(test)]
#[path = "desktop_source_tests.rs"]
mod tests;

/// Source supervisor settlement is platform-specific; this alias is Linux only.
pub(crate) type DesktopSourceStop = WatchReport;
pub(crate) fn source_stop_complete(report: &DesktopSourceStop) -> bool {
    report.child_reaped && report.stdout_joined
}

#[cfg(test)]
impl DesktopSource {
    pub(super) fn for_tests() -> Self {
        let (requests, _) = mpsc::channel(1);
        Self {
            inner: Arc::new(Handle {
                state: Arc::new(State {
                    fenced: AtomicBool::new(false),
                    epoch: AtomicU64::new(1),
                    lease: Mutex::new(None),
                    verified_at: Mutex::new(None),
                }),
                cancel: CancellationToken::new(),
                requests,
                job: AsyncMutex::new(None),
                terminal: Mutex::new(None),
            }),
        }
    }
}
