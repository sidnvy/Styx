//! Async custody around the original Windows session reader and WTS thread.
//! Never call blocking acquisition, checkpoint or join on a Tokio worker/App UI.
use super::{
    windows_native_observation::{ObservationError, Result},
    windows_source::{SourceObservation, WindowsSource},
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use styx_contracts::identity::{AgentInstanceId, Sha256Digest};
use styx_core::session::RegistrationFacts;
use tokio::{
    sync::{Mutex as AsyncMutex, mpsc, oneshot},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

type Answer = oneshot::Sender<Result<()>>;
#[derive(Clone, Copy, Debug)]
pub struct SourceCleanup {
    pub native_thread_joined: bool,
    pub native_handles_released: bool,
}
struct State {
    fenced: AtomicBool,
    epoch: AtomicU64,
    latest: Mutex<Option<SourceObservation>>,
    source_id: String,
    native_invalidated: Mutex<Option<CancellationToken>>,
}
impl State {
    fn fence(&self) {
        if !self.fenced.swap(true, Ordering::AcqRel) {
            self.epoch.fetch_add(1, Ordering::AcqRel);
        }
    }
}
struct Inner {
    state: Arc<State>,
    cancel: CancellationToken,
    requests: mpsc::Sender<Answer>,
    worker: AsyncMutex<Option<JoinHandle<Result<()>>>>,
    terminal: Mutex<Option<Result<()>>>,
}
impl Drop for Inner {
    fn drop(&mut self) {
        self.state.fence();
        self.cancel.cancel();
        // The supervisor still owns all blocking jobs and original native source.
        // Dropping this observer does not abort work or synchronously join WTS.
    }
}
#[derive(Clone)]
pub(crate) struct DesktopSource {
    inner: Arc<Inner>,
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
    pub(crate) async fn start() -> Result<Self> {
        let state = Arc::new(State {
            fenced: AtomicBool::new(false),
            epoch: AtomicU64::new(1),
            latest: Mutex::new(None),
            native_invalidated: Mutex::new(None),
            source_id: format!("windows-source-{}", uuid::Uuid::new_v4().simple()),
        });
        let cancel = CancellationToken::new();
        let mut guard = StartGuard(Some(cancel.clone()));
        let (requests, rx) = mpsc::channel(1);
        let (ready, ready_rx) = oneshot::channel();
        let worker = tokio::spawn(supervise(state.clone(), cancel.clone(), rx, ready));
        let source = Self {
            inner: Arc::new(Inner {
                state,
                cancel,
                requests,
                worker: AsyncMutex::new(Some(worker)),
                terminal: Mutex::new(None),
            }),
        };
        match ready_rx.await {
            Ok(Ok(())) => {
                guard.0 = None;
                Ok(source)
            }
            other => {
                drop(guard);
                let _ = source.stop().await;
                Err(other
                    .ok()
                    .and_then(Result::err)
                    .unwrap_or(ObservationError::Fenced))
            }
        }
    }
    pub(crate) fn source_id(&self) -> &str {
        &self.inner.state.source_id
    }
    pub(crate) fn fenced(&self) -> bool {
        self.inner.state.fenced.load(Ordering::Acquire)
            || self
                .inner
                .state
                .native_invalidated
                .lock()
                .map_or(true, |v| {
                    v.as_ref().is_some_and(CancellationToken::is_cancelled)
                })
    }
    pub(crate) fn epoch(&self) -> u64 {
        self.inner.state.epoch.load(Ordering::Acquire)
    }
    pub(crate) async fn fresh(&self) -> Result<()> {
        if self.fenced() {
            return Err(ObservationError::Fenced);
        }
        let (answer, receive) = oneshot::channel();
        self.inner
            .requests
            .try_send(answer)
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => ObservationError::Busy,
                mpsc::error::TrySendError::Closed(_) => ObservationError::Fenced,
            })?;
        receive.await.map_err(|_| ObservationError::Fenced)?
    }
    /// Cached native facts installed only by the original successful reader.
    /// Caller obtains fresh() before registration; this does no native blocking.
    pub(crate) fn initial_facts(&self, agent: AgentInstanceId) -> Result<RegistrationFacts> {
        let epoch = self.epoch();
        if self.fenced() {
            return Err(ObservationError::Fenced);
        }
        let held = self
            .inner
            .state
            .latest
            .lock()
            .map_err(|_| ObservationError::Fenced)?;
        let observed = held.as_ref().ok_or(ObservationError::Fenced)?;
        let bytes = serde_json::to_vec(&(
            &observed.native.identity,
            &observed.native.process,
            self.source_id(),
        ))
        .map_err(|_| ObservationError::Malformed)?;
        let facts = RegistrationFacts {
            id: format!("windows-{}", Sha256Digest::of_bytes(&bytes).to_hex())
                .try_into()
                .map_err(|_| ObservationError::Malformed)?,
            identity: observed.native.identity.clone(),
            agent_instance: agent,
            protocol_version: 1,
            provenance:
                "original primary token/process/input desktop; WTS registered native source".into(),
        };
        if self.fenced() || epoch != self.epoch() || observed.epoch != epoch {
            return Err(ObservationError::Fenced);
        }
        Ok(facts)
    }
    pub(crate) fn window_read_evidence(
        &self,
    ) -> Result<super::windows_native_observation::WindowReadEvidence> {
        let before = self.epoch();
        if self.fenced() {
            return Err(ObservationError::Fenced);
        }
        let held = self
            .inner
            .state
            .latest
            .lock()
            .map_err(|_| ObservationError::Fenced)?;
        let observed = held.as_ref().ok_or(ObservationError::Fenced)?;
        if observed.epoch != before || before != self.epoch() || self.fenced() {
            return Err(ObservationError::Fenced);
        }
        Ok(observed.windows)
    }
    pub(crate) async fn stop(&self) -> Result<SourceCleanup> {
        self.inner.state.fence();
        self.inner.cancel.cancel();
        let mut slot = self.inner.worker.lock().await;
        if let Some(job) = slot.as_mut() {
            let result = job
                .await
                .unwrap_or(Err(ObservationError::NativeQueryFailed));
            *slot = None;
            *self
                .inner
                .terminal
                .lock()
                .map_err(|_| ObservationError::Fenced)? = Some(result);
            return result.map(|_| SourceCleanup {
                native_thread_joined: true,
                native_handles_released: true,
            });
        }
        self.inner
            .terminal
            .lock()
            .map_err(|_| ObservationError::Fenced)?
            .unwrap_or(Err(ObservationError::Fenced))
            .map(|_| SourceCleanup {
                native_thread_joined: true,
                native_handles_released: true,
            })
    }
    pub(crate) async fn invalidated(&self) {
        self.inner.cancel.cancelled().await;
    }
}
fn install(state: &State, observed: SourceObservation) -> Result<()> {
    if state.fenced.load(Ordering::Acquire) || observed.epoch != state.epoch.load(Ordering::Acquire)
    {
        return Err(ObservationError::Fenced);
    }
    *state.latest.lock().map_err(|_| ObservationError::Fenced)? = Some(observed);
    Ok(())
}
async fn supervise(
    state: Arc<State>,
    cancel: CancellationToken,
    mut rx: mpsc::Receiver<Answer>,
    ready: Answer,
) -> Result<()> {
    // The supervisor (not the request waiter) owns this original JoinHandle.
    // If Win32 startup wedges, only this lane stays pending/Unknown; other Host
    // lanes must not hold a lock or await Desktop readiness before serving Exec.
    let mut acquire = tokio::task::spawn_blocking(|| {
        let source = WindowsSource::acquire_current()?;
        let observation = source.fresh()?;
        let invalidated = source.invalidation_token();
        Ok::<_, ObservationError>((Arc::new(Mutex::new(source)), observation, invalidated))
    });
    let acquired = tokio::select! {
        value = &mut acquire => value,
        _ = cancel.cancelled() => { state.fence(); (&mut acquire).await },
    };
    let (source, observation, invalidated) = match acquired {
        Ok(Ok(value)) => value,
        other => {
            state.fence();
            cancel.cancel();
            let error = other
                .ok()
                .and_then(Result::err)
                .unwrap_or(ObservationError::NativeQueryFailed);
            let _ = ready.send(Err(error));
            return Err(error);
        }
    };
    if let Ok(mut native) = state.native_invalidated.lock() {
        *native = Some(invalidated.clone());
    } else {
        state.fence();
    }
    let initial = if cancel.is_cancelled() || invalidated.is_cancelled() {
        Err(ObservationError::Fenced)
    } else {
        install(&state, observation)
    };
    let initial_failed = initial.is_err();
    let _ = ready.send(initial);
    if !initial_failed {
        loop {
            let answer = tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                _ = invalidated.cancelled() => { break; },
                answer = rx.recv() => match answer { Some(answer) => answer, None => break },
            };
            let original = source.clone();
            let mut read = tokio::task::spawn_blocking(move || {
                original
                    .lock()
                    .map_err(|_| ObservationError::Fenced)?
                    .fresh()
            });
            let value = tokio::select! {
                value = &mut read => value,
                _ = cancel.cancelled() => { state.fence(); (&mut read).await },
                _ = invalidated.cancelled() => { state.fence(); (&mut read).await },
            };
            let result = value
                .unwrap_or(Err(ObservationError::NativeQueryFailed))
                .and_then(|v| install(&state, v));
            let failed = result.is_err();
            let _ = answer.send(result);
            if failed {
                break;
            }
        }
    }
    state.fence();
    cancel.cancel();
    while let Ok(answer) = rx.try_recv() {
        let _ = answer.send(Err(ObservationError::Fenced));
    }
    // No blocking mutex guard is carried across await; cleanup retains the
    // original source and joins its exact WTS thread inside this blocking job.
    let stopped = tokio::task::spawn_blocking(move || {
        source
            .lock()
            .map_err(|_| ObservationError::Fenced)?
            .stop_and_join()
    })
    .await
    .unwrap_or(Err(ObservationError::NativeQueryFailed));
    stopped
}
