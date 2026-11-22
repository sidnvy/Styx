//! Host-owned start/read/targeted-action composition.
//! No network DTO can construct control authority. Physical retention is Core-
//! attested; legacy raw-wire mode remains outside this composition.
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
mod browser;
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
pub use browser::*;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
mod desktop;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) use desktop::*;
#[cfg(target_os = "linux")]
mod desktop_source;
#[cfg(target_os = "windows")]
mod desktop_source {
    pub(crate) use crate::platform::windows_desktop::{
        DesktopSource, SourceCleanup as DesktopSourceStop,
    };
    pub(crate) fn source_stop_complete(report: &DesktopSourceStop) -> bool {
        report.native_thread_joined && report.native_handles_released
    }
}
#[cfg(target_os = "macos")]
#[path = "desktop_source_macos.rs"]
mod desktop_source;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) use desktop_source::{DesktopSource, source_stop_complete};
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
mod desktop_cleanup;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub use desktop_cleanup::DesktopLaneCleanup;
#[cfg(not(target_os = "android"))]
mod exec;
#[cfg(not(target_os = "android"))]
use exec::transfer_known_action;
#[cfg(not(target_os = "android"))]
pub use exec::{
    ActionCompletion, ActionSubmission, ActionTicket, StartCompletion, StartSubmission, StartTicket,
};
mod android;
mod owner_cleanup;
mod retention;
#[cfg(not(target_os = "android"))]
mod session;
pub use owner_cleanup::{OwnerCleanupFacts, OwnerCleanupHandle, OwnerCleanupTicket};
pub use retention::{RetentionBlock, RetentionCollection};

#[cfg(not(target_os = "android"))]
use crate::providers::codex::{
    ActionEvidence, ActionReceipt, CleanupReceipt, CodexStdio, DispatchEvidence, ExecError,
    ProcessAction, ProcessOutput, StartProcess, TerminationEvidence,
};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use styx_contracts::{error::ErrorCategory, identity::*, operation::*};
use styx_core::{operations::*, policy::AdmissionFacts};
use tokio::sync::{OwnedRwLockReadGuard, RwLock, oneshot};
use tokio::task::JoinSet;

#[derive(Debug, thiserror::Error)]
pub enum CoordinatorError {
    #[error("Host admission refused ({0:?})")]
    Admission(ErrorCategory),
    #[cfg(not(target_os = "android"))]
    #[error("executor refused or could not resolve resource")]
    Executor(#[from] ExecError),
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    #[error("Browser executor refused or has an unknown outcome")]
    Browser(#[from] crate::providers::browser::BrowserError),
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[error("Desktop executor refused or has an unknown outcome")]
    Desktop(#[from] crate::providers::cua::CuaError),
    #[error("Host work budget exhausted or maintenance is active")]
    Busy,
    #[error("Host response delivery ended; reconcile original operation without replay")]
    ResponseLost,
    #[error("read deadline expired; process outcome is unchanged")]
    ReadDeadline,
    #[error("read output was consumed but delivery authorization is no longer valid ({0:?})")]
    OutputDeliveryDenied(ErrorCategory),
}
impl From<ErrorCategory> for CoordinatorError {
    fn from(value: ErrorCategory) -> Self {
        Self::Admission(value)
    }
}
struct State {
    ledger: OperationLedger,
    facts: AdmissionFacts,
    shutting_down: bool,
    #[cfg(not(target_os = "android"))]
    sessions: crate::session::HostSessions,
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    browser: Option<browser::BrowserLane>,
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    desktop: Option<desktop::DesktopLane>,
}
impl State {
    fn new(ledger: OperationLedger, facts: AdmissionFacts, origin: Instant) -> Self {
        #[cfg(not(target_os = "android"))]
        let sessions =
            crate::session::HostSessions::bootstrap(ledger.host_generation().clone(), origin);
        Self {
            ledger,
            facts,
            #[cfg(not(target_os = "android"))]
            sessions,
            #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
            browser: None,
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            desktop: None,
            shutting_down: false,
        }
    }
    /// This coordinator owns only Codex Exec. Session facts have a separate
    /// registry; accidentally replacing Exec policy with GUI facts is refused.
    #[cfg(not(target_os = "android"))]
    fn exec_facts(&self) -> Result<AdmissionFacts, ErrorCategory> {
        if self.facts.descriptor.capability_id != styx_contracts::capability::CapabilityId::ExecRun
        {
            return Err(ErrorCategory::ProtocolMismatch);
        }
        if self.facts.descriptor.target_session.is_some()
            || self.facts.session_state.is_some()
            || self.facts.current_observation.is_some()
            || self.facts.descriptor.scope != styx_contracts::capability::Scope::Host
        {
            return Err(ErrorCategory::StateConflict);
        }
        Ok(self.facts.clone())
    }
    #[cfg(not(target_os = "android"))]
    fn reserve_exec(
        &mut self,
        owner: &OwnerLease,
        context: PreparedContext,
        payload: Vec<u8>,
        target: Option<ResourceTarget>,
        now: MonotonicMillis,
    ) -> Result<OperationSnapshot, CoordinatorError> {
        validate_exec_context(&context)?;
        if self.shutting_down {
            return Err(CoordinatorError::Busy);
        }
        self.exec_facts()?;
        Ok(match target {
            Some(target) => self
                .ledger
                .prepare_targeted(owner, target, context, payload, now)?,
            None => self.ledger.prepare(owner, context, payload, now)?,
        })
    }
    #[cfg(not(target_os = "android"))]
    fn dispatch_exec(
        &mut self,
        owner: &OwnerLease,
        id: &OperationId,
        digest: Sha256Digest,
        now: MonotonicMillis,
    ) -> Result<DispatchDisposition, ErrorCategory> {
        let facts = self.exec_facts()?;
        self.ledger.dispatch(owner, id, digest, &facts, now)
    }
    #[cfg(not(target_os = "android"))]
    fn authorize_exec_read(
        &self,
        owner: &OwnerLease,
        id: &OperationId,
        digest: Sha256Digest,
        context: &PreparedContext,
        now: MonotonicMillis,
    ) -> Result<OperationSnapshot, ErrorCategory> {
        validate_exec_context(context)?;
        self.ledger
            .authorize_resource_access(owner, id, digest, context, &self.exec_facts()?, now)
    }
    #[cfg(not(target_os = "android"))]
    fn with_sessions<T>(
        &mut self,
        f: impl FnOnce(&mut crate::session::HostSessions) -> Result<T, crate::session::HostSessionError>,
    ) -> Result<T, crate::session::HostSessionError> {
        if self.shutting_down {
            return Err(crate::session::HostSessionError::Stopping);
        }
        f(&mut self.sessions)
    }
}
#[cfg(not(target_os = "android"))]
fn validate_exec_context(context: &PreparedContext) -> Result<(), ErrorCategory> {
    if context.capability != styx_contracts::capability::CapabilityId::ExecRun {
        return Err(ErrorCategory::ProtocolMismatch);
    }
    if context.session.is_some() || context.observation.is_some() {
        return Err(ErrorCategory::StateConflict);
    }
    Ok(())
}

/// Trusted local composition only. This reads the original configuration
/// authority; no request or DTO can install/replace an admission source.
#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "macos",
    target_os = "windows"
))]
pub(crate) trait ExecAdmission: Send + Sync {
    fn check(&self) -> Result<(), CoordinatorError>;
}
struct Inner {
    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "macos",
        target_os = "windows"
    ))]
    exec_admission: Mutex<Option<Arc<dyn ExecAdmission>>>,
    bootstrap_device: DeviceId,
    host_generation: HostGeneration,
    #[cfg(not(target_os = "android"))]
    adapter: Mutex<Option<Arc<CodexStdio>>>,
    state: Mutex<State>,
    jobs: Mutex<JoinSet<()>>,
    cleanup_lock: tokio::sync::Mutex<()>,
    execution_gate: Arc<RwLock<()>>,
    origin: Instant,
    #[cfg(test)]
    delivery_gate: Mutex<Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>>,
}
impl Inner {
    fn now(&self) -> MonotonicMillis {
        MonotonicMillis(u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX))
    }
}
// Kept outside Inner: caller cleanup handles retain Inner, so putting the
// access registry inside it would create a self-owning cycle on shutdown.
struct RuntimeState {
    #[cfg(not(target_os = "android"))]
    browser_sessions: super::browser_sessions::State,
    #[cfg(not(target_os = "android"))]
    exec_tasks: super::exec_tasks::State,
    remote_access: Mutex<super::callers::OwnerRegistry>,
    connection_slot: tokio::sync::Semaphore,
}
/// Request plane. Clones share one Host runtime and never create an executor.
#[derive(Clone)]
pub struct HostCoordinator {
    runtime: Arc<RuntimeState>,
    inner: Arc<Inner>,
}
/// Bootstrap-only control plane. No Deserialize, Clone or public field constructor.
/// Pass only to authenticated Host composition, never to a network request handler.
pub struct HostAuthority {
    inner: Arc<Inner>,
}
#[derive(Debug)]
pub struct HostCleanup {
    /// None means no Exec adapter was ever started, not an observed exit.
    #[cfg(not(target_os = "android"))]
    pub native: Option<CleanupReceipt>,
    pub supervised_jobs_joined: bool,
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    pub browser: Option<BrowserLaneCleanup>,
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    pub desktop: Option<DesktopLaneCleanup>,
}
impl HostCleanup {
    /// Native Codex facts and Browser process-tree facts are independent.
    pub fn ancillary_providers_settled(&self) -> bool {
        #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
        {
            self.browser.as_ref().is_none_or(|facts| facts.complete)
                && self.desktop.as_ref().is_none_or(|facts| facts.complete)
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        {
            true
        }
    }
}

#[cfg(not(target_os = "android"))]
impl Inner {
    fn check_exec_admission(&self) -> Result<(), CoordinatorError> {
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "macos",
            target_os = "windows"
        ))]
        {
            let source = self
                .exec_admission
                .lock()
                .expect("Exec admission mutex")
                .clone();
            if let Some(source) = source {
                source.check()?;
            }
        }
        Ok(())
    }
    fn exec_adapter(&self) -> Result<Arc<CodexStdio>, CoordinatorError> {
        self.adapter
            .lock()
            .expect("Exec adapter mutex")
            .clone()
            .ok_or_else(|| ErrorCategory::CapabilityUnsupported.into())
    }
}
impl HostCoordinator {
    /// Takes exclusive ownership of one already-started executor, never spawns a second.
    #[cfg(not(target_os = "android"))]
    pub fn new_owned(
        adapter: CodexStdio,
        ledger: OperationLedger,
        trusted_facts: AdmissionFacts,
    ) -> Result<(Self, HostAuthority), CoordinatorError> {
        Self::compose(Some(adapter), ledger, trusted_facts)
    }
    /// Explicit disabled Exec composition, with the same ledger and authority.
    /// A configured executor's spawn failure must never call this as fallback.
    #[cfg(not(target_os = "android"))]
    pub fn new_without_executor(
        ledger: OperationLedger,
        mut trusted_facts: AdmissionFacts,
    ) -> Result<(Self, HostAuthority), CoordinatorError> {
        trusted_facts.descriptor.configured = false;
        trusted_facts.descriptor.availability =
            styx_contracts::capability::Availability::Unavailable;
        trusted_facts.descriptor.authorization = styx_contracts::capability::Authorization::Unknown;
        trusted_facts.descriptor.reason = Some(ErrorCategory::CapabilityUnsupported);
        Self::compose(None, ledger, trusted_facts)
    }
    /// Mobile composition keeps the same identity, owner ledger and lifecycle.
    pub fn new_mobile(
        ledger: OperationLedger,
        trusted_facts: AdmissionFacts,
    ) -> Result<(Self, HostAuthority), CoordinatorError> {
        #[cfg(target_os = "android")]
        {
            Self::compose(ledger, trusted_facts)
        }
        #[cfg(not(target_os = "android"))]
        {
            Self::compose(None, ledger, trusted_facts)
        }
    }
    fn compose(
        #[cfg(not(target_os = "android"))] adapter: Option<CodexStdio>,
        ledger: OperationLedger,
        trusted_facts: AdmissionFacts,
    ) -> Result<(Self, HostAuthority), CoordinatorError> {
        let origin = Instant::now();
        let inner = Arc::new(Inner {
            #[cfg(any(
                all(target_os = "linux", target_env = "gnu"),
                target_os = "macos",
                target_os = "windows"
            ))]
            exec_admission: Mutex::new(None),
            bootstrap_device: trusted_facts.device_id.clone(),
            host_generation: ledger.host_generation().clone(),
            #[cfg(not(target_os = "android"))]
            adapter: Mutex::new(adapter.map(Arc::new)),
            state: Mutex::new(State::new(ledger, trusted_facts, origin)),
            jobs: Mutex::new(JoinSet::new()),
            cleanup_lock: tokio::sync::Mutex::new(()),
            execution_gate: Arc::new(RwLock::new(())),
            origin,
            #[cfg(test)]
            delivery_gate: Mutex::new(None),
        });
        Ok((
            Self {
                inner: inner.clone(),
                runtime: Arc::new(RuntimeState {
                    #[cfg(not(target_os = "android"))]
                    browser_sessions: super::browser_sessions::State::default(),
                    #[cfg(not(target_os = "android"))]
                    exec_tasks: super::exec_tasks::State::default(),
                    remote_access: Mutex::new(super::callers::OwnerRegistry::default()),
                    connection_slot: tokio::sync::Semaphore::new(1),
                }),
            },
            HostAuthority { inner },
        ))
    }
    /// Configuration/presence only; never infer liveness from cached initialize.
    #[cfg(not(target_os = "android"))]
    pub(crate) fn browser_sessions(&self) -> &super::browser_sessions::State {
        &self.runtime.browser_sessions
    }
    pub(crate) fn remote_access(&self) -> &Mutex<super::callers::OwnerRegistry> {
        &self.runtime.remote_access
    }
    pub(crate) fn connection_slot(&self) -> &tokio::sync::Semaphore {
        &self.runtime.connection_slot
    }
    #[cfg(not(target_os = "android"))]
    pub(crate) fn exec_tasks(&self) -> &super::exec_tasks::State {
        &self.runtime.exec_tasks
    }
    pub fn exec_configured(&self) -> bool {
        #[cfg(target_os = "android")]
        {
            false
        }
        #[cfg(not(target_os = "android"))]
        {
            self.inner
                .adapter
                .lock()
                .expect("Exec adapter mutex")
                .is_some()
        }
    }
    /// Immutable, non-secret bootstrap identity; policy refresh cannot rebind it.
    pub fn bootstrap_identity(&self) -> (&DeviceId, &HostGeneration) {
        (&self.inner.bootstrap_device, &self.inner.host_generation)
    }
    /// Prevent cross-wiring independent Host instances with identical public IDs.
    pub fn shares_authority(&self, authority: &HostAuthority) -> bool {
        Arc::ptr_eq(&self.inner, &authority.inner)
    }
    /// Host-local policy revision; never derived from Gateway enrollment generations.
    pub(crate) fn grant_revision(&self) -> u64 {
        self.inner
            .state
            .lock()
            .expect("Host state mutex")
            .facts
            .grant_revision
    }
    pub fn now(&self) -> MonotonicMillis {
        self.inner.now()
    }
    // Wait on the existing lifecycle lock within this request's original
    // deadline. Another owner's collection is not a capacity refusal.
    async fn execution_before(
        &self,
        deadline: Option<MonotonicMillis>,
    ) -> Result<OwnedRwLockReadGuard<()>, CoordinatorError> {
        if let Ok(guard) = self.inner.execution_gate.clone().try_read_owned() {
            return Ok(guard);
        }
        let until = deadline.map(|deadline| {
            tokio::time::Instant::now()
                + Duration::from_millis(deadline.0.saturating_sub(self.now().0))
        });
        let wait = self.inner.execution_gate.clone().read_owned();
        match until {
            Some(until) => tokio::time::timeout_at(until, wait)
                .await
                .map_err(|_| ErrorCategory::OperationTimeout.into()),
            None => Ok(wait.await),
        }
    }
    async fn execution_for_operation(
        &self,
        owner: &OwnerLease,
        id: &OperationId,
        digest: Sha256Digest,
    ) -> Result<OwnedRwLockReadGuard<()>, CoordinatorError> {
        let deadline = {
            let state = self.inner.state.lock().expect("Host state mutex");
            if state.shutting_down {
                return Err(CoordinatorError::Busy);
            }
            state.ledger.inspect_context(owner, id, digest)?.deadline
        };
        self.execution_before(deadline).await
    }
}
struct UnsettledAction {
    inner: Arc<Inner>,
    operation: OperationId,
    settled: bool,
    _execution: OwnedRwLockReadGuard<()>,
}
impl Drop for UnsettledAction {
    fn drop(&mut self) {
        if !self.settled {
            let mut state = self.inner.state.lock().expect("Host state mutex");
            let _ = state.ledger.record_action_result(
                &self.operation,
                ActionResult::Unknown,
                self.inner.now(),
            );
        }
    }
}
struct UnsettledStart {
    inner: Arc<Inner>,
    operation: OperationId,
    settled: bool,
    _execution: OwnedRwLockReadGuard<()>,
}
impl Drop for UnsettledStart {
    fn drop(&mut self) {
        if !self.settled {
            let _ = self
                .inner
                .state
                .lock()
                .expect("Host state mutex")
                .ledger
                .mark_result_unknown(&self.operation);
        }
    }
}
impl HostAuthority {
    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        all(test, target_os = "macos")
    ))]
    pub(crate) fn configure_exec_admission(
        &self,
        source: Arc<dyn ExecAdmission>,
    ) -> Result<(), CoordinatorError> {
        let state = self.inner.state.lock().expect("Host state mutex");
        if state.shutting_down {
            return Err(CoordinatorError::Busy);
        }
        let mut current = self
            .inner
            .exec_admission
            .lock()
            .expect("Exec admission mutex");
        if current.is_some() {
            return Err(CoordinatorError::Busy);
        }
        *current = Some(source);
        Ok(())
    }
    pub fn register_verified_owner(
        &self,
        owner: OwnerId,
        epoch: OwnerEpoch,
    ) -> Result<OwnerLease, CoordinatorError> {
        Ok(self
            .inner
            .state
            .lock()
            .expect("Host state mutex")
            .ledger
            .register_verified_owner(owner, epoch)?)
    }
    #[cfg(not(target_os = "android"))]
    pub(crate) fn attach_executor(
        &self,
        adapter: CodexStdio,
        facts: AdmissionFacts,
    ) -> Result<(), CoordinatorError> {
        let mut current = self.inner.adapter.lock().expect("Exec adapter mutex");
        let mut state = self.inner.state.lock().expect("Host state mutex");
        if current.is_some() || state.shutting_down {
            return Err(CoordinatorError::Busy);
        }
        *current = Some(Arc::new(adapter));
        state.facts = facts;
        Ok(())
    }
    /// Host-local settings close only disabled providers. Pairing, owner identity
    /// and resources belonging to enabled providers remain in the same ledger.
    pub(crate) async fn stop_disabled_capabilities(
        &self,
        enabled: crate::host::settings::Capabilities,
    ) -> Result<(), ErrorCategory> {
        let until = tokio::time::Instant::now() + Duration::from_secs(30);
        let _cleanup = tokio::time::timeout_at(until, self.inner.cleanup_lock.lock())
            .await
            .map_err(|_| ErrorCategory::Busy)?;
        let _quiescent =
            tokio::time::timeout_at(until, self.inner.execution_gate.clone().write_owned())
                .await
                .map_err(|_| ErrorCategory::Busy)?;
        let remaining = || until.saturating_duration_since(tokio::time::Instant::now());
        let mut complete = true;
        #[cfg(not(target_os = "android"))]
        if !enabled.exec {
            let adapter = self
                .inner
                .adapter
                .lock()
                .expect("Exec adapter mutex")
                .clone();
            if let Some(adapter) = adapter {
                let processes = adapter.stop_owned_tasks(until).await;
                for (handle, evidence) in &processes {
                    if let TerminationEvidence::ProcessExited(code) = evidence {
                        let _ = self
                            .inner
                            .state
                            .lock()
                            .expect("Host state mutex")
                            .ledger
                            .record_executor_fact(
                                handle.operation(),
                                ExecutorFact::Exited {
                                    successful: *code == 0,
                                },
                                self.inner.now(),
                            );
                    }
                }
                complete &= processes
                    .iter()
                    .all(|(_, evidence)| matches!(evidence, TerminationEvidence::ProcessExited(_)));
                // The Host retains this executor and its original task records.
                // Turning a capability back on never swaps provider ownership.
            }
        }
        #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
        {
            if !enabled.browser {
                complete &= browser::cleanup_browser_lane(self.inner.clone(), remaining())
                    .await
                    .is_none_or(|r| r.complete);
            }
            if !enabled.computer {
                // Retain the platform observation source; only its Cua sessions
                // end. Re-enabling uses the same normal platform lifecycle.
                complete &=
                    desktop_cleanup::cleanup_selected(self.inner.clone(), None, remaining())
                        .await
                        .is_none_or(|r| r.complete);
            }
        }
        if complete {
            Ok(())
        } else {
            Err(ErrorCategory::ResultUnknown)
        }
    }
    pub fn replace_trusted_facts(&self, facts: AdmissionFacts) {
        self.inner.state.lock().expect("Host state mutex").facts = facts;
    }
    pub fn revoke_owner(&self, owner: &OwnerLease) -> Result<(), CoordinatorError> {
        Ok(self
            .inner
            .state
            .lock()
            .expect("Host state mutex")
            .ledger
            .revoke_owner(owner)?)
    }
    /// Explicit Host supervision action, never implicitly called on transport drop.
    /// Retains unfinished JoinHandles and real cleanup facts on deadline exhaustion.
    pub async fn shutdown_owned(&self, budget: Duration) -> Result<HostCleanup, CoordinatorError> {
        let until = tokio::time::Instant::now() + budget.min(Duration::from_secs(30));
        let _cleanup = tokio::time::timeout_at(until, self.inner.cleanup_lock.lock())
            .await
            .map_err(|_| CoordinatorError::Busy)?;
        {
            let mut state = self.inner.state.lock().expect("Host state mutex");
            state.shutting_down = true;
            state.ledger.begin_maintenance();
        }
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        let desktop = desktop_cleanup::cleanup_desktop_lane(
            self.inner.clone(),
            until.saturating_duration_since(tokio::time::Instant::now()),
        )
        .await;
        let mut jobs = std::mem::replace(
            &mut *self.inner.jobs.lock().expect("Host jobs mutex"),
            JoinSet::new(),
        );
        let mut joined = true;
        while !jobs.is_empty() {
            match tokio::time::timeout_at(until, jobs.join_next()).await {
                Ok(Some(Ok(()))) => {}
                Ok(Some(Err(_))) => joined = false,
                Ok(None) => break,
                Err(_) => {
                    joined = false;
                    break;
                }
            }
        }
        // A JoinSet aborts on drop; preserve unfinished jobs rather than implicitly
        // canceling a possible native start while forgetting its result.
        *self.inner.jobs.lock().expect("Host jobs mutex") = jobs;
        #[cfg(not(target_os = "android"))]
        let adapter = self
            .inner
            .adapter
            .lock()
            .expect("Exec adapter mutex")
            .clone();
        #[cfg(not(target_os = "android"))]
        let native = match adapter.as_ref() {
            Some(adapter) => Some(
                adapter
                    .shutdown_owned(until.saturating_duration_since(tokio::time::Instant::now()))
                    .await,
            ),
            None => None,
        };
        #[cfg(not(target_os = "android"))]
        if let Some(receipt) = &native {
            for (handle, evidence) in &receipt.processes {
                if let TerminationEvidence::ProcessExited(code) = evidence {
                    let _ = self
                        .inner
                        .state
                        .lock()
                        .expect("Host state mutex")
                        .ledger
                        .record_executor_fact(
                            handle.operation(),
                            ExecutorFact::Exited {
                                successful: *code == 0,
                            },
                            self.inner.now(),
                        );
                }
            }
        }
        #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
        let browser = browser::cleanup_browser_lane(
            self.inner.clone(),
            until.saturating_duration_since(tokio::time::Instant::now()),
        )
        .await;
        Ok(HostCleanup {
            #[cfg(not(target_os = "android"))]
            native,
            supervised_jobs_joined: joined,
            #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
            browser,
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            desktop,
        })
    }
}
#[cfg(all(test, not(target_os = "android")))]
mod tests;

impl HostCoordinator {
    pub(crate) fn owner_is_active(&self, owner: &OwnerLease) -> bool {
        self.inner
            .state
            .lock()
            .is_ok_and(|state| state.ledger.validate_owner(owner).is_ok())
    }
}

#[cfg(all(test, not(target_os = "android")))]
impl HostCoordinator {
    pub(crate) fn retained_exec_processes_for_test(&self) -> usize {
        self.inner.exec_adapter().unwrap().retained_processes()
    }
    pub(crate) async fn close_exec_fixture_for_test(&self) {
        self.inner.exec_adapter().unwrap().close_fixture_io().await;
    }
}
