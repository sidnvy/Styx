//! App-owned macOS daemon with the official embedded socket MCP proxy.
//! Standard session lifecycle and actual owned-process/IO completion replace
//! the former private control/drain/report protocol.
//! Source observations pin the original App/daemon; the official proxy opens
//! its own private-path connections. This is not per-call FD/PID attestation.
use super::macos_source::{BoundMacSource, MacAppImages, MacSourceCandidate, NativeObservation};
use super::probe_diagnostic::{ProbeCause, ProbeDiagnostic, ProbeStage};
use super::{CuaError, OwnedCuaConfig, Result};
use crate::{
    platform::macos_spawn::{self, RunningChild, SuspendedChild},
    store::PrivateRoot,
};
use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
};
use styx_contracts::{identity::Sha256Digest, session::SessionBinding};
use tokio::{
    process::{ChildStderr, ChildStdin, ChildStdout},
    time::{Instant, timeout_at},
};

/// Preparing/Prepared/Probing are the exclusive substeps of qualification.
/// Only Ready may back a native executor; transport cleanup remains separate.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum SourcePhase {
    Unqualified,
    Preparing,
    Prepared,
    Probing,
    Ready,
    Fenced,
    Ended,
}

fn publish_runtime_fault(
    sender: &tokio::sync::watch::Sender<Option<(ProbeStage, ProbeCause)>>,
    ready: bool,
    diagnostic: ProbeDiagnostic,
) {
    if ready
        && diagnostic.stage != ProbeStage::AlreadyFenced
        && !(diagnostic.stage == ProbeStage::EvidenceLookup
            && diagnostic.cause == ProbeCause::Fenced)
    {
        sender.send_if_modified(|current| {
            if current.is_some() {
                false
            } else {
                *current = Some((diagnostic.stage, diagnostic.cause));
                true
            }
        });
    }
}

pub(crate) struct MacProxySource {
    control: Mutex<BoundMacSource>,
    observations: Mutex<BoundMacSource>,
    fingerprint: Sha256Digest,
    phase: AtomicU8,
    initial_epoch_advanced: AtomicBool,
    // Diagnostic custody only; no source permission or readiness derives from it.
    probe_failure: Mutex<Option<ProbeDiagnostic>>,
    runtime_fault: Mutex<Option<tokio::sync::watch::Sender<Option<(ProbeStage, ProbeCause)>>>>,
}
impl MacProxySource {
    /// Trusted supervisor setup only. No operation/grant/session can be minted by
    /// this function. It never starts the App/daemon or repairs an old endpoint.
    pub(crate) async fn discover(until: Instant) -> Result<Arc<Self>> {
        // Headless/no-daemon is an immediate typed absence, not a ten-second
        // socket retry or an expensive full installed-image inventory first.
        tokio::task::spawn_blocking(MacSourceCandidate::check_discovery_presence)
            .await
            .map_err(|_| CuaError::Unknown)?
            .map_err(|_| CuaError::PermissionDenied)?;
        if Instant::now() >= until {
            return Err(CuaError::Unknown);
        }
        let images = tokio::task::spawn_blocking(MacAppImages::open_fixed)
            .await
            .map_err(|_| CuaError::Unknown)?
            .map_err(|_| CuaError::PermissionDenied)?;
        let candidate = tokio::task::spawn_blocking(move || MacSourceCandidate::discover(images))
            .await
            .map_err(|_| CuaError::Unknown)?
            .map_err(|_| CuaError::PermissionDenied)?;
        let connected = candidate
            .connect(until)
            .await
            .map_err(|_| CuaError::PermissionDenied)?;
        let mut control = tokio::task::spawn_blocking(move || connected.finish_binding())
            .await
            .map_err(|_| CuaError::Unknown)?
            .map_err(|_| CuaError::PermissionDenied)?;
        let mut control = tokio::task::spawn_blocking(move || {
            let facts = control
                .observe_native(until.into_std())
                .map_err(|_| CuaError::PermissionDenied)?;
            // Unknown lock evidence remains unavailable; no missing-key/permission lift.
            if !facts.observed_unlocked() {
                return Err(CuaError::PermissionDenied);
            }
            Ok(control)
        })
        .await
        .map_err(|_| CuaError::Unknown)??;
        let observations = control
            .connect_same_peer(until)
            .await
            .map_err(|_| CuaError::PermissionDenied)?;
        let fingerprint = control
            .binding_digest()
            .map_err(|_| CuaError::PermissionDenied)?;
        Ok(Arc::new(Self {
            control: Mutex::new(control),
            observations: Mutex::new(observations),
            fingerprint,
            phase: AtomicU8::new(SourcePhase::Unqualified as u8),
            initial_epoch_advanced: AtomicBool::new(false),
            probe_failure: Mutex::new(None),
            runtime_fault: Mutex::new(None),
        }))
    }
    pub(crate) fn fingerprint(&self) -> Sha256Digest {
        self.fingerprint
    }
    pub(crate) fn fenced(&self) -> bool {
        matches!(self.phase.load(Ordering::Acquire), value
            if value == SourcePhase::Fenced as u8 || value == SourcePhase::Ended as u8)
    }
    pub(crate) fn ready(&self) -> bool {
        self.phase.load(Ordering::Acquire) == SourcePhase::Ready as u8
    }
    fn fence(&self) {
        // An ended original source cannot be reopened by a late observer.
        let _ = self
            .phase
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |phase| {
                (phase != SourcePhase::Ended as u8).then_some(SourcePhase::Fenced as u8)
            });
    }
    fn advance(&self, before: SourcePhase, after: SourcePhase) -> Result<()> {
        self.phase
            .compare_exchange(
                before as u8,
                after as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map(|_| ())
            .map_err(|_| CuaError::PermissionDenied)
    }
    /// Read-only permission preparation before Host registration. Standard SDK
    /// source sessions remain owned until stop; no action target is published.
    pub(crate) fn observe_preparation(
        &self,
        until: std::time::Instant,
    ) -> Result<NativeObservation> {
        self.advance(SourcePhase::Unqualified, SourcePhase::Preparing)?;
        let result = self
            .observe_current_at(until, std::time::Instant::now(), false, true)
            .and_then(|value| {
                self.advance(SourcePhase::Preparing, SourcePhase::Prepared)?;
                Ok(value)
            });
        if result.is_err() {
            self.fence_initial_sources();
        }
        result
    }
    pub(crate) fn probe_diagnostic(&self) -> Option<ProbeDiagnostic> {
        *self
            .probe_failure
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }
    /// Installed once before qualification; this carries diagnostic facts only.
    pub(crate) fn attach_runtime_fault(
        &self,
        sender: tokio::sync::watch::Sender<Option<(ProbeStage, ProbeCause)>>,
    ) {
        *self.runtime_fault.lock().unwrap_or_else(|e| e.into_inner()) = Some(sender);
    }
    pub(crate) fn remember_probe_diagnostic(&self, diagnostic: ProbeDiagnostic) {
        // This is the first recorded failure after qualification, not a claim
        // of an atomic first OS event. Shutdown and subsequent fenced reads do
        // not acquire a new observation or replace the original fact.
        if let Some(sender) = self
            .runtime_fault
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            publish_runtime_fault(sender, self.ready(), diagnostic);
        }
        self.probe_failure
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get_or_insert(diagnostic);
    }
    fn remember_probe_failure(
        &self,
        stage: ProbeStage,
        cause: ProbeCause,
        started: std::time::Instant,
        until: std::time::Instant,
    ) {
        self.remember_probe_diagnostic(ProbeDiagnostic::observed(stage, cause, started, until));
    }
    /// Caller owns and joins the blocking job. Console availability belongs to
    /// the authenticated App bridge; live TCC comes from the daemon tool result.
    pub(crate) fn observe_current(&self, until: std::time::Instant) -> Result<NativeObservation> {
        if !self.ready() {
            return Err(CuaError::PermissionDenied);
        }
        self.observe_current_at(until, std::time::Instant::now(), false, false)
            .and_then(|value| {
                if self.ready() {
                    Ok(value)
                } else {
                    Err(CuaError::PermissionDenied)
                }
            })
    }
    fn observe_current_at(
        &self,
        until: std::time::Instant,
        started: std::time::Instant,
        after: bool,
        qualifying: bool,
    ) -> Result<NativeObservation> {
        let (binding, observation, final_binding) = if after {
            (
                ProbeStage::NativeAfterBinding,
                ProbeStage::NativeAfterObservation,
                ProbeStage::NativeAfterFinalBinding,
            )
        } else {
            (
                ProbeStage::NativeBeforeBinding,
                ProbeStage::NativeBeforeObservation,
                ProbeStage::NativeBeforeFinalBinding,
            )
        };
        if self.fenced() {
            self.remember_probe_failure(
                ProbeStage::AlreadyFenced,
                ProbeCause::Fenced,
                started,
                until,
            );
            return Err(CuaError::PermissionDenied);
        }
        let result = (|| {
            self.control
                .lock()
                .map_err(|_| {
                    self.remember_probe_failure(
                        ProbeStage::ControlMutex,
                        ProbeCause::MutexPoisoned,
                        started,
                        until,
                    );
                    CuaError::Unknown
                })?
                .fresh_binding()
                .map_err(|error| {
                    self.remember_probe_failure(binding, error.probe_cause(), started, until);
                    CuaError::PermissionDenied
                })?;
            let mut observations = self.observations.lock().map_err(|_| {
                self.remember_probe_failure(
                    ProbeStage::ObservationMutex,
                    ProbeCause::MutexPoisoned,
                    started,
                    until,
                );
                CuaError::Unknown
            })?;
            let response = if qualifying {
                observations.observe_initial_native(until)
            } else {
                observations.observe_native(until)
            };
            let value = response.map_err(|error| {
                let fault = observations.probe_diagnostic().map_or_else(
                    || ProbeDiagnostic::observed(observation, error.probe_cause(), started, until),
                    |fault| ProbeDiagnostic::observed(fault.stage, fault.cause, started, until),
                );
                self.remember_probe_diagnostic(fault);
                CuaError::PermissionDenied
            })?;
            drop(observations);
            if !value.observed_unlocked() {
                self.remember_probe_failure(observation, ProbeCause::Locked, started, until);
                return Err(CuaError::PermissionDenied);
            }
            self.control
                .lock()
                .map_err(|_| {
                    self.remember_probe_failure(
                        ProbeStage::ControlMutex,
                        ProbeCause::MutexPoisoned,
                        started,
                        until,
                    );
                    CuaError::Unknown
                })?
                .fresh_binding()
                .map_err(|error| {
                    self.remember_probe_failure(final_binding, error.probe_cause(), started, until);
                    CuaError::PermissionDenied
                })?;
            Ok(value)
        })();
        if result.is_err() {
            self.fence();
        }
        result
    }
}

impl MacProxySource {
    /// Before-target bootstrap only. Even a failed attempt consumes this claim;
    /// neither a caller retry nor any strict window read can reopen it.
    pub(crate) fn observe_initial_with_windows(
        &self,
        until: std::time::Instant,
    ) -> Result<(NativeObservation, super::macos_source::WindowReadEvidence)> {
        self.advance(SourcePhase::Prepared, SourcePhase::Probing)?;
        self.observe_windows_mode(until, true).and_then(|value| {
            if let Err(error) = self.advance(SourcePhase::Probing, SourcePhase::Ready) {
                self.fence_initial_sources();
                return Err(error);
            }
            Ok(value)
        })
    }
    /// Receipt only; this value is never a readiness or authorization input.
    pub(crate) fn initial_epoch_advanced(&self) -> bool {
        self.initial_epoch_advanced.load(Ordering::Acquire)
    }
    pub(crate) fn observe_with_windows(
        &self,
        until: std::time::Instant,
    ) -> Result<(NativeObservation, super::macos_source::WindowReadEvidence)> {
        if !self.ready() {
            return Err(CuaError::PermissionDenied);
        }
        self.observe_windows_mode(until, false).and_then(|value| {
            if self.ready() {
                Ok(value)
            } else {
                Err(CuaError::PermissionDenied)
            }
        })
    }
    fn observe_windows_mode(
        &self,
        until: std::time::Instant,
        initial: bool,
    ) -> Result<(NativeObservation, super::macos_source::WindowReadEvidence)> {
        let started = std::time::Instant::now();
        let result = (|| {
            let before = self.observe_current_at(until, started, false, initial)?;
            let mut observations = self.observations.lock().map_err(|_| {
                self.remember_probe_failure(
                    ProbeStage::ObservationMutex,
                    ProbeCause::MutexPoisoned,
                    started,
                    until,
                );
                CuaError::Unknown
            })?;
            let windows = observations.probe_windows(until).map_err(|error| {
                let fault = observations.probe_diagnostic().map_or_else(
                    || {
                        ProbeDiagnostic::observed(
                            ProbeStage::SessionBinding,
                            error.probe_cause(),
                            started,
                            until,
                        )
                    },
                    |fault| ProbeDiagnostic::observed(fault.stage, fault.cause, started, until),
                );
                self.remember_probe_diagnostic(fault);
                CuaError::PermissionDenied
            })?;
            if initial {
                let mut control = self.control.lock().map_err(|_| {
                    self.remember_probe_failure(
                        ProbeStage::ControlMutex,
                        ProbeCause::MutexPoisoned,
                        started,
                        until,
                    );
                    CuaError::Unknown
                })?;
                let after = observations
                    .observe_initial_native(until)
                    .map_err(|error| {
                        let fault = observations.probe_diagnostic().map_or_else(
                            || {
                                ProbeDiagnostic::observed(
                                    ProbeStage::NativeAfterObservation,
                                    error.probe_cause(),
                                    started,
                                    until,
                                )
                            },
                            |fault| {
                                ProbeDiagnostic::observed(fault.stage, fault.cause, started, until)
                            },
                        );
                        self.remember_probe_diagnostic(fault);
                        CuaError::PermissionDenied
                    })?;
                let control_after = control.observe_initial_native(until).map_err(|error| {
                    let fault = control.probe_diagnostic().map_or_else(
                        || {
                            ProbeDiagnostic::observed(
                                ProbeStage::NativeAfterFinalBinding,
                                error.probe_cause(),
                                started,
                                until,
                            )
                        },
                        |fault| ProbeDiagnostic::observed(fault.stage, fault.cause, started, until),
                    );
                    self.remember_probe_diagnostic(fault);
                    CuaError::PermissionDenied
                })?;
                let advanced = observations
                    .commit_initial_native_pair(
                        &mut control,
                        &before,
                        &after,
                        &control_after,
                        until,
                    )
                    .map_err(|error| {
                        let fault = observations.probe_diagnostic().map_or_else(
                            || {
                                ProbeDiagnostic::observed(
                                    ProbeStage::ConsoleMatch,
                                    error.probe_cause(),
                                    started,
                                    until,
                                )
                            },
                            |fault| {
                                ProbeDiagnostic::observed(fault.stage, fault.cause, started, until)
                            },
                        );
                        self.remember_probe_diagnostic(fault);
                        CuaError::PermissionDenied
                    })?;
                if advanced {
                    self.initial_epoch_advanced.store(true, Ordering::Release);
                }
                return Ok((control_after, windows));
            }
            drop(observations);
            // The read probe may take time. Return ONLY a new original-FD
            // native lock/TCC sample, never retimestamp the pre-probe facts.
            let after = self.observe_current_at(until, started, true, false)?;
            if before.console_identity() != after.console_identity() {
                self.remember_probe_failure(
                    ProbeStage::ConsoleMatch,
                    ProbeCause::ConsoleChanged,
                    started,
                    until,
                );
                return Err(CuaError::PermissionDenied);
            }
            // BoundMacSource also verifies the same original daemon instance,
            // full kernel peer and App/daemon births on both observations.
            Ok((after, windows))
        })();
        if result.is_err() {
            if initial {
                self.fence_initial_sources();
            } else {
                self.fence();
            }
        }
        result
    }
    fn fence_initial_sources(&self) {
        self.fence();
        // Recover poisoned guards only to deny use, never to restore authority.
        self.control
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .fence_initial_native();
        self.observations
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .fence_initial_native();
    }

    pub(crate) fn drain_source_probe(&self, until: std::time::Instant) -> Result<bool> {
        self.fence();
        let result = self
            .observations
            .lock()
            .map_err(|_| CuaError::Unknown)?
            .drain_probe(until)
            .map_err(|_| CuaError::CleanupUnconfirmed);
        let result = result.and_then(|observations| {
            let control = self
                .control
                .lock()
                .map_err(|_| CuaError::Unknown)?
                .drain_probe(until)
                .map_err(|_| CuaError::CleanupUnconfirmed)?;
            Ok(observations && control)
        });
        if result == Ok(true) {
            self.phase
                .store(SourcePhase::Ended as u8, Ordering::Release);
        }
        result
    }
}

#[derive(Clone)]
pub(crate) struct TrustedCuaLaunch {
    pub(crate) session: SessionBinding,
    pub(crate) source: Arc<MacProxySource>,
    workspace_path: PathBuf,
    home_path: PathBuf,
    workspace: Arc<PrivateRoot>,
    home: Arc<PrivateRoot>,
}
impl TrustedCuaLaunch {
    pub(crate) fn bind(
        session: SessionBinding,
        source: Arc<MacProxySource>,
        workspace: PathBuf,
        home: PathBuf,
    ) -> Result<Self> {
        if !workspace.is_absolute() || !home.is_absolute() {
            return Err(CuaError::InvalidRequest);
        }
        let workspace_root =
            Arc::new(PrivateRoot::open(&workspace).map_err(|_| CuaError::PermissionDenied)?);
        let home_root = Arc::new(PrivateRoot::open(&home).map_err(|_| CuaError::PermissionDenied)?);
        Ok(Self {
            session,
            source,
            workspace_path: workspace,
            home_path: home,
            workspace: workspace_root,
            home: home_root,
        })
    }
}
pub(super) fn profile_launch_bytes(launch: &TrustedCuaLaunch) -> usize {
    launch.workspace_path.capacity() + launch.home_path.capacity()
}
pub(super) fn validate_config(config: &OwnedCuaConfig) -> Result<()> {
    if config.rpc_timeout.is_zero()
        || config.rpc_timeout > std::time::Duration::from_secs(30)
        || !config.workspace.is_absolute()
        || !config.home.is_absolute()
        || config.workspace != config.launch.workspace_path
        || config.home != config.launch.home_path
        || config.workspace.as_os_str().len() > 4096
        || config.home.as_os_str().len() > 4096
        || !config.launch.source.ready()
    {
        return Err(CuaError::PermissionDenied);
    }
    Ok(())
}
pub(super) fn config_digest(config: &OwnedCuaConfig) -> Result<Sha256Digest> {
    validate_config(config)?;
    super::bounded_bytes(&serde_json::json!({"schema":1,"platform":"macos_app_owned","session":config.launch.session,"source":config.launch.source.fingerprint(),"workspace":config.workspace,"home":config.home,"timeout_ms":config.rpc_timeout.as_millis()}),super::REQUEST_BYTES).map(|bytes|Sha256Digest::of_bytes(&bytes))
}
pub(super) async fn preflight(
    live: &mut super::Live,
    config: &OwnedCuaConfig,
    until: Instant,
) -> Result<()> {
    validate_config(config)?;
    // If an earlier public waiter disappeared, join its ORIGINAL read task and
    // discard those old facts. Do not turn an old observation into new admission.
    if let Some(job) = live.mac_probe.as_mut() {
        let result = job.await;
        live.mac_probe.take();
        result.map_err(|_| CuaError::Unknown)??;
    }
    if Instant::now() >= until {
        return Err(CuaError::Unknown);
    }
    let source = config.launch.source.clone();
    let workspace = config.workspace.clone();
    let home = config.home.clone();
    let workspace_pin = config.launch.workspace.clone();
    let home_pin = config.launch.home.clone();
    live.mac_probe = Some(tokio::task::spawn_blocking(move || {
        let workspace = PrivateRoot::open(&workspace).map_err(|_| CuaError::PermissionDenied)?;
        let home = PrivateRoot::open(&home).map_err(|_| CuaError::PermissionDenied)?;
        source.observe_current(until.into_std())?;
        if workspace.identity() != workspace_pin.identity()
            || home.identity() != home_pin.identity()
        {
            return Err(CuaError::PermissionDenied);
        }
        if std::time::Instant::now() >= until.into_std() {
            return Err(CuaError::Unknown);
        }
        Ok(())
    }));
    // Borrow, never take, the original handle across await. Resource cleanup
    // joins this same slot if the public waiter is cancelled.
    let result = live.mac_probe.as_mut().ok_or(CuaError::Unknown)?.await;
    live.mac_probe.take();
    result.map_err(|_| CuaError::Unknown)?
}
pub(super) struct ProxyWorker {
    running: Option<RunningChild>,
    suspended: Option<SuspendedChild>,
    session_started: bool,
    session_ended: bool,
    attempted: bool,
    resumed: bool,
    // Original source and budget survive cancellation/failed starts and cleanup.
    _source: Arc<MacProxySource>,
    _control: BoundMacSource,
    _budget: Arc<super::CuaIoBudget>,
}
impl ProxyWorker {
    fn new(
        source: Arc<MacProxySource>,
        control: BoundMacSource,
        budget: Arc<super::CuaIoBudget>,
    ) -> Self {
        Self {
            running: None,
            suspended: None,
            session_started: false,
            session_ended: false,
            attempted: false,
            resumed: false,
            _source: source,
            _control: control,
            _budget: budget,
        }
    }
    pub(super) fn mark_session_started(&mut self) {
        self.session_started = true;
    }
    pub(super) fn mark_session_ended(&mut self) {
        self.session_ended = true;
    }
    pub(super) fn was_started(&self) -> bool {
        self.attempted
    }
    pub(super) fn native_not_started(&self) -> bool {
        !self.attempted || (!self.resumed && self.suspended.is_some())
    }
    pub(super) async fn settle(&mut self, until: Instant) -> (bool, Option<bool>, bool) {
        if let Some(child) = self.running.as_mut() {
            child.take_stdin();
            child.take_stdout();
            child.take_stderr();
        }
        if self.attempted && self.running.is_none() && self.suspended.is_none() {
            return (false, None, false);
        }
        if let Some(child) = self.suspended.as_mut() {
            // Verification never resumed this owned child. Only this proxy may be
            // terminated; the original App daemon is never a termination target.
            let _ = timeout_at(until, child.terminate_and_wait()).await;
            let receipt = child.receipt();
            return (
                receipt.actual_wait && receipt.supervisor_joined,
                receipt.exit_success,
                false,
            );
        }
        let mut exited = self.running.is_none();
        let mut success = None;
        if let Some(child) = self.running.as_mut() {
            // SDK close already removed stdin. Never kill a live proxy merely because
            // this wait budget expires: it may still be waiting for native daemon work.
            let _ = timeout_at(until, child.wait()).await;
            let receipt = child.receipt();
            exited = receipt.actual_wait && receipt.supervisor_joined;
            success = receipt.exit_success;
        }
        (
            exited,
            success,
            (!self.session_started || self.session_ended) && exited && success == Some(true),
        )
    }
}
pub(super) async fn start_proxy(
    live: &mut super::Live,
    config: &Arc<OwnedCuaConfig>,
    budget: Arc<super::CuaIoBudget>,
    until: Instant,
) -> Result<(ChildStdin, ChildStdout, ChildStderr)> {
    preflight(live, config, until).await?;
    let source = config.launch.source.clone();
    let anchor = source.clone();
    let mut original = tokio::task::spawn_blocking(move || {
        anchor
            .control
            .lock()
            .map_err(|_| CuaError::Unknown)?
            .duplicate_binding()
            .map_err(|_| CuaError::PermissionDenied)
    })
    .await
    .map_err(|_| CuaError::Unknown)??;
    // Retain source identity before launching the official proxy. Its later
    // connections use the standard private socket path, not this observed FD.
    let mut control_binding = original
        .connect_same_peer(until)
        .await
        .map_err(|_| CuaError::PermissionDenied)?;
    let (control_binding, image, socket) = tokio::task::spawn_blocking(move || {
        let (image, socket) = control_binding
            .proxy_parts()
            .map_err(|_| CuaError::PermissionDenied)?;
        Ok::<_, CuaError>((control_binding, image, socket))
    })
    .await
    .map_err(|_| CuaError::Unknown)??;
    let mut worker = ProxyWorker::new(source, control_binding, budget.clone());
    worker.attempted = true;
    live.mac_proxy = Some(worker);
    let workspace = config.workspace.clone();
    let home = config.home.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        macos_spawn::spawn_installed_proxy_suspended(image, socket, workspace, home, budget)
    })
    .await
    .map_err(|_| CuaError::Unknown)?;
    let worker = live.mac_proxy.as_mut().ok_or(CuaError::Unknown)?;
    match outcome {
        Ok(child) => worker.suspended = Some(child),
        Err(error) => {
            worker.suspended = error.into_owned_child();
            worker.attempted = worker.suspended.is_some();
            return Err(CuaError::Unknown);
        }
    }
    // The process and supervisor are owned in Live BEFORE any resume operation.
    let suspended = worker.suspended.take().ok_or(CuaError::Unknown)?;
    match tokio::task::spawn_blocking(move || suspended.verify_and_resume())
        .await
        .map_err(|_| CuaError::Unknown)?
    {
        Ok(child) => {
            worker.resumed = true;
            worker.running = Some(child)
        }
        Err(error) => {
            worker.suspended = error.into_owned_child();
            return Err(CuaError::PermissionDenied);
        }
    }
    let child = worker.running.as_mut().ok_or(CuaError::Unknown)?;
    live.identity = child.receipt().birth;
    Ok((
        child.take_stdin().ok_or(CuaError::Unknown)?,
        child.take_stdout().ok_or(CuaError::Unknown)?,
        child.take_stderr().ok_or(CuaError::Unknown)?,
    ))
}

#[cfg(test)]
mod qualification_reference {
    use super::*;

    #[test]
    fn runtime_fault_projection_is_first_ready_fact_only() {
        let (sender, receiver) = tokio::sync::watch::channel(None);
        let diagnostic = |stage, cause| ProbeDiagnostic {
            stage,
            cause,
            elapsed_ms: 123,
            deadline_expired: true,
        };
        publish_runtime_fault(
            &sender,
            false,
            diagnostic(ProbeStage::NativeBeforeBinding, ProbeCause::Peer),
        );
        assert!(receiver.borrow().is_none());
        publish_runtime_fault(
            &sender,
            true,
            diagnostic(ProbeStage::AlreadyFenced, ProbeCause::Fenced),
        );
        assert!(receiver.borrow().is_none());
        publish_runtime_fault(
            &sender,
            true,
            diagnostic(
                ProbeStage::NativeAfterObservation,
                ProbeCause::ConsoleEpochChanged,
            ),
        );
        publish_runtime_fault(
            &sender,
            true,
            diagnostic(ProbeStage::ControlMutex, ProbeCause::MutexPoisoned),
        );
        let current = *receiver.borrow();
        assert_eq!(
            current,
            Some((
                ProbeStage::NativeAfterObservation,
                ProbeCause::ConsoleEpochChanged
            ))
        );
        let (stage, cause) = current.unwrap();
        let projected = serde_json::json!({"stage":stage,"cause":cause});
        assert_eq!(projected.as_object().unwrap().len(), 2);
        assert_eq!(projected["stage"], "native_after_observation");
        assert_eq!(projected["cause"], "console_epoch_changed");

        // A first failure from the original binding may itself be Fenced;
        // only an already-fenced follow-up is suppressed.
        let (sender, receiver) = tokio::sync::watch::channel(None);
        publish_runtime_fault(
            &sender,
            true,
            diagnostic(ProbeStage::NativeBeforeBinding, ProbeCause::Fenced),
        );
        assert_eq!(
            *receiver.borrow(),
            Some((ProbeStage::NativeBeforeBinding, ProbeCause::Fenced))
        );
    }
}
