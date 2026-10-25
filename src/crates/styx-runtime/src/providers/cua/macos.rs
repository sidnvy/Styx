//! App-owned macOS daemon + owned stdio proxy. No daemon spawn/stop/adoption.
//! The original authenticated controlFD and independent factFD are both bound
//! to the same original App/daemon. Only that control's real drain ACK settles
//! native work. Proxy wait and all IO joins remain separate requirements.
use super::macos_source::{BoundMacSource, MacAppImages, MacSourceCandidate, NativeObservation};
use super::{CuaError, OwnedCuaConfig, Result};
use crate::{
    platform::macos_spawn::{self, RunningChild, SuspendedChild},
    store::PrivateRoot,
};
use std::{
    os::fd::OwnedFd,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use styx_contracts::{identity::Sha256Digest, session::SessionBinding};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, BufReader},
    process::{ChildStderr, ChildStdin, ChildStdout},
    task::JoinHandle,
    time::{Instant, timeout_at},
};

pub(crate) struct MacProxySource {
    control: Mutex<BoundMacSource>,
    observations: Mutex<BoundMacSource>,
    fingerprint: Sha256Digest,
    fenced: AtomicBool,
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
        let control = tokio::task::spawn_blocking(move || connected.finish_binding())
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
            fenced: AtomicBool::new(false),
        }))
    }
    pub(crate) fn fingerprint(&self) -> Sha256Digest {
        self.fingerprint
    }
    pub(crate) fn fenced(&self) -> bool {
        self.fenced.load(Ordering::Acquire)
    }
    /// Caller owns the existing bounded blocking job and joins it; facts never
    /// derive from caller env/descriptor booleans or the proxy's exit status.
    pub(crate) fn observe_current(&self, until: std::time::Instant) -> Result<NativeObservation> {
        if self.fenced() {
            return Err(CuaError::PermissionDenied);
        }
        let result = (|| {
            self.control
                .lock()
                .map_err(|_| CuaError::Unknown)?
                .fresh_binding()
                .map_err(|_| CuaError::PermissionDenied)?;
            let value = self
                .observations
                .lock()
                .map_err(|_| CuaError::Unknown)?
                .observe_native(until)
                .map_err(|_| CuaError::PermissionDenied)?;
            if !value.observed_unlocked() {
                return Err(CuaError::PermissionDenied);
            }
            self.control
                .lock()
                .map_err(|_| CuaError::Unknown)?
                .fresh_binding()
                .map_err(|_| CuaError::PermissionDenied)?;
            Ok(value)
        })();
        if result.is_err() {
            self.fenced.store(true, Ordering::Release)
        }
        result
    }
}
impl MacProxySource {
    pub(crate) fn observe_with_windows(
        &self,
        until: std::time::Instant,
    ) -> Result<(NativeObservation, super::macos_source::WindowReadEvidence)> {
        let result = (|| {
            let before = self.observe_current(until)?;
            let windows = self
                .observations
                .lock()
                .map_err(|_| CuaError::Unknown)?
                .probe_windows(until)
                .map_err(|_| CuaError::PermissionDenied)?;
            // The read probe may take time. Return ONLY a new original-FD
            // native lock/TCC sample, never retimestamp the pre-probe facts.
            let after = self.observe_current(until)?;
            if before.console_identity() != after.console_identity() {
                return Err(CuaError::PermissionDenied);
            }
            // BoundMacSource also verifies the same original daemon instance,
            // full kernel peer and App/daemon births on both observations.
            Ok((after, windows))
        })();
        if result.is_err() {
            self.fenced.store(true, Ordering::Release);
        }
        result
    }

    pub(crate) fn drain_source_probe(&self, until: std::time::Instant) -> Result<bool> {
        self.observations
            .lock()
            .map_err(|_| CuaError::Unknown)?
            .drain_probe(until)
            .map_err(|_| CuaError::CleanupUnconfirmed)
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
pub(super) fn validate_config(config: &OwnedCuaConfig) -> Result<()> {
    if config.rpc_timeout.is_zero()
        || config.rpc_timeout > std::time::Duration::from_secs(30)
        || !config.workspace.is_absolute()
        || !config.home.is_absolute()
        || config.workspace != config.launch.workspace_path
        || config.home != config.launch.home_path
        || config.workspace.as_os_str().len() > 4096
        || config.home.as_os_str().len() > 4096
        || config.launch.source.fenced()
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
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DrainReport {
    schema: u32,
    source: String,
    drained: bool,
}
async fn read_report(reader: std::io::PipeReader) -> Result<()> {
    let file = std::fs::File::from(OwnedFd::from(reader));
    let file = tokio::fs::File::from_std(file);
    let mut reader = BufReader::new(file.take(4097));
    let mut bytes = Vec::new();
    if reader
        .read_until(b'\n', &mut bytes)
        .await
        .map_err(|_| CuaError::Unknown)?
        == 0
        || bytes.len() > 4096
        || bytes.last() != Some(&b'\n')
    {
        return Err(CuaError::Unknown);
    }
    let report: DrainReport =
        serde_json::from_slice(&bytes).map_err(|_| CuaError::ProtocolMismatch)?;
    if report.schema != 1 || report.source != "original_control_transport" || !report.drained {
        return Err(CuaError::CleanupUnconfirmed);
    }
    let mut extra = [0u8; 1];
    if reader
        .read(&mut extra)
        .await
        .map_err(|_| CuaError::Unknown)?
        != 0
    {
        return Err(CuaError::ProtocolMismatch);
    }
    Ok(())
}
pub(super) struct ProxyWorker {
    running: Option<RunningChild>,
    suspended: Option<SuspendedChild>,
    report: Option<JoinHandle<Result<()>>>,
    report_failed: bool,
    drained: bool,
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
            report: None,
            report_failed: false,
            drained: false,
            attempted: false,
            resumed: false,
            _source: source,
            _control: control,
            _budget: budget,
        }
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
        if let Some(job) = self.report.as_mut() {
            match timeout_at(until, job).await {
                Ok(Ok(Ok(()))) => {
                    self.report.take();
                    self.drained = true;
                }
                Ok(_) => {
                    self.report.take();
                    self.report_failed = true;
                }
                Err(_) => {}
            }
        }
        (exited, success, self.drained && !self.report_failed)
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
    // A fresh resource authenticates its original control BEFORE FD handoff.
    // This path is never called by settlement/recovery of an existing resource.
    let mut control_binding = original
        .connect_same_peer(until)
        .await
        .map_err(|_| CuaError::PermissionDenied)?;
    let (control_binding, image, socket, control) = tokio::task::spawn_blocking(move || {
        let (image, socket, control) = control_binding
            .proxy_parts()
            .map_err(|_| CuaError::PermissionDenied)?;
        Ok::<_, CuaError>((control_binding, image, socket, control))
    })
    .await
    .map_err(|_| CuaError::Unknown)??;
    let (report_read, report_write) = std::io::pipe().map_err(|_| CuaError::Unknown)?;
    let mut worker = ProxyWorker::new(source, control_binding, budget.clone());
    worker.attempted = true;
    live.mac_proxy = Some(worker);
    let workspace = config.workspace.clone();
    let home = config.home.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        macos_spawn::spawn_installed_proxy_suspended(
            image,
            control,
            OwnedFd::from(report_write),
            socket,
            workspace,
            home,
            budget,
        )
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
    worker.report = Some(tokio::spawn(read_report(report_read)));
    let child = worker.running.as_mut().ok_or(CuaError::Unknown)?;
    live.identity = child.receipt().birth;
    Ok((
        child.take_stdin().ok_or(CuaError::Unknown)?,
        child.take_stdout().ok_or(CuaError::Unknown)?,
        child.take_stderr().ok_or(CuaError::Unknown)?,
    ))
}
