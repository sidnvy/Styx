//! Original App-owned source: actual facts/read acquisition, never descriptor grants.
use crate::{
    providers::cua::{
        MacProxySource,
        macos_source::{NativeObservation, WindowReadEvidence},
    },
    session::ProviderEvidence,
};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use styx_contracts::{
    capability::{Authorization, Availability, CapabilityId},
    error::{ErrorCategory, Recovery},
    identity::{AgentInstanceId, SessionId, Sha256Digest},
    session::SessionIdentity,
};
use styx_core::session::RegistrationFacts;
use tokio::{sync::Mutex as AsyncMutex, task::JoinHandle};
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum DesktopSourceError {
    #[error("desktop source unavailable")]
    Unavailable,
    #[error("desktop source changed or ended")]
    Fenced,
    #[error("desktop source probe busy")]
    Busy,
    #[error("desktop source supervisor failed")]
    Supervisor,
}
impl DesktopSourceError {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::Unavailable => "desktop_source_unavailable",
            Self::Fenced => "desktop_source_fenced",
            Self::Busy => "desktop_source_busy",
            Self::Supervisor => "desktop_source_supervisor_failed",
        }
    }
}
type Result<T> = std::result::Result<T, DesktopSourceError>;
struct Observed {
    native: NativeObservation,
    windows: Option<WindowReadEvidence>,
    at: Instant,
}
#[derive(Clone, Copy, Debug)]
pub struct DesktopSourceStop {
    pub observation_task_joined: bool,
    pub original_probe_transport_drained: bool,
}
impl DesktopSourceStop {
    pub(crate) fn complete(&self) -> bool {
        self.observation_task_joined && self.original_probe_transport_drained
    }
}
struct Inner {
    source: Arc<MacProxySource>,
    fenced: AtomicBool,
    epoch: AtomicU64,
    observations: Mutex<Option<Observed>>,
    job: AsyncMutex<Option<JoinHandle<Result<Observed>>>>,
    stop_job: AsyncMutex<Option<JoinHandle<Result<bool>>>>,
    stopped: Mutex<Option<DesktopSourceStop>>,
}
impl Inner {
    fn fence(&self) {
        if !self.fenced.swap(true, Ordering::AcqRel) {
            self.epoch.fetch_add(1, Ordering::AcqRel);
        }
    }
}
#[derive(Clone)]
pub(crate) struct DesktopSource {
    inner: Arc<Inner>,
}
impl DesktopSource {
    pub(crate) async fn start() -> Result<Self> {
        let source =
            MacProxySource::discover(tokio::time::Instant::now() + Duration::from_secs(10))
                .await
                .map_err(|_| DesktopSourceError::Unavailable)?;
        let value = Self {
            inner: Arc::new(Inner {
                source,
                fenced: AtomicBool::new(false),
                epoch: AtomicU64::new(1),
                observations: Mutex::new(None),
                job: AsyncMutex::new(None),
                stop_job: AsyncMutex::new(None),
                stopped: Mutex::new(None),
            }),
        };
        // No SDK tool invocation before the Host has retained this source lane.
        let source = value.inner.source.clone();
        let mut slot = value.inner.job.lock().await;
        *slot = Some(tokio::task::spawn_blocking(move || {
            let native = source
                .observe_current(Instant::now() + Duration::from_secs(10))
                .map_err(|_| DesktopSourceError::Unavailable)?;
            Ok(Observed {
                native,
                windows: None,
                at: Instant::now(),
            })
        }));
        let result = slot.as_mut().ok_or(DesktopSourceError::Supervisor)?.await;
        slot.take();
        drop(slot);
        let observed = result.map_err(|_| DesktopSourceError::Supervisor)??;
        *value
            .inner
            .observations
            .lock()
            .map_err(|_| DesktopSourceError::Supervisor)? = Some(observed);
        Ok(value)
    }
    pub(crate) fn fenced(&self) -> bool {
        self.inner.fenced.load(Ordering::Acquire) || self.inner.source.fenced()
    }
    pub(crate) fn epoch(&self) -> u64 {
        self.inner.epoch.load(Ordering::Acquire)
    }
    pub(crate) fn proxy_source(&self) -> Result<Arc<MacProxySource>> {
        if self.fenced() {
            return Err(DesktopSourceError::Fenced);
        }
        Ok(self.inner.source.clone())
    }
    pub(crate) async fn fresh(&self) -> Result<()> {
        if self.fenced() {
            return Err(DesktopSourceError::Fenced);
        }
        let mut slot = self
            .inner
            .job
            .try_lock()
            .map_err(|_| DesktopSourceError::Busy)?;
        // Rejoin a cancelled prior observation; its old facts are never reused.
        if let Some(job) = slot.as_mut() {
            let result = job.await;
            slot.take();
            if !matches!(result, Ok(Ok(_))) {
                self.inner.fence();
                return Err(DesktopSourceError::Supervisor);
            }
        }
        let source = self.inner.source.clone();
        *slot = Some(tokio::task::spawn_blocking(move || {
            let (native, windows) = source
                .observe_with_windows(Instant::now() + Duration::from_secs(10))
                .map_err(|_| DesktopSourceError::Unavailable)?;
            if !native.observed_unlocked() {
                return Err(DesktopSourceError::Unavailable);
            }
            Ok(Observed {
                native,
                windows: Some(windows),
                at: Instant::now(),
            })
        }));
        let result = slot.as_mut().ok_or(DesktopSourceError::Supervisor)?.await;
        slot.take();
        match result {
            Ok(Ok(facts)) if !self.fenced() => {
                *self
                    .inner
                    .observations
                    .lock()
                    .map_err(|_| DesktopSourceError::Supervisor)? = Some(facts);
                Ok(())
            }
            Ok(Err(error)) => {
                self.inner.fence();
                Err(error)
            }
            _ => {
                self.inner.fence();
                Err(DesktopSourceError::Supervisor)
            }
        }
    }
    fn with_observation<T>(&self, f: impl FnOnce(&Observed) -> Result<T>) -> Result<T> {
        if self.fenced() {
            return Err(DesktopSourceError::Fenced);
        }
        let held = self
            .inner
            .observations
            .lock()
            .map_err(|_| DesktopSourceError::Supervisor)?;
        let value = held.as_ref().ok_or(DesktopSourceError::Unavailable)?;
        if value.at.elapsed() > Duration::from_secs(1) || !value.native.observed_unlocked() {
            return Err(DesktopSourceError::Unavailable);
        }
        f(value)
    }
    pub(crate) fn initial_facts(
        &self,
        agent_instance: AgentInstanceId,
    ) -> Result<RegistrationFacts> {
        self.with_observation(|value|{
  let console=value.native.console_identity().ok_or(DesktopSourceError::Unavailable)?;
  let material=format!("{}:{}:{}:{}",console.uid,console.audit_id,console.console_uuid,self.inner.source.fingerprint().to_hex());
  Ok(RegistrationFacts{id:SessionId::try_from(format!("macos-{}",Sha256Digest::of_bytes(material.as_bytes()).to_hex())).map_err(|_|DesktopSourceError::Unavailable)?,identity:SessionIdentity::Macos{uid:console.uid,audit_session:u64::from(console.audit_id),console_instance:console.console_uuid,window_server_instance:None},agent_instance,protocol_version:1,provenance:"fixed signed App/daemon parent, exact kernel peer audit token and native console observation".into()})
 })
    }
    pub(crate) fn provider_evidence(&self, capability: CapabilityId) -> Result<ProviderEvidence> {
        self.with_observation(|value|{
  // Empty list alone never grants TCC. Authorization is independently the
  // original daemon AX/screen-recording observation; unsupported lanes stay so.
  let (available,authorized)=match capability {
   CapabilityId::DesktopWindowsRead=>(value.windows.is_some(),value.native.permissions.accessibility),
   CapabilityId::DesktopAccessibility=>(true,value.native.permissions.accessibility),
   CapabilityId::DesktopCapture=>(false,value.native.permissions.screen_recording),
   _=>(false,false),
  };
  Ok(ProviderEvidence{capability,provider:"macos-app-owned-native".try_into().map_err(|_|DesktopSourceError::Unavailable)?,availability:if available{Availability::Available}else{Availability::Unavailable},authorization:if authorized{Authorization::Granted}else if available{Authorization::Required}else{Authorization::Unknown},provenance:format!("same authenticated facts FD list_windows count={} sha256={}; separate original daemon TCC facts",value.windows.as_ref().map(|v|v.count).unwrap_or(0),value.windows.as_ref().map(|v|v.digest.to_hex()).unwrap_or_else(||"not_observed".into())),reason:if !available{Some(ErrorCategory::CapabilityUnsupported)}else if !authorized{Some(ErrorCategory::PermissionRequired)}else{None},recovery:if available&&authorized{Recovery::None}else{Recovery::Rediscover}})
 })
    }
    pub(crate) async fn stop(&self) -> Result<DesktopSourceStop> {
        self.inner.fence();
        if let Some(value) = *self
            .inner
            .stopped
            .lock()
            .map_err(|_| DesktopSourceError::Supervisor)?
        {
            return Ok(value);
        }
        let mut probe = self.inner.job.lock().await;
        if let Some(job) = probe.as_mut() {
            let result = job.await;
            probe.take();
            let _ = result.map_err(|_| DesktopSourceError::Supervisor)?;
        }
        drop(probe);
        let mut slot = self.inner.stop_job.lock().await;
        if slot.is_none() {
            let source = self.inner.source.clone();
            *slot = Some(tokio::task::spawn_blocking(move || {
                source
                    .drain_source_probe(Instant::now() + Duration::from_secs(10))
                    .map_err(|_| DesktopSourceError::Fenced)
            }));
        }
        let result = slot.as_mut().ok_or(DesktopSourceError::Supervisor)?.await;
        slot.take();
        let drained = result.map_err(|_| DesktopSourceError::Supervisor)??;
        let facts = DesktopSourceStop {
            observation_task_joined: true,
            original_probe_transport_drained: drained,
        };
        *self
            .inner
            .stopped
            .lock()
            .map_err(|_| DesktopSourceError::Supervisor)? = Some(facts);
        Ok(facts)
    }
}

pub(crate) fn source_stop_complete(report: &DesktopSourceStop) -> bool {
    report.complete()
}
