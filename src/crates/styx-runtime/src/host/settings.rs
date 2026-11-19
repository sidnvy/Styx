//! Host-owned mutable capability settings. Enrollment identity remains immutable.
//! The same controller serves local UI and the authenticated Gateway connection.
#[cfg(not(target_os = "android"))]
use crate::store::{PrivateRoot, StoreError};
use futures_util::future::BoxFuture;
use serde::{Deserialize, Serialize};
use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use styx_contracts::error::ErrorCategory;
use tokio::sync::{OwnedRwLockReadGuard, RwLock, watch};
use tokio_util::task::TaskTracker;

const FILE: &str = "host-capabilities.json";
pub const FEATURE: &str = "host_capabilities_v1";
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    pub exec: bool,
    pub browser: bool,
    pub computer: bool,
    #[serde(default)]
    pub android: bool,
}
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityPatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub computer: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub android: Option<bool>,
}
impl CapabilityPatch {
    fn apply(self, previous: Capabilities) -> Capabilities {
        Capabilities {
            exec: self.exec.unwrap_or(previous.exec),
            browser: self.browser.unwrap_or(previous.browser),
            computer: self.computer.unwrap_or(previous.computer),
            android: self.android.unwrap_or(previous.android),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.exec.is_none()
            && self.browser.is_none()
            && self.computer.is_none()
            && self.android.is_none()
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsReport {
    pub generations: [u64; 4],
    pub configured: Capabilities,
    pub applied: bool,
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub android_status: Option<AndroidStatus>,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct AndroidStatus {
    pub accessibility: bool,
    pub device_locked: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Persisted {
    schema: u16,
    capabilities: Capabilities,
}
/// Applies only the changed capabilities; never replaces the Host or its pairing.
pub trait CapabilityRuntime: Send + Sync {
    fn apply(
        &self,
        before: Capabilities,
        after: Capabilities,
    ) -> BoxFuture<'_, Result<(), ErrorCategory>>;
}
pub struct HostSettings {
    path: PathBuf,
    #[cfg(not(target_os = "android"))]
    root: PrivateRoot,
    current: watch::Sender<Capabilities>,
    report: Mutex<SettingsReport>,
    gate: Arc<RwLock<()>>,
    runtime: Mutex<Option<Arc<dyn CapabilityRuntime>>>,
    tasks: TaskTracker,
}
impl HostSettings {
    /// Absence imports the old *effective* local selection once. Callers include
    /// historical remote denials so an upgrade cannot silently enable a capability.
    pub fn open(path: &Path, initial: Capabilities) -> Result<Arc<Self>, ErrorCategory> {
        #[cfg(not(target_os = "android"))]
        let root = PrivateRoot::open(path).map_err(|_| ErrorCategory::IntegrityFailure)?;
        #[cfg(not(target_os = "android"))]
        let configured = match root.read_raw(FILE, 4096) {
            Ok(raw) => {
                let value: Persisted = serde_json::from_slice(raw.bytes())
                    .map_err(|_| ErrorCategory::IntegrityFailure)?;
                if value.schema != 1 {
                    return Err(ErrorCategory::IntegrityFailure);
                }
                value.capabilities
            }
            Err(StoreError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => initial,
            Err(_) => return Err(ErrorCategory::IntegrityFailure),
        };
        // Android supplies its app-private filesDir; the OS owns its UID boundary.
        #[cfg(target_os = "android")]
        let configured = match std::fs::read(path.join(FILE)) {
            Ok(bytes) => {
                let value: Persisted =
                    serde_json::from_slice(&bytes).map_err(|_| ErrorCategory::IntegrityFailure)?;
                if value.schema != 1 {
                    return Err(ErrorCategory::IntegrityFailure);
                }
                value.capabilities
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => initial,
            Err(_) => return Err(ErrorCategory::IntegrityFailure),
        };
        let (current, _) = watch::channel(configured);
        Ok(Arc::new(Self {
            path: path.to_owned(),
            #[cfg(not(target_os = "android"))]
            root,
            current,
            report: Mutex::new(SettingsReport {
                generations: [0; 4],
                configured,
                applied: true,
                error: None,
                android_status: None,
            }),
            gate: Arc::new(RwLock::new(())),
            runtime: Mutex::new(None),
            tasks: TaskTracker::new(),
        }))
    }
    pub fn current(&self) -> Capabilities {
        *self.current.borrow()
    }
    pub fn subscribe(&self) -> watch::Receiver<Capabilities> {
        self.current.subscribe()
    }
    pub fn report(&self) -> SettingsReport {
        self.report.lock().expect("Host settings mutex").clone()
    }
    pub fn attach(&self, runtime: Arc<dyn CapabilityRuntime>) -> Result<(), ErrorCategory> {
        let mut current = self.runtime.lock().expect("Host settings runtime");
        if current.is_some() {
            return Err(ErrorCategory::StateConflict);
        }
        *current = Some(runtime);
        Ok(())
    }
    pub async fn admit(
        &self,
        enabled: impl FnOnce(Capabilities) -> bool,
    ) -> Result<OwnedRwLockReadGuard<()>, ErrorCategory> {
        let guard = self.gate.clone().read_owned().await;
        if self.tasks.is_closed() || !enabled(self.current()) {
            return Err(ErrorCategory::PermissionDenied);
        }
        Ok(guard)
    }
    pub async fn update(
        self: &Arc<Self>,
        patch: CapabilityPatch,
    ) -> Result<SettingsReport, ErrorCategory> {
        if patch.is_empty() {
            return Ok(self.report());
        }
        if self.tasks.is_closed() {
            return Err(ErrorCategory::StateConflict);
        }
        let this = self.clone();
        // A disconnected caller cannot abandon the accepted local update/cleanup.
        self.tasks
            .spawn(async move { this.apply(patch).await })
            .await
            .map_err(|_| ErrorCategory::ResultUnknown)?
    }
    async fn apply(
        self: Arc<Self>,
        patch: CapabilityPatch,
    ) -> Result<SettingsReport, ErrorCategory> {
        let _guard = self.gate.clone().write_owned().await;
        if self.tasks.is_closed() {
            return Err(ErrorCategory::StateConflict);
        }
        let runtime = self
            .runtime
            .lock()
            .expect("Host settings runtime")
            .clone()
            .ok_or(ErrorCategory::CapabilityUnsupported)?;
        let before = self.current();
        let after = patch.apply(before);
        let mut generations = self.report().generations;
        for (index, changed) in [
            before.exec != after.exec,
            before.browser != after.browser,
            before.computer != after.computer,
            before.android != after.android,
        ]
        .into_iter()
        .enumerate()
        {
            if changed {
                generations[index] = generations[index]
                    .checked_add(1)
                    .ok_or(ErrorCategory::StateConflict)?;
            }
        }
        // Do not re-enable while a previous disable has unfinished cleanup.
        let previous = self.report();
        if !previous.applied
            && ((after.exec && !before.exec)
                || (after.browser && !before.browser)
                || (after.computer && !before.computer)
                || (after.android && !before.android))
        {
            return Err(ErrorCategory::Busy);
        }
        let retained = self.clone();
        let persistence_warning = tokio::task::spawn_blocking(move || retained.persist(after))
            .await
            .map_err(|_| ErrorCategory::ResultUnknown)??;
        *self.report.lock().expect("Host settings mutex") = SettingsReport {
            generations,
            configured: after,
            applied: false,
            error: None,
            android_status: None,
        };
        self.current.send_replace(after);
        let result = runtime.apply(before, after).await;
        let report = SettingsReport {
            generations,
            configured: after,
            applied: result.is_ok() && persistence_warning.is_none(),
            android_status: None,
            error: result
                .err()
                .or(persistence_warning)
                .map(|e| format!("{e:?}")),
        };
        *self.report.lock().expect("Host settings mutex") = report.clone();
        Ok(report)
    }
    // An error before rename leaves configuration unchanged. A durability/readback
    // warning after rename must still apply the committed setting to this Host.
    fn persist(&self, capabilities: Capabilities) -> Result<Option<ErrorCategory>, ErrorCategory> {
        #[cfg(not(target_os = "android"))]
        if PrivateRoot::open(&self.path)
            .map_err(|_| ErrorCategory::IntegrityFailure)?
            .identity()
            != self.root.identity()
        {
            return Err(ErrorCategory::IntegrityFailure);
        }
        let bytes = serde_json::to_vec(&Persisted {
            schema: 1,
            capabilities,
        })
        .map_err(|_| ErrorCategory::IntegrityFailure)?;
        let mut file = tempfile::NamedTempFile::new_in(&self.path)
            .map_err(|_| ErrorCategory::IntegrityFailure)?;
        file.write_all(&bytes)
            .and_then(|()| file.as_file().sync_all())
            .map_err(|_| ErrorCategory::IntegrityFailure)?;
        file.persist(self.path.join(FILE))
            .map_err(|_| ErrorCategory::IntegrityFailure)?;
        #[cfg(unix)]
        if std::fs::File::open(&self.path)
            .and_then(|f| f.sync_all())
            .is_err()
        {
            return Ok(Some(ErrorCategory::ResultUnknown));
        }
        #[cfg(target_os = "android")]
        return match std::fs::read(self.path.join(FILE)) {
            Ok(raw) if raw == bytes => Ok(None),
            _ => Ok(Some(ErrorCategory::ResultUnknown)),
        };
        #[cfg(not(target_os = "android"))]
        match self.root.read_raw(FILE, 4096) {
            Ok(raw) if raw.bytes() == bytes => Ok(None),
            _ => Ok(Some(ErrorCategory::ResultUnknown)),
        }
    }
    pub async fn close(&self) {
        self.tasks.close();
        self.tasks.wait().await;
        self.runtime.lock().expect("Host settings runtime").take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Runtime {
        calls: AtomicUsize,
        fail: bool,
    }
    impl CapabilityRuntime for Runtime {
        fn apply(
            &self,
            _: Capabilities,
            _: Capabilities,
        ) -> BoxFuture<'_, Result<(), ErrorCategory>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                if self.fail {
                    Err(ErrorCategory::ResultUnknown)
                } else {
                    Ok(())
                }
            })
        }
    }
    fn root() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        root
    }
    const OFF: Capabilities = Capabilities {
        exec: false,
        browser: false,
        computer: false,
        android: false,
    };
    #[tokio::test]
    async fn settings_preserve_import_and_reopen_independently_of_pairing_defaults() {
        let root = root();
        let settings = HostSettings::open(root.path(), OFF).unwrap();
        let runtime = Arc::new(Runtime {
            calls: AtomicUsize::new(0),
            fail: false,
        });
        settings.attach(runtime.clone()).unwrap();
        let enabled = settings
            .update(CapabilityPatch {
                browser: Some(true),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(enabled.generations, [0, 1, 0, 0]);
        assert!(enabled.configured.browser && enabled.applied);
        assert_eq!(runtime.calls.load(Ordering::SeqCst), 1);
        let reopened = HostSettings::open(
            root.path(),
            Capabilities {
                exec: true,
                browser: false,
                computer: true,
                android: false,
            },
        )
        .unwrap();
        assert_eq!(reopened.current(), enabled.configured);
        settings.close().await;
        assert!(
            settings
                .update(CapabilityPatch {
                    exec: Some(true),
                    ..Default::default()
                })
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn unfinished_cleanup_remains_disabled_and_is_not_replayed_by_reads() {
        let root = root();
        let settings = HostSettings::open(root.path(), Capabilities { exec: true, ..OFF }).unwrap();
        let runtime = Arc::new(Runtime {
            calls: AtomicUsize::new(0),
            fail: true,
        });
        settings.attach(runtime.clone()).unwrap();
        let report = settings
            .update(CapabilityPatch {
                exec: Some(false),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(!report.applied && !report.configured.exec);
        assert!(settings.admit(|c| c.exec).await.is_err());
        assert!(!settings.report().applied);
        assert_eq!(
            settings
                .update(CapabilityPatch {
                    exec: Some(true),
                    ..Default::default()
                })
                .await
                .unwrap_err(),
            ErrorCategory::Busy
        );
        assert_eq!(runtime.calls.load(Ordering::SeqCst), 1);
        settings.close().await;
    }
    #[tokio::test]
    async fn settings_wait_for_admitted_work_before_stopping_its_provider() {
        let root = root();
        let settings = HostSettings::open(root.path(), Capabilities { exec: true, ..OFF }).unwrap();
        let runtime = Arc::new(Runtime {
            calls: AtomicUsize::new(0),
            fail: false,
        });
        settings.attach(runtime.clone()).unwrap();
        let guard = settings.admit(|c| c.exec).await.unwrap();
        let pending = settings.clone();
        let change = tokio::spawn(async move {
            pending
                .update(CapabilityPatch {
                    exec: Some(false),
                    ..Default::default()
                })
                .await
        });
        tokio::task::yield_now().await;
        assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
        drop(guard);
        assert!(change.await.unwrap().unwrap().applied);
        assert!(settings.admit(|c| c.exec).await.is_err());
        settings.close().await;
    }
}
