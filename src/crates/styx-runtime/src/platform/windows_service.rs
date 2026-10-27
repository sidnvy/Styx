//! Current-user Windows SCM adapter. SCM facts never mint C07 desired state.
//! Registration material is DATA: no account creation, password API, SYSTEM,
//! S4U, elevation, registry write, or privileged registration occurs here.
#![allow(unsafe_code)] // Official retained SCM/process/token HANDLE APIs.
use crate::{
    release::{self, VerifiedNativeRelease},
    store::{self, PrivateRoot, ProcessIdentity, RootIdentity, native_state},
};
use serde::Serialize;
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use styx_contracts::{
    identity::Sha256Digest,
    native_management::{
        NativeComponentDesired, NativeManager, NativeRunDesired, NativeRuntimeSelection,
        NativeState,
    },
};
use tokio::sync::Semaphore;
#[path = "windows_service/runner.rs"]
mod runner;
#[path = "windows_service/scm.rs"]
mod scm;
pub(crate) use runner::dispatch;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ServiceRole {
    Host,
    Gateway,
}
impl ServiceRole {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Gateway => "gateway",
        }
    }
    pub(crate) fn desired(self, state: &NativeState) -> Option<NativeComponentDesired> {
        match self {
            Self::Host => state.desired.host,
            Self::Gateway => state.desired.gateway,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ServiceError {
    #[error("invalid Windows service input")]
    Invalid,
    #[error("original Windows service identity changed")]
    Conflict,
    #[error("Windows service unavailable or registration requires OS authorization")]
    Unavailable,
    #[error("Windows service reader capacity reached")]
    Busy,
    #[error("Windows service outcome unknown; inspect original operation")]
    Unknown,
}
type Result<T> = std::result::Result<T, ServiceError>;
fn changed<T>(_: T) -> ServiceError {
    ServiceError::Conflict
}
fn unknown<T>(_: T) -> ServiceError {
    ServiceError::Unknown
}
fn unavailable<T>(_: T) -> ServiceError {
    ServiceError::Unavailable
}
static READERS: Semaphore = Semaphore::const_new(2);
/// The permit and captured pins remain with the original blocking call after
/// waiter loss; none of these native calls are canceled or retried.
pub(crate) async fn blocking_read<T: Send + 'static>(
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    let permit = READERS.try_acquire().map_err(|_| ServiceError::Busy)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work()
    })
    .await
    .map_err(unknown)?
}
fn owner(root: &RootIdentity) -> Result<&str> {
    let RootIdentity::Windows { owner_sid, .. } = root else {
        return Err(ServiceError::Invalid);
    };
    // Existing ordinary local/domain user only. Never built-in service accounts.
    if !owner_sid.starts_with("S-1-5-21-") {
        return Err(ServiceError::Conflict);
    }
    Ok(owner_sid)
}
pub(crate) fn fixed_name(path: &Path, role: ServiceRole) -> Result<String> {
    let root = PrivateRoot::open(path).map_err(unavailable)?;
    let identity = root.identity();
    let RootIdentity::Windows {
        volume_serial,
        file_id,
        ..
    } = &identity
    else {
        return Err(ServiceError::Invalid);
    };
    let sid = owner(&identity)?;
    let ProcessIdentity::Windows { owner_sid, .. } =
        ProcessIdentity::current().map_err(unavailable)?
    else {
        return Err(ServiceError::Invalid);
    };
    if owner_sid != sid {
        return Err(ServiceError::Conflict);
    }
    let digest = Sha256Digest::of_bytes(
        format!("styx-native-scm-v1:{volume_serial}:{file_id}:{sid}").as_bytes(),
    )
    .to_hex();
    Ok(format!("Styx-Native-{}-{}", &digest[..32], role.name()))
}
fn read_state(root: &PrivateRoot) -> Result<NativeState> {
    let marker_raw = root
        .read_raw(".styx-native-root-v1.json", 4096)
        .map_err(changed)?;
    let marker = native_state::decode_marker(marker_raw.bytes()).map_err(changed)?;
    let RootIdentity::Windows {
        volume_serial,
        file_id,
        owner_sid,
    } = root.identity()
    else {
        return Err(ServiceError::Invalid);
    };
    if marker.root_identity
        != (styx_contracts::native_management::NativeRootIdentity::Windows {
            volume_serial,
            file_id,
            owner_sid,
        })
    {
        return Err(ServiceError::Conflict);
    }
    let raw = root.read_raw("state.json", 1024 * 1024).map_err(changed)?;
    let checked = native_state::decode_state(raw.bytes(), &marker).map_err(changed)?;
    let deployment = root
        .read_raw("deployment.json", 1024 * 1024)
        .map_err(changed)?;
    if Sha256Digest::of_bytes(deployment.bytes()) != checked.state().deployment_raw_sha256 {
        return Err(ServiceError::Conflict);
    }
    Ok(checked.state().clone())
}
/// All fields are public preparation DATA, never a privilege or a runtime scope.
#[derive(Serialize)]
pub(crate) struct RegistrationRequest {
    pub(crate) schema: u32,
    pub(crate) service_name: String,
    pub(crate) binary_path_name: String,
    pub(crate) account_name: String,
    pub(crate) account_sid: String,
    pub(crate) service_type: &'static str,
    pub(crate) initial_start_type: &'static str,
    pub(crate) automatic_restart: bool,
    pub(crate) service_security_sddl: String,
    pub(crate) requires_administrator_registration: bool,
    pub(crate) requires_os_managed_service_logon: bool,
    pub(crate) password_accepted_by_styx: bool,
}
#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ServiceObservation {
    pub(crate) schema: u16,
    pub(crate) unit: String,
    pub(crate) role: ServiceRole,
    pub(crate) installed: bool,
    pub(crate) enabled: Option<bool>,
    pub(crate) active: String,
    pub(crate) main_pid: u32,
    pub(crate) service_exit_code: u32,
    pub(crate) checkpoint: u32,
    pub(crate) lifetime_scope: &'static str,
    pub(crate) survives_logout: Option<bool>,
    pub(crate) runtime_health: &'static str,
}
pub(crate) struct Definition {
    root: PrivateRoot,
    root_identity: RootIdentity,
    path: PathBuf,
    role: ServiceRole,
    selection: NativeRuntimeSelection,
    candidate: Arc<VerifiedNativeRelease>,
    executable: PathBuf,
    name: String,
    sid: String,
    command: String,
    account: String,
    registration: Option<scm::Registration>,
    stop: Mutex<Option<Arc<scm::OriginalProcess>>>,
}
impl Definition {
    pub(crate) fn prepare(path: &Path, role: ServiceRole, installation: bool) -> Result<Self> {
        let root = PrivateRoot::open(path).map_err(unavailable)?;
        let root_identity = root.identity();
        let sid = owner(&root_identity)?.to_owned();
        let name = fixed_name(path, role)?;
        let state = read_state(&root)?;
        let desired = role.desired(&state).ok_or(ServiceError::Invalid)?;
        // Legacy/migrated roots still require their own original owner handoff.
        if state.has_migration_binding()
            || desired.manager == NativeManager::AppManaged
            || (installation
                && (desired.manager != NativeManager::ForegroundCli
                    || desired.run != NativeRunDesired::Stopped
                    || desired.autostart
                        != styx_contracts::native_management::NativeAutostartDesired::Disabled))
            || (!installation && desired.manager != NativeManager::PersistentService)
        {
            return Err(ServiceError::Conflict);
        }
        let marker_raw = root
            .read_raw(".styx-native-root-v1.json", 4096)
            .map_err(changed)?;
        let marker = native_state::decode_marker(marker_raw.bytes()).map_err(changed)?;
        let raw = root.read_raw("state.json", 1024 * 1024).map_err(changed)?;
        let checked = native_state::decode_state(raw.bytes(), &marker).map_err(changed)?;
        if serde_json::to_vec(checked.state()).map_err(changed)?
            != serde_json::to_vec(&state).map_err(changed)?
        {
            return Err(ServiceError::Conflict);
        }
        let selection =
            store::native_host_snapshot::validated_runtime_selection(&root, &checked, &marker)
                .map_err(changed)?;
        let candidate = Arc::new(release::verify_selected(&selection).map_err(changed)?);
        if candidate.report().target != "x86_64-pc-windows-msvc" {
            return Err(ServiceError::Invalid);
        }
        let image = candidate.windows_executable().map_err(changed)?;
        let executable = image.source_path_for_suspended_spawn().map_err(changed)?;
        let command = scm::command_line(&executable, path, role)?;
        let account = scm::current_account(&sid)?;
        let registration = scm::Registration::open(&name, &command, &sid)?;
        let result = Self {
            root,
            root_identity,
            path: path.into(),
            role,
            selection,
            candidate,
            executable,
            name,
            sid,
            command,
            account,
            registration,
            stop: Mutex::new(None),
        };
        result.validate()?;
        Ok(result)
    }
    pub(crate) fn registration_request(&self) -> Result<RegistrationRequest> {
        self.validate()?;
        Ok(RegistrationRequest {
            schema: 1,
            service_name: self.name.clone(),
            binary_path_name: self.command.clone(),
            account_name: self.account.clone(),
            account_sid: self.sid.clone(),
            service_type: "own_process_noninteractive",
            initial_start_type: "demand_start_autostart_disabled",
            automatic_restart: false,
            service_security_sddl: format!(
                "O:{}D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{})",
                self.sid, self.sid
            ),
            requires_administrator_registration: true,
            requires_os_managed_service_logon: true,
            password_accepted_by_styx: false,
        })
    }
    pub(crate) fn state(&self) -> Result<NativeState> {
        self.validate_identity()?;
        read_state(&self.root)
    }
    pub(crate) fn validate_identity(&self) -> Result<()> {
        if self.root.identity() != self.root_identity
            || PrivateRoot::open(&self.path)
                .map_err(unavailable)?
                .identity()
                != self.root_identity
        {
            return Err(ServiceError::Conflict);
        }
        self.candidate.revalidate().map_err(changed)?;
        let image = self.candidate.windows_executable().map_err(changed)?;
        if image.source_path_for_suspended_spawn().map_err(changed)? != self.executable {
            return Err(ServiceError::Conflict);
        }
        match &self.registration {
            Some(registration) => registration.validate(&self.command, &self.sid),
            None if scm::Registration::open(&self.name, &self.command, &self.sid)?.is_none() => {
                Ok(())
            }
            None => Err(ServiceError::Conflict),
        }
    }
    pub(crate) fn validate(&self) -> Result<()> {
        self.validate_identity()?;
        let state = read_state(&self.root)?;
        if state.runtime_selection().map_err(changed)?.as_ref() != Some(&self.selection) {
            return Err(ServiceError::Conflict);
        }
        Ok(())
    }
    fn inspect_sync(&self) -> Result<ServiceObservation> {
        self.validate()?;
        let status = self
            .registration
            .as_ref()
            .map(scm::Registration::status)
            .transpose()?;
        Ok(ServiceObservation {
            schema: 1,
            unit: self.name.clone(),
            role: self.role,
            installed: status.is_some(),
            enabled: self
                .registration
                .as_ref()
                .map(scm::Registration::enabled)
                .transpose()?,
            active: status
                .as_ref()
                .map_or("not_installed", scm::Status::active)
                .into(),
            main_pid: status.as_ref().map_or(0, |s| s.pid),
            service_exit_code: status.as_ref().map_or(0, |s| s.exit_code),
            checkpoint: status.as_ref().map_or(0, |s| s.checkpoint),
            lifetime_scope: "machine_boot",
            survives_logout: None,
            runtime_health: "not_observed",
        })
    }
    pub(crate) async fn inspect(self: &Arc<Self>) -> Result<ServiceObservation> {
        let this = self.clone();
        blocking_read(move || this.inspect_sync()).await
    }
    pub(crate) fn require_installed_inactive(&self) -> Result<()> {
        self.validate()?;
        let registration = self
            .registration
            .as_ref()
            .ok_or(ServiceError::Unavailable)?;
        if registration.enabled()? || !registration.status()?.stopped() {
            return Err(ServiceError::Conflict);
        }
        Ok(())
    }
    pub(crate) async fn set_enabled(self: &Arc<Self>, enabled: bool) -> Result<ServiceObservation> {
        let this = self.clone();
        blocking_read(move || {
            this.validate()?;
            let registration = this
                .registration
                .as_ref()
                .ok_or(ServiceError::Unavailable)?;
            registration.set_enabled(enabled)?;
            this.inspect_sync()
        })
        .await
    }
    pub(crate) async fn start(self: &Arc<Self>) -> Result<ServiceObservation> {
        let this = self.clone();
        blocking_read(move || {
            this.validate()?;
            let registration = this
                .registration
                .as_ref()
                .ok_or(ServiceError::Unavailable)?;
            if !registration.status()?.stopped() {
                return Err(ServiceError::Conflict);
            }
            registration.start()?; // ONE dispatch; never retry on an ambiguous return.
            Ok(())
        })
        .await?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        loop {
            let observation = self.inspect().await?;
            if observation.active == "active" {
                let definition = self.clone();
                blocking_read(move || ServicePeer::bind(definition).map(|_| ())).await?;
                return Ok(observation);
            }
            if observation.active != "activating" || tokio::time::Instant::now() >= deadline {
                return Err(ServiceError::Unknown);
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
    pub(crate) async fn prepare_stop(self: &Arc<Self>) -> Result<()> {
        let this = self.clone();
        blocking_read(move || {
            this.validate()?;
            let registration = this
                .registration
                .as_ref()
                .ok_or(ServiceError::Unavailable)?;
            let status = registration.status()?;
            let mut stop = this.stop.lock().map_err(unknown)?;
            if stop.is_some() {
                return Err(ServiceError::Conflict);
            }
            if !status.stopped() {
                *stop = Some(Arc::new(scm::OriginalProcess::capture(
                    registration,
                    this.candidate.windows_executable().map_err(changed)?,
                    &this.sid,
                )?));
            }
            Ok(())
        })
        .await
    }
    pub(crate) async fn stop(self: &Arc<Self>, send_control: bool) -> Result<ServiceObservation> {
        let this = self.clone();
        let original = blocking_read(move || {
            this.validate_identity()?;
            let original = this.stop.lock().map_err(unknown)?.clone();
            let registration = this
                .registration
                .as_ref()
                .ok_or(ServiceError::Unavailable)?;
            if let Some(process) = &original {
                if !process.exited()? {
                    process.validate(
                        registration,
                        this.candidate.windows_executable().map_err(changed)?,
                        &this.sid,
                    )?;
                    if send_control {
                        registration.stop()?;
                    }
                }
            } else if !registration.status()?.stopped() {
                return Err(ServiceError::Conflict);
            }
            Ok(original)
        })
        .await?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        loop {
            let this = self.clone();
            let process = original.clone();
            let complete = blocking_read(move || {
                this.validate_identity()?;
                let registration = this
                    .registration
                    .as_ref()
                    .ok_or(ServiceError::Unavailable)?;
                let status = registration.status()?;
                if let Some(original) = process {
                    if original.exited()? {
                        if !status.stopped()
                            || status.exit_code != 0
                            || original.exit_code()? != Some(0)
                        {
                            return Err(ServiceError::Unknown);
                        }
                        return Ok(true);
                    }
                    original.validate(
                        registration,
                        this.candidate.windows_executable().map_err(changed)?,
                        &this.sid,
                    )?;
                    Ok(false)
                } else {
                    Ok(status.stopped() && status.exit_code == 0)
                }
            })
            .await?;
            if complete {
                return self.inspect().await;
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(ServiceError::Unknown);
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
    /// Deletion marks the exact retained SCM object. Its name cannot be reused
    /// while this original HANDLE is held; no by-name delete or wait is used.
    pub(crate) async fn uninstall(self: &Arc<Self>) -> Result<ServiceObservation> {
        let this = self.clone();
        blocking_read(move || {
            this.require_installed_inactive()?;
            this.registration
                .as_ref()
                .ok_or(ServiceError::Unavailable)?
                .delete()?;
            let mut observed = this.inspect_sync()?;
            observed.active = "marked_for_delete_original_handle_retained".into();
            Ok(observed)
        })
        .await
    }
}
pub(crate) struct ServicePeer {
    definition: Arc<Definition>,
    process: Arc<scm::OriginalProcess>,
}
impl ServicePeer {
    fn bind(definition: Arc<Definition>) -> Result<Arc<Self>> {
        definition.validate()?;
        let desired = definition
            .role
            .desired(&definition.state()?)
            .ok_or(ServiceError::Invalid)?;
        if desired.manager != NativeManager::PersistentService
            || desired.run != NativeRunDesired::Running
        {
            return Err(ServiceError::Conflict);
        }
        let registration = definition
            .registration
            .as_ref()
            .ok_or(ServiceError::Unavailable)?;
        let process = Arc::new(scm::OriginalProcess::capture(
            registration,
            definition.candidate.windows_executable().map_err(changed)?,
            &definition.sid,
        )?);
        let peer = Arc::new(Self {
            definition,
            process,
        });
        peer.validate()?;
        Ok(peer)
    }
    pub(crate) async fn observe(path: &Path, role: ServiceRole) -> Result<Arc<Self>> {
        let path = path.to_owned();
        blocking_read(move || Self::bind(Arc::new(Definition::prepare(&path, role, false)?))).await
    }
    pub(crate) fn pid(&self) -> u32 {
        self.process.pid()
    }
    pub(crate) fn sid(&self) -> &str {
        &self.definition.sid
    }
    pub(crate) fn state_dir(&self) -> &Path {
        &self.definition.path
    }
    pub(crate) fn role(&self) -> ServiceRole {
        self.definition.role
    }
    pub(crate) fn validate_identity(&self) -> Result<()> {
        self.definition.validate_identity()?;
        self.process.validate(
            self.definition
                .registration
                .as_ref()
                .ok_or(ServiceError::Unavailable)?,
            self.definition
                .candidate
                .windows_executable()
                .map_err(changed)?,
            &self.definition.sid,
        )
    }
    pub(crate) fn validate(&self) -> Result<()> {
        self.definition.validate()?;
        if self
            .definition
            .role
            .desired(&self.definition.state()?)
            .is_none_or(|d| d.manager != NativeManager::PersistentService)
        {
            return Err(ServiceError::Conflict);
        }
        self.validate_identity()
    }
}
/// Opaque original SCM process. A name, PID, argv or pipe DTO is no authority.
pub(crate) struct ServiceScope {
    peer: Arc<ServicePeer>,
}
impl ServiceScope {
    pub(crate) async fn authenticate(path: &Path, role: ServiceRole) -> Result<Arc<Self>> {
        let peer = if let Some(definition) = runner::retained_definition(path, role) {
            blocking_read(move || ServicePeer::bind(definition)).await?
        } else {
            return Err(ServiceError::Conflict);
        };
        if peer.pid() != std::process::id() || !runner::dispatched_for(path, role) {
            return Err(ServiceError::Conflict);
        }
        let scope = Arc::new(Self { peer });
        scope.validate()?;
        Ok(scope)
    }
    pub(crate) fn state_dir(&self) -> &Path {
        self.peer.state_dir()
    }
    pub(crate) fn role(&self) -> ServiceRole {
        self.peer.role()
    }
    pub(crate) fn sid(&self) -> &str {
        self.peer.sid()
    }
    pub(crate) fn validate_identity(&self) -> Result<()> {
        self.peer.validate_identity()
    }
    pub(crate) fn validate(&self) -> Result<()> {
        self.peer.validate()
    }
}
