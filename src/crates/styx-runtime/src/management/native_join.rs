//! Explicit native Host enrollment. No runtime start, approval, legacy adoption,
//! automatic Join/Confirm retry, or inferred permission lives in this actor.
use serde::Serialize;
use std::{
    ffi::OsStr,
    fmt,
    path::{Path, PathBuf},
    sync::Arc,
};
use styx_contracts::identity::{DeviceId, Sha256Digest};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinStatus {
    AwaitingApproval,
    Rejected,
    ReadyToConnect,
    AlreadyReady,
}
impl JoinStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AwaitingApproval => "awaiting_approval",
            Self::Rejected => "rejected",
            Self::ReadyToConnect => "ready_to_connect",
            Self::AlreadyReady => "already_ready",
        }
    }
    pub const fn is_ready(self) -> bool {
        matches!(self, Self::ReadyToConnect | Self::AlreadyReady)
    }
}
impl fmt::Display for JoinStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
impl PartialEq<&str> for JoinStatus {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}
impl PartialEq<JoinStatus> for &str {
    fn eq(&self, other: &JoinStatus) -> bool {
        *self == other.as_str()
    }
}

#[derive(Serialize)]
pub struct JoinReport {
    pub schema: u16,
    pub operation: &'static str,
    pub status: JoinStatus,
    pub state_dir: PathBuf,
    pub device_id: DeviceId,
    pub fingerprint: Sha256Digest,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comparison_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    pub service_started: bool,
    pub runtime_health: &'static str,
    /// Display-only setup choices, never evidence of current Gateway approval.
    pub selected_features: SelectedFeatures,
    // Original verified seed intent, used only to omit an optional desktop read.
    // It is never accepted from, or exposed as, a public enrollment DTO.
    #[serde(skip)]
    pub(crate) computer_requested: bool,
    // Original formal runtime authority, never serialized or accepted from a DTO.
    #[serde(skip)]
    pub(crate) verified_runtime: Arc<crate::release::VerifiedNativeRelease>,
}
#[derive(Serialize)]
pub struct SelectedFeatures {
    pub computer: bool,
    pub browser: bool,
}
#[must_use]
pub struct JoinError {
    code: &'static str,
    exit: u8,
    retryable: bool,
    detail: Option<(&'static str, String)>,
    #[cfg(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(
            target_os = "macos",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")
    ))]
    _retained: Option<Box<platform::Retained>>,
}
impl JoinError {
    pub fn code(&self) -> &'static str {
        self.code
    }
    pub fn retryable(&self) -> bool {
        self.retryable
    }
    pub fn uncertain(&self) -> bool {
        self.exit == 4
    }
    pub fn hint(&self) -> Option<&'static str> {
        self.retryable.then_some("The pairing request was not sent. Check that this computer can reach the hub, then try a new join link.")
    }
    pub fn exit_code(&self) -> u8 {
        self.exit
    }
    /// The deployment field that was refused and why, when that is known.
    /// Deployment files hold paths and URLs, never credentials.
    pub fn detail(&self) -> Option<(&'static str, &str)> {
        self.detail
            .as_ref()
            .map(|(field, reason)| (*field, reason.as_str()))
    }
    fn new(code: &'static str, exit: u8) -> Self {
        Self {
            code,
            exit,
            retryable: false,
            detail: None,
            #[cfg(any(
                all(target_os = "windows", target_arch = "x86_64"),
                all(
                    target_os = "macos",
                    any(target_arch = "x86_64", target_arch = "aarch64")
                ),
                all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")
            ))]
            _retained: None,
        }
    }
}
impl fmt::Debug for JoinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code)
    }
}
impl fmt::Display for JoinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code)
    }
}
impl std::error::Error for JoinError {}
type Result<T> = std::result::Result<T, JoinError>;

pub async fn request(parent: &Path, name: &OsStr, deployment_file: &Path) -> Result<JoinReport> {
    #[cfg(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(
            target_os = "macos",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")
    ))]
    {
        let (parent, name, deployment) = (
            parent.to_path_buf(),
            name.to_owned(),
            deployment_file.to_path_buf(),
        );
        platform::owned(async move { platform::request(parent, name, deployment, None).await })
            .await
    }
    #[cfg(not(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(
            target_os = "macos",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")
    )))]
    {
        let _ = (parent, name, deployment_file);
        Err(JoinError::new("native_join_platform_unsupported", 3))
    }
}
pub async fn claim(state_dir: &Path) -> Result<JoinReport> {
    #[cfg(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(
            target_os = "macos",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")
    ))]
    {
        let path = state_dir.to_path_buf();
        platform::owned(async move { platform::claim(path, None, None).await }).await
    }
    #[cfg(not(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(
            target_os = "macos",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")
    )))]
    {
        let _ = state_dir;
        Err(JoinError::new("native_join_platform_unsupported", 3))
    }
}

/// Explicit owned-App enrollment; the public CLI entry remains ForegroundCli.
pub(crate) async fn request_for_app(
    scope: Arc<crate::app::HostScope>,
    deployment_file: &Path,
) -> Result<JoinReport> {
    #[cfg(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(
            target_os = "macos",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")
    ))]
    {
        let path = scope.state_dir().to_owned();
        let parent = path
            .parent()
            .ok_or_else(|| JoinError::new("native_join_invalid_input", 2))?
            .to_owned();
        let name = path
            .file_name()
            .ok_or_else(|| JoinError::new("native_join_invalid_input", 2))?
            .to_owned();
        let deployment = deployment_file.to_owned();
        let retained = scope.clone();
        let attempt = scope
            .scope_for_join()
            .map_err(|_| JoinError::new("native_join_app_scope_changed", 4))?;
        let result = platform::owned(async move {
            platform::request(parent, name, deployment, Some(attempt)).await
        })
        .await;
        // The attempt's Work has closed on success or safe recovery. Bind the
        // long-lived App scope only when a root remains; unknown errors retain
        // the original Work and continue to fence all enrollment operations.
        if result.is_ok() {
            retained.bind().map_err(|_| {
                JoinError::new("native_join_app_scope_changed", 4).with_app_scope(retained.clone())
            })?;
        } else if !result.as_ref().is_err_and(|error| error.retryable()) {
            let _ = retained.bind();
        }
        result.map_err(|error| error.with_app_scope(retained))
    }
    #[cfg(not(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(
            target_os = "macos",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")
    )))]
    {
        let _ = (scope, deployment_file);
        Err(JoinError::new("native_join_platform_unsupported", 3))
    }
}
pub(crate) async fn claim_for_app(
    scope: Arc<crate::app::HostScope>,
    candidate: Option<Arc<crate::release::VerifiedNativeRelease>>,
) -> Result<JoinReport> {
    #[cfg(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(
            target_os = "macos",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")
    ))]
    {
        let path = scope.state_dir().to_owned();
        let retained = scope.clone();
        platform::owned(async move { platform::claim(path, Some(scope), candidate).await })
            .await
            .map_err(|error| error.with_app_scope(retained))
    }
    #[cfg(not(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(
            target_os = "macos",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")
    )))]
    {
        let _ = (scope, candidate);
        Err(JoinError::new("native_join_platform_unsupported", 3))
    }
}

/// Recover only protected local enrollment progress for the original owned App.
/// This does not contact the Gateway or establish current remote authorization.
pub(crate) async fn inspect_for_app(scope: Arc<crate::app::HostScope>) -> Result<JoinReport> {
    #[cfg(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(
            target_os = "macos",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")
    ))]
    {
        let path = scope.state_dir().to_owned();
        let retained = scope.clone();
        platform::owned(async move { platform::inspect(path, Some(scope)).await })
            .await
            .map_err(|error| error.with_app_scope(retained))
    }
    #[cfg(not(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(
            target_os = "macos",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")
    )))]
    {
        let _ = scope;
        Err(JoinError::new("native_join_platform_unsupported", 3))
    }
}

/// Same complete inspector, retaining an already authenticated formal release.
/// The receiver still compares it with current C07 and revalidates every member.
pub(crate) async fn inspect_for_app_retained(
    scope: Arc<crate::app::HostScope>,
    runtime: Arc<crate::release::VerifiedNativeRelease>,
) -> Result<JoinReport> {
    let path = scope.state_dir().to_path_buf();
    let retained = scope.clone();
    platform::owned(async move {
        platform::inspect_with_candidate(path, Some(scope), Some(runtime)).await
    })
    .await
    .map_err(|error| error.with_app_scope(retained))
}

/// Read the original CLI enrollment prefix without dispatching Join/Claim/Confirm.
/// A partial or uncertain prefix is refused by the same inspector used by the App.
pub async fn inspect(state_dir: &Path) -> Result<JoinReport> {
    let path = state_dir.to_path_buf();
    platform::owned(async move { platform::inspect(path, None).await }).await
}

#[cfg(any(
    all(target_os = "windows", target_arch = "x86_64"),
    all(
        target_os = "macos",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")
))]
pub(crate) use platform::retirement_host_preflight;

#[cfg(any(
    all(target_os = "windows", target_arch = "x86_64"),
    all(
        target_os = "macos",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")
))]
#[path = "native_join"]
mod platform {
    mod deployment;
    mod retirement;
    mod work;

    pub(crate) use retirement::retirement_host_preflight;
    use work::{Work, create, io, open_with_candidate};

    use super::super::{native_join_http as http, native_join_protocol as protocol};
    use super::*;
    use crate::{
        release,
        store::native_root::{
            FreshNativeRoot, NativeRootFailure,
            host::{NativeHostJoinFile as File, NativeHostJoinStore},
        },
        tls::GatewayLeafPin,
    };
    use serde::{Deserialize, Serialize};
    use serde_json::value::RawValue;
    use std::{
        future::Future,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };
    use styx_contracts::native_host::{NativeHostReady, NativeHostRejected};
    use zeroize::Zeroizing;
    const LIMIT: usize = 1024 * 1024;
    // Enrollment wire names follow the existing Node/Host protocol, not Rust's
    // OS identifier: Windows is "win32" and macOS is "darwin".
    const PLATFORM: &str = if cfg!(target_os = "windows") {
        "win32"
    } else if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "linux"
    };
    const HTTP_BUDGET: Duration = Duration::from_secs(30);
    static JOBS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);

    pub(super) enum Retained {
        Root {
            _failure: NativeRootFailure,
        },
        Fresh {
            _root: Box<FreshNativeRoot>,
        },
        Store {
            _store: Box<NativeHostJoinStore>,
        },
        Work {
            _work: Box<Work>,
        },
        App {
            _scope: Arc<crate::app::HostScope>,
            _retained: Option<Box<Retained>>,
        },
    }
    impl JoinError {
        pub(super) fn with_app_scope(mut self, scope: Arc<crate::app::HostScope>) -> Self {
            if self.retryable {
                return self;
            }
            let retained = self._retained.take();
            self._retained = Some(Box::new(Retained::App {
                _scope: scope,
                _retained: retained,
            }));
            self
        }
        fn keep(mut self, retained: Retained) -> Self {
            self._retained = Some(Box::new(retained));
            self
        }
        fn root(failure: NativeRootFailure) -> Self {
            use crate::store::native_root::NativeRootError;
            let (code, exit) = match failure.error() {
                NativeRootError::AlreadyExists => ("native_join_already_exists", 2),
                NativeRootError::InvalidInput => ("native_join_invalid_input", 2),
                NativeRootError::Unsupported => ("native_join_platform_unsupported", 3),
                NativeRootError::Unknown => ("native_join_persistence_unknown", 4),
            };
            Self::new(code, exit).keep(Retained::Root { _failure: failure })
        }
    }
    fn bad() -> JoinError {
        JoinError::new("native_join_invalid_input", 2)
    }
    fn invalid(field: &'static str, reason: impl Into<String>) -> JoinError {
        let mut error = bad();
        error.detail = Some((field, reason.into()));
        error
    }
    fn unknown() -> JoinError {
        JoinError::new("native_join_unknown_inspect", 4)
    }
    fn protocol_error(error: protocol::ProtocolError) -> JoinError {
        JoinError::new(error.code(), 4)
    }
    fn clock_ms() -> Result<u64> {
        u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| unknown())?
                .as_millis(),
        )
        .ok()
        .filter(|n| *n != 0)
        .ok_or_else(unknown)
    }
    pub(super) async fn owned(
        job: impl Future<Output = Result<JoinReport>> + Send + 'static,
    ) -> Result<JoinReport> {
        let permit = JOBS
            .try_acquire()
            .map_err(|_| JoinError::new("native_join_busy", 3))?;
        // Dropping the caller's JoinHandle does not abort this once-only job.
        // The original owner and bounded permit remain held until real completion.
        tokio::spawn(async move {
            let _permit = permit;
            job.await
        })
        .await
        .map_err(|_| JoinError::new("native_join_worker_unknown", 4))?
    }
    async fn blocking<T: Send + 'static>(
        job: impl FnOnce() -> Result<T> + Send + 'static,
    ) -> Result<T> {
        tokio::task::spawn_blocking(job)
            .await
            .map_err(|_| JoinError::new("native_join_worker_unknown", 4))?
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RecordedReply<'a> {
        schema: u16,
        peer_leaf_sha256: Sha256Digest,
        #[serde(borrow)]
        body: &'a RawValue,
    }
    pub(super) async fn request(
        parent: PathBuf,
        name: std::ffi::OsString,
        deployment_file: PathBuf,
        app_scope: Option<Arc<crate::app::HostScope>>,
    ) -> Result<JoinReport> {
        let (mut work, body) =
            blocking(move || create(&parent, &name, &deployment_file, app_scope)).await?;
        let response = match http::exchange(
            &work.origin,
            &work.tls,
            "/styx/enroll/join",
            &body,
            None,
            HTTP_BUDGET,
        )
        .await
        {
            Ok(value) => value,
            Err(error) => {
                if error.certainty == http::JoinHttpCertainty::NotDispatched {
                    return blocking(move || recover_unsent(work, error.code())).await;
                }
                return Err(JoinError::new(error.code(), 4).keep(Retained::Work {
                    _work: Box::new(work),
                }));
            }
        };
        if response.status != 200 && response.status != 202 {
            return Err(
                JoinError::new("native_join_response_rejected", 4).keep(Retained::Work {
                    _work: Box::new(work),
                }),
            );
        }
        let (next, pending) = io(work, move |w| {
            let pending = protocol::validate_pending(
                &w.seed,
                &response.body,
                &response.leaf_pin,
                clock_ms()?,
            )
            .map_err(protocol_error)?;
            let record = RecordedReply {
                schema: 1,
                peer_leaf_sha256: Sha256Digest::try_from(response.leaf_pin.as_hex())
                    .map_err(|_| unknown())?,
                body: serde_json::from_slice::<&RawValue>(&response.body).map_err(|_| unknown())?,
            };
            let bytes = Zeroizing::new(serde_json::to_vec(&record).map_err(|_| unknown())?);
            w.append(File::JoinReply, &bytes)?;
            Ok(pending)
        })
        .await?;
        work = next;
        Ok(work.report(
            "native_host_request",
            JoinStatus::AwaitingApproval,
            &pending,
        ))
    }
    fn recover_unsent(work: Work, code: &'static str) -> Result<JoinReport> {
        // Never infer this permission from persisted phases on reopen. Only
        // this creating request's transport result can authorize recovery.
        let checked = (|| {
            work.validate()?;
            if work
                .store
                .read(File::JoinDispatched)
                .map_err(|_| unknown())?
                .is_none()
                || work
                    .store
                    .read(File::JoinReply)
                    .map_err(|_| unknown())?
                    .is_some()
            {
                return Err(unknown());
            }
            clock_ms()
        })();
        let now = match checked {
            Ok(now) => now,
            Err(_) => {
                return Err(JoinError::new(code, 4).keep(Retained::Work {
                    _work: Box::new(work),
                }));
            }
        };
        let identity = work.root.identity();
        let path = work.state_dir.clone();
        let scope = work.app_scope.clone();
        // Includes the journal/configuration writer, PrivateRoots and Input
        // handles. The App pin must also close before Windows can rename.
        drop(work);
        let inputs = scope
            .as_ref()
            .map_or_else(Vec::new, |s| s.unsent_join_inputs());
        drop(scope);
        if crate::store::native_root::host::move_unsent_join(&path, &identity, now, &inputs)
            .is_err()
        {
            return Err(JoinError::new(code, 4));
        }
        let mut error = JoinError::new(code, 2);
        error.retryable = true;
        Err(error)
    }
    fn pending(work: &Work, raw: &[u8], historical: bool) -> Result<protocol::PendingJoin> {
        let record: RecordedReply<'_> = serde_json::from_slice(raw).map_err(|_| unknown())?;
        if record.schema != 1 {
            return Err(unknown());
        }
        let leaf =
            GatewayLeafPin::parse_hex(&record.peer_leaf_sha256.to_hex()).map_err(|_| unknown())?;
        if historical {
            protocol::validate_recorded_pending(&work.seed, record.body.get().as_bytes(), &leaf)
                .map_err(protocol_error)
        } else {
            protocol::validate_pending(&work.seed, record.body.get().as_bytes(), &leaf, clock_ms()?)
                .map_err(protocol_error)
        }
    }
    fn validate_rejection(work: &Work, pending: &protocol::PendingJoin, raw: &[u8]) -> Result<()> {
        let rejected: NativeHostRejected = serde_json::from_slice(raw).map_err(|_| unknown())?;
        if work.seed.schema != styx_contracts::native_host::NATIVE_HOST_JOIN_SEED_SCHEMA
            || rejected.schema != 1
            || rejected.seed_sha256 != Sha256Digest::of_bytes(&work.seed_raw)
            || rejected.request_id != pending.request_id
            || rejected.device_id != work.seed.device_id
            || rejected.fingerprint != work.seed.fingerprint
        {
            return Err(unknown());
        }
        Ok(())
    }
    pub(super) async fn inspect(
        path: PathBuf,
        scope: Option<Arc<crate::app::HostScope>>,
    ) -> Result<JoinReport> {
        inspect_with_candidate(path, scope, None).await
    }
    pub(super) async fn inspect_with_candidate(
        path: PathBuf,
        scope: Option<Arc<crate::app::HostScope>>,
        candidate: Option<Arc<release::VerifiedNativeRelease>>,
    ) -> Result<JoinReport> {
        let work = blocking(move || open_with_candidate(&path, scope, candidate)).await?;
        let (_work, report) = io(work, |w| {
            // A strict complete prefix is required; absence/partial Claim or
            // Confirm stays unknown and never authorizes a network retry.
            // One fixed read-only batch validates all original files and the
            // complete C07 history before/after capture under the same owner.
            w.validate()?;
            let [dispatched, reply, credential, confirm, ready] =
                w.store.read_prefix().map_err(|_| unknown())?;
            if dispatched.is_none() {
                return Err(JoinError::new("native_join_dispatch_unknown_no_retry", 4));
            }
            let reply =
                reply.ok_or_else(|| JoinError::new("native_join_dispatch_unknown_no_retry", 4))?;
            if let Some(rejected) = w.store.read(File::Rejected).map_err(|_| unknown())? {
                if credential.is_some() || confirm.is_some() || ready.is_some() {
                    return Err(unknown());
                }
                let pending = pending(w, &reply, true)?;
                validate_rejection(w, &pending, &rejected)?;
                w.validate()?;
                return Ok(w.report("native_host_inspect", JoinStatus::Rejected, &pending));
            }
            let status;
            let observed_pending;
            match (credential, confirm, ready) {
                (None, None, None) => {
                    observed_pending = pending(w, &reply, false)?;
                    status = JoinStatus::AwaitingApproval;
                }
                (Some(credential), Some(confirm), Some(raw)) => {
                    observed_pending = pending(w, &reply, true)?;
                    let original: NativeHostReady =
                        serde_json::from_slice(&raw).map_err(|_| unknown())?;
                    if original.schema != 1
                        || original.seed_sha256 != Sha256Digest::of_bytes(&w.seed_raw)
                        || original.request_id != observed_pending.request_id
                        || original.credential_sha256 != Sha256Digest::of_bytes(&credential)
                        || original.device_id != w.seed.device_id
                        || original.fingerprint != w.seed.fingerprint
                        || original.generation.is_empty()
                        || original.generation.len() > 128
                        || !(32..=4096).contains(&credential.len())
                        || !credential
                            .iter()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(*b, b'_' | b'-'))
                    {
                        return Err(JoinError::new("native_ready_binding_changed", 4));
                    }
                    let expected_confirm =
                        protocol::confirm_request(&observed_pending, &credential)
                            .map_err(protocol_error)?;
                    if expected_confirm.as_slice() != confirm.as_slice() {
                        return Err(unknown());
                    }
                    // This is the persisted local Ready proof, not a current
                    // GET-self observation. Connect still rechecks admission.
                    status = JoinStatus::ReadyToConnect;
                }
                _ => return Err(JoinError::new("native_join_phase_unknown_no_retry", 4)),
            }
            w.validate()?;
            Ok(w.report("native_host_inspect", status, &observed_pending))
        })
        .await?;
        Ok(report)
    }
    pub(super) async fn claim(
        path: PathBuf,
        app_scope: Option<Arc<crate::app::HostScope>>,
        candidate: Option<Arc<release::VerifiedNativeRelease>>,
    ) -> Result<JoinReport> {
        let work = blocking(move || open_with_candidate(&path, app_scope, candidate)).await?;
        let (work, (reply, ready_raw, mut credential, confirm_dispatched, rejected)) =
            io(work, |w| {
                // All local prefix reads complete before any HTTP or append.
                // No cached prefix is used as authority for a later operation.
                w.validate()?;
                if w.seed.schema != styx_contracts::native_host::NATIVE_HOST_JOIN_SEED_SCHEMA {
                    return Err(JoinError::new("native_join_reader_upgrade_required", 2));
                }
                let [_, reply, credential, confirm, ready] =
                    w.store.read_prefix().map_err(|_| unknown())?;
                let reply = reply
                    .ok_or_else(|| JoinError::new("native_join_dispatch_unknown_no_retry", 4))?;
                let confirm = confirm.is_some();
                let rejected = w.store.read(File::Rejected).map_err(|_| unknown())?;
                w.validate()?;
                Ok((reply, ready, credential, confirm, rejected))
            })
            .await?;
        let historical = ready_raw.is_some()
            || rejected.is_some()
            || (credential.is_some() && confirm_dispatched);
        let (mut work, mut pending) = io(work, move |w| pending(w, &reply, historical)).await?;
        if let Some(raw) = rejected {
            let (_work, report) = io(work, move |w| {
                validate_rejection(w, &pending, &raw)?;
                Ok(w.report("native_host_claim", JoinStatus::Rejected, &pending))
            })
            .await?;
            return Ok(report);
        }
        if credential.is_none() {
            let body = match protocol::claim_request(&pending) {
                Ok(value) => value,
                Err(error) => {
                    return Err(protocol_error(error).keep(Retained::Work {
                        _work: Box::new(work),
                    }));
                }
            };
            let response = match http::exchange(
                &work.origin,
                &work.tls,
                "/styx/enroll/claim",
                &body,
                None,
                HTTP_BUDGET,
            )
            .await
            {
                Ok(value) => value,
                Err(error) => {
                    return Err(JoinError::new(error.code(), 4).keep(Retained::Work {
                        _work: Box::new(work),
                    }));
                }
            };
            if response.status == 202 {
                return Ok(work.report(
                    "native_host_claim",
                    JoinStatus::AwaitingApproval,
                    &pending,
                ));
            }
            if response.status != 200 {
                return Err(JoinError::new("native_claim_response_rejected", 4).keep(
                    Retained::Work {
                        _work: Box::new(work),
                    },
                ));
            }
            let (next, (original_pending, value)) = io(work, move |w| {
                if protocol::rejected_claim(&pending, &response.body).map_err(protocol_error)? {
                    let rejected = NativeHostRejected {
                        schema: 1,
                        seed_sha256: Sha256Digest::of_bytes(&w.seed_raw),
                        request_id: pending.request_id.clone(),
                        device_id: w.seed.device_id.clone(),
                        fingerprint: w.seed.fingerprint,
                    };
                    let raw = serde_json::to_vec(&rejected).map_err(|_| unknown())?;
                    w.append(File::Rejected, &raw)?;
                    validate_rejection(w, &pending, &raw)?;
                    return Ok((pending, None));
                }
                let credential = protocol::decrypt_claim(&w.seed, &w.key, &response.body)
                    .map_err(protocol_error)?;
                w.append(File::Credential, &credential)?;
                Ok((pending, Some(credential)))
            })
            .await?;
            work = next;
            pending = original_pending;
            let Some(value) = value else {
                return Ok(work.report("native_host_claim", JoinStatus::Rejected, &pending));
            };
            credential = Some(value);
        }
        let credential = match credential {
            Some(value) => value,
            None => {
                return Err(unknown().keep(Retained::Work {
                    _work: Box::new(work),
                }));
            }
        };
        if !confirm_dispatched {
            let proof_credential = Zeroizing::new(credential.to_vec());
            let (next, (original_pending, body)) = io(work, move |_w| {
                let body = protocol::confirm_request(&pending, &proof_credential)
                    .map_err(protocol_error)?;
                Ok((pending, body))
            })
            .await?;
            work = next;
            pending = original_pending;
            let persisted = Zeroizing::new(body.to_vec());
            (work, ()) = io(work, move |w| w.append(File::ConfirmDispatched, &persisted)).await?;
            let response = match http::exchange(
                &work.origin,
                &work.tls,
                "/styx/enroll/confirm",
                &body,
                None,
                HTTP_BUDGET,
            )
            .await
            {
                Ok(value) => value,
                Err(error) => {
                    return Err(JoinError::new(error.code(), 4).keep(Retained::Work {
                        _work: Box::new(work),
                    }));
                }
            };
            if response.status != 200 {
                return Err(JoinError::new("native_confirm_result_unknown", 4).keep(
                    Retained::Work {
                        _work: Box::new(work),
                    },
                ));
            }
            if let Err(error) = protocol::validate_confirmation(&work.seed, &response.body) {
                return Err(protocol_error(error).keep(Retained::Work {
                    _work: Box::new(work),
                }));
            }
        }
        // An existing confirm marker is never replayed. Only authenticated self
        // can resolve a lost confirmation response; 401 is not reachability proof.
        let response = match http::exchange_self(
            &work.origin,
            &work.tls,
            &work.seed.device_id,
            &credential,
            HTTP_BUDGET,
        )
        .await
        {
            Ok(value) => value,
            Err(error) => {
                return Err(JoinError::new(error.code(), 4).keep(Retained::Work {
                    _work: Box::new(work),
                }));
            }
        };
        if response.status != 200 {
            return Err(JoinError::new(
                if response.status == 401 || response.status == 403 {
                    "native_self_authentication_refused"
                } else {
                    "native_self_result_unknown"
                },
                4,
            )
            .keep(Retained::Work {
                _work: Box::new(work),
            }));
        }
        let observed = match protocol::validate_self(&work.seed, &response.body) {
            Ok(value) => value,
            Err(error) => {
                return Err(protocol_error(error).keep(Retained::Work {
                    _work: Box::new(work),
                }));
            }
        };
        let ready = NativeHostReady {
            schema: 1,
            seed_sha256: Sha256Digest::of_bytes(&work.seed_raw),
            request_id: pending.request_id.clone(),
            credential_sha256: Sha256Digest::of_bytes(&credential),
            device_id: work.seed.device_id.clone(),
            fingerprint: work.seed.fingerprint,
            generation: observed.generation,
            computer_approved: observed.computer_approved,
            browser_approved: observed.browser_approved,
        };
        if let Some(raw) = ready_raw {
            let original: NativeHostReady = match serde_json::from_slice(&raw) {
                Ok(value) => value,
                Err(_) => {
                    return Err(unknown().keep(Retained::Work {
                        _work: Box::new(work),
                    }));
                }
            };
            if original.schema != ready.schema
                || original.seed_sha256 != ready.seed_sha256
                || original.request_id != ready.request_id
                || original.credential_sha256 != ready.credential_sha256
                || original.device_id != ready.device_id
                || original.fingerprint != ready.fingerprint
            {
                return Err(JoinError::new("native_ready_binding_changed", 4).keep(
                    Retained::Work {
                        _work: Box::new(work),
                    },
                ));
            }
            (work, ()) = io(work, |w| w.validate()).await?;
            return Ok(work.report("native_host_claim", JoinStatus::AlreadyReady, &pending));
        }
        let bytes = match serde_json::to_vec(&ready) {
            Ok(value) => value,
            Err(_) => {
                return Err(unknown().keep(Retained::Work {
                    _work: Box::new(work),
                }));
            }
        };
        (work, ()) = io(work, move |w| w.append(File::Ready, &bytes)).await?;
        Ok(work.report("native_host_claim", JoinStatus::ReadyToConnect, &pending))
    }
}
