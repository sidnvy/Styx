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

#[derive(Serialize)]
pub struct JoinReport {
    pub schema: u16,
    pub operation: &'static str,
    pub status: &'static str,
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
    // Original verified seed intent, used only to omit an optional desktop read.
    // It is never accepted from, or exposed as, a public enrollment DTO.
    #[serde(skip)]
    pub(crate) computer_requested: bool,
    // Original formal runtime authority, never serialized or accepted from a DTO.
    #[serde(skip)]
    pub(crate) verified_runtime: Arc<crate::release::VerifiedNativeRelease>,
}
#[must_use]
pub struct JoinError {
    code: &'static str,
    exit: u8,
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
        platform::owned(
            async move { platform::request(parent, name, deployment, Some(scope)).await },
        )
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
mod platform {
    use super::super::{native_join_http as http, native_join_protocol as protocol};
    use super::*;
    use crate::{
        crypto::DevicePrivateKey,
        release::{self, VerifiedNativeRelease},
        store::{
            FileObservation, PrivateRoot, RootIdentity,
            native_root::{
                self, FreshNativeRoot, NativeRootFailure,
                host::{FreshHostFiles, NativeHostJoinFile as File, NativeHostJoinStore},
            },
        },
        tls::{GatewayClientTls, GatewayLeafPin, TrustAnchorPin},
    };
    use serde::{Deserialize, Serialize};
    use serde_json::value::RawValue;
    use std::{
        collections::BTreeMap,
        future::Future,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };
    use styx_contracts::{
        management::ReaderContract,
        native_host::{NativeHostJoinSeed, NativeHostReady},
        native_management::*,
    };
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
    // A protected input retains raw custody and its descriptor-relative identity.
    // PrivateRoot's transient read buffer follows the existing store lifecycle;
    // retained copies here are zeroizing and never formatted or serialized.
    struct Input {
        root: PrivateRoot,
        relative: PathBuf,
        observation: FileObservation,
        raw: Zeroizing<Vec<u8>>,
    }
    impl Input {
        fn open(path: &Path, limit: usize) -> Result<Self> {
            if !path.is_absolute() {
                return Err(bad());
            }
            let root = PrivateRoot::open(path.parent().ok_or_else(bad)?).map_err(|_| bad())?;
            let file = root
                .read_raw(path.file_name().ok_or_else(bad)?, limit)
                .map_err(|_| bad())?;
            Ok(Self {
                relative: file.relative_path().to_path_buf(),
                observation: file.observation().clone(),
                raw: Zeroizing::new(file.bytes().to_vec()),
                root,
            })
        }
        fn revalidate(&self) -> Result<()> {
            let after = self
                .root
                .read_raw(&self.relative, LIMIT)
                .map_err(|_| unknown())?;
            if after.observation() != &self.observation || after.bytes() != self.raw.as_slice() {
                return Err(unknown());
            }
            Ok(())
        }
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "camelCase")]
    struct Deployment {
        schema: u16,
        mode: String,
        gateway: Gateway,
        host: Host,
        runtime_selection_file: PathBuf,
        invitation_file: PathBuf,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "camelCase")]
    struct Gateway {
        url: String,
        ca_file: PathBuf,
        expected_ca_sha256: Sha256Digest,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Host {
        label: String,
        cwd: PathBuf,
        shell: PathBuf,
        #[serde(default)]
        computer: bool,
        browser: Option<Box<RawValue>>,
    }
    // Same closed selection spellings as the existing protected Browser loader;
    // these are requested DATA, never permission or executable authority here.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "camelCase")]
    struct BrowserSelection {
        enabled: bool,
        #[serde(rename = "headless")]
        _headless: Option<bool>,
        #[serde(rename = "persistLogin")]
        _persist_login: Option<bool>,
        #[serde(rename = "executablePath")]
        _executable_path: Option<PathBuf>,
        #[serde(rename = "channel")]
        _channel: Option<String>,
        #[serde(rename = "profileRoot")]
        _profile_root: Option<PathBuf>,
    }
    fn deployment(raw: &[u8]) -> Result<(Deployment, url::Url, bool)> {
        let d: Deployment =
            serde_json::from_slice(raw).map_err(|e| invalid("deployment", e.to_string()))?;
        if d.schema != 1 {
            return Err(invalid("schema", "must be 1"));
        }
        if d.mode != "join-existing" {
            return Err(invalid("mode", "must be \"join-existing\""));
        }
        let origin =
            url::Url::parse(&d.gateway.url).map_err(|e| invalid("gateway.url", e.to_string()))?;
        if origin.scheme() != "https"
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
            || d.gateway.url != origin.origin().ascii_serialization()
        {
            return Err(invalid(
                "gateway.url",
                format!(
                    "must be the bare https origin with no path or trailing slash, e.g. {}",
                    origin.origin().ascii_serialization()
                ),
            ));
        }
        for (field, path) in [
            ("host.cwd", &d.host.cwd),
            ("host.shell", &d.host.shell),
            ("gateway.caFile", &d.gateway.ca_file),
            ("runtimeSelectionFile", &d.runtime_selection_file),
            ("invitationFile", &d.invitation_file),
        ] {
            if !path.is_absolute() {
                return Err(invalid(field, "must be an absolute path"));
            }
        }
        let requested = d
            .host
            .browser
            .as_ref()
            .map(|b| serde_json::from_str::<BrowserSelection>(b.get()))
            .transpose()
            .map_err(|e| invalid("host.browser", e.to_string()))?
            .is_some_and(|b| b.enabled);
        Ok((d, origin, requested))
    }
    fn tls(ca: &[u8], expected: Sha256Digest) -> Result<GatewayClientTls> {
        let pin = TrustAnchorPin::parse_hex(&expected.to_hex()).map_err(|_| bad())?;
        GatewayClientTls::from_pinned_ca_pem(ca, pin, None)
            .map_err(|_| JoinError::new("native_join_ca_rejected", 2))
    }
    fn text(path: &Path) -> Result<String> {
        path.to_str().map(str::to_owned).ok_or_else(bad)
    }
    fn identity(root: &PrivateRoot) -> NativeRootIdentity {
        match root.identity() {
            RootIdentity::Linux { device, inode, uid } => {
                NativeRootIdentity::Linux { device, inode, uid }
            }
            #[cfg(target_os = "macos")]
            RootIdentity::Macos { device, inode, uid } => {
                NativeRootIdentity::Macos { device, inode, uid }
            }
            #[cfg(target_os = "windows")]
            RootIdentity::Windows {
                volume_serial,
                file_id,
                owner_sid,
            } => NativeRootIdentity::Windows {
                volume_serial,
                file_id,
                owner_sid,
            },
        }
    }
    pub(super) struct Work {
        store: NativeHostJoinStore,
        root: PrivateRoot,
        state_dir: PathBuf,
        seed: NativeHostJoinSeed,
        seed_raw: Zeroizing<Vec<u8>>,
        key: DevicePrivateKey,
        tls: GatewayClientTls,
        origin: url::Url,
        candidate: Arc<VerifiedNativeRelease>,
        inputs: Vec<Input>,
        app_scope: Option<Arc<crate::app::HostScope>>,
    }
    impl Work {
        fn validate(&self) -> Result<()> {
            validate_app_scope(self.app_scope.as_deref(), &self.state_dir)?;
            let state = self.store.readstate().map_err(|_| unknown())?;
            if !state
                .state()
                .desired
                .host
                .as_ref()
                .is_some_and(|host| host.manager == caller_manager(self.app_scope.as_deref()))
            {
                return Err(unknown());
            }
            // readstate already checks the complete C07 chain under the original
            // join-store owner. Immutable seed runtime remains the bootstrap only.
            let selected = state
                .state()
                .runtime_selection()
                .map_err(|_| unknown())?
                .ok_or_else(unknown)?;
            let update = state.state().runtime_update().map_err(|_| unknown())?;
            let bootstrap = update
                .as_ref()
                .map_or(&selected, |update| &update.bootstrap_runtime);
            // Keep a complete pinned-release check at every existing Work
            // boundary, but derive reader support from that same authenticated
            // immutable manifest. The publication getters would scan the entire
            // payload three times here; no validation is cached across calls.
            self.candidate
                .revalidate_matches_selection(&selected)
                .map_err(|_| unknown())?;
            if bootstrap != &self.seed.runtime
                || selected.publisher_spki_sha256 != self.seed.runtime.publisher_spki_sha256
                || !self
                    .candidate
                    .manifest()
                    .minimum_reader
                    .supports_state_reader(state.state().reader_contract)
                || self.store.seed_binding().map_err(|_| unknown())? != self.seed_raw.as_slice()
                || self
                    .store
                    .configuration_root()
                    .identity()
                    .map_err(|_| unknown())?
                    != self.root.identity()
            {
                return Err(unknown());
            }
            for input in &self.inputs {
                input.revalidate()?;
            }
            validate_app_scope(self.app_scope.as_deref(), &self.state_dir)
        }
        fn append(&mut self, file: File, bytes: &[u8]) -> Result<()> {
            self.validate()?;
            self.store.append(file, bytes).map_err(|_| unknown())?;
            self.validate()
        }
        fn report(
            &self,
            operation: &'static str,
            status: &'static str,
            pending: &protocol::PendingJoin,
        ) -> JoinReport {
            JoinReport {
                schema: 1,
                operation,
                status,
                state_dir: self.state_dir.clone(),
                device_id: self.seed.device_id.clone(),
                fingerprint: self.seed.fingerprint,
                request_id: Some(pending.request_id.clone()),
                comparison_code: Some(pending.comparison_code.clone()),
                expires_at: Some(pending.expires_at),
                service_started: false,
                runtime_health: "not_started",
                computer_requested: self.seed.computer_requested,
                verified_runtime: self.candidate.clone(),
            }
        }
    }
    async fn io<T: Send + 'static>(
        mut work: Work,
        job: impl FnOnce(&mut Work) -> Result<T> + Send + 'static,
    ) -> Result<(Work, T)> {
        blocking(move || match job(&mut work) {
            Ok(value) => Ok((work, value)),
            Err(error) => Err(error.keep(Retained::Work {
                _work: Box::new(work),
            })),
        })
        .await
    }
    fn caller_manager(scope: Option<&crate::app::HostScope>) -> NativeManager {
        if scope.is_some() {
            NativeManager::AppManaged
        } else {
            NativeManager::ForegroundCli
        }
    }
    fn validate_app_scope(scope: Option<&crate::app::HostScope>, path: &Path) -> Result<()> {
        if let Some(scope) = scope {
            if path != scope.state_dir() {
                return Err(bad());
            }
            scope
                .validate()
                .map_err(|_| JoinError::new("native_join_app_scope_changed", 4))?;
        }
        Ok(())
    }
    fn candidate_for_load(
        selected: &NativeRuntimeSelection,
        retained: Option<Arc<release::VerifiedNativeRelease>>,
    ) -> Result<Arc<release::VerifiedNativeRelease>> {
        let candidate = match retained {
            Some(candidate) => {
                // Create or the original App owner may pass its formal object.
                // Each loader fully revalidates the exact selection; an earlier
                // result or caller-supplied DATA never supplies admission.
                candidate
                    .revalidate_matches_selection(selected)
                    .map_err(|_| JoinError::new("native_join_candidate_untrusted", 2))?;
                candidate
            }
            None => Arc::new(
                release::verify_selected(selected)
                    .map_err(|_| JoinError::new("native_join_candidate_untrusted", 2))?,
            ),
        };
        Ok(candidate)
    }
    fn load_with_candidate(
        store: NativeHostJoinStore,
        path: PathBuf,
        app_scope: Option<Arc<crate::app::HostScope>>,
        candidate: Option<Arc<release::VerifiedNativeRelease>>,
    ) -> Result<Work> {
        let loaded: Result<_> = (|| {
            validate_app_scope(app_scope.as_deref(), &path)?;
            let state = store.readstate().map_err(|_| unknown())?;
            if !state
                .state()
                .desired
                .host
                .as_ref()
                .is_some_and(|host| host.manager == caller_manager(app_scope.as_deref()))
            {
                return Err(bad());
            }
            let root = PrivateRoot::open(&path).map_err(|_| unknown())?;
            if store
                .configuration_root()
                .identity()
                .map_err(|_| unknown())?
                != root.identity()
            {
                return Err(unknown());
            }
            let seed_raw = Zeroizing::new(store.seed_binding().map_err(|_| unknown())?.to_vec());
            let seed: NativeHostJoinSeed =
                serde_json::from_slice(&seed_raw).map_err(|_| unknown())?;
            let deployment_input = Input::open(&path.join("deployment.json"), LIMIT)?;
            let (d, origin, browser_requested) = deployment(&deployment_input.raw)?;
            let ca = Input::open(&path.join("host-ca.pem"), 128 * 1024)?;
            let private = Input::open(&path.join("host-identity.pem"), 16 * 1024)?;
            let key = DevicePrivateKey::from_pkcs8_pem(&private.raw).map_err(|_| unknown())?;
            // The original store read above proves the complete C07 history.
            let selected = state
                .state()
                .runtime_selection()
                .map_err(|_| unknown())?
                .ok_or_else(unknown)?;
            let update = state.state().runtime_update().map_err(|_| unknown())?;
            let bootstrap = update
                .as_ref()
                .map_or(&selected, |update| &update.bootstrap_runtime);
            if update.is_some() && store.read(File::Ready).map_err(|_| unknown())?.is_none() {
                // Updating an incomplete enrollment cannot authorize replaying a
                // request/claim/confirm, including App-managed updates.
                return Err(bad());
            }
            let candidate = candidate_for_load(&selected, candidate)?;
            // The cold verifier or retained-candidate boundary above performed
            // complete original-root/publisher validation and exact selection
            // comparison. Reader support is part
            // of that same immutable authenticated manifest, not a new boundary.
            if !candidate
                .manifest()
                .minimum_reader
                .supports_state_reader(state.state().reader_contract)
            {
                return Err(bad());
            }
            if seed.schema != 1
                || seed.root_identity != identity(&root)
                || seed.scope_generation != state.state().scope_generation
                || seed.deployment_raw_sha256 != Sha256Digest::of_bytes(&deployment_input.raw)
                || seed.deployment_raw_sha256 != state.state().deployment_raw_sha256
                || seed.gateway_origin != d.gateway.url
                || seed.anchor_sha256 != d.gateway.expected_ca_sha256
                || &seed.runtime != bootstrap
                || selected.publisher_spki_sha256 != seed.runtime.publisher_spki_sha256
                || seed.label != d.host.label
                || seed.cwd != text(&d.host.cwd)?
                || seed.shell != text(&d.host.shell)?
                || seed.computer_requested != d.host.computer
                || seed.browser_requested != browser_requested
                || seed.platform != PLATFORM
                || Sha256Digest::of_bytes(key.public_key().spki_der()) != seed.fingerprint
                || crate::crypto::DevicePublicKey::from_spki_pem(seed.public_key_pem.as_bytes())
                    .map_err(|_| unknown())?
                    .spki_der()
                    != key.public_key().spki_der()
            {
                return Err(unknown());
            }
            let client = tls(&ca.raw, seed.anchor_sha256)?;
            Ok((
                root,
                seed,
                seed_raw,
                key,
                client,
                origin,
                candidate,
                vec![deployment_input, ca, private],
            ))
        })();
        let (root, seed, seed_raw, key, tls, origin, candidate, inputs) = match loaded {
            Ok(value) => value,
            Err(error) => {
                return Err(error.keep(Retained::Store {
                    _store: Box::new(store),
                }));
            }
        };
        let work = Work {
            store,
            root,
            state_dir: path,
            seed,
            seed_raw,
            key,
            tls,
            origin,
            candidate,
            inputs,
            app_scope,
        };
        if let Err(error) = work.validate() {
            return Err(error.keep(Retained::Work {
                _work: Box::new(work),
            }));
        }
        Ok(work)
    }
    fn create(
        parent: &Path,
        name: &OsStr,
        deployment_file: &Path,
        app_scope: Option<Arc<crate::app::HostScope>>,
    ) -> Result<(Work, Zeroizing<Vec<u8>>)> {
        if !parent.is_absolute() {
            return Err(bad());
        }
        validate_app_scope(app_scope.as_deref(), &parent.join(name))?;
        let source = Input::open(deployment_file, LIMIT)?;
        let (d, _, browser_requested) = deployment(&source.raw)?;
        let selection_input = Input::open(&d.runtime_selection_file, LIMIT)?;
        let selection: NativeRuntimeSelection =
            serde_json::from_slice(&selection_input.raw).map_err(|_| bad())?;
        let candidate = release::verify_selected(&selection)
            .map_err(|_| JoinError::new("native_join_candidate_untrusted", 2))?;
        // verify_selected already binds the exact original selection. The full
        // release is checked again below at the actual root-creation boundary.
        let ca = Input::open(&d.gateway.ca_file, 128 * 1024)?;
        let _ = tls(&ca.raw, d.gateway.expected_ca_sha256)?;
        let invitation_input = Input::open(&d.invitation_file, 4096)?;
        let invitation = std::str::from_utf8(&invitation_input.raw)
            .map_err(|_| bad())?
            .trim();
        if invitation.is_empty() {
            return Err(bad());
        }
        let generated = DevicePrivateKey::generate_rsa3072()
            .map_err(|_| JoinError::new("native_join_identity_generation_failed", 3))?;
        let mut random = [0u8; 12];
        getrandom::fill(&mut random)
            .map_err(|_| JoinError::new("native_join_entropy_unavailable", 3))?;
        let device_id =
            DeviceId::try_from(format!("styx-{}", hex::encode(random))).map_err(|_| bad())?;
        let parent_root = PrivateRoot::open(parent).map_err(|_| bad())?;
        for input in [&source, &selection_input, &ca, &invitation_input] {
            input.revalidate()?;
        }
        candidate.revalidate().map_err(|_| unknown())?;
        // Validate the original App parent again immediately before creation.
        validate_app_scope(app_scope.as_deref(), &parent.join(name))?;
        let fresh = native_root::create_fresh(&parent_root, name).map_err(JoinError::root)?;
        if let Some(scope) = &app_scope
            && scope.bind().and_then(|()| scope.validate()).is_err()
        {
            return Err(
                JoinError::new("native_join_app_scope_changed", 4).keep(Retained::Fresh {
                    _root: Box::new(fresh),
                }),
            );
        }
        let metadata: Result<_> = (|| {
            let seed = NativeHostJoinSeed {
                schema: 1,
                root_identity: fresh.marker().root_identity.clone(),
                scope_generation: fresh.marker().scope_generation,
                deployment_raw_sha256: Sha256Digest::of_bytes(&source.raw),
                runtime: selection.clone(),
                gateway_origin: d.gateway.url.clone(),
                anchor_sha256: d.gateway.expected_ca_sha256,
                device_id,
                fingerprint: Sha256Digest::of_bytes(generated.public_key().spki_der()),
                public_key_pem: generated.public_key_pem().to_owned(),
                label: d.host.label.clone(),
                platform: PLATFORM.into(),
                cwd: text(&d.host.cwd)?,
                shell: text(&d.host.shell)?,
                computer_requested: d.host.computer,
                browser_requested,
            };
            let join = protocol::make_join(&seed, invitation, generated.private_key())
                .map_err(protocol_error)?;
            let seed_raw = Zeroizing::new(serde_json::to_vec(&seed).map_err(|_| bad())?);
            let mut extensions = BTreeMap::new();
            extensions.insert(
                "fresh_host_seed_v1".into(),
                serde_json::value::to_raw_value(&Sha256Digest::of_bytes(&seed_raw))
                    .map_err(|_| bad())?,
            );
            extensions.insert(
                "runtime_selection_v1".into(),
                serde_json::value::to_raw_value(&selection).map_err(|_| bad())?,
            );
            let state = NativeState {
                schema: NATIVE_STATE_SCHEMA,
                kind: NativeStateKind::StyxDesiredState,
                runtime_format: NativeRuntimeFormat::NativeRustV1,
                reader_contract: ReaderContract::NativeManagementStateV1,
                scope_generation: seed.scope_generation,
                deployment_raw_sha256: seed.deployment_raw_sha256,
                mode: NativeDeploymentMode::JoinExisting,
                revision: 0,
                last_transaction: None,
                desired: NativeDesired {
                    gateway: None,
                    host: Some(NativeComponentDesired {
                        manager: caller_manager(app_scope.as_deref()),
                        run: NativeRunDesired::Stopped,
                        autostart: NativeAutostartDesired::Disabled,
                    }),
                },
                migration: None,
                extensions,
            };
            Ok((seed_raw, state, join))
        })();
        let (seed_raw, state, join) = match metadata {
            Ok(value) => value,
            Err(error) => {
                return Err(error.keep(Retained::Fresh {
                    _root: Box::new(fresh),
                }));
            }
        };
        let seconds = match clock_ms() {
            Ok(now) => now / 1000,
            Err(error) => {
                return Err(error.keep(Retained::Fresh {
                    _root: Box::new(fresh),
                }));
            }
        };
        let material = FreshHostFiles {
            ca_certificate_pem: &ca.raw,
            private_identity_pem: generated.protected_pkcs8_pem(),
            seed_binding: &seed_raw,
        };
        let store = fresh
            .initialize_host_pending(&source.raw, &state, material, seconds)
            .map_err(JoinError::root)?;
        // Retain the exact candidate admitted before root creation. The loader
        // still derives selection from the original store/C07 chain and performs
        // a complete exact-selection revalidation before retaining it in Work.
        let mut work = load_with_candidate(
            store,
            parent.join(name),
            app_scope,
            Some(Arc::new(candidate)),
        )?;
        // Before dispatch recheck the caller's original source/CA/invitation too.
        for input in [source, selection_input, ca, invitation_input] {
            if let Err(error) = input.revalidate() {
                return Err(error.keep(Retained::Work {
                    _work: Box::new(work),
                }));
            }
        }
        if let Err(error) = work.append(File::JoinDispatched, &join) {
            return Err(error.keep(Retained::Work {
                _work: Box::new(work),
            }));
        }
        Ok((work, join))
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
        Ok(work.report("native_host_request", "awaiting_approval", &pending))
    }
    fn open(path: &Path, app_scope: Option<Arc<crate::app::HostScope>>) -> Result<Work> {
        open_with_candidate(path, app_scope, None)
    }
    fn open_with_candidate(
        path: &Path,
        app_scope: Option<Arc<crate::app::HostScope>>,
        candidate: Option<Arc<release::VerifiedNativeRelease>>,
    ) -> Result<Work> {
        if !path.is_absolute() {
            return Err(bad());
        }
        validate_app_scope(app_scope.as_deref(), path)?;
        let root = PrivateRoot::open(path).map_err(|_| bad())?;
        let writer = root
            .try_existing_configuration_writer()
            .map_err(|_| JoinError::new("native_join_configuration_busy", 3))?;
        let binding = native_root::reopen_native(root, writer).map_err(JoinError::root)?;
        let store = NativeHostJoinStore::from_binding(binding).map_err(JoinError::root)?;
        load_with_candidate(store, path.to_path_buf(), app_scope, candidate)
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
    pub(super) async fn inspect(
        path: PathBuf,
        scope: Option<Arc<crate::app::HostScope>>,
    ) -> Result<JoinReport> {
        let work = blocking(move || open(&path, scope)).await?;
        let (_work, report) = io(work, |w| {
            // A strict complete prefix is required. Missing reply or a partial
            // Claim/Confirm has unknown outcome, never an invitation to retry.
            // Inspect one bounded read-only prefix under the original writer.
            // Each store read still checks every original phase/material pin
            // and journal tip. No network or mutation occurs between reads;
            // validate the complete release before and after this batch instead
            // of streaming that same closure separately for every phase file.
            w.validate()?;
            let dispatched = w.store.read(File::JoinDispatched).map_err(|_| unknown())?;
            let reply = w.store.read(File::JoinReply).map_err(|_| unknown())?;
            let credential = w.store.read(File::Credential).map_err(|_| unknown())?;
            let confirm = w
                .store
                .read(File::ConfirmDispatched)
                .map_err(|_| unknown())?;
            let ready = w.store.read(File::Ready).map_err(|_| unknown())?;
            w.validate()?;
            if dispatched.is_none() {
                return Err(JoinError::new("native_join_dispatch_unknown_no_retry", 4));
            }
            let reply =
                reply.ok_or_else(|| JoinError::new("native_join_dispatch_unknown_no_retry", 4))?;
            let status;
            let observed_pending;
            match (credential, confirm, ready) {
                (None, None, None) => {
                    observed_pending = pending(w, &reply, false)?;
                    status = "awaiting_approval";
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
                    status = "ready_to_connect";
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
        let (work, (reply, ready_raw, mut credential, confirm_dispatched)) = io(work, |w| {
            // One read-only prefix under the same original writer, as in
            // inspect above. Every store.read still verifies its original pins
            // and journal tip; no append or HTTP occurs between these reads.
            w.validate()?;
            let reply = w
                .store
                .read(File::JoinReply)
                .map_err(|_| unknown())?
                .ok_or_else(|| JoinError::new("native_join_dispatch_unknown_no_retry", 4))?;
            let ready = w.store.read(File::Ready).map_err(|_| unknown())?;
            let credential = w.store.read(File::Credential).map_err(|_| unknown())?;
            let confirm = w
                .store
                .read(File::ConfirmDispatched)
                .map_err(|_| unknown())?
                .is_some();
            w.validate()?;
            Ok((reply, ready, credential, confirm))
        })
        .await?;
        let historical = ready_raw.is_some() || (credential.is_some() && confirm_dispatched);
        let (mut work, mut pending) = io(work, move |w| pending(w, &reply, historical)).await?;
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
                return Ok(work.report("native_host_claim", "awaiting_approval", &pending));
            }
            if response.status != 200 {
                return Err(JoinError::new("native_claim_response_rejected", 4).keep(
                    Retained::Work {
                        _work: Box::new(work),
                    },
                ));
            }
            let (next, value) = io(work, move |w| {
                let credential = protocol::decrypt_claim(&w.seed, &w.key, &response.body)
                    .map_err(protocol_error)?;
                w.append(File::Credential, &credential)?;
                Ok(credential)
            })
            .await?;
            work = next;
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
            return Ok(work.report("native_host_claim", "already_ready", &pending));
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
        Ok(work.report("native_host_claim", "ready_to_connect", &pending))
    }

    #[cfg(all(test, target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    mod deployment_field_tests {
        use super::*;

        fn refused(value: serde_json::Value) -> (&'static str, String) {
            let error = deployment(value.to_string().as_bytes()).err().unwrap();
            assert_eq!(error.code(), "native_join_invalid_input");
            let (field, reason) = error.detail().unwrap();
            (field, reason.to_owned())
        }

        #[test]
        fn join_deployment_refusals_name_the_field() {
            let valid = serde_json::json!({
                "schema": 1, "mode": "join-existing",
                "gateway": {"url": "https://127.0.0.1:8443", "caFile": "/p/ca.pem",
                    "expectedCaSha256": "00".repeat(32)},
                "host": {"label": "l", "cwd": "/p/cwd", "shell": "/bin/bash",
                    "browser": {"enabled": true, "headless": true, "persistLogin": false}},
                "runtimeSelectionFile": "/p/sel.json", "invitationFile": "/p/inv.txt"
            });
            assert!(deployment(valid.to_string().as_bytes()).is_ok());
            for origin in ["https://192.168.1.2:8443", "https://100.64.1.2:8443"] {
                let mut remote = valid.clone();
                remote["gateway"]["url"] = origin.into();
                assert!(deployment(remote.to_string().as_bytes()).is_ok());
            }

            let mut slash = valid.clone();
            slash["gateway"]["url"] = "https://127.0.0.1:8443/".into();
            let (field, reason) = refused(slash);
            assert_eq!(field, "gateway.url");
            assert!(reason.contains("https://127.0.0.1:8443"), "{reason}");

            let mut misspelt = valid.clone();
            misspelt["host"]["browser"]["executable"] = "/usr/bin/chrome".into();
            let (field, reason) = refused(misspelt);
            assert_eq!(field, "host.browser");
            assert!(reason.contains("executable"), "{reason}");

            let mut relative = valid;
            relative["host"]["cwd"] = "work".into();
            assert_eq!(refused(relative).0, "host.cwd");
        }
    }

    #[cfg(all(test, target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    mod retained_candidate_tests {
        use super::*;
        use base64::Engine as _;
        use ed25519_dalek::{Signer as _, SigningKey, pkcs8::EncodePublicKey as _};
        use std::{
            fs,
            io::Write as _,
            os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _},
        };

        // Actual private files and a synthetic signing key; no worker execution,
        // pairing, external publisher key or platform acceptance is claimed.
        #[test]
        fn retained_join_candidate_rejects_selection_other_release_and_changed_member() {
            fn directory(path: &Path) {
                fs::DirBuilder::new().mode(0o700).create(path).unwrap();
            }
            fn write(path: &Path, bytes: &[u8], executable: bool) {
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(if executable { 0o700 } else { 0o600 })
                    .open(path)
                    .unwrap();
                file.write_all(bytes).unwrap();
                file.sync_all().unwrap();
            }
            let root =
                std::env::temp_dir().join(format!("styx-join-retained-{}", uuid::Uuid::new_v4()));
            directory(&root);
            let key = SigningKey::from_bytes(&[37u8; 32]);
            let der = key.verifying_key().to_public_key_der().unwrap();
            let pem = format!(
                "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
                base64::engine::general_purpose::STANDARD.encode(der.as_bytes())
            );
            let publisher = root.join("publisher.pem");
            write(&publisher, pem.as_bytes(), false);
            let expected = crate::crypto::PublisherVerifyingKey::from_spki_pem(pem.as_bytes())
                .unwrap()
                .fingerprint()
                .unwrap();
            let make = |name: &str| {
                let payload = root.join(name);
                directory(&payload);
                directory(&payload.join("bin"));
                let sources = [
                    (
                        "LICENSE",
                        b"synthetic join fixture license".as_slice(),
                        false,
                    ),
                    (
                        "bin/styx",
                        b"\x7fELF synthetic join fixture, never executed".as_slice(),
                        true,
                    ),
                    (
                        "source-inputs.json",
                        b"synthetic source inputs".as_slice(),
                        false,
                    ),
                ];
                let files: Vec<_> = sources
                    .iter()
                    .map(|(name, bytes, executable)| {
                        write(&payload.join(name), bytes, *executable);
                        styx_contracts::native_release::NativeReleaseMember {
                            path: (*name).to_owned(),
                            size: bytes.len() as u64,
                            sha256: Sha256Digest::of_bytes(bytes),
                            executable: *executable,
                        }
                    })
                    .collect();
                let manifest = serde_json::json!({"schema":2,"runtime_format":"native_rust_v1","component":"styx",
                    "scope":"runtime_candidate","minimum_reader":"native_runtime_migrated_v3","target":"x86_64-unknown-linux-gnu",
                    "version":"0.4.0-test.1","entrypoint":"bin/styx","source":{"revision":"1".repeat(40),
                    "inputs_sha256":Sha256Digest::of_bytes(sources[2].1)},"contracts":{"control":1,"management_state":2},
                    "files":files,"external_workers":[]});
                let raw = serde_json::to_vec(&manifest).unwrap();
                write(&payload.join("manifest.json"), &raw, false);
                write(
                    &payload.join("manifest.sig"),
                    &key.sign(&raw).to_bytes(),
                    false,
                );
                let verified = release::verify(&payload, &publisher, &expected).unwrap();
                let selected = verified.runtime_selection().unwrap();
                (Arc::new(verified), selected)
            };
            let (original, selected) = make("original");
            let accepted = candidate_for_load(&selected, Some(original)).unwrap();
            let mut wrong = selected.clone();
            wrong.manifest_sha256 = Sha256Digest::of_bytes(b"wrong manifest");
            assert!(candidate_for_load(&wrong, Some(accepted)).is_err());
            let (other, _) = make("other");
            assert!(candidate_for_load(&selected, Some(other)).is_err());
            // Cold load is still the original complete verifier.
            let original = candidate_for_load(&selected, None).unwrap();
            let member = root.join("original/source-inputs.json");
            let mut file = fs::OpenOptions::new().write(true).open(member).unwrap();
            file.write_all(b"changed").unwrap();
            file.sync_all().unwrap();
            drop(file);
            assert!(candidate_for_load(&selected, Some(original)).is_err());
            fs::remove_dir_all(root).unwrap();
        }
    }
}
