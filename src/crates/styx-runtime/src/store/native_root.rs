//! Explicitly fresh native configuration roots. No legacy adoption, service
//! handoff, runtime readiness, publisher trust, or pairing authority is created.
//! Every ambiguous persistence outcome retains its original owned resources.
use super::native_state::{self, ValidatedNativeState};
use super::{ConfigurationWriterGuard, OwnedConfigurationRoot, PrivateRoot, RootIdentity};
use styx_contracts::native_management::{NativeRootMarker, NativeState};

pub const NATIVE_MARKER_FILE: &str = ".styx-native-root-v1.json";
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NativeRootError {
    #[error("native_root_unsupported")]
    Unsupported,
    #[error("native_root_invalid_input")]
    InvalidInput,
    #[error("native_root_already_exists")]
    AlreadyExists,
    #[error("native_root_unknown")]
    Unknown,
}
/// No retry/resume/delete port. Dropping the entire owned failure is explicit
/// scope teardown, not evidence that partially persisted bytes disappeared.
#[must_use = "retain unresolved native root resources or explicitly tear down the entire owned scope"]
pub struct NativeRootFailure {
    error: NativeRootError,
    ownership: Box<Ownership>,
}
enum Ownership {
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    Unavailable,
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    Parent {
        parent: PrivateRoot,
        component: std::ffi::OsString,
        created: bool,
        child: Option<PrivateRoot>,
    },
    Root {
        root: PrivateRoot,
        writer: ConfigurationWriterGuard,
    },
    Configuration(OwnedConfigurationRoot),
}
impl NativeRootFailure {
    pub fn error(&self) -> NativeRootError {
        self.error
    }
    pub fn writer_held(&self) -> bool {
        match &*self.ownership {
            Ownership::Root { writer, .. } => {
                let _ = writer;
                true
            }
            Ownership::Configuration(_) => true,
            _ => false,
        }
    }
    pub fn owned_root_identity(&self) -> Option<RootIdentity> {
        match &*self.ownership {
            Ownership::Root { root, .. } => Some(root.identity()),
            Ownership::Configuration(owner) => owner.identity().ok(),
            #[cfg(all(target_os = "linux", target_env = "gnu"))]
            Ownership::Parent { child, .. } => child.as_ref().map(PrivateRoot::identity),
            #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
            Ownership::Unavailable => None,
        }
    }
    /// Facts only: a directory may exist even before any child writer could be
    /// acquired. The retained parent locator never grants native-root authority.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    pub fn orphan_locator(&self) -> Option<(RootIdentity, &std::ffi::OsStr, bool)> {
        match &*self.ownership {
            Ownership::Parent {
                parent,
                component,
                created,
                ..
            } => Some((parent.identity(), component.as_os_str(), *created)),
            _ => None,
        }
    }
}
/// Non-cloneable bootstrap authority, minted only by a successful mkdirat.
#[must_use]
pub struct FreshNativeRoot {
    root: PrivateRoot,
    writer: ConfigurationWriterGuard,
    marker: NativeRootMarker,
    marker_bytes: Vec<u8>,
    marker_observation: super::FileObservation,
}
/// Opaque runtime binding, never Deserialize/Clone or constructed from a DTO.
/// Its configuration handle shares the exact single writer, not another lock.
pub struct NativeRootBinding {
    owner: OwnedConfigurationRoot,
    marker: NativeRootMarker,
    marker_bytes: Vec<u8>,
    marker_observation: super::FileObservation,
}
impl FreshNativeRoot {
    pub fn marker(&self) -> &NativeRootMarker {
        &self.marker
    }
    /// Canonical genesis only: original deployment bytes remain opaque and are
    /// not evidence of a completed onboarding/service/legacy migration flow.
    pub fn initialize(
        self,
        deployment: &[u8],
        state: &NativeState,
    ) -> Result<NativeRootBinding, NativeRootFailure> {
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        {
            platform::initialize(self, deployment, state, &|_, _| {})
        }
        #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
        {
            let _ = (deployment, state);
            Err(NativeRootFailure {
                error: NativeRootError::Unsupported,
                ownership: Box::new(Ownership::Root {
                    root: self.root,
                    writer: self.writer,
                }),
            })
        }
    }
}
impl NativeRootBinding {
    pub fn configuration_root(&self) -> OwnedConfigurationRoot {
        self.owner.clone()
    }
    /// Cached non-secret metadata; sensitive accesses must revalidate the pin.
    pub fn marker(&self) -> &NativeRootMarker {
        &self.marker
    }
    pub fn validated_readstate(&self) -> Result<ValidatedNativeState, NativeRootError> {
        self.with_binding(|state, marker| {
            verify_read(
                &state.root,
                marker,
                &self.marker_bytes,
                &self.marker_observation,
            )
            .map_err(|_| super::secure_journal::JournalError::Unknown)
        })
        .map_err(|_| NativeRootError::Unknown)
    }
    pub(super) fn read_locked(
        &self,
        state: &super::configuration::ConfigurationState,
    ) -> super::secure_journal::JournalResult<ValidatedNativeState> {
        verify_read(
            &state.root,
            &self.marker,
            &self.marker_bytes,
            &self.marker_observation,
        )
        .map_err(|_| super::secure_journal::JournalError::Unknown)
    }
    /// Re-establish durability for the exact observed native canonical files.
    /// Caller already holds this binding's shared owner mutex and maintenance
    /// fence. This does not acquire/release a fence or make an observed target a
    /// committed transaction. Any IO/change remains Unknown to that same owner.
    pub(super) fn resync_locked(
        &self,
        state: &super::configuration::ConfigurationState,
    ) -> super::secure_journal::JournalResult<ValidatedNativeState> {
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        {
            use super::secure_journal::{JournalError, files};
            use styx_contracts::native_management::NATIVE_STATE_BYTES;
            let before = self.read_locked(state)?;
            let canonical = state
                .root
                .read_raw("state.json", NATIVE_STATE_BYTES)
                .map_err(|_| JournalError::Unknown)?;
            let deployment = state
                .root
                .read_raw("deployment.json", NATIVE_STATE_BYTES)
                .map_err(|_| JournalError::Unknown)?;
            if canonical.bytes() != before.raw_bytes() {
                return Err(JournalError::Unknown);
            }
            state
                .root
                .inner
                .with_configuration_writer_directory(&state.writer, |directory| {
                    Ok((|| {
                        for name in [NATIVE_MARKER_FILE, "deployment.json", "state.json"] {
                            files::sync_file(directory, name)?;
                        }
                        directory.sync_all().map_err(|_| JournalError::Unknown)
                    })())
                })
                .map_err(|_| JournalError::Unknown)??;
            let after = self.read_locked(state)?;
            let canonical_after = state
                .root
                .read_raw("state.json", NATIVE_STATE_BYTES)
                .map_err(|_| JournalError::Unknown)?;
            let deployment_after = state
                .root
                .read_raw("deployment.json", NATIVE_STATE_BYTES)
                .map_err(|_| JournalError::Unknown)?;
            if after.raw_sha256() != before.raw_sha256()
                || after.raw_bytes() != before.raw_bytes()
                || canonical_after.bytes() != after.raw_bytes()
                || canonical_after.observation() != canonical.observation()
                || deployment_after.bytes() != deployment.bytes()
                || deployment_after.observation() != deployment.observation()
            {
                return Err(JournalError::Unknown);
            }
            verify_marker(
                &state.root,
                &self.marker,
                &self.marker_bytes,
                &self.marker_observation,
            )
            .map_err(|_| JournalError::Unknown)?;
            Ok(after)
        }
        #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
        {
            let _ = state;
            Err(super::secure_journal::JournalError::Unsupported)
        }
    }
    /// Store-private boundary for future apply: the original marker pin is
    /// checked before AND after the short filesystem closure, under one mutex.
    pub(super) fn with_binding<T>(
        &self,
        operation: impl FnOnce(
            &mut super::configuration::ConfigurationState,
            &NativeRootMarker,
        ) -> super::secure_journal::JournalResult<T>,
    ) -> super::secure_journal::JournalResult<T> {
        self.owner.with_state(|state| {
            verify_marker(
                &state.root,
                &self.marker,
                &self.marker_bytes,
                &self.marker_observation,
            )
            .map_err(|_| super::secure_journal::JournalError::Unknown)?;
            let result = operation(state, &self.marker);
            verify_marker(
                &state.root,
                &self.marker,
                &self.marker_bytes,
                &self.marker_observation,
            )
            .map_err(|_| super::secure_journal::JournalError::Unknown)?;
            result
        })
    }
}
fn same_identity(root: &RootIdentity, marker: &NativeRootMarker) -> bool {
    match root {
        RootIdentity::Linux { device, inode, uid } => {
            marker.root_identity
                == styx_contracts::native_management::NativeRootIdentity::Linux {
                    device: *device,
                    inode: *inode,
                    uid: *uid,
                }
        }
        // Native writable roots/journals remain Linux-only. A Darwin read/lease
        // identity must never be relabeled as a compatible native writer root.
        #[cfg(target_os = "macos")]
        RootIdentity::Macos { .. } => false,
    }
}

fn verify_marker(
    root: &PrivateRoot,
    marker: &NativeRootMarker,
    bytes: &[u8],
    pin: &super::FileObservation,
) -> Result<(), NativeRootError> {
    let observed = root
        .read_raw(
            NATIVE_MARKER_FILE,
            styx_contracts::native_management::NATIVE_MARKER_BYTES,
        )
        .map_err(|_| NativeRootError::Unknown)?;
    if observed.bytes() != bytes
        || observed.observation() != pin
        || !same_identity(&root.identity(), marker)
        || native_state::decode_marker(observed.bytes()).map_err(|_| NativeRootError::Unknown)?
            != *marker
    {
        return Err(NativeRootError::Unknown);
    }
    Ok(())
}
fn verify_read(
    root: &PrivateRoot,
    marker: &NativeRootMarker,
    marker_bytes: &[u8],
    pin: &super::FileObservation,
) -> Result<ValidatedNativeState, NativeRootError> {
    use styx_contracts::{identity::Sha256Digest, native_management::*};
    verify_marker(root, marker, marker_bytes, pin)?;
    let raw = root
        .read_raw("state.json", NATIVE_STATE_BYTES)
        .map_err(|_| NativeRootError::Unknown)?;
    let state =
        native_state::decode_state(raw.bytes(), marker).map_err(|_| NativeRootError::Unknown)?;
    let deployment = root
        .read_raw("deployment.json", NATIVE_STATE_BYTES)
        .map_err(|_| NativeRootError::Unknown)?;
    if Sha256Digest::of_bytes(deployment.bytes()) != state.state().deployment_raw_sha256 {
        return Err(NativeRootError::Unknown);
    }
    verify_marker(root, marker, marker_bytes, pin)?;
    Ok(state)
}
pub fn create_fresh(
    parent: &PrivateRoot,
    component: &std::ffi::OsStr,
) -> Result<FreshNativeRoot, NativeRootFailure> {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        platform::create(parent, component, &|_, _| {})
    }
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    {
        let _ = (parent, component);
        Err(NativeRootFailure {
            error: NativeRootError::Unsupported,
            ownership: Box::new(Ownership::Unavailable),
        })
    }
}
pub fn reopen_native(
    root: PrivateRoot,
    writer: ConfigurationWriterGuard,
) -> Result<NativeRootBinding, NativeRootFailure> {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        platform::reopen(root, writer)
    }
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    {
        Err(NativeRootFailure {
            error: NativeRootError::Unsupported,
            ownership: Box::new(Ownership::Root { root, writer }),
        })
    }
}
#[cfg(all(target_os = "linux", target_env = "gnu"))]
mod platform {
    use super::*;
    use crate::store::{
        StoreError,
        secure_journal::{NamespaceName, files},
    };
    use styx_contracts::{
        identity::Sha256Digest, management::ReaderContract, native_management::*,
    };
    // Same thin bounded-to_writer idiom as IPC's BoundedJson. The IPC type
    // is module-private; importing a Host/IPC layer into store would invert the
    // dependency. Check before copying any serializer fragment, including a
    // caller-constructed oversized RawValue extension.
    struct GenesisJson(Vec<u8>);
    impl std::io::Write for GenesisJson {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > NATIVE_STATE_BYTES.saturating_sub(self.0.len()) {
                return Err(std::io::Error::other("native_genesis_capacity"));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    fn encode_genesis(state: &NativeState) -> Result<Vec<u8>, NativeRootError> {
        let mut output = GenesisJson(Vec::with_capacity(NATIVE_STATE_BYTES));
        serde_json::to_writer(&mut output, state).map_err(|_| NativeRootError::InvalidInput)?;
        Ok(output.0)
    }
    fn failure(
        root: PrivateRoot,
        writer: ConfigurationWriterGuard,
        error: NativeRootError,
    ) -> NativeRootFailure {
        NativeRootFailure {
            error,
            ownership: Box::new(Ownership::Root { root, writer }),
        }
    }
    pub(super) fn create(
        parent: &PrivateRoot,
        name: &std::ffi::OsStr,
        observer: &dyn Fn(&str, &str),
    ) -> Result<FreshNativeRoot, NativeRootFailure> {
        let parent_copy = || PrivateRoot {
            inner: parent.inner.clone(),
        };
        let mut entropy = [0u8; 32];
        if getrandom::fill(&mut entropy).is_err() {
            return Err(NativeRootFailure {
                error: NativeRootError::Unknown,
                ownership: Box::new(Ownership::Parent {
                    parent: parent_copy(),
                    component: name.to_owned(),
                    created: false,
                    child: None,
                }),
            });
        }
        let root = match parent.inner.create_fresh_child(name) {
            Ok(root) => PrivateRoot { inner: root },
            Err(error) => {
                let code = if !error.created
                    && matches!(&error.cause,StoreError::Io(e) if e.kind()==std::io::ErrorKind::AlreadyExists)
                {
                    NativeRootError::AlreadyExists
                } else if !error.created && matches!(&error.cause, StoreError::InvalidRelativePath)
                {
                    NativeRootError::InvalidInput
                } else {
                    NativeRootError::Unknown
                };
                return Err(NativeRootFailure {
                    error: code,
                    ownership: Box::new(Ownership::Parent {
                        parent: parent_copy(),
                        component: name.to_owned(),
                        created: error.created,
                        child: error.root.map(|inner| PrivateRoot { inner }),
                    }),
                });
            }
        };
        let writer = match root.try_configuration_writer() {
            Ok(writer) => writer,
            Err(_) => {
                return Err(NativeRootFailure {
                    error: NativeRootError::Unknown,
                    ownership: Box::new(Ownership::Parent {
                        parent: parent_copy(),
                        component: name.to_owned(),
                        created: true,
                        child: Some(root),
                    }),
                });
            }
        };
        let RootIdentity::Linux { device, inode, uid } = root.identity();
        let marker = NativeRootMarker {
            schema: NATIVE_MARKER_SCHEMA,
            kind: NativeRootKind::StyxConfigurationRoot,
            runtime_format: NativeRuntimeFormat::NativeRustV1,
            root_identity: NativeRootIdentity::Linux { device, inode, uid },
            scope_generation: Sha256Digest::from_bytes(entropy),
            reader_floor: ReaderContract::NativeManagementStateV1,
        };
        let result = (|| {
            let bytes = serde_json::to_vec(&marker).map_err(|_| NativeRootError::InvalidInput)?;
            native_state::decode_marker(&bytes).map_err(|_| NativeRootError::InvalidInput)?;
            root.inner
                .create_fixed(&writer, NATIVE_MARKER_FILE, &bytes, &|phase| {
                    observer("marker", phase)
                })
                .map_err(|_| NativeRootError::Unknown)?;
            for name in [NamespaceName::EnrollmentV1, NamespaceName::ManagementV1] {
                root.ensure_absent(name.as_str())
                    .map_err(|_| NativeRootError::Unknown)?;
            }
            root.inner
                .with_configuration_writer_directory(&writer, |directory| {
                    for name in [NamespaceName::EnrollmentV1, NamespaceName::ManagementV1] {
                        files::create_namespace(directory, name)
                            .map_err(|_| StoreError::Changed)?;
                        observer(name.as_str(), "directory_sync");
                    }
                    Ok(())
                })
                .map_err(|_| NativeRootError::Unknown)?;
            let raw = root
                .read_raw(NATIVE_MARKER_FILE, NATIVE_MARKER_BYTES)
                .map_err(|_| NativeRootError::Unknown)?;
            if raw.bytes() != bytes {
                return Err(NativeRootError::Unknown);
            }
            Ok((bytes, raw.observation().clone()))
        })();
        match result {
            Ok((marker_bytes, marker_observation)) => Ok(FreshNativeRoot {
                root,
                writer,
                marker,
                marker_bytes,
                marker_observation,
            }),
            Err(error) => Err(failure(root, writer, error)),
        }
    }
    pub(super) fn initialize(
        fresh: FreshNativeRoot,
        deployment: &[u8],
        state: &NativeState,
        observer: &dyn Fn(&str, &str),
    ) -> Result<NativeRootBinding, NativeRootFailure> {
        let FreshNativeRoot {
            root,
            writer,
            marker,
            marker_bytes,
            marker_observation,
        } = fresh;
        let result = (|| {
            if deployment.is_empty()
                || deployment.len() > NATIVE_STATE_BYTES
                || state.revision != 0
                || state.last_transaction.is_some()
                || state.deployment_raw_sha256 != Sha256Digest::of_bytes(deployment)
            {
                return Err(NativeRootError::InvalidInput);
            }
            let bytes = encode_genesis(state)?;
            native_state::decode_state(&bytes, &marker)
                .map_err(|_| NativeRootError::InvalidInput)?;
            if !same_identity(&root.identity(), &marker) {
                return Err(NativeRootError::Unknown);
            }
            // Validate the original immutable marker before the first genesis IO.
            let raw = root
                .read_raw(NATIVE_MARKER_FILE, NATIVE_MARKER_BYTES)
                .map_err(|_| NativeRootError::Unknown)?;
            if raw.bytes() != marker_bytes || raw.observation() != &marker_observation {
                return Err(NativeRootError::Unknown);
            }
            root.inner
                .create_fixed(&writer, "deployment.json", deployment, &|phase| {
                    observer("deployment", phase)
                })
                .map_err(|_| NativeRootError::Unknown)?;
            root.inner
                .create_fixed(&writer, "state.json", &bytes, &|phase| {
                    observer("state", phase)
                })
                .map_err(|_| NativeRootError::Unknown)?;
            let read = verify_read(&root, &marker, &marker_bytes, &marker_observation)?;
            if read.raw_bytes() != bytes {
                return Err(NativeRootError::Unknown);
            }
            Ok(())
        })();
        if let Err(error) = result {
            return Err(failure(root, writer, error));
        }
        bind(root, writer, marker, marker_bytes, marker_observation)
    }
    fn bind(
        root: PrivateRoot,
        writer: ConfigurationWriterGuard,
        marker: NativeRootMarker,
        marker_bytes: Vec<u8>,
        marker_observation: super::super::FileObservation,
    ) -> Result<NativeRootBinding, NativeRootFailure> {
        let owner = match OwnedConfigurationRoot::open_existing_retaining(root, writer) {
            Ok(owner) => owner,
            Err(error) => return Err(failure(error.root, error.writer, NativeRootError::Unknown)),
        };
        let binding = NativeRootBinding {
            owner,
            marker,
            marker_bytes,
            marker_observation,
        };
        if binding.validated_readstate().is_err() {
            return Err(NativeRootFailure {
                error: NativeRootError::Unknown,
                ownership: Box::new(Ownership::Configuration(binding.owner)),
            });
        }
        Ok(binding)
    }
    pub(super) fn reopen(
        root: PrivateRoot,
        writer: ConfigurationWriterGuard,
    ) -> Result<NativeRootBinding, NativeRootFailure> {
        let result = (|| {
            root.inner
                .with_configuration_writer_directory(&writer, |_| Ok(()))
                .map_err(|_| NativeRootError::Unknown)?;
            let raw = root
                .read_raw(NATIVE_MARKER_FILE, NATIVE_MARKER_BYTES)
                .map_err(|_| NativeRootError::Unknown)?;
            let marker =
                native_state::decode_marker(raw.bytes()).map_err(|_| NativeRootError::Unknown)?;
            verify_read(&root, &marker, raw.bytes(), raw.observation())?;
            Ok((marker, raw.bytes().to_vec(), raw.observation().clone()))
        })();
        match result {
            Ok((marker, bytes, pin)) => bind(root, writer, marker, bytes, pin),
            Err(error) => Err(failure(root, writer, error)),
        }
    }
}

#[cfg(test)]
#[path = "native_root_tests.rs"]
mod tests;
