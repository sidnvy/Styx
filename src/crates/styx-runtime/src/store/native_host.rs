//! Closed, one-writer native Host join storage. All bytes are DATA supplied by
//! the trusted protocol client: no remote validation, HTTP, grant or retry here.
use super::{FreshNativeRoot, NativeRootBinding, NativeRootError, NativeRootFailure, Ownership};
use crate::store::{
    FileObservation, OwnedConfigurationRoot, PrivateRoot, RawFile,
    native_state::ValidatedNativeState,
    secure_journal::{JournalError, JournalResult},
};
use styx_contracts::{
    identity::Sha256Digest,
    native_management::{NATIVE_STATE_BYTES, NativeDeploymentMode, NativeState},
};
use zeroize::Zeroizing;

const SEED: &str = "host-join-seed-v1.json";
const SEED_EXTENSION: &str = "fresh_host_seed_v1";
const MATERIALS: [(&str, usize); 3] = [
    ("host-ca.pem", 128 * 1024),
    ("host-identity.pem", 16 * 1024),
    (SEED, NATIVE_STATE_BYTES),
];
/// No Debug/Clone/Serde; the caller retains zeroizing identity custody until IO
/// is settled. This closed shape cannot select an arbitrary filesystem path.
pub(crate) struct FreshHostFiles<'a> {
    pub(crate) ca_certificate_pem: &'a [u8],
    pub(crate) private_identity_pem: &'a [u8],
    pub(crate) seed_binding: &'a [u8],
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum NativeHostJoinFile {
    JoinDispatched,
    JoinReply,
    Credential,
    ConfirmDispatched,
    Ready,
}
impl NativeHostJoinFile {
    const ALL: [Self; 5] = [
        Self::JoinDispatched,
        Self::JoinReply,
        Self::Credential,
        Self::ConfirmDispatched,
        Self::Ready,
    ];
    fn index(self) -> usize {
        match self {
            Self::JoinDispatched => 0,
            Self::JoinReply => 1,
            Self::Credential => 2,
            Self::ConfirmDispatched => 3,
            Self::Ready => 4,
        }
    }
    fn path(self) -> &'static str {
        match self {
            Self::JoinDispatched => "host-join-dispatched-v1.json",
            Self::JoinReply => "host-join-reply-v1.json",
            Self::Credential => "host-credential.token",
            Self::ConfirmDispatched => "host-confirm-dispatched-v1.json",
            Self::Ready => "host-ready-v1.json",
        }
    }
    fn max_bytes(self) -> usize {
        if self == Self::Credential {
            4096
        } else {
            NATIVE_STATE_BYTES
        }
    }
    fn valid_size(self, n: usize) -> bool {
        n >= if self == Self::Credential { 32 } else { 1 } && n <= self.max_bytes()
    }
}
struct Pin {
    observation: FileObservation,
    digest: Sha256Digest,
}
impl Pin {
    fn from_raw(raw: &RawFile) -> Self {
        Self {
            observation: raw.observation().clone(),
            digest: Sha256Digest::of_bytes(raw.bytes()),
        }
    }
    fn matches(&self, raw: &RawFile) -> bool {
        self.observation == *raw.observation() && self.digest == Sha256Digest::of_bytes(raw.bytes())
    }
}
/// Noncloneable typed port over the original configuration owner, not a second
/// journal/ledger or evidence of enrollment. No secret-bearing Debug/Serde.
pub(crate) struct NativeHostJoinStore {
    binding: NativeRootBinding,
    seed: Zeroizing<Vec<u8>>,
    materials: Vec<Pin>,
    phases: Vec<Pin>,
}
fn seed_hash(state: &NativeState) -> JournalResult<Sha256Digest> {
    if state.has_migration_binding()
        || state.mode != NativeDeploymentMode::JoinExisting
        || state.desired.gateway.is_some()
        || state.desired.host.is_none()
    {
        return Err(JournalError::Unknown);
    }
    let raw = state
        .extensions
        .get(SEED_EXTENSION)
        .ok_or(JournalError::Unknown)?;
    serde_json::from_str(raw.get()).map_err(|_| JournalError::Unknown)
}
fn optional(root: &PrivateRoot, file: NativeHostJoinFile) -> JournalResult<Option<RawFile>> {
    match root.read_raw(file.path(), file.max_bytes()) {
        Ok(raw) => {
            if file.valid_size(raw.bytes().len()) {
                Ok(Some(raw))
            } else {
                Err(JournalError::Unknown)
            }
        }
        Err(crate::store::StoreError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            root.ensure_absent(file.path())
                .map_err(|_| JournalError::Unknown)?;
            Ok(None)
        }
        Err(_) => Err(JournalError::Unknown),
    }
}
impl FreshNativeRoot {
    pub(crate) fn initialize_host_pending(
        self,
        deployment: &[u8],
        state: &NativeState,
        material: FreshHostFiles<'_>,
        trusted_now_unix_seconds: u64,
    ) -> Result<NativeHostJoinStore, NativeRootFailure> {
        #[cfg(any(
            target_os = "windows",
            target_os = "macos",
            all(target_os = "linux", target_env = "gnu")
        ))]
        {
            initialize(self, deployment, state, material, trusted_now_unix_seconds)
        }
        #[cfg(not(any(
            target_os = "windows",
            target_os = "macos",
            all(target_os = "linux", target_env = "gnu")
        )))]
        {
            let _ = (deployment, state, material, trusted_now_unix_seconds);
            Err(NativeRootFailure {
                error: NativeRootError::Unsupported,
                ownership: Box::new(Ownership::Root {
                    root: self.root,
                    writer: Box::new(self.writer),
                }),
            })
        }
    }
}
#[cfg(any(
    target_os = "windows",
    target_os = "macos",
    all(target_os = "linux", target_env = "gnu")
))]
fn initialize(
    mut fresh: FreshNativeRoot,
    deployment: &[u8],
    state: &NativeState,
    material: FreshHostFiles<'_>,
    now: u64,
) -> Result<NativeHostJoinStore, NativeRootFailure> {
    use crate::store::enrollment::{EnrollmentJournal, JournalBudget};
    let values = [
        material.ca_certificate_pem,
        material.private_identity_pem,
        material.seed_binding,
    ];
    let preflight = (|| {
        if now == 0
            || deployment.is_empty()
            || deployment.len() > NATIVE_STATE_BYTES
            || state.revision != 0
            || state.last_transaction.is_some()
            || state.deployment_raw_sha256 != Sha256Digest::of_bytes(deployment)
            || seed_hash(state).ok() != Some(Sha256Digest::of_bytes(material.seed_binding))
            || values
                .iter()
                .zip(MATERIALS)
                .any(|(v, (_, max))| v.is_empty() || v.len() > max)
        {
            return Err(NativeRootError::InvalidInput);
        }
        let clock = i64::try_from(now).map_err(|_| NativeRootError::InvalidInput)?;
        time::OffsetDateTime::from_unix_timestamp(clock)
            .map_err(|_| NativeRootError::InvalidInput)?;
        let floor = now.checked_mul(1000).ok_or(NativeRootError::InvalidInput)?;
        let raw = super::platform::encode_genesis(state)?;
        crate::store::native_state::decode_state(&raw, &fresh.marker)
            .map_err(|_| NativeRootError::InvalidInput)?;
        Ok(floor)
    })();
    let floor = match preflight {
        Ok(floor) => floor,
        Err(error) => {
            return Err(NativeRootFailure {
                error,
                ownership: Box::new(Ownership::Root {
                    root: fresh.root,
                    writer: Box::new(fresh.writer),
                }),
            });
        }
    };
    let persisted = (|| {
        super::verify_marker(
            &fresh.root,
            &fresh.marker,
            &fresh.marker_bytes,
            &fresh.marker_observation,
        )
        .map_err(|_| JournalError::Unknown)?;
        for name in MATERIALS
            .iter()
            .map(|(n, _)| *n)
            .chain(NativeHostJoinFile::ALL.map(NativeHostJoinFile::path))
            .chain(["deployment.json", "state.json"])
        {
            fresh
                .root
                .ensure_absent(name)
                .map_err(|_| JournalError::Unknown)?
        }
        let mut pins = Vec::with_capacity(3);
        for ((name, max), bytes) in MATERIALS.iter().zip(values) {
            fresh
                .root
                .inner
                .create_fixed(&fresh.writer, name, bytes, &|_| {})
                .map_err(|_| JournalError::Unknown)?;
            let raw = fresh
                .root
                .read_raw(name, *max)
                .map_err(|_| JournalError::Unknown)?;
            if raw.bytes() != bytes {
                return Err(JournalError::Unknown);
            }
            pins.push(Pin::from_raw(&raw));
        }
        {
            let mut journal = EnrollmentJournal::open_existing(
                &fresh.root,
                &mut fresh.writer,
                JournalBudget::default(),
            )?;
            if !journal.scan()?.files.is_empty() {
                return Err(JournalError::Unknown);
            }
            journal.record_time_floor(floor)?;
            if journal.read_time_floor()? != Some(floor) {
                return Err(JournalError::Unknown);
            }
        }
        Ok(pins)
    })();
    let pins = match persisted {
        Ok(pins) => pins,
        Err(_) => {
            return Err(NativeRootFailure {
                error: NativeRootError::Unknown,
                ownership: Box::new(Ownership::Root {
                    root: fresh.root,
                    writer: Box::new(fresh.writer),
                }),
            });
        }
    };
    let binding = super::platform::initialize(fresh, deployment, state, &|_, _| {})?;
    let store = NativeHostJoinStore::from_binding(binding)?;
    let checked = store.binding.with_binding(|configuration, _| {
        for (((name, max), bytes), pin) in MATERIALS.iter().zip(values).zip(&pins) {
            let raw = configuration
                .root
                .read_raw(name, *max)
                .map_err(|_| JournalError::Unknown)?;
            if !pin.matches(&raw) || raw.bytes() != bytes {
                return Err(JournalError::Unknown);
            }
        }
        Ok(())
    });
    if checked.is_err() {
        return Err(NativeRootFailure {
            error: NativeRootError::Unknown,
            ownership: Box::new(Ownership::Configuration(store.binding.owner)),
        });
    }
    Ok(store)
}
impl NativeHostJoinStore {
    pub(crate) fn from_binding(binding: NativeRootBinding) -> Result<Self, NativeRootFailure> {
        #[cfg(any(
            target_os = "windows",
            target_os = "macos",
            all(target_os = "linux", target_env = "gnu")
        ))]
        {
            let captured = binding.with_binding(|configuration, _| {
                let state = binding.read_locked(configuration)?;
                let expected = seed_hash(state.state())?;
                let mut materials = Vec::with_capacity(3);
                let mut seed = None;
                for (name, max) in MATERIALS {
                    let raw = configuration
                        .root
                        .read_raw(name, max)
                        .map_err(|_| JournalError::Unknown)?;
                    if raw.bytes().is_empty() {
                        return Err(JournalError::Unknown);
                    };
                    materials.push(Pin::from_raw(&raw));
                    if name == SEED {
                        if Sha256Digest::of_bytes(raw.bytes()) != expected {
                            return Err(JournalError::Unknown);
                        };
                        seed = Some(Zeroizing::new(raw.bytes));
                    }
                }
                let mut phases = Vec::with_capacity(5);
                let mut missing = false;
                for file in NativeHostJoinFile::ALL {
                    match optional(&configuration.root, file)? {
                        Some(raw) if !missing => phases.push(Pin::from_raw(&raw)),
                        Some(_) => return Err(JournalError::Unknown),
                        None => missing = true,
                    }
                }
                Ok((materials, seed.ok_or(JournalError::Unknown)?, phases))
            });
            match captured {
                Ok((materials, seed, phases)) => Ok(Self {
                    binding,
                    seed,
                    materials,
                    phases,
                }),
                Err(_) => Err(NativeRootFailure {
                    error: NativeRootError::Unknown,
                    ownership: Box::new(Ownership::Configuration(binding.owner)),
                }),
            }
        }
        #[cfg(not(any(
            target_os = "windows",
            target_os = "macos",
            all(target_os = "linux", target_env = "gnu")
        )))]
        {
            Err(NativeRootFailure {
                error: NativeRootError::Unsupported,
                ownership: Box::new(Ownership::Configuration(binding.owner)),
            })
        }
    }
    pub(crate) fn configuration_root(&self) -> OwnedConfigurationRoot {
        self.binding.configuration_root()
    }
    fn validate_base_locked(
        &self,
        configuration: &crate::store::configuration::ConfigurationState,
    ) -> JournalResult<ValidatedNativeState> {
        let state = self.binding.read_locked(configuration)?;
        // Original namespace parsing under the same configuration owner. This
        // observes complete history, never repairs or advances an unresolved tip.
        configuration
            .root
            .inner
            .with_configuration_writer_directory(&configuration.writer, |directory| {
                Ok((|| {
                    let namespace = crate::store::secure_journal::files::directory(
                        directory,
                        ".styx-management-journal-v1",
                    )?;
                    let scan = crate::store::secure_journal::files::scan(
                        &namespace,
                        crate::store::secure_journal::JournalBudget::default(),
                    )?;
                    crate::store::management::validate_readonly_native_tip(
                        &scan,
                        &state,
                        self.binding.marker(),
                    )
                })())
            })
            .map_err(|_| JournalError::Unknown)??;
        if seed_hash(state.state())? != Sha256Digest::of_bytes(&self.seed) {
            return Err(JournalError::Unknown);
        }
        for ((name, max), pin) in MATERIALS.iter().zip(&self.materials) {
            let raw = configuration
                .root
                .read_raw(name, *max)
                .map_err(|_| JournalError::Unknown)?;
            if !pin.matches(&raw) {
                return Err(JournalError::Unknown);
            }
        }
        Ok(state)
    }
    fn validate_locked(
        &self,
        configuration: &crate::store::configuration::ConfigurationState,
    ) -> JournalResult<ValidatedNativeState> {
        let state = self.validate_base_locked(configuration)?;
        for file in NativeHostJoinFile::ALL {
            match (
                optional(&configuration.root, file)?,
                self.phases.get(file.index()),
            ) {
                (Some(raw), Some(pin)) if pin.matches(&raw) => {}
                (None, None) => {}
                _ => return Err(JournalError::Unknown),
            }
        }
        Ok(state)
    }
    pub(crate) fn readstate(&self) -> JournalResult<ValidatedNativeState> {
        self.binding
            .with_binding(|configuration, _| self.validate_locked(configuration))
    }
    /// Revalidated before returning. These borrowed cached bytes are data, not a
    /// promise of future filesystem stability or an enrollment capability.
    pub(crate) fn seed_binding(&self) -> JournalResult<&[u8]> {
        self.readstate()?;
        Ok(&self.seed)
    }
    pub(crate) fn read(
        &self,
        file: NativeHostJoinFile,
    ) -> JournalResult<Option<Zeroizing<Vec<u8>>>> {
        self.binding.with_binding(|configuration, _| {
            self.validate_locked(configuration)?;
            let raw = optional(&configuration.root, file)?;
            Ok(raw.map(|raw| Zeroizing::new(raw.bytes)))
        })
    }
    pub(crate) fn append(&mut self, file: NativeHostJoinFile, bytes: &[u8]) -> JournalResult<()> {
        if !file.valid_size(bytes.len()) {
            return Err(JournalError::InvalidInput);
        }
        #[cfg(any(
            target_os = "windows",
            target_os = "macos",
            all(target_os = "linux", target_env = "gnu")
        ))]
        {
            let pin = self.binding.with_binding(|configuration, _| {
                self.validate_locked(configuration)?;
                if file.index() != self.phases.len() {
                    return Err(JournalError::Conflict);
                }
                configuration
                    .root
                    .ensure_absent(file.path())
                    .map_err(|_| JournalError::Unknown)?;
                configuration
                    .root
                    .inner
                    .create_fixed(&configuration.writer, file.path(), bytes, &|_| {})
                    .map_err(|_| JournalError::Unknown)?;
                let raw = configuration
                    .root
                    .read_raw(file.path(), file.max_bytes())
                    .map_err(|_| JournalError::Unknown)?;
                if raw.bytes() != bytes {
                    return Err(JournalError::Unknown);
                }
                let new_pin = Pin::from_raw(&raw);
                self.validate_base_locked(configuration)?;
                for observed_file in NativeHostJoinFile::ALL {
                    let expected = if observed_file == file {
                        Some(&new_pin)
                    } else {
                        self.phases.get(observed_file.index())
                    };
                    match (optional(&configuration.root, observed_file)?, expected) {
                        (Some(raw), Some(pin)) if pin.matches(&raw) => {}
                        (None, None) => {}
                        _ => return Err(JournalError::Unknown),
                    }
                }
                Ok(new_pin)
            })?;
            self.phases.push(pin);
            Ok(())
        }
        #[cfg(not(any(
            target_os = "windows",
            target_os = "macos",
            all(target_os = "linux", target_env = "gnu")
        )))]
        {
            let _ = (file, bytes);
            Err(JournalError::Unsupported)
        }
    }
}
#[cfg(test)]
#[path = "native_host_tests.rs"]
mod tests;
