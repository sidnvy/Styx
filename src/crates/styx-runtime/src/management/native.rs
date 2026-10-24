//! Offline native configuration commands shared by CLI/future Control clients.
//! No service/runtime activation, pairing, legacy adoption or implicit pending
//! transaction recovery. Blocking jobs keep their bounded permit after waiter loss.
use crate::store::{
    native_root::{NativeRootError, NativeRootFailure},
    native_transaction::{
        NativeTransactionError, NativeTransactionOpenFailure, NativeTransactions,
    },
};
use serde::Serialize;
use std::{
    ffi::OsStr,
    fmt,
    path::{Path, PathBuf},
};
use styx_contracts::{
    identity::{Sha256Digest, TransactionId},
    management::{DurableStage, JournalReceipt},
    native_management::*,
};

pub struct NativeCreateOptions {
    pub mode: NativeDeploymentMode,
    pub manager: NativeManager,
    pub host: bool,
    pub gateway: bool,
}
#[derive(Clone, Copy)]
pub enum NativeComponent {
    Host,
    Gateway,
}
pub struct NativeDesiredChange {
    pub component: NativeComponent,
    pub run: NativeRunDesired,
    pub transaction_id: TransactionId,
    pub sequence: u64,
}
#[derive(Debug, Serialize)]
pub struct NativeTransactionReport {
    pub transaction_id: TransactionId,
    pub sequence: u64,
    pub observed_stage: Option<DurableStage>,
    pub receipt: Option<JournalReceipt>,
    pub recovered: bool,
}
#[derive(Debug, Serialize)]
pub struct NativeManagementReport {
    pub schema: u16,
    pub configuration_only: bool,
    pub operation: &'static str,
    pub runtime_health: &'static str,
    pub revision: u64,
    pub canonical_state_sha256: Sha256Digest,
    pub desired: NativeDesired,
    pub admission_fenced: bool,
    pub transaction: Option<NativeTransactionReport>,
}
/// Redacted review output. The stored private DTO contains the opaque target;
/// this public result deliberately does not serialize it or unknown extensions.
#[derive(Debug, Serialize)]
pub struct NativeManagementPlan {
    pub schema: u16,
    pub configuration_only: bool,
    pub runtime_health: &'static str,
    pub plan_file: PathBuf,
    pub plan_sha256: Sha256Digest,
    pub transaction_id: TransactionId,
    pub sequence: u64,
    pub before_state_sha256: Sha256Digest,
    pub target_state_sha256: Sha256Digest,
    pub before_desired: NativeDesired,
    pub target_desired: NativeDesired,
}
#[derive(Clone, Copy)]
enum ErrorKind {
    Invalid,
    Conflict,
    Unavailable,
    Unsupported,
    Unknown,
    Busy,
}
/// Error ownership is intentional: inspecting/printing a curated code must not
/// silently discard an unresolved bootstrap/coordinator. No background registry.
pub struct NativeManagementError {
    kind: ErrorKind,
    _retained: Option<Retained>,
}
enum Retained {
    Bootstrap {
        _owner: NativeRootFailure,
    },
    Open {
        _owner: NativeTransactionOpenFailure,
    },
    Transactions {
        _owner: Box<NativeTransactions>,
    },
}
impl NativeManagementError {
    pub fn code(&self) -> &'static str {
        match self.kind {
            ErrorKind::Invalid => "native_management_invalid_input",
            ErrorKind::Conflict => "native_management_conflict",
            ErrorKind::Unavailable => "native_management_unavailable",
            ErrorKind::Unsupported => "native_management_unsupported",
            ErrorKind::Unknown => "native_management_unknown_inspect",
            ErrorKind::Busy => "native_management_busy",
        }
    }
    pub fn exit_code(&self) -> u8 {
        match self.kind {
            ErrorKind::Invalid | ErrorKind::Conflict => 2,
            ErrorKind::Unavailable | ErrorKind::Unsupported | ErrorKind::Busy => 3,
            ErrorKind::Unknown => 4,
        }
    }
    fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            _retained: None,
        }
    }
    fn transaction(error: NativeTransactionError) -> Self {
        Self::new(match error {
            NativeTransactionError::InvalidInput => ErrorKind::Invalid,
            NativeTransactionError::Conflict => ErrorKind::Conflict,
            NativeTransactionError::UnknownInspect => ErrorKind::Unknown,
            NativeTransactionError::Unsupported => ErrorKind::Unsupported,
        })
    }
    fn keep(mut self, transactions: NativeTransactions) -> Self {
        self._retained = Some(Retained::Transactions {
            _owner: Box::new(transactions),
        });
        self
    }
    fn bootstrap(error: NativeRootFailure) -> Self {
        let kind = match error.error() {
            NativeRootError::Unsupported => ErrorKind::Unsupported,
            NativeRootError::InvalidInput => ErrorKind::Invalid,
            NativeRootError::AlreadyExists => ErrorKind::Conflict,
            NativeRootError::Unknown => ErrorKind::Unknown,
        };
        Self {
            kind,
            _retained: Some(Retained::Bootstrap { _owner: error }),
        }
    }
    fn open(error: NativeTransactionOpenFailure) -> Self {
        let kind = Self::transaction(error.error()).kind;
        Self {
            kind,
            _retained: Some(Retained::Open { _owner: error }),
        }
    }
}
impl fmt::Debug for NativeManagementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeManagementError")
            .field("code", &self.code())
            .finish_non_exhaustive()
    }
}
impl fmt::Display for NativeManagementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for NativeManagementError {}
type Result<T> = std::result::Result<T, NativeManagementError>;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
static WORKERS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);
async fn blocking<T: Send + 'static>(
    job: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        let permit = WORKERS
            .try_acquire()
            .map_err(|_| NativeManagementError::new(ErrorKind::Busy))?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            job()
        })
        .await
        .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?
    }
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    {
        let _ = job;
        Err(NativeManagementError::new(ErrorKind::Unsupported))
    }
}
pub async fn initialize(
    parent_dir: &Path,
    name: &OsStr,
    deployment_file: &Path,
    options: NativeCreateOptions,
) -> Result<NativeManagementReport> {
    let parent = parent_dir.to_owned();
    let name = name.to_owned();
    let deployment = deployment_file.to_owned();
    blocking(move || platform::initialize(&parent, &name, &deployment, options)).await
}
pub async fn plan(state_dir: &Path, change: NativeDesiredChange) -> Result<NativeManagementPlan> {
    let path = state_dir.to_owned();
    blocking(move || platform::plan(&path, change)).await
}
pub async fn apply(state_dir: &Path, plan_file: &Path) -> Result<NativeManagementReport> {
    let path = state_dir.to_owned();
    let plan = plan_file.to_owned();
    blocking(move || platform::apply(&path, &plan)).await
}
fn parse_transaction_id(value: &str) -> Result<TransactionId> {
    if !cfg!(all(target_os = "linux", target_env = "gnu")) {
        return Err(NativeManagementError::new(ErrorKind::Unsupported));
    }
    if value.len() > 128 {
        return Err(NativeManagementError::new(ErrorKind::Invalid));
    }
    TransactionId::try_from(value).map_err(|_| NativeManagementError::new(ErrorKind::Invalid))
}
pub async fn recover(state_dir: &Path, transaction_id: &str) -> Result<NativeManagementReport> {
    let path = state_dir.to_owned();
    let id = parse_transaction_id(transaction_id)?;
    blocking(move || platform::recover(&path, &id)).await
}
pub async fn inspect(
    state_dir: &Path,
    transaction_id: Option<&str>,
) -> Result<NativeManagementReport> {
    let path = state_dir.to_owned();
    let id = transaction_id.map(parse_transaction_id).transpose()?;
    blocking(move || platform::inspect(&path, id.as_ref())).await
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
mod platform {
    use super::*;
    use crate::store::{PrivateRoot, RawFile, StoreError, native_root, native_state};
    use std::{collections::BTreeMap, io::Write};
    fn store(error: StoreError) -> NativeManagementError {
        NativeManagementError::new(match error {
            StoreError::Unsupported => ErrorKind::Unsupported,
            StoreError::Busy(_) => ErrorKind::Busy,
            StoreError::InvalidRoot
            | StoreError::InvalidRelativePath
            | StoreError::NotPrivate
            | StoreError::NotRegularFile
            | StoreError::TooLarge => ErrorKind::Invalid,
            StoreError::Io(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                ) =>
            {
                ErrorKind::Unavailable
            }
            _ => ErrorKind::Unknown,
        })
    }
    fn private_file(path: &Path, limit: usize) -> Result<RawFile> {
        if !path.is_absolute() {
            return Err(NativeManagementError::new(ErrorKind::Invalid));
        }
        let parent = path
            .parent()
            .ok_or_else(|| NativeManagementError::new(ErrorKind::Invalid))?;
        let name = path
            .file_name()
            .ok_or_else(|| NativeManagementError::new(ErrorKind::Invalid))?;
        PrivateRoot::open(parent)
            .map_err(store)?
            .read_raw(Path::new(name), limit)
            .map_err(store)
    }
    fn open(path: &Path) -> Result<NativeTransactions> {
        let root = PrivateRoot::open(path).map_err(store)?;
        // Read-only format check before existing-lock acquisition. A missing
        // original lock is refused, never repaired while opening/querying.
        let raw = root
            .read_raw(native_root::NATIVE_MARKER_FILE, NATIVE_MARKER_BYTES)
            .map_err(store)?;
        let marker = native_state::decode_marker(raw.bytes())
            .map_err(|_| NativeManagementError::new(ErrorKind::Invalid))?;
        let crate::store::RootIdentity::Linux { device, inode, uid } = root.identity();
        if marker.root_identity != (NativeRootIdentity::Linux { device, inode, uid }) {
            return Err(NativeManagementError::new(ErrorKind::Conflict));
        }
        let writer = root.try_existing_configuration_writer().map_err(store)?;
        let binding =
            native_root::reopen_native(root, writer).map_err(NativeManagementError::bootstrap)?;
        NativeTransactions::open(binding).map_err(NativeManagementError::open)
    }
    fn use_transactions<T>(
        path: &Path,
        job: impl FnOnce(&mut NativeTransactions) -> Result<T>,
    ) -> Result<T> {
        let mut transactions = open(path)?;
        match job(&mut transactions) {
            Ok(value) => Ok(value),
            Err(error) => Err(error.keep(transactions)),
        }
    }
    fn tx(error: NativeTransactionError) -> NativeManagementError {
        NativeManagementError::transaction(error)
    }
    fn admission(transactions: &NativeTransactions) -> Result<bool> {
        use crate::store::enrollment::JournalError;
        match transactions.configuration_root().ensure_admission() {
            Ok(()) => Ok(false),
            Err(JournalError::Conflict) => Ok(true),
            Err(JournalError::Unsupported) => {
                Err(NativeManagementError::new(ErrorKind::Unsupported))
            }
            Err(_) => Err(NativeManagementError::new(ErrorKind::Unknown)),
        }
    }
    fn report(
        transactions: &NativeTransactions,
        operation: &'static str,
        transaction: Option<NativeTransactionReport>,
    ) -> Result<NativeManagementReport> {
        let state = transactions.readstate().map_err(tx)?;
        Ok(NativeManagementReport {
            schema: 1,
            configuration_only: true,
            operation,
            runtime_health: "not_observed",
            revision: state.state().revision,
            canonical_state_sha256: state.raw_sha256(),
            desired: state.state().desired.clone(),
            admission_fenced: admission(transactions)?,
            transaction,
        })
    }
    fn observed(
        transactions: &NativeTransactions,
        id: &TransactionId,
    ) -> Result<NativeTransactionReport> {
        let observation = transactions
            .query(id)
            .map_err(tx)?
            .ok_or_else(|| NativeManagementError::new(ErrorKind::Conflict))?;
        let observed_stage = observation
            .phase_receipts
            .last()
            .map(|receipt| receipt.stage)
            .or_else(|| {
                observation
                    .prepared
                    .as_ref()
                    .map(|prepared| prepared.journal.stage)
            });
        Ok(NativeTransactionReport {
            transaction_id: id.clone(),
            sequence: observation.intent.sequence,
            observed_stage,
            receipt: None,
            recovered: false,
        })
    }
    /// Only re-establish an already complete canonical tip. Never complete a
    /// pending phase, adopt an orphan or replay an action as an implicit startup.
    fn reconcile_complete_tip(transactions: &mut NativeTransactions) -> Result<()> {
        if !admission(transactions)? {
            return Ok(());
        }
        let state = transactions.readstate().map_err(tx)?;
        let Some(last) = &state.state().last_transaction else {
            return Err(NativeManagementError::new(ErrorKind::Conflict));
        };
        let id = last.transaction_id.clone();
        let original = transactions
            .query(&id)
            .map_err(tx)?
            .ok_or_else(|| NativeManagementError::new(ErrorKind::Conflict))?;
        if original
            .phase_receipts
            .last()
            .is_none_or(|r| r.stage != DurableStage::Committed)
        {
            return Err(NativeManagementError::new(ErrorKind::Conflict));
        }
        transactions.recover_original(&id).map_err(tx)?;
        if admission(transactions)? {
            return Err(NativeManagementError::new(ErrorKind::Conflict));
        }
        Ok(())
    }
    struct BoundedJson {
        bytes: Vec<u8>,
        limit: usize,
    }
    impl Write for BoundedJson {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
                return Err(std::io::Error::other("native_management_capacity"));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    fn encode(value: &impl Serialize, limit: usize) -> Result<Vec<u8>> {
        let mut output = BoundedJson {
            bytes: Vec::with_capacity(limit),
            limit,
        };
        serde_json::to_writer(&mut output, value)
            .map_err(|_| NativeManagementError::new(ErrorKind::Invalid))?;
        Ok(output.bytes)
    }
    fn validate_deployment(bytes: &[u8], options: &NativeCreateOptions) -> Result<()> {
        let deployment: super::super::Deployment = super::super::decode(bytes)
            .map_err(|_| NativeManagementError::new(ErrorKind::Invalid))?;
        let local = options.mode == NativeDeploymentMode::CreateLocal;
        if deployment.schema != 1
            || deployment.mode
                != if local {
                    "create-local"
                } else {
                    "join-existing"
                }
            || options.gateway != local
            || options.host != deployment.host.is_some()
            || !options.host && !options.gateway
            || deployment.host.is_none() && (!local || deployment.gateway.runtime.is_none())
            || deployment.host.is_none()
                && (deployment.pairing_mode.is_some() || deployment.invitation_file.is_some())
            || !local
                && (deployment.gateway.runtime.is_some()
                    || deployment.gateway.device_ingress.is_some()
                    || deployment.gateway.listen_host.is_some()
                    || deployment.gateway.openssl.is_some()
                    || deployment.gateway.openssl_config.is_some()
                    || deployment.gateway.allow_remote_hosts.is_some()
                    || deployment.pairing_mode.as_deref() == Some("owner-local"))
            || deployment
                .pairing_mode
                .as_deref()
                .is_some_and(|mode| !matches!(mode, "manual" | "owner-local"))
            || local && deployment.invitation_file.is_some()
            || deployment
                .gateway
                .device_ingress
                .as_ref()
                .is_some_and(|ingress| ingress.schema != 1)
        {
            return Err(NativeManagementError::new(ErrorKind::Invalid));
        }
        let url = url::Url::parse(&deployment.gateway.url)
            .map_err(|_| NativeManagementError::new(ErrorKind::Invalid))?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
        {
            return Err(NativeManagementError::new(ErrorKind::Invalid));
        }
        Ok(())
    }
    pub(super) fn initialize(
        parent: &Path,
        name: &OsStr,
        deployment_file: &Path,
        options: NativeCreateOptions,
    ) -> Result<NativeManagementReport> {
        let deployment = private_file(deployment_file, NATIVE_STATE_BYTES)?;
        validate_deployment(deployment.bytes(), &options)?;
        let parent = PrivateRoot::open(parent).map_err(store)?;
        let fresh =
            native_root::create_fresh(&parent, name).map_err(NativeManagementError::bootstrap)?;
        let component = NativeComponentDesired {
            manager: options.manager,
            run: NativeRunDesired::Stopped,
            autostart: NativeAutostartDesired::Disabled,
        };
        let state = NativeState {
            schema: NATIVE_STATE_SCHEMA,
            kind: NativeStateKind::StyxDesiredState,
            runtime_format: NativeRuntimeFormat::NativeRustV1,
            reader_contract: fresh.marker().reader_floor,
            scope_generation: fresh.marker().scope_generation,
            deployment_raw_sha256: Sha256Digest::of_bytes(deployment.bytes()),
            mode: options.mode,
            revision: 0,
            last_transaction: None,
            desired: NativeDesired {
                gateway: options.gateway.then_some(component),
                host: options.host.then_some(component),
            },
            migration: None,
            extensions: BTreeMap::new(),
        };
        let binding = fresh
            .initialize(deployment.bytes(), &state)
            .map_err(NativeManagementError::bootstrap)?;
        let transactions =
            NativeTransactions::open(binding).map_err(NativeManagementError::open)?;
        match report(&transactions, "initialize", None) {
            Ok(value) => Ok(value),
            Err(error) => Err(error.keep(transactions)),
        }
    }
    pub(super) fn plan(path: &Path, change: NativeDesiredChange) -> Result<NativeManagementPlan> {
        use_transactions(path, |transactions| {
            reconcile_complete_tip(transactions)?;
            let before = transactions.readstate().map_err(tx)?;
            let mut target = before.state().clone();
            let component = match change.component {
                NativeComponent::Host => target.desired.host.as_mut(),
                NativeComponent::Gateway => target.desired.gateway.as_mut(),
            }
            .ok_or_else(|| NativeManagementError::new(ErrorKind::Invalid))?;
            component.run = change.run;
            target.revision = target
                .revision
                .checked_add(1)
                .ok_or_else(|| NativeManagementError::new(ErrorKind::Invalid))?;
            target.last_transaction = Some(NativeStateTransaction {
                transaction_id: change.transaction_id.clone(),
                sequence: change.sequence,
            });
            let target_bytes = encode(&target, NATIVE_STATE_BYTES)?;
            let intent = transactions.validate_target(&target_bytes).map_err(tx)?;
            let target_raw = serde_json::value::RawValue::from_string(
                String::from_utf8(target_bytes)
                    .map_err(|_| NativeManagementError::new(ErrorKind::Invalid))?,
            )
            .map_err(|_| NativeManagementError::new(ErrorKind::Invalid))?;
            let plan = NativeConfigurationPlan {
                schema: 1,
                scope_generation: transactions.marker().scope_generation,
                root_identity: transactions.marker().root_identity.clone(),
                intent,
                target: target_raw,
            };
            let bytes = encode(&plan, NATIVE_STATE_BYTES)?;
            let filename = transactions
                .save_plan(&change.transaction_id, &bytes)
                .map_err(tx)?;
            Ok(NativeManagementPlan {
                schema: 1,
                configuration_only: true,
                runtime_health: "not_observed",
                plan_file: path.join(filename),
                plan_sha256: Sha256Digest::of_bytes(&bytes),
                transaction_id: change.transaction_id,
                sequence: change.sequence,
                before_state_sha256: plan.intent.before_state_sha256,
                target_state_sha256: plan.intent.target_state_sha256,
                before_desired: before.state().desired.clone(),
                target_desired: target.desired,
            })
        })
    }
    pub(super) fn apply(path: &Path, plan_file: &Path) -> Result<NativeManagementReport> {
        let raw = private_file(plan_file, 2 * NATIVE_STATE_BYTES)?;
        let plan: NativeConfigurationPlan = serde_json::from_slice(raw.bytes())
            .map_err(|_| NativeManagementError::new(ErrorKind::Invalid))?;
        use_transactions(path, |transactions| {
            reconcile_complete_tip(transactions)?;
            let before = transactions.readstate().map_err(tx)?;
            if plan.schema != 1
                || plan.scope_generation != transactions.marker().scope_generation
                || plan.root_identity != transactions.marker().root_identity
                || plan.intent.before_state_sha256 != before.raw_sha256()
                || Sha256Digest::of_bytes(plan.target.get().as_bytes())
                    != plan.intent.target_state_sha256
            {
                return Err(NativeManagementError::new(ErrorKind::Conflict));
            }
            if transactions
                .validate_target(plan.target.get().as_bytes())
                .map_err(tx)?
                != plan.intent
            {
                return Err(NativeManagementError::new(ErrorKind::Conflict));
            }
            let committed = transactions
                .apply_target(plan.target.get().as_bytes())
                .map_err(tx)?;
            let transaction = NativeTransactionReport {
                transaction_id: committed.transaction_id,
                sequence: committed.committed.sequence,
                observed_stage: Some(DurableStage::Committed),
                receipt: Some(committed.committed),
                recovered: committed.recovered,
            };
            report(transactions, "apply", Some(transaction))
        })
    }
    pub(super) fn recover(path: &Path, id: &TransactionId) -> Result<NativeManagementReport> {
        use_transactions(path, |transactions| {
            let committed = transactions.recover_original(id).map_err(tx)?;
            let transaction = NativeTransactionReport {
                transaction_id: committed.transaction_id,
                sequence: committed.committed.sequence,
                observed_stage: Some(DurableStage::Committed),
                receipt: Some(committed.committed),
                recovered: committed.recovered,
            };
            report(transactions, "recover", Some(transaction))
        })
    }
    pub(super) fn inspect(
        path: &Path,
        id: Option<&TransactionId>,
    ) -> Result<NativeManagementReport> {
        use_transactions(path, |transactions| {
            let transaction = id.map(|id| observed(transactions, id)).transpose()?;
            report(transactions, "inspect", transaction)
        })
    }
}
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
mod platform {
    use super::*;
    pub(super) fn initialize(
        _: &Path,
        _: &OsStr,
        _: &Path,
        _: NativeCreateOptions,
    ) -> Result<NativeManagementReport> {
        Err(NativeManagementError::new(ErrorKind::Unsupported))
    }
    pub(super) fn plan(_: &Path, _: NativeDesiredChange) -> Result<NativeManagementPlan> {
        Err(NativeManagementError::new(ErrorKind::Unsupported))
    }
    pub(super) fn apply(_: &Path, _: &Path) -> Result<NativeManagementReport> {
        Err(NativeManagementError::new(ErrorKind::Unsupported))
    }
    pub(super) fn recover(_: &Path, _: &TransactionId) -> Result<NativeManagementReport> {
        Err(NativeManagementError::new(ErrorKind::Unsupported))
    }
    pub(super) fn inspect(_: &Path, _: Option<&TransactionId>) -> Result<NativeManagementReport> {
        Err(NativeManagementError::new(ErrorKind::Unsupported))
    }
}
