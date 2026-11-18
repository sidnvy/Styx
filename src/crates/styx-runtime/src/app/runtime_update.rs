//! App-owned immutable inputs and the original per-role C07 transactions.
//! This input is not a progress ledger: all phase decisions come from C07.
use super::*;
use crate::store::RawFile;
use styx_contracts::{
    identity::{Sha256Digest, TransactionId},
    management::DurableStage,
    native_management::NativeRuntimeSelection,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RoleInput {
    pub(super) gateway: bool,
    pub(super) root_sha256: Sha256Digest,
    before_sha256: Sha256Digest,
    previous: NativeRuntimeSelection,
    stop_transaction: TransactionId,
    stop_sequence: u64,
    stop_required: bool,
    pub(super) select_transaction: TransactionId,
    pub(super) select_sequence: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OriginalInput {
    schema: u16,
    transaction_id: TransactionId,
    pub(super) container_sha256: Sha256Digest,
    pub(super) selection_file: String,
    pub(super) selection_sha256: Sha256Digest,
    pub(super) selection: NativeRuntimeSelection,
    pub(super) roles: Vec<RoleInput>,
}
impl OriginalInput {
    pub(super) fn validate_shape(&self, id: &TransactionId) -> Result<(), AppError> {
        if self.schema != 1
            || &self.transaction_id != id
            || self.roles.is_empty()
            || self.roles.len() > 2
            || self.roles[0].gateway
            || self.roles.get(1).is_some_and(|r| !r.gateway)
            || self.selection_file.contains('/')
            || self.selection_file.contains('\\')
            || self.selection_file != format!("{}.json", self.selection_sha256.to_hex())
        {
            return Err(AppError("app_runtime_original_input_invalid"));
        }
        for role in &self.roles {
            let suffix = if role.gateway { "gateway" } else { "host" };
            if role.stop_sequence == 0
                || role.stop_transaction.as_str() != format!("{}-{suffix}-stop", id.as_str())
                || role.select_transaction.as_str() != format!("{}-{suffix}-select", id.as_str())
                || role
                    .stop_sequence
                    .checked_add(u64::from(role.stop_required))
                    != Some(role.select_sequence)
                || role.previous.publisher_spki_sha256 != self.selection.publisher_spki_sha256
            {
                return Err(AppError("app_runtime_original_input_invalid"));
            }
        }
        Ok(())
    }
}
pub(super) struct SelectionPin {
    root: PrivateRoot,
    pub(super) file: RawFile,
    pub(super) selection: NativeRuntimeSelection,
}
impl SelectionPin {
    pub(super) fn open(path: &Path) -> Result<Self, AppError> {
        let root = PrivateRoot::open(
            path.parent()
                .ok_or(AppError("app_runtime_selection_invalid"))?,
        )
        .map_err(|_| AppError("app_runtime_selection_invalid"))?;
        let file = root
            .read_raw(
                Path::new(
                    path.file_name()
                        .ok_or(AppError("app_runtime_selection_invalid"))?,
                ),
                65536,
            )
            .map_err(|_| AppError("app_runtime_selection_invalid"))?;
        let selection = serde_json::from_slice(file.bytes())
            .map_err(|_| AppError("app_runtime_selection_invalid"))?;
        Ok(Self {
            root,
            file,
            selection,
        })
    }
    pub(super) fn validate(&self) -> Result<(), AppError> {
        same_file(&self.root, &self.file)
    }
}
pub(super) fn same_file(root: &PrivateRoot, file: &RawFile) -> Result<(), AppError> {
    let current = root
        .read_raw(file.relative_path(), 65536)
        .map_err(|_| AppError("app_runtime_input_changed"))?;
    if current.observation() != file.observation() || current.bytes() != file.bytes() {
        return Err(AppError("app_runtime_input_changed"));
    }
    Ok(())
}
fn identity_digest(mut identity: serde_json::Value) -> Result<Sha256Digest, AppError> {
    if identity["platform"] == "macos" {
        identity
            .as_object_mut()
            .ok_or(AppError("app_runtime_input_invalid"))?
            .remove("device");
    }
    serde_json::to_vec(&identity)
        .map(|raw| Sha256Digest::of_bytes(&raw))
        .map_err(|_| AppError("app_runtime_input_invalid"))
}
pub(super) fn root_digest(root: &PrivateRoot) -> Result<Sha256Digest, AppError> {
    let identity = root.identity();
    let value =
        serde_json::to_value(&identity).map_err(|_| AppError("app_runtime_input_invalid"))?;
    if value["platform"] == "macos" {
        identity_digest(value)
    } else {
        serde_json::to_vec(&identity)
            .map(|raw| Sha256Digest::of_bytes(&raw))
            .map_err(|_| AppError("app_runtime_input_invalid"))
    }
}
fn legacy_mac_digest(identity: &serde_json::Value, device: u64) -> Result<Sha256Digest, AppError> {
    let legacy = styx_contracts::native_management::NativeRootIdentity::Macos {
        device,
        inode: identity["inode"]
            .as_u64()
            .ok_or(AppError("app_runtime_input_invalid"))?,
        uid: identity["uid"]
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or(AppError("app_runtime_input_invalid"))?,
    };
    serde_json::to_vec(&legacy)
        .map(|raw| Sha256Digest::of_bytes(&raw))
        .map_err(|_| AppError("app_runtime_input_invalid"))
}
pub(super) fn root_digest_matches(
    root: &PrivateRoot,
    expected: Sha256Digest,
    input: &OriginalInput,
) -> Result<bool, AppError> {
    if root_digest(root)? == expected {
        return Ok(true);
    }
    let identity =
        serde_json::to_value(root.identity()).map_err(|_| AppError("app_runtime_input_invalid"))?;
    if identity["platform"] != "macos" {
        return Ok(false);
    }
    let styx_contracts::native_management::NativeRootIdentity::Macos { device, .. } =
        &input.selection.payload_root
    else {
        return Ok(false);
    };
    Ok(legacy_mac_digest(&identity, *device)? == expected)
}

struct Role {
    scope: Arc<HostScope>,
    retained: Option<native::NativeManagementError>,
    // Local DATA tag records which exact original call returned this object.
    // It cannot mint custody or substitute for backend same-owner validation.
    retained_transaction: Option<TransactionId>,
}
struct Work {
    scope: Arc<HostScope>,
    writer: ConfigurationWriterGuard,
    versions: Option<PrivateRoot>,
    updates: Option<PrivateRoot>,
    staged: Option<SelectionPin>,
    original: Option<OriginalInput>,
    original_pin: Option<RawFile>,
    roles: Vec<Role>,
    error: Option<&'static str>,
    committed: bool,
}
#[derive(Serialize)]
pub(super) struct State {
    status: &'static str,
    transaction_id: Option<TransactionId>,
    can_recover: bool,
    error: Option<&'static str>,
    split_atomic: bool,
    #[serde(skip)]
    work: Option<Work>,
    #[serde(skip)]
    job: Option<JoinHandle<Work>>,
}
impl State {
    fn fenced(&self) -> bool {
        self.job.is_some()
            || self.error.is_some()
            || (self.transaction_id.is_some() && self.status != "committed")
    }
    fn running(&self) -> bool {
        self.job.is_some()
    }
}
impl Work {
    fn validate(&self) -> Result<(), AppError> {
        self.scope.validate()?;
        self.writer
            .validate()
            .map_err(|_| AppError("app_runtime_input_writer_changed"))?;
        if let Some(stage) = &self.staged {
            stage.validate()?;
        }
        if let Some(input) = &self.original {
            if input.schema != 1
                || !root_digest_matches(
                    &self.scope.container.parent,
                    input.container_sha256,
                    input,
                )?
                || input.roles.len() != self.roles.len()
            {
                return Err(AppError("app_runtime_input_changed"));
            }
            same_file(
                self.updates
                    .as_ref()
                    .ok_or(AppError("app_runtime_input_missing"))?,
                self.original_pin
                    .as_ref()
                    .ok_or(AppError("app_runtime_input_missing"))?,
            )?;
            for (binding, role) in input.roles.iter().zip(&self.roles) {
                role.scope.validate()?;
                if !root_digest_matches(
                    role.scope
                        .root
                        .get()
                        .ok_or(AppError("app_not_configured"))?,
                    binding.root_sha256,
                    input,
                )? {
                    return Err(AppError("app_runtime_input_changed"));
                }
            }
        }
        Ok(())
    }
    fn read_status(
        &mut self,
        index: usize,
        tx: Option<&str>,
    ) -> Result<native::update::AppRuntimeStatus, AppError> {
        let role = &mut self.roles[index];
        match native::update::runtime_status_for_app(&role.scope, tx, role.retained.as_ref()) {
            Ok(status) => Ok(status),
            Err(error) => {
                let code = error.code();
                let pending = error.runtime_update_transaction().is_some();
                if role.retained.is_none() {
                    role.retained_transaction = error.runtime_update_transaction().cloned();
                    role.retained = Some(error);
                }
                if pending {
                    // This is the same observation through its retained writer,
                    // not a reopen or promotion of Pending to admitted.
                    return native::update::runtime_status_for_app(
                        &role.scope,
                        tx,
                        role.retained.as_ref(),
                    )
                    .map_err(|e| AppError(e.code()));
                }
                Err(AppError(code))
            }
        }
    }
    fn load(&mut self, id: &TransactionId) -> Result<(), AppError> {
        self.scope.validate()?;
        // Recovery opens existing input directories only; missing/failed staging
        // cannot be adopted by creating replacement paths.
        self.versions = Some(
            PrivateRoot::open(self.scope.container.parent_path.join("runtime-versions"))
                .map_err(|_| AppError("app_runtime_original_input_required"))?,
        );
        self.updates = Some(
            PrivateRoot::open(self.scope.container.parent_path.join("runtime-updates"))
                .map_err(|_| AppError("app_runtime_original_input_required"))?,
        );
        let raw = self
            .updates
            .as_ref()
            .ok_or(AppError("app_runtime_storage_unknown"))?
            .read_raw(format!("{}.json", id.as_str()), 65536)
            .map_err(|_| AppError("app_runtime_original_input_required"))?;
        let input: OriginalInput = serde_json::from_slice(raw.bytes())
            .map_err(|_| AppError("app_runtime_original_input_invalid"))?;
        input.validate_shape(id)?;
        let stage = SelectionPin::open(
            &self
                .scope
                .container
                .parent_path
                .join("runtime-versions")
                .join(&input.selection_file),
        )?;
        if stage.selection != input.selection
            || Sha256Digest::of_bytes(stage.file.bytes()) != input.selection_sha256
        {
            return Err(AppError("app_runtime_original_input_changed"));
        }
        // Preserve the SAME original scope Arc and coordinator while scanning
        // later inputs or recovering in-process. A historical committed input
        // may share its root with a newer pending transaction.
        if self.roles.len() != input.roles.len() {
            if self.roles.iter().any(|role| role.retained.is_some()) {
                return Err(AppError("app_runtime_original_scope_required"));
            }
            self.roles = vec![Role {
                scope: self.scope.clone(),
                retained: None,
                retained_transaction: None,
            }];
            if input.roles.len() == 2 {
                self.roles.push(Role {
                    scope: Arc::new(self.scope.gateway_sibling()?),
                    retained: None,
                    retained_transaction: None,
                });
            }
        }
        self.staged = Some(stage);
        self.original = Some(input);
        self.original_pin = Some(raw);
        self.validate()
    }
}
impl HostApp {
    /// Discover only already-published immutable original inputs. No stage,
    /// C07 phase, pairing request or role launch is performed on startup.
    pub(super) fn observe_runtime_update(&mut self) -> Result<bool, AppError> {
        if self
            .scope
            .container
            .parent
            .ensure_absent("runtime-updates")
            .is_ok()
        {
            return Ok(false);
        }
        let directory = self.scope.container.parent_path.join("runtime-updates");
        let held = PrivateRoot::open(&directory)
            .map_err(|_| AppError("app_runtime_original_input_invalid"))?;
        let mut ids = Vec::new();
        for entry in std::fs::read_dir(&directory)
            .map_err(|_| AppError("app_runtime_original_input_invalid"))?
        {
            let name = entry
                .map_err(|_| AppError("app_runtime_original_input_invalid"))?
                .file_name();
            let name = name
                .to_str()
                .ok_or(AppError("app_runtime_original_input_invalid"))?;
            let id = name
                .strip_suffix(".json")
                .and_then(|id| TransactionId::try_from(id).ok())
                .ok_or(AppError("app_runtime_original_input_invalid"))?;
            // Names are locators only: every entry is opened through the held
            // protected root and the complete original input is checked below.
            let raw = held
                .read_raw(name, 65536)
                .map_err(|_| AppError("app_runtime_original_input_invalid"))?;
            let input: OriginalInput = serde_json::from_slice(raw.bytes())
                .map_err(|_| AppError("app_runtime_original_input_invalid"))?;
            if input.transaction_id != id {
                return Err(AppError("app_runtime_original_input_invalid"));
            }
            ids.push(id);
        }
        if PrivateRoot::open(&directory)
            .map_err(|_| AppError("app_runtime_original_input_changed"))?
            .identity()
            != held.identity()
        {
            return Err(AppError("app_runtime_original_input_changed"));
        }
        self.scope.validate()?;
        ids.sort();
        let mut work = self.new_runtime_work()?;
        let mut pending = None;
        for id in ids {
            work.load(&id)?;
            let mut complete = true;
            let bindings: Vec<_> = work
                .original
                .as_ref()
                .ok_or(AppError("app_runtime_original_input_required"))?
                .roles
                .iter()
                .map(|r| r.select_transaction.clone())
                .collect();
            for (index, tx) in bindings.iter().enumerate() {
                match work.read_status(index, Some(tx.as_str())) {
                    Ok(status) => {
                        if status
                            .configuration
                            .transaction
                            .as_ref()
                            .is_none_or(|t| t.observed_stage != Some(DurableStage::Committed))
                        {
                            complete = false;
                        }
                    }
                    Err(error) => {
                        work.error = Some(error.code());
                        complete = false;
                    }
                }
            }
            if !complete {
                pending = Some(id);
                break;
            }
            // Completed historical input never selects its old target again.
            work.original = None;
            work.original_pin = None;
        }
        if let Some(id) = pending {
            let error = work.error.unwrap_or("app_runtime_update_pending");
            work.error = Some(error);
            self.runtime_update = Some(State {
                status: "unknown",
                transaction_id: Some(id),
                can_recover: true,
                error: Some(error),
                split_atomic: false,
                job: None,
                work: Some(work),
            });
            self.enrollment = Some(json!({"status":"runtime_update_pending"}));
            Ok(true)
        } else if work.roles.iter().any(|role| role.retained.is_some()) {
            // Never drop a newer pending coordinator merely because historical
            // selection transactions were all committed. No original input
            // bound this pending operation, so no old target is recovered.
            work.error = Some("app_runtime_original_input_required");
            self.runtime_update = Some(State {
                status: "unknown",
                transaction_id: None,
                can_recover: false,
                error: work.error,
                split_atomic: false,
                job: None,
                work: Some(work),
            });
            Ok(true)
        } else {
            self.input_writer = Some(work.writer);
            Ok(false)
        }
    }
    pub(super) fn runtime_update_fenced(&self) -> bool {
        self.runtime_update.as_ref().is_some_and(State::fenced)
    }
    pub(super) fn runtime_update_running(&self) -> bool {
        self.runtime_update.as_ref().is_some_and(State::running)
    }
    pub(super) fn runtime_update_owns_work(&self) -> bool {
        self.runtime_update
            .as_ref()
            .is_some_and(|state| state.work.is_some() || state.job.is_some())
    }
    fn new_runtime_work(&mut self) -> Result<Work, AppError> {
        self.scope.validate()?;
        let writer = match self.input_writer.take() {
            Some(writer) => writer,
            None => self
                .scope
                .container
                .parent
                .try_configuration_writer()
                .map_err(|_| AppError("app_input_writer_busy"))?,
        };
        Ok(Work {
            scope: self.scope.clone(),
            writer,
            versions: None,
            updates: None,
            staged: None,
            original: None,
            original_pin: None,
            roles: vec![Role {
                scope: self.scope.clone(),
                retained: None,
                retained_transaction: None,
            }],
            error: None,
            committed: false,
        })
    }
    pub(super) async fn reap_runtime_update(&mut self, wait: bool) {
        let Some(state) = &mut self.runtime_update else {
            return;
        };
        if state
            .job
            .as_ref()
            .is_none_or(|job| !wait && !job.is_finished())
        {
            return;
        }
        let Some(job) = state.job.take() else {
            return;
        };
        match job.await {
            Ok(work) => {
                state.error = work.error;
                state.can_recover = work.error.is_some() && work.original.is_some();
                state.status = if work.error.is_some() {
                    "unknown"
                } else if work.committed {
                    "committed"
                } else {
                    "staged"
                };
                state.work = Some(work);
            }
            Err(_) => {
                state.status = "unknown";
                state.error = Some("app_runtime_worker_unknown");
                state.can_recover = false;
                self.unknown = true;
            }
        }
        let mut gateway_scope = None;
        let completed = state.status == "committed";
        if completed {
            // Update reports never imply role startup. Read only the committed
            // current tip; Connect will acquire the new pinned runtime later.
            if let Some(work) = &mut state.work {
                match work.read_status(0, None) {
                    Ok(status) => {
                        self.configuration = Some(status.configuration);
                        gateway_scope = work.roles.get(1).map(|r| r.scope.clone());
                    }
                    Err(e) => {
                        state.status = "unknown";
                        state.error = Some(e.code());
                        state.can_recover = true;
                    }
                }
            }
        }
        if completed && !self.runtime_update_fenced() {
            let refreshed = async {
                let enrollment = native_join::inspect_for_app(self.scope.clone())
                    .await
                    .map_err(|e| self.join_error(e))?;
                self.native_computer_requested = Some(enrollment.computer_requested);
                self.native_runtime = Some(enrollment.verified_runtime.clone());
                self.enrollment = Some(
                    serde_json::to_value(enrollment)
                        .map_err(|_| AppError("app_response_invalid"))?,
                );
                if self.local_gateway.is_none()
                    && let Some(scope) = gateway_scope
                {
                    self.local_gateway = Some(self.load_local_gateway(scope).await?);
                }
                self.scope.validate()
            }
            .await;
            if let Err(error) = refreshed
                && let Some(state) = &mut self.runtime_update
            {
                state.status = "unknown";
                state.error = Some(error.code());
                state.can_recover = true;
            }
        }
        if completed && !self.runtime_update_fenced() {
            // Keep the UI result, not the completed operation's file handles and
            // role roots. The App resumes custody of its existing input writer.
            if let Some(work) = self
                .runtime_update
                .as_mut()
                .and_then(|state| state.work.take())
            {
                debug_assert!(self.input_writer.is_none());
                self.input_writer = Some(work.writer);
            }
        }
    }
}

#[cfg(test)]
#[test]
fn mac_update_history_digest_survives_mount_change_but_not_root_replacement() {
    let old = serde_json::json!({"platform":"macos","device":16777229,"inode":25590241,"uid":501});
    let mut now = old.clone();
    now["device"] = serde_json::json!(16777231);
    assert_eq!(
        identity_digest(old.clone()).unwrap(),
        identity_digest(now.clone()).unwrap()
    );
    let legacy = legacy_mac_digest(&old, 16777229).unwrap();
    assert_eq!(legacy_mac_digest(&now, 16777229).unwrap(), legacy);
    for key in ["inode", "uid"] {
        let mut changed = now.clone();
        changed[key] = serde_json::json!(999);
        assert_ne!(
            identity_digest(changed.clone()).unwrap(),
            identity_digest(old.clone()).unwrap()
        );
        assert_ne!(legacy_mac_digest(&changed, 16777229).unwrap(), legacy);
    }
}
