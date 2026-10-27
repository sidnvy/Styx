//! App-owned immutable inputs and the original per-role C07 transactions.
//! This input is not a progress ledger: all phase decisions come from C07.
use super::*;
use crate::{release, store::RawFile};
use styx_contracts::{
    identity::{Sha256Digest, TransactionId},
    management::{DurableStage, ReaderContract},
    native_management::NativeRuntimeSelection,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StageInput {
    authorize: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct UpdateInput {
    authorize: bool,
    transaction_id: TransactionId,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RoleInput {
    gateway: bool,
    root_sha256: Sha256Digest,
    before_sha256: Sha256Digest,
    previous: NativeRuntimeSelection,
    stop_transaction: TransactionId,
    stop_sequence: u64,
    stop_required: bool,
    select_transaction: TransactionId,
    select_sequence: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginalInput {
    schema: u16,
    transaction_id: TransactionId,
    container_sha256: Sha256Digest,
    selection_file: String,
    selection_sha256: Sha256Digest,
    selection: NativeRuntimeSelection,
    roles: Vec<RoleInput>,
}
struct SelectionPin {
    root: PrivateRoot,
    file: RawFile,
    selection: NativeRuntimeSelection,
}
impl SelectionPin {
    fn open(path: &Path) -> Result<Self, AppError> {
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
    fn validate(&self) -> Result<(), AppError> {
        same_file(&self.root, &self.file)
    }
}
fn same_file(root: &PrivateRoot, file: &RawFile) -> Result<(), AppError> {
    let current = root
        .read_raw(file.relative_path(), 65536)
        .map_err(|_| AppError("app_runtime_input_changed"))?;
    if current.observation() != file.observation() || current.bytes() != file.bytes() {
        return Err(AppError("app_runtime_input_changed"));
    }
    Ok(())
}
fn root_digest(root: &PrivateRoot) -> Result<Sha256Digest, AppError> {
    serde_json::to_vec(&root.identity())
        .map(|raw| Sha256Digest::of_bytes(&raw))
        .map_err(|_| AppError("app_runtime_input_invalid"))
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
    fn new(work: Work) -> Self {
        Self {
            status: "not_started",
            transaction_id: None,
            can_recover: false,
            error: None,
            split_atomic: false,
            work: Some(work),
            job: None,
        }
    }
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
                || input.container_sha256 != root_digest(&self.scope.container.parent)?
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
                if binding.root_sha256
                    != root_digest(
                        role.scope
                            .root
                            .get()
                            .ok_or(AppError("app_not_configured"))?,
                    )?
                {
                    return Err(AppError("app_runtime_input_changed"));
                }
            }
        }
        Ok(())
    }
    fn directories(&mut self) -> Result<(), AppError> {
        self.scope.validate()?;
        let parent = &self.scope.container.parent;
        if self.versions.is_none() {
            self.versions = Some(
                parent
                    .prepare_app_runtime_directory(&self.writer, "runtime-versions")
                    .map_err(|_| AppError("app_runtime_storage_unknown"))?,
            );
        }
        if self.updates.is_none() {
            self.updates = Some(
                parent
                    .prepare_app_runtime_directory(&self.writer, "runtime-updates")
                    .map_err(|_| AppError("app_runtime_storage_unknown"))?,
            );
        }
        self.validate()
    }
    async fn stage(&mut self, launcher: PathBuf) -> Result<(), AppError> {
        let source = SelectionPin::open(&launcher)?;
        let verified =
            release::verify_selected(&source.selection).map_err(|e| AppError(e.code()))?;
        if !verified
            .supports_state_reader(ReaderContract::NativeAppRuntimeSelectedStateV1)
            .map_err(|e| AppError(e.code()))?
        {
            return Err(AppError("app_runtime_reader_unsupported"));
        }
        self.directories()?;
        let name = format!(
            "{}-{}",
            source.selection.manifest_sha256.to_hex(),
            uuid::Uuid::new_v4().simple()
        );
        let parent = self.scope.container.parent_path.join("runtime-versions");
        let staged = release::stage(
            Path::new(&source.selection.payload_path),
            Path::new(&source.selection.publisher_file),
            &source.selection.publisher_spki_sha256.to_hex(),
            &parent,
            std::ffi::OsStr::new(&name),
        )
        .await
        .map_err(|e| AppError(e.code()))?;
        source.validate()?;
        verified.revalidate().map_err(|e| AppError(e.code()))?;
        self.validate()?;
        let bytes =
            serde_json::to_vec(&staged).map_err(|_| AppError("app_runtime_input_invalid"))?;
        let filename = format!("{}.json", Sha256Digest::of_bytes(&bytes).to_hex());
        let versions = self
            .versions
            .as_ref()
            .ok_or(AppError("app_runtime_storage_unknown"))?;
        let file = self
            .scope
            .container
            .parent
            .publish_app_runtime_file(&self.writer, versions, &filename, &bytes)
            .map_err(|_| AppError("app_runtime_stage_unknown"))?;
        self.staged = Some(SelectionPin::open(&parent.join(file.relative_path()))?);
        self.original = None;
        self.original_pin = None;
        self.committed = false;
        self.validate()
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
    async fn settle_retained_transaction(
        &mut self,
        index: usize,
        id: &TransactionId,
        runtime_only: bool,
    ) -> Result<(), AppError> {
        if self.roles[index].retained_transaction.as_ref() != Some(id)
            || self.roles[index].retained.is_none()
        {
            return Err(AppError("app_runtime_original_transaction_required"));
        }
        let retained = self.roles[index].retained.take();
        let scope = self.roles[index].scope.clone();
        let result = if runtime_only {
            native::update::recover_runtime_for_app(scope, id.as_str(), retained).await
        } else {
            native::update::recover_transaction_for_app(scope, id.as_str(), retained).await
        };
        match result {
            Ok(_) => {
                self.roles[index].retained_transaction = None;
                Ok(())
            }
            Err(error) => {
                let code = error.code();
                self.roles[index].retained = Some(error);
                Err(AppError(code))
            }
        }
    }
    fn capture(&mut self, id: TransactionId) -> Result<(), AppError> {
        self.validate()?;
        if id.as_str().len() > 80 {
            return Err(AppError("app_runtime_transaction_invalid"));
        }
        let staged = self
            .staged
            .as_ref()
            .ok_or(AppError("app_runtime_not_staged"))?;
        let selection = staged.selection.clone();
        let filename = staged
            .file
            .relative_path()
            .to_str()
            .ok_or(AppError("app_runtime_input_invalid"))?
            .to_owned();
        let selection_sha256 = Sha256Digest::of_bytes(staged.file.bytes());
        let mut roles = Vec::new();
        for index in 0..self.roles.len() {
            let status = self.read_status(index, None)?;
            let desired = &status.configuration.desired;
            let gateway = index > 0;
            let role = if gateway {
                desired.gateway
            } else {
                desired.host
            }
            .ok_or(AppError("app_runtime_role_invalid"))?;
            if (gateway && desired.host.is_some())
                || (!gateway && desired.gateway.is_some())
                || role.manager != NativeManager::AppManaged
                || role.autostart != NativeAutostartDesired::Disabled
                || status.configuration.admission_fenced
                || status.current_selection.publisher_spki_sha256 != selection.publisher_spki_sha256
            {
                return Err(AppError("app_runtime_role_invalid"));
            }
            let stop_required = role.run != NativeRunDesired::Stopped;
            let prefix = if gateway { "gateway" } else { "host" };
            roles.push(RoleInput {
                gateway,
                root_sha256: root_digest(
                    self.roles[index]
                        .scope
                        .root
                        .get()
                        .ok_or(AppError("app_not_configured"))?,
                )?,
                before_sha256: status.configuration.canonical_state_sha256,
                previous: status.current_selection,
                stop_transaction: format!("{}-{prefix}-stop", id.as_str())
                    .try_into()
                    .map_err(|_| AppError("app_runtime_transaction_invalid"))?,
                stop_sequence: status.next_sequence,
                stop_required,
                select_transaction: format!("{}-{prefix}-select", id.as_str())
                    .try_into()
                    .map_err(|_| AppError("app_runtime_transaction_invalid"))?,
                select_sequence: status
                    .next_sequence
                    .checked_add(u64::from(stop_required))
                    .ok_or(AppError("app_revision_exhausted"))?,
            });
        }
        let input = OriginalInput {
            schema: 1,
            transaction_id: id,
            container_sha256: root_digest(&self.scope.container.parent)?,
            selection_file: filename,
            selection_sha256,
            selection,
            roles,
        };
        let raw = serde_json::to_vec(&input).map_err(|_| AppError("app_runtime_input_invalid"))?;
        let filename = format!("{}.json", input.transaction_id.as_str());
        self.original = Some(input);
        let file = self
            .scope
            .container
            .parent
            .publish_app_runtime_file(
                &self.writer,
                self.updates
                    .as_ref()
                    .ok_or(AppError("app_runtime_storage_unknown"))?,
                &filename,
                &raw,
            )
            .map_err(|_| AppError("app_runtime_input_publication_unknown"))?;
        self.original_pin = Some(file);
        self.validate()
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
        if input.schema != 1
            || &input.transaction_id != id
            || input.roles.is_empty()
            || input.roles.len() > 2
            || input.roles[0].gateway
            || input.roles.get(1).is_some_and(|r| !r.gateway)
            || input.selection_file.contains('/')
            || input.selection_file.contains('\\')
            || input.selection_file != format!("{}.json", input.selection_sha256.to_hex())
        {
            return Err(AppError("app_runtime_original_input_invalid"));
        }
        for role in &input.roles {
            let suffix = if role.gateway { "gateway" } else { "host" };
            if role.stop_sequence == 0
                || role.stop_transaction.as_str() != format!("{}-{suffix}-stop", id.as_str())
                || role.select_transaction.as_str() != format!("{}-{suffix}-select", id.as_str())
                || role
                    .stop_sequence
                    .checked_add(u64::from(role.stop_required))
                    != Some(role.select_sequence)
                || role.previous.publisher_spki_sha256 != input.selection.publisher_spki_sha256
            {
                return Err(AppError("app_runtime_original_input_invalid"));
            }
        }
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
    async fn execute(&mut self, recover: bool) -> Result<(), AppError> {
        if self.original_pin.is_none() {
            let original = self
                .original
                .as_ref()
                .ok_or(AppError("app_runtime_original_input_required"))?;
            let expected =
                serde_json::to_vec(original).map_err(|_| AppError("app_runtime_input_invalid"))?;
            let raw = self
                .updates
                .as_ref()
                .ok_or(AppError("app_runtime_original_input_required"))?
                .read_raw(format!("{}.json", original.transaction_id.as_str()), 65536)
                .map_err(|_| AppError("app_runtime_input_publication_unknown"))?;
            if raw.bytes() != expected {
                return Err(AppError("app_runtime_original_input_changed"));
            }
            self.original_pin = Some(raw);
        }
        self.validate()?;
        // Use owned copies of DATA only; actual scope/coordinator stays in self.
        let raw = serde_json::to_vec(
            self.original
                .as_ref()
                .ok_or(AppError("app_runtime_original_input_required"))?,
        )
        .map_err(|_| AppError("app_runtime_input_invalid"))?;
        let original: OriginalInput =
            serde_json::from_slice(&raw).map_err(|_| AppError("app_runtime_input_invalid"))?;
        for (index, binding) in original.roles.iter().enumerate() {
            self.validate()?;
            // Exact original selection transaction first: Committed is never
            // executed again, regardless of response delivery or process restart.
            let mut selected =
                self.read_status(index, Some(binding.select_transaction.as_str()))?;
            if recover
                && self.roles[index].retained_transaction.as_ref()
                    == Some(&binding.select_transaction)
            {
                self.settle_retained_transaction(index, &binding.select_transaction, true)
                    .await?;
                selected = self.read_status(index, Some(binding.select_transaction.as_str()))?;
            }
            if let Some(tx) = &selected.configuration.transaction {
                if tx.sequence != binding.select_sequence {
                    return Err(AppError("app_runtime_original_transaction_changed"));
                }
                if tx.observed_stage == Some(DurableStage::Committed) {
                    if selected.configuration.admission_fenced
                        || selected.pending_transaction.is_some()
                        || selected.current_selection != original.selection
                    {
                        return Err(AppError("app_runtime_committed_target_changed"));
                    }
                    continue;
                }
                if !recover {
                    return Err(AppError("app_runtime_original_transaction_pending"));
                }
                let retained = self.roles[index].retained.take();
                let result = native::update::recover_runtime_for_app(
                    self.roles[index].scope.clone(),
                    binding.select_transaction.as_str(),
                    retained,
                )
                .await;
                match result {
                    Ok(_) => {}
                    Err(error) => {
                        let code = error.code();
                        self.roles[index].retained_transaction =
                            Some(binding.select_transaction.clone());
                        self.roles[index].retained = Some(error);
                        return Err(AppError(code));
                    }
                }
                let status = self.read_status(index, Some(binding.select_transaction.as_str()))?;
                if status
                    .configuration
                    .transaction
                    .as_ref()
                    .is_none_or(|tx| tx.observed_stage != Some(DurableStage::Committed))
                    || status.current_selection != original.selection
                {
                    return Err(AppError("app_runtime_recovery_unconfirmed"));
                }
                continue;
            }
            if binding.stop_required {
                let mut status =
                    self.read_status(index, Some(binding.stop_transaction.as_str()))?;
                if recover
                    && self.roles[index].retained_transaction.as_ref()
                        == Some(&binding.stop_transaction)
                {
                    self.settle_retained_transaction(index, &binding.stop_transaction, false)
                        .await?;
                    status = self.read_status(index, Some(binding.stop_transaction.as_str()))?;
                }
                if let Some(tx) = &status.configuration.transaction {
                    if tx.sequence != binding.stop_sequence {
                        return Err(AppError("app_runtime_original_transaction_changed"));
                    }
                    if tx.observed_stage != Some(DurableStage::Committed) {
                        if !recover {
                            return Err(AppError("app_runtime_original_transaction_pending"));
                        }
                        let retained = self.roles[index].retained.take();
                        match native::update::recover_transaction_for_app(
                            self.roles[index].scope.clone(),
                            binding.stop_transaction.as_str(),
                            retained,
                        )
                        .await
                        {
                            Ok(_) => {}
                            Err(error) => {
                                let code = error.code();
                                self.roles[index].retained_transaction =
                                    Some(binding.stop_transaction.clone());
                                self.roles[index].retained = Some(error);
                                return Err(AppError(code));
                            }
                        }
                    }
                } else {
                    if status.configuration.admission_fenced
                        || status.configuration.canonical_state_sha256 != binding.before_sha256
                        || status.current_selection != binding.previous
                        || status.next_sequence != binding.stop_sequence
                    {
                        return Err(AppError("app_runtime_original_before_changed"));
                    }
                    let change = native::NativeDesiredChange {
                        component: if binding.gateway {
                            native::NativeComponent::Gateway
                        } else {
                            native::NativeComponent::Host
                        },
                        run: NativeRunDesired::Stopped,
                        transaction_id: binding.stop_transaction.clone(),
                        sequence: binding.stop_sequence,
                    };
                    let plan =
                        match native::plan_for_app(self.roles[index].scope.clone(), change).await {
                            Ok(plan) => plan,
                            Err(error) => {
                                let code = error.code();
                                self.roles[index].retained_transaction =
                                    Some(binding.stop_transaction.clone());
                                self.roles[index].retained = Some(error);
                                return Err(AppError(code));
                            }
                        };
                    match native::apply_for_app(self.roles[index].scope.clone(), &plan.plan_file)
                        .await
                    {
                        Ok(_) => {}
                        Err(error) => {
                            let code = error.code();
                            self.roles[index].retained_transaction =
                                Some(binding.stop_transaction.clone());
                            self.roles[index].retained = Some(error);
                            return Err(AppError(code));
                        }
                    }
                }
            }
            let status = self.read_status(index, None)?;
            let desired = if binding.gateway {
                status.configuration.desired.gateway
            } else {
                status.configuration.desired.host
            }
            .ok_or(AppError("app_runtime_role_invalid"))?;
            if status.configuration.admission_fenced
                || desired.run != NativeRunDesired::Stopped
                || desired.manager != NativeManager::AppManaged
                || desired.autostart != NativeAutostartDesired::Disabled
                || status.current_selection != binding.previous
                || status.next_sequence != binding.select_sequence
                || (!binding.stop_required
                    && status.configuration.canonical_state_sha256 != binding.before_sha256)
            {
                return Err(AppError("app_runtime_original_before_changed"));
            }
            self.validate()?;
            let selection = self
                .scope
                .container
                .parent_path
                .join("runtime-versions")
                .join(&original.selection_file);
            match native::update::select_runtime_for_app(
                self.roles[index].scope.clone(),
                &selection,
                binding.select_transaction.as_str(),
                binding.select_sequence,
            )
            .await
            {
                Ok(report) => {
                    if report.configuration.admission_fenced
                        || report.selected_manifest_sha256 != original.selection.manifest_sha256
                    {
                        return Err(AppError("app_runtime_selection_unconfirmed"));
                    }
                }
                Err(error) => {
                    let code = error.code();
                    self.roles[index].retained_transaction =
                        Some(binding.select_transaction.clone());
                    self.roles[index].retained = Some(error);
                    return Err(AppError(code));
                }
            }
        }
        self.validate()?;
        self.committed = true;
        Ok(())
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
            if ids.len() >= 64 {
                return Err(AppError("app_runtime_input_budget"));
            }
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
    pub(super) async fn stage_runtime(&mut self, input: StageInput) -> Result<(), AppError> {
        if !input.authorize {
            return Err(AppError("app_runtime_authorization_required"));
        }
        self.available()?;
        if self.committed_migration || self.configuration.is_none() {
            return Err(AppError("app_runtime_profile_unsupported"));
        }
        let selection = self
            .runtime_selection_file
            .clone()
            .ok_or(AppError("app_runtime_candidate_unavailable"))?;
        let mut state = match self.runtime_update.take() {
            Some(state) => state,
            None => State::new(self.new_runtime_work()?),
        };
        let Some(mut work) = state.work.take() else {
            self.runtime_update = Some(state);
            return Err(AppError("app_runtime_update_in_progress"));
        };
        work.error = None;
        work.committed = false;
        work.roles = vec![Role {
            scope: self.scope.clone(),
            retained: None,
            retained_transaction: None,
        }];
        work.original = None;
        work.original_pin = None;
        state.transaction_id = None;
        state.error = None;
        state.status = "staging";
        state.job = Some(tokio::spawn(async move {
            if let Err(e) = work.stage(selection).await {
                work.error = Some(e.code());
            }
            work
        }));
        self.runtime_update = Some(state);
        Ok(())
    }
    pub(super) async fn update_runtime(
        &mut self,
        input: UpdateInput,
        recover: bool,
    ) -> Result<(), AppError> {
        self.scope.validate()?;
        if !input.authorize {
            return Err(AppError("app_runtime_authorization_required"));
        }
        if self.migration_fenced()
            || self.committed_migration
            || self.unknown
            || self.quit_ticket.is_some()
        {
            return Err(AppError("app_runtime_profile_unsupported"));
        }
        if self.runtime_update_running() {
            return Err(AppError("app_runtime_update_in_progress"));
        }
        if !recover {
            self.available()?;
            if self
                .runtime_update
                .as_ref()
                .is_none_or(|state| state.status != "staged")
            {
                return Err(AppError("app_runtime_not_staged"));
            }
        }
        // Dispatch is owned and not selected against pipe cancellation. Actual
        // Host drain and Gateway joins precede every configuration write.
        self.settle().await?;
        if let Some(gateway) = &mut self.local_gateway {
            gateway.settle().await?;
        }
        let mut state = match self.runtime_update.take() {
            Some(state) => state,
            None => State::new(self.new_runtime_work()?),
        };
        if state
            .transaction_id
            .as_ref()
            .is_some_and(|id| id != &input.transaction_id)
        {
            self.runtime_update = Some(state);
            return Err(AppError("app_runtime_original_transaction_required"));
        }
        let Some(mut work) = state.work.take() else {
            self.runtime_update = Some(state);
            return Err(AppError("app_runtime_update_in_progress"));
        };
        if !recover && let Some(gateway) = &self.local_gateway {
            work.roles.push(Role {
                scope: gateway.scope.clone(),
                retained: None,
                retained_transaction: None,
            });
        }
        state.status = "updating";
        state.transaction_id = Some(input.transaction_id.clone());
        state.can_recover = false;
        state.error = None;
        state.job = Some(tokio::spawn(async move {
            work.error = None;
            let result = async {
                if work.original.is_none() {
                    if recover {
                        work.load(&input.transaction_id)?;
                    } else {
                        work.capture(input.transaction_id)?;
                    }
                }
                work.execute(recover).await
            }
            .await;
            if let Err(error) = result {
                work.error = Some(error.code());
            }
            work
        }));
        self.runtime_update = Some(state);
        Ok(())
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
    }
}
