//! Live original-App maintenance admission. Reports are correlation DATA, never
//! an installer permit. The native owner still joins its original Core, native
//! workers and App; the platform installer retains its own verified operation.
use super::*;
use crate::{
    release::{self, VerifiedNativeRelease},
    store::{RawFile, RootIdentity, native_host_snapshot, native_state},
};
use styx_contracts::{
    identity::Sha256Digest,
    native_management::{NATIVE_MARKER_BYTES, NATIVE_STATE_BYTES, NativeRuntimeSelection},
};

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum MaintenanceOperation {
    Upgrade,
    Uninstall,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct PrepareInput {
    schema: u16,
    authorize: bool,
    operation: MaintenanceOperation,
    request_id: String,
    install_root: PathBuf,
    package_sha256: Option<Sha256Digest>,
    candidate_package_sha256: Option<Sha256Digest>,
    login_observation: Option<login::Observation>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct CancelInput {
    authorize: bool,
    ticket_id: String,
}
fn refused() -> AppError {
    AppError("app_maintenance_references_unconfirmed")
}
fn canonical(path: &Path) -> Result<PathBuf, AppError> {
    if !path.is_absolute()
        || path.components().any(|p| {
            !matches!(
                p,
                Component::Normal(_) | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(AppError("app_maintenance_input_invalid"));
    }
    std::fs::canonicalize(path).map_err(|_| refused())
}
fn outside(path: &Path, install: &Path) -> Result<(), AppError> {
    if canonical(path)?.starts_with(install) {
        return Err(AppError("app_maintenance_runtime_in_install_root"));
    }
    Ok(())
}
fn reobserve(root: &PrivateRoot, raw: &RawFile, limit: usize) -> Result<(), AppError> {
    let current = root
        .read_raw(raw.relative_path(), limit)
        .map_err(|_| refused())?;
    if current.observation() != raw.observation() || current.bytes() != raw.bytes() {
        return Err(refused());
    }
    Ok(())
}
fn selections(root: &PrivateRoot) -> Result<Vec<NativeRuntimeSelection>, AppError> {
    let marker_raw = root
        .read_raw(".styx-native-root-v1.json", NATIVE_MARKER_BYTES)
        .map_err(|_| refused())?;
    let marker = native_state::decode_marker(marker_raw.bytes()).map_err(|_| refused())?;
    let state_raw = root
        .read_raw("state.json", NATIVE_STATE_BYTES)
        .map_err(|_| refused())?;
    let state = native_state::decode_state(state_raw.bytes(), &marker).map_err(|_| refused())?;
    let deployment = root
        .read_raw("deployment.json", NATIVE_STATE_BYTES)
        .map_err(|_| refused())?;
    if Sha256Digest::of_bytes(deployment.bytes()) != state.state().deployment_raw_sha256 {
        return Err(refused());
    }
    // Existing complete C07 read-only tip reader: no configuration writer,
    // recovery, adoption or runtime execution capability is acquired here.
    let selected = native_host_snapshot::validated_runtime_selection(root, &state, &marker)
        .map_err(|_| refused())?;
    // The complete committed C07 tip supplies the sole live runtime pointer.
    // Bootstrap/previous are immutable historical DATA, not implicit reopen or
    // rollback authority. The existing reader still validates the full chain.
    // Pending update/recovery custody is refused by App availability above.
    let result = vec![selected];
    reobserve(root, &marker_raw, NATIVE_MARKER_BYTES)?;
    reobserve(root, &state_raw, NATIVE_STATE_BYTES)?;
    reobserve(root, &deployment, NATIVE_STATE_BYTES)?;
    Ok(result)
}
struct Reference {
    scope: Arc<HostScope>,
    identity: RootIdentity,
    marker: RawFile,
    deployment: RawFile,
    selections: Vec<NativeRuntimeSelection>,
    release: Arc<VerifiedNativeRelease>,
}
impl Reference {
    fn open(scope: Arc<HostScope>, install: &Path) -> Result<Self, AppError> {
        scope.validate()?;
        outside(&scope.container.parent_path, install)?;
        outside(scope.state_dir(), install)?;
        let root = PrivateRoot::open(scope.state_dir()).map_err(|_| refused())?;
        let references = selections(&root)?;
        for selection in &references {
            outside(Path::new(&selection.payload_path), install)?;
            outside(Path::new(&selection.publisher_file), install)?;
        }
        let release = Arc::new(release::verify_selected(&references[0]).map_err(|_| refused())?);
        let result = Self {
            scope,
            identity: root.identity(),
            marker: root
                .read_raw(".styx-native-root-v1.json", NATIVE_MARKER_BYTES)
                .map_err(|_| refused())?,
            deployment: root
                .read_raw("deployment.json", NATIVE_STATE_BYTES)
                .map_err(|_| refused())?,
            selections: references,
            release,
        };
        result.validate(install)?;
        Ok(result)
    }
    fn validate(&self, install: &Path) -> Result<(), AppError> {
        self.scope.validate()?;
        let root = PrivateRoot::open(self.scope.state_dir()).map_err(|_| refused())?;
        if root.identity() != self.identity {
            return Err(refused());
        }
        outside(&self.scope.container.parent_path, install)?;
        outside(self.scope.state_dir(), install)?;
        reobserve(&root, &self.marker, NATIVE_MARKER_BYTES)?;
        reobserve(&root, &self.deployment, NATIVE_STATE_BYTES)?;
        if selections(&root)? != self.selections {
            return Err(refused());
        }
        for selected in &self.selections {
            outside(Path::new(&selected.payload_path), install)?;
            outside(Path::new(&selected.publisher_file), install)?;
        }
        self.release
            .revalidate_matches_selection(&self.selections[0])
            .map_err(|_| refused())
    }
}
struct SelectionInput {
    root: PrivateRoot,
    raw: RawFile,
    selection: NativeRuntimeSelection,
    release: VerifiedNativeRelease,
}
impl SelectionInput {
    fn open(path: &Path) -> Result<Self, AppError> {
        let root = PrivateRoot::open(path.parent().ok_or_else(refused)?).map_err(|_| refused())?;
        let raw = root
            .read_raw(path.file_name().ok_or_else(refused)?, NATIVE_STATE_BYTES)
            .map_err(|_| refused())?;
        let selection: NativeRuntimeSelection =
            serde_json::from_slice(raw.bytes()).map_err(|_| refused())?;
        let release = release::verify_selected(&selection).map_err(|_| refused())?;
        let result = Self {
            root,
            raw,
            selection,
            release,
        };
        result.validate()?;
        Ok(result)
    }
    fn validate(&self) -> Result<(), AppError> {
        reobserve(&self.root, &self.raw, NATIVE_STATE_BYTES)?;
        // The original signed App package is the current process's pinned
        // launch input. Keep it verified through final Quit; it is not the
        // C07 runtime pointer used after the outer App is replaced.
        self.release
            .revalidate_matches_selection(&self.selection)
            .map_err(|_| refused())
    }
}
struct Custody {
    scope: Arc<HostScope>,
    install: PathBuf,
    references: Vec<Reference>,
    selection_input: Option<SelectionInput>,
}
impl Custody {
    fn validate(&self) -> Result<(), AppError> {
        self.scope.validate()?;
        outside(&self.scope.container.parent_path, &self.install)?;
        for reference in &self.references {
            reference.validate(&self.install)?;
        }
        if let Some(selection) = &self.selection_input {
            selection.validate()?;
        }
        Ok(())
    }
}
pub(super) struct State {
    input: PrepareInput,
    ticket: String,
    status: &'static str,
    custody: Arc<Custody>,
}
impl State {
    pub(super) fn fenced(&self) -> bool {
        self.status != "cancelled"
    }
    fn report(&self) -> Value {
        json!({"schema":1,"status":self.status,"ticketId":self.ticket,"requestId":self.input.request_id,
            "operation":self.input.operation,"installRoot":self.input.install_root,
            "packageSha256":self.input.package_sha256,"candidatePackageSha256":self.input.candidate_package_sha256,
            "scope":"original_app","runtimeReferences":if self.status == "unknown" {"unconfirmed"} else {"outside_install_root"},"statePreserved":true,
            "operationsReplayed":false,"requiresOwnedQuit":true})
    }
}
async fn checked<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, AppError> + Send + 'static,
) -> Result<T, AppError> {
    static READERS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
    let permit = READERS
        .try_acquire()
        .map_err(|_| AppError("app_maintenance_busy"))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work()
    })
    .await
    .map_err(|_| refused())?
}
impl HostApp {
    pub(super) fn maintenance_fenced(&self) -> bool {
        self.maintenance.as_ref().is_some_and(State::fenced)
    }
    pub(super) fn maintenance_quit_allowed(&self) -> bool {
        self.maintenance
            .as_ref()
            .is_none_or(|state| matches!(state.status, "prepared" | "cancelled"))
    }
    pub(super) fn maintenance_status(&self) -> Value {
        json!({"maintenance":self.maintenance.as_ref().map(State::report)
            .unwrap_or_else(|| json!({"schema":1,"status":"not_started","operationsReplayed":false}))})
    }
    pub(super) async fn prepare_maintenance(
        &mut self,
        input: PrepareInput,
    ) -> Result<Value, AppError> {
        self.available()?;
        if self.maintenance_fenced() || !self.login.settled() {
            return Err(AppError("app_maintenance_original_operation_required"));
        }
        if input.schema != 1
            || !input.authorize
            || input.request_id.len() != 32
            || !input
                .request_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || (cfg!(target_os = "windows") && input.package_sha256.is_none())
            || (cfg!(target_os = "windows")
                && input.operation == MaintenanceOperation::Upgrade
                && input.candidate_package_sha256.is_none())
            || (input.operation == MaintenanceOperation::Uninstall
                && input.candidate_package_sha256.is_some())
        {
            return Err(AppError("app_maintenance_input_invalid"));
        }
        if input.operation == MaintenanceOperation::Uninstall {
            self.login
                .require_unregistered(input.login_observation.as_ref(), std::env::consts::OS)?;
        }
        let scope = self.scope.clone();
        let mut scopes = vec![scope.clone()];
        if let Some(gateway) = &self.local_gateway
            && gateway.scope.state_dir() != scope.state_dir()
        {
            scopes.push(gateway.scope.clone());
        }
        let install_path = input.install_root.clone();
        let selection_file = self.runtime_selection_file.clone();
        let custody = checked(move || {
            let install = canonical(&install_path)?;
            outside(&scope.container.parent_path, &install)?;
            let mut references = Vec::new();
            for scope in scopes {
                scope.validate()?;
                if scope.root.get().is_some() {
                    references.push(Reference::open(scope, &install)?);
                }
            }
            let selection_input = selection_file
                .as_deref()
                .map(SelectionInput::open)
                .transpose()?;
            let custody = Arc::new(Custody {
                scope,
                install,
                references,
                selection_input,
            });
            custody.validate()?;
            Ok(custody)
        })
        .await?;
        self.scope.validate()?;
        self.maintenance = Some(State {
            input,
            ticket: uuid::Uuid::new_v4().simple().to_string(),
            status: "prepared",
            custody,
        });
        Ok(self.maintenance_status())
    }
    pub(super) async fn cancel_maintenance(
        &mut self,
        input: CancelInput,
    ) -> Result<Value, AppError> {
        let state = self
            .maintenance
            .as_ref()
            .filter(|state| {
                input.authorize && state.ticket == input.ticket_id && state.status == "prepared"
            })
            .ok_or(AppError("app_maintenance_original_ticket_required"))?;
        let custody = state.custody.clone();
        if let Err(error) = checked(move || custody.validate()).await {
            self.maintenance
                .as_mut()
                .expect("original pending maintenance")
                .status = "unknown";
            return Err(error);
        }
        self.maintenance
            .as_mut()
            .expect("original pending maintenance")
            .status = "cancelled";
        Ok(self.maintenance_status())
    }
    pub(super) async fn maintenance_quit_result(
        &mut self,
        result: Result<Value, AppError>,
    ) -> Result<Value, AppError> {
        if !self.maintenance_fenced() {
            return result;
        }
        let mut result = match result {
            Ok(result) => result,
            Err(error) => {
                self.maintenance
                    .as_mut()
                    .expect("pending maintenance")
                    .status = "unknown";
                return Err(error);
            }
        };
        let state = self.maintenance.as_ref().expect("pending maintenance");
        if state.status != "prepared"
            || result["quit"]["status"] != "ready_to_quit"
            || result["quit"]["ticketId"]
                .as_str()
                .is_none_or(|v| v.len() != 32)
        {
            return Err(AppError("app_maintenance_exit_unconfirmed"));
        }
        let custody = state.custody.clone();
        if let Err(error) = checked(move || custody.validate()).await {
            self.maintenance
                .as_mut()
                .expect("pending maintenance")
                .status = "unknown";
            return Err(error);
        }
        let state = self.maintenance.as_mut().expect("pending maintenance");
        state.status = "ready_to_exit";
        result["maintenance"] = state.report();
        Ok(result)
    }
}

#[cfg(all(test, target_os = "linux", target_env = "gnu"))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    struct Fixture {
        top: PathBuf,
        parent: PathBuf,
        install: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let top = std::env::temp_dir().join(format!(
                "styx-app-maintenance-{}",
                uuid::Uuid::new_v4().simple()
            ));
            std::fs::create_dir(&top).unwrap();
            std::fs::set_permissions(&top, std::fs::Permissions::from_mode(0o700)).unwrap();
            let parent = top.join("private-app");
            let install = top.join("Styx.app");
            for p in [&parent, &install] {
                std::fs::create_dir(p).unwrap();
                std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            Self {
                top,
                parent,
                install,
            }
        }
        async fn app(&self) -> HostApp {
            HostApp::open(
                &self.parent.join("profile"),
                &self.parent.join("app-input.json"),
            )
            .await
            .unwrap()
        }
        fn prepare(&self, request: &str) -> Box<serde_json::value::RawValue> {
            serde_json::value::to_raw_value(&json!({"schema":1,"authorize":true,"operation":"upgrade","requestId":request,"installRoot":self.install,"packageSha256":null,"candidatePackageSha256":null,"loginObservation":null})).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.top).unwrap();
        }
    }
    fn raw(value: Value) -> Box<serde_json::value::RawValue> {
        serde_json::value::to_raw_value(&value).unwrap()
    }
    #[tokio::test]
    async fn maintenance_requires_same_live_owner_ticket_and_final_normal_quit() {
        let _serial = SERIAL.lock().await;
        let f = Fixture::new();
        let mut app = f.app().await;
        let prepared = app
            .dispatch(Operation::PrepareAppMaintenance, f.prepare(&"1".repeat(32)))
            .await
            .unwrap();
        let ticket = prepared["maintenance"]["ticketId"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(prepared["maintenance"]["status"], "prepared");
        assert_eq!(
            app.dispatch(Operation::Connect, raw(json!({})))
                .await
                .unwrap_err()
                .code(),
            "app_maintenance_original_operation_required"
        );
        assert!(
            app.dispatch(
                Operation::CancelAppMaintenance,
                raw(json!({"authorize":true,"ticketId":"2".repeat(32)}))
            )
            .await
            .is_err()
        );
        assert_eq!(
            app.maintenance_status()["maintenance"]["status"],
            "prepared"
        );
        let cancelled = app
            .dispatch(
                Operation::CancelAppMaintenance,
                raw(json!({"authorize":true,"ticketId":ticket})),
            )
            .await
            .unwrap();
        assert_eq!(cancelled["maintenance"]["status"], "cancelled");
        assert!(
            app.dispatch(
                Operation::CancelAppMaintenance,
                raw(json!({"authorize":true,"ticketId":ticket}))
            )
            .await
            .is_err()
        );
        let next = app
            .dispatch(Operation::PrepareAppMaintenance, f.prepare(&"3".repeat(32)))
            .await
            .unwrap();
        assert_ne!(next["maintenance"]["ticketId"], ticket);
        let quit = app
            .dispatch(Operation::QuitAdmission, raw(json!({})))
            .await
            .unwrap();
        assert_eq!(quit["quit"]["status"], "ready_to_quit");
        assert_eq!(quit["maintenance"]["status"], "ready_to_exit");
        assert_eq!(
            quit["maintenance"]["ticketId"],
            next["maintenance"]["ticketId"]
        );
        assert_ne!(quit["quit"]["ticketId"], next["maintenance"]["ticketId"]);
        let original_quit = app.quit_ticket.clone();
        assert_eq!(
            app.dispatch(Operation::QuitAdmission, raw(json!({})))
                .await
                .unwrap_err()
                .code(),
            "app_maintenance_original_operation_required"
        );
        assert_eq!(app.quit_ticket, original_quit);
        drop(app);
    }
    #[tokio::test]
    async fn replaced_original_app_root_cannot_finish_or_cancel_pending_maintenance() {
        let _serial = SERIAL.lock().await;
        let f = Fixture::new();
        let mut app = f.app().await;
        let prepared = app
            .dispatch(Operation::PrepareAppMaintenance, f.prepare(&"4".repeat(32)))
            .await
            .unwrap();
        let old = f.top.join("original-retained-app");
        std::fs::rename(&f.parent, &old).unwrap();
        std::fs::create_dir(&f.parent).unwrap();
        std::fs::set_permissions(&f.parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            app.dispatch(Operation::QuitAdmission, raw(json!({})))
                .await
                .is_err()
        );
        assert_eq!(app.maintenance_status()["maintenance"]["status"], "unknown");
        assert!(
            app.dispatch(
                Operation::CancelAppMaintenance,
                raw(json!({"authorize":true,"ticketId":prepared["maintenance"]["ticketId"]}))
            )
            .await
            .is_err()
        );
        assert_eq!(app.maintenance_status()["maintenance"]["status"], "unknown");
        drop(app);
    }
    #[tokio::test]
    async fn install_root_cannot_contain_preserved_app_state() {
        let _serial = SERIAL.lock().await;
        let f = Fixture::new();
        let mut app = f.app().await;
        let mut input: Value = serde_json::from_str(f.prepare(&"5".repeat(32)).get()).unwrap();
        input["installRoot"] = json!(f.parent);
        assert_eq!(
            app.dispatch(Operation::PrepareAppMaintenance, raw(input))
                .await
                .unwrap_err()
                .code(),
            "app_maintenance_runtime_in_install_root"
        );
        assert!(!app.maintenance_fenced());
        drop(app);
    }
    #[test]
    fn lexical_external_alias_is_not_an_external_runtime_reference() {
        let f = Fixture::new();
        let internal = f.install.join("runtime");
        std::fs::create_dir(&internal).unwrap();
        let alias = f.top.join("external-looking-runtime");
        std::os::unix::fs::symlink(&internal, &alias).unwrap();
        assert_eq!(
            outside(&alias, &canonical(&f.install).unwrap())
                .unwrap_err()
                .code(),
            "app_maintenance_runtime_in_install_root"
        );
    }
}
