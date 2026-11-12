//! Current read-only startup observation. Recovery and mutations keep their
//! original coordinators; a historical observation never resumes a transaction.
use super::runtime_update::{OriginalInput, SelectionPin, root_digest, same_file};
use super::*;
use crate::store::{
    ExecutionLeaseGuard, RawFile, management::ManagementInventory,
    native_host_snapshot::NativeHostSnapshot,
};
use std::collections::BTreeSet;
use styx_contracts::{identity::TransactionId, management::DurableStage};

fn committed(inventory: &ManagementInventory, id: &TransactionId, sequence: u64) -> bool {
    inventory.orphans.is_empty()
        && inventory.transactions.iter().any(|transaction| {
            transaction.intent.transaction_id == *id
                && transaction.intent.sequence == sequence
                && transaction
                    .phase_receipts
                    .last()
                    .is_some_and(|receipt| receipt.stage == DurableStage::Committed)
        })
}
fn names(path: &Path) -> Result<BTreeSet<std::ffi::OsString>, AppError> {
    bounded_names(path, 64)
}
fn bounded_names(path: &Path, limit: usize) -> Result<BTreeSet<std::ffi::OsString>, AppError> {
    let mut names = BTreeSet::new();
    for entry in
        std::fs::read_dir(path).map_err(|_| AppError("app_runtime_original_input_invalid"))?
    {
        if names.len() >= limit {
            return Err(AppError("app_runtime_input_budget"));
        }
        names.insert(
            entry
                .map_err(|_| AppError("app_runtime_original_input_invalid"))?
                .file_name(),
        );
    }
    Ok(names)
}

/// Historical DATA for another physical root. This never resumes its updates
/// or changes its desired state. Its existing execution lease remains held
/// until every original input and C07 file has been revalidated.
struct RetiredHistoryRoot {
    path: PathBuf,
    root: PrivateRoot,
    lease: ExecutionLeaseGuard,
    pins: Vec<RawFile>,
    journal: PrivateRoot,
    journal_names: BTreeSet<std::ffi::OsString>,
    journal_pins: Vec<RawFile>,
    inventory: ManagementInventory,
}
impl RetiredHistoryRoot {
    fn open(path: PathBuf) -> Result<Self, AppError> {
        const JOURNAL: &str = ".styx-management-journal-v1";
        const MAX: usize = 1024 * 1024;
        let changed = |_| AppError("app_runtime_original_input_changed");
        let root = PrivateRoot::open(&path).map_err(changed)?;
        let lease = root.try_existing_execution_lease().map_err(changed)?;
        let pins = [
            ".styx-native-root-v1.json",
            "state.json",
            "deployment.json",
            ".styx-configuration-writer.lock",
        ]
        .into_iter()
        .map(|name| root.read_raw(name, MAX).map_err(changed))
        .collect::<Result<Vec<_>, _>>()?;
        let journal_path = path.join(JOURNAL);
        let journal = PrivateRoot::open(&journal_path).map_err(changed)?;
        let budget = crate::store::enrollment::JournalBudget::default();
        let journal_names = bounded_names(&journal_path, budget.max_files)?;
        let mut journal_pins = Vec::new();
        let mut total = 0usize;
        for name in &journal_names {
            let pin = journal.read_raw(Path::new(name), MAX).map_err(changed)?;
            total = total
                .checked_add(pin.bytes().len())
                .filter(|total| *total <= budget.max_bytes)
                .ok_or(AppError("app_runtime_input_budget"))?;
            journal_pins.push(pin);
        }
        // The original native parser proves the complete canonical C07 chain;
        // names or a retired suffix alone are never completion evidence.
        let observed = crate::store::native_observation::read(&path)
            .map_err(|_| AppError("app_runtime_original_input_changed"))?;
        if !observed.inventory.orphans.is_empty()
            || observed.inventory.transactions.iter().any(|t| {
                t.phase_receipts
                    .last()
                    .is_none_or(|r| r.stage != DurableStage::Committed)
            })
        {
            return Err(AppError("app_runtime_original_input_changed"));
        }
        let held = Self {
            path,
            root,
            lease,
            pins,
            journal,
            journal_names,
            journal_pins,
            inventory: observed.inventory,
        };
        held.validate()?;
        Ok(held)
    }
    fn validate(&self) -> Result<(), AppError> {
        let changed = |_| AppError("app_runtime_original_input_changed");
        let path = self.path.join(".styx-management-journal-v1");
        if PrivateRoot::open(&self.path).map_err(changed)?.identity() != self.root.identity()
            || PrivateRoot::open(&path).map_err(changed)?.identity() != self.journal.identity()
            || bounded_names(
                &path,
                crate::store::enrollment::JournalBudget::default().max_files,
            )? != self.journal_names
        {
            return Err(AppError("app_runtime_original_input_changed"));
        }
        self.lease.validate().map_err(changed)?;
        for (root, pins) in [
            (&self.root, &self.pins),
            (&self.journal, &self.journal_pins),
        ] {
            for pin in pins {
                let after = root
                    .read_raw(pin.relative_path(), 1024 * 1024)
                    .map_err(changed)?;
                if after.observation() != pin.observation() || after.bytes() != pin.bytes() {
                    return Err(AppError("app_runtime_original_input_changed"));
                }
            }
        }
        Ok(())
    }
}

struct RetiredHistoryPair {
    host: RetiredHistoryRoot,
    gateway: RetiredHistoryRoot,
}
impl RetiredHistoryPair {
    fn matches(&self, input: &OriginalInput) -> Result<bool, AppError> {
        Ok(input.roles.len() == 2
            && root_digest(&self.host.root)? == input.roles[0].root_sha256
            && root_digest(&self.gateway.root)? == input.roles[1].root_sha256)
    }
    fn prove(&self, input: &OriginalInput) -> Result<(), AppError> {
        if !self.matches(input)?
            || input
                .roles
                .iter()
                .zip([&self.host, &self.gateway])
                .any(|(role, root)| {
                    !committed(
                        &root.inventory,
                        &role.select_transaction,
                        role.select_sequence,
                    )
                })
        {
            return Err(AppError("app_runtime_original_input_changed"));
        }
        Ok(())
    }
}

impl HostApp {
    pub(super) fn completed_runtime_history(
        &self,
        profile: &NativeHostSnapshot,
    ) -> Result<bool, AppError> {
        if self
            .scope
            .container
            .parent
            .ensure_absent("runtime-updates")
            .is_ok()
        {
            return Ok(true);
        }
        let directory = self.scope.container.parent_path.join("runtime-updates");
        let held = PrivateRoot::open(&directory)
            .map_err(|_| AppError("app_runtime_original_input_invalid"))?;
        let original_names = names(&directory)?;
        let inventory = profile
            .management_inventory()
            .map_err(|_| AppError("app_startup_observation_changed"))?;
        let container = root_digest(&self.scope.container.parent)?;
        let root = root_digest(
            self.scope
                .root
                .get()
                .ok_or(AppError("app_not_configured"))?,
        )?;
        let mut inputs = Vec::new();
        let mut selections = Vec::new();
        let mut retired: Vec<RetiredHistoryPair> = Vec::new();
        let mut retired_namespace = None;
        for name in &original_names {
            let name = name
                .to_str()
                .ok_or(AppError("app_runtime_original_input_invalid"))?;
            let id = name
                .strip_suffix(".json")
                .and_then(|id| TransactionId::try_from(id).ok())
                .ok_or(AppError("app_runtime_original_input_invalid"))?;
            let raw = held
                .read_raw(name, 65536)
                .map_err(|_| AppError("app_runtime_original_input_invalid"))?;
            let input: OriginalInput = serde_json::from_slice(raw.bytes())
                .map_err(|_| AppError("app_runtime_original_input_invalid"))?;
            input.validate_shape(&id)?;
            if input.container_sha256 != container {
                return Err(AppError("app_runtime_original_input_changed"));
            }
            let selection = SelectionPin::open(
                &self
                    .scope
                    .container
                    .parent_path
                    .join("runtime-versions")
                    .join(&input.selection_file),
            )?;
            if selection.selection != input.selection
                || styx_contracts::identity::Sha256Digest::of_bytes(selection.file.bytes())
                    != input.selection_sha256
            {
                return Err(AppError("app_runtime_original_input_changed"));
            }
            if input.roles.len() == 1 {
                let role = &input.roles[0];
                if role.root_sha256 != root || role.gateway {
                    return Err(AppError("app_runtime_original_input_changed"));
                }
                if !committed(&inventory, &role.select_transaction, role.select_sequence) {
                    return Ok(false);
                }
            } else {
                // Live split composition keeps its original recovery path.
                if self.scope.gateway_sibling()?.root.get().is_some() {
                    return Ok(false);
                }
                if input.roles[0].root_sha256 == root {
                    return Err(AppError("app_runtime_original_input_changed"));
                }
                if !retired
                    .iter()
                    .any(|pair| pair.matches(&input).unwrap_or(false))
                {
                    let parent = &self.scope.container.parent_path;
                    let namespace = names(parent)?;
                    let host_name = self
                        .scope
                        .state_dir
                        .file_name()
                        .and_then(|s| s.to_str())
                        .ok_or(AppError("app_runtime_original_input_changed"))?;
                    let prefix = format!("{host_name}.retired-");
                    let mut found = None;
                    for name in &namespace {
                        let Some(suffix) = name.to_str().and_then(|s| s.strip_prefix(&prefix))
                        else {
                            continue;
                        };
                        if suffix.is_empty()
                            || !namespace.contains(std::ffi::OsStr::new(&format!(
                                "gateway.retired-{suffix}"
                            )))
                        {
                            continue;
                        }
                        let host_path = parent.join(name);
                        let gateway_path = parent.join(format!("gateway.retired-{suffix}"));
                        let Ok(host) = PrivateRoot::open(&host_path) else {
                            continue;
                        };
                        let Ok(gateway) = PrivateRoot::open(&gateway_path) else {
                            continue;
                        };
                        if root_digest(&host)? != input.roles[0].root_sha256
                            || root_digest(&gateway)? != input.roles[1].root_sha256
                        {
                            continue;
                        }
                        found = Some(RetiredHistoryPair {
                            host: RetiredHistoryRoot::open(host_path)?,
                            gateway: RetiredHistoryRoot::open(gateway_path)?,
                        });
                        break;
                    }
                    retired.push(found.ok_or(AppError("app_runtime_original_input_changed"))?);
                    if retired_namespace
                        .as_ref()
                        .is_some_and(|before| before != &namespace)
                    {
                        return Err(AppError("app_runtime_original_input_changed"));
                    }
                    retired_namespace = Some(namespace);
                }
                retired
                    .iter()
                    .find(|pair| pair.matches(&input).unwrap_or(false))
                    .ok_or(AppError("app_runtime_original_input_changed"))?
                    .prove(&input)?;
            }
            inputs.push(raw);
            selections.push(selection);
        }
        // The one validated journal observation is DATA. Detect any change to
        // its namespace, original inputs or original selection files before use.
        if names(&directory)? != original_names
            || PrivateRoot::open(&directory)
                .map_err(|_| AppError("app_runtime_original_input_changed"))?
                .identity()
                != held.identity()
        {
            return Err(AppError("app_runtime_original_input_changed"));
        }
        for input in &inputs {
            same_file(&held, input)?;
        }
        for selection in &selections {
            selection.validate()?;
        }
        for pair in &retired {
            pair.host.validate()?;
            pair.gateway.validate()?;
        }
        if retired_namespace.is_some_and(|before| {
            names(&self.scope.container.parent_path).ok().as_ref() != Some(&before)
        }) {
            return Err(AppError("app_runtime_original_input_changed"));
        }
        profile
            .revalidate()
            .map_err(|_| AppError("app_startup_observation_changed"))?;
        self.scope.validate()?;
        Ok(true)
    }
    pub(super) async fn try_ready_startup(&mut self) -> Result<bool, AppError> {
        // Existing service clients and split local Gateway composition keep
        // their original path. No sibling is created or paired here.
        if self.scope.gateway_sibling()?.root.get().is_some() {
            return Ok(false);
        }
        if let Some(d) = &self.startup_diagnostic {
            d.report("app_current_observation_begin");
        }
        let scope = self.scope.clone();
        let profile = match tokio::task::spawn_blocking(move || {
            NativeHostSnapshot::observe_for_app(scope.state_dir(), scope.clone())
        })
        .await
        {
            Ok(Ok(profile)) => Arc::new(profile),
            // Incomplete/pending roots enter the original full inspector and
            // original recovery/fencing path; no cached success substitutes it.
            _ => return Ok(false),
        };
        if !self.completed_runtime_history(&profile)? {
            return Ok(false);
        }
        let state = profile.canonical();
        self.configuration = Some(native::NativeManagementReport {
            schema: 1,
            configuration_only: true,
            operation: "app_current_observation",
            runtime_health: "not_observed",
            revision: state.state().revision,
            canonical_state_sha256: state.raw_sha256(),
            desired: state.state().desired.clone(),
            // observe_for_app requires the entire completed canonical C07 chain.
            admission_fenced: false,
            transaction: None,
        });
        match native_join::inspect_for_app_retained(self.scope.clone(), profile.verified_release())
            .await
        {
            Ok(report) => {
                if profile.revalidate().is_err() {
                    self.unknown = true;
                    self.enrollment = Some(
                        json!({"status":"incomplete","error":"app_startup_observation_changed"}),
                    );
                    return Ok(true);
                }
                self.native_computer_requested = Some(report.computer_requested);
                self.native_runtime = Some(report.verified_runtime.clone());
                self.enrollment = Some(
                    serde_json::to_value(report).map_err(|_| AppError("app_response_invalid"))?,
                );
                self.startup_profile = Some(profile);
            }
            Err(error) => {
                let code = self.join_error(error).code();
                self.unknown = true;
                self.enrollment = Some(json!({"status":"incomplete","error":code}));
            }
        }
        if let Some(d) = &self.startup_diagnostic {
            d.report("app_current_observation_ready");
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::management::ManagementTransactionObservation;
    use styx_contracts::{
        identity::Sha256Digest,
        management::{DesiredStateCommit, JournalReceipt, ReaderContract},
    };

    #[cfg(any(all(target_os = "linux", target_env = "gnu"), target_os = "macos"))]
    fn retirement_test_parent() -> PathBuf {
        use std::os::unix::fs::DirBuilderExt;
        let path = std::env::temp_dir().join(format!("styx-retire-test-{}", uuid::Uuid::new_v4()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        path
    }
    #[cfg(target_os = "windows")]
    fn retirement_test_parent() -> PathBuf {
        let base = PathBuf::from(
            std::env::var("STYX_RETIRE_FS_PARENT")
                .expect("STYX_RETIRE_FS_PARENT must name an existing private test parent"),
        );
        let root = PrivateRoot::open(&base).expect("private test parent required");
        let name = format!("test-{}", uuid::Uuid::new_v4().simple());
        drop(
            root.create_setup_journal_child(&name)
                .expect("private test child"),
        );
        base.join(name)
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "requires STYX_TEST_RETAINED_HISTORY_PROFILE; existing-only read-only native profile and closed retired history"]
    fn retained_history_existing_profile_read_only() {
        let path = PathBuf::from(std::env::var("STYX_TEST_RETAINED_HISTORY_PROFILE").unwrap());
        assert!(path.is_absolute() && path.is_dir());
        let scope = Arc::new(HostScope::open(&path).unwrap());
        let profile = NativeHostSnapshot::observe_for_app(&path, scope.clone()).unwrap();
        let (status, observed) = watch::channel(ConnectionStatus::stopped());
        // Construct only the observer. HostApp::open_native would also inspect
        // enrollment/fallback coordinators, which this reference must not run.
        let app = HostApp {
            scope,
            status,
            observed,
            deployment_file: PathBuf::new(),
            retire_failure: None,
            runtime_update: None,
            service: None,
            local_gateway: None,
            resume_local_available: false,
            configuration: None,
            runtime_selection_file: None,
            inspected_join: None,
            enrollment: None,
            native_computer_requested: None,
            native_runtime: None,
            input_writer: None,
            running: None,
            cleanup: None,
            retained: None,
            join_retry: None,
            unknown: false,
            quit_ticket: None,
            login: login::Login::default(),
            maintenance: None,
            startup_diagnostic: None,
            startup_profile: None,
        };
        assert!(app.completed_runtime_history(&profile).unwrap());
        profile.revalidate().unwrap();
        app.scope.validate().unwrap();
    }

    // Real signed payload and original dual-role update/retirement. The new
    // empty private root exercises cold-open scope validation only; it is not
    // a completed Host enrollment or native acceptance.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires STYX_HISTORY_C29 and STYX_HISTORY_C30 signed payload directories; disposable local TLS"]
    async fn retired_dual_history_archives_before_new_root_cold_open() {
        use std::{
            fs,
            io::Write,
            os::unix::fs::{DirBuilderExt, OpenOptionsExt},
        };
        fn dir(path: &Path) {
            fs::DirBuilder::new().mode(0o700).create(path).unwrap();
        }
        fn write(path: &Path, bytes: &[u8]) {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .unwrap();
            f.write_all(bytes).unwrap();
            f.sync_all().unwrap();
        }
        fn raw(value: Value) -> Box<serde_json::value::RawValue> {
            serde_json::value::to_raw_value(&value).unwrap()
        }
        fn selection(path: &Path) -> styx_contracts::native_management::NativeRuntimeSelection {
            let publisher = path.join("publisher.pem");
            let pin =
                crate::crypto::PublisherVerifyingKey::from_spki_pem(&fs::read(&publisher).unwrap())
                    .unwrap()
                    .fingerprint()
                    .unwrap();
            crate::release::verify(&path.join("payload"), &publisher, &pin)
                .unwrap()
                .runtime_selection()
                .unwrap()
        }
        async fn wait(app: &mut HostApp, target: &str) {
            tokio::time::timeout(Duration::from_secs(150), async {
                loop {
                    let status = app
                        .dispatch(Operation::RuntimeUpdateStatus, raw(json!({})))
                        .await
                        .unwrap();
                    let phase = status["runtimeUpdate"]["status"].as_str().unwrap();
                    assert_ne!(phase, "unknown", "runtime update: {status}");
                    if phase == target {
                        break;
                    }
                    assert!(matches!(phase, "staging" | "updating"));
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            })
            .await
            .unwrap();
        }
        let top =
            std::env::temp_dir().join(format!("styx-retired-history-{}", uuid::Uuid::new_v4()));
        dir(&top);
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(top.clone());
        let parent = top.join("app");
        dir(&parent);
        let old = selection(Path::new(&std::env::var("STYX_HISTORY_C29").unwrap()));
        let new = selection(Path::new(&std::env::var("STYX_HISTORY_C30").unwrap()));
        let old_selection = top.join("old.json");
        write(&old_selection, &serde_json::to_vec(&old).unwrap());
        let new_selection = top.join("new.json");
        write(&new_selection, &serde_json::to_vec(&new).unwrap());
        let profile = parent.join("profile");
        let mut app = HostApp::open_native(&profile, &old_selection)
            .await
            .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        app.create_local(LocalInput {
            label: "Disposable history".into(),
            computer: false,
            browser: false,
            browser_channel: None,
            persist_login: false,
            port,
            lan_address: None,
            allow_remote_hosts: false,
        })
        .await
        .unwrap();
        app.settle_all().await.unwrap();
        app.set_desired(NativeRunDesired::Stopped).await.unwrap();
        drop(app);
        let mut app = HostApp::open_native(&profile, &new_selection)
            .await
            .unwrap();
        app.dispatch(Operation::StageRuntime, raw(json!({"authorize":true})))
            .await
            .unwrap();
        wait(&mut app, "staged").await;
        app.dispatch(Operation::UpdateRuntime, raw(json!({"authorize":true,"transactionId":format!("history-{}", uuid::Uuid::new_v4().simple())}))).await.unwrap();
        wait(&mut app, "committed").await;
        let old_root = root_digest(app.scope.root.get().unwrap()).unwrap();
        let updates = parent.join("runtime-updates");
        let entries: Vec<_> = fs::read_dir(&updates)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(entries.len(), 1);
        let before = fs::read(&entries[0]).unwrap();
        let original: OriginalInput = serde_json::from_slice(&before).unwrap();
        assert_eq!(original.roles.len(), 2);
        app.dispatch(Operation::QuitAdmission, raw(json!({})))
            .await
            .unwrap();
        drop(app);
        // Control: completed history remains readable while original roots exist.
        let mut app = HostApp::open_native(&profile, &new_selection)
            .await
            .unwrap();
        // A foreign/invalid history entry must not be swept into a new receipt.
        let foreign = updates.join("foreign.json");
        write(&foreign, b"{}");
        let refused = app
            .dispatch(
                Operation::RetireRole,
                raw(json!({"allowOtherDevices":false})),
            )
            .await
            .unwrap_err();
        assert_eq!(refused.code(), "role_retire_history_unproven");
        assert!(profile.is_dir() && parent.join("gateway").is_dir());
        assert!(!parent.join(".styx-app-role-retire-v1").exists());
        fs::remove_file(&foreign).unwrap();
        let retired = app
            .dispatch(
                Operation::RetireRole,
                raw(json!({"allowOtherDevices":false})),
            )
            .await
            .unwrap();
        assert_eq!(retired["retirement"]["outcome"], "retired");
        drop(app);
        let history = retired["retirement"]["retired"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| {
                p["oldPath"]
                    .as_str()
                    .is_some_and(|p| p.ends_with("/runtime-updates"))
            })
            .unwrap();
        let archived = PathBuf::from(history["newPath"].as_str().unwrap());
        assert!(!updates.exists());
        assert_eq!(
            fs::read(archived.join(entries[0].file_name().unwrap())).unwrap(),
            before
        );
        let ledger = parent.join(".styx-app-role-retire-v1");
        let receipt = fs::read_dir(&ledger)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        assert!(parent.join("runtime-versions").is_dir());
        assert!(!profile.exists());
        dir(&profile);
        let root = PrivateRoot::open(&profile).unwrap();
        assert_ne!(root_digest(&root).unwrap(), old_root);
        drop(root);
        assert_eq!(
            fs::read(archived.join(entries[0].file_name().unwrap())).unwrap(),
            before
        );
        // Clean-parent control uses the same empty-root cold-open entry.
        let clean = top.join("clean");
        dir(&clean);
        dir(&clean.join("profile"));
        let clean_result = HostApp::open_native(&clean.join("profile"), &new_selection).await;
        let clean_code = clean_result.as_ref().err().map(AppError::code);
        assert_ne!(clean_code, Some("app_runtime_input_changed"));
        assert_ne!(clean_code, Some("app_role_retire_unknown"));
        drop(clean_result);
        let reopened = HostApp::open_native(&profile, &new_selection).await;
        assert_eq!(reopened.as_ref().err().map(AppError::code), clean_code);
        drop(reopened);
        // Completed records remain valid if an owner later removes old archives.
        fs::remove_dir_all(&archived).unwrap();
        let after_archive_removal = HostApp::open_native(&profile, &new_selection).await;
        assert_eq!(
            after_archive_removal.as_ref().err().map(AppError::code),
            clean_code
        );
        drop(after_archive_removal);
        fs::write(
            receipt.join("done"),
            br#"{"schema":1,"begin_sha256":"fake-test-secret"}"#,
        )
        .unwrap();
        let tampered = HostApp::open_native(&profile, &new_selection).await;
        assert_eq!(
            tampered.as_ref().err().map(AppError::code),
            Some("app_role_retire_unknown")
        );
        drop(tampered);
    }

    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "macos",
        target_os = "windows"
    ))]
    #[test]
    fn incomplete_retirement_journal_fences_before_root_open() {
        use std::fs;
        let parent = retirement_test_parent();
        let root = PrivateRoot::open(&parent).unwrap();
        let ledger = root
            .create_setup_journal_child(".styx-app-role-retire-v1")
            .unwrap();
        // An empty ledger predates all actions and remains neutral.
        let scope = HostScope::open(&parent.join("profile")).unwrap();
        drop(scope);
        let entry = ledger
            .create_setup_journal_child("20261111T120000Z")
            .unwrap();
        entry
            .create_setup_export("begin".as_ref(), b"{}\n")
            .unwrap();
        assert_eq!(
            HostScope::open(&parent.join("profile"))
                .err()
                .map(|e| e.code()),
            Some("app_role_retire_unknown")
        );
        assert!(!parent.join("profile").exists());
        drop(entry);
        drop(ledger);
        drop(root);
        fs::remove_dir_all(parent).unwrap();
    }

    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "macos",
        target_os = "windows"
    ))]
    #[test]
    fn interrupted_retirement_does_not_resume_or_admit_new_root() {
        use std::fs;
        let parent = retirement_test_parent();
        let profile = parent.join("profile");
        let root = PrivateRoot::open(&parent).unwrap();
        drop(root.create_setup_journal_child("profile").unwrap());
        let mut prepared =
            crate::management::role_retire::prepare(Some(&profile), None, Default::default())
                .unwrap();
        let input = parent.join("app-join-input-v1.json");
        drop(
            root.create_setup_export("app-join-input-v1.json".as_ref(), b"test")
                .unwrap(),
        );
        prepared.add_input(&input).unwrap();
        let error = prepared
            .retire_app_fault_after(&root, &parent, "profile", 1)
            .unwrap_err();
        assert_eq!(error.report.outcome, "unknown");
        assert!(!profile.exists() && input.exists());
        assert_eq!(
            HostScope::open(&profile).err().map(|e| e.code()),
            Some("app_role_retire_unknown")
        );
        assert!(input.exists());
        drop(root);
        fs::remove_dir_all(parent).unwrap();
    }

    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    #[test]
    fn root_changed_after_retirement_begin_is_unknown_and_fenced() {
        let parent = retirement_test_parent();
        let root = PrivateRoot::open(&parent).unwrap();
        drop(root.create_setup_journal_child("profile").unwrap());
        let profile = parent.join("profile");
        let prepared =
            crate::management::role_retire::prepare(Some(&profile), None, Default::default())
                .unwrap();
        let error = prepared
            .retire_app_fault_after(&root, &parent, "profile", usize::MAX)
            .unwrap_err();
        assert_eq!(error.code, "role_retire_completion_unknown");
        assert_eq!(error.report.outcome, "unknown");
        assert!(error.report.restart_required);
        assert_eq!(
            HostScope::open(&profile).err().map(|e| e.code()),
            Some("app_role_retire_unknown")
        );
        assert!(parent.join("test-root-changed").is_dir());
        drop(root);
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "macos",
        target_os = "windows"
    ))]
    #[test]
    fn completed_retirement_fence_survives_archive_removal() {
        let parent = retirement_test_parent();
        let root = PrivateRoot::open(&parent).unwrap();
        drop(root.create_setup_journal_child("profile").unwrap());
        let profile = parent.join("profile");
        let prepared =
            crate::management::role_retire::prepare(Some(&profile), None, Default::default())
                .unwrap();
        let report = prepared.retire_app(&root, &parent, "profile").unwrap();
        assert_eq!(report.outcome, "retired");
        let archived = report.retired[0].new_path.clone();
        let scope = HostScope::open(&profile).unwrap();
        drop(scope);
        std::fs::remove_dir_all(&archived).unwrap();
        let scope = HostScope::open(&profile).unwrap();
        drop(scope);
        drop(root);
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn history_observation_never_treats_pending_unknown_or_another_assignment_as_complete() {
        let id: TransactionId = "startup-history-host-select".try_into().unwrap();
        let other: TransactionId = "other-host-select".try_into().unwrap();
        let mut inventory = ManagementInventory {
            high_water: 7,
            transactions: vec![ManagementTransactionObservation {
                intent: DesiredStateCommit {
                    transaction_id: id.clone(),
                    sequence: 7,
                    deployment_raw_sha256: Sha256Digest::of_bytes(b"deployment"),
                    before_state_sha256: Sha256Digest::of_bytes(b"before"),
                    target_state_sha256: Sha256Digest::of_bytes(b"after"),
                    reader: ReaderContract::NativeAppRuntimeSelectedStateV1,
                },
                prepared: None,
                phase_receipts: Vec::new(),
            }],
            orphans: Vec::new(),
        };
        for stage in [
            DurableStage::Prepared,
            DurableStage::Applied,
            DurableStage::Verified,
        ] {
            inventory.transactions[0].phase_receipts = vec![JournalReceipt {
                transaction_id: id.clone(),
                sequence: 7,
                stage,
                previous: None,
                record_sha256: Sha256Digest::of_bytes(b"observed"),
            }];
            assert!(!committed(&inventory, &id, 7));
        }
        inventory.transactions[0].phase_receipts[0].stage = DurableStage::Committed;
        assert!(committed(&inventory, &id, 7));
        assert!(!committed(&inventory, &id, 8));
        assert!(!committed(&inventory, &other, 7));
        inventory.orphans.push("unsettled-original.tmp".into());
        assert!(!committed(&inventory, &id, 7));
    }

    #[cfg(unix)]
    #[test]
    fn history_original_pin_rejects_same_content_replacement_and_namespace_growth_is_bounded() {
        use std::{
            fs,
            io::Write,
            os::unix::fs::{DirBuilderExt, OpenOptionsExt},
        };
        let path =
            std::env::temp_dir().join(format!("styx-startup-observe-{}", uuid::Uuid::new_v4()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        let create = |name: &str| {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path.join(name))
                .unwrap();
            f.write_all(b"original read-only input").unwrap();
        };
        create("original.json");
        let held = PrivateRoot::open(&path).unwrap();
        let raw = held.read_raw("original.json", 65536).unwrap();
        assert!(same_file(&held, &raw).is_ok());
        fs::rename(path.join("original.json"), path.join("retained.json")).unwrap();
        create("original.json");
        assert!(same_file(&held, &raw).is_err());
        let before = names(&path).unwrap();
        create("added.json");
        assert_ne!(names(&path).unwrap(), before);
        for index in 0..61 {
            create(&format!("entry-{index}.json"));
        }
        assert_eq!(names(&path).unwrap().len(), 64);
        create("over-budget.json");
        assert!(names(&path).is_err());
        drop(raw);
        drop(held);
        fs::remove_dir_all(path).unwrap();
    }
}
