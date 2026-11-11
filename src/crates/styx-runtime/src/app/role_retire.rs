use super::*;
use crate::management::role_retire::{self, RetireError, RetireOptions};

impl HostApp {
    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "macos",
        target_os = "windows"
    ))]
    fn prove_retiring_runtime_history(&self, gateway: &HostScope) -> Result<(), AppError> {
        use super::runtime_update::{OriginalInput, SelectionPin, root_digest, same_file};
        use styx_contracts::{
            identity::{Sha256Digest, TransactionId},
            management::DurableStage,
        };
        let parent = &self.scope.container.parent;
        if parent.ensure_absent("runtime-updates").is_ok() {
            return Ok(());
        }
        let host_root = self
            .scope
            .root
            .get()
            .ok_or(AppError("role_retire_history_unproven"))?;
        let directory = self.scope.container.parent_path.join("runtime-updates");
        let updates =
            PrivateRoot::open(&directory).map_err(|_| AppError("role_retire_history_unproven"))?;
        let mut names = std::collections::BTreeSet::new();
        for item in
            std::fs::read_dir(&directory).map_err(|_| AppError("role_retire_history_unproven"))?
        {
            if names.len() >= 64 {
                return Err(AppError("role_retire_history_unproven"));
            }
            let name = item
                .map_err(|_| AppError("role_retire_history_unproven"))?
                .file_name()
                .into_string()
                .map_err(|_| AppError("role_retire_history_unproven"))?;
            if !names.insert(name) {
                return Err(AppError("role_retire_history_unproven"));
            }
        }
        if names.is_empty() {
            return Err(AppError("role_retire_history_unproven"));
        }
        let mut pins = Vec::new();
        for name in &names {
            let id: TransactionId = name
                .strip_suffix(".json")
                .and_then(|s| s.try_into().ok())
                .ok_or(AppError("role_retire_history_unproven"))?;
            let raw = updates
                .read_raw(name, 65536)
                .map_err(|_| AppError("role_retire_history_unproven"))?;
            let input: OriginalInput = serde_json::from_slice(raw.bytes())
                .map_err(|_| AppError("role_retire_history_unproven"))?;
            input.validate_shape(&id)?;
            if input.container_sha256 != root_digest(parent)?
                || input.roles.len() != if gateway.root.get().is_some() { 2 } else { 1 }
            {
                return Err(AppError("role_retire_history_unproven"));
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
                || Sha256Digest::of_bytes(selection.file.bytes()) != input.selection_sha256
            {
                return Err(AppError("role_retire_history_unproven"));
            }
            for (index, role) in input.roles.iter().enumerate() {
                let (root, path) = if index == 0 {
                    (host_root, &self.scope.state_dir)
                } else {
                    (
                        gateway
                            .root
                            .get()
                            .ok_or(AppError("role_retire_history_unproven"))?,
                        &gateway.state_dir,
                    )
                };
                if root_digest(root)? != role.root_sha256 {
                    return Err(AppError("role_retire_history_unproven"));
                }
                let observed = crate::store::native_observation::read(path)
                    .map_err(|_| AppError("role_retire_history_unproven"))?;
                let inventory = observed.inventory;
                if !inventory.orphans.is_empty()
                    || inventory.transactions.iter().any(|t| {
                        t.phase_receipts
                            .last()
                            .is_none_or(|r| r.stage != DurableStage::Committed)
                    })
                    || !inventory.transactions.iter().any(|t| {
                        t.intent.transaction_id == role.select_transaction
                            && t.intent.sequence == role.select_sequence
                            && t.phase_receipts
                                .last()
                                .is_some_and(|r| r.stage == DurableStage::Committed)
                    })
                {
                    return Err(AppError("role_retire_history_unproven"));
                }
            }
            same_file(&updates, &raw)?;
            selection.validate()?;
            pins.push((raw, selection));
        }
        for (raw, selection) in &pins {
            same_file(&updates, raw)?;
            selection.validate()?;
        }
        let after: std::collections::BTreeSet<_> = std::fs::read_dir(&directory)
            .map_err(|_| AppError("role_retire_history_unproven"))?
            .map(|e| e.ok().and_then(|v| v.file_name().into_string().ok()))
            .collect();
        if after != names.iter().cloned().map(Some).collect()
            || PrivateRoot::open(&directory)
                .map_err(|_| AppError("role_retire_history_unproven"))?
                .identity()
                != updates.identity()
        {
            return Err(AppError("role_retire_history_unproven"));
        }
        self.scope.validate()?;
        gateway.validate()?;
        Ok(())
    }
    #[cfg(not(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "macos",
        target_os = "windows"
    )))]
    fn prove_retiring_runtime_history(&self, _: &HostScope) -> Result<(), AppError> {
        if self
            .scope
            .container
            .parent
            .ensure_absent("runtime-updates")
            .is_ok()
        {
            Ok(())
        } else {
            Err(AppError("role_retire_history_unproven"))
        }
    }
    fn retire_error(&mut self, error: RetireError) -> AppError {
        let code = error.code;
        self.retire_failure = Some(error);
        AppError(code)
    }
    pub(super) async fn retire_role(&mut self, options: RetireOptions) -> Result<Value, AppError> {
        self.retire_failure = None;
        if self.running.is_some() || self.local_gateway.as_ref().is_some_and(|g| g.is_running()) {
            return Err(AppError("role_retire_role_busy"));
        }
        if self.login.pending() {
            return Err(AppError("app_login_in_progress"));
        }
        // A live/staged/retained Work owns its original writer and pins. Do not
        // drop it or acquire a replacement owner during retirement.
        if self.runtime_update.is_some() {
            return Err(AppError("role_retire_runtime_owner_retained"));
        }
        let name = self
            .scope
            .state_dir
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or(AppError("role_retire_invalid_roots"))?
            .to_owned();
        if [
            "gateway",
            "runtime-updates",
            "runtime-versions",
            "migration-candidates",
            ".styx-app-role-retire-v1",
            "app-join-input-v1.json",
            "app-join-ca-v1.pem",
            "app-join-invitation-v1",
            "app-local-gateway-input-v1.json",
        ]
        .contains(&name.as_str())
            || name.starts_with('.')
            || name.contains(".retired-")
        {
            return Err(AppError("role_retire_invalid_roots"));
        }
        // The UI stops both roles through QuitAdmission first. Its ticket may
        // authorize quitting, but does not prevent this explicit fresh setup.
        self.quit_ticket = None;
        self.available()?;
        self.settle_all().await?;
        let gateway_scope = self.scope.gateway_sibling()?;
        let host = self.scope.root.get().map(|_| self.scope.state_dir.clone());
        let gateway = gateway_scope
            .root
            .get()
            .map(|_| gateway_scope.state_dir.clone());
        if host.is_none() && gateway.is_none() {
            return Err(AppError("role_retire_history_unproven"));
        }
        drop(gateway_scope);
        let mut prepared = tokio::task::spawn_blocking(move || {
            role_retire::prepare(host.as_deref(), gateway.as_deref(), options)
        })
        .await
        .map_err(|_| AppError("role_retire_worker_unknown"))?
        .map_err(|error| self.retire_error(error))?;
        // A successful setup retains its original input writer; otherwise take
        // a temporary one. Refusals leave the original App state untouched.
        let temporary_writer = if self.input_writer.is_none() {
            Some(
                self.scope
                    .container
                    .parent
                    .try_configuration_writer()
                    .map_err(|_| AppError("app_input_writer_busy"))?,
            )
        } else {
            None
        };
        self.prove_retiring_runtime_history(&self.scope.gateway_sibling()?)?;
        for name in [
            "app-join-input-v1.json",
            "app-join-ca-v1.pem",
            "app-join-invitation-v1",
            "app-local-gateway-input-v1.json",
        ] {
            if self.scope.container.parent.ensure_absent(name).is_err() {
                self.scope
                    .container
                    .parent
                    .read_raw(name, 1024 * 1024)
                    .map_err(|_| AppError("role_retire_input_refused"))?;
                prepared
                    .add_input(&self.scope.container.parent_path.join(name))
                    .map_err(|error| self.retire_error(error))?;
            }
        }
        let history = self.scope.container.parent_path.join("runtime-updates");
        if self
            .scope
            .container
            .parent
            .ensure_absent("runtime-updates")
            .is_err()
        {
            prepared
                .add_runtime_history(&history)
                .map_err(|error| self.retire_error(error))?;
        }
        let container = self.scope.container.clone();
        let retire_container = container.clone();
        let state_dir = self.scope.state_dir.clone();
        // Release Windows child name pins, retaining the original container
        // instance and input writer. PreparedRetire still owns the root leases.
        self.local_gateway = None;
        // This is a read-only snapshot, not a retained coordinator. Its root
        // handle must not prevent the original Windows no-replace rename.
        self.startup_profile = None;
        self.scope = Arc::new(HostScope {
            container: container.clone(),
            state_dir: state_dir.clone(),
            root: OnceLock::new(),
        });
        let host_name = name;
        let result = tokio::task::spawn_blocking(move || {
            prepared.retire_app(
                &retire_container.parent,
                &retire_container.parent_path,
                &host_name,
            )
        })
        .await;
        let report = match result {
            Ok(Ok(report)) => report,
            other => {
                self.unknown = true;
                // Rebind only for inspection/quit; an uncertain rename is never
                // replayed and cannot enable new setup in this process.
                if let Ok(scope) = HostScope::in_container(container, state_dir) {
                    self.scope = Arc::new(scope);
                }
                return Err(match other {
                    Ok(Err(error)) => self.retire_error(error),
                    _ => AppError("role_retire_worker_unknown"),
                });
            }
        };
        drop(temporary_writer);
        self.input_writer = None;
        self.configuration = None;
        self.enrollment = None;
        self.inspected_join = None;
        self.native_computer_requested = None;
        self.native_runtime = None;
        self.startup_profile = None;
        self.cleanup = None;
        self.quit_ticket = None;
        self.resume_local_available = false;
        self.runtime_update = None;
        self.maintenance = None;
        self.startup_diagnostic = None;
        self.status.send_replace(ConnectionStatus::stopped());
        self.scope.validate()?;
        let mut snapshot = self.snapshot().await;
        snapshot["retirement"] =
            serde_json::to_value(report).map_err(|_| AppError("app_response_invalid"))?;
        Ok(snapshot)
    }
}

#[cfg(all(test, target_os = "linux", target_env = "gnu"))]
mod tests {
    use super::*;
    use std::{
        fs,
        io::Write,
        os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    };
    fn input(value: Value) -> Box<serde_json::value::RawValue> {
        serde_json::value::RawValue::from_string(value.to_string()).unwrap()
    }
    #[tokio::test]
    async fn retire_role_app_refuses_running_then_resets_status_and_setup_inputs() {
        let parent = std::env::temp_dir().join(format!("styx-app-retire-{}", uuid::Uuid::new_v4()));
        fs::DirBuilder::new().mode(0o700).create(&parent).unwrap();
        let host = parent.join("host");
        let mut app = HostApp::open(&host, &parent.join("app-join-input-v1.json"))
            .await
            .unwrap();
        fs::DirBuilder::new().mode(0o700).create(&host).unwrap();
        app.scope.bind().unwrap();
        let gateway_path = parent.join("gateway");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&gateway_path)
            .unwrap();
        {
            let root = PrivateRoot::open(&gateway_path).unwrap();
            let mut writer = root.try_configuration_writer().unwrap();
            let mut journal = crate::store::enrollment::EnrollmentJournal::open(
                &root,
                &mut writer,
                crate::store::enrollment::JournalBudget::default(),
            )
            .unwrap();
            journal.record_time_floor(1000).unwrap();
        }
        for name in [
            "app-join-input-v1.json",
            "app-join-ca-v1.pem",
            "app-join-invitation-v1",
            "app-local-gateway-input-v1.json",
        ] {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(parent.join(name))
                .unwrap();
            f.write_all(b"original input preserved").unwrap();
        }
        app.enrollment = Some(json!({"status":"ready_to_connect"}));
        let lease = app.scope.root.get().unwrap().try_execution_lease().unwrap();
        let worker = tokio::spawn(async move {
            let _lease = lease;
            std::future::pending::<Result<ForegroundOutcome, ForegroundError>>().await
        });
        let events = tokio::spawn(std::future::pending::<()>());
        let cancel = CancellationToken::new();
        app.running = Some(RunningHost {
            desktop_intent: None,
            worker,
            events,
            _cancel_on_drop: cancel.clone().drop_guard(),
            cancel,
        });
        let refusal = app
            .dispatch(
                Operation::RetireRole,
                input(json!({"allowOtherDevices":false})),
            )
            .await
            .unwrap_err();
        assert_eq!(refusal.code(), "role_retire_role_busy");
        assert!(host.is_dir() && parent.join("app-join-input-v1.json").is_file());
        // Join the original fixture workers before invoking the stopped path.
        let running = app.running.take().unwrap();
        running.worker.abort();
        running.events.abort();
        let _ = running.worker.await;
        let _ = running.events.await;
        let retired = app
            .dispatch(
                Operation::RetireRole,
                input(json!({"allowOtherDevices":false})),
            )
            .await
            .unwrap();
        assert_eq!(retired["retirement"]["outcome"], "retired");
        assert_eq!(
            retired["retirement"]["retired"].as_array().unwrap().len(),
            6
        );
        for path in retired["retirement"]["retired"].as_array().unwrap() {
            assert!(!Path::new(path["oldPath"].as_str().unwrap()).exists());
            assert!(Path::new(path["newPath"].as_str().unwrap()).exists());
        }
        let status = app
            .dispatch(Operation::Status, input(json!({})))
            .await
            .unwrap();
        assert!(
            status["configuration"].is_null()
                && status["enrollment"].is_null()
                && status["gateway"].is_null()
        );
        assert_eq!(status["admission_fenced"], false);
        // Both normal welcome choices get past the old setup guards in this
        // same process. These negative inputs never dispatch pairing/network.
        let local = app.dispatch(Operation::CreateLocal, input(json!({"label":"New computer","computer":false,"browser":false,"browserChannel":null,"persistLogin":false}))).await.unwrap_err();
        assert_eq!(local.code(), "app_runtime_selection_invalid");
        let join = app
            .dispatch(Operation::InspectJoin, input(json!({"link":"invalid"})))
            .await
            .unwrap_err();
        assert_ne!(join.code(), "app_join_already_exists");
        assert!(app.scope.root.get().is_none());
        drop(app);
        fs::remove_dir_all(parent).unwrap();
    }
}
