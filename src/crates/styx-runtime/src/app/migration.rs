//! App orchestration of the existing native migration authority. Status and
//! transaction labels are observations; the native producer owns all writes.
use super::*;
use crate::store::app_migration_observation::{self, AppMigrationObservation};
use styx_contracts::{identity::TransactionId, management::DurableStage};

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Input {
    transaction_id: TransactionId,
    authorize: bool,
    run: NativeRunDesired,
}

#[derive(Serialize)]
pub(super) struct State {
    status: &'static str,
    transaction_id: Option<TransactionId>,
    can_recover: bool,
    diagnostic: Option<Value>,
    error: Option<&'static str>,
    // The same task remains owned until its actual join, including on EOF.
    #[serde(skip)]
    job: Option<JoinHandle<Result<native::NativeManagementReport, native::NativeManagementError>>>,
}
impl State {
    fn required(transaction_id: Option<TransactionId>) -> Self {
        Self {
            status: "required",
            can_recover: transaction_id.is_some(),
            transaction_id,
            diagnostic: None,
            error: None,
            job: None,
        }
    }
    fn blocked(code: &'static str) -> Self {
        Self {
            status: "blocked",
            error: Some(code),
            ..Self::required(None)
        }
    }
}

impl HostApp {
    pub(super) async fn observe_migration(&mut self) {
        let scope = self.scope.clone();
        self.migration =
            match tokio::task::spawn_blocking(move || app_migration_observation::observe(scope))
                .await
            {
                Ok(Ok(AppMigrationObservation::NotMigration)) => None,
                #[cfg(any(
                    target_os = "macos",
                    all(test, target_os = "linux", target_env = "gnu")
                ))]
                Ok(Ok(AppMigrationObservation::Required)) => Some(State::required(None)),
                #[cfg(any(
                    target_os = "macos",
                    all(test, target_os = "linux", target_env = "gnu")
                ))]
                Ok(Ok(AppMigrationObservation::Pending { transaction_id })) => {
                    match TransactionId::try_from(transaction_id) {
                        Ok(id) => Some(State::required(Some(id))),
                        Err(_) => Some(State::blocked("app_migration_observation_invalid")),
                    }
                }
                #[cfg(any(
                    target_os = "macos",
                    all(test, target_os = "linux", target_env = "gnu")
                ))]
                Ok(Ok(AppMigrationObservation::Blocked { code })) => Some(State::blocked(code)),
                _ => Some(State::blocked("app_migration_observation_unavailable")),
            };
    }
    pub(super) fn migration_fenced(&self) -> bool {
        self.migration
            .as_ref()
            .is_some_and(|m| m.status != "committed")
    }
    pub(super) fn migration_running(&self) -> bool {
        self.migration.as_ref().is_some_and(|m| m.job.is_some())
    }
    pub(super) fn start_migration(&mut self, input: Input, recover: bool) -> Result<(), AppError> {
        // The caller supplies no root, selected package, ownership proof or
        // policy authority. Those belong to the original launcher and scope.
        self.scope.validate()?;
        if !input.authorize || input.run != NativeRunDesired::Stopped {
            return Err(AppError("app_migration_authorization_required"));
        }
        if self.running.is_some()
            || self.local_gateway.is_some()
            || self.input_writer.is_some()
            || self.retained.is_some()
            || self.unknown
            || self.quit_ticket.is_some()
        {
            return Err(AppError("app_migration_owner_busy"));
        }
        let selection = self
            .runtime_selection_file
            .clone()
            .ok_or(AppError("app_runtime_selection_invalid"))?;
        let migration = self
            .migration
            .as_mut()
            .ok_or(AppError("app_migration_not_required"))?;
        if migration.job.is_some() {
            return Err(AppError("app_migration_in_progress"));
        }
        if recover {
            if !migration.can_recover
                || migration.transaction_id.as_ref() != Some(&input.transaction_id)
            {
                return Err(AppError("app_migration_original_transaction_required"));
            }
        } else if migration.status != "required" || migration.transaction_id.is_some() {
            return Err(AppError("app_migration_original_transaction_required"));
        }
        let scope = self.scope.clone();
        let id = input.transaction_id.clone();
        migration.transaction_id = Some(input.transaction_id);
        migration.status = "running";
        migration.can_recover = false;
        migration.error = None;
        migration.job = Some(tokio::spawn(async move {
            if recover {
                native::recover_migration_for_app(scope, id.as_str()).await
            } else {
                native::migrate_for_app(scope, &selection, id.as_str(), NativeRunDesired::Stopped)
                    .await
            }
        }));
        Ok(())
    }
    pub(super) async fn reap_migration(&mut self, wait: bool) {
        let Some(migration) = self.migration.as_mut() else {
            return;
        };
        if !migration
            .job
            .as_ref()
            .is_some_and(|job| wait || job.is_finished())
        {
            return;
        }
        let Some(job) = migration.job.take() else {
            return;
        };
        match job.await {
            Ok(Ok(report)) => {
                let same_commit = report.transaction.as_ref().is_some_and(|tx| {
                    Some(&tx.transaction_id) == migration.transaction_id.as_ref()
                        && tx.observed_stage == Some(DurableStage::Committed)
                        && tx.receipt.as_ref().is_some_and(|r| {
                            r.transaction_id == tx.transaction_id
                                && r.stage == DurableStage::Committed
                        })
                });
                if !same_commit
                    || report.admission_fenced
                    || !report
                        .desired
                        .host
                        .is_some_and(|h| h.run == NativeRunDesired::Stopped)
                {
                    migration.status = "unknown";
                    migration.error = Some("app_migration_commit_unconfirmed");
                    self.unknown = true;
                    return;
                }
                // Producer success is insufficient: reopen through the existing
                // committed-original-pair reader before enabling normal entry.
                let result = self.read_configuration().await;
                let code = match result {
                    Err(error) => Some(error.code()),
                    Ok(()) if !self.committed_migration => Some("app_migration_commit_unconfirmed"),
                    Ok(()) => None,
                };
                if let Some(code) = code {
                    if let Some(migration) = &mut self.migration {
                        migration.status = "unknown";
                        migration.error = Some(code);
                    }
                    self.unknown = true;
                } else if let Some(migration) = &mut self.migration {
                    migration.status = "committed";
                    migration.error = None;
                    // No connect/startup side effect. User explicitly connects.
                }
            }
            Ok(Err(error)) => {
                migration.status = if error.exit_code() == 4 {
                    "unknown"
                } else {
                    "blocked"
                };
                migration.error = Some(error.code());
                migration.diagnostic = error.migration_diagnostic();
                // Even Conflict/Unavailable may retain an acquired transaction
                // owner. Never release it to open a second recovery writer.
                self.retained = Some(RetainedFailure::Management(error));
                self.unknown = true;
            }
            Err(_) => {
                migration.status = "unknown";
                migration.error = Some("app_migration_worker_unknown");
                self.unknown = true;
            }
        }
    }
}

#[cfg(all(test, target_os = "linux", target_env = "gnu"))]
mod tests {
    use super::*;
    use std::{
        os::unix::fs::DirBuilderExt,
        sync::atomic::{AtomicUsize, Ordering},
    };
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("styx-app-migration-{}", uuid::Uuid::new_v4()));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .expect("private test container");
            Self(path)
        }
        async fn app(&self) -> HostApp {
            HostApp::open(&self.0.join("profile"), &self.0.join("input.json"))
                .await
                .expect("owned fixture")
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    // This exercises the actual private pipe dispatcher and original job join,
    // not macOS migration effects. The terminal native call is Unsupported on
    // Linux; its actual retained scope must still be observed as an error.
    #[tokio::test]
    async fn status_remains_responsive_and_eof_joins_original_migration_without_replay() {
        let fixture = Fixture::new();
        let mut app = fixture.app().await;
        let scope = app.scope.clone();
        let (release, wait) = tokio::sync::oneshot::channel();
        let effects = Arc::new(AtomicUsize::new(0));
        let observed = effects.clone();
        let mut state = State::required(Some("original-migration".try_into().expect("id")));
        state.status = "running";
        state.can_recover = false;
        state.job = Some(tokio::spawn(async move {
            wait.await.expect("original task remains alive");
            observed.fetch_add(1, Ordering::SeqCst);
            native::recover_migration_for_app(scope, "original-migration").await
        }));
        app.migration = Some(state);
        let (client, server) = tokio::io::duplex(8192);
        let (read, write) = tokio::io::split(server);
        let mut serving = tokio::spawn(serve_app(app, read, write, CancellationToken::new()));
        let (read, mut write) = tokio::io::split(client);
        let mut read = BufReader::new(read);
        for (id, operation, expected) in [
            (1, "status", None),
            (2, "quitAdmission", Some("app_migration_in_progress")),
            (3, "connect", Some("app_migration_pending")),
            (4, "claimJoin", Some("app_migration_pending")),
        ] {
            let frame =
                json!({"schema":1,"id":id,"operation":operation,"input":{}}).to_string() + "\n";
            write.write_all(frame.as_bytes()).await.expect("request");
            let mut line = String::new();
            tokio::time::timeout(Duration::from_secs(1), read.read_line(&mut line))
                .await
                .expect("status cannot wait on migration")
                .expect("response");
            let response: Value = serde_json::from_str(&line).expect("JSON");
            if let Some(code) = expected {
                assert_eq!(response["error"], code);
            } else {
                assert_eq!(response["result"]["migration"]["status"], "running");
                assert_eq!(
                    response["result"]["migration"]["transaction_id"],
                    "original-migration"
                );
                assert_eq!(response["result"]["migration"]["can_recover"], false);
                assert_eq!(response["result"]["admission_fenced"], true);
            }
        }
        write.shutdown().await.expect("EOF");
        assert!(
            tokio::time::timeout(Duration::from_millis(30), &mut serving)
                .await
                .is_err()
        );
        assert_eq!(effects.load(Ordering::SeqCst), 0);
        release.send(()).expect("same original task");
        let result = tokio::time::timeout(Duration::from_secs(2), serving)
            .await
            .expect("join after actual terminal result")
            .expect("server did not panic");
        assert!(
            result.is_err(),
            "unsupported result must not become successful cleanup"
        );
        assert_eq!(effects.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn recovery_rejects_replacement_transaction_and_unapproved_running_request() {
        let fixture = Fixture::new();
        let mut app = fixture.app().await;
        app.runtime_selection_file = Some(fixture.0.join("selection.json"));
        app.migration = Some(State::required(Some(
            "original-migration".try_into().expect("id"),
        )));
        for (tx, authorize, run, recover) in [
            ("replacement", true, NativeRunDesired::Stopped, true),
            ("original-migration", false, NativeRunDesired::Stopped, true),
            ("original-migration", true, NativeRunDesired::Running, true),
            ("replacement", true, NativeRunDesired::Stopped, false),
        ] {
            assert!(
                app.start_migration(
                    Input {
                        transaction_id: tx.try_into().expect("id"),
                        authorize,
                        run
                    },
                    recover
                )
                .is_err()
            );
            let state = app.migration.as_ref().expect("original observation");
            assert_eq!(
                state.transaction_id.as_ref().expect("id").as_str(),
                "original-migration"
            );
            assert!(state.job.is_none());
        }
        assert!(
            !fixture.0.join("profile").exists(),
            "refusals cannot initialize a fresh root"
        );
        assert!(
            !fixture.0.join("selection.json").exists(),
            "no candidate publication"
        );
    }
    #[tokio::test]
    async fn startup_observes_original_files_without_creating_migration_state() {
        use std::{io::Write, os::unix::fs::OpenOptionsExt};
        let fixture = Fixture::new();
        let root = fixture.0.join("profile");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .expect("original root");
        let raw = br#"{"schema":1,"mode":"join-existing","original_extension":{"keep":true}}"#;
        for name in ["deployment.json", "state.json"] {
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(root.join(name))
                .expect("original private input");
            file.write_all(raw).expect("original bytes");
        }
        let scope = Arc::new(HostScope::open(&root).expect("original scope"));
        let observation =
            app_migration_observation::observe(scope.clone()).expect("read-only observation");
        assert!(matches!(observation, AppMigrationObservation::Required));
        for name in ["deployment.json", "state.json"] {
            assert_eq!(
                std::fs::read(root.join(name)).expect("preserved input"),
                raw
            );
        }
        assert_eq!(std::fs::read_dir(&root).expect("root entries").count(), 2);
        assert!(!root.join(".styx-management-journal-v1").exists());
        // An incomplete source never becomes a fresh-setup invitation.
        std::fs::remove_file(root.join("state.json")).expect("simulate incomplete source");
        let observation = app_migration_observation::observe(scope).expect("blocked observation");
        assert!(matches!(
            observation,
            AppMigrationObservation::Blocked { .. }
        ));
        assert_eq!(std::fs::read_dir(&root).expect("root entries").count(), 1);
    }
}
