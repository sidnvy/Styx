//! Startup observes the current committed profile and pending native operation.
//! Retired App-updater files do not govern installed bundle admission.
use super::*;
use crate::store::native_host_snapshot::NativeHostSnapshot;

impl HostApp {
    pub(super) async fn try_ready_startup(&mut self) -> Result<bool, AppError> {
        // Existing split local Gateway composition keeps
        // their original path. No sibling is created or paired here.
        if self.scope.gateway_sibling()?.root.get().is_some() {
            return Ok(false);
        }
        if let Some(d) = &self.startup_diagnostic {
            d.report("app_current_observation_begin");
        }
        let scope = self.scope.clone();
        let bundle = self.native_runtime.clone();
        let profile = match tokio::task::spawn_blocking(move || {
            if let Some(bundle) = bundle {
                NativeHostSnapshot::observe_for_app_retained(
                    scope.state_dir(),
                    scope.clone(),
                    bundle,
                )
            } else {
                NativeHostSnapshot::observe_for_app(scope.state_dir(), scope.clone())
            }
        })
        .await
        {
            Ok(Ok(profile)) => Arc::new(profile),
            // Incomplete/pending roots enter the original full inspector and
            // original recovery/fencing path; no cached success substitutes it.
            _ => return Ok(false),
        };
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
    #[cfg(unix)]
    use super::super::runtime_bootstrap::same_file;
    use super::*;

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
            startup_diagnostic: None,
            startup_profile: None,
        };
        profile.revalidate().unwrap();
        app.scope.validate().unwrap();
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

    #[cfg(unix)]
    #[test]
    fn installed_selection_input_pin_rejects_same_content_replacement() {
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
        drop(raw);
        drop(held);
        fs::remove_dir_all(path).unwrap();
    }
}

#[cfg(all(test, target_os = "macos"))]
mod installed_bundle_acceptance {
    use super::*;
    use styx_contracts::native_management::NativeRuntimeSelection;

    /// Read only: verify the existing paired Pilot Mac Host can load its
    /// current App-bundled Runtime without changing its old C07 selection.
    #[tokio::test]
    #[ignore = "requires existing paired Pilot Mac, installed signed App; read-only"]
    async fn original_paired_host_uses_new_app_bundle_without_runtime_update() {
        assert_eq!(
            std::env::var("STYX_TEST_APP_BUNDLE_READONLY").as_deref(),
            Ok("1"),
        );
        let parent = std::path::PathBuf::from(std::env::var("HOME").unwrap())
            .join("Library/Application Support/Styx/NativeRustHost-v1");
        let state_dir = parent.join("profile");
        let payload = std::path::Path::new("/Applications/Styx.app/Contents/Resources/native");
        let manifest_meta: serde_json::Value = serde_json::from_slice(
            &std::fs::read("/Applications/Styx.app/Contents/Resources/macos-runtime.json").unwrap(),
        )
        .unwrap();
        let current_manifest = manifest_meta["nativeRuntime"]["manifestSha256"]
            .as_str()
            .unwrap();
        let chosen = std::fs::read_dir(parent.join("migration-candidates"))
            .unwrap()
            .filter_map(Result::ok)
            .filter_map(|entry| std::fs::read(entry.path()).ok())
            .filter_map(|raw| serde_json::from_slice::<NativeRuntimeSelection>(&raw).ok())
            .find(|selection| {
                std::path::Path::new(&selection.payload_path) == payload
                    && selection.manifest_sha256.to_hex() == current_manifest
            })
            .expect("installed signed App candidate must be published");
        let runtime = Arc::new(crate::release::load_selected(&chosen).unwrap());
        let scope = Arc::new(HostScope::open(&state_dir).unwrap());
        let snapshot = NativeHostSnapshot::observe_for_app_retained(
            &state_dir,
            scope.clone(),
            runtime.clone(),
        )
        .unwrap();
        assert_eq!(snapshot.current_selection(), &chosen);
        let report = native_join::inspect_for_app_retained(scope, runtime)
            .await
            .unwrap();
        assert_eq!(report.verified_runtime.runtime_selection().unwrap(), chosen);
        snapshot.revalidate().unwrap();
    }
}
