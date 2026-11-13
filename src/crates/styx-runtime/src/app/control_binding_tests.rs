//! Disposable completed enrollment over the real strict-TLS bootstrap path.
//! Never opens or copies an installed profile, never starts a Host executor.
use super::*;
use crate::store::native_host_snapshot::NativeHostSnapshot;
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, MetadataExt},
};
use styx_contracts::native_management::NativeRunDesired;

fn raw_empty() -> Box<serde_json::value::RawValue> {
    serde_json::value::RawValue::from_string("{}".into()).unwrap()
}
fn private_files(path: &Path) -> Vec<(PathBuf, u64, String)> {
    fn visit(base: &Path, path: &Path, files: &mut Vec<(PathBuf, u64, String)>) {
        let mut entries = fs::read_dir(path)
            .unwrap()
            .map(Result::unwrap)
            .collect::<Vec<_>>();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let meta = fs::symlink_metadata(entry.path()).unwrap();
            assert!(!meta.file_type().is_symlink());
            if meta.is_dir() {
                visit(base, &entry.path(), files);
            } else {
                files.push((
                    entry.path().strip_prefix(base).unwrap().to_owned(),
                    meta.ino(),
                    styx_contracts::identity::Sha256Digest::of_bytes(
                        &fs::read(entry.path()).unwrap(),
                    )
                    .to_hex(),
                ));
            }
        }
    }
    let mut files = Vec::new();
    visit(path, path, &mut files);
    files
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires STYX_TEST_APP_CONTROL_SELECTION: real signed native payload; disposable strict-TLS enrollment and private filesystem"]
async fn completed_stopped_host_control_binding_preserves_execution_refusal_and_integrity() {
    let selection = PathBuf::from(std::env::var("STYX_TEST_APP_CONTROL_SELECTION").unwrap());
    assert!(selection.is_absolute());
    let parent =
        std::env::temp_dir().join(format!("styx-stopped-binding-{}", uuid::Uuid::new_v4()));
    fs::DirBuilder::new().mode(0o700).create(&parent).unwrap();
    for damage in ["none", "ready", "ca"] {
        let container = parent.join(damage);
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&container)
            .unwrap();
        let profile = container.join("profile");
        // Only selects an available isolated loopback port; normal Gateway
        // bind remains authoritative and any collision fails this fixture.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut app = HostApp::open_native(&profile, &selection).await.unwrap();
        app.create_local(LocalInput {
            label: "Stopped binding fixture".into(),
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
        assert_eq!(
            app.enrollment.as_ref().unwrap().status(),
            "ready_to_connect"
        );
        app.settle_all().await.unwrap();
        assert!(app.running.is_none());
        // Use the original C07 actor; never edit canonical intent as a fixture.
        app.set_desired(NativeRunDesired::Stopped).await.unwrap();
        let before = private_files(&container);
        let binding =
            NativeHostSnapshot::inspect_gateway_binding_for_app(&profile, app.scope.clone())
                .unwrap();
        assert_eq!(
            binding.gateway_origin(),
            format!("https://127.0.0.1:{port}")
        );
        assert!(matches!(
            NativeHostSnapshot::open_for_app(&profile, app.scope.clone()),
            Err(crate::store::enrollment::JournalError::Conflict)
        ));
        assert!(matches!(
            NativeHostSnapshot::open(&profile),
            Err(crate::store::enrollment::JournalError::Conflict)
        ));
        assert_eq!(private_files(&container), before);
        if damage == "none" {
            drop(app);
            let mut reopened = HostApp::open_native(&profile, &selection).await.unwrap();
            let status = reopened.snapshot().await;
            assert!(!status["admission_fenced"].as_bool().unwrap());
            assert_eq!(status["enrollment"]["status"], "ready_to_connect");
            assert_eq!(status["gateway"]["running"], false);
            let quit = reopened
                .dispatch(Operation::QuitAdmission, raw_empty())
                .await
                .unwrap();
            assert_eq!(quit["quit"]["status"], "ready_to_quit");
            assert_eq!(private_files(&container), before);
            drop(reopened);
        } else {
            if damage == "ready" {
                let path = profile.join("host-ready-v1.json");
                let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                value["credential_sha256"] = json!("0".repeat(64));
                fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
            } else {
                let other = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
                fs::write(profile.join("host-ca.pem"), other.cert.pem()).unwrap();
            }
            assert!(
                NativeHostSnapshot::inspect_gateway_binding_for_app(&profile, app.scope.clone())
                    .is_err()
            );
            assert!(NativeHostSnapshot::open_for_app(&profile, app.scope.clone()).is_err());
            drop(app);
        }
    }
    fs::remove_dir_all(parent).unwrap();
    println!(
        "completed_enrollment=true; stopped_control_binding=true; stopped_execution_refused=true; ready_and_CA_corruption_refused=true; installed_profile=NOT_OPENED; Host_execution=NOT_STARTED"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires STYX_TEST_APP_CONTROL_SELECTION: real signed native payload and disposable strict-TLS local enrollment"]
async fn reopen_resumes_gateway_intent_without_resuming_stopped_host() {
    let selection = PathBuf::from(std::env::var("STYX_TEST_APP_CONTROL_SELECTION").unwrap());
    assert!(selection.is_absolute());
    let parent = std::env::temp_dir().join(format!("styx-gateway-resume-{}", uuid::Uuid::new_v4()));
    fs::DirBuilder::new().mode(0o700).create(&parent).unwrap();

    // Exercise the negative first so the baseline failure cannot hide it.
    for gateway_wanted in [NativeRunDesired::Stopped, NativeRunDesired::Running] {
        let container = parent.join(if gateway_wanted == NativeRunDesired::Running {
            "running"
        } else {
            "stopped"
        });
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&container)
            .unwrap();
        let profile = container.join("profile");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut app = HostApp::open_native(&profile, &selection).await.unwrap();
        app.create_local(LocalInput {
            label: "Gateway resume fixture".into(),
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
        assert_eq!(
            app.enrollment.as_ref().unwrap().status(),
            "ready_to_connect"
        );
        assert!(app.running.is_none());
        app.set_desired(NativeRunDesired::Stopped).await.unwrap();

        if gateway_wanted == NativeRunDesired::Stopped {
            let gateway = app.local_gateway.as_mut().unwrap();
            gateway.settle().await.unwrap();
            let scope = gateway.scope.clone();
            let before = native::inspect_gateway_for_app(scope.clone())
                .await
                .unwrap();
            assert_eq!(
                before.desired.gateway.unwrap().run,
                NativeRunDesired::Running
            );
            let change = native::NativeDesiredChange {
                component: native::NativeComponent::Gateway,
                run: NativeRunDesired::Stopped,
                transaction_id: uuid::Uuid::new_v4().to_string().try_into().unwrap(),
                sequence: before.revision + 1,
            };
            let plan = native::plan_for_app(scope.clone(), change).await.unwrap();
            native::apply_for_app(scope, &plan.plan_file).await.unwrap();
        }
        let gateway_state = container.join("gateway");
        let desired = native::inspect(&gateway_state, None).await.unwrap();
        assert_eq!(desired.desired.gateway.unwrap().run, gateway_wanted);
        let quit = app
            .dispatch(Operation::QuitAdmission, raw_empty())
            .await
            .unwrap();
        assert_eq!(quit["quit"]["status"], "ready_to_quit");
        drop(app);

        // Capture the actual canonical state and journal after the normal quit;
        // observations and Gateway startup must never write a Host Running intent.
        let host_before = private_files(&profile);
        let gateway_before = private_files(&container.join("gateway"));
        let mut reopened = HostApp::open_native(&profile, &selection).await.unwrap();
        let status = reopened
            .dispatch(Operation::StartupStatus, raw_empty())
            .await
            .unwrap();
        assert_eq!(status["configuration"]["desired"]["host"]["run"], "stopped");
        assert!(reopened.running.is_none());
        assert_eq!(private_files(&profile), host_before);
        let desired = native::inspect(&gateway_state, None).await.unwrap();
        assert_eq!(desired.desired.gateway.unwrap().run, gateway_wanted);
        if gateway_wanted == NativeRunDesired::Stopped {
            assert_eq!(status["gateway"]["running"], false);
            assert_eq!(status["gateway"]["listening"], false);
            assert_eq!(private_files(&container.join("gateway")), gateway_before);
        } else {
            assert_eq!(status["gateway"]["running"], true);
            assert_eq!(status["gateway"]["listening"], true);
            let computers = reopened
                .dispatch(Operation::Computers, raw_empty())
                .await
                .unwrap();
            assert_eq!(computers["devices"].as_array().unwrap().len(), 1);
            assert_eq!(computers["devices"][0]["is_local"], true);
            assert!(reopened.running.is_none());
            assert_eq!(private_files(&profile), host_before);
        }
        let quit = reopened
            .dispatch(Operation::QuitAdmission, raw_empty())
            .await
            .unwrap();
        assert_eq!(quit["quit"]["status"], "ready_to_quit");
        drop(reopened);
    }
    fs::remove_dir_all(parent).unwrap();
}
