//! One owned real-filesystem import batch. No installed profile or OS service.
use super::*;
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires a fresh owned external STYX_TEST_MANAGEMENT_ROOT"]
async fn actual_legacy_management_raw_import_and_plan_batch() {
    use std::{
        fs,
        io::Write,
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
    };
    let parent = std::path::PathBuf::from(
        std::env::var_os("STYX_TEST_MANAGEMENT_ROOT").expect("explicit owned root"),
    );
    assert!(parent.is_absolute() && parent.is_dir());
    let root = parent.join(uuid::Uuid::new_v4().to_string());
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    fn put(path: &Path, bytes: &[u8]) {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        f.write_all(bytes).unwrap();
        f.sync_all().unwrap();
    }
    let config=br#"{ "schema":1, "mode":"join-existing", "gateway":{"url":"https://127.0.0.1:63570"}, "host":{"computer":true,"browser":{"enabled":true}}, "future_config":{"n":340282366920938463463374607431768211457,"private":"not-for-output"} }
"#;
    let digest = Sha256Digest::of_bytes(config).to_hex();
    let state = format!(
        r#"{{"schema":1,"mode":"join-existing","configSha256":"{digest}","steps":[{{"id":"host.prepare","status":"succeeded"}},{{"id":"host.claim","status":"running"}}],"appPreferences":{{"loginAtStartup":{{"desiredEnabled":false,"registration":null,"lastOperation":{{"status":"succeeded"}}}}}},"onboardingDecisions":{{"background":{{"choice":"foreground","configSha256":"{digest}"}}}},"future_state":340282366920938463463374607431768211457}}
"#
    );
    put(&root.join("deployment.json"), config);
    put(&root.join("state.json"), state.as_bytes());
    let imported = inspect_deployment(&root).await.unwrap();
    assert_eq!(imported.roles.gateway, "external");
    assert_eq!(imported.roles.host, "local");
    assert_eq!(imported.roles.computer, "requested");
    assert_eq!(imported.roles.browser, "requested");
    assert_eq!(imported.needs_explicit_decision, vec!["host"]);
    assert_eq!(imported.review_plan.len(), 2);
    assert!(imported.review_plan.iter().all(|x| x.component == "host"
        && !x.authorization_required
        && x.action.starts_with("review_")));
    assert_eq!(imported.roles.readiness, "not_inferred");
    assert_eq!(imported.host_manager, "unspecified");
    assert_eq!(imported.host_desired_run, "unspecified");
    assert_eq!(imported.background_choice, "foreground");
    assert_eq!(imported.app_login.desired_enabled, Some(false));
    assert_eq!(imported.runtime_health, "not_observed");
    assert_eq!(imported.steps[1].recorded_status, "running");
    assert_eq!(imported.steps[1].projected_status, "uncertain");
    assert_eq!(imported.steps[1].requires, vec!["host.prepare"]);
    assert!(!imported.steps.iter().any(|x| x.replay_authorized));
    assert_eq!(fs::read(root.join("deployment.json")).unwrap(), config);
    assert_eq!(fs::read(root.join("state.json")).unwrap(), state.as_bytes());
    assert_eq!(fs::read_dir(&root).unwrap().count(), 2);
    let public = serde_json::to_string(&imported).unwrap();
    assert!(
        !public.contains("not-for-output")
            && !public.contains("340282366920938463463374607431768211457")
    );
    assert!(!public.contains("https://"));
    // Legacy host.claim can legitimately wait for independent owner approval.
    let waiting = state.replace("\"status\":\"running\"", "\"status\":\"awaiting_approval\"");
    fs::write(root.join("state.json"), waiting.as_bytes()).unwrap();
    let waiting_view = inspect_deployment(&root).await.unwrap();
    assert_eq!(waiting_view.steps[1].projected_status, "awaiting_approval");
    assert!(!waiting_view.steps[1].replay_authorized);
    fs::write(root.join("state.json"), state.as_bytes()).unwrap();
    // Existing legacy management ownership is observed, never taken over.
    put(&root.join("advance.lock"), b"private-owner-do-not-print");
    let blocked = inspect_deployment(&root).await.unwrap();
    assert_eq!(blocked.management_guards, vec!["advance.lock"]);
    assert_eq!(
        fs::read(root.join("advance.lock")).unwrap(),
        b"private-owner-do-not-print"
    );
    // A changed protected source cannot return the prior loaded plan/binding.
    let loaded = load(&root).unwrap();
    let altered = state.replace("\"desiredEnabled\":false", "\"desiredEnabled\":true");
    fs::write(root.join("state.json"), altered.as_bytes()).unwrap();
    assert_eq!(loaded.finish().unwrap_err(), ManagementError::Changed);
    fs::write(root.join("state.json"), state.as_bytes()).unwrap();
    // A wrong raw config binding or unknown schema is refused without repair.
    for bad in [
        state.replace(&digest, &"0".repeat(64)),
        state.replacen("\"schema\":1", "\"schema\":2", 1),
    ] {
        fs::write(root.join("state.json"), bad.as_bytes()).unwrap();
        assert_eq!(
            inspect_deployment(&root).await.unwrap_err(),
            ManagementError::Invalid
        );
        assert_eq!(fs::read(root.join("state.json")).unwrap(), bad.as_bytes());
    }
    fs::write(root.join("state.json"), state.as_bytes()).unwrap();
    // Join cannot smuggle a second local Gateway/ingress through the read model.
    let invalid = config.to_vec();
    let invalid = String::from_utf8(invalid).unwrap().replace(
        "\"url\":\"https://127.0.0.1:63570\"",
        "\"url\":\"https://127.0.0.1:63570\",\"runtime\":{}",
    );
    fs::write(root.join("deployment.json"), invalid.as_bytes()).unwrap();
    let badstate = state.replace(
        &digest,
        &Sha256Digest::of_bytes(invalid.as_bytes()).to_hex(),
    );
    fs::write(root.join("state.json"), badstate.as_bytes()).unwrap();
    assert_eq!(
        inspect_deployment(&root).await.unwrap_err(),
        ManagementError::Invalid
    );
    fs::write(root.join("deployment.json"), config).unwrap();
    fs::write(root.join("state.json"), state.as_bytes()).unwrap();
    let receipt = serde_json::json!({"schema":1,"status":"PASS","scope":"owned Linux real protected raw import; no migration/mutation/nativeUI/platform acceptance","fixture":root,"source":imported.source,"raw_bytes_preserved":true,"unknown_fields_and_large_integers_preserved":true,"uncertain_step_not_replayed":true,"app_login_false_preserved":true,"manager_and_run_not_inferred":true,"lock_not_removed":true,"original_inputs_restored":true,"services_started":0,"identity_or_pairing_writes":0});
    put(
        &parent.join("receipt.json"),
        serde_json::to_string_pretty(&receipt).unwrap().as_bytes(),
    );
}
