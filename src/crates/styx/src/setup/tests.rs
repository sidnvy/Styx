use super::*;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn rejected_join_requires_exact_recorded_identity() {
    let original =
        json!({"device_id":"device", "fingerprint":"fingerprint", "request_id":"request"});
    let mut rejected = original.clone();
    rejected["status"] = json!("rejected");
    assert!(rejection_matches(&original, &rejected));
    for field in ["device_id", "fingerprint", "request_id", "status"] {
        let mut different = rejected.clone();
        different[field] = json!("other");
        assert!(!rejection_matches(&original, &different));
    }
    let mut missing = original.clone();
    missing["request_id"] = Value::Null;
    assert!(!rejection_matches(&missing, &rejected));
    if let Some(path) = std::env::var_os("STYX_TEST_SETUP_PAIR_NEW") {
        let root = PathBuf::from(path).join("cli");
        let mut answers: Answers = serde_json::from_value(valid()).unwrap();
        answers.role = Role::Join;
        answers.workspace = root.clone();
        answers.shell = PathBuf::from("/bin/sh");
        answers.join_link_file = Some(root.join("new-link"));
        answers
            .approve
            .extend(["trust".into(), "request".into(), "claim".into()]);
        let session = Session {
            root,
            answers,
            automated: true,
            plan_approved: false,
            mutation: Default::default(),
        };
        assert!(pair(&session, None).await.unwrap().is_some());
        return;
    }
    if let Some(path) = std::env::var_os("STYX_TEST_SETUP_REJECTION_FIXTURE") {
        let mut answers: Answers = serde_json::from_value(valid()).unwrap();
        answers.approve.insert("claim".into());
        let session = Session {
            root: PathBuf::from(path).join("cli"),
            answers,
            automated: true,
            plan_approved: false,
            mutation: Default::default(),
        };
        let failure = pair(&session, None).await.unwrap_err();
        assert_eq!(failure.code, "setup_pairing_rejected");
        assert_eq!(failure.exit, 2);
    }
}
fn valid() -> Value {
    json!({"schema":1,"role":"hub","payload":{"payload_dir":"/p/runtime","publisher_file":"/p/publisher.pem","expected_publisher":"a".repeat(64)},"label":"workstation","workspace":"/p/work","shell":"/bin/bash","approve":[]})
}
#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[test]
fn service_enable_precedes_start_without_a_live_writer_dependency() {
    use native::service::ServiceAction;
    let steps = service_steps();
    assert!(matches!(steps[0], ("install", ServiceAction::Install)));
    assert!(matches!(steps[1], ("enable", ServiceAction::Enable)));
    assert!(matches!(steps[2], ("start", ServiceAction::Start)));
}
#[test]
fn gateway_only_plan_never_pairs_or_runs_a_local_host() {
    let mut value = valid();
    value["role"] = json!("gateway");
    value["browser"] = json!(false);
    value["browser_executable"] = Value::Null;
    value["computer"] = json!(false);
    let answers: Answers = serde_json::from_value(value.clone()).unwrap();
    answers.validate().unwrap();
    let plan = plan_steps(&answers, false, Path::new("/private/setup"));
    let text = plan.join("\n");
    assert!(text.contains("Styx Gateway"));
    assert!(!text.contains("Pair this computer"));
    assert!(!text.contains("Enable commands"));
    assert!(!text.contains("computer's connection"));
    value["computer"] = json!(true);
    assert!(
        serde_json::from_value::<Answers>(value)
            .unwrap()
            .validate()
            .is_err()
    );
}
#[test]
fn plan_consent_never_supplies_automation_approval_or_new_identity_decisions() {
    let mut session = Session {
        root: PathBuf::from("/private/profile"),
        answers: serde_json::from_value(valid()).unwrap(),
        automated: false,
        plan_approved: true,
        mutation: Default::default(),
    };
    assert!(session.consent("payload", "Check installed files").is_ok());
    session.automated = true;
    assert_eq!(
        session
            .consent("payload", "Check installed files")
            .unwrap_err()
            .code,
        "setup_step_not_authorized"
    );
    assert_eq!(
        session
            .decision("trust", "Trust this hub?")
            .unwrap_err()
            .code,
        "setup_step_not_authorized"
    );
    session.answers.approve.insert("payload".into());
    assert!(session.consent("payload", "Check installed files").is_ok());
    assert!(session.decision("trust", "Trust this hub?").is_err());
}
#[test]
fn publisher_prompt_defaults_only_when_one_candidate_exists() {
    let root = std::env::current_dir()
        .unwrap()
        .join("target")
        .join(format!(
            "setup-publisher-{}-{}",
            std::process::id(),
            now_ms().unwrap()
        ));
    let payload = root.join("runtime");
    inputs::private_directory(&payload).unwrap();
    assert!(publisher_default(&payload).is_none());
    inputs::write_new(&root.join("publisher.pem"), b"public fixture").unwrap();
    assert_eq!(
        publisher_default(&payload),
        Some(root.join("publisher.pem"))
    );
    inputs::write_new(
        &payload.join("publisher-dev.pem"),
        b"another public fixture",
    )
    .unwrap();
    assert!(publisher_default(&payload).is_none());
    std::fs::remove_file(root.join("publisher.pem")).unwrap();
    assert_eq!(
        publisher_default(&payload),
        Some(payload.join("publisher-dev.pem"))
    );
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn publisher_pin_accepts_printed_fingerprint_without_deriving_trust() {
    let printed = vec!["AA"; 32].join(": ");
    assert_eq!(normalize_publisher_pin(&printed), "a".repeat(64));
    let mut value = valid();
    value["payload"]["expected_publisher"] = json!(printed);
    let answers: Answers = serde_json::from_value(value).unwrap();
    answers.validate().unwrap();
    assert_eq!(answers.payload.expected_publisher, "a".repeat(64));
    let mut value = valid();
    value["payload"]["expected_publisher"] = json!("not a fingerprint");
    assert!(
        serde_json::from_value::<Answers>(value)
            .unwrap()
            .validate()
            .is_err()
    );
}
#[tokio::test]
async fn host_runtime_events_identify_this_computer() {
    let (send, mut receive) = tokio::sync::mpsc::channel(1);
    let result = styx_runtime::foreground::gateway_run(
        Path::new("relative-test-state"),
        CancellationToken::new(),
        send,
    )
    .await;
    assert!(matches!(result, Err(error) if error.code() == "absolute_state_directory_required"));
    let mut event = receive.recv().await.unwrap();
    event.event = styx_runtime::foreground::ForegroundEventKind::Connecting;
    event.device_id = Some("setup-computer".to_owned().try_into().unwrap());
    assert_eq!(runtime_event_line(&event), "This computer: connecting");
    event.reason = Some("waiting");
    assert_eq!(
        runtime_event_line(&event),
        "This computer: connecting (waiting)"
    );
    event.device_id = None;
    event.event = styx_runtime::foreground::ForegroundEventKind::GatewayLoading;
    event.reason = None;
    assert_eq!(runtime_event_line(&event), "Runtime: gateway_loading");
}
#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[tokio::test]
async fn setup_clean_foreground_stop_then_rerun_keeps_committed_intent() {
    use styx_contracts::native_management::{NativeDeploymentMode, NativeManager};
    let root = std::env::current_dir()
        .unwrap()
        .join("target")
        .join(format!(
            "setup-clean-stop-{}-{}",
            std::process::id(),
            now_ms().unwrap()
        ));
    inputs::private_directory(&root.join("inputs")).unwrap();
    let session = Session {
        root: root.clone(),
        answers: serde_json::from_value(valid()).unwrap(),
        automated: true,
        plan_approved: false,
        mutation: Default::default(),
    };
    for (name, mode, component, deployment) in [
        (
            "gateway",
            NativeDeploymentMode::CreateLocal,
            native::NativeComponent::Gateway,
            json!({"schema":1,"mode":"create-local","gateway":{"url":"https://127.0.0.1:22122/","runtime":{}}}),
        ),
        (
            "host",
            NativeDeploymentMode::JoinExisting,
            native::NativeComponent::Host,
            json!({"schema":1,"mode":"join-existing","gateway":{"url":"https://127.0.0.1:22122/"},"host":{"computer":false}}),
        ),
    ] {
        let file = session.input(&format!("{name}.json"));
        inputs::write_new(&file, &serde_json::to_vec(&deployment).unwrap()).unwrap();
        let path = root.join(name);
        native::initialize(
            &root,
            std::ffi::OsStr::new(name),
            &file,
            native::NativeCreateOptions {
                mode,
                manager: NativeManager::ForegroundCli,
                host: name == "host",
                gateway: name == "gateway",
            },
        )
        .await
        .unwrap();
        let step = format!("{name}-running");
        desired_running(&session, &path, component, &step)
            .await
            .unwrap();
        let before = std::fs::read(path.join("state.json")).unwrap();
        // Role shutdown joins its tasks without changing desired Running.
        // Reopening the actual C07 transaction reproduces the reported fence.
        Foreground::new().stop().await.unwrap();
        assert!(native::inspect(&path, None).await.unwrap().admission_fenced);
        for _ in 0..2 {
            desired_running(&session, &path, component, &step)
                .await
                .unwrap();
            assert_eq!(std::fs::read(path.join("state.json")).unwrap(), before);
        }
        // A complete native tip does not excuse a lost setup completion.
        std::fs::remove_file(session.input(&format!("{step}.done"))).unwrap();
        let error = desired_running(&session, &path, component, &step)
            .await
            .unwrap_err();
        assert_eq!(error.exit, 4);
        assert_eq!(error.code, "setup_previous_outcome_unknown");
        assert_eq!(std::fs::read(path.join("state.json")).unwrap(), before);
    }
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn answers_reject_unknown_fields_invalid_choices_and_embedded_secrets() {
    let parse = |value: Value| -> bool {
        serde_json::from_value::<Answers>(value)
            .ok()
            .is_some_and(|a| a.validate().is_ok())
    };
    assert!(parse(valid()));
    for field in ["api_key", "password", "unexpected"] {
        let mut v = valid();
        v[field] = json!("secret-must-not-be-accepted");
        assert!(!parse(v));
    }
    for changes in [
        json!({"schema":2}),
        json!({"role":"other"}),
        json!({"workspace":"relative"}),
        json!({"networks":["8.8.8.8"]}),
        json!({"networks":["10.0.0.1","10.0.0.1"]}),
        json!({"browser":true}),
        json!({"role":"join","tunnel":{"id":format!("tunnel_{}","a".repeat(32))}}),
        json!({"approve":["everything"]}),
    ] {
        let mut v = valid();
        v.as_object_mut()
            .unwrap()
            .extend(changes.as_object().unwrap().clone());
        assert!(!parse(v));
    }
}
#[test]
fn custom_mcp_icon_export_reuses_exact_asset_and_preserves_conflicts() {
    let root = std::env::temp_dir().join(format!(
        "styx-custom-mcp-{}-{}",
        std::process::id(),
        now_ms().unwrap()
    ));
    let path = prepare_chatgpt_icon(&root).unwrap();
    let exported = std::fs::read(&path).unwrap();
    assert!(exported.len() <= 10_000);
    assert_eq!(&exported[..8], b"\x89PNG\r\n\x1a\n");
    assert_eq!(exported, CHATGPT_ICON);
    assert_eq!(prepare_chatgpt_icon(&root).unwrap(), path);
    assert!(!root.join("inputs/plugin-intent.json").exists());
    assert!(!root.with_extension("zip").exists());

    std::fs::write(&path, b"owner file").unwrap();
    assert_eq!(
        prepare_chatgpt_icon(&root).unwrap_err().code,
        "setup_chatgpt_icon_conflict"
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"owner file");
    std::fs::remove_file(&path).unwrap();
    assert_eq!(
        std::fs::read(prepare_chatgpt_icon(&root).unwrap()).unwrap(),
        CHATGPT_ICON
    );
    #[cfg(unix)]
    {
        std::fs::remove_file(&path).unwrap();
        let other = root.join("owner-icon.png");
        std::fs::write(&other, CHATGPT_ICON).unwrap();
        std::os::unix::fs::symlink(&other, &path).unwrap();
        assert_eq!(
            prepare_chatgpt_icon(&root).unwrap_err().code,
            "setup_chatgpt_icon_conflict"
        );
        assert_eq!(std::fs::read(other).unwrap(), CHATGPT_ICON);
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn tunnel_setup_does_not_require_a_zip_profile() {
    let mut value = valid();
    value["tunnel"] = json!({"id": format!("tunnel_{}", "a".repeat(32))});
    let answers: Answers = serde_json::from_value(value).unwrap();
    answers.validate().unwrap();
    assert!(answers.plugin.is_none());
    let plan = plan_steps(&answers, true, Path::new("/tmp/styx-example"));
    assert!(plan.iter().any(|step| step.contains("Custom MCP > Tunnel")));
    assert!(!plan.iter().any(|step| step.contains("legacy ZIP")));
}

#[tokio::test]
async fn custom_mcp_resume_does_not_read_or_rewrite_legacy_zip_inputs() {
    let root = std::env::temp_dir().join(format!(
        "styx-legacy-zip-resume-{}-{}",
        std::process::id(),
        now_ms().unwrap()
    ));
    inputs::private_directory(&root.join("inputs")).unwrap();
    let legacy_intent = root.join("inputs/plugin-intent.json");
    inputs::write_new(&legacy_intent, b"older or incomplete export intent").unwrap();
    let mut answers: Answers = serde_json::from_value(valid()).unwrap();
    answers.plugin = Some(Plugin {
        display_name: "Existing Styx".into(),
        profile: None,
        output: root.join("styx-native"),
        wait: false,
    });
    let mut session = Session {
        root: root.clone(),
        answers,
        automated: false,
        plan_approved: true,
        mutation: Default::default(),
    };
    // No Gateway exists here. Custom MCP must not discover one just to
    // validate an old archive, even when the saved ZIP intent is invalid.
    export_legacy_plugin(&mut session, &root.join("gateway"))
        .await
        .unwrap();
    session.automated = true;
    export_legacy_plugin(&mut session, &root.join("gateway"))
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(&legacy_intent).unwrap(),
        b"older or incomplete export intent"
    );
    assert!(!root.join("styx-native").exists());
    session.answers.approve.insert("plugin".into());
    assert_eq!(
        export_legacy_plugin(&mut session, &root.join("gateway"))
            .await
            .unwrap_err()
            .code,
        "setup_plugin_intent_invalid"
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn resume_dispatch_without_receipt_is_never_replayed() {
    let root = std::env::current_dir()
        .unwrap()
        .join("target")
        .join(format!(
            "setup-resume-{}-{}",
            std::process::id(),
            now_ms().unwrap()
        ));
    inputs::private_directory(&root.join("inputs")).unwrap();
    let session = Session {
        root: root.clone(),
        answers: serde_json::from_value(valid()).unwrap(),
        automated: true,
        plan_approved: false,
        mutation: Default::default(),
    };
    for step in [
        "payload",
        "workspace",
        "gateway-bootstrap",
        "tunnel",
        "gateway-service-install",
        "gateway-service-start",
        "gateway-service-enable",
        "local-invite",
        "join-input",
        "request",
        "approve",
        "claim",
        "host-service-install",
        "host-service-start",
        "host-service-enable",
        "plugin",
    ] {
        assert!(!session.completed(step));
        session
            .begin(step)
            .unwrap_or_else(|_| panic!("first dispatch"));
        assert_eq!(session.begin(step).err().unwrap().exit, 4);
        session
            .done(step)
            .unwrap_or_else(|_| panic!("completion receipt"));
        assert!(session.completed(step));
    }
    std::fs::remove_dir_all(root).unwrap();
}
