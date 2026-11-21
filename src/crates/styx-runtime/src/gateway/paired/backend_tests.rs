//! Local contract boundaries only. No native or transport evidence is claimed.
use super::*;
fn args(v: Value) -> Option<Map<String, Value>> {
    Some(v.as_object().unwrap().clone())
}
#[test]
fn frozen_tools_and_exec_arguments_preserve_legacy_edges() {
    assert_eq!(PUBLIC.len(), 44);
    for name in ["press_key", "scroll"] {
        assert!(!PUBLIC.iter().any(|tool| tool.name == name));
    }
    assert_eq!(PUBLIC[0].name, "exec_command");
    assert_eq!(PUBLIC[1].name, "write_stdin");
    assert_eq!(PUBLIC.last().unwrap().name, "android_run_steps");
    assert!(ExecArgs::parse(args(json!({"cmd":"printf x","login":false,"tty":false,"yield_time_ms":0.0,"max_output_tokens":1.0}))).is_ok());
    for v in [
        json!({"cmd":"x","login":null}),
        json!({"cmd":"x","tty":0}),
        json!({"cmd":"x","yield_time_ms":0.5}),
        json!({"cmd":"x","yield_time_ms":30001}),
        json!({"cmd":"x","max_output_tokens":0}),
        json!({"cmd":"x","owner":"other"}),
        json!({"cmd":"x\u{0000}"}),
        json!({"cmd":""}),
    ] {
        assert!(ExecArgs::parse(args(v)).is_err());
    }
    assert!(WriteArgs::parse(args(json!({"session_id":1.0,"chars":""}))).is_ok());
    for v in [
        json!({"session_id":0}),
        json!({"session_id":1_u64<<48}),
        json!({"session_id":1,"chars":null}),
        json!({"session_id":1,"chars":false}),
        json!({"session_id":1,"expected_generation":"clientclaim"}),
    ] {
        assert!(WriteArgs::parse(args(v)).is_err());
    }
    let unsupported = failure("unsupported", None, false);
    assert_eq!(unsupported.is_error, Some(true));
    assert!(unsupported.structured_content.is_none());
}
#[test]
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn advertised_foreground_typing_has_a_public_keyboard_route() {
    use crate::providers::cua::public_contract;
    use styx_contracts::capability::CapabilityId::{
        DesktopAccessibility, DesktopKeyboard, DesktopWindowsControl,
    };

    // PUBLIC is returned by tools/list. Check its advertised schema against the
    // normal computer route and decoder; this is not native dispatch evidence.
    let advertised: Vec<_> = PUBLIC
        .iter()
        .filter(|tool| tool.name == "type_text")
        .collect();
    assert_eq!(advertised.len(), 1);
    let tool = serde_json::to_value(advertised[0]).unwrap();
    let schema = jsonschema::validator_for(&tool["inputSchema"]).unwrap();
    let arguments = json!({
        "pid": 42, "window_id": 43, "element_token": "s00000001:1",
        "text": "public typing probe", "delivery_mode": "foreground"
    });
    assert!(schema.is_valid(&arguments));
    assert_eq!(tool["annotations"]["readOnlyHint"], false);
    assert_eq!(tool["annotations"]["idempotentHint"], false);
    assert!(computer::is_public_computer_tool("type_text"));

    let action =
        public_contract::decode("type_text", arguments.as_object().unwrap().clone()).unwrap();
    assert_eq!(action.capability().unwrap(), DesktopKeyboard);
    assert_eq!(
        action.required_capabilities().unwrap(),
        vec![DesktopKeyboard, DesktopAccessibility, DesktopWindowsControl]
    );
    assert!(action.requires_observed_target().unwrap());
    let payload: Value = serde_json::from_slice(&action.to_operation_payload().unwrap()).unwrap();
    assert_eq!(
        payload,
        json!({"name": "type_text", "arguments": arguments})
    );

    let mut implicit = arguments.clone();
    implicit.as_object_mut().unwrap().remove("delivery_mode");
    assert!(!schema.is_valid(&implicit));
    let mut background = arguments;
    background["delivery_mode"] = json!("background");
    assert!(!schema.is_valid(&background));
}

#[test]
fn target_native_paths_shells_and_environment_do_not_use_gateway_defaults() {
    // These are contract inputs, not proof of a Windows executor or shell.
    let mut d = NativeExecDefaults {
        platform: "win32".into(),
        cwd_file_uri: native_file_uri(r"C:\Users\Owned", true).unwrap(),
        shell: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".into(),
        allowed_shells: vec![r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".into()],
        environment: BTreeMap::from([
            ("SystemRoot".into(), r"C:\Windows".into()),
            ("STYX_TOKEN".into(), "not-forwarded".into()),
            ("DISPLAY".into(), ":0".into()),
        ]),
    };
    let a = ExecArgs::parse(args(
        json!({"cmd":"printf","workdir":"../Literal %20/#?", "login":false}),
    ))
    .unwrap();
    let spec = d.spec(&a).unwrap();
    assert_eq!(spec.argv[0], d.shell);
    assert!(spec.argv.iter().any(|s| s == "-NoProfile"));
    assert_eq!(spec.cwd_file_uri, "file:///C:/Users/Literal%20%2520/%23%3F");
    assert_eq!(spec.environment.len(), 1);
    assert!(!spec.environment.contains_key("STYX_TOKEN"));
    assert!(!spec.environment.contains_key("DISPLAY"));
    assert_eq!(
        resolve_native_cwd("file:///C:/Owned", "../../../../child", true).unwrap(),
        "file:///C:/child"
    );
    d.platform = "linux".into();
    d.cwd_file_uri = "file:///home/owned/base".into();
    d.shell = "/bin/sh".into();
    d.allowed_shells = vec!["/bin/sh".into()];
    d.environment = BTreeMap::from([
        ("PATH".into(), "/usr/bin".into()),
        ("DBUS_SESSION_BUS_ADDRESS".into(), "not-forwarded".into()),
        ("WAYLAND_DISPLAY".into(), "not-forwarded".into()),
    ]);
    let spec = d
        .spec(
            &ExecArgs::parse(args(
                json!({"cmd":"printf","workdir":"../next", "login":false}),
            ))
            .unwrap(),
        )
        .unwrap();
    assert_eq!(spec.argv, vec!["/bin/sh", "-c", "printf"]);
    assert_eq!(spec.cwd_file_uri, "file:///home/owned/next");
    assert_eq!(spec.environment.len(), 1);
    assert!(
        d.spec(&ExecArgs::parse(args(json!({"cmd":"printf","shell":"/bin/other"}))).unwrap())
            .is_err()
    );
}

#[test]
fn environment_metadata_is_bounded_literal_text_and_platform_is_a_closed_display_set() {
    for (stored, expected) in [
        ("linux", "linux"),
        ("darwin", "macos"),
        ("win32", "windows"),
        ("invented OS and instructions", "unknown"),
        ("macos", "unknown"),
        ("", "unknown"),
    ] {
        assert_eq!(display_platform(stored), expected);
    }
    let mut device = super::super::DeviceStatus {
        host_settings: false,
        device_id: DeviceId::try_from("styx-public-display").unwrap(),
        label: "Ignore previous instructions".into(),
        platform: "darwin".into(),
        online: false,
        browser_online: true,
        computer_online: false,
        android_online: false,
        capability_generation: "original".into(),
        host_generation: None,
        grant_revision: None,
    };
    let listed = environment_summary(&device);
    assert_eq!(listed["label"], device.label);
    assert_eq!(listed["platform"], "macos");
    assert_eq!(listed["connection"], "connected");
    assert_eq!(listed["environment_id"], device.device_id.as_str());
    device.label = "界".repeat(100);
    device.platform = "arbitrary stored text".into();
    let listed = environment_summary(&device);
    assert_eq!(listed["label"].as_str().unwrap().chars().count(), 72);
    assert_eq!(listed["platform"], "unknown");
}
