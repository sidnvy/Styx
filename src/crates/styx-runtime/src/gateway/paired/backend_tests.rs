//! Local contract boundaries only. No native or transport evidence is claimed.
use super::*;
fn args(v: Value) -> Option<Map<String, Value>> {
    Some(v.as_object().unwrap().clone())
}
#[test]
fn frozen_tools_and_exec_arguments_preserve_legacy_edges() {
    assert_eq!(PUBLIC.len(), 38);
    assert_eq!(PUBLIC[0].name, "exec_command");
    assert_eq!(PUBLIC[1].name, "write_stdin");
    assert_eq!(
        PUBLIC.last().unwrap().name,
        "get_execution_environment_status"
    );
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
fn authenticated_host_errors_preserve_certainty_and_read_cursor_evidence() {
    use styx_contracts::error::{ErrorCategory, ExecutionCertainty};
    fn projection(result: CallToolResult) -> Value {
        assert_eq!(result.is_error, Some(true));
        assert!(result.structured_content.is_none());
        let wire = serde_json::to_value(result).unwrap();
        serde_json::from_str(wire["content"][0]["text"].as_str().unwrap()).unwrap()
    }
    fn explicit(
        category: ErrorCategory,
        certainty: ExecutionCertainty,
        cursor_may_be_consumed: bool,
    ) -> Result<Reply, super::super::RelayError> {
        Ok(Reply::Error {
            category,
            certainty,
            cursor_may_be_consumed,
        })
    }
    // Typed authenticated Host evidence is the only source of known refusal.
    let denied = HostFailure::from_exchange(&explicit(
        ErrorCategory::PermissionDenied,
        ExecutionCertainty::NotDispatched,
        false,
    ))
    .unwrap();
    let mut mutation_unknown = true;
    let value = projection(denied.mutation_result(&mut mutation_unknown, 17));
    assert_eq!(value["category"], "PERMISSION_DENIED");
    assert_eq!(value["error"], "permission_denied");
    assert_eq!(value["execution_certainty"], "not_dispatched");
    assert_eq!(value["session_id"], 17);
    assert_eq!(value["cursor_may_be_consumed"], false);
    assert_eq!(value["uncertain"], false);
    assert!(!mutation_unknown);
    let unknown = HostFailure::from_exchange(&explicit(
        ErrorCategory::ResultUnknown,
        ExecutionCertainty::Unknown,
        false,
    ))
    .unwrap();
    mutation_unknown = true;
    let value = projection(unknown.mutation_result(&mut mutation_unknown, 17));
    assert_eq!(value["category"], "RESULT_UNKNOWN");
    assert_eq!(value["execution_certainty"], "unknown");
    assert_eq!(value["uncertain"], true);
    assert!(mutation_unknown);
    // Category alone is not certainty: even a permission error can have an
    // unknown effect. Completed without a successful action receipt is no ACK.
    for certainty in [ExecutionCertainty::Unknown, ExecutionCertainty::Completed] {
        mutation_unknown = true;
        let fact = HostFailure::from_exchange(&explicit(
            ErrorCategory::PermissionDenied,
            certainty,
            false,
        ))
        .unwrap();
        let _ = fact.mutation_result(&mut mutation_unknown, 17);
        assert!(mutation_unknown);
    }
    for cursor_consumed in [false, true] {
        let mut cursor_unknown = true; // Production poisons before native await.
        let fact = HostFailure::from_exchange(&explicit(
            ErrorCategory::ResultUnknown,
            ExecutionCertainty::Unknown,
            cursor_consumed,
        ))
        .unwrap();
        let value = projection(fact.read_result(&mut cursor_unknown, 17));
        assert_eq!(value["cursor_may_be_consumed"], cursor_consumed);
        assert_eq!(value["execution_certainty"], "unknown");
        assert_eq!(cursor_unknown, cursor_consumed);
    }
    let mut cursor_unknown = true;
    let _ = denied.read_result(&mut cursor_unknown, 17);
    assert!(!cursor_unknown);
    // No transport or generic adapter error can be upgraded into Host proof,
    // including a local authorization error. Missing replies retain poison.
    for error in [
        super::super::RelayError::Unknown,
        super::super::RelayError::Offline,
        super::super::RelayError::Unauthorized,
        super::super::RelayError::Busy,
        super::super::RelayError::Invalid,
        super::super::RelayError::Unsupported,
    ] {
        assert!(HostFailure::from_exchange(&Err(error)).is_none());
    }
}
