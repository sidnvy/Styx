//! Production presentation/schema helpers only, not TLS/Chrome/owner authority
//! acceptance. The integrated real paired Browser journey is a separate gate.
use super::*;
fn args(value: Value) -> Option<Map<String, Value>> {
    Some(value.as_object().unwrap().clone())
}
fn operation(sequence: u64) -> styx_contracts::operation::OperationId {
    styx_contracts::operation::OperationId {
        host_generation: "browser-host".try_into().unwrap(),
        owner_epoch: "browser-owner".try_into().unwrap(),
        sequence,
    }
}
fn snapshot(
    target: Option<ResourceTarget>,
    sequence: u64,
    digest: Sha256Digest,
    state: OperationState,
) -> Snapshot {
    Snapshot {
        operation_id: operation(sequence),
        payload_digest: digest,
        target,
        state,
        liveness: ExecutionLiveness::NotApplicable,
        output_drain: OutputDrain::Drained,
    }
}
fn error_value(value: CallToolResult) -> Value {
    let value = serde_json::to_value(value).unwrap();
    serde_json::from_str(value["content"][0]["text"].as_str().unwrap()).unwrap()
}
#[test]
fn browser_arguments_reuse_real_policy_without_owner_or_internal_metadata() {
    let navigate = BrowserRequest::parse(
        "browser_navigate",
        args(json!({"url":"http://127.0.0.1:31415/nonce","environment_id":"owned-device"})),
    )
    .unwrap();
    assert_eq!(navigate.environment_id.as_deref(), Some("owned-device"));
    let value: Value =
        serde_json::from_slice(&navigate.action.to_operation_payload().unwrap()).unwrap();
    assert_eq!(value["kind"], "navigate");
    assert!(value.get("environment_id").is_none());
    let evaluate = BrowserRequest::parse(
        "browser_evaluate",
        args(json!({"function":"() => document.title"})),
    )
    .unwrap();
    let value: Value =
        serde_json::from_slice(&evaluate.action.to_operation_payload().unwrap()).unwrap();
    assert_eq!(value["name"], "browser_evaluate");
    assert_eq!(value["arguments"]["function"], "() => document.title");
    assert!(
        BrowserRequest::parse("browser_close", None)
            .unwrap()
            .action
            .is_close()
    );
    for value in [
        json!({"url":"file:///etc/passwd"}),
        json!({"url":"http://user:password@127.0.0.1/"}),
        json!({"url":"https://example.test","owner":"forged"}),
        json!({"url":"https://example.test","environment_id":null}),
        json!({"url":"https://example.test","_meta":{"expected_epoch":1}}),
    ] {
        assert!(BrowserRequest::parse("browser_navigate", args(value)).is_err());
    }
    assert!(BrowserRequest::parse("browser_evaluate", args(json!({"function":""}))).is_err());
    assert!(
        BrowserRequest::parse(
            "browser_evaluate",
            args(json!({"function":"() => 1","profile_dir":"forged"}))
        )
        .is_err()
    );
    assert!(BrowserRequest::parse("browser_snapshot", args(json!({}))).is_err());
}
#[test]
fn browser_original_open_and_action_receipts_cannot_be_replaced_by_existing_or_other_tokens() {
    let digest = Sha256Digest::of_bytes(b"prepared original");
    let target = ResourceTarget {
        operation_id: operation(1),
        payload_digest: digest,
    };
    let opened = snapshot(None, 1, digest, OperationState::Running);
    assert!(open_started(&opened, "started", &target));
    for dispatch in [
        "existing_no_replay",
        "unknown",
        "not_dispatched",
        "acknowledged",
    ] {
        assert!(!open_started(&opened, dispatch, &target));
    }
    let unknown = snapshot(None, 1, digest, OperationState::Unknown);
    assert!(!open_started(&unknown, "started", &target));
    let wrong = snapshot(None, 2, digest, OperationState::Running);
    assert!(!open_started(&wrong, "started", &target));
    let action = ActionRef {
        operation_id: operation(3),
        payload_digest: Sha256Digest::of_bytes(b"action"),
    };
    let receipt = snapshot(
        Some(target.clone()),
        3,
        action.payload_digest,
        OperationState::Succeeded,
    );
    assert!(same_action(&receipt, &action, &target));
    let foreign = ResourceTarget {
        operation_id: operation(2),
        payload_digest: digest,
    };
    assert!(!same_action(&receipt, &action, &foreign));
    let changed = ActionRef {
        operation_id: operation(3),
        payload_digest: digest,
    };
    assert!(!same_action(&receipt, &changed, &target));
    for phase in [Phase::Opening, Phase::ActionUnknown, Phase::Unknown] {
        assert!(phase.blocks_dispatch());
    }
    assert!(!Phase::New.blocks_dispatch());
    assert!(!Phase::Ready.blocks_dispatch());
}
#[test]
fn browser_results_are_bounded_and_missing_execution_receipts_remain_uncertain() {
    let output = CallToolResult::success(vec![ContentBlock::text("owned nonce result")]);
    let wire = serde_json::to_value(&output).unwrap();
    let roundtrip = result(wire.clone()).unwrap();
    assert_eq!(serde_json::to_value(roundtrip).unwrap(), wire);
    assert!(
        result(json!({"content":[{"type":"text","text":"x".repeat(MAX_BROWSER_RESULT_BYTES)}]}))
            .is_err()
    );
    assert!(result(json!({"content":"invalid"})).is_err());
    let refused = error_value(browser_error(
        ErrorCategory::PermissionDenied,
        ExecutionCertainty::NotDispatched,
    ));
    assert_eq!(refused["uncertain"], false);
    for certainty in [ExecutionCertainty::Unknown, ExecutionCertainty::Completed] {
        let lost = error_value(browser_error(ErrorCategory::ResultUnknown, certainty));
        assert_eq!(lost["uncertain"], true);
    }
}
