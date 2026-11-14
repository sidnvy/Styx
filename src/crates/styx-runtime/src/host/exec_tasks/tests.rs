//! Exec certainty belongs beside the Host task state it protects.
use super::*;
#[test]
fn authenticated_host_errors_preserve_certainty_and_read_cursor_evidence() {
    use styx_contracts::error::{ErrorCategory, ExecutionCertainty};
    fn projection(result: ExecTaskResult) -> Value {
        assert!(result.is_error);
        result.value
    }
    fn explicit(
        category: ErrorCategory,
        certainty: ExecutionCertainty,
        cursor_may_be_consumed: bool,
    ) -> Result<Reply, ()> {
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
    assert!(HostFailure::from_exchange(&Err(())).is_none());
}

#[test]
fn known_capacity_is_retryable_and_never_an_unknown_action() {
    fn value(r: ExecTaskResult) -> Value {
        r.value
    }
    let busy = HostFailure {
        category: styx_contracts::error::ErrorCategory::Busy,
        certainty: styx_contracts::error::ExecutionCertainty::NotDispatched,
        cursor_may_be_consumed: false,
    };
    let mut unknown = true;
    let result = value(busy.mutation_result(&mut unknown, 17));
    assert_eq!(result["error"], "capacity_busy");
    assert_eq!(result["uncertain"], false);
    assert_eq!(result["retryable"], true);
    assert!(!unknown);
    for cause in ["capacity", "busy", "capacity_busy"] {
        let r = value(failure(cause, None, false));
        assert_eq!(r["error"], "capacity_busy");
        assert_eq!(r["uncertain"], false);
        assert_eq!(r["retryable"], true);
    }
    assert_eq!(
        value(failure("outcome_unknown", None, true))["uncertain"],
        true,
        "missing replies must retain uncertainty"
    );
}
