//! Transport serialization negatives; actual TLS/signed state journey is owned
//! by enrollment/service_tests.rs, not duplicated by this focused fixture.
use super::*;

#[test]
fn response_serialization_is_bounded_before_growth_and_never_returns_partial_secret() {
    let value = serde_json::json!({"public":"é".repeat(RESPONSE_BYTES)});
    assert!(encode_response(&value).is_err());
    let accepted = serde_json::Value::String("x".repeat(RESPONSE_BYTES - 2));
    assert_eq!(encode_response(&accepted).unwrap().len(), RESPONSE_BYTES);
    let mut writer = BoundedResponse(vec![0; RESPONSE_BYTES]);
    assert!(writer.write_all(b"x").is_err());
    assert_eq!(writer.0.len(), RESPONSE_BYTES);
    let failed = failure(503, "enrollment_outcome_unknown", true);
    assert_eq!(failed.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(failed.headers()[http::header::CACHE_CONTROL], "no-store");
    assert_eq!(failed.headers()[http::header::CONNECTION], "close");
    assert_eq!(
        failed.headers()[http::header::X_CONTENT_TYPE_OPTIONS],
        "nosniff"
    );
}
