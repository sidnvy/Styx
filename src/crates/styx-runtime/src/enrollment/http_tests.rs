//! Transport serialization negatives; actual TLS/signed state journey is owned
//! by enrollment/service_tests.rs, not duplicated by this focused fixture.
use super::*;

#[test]
fn gateway_lan_routes_exclude_mcp_and_every_admin_route() {
    for path in [
        "/styx/enroll/join",
        "/styx/enroll/claim",
        "/styx/enroll/confirm",
        "/styx/enroll/self/styx-0123456789abcdef01234567/capabilities",
    ] {
        assert_eq!(lan_route(path), Some(LanRoute::Enrollment));
    }
    assert_eq!(
        lan_route("/styx/host/v3/styx-0123456789abcdef01234567/exec"),
        Some(LanRoute::HostLink)
    );
    for path in [
        "/mcp",
        "/mcp/",
        "/admin",
        "/control",
        "/styx/enroll/pending",
        "/styx/enroll/devices",
        "/styx/enroll/invitations",
        "/styx/enroll/invitations/close",
        "/styx/enroll/approve",
        "/styx/enroll/revoke",
        "/styx/enroll/recover",
        "/styx/enroll/capabilities",
        "/styx/enroll/set-default",
        "/styx/enroll/self/invalid/capabilities",
        "/styx/enroll/join/../approve",
        "/styx/enroll/%61pprove",
    ] {
        assert_eq!(lan_route(path), None, "{path}");
    }
}

#[test]
fn gateway_listener_host_and_origin_allowlists_are_disjoint() {
    let local = BTreeSet::from(["127.0.0.1:8795".into()]);
    let lan = BTreeSet::from(["192.168.1.2:8795".into()]);
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, "192.168.1.2:8795".parse().unwrap());
    headers.insert(
        http::header::ORIGIN,
        "https://192.168.1.2:8795".parse().unwrap(),
    );
    assert!(listener_headers(&headers, &lan, true));
    assert!(!listener_headers(&headers, &local, true));
    headers.insert(
        http::header::ORIGIN,
        "https://127.0.0.1:8795".parse().unwrap(),
    );
    assert!(!listener_headers(&headers, &lan, true));
    headers.remove(http::header::ORIGIN);
    assert!(listener_headers(&headers, &lan, true));
    headers.append(http::header::HOST, "127.0.0.1:8795".parse().unwrap());
    assert!(!listener_headers(&headers, &lan, true));
}

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
