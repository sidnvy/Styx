//! Pure admin response/binding contract tests; not platform/TLS acceptance.
use super::*;
use serde_json::json;

#[test]
fn gateway_invitation_reports_lan_by_default_but_keeps_loopback_selectable() {
    let mut origins = vec!["https://127.0.0.1:22345".into()];
    assert_eq!(invitation_origin(&origins, None).unwrap(), origins[0]);
    assert!(invitation_origin(&origins, Some(InvitationOrigin::Lan)).is_err());
    origins.push("https://100.64.0.2:22345".into());
    assert_eq!(invitation_origin(&origins, None).unwrap(), origins[1]);
    assert_eq!(
        invitation_origin(&origins, Some(InvitationOrigin::Lan)).unwrap(),
        origins[1]
    );
    assert_eq!(
        invitation_origin(&origins, Some(InvitationOrigin::Loopback)).unwrap(),
        origins[0]
    );
}

#[test]
fn gateway_lan_pending_compares_actual_ingress_and_rejects_foreign_origins_or_leaves() {
    let (local, leaf, mut row, mut selected) = fixture();
    let lan = "https://192.168.1.2:22345".to_owned();
    let origins = vec![local.origin().ascii_serialization(), lan.clone()];
    let original_code = row["comparison_code"].clone();
    row["ingress"]["origin"] = json!(lan);
    let encode = |row: &serde_json::Value| serde_json::to_vec(&vec![row]).unwrap();
    assert!(pending_body(&encode(&row), &origins, &leaf, 10_000).is_err());
    selected.comparison_code = PairingComparison {
        gateway_origin: lan.clone(),
        certificate_sha256: Sha256Digest::try_from(leaf.as_hex()).unwrap(),
        request_id: selected.request_id.clone(),
        device_fingerprint: selected.fingerprint,
    }
    .comparison_code()
    .unwrap();
    row["comparison_code"] = json!(selected.comparison_code);
    assert_ne!(row["comparison_code"], original_code);
    let rows = pending_body(&encode(&row), &origins, &leaf, 10_000).unwrap();
    assert_eq!(rows[0].gateway_origin, lan);
    assert!(approval_body(&rows, &selected).is_ok());
    assert!(pending_body(&encode(&row), &origins[..1], &leaf, 10_000).is_err());
    assert!(
        pending_body(
            &encode(&row),
            &origins,
            &GatewayLeafPin::from_certificate_der(b"other"),
            10_000
        )
        .is_err()
    );
    row["ingress"]["origin"] = json!("https://192.168.1.3:22345");
    assert!(pending_body(&encode(&row), &origins, &leaf, 10_000).is_err());
}
fn fixture() -> (
    url::Url,
    GatewayLeafPin,
    serde_json::Value,
    ApprovalSelection,
) {
    let origin = url::Url::parse("https://127.0.0.1:22345/").expect("origin");
    let leaf = GatewayLeafPin::from_certificate_der(b"fixed observed peer DER test input");
    let fingerprint = Sha256Digest::of_bytes(b"actual Host SPKI test input");
    let request_id = "a".repeat(32);
    let device_id = DeviceId::try_from(format!("styx-{}", "b".repeat(24))).expect("device");
    let comparison = PairingComparison {
        gateway_origin: origin.origin().ascii_serialization(),
        certificate_sha256: Sha256Digest::try_from(leaf.as_hex()).expect("leaf"),
        request_id: request_id.clone(),
        device_fingerprint: fingerprint,
    }
    .comparison_code()
    .expect("original shared codec");
    let row = json!({"request_id":request_id,"device_id":device_id,"fingerprint":fingerprint,"comparison_code":comparison,"expires_at":20_000,
        "computer_requested":false,"browser_requested":true,"ingress":{"origin":origin.origin().ascii_serialization(),"certificate_sha256":leaf.as_hex(),"generation":"original"},
        "label":"public label","platform":"linux","cwd":"/private/work","shell":"/bin/sh"});
    let selected = ApprovalSelection {
        request_id,
        device_id,
        fingerprint,
        comparison_code: comparison,
        enable_computer: false,
        enable_browser: true,
    };
    (origin, leaf, row, selected)
}
#[test]
fn pending_actual_leaf_and_explicit_identity_gate_the_original_approval_body() {
    let (origin, leaf, row, selected) = fixture();
    let raw = serde_json::to_vec(&vec![row.clone()]).expect("fixture");
    let rows = pending_body(
        &raw,
        &[origin.origin().ascii_serialization()],
        &leaf,
        10_000,
    )
    .expect("verified pending");
    let wire = approval_body(&rows, &selected).expect("exact explicit binding");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&wire).expect("wire"),
        json!({"request_id":selected.request_id,"fingerprint":selected.fingerprint,"enable_computer":false,"enable_browser":true})
    );
    let error = pending_body(
        &raw,
        &[origin.origin().ascii_serialization()],
        &GatewayLeafPin::from_certificate_der(b"other peer"),
        10_000,
    )
    .err()
    .expect("wrong actual peer denied");
    assert_eq!(error.code(), "native_gateway_pending_binding_mismatch");
    for field in [
        "request_id",
        "device_id",
        "fingerprint",
        "comparison_code",
        "computer",
    ] {
        let (_, _, _, mut wrong) = fixture();
        match field {
            "request_id" => wrong.request_id = "c".repeat(32),
            "device_id" => {
                wrong.device_id =
                    DeviceId::try_from(format!("styx-{}", "c".repeat(24))).expect("other device")
            }
            "fingerprint" => wrong.fingerprint = Sha256Digest::of_bytes(b"other SPKI"),
            "comparison_code" => wrong.comparison_code = "0000-0000-0000-0000".into(),
            "computer" => wrong.enable_computer = true,
            _ => unreachable!(),
        }
        // This is the production helper called before the sole approval POST.
        let error = approval_body(&rows, &wrong).expect_err("wrong explicit selection denied");
        assert_eq!(error.code(), "native_gateway_approval_binding_mismatch");
        assert_eq!(error.outcome(), "not_dispatched");
        assert_eq!(error.exit_code(), 2);
    }
    assert!(
        pending_body(
            &serde_json::to_vec(&vec![row.clone(), row.clone()]).expect("duplicate"),
            &[origin.origin().ascii_serialization()],
            &leaf,
            10_000
        )
        .is_err()
    );
    assert!(
        pending_body(
            &raw,
            &[origin.origin().ascii_serialization()],
            &leaf,
            20_000
        )
        .is_err()
    );
    let mut changed = row;
    changed["ingress"]["origin"] = json!("https://127.0.0.1:22346");
    assert!(
        pending_body(
            &serde_json::to_vec(&vec![changed]).expect("origin change"),
            &[origin.origin().ascii_serialization()],
            &leaf,
            10_000
        )
        .is_err()
    );
}
#[test]
fn actual_http_rejection_and_postdispatch_uncertainty_are_not_not_dispatched() {
    for status in [400, 401, 403, 404, 409, 429] {
        let error = accepted_status(status).expect_err("explicit server rejection");
        assert_eq!(error.outcome(), "rejected");
        assert_eq!(error.exit_code(), 2);
    }
    for status in [202, 301, 500, 503] {
        let error = accepted_status(status).expect_err("no proof of completed admin mutation");
        assert_eq!(error.outcome(), "unknown");
        assert_eq!(error.exit_code(), 4);
    }
    assert!(accepted_status(200).is_ok());
}
