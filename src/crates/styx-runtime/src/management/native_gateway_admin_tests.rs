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

#[test]
fn gateway_invitation_selects_only_a_configured_private_address() {
    let origins = vec![
        "https://127.0.0.1:22345".into(),
        "https://10.118.53.220:22345".into(),
        "https://10.0.2.19:22345".into(),
    ];
    assert_eq!(invitation_origin(&origins, None).unwrap(), origins[1]);
    assert_eq!(
        invitation_origin(
            &origins,
            Some(InvitationOrigin::Address("10.0.2.19".parse().unwrap()))
        )
        .unwrap(),
        origins[2]
    );
    for ip in ["127.0.0.1", "10.0.2.20", "8.8.8.8"] {
        assert_eq!(
            invitation_origin(
                &origins,
                Some(InvitationOrigin::Address(ip.parse().unwrap()))
            )
            .unwrap_err()
            .code(),
            "native_gateway_origin_address_not_configured"
        );
    }
}

#[test]
fn gateway_invite_app_link_round_trips_origin_ca_and_expiry() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let now = clock_ms().unwrap();
    let ca =
        crate::tls::generate_gateway_ca(now / 1000, now / 1000 - 60, now / 1000 + 86400).unwrap();
    let origin = "https://10.0.2.19:22345";
    for ttl in [60_000, 600_000] {
        let invite = Invitation {
            invitation: Zeroizing::new(URL_SAFE_NO_PAD.encode([7u8; 32])),
            expires_at: now + ttl,
            one_use: true,
        };
        // This helper is the production invite export path, including caPem.
        let link = invitation_app_link(&invite, origin, &ca.certificate_pem, now).unwrap();
        let inspected = crate::app::pairing_link::inspect(&link, now).unwrap();
        let preview = inspected.preview();
        assert_eq!(preview.origin, origin);
        assert_eq!(preview.expires_at, invite.expires_at);
        assert_eq!(
            preview.ca_sha256.as_deref(),
            Some(ca.anchor_pin.as_hex().as_str())
        );
        assert!(preview.requires_certificate_approval);
        let (accepted_origin, invitation, pem, expiry) = inspected
            .approve(origin, Some(ca.anchor_pin.as_hex().as_str()), now)
            .unwrap()
            .into_parts();
        assert_eq!(accepted_origin, origin);
        assert_eq!(invitation.as_str(), invite.invitation.as_str());
        assert_eq!(pem.unwrap().as_bytes(), ca.certificate_pem);
        assert_eq!(expiry, invite.expires_at);
        assert!(crate::app::pairing_link::inspect(&link, expiry).is_err());
    }
    let mut invite = Invitation {
        invitation: Zeroizing::new(URL_SAFE_NO_PAD.encode([7u8; 32])),
        expires_at: now,
        one_use: true,
    };
    assert!(invitation_app_link(&invite, origin, &ca.certificate_pem, now).is_err());
    invite.expires_at = now + 600_001;
    assert!(invitation_app_link(&invite, origin, &ca.certificate_pem, now).is_err());
    invite.expires_at = now + 60_000;
    assert!(invitation_app_link(&invite, origin, b"invalid CA", now).is_err());
}

#[cfg(unix)]
#[test]
fn gateway_invite_exports_private_link_without_overwriting_existing_file() {
    use std::os::unix::fs::PermissionsExt;
    let parent = std::env::current_dir()
        .unwrap()
        .join("target")
        .join(format!("invite-link-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = parent.join("app-link");
    let output = || Output {
        root: PrivateRoot::open(&parent).unwrap(),
        path: path.clone(),
        name: "app-link".into(),
    };
    let secret = b"styx://join#synthetic-private-link";
    assert_eq!(output().publish(secret).unwrap(), path);
    assert_eq!(std::fs::read(&path).unwrap(), secret);
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(output().publish(b"replacement").is_err());
    assert_eq!(std::fs::read(&path).unwrap(), secret);
    std::fs::remove_dir_all(parent).unwrap();
}
