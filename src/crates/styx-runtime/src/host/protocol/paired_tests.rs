//! DTO boundary checks only. Real paired owner authority/effects must be covered
//! by the Gateway HTTP -> paired WSS -> native executor integration journey.
use super::*;

#[test]
fn paired_wire_preserves_v2_bytes_and_typed_v3_contract() {
    // These exact original v2 fields/order remain unchanged; v3-only revision
    // must not appear (even as null) in an old negotiation response.
    let v2 = Reply::Negotiated {
        version: 2,
        challenge: "fixture-side-effect-free-challenge".into(),
        device_id: "owned-protocol-device".try_into().unwrap(),
        host_generation: "protocol-host-generation".try_into().unwrap(),
        connection_generation: "connection-a".try_into().unwrap(),
        features: vec!["prepare_start".into(), "read".into()],
        write: true,
        terminate: true,
        read_resume: false,
        owner_issuance: "bootstrap_preverified_only".into(),
        grant_revision: None,
    };
    let bytes = serde_json::to_string(&v2).unwrap();
    assert_eq!(
        bytes,
        r#"{"status":"negotiated","version":2,"challenge":"fixture-side-effect-free-challenge","device_id":"owned-protocol-device","host_generation":"protocol-host-generation","connection_generation":"connection-a","features":["prepare_start","read"],"write":true,"terminate":true,"read_resume":false,"owner_issuance":"bootstrap_preverified_only"}"#
    );
    assert!(matches!(
        serde_json::from_str::<Reply>(&bytes).unwrap(),
        Reply::Negotiated {
            grant_revision: None,
            ..
        }
    ));

    let request = r#"{"request_id":"request-a","connection_generation":"connection-a","call":{"owner_open":{"owner":{"owner_id":"mcp-session:owned-a","owner_epoch":"owner-epoch-a"},"grant_revision":7}}}"#;
    let parsed: Request = serde_json::from_str(request).unwrap();
    assert!(matches!(
        &parsed.call,
        Call::OwnerOpen {
            grant_revision: 7,
            ..
        }
    ));
    assert_eq!(serde_json::to_string(&parsed).unwrap(), request);
    let forged = request.replace(
        "\"owner_epoch\":\"owner-epoch-a\"",
        "\"owner_epoch\":\"owner-epoch-a\",\"admin\":true",
    );
    assert!(serde_json::from_str::<Request>(&forged).is_err());
    let unknown = request.replace(
        "\"grant_revision\":7",
        "\"grant_revision\":7,\"skip_auth\":true",
    );
    assert!(serde_json::from_str::<Request>(&unknown).is_err());

    let reply = Reply::OwnerRevoked {
        owner: OwnerRef {
            owner_id: "mcp-session:owned-a".try_into().unwrap(),
            owner_epoch: "owner-epoch-a".try_into().unwrap(),
        },
        fenced: true,
        cleanup: "unknown".into(),
    };
    let bytes = serde_json::to_vec(&reply).unwrap();
    assert!(
        matches!(serde_json::from_slice::<Reply>(&bytes).unwrap(), Reply::OwnerRevoked { fenced: true, cleanup, .. } if cleanup == "unknown")
    );
    // Revoke acknowledgement intentionally contains no synthetic process exit.
    assert!(!String::from_utf8(bytes).unwrap().contains("exit"));
}
