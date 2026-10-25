//! Contract checks for the Windows/legacy-JS time boundary. Synthetic raw
//! timestamps only: these are not Windows boot or process-settlement evidence.
use super::*;

fn windows_stamp(seconds: i64, nanos: i64) -> NativeRetirementFileStamp {
    NativeRetirementFileStamp::Windows {
        volume_serial: 12,
        file_id: 34,
        owner_sid: "S-1-5-21-1234".into(),
        nlink: 1,
        byte_len: 4,
        modified_seconds: seconds,
        modified_nanoseconds: nanos,
        changed_seconds: seconds,
        changed_nanoseconds: nanos,
        sha256: Sha256Digest::of_bytes(b"lock"),
    }
}

#[test]
fn windows_raw_epoch_matches_original_unix_plan_without_rewriting_stamp() {
    // 2000-01-01T00:00:00.1234567Z: two independently specified epochs.
    let stamp = windows_stamp(12_591_158_400, 123_456_700);
    let before = serde_json::to_vec(&stamp).unwrap();
    let hash = Sha256Digest::of_bytes(b"synthetic-authorized-material");
    let device: styx_contracts::identity::DeviceId =
        "styx-1234567890abcdef12345678".try_into().unwrap();
    let mut plan = serde_json::json!({
        "schema": 1,
        "action": "retire_legacy_foreground_owner",
        "stateDir": std::env::temp_dir(),
        "deviceId": device,
        "identitySha256": hash,
        "configurationHash": hash,
        "currentBoot": {"platform":"win32", "id":"synthetic-boot", "startedAt":946_684_801_000_u64},
        "previousOwnerPid": 42,
        "files": [{"name":"foreground.lock", "ino":"34", "dev":"12", "sha256":stamp.content_sha256(), "modifiedAt":946_684_800_123_u64}],
        "previousWorkOutcome":"unknown_not_replayed",
        "identityMutation":"none",
        "requiresExplicitAuthorization":true
    });
    let mut intent = LegacyOwnerRecoveryIntent {
        schema: 2,
        kind: RecoveryKind::LegacyOwnerRecovery,
        transaction_id: "epoch-boundary".try_into().unwrap(),
        sequence: 1,
        config_root: styx_contracts::native_management::NativeRootIdentity::Windows {
            volume_serial: 12,
            file_id: 56,
            owner_sid: "S-1-5-21-1234".into(),
        },
        deployment_raw_sha256: hash,
        before_state_sha256: hash,
        candidate_manifest_sha256: hash,
        publisher_spki_sha256: hash,
        previous_boot: None,
        current_boot: RecoveryBoot {
            id: "synthetic-boot".into(),
            started_at_ms: 946_684_801_000,
        },
        basis: None,
        restart: RecoveryRestartBinding::ForegroundOnlyNoInstalledManager,
        successor_retirement_intent_sha256: hash,
        originals: vec![RecoveryOriginalBinding {
            name: RecoveryOriginalName::Lock,
            stamp,
        }],
        guards: vec![],
    };
    let bind = |intent: &mut LegacyOwnerRecoveryIntent, plan: &serde_json::Value| {
        let raw = serde_json::to_vec(plan).unwrap();
        intent.basis = Some(RecoveryBasis::ExplicitLegacyMaintenance {
            plan_sha256: Sha256Digest::of_bytes(&raw),
            device_id: device.clone(),
            identity_json_sha256: hash,
            configuration_hash: hash,
            observer_pid: 42,
        });
        raw
    };
    let raw = bind(&mut intent, &plan);
    validate_authorization_plan(&intent, Some(&raw)).unwrap();
    assert_eq!(
        serde_json::to_vec(&intent.originals[0].stamp).unwrap(),
        before
    );

    // A native FILETIME value cannot masquerade as Node's Unix milliseconds.
    plan["files"][0]["modifiedAt"] = serde_json::json!(12_591_158_400_123_u64);
    let raw = bind(&mut intent, &plan);
    assert!(validate_authorization_plan(&intent, Some(&raw)).is_err());
    // A file at/after the authorized boot still fails after correct conversion.
    plan["files"][0]["modifiedAt"] = serde_json::json!(946_684_800_123_u64);
    plan["currentBoot"]["startedAt"] = serde_json::json!(946_684_800_000_u64);
    intent.current_boot.started_at_ms = 946_684_800_000;
    let raw = bind(&mut intent, &plan);
    assert!(validate_authorization_plan(&intent, Some(&raw)).is_err());
}

#[test]
fn windows_epoch_projection_keeps_subseconds_and_refuses_invalid_raw_time() {
    assert_eq!(
        file_tuple(&windows_stamp(11_644_473_600, 0)).unwrap(),
        (12, 34, 0, 0)
    );
    assert_eq!(
        file_tuple(&windows_stamp(0, 100)).unwrap(),
        (12, 34, -11_644_473_600, 100)
    );
    assert!(file_tuple(&windows_stamp(-1, 0)).is_err());
    assert!(file_tuple(&windows_stamp(i64::MIN, 0)).is_err());
    assert!(file_tuple(&windows_stamp(11_644_473_600, -1)).is_err());
    assert!(file_tuple(&windows_stamp(11_644_473_600, 1_000_000_000)).is_err());
}
