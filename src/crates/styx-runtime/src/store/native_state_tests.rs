use super::*;
#[test]
fn all_nested_decoded_keys_and_lexical_numbers_are_bounded_batch() {
    let exact=br#"{ "extension": {"integer":900719925474099312345678901234567890, "decimal":0.123456789012345678901234567890, "exponent":1e99999}, "array":[{"ok":true}] }"#;
    assert_eq!(guard_document(exact, MAX_STATE_BYTES), Ok(()));
    let raw: &RawValue = serde_json::from_slice(exact).unwrap();
    assert_eq!(raw.get().as_bytes(), exact);
    for duplicate in [
        br#"{"schema":2,"schema":2}"#.as_slice(),
        br#"{"extension":{"a":1,"\u0061":2}}"#.as_slice(),
        br#"{"extension":[{"ok":1},{"nested":{"x":0,"x":1}}]}"#.as_slice(),
        r#"{"extension":{"\ud83d\ude00":0,"😀":1}}"#.as_bytes(),
    ] {
        assert_eq!(
            guard_document(duplicate, MAX_STATE_BYTES),
            Err(NativeStateError::DuplicateKey)
        );
    }
    for invalid in [
        br#"{"x":01}"#.as_slice(),
        br#"{"x":1} {}"#.as_slice(),
        br#"{"x": [true,]}"#.as_slice(),
    ] {
        assert_eq!(
            guard_document(invalid, MAX_STATE_BYTES),
            Err(NativeStateError::InvalidJson)
        );
    }
    let nested = |n: usize| format!("{}0{}", "[".repeat(n), "]".repeat(n));
    assert_eq!(
        guard_document(nested(MAX_DEPTH).as_bytes(), MAX_STATE_BYTES),
        Ok(())
    );
    assert_eq!(
        guard_document(nested(MAX_DEPTH + 1).as_bytes(), MAX_STATE_BYTES),
        Err(NativeStateError::Capacity)
    );
    let array = |n: usize| format!("[{}]", vec!["0"; n].join(","));
    assert_eq!(
        guard_document(array(MAX_MEMBERS).as_bytes(), MAX_STATE_BYTES),
        Ok(())
    );
    assert_eq!(
        guard_document(array(MAX_MEMBERS + 1).as_bytes(), MAX_STATE_BYTES),
        Err(NativeStateError::Capacity)
    );
    let key = |n: usize| format!("{{\"{}\":null}}", "a".repeat(n));
    assert_eq!(
        guard_document(key(MAX_KEY_BYTES).as_bytes(), MAX_STATE_BYTES),
        Ok(())
    );
    assert_eq!(
        guard_document(key(MAX_KEY_BYTES + 1).as_bytes(), MAX_STATE_BYTES),
        Err(NativeStateError::Capacity)
    );
    assert_eq!(
        guard_document(&vec![b' '; MAX_MARKER_BYTES + 1], MAX_MARKER_BYTES),
        Err(NativeStateError::Capacity)
    );
    assert_eq!(
        guard_document(&vec![b' '; MAX_STATE_BYTES + 1], MAX_STATE_BYTES),
        Err(NativeStateError::Capacity)
    );
}

fn marker() -> NativeRootMarker {
    use styx_contracts::{management::ReaderContract, native_management::*};
    NativeRootMarker {
        schema: 1,
        kind: NativeRootKind::StyxConfigurationRoot,
        runtime_format: NativeRuntimeFormat::NativeRustV1,
        root_identity: NativeRootIdentity::Linux {
            device: 7,
            inode: 11,
            uid: 1000,
        },
        scope_generation: Sha256Digest::from_bytes([19; 32]),
        reader_floor: ReaderContract::NativeManagementStateV1,
    }
}
fn state_bytes(marker: &NativeRootMarker, revision: u64, run: &str) -> Vec<u8> {
    let transaction = if revision == 0 {
        "null".to_owned()
    } else {
        r#"{"transaction_id":"native-state-7","sequence":7}"#.to_owned()
    };
    let deployment = Sha256Digest::of_bytes(b"native deployment exact bytes").to_hex();
    format!(r#" {{"schema":2,"kind":"styx_desired_state","runtime_format":"native_rust_v1","reader_contract":"native_management_state_v1","scope_generation":"{}","deployment_raw_sha256":"{}","mode":"create_local","revision":{},"last_transaction":{},"desired":{{"gateway":{{"manager":"persistent_service","run":"{}","autostart":"disabled"}},"host":null}},"opaque":{{ "integer":900719925474099312345678901234567890, "decimal":0.123456789012345678901234567890, "huge":1e99999 }},"opaque_array":[null,{{"raw":-0.00000000000000000000000000001}}]}} 
"#,marker.scope_generation.to_hex(),deployment,revision,transaction,run).into_bytes()
}
#[test]
fn formal_native_reader_preserves_bytes_and_fails_closed_batch() {
    let marker = marker();
    let marker_bytes = serde_json::to_vec(&marker).unwrap();
    assert_eq!(decode_marker(&marker_bytes).unwrap(), marker);
    let raw = state_bytes(&marker, 0, "running");
    let before = decode_state(&raw, &marker).unwrap();
    assert_eq!(before.raw_bytes(), raw);
    assert_eq!(before.raw_sha256(), Sha256Digest::of_bytes(&raw));
    assert_eq!(
        before.state().deployment_raw_sha256,
        Sha256Digest::of_bytes(b"native deployment exact bytes")
    );
    let extension = r#"{ "integer":900719925474099312345678901234567890, "decimal":0.123456789012345678901234567890, "huge":1e99999 }"#;
    assert_eq!(before.state().extensions["opaque"].get(), extension);
    assert_eq!(
        before.state().extensions["opaque_array"].get(),
        r#"[null,{"raw":-0.00000000000000000000000000001}]"#
    );
    let target_raw = state_bytes(&marker, 1, "stopped");
    let target = decode_state(&target_raw, &marker).unwrap();
    let intent = styx_contracts::management::DesiredStateCommit {
        transaction_id: "native-state-7".try_into().unwrap(),
        sequence: 7,
        deployment_raw_sha256: before.state().deployment_raw_sha256,
        before_state_sha256: before.raw_sha256(),
        target_state_sha256: target.raw_sha256(),
        reader: marker.reader_floor,
    };
    assert!(
        styx_core::management::state::validate_transition(
            before.state(),
            target.state(),
            &marker,
            &intent
        )
        .is_ok()
    );
    let changed = String::from_utf8(target_raw)
        .unwrap()
        .replace("1e99999", "1e99998");
    let changed = decode_state(changed.as_bytes(), &marker).unwrap();
    assert_eq!(
        styx_core::management::state::validate_transition(
            before.state(),
            changed.state(),
            &marker,
            &intent
        ),
        Err(styx_core::management::state::NativeStateRuleError::ChangedExtensions)
    );
    let text = String::from_utf8(raw).unwrap();
    for invalid in [
        text.replace("\"schema\":2", "\"schema\":1"),
        text.replace("native_management_state_v1", "native_management_state_v2"),
        text.replace("native_rust_v1", "legacy_js_v1"),
        text.replace("\"last_transaction\":null,", ""),
        text.replace(",\"host\":null", ""),
        text.replace("\"revision\":0", "\"revision\":1"),
        text.replace(
            "\"autostart\":\"disabled\"",
            "\"autostart\":\"unspecified\"",
        ),
        text.replace("\"persistent_service\"", "\"foreground_cli\"")
            .replace("\"autostart\":\"disabled\"", "\"autostart\":\"enabled\""),
        text.replace(
            &before.state().deployment_raw_sha256.to_hex(),
            "not-a-digest",
        ),
    ] {
        assert!(decode_state(invalid.as_bytes(), &marker).is_err());
    }
    let mut other = marker.clone();
    other.scope_generation = Sha256Digest::from_bytes([20; 32]);
    assert!(matches!(
        decode_state(text.as_bytes(), &other),
        Err(NativeStateError::InvalidState)
    ));
    let duplicate = text.replace("\"revision\":0", r#""revision":0,"rev\u0069sion":1"#);
    assert!(matches!(
        decode_state(duplicate.as_bytes(), &marker),
        Err(NativeStateError::DuplicateKey)
    ));
    let unknown_duplicate = text.replace("\"huge\":1e99999", r#""huge":1e99999,"hu\u0067e":2"#);
    assert!(matches!(
        decode_state(unknown_duplicate.as_bytes(), &marker),
        Err(NativeStateError::DuplicateKey)
    ));
    let mut marker_bad = marker.clone();
    marker_bad.schema = 2;
    assert_eq!(
        decode_marker(&serde_json::to_vec(&marker_bad).unwrap()),
        Err(NativeStateError::InvalidMarker)
    );
    let marker_text = String::from_utf8(marker_bytes).unwrap();
    assert!(
        decode_marker(
            marker_text
                .replace("\"schema\":1", r#""schema":1,"schema":1"#)
                .as_bytes()
        )
        .is_err()
    );
    assert!(
        decode_marker(
            marker_text
                .replace("\"reader_floor\":", "\"unknown\":1,\"reader_floor\":")
                .as_bytes()
        )
        .is_err()
    );
    assert!(matches!(
        decode_state(&vec![b' '; MAX_STATE_BYTES + 1], &marker),
        Err(NativeStateError::Capacity)
    ));
    // Neither decoding nor desired Stopped/Disabled claims an OS service action.
    assert_eq!(
        target.state().desired.gateway.unwrap().run,
        styx_contracts::native_management::NativeRunDesired::Stopped
    );
}

/// Formal reader/Core rules only: no physical migration, writer settlement,
/// native execution, or C07 commit is asserted by these synthetic bindings.
#[test]
fn migrated_reader_binding_is_closed_preserved_and_allows_later_native_transactions() {
    use styx_contracts::{management::ReaderContract, native_management::*};
    use styx_core::management::state::{NativeStateRuleError, validate_transition};
    let old_marker = marker();
    let old_raw = state_bytes(&old_marker, 1, "running");
    let old = decode_state(&old_raw, &old_marker).unwrap();
    assert!(old.state().migration.is_none());
    let old_encoded = serde_json::to_vec(old.state()).unwrap();
    assert!(
        !String::from_utf8(old_encoded.clone())
            .unwrap()
            .contains("\"migration\"")
    );
    assert!(
        decode_state(&old_encoded, &old_marker)
            .unwrap()
            .state()
            .migration
            .is_none()
    );
    let opaque = old.state().extensions["opaque"].get().as_bytes().to_vec();
    let mut migrated_marker = old_marker.clone();
    migrated_marker.reader_floor = ReaderContract::NativeMigratedStateV1;
    let binding = NativeMigrationBinding {
        transaction_id: "original-migration".try_into().unwrap(),
        original_state_sha256: Sha256Digest::from_bytes([1; 32]),
        retired_receipt_sha256: Sha256Digest::from_bytes([2; 32]),
        enrollment_baseline_sha256: Sha256Digest::from_bytes([3; 32]),
        enrollment_committed_sha256: Sha256Digest::from_bytes([4; 32]),
        candidate_manifest_sha256: Sha256Digest::from_bytes([5; 32]),
        publisher_spki_sha256: Sha256Digest::from_bytes([6; 32]),
        preservation_sha256: Sha256Digest::from_bytes([7; 32]),
        scope_bindings_sha256: Sha256Digest::from_bytes([8; 32]),
        original_token_relative_path: "device/.styx-retired-host-token-original-migration".into(),
    };
    let mut before = old.state().clone();
    before.reader_contract = ReaderContract::NativeMigratedStateV1;
    before.migration = Some(binding.clone());
    let raw = serde_json::to_vec(&before).unwrap();
    let decoded = decode_state(&raw, &migrated_marker).unwrap();
    assert_eq!(decoded.state().migration.as_ref(), Some(&binding));
    assert_eq!(
        decoded.state().extensions["opaque"].get().as_bytes(),
        opaque
    );
    assert_eq!(decoded.raw_bytes(), raw);
    // Original migration provenance is immutable, but last_transaction is the
    // current desired-state transaction, not permanently the migration ID.
    let mut target = before.clone();
    target.revision = 2;
    target.last_transaction = Some(NativeStateTransaction {
        transaction_id: "later-desired-change".try_into().unwrap(),
        sequence: 8,
    });
    target.desired.gateway.as_mut().unwrap().run = NativeRunDesired::Stopped;
    let intent_for = |state: &NativeState| styx_contracts::management::DesiredStateCommit {
        transaction_id: "later-desired-change".try_into().unwrap(),
        sequence: 8,
        deployment_raw_sha256: before.deployment_raw_sha256,
        before_state_sha256: Sha256Digest::of_bytes(&raw),
        target_state_sha256: Sha256Digest::of_bytes(&serde_json::to_vec(state).unwrap()),
        reader: ReaderContract::NativeMigratedStateV1,
    };
    validate_transition(&before, &target, &migrated_marker, &intent_for(&target)).unwrap();
    let target_raw = serde_json::to_vec(&target).unwrap();
    let target_read = decode_state(&target_raw, &migrated_marker).unwrap();
    assert_eq!(target_read.state().migration.as_ref(), Some(&binding));
    assert_eq!(
        target_read.state().extensions["opaque"].get().as_bytes(),
        opaque
    );
    assert!(target_read.state().extensions_preserved_in(&before));
    assert_ne!(
        target.last_transaction.as_ref().unwrap().transaction_id,
        binding.transaction_id
    );

    let mut changed_bindings = Vec::new();
    macro_rules! changed {
        ($field:ident, $value:expr) => {{
            let mut changed = binding.clone();
            changed.$field = $value;
            changed_bindings.push(changed);
        }};
    }
    let other = Sha256Digest::from_bytes([99; 32]);
    changed!(original_state_sha256, other);
    changed!(retired_receipt_sha256, other);
    changed!(enrollment_baseline_sha256, other);
    changed!(enrollment_committed_sha256, other);
    changed!(candidate_manifest_sha256, other);
    changed!(publisher_spki_sha256, other);
    changed!(preservation_sha256, other);
    changed!(scope_bindings_sha256, other);
    // Keep this changed binding individually valid, so only the immutable
    // transition comparison can reject a new migration identity/locator.
    let mut other_migration = binding.clone();
    other_migration.transaction_id = "different-migration".try_into().unwrap();
    other_migration.original_token_relative_path =
        "device/.styx-retired-host-token-different-migration".into();
    changed_bindings.push(other_migration);
    for changed in changed_bindings {
        let mut bad = target.clone();
        bad.migration = Some(changed);
        let bad_raw = serde_json::to_vec(&bad).unwrap();
        decode_state(&bad_raw, &migrated_marker).unwrap();
        assert_eq!(
            validate_transition(&before, &bad, &migrated_marker, &intent_for(&bad)),
            Err(NativeStateRuleError::InvalidTransition)
        );
    }
    let mut bad_path = before.clone();
    bad_path
        .migration
        .as_mut()
        .unwrap()
        .original_token_relative_path = "device/host.token".into();
    assert!(decode_state(&serde_json::to_vec(&bad_path).unwrap(), &migrated_marker).is_err());
    let mut genesis = before.clone();
    genesis.revision = 0;
    genesis.last_transaction = None;
    assert!(decode_state(&serde_json::to_vec(&genesis).unwrap(), &migrated_marker).is_err());
    assert!(decode_state(&raw, &old_marker).is_err());
    assert!(decode_state(&old_encoded, &migrated_marker).is_err());
    let text = std::str::from_utf8(&raw).unwrap();
    let old_text = String::from_utf8(old_encoded).unwrap();
    for (bad, active_marker) in [
        (
            text.replace("native_migrated_state_v1", "unknown_migrated_reader"),
            &migrated_marker,
        ),
        (
            text.replace("native_migrated_state_v1", "native_management_state_v1"),
            &old_marker,
        ),
        (
            old_text.replace("native_management_state_v1", "native_migrated_state_v1"),
            &migrated_marker,
        ),
        (
            old_text.replacen('{', "{\"migration\":null,", 1),
            &old_marker,
        ),
        (
            old_text
                .replace("native_management_state_v1", "native_migrated_state_v1")
                .replacen('{', "{\"migration\":null,", 1),
            &migrated_marker,
        ),
    ] {
        assert!(decode_state(bad.as_bytes(), active_marker).is_err());
    }
    let mut raw_changed = target.clone();
    raw_changed.extensions.insert(
        "opaque".into(),
        RawValue::from_string(
            String::from_utf8(opaque)
                .unwrap()
                .replace("1e99999", "1e99998"),
        )
        .unwrap(),
    );
    assert_eq!(
        validate_transition(
            &before,
            &raw_changed,
            &migrated_marker,
            &intent_for(&raw_changed)
        ),
        Err(NativeStateRuleError::ChangedExtensions)
    );
}
