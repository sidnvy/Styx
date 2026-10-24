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
