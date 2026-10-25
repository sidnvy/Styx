//! Pure versioned-root contract/replay checks, not filesystem or migration proof.
use super::*;
use styx_contracts::historical_enrollment::SourceRoot;

// Literal encoding of the original schema1 DTO, before journal_root existed.
// Do not derive this expected value with the new serializer.
const V1: &[u8] = br#"{"schema":1,"migration":"migration-original","gateway_epoch":"original-epoch","sequence":1,"expected_revision":0,"prepared_at":10,"source_bindings_sha256":"0000000000000000000000000000000000000000000000000000000000000000","source_root":{"platform":"linux","device":1,"inode":2,"uid":1000},"enrollment_root":{"platform":"linux","device":1,"inode":3,"uid":1000},"devices":[],"revoked":[],"default_device":null,"token_bindings":[],"required_materials":[]}"#;

fn hash(s: &str) -> Sha256Digest {
    Sha256Digest::of_bytes(s.as_bytes())
}
fn fresh() -> (EnrollmentLedger, EnrollmentControl) {
    EnrollmentLedger::new_recovering("current-epoch".try_into().unwrap(), Limits::default())
        .unwrap()
}
fn recover(ledger: &mut EnrollmentLedger, control: &EnrollmentControl, raw: &[u8]) -> Result<()> {
    let proof = control.attest_historical_baseline(
        raw,
        Sha256Digest::of_bytes(raw),
        hash("historical-receipt"),
    )?;
    ledger.recover_historical_baseline(proof)
}
#[test]
fn historical_root_versions_preserve_original_bytes_and_native_continuation() {
    let v1 = contract::decode(V1).unwrap();
    assert_eq!(v1.schema, 1);
    assert_eq!(v1.journal_root, None);
    assert_eq!(v1.journal_root().unwrap(), &v1.enrollment_root);
    assert_eq!(contract::encode(&v1).unwrap(), V1);
    validate_historical_baseline(&v1, Limits::default()).unwrap();
    let (mut original, oc) = fresh();
    recover(&mut original, &oc, V1).unwrap();
    assert_eq!(
        original
            .historical_baseline
            .as_ref()
            .unwrap()
            .bytes
            .as_ref(),
        V1
    );

    let mut v2 = v1.clone();
    v2.schema = 2;
    v2.journal_root = Some(v2.source_root.clone());
    assert_ne!(v2.source_root, v2.enrollment_root);
    assert_eq!(v2.journal_root().unwrap(), &v2.source_root);
    validate_historical_baseline(&v2, Limits::default()).unwrap();
    let raw = contract::encode(&v2).unwrap();
    assert_eq!(contract::decode(&raw).unwrap(), v2);
    let (mut live, c) = fresh();
    recover(&mut live, &c, &raw).unwrap();
    assert!(live.recovering);
    assert_eq!((live.revision, live.sequence), (1, 1));
    assert_eq!(
        live.historical_baseline.as_ref().unwrap().bytes.as_ref(),
        raw
    );
    live.finish_recovery(c.attest_recovery_closure(
        1,
        1,
        Some(hash("historical-receipt")),
        None,
        20,
        20,
    ))
    .unwrap();
    let next = live
        .invite(&c.admin(), hash("invitation"), 60, None, 21)
        .unwrap();
    assert_eq!(
        (next.body().sequence, next.body().expected_revision),
        (2, 1)
    );
    live.confirm_durable(c.attest_durable(&next, hash("native-receipt")))
        .unwrap();
    let (mut replay, rc) = fresh();
    recover(&mut replay, &rc, &raw).unwrap();
    replay
        .recover_committed(
            rc.attest_recovery_record(
                next.original_bytes(),
                next.digest(),
                Some(hash("historical-receipt")),
                hash("native-receipt"),
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!((replay.revision, replay.sequence), (2, 2));
    assert_eq!(replay.recovered_head, Some(hash("native-receipt")));
    assert_eq!(
        replay.historical_baseline.as_ref().unwrap().bytes.as_ref(),
        raw
    );

    // Schema 3 is now an explicit native-root codec. Core replay retains its
    // original bytes; this pure proof does not enable a platform writer.
    let mut v3 = v2.clone();
    v3.schema = 3;
    let native_raw = contract::encode(&v3).unwrap();
    assert_eq!(contract::decode(&native_raw).unwrap(), v3);
    validate_historical_baseline(&v3, Limits::default()).unwrap();
    let (mut native, native_control) = fresh();
    recover(&mut native, &native_control, &native_raw).unwrap();
    assert!(native.recovering);
    assert_eq!(
        native.historical_baseline.as_ref().unwrap().bytes.as_ref(),
        native_raw
    );

    let mut missing = v2.clone();
    missing.journal_root = None;
    let mut wrong = v2.clone();
    wrong.journal_root = Some(SourceRoot::Linux {
        device: 1,
        inode: 4,
        uid: 1000,
    });
    let mut old_source_child = v2.clone();
    old_source_child.journal_root = Some(v2.enrollment_root.clone());
    let mut swapped_source = v2.clone();
    swapped_source.source_root = v2.enrollment_root.clone();
    let mut added_to_old = v1.clone();
    added_to_old.journal_root = Some(v1.enrollment_root.clone());
    let mut unknown = v2.clone();
    unknown.schema = 4;
    for invalid in [
        missing,
        wrong,
        old_source_child,
        swapped_source,
        added_to_old,
        unknown,
    ] {
        assert!(invalid.journal_root().is_err());
        assert!(validate_historical_baseline(&invalid, Limits::default()).is_err());
        assert!(contract::encode(&invalid).is_err());
    }
    // Decode must also refuse malformed on-disk version/root combinations;
    // these are independent raw negatives, not just encoder refusals.
    let text = String::from_utf8(raw.clone()).unwrap();
    for bad in [
        String::from_utf8(V1.to_vec()).unwrap().replacen(
            "\"devices\":",
            "\"journal_root\":null,\"devices\":",
            1,
        ),
        text.replace("\"schema\":2", "\"schema\":1"),
        text.replace("\"schema\":2", "\"schema\":4"),
        String::from_utf8(V1.to_vec())
            .unwrap()
            .replace("\"schema\":1", "\"schema\":2"),
    ] {
        let (mut rejected, control) = fresh();
        assert!(recover(&mut rejected, &control, bad.as_bytes()).is_err());
        assert_eq!((rejected.revision, rejected.sequence), (0, 0));
        assert!(rejected.historical_baseline.is_none());
        assert!(rejected.staged.is_none());
    }
}
