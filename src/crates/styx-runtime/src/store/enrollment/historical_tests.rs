//! Actual private-file adapter cases only; no legacy stop, enrollment crypto,
//! Core attestation, C07 completion, activation, or power-loss claim.
use super::*;
use crate::store::RootIdentity;
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let p =
            std::env::temp_dir().join(format!("styx-historical-store-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        Self(p)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn root_binding(root: &PrivateRoot) -> SourceRoot {
    let RootIdentity::Linux { device, inode, uid } = root.identity();
    SourceRoot::Linux { device, inode, uid }
}
fn body(root: &PrivateRoot, required_materials: Vec<MaterialRef>) -> HistoricalEnrollmentBaseline {
    let RootIdentity::Linux { device, inode, uid } = root.identity();
    HistoricalEnrollmentBaseline {
        schema: 1,
        migration: "historical-fixture".try_into().unwrap(),
        gateway_epoch: "historical-epoch".try_into().unwrap(),
        sequence: 1,
        expected_revision: 0,
        prepared_at: 100,
        source_bindings_sha256: Sha256Digest::of_bytes(b"original protected binding fixture"),
        // Deliberately a different source root: only enrollment_root must match.
        source_root: SourceRoot::Linux {
            device,
            inode: inode + 1,
            uid,
        },
        enrollment_root: root_binding(root),
        journal_root: None,
        devices: vec![],
        revoked: vec![],
        default_device: None,
        token_bindings: vec![],
        required_materials,
    }
}
fn fill(j: &mut EnrollmentJournal<'_>) -> Vec<MaterialRef> {
    vec![
        j.put_material(MaterialKind::Token, b"historical-fixture-token\n")
            .unwrap(),
        j.put_material(
            MaterialKind::Profile,
            b"historical-fixture-profile-not-a-real-profile",
        )
        .unwrap(),
    ]
}
fn native(sequence: u64, revision: u64) -> Vec<u8> {
    contract::encode(&contract::IntentBody {
        schema: 1,
        gateway_epoch: "later-native-epoch".try_into().unwrap(),
        transaction: format!("later-native-{sequence}").try_into().unwrap(),
        sequence,
        expected_revision: revision,
        prepared_at: 101,
        required_materials: vec![],
        mutation: Mutation::CloseWindow { scope: None },
    })
    .unwrap()
}

#[test]
fn historical_original_bytes_incomplete_phases_and_native_head_are_distinct() {
    let fixture = Fixture::new();
    let root = PrivateRoot::open(&fixture.0).unwrap();
    let mut writer = root.try_configuration_writer().unwrap();
    let mut journal =
        EnrollmentJournal::open(&root, &mut writer, JournalBudget::default()).unwrap();
    journal.record_time_floor(100).unwrap();
    let refs = fill(&mut journal);
    let baseline = body(&root, refs);
    // Preserve actual noncanonical original bytes, not a re-encoded body.
    let mut original = b" \n".to_vec();
    original.extend(historical_contract::encode(&baseline).unwrap());
    original.extend(b"\n ");
    let prepared = journal.prepare_historical(&original).unwrap();
    // Literal pre-V2 phase representation; do not produce this expectation
    // through prepared_for or serialize the new receipt struct.
    let old_prepared = format!(
        "{{\"schema\":1,\"migration\":\"historical-fixture\",\"enrollment_root\":{},\"baseline_digest\":\"{}\",\"sequence\":1,\"expected_revision\":0}}",
        serde_json::to_string(&baseline.enrollment_root).unwrap(),
        Sha256Digest::of_bytes(&original).to_hex(),
    ).into_bytes();
    assert_eq!(
        journal.read(HISTORICAL_PREPARED).unwrap().unwrap(),
        old_prepared
    );
    assert_eq!(
        journal.prepare_historical(&original),
        Err(JournalError::Conflict)
    );
    assert_eq!(
        journal.prepare(&native(2, 1), None),
        Err(JournalError::Conflict)
    );
    let pending = journal.resync_historical().unwrap().unwrap();
    assert_eq!(pending.original_bytes, original);
    assert_eq!(pending.prepared, Some(prepared.clone()));
    assert!(pending.committed.is_none());
    assert!(journal.read(HISTORICAL_COMMITTED).unwrap().is_none());
    drop(writer);
    let mut writer = root.try_configuration_writer().unwrap();
    let mut journal =
        EnrollmentJournal::open_existing(&root, &mut writer, JournalBudget::default()).unwrap();
    let committed = journal.commit_historical(&prepared).unwrap();
    let old_committed = format!(
        "{{\"schema\":1,\"prepared\":{},\"prepared_digest\":\"{}\"}}",
        std::str::from_utf8(&old_prepared).unwrap(),
        Sha256Digest::of_bytes(&old_prepared).to_hex(),
    )
    .into_bytes();
    assert_eq!(
        journal.read(HISTORICAL_COMMITTED).unwrap().unwrap(),
        old_committed
    );
    assert_eq!(
        committed.prepared.baseline_digest,
        Sha256Digest::of_bytes(&original)
    );
    let observed = journal.resync_historical().unwrap().unwrap();
    assert_eq!(observed.original_bytes, original);
    assert_eq!(observed.committed, Some(committed.clone()));
    // Historical rev1/head is mandatory. Native sequence gaps remain allowed.
    let bad = journal.prepare(&native(2, 0), None).unwrap();
    assert_eq!(journal.commit(&bad), Err(JournalError::Conflict));
    let next = journal
        .prepare(&native(3, 1), Some(committed.digest().unwrap()))
        .unwrap();
    let next_commit = journal.commit(&next).unwrap();
    assert_eq!(next_commit.binding.expected_revision, 1);
    assert_eq!(
        journal.reconcile(&next.binding.transaction).unwrap(),
        Some(next_commit)
    );
    assert_eq!(journal.commit_historical(&prepared).unwrap(), committed);
    assert_eq!(
        journal
            .observe_historical()
            .unwrap()
            .unwrap()
            .original_bytes,
        original
    );
}

#[test]
fn historical_orphans_native_pending_wrong_root_and_budget_never_get_absorbed() {
    for variant in [
        "intent-only",
        "commit-orphan",
        "native-pending",
        "foreign-root",
        "v2-foreign-journal-root",
        "budget",
    ] {
        let fixture = Fixture::new();
        let root = PrivateRoot::open(&fixture.0).unwrap();
        let mut writer = root.try_configuration_writer().unwrap();
        let mut journal =
            EnrollmentJournal::open(&root, &mut writer, JournalBudget::default()).unwrap();
        let refs = fill(&mut journal);
        let mut baseline = body(&root, refs);
        match variant {
            "intent-only" => {
                let original = historical_contract::encode(&baseline).unwrap();
                journal
                    .write(HISTORICAL_INTENT, &original, &|_| {})
                    .unwrap();
                let observation = journal.resync_historical().unwrap().unwrap();
                assert!(observation.prepared.is_none());
                assert!(observation.committed.is_none());
                assert_eq!(
                    journal.prepare(&native(1, 0), None),
                    Err(JournalError::Conflict)
                );
                assert_eq!(
                    journal.prepare_historical(&original),
                    Err(JournalError::Conflict)
                );
                assert!(journal.read(HISTORICAL_PREPARED).unwrap().is_none());
                assert!(journal.read(HISTORICAL_COMMITTED).unwrap().is_none());
            }
            "commit-orphan" => {
                journal.write(HISTORICAL_COMMITTED, b"{}", &|_| {}).unwrap();
                assert!(matches!(
                    journal.observe_historical(),
                    Err(JournalError::Unknown)
                ));
                assert!(matches!(
                    journal.resync_historical(),
                    Err(JournalError::Unknown)
                ));
                assert!(journal.read(HISTORICAL_INTENT).unwrap().is_none());
            }
            "native-pending" => {
                journal.prepare(&native(1, 0), None).unwrap();
                assert_eq!(
                    journal.prepare_historical(&historical_contract::encode(&baseline).unwrap()),
                    Err(JournalError::Conflict)
                );
                assert!(journal.read(HISTORICAL_INTENT).unwrap().is_none());
            }
            "foreign-root" => {
                baseline.enrollment_root = baseline.source_root.clone();
                assert_eq!(
                    journal.prepare_historical(&historical_contract::encode(&baseline).unwrap()),
                    Err(JournalError::Conflict)
                );
                assert!(journal.read(HISTORICAL_INTENT).unwrap().is_none());
            }
            "v2-foreign-journal-root" => {
                // A valid V2 DTO with another state identity cannot write to
                // this physical journal, even though old enrollment matches.
                baseline.schema = 2;
                baseline.journal_root = Some(baseline.source_root.clone());
                let raw = historical_contract::encode(&baseline).unwrap();
                assert_eq!(
                    journal.prepare_historical(&raw),
                    Err(JournalError::Conflict)
                );
                assert!(journal.read(HISTORICAL_INTENT).unwrap().is_none());
            }
            "budget" => {
                let original = historical_contract::encode(&baseline).unwrap();
                let prepared = prepared_for(&baseline, Sha256Digest::of_bytes(&original));
                let required = journal.scan().unwrap().total_bytes
                    + original.len()
                    + encode(&prepared).unwrap().len()
                    + encode(&committed_for(&prepared).unwrap()).unwrap().len();
                journal.budget.max_bytes = required - 1;
                journal.budget.max_file_bytes = required - 1;
                assert_eq!(
                    journal.prepare_historical(&original),
                    Err(JournalError::BudgetExceeded)
                );
                assert!(journal.read(HISTORICAL_INTENT).unwrap().is_none());
            }
            _ => unreachable!(),
        }
    }
}
