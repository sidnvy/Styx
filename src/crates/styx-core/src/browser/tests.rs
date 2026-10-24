//! Pure reference-boundary scenarios; no native browser/liveness claim.
use super::*;
use crate::operations::OperationLedger;
use styx_contracts::{identity::*, operation::OperationId};

fn fixture() -> (OperationLedger, OwnerLease, ResourceTarget) {
    let generation = HostGeneration::try_from("ref-host").unwrap();
    let mut ledger = OperationLedger::new(generation.clone());
    let owner = ledger
        .register_verified_owner(
            OwnerId::try_from("ref-owner").unwrap(),
            OwnerEpoch::try_from("ref-epoch").unwrap(),
        )
        .unwrap();
    let target = ResourceTarget {
        operation_id: OperationId {
            host_generation: generation,
            owner_epoch: OwnerEpoch::try_from("ref-epoch").unwrap(),
            sequence: 7,
        },
        payload_digest: Sha256Digest::of_bytes(b"original browser resource"),
    };
    (ledger, owner, target)
}

#[test]
fn references_bind_original_incarnation_resource_scope_snapshot_and_native_epoch() {
    let (mut ledger, owner, target) = fixture();
    let mut scope = BrowserReferenceScope::new(owner.clone(), target.clone(), [11; 32]);
    let mapping = scope
        .replace_snapshot(9, &["e1".into(), "f2e3".into(), "e1".into()])
        .unwrap();
    assert_eq!(mapping.len(), 2);
    let token = mapping["f2e3"].clone();
    assert!(valid_opaque_token(&token));
    assert_eq!(scope.resolve(&owner, &target, &token, 9).unwrap(), "f2e3");
    for invalid in ["f2e3", "e1", "styx-unknown", "styx-ABCDEF"] {
        assert_eq!(
            scope.resolve(&owner, &target, invalid, 9),
            Err(ErrorCategory::StaleObservation)
        );
    }
    assert_eq!(
        scope.resolve(&owner, &target, &token, 10),
        Err(ErrorCategory::StaleObservation)
    );
    assert_eq!(
        scope.resolve(&owner, &target, &token, 0),
        Err(ErrorCategory::InvalidRequest)
    );
    let mut changed = target.clone();
    changed.payload_digest = Sha256Digest::of_bytes(b"different resource bytes");
    assert_eq!(
        scope.resolve(&owner, &changed, &token, 9),
        Err(ErrorCategory::StaleObservation)
    );
    changed = target.clone();
    changed.operation_id.sequence += 1;
    assert_eq!(
        scope.resolve(&owner, &changed, &token, 9),
        Err(ErrorCategory::StaleObservation)
    );
    let other = ledger
        .register_verified_owner(
            OwnerId::try_from("another-owner").unwrap(),
            OwnerEpoch::try_from("another-epoch").unwrap(),
        )
        .unwrap();
    assert_eq!(
        scope.resolve(&other, &target, &token, 9),
        Err(ErrorCategory::Unauthorized)
    );
    ledger.revoke_owner(&owner).unwrap();
    let replacement = ledger
        .register_verified_owner(
            OwnerId::try_from("ref-owner").unwrap(),
            OwnerEpoch::try_from("ref-epoch").unwrap(),
        )
        .unwrap();
    assert_eq!(
        scope.resolve(&replacement, &target, &token, 9),
        Err(ErrorCategory::Unauthorized)
    );
    let mut rebuilt = BrowserReferenceScope::new(owner.clone(), target.clone(), [12; 32]);
    let rebuilt_token = rebuilt.replace_snapshot(9, &["f2e3".into()]).unwrap()["f2e3"].clone();
    assert_ne!(token, rebuilt_token);
    assert_eq!(
        rebuilt.resolve(&owner, &target, &token, 9),
        Err(ErrorCategory::StaleObservation)
    );
    // Repeated document snapshots are new observation bindings even when both
    // the native epoch and native element string happen to remain equal.
    let next = scope.replace_snapshot(9, &["f2e3".into()]).unwrap()["f2e3"].clone();
    assert_ne!(token, next);
    assert_eq!(
        scope.resolve(&owner, &target, &token, 9),
        Err(ErrorCategory::StaleObservation)
    );
    scope.invalidate();
    assert_eq!(scope.current_epoch(), None);
    assert_eq!(
        scope.resolve(&owner, &target, &next, 9),
        Err(ErrorCategory::StaleObservation)
    );
    let after_clear = scope.replace_snapshot(9, &["f2e3".into()]).unwrap()["f2e3"].clone();
    assert_ne!(after_clear, next);
    // Native epoch ABA cannot revive the previous binding.
    scope.replace_snapshot(10, &["f2e3".into()]).unwrap();
    scope.replace_snapshot(9, &["f2e3".into()]).unwrap();
    assert_eq!(
        scope.resolve(&owner, &target, &after_clear, 9),
        Err(ErrorCategory::StaleObservation)
    );
}

#[test]
fn malformed_over_budget_and_overflow_attempts_invalidate_instead_of_partial_eviction() {
    let (_, owner, target) = fixture();
    let mut scope = BrowserReferenceScope::new(owner.clone(), target.clone(), [21; 32]);
    for invalid in [
        "",
        "1",
        "fe1",
        "f1e",
        "e",
        "e1suffix",
        "f1f2e3",
        "e１２",
        "styx-0123456789abcdef0123456789abcdef",
    ] {
        let old = scope.replace_snapshot(1, &["e1".into()]).unwrap()["e1"].clone();
        assert_eq!(
            scope.replace_snapshot(1, &[invalid.into()]),
            Err(ErrorCategory::InvalidRequest)
        );
        assert_eq!(scope.current_epoch(), None);
        assert_eq!(
            scope.resolve(&owner, &target, &old, 1),
            Err(ErrorCategory::StaleObservation)
        );
    }
    let old = scope.replace_snapshot(1, &["e1".into()]).unwrap()["e1"].clone();
    assert_eq!(
        scope.replace_snapshot(0, &[]),
        Err(ErrorCategory::InvalidRequest)
    );
    assert_eq!(
        scope.resolve(&owner, &target, &old, 1),
        Err(ErrorCategory::StaleObservation)
    );
    let small: Vec<_> = (0..MAX_NATIVE_REFS).map(|n| format!("e{n}")).collect();
    assert_eq!(
        scope.replace_snapshot(2, &small).unwrap().len(),
        MAX_NATIVE_REFS
    );
    let too_many = vec!["e1".to_owned(); MAX_NATIVE_REFS + 1];
    assert_eq!(
        scope.replace_snapshot(2, &too_many),
        Err(ErrorCategory::Busy)
    );
    assert!(scope.token_to_native.is_empty());
    let long: Vec<_> = (0..MAX_NATIVE_REFS).map(|n| format!("e{n:063}")).collect();
    assert_eq!(scope.replace_snapshot(2, &long), Err(ErrorCategory::Busy));
    assert!(scope.token_to_native.is_empty());
    assert_eq!(scope.current_epoch(), None);
    scope.snapshot_revision = u64::MAX - 1;
    let last = scope.replace_snapshot(3, &["e1".into()]).unwrap()["e1"].clone();
    assert_eq!(
        scope.replace_snapshot(3, &["e1".into()]),
        Err(ErrorCategory::Busy)
    );
    assert_eq!(
        scope.resolve(&owner, &target, &last, 3),
        Err(ErrorCategory::StaleObservation)
    );
    scope.clear();
    assert_eq!(scope.replace_snapshot(3, &[]), Err(ErrorCategory::Busy));
    assert_eq!(scope.snapshot_revision, u64::MAX);
}
