//! Explicit fake-provider physical storage. No OS/native release is claimed.
#![allow(dead_code)]
use std::collections::BTreeMap;
use styx_contracts::{
    identity::Sha256Digest,
    operation::{OperationId, ResourceTarget},
};
use styx_core::operations::{
    OperationLedger, OperationSnapshot, ProviderReleaseConfirmation, ProviderReleasePermit,
};

#[derive(Default)]
pub struct FakeProvider(BTreeMap<OperationId, Sha256Digest>);
impl FakeProvider {
    pub fn retain(&mut self, snapshot: &OperationSnapshot) {
        assert!(
            self.0
                .insert(snapshot.id.clone(), snapshot.payload_digest)
                .is_none()
        );
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn release(&mut self, permit: ProviderReleasePermit) -> ProviderReleaseConfirmation {
        // Validate the complete linear bundle before changing independent storage.
        for key in permit.resource().into_iter().chain(permit.actions().iter()) {
            assert_eq!(
                self.0.get(&key.snapshot().id),
                Some(&key.snapshot().payload_digest)
            );
        }
        for key in permit.resource().into_iter().chain(permit.actions().iter()) {
            assert!(self.0.remove(&key.snapshot().id).is_some());
        }
        permit.confirm_released()
    }
}
pub fn audit(ledger: &mut OperationLedger, action: &OperationSnapshot) {
    ledger
        .record_provider_audit(&action.id, b"fake-provider:receipt-v1".to_vec())
        .unwrap();
}
pub fn release_action(ledger: &mut OperationLedger, action: &OperationSnapshot) {
    let mut provider = FakeProvider::default();
    provider.retain(action);
    audit(ledger, action);
    let permit = ledger.begin_action_release(&action.id).unwrap();
    let confirmation = provider.release(permit);
    assert_eq!(provider.len(), 0);
    ledger.record_provider_release(confirmation).unwrap();
}
pub fn release_resource(
    ledger: &mut OperationLedger,
    resource: &OperationSnapshot,
    actions: &[&OperationSnapshot],
) {
    let mut provider = FakeProvider::default();
    provider.retain(resource);
    for action in actions {
        provider.retain(action);
        audit(ledger, action);
    }
    let permit = ledger
        .begin_resource_release(&ResourceTarget {
            operation_id: resource.id.clone(),
            payload_digest: resource.payload_digest,
        })
        .unwrap();
    let confirmation = provider.release(permit);
    assert_eq!(provider.len(), 0);
    ledger.record_provider_release(confirmation).unwrap();
}
