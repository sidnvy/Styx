//! Trusted revoked-owner cleanup, not authority to execute or deliver output.
use super::*;

/// Only a successfully fenced exact owner incarnation can mint this capability.
/// It is neither Clone nor Deserialize; runtime supervision may share it by Arc.
/// The contained lease remains revoked for every ordinary Core request.
pub struct OwnerCleanupAuthority {
    owner: OwnerLease,
}
impl std::fmt::Debug for OwnerCleanupAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OwnerCleanupAuthority([REDACTED])")
    }
}
impl OwnerCleanupAuthority {
    /// Provider ownership check only. Never use to bypass ordinary Core checks.
    pub fn owner(&self) -> &OwnerLease {
        &self.owner
    }
}
impl OperationLedger {
    pub fn fence_owner_for_cleanup(
        &mut self,
        owner: &OwnerLease,
        now: MonotonicMillis,
    ) -> Result<OwnerCleanupAuthority, ErrorCategory> {
        self.revoke_owner(owner)?;
        for record in self.records.values_mut().filter(|r| {
            r.owner == owner.owner
                && r.owner_incarnation == owner.incarnation
                && r.snapshot.id.owner_epoch == owner.epoch
        }) {
            if record.snapshot.state == OperationState::Reserved {
                record.snapshot.state = OperationState::Cancelled;
                record.snapshot.cancellation = Some(Cancellation::NotDispatched);
                record.terminal_at = Some(now);
            }
        }
        Ok(OwnerCleanupAuthority {
            owner: owner.clone(),
        })
    }
    /// Bounded metadata inventory, never payload or process output. Includes
    /// previously released history; callers must use physical retention facts.
    pub fn owner_cleanup_inventory(
        &self,
        authority: &OwnerCleanupAuthority,
    ) -> Result<Vec<OperationSnapshot>, ErrorCategory> {
        let owner = authority.owner();
        if owner.host != self.host
            || self.owners.get(&owner.owner) == Some(&(owner.epoch.clone(), owner.incarnation))
        {
            return Err(ErrorCategory::Unauthorized);
        }
        Ok(self
            .records
            .values()
            .filter(|r| {
                r.owner == owner.owner
                    && r.owner_incarnation == owner.incarnation
                    && r.snapshot.id.owner_epoch == owner.epoch
            })
            .map(|r| r.snapshot.clone())
            .collect())
    }
    pub fn owner_unreleased_provider_records(
        &self,
        authority: &OwnerCleanupAuthority,
    ) -> Result<usize, ErrorCategory> {
        self.owner_cleanup_inventory(authority)?;
        let owner = authority.owner();
        Ok(self
            .records
            .values()
            .filter(|r| {
                r.owner == owner.owner
                    && r.owner_incarnation == owner.incarnation
                    && r.snapshot.id.owner_epoch == owner.epoch
                    && !r.physical.collectible()
            })
            .count())
    }
}
