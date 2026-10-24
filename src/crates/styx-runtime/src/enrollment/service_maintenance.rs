//! Sealed original migration composition only, not an ordinary HTTP admission
//! switch. The original management writer/fence and physical proof stay owned by
//! the supplied migration binding. No device or lane is inferred from a DTO.
use super::*;
use crate::migration::legacy_service::GatewayMaintenanceBinding;

impl EnrollmentService {
    /// Promote the existing maintenance authority only after the same original
    /// transaction has a durable committed proof. No ledger is reconstructed,
    /// no owner history is discarded, and no recovered lane is made Offline.
    pub(crate) fn promote_committed_migration(
        &mut self,
        proof: &crate::store::legacy_handoff::CommittedNativeCutover,
    ) -> Result<(), ServiceError> {
        self.healthy()?;
        if !self.historical_migration_pending {
            return Err(ServiceError::new(503, "migration_promotion_not_pending"));
        }
        let owner = self.store.configuration_root();
        proof.validate_owner(&owner)?;
        self.migration_binding
            .as_ref()
            .ok_or_else(|| ServiceError::new(503, "migration_binding_required"))?
            .validate_committed(proof, &owner)?;
        // The genuine committed proof has already closed the configuration
        // maintenance fence. Material reads must now use ordinary journal
        // admission, never the old binding's retired-fence validation path.
        // The caller holds the complete service mutex throughout this change.
        let binding = self
            .migration_binding
            .take()
            .ok_or_else(|| ServiceError::new(503, "migration_binding_required"))?;
        let verified = (|| {
            self.verify_profiles()?;
            proof.validate_owner(&owner)?;
            binding.validate_committed(proof, &owner)?;
            Ok::<(), ServiceError>(())
        })();
        if let Err(error) = verified {
            self.migration_binding = Some(binding);
            self.uncertain = true;
            return Err(error);
        }
        self.historical_migration_pending = false;
        Ok(())
    }
    /// A fresh process may accept the imported baseline only after the enclosing
    /// original C07 Committed chain was re-synced by this same configuration owner.
    /// Unknown transports/operations remain unknown until the separate actual
    /// startup transport closure runs; history is never reset here.
    pub(crate) fn accept_committed_recovery(
        &mut self,
        proof: &crate::store::committed_runtime::RecoveredCommittedRuntime,
    ) -> Result<(), ServiceError> {
        self.healthy()?;
        if !self.historical_migration_pending || self.migration_binding.is_some() {
            return Err(ServiceError::new(503, "committed_recovery_not_pending"));
        }
        let owner = self.store.configuration_root();
        proof.validate_owner(&owner)?;
        let expected = proof
            .state()
            .migration
            .as_ref()
            .ok_or_else(|| ServiceError::new(503, "committed_migration_binding_required"))?;
        self.store.with_journal(|journal| {
            let observed = journal.resync_historical()?.ok_or(JournalError::Conflict)?;
            if observed.body.schema != 2
                || observed.body.migration != expected.transaction_id
                || observed.digest != expected.enrollment_baseline_sha256
                || observed
                    .committed
                    .as_ref()
                    .ok_or(JournalError::Conflict)?
                    .digest()?
                    != expected.enrollment_committed_sha256
            {
                return Err(JournalError::Conflict);
            }
            Ok(())
        })?;
        self.verify_profiles()?;
        proof.validate_owner(&owner)?;
        self.historical_migration_pending = false;
        Ok(())
    }
    pub(crate) fn recover_for_migration(
        mut store: OwnedEnrollmentJournal,
        binding: GatewayMaintenanceBinding,
        admin_token: &[u8],
        ordinary_mcp_digest: Sha256Digest,
        allowed_hosts: Vec<String>,
        limits: Limits,
    ) -> Result<Self, ServiceError> {
        let owner = store.configuration_root();
        binding.validate_owner(&owner)?;
        if verify_slices_are_equal(
            Sha256Digest::of_bytes(admin_token).as_bytes(),
            ordinary_mcp_digest.as_bytes(),
        )
        .is_ok()
        {
            return Err(ServiceError::new(500, "admin_mcp_authorities_must_differ"));
        }
        let admin = GatewayBearerPolicy::new(admin_token, allowed_hosts.clone(), vec![])
            .map_err(|_| invalid())?;
        let now = wall_now()?;
        let epoch =
            GatewayEpoch::try_from(format!("migration-enrollment-{}", uuid::Uuid::new_v4()))
                .map_err(|_| invalid())?;
        let recovered = binding
            .with_journal(&mut store, |journal| {
                Ok(recovery::recover_journal(journal, epoch, limits, now))
            })?
            .map_err(|_| ServiceError::new(503, "enrollment_recovery_required"))?;
        if recovered.facts.historical_baseline.is_none() {
            return Err(ServiceError::new(
                503,
                "historical_migration_baseline_required",
            ));
        }
        let mut service = Self {
            store,
            ledger: recovered.ledger,
            control: recovered.control,
            head: recovered.facts.head,
            admin,
            hosts: allowed_hosts.into_iter().collect(),
            clock: Clock::new(now),
            uncertain: false,
            historical_migration_pending: true,
            migration_binding: Some(binding),
            #[cfg(target_arch = "x86_64")]
            startup_transport_reconciled: true,
        };
        service.verify_profiles()?;
        let bound = service.migration_binding.as_ref().ok_or_else(invalid)?;
        bound.validate_owner(&service.store.configuration_root())?;
        let selected = service
            .ledger
            .authentication_target(&service.control, bound.selected_device())?;
        // The immutable original dual-scope closure lives in bound. Only this
        // actual recovered device's Exec lane is closed; Browser/Computer and
        // every other historical device stay RecoveredUnknown.
        service.ledger.reconcile_recovered_lane(
            service
                .control
                .attest_recovered_lane_closed(&selected, Lane::Exec),
        )?;
        bound.validate_owner(&service.store.configuration_root())?;
        // A successful maintenance constructor MUST still reject every normal
        // HTTP/admin/self request and must never clear the configuration fence.
        if service.ordinary_admission().is_ok() {
            return Err(ServiceError::new(503, "migration_admission_invariant"));
        }
        Ok(service)
    }
}
