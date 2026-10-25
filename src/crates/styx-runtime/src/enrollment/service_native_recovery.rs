//! Same-owner acceptance of imported history after a fully resynced schema4
//! committed migration. No new Core ledger, lane closure or writer is minted.
use super::*;
use styx_contracts::native_management::{NativeMigrationHistory, NativeRootIdentity};
impl EnrollmentService {
    pub(crate) fn accept_native_committed_recovery(
        &mut self,
        proof: &crate::store::committed_runtime_native::RecoveredNativeCommittedRuntime,
    ) -> Result<(), ServiceError> {
        self.healthy()?;
        if !self.historical_migration_pending {
            return Err(ServiceError::new(503, "committed_recovery_not_pending"));
        }
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        if self.migration_binding.is_some() {
            return Err(ServiceError::new(503, "committed_recovery_not_pending"));
        }
        let owner = self.store.configuration_root();
        proof.validate_owner(&owner)?;
        let binding = proof
            .state()
            .migration_v2()
            .map_err(|_| ServiceError::new(503, "committed_migration_binding_required"))?
            .ok_or_else(|| ServiceError::new(503, "committed_migration_binding_required"))?;
        let NativeMigrationHistory::ImportedLocalGateway {
            baseline_sha256,
            committed_sha256,
        } = &binding.history
        else {
            return Err(ServiceError::new(503, "local_gateway_history_required"));
        };
        if proof.state().desired.gateway.is_none() {
            return Err(ServiceError::new(503, "local_gateway_history_required"));
        }
        let root = match owner.identity()? {
            crate::store::RootIdentity::Linux { device, inode, uid } => {
                NativeRootIdentity::Linux { device, inode, uid }
            }
            #[cfg(target_os = "macos")]
            crate::store::RootIdentity::Macos { device, inode, uid } => {
                NativeRootIdentity::Macos { device, inode, uid }
            }
            #[cfg(target_os = "windows")]
            crate::store::RootIdentity::Windows {
                volume_serial,
                file_id,
                owner_sid,
            } => NativeRootIdentity::Windows {
                volume_serial,
                file_id,
                owner_sid,
            },
        };
        let journal_root: styx_contracts::historical_enrollment::SourceRoot = root.into();
        self.store.with_journal(|journal| {
            let observed = journal.resync_historical()?.ok_or(JournalError::Conflict)?;
            if !matches!(observed.body.schema, 2 | 3)
                || observed.body.migration != binding.transaction_id
                || observed
                    .body
                    .journal_root()
                    .map_err(|_| JournalError::Conflict)?
                    != &journal_root
                || observed.digest != *baseline_sha256
                || observed
                    .committed
                    .as_ref()
                    .ok_or(JournalError::Conflict)?
                    .digest()?
                    != *committed_sha256
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
}
