//! Move-owned bootstrap resource for static services. No self-reference, cloned
//! writer description, second filesystem implementation or network authority.
use super::*;

pub struct OwnedEnrollmentJournal {
    owner: crate::store::OwnedConfigurationRoot,
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    budget: JournalBudget,
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    namespace: (u64, u64),
}
impl OwnedEnrollmentJournal {
    pub fn open_existing(
        root: PrivateRoot,
        writer: ConfigurationWriterGuard,
        budget: JournalBudget,
    ) -> JournalResult<Self> {
        Self::from_configuration(
            crate::store::OwnedConfigurationRoot::open_existing(root, writer)?,
            budget,
        )
    }
    /// Trusted bootstrap composes typed adapters under one move-owned writer.
    /// Only one enrollment handle/ledger can be minted by a configuration root.
    pub fn from_configuration(
        owner: crate::store::OwnedConfigurationRoot,
        budget: JournalBudget,
    ) -> JournalResult<Self> {
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        {
            let namespace = owner.claim_namespace(
                crate::store::secure_journal::NamespaceName::EnrollmentV1,
                budget,
            )?;
            Ok(Self {
                owner,
                budget,
                namespace,
            })
        }
        #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
        {
            let _ = (owner, budget);
            Err(JournalError::Unsupported)
        }
    }
    /// Migration-only access under the SAME original configuration writer and
    /// active opaque fence; this does not grant HTTP admission or C07 completion.
    pub(crate) fn open_for_historical(
        owner: crate::store::OwnedConfigurationRoot,
        maintenance: &crate::store::ConfigurationMaintenance,
        budget: JournalBudget,
    ) -> JournalResult<Self> {
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        {
            let namespace = owner.claim_legacy_enrollment_namespace(maintenance, budget)?;
            Ok(Self {
                owner,
                budget,
                namespace,
            })
        }
        #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
        {
            let _ = (owner, maintenance, budget);
            Err(JournalError::Unsupported)
        }
    }
    pub(crate) fn with_historical_journal<T>(
        &mut self,
        maintenance: &crate::store::ConfigurationMaintenance,
        operation: impl FnOnce(&mut EnrollmentJournal<'_>) -> JournalResult<T>,
    ) -> JournalResult<T> {
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        {
            self.owner.with_maintenance(maintenance, |state| {
                let remaining = state.remaining_growth()?;
                let mut journal = EnrollmentJournal {
                    root: &state.root,
                    writer: &mut state.writer,
                    budget: self.budget,
                    namespace: self.namespace,
                    historical_transaction: Some(maintenance.transaction_id().clone()),
                };
                let observed = journal.scan()?;
                journal.budget.max_bytes = journal.budget.max_bytes.min(
                    observed
                        .total_bytes
                        .checked_add(remaining)
                        .ok_or(JournalError::BudgetExceeded)?,
                );
                if journal.budget.max_bytes == 0 {
                    return Err(JournalError::BudgetExceeded);
                }
                journal.budget.max_file_bytes =
                    journal.budget.max_file_bytes.min(journal.budget.max_bytes);
                journal.scan()?;
                let result = operation(&mut journal);
                journal.scan()?;
                result
            })
        }
        #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
        {
            let _ = (maintenance, operation);
            Err(JournalError::Unsupported)
        }
    }
    pub(crate) fn configuration_root(&self) -> crate::store::OwnedConfigurationRoot {
        self.owner.clone()
    }
    pub fn with_journal<T>(
        &mut self,
        operation: impl FnOnce(&mut EnrollmentJournal<'_>) -> JournalResult<T>,
    ) -> JournalResult<T> {
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        {
            self.owner.with_state(|state| {
                state.ordinary_admission()?;
                let mut journal = EnrollmentJournal {
                    root: &state.root,
                    writer: &mut state.writer,
                    budget: self.budget,
                    namespace: self.namespace,
                    historical_transaction: None,
                };
                journal.scan()?;
                let result = operation(&mut journal);
                journal.scan()?;
                result
            })
        }
        #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
        {
            let _ = operation;
            Err(JournalError::Unsupported)
        }
    }
}

#[cfg(test)]
#[path = "owned_tests.rs"]
mod tests;
