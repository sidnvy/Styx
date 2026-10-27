//! Move-owned bootstrap resource for static services. No self-reference, cloned
//! writer description, second filesystem implementation or network authority.
use super::*;

pub struct OwnedEnrollmentJournal {
    owner: crate::store::OwnedConfigurationRoot,
    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "windows",
        target_os = "macos"
    ))]
    budget: JournalBudget,
    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "windows",
        target_os = "macos"
    ))]
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
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "windows",
            target_os = "macos"
        ))]
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
        #[cfg(not(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "windows",
            target_os = "macos"
        )))]
        {
            let _ = (owner, budget);
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
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "windows",
            target_os = "macos"
        ))]
        {
            self.owner.with_state(|state| {
                state.ordinary_admission()?;
                let mut journal = EnrollmentJournal {
                    root: &state.root,
                    writer: &mut state.writer,
                    budget: self.budget,
                    namespace: self.namespace,
                    #[cfg(all(target_os = "linux", target_env = "gnu"))]
                    historical_transaction: None,
                };
                journal.scan()?;
                let result = operation(&mut journal);
                journal.scan()?;
                result
            })
        }
        #[cfg(not(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "windows",
            target_os = "macos"
        )))]
        {
            let _ = operation;
            Err(JournalError::Unsupported)
        }
    }
}

#[cfg(test)]
#[path = "owned_tests.rs"]
mod tests;
