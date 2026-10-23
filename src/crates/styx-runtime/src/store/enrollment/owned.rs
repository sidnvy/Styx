//! Move-owned bootstrap resource for static services. No self-reference, cloned
//! writer description, second filesystem implementation or network authority.
use super::*;

pub struct OwnedEnrollmentJournal {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    root: PrivateRoot,
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    writer: ConfigurationWriterGuard,
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    budget: JournalBudget,
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    namespace: (u64, u64),
}
impl OwnedEnrollmentJournal {
    /// Takes, rather than duplicates, an existing private root and its exclusive
    /// configuration writer. Existing namespace identity is pinned only once.
    pub fn open_existing(
        root: PrivateRoot,
        mut writer: ConfigurationWriterGuard,
        budget: JournalBudget,
    ) -> JournalResult<Self> {
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        {
            let namespace = {
                let journal = EnrollmentJournal::open_existing(&root, &mut writer, budget)?;
                journal.namespace
            };
            Ok(Self {
                root,
                writer,
                budget,
                namespace,
            })
        }
        #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
        {
            let _ = (root, &mut writer, budget);
            Err(JournalError::Unsupported)
        }
    }
    /// Each synchronous closure borrows the same owned authority and original
    /// namespace pin. Post-checks run even if the closure reports an error;
    /// replacement/unsafe observations cannot be returned as a durable success.
    pub fn with_journal<T>(
        &mut self,
        operation: impl FnOnce(&mut EnrollmentJournal<'_>) -> JournalResult<T>,
    ) -> JournalResult<T> {
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        {
            let mut journal = EnrollmentJournal {
                root: &self.root,
                writer: &mut self.writer,
                budget: self.budget,
                namespace: self.namespace,
            };
            journal.scan()?;
            let result = operation(&mut journal);
            journal.scan()?;
            result
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
