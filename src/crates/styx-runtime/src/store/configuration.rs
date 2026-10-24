//! One move-owned configuration writer shared by typed store adapters.
//!
//! This is a trusted bootstrap resource, not proof that an old JS owner stopped.
//! No network DTO, pathname, mutex, or flock grants legacy migration authority.
//! Locks serialize short filesystem closures only; never wait for native work
//! while holding them. A panic or unsafe observation poisons every handle.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
use super::secure_journal::{JournalBudget, NamespaceName, files};
use super::secure_journal::{JournalError, JournalResult};
use super::{ConfigurationWriterGuard, PrivateRoot, RootIdentity};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU8, Ordering},
};
use styx_contracts::identity::TransactionId;

#[cfg(all(target_os = "linux", target_env = "gnu"))]
const TOTAL_JOURNAL_BYTES: usize = 64 * 1024 * 1024;

/// Clones share the SAME owned root/guard, never a cloned writer description.
/// Enrollment's domain authority remains singleton; this does not clone it.
#[derive(Clone)]
pub struct OwnedConfigurationRoot {
    inner: Arc<ConfigurationOwner>,
}
struct ConfigurationOwner {
    state: Mutex<ConfigurationState>,
    // Published rejection facts (poison monotonic), not another writer authority.
    // Hot async lease/admission checks never wait behind filesystem I/O.
    rejection: AtomicU8,
}
const POISONED: u8 = 1;
const FENCED: u8 = 2;
impl ConfigurationOwner {
    fn publish(&self, state: &ConfigurationState) {
        let proposed = (u8::from(state.poisoned) * POISONED)
            | (u8::from(state.recovery_required || state.fence.is_some()) * FENCED);
        // A single coherent snapshot permits a verified commit to clear only
        // FENCED; once published POISONED can never be cleared in this owner.
        let _ = self
            .rejection
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
                Some(proposed | (old & POISONED))
            });
    }
}
struct UnfinishedAccess<'a> {
    owner: &'a ConfigurationOwner,
    completed: bool,
}
impl Drop for UnfinishedAccess<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.owner.rejection.fetch_or(POISONED, Ordering::Release);
        }
    }
}
pub(super) struct ConfigurationState {
    pub(super) root: PrivateRoot,
    pub(super) writer: ConfigurationWriterGuard,
    poisoned: bool,
    fence: Option<TransactionId>,
    recovery_required: bool,
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    namespaces: Vec<NamespaceBinding>,
}
#[cfg(all(target_os = "linux", target_env = "gnu"))]
struct NamespaceBinding {
    name: NamespaceName,
    pin: (u64, u64),
    budget: JournalBudget,
    claimed: bool,
}
impl ConfigurationState {
    fn validate(&self) -> JournalResult<()> {
        if self.poisoned {
            return Err(JournalError::Unknown);
        }
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        {
            for name in [NamespaceName::EnrollmentV1, NamespaceName::ManagementV1] {
                if !self
                    .namespaces
                    .iter()
                    .any(|b| b.name.as_str() == name.as_str())
                {
                    // Both fixed namespaces belong to this owner even if no
                    // domain handle was minted. Never adopt a newly appearing one.
                    self.root
                        .ensure_absent(name.as_str())
                        .map_err(|_| JournalError::Unknown)?;
                }
            }
            self.root
                .inner
                .with_configuration_writer_directory(&self.writer, |directory| {
                    let checked = (|| {
                        let mut total = 0usize;
                        for binding in &self.namespaces {
                            if files::existing_namespace(directory, binding.name)? != binding.pin {
                                return Err(JournalError::Unknown);
                            }
                            let dir = files::directory(directory, binding.name.as_str())?;
                            let inventory = files::scan(&dir, binding.budget)?;
                            total = total
                                .checked_add(inventory.total_bytes)
                                .ok_or(JournalError::BudgetExceeded)?;
                            if total > TOTAL_JOURNAL_BYTES {
                                return Err(JournalError::BudgetExceeded);
                            }
                        }
                        Ok(())
                    })();
                    Ok(checked)
                })
                .map_err(|_| JournalError::Unknown)?
        }
        #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
        {
            Err(JournalError::Unsupported)
        }
    }
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    pub(super) fn preflight_growth(&self, additional_bytes: usize) -> JournalResult<()> {
        self.root
            .inner
            .with_configuration_writer_directory(&self.writer, |directory| {
                Ok((|| {
                    let mut total = additional_bytes;
                    for binding in &self.namespaces {
                        if files::existing_namespace(directory, binding.name)? != binding.pin {
                            return Err(JournalError::Unknown);
                        }
                        let dir = files::directory(directory, binding.name.as_str())?;
                        total = total
                            .checked_add(files::scan(&dir, binding.budget)?.total_bytes)
                            .ok_or(JournalError::BudgetExceeded)?;
                    }
                    if total > TOTAL_JOURNAL_BYTES {
                        Err(JournalError::BudgetExceeded)
                    } else {
                        Ok(())
                    }
                })())
            })
            .map_err(|_| JournalError::Unknown)?
    }
    /// Remaining bytes across BOTH namespaces under this same held writer.
    /// A temporary per-adapter budget can consume this room without inventing
    /// another reservation or retaining a filesystem lock across native work.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    pub(super) fn remaining_growth(&self) -> JournalResult<usize> {
        self.root
            .inner
            .with_configuration_writer_directory(&self.writer, |directory| {
                Ok((|| {
                    let mut total = 0usize;
                    for binding in &self.namespaces {
                        if files::existing_namespace(directory, binding.name)? != binding.pin {
                            return Err(JournalError::Unknown);
                        }
                        let dir = files::directory(directory, binding.name.as_str())?;
                        total = total
                            .checked_add(files::scan(&dir, binding.budget)?.total_bytes)
                            .ok_or(JournalError::BudgetExceeded)?;
                    }
                    TOTAL_JOURNAL_BYTES
                        .checked_sub(total)
                        .ok_or(JournalError::BudgetExceeded)
                })())
            })
            .map_err(|_| JournalError::Unknown)?
    }
    pub(super) fn require_native_maintenance(
        &self,
        transaction: &TransactionId,
    ) -> JournalResult<()> {
        if self.fence.as_ref() != Some(transaction) {
            return Err(JournalError::Conflict);
        }
        Ok(())
    }
    pub(super) fn finish_native(
        &mut self,
        proof: &super::native_transaction::NativeCommitProof,
    ) -> JournalResult<()> {
        if !proof.matches(&self.root.identity(), self.fence.as_ref()) {
            return Err(JournalError::Conflict);
        }
        self.fence = None;
        self.recovery_required = false;
        Ok(())
    }
    pub(super) fn ordinary_admission(&self) -> JournalResult<()> {
        if self.recovery_required || self.fence.is_some() {
            Err(JournalError::Conflict)
        } else {
            Ok(())
        }
    }
}
pub(super) struct ConfigurationOpenFailure {
    pub(super) error: JournalError,
    pub(super) root: PrivateRoot,
    pub(super) writer: ConfigurationWriterGuard,
}
impl OwnedConfigurationRoot {
    /// Moves an already acquired writer. This neither creates namespaces nor
    /// authorizes fresh bootstrap, legacy handoff, migration, or service changes.
    pub fn open_existing(
        root: PrivateRoot,
        writer: ConfigurationWriterGuard,
    ) -> JournalResult<Self> {
        Self::open_existing_retaining(root, writer).map_err(|failure| failure.error)
    }
    pub(super) fn open_existing_retaining(
        root: PrivateRoot,
        writer: ConfigurationWriterGuard,
    ) -> Result<Self, Box<ConfigurationOpenFailure>> {
        let mut state = ConfigurationState {
            root,
            writer,
            poisoned: false,
            fence: None,
            recovery_required: false,
            #[cfg(all(target_os = "linux", target_env = "gnu"))]
            namespaces: Vec::with_capacity(2),
        };
        let initialized: JournalResult<()> = (|| {
            #[cfg(all(target_os = "linux", target_env = "gnu"))]
            for name in [NamespaceName::EnrollmentV1, NamespaceName::ManagementV1] {
                if state.root.ensure_absent(name.as_str()).is_ok() {
                    continue;
                }
                let budget = JournalBudget::default();
                let (pin, nonempty) = state
                    .root
                    .inner
                    .with_configuration_writer_directory(&state.writer, |directory| {
                        Ok((|| {
                            let pin = files::existing_namespace(directory, name)?;
                            let dir = files::directory(directory, name.as_str())?;
                            Ok::<_, JournalError>((
                                pin,
                                !files::scan(&dir, budget)?.files.is_empty(),
                            ))
                        })())
                    })
                    .map_err(|_| JournalError::Unknown)??;
                state.namespaces.push(NamespaceBinding {
                    name,
                    pin,
                    budget,
                    claimed: false,
                });
                // Both journals count against the total even in standalone
                // management. Only enrollment's own ledger can reconcile enrollment;
                // retained management bytes always require management reconciliation.
                if name.as_str() == NamespaceName::ManagementV1.as_str() {
                    state.recovery_required = nonempty;
                }
            }
            state.validate()
        })();
        if let Err(error) = initialized {
            return Err(Box::new(ConfigurationOpenFailure {
                error,
                root: state.root,
                writer: state.writer,
            }));
        }
        Ok(Self {
            inner: Arc::new(ConfigurationOwner {
                rejection: AtomicU8::new(
                    (u8::from(state.poisoned) * POISONED)
                        | (u8::from(state.recovery_required || state.fence.is_some()) * FENCED),
                ),
                state: Mutex::new(state),
            }),
        })
    }
    pub fn identity(&self) -> JournalResult<RootIdentity> {
        self.with_state(|state| Ok(state.root.identity()))
    }
    pub(crate) fn same_authority(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
    pub(super) fn with_state<T>(
        &self,
        operation: impl FnOnce(&mut ConfigurationState) -> JournalResult<T>,
    ) -> JournalResult<T> {
        let mut state = self.inner.state.lock().map_err(|_| {
            self.inner.rejection.fetch_or(POISONED, Ordering::Release);
            JournalError::Unknown
        })?;
        // Publish rejection even if a trusted store callback unwinds. No
        // authentication or memory-safety claim relies on advisory Mutex poison.
        let mut access = UnfinishedAccess {
            owner: &self.inner,
            completed: false,
        };
        if let Err(error) = state.validate() {
            state.poisoned = true;
            self.inner.publish(&state);
            access.completed = true;
            return Err(error);
        }
        let result = operation(&mut state);
        // Even an ordinary closure error cannot hide a replaced root/namespace.
        if let Err(error) = state.validate() {
            state.poisoned = true;
            self.inner.publish(&state);
            access.completed = true;
            return Err(error);
        }
        if matches!(result, Err(JournalError::Unknown)) {
            state.poisoned = true;
        }
        self.inner.publish(&state);
        access.completed = true;
        result
    }
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    pub(super) fn claim_namespace(
        &self,
        name: NamespaceName,
        budget: JournalBudget,
    ) -> JournalResult<(u64, u64)> {
        if !budget.valid() {
            return Err(JournalError::InvalidInput);
        }
        self.with_state(|state| {
            // Claims are typed reader/store handles, not ordinary execution
            // admission. A retained journal can be inspected while recovery is
            // fenced, but cannot begin new transactions.
            if let Some(binding) = state
                .namespaces
                .iter_mut()
                .find(|b| b.name.as_str() == name.as_str())
            {
                if binding.claimed {
                    return Err(JournalError::Conflict);
                }
                binding.claimed = true;
                binding.budget = budget;
                return Ok(binding.pin);
            }
            let pin = state
                .root
                .inner
                .with_configuration_writer_directory(&state.writer, |dir| {
                    Ok(files::existing_namespace(dir, name))
                })
                .map_err(|_| JournalError::Unknown)??;
            state.namespaces.push(NamespaceBinding {
                name,
                pin,
                budget,
                claimed: true,
            });
            Ok(pin)
        })
    }
    /// The original maintenance owner may initialize exactly its management
    /// namespace for migration. No new writer, enrollment namespace or fresh
    /// root authority is created; an unexpected existing name is not adopted.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    pub(super) fn claim_legacy_management_namespace(
        &self,
        maintenance: &ConfigurationMaintenance,
        budget: JournalBudget,
    ) -> JournalResult<(u64, u64)> {
        if !budget.valid() {
            return Err(JournalError::InvalidInput);
        }
        self.with_maintenance(maintenance, |state| {
            let name = NamespaceName::ManagementV1;
            if let Some(binding) = state
                .namespaces
                .iter_mut()
                .find(|binding| binding.name.as_str() == name.as_str())
            {
                if binding.claimed {
                    return Err(JournalError::Conflict);
                }
                binding.claimed = true;
                binding.budget = budget;
                return Ok(binding.pin);
            }
            state
                .root
                .ensure_absent(name.as_str())
                .map_err(|_| JournalError::Conflict)?;
            let pin = state
                .root
                .inner
                .with_configuration_writer_directory(&state.writer, |directory| {
                    Ok(files::create_new_namespace(directory, name))
                })
                .map_err(|_| JournalError::Unknown)??;
            state.namespaces.push(NamespaceBinding {
                name,
                pin,
                budget,
                claimed: true,
            });
            Ok(pin)
        })
    }
    /// Initialize only the fixed enrollment namespace under this original
    /// root's active migration fence. It does not settle any legacy writer or
    /// release maintenance; an unexpected appearing namespace is never adopted.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    pub(super) fn claim_legacy_enrollment_namespace(
        &self,
        maintenance: &ConfigurationMaintenance,
        budget: JournalBudget,
    ) -> JournalResult<(u64, u64)> {
        if !budget.valid() {
            return Err(JournalError::InvalidInput);
        }
        self.with_maintenance(maintenance, |state| {
            let name = NamespaceName::EnrollmentV1;
            if let Some(binding) = state
                .namespaces
                .iter_mut()
                .find(|b| b.name.as_str() == name.as_str())
            {
                if binding.claimed {
                    return Err(JournalError::Conflict);
                }
                binding.claimed = true;
                binding.budget = budget;
                return Ok(binding.pin);
            }
            state
                .root
                .ensure_absent(name.as_str())
                .map_err(|_| JournalError::Conflict)?;
            let pin = state
                .root
                .inner
                .with_configuration_writer_directory(&state.writer, |directory| {
                    Ok(files::create_new_namespace(directory, name))
                })
                .map_err(|_| JournalError::Unknown)??;
            state.namespaces.push(NamespaceBinding {
                name,
                pin,
                budget,
                claimed: true,
            });
            Ok(pin)
        })
    }
    // Hot checks consume only published rejection facts. Actual store access
    // still validates the guarded root and full namespace inventory before/after.
    pub(crate) fn ensure_usable(&self) -> JournalResult<()> {
        if self.inner.rejection.load(Ordering::Acquire) & POISONED != 0 {
            Err(JournalError::Unknown)
        } else {
            Ok(())
        }
    }
    pub(crate) fn ensure_admission(&self) -> JournalResult<()> {
        let rejection = self.inner.rejection.load(Ordering::Acquire);
        if rejection & POISONED != 0 {
            return Err(JournalError::Unknown);
        }
        if rejection & FENCED != 0 {
            Err(JournalError::Conflict)
        } else {
            Ok(())
        }
    }
    /// Only a native coordinator without an instantiated enrollment authority
    /// may use this port. Otherwise the existing complete service gate is required.
    pub(super) fn begin_standalone_native(
        &self,
        transaction: TransactionId,
        recovery: bool,
    ) -> JournalResult<ConfigurationMaintenance> {
        self.with_state(|state| {
            #[cfg(all(target_os = "linux", target_env = "gnu"))]
            if state.namespaces.iter().any(|binding| {
                binding.name.as_str() == NamespaceName::EnrollmentV1.as_str() && binding.claimed
            }) {
                return Err(JournalError::Conflict);
            }
            if recovery {
                if !state.recovery_required || state.fence.is_some() {
                    return Err(JournalError::Conflict);
                }
            } else {
                state.ordinary_admission()?;
            }
            state.fence = Some(transaction.clone());
            Ok(())
        })?;
        Ok(ConfigurationMaintenance {
            owner: self.clone(),
            transaction,
        })
    }
    pub(super) fn with_maintenance<T>(
        &self,
        maintenance: &ConfigurationMaintenance,
        operation: impl FnOnce(&mut ConfigurationState) -> JournalResult<T>,
    ) -> JournalResult<T> {
        if !maintenance.matches(self) {
            return Err(JournalError::Conflict);
        }
        self.with_state(|state| {
            if state.fence.as_ref() != Some(maintenance.transaction_id()) {
                return Err(JournalError::Conflict);
            }
            operation(state)
        })
    }
    /// Call only while holding the SAME enrollment service gate for the entire
    /// prior Core->journal->publish round trip. No lock is held after return.
    pub(crate) fn begin_maintenance(
        &self,
        transaction: TransactionId,
    ) -> JournalResult<ConfigurationMaintenance> {
        self.with_state(|state| {
            state.ordinary_admission()?;
            state.fence = Some(transaction.clone());
            Ok(())
        })?;
        Ok(ConfigurationMaintenance {
            owner: self.clone(),
            transaction,
        })
    }
}
/// Opaque in-process fence capability. Dropping a waiter/handle never reopens
/// admission. This is NOT a durable transaction, Host maintenance, or cutover.
/// Persistent management reconciliation must own release in the next adapter.
pub struct ConfigurationMaintenance {
    owner: OwnedConfigurationRoot,
    transaction: TransactionId,
}
impl ConfigurationMaintenance {
    pub fn transaction_id(&self) -> &TransactionId {
        &self.transaction
    }
    pub fn root_identity(&self) -> JournalResult<RootIdentity> {
        self.owner.identity()
    }
    /// Prove this exact maintenance fence is still active, not just that the
    /// filesystem root has the same identity. This does not settle old writers.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    pub(crate) fn validate_active(&self) -> JournalResult<RootIdentity> {
        self.owner
            .with_maintenance(self, |state| Ok(state.root.identity()))
    }
    pub(crate) fn matches(&self, owner: &OwnedConfigurationRoot) -> bool {
        self.owner.same_authority(owner)
    }
    // No resume port yet: releasing this fence requires a verified persistent
    // transaction/abort adapter, not a caller-provided boolean or Drop.
}

#[cfg(test)]
#[path = "configuration_tests.rs"]
mod tests;
