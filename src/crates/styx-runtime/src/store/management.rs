//! C07 original transaction persistence. No canonical replacement or reader
//! attestation: only the trusted native coordinator supplies phase decisions.
//! Exact legacy bytes remain opaque. An existing namespace is not cutover proof.
use super::configuration::{ConfigurationMaintenance, OwnedConfigurationRoot};
use super::secure_journal::{JournalBudget, JournalError, JournalResult};
use styx_contracts::identity::{Sha256Digest, TransactionId};
use styx_core::management::transaction::{DesiredStateCommit, DurableStage, JournalReceipt};
#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[path = "management_handoff.rs"]
pub(in crate::store) mod handoff;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub use handoff::{CredentialRetirementObservation, CredentialRetirementStage};
#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[path = "management_cutover.rs"]
pub(in crate::store) mod cutover;

#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "windows",
    target_os = "macos"
))]
#[path = "management_parser.rs"]
mod parser;

/// Read-only reuse of the canonical journal parser. Observations are not new
/// durability receipts, writer authority, or permission to recover/apply.
#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "windows",
    target_os = "macos"
))]
pub(super) fn readonly_inventory(
    scan: &super::secure_journal::JournalObservation,
) -> JournalResult<ManagementInventory> {
    parser::inventory(scan)
}
#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "windows",
    target_os = "macos"
))]
pub(super) fn readonly_original(
    scan: &super::secure_journal::JournalObservation,
    id: &TransactionId,
) -> JournalResult<OriginalManagementTransaction> {
    parser::original(scan, id)
}

/// Canonical native state must agree with a complete original pure C07 tip.
/// Read-only evidence only: does not clear maintenance or attest durability.
#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "windows",
    target_os = "macos"
))]
pub(super) fn validate_readonly_native_tip(
    scan: &super::secure_journal::JournalObservation,
    canonical: &super::native_state::ValidatedNativeState,
    marker: &styx_contracts::native_management::NativeRootMarker,
) -> JournalResult<()> {
    let inventory = readonly_inventory(scan)?;
    let state = canonical.state();
    if scan.files.is_empty() {
        return if state.revision == 0 && state.last_transaction.is_none() {
            Ok(())
        } else {
            Err(JournalError::Conflict)
        };
    }
    let tip = state
        .last_transaction
        .as_ref()
        .ok_or(JournalError::Conflict)?;
    if !inventory.orphans.is_empty()
        || inventory.has_legacy_handoffs()
        || inventory.high_water != tip.sequence
        || inventory.transactions.last().is_none_or(|tx| {
            tx.intent.transaction_id != tip.transaction_id || tx.intent.sequence != tip.sequence
        })
        || inventory.transactions.iter().any(|tx| {
            tx.prepared.is_none()
                || tx
                    .phase_receipts
                    .last()
                    .is_none_or(|p| p.stage != DurableStage::Committed)
        })
    {
        return Err(JournalError::Conflict);
    }
    let original = readonly_original(scan, &tip.transaction_id)?;
    let before = super::native_state::decode_state(&original.before, marker)
        .map_err(|_| JournalError::Conflict)?;
    let target = super::native_state::decode_state(&original.target, marker)
        .map_err(|_| JournalError::Conflict)?;
    if original.intent.sequence != tip.sequence
        || original.intent.deployment_raw_sha256 != state.deployment_raw_sha256
        || original.intent.target_state_sha256 != Sha256Digest::of_bytes(&original.target)
        || original.intent.before_state_sha256 != Sha256Digest::of_bytes(&original.before)
        || original
            .phases
            .last()
            .is_none_or(|p| p.stage != DurableStage::Committed)
        || before.state().migration.is_some()
        || target.state().migration.is_some()
        || original.target != canonical.raw_bytes()
    {
        return Err(JournalError::Conflict);
    }
    styx_core::management::state::validate_transition(
        before.state(),
        target.state(),
        marker,
        &original.intent,
    )
    .map_err(|_| JournalError::Conflict)
}

pub struct PreparedPersistence {
    pub intent: DesiredStateCommit,
    pub raw_intent_sha256: styx_contracts::identity::Sha256Digest,
    pub journal: JournalReceipt,
}
/// Observed bytes are NOT a fresh fsync receipt or permission to resume/apply.
/// Recovery must revalidate/resync the original chain under its writer authority.
pub struct ObservedPrepared {
    pub intent: DesiredStateCommit,
    pub raw_intent_sha256: styx_contracts::identity::Sha256Digest,
    pub journal: JournalReceipt,
}
/// Prepared is unresolved, not a successful desired-state application.
pub struct ManagementTransactionObservation {
    pub intent: DesiredStateCommit,
    pub prepared: Option<ObservedPrepared>,
    /// Observed original records, not fresh durability attestations.
    pub phase_receipts: Vec<JournalReceipt>,
}
pub struct ManagementInventory {
    pub high_water: u64,
    pub transactions: Vec<ManagementTransactionObservation>,
    /// Uncommitted legacy credential sub-stages; never admission/cutover proof.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    pub handoffs: Vec<CredentialRetirementObservation>,
    /// Retained unknown names/materials/temporary files; never silently deleted.
    pub orphans: Vec<String>,
}
impl ManagementInventory {
    /// Typed legacy records exist only for the implemented Linux reader. On
    /// Windows/macOS their names remain orphans, which every complete-tip check must
    /// reject; false here is never proof that an unknown legacy file is safe.
    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "windows",
        target_os = "macos"
    ))]
    pub(super) fn has_legacy_handoffs(&self) -> bool {
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        {
            !self.handoffs.is_empty()
        }
        #[cfg(any(target_os = "windows", target_os = "macos"))]
        {
            false
        }
    }
}
/// Raw original materials are private; no Debug or serialization.
pub(super) struct OriginalManagementTransaction {
    pub intent: DesiredStateCommit,
    pub raw_intent: Vec<u8>,
    pub before: Vec<u8>,
    pub target: Vec<u8>,
    /// Includes Prepared and every validated successor in order.
    pub phases: Vec<JournalReceipt>,
}
pub struct OwnedManagementJournal {
    owner: OwnedConfigurationRoot,
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
    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "windows",
        target_os = "macos"
    ))]
    root_identity: super::RootIdentity,
}
impl OwnedManagementJournal {
    pub fn open_existing(
        owner: OwnedConfigurationRoot,
        budget: JournalBudget,
    ) -> JournalResult<Self> {
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "windows",
            target_os = "macos"
        ))]
        {
            let root_identity = owner.identity()?;
            let namespace = owner
                .claim_namespace(super::secure_journal::NamespaceName::ManagementV1, budget)?;
            Ok(Self {
                owner,
                budget,
                namespace,
                root_identity,
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
    pub fn configuration_root(&self) -> OwnedConfigurationRoot {
        self.owner.clone()
    }
    pub fn observe(&self) -> JournalResult<ManagementInventory> {
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "windows",
            target_os = "macos"
        ))]
        {
            self.owner.with_state(|state| {
                platform::with_directory(state, self.namespace, |dir| {
                    platform::inventory(&super::secure_journal::files::scan(dir, self.budget)?)
                })
            })
        }
        #[cfg(not(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "windows",
            target_os = "macos"
        )))]
        {
            Err(JournalError::Unsupported)
        }
    }
    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "windows",
        target_os = "macos"
    ))]
    pub(super) fn observe_locked(
        &self,
        state: &super::configuration::ConfigurationState,
    ) -> JournalResult<ManagementInventory> {
        self.with_directory_locked(state, |directory| {
            platform::inventory(&super::secure_journal::files::scan(directory, self.budget)?)
        })
    }
    pub(super) fn read_original(
        &self,
        id: &TransactionId,
    ) -> JournalResult<OriginalManagementTransaction> {
        self.owner
            .with_state(|state| self.read_original_locked(state, id))
    }
    /// Already under this owner's store lock; never acquire it recursively.
    /// Still reject a caller accidentally passing another configuration state.
    pub(super) fn read_original_locked(
        &self,
        state: &super::configuration::ConfigurationState,
        id: &TransactionId,
    ) -> JournalResult<OriginalManagementTransaction> {
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "windows",
            target_os = "macos"
        ))]
        {
            self.with_directory_locked(state, |dir| {
                platform::original(&super::secure_journal::files::scan(dir, self.budget)?, id)
            })
        }
        #[cfg(not(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "windows",
            target_os = "macos"
        )))]
        {
            let _ = (state, id);
            Err(JournalError::Unsupported)
        }
    }
    /// Store-private pinned namespace access under an ALREADY held writer lock.
    /// It neither acquires/replaces authority nor exposes arbitrary directories.
    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "windows",
        target_os = "macos"
    ))]
    pub(super) fn with_directory_locked<T>(
        &self,
        state: &super::configuration::ConfigurationState,
        operation: impl FnOnce(&std::fs::File) -> JournalResult<T>,
    ) -> JournalResult<T> {
        if state.root.identity() != self.root_identity {
            return Err(JournalError::Conflict);
        }
        platform::with_directory(state, self.namespace, operation)
    }
    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "windows",
        target_os = "macos"
    ))]
    pub(super) fn budget(&self) -> JournalBudget {
        self.budget
    }
    /// Final proof precondition under the same writer lock: no unknown files,
    /// no pending/intent-only history and the exact latest committed transaction.
    /// This observes the verified original chain; coordinator must have resynced
    /// it before minting its private commit proof.
    pub(super) fn assert_complete_locked(
        &self,
        state: &super::configuration::ConfigurationState,
        id: &TransactionId,
    ) -> JournalResult<()> {
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "windows",
            target_os = "macos"
        ))]
        {
            self.with_directory_locked(state, |dir| {
                let scan = super::secure_journal::files::scan(dir, self.budget)?;
                let inventory = platform::inventory(&scan)?;
                if !inventory.orphans.is_empty()
                    || inventory.has_legacy_handoffs()
                    || inventory
                        .transactions
                        .last()
                        .is_none_or(|tx| &tx.intent.transaction_id != id)
                    || inventory.transactions.iter().any(|tx| {
                        tx.prepared.is_none()
                            || tx.phase_receipts.len() != 3
                            || !tx
                                .phase_receipts
                                .last()
                                .is_some_and(|receipt| receipt.stage == DurableStage::Committed)
                    })
                {
                    return Err(JournalError::Conflict);
                }
                Ok(())
            })
        }
        #[cfg(not(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "windows",
            target_os = "macos"
        )))]
        {
            let _ = (state, id);
            Err(JournalError::Unsupported)
        }
    }
    /// Reestablish durability observations of original bytes, never regenerate
    /// a record/reconciled flag or remove retained unknown files.
    pub(super) fn resync_original(
        &self,
        maintenance: &ConfigurationMaintenance,
        id: &TransactionId,
    ) -> JournalResult<OriginalManagementTransaction> {
        if maintenance.transaction_id() != id {
            return Err(JournalError::Conflict);
        }
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "windows",
            target_os = "macos"
        ))]
        {
            self.owner.with_maintenance(maintenance, |state| {
                self.with_directory_locked(state, |dir| {
                    use super::secure_journal::files;
                    let scan = files::scan(dir, self.budget)?;
                    #[cfg(any(target_os = "windows", target_os = "macos"))]
                    {
                        // Windows/macOS have no legacy migration reader. Unknown file
                        // families are preserved as orphans, never resynced into
                        // an apparently complete supported native transaction.
                        let observed = platform::inventory(&scan)?;
                        if !observed.orphans.is_empty() || observed.has_legacy_handoffs() {
                            return Err(JournalError::Conflict);
                        }
                    }
                    let before = platform::original(&scan, id)?;
                    let (intent_name, prepared_name, before_name, target_name) =
                        platform::names(&before.intent);
                    let mut names = vec![intent_name, before_name, target_name, prepared_name];
                    for receipt in &before.phases {
                        if receipt.stage != DurableStage::Prepared {
                            names.push(platform::phase_name(&before.intent, receipt.stage)?);
                        }
                    }
                    for name in names {
                        files::sync_file(dir, &name)?;
                    }
                    platform::sync_directory(dir)?;
                    let after = platform::original(&files::scan(dir, self.budget)?, id)?;
                    if before.intent != after.intent
                        || before.raw_intent != after.raw_intent
                        || before.before != after.before
                        || before.target != after.target
                        || before.phases != after.phases
                    {
                        return Err(JournalError::Unknown);
                    }
                    Ok(after)
                })
            })
        }
        #[cfg(not(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "windows",
            target_os = "macos"
        )))]
        {
            Err(JournalError::Unsupported)
        }
    }
    pub(super) fn append_phase(
        &mut self,
        maintenance: &ConfigurationMaintenance,
        intent: &DesiredStateCommit,
        stage: DurableStage,
        previous: Sha256Digest,
        reconciled: bool,
    ) -> JournalResult<JournalReceipt> {
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "windows",
            target_os = "macos"
        ))]
        {
            platform::append(
                self,
                maintenance,
                intent,
                stage,
                previous,
                reconciled,
                &|_, _| {},
            )
        }
        #[cfg(not(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "windows",
            target_os = "macos"
        )))]
        {
            let _ = (maintenance, intent, stage, previous, reconciled);
            Err(JournalError::Unsupported)
        }
    }
    #[cfg(all(test, target_os = "linux", target_env = "gnu"))]
    pub(super) fn append_phase_observing(
        &mut self,
        maintenance: &ConfigurationMaintenance,
        intent: &DesiredStateCommit,
        stage: DurableStage,
        previous: Sha256Digest,
        reconciled: bool,
        observer: &dyn Fn(&str, &str),
    ) -> JournalResult<JournalReceipt> {
        platform::append(
            self,
            maintenance,
            intent,
            stage,
            previous,
            reconciled,
            observer,
        )
    }
    /// Opaque maintenance authority must belong to this exact shared writer and
    /// transaction. Actual canonical before bytes are checked before AND after
    /// preparation; external writers are not made cooperative by this mutex.
    pub fn prepare(
        &mut self,
        maintenance: &ConfigurationMaintenance,
        raw_intent: &[u8],
        before: &[u8],
        target: &[u8],
    ) -> JournalResult<PreparedPersistence> {
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "windows",
            target_os = "macos"
        ))]
        {
            platform::prepare(self, maintenance, raw_intent, before, target, &|_, _| {})
        }
        #[cfg(not(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "windows",
            target_os = "macos"
        )))]
        {
            let _ = (maintenance, raw_intent, before, target);
            Err(JournalError::Unsupported)
        }
    }
    #[cfg(all(test, target_os = "linux", target_env = "gnu"))]
    fn prepare_observing(
        &mut self,
        maintenance: &ConfigurationMaintenance,
        raw_intent: &[u8],
        before: &[u8],
        target: &[u8],
        observer: &dyn Fn(&str, &str),
    ) -> JournalResult<PreparedPersistence> {
        platform::prepare(self, maintenance, raw_intent, before, target, observer)
    }
}
#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "windows",
    target_os = "macos"
))]
mod platform {
    use super::parser::{PhaseRecord, PreparedRecord, persistence, phase_label};
    pub(super) use super::parser::{inventory, names, original, phase_name};
    use super::*;
    use crate::store::{
        configuration::ConfigurationState,
        secure_journal::{NamespaceName, files},
    };
    use std::fs::File;
    use styx_contracts::identity::Sha256Digest;

    // These are the platform's actual directory barriers. Windows calls the
    // identity-checked writable-HANDLE implementation; macOS uses its native
    // descriptor barrier. No branch infers durability merely from presence.
    pub(super) fn sync_directory(dir: &File) -> JournalResult<()> {
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        {
            dir.sync_all().map_err(|_| JournalError::Unknown)
        }
        #[cfg(any(target_os = "windows", target_os = "macos"))]
        {
            files::sync_directory(dir)
        }
    }
    pub(super) fn with_directory<T>(
        state: &ConfigurationState,
        pin: (u64, u64),
        operation: impl FnOnce(&File) -> JournalResult<T>,
    ) -> JournalResult<T> {
        files::with_namespace(
            &state.root,
            &state.writer,
            NamespaceName::ManagementV1,
            pin,
            operation,
        )
    }
    fn check_target(state: &ConfigurationState, intent: &DesiredStateCommit) -> JournalResult<()> {
        let deployment = state
            .root
            .read_raw("deployment.json", 1024 * 1024)
            .map_err(|_| JournalError::Unknown)?;
        let canonical = state
            .root
            .read_raw("state.json", 1024 * 1024)
            .map_err(|_| JournalError::Unknown)?;
        if Sha256Digest::of_bytes(deployment.bytes()) != intent.deployment_raw_sha256
            || Sha256Digest::of_bytes(canonical.bytes()) != intent.target_state_sha256
        {
            return Err(JournalError::Conflict);
        }
        Ok(())
    }
    pub(super) fn append(
        journal: &mut OwnedManagementJournal,
        maintenance: &ConfigurationMaintenance,
        intent: &DesiredStateCommit,
        stage: DurableStage,
        previous: Sha256Digest,
        reconciled: bool,
        observer: &dyn Fn(&str, &str),
    ) -> JournalResult<JournalReceipt> {
        let label = phase_label(stage)?;
        if &intent.transaction_id != maintenance.transaction_id() {
            return Err(JournalError::Conflict);
        }
        journal.owner.with_maintenance(maintenance, |state| {
            check_target(state, intent)?;
            let receipt = with_directory(state, journal.namespace, |dir| {
                let scan = files::scan(dir, journal.budget)?;
                let inventory = inventory(&scan)?;
                if !inventory.orphans.is_empty() || inventory.has_legacy_handoffs() {
                    return Err(JournalError::Conflict);
                }
                let source = original(&scan, &intent.transaction_id)?;
                if &source.intent != intent {
                    return Err(JournalError::Conflict);
                }
                let last = source.phases.last().ok_or(JournalError::Conflict)?;
                let expected = match stage {
                    DurableStage::Applied => DurableStage::Prepared,
                    DurableStage::Verified => DurableStage::Applied,
                    DurableStage::Committed => DurableStage::Verified,
                    _ => return Err(JournalError::InvalidInput),
                };
                let repeat = last.stage == stage && last.previous == Some(previous);
                if !repeat && (last.stage != expected || last.record_sha256 != previous) {
                    return Err(JournalError::Conflict);
                }
                let record = serde_json::to_vec(&PhaseRecord {
                    schema: 1,
                    intent: intent.clone(),
                    raw_intent_sha256: Sha256Digest::of_bytes(&source.raw_intent),
                    stage,
                    previous,
                    canonical_raw_sha256: intent.target_state_sha256,
                    reconciled,
                })
                .map_err(|_| JournalError::InvalidInput)?;
                let name = phase_name(intent, stage)?;
                let extra = if let Some(file) = scan.files.iter().find(|f| f.name == name) {
                    if file.bytes() != record {
                        return Err(JournalError::Conflict);
                    }
                    0
                } else {
                    if scan.files.len() >= journal.budget.max_files {
                        return Err(JournalError::BudgetExceeded);
                    }
                    record.len()
                };
                if record.len() > journal.budget.max_file_bytes
                    || scan
                        .total_bytes
                        .checked_add(extra)
                        .is_none_or(|n| n > journal.budget.max_bytes)
                {
                    return Err(JournalError::BudgetExceeded);
                }
                state.preflight_growth(extra)?;
                // Re-sync every original material and receipt. Presence is not durability.
                let (intent_name, prepared_name, before_name, target_name) = names(intent);
                let mut sync_names = vec![intent_name, before_name, target_name, prepared_name];
                for receipt in &source.phases {
                    if receipt.stage != DurableStage::Prepared {
                        sync_names.push(phase_name(intent, receipt.stage)?);
                    }
                }
                for name in sync_names {
                    let bytes = scan
                        .files
                        .iter()
                        .find(|f| f.name == name)
                        .ok_or(JournalError::Unknown)?
                        .bytes();
                    files::immutable(dir, &name, bytes, journal.budget, &|_| {})?;
                }
                files::immutable(dir, &name, &record, journal.budget, &|phase| {
                    observer(label, phase)
                })?;
                let final_scan = files::scan(dir, journal.budget)?;
                let updated = original(&final_scan, &intent.transaction_id)?;
                let receipt = updated.phases.last().ok_or(JournalError::Unknown)?;
                if receipt.stage != stage
                    || receipt.previous != Some(previous)
                    || receipt.record_sha256 != Sha256Digest::of_bytes(&record)
                {
                    return Err(JournalError::Unknown);
                }
                Ok(receipt.clone())
            })?;
            check_target(state, intent).map_err(|_| JournalError::Unknown)?;
            Ok(receipt)
        })
    }
    fn check_canonical(
        state: &ConfigurationState,
        intent: &DesiredStateCommit,
        before: &[u8],
    ) -> JournalResult<()> {
        let deployment = state
            .root
            .read_raw("deployment.json", 1024 * 1024)
            .map_err(|_| JournalError::Unknown)?;
        let canonical = state
            .root
            .read_raw("state.json", 1024 * 1024)
            .map_err(|_| JournalError::Unknown)?;
        if Sha256Digest::of_bytes(deployment.bytes()) != intent.deployment_raw_sha256
            || Sha256Digest::of_bytes(canonical.bytes()) != intent.before_state_sha256
            || canonical.bytes() != before
        {
            return Err(JournalError::Conflict);
        }
        Ok(())
    }
    pub(super) fn prepare(
        journal: &mut OwnedManagementJournal,
        maintenance: &ConfigurationMaintenance,
        raw: &[u8],
        before: &[u8],
        target: &[u8],
        observer: &dyn Fn(&str, &str),
    ) -> JournalResult<PreparedPersistence> {
        let intent = DesiredStateCommit::decode(raw).map_err(|_| JournalError::InvalidInput)?;
        if &intent.transaction_id != maintenance.transaction_id()
            || before.is_empty()
            || target.is_empty()
            || before.len() > journal.budget.max_file_bytes
            || target.len() > journal.budget.max_file_bytes
            || Sha256Digest::of_bytes(before) != intent.before_state_sha256
            || Sha256Digest::of_bytes(target) != intent.target_state_sha256
        {
            return Err(JournalError::InvalidInput);
        }
        let raw_digest = Sha256Digest::of_bytes(raw);
        let record = serde_json::to_vec(&PreparedRecord {
            schema: 1,
            intent: intent.clone(),
            raw_intent_sha256: raw_digest,
            stage: DurableStage::Prepared,
            previous: None,
        })
        .map_err(|_| JournalError::InvalidInput)?;
        let (intent_name, prepared_name, before_name, target_name) = names(&intent);
        let entries = [
            (intent_name, raw),
            (before_name, before),
            (target_name, target),
            (prepared_name, record.as_slice()),
        ];
        if entries
            .iter()
            .any(|(_, bytes)| bytes.len() > journal.budget.max_file_bytes)
        {
            return Err(JournalError::BudgetExceeded);
        }
        journal.owner.with_maintenance(maintenance, |state| {
            check_canonical(state, &intent, before)?;
            with_directory(state, journal.namespace, |dir| {
                let scan = files::scan(dir, journal.budget)?;
                let observed = inventory(&scan)?;
                if !observed.orphans.is_empty() || observed.has_legacy_handoffs() {
                    return Err(JournalError::Conflict);
                }
                if let Some(existing) = observed
                    .transactions
                    .iter()
                    .find(|tx| tx.intent.transaction_id == intent.transaction_id)
                {
                    if existing.intent != intent
                        || existing.prepared.is_none()
                        || !existing.phase_receipts.is_empty()
                    {
                        return Err(JournalError::Conflict);
                    }
                } else {
                    if intent.sequence <= observed.high_water
                        || observed.transactions.iter().any(|tx| {
                            !tx.phase_receipts
                                .last()
                                .is_some_and(|p| p.stage == DurableStage::Committed)
                        })
                    {
                        return Err(JournalError::Conflict);
                    }
                    if observed.transactions.last().is_some_and(|tx| {
                        tx.intent.target_state_sha256 != intent.before_state_sha256
                    }) {
                        return Err(JournalError::Conflict);
                    }
                }
                // Whole prepare preflight, not merely each individual append.
                let mut count = scan.files.len();
                let mut bytes = scan.total_bytes;
                for (name, value) in &entries {
                    if let Some(existing) = scan.files.iter().find(|file| &file.name == name) {
                        if existing.bytes() != *value {
                            return Err(JournalError::Conflict);
                        }
                    } else {
                        count = count.checked_add(1).ok_or(JournalError::BudgetExceeded)?;
                        bytes = bytes
                            .checked_add(value.len())
                            .ok_or(JournalError::BudgetExceeded)?;
                    }
                }
                if count > journal.budget.max_files || bytes > journal.budget.max_bytes {
                    return Err(JournalError::BudgetExceeded);
                }
                state.preflight_growth(bytes - scan.total_bytes)?;
                for ((name, value), label) in entries
                    .iter()
                    .zip(["intent", "before", "target", "prepared"])
                {
                    files::immutable(dir, name, value, journal.budget, &|phase| {
                        observer(label, phase)
                    })?;
                }
                let after = inventory(&files::scan(dir, journal.budget)?)?;
                if !after.transactions.iter().any(|tx| {
                    tx.intent == intent && tx.prepared.is_some() && tx.phase_receipts.is_empty()
                }) || !after.orphans.is_empty()
                {
                    return Err(JournalError::Unknown);
                }
                Ok(())
            })?;
            // A post-persistence canonical conflict is uncertain, never ordinary
            // pre-write refusal: all shared handles remain fenced/poisoned.
            check_canonical(state, &intent, before).map_err(|_| JournalError::Unknown)?;
            Ok(persistence(intent.clone(), raw_digest, &record))
        })
    }
}

#[cfg(test)]
#[path = "management_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "management_phase_tests.rs"]
mod phase_tests;
