//! C07 durable preparation only. No canonical replacement, reader attestation,
//! Applied/Verified/Committed authority, automatic recovery or fence release.
//! Exact legacy bytes remain opaque. An existing namespace is not cutover proof.
use super::configuration::{ConfigurationMaintenance, OwnedConfigurationRoot};
use super::secure_journal::{JournalBudget, JournalError, JournalResult};
use styx_core::management::transaction::{DesiredStateCommit, JournalReceipt};

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
}
pub struct ManagementInventory {
    pub high_water: u64,
    pub transactions: Vec<ManagementTransactionObservation>,
    /// Retained unknown names/materials/temporary files; never silently deleted.
    pub orphans: Vec<String>,
}
pub struct OwnedManagementJournal {
    owner: OwnedConfigurationRoot,
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    budget: JournalBudget,
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    namespace: (u64, u64),
}
impl OwnedManagementJournal {
    pub fn open_existing(
        owner: OwnedConfigurationRoot,
        budget: JournalBudget,
    ) -> JournalResult<Self> {
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        {
            let namespace = owner
                .claim_namespace(super::secure_journal::NamespaceName::ManagementV1, budget)?;
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
    pub fn configuration_root(&self) -> OwnedConfigurationRoot {
        self.owner.clone()
    }
    pub fn observe(&self) -> JournalResult<ManagementInventory> {
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        {
            self.owner.with_state(|state| {
                platform::with_directory(state, self.namespace, |dir| {
                    platform::inventory(&super::secure_journal::files::scan(dir, self.budget)?)
                })
            })
        }
        #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
        {
            Err(JournalError::Unsupported)
        }
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
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        {
            platform::prepare(self, maintenance, raw_intent, before, target, &|_, _| {})
        }
        #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
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
#[cfg(all(target_os = "linux", target_env = "gnu"))]
mod platform {
    use super::*;
    use crate::store::{
        configuration::ConfigurationState,
        secure_journal::{JournalObservation, NamespaceName, files},
    };
    use serde::{Deserialize, Serialize};
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs::File,
    };
    use styx_contracts::identity::Sha256Digest;
    use styx_core::management::transaction::DurableStage;

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PreparedRecord {
        schema: u32,
        intent: DesiredStateCommit,
        raw_intent_sha256: Sha256Digest,
        stage: DurableStage,
        previous: Option<Sha256Digest>,
    }
    fn names(intent: &DesiredStateCommit) -> (String, String, String, String) {
        let id = intent.transaction_id.as_str();
        (
            format!("txn-{id}.intent"),
            format!("txn-{id}.prepared"),
            format!("before-{}.material", intent.before_state_sha256.to_hex()),
            format!("target-{}.material", intent.target_state_sha256.to_hex()),
        )
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
    fn persistence(
        intent: DesiredStateCommit,
        raw_digest: Sha256Digest,
        record: &[u8],
    ) -> PreparedPersistence {
        PreparedPersistence {
            journal: JournalReceipt {
                transaction_id: intent.transaction_id.clone(),
                sequence: intent.sequence,
                stage: DurableStage::Prepared,
                previous: None,
                record_sha256: Sha256Digest::of_bytes(record),
            },
            intent,
            raw_intent_sha256: raw_digest,
        }
    }
    pub(super) fn inventory(scan: &JournalObservation) -> JournalResult<ManagementInventory> {
        let by_name: BTreeMap<_, _> = scan
            .files
            .iter()
            .map(|file| (file.name.as_str(), file.bytes()))
            .collect();
        let mut used = BTreeSet::new();
        let mut sequences = BTreeSet::new();
        let mut transactions = Vec::new();
        let mut high_water = 0;
        for file in &scan.files {
            if !file.name.ends_with(".intent") {
                continue;
            }
            let Ok(intent) = DesiredStateCommit::decode(file.bytes()) else {
                continue;
            };
            let (intent_name, prepared_name, before_name, target_name) = names(&intent);
            if file.name != intent_name {
                continue;
            }
            if !sequences.insert(intent.sequence) {
                return Err(JournalError::Conflict);
            }
            high_water = high_water.max(intent.sequence);
            used.insert(intent_name);
            let prepared = if let Some(bytes) = by_name.get(prepared_name.as_str()) {
                let record: PreparedRecord =
                    serde_json::from_slice(bytes).map_err(|_| JournalError::Unknown)?;
                if record.schema != 1
                    || record.intent != intent
                    || record.stage != DurableStage::Prepared
                    || record.previous.is_some()
                    || record.raw_intent_sha256 != Sha256Digest::of_bytes(file.bytes())
                {
                    return Err(JournalError::Unknown);
                }
                for (name, digest) in [
                    (&before_name, intent.before_state_sha256),
                    (&target_name, intent.target_state_sha256),
                ] {
                    let bytes = by_name.get(name.as_str()).ok_or(JournalError::Unknown)?;
                    if Sha256Digest::of_bytes(bytes) != digest {
                        return Err(JournalError::Unknown);
                    }
                    used.insert(name.clone());
                }
                used.insert(prepared_name);
                Some(ObservedPrepared {
                    intent: intent.clone(),
                    raw_intent_sha256: record.raw_intent_sha256,
                    journal: persistence(intent.clone(), record.raw_intent_sha256, bytes).journal,
                })
            } else {
                None
            };
            transactions.push(ManagementTransactionObservation { intent, prepared });
        }
        transactions.sort_by_key(|transaction| transaction.intent.sequence);
        Ok(ManagementInventory {
            high_water,
            transactions,
            orphans: scan
                .files
                .iter()
                .filter(|file| !used.contains(&file.name))
                .map(|file| file.name.clone())
                .collect(),
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
                if !observed.orphans.is_empty() || observed.transactions.len() > 1 {
                    return Err(JournalError::Conflict);
                }
                if let Some(existing) = observed
                    .transactions
                    .iter()
                    .find(|tx| tx.intent.transaction_id == intent.transaction_id)
                {
                    if existing.intent != intent || existing.prepared.is_none() {
                        return Err(JournalError::Conflict);
                    }
                } else if !observed.transactions.is_empty()
                    || intent.sequence <= observed.high_water
                {
                    return Err(JournalError::Conflict);
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
                if after.transactions.len() != 1
                    || after.transactions[0].prepared.is_none()
                    || !after.orphans.is_empty()
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
