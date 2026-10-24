//! Versioned credential retirement sub-stage of the SAME ManagementV1 journal.
//! Durability records, not proof of OS rename, stopped Host, or native handoff.
use super::*;
use crate::store::{
    RootIdentity,
    configuration::ConfigurationState,
    secure_journal::{JournalObservation, files},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};
const MAX_INTENT: usize = 8192;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::store) struct RetirementLinuxRoot {
    pub device: u64,
    pub inode: u64,
    pub uid: u32,
}
impl RetirementLinuxRoot {
    fn matches(&self, actual: RootIdentity) -> bool {
        let RootIdentity::Linux { device, inode, uid } = actual;
        self.device == device && self.inode == inode && self.uid == uid
    }
}
/// Metadata and an INTERNAL content digest, never token bytes or Debug output.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::store) struct RetirementFileStamp {
    pub device: u64,
    pub inode: u64,
    pub uid: u32,
    pub mode: u32,
    pub nlink: u64,
    pub byte_len: u64,
    pub modified_seconds: i64,
    pub modified_nanoseconds: i64,
    pub changed_seconds: i64,
    pub changed_nanoseconds: i64,
    pub sha256: Sha256Digest,
}
impl RetirementFileStamp {
    fn valid(&self, uid: u32) -> bool {
        self.inode != 0
            && self.uid == uid
            && self.mode == (libc::S_IFREG | 0o600)
            && self.nlink == 1
            && self.byte_len > 0
            && self.byte_len <= 4096
            && (0..1_000_000_000).contains(&self.modified_nanoseconds)
            && (0..1_000_000_000).contains(&self.changed_nanoseconds)
    }
    fn same_renamed_file(&self, post: &Self) -> bool {
        post.valid(self.uid)
            && self.device == post.device
            && self.inode == post.inode
            && self.uid == post.uid
            && self.mode == post.mode
            && self.nlink == post.nlink
            && self.byte_len == post.byte_len
            && self.modified_seconds == post.modified_seconds
            && self.modified_nanoseconds == post.modified_nanoseconds
            && self.sha256 == post.sha256
        // ctime may change under rename. DTOs still do NOT attest the OS effect.
    }
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::store) enum RetirementKind {
    LegacyCredentialRetirement,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::store) struct LegacyCredentialRetirementIntent {
    pub schema: u16,
    pub kind: RetirementKind,
    pub transaction_id: TransactionId,
    pub sequence: u64,
    pub config_root: RetirementLinuxRoot,
    pub host_root: RetirementLinuxRoot,
    pub deployment_raw_sha256: Sha256Digest,
    pub before_state_sha256: Sha256Digest,
    pub preservation_sha256: Sha256Digest,
    pub service_descriptor_sha256: Sha256Digest,
    pub candidate_manifest_sha256: Sha256Digest,
    pub publisher_spki_sha256: Sha256Digest,
    pub original_token: RetirementFileStamp,
}
impl LegacyCredentialRetirementIntent {
    fn validate(&self) -> JournalResult<()> {
        if self.schema != 1
            || self.sequence == 0
            || self.config_root.inode == 0
            || self.host_root.inode == 0
            || self.config_root.uid != self.host_root.uid
            || self.config_root.uid != nix::unistd::geteuid().as_raw()
            || !self.original_token.valid(self.host_root.uid)
        {
            return Err(JournalError::InvalidInput);
        }
        Ok(())
    }
    pub(in crate::store) fn token_source(&self) -> PathBuf {
        PathBuf::from("device/host.token")
    }
    pub(in crate::store) fn token_destination(&self) -> PathBuf {
        PathBuf::from(format!(
            "device/.styx-retired-host-token-{}",
            self.transaction_id.as_str()
        ))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialRetirementStage {
    IntentOnly,
    Prepared,
    Retired,
}
/// Public inventory facts exclude original/post token stamps and token hashes.
pub struct CredentialRetirementObservation {
    pub transaction_id: TransactionId,
    pub sequence: u64,
    pub stage: CredentialRetirementStage,
    pub intent_sha256: Sha256Digest,
    pub prepared_sha256: Option<Sha256Digest>,
    pub retired_sha256: Option<Sha256Digest>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PhaseRecord {
    schema: u16,
    kind: RetirementKind,
    transaction_id: TransactionId,
    sequence: u64,
    raw_intent_sha256: Sha256Digest,
    stage: CredentialRetirementStage,
    #[serde(deserialize_with = "required_option")]
    previous: Option<Sha256Digest>,
    #[serde(deserialize_with = "required_option")]
    post_stamp: Option<RetirementFileStamp>,
}
fn required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}
pub(in crate::store) struct PreparedCredentialRetirement {
    intent: LegacyCredentialRetirementIntent,
    raw_intent_sha256: Sha256Digest,
    record_sha256: Sha256Digest,
    owner: OwnedConfigurationRoot,
    namespace: (u64, u64),
}
pub(in crate::store) struct RetiredCredentialRecord {
    prepared: PreparedCredentialRetirement,
    record_sha256: Sha256Digest,
    post_stamp: RetirementFileStamp,
}
impl PreparedCredentialRetirement {
    pub(in crate::store) fn intent(&self) -> &LegacyCredentialRetirementIntent {
        &self.intent
    }
    pub(in crate::store) fn record_sha256(&self) -> Sha256Digest {
        self.record_sha256
    }
}
impl RetiredCredentialRecord {
    pub(in crate::store) fn intent(&self) -> &LegacyCredentialRetirementIntent {
        &self.prepared.intent
    }
    pub(in crate::store) fn record_sha256(&self) -> Sha256Digest {
        self.record_sha256
    }
    pub(in crate::store) fn post_stamp(&self) -> &RetirementFileStamp {
        &self.post_stamp
    }
}
/// Original exact bytes; no Debug/Serde or token contents. Re-sync never advances.
pub(in crate::store) struct OriginalCredentialRetirement {
    pub intent: LegacyCredentialRetirementIntent,
    pub raw_intent: Vec<u8>,
    pub prepared_sha256: Option<Sha256Digest>,
    pub retired_sha256: Option<Sha256Digest>,
    pub post_stamp: Option<RetirementFileStamp>,
}
pub(in crate::store) struct ObservedRetirement {
    pub(in crate::store) intent: LegacyCredentialRetirementIntent,
    raw: Vec<u8>,
    prepared: Option<Sha256Digest>,
    retired: Option<Sha256Digest>,
    post: Option<RetirementFileStamp>,
}
impl ObservedRetirement {
    pub(super) fn observation(&self) -> CredentialRetirementObservation {
        CredentialRetirementObservation {
            transaction_id: self.intent.transaction_id.clone(),
            sequence: self.intent.sequence,
            stage: if self.retired.is_some() {
                CredentialRetirementStage::Retired
            } else if self.prepared.is_some() {
                CredentialRetirementStage::Prepared
            } else {
                CredentialRetirementStage::IntentOnly
            },
            intent_sha256: Sha256Digest::of_bytes(&self.raw),
            prepared_sha256: self.prepared,
            retired_sha256: self.retired,
        }
    }
    pub(in crate::store) fn original(&self) -> OriginalCredentialRetirement {
        OriginalCredentialRetirement {
            intent: self.intent.clone(),
            raw_intent: self.raw.clone(),
            prepared_sha256: self.prepared,
            retired_sha256: self.retired,
            post_stamp: self.post.clone(),
        }
    }
}
pub(in crate::store) struct HandoffInventory {
    pub records: Vec<ObservedRetirement>,
    pub used: BTreeSet<String>,
}
fn names(id: &TransactionId) -> [String; 3] {
    let id = id.as_str();
    [
        format!("txn-{id}.handoff-intent"),
        format!("txn-{id}.handoff-prepared"),
        format!("txn-{id}.handoff-retired"),
    ]
}
pub(in crate::store) fn scan_handoffs(
    scan: &JournalObservation,
) -> JournalResult<HandoffInventory> {
    let by_name: BTreeMap<_, _> = scan
        .files
        .iter()
        .map(|f| (f.name.as_str(), f.bytes()))
        .collect();
    let mut used = BTreeSet::new();
    let mut records = Vec::new();
    for file in &scan.files {
        if !file.name.ends_with(".handoff-intent") {
            continue;
        }
        if file.bytes().len() > MAX_INTENT {
            return Err(JournalError::BudgetExceeded);
        }
        let intent: LegacyCredentialRetirementIntent =
            serde_json::from_slice(file.bytes()).map_err(|_| JournalError::Unknown)?;
        intent.validate().map_err(|_| JournalError::Unknown)?;
        let [raw_name, prepared_name, retired_name] = names(&intent.transaction_id);
        if raw_name != file.name {
            return Err(JournalError::Unknown);
        }
        used.insert(raw_name);
        let digest = Sha256Digest::of_bytes(file.bytes());
        let mut prepared = None;
        let mut retired = None;
        let mut post = None;
        for (stage, name) in [
            (CredentialRetirementStage::Prepared, prepared_name),
            (CredentialRetirementStage::Retired, retired_name),
        ] {
            if let Some(bytes) = by_name.get(name.as_str()) {
                let record: PhaseRecord =
                    serde_json::from_slice(bytes).map_err(|_| JournalError::Unknown)?;
                if record.schema != 1
                    || record.kind != RetirementKind::LegacyCredentialRetirement
                    || record.transaction_id != intent.transaction_id
                    || record.sequence != intent.sequence
                    || record.raw_intent_sha256 != digest
                    || record.stage != stage
                {
                    return Err(JournalError::Unknown);
                }
                match stage {
                    CredentialRetirementStage::Prepared => {
                        if record.previous.is_some() || record.post_stamp.is_some() {
                            return Err(JournalError::Unknown);
                        }
                        prepared = Some(Sha256Digest::of_bytes(bytes));
                    }
                    CredentialRetirementStage::Retired => {
                        if prepared.is_none()
                            || record.previous != prepared
                            || !record
                                .post_stamp
                                .as_ref()
                                .is_some_and(|p| intent.original_token.same_renamed_file(p))
                        {
                            return Err(JournalError::Unknown);
                        }
                        retired = Some(Sha256Digest::of_bytes(bytes));
                        post = record.post_stamp;
                    }
                    CredentialRetirementStage::IntentOnly => return Err(JournalError::Unknown),
                }
                used.insert(name);
            }
        }
        records.push(ObservedRetirement {
            intent,
            raw: file.bytes().to_vec(),
            prepared,
            retired,
            post,
        });
    }
    // No commit exists; even Retired is a pending substage of its original ID.
    if records.len() > 1 {
        return Err(JournalError::Conflict);
    }
    Ok(HandoffInventory { records, used })
}
fn check_canonical(
    journal: &OwnedManagementJournal,
    state: &ConfigurationState,
    intent: &LegacyCredentialRetirementIntent,
) -> JournalResult<()> {
    if !intent.config_root.matches(state.root.identity()) {
        return Err(JournalError::Conflict);
    }
    let deployment = state
        .root
        .read_raw("deployment.json", 1024 * 1024)
        .map_err(|_| JournalError::Unknown)?;
    let before = state
        .root
        .read_raw("state.json", 1024 * 1024)
        .map_err(|_| JournalError::Unknown)?;
    if Sha256Digest::of_bytes(deployment.bytes()) != intent.deployment_raw_sha256 {
        return Err(JournalError::Conflict);
    }
    if Sha256Digest::of_bytes(before.bytes()) != intent.before_state_sha256
        && !super::cutover::canonical_matches_retired_cutover_locked(journal, state, intent)?
    {
        return Err(JournalError::Conflict);
    }
    Ok(())
}
fn preflight(
    state: &ConfigurationState,
    scan: &JournalObservation,
    entries: &[(String, Vec<u8>)],
    budget: JournalBudget,
) -> JournalResult<()> {
    let mut count = scan.files.len();
    let mut bytes = scan.total_bytes;
    for (name, value) in entries {
        if value.is_empty() || value.len() > budget.max_file_bytes {
            return Err(JournalError::BudgetExceeded);
        }
        if let Some(old) = scan.files.iter().find(|f| &f.name == name) {
            if old.bytes() != value {
                return Err(JournalError::Conflict);
            }
        } else {
            count = count.checked_add(1).ok_or(JournalError::BudgetExceeded)?;
            bytes = bytes
                .checked_add(value.len())
                .ok_or(JournalError::BudgetExceeded)?;
        }
    }
    if count > budget.max_files || bytes > budget.max_bytes {
        return Err(JournalError::BudgetExceeded);
    }
    state.preflight_growth(bytes - scan.total_bytes)
}
fn prepared(
    journal: &OwnedManagementJournal,
    record: &ObservedRetirement,
) -> JournalResult<PreparedCredentialRetirement> {
    Ok(PreparedCredentialRetirement {
        intent: record.intent.clone(),
        raw_intent_sha256: Sha256Digest::of_bytes(&record.raw),
        record_sha256: record.prepared.ok_or(JournalError::Conflict)?,
        owner: journal.owner.clone(),
        namespace: journal.namespace,
    })
}
fn original(scan: &JournalObservation, id: &TransactionId) -> JournalResult<ObservedRetirement> {
    let inventory = super::platform::inventory(scan)?;
    if !inventory.orphans.is_empty() {
        return Err(JournalError::Conflict);
    }
    scan_handoffs(scan)?
        .records
        .into_iter()
        .find(|r| &r.intent.transaction_id == id)
        .ok_or(JournalError::Conflict)
}

impl OwnedManagementJournal {
    /// Retains the original writer while initializing its one fixed journal.
    /// Existing tracked namespaces may be claimed once, never an untracked one.
    pub(in crate::store) fn open_for_legacy_retirement(
        owner: OwnedConfigurationRoot,
        maintenance: &ConfigurationMaintenance,
        budget: JournalBudget,
    ) -> JournalResult<Self> {
        let root_identity = owner.identity()?;
        let namespace = owner.claim_legacy_management_namespace(maintenance, budget)?;
        Ok(Self {
            owner,
            budget,
            namespace,
            root_identity,
        })
    }
    pub(in crate::store) fn prepare_credential_retirement(
        &mut self,
        maintenance: &ConfigurationMaintenance,
        intent: &LegacyCredentialRetirementIntent,
    ) -> JournalResult<PreparedCredentialRetirement> {
        self.prepare_credential_retirement_observing(maintenance, intent, &|_, _| {})
    }
    fn prepare_credential_retirement_observing(
        &mut self,
        maintenance: &ConfigurationMaintenance,
        intent: &LegacyCredentialRetirementIntent,
        observer: &dyn Fn(&str, &str),
    ) -> JournalResult<PreparedCredentialRetirement> {
        intent.validate()?;
        if maintenance.transaction_id() != &intent.transaction_id {
            return Err(JournalError::Conflict);
        }
        let raw = serde_json::to_vec(intent).map_err(|_| JournalError::InvalidInput)?;
        if raw.len() > MAX_INTENT {
            return Err(JournalError::BudgetExceeded);
        }
        let record = serde_json::to_vec(&PhaseRecord {
            schema: 1,
            kind: RetirementKind::LegacyCredentialRetirement,
            transaction_id: intent.transaction_id.clone(),
            sequence: intent.sequence,
            raw_intent_sha256: Sha256Digest::of_bytes(&raw),
            stage: CredentialRetirementStage::Prepared,
            previous: None,
            post_stamp: None,
        })
        .map_err(|_| JournalError::InvalidInput)?;
        let [raw_name, prepared_name, _] = names(&intent.transaction_id);
        let entries = vec![(raw_name, raw), (prepared_name, record)];
        self.owner.with_maintenance(maintenance, |state| {
            check_canonical(self, state, intent)?;
            let result = self.with_directory_locked(state, |dir| {
                let scan = files::scan(dir, self.budget)?;
                let inventory = super::platform::inventory(&scan)?;
                if !inventory.orphans.is_empty() {
                    return Err(JournalError::Conflict);
                }
                let handoffs = scan_handoffs(&scan)?;
                if let Some(existing) = handoffs.records.first() {
                    if existing.intent != *intent
                        || existing.prepared.is_none()
                        || existing.retired.is_some()
                    {
                        return Err(JournalError::Conflict);
                    }
                } else {
                    if intent.sequence <= inventory.high_water
                        || inventory.transactions.iter().any(|tx| {
                            tx.intent.transaction_id == intent.transaction_id
                                || !tx
                                    .phase_receipts
                                    .last()
                                    .is_some_and(|p| p.stage == DurableStage::Committed)
                        })
                    {
                        return Err(JournalError::Conflict);
                    }
                    if inventory.transactions.last().is_some_and(|tx| {
                        tx.intent.target_state_sha256 != intent.before_state_sha256
                    }) {
                        return Err(JournalError::Conflict);
                    }
                }
                preflight(state, &scan, &entries, self.budget)?;
                for ((name, bytes), label) in
                    entries.iter().zip(["handoff_intent", "handoff_prepared"])
                {
                    files::immutable(dir, name, bytes, self.budget, &|phase| {
                        observer(label, phase)
                    })?;
                }
                let after = files::scan(dir, self.budget)?;
                let original =
                    original(&after, &intent.transaction_id).map_err(|_| JournalError::Unknown)?;
                if original.intent != *intent || original.retired.is_some() {
                    return Err(JournalError::Unknown);
                }
                prepared(self, &original)
            })?;
            check_canonical(self, state, intent).map_err(|_| JournalError::Unknown)?;
            Ok(result)
        })
    }
    /// The post stamp is trusted adapter metadata, NOT proof this journal renamed
    /// anything. Original token rename/namespace fsync belongs to its OS adapter.
    pub(in crate::store) fn record_credential_retired(
        &mut self,
        maintenance: &ConfigurationMaintenance,
        source: &PreparedCredentialRetirement,
        post_stamp: &RetirementFileStamp,
    ) -> JournalResult<RetiredCredentialRecord> {
        self.record_credential_retired_observing(maintenance, source, post_stamp, &|_, _| {})
    }
    fn record_credential_retired_observing(
        &mut self,
        maintenance: &ConfigurationMaintenance,
        source: &PreparedCredentialRetirement,
        post_stamp: &RetirementFileStamp,
        observer: &dyn Fn(&str, &str),
    ) -> JournalResult<RetiredCredentialRecord> {
        if !self.owner.same_authority(&source.owner)
            || self.namespace != source.namespace
            || maintenance.transaction_id() != &source.intent.transaction_id
            || !source.intent.original_token.same_renamed_file(post_stamp)
        {
            return Err(JournalError::Conflict);
        }
        self.owner.with_maintenance(maintenance, |state| {
            check_canonical(self, state, &source.intent)?;
            let result = self.with_directory_locked(state, |dir| {
                let scan = files::scan(dir, self.budget)?;
                let existing = original(&scan, &source.intent.transaction_id)?;
                if existing.intent != source.intent
                    || Sha256Digest::of_bytes(&existing.raw) != source.raw_intent_sha256
                    || existing.prepared != Some(source.record_sha256)
                {
                    return Err(JournalError::Conflict);
                }
                let [raw_name, prepared_name, retired_name] = names(&source.intent.transaction_id);
                let record = serde_json::to_vec(&PhaseRecord {
                    schema: 1,
                    kind: RetirementKind::LegacyCredentialRetirement,
                    transaction_id: source.intent.transaction_id.clone(),
                    sequence: source.intent.sequence,
                    raw_intent_sha256: source.raw_intent_sha256,
                    stage: CredentialRetirementStage::Retired,
                    previous: Some(source.record_sha256),
                    post_stamp: Some(post_stamp.clone()),
                })
                .map_err(|_| JournalError::InvalidInput)?;
                preflight(
                    state,
                    &scan,
                    &[(retired_name.clone(), record.clone())],
                    self.budget,
                )?;
                // Re-sync EXACT existing material and predecessor, never infer
                // durability from a recognized Prepared pathname alone.
                for name in [raw_name, prepared_name] {
                    let bytes = scan
                        .files
                        .iter()
                        .find(|f| f.name == name)
                        .ok_or(JournalError::Unknown)?
                        .bytes();
                    files::immutable(dir, &name, bytes, self.budget, &|_| {})?;
                }
                files::immutable(dir, &retired_name, &record, self.budget, &|phase| {
                    observer("handoff_retired", phase)
                })?;
                let after = original(
                    &files::scan(dir, self.budget)?,
                    &source.intent.transaction_id,
                )
                .map_err(|_| JournalError::Unknown)?;
                if after.intent != source.intent
                    || after.retired != Some(Sha256Digest::of_bytes(&record))
                    || after.post.as_ref() != Some(post_stamp)
                {
                    return Err(JournalError::Unknown);
                }
                Ok(RetiredCredentialRecord {
                    prepared: prepared(self, &after)?,
                    record_sha256: after.retired.ok_or(JournalError::Unknown)?,
                    post_stamp: post_stamp.clone(),
                })
            })?;
            check_canonical(self, state, &source.intent).map_err(|_| JournalError::Unknown)?;
            Ok(result)
        })
    }
    pub(in crate::store) fn resync_original_retirement(
        &self,
        maintenance: &ConfigurationMaintenance,
        id: &TransactionId,
    ) -> JournalResult<OriginalCredentialRetirement> {
        if maintenance.transaction_id() != id {
            return Err(JournalError::Conflict);
        }
        self.owner.with_maintenance(maintenance, |state| {
            self.with_directory_locked(state, |dir| {
                let scan = files::scan(dir, self.budget)?;
                let before = original(&scan, id)?;
                check_canonical(self, state, &before.intent)?;
                // Recovery may observe an intent-only crash, but never manufactures
                // Prepared/Retired or renames/restores a token to advance the chain.
                let [raw, prepared, retired] = names(id);
                let mut exact = vec![raw];
                if before.prepared.is_some() {
                    exact.push(prepared);
                }
                if before.retired.is_some() {
                    exact.push(retired);
                }
                for name in exact {
                    files::sync_file(dir, &name)?;
                }
                dir.sync_all().map_err(|_| JournalError::Unknown)?;
                let after = original(&files::scan(dir, self.budget)?, id)?;
                if before.intent != after.intent
                    || before.raw != after.raw
                    || before.prepared != after.prepared
                    || before.retired != after.retired
                    || before.post != after.post
                {
                    return Err(JournalError::Unknown);
                }
                check_canonical(self, state, &after.intent).map_err(|_| JournalError::Unknown)?;
                Ok(after.original())
            })
        })
    }
}

#[cfg(test)]
#[path = "management_handoff_tests.rs"]
mod tests;
