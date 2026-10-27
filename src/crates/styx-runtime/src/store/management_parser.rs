//! Pure original-management byte parser shared by read-only platform readers.
//! Presence is not durability or writer/commit authority. Unknown file families
//! remain orphans and prevent admission on every platform.
use super::*;
use crate::store::secure_journal::JournalObservation;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PreparedRecord {
    pub(super) schema: u32,
    pub(super) intent: DesiredStateCommit,
    pub(super) raw_intent_sha256: Sha256Digest,
    pub(super) stage: DurableStage,
    pub(super) previous: Option<Sha256Digest>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PhaseRecord {
    pub(super) schema: u32,
    pub(super) intent: DesiredStateCommit,
    pub(super) raw_intent_sha256: Sha256Digest,
    pub(super) stage: DurableStage,
    pub(super) previous: Sha256Digest,
    pub(super) canonical_raw_sha256: Sha256Digest,
    pub(super) reconciled: bool,
}
pub(super) fn phase_label(stage: DurableStage) -> JournalResult<&'static str> {
    match stage {
        DurableStage::Applied => Ok("applied"),
        DurableStage::Verified => Ok("verified"),
        DurableStage::Committed => Ok("committed"),
        _ => Err(JournalError::InvalidInput),
    }
}
pub(super) fn phase_name(
    intent: &DesiredStateCommit,
    stage: DurableStage,
) -> JournalResult<String> {
    Ok(format!(
        "txn-{}.{}",
        intent.transaction_id.as_str(),
        phase_label(stage)?
    ))
}
pub(super) fn names(intent: &DesiredStateCommit) -> (String, String, String, String) {
    let id = intent.transaction_id.as_str();
    (
        format!("txn-{id}.intent"),
        format!("txn-{id}.prepared"),
        format!("before-{}.material", intent.before_state_sha256.to_hex()),
        format!("target-{}.material", intent.target_state_sha256.to_hex()),
    )
}
pub(super) fn persistence(
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
        let mut phase_receipts = Vec::new();
        let mut previous = prepared.as_ref().map(|p| p.journal.record_sha256);
        for stage in [
            DurableStage::Applied,
            DurableStage::Verified,
            DurableStage::Committed,
        ] {
            let name = phase_name(&intent, stage)?;
            if let Some(bytes) = by_name.get(name.as_str()) {
                let expected = previous.ok_or(JournalError::Unknown)?;
                let record: PhaseRecord =
                    serde_json::from_slice(bytes).map_err(|_| JournalError::Unknown)?;
                if record.schema != 1
                    || record.intent != intent
                    || record.raw_intent_sha256 != Sha256Digest::of_bytes(file.bytes())
                    || record.stage != stage
                    || record.previous != expected
                    || record.canonical_raw_sha256 != intent.target_state_sha256
                {
                    return Err(JournalError::Unknown);
                }
                let receipt = JournalReceipt {
                    transaction_id: intent.transaction_id.clone(),
                    sequence: intent.sequence,
                    stage,
                    previous: Some(expected),
                    record_sha256: Sha256Digest::of_bytes(bytes),
                };
                previous = Some(receipt.record_sha256);
                phase_receipts.push(receipt);
                used.insert(name);
            } else {
                previous = None;
            }
        }
        transactions.push(ManagementTransactionObservation {
            intent,
            prepared,
            phase_receipts,
        });
    }
    transactions.sort_by_key(|transaction| transaction.intent.sequence);
    for (index, tx) in transactions.iter().enumerate() {
        let committed = tx
            .phase_receipts
            .last()
            .is_some_and(|p| p.stage == DurableStage::Committed);
        if !committed && index + 1 != transactions.len() {
            return Err(JournalError::Conflict);
        }
        let previous = index
            .checked_sub(1)
            .map(|previous| transactions[previous].intent.target_state_sha256);
        if previous.is_some_and(|hash| hash != tx.intent.before_state_sha256) {
            return Err(JournalError::Conflict);
        }
    }
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
pub(super) fn original(
    scan: &JournalObservation,
    id: &TransactionId,
) -> JournalResult<OriginalManagementTransaction> {
    let inventory = inventory(scan)?;
    let tx = inventory
        .transactions
        .into_iter()
        .find(|tx| &tx.intent.transaction_id == id)
        .ok_or(JournalError::Conflict)?;
    original_observed(scan, tx)
}
/// The inventory has already verified the one canonical parser. This extracts
/// its original raw attachments without recursively reparsing the full history.
pub(super) fn original_observed(
    scan: &JournalObservation,
    tx: ManagementTransactionObservation,
) -> JournalResult<OriginalManagementTransaction> {
    let (raw_name, _, before_name, target_name) = names(&tx.intent);
    let read = |name: &str| {
        scan.files
            .iter()
            .find(|f| f.name == name)
            .map(|f| f.bytes().to_vec())
            .ok_or(JournalError::Unknown)
    };
    let raw_intent = read(&raw_name)?;
    let before = read(&before_name)?;
    let target = read(&target_name)?;
    if Sha256Digest::of_bytes(&before) != tx.intent.before_state_sha256
        || Sha256Digest::of_bytes(&target) != tx.intent.target_state_sha256
    {
        return Err(JournalError::Unknown);
    }
    let prepared = tx.prepared.ok_or(JournalError::Conflict)?;
    let mut phases = vec![prepared.journal];
    phases.extend(tx.phase_receipts);
    Ok(OriginalManagementTransaction {
        intent: tx.intent,
        raw_intent,
        before,
        target,
        phases,
    })
}
