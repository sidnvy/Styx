//! Pure original-management byte parser shared by read-only platform readers.
//! Presence is not durability or writer/commit authority. Unsupported legacy
//! file families stay unused/orphaned on Windows; only Linux parses migration.
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
    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "macos",
        target_os = "windows"
    ))]
    let handoff_inventory = handoff::scan_handoffs(scan)?;
    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "macos",
        target_os = "windows"
    ))]
    let cutover_inventory = super::cutover::scan_cutovers(scan)?;
    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "macos",
        target_os = "windows"
    ))]
    let completed_native_anchor = {
        let mut completed = cutover_inventory
            .native_records
            .iter()
            .filter(|c| c.intent.schema == 4 && c.last_stage == DurableStage::Committed);
        let first = completed.next();
        if completed.next().is_some() {
            return Err(JournalError::Conflict);
        }
        first.map(|c| {
            (
                c.intent.transaction_id.clone(),
                c.intent.sequence,
                c.intent.before_state_sha256,
                c.intent.target_state_sha256,
            )
        })
    };

    // Legacy schema2 and native schema4 have different original material
    // codecs, but both reserve the same one C07 sequence. Never mix anchors.
    let completed_legacy_anchor = {
        let mut completed = cutover_inventory.records.iter().filter(|c| {
            c.intent.schema == 2
                && c.last_stage == DurableStage::Committed
                && c.validation_report().is_some()
                && c.paired_validation_report().is_some()
        });
        let first = completed.next();
        if completed.next().is_some() {
            return Err(JournalError::Conflict);
        }
        first.map(|c| {
            (
                c.intent.transaction_id.clone(),
                c.intent.sequence,
                c.intent.before_state_sha256,
                c.intent.target_state_sha256,
            )
        })
    };
    if completed_legacy_anchor.is_some() && completed_native_anchor.is_some() {
        return Err(JournalError::Conflict);
    }
    let completed_anchor = completed_native_anchor
        .as_ref()
        .or(completed_legacy_anchor.as_ref());

    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "macos",
        target_os = "windows"
    ))]
    let mut ids: BTreeSet<_> = transactions
        .iter()
        .map(|tx| tx.intent.transaction_id.clone())
        .collect();
    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "macos",
        target_os = "windows"
    ))]
    for (record, before_state_sha256) in handoff_inventory.observations() {
        if !ids.insert(record.transaction_id.clone()) || !sequences.insert(record.sequence) {
            return Err(JournalError::Conflict);
        }
        high_water = high_water.max(record.sequence);
        let completed = completed_anchor.is_some_and(|(id, seq, before, _)| {
            id == &record.transaction_id
                && *seq == record.sequence
                && *before == before_state_sha256
        });
        if transactions.iter().any(|tx| {
            tx.intent.sequence == record.sequence
                || (tx.intent.sequence > record.sequence && !completed)
                || (tx.intent.sequence < record.sequence
                    && tx
                        .phase_receipts
                        .last()
                        .is_none_or(|p| p.stage != DurableStage::Committed))
        }) {
            return Err(JournalError::Conflict);
        }
        if transactions
            .iter()
            .rfind(|tx| tx.intent.sequence < record.sequence)
            .is_some_and(|tx| tx.intent.target_state_sha256 != before_state_sha256)
        {
            return Err(JournalError::Conflict);
        }
    }
    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "macos",
        target_os = "windows"
    ))]
    {
        used.extend(handoff_inventory.used.iter().cloned());
        used.extend(cutover_inventory.used.iter().cloned());
    }
    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "macos",
        target_os = "windows"
    ))]
    let owner_recoveries: Vec<(TransactionId, u64, Option<handoff::OwnerRecoveryStage>)> = {
        let recovery = handoff::scan_owner_recoveries(scan)?;
        used.extend(recovery.used.iter().cloned());
        for record in &recovery.records {
            let i = &record.intent;
            let matching = handoff_inventory
                .native_records
                .iter()
                .find(|r| r.intent.transaction_id == i.transaction_id);
            if let Some(retirement) = matching {
                if record.stage() != Some(handoff::OwnerRecoveryStage::GuardsHeld)
                    || i.sequence != retirement.intent.sequence
                    || i.config_root != retirement.intent.config_root
                    || i.before_state_sha256 != retirement.intent.before_state_sha256
                    || i.deployment_raw_sha256 != retirement.intent.deployment_raw_sha256
                    || i.candidate_manifest_sha256 != retirement.intent.candidate_manifest_sha256
                    || i.publisher_spki_sha256 != retirement.intent.publisher_spki_sha256
                    || i.successor_retirement_intent_sha256
                        != retirement.observation().intent_sha256
                {
                    return Err(JournalError::Conflict);
                }
            } else {
                if !ids.insert(i.transaction_id.clone())
                    || !sequences.insert(i.sequence)
                    || !handoff_inventory.records.is_empty()
                    || !handoff_inventory.native_records.is_empty()
                    || transactions.iter().any(|t| {
                        t.intent.sequence >= i.sequence
                            || t.phase_receipts
                                .last()
                                .is_none_or(|p| p.stage != DurableStage::Committed)
                    })
                    || transactions
                        .last()
                        .is_some_and(|t| t.intent.target_state_sha256 != i.before_state_sha256)
                {
                    return Err(JournalError::Conflict);
                }
                high_water = high_water.max(i.sequence);
            }
        }
        recovery
            .records
            .iter()
            .map(|r| {
                (
                    r.intent.transaction_id.clone(),
                    r.intent.sequence,
                    r.stage(),
                )
            })
            .collect()
    };
    // A PRE-EFFECT plan reserves the SAME original transaction/sequence.
    // It is unfinished until the existing schema4 chain actually COMMITs.
    let migration_plan_inventory = super::migration_plan::scan_plans(scan)?;
    used.extend(migration_plan_inventory.used.iter().cloned());
    let mut migration_plans = Vec::new();
    for plan in &migration_plan_inventory.records {
        let i = &plan.retirement;
        let recovery = handoff::scan_owner_recoveries(scan)?;
        if let Some(c) = recovery
            .records
            .iter()
            .find(|r| r.intent.transaction_id == i.transaction_id)
            && !plan.matches_recovery(&c.intent)
        {
            return Err(JournalError::Conflict);
        }
        if let Some(r) = handoff_inventory
            .native_records
            .iter()
            .find(|r| r.intent.transaction_id == i.transaction_id)
            && (!plan.complete()
                || r.intent != *i
                || r.observation().intent_sha256 != Sha256Digest::of_bytes(plan.retirement_raw()))
        {
            return Err(JournalError::Conflict);
        }
        let cutover = cutover_inventory
            .native_records
            .iter()
            .find(|c| c.intent.transaction_id == i.transaction_id);
        if let Some(c) = cutover {
            plan.validate_cutover(c)?;
        }
        let resolved = cutover
            .is_some_and(|c| c.intent.schema == 4 && c.last_stage == DurableStage::Committed);
        if ids.contains(&i.transaction_id) {
            // Existing C/retirement must be the exact continuation checked above,
            // never a pure transaction or Linux-v1 record with a matching id.
            if !sequences.contains(&i.sequence)
                || transactions
                    .iter()
                    .any(|t| t.intent.transaction_id == i.transaction_id)
                || handoff_inventory
                    .records
                    .iter()
                    .any(|r| r.intent.transaction_id == i.transaction_id)
            {
                return Err(JournalError::Conflict);
            }
        } else {
            if !ids.insert(i.transaction_id.clone())
                || !sequences.insert(i.sequence)
                || !handoff_inventory.records.is_empty()
                || !handoff_inventory.native_records.is_empty()
                || !owner_recoveries.is_empty()
            {
                return Err(JournalError::Conflict);
            }
        }
        if transactions.iter().any(|t| {
            t.intent.sequence == i.sequence
                || (t.intent.sequence > i.sequence && !resolved)
                || (t.intent.sequence < i.sequence
                    && t.phase_receipts
                        .last()
                        .is_none_or(|p| p.stage != DurableStage::Committed))
        }) || transactions
            .iter()
            .rfind(|t| t.intent.sequence < i.sequence)
            .is_some_and(|t| t.intent.target_state_sha256 != i.before_state_sha256)
        {
            return Err(JournalError::Conflict);
        }
        high_water = high_water.max(i.sequence);
        migration_plans.push((i.transaction_id.clone(), i.sequence, resolved));
    }
    for (index, tx) in transactions.iter().enumerate() {
        let committed = tx
            .phase_receipts
            .last()
            .is_some_and(|p| p.stage == DurableStage::Committed);
        if !committed && index + 1 != transactions.len() {
            return Err(JournalError::Conflict);
        }
        let previous = if let Some((_, sequence, _, target)) = completed_anchor {
            if tx.intent.sequence > *sequence
                && (index == 0 || transactions[index - 1].intent.sequence < *sequence)
            {
                Some(*target)
            } else if index > 0 {
                Some(transactions[index - 1].intent.target_state_sha256)
            } else {
                None
            }
        } else if index > 0 {
            Some(transactions[index - 1].intent.target_state_sha256)
        } else {
            None
        };
        if previous.is_some_and(|hash| hash != tx.intent.before_state_sha256) {
            return Err(JournalError::Conflict);
        }
    }
    Ok(ManagementInventory {
        high_water,
        committed_cutover_anchor: completed_anchor
            .filter(|(id, seq, _, _)| {
                let legacy = completed_legacy_anchor.is_some()
                    && cutover_inventory.records.len() == 1
                    && cutover_inventory.native_records.is_empty()
                    && handoff_inventory.records.len() == 1
                    && handoff_inventory.native_records.is_empty()
                    && owner_recoveries.is_empty()
                    && migration_plans.is_empty();
                let native = completed_native_anchor.is_some()
                    && handoff_inventory.records.is_empty()
                    && handoff_inventory.native_records.len() == 1
                    && owner_recoveries.len() == 1
                    && owner_recoveries.iter().all(|(rid, rseq, stage)| {
                        rid == id
                            && rseq == seq
                            && *stage == Some(handoff::OwnerRecoveryStage::GuardsHeld)
                    });
                legacy || native
            })
            .map(|(_, seq, _, target)| (*seq, *target)),
        transactions,
        migration_plans,
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "macos",
            target_os = "windows"
        ))]
        owner_recoveries,
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "macos",
            target_os = "windows"
        ))]
        handoffs: handoff_inventory
            .observations()
            .map(|(observation, _)| observation)
            .collect(),
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
