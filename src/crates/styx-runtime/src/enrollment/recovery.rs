//! Trusted boot adapter. It never treats an empty/missing journal as a fresh
//! profile, never auto-commits an unresolved intent and never closes a Host lane.
//! Returned state is bootstrap-only: typed profile/crypto and prior transport
//! owner reconciliation are separate prerequisites to network publication.
use crate::store::enrollment::{
    CommittedReceipt, EnrollmentJournal, IntentBinding, JournalError, MaterialKind, MaterialRef,
    PreparedReceipt,
};
use serde::{Serialize, de::DeserializeOwned};
use std::collections::{BTreeMap, BTreeSet};
use styx_contracts::{
    enrollment::{self as contract, IntentBody},
    identity::{GatewayEpoch, Sha256Digest, TransactionId},
};
use styx_core::enrollment::{EnrollmentControl, EnrollmentError, EnrollmentLedger, Limits};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(super) enum RecoveryBlocked {
    #[error("protected enrollment inventory could not be proven")]
    Store(#[from] JournalError),
    #[error("enrollment journal has an unknown or temporary entry")]
    UnknownEntry,
    #[error("enrollment journal record is invalid or incomplete")]
    InvalidRecord,
    #[error("enrollment journal has conflicting identities or revision chain")]
    ConflictingChain,
    #[error("enrollment journal has multiple or out-of-order unresolved intents")]
    UnresolvedInventory,
    #[error("durable enrollment clock floor is missing or behind recorded facts")]
    ClockUnproven,
    #[error("trusted current time is behind the durable enrollment clock floor")]
    ClockRollback,
    #[error("enrollment namespace changed during recovery")]
    InventoryChanged,
    #[error("Core refused historical enrollment facts ({0:?})")]
    Core(EnrollmentError),
}
impl From<EnrollmentError> for RecoveryBlocked {
    fn from(value: EnrollmentError) -> Self {
        Self::Core(value)
    }
}
type Result<T> = std::result::Result<T, RecoveryBlocked>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UnresolvedKind {
    IntentOnly,
    PreparedOnly,
}
#[derive(Debug)]
pub(super) struct InventoryFacts {
    pub head: Option<Sha256Digest>,
    pub revision: u64,
    /// Only identities observable in verified journal records. A never-written
    /// in-memory abort cannot be recovered; a fresh epoch prevents ID reuse.
    pub sequence_high_water: u64,
    pub unresolved: Option<Sha256Digest>,
    pub unresolved_kind: Option<UnresolvedKind>,
    pub clock_floor: u64,
    pub transaction_files: usize,
    pub material_files: usize,
    pub unreferenced_material_files: usize,
}
/// Not Serialize and not public outside the trusted bootstrap module. A finished
/// Core recovery phase does not itself prove profile semantics or network ready.
pub(super) struct RecoveredEnrollment {
    pub ledger: EnrollmentLedger,
    pub control: EnrollmentControl,
    pub facts: InventoryFacts,
}

struct OriginalIntent {
    file: usize,
    body: IntentBody,
    digest: Sha256Digest,
}
struct Receipt<T> {
    file: usize,
    value: T,
}
#[derive(Default)]
struct Transaction {
    intent: Option<OriginalIntent>,
    prepared: Option<Receipt<PreparedReceipt>>,
    committed: Option<Receipt<CommittedReceipt>>,
}
fn invalid<T>(_: T) -> RecoveryBlocked {
    RecoveryBlocked::InvalidRecord
}
fn receipt<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T> {
    let value: T = serde_json::from_slice(bytes).map_err(invalid)?;
    // Receipts have a canonical schema-1 byte representation. Check the exact
    // original before using its raw hash as a predecessor. Intents are NEVER
    // reserialized here, including for a historical epoch.
    if serde_json::to_vec(&value).map_err(invalid)? != bytes {
        return Err(RecoveryBlocked::InvalidRecord);
    }
    Ok(value)
}
fn record_name(id: &TransactionId, suffix: &str) -> String {
    format!("txn-{}.{suffix}", id.as_str())
}
fn material_name(reference: &MaterialRef) -> String {
    let role = match reference.kind {
        MaterialKind::Profile => "profile",
        MaterialKind::Token => "token",
        MaterialKind::Sealed => "sealed",
    };
    format!("{role}-{}.material", reference.digest.to_hex())
}
fn material_reference(name: &str) -> Option<MaterialRef> {
    let raw = name.strip_suffix(".material")?;
    let (role, digest) = raw.split_once('-')?;
    let kind = match role {
        "profile" => MaterialKind::Profile,
        "token" => MaterialKind::Token,
        "sealed" => MaterialKind::Sealed,
        _ => return None,
    };
    Some(MaterialRef {
        kind,
        digest: Sha256Digest::try_from(digest.to_owned()).ok()?,
    })
}
fn binding(intent: &OriginalIntent, previous: Option<Sha256Digest>) -> IntentBinding {
    IntentBinding {
        transaction: intent.body.transaction.clone(),
        epoch: intent.body.gateway_epoch.clone(),
        sequence: intent.body.sequence,
        expected_revision: intent.body.expected_revision,
        previous_commit: previous,
        intent_digest: intent.digest,
        required_materials: intent.body.required_materials.clone(),
    }
}
fn verify_binding(intent: &OriginalIntent, actual: &IntentBinding) -> Result<()> {
    if binding(intent, actual.previous_commit) != *actual {
        return Err(RecoveryBlocked::InvalidRecord);
    }
    let mut refs = BTreeSet::new();
    for r in &actual.required_materials {
        if !refs.insert((r.kind, r.digest.to_hex())) {
            return Err(RecoveryBlocked::InvalidRecord);
        }
    }
    Ok(())
}

/// `trusted_now` comes from the trusted runtime clock, never request metadata.
/// This adapter requires an existing floor even for a zero-record namespace;
/// only the parent bootstrap may prove a truly fresh native store and initialize
/// its floor before calling. Unknown orphans/temporary files block, never skip.
pub(super) fn recover_journal(
    journal: &mut EnrollmentJournal<'_>,
    epoch: GatewayEpoch,
    limits: Limits,
    trusted_now: u64,
) -> Result<RecoveredEnrollment> {
    let observed = journal.scan()?;
    let floor = journal
        .read_time_floor()?
        .ok_or(RecoveryBlocked::ClockUnproven)?;
    if trusted_now < floor {
        return Err(RecoveryBlocked::ClockRollback);
    }
    let mut manifest = BTreeMap::new();
    let mut transactions: BTreeMap<TransactionId, Transaction> = BTreeMap::new();
    let mut materials = BTreeMap::new();
    let mut clock_seen = false;
    let mut transaction_files = 0;
    for (index, file) in observed.files.iter().enumerate() {
        if manifest
            .insert(file.name.clone(), Sha256Digest::of_bytes(file.bytes()))
            .is_some()
        {
            return Err(RecoveryBlocked::ConflictingChain);
        }
        if file.name == "clock.floor" {
            if clock_seen || file.bytes() != floor.to_be_bytes() {
                return Err(RecoveryBlocked::ClockUnproven);
            }
            clock_seen = true;
            continue;
        }
        if let Some(reference) = material_reference(&file.name) {
            if material_name(&reference) != file.name
                || Sha256Digest::of_bytes(file.bytes()) != reference.digest
            {
                return Err(RecoveryBlocked::InvalidRecord);
            }
            // Existing store reader supplies per-role bounds, protected-file
            // identity/mode/link checks and exact content-reference validation.
            if journal.read_material(&reference)? != file.bytes() {
                return Err(RecoveryBlocked::InventoryChanged);
            }
            materials.insert(file.name.clone(), reference);
            continue;
        }
        let Some(raw) = file.name.strip_prefix("txn-") else {
            return Err(RecoveryBlocked::UnknownEntry);
        };
        let Some((id, suffix)) = raw.rsplit_once('.') else {
            return Err(RecoveryBlocked::UnknownEntry);
        };
        let id = TransactionId::try_from(id.to_owned()).map_err(invalid)?;
        if record_name(&id, suffix) != file.name {
            return Err(RecoveryBlocked::InvalidRecord);
        }
        let transaction = transactions.entry(id.clone()).or_default();
        transaction_files += 1;
        match suffix {
            "intent" => {
                if transaction.intent.is_some() {
                    return Err(RecoveryBlocked::ConflictingChain);
                }
                let body = contract::decode(file.bytes()).map_err(invalid)?;
                if body.transaction != id {
                    return Err(RecoveryBlocked::InvalidRecord);
                }
                transaction.intent = Some(OriginalIntent {
                    file: index,
                    body,
                    digest: Sha256Digest::of_bytes(file.bytes()),
                });
            }
            "prepared" => {
                let value: PreparedReceipt = receipt(file.bytes())?;
                if value.schema != 1 || value.binding.transaction != id {
                    return Err(RecoveryBlocked::InvalidRecord);
                }
                transaction.prepared = Some(Receipt { file: index, value });
            }
            "committed" => {
                let value: CommittedReceipt = receipt(file.bytes())?;
                if value.schema != 1 || value.binding.transaction != id {
                    return Err(RecoveryBlocked::InvalidRecord);
                }
                transaction.committed = Some(Receipt { file: index, value });
            }
            _ => return Err(RecoveryBlocked::UnknownEntry),
        }
    }
    if !clock_seen {
        return Err(RecoveryBlocked::ClockUnproven);
    }
    let mut sequences = BTreeSet::new();
    let mut referenced = BTreeSet::new();
    let mut commits = Vec::new();
    let mut unresolved = Vec::new();
    let mut high_water = 0;
    let mut highest_time = 0;
    for (id, transaction) in &transactions {
        let intent = transaction
            .intent
            .as_ref()
            .ok_or(RecoveryBlocked::InvalidRecord)?;
        if !sequences.insert(intent.body.sequence) {
            return Err(RecoveryBlocked::ConflictingChain);
        }
        high_water = high_water.max(intent.body.sequence);
        highest_time = highest_time.max(intent.body.prepared_at);
        for reference in &intent.body.required_materials {
            let name = material_name(reference);
            if materials.get(&name) != Some(reference) {
                return Err(RecoveryBlocked::InvalidRecord);
            }
            referenced.insert(name);
        }
        if let Some(prepared) = &transaction.prepared {
            verify_binding(intent, &prepared.value.binding)?;
        }
        if let Some(committed) = &transaction.committed {
            let prepared = transaction
                .prepared
                .as_ref()
                .ok_or(RecoveryBlocked::InvalidRecord)?;
            if committed.value.binding != prepared.value.binding
                || committed.value.prepared_digest
                    != Sha256Digest::of_bytes(observed.files[prepared.file].bytes())
            {
                return Err(RecoveryBlocked::InvalidRecord);
            }
            commits.push((intent.body.sequence, id, transaction));
        } else {
            unresolved.push((id, transaction));
        }
    }
    if floor < highest_time {
        return Err(RecoveryBlocked::ClockUnproven);
    }
    if unresolved.len() > 1 {
        return Err(RecoveryBlocked::UnresolvedInventory);
    }
    commits.sort_by_key(|entry| entry.0);
    let mut head = None;
    let mut revision = 0u64;
    let mut last_sequence = 0;
    let (mut ledger, control) = EnrollmentLedger::new_recovering(epoch, limits)?;
    for (sequence, id, transaction) in commits {
        let intent = transaction
            .intent
            .as_ref()
            .ok_or(RecoveryBlocked::InvalidRecord)?;
        let committed = transaction
            .committed
            .as_ref()
            .ok_or(RecoveryBlocked::InvalidRecord)?;
        if sequence <= last_sequence
            || committed.value.binding.expected_revision != revision
            || committed.value.binding.previous_commit != head
        {
            return Err(RecoveryBlocked::ConflictingChain);
        }
        // Sole existing durability mechanism. Reconcile exact already-present
        // marker; never call commit to promote a prepared-only transaction.
        if journal.reconcile(id)? != Some(committed.value.clone()) {
            return Err(RecoveryBlocked::InventoryChanged);
        }
        let digest = Sha256Digest::of_bytes(observed.files[committed.file].bytes());
        let fact = control.attest_recovery_record(
            observed.files[intent.file].bytes(),
            intent.digest,
            head,
            digest,
        )?;
        ledger.recover_committed(fact)?;
        revision = revision
            .checked_add(1)
            .ok_or(RecoveryBlocked::ConflictingChain)?;
        last_sequence = sequence;
        head = Some(digest);
    }
    let mut unresolved_digest = None;
    let mut unresolved_kind = None;
    if let Some((id, transaction)) = unresolved.first() {
        let intent = transaction
            .intent
            .as_ref()
            .ok_or(RecoveryBlocked::InvalidRecord)?;
        if intent.body.sequence <= last_sequence
            || intent.body.expected_revision != revision
            || transaction
                .prepared
                .as_ref()
                .is_some_and(|p| p.value.binding.previous_commit != head)
        {
            return Err(RecoveryBlocked::UnresolvedInventory);
        }
        // This store port syncs ONLY existing exact intent/prepared records and
        // confirms no commit; it must never create a missing prepared marker.
        journal.preserve_unresolved(id)?;
        let fact = control
            .attest_recovery_unresolved(observed.files[intent.file].bytes(), intent.digest)?;
        ledger.recover_unresolved(fact)?;
        unresolved_digest = Some(intent.digest);
        unresolved_kind = Some(if transaction.prepared.is_some() {
            UnresolvedKind::PreparedOnly
        } else {
            UnresolvedKind::IntentOnly
        });
    }
    // Advance the actual durable floor BEFORE exposing the recovered Core.
    journal.record_time_floor(trusted_now)?;
    manifest.insert(
        "clock.floor".into(),
        Sha256Digest::of_bytes(&trusted_now.to_be_bytes()),
    );
    let after = journal.scan()?;
    let final_manifest: BTreeMap<_, _> = after
        .files
        .iter()
        .map(|f| (f.name.clone(), Sha256Digest::of_bytes(f.bytes())))
        .collect();
    if final_manifest != manifest || journal.read_time_floor()? != Some(trusted_now) {
        return Err(RecoveryBlocked::InventoryChanged);
    }
    let closure = control.attest_recovery_closure(
        revision,
        high_water,
        head,
        unresolved_digest,
        trusted_now,
        trusted_now,
    );
    ledger.finish_recovery(closure)?;
    Ok(RecoveredEnrollment {
        ledger,
        control,
        facts: InventoryFacts {
            head,
            revision,
            sequence_high_water: high_water,
            unresolved: unresolved_digest,
            unresolved_kind,
            clock_floor: trusted_now,
            transaction_files,
            material_files: materials.len(),
            unreferenced_material_files: materials.len() - referenced.len(),
        },
    })
}

#[cfg(test)]
#[path = "recovery_tests.rs"]
mod tests;
