//! Same-transaction PRE-EFFECT inputs. These bytes are DATA, never settlement,
//! candidate verification, Prepared authority, or permission to release a fence.
use super::*;
use crate::store::secure_journal::JournalObservation;
#[cfg(any(target_os = "macos", target_os = "windows", test))]
use crate::store::secure_journal::{ObservedJournalFile, files};
use handoff::{NativeRetirementIntent, ProofRoot, ProofStamp};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::collections::BTreeSet;
use styx_contracts::native_management::*;

const HEADER_LIMIT: usize = 64 * 1024;
const MATERIAL_LIMIT: usize = 1024 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MaterialBinding {
    sha256: Sha256Digest,
    bytes: usize,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PlanKind {
    NativeHostMigrationPlan,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanHeader {
    schema: u16,
    kind: PlanKind,
    // RawValue preserves the ORIGINAL selected producer bytes, including any
    // original JSON whitespace. These are not re-encoded to replace a predecessor.
    retirement: Box<RawValue>,
    host_pair: Box<RawValue>,
    desired: Box<RawValue>,
    marker: Box<RawValue>,
    runtime_selection: Box<RawValue>,
    owner_recovery: Option<Box<RawValue>>,
    before: MaterialBinding,
    preservation: MaterialBinding,
    selected: MaterialBinding,
}
/// No Debug/Clone/Serde: no credential bytes belong in this input or header.
/// Random marker generation must happen ONCE, before this immutable header.
/// On restart missing attachments may only be supplied with these exact hashes.
#[cfg(any(target_os = "macos", target_os = "windows", test))]
pub(in crate::store) struct MigrationPlanInputs {
    pub retirement: Vec<u8>,
    pub host_pair: Vec<u8>,
    pub desired: Vec<u8>,
    pub marker: Vec<u8>,
    pub runtime_selection: Vec<u8>,
    pub owner_recovery: Option<Vec<u8>>,
    pub before: Vec<u8>,
    pub preservation: Vec<u8>,
    pub selected: Vec<u8>,
}
/// A parsed observation. It has no owner or phase authority. Missing attachments
/// are a known unfinished plan, not permission to start ANY source-file effect.
pub(in crate::store) struct OriginalMigrationPlan {
    pub retirement: NativeRetirementIntent,
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    pub pair: NativePreservedHostPair,
    pub desired: NativeDesired,
    pub marker: NativeRootMarker,
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    pub selection: NativeRuntimeSelection,
    #[cfg(any(target_os = "macos", target_os = "windows", test))]
    pub raw_header: Vec<u8>,
    header: PlanHeader,
    pub before: Option<Vec<u8>>,
    pub preservation: Option<Vec<u8>>,
    pub selected: Option<Vec<u8>>,
}
impl OriginalMigrationPlan {
    pub(in crate::store) fn owner_recovery_inputs(
        &self,
    ) -> JournalResult<Option<handoff::OwnerRecoveryPlan>> {
        self.header
            .owner_recovery
            .as_ref()
            .map(|raw| serde_json::from_str(raw.get()).map_err(|_| JournalError::Conflict))
            .transpose()
    }
    pub(in crate::store) fn complete(&self) -> bool {
        self.before.is_some() && self.preservation.is_some() && self.selected.is_some()
    }
    pub(in crate::store) fn retirement_raw(&self) -> &[u8] {
        self.header.retirement.get().as_bytes()
    }
    pub(in crate::store) fn pair_raw(&self) -> &[u8] {
        self.header.host_pair.get().as_bytes()
    }
    pub(in crate::store) fn marker_raw(&self) -> &[u8] {
        self.header.marker.get().as_bytes()
    }
    pub(in crate::store) fn selection_raw(&self) -> &[u8] {
        self.header.runtime_selection.get().as_bytes()
    }
    pub(in crate::store) fn matches_recovery(
        &self,
        r: &handoff::LegacyOwnerRecoveryIntent,
    ) -> bool {
        self.complete()
            && self.owner_recovery_inputs().is_ok_and(|saved| {
                saved.is_none_or(|p| p.validated_intent().is_ok_and(|intent| intent == *r))
            })
            && r.transaction_id == self.retirement.transaction_id
            && r.sequence == self.retirement.sequence
            && r.config_root == self.retirement.config_root
            && r.deployment_raw_sha256 == self.retirement.deployment_raw_sha256
            && r.before_state_sha256 == self.retirement.before_state_sha256
            && r.candidate_manifest_sha256 == self.retirement.candidate_manifest_sha256
            && r.publisher_spki_sha256 == self.retirement.publisher_spki_sha256
            && r.successor_retirement_intent_sha256 == Sha256Digest::of_bytes(self.retirement_raw())
    }
    pub(in crate::store) fn validate_cutover(
        &self,
        c: &cutover::OriginalCutover<NativeRootIdentity>,
    ) -> JournalResult<()> {
        if !self.complete()
            || c.intent.schema != 4
            || c.intent.transaction_id != self.retirement.transaction_id
            || c.intent.sequence != self.retirement.sequence
            || c.marker != self.marker_raw()
            || c.before.as_slice() != self.before.as_deref().ok_or(JournalError::Conflict)?
            || c.preservation.as_slice()
                != self.preservation.as_deref().ok_or(JournalError::Conflict)?
            || c.host_pair.as_deref() != Some(self.pair_raw())
        {
            return Err(JournalError::Conflict);
        }
        let target = crate::store::native_state::decode_state(&c.target, &self.marker)
            .map_err(|_| JournalError::Conflict)?;
        if target.state().desired != self.desired
            || target
                .state()
                .extensions
                .get("runtime_selection_v1")
                .map(|r| r.get().as_bytes())
                != Some(self.selection_raw())
        {
            return Err(JournalError::Conflict);
        }
        Ok(())
    }
}
pub(in crate::store) struct MigrationPlanInventory {
    pub used: BTreeSet<String>,
    pub records: Vec<OriginalMigrationPlan>,
}
#[cfg(any(target_os = "macos", target_os = "windows", test))]
fn actual_root(root: crate::store::RootIdentity) -> JournalResult<NativeRootIdentity> {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        let crate::store::RootIdentity::Linux { device, inode, uid } = root;
        Ok(NativeRootIdentity::Linux { device, inode, uid })
    }
    #[cfg(target_os = "macos")]
    {
        match root {
            crate::store::RootIdentity::Macos { device, inode, uid } => {
                Ok(NativeRootIdentity::Macos { device, inode, uid })
            }
            _ => Err(JournalError::Conflict),
        }
    }
    #[cfg(target_os = "windows")]
    {
        match root {
            crate::store::RootIdentity::Windows {
                volume_serial,
                file_id,
                owner_sid,
            } => Ok(NativeRootIdentity::Windows {
                volume_serial,
                file_id,
                owner_sid,
            }),
            _ => Err(JournalError::Conflict),
        }
    }
}
fn names(id: &TransactionId) -> [String; 4] {
    let p = format!("txn-{}.native-migration-plan", id.as_str());
    [
        p.clone(),
        format!("{p}-before"),
        format!("{p}-preservation"),
        format!("{p}-selected"),
    ]
}
#[cfg(any(target_os = "macos", target_os = "windows", test))]
fn raw(bytes: &[u8]) -> JournalResult<Box<RawValue>> {
    serde_json::from_slice(bytes).map_err(|_| JournalError::InvalidInput)
}
#[cfg(any(target_os = "macos", target_os = "windows", test))]
fn binding(bytes: &[u8]) -> JournalResult<MaterialBinding> {
    if bytes.is_empty() || bytes.len() > MATERIAL_LIMIT {
        return Err(JournalError::BudgetExceeded);
    }
    Ok(MaterialBinding {
        sha256: Sha256Digest::of_bytes(bytes),
        bytes: bytes.len(),
    })
}
#[cfg(any(target_os = "macos", target_os = "windows", test))]
fn encode(input: &MigrationPlanInputs) -> JournalResult<Vec<u8>> {
    let header = PlanHeader {
        schema: 1,
        kind: PlanKind::NativeHostMigrationPlan,
        retirement: raw(&input.retirement)?,
        host_pair: raw(&input.host_pair)?,
        desired: raw(&input.desired)?,
        marker: raw(&input.marker)?,
        runtime_selection: raw(&input.runtime_selection)?,
        owner_recovery: input.owner_recovery.as_ref().map(|b| raw(b)).transpose()?,
        before: binding(&input.before)?,
        preservation: binding(&input.preservation)?,
        selected: binding(&input.selected)?,
    };
    let bytes = serde_json::to_vec(&header).map_err(|_| JournalError::InvalidInput)?;
    if bytes.len() > HEADER_LIMIT {
        return Err(JournalError::BudgetExceeded);
    }
    Ok(bytes)
}
fn parse(bytes: &[u8]) -> JournalResult<OriginalMigrationPlan> {
    if bytes.len() > HEADER_LIMIT {
        return Err(JournalError::BudgetExceeded);
    }
    let h: PlanHeader = serde_json::from_slice(bytes).map_err(|_| JournalError::Conflict)?;
    let i: NativeRetirementIntent =
        serde_json::from_str(h.retirement.get()).map_err(|_| JournalError::Conflict)?;
    let pair: NativePreservedHostPair =
        serde_json::from_str(h.host_pair.get()).map_err(|_| JournalError::Conflict)?;
    let desired: NativeDesired =
        serde_json::from_str(h.desired.get()).map_err(|_| JournalError::Conflict)?;
    let marker: NativeRootMarker =
        serde_json::from_str(h.marker.get()).map_err(|_| JournalError::Conflict)?;
    let selection: NativeRuntimeSelection =
        serde_json::from_str(h.runtime_selection.get()).map_err(|_| JournalError::Conflict)?;
    if h.schema != 1
        || i.schema != 3
        || i.sequence == 0
        || !i.config_root.valid_pair(&i.host_root)
        || !i.config_root.valid_pair(&selection.payload_root)
        || !i.original_token.valid_for(&i.host_root)
        || pair.schema != 1
        || pair.transaction_id != i.transaction_id
        || pair.config_root != i.config_root
        || pair.host_root != i.host_root
        || pair.deployment_raw_sha256 != i.deployment_raw_sha256
        || pair.credential_sha256 != i.original_token.content_sha256()
        || pair.preservation_sha256 != h.preservation.sha256
        || i.preservation_sha256 != h.selected.sha256
        || i.before_state_sha256 != h.before.sha256
        || marker.root_identity != i.config_root
        || marker.reader_floor != styx_contracts::management::ReaderContract::NativeMigratedStateV2
        || styx_core::management::state::validate_marker(&marker).is_err()
        || selection.schema != 1
        || !std::path::Path::new(&selection.payload_path).is_absolute()
        || !std::path::Path::new(&selection.publisher_file).is_absolute()
        || selection.manifest_sha256 != i.candidate_manifest_sha256
        || selection.publisher_spki_sha256 != i.publisher_spki_sha256
        || desired.gateway.is_some()
        || desired.host.as_ref().is_none_or(|h| {
            h.autostart != NativeAutostartDesired::Disabled
                || h.manager == NativeManager::PersistentService
        })
        || [&h.before, &h.preservation, &h.selected]
            .iter()
            .any(|b| b.bytes == 0 || b.bytes > MATERIAL_LIMIT)
    {
        return Err(JournalError::Conflict);
    }
    if let Some(saved) = &h.owner_recovery {
        let inputs: handoff::OwnerRecoveryPlan =
            serde_json::from_str(saved.get()).map_err(|_| JournalError::Conflict)?;
        let c = inputs.validated_intent()?;
        if c.transaction_id != i.transaction_id
            || c.sequence != i.sequence
            || c.config_root != i.config_root
            || c.deployment_raw_sha256 != i.deployment_raw_sha256
            || c.before_state_sha256 != i.before_state_sha256
            || c.candidate_manifest_sha256 != i.candidate_manifest_sha256
            || c.publisher_spki_sha256 != i.publisher_spki_sha256
            || c.successor_retirement_intent_sha256
                != Sha256Digest::of_bytes(h.retirement.get().as_bytes())
        {
            return Err(JournalError::Conflict);
        }
    } else if matches!(i.config_root, NativeRootIdentity::Macos { .. }) {
        return Err(JournalError::Conflict);
    }
    Ok(OriginalMigrationPlan {
        retirement: i,
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        pair,
        desired,
        marker,
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        selection,
        #[cfg(any(target_os = "macos", target_os = "windows", test))]
        raw_header: bytes.to_vec(),
        header: h,
        before: None,
        preservation: None,
        selected: None,
    })
}
/// Pure scanner. Header first means a power interruption before attachments is
/// visible/unfinished with the ORIGINAL random marker/desired/candidate intact.
pub(in crate::store) fn scan_plans(
    scan: &JournalObservation,
) -> JournalResult<MigrationPlanInventory> {
    let mut used = BTreeSet::new();
    let mut records = Vec::new();
    for file in &scan.files {
        if !file.name.ends_with(".native-migration-plan") {
            continue;
        }
        if !records.is_empty() {
            return Err(JournalError::Conflict);
        }
        let mut p = parse(file.bytes())?;
        let n = names(&p.retirement.transaction_id);
        if file.name != n[0] {
            return Err(JournalError::Conflict);
        }
        used.insert(n[0].clone());
        let mut attachments = Vec::new();
        for (name, b) in
            n[1..]
                .iter()
                .zip([&p.header.before, &p.header.preservation, &p.header.selected])
        {
            let actual = scan
                .files
                .iter()
                .filter(|f| &f.name == name)
                .collect::<Vec<_>>();
            if actual.len() > 1 {
                return Err(JournalError::Conflict);
            }
            let bytes = if let Some(f) = actual.first() {
                if f.bytes().len() != b.bytes || Sha256Digest::of_bytes(f.bytes()) != b.sha256 {
                    return Err(JournalError::Conflict);
                }
                used.insert(name.clone());
                Some(f.bytes().to_vec())
            } else {
                None
            };
            attachments.push(bytes);
        }
        p.before = attachments.remove(0);
        p.preservation = attachments.remove(0);
        p.selected = attachments.remove(0);
        if let Some(before) = &p.before {
            handoff::reject_migration_v2_collision(before)?;
        }
        records.push(p);
    }
    Ok(MigrationPlanInventory { used, records })
}
/// Only for FIRST C preparation. Drop this exact complete plan from a baseline
/// inventory AFTER checking its original successor hash. No other names disappear.
#[cfg(any(target_os = "macos", target_os = "windows", test))]
pub(in crate::store) fn recovery_baseline(
    scan: &JournalObservation,
    intent: &handoff::LegacyOwnerRecoveryIntent,
    entries: &[(String, Vec<u8>)],
) -> JournalResult<Option<JournalObservation>> {
    let plans = scan_plans(scan)?;
    if plans.records.is_empty() {
        return Ok(None);
    }
    if !plans.records[0].matches_recovery(intent) {
        return Err(JournalError::Conflict);
    }
    let mut used = plans.used;
    if plans.records[0].owner_recovery_inputs()?.is_some() {
        // Only exact original preparation bytes may be resynced. Later phases
        // or unrecognized names stay in the baseline and refuse fresh prepare.
        for file in &scan.files {
            if let Some((_, raw)) = entries.iter().find(|(name, _)| name == &file.name) {
                if file.bytes() != raw {
                    return Err(JournalError::Conflict);
                }
                used.insert(file.name.clone());
            }
        }
    }
    Ok(Some(without(scan, &used)))
}
#[cfg(any(target_os = "macos", target_os = "windows", test))]
fn without(scan: &JournalObservation, names: &BTreeSet<String>) -> JournalObservation {
    let files: Vec<_> = scan
        .files
        .iter()
        .filter(|f| !names.contains(&f.name))
        .map(|f| ObservedJournalFile {
            name: f.name.clone(),
            bytes: f.bytes().to_vec(),
        })
        .collect();
    JournalObservation {
        total_bytes: files.iter().map(|f| f.bytes().len()).sum(),
        files,
    }
}
#[cfg(any(target_os = "macos", target_os = "windows", test))]
pub(in crate::store) fn retirement_continuation(
    scan: &JournalObservation,
    intent: &NativeRetirementIntent,
    raw: &[u8],
) -> JournalResult<bool> {
    let plans = scan_plans(scan)?;
    Ok(plans
        .records
        .first()
        .is_some_and(|p| p.complete() && p.retirement == *intent && p.retirement_raw() == raw))
}
#[cfg(any(target_os = "macos", target_os = "windows", test))]
impl OwnedManagementJournal {
    /// Full input budget and immutable header precede any SOURCE mutation. A
    /// partial plan can only fill exact missing attachments; changing even the
    /// saved random marker/desired is a conflict, not a new migration attempt.
    pub(in crate::store) fn persist_native_migration_plan(
        &mut self,
        maintenance: &ConfigurationMaintenance,
        input: &MigrationPlanInputs,
    ) -> JournalResult<OriginalMigrationPlan> {
        handoff::reject_migration_v2_collision(&input.before)?;
        let header = encode(input)?;
        let plan = parse(&header)?;
        if maintenance.transaction_id() != &plan.retirement.transaction_id {
            return Err(JournalError::Conflict);
        }
        let n = names(&plan.retirement.transaction_id);
        let entries = [
            (&n[0], header.as_slice()),
            (&n[1], input.before.as_slice()),
            (&n[2], input.preservation.as_slice()),
            (&n[3], input.selected.as_slice()),
        ];
        self.owner.with_maintenance(maintenance, |state| {
            if actual_root(state.root.identity())? != plan.retirement.config_root {
                return Err(JournalError::Conflict);
            }
            for (name, digest) in [
                ("state.json", plan.retirement.before_state_sha256),
                ("deployment.json", plan.retirement.deployment_raw_sha256),
            ] {
                let file = state
                    .root
                    .read_raw(name, MATERIAL_LIMIT)
                    .map_err(|_| JournalError::Unknown)?;
                if Sha256Digest::of_bytes(file.bytes()) != digest {
                    return Err(JournalError::Conflict);
                }
            }
            self.with_directory_locked(state, |dir| {
                let scan = files::scan(dir, self.budget)?;
                let inventory = parser::inventory(&scan)?;
                if !inventory.orphans.is_empty() {
                    return Err(JournalError::Conflict);
                }
                let old = scan_plans(&scan)?;
                if let Some(p) = old.records.first() {
                    if p.raw_header != header {
                        return Err(JournalError::Conflict);
                    }
                } else if inventory.has_legacy_handoffs()
                    || inventory.high_water.checked_add(1) != Some(plan.retirement.sequence)
                    || inventory.transactions.iter().any(|t| {
                        t.phase_receipts
                            .last()
                            .is_none_or(|p| p.stage != DurableStage::Committed)
                    })
                    || inventory.transactions.last().is_some_and(|t| {
                        t.intent.target_state_sha256 != plan.retirement.before_state_sha256
                    })
                {
                    return Err(JournalError::Conflict);
                }
                let mut bytes = scan.total_bytes;
                let mut count = scan.files.len();
                for (name, raw) in entries {
                    if raw.is_empty() || raw.len() > self.budget.max_file_bytes {
                        return Err(JournalError::BudgetExceeded);
                    }
                    if let Some(f) = scan.files.iter().find(|f| &f.name == name) {
                        if f.bytes() != raw {
                            return Err(JournalError::Conflict);
                        }
                    } else {
                        bytes = bytes
                            .checked_add(raw.len())
                            .ok_or(JournalError::BudgetExceeded)?;
                        count = count.checked_add(1).ok_or(JournalError::BudgetExceeded)?;
                    }
                }
                // Each CREATE_NEW immutable temporary occupies the slot of
                // its not-yet-existing final member; these bytes include every
                // final member before the first header is published.
                let extra = bytes
                    .checked_sub(scan.total_bytes)
                    .ok_or(JournalError::BudgetExceeded)?;
                if bytes > self.budget.max_bytes || count > self.budget.max_files {
                    return Err(JournalError::BudgetExceeded);
                }
                state.preflight_growth(extra)?;
                for (name, raw) in entries {
                    files::immutable(dir, name, raw, self.budget, &|_| {})?;
                }
                let after = scan_plans(&files::scan(dir, self.budget)?)?
                    .records
                    .pop()
                    .ok_or(JournalError::Unknown)?;
                if after.raw_header != header || !after.complete() {
                    return Err(JournalError::Unknown);
                }
                Ok(after)
            })
        })
    }
    /// Re-sync existing bytes only. Incomplete plan remains incomplete; no
    /// reconstruction, marker generation, source rename, or authority minting.
    pub(in crate::store) fn resync_native_migration_plan(
        &self,
        maintenance: &ConfigurationMaintenance,
    ) -> JournalResult<OriginalMigrationPlan> {
        self.owner.with_maintenance(maintenance, |state| {
            self.with_directory_locked(state, |dir| {
                let scan = files::scan(dir, self.budget)?;
                let plans = scan_plans(&scan)?;
                let p = plans.records.first().ok_or(JournalError::Conflict)?;
                let inv = match parser::inventory(&scan) {
                    Ok(inv) => inv,
                    Err(_) => {
                        // A partial C preparation cannot be parsed as a full C
                        // chain. Its exact saved header is readable before any
                        // recovery capability can exist. Only those expected
                        // byte-identical preparation members are filtered here;
                        // foreign files and later phases still fail inventory.
                        let c = p.owner_recovery_inputs()?.ok_or(JournalError::Conflict)?;
                        let intent = c.validated_intent()?;
                        let entries = c.preparation_entries()?;
                        let baseline = recovery_baseline(&scan, &intent, &entries)?
                            .ok_or(JournalError::Conflict)?;
                        parser::inventory(&baseline)?
                    }
                };
                if !inv.orphans.is_empty() {
                    return Err(JournalError::Conflict);
                }
                if &p.retirement.transaction_id != maintenance.transaction_id()
                    || p.retirement.config_root != actual_root(state.root.identity())?
                {
                    return Err(JournalError::Conflict);
                }
                for name in &plans.used {
                    files::sync_file(dir, name)?;
                }
                platform::sync_directory(dir)?;
                let after = scan_plans(&files::scan(dir, self.budget)?)?
                    .records
                    .pop()
                    .ok_or(JournalError::Unknown)?;
                if p.raw_header != after.raw_header
                    || p.before != after.before
                    || p.preservation != after.preservation
                    || p.selected != after.selected
                {
                    return Err(JournalError::Unknown);
                }
                Ok(after)
            })
        })
    }
}

#[cfg(all(test, target_os = "linux", target_env = "gnu"))]
#[path = "management_migration_plan_tests.rs"]
mod tests;
