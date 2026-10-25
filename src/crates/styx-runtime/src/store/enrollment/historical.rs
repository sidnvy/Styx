//! Exact versioned historical baseline data under the retained journal writer. These
//! receipts are storage observations, never Core authorization or C07 proof.
use super::*;
use styx_contracts::historical_enrollment::{
    self as historical_contract, HistoricalEnrollmentBaseline, SourceRoot,
};

pub(crate) const HISTORICAL_INTENT: &str = "historical-baseline.intent";
pub(crate) const HISTORICAL_PREPARED: &str = "historical-baseline.prepared";
pub(crate) const HISTORICAL_COMMITTED: &str = "historical-baseline.committed";
const HISTORICAL_FILES: [&str; 3] = [HISTORICAL_INTENT, HISTORICAL_PREPARED, HISTORICAL_COMMITTED];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalPreparedReceipt {
    pub schema: u8,
    pub migration: TransactionId,
    pub enrollment_root: SourceRoot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub journal_root: Option<SourceRoot>,
    pub baseline_digest: Sha256Digest,
    pub sequence: u64,
    pub expected_revision: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalCommittedReceipt {
    pub schema: u8,
    pub prepared: HistoricalPreparedReceipt,
    pub prepared_digest: Sha256Digest,
}
impl HistoricalCommittedReceipt {
    pub fn digest(&self) -> JournalResult<Sha256Digest> {
        encode(self).map(|raw| Sha256Digest::of_bytes(&raw))
    }
}
/// Raw baseline/material contents must never be logged. A missing phase is
/// unresolved, not an instruction to create it or replay enrollment.
pub struct HistoricalObservation {
    pub body: HistoricalEnrollmentBaseline,
    pub original_bytes: Vec<u8>,
    pub digest: Sha256Digest,
    pub prepared: Option<HistoricalPreparedReceipt>,
    pub committed: Option<HistoricalCommittedReceipt>,
}
fn prepared_for(
    body: &HistoricalEnrollmentBaseline,
    digest: Sha256Digest,
) -> HistoricalPreparedReceipt {
    HistoricalPreparedReceipt {
        schema: body.schema,
        migration: body.migration.clone(),
        enrollment_root: body.enrollment_root.clone(),
        journal_root: body.journal_root.clone(),
        baseline_digest: digest,
        sequence: body.sequence,
        expected_revision: body.expected_revision,
    }
}
fn committed_for(
    prepared: &HistoricalPreparedReceipt,
) -> JournalResult<HistoricalCommittedReceipt> {
    Ok(HistoricalCommittedReceipt {
        schema: prepared.schema,
        prepared: prepared.clone(),
        prepared_digest: Sha256Digest::of_bytes(&encode(prepared)?),
    })
}
impl EnrollmentJournal<'_> {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    pub(crate) fn root_identity(&self) -> JournalResult<crate::store::RootIdentity> {
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        {
            Ok(self.root.identity())
        }
        #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
        {
            Err(JournalError::Unsupported)
        }
    }
    /// Validate the WHOLE selected bundle before the first material write. An
    /// old transaction or unrelated material is not an empty migration target.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    pub(crate) fn preflight_historical_bundle(
        &self,
        baseline: &[u8],
        materials: &[(MaterialRef, zeroize::Zeroizing<Vec<u8>>)],
    ) -> JournalResult<()> {
        let body = historical_contract::decode(baseline).map_err(|_| JournalError::InvalidInput)?;
        self.validate_historical_root(&body)?;
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        if self
            .historical_transaction
            .as_ref()
            .is_some_and(|id| id != &body.migration)
        {
            return Err(JournalError::Conflict);
        }
        let observed = self.scan()?;
        if observed
            .files
            .iter()
            .any(|f| f.name != "clock.floor" || f.bytes().len() != 8)
        {
            return Err(JournalError::Conflict);
        }
        let required: std::collections::BTreeSet<_> =
            body.required_materials.iter().map(material_name).collect();
        if required.len() != body.required_materials.len() || materials.len() != required.len() {
            return Err(JournalError::InvalidInput);
        }
        let mut supplied = std::collections::BTreeSet::new();
        let mut material_bytes = 0usize;
        let mut largest = baseline.len();
        for (reference, bytes) in materials {
            let name = material_name(reference);
            if !required.contains(&name)
                || !supplied.insert(name)
                || bytes.is_empty()
                || bytes.len() > material_limit(reference.kind)
                || Sha256Digest::of_bytes(bytes.as_slice()) != reference.digest
            {
                return Err(JournalError::InvalidInput);
            }
            material_bytes = material_bytes
                .checked_add(bytes.len())
                .ok_or(JournalError::BudgetExceeded)?;
            largest = largest.max(bytes.len());
        }
        let prepared = prepared_for(&body, Sha256Digest::of_bytes(baseline));
        let prepared_bytes = encode(&prepared)?;
        let committed_bytes = encode(&committed_for(&prepared)?)?;
        largest = largest.max(prepared_bytes.len()).max(committed_bytes.len());
        // The trusted producer records the durable floor after this preflight.
        // Account for its fixed file even when the namespace starts empty.
        let new_clock = !observed.files.iter().any(|f| f.name == "clock.floor");
        let projected = observed
            .total_bytes
            .checked_add(if new_clock { 8 } else { 0 })
            .and_then(|n| n.checked_add(material_bytes))
            .and_then(|n| n.checked_add(baseline.len()))
            .and_then(|n| n.checked_add(prepared_bytes.len()))
            .and_then(|n| n.checked_add(committed_bytes.len()))
            .ok_or(JournalError::BudgetExceeded)?;
        let file_count = observed
            .files
            .len()
            .checked_add(usize::from(new_clock))
            .and_then(|n| n.checked_add(materials.len()))
            .and_then(|n| n.checked_add(3))
            .ok_or(JournalError::BudgetExceeded)?;
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        if projected > self.budget.max_bytes
            || file_count > self.budget.max_files
            || largest > self.budget.max_file_bytes
        {
            return Err(JournalError::BudgetExceeded);
        }
        #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
        let _ = (projected, file_count, largest);
        Ok(())
    }
    fn validate_historical_root(&self, body: &HistoricalEnrollmentBaseline) -> JournalResult<()> {
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        {
            let crate::store::RootIdentity::Linux { device, inode, uid } = self.root.identity();
            if body
                .journal_root()
                .map_err(|_| JournalError::InvalidInput)?
                != &(SourceRoot::Linux { device, inode, uid })
            {
                return Err(JournalError::Conflict);
            }
            Ok(())
        }
        #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
        {
            let _ = body;
            Err(JournalError::Unsupported)
        }
    }
    fn historical_materials(
        &self,
        body: &HistoricalEnrollmentBaseline,
    ) -> JournalResult<Vec<String>> {
        let mut names = std::collections::BTreeSet::new();
        for reference in &body.required_materials {
            if !names.insert(material_name(reference)) {
                return Err(JournalError::InvalidInput);
            }
            self.read_material(reference)?;
        }
        Ok(names.into_iter().collect())
    }
    /// First preparation must not absorb a native transaction, unrelated
    /// material, orphan, or an earlier historical attempt. Nothing is deleted.
    fn historical_pristine(
        &self,
        body: &HistoricalEnrollmentBaseline,
        own_phases_allowed: bool,
    ) -> JournalResult<JournalObservation> {
        let material_names = self.historical_materials(body)?;
        let observed = self.scan()?;
        for file in &observed.files {
            if material_names.contains(&file.name)
                || (file.name == "clock.floor" && file.bytes().len() == 8)
                || (own_phases_allowed && HISTORICAL_FILES.contains(&file.name.as_str()))
            {
                continue;
            }
            return Err(JournalError::Conflict);
        }
        Ok(observed)
    }
    pub fn prepare_historical(
        &mut self,
        original_bytes: &[u8],
    ) -> JournalResult<HistoricalPreparedReceipt> {
        let body =
            historical_contract::decode(original_bytes).map_err(|_| JournalError::InvalidInput)?;
        self.validate_historical_root(&body)?;
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        if self
            .historical_transaction
            .as_ref()
            .is_some_and(|id| id != &body.migration)
        {
            return Err(JournalError::Conflict);
        }
        let observed = self.historical_pristine(&body, false)?;
        let prepared = prepared_for(&body, Sha256Digest::of_bytes(original_bytes));
        let prepared_bytes = encode(&prepared)?;
        let committed_bytes = encode(&committed_for(&prepared)?)?;
        // Reserve capacity logically for all three immutable phases before the
        // first IO. This does not claim that any phase has been written.
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        {
            let addition = original_bytes
                .len()
                .checked_add(prepared_bytes.len())
                .and_then(|n| n.checked_add(committed_bytes.len()))
                .ok_or(JournalError::BudgetExceeded)?;
            if [
                original_bytes.len(),
                prepared_bytes.len(),
                committed_bytes.len(),
            ]
            .into_iter()
            .any(|n| n > self.budget.max_file_bytes)
                || observed
                    .files
                    .len()
                    .checked_add(3)
                    .is_none_or(|n| n > self.budget.max_files)
                || observed
                    .total_bytes
                    .checked_add(addition)
                    .is_none_or(|n| n > self.budget.max_bytes)
            {
                return Err(JournalError::BudgetExceeded);
            }
        }
        #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
        let _ = (&observed, &committed_bytes);
        self.write(HISTORICAL_INTENT, original_bytes, &|_| {})?;
        self.write(HISTORICAL_PREPARED, &prepared_bytes, &|_| {})?;
        let observed = self.observe_historical()?.ok_or(JournalError::Unknown)?;
        if observed.original_bytes != original_bytes
            || observed.prepared.as_ref() != Some(&prepared)
            || observed.committed.is_some()
        {
            return Err(JournalError::Unknown);
        }
        Ok(prepared)
    }
    pub fn commit_historical(
        &mut self,
        prepared: &HistoricalPreparedReceipt,
    ) -> JournalResult<HistoricalCommittedReceipt> {
        let observed = self.observe_historical()?.ok_or(JournalError::Unknown)?;
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        if self
            .historical_transaction
            .as_ref()
            .is_some_and(|id| id != &observed.body.migration)
        {
            return Err(JournalError::Conflict);
        }
        if observed.prepared.as_ref() != Some(prepared) {
            return Err(JournalError::Conflict);
        }
        let committed = committed_for(prepared)?;
        if let Some(existing) = &observed.committed {
            if existing != &committed {
                return Err(JournalError::Conflict);
            }
            // Explicit idempotent settlement only of the already existing
            // marker, even if subsequent native transactions now exist.
            self.resync_historical()?;
            return Ok(committed);
        }
        self.historical_pristine(&observed.body, true)?;
        self.resync_historical()?; // sync original materials/intent/prepared only
        self.write(HISTORICAL_COMMITTED, &encode(&committed)?, &|_| {})?;
        let current = self.observe_historical()?.ok_or(JournalError::Unknown)?;
        if current.original_bytes != observed.original_bytes
            || current.committed.as_ref() != Some(&committed)
        {
            return Err(JournalError::Unknown);
        }
        Ok(committed)
    }
    pub fn observe_historical(&self) -> JournalResult<Option<HistoricalObservation>> {
        let observed = self.scan()?;
        if observed.files.iter().any(|f| {
            f.name.starts_with("historical-baseline.")
                && !HISTORICAL_FILES.contains(&f.name.as_str())
        }) {
            return Err(JournalError::Unknown);
        }
        let find = |name: &str| observed.files.iter().find(|f| f.name == name);
        let Some(intent) = find(HISTORICAL_INTENT) else {
            return if find(HISTORICAL_PREPARED).is_some() || find(HISTORICAL_COMMITTED).is_some() {
                Err(JournalError::Unknown)
            } else {
                Ok(None)
            };
        };
        let original_bytes = intent.bytes().to_vec();
        let body =
            historical_contract::decode(&original_bytes).map_err(|_| JournalError::Unknown)?;
        self.validate_historical_root(&body)?;
        self.historical_materials(&body)?;
        let digest = Sha256Digest::of_bytes(&original_bytes);
        let expected_prepared = prepared_for(&body, digest);
        let prepared = if let Some(file) = find(HISTORICAL_PREPARED) {
            let decoded: HistoricalPreparedReceipt =
                serde_json::from_slice(file.bytes()).map_err(|_| JournalError::Unknown)?;
            if decoded != expected_prepared || encode(&decoded)? != file.bytes() {
                return Err(JournalError::Unknown);
            }
            Some(decoded)
        } else {
            None
        };
        let committed = if let Some(file) = find(HISTORICAL_COMMITTED) {
            let prepared = prepared.as_ref().ok_or(JournalError::Unknown)?;
            let decoded: HistoricalCommittedReceipt =
                serde_json::from_slice(file.bytes()).map_err(|_| JournalError::Unknown)?;
            if decoded != committed_for(prepared)? || encode(&decoded)? != file.bytes() {
                return Err(JournalError::Unknown);
            }
            Some(decoded)
        } else {
            None
        };
        Ok(Some(HistoricalObservation {
            body,
            original_bytes,
            digest,
            prepared,
            committed,
        }))
    }
    /// Fsync/readback ONLY already-existing exact original files. Missing phases
    /// remain missing. This method never commits or issues a Core durable fact.
    pub fn resync_historical(&mut self) -> JournalResult<Option<HistoricalObservation>> {
        let Some(before) = self.observe_historical()? else {
            return Ok(None);
        };
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        files::with_namespace(self, |dir| {
            let mut names: Vec<String> = before
                .body
                .required_materials
                .iter()
                .map(material_name)
                .collect();
            names.push(HISTORICAL_INTENT.to_owned());
            if before.prepared.is_some() {
                names.push(HISTORICAL_PREPARED.to_owned());
            }
            if before.committed.is_some() {
                names.push(HISTORICAL_COMMITTED.to_owned());
            }
            for name in names {
                let original = files::read(dir, &name, self.budget.max_file_bytes)?
                    .ok_or(JournalError::Unknown)?;
                files::sync_file(dir, &name)?;
                if files::read(dir, &name, self.budget.max_file_bytes)?.as_deref()
                    != Some(original.as_slice())
                {
                    return Err(JournalError::Unknown);
                }
            }
            dir.sync_all().map_err(|_| JournalError::Unknown)
        })?;
        let after = self.observe_historical()?.ok_or(JournalError::Unknown)?;
        if before.original_bytes != after.original_bytes
            || before.prepared != after.prepared
            || before.committed != after.committed
        {
            return Err(JournalError::Unknown);
        }
        Ok(Some(after))
    }
}

#[cfg(all(test, target_os = "linux", target_env = "gnu"))]
#[path = "historical_tests.rs"]
mod tests;
