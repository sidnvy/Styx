//! Append-only enrollment persistence facts, never a second policy authority.
//!
//! Namespace creation does not prove a fresh profile or that a legacy owner has
//! stopped. Callers must coordinate legacy ownership before explicit migration.
//! Unknown files/transactions are retained. No API mints Core durable authority.
use super::{ConfigurationWriterGuard, PrivateRoot};
use serde::{Deserialize, Serialize};
use styx_contracts::identity::{GatewayEpoch, Sha256Digest, TransactionId};

#[cfg(all(test, target_os = "linux", target_env = "gnu"))]
const NAMESPACE: &str = super::secure_journal::NamespaceName::EnrollmentV1.as_str();
const SCHEMA: u8 = 1;
const MAX_INTENT: usize = 16 * 1024;
use styx_contracts::enrollment::{self as contract, Mutation};
pub use styx_contracts::enrollment::{MaterialKind, MaterialRef};

pub use super::secure_journal::{
    JournalBudget, JournalError, JournalObservation, JournalResult, ObservedJournalFile,
};

fn material_prefix(kind: MaterialKind) -> &'static str {
    match kind {
        MaterialKind::Profile => "profile",
        MaterialKind::Token => "token",
        MaterialKind::Sealed => "sealed",
    }
}
fn material_limit(kind: MaterialKind) -> usize {
    match kind {
        MaterialKind::Profile => 256 * 1024,
        MaterialKind::Token => 4 * 1024,
        MaterialKind::Sealed => 16 * 1024,
    }
}
fn material_name(reference: &MaterialRef) -> String {
    format!(
        "{}-{}.material",
        material_prefix(reference.kind),
        reference.digest.to_hex()
    )
}
/// Supplied by the trusted Core adapter, not request metadata. The eventual
/// integration must use the frozen Core intent DTO, not infer approval rules here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentBinding {
    pub transaction: TransactionId,
    pub epoch: GatewayEpoch,
    pub sequence: u64,
    pub expected_revision: u64,
    pub previous_commit: Option<Sha256Digest>,
    pub intent_digest: Sha256Digest,
    pub required_materials: Vec<MaterialRef>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedReceipt {
    pub schema: u8,
    pub binding: IntentBinding,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommittedReceipt {
    pub schema: u8,
    pub binding: IntentBinding,
    pub prepared_digest: Sha256Digest,
}
impl CommittedReceipt {
    pub fn digest(&self) -> JournalResult<Sha256Digest> {
        encode(self).map(|b| Sha256Digest::of_bytes(&b))
    }
}
pub struct EnrollmentJournal<'a> {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    root: &'a PrivateRoot,
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    writer: &'a mut ConfigurationWriterGuard,
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    budget: JournalBudget,
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    _borrow: std::marker::PhantomData<&'a mut ConfigurationWriterGuard>,
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    namespace: (u64, u64),
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    historical_transaction: Option<TransactionId>,
}
fn encode(value: &impl Serialize) -> JournalResult<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| JournalError::InvalidInput)
}
fn record_name(id: &TransactionId, suffix: &str) -> String {
    format!("txn-{}.{suffix}", id.as_str())
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
mod files {
    use super::*;
    use crate::store::secure_journal::{self, NamespaceName};
    pub(super) use secure_journal::files::{immutable, read, scan, sync_file};
    use std::fs::File;
    pub(super) fn existing_namespace(root: &File) -> JournalResult<(u64, u64)> {
        secure_journal::files::existing_namespace(root, NamespaceName::EnrollmentV1)
    }
    pub(super) fn create_namespace(root: &File) -> JournalResult<(u64, u64)> {
        secure_journal::files::create_namespace(root, NamespaceName::EnrollmentV1)
    }
    pub(super) fn with_namespace<T>(
        journal: &EnrollmentJournal<'_>,
        operation: impl FnOnce(&File) -> JournalResult<T>,
    ) -> JournalResult<T> {
        secure_journal::files::with_namespace(
            journal.root,
            journal.writer,
            NamespaceName::EnrollmentV1,
            journal.namespace,
            operation,
        )
    }
}

impl<'a> EnrollmentJournal<'a> {
    pub fn open(
        root: &'a PrivateRoot,
        writer: &'a mut ConfigurationWriterGuard,
        budget: JournalBudget,
    ) -> JournalResult<Self> {
        Self::open_with(root, writer, budget, true)
    }
    /// Boot recovery cannot create a new namespace in an existing legacy root.
    pub fn open_existing(
        root: &'a PrivateRoot,
        writer: &'a mut ConfigurationWriterGuard,
        budget: JournalBudget,
    ) -> JournalResult<Self> {
        Self::open_with(root, writer, budget, false)
    }
    fn open_with(
        root: &'a PrivateRoot,
        writer: &'a mut ConfigurationWriterGuard,
        budget: JournalBudget,
        create: bool,
    ) -> JournalResult<Self> {
        if !budget.valid() {
            return Err(JournalError::InvalidInput);
        }
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        {
            let namespace = root
                .inner
                .with_configuration_writer_directory(writer, |directory| {
                    Ok(if create {
                        files::create_namespace(directory)
                    } else {
                        files::existing_namespace(directory)
                    })
                })
                .map_err(|_| JournalError::Unknown)??;
            let journal = Self {
                root,
                writer,
                budget,
                namespace,
                historical_transaction: None,
            };
            journal.scan()?; // An over-budget/unsafe namespace never becomes writable.
            Ok(journal)
        }
        #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
        {
            let _ = (root, writer, budget, create);
            Err(JournalError::Unsupported)
        }
    }
    pub fn put_material(&mut self, kind: MaterialKind, bytes: &[u8]) -> JournalResult<MaterialRef> {
        if bytes.is_empty() || bytes.len() > material_limit(kind) {
            return Err(JournalError::InvalidInput);
        }
        let reference = MaterialRef {
            kind,
            digest: Sha256Digest::of_bytes(bytes),
        };
        self.write(&material_name(&reference), bytes, &|_| {})?;
        Ok(reference)
    }
    /// Returns only protected bytes matching the typed content reference. Callers
    /// must not log token/sealed/profile material or expose it as public DTOs.
    pub fn read_material(&self, reference: &MaterialRef) -> JournalResult<Vec<u8>> {
        let bytes = self
            .read(&material_name(reference))?
            .ok_or(JournalError::Unknown)?;
        if bytes.is_empty()
            || bytes.len() > material_limit(reference.kind)
            || Sha256Digest::of_bytes(&bytes) != reference.digest
        {
            return Err(JournalError::Unknown);
        }
        Ok(bytes)
    }
    pub fn prepare(
        &mut self,
        original_bytes: &[u8],
        previous_commit: Option<Sha256Digest>,
    ) -> JournalResult<PreparedReceipt> {
        self.prepare_observing(original_bytes, previous_commit, &|_, _| {})
    }
    fn prepare_observing(
        &mut self,
        original_bytes: &[u8],
        previous_commit: Option<Sha256Digest>,
        fault: &impl Fn(&str, &str),
    ) -> JournalResult<PreparedReceipt> {
        if self
            .observe_historical()?
            .is_some_and(|baseline| baseline.committed.is_none())
        {
            return Err(JournalError::Conflict);
        }
        let body = contract::decode(original_bytes).map_err(|_| JournalError::InvalidInput)?;
        let binding = IntentBinding {
            transaction: body.transaction,
            epoch: body.gateway_epoch,
            sequence: body.sequence,
            expected_revision: body.expected_revision,
            previous_commit,
            intent_digest: Sha256Digest::of_bytes(original_bytes),
            required_materials: body.required_materials,
        };
        let prepared = PreparedReceipt {
            schema: SCHEMA,
            binding,
        };
        self.write(
            &record_name(&prepared.binding.transaction, "intent"),
            original_bytes,
            &|at| fault("intent", at),
        )?;
        self.write(
            &record_name(&prepared.binding.transaction, "prepared"),
            &encode(&prepared)?,
            &|at| fault("prepared", at),
        )?;
        Ok(prepared)
    }
    pub fn commit(&mut self, prepared: &PreparedReceipt) -> JournalResult<CommittedReceipt> {
        self.commit_observing(prepared, &|_, _| {})
    }
    fn commit_observing(
        &mut self,
        prepared: &PreparedReceipt,
        fault: &impl Fn(&str, &str),
    ) -> JournalResult<CommittedReceipt> {
        self.verify_prepared(prepared)?;
        self.verify_predecessor(&prepared.binding)?;
        // Re-sync every required material and exact original intent/receipt
        // before the sole authority marker. No caller-provided "written" flag.
        for reference in &prepared.binding.required_materials {
            let bytes = self.read_material(reference)?;
            self.write(&material_name(reference), &bytes, &|_| {})?;
        }
        let intent_name = record_name(&prepared.binding.transaction, "intent");
        let bytes = self.read(&intent_name)?.ok_or(JournalError::Unknown)?;
        self.write(&intent_name, &bytes, &|_| {})?;
        let prepared_name = record_name(&prepared.binding.transaction, "prepared");
        let prepared_bytes = encode(prepared)?;
        self.write(&prepared_name, &prepared_bytes, &|_| {})?;
        let committed = CommittedReceipt {
            schema: SCHEMA,
            binding: prepared.binding.clone(),
            prepared_digest: Sha256Digest::of_bytes(&prepared_bytes),
        };
        self.write(
            &record_name(&prepared.binding.transaction, "committed"),
            &encode(&committed)?,
            &|at| fault("committed", at),
        )?;
        Ok(committed)
    }
    fn verify_prepared(&self, prepared: &PreparedReceipt) -> JournalResult<()> {
        if prepared.schema != SCHEMA
            || prepared.binding.sequence == 0
            || prepared.binding.required_materials.len() > 8
        {
            return Err(JournalError::InvalidInput);
        }
        let expected = encode(prepared)?;
        if self
            .read(&record_name(&prepared.binding.transaction, "prepared"))?
            .as_deref()
            != Some(expected.as_slice())
        {
            return Err(JournalError::Conflict);
        }
        let raw = self
            .read(&record_name(&prepared.binding.transaction, "intent"))?
            .ok_or(JournalError::Unknown)?;
        if raw.is_empty()
            || raw.len() > MAX_INTENT
            || Sha256Digest::of_bytes(&raw) != prepared.binding.intent_digest
        {
            return Err(JournalError::Unknown);
        }
        let body = contract::decode(&raw).map_err(|_| JournalError::Unknown)?;
        if body.transaction != prepared.binding.transaction
            || body.gateway_epoch != prepared.binding.epoch
            || body.sequence != prepared.binding.sequence
            || body.expected_revision != prepared.binding.expected_revision
            || body.required_materials != prepared.binding.required_materials
        {
            return Err(JournalError::Conflict);
        }
        if let Mutation::Approve { device, .. } = body.mutation
            && (device.credential.0 != device.credential_hash
                || !prepared.binding.required_materials.contains(&MaterialRef {
                    kind: MaterialKind::Token,
                    digest: device.credential_hash,
                }))
        {
            return Err(JournalError::Conflict);
        }
        Ok(())
    }
    fn verify_predecessor(&self, binding: &IntentBinding) -> JournalResult<()> {
        let observation = self.scan()?;
        let mut commits = vec![];
        for file in observation.files.iter().filter(|f| {
            f.name.ends_with(".committed") && f.name != historical::HISTORICAL_COMMITTED
        }) {
            let commit: CommittedReceipt =
                serde_json::from_slice(file.bytes()).map_err(|_| JournalError::Unknown)?;
            if file.name != record_name(&commit.binding.transaction, "committed")
                || encode(&commit)? != file.bytes()
                || commit.schema != SCHEMA
            {
                return Err(JournalError::Unknown);
            }
            let prepared = PreparedReceipt {
                schema: SCHEMA,
                binding: commit.binding.clone(),
            };
            self.verify_prepared(&prepared)?;
            if commit.prepared_digest != Sha256Digest::of_bytes(&encode(&prepared)?) {
                return Err(JournalError::Unknown);
            }
            for reference in &commit.binding.required_materials {
                self.read_material(reference)?;
            }
            commits.push(commit);
        }
        commits.sort_by_key(|c| c.binding.sequence);
        let historical = self.observe_historical()?;
        let (mut sequence, mut revision, mut head) = match historical {
            Some(baseline) => {
                let committed = baseline.committed.ok_or(JournalError::Conflict)?;
                (committed.prepared.sequence, 1u64, Some(committed.digest()?))
            }
            None => (0, 0, None),
        };
        for current in &commits {
            if current.binding.sequence <= sequence
                || current.binding.expected_revision != revision
                || current.binding.previous_commit != head
            {
                return Err(JournalError::Conflict);
            }
            sequence = current.binding.sequence;
            revision = revision.checked_add(1).ok_or(JournalError::Conflict)?;
            head = Some(current.digest()?);
        }
        if let Some(existing) = commits
            .iter()
            .find(|c| c.binding.transaction == binding.transaction)
        {
            return if &existing.binding == binding {
                Ok(())
            } else {
                Err(JournalError::Conflict)
            };
        }
        if binding.sequence > sequence
            && binding.expected_revision == revision
            && binding.previous_commit == head
        {
            Ok(())
        } else {
            Err(JournalError::Conflict)
        }
    }

    /// Bounded observation, never an implicit sweep or automatic replay. A
    /// prepared-only intent remains Unknown; an orphan alone is not NotWritten.
    pub fn scan(&self) -> JournalResult<JournalObservation> {
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        {
            files::with_namespace(self, |dir| files::scan(dir, self.budget))
        }
        #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
        {
            Err(JournalError::Unsupported)
        }
    }
    /// Reconcile only a caller-selected original transaction. Does not mint
    /// credentials, apply policy, or turn prepared-only into committed.
    pub fn reconcile(
        &mut self,
        transaction: &TransactionId,
    ) -> JournalResult<Option<CommittedReceipt>> {
        let Some(bytes) = self.read(&record_name(transaction, "committed"))? else {
            return Ok(None);
        };
        let committed: CommittedReceipt =
            serde_json::from_slice(&bytes).map_err(|_| JournalError::Unknown)?;
        if committed.schema != SCHEMA
            || &committed.binding.transaction != transaction
            || encode(&committed)? != bytes
        {
            return Err(JournalError::Unknown);
        }
        let prepared = PreparedReceipt {
            schema: SCHEMA,
            binding: committed.binding.clone(),
        };
        if Sha256Digest::of_bytes(&encode(&prepared)?) != committed.prepared_digest {
            return Err(JournalError::Unknown);
        }
        let verified = self.commit(&prepared)?;
        if verified != committed {
            return Err(JournalError::Unknown);
        }
        Ok(Some(verified))
    }
    /// Re-sync only an existing unresolved transaction. Never creates a missing
    /// prepared/commit marker and never turns absence of commit into NotWritten.
    pub fn preserve_unresolved(&mut self, transaction: &TransactionId) -> JournalResult<()> {
        let intent_name = record_name(transaction, "intent");
        let commit_name = record_name(transaction, "committed");
        if self.read(&commit_name)?.is_some() {
            return Err(JournalError::Conflict);
        }
        let raw = self.read(&intent_name)?.ok_or(JournalError::Unknown)?;
        let body = contract::decode(&raw).map_err(|_| JournalError::Unknown)?;
        if &body.transaction != transaction {
            return Err(JournalError::Conflict);
        }
        let prepared_name = record_name(transaction, "prepared");
        let prepared_bytes = self.read(&prepared_name)?;
        if let Some(bytes) = &prepared_bytes {
            let prepared: PreparedReceipt =
                serde_json::from_slice(bytes).map_err(|_| JournalError::Unknown)?;
            self.verify_prepared(&prepared)?;
            if &prepared.binding.transaction != transaction {
                return Err(JournalError::Conflict);
            }
        }
        for reference in &body.required_materials {
            let bytes = self.read_material(reference)?;
            self.write(&material_name(reference), &bytes, &|_| {})?;
        }
        self.write(&intent_name, &raw, &|_| {})?;
        if let Some(bytes) = &prepared_bytes {
            self.write(&prepared_name, bytes, &|_| {})?;
        }
        if self.read(&commit_name)?.is_some()
            || self.read(&intent_name)?.as_deref() != Some(raw.as_slice())
            || self.read(&prepared_name)? != prepared_bytes
        {
            return Err(JournalError::Unknown);
        }
        Ok(())
    }
    fn read(&self, name: &str) -> JournalResult<Option<Vec<u8>>> {
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        {
            files::with_namespace(self, |dir| {
                files::read(dir, name, self.budget.max_file_bytes)
            })
        }
        #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
        {
            let _ = name;
            Err(JournalError::Unsupported)
        }
    }
    fn write(&self, name: &str, bytes: &[u8], fault: &impl Fn(&str)) -> JournalResult<()> {
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        {
            files::with_namespace(self, |dir| {
                files::immutable(dir, name, bytes, self.budget, fault)
            })
        }
        #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
        {
            let _ = (name, bytes, fault);
            Err(JournalError::Unsupported)
        }
    }
}

#[cfg(test)]
#[path = "enrollment/tests.rs"]
mod tests;

#[path = "enrollment/clock.rs"]
mod clock;

#[path = "enrollment/owned.rs"]
mod owned;
pub use owned::OwnedEnrollmentJournal;

#[path = "enrollment/historical.rs"]
mod historical;
pub use historical::{
    HistoricalCommittedReceipt, HistoricalObservation, HistoricalPreparedReceipt,
};
