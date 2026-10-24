//! Pure C07 desired-state transaction protocol. Facts are supplied by a trusted
//! writer adapter; these structs do not prove fsync, ownership, or authorization.
//! No filesystem mutation, runtime handoff, implicit replay, or legacy adoption.
use styx_contracts::identity::Sha256Digest;

pub use styx_contracts::management::{
    DesiredStateCommit, DurableStage, JournalReceipt, ReaderContract, TransactionState,
};
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedFacts {
    pub intent: DesiredStateCommit,
    pub deployment_raw_sha256: Sha256Digest,
    pub canonical_state_sha256: Sha256Digest,
    pub reader: ReaderContract,
    pub journal: JournalReceipt,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedFacts {
    pub intent: DesiredStateCommit,
    pub deployment_raw_sha256: Sha256Digest,
    pub canonical_state_sha256: Sha256Digest,
    pub journal: JournalReceipt,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationFacts {
    pub intent: DesiredStateCommit,
    pub deployment_raw_sha256: Sha256Digest,
    pub canonical_state_sha256: Sha256Digest,
    pub reader: ReaderContract,
    pub journal: JournalReceipt,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitFacts {
    pub intent: DesiredStateCommit,
    pub deployment_raw_sha256: Sha256Digest,
    pub canonical_state_sha256: Sha256Digest,
    pub journal: JournalReceipt,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionSnapshot {
    pub intent: DesiredStateCommit,
    pub state: TransactionState,
    pub last_durable_stage: DurableStage,
    pub journal_head: Option<Sha256Digest>,
    /// Monotonic audit fact: reconciliation never erases an uncertain boundary.
    pub uncertain_history: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryDecision {
    /// No prepared boundary: ordinary planning may continue, never apply yet.
    PrepareOriginal,
    /// Canonical bytes remain before; apply may be attempted only by the original writer transaction.
    ResumePrepared,
    /// Target bytes exist but have not been independently verified.
    VerifyTarget,
    CommitVerified,
    AlreadyCommitted,
    /// Includes neither-hash, rollback after Applied, or explicit Unknown.
    UnknownInspect,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TransactionError {
    #[error("invalid_transaction_intent")]
    InvalidIntent,
    #[error("transaction_capacity")]
    Capacity,
    #[error("transaction_binding_mismatch")]
    BindingMismatch,
    #[error("transaction_phase_mismatch")]
    PhaseMismatch,
    #[error("transaction_state_mismatch")]
    StateMismatch,
    #[error("transaction_reader_mismatch")]
    ReaderMismatch,
    #[error("transaction_journal_mismatch")]
    JournalMismatch,
}
/// Owned pure state: deliberately not Deserialize/Clone. Recovery of a durable
/// chain must replay these same checked boundaries, not load a caller snapshot.
pub struct ManagementTransaction {
    snapshot: TransactionSnapshot,
    last_receipt: Option<JournalReceipt>,
}
impl ManagementTransaction {
    pub fn plan(intent: DesiredStateCommit) -> Result<Self, TransactionError> {
        intent
            .validate()
            .map_err(|_| TransactionError::InvalidIntent)?;
        Ok(Self {
            snapshot: TransactionSnapshot {
                intent,
                state: TransactionState::Planned,
                last_durable_stage: DurableStage::Planned,
                journal_head: None,
                uncertain_history: false,
            },
            last_receipt: None,
        })
    }
    pub fn snapshot(&self) -> TransactionSnapshot {
        self.snapshot.clone()
    }
    fn binding(
        &self,
        intent: &DesiredStateCommit,
        deployment: Sha256Digest,
    ) -> Result<(), TransactionError> {
        if intent != &self.snapshot.intent
            || deployment != self.snapshot.intent.deployment_raw_sha256
        {
            return Err(TransactionError::BindingMismatch);
        }
        Ok(())
    }
    fn phase(&self, expected: TransactionState) -> Result<(), TransactionError> {
        if self.snapshot.state != expected {
            return Err(TransactionError::PhaseMismatch);
        }
        Ok(())
    }
    fn journal(
        &self,
        receipt: &JournalReceipt,
        stage: DurableStage,
    ) -> Result<(), TransactionError> {
        if receipt.transaction_id != self.snapshot.intent.transaction_id
            || receipt.sequence != self.snapshot.intent.sequence
            || receipt.stage != stage
            || receipt.previous != self.snapshot.journal_head
            || Some(receipt.record_sha256) == receipt.previous
        {
            return Err(TransactionError::JournalMismatch);
        }
        Ok(())
    }
    fn target(&self, canonical: Sha256Digest) -> Result<(), TransactionError> {
        if canonical != self.snapshot.intent.target_state_sha256 {
            return Err(TransactionError::StateMismatch);
        }
        Ok(())
    }
    fn reader(&self, reader: &ReaderContract) -> Result<(), TransactionError> {
        if reader != &self.snapshot.intent.reader {
            return Err(TransactionError::ReaderMismatch);
        }
        Ok(())
    }
    fn advance(&mut self, state: TransactionState, receipt: JournalReceipt) {
        self.snapshot.state = state;
        self.snapshot.last_durable_stage = receipt.stage;
        self.snapshot.journal_head = Some(receipt.record_sha256);
        self.last_receipt = Some(receipt);
    }
    pub fn prepare(&mut self, facts: PreparedFacts) -> Result<(), TransactionError> {
        self.phase(TransactionState::Planned)?;
        self.binding(&facts.intent, facts.deployment_raw_sha256)?;
        self.reader(&facts.reader)?;
        if facts.canonical_state_sha256 != self.snapshot.intent.before_state_sha256 {
            return Err(TransactionError::StateMismatch);
        }
        self.journal(&facts.journal, DurableStage::Prepared)?;
        self.advance(TransactionState::Prepared, facts.journal);
        Ok(())
    }
    pub fn applied(&mut self, facts: AppliedFacts) -> Result<(), TransactionError> {
        self.phase(TransactionState::Prepared)?;
        self.binding(&facts.intent, facts.deployment_raw_sha256)?;
        self.target(facts.canonical_state_sha256)?;
        self.journal(&facts.journal, DurableStage::Applied)?;
        self.advance(TransactionState::Applied, facts.journal);
        Ok(())
    }
    pub fn verified(&mut self, facts: VerificationFacts) -> Result<(), TransactionError> {
        self.phase(TransactionState::Applied)?;
        self.binding(&facts.intent, facts.deployment_raw_sha256)?;
        self.target(facts.canonical_state_sha256)?;
        self.reader(&facts.reader)?;
        self.journal(&facts.journal, DurableStage::Verified)?;
        self.advance(TransactionState::Verified, facts.journal);
        Ok(())
    }
    pub fn committed(&mut self, facts: CommitFacts) -> Result<(), TransactionError> {
        self.phase(TransactionState::Verified)?;
        self.binding(&facts.intent, facts.deployment_raw_sha256)?;
        self.target(facts.canonical_state_sha256)?;
        self.journal(&facts.journal, DurableStage::Committed)?;
        self.advance(TransactionState::Committed, facts.journal);
        Ok(())
    }
    pub fn mark_recoverable(&mut self) -> Result<(), TransactionError> {
        if matches!(
            self.snapshot.state,
            TransactionState::Committed | TransactionState::Unknown
        ) {
            return Err(TransactionError::PhaseMismatch);
        }
        self.snapshot.state = TransactionState::Recoverable;
        Ok(())
    }
    pub fn mark_unknown(&mut self) -> Result<(), TransactionError> {
        if self.snapshot.state == TransactionState::Committed {
            return Err(TransactionError::PhaseMismatch);
        }
        self.snapshot.state = TransactionState::Unknown;
        self.snapshot.uncertain_history = true;
        Ok(())
    }
    /// Explicit trusted-adapter reconciliation of an ALREADY recorded boundary.
    /// This neither synthesizes a missing receipt nor retries a write. Unknown
    /// at Prepared remains fenced: the effect may have happened without its
    /// Applied receipt. A later original journal replay is a separate adapter task.
    pub fn reconcile_existing(
        &mut self,
        original: &DesiredStateCommit,
        deployment: Sha256Digest,
        canonical: Sha256Digest,
        reader: ReaderContract,
        receipt: &JournalReceipt,
    ) -> Result<(), TransactionError> {
        if !matches!(
            self.snapshot.state,
            TransactionState::Recoverable | TransactionState::Unknown
        ) {
            return Err(TransactionError::PhaseMismatch);
        }
        self.binding(original, deployment)?;
        self.reader(&reader)?;
        if self.last_receipt.as_ref() != Some(receipt) {
            return Err(TransactionError::JournalMismatch);
        }
        let target = canonical == self.snapshot.intent.target_state_sha256;
        let state = match self.snapshot.last_durable_stage {
            DurableStage::Prepared
                if self.snapshot.state == TransactionState::Recoverable
                    && canonical == self.snapshot.intent.before_state_sha256 =>
            {
                TransactionState::Prepared
            }
            DurableStage::Applied if target => TransactionState::Applied,
            DurableStage::Verified if target => TransactionState::Verified,
            _ => return Err(TransactionError::StateMismatch),
        };
        self.snapshot.state = state;
        Ok(())
    }
    /// Read-only decision for the SAME original intent. Canonical target alone
    /// does not prove apply/verify/commit or erase an uncertain historical write.
    pub fn recovery_decision(
        &self,
        original: &DesiredStateCommit,
        deployment: Sha256Digest,
        canonical: Sha256Digest,
    ) -> Result<RecoveryDecision, TransactionError> {
        self.binding(original, deployment)?;
        if self.snapshot.state == TransactionState::Unknown {
            return Ok(RecoveryDecision::UnknownInspect);
        }
        let intent = &self.snapshot.intent;
        let decision = match (self.snapshot.last_durable_stage, canonical) {
            (DurableStage::Planned, hash) if hash == intent.before_state_sha256 => {
                RecoveryDecision::PrepareOriginal
            }
            (DurableStage::Prepared, hash) if hash == intent.before_state_sha256 => {
                RecoveryDecision::ResumePrepared
            }
            (DurableStage::Prepared | DurableStage::Applied, hash)
                if hash == intent.target_state_sha256 =>
            {
                RecoveryDecision::VerifyTarget
            }
            (DurableStage::Verified, hash) if hash == intent.target_state_sha256 => {
                RecoveryDecision::CommitVerified
            }
            (DurableStage::Committed, hash) if hash == intent.target_state_sha256 => {
                RecoveryDecision::AlreadyCommitted
            }
            _ => RecoveryDecision::UnknownInspect,
        };
        Ok(decision)
    }
}
#[cfg(test)]
#[path = "transaction_tests.rs"]
mod tests;
