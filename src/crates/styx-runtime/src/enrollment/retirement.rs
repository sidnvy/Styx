//! Narrow negative settlement for an explicitly retired, stopped local Hub Join.
//! Caller owns setup, Host and Gateway execution leases across this operation.
use super::{BootstrapError, EnrollmentBootstrap};
use crate::store::{
    ConfigurationWriterGuard, PrivateRoot,
    enrollment::{EnrollmentJournal, JournalBudget},
};
use std::time::{SystemTime, UNIX_EPOCH};
use styx_contracts::{
    enrollment::{Mutation, PairingContext, PendingStatus},
    identity::Sha256Digest,
};
use styx_core::enrollment::RejectionRequest;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RetirementOutcome {
    Rejected,
    Expired,
}

#[derive(Debug)]
pub(crate) struct RetirementReceipt {
    pub outcome: RetirementOutcome,
    pub intent_digest: Option<Sha256Digest>,
    pub durable_receipt: Option<Sha256Digest>,
    pub durable_clock_floor: u64,
    pub revision: u64,
}

fn refused(category: &'static str) -> BootstrapError {
    BootstrapError { category }
}
fn now() -> Result<u64, BootstrapError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .ok_or_else(|| refused("clock_unproven"))
}

impl EnrollmentBootstrap<'_> {
    /// No writes: use the caller's existing writer to validate the protected
    /// native reader, selected signed release and full C07 selection tip.
    pub(crate) fn validate_retirement_reader(
        root: &PrivateRoot,
        writer: &mut ConfigurationWriterGuard,
    ) -> Result<(), BootstrapError> {
        let journal = EnrollmentJournal::open_existing(root, writer, JournalBudget::default())?;
        journal
            .require_pairing_lifecycle_reader()
            .map_err(BootstrapError::from)
    }

    /// Caller durably records its retirement intent before invoking this;
    /// recovery advances the clock floor only after the reader check succeeds.
    pub(crate) fn recover_existing_for_retirement<'a>(
        root: &'a PrivateRoot,
        writer: &'a mut ConfigurationWriterGuard,
        limits: styx_core::enrollment::Limits,
    ) -> Result<EnrollmentBootstrap<'a>, BootstrapError> {
        Self::validate_retirement_reader(root, writer)?;
        EnrollmentBootstrap::recover_existing(root, writer, limits)
    }
    // This method does not write. Note that recover_existing, which must happen
    // first, advances the durable clock floor under the configuration writer.
    pub(crate) fn retirement_preflight(
        &self,
        selection: &RejectionRequest,
        expected_pairing: &PairingContext,
        expected_expires: u64,
    ) -> Result<RetirementOutcome, BootstrapError> {
        self.retirement_preflight_at(selection, expected_pairing, expected_expires, now()?)
    }

    fn retirement_preflight_at(
        &self,
        selection: &RejectionRequest,
        expected_pairing: &PairingContext,
        expected_expires: u64,
        now: u64,
    ) -> Result<RetirementOutcome, BootstrapError> {
        if self.facts.unresolved.is_some() || self.ledger.pending_intent().is_some() {
            return Err(refused("retirement_unresolved"));
        }
        if now == 0 || now < self.facts.clock_floor {
            return Err(refused("clock_rollback"));
        }
        // Check that the durable floor still matches the recovered snapshot.
        if self
            .journal
            .read_time_floor()
            .map_err(BootstrapError::from)?
            != Some(self.facts.clock_floor)
        {
            return Err(refused("retirement_inventory_changed"));
        }
        let pending = self
            .ledger
            .recovery_pending(&self.control)
            .map_err(|_| refused("core_refused"))?;
        let row = pending
            .iter()
            .find(|p| p.facts.request == selection.request)
            .ok_or_else(|| refused("retirement_target_mismatch"))?;
        if expected_expires == 0
            || row.expires != expected_expires
            || row.status != PendingStatus::Pending
            || row.facts.device != selection.device
            || row.facts.fingerprint != selection.fingerprint
            || row.facts.comparison != selection.comparison
            || &row.facts.pairing != expected_pairing
        {
            return Err(refused("retirement_target_mismatch"));
        }
        Ok(if row.expires <= now {
            RetirementOutcome::Expired
        } else {
            RetirementOutcome::Rejected
        })
    }

    /// Consumes the recovered writer on every result. Unknown never retries:
    /// a caller must retain evidence and cannot infer whether a write landed.
    pub(crate) fn abandon_pending_for_retirement(
        self,
        selection: RejectionRequest,
        expected_pairing: &PairingContext,
        expected_expires: u64,
    ) -> Result<RetirementReceipt, BootstrapError> {
        self.abandon_pending_at(selection, expected_pairing, expected_expires, now()?)
    }

    // Only this module's tests can supply a synthetic clock. The production
    // entry point above always obtains the wall clock itself.
    fn abandon_pending_at(
        mut self,
        selection: RejectionRequest,
        expected_pairing: &PairingContext,
        expected_expires: u64,
        clock: u64,
    ) -> Result<RetirementReceipt, BootstrapError> {
        let outcome =
            self.retirement_preflight_at(&selection, expected_pairing, expected_expires, clock)?;
        self.journal
            .require_pairing_lifecycle_reader()
            .map_err(BootstrapError::from)?;
        self.journal
            .record_time_floor(clock)
            .map_err(|_| refused("retirement_outcome_unknown"))?;
        let target = selection.request.clone();
        let intent = self
            .ledger
            .abandon_pending(&self.control.admin(), selection, expected_pairing, clock)
            .map_err(|_| refused("core_refused"))?;
        let intent = match (intent, outcome) {
            (None, RetirementOutcome::Expired) => {
                return Ok(RetirementReceipt {
                    outcome,
                    intent_digest: None,
                    durable_receipt: None,
                    durable_clock_floor: clock,
                    revision: self.facts.revision,
                });
            }
            (Some(intent), RetirementOutcome::Rejected) if matches!(&intent.body().mutation, Mutation::Reject { target: actual } if actual.request == target) => {
                intent
            }
            _ => return Err(refused("retirement_outcome_unknown")),
        };
        let prepared = self
            .journal
            .prepare(intent.original_bytes(), self.facts.head)
            .map_err(|_| refused("retirement_outcome_unknown"))?;
        let receipt = self
            .journal
            .commit(&prepared)
            .and_then(|r| r.digest())
            .map_err(|_| refused("retirement_outcome_unknown"))?;
        let committed = self
            .ledger
            .confirm_durable(self.control.attest_durable(&intent, receipt))
            .map_err(|_| refused("retirement_outcome_unknown"))?;
        Ok(RetirementReceipt {
            outcome,
            intent_digest: Some(intent.digest()),
            durable_receipt: Some(receipt),
            durable_clock_floor: clock,
            revision: committed.revision,
        })
    }
}

#[cfg(test)]
#[path = "retirement_tests.rs"]
mod tests;
