//! Protected enrollment bootstrap. This is not a network listener or an
//! administrator factory. Recovery of file/Core facts does not prove profile
//! crypto semantics, original transport quiescence or OS/native readiness.
pub mod http;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub(crate) mod legacy_import;
mod profile;
mod recovery;
pub mod service;
pub mod shared;

use crate::store::{
    ConfigurationWriterGuard, PrivateRoot,
    enrollment::{EnrollmentJournal, JournalBudget, JournalError},
};
use recovery::{InventoryFacts, RecoveryBlocked};
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};
use styx_contracts::identity::GatewayEpoch;
use styx_core::enrollment::{EnrollmentControl, EnrollmentLedger, Limits};

#[derive(Debug, thiserror::Error)]
#[error("protected enrollment bootstrap refused: {category}")]
pub struct BootstrapError {
    category: &'static str,
}
impl BootstrapError {
    pub fn category(&self) -> &'static str {
        self.category
    }
}
impl From<RecoveryBlocked> for BootstrapError {
    fn from(value: RecoveryBlocked) -> Self {
        let category = match value {
            RecoveryBlocked::Store(_) => "store_unproven",
            RecoveryBlocked::UnknownEntry => "unknown_entry",
            RecoveryBlocked::InvalidRecord => "invalid_record",
            RecoveryBlocked::ConflictingChain => "conflicting_chain",
            RecoveryBlocked::UnresolvedInventory => "unresolved_inventory",
            RecoveryBlocked::ClockUnproven => "clock_unproven",
            RecoveryBlocked::ClockRollback => "clock_rollback",
            RecoveryBlocked::InventoryChanged => "inventory_changed",
            RecoveryBlocked::Core(_) => "core_refused",
        };
        Self { category }
    }
}
impl From<JournalError> for BootstrapError {
    fn from(_: JournalError) -> Self {
        Self {
            category: "store_unproven",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct BootstrapDiagnostics {
    pub stage: &'static str,
    pub network_ready: bool,
    pub revision: u64,
    pub sequence_high_water: u64,
    pub has_commit_head: bool,
    pub unresolved: bool,
    pub unresolved_kind: Option<&'static str>,
    pub clock_floor: u64,
    pub transaction_files: usize,
    pub material_files: usize,
    pub unreferenced_material_files: usize,
    pub observed_files: usize,
    pub observed_bytes: usize,
    pub devices: usize,
    pub revoked_devices: usize,
}

/// Retains the exclusive configuration writer throughout this boot phase.
/// No control/admin capability, token or raw material escapes this wrapper.
/// Desktop/Host transport and typed-profile crypto composition are still needed.
pub struct EnrollmentBootstrap<'a> {
    journal: EnrollmentJournal<'a>,
    ledger: EnrollmentLedger,
    control: EnrollmentControl,
    facts: InventoryFacts,
}
impl<'a> EnrollmentBootstrap<'a> {
    /// Recover only an existing native enrollment journal with a durable floor.
    /// Never initializes an empty/legacy store or changes original credentials.
    pub fn recover_existing(
        root: &'a PrivateRoot,
        writer: &'a mut ConfigurationWriterGuard,
        limits: Limits,
    ) -> Result<Self, BootstrapError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|d| u64::try_from(d.as_millis()).ok())
            .ok_or(BootstrapError {
                category: "clock_unproven",
            })?;
        let epoch = GatewayEpoch::try_from(format!("enrollment-boot-{}", uuid::Uuid::new_v4()))
            .map_err(|_| BootstrapError {
                category: "epoch_unproven",
            })?;
        let mut journal = EnrollmentJournal::open_existing(root, writer, JournalBudget::default())?;
        let recovered = recovery::recover_journal(&mut journal, epoch, limits, now)?;
        Ok(Self {
            journal,
            ledger: recovered.ledger,
            control: recovered.control,
            facts: recovered.facts,
        })
    }
    /// Secret-safe boot observations, explicitly not network/native acceptance.
    pub fn diagnostics(&self) -> Result<BootstrapDiagnostics, BootstrapError> {
        let inventory = self.journal.scan()?;
        let devices = self
            .ledger
            .recovery_devices(&self.control)
            .map_err(|_| BootstrapError {
                category: "core_refused",
            })?;
        Ok(BootstrapDiagnostics {
            stage: "journal_recovered_profile_crypto_and_transport_not_composed",
            network_ready: false,
            revision: self.facts.revision,
            sequence_high_water: self.facts.sequence_high_water,
            has_commit_head: self.facts.head.is_some(),
            unresolved: self.ledger.pending_intent().is_some() || self.facts.unresolved.is_some(),
            unresolved_kind: self.facts.unresolved_kind.map(|kind| match kind {
                recovery::UnresolvedKind::IntentOnly => "intent_only",
                recovery::UnresolvedKind::PreparedOnly => "prepared_only",
            }),
            clock_floor: self.facts.clock_floor,
            transaction_files: self.facts.transaction_files,
            material_files: self.facts.material_files,
            unreferenced_material_files: self.facts.unreferenced_material_files,
            observed_files: inventory.files.len(),
            observed_bytes: inventory.total_bytes,
            devices: devices.len(),
            revoked_devices: devices.iter().filter(|d| d.revoked).count(),
        })
    }
}

/// Reuses the server's bounded canonical admission checks without granting or
/// approving a local device. Client-side validation is not Gateway authority.
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
pub(crate) fn validate_local_join(
    payload: &styx_contracts::legacy::JoinPayload,
    signature: &str,
) -> Result<(), &'static str> {
    profile::verify_join(payload, signature)
        .map(|_| ())
        .map_err(|_| "native_join_profile_invalid")
}
