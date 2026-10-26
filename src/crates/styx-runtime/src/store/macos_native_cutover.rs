//! Darwin canonical publication under the ORIGINAL configuration writer.
//! This retains physical prerequisites, not a receipt-derived settlement claim.
//! Fresh final commit consumes only the original completed probe objects.
use super::*;
use super::{legacy_effect::MacTokenRetirement, previous_boot::MacBootRecoveryEffects};
use crate::{
    foreground::profile::OriginalNativePairMaterials,
    release::VerifiedNativeRelease,
    store::{
        configuration::{ConfigurationMaintenance, OwnedConfigurationRoot},
        management::{
            OwnedManagementJournal,
            cutover::{NativeCutoverHistoryInputs, NativeCutoverInputs, PreparedCutover},
            handoff::{LegacyGuardsHeld, ProofStamp},
        },
        native_root::NATIVE_MARKER_FILE,
        native_state,
        secure_journal::{JournalError, JournalResult, files},
    },
};
use styx_contracts::{
    identity::{Sha256Digest, TransactionId},
    native_management::{NATIVE_STATE_BYTES, NativePreservedHostPair, NativeRootIdentity},
};
use styx_core::management::transaction::DurableStage;

/// Captured while the original credential and canonical state still exist.
/// Holding this value does not attest that the original runtime has settled.
pub(in crate::store) struct MacCutoverPlan<'a, 'm> {
    materials: &'a OriginalNativePairMaterials<'m>,
    pair: NativePreservedHostPair,
    publisher: Sha256Digest,
    before_sha256: Sha256Digest,
}
impl<'a, 'm> MacCutoverPlan<'a, 'm> {
    pub(in crate::store) fn capture(
        materials: &'a OriginalNativePairMaterials<'m>,
        preservation_sha256: Sha256Digest,
    ) -> JournalResult<Self> {
        materials.revalidate().map_err(|_| JournalError::Unknown)?;
        let pair = materials
            .pair_binding(preservation_sha256)
            .map_err(|_| JournalError::Unknown)?;
        let publisher = materials
            .publisher_sha256()
            .map_err(|_| JournalError::Unknown)?;
        let before_sha256 = materials
            .before_sha256()
            .map_err(|_| JournalError::Unknown)?;
        materials.revalidate().map_err(|_| JournalError::Unknown)?;
        Ok(Self {
            materials,
            pair,
            publisher,
            before_sha256,
        })
    }

    /// Only an actual retained Darwin guard effect and actual retired-token pin
    /// can reach publication. The journal independently checks the retired chain.
    pub(in crate::store) fn prepare<'scope>(
        self,
        owner: OwnedConfigurationRoot,
        maintenance: &'scope ConfigurationMaintenance,
        journal: &mut OwnedManagementJournal,
        guards: &'scope MacBootRecoveryEffects,
        held: &'scope LegacyGuardsHeld,
        token: &'scope MacTokenRetirement,
        host: &'scope PrivateRoot,
        state_dir: &Path,
        inputs: NativeCutoverInputs,
        candidate: Arc<VerifiedNativeRelease>,
    ) -> JournalResult<MacCanonicalCutover<'scope, 'm>>
    where
        'a: 'scope,
    {
        let expected_pair =
            serde_json::to_vec(&self.pair).map_err(|_| JournalError::InvalidInput)?;
        let supplied = match &inputs.history {
            NativeCutoverHistoryInputs::PreservedHostPair { bindings }
            | NativeCutoverHistoryInputs::ImportedLocalGateway { bindings, .. } => bindings,
        };
        if supplied != &expected_pair
            || Sha256Digest::of_bytes(&inputs.before) != self.before_sha256
            || Sha256Digest::of_bytes(&inputs.preservation) != self.pair.preservation_sha256
        {
            return Err(JournalError::Conflict);
        }
        if !maintenance.matches(&owner)
            || !guards.matches_owner(&owner)
            || !held.prepared().matches_owner(&owner)
            || held.prepared().intent().transaction_id != self.pair.transaction_id
            || !token.matches_binding(&owner, &self.pair.host_root, self.pair.credential_sha256)
            || self.publisher.to_hex() != candidate.report().publisher_spki_sha256
            || host.identity() != root_identity_from_native(&self.pair.host_root)?
        {
            return Err(JournalError::Conflict);
        }
        guards.validate_retained(held)?;
        self.materials
            .revalidate_preserved_materials()
            .map_err(|_| JournalError::Unknown)?;
        if token.pre_stamp().content_sha256() != self.pair.credential_sha256 {
            return Err(JournalError::Conflict);
        }
        token.validate_retired()?;
        // The read-only record is captured only after actual guards are held.
        // It does not replace those guards or grant ordinary admission.
        owner.with_maintenance(maintenance, |state| {
            if state.root.identity() != root_identity_from_native(&self.pair.config_root)?
                || PrivateRoot::open(state_dir)
                    .map_err(|_| JournalError::Unknown)?
                    .identity()
                    != state.root.identity()
            {
                return Err(JournalError::Conflict);
            }
            let owners = crate::store::native_legacy_owners::capture_native_legacy_owners(
                &state.root,
                state_dir,
            )?;
            let marker = native_state::decode_marker(&inputs.marker)
                .map_err(|_| JournalError::InvalidInput)?;
            let target = native_state::decode_state(&inputs.target, &marker)
                .map_err(|_| JournalError::InvalidInput)?;
            if target
                .state()
                .extensions
                .get("legacy_owner_bindings_v2")
                .map(|raw| raw.get())
                != Some(owners.get())
            {
                return Err(JournalError::Conflict);
            }
            Ok(())
        })?;
        let retained_candidate = candidate.clone();
        let prepared = journal.prepare_native_cutover(maintenance, inputs, candidate)?;
        guards.validate_retained(held)?;
        token.validate_retired()?;
        self.materials
            .revalidate_preserved_materials()
            .map_err(|_| JournalError::Unknown)?;
        Ok(MacCanonicalCutover {
            owner,
            maintenance,
            prepared,
            pair: self.pair,
            candidate: retained_candidate,
            materials: self.materials,
            guards,
            held,
            token,
            canonical_pin: None,
            attempted: false,
            unknown: false,
        })
    }
}
fn root_identity_from_native(root: &NativeRootIdentity) -> JournalResult<RootIdentity> {
    match root {
        NativeRootIdentity::Macos { device, inode, uid } => Ok(RootIdentity::Macos {
            device: *device,
            inode: *inode,
            uid: *uid,
        }),
        _ => Err(JournalError::Conflict),
    }
}

/// Keep this SAME value and all borrowed original effects on failure. No Drop
/// operation, process exit or raw JSON assertion is interpreted as completion.
pub(crate) struct MacCanonicalCutover<'a, 'm> {
    owner: OwnedConfigurationRoot,
    maintenance: &'a ConfigurationMaintenance,
    prepared: PreparedCutover<NativeRootIdentity>,
    pair: NativePreservedHostPair,
    candidate: Arc<VerifiedNativeRelease>,
    materials: &'a OriginalNativePairMaterials<'m>,
    guards: &'a MacBootRecoveryEffects,
    held: &'a LegacyGuardsHeld,
    token: &'a MacTokenRetirement,
    canonical_pin: Option<FileObservation>,
    attempted: bool,
    unknown: bool,
}
impl MacCanonicalCutover<'_, '_> {
    /// Borrowed maintenance DATA. Call validate_applied before/after protected
    /// reads and every operation; these getters do not release admission.
    pub(crate) fn matches_owner(&self, owner: &OwnedConfigurationRoot) -> bool {
        self.owner.same_authority(owner)
            && self.maintenance.matches(owner)
            && self.prepared.matches_owner(owner)
            && self.guards.matches_owner(owner)
    }
    pub(crate) fn config_root(&self) -> &NativeRootIdentity {
        &self.pair.config_root
    }
    pub(crate) fn host_root(&self) -> &NativeRootIdentity {
        &self.pair.host_root
    }
    pub(crate) fn transaction_id(&self) -> &TransactionId {
        &self.prepared.intent().transaction_id
    }
    pub(crate) fn target_sha256(&self) -> Sha256Digest {
        self.prepared.intent().target_state_sha256
    }
    pub(crate) fn before(&self) -> &[u8] {
        self.prepared.before()
    }
    /// Borrow the SAME protected original reader. This is not an execution or
    /// ordinary-profile conversion; maintenance construction still requires self.
    pub(crate) fn original_materials(&self) -> &OriginalNativePairMaterials<'_> {
        self.materials
    }
    pub(crate) fn original_pair(&self) -> &NativePreservedHostPair {
        &self.pair
    }
    pub(crate) fn candidate(&self) -> &Arc<VerifiedNativeRelease> {
        &self.candidate
    }
    pub(crate) fn retired_token_relative_path(&self) -> PathBuf {
        self.token.retired_relative_path()
    }
    pub(crate) fn read_retired_token(
        &self,
        host: &PrivateRoot,
    ) -> JournalResult<zeroize::Zeroizing<Vec<u8>>> {
        self.validate_applied()?;
        if host.identity() != root_identity_from_native(&self.pair.host_root)?
            || !self.token.matches_binding(
                &self.owner,
                &self.pair.host_root,
                self.pair.credential_sha256,
            )
        {
            return Err(JournalError::Conflict);
        }
        let bytes = self.token.read_retired(host)?;
        if Sha256Digest::of_bytes(&bytes) != self.pair.credential_sha256 {
            return Err(JournalError::Unknown);
        }
        self.validate_applied()?;
        Ok(bytes)
    }
    fn prerequisites(&self) -> JournalResult<()> {
        if self.unknown || !self.prepared.matches_owner(&self.owner) {
            return Err(JournalError::Conflict);
        }
        self.candidate
            .revalidate()
            .map_err(|_| JournalError::Unknown)?;
        if self.candidate.report().manifest_sha256
            != self.prepared.intent().candidate_manifest_sha256
            || self.candidate.report().publisher_spki_sha256
                != self.prepared.intent().publisher_spki_sha256.to_hex()
        {
            return Err(JournalError::Unknown);
        }
        self.guards.validate_retained(self.held)?;
        self.token.validate_retired()?;
        self.materials
            .revalidate_preserved_materials()
            .map_err(|_| JournalError::Unknown)
    }
    pub(in crate::store) fn apply(
        &mut self,
        journal: &mut OwnedManagementJournal,
    ) -> JournalResult<()> {
        if self.attempted {
            return Err(JournalError::Conflict);
        }
        self.prerequisites()?;
        if !journal.cutover_prepared_matches(&self.prepared) {
            return Err(JournalError::Conflict);
        }
        // Validate this exact same namespace/owner/prepared chain BEFORE effects.
        // resync only synchronizes existing bytes and never advances a phase.
        let original = journal
            .resync_native_cutover(self.maintenance, &self.prepared.intent().transaction_id)?;
        if original.intent != *self.prepared.intent()
            || original.last_stage != DurableStage::Prepared
        {
            return Err(JournalError::Conflict);
        }
        self.attempted = true;
        let result = self.owner.with_maintenance(self.maintenance, |state| {
            let before = state
                .root
                .read_raw("state.json", NATIVE_STATE_BYTES)
                .map_err(|_| JournalError::Unknown)?;
            if before.bytes() != self.prepared.before() {
                return Err(JournalError::Conflict);
            }
            state
                .root
                .ensure_absent(NATIVE_MARKER_FILE)
                .map_err(|_| JournalError::Conflict)?;
            let marker = native_state::decode_marker(self.prepared.marker())
                .map_err(|_| JournalError::InvalidInput)?;
            native_state::decode_state(self.prepared.target(), &marker)
                .map_err(|_| JournalError::InvalidInput)?;
            state.preflight_growth(
                self.prepared
                    .target()
                    .len()
                    .checked_add(self.prepared.marker().len())
                    .ok_or(JournalError::BudgetExceeded)?,
            )?;
            journal.with_directory_locked(state, |directory| {
                let temporary = format!(
                    "txn-{}.state-temporary",
                    self.prepared.intent().transaction_id.as_str()
                );
                files::immutable(
                    directory,
                    &temporary,
                    self.prepared.target(),
                    journal.budget(),
                    &|_| {},
                )?;
                state
                    .root
                    .inner
                    .with_configuration_writer_directory(&state.writer, |root_dir| {
                        Ok((|| {
                            state
                                .root
                                .inner
                                .create_fixed(
                                    &state.writer,
                                    NATIVE_MARKER_FILE,
                                    self.prepared.marker(),
                                    &|_| {},
                                )
                                .map_err(|_| JournalError::Unknown)?;
                            let now = state
                                .root
                                .read_raw("state.json", NATIVE_STATE_BYTES)
                                .map_err(|_| JournalError::Unknown)?;
                            if now.observation() != before.observation()
                                || now.bytes() != before.bytes()
                            {
                                return Err(JournalError::Unknown);
                            }
                            // Cooperative conditional replace under the original
                            // writer; this is not hostile same-UID compare-and-swap.
                            nix::fcntl::renameat(
                                directory,
                                temporary.as_str(),
                                root_dir,
                                "state.json",
                            )
                            .map_err(|_| JournalError::Unknown)?;
                            let current = open_at(
                                root_dir,
                                OsStr::new("state.json"),
                                OFlag::O_RDONLY,
                                Mode::empty(),
                            )
                            .map_err(|_| JournalError::Unknown)?;
                            sync_private_file(&current).map_err(|_| JournalError::Unknown)?;
                            sync_private_directory(root_dir).map_err(|_| JournalError::Unknown)?;
                            sync_private_directory(directory).map_err(|_| JournalError::Unknown)?;
                            Ok(())
                        })())
                    })
                    .map_err(|_| JournalError::Unknown)??;
                Ok(())
            })?;
            let raw = state
                .root
                .read_raw("state.json", NATIVE_STATE_BYTES)
                .map_err(|_| JournalError::Unknown)?;
            if raw.bytes() != self.prepared.target() {
                return Err(JournalError::Unknown);
            }
            Ok(raw.observation().clone())
        });
        match result {
            Ok(pin) => self.canonical_pin = Some(pin),
            Err(error) => {
                self.unknown = true;
                return Err(error);
            }
        }
        if let Err(error) = self.validate_applied() {
            self.unknown = true;
            return Err(error);
        }
        if let Err(error) =
            journal.append_cutover_phase(self.maintenance, &self.prepared, DurableStage::Applied)
        {
            self.unknown = true;
            return Err(error);
        }
        Ok(())
    }
    pub(crate) fn validate_applied(&self) -> JournalResult<()> {
        self.prerequisites()?;
        let pin = self.canonical_pin.as_ref().ok_or(JournalError::Conflict)?;
        self.owner.with_maintenance(self.maintenance, |state| {
            let raw = state
                .root
                .read_raw("state.json", NATIVE_STATE_BYTES)
                .map_err(|_| JournalError::Unknown)?;
            let marker = state
                .root
                .read_raw(
                    NATIVE_MARKER_FILE,
                    styx_contracts::native_management::NATIVE_MARKER_BYTES,
                )
                .map_err(|_| JournalError::Unknown)?;
            if raw.observation() != pin
                || raw.bytes() != self.prepared.target()
                || marker.bytes() != self.prepared.marker()
            {
                return Err(JournalError::Unknown);
            }
            let marker =
                native_state::decode_marker(marker.bytes()).map_err(|_| JournalError::Unknown)?;
            native_state::decode_state(raw.bytes(), &marker).map_err(|_| JournalError::Unknown)?;
            Ok(())
        })
    }
}

use crate::migration::{
    mac_exec_validation::MacCandidateExecProbe, mac_pair_validation::MacPairReadinessProbe,
};
use styx_core::management::transaction::JournalReceipt;

/// Same live original effects and writer; no Clone/Serde/public constructor.
/// This capability does not come from reopening a committed JSON receipt.
#[must_use]
pub(crate) struct MacCommittedCutover<'guard, 'effects, 'materials> {
    guard: &'guard MacCanonicalCutover<'effects, 'materials>,
    committed: JournalReceipt,
    local_sha256: Sha256Digest,
    pair_sha256: Sha256Digest,
}

impl<'effects, 'materials> MacCanonicalCutover<'effects, 'materials> {
    fn validation_bytes(
        &self,
        local: &mut MacCandidateExecProbe<'_, '_, '_, '_>,
        pair: &mut MacPairReadinessProbe<'_, '_, '_, '_>,
    ) -> JournalResult<(Vec<u8>, Vec<u8>)> {
        // Signed loader compatibility, supplied by the root's R72 release
        // contract change; supporting StateV2 alone does not read report v2.
        if !self
            .candidate
            .manifest()
            .minimum_reader
            .supports_host_admission_v2()
        {
            return Err(JournalError::Conflict);
        }
        self.validate_applied()?;
        let local = local
            .validated_report_for(self)
            .map_err(|_| JournalError::Unknown)?;
        let pair = pair
            .validated_report_for(self)
            .map_err(|_| JournalError::Unknown)?;
        self.validate_applied()?;
        Ok((local, pair))
    }

    /// No probe execution here. Both actual attempts have already completed and
    /// joined. Resuming this method only reads/re-syncs the original chain and
    /// appends missing durable stages; it never replays a nonce or connection.
    pub(crate) fn commit_validated<'guard>(
        &'guard self,
        journal: &mut OwnedManagementJournal,
        local: &mut MacCandidateExecProbe<'_, '_, '_, '_>,
        pair: &mut MacPairReadinessProbe<'_, '_, '_, '_>,
    ) -> JournalResult<MacCommittedCutover<'guard, 'effects, 'materials>> {
        if !journal.cutover_prepared_matches(&self.prepared) {
            return Err(JournalError::Conflict);
        }
        let (local_raw, pair_raw) = self.validation_bytes(local, pair)?;
        let mut original =
            journal.resync_native_cutover(self.maintenance, self.transaction_id())?;
        if original.intent != *self.prepared.intent()
            || !matches!(
                original.last_stage,
                DurableStage::Applied | DurableStage::Verified | DurableStage::Committed
            )
        {
            return Err(JournalError::Conflict);
        }
        // Existing bytes must be EXACTLY this original completed probe's bytes.
        // Absent attachments may only be appended at Applied, by the same writer.
        match original.validation_report() {
            Some(raw) if raw == local_raw => {}
            None if original.last_stage == DurableStage::Applied => {
                journal.record_cutover_validation(self.maintenance, &self.prepared, &local_raw)?;
            }
            _ => return Err(JournalError::Conflict),
        }
        match original.paired_validation_report() {
            Some(raw) if raw == pair_raw => {}
            None if original.last_stage == DurableStage::Applied => {
                journal.record_cutover_paired_validation(
                    self.maintenance,
                    &self.prepared,
                    &pair_raw,
                )?;
            }
            _ => return Err(JournalError::Conflict),
        }
        original = journal.resync_native_cutover(self.maintenance, self.transaction_id())?;
        if original.validation_report() != Some(local_raw.as_slice())
            || original.paired_validation_report() != Some(pair_raw.as_slice())
        {
            return Err(JournalError::Unknown);
        }
        if original.last_stage == DurableStage::Applied {
            self.require_same_validation(local, pair, &local_raw, &pair_raw)?;
            journal.append_cutover_phase(
                self.maintenance,
                &self.prepared,
                DurableStage::Verified,
            )?;
            original = journal.resync_native_cutover(self.maintenance, self.transaction_id())?;
        }
        if original.last_stage == DurableStage::Verified {
            self.require_same_validation(local, pair, &local_raw, &pair_raw)?;
            journal.append_cutover_phase(
                self.maintenance,
                &self.prepared,
                DurableStage::Committed,
            )?;
            original = journal.resync_native_cutover(self.maintenance, self.transaction_id())?;
        }
        if original.last_stage != DurableStage::Committed {
            return Err(JournalError::Unknown);
        }
        self.require_same_validation(local, pair, &local_raw, &pair_raw)?;
        let proof = MacCommittedCutover {
            guard: self,
            committed: original.phases.last().ok_or(JournalError::Unknown)?.clone(),
            local_sha256: Sha256Digest::of_bytes(&local_raw),
            pair_sha256: Sha256Digest::of_bytes(&pair_raw),
        };
        // Do not nest an API that reacquires the same mutex in this closure.
        self.owner.with_maintenance(self.maintenance, |state| {
            proof.validate_locked(journal, state)
        })?;
        Ok(proof)
    }
    fn require_same_validation(
        &self,
        local: &mut MacCandidateExecProbe<'_, '_, '_, '_>,
        pair: &mut MacPairReadinessProbe<'_, '_, '_, '_>,
        local_raw: &[u8],
        pair_raw: &[u8],
    ) -> JournalResult<()> {
        let current = self.validation_bytes(local, pair)?;
        if current.0 != local_raw || current.1 != pair_raw {
            return Err(JournalError::Unknown);
        }
        Ok(())
    }
}
impl MacCommittedCutover<'_, '_, '_> {
    pub(in crate::store) fn matches_fenced_owner(
        &self,
        owner: &OwnedConfigurationRoot,
        root: &RootIdentity,
        transaction: Option<&TransactionId>,
    ) -> bool {
        self.guard.owner.same_authority(owner)
            && self.guard.maintenance.matches(owner)
            && self.guard.prepared.matches_owner(owner)
            && root_identity_from_native(self.guard.config_root())
                .is_ok_and(|actual| &actual == root)
            && transaction == Some(self.guard.transaction_id())
    }
    fn validate_locked(
        &self,
        journal: &OwnedManagementJournal,
        state: &crate::store::configuration::ConfigurationState,
    ) -> JournalResult<()> {
        state.require_native_maintenance(self.guard.transaction_id())?;
        if !journal.cutover_prepared_matches(&self.guard.prepared) {
            return Err(JournalError::Conflict);
        }
        let raw = state
            .root
            .read_raw("state.json", NATIVE_STATE_BYTES)
            .map_err(|_| JournalError::Unknown)?;
        if Some(raw.observation()) != self.guard.canonical_pin.as_ref()
            || raw.bytes() != self.guard.prepared.target()
        {
            return Err(JournalError::Unknown);
        }
        journal.validate_committed_cutover_locked(state, &self.guard.prepared, &self.committed)?;
        let inventory = journal.observe_locked(state)?;
        if inventory.has_unresolved_legacy_handoffs()
            || inventory.high_water != self.guard.prepared.intent().sequence
            || inventory.committed_cutover_anchor
                != Some((
                    self.guard.prepared.intent().sequence,
                    self.guard.target_sha256(),
                ))
            || inventory.transactions.iter().any(|transaction| {
                transaction.prepared.is_none()
                    || transaction
                        .phase_receipts
                        .last()
                        .is_none_or(|phase| phase.stage != DurableStage::Committed)
            })
        {
            return Err(JournalError::Conflict);
        }
        Ok(())
    }
    /// Consume this capability only under its original retained owner/fence.
    /// On any failure all original objects remain with the outer owner; this does
    /// not reconstruct fresh probes, drop/reopen a writer, or clear Unknown.
    pub(crate) fn release_admission(
        self,
        journal: &OwnedManagementJournal,
        local: &mut MacCandidateExecProbe<'_, '_, '_, '_>,
        pair: &mut MacPairReadinessProbe<'_, '_, '_, '_>,
    ) -> JournalResult<()> {
        let (local_raw, pair_raw) = self.guard.validation_bytes(local, pair)?;
        if Sha256Digest::of_bytes(&local_raw) != self.local_sha256
            || Sha256Digest::of_bytes(&pair_raw) != self.pair_sha256
        {
            return Err(JournalError::Conflict);
        }
        self.guard
            .owner
            .with_maintenance(self.guard.maintenance, |state| {
                self.validate_locked(journal, state)?;
                state.finish_mac_cutover(&self, &self.guard.owner)
            })
    }
}
