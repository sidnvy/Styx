//! Darwin canonical publication under the ORIGINAL configuration writer.
//! This retains physical prerequisites, not a receipt-derived settlement claim.
//! No Verified/Committed phase or admission-release port is exposed here.
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
    inputs: NativeCutoverInputs,
}
impl<'a, 'm> MacCutoverPlan<'a, 'm> {
    pub(in crate::store) fn capture(
        materials: &'a OriginalNativePairMaterials<'m>,
        inputs: NativeCutoverInputs,
    ) -> JournalResult<Self> {
        materials.revalidate().map_err(|_| JournalError::Unknown)?;
        let pair = materials
            .pair_binding(Sha256Digest::of_bytes(&inputs.preservation))
            .map_err(|_| JournalError::Unknown)?;
        let publisher = materials
            .publisher_sha256()
            .map_err(|_| JournalError::Unknown)?;
        if materials
            .before_sha256()
            .map_err(|_| JournalError::Unknown)?
            != Sha256Digest::of_bytes(&inputs.before)
        {
            return Err(JournalError::Conflict);
        }
        let bytes = serde_json::to_vec(&pair).map_err(|_| JournalError::InvalidInput)?;
        let supplied = match &inputs.history {
            NativeCutoverHistoryInputs::PreservedHostPair { bindings }
            | NativeCutoverHistoryInputs::ImportedLocalGateway { bindings, .. } => bindings,
        };
        if supplied != &bytes {
            return Err(JournalError::Conflict);
        }
        materials.revalidate().map_err(|_| JournalError::Unknown)?;
        Ok(Self {
            materials,
            pair,
            publisher,
            inputs,
        })
    }

    /// Only an actual retained Darwin guard effect and actual retired-token pin
    /// can reach publication. The journal independently checks the retired chain.
    pub(in crate::store) fn prepare(
        self,
        owner: OwnedConfigurationRoot,
        maintenance: &'a ConfigurationMaintenance,
        journal: &mut OwnedManagementJournal,
        guards: &'a MacBootRecoveryEffects,
        held: &'a LegacyGuardsHeld,
        token: &'a MacTokenRetirement,
        host: &'a PrivateRoot,
        state_dir: &Path,
        candidate: Arc<VerifiedNativeRelease>,
    ) -> JournalResult<MacCanonicalCutover<'a, 'm>> {
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
            let marker = native_state::decode_marker(&self.inputs.marker)
                .map_err(|_| JournalError::InvalidInput)?;
            let target = native_state::decode_state(&self.inputs.target, &marker)
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
        let prepared = journal.prepare_native_cutover(maintenance, self.inputs, candidate)?;
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
