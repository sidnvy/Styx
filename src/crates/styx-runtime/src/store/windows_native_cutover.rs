//! Windows canonical publication under the original configuration writer.
//! This guard retains actual C/token HANDLE custody. Final settlement consumes
//! the same completed Exec/Pair probes through the shared native commit stage.
use super::*;
use crate::{
    foreground::profile::OriginalNativePairMaterials,
    platform::windows_legacy_observation::WindowsLegacyObservation,
    release::VerifiedNativeRelease,
    store::{
        ConfigurationMaintenance, OwnedConfigurationRoot,
        management::{
            OwnedManagementJournal,
            cutover::{NativeCutoverHistoryInputs, NativeCutoverInputs, PreparedCutover},
            handoff::LegacyGuardsHeld,
        },
        native_root::NATIVE_MARKER_FILE,
        native_state,
        secure_journal::{JournalError, JournalResult, files},
    },
};
use styx_contracts::{
    identity::{Sha256Digest, TransactionId},
    native_management::{NATIVE_STATE_BYTES, NativePreservedHostPair, NativeRootIdentity},
    native_release::NativeReleaseScope,
};
use styx_core::management::transaction::DurableStage;

fn original_root(identity: &NativeRootIdentity) -> JournalResult<RootIdentity> {
    match identity {
        NativeRootIdentity::Windows {
            volume_serial,
            file_id,
            owner_sid,
        } => Ok(RootIdentity::Windows {
            volume_serial: *volume_serial,
            file_id: *file_id,
            owner_sid: owner_sid.clone(),
        }),
        _ => Err(JournalError::Conflict),
    }
}

/// Borrow the existing OS effects as one scope, never a serialized admission.
/// The owning producer must retain these objects inside its non-abortable job.
/// Construction only groups references; prepare revalidates every actual fact.
pub(in crate::store) struct WindowsCutoverCustody<'scope> {
    owner: OwnedConfigurationRoot,
    effects: &'scope WindowsBootRecoveryEffects,
    held: &'scope LegacyGuardsHeld,
    observation: &'scope WindowsLegacyObservation,
    token: &'scope WindowsTokenRetirement,
    host: &'scope PrivateRoot,
}
impl<'scope> WindowsCutoverCustody<'scope> {
    pub(in crate::store) fn new(
        owner: OwnedConfigurationRoot,
        effects: &'scope WindowsBootRecoveryEffects,
        held: &'scope LegacyGuardsHeld,
        observation: &'scope WindowsLegacyObservation,
        token: &'scope WindowsTokenRetirement,
        host: &'scope PrivateRoot,
    ) -> Self {
        Self {
            owner,
            effects,
            held,
            observation,
            token,
            host,
        }
    }
}

/// Capture while the original token still exists, before opening its writable
/// retirement HANDLE. This is protected material DATA, never settlement proof.
pub(in crate::store) struct WindowsCutoverPlan<'a, 'm> {
    materials: &'a OriginalNativePairMaterials<'m>,
    pair: NativePreservedHostPair,
    publisher: Sha256Digest,
    before_sha256: Sha256Digest,
}
impl<'a, 'm> WindowsCutoverPlan<'a, 'm> {
    pub(in crate::store) fn capture(
        materials: &'a OriginalNativePairMaterials<'m>,
        preservation_sha256: Sha256Digest,
    ) -> JournalResult<Self> {
        materials.revalidate().map_err(|_| JournalError::Unknown)?;
        let pair = materials
            .pair_binding(preservation_sha256)
            .map_err(|_| JournalError::Unknown)?;
        original_root(&pair.config_root)?;
        original_root(&pair.host_root)?;
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

    /// Only the actual retained OS effects may prepare this publication. No
    /// report, caller boolean or second writer can replace their custody.
    pub(in crate::store) fn prepare<'scope>(
        self,
        custody: WindowsCutoverCustody<'scope>,
        journal: &mut OwnedManagementJournal,
        state_dir: &Path,
        inputs: NativeCutoverInputs,
        candidate: Arc<VerifiedNativeRelease>,
    ) -> JournalResult<WindowsCanonicalCutover<'scope, 'm>>
    where
        'a: 'scope,
    {
        let WindowsCutoverCustody {
            owner,
            effects,
            held,
            observation,
            token,
            host,
        } = custody;
        let maintenance = effects.maintenance();
        let expected_pair =
            serde_json::to_vec(&self.pair).map_err(|_| JournalError::InvalidInput)?;
        // This production port is the preserved remote Host pair. Local Gateway
        // activation needs its own real endpoint/service consumer, not a fake CA.
        let NativeCutoverHistoryInputs::PreservedHostPair { bindings } = &inputs.history else {
            return Err(JournalError::Unsupported);
        };
        if inputs.endpoint.is_some()
            || bindings != &expected_pair
            || Sha256Digest::of_bytes(&inputs.before) != self.before_sha256
            || Sha256Digest::of_bytes(&inputs.preservation) != self.pair.preservation_sha256
            || !maintenance.matches(&owner)
            || !journal.configuration_root().same_authority(&owner)
            || !journal.owner_recovery_prepared_matches(held.prepared())
            || self.pair.transaction_id != *maintenance.transaction_id()
            || host.identity() != original_root(&self.pair.host_root)?
            || self.publisher.to_hex() != candidate.report().publisher_spki_sha256
        {
            return Err(JournalError::Conflict);
        }
        candidate.revalidate().map_err(|_| JournalError::Unknown)?;
        if candidate.report().target != "x86_64-pc-windows-msvc"
            || candidate.manifest().scope != NativeReleaseScope::RuntimeCandidate
            || !candidate
                .manifest()
                .minimum_reader
                .supports_host_admission_v2()
        {
            return Err(JournalError::Unsupported);
        }
        effects.validate_cutover_custody(&owner, held, observation)?;
        token.validate_cutover_binding(&owner, maintenance, &self.pair, &candidate)?;
        self.materials
            .revalidate_preserved_materials()
            .map_err(|_| JournalError::Unknown)?;
        owner.with_maintenance(maintenance, |state| {
            if state.root.identity() != original_root(&self.pair.config_root)?
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
        let prepared = journal.prepare_native_cutover(maintenance, inputs, candidate.clone())?;
        effects.validate_cutover_custody(&owner, held, observation)?;
        token.validate_cutover_binding(&owner, maintenance, &self.pair, &candidate)?;
        self.materials
            .revalidate_preserved_materials()
            .map_err(|_| JournalError::Unknown)?;
        Ok(WindowsCanonicalCutover {
            owner,
            maintenance,
            prepared,
            pair: self.pair,
            candidate,
            materials: self.materials,
            effects,
            held,
            observation,
            token,
            canonical_pin: None,
            attempted: false,
            unknown: false,
        })
    }
}

/// Retain this SAME object and its borrowed original effects on error. It grants
/// maintenance validation only after actual apply; no ordinary dispatch/commit.
pub(crate) struct WindowsCanonicalCutover<'effects, 'materials> {
    owner: OwnedConfigurationRoot,
    maintenance: &'effects ConfigurationMaintenance,
    prepared: PreparedCutover<NativeRootIdentity>,
    pair: NativePreservedHostPair,
    candidate: Arc<VerifiedNativeRelease>,
    materials: &'effects OriginalNativePairMaterials<'materials>,
    effects: &'effects WindowsBootRecoveryEffects,
    held: &'effects LegacyGuardsHeld,
    observation: &'effects WindowsLegacyObservation,
    token: &'effects WindowsTokenRetirement,
    canonical_pin: Option<FileObservation>,
    attempted: bool,
    unknown: bool,
}
impl WindowsCanonicalCutover<'_, '_> {
    pub(crate) fn matches_owner(&self, owner: &OwnedConfigurationRoot) -> bool {
        self.owner.same_authority(owner)
            && self.maintenance.matches(owner)
            && self.prepared.matches_owner(owner)
    }
    pub(crate) fn config_root(&self) -> &NativeRootIdentity {
        &self.pair.config_root
    }
    pub(crate) fn host_root(&self) -> &NativeRootIdentity {
        &self.pair.host_root
    }
    pub(crate) fn transaction_id(&self) -> &TransactionId {
        &self.pair.transaction_id
    }
    pub(crate) fn target_sha256(&self) -> Sha256Digest {
        self.prepared.intent().target_state_sha256
    }
    pub(crate) fn before(&self) -> &[u8] {
        self.prepared.before()
    }
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
        if host.identity() != original_root(&self.pair.host_root)? {
            return Err(JournalError::Conflict);
        }
        let bytes = self
            .token
            .read_retired_for_cutover(&self.owner, self.maintenance, host)?;
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
        self.effects
            .validate_cutover_custody(&self.owner, self.held, self.observation)?;
        self.token.validate_cutover_binding(
            &self.owner,
            self.maintenance,
            &self.pair,
            &self.candidate,
        )?;
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
        let original = journal.resync_native_cutover(self.maintenance, self.transaction_id())?;
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
                let temporary = format!("txn-{}.state-temporary", self.transaction_id().as_str());
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
                    .create_fixed(
                        &state.writer,
                        NATIVE_MARKER_FILE,
                        self.prepared.marker(),
                        &|_| {},
                    )
                    .map_err(|_| JournalError::Unknown)?;
                // Original source HANDLE/fileID and before observation are
                // checked by the existing native Windows publication port.
                state
                    .root
                    .inner
                    .replace_native_state_from_journal(
                        &state.writer,
                        (directory, &temporary),
                        &before,
                        self.prepared.target(),
                        &|_| {},
                    )
                    .map_err(|_| JournalError::Unknown)
            })?;
            let current = state
                .root
                .read_raw("state.json", NATIVE_STATE_BYTES)
                .map_err(|_| JournalError::Unknown)?;
            if current.bytes() != self.prepared.target() {
                return Err(JournalError::Unknown);
            }
            Ok(current.observation().clone())
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
            if state.root.identity() != original_root(&self.pair.config_root)? {
                return Err(JournalError::Conflict);
            }
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

use original_root as committed_root_identity;
type NativeCanonicalCutover<'effects, 'materials> = WindowsCanonicalCutover<'effects, 'materials>;
#[path = "native_cutover_commit.rs"]
mod committed;
pub(crate) use committed::NativeCommittedCutover;
