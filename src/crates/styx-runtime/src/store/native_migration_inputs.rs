//! Shared preserved-pair migration inputs. These validate original retained
//! bytes and render the existing native contract; they grant no OS custody.
use super::*;
use crate::{
    foreground::profile::OriginalNativePairMaterials,
    release::VerifiedNativeRelease,
    store::{
        management::{
            OwnedManagementJournal,
            cutover::{NativeCutoverHistoryInputs, NativeCutoverInputs},
            handoff::{self, LegacyGuardsHeld, NativeRetirementIntent, OwnerRecoveryStage},
        },
        secure_journal::{JournalError, JournalResult, files},
    },
};
use serde_json::value::RawValue;
use std::collections::BTreeMap;
use styx_contracts::{identity::Sha256Digest, management::ReaderContract, native_management::*};
#[cfg(target_os = "macos")]
const SCOPE_BINDINGS_KIND: &str = "mac_original_previous_boot_guards_held";
#[cfg(target_os = "windows")]
const SCOPE_BINDINGS_KIND: &str = "windows_original_previous_boot_guards_held";

#[derive(Serialize)]
pub(in crate::store) struct PreservationRow {
    path: PathBuf,
    sha256: Sha256Digest,
    bytes: u64,
    observation: FileObservation,
}
struct PreservationPin {
    root: PrivateRoot,
    name: PathBuf,
    observation: FileObservation,
    digest: Sha256Digest,
    max: usize,
}
pub(in crate::store) struct Preservation {
    pub(in crate::store) rows: Vec<PreservationRow>,
    pins: Vec<PreservationPin>,
}
impl Preservation {
    pub(in crate::store) fn capture(
        materials: &OriginalNativePairMaterials<'_>,
    ) -> JournalResult<Self> {
        materials.revalidate().map_err(|_| JournalError::Unknown)?;
        let entries = materials.preservation_entries();
        if entries.is_empty() || entries.len() > 128 {
            return Err(JournalError::BudgetExceeded);
        }
        let mut rows = BTreeMap::new();
        let mut pins = Vec::new();
        for entry in entries {
            let root = PrivateRoot::open(entry.path.parent().ok_or(JournalError::InvalidInput)?)
                .map_err(|_| JournalError::Unknown)?;
            let name = PathBuf::from(entry.path.file_name().ok_or(JournalError::InvalidInput)?);
            let max = usize::try_from(entry.bytes)
                .map_err(|_| JournalError::BudgetExceeded)?
                .checked_add(1)
                .ok_or(JournalError::BudgetExceeded)?;
            if max > NATIVE_STATE_BYTES + 1 {
                return Err(JournalError::BudgetExceeded);
            }
            let raw = root
                .read_raw(&name, max)
                .map_err(|_| JournalError::Unknown)?;
            if Sha256Digest::of_bytes(raw.bytes()) != entry.sha256
                || raw.bytes().len() as u64 != entry.bytes
            {
                return Err(JournalError::Unknown);
            }
            if let Some(old) = rows.get(&entry.path) {
                let old: &PreservationRow = old;
                if old.sha256 != entry.sha256 || old.observation != *raw.observation() {
                    return Err(JournalError::Unknown);
                }
            } else {
                rows.insert(
                    entry.path.clone(),
                    PreservationRow {
                        path: entry.path.clone(),
                        sha256: entry.sha256,
                        bytes: entry.bytes,
                        observation: raw.observation().clone(),
                    },
                );
            }
            pins.push(PreservationPin {
                root,
                name,
                observation: raw.observation().clone(),
                digest: entry.sha256,
                max,
            });
        }
        let value = Self {
            rows: rows.into_values().collect(),
            pins,
        };
        value.validate_original()?;
        materials.revalidate().map_err(|_| JournalError::Unknown)?;
        Ok(value)
    }
    pub(in crate::store) fn validate_original(&self) -> JournalResult<()> {
        for pin in &self.pins {
            let raw = pin
                .root
                .read_raw(&pin.name, pin.max)
                .map_err(|_| JournalError::Unknown)?;
            if raw.observation() != &pin.observation
                || Sha256Digest::of_bytes(raw.bytes()) != pin.digest
            {
                return Err(JournalError::Unknown);
            }
        }
        Ok(())
    }
}
pub(in crate::store) fn scope_bindings(
    owner: &OwnedConfigurationRoot,
    maintenance: &ConfigurationMaintenance,
    journal: &OwnedManagementJournal,
    held: &LegacyGuardsHeld,
) -> JournalResult<Vec<u8>> {
    owner.with_maintenance(maintenance, |state| journal.with_directory_locked(state, |directory| {
        let scan = files::scan(directory, journal.budget())?;
        let records = handoff::scan_owner_recoveries(&scan)?;
        if records.records.len() != 1 { return Err(JournalError::Conflict); }
        let original = &records.records[0];
        if original.stage() != Some(OwnerRecoveryStage::GuardsHeld) || original.intent != *held.prepared().intent() { return Err(JournalError::Conflict); }
        serde_json::to_vec(&serde_json::json!({"schema":1,"kind":SCOPE_BINDINGS_KIND,"transaction_id":original.intent.transaction_id,"config_root":original.intent.config_root,"original_recovery_intent_sha256":Sha256Digest::of_bytes(&original.raw_intent),"guard_posts":original.guards_held_posts().ok_or(JournalError::Conflict)?,"historical_outcome":"unknown_not_replayed"})).map_err(|_| JournalError::InvalidInput)
    }))
}
fn raw<T: Serialize>(value: &T) -> JournalResult<Box<RawValue>> {
    RawValue::from_string(serde_json::to_string(value).map_err(|_| JournalError::InvalidInput)?)
        .map_err(|_| JournalError::InvalidInput)
}
pub(in crate::store) fn migration_marker(
    retirement: &NativeRetirementIntent,
) -> JournalResult<NativeRootMarker> {
    let mut entropy = [0u8; 32];
    getrandom::fill(&mut entropy).map_err(|_| JournalError::Unknown)?;
    Ok(NativeRootMarker {
        schema: NATIVE_MARKER_SCHEMA,
        kind: NativeRootKind::StyxConfigurationRoot,
        runtime_format: NativeRuntimeFormat::NativeRustV1,
        root_identity: retirement.config_root.clone(),
        scope_generation: Sha256Digest::from_bytes(entropy),
        reader_floor: ReaderContract::NativeMigratedStateV2,
    })
}
pub(in crate::store) fn render_target(
    candidate: &VerifiedNativeRelease,
    retirement: &NativeRetirementIntent,
    marker: &NativeRootMarker,
    retired_sha256: Sha256Digest,
    pair: &NativePreservedHostPair,
    preservation: Vec<u8>,
    scopes: Vec<u8>,
    owners: Box<RawValue>,
    before: &[u8],
    desired: NativeDesired,
) -> JournalResult<NativeCutoverInputs> {
    if marker.root_identity != retirement.config_root
        || marker.reader_floor != ReaderContract::NativeMigratedStateV2
    {
        return Err(JournalError::Conflict);
    }
    let pair_raw = serde_json::to_vec(pair).map_err(|_| JournalError::InvalidInput)?;
    let binding = NativeMigrationBindingV2 {
        schema: 2,
        transaction_id: retirement.transaction_id.clone(),
        root_identity: retirement.config_root.clone(),
        original_state_sha256: retirement.before_state_sha256,
        retired_receipt_sha256: retired_sha256,
        candidate_manifest_sha256: retirement.candidate_manifest_sha256,
        publisher_spki_sha256: retirement.publisher_spki_sha256,
        preservation_sha256: Sha256Digest::of_bytes(&preservation),
        scope_bindings_sha256: Sha256Digest::of_bytes(&scopes),
        original_token_relative_path: retirement
            .token_destination()
            .to_str()
            .ok_or(JournalError::Unsupported)?
            .to_owned(),
        host_pair_sha256: Sha256Digest::of_bytes(&pair_raw),
        endpoint_mode: NativeMigrationEndpointMode::PreservedRemote,
        history: NativeMigrationHistory::PreservedHostPair {
            source_bindings_sha256: Sha256Digest::of_bytes(&pair_raw),
        },
    };
    let original = RawValue::from_string(
        std::str::from_utf8(before)
            .map_err(|_| JournalError::InvalidInput)?
            .to_owned(),
    )
    .map_err(|_| JournalError::InvalidInput)?;
    let extensions = BTreeMap::from([
        ("original_legacy_state".into(), original),
        (NATIVE_MIGRATION_V2_KEY.into(), raw(&binding)?),
        (
            "runtime_selection_v1".into(),
            raw(&candidate
                .runtime_selection()
                .map_err(|_| JournalError::Unknown)?)?,
        ),
        ("legacy_owner_bindings_v2".into(), owners),
    ]);
    let target = NativeState {
        schema: NATIVE_STATE_SCHEMA,
        kind: NativeStateKind::StyxDesiredState,
        runtime_format: NativeRuntimeFormat::NativeRustV1,
        reader_contract: marker.reader_floor,
        scope_generation: marker.scope_generation,
        deployment_raw_sha256: retirement.deployment_raw_sha256,
        mode: NativeDeploymentMode::JoinExisting,
        revision: 1,
        last_transaction: Some(NativeStateTransaction {
            transaction_id: retirement.transaction_id.clone(),
            sequence: retirement.sequence,
        }),
        desired,
        migration: None,
        extensions,
    };
    styx_core::management::state::validate_state(&target, &marker)
        .map_err(|_| JournalError::InvalidInput)?;
    Ok(NativeCutoverInputs {
        history: NativeCutoverHistoryInputs::PreservedHostPair { bindings: pair_raw },
        endpoint_mode: NativeMigrationEndpointMode::PreservedRemote,
        preservation,
        scope_bindings: scopes,
        marker: serde_json::to_vec(&marker).map_err(|_| JournalError::InvalidInput)?,
        before: before.to_vec(),
        target: serde_json::to_vec(&target).map_err(|_| JournalError::InvalidInput)?,
        endpoint: None,
    })
}
