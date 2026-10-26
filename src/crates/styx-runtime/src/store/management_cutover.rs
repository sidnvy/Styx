//! First native conversion as a successor of the original credential retirement.
//! These are journal facts, never physical settlement, activation, or authority
//! to clear the shared management fence. Original bytes are never reconstructed.
use super::*;
use crate::store::{
    RootIdentity,
    configuration::ConfigurationState,
    native_state::{decode_marker, decode_state},
    secure_journal::{JournalObservation, files},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
};
use styx_contracts::{
    management::ReaderContract,
    native_management::{NativeDeploymentMode, NativeGatewayEndpointBinding, NativeRootIdentity},
};
use styx_core::management::transaction::{
    AppliedFacts, CommitFacts, ManagementTransaction, PreparedFacts, VerificationFacts,
};

use zeroize::Zeroizing;

const MAX_RAW: usize = 1024 * 1024;
const MAX_INTENT: usize = 16 * 1024;
const MAX_VALIDATION: usize = 16 * 1024;
const MARKER: &str = ".styx-native-root-v1.json";
const ATTACHMENTS: [&str; 5] = ["preservation", "scopes", "marker", "before", "target"];

pub(crate) struct CutoverEndpointInputs {
    pub binding: Vec<u8>,
    pub chain: Vec<u8>,
    pub key: Zeroizing<Vec<u8>>,
}
#[derive(Clone)]
pub(in crate::store) struct CutoverEndpointMaterials {
    binding: Vec<u8>,
    chain: Vec<u8>,
    key: Zeroizing<Vec<u8>>,
}

pub(crate) struct CutoverInputs {
    pub history_baseline_sha256: Sha256Digest,
    pub history_committed_sha256: Sha256Digest,
    pub preservation: Vec<u8>,
    pub scope_bindings: Vec<u8>,
    pub marker: Vec<u8>,
    pub before: Vec<u8>,
    pub target: Vec<u8>,
    pub endpoint: Option<CutoverEndpointInputs>,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::store) enum CutoverKind {
    LegacyRuntimeCutover,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::store) struct CutoverIntent<R = handoff::RetirementLinuxRoot> {
    pub schema: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_mode: Option<styx_contracts::native_management::NativeMigrationEndpointMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history: Option<styx_contracts::native_management::NativeMigrationHistory>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_pair_sha256: Option<Sha256Digest>,
    pub kind: CutoverKind,
    pub transaction_id: TransactionId,
    pub sequence: u64,
    pub retired_record_sha256: Sha256Digest,
    pub config_root: R,
    pub host_root: R,
    pub candidate_manifest_sha256: Sha256Digest,
    pub publisher_spki_sha256: Sha256Digest,
    pub deployment_raw_sha256: Sha256Digest,
    pub before_state_sha256: Sha256Digest,
    pub target_state_sha256: Sha256Digest,
    pub reader: ReaderContract,
    pub retirement_preservation_sha256: Sha256Digest,
    pub preservation_sha256: Sha256Digest,
    pub scope_bindings_sha256: Sha256Digest,
    pub marker_sha256: Sha256Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_baseline_sha256: Option<Sha256Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_committed_sha256: Option<Sha256Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_binding_sha256: Option<Sha256Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_chain_sha256: Option<Sha256Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_key_sha256: Option<Sha256Digest>,
}
impl<R> CutoverIntent<R> {
    pub(in crate::store) fn management_intent(&self) -> DesiredStateCommit {
        DesiredStateCommit {
            transaction_id: self.transaction_id.clone(),
            sequence: self.sequence,
            deployment_raw_sha256: self.deployment_raw_sha256,
            before_state_sha256: self.before_state_sha256,
            target_state_sha256: self.target_state_sha256,
            reader: self.reader,
        }
    }
}
/// Private data observation, not a retained writer/durability capability.
#[derive(Clone)]
pub(in crate::store) struct OriginalCutover<R = handoff::RetirementLinuxRoot> {
    pub intent: CutoverIntent<R>,
    pub raw_intent: Vec<u8>,
    pub preservation: Vec<u8>,
    pub scope_bindings: Vec<u8>,
    pub marker: Vec<u8>,
    pub before: Vec<u8>,
    pub target: Vec<u8>,
    pub phases: Vec<JournalReceipt>,
    pub last_stage: DurableStage,
    pub host_pair: Option<Vec<u8>>,
    pub validation: Option<Vec<u8>>,
    pub validation_sha256: Option<Sha256Digest>,
    pub paired_validation: Option<Vec<u8>>,
    pub paired_validation_sha256: Option<Sha256Digest>,
    pub endpoint: Option<CutoverEndpointMaterials>,
}
impl<R> OriginalCutover<R> {
    pub(in crate::store) fn paired_validation_report(&self) -> Option<&[u8]> {
        self.paired_validation.as_deref()
    }
    pub(in crate::store) fn validation_report(&self) -> Option<&[u8]> {
        self.validation.as_deref()
    }
    pub(in crate::store) fn endpoint_binding(&self) -> Option<&[u8]> {
        self.endpoint.as_ref().map(|e| e.binding.as_slice())
    }
    pub(in crate::store) fn endpoint_chain(&self) -> Option<&[u8]> {
        self.endpoint.as_ref().map(|e| e.chain.as_slice())
    }
    pub(in crate::store) fn endpoint_key(&self) -> Option<&[u8]> {
        self.endpoint.as_ref().map(|e| e.key.as_slice())
    }
}
pub(in crate::store) struct CutoverInventory {
    pub used: BTreeSet<String>,
    pub records: Vec<OriginalCutover>,
    pub native_records: Vec<OriginalCutover<NativeRootIdentity>>,
}
/// Move-owned preparation evidence; no Clone/Serde or arbitrary constructor.
pub(in crate::store) struct PreparedCutover<R = handoff::RetirementLinuxRoot> {
    owner: OwnedConfigurationRoot,
    namespace: (u64, u64),
    original: OriginalCutover<R>,
    candidate: Option<std::sync::Arc<crate::release::VerifiedNativeRelease>>,
}
impl<R> PreparedCutover<R> {
    fn validate_candidate(&self) -> JournalResult<()> {
        if self.original.intent.schema == 4 {
            let candidate = self.candidate.as_ref().ok_or(JournalError::Conflict)?;
            candidate.revalidate().map_err(|_| JournalError::Unknown)?;
            if candidate.report().manifest_sha256 != self.original.intent.candidate_manifest_sha256
                || candidate.report().publisher_spki_sha256
                    != self.original.intent.publisher_spki_sha256.to_hex()
                || !candidate
                    .manifest()
                    .minimum_reader
                    .supports_state_reader(ReaderContract::NativeMigratedStateV2)
            {
                return Err(JournalError::Conflict);
            }
        }
        Ok(())
    }
    pub(in crate::store) fn matches_owner(&self, owner: &OwnedConfigurationRoot) -> bool {
        self.owner.same_authority(owner)
    }
    pub(in crate::store) fn intent(&self) -> &CutoverIntent<R> {
        &self.original.intent
    }
    pub(in crate::store) fn before(&self) -> &[u8] {
        &self.original.before
    }
    pub(in crate::store) fn target(&self) -> &[u8] {
        &self.original.target
    }
    pub(in crate::store) fn marker(&self) -> &[u8] {
        &self.original.marker
    }
    pub(in crate::store) fn endpoint_binding(&self) -> Option<&[u8]> {
        self.original
            .endpoint
            .as_ref()
            .map(|e| e.binding.as_slice())
    }
    pub(in crate::store) fn endpoint_chain(&self) -> Option<&[u8]> {
        self.original.endpoint.as_ref().map(|e| e.chain.as_slice())
    }
    pub(in crate::store) fn endpoint_key(&self) -> Option<&[u8]> {
        self.original.endpoint.as_ref().map(|e| e.key.as_slice())
    }
    pub(in crate::store) fn journal(&self) -> &JournalReceipt {
        &self.original.phases[0]
    }
}
impl PreparedCutover<handoff::RetirementLinuxRoot> {
    pub(in crate::store) fn history_baseline_sha256(&self) -> Sha256Digest {
        self.original
            .intent
            .history_baseline_sha256
            .expect("validated legacy baseline")
    }
    pub(in crate::store) fn history_committed_sha256(&self) -> Sha256Digest {
        self.original
            .intent
            .history_committed_sha256
            .expect("validated legacy committed baseline")
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PhaseRecord<R = handoff::RetirementLinuxRoot> {
    schema: u16,
    intent: CutoverIntent<R>,
    raw_intent_sha256: Sha256Digest,
    stage: DurableStage,
    #[serde(deserialize_with = "required_option")]
    previous: Option<Sha256Digest>,
    canonical_raw_sha256: Sha256Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    validation_sha256: Option<Sha256Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    paired_validation_sha256: Option<Sha256Digest>,
}
fn required_option<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d)
}
/// Required bounded data header only. Additional report metadata is retained
/// verbatim in the private attachment; this decoder does not attest execution.
#[derive(Deserialize)]
struct ValidationHeader {
    schema: u8,
    transaction_id: TransactionId,
    candidate_manifest_sha256: Sha256Digest,
    exit_code: i32,
    liveness: styx_contracts::operation::ExecutionLiveness,
    drain: styx_contracts::operation::OutputDrain,
    executor_exited: bool,
    processes_exited: bool,
    reader_task_reaped: bool,
    stderr_task_reaped: bool,
    supervised_jobs_joined: bool,
    probe_task_joined: bool,
}
fn validate_report<R>(raw: &[u8], intent: &CutoverIntent<R>) -> JournalResult<()> {
    if raw.is_empty() || raw.len() > MAX_VALIDATION {
        return Err(JournalError::BudgetExceeded);
    }
    let report: ValidationHeader =
        serde_json::from_slice(raw).map_err(|_| JournalError::InvalidInput)?;
    if report.schema != 1
        || report.transaction_id != intent.transaction_id
        || report.candidate_manifest_sha256 != intent.candidate_manifest_sha256
        || report.exit_code != 0
        || report.liveness != styx_contracts::operation::ExecutionLiveness::Exited
        || report.drain != styx_contracts::operation::OutputDrain::Drained
        || !report.executor_exited
        || !report.processes_exited
        || !report.reader_task_reaped
        || !report.stderr_task_reaped
        || !report.supervised_jobs_joined
        || !report.probe_task_joined
    {
        return Err(JournalError::Conflict);
    }
    Ok(())
}
/// Data-only receipt check; only the upper opaque validator attests execution.
#[derive(Deserialize)]
struct PairedValidationHeader {
    schema: u8,
    transaction_id: TransactionId,
    candidate_manifest_sha256: Sha256Digest,
    target_sha256: Sha256Digest,
    endpoint: NativeGatewayEndpointBinding,
    exit_code: i32,
    drained: bool,
    connections_joined: bool,
    blocking_jobs_joined: bool,
    mcp_lifecycle_jobs_joined: bool,
    mcp_session_transports_joined: bool,
    unconfirmed_owner_cleanups: usize,
    sdk_service_joined: bool,
    #[serde(deserialize_with = "required_option")]
    sdk_detached_tasks_joined: Option<bool>,
    host_protocol_joined: bool,
    host_link_io_joined: bool,
    executor_exited: bool,
    processes_exited: bool,
    reader_task_reaped: bool,
    stderr_task_reaped: bool,
    supervised_jobs_joined: bool,
    validation_task_joined: bool,
    migration_committed: bool,
    ordinary_admission_open: bool,
}
fn validate_paired_report<R>(raw: &[u8], original: &OriginalCutover<R>) -> JournalResult<()> {
    if raw.is_empty() || raw.len() > MAX_VALIDATION {
        return Err(JournalError::BudgetExceeded);
    }
    if original.intent.schema == 4
        && original.intent.endpoint_mode
            == Some(styx_contracts::native_management::NativeMigrationEndpointMode::PreservedRemote)
    {
        return native_writer::validate_remote_report(raw, original);
    }
    let report: PairedValidationHeader =
        serde_json::from_slice(raw).map_err(|_| JournalError::InvalidInput)?;
    let endpoint: NativeGatewayEndpointBinding = serde_json::from_slice(
        &original
            .endpoint
            .as_ref()
            .ok_or(JournalError::Conflict)?
            .binding,
    )
    .map_err(|_| JournalError::Conflict)?;
    if !matches!(original.intent.schema, 2..=4)
        || report.schema != 1
        || report.transaction_id != original.intent.transaction_id
        || report.candidate_manifest_sha256 != original.intent.candidate_manifest_sha256
        || report.target_sha256 != original.intent.target_state_sha256
        || report.endpoint != endpoint
        || report.exit_code != 0
        || !report.drained
        || !report.connections_joined
        || !report.blocking_jobs_joined
        || !report.mcp_lifecycle_jobs_joined
        || !report.mcp_session_transports_joined
        || report.unconfirmed_owner_cleanups != 0
        || !report.sdk_service_joined
        || report.sdk_detached_tasks_joined == Some(false)
        || !report.host_protocol_joined
        || !report.host_link_io_joined
        || !report.executor_exited
        || !report.processes_exited
        || !report.reader_task_reaped
        || !report.stderr_task_reaped
        || !report.supervised_jobs_joined
        || !report.validation_task_joined
        || report.migration_committed
        || report.ordinary_admission_open
    {
        return Err(JournalError::Conflict);
    }
    Ok(())
}
#[derive(Deserialize)]
struct LegacyDeployment {
    schema: u32,
    mode: String,
    host: Option<serde_json::Value>,
}
fn name(id: &TransactionId, suffix: &str) -> String {
    format!("txn-{}.cutover-{suffix}", id.as_str())
}
fn stage_name(stage: DurableStage) -> JournalResult<&'static str> {
    match stage {
        DurableStage::Prepared => Ok("prepared"),
        DurableStage::Applied => Ok("applied"),
        DurableStage::Verified => Ok("verified"),
        DurableStage::Committed => Ok("committed"),
        _ => Err(JournalError::InvalidInput),
    }
}
fn phase_bytes<R: Clone + Serialize>(
    original: &OriginalCutover<R>,
    stage: DurableStage,
    previous: Option<Sha256Digest>,
) -> JournalResult<Vec<u8>> {
    let validation_sha256 = match stage {
        DurableStage::Verified | DurableStage::Committed => {
            Some(original.validation_sha256.ok_or(JournalError::Conflict)?)
        }
        _ => None,
    };
    let paired_validation_sha256 = if matches!(original.intent.schema, 2..=4)
        && matches!(stage, DurableStage::Verified | DurableStage::Committed)
    {
        Some(
            original
                .paired_validation_sha256
                .ok_or(JournalError::Conflict)?,
        )
    } else {
        None
    };
    serde_json::to_vec(&PhaseRecord {
        schema: if matches!(original.intent.schema, 3 | 4) {
            original.intent.schema
        } else if paired_validation_sha256.is_some() {
            2
        } else {
            1
        },
        paired_validation_sha256,
        intent: original.intent.clone(),
        raw_intent_sha256: Sha256Digest::of_bytes(&original.raw_intent),
        validation_sha256,
        stage,
        previous,
        canonical_raw_sha256: if stage == DurableStage::Prepared {
            original.intent.before_state_sha256
        } else {
            original.intent.target_state_sha256
        },
    })
    .map_err(|_| JournalError::InvalidInput)
}
fn receipt<R>(
    intent: &CutoverIntent<R>,
    stage: DurableStage,
    previous: Option<Sha256Digest>,
    bytes: &[u8],
) -> JournalReceipt {
    JournalReceipt {
        transaction_id: intent.transaction_id.clone(),
        sequence: intent.sequence,
        stage,
        previous,
        record_sha256: Sha256Digest::of_bytes(bytes),
    }
}
fn root_matches<R: handoff::ProofRoot>(expected: &R, actual: RootIdentity) -> bool {
    let actual = match actual {
        RootIdentity::Linux { device, inode, uid } => {
            NativeRootIdentity::Linux { device, inode, uid }
        }
        #[cfg(target_os = "macos")]
        RootIdentity::Macos { device, inode, uid } => {
            NativeRootIdentity::Macos { device, inode, uid }
        }
        #[cfg(target_os = "windows")]
        RootIdentity::Windows {
            volume_serial,
            file_id,
            owner_sid,
        } => NativeRootIdentity::Windows {
            volume_serial,
            file_id,
            owner_sid,
        },
    };
    expected.native_identity() == actual
}
#[path = "management_cutover_native.rs"]
mod native_writer;
pub(in crate::store) use native_writer::CutoverProofRoot;
pub(crate) use native_writer::{NativeCutoverHistoryInputs, NativeCutoverInputs};
fn validate_materials<R: handoff::ProofRoot>(original: &OriginalCutover<R>) -> JournalResult<()> {
    let i = &original.intent;
    if i.schema == 4 {
        handoff::reject_migration_v2_collision(&original.before)?;
    }
    if !R::permits_cutover(i.schema)
        || i.kind != CutoverKind::LegacyRuntimeCutover
        || i.sequence == 0
        || !i.config_root.valid_pair(&i.host_root)
        || original.raw_intent.len() > MAX_INTENT
        || original.marker.len() > 4096
        || [
            &original.preservation,
            &original.scope_bindings,
            &original.marker,
            &original.before,
            &original.target,
        ]
        .iter()
        .any(|b| b.is_empty() || b.len() > MAX_RAW)
        || Sha256Digest::of_bytes(&original.preservation) != i.preservation_sha256
        || Sha256Digest::of_bytes(&original.scope_bindings) != i.scope_bindings_sha256
        || Sha256Digest::of_bytes(&original.marker) != i.marker_sha256
        || Sha256Digest::of_bytes(&original.before) != i.before_state_sha256
        || Sha256Digest::of_bytes(&original.target) != i.target_state_sha256
        || i.management_intent().validate().is_err()
    {
        return Err(JournalError::Unknown);
    }
    let marker = decode_marker(&original.marker).map_err(|_| JournalError::Unknown)?;
    if marker.root_identity != i.config_root.native_identity() {
        return Err(JournalError::Conflict);
    }
    let validated = decode_state(&original.target, &marker).map_err(|_| JournalError::Unknown)?;
    let state = validated.state();
    if state.revision != 1
        || i.reader
            != if i.schema == 4 {
                ReaderContract::NativeMigratedStateV2
            } else {
                ReaderContract::NativeMigratedStateV1
            }
        || state.reader_contract != i.reader
        || state.deployment_raw_sha256 != i.deployment_raw_sha256
        || state
            .last_transaction
            .as_ref()
            .is_none_or(|tx| tx.transaction_id != i.transaction_id || tx.sequence != i.sequence)
    {
        return Err(JournalError::Conflict);
    }
    let extension = state.extensions.get("gateway_endpoint_v1");
    match (i.schema, original.endpoint.as_ref()) {
        (1 | 4, None) => {
            if extension.is_some()
                || i.endpoint_binding_sha256.is_some()
                || i.endpoint_chain_sha256.is_some()
                || i.endpoint_key_sha256.is_some()
            {
                return Err(JournalError::Conflict);
            }
        }
        (2..=4, Some(endpoint)) => {
            if [
                endpoint.binding.as_slice(),
                endpoint.chain.as_slice(),
                endpoint.key.as_slice(),
            ]
            .iter()
            .any(|raw| raw.is_empty() || raw.len() > MAX_RAW)
                || i.endpoint_binding_sha256 != Some(Sha256Digest::of_bytes(&endpoint.binding))
                || i.endpoint_chain_sha256 != Some(Sha256Digest::of_bytes(&endpoint.chain))
                || i.endpoint_key_sha256 != Some(Sha256Digest::of_bytes(&endpoint.key))
                || state.desired.gateway.is_none()
                || extension.is_none_or(|raw| raw.get().as_bytes() != endpoint.binding.as_slice())
            {
                return Err(JournalError::Conflict);
            }
            // Typed data links only. Certificate issuance, trust, key matching,
            // hostname/time verification and native TLS admission belong upstream.
            let binding: NativeGatewayEndpointBinding =
                serde_json::from_slice(&endpoint.binding).map_err(|_| JournalError::Conflict)?;
            if binding.schema != 1
                || binding.transaction_id != i.transaction_id
                || binding.root_identity != marker.root_identity
                || binding.candidate_manifest_sha256 != i.candidate_manifest_sha256
                || binding.chain_sha256 != Sha256Digest::of_bytes(&endpoint.chain)
                || binding.not_before_unix >= binding.not_after_unix
                || binding.origin.is_empty()
                || binding.origin.len() > 4096
            {
                return Err(JournalError::Conflict);
            }
        }
        _ => return Err(JournalError::Conflict),
    }
    if i.schema == 4 {
        return native_writer::validate_v4(original, state);
    }
    if i.endpoint_mode.is_some()
        || i.history.is_some()
        || original.host_pair.is_some()
        || i.host_pair_sha256.is_some()
    {
        return Err(JournalError::Conflict);
    }
    let migration = state.migration.as_ref().ok_or(JournalError::Conflict)?;
    if migration.transaction_id != i.transaction_id
        || migration.original_state_sha256 != i.before_state_sha256
        || migration.retired_receipt_sha256 != i.retired_record_sha256
        || Some(migration.enrollment_baseline_sha256) != i.history_baseline_sha256
        || Some(migration.enrollment_committed_sha256) != i.history_committed_sha256
        || migration.candidate_manifest_sha256 != i.candidate_manifest_sha256
        || migration.publisher_spki_sha256 != i.publisher_spki_sha256
        || migration.preservation_sha256 != i.preservation_sha256
        || migration.scope_bindings_sha256 != i.scope_bindings_sha256
        || migration.original_token_relative_path
            != format!(
                "device/.styx-retired-host-token-{}",
                i.transaction_id.as_str()
            )
    {
        return Err(JournalError::Conflict);
    }
    Ok(())
}
fn validate_roles<R>(deployment: &[u8], original: &OriginalCutover<R>) -> JournalResult<()> {
    let legacy: LegacyDeployment =
        serde_json::from_slice(deployment).map_err(|_| JournalError::Conflict)?;
    let mode = match legacy.mode.as_str() {
        "create-local" => NativeDeploymentMode::CreateLocal,
        "join-existing" => NativeDeploymentMode::JoinExisting,
        _ => return Err(JournalError::Conflict),
    };
    let marker = decode_marker(&original.marker).map_err(|_| JournalError::Conflict)?;
    let target = decode_state(&original.target, &marker).map_err(|_| JournalError::Conflict)?;
    let s = target.state();
    if legacy.schema != 1
        || Sha256Digest::of_bytes(deployment) != original.intent.deployment_raw_sha256
        || s.mode != mode
        || s.desired.host.is_some() != legacy.host.is_some()
        || s.desired.gateway.is_some() != (mode == NativeDeploymentMode::CreateLocal)
    {
        return Err(JournalError::Conflict);
    }
    Ok(())
}
fn replay<R>(original: &OriginalCutover<R>) -> JournalResult<()> {
    let i = original.intent.management_intent();
    let mut tx = ManagementTransaction::plan(i.clone()).map_err(|_| JournalError::Unknown)?;
    for r in &original.phases {
        let result = match r.stage {
            DurableStage::Prepared => tx.prepare(PreparedFacts {
                intent: i.clone(),
                deployment_raw_sha256: i.deployment_raw_sha256,
                canonical_state_sha256: i.before_state_sha256,
                reader: i.reader,
                journal: r.clone(),
            }),
            DurableStage::Applied => tx.applied(AppliedFacts {
                intent: i.clone(),
                deployment_raw_sha256: i.deployment_raw_sha256,
                canonical_state_sha256: i.target_state_sha256,
                journal: r.clone(),
            }),
            DurableStage::Verified => tx.verified(VerificationFacts {
                intent: i.clone(),
                deployment_raw_sha256: i.deployment_raw_sha256,
                canonical_state_sha256: i.target_state_sha256,
                reader: i.reader,
                journal: r.clone(),
            }),
            DurableStage::Committed => tx.committed(CommitFacts {
                intent: i.clone(),
                deployment_raw_sha256: i.deployment_raw_sha256,
                canonical_state_sha256: i.target_state_sha256,
                journal: r.clone(),
            }),
            _ => return Err(JournalError::Unknown),
        };
        result.map_err(|_| JournalError::Unknown)?;
    }
    Ok(())
}
/// Pure scan only. It never calls platform::inventory (which calls this scanner),
/// opens a root, advances a stage, or treats an observed marker as durability.
pub(in crate::store) fn scan_cutovers(
    scan: &JournalObservation,
) -> JournalResult<CutoverInventory> {
    let by_name: BTreeMap<_, _> = scan
        .files
        .iter()
        .map(|f| (f.name.as_str(), f.bytes()))
        .collect();
    if by_name.len() != scan.files.len() {
        return Err(JournalError::Unknown);
    }
    let handoffs = handoff::scan_handoffs(scan)?;
    let mut used = BTreeSet::new();
    let mut records = Vec::new();
    let mut native_records = Vec::new();
    for file in &scan.files {
        if !file.name.ends_with(".cutover-intent") {
            continue;
        }
        if file.bytes().len() > MAX_INTENT {
            return Err(JournalError::BudgetExceeded);
        }
        #[derive(Deserialize)]
        struct Version {
            schema: u16,
            transaction_id: TransactionId,
        }
        let version: Version =
            serde_json::from_slice(file.bytes()).map_err(|_| JournalError::Unknown)?;
        match version.schema {
            1 | 2 => {
                let old = handoffs
                    .records
                    .iter()
                    .find(|r| r.intent.transaction_id == version.transaction_id)
                    .ok_or(JournalError::Conflict)?;
                records.push(parse_cutover(file, &by_name, &mut used, old)?);
            }
            3 | 4 => {
                let old = handoffs
                    .native_records
                    .iter()
                    .find(|r| r.intent.transaction_id == version.transaction_id)
                    .ok_or(JournalError::Conflict)?;
                native_records.push(parse_cutover(file, &by_name, &mut used, old)?);
            }
            _ => return Err(JournalError::Unknown),
        }
    }
    if records.len() + native_records.len() > 1 {
        return Err(JournalError::Conflict);
    }
    if scan
        .files
        .iter()
        .any(|f| f.name.contains(".cutover-") && !used.contains(&f.name))
    {
        return Err(JournalError::Unknown);
    }
    Ok(CutoverInventory {
        used,
        records,
        native_records,
    })
}
fn parse_cutover<R: handoff::ProofRoot, S: handoff::ProofStamp<R>>(
    file: &crate::store::secure_journal::ObservedJournalFile,
    by_name: &BTreeMap<&str, &[u8]>,
    used: &mut BTreeSet<String>,
    old: &handoff::ObservedRetirement<R, S>,
) -> JournalResult<OriginalCutover<R>> {
    let intent: CutoverIntent<R> =
        serde_json::from_slice(file.bytes()).map_err(|_| JournalError::Unknown)?;
    if file.name != name(&intent.transaction_id, "intent") {
        return Err(JournalError::Unknown);
    }
    let observation = old.observation();
    let r = &old.intent;
    if observation.stage != handoff::CredentialRetirementStage::Retired
        || observation.retired_sha256 != Some(intent.retired_record_sha256)
        || intent.sequence != r.sequence
        || intent.config_root != r.config_root
        || intent.host_root != r.host_root
        || intent.candidate_manifest_sha256 != r.candidate_manifest_sha256
        || intent.publisher_spki_sha256 != r.publisher_spki_sha256
        || intent.deployment_raw_sha256 != r.deployment_raw_sha256
        || intent.before_state_sha256 != r.before_state_sha256
        || intent.retirement_preservation_sha256 != r.preservation_sha256
    {
        return Err(JournalError::Conflict);
    }
    used.insert(file.name.clone());
    let mut read = |suffix: &str| -> JournalResult<Vec<u8>> {
        let n = name(&intent.transaction_id, suffix);
        let raw = by_name.get(n.as_str()).ok_or(JournalError::Unknown)?;
        used.insert(n);
        Ok(raw.to_vec())
    };
    let endpoint = match (intent.schema, intent.endpoint_mode) {
        (1, None)
        | (
            4,
            Some(styx_contracts::native_management::NativeMigrationEndpointMode::PreservedRemote),
        ) => None,
        (2 | 3, None)
        | (4, Some(styx_contracts::native_management::NativeMigrationEndpointMode::IssuedLocal)) => {
            Some(CutoverEndpointMaterials {
                binding: read("endpoint-binding")?,
                chain: read("endpoint-chain")?,
                key: Zeroizing::new(read("endpoint-key")?),
            })
        }
        _ => return Err(JournalError::Unknown),
    };
    let host_pair = if intent.schema == 4 {
        Some(read("host-pair")?)
    } else {
        None
    };
    let mut original = OriginalCutover {
        intent: intent.clone(),
        raw_intent: file.bytes().to_vec(),
        preservation: read("preservation")?,
        scope_bindings: read("scopes")?,
        marker: read("marker")?,
        before: read("before")?,
        target: read("target")?,
        phases: vec![],
        last_stage: DurableStage::Planned,
        host_pair,
        validation: None,
        validation_sha256: None,
        paired_validation: None,
        paired_validation_sha256: None,
        endpoint,
    };
    validate_materials(&original)?;
    if let Some(pair) = original.host_pair.as_ref() {
        let binding: styx_contracts::native_management::NativePreservedHostPair =
            serde_json::from_slice(pair).map_err(|_| JournalError::Unknown)?;
        if binding.credential_sha256
            != handoff::ProofStamp::content_sha256(&old.intent.original_token)
        {
            return Err(JournalError::Conflict);
        }
    }

    let validation_name = name(&intent.transaction_id, "validation");
    if let Some(raw) = by_name.get(validation_name.as_str()) {
        validate_report(raw, &intent).map_err(|_| JournalError::Unknown)?;
        original.validation = Some(raw.to_vec());
        original.validation_sha256 = Some(Sha256Digest::of_bytes(raw));
    }
    let paired_name = name(&intent.transaction_id, "paired-validation");
    if let Some(raw) = by_name.get(paired_name.as_str()) {
        validate_paired_report(raw, &original).map_err(|_| JournalError::Unknown)?;
        original.paired_validation = Some(raw.to_vec());
        original.paired_validation_sha256 = Some(Sha256Digest::of_bytes(raw));
    }
    let mut previous = None;
    let mut missing = false;
    for stage in [
        DurableStage::Prepared,
        DurableStage::Applied,
        DurableStage::Verified,
        DurableStage::Committed,
    ] {
        let n = name(&intent.transaction_id, stage_name(stage)?);
        if let Some(bytes) = by_name.get(n.as_str()) {
            if missing || bytes.len() > MAX_INTENT {
                return Err(JournalError::Unknown);
            }
            let record: PhaseRecord<R> =
                serde_json::from_slice(bytes).map_err(|_| JournalError::Unknown)?;
            let final_paired = matches!(intent.schema, 2..=4)
                && matches!(stage, DurableStage::Verified | DurableStage::Committed);
            let expected_schema = if matches!(intent.schema, 3 | 4) {
                intent.schema
            } else if final_paired {
                2
            } else {
                1
            };
            let invalid_paired = if final_paired {
                original.paired_validation_sha256.is_none()
                    || record.paired_validation_sha256 != original.paired_validation_sha256
            } else {
                record.paired_validation_sha256.is_some()
            };
            if record.schema != expected_schema
                || invalid_paired
                || record.intent != intent
                || record.raw_intent_sha256 != Sha256Digest::of_bytes(file.bytes())
                || record.stage != stage
                || record.previous != previous
                || match stage {
                    DurableStage::Verified | DurableStage::Committed => {
                        original.validation_sha256.is_none()
                            || record.validation_sha256 != original.validation_sha256
                    }
                    _ => record.validation_sha256.is_some(),
                }
                || record.canonical_raw_sha256
                    != if stage == DurableStage::Prepared {
                        intent.before_state_sha256
                    } else {
                        intent.target_state_sha256
                    }
            {
                return Err(JournalError::Unknown);
            }
            let r = receipt(&intent, stage, previous, bytes);
            previous = Some(r.record_sha256);
            original.phases.push(r);
            original.last_stage = stage;
            used.insert(n);
        } else {
            missing = true;
        }
    }
    if original.validation.is_some() {
        if !original
            .phases
            .iter()
            .any(|p| p.stage == DurableStage::Applied)
        {
            return Err(JournalError::Unknown);
        }
        used.insert(validation_name);
    }
    if original.paired_validation.is_some() {
        if original.validation.is_none()
            || !original
                .phases
                .iter()
                .any(|p| p.stage == DurableStage::Applied)
        {
            return Err(JournalError::Unknown);
        }
        used.insert(paired_name);
    }
    replay(&original)?;

    Ok(original)
}
pub(in crate::store) fn original(
    scan: &JournalObservation,
    id: &TransactionId,
) -> JournalResult<OriginalCutover> {
    original_for::<handoff::RetirementLinuxRoot>(scan, id)
}
pub(in crate::store) fn original_for<R: CutoverProofRoot>(
    scan: &JournalObservation,
    id: &TransactionId,
) -> JournalResult<OriginalCutover<R>> {
    let inventory = super::platform::inventory(scan)?;
    if !inventory.orphans.is_empty()
        || inventory.transactions.iter().any(|t| {
            t.prepared.is_none()
                || t.phase_receipts
                    .last()
                    .is_none_or(|r| r.stage != DurableStage::Committed)
        })
    {
        return Err(JournalError::Conflict);
    }
    let handoffs = handoff::scan_handoffs(scan)?;
    let old = R::retirement(handoffs)?;
    if &old.intent.transaction_id != id {
        return Err(JournalError::Conflict);
    }
    R::cutovers(scan_cutovers(scan)?).and_then(|records| {
        records
            .into_iter()
            .find(|r| &r.intent.transaction_id == id)
            .ok_or(JournalError::Conflict)
    })
}
pub(in crate::store) fn check_canonical<R: handoff::ProofRoot>(
    state: &ConfigurationState,
    original: &OriginalCutover<R>,
    require_target: bool,
) -> JournalResult<()> {
    check_canonical_root(&state.root, original, require_target)
}
pub(in crate::store) fn check_canonical_root<R: handoff::ProofRoot>(
    root: &crate::store::PrivateRoot,
    original: &OriginalCutover<R>,
    require_target: bool,
) -> JournalResult<()> {
    let i = &original.intent;
    if !root_matches(&i.config_root, root.identity()) {
        return Err(JournalError::Conflict);
    }
    let deployment = root
        .read_raw("deployment.json", MAX_RAW)
        .map_err(|_| JournalError::Unknown)?;
    validate_roles(deployment.bytes(), original)?;
    let current = root
        .read_raw("state.json", MAX_RAW)
        .map_err(|_| JournalError::Unknown)?;
    let hash = Sha256Digest::of_bytes(current.bytes());
    if require_target
        || matches!(
            original.last_stage,
            DurableStage::Applied | DurableStage::Verified | DurableStage::Committed
        )
    {
        if hash != i.target_state_sha256 {
            return Err(JournalError::Conflict);
        }
    } else if hash != i.before_state_sha256 && hash != i.target_state_sha256 {
        return Err(JournalError::Conflict);
    }
    if hash == i.target_state_sha256 || root.ensure_absent(MARKER).is_err() {
        let marker = root
            .read_raw(MARKER, 4096)
            .map_err(|_| JournalError::Unknown)?;
        if marker.bytes() != original.marker {
            return Err(JournalError::Conflict);
        }
    }
    for (path, expected) in [
        (
            ".styx-enrollment-journal-v1/historical-baseline.intent",
            i.history_baseline_sha256,
        ),
        (
            ".styx-enrollment-journal-v1/historical-baseline.committed",
            i.history_committed_sha256,
        ),
    ] {
        let Some(expected) = expected else { continue };
        let raw = root
            .read_raw(path, MAX_RAW)
            .map_err(|_| JournalError::Unknown)?;
        if Sha256Digest::of_bytes(raw.bytes()) != expected {
            return Err(JournalError::Conflict);
        }
    }
    if original.intent.schema == 4
        && original.intent.endpoint_mode
            == Some(styx_contracts::native_management::NativeMigrationEndpointMode::PreservedRemote)
    {
        root.ensure_absent(".styx-enrollment-journal-v1")
            .map_err(|_| JournalError::Conflict)?;
        root.ensure_absent("gateway")
            .map_err(|_| JournalError::Conflict)?;
    }
    Ok(())
}
fn preflight<B: AsRef<[u8]>>(
    state: &ConfigurationState,
    scan: &JournalObservation,
    entries: &[(String, B)],
    budget: JournalBudget,
) -> JournalResult<()> {
    preflight_with_root_growth(state, scan, entries, budget, 0)
}
fn preflight_with_root_growth<B: AsRef<[u8]>>(
    state: &ConfigurationState,
    scan: &JournalObservation,
    entries: &[(String, B)],
    budget: JournalBudget,
    root_growth: usize,
) -> JournalResult<()> {
    let mut count = scan.files.len();
    let mut bytes = scan.total_bytes;
    for (n, b) in entries {
        let b = b.as_ref();
        if b.is_empty() || b.len() > budget.max_file_bytes {
            return Err(JournalError::BudgetExceeded);
        }
        if let Some(old) = scan.files.iter().find(|f| f.name == *n) {
            if old.bytes() != b {
                return Err(JournalError::Conflict);
            }
        } else {
            count = count.checked_add(1).ok_or(JournalError::BudgetExceeded)?;
            bytes = bytes
                .checked_add(b.len())
                .ok_or(JournalError::BudgetExceeded)?;
        }
    }
    if count > budget.max_files || bytes > budget.max_bytes {
        return Err(JournalError::BudgetExceeded);
    }
    state.preflight_growth(
        (bytes - scan.total_bytes)
            .checked_add(root_growth)
            .ok_or(JournalError::BudgetExceeded)?,
    )
}
fn sync_existing(
    dir: &File,
    scan: &JournalObservation,
    used: &BTreeSet<String>,
) -> JournalResult<()> {
    for name in used {
        let expected = scan
            .files
            .iter()
            .find(|f| &f.name == name)
            .ok_or(JournalError::Unknown)?
            .bytes();
        files::sync_file(dir, name)?;
        if files::read(dir, name, MAX_RAW)?.as_deref() != Some(expected) {
            return Err(JournalError::Unknown);
        }
    }
    super::platform::sync_directory(dir)
}
impl OwnedManagementJournal {
    pub(in crate::store) fn cutover_prepared_matches<R>(
        &self,
        prepared: &PreparedCutover<R>,
    ) -> bool {
        self.owner.same_authority(&prepared.owner) && self.namespace == prepared.namespace
    }
    pub(in crate::store) fn prepare_cutover(
        &mut self,
        maintenance: &ConfigurationMaintenance,
        inputs: CutoverInputs,
    ) -> JournalResult<PreparedCutover> {
        self.prepare_cutover_for::<handoff::RetirementLinuxRoot>(maintenance, inputs.into())
    }
    /// Capacity only, before the native token effect. This does not publish a
    /// target or attest a future retired receipt. The caller supplies encoded
    /// size inputs; fixed-width digest values do not change their byte lengths.
    #[cfg(target_os = "macos")]
    pub(in crate::store) fn preflight_host_cutover_capacity(
        &self,
        maintenance: &ConfigurationMaintenance,
        inputs: &NativeCutoverInputs,
    ) -> JournalResult<()> {
        let NativeCutoverHistoryInputs::PreservedHostPair { bindings } = &inputs.history else {
            return Err(JournalError::Unsupported);
        };
        if inputs.endpoint.is_some() || inputs.target.len() > MAX_RAW {
            return Err(JournalError::BudgetExceeded);
        }
        let sizes = [
            inputs.preservation.len(),
            inputs.scope_bindings.len(),
            inputs.marker.len(),
            inputs.before.len(),
            inputs.target.len(),
            bindings.len(),
        ];
        if sizes
            .iter()
            .any(|n| *n == 0 || *n > self.budget.max_file_bytes || *n > MAX_RAW)
            || self.budget.max_file_bytes < MAX_INTENT.max(MAX_VALIDATION)
        {
            return Err(JournalError::BudgetExceeded);
        }
        // Six material members; intent + four phases + retirement completion;
        // two validation reports; one apply temporary. Reserve bounded metadata
        // and the apply peak conservatively; no placeholder bytes are written.
        let extra = sizes
            .iter()
            .try_fold(0usize, |a, b| a.checked_add(*b))
            .and_then(|n| n.checked_add(6 * MAX_INTENT + 2 * MAX_VALIDATION))
            .and_then(|n| n.checked_add(inputs.target.len()))
            .ok_or(JournalError::BudgetExceeded)?;
        self.owner.with_maintenance(maintenance, |state| {
            self.with_directory_locked(state, |dir| {
                let scan = files::scan(dir, self.budget)?;
                if scan
                    .total_bytes
                    .checked_add(extra)
                    .is_none_or(|n| n > self.budget.max_bytes)
                    || scan
                        .files
                        .len()
                        .checked_add(15)
                        .is_none_or(|n| n > self.budget.max_files)
                {
                    return Err(JournalError::BudgetExceeded);
                }
                state.preflight_growth(
                    extra
                        .checked_add(inputs.marker.len())
                        .ok_or(JournalError::BudgetExceeded)?,
                )
            })
        })
    }
    pub(in crate::store) fn prepare_native_cutover(
        &mut self,
        maintenance: &ConfigurationMaintenance,
        inputs: NativeCutoverInputs,
        candidate: std::sync::Arc<crate::release::VerifiedNativeRelease>,
    ) -> JournalResult<PreparedCutover<NativeRootIdentity>> {
        candidate.revalidate().map_err(|_| JournalError::Unknown)?;
        if candidate.report().scope != "runtime_candidate"
            || !candidate
                .manifest()
                .minimum_reader
                .supports_state_reader(ReaderContract::NativeMigratedStateV2)
        {
            return Err(JournalError::Unsupported);
        }
        self.owner.with_maintenance(maintenance, |state| {
            self.with_directory_locked(state, |dir| {
                let old = NativeRootIdentity::retirement(handoff::scan_handoffs(&files::scan(
                    dir,
                    self.budget,
                )?)?)?;
                if old.intent.candidate_manifest_sha256 != candidate.report().manifest_sha256
                    || old.intent.publisher_spki_sha256.to_hex()
                        != candidate.report().publisher_spki_sha256
                {
                    return Err(JournalError::Conflict);
                }
                Ok(())
            })
        })?;
        let mut prepared =
            self.prepare_cutover_for::<NativeRootIdentity>(maintenance, inputs.try_into()?)?;
        prepared.candidate = Some(candidate);
        prepared.validate_candidate()?;
        Ok(prepared)
    }
    fn prepare_cutover_for<R: CutoverProofRoot>(
        &mut self,
        maintenance: &ConfigurationMaintenance,
        inputs: native_writer::NormalizedInputs,
    ) -> JournalResult<PreparedCutover<R>> {
        self.owner.with_maintenance(maintenance, |state| {
            self.with_directory_locked(state, |dir| {
                let scan = files::scan(dir, self.budget)?;
                let inventory = super::platform::inventory(&scan)?;
                let handoffs = handoff::scan_handoffs(&scan)?;
                if !inventory.orphans.is_empty()
                    || {
                        let cutovers = scan_cutovers(&scan)?;
                        !cutovers.records.is_empty() || !cutovers.native_records.is_empty()
                    }
                    || inventory.transactions.iter().any(|t| {
                        t.prepared.is_none()
                            || t.phase_receipts
                                .last()
                                .is_none_or(|p| p.stage != DurableStage::Committed)
                    })
                {
                    return Err(JournalError::Conflict);
                }
                let old = R::retirement(handoffs)?;
                let r = &old.intent;
                let fact = old.observation();
                if maintenance.transaction_id() != &r.transaction_id
                    || fact.stage != handoff::CredentialRetirementStage::Retired
                {
                    return Err(JournalError::Conflict);
                }
                let marker =
                    decode_marker(&inputs.marker).map_err(|_| JournalError::InvalidInput)?;
                let target = decode_state(&inputs.target, &marker)
                    .map_err(|_| JournalError::InvalidInput)?;
                let intent = CutoverIntent {
                    schema: if inputs.schema4 {
                        if !R::permits_cutover(4) {
                            return Err(JournalError::InvalidInput);
                        }
                        4
                    } else {
                        R::schema(inputs.endpoint.is_some())?
                    },
                    endpoint_mode: inputs.endpoint_mode,
                    history: inputs.history,
                    host_pair_sha256: inputs.host_pair.as_ref().map(|b| Sha256Digest::of_bytes(b)),
                    kind: CutoverKind::LegacyRuntimeCutover,
                    transaction_id: r.transaction_id.clone(),
                    sequence: r.sequence,
                    retired_record_sha256: fact.retired_sha256.ok_or(JournalError::Conflict)?,
                    config_root: r.config_root.clone(),
                    host_root: r.host_root.clone(),
                    candidate_manifest_sha256: r.candidate_manifest_sha256,
                    publisher_spki_sha256: r.publisher_spki_sha256,
                    deployment_raw_sha256: r.deployment_raw_sha256,
                    before_state_sha256: r.before_state_sha256,
                    target_state_sha256: target.raw_sha256(),
                    reader: target.state().reader_contract,
                    retirement_preservation_sha256: r.preservation_sha256,
                    preservation_sha256: Sha256Digest::of_bytes(&inputs.preservation),
                    scope_bindings_sha256: Sha256Digest::of_bytes(&inputs.scope_bindings),
                    marker_sha256: Sha256Digest::of_bytes(&inputs.marker),
                    history_baseline_sha256: inputs.history_baseline_sha256,
                    history_committed_sha256: inputs.history_committed_sha256,
                    endpoint_binding_sha256: inputs
                        .endpoint
                        .as_ref()
                        .map(|e| Sha256Digest::of_bytes(&e.binding)),
                    endpoint_chain_sha256: inputs
                        .endpoint
                        .as_ref()
                        .map(|e| Sha256Digest::of_bytes(&e.chain)),
                    endpoint_key_sha256: inputs
                        .endpoint
                        .as_ref()
                        .map(|e| Sha256Digest::of_bytes(&e.key)),
                };
                let raw = serde_json::to_vec(&intent).map_err(|_| JournalError::InvalidInput)?;
                let mut data = OriginalCutover {
                    intent,
                    raw_intent: raw,
                    preservation: inputs.preservation,
                    scope_bindings: inputs.scope_bindings,
                    marker: inputs.marker,
                    before: inputs.before,
                    target: inputs.target,
                    host_pair: inputs.host_pair,
                    phases: vec![],
                    last_stage: DurableStage::Planned,
                    validation: None,
                    validation_sha256: None,
                    paired_validation: None,
                    paired_validation_sha256: None,
                    endpoint: inputs.endpoint.map(|e| CutoverEndpointMaterials {
                        binding: e.binding,
                        chain: e.chain,
                        key: e.key,
                    }),
                };
                validate_materials(&data)?;
                check_canonical(state, &data, false)?;
                let current = state
                    .root
                    .read_raw("state.json", MAX_RAW)
                    .map_err(|_| JournalError::Unknown)?;
                if current.bytes() != data.before {
                    return Err(JournalError::Conflict);
                }
                state
                    .root
                    .ensure_absent(MARKER)
                    .map_err(|_| JournalError::Conflict)?;
                let mut entries = vec![(
                    name(&data.intent.transaction_id, "intent"),
                    Zeroizing::new(data.raw_intent.clone()),
                )];
                for (suffix, bytes) in ATTACHMENTS.iter().zip([
                    &data.preservation,
                    &data.scope_bindings,
                    &data.marker,
                    &data.before,
                    &data.target,
                ]) {
                    entries.push((
                        name(&data.intent.transaction_id, suffix),
                        Zeroizing::new(bytes.clone()),
                    ));
                }
                if let Some(pair) = &data.host_pair {
                    entries.push((
                        name(&data.intent.transaction_id, "host-pair"),
                        Zeroizing::new(pair.clone()),
                    ));
                }
                if let Some(endpoint) = &data.endpoint {
                    entries.push((
                        name(&data.intent.transaction_id, "endpoint-binding"),
                        Zeroizing::new(endpoint.binding.clone()),
                    ));
                    entries.push((
                        name(&data.intent.transaction_id, "endpoint-chain"),
                        Zeroizing::new(endpoint.chain.clone()),
                    ));
                    entries.push((
                        name(&data.intent.transaction_id, "endpoint-key"),
                        endpoint.key.clone(),
                    ));
                }
                let initial_count = entries.len() + 1; // plus actual Prepared below
                let mut reserved = data.clone();
                // Fixed-size digest placeholders reserve bytes only. No future
                // phase or synthetic validation report is written by prepare.
                reserved.validation_sha256 = Some(Sha256Digest::from_bytes([0; 32]));
                if matches!(reserved.intent.schema, 2..=4) {
                    reserved.paired_validation_sha256 = Some(Sha256Digest::from_bytes([0; 32]));
                }
                let mut previous = None;
                for stage in [
                    DurableStage::Prepared,
                    DurableStage::Applied,
                    DurableStage::Verified,
                    DurableStage::Committed,
                ] {
                    let raw = phase_bytes(&reserved, stage, previous)?;
                    let r = receipt(&data.intent, stage, previous, &raw);
                    previous = Some(r.record_sha256);
                    entries.push((
                        name(&data.intent.transaction_id, stage_name(stage)?),
                        Zeroizing::new(raw),
                    ));
                }
                entries.push((
                    name(&data.intent.transaction_id, "validation"),
                    Zeroizing::new(vec![0; MAX_VALIDATION]),
                ));
                if matches!(data.intent.schema, 2..=4) {
                    entries.push((
                        name(&data.intent.transaction_id, "paired-validation"),
                        Zeroizing::new(vec![0; MAX_VALIDATION]),
                    ));
                }
                preflight(state, &scan, &entries, self.budget)?;
                // Apply temporarily retains another target inside this namespace
                // while creating the canonical marker at the root. Check that
                // separate peak, rather than adding it to all future phases:
                // the temporary is renamed out before those phases are written.
                let mut apply_peak = entries[..initial_count].to_vec();
                apply_peak.push((
                    format!(
                        "txn-{}.state-temporary",
                        data.intent.transaction_id.as_str()
                    ),
                    Zeroizing::new(data.target.clone()),
                ));
                preflight_with_root_growth(
                    state,
                    &scan,
                    &apply_peak,
                    self.budget,
                    data.marker.len(),
                )?;
                // Seven schema1 or ten schema2 initial files. Future phases are NEVER created.
                for (n, b) in entries.iter().take(initial_count) {
                    files::immutable(dir, n, b, self.budget, &|_| {})?;
                }
                let after = files::scan(dir, self.budget)?;
                let observed = original_for::<R>(&after, &data.intent.transaction_id)
                    .map_err(|_| JournalError::Unknown)?;
                if observed.raw_intent != data.raw_intent
                    || observed.phases.len() != 1
                    || observed.last_stage != DurableStage::Prepared
                {
                    return Err(JournalError::Unknown);
                }
                check_canonical(state, &observed, false).map_err(|_| JournalError::Unknown)?;
                data.phases = observed.phases;
                data.last_stage = DurableStage::Prepared;
                Ok(PreparedCutover {
                    owner: self.owner.clone(),
                    namespace: self.namespace,
                    original: data,
                    candidate: None,
                })
            })
        })
    }
    /// Persist a report obtained from a trusted opaque successful probe. This
    /// validates its data links only; no caller-supplied JSON proves execution.
    pub(in crate::store) fn record_cutover_validation<R: CutoverProofRoot>(
        &mut self,
        maintenance: &ConfigurationMaintenance,
        prepared: &PreparedCutover<R>,
        report: &[u8],
    ) -> JournalResult<Sha256Digest> {
        prepared.validate_candidate()?;
        if !prepared.matches_owner(&self.owner)
            || prepared.namespace != self.namespace
            || maintenance.transaction_id() != &prepared.intent().transaction_id
        {
            return Err(JournalError::Conflict);
        }
        validate_report(report, prepared.intent())?;
        self.owner.with_maintenance(maintenance, |state| {
            self.with_directory_locked(state, |dir| {
                let scan = files::scan(dir, self.budget)?;
                let source = original_for::<R>(&scan, &prepared.intent().transaction_id)?;
                if source.intent != *prepared.intent()
                    || source.raw_intent != prepared.original.raw_intent
                    || source.last_stage != DurableStage::Applied
                {
                    return Err(JournalError::Conflict);
                }
                check_canonical(state, &source, true)?;
                let n = name(&source.intent.transaction_id, "validation");
                preflight(state, &scan, &[(n.clone(), report.to_vec())], self.budget)?;
                let mut used = scan_cutovers(&scan)?.used;
                used.extend(handoff::scan_handoffs(&scan)?.used);
                sync_existing(dir, &scan, &used)?;
                files::immutable(dir, &n, report, self.budget, &|_| {})?;
                let after = original_for::<R>(
                    &files::scan(dir, self.budget)?,
                    &source.intent.transaction_id,
                )
                .map_err(|_| JournalError::Unknown)?;
                let digest = Sha256Digest::of_bytes(report);
                if after.validation_report() != Some(report)
                    || after.validation_sha256 != Some(digest)
                    || after.last_stage != DurableStage::Applied
                {
                    return Err(JournalError::Unknown);
                }
                check_canonical(state, &after, true).map_err(|_| JournalError::Unknown)?;
                Ok(digest)
            })
        })
    }
    /// Persist data supplied only by the upper retained opaque paired proof.
    /// This port checks links and durability, never grants physical authority.
    pub(in crate::store) fn record_cutover_paired_validation<R: CutoverProofRoot>(
        &mut self,
        maintenance: &ConfigurationMaintenance,
        prepared: &PreparedCutover<R>,
        report: &[u8],
    ) -> JournalResult<Sha256Digest> {
        prepared.validate_candidate()?;
        if !prepared.matches_owner(&self.owner)
            || prepared.namespace != self.namespace
            || maintenance.transaction_id() != &prepared.intent().transaction_id
        {
            return Err(JournalError::Conflict);
        }
        self.owner.with_maintenance(maintenance, |state| {
            self.with_directory_locked(state, |dir| {
                let scan = files::scan(dir, self.budget)?;
                let source = original_for::<R>(&scan, &prepared.intent().transaction_id)?;
                if source.intent != *prepared.intent()
                    || source.raw_intent != prepared.original.raw_intent
                    || source.last_stage != DurableStage::Applied
                {
                    return Err(JournalError::Conflict);
                }
                if source.validation.is_none() {
                    return Err(JournalError::Conflict);
                }
                validate_paired_report(report, &source)?;
                check_canonical(state, &source, true)?;
                let n = name(&source.intent.transaction_id, "paired-validation");
                preflight(state, &scan, &[(n.clone(), report.to_vec())], self.budget)?;
                let mut used = scan_cutovers(&scan)?.used;
                used.extend(handoff::scan_handoffs(&scan)?.used);
                sync_existing(dir, &scan, &used)?;
                files::immutable(dir, &n, report, self.budget, &|_| {})?;
                let after = original_for::<R>(
                    &files::scan(dir, self.budget)?,
                    &source.intent.transaction_id,
                )
                .map_err(|_| JournalError::Unknown)?;
                let digest = Sha256Digest::of_bytes(report);
                if after.paired_validation_report() != Some(report)
                    || after.paired_validation_sha256 != Some(digest)
                    || after.last_stage != DurableStage::Applied
                {
                    return Err(JournalError::Unknown);
                }
                check_canonical(state, &after, true).map_err(|_| JournalError::Unknown)?;
                Ok(digest)
            })
        })
    }
    pub(in crate::store) fn append_cutover_phase<R: CutoverProofRoot>(
        &mut self,
        maintenance: &ConfigurationMaintenance,
        prepared: &PreparedCutover<R>,
        stage: DurableStage,
    ) -> JournalResult<JournalReceipt> {
        prepared.validate_candidate()?;
        if !prepared.matches_owner(&self.owner)
            || prepared.namespace != self.namespace
            || maintenance.transaction_id() != &prepared.intent().transaction_id
        {
            return Err(JournalError::Conflict);
        }
        let wanted = match stage {
            DurableStage::Applied => DurableStage::Prepared,
            DurableStage::Verified => DurableStage::Applied,
            DurableStage::Committed => DurableStage::Verified,
            _ => return Err(JournalError::InvalidInput),
        };
        self.owner.with_maintenance(maintenance, |state| {
            self.with_directory_locked(state, |dir| {
                let scan = files::scan(dir, self.budget)?;
                let source = original_for::<R>(&scan, &prepared.intent().transaction_id)?;
                if source.intent != *prepared.intent()
                    || source.raw_intent != prepared.original.raw_intent
                    || source.last_stage != wanted
                {
                    return Err(JournalError::Conflict);
                }
                check_canonical(state, &source, true)?;
                let prior = source
                    .phases
                    .last()
                    .ok_or(JournalError::Conflict)?
                    .record_sha256;
                let raw = phase_bytes(&source, stage, Some(prior))?;
                let n = name(&source.intent.transaction_id, stage_name(stage)?);
                preflight(state, &scan, &[(n.clone(), raw.clone())], self.budget)?;
                let mut used = scan_cutovers(&scan)?.used;
                used.extend(handoff::scan_handoffs(&scan)?.used);
                sync_existing(dir, &scan, &used)?;
                files::immutable(dir, &n, &raw, self.budget, &|_| {})?;
                let after = original_for::<R>(
                    &files::scan(dir, self.budget)?,
                    &source.intent.transaction_id,
                )
                .map_err(|_| JournalError::Unknown)?;
                let result = after.phases.last().ok_or(JournalError::Unknown)?;
                if result.stage != stage
                    || result.previous != Some(prior)
                    || result.record_sha256 != Sha256Digest::of_bytes(&raw)
                {
                    return Err(JournalError::Unknown);
                }
                check_canonical(state, &after, true).map_err(|_| JournalError::Unknown)?;
                Ok(result.clone())
            })
        })
    }
    /// Read the exact completed successor under the retained configuration
    /// lock. This does not clear a fence or reconstruct physical runtime proof.
    pub(in crate::store) fn validate_committed_cutover_locked<R: CutoverProofRoot>(
        &self,
        state: &ConfigurationState,
        prepared: &PreparedCutover<R>,
        committed: &JournalReceipt,
    ) -> JournalResult<()> {
        prepared.validate_candidate()?;
        self.with_directory_locked(state, |dir| {
            let scan = files::scan(dir, self.budget)?;
            let source = original_for::<R>(&scan, &prepared.intent().transaction_id)?;
            if source.intent != *prepared.intent()
                || source.raw_intent != prepared.original.raw_intent
                || !source.phases.starts_with(&prepared.original.phases)
                || prepared
                    .original
                    .validation
                    .as_ref()
                    .is_some_and(|raw| source.validation.as_ref() != Some(raw))
                || prepared
                    .original
                    .paired_validation
                    .as_ref()
                    .is_some_and(|raw| source.paired_validation.as_ref() != Some(raw))
                || source.phases.first() != Some(prepared.journal())
                || source.phases.last() != Some(committed)
                || committed.stage != DurableStage::Committed
                || source.last_stage != DurableStage::Committed
                || source.validation_report().is_none()
                || (matches!(source.intent.schema, 2..=4)
                    && source.paired_validation_report().is_none())
            {
                return Err(JournalError::Conflict);
            }
            check_canonical(state, &source, true)
        })
    }
    /// Reopen an already validated native successor. This recovers journal
    /// ownership only; the Mac coordinator separately reopens actual OS custody.
    #[cfg(target_os = "macos")]
    pub(in crate::store) fn reopen_validated_native_cutover(
        &self,
        maintenance: &ConfigurationMaintenance,
        candidate: std::sync::Arc<crate::release::VerifiedNativeRelease>,
    ) -> JournalResult<PreparedCutover<NativeRootIdentity>> {
        let original = self.resync_native_cutover(maintenance, maintenance.transaction_id())?;
        let prepared = PreparedCutover {
            owner: self.owner.clone(),
            namespace: self.namespace,
            original,
            candidate: Some(candidate),
        };
        self.owner.with_maintenance(maintenance, |state| {
            self.with_directory_locked(state, |dir| {
                self.validated_native_cutover_locked(
                    state,
                    &files::scan(dir, self.budget)?,
                    &prepared,
                )?;
                Ok(())
            })
        })?;
        Ok(prepared)
    }
    /// Called while the original owner and journal are already locked. Never
    /// acquire another mutex here. Only exact successful report bytes survive
    /// resumption; newer phases may append to, never replace, the original chain.
    #[cfg(target_os = "macos")]
    pub(in crate::store) fn validated_native_cutover_locked(
        &self,
        state: &ConfigurationState,
        scan: &JournalObservation,
        prepared: &PreparedCutover<NativeRootIdentity>,
    ) -> JournalResult<OriginalCutover<NativeRootIdentity>> {
        if !self.cutover_prepared_matches(prepared) {
            return Err(JournalError::Conflict);
        }
        state.require_native_maintenance(&prepared.intent().transaction_id)?;
        prepared.validate_candidate()?;
        let source = original_for::<NativeRootIdentity>(scan, &prepared.intent().transaction_id)?;
        if source.intent.schema != 4
            || source.intent != *prepared.intent()
            || source.raw_intent != prepared.original.raw_intent
            || !source.phases.starts_with(&prepared.original.phases)
            || !matches!(
                source.last_stage,
                DurableStage::Applied | DurableStage::Verified | DurableStage::Committed
            )
            || source.validation_report().is_none()
            || source.paired_validation_report().is_none()
            || source.validation != prepared.original.validation
            || source.paired_validation != prepared.original.paired_validation
        {
            return Err(JournalError::Conflict);
        }
        let plans = super::migration_plan::scan_plans(scan)?;
        let plan = plans.records.first().ok_or(JournalError::Conflict)?;
        plan.validate_cutover(&source)?;
        let candidate = prepared.candidate.as_ref().ok_or(JournalError::Conflict)?;
        if plan.selection
            != candidate
                .runtime_selection()
                .map_err(|_| JournalError::Unknown)?
        {
            return Err(JournalError::Conflict);
        }
        crate::store::committed_runtime_native::validate_selected_reader_features(
            candidate.manifest().minimum_reader,
            true,
            source
                .paired_validation_report()
                .ok_or(JournalError::Conflict)?,
        )?;
        let inventory = super::parser::inventory(scan)?;
        if !inventory.orphans.is_empty()
            || inventory.high_water != source.intent.sequence
            || inventory.transactions.iter().any(|t| {
                t.intent.sequence >= source.intent.sequence
                    || t.phase_receipts
                        .last()
                        .is_none_or(|p| p.stage != DurableStage::Committed)
            })
        {
            return Err(JournalError::Conflict);
        }
        check_canonical(state, &source, true)?;
        Ok(source)
    }
    pub(in crate::store) fn resync_original_cutover(
        &self,
        maintenance: &ConfigurationMaintenance,
        id: &TransactionId,
    ) -> JournalResult<OriginalCutover> {
        self.resync_cutover_for::<handoff::RetirementLinuxRoot>(maintenance, id)
    }
    pub(in crate::store) fn resync_native_cutover(
        &self,
        maintenance: &ConfigurationMaintenance,
        id: &TransactionId,
    ) -> JournalResult<OriginalCutover<NativeRootIdentity>> {
        self.resync_cutover_for::<NativeRootIdentity>(maintenance, id)
    }
    pub(in crate::store) fn resync_cutover_for<R: CutoverProofRoot>(
        &self,
        maintenance: &ConfigurationMaintenance,
        id: &TransactionId,
    ) -> JournalResult<OriginalCutover<R>> {
        if maintenance.transaction_id() != id {
            return Err(JournalError::Conflict);
        }
        self.owner.with_maintenance(maintenance, |state| {
            self.with_directory_locked(state, |dir| {
                let scan = files::scan(dir, self.budget)?;
                let before = original_for::<R>(&scan, id)?;
                check_canonical(state, &before, false)?;
                let mut used = scan_cutovers(&scan)?.used;
                used.extend(handoff::scan_handoffs(&scan)?.used);
                sync_existing(dir, &scan, &used)?;
                let after = original_for::<R>(&files::scan(dir, self.budget)?, id)?;
                if before.raw_intent != after.raw_intent
                    || before.host_pair != after.host_pair
                    || before.preservation != after.preservation
                    || before.scope_bindings != after.scope_bindings
                    || before.marker != after.marker
                    || before.before != after.before
                    || before.target != after.target
                    || before.phases != after.phases
                    || before.validation != after.validation
                    || before.validation_sha256 != after.validation_sha256
                    || before.paired_validation != after.paired_validation
                    || before.paired_validation_sha256 != after.paired_validation_sha256
                {
                    return Err(JournalError::Unknown);
                }
                check_canonical(state, &after, false).map_err(|_| JournalError::Unknown)?;
                Ok(after)
            })
        })
    }
}

/// Already under this exact owner's lock. This only recognizes an original
/// prepared successor whose exact target/marker are now canonical; it grants no
/// mutation, live-fence exception, phase advancement or admission authority.
pub(in crate::store) fn canonical_matches_retired_cutover_locked(
    journal: &OwnedManagementJournal,
    state: &ConfigurationState,
    retired: &handoff::LegacyCredentialRetirementIntent,
) -> JournalResult<bool> {
    journal.with_directory_locked(state, |dir| {
        let scan = files::scan(dir, journal.budget)?;
        let handoffs = handoff::scan_handoffs(&scan)?;
        if handoffs.records.len() != 1 || handoffs.records[0].intent != *retired {
            return Err(JournalError::Conflict);
        }
        let Some(source) = scan_cutovers(&scan)?
            .records
            .into_iter()
            .find(|r| r.intent.transaction_id == retired.transaction_id)
        else {
            return Ok(false);
        };
        if source
            .phases
            .first()
            .is_none_or(|p| p.stage != DurableStage::Prepared)
        {
            return Ok(false);
        }
        // Inventory also rejects unrelated/orphan files and uncommitted older
        // desired-state transactions. scan_cutovers itself has no recursion.
        let checked = original(&scan, &retired.transaction_id)?;
        check_canonical(state, &checked, true)?;
        Ok(true)
    })
}

#[cfg(all(test, target_os = "linux", target_env = "gnu"))]
#[path = "management_cutover_tests.rs"]
mod tests;
