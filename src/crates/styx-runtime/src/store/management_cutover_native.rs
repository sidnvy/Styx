//! Root/version selection for the existing cutover implementation. No alternate
//! parser, journal, phase machine or admission authority is introduced.
use super::*;
pub(in crate::store) trait CutoverProofRoot: handoff::ProofRoot {
    type Stamp: handoff::ProofStamp<Self>;
    fn retirement(
        inventory: handoff::HandoffInventory,
    ) -> JournalResult<handoff::ObservedRetirement<Self, Self::Stamp>>;
    fn cutovers(inventory: CutoverInventory) -> JournalResult<Vec<OriginalCutover<Self>>>;
    fn schema(endpoint: bool) -> JournalResult<u16>;
}
impl CutoverProofRoot for handoff::RetirementLinuxRoot {
    type Stamp = handoff::RetirementFileStamp;
    fn retirement(
        mut inventory: handoff::HandoffInventory,
    ) -> JournalResult<handoff::ObservedRetirement<Self, Self::Stamp>> {
        if !inventory.native_records.is_empty() || inventory.records.len() != 1 {
            return Err(JournalError::Conflict);
        }
        Ok(inventory.records.remove(0))
    }
    fn cutovers(inventory: CutoverInventory) -> JournalResult<Vec<OriginalCutover<Self>>> {
        if !inventory.native_records.is_empty() {
            return Err(JournalError::Conflict);
        }
        Ok(inventory.records)
    }
    fn schema(endpoint: bool) -> JournalResult<u16> {
        Ok(if endpoint { 2 } else { 1 })
    }
}
impl CutoverProofRoot for NativeRootIdentity {
    type Stamp = handoff::NativeRetirementFileStamp;
    fn retirement(
        mut inventory: handoff::HandoffInventory,
    ) -> JournalResult<handoff::ObservedRetirement<Self, Self::Stamp>> {
        if !inventory.records.is_empty() || inventory.native_records.len() != 1 {
            return Err(JournalError::Conflict);
        }
        Ok(inventory.native_records.remove(0))
    }
    fn cutovers(inventory: CutoverInventory) -> JournalResult<Vec<OriginalCutover<Self>>> {
        if !inventory.records.is_empty() {
            return Err(JournalError::Conflict);
        }
        Ok(inventory.native_records)
    }
    fn schema(endpoint: bool) -> JournalResult<u16> {
        if endpoint {
            Ok(3)
        } else {
            Err(JournalError::Unsupported)
        }
    }
}

/// Raw local composition input, never a network DTO or activation capability.
pub(crate) struct NativeCutoverInputs {
    pub history: NativeCutoverHistoryInputs,
    pub endpoint_mode: styx_contracts::native_management::NativeMigrationEndpointMode,
    pub preservation: Vec<u8>,
    pub scope_bindings: Vec<u8>,
    pub marker: Vec<u8>,
    pub before: Vec<u8>,
    pub target: Vec<u8>,
    pub endpoint: Option<CutoverEndpointInputs>,
}
pub(crate) enum NativeCutoverHistoryInputs {
    PreservedHostPair {
        bindings: Vec<u8>,
    },
    ImportedLocalGateway {
        baseline_sha256: Sha256Digest,
        committed_sha256: Sha256Digest,
        bindings: Vec<u8>,
    },
}
pub(super) struct NormalizedInputs {
    pub history_baseline_sha256: Option<Sha256Digest>,
    pub history_committed_sha256: Option<Sha256Digest>,
    pub schema4: bool,
    pub endpoint_mode: Option<styx_contracts::native_management::NativeMigrationEndpointMode>,
    pub history: Option<styx_contracts::native_management::NativeMigrationHistory>,
    pub host_pair: Option<Vec<u8>>,
    pub preservation: Vec<u8>,
    pub scope_bindings: Vec<u8>,
    pub marker: Vec<u8>,
    pub before: Vec<u8>,
    pub target: Vec<u8>,
    pub endpoint: Option<CutoverEndpointInputs>,
}
impl From<CutoverInputs> for NormalizedInputs {
    fn from(i: CutoverInputs) -> Self {
        Self {
            history_baseline_sha256: Some(i.history_baseline_sha256),
            history_committed_sha256: Some(i.history_committed_sha256),
            schema4: false,
            endpoint_mode: None,
            history: None,
            host_pair: None,
            preservation: i.preservation,
            scope_bindings: i.scope_bindings,
            marker: i.marker,
            before: i.before,
            target: i.target,
            endpoint: i.endpoint,
        }
    }
}
impl TryFrom<NativeCutoverInputs> for NormalizedInputs {
    type Error = JournalError;
    fn try_from(i: NativeCutoverInputs) -> JournalResult<Self> {
        use styx_contracts::native_management::{
            NativeMigrationEndpointMode as Mode, NativeMigrationHistory as History,
        };
        let (history, host_pair, baseline, committed) =
            match (i.endpoint_mode, i.history, i.endpoint.is_some()) {
                (
                    Mode::PreservedRemote,
                    NativeCutoverHistoryInputs::PreservedHostPair { bindings },
                    false,
                ) => {
                    if bindings.is_empty() || bindings.len() > MAX_RAW {
                        return Err(JournalError::InvalidInput);
                    }
                    (
                        History::PreservedHostPair {
                            source_bindings_sha256: Sha256Digest::of_bytes(&bindings),
                        },
                        Some(bindings),
                        None,
                        None,
                    )
                }
                (
                    Mode::IssuedLocal,
                    NativeCutoverHistoryInputs::ImportedLocalGateway {
                        baseline_sha256,
                        committed_sha256,
                        bindings,
                    },
                    true,
                ) => (
                    History::ImportedLocalGateway {
                        baseline_sha256,
                        committed_sha256,
                    },
                    Some(bindings),
                    Some(baseline_sha256),
                    Some(committed_sha256),
                ),
                _ => return Err(JournalError::InvalidInput),
            };
        Ok(Self {
            history_baseline_sha256: baseline,
            history_committed_sha256: committed,
            schema4: true,
            endpoint_mode: Some(i.endpoint_mode),
            history: Some(history),
            host_pair,
            preservation: i.preservation,
            scope_bindings: i.scope_bindings,
            marker: i.marker,
            before: i.before,
            target: i.target,
            endpoint: i.endpoint,
        })
    }
}

pub(super) fn validate_v4(
    original: &OriginalCutover<impl handoff::ProofRoot>,
    state: &styx_contracts::native_management::NativeState,
) -> JournalResult<()> {
    use styx_contracts::native_management::{
        NativeMigrationEndpointMode as Mode, NativeMigrationHistory as History,
        NativePreservedHostPair,
    };
    let i = &original.intent;
    let binding = state
        .migration_v2()
        .map_err(|_| JournalError::Conflict)?
        .ok_or(JournalError::Conflict)?;
    if i.schema != 4
        || state.reader_contract != ReaderContract::NativeMigratedStateV2
        || state.migration.is_some()
        || binding.schema != 2
        || Some(binding.host_pair_sha256) != i.host_pair_sha256
        || binding.transaction_id != i.transaction_id
        || binding.root_identity != i.config_root.native_identity()
        || binding.original_state_sha256 != i.before_state_sha256
        || binding.retired_receipt_sha256 != i.retired_record_sha256
        || binding.candidate_manifest_sha256 != i.candidate_manifest_sha256
        || binding.publisher_spki_sha256 != i.publisher_spki_sha256
        || binding.preservation_sha256 != i.preservation_sha256
        || binding.scope_bindings_sha256 != i.scope_bindings_sha256
        || Some(binding.endpoint_mode) != i.endpoint_mode
        || Some(&binding.history) != i.history.as_ref()
        || binding.original_token_relative_path
            != format!(
                "device/.styx-retired-host-token-{}",
                i.transaction_id.as_str()
            )
    {
        return Err(JournalError::Conflict);
    }
    let pair_raw = original
        .host_pair
        .as_deref()
        .ok_or(JournalError::Conflict)?;
    if pair_raw.len() > MAX_RAW || Some(Sha256Digest::of_bytes(pair_raw)) != i.host_pair_sha256 {
        return Err(JournalError::Conflict);
    }
    let common_pair: NativePreservedHostPair =
        serde_json::from_slice(pair_raw).map_err(|_| JournalError::Conflict)?;
    let common_origin =
        url::Url::parse(&common_pair.gateway_origin).map_err(|_| JournalError::Conflict)?;
    if common_pair.schema != 1
        || common_pair.transaction_id != i.transaction_id
        || common_pair.config_root != i.config_root.native_identity()
        || common_pair.host_root != i.host_root.native_identity()
        || common_pair.deployment_raw_sha256 != i.deployment_raw_sha256
        || common_pair.preservation_sha256 != i.preservation_sha256
        || common_origin.scheme() != "https"
        || common_origin.origin().ascii_serialization() != common_pair.gateway_origin
        || common_origin.host_str().is_none()
        || !common_origin.username().is_empty()
        || common_origin.password().is_some()
        || common_origin.query().is_some()
        || common_origin.fragment().is_some()
    {
        return Err(JournalError::Conflict);
    }
    match (i.endpoint_mode, i.history.as_ref()) {
        (
            Some(Mode::PreservedRemote),
            Some(History::PreservedHostPair {
                source_bindings_sha256,
            }),
        ) => {
            if i.history_baseline_sha256.is_some()
                || i.history_committed_sha256.is_some()
                || original.endpoint.is_some()
                || state.desired.gateway.is_some()
                || state.mode != NativeDeploymentMode::JoinExisting
            {
                return Err(JournalError::Conflict);
            }
            let raw = original.host_pair.as_ref().ok_or(JournalError::Conflict)?;
            if raw.len() > MAX_RAW || Sha256Digest::of_bytes(raw) != *source_bindings_sha256 {
                return Err(JournalError::Conflict);
            }
            let pair: NativePreservedHostPair =
                serde_json::from_slice(raw).map_err(|_| JournalError::Conflict)?;
            let origin =
                url::Url::parse(&pair.gateway_origin).map_err(|_| JournalError::Conflict)?;
            if pair.schema != 1
                || pair.transaction_id != i.transaction_id
                || pair.config_root != i.config_root.native_identity()
                || pair.host_root != i.host_root.native_identity()
                || pair.deployment_raw_sha256 != i.deployment_raw_sha256
                || pair.preservation_sha256 != i.preservation_sha256
                || origin.scheme() != "https"
                || origin.origin().ascii_serialization() != pair.gateway_origin
                || origin.host_str().is_none()
                || origin.username() != ""
                || origin.password().is_some()
                || origin.query().is_some()
                || origin.fragment().is_some()
            {
                return Err(JournalError::Conflict);
            }
        }
        (
            Some(Mode::IssuedLocal),
            Some(History::ImportedLocalGateway {
                baseline_sha256,
                committed_sha256,
            }),
        ) => {
            if original.endpoint.is_none()
                || i.history_baseline_sha256 != Some(*baseline_sha256)
                || i.history_committed_sha256 != Some(*committed_sha256)
                || state.mode != NativeDeploymentMode::CreateLocal
                || state.desired.gateway.is_none()
            {
                return Err(JournalError::Conflict);
            }
        }
        _ => return Err(JournalError::Conflict),
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreservedRemoteValidation {
    schema: u16,
    kind: String,
    transaction_id: TransactionId,
    candidate_manifest_sha256: Sha256Digest,
    target_sha256: Sha256Digest,
    source_bindings_sha256: Sha256Digest,
    origin: String,
    device_id: styx_contracts::identity::DeviceId,
    fingerprint: Sha256Digest,
    gateway_ca_pem_sha256: Sha256Digest,
    exit_code: i32,
    host_authenticated: bool,
    mcp_effect_verified: bool,
    foreign_owner_refused: bool,
    sdk_service_joined: bool,
    sdk_detached_tasks_joined: bool,
    mcp_session_closed: bool,
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
/// Data links and required observations only. Only the upper actual owned
/// validator may supply this report; JSON booleans are not an OS/network proof.
pub(super) fn validate_remote_report<R>(
    raw: &[u8],
    original: &OriginalCutover<R>,
) -> JournalResult<()> {
    use styx_contracts::native_management::{NativeMigrationHistory, NativePreservedHostPair};
    let report: PreservedRemoteValidation =
        serde_json::from_slice(raw).map_err(|_| JournalError::InvalidInput)?;
    let pair: NativePreservedHostPair = serde_json::from_slice(
        original
            .host_pair
            .as_deref()
            .ok_or(JournalError::Conflict)?,
    )
    .map_err(|_| JournalError::Conflict)?;
    let Some(NativeMigrationHistory::PreservedHostPair {
        source_bindings_sha256,
    }) = original.intent.history.as_ref()
    else {
        return Err(JournalError::Conflict);
    };
    if report.schema != 1
        || report.kind != "preserved_remote_host"
        || report.transaction_id != original.intent.transaction_id
        || report.candidate_manifest_sha256 != original.intent.candidate_manifest_sha256
        || report.target_sha256 != original.intent.target_state_sha256
        || report.source_bindings_sha256 != *source_bindings_sha256
        || report.origin != pair.gateway_origin
        || report.device_id != pair.device_id
        || report.fingerprint != pair.fingerprint
        || report.gateway_ca_pem_sha256 != pair.gateway_ca_pem_sha256
        || report.exit_code != 0
        || !report.host_authenticated
        || !report.mcp_effect_verified
        || !report.foreign_owner_refused
        || !report.sdk_service_joined
        || !report.sdk_detached_tasks_joined
        || !report.mcp_session_closed
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
