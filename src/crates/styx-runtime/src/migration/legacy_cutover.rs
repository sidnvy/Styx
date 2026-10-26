//! First conversion composition, retaining the original scope/writer/candidate.
//! Applied + candidate Exec evidence does not grant ordinary admission. Full
//! Gateway/Host maintenance validation and final C07 commit remain required.
use super::*;
use crate::store::{
    PrivateRoot, RootIdentity,
    enrollment::OwnedEnrollmentJournal,
    legacy_handoff::{
        AppliedNativeCutover, CommittedNativeCutover, CutoverInputs, PreparedNativeCutover,
    },
};
use serde::Serialize;
use std::{collections::BTreeMap, path::PathBuf};
use styx_contracts::{
    identity::Sha256Digest,
    management::{DurableStage, ReaderContract},
    native_management::*,
};

#[derive(Serialize)]
pub struct LegacyCutoverReport {
    pub schema: u8,
    pub stage: &'static str,
    pub transaction_id: styx_contracts::identity::TransactionId,
    pub target_sha256: Sha256Digest,
    pub prepared_sha256: Sha256Digest,
    pub applied_sha256: Option<Sha256Digest>,
    pub candidate_exec_validation_sha256: Option<Sha256Digest>,
    pub paired_validation_sha256: Option<Sha256Digest>,
    pub preservation: PreservationReport,
    pub network_ready: bool,
    pub migration_committed: bool,
    pub verified_sha256: Option<Sha256Digest>,
    pub committed_sha256: Option<Sha256Digest>,
    pub ordinary_service_promoted: bool,
}
/// Owned intermediate state, never a deserializable commit/activation flag.
/// Errors leave the original resources in this object; apply cannot be retried.
#[must_use]
pub struct PreparedLegacyCutover {
    pub(super) original: Arc<SettledLegacyRuntime>,
    pub(super) _state_dir: PathBuf,
    pub(super) preservation: Arc<OriginalPreservation>,
    pub(super) prepared: Arc<PreparedNativeCutover>,
    applied: Option<AppliedNativeCutover>,
    probe: Option<Arc<MigrationValidationProbe>>,
    network: Option<PairedGatewayValidation>,
    committed: Option<Arc<CommittedNativeCutover>>,
    ordinary: Option<crate::enrollment::shared::SharedEnrollment>,
    pub(super) validation_prepared: std::sync::atomic::AtomicBool,
    report: LegacyCutoverReport,
}
impl SettledLegacyRuntime {
    /// Desired manager/run/autostart is an explicit reviewed plan input. Old
    /// successful service steps never silently turn into a new run preference.
    pub fn prepare_native_transition(
        self: &Arc<Self>,
        state_dir: &Path,
        history: &mut OwnedEnrollmentJournal,
        desired: NativeDesired,
    ) -> Result<PreparedLegacyCutover, TransitionError> {
        // Refuse before any cutover write: a verified old worker closure does
        // not attest that its native entrypoint can read the target state.
        if !self
            .target()
            .supports_state_reader(ReaderContract::NativeMigratedStateV1)
            .map_err(|_| TransitionError::Unknown)?
        {
            return Err(TransitionError::Unsupported);
        }
        self.with_original_history(state_dir, |snapshot, owner, maintenance| {
            if !history.configuration_root().same_authority(owner) {
                return Err(TransitionError::Conflict);
            }
            let summary = snapshot.summary()?;
            snapshot.validate_preparation()?;
            let observation = history
                .with_historical_journal(maintenance, |journal| {
                    journal
                        .resync_historical()?
                        .ok_or(crate::store::enrollment::JournalError::Conflict)
                })
                .map_err(|_| TransitionError::Unknown)?;
            let committed = observation
                .committed
                .as_ref()
                .ok_or(TransitionError::Conflict)?;
            if observation.body.schema != 2
                || observation.body.migration != *maintenance.transaction_id()
                || observation.body.source_bindings_sha256 != summary.source_bindings_sha256
            {
                return Err(TransitionError::Conflict);
            }
            let profile = self
                .maintenance_profile(state_dir)
                .map_err(|_| TransitionError::Unknown)?;
            let retired = self.original_retirement()?;
            let preservation =
                super::preservation::capture(state_dir, &profile, &summary, &retired)?;
            let preservation_bytes = preservation.private_bytes()?;
            let scope_bindings = self.scope_bindings()?;
            let root = PrivateRoot::open(state_dir).map_err(|_| TransitionError::Conflict)?;
            let before = root
                .read_raw("state.json", NATIVE_STATE_BYTES)
                .map_err(|_| TransitionError::Unknown)?;
            let deployment = root
                .read_raw("deployment.json", NATIVE_STATE_BYTES)
                .map_err(|_| TransitionError::Unknown)?;
            let RootIdentity::Linux { device, inode, uid } =
                owner.identity().map_err(|_| TransitionError::Unknown)?;
            let sequence = self
                .original_fence()
                .cutover_sequence()
                .map_err(|_| TransitionError::Unknown)?;
            let mut entropy = [0u8; 32];
            getrandom::fill(&mut entropy).map_err(|_| TransitionError::Unavailable)?;
            let marker = NativeRootMarker {
                schema: NATIVE_MARKER_SCHEMA,
                kind: NativeRootKind::StyxConfigurationRoot,
                runtime_format: NativeRuntimeFormat::NativeRustV1,
                root_identity: NativeRootIdentity::Linux { device, inode, uid },
                scope_generation: Sha256Digest::from_bytes(entropy),
                reader_floor: ReaderContract::NativeMigratedStateV1,
            };
            let deployment_mode: serde_json::Value = serde_json::from_slice(deployment.bytes())
                .map_err(|_| TransitionError::Conflict)?;
            let mode = match deployment_mode.get("mode").and_then(|v| v.as_str()) {
                Some("create-local") => NativeDeploymentMode::CreateLocal,
                Some("join-existing") => NativeDeploymentMode::JoinExisting,
                _ => return Err(TransitionError::Unsupported),
            };
            let candidate = self.target().report();
            let migration = NativeMigrationBinding {
                transaction_id: maintenance.transaction_id().clone(),
                original_state_sha256: Sha256Digest::of_bytes(before.bytes()),
                retired_receipt_sha256: retired.retired_receipt_sha256,
                enrollment_baseline_sha256: observation.digest,
                enrollment_committed_sha256: committed
                    .digest()
                    .map_err(|_| TransitionError::Unknown)?,
                candidate_manifest_sha256: candidate.manifest_sha256,
                publisher_spki_sha256: candidate
                    .publisher_spki_sha256
                    .clone()
                    .try_into()
                    .map_err(|_| TransitionError::Conflict)?,
                preservation_sha256: Sha256Digest::of_bytes(&preservation_bytes),
                scope_bindings_sha256: Sha256Digest::of_bytes(&scope_bindings),
                original_token_relative_path: retired
                    .retired_relative_path
                    .to_str()
                    .ok_or(TransitionError::Unsupported)?
                    .to_owned(),
            };
            let original = serde_json::value::RawValue::from_string(
                std::str::from_utf8(before.bytes())
                    .map_err(|_| TransitionError::Conflict)?
                    .to_owned(),
            )
            .map_err(|_| TransitionError::Conflict)?;
            let endpoint = if desired.gateway.is_some() {
                Some(super::endpoint::issue_original_endpoint(
                    &root,
                    &profile,
                    &marker,
                    maintenance.transaction_id(),
                    candidate.manifest_sha256,
                )?)
            } else {
                None
            };
            preservation.revalidate()?;
            let mut extensions = BTreeMap::from([("original_legacy_state".into(), original)]);
            let selection = self
                .target()
                .runtime_selection()
                .map_err(|_| TransitionError::Unknown)?;
            extensions.insert(
                "runtime_selection_v1".into(),
                serde_json::value::RawValue::from_string(
                    serde_json::to_string(&selection).map_err(|_| TransitionError::Conflict)?,
                )
                .map_err(|_| TransitionError::Conflict)?,
            );
            if let Some(endpoint) = &endpoint {
                extensions.insert(
                    "gateway_endpoint_v1".into(),
                    serde_json::value::RawValue::from_string(
                        std::str::from_utf8(&endpoint.binding)
                            .map_err(|_| TransitionError::Conflict)?
                            .to_owned(),
                    )
                    .map_err(|_| TransitionError::Conflict)?,
                );
            }
            let gateway_runtime = deployment_mode
                .get("gateway")
                .and_then(|v| v.get("runtime"))
                .and_then(|v| v.get("baseDir"))
                .and_then(|v| v.as_str())
                .map(Path::new);
            extensions.insert(
                "legacy_owner_bindings_v1".into(),
                crate::store::committed_runtime::capture_legacy_owners(
                    state_dir,
                    profile.host_base_dir(),
                    gateway_runtime,
                )
                .map_err(|_| TransitionError::Unknown)?,
            );
            let target = NativeState {
                schema: NATIVE_STATE_SCHEMA,
                kind: NativeStateKind::StyxDesiredState,
                runtime_format: NativeRuntimeFormat::NativeRustV1,
                reader_contract: marker.reader_floor,
                scope_generation: marker.scope_generation,
                deployment_raw_sha256: Sha256Digest::of_bytes(deployment.bytes()),
                mode,
                revision: 1,
                last_transaction: Some(NativeStateTransaction {
                    transaction_id: maintenance.transaction_id().clone(),
                    sequence,
                }),
                desired,
                migration: Some(migration),
                extensions,
            };
            let target = serde_json::to_vec(&target).map_err(|_| TransitionError::Conflict)?;
            let prepared = self
                .original_fence()
                .prepare_native_cutover(CutoverInputs {
                    endpoint,
                    history_baseline_sha256: observation.digest,
                    history_committed_sha256: committed
                        .digest()
                        .map_err(|_| TransitionError::Unknown)?,
                    preservation: preservation_bytes,
                    scope_bindings,
                    marker: serde_json::to_vec(&marker).map_err(|_| TransitionError::Conflict)?,
                    before: before.bytes().to_vec(),
                    target,
                })
                .map_err(|_| TransitionError::Unknown)?;
            preservation.revalidate()?;
            let report = LegacyCutoverReport {
                schema: 1,
                stage: "prepared_original_cutover_only",
                transaction_id: prepared.transaction_id().clone(),
                target_sha256: prepared.target_sha256(),
                prepared_sha256: prepared.prepared_sha256(),
                applied_sha256: None,
                candidate_exec_validation_sha256: None,
                paired_validation_sha256: None,
                preservation: preservation.report(),
                network_ready: false,
                migration_committed: false,
                verified_sha256: None,
                committed_sha256: None,
                ordinary_service_promoted: false,
            };
            Ok(PreparedLegacyCutover {
                original: self.clone(),
                _state_dir: state_dir.to_owned(),
                preservation: Arc::new(preservation),
                prepared: Arc::new(prepared),
                applied: None,
                probe: None,
                network: None,
                committed: None,
                ordinary: None,
                validation_prepared: std::sync::atomic::AtomicBool::new(false),
                report,
            })
        })
    }
}
impl PreparedLegacyCutover {
    pub(in crate::migration) fn promoted_service(
        &self,
    ) -> Option<&crate::enrollment::shared::SharedEnrollment> {
        self.ordinary.as_ref()
    }
    pub fn report(&self) -> &LegacyCutoverReport {
        &self.report
    }
    /// Consume the report after the entry coordinator has settled its readers.
    /// This accessor supplies no commit or cleanup authority of its own.
    pub(crate) fn into_report(self) -> LegacyCutoverReport {
        self.report
    }
    /// Uncancellable short filesystem transition; caller still owns this object
    /// on error. It does not mark C07 Verified/Committed or clear any fence.
    pub fn apply_candidate(
        &mut self,
        probe: MigrationValidationProbe,
    ) -> Result<(), TransitionError> {
        if self.probe.is_some()
            || self.applied.is_some()
            || !Arc::ptr_eq(probe.original_runtime(), &self.original)
        {
            return Err(TransitionError::Conflict);
        }
        self.probe = Some(Arc::new(probe));
        self.apply_stored_probe()
    }
    /// Preserve the actual paired proof, including the one recovered journal.
    /// Network readiness never itself grants final commit or ordinary startup.
    pub fn apply_gateway_validated_candidate(
        &mut self,
        proof: PairedGatewayValidation,
    ) -> Result<(), TransitionError> {
        if self.probe.is_some()
            || self.applied.is_some()
            || self.network.is_some()
            || !proof.matches(&self.original, &self.prepared)
        {
            return Err(TransitionError::Conflict);
        }
        let handle =
            tokio::runtime::Handle::try_current().map_err(|_| TransitionError::Unsupported)?;
        if handle.runtime_flavor() != tokio::runtime::RuntimeFlavor::MultiThread {
            return Err(TransitionError::Unsupported);
        }
        tokio::task::block_in_place(|| handle.block_on(proof.revalidate(None)))?;
        self.probe = Some(proof.local_probe());
        self.network = Some(proof);
        self.apply_stored_probe()?;
        let applied = self.applied.as_ref().ok_or(TransitionError::Unknown)?;
        let proof = self.network.as_ref().ok_or(TransitionError::Unknown)?;
        tokio::task::block_in_place(|| handle.block_on(proof.revalidate(Some(applied))))?;
        let raw = serde_json::to_vec(proof.report()).map_err(|_| TransitionError::Unknown)?;
        self.report.paired_validation_sha256 = Some(Sha256Digest::of_bytes(&raw));
        self.report.network_ready = true;
        self.report.stage = "applied_original_pair_network_validated_final_commit_required";
        Ok(())
    }
    /// Finish the already validated original transaction, then publish a new
    /// reader epoch on the SAME enrollment service. No old request gate reopens.
    /// A cancelled promotion waiter can retrieve the retained completed result
    /// with the same proof; committed actions are never replayed.
    pub async fn commit_gateway_validated_candidate(&mut self) -> Result<(), TransitionError> {
        if self.ordinary.is_some() {
            return Err(TransitionError::Conflict);
        }
        if self.committed.is_none() {
            let handle =
                tokio::runtime::Handle::try_current().map_err(|_| TransitionError::Unsupported)?;
            if handle.runtime_flavor() != tokio::runtime::RuntimeFlavor::MultiThread {
                return Err(TransitionError::Unsupported);
            }
            tokio::task::block_in_place(|| {
                let applied = self.applied.as_ref().ok_or(TransitionError::Conflict)?;
                let network = self.network.as_ref().ok_or(TransitionError::Conflict)?;
                if !self.report.network_ready || !network.matches(&self.original, &self.prepared) {
                    return Err(TransitionError::Conflict);
                }
                handle.block_on(network.revalidate(Some(applied)))?;
                self.original
                    .target()
                    .runtime_selection()
                    .map_err(|_| TransitionError::Unknown)?;
                self.preservation.revalidate_except_canonical()?;
                let raw =
                    serde_json::to_vec(network.report()).map_err(|_| TransitionError::Unknown)?;
                let fence = self.original.original_fence();
                let paired = fence
                    .record_cutover_paired_validation(applied, &raw)
                    .map_err(|_| TransitionError::Unknown)?;
                if self.report.paired_validation_sha256 != Some(paired) {
                    return Err(TransitionError::Unknown);
                }
                let verified = fence
                    .record_cutover_phase(applied, DurableStage::Verified)
                    .map_err(|_| TransitionError::Unknown)?;
                self.report.verified_sha256 = Some(verified.record_sha256);
                // Recheck actual retained scopes/effects immediately before the
                // last durable phase. Any uncertain cleanup leaves admission shut.
                handle.block_on(network.revalidate(Some(applied)))?;
                let committed = fence
                    .record_cutover_phase(applied, DurableStage::Committed)
                    .map_err(|_| TransitionError::Unknown)?;
                self.report.committed_sha256 = Some(committed.record_sha256);
                let proof = fence
                    .finish_original_cutover(applied, committed)
                    .map_err(|_| TransitionError::Unknown)?;
                self.committed = Some(Arc::new(proof));
                self.report.migration_committed = true;
                self.report.stage = "committed_same_service_promotion_required";
                Ok::<(), TransitionError>(())
            })?;
        }
        let proof = self
            .committed
            .as_ref()
            .ok_or(TransitionError::Unknown)?
            .clone();
        let network = self.network.as_ref().ok_or(TransitionError::Unknown)?;
        let ordinary = network.promote_committed(proof).await?;
        self.ordinary = Some(ordinary);
        self.report.ordinary_service_promoted = true;
        self.report.stage = "committed_same_service_promoted";
        Ok(())
    }
    fn apply_stored_probe(&mut self) -> Result<(), TransitionError> {
        let handle =
            tokio::runtime::Handle::try_current().map_err(|_| TransitionError::Unsupported)?;
        if handle.runtime_flavor() != tokio::runtime::RuntimeFlavor::MultiThread {
            return Err(TransitionError::Unsupported);
        }
        tokio::task::block_in_place(|| {
            let probe = self.probe.as_ref().ok_or(TransitionError::Conflict)?;
            handle.block_on(probe.revalidate())?;
            self.preservation.revalidate()?;
            let applied = self
                .original
                .original_fence()
                .apply_native_cutover(&self.prepared)
                .map_err(|_| TransitionError::Unknown)?;
            self.applied = Some(applied);
            let applied = self.applied.as_ref().ok_or(TransitionError::Unknown)?;
            if applied.target_sha256() != self.report.target_sha256 {
                return Err(TransitionError::Unknown);
            }
            self.preservation.revalidate_except_canonical()?;
            handle.block_on(probe.revalidate_after_canonical(applied))?;
            let receipt = self
                .original
                .original_fence()
                .record_cutover_phase(applied, DurableStage::Applied)
                .map_err(|_| TransitionError::Unknown)?;
            let report =
                serde_json::to_vec(probe.report()).map_err(|_| TransitionError::Unknown)?;
            let validation = self
                .original
                .original_fence()
                .record_cutover_validation(applied, &report)
                .map_err(|_| TransitionError::Unknown)?;
            self.preservation.revalidate_except_canonical()?;
            handle.block_on(self.original.revalidate())?;
            if self
                .original
                .configuration_root()
                .ensure_admission()
                .is_ok()
            {
                return Err(TransitionError::Unknown);
            }
            self.report.stage =
                "applied_candidate_exec_verified_gateway_validation_and_final_commit_required";
            self.report.applied_sha256 = Some(receipt.record_sha256);
            self.report.candidate_exec_validation_sha256 = Some(validation);
            Ok(())
        })
    }
}

/// Existing pending data can be inspected after process exit. Inspection never
/// recreates physical scope/probe proof, resumes an action or opens dispatch.
pub fn inspect_pending_cutover(
    owner: OwnedConfigurationRoot,
) -> Result<crate::store::legacy_handoff::PendingNativeCutoverReport, TransitionError> {
    crate::store::legacy_handoff::inspect_pending_native_cutover(owner).map_err(|error| match error
    {
        crate::store::enrollment::JournalError::Unknown => TransitionError::Unknown,
        crate::store::enrollment::JournalError::Unsupported => TransitionError::Unsupported,
        _ => TransitionError::Conflict,
    })
}
