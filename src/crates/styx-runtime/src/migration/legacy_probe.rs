//! One fixed, maintenance-only candidate Exec validation. This does not create
//! ordinary Host admission, a network owner, a credential, or a migration commit.
//! Dropping the caller never aborts the owned task or releases a live executor's
//! image/lease. Bootstrap failures lack a retained-child cleanup API today: they
//! conservatively retain the ONE slot forever instead of claiming recovery.
use super::{SettledLegacyRuntime, TransitionError};
use crate::{
    foreground::profile::LoadedMaintenanceProfile,
    host::{bootstrap::OwnedExecHost, coordinator::StartSubmission},
    providers::codex::{DispatchEvidence, StartProcess, TerminationEvidence},
    store::{ExecutionLeaseGuard, FileObservation, PrivateRoot},
};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use styx_contracts::{
    capability::{Authorization, Availability, CapabilityDescriptor, CapabilityId, Scope},
    error::Recovery,
    identity::{DeviceId, HostGeneration, ProviderId, Sha256Digest, TransactionId},
    operation::{
        DisconnectPolicy, ExecutionLiveness, MonotonicMillis, OperationId, OutputDrain,
        PreparedContext,
    },
};
use styx_core::{operations::OwnerLease, policy::AdmissionFacts};
use tokio::sync::{Semaphore, SemaphorePermit, oneshot};

static PROBE_SLOT: Semaphore = Semaphore::const_new(1);
const COMMAND_BUDGET: Duration = Duration::from_secs(20);
const CLEANUP_BUDGET: Duration = Duration::from_secs(30);

#[derive(Debug, Serialize)]
pub struct MigrationProbeReport {
    pub schema: u8,
    pub status: &'static str,
    pub failure_recovery: &'static str,
    pub scope: &'static str,
    pub transaction_id: TransactionId,
    pub candidate_manifest_sha256: Sha256Digest,
    pub device_id: DeviceId,
    pub operation: OperationId,
    pub payload_digest: Sha256Digest,
    pub nonce_sha256: Sha256Digest,
    pub nonce_relative_path: PathBuf,
    pub nonce_bytes: usize,
    pub stdout_bytes: usize,
    pub exit_code: i32,
    pub liveness: ExecutionLiveness,
    pub drain: OutputDrain,
    pub executor_exited: bool,
    pub processes_exited: bool,
    pub reader_task_reaped: bool,
    pub stderr_task_reaped: bool,
    pub supervised_jobs_joined: bool,
    pub probe_task_joined: bool,
}
struct Effect {
    observation: FileObservation,
    digest: Sha256Digest,
    bytes: usize,
}
struct Custody {
    original: Arc<SettledLegacyRuntime>,
    profile: LoadedMaintenanceProfile,
    base: PrivateRoot,
    lease: ExecutionLeaseGuard,
    _slot: SemaphorePermit<'static>,
    nonce_relative_path: PathBuf,
    effect: Mutex<Option<Effect>>,
}
impl Custody {
    fn record_effect(&self, expected: &[u8]) -> Result<(), TransitionError> {
        let first = self
            .base
            .read_raw(&self.nonce_relative_path, 256)
            .map_err(|_| TransitionError::Unknown)?;
        let second = self
            .base
            .read_raw(&self.nonce_relative_path, 256)
            .map_err(|_| TransitionError::Unknown)?;
        if first.bytes() != expected
            || second.bytes() != expected
            || first.observation() != second.observation()
        {
            return Err(TransitionError::Unknown);
        }
        let mut effect = self.effect.lock().map_err(|_| TransitionError::Unknown)?;
        if effect.is_some() {
            return Err(TransitionError::Conflict);
        }
        *effect = Some(Effect {
            observation: first.observation().clone(),
            digest: Sha256Digest::of_bytes(first.bytes()),
            bytes: first.bytes().len(),
        });
        Ok(())
    }
    fn revalidate_exact_effect(&self) -> Result<(), TransitionError> {
        let effect = self.effect.lock().map_err(|_| TransitionError::Unknown)?;
        let expected = effect.as_ref().ok_or(TransitionError::Unknown)?;
        for _ in 0..2 {
            let current = self
                .base
                .read_raw(&self.nonce_relative_path, 256)
                .map_err(|_| TransitionError::Unknown)?;
            if current.observation() != &expected.observation
                || current.bytes().len() != expected.bytes
                || Sha256Digest::of_bytes(current.bytes()) != expected.digest
            {
                return Err(TransitionError::Unknown);
            }
        }
        Ok(())
    }
    fn validate(&self) -> Result<(), TransitionError> {
        self.lease
            .validate()
            .map_err(|_| TransitionError::Unknown)?;
        let current = PrivateRoot::open(self.profile.host_base_dir())
            .map_err(|_| TransitionError::Unknown)?;
        if current.identity() != self.base.identity() {
            return Err(TransitionError::Unknown);
        }
        self.profile
            .revalidate()
            .map_err(|_| TransitionError::Unknown)
    }
}
/// Non-Clone/non-Deserialize maintenance proof. Retains original state writer,
/// original scope proofs, signed images and execution lease after physical exit.
#[must_use]
pub struct MigrationValidationProbe {
    custody: Arc<Custody>,
    report: MigrationProbeReport,
}
impl MigrationValidationProbe {
    pub fn report(&self) -> &MigrationProbeReport {
        &self.report
    }
    pub(crate) fn original_runtime(&self) -> &Arc<SettledLegacyRuntime> {
        &self.custody.original
    }
    /// The local executor has actually exited; retain its existing Host lease
    /// while a fresh network validation executor is owned by the coordinator.
    pub(super) fn validate_host_lease(&self) -> Result<(), TransitionError> {
        self.custody
            .lease
            .validate()
            .map_err(|_| TransitionError::Unknown)
    }
    /// Only the exact opaque canonical effect may select this variant. Full
    /// pre-cutover profile checks remain in revalidate(); the coordinator must
    /// revalidate every other captured preservation input after replacement.
    pub(crate) async fn revalidate_after_canonical(
        &self,
        applied: &crate::store::legacy_handoff::AppliedNativeCutover,
    ) -> Result<(), TransitionError> {
        if applied.transaction_id() != &self.report.transaction_id
            || applied.candidate_sha256() != self.report.candidate_manifest_sha256
        {
            return Err(TransitionError::Conflict);
        }
        self.original_runtime().revalidate().await?;
        let custody = self.custody.clone();
        tokio::task::spawn_blocking(move || {
            custody
                .lease
                .validate()
                .map_err(|_| TransitionError::Unknown)?;
            let current = PrivateRoot::open(custody.profile.host_base_dir())
                .map_err(|_| TransitionError::Unknown)?;
            if current.identity() != custody.base.identity() {
                return Err(TransitionError::Unknown);
            }
            custody
                .profile
                .revalidate_worker_closures()
                .map_err(|_| TransitionError::Unknown)?;
            custody.revalidate_exact_effect()
        })
        .await
        .map_err(|_| TransitionError::Unknown)??;
        self.original_runtime().revalidate().await
    }
    pub(crate) async fn revalidate(&self) -> Result<(), TransitionError> {
        self.original_runtime().revalidate().await?;
        let retained = self.custody.clone();
        tokio::task::spawn_blocking(move || {
            retained.validate()?;
            retained.revalidate_exact_effect()
        })
        .await
        .map_err(|_| TransitionError::Unknown)??;
        self.original_runtime().revalidate().await
    }
}
impl SettledLegacyRuntime {
    /// Fixed argv-separated noclobber shell program only. No caller command or network connection,
    /// ordinary profile conversion, action retry or restored credential locator.
    pub async fn validate_candidate_exec(
        self: &Arc<Self>,
        state_dir: &Path,
    ) -> Result<MigrationValidationProbe, TransitionError> {
        // This slot precedes every FS/process IO and survives Unknown/drop.
        let slot = PROBE_SLOT
            .try_acquire()
            .map_err(|_| TransitionError::Busy)?;
        let original = self.clone();
        let state_dir = state_dir.to_owned();
        let (sender, receiver) = oneshot::channel();
        let job = tokio::spawn(async move {
            run_owned(original, state_dir, slot, sender).await;
        });
        let mut proof = receiver.await.map_err(|_| TransitionError::Unknown)??;
        job.await.map_err(|_| TransitionError::Unknown)?;
        proof.report.probe_task_joined = true;
        Ok(proof)
    }
}

pub(super) fn facts(device: DeviceId) -> AdmissionFacts {
    // Local, fixed validation only. This private Core authority is never a
    // Gateway-issued owner/grant and is never exposed to ordinary dispatch.
    AdmissionFacts {
        device_id: device,
        grant_revision: 1,
        local_policy_allowed: true,
        descriptor: CapabilityDescriptor {
            contract_version: styx_contracts::CONTRACT_VERSION,
            capability_id: CapabilityId::ExecRun,
            scope: Scope::Host,
            provider_id: ProviderId::try_from("codex").expect("static provider"),
            configured: true,
            remote_grant: true,
            availability: Availability::Available,
            authorization: Authorization::Granted,
            target_session: None,
            reason: None,
            observed_at: 0,
            observation_generation: 1,
            recovery: Recovery::None,
        },
        session_state: None,
        current_observation: None,
    }
}
fn context(host: &OwnedExecHost, device: &DeviceId) -> PreparedContext {
    PreparedContext {
        device_id: device.clone(),
        grant_revision: 1,
        session: None,
        observation: None,
        capability: CapabilityId::ExecRun,
        deadline: MonotonicMillis(host.coordinator().now().0.saturating_add(20000)),
        disconnect_policy: DisconnectPolicy::RetainForOwner,
    }
}
struct Executed {
    operation: OperationId,
    digest: Sha256Digest,
    stdout_bytes: usize,
    nonce_digest: Sha256Digest,
    nonce: String,
}
async fn execute(
    host: &OwnedExecHost,
    device: &DeviceId,
    cwd: &Path,
    nonce_path: &Path,
) -> Result<Executed, TransitionError> {
    let owner: OwnerLease = host
        .authority()
        .register_verified_owner(
            "migration-validation"
                .try_into()
                .map_err(|_| TransitionError::Conflict)?,
            uuid::Uuid::new_v4()
                .to_string()
                .try_into()
                .map_err(|_| TransitionError::Conflict)?,
        )
        .map_err(|_| TransitionError::Unknown)?;
    let nonce = format!("styx-maintenance-{}\n", uuid::Uuid::new_v4());
    let spec = StartProcess {
        argv: vec![
            "/bin/sh".into(),
            "-c".into(),
            "set -e; umask 077; set -C; printf \"%s\" \"$2\" > \"$1\"; printf \"%s\" \"$2\"".into(),
            "styx-migration-validation".into(),
            nonce_path
                .to_str()
                .ok_or(TransitionError::Conflict)?
                .to_owned(),
            nonce.clone(),
        ],
        cwd_file_uri: url::Url::from_directory_path(cwd)
            .map_err(|_| TransitionError::Conflict)?
            .to_string(),
        environment: BTreeMap::new(),
        tty: false,
    };
    let start = host
        .coordinator()
        .prepare_start(&owner, context(host, device), &spec)
        .map_err(|_| TransitionError::Unknown)?;
    match host
        .coordinator()
        .dispatch_start(&owner, &start.id, start.payload_digest)
        .map_err(|_| TransitionError::Unknown)?
    {
        StartSubmission::Submitted(ticket) => {
            if ticket
                .wait()
                .await
                .map_err(|_| TransitionError::Unknown)?
                .dispatch
                != DispatchEvidence::Started
            {
                return Err(TransitionError::Unknown);
            }
        }
        StartSubmission::Existing(_) => return Err(TransitionError::Unknown),
    }
    let mut stdout = String::new();
    loop {
        let page = host
            .coordinator()
            .read(
                &owner,
                &start.id,
                start.payload_digest,
                &context(host, device),
                256,
                Duration::from_millis(50),
            )
            .await
            .map_err(|_| TransitionError::Unknown)?;
        for chunk in page.chunks {
            if chunk.stream != "stdout" || stdout.len().saturating_add(chunk.text.len()) > 256 {
                return Err(TransitionError::Unknown);
            }
            stdout.push_str(&chunk.text);
        }
        if page.drain == OutputDrain::Drained {
            if page.liveness != ExecutionLiveness::Exited
                || page.exit_code != Some(0)
                || stdout != nonce
            {
                return Err(TransitionError::Unknown);
            }
            return Ok(Executed {
                operation: start.id,
                digest: start.payload_digest,
                stdout_bytes: stdout.len(),
                nonce_digest: Sha256Digest::of_bytes(nonce.as_bytes()),
                nonce,
            });
        }
    }
}
async fn run_owned(
    original: Arc<SettledLegacyRuntime>,
    state_dir: std::path::PathBuf,
    slot: SemaphorePermit<'static>,
    sender: oneshot::Sender<Result<MigrationValidationProbe, TransitionError>>,
) {
    if let Err(error) = original.revalidate().await {
        let _ = sender.send(Err(error));
        return;
    }
    let retained = original.clone();
    let prepared = tokio::task::spawn_blocking(move || {
        let profile = retained
            .maintenance_profile(&state_dir)
            .map_err(|_| TransitionError::Conflict)?;
        let base =
            PrivateRoot::open(profile.host_base_dir()).map_err(|_| TransitionError::Conflict)?;
        let lease = base
            .try_execution_lease()
            .map_err(|_| TransitionError::Busy)?;
        let nonce_relative_path = PathBuf::from(format!(
            ".styx-migration-probe-{}",
            retained.maintenance_transaction().as_str()
        ));
        base.ensure_absent(&nonce_relative_path)
            .map_err(|_| TransitionError::Conflict)?;
        let custody = Arc::new(Custody {
            original: retained,
            profile,
            base,
            lease,
            _slot: slot,
            nonce_relative_path,
            effect: Mutex::new(None),
        });
        custody.validate()?;
        let mut config = custody
            .profile
            .executor_config()
            .map_err(|_| TransitionError::Conflict)?;
        config.rpc_timeout = config.rpc_timeout.min(Duration::from_secs(5));
        config.retained_process_limit = 2;
        Ok::<_, TransitionError>((custody, config))
    })
    .await;
    let (custody, config) = match prepared {
        Ok(Ok(prepared)) => prepared,
        Ok(Err(error)) => {
            let _ = sender.send(Err(error));
            return;
        }
        Err(_) => {
            let _ = sender.send(Err(TransitionError::Unknown));
            return;
        }
    };
    let cwd = config.cwd.clone();
    if let Err(error) = custody.original.revalidate().await {
        let _ = sender.send(Err(error));
        return;
    }
    let generation: HostGeneration = match uuid::Uuid::new_v4().to_string().try_into() {
        Ok(value) => value,
        Err(_) => {
            let _ = sender.send(Err(TransitionError::Conflict));
            return;
        }
    };
    let host = match OwnedExecHost::spawn(
        config,
        generation,
        facts(custody.profile.device_id().clone()),
        2,
    )
    .await
    {
        Ok(host) => host,
        Err(_) => {
            let _ = sender.send(Err(TransitionError::Unknown));
            // Bootstrap has no retained-failure cleanup receipt. Never turn an
            // error into "not started" or release the original execution lease.
            std::future::pending::<()>().await;
            drop(custody);
            return;
        }
    };
    // No business bytes are sent before original custody and scope revalidation.
    let retained = custody.clone();
    let checked = tokio::task::spawn_blocking(move || retained.validate()).await;
    let execution = match checked {
        Ok(Ok(())) => match custody.original.revalidate().await {
            Ok(()) => tokio::time::timeout(
                COMMAND_BUDGET,
                execute(
                    &host,
                    custody.profile.device_id(),
                    &cwd,
                    &custody
                        .profile
                        .host_base_dir()
                        .join(&custody.nonce_relative_path),
                ),
            )
            .await
            .unwrap_or(Err(TransitionError::Unknown)),
            Err(error) => Err(error),
        },
        _ => Err(TransitionError::Unknown),
    };
    // One explicit cleanup attempt; Unknown keeps the physical object, lease,
    // profile and bounded slot, not a retry loop or a recreated executor.
    let cleanup = match host.shutdown_owned(CLEANUP_BUDGET).await {
        Ok(value) => value,
        Err(_) => {
            let _ = sender.send(Err(TransitionError::Unknown));
            std::future::pending::<()>().await;
            drop((host, custody));
            return;
        }
    };
    let complete = cleanup.supervised_jobs_joined
        && cleanup.ancillary_providers_settled()
        && cleanup.native.as_ref().is_some_and(|n| {
            n.executor_exited
                && n.reader_task_reaped
                && n.stderr_task_reaped
                && n.processes
                    .iter()
                    .all(|(_, e)| matches!(e, TerminationEvidence::ProcessExited(_)))
        });
    if !complete {
        let _ = sender.send(Err(TransitionError::Unknown));
        std::future::pending::<()>().await;
        drop((host, custody));
        return;
    }
    let executed = match execution {
        Ok(value) => value,
        Err(error) => {
            let _ = sender.send(Err(error));
            return;
        }
    };
    let native = match cleanup.native.as_ref() {
        Some(value) => value,
        None => {
            let _ = sender.send(Err(TransitionError::Unknown));
            return;
        }
    };
    if !native.processes.iter().any(|(handle, e)| {
        handle.operation() == &executed.operation
            && matches!(e, TerminationEvidence::ProcessExited(0))
    }) {
        let _ = sender.send(Err(TransitionError::Unknown));
        return;
    }
    // Only a successfully ACKed, fully drained exit0 operation reaches this
    // read. A late file after timeout/Unknown never upgrades operation history.
    let retained = custody.clone();
    let nonce = executed.nonce;
    match tokio::task::spawn_blocking(move || retained.record_effect(nonce.as_bytes())).await {
        Ok(Ok(())) => {}
        _ => {
            let _ = sender.send(Err(TransitionError::Unknown));
            return;
        }
    }
    let report = MigrationProbeReport {
        schema: 1,
        status: "PASS_FIXED_LOCAL_CANDIDATE_EXEC_AND_PHYSICAL_CLEANUP",
        failure_recovery: "bootstrap_or_cleanup_unknown_retains_single_slot_and_custody; recovery_not_implemented",
        scope: "fixed local candidate Exec private noncefile plus stdout/exit/cleanup validation only; no ordinary admission or C07 commit",
        transaction_id: custody.original.maintenance_transaction(),
        candidate_manifest_sha256: custody.original.target().report().manifest_sha256,
        device_id: custody.profile.device_id().clone(),
        operation: executed.operation,
        payload_digest: executed.digest,
        nonce_sha256: executed.nonce_digest,
        nonce_relative_path: custody.nonce_relative_path.clone(),
        nonce_bytes: executed.stdout_bytes,
        stdout_bytes: executed.stdout_bytes,
        exit_code: 0,
        liveness: ExecutionLiveness::Exited,
        drain: OutputDrain::Drained,
        executor_exited: native.executor_exited,
        processes_exited: true,
        reader_task_reaped: native.reader_task_reaped,
        stderr_task_reaped: native.stderr_task_reaped,
        supervised_jobs_joined: cleanup.supervised_jobs_joined,
        probe_task_joined: false,
    };
    drop(host);
    let proof = MigrationValidationProbe { custody, report };
    if let Err(error) = proof.revalidate().await {
        let _ = sender.send(Err(error));
        return;
    }
    let _ = sender.send(Ok(proof));
}
