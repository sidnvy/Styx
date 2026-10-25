//! Fixed local Exec validation under an actual applied Mac maintenance profile.
//! This is not remote authentication, full capability validation or C07 proof.
//! The outer non-aborted owned migration task must retain the entire original
//! scope through the joined worker AND all bootstrap/cleanup outcomes. Dropping run's
//! future is NOT dropping/settling this probe; dropping this probe is NOT cleanup.
//! In particular, cancellation during spawn_optional_pinned before it returns
//! cannot be justified by host: Option below. Such an attempt remains Unknown.
use crate::{
    foreground::profile::AppliedMacMaintenanceProfile,
    host::{bootstrap::OwnedExecHost, coordinator::StartSubmission},
    providers::codex::{DispatchEvidence, StartProcess, TerminationEvidence},
    store::{ExecutionLeaseGuard, FileObservation, PrivateRoot},
};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
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
use tokio::sync::{Semaphore, SemaphorePermit};

static SLOT: Semaphore = Semaphore::const_new(1);
const COMMAND_BUDGET: Duration = Duration::from_secs(20);
const CLEANUP_BUDGET: Duration = Duration::from_secs(30);
#[derive(Debug, Clone, Copy, thiserror::Error)]
pub(crate) enum MacExecValidationError {
    #[error("mac_maintenance_probe_conflict")]
    Conflict,
    #[error("mac_maintenance_probe_busy")]
    Busy,
    #[error("mac_maintenance_probe_unknown")]
    Unknown,
}
type Result<T> = std::result::Result<T, MacExecValidationError>;
/// DATA only. No Serialize/Clone capability or final migration proof is derived
/// from this report. No task-joined fact is fabricated for an inline future.
#[derive(Serialize)]
pub(crate) struct MacCandidateExecReport {
    schema: u8,
    status: &'static str,
    scope: &'static str,
    transaction_id: TransactionId,
    candidate_manifest_sha256: Sha256Digest,
    device_id: DeviceId,
    operation: OperationId,
    payload_digest: Sha256Digest,
    nonce_sha256: Sha256Digest,
    nonce_relative_path: PathBuf,
    nonce_bytes: usize,
    stdout_bytes: usize,
    exit_code: i32,
    liveness: ExecutionLiveness,
    drain: OutputDrain,
    executor_exited: bool,
    processes_exited: bool,
    reader_task_reaped: bool,
    stderr_task_reaped: bool,
    supervised_jobs_joined: bool,
    inline_probe_future_completed: bool,
    probe_task_joined: bool,
}
struct Effect {
    observation: FileObservation,
    digest: Sha256Digest,
    len: usize,
}
/// No Clone/Serde/Drop cleanup and no constructor from a report, filename,
/// standalone Pair reader or candidate locator. One object means one attempt.
/// Keep it in the SAME outer owned task as the original applied guard.
pub(crate) struct MacCandidateExecProbe<'profile, 'borrow, 'effects, 'materials> {
    profile: &'profile AppliedMacMaintenanceProfile<'borrow, 'effects, 'materials>,
    base: PrivateRoot,
    lease: ExecutionLeaseGuard,
    _slot: SemaphorePermit<'static>,
    nonce_relative_path: PathBuf,
    transaction: TransactionId,
    host: Option<OwnedExecHost>,
    attempted: bool,
    unknown: bool,
    effect: Option<Effect>,
    report: Option<MacCandidateExecReport>,
}
impl<'profile, 'borrow, 'effects, 'materials>
    MacCandidateExecProbe<'profile, 'borrow, 'effects, 'materials>
{
    pub(crate) fn prepare(
        profile: &'profile AppliedMacMaintenanceProfile<'borrow, 'effects, 'materials>,
    ) -> Result<Self> {
        profile
            .revalidate()
            .map_err(|_| MacExecValidationError::Unknown)?;
        let slot = SLOT
            .try_acquire()
            .map_err(|_| MacExecValidationError::Busy)?;
        let base = PrivateRoot::open(profile.host_base_dir())
            .map_err(|_| MacExecValidationError::Unknown)?;
        let lease = base
            .try_execution_lease()
            .map_err(|_| MacExecValidationError::Busy)?;
        let transaction = profile.transaction_id().clone();
        let nonce_relative_path =
            PathBuf::from(format!(".styx-migration-probe-{}", transaction.as_str()));
        base.ensure_absent(&nonce_relative_path)
            .map_err(|_| MacExecValidationError::Conflict)?;
        let value = Self {
            profile,
            base,
            lease,
            _slot: slot,
            nonce_relative_path,
            transaction,
            host: None,
            attempted: false,
            unknown: false,
            effect: None,
            report: None,
        };
        value.validate_inputs()?;
        Ok(value)
    }
    fn validate_inputs(&self) -> Result<()> {
        self.profile
            .revalidate()
            .map_err(|_| MacExecValidationError::Unknown)?;
        if self.profile.transaction_id() != &self.transaction {
            return Err(MacExecValidationError::Unknown);
        }
        self.lease
            .validate()
            .map_err(|_| MacExecValidationError::Unknown)?;
        let current = PrivateRoot::open(self.profile.host_base_dir())
            .map_err(|_| MacExecValidationError::Unknown)?;
        if current.identity() != self.base.identity() {
            return Err(MacExecValidationError::Unknown);
        }
        Ok(())
    }
    /// Call from the retained outer blocking owner, never an async runtime thread.
    /// The scoped worker borrows this SAME probe and its original guard chain.
    /// Its actual join settles the validation task before a successful report is
    /// exposed; a disconnected waiter cannot cancel or detach that worker.
    pub(crate) fn run_joined(
        &mut self,
        runtime: &tokio::runtime::Handle,
    ) -> Result<&MacCandidateExecReport> {
        if self.attempted || self.unknown {
            return Err(MacExecValidationError::Conflict);
        }
        let outcome = std::thread::scope(|scope| {
            std::thread::Builder::new()
                .name("styx-mac-migration-probe".into())
                .spawn_scoped(scope, || runtime.block_on(self.run()).map(|_| ()))
                .map_err(|_| MacExecValidationError::Busy)?
                .join()
                .map_err(|_| MacExecValidationError::Unknown)?
        });
        if let Err(error) = outcome {
            // A failed spawn has no operation to settle. Once attempted, neither
            // a worker panic nor a late effect permits replay or a success claim.
            if self.attempted {
                self.unknown = true;
            }
            return Err(error);
        }
        let report = self.report.as_mut().ok_or(MacExecValidationError::Unknown)?;
        report.probe_task_joined = true;
        Ok(report)
    }
    /// Only the scoped worker may poll this future; it never escapes to a caller.
    async fn run(&mut self) -> Result<&MacCandidateExecReport> {
        if self.attempted || self.unknown {
            return Err(MacExecValidationError::Conflict);
        }
        if let Err(error) = self.run_once().await {
            self.unknown = true;
            return Err(error);
        }
        self.report.as_ref().ok_or(MacExecValidationError::Unknown)
    }
    async fn run_once(&mut self) -> Result<()> {
        self.validate_inputs()?;
        self.base
            .ensure_absent(&self.nonce_relative_path)
            .map_err(|_| MacExecValidationError::Conflict)?;
        let mut config = self
            .profile
            .executor_config()
            .map_err(|_| MacExecValidationError::Unknown)?;
        config.rpc_timeout = config.rpc_timeout.min(Duration::from_secs(5));
        config.retained_process_limit = 2;
        let cwd = config.cwd.clone();
        let image = self
            .profile
            .executor_image()
            .map_err(|_| MacExecValidationError::Unknown)?;
        let generation: HostGeneration = uuid::Uuid::new_v4()
            .to_string()
            .try_into()
            .map_err(|_| MacExecValidationError::Conflict)?;
        let reservation =
            OwnedExecHost::reserve(generation, local_facts(self.profile.device_id().clone()), 2)
                .map_err(|_| MacExecValidationError::Busy)?;
        self.attempted = true; // BEFORE the first poll which may create a child.
        self.host = Some(
            reservation
                .spawn_optional_pinned(Some(config), Some(image))
                .await
                .map_err(|_| MacExecValidationError::Unknown)?,
        );
        let host = self.host.as_ref().ok_or(MacExecValidationError::Unknown)?;
        let execution = match self.validate_inputs() {
            Ok(()) => tokio::time::timeout(
                COMMAND_BUDGET,
                execute(
                    host,
                    self.profile.device_id(),
                    &cwd,
                    &self.profile.host_base_dir().join(&self.nonce_relative_path),
                ),
            )
            .await
            .unwrap_or(Err(MacExecValidationError::Unknown)),
            Err(error) => Err(error),
        };
        // ALWAYS attempt original cleanup after a returned host, including an
        // execution/guard/timeout failure. An error retains host in this object.
        let cleanup = host
            .shutdown_owned(CLEANUP_BUDGET)
            .await
            .map_err(|_| MacExecValidationError::Unknown)?;
        let native = cleanup
            .native
            .as_ref()
            .ok_or(MacExecValidationError::Unknown)?;
        if !cleanup.supervised_jobs_joined
            || !cleanup.ancillary_providers_settled()
            || !native.executor_exited
            || !native.reader_task_reaped
            || !native.stderr_task_reaped
            || !native
                .processes
                .iter()
                .all(|(_, evidence)| matches!(evidence, TerminationEvidence::ProcessExited(_)))
        {
            return Err(MacExecValidationError::Unknown);
        }
        let executed = execution?; // A late nonce never repairs Unknown history.
        if !native.processes.iter().any(|(handle, evidence)| {
            handle.operation() == &executed.operation
                && matches!(evidence, TerminationEvidence::ProcessExited(0))
        }) {
            return Err(MacExecValidationError::Unknown);
        }
        self.validate_inputs()?;
        let first = self
            .base
            .read_raw(&self.nonce_relative_path, 256)
            .map_err(|_| MacExecValidationError::Unknown)?;
        let second = self
            .base
            .read_raw(&self.nonce_relative_path, 256)
            .map_err(|_| MacExecValidationError::Unknown)?;
        if first.bytes() != executed.nonce.as_bytes()
            || second.bytes() != executed.nonce.as_bytes()
            || first.observation() != second.observation()
        {
            return Err(MacExecValidationError::Unknown);
        }
        let digest = Sha256Digest::of_bytes(first.bytes());
        self.effect = Some(Effect {
            observation: first.observation().clone(),
            digest,
            len: first.bytes().len(),
        });
        self.validate_inputs()?;
        self.report = Some(MacCandidateExecReport {
            schema: 1,
            status: "PASS_FIXED_LOCAL_APPLIED_MAC_EXEC_AND_ACTUAL_CLEANUP",
            scope: "local private nonce + stdout/exit + executor cleanup only; no remote auth, full capabilities or C07 commit",
            transaction_id: self.transaction.clone(),
            candidate_manifest_sha256: self.profile.runtime_selection().manifest_sha256,
            device_id: self.profile.device_id().clone(),
            operation: executed.operation,
            payload_digest: executed.digest,
            nonce_sha256: digest,
            nonce_relative_path: self.nonce_relative_path.clone(),
            nonce_bytes: first.bytes().len(),
            stdout_bytes: executed.stdout_bytes,
            exit_code: 0,
            liveness: ExecutionLiveness::Exited,
            drain: OutputDrain::Drained,
            executor_exited: native.executor_exited,
            processes_exited: true,
            reader_task_reaped: native.reader_task_reaped,
            stderr_task_reaped: native.stderr_task_reaped,
            supervised_jobs_joined: cleanup.supervised_jobs_joined,
            inline_probe_future_completed: true,
            probe_task_joined: false,
        });
        self.revalidate_success()?;
        Ok(())
    }
    pub(crate) fn revalidate_success(&mut self) -> Result<()> {
        let result = self.validate_success_inner();
        if result.is_err() {
            self.unknown = true;
        }
        result
    }
    fn validate_success_inner(&self) -> Result<()> {
        if self.unknown {
            return Err(MacExecValidationError::Unknown);
        }
        self.validate_inputs()?;
        let report = self
            .report
            .as_ref()
            .ok_or(MacExecValidationError::Unknown)?;
        let effect = self
            .effect
            .as_ref()
            .ok_or(MacExecValidationError::Unknown)?;
        let raw = self
            .base
            .read_raw(&self.nonce_relative_path, 256)
            .map_err(|_| MacExecValidationError::Unknown)?;
        if raw.observation() != &effect.observation
            || Sha256Digest::of_bytes(raw.bytes()) != effect.digest
            || raw.bytes().len() != effect.len
            || report.nonce_sha256 != effect.digest
        {
            return Err(MacExecValidationError::Unknown);
        }
        self.validate_inputs()
    }
}

// Same fixed local-maintenance Core admission as legacy_probe::facts. This is
// NOT a remote Gateway grant, original registry generation or ordinary owner.
fn local_facts(device_id: DeviceId) -> AdmissionFacts {
    AdmissionFacts {
        device_id,
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
fn context(host: &OwnedExecHost, device_id: &DeviceId) -> PreparedContext {
    PreparedContext {
        device_id: device_id.clone(),
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
    nonce: String,
}
// Exact fixed-command algorithm reused from legacy_probe::execute; no Linux
// scope/custody, remote RPC, new tool or caller command is copied into this port.
async fn execute(
    host: &OwnedExecHost,
    device: &DeviceId,
    cwd: &Path,
    nonce_path: &Path,
) -> Result<Executed> {
    let owner: OwnerLease = host
        .authority()
        .register_verified_owner(
            "migration-validation"
                .try_into()
                .map_err(|_| MacExecValidationError::Conflict)?,
            uuid::Uuid::new_v4()
                .to_string()
                .try_into()
                .map_err(|_| MacExecValidationError::Conflict)?,
        )
        .map_err(|_| MacExecValidationError::Unknown)?;
    let nonce = format!("styx-maintenance-{}\n", uuid::Uuid::new_v4());
    let spec = StartProcess {
        argv: vec![
            "/bin/sh".into(),
            "-c".into(),
            r#"set -e; umask 077; set -C; printf "%s" "$2" > "$1"; printf "%s" "$2""#.into(),
            "styx-migration-validation".into(),
            nonce_path
                .to_str()
                .ok_or(MacExecValidationError::Conflict)?
                .to_owned(),
            nonce.clone(),
        ],
        cwd_file_uri: url::Url::from_directory_path(cwd)
            .map_err(|_| MacExecValidationError::Conflict)?
            .to_string(),
        environment: BTreeMap::new(),
        tty: false,
    };
    let start = host
        .coordinator()
        .prepare_start(&owner, context(host, device), &spec)
        .map_err(|_| MacExecValidationError::Unknown)?;
    match host
        .coordinator()
        .dispatch_start(&owner, &start.id, start.payload_digest)
        .map_err(|_| MacExecValidationError::Unknown)?
    {
        StartSubmission::Submitted(ticket) => {
            if ticket
                .wait()
                .await
                .map_err(|_| MacExecValidationError::Unknown)?
                .dispatch
                != DispatchEvidence::Started
            {
                return Err(MacExecValidationError::Unknown);
            }
        }
        StartSubmission::Existing(_) => return Err(MacExecValidationError::Unknown),
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
            .map_err(|_| MacExecValidationError::Unknown)?;
        for chunk in page.chunks {
            if chunk.stream != "stdout" || stdout.len().saturating_add(chunk.text.len()) > 256 {
                return Err(MacExecValidationError::Unknown);
            }
            stdout.push_str(&chunk.text);
        }
        if page.drain == OutputDrain::Drained {
            if page.liveness != ExecutionLiveness::Exited
                || page.exit_code != Some(0)
                || stdout != nonce
            {
                return Err(MacExecValidationError::Unknown);
            }
            return Ok(Executed {
                operation: start.id,
                digest: start.payload_digest,
                stdout_bytes: stdout.len(),
                nonce,
            });
        }
    }
}
