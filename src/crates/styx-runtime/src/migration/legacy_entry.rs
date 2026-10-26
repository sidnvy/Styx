//! Explicit Linux create-local migration through the existing original scopes.
//! A response waiter never owns cancellation. Unknown retains the one job and
//! all original resources; only joined, stopped completion releases the writer.
use super::legacy_service::{
    CaptureStatus, CredentialRetirementFailure, LegacyCutoverReport, LegacyGatewayTransition,
    LegacyServiceTransition, PreparationFailure, PreparedLegacyCutover, RetiredLegacyCredential,
    SettledLegacyRuntime, SettledLegacyService, SettlementStatus, TransitionError,
};
use crate::{
    release::VerifiedNativeRelease,
    store::{
        ConfigurationMaintenance, OwnedConfigurationRoot, PreservationInput, PreservationRole,
        PrivateRoot,
        enrollment::OwnedEnrollmentJournal,
        legacy_handoff::{LegacyMaterialInput, LegacyMaterialRoot},
    },
};
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use styx_contracts::{
    identity::{GatewayEpoch, Sha256Digest, TransactionId},
    management::ReaderContract,
    native_management::{NativeAutostartDesired, NativeDesired, NativeManager, NativeRunDesired},
};
use tokio::{
    sync::{Semaphore, SemaphorePermit, watch},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

static ENTRY: Semaphore = Semaphore::const_new(1);

#[derive(Clone)]
pub(crate) struct LegacyMigrationStatus {
    pub transaction_id: TransactionId,
    pub stage: &'static str,
    pub error: Option<TransitionError>,
    pub terminal: bool,
    pub effects_started: bool,
}
#[must_use = "observe and finish the original job; dropping a waiter does not cancel it"]
pub(crate) struct LegacyMigrationTask {
    status: watch::Receiver<LegacyMigrationStatus>,
    job: JoinHandle<Result<LegacyMigrationCompleted, TransitionError>>,
}
#[derive(serde::Serialize)]
pub(crate) struct LegacyMigrationCompleted {
    pub transaction_id: TransactionId,
    pub canonical_raw_sha256: Sha256Digest,
    pub report: LegacyCutoverReport,
}
#[must_use = "retain the original task until explicit process teardown on Unknown"]
pub(crate) struct LegacyMigrationFailure {
    code: TransitionError,
    status: LegacyMigrationStatus,
    _task: Option<LegacyMigrationTask>,
}
impl LegacyMigrationFailure {
    pub fn code(&self) -> TransitionError {
        self.code
    }
    pub fn requires_process_teardown(&self) -> bool {
        self._task.is_some()
    }
    pub fn diagnostic(&self) -> serde_json::Value {
        serde_json::json!({"schema":1,"transaction_id":self.status.transaction_id,
            "stage":self.status.stage,"error":self.code.to_string(),
            "effects_started":self.status.effects_started,
            "operations_replayed":false,"cleanup_confirmed":false})
    }
}
impl LegacyMigrationTask {
    pub fn status(&self) -> LegacyMigrationStatus {
        self.status.borrow().clone()
    }
    pub async fn observe(&mut self) -> LegacyMigrationStatus {
        while !self.status.borrow().terminal {
            if self.status.changed().await.is_err() {
                let mut status = self.status();
                status.stage = "owner_observation_lost";
                status.error = Some(TransitionError::Unknown);
                status.terminal = true;
                return status;
            }
        }
        self.status()
    }
    pub async fn finish(mut self) -> Result<LegacyMigrationCompleted, LegacyMigrationFailure> {
        let status = self.observe().await;
        if status.effects_started && status.error.is_some() {
            return Err(LegacyMigrationFailure {
                code: status.error.unwrap_or(TransitionError::Unknown),
                status,
                _task: Some(self),
            });
        }
        // Poll the original handle by reference: cancellation of this await
        // never aborts the actual job. A successful output exists only after
        // reader settlement and scope release inside that original job.
        match (&mut self.job).await {
            Ok(Ok(completed)) => Ok(completed),
            Ok(Err(code)) => Err(LegacyMigrationFailure {
                code,
                status,
                _task: None,
            }),
            Err(_) => Err(LegacyMigrationFailure {
                code: TransitionError::Unknown,
                status,
                _task: Some(self),
            }),
        }
    }
}

/// No caller-selected material/trust paths or commands. Only the explicitly
/// reviewed stopped, foreground, no-autostart topology is supported here.
pub(crate) fn start(
    state_dir: PathBuf,
    candidate: VerifiedNativeRelease,
    transaction_id: TransactionId,
    desired: NativeDesired,
) -> Result<LegacyMigrationTask, TransitionError> {
    let allowed = |role: &styx_contracts::native_management::NativeComponentDesired| {
        role.manager == NativeManager::ForegroundCli
            && role.run == NativeRunDesired::Stopped
            && role.autostart == NativeAutostartDesired::Disabled
    };
    if !desired.host.as_ref().is_some_and(allowed)
        || !desired.gateway.as_ref().is_some_and(allowed)
        || !state_dir.is_absolute()
        || !matches!(
            tokio::runtime::Handle::try_current().map(|h| h.runtime_flavor()),
            Ok(tokio::runtime::RuntimeFlavor::MultiThread)
        )
    {
        return Err(TransitionError::Unsupported);
    }
    let permit = ENTRY.try_acquire().map_err(|_| TransitionError::Busy)?;
    let (send, status) = watch::channel(LegacyMigrationStatus {
        transaction_id: transaction_id.clone(),
        stage: "preflight",
        error: None,
        terminal: false,
        effects_started: false,
    });
    let job = tokio::spawn(run(
        state_dir,
        candidate,
        transaction_id,
        desired,
        send,
        permit,
    ));
    Ok(LegacyMigrationTask { status, job })
}

struct Custody {
    owner: OwnedConfigurationRoot,
    _maintenance: Option<ConfigurationMaintenance>,
    host: Option<LegacyServiceTransition>,
    gateway: Option<LegacyGatewayTransition>,
    retired: Option<Arc<RetiredLegacyCredential>>,
    combined: Option<Arc<SettledLegacyRuntime>>,
    history: Option<OwnedEnrollmentJournal>,
    cutover: Option<PreparedLegacyCutover>,
    _preparation_failure: Option<PreparationFailure>,
    _retirement_failure: Option<CredentialRetirementFailure>,
}
fn publish(status: &watch::Sender<LegacyMigrationStatus>, stage: &'static str) {
    status.send_modify(|s| {
        s.stage = stage;
    });
}
async fn retain(
    status: &watch::Sender<LegacyMigrationStatus>,
    code: TransitionError,
    custody: Custody,
    permit: SemaphorePermit<'static>,
) -> Result<LegacyMigrationCompleted, TransitionError> {
    status.send_modify(|s| {
        s.error = Some(code);
        s.terminal = true;
        s.effects_started = true;
    });
    std::future::pending::<()>().await;
    drop((custody, permit));
    Err(code)
}
fn materials() -> Vec<LegacyMaterialInput> {
    use LegacyMaterialRoot::{Configuration, Host};
    use PreservationRole::{
        DeploymentConfiguration, DeviceIdentity, DevicePrivateKey, PairingCredential,
        PublisherTrust,
    };
    // Fixed production locators. The existing signed profile and final
    // preservation collector independently validate their complete closures.
    [
        (Configuration, "state.json", DeploymentConfiguration),
        (Configuration, "deployment.json", DeploymentConfiguration),
        (Host, "device/identity.json", DeviceIdentity),
        (Host, "device/identity.pem", DevicePrivateKey),
        (Host, "device/host.json", PairingCredential),
        (Host, "device/host.token", PairingCredential),
        (Host, "publisher.pem", PublisherTrust),
        (Host, "install/active.json", PublisherTrust),
    ]
    .into_iter()
    .map(|(root, path, role)| LegacyMaterialInput {
        root,
        input: PreservationInput {
            relative_path: path.into(),
            role,
            json_version: None,
        },
        max_bytes: 1024 * 1024,
    })
    .collect()
}
async fn capture_host(host: &mut LegacyServiceTransition) -> Result<(), TransitionError> {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match host.capture_status() {
                CaptureStatus::Pending => {
                    host.capture_changed().await;
                }
                CaptureStatus::Ready => match host.complete_capture() {
                    Ok(()) => return Ok(()),
                    Err(TransitionError::Busy) => {}
                    Err(e) => return Err(e),
                },
                CaptureStatus::Failed(e) => return Err(e),
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| TransitionError::Unknown)?
}
async fn capture_gateway(gateway: &mut LegacyGatewayTransition) -> Result<(), TransitionError> {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match gateway.capture_status() {
                CaptureStatus::Pending => {
                    gateway.capture_changed().await;
                }
                CaptureStatus::Ready => match gateway.complete_capture() {
                    Ok(()) => return Ok(()),
                    Err(TransitionError::Busy) => {}
                    Err(e) => return Err(e),
                },
                CaptureStatus::Failed(e) => return Err(e),
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| TransitionError::Unknown)?
}
async fn settle_host(
    host: &LegacyServiceTransition,
) -> Result<SettledLegacyService, TransitionError> {
    host.begin_settlement(Duration::from_secs(15), CancellationToken::new())?;
    tokio::time::timeout(Duration::from_secs(25), async {
        loop {
            let fact = host
                .settlement_observation()?
                .ok_or(TransitionError::Unknown)?;
            match fact.status {
                SettlementStatus::Unknown => return Err(TransitionError::Unknown),
                SettlementStatus::Confirmed => match host.consume_settlement() {
                    Ok(proof) => return Ok(proof),
                    Err(TransitionError::Busy) => {}
                    Err(e) => return Err(e),
                },
                _ => {}
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| TransitionError::Unknown)?
}
async fn settle_gateway(
    gateway: &LegacyGatewayTransition,
) -> Result<SettledLegacyRuntime, TransitionError> {
    gateway.begin_settlement(Duration::from_secs(15), CancellationToken::new())?;
    tokio::time::timeout(Duration::from_secs(25), async {
        loop {
            let fact = gateway
                .settlement_observation()?
                .ok_or(TransitionError::Unknown)?;
            match fact.status {
                SettlementStatus::Unknown => return Err(TransitionError::Unknown),
                SettlementStatus::Confirmed => match gateway.consume_settlement() {
                    Ok(proof) => return Ok(proof),
                    Err(TransitionError::Busy) => {}
                    Err(e) => return Err(e),
                },
                _ => {}
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| TransitionError::Unknown)?
}

async fn run(
    state_dir: PathBuf,
    candidate: VerifiedNativeRelease,
    transaction_id: TransactionId,
    desired: NativeDesired,
    status: watch::Sender<LegacyMigrationStatus>,
    permit: SemaphorePermit<'static>,
) -> Result<LegacyMigrationCompleted, TransitionError> {
    // Pure reads and actual original publisher verification precede all locks
    // and effects. Old state is never replaced with fixture/succeeded JSON.
    let preflight = tokio::task::block_in_place(|| {
        candidate
            .revalidate()
            .map_err(|_| TransitionError::Conflict)?;
        if !candidate
            .supports_state_reader(ReaderContract::NativeMigratedStateV1)
            .map_err(|_| TransitionError::Conflict)?
        {
            return Err(TransitionError::Unsupported);
        }
        let original = crate::foreground::profile::load_paired(&state_dir)
            .map_err(|_| TransitionError::Conflict)?;
        original
            .revalidate()
            .map_err(|_| TransitionError::Conflict)?;
        let root = PrivateRoot::open(&state_dir).map_err(|_| TransitionError::Conflict)?;
        root.ensure_absent(".styx-native-root-v1.json")
            .map_err(|_| TransitionError::Conflict)?;
        let deployment = root
            .read_raw("deployment.json", 1024 * 1024)
            .map_err(|_| TransitionError::Conflict)?;
        let data: serde_json::Value =
            serde_json::from_slice(deployment.bytes()).map_err(|_| TransitionError::Conflict)?;
        if data.get("schema").and_then(|v| v.as_u64()) != Some(1)
            || data.get("mode").and_then(|v| v.as_str()) != Some("create-local")
        {
            return Err(TransitionError::Unsupported);
        }
        // Keep the same protected root and move its actual writer once.
        let writer = root
            .try_configuration_writer()
            .map_err(|_| TransitionError::Busy)?;
        let owner = OwnedConfigurationRoot::open_existing(root, writer)
            .map_err(|_| TransitionError::Conflict)?;
        original
            .revalidate()
            .map_err(|_| TransitionError::Conflict)?;
        Ok(owner)
    });
    let owner = match preflight {
        Ok(owner) => owner,
        Err(error) => {
            status.send_modify(|s| {
                s.stage = "not_started";
                s.error = Some(error);
                s.terminal = true;
            });
            return Err(error);
        }
    };
    let mut custody = Custody {
        owner,
        _maintenance: None,
        host: None,
        gateway: None,
        retired: None,
        combined: None,
        history: None,
        cutover: None,
        _preparation_failure: None,
        _retirement_failure: None,
    };
    macro_rules! step {
        ($value:expr) => {
            match $value {
                Ok(value) => value,
                Err(error) => return retain(&status, error, custody, permit).await,
            }
        };
    }
    let maintenance = match custody.owner.begin_maintenance(transaction_id.clone()) {
        Ok(value) => value,
        Err(error) => {
            let _ = error;
            status.send_modify(|s| {
                s.stage = "not_started";
                s.error = Some(TransitionError::Conflict);
                s.terminal = true;
            });
            return Err(TransitionError::Conflict);
        }
    };
    custody._maintenance = Some(maintenance);
    status.send_modify(|s| {
        s.stage = "host_capture";
        s.effects_started = true;
    });
    let maintenance = step!(custody._maintenance.take().ok_or(TransitionError::Unknown));
    match LegacyServiceTransition::prepare(
        &state_dir,
        custody.owner.clone(),
        maintenance,
        &materials(),
        candidate,
    )
    .await
    {
        Ok(host) => custody.host = Some(host),
        Err(failure) => {
            let code = failure.code();
            custody._preparation_failure = Some(failure);
            return retain(&status, code, custody, permit).await;
        }
    }
    step!(capture_host(step!(custody.host.as_mut().ok_or(TransitionError::Unknown))).await);
    publish(&status, "host_settlement");
    let settled =
        step!(settle_host(step!(custody.host.as_ref().ok_or(TransitionError::Unknown))).await);
    publish(&status, "credential_retirement");
    match settled.retire_legacy_credential() {
        Ok(retired) => custody.retired = Some(Arc::new(retired)),
        Err(failure) => {
            let code = failure.code();
            custody._retirement_failure = Some(failure);
            return retain(&status, code, custody, permit).await;
        }
    }
    publish(&status, "gateway_capture");
    let gateway = step!(
        step!(custody.retired.as_ref().ok_or(TransitionError::Unknown))
            .prepare_gateway()
            .await
    );
    custody.gateway = Some(gateway);
    step!(
        capture_gateway(step!(
            custody.gateway.as_mut().ok_or(TransitionError::Unknown)
        ))
        .await
    );
    publish(&status, "gateway_settlement");
    let combined = Arc::new(step!(
        settle_gateway(step!(
            custody.gateway.as_ref().ok_or(TransitionError::Unknown)
        ))
        .await
    ));
    custody.combined = Some(combined.clone());
    step!(combined.revalidate().await);
    publish(&status, "history_import");
    let epoch: GatewayEpoch = step!(
        format!(
            "migration.{}",
            Sha256Digest::of_bytes(transaction_id.as_str().as_bytes()).to_hex()
        )
        .try_into()
        .map_err(|_| TransitionError::Conflict)
    );
    let now = step!(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| TransitionError::Unknown)
    );
    let now = step!(u64::try_from(now.as_millis()).map_err(|_| TransitionError::Unknown));
    let history = step!(combined.with_original_history(
        &state_dir,
        |snapshot, owner, maintenance| {
            snapshot.validate_preparation()?;
            let mut journal = snapshot.claim_history_store(owner, maintenance)?;
            snapshot.persist_candidate_history(&mut journal, maintenance, epoch, now)?;
            Ok(journal)
        }
    ));
    custody.history = Some(history);
    publish(&status, "cutover_prepare");
    let cutover = step!(combined.prepare_native_transition(
        &state_dir,
        step!(custody.history.as_mut().ok_or(TransitionError::Unknown)),
        desired.clone()
    ));
    custody.cutover = Some(cutover);
    let history = step!(custody.history.take().ok_or(TransitionError::Unknown));
    let network_plan = step!(
        step!(custody.cutover.as_ref().ok_or(TransitionError::Unknown))
            .prepare_gateway_validation(history)
    );
    publish(&status, "candidate_exec_validation");
    let probe = step!(combined.validate_candidate_exec(&state_dir).await);
    publish(&status, "original_pair_network_validation");
    let network = step!(network_plan.validate(probe).await);
    publish(&status, "canonical_apply");
    step!(
        step!(custody.cutover.as_mut().ok_or(TransitionError::Unknown))
            .apply_gateway_validated_candidate(network)
    );
    publish(&status, "verified_commit_and_promotion");
    step!(
        step!(custody.cutover.as_mut().ok_or(TransitionError::Unknown))
            .commit_gateway_validated_candidate()
            .await
    );
    publish(&status, "stopped_reader_settlement");
    let cutover = step!(custody.cutover.as_ref().ok_or(TransitionError::Unknown));
    let service = step!(cutover.promoted_service().ok_or(TransitionError::Unknown));
    service.close_readers();
    if !service
        .wait_readers(tokio::time::Instant::now() + Duration::from_secs(15))
        .await
    {
        return retain(&status, TransitionError::Unknown, custody, permit).await;
    }
    // No listener/Host was left running by the joined maintenance journey.
    // Check the exact committed bytes before releasing their original custody.
    let raw = step!(
        PrivateRoot::open(&state_dir)
            .and_then(|root| root.read_raw("state.json", 1024 * 1024))
            .map_err(|_| TransitionError::Unknown)
    );
    let canonical_raw_sha256 = Sha256Digest::of_bytes(raw.bytes());
    if canonical_raw_sha256 != cutover.report().target_sha256
        || !cutover.report().migration_committed
        || !cutover.report().ordinary_service_promoted
    {
        return retain(&status, TransitionError::Unknown, custody, permit).await;
    }
    let cutover = step!(custody.cutover.take().ok_or(TransitionError::Unknown));
    let report = cutover.into_report();
    drop((combined, custody, raw, permit));
    status.send_modify(|s| {
        s.stage = "committed_stopped_resources_released";
        s.terminal = true;
    });
    Ok(LegacyMigrationCompleted {
        transaction_id,
        canonical_raw_sha256,
        report,
    })
}
