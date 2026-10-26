//! Original-pair Host readiness under the same applied Mac migration fence.
//! This owns no MCP client or model credential and cannot attest remote SDK
//! cleanup. No execution provider is installed: ordinary dispatch stays denied.
use crate::{
    foreground::profile::AppliedMacMaintenanceProfile,
    host::{
        bootstrap::OwnedExecHost,
        link::{HostWssLink, LinkAuthentication},
        protocol::{PairedTrustedProfile, wire::TransportDrainOutcome},
    },
};
use serde::Serialize;
use std::time::Duration;
use styx_contracts::{
    capability::{Authorization, Availability, CapabilityDescriptor, CapabilityId, Scope},
    error::Recovery,
    identity::{
        ConnectionGeneration, DeviceId, HostGeneration, ProviderId, Sha256Digest, TransactionId,
    },
};
use styx_core::policy::AdmissionFacts;
use tokio::{net::TcpStream, runtime::Handle, sync::oneshot};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Copy, thiserror::Error)]
pub(crate) enum MacPairValidationError {
    #[error("mac_pair_validation_conflict")]
    Conflict,
    #[error("mac_pair_validation_unknown")]
    Unknown,
}
type Result<T> = std::result::Result<T, MacPairValidationError>;

/// Evidence from this worker only; local Exec is a separate required attachment.
#[derive(Serialize)]
pub(crate) struct MacPairAdmissionReport {
    schema: u16,
    kind: &'static str,
    transaction_id: TransactionId,
    candidate_manifest_sha256: Sha256Digest,
    target_sha256: Sha256Digest,
    source_bindings_sha256: Sha256Digest,
    origin: String,
    device_id: DeviceId,
    fingerprint: Sha256Digest,
    gateway_ca_pem_sha256: Sha256Digest,
    host_authenticated: bool,
    protocol_ready: bool,
    host_protocol_joined: bool,
    host_link_io_joined: bool,
    validation_task_joined: bool,
    migration_committed: bool,
    ordinary_admission_open: bool,
}

/// Retain this object in the SAME outer owner on failure. There is one attempt,
/// no retry, new pairing, TLS fallback, arbitrary endpoint or execution callback.
pub(crate) struct MacPairReadinessProbe<'profile, 'borrow, 'effects, 'materials> {
    profile: &'profile AppliedMacMaintenanceProfile<'borrow, 'effects, 'materials>,
    host: Option<OwnedExecHost>,
    link: Option<HostWssLink>,
    attempted: bool,
    unknown: bool,
    report: Option<MacPairAdmissionReport>,
}
impl<'profile, 'borrow, 'effects, 'materials>
    MacPairReadinessProbe<'profile, 'borrow, 'effects, 'materials>
{
    pub(crate) fn prepare(
        profile: &'profile AppliedMacMaintenanceProfile<'borrow, 'effects, 'materials>,
    ) -> Result<Self> {
        profile
            .revalidate()
            .map_err(|_| MacPairValidationError::Unknown)?;
        Ok(Self {
            profile,
            host: None,
            link: None,
            attempted: false,
            unknown: false,
            report: None,
        })
    }
    /// Actual scoped worker completion, not an inline-future or JSON assertion.
    /// Call only inside the retained outer blocking migration worker.
    pub(crate) fn run_joined(&mut self, runtime: &Handle) -> Result<&MacPairAdmissionReport> {
        if self.attempted || self.unknown {
            return Err(MacPairValidationError::Conflict);
        }
        let result = std::thread::scope(|scope| {
            std::thread::Builder::new()
                .name("styx-mac-pair-validation".into())
                .spawn_scoped(scope, || runtime.block_on(self.run_once()))
                .map_err(|_| MacPairValidationError::Unknown)?
                .join()
                .map_err(|_| MacPairValidationError::Unknown)?
        });
        if let Err(error) = result {
            self.unknown = true;
            return Err(error);
        }
        let report = self
            .report
            .as_mut()
            .ok_or(MacPairValidationError::Unknown)?;
        report.validation_task_joined = true;
        Ok(report)
    }
    async fn run_once(&mut self) -> Result<()> {
        self.profile
            .revalidate()
            .map_err(|_| MacPairValidationError::Unknown)?;
        let generation: HostGeneration = uuid::Uuid::new_v4()
            .to_string()
            .try_into()
            .map_err(|_| MacPairValidationError::Conflict)?;
        self.attempted = true;
        self.host = Some(
            OwnedExecHost::reserve(
                generation.clone(),
                denied_facts(self.profile.device_id().clone()),
                2,
            )
            .map_err(|_| MacPairValidationError::Unknown)?
            .without_executor()
            .map_err(|_| MacPairValidationError::Unknown)?,
        );
        let readiness = self.connect_and_drain(generation).await;
        // Always settle THIS link and Host, including readiness rejection/timeout.
        let link_settled = match self.link.take() {
            Some(link) => link.shutdown(Duration::from_secs(5)).await.is_ok(),
            None => true,
        };
        let host = self.host.as_ref().ok_or(MacPairValidationError::Unknown)?;
        let cleanup = host
            .shutdown_owned(Duration::from_secs(15))
            .await
            .map_err(|_| MacPairValidationError::Unknown)?;
        if !link_settled
            || !cleanup.supervised_jobs_joined
            || cleanup.native.is_some()
            || cleanup.browser.is_some()
            || cleanup.desktop.is_some()
        {
            return Err(MacPairValidationError::Unknown);
        }
        readiness?;
        self.profile
            .revalidate()
            .map_err(|_| MacPairValidationError::Unknown)?;
        let pair = self.profile.original_pair();
        let pair_raw = serde_json::to_vec(pair).map_err(|_| MacPairValidationError::Unknown)?;
        self.report = Some(MacPairAdmissionReport {
            schema: 2,
            kind: "preserved_remote_host_admission",
            transaction_id: self.profile.transaction_id().clone(),
            candidate_manifest_sha256: self.profile.runtime_selection().manifest_sha256,
            target_sha256: self.profile.target_sha256(),
            source_bindings_sha256: Sha256Digest::of_bytes(&pair_raw),
            origin: pair.gateway_origin.clone(),
            device_id: pair.device_id.clone(),
            fingerprint: pair.fingerprint,
            gateway_ca_pem_sha256: pair.gateway_ca_pem_sha256,
            host_authenticated: true,
            protocol_ready: true,
            host_protocol_joined: true,
            host_link_io_joined: true,
            validation_task_joined: false,
            migration_committed: false,
            ordinary_admission_open: false,
        });
        Ok(())
    }
    async fn connect_and_drain(&mut self, host_generation: HostGeneration) -> Result<()> {
        let endpoint = self.profile.endpoint();
        let url =
            url::Url::parse(endpoint.as_str()).map_err(|_| MacPairValidationError::Conflict)?;
        let host_name = url.host_str().ok_or(MacPairValidationError::Conflict)?;
        let port = url
            .port_or_known_default()
            .ok_or(MacPairValidationError::Conflict)?;
        let tcp = tokio::time::timeout(
            Duration::from_secs(10),
            TcpStream::connect((host_name, port)),
        )
        .await
        .map_err(|_| MacPairValidationError::Unknown)?
        .map_err(|_| MacPairValidationError::Unknown)?;
        self.profile
            .revalidate()
            .map_err(|_| MacPairValidationError::Unknown)?;
        let host = self.host.as_ref().ok_or(MacPairValidationError::Unknown)?;
        let generation: ConnectionGeneration = uuid::Uuid::new_v4()
            .to_string()
            .try_into()
            .map_err(|_| MacPairValidationError::Conflict)?;
        self.link = Some(
            HostWssLink::connect(
                endpoint,
                self.profile.tls(),
                tcp,
                LinkAuthentication::Bearer(self.profile.bearer()),
                generation,
                host.link_budget(),
            )
            .await
            .map_err(|_| MacPairValidationError::Unknown)?,
        );
        let protocol = host
            .paired_protocol(PairedTrustedProfile {
                endpoint: endpoint.as_str().to_owned(),
                gateway_namespace: self.profile.paired_gateway_namespace(),
                device_id: self.profile.device_id().clone(),
                host_generation,
            })
            .map_err(|_| MacPairValidationError::Unknown)?;
        let link = self.link.as_mut().ok_or(MacPairValidationError::Unknown)?;
        let stop = CancellationToken::new();
        let (ready_tx, ready_rx) = oneshot::channel();
        let observe = async {
            // Ready means the negotiated enable reply was actually flushed.
            let ready = tokio::time::timeout(Duration::from_secs(10), ready_rx).await;
            stop.cancel();
            matches!(ready, Ok(Ok(())))
        };
        let exchange = async {
            tokio::join!(
                protocol.run_connection_with_readiness(link, &stop, Some(ready_tx)),
                observe
            )
        };
        let result = tokio::time::timeout(Duration::from_secs(30), exchange).await;
        stop.cancel();
        if !matches!(
            result,
            Ok((Ok(Some(TransportDrainOutcome::Complete)), true))
        ) {
            return Err(MacPairValidationError::Unknown);
        }
        Ok(())
    }
    pub(crate) fn revalidate_success(&mut self) -> Result<()> {
        let valid = !self.unknown
            && self.link.is_none()
            && self
                .report
                .as_ref()
                .is_some_and(|r| r.validation_task_joined)
            && self.profile.revalidate().is_ok();
        if !valid {
            self.unknown = true;
            return Err(MacPairValidationError::Unknown);
        }
        Ok(())
    }
}

fn denied_facts(device_id: DeviceId) -> AdmissionFacts {
    AdmissionFacts {
        device_id,
        grant_revision: 1,
        local_policy_allowed: false,
        descriptor: CapabilityDescriptor {
            contract_version: styx_contracts::CONTRACT_VERSION,
            capability_id: CapabilityId::ExecRun,
            scope: Scope::Host,
            provider_id: ProviderId::try_from("codex").expect("static provider"),
            configured: false,
            remote_grant: false,
            availability: Availability::Unavailable,
            authorization: Authorization::Denied,
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
