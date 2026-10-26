//! Original-pair Host readiness under the same applied native migration fence.
//! This owns no MCP client or model credential and cannot attest remote SDK
//! cleanup. No execution provider is installed: ordinary dispatch stays denied.
use crate::{
    foreground::profile::AppliedNativeMaintenanceProfile,
    host::{
        bootstrap::OwnedExecHost,
        link::{HostWssLink, LinkAuthentication, LinkEndpoint, SecretBearer},
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
    profile: &'profile AppliedNativeMaintenanceProfile<'borrow, 'effects, 'materials>,
    work: PairWork,
    unknown: bool,
    report: Option<MacPairAdmissionReport>,
}
impl<'profile, 'borrow, 'effects, 'materials>
    MacPairReadinessProbe<'profile, 'borrow, 'effects, 'materials>
{
    pub(crate) fn prepare(
        profile: &'profile AppliedNativeMaintenanceProfile<'borrow, 'effects, 'materials>,
    ) -> Result<Self> {
        profile
            .revalidate()
            .map_err(|_| MacPairValidationError::Unknown)?;
        Ok(Self {
            profile,
            work: PairWork {
                host: None,
                link: None,
                attempted: false,
            },
            unknown: false,
            report: None,
        })
    }
    /// Original guard/COM facts never leave their owner thread. Only portable
    /// transport/Host state enters scoped work, and actual joins precede report.
    pub(crate) fn run_joined(&mut self, runtime: &Handle) -> Result<&MacPairAdmissionReport> {
        if self.work.attempted || self.unknown {
            return Err(MacPairValidationError::Conflict);
        }
        let result = self.run_phases(runtime);
        if let Err(error) = result {
            if self.work.attempted {
                self.unknown = true;
            }
            return Err(error);
        }
        self.report.as_ref().ok_or(MacPairValidationError::Unknown)
    }
    fn run_phases(&mut self, runtime: &Handle) -> Result<()> {
        self.profile
            .revalidate()
            .map_err(|_| MacPairValidationError::Unknown)?;
        let endpoint = self.profile.endpoint();
        let url =
            url::Url::parse(endpoint.as_str()).map_err(|_| MacPairValidationError::Conflict)?;
        let address = url
            .host_str()
            .ok_or(MacPairValidationError::Conflict)?
            .to_owned();
        let port = url
            .port_or_known_default()
            .ok_or(MacPairValidationError::Conflict)?;
        let generation: HostGeneration = uuid::Uuid::new_v4()
            .to_string()
            .try_into()
            .map_err(|_| MacPairValidationError::Conflict)?;
        self.work.attempted = true;
        self.work.host = Some(
            OwnedExecHost::reserve(
                generation.clone(),
                denied_facts(self.profile.device_id().clone()),
                2,
            )
            .map_err(|_| MacPairValidationError::Unknown)?
            .without_executor()
            .map_err(|_| MacPairValidationError::Unknown)?,
        );
        let tcp = joined_work(runtime, "styx-migration-pair-tcp", async {
            tokio::time::timeout(
                Duration::from_secs(10),
                TcpStream::connect((address.as_str(), port)),
            )
            .await
            .map_err(|_| MacPairValidationError::Unknown)?
            .map_err(|_| MacPairValidationError::Unknown)
        });
        let readiness = match tcp {
            Ok(tcp) => match self.profile.revalidate() {
                Ok(()) => {
                    let trusted = PairedTrustedProfile {
                        endpoint: endpoint.as_str().to_owned(),
                        gateway_namespace: self.profile.paired_gateway_namespace(),
                        device_id: self.profile.device_id().clone(),
                        host_generation: generation,
                    };
                    // These typed borrows contain no original profile/guard or
                    // COM observation, and reveal no caller-selected credential.
                    let tls = self.profile.tls();
                    let bearer = self.profile.bearer();
                    let work = &mut self.work;
                    joined_work(
                        runtime,
                        "styx-migration-pair-protocol",
                        work.connect_and_drain(tcp, endpoint, tls, bearer, trusted),
                    )
                }
                Err(_) => Err(MacPairValidationError::Unknown),
            },
            Err(error) => Err(error),
        };
        // Every returned connection/protocol failure still settles this SAME
        // original link and Host; a failed worker spawn is not cleanup success.
        let work = &mut self.work;
        joined_work(runtime, "styx-migration-pair-cleanup", work.cleanup())?;
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
            validation_task_joined: true, // original work handles actually joined
            migration_committed: false,
            ordinary_admission_open: false,
        });
        Ok(())
    }
    /// Only this actual completed probe can supply final-journal data. Caller
    /// JSON cannot construct the probe or substitute a different applied scope.
    pub(crate) fn validated_report_for(
        &mut self,
        guard: &crate::store::NativeCanonicalCutover<'_, '_>,
    ) -> Result<Vec<u8>> {
        if !self.profile.matches_cutover(guard) {
            return Err(MacPairValidationError::Conflict);
        }
        self.revalidate_success()?;
        let report = self
            .report
            .as_ref()
            .ok_or(MacPairValidationError::Unknown)?;
        if !report.validation_task_joined {
            return Err(MacPairValidationError::Unknown);
        }
        serde_json::to_vec(report).map_err(|_| MacPairValidationError::Unknown)
    }
    pub(crate) fn revalidate_success(&mut self) -> Result<()> {
        let valid = !self.unknown
            && self.work.link.is_none()
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

struct PairWork {
    host: Option<OwnedExecHost>,
    link: Option<HostWssLink>,
    attempted: bool,
}
impl PairWork {
    async fn connect_and_drain(
        &mut self,
        tcp: TcpStream,
        endpoint: &LinkEndpoint,
        tls: &crate::tls::GatewayClientTls,
        bearer: &SecretBearer,
        trusted: PairedTrustedProfile,
    ) -> Result<()> {
        let host = self.host.as_ref().ok_or(MacPairValidationError::Unknown)?;
        let generation: ConnectionGeneration = uuid::Uuid::new_v4()
            .to_string()
            .try_into()
            .map_err(|_| MacPairValidationError::Conflict)?;
        self.link = Some(
            HostWssLink::connect(
                endpoint,
                tls,
                tcp,
                LinkAuthentication::Bearer(bearer),
                generation,
                host.link_budget(),
            )
            .await
            .map_err(|_| MacPairValidationError::Unknown)?,
        );
        let protocol = host
            .paired_protocol(trusted)
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
    async fn cleanup(&mut self) -> Result<()> {
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
        Ok(())
    }
}
fn joined_work<T: Send>(
    runtime: &Handle,
    name: &'static str,
    work: impl std::future::Future<Output = Result<T>> + Send,
) -> Result<T> {
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name(name.into())
            .spawn_scoped(scope, move || runtime.block_on(work))
            .map_err(|_| MacPairValidationError::Unknown)?
            .join()
            .map_err(|_| MacPairValidationError::Unknown)?
    })
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
