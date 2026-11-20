//! Android Host composition: the shared identity, WSS, settings and Core lifetime
//! with an Android executor supplied by the app. No local HTTP or desktop runtime.
use crate::{
    enrollment::client::ReadyCredentials,
    host::{
        android::AndroidPlatform,
        coordinator::{HostAuthority, HostCoordinator},
        link::{HostWssLink, LinkAuthentication, LinkEndpoint, LinkError, SecretBearer},
        protocol::{
            HostProtocol, PairedTrustedProfile, ProtocolError, wire::TransportDrainOutcome,
        },
        settings::{Capabilities, CapabilityRuntime, HostSettings},
    },
    tls::{GatewayClientTls, TlsError, TrustAnchorPin, paired_gateway_namespace},
};
use futures_util::future::BoxFuture;
use serde::Serialize;
use std::{path::Path, sync::Arc, time::Duration};
use styx_contracts::{
    capability::{Authorization, Availability, CapabilityDescriptor, CapabilityId, Scope},
    error::{ErrorCategory, Recovery},
    identity::{ConnectionGeneration, DeviceId, HostGeneration},
};
use styx_core::{operations::OperationLedger, policy::AdmissionFacts};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Serialize)]
pub struct RunStatus {
    pub state: String,
    pub code: Option<String>,
    pub environment_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport_drain: Option<TransportDrainOutcome>,
}
type Reporter = Arc<dyn Fn(RunStatus) + Send + Sync>;
fn report(
    callback: &Reporter,
    device: &DeviceId,
    state: &str,
    code: Option<&str>,
    transport_drain: Option<TransportDrainOutcome>,
) {
    callback(RunStatus {
        state: state.into(),
        code: code.map(str::to_owned),
        environment_id: device.as_str().to_owned(),
        transport_drain,
    });
}

struct AndroidCapabilities {
    authority: Arc<HostAuthority>,
    platform: Arc<dyn AndroidPlatform>,
}
impl CapabilityRuntime for AndroidCapabilities {
    fn apply(
        &self,
        before: Capabilities,
        after: Capabilities,
    ) -> BoxFuture<'_, Result<(), ErrorCategory>> {
        Box::pin(async move {
            if after.exec || after.browser || after.computer {
                return Err(ErrorCategory::CapabilityUnsupported);
            }
            if before.android && !after.android {
                clear(self.platform.clone()).await?;
                self.authority.stop_disabled_capabilities(after).await?;
            }
            Ok(())
        })
    }
}
async fn clear(platform: Arc<dyn AndroidPlatform>) -> Result<(), ErrorCategory> {
    tokio::task::spawn_blocking(move || platform.execute("clear", serde_json::json!({})))
        .await
        .map_err(|_| ErrorCategory::ResultUnknown)??;
    Ok(())
}
fn facts(device: &DeviceId, configured: bool) -> AdmissionFacts {
    AdmissionFacts {
        device_id: device.clone(),
        grant_revision: 1,
        local_policy_allowed: true,
        descriptor: CapabilityDescriptor {
            contract_version: styx_contracts::CONTRACT_VERSION,
            capability_id: CapabilityId::AndroidObserve,
            scope: Scope::Host,
            provider_id: "android".try_into().expect("static provider identity"),
            configured,
            remote_grant: true,
            availability: Availability::Unknown,
            authorization: Authorization::Unknown,
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
struct ConnectFailure {
    code: &'static str,
    retryable: bool,
    revoked: bool,
}
impl ConnectFailure {
    fn network(code: &'static str) -> Self {
        Self {
            code,
            retryable: true,
            revoked: false,
        }
    }
}
impl From<LinkError> for ConnectFailure {
    fn from(error: LinkError) -> Self {
        match error {
            LinkError::UpgradeStatus(401 | 403) => Self {
                code: "gateway_pairing_revoked",
                retryable: false,
                revoked: true,
            },
            LinkError::UpgradeStatus(503) => Self::network("gateway_wss_unavailable"),
            LinkError::Deadline | LinkError::Tls(TlsError::HandshakeTimeout) => {
                Self::network("gateway_transport_deadline")
            }
            LinkError::Tls(TlsError::HandshakeIo(_)) | LinkError::Closed => {
                Self::network("gateway_connect_failed")
            }
            LinkError::Tls(TlsError::CertificateRejected(cause)) => Self {
                code: cause.code(),
                retryable: false,
                revoked: false,
            },
            LinkError::Tls(_) => Self {
                code: "gateway_tls_rejected",
                retryable: false,
                revoked: false,
            },
            _ => Self {
                code: "gateway_wss_rejected",
                retryable: false,
                revoked: false,
            },
        }
    }
}
async fn connect(
    endpoint: &LinkEndpoint,
    tls: &GatewayClientTls,
    bearer: &SecretBearer,
) -> Result<HostWssLink, ConnectFailure> {
    let url = url::Url::parse(endpoint.as_str()).expect("validated WSS endpoint");
    let host = match url.host().expect("validated WSS hostname") {
        url::Host::Domain(value) => value.to_owned(),
        url::Host::Ipv4(value) => value.to_string(),
        url::Host::Ipv6(value) => value.to_string(),
    };
    let tcp = tokio::time::timeout(
        Duration::from_secs(5),
        TcpStream::connect((
            host.as_str(),
            url.port_or_known_default().expect("WSS port"),
        )),
    )
    .await
    .map_err(|_| ConnectFailure::network("gateway_connect_timeout"))?
    .map_err(|_| ConnectFailure::network("gateway_connect_failed"))?;
    let generation: ConnectionGeneration = uuid::Uuid::new_v4()
        .to_string()
        .try_into()
        .expect("UUID identity");
    HostWssLink::connect(
        endpoint,
        tls,
        tcp,
        LinkAuthentication::Bearer(bearer),
        generation,
    )
    .await
    .map_err(ConnectFailure::from)
}

/// One native Host owns one Core and protocol across all transport reconnects.
/// The caller owns the Android foreground-service lifetime and protected storage.
pub async fn run(
    credentials: ReadyCredentials,
    files_dir: &Path,
    platform: Arc<dyn AndroidPlatform>,
    stop: CancellationToken,
    callback: Reporter,
) -> Result<(), ErrorCategory> {
    let device = credentials.device_id.clone();
    let mut endpoint =
        url::Url::parse(&credentials.gateway_origin).map_err(|_| ErrorCategory::InvalidRequest)?;
    endpoint
        .set_scheme("wss")
        .map_err(|_| ErrorCategory::InvalidRequest)?;
    endpoint.set_path(&format!("/styx/host/v3/{}/exec", device.as_str()));
    let endpoint =
        LinkEndpoint::parse(endpoint.as_str()).map_err(|_| ErrorCategory::InvalidRequest)?;
    let pin = TrustAnchorPin::parse_hex(&credentials.anchor_sha256.to_hex())
        .map_err(|_| ErrorCategory::IntegrityFailure)?;
    let namespace = paired_gateway_namespace(&pin);
    let tls = GatewayClientTls::from_pinned_ca_pem(credentials.ca_pem.as_bytes(), pin, None)
        .map_err(|_| ErrorCategory::IntegrityFailure)?;
    let bearer = SecretBearer::from_protected_reader(credentials.credential.to_string())
        .map_err(|_| ErrorCategory::IntegrityFailure)?;
    let generation: HostGeneration = uuid::Uuid::new_v4()
        .to_string()
        .try_into()
        .expect("UUID identity");
    let settings = HostSettings::open(
        files_dir,
        Capabilities {
            exec: false,
            browser: false,
            computer: false,
            android: true,
        },
    )?;
    if settings.current().exec || settings.current().browser || settings.current().computer {
        return Err(ErrorCategory::CapabilityUnsupported);
    }
    let (coordinator, authority) = HostCoordinator::new_mobile(
        OperationLedger::new(generation.clone()),
        facts(&device, settings.current().android),
    )
    .map_err(|_| ErrorCategory::StateConflict)?;
    let authority = Arc::new(authority);
    settings.attach(Arc::new(AndroidCapabilities {
        authority: authority.clone(),
        platform: platform.clone(),
    }))?;
    let protocol = HostProtocol::new_paired(
        PairedTrustedProfile {
            endpoint: endpoint.as_str().to_owned(),
            gateway_namespace: namespace,
            device_id: device.clone(),
            host_generation: generation,
        },
        coordinator,
        &authority,
    )
    .map_err(|_| ErrorCategory::StateConflict)?
    .with_android(platform.clone())
    .with_settings(settings.clone());
    let mut reconnect = false;
    let mut terminal = None;
    let mut transport_drain = None;
    loop {
        if stop.is_cancelled() {
            break;
        }
        report(
            &callback,
            &device,
            if reconnect {
                "reconnecting"
            } else {
                "connecting"
            },
            None,
            None,
        );
        let attempt = tokio::select! {
            _ = stop.cancelled() => break,
            value = connect(&endpoint, &tls, &bearer) => value,
        };
        match attempt {
            Ok(mut link) => {
                let (ready, mut readiness) = tokio::sync::oneshot::channel();
                let result = {
                    let running =
                        protocol.run_connection_with_readiness(&mut link, &stop, Some(ready));
                    tokio::pin!(running);
                    let mut awaiting_ready = true;
                    loop {
                        tokio::select! {
                            biased;
                            result = &mut running => break result,
                            observed = &mut readiness, if awaiting_ready => {
                                awaiting_ready = false;
                                if observed.is_ok() && !stop.is_cancelled() {
                                    report(&callback, &device, "connected", None, None);
                                }
                            },
                        }
                    }
                };
                if stop.is_cancelled() {
                    // Retain the original protocol receipt separately from local shutdown.
                    // Losing that receipt cannot establish completed Gateway cleanup.
                    transport_drain = Some(match &result {
                        Ok(Some(outcome)) => *outcome,
                        _ => TransportDrainOutcome::Unknown,
                    });
                }
                let close = link.shutdown(Duration::from_secs(3)).await;
                if matches!(result, Err(ProtocolError::PairingRevoked)) {
                    terminal = Some((
                        ErrorCategory::Unauthorized,
                        "revoked",
                        "gateway_pairing_revoked",
                    ));
                    break;
                }
                if stop.is_cancelled() {
                    break;
                }
                if matches!(
                    result,
                    Err(ProtocolError::BootstrapMismatch
                        | ProtocolError::NegotiationRejected
                        | ProtocolError::InvalidFrame
                        | ProtocolError::OwnerRegistrationRejected)
                ) {
                    terminal = Some((
                        ErrorCategory::ProtocolMismatch,
                        "failed",
                        "gateway_protocol_rejected",
                    ));
                    break;
                }
                report(
                    &callback,
                    &device,
                    "disconnected",
                    Some(if close.is_err() {
                        "link_close_deadline"
                    } else {
                        "gateway_connection_lost"
                    }),
                    None,
                );
            }
            Err(error) if !error.retryable => {
                terminal = Some((
                    if error.revoked {
                        ErrorCategory::Unauthorized
                    } else {
                        ErrorCategory::ProtocolMismatch
                    },
                    if error.revoked { "revoked" } else { "failed" },
                    error.code,
                ));
                break;
            }
            Err(error) => report(&callback, &device, "disconnected", Some(error.code), None),
        }
        reconnect = true;
        tokio::select! {
            _ = stop.cancelled() => break,
            _ = tokio::time::sleep(Duration::from_secs(2)) => {},
        }
    }
    report(
        &callback,
        &device,
        "stopping",
        terminal.as_ref().map(|(_, _, code)| *code),
        transport_drain,
    );
    let cleared = clear(platform).await;
    settings.close().await;
    // Reap the original owned jobs; cleanup never repeats an Android operation.
    loop {
        if let Ok(cleanup) = authority.shutdown_owned(Duration::from_secs(10)).await
            && cleanup.supervised_jobs_joined
            && cleanup.ancillary_providers_settled()
        {
            break;
        }
        report(
            &callback,
            &device,
            "stopping",
            Some("host_cleanup_pending"),
            transport_drain,
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    if let Some((category, state, code)) = terminal {
        report(&callback, &device, state, Some(code), transport_drain);
        return Err(category);
    }
    if let Err(error) = cleared {
        report(
            &callback,
            &device,
            "failed",
            Some("android_cleanup_unknown"),
            transport_drain,
        );
        return Err(error);
    }
    report(&callback, &device, "stopped", None, transport_drain);
    Ok(())
}

#[cfg(all(test, target_os = "linux", target_env = "gnu"))]
mod tests;
