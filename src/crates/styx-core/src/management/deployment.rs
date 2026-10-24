//! Deployment intent only. These values neither authorize a caller nor attest
//! an installation, process, permission, pairing or service-manager observation.
use styx_contracts::{error::ErrorCategory, identity::Sha256Digest};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeploymentMode {
    CreateLocal,
    JoinExisting,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagerMode {
    Unspecified,
    ForegroundCli,
    AppManaged,
    PersistentService,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunDesired {
    Unspecified,
    Running,
    Stopped,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutostartDesired {
    Unspecified,
    Enabled,
    Disabled,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComponentIntent {
    pub manager: ManagerMode,
    pub run: RunDesired,
    /// Independent from run: disabling autostart does not stop a running Host;
    /// explicit desired Stopped cannot be overridden by a recovery supervisor.
    pub autostart: AutostartDesired,
}
impl ComponentIntent {
    /// Absence in legacy state is not a default choice. Runtime imports missing
    /// manager/run/autostart as Unspecified, never from observed process health,
    /// succeeded service steps, background.foreground/login or App login prefs.
    pub fn is_explicit(&self) -> bool {
        self.manager != ManagerMode::Unspecified
            && self.run != RunDesired::Unspecified
            && self.autostart != AutostartDesired::Unspecified
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostIntent {
    pub component: ComponentIntent,
    pub computer_requested: bool,
    pub browser_requested: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingIntent {
    Unspecified,
    None,
    OwnerLocal,
    ManualLocal,
    ExternalOwner,
    /// Preserve original identity/credentials. Not a claim that enrollment is
    /// complete: the runtime must validate original profile/state separately.
    PreserveExisting,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressIntent {
    NotHosted,
    LoopbackOnly,
    ConfiguredUnverified,
}

/// Links a typed legacy projection to BOTH protected raw files. Core never
/// parses, reformats or serializes them; runtime retains RawFile including bytes
/// and kernel file observations. Hashes alone do not authenticate a caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegacySourceBinding {
    pub deployment_schema: u32,
    pub deployment_raw_sha256: Sha256Digest,
    pub state_schema: u32,
    pub state_raw_sha256: Sha256Digest,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentIntent {
    pub mode: DeploymentMode,
    /// None in JoinExisting means an external Gateway, never a request to
    /// create a local Gateway or to inherit the Host's manager mode.
    pub gateway: Option<ComponentIntent>,
    pub host: Option<HostIntent>,
    pub pairing: PairingIntent,
    pub device_ingress: IngressIntent,
    pub legacy_source: Option<LegacySourceBinding>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayRole {
    Local,
    External,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostRole {
    Local,
    Disabled,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityIntent {
    Enabled,
    Requested,
    Disabled,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Readiness {
    NotObserved,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeploymentRoles {
    pub gateway: GatewayRole,
    pub host: HostRole,
    pub exec: CapabilityIntent,
    pub computer: CapabilityIntent,
    pub browser: CapabilityIntent,
    pub device_ingress: IngressIntent,
    pub readiness: Readiness,
}
impl DeploymentIntent {
    pub fn validate(&self) -> Result<(), ErrorCategory> {
        if let Some(binding) = self.legacy_source
            && (binding.deployment_schema != 1 || binding.state_schema != 1)
        {
            return Err(ErrorCategory::CapabilityUnsupported);
        }
        for component in self
            .gateway
            .iter()
            .chain(self.host.iter().map(|h| &h.component))
        {
            // Foreground has no persistent registration. Reject an incompatible
            // explicit request rather than promoting it into a service.
            if component.manager == ManagerMode::ForegroundCli
                && component.autostart == AutostartDesired::Enabled
            {
                return Err(ErrorCategory::InvalidRequest);
            }
        }
        match self.mode {
            DeploymentMode::JoinExisting => {
                if self.gateway.is_some()
                    || self.host.is_none()
                    || self.device_ingress != IngressIntent::NotHosted
                    || !matches!(
                        self.pairing,
                        PairingIntent::ExternalOwner
                            | PairingIntent::PreserveExisting
                            | PairingIntent::Unspecified
                    )
                {
                    return Err(ErrorCategory::InvalidRequest);
                }
            }
            DeploymentMode::CreateLocal => {
                let Some(gateway) = self.gateway else {
                    return Err(ErrorCategory::InvalidRequest);
                };
                if self.device_ingress == IngressIntent::NotHosted {
                    return Err(ErrorCategory::InvalidRequest);
                }
                match self.host {
                    None if !matches!(
                        self.pairing,
                        PairingIntent::None | PairingIntent::Unspecified
                    ) =>
                    {
                        return Err(ErrorCategory::InvalidRequest);
                    }
                    Some(_)
                        if !matches!(
                            self.pairing,
                            PairingIntent::OwnerLocal
                                | PairingIntent::ManualLocal
                                | PairingIntent::PreserveExisting
                                | PairingIntent::Unspecified
                        ) =>
                    {
                        return Err(ErrorCategory::InvalidRequest);
                    }
                    _ => {}
                }
                if gateway.run == RunDesired::Stopped
                    && self
                        .host
                        .is_some_and(|h| h.component.run == RunDesired::Running)
                    && matches!(
                        self.pairing,
                        PairingIntent::OwnerLocal | PairingIntent::ManualLocal
                    )
                {
                    return Err(ErrorCategory::StateConflict);
                }
            }
        }
        Ok(())
    }
    pub fn roles(&self) -> Result<DeploymentRoles, ErrorCategory> {
        self.validate()?;
        Ok(DeploymentRoles {
            gateway: match self.mode {
                DeploymentMode::CreateLocal => GatewayRole::Local,
                DeploymentMode::JoinExisting => GatewayRole::External,
            },
            host: if self.host.is_some() {
                HostRole::Local
            } else {
                HostRole::Disabled
            },
            exec: if self.host.is_some() {
                CapabilityIntent::Enabled
            } else {
                CapabilityIntent::Disabled
            },
            computer: if self.host.is_some_and(|h| h.computer_requested) {
                CapabilityIntent::Requested
            } else {
                CapabilityIntent::Disabled
            },
            browser: if self.host.is_some_and(|h| h.browser_requested) {
                CapabilityIntent::Requested
            } else {
                CapabilityIntent::Disabled
            },
            device_ingress: self.device_ingress,
            readiness: Readiness::NotObserved,
        })
    }
}
