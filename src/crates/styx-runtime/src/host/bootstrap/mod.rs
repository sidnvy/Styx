//! Optional Exec Host composition; transports own their existing buffers.
//! This is not a process RSS/native-executor limit or the persistent service manager.
use super::{
    coordinator::{CoordinatorError, HostAuthority, HostCleanup, HostCoordinator},
    protocol::{HostProtocol, PairedTrustedProfile, ProtocolError, TrustedProfile},
};
use crate::providers::codex::{CodexStdio, ExecError, OwnedExecutorConfig};
#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::sync::Arc;
use std::time::Duration;
use styx_contracts::{capability::CapabilityId, identity::HostGeneration};
use styx_core::{operations::OperationLedger, policy::AdmissionFacts};

#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    #[error("invalid Exec Host bootstrap configuration")]
    InvalidConfiguration,
    #[error(transparent)]
    Executor(#[from] ExecError),
    #[error(transparent)]
    Coordinator(#[from] CoordinatorError),
}

/// Bootstrap/control handle. Never put this in network-request state; pass the
/// request coordinator and a borrowed, explicitly bound protocol endpoint instead.
/// The sole native executor outlives connections. Shutdown is an explicit Host
/// control action, not the consequence of a socket or response disappearing.
pub struct OwnedExecHost {
    coordinator: HostCoordinator,
    authority: HostAuthority,
}
impl OwnedExecHost {
    pub async fn spawn(
        executor: OwnedExecutorConfig,
        generation: HostGeneration,
        trusted_facts: AdmissionFacts,
    ) -> Result<Self, BootstrapError> {
        Self::reserve(generation, trusted_facts)?
            .spawn(executor)
            .await
    }
    /// Validate composition before connecting or spawning native code.
    pub fn reserve(
        generation: HostGeneration,
        trusted_facts: AdmissionFacts,
    ) -> Result<ExecHostReservation, BootstrapError> {
        // Refuse invalid composition before spawning native code or transferring
        // adapter ownership to a constructor that could reject it.
        if trusted_facts.descriptor.capability_id != CapabilityId::ExecRun
            || trusted_facts.descriptor.contract_version != styx_contracts::CONTRACT_VERSION
        {
            return Err(BootstrapError::InvalidConfiguration);
        }
        Ok(ExecHostReservation {
            generation,
            trusted_facts,
        })
    }
    pub(crate) async fn enable_executor(
        &self,
        config: OwnedExecutorConfig,
        facts: AdmissionFacts,
        #[cfg(any(target_os = "macos", target_os = "windows"))] image: Arc<
            crate::store::PinnedExecutable,
        >,
    ) -> Result<(), BootstrapError> {
        if self.coordinator.exec_configured() {
            return Ok(());
        }
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        let adapter = CodexStdio::spawn_pinned(config, image).await?;
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        let adapter = CodexStdio::spawn_owned(config).await?;
        self.authority.attach_executor(adapter, facts)?;
        Ok(())
    }
    pub fn coordinator(&self) -> &HostCoordinator {
        &self.coordinator
    }
    pub fn authority(&self) -> &HostAuthority {
        &self.authority
    }
    /// A protocol borrows the existing Host control authority.
    pub fn protocol(&self, profile: TrustedProfile) -> Result<HostProtocol<'_>, ProtocolError> {
        HostProtocol::new(profile, self.coordinator.clone(), &self.authority)
    }
    /// Same executor and authority, with protected pairing bootstrap.
    pub fn paired_protocol(
        &self,
        profile: PairedTrustedProfile,
    ) -> Result<HostProtocol<'_>, ProtocolError> {
        HostProtocol::new_paired(profile, self.coordinator.clone(), &self.authority)
    }
    pub async fn shutdown_owned(&self, budget: Duration) -> Result<HostCleanup, CoordinatorError> {
        self.authority.shutdown_owned(budget).await
    }
}

/// Move-only bootstrap resources; neither a transport nor a request can create
/// another executor from this reservation.
pub struct ExecHostReservation {
    generation: HostGeneration,
    trusted_facts: AdmissionFacts,
}
impl ExecHostReservation {
    /// Explicit protected configuration selected no Exec; not a spawn-failure fallback.
    pub fn without_executor(self) -> Result<OwnedExecHost, BootstrapError> {
        let (coordinator, authority) = HostCoordinator::new_without_executor(
            OperationLedger::new(self.generation),
            self.trusted_facts,
        )?;
        Ok(OwnedExecHost {
            coordinator,
            authority,
        })
    }
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    pub(crate) async fn spawn_optional_pinned(
        self,
        executor: Option<OwnedExecutorConfig>,
        image: Option<Arc<crate::store::PinnedExecutable>>,
    ) -> Result<OwnedExecHost, BootstrapError> {
        let (executor, image) = match (executor, image) {
            (None, None) => return self.without_executor(),
            (Some(executor), Some(image)) => (executor, image),
            _ => return Err(BootstrapError::InvalidConfiguration),
        };
        let adapter = CodexStdio::spawn_pinned(executor, image).await?;
        let (coordinator, authority) = HostCoordinator::new_owned(
            adapter,
            OperationLedger::new(self.generation),
            self.trusted_facts,
        )?;
        Ok(OwnedExecHost {
            coordinator,
            authority,
        })
    }
    pub async fn spawn_optional(
        self,
        executor: Option<OwnedExecutorConfig>,
    ) -> Result<OwnedExecHost, BootstrapError> {
        match executor {
            Some(config) => self.spawn(config).await,
            None => self.without_executor(),
        }
    }
    pub async fn spawn(
        self,
        executor: OwnedExecutorConfig,
    ) -> Result<OwnedExecHost, BootstrapError> {
        let adapter = CodexStdio::spawn_owned(executor).await?;
        let (coordinator, authority) = HostCoordinator::new_owned(
            adapter,
            OperationLedger::new(self.generation),
            self.trusted_facts,
        )?;
        Ok(OwnedExecHost {
            coordinator,
            authority,
        })
    }
}
