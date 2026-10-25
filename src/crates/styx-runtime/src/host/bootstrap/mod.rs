//! Optional Exec Host composition, with one shared logical queued-I/O budget.
//! This is not a process RSS/native-executor limit or the persistent service manager.
use super::{
    coordinator::{CoordinatorError, HostAuthority, HostCleanup, HostCoordinator},
    link::{HostLinkBudget, LINK_BYTES},
    protocol::{HostProtocol, PairedTrustedProfile, ProtocolError, TrustedProfile},
};
use crate::providers::codex::{CodexStdio, ExecError, OwnedExecutorConfig};
use std::{sync::Arc, time::Duration};
use styx_contracts::{capability::CapabilityId, identity::HostGeneration};
use styx_core::{operations::OperationLedger, policy::AdmissionFacts};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const RPC_BYTES: usize = 16 * 1024 * 1024;
const PROTOCOL_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    #[error("invalid Exec Host bootstrap configuration")]
    InvalidConfiguration,
    #[error("Host queued-I/O budget exhausted")]
    Capacity,
    #[error(transparent)]
    Executor(#[from] ExecError),
    #[error(transparent)]
    Coordinator(#[from] CoordinatorError),
}

struct Partitions {
    source: Arc<Semaphore>,
    rpc: OwnedSemaphorePermit,
    link: Arc<HostLinkBudget>,
    protocol: OwnedSemaphorePermit,
}
impl Partitions {
    fn reserve() -> Result<Self, BootstrapError> {
        let source = Arc::new(Semaphore::new(styx_contracts::HOST_QUEUED_BYTES));
        let reserve = |bytes: usize| {
            source
                .clone()
                .try_acquire_many_owned(bytes as u32)
                .map_err(|_| BootstrapError::Capacity)
        };
        let rpc = reserve(RPC_BYTES)?;
        let protocol = reserve(PROTOCOL_BYTES)?;
        let link = HostLinkBudget::from_reserved_partition(reserve(LINK_BYTES)?)
            .map_err(|_| BootstrapError::Capacity)?;
        Ok(Self {
            source,
            rpc,
            link,
            protocol,
        })
    }
}

/// Bootstrap/control handle. Never put this in network-request state; pass the
/// request coordinator and a borrowed, explicitly bound protocol endpoint instead.
/// The sole native executor outlives connections. Shutdown is an explicit Host
/// control action, not the consequence of a socket or response disappearing.
pub struct OwnedExecHost {
    coordinator: HostCoordinator,
    authority: HostAuthority,
    link: Arc<HostLinkBudget>,
    _protocol: OwnedSemaphorePermit,
    budget: Arc<Semaphore>,
}
impl OwnedExecHost {
    pub async fn spawn(
        executor: OwnedExecutorConfig,
        generation: HostGeneration,
        trusted_facts: AdmissionFacts,
        max_jobs: usize,
    ) -> Result<Self, BootstrapError> {
        Self::reserve(generation, trusted_facts, max_jobs)?
            .spawn(executor)
            .await
    }
    /// Reserve all partitions before connecting. A strict TLS/WSS rejection can
    /// therefore occur before spawning native code, without a second byte budget.
    pub fn reserve(
        generation: HostGeneration,
        trusted_facts: AdmissionFacts,
        max_jobs: usize,
    ) -> Result<ExecHostReservation, BootstrapError> {
        // Refuse invalid composition before spawning native code or transferring
        // adapter ownership to a constructor that could reject it.
        if max_jobs == 0
            || max_jobs > 64
            || trusted_facts.descriptor.capability_id != CapabilityId::ExecRun
            || trusted_facts.descriptor.contract_version != styx_contracts::CONTRACT_VERSION
        {
            return Err(BootstrapError::InvalidConfiguration);
        }
        Ok(ExecHostReservation {
            partitions: Partitions::reserve()?,
            generation,
            trusted_facts,
            max_jobs,
        })
    }
    pub fn coordinator(&self) -> &HostCoordinator {
        &self.coordinator
    }
    pub fn authority(&self) -> &HostAuthority {
        &self.authority
    }
    pub fn link_budget(&self) -> Arc<HostLinkBudget> {
        self.link.clone()
    }
    /// Borrowing control authority also pins the protocol heap reservation to
    /// this Host. A protocol cannot outlive its bootstrap's reserved partition.
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
    /// Explicit old Gateway mode; keep this same session across reconnects.
    pub fn legacy_session(
        &self,
        profile: super::legacy::TrustedLegacyGateway,
    ) -> Result<super::legacy::LegacyExecSession<'_>, super::legacy::LegacyError> {
        super::legacy::LegacyExecSession::new(profile, self.coordinator.clone(), &self.authority)
    }
    /// Explicit Browser lane allocation from this SAME Host budget. This does
    /// not enable a capability or create a worker; trusted policy does that.
    #[cfg(target_os = "linux")]
    pub fn reserve_browser_io(
        &self,
    ) -> Result<Arc<crate::providers::browser::BrowserIoBudget>, BootstrapError> {
        let partition = self
            .budget
            .clone()
            .try_acquire_many_owned((16 * 1024 * 1024) as u32)
            .map_err(|_| BootstrapError::Capacity)?;
        crate::providers::browser::BrowserIoBudget::from_reserved(partition)
            .map_err(|_| BootstrapError::InvalidConfiguration)
    }
    /// Final8MiB native Desktop partition from the same64MiB Host allocator.
    #[cfg(target_os = "linux")]
    pub(crate) fn reserve_computer_io(
        &self,
    ) -> Result<Arc<crate::providers::cua::CuaIoBudget>, BootstrapError> {
        let partition = self
            .budget
            .clone()
            .try_acquire_many_owned((8 * 1024 * 1024) as u32)
            .map_err(|_| BootstrapError::Capacity)?;
        crate::providers::cua::CuaIoBudget::from_reserved(partition)
            .map_err(|_| BootstrapError::InvalidConfiguration)
    }
    /// Remaining logical queued-I/O capacity, never total resident memory.
    pub fn unreserved_queued_bytes(&self) -> usize {
        self.budget.available_permits()
    }
    pub async fn shutdown_owned(&self, budget: Duration) -> Result<HostCleanup, CoordinatorError> {
        self.authority.shutdown_owned(budget).await
    }
}

/// Move-only bootstrap resources; neither a transport nor a request can create
/// another executor from this reservation.
pub struct ExecHostReservation {
    partitions: Partitions,
    generation: HostGeneration,
    trusted_facts: AdmissionFacts,
    max_jobs: usize,
}
impl ExecHostReservation {
    pub fn link_budget(&self) -> Arc<HostLinkBudget> {
        self.partitions.link.clone()
    }
    /// Explicit protected configuration selected no Exec; not a spawn-failure fallback.
    pub fn without_executor(self) -> Result<OwnedExecHost, BootstrapError> {
        drop(self.partitions.rpc);
        let (coordinator, authority) = HostCoordinator::new_without_executor(
            OperationLedger::new(self.generation),
            self.trusted_facts,
            self.max_jobs,
        )?;
        Ok(OwnedExecHost {
            coordinator,
            authority,
            link: self.partitions.link,
            _protocol: self.partitions.protocol,
            budget: self.partitions.source,
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
        let adapter =
            CodexStdio::spawn_pinned_with_reserved_budget(executor, self.partitions.rpc, image)
                .await?;
        let (coordinator, authority) = HostCoordinator::new_owned(
            adapter,
            OperationLedger::new(self.generation),
            self.trusted_facts,
            self.max_jobs,
        )?;
        Ok(OwnedExecHost {
            coordinator,
            authority,
            link: self.partitions.link,
            _protocol: self.partitions.protocol,
            budget: self.partitions.source,
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
        let adapter =
            CodexStdio::spawn_owned_with_reserved_budget(executor, self.partitions.rpc).await?;
        let (coordinator, authority) = HostCoordinator::new_owned(
            adapter,
            OperationLedger::new(self.generation),
            self.trusted_facts,
            self.max_jobs,
        )?;
        Ok(OwnedExecHost {
            coordinator,
            authority,
            link: self.partitions.link,
            _protocol: self.partitions.protocol,
            budget: self.partitions.source,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn reservations_share_one_source_and_cannot_be_double_spent() {
        let partitions = Partitions::reserve().unwrap();
        assert_eq!(partitions.rpc.num_permits(), RPC_BYTES);
        assert_eq!(partitions.protocol.num_permits(), PROTOCOL_BYTES);
        assert_eq!(
            partitions.source.available_permits(),
            styx_contracts::HOST_QUEUED_BYTES - RPC_BYTES - PROTOCOL_BYTES - LINK_BYTES
        );
        // Two additional full WSS partitions would overspend the remaining24MiB.
        assert!(
            partitions
                .source
                .clone()
                .try_acquire_many_owned((2 * LINK_BYTES) as u32)
                .is_err()
        );
        let source = partitions.source.clone();
        drop(partitions);
        assert_eq!(
            source.available_permits(),
            styx_contracts::HOST_QUEUED_BYTES
        );
    }
}
