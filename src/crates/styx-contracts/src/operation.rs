use crate::{capability::CapabilityId, identity::*, session::SessionBinding};
use serde::{Deserialize, Serialize};

/// Issued and reserved by the Host. Deserializing a token does not reserve it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationId {
    pub host_generation: HostGeneration,
    pub owner_epoch: OwnerEpoch,
    pub sequence: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Reserved,
    Validated,
    Dispatched,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionLiveness {
    NotStarted,
    Running,
    Exited,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Cancellation {
    Requested,
    NotDispatched,
    TerminationConfirmed,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisconnectPolicy {
    RetainForOwner,
    TerminateOnOwnerEnd,
}

/// A monotonic time relative to the current Host generation; never wall-clock boot time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MonotonicMillis(pub u64);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedContext {
    pub device_id: DeviceId,
    pub grant_revision: u64,
    pub session: Option<SessionBinding>,
    pub observation: Option<ObservationId>,
    pub capability: CapabilityId,
    pub deadline: MonotonicMillis,
    pub disconnect_policy: DisconnectPolicy,
}

/// Stream closure is independent of process termination and action outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputDrain {
    NotOpened,
    Open,
    Drained,
    Unknown,
}
