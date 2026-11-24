//! Host-runtime caller access and replay fencing, independent of sockets.
use super::coordinator::OwnerCleanupHandle;
use crate::host::protocol::wire::OwnerRef;
use std::collections::{BTreeMap, BTreeSet};
use styx_contracts::error::ErrorCategory;
use styx_contracts::identity::*;
use styx_core::operations::OwnerLease;
pub(crate) mod order;
pub(crate) struct OwnerRecord {
    pub(crate) lease: Option<OwnerLease>,
    pub(crate) revision: u64,
    pub(crate) cleanup: Option<OwnerCleanupHandle>,
}
#[derive(Default)]
pub(crate) struct OwnerRegistry {
    pub(crate) order: order::Order,
    pub(crate) owners: BTreeMap<(OwnerId, OwnerEpoch), OwnerRecord>,
    pub(crate) active_epoch: Option<GatewayEpoch>,
    pub(crate) retired_epochs: BTreeSet<GatewayEpoch>,
    pub(crate) stopping: bool,
}
